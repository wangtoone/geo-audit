#!/usr/bin/env python
"""录制 `fixtures/` 下的冻结 HTTP 快照（§8.1 / §8.2）。

用法::

    # 整份录（默认**不覆盖**已有快照 —— 已冻结的快照是断言的一部分，
    # 覆盖它等于改测试；要覆盖必须显式 --overwrite 且单独一个 commit，
    # message 前缀 fixture:）
    python scripts/capture_fixtures.py --contact you@example.com \\
        --from-file fixtures/urls.txt

    # 补录单条
    python scripts/capture_fixtures.py --contact you@example.com \\
        --url https://developers.brevo.com/docs/llms.txt

    # 只录 DNS（§3.6 的 dns.json）
    python scripts/capture_fixtures.py --contact you@example.com \\
        --from-file fixtures/urls.txt --dns-only

    # 第 4a 步的手写自检快照（不联网、不碰真 fixtures/）
    python scripts/capture_fixtures.py --write-selftest-fixtures \\
        --fixtures-dir fixtures/handwritten

三种指令（§8.2）:

``@control <url>``
    为 ``<url>`` 录一条同 host 的随机路径探针，并写 ``probe_for`` 反查。
    探针 URL 由 ``Fetcher.control_url`` 现场生成（``secrets.token_hex(12)``），
    录完就冻住 —— 重放时 ``store.probe_url()`` 取回的就是它。

``@expand <url> <extractor> <limit>``
    从**已录**的 ``<url>`` 正文里展开链接再逐条录。mistral 的 75 条内链、
    bytebase 的 504 条相对路径这类机械可派生的 URL 集不由人手写。超过
    ``limit`` 时确定性抽样（种子 = 父 URL），否则每次补录都换一批。

``@pair <index_url> <full_url>``
    llms.txt / llms-full.txt 配对，两条都录。

录制脚本自己也守 2.0s/域（走 ``DomainLimiter``，与生产同一把闸）、也要
``--contact``（UA 里必须有真实联系方式）。
"""

from __future__ import annotations

import argparse
import contextlib
import os
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import urljoin

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from geo_audit.fetch.cache import HttpCache  # noqa: E402
from geo_audit.fetch.client import Fetcher, FetcherConfig  # noqa: E402
from geo_audit.fetch.resolve import resolve_host  # noqa: E402
from geo_audit.fixtures import (  # noqa: E402
    REPLAY_STRIPPED_HEADERS,
    BodyNotStored,
    DnsFixtureMissing,
    FixtureMissing,
    FixtureStore,
    UrlSpec,
    canon_url,
    hosts_of,
    parse_urls_txt,
    sample_deterministic,
)
from geo_audit.models import Expect  # noqa: E402

EXIT_OK = 0
EXIT_USAGE = 4


# --------------------------------------------------------------------------- #
# 录制 transport
# --------------------------------------------------------------------------- #


class RecordingTransport(httpx.BaseTransport):
    """把每一跳原样落进 :class:`FixtureStore`，再把响应交给上层。

    挂在 transport 层而不是包一层 ``Fetcher`` 的理由有两条：

    1. **逐跳**。``Fetcher._fetch_chain`` 自己跟跳转，每一跳都是一次
       ``handle_request``，所以挂在这里天然就是「逐跳单独存」（§8.1 决定 2）。
    2. **完整正文**。``Fetcher`` 上面有 ``byte_cap``（外链存活检查只读 64 KiB），
       但 ``expect`` 块里的 md5 与字节数必须是**完整流**的值。transport 这一层
       先把整条流读完再交上去，于是 9 MB 那条也能算出真 md5。

    落盘的正文是**传输解码后**的字节（httpx 在 ``Response.read()`` 里已经把
    gzip 解掉了），所以交还上层时必须剥掉 ``content-encoding`` /
    ``content-length`` —— 否则客户端会二次解压直接报错。重放路径
    （``FixtureStore.replay``）剥的是同一张表，两边对称。
    """

    def __init__(
        self,
        store: FixtureStore,
        *,
        overwrite: bool = False,
        verify: bool = True,
        dry_run: bool = False,
    ) -> None:
        self._store = store
        self._inner = httpx.HTTPTransport(verify=verify, retries=0)
        self._overwrite = overwrite
        self._dry_run = dry_run
        self._comment: str | None = None
        self._probe_for: str | None = None
        self._probe_url: str | None = None
        self.recorded: list[str] = []
        self.skipped: list[str] = []
        self.errors: list[tuple[str, str]] = []

    def set_context(
        self, *, comment: str | None, probe_for: str | None = None, probe_url: str | None = None
    ) -> None:
        """下一次 fetch 期间录到的快照带上这些标注。"""
        self._comment = comment
        self._probe_for = canon_url(probe_for) if probe_for else None
        self._probe_url = canon_url(probe_url) if probe_url else None

    # -- httpx 接口 ------------------------------------------------------- #

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = FixtureStore.url_of_request(request)  # 与重放共用同一把索引键
        if self._store.has(url) and not self._overwrite:
            self.skipped.append(url)
            return self._store.replay(request)
        try:
            resp = self._inner.handle_request(request)
        except httpx.HTTPError as exc:
            err = f"{type(exc).__name__}: {exc}"
            self.errors.append((url, err))
            self._put(url, status=0, headers={}, body=b"", transport_error=err)
            raise
        resp.read()
        content = resp.content
        headers = {k.lower(): v for k, v in resp.headers.items()}
        self._put(url, status=resp.status_code, headers=headers, body=content)
        out = {k: v for k, v in headers.items() if k not in REPLAY_STRIPPED_HEADERS}
        return httpx.Response(resp.status_code, headers=out, content=content, request=request)

    def close(self) -> None:
        self._inner.close()

    # -- 落盘 ------------------------------------------------------------- #

    def _put(
        self,
        url: str,
        *,
        status: int,
        headers: Mapping[str, str],
        body: bytes,
        transport_error: str | None = None,
    ) -> None:
        if self._dry_run:
            print(f"  [dry-run] {status} {url} ({len(body):,} B)")
            self.recorded.append(url)
            return
        # probe_for 只贴在探针 URL 那一跳上：探针如果自己也跳转，反查索引应当
        # 指向探针本身，而不是让 store.probe_url() 有两个候选。
        probe_for = self._probe_for if (self._probe_url and url == self._probe_url) else None
        snap = self._store.put_snapshot(
            url,
            status=status,
            headers=headers,
            body=body,
            probe_for=probe_for,
            transport_error=transport_error,
            comment=self._comment,
            overwrite=self._overwrite,
        )
        self.recorded.append(url)
        drift = self._store.check_expect(url, raw_md5=snap.raw_md5, body_bytes=snap.body_bytes)
        for line in drift:
            print(f"  ⚠ {url} 与 expect 不符 —— {line}")
            print("    走 §8.1 的 drift 四分支：python scripts/refresh_fixtures.py --explain")


# --------------------------------------------------------------------------- #
# @expand 的四个抽取器
# --------------------------------------------------------------------------- #

_MD_LINK = re.compile(r"\[[^\]]*\]\(\s*<?([^)>\s]+)")
_BARE_URL = re.compile(r"https?://[^\s<>\"')\]]+")
_RELATIVE = re.compile(r"(?m)(?:^|[\s(\[])(/[A-Za-z0-9._~\-/%]+)")
_HTML_A = re.compile(r"<a\b[^>]*?\bhref\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)


def extract_links(body: str, *, extractor: str, base_url: str) -> list[str]:
    """从父文件正文里抽链接。

    抽取器名字与 §8.2 的 ``@expand`` 行逐字对应：

    - ``markdown``：``[text](url)``（mistral / replicate / saleor 那批）
    - ``bare``：裸 URL（turso 整份文件零 markdown 语法；inngest 的双 scheme 拼接）
    - ``relative``：``/xxx`` 相对路径（bytebase 504 条 ``.md``、mailerlite）
    - ``html_a``：正文里内嵌的裸 HTML ``<a href>``（attio / close / upstash）

    抽出来的结果**不做任何清洗**（不补 scheme、不去反引号伪影）—— 展开结果
    本身就是「我们的抽取器读到了什么」的证据，清洗会把证据洗掉。只做 urljoin
    把相对路径变成可请求的绝对 URL。
    """
    if extractor == "markdown":
        raw = _MD_LINK.findall(body)
    elif extractor == "bare":
        raw = _BARE_URL.findall(body)
    elif extractor == "relative":
        raw = _RELATIVE.findall(body)
    elif extractor == "html_a":
        raw = _HTML_A.findall(body)
    else:  # pragma: no cover - parse_urls_txt 已经挡掉了
        raise ValueError(f"未知抽取器 {extractor!r}")

    out: list[str] = []
    for item in raw:
        href = item.strip().rstrip(".,;")
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        absolute = href if "://" in href else urljoin(base_url, href)
        if absolute.startswith(("http://", "https://")):
            out.append(absolute)
    return out


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #


def build_fetcher(
    *, contact: str, rate: float, recorder: RecordingTransport, respect_robots: bool
) -> Fetcher:
    cache_dir = Path(tempfile.mkdtemp(prefix="geo-audit-capture-"))
    return Fetcher(
        FetcherConfig(
            contact=contact,
            interval=rate,
            respect_robots=respect_robots,
            # 录制要如实记下 bot-hostile 供应商 host 的真实响应，不能用
            # 「跳过并当 403」那条省预算的捷径 —— 那会把编出来的 403 冻进快照。
            probe_known_hostile=True,
        ),
        cache=HttpCache(path=cache_dir / "http.sqlite3"),
        transport=recorder,
    )


def capture(specs: Sequence[UrlSpec], args: argparse.Namespace) -> int:
    store = FixtureStore(args.fixtures_dir, dns_file=args.dns_file)
    recorder = RecordingTransport(
        store, overwrite=args.overwrite, verify=not args.no_verify, dry_run=args.dry_run
    )
    fetcher = build_fetcher(
        contact=args.contact,
        rate=args.rate,
        recorder=recorder,
        respect_robots=not args.no_robots,
    )
    n = 0
    with fetcher:
        for spec in specs:
            if args.limit and n >= args.limit:
                print(f"到 --limit {args.limit} 了，停。")
                break
            n += _do_spec(spec, fetcher, recorder, store, args)
    recorder.close()

    print(
        f"\n录到 {len(set(recorder.recorded))} 条，"
        f"跳过（已冻结）{len(set(recorder.skipped))} 条，"
        f"传输失败 {len(recorder.errors)} 条。"
    )
    for url, err in recorder.errors:
        print(f"  ✗ {url} —— {err}")
    if not args.dry_run:
        store.rebuild_index()
        print(f"index.json 已重建：{len(store.snapshots())} 条快照。")
    return EXIT_OK


def _do_spec(
    spec: UrlSpec,
    fetcher: Fetcher,
    recorder: RecordingTransport,
    store: FixtureStore,
    args: argparse.Namespace,
) -> int:
    if spec.kind == "control":
        probe = Fetcher.control_url(spec.url)
        existing = _existing_probe(store, spec.url)
        if existing is not None and not args.overwrite:
            print(f"@control {spec.url} -> 已有探针 {existing}，跳过")
            return 0
        print(f"@control {spec.url} -> {probe}")
        recorder.set_context(comment=spec.comment, probe_for=spec.url, probe_url=probe)
        fetcher.fetch(probe, expect=Expect.ANY, use_cache=False)
        return 1

    if spec.kind == "expand":
        return _do_expand(spec, fetcher, recorder, store, args)

    count = 0
    for url in spec.urls:
        print(f"{spec.kind:<8} {url}")
        recorder.set_context(comment=spec.comment)
        expect = Expect.TEXT_FILE if url.endswith(".txt") or url.endswith(".md") else Expect.ANY
        fetcher.fetch(url, expect=expect, use_cache=False)
        count += 1
    return count


def _existing_probe(store: FixtureStore, target: str) -> str | None:
    try:
        return store.probe_url(target)
    except FixtureMissing:
        return None


def _do_expand(
    spec: UrlSpec,
    fetcher: Fetcher,
    recorder: RecordingTransport,
    store: FixtureStore,
    args: argparse.Namespace,
) -> int:
    assert spec.extractor is not None
    assert spec.limit is not None
    try:
        body = _parent_body(spec, fetcher, recorder, store)
    except (FixtureMissing, BodyNotStored) as exc:
        print(f"@expand {spec.url} 拿不到父文件正文，跳过这一行：{exc}")
        return 0
    links = extract_links(body, extractor=spec.extractor, base_url=spec.url)
    picked = sample_deterministic(links, spec.limit, seed=canon_url(spec.url))
    print(
        f"@expand {spec.url} [{spec.extractor}] 抽出 {len(links)} 条"
        f"（去重后 {len(set(links))}），录 {len(picked)} 条"
    )
    for url in picked:
        if args.limit and recorder.recorded and len(set(recorder.recorded)) >= args.limit:
            break
        recorder.set_context(comment=f"{spec.comment} ← @expand {spec.url}")
        # 传输失败本身已经被 recorder 冻进快照了，继续下一条
        with contextlib.suppress(httpx.HTTPError):
            fetcher.fetch(url, expect=Expect.ANY, use_cache=False)
    return len(picked)


def _parent_body(
    spec: UrlSpec, fetcher: Fetcher, recorder: RecordingTransport, store: FixtureStore
) -> str:
    """@expand 的父文件正文。没录过就**先把父文件录下来**。

    §8.2 的全文里 17 条 @expand 有 10 条的父文件从没单独列过 URL 行
    （inngest / replicate / pingcap / bytebase / turso / zilliz /
    attio-customers / close / mailerlite / factorialhr）。展开本来就必须先有
    父文件的正文，所以这里按需补录，而不是要求作者去补那 10 行。
    """
    if not store.has(spec.url):
        print(f"  父文件 {spec.url} 还没录，先录它")
        recorder.set_context(comment=f"{spec.comment} ← @expand 的父文件")
        fetcher.fetch(spec.url, expect=Expect.TEXT_FILE, use_cache=False)
    return store.body(spec.url).decode("utf-8", errors="replace")


def capture_dns(specs: Sequence[UrlSpec], args: argparse.Namespace) -> int:
    """录 ``dns.json``（§3.6）。``urls.txt`` 里出现过的每个 host 一条。"""
    store = FixtureStore(args.fixtures_dir, dns_file=args.dns_file)
    table: dict[str, dict[str, object]] = {}
    for host in sorted(hosts_of(specs)):
        res = resolve_host(host)
        table[host] = {
            "addresses": list(res.addresses),
            "resolver": res.resolver,
            "poisoned": res.poisoned,
        }
        if res.error:
            table[host]["error"] = res.error
        print(f"{host:<40} {res.resolver:<8} {list(res.addresses)}")
    table.setdefault(
        "_default_absent",
        {"addresses": [], "resolver": "none", "poisoned": False, "error": "NXDOMAIN"},
    )
    path = store.write_dns(table)
    print(f"\n写了 {path}（{len(table) - 1} 个 host + _default_absent）。")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# 第 4a 步的手写自检快照（零网络）
# --------------------------------------------------------------------------- #

SELFTEST_NOTE = (
    "手写的自检快照（第 4a 步）。**不是实录**：host 全是 .invalid 保留域，"
    "正文是造的，只用来让 tests/test_fixture_store.py 在没有真快照时也能真跑起来。"
    "真快照由第 4b 步录进 fixtures/ 根目录，与本目录互不影响。"
    "重新生成：python scripts/capture_fixtures.py --write-selftest-fixtures "
    "--fixtures-dir fixtures/handwritten"
)

SELFTEST_HOST = "fixture-selftest.invalid"
SELFTEST_PROBE_HEX = "0f1e2d3c4b5a69788796a5b4"  # 冻住的探针路径，不随机
SELFTEST_LLMS_BODY = (
    b"# fixture-selftest\n\n"
    b"> handwritten fixture, not a recording\n\n"
    b"## Docs\n\n"
    b"- [Getting started](https://fixture-selftest.invalid/docs/start)\n"
    b"- [Dead page](https://fixture-selftest.invalid/docs/gone)\n"
    b"- [Relative](/docs/relative)\n"
)
SELFTEST_SHELL = (
    b"<!doctype html><html><head><title>Selftest Landing</title></head>"
    b"<body><div id=root><h1>Selftest</h1><p>handwritten fixture</p></div></body></html>"
)
#: 9,002,064 B —— 与 §8.2 记的 ``dev.wix.com/docs/llms-full.txt`` 同一个数，
#: 好让 digest_only 那一档的阈值在自检里也被真正跨过。
SELFTEST_HUGE_BYTES = 9_002_064
#: 2 MiB —— 落在 full(1 MiB) 与 truncated(8 MiB) 之间。
SELFTEST_BIG_BYTES = 2 * 1024 * 1024


def _filler(n: int) -> bytes:
    """可复现的填充正文（不是随机数据，重跑逐字节相同）。"""
    unit = b"handwritten-fixture-filler-line\n"
    return (unit * (n // len(unit) + 1))[:n]


def write_selftest_fixtures(root: Path) -> int:
    store = FixtureStore(root, dns_file="dns.sample.json")
    text_plain = {"content-type": "text/plain; charset=utf-8", "server": "selftest"}
    text_html = {"content-type": "text/html; charset=utf-8", "server": "selftest"}
    stamp = "2026-09-07T00:00:00Z"
    probe = f"https://{SELFTEST_HOST}/geo-audit-probe-{SELFTEST_PROBE_HEX}.txt"

    def put(url: str, **kw: object) -> None:
        store.put_snapshot(
            url,
            recorded_at=stamp,
            handwritten=True,
            note="手写，非实录",
            overwrite=True,
            **kw,  # type: ignore[arg-type]
        )

    put(
        f"https://{SELFTEST_HOST}/robots.txt",
        status=200,
        headers=text_plain,
        body=b"User-agent: *\nAllow: /\n",
        comment="自检 robots.txt：probe() 会先问它",
    )
    put(
        f"https://{SELFTEST_HOST}/llms.txt",
        status=200,
        headers=text_plain,
        body=SELFTEST_LLMS_BODY,
        comment="自检 full 档：完整正文 + expect 里的 md5/bytes",
    )
    put(
        probe,
        status=404,
        headers=text_plain,
        body=b"not found\n",
        probe_for=f"https://{SELFTEST_HOST}/llms.txt",
        comment="自检对照探针：probe_for 反查索引",
    )
    put(
        "https://redirect-selftest.invalid/llms-full.txt",
        status=302,
        headers={**text_plain, "location": "https://target-selftest.invalid/"},
        body=b"",
        comment="自检逐跳存：这一跳只有 Location，正文空",
    )
    put(
        "https://target-selftest.invalid/",
        status=200,
        headers=text_html,
        body=SELFTEST_SHELL,
        comment="自检逐跳存：跳转终点，HTML 壳",
    )
    put(
        "https://big-selftest.invalid/llms-full.txt",
        status=200,
        headers=text_plain,
        body=_filler(SELFTEST_BIG_BYTES),
        comment="自检 truncated 档：2 MiB，只落前 256 KiB + 全量 digest",
    )
    put(
        "https://huge-selftest.invalid/llms-full.txt",
        status=200,
        headers=text_plain,
        body=_filler(SELFTEST_HUGE_BYTES),
        comment="自检 digest_only 档：9,002,064 B，正文不落盘",
    )
    put(
        "https://timeout-selftest.invalid/llms.txt",
        status=0,
        headers={},
        body=b"",
        transport_error="timeout: ConnectTimeout('handwritten fixture')",
        comment="自检传输失败：重放成 httpx.ConnectTimeout",
    )

    store.set_index_meta(_note=SELFTEST_NOTE, _handwritten=True)
    store.rebuild_index()

    dns: dict[str, Mapping[str, object]] = {
        SELFTEST_HOST: {"addresses": ["203.0.113.10"], "resolver": "system", "poisoned": False},
        "redirect-selftest.invalid": {
            "addresses": ["203.0.113.11"],
            "resolver": "system",
            "poisoned": False,
        },
        "target-selftest.invalid": {
            "addresses": ["203.0.113.12"],
            "resolver": "system",
            "poisoned": False,
        },
        "big-selftest.invalid": {
            "addresses": ["203.0.113.13"],
            "resolver": "system",
            "poisoned": False,
        },
        "huge-selftest.invalid": {
            "addresses": ["203.0.113.14"],
            "resolver": "system",
            "poisoned": False,
        },
        "timeout-selftest.invalid": {
            "addresses": ["203.0.113.15"],
            "resolver": "system",
            "poisoned": False,
        },
        # 本机解析被污染、公共解析器给真实地址（§3.6 的 www.talkie-ai.com 形态）
        "poisoned-selftest.invalid": {
            "addresses": ["203.0.113.16"],
            "resolver": "8.8.8.8",
            "poisoned": False,
            "system_answer": ["127.0.0.1"],
        },
        # 双 resolver NXDOMAIN 的真死（§3.6 的 next.js 形态）
        "dead-selftest.invalid": {
            "addresses": [],
            "resolver": "none",
            "poisoned": False,
            "error": "NXDOMAIN on system/8.8.8.8/1.1.1.1",
        },
        "_default_absent": {
            "addresses": [],
            "resolver": "none",
            "poisoned": False,
            "error": "NXDOMAIN",
        },
    }
    path = store.write_dns(dns, note=SELFTEST_NOTE)
    print(f"写了 {len(store.snapshots())} 条手写快照 + {path}（全部标了 handwritten）。")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="capture_fixtures.py",
        description="录制 fixtures/ 下的冻结 HTTP 快照（§8.1 / §8.2）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--contact", help="UA 里的联系邮箱（抓取合规要求，录制也一样要）")
    p.add_argument("--from-file", type=Path, help="urls.txt 路径")
    p.add_argument("--url", action="append", default=[], help="补录单条（可重复）")
    p.add_argument("--fixtures-dir", type=Path, default=REPO_ROOT / "fixtures")
    p.add_argument("--dns-file", default=None, help="DNS 表文件名（默认 dns.json）")
    p.add_argument("--rate", type=float, default=2.0, help="同域最小间隔秒（下限 2.0）")
    p.add_argument("--limit", type=int, default=0, help="最多录几条（调试用，0 = 不限）")
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="覆盖已有快照。已冻结的快照是断言的一部分，覆盖它等于改测试 —— "
        "必须单独一个 commit，message 前缀 fixture:",
    )
    p.add_argument("--dry-run", action="store_true", help="只打印要录什么，不落盘")
    p.add_argument("--dns-only", action="store_true", help="只录 dns.json，不发 HTTP 请求")
    p.add_argument("--rebuild-index", action="store_true", help="只从磁盘重建 index.json")
    p.add_argument(
        "--write-selftest-fixtures",
        action="store_true",
        help="写第 4a 步的手写自检快照（零网络，只写 --fixtures-dir 指的目录）",
    )
    p.add_argument("--no-robots", action="store_true", help="不看 robots.txt（只用于自有站点）")
    p.add_argument("--no-verify", action="store_true", help="不校验 TLS（录坏证书的站点用）")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.write_selftest_fixtures:
        return write_selftest_fixtures(Path(args.fixtures_dir))

    if args.rebuild_index:
        store = FixtureStore(args.fixtures_dir, dns_file=args.dns_file)
        dropped = store.rebuild_index()
        print(f"index.json 已重建：{len(store.snapshots())} 条快照。")
        for canon in dropped:
            print(f"  - 磁盘上已没有的条目被移除：{canon}")
        return EXIT_OK

    if os.environ.get("GEO_AUDIT_FORBID_NETWORK") == "1":
        print("GEO_AUDIT_FORBID_NETWORK=1 —— 录制需要真网络，先把它关掉。", file=sys.stderr)
        return EXIT_USAGE
    if not args.contact or "@" not in args.contact:
        print("必须给 --contact（真实联系邮箱）。抓取合规要求 UA 里带它。", file=sys.stderr)
        return EXIT_USAGE
    if args.rate < 2.0:
        print(f"--rate {args.rate} 低于合规下限 2.0s/域。", file=sys.stderr)
        return EXIT_USAGE

    specs: list[UrlSpec] = []
    if args.from_file:
        specs.extend(parse_urls_txt(Path(args.from_file).read_text(encoding="utf-8")))
    for url in args.url:
        specs.append(UrlSpec(kind="url", url=url, comment="--url 补录"))
    if not specs:
        print("没给要录的东西：用 --from-file 或 --url。", file=sys.stderr)
        return EXIT_USAGE

    if args.dns_only:
        return capture_dns(specs, args)
    return capture(specs, args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FixtureMissing, DnsFixtureMissing) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(EXIT_USAGE) from exc
