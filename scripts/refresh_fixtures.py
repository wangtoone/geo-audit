#!/usr/bin/env python
"""每周对活网 diff 已冻结的快照（``fixture-freshness.yml`` 用）。

**这个脚本永远退出 0。** 它只开 issue，绝不阻塞 PR —— 活网漂移是别人家改了站，
不是我们的代码坏了。真要改，改的是 ``fixtures/index.json`` 的 ``expect`` 一处，
并按 §8.1 的四分支规程在 ``drift`` 块留痕。

用法::

    # 只打印四分支规程（零网络，capture_fixtures.py 的告警指向这里）
    python scripts/refresh_fixtures.py --explain

    # 对活网 diff（守 2.0s/域，要 --contact）
    python scripts/refresh_fixtures.py --contact you@example.com

    # 只看某几条
    python scripts/refresh_fixtures.py --contact you@example.com \\
        --url https://developers.deepgram.com/llms-full.txt

    # 把结论写成 drift 记录（需要人先看过分支判断）
    python scripts/refresh_fixtures.py --contact you@example.com \\
        --url https://... --write-drift unchanged

四个分支怎么选（§8.1 那张表，一个字不许临场发挥）：

======================  ==========================================  ==========
情形                     动作                                        谁批
======================  ==========================================  ==========
值变了、现象没变          更新 expect + drift.phenomenon=unchanged     普通 PR
现象没了                 不改断言，标 gone + xfail(strict=True)        issue + reviewer
拿不到了（403/超时/没了）  标 unreachable，继续用旧快照                 自动
必然过期的那条            不需要活网可达                               ——
======================  ==========================================  ==========
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from geo_audit.fetch.cache import HttpCache  # noqa: E402
from geo_audit.fetch.client import Fetcher, FetcherConfig  # noqa: E402
from geo_audit.fixtures import (  # noqa: E402
    DRIFT_PHENOMENA,
    DRIFT_PLAYBOOK,
    FixtureStore,
    canon_url,
)
from geo_audit.models import Expect  # noqa: E402

#: 这个脚本只报告，不判死。永远 0。
EXIT_OK = 0


@dataclass(frozen=True, slots=True)
class Finding:
    """一条快照的新鲜度结论。"""

    canon_url: str
    #: "ok" | "drifted" | "unreachable" | "not_comparable"
    state: str
    detail: str
    suggested_branch: str | None = None


def explain() -> int:
    print("§8.1 漂移四分支规程 —— 录制值与方案字面量不符时该走哪个分支：\n")
    for phenomenon in DRIFT_PHENOMENA:
        print(f"  [{phenomenon}]")
        print(f"    {DRIFT_PLAYBOOK[phenomenon]}\n")
    print(
        "断言一律从 fixtures/index.json 的 expect 块读（tests/ 下不许出现字面量摘要），"
        "所以字面量只在一处，drift 让「改了什么、为什么」留痕。"
    )
    return EXIT_OK


def check_one(fetcher: Fetcher, store: FixtureStore, url: str) -> Finding:
    canon = canon_url(url)
    snap = store.get(canon)
    exp = store.expect(canon)
    if snap.transport_error:
        return Finding(canon, "not_comparable", "冻结的是一次传输失败，没有可比的摘要")

    expect_text = snap.content_type in ("", "text/plain", "text/markdown")
    resp = fetcher.fetch(canon, expect=Expect.TEXT_FILE if expect_text else Expect.ANY)

    if resp.status == 0:
        return Finding(
            canon,
            "unreachable",
            f"拿不到了：{resp.transport_error}",
            suggested_branch="unreachable",
        )
    if resp.status in (401, 403, 429) or resp.blocked:
        return Finding(
            canon, "unreachable", f"活网返回 {resp.status}（挑战页/限流）", "unreachable"
        )
    if resp.raw_md5 is None:
        return Finding(
            canon,
            "not_comparable",
            f"正文被 byte_cap 截断（{resp.byte_len:,} B），截断正文的哈希不可比",
        )

    problems = store.check_expect(canon, raw_md5=resp.raw_md5, body_bytes=resp.byte_len)
    if not problems:
        return Finding(canon, "ok", f"与 expect 一致（{exp.get('bytes', '?')} B）")
    return Finding(
        canon,
        "drifted",
        "；".join(problems),
        # 值变了但还是同一类响应 -> 大概率是 unchanged 分支；现象有没有没了
        # 要人看一眼判据，脚本不替人做这个判断。
        suggested_branch="unchanged",
    )


def run(args: argparse.Namespace) -> int:
    store = FixtureStore(args.fixtures_dir)
    targets = [canon_url(u) for u in args.url] if args.url else store.snapshots()
    cache_dir = Path(tempfile.mkdtemp(prefix="geo-audit-refresh-"))
    findings: list[Finding] = []

    with Fetcher(
        FetcherConfig(contact=args.contact, interval=args.rate),
        cache=HttpCache(path=cache_dir / "http.sqlite3"),
    ) as fetcher:
        for canon in targets:
            try:
                finding = check_one(fetcher, store, canon)
            except httpx.HTTPError as exc:
                finding = Finding(
                    canon, "unreachable", f"{type(exc).__name__}: {exc}", "unreachable"
                )
            findings.append(finding)
            mark = {"ok": "·", "drifted": "⚠", "unreachable": "×", "not_comparable": "?"}[
                finding.state
            ]
            print(f"{mark} {canon}\n    {finding.detail}")
            if args.write_drift and finding.state == "drifted":
                store.set_drift(
                    canon,
                    {
                        "phenomenon": args.write_drift,
                        "date": args.date or "",
                        "old": store.expect(canon).get("raw_md5"),
                        "detail": finding.detail,
                    },
                )

    drifted = [f for f in findings if f.state == "drifted"]
    unreachable = [f for f in findings if f.state == "unreachable"]
    print(
        f"\n{len(findings)} 条：一致 {len(findings) - len(drifted) - len(unreachable)}，"
        f"漂移 {len(drifted)}，拿不到 {len(unreachable)}。"
    )
    if drifted or unreachable:
        print("\n该走哪个分支：")
        explain()
    if args.json:
        Path(args.json).write_text(
            json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"写了 {args.json}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="refresh_fixtures.py",
        description="对活网 diff 已冻结的快照。只报告，永远退出 0。",
    )
    p.add_argument("--contact", help="UA 里的联系邮箱")
    p.add_argument("--fixtures-dir", type=Path, default=REPO_ROOT / "fixtures")
    p.add_argument("--url", action="append", default=[], help="只查这几条（可重复）")
    p.add_argument("--rate", type=float, default=2.0, help="同域最小间隔秒（下限 2.0）")
    p.add_argument("--json", type=Path, default=None, help="把结论写成 JSON（给 workflow 用）")
    p.add_argument("--explain", action="store_true", help="只打印四分支规程，不联网")
    p.add_argument(
        "--write-drift",
        choices=DRIFT_PHENOMENA,
        default=None,
        help="把漂移写成 drift 记录。分支要人先判过 —— 脚本不替人选",
    )
    p.add_argument("--date", default=None, help="drift 记录里的日期")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.explain:
        return explain()
    if os.environ.get("GEO_AUDIT_FORBID_NETWORK") == "1":
        print("GEO_AUDIT_FORBID_NETWORK=1 —— 新鲜度检查要真网络。只想看规程用 --explain。")
        return EXIT_OK
    if not args.contact or "@" not in args.contact:
        print("必须给 --contact（真实联系邮箱）。想看规程用 --explain。", file=sys.stderr)
        return EXIT_OK
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
