"""冻结 HTTP 快照的存储层（§8.1）。

**这个模块存在的唯一理由**：实测报告 §5 已经自己撞上三次「同一个位置两次测出不同
数字，而没有快照可以对账」—— 12 处字节数复测 3 处对不上，`api-docs.ecwid.com`
一处记 82,302 一处记 715,130。所以判据的裁判必须是冻结的字节，不是活网。

五个决定（§8.1，逐条落到代码里）：

1. **存原始 HTTP 响应，含 headers。** 判据里有 content-type、status、Location、
   Retry-After，只存 body 的快照测不了这套里任何一条规则。
2. **逐跳单独存。** 每一跳都是 index.json 里独立的一条，`Fetcher._fetch_chain`
   自己跟跳转，于是「必须跟随 3xx」这条规则也被纳入测试范围。
3. **元数据 JSON 与正文分离，正文 gzip（``mtime=0``）。** 三档 ``body_storage``
   把「哪些断言许用哪些 fixture」变成机器可查的约束，见 :func:`body_storage_for`。
4. **DNS 也冻结**（``dns.json`` + :class:`FixtureResolver`，§3.6）。
5. **随机对照探针可重放**：录制时把探针 URL 写进 ``probe_for`` 建反查索引，
   探测器通过注入的 ``probe_url_provider``（= :meth:`FixtureStore.probe_url`）取回。

**禁止静默回落真网络**：:meth:`FixtureStore.get` 找不到就抛 :class:`FixtureMissing`，
message 里带可直接复制的 capture 命令。

**字面量断言一律不写进测试**：md5 / 字节数只在 ``fixtures/index.json`` 的 ``expect``
块里出现一次，测试从那里读（:meth:`FixtureStore.expect`）。活网漂移时改的是
index.json 一处，并在 ``drift`` 块留痕，见 :data:`DRIFT_PLAYBOOK`。
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.resources
import io
import json
import os
import random
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from .fetch.resolve import Resolution

__all__ = [
    "BODY_FULL_MAX",
    "BODY_TRUNCATED_MAX",
    "DNS_ABSENT_KEY",
    "DRIFT_PHENOMENA",
    "DRIFT_PLAYBOOK",
    "TRUNCATED_PREFIX_BYTES",
    "BodyNotStored",
    "BodyStorage",
    "DnsFixtureMissing",
    "FixtureError",
    "FixtureMissing",
    "FixtureResolver",
    "FixtureStore",
    "Snapshot",
    "UrlSpec",
    "body_storage_for",
    "canon_url",
    "load_urls_txt",
    "parse_urls_txt",
    "snapshot_path",
]

# --------------------------------------------------------------------------- #
# 三档 body_storage
# --------------------------------------------------------------------------- #

BodyStorage = Literal["full", "truncated", "digest_only"]

#: ≤1 MiB 存完整正文。1 MiB 这个上限是被最大的软 404 正文定的：
#: ``api-docs.ecwid.com`` 715,130 B 必须落在 ``full`` 档里，因为 A 组的判据
#: （html_where_text_expected / 归一化哈希）要读它的正文。
BODY_FULL_MAX: Final = 1 * 1024 * 1024

#: ≤8 MiB 存前 256 KiB + 全量 digest。liveblocks 3,564,760 B（3.5 MB）与
#: ``docs.canvasmedical.com/llms-full.txt`` 4.3 MB 走这一档。
BODY_TRUNCATED_MAX: Final = 8 * 1024 * 1024

#: ``truncated`` 档实际落盘的前缀长度。
TRUNCATED_PREFIX_BYTES: Final = 256 * 1024


def body_storage_for(body_bytes: int) -> BodyStorage:
    """按正文完整字节数选档。

    - ``full``（≤1 MiB）：任何依赖正文 / 归一化哈希的断言**只许**用它。
    - ``truncated``（≤8 MiB）：只存前 256 KiB + 全量 digest，只许用于 size/md5 断言。
    - ``digest_only``（>8 MiB）：``dev.wix.com/docs/llms-full.txt`` 9,002,064 B、
      ``docs.customer.io/llms-full.txt`` 19,977,336 B 这类。

    ``FixtureStore.body()`` 在非 ``full`` 档上抛 :class:`BodyNotStored`，
    **不给「悄悄拿截断正文算哈希」的机会**。
    """
    if body_bytes <= BODY_FULL_MAX:
        return "full"
    if body_bytes <= BODY_TRUNCATED_MAX:
        return "truncated"
    return "digest_only"


# --------------------------------------------------------------------------- #
# 异常
# --------------------------------------------------------------------------- #


class FixtureError(Exception):
    """fixture 层的基类异常。"""


class FixtureMissing(FixtureError):  # noqa: N818 —— 名字由 §8.1 定死，不加 Error 后缀
    """快照不存在。message 里必须带可直接复制的 capture 命令（门禁 M）。"""


class BodyNotStored(FixtureError):  # noqa: N818 —— 同上，§8.1 决定 3 指名这个类名
    """正文没有完整落盘（``body_storage != "full"``），不许拿它算哈希。"""


class DnsFixtureMissing(FixtureError):  # noqa: N818 —— 同上，§3.6 指名这个类名
    """``dns.json`` 里没有这个 host，且表里也没有 ``_default_absent`` 兜底。"""


def capture_command(url: str) -> str:
    """补录一条快照的命令。**必须**能被直接复制粘贴。"""
    return (
        f'python scripts/capture_fixtures.py --contact you@example.com --url "{url}"\n'
        "  # 整份重录（默认不覆盖已有快照）："
        "python scripts/capture_fixtures.py --contact you@example.com "
        "--from-file fixtures/urls.txt"
    )


# --------------------------------------------------------------------------- #
# 规范化与路径
# --------------------------------------------------------------------------- #

_DEFAULT_PORTS: Final = {"http": 80, "https": 443}
_SLUG_UNSAFE: Final = re.compile(r"[^A-Za-z0-9._-]+")

#: 索引键的长度上限（slug 部分）。超长路径截断后靠 sha1 后缀保证唯一。
SLUG_MAX_LEN: Final = 80


def canon_url(url: str) -> str:
    """索引键的规范形式。**只做无争议的规范化**，其余一律保留。

    做：scheme / host 小写、去末尾点、去默认端口、去 fragment、空 path 补 ``/``。
    不做：不动 path 大小写（路径大小写敏感）、不排序也不删 query
    （顺序是服务端语义，且 ``close.com`` 那条 presigned URL 的
    ``X-Amz-Expires=604800`` 就在 query 里，是判据本身）、不加也不删末尾斜杠
    （``https://modal.com/`` 与 ``https://modal.com/pricing`` 是两条不同快照）。
    """
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "https").lower()
    host = (parts.hostname or "").lower().strip(".")
    port = parts.port
    netloc = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _slug_of(canon: str) -> str:
    """从规范 URL 造人能看懂的文件名前缀。

    ``https://developers.brevo.com/docs/llms.txt`` -> ``docs-llms.txt``；
    ``https://modal.com/`` -> ``index``。
    """
    parts = urlsplit(canon)
    raw = parts.path.strip("/")
    if parts.query:
        raw = f"{raw}-q" if raw else "index-q"
    slug = _SLUG_UNSAFE.sub("-", raw.replace("/", "-")).strip("-")
    return (slug or "index")[:SLUG_MAX_LEN].strip("-") or "index"


def snapshot_path(url: str) -> str:
    """快照的相对路径**主干**（不含扩展名），相对 ``fixtures/``。

    形如 ``snapshots/<host>/<slug>-<sha1_8>``，元数据是 ``<主干>.meta.json``，
    正文是 ``<主干>.body.gz``。

    ``sha1_8`` = ``sha1(canon_url)`` 的前 8 个十六进制位。它承担唯一性，slug
    只承担可读性（所以 slug 可以被截断、可以撞车）。sha1 在这里纯做短哈希，
    不涉及任何安全性质，故 ``usedforsecurity=False``。
    """
    canon = canon_url(url)
    host = urlsplit(canon).netloc or "_nohost"
    digest = hashlib.sha1(canon.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
    return f"snapshots/{host}/{_slug_of(canon)}-{digest}"


# --------------------------------------------------------------------------- #
# 漂移规程（§8.1 的四分支表，供 refresh_fixtures.py 直接打印）
# --------------------------------------------------------------------------- #

DRIFT_PHENOMENA: Final = ("unchanged", "gone", "unreachable", "presigned_expiring")

DRIFT_PLAYBOOK: Final = {
    "unchanged": (
        "值变了、现象没变：更新 index.json 的 expect + 写 drift.phenomenon=unchanged，"
        "断言照样从 expect 读。普通 PR，commit message 前缀 fixture:"
    ),
    "gone": (
        "现象没了：**不改断言**，标 drift.phenomenon=gone 并给该用例加 "
        "pytest.mark.xfail(strict=True, reason=...)，CHANGELOG 记一行"
        "「现象已被站方修复，回归用例转为历史留档」。需要一个 issue + reviewer 确认"
    ),
    "unreachable": (
        "拿不到了（403/超时/域名没了）：标 drift.phenomenon=unreachable，"
        "用已冻结的旧快照继续跑 —— 这正是冻结的意义。无需批准"
    ),
    "presigned_expiring": (
        "必然过期的那条（close.com 的 X-Amz-Expires=604800）：fixture 就是过期后的状态，"
        "规则只看 URL 不看响应，不需要活网可达"
    ),
}


# --------------------------------------------------------------------------- #
# urls.txt 解析（§8.2 的三种指令）
# --------------------------------------------------------------------------- #

UrlSpecKind = Literal["url", "control", "expand", "pair"]

#: ``@expand`` 支持的抽取器（§8.2 里出现过的四个，逐个有出处）。
EXPAND_EXTRACTORS: Final = ("markdown", "bare", "relative", "html_a")


@dataclass(frozen=True, slots=True)
class UrlSpec:
    """``fixtures/urls.txt`` 的一行有效指令。

    ``comment`` 是**生效后**的用途注释，``raw_comment`` 是原文写了什么（没写是
    ``None``）。两者要分开，是因为 §8.2 自己矛盾：正文里 26 条 ``@control``
    只有 tenderly 那条带 ``#`` 注释、L 组 6 条 ``robots.txt`` 一条注释都没有，
    而同节的机器检查却写着 ``assert all(l.comment for l in lines)``。

    这里的裁法是：``@control`` 继承被对照 URL 的注释（它的用途本来就是「给那条
    做对照」），其余行**不替作者编用途** —— 原文没写就是空字符串，由
    ``test_urls_txt_shape`` 去报，而不是在解析期猜一个塞进去。
    """

    kind: UrlSpecKind
    #: url / control / expand 的目标；pair 行取 index_url
    url: str
    comment: str
    raw_comment: str | None = None
    lineno: int = 0
    #: pair 行的第二个 URL（llms-full.txt）
    pair_url: str | None = None
    #: expand 行的抽取器与条数上限
    extractor: str | None = None
    limit: int | None = None

    @property
    def urls(self) -> tuple[str, ...]:
        """这一行**要录**的 URL（``control`` 行录的是探针，不在这里）。"""
        if self.kind == "pair":
            assert self.pair_url is not None
            return (self.url, self.pair_url)
        if self.kind == "control":
            return ()
        return (self.url,)


def parse_urls_txt(text: str) -> list[UrlSpec]:
    """解析 ``urls.txt``。只返回有效行（跳过空行与纯注释行）。

    语法（§8.2 表头逐字照抄）::

        <url>              # 注释            录一条快照
        @control <url>                       为 <url> 录同 host 对照探针
        @expand <url> <extractor> <limit>    从已录的 <url> 正文里展开链接并逐条录制
        @pair <index_url> <full_url>         llms.txt / llms-full.txt 配对，两条都录
    """
    out: list[UrlSpec] = []
    by_url: dict[str, str] = {}  # canon_url -> comment，给 @control 继承注释用
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        payload, _, comment_part = line.partition("#")
        payload = payload.strip()
        raw_comment = comment_part.strip() or None
        if not payload:
            continue
        fields = payload.split()
        head = fields[0]

        if head == "@control":
            if len(fields) != 2:
                raise ValueError(f"urls.txt:{lineno} @control 只接受一个 URL：{line!r}")
            target = fields[1]
            inherited = by_url.get(canon_url(target))
            if raw_comment:
                comment = raw_comment
            elif inherited:
                comment = f"{inherited}（对照探针）"
            else:
                comment = ""
            out.append(
                UrlSpec(
                    kind="control",
                    url=target,
                    comment=comment,
                    raw_comment=raw_comment,
                    lineno=lineno,
                )
            )
            continue

        if head == "@expand":
            if len(fields) != 4:
                raise ValueError(
                    f"urls.txt:{lineno} @expand 需要 <url> <extractor> <limit>：{line!r}"
                )
            extractor = fields[2]
            if extractor not in EXPAND_EXTRACTORS:
                raise ValueError(
                    f"urls.txt:{lineno} 未知抽取器 {extractor!r}，"
                    f"可用：{', '.join(EXPAND_EXTRACTORS)}"
                )
            out.append(
                UrlSpec(
                    kind="expand",
                    url=fields[1],
                    comment=raw_comment or "",
                    raw_comment=raw_comment,
                    lineno=lineno,
                    extractor=extractor,
                    limit=int(fields[3]),
                )
            )
            continue

        if head == "@pair":
            if len(fields) != 3:
                raise ValueError(f"urls.txt:{lineno} @pair 需要 <index_url> <full_url>：{line!r}")
            out.append(
                UrlSpec(
                    kind="pair",
                    url=fields[1],
                    pair_url=fields[2],
                    comment=raw_comment or "",
                    raw_comment=raw_comment,
                    lineno=lineno,
                )
            )
            if raw_comment:
                by_url[canon_url(fields[1])] = raw_comment
                by_url[canon_url(fields[2])] = raw_comment
            continue

        if head.startswith("@"):
            raise ValueError(f"urls.txt:{lineno} 未知指令 {head!r}")
        if len(fields) != 1:
            raise ValueError(f"urls.txt:{lineno} URL 行只允许一个 URL：{line!r}")
        out.append(
            UrlSpec(
                kind="url",
                url=head,
                comment=raw_comment or "",
                raw_comment=raw_comment,
                lineno=lineno,
            )
        )
        if raw_comment:
            by_url[canon_url(head)] = raw_comment
    return out


def load_urls_txt(root: Path | str) -> list[UrlSpec]:
    """读 ``<root>/urls.txt``。"""
    path = Path(root) / "urls.txt"
    if not path.exists():
        raise FixtureMissing(
            f"{path} 不存在。它是 §8.2 的交付物（270 行），由第 4b 步实录前先落地。"
        )
    return parse_urls_txt(path.read_text(encoding="utf-8"))


def hosts_of(specs: Iterable[UrlSpec]) -> set[str]:
    """``urls.txt`` 里出现过的全部 host（含 ``@control`` 的目标 host）。

    §8.1 决定 4：这些 host 每一个都必须在 ``dns.json`` 里有条目。
    """
    out: set[str] = set()
    for spec in specs:
        for u in (spec.url, spec.pair_url):
            if u:
                host = urlsplit(canon_url(u)).hostname
                if host:
                    out.add(host)
    return out


# --------------------------------------------------------------------------- #
# 一条快照
# --------------------------------------------------------------------------- #

#: 重放时必须剥掉的 header。录的是**传输解码后**的正文（httpx 在 Response.read()
#: 里已经把 gzip 解掉了），所以再把 content-encoding 原样发回去会让客户端二次
#: 解压直接报错；content-length 同理，由 httpx 按重放正文重算。
#: 判据用得到的 header（content-type / location / retry-after / server / cf-ray …）
#: 一个都不剥。
REPLAY_STRIPPED_HEADERS: Final = frozenset(
    {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"}
)

#: 重放时加上的标记 header，让「这条正文是不是完整的」在响应上就能看见。
#: ``x-geo-audit-*`` 不参与任何判据（判据只读 content-type / status / location /
#: retry-after 与正文），所以加它们是安全的。
HDR_BODY_STORAGE: Final = "x-geo-audit-fixture-body"
HDR_BODY_BYTES: Final = "x-geo-audit-fixture-bytes"
HDR_BODY_MD5: Final = "x-geo-audit-fixture-md5"


@dataclass(frozen=True, slots=True)
class Snapshot:
    """一次完整 HTTP 交换的冻结形态（**一跳**，不是折叠后的最终响应）。"""

    canon_url: str
    #: 录制时请求的原始 URL（可能与 canon_url 差在大小写 / 默认端口上）
    url: str
    status: int
    headers: dict[str, str]
    body_storage: BodyStorage
    #: 正文的**完整**字节数（不是落盘字节数）
    body_bytes: int
    #: 完整正文的 md5（十六进制小写）。digest_only 档也有，这是它存在的意义
    raw_md5: str
    #: 实际落盘的字节数（full 档 == body_bytes；digest_only 档 == 0）
    stored_bytes: int
    path: str
    recorded_at: str
    body_file: str | None = None
    #: 这条是某个 URL 的对照探针时，指回被对照的 canon_url
    probe_for: str | None = None
    #: 录制时的传输层错误（status == 0 的那些）。重放时按它抛 httpx 异常
    transport_error: str | None = None
    handwritten: bool = False
    note: str | None = None
    comment: str | None = None
    expect: dict[str, Any] = field(default_factory=dict)
    drift: dict[str, Any] | None = None

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def body_is_complete(self) -> bool:
        return self.body_storage == "full"


# --------------------------------------------------------------------------- #
# FixtureStore
# --------------------------------------------------------------------------- #

INDEX_FILE: Final = "index.json"
DEFAULT_DNS_FILE: Final = "dns.json"
#: 第 4a 步自检用的 dns 样本文件名。真 ``dns.json`` 由 §8.2 那一步产出；
#: 它一落地，:class:`FixtureStore` 自动优先用 ``dns.json``，这里不需要改代码。
SAMPLE_DNS_FILE: Final = "dns.sample.json"
#: ``dns.json`` 里「不在表里的 host」的兜底键（§3.6）。
DNS_ABSENT_KEY: Final = "_default_absent"

INDEX_NOTE: Final = (
    "canon_url -> 快照相对路径 + probe_for 反查 + expect/drift 块。"
    "expect 是全项目唯一允许出现字面量摘要（md5/字节数）的地方，测试从这里读；"
    "改动请走 CONTRIBUTING.md 的 fixture 规程（§8.1 的 drift 四分支）。"
)
INDEX_SCHEMA: Final = 1

#: 索引条目里由 meta.json 机械派生的字段。``_rebuild_index`` 重算它们，
#: 其余字段（expect / drift / comment）是人工策展的，一律原样保留。
_DERIVED_KEYS: Final = (
    "path",
    "status",
    "content_type",
    "body_storage",
    "bytes",
    "raw_md5",
    "recorded_at",
    "probe_for",
    "transport_error",
    "handwritten",
)


#: 录制者的联系邮箱**会被目标站点回显进响应正文**。实测 7 条：youtube.com
#: 把 UA 塞进 `DEVICE` 配置串、pinterest 与 facebook 把它塞进页面内嵌 JSON 的
#: `user_agent` 字段。这些正文要进公开仓库，等于把私人邮箱发布出去。
#:
#: 所以在**落盘之前**替换掉，且摘要按脱敏后的字节算 —— 顺序反了就会得到一个
#: 对不上磁盘内容的 md5。
REDACTED_CONTACT = b"contact-redacted@example.invalid"
#: UA 整串的占位。见 redact_contact 里的理由。
REDACTED_UA = b"geo-audit/x.y.z (+https://example.invalid/geo-audit; contact: redacted)"
#: owner handle 的单独占位（第一步半的兜底，见 redact_contact）。
REDACTED_REPO_PATH = b"example.invalid/geo-audit-owner/geo-audit"


#: 同理：UA 里带着仓库 URL 与版本号，回显出来无所谓，但邮箱那一段要换掉。
#: URL 编码形态也要覆盖（youtube 回显的是 `contact%3A+x%40gmail.com`，
#: facebook 回显的是 `x` 加 JSON 转义的 at 符号 加 `gmail.com`）。
def redact_contact(body: bytes, contact: str, user_agent: str = "") -> tuple[bytes, int]:
    r"""把正文里回显出来的联系邮箱与 UA 换成占位符。返回 (脱敏后正文, 替换次数)。

    **顺序很重要，UA 必须先换。** 实测踩过：先把邮箱换成占位符之后，完整 UA 串里
    的邮箱那一段也跟着变了，于是 UA 整串再也匹配不上，``github.com/<owner>``
    那半就留在了正文里。两步互相破坏。

    邮箱覆盖四种形态：原样、URL 编码（``%40``）、JSON ``\u0040``、双转义。
    UA 覆盖三种：原样、JSON 里 ``/`` 转义成 ``\/``、整串 URL 编码。
    找不到就原样返回，零开销。
    """
    if not body:
        return body, 0
    n = 0

    # ── 第一步：UA 整串（必须在邮箱之前）──────────────────────────────────
    for ua in _ua_variants(user_agent):
        c = body.count(ua)
        if c:
            body = body.replace(ua, REDACTED_UA)
            n += c

    # ── 第一步半：owner handle 的兜底 ────────────────────────────────────
    # 上一步靠**整串** UA 匹配。如果正文已经被旧版本的脱敏动过一次（邮箱换了、
    # UA 整串因此对不上了），或者站点自己改写了 UA 的某一段，整串就命不中，
    # `github.com/<owner>` 那半会漏下来。实测踩过（facebook 那条）。
    # 所以再兜一层：把 UA 里的仓库路径单独换掉，形态同样覆盖 JSON 的 `\/` 转义。
    if user_agent:
        for repo in _repo_path_variants(user_agent):
            c = body.count(repo)
            if c:
                body = body.replace(repo, REDACTED_REPO_PATH)
                n += c

    # ── 第二步：残留的裸邮箱（UA 之外的回显位置）─────────────────────────
    if contact:
        local, _, domain = contact.partition("@")
        if domain:
            for v in (
                contact.encode(),
                f"{local}%40{domain}".encode(),
                f"{local}\\u0040{domain}".encode(),
                f"{local}\\\\u0040{domain}".encode(),
            ):
                c = body.count(v)
                if c:
                    body = body.replace(v, REDACTED_CONTACT)
                    n += c
    return body, n


def _repo_path_variants(ua: str) -> tuple[bytes, ...]:
    r"""从 UA 里抽出 ``github.com/<owner>/geo-audit`` 并给出它的两种形态。

    存在的理由见 ``redact_contact`` 第一步半：整串 UA 匹配会被「已经被脱敏动过
    一次的正文」打败，这一层单独兜住 owner handle。
    """
    m = re.search(r"github\.com/([^/\s)]+)/geo-audit", ua)
    if not m:
        return ()
    path = m.group(0)
    return (path.encode(), path.replace("/", "\\/").encode())


def _ua_variants(ua: str) -> tuple[bytes, ...]:
    r"""UA 串在正文里的三种形态：原样、JSON 里 ``/`` 被转义成 ``\/``、URL 编码。"""
    if not ua:
        return ()
    return (
        ua.encode(),
        ua.replace("/", "\\/").encode(),
        quote(ua, safe="").encode(),
    )


class FixtureStore:
    """``fixtures/`` 目录的读写口。

    读侧（测试与 ``--replay-fixtures``）：:meth:`get` / :meth:`body` / :meth:`expect` /
    :meth:`transport` / :meth:`probe_url` / :meth:`resolver`。
    写侧（``scripts/capture_fixtures.py``）：:meth:`put_snapshot` / :meth:`rebuild_index` /
    :meth:`write_dns`。
    """

    def __init__(self, root: Path | str, *, dns_file: str | None = None) -> None:
        self.root = Path(root)
        self._index: dict[str, dict[str, Any]] = {}
        self._meta: dict[str, Any] = {}
        self._probe_index: dict[str, str] = {}
        self._probe_by_host: dict[str, str] = {}
        self._dns: dict[str, dict[str, Any]] = {}
        self._dns_file_requested = dns_file
        self.dns_file: str | None = None
        self.reload()

    # -- 构造 ------------------------------------------------------------- #

    @classmethod
    def default(cls) -> FixtureStore:
        """按 ``GEO_AUDIT_FIXTURES`` -> 仓库内 ``fixtures/`` -> wheel 内
        ``geo_audit/_fixtures`` 的顺序找。

        wheel 那一档是卡点 B17b：smoke job 装 wheel 后跑 ``--replay-fixtures``，
        只 package ``src/geo_audit`` 会让它开箱就 FixtureMissing。
        """
        env = os.environ.get("GEO_AUDIT_FIXTURES")
        if env:
            return cls(Path(env))
        repo = Path(__file__).resolve().parents[2] / "fixtures"
        if (repo / INDEX_FILE).exists():
            return cls(repo)
        packaged = importlib.resources.files("geo_audit") / "_fixtures"
        if packaged.is_dir():
            return cls(Path(str(packaged)))
        raise FixtureMissing(
            "找不到 fixtures/ 目录（试过 $GEO_AUDIT_FIXTURES、仓库内 fixtures/、"
            "wheel 内 geo_audit/_fixtures）。录一份：\n  " + capture_command("https://example.com/")
        )

    def reload(self) -> None:
        """重新从磁盘读 index.json 与 dns 表。"""
        self._index = {}
        self._meta = {}
        index_path = self.root / INDEX_FILE
        if index_path.exists():
            doc = json.loads(index_path.read_text(encoding="utf-8"))
            snaps = doc.get("snapshots", {})
            if not isinstance(snaps, dict):
                raise FixtureError(f"{index_path} 的 snapshots 不是对象")
            self._index = {canon_url(k): dict(v) for k, v in snaps.items()}
            self._meta = {k: v for k, v in doc.items() if k != "snapshots"}
        self._rebuild_probe_lookup()
        self._load_dns()

    def _rebuild_probe_lookup(self) -> None:
        self._probe_index = {}
        self._probe_by_host = {}
        for canon, entry in sorted(self._index.items()):
            target = entry.get("probe_for")
            if not target:
                continue
            self._probe_index.setdefault(canon_url(str(target)), canon)
            host = urlsplit(canon).hostname or ""
            self._probe_by_host.setdefault(host, canon)

    def _load_dns(self) -> None:
        """读 DNS 表。

        显式传了 ``dns_file`` 就只认那一个；没传时优先 ``dns.json``，找不到才
        回落 ``dns.sample.json``（第 4a 步的手写样本）。真 ``dns.json`` 一落地，
        测试自动切过去，代码不动。
        """
        self._dns = {}
        self.dns_file = None
        candidates = (
            [self._dns_file_requested]
            if self._dns_file_requested
            else [DEFAULT_DNS_FILE, SAMPLE_DNS_FILE]
        )
        for name in candidates:
            path = self.root / str(name)
            if path.exists():
                doc = json.loads(path.read_text(encoding="utf-8"))
                self._dns = {
                    k: dict(v)
                    for k, v in doc.items()
                    if not k.startswith("_") or k == DNS_ABSENT_KEY
                }
                self.dns_file = str(name)
                return

    # -- 只读 API --------------------------------------------------------- #

    @property
    def index(self) -> Mapping[str, dict[str, Any]]:
        """``canon_url -> 索引条目``。测试从 ``store.index[url]["expect"]`` 读字面量。"""
        return self._index

    def snapshots(self) -> list[str]:
        """全部已录快照的 canon_url，排序后返回（第 4b 步的自验命令数它）。"""
        return sorted(self._index)

    def has(self, url: str) -> bool:
        return canon_url(url) in self._index

    def get(self, url: str) -> Snapshot:
        """取一条快照。**找不到就抛，绝不回落真网络。**"""
        canon = canon_url(url)
        entry = self._index.get(canon)
        if entry is None:
            raise FixtureMissing(
                f"没有 {canon} 的冻结快照（fixtures/index.json 里没这一条），"
                "而 fixture 层绝不静默回落真网络 —— 那会让离线 CI 变成不确定测试。\n"
                "补录（守 2.0s/域，需要真网络）：\n  " + capture_command(canon)
            )
        meta_path = self.root / (str(entry["path"]) + ".meta.json")
        if not meta_path.exists():
            raise FixtureMissing(
                f"index.json 里有 {canon}，但 {meta_path} 不在磁盘上"
                "（快照被删了？git-lfs 没拉全？）。补录：\n  " + capture_command(canon)
            )
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return self._snapshot_from(canon, entry, meta)

    def _snapshot_from(
        self, canon: str, entry: Mapping[str, Any], meta: Mapping[str, Any]
    ) -> Snapshot:
        storage: BodyStorage = meta["body_storage"]
        return Snapshot(
            canon_url=canon,
            url=str(meta.get("url", canon)),
            status=int(meta["status"]),
            headers={str(k).lower(): str(v) for k, v in dict(meta.get("headers", {})).items()},
            body_storage=storage,
            body_bytes=int(meta["body_bytes"]),
            raw_md5=str(meta["raw_md5"]),
            stored_bytes=int(meta.get("stored_bytes", 0)),
            path=str(entry["path"]),
            recorded_at=str(meta.get("recorded_at", "")),
            body_file=(str(meta["body_file"]) if meta.get("body_file") else None),
            probe_for=(str(meta["probe_for"]) if meta.get("probe_for") else None),
            transport_error=(str(meta["transport_error"]) if meta.get("transport_error") else None),
            handwritten=bool(meta.get("handwritten", False)),
            note=(str(meta["note"]) if meta.get("note") else None),
            comment=(str(entry["comment"]) if entry.get("comment") else None),
            expect=dict(entry.get("expect") or {}),
            drift=(dict(entry["drift"]) if entry.get("drift") else None),
        )

    def body(self, url: str) -> bytes:
        """完整正文。``body_storage != "full"`` 时抛 :class:`BodyNotStored`。

        这条**故意**不给退路：截断正文算出来的哈希跟完整正文的哈希不同，
        那是测量假象不是发现。要 size/md5，用 :meth:`digests`。
        """
        snap = self.get(url)
        if snap.body_storage != "full":
            raise BodyNotStored(
                f"{snap.canon_url} 的正文是 {snap.body_storage} 档"
                f"（完整 {snap.body_bytes:,} 字节，落盘 {snap.stored_bytes:,} 字节），"
                "依赖正文或归一化哈希的断言不许用它。"
                "只要 size/md5 就用 store.digests(url)；"
                "真要完整正文，改 body_storage 阈值并重录。"
            )
        return self._read_stored_body(snap)

    def stored_body(self, url: str) -> bytes:
        """**落盘的那部分**正文（full 档是全量，truncated 档是前 256 KiB，
        digest_only 档是空）。只有 :meth:`transport` 与展示用得上它。"""
        return self._read_stored_body(self.get(url))

    def _read_stored_body(self, snap: Snapshot) -> bytes:
        if snap.body_file is None:
            return b""
        path = self.root / snap.body_file
        if not path.exists():
            raise FixtureMissing(
                f"{snap.canon_url} 的正文文件 {path} 不在磁盘上。补录：\n  "
                + capture_command(snap.canon_url)
            )
        with gzip.open(path, "rb") as fh:
            return fh.read()

    def digests(self, url: str) -> dict[str, Any]:
        """完整正文的 ``{"raw_md5": ..., "bytes": ...}``，三档都可用。

        ``check_llms_full`` 在 truncated / digest_only 档上只能用这个 —— 它是
        录制时对**完整流**算的，不是对截断正文算的。
        """
        snap = self.get(url)
        return {"raw_md5": snap.raw_md5, "bytes": snap.body_bytes}

    def expect(self, url: str) -> dict[str, Any]:
        """这条快照的 ``expect`` 块（字面量断言的唯一出处）。"""
        return dict(self._entry(url).get("expect") or {})

    def drift(self, url: str) -> dict[str, Any] | None:
        d = self._entry(url).get("drift")
        return dict(d) if d else None

    def _entry(self, url: str) -> dict[str, Any]:
        canon = canon_url(url)
        entry = self._index.get(canon)
        if entry is None:
            raise FixtureMissing(f"没有 {canon} 的索引条目。补录：\n  " + capture_command(canon))
        return entry

    def check_expect(self, url: str, *, raw_md5: str, body_bytes: int) -> list[str]:
        """把刚录到的值与 ``expect`` 对账，返回不符项的人话描述（空 = 一致）。

        ``refresh_fixtures.py`` 用它决定该走 :data:`DRIFT_PLAYBOOK` 的哪个分支。
        """
        exp = self.expect(url)
        out: list[str] = []
        if "raw_md5" in exp and str(exp["raw_md5"]) != raw_md5:
            out.append(f"raw_md5: expect {exp['raw_md5']} -> 实测 {raw_md5}")
        if "bytes" in exp and int(exp["bytes"]) != body_bytes:
            out.append(f"bytes: expect {exp['bytes']:,} -> 实测 {body_bytes:,}")
        return out

    def probe_url_lenient(self, url: str) -> str:
        """:meth:`probe_url` 的宽容版：同 host 没录过探针时**不抛**，返回一个
        必然缺快照的合成 URL。

        为什么需要它：``discover()`` 会枚举 16 个子域前缀（help / support /
        api-docs / …），每个活着的 host 都要一条对照探针。那是有限集，但 §8.2 的
        urls.txt 只录了实测涉及的那些 —— 一个从没出现在实测里的子域（比如
        ``help.mistral.ai``）缺探针是**正常的**，不该让整份报告产不出来。

        返回的合成 URL 在 ``strict=False`` 的 transport 下会拿到 599，于是
        ``host_profile`` 判 ``control_unavailable``，那个位置走 UNKNOWN ——
        正是「我们没能做对照探测」该有的结论。

        ``strict`` 版仍然存在且仍然抛：测试与 fixture 完整性检查用它。
        """
        try:
            return self.probe_url(url)
        except FixtureMissing:
            parts = urlsplit(canon_url(url))
            token = hashlib.sha256(f"lenient|{parts.netloc}".encode()).hexdigest()[:24]
            return urlunsplit((parts.scheme, parts.netloc, f"/geo-audit-probe-{token}", "", ""))

    def probe_url(self, url: str) -> str:
        """录制时那条对照探针 URL（喂 ``Fetcher(probe_url_provider=...)``）。

        先按 ``probe_for`` 精确反查；同 host 录过别的探针就用那一条（对照探针
        的语义是「这个 host 拿一个不可能存在的路径怎么回」，同 host 通用，
        而且 ``host_profile`` 本身就是按 host 缓存的）。都没有才抛。
        """
        canon = canon_url(url)
        hit = self._probe_index.get(canon)
        if hit is not None:
            return hit
        host = urlsplit(canon).hostname or ""
        by_host = self._probe_by_host.get(host)
        if by_host is not None:
            return by_host
        raise FixtureMissing(
            f"没有 {canon} 的对照探针快照（index.json 里没有 probe_for 指向它的条目）。"
            "对照探测是软 404 判据的一半，缺了它整条判定都不成立。\n"
            f"在 fixtures/urls.txt 里该 URL 后面加一行 `@control {canon}` 然后：\n  "
            + capture_command(canon)
        )

    # -- httpx 重放 ------------------------------------------------------- #

    def transport(self, *, strict: bool = True) -> httpx.MockTransport:
        """喂给 ``Fetcher(transport=...)`` 的重放 transport。

        逐跳重放：3xx 那一跳原样带着 ``Location`` 返回，由
        ``Fetcher._fetch_chain`` 自己跟下去，于是「必须跟随 3xx」也被测到。

        ``strict``（默认 True）—— 缺快照抛 :class:`FixtureMissing`。测试与
        「探测集里的固定位置」用这个：那些位置缺快照说明 fixture 不全，是**我们的**
        问题，必须当场红。

        ``strict=False`` —— 缺快照返回一条 ``599 + x-geo-audit-fixture: missing``
        的合成响应，让判定层走 ``not_fetched`` / UNKNOWN。**这不是放宽纪律**：
        站内抓到的链接是无穷集（mistral.ai 首页上百条），一条条录既不可能也没意义，
        而「没录 = 没看过 = UNKNOWN」正是 ``not_fetched`` 本来的语义。
        区别在于**谁的问题**：探测位置缺快照是我们的，站内链接缺快照是事实。

        599 这个码刻意选在 5xx 段外的自定义区：``NOT_EVALUATED_REASONS`` 会把
        它归到「未能评估」，不会被误判成「站点 500 了」。
        """
        if strict:
            return httpx.MockTransport(self.replay)
        return httpx.MockTransport(self._replay_lenient)

    #: ``strict=False`` 下缺快照时的合成状态码。见 :meth:`transport`。
    MISSING_STATUS = 599

    def _replay_lenient(self, request: httpx.Request) -> httpx.Response:
        """缺快照 -> 599 合成响应（而不是抛异常）。见 :meth:`transport`。"""
        try:
            return self.replay(request)
        except FixtureMissing:
            return httpx.Response(
                self.MISSING_STATUS,
                headers={
                    "content-type": "text/plain",
                    "x-geo-audit-fixture": "missing",
                },
                content=b"fixture missing: this URL was never recorded",
                request=request,
            )

    def replay(self, request: httpx.Request) -> httpx.Response:
        """一条请求 -> 一条冻结响应。缺快照就抛 :class:`FixtureMissing`。"""
        url = self.url_of_request(request)
        snap = self.get(url)

        if snap.transport_error:
            # 录到的是传输层失败（status == 0）。重放成同类异常，让
            # Fetcher 的 DNS 二次意见 / 重试路径也跑得到。
            err = snap.transport_error
            if err.startswith("timeout"):
                raise httpx.ConnectTimeout(err, request=request)
            raise httpx.ConnectError(err, request=request)

        headers = {k: v for k, v in snap.headers.items() if k not in REPLAY_STRIPPED_HEADERS}
        headers[HDR_BODY_STORAGE] = snap.body_storage
        headers[HDR_BODY_BYTES] = str(snap.body_bytes)
        headers[HDR_BODY_MD5] = snap.raw_md5
        return httpx.Response(
            snap.status,
            headers=headers,
            content=self._read_stored_body(snap),
            request=request,
        )

    @staticmethod
    def url_of_request(request: httpx.Request) -> str:
        """请求 -> 索引键。

        ``resolve.R2`` 会把请求打到 IP 上、用 ``Host`` 头保留原域名
        （等价 ``curl --resolve``）。索引键必须是原域名那条，否则 pin 过的重试
        永远命不中快照。
        """
        parts = urlsplit(str(request.url))
        host_header = request.headers.get("host", "")
        if host_header and host_header.split(":")[0].lower() != (parts.hostname or "").lower():
            return canon_url(urlunsplit((parts.scheme, host_header, parts.path, parts.query, "")))
        return canon_url(str(request.url))

    # -- DNS -------------------------------------------------------------- #

    @property
    def dns(self) -> Mapping[str, dict[str, Any]]:
        return self._dns

    def resolver(self) -> FixtureResolver:
        """喂给 ``resolve_host(host, resolver=...)`` / ``discover(resolver=...)``。"""
        if not self._dns:
            raise DnsFixtureMissing(
                f"{self.root} 下既没有 {DEFAULT_DNS_FILE} 也没有 {SAMPLE_DNS_FILE}。"
                "离线 CI（GEO_AUDIT_FORBID_DNS=1）必须有冻结的 DNS 答案。录一份：\n"
                "  python scripts/capture_fixtures.py --contact you@example.com "
                "--from-file fixtures/urls.txt --dns-only"
            )
        return FixtureResolver(self._dns, source=str(self.root / (self.dns_file or "")))

    def write_dns(self, table: Mapping[str, Mapping[str, Any]], *, note: str | None = None) -> Path:
        """写 DNS 表（``capture_fixtures.py --dns-only`` 用）。"""
        name = self._dns_file_requested or DEFAULT_DNS_FILE
        path = self.root / name
        doc: dict[str, Any] = {
            "_note": note
            or (
                "冻结的 DNS 答案（§3.6）。IP 会变，所以 resolved_ips 在 VOLATILE_JSON_FIELDS "
                "里、不进确定性比对；这里冻结的是 ok / poisoned / resolver 三个决策位。"
            )
        }
        for host in sorted(table):
            doc[host] = dict(table[host])
        _write_json(path, doc)
        self.reload()
        return path

    # -- 写侧 ------------------------------------------------------------- #

    def put_snapshot(
        self,
        url: str,
        *,
        status: int,
        headers: Mapping[str, str],
        body: bytes = b"",
        body_bytes: int | None = None,
        raw_md5: str | None = None,
        recorded_at: str | None = None,
        probe_for: str | None = None,
        transport_error: str | None = None,
        comment: str | None = None,
        handwritten: bool = False,
        note: str | None = None,
        overwrite: bool = False,
        contact: str | None = None,
        user_agent: str | None = None,
    ) -> Snapshot:
        """落一条快照并更新索引。**默认不覆盖已有快照。**

        已冻结的快照是断言的一部分，覆盖它等于改测试 —— 所以默认命中就原样
        返回旧的（``overwrite=False``）。要覆盖必须显式 ``--overwrite``，且
        单独一个 commit，message 前缀 ``fixture:``（CONTRIBUTING.md）。

        ``body`` 传**完整**正文；档位、截断、digest 由本方法算。正文大到不想
        留在内存里时（digest_only 档），传 ``body=b""`` 加 ``body_bytes`` 与
        ``raw_md5``（边流边算的那两个值）。
        """
        canon = canon_url(url)
        if canon in self._index and not overwrite:
            return self.get(canon)

        # 脱敏必须在算 total / digest **之前** —— 摘要要对得上磁盘上的字节。
        redacted = 0
        if contact and body:
            body, redacted = redact_contact(body, contact, user_agent or "")
            if redacted:
                # 脱敏改了长度，调用方传进来的 body_bytes / raw_md5 就作废了。
                body_bytes = None
                raw_md5 = None

        total = len(body) if body_bytes is None else body_bytes
        if body_bytes is not None and body and len(body) > body_bytes:
            raise ValueError("body 比声明的 body_bytes 还长")
        storage = body_storage_for(total)
        digest = raw_md5 or hashlib.md5(body, usedforsecurity=False).hexdigest()

        stem = snapshot_path(canon)
        meta_path = self.root / f"{stem}.meta.json"
        meta_path.parent.mkdir(parents=True, exist_ok=True)

        body_file: str | None = None
        stored = b""
        if storage == "full":
            stored = body
        elif storage == "truncated":
            stored = body[:TRUNCATED_PREFIX_BYTES]
        if storage != "digest_only" and transport_error is None:
            body_file = f"{stem}.body.gz"
            _write_gzip(self.root / body_file, stored)
        elif storage == "digest_only":
            # 正文不落盘，但把「有多大、md5 是什么」留住 —— 这正是这一档的意义。
            stale = self.root / f"{stem}.body.gz"
            stale.unlink(missing_ok=True)

        lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        meta = {
            "canon_url": canon,
            "url": url,
            "status": status,
            "headers": lower_headers,
            "body_storage": storage,
            "body_bytes": total,
            "stored_bytes": len(stored) if body_file else 0,
            "raw_md5": digest,
            "body_file": body_file,
            "probe_for": canon_url(probe_for) if probe_for else None,
            "transport_error": transport_error,
            "recorded_at": recorded_at or _now(),
            "handwritten": handwritten,
            "note": note,
        }
        _write_json(meta_path, meta)

        prev = self._index.get(canon, {})
        entry: dict[str, Any] = {
            "path": stem,
            "status": status,
            "content_type": lower_headers.get("content-type", "").split(";")[0].strip(),
            "body_storage": storage,
            "bytes": total,
            "raw_md5": digest,
            "recorded_at": meta["recorded_at"],
            "probe_for": meta["probe_for"],
            "transport_error": transport_error,
            "handwritten": handwritten,
            "comment": comment if comment is not None else prev.get("comment"),
            # expect / drift 是人工策展的：已有就一个字不动（漂移规程要求
            # 「改的是 index.json 一处」，而改它的是 refresh_fixtures.py + 人，
            # 不是录制脚本）。第一次录才播种。
            "expect": dict(prev.get("expect") or {"raw_md5": digest, "bytes": total}),
            "drift": dict(prev["drift"]) if prev.get("drift") else None,
        }
        self._index[canon] = entry
        self._write_index()
        self._rebuild_probe_lookup()
        return self.get(canon)

    def rebuild_index(self) -> list[str]:
        """从磁盘上的 ``*.meta.json`` 重建 index.json。**幂等**。

        机械派生的字段（见 :data:`_DERIVED_KEYS`）重算，人工策展的
        ``expect`` / ``drift`` / ``comment`` 原样保留。所以连跑两次
        ``git diff --exit-code fixtures/index.json`` 退出 0（门禁 M）。
        """
        found: dict[str, dict[str, Any]] = {}
        for meta_path in sorted((self.root / "snapshots").rglob("*.meta.json")):
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            canon = canon_url(str(meta["canon_url"]))
            stem = meta_path.relative_to(self.root).as_posix()[: -len(".meta.json")]
            prev = self._index.get(canon, {})
            lower_headers = {str(k).lower(): str(v) for k, v in dict(meta["headers"]).items()}
            entry = {k: v for k, v in prev.items() if k not in _DERIVED_KEYS}
            entry.update(
                {
                    "path": stem,
                    "status": int(meta["status"]),
                    "content_type": lower_headers.get("content-type", "").split(";")[0].strip(),
                    "body_storage": meta["body_storage"],
                    "bytes": int(meta["body_bytes"]),
                    "raw_md5": str(meta["raw_md5"]),
                    "recorded_at": str(meta.get("recorded_at", "")),
                    "probe_for": meta.get("probe_for"),
                    "transport_error": meta.get("transport_error"),
                    "handwritten": bool(meta.get("handwritten", False)),
                }
            )
            entry.setdefault("comment", None)
            entry.setdefault("expect", {"raw_md5": entry["raw_md5"], "bytes": entry["bytes"]})
            entry.setdefault("drift", None)
            found[canon] = entry
        dropped = sorted(set(self._index) - set(found))
        self._index = found
        self._write_index()
        self._rebuild_probe_lookup()
        return dropped

    def _write_index(self) -> None:
        doc: dict[str, Any] = dict(self._meta)
        doc.setdefault("_note", INDEX_NOTE)
        doc.setdefault("_schema", INDEX_SCHEMA)
        doc["snapshots"] = {k: self._index[k] for k in sorted(self._index)}
        self._meta = {k: v for k, v in doc.items() if k != "snapshots"}
        _write_json(self.root / INDEX_FILE, doc)

    def set_index_meta(self, **meta: Any) -> None:
        """设 index.json 顶层的 ``_`` 开头字段（``_note`` / ``_handwritten`` 之类）。

        存在的理由：手写自检目录必须能在文件里自己说清「我不是实录」。
        """
        for key, value in meta.items():
            if not key.startswith("_"):
                raise ValueError(f"index.json 顶层只放 _ 开头的元字段，{key!r} 不合规")
            self._meta[key] = value
        self._write_index()

    def set_expect(self, url: str, expect: Mapping[str, Any]) -> None:
        """改 ``expect`` 块（漂移分支「值变了、现象没变」）。"""
        self._entry(url)["expect"] = dict(expect)
        self._write_index()

    def set_drift(self, url: str, drift: Mapping[str, Any] | None) -> None:
        """写 ``drift`` 记录。``phenomenon`` 必须是 :data:`DRIFT_PHENOMENA` 之一。"""
        if drift is not None:
            phenomenon = str(drift.get("phenomenon", ""))
            if phenomenon not in DRIFT_PHENOMENA:
                raise ValueError(
                    f"drift.phenomenon={phenomenon!r} 不是 {DRIFT_PHENOMENA} 之一。"
                    "四个分支该走哪个见 §8.1 的表（DRIFT_PLAYBOOK）"
                )
        self._entry(url)["drift"] = dict(drift) if drift else None
        self._write_index()


# --------------------------------------------------------------------------- #
# DNS 重放
# --------------------------------------------------------------------------- #


class FixtureResolver:
    """从 ``fixtures/dns.json`` 回放 DNS（§3.6）。

    落在这里而不是 ``fetch/resolve.py``：``resolve_host`` 的 docstring 已经
    把它排在「第 4a 步随 fixture 层落地」，而它读的是 fixture 的磁盘布局。
    对 ``resolve_host(host, resolver=...)`` 而言它只需满足 ``HostResolver``
    协议（``(str) -> Resolution``），放哪个模块不影响调用方。

    不在表里的 host 走 ``_default_absent``（NXDOMAIN），于是「不存在的子域花
    0 个 HTTP 请求」这条逻辑在 replay 下也测得到。
    """

    def __init__(
        self, table: Mapping[str, Mapping[str, Any]], *, source: str = "fixtures/dns.json"
    ) -> None:
        self._table = {
            str(k).lower().strip("."): dict(v)
            for k, v in table.items()
            if not str(k).startswith("_") or str(k) == DNS_ABSENT_KEY
        }
        self.source = source

    def __call__(self, host: str) -> Resolution:
        key = host.lower().strip(".")
        row = self._table.get(key)
        if row is None:
            row = self._table.get(DNS_ABSENT_KEY)
        if row is None:
            raise DnsFixtureMissing(
                f"{self.source} 里没有 {key}，也没有 {DNS_ABSENT_KEY} 兜底。"
                "urls.txt 里出现过的每个 host 都必须在 dns.json 里有条目（§8.1 决定 4）。"
                "补录：\n  python scripts/capture_fixtures.py "
                "--contact you@example.com --from-file fixtures/urls.txt --dns-only"
            )
        addresses = tuple(str(a) for a in row.get("addresses", ()))
        return Resolution(
            host=key,
            addresses=addresses,
            resolver=str(row.get("resolver", "none")),
            poisoned=bool(row.get("poisoned", False)),
            error=(str(row["error"]) if row.get("error") else None),
        )

    def hosts(self) -> set[str]:
        return {h for h in self._table if h != DNS_ABSENT_KEY}


# --------------------------------------------------------------------------- #
# 确定性抽样（@expand 用）
# --------------------------------------------------------------------------- #


def sample_deterministic(items: list[str], limit: int, *, seed: str) -> list[str]:
    """从 ``items`` 里确定性地抽 ``limit`` 条（超了才抽，不够就全给）。

    ``@expand https://www.bytebase.com/llms.txt relative 60`` 那条正文里有 504
    条相对路径，只录抽中的 60 条。抽样必须确定性，否则「补录一次换一批 URL」
    会让 index.json 每次 diff 都是全量。
    """
    uniq = sorted(dict.fromkeys(items))
    if len(uniq) <= limit:
        return uniq
    rnd = random.Random(seed)  # noqa: S311 —— 抽样，非密码学用途
    return sorted(rnd.sample(uniq, limit))


# --------------------------------------------------------------------------- #
# 落盘工具
# --------------------------------------------------------------------------- #


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, doc: Mapping[str, Any]) -> None:
    """确定性 JSON：sort_keys + indent=2 + 末尾换行。

    ``sort_keys`` 是幂等的前提：同样的内容必须产生同样的字节，否则
    ``git diff --exit-code fixtures/index.json`` 会因为键序抖动而红。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")


def _write_gzip(path: Path, data: bytes) -> None:
    """gzip 落盘，``mtime=0``。

    ``mtime=0`` 是「字节可复现、git diff 干净」的全部理由：默认的 gzip 头里带
    当前时间戳，同一份正文录两次会得到两个不同的文件。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as fh:
        fh.write(data)
    path.write_bytes(buf.getvalue())
