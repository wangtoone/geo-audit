"""§5.5 修复建议（IMPLEMENTATION-v2.md 行 2915–2941）。

四个候选变换，**每个最多 1 次请求，命中 200 即停，上限 4 请求/条**，且只对
``severity >= MEDIUM`` 的死链做：

    a) 换 host：www ↔ docs ↔ apex   bytebase：www.bytebase.com/introduction/what-is-bytebase
                                    404 → docs.bytebase.com 同名路径 **200**
    b) 剥掉重复的路径前缀           canvasmedical：/product-updates/release-notes/sdk/
                                    layout-effect/ → /sdk/layout-effect/ **200**
    c) 去掉最后一段                 brevo：/docs/api-clients/python 404 → /docs/api-clients **200**
    d) sitemap.xml 里最近似路径     tdengine：新路径 /developer-guide/connectors-reference/*
                                    就在 sitemap 里

**这一层唯一会真伤人的失败模式是幻觉出一个不存在的修复目标。** 所以：
``after`` 必须是我们**实际请求过并返回 200**（且判定不是软 404）的地址；四个候选
全不命中就 ``fix=None`` + ``NO_FIX_MESSAGE``，绝不编一个。``verified_target`` 为
False 的建议由 ``reportable_fix`` 机械挡掉，一条都不许进报告。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import urlsplit

from .models import Expect, FixHint, Probe, Severity, Verdict
from .rootcause import (
    SEVERITY_ORDER,
    edit_distance,
    normalize_url,
    path_segments,
    url_host,
    with_path,
)

#: 单条 fixhint 的请求上限（§5.5:2917）。四个候选各最多 1 次。
FIXHINT_MAX_REQUESTS = 4

#: 只对 ``severity >= MEDIUM`` 的死链做（§5.5:2917）。
FIXHINT_MIN_SEVERITY = Severity.MEDIUM

#: 候选 d) 的「最近似」判据（§5.5:2940，v1 未定义）：sitemap 里所有路径按
#: ``(末段完全相同, 末段编辑距离, 公共前缀段数)`` 三元组排序取第一个；
#: **末段编辑距离 > 3 时视为不命中**。
NEAREST_LAST_SEGMENT_MAX_DISTANCE = 3

#: 四个候选全不命中时报告卡片上的原话（§5.5:2937，逐字照抄）。
NO_FIX_MESSAGE = "我们没找到明显的正确目标；这个路径在你的 sitemap.xml 里也没有近似项"

CandidateId = Literal["a_swap_host", "b_strip_dup_prefix", "c_drop_last_segment", "d_sitemap_near"]

#: 候选的判定顺序 = 规格表的行序。
CANDIDATE_ORDER: tuple[CandidateId, ...] = (
    "a_swap_host",
    "b_strip_dup_prefix",
    "c_drop_last_segment",
    "d_sitemap_near",
)

CANDIDATE_LABEL: dict[str, str] = {
    "a_swap_host": "换 host（www ↔ docs ↔ apex）",
    "b_strip_dup_prefix": "剥掉重复的路径前缀",
    "c_drop_last_segment": "去掉最后一段",
    "d_sitemap_near": "sitemap.xml 里最近似路径",
}


class Prober(Protocol):
    """``fetch.client.Fetcher`` 的结构化子集（与 ``checks.ai_path.Prober`` 同源）。

    只要 ``probe`` 一个方法：候选验证要的就是「这个地址我们真请求过，回的是 200」。
    """

    def probe(
        self,
        url: str,
        *,
        expect: Expect = ...,
        liveness_only: bool = ...,
    ) -> Probe: ...


@dataclass(frozen=True, slots=True)
class FixAttempt:
    """一次候选尝试的账本。报告不印它，但 A21/§5.5 的「≤4 请求」靠它可测。"""

    candidate: str
    url: str
    status: int | None
    verdict: Verdict
    hit: bool


@dataclass(frozen=True, slots=True)
class FixResult:
    """``suggest_fix`` 的完整结果。``hint`` 为 None 时 ``message`` 是给甲方的原话。"""

    hint: FixHint | None
    attempts: tuple[FixAttempt, ...]
    message: str = ""
    skipped_reason: str = ""

    @property
    def requests(self) -> int:
        return len(self.attempts)


def severity_at_least(severity: Severity, floor: Severity) -> bool:
    """``severity >= floor``。models.py 的 Severity 只有枚举没有序，序在 rootcause。"""
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[floor]


def sibling_host(host: str) -> str | None:
    """候选 a) 的**唯一**兄弟 host —— 每个候选最多 1 次请求，所以只能挑一个。

    实测口径：www./apex 的对面是 ``docs.``（bytebase 那条就是 www → docs 命中 200）；
    docs./developers./api. 的对面是 ``www.``。挑不出就返回 None（不花请求）。
    """
    host = host.lower()
    if not host or "." not in host:
        return None
    labels = host.split(".")
    first = labels[0] + "."
    if first in ("docs.", "developers.", "api."):
        return "www." + ".".join(labels[1:])
    if first == "www.":
        return "docs." + ".".join(labels[1:])
    return "docs." + host  # apex


def swap_host(url: str) -> str | None:
    """候选 a)。"""
    sibling = sibling_host(url_host(url))
    if sibling is None:
        return None
    parts = urlsplit(url)
    return f"{parts.scheme}://{sibling}{parts.path}"


def strip_duplicated_prefix(url: str, source_page: str) -> str | None:
    """候选 b)：目标路径以**当前页路径**开头时剥掉那一段。

    canvasmedical 实测：页面 ``/product-updates/release-notes/`` 上写了相对路径
    ``sdk/layout-effect/``，浏览器拼成 ``/product-updates/release-notes/sdk/
    layout-effect/`` → 404，而 ``/sdk/layout-effect/`` 是 200。
    """
    if url_host(url) != url_host(source_page):
        return None
    src = path_segments(source_page)
    tgt = path_segments(url)
    if not src or len(tgt) <= len(src) or tgt[: len(src)] != src:
        return None
    rest = "/" + "/".join(tgt[len(src) :])
    if urlsplit(url).path.endswith("/"):
        rest += "/"
    return with_path(url, rest)


def drop_last_segment(url: str) -> str | None:
    """候选 c)：brevo ``/docs/api-clients/python`` → ``/docs/api-clients``。"""
    segs = path_segments(url)
    if len(segs) < 2:
        return None
    return with_path(url, "/" + "/".join(segs[:-1]))


def nearest_sitemap_url(url: str, sitemap_urls: Sequence[str]) -> str | None:
    """候选 d)：§5.5:2940 的三元组排序 —— ``(末段完全相同, 末段编辑距离, 公共前缀段数)``。

    末段编辑距离 > ``NEAREST_LAST_SEGMENT_MAX_DISTANCE`` 视为不命中（返回 None），
    这样「sitemap 里根本没近似项」不会被硬凑出一个建议来。
    """
    segs = path_segments(url)
    if not segs or not sitemap_urls:
        return None
    last = segs[-1].lower()
    target_path = urlsplit(normalize_url(url)).path

    ranked: list[tuple[int, int, int, str]] = []
    for candidate in sitemap_urls:
        cand_segs = path_segments(candidate)
        if not cand_segs:
            continue
        if urlsplit(normalize_url(candidate)).path == target_path:
            continue  # 就是它自己，不算修复目标
        cand_last = cand_segs[-1].lower()
        dist = edit_distance(last, cand_last)
        if dist > NEAREST_LAST_SEGMENT_MAX_DISTANCE:
            continue
        shared = 0
        for x, y in zip(segs, cand_segs, strict=False):
            if x != y:
                break
            shared += 1
        # 排序键：末段完全相同优先（0 在前）、编辑距离小优先、公共前缀多优先，
        # 末位用 URL 自身兜底保证确定性。
        ranked.append((0 if dist == 0 else 1, dist, -shared, candidate))
    if not ranked:
        return None
    ranked.sort()
    return ranked[0][3]


def reportable_fix(hint: FixHint | None) -> FixHint | None:
    """**机械闸门：``verified_target`` 为 False 的建议一律不进报告。**

    幻觉出一个不存在的修复目标是这一层唯一会真伤人的失败模式 —— 甲方按着改，
    改到另一个 404。所以报告层只许通过这个函数取 fix：``after`` 空、或
    ``verified_target`` 不为 True，都当作「没有建议」。
    """
    if hint is None or not hint.verified_target or not hint.after:
        return None
    return hint


def _hit(probe: Probe) -> bool:
    """命中 = 实际请求回了 200 **且**判定不是软 404。

    只看 200 会把兜底壳页当成修复目标（canvasmedical 主站 llms.txt 就是 200 的壳），
    那正好是本工具存在的理由，不能自己踩。
    """
    resp = probe.response
    return resp is not None and resp.status == 200 and probe.verdict is Verdict.OK


def suggest_fix(
    url: str,
    *,
    source_page: str = "",
    severity: Severity = Severity.MEDIUM,
    prober: Prober,
    sitemap_urls: Sequence[str] = (),
    locator: str = "",
    max_requests: int = FIXHINT_MAX_REQUESTS,
) -> FixResult:
    """对一条死链跑四个候选，命中 200 即停。

    ``url`` 传死链的 ``abs_url``（探测一律用原样 URL）。返回的 ``FixResult.hint``
    要么是 ``verified_target=True`` 的建议，要么是 None —— 没有第三种。
    """
    if not severity_at_least(severity, FIXHINT_MIN_SEVERITY):
        return FixResult(None, (), skipped_reason="severity_below_medium")

    plans: dict[str, str | None] = {
        "a_swap_host": swap_host(url),
        "b_strip_dup_prefix": strip_duplicated_prefix(url, source_page) if source_page else None,
        "c_drop_last_segment": drop_last_segment(url),
        "d_sitemap_near": nearest_sitemap_url(url, sitemap_urls),
    }

    attempts: list[FixAttempt] = []
    tried: set[str] = {normalize_url(url)}
    for candidate in CANDIDATE_ORDER:
        if len(attempts) >= max_requests:
            break
        after = plans[candidate]
        if after is None:
            continue
        key = normalize_url(after)
        if key in tried:
            continue  # 同一个地址不重复花请求
        tried.add(key)
        probe = prober.probe(after, expect=Expect.ANY, liveness_only=True)
        resp = probe.response
        hit = _hit(probe)
        attempts.append(
            FixAttempt(
                candidate=candidate,
                url=after,
                status=resp.status if resp is not None else None,
                verdict=probe.verdict,
                hit=hit,
            )
        )
        if not hit:
            continue
        hint = FixHint(
            action=(f"把这个链接的 href 改成 {after}（已验证 200）——{CANDIDATE_LABEL[candidate]}"),
            open_this=source_page or url,
            locator=locator or (f"锚点指向 {url}"),
            before=url,
            after=after,
            verified_target=True,
        )
        return FixResult(reportable_fix(hint), tuple(attempts))

    return FixResult(None, tuple(attempts), message=NO_FIX_MESSAGE)
