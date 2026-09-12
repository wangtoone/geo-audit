"""C3 · AI 路径体检的四个子检查（IMPLEMENTATION-v2.md §4.1–§4.4，行 1925–2374）。

四个子检查全部机械可判、零 LLM：

1. §4.1 路径真伪（软 404）—— ``check_ai_paths`` / ``has_ai_channel`` /
   ``collect_secondary_reasons`` / ``ai_path_position_seeds``（P2 原料）。
2. §4.2 llms-full 造假 —— ``check_llms_full``。
3. §4.3 索引内链存活 —— ``parse_index_links`` / ``sample_index_links`` /
   ``grade`` / ``probe_index_links`` / ``check_index_links``。
4. §4.4 ``.md`` 约定兑现 —— ``MdDeclaration`` / ``MdSample`` /
   ``detect_md_signal_from_page`` / ``sample_md_targets`` / ``judge_md_sample`` /
   ``finalize`` / ``check_md_convention``。

外加**产品核心卖点**：每条 finding 都挂一行 ``NaiveContrast``——「一个只探根路径、
只看最终状态码、不做对照探测的工具在同一批响应上会得出什么结论」。实测朴素
checker 把 llms.txt 采纳率读成 76%、真实 60%，这行就是那 16 个百分点的凭证。

⚠️ 本文件顶部有一段**占位区**（Stage / Severity / PositionClass / Evidence /
FixHint / Finding / make_finding_id / UNKNOWN_REMEDY）。它们的正式定义应在
``src/geo_audit/models.py``（§2.5–§2.10），当前那个文件里还没有。见占位区的横幅。
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Literal, Protocol, cast
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..fetch.classify import (
    find_notfound_copy,
    find_platform_missing,
    looks_like_html,
    redirect_discarded_path,
)
from ..fetch.denoise import EligibilityExclusion, classify_link_eligibility
from ..fetch.normalize import (
    MIN_SIMILARITY_LEN,
    MIN_STRUCT_TAGS,
    norm_sha256,
    normalize_body,
    similarity_norm,
    structural_fingerprint,
    visible_text,
)
from ..models import (
    FINDING_KINDS,
    TOOL_VERSION,
    UNKNOWN_REMEDY,
    Evidence,
    Expect,
    Finding,
    FindingKind,
    FixHint,
    HostProfile,
    HttpResponse,
    LinkContext,
    NaiveContrast,
    PositionClass,
    PositionSeed,
    Probe,
    Reason,
    RedirectHop,
    Severity,
    Stage,
    Status,
    Verdict,
    make_finding_id,
    verdict_to_status,
)

# 兑现本文件原注释里的承诺：「第 13 步 rootcause.normalize_url 落地后本函数改为
# re-export，不许两份口径并存 —— 归并键分叉会让 finding 身份跟着分叉。」
from ..rootcause import normalize_url

# ═════════════════════════════════════════════════════════════════════════════
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║ 占位区开始 —— PLACEHOLDER BLOCK BEGIN                                     ║
# ║                                                                           ║
# ║ 下面这一整段类型的**正式定义应在 src/geo_audit/models.py**，见规格         ║
# ║ §2.5（Stage / Severity / PositionClass / FindingKind，行 855–958）、       ║
# ║ §2.6（Evidence / FixHint，行 960–1000）、§2.7（Finding，行 1060–1115）、    ║
# ║ §2.8（UNKNOWN_REMEDY，行 1146–1184）、§2.9（Position，行 1198–1214）。      ║
# ║ 仓库现状：models.py 只到 LinkContext（563 行），**一个都还没有**。          ║
# ║                                                                           ║
# ║ 铁律 1 禁止本 agent 改 models.py，所以先在这里放**本地占位**，让 §4 的四个 ║
# ║ 子检查能写出来、能测。owner 把它们搬进 models.py 时：                      ║
# ║   1. 删掉本占位区整段（两条横幅之间的所有内容）；                          ║
# ║   2. 把这些名字加进本文件顶部的 ``from ..models import (...)``；           ║
# ║   3. 注意 ``Finding.naive`` 是本文件**新增**的字段（见该字段的注释），      ║
# ║      搬入时需要裁决是并入 models.Finding 还是改走 Position.naive。         ║
# ║ ⚠️ 验收 A6 用 ``grep -rn "class Severity\\|class PositionClass" src/`` 数  ║
# ║ 命中数，要求恰好 1 处。搬入时必须**同时**删这里，否则 A6 会变成 2 处。      ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║ 占位区结束 —— PLACEHOLDER BLOCK END                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
# ═════════════════════════════════════════════════════════════════════════════


class Prober(Protocol):
    """``fetch.client.Fetcher`` 的结构化子集。

    规格给 ``check_index_links`` / ``check_md_convention`` 写的是 ``fetcher: object``，
    在 mypy strict 下没法调用任何方法。这里用 Protocol 而不是直接 import Fetcher：
    checks 层不该依赖 client 的构造方式，测试也能塞一个只实现这三个方法的假货。
    """

    def probe(
        self,
        url: str,
        *,
        expect: Expect = ...,
        liveness_only: bool = ...,
        use_control: bool = ...,
    ) -> Probe: ...

    def probe_many(
        self,
        urls: Sequence[str],
        *,
        expect: Expect = ...,
        liveness_only: bool = ...,
    ) -> list[Probe]: ...

    def note_exclusion(self, url: str, rule_id: str, why: str) -> None: ...


# ─────────────────────────────────────────────────────────────────────────────
# 共用：Evidence / Finding 构造（A35 的四条硬要求都在这里落地）
# ─────────────────────────────────────────────────────────────────────────────

#: UA 没被注入时的兜底串。A35 要求 ``curl_repro`` 含「本次 UA」，而规格给
#: ``_mk`` 的签名里没有 UA 参数（见 spec_gaps）——所以四个入口都收一个
#: keyword-only 的 ``user_agent``，pipeline 传 ``build_user_agent(contact)``。
UA_NOT_INJECTED = f"geo-audit/{TOOL_VERSION} (contact: 未注入)"

#: 归一化正文的展示前缀长度（§2.6 Evidence.body_head / §4.4 MdSample.md_head）。
BODY_HEAD_CHARS = 240

_TITLE_RE = re.compile(r"<title[^>]*>(?P<t>.*?)</title>", re.I | re.S)


def _curl_repro(url: str, user_agent: str) -> str:
    """A35：必须以 ``curl `` 开头，且含目标 URL 与本次 UA。"""
    ua = user_agent or UA_NOT_INJECTED
    return f"curl -sSL -A '{ua}' '{url}'"


def _body_head(resp: HttpResponse) -> str | None:
    if not resp.body:
        return None
    return normalize_body(resp.text)[:BODY_HEAD_CHARS] or None


def _title_of(resp: HttpResponse) -> str | None:
    if not resp.is_html:
        return None
    m = _TITLE_RE.search(resp.text[:20000])
    return m.group("t").strip() if m else None


def evidence_of(resp: HttpResponse, *, user_agent: str = "") -> Evidence:
    """一个已抓响应 → 一条 Evidence。**不发请求、不算哈希**（卡点 S10：
    raw_md5 / norm_sha256 是 HttpResponse 的构造期字段，checks 层只读）。"""
    return Evidence(
        url=resp.url,
        http_status=resp.status,
        content_type=resp.content_type or None,
        bytes_len=resp.byte_len,
        norm_sha256=resp.norm_sha256,
        raw_md5=resp.raw_md5,
        body_head=_body_head(resp),
        title=_title_of(resp),
        final_url=resp.final_url,
        redirect_chain=tuple(f"{h.status} {h.to_url}" for h in resp.redirects),
        resolver_used=resp.resolver_used,
        error=resp.transport_error,
        curl_repro=_curl_repro(resp.url, user_agent),
    )


def _evidence_for_url(url: str, *, user_agent: str = "") -> Evidence:
    """没有响应体可挂时（被 robots 拦、未探）的最小 Evidence。"""
    return Evidence(url=url, curl_repro=_curl_repro(url, user_agent))


def _finding(
    *,
    kind: FindingKind,
    check_id: str,
    title: str,
    severity: Severity,
    stage: Stage,
    target: Evidence,
    norm_url: str,
    domain: str,
    why_it_matters: str,
    display_value: str,
    naive: NaiveContrast | None = None,
    counted_as_hit: bool = True,
    detail: dict[str, str | int | float | bool] | None = None,
    found_on: str | None = None,
    # 索引文件列这条链接时给的人类可读标签。**必须传上来**：一份说「这条链接死了」
    # 的报告，读的人要知道索引把它标成了什么（「Agents and conversations」），
    # 否则只剩一串 URL。IndexLink 一路带着它，原来在这里被丢掉了。
    anchor_text: str | None = None,
    occurrences: int = 1,
    occurrence_hrefs: tuple[str, ...] = (),
    fp_guard: tuple[str, ...] = (),
    fp_note: str | None = None,
    control: Evidence | None = None,
    confidence: Literal["confirmed", "needs_review"] = "confirmed",
) -> Finding:
    """唯一的 Finding 构造器。四条 A35 硬要求在这里一次性满足：

    1. ``target.curl_repro`` 以 ``curl `` 开头且含目标 URL 与本次 UA
       —— 由 ``_curl_repro`` 保证，这里断言兜住；
    2. ``why_it_matters`` 非空 —— 参数必填；
    3. ``suppress_hint`` 含自己的 finding_id —— 这里现算；
    4. ``fix is None`` 时 ``display_value`` 必须含「我们没找到」
       —— 这里自动补，绝不编一个修复目标（§2.6 FixHint 的原话）。
    """
    fid = make_finding_id(check_id, norm_url, found_on)
    assert target.curl_repro.startswith("curl "), "A35：curl_repro 必须以 curl 开头"
    assert why_it_matters, "A35：why_it_matters 不许为空"
    shown = display_value
    if "我们没找到" not in shown:
        shown = (
            f"{shown}（修复目标：我们没找到明显的正确目标，需人工确认）"
            if shown
            else ("我们没找到明显的正确目标，需人工确认")
        )
    return Finding(
        finding_id=fid,
        kind=kind,
        check_id=check_id,
        title=title,
        severity=severity,
        position_class=PositionClass.AI_CHANNEL,
        stage=stage,
        target=target,
        control=control,
        found_on=found_on,
        anchor_text=anchor_text,
        occurrences=occurrences,
        occurrence_hrefs=occurrence_hrefs,
        fix=None,
        naive_conclusion=naive.naive_conclusion if naive else "",
        naive_is_wrong=bool(naive and naive.diverges),
        actual_conclusion=naive.actual_conclusion if naive else "",
        confidence=confidence,
        why_it_matters=why_it_matters,
        fp_guard=fp_guard,
        fp_note=fp_note,
        suppress_hint=f"geo-audit {domain} --ignore {fid}",
        display_value=shown,
        detail=dict(detail or {}),
        counted_as_hit=counted_as_hit,
        # §2.7：severity_signals 四键必填。AI 通道内部没有锚点也没有 DOM 区域，
        # 所以四个键填的是「这一格的角色就是 AI 通道本身」——不留空，也不假装有锚文本。
        severity_signals={
            "page_role": "ai_channel",
            "anchor": "（AI 通道内部，无锚文本）",
            "anchor_class": "（AI 通道内部，无 class）",
            "region": "ai_channel",
        },
        naive=naive,
    )


# ═════════════════════════════════════════════════════════════════════════════
# 朴素对照（产品核心卖点）—— §4.5 的口径，按 finding 粒度
# ═════════════════════════════════════════════════════════════════════════════

#: §4.5:2400。朴素实现会探的位置：apex 与 www 上的两条根路径。**仅此四个**。
NAIVE_HOST_TEMPLATES: tuple[str, ...] = ("{apex}", "www.{apex}")
NAIVE_PATHS: tuple[str, ...] = ("/llms.txt", "/llms-full.txt")

#: §4.5 只钉了两条文案（1006-1012）。「朴素探过但拿到 404/403/500」的文案规格
#: 没给（见 spec_gaps），这里定死如下，四个子检查共用同一套串。
NAIVE_ADOPTED = "已采纳（200）"
NAIVE_NOT_PROBED = "未采纳（没探这个位置）"
NAIVE_METHOD_OUT_OF_SET = "不在朴素探测集内"


def in_naive_probe_set(url: str, apex: str) -> bool:
    """这个位置在朴素探测集（apex/www × llms.txt/llms-full.txt）里吗？"""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    apex = apex.lower().removeprefix("www.")
    hosts = {tpl.format(apex=apex) for tpl in NAIVE_HOST_TEMPLATES}
    return host in hosts and (parts.path or "/") in NAIVE_PATHS


def naive_reading(status: int | None) -> str:
    """朴素读数 = 跟完跳转的最终状态码，正文与对照一概不看。"""
    if status is None:
        return "未采纳（请求没成功）"
    if 200 <= status < 300:
        return NAIVE_ADOPTED
    if status in (404, 410):
        return f"未采纳（{status}）"
    if status in (401, 403, 429):
        return f"未采纳（{status}，被拦也读成没有）"
    if status >= 500:
        return f"未采纳（{status} 服务端错误）"
    return f"未采纳（HTTP {status}）"


def _conclusions_differ(naive_conclusion: str, real_status: Status) -> bool:
    """§4.5:2430 逐字照抄的判据：

    朴素说「已采纳」而真实 status 不是 PASS  -> True（假阳方向）
    朴素说「未采纳」而真实 status 是 PASS      -> True（假阴方向）
    其余                                       -> False
    """
    if naive_conclusion.startswith("已采纳"):
        return real_status is not Status.PASS
    if naive_conclusion.startswith("未采纳"):
        return real_status is Status.PASS
    return False


def naive_contrast(
    *,
    probe_url: str,
    apex: str,
    http_status: int | None,
    real_status: Status,
    actual_conclusion: str,
    extra_requests: int = 0,
    over_report: bool = False,
    why: str = "",
) -> NaiveContrast:
    """构造一行对照。``over_report=True`` 用于「朴素会报、我们按范围不报」。"""
    in_set = in_naive_probe_set(probe_url, apex)
    if not in_set:
        conclusion, method = NAIVE_NOT_PROBED, NAIVE_METHOD_OUT_OF_SET
    else:
        conclusion = naive_reading(http_status)
        method = f"GET {probe_url}，跟随跳转，只看最终状态码"
    if over_report:
        return NaiveContrast(
            probe_url=probe_url,
            in_naive_probe_set=in_set,
            naive_method=method,
            naive_conclusion=conclusion,
            actual_conclusion=actual_conclusion,
            diverges=True,
            direction="over_report",
            extra_requests=extra_requests,
            why=why,
        )
    diverges = _conclusions_differ(conclusion, real_status)
    direction: Literal["false_positive", "false_negative", "over_report", "agree"] = "agree"
    if diverges:
        direction = "false_positive" if conclusion.startswith("已采纳") else "false_negative"
    return NaiveContrast(
        probe_url=probe_url,
        in_naive_probe_set=in_set,
        naive_method=method,
        naive_conclusion=conclusion,
        actual_conclusion=actual_conclusion,
        diverges=diverges,
        direction=direction,
        extra_requests=extra_requests,
        why=why,
    )


# ═════════════════════════════════════════════════════════════════════════════
# 子检查一 · 路径真伪（软 404）—— §4.1:1929-1948
# ═════════════════════════════════════════════════════════════════════════════

#: soft_404 finding 的 detail 键。§4.1 通篇零代码、没给 detail 规格（见 spec_gaps），
#: 这五个键是本文件定的，与 §4.2/§4.3 的固定键同风格。
SOFT404_DETAIL_KEYS = (
    "probe_url",
    "http_status",
    "content_type",
    "reason",
    "secondary_reasons",
)


def _content_or_struct_identical(body: str, control: HostProfile) -> bool:
    """L3(i) 的原判据（classify.py:440-468 的局部变量，这里提成函数）。

    ⚠️ 规格 §3.4:1507 直接调用了一个同名 helper，但仓库里**没有**这个函数 ——
    classify.py 把 content/struct 两条判据写成了 ``classify_response`` 内部的
    局部变量。铁律 1 不许改 fetch/，所以在这里等价重写；判据一字不改：
    长度闸 ``MIN_SIMILARITY_LEN`` 与标签数闸 ``MIN_STRUCT_TAGS`` 都保留 ——
    没有这两个闸，任意两个空壳的归一化摘要都相同。
    """
    norm = normalize_body(body)
    struct, tags = structural_fingerprint(body)
    content_identical = len(norm) >= MIN_SIMILARITY_LEN and norm_sha256(body) == control.norm_sha256
    struct_identical = (
        tags >= MIN_STRUCT_TAGS
        and control.struct_tags >= MIN_STRUCT_TAGS
        and struct == control.struct_sha256
    )
    return content_identical or struct_identical


def _ct(headers: Mapping[str, str]) -> str:
    return headers.get("content-type", "").split(";")[0].strip().lower()


def collect_secondary_reasons(
    *,
    primary: Reason,
    status: int,
    headers: dict[str, str],
    body: str,
    url: str,
    final_url: str,
    redirects: tuple[RedirectHop, ...],
    expect: Expect,
    control: HostProfile | None,
) -> tuple[Reason, ...]:
    """把「除首要 reason 之外还会命中哪些规则」按 §3.4 的 L 层顺序列出。

    卡点 S1 的核心修法。AI 路径探测一律 ``Expect.TEXT_FILE``，于是 L2(a)
    ``html_where_text_expected`` 会在**所有 15 个 HTML 型软 404** 上抢先返回，
    「我们做了对照探测、两边同一个壳」这条证据在首要 reason 上就看不见了 ——
    而它正是首页差异化演示区的原料。这个函数在判为 SOFT404 时补算其余各层，
    证据不丢，首要归因一字不动。

    只在 verdict 是 SOFT404 时才该调用（OK/REAL404/BLOCKED 的 secondary 恒为空）：
    真文件上跑纯属浪费，且 near_identical 在长真文件上是 O(n) 的 difflib。

    ⚠️ 与规格 §3.4:1494-1506 的**唯一**差异（停工级裁决，见 spec_gaps 第 1 条）：
    L3 的门去掉了 ``expect is Expect.TEXT_FILE and control.control_is_html``那半，
    只剩 ``control is not None and control.usable``。理由：那半门是给**首要判定**
    用的 —— 「HTML 对照能证明文本文件是真的」，所以命中它时 classify 走 OK。
    但 minimax/moonshot 的对照恰恰是 200 text/html（status_discriminates=False、
    control_is_html=True），而 AI 路径 expect 恒为 TEXT_FILE，括号内恒 True →
    整个门恒 False → ``identical_to_control`` **永远进不了 secondary_reasons**，
    A 表 A04/A05 与验收 A8 按原文永远不可能通过。而「正文/骨架与对照逐字相同」
    是一个**观测事实**，不是推论，没有理由被那扇为推论设的门挡住。
    """
    out: list[Reason] = []
    if find_platform_missing(body) is not None:
        out.append("platform_deployment_missing")
    if find_notfound_copy(body) is not None:
        out.append("notfound_copy_in_body")
    disc = redirect_discarded_path(url, final_url, redirects)
    if disc is not None:
        out.append(cast("Reason", disc[0]))
    # 只去掉规格那扇门的**后半**（`expect is TEXT_FILE and control.control_is_html`）：
    # AI 路径的 expect 恒为 TEXT_FILE，而 minimax/moonshot 的对照恰恰是 200 text/html，
    # 于是后半恒真 → 整个 `not(...)` 恒假 → identical_to_control 永远进不了 secondary，
    # 卡点 S1 的修法就白做了。后半是为**首要判定**设的（HTML 对照能证明文本文件是真的），
    # 不该管 secondary。
    #
    # 前半 `not control.status_discriminates` **必须留着**：对照探测的状态码能区分，
    # 正是「这个 host 不是一个壳打天下」的正面证据；此时再报 identical_to_control
    # 是自相矛盾。第一版把两半一起删了，是错的。
    if control is not None and control.usable and not control.status_discriminates:
        if _content_or_struct_identical(body, control):
            out.append("identical_to_control")
        elif (
            status == control.status
            and _ct(headers) == control.content_type
            and similarity_norm(normalize_body(body), control.norm_body_prefix) > 0.90
        ):
            out.append("near_identical_to_control")
    return tuple(r for r in out if r != primary)


def enrich_probe(probe: Probe, control: HostProfile | None) -> Probe:
    """给一个已判完的 SOFT404 探测补算 ``secondary_reasons``。

    ⚠️ 归属裁决（见 spec_gaps 第 2 条）：规格 §3.4:1483/1515 要求
    ``collect_secondary_reasons`` 写在 ``classify.py`` 末尾、并在
    ``classify_response()`` 的四个 SOFT404 ``return`` 之前接线，而铁律 1 禁止本
    agent 碰 ``src/geo_audit/fetch/**``。所以本函数在 **checks 层**做同一件事：
    纯函数、不发请求、只往新字段里写，``verdict`` / ``reason`` / ``evidence``
    一字不动（A4 因此仍成立）。fetch 层接线后本函数应变成 no-op 并删除。
    """
    cls = probe.classification
    resp = probe.response
    if cls.verdict is not Verdict.SOFT404 or resp is None or cls.secondary_reasons:
        return probe
    secondary = collect_secondary_reasons(
        primary=cls.reason,
        status=resp.status,
        headers=resp.headers,
        body=resp.text,
        url=probe.url,
        final_url=resp.final_url,
        redirects=resp.redirects,
        expect=probe.expect,
        control=control,
    )
    if not secondary:
        return probe
    return replace(probe, classification=replace(cls, secondary_reasons=secondary))


def enrich_probes(
    probes: Sequence[Probe], controls: Mapping[str, HostProfile] | None = None
) -> tuple[Probe, ...]:
    """按 host 取对照基线，逐条补算 secondary_reasons。``controls`` 的键是 host。"""
    table = controls or {}
    out: list[Probe] = []
    for p in probes:
        host = (urlsplit(p.url).hostname or "").lower()
        out.append(enrich_probe(p, table.get(host)))
    return tuple(out)


def has_ai_channel(probes: Sequence[Probe]) -> bool:
    """§4.1 口径 3：一个域只要**任一位置**是真文件就算有 AI 通道。"""
    return any(p.verdict is Verdict.OK for p in probes)


def _stage_of_path(url: str) -> Stage:
    """§2.9 P2：路径含 ``llms-full`` → FULLTEXT，否则 INDEX_FILE。"""
    return Stage.FULLTEXT if "llms-full" in urlsplit(url).path.lower() else Stage.INDEX_FILE


def ai_path_position_seeds(probes: Sequence[Probe]) -> tuple[PositionSeed, ...]:
    """§2.9 P2 的原料：每个**实际发出去的** AI 路径探测各一格。

    口径 1（§4.1:1935）：BLOCKED 与 REAL404 是两个不同 verdict，这里不合并 ——
    ``verdict_to_status`` 已经把它们分别送进 UNKNOWN 与 NOT_APPLICABLE 两栏。
    口径 2（§4.1:1937）：同一 host 内不同路径各判各的，key 是 host+path。
    """
    seeds: list[PositionSeed] = []
    for p in probes:
        parts = urlsplit(p.url)
        status = verdict_to_status(p.verdict)
        cls = p.classification
        unknown_reason = cls.reason if status is Status.UNKNOWN else None
        seeds.append(
            PositionSeed(
                stage=_stage_of_path(p.url),
                key=f"{(parts.hostname or '').lower()}{parts.path}",
                kind="probe",
                probe_url=p.url,
                status=status,
                detail="；".join(cls.evidence) or cls.reason,
                unknown_reason=unknown_reason,
                unknown_remedy=(
                    UNKNOWN_REMEDY.get(
                        unknown_reason,
                        "本位置未能评估，补救办法未登记（UNKNOWN_REMEDY 缺这条，见 §2.8）。",
                    )
                    if unknown_reason is not None
                    else None
                ),
            )
        )
    return tuple(seeds)


def check_ai_paths(
    domain: str,
    probes: Sequence[Probe],
    *,
    controls: Mapping[str, HostProfile] | None = None,
    user_agent: str = "",
) -> tuple[Finding, ...]:
    """§4.1。探测集 = ``SiteMap.ai_path_probes``，判定直接用 ``probe.classification``
    （已由 ``fetch.classify`` 以 ``Expect.TEXT_FILE`` 判完）。

    SOFT404 各生成一条 ``kind="soft_404"`` 的 Finding；**BLOCKED 与 REAL404 不产
    finding**（分别落 UNKNOWN / NOT_APPLICABLE 格，见 ``ai_path_position_seeds``）。
    """
    table = controls or {}
    out: list[Finding] = []
    for raw_probe in probes:
        control = table.get((urlsplit(raw_probe.url).hostname or "").lower())
        probe = enrich_probe(raw_probe, control)
        if probe.verdict is not Verdict.SOFT404:
            continue
        resp = probe.response
        assert resp is not None, "SOFT404 必然有响应体"
        cls = probe.classification
        secondary = ", ".join(cls.secondary_reasons)
        actual = (
            f"软 404：{cls.reason}"
            + (f"（另命中 {secondary}）" if secondary else "")
            + f"，HTTP {resp.status} / {resp.content_type or '未声明'}"
        )
        contrast = naive_contrast(
            probe_url=probe.url,
            apex=domain,
            http_status=resp.status,
            real_status=Status.FAIL,
            actual_conclusion=actual,
            # 对照探测就是我们比朴素多打的那一个请求（§4.5 minimax 那行）。
            # 有 host profile 就说明这个请求实打实花掉了 —— 不看 cls.control_used：
            # L2(a) 抢先返回时它是 False，而对照探测照样已经发过了。
            extra_requests=1 if control is not None else 0,
            why="；".join(cls.evidence),
        )
        detail: dict[str, str | int | float | bool] = {
            "probe_url": probe.url,
            "http_status": resp.status,
            "content_type": resp.content_type or "",
            "reason": cls.reason,
            "secondary_reasons": secondary,
        }
        out.append(
            _finding(
                kind="soft_404",
                check_id="ai_path.soft404",
                title=f"{probe.url} 返回 200 但内容不是文本文件（软 404）",
                severity=Severity.HIGH,
                stage=_stage_of_path(probe.url),
                target=evidence_of(resp, user_agent=user_agent),
                norm_url=normalize_url(probe.url),
                domain=domain,
                why_it_matters=(
                    "AI 抓这个位置拿到的是页面外壳，不是你的索引文件。"
                    "只看状态码的工具会把它读成「已采纳 llms.txt」——采纳率因此虚高。"
                ),
                display_value=f"HTTP {resp.status}，{resp.byte_len} 字节，内容是兜底页",
                naive=contrast,
                detail=detail,
                fp_guard=tuple(cls.all_reasons),
                fp_note=(
                    "本条没有同域对照探测垫底（只靠 L2 的确定性规则）。"
                    if control is None
                    else None
                ),
            )
        )
    return tuple(out)


# ═════════════════════════════════════════════════════════════════════════════
# 子检查二 · llms-full 真伪 —— §4.2:1953-2049（逐字照抄）
# ═════════════════════════════════════════════════════════════════════════════

#: detail 字典的键，固定六个，进 schema（§4.2:1953）。
LLMS_FULL_DETAIL_KEYS = (
    "index_url",
    "full_url",
    "index_bytes",
    "full_bytes",
    "ratio",
    "docs_llms_full_bytes",
)

_LINKY_LINE_RE = re.compile(r"\s*[-*]?\s*\[.+?\]\(.+?\)")


def index_shape(text: str) -> tuple[float, int]:
    """返回 (链接行占非空行比例, 非链接非标题行的字符数)。§4.2:2044 逐字照抄。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    linky = sum(1 for ln in lines if _LINKY_LINE_RE.match(ln))
    prose = sum(
        len(ln) for ln in lines if not ln.lstrip().startswith(("#", "-", "*")) and "](" not in ln
    )
    return ((linky / len(lines)) if lines else 0.0, prose)


def _same_url(a: str, b: str) -> bool:
    """归一化后比较：去 query、去尾斜杠、大小写不敏感（§4.2:1992 的口径）。"""

    def canon(u: str) -> str:
        p = urlsplit(u.strip().lower())
        return f"{p.scheme}://{p.netloc}{(p.path or '/').rstrip('/') or '/'}"

    return canon(a) == canon(b)


def _pair_by_host_and_prefix(
    probes: Sequence[Probe],
) -> dict[tuple[str, str], tuple[Probe | None, Probe | None]]:
    """配对键 = (host, path[:path.rfind("/")])，即 llms.txt 与 llms-full.txt
    **同目录才配**。basename 含 ``llms-full`` 者为 full，否则 index。

    只收 basename 像 AI 路径文件的探测（``llms``），别的路径一律不进配对表 ——
    否则 ``/robots.txt`` 之类会被当成 index。
    """
    table: dict[tuple[str, str], tuple[Probe | None, Probe | None]] = {}
    for p in probes:
        parts = urlsplit(p.url)
        path = parts.path
        base = path.rsplit("/", 1)[-1].lower()
        if "llms" not in base:
            continue
        key = ((parts.hostname or "").lower(), path[: path.rfind("/")])
        index, full = table.get(key, (None, None))
        if "llms-full" in base:
            full = full or p
        else:
            index = index or p
        table[key] = (index, full)
    return table


def _mk(
    full: Probe,
    check_rule: str,
    sev: Severity,
    detail: dict[str, str | int | float | bool],
    *,
    counted_as_hit: bool = True,
    domain: str,
    index: Probe,
    user_agent: str = "",
) -> Finding:
    """§4.2:2035 的统一 Finding 构造器。``kind`` 恒为 ``"llms_full_fake"``
    （FINDING_KINDS 只有 5 个），具体规则放 ``check_id = f"ai_path.{check_rule}"``，
    ``position_class`` 恒为 AI_CHANNEL、``stage`` 恒为 FULLTEXT（§2.9 P2 把含
    ``llms-full`` 的位置归 FULLTEXT，取同一段）。

    ⚠️ 规格给的签名只有前四个参数，而 Finding 有 20+ 必填/半必填字段（A35 还要
    UA 与 finding_id）。多出来的 ``domain`` / ``index`` / ``user_agent`` 是
    keyword-only 的补写，见 spec_gaps。
    """
    fr = full.response
    ir = index.response
    assert fr is not None and ir is not None
    titles = {
        "llms_full_redirect_to_index": "llms-full.txt 跳回 llms.txt（没有全文通道）",
        "llms_full_byte_copy": "llms-full.txt 与 llms.txt 是同一份字节（一个字正文都没有）",
        "llms_full_not_fulltext": "llms-full.txt 不比 llms.txt 长（不是全文）",
        "llms_full_thin": "llms-full.txt 偏小且仍像纯索引（疑似没打包正文）",
    }
    whys = {
        "llms_full_redirect_to_index": (
            "AI 要全文时拿到的是索引本身。只看最终状态码的工具会判「有全文」。"
        ),
        # 原文是「说明打包流水线没把正文接进来。实测三家同为 Fern 托管 ——
        # 一条规则抓一整个平台的所有客户。」两处都不能留：
        #   1. 「打包流水线没接进来」是在断言对方的内部实现，我们只观测到
        #      两个 URL 的字节相同，推断原因不是观测；
        #   2. 「三家同为 Fern 托管」是对**那三家**的观测，贴到任何命中这条
        #      规则的公司头上就是把别人的结论按在它身上。
        # 现在只说我们真的看见了什么，以及它对 AI 的后果。
        "llms_full_byte_copy": (
            "两个文件的字节完全相同：AI 要全文时拿到的还是那份索引，一个字正文都没有。"
        ),
        "llms_full_not_fulltext": ("全文文件比索引还小，AI 拿不到任何额外正文。"),
        "llms_full_thin": (
            "膨胀比偏低且正文仍以链接行为主，可能只是又生成了一份索引；本条只提示、不进首页分子。"
        ),
    }
    contrast = naive_contrast(
        probe_url=full.url,
        apex=domain,
        http_status=fr.status,
        real_status=Status.FAIL if counted_as_hit else Status.PASS,
        actual_conclusion=(
            f"{titles[check_rule]}：索引 {ir.byte_len} B / 全文 {fr.byte_len} B"
            f"（比 {detail.get('ratio')}）"
        ),
        # llms.txt 本来就要抓，所以看出「字节副本」不需要额外请求（§4.5 deepgram 那行）。
        extra_requests=0,
        over_report=check_rule == "llms_full_thin",
        why="朴素实现只看 llms-full.txt 的最终状态码，两份文件一样它也说「有全文」",
    )
    return _finding(
        kind="llms_full_fake",
        check_id=f"ai_path.{check_rule}",
        title=titles[check_rule],
        severity=sev,
        stage=Stage.FULLTEXT,
        target=evidence_of(fr, user_agent=user_agent),
        control=evidence_of(ir, user_agent=user_agent),
        norm_url=normalize_url(fr.final_url),
        domain=domain,
        why_it_matters=whys[check_rule],
        display_value=(
            f"索引 {ir.byte_len} B → 全文 {fr.byte_len} B，比 {detail.get('ratio')}"
            + ("（轻度：只提示，不进分子）" if not counted_as_hit else "")
        ),
        naive=contrast,
        counted_as_hit=counted_as_hit,
        detail=detail,
        found_on=ir.final_url,
    )


def _judge_pair(
    index: Probe | None,
    full: Probe | None,
    *,
    domain: str,
    user_agent: str = "",
) -> Finding | None:
    """§4.2:1972-2032 逐字照抄，两处照抄会停工的地方按 spec_gaps 4/12 补写。"""
    if index is None or full is None:
        return None
    if full.verdict is not Verdict.OK or index.verdict is not Verdict.OK:
        return None  # 软404/404/被拦各归各的子检查，这里不重复计
    ir, fr = index.response, full.response
    assert ir is not None and fr is not None
    # 卡点 S10：digest 可能是 None（只查存活的 64 KiB 档不算哈希）。
    # None 绝不当「哈希不同」，判 UNKNOWN 并记 coverage_gap。
    if ir.raw_md5 is None or fr.raw_md5 is None:
        return None

    # ⚠️ ratio 先取局部 float 再写进 detail：Finding.detail 的值类型是
    # str|int|float|bool 联合，照抄 `detail["ratio"] >= 3.0` 过不了 mypy strict
    # （spec_gaps 第 12 条）。比较一律用局部量。
    ratio = round(fr.byte_len / max(ir.byte_len, 1), 3)
    detail: dict[str, str | int | float | bool] = {
        "index_url": ir.final_url,
        "full_url": fr.final_url,
        "index_bytes": ir.byte_len,
        "full_bytes": fr.byte_len,
        "ratio": ratio,
        "docs_llms_full_bytes": 0,
    }
    # ① 302/301 回 llms.txt。比较时归一化：去 query、去尾斜杠、大小写不敏感。
    #    实测：docs.bigcommerce.com/llms-full.txt 302 -> llms.txt（同一份 415 B 文件）。
    for hop in fr.redirects:
        if _same_url(hop.to_url, ir.final_url):
            return _mk(
                full,
                "llms_full_redirect_to_index",
                Severity.HIGH,
                detail,
                domain=domain,
                index=index,
                user_agent=user_agent,
            )
    if _same_url(fr.final_url, ir.final_url):
        return _mk(
            full,
            "llms_full_redirect_to_index",
            Severity.HIGH,
            detail,
            domain=domain,
            index=index,
            user_agent=user_agent,
        )

    # ② 字节副本。原始字节 md5 优先，归一化哈希兜底 gzip/换行差异。
    if fr.raw_md5 == ir.raw_md5 or (
        fr.norm_sha256 is not None and fr.norm_sha256 == ir.norm_sha256
    ):
        return _mk(
            full,
            "llms_full_byte_copy",
            Severity.HIGH,
            detail,
            domain=domain,
            index=index,
            user_agent=user_agent,
        )

    # ③ 不比 llms.txt 长。只用解码后字节，绝不用线上字节。
    if fr.byte_len <= ir.byte_len:
        return _mk(
            full,
            "llms_full_not_fulltext",
            Severity.HIGH,
            detail,
            domain=domain,
            index=index,
            user_agent=user_agent,
        )

    # ④ 正常情况：全站文档打包。膨胀比 >= 3 或 prose 字符 >= 5x 直接放行。
    f_link_ratio, f_prose = index_shape(fr.text)
    _, t_prose = index_shape(ir.text)
    if ratio >= 3.0 or f_prose >= 5 * max(t_prose, 1):
        return None

    # ⑤ 灰区：偏小且仍像纯索引 -> 只提示，counted_as_hit=False，**不进分子**。
    if f_link_ratio > 0.5:
        return _mk(
            full,
            "llms_full_thin",
            Severity.INFO,
            detail,
            counted_as_hit=False,
            domain=domain,
            index=index,
            user_agent=user_agent,
        )
    return None


def check_llms_full(
    domain: str,
    probes: Sequence[Probe],
    *,
    user_agent: str = "",
) -> tuple[Finding, ...]:
    """按 (host, 路径前缀) 配对，只在同 host 同前缀内比。返回 0..N 条 finding。

    返回 tuple 而不是 Optional，因为一个域可以有多对：resend 根
    ``/llms-full.txt``（8,056 B 索引）与 ``/docs/llms-full.txt``（2,173,432 B
    真全文）是两对，必须各判各的。

    **两趟**（spec_gaps 第 4 条）：``docs_llms_full_bytes`` 需要跨 pair 信息，而
    ``_judge_pair`` 只看得见自己那一对，更糟的是「④ 正常打包」那支直接
    ``return None`` 什么都没留下。所以第一趟记下每个「④ 放行」的 pair 的
    ``full.response.byte_len``，第二趟用 ``dataclasses.replace`` 把该值写进
    thin/copy 类 finding 的 detail。
    """
    pairs = _pair_by_host_and_prefix(probes)
    out: list[Finding] = []
    normal_full_bytes: list[int] = []

    for index, full in pairs.values():
        f = _judge_pair(index, full, domain=domain, user_agent=user_agent)
        if f is not None:
            out.append(f)
        elif (
            index is not None
            and full is not None
            and index.verdict is Verdict.OK
            and full.verdict is Verdict.OK
            and full.response is not None
        ):
            # ④ 放行的那一对：它的字节数就是「这个域真正的全文有多大」。
            normal_full_bytes.append(full.response.byte_len)

    if not normal_full_bytes:
        return tuple(out)
    docs_bytes = max(normal_full_bytes)
    patched: list[Finding] = []
    for f in out:
        detail = dict(f.detail)
        detail["docs_llms_full_bytes"] = docs_bytes
        patched.append(replace(f, detail=detail))
    return tuple(patched)


# ═════════════════════════════════════════════════════════════════════════════
# 子检查三 · 索引内链存活 —— §4.3:2069-2156
# ═════════════════════════════════════════════════════════════════════════════

LINK_RE_MARKDOWN = re.compile(r"\[(?P<text>[^\]]*)\]\((?P<url>[^)\s]+)\)")
LINK_RE_BARE = re.compile(r"(?<![(<\"'`])\bhttps?://[^\s`)>\"'\]]+")
LINK_RE_HTML_A = re.compile(r"<a[^>]+href=[\"'](?P<url>[^\"']+)[\"']", re.I)
LINK_RE_RELATIVE = re.compile(r"\[[^\]]*\]\((?P<url>/[^)\s]+)\)")

RIGHT_STRIP_CHARS = "`\"'“”)>]"  # zilliz 的反引号伪影
RIGHT_STRIP_PUNCT = ".,;:"

#: §4.3:2116。<= 120 条全量；> 120 条确定性分层抽 60 条。
INDEX_LINKS_FULL_THRESHOLD = 120
INDEX_LINKS_SAMPLE_SIZE = 60

#: §4.3:2152。五个固定键 + ``sampled`` / ``sampled_of`` 两个可选键。
INDEX_LINKS_DETAIL_KEYS = ("index_url", "n_links", "n_alive", "n_dead", "n_unknown")

#: §5.4:2838 的跟踪型 query 参数名。normalize_url 要丢掉它们。

_DOUBLE_SCHEME_RE = re.compile(r"https?://.+https?://", re.I)


def _right_strip(url: str) -> str:
    """右剥 ``RIGHT_STRIP_CHARS`` 与尾部 ``RIGHT_STRIP_PUNCT``。

    zilliz 实测：朴素正则把反引号吃进 URL 造成 **2 条假失败**，右剥后真实 8/8 全活。
    """
    return url.rstrip(RIGHT_STRIP_CHARS + RIGHT_STRIP_PUNCT)


@dataclass(frozen=True, slots=True)
class IndexLink:
    """§4.3:2096。"""

    line_no: int
    abs_url: str  # 探测用这个（服务端可能对 query 敏感）
    norm_url: str  # 去重与 finding 身份用这个
    anchor_text: str | None
    extractor: Literal["markdown", "bare", "html_a", "relative"]
    artifact: str | None = None  # "double_scheme" 等抽取阶段就能认出的形态


def _mk_link(
    *,
    line_no: int,
    raw: str,
    base_url: str,
    anchor_text: str | None,
    extractor: Literal["markdown", "bare", "html_a", "relative"],
) -> IndexLink | None:
    url = _right_strip(raw.strip())
    if not url or url.startswith(("#", "mailto:", "tel:", "javascript:")):
        return None
    # 相对路径**以该 llms.txt 的 final_url 为 base** 绝对化，不以 apex 为 base
    # （§4.3:2082，mailerlite / bytebase 504 条 /xxx.md 就靠这条）。
    abs_url = urljoin(base_url, url)
    if not abs_url.lower().startswith(("http://", "https://")):
        return None
    artifact = "double_scheme" if _DOUBLE_SCHEME_RE.search(abs_url) else None
    return IndexLink(
        line_no=line_no,
        abs_url=abs_url,
        norm_url=normalize_url(abs_url),
        anchor_text=anchor_text or None,
        extractor=extractor,
        artifact=artifact,
    )


def extract_index_links(text: str, base_url: str) -> list[IndexLink]:
    """四条抽取器并用，**不去重**（去重会丢掉 occurrences，A16 要那个数）。

    §4.3:2078-2093 五种必须处理的实测形态：
      裸 URL           turso 整份文件零 markdown 语法（只用 ``](url)`` 会读出 0 条）
      相对路径         mailerlite ``/getting-started``、bytebase 504 条 ``/xxx.md``
      内嵌裸 HTML <a>  attio ``/customers/llms.txt``、close ``help/llms.txt``
      反引号包裹       zilliz（右剥后真实 8/8 全活）
      一个 URL 两个 scheme  inngest 第 157/290/296 行 —— **抽取阶段不拆**
    """
    out: list[IndexLink] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        raws: list[tuple[Literal["markdown", "bare", "html_a", "relative"], str, str | None]] = []
        # ① relative 先跑：`[x](/path)` 这一形态既命中 MARKDOWN 也命中 RELATIVE，
        #    先跑 relative 才能把 extractor 标对（mailerlite / bytebase 的回归点）。
        for m in LINK_RE_RELATIVE.finditer(line):
            raws.append(("relative", m.group("url"), None))
        for m in LINK_RE_MARKDOWN.finditer(line):
            raws.append(("markdown", m.group("url"), m.group("text")))
        for m in LINK_RE_HTML_A.finditer(line):
            raws.append(("html_a", m.group("url"), None))
        for m in LINK_RE_BARE.finditer(line):
            raws.append(("bare", m.group(0), None))

        seen_on_line: set[str] = set()
        for extractor, raw, anchor in raws:
            link = _mk_link(
                line_no=line_no,
                raw=raw,
                base_url=base_url,
                anchor_text=anchor,
                extractor=extractor,
            )
            if link is None or link.abs_url in seen_on_line:
                continue
            seen_on_line.add(link.abs_url)
            out.append(link)
    return out


def parse_index_links(text: str, base_url: str) -> list[IndexLink]:
    """返回按行号排序的 IndexLink 列表。四条抽取器并用后按 ``norm_url`` 去重。

    双 scheme（inngest ``https://www.inngest.com/docs-markdownhttps://...``）
    **整条一个 URL**、打 ``artifact="double_scheme"``（卡点 A16:2104）：拆开会造出
    站上并不存在的两个 URL，而我们要报的缺陷恰恰是「模板把两个 URL 拼在一起了」。
    """
    seen: set[str] = set()
    out: list[IndexLink] = []
    for link in extract_index_links(text, base_url):
        if link.norm_url in seen:
            continue
        seen.add(link.norm_url)
        out.append(link)
    return sorted(out, key=lambda link: link.line_no)


def sample_index_links(links: list[IndexLink], *, domain: str = "") -> tuple[list[IndexLink], bool]:
    """<= 120 条：全量。> 120 条：确定性分层抽 60 条 = 前 20 + 中段等距 20 + 后 20。

    不用纯随机：死链集中在「旧路径前缀」和「文件尾部新增条目」两处。中段的
    「等距」完全由 index 决定，**不用随机数**，所以不需要种子（卡点 A13）。

    ``domain`` 在函数体里用不到（抽样与域名无关，spec_gaps 第 23 条），保留是为了
    跟规格签名一致；给了默认值，调用点不必编一个。
    """
    if len(links) <= INDEX_LINKS_FULL_THRESHOLD:
        return links, False
    head, tail = links[:20], links[-20:]
    mid = links[20:-20]
    step = max(len(mid) // 20, 1)
    return head + mid[::step][:20] + tail, True


def grade(alive: int, dead: int, unknown: int) -> tuple[Status, Severity, bool]:
    """返回 (status, severity, counted_as_hit)。分母剔掉 unknown。§4.3:2135 照抄。

    ⚠️ ``unknown`` 参数只用来说明「它不进分母」，函数体里不读它 —— 规格就是这么
    写的，保留签名以免调用点误以为分母含 unknown。
    """
    denom = alive + dead
    ratio = dead / denom if denom else 0.0
    if dead == 0:
        return Status.PASS, Severity.INFO, False
    if denom >= 10 and ratio >= 0.90:
        return Status.FAIL, Severity.HIGH, True  # mistral 75/75 = 1.00，索引整体作废
    if ratio >= 0.30 or dead >= 3:
        return Status.FAIL, Severity.HIGH, True  # replicate 6 条 /index、inngest 3 条拼接
    return Status.PASS, Severity.LOW, False  # 1-2 条 -> 标「轻度」，列出但不进分子


@dataclass(frozen=True, slots=True)
class IndexLinkReport:
    """一份索引文件的内链存活账本 = §2.9 P3 的那一格（``kind="aggregate"``）。

    规格 §4.3 只给了 ``parse_index_links`` / ``sample_index_links`` / ``grade``
    三个函数，没给对外入口，也没给 ``alive_claims_unreliable`` /
    ``mechanism_alive`` 这两个断言字段的家（spec_gaps 第 6/7 条）。这个
    dataclass 就是它们的家：**mistral 的 75 条死链是 1 格，不是 75 格**。
    """

    index_url: str
    links: tuple[IndexLink, ...]
    probed: tuple[IndexLink, ...]
    sampled: bool
    sampled_of: int
    excluded: tuple[tuple[str, EligibilityExclusion], ...]
    alive: tuple[IndexLink, ...]
    dead: tuple[IndexLink, ...]
    unknown: tuple[IndexLink, ...]
    status: Status
    severity: Severity
    counted_as_hit: bool
    #: platform.kimi.ai 坑（§4.3:2155）：该 host 对任意路径返回 2xx
    #: （``status_discriminates=False``），所以「全活」这个结论没有信息量。
    alive_claims_unreliable: bool = False
    #: A13 要求 mistral 断言 ``mechanism_alive is True``，但该字段全文无定义
    #: （spec_gaps 第 7 条）。这里定义为：「同机制的对照页探到 200」——
    #: 即 C02 ``docs.mistral.ai/getting-started/platform-overview.md`` 那条。
    #: 没传对照页时是 None（「没测过」，不是 False）。
    mechanism_alive: bool | None = None
    unknown_reasons: tuple[str, ...] = ()
    #: ``abs_url -> Evidence``，探到的那些链接各自的观测。
    #:
    #: 为什么要留着：一份说「这条链接死了」的报告，原来不带它测到的状态码 ——
    #: ``_evidence_for_url`` 是「没有响应体可挂时的最小 Evidence」，而这里明明
    #: 有响应。``curl_repro`` 在，所以 claim 可复核，但读的人看不见它到底返回了
    #: 什么，得自己跑一遍才知道是 404 还是 410。
    #:
    #: 空字典 = 这份账本没带观测（手工构造的测试账本），调用方回落到最小 Evidence。
    evidence_by_url: Mapping[str, Evidence] = field(default_factory=dict)

    @property
    def n_links(self) -> int:
        return len(self.links)

    @property
    def n_alive(self) -> int:
        return len(self.alive)

    @property
    def n_dead(self) -> int:
        return len(self.dead)

    @property
    def n_unknown(self) -> int:
        return len(self.unknown)

    @property
    def n_excluded(self) -> int:
        return len(self.excluded)

    def detail(self) -> dict[str, str | int | float | bool]:
        """五个固定键 + ``sampled`` / ``sampled_of`` 两个可选键（§4.3:2152）。"""
        out: dict[str, str | int | float | bool] = {
            "index_url": self.index_url,
            "n_links": self.n_links,
            "n_alive": self.n_alive,
            "n_dead": self.n_dead,
            "n_unknown": self.n_unknown,
        }
        if self.sampled:
            out["sampled"] = True
            out["sampled_of"] = self.sampled_of
        return out


def _link_state_of(probe: Probe) -> Literal["alive", "dead", "unknown"]:
    """探测结果 → 三态。SOFT404 与 REAL404 都算死（一个是骗人、一个是诚实）；
    BLOCKED / UNKNOWN 一条都不许折算成 alive（C09 pipedrive 8 条 429）。"""
    if probe.verdict is Verdict.OK:
        return "alive"
    if probe.verdict in (Verdict.REAL404, Verdict.SOFT404):
        return "dead"
    return "unknown"


def probe_index_links(
    domain: str,
    index_probe: Probe,
    *,
    fetcher: Prober,
    control: HostProfile | None = None,
    mechanism_probe: Probe | None = None,
    user_agent: str = "",
) -> IndexLinkReport:
    """抽取 → 去噪 → 抽样 → 探活 → 分级。**探测前必须过一遍去噪表**：saleor 的
    ``.../docs/{path}.mdx`` 只有 ``url_template_placeholder`` 这一条路能排除
    （A13；§5.3:2688），被排除的链接一个请求都不发。

    探用 ``abs_url`` 原样（服务端可能对 query 敏感），归并与身份用 ``norm_url``
    （§5.4:2840）。
    """
    resp = index_probe.response
    assert resp is not None, "索引内链检查只对判为真文件的索引跑"
    base_url = resp.final_url
    links = parse_index_links(resp.text, base_url)

    eligible: list[IndexLink] = []
    excluded: list[tuple[str, EligibilityExclusion]] = []
    for link in links:
        ctx = LinkContext(
            source_page=base_url,
            anchor_text=link.anchor_text or "",
            from_text_file=True,
        )
        ex = classify_link_eligibility(link.abs_url, ctx)
        if ex is not None:
            excluded.append((link.abs_url, ex))
            fetcher.note_exclusion(link.abs_url, ex.rule_id, ex.reason)
            continue
        eligible.append(link)

    sample, sampled = sample_index_links(eligible, domain=domain)
    results = (
        fetcher.probe_many([link.abs_url for link in sample], expect=Expect.ANY, liveness_only=True)
        if sample
        else []
    )
    by_url = {p.url: p for p in results}

    alive: list[IndexLink] = []
    dead: list[IndexLink] = []
    unknown: list[IndexLink] = []
    reasons: list[str] = []
    evidence_by_url: dict[str, Evidence] = {}
    for link in sample:
        probe = by_url.get(link.abs_url)
        if probe is None:
            unknown.append(link)
            reasons.append("not_fetched")
            continue
        if probe.response is not None:
            evidence_by_url[link.abs_url] = evidence_of(probe.response, user_agent=user_agent)
        state = _link_state_of(probe)
        if state == "alive":
            alive.append(link)
        elif state == "dead":
            dead.append(link)
        else:
            unknown.append(link)
            reasons.append(probe.classification.reason)

    status, severity, counted = grade(len(alive), len(dead), len(unknown))
    unreliable = control is not None and control.usable and not control.status_discriminates
    return IndexLinkReport(
        index_url=base_url,
        links=tuple(links),
        probed=tuple(sample),
        sampled=sampled,
        sampled_of=len(eligible),
        excluded=tuple(excluded),
        alive=tuple(alive),
        dead=tuple(dead),
        unknown=tuple(unknown),
        status=status,
        severity=severity,
        counted_as_hit=counted,
        evidence_by_url=evidence_by_url,
        alive_claims_unreliable=unreliable,
        mechanism_alive=(
            None if mechanism_probe is None else mechanism_probe.verdict is Verdict.OK
        ),
        unknown_reasons=tuple(dict.fromkeys(reasons)),
    )


def check_index_links(
    domain: str,
    index_probe: Probe,
    *,
    fetcher: Prober,
    control: HostProfile | None = None,
    mechanism_probe: Probe | None = None,
    user_agent: str = "",
) -> tuple[Finding, ...]:
    """§4.3 的对外入口（规格没给签名，见 spec_gaps 第 6 条）。

    finding 身份 = 唯一 ``norm_url``（A16）：同一个 norm_url 在索引里出现 10 次是
    **1 条 finding、occurrences=10**。1–2 条死链走 ``Severity.LOW`` +
    ``counted_as_hit=False``，``display_value`` 写「轻度」——列出来但不进分子。
    """
    report = probe_index_links(
        domain,
        index_probe,
        fetcher=fetcher,
        control=control,
        mechanism_probe=mechanism_probe,
        user_agent=user_agent,
    )
    return findings_from_index_report(report, domain=domain, user_agent=user_agent)


def _target_evidence(report: IndexLinkReport, link: IndexLink, *, user_agent: str) -> Evidence:
    """死链 finding 的 target：有观测就用观测，没有就退回最小 Evidence。

    ``curl_repro`` **一律按这里的 ``user_agent`` 重算**：账本可能是
    ``probe_index_links`` 直接造的（pipeline 就是这么调的），那一层没有 UA，
    于是证据里的复现命令会印成 `contact: 未注入`。UA 是复现命令的一部分 ——
    换个 UA 站点可能换个答案 —— 所以这里不能沿用一个空的。
    """
    observed = report.evidence_by_url.get(link.abs_url)
    if observed is None:
        return _evidence_for_url(link.abs_url, user_agent=user_agent)
    return replace(observed, curl_repro=_curl_repro(observed.url, user_agent))


def findings_from_index_report(
    report: IndexLinkReport, *, domain: str, user_agent: str = ""
) -> tuple[Finding, ...]:
    """把账本变成 finding（一条死 norm_url 一条）。dead == 0 时零 finding。"""
    if not report.dead:
        return ()
    resp_text_links = extract_index_links_occurrences(report)
    light = not report.counted_as_hit
    guards = tuple(f"{url} 被 {ex.rule_id} 排除" for url, ex in report.excluded)
    out: list[Finding] = []
    for link in report.dead:
        occ = resp_text_links.get(link.norm_url, (1, (link.abs_url,)))
        artifact = f"，抽取形态 {link.artifact}" if link.artifact else ""
        contrast = naive_contrast(
            probe_url=link.abs_url,
            apex=domain,
            http_status=None,
            real_status=Status.FAIL,
            actual_conclusion=(
                f"索引里列的这条链接死了（{report.n_dead}/{report.n_alive + report.n_dead}"
                f" 条判死{artifact}）"
            ),
            extra_requests=1,
            why="朴素实现不验索引里的链接，这一格它压根不问",
        )
        out.append(
            _finding(
                kind="index_link_dead",
                check_id="ai_path.index_links",
                title=f"llms.txt 里列的 {link.abs_url} 是死链",
                severity=report.severity,
                stage=Stage.INDEX_LINKS,
                target=_target_evidence(report, link, user_agent=user_agent),
                norm_url=link.norm_url,
                domain=domain,
                found_on=report.index_url,
                anchor_text=link.anchor_text,
                why_it_matters=(
                    "AI 顺着你的索引往下爬，爬到的是 404。索引里的死链等于把 AI 引到空页面上。"
                ),
                display_value=(
                    ("轻度：" if light else "")
                    + f"该索引 {report.n_dead} 条死 / {report.n_alive} 条活"
                    + f" / {report.n_unknown} 条判不了"
                    + ("（不进首页分子）" if light else "")
                ),
                naive=contrast,
                counted_as_hit=report.counted_as_hit,
                detail=report.detail(),
                occurrences=occ[0],
                occurrence_hrefs=occ[1],
                fp_guard=guards,
                fp_note=(
                    "该 host 对任意路径都返回 2xx（status_discriminates=False），"
                    "这一格的「全活」结论没有信息量。"
                    if report.alive_claims_unreliable
                    else None
                ),
            )
        )
    return tuple(out)


def extract_index_links_occurrences(
    report: IndexLinkReport,
) -> dict[str, tuple[int, tuple[str, ...]]]:
    """norm_url -> (出现次数, 原始 href 全列)。A16：同一 norm_url 出现 10 次是
    1 条 finding、occurrences=10。"""
    table: dict[str, list[str]] = {}
    for link in report.links:
        table.setdefault(link.norm_url, []).append(link.abs_url)
    return {k: (len(v), tuple(v)) for k, v in table.items()}


# ═════════════════════════════════════════════════════════════════════════════
# 子检查四 · .md 约定兑现 —— §4.4:2161-2372
# ═════════════════════════════════════════════════════════════════════════════

MdScope = Literal[
    "ANY_URL",
    "ANY_PAGE",
    "PREFIX",
    "DOCS_ONLY",
    "IMPLICIT_INDEX",
    "HTML_SWAP",
    "ENUMERATED",
    "UNKNOWN",
]

MdVerdict = Literal[
    "FULFILLED",
    "HARD_404",
    "SOFT_404_HTML",
    "SOFT_404_TEXT",
    "OPAQUE_ERROR",
    "OUT_OF_SCOPE",
    "UNDETERMINED",
]

#: §4.4:2201 七条声明正则，顺序即优先级（第一条命中者的 scope 生效）。
MD_PATTERNS: list[tuple[re.Pattern[str], MdScope]] = [
    (
        re.compile(
            r"all pages on this site are available in markdown format by appending\s+`?\.md`?",
            re.I,
        ),
        "ANY_URL",
    ),
    (re.compile(r"append\s+`?\.md`?\s+to\s+any\s+html\s+url", re.I), "ANY_URL"),  # depot.dev
    (
        re.compile(
            r"append\s+`?\.md`?\s+to\s+any\s+url\s+under\s+`?(?P<prefix>https?://[^\s`]+)`?", re.I
        ),
        "PREFIX",
    ),  # dev.wix.com/docs/
    (
        re.compile(r"append\s+`?\.md`?\s+to\s+any\s+documentation\s+page\s+url", re.I),
        "DOCS_ONLY",
    ),  # gusto/pipedrive/teachable/onfleet/factorial/voyageai/customer.io
    (
        re.compile(r"for clean markdown of any page,?\s*append\s+`?\.md`?", re.I),
        "ANY_PAGE",
    ),  # deepgram/hume/bigcommerce
    (re.compile(r"replace\s+`?\.html`?\s+with\s+`?\.md`?", re.I), "HTML_SWAP"),  # emqx
    (
        re.compile(r"many urls on this site are available as markdown", re.I),
        "ENUMERATED",
    ),  # hookdeck
]

#: hookdeck 自己写的例外条款（§4.4:2210）。
EXCEPTION_RE = re.compile(r"pages without a\s+`?\.md`?\s+version return html", re.I)

#: §4.4:2222 来源 B1 的横幅正则。
_MD_BANNER_RE = re.compile(
    r"(view|read|open)\s+(this\s+page\s+)?as\s+markdown|copy\s+page\s+as\s+markdown"
    r"|markdown\s+version|\.md\s+version",
    re.I,
)

#: §4.4:2256。每个声明最多抽 3 条，每条最多 2 个请求（.md + html 双胞胎）
#: → 预算上界 = 6 个请求 = 12 秒/域。
MD_SAMPLE_N = 3

#: §4.4:2280 文档 host 前缀正则。
#: ⚠️ 与 ``discovery.DOC_HOST_PREFIXES``（16 项）不一致：这条正则覆盖不到
#: ``supportcenter``（``apidocs?`` 已经把 apidoc 盖住了）。两份清单并存会让
#: 「这是不是文档 host」的判定分叉，见 spec_gaps；测试守在
#: tests/test_subdomain_discovery.py 的 test_doc_host_prefix_lists_agree_or_differ。
_DOC_HOST_RE = re.compile(
    r"^(docs?|developers?|dev|api|apidocs?|api-docs|support|help|platform|"
    r"reference|guides|learn|kb)\.",
    re.I,
)

#: §4.4:2290。「主力页」= 甲方最不能坏的那几个页面路径。固定清单、固定顺序，零随机。
#: 顺序即优先级：定价页在最前，因为 depot 那条实测命中就是 /pricing.md 404。
FLAGSHIP_PATHS: tuple[str, ...] = (
    "/pricing",
    "/pricing/",
    "/plans",
    "/plans/",  # 定价
    "/",
    "/index",  # 首页
    "/docs",
    "/docs/",  # 文档首页
)

#: §4.4:2348 算「没兑现」的四个 verdict。
_MISSED: tuple[MdVerdict, ...] = ("HARD_404", "SOFT_404_HTML", "SOFT_404_TEXT", "OPAQUE_ERROR")

#: B2 命中时记的 coverage gap 文案（§4.4:2245，协商通道我们不评估）。
MD_NEGOTIATION_GAP = (
    "你的站通过内容协商提供 markdown（我们从响应头看到了），"
    "本工具只检查 .md 后缀通道，协商通道未评估。"
)

_LINK_HEADER_RE = re.compile(
    r"<(?P<url>[^>]+)>\s*;[^,]*rel\s*=\s*\"?alternate\"?[^,]*type\s*=\s*\"?text/markdown\"?", re.I
)


@dataclass(frozen=True, slots=True)
class MdSample:
    """一次 ``.md`` 抽样（§4.4:2189）。"""

    html_url: str  # 原始 HTML 页 URL
    md_url: str  # 我们请求的 .md URL
    in_scope: bool  # 由 sample_md_targets 决定，不由判定结果决定
    verdict: MdVerdict
    md_status: int | None
    md_content_type: str | None
    md_bytes: int | None
    md_head: str | None  # 归一化正文前 240 字符，报告展示
    html_twin_status: int | None  # ⚠️ 三条佐证里第三条要用，必须探
    evidence: str = ""


@dataclass(frozen=True, slots=True)
class MdDeclaration:
    """站点声明了「任意页面加 .md」这个约定的一处证据（§4.4:2174）。"""

    source: Literal["A_llms_txt", "B_page_signal", "C_implicit_index"]
    source_url: str  # 声明出现在哪
    declaration_text: str  # 声明原文（报告逐字回显；UNKNOWN 时为空串）
    scope: MdScope
    scope_prefix: str = ""  # scope == "PREFIX" 时的绝对 URL 前缀
    stated_exception: bool = False  # 站点自己写了例外条款（hookdeck）
    samples: tuple[MdSample, ...] = ()
    suppressed_by: str | None = None  # "scope_unknown" / "no_fulfilled_sample" /
    #                                   "html_twin_also_404" / None
    #: B2 命中时置 True：报告要加一行「协商通道未评估」并记一条 CoverageGap。
    negotiation_advertised: bool = False


def _window(text: str, start: int, end: int, *, span: int = 120) -> str:
    return text[max(0, start - span) : end + span].strip()


def _scope_from_text(text: str) -> tuple[MdScope, str, str] | None:
    """跑 MD_PATTERNS，返回 (scope, 声明原文, PREFIX 的前缀)。全不命中返回 None。"""
    for pattern, scope in MD_PATTERNS:
        m = pattern.search(text)
        if m is None:
            continue
        prefix = ""
        if scope == "PREFIX":
            try:
                prefix = (m.group("prefix") or "").rstrip("`\"'")
            except IndexError:  # pragma: no cover —— 正则里就有这个组
                prefix = ""
        return scope, _window(text, m.start(), m.end()), prefix
    return None


def detect_md_declaration_from_index(probe: Probe) -> MdDeclaration | None:
    """来源 A（0 请求）：判为真文件的 llms.txt / llms-full.txt 正文跑 MD_PATTERNS。"""
    if probe.verdict is not Verdict.OK or probe.response is None:
        return None
    text = probe.response.text
    hit = _scope_from_text(text)
    if hit is None:
        return None
    scope, declaration_text, prefix = hit
    return MdDeclaration(
        source="A_llms_txt",
        source_url=probe.response.final_url,
        declaration_text=declaration_text,
        scope=scope,
        scope_prefix=prefix,
        stated_exception=EXCEPTION_RE.search(text) is not None,
    )


def detect_md_signal_from_page(resp: HttpResponse) -> MdDeclaration | None:
    """来源 B（≤1 请求）：只看**已经抓到的**文档首页响应，不为它单独发请求。

    B1 页内控件/横幅：可见文本命中 ``_MD_BANNER_RE`` → declaration_text 取命中处
       前后各 120 字符；``MD_PATTERNS`` 全不命中但信号存在 → ``scope="UNKNOWN"``。
    B2 响应头 ``Link: <...>; rel="alternate"; type="text/markdown"`` → scope 由
       Link 的 URL 形状定：同路径加 ``.md`` → ANY_PAGE；其它 → PREFIX（prefix =
       该 URL 的目录）。
    B3 内容协商：**v2 明确不做** —— 不发 ``Accept: text/markdown`` 探测请求
       （三条理由见 §4.4:2237-2243）。B2 命中时只置 ``negotiation_advertised``。
    """
    text = resp.text
    seen = visible_text(text)
    hit = _scope_from_text(seen) or _scope_from_text(text)

    link_hdr = _LINK_HEADER_RE.search(resp.headers.get("link", ""))
    if link_hdr is not None:
        alt = urljoin(resp.final_url, link_hdr.group("url"))
        same_path = _md_url(resp.final_url, "ANY_PAGE")
        if _same_url(alt, same_path):
            scope: MdScope = "ANY_PAGE"
            prefix = ""
        else:
            scope = "PREFIX"
            alt_parts = urlsplit(alt)
            prefix = urlunsplit(
                (
                    alt_parts.scheme,
                    alt_parts.netloc,
                    alt_parts.path.rsplit("/", 1)[0] + "/",
                    "",
                    "",
                )
            )
        return MdDeclaration(
            source="B_page_signal",
            source_url=resp.final_url,
            declaration_text=f'Link: <{alt}>; rel="alternate"; type="text/markdown"',
            scope=hit[0] if hit is not None else scope,
            scope_prefix=hit[2] if hit is not None and hit[0] == "PREFIX" else prefix,
            stated_exception=EXCEPTION_RE.search(text) is not None,
            negotiation_advertised=True,
        )

    banner = _MD_BANNER_RE.search(seen) or _MD_BANNER_RE.search(text)
    if banner is None:
        return None
    return MdDeclaration(
        source="B_page_signal",
        source_url=resp.final_url,
        # scope=UNKNOWN 时 declaration_text 为空串（§4.4:2177 的口径）。
        declaration_text=hit[1] if hit is not None else "",
        scope=hit[0] if hit is not None else "UNKNOWN",
        scope_prefix=hit[2] if hit is not None else "",
        stated_exception=EXCEPTION_RE.search(text) is not None,
    )


def detect_md_implicit_index(probe: Probe, *, threshold: float = 0.80) -> MdDeclaration | None:
    """来源 C（0 请求）：索引里 **≥80%** 链接以 ``.md`` 结尾 → 恒为 IMPLICIT_INDEX。"""
    if probe.verdict is not Verdict.OK or probe.response is None:
        return None
    resp = probe.response
    links = parse_index_links(resp.text, resp.final_url)
    if not links:
        return None
    md_like = sum(1 for link in links if urlsplit(link.abs_url).path.lower().endswith(".md"))
    if md_like / len(links) < threshold:
        return None
    return MdDeclaration(
        source="C_implicit_index",
        source_url=resp.final_url,
        declaration_text=(
            f"索引里 {md_like}/{len(links)} 条链接以 .md 结尾（隐式声明，站点没写成文字）"
        ),
        scope="IMPLICIT_INDEX",
    )


def _is_doc_host(url: str) -> bool:
    """host 以文档型前缀开头，**或** path 以 ``/docs`` 开头（§4.4:2285）。"""
    parts = urlsplit(url)
    return bool(_DOC_HOST_RE.match(parts.netloc)) or parts.path.startswith("/docs")


def _registrable(host: str) -> str:
    """够用的注册域近似：取最后两段。跨 host 比较只需要「是不是同一家」。"""
    bits = host.lower().split(".")
    return ".".join(bits[-2:]) if len(bits) >= 2 else host.lower()


def _dedup(urls: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(u for u in urls if u))


def _flagship(
    links: Sequence[str],
    domain: str,
    *,
    fetcher: Prober | None = None,
) -> list[str]:
    """返回按 FLAGSHIP_PATHS 顺序命中的**站内**主力页 URL，最多 2 条（§4.4:2298）。

    两个来源，按顺序：
      1. links 里 path 恰好等于 FLAGSHIP_PATHS 某一项且注册域相同；
      2. 都没命中时，构造 ``f"https://{domain}{p}"`` 并**先探 HTML 版**：
         HTML 版返回 200 才把它当主力页（否则这个域就是没有定价页，见 §3.7）。
    确定性：完全由 FLAGSHIP_PATHS 的顺序 + links 的既有顺序决定，无随机、无种子。

    ⚠️ 规格签名里没有 fetcher（spec_gaps 第 17 条）：来源 ② 要发请求却没地方拿
    client。这里加 keyword-only 的 ``fetcher``；不传就只走来源 ①（不猜、不编）。
    来源 ② 的请求**算进** §4.4:2256 的 6 请求/域预算，由调用方计数。
    """
    want = _registrable(domain)
    out: list[str] = []
    for path in FLAGSHIP_PATHS:
        for url in links:
            parts = urlsplit(url)
            if _registrable(parts.hostname or "") != want:
                continue
            if (parts.path or "/") == path:
                out.append(url)
                break
        if len(out) >= 2:
            return _dedup(out)[:2]
    if out or fetcher is None:
        return _dedup(out)[:2]
    for path in FLAGSHIP_PATHS:
        candidate = f"https://{domain}{path}"
        probe = fetcher.probe(candidate, expect=Expect.HTML_PAGE)
        if probe.response is not None and probe.response.status == 200:
            out.append(candidate)
        if len(out) >= 2:
            break
    return _dedup(out)[:2]


def _one_per_category(declaration_text: str, links: Sequence[str]) -> list[str]:
    """ENUMERATED（hookdeck「many urls ... are available as markdown」）：声明没给
    范围，所以按**路径第一段**分类，每类取该类中 links 里最先出现的 1 条，按第一段
    字典序取前 MD_SAMPLE_N 类。零随机。

    ⚠️ ``declaration_text`` 在逻辑里用不上（spec_gaps 第 22 条）：规格既要这个
    参数、描述里又没用它。保留签名，函数体不读它。
    """
    buckets: dict[str, str] = {}
    for url in links:
        segs = [s for s in urlsplit(url).path.split("/") if s]
        head = segs[0] if segs else ""
        buckets.setdefault(head, url)
    return [buckets[k] for k in sorted(buckets)][:MD_SAMPLE_N]


def _md_url(html_url: str, scope: MdScope) -> str:
    """HTML URL → ``.md`` URL。

    ⚠️ 规格没定义这条规则（spec_gaps 第 18 条），只能从 K 组样本反推，这里定死：
      * ``HTML_SWAP``：``.html`` 换 ``.md``（emqx）；
      * 路径是 ``/`` 或空 → ``/index.md``（K 组隐含：depot / resend / browserbase）；
      * 带尾斜杠 → 去掉尾斜杠再加 ``.md``；
      * 已经以 ``.md`` 结尾 → 原样；
      * query 与 fragment 一律丢掉（.md 是静态产物，带 query 无意义）。
    """
    parts = urlsplit(html_url)
    path = parts.path or "/"
    if scope == "HTML_SWAP":
        new_path = re.sub(r"\.html?$", ".md", path, flags=re.I)
    elif path in ("", "/"):
        new_path = "/index.md"
    elif path.lower().endswith(".md"):
        new_path = path
    else:
        new_path = path.rstrip("/") + ".md"
    return urlunsplit((parts.scheme, parts.netloc, new_path, "", ""))


def _docs_pool(links: Sequence[str]) -> list[str]:
    return [u for u in links if "/docs" in urlsplit(u).path or _is_doc_host(u)]


def sample_md_targets(
    decl: MdDeclaration,
    links: Sequence[str],
    domain: str,
    *,
    fetcher: Prober | None = None,
) -> list[str]:
    """§4.4:2258 照抄。**范围外一律不抽。**"""
    docs = _docs_pool(links)
    match decl.scope:
        case "ANY_URL" | "ANY_PAGE":
            # 声明覆盖全站 -> **必须抽主力页**，否则抓不到 depot 那条 /pricing.md
            return _dedup(
                [f"https://{domain}/", *_flagship(links, domain, fetcher=fetcher), *docs[:1]]
            )[:MD_SAMPLE_N]
        case "PREFIX":
            return [u for u in links if u.startswith(decl.scope_prefix)][:MD_SAMPLE_N]
        case "DOCS_ONLY" | "IMPLICIT_INDEX":
            return docs[:MD_SAMPLE_N]  # **绝不抽 /index.md、/pricing.md**
        case "HTML_SWAP":
            return [u for u in links if u.endswith(".html")][:MD_SAMPLE_N]
        case "ENUMERATED":
            return _one_per_category(decl.declaration_text, links)
        case _:  # "UNKNOWN"
            return []  # 一个都不抽，只标「需补测声明原文」


def out_of_scope_candidates(decl: MdDeclaration, links: Sequence[str], domain: str) -> list[str]:
    """被**显式**排除在声明范围外的候选页（首页 + 主力页 + 文档门户根）。

    ⚠️ 规格缺口（spec_gaps 第 5 条）：``MdVerdict`` 里有 ``OUT_OF_SCOPE``、A14 与
    第 10 步自验都要求 resend / turso / assemblyai 判 ``OUT_OF_SCOPE``，但
    ``judge_md_sample`` 的分支里根本产不出这个值，``sample_md_targets`` 也只返回
    范围内的 URL。裁决：范围外候选**单独列出、一个请求都不发**（「范围外一律不抽」
    的原话必须守住），由 ``check_md_convention`` 造成 ``in_scope=False`` +
    ``verdict="OUT_OF_SCOPE"`` 的样本，只作报告展示，不参与三条佐证。
    """
    if decl.scope in ("ANY_URL", "ANY_PAGE", "UNKNOWN"):
        return []  # 全站声明没有「范围外」；UNKNOWN 一个都不抽也不列
    in_scope = set(sample_md_targets(decl, links, domain))
    pool = _dedup([f"https://{domain}/", *(u for u in links if _flagship_path(u))])
    return [u for u in pool if u not in in_scope][:MD_SAMPLE_N]


def _flagship_path(url: str) -> bool:
    return (urlsplit(url).path or "/") in FLAGSHIP_PATHS


def judge_md_sample(
    md: HttpResponse,
    html_twin: HttpResponse | None,
    control: HostProfile | None,
) -> MdVerdict:
    """§4.4:2326 照抄，外加一条 S10 规程（见下）。

    ⚠️ 两处规格问题（spec_gaps 第 15/16 条）：
      * ``html_twin`` 在规格的函数体里一次都没用到，而 ``MdSample.html_twin_status``
        是第三条佐证的必需项 —— 探双胞胎的活由 ``check_md_convention`` 干，
        这个参数在这里只用于「双胞胎自己也 404 时不把 .md 的 404 说成机制坏了」的
        提示（不改判定，保持与规格逐条一致）；
      * ``md.norm_sha256`` 走 liveness_only 时恒为 None，``None == control.norm_sha256``
        恒 False，会静默退化成 FULFILLED（假阴）。这里按 §4.2 的 S10 规程补一条
        显式判据：摘要缺失时**不比**，判 UNDETERMINED，而不是当「哈希不同」。
    """
    if md.blocked or md.status in (401, 403, 429):
        return "UNDETERMINED"
    if md.status in (404, 410):
        if md.content_type.startswith("application/json") and md.text.strip() == "null":
            return "OPAQUE_ERROR"  # unkey .../billing.md：404 + JSON null（4 B）
        return "HARD_404"
    if md.status == 200:
        if looks_like_html(md.text, md.content_type):
            return "SOFT_404_HTML"
        if md.byte_len < 2000 and find_notfound_copy(md.text) is not None:
            return "SOFT_404_TEXT"
        if control is not None and control.usable:
            if md.norm_sha256 is None:
                return "UNDETERMINED"  # S10：摘要缺失不当「哈希不同」
            if md.norm_sha256 == control.norm_sha256:
                return "SOFT_404_HTML"
        return "FULFILLED"
    return "UNDETERMINED"


def _suppress(decl: MdDeclaration, why: str) -> tuple[MdDeclaration, Finding | None]:
    return replace(decl, suppressed_by=why), None


def finalize(
    decl: MdDeclaration,
    *,
    domain: str = "",
    user_agent: str = "",
) -> tuple[MdDeclaration, Finding | None]:
    """三条佐证，全过才 reportable（§4.4:2350 照抄）。

    返回 (带 suppressed_by 的声明, finding 或 None)。四个私有分支：
      ``_suppress`` → (replace(decl, suppressed_by=why), None)
      ``_ok``       → (decl, None)                                # 兑现了
      ``_downgrade``→ (decl, Finding(severity=INFO, counted_as_hit=False))
      ``_report``   → (decl, Finding(severity=HIGH, counted_as_hit=True))
    """
    missed = [s for s in decl.samples if s.in_scope and s.verdict in _MISSED]
    if decl.scope == "UNKNOWN":
        return _suppress(decl, "scope_unknown")  # browserbase：宁可漏报不假报
    if not missed:
        return decl, None  # _ok
    if not any(s.verdict == "FULFILLED" for s in decl.samples):
        return _suppress(decl, "no_fulfilled_sample")  # 机制根本不存在 != 声明没兑现
    if all(s.html_twin_status in (404, 410) for s in missed):
        return _suppress(decl, "html_twin_also_404")  # 页面本身没了 -> 归内链检查
    if decl.stated_exception and all(s.verdict == "HARD_404" for s in missed):
        return decl, _md_finding(
            decl, missed, severity=Severity.INFO, counted=False, domain=domain, ua=user_agent
        )  # _downgrade：hookdeck 自己写了例外条款
    return decl, _md_finding(
        decl, missed, severity=Severity.HIGH, counted=True, domain=domain, ua=user_agent
    )  # _report


def _md_finding(
    decl: MdDeclaration,
    missed: Sequence[MdSample],
    *,
    severity: Severity,
    counted: bool,
    domain: str,
    ua: str,
) -> Finding:
    first = missed[0]
    others = "；".join(f"{s.md_url} → {s.verdict}" for s in missed[1:])
    contrast = naive_contrast(
        probe_url=first.md_url,
        apex=domain or (urlsplit(first.md_url).hostname or ""),
        http_status=first.md_status,
        real_status=Status.FAIL,
        actual_conclusion=(
            f"声明的 .md 约定在范围内没兑现：{first.md_url} → {first.verdict}"
            + (f"；另有 {others}" if others else "")
        ),
        extra_requests=2,  # .md + HTML 双胞胎
        why="朴素实现不解析声明范围，也不探 HTML 双胞胎；它要么全不报、要么把范围外的也报上",
    )
    detail: dict[str, str | int | float | bool] = {
        "source": decl.source,
        "source_url": decl.source_url,
        "scope": decl.scope,
        "scope_prefix": decl.scope_prefix,
        "declaration_text": decl.declaration_text,
        "stated_exception": decl.stated_exception,
        "n_samples": len(decl.samples),
        "n_missed": len(missed),
        "n_fulfilled": sum(1 for s in decl.samples if s.verdict == "FULFILLED"),
        "negotiation_advertised": decl.negotiation_advertised,
    }
    return _finding(
        kind="md_unfulfilled",
        check_id="ai_path.md_convention",
        title=f"声明了「加 .md」但范围内的页面拿不到 markdown：{first.md_url}",
        severity=severity,
        stage=Stage.MD_CHANNEL,
        target=_evidence_for_url(first.md_url, user_agent=ua),
        norm_url=normalize_url(first.md_url),
        domain=domain,
        found_on=decl.source_url,
        why_it_matters=(
            "你自己写了「任意页面加 .md」，AI 就会照着拼 URL。范围内拼不出来的那些页面，"
            "AI 拿到的是 404 或一个壳 —— 声明本身成了误导。"
        ),
        display_value=(
            f"范围 {decl.scope}，抽 {len(decl.samples)} 条，{len(missed)} 条没兑现"
            + ("（站点自写例外条款，降为提示）" if not counted else "")
        ),
        naive=contrast,
        counted_as_hit=counted,
        detail=detail,
        fp_guard=(
            "第一条佐证：声明范围可解析（scope != UNKNOWN）",
            "第二条佐证：至少有一条 FULFILLED 样本（机制存在）",
            "第三条佐证：没兑现的样本，其 HTML 双胞胎必须 200（页面本身还在）",
        ),
        confidence="confirmed" if counted else "needs_review",
    )


def check_md_convention(
    domain: str,
    index_probes: Sequence[Probe],
    doc_home: HttpResponse | None,
    links: Sequence[str],
    *,
    fetcher: Prober,
    controls: Mapping[str, HostProfile] | None = None,
    user_agent: str = "",
) -> tuple[MdDeclaration | None, Finding | None]:
    """§4.4 的对外入口（规格没给签名，见 spec_gaps 第 6 条）。

    P4 恒一格，所以按 source 权威度 **A > B > C 只取唯一一个** MdDeclaration，
    其余进 ``detail["other_declarations"]``（§4.4:2248）。

    ⚠️ 返回类型比简报多一个 None：MS04（inngest 声明的是 ``/docs-markdown/`` 前缀
    路径而不是 ``.md`` 后缀）要求「没有 MdDeclaration → 不产生 finding」，
    ``tuple[MdDeclaration, Finding | None]`` 表达不了「没有声明」。
    """
    table = controls or {}
    found: list[MdDeclaration] = []
    for probe in index_probes:
        decl_a = detect_md_declaration_from_index(probe)
        if decl_a is not None:
            found.append(decl_a)
    if doc_home is not None:
        decl_b = detect_md_signal_from_page(doc_home)
        if decl_b is not None:
            found.append(decl_b)
    for probe in index_probes:
        decl_c = detect_md_implicit_index(probe)
        if decl_c is not None:
            found.append(decl_c)
    if not found:
        return None, None

    rank = {"A_llms_txt": 0, "B_page_signal": 1, "C_implicit_index": 2}
    found.sort(key=lambda d: rank[d.source])
    decl = found[0]

    targets = sample_md_targets(decl, links, domain, fetcher=fetcher)
    samples: list[MdSample] = []
    for html_url in targets:
        md_url = _md_url(html_url, decl.scope)
        md_probe = fetcher.probe(md_url, expect=Expect.TEXT_FILE)
        twin = fetcher.probe(html_url, expect=Expect.HTML_PAGE)
        md_resp = md_probe.response
        twin_resp = twin.response
        if md_resp is None:
            samples.append(
                MdSample(
                    html_url=html_url,
                    md_url=md_url,
                    in_scope=True,
                    verdict="UNDETERMINED",
                    md_status=None,
                    md_content_type=None,
                    md_bytes=None,
                    md_head=None,
                    html_twin_status=twin_resp.status if twin_resp is not None else None,
                    evidence=md_probe.classification.reason,
                )
            )
            continue
        host = (urlsplit(md_url).hostname or "").lower()
        verdict = judge_md_sample(md_resp, twin_resp, table.get(host))
        samples.append(
            MdSample(
                html_url=html_url,
                md_url=md_url,
                in_scope=True,
                verdict=verdict,
                md_status=md_resp.status,
                md_content_type=md_resp.content_type or None,
                md_bytes=md_resp.byte_len,
                md_head=_body_head(md_resp),
                html_twin_status=twin_resp.status if twin_resp is not None else None,
                evidence="；".join(md_probe.classification.evidence),
            )
        )
    # 范围外候选：零请求，只列出来给报告用（不进三条佐证）。
    for html_url in out_of_scope_candidates(decl, links, domain):
        samples.append(
            MdSample(
                html_url=html_url,
                md_url=_md_url(html_url, decl.scope),
                in_scope=False,
                verdict="OUT_OF_SCOPE",
                md_status=None,
                md_content_type=None,
                md_bytes=None,
                md_head=None,
                html_twin_status=None,
                evidence=f"声明范围是 {decl.scope}，这一页不在范围内，按设计不探",
            )
        )

    decl = replace(decl, samples=tuple(samples))
    decl, finding = finalize(decl, domain=domain, user_agent=user_agent)
    if finding is not None and len(found) > 1:
        detail = dict(finding.detail)
        detail["other_declarations"] = "；".join(
            f"{d.source}@{d.source_url}({d.scope})" for d in found[1:]
        )
        finding = replace(finding, detail=detail)
    return decl, finding


__all__ = [
    "EXCEPTION_RE",
    "FINDING_KINDS",
    "FLAGSHIP_PATHS",
    "INDEX_LINKS_DETAIL_KEYS",
    "INDEX_LINKS_FULL_THRESHOLD",
    "INDEX_LINKS_SAMPLE_SIZE",
    "LINK_RE_BARE",
    "LINK_RE_HTML_A",
    "LINK_RE_MARKDOWN",
    "LINK_RE_RELATIVE",
    "LLMS_FULL_DETAIL_KEYS",
    "MD_NEGOTIATION_GAP",
    "MD_PATTERNS",
    "MD_SAMPLE_N",
    "NAIVE_ADOPTED",
    "NAIVE_HOST_TEMPLATES",
    "NAIVE_NOT_PROBED",
    "NAIVE_PATHS",
    "RIGHT_STRIP_CHARS",
    "RIGHT_STRIP_PUNCT",
    "SOFT404_DETAIL_KEYS",
    "UA_NOT_INJECTED",
    "UNKNOWN_REMEDY",
    "Evidence",
    "Finding",
    "FindingKind",
    "FixHint",
    "IndexLink",
    "IndexLinkReport",
    "MdDeclaration",
    "MdSample",
    "MdScope",
    "MdVerdict",
    "NaiveContrast",
    "PositionClass",
    "PositionSeed",
    "Prober",
    "Severity",
    "Stage",
    "ai_path_position_seeds",
    "check_ai_paths",
    "check_index_links",
    "check_llms_full",
    "check_md_convention",
    "collect_secondary_reasons",
    "detect_md_declaration_from_index",
    "detect_md_implicit_index",
    "detect_md_signal_from_page",
    "enrich_probe",
    "enrich_probes",
    "evidence_of",
    "extract_index_links",
    "finalize",
    "findings_from_index_report",
    "grade",
    "has_ai_channel",
    "in_naive_probe_set",
    "index_shape",
    "judge_md_sample",
    "make_finding_id",
    "naive_contrast",
    "naive_reading",
    "normalize_url",
    "out_of_scope_candidates",
    "parse_index_links",
    "probe_index_links",
    "sample_index_links",
    "sample_md_targets",
]
