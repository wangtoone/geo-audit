"""全部数据结构 —— 唯一定义处。

**任何其他文件不许再定义判定枚举。** ``fetch/models.py`` 现在只是一层
re-export shim，存在的唯一理由是让冻结的测试（``from geo_audit.fetch.models
import ...``）零改动通过（§3.9 适配 #1）。

文件名必须是 ``models.py``，不能是 ``types.py``：包目录一旦进 ``sys.path``
（在目录里跑脚本就会），``types.py`` 会遮蔽 stdlib 的 ``types``，
``enum -> types -> dataclasses`` 的链条直接循环 import 崩掉。

以下是搬入前 fetch 层的原始设计说明，仍然适用：

Core data structures for the fetch & compliance layer.

Design rule that governs every type in this file: a check must always be able
to distinguish "we looked and it is broken" from "we could not look".  The
empirical run (FEATURE-PRIORITY.md §5) shows why: 10 domains were dropped for
anti-bot, and spoton/lawmatics scored zero findings purely because their docs
sites are JS SPAs.  Any type that collapses those into "ok" manufactures a
false zero.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Literal

# 只依赖 fetch.normalize 里的纯函数（该模块只 import stdlib，无循环风险）。
# fetch/__init__.py 必须保持为空，否则这条 import 会把整个 fetch 包拉进来。
from geo_audit.fetch.normalize import md5_hex, norm_sha256, structural_fingerprint

# --------------------------------------------------------------------------- #
# 版本与常量（§2.1）
# --------------------------------------------------------------------------- #

SCHEMA_VERSION = "geo-audit/report/1"
TOOL_VERSION = "0.1.0"
#: 与 fetch/fingerprints.TABLE_VERSION 同源。去噪规则表一改就要动它，
#: 否则跨版本的 fp-gate 报告没法比。
DENOISE_RULESET_VERSION = "denoise/2026-09-07.1"

#: JSON 里随环境变化、不参与确定性比对的字段路径。
#: L 组（§8.8）逐字节比对前先剔掉这些。
VOLATILE_JSON_FIELDS: frozenset[str] = frozenset(
    {
        "scanned_at",
        "duration_s",
        "fetched_at",
        "elapsed_ms",
        "from_cache",
        "resolver_used",  # v2：随 DNS 抖动变化（卡点 A8）
        "resolved_ips",  # v2：同上
        "probed_at",
        "requests_made",
    }
)

# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #


class Verdict(str, Enum):
    """Outcome of classifying a single HTTP response.

    Precedence when several could apply (see classify.classify_response):
        BLOCKED > REAL404 > SOFT404 > UNKNOWN > OK

    The ordering is deliberately biased away from calling anything dead.
    Rationale: FEATURE-PRIORITY.md measured 40.5% false positives on dead-link
    detection before de-noising (42 judged dead, 25 real).  A false "dead"
    discredits the whole report; a false "cannot tell" only costs coverage.
    """

    OK = "ok"
    SOFT404 = "soft404"
    REAL404 = "real404"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class LinkState(str, Enum):
    """**一条可点击链接**（C1）的判定。"""

    ALIVE = "alive"
    DEAD = "dead"
    #: 401/403/405/429/999/451/挑战页/超时/TLS/地理跳转/第三方无对照
    UNKNOWN = "unknown"
    EXCLUDED = "excluded"  # 被去噪规则丢掉，一次请求都不发


class Status(str, Enum):
    """**报告里一个「位置」**（§2.9）的状态。

    四态取自 axe-core 的 violations/passes/incomplete/inapplicable 四分法。
    **UNKNOWN 永不折算成 PASS** —— 实测 spoton / lawmatics 的文档站是纯 JS SPA，
    把「看不了」渲染成「没问题」就是制造假零。
    """

    PASS = "pass"  # noqa: S105  枚举值，不是密码
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


def verdict_to_status(v: Verdict) -> Status:
    """探测判定 → 位置状态。

    ``REAL404 -> NOT_APPLICABLE`` 而不是 ``FAIL``：tdengine.com / juicefs.com /
    lawmatics.com / gethealthie.com 的 llms.txt 是**真 404**（状态码正确）。
    把「你没做这件事」渲染成「你做坏了」是造假。这类域的 headline 走
    ``no_ai_channel`` 分支（§6.1）。
    """
    return {
        Verdict.OK: Status.PASS,
        Verdict.SOFT404: Status.FAIL,
        Verdict.REAL404: Status.NOT_APPLICABLE,
        Verdict.BLOCKED: Status.UNKNOWN,
        Verdict.UNKNOWN: Status.UNKNOWN,
    }[v]


def link_state_to_status(s: LinkState) -> Status:
    """v2 新增。C1 侧也需要一个显式映射，否则 Position 构造器只能靠猜。"""
    return {
        LinkState.ALIVE: Status.PASS,
        LinkState.DEAD: Status.FAIL,
        LinkState.UNKNOWN: Status.UNKNOWN,
        LinkState.EXCLUDED: Status.NOT_APPLICABLE,
    }[s]


#: Machine-stable reason codes.  Every verdict carries exactly one.  These are
#: emitted into the JSON report and asserted on in tests, so they never change
#: meaning once shipped.
Reason = Literal[
    # ok
    "ok",
    "ok_control_discriminates",
    # real404
    "status_404",
    "status_410",
    # soft404
    "html_where_text_expected",
    "notfound_copy_in_body",
    "redirect_to_site_root",
    "redirect_to_generic_landing",
    "identical_to_control",
    "near_identical_to_control",
    "platform_deployment_missing",
    # blocked
    "waf_status",
    "waf_challenge_body",
    "rate_limited",
    "login_required",
    "robots_disallowed",
    # unknown
    "server_error",
    "dns_unresolved",
    "dns_poisoned",
    "network_error",
    "timeout",
    "redirect_loop",
    "too_many_redirects",
    "control_unavailable",
    "needs_js",
    "body_truncated",
    "not_fetched",
]

#: Which reason codes mean "we could not evaluate this position".  Report
#: renderers MUST place these in the dedicated 未能评估 region.
NOT_EVALUATED_REASONS: frozenset[str] = frozenset(
    {
        "waf_status",
        "waf_challenge_body",
        "rate_limited",
        "login_required",
        "robots_disallowed",
        "server_error",
        "dns_unresolved",
        "dns_poisoned",
        "network_error",
        "timeout",
        "redirect_loop",
        "too_many_redirects",
        "control_unavailable",
        "needs_js",
        "body_truncated",
        "not_fetched",
    }
)


class Expect(str, Enum):
    """What kind of body the caller expects, which changes the soft-404 rules.

    TEXT_FILE  -- llms.txt / llms-full.txt / *.md / sitemap.  An HTML response
                  here is soft404 on its own (14 of the 16 confirmed soft404s
                  in FEATURE-PRIORITY.md are caught by this single rule).
    HTML_PAGE  -- an ordinary content page.  HTML is expected, so soft404 can
                  only be established via body copy, redirect target, or the
                  same-host control probe.
    ANY        -- liveness only (external link checking).  Body rules still
                  apply but content-type is not evidence.
    """

    TEXT_FILE = "text_file"
    HTML_PAGE = "html_page"
    ANY = "any"


# --------------------------------------------------------------------------- #
# Raw HTTP
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RedirectHop:
    status: int
    from_url: str
    to_url: str


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """One completed HTTP exchange, after following redirects.

    ``body`` is bytes; ``text`` decodes lazily.  ``byte_len`` is recorded for
    display only and MUST NOT feed any decision: FEATURE-PRIORITY.md §5 found
    3 of 12 re-measured byte counts irreproducible (printful 42108 vs 268184,
    saleor 864 vs 2043, commercelayer 3598 vs 9051), almost certainly a
    redirect-following difference.
    """

    url: str  # URL as requested
    final_url: str  # URL after the redirect chain
    status: int
    headers: dict[str, str]  # lower-cased keys
    body: bytes
    redirects: tuple[RedirectHop, ...] = ()
    elapsed_ms: int = 0
    from_cache: bool = False
    body_truncated: bool = False
    transport_error: str | None = None  # set when status == 0
    fetched_at: float = field(default_factory=time.time)

    # ── v2 新增五个字段（卡点 A9 / S10）─────────────────────────────────────
    # 这几个都在 fetch 层读完 body 的那一刻**一次性算好塞进来**，绝不做成
    # @property。理由：docs.canvasmedical.com/llms-full.txt 是 4.3 MB，
    # check_llms_full 会反复访问 md5，property 版每次重算 4.3 MB 的哈希。
    # 追加在 fetched_at 之后而不是插在中间：既有的位置参数构造一律不受影响。
    raw_md5: str | None = None  # 原始字节 md5（十六进制小写）
    norm_sha256: str | None = None  # normalize_body(text) 的 sha256
    struct_sha256: str | None = None  # HTML 骨架指纹
    resolver_used: str | None = None  # "system" | "8.8.8.8" | "1.1.1.1" | None
    blocked: bool = False  # is_blocked() 的结论，供 .md 子检查等直接用

    @property
    def byte_len(self) -> int:
        """Display only.  Never a decision input."""
        return len(self.body)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def charset(self) -> str:
        ct = self.headers.get("content-type", "")
        if "charset=" in ct:
            return ct.split("charset=", 1)[1].split(";")[0].strip().lower()
        return "utf-8"

    @property
    def text(self) -> str:
        try:
            return self.body.decode(self.charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def is_html(self) -> bool:
        return self.content_type in ("text/html", "application/xhtml+xml")


def finalize_response(resp: HttpResponse, *, want_digests: bool) -> HttpResponse:
    """v2 新增。fetch 层**唯一**允许填 raw_md5 / norm_sha256 / struct_sha256 的地方。

    ``want_digests=False``（只查存活的外链，64 KiB 上限）时三个字段留 ``None``，
    ``check_llms_full`` 遇到 ``None`` 就判 UNKNOWN 而不是当成「哈希不同」——
    截断过的正文算出来的哈希跟完整正文的哈希不同，那是测量假象不是发现。

    已经填好的响应（例如从缓存取出的）原样返回，不重算。
    """
    if not want_digests or resp.body_truncated:
        return resp
    if resp.raw_md5 is not None:
        return resp
    if not resp.body:
        return resp

    text = resp.text
    struct = structural_fingerprint(text)[0] if resp.is_html else None
    return replace(
        resp,
        raw_md5=md5_hex(resp.body),
        norm_sha256=norm_sha256(text),
        struct_sha256=struct,
    )


# --------------------------------------------------------------------------- #
# Classification result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Classification:
    verdict: Verdict
    reason: Reason
    #: Human-readable, report-ready evidence.  Chinese strings are fine here:
    #: they go straight into the HTML report.
    evidence: tuple[str, ...] = ()
    #: True when a naive checker (root path only, status code only, no control
    #: probe) would have reached a *different* conclusion.  This is what powers
    #: the report's headline claim; FEATURE-PRIORITY.md P0 puts it at >=20/72.
    naive_would_say: str | None = None
    needs_js: bool = False
    control_used: bool = False
    control_discriminates: bool | None = None

    # ── v2 新增（卡点 S1 的核心修法）─────────────────────────────────────
    #: 除首要 reason 之外，**还有哪几条规则也会命中**。按 §3.4 的 L 层顺序排列，
    #: 不含 reason 自身。存在的理由：L2(a) html_where_text_expected 会抢在
    #: platform / copy / redirect / L3 之前返回，于是 minimax 那条「我们做了对照
    #: 探测、两边同一个壳」的证据在首要 reason 上看不见 —— 而它正是首页差异化
    #: 演示区的原料。secondary_reasons 让证据不丢，同时不动首要归因。
    secondary_reasons: tuple[Reason, ...] = ()

    @property
    def evaluated(self) -> bool:
        return self.reason not in NOT_EVALUATED_REASONS

    @property
    def all_reasons(self) -> tuple[Reason, ...]:
        return (self.reason, *self.secondary_reasons)


@dataclass(frozen=True, slots=True)
class Probe:
    """A fetched-and-classified position.  This is the unit checks consume."""

    url: str
    expect: Expect
    response: HttpResponse | None
    classification: Classification

    @property
    def verdict(self) -> Verdict:
        return self.classification.verdict

    @property
    def ok(self) -> bool:
        return self.classification.verdict is Verdict.OK


# --------------------------------------------------------------------------- #
# JS assessment
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class JsAssessment:
    """Whether this HTML needs a browser to produce readable prose.

    v1 ships no renderer (see docs/DECISIONS.md#js).  The contract is: detect
    it, declare it, never let it become a zero-finding.
    """

    required: bool
    confidence: Literal["high", "low"]
    signals: tuple[str, ...]
    visible_text_len: int
    raw_len: int


# --------------------------------------------------------------------------- #
# Host profile (the cached control probe)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class HostProfile:
    """What a host does with a path that cannot exist.

    Probed once per host per run and cached, because a domain-wide audit hits
    the same host 6-20 times.  Real hosts observed in FEATURE-PRIORITY.md:

      www.minimax.io        -> 200 text/html 384052 B, identical to homepage
      www.moonshot.ai       -> 200 text/html  82460 B, identical to homepage
      platform.kimi.ai      -> 200 on /docs/<anything>, Quickstart page
      docs.moderntreasury.com -> 302 to "/"
      support.freshbooks.com  -> 307 to /hc/en-us then 200 text/html
      api-docs.ecwid.com    -> 302 to docs.ecwid.com/ then 200 text/html
      (18 well-behaved hosts) -> 404 text/html
    """

    host: str
    probe_url: str
    status: int
    content_type: str
    norm_sha256: str
    norm_len: int
    #: Normalized control body, capped at NORM_BODY_CAP chars.  Stored (not
    #: just digested) because similarity comparison needs the text, and
    #: re-fetching the control for every target would multiply the request
    #: budget by 2x for no information gain.
    norm_body_prefix: str
    #: Markup-skeleton digest + tag count.  For SPA shells the visible text is
    #: nearly empty, so the content digest cannot identify them; the skeleton
    #: can.  See normalize.structural_fingerprint.
    struct_sha256: str
    struct_tags: int
    final_path: str
    #: True when the control returned a non-2xx status.  A host that answers a
    #: missing path with 404/410/5xx discriminates for EVERY kind of target, so
    #: any 2xx response from it is trustworthy without body comparison.  This
    #: is the reverse validation that kept 20/20 real files from being
    #: misjudged (18 hosts: real file 200 text/plain, control 404 text/html).
    status_discriminates: bool
    #: True when the control body is HTML.  This discriminates only when the
    #: target was supposed to be a TEXT file -- a real llms.txt can never be
    #: confused with an HTML shell.  It discriminates NOT AT ALL when the
    #: target is itself an HTML page, which is exactly the catch-all-shell
    #: case (platform.kimi.ai answers /docs/<anything> with the Quickstart
    #: page): there, only body comparison can tell.
    control_is_html: bool
    #: True when the probe itself was blocked/errored, i.e. the profile is
    #: unusable and comparisons must degrade to UNKNOWN, not to OK.
    usable: bool
    probed_at: float


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


class HostRole(str, Enum):
    APEX = "apex"
    WWW = "www"
    DOCS = "docs"
    SUPPORT = "support"
    PLATFORM = "platform"
    DECLARED = "declared"  # mined out of robots.txt / llms.txt / page banner


@dataclass(frozen=True, slots=True)
class DiscoveredHost:
    host: str
    role: HostRole
    reachable: bool
    verdict: Verdict
    reason: Reason
    resolved_ips: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApexWwwResult:
    """Bidirectional apex/www probe.

    Anchor case: brevo.com apex returns Vercel's plaintext
    ``DEPLOYMENT_NOT_FOUND`` on /, /pricing/ and /blog/, while www.brevo.com
    and developers.brevo.com are fine.  No link-crawling design can find this,
    which is why the probe is unconditional rather than crawl-driven.

    ``evidence_strength`` is "single_case" until release gate #3 (144 probes
    across the 72 domains) is run; report renderers must keep single_case
    findings out of the headline count.
    """

    apex_host: str
    www_host: str
    apex: Probe
    www: Probe
    #: "both_ok" | "apex_dead" | "www_dead" | "both_dead" | "undetermined"
    outcome: str
    evidence_strength: Literal["single_case", "measured"] = "single_case"


@dataclass(frozen=True, slots=True)
class SiteMap:
    """Everything discovery produces for one input domain."""

    input_domain: str
    registrable_domain: str
    hosts: tuple[DiscoveredHost, ...]
    apex_www: ApexWwwResult | None
    #: host -> ordered sitemap URLs (already de-duplicated, capped)
    sitemap_urls: dict[str, tuple[str, ...]]
    #: first pricing page that classified OK, or None when every candidate
    #: failed.  None means "no comparable surface", NOT "zero problems" --
    #: www.voyageai.com/pricing is a real 404.
    pricing_url: str | None
    pricing_candidates_tried: tuple[tuple[str, Verdict], ...]
    #: (host, path) pairs where an AI path file was found or attempted
    ai_path_probes: tuple[Probe, ...]
    robots: dict[str, RobotsInfo]


@dataclass(frozen=True, slots=True)
class RobotsInfo:
    host: str
    fetched: bool
    status: int
    crawl_delay: float | None
    sitemaps: tuple[str, ...]
    raw: str


# --------------------------------------------------------------------------- #
# Findings (what checks emit; consumed by the report layer)
# --------------------------------------------------------------------------- #


class FindingStatus(str, Enum):
    PROBLEM = "problem"
    CLEAN = "clean"
    NOT_EVALUATED = "not_evaluated"


# 卡点 3 的裁决：原来这里有个 ``FindingDict(TypedDict)`` 自称「CLI --json 输出的
# 稳定公开契约」。它已删除 —— 对外契约只有一个，就是 schema/report-1.schema.json，
# 而那份 schema 由 scripts/gen_schema.py 从 dataclass 生成、CI 跑 --check 防漂移
# （§8.5）。两份契约必然对不上，留着只会有一天骗人。


# --------------------------------------------------------------------------- #
# 链接上下文（§3.9 适配 #2：从 fetch/denoise.py 搬来，denoise 改为从这里 import）
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LinkContext:
    """What the extractor knows about where a link came from.

    ``surrounding_html`` is a window (recommended: 400 chars either side of the
    anchor) used by the API-base-URL rule and the inline-display-none rule.
    Both need context that a bare URL does not carry.
    """

    source_page: str
    anchor_text: str = ""
    anchor_html: str = ""
    surrounding_html: str = ""
    #: True when the link came from an llms.txt / llms-full.txt listing rather
    #: than from an HTML page.  Those have no HTML context, so context-
    #: dependent rules must not fire on them.
    from_text_file: bool = False
