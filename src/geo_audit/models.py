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

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field, replace
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
    "unexpected_status",
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
        "unexpected_status",
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

    # ── §3.7 的 tier / 预算字段（§3.9 适配 #3）───────────────────────────────
    # 第 7 步的写手被禁止改本文件，先用 discovery.TieredSiteMap 子类承载过。
    # 现搬到正位：§8.5 的 gen_schema.py 从这些 dataclass 生成 JSON schema，
    # 长在子类上的字段在 schema 里会**整个缺掉**，报告的对外契约就少了四项。
    # 四个都有默认值，既有的 SiteMap(...) 构造调用一行不用改。
    tiers_run: tuple[str, ...] = ()
    requests_spent: int = 0
    budget_exhausted: bool = False
    skipped_by_budget: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RobotsInfo:
    host: str
    fetched: bool
    status: int
    crawl_delay: float | None
    sitemaps: tuple[str, ...]
    raw: str
    #: 这份 robots.txt 最后被**怎么执行**的。RFC 9309 §2.3.1 把三种结果分开，
    #: 而 `fetched` / `status` 读不出这个区别 —— 4xx 与 5xx 都是 `fetched=False`，
    #: 但一个该放行全部、另一个该全部不许抓。
    #:
    #:   parsed        2xx，按内容执行
    #:   allow_all     4xx，视为「没有 robots.txt」
    #:   disallow_all  5xx 或网络错误（unreachable），按完全不许抓处理
    policy: Literal["parsed", "allow_all", "disallow_all"] = "parsed"


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


@dataclass(frozen=True, slots=True)
class RootCause:
    """报告第一页的单位。一条 RootCause = 甲方改一处。"""

    root_cause_id: str
    summary: str  # 「首页连接器图标墙 8 个语言全部指向已迁移的文档路径」
    fix_once: str  # 「改 1 处 → 修 8 条：…」
    finding_ids: tuple[str, ...]
    max_severity: Severity
    instance_count: int  # = sum(f.occurrences)
    unique_target_count: int  # = len(finding_ids)
    defect: str = ""  # v2：缺陷指纹 id（§5.4 表），非空
    source_pages: tuple[str, ...] = ()
    merge_axes: dict[str, str] = field(default_factory=dict)  # 靠哪条边合并的，可审计


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


# --------------------------------------------------------------------------- #
# 报告层（§2.5–§2.9）
#
# 这一段原先是 checks/ai_path.py 里的**本地占位** —— 写它的 agent 被禁止改
# models.py，所以先放在了 checks 层，并在占位横幅里写明了搬入步骤。
# 现按验收标准 A6（`grep -rn "class Severity\|class PositionClass" src/` 必须
# 恰好 1 处命中）搬到唯一定义处。ai_path.py 那一段已删除、改为 import。
#
# `Finding.naive` 与 `NaiveContrast` 是 checks 层新增的（§2.6 只有三个扁平的
# naive_* 字段）。保留：产品的核心卖点「朴素实现会怎么读错」需要结构化承载，
# 而三个扁平字段装不下 direction 的第四个取值 over_report。三个扁平字段照样在，
# schema 不受影响。
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class NaiveContrast:
    """「一个只探根路径的工具会得出什么结论」——**一条 finding 一行**。

    这不是文案，是同一批已抓响应上的两个读数：``naive_conclusion`` 只用
    「跟完跳转的最终状态码」推，``actual_conclusion`` 是我们的判定。
    ``extra_requests`` 记我们为了看出差别多打了几个请求（§4.5 表的最后一列）。

    ``direction`` 比 §2.6 NaiveRow 多一个取值 ``over_report``：§4.5 的表里
    「过报（我们按设计不报）」那一行（resend.com/index.md）既不是假阳也不是
    假阴，是朴素实现多报了一条而我们按范围压住 —— NaiveRow 的三值枚举装不下
    （见 spec_gaps）。
    """

    probe_url: str
    in_naive_probe_set: bool
    naive_method: str
    naive_conclusion: str
    actual_conclusion: str
    diverges: bool
    direction: Literal["false_positive", "false_negative", "over_report", "agree"]
    extra_requests: int = 0
    why: str = ""


class Stage(str, Enum):
    """AI 检索链路的六段（§2.5:858）。第一页的链路图就是这六格。"""

    DISCOVERY = "discovery"  # ① 入口发现
    INDEX_FILE = "index_file"  # ② llms.txt 是真文件还是软 404
    FULLTEXT = "fulltext"  # ③ llms-full.txt 是真全文还是副本
    INDEX_LINKS = "index_links"  # ④ 索引里列的链接活着几条
    MD_CHANNEL = "md_channel"  # ⑤ 「任意页面加 .md」兑现了吗
    HUMAN_PATH = "human_path"  # ⑥ 人和爬虫共用的可点击路径


class Severity(str, Enum):
    """§2.5:878。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PositionClass(str, Enum):
    """§2.5:886。AI 路径体检产出的 finding **一律** AI_CHANNEL。"""

    SALES_PATH = "sales_path"
    DOC_ENTRY = "doc_entry"
    AI_CHANNEL = "ai_channel"
    NAV = "nav"
    BODY = "body"
    FOOTER_SOCIAL = "footer_social"


#: §2.5:940 冻结集合，多一个就让 v1 范围守门测试变红。
FindingKind = Literal[
    "soft_404",
    "llms_full_fake",
    "index_link_dead",
    "md_unfulfilled",
    "dead_link",
]
FINDING_KINDS: frozenset[str] = frozenset(
    ("soft_404", "llms_full_fake", "index_link_dead", "md_unfulfilled", "dead_link")
)

#: 真正**依赖同域对照探测**的判据。只有这些在拿不到对照时该说「判定作废」。
#:
#: 死链两类（`index_link_dead` / `dead_link`）靠状态码判，不需要对照。
#: 而报告模板原来在 `f.control` 为空时**无条件**印「判定作废，已按无法评估
#: 处理」—— 于是 mistral 那份 75 条死链，每一条都同时写着
#:     标题「llms.txt 里列的 …/sfcortex.md 是死链」
#:     证据「同域对照本身不可用，所以这一条的判定作废」
#: 两句话不能同时成立。
CONTROL_DEPENDENT_KINDS: frozenset[str] = frozenset(("soft_404", "llms_full_fake"))


@dataclass(frozen=True, slots=True)
class Evidence:
    """一次 HTTP 观测（§2.6:960）。``curl_repro`` 非空是硬要求（A35）。"""

    url: str
    http_status: int | None = None
    content_type: str | None = None
    bytes_len: int | None = None  # 只作展示，永不参与判定
    norm_sha256: str | None = None
    raw_md5: str | None = None
    body_head: str | None = None
    title: str | None = None
    final_url: str | None = None
    redirect_chain: tuple[str, ...] = ()
    resolver_used: str | None = None
    fetched_at: str = ""
    error: str | None = None
    curl_repro: str = ""


@dataclass(frozen=True, slots=True)
class FixHint:
    """§2.6:979。``after`` 必须是我们实际请求过并返回 200 的地址，否则
    ``verified_target=False`` 且报告写「我们没找到明显的正确目标」——绝不编一个。"""

    action: str
    open_this: str
    locator: str
    before: str | None
    after: str | None
    verified_target: bool


@dataclass(frozen=True, slots=True)
class Finding:
    """§2.7:1060。字段名与顺序照抄规格；本文件只多一个 ``naive`` 字段。"""

    finding_id: str
    kind: FindingKind
    check_id: str
    title: str
    severity: Severity
    position_class: PositionClass
    stage: Stage

    target: Evidence
    control: Evidence | None = None
    found_on: str | None = None
    anchor_text: str | None = None
    html_snippet: str | None = None
    source_hint: str | None = None

    occurrences: int = 1
    occurrence_pages: tuple[str, ...] = ()
    occurrence_hrefs: tuple[str, ...] = ()

    root_cause_id: str = ""
    root_cause_summary: str = ""
    sibling_count: int = 1

    fix: FixHint | None = None

    naive_conclusion: str = ""
    naive_is_wrong: bool = False
    actual_conclusion: str = ""

    confidence: Literal["confirmed", "needs_review"] = "confirmed"
    why_it_matters: str = ""
    fp_guard: tuple[str, ...] = ()
    fp_note: str | None = None
    suppress_hint: str = ""
    display_value: str = ""

    detail: dict[str, str | int | float | bool] = field(default_factory=dict)
    counted_as_hit: bool = True
    severity_signals: dict[str, str] = field(default_factory=dict)
    exposure_pages: tuple[str, ...] = ()

    # ── 本文件新增（规格 §2.7 里没有这个字段）────────────────────────────
    #: 「朴素实现会怎么读错」的整行结构化对照。§2.7 只给了三个扁平字段
    #: （naive_conclusion / naive_is_wrong / actual_conclusion），装不下
    #: 「我们比它多打了几个请求」「差异方向」「它用的方法」，而 §4.5 的对照表
    #: 与 A34 恰恰要这三样。三个扁平字段照样填，所以 schema 不受影响。
    naive: NaiveContrast | None = None


def make_finding_id(check_id: str, target_url: str, found_on: str | None) -> str:
    """§2.10:1333 逐字照抄。``target_url`` 传的是 **norm_url**。"""
    raw = f"{check_id}|{target_url}|{found_on or ''}"
    return "GA-" + hashlib.sha256(raw.encode()).hexdigest()[:10].upper()


#: §2.8:1146。每条 UNKNOWN 都必须有补救办法，且要具体到可执行（A32）。
#: 这里只抄本文件真正会用到的那些 reason —— 完整表（含 interrupted 等）由
#: models.py 承接，A32 断言 ``set(UNKNOWN_REMEDY) >= NOT_EVALUATED_REASONS``。
UNKNOWN_REMEDY: dict[str, str] = {
    "waf_challenge_body": (
        "你的 WAF 对 UA 含 geo-audit 的请求返回了挑战页。把这个 UA 加白名单后重跑即可。"
        "实测参照：gusto.com 的 llms.txt 是真文件（浏览器过挑战后 200 text/plain 8,217 B），"
        "但对纯 HTTP 客户端一律 403 —— 任何不带浏览器的工具都会把你这里报成「没有」。"
    ),
    "waf_status": (
        "该位置返回了拦截型状态码，不是内容。被拦截 ≠ 不存在，本位置既不计死链也不计存活。"
    ),
    "rate_limited": (
        "被限流（429）。用 --rate 0.2 调慢重跑。实测参照：www.pipedrive.com 的 llms.txt "
        "是 8,501 B 的真文件，但对 curl 返回 429；同域 8 条内链也全被 429 挡住无法判定。"
    ),
    "login_required": "需要登录才能看。本工具只抓无登录公开页，这个位置我们不碰。",
    "needs_js": (
        "服务端 HTML 里正文不足 200 字符，正文由 JS 渲染。纯 HTTP 客户端在这类页面上会系统性低估。"
        "实测参照：help.spoton.com 正文只有一行「SpotOn Knowledge Base」、"
        "docs.lawmatics.com（Redoc）只有一行「Lawmatics OAuth API v1.22.0」——"
        "它们的「零发现」是抓取能力问题，不是站点干净。"
    ),
    "server_error": (
        "服务端错误（5xx），无法判定内容是否存在。"
        "实测参照：developers.pinterest.com/llms.txt 返回 500。"
    ),
    "unexpected_status": (
        "该位置返回了本工具没有判据的状态码（既不是 2xx，也不落在我们逐条实测过的"
        "404/410/403/429/5xx 名单里）。这种情况我们不猜：不认定通过，也不认定失败。"
        "如果你知道这个码在你这儿的含义（比如自建网关的自定义码），"
        "把它的语义告诉我们，我们补一条判据；在那之前它留在「未能评估」里。"
    ),
    "dns_unresolved": (
        "两个独立 resolver 都解析不出。实测参照：cog.run 在本机 SERVFAIL 但 dig @8.8.8.8 有 A 记录 "
        "104.18.17.10，所以单一 resolver 的失败我们一律不采信。"
    ),
    "dns_poisoned": (
        "DNS 返回了本地/私有地址，判定为解析污染而非死链。"
        "实测参照：www.talkie-ai.com 本机解析到 127.0.0.1。"
    ),
    "timeout": (
        "超时。已重试 2 次。实测参照：app.close.com/download 第一次 curl exit 28、重测 200。"
    ),
    "network_error": "网络错误。",
    "redirect_loop": (
        "重定向成环（多为登录跳转环）。实测参照：app.moderntreasury.com 的 Auth0 跳转环。"
    ),
    "too_many_redirects": "重定向层数超过 10 跳。",
    "robots_disallowed": (
        "你的 robots.txt 禁止抓这个路径，我们遵守了。要检查请加 --ignore-robots。"
        "「我们没被允许看」是真话，「这里没问题」是假话。"
    ),
    "control_unavailable": (
        "同域对照探测自身不可用（被拦或出错），无法判定本响应是真文件还是兜底页。"
        "判定作废，绝不退化成「没问题」。"
    ),
    "body_truncated": "响应体超过 8 MiB 读取上限被截断，不做指纹判定。",
    "not_fetched": (
        "超出本次预算上限（--max-requests / --max-links），本位置未验证。"
        "用 --max-requests 0 取消上限重跑可以覆盖它。"
    ),
    # §7.5 的 Ctrl-C 路径。不是 Reason 的取值（Classification 里塞的是它，
    # 但 NOT_EVALUATED_REASONS 不含它），所以 A32 的断言写成
    # `set(UNKNOWN_REMEDY) >= NOT_EVALUATED_REASONS | {"interrupted"}`。
    "interrupted": "扫描被 Ctrl-C 中断，本位置还没轮到。已完成的位置结论有效，这一格没有结论。",
}


@dataclass(frozen=True, slots=True)
class PositionSeed:
    """**Position 的原料，不是 Position**（验收 A7 只许 ``pipeline.build_positions()``
    里出现 ``Position(``，而第 6 步 4429 又把「P2 构造」列成本步产出 —— 两条要求
    冲突，见交付说明 spec_gaps）。裁决：本层只产出与 §2.9 构造表逐字段对齐的
    seed，由第 16 步的 pipeline 一对一变成 ``Position``。"""

    stage: Stage
    key: str  # §2.9 构造表的 key 列；position_id = f"{stage.value}:{key}"
    kind: Literal["probe", "aggregate"]
    probe_url: str
    status: Status
    detail: str
    unknown_reason: str | None = None
    unknown_remedy: str | None = None
    aggregate_of: int = 1


# --------------------------------------------------------------------------- #
# 报告状态账本（§2.5 标签表 / §2.9 Position / §2.10 Report）
#
# 这一段原先在 **三个** 文件里各有一份完全相同的占位：pipeline.py、
# report/render.py、report/json_out.py —— 三个写手都需要它们，而三个都被禁止
# 改本文件（并行时的正确做法：谁都不许单方面动共享定义）。三份用 AST 逐字段
# 比对过，**零分叉**，唯一差异是 `Report.verdict_kind` 的注解写法
# （pipeline 用 `VerdictKind` 别名，另两份内联 Literal）。
#
# 现按验收标准 A6 合并到唯一定义处，取 pipeline.py 那份（它带 VerdictKind
# 别名与四张标签表，最全）。三处占位改为从这里 import。
#
# `Position` 只许由 `pipeline.build_positions()` 构造（验收 A7），本文件只给
# 定义不给构造器。
# --------------------------------------------------------------------------- #

#: §2.5:868。链路图六格的标签，报告与 §7.2 进度输出共用。
STAGE_LABEL: dict[Stage, str] = {
    Stage.DISCOVERY: "① 入口发现",
    Stage.INDEX_FILE: "② 索引文件真伪",
    Stage.FULLTEXT: "③ 全文通道",
    Stage.INDEX_LINKS: "④ 索引内链存活",
    Stage.MD_CHANNEL: "⑤ .md 通道",
    Stage.HUMAN_PATH: "⑥ 可点击路径",
}

#: §2.5:911。
POSITION_LABEL: dict[PositionClass, str] = {
    PositionClass.SALES_PATH: "销售路径",
    PositionClass.DOC_ENTRY: "文档/教程唯一出口",
    PositionClass.AI_CHANNEL: "AI 通道内部",
    PositionClass.NAV: "站内导航",
    PositionClass.BODY: "正文正在指引读者去点",
    PositionClass.FOOTER_SOCIAL: "页脚社交图标",
}

#: §2.5:898。**严重度由位置决定，不由条数决定。**
SEVERITY_BY_POSITION: dict[PositionClass, Severity] = {
    PositionClass.SALES_PATH: Severity.CRITICAL,
    PositionClass.DOC_ENTRY: Severity.HIGH,
    PositionClass.AI_CHANNEL: Severity.HIGH,
    PositionClass.NAV: Severity.MEDIUM,
    PositionClass.BODY: Severity.MEDIUM,
    PositionClass.FOOTER_SOCIAL: Severity.LOW,
}

#: §2.5:920。
SEVERITY_RANK: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

VerdictKind = Literal["has_fail", "zero_with_unknown", "zero_clean", "no_ai_channel", "unusable"]


@dataclass(frozen=True, slots=True)
class Position:
    """**报告状态账本里的一格**（§2.9:1196 逐字照抄字段表）。

    它回答「AI 走到这里，通不通？」，恰好有一个 ``Status``。
    **它不是一次 HTTP 请求，也不是一条 finding。**
    """

    position_id: str  # 稳定 id：f"{stage.value}:{key}"
    stage: Stage
    label: str  # 中文，直接显示
    probe_url: str  # 代表性 URL（聚合型取被聚合对象的入口 URL）
    status: Status
    detail: str
    kind: Literal["probe", "aggregate"]
    aggregate_of: int = 1
    unknown_reason: str | None = None  # Reason 的取值 | "interrupted"
    unknown_remedy: str | None = None  # 每个 UNKNOWN 都必须有
    evidence: Evidence | None = None
    control: Evidence | None = None
    #: §2.9 写的是 ``NaiveRow``；models.py 里这个类叫 ``NaiveContrast``
    #: （字段是它的超集，见 models.py 的说明）。
    naive: NaiveContrast | None = None
    finding_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Exclusion:
    """被去噪排除的一条链接（§2.6:1008 / ``Report.excluded`` 的元素类型）。

    ``fetch/denoise.EligibilityExclusion`` 只有规则与理由、没有 URL，
    报告的「被排除清单」区要按 URL 逐条列出来，所以这里是它的富版本。
    字段与 ``report/render.py`` / ``report/json_out.py`` 里那两份占位**逐字一致**，
    owner 合并时三份对得上。
    """

    url: str
    rule_id: str
    rule_desc: str
    found_on: str | None = None
    provenance: Literal["measured", "single_case"] = "measured"
    disposition: Literal["excluded", "needs_review"] = "excluded"


@dataclass(frozen=True, slots=True)
class CoverageGap:
    """§2.10:1246 逐字。"""

    where: str
    reason: str  # Reason 取值
    detail: str
    remedy: str


@dataclass(frozen=True, slots=True)
class Fragility:
    """结构性脆弱点。零发现报告的主体。每条必须挂一个实测先例，否则就是编的。"""

    fragility_id: str  # F1..F8
    title: str
    metric: str
    why: str
    precedent: str  # 实测先例，必填，非空有测试
    watch_command: str  # 能直接放进 CI 的一条命令
    severity: Severity = Severity.INFO


@dataclass(frozen=True, slots=True)
class Coverage:
    """§2.10:1264 逐字。"""

    checked: tuple[str, ...]
    not_checked: tuple[str, ...]
    positions_total: int
    links_extracted: int = 0
    links_excluded: int = 0
    links_needs_review: int = 0
    links_verified: int = 0
    links_unknown: int = 0
    pages_fetched: int = 0
    index_links_sampled: bool = False
    sampling_note: str = ""
    robots_respected: bool = True
    #: 逻辑 URL 计数（同一 URL 只算一次、对照探针按 host 算一次）。
    requests_made: int = 0
    #: **真实发出去的 HTTP 请求条数**：跳转每一跳、robots.txt、重试都算。
    #: 与 `requests_made` 分开印 —— 实测两者能差 10 倍，只印前者会让读者
    #: 以为我们比实际更克制。
    http_requests: int = 0
    budget_cap: int = 0
    interrupted: bool = False  # v2：Ctrl-C（§7.5）


@dataclass(frozen=True, slots=True)
class Counts:
    """§2.10:1283 逐字。首页四格用 positions_*，条数用 findings。"""

    positions: int
    positions_pass: int
    positions_fail: int
    positions_unknown: int
    positions_na: int
    findings: int
    findings_counted: int
    occurrences: int
    root_causes: int
    by_severity: dict[str, int]
    naive_divergences: int
    naive_dead_count: int = 0
    audited_dead_instances: int = 0
    llm_calls: int = 0  # 恒为 0，有断言（A18）


@dataclass(frozen=True, slots=True)
class Report:
    """§2.10:1303 逐字。``naive_table`` 的元素类型在 models.py 里叫 NaiveContrast。"""

    schema_version: str
    tool_version: str
    denoise_ruleset_version: str
    domain: str
    scanned_at: str
    duration_s: float
    contact: str
    user_agent: str
    headline: str
    verdict_kind: VerdictKind
    positions: tuple[Position, ...]
    findings: tuple[Finding, ...]
    root_causes: tuple[RootCause, ...]
    naive_table: tuple[NaiveContrast, ...]
    fragilities: tuple[Fragility, ...]
    coverage_gaps: tuple[CoverageGap, ...]
    excluded: tuple[Exclusion, ...]
    apex_www: ApexWwwResult | None
    coverage: Coverage
    counts: Counts

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2, sort_keys=True, default=str)
