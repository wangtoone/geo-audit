"""Link de-noising: decide whether a URL is even eligible to be called dead.

This module is the reason the dead-link check is worth shipping.  Measured:
40.5% false positives without it (42 links judged dead, 25 actually dead),
0% with it (n=51).  The report's own words: 去噪规则是死链检查的全部价值.

It runs BEFORE any request, so an excluded link costs zero rate-limit budget.
Every exclusion is logged with the rule id that fired -- FEATURE-PRIORITY.md §5
documents what happens without that log: five batches excluded
/cdn-cgi/l/email-protection and three did not, silently making the batches
non-comparable.

Three rules from the earlier draft could not be turned into code as written.
They are rewritten here, and the rewrite is stated in the returned reason so a
reviewer can see which rule is on thin ice:

  * "API base URL (a bare GET necessarily 404s)" gave no way to recognise one.
    Rewritten as: path shape AND a code-context signal in the surrounding HTML.
  * "an <a> whose class contains hidden or display:none" is undecidable from
    static HTML -- Tailwind's `md:hidden` means visible on desktop, and an
    external stylesheet cannot be resolved.  Narrowed to inline
    `style="display:none"` only, and the rule is flagged single-provenance
    (printify's IRS Form 8937 link is the only observed case).
  * "before judging an external link dead, hit a known-live control sample on
    the same host" had no source for "known-live".  Rewritten as an
    automatically constructed pair (host root + a random path); only when BOTH
    are abnormal is the host declared unprobeable.  No manual allowlist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..models import LinkContext, PositionClass
from . import fingerprints as fp


@dataclass(frozen=True, slots=True)
class EligibilityExclusion:
    rule_id: str
    reason: str
    #: "measured" -- multiple observed cases; "single_case" -- one observation,
    #: so the report shows it as 待人工确认 rather than silently dropping it.
    provenance: str = "measured"
    #: §5.3 第 12 步新增（卡点 S4）。"excluded" = 出死链分子；"needs_review" =
    #: **仍然计入分子**，只置 finding.confidence 并进「待人工确认」区。
    #: 追加在末尾且带默认值，所以原型那 11 条规则的构造点一个字都不用改。
    disposition: str = "excluded"


def classify_link_eligibility(
    url: str, ctx: LinkContext | None = None
) -> EligibilityExclusion | None:
    """Return an ``EligibilityExclusion`` when this URL must not be judged dead, else None.

    Ordered so the cheapest and least ambiguous rules run first.
    """
    ctx = ctx or LinkContext(source_page="")

    for rule_id, pattern, reason in fp.EXCLUDE_URL_RULES:
        if pattern.search(url):
            provenance = "single_case" if rule_id == "intellimize_endpoint" else "measured"
            return EligibilityExclusion(rule_id, reason, provenance)

    # API endpoint: path shape AND a code-context signal.  Both halves are
    # required -- /api/ alone would exclude legitimate documentation pages
    # under /api/reference/.
    # Observed false positives this prevents:
    #   enterprise.printful.com/api/pfy/public/v1/  (and /v2/)
    #   api.sendinblue.com/v3/emailCampaigns/{templateID}/sharedUrl -> 401
    if (
        fp.API_PATH_RE.search(urlsplit(url).path)
        and not ctx.from_text_file
        and fp.CODE_CONTEXT_RE.search(ctx.surrounding_html or ctx.anchor_html)
    ):
        return EligibilityExclusion(
            "api_endpoint_in_code_context",
            "路径形如 API 端点且出现在代码块 / curl 示例语境中，裸 GET 返回 4xx 属正常",
        )

    # Invisible anchor, narrowed to inline style only.
    if ctx.anchor_html and fp.INLINE_DISPLAY_NONE_RE.search(ctx.anchor_html):
        return EligibilityExclusion(
            "inline_display_none_anchor",
            '<a> 带内联 style="display:none"，普通访客点不到。'
            "注意：该规则只来自 printify 一例，报告里标为「待人工确认」而不是静默丢弃",
            provenance="single_case",
        )

    return None


_HOSTILE_SUFFIX_RE = re.compile("|".join(re.escape(s) + "$" for s in fp.KNOWN_BOT_HOSTILE_SUFFIXES))


def is_known_bot_hostile(url: str) -> bool:
    """Vendor hosts that answer bots with 403/429 on live pages.

    Used only to skip requests we already know are uninformative, saving
    rate-limit budget.  The general status rule in classify.is_blocked is what
    actually decides the verdict, so this list rotting costs speed, never
    correctness.
    """
    host = (urlsplit(url).hostname or "").lower()
    return bool(_HOSTILE_SUFFIX_RE.search(host)) or any(
        host == s or host.endswith("." + s) for s in fp.KNOWN_BOT_HOSTILE_SUFFIXES
    )


# --------------------------------------------------------------------------- #
# Severity: the report is sold on position, not on count
# --------------------------------------------------------------------------- #
# 94 dead links, 66 of them on 7 domains, and at least 38 traceable to 6
# template bugs.  So the report aggregates by root cause and weights by
# position.  saleor's "Talk to us" and tinybird's footer x.com icon are both
# "1 dead link" and differ in business impact by three orders of magnitude.

SEVERITY_SALES_PATH = "sales_path"
SEVERITY_TUTORIAL_EXIT = "tutorial_exit"
SEVERITY_FOOTER_SOCIAL = "footer_social"
SEVERITY_OTHER = "other"

_SALES_ANCHOR_RE = re.compile(
    r"talk to (?:us|sales)|contact sales|get a demo|book a demo|request a demo"
    r"|start(?: for)? free|get started|buy now|see pricing|see how|upgrade now"
    r"|read the docs",
    re.I,
)
_TUTORIAL_ANCHOR_RE = re.compile(
    r"example repo(?:sitory)?|sample (?:app|code|project)|starter (?:kit|template)"
    r"|quickstart|full example|source code",
    re.I,
)
_SOCIAL_HOST_RE = re.compile(
    r"(?:^|\.)(?:x\.com|twitter\.com|facebook\.com|instagram\.com|linkedin\.com"
    r"|youtube\.com|tiktok\.com|reddit\.com|discord\.(?:gg|com)|mastodon\.\w+)$",
    re.I,
)


def severity_of(url: str, ctx: LinkContext, *, pricing_url: str | None = None) -> str:
    """Three tiers plus a fallback.

    Tier 1 (sales_path) is anything on the pricing page, or any CTA-shaped
    anchor text anywhere.  Anchor: saleor.io's three "Talk to us" buttons on
    /pricing and the homepage's "See how Saleor fits" all resolve to 404,
    while /contact returns 200 -- the most expensive button on the site does
    nothing.  Also unkey's "Read the docs" on the pricing page (308->308->404).

    Tier 3 (footer_social) is the floor.  Anchor: tinybird's footer x.com link.
    """
    if pricing_url and ctx.source_page.rstrip("/") == pricing_url.rstrip("/"):
        return SEVERITY_SALES_PATH
    if _SALES_ANCHOR_RE.search(ctx.anchor_text):
        return SEVERITY_SALES_PATH
    if _TUTORIAL_ANCHOR_RE.search(ctx.anchor_text):
        return SEVERITY_TUTORIAL_EXIT
    if _SOCIAL_HOST_RE.search((urlsplit(url).hostname or "").lower()):
        return SEVERITY_FOOTER_SOCIAL
    return SEVERITY_OTHER


def root_cause_id(url: str, ctx: LinkContext) -> str:
    """Group dead links so one fix counts as one finding.

    Grouping key = (source page, URL path shape with the last segment
    generalised).  Verified against the recorded template bugs:
      tdengine   8 links, all /reference/connector/<lang>/ from the homepage
                 -> 1 group  (docs moved to /developer-guide/connectors-reference/*)
      bytebase   6 links, all on /changelog/ written as www-relative paths
                 -> 1 group
      copper     4 footer social links, all double-prefixed by the Intercom
                 template -> 1 group
      brevo      6 links, all a broken markdown-link render on /changelog
                 -> 1 group
      saleor    10 link instances, 2 unique paths -> 2 groups
    """
    parts = urlsplit(url)
    segments = [s for s in parts.path.split("/") if s]
    shape = "/".join(segments[:-1]) if len(segments) > 1 else "/".join(segments)
    return f"{ctx.source_page}|{parts.hostname}|/{shape}/*"


# --------------------------------------------------------------------------- #
# §5.3 第 12 步新增：三条 pre 规则 + framework_bind_artifact 的正则补丁
#
# 原型的 11 条 pre 规则在上面的 classify_link_eligibility 里，**一个字都没动**
# （tests/test_infra.py 直接 import 它与 severity_of / root_cause_id / 四个
# SEVERITY_* 常量并逐条断言，动一下 146 就破）。新规则一律走下面这个新入口
# classify_link_pre()，它先跑三条本节新写的规则、再委托给原型那 11 条。
#
# 三条新规则的状态列（§5.3，卡点 B22）：
#   presigned_expiring    新写   EXCLUDED + 报告提示区单列一句
#   class_hidden_anchor   新写   **needs_review，不 EXCLUDED**（卡点 S4）
#   seed_url_not_on_site  新写   EXCLUDED
# 另外 framework_bind_artifact 是「原型要补正则」：原型
# fingerprints.EXCLUDE_URL_RULES 里那条不含 `^\$\{`（§3.10）。fingerprints.py
# 不在本步的可写文件里，所以补丁落在本模块的 _DOLLAR_BRACE_RE 上，规则 id
# **仍然是 framework_bind_artifact**（同一条规则的两半，报告里看不出差别）。
# --------------------------------------------------------------------------- #

#: presigned_expiring：URL 自带过期时间，7 天后自己烂掉，不是甲方的死链。
#: 出处：close 的 help.close.com/llms.txt 正文里 logo 用 AWS 预签名
#: （X-Amz-Date=20260906T165455Z、X-Amz-Expires=604800）。
_PRESIGNED_MARKERS: tuple[str, ...] = ("X-Amz-Expires=", "X-Goog-Expires=")
#: Azure SAS 没有单一特征参数，靠 se=（expiry）+ sig=（签名）同时出现认。
_AZURE_SAS_MARKERS: tuple[str, ...] = ("se=", "sig=")

#: class_hidden_anchor：裸 ``hidden`` 且没有任何响应式可见覆盖 token。
#: 收窄的理由（§5.3）：``md:hidden`` 在桌面**是可见的**，外部样式表里的
#: display:none 静态 HTML 判不了。只有 n=1 证据，所以打标记不丢弃。
_RESPONSIVE_VISIBLE_RE = re.compile(
    r"^(?:sm|md|lg|xl|2xl):(?:block|flex|grid|inline|inline-block|table|contents)$"
)

#: framework_bind_artifact 的补丁半边：SSR 把 `${...}` 模板字符串原样落进 href。
_DOLLAR_BRACE_RE = re.compile(r"^\$\{")

#: region 退化推断用的两条正则。**权威实现是 extract.region_of**（走真 DOM
#: 祖先链，§5.2）；这里必须与 extract._PROMINENT_CLS / _FOOTER_CLS 逐字相同，
#: tests/test_denoise.py::test_region_regexes_match_extract 盯着这一点防漂移。
#: 不 import 那两个私名：extract 是上层模块且要拉 selectolax，fetch 层不该依赖它。
_REGION_PROMINENT_RE = re.compile(
    r"pricing|plan|tier|package|card|cta|hero|banner|nav|navbar|header|topbar|pill|button|btn"
)
_REGION_FOOTER_RE = re.compile(r"footer|social|legal|copyright|colophon|bottom")

_CLASS_ATTR_RE = re.compile(r"""\bclass\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)
_LABEL_ATTR_RE = re.compile(r"""\b(?:aria-label|alt|title)\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)


def class_tokens_of(ctx: LinkContext) -> tuple[str, ...]:
    """``<a>`` 的 class token 列表，从 ``anchor_html`` 里解析。

    为什么不是 ``ctx.class_tokens``：§2.7 规定 LinkContext 有 13 个字段（含
    ``class_tokens`` / ``region`` / ``anchor_label``），仓库里的 models.LinkContext
    只有原型的 5 个，而 models.py 是数据结构的唯一定义处、本步不许改
    （见交付说明 spec_gaps）。这五个字段里 ``anchor_html`` 就带着 class 属性，
    所以这里从它解析，等 LinkContext 补齐后改成直接读字段即可。
    """
    if not ctx.anchor_html:
        return ()
    m = _CLASS_ATTR_RE.search(ctx.anchor_html)
    if m is None:
        return ()
    raw = m.group(1) or m.group(2) or m.group(3) or ""
    return tuple(t for t in raw.split() if t)


def anchor_label_of(ctx: LinkContext) -> str:
    """无锚文本时的「可见内容」——``aria-label`` / ``<img alt>`` / ``title``。

    §5.6 表尾定死：commercelayer 的 Discord 图标只有 ``aria-label="Discord"``，
    **所以 aria-label 必须算「有可见内容」**；tdengine 首页连接器图标墙的
    anchor_label 来自 ``<img alt>``。
    """
    if not ctx.anchor_html:
        return ""
    m = _LABEL_ATTR_RE.search(ctx.anchor_html)
    if m is None:
        return ""
    return (m.group(1) or m.group(2) or "").strip()


def region_of_context(ctx: LinkContext) -> str:
    """``prominent`` / ``body`` / ``footer`` 的退化推断（footer 赢）。

    §5.2 的 ``extract.region_of`` 走真 DOM 祖先链，是唯一权威实现；本函数只在
    调用方拿不到 DOM 节点（fp_gate 的标注行、llms.txt 里的链接）时兜底，判据
    与它同源：同两条正则 + ``<footer>`` 标签，haystack 取
    ``anchor_html + surrounding_html``。拿得到 DOM 就把结果直接传
    ``position_class_of(..., region=...)``，别用这个。
    """
    haystack = f"{ctx.anchor_html} {ctx.surrounding_html}".lower()
    if not haystack.strip():
        return "body"
    if "<footer" in haystack or _REGION_FOOTER_RE.search(haystack):
        return "footer"
    if _REGION_PROMINENT_RE.search(haystack):
        return "prominent"
    return "body"


def _presigned_expiring(url: str) -> bool:
    return any(m in url for m in _PRESIGNED_MARKERS) or all(m in url for m in _AZURE_SAS_MARKERS)


def _class_hidden_anchor(ctx: LinkContext) -> bool:
    tokens = class_tokens_of(ctx)
    return "hidden" in tokens and not any(_RESPONSIVE_VISIBLE_RE.match(t) for t in tokens)


def _seed_url_not_on_site(
    url: str, *, seed_origin: str | None, extracted_norm_urls: frozenset[str] | None
) -> bool:
    """我们自己猜的候选 URL，站上没有任何 ``<a>`` 指向它。

    ``seed_origin`` 非空 = 这条 URL 来自 SEED_PAGES / PRICING_CANDIDATES /
    AI_PATH_CANDIDATES 的构造；``extracted_norm_urls`` 是本次抓取里真的抽到过
    的目标集合（None = 调用方没提供，此时只看 seed_origin）。
    实测出处：电商批那条「我自己塞进种子的猜测 URL」（Square 定价页候选之一，404）。
    """
    if seed_origin is None:
        return False
    if extracted_norm_urls is None:
        return True
    return url not in extracted_norm_urls


def classify_link_pre(
    url: str,
    ctx: LinkContext | None = None,
    *,
    raw_href: str | None = None,
    seed_origin: str | None = None,
    extracted_norm_urls: frozenset[str] | None = None,
) -> EligibilityExclusion | None:
    """pre 阶段全部 14 条规则的唯一入口：**一次请求都不发**。

    返回 None = 这条链接有资格被判死。返回值的 ``disposition``：
      ``"excluded"``      —— 出分子，进 Exclusion 日志（13 条规则）
      ``"needs_review"``  —— **仍然计入分子**，只把 finding.confidence 置成
                             needs_review 并进报告「待人工确认」区（卡点 S4，
                             目前只有 class_hidden_anchor 一条）
    """
    ctx = ctx or LinkContext(source_page="")
    href = raw_href if raw_href is not None else url

    # framework_bind_artifact 的补丁半边（`${...}`）。放在最前面：它是抽取伪影，
    # 连「URL」都不是，后面任何规则对它的判断都没有意义。
    if _DOLLAR_BRACE_RE.search(href):
        return EligibilityExclusion(
            "framework_bind_artifact",
            "raw_href 以 ${ 开头，是 SSR 把模板字符串原样落进 href 的抽取伪影",
        )

    if _presigned_expiring(url):
        return EligibilityExclusion(
            "presigned_expiring",
            "URL 是预签名链接（X-Amz-Expires / X-Goog-Expires / Azure SAS se+sig），"
            "会自己过期，不是甲方的死链；报告提示区单列一句",
        )

    # 原型那 11 条（含 inline_display_none_anchor）。顺序：内联 style 先判，
    # 再判 class —— printify 那条真实案例是 class 隐藏（X13 那条合成用例才是
    # 内联 style），两者必须分得开。
    prototype = classify_link_eligibility(url, ctx)
    if prototype is not None:
        return prototype

    if _class_hidden_anchor(ctx):
        return EligibilityExclusion(
            "class_hidden_anchor",
            '<a> 的 class 含裸 "hidden" 且无响应式可见覆盖 token，普通访客点不到。'
            "**不排除**：md:hidden 在桌面是可见的、外部样式表的 display:none 静态 HTML "
            "判不了，只有 n=1 证据，所以只标「待人工确认」，判死结论不变",
            provenance="single_case",
            disposition="needs_review",
        )

    if _seed_url_not_on_site(url, seed_origin=seed_origin, extracted_norm_urls=extracted_norm_urls):
        return EligibilityExclusion(
            "seed_url_not_on_site",
            f"这条 URL 来自我们自己的候选构造（{seed_origin}），站上没有任何 <a> 指向它，"
            "404 只说明我们猜错了路径，绝不进死链分子",
        )

    return None


# --------------------------------------------------------------------------- #
# §5.6 位置分级（零 LLM，三信号，全部可审计）
#
# 严重度由报告层的 SEVERITY_BY_POSITION 查表（§2.5）；本模块只负责 PositionClass。
# 上面那个 severity_of() 是原型的三档字符串实现，冻结测试直接断言它，**保留原样**
# —— 它与本函数的三处差异见 §2.5 差异表（最显眼的一条：unkey 的 "Read the docs"
# 在 severity_of 里落 sales_path，在这里落 DOC_ENTRY）。
# --------------------------------------------------------------------------- #

SALES_KW: tuple[str, ...] = (
    "talk to us",
    "talk to sales",
    "contact sales",
    "contact us",
    "get a demo",
    "book a demo",
    "request a demo",
    "schedule a call",
    "get a quote",
    "start free",
    "start for free",
    "free trial",
    "start trial",
    "sign up",
    "get started free",
    "buy now",
    "see pricing",
    "see plans",
    "see how",
    "upgrade",
    "联系销售",
    "预约演示",
    "免费试用",
    "立即购买",
    "咨询报价",
)
DOCS_ENTRY_KW: tuple[str, ...] = (
    "read the docs",
    "read docs",
    "documentation",
    "api reference",
    "api docs",
    "quickstart",
    "quick start",
    "get started",
    "view docs",
    "developer docs",
    "查看文档",
    "开发文档",
    "快速开始",
)
EXAMPLE_KW: tuple[str, ...] = (
    "example repository",
    "example repo",
    "sample code",
    "sample app",
    "view on github",
    "cookbook",
    "starter template",
    "boilerplate",
    "示例仓库",
    "示例代码",
)
SOCIAL_HOSTS: frozenset[str] = frozenset(
    {
        "x.com",
        "twitter.com",
        "linkedin.com",
        "www.linkedin.com",
        "facebook.com",
        "www.facebook.com",
        "youtube.com",
        "www.youtube.com",
        "instagram.com",
        "www.instagram.com",
        "discord.com",
        "discord.gg",
        "join.slack.com",
        "reddit.com",
        "www.reddit.com",
        "mastodon.social",
        "bsky.app",
    }
)

#: _looks_like_docs 的 host 半边。规格引用了 `_DOC_HOST_RE` 但全文没有定义它
#: （见交付说明 spec_gaps），这里按 §3.7 的文档子域前缀表落成正则。
_DOC_HOST_RE = re.compile(r"^(?:docs?|developer|developers|api|apidocs|api-docs|reference)\.", re.I)
_DOC_PATH_RE = re.compile(r"^/(?:docs?|documentation|reference|guides)(?:/|$)", re.I)


def _looks_like_docs(url: str) -> bool:
    """host 命中 _DOC_HOST_RE 或 path 以 /docs、/documentation、/reference、/guides 开头。"""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return bool(_DOC_HOST_RE.match(host) or _DOC_PATH_RE.match(parts.path or "/"))


def position_class_of(
    url: str,
    ctx: LinkContext,
    *,
    source_role: str,
    region: str | None = None,
) -> PositionClass:
    """判定顺序即优先级。一条 finding 取它所有实例里**最严重**的那个 PositionClass。

    ⚠️ DOCS_ENTRY_KW 在 SALES_KW **之后**判，但 "read the docs" 只在 DOCS_ENTRY_KW
       里，所以 unkey 那条落 DOC_ENTRY（与原型 severity_of 的差异，见 §2.5 差异表）。
       "get started" 同时在两张表里 -> 先命中 SALES_KW -> SALES_PATH。这是故意的：
       "Get started" 按钮实测都是注册入口。

    ``region`` 是本实现补的 keyword（规格签名只有 ``source_role``）：§5.6 的伪代码
    读 ``ctx.region`` / ``ctx.anchor_label``，而 models.LinkContext 现在没有这两个
    字段。拿得到 DOM 的调用方（extract.region_of）把结果传进来；传 None 时退回
    region_of_context(ctx) 的正则推断。
    """
    label = anchor_label_of(ctx)
    text = f"{ctx.anchor_text} {label}".strip().lower()
    host = (urlsplit(url).hostname or "").lower()
    where = region if region is not None else region_of_context(ctx)

    if ctx.from_text_file:
        return PositionClass.AI_CHANNEL
    if host in SOCIAL_HOSTS:
        return PositionClass.FOOTER_SOCIAL
    if where == "footer":
        return PositionClass.FOOTER_SOCIAL
    if any(k in text for k in SALES_KW):
        return PositionClass.SALES_PATH
    if any(k in text for k in EXAMPLE_KW):
        return PositionClass.DOC_ENTRY
    if any(k in text for k in DOCS_ENTRY_KW):
        return PositionClass.DOC_ENTRY
    if source_role in ("home", "pricing") and where == "prominent":
        return PositionClass.DOC_ENTRY if _looks_like_docs(url) else PositionClass.SALES_PATH
    if where == "prominent":
        return PositionClass.NAV
    return PositionClass.BODY
