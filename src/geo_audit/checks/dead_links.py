"""C1 · 死链判定（§5.1–§5.3 的第 12a / 12b 步）。

**去噪是这个检查的全部价值。** 实测：去噪前 42 条判死只有 25 条真死，假阳性
40.5%；去噪后 0%（n=51）。假阳性的六个来源逐条对应到 §5.3 的规则表里：
URL 模板占位符（``{permalink}`` / ``{year}`` / ``${...}``）、地理限制 404、
bot 挑战页（被当成 429/403）、UA 反爬、需登录页、跳转只看第一跳。

本模块的三件事：

1. :func:`classify_link` —— 一条链接从「有没有资格被判死」到「死没死」的全过程。
   位置由规格定死在本文件，**它就是生产路径**：``scripts/fp_gate.py`` 的六条
   门禁跑的是它，不是另写一份判定（卡点 A1）。
2. :func:`is_dead` —— 判死白名单。只有四种情况算 DEAD，且必须先过七条 post 规则。
   **偏向「判不了」而不是「判死」**：一条假死链毁掉整份报告的可信度，一条
   「看不了」只损失覆盖率。
3. :func:`host_unprobeable` / sibling control / login_wall 车道 —— 把实测里
   人工做过的证伪动作固化成代码（tenderly 的 27 条 429、crates.io 的 UA 敏感
   404、teachable 的登录墙、moonshot 的「兄弟全 200 所以是真路由缺失」）。

pre 阶段的 14 条规则不在这里，在 :mod:`geo_audit.fetch.denoise`（规格定死的位置）。
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urljoin, urlsplit

import httpx

from ..fetch import fingerprints as fp
from ..fetch.classify import classify_response
from ..fetch.client import Fetcher
from ..fetch.denoise import EligibilityExclusion, classify_link_pre, position_class_of
from ..fetch.ratelimit import registrable_domain
from ..fetch.resolve import HostResolver, Resolution
from ..fixtures import DnsFixtureMissing, FixtureMissing, FixtureStore
from ..models import (
    Expect,
    HostProfile,
    HttpResponse,
    LinkContext,
    LinkState,
    PositionClass,
    Probe,
    Verdict,
)
from ..naive import naive_link_is_dead

__all__ = [
    "AI_PATH_CANDIDATES",
    "DEAD_LINK_POST_RULES",
    "DEAD_LINK_PRE_RULES",
    "DEAD_LINK_RULE_IDS",
    "MAX_SEED_PAGES",
    "PRICING_CANDIDATES",
    "SEED_PAGES",
    "HostFacts",
    "LinkVerdict",
    "classify_link",
    "host_unprobeable",
    "is_dead",
    "seed_origin_of",
]

# --------------------------------------------------------------------------- #
# §5.1 采集范围
# --------------------------------------------------------------------------- #

#: 每个类别里的候选**按顺序探，命中第一个 200 就停**（不是全探）。
#: 没命中的候选一律走 ``seed_url_not_on_site``，**绝不进死链**。
SEED_PAGES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("home", ("https://{apex}/", "https://www.{apex}/")),
    ("pricing", ("/pricing", "/plans", "/pricing/", "/plans/", "/us/en/pricing")),
    (
        "changelog",
        (
            "/changelog",
            "/release-notes",
            "/releases",
            "/whats-new",
            "{docs_host}/changelog",
            "{docs_host}/product-updates/release-notes/",
        ),
    ),
    ("docs_home", ("{docs_host}/", "https://developers.{apex}/", "https://{apex}/docs")),
    ("docs_content", ("<pick_docs_content_seeds(docs_home_html, docs_host, n=3)>",)),
    ("api_ref", ("<pick_api_ref_seed(docs_home_html, docs_host)>",)),
    ("help", ("https://help.{apex}/", "https://support.{apex}/")),
)
MAX_SEED_PAGES = 12

#: §3.7 与 pricing seed 共用同一次探测结果，不重复发请求。
PRICING_CANDIDATES: tuple[str, ...] = (
    "/pricing",
    "/pricing/",
    "/plans",
    "/plans/",
    "/price",
    "/prices",
    "/pricing-plans",
    "/us/en/pricing",
    "/pricing/plans",
)
AI_PATH_CANDIDATES: tuple[str, ...] = (
    "/llms.txt",
    "/docs/llms.txt",
    "/llms-full.txt",
    "/docs/llms-full.txt",
    "/.well-known/llms.txt",
)

#: ``seed_url_not_on_site`` 的判据之一：这条路径是我们自己构造的候选形态。
#: **不含 ``/``** —— 首页是抓取起点，不是「猜的候选」。
_SEED_RELATIVE_PATHS: frozenset[str] = frozenset(
    {
        *(p.rstrip("/") or "/" for p in PRICING_CANDIDATES),
        *(p.rstrip("/") or "/" for p in AI_PATH_CANDIDATES),
        "/changelog",
        "/release-notes",
        "/releases",
        "/whats-new",
        "/product-updates/release-notes",
        "/docs",
    }
) - {"/"}

_SEED_ORIGIN_BY_PATH: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset(p.rstrip("/") or "/" for p in PRICING_CANDIDATES) - {"/"}, "PRICING_CANDIDATES"),
    (frozenset(p.rstrip("/") or "/" for p in AI_PATH_CANDIDATES), "AI_PATH_CANDIDATES"),
)

# --------------------------------------------------------------------------- #
# §5.3 规则 id 注册表（dead_links 那一半）
#
# ⚠️ 规格把 CHECK_IDS / RULE_REGISTRY 写成一张同时含 ai_path 的表（§5.3 卡点 B19），
#    但 ai_path 的四条规则 id 属于 checks/ai_path.py，CLI 的 --skip / --only 才是
#    真正的消费方。为了不出现第二处 RULE_REGISTRY 定义，这里只导出 dead_links
#    那一半；CLI 落地时把两半拼成 RULE_REGISTRY 即可（见交付说明 spec_gaps）。
# --------------------------------------------------------------------------- #

DEAD_LINK_PRE_RULES: tuple[str, ...] = (
    "url_template_placeholder",
    "reserved_example_domain",
    "non_http_scheme",
    "cloudflare_email_protection",
    "mintlify_injected_anchor",
    "fern_injected_anchor",
    "fern_console_host",
    "intellimize_endpoint",
    "framework_bind_artifact",
    "api_endpoint_in_code_context",
    "inline_display_none_anchor",
    "presigned_expiring",
    "class_hidden_anchor",
    "seed_url_not_on_site",
)
DEAD_LINK_POST_RULES: tuple[str, ...] = (
    "waf_challenge",
    "hostile_400",
    "host_unprobeable",
    "third_party_no_control",
    "geo_redirect",
    "login_wall",
    "network_timeout",
    "upstream_error",
    "dns_retry_second_resolver",
)
DEAD_LINK_RULE_IDS: tuple[str, ...] = DEAD_LINK_PRE_RULES + DEAD_LINK_POST_RULES

# --------------------------------------------------------------------------- #
# §5.3 卡点 S4 的口径差：不许藏
# --------------------------------------------------------------------------- #

#: 各批原始自报
RAW_DEAD_LINKS, RAW_DEAD_DOMAINS = 94, 28
#: challenge 的口径「只算普通访客点得到的内容链接」= 剔 attio 2 + brevo 2 +
#: close 2 + copper 1 + printify 1 = 8 条
CHALLENGE_DEAD_LINKS, CHALLENGE_DEAD_DOMAINS = 86, 25
#: 本工具：排掉前 7 条框架/机器产物，但 printify 那条按 class_hidden_anchor
#: 只打 needs_review、**仍计入分子**，所以比 challenge 多 1 条、多 1 个域。
TOOL_DEAD_LINKS, TOOL_DEAD_DOMAINS = 87, 26
CALIBRATION_DIFF_NOTE = (
    "本工具 87 条 / 26 域 与 challenge 86 条 / 25 域 差的那 1 条是 printify 的 "
    "IRS Form 8937 PDF：它的 <a> 是 class 含 hidden（不是内联 style），"
    "class_hidden_anchor 的处置是 needs_review 而不是 EXCLUDED，所以判死结论不变、"
    "只进「待人工确认」区。这不是 bug，是「静态 HTML 判不了 class 隐藏」这条约束的代价。"
)

# --------------------------------------------------------------------------- #
# post 阶段规则的字面量（§5.3 post 表）
# --------------------------------------------------------------------------- #

#: geo_redirect：跳转链在路径头插入了原 URL 没有的地区段随后 404。
_GEO_SEGMENT_RE = re.compile(r"^/((sg|us|uk|de|fr|jp|au|ca)|[a-z]{2}-[a-z]{2})(/|$)")
#: login_wall：host 或 path 命中，或跳转超 10 跳。
_LOGIN_HOST_RE = re.compile(r"^(app|dashboard|console|sso|secure|my|account|admin|portal)\.")
_LOGIN_PATH_RE = re.compile(r"/(login|signin|signup|oauth|auth|sso)(/|$)")
LOGIN_WALL_MAX_REDIRECTS = 10
#: network_timeout：``transport_error`` 属于这四种，退避重试 2 次仍失败。
#: 重试由 ``Fetcher._attempt`` 做（RETRY_ATTEMPTS=3、RETRY_BACKOFF=(2.0, 6.0)
#: 正好是「退避重试 2 次」），所以本模块只读结果、不再自己重试。
_TIMEOUT_TOKENS = ("timeout", "timed out")
_TLS_TOKENS = ("tls", "ssl", "certificate", "handshake")
_RESET_TOKENS = ("reset", "connection aborted", "broken pipe")
_MAX_REDIRECT_TOKENS = ("too many redirects", "maximum redirects", "max redirects")
#: upstream_error：5xx / 520–530。
_UPSTREAM_STATUSES: frozenset[int] = frozenset(
    {500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511, *range(520, 531)}
)
#: 软 404 里靠对照探针才成立的那几个 reason —— 它们要求 host_profile 可用。
_CONTROL_BASED_SOFT404_REASONS: frozenset[str] = frozenset(
    {"identical_to_control", "near_identical_to_control"}
)
#: is_dead 第 3 条：``>=2 个 resolver NXDOMAIN``。fixtures/dns.json 的
#: ``_default_absent`` 兜底行只写了一个裸 "NXDOMAIN"（没点名解析器），那**不够**
#: —— 只点名 0 个解析器的 NXDOMAIN 一律 UNKNOWN，不判死。
_RESOLVER_NAMES = ("system", "8.8.8.8", "1.1.1.1")
_MIN_NXDOMAIN_RESOLVERS = 2


@dataclass(frozen=True, slots=True)
class LinkVerdict:
    """一条可点击链接的判定结果。

    ⚠️ ``LinkVerdict`` 在规格全文里只出现一次（§8.6 行 4358 的 ``classify_link``
    返回类型），没有任何字段定义。这里按它的两个已知消费点（``v.rule_id`` 与
    「pred == DEAD」）加报告层需要的证据字段落成最小形状。它不属于 §2 的报告层
    类型，所以定义在本模块而不是 models.py（见交付说明 spec_gaps）。
    """

    url: str
    state: LinkState
    reason: str = ""
    #: 命中的去噪 / post 规则 id（空 = 没有规则参与判定）。
    rule_id: str = ""
    #: ``counted`` | ``excluded`` | ``needs_review``
    disposition: Literal["counted", "excluded", "needs_review"] = "counted"
    #: 直接喂 ``Finding.confidence``。
    confidence: Literal["confirmed", "needs_review"] = "confirmed"
    status: int | None = None
    final_url: str = ""
    #: 同 host 存活对照（A23：每条第三方 host 的 DEAD 目标必须非空）。
    confirmations: tuple[tuple[str, int], ...] = ()
    exclusions: tuple[EligibilityExclusion, ...] = ()
    evidence: tuple[str, ...] = ()
    #: 「一个只看最终状态码 / 只探第一跳的工具会怎么说」。
    naive_would_say: str = ""
    position_class: PositionClass | None = None
    #: 这次判定用的响应是不是从 fixture 快照回放来的。
    from_fixture: bool = False
    requests_spent: int = 0

    @property
    def counted_dead(self) -> bool:
        """进死链分子吗？``needs_review`` **进**（卡点 S4），``excluded`` 不进。"""
        return self.state is LinkState.DEAD


@dataclass(frozen=True, slots=True)
class HostFacts:
    """一个 host 的「拿不可能存在的路径怎么回」+ 根路径活没活。按 host 缓存。"""

    host: str
    root: Probe | None
    control: HostProfile | None
    unprobeable: bool
    root_status: int | None = None
    alive_urls: tuple[tuple[str, int], ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------- #
# seed 来源
# --------------------------------------------------------------------------- #


def seed_origin_of(url: str, *, audited_domain: str | None) -> str | None:
    """这条 URL 是不是我们自己构造的候选？返回构造表名，否则 None。

    判据三条同时成立：① 与被审计域同注册域（别人家的 /pricing 不是我们猜的）；
    ② 路径形态在 :data:`PRICING_CANDIDATES` / :data:`AI_PATH_CANDIDATES` /
    SEED_PAGES 的相对候选里；③ 调用方没能在任何已抓页面里抽到它（由
    ``classify_link`` 的 ``extracted_norm_urls`` / 空 ``source_page`` 判定）。
    实测出处：电商批那条 ``developer.squareup.com/pricing``（我自己塞进种子的
    猜测 URL，404）。
    """
    if not audited_domain:
        return None
    host = (urlsplit(url).hostname or "").lower()
    if registrable_domain(host) != registrable_domain(audited_domain.lower()):
        return None
    path = urlsplit(url).path or "/"
    key = path.rstrip("/") or "/"
    if key not in _SEED_RELATIVE_PATHS:
        return None
    for paths, origin in _SEED_ORIGIN_BY_PATH:
        if key in paths:
            return origin
    return "SEED_PAGES"


# --------------------------------------------------------------------------- #
# host_unprobeable（§5.3 的精确定义，卡点 2）
# --------------------------------------------------------------------------- #


def host_unprobeable(root: Probe, control: HostProfile | None) -> bool:
    """该 host 的根路径与随机路径**都不可信**时为真。

    「不可信」= verdict in (BLOCKED, UNKNOWN) 或 (verdict is OK and 该响应与
    control 无法区分，即 ``status_discriminates is False`` and not
    (expect is TEXT_FILE and control_is_html))。
    两条都不可信 -> True。**只有一条不可信不算**（那是正常的软 404 场景）。
    构造成本：每个第三方 host 2 个请求，按 host 缓存。

    ⚠️ 规格的签名是 ``(root: Probe, control: Probe)``，但 docstring 里读的
    ``status_discriminates`` / ``control_is_html`` 是 ``HostProfile`` 的字段
    （models.py），``Probe`` 上没有 —— 照签名写 mypy strict 直接红。第二个形参
    在语义上本来就是 HostProfile（「该 host 的随机路径怎么回」正是它的定义），
    所以这里按 HostProfile 落地（见交付说明 deviations）。
    """
    return _untrustworthy(root, control) and _control_untrustworthy(control)


def _untrustworthy(probe: Probe, control: HostProfile | None) -> bool:
    verdict = probe.classification.verdict
    if verdict in (Verdict.BLOCKED, Verdict.UNKNOWN):
        return True
    if verdict is Verdict.OK and control is not None:
        indistinguishable = not control.status_discriminates and not (
            probe.expect is Expect.TEXT_FILE and control.control_is_html
        )
        return indistinguishable
    return False


def _control_untrustworthy(control: HostProfile | None) -> bool:
    if control is None:
        return True
    if not control.usable:
        return True
    # 控制探针本该 404/410。它回 2xx 说明这个 host 对任何路径都给同一张壳。
    return not control.status_discriminates


# --------------------------------------------------------------------------- #
# 判死白名单
# --------------------------------------------------------------------------- #


def is_dead(
    probe: Probe,
    host_profile: HostProfile | None,
    confirmations: Sequence[tuple[str, int]],
    exclusions: Sequence[EligibilityExclusion],
    *,
    dns: Resolution | None = None,
) -> bool:
    """1. 最终状态 404
       2. 最终状态 410
       3. >=2 个 resolver NXDOMAIN
       4. 确认的软 404（host_profile 模式 + 正文/骨架/落地页比对）

    并且必须先过 waf_challenge / third_party_no_control / geo_redirect /
    network_timeout / upstream_error / host_unprobeable / login_wall
    —— 那七条在 :func:`classify_link` 里跑，本函数假设它们已经放行。
    202 算 ALIVE（app.baseten.co 系列返 202）；400/405/451/5xx 一律 UNKNOWN。

    ⚠️ 卡点 S4：命中 ``disposition == "needs_review"`` 的规则（目前只有
    ``class_hidden_anchor``）**不改变本函数的结论**，只置
    ``finding.confidence = "needs_review"`` 并进报告的「待人工确认」区。

    ``dns`` 是本实现补的 keyword：规格的四个形参里没有任何东西能表达第 3 条
    （resolver 的答案不在 Probe 上），而漏掉第 3 条 ``http://next.js/`` 那种
    真死链就检不出来（见交付说明 deviations）。
    """
    if any(ex.disposition == "excluded" for ex in exclusions):
        return False

    if dns is not None and _nxdomain_confirmed(dns):
        return True

    resp = probe.response
    status = resp.status if resp is not None else 0
    if status in (404, 410):
        return True
    if probe.classification.verdict is Verdict.SOFT404:
        if probe.classification.reason in _CONTROL_BASED_SOFT404_REASONS:
            return host_profile is not None and host_profile.usable
        return True
    return False


def _nxdomain_confirmed(dns: Resolution) -> bool:
    """>=2 个 resolver 明确 NXDOMAIN 才算。"""
    if dns.ok or dns.addresses:
        return False
    err = (dns.error or "").upper()
    if "NXDOMAIN" not in err:
        return False
    named = sum(1 for name in _RESOLVER_NAMES if name.upper() in err)
    return named >= _MIN_NXDOMAIN_RESOLVERS


# --------------------------------------------------------------------------- #
# post 阶段的九条规则
# --------------------------------------------------------------------------- #


def _transport_error_kind(err: str | None) -> str | None:
    if not err:
        return None
    e = err.lower()
    if any(t in e for t in _MAX_REDIRECT_TOKENS):
        return "max_redirects"
    if any(t in e for t in _TIMEOUT_TOKENS):
        return "timeout"
    if any(t in e for t in _TLS_TOKENS):
        return "tls"
    if any(t in e for t in _RESET_TOKENS):
        return "reset"
    return None


def _is_challenge(probe: Probe) -> bool:
    resp = probe.response
    if resp is None:
        return False
    if probe.classification.verdict is Verdict.BLOCKED:
        return True
    return resp.status in fp.BLOCKED_STATUSES


def _hostile_400(url: str, probe: Probe) -> bool:
    resp = probe.response
    host = (urlsplit(url).hostname or "").lower()
    return resp is not None and resp.status == 400 and host in fp.HOSTILE_400_HOSTS


def _login_wall(url: str, probe: Probe, confirmations: Sequence[tuple[str, int]]) -> bool:
    """登录墙**不能一刀切**（三个反例定的表）。

    teachable 8 条 ``sso.teachable.com/secure/...`` 403、兄弟同样 403 -> UNKNOWN；
    moderntreasury 4 条 ``app.moderntreasury.com`` 的 Auth0 跳转环 -> UNKNOWN；
    但 moonshot ``platform.kimi.ai/console/invoice`` 的四个兄弟路径**全部 200**
    -> **DEAD**（路由缺失，不是需登录）。最后这条就是下面那个 early return：
    目标 404/410 而同 host 有活着的兄弟 = 路由缺失，不是墙。
    """
    resp = probe.response
    status = resp.status if resp is not None else 0
    if status in (404, 410) and any(200 <= code < 300 for _, code in confirmations):
        return False

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if _LOGIN_HOST_RE.match(host) or _LOGIN_PATH_RE.search(parts.path or "/"):
        return status == 0 or status in fp.BLOCKED_STATUSES or status in (301, 302, 303, 307, 308)
    return resp is not None and len(resp.redirects) > LOGIN_WALL_MAX_REDIRECTS


def _upstream_error(probe: Probe) -> bool:
    resp = probe.response
    return resp is not None and resp.status in _UPSTREAM_STATUSES


def _geo_redirect(url: str, probe: Probe, *, source_page: str) -> bool:
    """跳转链在路径头插入了原 URL 没有的地区段，随后 404。

    出口在新加坡时 klaviyo 与 zendesk 的链接被 geo-redirect 到 ``/sg/`` 之后才
    404。两种形态都要认：
      ① 我们请求的 URL 没有地区段，跳转链把它插进来了（跳转可见）；
      ② 我们手上的 URL 已经是被 geo-redirect 之后的那条（实测标注就是这形态），
         此时对照物是**源页自己的路径**：源页在 ``/pricing``、目标在
         ``/sg/pricing``，那个 ``/sg`` 不是站点结构，是出口 IP 造成的。
    """
    resp = probe.response
    if resp is None or resp.status not in (404, 410):
        return False

    requested = urlsplit(url).path or "/"
    final = urlsplit(resp.final_url or url).path or "/"
    if _GEO_SEGMENT_RE.match(final) and not _GEO_SEGMENT_RE.match(requested):
        return True
    if not _GEO_SEGMENT_RE.match(requested):
        return False
    source_path = urlsplit(source_page).path or "/" if source_page else ""
    return bool(source_path) and not _GEO_SEGMENT_RE.match(source_path)


# --------------------------------------------------------------------------- #
# 探测
# --------------------------------------------------------------------------- #


def _probe_with_client(client: httpx.Client, url: str, *, expect: Expect) -> Probe:
    """没有 Fetcher 时的退化探测：一次请求 + classify_response，无对照探针。

    生产调用方一律传 ``fetcher=``（限速器、缓存、跟跳转、对照探测全在那条路上）。
    这条退化路只服务「调用方手里只有一个 httpx.Client」的场景 —— 规格给
    ``classify_link`` 的签名就是这样（``client: httpx.Client``，见 §8.6 行 4357）。
    """
    try:
        raw = client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        resp = HttpResponse(
            url=url, final_url=url, status=0, headers={}, body=b"", transport_error=str(exc)
        )
    else:
        resp = HttpResponse(
            url=url,
            final_url=str(raw.url),
            status=raw.status_code,
            headers={k.lower(): v for k, v in raw.headers.items()},
            body=raw.content,
        )
    cls = classify_response(
        resp.status,
        resp.headers,
        resp.text,
        url=url,
        expect=expect,
        final_url=resp.final_url,
        redirects=resp.redirects,
        transport_error=resp.transport_error,
    )
    return Probe(url, expect, resp, cls)


def _probe(
    url: str,
    *,
    fetcher: Fetcher | None,
    client: httpx.Client,
    expect: Expect = Expect.ANY,
) -> Probe | None:
    """探一条 URL。缺快照 / 缺 DNS 冻结记录时返回 None（判 UNKNOWN(not_fetched)）。"""
    try:
        if fetcher is not None:
            return fetcher.probe(url, expect=expect)
        return _probe_with_client(client, url, expect=expect)
    except (FixtureMissing, DnsFixtureMissing):
        return None


def _host_facts(
    url: str,
    *,
    fetcher: Fetcher | None,
    client: httpx.Client,
    cache: dict[str, HostFacts] | None,
) -> HostFacts:
    """根路径 + 随机路径两个探针，按 host 缓存（每个 host 最多 2 个请求）。"""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if cache is not None and host in cache:
        return cache[host]

    root_url = f"{parts.scheme or 'https'}://{parts.netloc}/"
    root = _probe(root_url, fetcher=fetcher, client=client)
    control: HostProfile | None = None
    if fetcher is not None:
        try:
            control = fetcher.host_profile(url)
        except (FixtureMissing, DnsFixtureMissing):
            control = None

    root_status = root.response.status if root is not None and root.response is not None else None
    alive: tuple[tuple[str, int], ...] = ()
    if root_status is not None and 200 <= root_status < 300:
        alive = ((root_url, root_status),)
    facts = HostFacts(
        host=host,
        root=root,
        control=control,
        unprobeable=(root is not None and host_unprobeable(root, control)),
        root_status=root_status,
        alive_urls=alive,
    )
    if cache is not None:
        cache[host] = facts
    return facts


def _collect_confirmations(
    url: str,
    *,
    candidates: Sequence[str],
    fetcher: Fetcher | None,
    client: httpx.Client,
    host_cache: dict[str, HostFacts] | None,
) -> tuple[tuple[tuple[str, int], ...], int]:
    """同 host 存活对照。**第三方 404 必须有它才允许判死。**

    来源优先级（§5.3）：本次抓取里同 host 的已知 200 -> 目标路径的父路径 ->
    host 根路径。拿不到 -> UNKNOWN。实测里人工做过的四处动作就是这条链：
    depot 的 ``x.com/turckalicious`` 靠 ``x.com/vercel`` + ``x.com/jacobwgillespie``
    200 排除 x.com 整体反爬；baseten 的 ``x.com/basetenco`` 靠 openai /
    deepgramai / modal_labs 三条 200 排除；liveblocks 的 ``github.com/daniliwoz``
    靠同页 ``github.com/ctnicholas`` 200；tinybird 的 ``x.com/tinybirdco`` 靠
    ``x.com/vercel`` 200 —— 而且 ``x.com`` 与 ``twitter.com`` 双写都要探，
    两者都 404 才判死。
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    out: list[tuple[str, int]] = []
    spent = 0

    for cand in candidates:
        if (urlsplit(cand).hostname or "").lower() != host:
            continue
        probe = _probe(cand, fetcher=fetcher, client=client)
        spent += 1
        if probe is not None and probe.response is not None and 200 <= probe.response.status < 300:
            out.append((cand, probe.response.status))
    if out:
        return tuple(out), spent

    path = parts.path or "/"
    parent = urljoin(url, ".") if path.rstrip("/").count("/") >= 2 else ""
    if parent and parent.rstrip("/") != f"{parts.scheme}://{parts.netloc}":
        probe = _probe(parent, fetcher=fetcher, client=client)
        spent += 1
        if probe is not None and probe.response is not None and 200 <= probe.response.status < 300:
            return ((parent, probe.response.status),), spent

    fresh = host_cache is None or host not in host_cache
    facts = _host_facts(url, fetcher=fetcher, client=client, cache=host_cache)
    if fresh:
        spent += 2  # host 根路径 + 随机路径，按 host 缓存，每个 host 只花这两个
    return facts.alive_urls, spent


# --------------------------------------------------------------------------- #
# 生产入口
# --------------------------------------------------------------------------- #


def classify_link(
    url: str,
    *,
    source_page: str,
    ctx: LinkContext,
    client: httpx.Client,
    store: FixtureStore,
    fetcher: Fetcher | None = None,
    source_role: str = "unknown",
    audited_domain: str | None = None,
    raw_href: str | None = None,
    region: str | None = None,
    extracted_norm_urls: frozenset[str] | None = None,
    confirmation_candidates: Sequence[str] = (),
    resolver: HostResolver | None = None,
    host_cache: dict[str, HostFacts] | None = None,
    denoise: bool = True,
) -> LinkVerdict:
    """一条链接的完整判定。**这个函数就是生产路径。**

    卡点 A1：v1 的 fp_gate 里用了一个从未定义、且绕开 Fetcher 直连 httpx 的
    classify_link —— 那样测的不是生产代码。v2 的签名要求传入 ``client`` 与
    ``store``，fp_gate 构造的是**真正的 Fetcher**（``transport=store.transport()``、
    ``probe_url_provider=store.probe_url``），所以门禁跑的是限速器、缓存、
    跟跳转、对照探测全在的那条路。

    ``denoise=False`` 复现「没有去噪的那个朴素实现」：pre 与 post 全部规则关掉、
    DNS 重试车道关掉，判死只看「最终状态 404/410 或请求失败」。它是
    ``test_naive_would_be_405_percent`` 的输入，也是报告里 40.5% -> 0% 那句话的
    可执行证据。

    除 ``url`` / ``source_page`` / ``ctx`` / ``client`` / ``store`` 五个规格形参外
    全部是 keyword-only 且带默认值的补充（见交付说明 deviations）。
    """
    exclusions: list[EligibilityExclusion] = []
    disposition: Literal["counted", "excluded", "needs_review"] = "counted"
    confidence: Literal["confirmed", "needs_review"] = "confirmed"
    rule_id = ""
    spent = 0
    position = position_class_of(url, ctx, source_role=source_role, region=region)

    # ---- pre：一次请求都不发 ------------------------------------------ #
    if denoise:
        seed_origin = None
        if not source_page:
            seed_origin = seed_origin_of(url, audited_domain=audited_domain)
        pre = classify_link_pre(
            url,
            ctx,
            raw_href=raw_href,
            seed_origin=seed_origin,
            extracted_norm_urls=extracted_norm_urls,
        )
        if pre is not None:
            exclusions.append(pre)
            rule_id = pre.rule_id
            if pre.disposition == "excluded":
                return LinkVerdict(
                    url=url,
                    state=LinkState.EXCLUDED,
                    reason=pre.reason,
                    rule_id=pre.rule_id,
                    disposition="excluded",
                    exclusions=tuple(exclusions),
                    evidence=(f"pre 规则 {pre.rule_id} 命中，一次请求都没发",),
                    naive_would_say="朴素实现会把它算成一条死链",
                    position_class=position,
                )
            disposition = "needs_review"
            confidence = "needs_review"

    # ---- DNS：解析失败永远不是死链（resolve.R1–R4）--------------------- #
    host = (urlsplit(url).hostname or "").lower()
    dns: Resolution | None = None
    if resolver is not None and host:
        try:
            dns = resolver(host)
        except DnsFixtureMissing:
            dns = None

    if dns is not None and not denoise:
        # 朴素实现把「解析不出来」直接采信成死链 —— 实测就是这样误报了
        # pinterest 2 条与 platform.minimax.io 12 条。
        if not dns.ok:
            return LinkVerdict(
                url=url,
                state=LinkState.DEAD,
                reason="dns_unresolved",
                evidence=(f"DNS 无有效答案（resolver={dns.resolver}）",),
                position_class=position,
            )
    elif dns is not None:
        if dns.poisoned:
            return LinkVerdict(
                url=url,
                state=LinkState.UNKNOWN,
                reason="dns_poisoned",
                evidence=(f"DNS 返回本地/私有地址，判解析污染而非死链：{dns.error}",),
                position_class=position,
            )
        if _nxdomain_confirmed(dns):
            return LinkVerdict(
                url=url,
                state=LinkState.DEAD,
                reason="dns_unresolved",
                evidence=(f">=2 个 resolver NXDOMAIN：{dns.error}",),
                position_class=position,
                disposition=disposition,
                confidence=confidence,
                exclusions=tuple(exclusions),
            )
        if dns.resolver not in ("system", "none", ""):
            # 首个 resolver 失败、备用 resolver 有答案 -> pin 到该 IP 重试。
            # 实测：pinterest 2 条、cog.run、platform.minimax.io 12 条。
            rule_id = "dns_retry_second_resolver"

    # ---- 探测 ---------------------------------------------------------- #
    probe = _probe(url, fetcher=fetcher, client=client)
    spent += 1
    if probe is None:
        return LinkVerdict(
            url=url,
            state=LinkState.UNKNOWN,
            reason="not_fetched",
            rule_id=rule_id,
            disposition=disposition,
            confidence=confidence,
            exclusions=tuple(exclusions),
            evidence=("没有这条 URL 的冻结快照，本位置未评估（绝不回落真网络）",),
            position_class=position,
            requests_spent=spent,
        )
    resp = probe.response
    status = resp.status if resp is not None else 0
    final_url = resp.final_url if resp is not None else url
    from_fixture = store.has(url)

    # 朴素口径统一到 naive.naive_link_is_dead（§4.5:2463 逐字：**首跳** >= 400 判死，
    # 没有状态码就判不死）。本文件原先自己写了一份「最终状态 ∈ {404,410,0}」，
    # 两者在规格用来定义这条口径的那个例子上给出**相反答案**：
    # X07 unkey 308 -> 308 -> 404，按首跳是「活的」（朴素工具确实会漏掉它），
    # 按最终状态是「死链」。而 client.py 的模块 docstring 写得很清楚：
    # 「第一遍用 urllib 把 308 当终态，漏了定价页上的真死链」——
    # **漏掉正是朴素实现的特征**，所以首跳口径才是朴素基线的正确定义。
    # 两份口径并存等于朴素对照可以自己挑一个好看的答案。
    first_hop = resp.redirects[0].status if (resp is not None and resp.redirects) else status
    naive = "死链" if naive_link_is_dead(first_hop) else "活的"
    if not denoise:
        return LinkVerdict(
            url=url,
            state=LinkState.DEAD if naive == "死链" else LinkState.ALIVE,
            reason=probe.classification.reason,
            status=status,
            final_url=final_url,
            evidence=probe.classification.evidence,
            naive_would_say=naive,
            position_class=position,
            from_fixture=from_fixture,
            requests_spent=spent,
        )

    def _unknown(rid: str, why: str) -> LinkVerdict:
        return LinkVerdict(
            url=url,
            state=LinkState.UNKNOWN,
            reason=probe.classification.reason if probe is not None else "not_fetched",
            rule_id=rid,
            disposition=disposition,
            confidence=confidence,
            status=status,
            final_url=final_url,
            exclusions=tuple(exclusions),
            evidence=(why, *(probe.classification.evidence if probe is not None else ())),
            naive_would_say=naive,
            position_class=position,
            from_fixture=from_fixture,
            requests_spent=spent,
        )

    # ---- post：七条前置 + 两条归因规则 --------------------------------- #
    # ⚠️ 规格把七条前置写成一串（§5.3 is_dead 的 docstring），照那个顺序
    #    waf_challenge 排在 host_unprobeable / login_wall / upstream_error 前面，
    #    于是那三条永远轮不到（tenderly 的根路径、teachable 的 403、twitter 的
    #    520 都会先被 waf_challenge 吃掉）。它们的结论**全是 UNKNOWN，完全一样**，
    #    差别只在报告里写哪条理由，所以这里把更具体的排前面（见交付说明 deviations）。
    if _hostile_400(url, probe):
        return _unknown("hostile_400", f"HTTP 400 且 {host} 是已知对 bot 返回 400 的站点")

    confirmations: tuple[tuple[str, int], ...] = ()
    if status in (404, 410) or _is_challenge(probe):
        confirmations, extra = _collect_confirmations(
            url,
            candidates=confirmation_candidates,
            fetcher=fetcher,
            client=client,
            host_cache=host_cache,
        )
        spent += extra

    if _login_wall(url, probe, confirmations):
        return _unknown("login_wall", "host/path 是认证入口或跳转成环，且同 host 没有活着的兄弟")

    if _upstream_error(probe):
        return _unknown("upstream_error", f"HTTP {status}，上游错误不是内容不存在")

    kind = _transport_error_kind(resp.transport_error if resp is not None else None)
    if kind is not None:
        return _unknown(
            "network_timeout",
            f"传输层失败（{kind}），Fetcher 已退避重试 2 次仍失败，不判死",
        )

    if _is_challenge(probe):
        facts = _host_facts(url, fetcher=fetcher, client=client, cache=host_cache)
        path = urlsplit(url).path or "/"
        if facts.unprobeable and path in ("", "/"):
            # 归因给 host 级事实：这个 host 的根路径与随机路径都不可信，
            # 于是它上面**全部**链接 UNKNOWN。自动构造，不需要人工白名单。
            return _unknown("host_unprobeable", "根路径与随机路径都不可信，该 host 整体判不了")
        return _unknown("waf_challenge", "命中 WAF/挑战页指纹或拦截型状态码，被拦截 != 不存在")

    if _geo_redirect(url, probe, source_page=source_page):
        return _unknown("geo_redirect", "路径头被插入了源页没有的地区段之后才 404")

    facts = _host_facts(url, fetcher=fetcher, client=client, cache=host_cache)
    if status in (404, 410) and not confirmations and not facts.alive_urls:
        # 第三方 404 必须有同 host 存活对照才允许判死；拿不到 -> UNKNOWN，
        # **不重试、不伪装浏览器 UA**（crates.io/crates/helius 对工具 UA 404、
        # 浏览器 UA 200 —— 我们不去骗它）。
        return _unknown("third_party_no_control", "拿不到同 host 的存活对照，不允许判死")
    if facts.unprobeable:
        return _unknown("host_unprobeable", "根路径与随机路径都不可信，该 host 整体判不了")

    confirmations = confirmations or facts.alive_urls
    dead = is_dead(probe, facts.control, confirmations, exclusions, dns=dns)
    state = LinkState.DEAD if dead else LinkState.ALIVE
    return LinkVerdict(
        url=url,
        state=state,
        reason=probe.classification.reason,
        rule_id=rule_id,
        disposition=disposition,
        confidence=confidence,
        status=status,
        final_url=final_url,
        confirmations=confirmations,
        exclusions=tuple(exclusions),
        evidence=probe.classification.evidence,
        naive_would_say=naive,
        position_class=position,
        from_fixture=from_fixture,
        requests_spent=spent,
    )
