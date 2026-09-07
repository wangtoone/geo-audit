"""Discovery: from one domain to a SiteMap.

Design principle: **do not discover by crawling links.**

That is not a style preference, it is the brevo.com lesson.  brevo.com's apex
serves Vercel's plaintext ``DEPLOYMENT_NOT_FOUND`` on /, /pricing/ and /blog/
while www.brevo.com and developers.brevo.com are healthy -- and no page on the
site links to the bare domain, so a link-crawler can never reach the broken
surface.  Meanwhile 6 domains in the 72-domain run keep their real llms.txt on
a subdomain or a /docs/ subpath (minimax, moonshot, siliconflow, onfleet,
canvasmedical, ecwid), so probing only the root path misreads them as
"not adopted".

So discovery is **deterministic enumeration + first-party declarations**:

  1. apex/www bidirectional probe -- always, both directions.
  2. Candidate doc/support hosts from a fixed prefix list, DNS-gated.
  3. First-party declarations: robots.txt ``Sitemap:`` lines and absolute URLs
     inside llms.txt (moonshot's own docs banner declares
     ``https://platform.kimi.ai/docs/llms.txt`` -- a different registrable
     domain that no prefix list could reach).
  4. Fixed AI-path candidates per host.
  5. Pricing-page candidates, where "every candidate 404s" is a first-class
     outcome, not zero problems.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Final
from urllib.parse import urlsplit, urlunsplit

from ..models import (
    ApexWwwResult,
    DiscoveredHost,
    Expect,
    HostRole,
    Probe,
    RobotsInfo,
    SiteMap,
    Verdict,
)
from .client import Fetcher
from .ratelimit import registrable_domain
from .resolve import HostResolver, resolve_host

#: Every prefix here was earned by a real host in the 72-domain run:
#:   docs.        mistral, canvasmedical, turso, ecwid, pinecone, baseten, ...
#:   developers.  brevo, printify, printful, pipedrive, pinterest, mailerlite, swell
#:   developer.   close, bigcommerce, squareup
#:   dev.         hume (dev.hume.ai), wix (dev.wix.com)
#:   apidoc.      factorialhr (apidoc.factorialhr.com)
#:   api-docs.    ecwid (legacy, still the canonical URL in old articles)
#:   support.     copper, docketwise, freshbooks, goshippo
#:   help.        brevo, owner, canvasmedical, spoton
#:   supportcenter. mycase
#:   platform.    minimax (platform.minimax.io)
DOC_HOST_PREFIXES: tuple[tuple[str, HostRole], ...] = (
    ("docs", HostRole.DOCS),
    ("developers", HostRole.DOCS),
    ("developer", HostRole.DOCS),
    ("dev", HostRole.DOCS),
    ("doc", HostRole.DOCS),
    ("apidoc", HostRole.DOCS),
    ("api-docs", HostRole.DOCS),
    ("apidocs", HostRole.DOCS),
    ("api", HostRole.DOCS),
    ("reference", HostRole.DOCS),
    ("platform", HostRole.PLATFORM),
    ("support", HostRole.SUPPORT),
    ("help", HostRole.SUPPORT),
    ("supportcenter", HostRole.SUPPORT),
    ("learn", HostRole.DOCS),
    ("kb", HostRole.SUPPORT),
)

#: Root path only would misread 6 of 72 domains as "not adopted".
AI_PATH_CANDIDATES: tuple[str, ...] = (
    "/llms.txt",
    "/docs/llms.txt",
    "/llms-full.txt",
    "/docs/llms-full.txt",
    "/.well-known/llms.txt",
)

#: Ordered.  `/us/en/pricing` is squareup, `/plans` is wix.
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

SITEMAP_CANDIDATES: tuple[str, ...] = (
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
)

MAX_DECLARED_HOSTS = 3
MAX_SITEMAP_URLS = 20000

# --------------------------------------------------------------------------- #
# §3.7 的分层探测：tier 名、每层的路径、短路配对、请求预算
# --------------------------------------------------------------------------- #

#: 原型是「每个 live host × 5 条候选路径，无条件全探」，没有短路也没有预算。
#: 分层的收益是实测过的：tier2 的两条 ``/docs`` 只对根路径没拿到真文件的 host 补
#: （minimax / moonshot 的真文件正在那里），tier3 的 ``/.well-known/llms.txt``
#: 在 72 域实测 **0 命中**，所以排最后 —— 不为 0 收益烧速率预算。
TIER0: Final = "tier0"
TIER1: Final = "tier1"
TIER2: Final = "tier2"
TIER3: Final = "tier3"

#: 顺序即探测顺序。``discover(tiers=...)`` 只做子集筛选，改不了顺序 ——
#: 顺序本身是判据的一部分（先根路径、后 /docs、最后 .well-known）。
TIER_ORDER: tuple[str, ...] = (TIER0, TIER1, TIER2, TIER3)
DEFAULT_TIERS: tuple[str, ...] = TIER_ORDER

#: tier0（apex + www）与 tier1（文档/支持子域 + 站点自身声明的 host）的两条根路径。
ROOT_AI_PATHS: tuple[str, ...] = ("/llms.txt", "/llms-full.txt")
#: tier2：只对根路径没拿到真文件的 host 补这两条。
DOCS_AI_PATHS: tuple[str, ...] = ("/docs/llms.txt", "/docs/llms-full.txt")
#: tier3：只在该 host 前三层全空（没有任何 OK）时才探。
WELLKNOWN_AI_PATHS: tuple[str, ...] = ("/.well-known/llms.txt",)

AI_PATHS_BY_TIER: dict[str, tuple[str, ...]] = {
    TIER0: ROOT_AI_PATHS,
    TIER1: ROOT_AI_PATHS,
    TIER2: DOCS_AI_PATHS,
    TIER3: WELLKNOWN_AI_PATHS,
}

#: tier2 的短路配对：``/docs`` 那条 -> 它对应的根路径。根路径已判 OK 就不探
#: ``/docs`` 那条（§3.7 的短路条件），两条根路径都 OK 时整个 host 跳过。
TIER2_SHORTCUT: dict[str, str] = {
    "/docs/llms.txt": "/llms.txt",
    "/docs/llms-full.txt": "/llms-full.txt",
}

#: ``--max-requests`` 的默认值；0 = 不限。实测最大分母是 brevo（apex + www +
#: developers 三个 live host）25 个请求，默认 120 有 4.8 倍余量。
DEFAULT_REQUEST_BUDGET: Final = 120


class DiscoveryBudget:
    """发现层的请求记账（§3.7）。

    计入：host 根路径探测、AI 路径探测、定价页候选、对照探测。
    **不计入**：robots.txt、sitemap.xml、DNS 查询 —— 它们不是内容探测。

    两条与规格原文不同的实现细节（交付说明里逐条列了）：

    * **同一 URL 只计一次**。``Fetcher`` 自带 HTTP 缓存，重复 fetch 同一 URL
      不再出网；apex/www 的根路径在 ``probe_apex_and_www`` 与 tier0 里各探一次，
      按 URL 去重才是真实的网络开销。
    * **对照探测按 host 计一次**。``Fetcher.host_profile`` 按 host 缓存，一个
      host 一条对照探针；探针请求由 ``Fetcher`` 内部发出，发现层看不见它，
      所以在该 host 第一次被计费时一并记上。（软 404 复核时 ``_confirm_soft404``
      会再发一条 ``refresh`` 对照，这一条发现层无从观测，没有计入。）
    """

    def __init__(self, limit: int = DEFAULT_REQUEST_BUDGET) -> None:
        self.limit = limit
        self.spent = 0
        self.exhausted = False
        self.skipped: list[str] = []
        self._charged_urls: set[str] = set()
        self._charged_hosts: set[str] = set()

    @property
    def unlimited(self) -> bool:
        """``budget=0``（或负数）= 不限。"""
        return self.limit <= 0

    def exceeded(self) -> bool:
        """每层开始前调一次；True 就把该层剩余 URL 全记入 ``skipped``。"""
        return not self.unlimited and self.spent >= self.limit

    def charge(self, url: str) -> None:
        """记一次内容探测。"""
        if url in self._charged_urls:
            return
        self._charged_urls.add(url)
        self.spent += 1
        host = (urlsplit(url).hostname or "").lower()
        if host and host not in self._charged_hosts:
            self._charged_hosts.add(host)
            self.spent += 1  # 该 host 的对照探针

    def skip(self, urls: Iterable[str]) -> None:
        """预算耗尽：记下没探的 URL，置 ``exhausted``。

        这些 URL 在 pipeline 里生成 ``Status.UNKNOWN(not_fetched)`` 的 Position，
        **绝不当成「没有这个文件」** —— 那正是本工具存在的理由的反面。
        """
        self.exhausted = True
        for url in urls:
            if url not in self.skipped:
                self.skipped.append(url)


_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_SITEMAP_TAG_RE = re.compile(r"<sitemapindex", re.I)
_ABS_URL_RE = re.compile(r"https?://[\w.-]+(?:/[^\s)\"'<>]*)?")


def normalize_input_domain(raw: str) -> tuple[str, str]:
    """Accept anything a human types; return (apex_host, www_host).

    Handles "brevo.com", "https://www.brevo.com/pricing", "WWW.Brevo.com/".
    """
    s = raw.strip()
    if "//" not in s:
        s = "https://" + s
    host = (urlsplit(s).hostname or "").lower().strip(".")
    if not host:
        raise ValueError(f"无法从 {raw!r} 解析出域名")
    apex = host[4:] if host.startswith("www.") else host
    return apex, f"www.{apex}"


def probe_apex_and_www(
    fetcher: Fetcher, apex: str, www: str, *, budget: DiscoveryBudget | None = None
) -> ApexWwwResult:
    """Bidirectional reachability probe.  Runs unconditionally.

    Anchor: brevo.com apex returns Vercel's plaintext ``DEPLOYMENT_NOT_FOUND``
    on /, /pricing/ and /blog/ while www + developers are healthy.  The
    classifier's ``platform_deployment_missing`` rule turns that into a
    SOFT404 rather than an OK-200, which is the whole point.

    ``evidence_strength`` stays "single_case" until release gate #3 (144 probes
    across the 72 domains) is run.  Report renderers must keep single_case
    findings out of the headline count -- n=1 does not get to drive a number
    on page one.
    """
    apex_url, www_url = f"https://{apex}/", f"https://{www}/"
    if budget is not None:
        budget.charge(apex_url)
        budget.charge(www_url)
    apex_probe = fetcher.probe(apex_url, expect=Expect.HTML_PAGE)
    www_probe = fetcher.probe(www_url, expect=Expect.HTML_PAGE)

    def dead(p: Probe) -> bool:
        return p.verdict in (Verdict.REAL404, Verdict.SOFT404)

    def usable(p: Probe) -> bool:
        return p.verdict is Verdict.OK

    if usable(apex_probe) and usable(www_probe):
        outcome = "both_ok"
    elif dead(apex_probe) and usable(www_probe):
        outcome = "apex_dead"
    elif usable(apex_probe) and dead(www_probe):
        outcome = "www_dead"
    elif dead(apex_probe) and dead(www_probe):
        outcome = "both_dead"
    else:
        outcome = "undetermined"  # blocked / unknown on either side

    return ApexWwwResult(apex, www, apex_probe, www_probe, outcome)


def enumerate_doc_hosts(apex: str) -> list[tuple[str, HostRole]]:
    return [(f"{prefix}.{apex}", role) for prefix, role in DOC_HOST_PREFIXES]


def mine_declared_hosts(bodies: list[str], *, apex: str) -> list[str]:
    """Pull doc hosts out of first-party declarations.

    Needed because some doc sites live on a completely different registrable
    domain: moonshot.ai's own docs pages carry the banner
    "Fetch the complete documentation index at:
    https://platform.kimi.ai/docs/llms.txt".  No prefix list reaches
    ``platform.kimi.ai`` from ``moonshot.ai``.

    Only hosts appearing at least twice are accepted, and at most
    MAX_DECLARED_HOSTS are returned, so a stray link in a changelog cannot
    drag the audit onto someone else's property.
    """
    counts: dict[str, int] = {}
    for body in bodies:
        for m in _ABS_URL_RE.finditer(body[:200000]):
            host = (urlsplit(m.group(0)).hostname or "").lower()
            if not host or host == apex or host.endswith("." + apex):
                continue
            if any(
                host == s or host.endswith("." + s)
                for s in (
                    "github.com",
                    "x.com",
                    "twitter.com",
                    "linkedin.com",
                    "youtube.com",
                    "facebook.com",
                    "npmjs.com",
                    "pypi.org",
                )
            ):
                continue
            if not re.match(r"^(docs?|developers?|api|apidocs?|platform|help|support)\.", host):
                continue
            counts[host] = counts.get(host, 0) + 1
    ranked = sorted((h for h, c in counts.items() if c >= 2), key=lambda h: -counts[h])
    return ranked[:MAX_DECLARED_HOSTS]


def fetch_sitemap_urls(
    fetcher: Fetcher, host: str, robots_sitemaps: tuple[str, ...]
) -> tuple[str, ...]:
    """robots.txt Sitemap: lines first, then the conventional filenames.

    One level of <sitemapindex> is followed (5 children max).  Used by the
    dead-link check to find content pages without crawling, and to produce a
    fix hint rather than a bare "404": the tdengine case is exactly this --
    docs.tdengine.com/sitemap.xml carries the NEW connector paths while the
    homepage still points at the old ones, so the tool can say
    "改成 /developer-guide/connectors-reference/*" instead of "8 条 404".
    """
    candidates = list(robots_sitemaps) or [
        urlunsplit(("https", host, p, "", "")) for p in SITEMAP_CANDIDATES
    ]
    urls: list[str] = []
    children_followed = 0

    for cand in candidates[:5]:
        resp = fetcher.fetch(cand, expect=Expect.TEXT_FILE)
        if resp.status != 200:
            continue
        text = resp.text
        locs = _LOC_RE.findall(text)
        if _SITEMAP_TAG_RE.search(text[:2000]):
            for child in locs[:5]:
                if children_followed >= 5:
                    break
                children_followed += 1
                sub = fetcher.fetch(child, expect=Expect.TEXT_FILE)
                if sub.status == 200:
                    urls.extend(_LOC_RE.findall(sub.text))
        else:
            urls.extend(locs)
        if len(urls) >= MAX_SITEMAP_URLS:
            break

    return tuple(dict.fromkeys(urls))[:MAX_SITEMAP_URLS]


def pricing_candidate_urls(host: str) -> tuple[str, ...]:
    """``PRICING_CANDIDATES`` 在一个 host 上展开成的完整 URL 列表（预算记账用）。"""
    return tuple(urlunsplit(("https", host, path, "", "")) for path in PRICING_CANDIDATES)


def find_pricing_page(
    fetcher: Fetcher, host: str, *, budget: DiscoveryBudget | None = None
) -> tuple[str | None, tuple[tuple[str, Verdict], ...]]:
    """First candidate that classifies OK, else None.

    None means "no pricing page found", which is a real state and must never
    be rendered as "pricing is fine": ``www.voyageai.com/pricing`` is a
    genuine 404, and treating that as a clean result is how a tool reports 0
    on a domain it never examined.

    The pricing URL matters to v1 even though the fact-conflict check was cut:
    the dead-link check weights severity by position, and "定价页上的 CTA" is
    the top tier -- saleor's three "Talk to us" buttons on /pricing all point
    at a 404, which was the highest-commercial-impact finding in the run.
    """
    tried: list[tuple[str, Verdict]] = []
    for url in pricing_candidate_urls(host):
        if budget is not None:
            budget.charge(url)
        p = fetcher.probe(url, expect=Expect.HTML_PAGE)
        tried.append((url, p.verdict))
        if p.verdict is Verdict.OK:
            return url, tuple(tried)
    return None, tuple(tried)


def ai_path_urls(host: str, paths: Sequence[str]) -> tuple[str, ...]:
    """一个 host 上一组 AI 路径展开成的完整 URL（预算记账与 skip 清单都用它）。"""
    return tuple(urlunsplit(("https", host, path, "", "")) for path in paths)


def probe_ai_paths(
    fetcher: Fetcher,
    host: str,
    paths: Sequence[str],
    *,
    budget: DiscoveryBudget | None = None,
) -> tuple[Probe, ...]:
    """对一个 host 探一组 AI 路径。

    ⚠️ 卡点 S1：AI 路径探测**一律** ``Expect.TEXT_FILE``。改成 ``HTML_PAGE``
    会废掉抓 15/16 软 404 的主力规则 L2(a)（``html_where_text_expected``）——
    「期望文本文件却拿到 HTML」这条判据本身就是由 expect 决定的。需要
    ``identical_to_control`` 那条证据时从 ``Classification.secondary_reasons`` 取。
    """
    probes: list[Probe] = []
    for url in ai_path_urls(host, paths):
        if budget is not None:
            budget.charge(url)
        probes.append(fetcher.probe(url, expect=Expect.TEXT_FILE))
    return tuple(probes)


def probe_host_root(
    fetcher: Fetcher,
    host: str,
    role: HostRole,
    *,
    resolver: HostResolver | None = None,
    budget: DiscoveryBudget | None = None,
) -> tuple[DiscoveredHost, Probe | None]:
    """DNS 先行、再探根路径。返回 ``(DiscoveredHost, 根路径 Probe 或 None)``。

    DNS 不通时返回的 Probe 是 None，且**一个 HTTP 请求都不花** —— 「不存在的
    子域花 0 个请求」这条正是 16 个前缀枚举得以廉价的原因。DNS 失败判
    ``UNKNOWN``（``dns_unresolved`` / ``dns_poisoned``），**绝不判死**：
    platform.minimax.io 一次并发跑出过 12 条假 DNS 失败，25 秒后重试全部 200。

    ``resolver`` 一路从 ``discover()`` 传进来，``GEO_AUDIT_FORBID_DNS=1`` 下
    没注入就由 ``resolve_host`` 抛 AssertionError，不会静默回落真 DNS。
    """
    resolution = resolve_host(host, resolver=resolver)
    if not resolution.ok:
        return (
            DiscoveredHost(
                host,
                role,
                reachable=False,
                verdict=Verdict.UNKNOWN,
                reason="dns_poisoned" if resolution.poisoned else "dns_unresolved",
                evidence=(f"DNS 无有效记录（已过 8.8.8.8 / 1.1.1.1 复测）：{resolution.error}",),
            ),
            None,
        )
    url = f"https://{host}/"
    if budget is not None:
        budget.charge(url)
    root = fetcher.probe(url, expect=Expect.HTML_PAGE)
    return (
        DiscoveredHost(
            host,
            role,
            reachable=root.verdict is Verdict.OK,
            verdict=root.verdict,
            reason=root.classification.reason,
            resolved_ips=resolution.addresses,
            evidence=root.classification.evidence,
        ),
        root,
    )


def host_is_live(root: Probe) -> bool:
    """WAF 第三状态：``BLOCKED`` 的 host 留在探测集里，**不判死、不丢弃**。

    gusto.com（Cloudflare 403 挑战页）与 www.pipedrive.com（429）背后都是真
    llms.txt。把它们丢掉就是「软 404 让采纳率虚高」的反向孪生错误 —— 虚低。
    """
    return root.verdict in (Verdict.OK, Verdict.BLOCKED)


def _resolvable(hosts: Iterable[tuple[str, HostRole]], resolver: HostResolver | None) -> list[str]:
    """预算耗尽时列 skip 清单用：只列 DNS 通得过的 host。

    DNS 不计入预算，所以这一步是免费的；而把不存在的子域写进
    ``skipped_by_budget`` 会在报告里凭空造出「这个位置没看」的 UNKNOWN 格。
    """
    return [h for h, _role in hosts if resolve_host(h, resolver=resolver).ok]


def discover(
    fetcher: Fetcher,
    raw_domain: str,
    *,
    include_apex_check: bool = True,
    tiers: tuple[str, ...] = DEFAULT_TIERS,
    wellknown: bool = True,
    budget: int = DEFAULT_REQUEST_BUDGET,
    resolver: HostResolver | None = None,
) -> SiteMap:
    """分层探测，每层结束（下一层开始前）检查预算。

    tier0  apex + www × {/llms.txt, /llms-full.txt}
    tier1  16 个文档/支持子域前缀（先过 DNS）× 同两条路径
           + ``mine_declared_hosts()`` 挖出的最多 3 个外部声明 host
    tier2  **只对 tier0/tier1 里根路径没拿到真文件的 host** 补
           {/docs/llms.txt, /docs/llms-full.txt}
           ← 短路条件：该 host 的 /llms.txt 已判 OK 就不探 /docs/llms.txt
             （minimax / moonshot 的真文件在这层）
    tier3  /.well-known/llms.txt，**只在该 host 前三层全空（无任何 OK）时才探**
           ← 72 域实测 0 命中，排最后

    参数：

    ``tiers``      要跑哪几层（子集筛选，顺序恒为 :data:`TIER_ORDER`）。
    ``wellknown``  ``--no-wellknown -> False``，等价去掉 tier3。
    ``budget``     ``--max-requests``；0 = 不限。记账口径见 :class:`DiscoveryBudget`。
    ``resolver``   §3.6 的 DNS 注入点，一路传给 ``resolve_host``。

    预算耗尽时：该层剩余 URL 全部记入 ``skipped_by_budget``、置
    ``budget_exhausted=True``，后续层不再发请求。被跳过的 URL 在 pipeline 里
    生成 ``Status.UNKNOWN(not_fetched)`` 的 Position，**绝不当成「没有这个文件」**。
    """
    apex, www = normalize_input_domain(raw_domain)
    reg = registrable_domain(apex)
    acct = DiscoveryBudget(budget)
    active = tuple(t for t in TIER_ORDER if t in tiers and (t != TIER3 or wellknown))

    # 裁决 #12：apex/www 双向探测无条件跑（``include_apex_check`` 只给调用方留
    # 关掉的口子），结果落 Report.apex_www，不进 findings、不进首页计数。
    apex_www = probe_apex_and_www(fetcher, apex, www, budget=acct) if include_apex_check else None

    hosts: list[DiscoveredHost] = []
    seen_hosts: set[str] = set()
    live_hosts: list[str] = []
    ai_probes: list[Probe] = []
    #: host -> 已经拿到真文件（OK）的路径集合，tier2/tier3 的短路判据
    ok_paths: dict[str, set[str]] = {}
    #: 拿到过正文的响应，喂 ``mine_declared_hosts``
    bodies: list[str] = []
    tiers_run: list[str] = []

    def record(probes: Iterable[Probe]) -> None:
        for probe in probes:
            ai_probes.append(probe)
            if probe.response is not None and probe.response.body:
                bodies.append(probe.response.text)
            if probe.verdict is Verdict.OK:
                host = (urlsplit(probe.url).hostname or "").lower()
                ok_paths.setdefault(host, set()).add(urlsplit(probe.url).path or "/")

    def run_root_tier(candidates: list[tuple[str, HostRole]]) -> None:
        for host, role in candidates:
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            discovered, root = probe_host_root(fetcher, host, role, resolver=resolver, budget=acct)
            hosts.append(discovered)
            if root is None:
                continue
            if root.response is not None and root.response.body:
                bodies.append(root.response.text)
            if host_is_live(root):
                live_hosts.append(host)
                record(probe_ai_paths(fetcher, host, ROOT_AI_PATHS, budget=acct))

    for tier in active:
        candidates: list[tuple[str, HostRole]] = []
        if tier == TIER0:
            candidates = [(apex, HostRole.APEX), (www, HostRole.WWW)]
        elif tier == TIER1:
            # 站点自身声明：moonshot.ai 的文档站在 platform.kimi.ai —— 完全不同的
            # 注册域，任何前缀枚举都到不了，只能靠它自己写出来的那条横幅。
            declared = [
                (h, HostRole.DECLARED)
                for h in mine_declared_hosts(bodies, apex=apex)
                if h not in seen_hosts
            ]
            candidates = [*enumerate_doc_hosts(apex), *declared]

        if tier in (TIER0, TIER1):
            if acct.exceeded():
                planned = [
                    url
                    for host in _resolvable(candidates, resolver)
                    for url in (f"https://{host}/", *ai_path_urls(host, ROOT_AI_PATHS))
                ]
                acct.skip(planned)
                continue
            tiers_run.append(tier)
            run_root_tier(candidates)
            continue

        # tier2 / tier3：只在已经 live 的 host 上补路径，且逐条过短路条件
        todo: list[tuple[str, tuple[str, ...]]] = []
        for host in live_hosts:
            found = ok_paths.get(host, set())
            if tier == TIER2:
                paths = tuple(path for path in DOCS_AI_PATHS if TIER2_SHORTCUT[path] not in found)
            else:  # tier3：前三层全空才探
                paths = () if found else WELLKNOWN_AI_PATHS
            if paths:
                todo.append((host, paths))
        if not todo:
            continue
        if acct.exceeded():
            acct.skip([url for host, paths in todo for url in ai_path_urls(host, paths)])
            continue
        tiers_run.append(tier)
        for host, paths in todo:
            record(probe_ai_paths(fetcher, host, paths, budget=acct))

    # robots.txt 与 sitemap.xml 不计入预算（不是内容探测），但 C1 需要它们。
    robots: dict[str, RobotsInfo] = {h: fetcher.robots_for(f"https://{h}/") for h in live_hosts}
    sitemaps = {h: fetch_sitemap_urls(fetcher, h, robots[h].sitemaps) for h in live_hosts}

    marketing_host = www if any(x.host == www and x.reachable for x in hosts) else apex
    if acct.exceeded():
        # 定价页找不到与「没探定价页」是两种状态，后者必须写进 skip 清单，
        # 否则报告会把「没看」渲染成「定价页没问题」。
        acct.skip(pricing_candidate_urls(marketing_host))
        pricing_url: str | None = None
        pricing_tried: tuple[tuple[str, Verdict], ...] = ()
    else:
        pricing_url, pricing_tried = find_pricing_page(fetcher, marketing_host, budget=acct)

    return SiteMap(
        input_domain=raw_domain,
        registrable_domain=reg,
        hosts=tuple(hosts),
        apex_www=apex_www,
        sitemap_urls=sitemaps,
        pricing_url=pricing_url,
        pricing_candidates_tried=pricing_tried,
        ai_path_probes=tuple(ai_probes),
        robots=robots,
        tiers_run=tuple(tiers_run),
        requests_spent=acct.spent,
        budget_exhausted=acct.exhausted,
        skipped_by_budget=tuple(acct.skipped),
    )
