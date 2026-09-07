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
from urllib.parse import urlsplit, urlunsplit

from .client import Fetcher
from .models import (
    ApexWwwResult,
    DiscoveredHost,
    Expect,
    HostRole,
    Probe,
    SiteMap,
    Verdict,
)
from .ratelimit import registrable_domain
from .resolve import resolve_host

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


def probe_apex_and_www(fetcher: Fetcher, apex: str, www: str) -> ApexWwwResult:
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
    apex_probe = fetcher.probe(f"https://{apex}/", expect=Expect.HTML_PAGE)
    www_probe = fetcher.probe(f"https://{www}/", expect=Expect.HTML_PAGE)

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
                for s in ("github.com", "x.com", "twitter.com", "linkedin.com",
                          "youtube.com", "facebook.com", "npmjs.com", "pypi.org")
            ):
                continue
            if not re.match(r"^(docs?|developers?|api|apidocs?|platform|help|support)\.", host):
                continue
            counts[host] = counts.get(host, 0) + 1
    ranked = sorted((h for h, c in counts.items() if c >= 2), key=lambda h: -counts[h])
    return ranked[:MAX_DECLARED_HOSTS]


def fetch_sitemap_urls(fetcher: Fetcher, host: str, robots_sitemaps: tuple[str, ...]) -> tuple[str, ...]:
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


def find_pricing_page(fetcher: Fetcher, host: str) -> tuple[str | None, tuple[tuple[str, Verdict], ...]]:
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
    for path in PRICING_CANDIDATES:
        url = urlunsplit(("https", host, path, "", ""))
        p = fetcher.probe(url, expect=Expect.HTML_PAGE)
        tried.append((url, p.verdict))
        if p.verdict is Verdict.OK:
            return url, tuple(tried)
    return None, tuple(tried)


def discover(fetcher: Fetcher, raw_domain: str, *, include_apex_check: bool = True) -> SiteMap:
    """Full discovery for one input domain.

    Request budget on a typical domain: 2 (apex/www) + 2-4 host probes
    (DNS-gated, so nonexistent subdomains cost 0 HTTP) + 1 robots + 1 sitemap
    + 5 AI paths per live host + <=9 pricing candidates.  ~25-40 requests,
    i.e. 50-80 s at the 2 s floor.
    """
    apex, www = normalize_input_domain(raw_domain)
    reg = registrable_domain(apex)

    apex_www = probe_apex_and_www(fetcher, apex, www) if include_apex_check else None

    hosts: list[DiscoveredHost] = []
    live_hosts: list[str] = []

    for host, role in [(apex, HostRole.APEX), (www, HostRole.WWW), *enumerate_doc_hosts(apex)]:
        resolution = resolve_host(host)
        if not resolution.ok:
            # DNS-gated: a nonexistent subdomain costs zero HTTP requests and
            # zero rate-limit budget.  resolve_host already escalated to
            # 8.8.8.8 / 1.1.1.1, so a negative here is trustworthy.
            hosts.append(
                DiscoveredHost(
                    host, role, reachable=False,
                    verdict=Verdict.UNKNOWN,
                    reason="dns_poisoned" if resolution.poisoned else "dns_unresolved",
                    evidence=(f"DNS 无有效记录（已过 8.8.8.8 / 1.1.1.1 复测）：{resolution.error}",),
                )
            )
            continue
        root = fetcher.probe(f"https://{host}/", expect=Expect.HTML_PAGE)
        hosts.append(
            DiscoveredHost(
                host, role, reachable=root.verdict is Verdict.OK,
                verdict=root.verdict, reason=root.classification.reason,
                resolved_ips=resolution.addresses,
                evidence=root.classification.evidence,
            )
        )
        if root.verdict in (Verdict.OK, Verdict.BLOCKED):
            # BLOCKED hosts stay in the list: gusto.com and www.pipedrive.com
            # serve real llms.txt files behind a WAF, and dropping them would
            # under-report adoption (the reverse twin of the soft-404 error).
            live_hosts.append(host)

    # AI-path probes across every live host.
    ai_probes: list[Probe] = []
    bodies_for_mining: list[str] = []
    for host in live_hosts:
        for path in AI_PATH_CANDIDATES:
            url = urlunsplit(("https", host, path, "", ""))
            p = fetcher.probe(url, expect=Expect.TEXT_FILE)
            ai_probes.append(p)
            if p.verdict is Verdict.OK and p.response is not None:
                bodies_for_mining.append(p.response.text)

    # First-party declarations may point at a doc host on another domain.
    for extra in mine_declared_hosts(bodies_for_mining, apex=apex):
        if extra in live_hosts:
            continue
        resolution = resolve_host(extra)
        if not resolution.ok:
            continue
        root = fetcher.probe(f"https://{extra}/", expect=Expect.HTML_PAGE)
        hosts.append(
            DiscoveredHost(extra, HostRole.DECLARED, root.verdict is Verdict.OK,
                           root.verdict, root.classification.reason,
                           resolution.addresses,
                           ("由站点自身声明（llms.txt / 文档横幅）发现",))
        )
        if root.verdict is Verdict.OK:
            for path in AI_PATH_CANDIDATES:
                ai_probes.append(
                    fetcher.probe(urlunsplit(("https", extra, path, "", "")),
                                  expect=Expect.TEXT_FILE)
                )

    robots = {h: fetcher.robots_for(f"https://{h}/") for h in live_hosts}
    sitemaps = {
        h: fetch_sitemap_urls(fetcher, h, robots[h].sitemaps) for h in live_hosts
    }

    marketing_host = www if any(x.host == www and x.reachable for x in hosts) else apex
    pricing_url, pricing_tried = find_pricing_page(fetcher, marketing_host)

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
    )
