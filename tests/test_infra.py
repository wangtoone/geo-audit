"""Tests for rate limiting, DNS guards, cache, de-noise and discovery.

No network access: every test either exercises pure logic or drives the
Fetcher through a stub transport.
"""

from __future__ import annotations

import time

import httpx
import pytest

from geo_audit.fetch import fingerprints as fp
from geo_audit.fetch.cache import CachePolicy, HttpCache, TTL_DEFINITIVE, TTL_INDETERMINATE
from geo_audit.fetch.client import Fetcher, FetcherConfig, build_user_agent
from geo_audit.fetch.denoise import (
    LinkContext,
    SEVERITY_FOOTER_SOCIAL,
    SEVERITY_SALES_PATH,
    SEVERITY_TUTORIAL_EXIT,
    classify_link_eligibility,
    root_cause_id,
    severity_of,
)
from geo_audit.fetch.discovery import (
    AI_PATH_CANDIDATES,
    DOC_HOST_PREFIXES,
    PRICING_CANDIDATES,
    mine_declared_hosts,
    normalize_input_domain,
)
from geo_audit.fetch.models import Expect, HostProfile, HttpResponse, Verdict
from geo_audit.fetch.normalize import normalize_body, structural_fingerprint
from geo_audit.fetch.ratelimit import (
    MIN_INTERVAL_SECONDS,
    DomainLimiter,
    registrable_domain,
)
from geo_audit.fetch.resolve import _is_bogus

CONTACT = "audit@example.org"


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host,expected",
    [
        ("docs.mistral.ai", "mistral.ai"),
        ("platform.kimi.ai", "kimi.ai"),
        ("www.moonshot.ai", "moonshot.ai"),
        ("ed.link", "ed.link"),
        ("www.voyageai.com", "voyageai.com"),
        ("support.goshippo.com", "goshippo.com"),
        ("developers.brevo.com", "brevo.com"),
        ("brevo.com", "brevo.com"),
        ("api-docs.ecwid.com", "ecwid.com"),
        ("supportcenter.mycase.com", "mycase.com"),
        # readme.io is a hosting suffix, so each tenant is its own site and
        # must get its own bucket.  Observed: pipedrive.readme.io.
        ("pipedrive.readme.io", "pipedrive.readme.io"),
        # so is zendesk.com: support.goshippo.com is Zendesk-hosted on the
        # customer's own domain, but foo.zendesk.com is a tenant.
        ("brevo.zendesk.com", "brevo.zendesk.com"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


def test_apex_and_docs_subdomain_share_one_bucket() -> None:
    """合规口径是「单域 ≤1 请求/2 秒」，apex/www/docs 不能各自跑满。"""
    assert registrable_domain("brevo.com") == registrable_domain("developers.brevo.com")


def test_limiter_enforces_two_second_floor() -> None:
    limiter = DomainLimiter()
    t0 = time.monotonic()
    with limiter.hold("docs.mistral.ai"):
        pass
    with limiter.hold("www.mistral.ai"):  # same registrable domain
        pass
    assert time.monotonic() - t0 >= MIN_INTERVAL_SECONDS - 0.05


def test_limiter_does_not_serialize_across_domains() -> None:
    limiter = DomainLimiter()
    t0 = time.monotonic()
    with limiter.hold("a.example"):
        pass
    with limiter.hold("b.example"):
        pass
    assert time.monotonic() - t0 < 0.5


def test_interval_below_floor_is_rejected() -> None:
    with pytest.raises(ValueError):
        DomainLimiter(0.5)


def test_throttle_doubles_and_honours_retry_after() -> None:
    """pipedrive 的 429 是必须处理的真实场景。"""
    limiter = DomainLimiter()
    wait = limiter.note_throttled("www.pipedrive.com", retry_after="60")
    assert wait >= 60
    assert limiter.stats()["pipedrive.com"]["interval"] == 4.0
    limiter.note_throttled("www.pipedrive.com")
    assert limiter.stats()["pipedrive.com"]["interval"] == 8.0


def test_crawl_delay_only_ever_tightens() -> None:
    limiter = DomainLimiter()
    limiter.set_crawl_delay("example.com", 0.5)
    assert limiter.stats()["example.com"]["interval"] == MIN_INTERVAL_SECONDS
    limiter.set_crawl_delay("example.com", 10.0)
    assert limiter.stats()["example.com"]["interval"] == 10.0


# --------------------------------------------------------------------------- #
# DNS guards
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "addr,bogus",
    [
        ("127.0.0.1", True),   # www.talkie-ai.com 的实测形态：本机解析到 127.0.0.1
        ("0.0.0.0", True),
        ("10.0.0.5", True),
        ("192.168.1.1", True),
        ("169.254.1.1", True),
        ("104.18.17.10", False),  # cog.run 在 8.8.8.8 上的真实 A 记录
        ("8.8.8.8", False),
        ("not-an-ip", True),
    ],
)
def test_bogus_address_detection(addr: str, bogus: bool) -> None:
    assert _is_bogus(addr) is bogus


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #


def test_cache_roundtrip(tmp_path) -> None:
    cache = HttpCache(tmp_path / "c.sqlite3", ua_profile="ua-1")
    resp = HttpResponse(
        url="https://docs.mistral.ai/llms.txt",
        final_url="https://docs.mistral.ai/llms.txt",
        status=200,
        headers={"content-type": "text/plain"},
        body=b"# Mistral\n",
    )
    cache.put(resp, accept="text/plain")
    got = cache.get("GET", resp.url, "text/plain")
    assert got is not None and got.from_cache and got.body == b"# Mistral\n"


def test_cache_key_includes_ua_profile(tmp_path) -> None:
    """换 UA 会改变 WAF 行为，旧 UA 下的响应不能当替代品。"""
    path = tmp_path / "c.sqlite3"
    a = HttpCache(path, ua_profile="ua-1")
    b = HttpCache(path, ua_profile="ua-2")
    resp = HttpResponse(url="https://gusto.com/llms.txt", final_url="https://gusto.com/llms.txt",
                        status=200, headers={}, body=b"x")
    a.put(resp, accept="text/plain")
    assert a.get("GET", resp.url, "text/plain") is not None
    assert b.get("GET", resp.url, "text/plain") is None


def test_blocked_and_5xx_get_the_short_ttl() -> None:
    """判不了的结果只缓存 15 分钟，否则会把一个假零冻在报告里。"""
    assert HttpCache.ttl_for(200, None) == TTL_DEFINITIVE
    assert HttpCache.ttl_for(404, None) == TTL_DEFINITIVE
    assert HttpCache.ttl_for(308, None) == TTL_DEFINITIVE
    assert HttpCache.ttl_for(403, None) == TTL_INDETERMINATE
    assert HttpCache.ttl_for(429, None) == TTL_INDETERMINATE
    assert HttpCache.ttl_for(500, None) == TTL_INDETERMINATE
    assert HttpCache.ttl_for(0, "timeout") == TTL_INDETERMINATE


def test_expired_entry_is_not_served(tmp_path) -> None:
    cache = HttpCache(tmp_path / "c.sqlite3")
    stale = HttpResponse(url="https://x.example/a", final_url="https://x.example/a",
                         status=403, headers={}, body=b"", fetched_at=time.time() - 3600)
    cache.put(stale, accept="*/*")
    assert cache.get("GET", stale.url, "*/*") is None


def test_host_profile_roundtrip(tmp_path) -> None:
    cache = HttpCache(tmp_path / "c.sqlite3")
    body = "<html><head><title>MiniMax</title></head><body>" + "<div class='sk'>x</div>" * 60 + "</body></html>"
    norm = normalize_body(body)
    sha, tags = structural_fingerprint(body)
    prof = HostProfile(
        host="www.minimax.io", probe_url="https://www.minimax.io/geo-audit-probe-1.txt",
        status=200, content_type="text/html", norm_sha256="deadbeef", norm_len=len(norm),
        norm_body_prefix=norm, struct_sha256=sha, struct_tags=tags,
        final_path="/geo-audit-probe-1.txt", status_discriminates=False,
        control_is_html=True, usable=True,
        probed_at=time.time(),
    )
    cache.put_profile(prof)
    got = cache.get_profile("www.minimax.io")
    assert got is not None
    assert got.struct_sha256 == sha and got.struct_tags == tags
    assert got.status_discriminates is False and got.control_is_html is True
    assert got.usable is True


def test_read_only_policy_never_writes(tmp_path) -> None:
    cache = HttpCache(tmp_path / "c.sqlite3", policy=CachePolicy(read=True, write=False))
    resp = HttpResponse(url="https://x.example/b", final_url="https://x.example/b",
                        status=200, headers={}, body=b"y")
    cache.put(resp, accept="*/*")
    assert cache.get("GET", resp.url, "*/*") is None


# --------------------------------------------------------------------------- #
# De-noise
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url,rule",
    [
        ("https://docs.gusto.com/cdn-cgi/l/email-protection", "cloudflare_email_protection"),
        ("https://docs.attio.com/base-ui-disable-scrollbar", "mintlify_injected_anchor"),
        ("https://developers.brevo.com/fern-scroll-area-viewport", "fern_injected_anchor"),
        ("https://app.buildwithfern.com", "fern_console_host"),
        ("https://117340892.intellimizeio.com", "intellimize_endpoint"),
        ("https://example.com/foo", "reserved_example_domain"),
        ("https://www.teachable.com/blog/{year}/post", "url_template_placeholder"),
        ("https://api.sendinblue.com/v3/emailCampaigns/%7BtemplateID%7D/sharedUrl",
         "url_template_placeholder"),
        ("mailto:hi@example.org", "non_http_scheme"),
    ],
)
def test_known_false_positive_sources_are_excluded(url: str, rule: str) -> None:
    """实测的假阳性来源，逐条对应。去噪前 40.5%，去噪后 0%。"""
    ex = classify_link_eligibility(url)
    assert ex is not None, f"{url} 应被排除（规则 {rule}）"
    assert ex.rule_id == rule


@pytest.mark.parametrize(
    "url",
    [
        # 全部是实测确认的真死链，一条都不能被去噪规则吃掉
        "https://docs.tdengine.com/reference/connector/java/",
        "https://www.bytebase.com/introduction/what-is-bytebase",
        "https://saleor.io/cloud/talk-to-us?cta=See+how+Saleor+fits&cta_page=%2F",
        "https://saleor.io/cloud/pricing-page?cta=Talk+to+us&cta_page=%2Fpricing",
        "https://unkey.com/docs/platform/workspaces/billing",
        "https://developers.brevo.com/docs/api-clients/python",
        "https://www.swell.is/help/integrations/hubspot",
        "https://replicatestatus.com/feed",
        "https://docs.canvasmedical.com/sdk/canvas-cli/",
        "https://www.linkedin.com/https://www.linkedin.com/company/copper-inc/",
    ],
)
def test_real_dead_links_survive_denoise(url: str) -> None:
    assert classify_link_eligibility(url) is None, f"{url} 被去噪规则误吃"


def test_api_path_needs_code_context() -> None:
    """「API base URL」原写法无法落地，改写成路径形状 + 代码语境双条件。"""
    url = "https://enterprise.printful.com/api/pfy/public/v1/"
    assert classify_link_eligibility(url, LinkContext(source_page="p")) is None
    ex = classify_link_eligibility(
        url,
        LinkContext(source_page="p", surrounding_html="<pre><code>curl -X GET " + url + "</code></pre>"),
    )
    assert ex is not None and ex.rule_id == "api_endpoint_in_code_context"


def test_api_reference_page_is_not_excluded() -> None:
    """/api/reference/... 这类正常文档页不能因为路径含 api 就被排除。"""
    assert (
        classify_link_eligibility(
            "https://resend.com/docs/api-reference/emails/send-email",
            LinkContext(source_page="p", anchor_text="Send email", surrounding_html="<p>see the guide</p>"),
        )
        is None
    )


def test_inline_display_none_only_and_flagged_single_case() -> None:
    """收窄后的不可见锚点规则：只认内联 style，且标注单例来源。"""
    ex = classify_link_eligibility(
        "https://printify.com/wp-content/uploads/2024/12/Printify-Inc.-IRS-Form-8937.pdf",
        LinkContext(source_page="https://printify.com/",
                    anchor_html='<a style="display:none" href="...">IRS Form 8937</a>'),
    )
    assert ex is not None and ex.rule_id == "inline_display_none_anchor"
    assert ex.provenance == "single_case"

    # Tailwind 的 md:hidden 在桌面可见，静态 HTML 判不了，必须不排除
    assert (
        classify_link_eligibility(
            "https://printify.com/x.pdf",
            LinkContext(source_page="p", anchor_html='<a class="md:hidden" href="...">x</a>'),
        )
        is None
    )


def test_severity_tiers() -> None:
    """按位置分档：saleor 的 CTA 与 tinybird 的页脚图标都是 1 条，差三个数量级。"""
    assert (
        severity_of(
            "https://saleor.io/cloud/talk-to-us",
            LinkContext(source_page="https://saleor.io/", anchor_text="See how Saleor fits"),
        )
        == SEVERITY_SALES_PATH
    )
    assert (
        severity_of(
            "https://saleor.io/cloud/pricing-page",
            LinkContext(source_page="https://saleor.io/pricing", anchor_text="Talk to us"),
            pricing_url="https://saleor.io/pricing",
        )
        == SEVERITY_SALES_PATH
    )
    assert (
        severity_of(
            "https://unkey.com/docs/platform/workspaces/billing",
            LinkContext(source_page="https://www.unkey.com/pricing", anchor_text="Read the docs"),
        )
        == SEVERITY_SALES_PATH
    )
    assert (
        severity_of(
            "https://github.com/swellstores/swell-sdk",
            LinkContext(source_page="https://www.swell.is/changelog",
                        anchor_text="New product methods in Swell SDK"),
        )
        != SEVERITY_SALES_PATH
    )
    assert (
        severity_of("https://x.com/tinybirdco",
                    LinkContext(source_page="https://tinybird.co/", anchor_text=""))
        == SEVERITY_FOOTER_SOCIAL
    )
    assert (
        severity_of(
            "https://github.com/canvas-medical/canvas-plugins/blob/main/example-plugins/x/README.md",
            LinkContext(source_page="https://docs.canvasmedical.com/product-updates/release-notes/",
                        anchor_text="Example repository"),
        )
        == SEVERITY_TUTORIAL_EXIT
    )


def test_root_cause_grouping_collapses_template_bugs() -> None:
    """8 条 tdengine 连接器链接是一处根因，报告必须按根因报而不是按条数。"""
    ctx = LinkContext(source_page="https://tdengine.com/")
    ids = {
        root_cause_id(f"https://docs.tdengine.com/reference/connector/{lang}/", ctx)
        for lang in ("java", "python", "go", "rust", "csharp", "cpp", "node", "r-lang")
    }
    assert len(ids) == 1, f"8 条应归为 1 个根因，实得 {len(ids)}"

    saleor_ctx_home = LinkContext(source_page="https://saleor.io/")
    saleor_ctx_pricing = LinkContext(source_page="https://saleor.io/pricing")
    saleor = {
        root_cause_id("https://saleor.io/cloud/talk-to-us?cta=a", saleor_ctx_home),
        root_cause_id("https://saleor.io/cloud/talk-to-us?cta=b", saleor_ctx_home),
        root_cause_id("https://saleor.io/cloud/pricing-page?cta=c", saleor_ctx_pricing),
    }
    assert len(saleor) == 2, "saleor 10 个链接实例 = 2 个唯一路径根因"


def test_exclusion_table_is_versioned() -> None:
    """排除清单必须版本化，否则会重演「五批排除、三批不排除」。"""
    assert fp.TABLE_VERSION


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw,apex,www",
    [
        ("brevo.com", "brevo.com", "www.brevo.com"),
        ("https://www.brevo.com/pricing", "brevo.com", "www.brevo.com"),
        ("WWW.Brevo.com/", "brevo.com", "www.brevo.com"),
        ("ed.link", "ed.link", "www.ed.link"),
        ("http://docs.mistral.ai/llms.txt", "docs.mistral.ai", "www.docs.mistral.ai"),
    ],
)
def test_normalize_input_domain(raw: str, apex: str, www: str) -> None:
    assert normalize_input_domain(raw) == (apex, www)


def test_subdomain_prefix_list_covers_every_observed_doc_host() -> None:
    """实测里真文件所在的子域前缀必须全在枚举表里。"""
    prefixes = {p for p, _ in DOC_HOST_PREFIXES}
    observed = {
        "docs",       # docs.mistral.ai / docs.canvasmedical.com / docs.turso.tech
        "developers", # developers.brevo.com / developers.printify.com
        "developer",  # developer.close.com / developer.bigcommerce.com
        "dev",        # dev.hume.ai / dev.wix.com
        "apidoc",     # apidoc.factorialhr.com
        "api-docs",   # api-docs.ecwid.com
        "support",    # support.copper.com / support.freshbooks.com
        "help",       # help.owner.com / help.brevo.com
        "supportcenter",  # supportcenter.mycase.com
        "platform",   # platform.minimax.io
    }
    assert observed <= prefixes, f"缺少前缀：{observed - prefixes}"


def test_ai_path_candidates_include_docs_subpath() -> None:
    """只探根路径会把 6 个域的真文件读成「未采纳」。"""
    assert "/llms.txt" in AI_PATH_CANDIDATES
    assert "/docs/llms.txt" in AI_PATH_CANDIDATES
    assert "/docs/llms-full.txt" in AI_PATH_CANDIDATES


def test_pricing_candidates_cover_squareup_and_wix() -> None:
    assert "/us/en/pricing" in PRICING_CANDIDATES  # squareup
    assert "/plans" in PRICING_CANDIDATES          # wix


def test_mine_declared_hosts_finds_kimi_from_moonshot_docs() -> None:
    """moonshot.ai 的文档站在 platform.kimi.ai —— 完全不同的注册域，
    任何前缀枚举都到不了，只能靠站点自身的声明。"""
    banner = (
        "Fetch the complete documentation index at: "
        "https://platform.kimi.ai/docs/llms.txt\n"
        "See also https://platform.kimi.ai/docs/overview for a walkthrough."
    )
    assert mine_declared_hosts([banner], apex="moonshot.ai") == ["platform.kimi.ai"]


def test_mine_declared_hosts_ignores_social_and_single_mentions() -> None:
    body = (
        "https://github.com/foo https://github.com/bar https://x.com/baz "
        "https://docs.somethingelse.com/one"
    )
    assert mine_declared_hosts([body], apex="moonshot.ai") == []


def test_mine_declared_hosts_is_capped() -> None:
    body = " ".join(
        f"https://docs.vendor{i}.com/a https://docs.vendor{i}.com/b" for i in range(10)
    )
    assert len(mine_declared_hosts([body], apex="acme.com")) <= 3


# --------------------------------------------------------------------------- #
# Fetcher wiring (stub transport, no network)
# --------------------------------------------------------------------------- #


def _fetcher(tmp_path, handler) -> Fetcher:
    f = Fetcher(
        FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
        cache=HttpCache(tmp_path / "c.sqlite3", ua_profile="test"),
        limiter=DomainLimiter(2.0),
    )
    f._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        headers={"User-Agent": f.user_agent, "From": CONTACT},
    )
    return f


def test_user_agent_requires_contact_email() -> None:
    """合规约束要求 UA 带真实联系邮箱，做成可选等于没有。"""
    with pytest.raises(ValueError):
        build_user_agent("")
    with pytest.raises(ValueError):
        build_user_agent("not-an-email")
    ua = build_user_agent(CONTACT)
    assert "geo-audit/" in ua and CONTACT in ua


def test_redirect_chain_is_recorded_unkey_308_308_404(tmp_path) -> None:
    """第一遍用 urllib 把 308 当终态，漏了定价页上的真死链。"""
    def handler(request: httpx.Request) -> httpx.Response:
        p = str(request.url)
        if p == "https://unkey.com/docs/platform/workspaces/billing":
            return httpx.Response(308, headers={"location":
                "https://www.unkey.com/docs/platform/workspaces/billing"})
        if p == "https://www.unkey.com/docs/platform/workspaces/billing":
            return httpx.Response(308, headers={"location":
                "https://www.unkey.com/docs/platform/workspaces/billing/overview"})
        return httpx.Response(404, text="not found", headers={"content-type": "text/html"})

    f = _fetcher(tmp_path, handler)
    resp = f.fetch("https://unkey.com/docs/platform/workspaces/billing")
    assert resp.status == 404
    assert len(resp.redirects) == 2
    assert [h.status for h in resp.redirects] == [308, 308]
    assert resp.final_url.endswith("/overview")
    f.close()


def test_redirect_loop_becomes_unknown_not_dead(tmp_path) -> None:
    """app.moderntreasury.com 的 Auth0 跳转环：curl error 47，绝不能判死。"""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://app.example/login"})

    f = _fetcher(tmp_path, handler)
    resp = f.fetch("https://app.example/login")
    assert resp.status == 0
    assert "redirect loop" in (resp.transport_error or "")
    from geo_audit.fetch.classify import classify

    cls = classify(resp)
    assert cls.verdict is Verdict.UNKNOWN
    assert cls.reason == "redirect_loop"
    assert not cls.evaluated
    f.close()


def test_control_url_is_same_host_and_keeps_extension(tmp_path) -> None:
    """两种对照路径形状：裸随机路径 + 带同扩展名的随机路径。"""
    u = Fetcher.control_url("https://www.minimax.io/llms.txt")
    assert u.startswith("https://www.minimax.io/geo-audit-probe-")
    assert u.endswith(".txt")
    u2 = Fetcher.control_url("https://platform.kimi.ai/docs/changelog")
    assert u2.startswith("https://platform.kimi.ai/docs/geo-audit-probe-")
    assert not u2.endswith(".txt")
    assert Fetcher.control_url("https://x.example/a.txt") != Fetcher.control_url(
        "https://x.example/a.txt"
    ), "对照路径必须每次随机，否则会被缓存/被站点特殊处理"


def test_host_profile_detects_catch_all_shell(tmp_path) -> None:
    """www.minimax.io 对任意路径返回同一个壳 -> discriminates=False。"""
    shell = (
        "<!DOCTYPE html><html><head><title>MiniMax</title></head><body>"
        + "<div class='sk'><span>Products</span></div>" * 80
        + "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=shell, headers={"content-type": "text/html"})

    f = _fetcher(tmp_path, handler)
    prof = f.host_profile("https://www.minimax.io/llms.txt")
    assert prof.usable is True
    # 200 + HTML for a path that cannot exist: the status tells us nothing,
    # only the fact that it is HTML does -- and that only helps a .txt target.
    assert prof.status_discriminates is False
    assert prof.control_is_html is True
    assert prof.struct_tags > 30
    f.close()


def test_catch_all_html_host_does_not_get_a_free_pass(tmp_path) -> None:
    """platform.kimi.ai 对 /docs/<任意> 都返回 Quickstart 页。

    对照探测返回 200 + HTML，如果把「HTML」当成可区分信号，普通页面就会被判
    「真实内容」——这个 host 上的死链会永远查不出来（实测原文：朴素 checker
    在这个文档站上永远查不出死链）。
    """
    shell = (
        "<!DOCTYPE html><html><head><title>Quickstart - Kimi API Platform</title>"
        "</head><body>" + "<div class='doc'><span>Quickstart</span></div>" * 80
        + "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=shell, headers={"content-type": "text/html"})

    f = _fetcher(tmp_path, handler)
    probe = f.probe("https://platform.kimi.ai/docs/changelog", expect=Expect.HTML_PAGE)
    assert probe.verdict is Verdict.SOFT404, (
        f"catch-all HTML host 上的页面应判 soft404，实得 {probe.verdict}/"
        f"{probe.classification.reason}"
    )
    assert probe.classification.reason == "identical_to_control"
    f.close()


def test_well_behaved_host_still_passes_a_real_html_page(tmp_path) -> None:
    """反向：404 对照 + 200 页面 -> OK。不能因为收紧规则把好站判坏。"""
    page = (
        "<!DOCTYPE html><html><head><title>Pricing</title></head><body>"
        "<h1>Pricing</h1><p>" + "Transparent pricing for teams. " * 40
        + "</p><table><tr><td>Pro</td><td>$29</td></tr></table></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if "geo-audit-probe" in str(request.url):
            return httpx.Response(404, text="<html><title>404</title></html>",
                                  headers={"content-type": "text/html"})
        return httpx.Response(200, text=page, headers={"content-type": "text/html"})

    f = _fetcher(tmp_path, handler)
    probe = f.probe("https://saleor.io/pricing", expect=Expect.HTML_PAGE)
    assert probe.verdict is Verdict.OK, probe.classification
    f.close()


def test_host_profile_unusable_when_control_is_blocked(tmp_path) -> None:
    """对照探测自己被 WAF 拦时，profile 不可用，判定必须退化成 UNKNOWN。"""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="Just a moment...",
                              headers={"content-type": "text/html"})

    f = _fetcher(tmp_path, handler)
    prof = f.host_profile("https://gusto.com/llms.txt")
    assert prof.usable is False
    assert prof.status_discriminates is False
    f.close()


def test_well_behaved_host_discriminates(tmp_path) -> None:
    """18 个 host 的反向验证形态：对照返回 404 -> discriminates=True。"""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="<html><title>404</title></html>",
                              headers={"content-type": "text/html"})

    f = _fetcher(tmp_path, handler)
    prof = f.host_profile("https://docs.mistral.ai/llms.txt")
    assert prof.usable is True and prof.status_discriminates is True
    f.close()


def test_second_run_of_same_domain_hits_cache(tmp_path) -> None:
    """同一域名重复跑必须免费：缓存命中，不再发请求。"""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text="# real llms.txt\n" + "- [a](b)\n" * 200,
                              headers={"content-type": "text/plain"})

    f = _fetcher(tmp_path, handler)
    url = "https://docs.mistral.ai/llms.txt"
    first = f.fetch(url, expect=Expect.TEXT_FILE)
    second = f.fetch(url, expect=Expect.TEXT_FILE)
    assert first.from_cache is False and second.from_cache is True
    assert calls["n"] == 1
    f.close()


def test_known_hostile_host_costs_no_request(tmp_path) -> None:
    """Zendesk / LinkedIn 之类的站点跳过请求以省速率预算，但判定仍是 BLOCKED。"""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text="should never be reached")

    f = _fetcher(tmp_path, handler)
    resp = f.fetch("https://www.linkedin.com/company/factorialhr")
    assert calls["n"] == 0
    from geo_audit.fetch.classify import classify

    assert classify(resp).verdict is Verdict.BLOCKED
    f.close()
