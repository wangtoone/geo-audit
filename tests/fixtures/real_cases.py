"""Fixtures reconstructed from the 72-domain run (feature-raw.json).

Every case carries its real domain, real status, real content-type and the real
distinguishing body fragment.  Bodies are synthesised to the recorded shape
(shell / copy / marker) rather than stored verbatim -- the recorded byte counts
are explicitly NOT reproducible (3 of 12 re-measurements disagreed), so a test
that asserted on byte length would be asserting on a known-bad number.  What is
reproducible, and what these tests assert on, is the *verdict*.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Case:
    name: str
    url: str
    status: int
    headers: dict[str, str]
    body: str
    expect_verdict: str
    expect_reason: str
    final_url: str | None = None
    redirects: tuple[tuple[int, str, str], ...] = ()
    note: str = ""
    control: dict[str, object] | None = None


def _spa_shell(title: str, *, size: int = 6000, nonce: str = "abc123def456abc7") -> str:
    # A real SPA shell carries a bit of boilerplate prose (cookie banner, nav
    # labels, footer) plus a lot of empty markup.  Both are reproduced so the
    # tests exercise the content digest AND the structural fingerprint.
    filler = (
        "<div class='sk'><span class='nav-label'>Products</span></div>"
        "<div class='sk'><span class='nav-label'>Pricing</span></div>"
    ) * max(1, size // 120)
    return (
        f"<!DOCTYPE html><html lang=en><head><meta charset=utf-8>"
        f"<title>{title}</title><script nonce=\"{nonce}\" src=\"/_next/static/chunks/main-{nonce}.js\"></script>"
        f"</head><body><div id=\"__next\"></div><script src=\"/_next/static/app.js\"></script>"
        f"{filler}</body></html>"
    )


def _docusaurus_shell(title: str) -> str:
    return (
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        '<meta name="generator" content="Docusaurus v3.10.2">'
        f"<title>{title}</title></head><body><div id=\"__docusaurus\"></div>"
        '<script src="/assets/js/main.9f8a.js"></script></body></html>'
    )


def _real_llmstxt(brand: str, urls: int = 40) -> str:
    lines = [f"# {brand}", "", f"> {brand} developer documentation index.", ""]
    lines += [
        f"- [Guide {i}](https://docs.{brand}.com/guide/{i}.md): section {i} of the docs, "
        f"covering setup, configuration and troubleshooting for module {i}."
        for i in range(urls)
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# GROUP A -- the 16 confirmed soft404s (challenge verified 16/16)
# --------------------------------------------------------------------------- #

SOFT404_CASES: list[Case] = [
    Case(
        "medplum_llmstxt_docusaurus_shell",
        "https://www.medplum.com/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _docusaurus_shell("Medplum"),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html 57592B，Docusaurus 页面外壳；朴素 checker 判「已采纳」",
    ),
    Case(
        "edlink_llmstxt_spa_shell",
        "https://ed.link/llms.txt",
        200, {"content-type": "text/html"},
        _spa_shell("Edlink Dashboard", size=4490),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html 4490B，<title>Edlink Dashboard</title>",
    ),
    Case(
        "printify_developers_llmstxt_spa",
        "https://developers.printify.com/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Printify Developers", size=42569),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html 425692B 文档站 SPA 兜底页",
    ),
    Case(
        "canvasmedical_apex_llmstxt_homepage_shell",
        "https://www.canvasmedical.com/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Canvas: AI-Powered Healthcare Platform for Clinics", size=31786),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html 317869B，是主站首页外壳；真文件在 docs.canvasmedical.com",
    ),
    Case(
        "pinterest_business_llmstxt_shell",
        "https://business.pinterest.com/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Pinterest for Business", size=21828),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html 21828B 商家站兜底页",
    ),
    Case(
        "pipedrive_developers_llmstxt_shell",
        "https://developers.pipedrive.com/llms.txt",
        200, {"content-type": "text/html"},
        _spa_shell("Pipedrive Developer Documentation", size=24907),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html 24907B（质证逐字节复现）",
    ),
    Case(
        "browserbase_llmsfull_shell",
        "https://www.browserbase.com/llms-full.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Browserbase", size=18000),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html；质证时还多了一跳到 sign-in",
    ),
    # -- the variant that content-type checks cannot see -------------------- #
    Case(
        "brevo_docs_llmstxt_44_bytes_page_not_found",
        "https://developers.brevo.com/docs/llms.txt",
        200, {"content-type": "text/plain; charset=utf-8"},
        "# Page Not Found\n\nThis page does not exist.",
        "soft404", "notfound_copy_in_body",
        note="实测 200 + text/plain + 44 字节。状态码对、content-type 对，"
             "只有正文文案能抓到。这是全套判定里最关键的一个反例",
    ),
    # -- redirect variants -------------------------------------------------- #
    Case(
        "ecwid_legacy_apidocs_302_to_new_docs_root",
        "https://api-docs.ecwid.com/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Ecwid Developers", size=71513),
        "soft404", "html_where_text_expected",
        final_url="https://docs.ecwid.com/",
        redirects=((302, "https://api-docs.ecwid.com/llms.txt", "https://docs.ecwid.com/"),),
        note="实测 302 到新文档首页并返 200；api-docs 是历史上被大量文章引用的规范域名",
    ),
    Case(
        "freshbooks_support_307_to_hc_en_us",
        "https://support.freshbooks.com/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        "<!DOCTYPE html><html><head><title>FreshBooks Support</title></head>"
        "<body><h1>Help Centre</h1><p>Search our articles.</p>"
        "<ul><li><a href='/hc/en-us/articles/1'>Getting started</a></li></ul></body></html>",
        "soft404", "html_where_text_expected",
        final_url="https://support.freshbooks.com/hc/en-us",
        redirects=((307, "https://support.freshbooks.com/llms.txt",
                    "https://support.freshbooks.com/hc/en-us"),),
        note="实测 307 → /hc/en-us → 200 text/html 35749B。"
             "同子域上任意编造路径返回完全相同的链路，已用对照实验坐实",
    ),
    Case(
        "attio_developers_302_to_docs_overview",
        "https://developers.attio.com/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Attio Docs", size=22587),
        "soft404", "html_where_text_expected",
        final_url="https://docs.attio.com/docs/overview",
        redirects=((302, "https://developers.attio.com/llms.txt",
                    "https://docs.attio.com/docs/overview"),),
        note="实测 302 → docs.attio.com/docs/overview，225877B（质证逐字节复现）",
    ),
    Case(
        "moderntreasury_docs_llmsfull_302_to_overview",
        "https://docs.moderntreasury.com/llms-full.txt",
        200, {"content-type": "text/html"},
        _spa_shell("Modern Treasury Docs", size=15000),
        "soft404", "html_where_text_expected",
        final_url="https://docs.moderntreasury.com/payments/docs/overview",
        redirects=((302, "https://docs.moderntreasury.com/llms-full.txt",
                    "https://docs.moderntreasury.com/payments/docs/overview"),),
        note="该 host 对任意不存在路径 302 → 通用落地页，站内死链会伪装成 200",
    ),
    Case(
        "pinterest_developers_llmsfull_302_to_root",
        "https://developers.pinterest.com/llms-full.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Pinterest Developers", size=19652),
        "soft404", "html_where_text_expected",
        final_url="https://developers.pinterest.com/",
        redirects=((302, "https://developers.pinterest.com/llms-full.txt",
                    "https://developers.pinterest.com/"),),
    ),
    Case(
        "gusto_docs_llmsfull_to_homepage",
        "https://docs.gusto.com/llms-full.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Gusto Embedded Payroll", size=29359),
        "soft404", "html_where_text_expected",
        final_url="https://docs.gusto.com/",
        redirects=((302, "https://docs.gusto.com/llms-full.txt", "https://docs.gusto.com/"),),
    ),
]

#: The two cases that ONLY the control probe can decide: status 200,
#: content-type text/html, and the *expected* type is also HTML-ish, so no
#: deterministic rule fires.  These need the same-host control comparison.
CONTROL_ONLY_CASES: list[Case] = [
    Case(
        "minimax_apex_any_path_same_shell",
        "https://www.minimax.io/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("MiniMax", size=38405, nonce="deadbeefdeadbee1"),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html 384052B；/this-does-not-exist-xyz123 同样 200 + 384052B。"
             "按 .txt 探测时 L2(a) 先命中（证据更强）；把同一个壳当普通页面判时只有对照探测抓得到。"
             "两个方向都会读错：只探根路径又会把真文件（platform.minimax.io/docs/llms.txt）读成未采纳",
        control={
            "probe_url": "https://www.minimax.io/geo-audit-probe-0123456789abcdef01234567.txt",
            "status": 200, "content_type": "text/html",
            "body": _spa_shell("MiniMax", size=38405, nonce="deadbeefdeadbee1"),
            "status_discriminates": False, "control_is_html": True, "usable": True, "final_path": "/geo-audit-probe.txt",
        },
    ),
    Case(
        "moonshot_apex_any_path_same_shell",
        "https://www.moonshot.ai/llms.txt",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Moonshot AI", size=8246, nonce="cafebabecafebab1"),
        "soft404", "html_where_text_expected",
        note="实测 200 + text/html 82460B；/nonexistent-xyz-123 同样 200 + 82460B",
        control={
            "probe_url": "https://www.moonshot.ai/geo-audit-probe-fedcba9876543210fedcba98.txt",
            "status": 200, "content_type": "text/html",
            "body": _spa_shell("Moonshot AI", size=8246, nonce="cafebabecafebab1"),
            "status_discriminates": False, "control_is_html": True, "usable": True, "final_path": "/geo-audit-probe.txt",
        },
    ),
    Case(
        "kimi_docs_any_path_returns_quickstart",
        "https://platform.kimi.ai/docs/changelog",
        200, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Quickstart - Kimi API Platform", size=41407, nonce="1111222233334441"),
        "soft404", "identical_to_control",
        note="实测 /docs/nonsense-xyz 与 /docs/changelog 都是 200、414072B、"
             "<title>Quickstart - Kimi API Platform</title>，与 /docs/overview 完全一致。"
             "朴素 checker 在这个文档站上永远查不出死链",
        control={
            "probe_url": "https://platform.kimi.ai/docs/geo-audit-probe-aaaabbbbccccddddeeeeffff",
            "status": 200, "content_type": "text/html",
            "body": _spa_shell("Quickstart - Kimi API Platform", size=41407, nonce="1111222233334441"),
            "status_discriminates": False, "control_is_html": True, "usable": True, "final_path": "/docs/geo-audit-probe",
        },
    ),
]

# --------------------------------------------------------------------------- #
# GROUP B -- real files that must NOT be condemned (specificity, 20/20)
# --------------------------------------------------------------------------- #

REAL_FILE_CASES: list[Case] = [
    Case(
        "mistral_docs_llmstxt_real_but_all_links_dead",
        "https://docs.mistral.ai/llms.txt",
        200, {"content-type": "text/plain; charset=utf-8"},
        _real_llmstxt("mistral", urls=75),
        "ok", "ok_control_discriminates",
        note="实测 200 text/plain 真文件 14658B。文件本身没问题，问题是 75/75 内链全死 —— "
             "文件存在性判定必须判 ok，内链检查才是报出问题的那一步",
        control={
            "probe_url": "https://docs.mistral.ai/geo-audit-probe-1234.txt",
            "status": 404, "content_type": "text/html",
            "body": "<html><head><title>Page Not Found</title></head><body>404</body></html>",
            "status_discriminates": True, "control_is_html": True, "usable": True, "final_path": "/geo-audit-probe-1234.txt",
        },
    ),
    Case(
        "resend_llmstxt_real",
        "https://resend.com/llms.txt",
        200, {"content-type": "text/plain; charset=utf-8"},
        _real_llmstxt("resend", urls=30),
        "ok", "ok_control_discriminates",
        note="实测 200 text/plain 7316B 真 markdown",
        control={
            "probe_url": "https://resend.com/geo-audit-probe-5678.txt",
            "status": 404, "content_type": "text/html",
            "body": "<html><title>404</title><body>Not found</body></html>",
            "status_discriminates": True, "control_is_html": True, "usable": True, "final_path": "/geo-audit-probe-5678.txt",
        },
    ),
    Case(
        "close_llmstxt_real_with_last_updated",
        "https://close.com/llms.txt",
        200, {"content-type": "text/plain; charset=utf-8"},
        "# Close CRM\n\nLast Updated: August 2026\n\n" + _real_llmstxt("close", urls=60),
        "ok", "ok",
        note="实测 200 text/plain 29752B，开头写「Last Updated: August 2026」，四家里做得最认真",
    ),
    Case(
        "brevo_developers_llmstxt_real",
        "https://developers.brevo.com/llms.txt",
        200, {"content-type": "text/plain; charset=utf-8"},
        _real_llmstxt("brevo", urls=90),
        "ok", "ok",
        note="实测 200 text/plain 48852B 真文件。注意同一个 host 上 /docs/llms.txt "
             "是 44 字节的软 404 —— 同 host 内不同路径必须各判各的",
    ),
    Case(
        "spoton_llmstxt_real",
        "https://spoton.com/llms.txt",
        200, {"content-type": "text/plain"},
        _real_llmstxt("spoton", urls=20),
        "ok", "ok",
        note="实测 7.3KB text/plain 真文件。spoton 的零发现来自它的 help 子域是纯 JS，"
             "不是 llms.txt 有问题",
    ),
    Case(
        "canvasmedical_docs_llmsfull_4mb_real",
        "https://docs.canvasmedical.com/llms-full.txt",
        200, {"content-type": "text/plain; charset=utf-8"},
        _real_llmstxt("canvasmedical", urls=400),
        "ok", "ok",
        note="实测 200 text/plain 4.3MB 真全文。是缓存/读取上限必须留够余量的那个上界样本",
    ),
]

# --------------------------------------------------------------------------- #
# GROUP C -- honest 404s.  Must be real404, never soft404.
# --------------------------------------------------------------------------- #

REAL404_CASES: list[Case] = [
    Case(
        "snipcart_llmstxt_404_with_nuxt_spa_body",
        "https://snipcart.com/llms.txt",
        404, {"content-type": "text/html; charset=utf-8"},
        _spa_shell("Snipcart", size=12000),
        "real404", "status_404",
        note="实测：状态码是真 404，正文是 Nuxt SPA 兜底页。报告原文明写"
             "「判真 404 不判 soft404」。正文形态不得覆盖正确的状态码",
    ),
    Case(
        "siliconflow_apex_llmstxt_404_ten_bytes",
        "https://www.siliconflow.com/llms.txt",
        404, {"content-type": "text/plain"},
        "Not found",
        "real404", "status_404",
        note="实测 404 且 body 只有 10 字节「Not found」，是真 404 不是软 404",
    ),
    Case(
        "fireworks_apex_llmstxt_clean_404",
        "https://fireworks.ai/llms.txt",
        404, {"content-type": "text/html"},
        "<html><head><title>404: This page could not be found</title></head><body></body></html>",
        "real404", "status_404",
        note="实测干净 404，不是软 404。真文件在 docs.fireworks.ai",
    ),
    Case(
        "printful_developers_llmstxt_404_20_bytes",
        "https://developers.printful.com/llms.txt",
        404, {"content-type": "text/plain"},
        "404 page not found",
        "real404", "status_404",
        note="实测真 404，text/plain 20B。主域 www.printful.com/llms.txt 是真文件",
    ),
    Case(
        "unkey_docs_billing_308_308_404",
        "https://unkey.com/docs/platform/workspaces/billing",
        404, {"content-type": "text/html"},
        "<html><head><title>Not found</title></head><body>404</body></html>",
        "real404", "status_404",
        final_url="https://www.unkey.com/docs/platform/workspaces/billing/overview",
        redirects=(
            (308, "https://unkey.com/docs/platform/workspaces/billing",
             "https://www.unkey.com/docs/platform/workspaces/billing"),
            (308, "https://www.unkey.com/docs/platform/workspaces/billing",
             "https://www.unkey.com/docs/platform/workspaces/billing/overview"),
        ),
        note="实测 308 → 308 → 404，出现在定价页的「Read the docs」按钮上。"
             "第一遍用 urllib 把 308 当终态漏检了这条真死链",
    ),
]

# --------------------------------------------------------------------------- #
# GROUP D -- blocked.  Must never become real404 / soft404.
# --------------------------------------------------------------------------- #

BLOCKED_CASES: list[Case] = [
    Case(
        "gusto_llmstxt_cloudflare_challenge_but_file_is_real",
        "https://gusto.com/llms.txt",
        403, {"content-type": "text/html; charset=UTF-8", "server": "cloudflare"},
        "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
        "<body><div class='cf-browser-verification'></div></body></html>",
        "blocked", "waf_challenge_body",
        note="实测 curl 得 403 Cloudflare 挑战页；浏览器过挑战后同源 fetch 得 200 text/plain "
             "8217B 真文件。判成「没有 llms.txt」会让采纳率虚低",
    ),
    Case(
        "pipedrive_www_llmstxt_429_but_file_is_real",
        "https://www.pipedrive.com/llms.txt",
        429, {"content-type": "text/html", "retry-after": "60"},
        "<html><body>Too Many Requests</body></html>",
        "blocked", "rate_limited",
        note="实测 429，但 www.pipedrive.com/llms.txt 是 200 text/plain 8501B 真文件",
    ),
    Case(
        "goshippo_support_zendesk_403",
        "https://support.goshippo.com/hc/en-us/articles/115003765647",
        403, {"content-type": "text/html"},
        "<html><body>Forbidden</body></html>",
        "blocked", "waf_status",
        note="实测 7 条 support.goshippo.com（Zendesk）403，全部不算死链",
    ),
    Case(
        "linkedin_company_999",
        "https://www.linkedin.com/company/factorialhr",
        999, {"content-type": "text/html"},
        "",
        "blocked", "waf_status",
        note="实测 LinkedIn 对 bot 返回 999。factorial 与 goshippo 各一条",
    ),
    Case(
        "facebook_page_400",
        "https://www.facebook.com/brevo.official",
        400, {"content-type": "text/html"},
        "<html><body>Bad Request</body></html>",
        "blocked", "waf_status",
        note="实测 Facebook 对 bot 返回 400（brevo / copper / bigcommerce / factorial 各一条）",
    ),
    Case(
        "factorial_signin_endpoint_403",
        "https://api.factorialhr.com/en/users/sign_in?return_host=factorialhr.com",
        403, {"content-type": "text/html"},
        "<html><body>Forbidden</body></html>",
        "blocked", "login_required",
        note="实测登录端点 403，不是内容页",
    ),
]

# --------------------------------------------------------------------------- #
# GROUP E -- unknown.  The false-zero guards.
# --------------------------------------------------------------------------- #

UNKNOWN_CASES: list[Case] = [
    Case(
        "pinterest_developers_llmstxt_500",
        "https://developers.pinterest.com/llms.txt",
        500, {"content-type": "text/html"},
        "<html><body>Internal Server Error</body></html>",
        "unknown", "server_error",
        note="实测 500。5xx 是「判不了」，不是「死了」——判死就是假阳性",
    ),
    Case(
        "edlink_docs_rate_limits_500",
        "https://ed.link/docs/platform/rate-limits",
        500, {"content-type": "text/html"},
        "<html><body>500</body></html>",
        "unknown", "server_error",
        note="实测 500，文档站有服务端错误路径",
    ),
]

JS_REQUIRED_CASES: list[Case] = [
    Case(
        "spoton_help_center_pure_js_one_line",
        "https://help.spoton.com/",
        200, {"content-type": "text/html; charset=utf-8"},
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<title>SpotOn Knowledge Base</title>"
        '<script src="/static/js/bundle.4f9a2c.js"></script></head>'
        '<body><div id="root"></div>'
        '<script src="/static/js/main.chunk.js"></script>'
        + ("<!-- padding -->" * 400)
        + "</body></html>",
        "unknown", "needs_js",
        note="实测抓下来正文只有一行标题「SpotOn Knowledge Base」。"
             "判 ok 就是制造假零：spoton 的 C2/C4 零发现正是这么来的",
    ),
    Case(
        "lawmatics_docs_redoc_one_line",
        "https://docs.lawmatics.com/",
        200, {"content-type": "text/html; charset=utf-8"},
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<title>Lawmatics OAuth API v1.22.0</title></head>"
        '<body><div id="redoc"></div>'
        '<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>'
        "<script>Redoc.init('/openapi.json', {}, document.getElementById('redoc'))</script>"
        + ("<!-- x -->" * 300)
        + "</body></html>",
        "unknown", "needs_js",
        note="实测纯 Redoc 单页应用，抓下来正文只有一行「Lawmatics OAuth API v1.22.0」",
    ),
]

# --------------------------------------------------------------------------- #
# GROUP F -- platform-level "deployment missing" (the brevo apex case)
# --------------------------------------------------------------------------- #

APEX_CASES: list[Case] = [
    Case(
        "brevo_apex_root_vercel_deployment_not_found",
        "https://brevo.com/",
        200, {"content-type": "text/plain; charset=utf-8"},
        "The deployment could not be found on Vercel.\n\nDEPLOYMENT_NOT_FOUND",
        "soft404", "platform_deployment_missing",
        note="实测裸域 /、/pricing/、/blog/ 全是这个纯文本；www 与 developers 子域正常。"
             "爬链接的范式永远抓不到——站内没有 href 指向裸域",
    ),
    Case(
        "brevo_apex_pricing_vercel_deployment_not_found",
        "https://brevo.com/pricing/",
        200, {"content-type": "text/plain; charset=utf-8"},
        "The deployment could not be found on Vercel.\n\nDEPLOYMENT_NOT_FOUND",
        "soft404", "platform_deployment_missing",
    ),
]

ALL_CASES: list[Case] = (
    SOFT404_CASES + CONTROL_ONLY_CASES + REAL_FILE_CASES + REAL404_CASES
    + BLOCKED_CASES + UNKNOWN_CASES + JS_REQUIRED_CASES + APEX_CASES
)

#: The 20 domains whose llms.txt was reverse-validated as a real file.  Used by
#: the specificity test: not one of them may be judged soft404.
REVERSE_VALIDATED_REAL_DOMAINS: tuple[str, ...] = (
    "resend.com", "trigger.dev", "inngest.com", "upstash.com", "depot.dev",
    "unkey.com", "liveblocks.io", "tinybird.co", "hookdeck.com",
    "openstatus.dev", "turso.tech", "browserbase.com", "attio.com",
    "close.com", "customer.io", "loops.so", "mailerlite.com", "docketwise.com",
    "mycase.com", "teachable.com",
)
