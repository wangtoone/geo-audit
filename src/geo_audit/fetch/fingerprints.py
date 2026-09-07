"""Literal fingerprint tables.

Every entry here was observed in the 72-domain run recorded in
FEATURE-PRIORITY.md / feature-raw.json.  Nothing is speculative.  Each table
is versioned (TABLE_VERSION) and every hit is logged with the rule id that
matched, because §5 of the report documents exactly what happens without that:
five batches excluded /cdn-cgi/l/email-protection and three did not, which made
the batches non-comparable.
"""

from __future__ import annotations

import re

TABLE_VERSION = "2026-09-07.1"

# --------------------------------------------------------------------------- #
# WAF / bot-challenge fingerprints  ->  Verdict.BLOCKED
# --------------------------------------------------------------------------- #
# Anchors: gusto.com/llms.txt returns 403 + Cloudflare "Just a moment..." yet
# the file is REAL (200 text/plain 8217 B in a browser).  www.pipedrive.com/
# llms.txt returns 429 and the file is real too.  Calling either "no llms.txt"
# is the reverse twin of the soft-404 error and inflates nothing -- it deflates
# the adoption number.  Both directions must be handled.

#: Status codes that are a gate, never a verdict about content.
BLOCKED_STATUSES: frozenset[int] = frozenset({401, 402, 403, 405, 407, 429, 451, 999})

#: Hosts observed answering bots with 400.  400 is otherwise ambiguous, so it
#: only means "blocked" on these.  Observed: facebook 400 on brevo, copper,
#: bigcommerce and factorial link sets.
HOSTILE_400_HOSTS: frozenset[str] = frozenset(
    {
        "facebook.com",
        "www.facebook.com",
        "m.facebook.com",
        "instagram.com",
        "www.instagram.com",
    }
)

#: Vendors that answer bots with 403/429 on perfectly live pages.  Used only to
#: skip requests we already know will be useless (saves rate-limit budget);
#: the general rule above is what decides the verdict, so this list rotting
#: costs speed, never correctness.
KNOWN_BOT_HOSTILE_SUFFIXES: tuple[str, ...] = (
    "zendesk.com",  # support.goshippo.com 7x403, help.printify.com 7x403
    "linkedin.com",  # 999
    "g2.com",
    "capterra.com",
    "gartner.com",
    "trustpilot.com",
    "sourceforge.net",
    "intercom.com",
    "intercom.help",
    "join.slack.com",
    "chatgpt.com",
    "claude.ai",
    "perplexity.ai",
    "twitter.com",
    "x.com",
)

CHALLENGE_BODY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cf_just_a_moment", re.compile(r"just a moment\s*\.{0,3}", re.I)),
    ("cf_browser_verification", re.compile(r"cf-browser-verification|cf_chl_opt|__cf_chl_", re.I)),
    ("cf_attention_required", re.compile(r"attention required!\s*\|\s*cloudflare", re.I)),
    ("cf_checking_browser", re.compile(r"checking your browser before accessing", re.I)),
    ("akamai_access_denied", re.compile(r"access denied.{0,200}reference\s*#\d", re.I | re.S)),
    ("incapsula", re.compile(r"request unsuccessful\.\s*incapsula incident", re.I)),
    ("distil_imperva", re.compile(r"pardon our interruption", re.I)),
    ("perimeterx", re.compile(r"perimeterx|px-captcha|_pxhd", re.I)),
    ("datadome", re.compile(r"captcha-delivery\.com|datadome", re.I)),
    ("recaptcha_gate", re.compile(r"g-recaptcha|hcaptcha\.com/captcha", re.I)),
    ("generic_bot_verification", re.compile(r"<title>\s*bot verification", re.I)),
)

#: Paths that are authentication endpoints.  A 401/403 here is not information
#: about content.  Anchor: api.factorialhr.com/en/users/sign_in?... -> 403.
LOGIN_PATH_RE = re.compile(
    r"/(?:sign_?in|sign_?up|log_?in|log_?on|auth(?:orize)?|oauth|sso|account/login)(?:/|$|\?)",
    re.I,
)

# --------------------------------------------------------------------------- #
# Soft-404 body copy  ->  Verdict.SOFT404
# --------------------------------------------------------------------------- #
# Anchor for why this table must exist at all:
#   https://developers.brevo.com/docs/llms.txt
#     -> 200, content-type text/plain, 44 bytes, body "# Page Not Found
#        This page does not exist."
# Status is 200 and content-type is *correct*, so neither the status check nor
# the content-type check sees it.  Only body copy (or a control probe) does.

NOTFOUND_COPY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("page_not_found_en", re.compile(r"\bpage not found\b", re.I)),
    ("not_found_bare", re.compile(r"^\s*#?\s*not found\s*$", re.I | re.M)),
    ("does_not_exist", re.compile(r"\b(?:page|this page)?\s*(?:does not|doesn'?t) exist\b", re.I)),
    ("no_longer_exists", re.compile(r"\bno longer exists\b", re.I)),
    ("nothing_here", re.compile(r"\b(?:nothing (?:to see )?here|there'?s nothing here)\b", re.I)),
    (
        "cannot_be_found",
        re.compile(r"\b(?:could|couldn'?t|cannot|can'?t) (?:not )?be found\b", re.I),
    ),
    ("http_404_title", re.compile(r"\b404\b[^\d]{0,20}(?:not found|page not found|error)", re.I)),
    ("zh_page_missing", re.compile(r"页面不存在|找不到页面|页面未找到|页面已删除|无法找到该页面")),
)

#: Body-copy matching is restricted to this many leading normalized characters
#: (or to bodies shorter than SHORT_BODY_LIMIT in full).  Without the window a
#: real llms.txt that merely *links* to a page whose title contains "404" would
#: be condemned.  Cross-checked against the fixture set: none of the 20
#: confirmed-real llms.txt files (mistral 14658 B, resend 7316 B,
#: close 29752 B, brevo-developers 48852 B, ...) contains a match inside the
#: first 400 chars.
COPY_WINDOW_CHARS = 400
SHORT_BODY_LIMIT = 512

#: Redirect destinations that mean "we threw your path away".
#: Anchors: api-docs.ecwid.com/llms.txt -> docs.ecwid.com/ ;
#: support.freshbooks.com/llms.txt -> /hc/en-us ;
#: developers.attio.com/llms.txt -> docs.attio.com/docs/overview ;
#: docs.moderntreasury.com/<anything> -> / ;
#: developers.pinterest.com/llms-full.txt -> / ;
#: docs.gusto.com/llms-full.txt -> site homepage.
GENERIC_LANDING_PATHS: frozenset[str] = frozenset(
    {
        "",
        "/",
        "/hc/en-us",
        "/en-us",
        "/docs",
        "/docs/",
        "/docs/overview",
        "/docs/introduction",
        "/docs/get-started",
        "/home",
        "/index.html",
        "/payments/docs/overview",
    }
)

#: Hosting-platform "this deployment does not exist" pages.  Zero ambiguity --
#: these strings only ever appear on a broken deployment.
#: Anchor: brevo.com apex serves Vercel's plaintext DEPLOYMENT_NOT_FOUND on
#: /, /pricing/ and /blog/ while www + developers are healthy.
PLATFORM_MISSING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "vercel_deployment_not_found",
        re.compile(r"DEPLOYMENT_NOT_FOUND|the deployment could not be found on vercel", re.I),
    ),
    ("github_pages_missing", re.compile(r"there isn'?t a github pages site here", re.I)),
    ("heroku_no_app", re.compile(r"no such app\b.{0,80}herokuapp", re.I | re.S)),
    ("netlify_missing", re.compile(r"not found\s*-\s*request id:\s*\w+", re.I)),
    ("nginx_default", re.compile(r"welcome to nginx!", re.I)),
    ("fastly_unknown_domain", re.compile(r"fastly error: unknown domain", re.I)),
    ("s3_nosuchbucket", re.compile(r"<code>nosuchbucket</code>", re.I)),
)

# --------------------------------------------------------------------------- #
# Dead-link de-noise table  ->  excluded from the C1 numerator
# --------------------------------------------------------------------------- #
# This table IS the value of the dead-link check: 40.5% false positives without
# it (42 judged dead, 25 real), 0% with it (n=51).  Every rule carries an id
# so the report can print an exclusion log.

EXCLUDE_URL_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "cloudflare_email_protection",
        re.compile(r"/cdn-cgi/l/email-protection"),
        "Cloudflare 邮箱混淆端点，不是内容链接",
    ),
    (
        "mintlify_injected_anchor",
        re.compile(r"/base-ui-[a-z0-9-]+$"),
        "Mintlify 注入的锚点（attio 2 条）",
    ),
    (
        "fern_injected_anchor",
        re.compile(r"/fern-scroll-area-[a-z0-9-]+$"),
        "Fern 注入的锚点（brevo 1 条）",
    ),
    (
        "fern_console_host",
        re.compile(r"^https?://app\.buildwithfern\.com"),
        "Fern 控制台域，非甲方内容（brevo/close 各 1 条）",
    ),
    (
        "intellimize_endpoint",
        re.compile(r"^https?://[\w.-]*intellimize(?:io)?\.(?:com|co)"),
        "Intellimize A/B 脚本端点（copper 1 条）",
    ),
    (
        "reserved_example_domain",
        re.compile(
            r"^https?://(?:[\w-]+\.)*(?:example\.(?:com|org|net)|example|test|invalid|localhost)(?:[:/]|$)"
        ),
        "IANA 保留示例域名",
    ),
    (
        "url_template_placeholder",
        re.compile(
            r"[{<\[](?:\s*)(?:[a-z_][a-z0-9_]*)(?:\s*)[}>\]]|%7B[a-z_]+%7D|:[a-z_]+Id(?:/|$)", re.I
        ),
        "URL 里含未替换的模板占位符（{year}/{permalink}/{templateID}）",
    ),
    (
        "framework_bind_artifact",
        re.compile(r"^(?::|x-bind:|v-bind:|@)?href$|^\{\{"),
        "Alpine/Vue 的 :href / x-bind:href 抽取伪影",
    ),
    (
        "non_http_scheme",
        re.compile(r"^(?!https?:)(?:mailto|tel|sms|javascript|data|ftp|file|slack|intent):", re.I),
        "非 HTTP scheme",
    ),
)

#: An API base URL answers 404/401 to a bare GET by design.  The empirical
#: false positives were enterprise.printful.com/api/pfy/public/v1/ and
#: api.sendinblue.com/v3/emailCampaigns/{templateID}/sharedUrl.
#: The original rule ("API base URL") was uncodeable; this is the codeable
#: form: path shape AND a code-context signal.
API_PATH_RE = re.compile(r"/(?:api|v[0-9]+|graphql|rest)(?:/|$)", re.I)
CODE_CONTEXT_RE = re.compile(
    r"</?(?:code|pre|kbd|samp)\b|\bcurl\b|\bfetch\(|\brequests\.(?:get|post)\b", re.I
)

#: Anchor-invisible links.  The original rule ("class contains hidden") is not
#: decidable from static HTML -- Tailwind's md:hidden means visible on desktop.
#: Narrowed to inline style only.  Provenance: single case (printify's IRS Form
#: 8937 link), so anything it excludes is logged as "待人工确认", not silently
#: dropped.
INLINE_DISPLAY_NONE_RE = re.compile(r"style\s*=\s*[\"'][^\"']*display\s*:\s*none", re.I)
