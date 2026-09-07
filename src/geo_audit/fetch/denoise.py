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

from ..models import LinkContext
from . import fingerprints as fp


@dataclass(frozen=True, slots=True)
class EligibilityExclusion:
    rule_id: str
    reason: str
    #: "measured" -- multiple observed cases; "single_case" -- one observation,
    #: so the report shows it as 待人工确认 rather than silently dropping it.
    provenance: str = "measured"


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
