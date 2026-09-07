"""Core data structures for the fetch & compliance layer.

Design rule that governs every type in this file: a check must always be able
to distinguish "we looked and it is broken" from "we could not look".  The
empirical run (FEATURE-PRIORITY.md §5) shows why: 10 domains were dropped for
anti-bot, and spoton/lawmatics scored zero findings purely because their docs
sites are JS SPAs.  Any type that collapses those into "ok" manufactures a
false zero.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, TypedDict

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

    @property
    def evaluated(self) -> bool:
        return self.reason not in NOT_EVALUATED_REASONS


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
    robots: dict[str, "RobotsInfo"]


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


class FindingDict(TypedDict):
    """JSON shape.  Stable public contract of the CLI's --json output."""

    check_id: str
    status: str
    position: str
    url: str
    severity: str
    reason: str
    evidence: list[str]
    naive_would_say: str | None
    root_cause_id: str | None
    fix_hint: str | None
