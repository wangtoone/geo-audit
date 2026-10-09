"""JS-dependence detection.  v1 ships NO renderer.

Decision and its justification (do not revisit without new data):

1. No Playwright in v1.
   a) Compliance.  The stated constraints are "<=1 request / 2 s per domain",
      "no WAF bypass, no CAPTCHA solving, no residential proxies".  A headless
      browser is precisely the tool that makes bypassing a WAF trivial; adding
      it invites the tool to become the thing we promised not to build.
   b) Distribution.  `uvx geo-audit example.com` has to work in one line.
      Playwright needs a separate ~300 MB `playwright install` step, which
      breaks the one-line promise and breaks it hardest for the
      non-command-line audience the product explicitly targets.
   c) The payoff is bounded and already measured.  The confirmed JS-blind
      cases in the 72-domain run are help.spoton.com (extracted body: one line,
      "SpotOn Knowledge Base") and docs.lawmatics.com (Redoc SPA; extracted
      body: one line, "Lawmatics OAuth API v1.22.0") -- 2/72 = 2.8%, plus the
      zilliz/minimax marketing shells.
   d) Neither v1 check needs rendered prose.  C3 reads llms.txt/llms-full.txt,
      which are text files and are never JS-rendered.  C1 needs status codes
      and soft-404 fingerprints, not prose.  JS-blindness bites the checks that
      were CUT (C2 stale signals, C4 fact conflicts), which read body text.

2. Therefore v1 must DETECT and DECLARE JS-dependence.  This module is that
   guard.  A position whose page needs JS becomes
   Verdict.UNKNOWN / reason "needs_js", which report renderers are required to
   place in the 未能评估 region.  It must never become "no problem" -- that is
   the false zero the whole design is built to avoid.

3. `--render` exists as a flag and exits non-zero with this explanation, so
   the v2 upgrade path is visible without shipping the dependency.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator

from ..models import JsAssessment
from .normalize import visible_text

#: Below this many visible characters an HTML page carries no readable prose.
#: Calibrated on the two known cases: spoton's help centre extracts to
#: "SpotOn Knowledge Base" (21 chars) and lawmatics' Redoc to
#: "Lawmatics OAuth API v1.22.0" (27 chars).  A genuinely thin but real page
#: (a 404 page, a login page) also lands here, which is fine: those are
#: classified before this runs.
EMPTY_SHELL_TEXT_LEN = 200

#: A page with prose but suspiciously little of it relative to its markup.
THIN_TEXT_LEN = 500

# --------------------------------------------------------------------------- #
# Tag signals -- linear time, on purpose
# --------------------------------------------------------------------------- #
# Five of the signals used to be single regexes of the shape ``<div[^>]+id=...[^>]*>...``,
# ``<script[^>]+src=`` and ``<noscript[^>]*>...``.  ``[^>]+`` takes everything up to the next ``>``
# (or the end of the page) and then gives characters back one at a time looking for ``id=``, and
# every ``<div`` start did that again over the same text: N copies of ``<div id='app'`` with no
# ``>`` cost O(N^3), ``<div `` / ``<script `` / ``<noscript `` x N cost O(N^2).
# ``classify_response`` runs this on every HTML response that is not blocked, 404/410 or 5xx (and
# ``geo-audit page`` runs it too), so a hostile -- or merely broken -- page could stall an audit.
#
# Each signal is only ever used as a yes/no, so each is computed per TAG instead: the first
# ``<div`` after a ``>`` fixes where its tag ends (the next ``>``), and any later ``<div`` before
# that ``>`` has the same end and a shorter attribute span, so it cannot match when the first one
# does not.  Every tag is therefore looked at once.  The pieces are the original patterns
# (``re.I``, ``\s`` and all).  Only the searches inside a tag are bounded by its ``>``; the ones
# after it (``\s*</div>``, the next ``-->``, the demand phrase) run as far as they need to and
# stay linear because each is cached or resumed where the previous one stopped.  The tests keep
# the old single regexes as the oracle and compare yes/no on the frozen corpus and on fuzzed
# pages.

#: ``re.I`` also accepts look-alike spellings (``ı`` / ``İ`` for ``i``, ``ſ`` for
#: ``s``) -- keep it on every piece, exactly like the original patterns.
_DIV_OPEN_RE = re.compile(r"<div", re.I)
_SCRIPT_OPEN_RE = re.compile(r"<script", re.I)
_NOSCRIPT_OPEN_RE = re.compile(r"<noscript", re.I)

_SRC_RE = re.compile(r"src=", re.I)
_MOUNT_ID_RE = re.compile(r"id=[\"'](?:root|app|__next|__nuxt|application|main-content)[\"']", re.I)
_FRAMEWORK_MOUNT_ID_RE = re.compile(r"id=[\"'](?:root|app|__next|__nuxt)[\"']", re.I)
_REDOC_ID_RE = re.compile(r"id=[\"']redoc[\"']", re.I)

_WS_RE = re.compile(r"\s*")
_CLOSE_DIV_RE = re.compile(r"</div>", re.I)
_EMPTY_DIV_BODY_RE = re.compile(r"\s*</div>", re.I)
_COMMENT_END_THEN_CLOSE_DIV_RE = re.compile(r"-->\s*</div>", re.I)
_UP_TO_SCRIPT_RE = re.compile(r"\s*(?:<[^>]+>\s*){0,3}<script", re.I)

#: The API-reference markers that never needed a tag scan (``<div id="redoc"`` does, below).
_API_DOC_MARKERS_RE = re.compile(
    r"<redoc\b|<rapi-doc\b|id=[\"']swagger-ui[\"']\s*>\s*</div>|Redoc\.init\(|SwaggerUIBundle\(",
    re.I,
)
_NOSCRIPT_CLOSE_RE = re.compile(r"</noscript>", re.I)
_JS_DEMAND_RE = re.compile(
    r"enable\s+javascript|requires\s+javascript|javascript\s+(?:is\s+)?(?:required|disabled)"
    r"|需要?启用\s*javascript|请开启\s*javascript",
    re.I,
)
#: How far past ``<noscript>`` the demand phrase may start.
_NOSCRIPT_WINDOW = 600
#: "no such position": larger than any index.
_NEVER = sys.maxsize

_NUXT_RE = re.compile(r"window\.__NUXT__|data-server-rendered=[\"']false[\"']", re.I)
_NEXT_DATA_RE = re.compile(r"id=[\"']__NEXT_DATA__[\"']", re.I)
_CONTENT_ELEMENT_RE = re.compile(r"<(?:p|li|h2|h3|article|table|dd)\b", re.I)


def _tags(text: str, opening: re.Pattern[str]) -> Iterator[tuple[int, int]]:
    """``(end of the opening token, index of the next ">" or -1)`` for the first ``opening`` after
    every ``>``.  Later openings before the same ``>`` are skipped (see above).  Nothing follows a
    ``-1``: with no ``>`` left, no later opening has one either."""
    pos = 0
    while True:
        m = opening.search(text, pos)
        if m is None:
            return
        gt = text.find(">", m.end())
        yield m.end(), gt
        if gt < 0:
            return
        pos = gt + 1


def _skip_ws(text: str, pos: int) -> int:
    m = _WS_RE.match(text, pos)
    return m.end() if m else pos


def _has_script_src(text: str) -> bool:
    """``re.search(r"<script[^>]+src=", text, re.I)``"""
    for end, gt in _tags(text, _SCRIPT_OPEN_RE):
        # ``[^>]+`` takes at least one character, so ``src=`` starts at ``end + 1`` or later
        if _SRC_RE.search(text, end + 1, len(text) if gt < 0 else gt):
            return True
    return False


def _has_empty_mount(text: str) -> bool:
    r"""``<div[^>]+id=["'](root|app|__next|__nuxt|application|main-content)["'][^>]*>\s*</div>``"""
    for end, gt in _tags(text, _DIV_OPEN_RE):
        if gt < 0:
            return False  # the tag never ends, and the pattern needs its ``>``
        if _MOUNT_ID_RE.search(text, end + 1, gt) and _EMPTY_DIV_BODY_RE.match(text, gt + 1):
            return True
    return False


def _comment_then_script(text: str, start: int) -> bool:
    r"""``<!--.*?-->\s*</div>\s*(?:<[^>]+>\s*){0,3}<script`` anchored at ``start``, where ``<!--``
    is: some ``-->`` after the comment's own dashes, then ``</div>``, then the rest."""
    pos = start + 4
    while True:
        m = _COMMENT_END_THEN_CLOSE_DIV_RE.search(text, pos)
        if m is None:
            return False
        if _UP_TO_SCRIPT_RE.match(text, m.end()):
            return True
        pos = m.start() + 1


def _has_mount_then_script(text: str) -> bool:
    r"""``<div[^>]+id=["'](root|app|__next|__nuxt)["'][^>]*>\s*(?:<!--.*?-->\s*)?</div>\s*
    (?:<[^>]+>\s*){0,3}<script``"""
    # Once the comment branch has failed at one place it fails at every later one: the ``-->``
    # candidates after a later ``<!--`` are a subset of the ones that were just exhausted.
    comment_dead = False
    for end, gt in _tags(text, _DIV_OPEN_RE):
        if gt < 0:
            return False
        if not _FRAMEWORK_MOUNT_ID_RE.search(text, end + 1, gt):
            continue
        after_tag = _skip_ws(text, gt + 1)
        if text.startswith("<!--", after_tag):  # then ``</div>`` cannot be right here
            if comment_dead:
                continue
            if _comment_then_script(text, after_tag):
                return True
            comment_dead = True
            continue
        close = _CLOSE_DIV_RE.match(text, after_tag)
        if close and _UP_TO_SCRIPT_RE.match(text, close.end()):
            return True
    return False


def _has_api_doc_spa(text: str) -> bool:
    r"""``<redoc\b|<div[^>]+id=["']redoc["']|<rapi-doc\b|id=["']swagger-ui["']\s*>\s*</div>
    |Redoc\.init\(|SwaggerUIBundle\(``"""
    if _API_DOC_MARKERS_RE.search(text):
        return True
    for end, gt in _tags(text, _DIV_OPEN_RE):
        if _REDOC_ID_RE.search(text, end + 1, len(text) if gt < 0 else gt):
            return True
    return False


def _has_noscript_demand(text: str) -> bool:
    r"""``<noscript[^>]*>(?:(?!</noscript>).){0,600}(?:enable\s+javascript|...)``: a demand phrase
    that starts within 600 characters of the ``<noscript ...>`` tag and not behind its
    ``</noscript>``."""
    # The first ``</noscript>`` / demand phrase at or after the latest ``lo``.  The ``lo`` only
    # grow, so a cached position stays right until ``lo`` passes it: every ``search`` runs forward
    # once.
    closing = demand = -1
    for _, gt in _tags(text, _NOSCRIPT_OPEN_RE):
        if gt < 0:
            return False
        lo = gt + 1
        if closing < lo:
            m = _NOSCRIPT_CLOSE_RE.search(text, lo)
            closing = m.start() if m else _NEVER
        if demand < lo:
            m = _JS_DEMAND_RE.search(text, lo)
            demand = m.start() if m else _NEVER
        if demand <= min(lo + _NOSCRIPT_WINDOW, closing):
            return True
    return False


def detect_js_dependency(
    status: int,
    headers: dict[str, str],
    body: str,
    *,
    url: str = "",
) -> JsAssessment:
    """Decide whether this HTML needs a browser to yield readable content.

    Returns ``required=True, confidence="high"`` when any single hard signal
    fires, or ``required=True, confidence="low"`` when two or more soft signals
    fire.  A single soft signal is not enough: `<noscript>enable javascript`
    appears on plenty of server-rendered pages as a progressive-enhancement
    courtesy.

    Non-HTML bodies always return ``required=False`` -- an llms.txt cannot need
    JS, and running this on a 4.3 MB text file would be pure waste.
    """
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type and content_type not in ("text/html", "application/xhtml+xml"):
        return JsAssessment(False, "high", ("non_html_body",), len(body), len(body))

    text = visible_text(body)
    vlen, rlen = len(text), len(body)
    hard: list[str] = []
    soft: list[str] = []

    has_script_src = _has_script_src(body)

    # HARD 1: big markup, no prose.  spoton / lawmatics.
    if vlen < EMPTY_SHELL_TEXT_LEN and has_script_src and rlen > 5 * max(vlen, 1):
        hard.append(f"empty_shell(visible={vlen},raw={rlen})")

    # HARD 2: the mount point is empty in the served HTML.
    if _has_mount_then_script(body) or (vlen < THIN_TEXT_LEN and _has_empty_mount(body)):
        hard.append("empty_spa_mount")

    # HARD 3: API-reference SPAs render entirely client-side.
    if _has_api_doc_spa(body):
        hard.append("api_doc_spa(redoc/swagger/rapidoc)")

    # SOFT signals
    if _has_noscript_demand(body):
        soft.append("noscript_demands_js")
    if _NUXT_RE.search(body):
        soft.append("nuxt_client_only")
    if _NEXT_DATA_RE.search(body) and not _CONTENT_ELEMENT_RE.search(body):
        soft.append("next_data_without_content_elements")
    # rlen guard: a small page is just a small page.  A shell is *big* markup
    # with no prose, which is what the ratio below actually tests.
    if vlen < THIN_TEXT_LEN and has_script_src and rlen > 3000:
        soft.append(f"thin_text({vlen})")
    if not _CONTENT_ELEMENT_RE.search(body) and rlen > 2000:
        soft.append("no_content_elements")

    if hard:
        return JsAssessment(True, "high", tuple(hard + soft), vlen, rlen)
    if len(soft) >= 2:
        return JsAssessment(True, "low", tuple(soft), vlen, rlen)
    return JsAssessment(False, "high", tuple(soft), vlen, rlen)


RENDER_FLAG_MESSAGE = (
    "--render 需要 Playwright，v1 不内置。原因：\n"
    "  1. 合规约束明确写了不绕 WAF、不解 CAPTCHA，无头浏览器正是最容易越界的工具；\n"
    "  2. uvx 一行可跑是硬需求，Playwright 要额外 ~300MB 的 `playwright install`；\n"
    "  3. 实测只有 2/72 = 2.8% 的域因纯 JS 文档站产生盲区（spoton、lawmatics），\n"
    "     且 v1 的两项检查都不读渲染后的正文（llms.txt 是文本文件，死链看状态码）。\n"
    "v1 的处理方式是检测并声明：需要 JS 的页面一律进报告的「未能评估」区，"
    "绝不计入「未发现问题」。"
)
