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

from .normalize import visible_text
from .models import JsAssessment

#: Below this many visible characters an HTML page carries no readable prose.
#: Calibrated on the two known cases: spoton's help centre extracts to
#: "SpotOn Knowledge Base" (21 chars) and lawmatics' Redoc to
#: "Lawmatics OAuth API v1.22.0" (27 chars).  A genuinely thin but real page
#: (a 404 page, a login page) also lands here, which is fine: those are
#: classified before this runs.
EMPTY_SHELL_TEXT_LEN = 200

#: A page with prose but suspiciously little of it relative to its markup.
THIN_TEXT_LEN = 500

_EMPTY_MOUNT_RE = re.compile(
    r"<div[^>]+id=[\"'](?:root|app|__next|__nuxt|application|main-content)[\"'][^>]*>\s*</div>",
    re.I,
)
_MOUNT_THEN_SCRIPT_RE = re.compile(
    r"<div[^>]+id=[\"'](?:root|app|__next|__nuxt)[\"'][^>]*>\s*(?:<!--.*?-->\s*)?</div>\s*(?:<[^>]+>\s*){0,3}<script",
    re.I | re.S,
)
_API_DOC_SPA_RE = re.compile(
    r"<redoc\b|<div[^>]+id=[\"']redoc[\"']|<rapi-doc\b|id=[\"']swagger-ui[\"']\s*>\s*</div>"
    r"|Redoc\.init\(|SwaggerUIBundle\(",
    re.I,
)
_NOSCRIPT_DEMAND_RE = re.compile(
    r"<noscript[^>]*>(?:(?!</noscript>).){0,600}"
    r"(?:enable\s+javascript|requires\s+javascript|javascript\s+(?:is\s+)?(?:required|disabled)"
    r"|需要?启用\s*javascript|请开启\s*javascript)",
    re.I | re.S,
)
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=", re.I)
_NUXT_RE = re.compile(r"window\.__NUXT__|data-server-rendered=[\"']false[\"']", re.I)
_NEXT_DATA_RE = re.compile(r"id=[\"']__NEXT_DATA__[\"']", re.I)
_CONTENT_ELEMENT_RE = re.compile(r"<(?:p|li|h2|h3|article|table|dd)\b", re.I)


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

    has_script_src = bool(_SCRIPT_SRC_RE.search(body))

    # HARD 1: big markup, no prose.  spoton / lawmatics.
    if vlen < EMPTY_SHELL_TEXT_LEN and has_script_src and rlen > 5 * max(vlen, 1):
        hard.append(f"empty_shell(visible={vlen},raw={rlen})")

    # HARD 2: the mount point is empty in the served HTML.
    if _MOUNT_THEN_SCRIPT_RE.search(body) or (
        _EMPTY_MOUNT_RE.search(body) and vlen < THIN_TEXT_LEN
    ):
        hard.append("empty_spa_mount")

    # HARD 3: API-reference SPAs render entirely client-side.
    if _API_DOC_SPA_RE.search(body):
        hard.append("api_doc_spa(redoc/swagger/rapidoc)")

    # SOFT signals
    if _NOSCRIPT_DEMAND_RE.search(body):
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
