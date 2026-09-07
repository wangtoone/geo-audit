"""The soft-404 classifier.  This is the single most load-bearing function in
the tool: every other check reads its output, so a misjudgement here poisons
the whole report.

Contract
--------
    classify_response(status, headers, body, *, url, expect, ...) -> Classification

Precedence, first match wins:

    L0  BLOCKED   -- WAF / rate limit / auth gate.  Evaluated FIRST so a
                     challenge page can never become "dead".
    L1  REAL404   -- status 404 or 410, whatever the body says.
    L1b UNKNOWN   -- 5xx without a challenge body: "cannot tell", not "dead".
    L2  SOFT404   -- deterministic, no control probe needed:
                     (a) HTML where a text file was expected
                     (b) not-found copy at the top of the body
                     (c) redirect threw the path away (site root / generic landing)
                     (d) hosting-platform "deployment missing" page
    L3  SOFT404   -- via the same-host control probe:
                     (i)  normalized sha256 identical to control
                     (ii) same status + same content-type + similarity > 0.90
    L4  UNKNOWN   -- needs_js (HTML shell with no prose)
    L5  OK

Two rules that were explicitly deleted from the earlier draft, and why:

* "status + content-type + byte length, any one equal to the control => soft404"
  is wrong on its face.  When both target and control return 200, "status
  equal" is always true, so every real file would be condemned.  The measured
  0% false-positive rate (n=36) proves the code never implemented the
  documented rule.  L3 below requires *body* agreement, always.

* Byte length is not evidence.  FEATURE-PRIORITY.md §5 re-measured 12 byte
  counts and 3 did not reproduce (printful 42108 vs 268184, saleor 864 vs 2043,
  commercelayer 3598 vs 9051).  Byte length is display metadata only.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import fingerprints as fp
from .jsrender import detect_js_dependency
from .normalize import (
    MIN_SIMILARITY_LEN,
    MIN_STRUCT_TAGS,
    SIMILARITY_THRESHOLD,
    normalize_body,
    norm_sha256,
    similarity_norm,
    structural_fingerprint,
)
from .models import (
    Classification,
    Expect,
    HostProfile,
    HttpResponse,
    RedirectHop,
    Verdict,
)

_HTML_START_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<\?xml[^>]*\?>\s*<html\b)", re.I)
_SERVER_ERROR = frozenset({500, 502, 503, 504, 507, 508, 520, 521, 522, 523, 524, 525, 526, 527, 530})


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _path_of(url: str) -> str:
    parts = urlsplit(url)
    return parts.path or "/"


def _registrable_suffix_match(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def looks_like_html(body: str, content_type: str) -> bool:
    """HTML by declaration or by shape.

    Shape matters because some hosts serve an HTML shell with content-type
    text/plain.  Declaration matters because some serve real markdown with a
    text/html content-type.  Either is enough to call it HTML for the purpose
    of "you promised me a text file".
    """
    if content_type in ("text/html", "application/xhtml+xml"):
        return True
    return bool(_HTML_START_RE.match(body[:2048]))


def is_blocked(
    status: int,
    headers: dict[str, str],
    body: str,
    *,
    url: str,
) -> tuple[bool, str, str] | None:
    """L0.  Returns (True, reason, evidence) or None.

    Runs before everything else on purpose.  Anchors from the 72-domain run:
      gusto.com/llms.txt          403 + Cloudflare "Just a moment..."  (file is REAL)
      www.pipedrive.com/llms.txt  429                                  (file is REAL)
      support.goshippo.com        403 x7  (Zendesk)
      help.printify.com           403 x7  (Zendesk)
      linkedin.com/company/...    999
      facebook.com/<page>         400
      api.factorialhr.com/.../sign_in  403 (auth endpoint)
    Ten further domains were dropped from the sample entirely for anti-bot.
    Calling any of these "dead" or "absent" is the reverse twin of the
    soft-404 error, and it deflates the adoption number instead of inflating
    it.  Both directions have to be handled or the P0 check lies.
    """
    host = _host_of(url)

    for rule_id, pattern in fp.CHALLENGE_BODY_PATTERNS:
        if pattern.search(body[:20000]):
            return (True, "waf_challenge_body", f"命中反爬挑战页指纹 {rule_id}（HTTP {status}）")

    if status == 429:
        retry_after = headers.get("retry-after", "")
        extra = f"，Retry-After: {retry_after}" if retry_after else ""
        return (True, "rate_limited", f"HTTP 429 限流{extra}")

    if status in (401, 403) and fp.LOGIN_PATH_RE.search(url):
        return (True, "login_required", f"HTTP {status} 且路径是认证端点，非内容页")

    if status in fp.BLOCKED_STATUSES:
        return (True, "waf_status", f"HTTP {status}，判定为被拦截而非死链")

    if status == 400 and host in fp.HOSTILE_400_HOSTS:
        return (True, "waf_status", f"HTTP 400 且目标是已知对 bot 返回 400 的站点（{host}）")

    if status in _SERVER_ERROR and any(
        _registrable_suffix_match(host, s) for s in fp.KNOWN_BOT_HOSTILE_SUFFIXES
    ):
        return (True, "waf_status", f"HTTP {status} 于已知反爬供应商域（{host}）")

    return None


def find_notfound_copy(body: str) -> tuple[str, str] | None:
    """L2(b).  Not-found copy, windowed to the top of the body.

    The window is what makes this safe.  Anchor for why the rule is needed:
      https://developers.brevo.com/docs/llms.txt
        -> 200, content-type text/plain (correct!), 44 bytes,
           body "# Page Not Found  This page does not exist."
    Neither the status check nor the content-type check can see that.

    Anchor for why the window is needed: a real llms.txt is thousands of bytes
    and routinely links to pages whose titles contain "404".  Verified against
    the fixture set -- none of the 20 confirmed-real llms.txt files matches
    inside the first 400 normalized characters.
    """
    norm = normalize_body(body)
    window = norm if len(norm) <= fp.SHORT_BODY_LIMIT else norm[: fp.COPY_WINDOW_CHARS]
    for rule_id, pattern in fp.NOTFOUND_COPY_PATTERNS:
        m = pattern.search(window)
        if m:
            snippet = window[max(0, m.start() - 40) : m.end() + 40].strip()
            return (rule_id, f'正文开头命中「未找到」文案（{rule_id}）：“{snippet}”')
    return None


def find_platform_missing(body: str) -> tuple[str, str] | None:
    """L2(d).  Hosting-platform "this deployment does not exist" pages.

    Anchor: brevo.com apex serves Vercel's plaintext
    "The deployment could not be found on Vercel. DEPLOYMENT_NOT_FOUND"
    on /, /pricing/ and /blog/, while www.brevo.com and
    developers.brevo.com are healthy.  These strings are unambiguous.
    """
    head = body[:8000]
    for rule_id, pattern in fp.PLATFORM_MISSING_PATTERNS:
        if pattern.search(head):
            return (rule_id, f"命中托管平台「部署不存在」页指纹 {rule_id}")
    return None


def redirect_discarded_path(
    url: str, final_url: str, redirects: tuple[RedirectHop, ...]
) -> tuple[str, str] | None:
    """L2(c).  The chain landed somewhere generic while we asked for a path.

    Anchors, all from the confirmed-soft404 set:
      api-docs.ecwid.com/llms.txt        302 -> docs.ecwid.com/          (site root)
      support.freshbooks.com/llms.txt    307 -> /hc/en-us                (help home)
      developers.attio.com/llms.txt      302 -> docs.attio.com/docs/overview
      docs.moderntreasury.com/<any>      302 -> /
      developers.pinterest.com/llms-full.txt -> /
      docs.gusto.com/llms-full.txt       -> site homepage

    A same-path host change (http->https, apex->www) is NOT this: spoton's
    3 internal links 301 to a more specific page and are legitimately alive.
    The test is on the *path*, not on the host.
    """
    if not redirects:
        return None
    req_path = _path_of(url).rstrip("/") or "/"
    final_path = _path_of(final_url).rstrip("/") or "/"
    if req_path == final_path:
        return None
    if final_path in fp.GENERIC_LANDING_PATHS or final_path == "/":
        kind = "redirect_to_site_root" if final_path == "/" else "redirect_to_generic_landing"
        chain = " -> ".join(f"{h.status} {h.to_url}" for h in redirects)
        return (kind, f"请求 {req_path}，最终落在通用落地页 {final_path}（链路：{chain}）")
    return None


def classify_response(
    status: int,
    headers: dict[str, str],
    body: str,
    *,
    url: str,
    expect: Expect = Expect.ANY,
    final_url: str | None = None,
    redirects: tuple[RedirectHop, ...] = (),
    control: HostProfile | None = None,
    transport_error: str | None = None,
    body_truncated: bool = False,
    robots_disallowed: bool = False,
) -> Classification:
    """Classify one HTTP response.

    Parameters
    ----------
    status
        HTTP status of the final response.  ``0`` means the request never
        completed; pass ``transport_error``.
    headers
        Lower-cased header mapping of the final response.
    body
        Decoded body text of the final response.
    url
        The URL as requested (pre-redirect).  Used for path and host rules.
    expect
        See ``Expect``.  ``TEXT_FILE`` turns "served HTML" into sufficient
        evidence on its own -- 14 of the 16 confirmed soft-404s in the
        empirical run are caught by that one rule.
    control
        The host's control profile (what this host does with a path that
        cannot exist).  Optional: L2 works without it, L3 needs it.
    robots_disallowed
        True when robots.txt forbids this URL for our UA and we did not fetch.

    Returns
    -------
    Classification
        ``verdict`` plus a stable ``reason`` code, report-ready ``evidence``,
        and ``naive_would_say`` -- what a checker that only looks at the status
        code on the root path would have concluded.  That last field is what
        the report's headline is built from.
    """
    final_url = final_url or url
    headers = {k.lower(): v for k, v in headers.items()}
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()

    # ---- pre-flight: things that happened instead of a response ----------
    if robots_disallowed:
        return Classification(
            Verdict.UNKNOWN,
            "robots_disallowed",
            (f"robots.txt 禁止抓取 {_path_of(url)}，本位置未评估",),
        )
    if status == 0:
        err = (transport_error or "").lower()
        if "resolve" in err or "nodename" in err or "name or service" in err or "servfail" in err:
            reason = "dns_unresolved"
            ev = f"DNS 解析失败（已换第二解析器复测仍失败）：{transport_error}"
        elif "poison" in err or "private-ip" in err:
            reason = "dns_poisoned"
            ev = f"DNS 返回本地/私有地址，判定为解析污染而非死链：{transport_error}"
        elif "timeout" in err or "timed out" in err:
            reason = "timeout"
            ev = f"请求超时：{transport_error}"
        elif "too many redirects" in err or "maximum redirects" in err:
            reason = "too_many_redirects"
            ev = f"重定向层数超限（多为登录跳转环）：{transport_error}"
        elif "redirect loop" in err:
            reason = "redirect_loop"
            ev = f"重定向成环：{transport_error}"
        else:
            reason = "network_error"
            ev = f"网络错误：{transport_error}"
        return Classification(Verdict.UNKNOWN, reason, (ev,))  # type: ignore[arg-type]

    # ---- L0  blocked -----------------------------------------------------
    blocked = is_blocked(status, headers, body, url=url)
    if blocked is not None:
        _, reason, evidence = blocked
        return Classification(
            Verdict.BLOCKED,
            reason,  # type: ignore[arg-type]
            (evidence, "被拦截 != 不存在：本位置计入「未能评估」，不计入死链也不计入存活"),
            naive_would_say="朴素实现会报「没有这个文件 / 这条链接是死的」",
        )

    # ---- L1  honest 404 --------------------------------------------------
    if status in (404, 410):
        # Body deliberately ignored.  Anchor: snipcart.com/llms.txt and
        # docs.snipcart.com/llms.txt both return status 404 with a Nuxt SPA
        # shell body.  Correct status => real404, never soft404.  Letting the
        # body override a correct status code is how you invent findings.
        return Classification(
            Verdict.REAL404,
            "status_404" if status == 404 else "status_410",
            (f"HTTP {status}（状态码正确，正文形态不参与判定）",),
        )

    # ---- L1b  server error is not death ----------------------------------
    if status in _SERVER_ERROR:
        # Anchors: developers.pinterest.com/llms.txt -> 500;
        # ed.link/docs/platform/rate-limits -> 500.
        return Classification(
            Verdict.UNKNOWN,
            "server_error",
            (f"HTTP {status}，服务端错误，无法判定内容是否存在",),
        )

    if body_truncated:
        return Classification(
            Verdict.UNKNOWN,
            "body_truncated",
            (f"响应体超过读取上限被截断（{len(body)} 字符），不做指纹判定",),
        )

    evidence: list[str] = []

    # ---- L2  deterministic soft404 ---------------------------------------
    # (a) HTML where a text file was promised.
    if expect is Expect.TEXT_FILE and looks_like_html(body, content_type):
        evidence.append(
            f"请求的是文本文件，实际返回 HTML（content-type: {content_type or '未声明'}，"
            f"{len(body)} 字符）"
        )
        js = detect_js_dependency(status, headers, body, url=url)
        if js.required:
            evidence.append(f"且是前端框架外壳：{', '.join(js.signals)}")
        return Classification(
            Verdict.SOFT404,
            "html_where_text_expected",
            tuple(evidence),
            naive_would_say="朴素实现只看 HTTP 200，会判「已采纳 llms.txt」",
            needs_js=js.required,
        )

    # (d) hosting-platform deployment-missing page (checked before copy
    #     patterns because it is more specific and produces a better fix hint)
    plat = find_platform_missing(body)
    if plat is not None:
        _, ev = plat
        return Classification(
            Verdict.SOFT404,
            "platform_deployment_missing",
            (ev, f"HTTP {status}，但正文是托管平台的部署缺失页"),
            naive_would_say="朴素实现只看 HTTP 200，会判「这个域活着」",
        )

    # (b) not-found copy at the top of the body.
    copy = find_notfound_copy(body)
    if copy is not None:
        _, ev = copy
        return Classification(
            Verdict.SOFT404,
            "notfound_copy_in_body",
            (ev, f"HTTP {status}，content-type {content_type or '未声明'}"),
            naive_would_say="朴素实现看状态码 200 + content-type 正确，会判「文件存在」",
        )

    # (c) the redirect chain discarded our path.
    disc = redirect_discarded_path(url, final_url, redirects)
    if disc is not None:
        kind, ev = disc
        return Classification(
            Verdict.SOFT404,
            kind,  # type: ignore[arg-type]
            (ev, "跳转到通用落地页等同于「这个路径不存在」"),
            naive_would_say="朴素实现跟完跳转只看终态 200，会判「文件存在」",
        )

    # ---- L3  control-probe soft404 ---------------------------------------
    if control is not None:
        if not control.usable:
            # The control probe itself was blocked or errored, so comparing to
            # it is meaningless.  Degrade to UNKNOWN, never to OK.
            return Classification(
                Verdict.UNKNOWN,
                "control_unavailable",
                (
                    f"同域对照探测（{control.probe_url}）自身不可用，"
                    "无法判定本响应是真文件还是兜底页",
                ),
                control_used=True,
            )

        # Whether the control discriminates depends on what we asked for.
        #   * A non-2xx control discriminates for every target kind.
        #   * An HTML control discriminates only when a TEXT file was expected
        #     -- a real llms.txt can never be confused with an HTML shell.
        #     When the target is itself an HTML page, an HTML control proves
        #     nothing, and treating it as proof is precisely how the
        #     catch-all-shell hosts (platform.kimi.ai answering
        #     /docs/<anything> with the Quickstart page) would slip through.
        discriminating = control.status_discriminates or (
            expect is Expect.TEXT_FILE and control.control_is_html
        )
        if discriminating:
            evidence.append(
                f"对照探测 {control.probe_url} 返回 HTTP {control.status} / "
                f"{control.content_type or '未声明'}，与本响应可区分，判为真实内容"
            )
            js = detect_js_dependency(status, headers, body, url=url)
            if js.required and expect is Expect.HTML_PAGE:
                return Classification(
                    Verdict.UNKNOWN,
                    "needs_js",
                    tuple(evidence + [f"但正文需要 JS 渲染才可读：{', '.join(js.signals)}"]),
                    needs_js=True,
                    control_used=True,
                    control_discriminates=True,
                )
            return Classification(
                Verdict.OK,
                "ok_control_discriminates",
                tuple(evidence),
                control_used=True,
                control_discriminates=True,
            )

        target_norm = normalize_body(body)
        target_sha = norm_sha256(body)
        target_struct, target_tags = structural_fingerprint(body)

        # (i) Identical to control -- a single sufficient condition, but only
        # when there is enough substance on both sides to identify anything.
        #
        # Two ways to be identical, and both are needed:
        #   * content identity, when the page has real text;
        #   * skeleton identity, when it does not.  An SPA shell strips down to
        #     almost nothing (www.minimax.io's 384 KB shell leaves the <title>
        #     and nothing else), so EVERY empty shell has the same content
        #     digest -- comparing those by content alone would call two
        #     unrelated shells the same page.  The length/tag-count guards are
        #     what stop that.
        #
        # Anchors: www.minimax.io/llms.txt vs /this-does-not-exist-xyz123
        # (both 200, both 384052 B, same shell); www.moonshot.ai/llms.txt vs
        # /nonexistent-xyz-123 (both 200, both 82460 B);
        # platform.kimi.ai/docs/nonsense-xyz vs /docs/overview (both 200,
        # 414072 B, <title>Quickstart - Kimi API Platform</title>).
        content_identical = (
            len(target_norm) >= MIN_SIMILARITY_LEN
            and target_sha == control.norm_sha256
        )
        struct_identical = (
            target_tags >= MIN_STRUCT_TAGS
            and control.struct_tags >= MIN_STRUCT_TAGS
            and target_struct == control.struct_sha256
        )
        if content_identical or struct_identical:
            how = "归一化正文" if content_identical else "HTML 骨架指纹"
            digest = target_sha if content_identical else target_struct
            return Classification(
                Verdict.SOFT404,
                "identical_to_control",
                (
                    f"与同域不存在路径 {control.probe_url} 的{how}完全相同"
                    f"（sha256 {digest[:16]}…，标签数 {target_tags}）",
                    "该 host 对任意路径返回同一个壳，本位置等同不存在",
                ),
                naive_would_say="朴素实现只看 HTTP 200，会判「存在 / 存活」",
                control_used=True,
                control_discriminates=False,
            )

        if status == control.status and content_type == control.content_type:
            ratio = similarity_norm(target_norm, control.norm_body_prefix)
            if ratio > SIMILARITY_THRESHOLD:
                return Classification(
                    Verdict.SOFT404,
                    "near_identical_to_control",
                    (
                        f"与同域不存在路径 {control.probe_url} 状态码与 content-type 相同，"
                        f"归一化正文相似度 {ratio:.3f} > {SIMILARITY_THRESHOLD}",
                    ),
                    naive_would_say="朴素实现只看 HTTP 200，会判「存在 / 存活」",
                    control_used=True,
                    control_discriminates=False,
                )

    # ---- L4  needs JS ----------------------------------------------------
    if expect in (Expect.HTML_PAGE,) and looks_like_html(body, content_type):
        js = detect_js_dependency(status, headers, body, url=url)
        if js.required:
            return Classification(
                Verdict.UNKNOWN,
                "needs_js",
                (
                    f"HTTP {status} 但正文需要 JS 渲染才可读："
                    f"可见文本 {js.visible_text_len} 字符 / 原始 {js.raw_len} 字符；"
                    f"信号：{', '.join(js.signals)}",
                    "本位置计入「未能评估」，不计入「未发现问题」",
                ),
                naive_would_say="朴素实现拿到 200 + 一行标题，会判「这页没问题」",
                needs_js=True,
            )

    # ---- L5  ok ----------------------------------------------------------
    return Classification(
        Verdict.OK,
        "ok",
        tuple(evidence) or (f"HTTP {status} / {content_type or '未声明'}",),
        control_used=control is not None,
        control_discriminates=(
            control.status_discriminates if control else None
        ),
    )




def classify(response: HttpResponse, *, expect: Expect = Expect.ANY,
             control: HostProfile | None = None,
             robots_disallowed: bool = False) -> Classification:
    """Convenience wrapper over ``classify_response`` for an ``HttpResponse``."""
    return classify_response(
        response.status,
        response.headers,
        response.text,
        url=response.url,
        expect=expect,
        final_url=response.final_url,
        redirects=response.redirects,
        control=control,
        transport_error=response.transport_error,
        body_truncated=response.body_truncated,
        robots_disallowed=robots_disallowed,
    )
