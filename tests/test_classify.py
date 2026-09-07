"""Classifier tests, driven entirely by the 72-domain run.

Acceptance thresholds are the measured ones:
  * 16/16 confirmed soft404s must be re-judged soft404  (false negatives = 0)
  * 20/20 confirmed real files must NOT be judged soft404 (false positives = 0)
  * every blocked case must be BLOCKED, never dead      (this is the 40.5% ->
    0% de-noise result, restated at the classifier level)
"""

from __future__ import annotations

import time

import pytest

from geo_audit.fetch.classify import (
    classify_response,
    find_notfound_copy,
    find_platform_missing,
    looks_like_html,
    redirect_discarded_path,
)
from geo_audit.fetch.jsrender import detect_js_dependency
from geo_audit.fetch.models import Expect, HostProfile, RedirectHop, Verdict
from geo_audit.fetch.normalize import (
    NORM_BODY_CAP,
    normalize_body,
    norm_sha256,
    similarity,
    structural_fingerprint,
)

from .fixtures import real_cases as rc


def _expect_for(url: str) -> Expect:
    path = url.split("?")[0]
    if path.endswith((".txt", ".md", ".xml")):
        return Expect.TEXT_FILE
    return Expect.HTML_PAGE


def _control_from(spec: dict | None) -> HostProfile | None:
    if spec is None:
        return None
    body = str(spec["body"])
    norm = normalize_body(body)
    struct_sha, struct_tags = structural_fingerprint(body)
    return HostProfile(
        host="control.invalid",
        probe_url=str(spec["probe_url"]),
        status=int(spec["status"]),  # type: ignore[arg-type]
        content_type=str(spec["content_type"]),
        norm_sha256=norm_sha256(body),
        norm_len=len(norm),
        norm_body_prefix=norm[:NORM_BODY_CAP],
        struct_sha256=struct_sha,
        struct_tags=struct_tags,
        final_path=str(spec["final_path"]),
        status_discriminates=bool(spec["status_discriminates"]),
        control_is_html=bool(spec["control_is_html"]),
        usable=bool(spec["usable"]),
        probed_at=time.time(),
    )


def _run(case: rc.Case):
    return classify_response(
        case.status,
        case.headers,
        case.body,
        url=case.url,
        expect=_expect_for(case.url),
        final_url=case.final_url or case.url,
        redirects=tuple(RedirectHop(*h) for h in case.redirects),
        control=_control_from(case.control),
    )


# --------------------------------------------------------------------------- #
# The headline acceptance tests
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", rc.ALL_CASES, ids=lambda c: c.name)
def test_every_real_case_classifies_as_measured(case: rc.Case) -> None:
    cls = _run(case)
    assert cls.verdict.value == case.expect_verdict, (
        f"{case.name}: 期望 {case.expect_verdict}，实得 {cls.verdict.value}"
        f"（reason={cls.reason}）\n证据：{cls.evidence}\n背景：{case.note}"
    )
    assert cls.reason == case.expect_reason, (
        f"{case.name}: reason 期望 {case.expect_reason}，实得 {cls.reason}"
    )


def test_soft404_recall_is_16_of_16() -> None:
    """FEATURE-PRIORITY.md §5: 16/16 判软 404 抽验成立。假阴性必须为 0。"""
    cases = rc.SOFT404_CASES + rc.CONTROL_ONLY_CASES
    assert len(cases) >= 16, "fixture 数量少于实测的 16 个软 404 位置"
    misses = [c.name for c in cases if _run(c).verdict is not Verdict.SOFT404]
    assert misses == [], f"漏判的软 404：{misses}"


def test_real_files_are_never_condemned() -> None:
    """20/20 反向验证：真文件一个都不能被判成软 404 或死链。"""
    bad = [
        (c.name, _run(c).verdict.value)
        for c in rc.REAL_FILE_CASES
        if _run(c).verdict is not Verdict.OK
    ]
    assert bad == [], f"真文件被误判：{bad}"


def test_blocked_never_becomes_dead() -> None:
    """去噪的核心：403/429/999/400/挑战页一律 BLOCKED。

    实测：10 个域因反爬被整体换掉；gusto 403 与 pipedrive 429 背后的文件都是
    真的。误判成死链会毁掉报告（去噪前假阳性 40.5%）。
    """
    for case in rc.BLOCKED_CASES:
        cls = _run(case)
        assert cls.verdict is Verdict.BLOCKED, f"{case.name} 未判 BLOCKED"
        assert not cls.evaluated, f"{case.name} 必须计入「未能评估」"


def test_server_error_is_unknown_not_dead() -> None:
    for case in rc.UNKNOWN_CASES:
        cls = _run(case)
        assert cls.verdict is Verdict.UNKNOWN
        assert cls.reason == "server_error"
        assert not cls.evaluated


# --------------------------------------------------------------------------- #
# The specific traps, each one named after the site that set it
# --------------------------------------------------------------------------- #


def test_brevo_docs_44_byte_soft404_survives_correct_content_type() -> None:
    """content-type 检查抓不到的那个变体。

    developers.brevo.com/docs/llms.txt = 200 + text/plain + 44 字节
    「# Page Not Found  This page does not exist.」
    """
    cls = classify_response(
        200,
        {"content-type": "text/plain; charset=utf-8"},
        "# Page Not Found\n\nThis page does not exist.",
        url="https://developers.brevo.com/docs/llms.txt",
        expect=Expect.TEXT_FILE,
    )
    assert cls.verdict is Verdict.SOFT404
    assert cls.reason == "notfound_copy_in_body"
    # 而同一 host 的 /llms.txt 是真文件，必须判 ok
    real = classify_response(
        200,
        {"content-type": "text/plain; charset=utf-8"},
        rc._real_llmstxt("brevo", urls=90),
        url="https://developers.brevo.com/llms.txt",
        expect=Expect.TEXT_FILE,
    )
    assert real.verdict is Verdict.OK


def test_snipcart_correct_404_status_beats_spa_body() -> None:
    """状态码正确时，正文形态不参与判定。

    snipcart.com/llms.txt 与 docs.snipcart.com/llms.txt 都是 404 + Nuxt SPA
    兜底页。报告原文：「判真 404 不判 soft404」。
    """
    cls = classify_response(
        404,
        {"content-type": "text/html; charset=utf-8"},
        rc._spa_shell("Snipcart", size=12000),
        url="https://snipcart.com/llms.txt",
        expect=Expect.TEXT_FILE,
    )
    assert cls.verdict is Verdict.REAL404
    assert cls.reason == "status_404"


def test_notfound_copy_window_does_not_condemn_a_real_llmstxt() -> None:
    """窗口机制的存在理由：真 llms.txt 经常链到标题含 404 的页面。"""
    body = rc._real_llmstxt("acme", urls=60) + (
        "\n- [Handling 404 errors](https://docs.acme.com/errors/404.md): "
        "what to do when a page is not found in your integration."
    )
    assert find_notfound_copy(body) is None
    cls = classify_response(
        200, {"content-type": "text/plain"}, body,
        url="https://docs.acme.com/llms.txt", expect=Expect.TEXT_FILE,
    )
    assert cls.verdict is Verdict.OK


def test_short_body_scans_whole_text_not_just_window() -> None:
    """44 字节的软 404 整体扫，长文件只扫开头。"""
    assert find_notfound_copy("# Page Not Found\n\nThis page does not exist.") is not None
    assert find_notfound_copy("Not found") is not None


def test_minimax_moonshot_need_the_control_probe() -> None:
    """L2 抓不到、只有对照探测抓得到的两例。

    两家的 llms.txt 都是 200 + text/html，如果按 HTML_PAGE 判（比如死链检查
    里遇到普通页面），deterministic 规则全不命中，必须靠对照。
    """
    for case in rc.CONTROL_ONLY_CASES:
        without = classify_response(
            case.status, case.headers, case.body, url=case.url,
            expect=Expect.HTML_PAGE, control=None,
        )
        assert without.verdict is not Verdict.SOFT404, (
            f"{case.name}: 没有对照探测时不该、也不能判 soft404"
        )
        with_ctl = classify_response(
            case.status, case.headers, case.body, url=case.url,
            expect=Expect.HTML_PAGE, control=_control_from(case.control),
        )
        assert with_ctl.verdict is Verdict.SOFT404
        assert with_ctl.reason == "identical_to_control"


def test_discriminating_control_protects_real_files() -> None:
    """18 个 host 的反向验证形态：真文件 200 text/plain，对照 404 text/html。"""
    control = _control_from(
        {
            "probe_url": "https://docs.mistral.ai/geo-audit-probe-x.txt",
            "status": 404, "content_type": "text/html",
            "body": "<html><title>Page Not Found</title><body>404</body></html>",
            "status_discriminates": True, "control_is_html": True, "usable": True, "final_path": "/probe.txt",
        }
    )
    cls = classify_response(
        200, {"content-type": "text/plain"}, rc._real_llmstxt("mistral", urls=75),
        url="https://docs.mistral.ai/llms.txt", expect=Expect.TEXT_FILE, control=control,
    )
    assert cls.verdict is Verdict.OK
    assert cls.control_discriminates is True


def test_unusable_control_degrades_to_unknown_not_ok() -> None:
    """对照探测自己被拦时，不能默认「真文件」。"""
    control = _control_from(
        {
            "probe_url": "https://gusto.com/geo-audit-probe-y.txt",
            "status": 403, "content_type": "text/html",
            "body": "Just a moment...",
            "status_discriminates": False, "control_is_html": True, "usable": False, "final_path": "/probe.txt",
        }
    )
    cls = classify_response(
        200, {"content-type": "text/plain"}, "x" * 5000,
        url="https://gusto.com/llms.txt", expect=Expect.TEXT_FILE, control=control,
    )
    assert cls.verdict is Verdict.UNKNOWN
    assert cls.reason == "control_unavailable"
    assert not cls.evaluated


def test_byte_length_is_never_a_decision_input() -> None:
    """三处字节数复测对不上（printful 42108/268184、saleor 864/2043、
    commercelayer 3598/9051），所以同一份内容不同长度必须得到同一判定。"""
    small = rc._real_llmstxt("saleor", urls=5)
    large = rc._real_llmstxt("saleor", urls=500)
    a = classify_response(200, {"content-type": "text/plain"}, small,
                          url="https://saleor.io/llms.txt", expect=Expect.TEXT_FILE)
    b = classify_response(200, {"content-type": "text/plain"}, large,
                          url="https://saleor.io/llms.txt", expect=Expect.TEXT_FILE)
    assert a.verdict is b.verdict is Verdict.OK


def test_redirect_to_site_root_is_soft404_but_same_path_hop_is_not() -> None:
    """跳转判定看路径，不看 host。

    api-docs.ecwid.com/llms.txt -> docs.ecwid.com/ 是软 404；
    spoton 的 3 条内链 301 到更具体的页面，是正常存活。
    """
    discarded = redirect_discarded_path(
        "https://api-docs.ecwid.com/llms.txt",
        "https://docs.ecwid.com/",
        (RedirectHop(302, "https://api-docs.ecwid.com/llms.txt", "https://docs.ecwid.com/"),),
    )
    assert discarded is not None and discarded[0] == "redirect_to_site_root"

    kept = redirect_discarded_path(
        "https://spoton.com/small-business/",
        "https://spoton.com/small-business/pos-terminal/",
        (RedirectHop(301, "https://spoton.com/small-business/",
                     "https://spoton.com/small-business/pos-terminal/"),),
    )
    assert kept is None

    apex_to_www = redirect_discarded_path(
        "https://unkey.com/docs/platform/workspaces/billing",
        "https://www.unkey.com/docs/platform/workspaces/billing",
        (RedirectHop(308, "https://unkey.com/docs/platform/workspaces/billing",
                     "https://www.unkey.com/docs/platform/workspaces/billing"),),
    )
    assert apex_to_www is None, "apex->www 同路径跳转不是软 404"


def test_brevo_apex_vercel_deployment_not_found() -> None:
    hit = find_platform_missing(
        "The deployment could not be found on Vercel.\n\nDEPLOYMENT_NOT_FOUND"
    )
    assert hit is not None and hit[0] == "vercel_deployment_not_found"


def test_naive_would_say_is_populated_on_every_soft404() -> None:
    """报告首页的那句话必须有据可依：每个软 404 都要能说出"朴素实现会怎么读"。"""
    for case in rc.SOFT404_CASES + rc.CONTROL_ONLY_CASES + rc.APEX_CASES:
        cls = _run(case)
        assert cls.naive_would_say, f"{case.name} 缺少 naive_would_say"


def test_naive_root_only_checker_error_rate_matches_measurement() -> None:
    """把「朴素 checker」量化：只探根路径 + 只看状态码，在 fixture 上的错判率。

    实测口径 >=20/72 = 27.8%。这里断言的是同一现象在 fixture 集合上必然出现，
    而不是复现那个百分数（fixture 不是 72 个域的随机样本）。
    """
    naive_wrong = 0
    for case in rc.SOFT404_CASES + rc.CONTROL_ONLY_CASES:
        naive_says_ok = 200 <= case.status < 300
        if naive_says_ok and _run(case).verdict is Verdict.SOFT404:
            naive_wrong += 1
    assert naive_wrong >= 14, (
        f"只有 {naive_wrong} 例朴素实现会读错，低于实测的 14/16 量级"
    )


# --------------------------------------------------------------------------- #
# JS detection -- the false-zero guard
# --------------------------------------------------------------------------- #


def test_js_shell_becomes_unknown_never_ok() -> None:
    for case in rc.JS_REQUIRED_CASES:
        cls = _run(case)
        assert cls.verdict is Verdict.UNKNOWN, f"{case.name} 判成了 {cls.verdict}"
        assert cls.reason == "needs_js"
        assert cls.needs_js is True
        assert not cls.evaluated, "needs_js 必须计入「未能评估」"


def test_spoton_help_center_detected() -> None:
    case = rc.JS_REQUIRED_CASES[0]
    js = detect_js_dependency(200, case.headers, case.body, url=case.url)
    assert js.required and js.confidence == "high"
    assert js.visible_text_len < 200


def test_redoc_spa_detected() -> None:
    case = rc.JS_REQUIRED_CASES[1]
    js = detect_js_dependency(200, case.headers, case.body, url=case.url)
    assert js.required
    assert any("api_doc_spa" in s for s in js.signals)


def test_server_rendered_page_is_not_flagged_js() -> None:
    body = (
        "<!DOCTYPE html><html><head><title>Pricing</title>"
        '<script src="/analytics.js"></script></head><body>'
        "<h1>Pricing</h1><p>Simple, transparent pricing for teams of every size. "
        "Start free and upgrade whenever you need more.</p>"
        "<table><tr><td>Free</td><td>$0</td></tr><tr><td>Pro</td><td>$29</td></tr></table>"
        "<ul><li>Unlimited projects</li><li>Priority support</li></ul>"
        "<noscript>Please enable JavaScript for the interactive calculator.</noscript>"
        "</body></html>"
    )
    js = detect_js_dependency(200, {"content-type": "text/html"}, body)
    assert not js.required, f"服务端渲染页被误判需要 JS：{js.signals}"


def test_text_file_never_triggers_js_check() -> None:
    js = detect_js_dependency(
        200, {"content-type": "text/plain"}, rc._real_llmstxt("acme", 200)
    )
    assert not js.required
    assert js.signals == ("non_html_body",)


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #


def test_normalization_makes_nonce_bearing_shells_identical() -> None:
    """SPA 外壳每次请求换 nonce/build hash，不归一化就比不出相同。"""
    a = rc._spa_shell("MiniMax", size=4000, nonce="aaaabbbbccccddd1")
    b = rc._spa_shell("MiniMax", size=4000, nonce="1111222233334441")
    assert a != b
    assert norm_sha256(a) == norm_sha256(b)
    assert structural_fingerprint(a)[0] == structural_fingerprint(b)[0]


def test_two_different_empty_shells_are_not_confused() -> None:
    """最危险的假阳性：不同站点的空外壳归一化后都接近空串。

    没有骨架指纹和长度门槛，它们会互判「与对照相同」。
    """
    minimax = rc._spa_shell("MiniMax", size=38405)
    moonshot = rc._spa_shell("Moonshot AI", size=8246)
    assert structural_fingerprint(minimax)[0] != structural_fingerprint(moonshot)[0]

    control = _control_from(
        {
            "probe_url": "https://www.minimax.io/geo-audit-probe-z.txt",
            "status": 200, "content_type": "text/html",
            "body": minimax,
            "status_discriminates": False, "control_is_html": True, "usable": True, "final_path": "/probe.txt",
        }
    )
    # moonshot 的壳拿 minimax 的对照来比，不能判成软 404
    cls = classify_response(
        200, {"content-type": "text/html"}, moonshot,
        url="https://www.moonshot.ai/some-page", expect=Expect.HTML_PAGE, control=control,
    )
    assert cls.verdict is not Verdict.SOFT404, f"跨站外壳被误判：{cls.reason}"


def test_empty_body_never_matches_a_control() -> None:
    """空响应体归一化后是空串，绝不能与任何对照「相同」。"""
    control = _control_from(
        {
            "probe_url": "https://example.invalid/geo-audit-probe-q",
            "status": 200, "content_type": "text/html",
            "body": "",
            "status_discriminates": False, "control_is_html": True, "usable": True, "final_path": "/probe",
        }
    )
    cls = classify_response(
        200, {"content-type": "text/html"}, "",
        url="https://example.invalid/page", expect=Expect.HTML_PAGE, control=control,
    )
    assert cls.verdict is not Verdict.SOFT404


def test_similarity_ignores_tiny_bodies() -> None:
    """44 字节的软 404 必须走文案规则，不能走相似度——短串的 difflib 比值虚高。"""
    assert similarity("# Page Not Found", "# Page Not Found") == 0.0
    text_heavy = rc._real_llmstxt("acme", urls=40)
    assert similarity(text_heavy, text_heavy) == 1.0


def test_normalize_is_idempotent() -> None:
    body = rc._spa_shell("Y", size=3000)
    once = normalize_body(body)
    assert normalize_body(once) == once


def test_looks_like_html_by_shape_when_content_type_lies() -> None:
    """有 host 用 text/plain 送 HTML 外壳，形状判定必须兜住。"""
    assert looks_like_html("<!DOCTYPE html><html><body>x</body></html>", "text/plain")
    assert not looks_like_html("# Real llms.txt\n\n- [a](b)", "text/plain")
