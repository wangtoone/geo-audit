"""厂商名 / 验证码控件的正文指纹，只在响应「长得像拦截页」时才算。

## 修复前

``CHALLENGE_BODY_PATTERNS`` 在**任何状态码**的前 20 KB 里找 ``datadome`` / ``g-recaptcha`` /
``perimeterx`` / ``Just a moment``。可这些词在正常页面上也有：DataDome 的接入方式是把
``js.datadome.co/tags.js`` 放进每个页面，任何带表单的页面都可能有 reCAPTCHA 控件。于是一个
200、正文几千字的正常页面被判成「被拦」进「未能评估」；DataDome / PerimeterX 的客户则是每一页。
连 404 页都带那段脚本：对照探针（同 host 的随机路径，应当 404）被判成「被拦」，整个 host 的位置
全部「无法判断」。

## 现在

这四条（``fingerprints.AMBIGUOUS_BODY_RULES``）只在响应**长得像拦截页**时才算：

* 404 / 410 不算 —— 诚实的「没有这个页面」；
* 其余非 2xx 算；
* 2xx 要整页可见文字不足 ``GATE_PAGE_TEXT_LEN``。

挑战页**独有**的标记在任何状态码、任何长度下都算 —— 包括 ``captcha-delivery.com``（DataDome
挑战 iframe 所在的域）和 ``px-captcha`` / ``_pxhd``（PerimeterX 的验证码容器 / cookie 名）：它们原来
和厂商名写在同一条正则里，整条规则被豁免时被一起豁免了（评审用一个 200、带页眉页脚、带
``captcha-delivery.com`` iframe 的「Verify you are human」页复现）。现在按**标记**拆成独立的规则。

**这里的 HTML 片段是合成的**：冻结语料对这条是盲的（569 条 200 响应里没有一条在前 20,000
字符内命中这些词；13 条命中的响应全是 403）。片段按各厂商公开的接入方式写，不是从某个站抄的。

## 这组测试的结构

``SAMPLES`` 给表里**每一条**规则一个片段，由 ``test_every_rule_has_a_sample...`` 钉住「没有遗漏、
每个片段命中的第一条规则就是它自己」。之后的行为测试都从 ``fp.AMBIGUOUS_BODY_RULES`` 派生，
不再各写一份名单 —— 名单里多一条或少一条，对应的行为测试就会红。
"""

from __future__ import annotations

import time
import types

import httpx
import pytest

from geo_audit.checks.dead_links import LinkState, classify_link
from geo_audit.fetch import fingerprints as fp
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.classify import classify_response, is_blocked
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.normalize import visible_text
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import FixtureStore
from geo_audit.models import Expect, LinkContext, Verdict

SAMPLES: dict[str, str] = {
    "cf_just_a_moment": "<p>Just a moment, loading your dashboard...</p>",
    "cf_browser_verification": "<script>window._cf_chl_opt = {};</script>",
    "cf_attention_required": "<title>Attention Required! | Cloudflare</title>",
    "cf_checking_browser": "<p>Checking your browser before accessing the site</p>",
    "akamai_access_denied": "<h1>Access Denied</h1><p>No access here. Reference #18.2b</p>",
    "incapsula": "<p>Request unsuccessful. Incapsula incident ID: 1</p>",
    "distil_imperva": "<h1>Pardon Our Interruption</h1>",
    "perimeterx_challenge": '<div id="px-captcha"></div>',
    "perimeterx": '<script src="https://client.perimeterx.net/PX1/main.min.js"></script>',
    "datadome_challenge": '<iframe src="https://geo.captcha-delivery.com/captcha/?cid=1"></iframe>',
    "datadome": '<script src="https://js.datadome.co/tags.js" async></script>',
    "recaptcha_gate": '<div class="g-recaptcha" data-sitekey="k"></div>',
    "generic_bot_verification": "<title>Bot Verification</title>",
}
AMBIGUOUS = sorted(fp.AMBIGUOUS_BODY_RULES)
GATE_ONLY = sorted(set(SAMPLES) - fp.AMBIGUOUS_BODY_RULES)

PARAGRAPH = "<p>Real content about widgets and how to order them.</p>"
CHROME = (
    "<header><nav>Home Products Pricing Docs Blog Careers Contact Support Login</nav></header>"
    "<footer>Copyright 2026 Example Inc. All rights reserved. Privacy policy. Terms of service. "
    "Cookie settings. Status page. Security. Accessibility statement. Sitemap.</footer>"
)
URL = "https://x.test/"
BLOCKED = "waf_challenge_body"
#: 非 2xx 里除 404 / 410 之外的、各类拦截页真实会用的状态码（评审：只测 403 / 503，把判据改成
#: ``status in (403, 503)`` / ``>= 400`` / ``!= 200`` 整套件仍然全绿）。
GATE_STATUSES = (301, 302, 401, 403, 429, 451, 500, 502, 503, 999)


def _page(widget: str, *, paragraphs: int) -> str:
    return f"<html><body><h1>Acme</h1>{PARAGRAPH * paragraphs}{widget}</body></html>"


def _tiny(widget: str) -> str:
    return f"<html><body>Please verify you are human. {widget}</body></html>"


@pytest.fixture(autouse=True)
def _fast_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """限速下限是合规约束，测试里不能调低 —— 只让它不真睡。"""
    fake = types.SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=lambda _s: None)
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time", fake)
    monkeypatch.setattr("geo_audit.fetch.client.time", fake)


# ── 结构：表里每条规则都有片段，行为测试都从名单派生 ─────────────────────────────────
def test_every_rule_has_a_sample_and_the_sample_triggers_its_own_rule_first() -> None:
    assert set(SAMPLES) == {rid for rid, _ in fp.CHALLENGE_BODY_PATTERNS}, "表和片段对不上"
    for rid, sample in SAMPLES.items():
        first = next(r for r, pat in fp.CHALLENGE_BODY_PATTERNS if pat.search(sample))
        assert first == rid, f"{rid} 的片段先命中了 {first}"


def test_the_ambiguous_set_is_exactly_the_four_vendor_name_rules() -> None:
    assert {"cf_just_a_moment", "perimeterx", "datadome", "recaptcha_gate"} == (
        fp.AMBIGUOUS_BODY_RULES
    )
    # 挑战页独有的标记按**标记**单独成规则，不能再和厂商名共用一条正则
    assert {"perimeterx_challenge", "datadome_challenge"} <= set(GATE_ONLY)


# ── 歧义标记：正常页面不是挑战页 ───────────────────────────────────────────────
@pytest.mark.parametrize("rid", AMBIGUOUS)
def test_a_long_2xx_page_with_an_ambiguous_marker_is_not_blocked(rid: str) -> None:
    for status in (200, 201, 206):
        assert is_blocked(status, {}, _page(SAMPLES[rid], paragraphs=40), url=URL) is None, status


@pytest.mark.parametrize("rid", AMBIGUOUS)
def test_it_classifies_ok_not_blocked_end_to_end(rid: str) -> None:
    c = classify_response(
        200,
        {"content-type": "text/html"},
        _page(SAMPLES[rid], paragraphs=40),
        url="https://x.test/contact",
        expect=Expect.HTML_PAGE,
    )
    assert c.verdict is not Verdict.BLOCKED  # 修复前：BLOCKED / waf_challenge_body


# ── 歧义标记：真正的拦截页 —— 非 2xx，或页面只有几十个字 ────────────────────────────
@pytest.mark.parametrize("rid", AMBIGUOUS)
@pytest.mark.parametrize("status", GATE_STATUSES)
def test_a_gate_status_with_an_ambiguous_marker_is_still_blocked(rid: str, status: int) -> None:
    hit = is_blocked(status, {}, _page(SAMPLES[rid], paragraphs=40), url=URL)
    assert hit is not None and hit[1] == BLOCKED, status


@pytest.mark.parametrize("rid", AMBIGUOUS)
def test_a_tiny_200_gate_page_is_still_blocked(rid: str) -> None:
    """200 的验证码墙：整页只有一句话 + 控件 —— 这才是挑战页的形状。"""
    hit = is_blocked(200, {}, _tiny(SAMPLES[rid]), url=URL)
    assert hit is not None and hit[1] == BLOCKED


def test_the_visible_text_threshold_is_exact() -> None:
    def page_with_visible(n: int) -> str:
        return f'<html><body>{"a" * n}<div class="g-recaptcha"></div></body></html>'

    assert fp.GATE_PAGE_TEXT_LEN == 200
    assert is_blocked(200, {}, page_with_visible(199), url=URL) is not None
    assert is_blocked(200, {}, page_with_visible(200), url=URL) is None


def test_visible_text_is_measured_on_the_whole_page_not_the_first_20_kb() -> None:
    """很多页面的 <head> 里就有几十 KB 内联脚本，正文在 20 KB 窗口之外 ——
    窗口内的可见文字是 0（厂商脚本在窗口里、正文不在），但这页有很多正文，不是挑战页。

    窗口恰好在一个闭合的 </script> 处结束：否则窗口尾巴上会留下一个没闭合的 <script>，
    它的内容会被当成可见文字，把「只量窗口」这种错误掩盖掉。"""
    parts = ['<html><head><script src="https://js.datadome.co/tags.js"></script>']
    while sum(map(len, parts)) < 19000:
        parts.append("<script>" + "var x=1;" * 100 + "</script>")
    pad = 20000 - sum(map(len, parts))  # >= 183：最后一个脚本把窗口正好补满
    parts.append("<script>" + "x" * (pad - len("<script></script>")) + "</script>")
    prefix = "".join(parts)
    assert len(prefix) == 20000 and prefix.endswith("</script>")
    body = f"{prefix}</head><body>{PARAGRAPH * 40}</body></html>"
    assert "datadome" in body[:20000]  # 厂商名在 20 KB 窗口里
    assert PARAGRAPH not in body[:20000]  # 正文不在
    assert is_blocked(200, {}, body, url=URL) is None


# ── 404 / 410：诚实的「没有这个页面」，哪怕带着厂商脚本 ────────────────────────────────
@pytest.mark.parametrize("rid", AMBIGUOUS)
@pytest.mark.parametrize("status", [404, 410])
def test_an_honest_not_found_page_with_an_ambiguous_marker_is_not_blocked(
    rid: str, status: int
) -> None:
    assert is_blocked(status, {}, _page(SAMPLES[rid], paragraphs=40), url=URL) is None
    assert is_blocked(status, {}, _tiny(SAMPLES[rid]), url=URL) is None  # 短的 404 页也一样


def test_a_site_whose_404_pages_carry_the_vendor_script_still_gets_a_usable_control() -> None:
    """DataDome 的客户连 404 页也带 ``js.datadome.co/tags.js``。修复前：对照探针（同 host 随机路径，
    404）被判「被拦」→ host_profile 不可用 → 真存在的 /llms.txt 判 UNKNOWN（control_unavailable），
    /llms-full.txt 判 BLOCKED，而这个 host 什么都没拦。"""
    not_found = (
        f"<html><head>{SAMPLES['datadome']}</head>"
        f"<body><h1>Page not found</h1>{CHROME}</body></html>"
    )

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        if req.url.path == "/llms.txt":
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                text="# Site\n\n- [Docs](/docs): docs\n",
            )
        return httpx.Response(404, headers={"content-type": "text/html"}, text=not_found)

    f = _fetcher(handler)
    assert f.probe("https://x.test/llms.txt", expect=Expect.TEXT_FILE).verdict is Verdict.OK
    absent = f.probe("https://x.test/llms-full.txt", expect=Expect.TEXT_FILE)
    assert absent.verdict is Verdict.REAL404, (absent.verdict, absent.classification.reason)
    profile = f.host_profile("https://x.test/llms.txt")
    assert profile is not None and profile.usable is True


# ── 挑战页独有的标记：任何状态码、任何长度都算 ──────────────────────────────────────
@pytest.mark.parametrize("rid", GATE_ONLY)
@pytest.mark.parametrize("status", [200, 201, 403, 404, 410, 503])
def test_a_gate_only_marker_counts_at_any_status_and_length(rid: str, status: int) -> None:
    hit = is_blocked(status, {}, _page(SAMPLES[rid], paragraphs=40), url=URL)
    assert hit is not None and hit[1] == BLOCKED and rid in hit[2], (rid, status)


@pytest.mark.parametrize(
    ("rid", "interstitial"),
    [
        (
            "datadome_challenge",
            f"<html><body>{CHROME}<h1>Verify you are human</h1><p>Complete the check to continue."
            f"</p>{SAMPLES['recaptcha_gate']}{SAMPLES['datadome_challenge']}</body></html>",
        ),
        (
            "perimeterx_challenge",
            f"<html><body>{CHROME}<p>Press and hold to confirm you are human.</p>"
            f"{SAMPLES['perimeterx_challenge']}</body></html>",
        ),
    ],
    ids=["datadome", "perimeterx"],
)
def test_a_long_200_interstitial_with_a_challenge_only_marker_is_blocked(
    rid: str, interstitial: str
) -> None:
    """评审复现：200 + 页眉页脚（可见文字远超 200）+ captcha-delivery.com / px-captcha。
    修复前这两个标记和厂商名共用一条被整条豁免的正则，于是 HTML 位置判 OK、llms.txt 位置判
    SOFT404 / html_where_text_expected（一条站点并没有的 HIGH 指控）。"""
    assert len(visible_text(interstitial)) > fp.GATE_PAGE_TEXT_LEN  # 钉住前提：页面「够长」
    hit = is_blocked(200, {"content-type": "text/html"}, interstitial, url=URL)
    assert hit is not None and hit[1] == BLOCKED and rid in hit[2]
    for expect, path in ((Expect.HTML_PAGE, ""), (Expect.TEXT_FILE, "llms.txt")):
        c = classify_response(
            200, {"content-type": "text/html"}, interstitial, url=URL + path, expect=expect
        )
        assert c.verdict is Verdict.BLOCKED, (expect, c.verdict, c.reason)


# ── dead_links：这类页面作为链接目标是活的，不是「无法判断」────────────────────────
def _fetcher(handler: object) -> Fetcher:
    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )


def test_a_link_to_a_normal_page_with_a_widget_is_alive() -> None:
    page = _page(SAMPLES["recaptcha_gate"], paragraphs=40)

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        if req.url.path == "/contact":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=page)
        return httpx.Response(404, text="not found")

    f = _fetcher(handler)
    src = "https://www.acme-widgets.com/docs/a"
    with httpx.Client() as client:
        v = classify_link(
            "https://www.acme-widgets.com/contact",
            source_page=src,
            ctx=LinkContext(source_page=src, anchor_text="contact"),
            client=client,
            store=FixtureStore.default(),
            fetcher=f,
            audited_domain="acme-widgets.com",
        )
    assert v.state is LinkState.ALIVE  # 修复前：UNKNOWN / waf_challenge
