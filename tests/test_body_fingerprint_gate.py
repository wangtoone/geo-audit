"""厂商名 / 验证码控件的正文指纹，只在响应「长得像拦截页」时才算。

## 修复前

``CHALLENGE_BODY_PATTERNS`` 在**任何状态码**的前 20 KB 里找 ``datadome`` / ``g-recaptcha`` /
``perimeterx`` / ``Just a moment``。可这些词在正常页面上也有：DataDome 的接入方式是把
``js.datadome.co/tags.js`` 放进每个页面，任何带表单的页面都可能有 reCAPTCHA 控件。于是一个
200、正文几千字的正常页面被判成「被拦」进「未能评估」；DataDome / PerimeterX 的客户则是每一页。

## 现在

这四条（``fingerprints.AMBIGUOUS_BODY_RULES``）只在**状态码不是 2xx，或整页可见文字不足
``GATE_PAGE_TEXT_LEN``** 时才算。挑战页独有的标记（``cf_chl_opt`` 等）仍然在任何状态码、任何
长度下都算。

**这里的 HTML 片段是合成的**：冻结语料对这条是盲的（569 条 200 响应里没有一条在前 20,000
字符内命中这些词）。片段按各厂商公开的接入方式写，不是从某个站抄的。
"""

from __future__ import annotations

import httpx
import pytest

from geo_audit.checks.dead_links import LinkState, classify_link
from geo_audit.fetch import fingerprints as fp
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.classify import classify_response, is_blocked
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import FixtureStore
from geo_audit.models import Expect, LinkContext, Verdict

WIDGETS = {
    "recaptcha": '<div class="g-recaptcha" data-sitekey="k"></div>',
    "datadome": '<script src="https://js.datadome.co/tags.js" async></script>',
    "perimeterx": '<script src="https://client.perimeterx.net/PX1/main.min.js"></script>',
    "hcaptcha": '<script src="https://hcaptcha.com/captcha/v1/api.js"></script>',
    "just-a-moment": "<p>Just a moment, loading your dashboard...</p>",
}
PARAGRAPH = "<p>Real content about widgets and how to order them.</p>"


def _page(widget: str, *, paragraphs: int) -> str:
    return f"<html><body><h1>Acme</h1>{PARAGRAPH * paragraphs}{widget}</body></html>"


@pytest.fixture(params=list(WIDGETS), ids=list(WIDGETS))
def widget(request: pytest.FixtureRequest) -> str:
    return WIDGETS[request.param]


# ── 正常页面：长内容 + 内嵌控件，不是挑战页 ─────────────────────────────────────
def test_a_normal_page_embedding_the_widget_is_not_blocked(widget: str) -> None:
    assert (
        is_blocked(
            200, {"content-type": "text/html"}, _page(widget, paragraphs=40), url="https://x.test/"
        )
        is None
    )


def test_it_classifies_ok_not_blocked_end_to_end(widget: str) -> None:
    c = classify_response(
        200,
        {"content-type": "text/html"},
        _page(widget, paragraphs=40),
        url="https://x.test/contact",
        expect=Expect.HTML_PAGE,
    )
    assert c.verdict is not Verdict.BLOCKED  # 修复前：BLOCKED / waf_challenge_body


# ── 真正的拦截页：状态码非 2xx，或页面只有几十个字 ─────────────────────────────────
def test_a_non_2xx_response_with_the_widget_is_still_blocked(widget: str) -> None:
    for status in (403, 503):
        hit = is_blocked(status, {}, _page(widget, paragraphs=40), url="https://x.test/")
        assert hit is not None and hit[1] == "waf_challenge_body", status


def test_a_tiny_200_gate_page_is_still_blocked(widget: str) -> None:
    """200 的验证码墙：整页只有一句话 + 控件 —— 这才是挑战页的形状。"""
    tiny = f"<html><body>Please verify you are human. {widget}</body></html>"
    hit = is_blocked(200, {}, tiny, url="https://x.test/")
    assert hit is not None and hit[1] == "waf_challenge_body"


def test_the_visible_text_threshold_is_exact() -> None:
    def page_with_visible(n: int) -> str:
        return f'<html><body>{"a" * n}<div class="g-recaptcha"></div></body></html>'

    assert fp.GATE_PAGE_TEXT_LEN == 200
    assert is_blocked(200, {}, page_with_visible(199), url="https://x.test/") is not None
    assert is_blocked(200, {}, page_with_visible(200), url="https://x.test/") is None


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
    assert is_blocked(200, {}, body, url="https://x.test/") is None


# ── 挑战页独有的标记：任何状态码、任何长度都算（与原来一致）──────────────────────────
@pytest.mark.parametrize(
    "marker",
    [
        "<script>window._cf_chl_opt = {};</script>",
        "<title>Attention Required! | Cloudflare</title>",
        "<h1>Pardon Our Interruption</h1>",
        "<p>Request unsuccessful. Incapsula incident ID: 1</p>",
        "<title>Bot Verification</title>",
        "<p>Checking your browser before accessing the site</p>",
    ],
    ids=[
        "cf_chl_opt",
        "attention-required",
        "imperva",
        "incapsula",
        "bot-verification",
        "checking",
    ],
)
def test_unambiguous_challenge_markers_apply_at_any_length(marker: str) -> None:
    long_page = _page(marker, paragraphs=40)
    hit = is_blocked(200, {}, long_page, url="https://x.test/")
    assert hit is not None and hit[1] == "waf_challenge_body"


def test_the_ambiguous_set_is_exactly_the_four_vendor_name_rules() -> None:
    expected = {"cf_just_a_moment", "perimeterx", "datadome", "recaptcha_gate"}
    assert expected == fp.AMBIGUOUS_BODY_RULES
    ids = {rid for rid, _ in fp.CHALLENGE_BODY_PATTERNS}
    assert ids >= fp.AMBIGUOUS_BODY_RULES  # 名单里的规则 id 必须真的存在，别拼错


# ── dead_links：这类页面作为链接目标是活的，不是「无法判断」────────────────────────
def test_a_link_to_a_normal_page_with_a_widget_is_alive() -> None:
    page = _page(WIDGETS["recaptcha"], paragraphs=40)

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        if req.url.path == "/contact":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=page)
        return httpx.Response(404, text="not found")

    f = Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )
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
