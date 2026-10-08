"""两处「读它的人得到的是假话」的清理。

## 一、``HttpResponse.blocked`` 从没被置过 True

字段注释写的是「is_blocked() 的结论，供 .md 子检查等直接用」，``md_convention`` 读它、
报告 JSON 里每个 ``response`` 都带它 —— 可全仓没有任何地方写它，缓存也不存它。于是 ``.md``
子检查拿到一个被挑战的 200 响应时，``md.blocked`` 恒为 False，会继续往下判成 ``SOFT_404_HTML``
（「声明了 .md 却没兑现」的假指控）。现在抓取层在出口统一算一次（缓存命中的响应也补上）。

**线上行为的变化（评审要求写明）**：这个字段现在是完整的 ``is_blocked`` 结论，所以读它的地方都变了：
报告 JSON 里的 ``apex_www.*.response.blocked``、``judge_md_sample``（被拦的样本判 UNDETERMINED）、
``scripts/refresh_fixtures.py``（405 / 451 / 999 这些状态码现在也算「拿不到」，
不再当「内容变了」）。
挑战页独有的正文指纹在任何长度下都算，所以一页很长、恰好引用了「Pardon Our Interruption」的正常
文档，也会得到 blocked=True（方向是「无法判断」）。**``geo-audit page`` 不用这个字段**，仍只认响应头
（评审指出：它会把一个普通 403 说成「命中防火墙特征」，还会拒绝评估引用了挑战页措辞的长页面）。

## 二、replay 里没录过的链接被记成 ALIVE

lenient 回放给没录过的 URL 一个合成的 ``599 + x-geo-audit-fixture: missing``，分类是
UNKNOWN/not_fetched；可 ``dead_links.classify_link`` 只处理了「_probe 返回 None」那一种，
合成 599 一路走到 ``state = DEAD if dead else ALIVE``，被记成 ALIVE（reason 仍写着 not_fetched）。
合成 599 只存在于 replay，所以这一条不影响线上结果。
"""

from __future__ import annotations

import time
import types

import httpx
import pytest

from geo_audit.checks.ai_path import judge_md_sample
from geo_audit.checks.dead_links import LinkState, LinkVerdict, classify_link
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import FixtureStore
from geo_audit.models import LinkContext

AWS = {"x-amzn-waf-action": "challenge"}
CF_WALL = (
    "<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"
)
LONG_WITH_WIDGET = (
    "<html><body><h1>Contact</h1>"
    + "<p>Real content about widgets and ordering.</p>" * 40
    + '<div class="g-recaptcha"></div></body></html>'
)


@pytest.fixture(autouse=True)
def _fast_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=lambda s: None)
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time", fake)
    monkeypatch.setattr("geo_audit.fetch.client.time", fake)


def _fetcher(handler: object) -> Fetcher:
    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )


def _serving(response: httpx.Response) -> Fetcher:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404) if req.url.path == "/robots.txt" else response

    return _fetcher(handler)


# ── 一、blocked 字段 ────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("response", "blocked"),
    [
        (httpx.Response(202, headers=AWS, text=""), True),  # AWS WAF Challenge：202 + 头 + 空正文
        (httpx.Response(403, headers={"content-type": "text/html"}, text=CF_WALL), True),
        (
            httpx.Response(200, headers={"content-type": "text/html"}, text=CF_WALL),
            True,
        ),  # 200 的短墙
        (httpx.Response(429, headers={"retry-after": "30"}, text=""), True),
        (httpx.Response(200, headers={"content-type": "text/html"}, text=LONG_WITH_WIDGET), False),
        (httpx.Response(200, headers={"content-type": "text/plain"}, text="# Docs\n" * 50), False),
        (httpx.Response(404, text="not found"), False),
    ],
    ids=["aws-202", "cf-403", "short-200-wall", "429", "long-page-with-widget", "plain-200", "404"],
)
def test_fetch_fills_the_blocked_field(response: httpx.Response, blocked: bool) -> None:
    f = _serving(response)
    resp = f.fetch("https://x.test/page", expect=None)  # type: ignore[arg-type]
    assert resp.blocked is blocked  # 修复前：恒为 False


def test_a_cache_hit_is_marked_too() -> None:
    """缓存不存这个字段：命中的响应要在出口补上，否则第二次读到的是 False。"""
    f = _serving(httpx.Response(202, headers=AWS, text=""))
    first = f.fetch("https://x.test/page")
    second = f.fetch("https://x.test/page")
    assert second.from_cache is True
    assert first.blocked is True and second.blocked is True


def test_the_known_bot_hostile_skip_is_blocked() -> None:
    f = _serving(httpx.Response(200, text="never requested"))
    resp = f.fetch("https://www.linkedin.com/company/x")
    assert resp.status == 403 and resp.blocked is True


def test_a_transport_error_is_not_blocked() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        raise httpx.ConnectTimeout("boom")

    resp = _fetcher(handler).fetch("https://x.test/page")
    assert resp.status == 0 and resp.blocked is False


# ── 读它的人：md_convention ─────────────────────────────────────────────────
def test_a_challenged_md_sample_is_undetermined_not_a_false_soft_404() -> None:
    """修复前：200 + 挑战页（是 HTML）→ SOFT_404_HTML →「声明了 .md 却没兑现」的假指控。"""
    f = _serving(httpx.Response(200, headers={"content-type": "text/html"}, text=CF_WALL))
    md = f.fetch("https://x.test/pricing.md")
    assert md.blocked is True
    assert judge_md_sample(md, None, None) == "UNDETERMINED"


def test_an_honest_markdown_sample_is_still_fulfilled() -> None:
    body = "# Pricing\n\nPro is $20 per month.\n" * 80
    f = _serving(httpx.Response(200, headers={"content-type": "text/markdown"}, text=body))
    md = f.fetch("https://x.test/pricing.md")
    assert md.blocked is False
    assert judge_md_sample(md, None, None) == "FULFILLED"


# ── 读它的人：geo-audit page 与刷新脚本 ──────────────────────────────────────
def _page_run(response: httpx.Response, url: str = "https://x.test/contact") -> tuple[int, str]:
    import contextlib
    import io

    from geo_audit.pagecli import run

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = run(
            [url, "--contact", "ci@geo-audit.invalid", "--h1-contains", "Contact"],
            fetcher=_serving(response),
        )
    return rc, out.getvalue()


def test_page_does_not_claim_a_fingerprint_hit_for_a_plain_403() -> None:
    """评审复现：``blocked`` 现在是完整的 is_blocked 结论，普通 403 / 429 / 401 也是 True。
    page 若读它，就把「只有状态码」说成「命中防火墙 / 验证码挑战页的特征」—— 一句没发生过的话。"""
    for status in (401, 403, 429, 451):
        resp = httpx.Response(status, headers={"content-type": "text/html"}, text="Forbidden")
        rc, out = _page_run(resp)
        assert rc == 3 and f"HTTP {status}，不是一个可读的页面" in out, (status, out)
        assert "命中" not in out and "特征" not in out, (status, out)


def test_page_still_names_the_challenge_header() -> None:
    rc, out = _page_run(httpx.Response(202, headers=AWS, text=""))
    assert rc == 3 and "被站方拦截" in out and "x-amzn-waf-action: challenge" in out


def test_page_still_evaluates_a_long_normal_page_that_quotes_a_challenge_phrase() -> None:
    """评审复现：一页 1800 字的正常文档，正文里引用了「Pardon Our Interruption」。page 读完整的
    is_blocked 会 rc 3、每条期望都是「?」；上游（PR #13 之前的）行为是照常评估。"""
    page = (
        "<html><body><h1>Contact</h1>"
        + "<p>How to fix Cloudflare errors.</p>" * 60
        + "<p>Pardon Our Interruption</p></body></html>"
    )
    rc, out = _page_run(httpx.Response(200, headers={"content-type": "text/html"}, text=page))
    assert rc == 0 and "✓ H1 含「Contact」" in out and "被站方拦截" not in out


def test_page_does_not_say_it_fingerprinted_a_host_it_never_asked() -> None:
    """已知对 bot 一律 403 的站点（linkedin 等）：Fetcher 不发请求、自己合成一个 403。"""
    rc, out = _page_run(
        httpx.Response(200, text="never requested"), url="https://www.linkedin.com/company/x"
    )
    assert rc == 3 and "命中" not in out


def test_refresh_script_treats_a_short_wall_as_unreachable_but_a_changed_page_as_drift() -> None:
    import sys
    from pathlib import Path

    scripts = str(Path(__file__).resolve().parent.parent / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import refresh_fixtures

    store = FixtureStore.default()
    url = "https://about.pinterest.com/"
    wall = httpx.Response(200, headers={"content-type": "text/html"}, text=CF_WALL)
    assert refresh_fixtures.check_one(_serving(wall), store, url).state == "unreachable"
    changed = httpx.Response(200, headers={"content-type": "text/html"}, text=LONG_WITH_WIDGET)
    assert refresh_fixtures.check_one(_serving(changed), store, url).state == "drifted"


@pytest.mark.parametrize("status", [402, 405, 407, 451, 999])
def test_refresh_script_treats_every_blocked_status_as_unreachable(status: int) -> None:
    """原来只有 (401, 403, 429) 当「拿不到」，405 / 451 / 999 会被当成「内容变了」，剧本随后会把
    expect 的 md5 改成那个拦截页的。现在认 is_blocked 的整张状态表。"""
    import sys
    from pathlib import Path

    scripts = str(Path(__file__).resolve().parent.parent / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import refresh_fixtures

    store = FixtureStore.default()
    resp = httpx.Response(status, headers={"content-type": "text/html"}, text="blocked")
    found = refresh_fixtures.check_one(_serving(resp), store, "https://about.pinterest.com/")
    assert found.state == "unreachable"


# ── 字段的边角：重定向、截断、请求的 URL、没有 Fetcher 的探测 ────────────────────────────
def test_a_redirected_response_that_ends_in_a_challenge_is_marked() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        if req.url.path == "/old":
            return httpx.Response(301, headers={"location": "https://x.test/new"})
        return httpx.Response(202, headers=AWS, text="")

    resp = _fetcher(handler).fetch("https://x.test/old")
    assert resp.redirects and resp.final_url.endswith("/new") and resp.blocked is True


def test_a_truncated_liveness_response_is_marked_too() -> None:
    body = "x" * 200_000
    resp = _serving(httpx.Response(202, headers=AWS, text=body)).fetch(
        "https://x.test/page", liveness_only=True
    )
    assert resp.body_truncated is True and resp.blocked is True


def test_blocked_uses_the_requested_url_like_the_classifier_does() -> None:
    """请求 x.test/a，跳到已知对 bot 敌对的域名、那边回 502：``classify_response`` 拿的是**请求的**
    URL（x.test 不在敌对名单上）→ 不判被拦；这个字段必须同口径，否则同一条响应两处说两样。"""
    from geo_audit.fetch.classify import classify_response
    from geo_audit.models import Expect, Verdict

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        if req.url.host == "x.test":
            return httpx.Response(302, headers={"location": "https://www.linkedin.com/y"})
        return httpx.Response(502, text="bad gateway")

    resp = _fetcher(handler).fetch("https://x.test/a")
    assert resp.final_url == "https://www.linkedin.com/y" and resp.status == 502
    cls = classify_response(
        resp.status,
        resp.headers,
        resp.text,
        url=resp.url,
        expect=Expect.ANY,
        final_url=resp.final_url,
        redirects=resp.redirects,
    )
    assert (cls.verdict is Verdict.BLOCKED) == resp.blocked
    assert resp.blocked is False


def test_the_fetcherless_probe_fills_blocked_too() -> None:
    """``dead_links._probe_with_client`` 自己拼 HttpResponse，原来写死 blocked=False
    （没有生产调用方，但标题说「blocked 说真话」就不该留一个说假话的构造点）。"""
    from geo_audit.checks.dead_links import _probe_with_client
    from geo_audit.models import Expect

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/c":
            return httpx.Response(202, headers=AWS, text="")
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="fine")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        blocked = _probe_with_client(client, "https://x.test/c", expect=Expect.ANY)
        fine = _probe_with_client(client, "https://x.test/ok", expect=Expect.ANY)
    assert blocked.response is not None and blocked.response.blocked is True
    assert fine.response is not None and fine.response.blocked is False


# ── 二、replay 缺快照 ≠ 存活 ────────────────────────────────────────────────
HOST = "https://www.acme-widgets.com"


def _classify_with(handler: object, link: str, ctx: LinkContext | None = None) -> LinkVerdict:
    page = f"{HOST}/docs/a"
    with httpx.Client() as client:
        return classify_link(
            link,
            source_page=page,
            ctx=ctx or LinkContext(source_page=page, anchor_text="x"),
            client=client,
            store=FixtureStore.default(),
            fetcher=_fetcher(handler),
            audited_domain="acme-widgets.com",
        )


def _classify(
    responses: dict[str, httpx.Response], link: str, ctx: LinkContext | None = None
) -> LinkVerdict:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        return responses.get(req.url.path, httpx.Response(404, text="not found"))

    return _classify_with(handler, link, ctx)


MISSING = httpx.Response(599, headers={"x-geo-audit-fixture": "missing"}, text="")


def test_an_unrecorded_link_is_unknown_not_alive() -> None:
    v = _classify({"/gone": MISSING}, f"{HOST}/gone")
    assert v.state is LinkState.UNKNOWN  # 修复前：ALIVE（reason 却写着 not_fetched）
    assert v.reason == "not_fetched"


def test_real_alive_and_real_dead_links_are_unchanged() -> None:
    ok = httpx.Response(200, headers={"content-type": "text/html"}, text=LONG_WITH_WIDGET)
    assert _classify({"/ok": ok, "/": ok}, f"{HOST}/ok").state is LinkState.ALIVE
    assert _classify({"/": ok}, f"{HOST}/gone").state is LinkState.DEAD


def test_real_unknowns_keep_their_own_reason_they_are_not_unrecorded_links() -> None:
    """``not_fetched`` 只来自 fixture 层的那个合成响应头。超时、线上碰巧回 599 的站点都是**别的**
    UNKNOWN，要保留各自的理由 —— 评审的变异「任何 UNKNOWN 都当 not_fetched」「按 status == 599 判」
    原来只有 fp_gate 一条测试咬得住。"""

    def timeout(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        raise httpx.ConnectTimeout("boom")

    slow = _classify_with(timeout, f"{HOST}/slow")
    assert (slow.state, slow.reason) == (LinkState.UNKNOWN, "timeout")

    # 线上碰巧回 599 的站点（没有 fixture 头）：它的判定是另一回事，但**不是** not_fetched
    odd = _classify({"/odd": httpx.Response(599, text="odd")}, f"{HOST}/odd")
    assert odd.reason != "not_fetched"


def test_an_unrecorded_link_keeps_everything_the_normal_path_would_have_recorded() -> None:
    """提前返回不能丢字段：needs_review 的 pre 规则（隐藏锚点）、规则 id、花掉的请求数、位置类别
    都要带上（评审：把 requests_spent / disposition / confidence 删掉整套件仍然全绿）。"""
    ctx = LinkContext(
        source_page=f"{HOST}/docs/a",
        anchor_text="x",
        anchor_html='<a class="nav-link hidden" href="x">x</a>',
    )
    v = _classify({"/gone": MISSING}, f"{HOST}/gone", ctx=ctx)
    assert (v.state, v.reason) == (LinkState.UNKNOWN, "not_fetched")
    assert (v.rule_id, v.disposition, v.confidence) == (
        "class_hidden_anchor",
        "needs_review",
        "needs_review",
    )
    assert v.requests_spent == 1 and v.position_class is not None and v.exclusions
