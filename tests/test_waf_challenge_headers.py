"""WAF / CDN 挑战页：靠**响应头**认，不靠状态码、不靠正文。

## 为什么要有这个文件

``is_blocked`` 原来只看三样东西：一张拦截型状态码名单、一组挑战页**正文**指纹、429 / 登录路径。
**响应头从来不读。** 于是 AWS WAF 的 Challenge 动作 —— 厂商文档写明答 **HTTP 202** 加响应头
``x-amzn-waf-action: challenge`` —— 两头都漏：

* 202 不在拦截状态名单里（它是「成功」状态）；
* 请求的 Accept 不含 ``text/html``（我们对文本文件就是这样）时，AWS **不发任何挑战页正文**，
  正文指纹什么也看不到。

修复前同一个 202 挑战，在 llms.txt 位置：空正文 → 判 **OK**（假通过）；带 HTML 壳 → 判
**SOFT404 / html_where_text_expected**（假的 HIGH 指控）。dead_links 把 202 一律算存活，
被挑战的根路径还会被当成「同 host 活着」的证据，让一条诚实的 404 变成 **DEAD**。

真实数据：``tests/data/aws_waf_challenge_app.baseten.co_2026-10-07.json`` 是 2026-10-07 对
app.baseten.co 的两次真实抓取（202 + 头；``Accept: text/html`` 得 2 KB 的 JS 挑战页，
``Accept: text/plain`` 得 0 字节）。**那个站正是 dead_links.py 里「202 算 ALIVE」那条的出处
—— 今天实测它的 202 是挑战页，不是内容；当年那批 202 很可能是同一回事，但没有冻结的响应可核对，
这是推断。** 所以这里不再有「某个站真的返回没有挑战头的 202 内容页」这种前提：「没有头的 202
仍按原样处理」守的只是**不要把状态码 202 本身当成挑战的证据**。

不碰网络；真实快照那条走 ``fixtures/``。
"""

from __future__ import annotations

import json
import sys
import time
import types
from pathlib import Path

import httpx
import pytest

from geo_audit.checks.dead_links import (
    LinkState,
    LinkVerdict,
    _is_challenge,
    classify_link,
    is_dead,
)
from geo_audit.fetch import fingerprints as fp
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.classify import challenge_header, classify_response, is_blocked
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import FixtureStore
from geo_audit.models import (
    NOT_EVALUATED_REASONS,
    UNKNOWN_REMEDY,
    Expect,
    HttpResponse,
    LinkContext,
    Probe,
    Status,
    Verdict,
    verdict_to_status,
)

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))

import refresh_fixtures  # noqa: E402

AWS = {"x-amzn-waf-action": "challenge"}
AWS_SHELL = (
    "<html><head><script src='https://x.token.awswaf.com/challenge.js'></script></head>"
    "<body><noscript>JavaScript is disabled</noscript></body></html>"
)
CF_BODY = (
    "<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"
)
REAL = json.loads(
    (REPO / "tests/data/aws_waf_challenge_app.baseten.co_2026-10-07.json").read_text("utf-8")
)


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """限速下限（2s）是合规约束，测试里不能调低 —— 记录要睡多久，但不真睡。"""
    slept: list[float] = []
    fake = types.SimpleNamespace(monotonic=time.monotonic, sleep=slept.append)
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time", fake)
    return slept


# ── challenge_header：只认厂商文档里写明的那两个头，值逐 token 比 ─────────────
@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"cf-mitigated": "challenge"}, ("cf-mitigated", "challenge")),
        ({"x-amzn-waf-action": "challenge"}, ("x-amzn-waf-action", "challenge")),
        ({"x-amzn-waf-action": "captcha"}, ("x-amzn-waf-action", "captcha")),
        # 头名和值都不分大小写
        ({"CF-Mitigated": "Challenge"}, ("cf-mitigated", "challenge")),
        ({"X-Amzn-Waf-Action": " CAPTCHA "}, ("x-amzn-waf-action", "captcha")),
        # 逗号分隔的多值：任一 token 命中即可
        ({"cf-mitigated": "foo, challenge"}, ("cf-mitigated", "challenge")),
        ({"x-vercel-mitigated": "challenge"}, ("x-vercel-mitigated", "challenge")),
        # 同名头被合并成一行时（"challenge, challenge"）
        ({"x-amzn-waf-action": "challenge, challenge"}, ("x-amzn-waf-action", "challenge")),
    ],
)
def test_challenge_header_positive(headers: dict[str, str], expected: tuple[str, str]) -> None:
    assert challenge_header(headers) == expected


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"cf-ray": "8a1b2c3d4e5f-SIN"},  # 只是走了 Cloudflare，不代表被挑战
        {"server": "cloudflare", "cf-cache-status": "HIT"},
        {"x-amzn-waf-action": "allow"},  # 不是文档里的值
        {"x-amzn-waf-action": "count"},
        {"cf-mitigated": "block"},  # 文档说唯一合法值是 challenge
        {"cf-mitigated": "notchallenge"},  # 子串陷阱：必须是整个 token
        {"cf-mitigated": ""},
        {"x-amzn-requestid": "challenge"},  # 值对、头名不对
        {"x-vercel-mitigated": "deny"},  # deny 是 403 拦截，状态码本来就判被拦；只认 challenge
        {"x-vercel-id": "sin1::abc"},  # 只是走了 Vercel
    ],
)
def test_challenge_header_negative(headers: dict[str, str]) -> None:
    assert challenge_header(headers) is None


def test_header_table_has_exactly_the_three_anchored_vendors() -> None:
    """表里每一行都要有出处（见 fingerprints.py 的注释：Cloudflare / AWS 有厂商文档，
    Vercel 只有实测），别悄悄多一行。"""
    assert {name for name, _ in fp.CHALLENGE_HEADERS} == {
        "cf-mitigated",
        "x-amzn-waf-action",
        "x-vercel-mitigated",
    }


# ── is_blocked：头先于正文、与状态码无关 ────────────────────────────────────
@pytest.mark.parametrize("status", [200, 202, 403, 405, 503])
def test_is_blocked_by_header_whatever_the_status(status: int) -> None:
    hit = is_blocked(status, AWS, "", url="https://x.test/llms.txt")
    assert hit is not None
    _, reason, evidence = hit
    assert reason == "waf_challenge_header"
    assert "x-amzn-waf-action: challenge" in evidence
    assert f"HTTP {status}" in evidence


def test_header_evidence_beats_body_fingerprint() -> None:
    """头和正文指纹同时命中时，证据要引头：头是厂商保证的，正文只是我们猜的。"""
    hit = is_blocked(403, {"cf-mitigated": "challenge"}, CF_BODY, url="https://x.test/")
    assert hit is not None
    assert "cf-mitigated: challenge" in hit[2]
    assert "指纹" not in hit[2]


def test_the_status_code_202_alone_is_not_evidence_of_a_challenge() -> None:
    """反方向的守卫：只有厂商头才算挑战，状态码 202 本身不算。"""
    page = "<h1>Welcome</h1>" * 50
    assert is_blocked(202, {"content-type": "text/html"}, page, url="https://x.test/") is None
    assert is_blocked(202, {}, "", url="https://x.test/") is None


# ── classify_response：修复前读错的两种形态 ──────────────────────────────────
def test_202_challenge_with_html_shell_is_blocked_not_a_soft404() -> None:
    c = classify_response(
        202,
        {"content-type": "text/html", **AWS},
        AWS_SHELL,
        url="https://x.test/llms.txt",
        expect=Expect.TEXT_FILE,
    )
    assert c.verdict is Verdict.BLOCKED  # 修复前：SOFT404 / html_where_text_expected
    assert c.reason == "waf_challenge_header"
    assert "挑战页" in c.evidence[0]


def test_202_challenge_with_empty_body_is_blocked_not_ok() -> None:
    """请求的 Accept 不含 text/html 时 AWS 不发正文 —— 修复前这里是**假通过**。"""
    for expect in (Expect.TEXT_FILE, Expect.HTML_PAGE, Expect.ANY):
        c = classify_response(202, dict(AWS), "", url="https://x.test/p", expect=expect)
        assert c.verdict is Verdict.BLOCKED, expect


def test_202_without_the_header_still_classifies_as_before() -> None:
    c = classify_response(
        202,
        {"content-type": "text/plain"},
        "# Docs\n" + "line\n" * 40,
        url="https://x.test/llms.txt",
        expect=Expect.TEXT_FILE,
    )
    assert c.verdict is Verdict.OK


def test_blocked_is_an_unknown_position_with_a_remedy() -> None:
    """被挑战的位置必须落进「未能评估」：判定、状态映射、理由码、补救办法四样都要对。"""
    c = classify_response(
        202, dict(AWS), "", url="https://x.test/llms.txt", expect=Expect.TEXT_FILE
    )
    assert c.verdict is Verdict.BLOCKED
    assert verdict_to_status(c.verdict) is Status.UNKNOWN
    assert c.reason == "waf_challenge_header"
    assert c.reason in NOT_EVALUATED_REASONS
    assert c.reason in UNKNOWN_REMEDY


@pytest.mark.parametrize("status", [200, 202, 204])
def test_naive_text_for_a_blocked_2xx_is_what_a_status_only_checker_would_say(status: int) -> None:
    c = classify_response(status, dict(AWS), "", url="https://x.test/a")
    naive = c.naive_would_say or ""
    assert "2xx" in naive and "存在" in naive


def test_naive_text_for_a_blocked_non_2xx_is_unchanged() -> None:
    c = classify_response(403, {"cf-mitigated": "challenge"}, CF_BODY, url="https://x.test/a")
    assert "死的" in (c.naive_would_say or "")


# ── 真实数据 1：语料里带头的快照。**头本身**必须足够 —— 去掉状态码和正文也要判被拦 ──────
def test_every_frozen_response_carrying_a_challenge_header_is_blocked() -> None:
    store = FixtureStore.default()
    hits = []
    for url in store.snapshots():
        snap = store.get(url)
        if challenge_header(snap.headers) is None:
            continue
        body = store.stored_body(url).decode("utf-8", "replace")
        recorded = classify_response(snap.status, snap.headers, body, url=url, expect=Expect.ANY)
        # 语料里这 9 条原本就是 403 + Cloudflare 正文，状态码和正文单独就能判被拦，
        # 所以只验「录到的样子」不能证明头起了作用。把状态码改成 200、正文清空，只留头：
        header_only = classify_response(200, snap.headers, "", url=url, expect=Expect.ANY)
        hits.append((url, recorded.verdict, header_only.verdict, recorded.reason))
    # 9 条 cf-mitigated（gusto.com ×6、npmjs.com ×2、api.factorialhr.com ×1）+ 3 条
    # x-vercel-mitigated（tenderly.co，429）。
    assert len(hits) >= 12, f"语料里只剩 {len(hits)} 条带挑战头的快照，这条回归失去意义"
    assert [h for h in hits if h[1] is not Verdict.BLOCKED] == []
    assert [h for h in hits if h[2] is not Verdict.BLOCKED] == []
    # 理由也要钉：这些快照以前的理由是 waf_challenge_body（Cloudflare）/ rate_limited（Vercel），
    # 现在是 waf_challenge_header。soft404_expectations.json 的 B19（gusto llms.txt）写的是
    # 手工冻结样本（real_cases.py，没带这个头）的合成判定，不在这里；真实快照只在这里被钉。
    assert [h[0] for h in hits if h[3] != "waf_challenge_header"] == []


# ── 真实数据 2：app.baseten.co 的两次真实抓取（语料里没有任何 x-amzn-waf-action）─────────
@pytest.mark.parametrize("shape", REAL["shapes"], ids=lambda s: s["request_accept"])
@pytest.mark.parametrize("expect", [Expect.TEXT_FILE, Expect.HTML_PAGE, Expect.ANY])
def test_real_aws_waf_challenge_captures_are_blocked(
    shape: dict[str, object], expect: Expect
) -> None:
    headers = {str(k): str(v) for k, v in dict(shape["headers"]).items()}  # type: ignore[call-overload]
    assert challenge_header(headers) == ("x-amzn-waf-action", "challenge")
    c = classify_response(
        int(shape["status"]),  # type: ignore[call-overload]
        headers,
        str(shape["body"]),
        url="https://app.baseten.co/",
        expect=expect,
    )
    # 修复前：text/html 那份判 soft404 / needs_js，text/plain 那份（0 字节）判 ok
    assert c.verdict is Verdict.BLOCKED
    assert c.reason == "waf_challenge_header"


def test_real_capture_through_the_real_fetcher_like_the_server_does() -> None:
    """服务器按请求的 Accept 决定要不要发挑战页正文 —— 照这个行为回放，走 Fetcher.probe。"""
    by_accept = {s["request_accept"]: s for s in REAL["shapes"]}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        shape = by_accept[
            "text/html" if "text/html" in req.headers.get("accept", "") else "text/plain"
        ]
        return httpx.Response(shape["status"], headers=shape["headers"], text=shape["body"])

    f = _fetcher(handler)
    for url, expect in (
        ("https://app.baseten.co/llms.txt", Expect.TEXT_FILE),  # Accept 不含 text/html → 0 字节
        ("https://app.baseten.co/", Expect.HTML_PAGE),  # Accept 含 text/html → 2 KB 挑战页
    ):
        p = f.probe(url, expect=expect)
        assert p.verdict is Verdict.BLOCKED, url
        assert p.classification.reason == "waf_challenge_header", url


# ── 端到端：Fetcher.probe 走真实的抓取层（含对照探针）──────────────────────────
def _fetcher(handler: object) -> Fetcher:
    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )


def _aws_202(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/robots.txt":
        return httpx.Response(404)
    return httpx.Response(202, headers={"x-amzn-waf-action": "challenge"}, text="")


def test_probe_through_the_real_fetcher_is_blocked() -> None:
    p = _fetcher(_aws_202).probe("https://x.test/llms.txt", expect=Expect.TEXT_FILE)
    assert p.verdict is Verdict.BLOCKED
    assert p.classification.reason == "waf_challenge_header"


def test_a_challenged_control_probe_makes_the_host_profile_unusable() -> None:
    profile = _fetcher(_aws_202).host_profile("https://x.test/llms.txt")
    assert profile is not None
    assert profile.usable is False  # 对照探针自己被挑战了，拿它比对没有意义


def test_second_ruler_treats_a_challenged_side_as_incomparable() -> None:
    def resp(status: int, headers: dict[str, str]) -> HttpResponse:
        return HttpResponse(
            url="https://x.test/llms.txt",
            final_url="https://x.test/llms.txt",
            status=status,
            headers=headers,
            body=b"",
        )

    why = Fetcher._ruler_blocked(
        "https://x.test/llms.txt",
        resp(200, {"content-type": "text/plain"}),
        resp(202, dict(AWS)),
    )
    assert why is not None and "第二把尺子" in why


# ── dead_links：被挑战的响应不是「活着」的证据，也不是死 ─────────────────────────
HOST = "https://www.acme-widgets.com"
CHALLENGED = httpx.Response(202, headers=dict(AWS), text="")
ALIVE_PAGE = "<h1>Acme</h1>" + "<p>widgets</p>" * 30


def _classify(
    responses: dict[str, httpx.Response],
    *,
    link: str = f"{HOST}/gone",
    candidates: tuple[str, ...] = (),
) -> LinkVerdict:
    """被测的链接默认是诚实的 404、对照探针也是 404；变量只有「别的路径给什么」。"""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        if req.url.path in responses:
            return responses[req.url.path]
        return httpx.Response(404, text="not found")

    page = f"{HOST}/docs/a"
    with httpx.Client() as client:
        return classify_link(
            link,
            source_page=page,
            ctx=LinkContext(source_page=page, anchor_text="gone"),
            client=client,
            store=FixtureStore.default(),
            fetcher=_fetcher(handler),
            audited_domain="acme-widgets.com",
            confirmation_candidates=candidates,
        )


def test_a_challenged_root_does_not_prove_the_host_is_alive() -> None:
    """修复前：根路径 202 + 头被当成存活对照 → 这条诚实的 404 被判 **DEAD**。"""
    v = _classify({"/": CHALLENGED})
    assert v.state is LinkState.UNKNOWN
    assert v.confirmations == ()


def test_a_challenged_sibling_candidate_does_not_confirm_either() -> None:
    v = _classify({"/": CHALLENGED, "/pricing": CHALLENGED}, candidates=(f"{HOST}/pricing",))
    assert v.state is LinkState.UNKNOWN
    assert v.confirmations == ()


def test_a_challenged_parent_page_does_not_confirm_either() -> None:
    v = _classify({"/": CHALLENGED, "/docs/a/": CHALLENGED}, link=f"{HOST}/docs/a/gone")
    assert v.state is LinkState.UNKNOWN
    assert v.confirmations == ()


@pytest.mark.parametrize(
    ("responses", "kw", "confirmed_by"),
    [
        (
            {"/": httpx.Response(200, headers={"content-type": "text/html"}, text=ALIVE_PAGE)},
            {},
            "/",
        ),
        (
            {"/": CHALLENGED, "/pricing": httpx.Response(200, text=ALIVE_PAGE)},
            {"candidates": (f"{HOST}/pricing",)},
            "/pricing",
        ),
        (
            {"/": CHALLENGED, "/docs/a/": httpx.Response(200, text=ALIVE_PAGE)},
            {"link": f"{HOST}/docs/a/gone"},
            "/docs/a/",
        ),
        # 状态码 202 本身不是挑战的证据 —— 和 main 上的行为一致，只有厂商头才排除
        (
            {"/": httpx.Response(202, headers={"content-type": "text/html"}, text=ALIVE_PAGE)},
            {},
            "/",
        ),
    ],
    ids=["root", "candidate", "parent", "root-202-without-header"],
)
def test_an_honest_alive_page_still_confirms_a_dead_link(
    responses: dict[str, httpx.Response], kw: dict[str, object], confirmed_by: str
) -> None:
    """反方向的守卫：真的活着的页面仍然能证明 404 是真死 —— 别矫枉过正。"""
    v = _classify(responses, **kw)  # type: ignore[arg-type]
    assert v.state is LinkState.DEAD
    assert [u.removeprefix(HOST) for u, _ in v.confirmations] == [confirmed_by]


# 正常页面会内嵌验证码 / 机器人防护厂商的脚本；正文里出现厂商名不等于这页是挑战页。
# （冻结语料对这条是盲的：570 条 2xx 响应在前 20,000 字符里一条都不命中，所以守卫是合成的。）
@pytest.mark.parametrize(
    "widget",
    [
        '<div class="g-recaptcha" data-sitekey="k"></div>',
        '<script src="https://js.datadome.co/tags.js"></script>',
        '<script src="/px/perimeterx/init.js"></script>',
        '<script src="https://hcaptcha.com/captcha/v1/api.js"></script>',
        "<noscript>Just a moment... loading your dashboard</noscript>",
    ],
    ids=["recaptcha", "datadome", "perimeterx", "hcaptcha", "just-a-moment"],
)
def test_a_normal_page_that_embeds_a_bot_vendor_script_still_confirms_a_dead_link(
    widget: str,
) -> None:
    """修复第一版时的回归：用 _is_challenge（含正文指纹）排除存活证据，这些页面就不再算活着，
    真死链从 DEAD 退成 UNKNOWN。现在只看响应头。"""
    root = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text=f"<html><body><h1>Acme</h1>{'<p>widgets</p>' * 30}{widget}</body></html>",
    )
    v = _classify({"/": root})
    assert v.state is LinkState.DEAD
    assert [u.removeprefix(HOST) for u, _ in v.confirmations] == ["/"]


def test_a_link_that_is_itself_challenged_is_unknown_not_alive() -> None:
    """被测链接自己被挑战：修复前 202 当存活（甚至 alive 都不是证据，是「没读到」）。"""
    v = _classify({"/docs/page": CHALLENGED}, link=f"{HOST}/docs/page")
    assert v.state is LinkState.UNKNOWN
    assert v.rule_id in ("waf_challenge", "host_unprobeable")


def test_a_challenged_link_is_never_dead_or_alive() -> None:
    url = "https://x.test/docs/page"
    resp = HttpResponse(url=url, final_url=url, status=202, headers=dict(AWS), body=b"")
    cls = classify_response(202, dict(AWS), "", url=url, expect=Expect.HTML_PAGE)
    probe = Probe(url, Expect.HTML_PAGE, resp, cls)
    assert _is_challenge(probe) is True  # 修复前：202 不在名单里 → False
    assert is_dead(probe, None, (), ()) is False


# ── scripts/refresh_fixtures.py：挑战页不是「内容变了」───────────────────────────
def test_refresh_script_does_not_call_a_challenge_page_drift() -> None:
    """修复前：202 + 头 → state='drifted'，剧本据此把 expect 的 md5 改成挑战页的。"""
    store = FixtureStore.default()
    url = "https://about.pinterest.com/"
    assert store.has(url)

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(202, headers={"content-type": "text/html", **AWS}, text=AWS_SHELL)

    r = refresh_fixtures.check_one(_fetcher(handler), store, url)
    assert r.state == "unreachable"
    assert r.suggested_branch == "unreachable"
