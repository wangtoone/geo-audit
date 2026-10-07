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
于是被挑战的链接被算成「活着」。

这里的每条用例对应上面某一种读错；「没有响应头的 202 仍然是内容」那几条守的是反方向
（``app.baseten.co`` 的真实页面就返回 202，不能把所有 202 都当挑战）。

不碰网络；真实快照那条走 ``fixtures/``。
"""

from __future__ import annotations

import time
import types

import httpx
import pytest

from geo_audit.checks.dead_links import _is_challenge, is_dead
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
    Probe,
    Verdict,
)

AWS = {"x-amzn-waf-action": "challenge"}
AWS_SHELL = (
    "<html><head><script src='https://x.token.awswaf.com/challenge.js'></script></head>"
    "<body><noscript>JavaScript is disabled</noscript></body></html>"
)
CF_BODY = (
    "<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"
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
    ],
)
def test_challenge_header_negative(headers: dict[str, str]) -> None:
    assert challenge_header(headers) is None


def test_header_table_is_exactly_the_two_documented_vendors() -> None:
    """表里每一行都要有厂商文档与实测出处（见 fingerprints.py 的注释），别悄悄多一行。"""
    assert {name for name, _ in fp.CHALLENGE_HEADERS} == {"cf-mitigated", "x-amzn-waf-action"}


# ── is_blocked：头先于正文、与状态码无关 ────────────────────────────────────
@pytest.mark.parametrize("status", [200, 202, 403, 405, 503])
def test_is_blocked_by_header_whatever_the_status(status: int) -> None:
    hit = is_blocked(status, AWS, "", url="https://x.test/llms.txt")
    assert hit is not None
    _, reason, evidence = hit
    assert reason == "waf_challenge_body"
    assert "x-amzn-waf-action: challenge" in evidence
    assert f"HTTP {status}" in evidence


def test_header_evidence_beats_body_fingerprint() -> None:
    """头和正文指纹同时命中时，证据要引头：头是厂商保证的，正文只是我们猜的。"""
    hit = is_blocked(
        403,
        {"cf-mitigated": "challenge"},
        CF_BODY,
        url="https://x.test/",
    )
    assert hit is not None
    assert "cf-mitigated: challenge" in hit[2]
    assert "指纹" not in hit[2]


def test_a_plain_202_is_still_content() -> None:
    """反方向的守卫：app.baseten.co 的真实页面就返回 202（dead_links.py 里有这条出处）。"""
    assert (
        is_blocked(
            202, {"content-type": "text/html"}, "<h1>Welcome</h1>" * 50, url="https://x.test/"
        )
        is None
    )
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
    assert c.reason == "waf_challenge_body"
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


def test_blocked_lands_in_the_not_evaluated_region_with_a_remedy() -> None:
    c = classify_response(
        202, dict(AWS), "", url="https://x.test/llms.txt", expect=Expect.TEXT_FILE
    )
    assert c.reason in NOT_EVALUATED_REASONS
    assert c.reason in UNKNOWN_REMEDY


def test_naive_text_matches_what_a_status_only_checker_would_have_said() -> None:
    ok = classify_response(202, dict(AWS), "", url="https://x.test/a")
    assert "2xx" in (ok.naive_would_say or "") and "存在" in (ok.naive_would_say or "")
    # 403 的老读法不变
    old = classify_response(403, {"cf-mitigated": "challenge"}, CF_BODY, url="https://x.test/a")
    assert "死的" in (old.naive_would_say or "")


# ── 真实快照：语料里带这个头的响应必须都判成「被拦」────────────────────────────
def test_every_frozen_response_carrying_a_challenge_header_is_blocked() -> None:
    store = FixtureStore.default()
    hits = []
    for url in store.snapshots():
        snap = store.get(url)
        if challenge_header(snap.headers) is None:
            continue
        body = store.stored_body(url).decode("utf-8", "replace")
        c = classify_response(snap.status, snap.headers, body, url=url, expect=Expect.TEXT_FILE)
        hits.append((url, c.verdict))
    assert len(hits) >= 9, f"语料里只剩 {len(hits)} 条带挑战头的快照，这条回归失去意义"
    assert [h for h in hits if h[1] is not Verdict.BLOCKED] == []


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
    assert p.classification.reason == "waf_challenge_body"


def test_a_challenged_control_probe_makes_the_host_profile_unusable() -> None:
    f = _fetcher(_aws_202)
    profile = f.host_profile("https://x.test/llms.txt")
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


# ── dead_links：被挑战的链接既不是死的、也不是活的 ────────────────────────────
def test_a_challenged_link_is_neither_dead_nor_alive() -> None:
    url = "https://x.test/docs/page"
    resp = HttpResponse(url=url, final_url=url, status=202, headers=dict(AWS), body=b"")
    cls = classify_response(202, dict(AWS), "", url=url, expect=Expect.HTML_PAGE)
    probe = Probe(url, Expect.HTML_PAGE, resp, cls)
    assert _is_challenge(probe) is True  # 修复前：202 不在名单里 → False → 当成存活
    assert is_dead(probe, None, (), ()) is False
