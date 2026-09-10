"""robots 两条修复：闸装在 fetch()、以及取不到时按不许抓处理。

## 一、`robots_allows` 原来只有一个调用方

`grep -rn robots_allows src/` 的结果是 **一处**：`client.py` 的 `probe()`。
于是所有走 `fetch()` 的路径都绕过了它：

* `discovery.fetch_sitemap_urls` —— sitemap 与子 sitemap，最多 5+5 条；
* `Fetcher.host_profile` —— 每个 host 的对照探针；
* 录制脚本。

而 `robots_allows` 自己的文档串写的是「honour robots.txt for **everything**
except /robots.txt itself」。**最要紧的情形是 `Disallow: /`**：那样的站原本
仍会被抓 sitemap 与对照探针。

## 二、robots.txt 取不到时一律放行

原来是 `raw = resp.text if resp.status == 200 else ""`，于是 503 / 超时 /
DNS 失败都得到一个空 parser，而空 parser 的 `can_fetch()` 恒为 True ——
**robots.txt 临时 503 的站会被完整抓一遍**，而且结果缓存一整轮。

RFC 9309 §2.3.1 把三种结果分开：2xx 按内容执行、4xx 视为没有 robots.txt、
5xx「unreachable」**可以按完全不许抓处理**。这里选后者：对一个把「我们没被
允许看」当成合法结论的工具，宁可少看不要多抓。

## 三、差点撞出来的那个坑

replay 下缺 robots.txt 快照会得到合成 `599 + x-geo-audit-fixture: missing`，
而 599 ≥ 500。语料里 143 个 host 只有 13 个录了 robots.txt —— 按 unreachable
处理的话 130 个 host 全部变「不许抓」，九份报告会 100% 变成 robots_disallowed。

区分点：**robots 管的是「我们可不可以发这个请求」，而 replay 下我们不发请求**。
所以合成响应放行（那是语料完整性的事），真 5xx 才 disallow。
"""

from __future__ import annotations

import httpx
import pytest

from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.classify import classify_response
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.models import Expect, Verdict


def _fetcher(
    robots_status: int, robots_body: str = "", *, robots_headers: dict[str, str] | None = None
) -> Fetcher:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(
                robots_status,
                headers={"content-type": "text/plain", **(robots_headers or {})},
                text=robots_body,
            )
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="content")

    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.parametrize(
    ("name", "status", "body", "policy", "may_fetch"),
    [
        ("2xx + Disallow: /", 200, "User-agent: *\nDisallow: /", "parsed", False),
        ("2xx + Allow: /", 200, "User-agent: *\nAllow: /", "parsed", True),
        ("404 视为没有 robots", 404, "", "allow_all", True),
        ("503 取不到 → 不许抓", 503, "", "disallow_all", False),
        ("500 取不到 → 不许抓", 500, "", "disallow_all", False),
    ],
)
def test_robots_policy_matches_rfc9309(
    name: str, status: int, body: str, policy: str, may_fetch: bool
) -> None:
    fetcher = _fetcher(status, body)
    try:
        info = fetcher.robots_for("https://x.invalid/")
        assert info.policy == policy, f"{name}: policy={info.policy}"
        resp = fetcher.fetch("https://x.invalid/page", expect=Expect.ANY)
        fetched = resp.status == 200
        assert fetched is may_fetch, f"{name}: 抓了={fetched}，应当={may_fetch}"
    finally:
        fetcher.close()


def test_fetch_itself_honours_robots_not_just_probe() -> None:
    """闸必须在 `fetch()` 里 —— 那是所有内容抓取的咽喉。

    只装在 `probe()` 的话，sitemap 抓取与对照探针会绕过去。
    """
    fetcher = _fetcher(200, "User-agent: *\nDisallow: /")
    try:
        resp = fetcher.fetch("https://x.invalid/sitemap.xml", expect=Expect.TEXT_FILE)
        assert resp.status == 0
        assert (resp.transport_error or "").startswith("robots_disallowed")
    finally:
        fetcher.close()


def test_robots_txt_itself_is_never_blocked() -> None:
    """robots.txt 自己不受 robots 约束 —— 否则 `Disallow: /` 的站取不到它。"""
    fetcher = _fetcher(200, "User-agent: *\nDisallow: /")
    try:
        info = fetcher.robots_for("https://x.invalid/")
        assert info.status == 200, "取 robots.txt 被 robots 自己挡住了"
        assert info.policy == "parsed"
    finally:
        fetcher.close()


def test_robots_gate_runs_before_the_cache() -> None:
    """闸排在缓存命中之前。

    否则一条早先（比如 --no-robots 那轮）缓存过的响应，会让这次绕过检查。
    """
    cache = HttpCache(":memory:")
    allowing = Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0, respect_robots=False),
        cache,
        DomainLimiter(2.0),
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, headers={"content-type": "text/plain"}, text="cached")
        ),
    )
    try:
        first = allowing.fetch("https://x.invalid/page", expect=Expect.ANY)
        assert first.status == 200
    finally:
        allowing._client.close()  # 保留缓存，只关连接

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(
                200, headers={"content-type": "text/plain"}, text="User-agent: *\nDisallow: /"
            )
        raise AssertionError("robots 说不许抓，却还是发了内容请求")

    respecting = Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        cache,
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )
    try:
        resp = respecting.fetch("https://x.invalid/page", expect=Expect.ANY)
        assert resp.status == 0, "缓存命中绕过了 robots 闸"
        assert (resp.transport_error or "").startswith("robots_disallowed")
    finally:
        respecting.close()


def test_replay_gap_is_not_treated_as_unreachable() -> None:
    """合成的「缺快照」响应不算 unreachable。

    143 个 host 只有 13 个录了 robots.txt。按 unreachable 处理的话 130 个 host
    全部变「不许抓」，九份报告 100% 变成 robots_disallowed。
    """
    fetcher = _fetcher(599, "", robots_headers={"x-geo-audit-fixture": "missing"})
    try:
        info = fetcher.robots_for("https://x.invalid/")
        assert info.policy == "allow_all", f"缺快照被当成了 {info.policy}"
        assert fetcher.fetch("https://x.invalid/page", expect=Expect.ANY).status == 200
    finally:
        fetcher.close()


def test_disallowed_classifies_as_robots_not_network_error() -> None:
    """「我们没被允许看」与「网络出错了」在报告里不该长得一样。

    前者是站方的决定，后者是我们的故障。标记不被 classify 认出来的话，
    会落到 `network_error`。
    """
    cls = classify_response(
        0,
        {},
        "",
        url="https://x.invalid/page",
        expect=Expect.ANY,
        transport_error="robots_disallowed: /page",
    )
    assert cls.verdict is Verdict.UNKNOWN
    assert cls.reason == "robots_disallowed"
