"""A challenge page is a verdict about *us* (UA / IP), not a load signal.

The limiter widens a registrable domain's interval on every 429 / gateway 5xx and never lets it
fall back inside a run (``DomainLimiter.note_throttled``); ``Fetcher._attempt`` retries gateway
5xx twice.  Both are right for real load shedding (www.pipedrive.com's 429 on a file that exists).
Neither is right for a response that says, in a vendor header, "this is a challenge":

* Vercel answers its security checkpoint with **429** + ``x-vercel-mitigated: challenge``
  (tenderly.co: 27 of 27 requests, random paths included).  Five of those used to take the
  domain's interval 2 -> 4 -> 8 -> 16 -> 30 s -- slowing the rest of the run for nothing, since the
  next request is challenged just the same;
* Cloudflare answers "Under Attack" mode with **503** + ``cf-mitigated: challenge``; the two
  retries only cost two more requests against a WAF.

Found by independent review of the contract PR (which is what made Vercel's 429 a challenge in the
report while the fetcher kept treating it as a rate limit).
"""

from __future__ import annotations

import time
import types

import httpx
import pytest

from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.models import Expect

VERCEL = {"x-vercel-mitigated": "challenge", "x-vercel-challenge-token": "t"}
CLOUDFLARE = {"cf-mitigated": "challenge"}


@pytest.fixture(autouse=True)
def _fast_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """限速下限与重试退避是合规 / 稳健性约束，测试里不能调低 —— 记录要睡多久，但不真睡。"""
    slept: list[float] = []
    fake = types.SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=slept.append)
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time", fake)
    monkeypatch.setattr("geo_audit.fetch.client.time", fake)
    return slept


def _fetcher(status: int, headers: dict[str, str]) -> tuple[Fetcher, list[str]]:
    content_requests: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        content_requests.append(str(req.url))
        return httpx.Response(status, headers=headers, text="")

    f = Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )
    return f, content_requests


def _stats(f: Fetcher) -> dict[str, float]:
    return f.limiter.stats().get("x.test", {"interval": 2.0, "throttle_events": 0})


def test_a_vercel_challenge_429_does_not_widen_the_domains_pacing() -> None:
    f, _ = _fetcher(429, VERCEL)
    for i in range(5):
        f.fetch(f"https://x.test/p{i}", expect=Expect.ANY)
    assert _stats(f) == {"interval": 2.0, "throttle_events": 0}  # 修复前：2 -> 4 -> 8 -> 16 -> 30


def test_a_plain_429_still_widens_the_pacing() -> None:
    """对照：没有挑战头的 429 是真的限流，照旧拉宽（www.pipedrive.com 那一课）。"""
    f, _ = _fetcher(429, {"retry-after": "30"})
    for i in range(3):
        f.fetch(f"https://x.test/p{i}", expect=Expect.ANY)
    assert _stats(f)["interval"] == 16.0 and _stats(f)["throttle_events"] == 3


def test_a_cloudflare_503_challenge_is_not_retried() -> None:
    f, content = _fetcher(503, CLOUDFLARE)
    resp = f.fetch("https://x.test/p", expect=Expect.ANY)
    assert resp.status == 503
    assert len(content) == 1, "挑战页重试不会变，只是多打请求"  # 修复前：3 次
    assert _stats(f) == {"interval": 2.0, "throttle_events": 0}


def test_a_plain_503_is_still_retried_and_widens() -> None:
    """对照：没有挑战头的 503 是网关故障，照旧重试 + 拉宽。"""
    f, content = _fetcher(503, {})
    f.fetch("https://x.test/p", expect=Expect.ANY)
    assert len(content) == 3
    assert _stats(f)["throttle_events"] == 3
