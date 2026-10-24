"""跳转链的每一跳都要按目标的 robots 复查（2026-10-22 跑 meshy.cn 时发现）。

（同一次发现的另一条 —— robots.txt 自己的 3xx 不跟 —— 已由 #15 修掉，
测试在 ``test_robots_fetch_rfc9309.py``。）

`_fetch_chain` 原来只在入口查一次。实测探 `https://www.meshy.cn/` → 301 →
`https://meshy.cn/`，apex 对我们的 UA 是 `Disallow: /`，工具照样抓了并判
`discovery:www.meshy.cn = pass`。同一份内容，从 apex 进是「robots 禁止」，
从 www 进是「通过」。
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.models import Expect, Verdict

DISALLOW_ALL = "User-agent: *\nDisallow: /"
ALLOW_ALL = "User-agent: *\nAllow: /"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """限速下限不许为测试放宽（DomainLimiter 拒绝 <2.0s），只把等待拿掉。"""
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("geo_audit.fetch.client.time.sleep", lambda _seconds: None)


def _fetcher(
    handler: Callable[[httpx.Request], httpx.Response], *, respect_robots: bool = True
) -> Fetcher:
    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0, respect_robots=respect_robots),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )


def _text(body: str, status: int = 200) -> httpx.Response:
    return httpx.Response(status, headers={"content-type": "text/plain"}, text=body)


def _redirect(to: str, status: int = 301) -> httpx.Response:
    return httpx.Response(status, headers={"location": to})


# --------------------------------------------------------------------------- #
# 跳转链每一跳复查 robots
# --------------------------------------------------------------------------- #


def _www_to_apex_handler(sent: list[str]) -> Callable[[httpx.Request], httpx.Response]:
    """www 的 robots 放行；apex 的 robots 禁止；www 的页面 301 到 apex。"""

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        host, path = request.url.host, request.url.path
        if path == "/robots.txt":
            return _text(ALLOW_ALL if host == "www.x.invalid" else DISALLOW_ALL)
        if host == "www.x.invalid":
            return _redirect(f"https://x.invalid{path}")
        return _text("# real content\n")

    return handler


def test_redirect_into_disallowed_host_is_not_fetched() -> None:
    sent: list[str] = []
    fetcher = _fetcher(_www_to_apex_handler(sent))
    try:
        resp = fetcher.fetch("https://www.x.invalid/", expect=Expect.ANY)
        assert "https://x.invalid/" not in sent, "apex 的 robots 禁止，却还是发了请求"
        assert resp.status == 0
        assert (resp.transport_error or "").startswith("robots_disallowed")
        assert len(resp.redirects) == 1, "被禁前走过的那一跳要留在证据里"
    finally:
        fetcher.close()


def test_redirect_into_disallowed_host_probes_as_robots_unknown() -> None:
    """判定落在「robots 禁止」那一态，不是 pass。"""
    sent: list[str] = []
    fetcher = _fetcher(_www_to_apex_handler(sent))
    try:
        probe = fetcher.probe("https://www.x.invalid/llms.txt", expect=Expect.TEXT_FILE)
        assert probe.classification.verdict is Verdict.UNKNOWN
        assert probe.classification.reason == "robots_disallowed"
    finally:
        fetcher.close()


def test_redirect_to_disallowed_path_on_same_host_is_not_fetched() -> None:
    """不换 host、只换路径时也要查：/a 被放行，/private/ 被禁。"""
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        if request.url.path == "/robots.txt":
            return _text("User-agent: *\nDisallow: /private/")
        if request.url.path == "/a":
            return _redirect("/private/b")
        return _text("content")

    fetcher = _fetcher(handler)
    try:
        resp = fetcher.fetch("https://x.invalid/a", expect=Expect.ANY)
        assert "/private/b" not in sent
        assert (resp.transport_error or "").startswith("robots_disallowed")
    finally:
        fetcher.close()


def test_redirect_into_host_with_unreadable_robots_is_not_fetched() -> None:
    """目标 host 的 robots.txt 读不到（持续 503）：同样不抓。

    记 robots_unreadable 而不是「禁止」—— 站方什么都没禁，是我们没能看。
    """
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        host, path = request.url.host, request.url.path
        if path == "/robots.txt":
            return _text(ALLOW_ALL) if host == "www.x.invalid" else _text("", 503)
        if host == "www.x.invalid":
            return _redirect(f"https://x.invalid{path}")
        return _text("# real content\n")

    fetcher = _fetcher(handler)
    try:
        resp = fetcher.fetch("https://www.x.invalid/", expect=Expect.ANY)
        assert "https://x.invalid/" not in sent
        assert (resp.transport_error or "").startswith("robots_unreadable")
    finally:
        fetcher.close()


def test_ignore_robots_still_follows_the_chain() -> None:
    """--ignore-robots 时照旧不查：跟到底，拿到 apex 的内容。"""
    sent: list[str] = []
    fetcher = _fetcher(_www_to_apex_handler(sent), respect_robots=False)
    try:
        resp = fetcher.fetch("https://www.x.invalid/", expect=Expect.ANY)
        assert resp.status == 200
        assert resp.final_url == "https://x.invalid/"
        assert not any(u.endswith("/robots.txt") for u in sent), "不查 robots 时不该去取它"
    finally:
        fetcher.close()
