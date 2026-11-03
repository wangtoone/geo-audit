"""robots.txt 与 sitemap 事实：被拦 ≠ 没有，没读到 ≠ 放行，抽样页的 noindex / canonical 要报。"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

from geo_audit.checks.seo_facts import robots_facts
from geo_audit.fetch import discovery
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from tests.test_subdomain_discovery import CONTACT, FakeSite, _control_for, _resolver

PROSE = "<html><head><title>t</title></head><body><h1>t</h1>" + "copy " * 400 + "</body></html>"
NOINDEX = (
    '<html><head><title>t</title><meta name="robots" content="noindex">'
    '<link rel="canonical" href="https://example.ai/other">'
    "</head><body><h1>t</h1>" + "copy " * 400 + "</body></html>"
)


@pytest.fixture
def make(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[FakeSite], Fetcher]]:
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _s: None)
    made: list[Fetcher] = []

    def _make(site: FakeSite) -> Fetcher:
        f = Fetcher(
            FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
            cache=HttpCache(tmp_path / "c.sqlite3", ua_profile="test"),
            limiter=DomainLimiter(2.0),
            transport=httpx.MockTransport(site.handler),
            probe_url_provider=_control_for,
        )
        made.append(f)
        return f

    yield _make
    for f in made:
        f.close()


def _site(extra: dict[str, tuple[int, str, str]]) -> FakeSite:
    pages = {f"https://{h}/": (200, "text/html", PROSE) for h in ("example.ai", "www.example.ai")}
    pages.update(extra)
    return FakeSite(pages)


def _run(make: Callable[[FakeSite], Fetcher], site: FakeSite) -> discovery.SiteMap:
    return discovery.discover(
        make(site), "example.ai", resolver=_resolver("example.ai", "www.example.ai")
    )


def test_blocked_sitemap_is_blocked_not_absent(make: Callable[[FakeSite], Fetcher]) -> None:
    """framia / enter 的形态：/sitemap.xml 对 curl 回 403。"""
    sm = _run(make, _site({"https://example.ai/sitemap.xml": (403, "text/html", "denied")}))
    f = sm.sitemap_facts["example.ai"]
    assert f.state == "blocked" and "sitemap_blocked" in f.flags and f.status == 403


def test_honest_404_sitemap_is_absent(make: Callable[[FakeSite], Fetcher]) -> None:
    sm = _run(make, _site({}))
    assert sm.sitemap_facts["example.ai"].state == "absent"


def test_sitemap_sample_reports_noindex_and_canonical(make: Callable[[FakeSite], Fetcher]) -> None:
    urls = [f"https://example.ai/p{i}" for i in range(6)]
    xml = "<urlset>" + "".join(f"<loc>{u}</loc>" for u in urls) + "</urlset>"
    extra: dict[str, tuple[int, str, str]] = {
        "https://example.ai/sitemap.xml": (200, "application/xml", xml)
    }
    extra.update(dict.fromkeys(urls, (200, "text/html", NOINDEX)))
    f = _run(make, _site(extra)).sitemap_facts["example.ai"]
    assert f.state == "ok" and f.url_count == 6 and len(f.sample) == 3
    assert "not_declared_in_robots" in f.flags
    assert "sample_noindex:3/3" in f.flags
    assert "sample_canonical_not_self:3/3" in f.flags


def test_robots_facts_cover_baiduspider_and_unreadable(make: Callable[[FakeSite], Fetcher]) -> None:
    robots = "User-agent: Baiduspider\nDisallow: /\n\nUser-agent: *\nDisallow: /private\n"
    sm = _run(make, _site({"https://example.ai/robots.txt": (200, "text/plain", robots)}))
    by_host = {r.host: r for r in robots_facts(sm.robots)}
    ex = {c.token: c.access for c in by_host["example.ai"].crawlers}
    assert ex["Baiduspider"] == "blocked_all"
    assert ex["GPTBot"] == "partial"
    # www 没有 robots.txt（诚实 404）：读到了「没有」，不是 unreadable
    assert by_host["www.example.ai"].readable


def test_robots_unreadable_is_not_allow(make: Callable[[FakeSite], Fetcher]) -> None:
    sm = _run(make, _site({"https://example.ai/robots.txt": (503, "text/html", "down")}))
    r = {x.host: x for x in robots_facts(sm.robots)}["example.ai"]
    assert not r.readable
    assert {c.access for c in r.crawlers} == {"unreadable"}
