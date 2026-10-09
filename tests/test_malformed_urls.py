"""被体检站点给的 URL 解析不了的时候，体检不许崩：它是一条发现，不是一次异常。

## 缺陷

``urllib.parse`` 对浏览器也会拒绝的 URL 抛 ``ValueError``：host 里括号没闭合（``http://[``）、
方括号里不是地址（``https://[your-domain]/docs`` —— 占位符漏进模板，API 文档里很常见）、端口不是
数字（``http://h:abc/``：``urlsplit`` 放行，``.port`` 才抛）、NFKC 之后 host 里出现 ``/``
（``http://℀/``）。这些字符串全是**被体检的站点**交给我们的 —— 重定向的 ``Location``、
``<a href>``、``llms.txt`` 里的链接、sitemap 的 ``<loc>``、``Link`` 响应头 —— 而 geo-audit 对它们
调 ``urljoin`` / ``urlsplit`` 的地方没有任何 ``try``：``Fetcher.fetch`` 回一个
``301 Location: http://[`` 就抛，整次体检退出码 1、裸 traceback、不出报告。任何被抓的 URL
（含 ``robots.txt`` 和首页）上一个响应头就够。

## 现在怎么办

* ``fetch/urlsafe.py`` 的 ``split_or_none`` / ``join_or_none`` 是读站点字符串的入口：解析不了就
  返回 ``None``。
* 重定向 ``Location`` 解析不了 → ``Fetcher`` 回 status 0 + ``transport_error``（和「redirect
  loop」同一条错误通道），分类成 ``UNKNOWN / network_error``，证据里带着原串。
* 要抓的 URL 本身解析不了（``fetch`` / ``probe`` / ``probe_many``）→ 一个请求都不发，同样
  ``UNKNOWN``。
* ``dead_links.classify_link``：没有拿到任何 HTTP 响应（status 0）而前面的规则都没认出它 →
  ``UNKNOWN``，不再落到「不是死链就是活链」（以前：跳转成环、跳转指向坏地址的链接被记成活着）。
* 站点上的链接（HTML ``<a href>`` 与 ``llms.txt`` 里的链接）解析不了 → **仍然是一条抽出来的链接**，
  进「被排除」清单、规则 ``unparseable_url``、写明原因，一个请求都不发，也不当成死链（账上
  ``links_extracted`` = 排除 + 待确认 + 已验证 + 未知 的恒等式照旧成立）。
* sitemap 的 ``<loc>`` 与 ``Link`` 头里解析不了的 URL 当没写（它们只用来给修复提示找「最近的
  现存路径」）。

## 这组测试

1. ``urlsafe`` 两个函数：一张坏 URL 表、一张好 URL 表；
2. ``Fetcher``：坏的 ``Location``（单跳、多跳、对 ``robots.txt``）、坏的入参 URL —— 不抛、不发
   请求、分类对；
3. 抽取与判定：HTML 与 ``llms.txt`` 里的坏链接被排除并写明原因，好链接不受影响；
4. sitemap、``Link`` 头、``normalize_url``；
5. 整站端到端（假站 + 真管线）：带坏 ``href`` / 坏 ``llms.txt`` 链接 / 跳到坏地址的页面的站点，
   ``audit_domain`` 出报告。
"""

from __future__ import annotations

import html
import random
import threading
import time
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from geo_audit.checks import ai_path as ap
from geo_audit.checks import dead_links as dl
from geo_audit.extract import extract_links, extract_page
from geo_audit.fetch import discovery
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fetch.urlsafe import (
    INVALID_REDIRECT_ERROR,
    INVALID_URL_ERROR,
    REJECTED_URL_ERROR,
    UNPARSEABLE_RULE_ID,
    join_or_none,
    split_or_none,
)
from geo_audit.fixtures import DNS_ABSENT_KEY, FixtureResolver, FixtureStore
from geo_audit.models import (
    Classification,
    Expect,
    HttpResponse,
    LinkContext,
    LinkState,
    Probe,
    Verdict,
)
from geo_audit.pipeline import AuditOptions, StopTransport, audit_domain, index_links_seeds
from geo_audit.rootcause import normalize_url

CONTACT = "ci@geo-audit.invalid"

#: urllib 拒绝的 URL（Python 3.11.15 / 3.12.14 / 3.13.15 都抛 ValueError）
BAD_URLS = [
    "http://[",  # host 里括号没闭合
    "http://[::1",  # IPv6 没闭合
    "https://[your-domain]/docs",  # 方括号里不是地址：占位符漏进了模板
    "http://a]b/",  # 多余的 ]
    "http://h:abc/x",  # 端口不是数字：urlsplit 放行，.port 才抛
    "http://h:99999/x",  # 端口越界
    "http://℀/",  # ℀ 在 NFKC 之后是 a/c，host 里不许出现 /
    "//[",  # 相对协议 + 坏 host
    "http://[::1]:abc/",
    "http://h:-1/",
    "http://h:80:80/",  # 两个端口
]
#: urlsplit 放行、**httpx 拒绝**的 URL（请求建不出来）：``split_or_none`` 一并拒绝。以前它们到了
#: ``Fetcher`` 才抛 ``httpx.InvalidURL`` / ``idna.IDNAError``，同样是整次体检崩掉。
HTTPX_BAD_URLS = [
    "http://256.256.256.256/",  # IPv4 的某一段超过 255
    "http://[v1.fe]/",  # 方括号里不是合法的 IPv6 字面量
    "http://xn--/",  # 不是合法的 IDNA（httpx 解码主机名时才抛 idna.IDNAError）
    "http://xn--a/",
    "http://\u200bhost/",  # 零宽空格
    "http://ＨＯＳＴ/",  # 全角的主机名
    "http://a.test/\x00",  # 控制字符
    "http://a.test/a\x01b",
]
ALL_BAD_URLS = [*BAD_URLS, *HTTPX_BAD_URLS]
GOOD_URLS = [
    "http://[::1]/x",
    "https://a.test:8080/p?q=[1]#f",
    "/relative/path",
    "",
    "mailto:a@b.c",
    "//cdn.test/x.js",
    "https://a.test:0/",
]
#: 响应头里只能有 ASCII（httpx 编码头值用 ascii）：``Location`` 的测试只用这些
ASCII_BAD_URLS = [u for u in ALL_BAD_URLS if u.isascii() and u.isprintable()]
#: httpx 自己会在读响应时拒绝一部分坏 ``Location``（``RemoteProtocolError``）；其余的由我们的
#: ``join_or_none`` 拦下。两条路径的结果必须一样：status 0 + 分类 UNKNOWN / network_error。
HTTPX_LOCATION_ERROR = "Invalid URL in location header"


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """合规下限是 1 请求 / 2 秒 / 域：只掐掉限流器与重试退避的 sleep，不动任何生产代码。"""
    fake = types.SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=lambda _s: None)
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time", fake)
    monkeypatch.setattr("geo_audit.fetch.client.time", fake)


class Site:
    """按 URL 表回放的假站：``url -> (status, headers, body)``；表里没有的一律 404 + text/html。"""

    def __init__(self, routes: dict[str, tuple[int, dict[str, str], str]]) -> None:
        self.routes = routes
        self.requested: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requested.append(url)
        row = self.routes.get(url)
        if row is None:
            return httpx.Response(
                404, headers={"content-type": "text/html"}, text="<title>404</title>not found"
            )
        status, headers, body = row
        return httpx.Response(status, headers=headers, text=body)


HTML = {"content-type": "text/html"}
TEXT = {"content-type": "text/plain"}


def _control(url: str) -> str:
    return f"https://{httpx.URL(url).host}/geo-audit-probe-x9f2.txt"


@pytest.fixture
def make_fetcher(tmp_path: Path) -> Iterator[Callable[..., Fetcher]]:
    made: list[Fetcher] = []

    def make(site: Site, *, respect_robots: bool = False) -> Fetcher:
        f = Fetcher(
            FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=respect_robots),
            cache=HttpCache(tmp_path / f"cache{len(made)}.sqlite3", ua_profile="test"),
            limiter=DomainLimiter(2.0),
            transport=StopTransport(httpx.MockTransport(site.handler), threading.Event()),
            probe_url_provider=_control,
        )
        made.append(f)
        return f

    yield make
    for f in made:
        f.close()


# ── 1. urlsafe ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("url", BAD_URLS)
def test_split_or_none_rejects_what_urllib_rejects(url: str) -> None:
    with pytest.raises(ValueError):
        urlsplit(url).port  # noqa: B018 - 前提：urllib 真的拒绝（lazy 的 .port 也算）
    assert split_or_none(url) is None


@pytest.mark.parametrize("url", HTTPX_BAD_URLS)
def test_split_or_none_also_rejects_what_only_httpx_rejects(url: str) -> None:
    urlsplit(url).port  # noqa: B018 - 前提：urllib 放行（这张表存在的理由）
    with pytest.raises((ValueError, httpx.InvalidURL)):
        httpx.URL(url).host  # noqa: B018
    assert split_or_none(url) is None


def test_split_or_none_rejects_a_url_longer_than_httpx_allows() -> None:
    url = "https://a.test/" + "a" * 70_000
    urlsplit(url).port  # noqa: B018
    assert split_or_none(url) is None


@pytest.mark.parametrize("url", GOOD_URLS)
def test_split_or_none_accepts_ordinary_urls(url: str) -> None:
    parts = split_or_none(url)
    assert parts is not None and parts.geturl() == url


def test_join_or_none() -> None:
    base = "https://a.test/b/c"
    assert join_or_none(base, "../d?x=1") == "https://a.test/d?x=1"
    assert join_or_none(base, "//cdn.test/x.js") == "https://cdn.test/x.js"
    for bad in ALL_BAD_URLS:
        assert join_or_none(base, bad) is None, bad


# ── 2. Fetcher ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("location", ASCII_BAD_URLS)
def test_a_redirect_to_an_unparseable_location_is_a_transport_error(
    make_fetcher: Callable[..., Fetcher], location: str
) -> None:
    site = Site({"https://x.test/old": (301, {"location": location}, "")})
    f = make_fetcher(site)
    resp = f.fetch("https://x.test/old", expect=Expect.ANY)  # 以前：ValueError，整次体检崩掉
    assert resp.status == 0
    error = resp.transport_error or ""
    assert (
        error.startswith((INVALID_REDIRECT_ERROR, REJECTED_URL_ERROR))
        or HTTPX_LOCATION_ERROR in error
    ), error
    if error.startswith(INVALID_REDIRECT_ERROR):
        assert repr(location[:200]) in error  # 证据里带着那个原串
    assert resp.final_url == "https://x.test/old"
    # 没有任何跟随的请求（httpx 自己拒绝的那一类会被当成传输错误重试，同一个 URL 最多 3 次）
    assert set(site.requested) == {"https://x.test/old"} and len(site.requested) <= 3
    probe = f.probe("https://x.test/old", expect=Expect.ANY, use_control=False)
    assert (probe.verdict, probe.classification.reason) == (Verdict.UNKNOWN, "network_error")


def test_our_own_check_catches_what_httpx_does_not() -> None:
    """``http://[`` 这类 Location httpx 放行，所以 ``INVALID_REDIRECT_ERROR`` 这条路必须真有人走：
    没有它，这一类就是原来的 ValueError。"""
    assert split_or_none("http://[") is None and join_or_none("https://x.test/", "http://[") is None


def test_a_bad_location_in_the_middle_of_a_chain_keeps_the_hops_before_it(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    site = Site(
        {
            "https://x.test/a": (301, {"location": "/b"}, ""),
            "https://x.test/b": (302, {"location": "http://["}, ""),
        }
    )
    resp = make_fetcher(site).fetch("https://x.test/a", expect=Expect.ANY)
    assert resp.status == 0
    assert (resp.transport_error or "").startswith(INVALID_REDIRECT_ERROR)
    assert [(h.status, h.from_url, h.to_url) for h in resp.redirects] == [
        (301, "https://x.test/a", "https://x.test/b")
    ]
    assert resp.final_url == "https://x.test/b"
    assert site.requested == ["https://x.test/a", "https://x.test/b"]


def test_a_robots_txt_that_redirects_to_garbage_is_unreadable_not_a_crash(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    """``robots.txt`` 也是站点说了算：它的 301 指向坏地址，同样不许崩 —— 读不到，保守一侧不抓。"""
    site = Site(
        {
            "https://x.test/robots.txt": (301, {"location": "http://["}, ""),
            "https://x.test/p": (200, HTML, "<html>p</html>"),
        }
    )
    f = make_fetcher(site, respect_robots=True)
    probe = f.probe("https://x.test/p", expect=Expect.HTML_PAGE)
    assert probe.verdict is Verdict.UNKNOWN
    assert probe.classification.reason == "robots_unreadable"
    assert "https://x.test/p" not in site.requested


@pytest.mark.parametrize("url", ALL_BAD_URLS)
def test_a_url_that_cannot_be_parsed_is_never_requested(
    make_fetcher: Callable[..., Fetcher], url: str
) -> None:
    site = Site({})
    f = make_fetcher(site)
    resp = f.fetch(url, expect=Expect.ANY)
    assert resp.status == 0 and (resp.transport_error or "").startswith(INVALID_URL_ERROR)
    probe = f.probe(url, expect=Expect.TEXT_FILE)
    assert (probe.verdict, probe.classification.reason) == (Verdict.UNKNOWN, "network_error")
    assert INVALID_URL_ERROR in probe.classification.evidence[0]
    assert site.requested == [] and f.http_requests == 0


class _Exploding(Site):
    """传输层一发请求就抛：模拟 httpx / DNS 在 ``split_or_none`` 之后才暴露的 URL 问题。"""

    def __init__(self, exc: Exception) -> None:
        super().__init__({})
        self.exc = exc

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requested.append(str(request.url))
        raise self.exc


# ``a..b``：socket 的 idna 编码抛 UnicodeError，它不是 httpx.HTTPError
_UNBUILDABLE = [UnicodeError("label empty or too long"), httpx.InvalidURL("Invalid IDNA hostname")]


@pytest.mark.parametrize("exc", _UNBUILDABLE, ids=["unicode_error", "invalid_url"])
@pytest.mark.parametrize(
    "url",
    [
        "https://a..test/x",
        # 报错文字里带着 URL：URL 里出现 DNS 错误的关键词，也不能让它被当成 DNS 抖动去问第二意见
        "https://a..test/getaddrinfo-resolve",
    ],
)
def test_a_request_that_cannot_be_built_is_a_transport_error_not_a_crash(
    make_fetcher: Callable[..., Fetcher], exc: Exception, url: str
) -> None:
    site = _Exploding(exc)
    f = make_fetcher(site)
    resp = f.fetch(url, expect=Expect.ANY)
    assert resp.status == 0
    error = resp.transport_error or ""
    assert error.startswith(REJECTED_URL_ERROR) and type(exc).__name__ in error, error
    # 确定性的本地失败：不重试（RETRY_ATTEMPTS 次）、不去问 DNS 第二意见
    assert len(site.requested) == 1
    probe = f.probe("https://a..test/y", expect=Expect.ANY, use_control=False)
    assert (probe.verdict, probe.classification.reason) == (Verdict.UNKNOWN, "network_error")


def test_probe_many_answers_every_url_and_requests_only_the_parseable_ones(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    site = Site({"https://x.test/ok": (200, HTML, "<html>ok</html>")})
    f = make_fetcher(site)
    urls = ["http://[", "https://x.test/ok", "http://h:abc/x", "https://[your-domain]/z"]
    probes = f.probe_many(urls, expect=Expect.HTML_PAGE)
    got = {p.url: (p.verdict, p.classification.reason) for p in probes}
    assert set(got) == set(urls)
    assert got["https://x.test/ok"][0] is Verdict.OK
    for bad in ("http://[", "http://h:abc/x", "https://[your-domain]/z"):
        assert got[bad] == (Verdict.UNKNOWN, "network_error"), bad
    assert all("[" not in u and "abc" not in u for u in site.requested)


# ── 3. 链接：HTML 与 llms.txt ────────────────────────────────────────────────
_HOME = (
    '<html><body><a href="/ok">Ok</a><a href="https://[your-domain]/docs">Placeholder</a>'
    '<a href="http://[">Broken</a><a href="http://h:abc/x">Port</a></body></html>'
)


def test_unparseable_hrefs_are_extracted_as_links_not_dropped_and_not_fatal() -> None:
    page = extract_page(_HOME, source_page="https://acme.io/docs/", source_role="home")
    by_raw = {t.raw_href: t for t in page.targets}
    assert set(by_raw) == {"/ok", "https://[your-domain]/docs", "http://[", "http://h:abc/x"}
    assert by_raw["/ok"].abs_url == "https://acme.io/ok"
    for raw in ("https://[your-domain]/docs", "http://[", "http://h:abc/x"):
        target = by_raw[raw]
        assert target.abs_url == raw and target.norm_url == raw  # 原串：后面只当字符串用
        assert split_or_none(target.abs_url) is None
    assert len(extract_links(_HOME, source_page="https://acme.io/", source_role="home")) == 4
    padded = extract_links(
        '<a href="  http://[  ">x</a>', source_page="https://acme.io/", source_role="h"
    )
    assert [(t.raw_href, t.abs_url, t.norm_url) for t in padded] == [
        ("  http://[  ", "http://[", "http://[")
    ]  # 原串去掉首尾空白：身份稳定


@pytest.mark.parametrize("url", ALL_BAD_URLS)
def test_classify_link_excludes_an_unparseable_url_and_sends_nothing(url: str) -> None:
    verdict = dl.classify_link(
        url,
        source_page="https://acme.io/",
        ctx=LinkContext(source_page="https://acme.io/"),
        client=None,  # type: ignore[arg-type]  # 在发请求之前就返回
        store=None,  # type: ignore[arg-type]
        fetcher=None,
        source_role="home",
    )
    assert verdict.state is LinkState.EXCLUDED
    assert verdict.rule_id == UNPARSEABLE_RULE_ID == "unparseable_url"
    assert [ex.rule_id for ex in verdict.exclusions] == [UNPARSEABLE_RULE_ID]
    assert verdict.disposition == "excluded" and verdict.requests_spent == 0


@pytest.mark.parametrize(
    "location, via",
    [("http://[", "our check"), ("https://[your-domain]/x", "httpx"), ("http://h:abc/", "ours")],
)
def test_a_link_that_redirects_to_garbage_is_unknown_not_alive(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path, location: str, via: str
) -> None:
    """没有这条判定时，status 0 + 不认识的 transport_error 一路落到「不是死链就是活链」：一条
    浏览器也打不开的链接被记成活着（这里的两条路径 —— 我们拦的和 httpx 拦的 —— 都一样）。"""
    site = Site(
        {
            "https://third.acmevendor.io/": (200, HTML, "<html>root</html>"),
            "https://third.acmevendor.io/x": (301, {"location": location}, ""),
        }
    )
    f = make_fetcher(site)
    with httpx.Client(transport=httpx.MockTransport(site.handler)) as client:
        verdict = dl.classify_link(
            "https://third.acmevendor.io/x",
            source_page="https://acme.io/",
            ctx=LinkContext(source_page="https://acme.io/"),
            client=client,
            store=FixtureStore(tmp_path / "empty"),
            fetcher=f,
            source_role="home",
        )
    assert verdict.state is LinkState.UNKNOWN, via
    assert verdict.rule_id == "no_http_response"
    assert "没有拿到 HTTP 响应" in verdict.evidence[0]


def test_a_link_that_loops_forever_is_unknown_not_alive(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path
) -> None:
    """同一类洞的另一个实例（和坏 URL 无关）：跳转成环的链接浏览器同样打不开。"""
    site = Site(
        {
            "https://third.acmevendor.io/": (200, HTML, "<html>root</html>"),
            "https://third.acmevendor.io/a": (302, {"location": "/b"}, ""),
            "https://third.acmevendor.io/b": (302, {"location": "/a"}, ""),
        }
    )
    f = make_fetcher(site)
    with httpx.Client(transport=httpx.MockTransport(site.handler)) as client:
        verdict = dl.classify_link(
            "https://third.acmevendor.io/a",
            source_page="https://acme.io/",
            ctx=LinkContext(source_page="https://acme.io/"),
            client=client,
            store=FixtureStore(tmp_path / "empty"),
            fetcher=f,
            source_role="home",
        )
    assert verdict.state is LinkState.UNKNOWN and verdict.rule_id == "no_http_response"


_LLMS = (
    "# Acme\n"
    "- [Quickstart](/quickstart.md)\n"
    "- [Broken](http://[)\n"
    "- [Placeholder](https://[your-domain]/x)\n"
    "<a href='http://h:abc/y'>port</a> and https://acme.io/bare\n"
)


def test_parse_index_links_hands_out_only_links_that_can_be_parsed() -> None:
    base = "https://acme.io/llms.txt"
    links = ap.parse_index_links(_LLMS, base)
    assert [link.abs_url for link in links] == [
        "https://acme.io/quickstart.md",
        "https://acme.io/bare",
    ]
    assert all(split_or_none(link.abs_url) is not None for link in links)
    assert all(link.artifact != "unparseable_url" for link in links)


def test_keep_unparseable_returns_them_flagged_in_file_order() -> None:
    base = "https://acme.io/llms.txt"
    links = ap.parse_index_links(_LLMS, base, keep_unparseable=True)
    assert [(link.abs_url, link.artifact) for link in links] == [
        ("https://acme.io/quickstart.md", None),
        ("http://[", "unparseable_url"),
        ("https://[your-domain]/x", "unparseable_url"),
        ("http://h:abc/y", "unparseable_url"),
        ("https://acme.io/bare", None),
    ]
    assert all(link.norm_url == link.abs_url for link in links if link.artifact)
    # 相对协议 + 坏 host 也是链接；其它方案（ftp:、mailto:）不是
    odd = ap.parse_index_links("[a](//[) [b](ftp://[) [c](mailto:x@y)", base, keep_unparseable=True)
    assert [link.abs_url for link in odd] == ["//["]


def test_extract_index_links_drops_the_unparseable_ones_unless_asked() -> None:
    base = "https://acme.io/llms.txt"
    assert [link.abs_url for link in ap.extract_index_links(_LLMS, base)] == [
        "https://acme.io/quickstart.md",
        "https://acme.io/bare",
    ]
    asked = ap.extract_index_links(_LLMS, base, keep_unparseable=True)
    assert [link.artifact for link in asked].count("unparseable_url") == 3


def test_an_unparseable_link_is_kept_as_written_not_normalised() -> None:
    """看不出坏 URL 里哪段是 host、哪段是路径，所以不替它做大小写折叠：只有一字不差的重复才去重。"""
    base = "https://acme.io/llms.txt"
    text = "[a](https://[Foo/A) [b](https://[foo/a) [c](https://[Foo/A)"
    links = ap.parse_index_links(text, base, keep_unparseable=True)
    assert [link.abs_url for link in links] == ["https://[Foo/A", "https://[foo/a"]
    assert [link.norm_url for link in links] == ["https://[Foo/A", "https://[foo/a"]


def test_probe_index_links_excludes_the_unparseable_ones_with_the_reason(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    site = Site(
        {
            "https://acme.io/llms.txt": (200, TEXT, _LLMS),
            "https://acme.io/quickstart.md": (200, {"content-type": "text/markdown"}, "# q\n"),
            "https://acme.io/bare": (200, HTML, "<html>bare</html>"),
        }
    )
    f = make_fetcher(site)
    index = f.probe("https://acme.io/llms.txt", expect=Expect.TEXT_FILE)
    report = ap.probe_index_links("acme.io", index, fetcher=f)
    assert report.n_links == 5  # 文件里有 5 条链接，坏的也算一条
    assert sorted(url for url, _ in report.excluded) == sorted(
        ["http://[", "https://[your-domain]/x", "http://h:abc/y"]
    )
    assert {ex.rule_id for _, ex in report.excluded} == {"unparseable_url"}
    assert all("无法解析" in ex.reason for _, ex in report.excluded)
    assert sorted(link.abs_url for link in report.probed) == [
        "https://acme.io/bare",
        "https://acme.io/quickstart.md",
    ]
    assert report.n_dead == 0 and report.n_unknown == 0
    assert [u for u in site.requested if "[" in u or "abc" in u] == []
    assert [row[0] for row in f.exclusion_log()] == [url for url, _ in report.excluded]


def test_the_coverage_gap_of_an_unjudged_index_counts_its_unparseable_links_too() -> None:
    """判不了的索引整批不查；缺口里写的条数是「文件里有几条链接」，坏链接也是链接。"""
    from geo_audit.models import SiteMap
    from geo_audit.pipeline import NullProgress, RunState, _stage_index_links

    body = "\n".join(
        [f"- [p{i}](https://docs.acme.io/p{i}.md)" for i in range(3)]
        + ["- [x](http://[)", "- [y](https://[your-domain]/z.md)"]
    )
    probe = _index_probe(body)
    unknown = Probe(
        probe.url,
        probe.expect,
        probe.response,
        Classification(Verdict.UNKNOWN, "control_unavailable", ("没能做对照探测",)),
    )
    sitemap = SiteMap(
        input_domain="acme.io",
        registrable_domain="acme.io",
        hosts=(),
        apex_www=None,
        sitemap_urls={},
        pricing_url=None,
        pricing_candidates_tried=(),
        ai_path_probes=(unknown,),
        robots={},
    )
    st = RunState(sitemap=sitemap)
    options = AuditOptions(domain="acme.io", contact=CONTACT, replay_fixtures=True)
    _stage_index_links(st, options, None, NullProgress())  # type: ignore[arg-type]
    gaps = [g for g in st.coverage_gaps if unknown.url in g.where]
    assert len(gaps) == 1
    assert "解析出 5 条内链" in gaps[0].detail, gaps[0].detail


def _index_probe(body: str) -> Probe:
    resp = HttpResponse(
        url="https://docs.acme.io/llms.txt",
        final_url="https://docs.acme.io/llms.txt",
        status=200,
        headers={"content-type": "text/plain"},
        body=body.encode(),
    )
    return Probe(resp.url, Expect.TEXT_FILE, resp, Classification(Verdict.OK, "ok", ()))


def test_the_implicit_index_sees_only_parseable_links() -> None:
    body = "\n".join(
        [f"- [p{i}](https://docs.acme.io/p{i}.md)" for i in range(8)]
        + ["- [x](http://[)", "- [y](https://[your-domain]/z.md)"]
    )
    decl = ap.detect_md_implicit_index(_index_probe(body))  # 以前：ValueError
    assert decl is not None and decl.scope == "IMPLICIT_INDEX"
    assert "8/8" in decl.declaration_text  # 分母只数能解析的链接


def test_an_index_with_only_unparseable_links_still_gets_its_cell() -> None:
    seeds = index_links_seeds([_index_probe("# Acme\n- [x](http://[)\n")])
    assert len(seeds) == 1 and seeds[0].aggregate_of == 1


# ── 4. sitemap、Link 头、normalize_url ───────────────────────────────────────
def test_unparseable_sitemap_locs_are_ignored(make_fetcher: Callable[..., Fetcher]) -> None:
    xml = {"content-type": "application/xml"}
    sitemap = (
        "<urlset><url><loc>https://x.test/a</loc></url><url><loc>http://[</loc></url>"
        "<url><loc>https://x.test/b</loc></url><url><loc>http://h:abc/c</loc></url></urlset>"
    )
    index = (
        "<sitemapindex><sitemap><loc>http://[</loc></sitemap>"
        "<sitemap><loc>https://x.test/sitemap-1.xml</loc></sitemap></sitemapindex>"
    )
    site = Site(
        {
            "https://x.test/sitemap.xml": (200, xml, sitemap),
            "https://y.test/sitemap.xml": (200, xml, index),
            "https://x.test/sitemap-1.xml": (200, xml, sitemap),
        }
    )
    f = make_fetcher(site)
    assert discovery.fetch_sitemap_urls(f, "x.test", ()) == ("https://x.test/a", "https://x.test/b")
    assert discovery.fetch_sitemap_urls(f, "y.test", ()) == ("https://x.test/a", "https://x.test/b")


def test_an_unparseable_link_header_url_is_treated_as_no_link_header() -> None:
    def page(link: str) -> HttpResponse:
        return HttpResponse(
            url="https://docs.acme.io/guide",
            final_url="https://docs.acme.io/guide",
            status=200,
            headers={"content-type": "text/html", "link": link},
            body=b"<html><body><p>docs</p></body></html>",
        )

    assert (
        ap.detect_md_signal_from_page(page('<http://[>; rel="alternate"; type="text/markdown"'))
        is None
    )
    good = ap.detect_md_signal_from_page(page('</guide.md>; rel="alternate"; type="text/markdown"'))
    assert good is not None and good.negotiation_advertised is True


@pytest.mark.parametrize("url", ALL_BAD_URLS)
def test_normalize_url_leaves_an_unparseable_url_as_it_is(url: str) -> None:
    assert normalize_url(f"  {url}  ") == url


def test_normalize_url_does_not_fold_the_case_of_an_unparseable_url() -> None:
    assert normalize_url("  HTTPS://[Your-Domain]/Docs  ") == "HTTPS://[Your-Domain]/Docs"
    # 对照：能解析的 URL 照旧折叠 host 的大小写
    assert normalize_url("HTTPS://Acme.IO/Docs") == "https://acme.io/Docs"


# ── 5. 整站端到端：假站 + 真管线 ─────────────────────────────────────────────
def _resolver(*hosts: str) -> FixtureResolver:
    table: dict[str, dict[str, Any]] = {
        h: {"addresses": ["203.0.113.10"], "resolver": "system", "poisoned": False} for h in hosts
    }
    table[DNS_ABSENT_KEY] = {
        "addresses": [],
        "resolver": "none",
        "poisoned": False,
        "error": "NXDOMAIN",
    }
    return FixtureResolver(table, source="tests/test_malformed_urls.py")


def _assert_report_survives_output(report: Any) -> None:
    """报告还要渲染成 HTML、写成 JSON、再读回来：坏 URL 只是字符串，这几步也不许碰它们的结构。"""
    from geo_audit.report import render_html
    from geo_audit.report.json_out import report_from_json, report_to_json

    html = render_html(report)
    assert "[your-domain]" in html  # 被排除的坏链接在报告里看得见（HTML 转义后）
    again = report_from_json(report_to_json(report))
    assert {e.url for e in again.excluded} == {e.url for e in report.excluded}


def _audit_a_site_full_of_garbage(
    make_fetcher: Callable[..., Fetcher],
    tmp_path: Path,
    *,
    only: tuple[str, ...],
    extra_index_links: int = 0,
    extra_home_hrefs: tuple[str, ...] = (),
) -> tuple[Any, Site]:
    home = (
        "<html><body><a href='/ok'>Ok</a><a href='/old'>Old</a>"
        "<a href='https://[your-domain]/docs'>Placeholder</a><a href='http://['>Broken</a>"
        "<a href='http://h:abc/x'>Port</a>"
        + "".join(f"<a href='{href}'>extra</a>" for href in extra_home_hrefs)
        + "</body></html>"
    )
    llms = (
        "# Acme\n\nAppend `.md` to any documentation page URL to get its Markdown.\n\n"
        "- [Quickstart](https://docs.acmecloud.io/quickstart.md)\n"
        "- [Broken](http://[)\n- [Placeholder](https://[your-domain]/x)\n"
    ) + "".join(
        f"- [Page {i}](https://docs.acmecloud.io/p{i}.md)\n" for i in range(extra_index_links)
    )
    routes: dict[str, tuple[int, dict[str, str], str]] = {}
    for host in ("acmecloud.io", "www.acmecloud.io"):
        routes[f"https://{host}/"] = (200, HTML, home)
        routes[f"https://{host}/ok"] = (200, HTML, "<html>ok</html>")
        routes[f"https://{host}/old"] = (301, {"location": "http://["}, "")  # 跳到坏地址
    routes["https://docs.acmecloud.io/"] = (200, HTML, "<html>docs</html>")
    routes["https://docs.acmecloud.io/llms.txt"] = (200, TEXT, llms)
    routes["https://docs.acmecloud.io/quickstart.md"] = (
        200,
        {"content-type": "text/markdown"},
        "# Quickstart\n",
    )
    for i in range(extra_index_links):
        routes[f"https://docs.acmecloud.io/p{i}.md"] = (
            200,
            {"content-type": "text/markdown"},
            f"# Page {i}\n",
        )
    site = Site(routes)
    report = audit_domain(
        AuditOptions(domain="acmecloud.io", contact=CONTACT, only=only, max_requests=0),
        fetcher=make_fetcher(site),
        store=FixtureStore(tmp_path / "empty-fixtures"),
        resolver=_resolver("acmecloud.io", "www.acmecloud.io", "docs.acmecloud.io"),
    )
    return report, site


def test_a_site_full_of_garbage_urls_still_gets_a_report(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path
) -> None:
    report, site = _audit_a_site_full_of_garbage(make_fetcher, tmp_path, only=())

    # ① 报告出来了，账是平的，渲染与 JSON 往返也都过得去
    _assert_report_survives_output(report)
    c = report.counts
    assert c.positions == len(report.positions)
    assert c.positions_pass + c.positions_fail + c.positions_unknown + c.positions_na == c.positions
    cov = report.coverage
    assert cov.links_extracted == (
        cov.links_excluded + cov.links_needs_review + cov.links_verified + cov.links_unknown
    )

    # ② 坏 URL 进「被排除」清单，写明原因、来源页；好链接照常验证
    bad = {(e.url, e.found_on) for e in report.excluded if e.rule_id == "unparseable_url"}
    assert {url for url, _ in bad} == {
        "https://[your-domain]/docs",
        "http://[",
        "http://h:abc/x",
        "https://[your-domain]/x",
    }
    assert ("http://[", "https://docs.acmecloud.io/llms.txt") in bad
    assert ("http://[", "https://www.acmecloud.io/") in bad
    assert all("无法解析" in e.rule_desc for e in report.excluded if e.rule_id == "unparseable_url")
    assert cov.links_excluded == 3  # 首页上的三条（llms.txt 的那两条在索引内链这一格里）

    # ③ 一个请求都没为坏 URL 发过
    assert [u for u in site.requested if "[" in u or "abc" in u] == []

    # ④ 跳到坏地址的那条链接既没崩也没被记成活着：未知（不判死也不判活）
    assert cov.links_unknown == 1
    assert all(not f.target.url.endswith("/old") for f in report.findings)


def test_the_human_path_cell_does_not_claim_the_unreachable_link_is_alive(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path
) -> None:
    report, _ = _audit_a_site_full_of_garbage(make_fetcher, tmp_path, only=("dead_links",))
    home = next(p for p in report.positions if p.probe_url == "https://www.acmecloud.io/")
    assert "2 条可点击链接全部活着" not in home.detail  # /old 没判成：不能和 /ok 一起算「活着」


def test_a_big_index_with_unparseable_links_still_gets_a_report(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path
) -> None:
    """索引 20 条起要逐条看路径前缀（F1「索引单点依赖」）：坏链接不许把它带崩。"""
    report, site = _audit_a_site_full_of_garbage(
        make_fetcher, tmp_path, only=(), extra_index_links=40
    )
    _assert_report_survives_output(report)
    bad = {e.url for e in report.excluded if e.rule_id == "unparseable_url"}
    assert {"http://[", "https://[your-domain]/x"} <= bad
    assert [u for u in site.requested if "[" in u] == []
    # 好链接照常探了：40 个 p{i}.md 都是活的
    assert sum(1 for u in site.requested if "/p" in u and u.endswith(".md")) >= 40


def test_path_segments_does_not_mistake_a_path_for_a_url() -> None:
    from geo_audit.rootcause import path_segments

    assert path_segments("//[locale]/docs") == (
        "[locale]",
        "docs",
    )  # 以 // 开头的路径，不是主机 [locale]
    assert path_segments("https://acme.io//[locale]/docs") == ("[locale]", "docs")
    assert path_segments("https://acme.io/a/b/") == ("a", "b")  # 老用法照旧
    assert path_segments("/a/b") == ("a", "b")


def test_a_dead_link_whose_path_looks_like_an_authority_does_not_crash_the_analysis(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path
) -> None:
    """``https://host//[locale]/docs`` 是合法 URL，死了才会进根因分析（那里按路径切段）。"""
    report, _ = _audit_a_site_full_of_garbage(
        make_fetcher,
        tmp_path,
        only=(),
        extra_home_hrefs=(
            "https://www.acmecloud.io//[locale]/docs",
            "https://www.acmecloud.io//[x",
        ),
    )
    dead = [f for f in report.findings if "[locale]" in f.target.url or "[x" in f.target.url]
    assert dead, "两条链接都是 404，应当各记一条死链"


def _index_report(n_good: int, n_bad: int) -> ap.IndexLinkReport:
    from geo_audit.models import Severity, Status

    links = [
        ap.IndexLink(
            line_no=i,
            abs_url=f"https://docs.acme.io/guide/v2/p{i}.md",
            norm_url=f"https://docs.acme.io/guide/v2/p{i}.md",
            anchor_text=None,
            extractor="markdown",
            # 双 scheme 的链接能解析、有路径：它照常进 F1 的分母（只有解析不了的才不进）
            artifact="double_scheme" if i == 0 else None,
        )
        for i in range(n_good)
    ] + [
        ap.IndexLink(
            line_no=n_good + i,
            abs_url=f"http://[{i}",
            norm_url=f"http://[{i}",
            anchor_text=None,
            extractor="markdown",
            artifact="unparseable_url",
        )
        for i in range(n_bad)
    ]
    return ap.IndexLinkReport(
        index_url="https://docs.acme.io/llms.txt",
        links=tuple(links),
        probed=(),
        sampled=False,
        sampled_of=n_good,
        excluded=(),
        alive=(),
        dead=(),
        unknown=(),
        status=Status.PASS,
        severity=Severity.INFO,
        counted_as_hit=False,
    )


def test_f1_looks_only_at_links_it_can_parse() -> None:
    """F1「索引单点依赖」要逐条看路径前缀：解析不了的链接没有路径，不进分母、也不许把它带崩。"""
    from geo_audit.pipeline import build_fragilities

    def f1(n_good: int, n_bad: int) -> list[Any]:
        got = build_fragilities("acme.io", {}, [_index_report(n_good, n_bad)])
        return [f for f in got if f.fragility_id == "F1"]

    # 20 条能看的 + 3 条坏的：能看的 20/20 都挤在 /guide/v2 下 → 报；分母是 20，不是 23
    (hit,) = f1(20, 3)
    assert hit.metric.endswith("20 条链接里 20 条（100%）挤在 /guide/v2 下")
    # 19 条能看的 + 5 条坏的：能看的不到 20 条 → 不报（坏链接不替它凑数）
    assert f1(19, 5) == []
    # 没有坏链接：行为照旧
    assert len(f1(20, 0)) == 1 and f1(19, 0) == []


# ── 6. 坏 URL 出现在站上每一个会被读的位置 ───────────────────────────────────
#
# 上面那个整站只塞了几条坏链接、索引也只有几行，而下游有按规模才走的分支：索引 ≥ 20 条才算
# F1「索引单点依赖」（逐条 ``urlsplit`` 路径前缀）、> 120 条才抽样。所以这里把同一个坏 URL 放进
# 站上每个会读 URL 的位置（HTML 的 href / src / action / canonical / base / og:url、正文里的裸 URL、
# llms.txt、robots.txt 的 Sitemap 行、sitemap 与 sitemapindex 的 <loc>、重定向的 Location），再把
# 页面链接与索引链接放大到跨过那些阈值，整条管线都要走完，HTML 与 JSON 也要输出得出来。
_XML = {"content-type": "application/xml"}
_MD = {"content-type": "text/markdown"}


def _everywhere_page(bad: str, host: str, n_good: int) -> str:
    good = "".join(f"<li><a href='/g{i}'>Good {i}</a></li>" for i in range(n_good))
    return (
        "<html><head>"
        f"<link rel='canonical' href='{bad}'>"
        f"<link rel='alternate' type='text/markdown' href='{bad}'>"
        f"<meta property='og:url' content='{bad}'><base href='{bad}'></head><body>"
        f"<nav><a href='{bad}'>nav</a><a href='/'>home</a></nav>"
        f"<main><h1>Hi</h1><ul>{good}</ul><a href='{bad}'>body</a><a href='  {bad}  '>padded</a>"
        f"<a href='mailto:x@y.z'>mail</a><img src='{bad}'><form action='{bad}'></form>"
        f"<p>see {bad} and https://docs.{host}/llms.txt</p></main>"
        f"<footer><a href='{bad}'>footer</a></footer></body></html>"
    )


def _everywhere_site(
    bad: str, n_good: int, n_index: int
) -> dict[str, tuple[int, dict[str, str], str]]:
    d = "acmecloud.io"
    index = (
        "# Acme\n\nAppend `.md` to any documentation page URL to get its Markdown.\n\n"
        + "".join(f"- [Page {i}](https://docs.{d}/p{i}.md)\n" for i in range(n_index))
        + f"- [Bad]({bad})\n- [Bad2]({bad}/x)\n<a href='{bad}'>html</a>\n{bad}\n- [Rel](/rel.md)\n"
    )
    routes: dict[str, tuple[int, dict[str, str], str]] = {}
    for host in (d, f"www.{d}", f"docs.{d}"):
        for path in ("/", "/pricing", "/changelog", "/docs", "/help"):
            routes[f"https://{host}{path}"] = (200, HTML, _everywhere_page(bad, host, n_good))
        for i in range(n_good):
            routes[f"https://{host}/g{i}"] = (200, HTML, "<html><body>ok</body></html>")
        routes[f"https://{host}/llms.txt"] = (200, TEXT, index)
        routes[f"https://{host}/llms-full.txt"] = (200, TEXT, index)
        routes[f"https://{host}/robots.txt"] = (
            200,
            TEXT,
            f"User-agent: *\nAllow: /\nSitemap: {bad}\nSitemap: https://{host}/sitemap.xml\n",
        )
        urlset = (
            f"<urlset><url><loc>{bad}</loc></url><url><loc>https://{host}/g0</loc></url></urlset>"
        )
        if host.startswith("www."):  # sitemapindex：一个子 sitemap 是坏地址
            routes[f"https://{host}/sitemap.xml"] = (
                200,
                _XML,
                f"<sitemapindex><sitemap><loc>{bad}</loc></sitemap>"
                f"<sitemap><loc>https://{host}/sitemap-1.xml</loc></sitemap></sitemapindex>",
            )
            routes[f"https://{host}/sitemap-1.xml"] = (200, _XML, urlset)
        else:
            routes[f"https://{host}/sitemap.xml"] = (200, _XML, urlset)
        routes[f"https://{host}/old"] = (301, {"location": bad}, "")
    for i in range(n_index):
        routes[f"https://docs.{d}/p{i}.md"] = (200, _MD, f"# P{i}\n")
    routes[f"https://docs.{d}/rel.md"] = (200, _MD, "# rel\n")
    return routes


@pytest.mark.parametrize("n_good,n_index", [(3, 3), (30, 30), (200, 150)])
@pytest.mark.parametrize("bad", ASCII_BAD_URLS)
def test_a_garbage_url_in_every_place_the_audit_reads_still_gets_a_report(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path, bad: str, n_good: int, n_index: int
) -> None:
    site = Site(_everywhere_site(bad, n_good, n_index))
    report = audit_domain(
        AuditOptions(domain="acmecloud.io", contact=CONTACT, max_requests=0),
        fetcher=make_fetcher(site),
        store=FixtureStore(tmp_path / "empty-fixtures"),
        resolver=_resolver("acmecloud.io", "www.acmecloud.io", "docs.acmecloud.io"),
    )
    _assert_report_survives_output(report)
    assert any(e.rule_id == "unparseable_url" for e in report.excluded)
    assert [u for u in site.requested if any(t in u for t in ("[", ":abc", ":99999", ":-1"))] == []


# ── 7. 属性测试：随便什么字符串，都不许让体检崩 ──────────────────────────────
#
# 上面各节是「已知的坏 URL」。这一节是「任意字符串」：用固定种子随机拼 URL（括号不配对、控制
# 字符、非 ASCII 主机、IDNA 错误、超长、``//[x`` 开头的路径……），喂给 ``Fetcher`` 和整条管线。
# 它抓出过前几节想不到的三类：httpx 拒绝而 urllib 放行的 URL（``http://256.256.256.256/``、
# 控制字符、``http://xn--/``）、DNS 标签编不出来（``a..b``）、根因分析把以 ``//[`` 开头的
# **路径**当 URL 解析。
_SCHEMES = ["http", "https", "HTTP", "https", "ftp", "", "http:", "https:/", "htt p", "javascript"]
_HOSTS = [
    "a.test",
    "A.TEST",
    "a..test",
    ".test",
    "a.test.",
    "-a.test",
    "a_b.test",
    "xn--",
    "xn--a",
    "256.256.256.256",
    "1.2.3",
    "0x7f.1",
    "[::1]",
    "[::1",
    "::1]",
    "[v1.fe]",
    "[1:2:3:4:5:6:7:8:9]",
    "a b",
    "a\u200bb.test",
    "\uff48ost.test",
    "ex\u00e4mple.test",
    "\u2100",
    "a\u3002test",
    "a@b",
    "a:b",
    "user:pw@host.test",
    "@",
    ":",
    "",
    "h" * 70 + ".test",
    "%41.test",
    "a.test:80",
    "a.test:0",
    "a.test:65536",
    "a.test:abc",
    "a.test:-1",
    "a.test: 80",
    "a.test:80:80",
    "[::1]:abc",
]
_CHARS = [
    *"abcXYZ019/\\?#[]@:;%&=+ \t\n\r\x00\x01\x7f.-_~!$'()*,<>\"{}|^`",
    "\u00e9",
    "\u4e2d",
    "\u200b",
    "\ufeff",
    "\U0001f600",
    "\u2100",
    "\u0301",
]
_SEGMENTS = [
    "docs",
    "guide",
    "v2",
    "[slug]",
    "[locale]",
    "%zz",
    "..;",
    "..",
    ".",
    ":id",
    "{id}",
    "<id>",
    "@user",
    "a;b",
    "\u00e9",
    "a b",
    "x" * 40,
    "[",
    "]",
    "[x",
    "x]",
    "",
    "",
    "p1.md",
    "g1",
]
_QUERIES = ["", "", "?a", "?=", "?&", "?%zz", "?a=b=c", "?utm_source=x", "?a[]=1", "?[", "?x=%"]


def _random_url(rnd: random.Random, mode: str) -> str:
    if mode == "paths":  # 全是合法 URL，路径里什么都有：死链分析（根因 / 修复提示）才会跑到
        host = rnd.choice(["www.acmecloud.io", "docs.acmecloud.io", "acmecloud.io", "other.test"])
        path = "/" + "/".join(rnd.choice(_SEGMENTS) for _ in range(rnd.randint(0, 5)))
        if rnd.random() < 0.15:
            path = "/" + path  # ``//[slug]/…``：以 // 开头的路径
        return f"https://{host}{path}{'/' if rnd.random() < 0.2 else ''}{rnd.choice(_QUERIES)}"
    if rnd.random() < 0.15:
        return "".join(rnd.choice(_CHARS) for _ in range(rnd.randint(0, 24)))
    host = (
        rnd.choice(_HOSTS) if rnd.random() < 0.85 else "".join(rnd.choice(_CHARS) for _ in range(5))
    )
    path = rnd.choice(
        ["", "/", "/x", "/x/y.md", "/%zz", "/\u00e9", "/ a", "/\x00", "/\n", "/a" * 1500]
    )
    tail = (
        "".join(rnd.choice(_CHARS) for _ in range(rnd.randint(0, 8))) if rnd.random() < 0.5 else ""
    )
    sep = rnd.choice(["://", "://", "://", ":/", ":", ""])
    return f"{rnd.choice(_SCHEMES)}{sep}{host}{path}{tail}"


@pytest.mark.parametrize("seed", range(3))
def test_fetcher_never_raises_whatever_string_it_is_given(
    make_fetcher: Callable[..., Fetcher], seed: int
) -> None:
    site = Site({})
    f = make_fetcher(site)
    rnd = random.Random(seed)
    rejected = 0
    for _ in range(1500):
        url = _random_url(rnd, "anything")
        before = len(site.requested)
        ok = split_or_none(url) is not None
        f.fetch(url)
        f.probe(url, expect=Expect.ANY)
        f.probe_many([url], expect=Expect.ANY, liveness_only=True)
        if not ok:
            rejected += 1
            assert len(site.requested) == before, f"请求了一个解析不了的 URL：{url!r}"
    assert rejected > 100  # 前提：随机串里确实有大量解析不了的，否则上面等于没测


@pytest.mark.parametrize("mode", ["anything", "paths"])
@pytest.mark.parametrize("seed", range(2))
def test_the_whole_audit_survives_random_urls_everywhere(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path, seed: int, mode: str
) -> None:
    rnd = random.Random(seed)
    urls = [_random_url(rnd, mode) for _ in range(150)]
    page = (
        "<html><body>"
        + "".join(f'<a href="{html.escape(u, quote=True)}">l{i}</a>' for i, u in enumerate(urls))
        + "</body></html>"
    )
    one_line = [u.replace("\n", "").replace("\r", "") for u in urls]
    llms = (
        "# Acme\n\nAppend `.md` to any documentation page URL to get its Markdown.\n\n"
        + "".join(f"- [L{i}]({u})\n" for i, u in enumerate(one_line))
    )
    locs = "".join(f"<url><loc>{html.escape(u)}</loc></url>" for u in urls)
    robots = "User-agent: *\nAllow: /\n" + "".join(f"Sitemap: {u}\n" for u in one_line[:20])
    routes: dict[str, tuple[int, dict[str, str], str]] = {}
    for host in ("acmecloud.io", "www.acmecloud.io", "docs.acmecloud.io"):
        for path in ("/", "/pricing", "/changelog", "/docs", "/help"):
            routes[f"https://{host}{path}"] = (200, HTML, page)
        routes[f"https://{host}/llms.txt"] = (200, TEXT, llms)
        routes[f"https://{host}/robots.txt"] = (200, TEXT, robots)
        routes[f"https://{host}/sitemap.xml"] = (200, _XML, f"<urlset>{locs}</urlset>")
    site = Site(routes)
    report = audit_domain(
        AuditOptions(domain="acmecloud.io", contact=CONTACT, max_requests=0),
        fetcher=make_fetcher(site),
        store=FixtureStore(tmp_path / "empty-fixtures"),
        resolver=_resolver("acmecloud.io", "www.acmecloud.io", "docs.acmecloud.io"),
    )
    from geo_audit.report import render_html
    from geo_audit.report.json_out import report_from_json, report_to_json

    render_html(report)
    report_from_json(report_to_json(report))
    assert report.coverage.links_extracted >= 1
