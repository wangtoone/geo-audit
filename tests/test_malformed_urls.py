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
from geo_audit.fetch.classify import classify_response
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fetch.resolve import HostResolver, Resolution
from geo_audit.fetch.urlsafe import (
    INVALID_REDIRECT_ERROR,
    INVALID_URL_ERROR,
    REJECTED_URL_ERROR,
    UNPARSEABLE_REASON,
    UNPARSEABLE_RULE_ID,
    dns_name,
    invalid_redirect_error,
    invalid_url_error,
    is_url_error,
    join_or_none,
    rejected_url_error,
    requestable,
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
#: urlsplit 放行、**httpx 拒绝**的 URL（请求建不出来）：``split_or_none``（urllib 层）放行它们，
#: ``requestable``（请求层）拒绝。以前它们到了 ``Fetcher`` 才抛 ``httpx.InvalidURL`` /
#: ``idna.IDNAError``，同样是整次体检崩掉。
HTTPX_BAD_URLS = [
    "http://256.256.256.256/",  # IPv4 的某一段超过 255
    "http://[v1.fe]/",  # 方括号里不是合法的 IPv6 字面量
    "http://xn--/",  # 不是合法的 IDNA（httpx 解码主机名时才抛 idna.IDNAError）
    "http://xn--a/",
    "http://\u200bhost/",  # 零宽空格
    "http://ＨＯＳＴ/",  # 全角的主机名
    "http://acmevendor.io/\x00",  # 控制字符
    "http://acmevendor.io/a\x01b",
]
#: urlsplit 和 httpx 都放行，但 DNS 标签编不出来：``socket.getaddrinfo`` 抛 ``UnicodeError``（它不是
#: ``httpx.HTTPError``）。``requestable`` 按 RFC 1035 的长度（标签 1–63、整名 ≤253）拦。
DNS_BAD_URLS = [
    "http://a..b/",  # 空标签
    "https://docs..vendor.io/x",  # 模板里的变量没填
    "http://" + "a" * 64 + ".acmevendor.io/",  # 标签 64 字符
    "http://" + ".".join(["abcdefghi"] * 30) + "/",  # 整个名字 299 字符
    "http://" + ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62]) + "/",  # 恰好 254 字符
    "http://./",
]
ALL_BAD_URLS = [*BAD_URLS, *HTTPX_BAD_URLS, *DNS_BAD_URLS]
GOOD_URLS = [
    "http://[::1]/x",
    "https://a.test:8080/p?q=[1]#f",
    "/relative/path",
    "",
    "mailto:a@b.c",
    "//cdn.test/x.js",
    "https://a.test:0/",
]
#: 真实世界里合法、能请求的 URL：被拒绝就是误杀（这张表让「什么都拒绝」的实现过不了测试）
REAL_URLS = [
    "https://münchen.de/straße?q=ü",  # IDN 主机 + 非 ASCII 路径与查询
    "https://例え.jp/",
    "https://xn--mnchen-3ya.de/",
    "http://[::1]:8080/x",
    "http://[2001:db8::1]/x",
    "http://[fe80::1%25eth0]/",
    "https://user:pw@a.test:8443/p?q=1#f",
    "https://a.test/" + "x" * 8000,  # 8 KB 的路径
    "https://a.test/p?" + "&".join(f"k{i}=v{i}" for i in range(800)),  # 长查询串
    "https://a.test/a b|c^d{e}f",  # 浏览器会自己转义的字符
    "https://a.test./",  # 末尾的点
    "HTTPS://A.TEST/Docs",
    "http://localhost:8080/",
    "https://a.test/%E6%97%A5%E6%9C%AC",
    "https://" + "a" * 63 + ".test/",  # 恰好 63 字符的标签
    "https://" + ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61]) + "/",  # 恰好 253 字符的名字
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
        self.request_headers: list[dict[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requested.append(url)
        self.request_headers.append(dict(request.headers))
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

    def make(
        site: Site, *, respect_robots: bool = False, resolver: HostResolver | None = None
    ) -> Fetcher:
        f = Fetcher(
            FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=respect_robots),
            cache=HttpCache(tmp_path / f"cache{len(made)}.sqlite3", ua_profile="test"),
            limiter=DomainLimiter(2.0),
            transport=StopTransport(httpx.MockTransport(site.handler), threading.Event()),
            probe_url_provider=_control,
            resolver=resolver,
        )
        made.append(f)
        return f

    yield make
    for f in made:
        f.close()


# ── 1. urlsafe ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("url", BAD_URLS)
def test_urllib_rejects_these_and_so_do_we(url: str) -> None:
    with pytest.raises(ValueError):
        urlsplit(url).port  # noqa: B018 - 前提：urllib 真的拒绝（lazy 的 .port 也算）
    assert split_or_none(url) is None and not requestable(url)


@pytest.mark.parametrize("url", [*HTTPX_BAD_URLS, *DNS_BAD_URLS])
def test_urllib_accepts_these_but_the_request_cannot_be_made(url: str) -> None:
    """两层：``split_or_none``（urllib 能拆吗）放行，``requestable``（请求发得出去吗）拒绝。"""
    urlsplit(url).port  # noqa: B018 - 前提：urllib 放行（这两张表存在的理由）
    assert split_or_none(url) is not None
    assert not requestable(url)


@pytest.mark.parametrize("url", HTTPX_BAD_URLS)
def test_httpx_really_rejects_the_httpx_table(url: str) -> None:
    with pytest.raises((ValueError, httpx.InvalidURL)):
        httpx.URL(url).host  # noqa: B018


@pytest.mark.parametrize("url", DNS_BAD_URLS)
def test_httpx_lets_the_dns_table_through_which_is_why_the_labels_are_checked(url: str) -> None:
    httpx.URL(url).host  # noqa: B018 - 前提：httpx 放行，DNS 才是拦它的那一层


def test_requestable_has_nothing_to_say_about_a_url_without_a_host() -> None:
    """相对路径、``mailto:``：没有主机，没有标签可查；该不该请求不是它的问题。"""
    for url in ("/relative/path", "", "mailto:a@b.c", "?q=1", "#frag"):
        assert requestable(url), url
    assert not requestable("https://a..b/")  # 对照：有主机就查


def test_requestable_rejects_a_url_longer_than_httpx_allows() -> None:
    url = "https://a.test/" + "a" * 70_000
    urlsplit(url).port  # noqa: B018
    assert split_or_none(url) is not None and not requestable(url)


@pytest.mark.parametrize("url", REAL_URLS)
def test_real_world_urls_are_accepted(url: str) -> None:
    assert split_or_none(url) is not None and requestable(url)


@pytest.mark.parametrize("url", GOOD_URLS)
def test_split_or_none_accepts_ordinary_urls(url: str) -> None:
    parts = split_or_none(url)
    assert parts is not None and parts.geturl() == url


def test_join_or_none() -> None:
    base = "https://a.test/b/c"
    assert join_or_none(base, "../d?x=1") == "https://a.test/d?x=1"
    assert join_or_none(base, "//cdn.test/x.js") == "https://cdn.test/x.js"
    for bad in BAD_URLS:
        assert join_or_none(base, bad) is None, bad
    # urllib 能拆的归 requestable 管，不归 join 管：join 不替它们下结论
    for odd in [*HTTPX_BAD_URLS, *DNS_BAD_URLS]:
        assert join_or_none(base, odd) is not None, odd
    # 浏览器会去掉 URL 里的 TAB / LF（urllib 也去）：不是丢掉这条链接的理由
    assert join_or_none("https://a.test/", "/x\ty") == "https://a.test/xy"
    assert join_or_none("https://a.test/", "/x\ny") == "https://a.test/xy"


def test_is_url_error_matches_the_prefix_only() -> None:
    """报错文字里引着站点的 URL：别处出现这几个字不算（否则站点能决定自己被怎么分类）。"""
    for err in (
        invalid_url_error("http://["),
        invalid_redirect_error("http://["),
        rejected_url_error("https://x.test/", UnicodeError("e")),
    ):
        assert is_url_error(err)
        assert not is_url_error(f"timeout: {err}")
    assert not is_url_error(None) and not is_url_error("")


def test_dns_name_is_the_name_the_request_connects_to() -> None:
    assert dns_name("https://münchen.de/x") == "xn--mnchen-3ya.de"
    assert dns_name("HTTPS://Example.COM:8443/x") == "example.com"
    assert dns_name("http://[2001:db8::1]/x") == "2001:db8::1"
    assert dns_name("/relative") == "" and dns_name("http://256.256.256.256/") == ""


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
    """``http://[`` / ``http://a..b/`` 这类 Location httpx 放行，所以 ``INVALID_REDIRECT_ERROR``
    这条路必须真有人走：没有它，这一类就是原来的 ValueError / UnicodeError。"""
    assert split_or_none("http://[") is None and join_or_none("https://x.test/", "http://[") is None
    assert join_or_none("https://x.test/", "http://a..b/") is not None
    assert not requestable("http://a..b/")


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
        "https://x.test/x",
        # 报错文字里带着 URL：URL 里出现 DNS 错误的关键词，也不能让它被当成 DNS 抖动去问第二意见
        "https://x.test/getaddrinfo-resolve",
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
    probe = f.probe("https://x.test/y", expect=Expect.ANY, use_control=False)
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
    # 证据说清是哪一层拦的：urllib 拆不了，还是能拆但发不出请求
    assert verdict.evidence == (
        ("URL 无法解析，一次请求都没发",)
        if url in BAD_URLS
        else ("URL 能解析但发不出请求（httpx / DNS 拒绝它），一次请求都没发",)
    )


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


def test_probe_index_links_excludes_links_that_parse_but_cannot_be_requested(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    """urllib 拆得开、httpx / DNS 发不出请求的链接（``256.256.256.256``、控制字符、``a..b``）：
    和解析不了的同样被排除并写明原因；去噪规则排在前面
    （示例域名仍归 ``reserved_example_domain``）。"""
    text = (
        "# Acme\n- [Ok](https://acmevendor.io/ok.md)\n"
        "- [Ip](http://256.256.256.256/x)\n"
        "- [Ctl](https://acmevendor.io/a\x01b)\n"
        "- [Dns](https://docs..acmevendor.io/y)\n"
        "- [Ex](https://a.test/p\x01q)\n"
    )
    site = Site(
        {
            "https://acmevendor.io/llms.txt": (200, TEXT, text),
            "https://acmevendor.io/ok.md": (200, {"content-type": "text/markdown"}, "# ok\n"),
        }
    )
    f = make_fetcher(site)
    index = f.probe("https://acmevendor.io/llms.txt", expect=Expect.TEXT_FILE)
    report = ap.probe_index_links("acmevendor.io", index, fetcher=f)
    assert report.n_links == 5
    by_url = {url: ex.rule_id for url, ex in report.excluded}
    assert by_url == {
        "http://256.256.256.256/x": "unparseable_url",
        "https://acmevendor.io/a\x01b": "unparseable_url",
        "https://docs..acmevendor.io/y": "unparseable_url",
        "https://a.test/p\x01q": "reserved_example_domain",
    }
    assert [link.abs_url for link in report.probed] == ["https://acmevendor.io/ok.md"]
    assert not [u for u in site.requested if "256" in u or "\x01" in u or ".." in u]


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


@pytest.mark.parametrize("url", BAD_URLS)
def test_normalize_url_leaves_an_unparseable_url_as_it_is(url: str) -> None:
    assert normalize_url(f"  {url}  ") == url


def test_normalize_url_folds_what_urllib_can_parse_exactly_as_before() -> None:
    """httpx 拒绝、urllib 放行的 URL 不改身份：折叠和 main 一样，只有 urllib 拆不了的才原样返回。"""
    assert normalize_url("http://ＨＯＳＴ/a#f") == "http://ｈｏｓｔ/a"
    assert normalize_url("HTTP://A..B/X?utm_source=1&q=2") == "http://a..b/X?q=2"
    assert normalize_url("http://256.256.256.256/p/") == "http://256.256.256.256/p"


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
    if any(e.rule_id == UNPARSEABLE_RULE_ID for e in report.excluded):
        assert UNPARSEABLE_REASON[:8] in html  # 被排除的坏链接和原因在报告里看得见
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


def test_markup_in_an_unparseable_url_reaches_the_html_report_escaped(
    make_fetcher: Callable[..., Fetcher], tmp_path: Path
) -> None:
    """坏 URL 是站点给的字符串，原样进「被排除」清单、证据和 JSON：HTML 里只能是转义后的文字。"""
    evil = "http://[<script>alert(1)</script>"
    page = f'<html><body><a href="{html.escape(evil)}">x</a><a href="/old">old</a></body></html>'
    llms = f"# Acme\n\n- [E]({evil.replace('1', '2')})\n"
    routes: dict[str, tuple[int, dict[str, str], str]] = {}
    for host in ("acmecloud.io", "www.acmecloud.io", "docs.acmecloud.io"):
        for path in ("/", "/pricing", "/docs"):
            routes[f"https://{host}{path}"] = (200, HTML, page)
        routes[f"https://{host}/llms.txt"] = (200, TEXT, llms)
        routes[f"https://{host}/old"] = (301, {"location": "http://[<b>x"}, "")
    report = audit_domain(
        AuditOptions(domain="acmecloud.io", contact=CONTACT, max_requests=0),
        fetcher=make_fetcher(Site(routes)),
        store=FixtureStore(tmp_path / "empty-fixtures"),
        resolver=_resolver("acmecloud.io", "www.acmecloud.io", "docs.acmecloud.io"),
    )
    from geo_audit.report import render_html

    out = render_html(report)
    assert "&lt;script&gt;alert(" in out  # 看得见，而且是转义后的
    assert "<script>alert(" not in out and "<b>x" not in out


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
# 字符、非 ASCII 主机、IDNA 错误、超长、``//[x`` 开头的路径、百分号编码后才露出来的方括号……），
# 喂给 ``Fetcher`` 和整条管线，**robots 闸开着**（它把站点的字符串交给标准库再解析一遍：
# Python 3.11 / 3.12 上 ``urlparse`` 会对 ``Disallow: //[`` 和 ``https://%5B@x.test/p`` 抛
# ValueError，3.13 不抛，所以这些测试在 CI 的 3.11 / 3.12 上才咬得到）。
# 它抓出过前几节想不到的几类：httpx 拒绝而 urllib 放行的 URL、DNS 标签编不出来（``a..b``）、
# 根因分析把以 ``//[`` 开头的**路径**当 URL 解析、robots 解析器对站点规则行的二次解析。
_SCHEMES = ["http", "https", "HTTP", "https", "https", "ftp", "", "http:", "https:/", "javascript"]
_HOSTS = [
    # 一半是正常主机：被接受、真的发出请求，「什么都拒绝」的实现过不了
    *["acmevendor.io", "docs.acmevendor.io", "A.AcmeVendor.IO", "acmevendor.io:8443"] * 3,
    "münchen.acmevendor.io",
    "[::1]",
    "[2001:db8::1]:8080",
    "user:pw@acmevendor.io",
    # 解析不了 / 发不出请求
    "a..acmevendor.io",
    ".acmevendor.io",
    "-a.acmevendor.io",
    "xn--",
    "xn--a",
    "256.256.256.256",
    "1.2.3",
    "0x7f.1",
    "[::1",
    "::1]",
    "[v1.fe]",
    "[1:2:3:4:5:6:7:8:9]",
    "a b",
    "a​b.acmevendor.io",
    "ｈost.acmevendor.io",
    "℀",
    "a。b",
    "a@b",
    "a:b",
    "@",
    ":",
    "",
    "h" * 70 + ".acmevendor.io",
    "%41.acmevendor.io",
    "acmevendor.io:0",
    "acmevendor.io:65536",
    "acmevendor.io:abc",
    "acmevendor.io:-1",
    "acmevendor.io: 80",
    "acmevendor.io:80:80",
    "[::1]:abc",
    # 百分号编码后才露出方括号 / NFKC 展开：urlsplit 放行，标准库 robots 解析器会二次解析
    "%5B@acmevendor.io",
    "%E2%84%80@acmevendor.io",
    "u%40x@acmevendor.io",
]
_PRINTABLE = [
    *"abcXYZ019/\\?#[]@:;%&=+ .-_~!$'()*,<>\"{}|^`",
    "%5B",
    "%5D",
    "%2F",
    "%40",
    "%E2%84%80",
    "é",
    "中",
    "​",
    "\U0001f600",
    "℀",
    "́",
]
_CONTROL = ["\t", "\n", "\r", "\x00", "\x01", "\x7f", "﻿"]
_SEGMENTS = [
    "docs",
    "guide",
    "v2",
    "[slug]",
    "[locale]",
    "%zz",
    "%5B",
    "%5Bx%5D",
    "%2F",
    "..;",
    "..",
    ".",
    ":id",
    "{id}",
    "<id>",
    "@user",
    "a;b",
    "é",
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
_QUERIES = ["", "", "?a", "?=", "?&", "?%zz", "?%5B", "?a=b=c", "?utm_source=x", "?a[]=1", "?x=%"]


def _soup(rnd: random.Random, n: int) -> str:
    """可打印字符为主，偶尔掺一个控制字符（httpx 拒绝它们：占比太高就没有几条能被接受）。"""
    return "".join(rnd.choice(_CONTROL if rnd.random() < 0.04 else _PRINTABLE) for _ in range(n))


def _random_url(rnd: random.Random, mode: str) -> str:
    if mode == "paths":  # 全是合法 URL，路径里什么都有：死链分析（根因 / 修复提示）才会跑到
        host = rnd.choice(["www.acmecloud.io", "docs.acmecloud.io", "acmecloud.io", "other.test"])
        path = "/" + "/".join(rnd.choice(_SEGMENTS) for _ in range(rnd.randint(0, 5)))
        if rnd.random() < 0.15:
            path = "/" + path  # ``//[slug]/…``：以 // 开头的路径
        return f"https://{host}{path}{'/' if rnd.random() < 0.2 else ''}{rnd.choice(_QUERIES)}"
    if rnd.random() < 0.1:
        return _soup(rnd, rnd.randint(0, 24))
    host = rnd.choice(_HOSTS) if rnd.random() < 0.9 else _soup(rnd, 5)
    path = rnd.choice(
        ["", "/", "/x", "/x/y.md", "/%zz", "//%5B/p", "/é", "/ a", "/\x00", "/a" * 1500]
        + ["/x", "/p/q", "/docs/a"] * 3
    )
    tail = _soup(rnd, rnd.randint(1, 6)) if rnd.random() < 0.3 else ""
    sep = rnd.choice(["://", "://", "://", "://", ":/", ":", ""])
    return f"{rnd.choice(_SCHEMES)}{sep}{host}{path}{tail}"


def _hostile_robots(rnd: random.Random) -> str:
    """一份 robots.txt：有效规则之外混着解析不了的规则行（URL 写在了该写路径的地方）。"""
    bad = [
        f"{rnd.choice(['Allow', 'Disallow'])}: {_random_url(rnd, 'anything')}" for _ in range(12)
    ]
    bad = [line.replace("\n", "").replace("\r", "") for line in bad]
    fixed = ["Disallow: https://[your-domain]/search", "Disallow: //[", "Allow: http://["]
    return "\n".join(["User-agent: *", *fixed, *bad, "Disallow: /private", ""])


@pytest.mark.parametrize("respect_robots", [False, True], ids=["robots_off", "robots_on"])
@pytest.mark.parametrize("seed", range(3))
def test_fetcher_never_raises_whatever_string_it_is_given(
    make_fetcher: Callable[..., Fetcher], seed: int, respect_robots: bool
) -> None:
    rnd = random.Random(seed)
    site = _RobotsSite(_hostile_robots(rnd), {})
    f = make_fetcher(site, respect_robots=respect_robots)
    rejected = accepted = 0
    for _ in range(1000):
        url = _random_url(rnd, "anything")
        before = len(site.requested)
        ok = requestable(url)
        f.fetch(url)
        f.probe(url, expect=Expect.ANY)
        f.probe_many([url], expect=Expect.ANY, liveness_only=True)
        if ok:
            accepted += 1
        else:
            rejected += 1
            assert len(site.requested) == before, f"请求了一个发不出请求的 URL：{url!r}"
    # 前提：随机串里两种都有一大批，否则上面等于没测；被接受的还要真的发出了请求
    # （「什么都拒绝」的实现过不了）
    assert rejected > 100 and accepted > 200
    assert len([u for u in site.requested if not u.endswith("/robots.txt")]) > 150


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
    robots = (
        _hostile_robots(rnd).replace("Disallow: /private\n", "")
        + "Allow: /\n"
        + "".join(f"Sitemap: {u}\n" for u in one_line[:20])
    )
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
        fetcher=make_fetcher(site, respect_robots=True),
        store=FixtureStore(tmp_path / "empty-fixtures"),
        resolver=_resolver("acmecloud.io", "www.acmecloud.io", "docs.acmecloud.io"),
    )
    _assert_report_survives_output(report)
    assert report.coverage.links_extracted >= 1


# ── 8. 独立 review 之后补的 ──────────────────────────────────────────────────
#
# 复现过、修掉的缺陷，各一组测试（修之前这些都是红的：见提交信息里的清单）。
class _RobotsSite(Site):
    """``Site`` 再加上每个 host 都有一份 robots.txt（``Site`` 单用的话 robots.txt 是 404）。"""

    def __init__(
        self, robots: str, routes: dict[str, tuple[int, dict[str, str], str]] | None = None
    ) -> None:
        super().__init__(routes or {})
        self.robots = robots

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            self.requested.append(str(request.url))
            return httpx.Response(200, headers=TEXT, text=self.robots)
        return super().handler(request)


_HOSTILE_ROBOTS_RULES = [
    "Disallow: https://[your-domain]/search",
    "Disallow: //[",
    "Allow: http://[",
]


def _install_old_stdlib_robots(monkeypatch: pytest.MonkeyPatch) -> None:
    """让任何 Python 的 ``urllib.robotparser`` 表现得像 3.11 / 3.12（3.13 不抛，那两个版本才会）：

    * ``parse``：已经进了某个 ``User-agent`` 组的 ``Allow`` / ``Disallow`` 行有 ``[`` 就抛
      ValueError（3.11 / 3.12 对规则的路径做 ``urlparse``）；
    * ``can_fetch``：URL 的 authority 百分号解码后有方括号就抛 ValueError
      （3.11 / 3.12 先 ``urlparse(unquote(url))``，userinfo 解码成 ``[`` 就炸）。
    """
    import urllib.parse
    from urllib.robotparser import RobotFileParser

    real_parse, real_can_fetch = RobotFileParser.parse, RobotFileParser.can_fetch

    def parse(self: RobotFileParser, lines: Any) -> None:
        lines = list(lines)
        in_group = False
        for line in lines:
            key = line.split(":", 1)[0].strip().lower()
            if key == "user-agent":
                in_group = True
            elif key in ("allow", "disallow") and in_group and "[" in line:
                raise ValueError("Invalid IPv6 URL")
        real_parse(self, lines)

    def can_fetch(self: RobotFileParser, useragent: str, url: str) -> bool:
        authority = urllib.parse.unquote(url).split("://", 1)[1].split("/", 1)[0]
        if "[" in authority or "]" in authority:
            raise ValueError("Invalid IPv6 URL")
        return real_can_fetch(self, useragent, url)

    monkeypatch.setattr(RobotFileParser, "parse", parse)
    monkeypatch.setattr(RobotFileParser, "can_fetch", can_fetch)


_STDLIB = pytest.mark.parametrize("old_stdlib", [False, True], ids=["real_stdlib", "as_in_3_12"])


@_STDLIB
@pytest.mark.parametrize("rule", _HOSTILE_ROBOTS_RULES)
def test_a_hostile_rule_line_in_robots_txt_costs_that_line_only(
    make_fetcher: Callable[..., Fetcher],
    monkeypatch: pytest.MonkeyPatch,
    rule: str,
    old_stdlib: bool,
) -> None:
    """3.11 / 3.12 的 ``RobotFileParser.parse`` 对这些规则行抛 ValueError（整份文件连同整次体检
    一起丢）；现在只丢这一行，站点的其它规则照常生效。"""
    if old_stdlib:
        _install_old_stdlib_robots(monkeypatch)
    site = _RobotsSite(
        f"User-agent: *\n{rule}\nDisallow: /private\n",
        {
            "https://x.test/ok": (200, HTML, "<html>ok</html>"),
            "https://x.test/private/a": (200, HTML, "<html>secret</html>"),
        },
    )
    f = make_fetcher(site, respect_robots=True)
    assert f.probe("https://x.test/ok", expect=Expect.HTML_PAGE).verdict is Verdict.OK
    blocked = f.probe("https://x.test/private/a", expect=Expect.HTML_PAGE)
    assert (blocked.verdict, blocked.classification.reason) == (
        Verdict.UNKNOWN,
        "robots_disallowed",
    )
    assert "https://x.test/private/a" not in site.requested


def test_the_robots_parser_drops_only_the_lines_the_stdlib_cannot_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from geo_audit.fetch.client import _robots_parser

    _install_old_stdlib_robots(monkeypatch)
    parser = _robots_parser(
        ["User-agent: *", "Disallow: https://[your-domain]/x", "Disallow: /private", "Allow: //["]
    )
    assert not parser.can_fetch("bot", "https://x.test/private/a")
    assert parser.can_fetch("bot", "https://x.test/ok")


def test_can_fetch_is_not_handed_the_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    from urllib.robotparser import RobotFileParser

    from geo_audit.fetch.client import _can_fetch

    _install_old_stdlib_robots(monkeypatch)
    parser = RobotFileParser()
    parser.parse(["User-agent: *", "Disallow: /private", "Disallow: /search?q="])
    assert _can_fetch(parser, "bot", "https://%5B@x.test/p") is True
    assert _can_fetch(parser, "bot", "https://%5B@x.test/private/a") is False
    assert _can_fetch(parser, "bot", "https://x.test//%5B/p?q=1#f") is True
    assert _can_fetch(parser, "bot", "https://x.test/search?q=1") is False  # 查询串也参与匹配


def test_can_fetch_gives_an_authority_less_string_a_path_not_a_host() -> None:
    """``ftp:x`` 没有 authority：路径接在假 authority 后面会变成主机名（NFKC 会让真标准库抛）。"""
    from urllib.robotparser import RobotFileParser

    from geo_audit.fetch.client import _can_fetch

    parser = RobotFileParser()
    parser.parse(["User-agent: *", "Disallow: /private"])
    assert _can_fetch(parser, "bot", "ftp:acme\u2100x") is True
    assert _can_fetch(parser, "bot", "mailto:a@b.c") is True


@_STDLIB
@pytest.mark.parametrize(
    "url",
    [
        "https://%5B@x.test/p",
        "https://%E2%84%80@x.test/p",
        "https://x.test//%5B/p",
        "https://x.test/%2F%2F",
    ],
)
def test_the_robots_gate_survives_urls_that_unquote_into_garbage(
    make_fetcher: Callable[..., Fetcher],
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    old_stdlib: bool,
) -> None:
    if old_stdlib:
        _install_old_stdlib_robots(monkeypatch)
    site = _RobotsSite("User-agent: *\nDisallow: /private\n", {})
    f = make_fetcher(site, respect_robots=True)
    f.fetch(url)
    f.probe(url, expect=Expect.ANY)
    f.probe_many([url], expect=Expect.ANY)
    blocked = f.probe("https://%5B@x.test/private/a", expect=Expect.ANY)
    assert (blocked.verdict, blocked.classification.reason) == (
        Verdict.UNKNOWN,
        "robots_disallowed",
    )


def test_a_declared_host_that_cannot_be_requested_is_not_probed() -> None:
    """模板里的变量没填：``https://docs..vendor.io``（空标签）。以前发现阶段会抛 UnicodeError。"""
    body = "see https://docs..vendor.io/llms.txt and https://docs..vendor.io/x and https://docs.ok.io/a"
    assert discovery.mine_declared_hosts([body, body], apex="acme.io") == ["docs.ok.io"]


@pytest.mark.parametrize("host", ["a..b", "docs..vendor.io", "a" * 64 + ".io", "مثال1.com"])
def test_the_system_resolver_survives_a_host_the_idna_codec_refuses(
    host: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket

    from geo_audit.fetch.resolve import _system_resolve

    def getaddrinfo(name: str, *args: Any, **kwargs: Any) -> Any:
        name.encode("idna")  # 真的 getaddrinfo 先做这一步：编不出来就抛 UnicodeError，不碰网络
        raise socket.gaierror(8, "nodename nor servname provided, or not known")

    monkeypatch.setattr("geo_audit.fetch.resolve.socket.getaddrinfo", getaddrinfo)
    with pytest.raises(UnicodeError):
        host.encode("idna")  # 前提：标准库的 IDNA 编码器真的拒绝它
    addresses, error = _system_resolve(host)
    assert addresses == () and error is not None and error.startswith("getaddrinfo")
    assert "UnicodeError" in error or "UnicodeEncodeError" in error


def test_a_dns_failure_for_an_idn_host_asks_the_resolver_about_the_a_label(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    """``https://مثال1.com/`` 在 IDNA-2008 下合法，标准库的 IDNA-2003 编码器却拒绝它：问 DNS
    要用 httpx 连接用的名字（punycode），不是 Unicode 主机名。"""

    class DnsDown(Site):
        def handler(self, request: httpx.Request) -> httpx.Response:
            self.requested.append(str(request.url))
            raise httpx.ConnectError("[Errno 8] nodename nor servname provided, or not known")

    asked: list[str] = []

    def resolver(host: str) -> Resolution:
        asked.append(host)
        return Resolution(host, (), "system", poisoned=False, error="NXDOMAIN")

    url = "https://مثال1.com/x"
    f = make_fetcher(DnsDown({}), resolver=resolver)
    resp = f.fetch(url)
    assert resp.status == 0
    assert asked and all(h.isascii() for h in asked) and asked[0] == dns_name(url)


def test_a_url_with_an_ipv6_literal_gets_its_robots_txt_from_the_bracketed_origin(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    site = _RobotsSite(
        "User-agent: *\nDisallow: /private\n", {"http://[2001:db8::1]/x": (200, HTML, "ok")}
    )
    f = make_fetcher(site, respect_robots=True)
    assert f.fetch("http://[2001:db8::1]/x").status == 200
    assert "http://[2001:db8::1]/robots.txt" in site.requested  # 以前：去掉了方括号，请求建不出来
    blocked = f.probe("http://[2001:db8::1]/private/a", expect=Expect.ANY)
    assert blocked.classification.reason == "robots_disallowed"


class _PinSite(Site):
    """系统解析失败、第二解析器给了 IP：只有连到那个 IP 的请求会成功。"""

    def __init__(self, ip: str) -> None:
        super().__init__({})
        self.ip = ip
        self.sni: list[Any] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requested.append(str(request.url))
        self.request_headers.append(dict(request.headers))
        self.sni.append(request.extensions.get("sni_hostname"))
        if request.url.host != self.ip:
            raise httpx.ConnectError("[Errno 8] nodename nor servname provided, or not known")
        return httpx.Response(200, headers=HTML, text="<html>pinned</html>")


@pytest.mark.parametrize(
    "ip, url, host_header",
    [
        ("2001:db8::1", "https://ipv6only.test/x", "ipv6only.test"),  # IPv6 的 IP 进 URL 要加方括号
        ("93.184.216.34", "https://münchen.test/x", "xn--mnchen-3ya.test"),  # Host 头只能是 ASCII
    ],
)
def test_the_pinned_ip_retry_builds_a_valid_request(
    make_fetcher: Callable[..., Fetcher], ip: str, url: str, host_header: str
) -> None:
    site = _PinSite(ip)
    f = make_fetcher(site, resolver=lambda h: Resolution(h, (ip,), "8.8.8.8", poisoned=False))
    resp = f.fetch(url)
    assert resp.status == 200, resp.transport_error
    assert site.request_headers[-1]["host"] == host_header
    assert site.sni[-1] == host_header  # TLS 的 SNI 也是 ASCII 名字


@pytest.mark.parametrize(
    "href",
    [
        "data:text/plain;base64," + "A" * 70_000,  # 长过 httpx 的 65536 字符上限
        "mailto:a@b.c\x7f",
        "javascript:void(0)\x01",
        "tel:+1\x00",
    ],
)
def test_a_non_http_link_stays_non_http_scheme_even_when_httpx_would_refuse_it(href: str) -> None:
    """``unparseable_url`` 排在去噪规则之后：它们原来就是 ``non_http_scheme``，不是「解析不了」"""
    verdict = dl.classify_link(
        href,
        source_page="https://acme.io/",
        ctx=LinkContext(source_page="https://acme.io/"),
        client=None,  # type: ignore[arg-type]  # 在发请求之前就返回
        store=None,  # type: ignore[arg-type]
        fetcher=None,
        source_role="home",
    )
    assert (verdict.state, verdict.rule_id) == (LinkState.EXCLUDED, "non_http_scheme")


def test_the_reason_says_what_the_tool_did_not_do_and_not_that_the_site_is_broken() -> None:
    assert "缺陷" not in UNPARSEABLE_REASON  # 占位符漏进示例代码和漏进链接长得一模一样
    assert "``" not in UNPARSEABLE_REASON  # 进 HTML / JSON 的 rule_desc：不带 reST 记号
    assert "没有检查" in UNPARSEABLE_REASON and "httpx" in UNPARSEABLE_REASON


@pytest.mark.parametrize(
    "word", ["timeout", "resolve", "poison", "tls", "ssl", "reset", "nodename"]
)
def test_a_url_error_is_never_classified_by_substrings_of_the_site_url(word: str) -> None:
    """报错文字里引着站点自己的 URL：含 "timeout" / "resolve" 的 URL 不是超时、也不是 DNS 失败。"""
    for err in (
        invalid_url_error(f"http://[/{word}"),
        invalid_redirect_error(f"http://[/{word}"),
        rejected_url_error(f"https://x.test/{word}", UnicodeError(word)),
    ):
        cls = classify_response(
            0, {}, "", url="https://x.test/p", expect=Expect.ANY, transport_error=err
        )
        assert (cls.verdict, cls.reason) == (Verdict.UNKNOWN, "network_error"), err
        assert dl._transport_error_kind(err) is None, err


def test_the_parsing_level_functions_never_ask_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    """``join_or_none`` / ``normalize_url`` / ``path_segments`` 对每条链接都跑；它们只拆 URL，
    不该为此建一个 httpx.URL（长 base 上慢 50 倍以上，每条相对链接都要再付一次）。"""
    from geo_audit.rootcause import path_segments

    calls: list[str] = []

    def spy(url: str) -> Any:
        calls.append(url)
        raise AssertionError("httpx.URL asked")

    long_base = "https://acme.io/" + "é" * 5000 + "/llms.txt"
    monkeypatch.setattr("geo_audit.fetch.urlsafe.httpx.URL", spy)
    assert join_or_none(long_base, "p.md") is not None
    assert normalize_url(long_base) and path_segments(long_base) and split_or_none(long_base)
    assert calls == []
    with pytest.raises(AssertionError):  # 对照：请求层确实问了，探针没坏
        requestable("https://acme.io/x")


def test_rejected_urls_cost_no_request_and_no_pacing(
    make_fetcher: Callable[..., Fetcher], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``https://a..test/N``（空标签）发不出请求：不计入请求数（``--max-requests`` 不被它们耗光）、
    不等限速器（同一个域的第二个请求本来要等 2 秒）。"""
    sleeps: list[float] = []
    fake = types.SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=sleeps.append)
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time", fake)
    monkeypatch.setattr("geo_audit.fetch.client.time", fake)
    site = Site({})
    f = make_fetcher(site)
    for i in range(5):
        assert f.fetch(f"https://a..test/{i}").status == 0
    assert f.http_requests == 0 and site.requested == [] and sleeps == []


def test_a_dead_link_whose_path_starts_with_two_slashes_is_segmented_as_a_path() -> None:
    """``https://acme.io//docs/x`` 的路径是 ``//docs/x``：``docs`` 是第一段，不是主机。"""
    from geo_audit.rootcause import DeadTarget, ProbeLedger, _detect_relative_path_prefixed

    target = DeadTarget(
        norm_url="https://acme.io//docs/x",
        abs_url="https://acme.io//docs/x",
        source_page="https://acme.io/docs",
    )
    verdict = _detect_relative_path_prefixed(
        target, ProbeLedger(statuses={"https://acme.io/x": 200})
    )
    assert verdict is not None and verdict.defect == "relative_path_prefixed"


def test_path_segments_reads_urls_including_protocol_relative_ones() -> None:
    from geo_audit.rootcause import path_segments

    assert path_segments("//cdn.test/a/b") == ("a", "b")
    assert path_segments("ftp://h/a/b") == ("a", "b")
    assert path_segments("https://acme.io/a/b/") == ("a", "b")


# ── 8b. 以前没钉住的行为 ────────────────────────────────────────────────────
def test_the_invalid_url_evidence_quotes_the_url(make_fetcher: Callable[..., Fetcher]) -> None:
    resp = make_fetcher(Site({})).fetch("http://[")
    assert repr("http://[") in (resp.transport_error or "")


def test_an_unrelated_error_inside_the_exchange_is_not_relabelled(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    """``(httpx.InvalidURL, UnicodeError)`` 之外的异常照旧抛：我们自己的 bug 不能被记成站点的问题"""
    with pytest.raises(ValueError, match="boom"):
        make_fetcher(_Exploding(ValueError("boom"))).fetch("https://x.test/x")


def test_a_relative_location_after_a_cross_host_hop_is_resolved_against_that_hop(
    make_fetcher: Callable[..., Fetcher],
) -> None:
    site = Site(
        {
            "https://x.test/a": (301, {"location": "https://y.test/b"}, ""),
            "https://y.test/b": (301, {"location": "/c"}, ""),
            "https://y.test/c": (200, HTML, "<html>c</html>"),
        }
    )
    resp = make_fetcher(site).fetch("https://x.test/a")
    assert (resp.status, resp.final_url) == (200, "https://y.test/c")


def test_the_no_response_verdict_names_what_happened(make_fetcher: Callable[..., Fetcher]) -> None:
    site = Site(
        {"https://acme.io/old": (301, {"location": "http://[/timeout"}, "")},
    )
    verdict = dl.classify_link(
        "https://acme.io/old",
        source_page="https://acme.io/",
        ctx=LinkContext(source_page="https://acme.io/"),
        client=httpx.Client(transport=httpx.MockTransport(site.handler)),
        store=FixtureStore(Path("nonexistent-fixtures")),
        fetcher=make_fetcher(site),
        source_role="home",
    )
    assert verdict.state is LinkState.UNKNOWN and verdict.rule_id == "no_http_response"
    assert any(
        "没有拿到 HTTP 响应" in e and "invalid redirect Location" in e for e in verdict.evidence
    ), verdict.evidence


def test_an_unparseable_verdict_says_no_request_was_sent() -> None:
    verdict = dl.classify_link(
        "http://[",
        source_page="https://acme.io/",
        ctx=LinkContext(source_page="https://acme.io/"),
        client=None,  # type: ignore[arg-type]
        store=None,  # type: ignore[arg-type]
        fetcher=None,
        source_role="home",
    )
    assert verdict.evidence == ("URL 无法解析，一次请求都没发",)


def test_the_sitemap_cap_applies_after_the_unparseable_urls_are_dropped(
    make_fetcher: Callable[..., Fetcher], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(discovery, "MAX_SITEMAP_URLS", 3)
    locs = "".join(
        f"<url><loc>{u}</loc></url>"
        for u in ["http://[", "http://h:abc/"] + [f"https://x.test/p{i}" for i in range(5)]
    )
    site = Site(
        {
            "https://x.test/sitemap.xml": (
                200,
                {"content-type": "application/xml"},
                f"<urlset>{locs}</urlset>",
            )
        }
    )
    got = discovery.fetch_sitemap_urls(make_fetcher(site), "x.test", ())
    assert got == ("https://x.test/p0", "https://x.test/p1", "https://x.test/p2")
