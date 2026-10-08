"""robots.txt 的抓取层：RFC 9309 的跳转 / 读上限 / 读不到，加上防火墙能对它做的事。

## 修复前的五种读错

``Fetcher.robots_for`` 原来是**单发**的 ``_raw_request``，读 64 KiB，不跟跳转：

1. ``/robots.txt`` 301 / 308（apex → www 很常见）→ 当成「没有 robots.txt」，**全放行**。
   RFC 9309 §2.3.1.2：至少跟 5 跳，「可达就必须按文件里的规则办」。
2. 一次 503 / 一次 DNS 抖动 → 这个 host 在这一轮里**全部不许抓**，结果缓存一整轮。
3. 202 + ``x-amzn-waf-action: challenge``（AWS WAF 的 Challenge）→ 当成真的 robots.txt 解析，
   没有规则 → 报「放行」；403 + ``cf-mitigated`` → 报「站点没有 robots.txt」。
4. 200 KiB 的 robots.txt 在 64 KiB 之后的规则全丢（RFC 要求至少解析 500 KiB）。
5. 读不到时，报告里写「你的 robots.txt 禁止抓这个路径，我们遵守了」—— 站点什么都没禁止。

下面每条用例对应其中一种；「反方向」那几条守的是不要矫枉过正
（403 仍按 RFC 放行、404 仍是干净的缺席）。

## 设计：``policy`` 是我们怎么做，``readable`` 是我们知道多少

两件事分开。第一版把「挑战页」也定成全禁止（为了不说假话），结果整站体检不再往下抓：实测
gusto.com 从 19 个位置掉到 14 个，原来每个位置上具体的「防火墙挑战」证据全没了 —— 而按 RFC 9309，
403 是「不可用」，可以访问全部，原来的抓取行为是对的，错的只是**报告怎么说**。所以现在：
抓取行为严格按 RFC（4xx 与挑战页放行，5xx / 网络错误 / 跳转成环才全禁止），``readable`` 记下
「没真读到」，由报告层去说。
"""

from __future__ import annotations

import time
import types
from collections.abc import Callable

import httpx
import pytest

from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import (
    ROBOTS_BYTE_CAP,
    Fetcher,
    FetcherConfig,
    interpret_robots_response,
)
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.models import Expect, HttpResponse, RedirectHop, Verdict

AWS = {"x-amzn-waf-action": "challenge"}
RULES = "User-agent: *\nDisallow: /private\n"
Handler = Callable[[httpx.Request], httpx.Response]


class _Sleeps:
    """两处睡眠分开记：``backoff`` 是 client.py 的重试退避，``pacing`` 是限速器补足间隔。

    混在一个列表里时，「删掉退避」这种变异会被限速器的睡眠遮住（同一个 2.0 出现在两处），
    断言 ``assert sleeps`` 也永远为真。"""

    def __init__(self) -> None:
        self.backoff: list[float] = []
        self.pacing: list[float] = []


@pytest.fixture(autouse=True)
def _fast_clock(monkeypatch: pytest.MonkeyPatch) -> _Sleeps:
    """限速下限与重试退避都是合规 / 稳健性约束，测试里不能调低 —— 记录要睡多久，但不真睡。"""
    sleeps = _Sleeps()
    for module, sink in (("client", sleeps.backoff), ("ratelimit", sleeps.pacing)):
        fake = types.SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=sink.append)
        monkeypatch.setattr(f"geo_audit.fetch.{module}.time", fake)
    return sleeps


def _fetcher(handler: Handler, *, respect_robots: bool = True) -> Fetcher:
    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0, respect_robots=respect_robots),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )


def _only_robots(response: httpx.Response, log: list[str] | None = None) -> Handler:
    """/robots.txt 给定响应；任何别的路径都是测试失败（说明闸没拦住）。"""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            if log is not None:
                log.append(str(req.url))
            return response
        raise AssertionError(f"robots 没读到 / 说不许抓，却还是发了内容请求：{req.url}")

    return handler


# ── 1. 跳转 ────────────────────────────────────────────────────────────────
def test_robots_txt_that_redirects_is_followed_and_its_rules_apply() -> None:
    """修复前：301 → 「没有 robots.txt」→ 全放行，/private 照抓。"""
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        if req.url.host == "x.test" and req.url.path == "/robots.txt":
            return httpx.Response(301, headers={"location": "https://www.x.test/robots.txt"})
        if req.url.host == "www.x.test" and req.url.path == "/robots.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=RULES)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="content")

    f = _fetcher(handler)
    info = f.robots_for("https://x.test/")
    assert info.policy == "parsed" and info.status == 200
    assert "经 1 次跳转" in info.why and "www.x.test" in info.why
    assert f.robots_verdict("https://x.test/private/a") == "disallowed"
    assert f.robots_verdict("https://x.test/ok") == "allowed"
    assert seen[:2] == ["https://x.test/robots.txt", "https://www.x.test/robots.txt"]


def test_redirect_loop_and_too_many_redirects_are_unreadable() -> None:
    def loop(req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://x.test/robots.txt"})

    f = _fetcher(loop)
    info = f.robots_for("https://x.test/")
    assert info.policy == "disallow_all" and info.readable is False
    assert "redirect loop" in info.why

    n = {"i": 0}

    def long_chain(req: httpx.Request) -> httpx.Response:
        n["i"] += 1
        return httpx.Response(302, headers={"location": f"https://x.test/r{n['i']}"})

    info2 = _fetcher(long_chain).robots_for("https://x.test/")
    assert info2.policy == "disallow_all" and "too many redirects" in info2.why


# ── 2. 瞬时 5xx：重试，而不是整个 host 这一轮全部不许抓 ─────────────────────────
def test_a_transient_503_is_retried_and_the_real_file_is_used(_fast_clock: _Sleeps) -> None:
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text=RULES)

    info = _fetcher(handler).robots_for("https://x.test/")
    assert calls["n"] == 3 and info.policy == "parsed"  # 修复前：1 次请求，503 → 全部不许抓
    assert info.readable is True
    # 两次重试之间各退避一次：RETRY_BACKOFF = (2.0, 6.0)。删掉退避 = 连发三次请求。
    assert _fast_clock.backoff == [2.0, 6.0], "重试之间必须按 RETRY_BACKOFF 退避，不能连发"


def test_a_persistent_503_is_unreadable_after_the_retries() -> None:
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503)

    info = _fetcher(handler).robots_for("https://x.test/")
    assert calls["n"] == 3
    assert info.policy == "disallow_all" and info.readable is False and "HTTP 503" in info.why


# ── 3. 防火墙挑战页不是 robots.txt：不当成规则，但抓取照 RFC 走 ────────────────────
@pytest.mark.parametrize(
    ("response", "named"),
    [
        (httpx.Response(202, headers=AWS, text=""), "x-amzn-waf-action: challenge"),
        (
            httpx.Response(
                202,
                headers={"content-type": "text/html", **AWS},
                text="<html><script src='https://x.token.awswaf.com/challenge.js'></script></html>",
            ),
            "x-amzn-waf-action: challenge",
        ),
        (
            httpx.Response(
                403,
                headers={"content-type": "text/html", "cf-mitigated": "challenge"},
                text="<title>Just a moment...</title>",
            ),
            "cf-mitigated: challenge",
        ),
    ],
    ids=["aws-202-empty", "aws-202-interstitial", "cloudflare-403"],
)
def test_a_challenge_page_is_not_a_robots_txt_but_crawling_follows_rfc(
    response: httpx.Response, named: str
) -> None:
    """修复前：AWS 的 202 + 空正文被当成真 robots.txt（没有规则）→ 报「放行」；403 → 「站点没有」。

    现在：记为没读到（readable=False，why 点名响应头），**但抓取行为不变** —— 4xx / 无规则都是
    RFC 的「不可用 / 无限制」。于是每个位置上仍会拿到具体的挑战证据
    （BLOCKED / waf_challenge_header），而不是整站体检在 robots.txt 这一步就停下。"""
    content_requests: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path != "/robots.txt":
            content_requests.append(str(req.url))
        return response

    f = _fetcher(handler)
    info = f.robots_for("https://x.test/")
    assert info.policy == "allow_all" and info.readable is False
    assert named in info.why and "不是 robots.txt" in info.why
    p = f.probe("https://x.test/llms.txt", expect=Expect.TEXT_FILE)
    assert content_requests, "挑战页被当成「全禁止」，整站体检停在了 robots.txt 这一步"
    assert p.verdict is Verdict.BLOCKED
    assert p.classification.reason == "waf_challenge_header"


# ── 3b. 没带挑战头的挑战页（评审：200 + 正文是「Just a moment」，整张表读成「放行」）────────────
CF_BODY = (
    "<html><head><title>Just a moment...</title></head>"
    "<body>Checking your browser before accessing the site</body></html>"
)


def test_a_challenge_page_served_as_200_without_a_header_is_not_a_robots_txt() -> None:
    """评审复现：``/robots.txt`` 回 200 + text/html + 「Just a moment...」正文，**没有**
    cf-mitigated 头。只认响应头 + 任何 2xx 都算「读到了」→ readable=True、没有规则 →
    ``robots`` 子命令 22 行全是「放行」，退出码 0。位置判定拿同一个正文会判 BLOCKED。"""
    f = _fetcher(
        _only_robots(httpx.Response(200, headers={"content-type": "text/html"}, text=CF_BODY))
    )
    info = f.robots_for("https://x.test/")
    assert info.policy == "allow_all" and info.readable is False  # 照常抓，但没读到
    assert "挑战页" in info.why and "cf_just_a_moment" in info.why


def test_a_long_normal_page_that_merely_quotes_a_challenge_phrase_is_still_read_as_no_rules() -> (
    None
):
    """别矫枉过正：歧义标记只在「长得像拦截页」时才算（#13 的规则），一页几千字的正常 HTML 里
    出现 Just a moment 不是挑战页。"""
    quote = "<p>Just a moment, loading your dashboard...</p>"  # 歧义标记；不是 gate-only 的那几条
    page = "<html><body>" + "<p>Real content about widgets.</p>" * 60 + quote + "</body></html>"
    info = _fetcher(
        _only_robots(httpx.Response(200, headers={"content-type": "text/html"}, text=page))
    ).robots_for("https://x.test/")
    assert info.policy == "parsed" and info.readable is True and "HTML 页面" in info.why


def test_a_plain_text_robots_txt_that_mentions_the_phrase_is_not_a_challenge() -> None:
    """只有「正文是 HTML」才去问 is_blocked：纯文本里的注释不会把一份真文件读成挑战页。"""
    body = "# Just a moment please, our rules are being rewritten\n"
    info = _fetcher(
        _only_robots(httpx.Response(200, headers={"content-type": "text/plain"}, text=body))
    ).robots_for("https://x.test/")
    assert info.readable is True and info.why == ""


def test_a_real_rules_file_mislabelled_as_html_is_still_read() -> None:
    """只在「没有任何规则行」时才问 is_blocked：有规则的文件哪怕被标成 text/html、注释里碰巧有
    挑战页的词，也照读、照执行。"""
    body = "User-agent: *\nDisallow: /private\n# Just a moment, we are migrating hosts\n"
    f = _fetcher(
        _only_robots(httpx.Response(200, headers={"content-type": "text/html"}, text=body))
    )
    info = f.robots_for("https://x.test/")
    assert info.policy == "parsed" and info.readable is True
    assert f.robots_verdict("https://x.test/private/a") == "disallowed"


@pytest.mark.parametrize("body", ["", RULES], ids=["empty", "with-rules"])
def test_a_202_without_the_challenge_header_is_not_a_robots_txt(body: str) -> None:
    """202 =「已接受、还没处理完」，不是这份资源的表示；空正文读成「空文件 = 全放行」是假的。"""
    info = _fetcher(_only_robots(httpx.Response(202, text=body))).robots_for("https://x.test/")
    assert info.policy == "allow_all" and info.readable is False and info.raw == ""
    assert "HTTP 202" in info.why


# ── 4. 反方向：别矫枉过正 ────────────────────────────────────────────────────
def test_404_is_a_clean_absence_and_everything_is_allowed() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="content")

    f = _fetcher(handler)
    info = f.robots_for("https://x.test/")
    assert info.policy == "allow_all" and info.status == 404 and info.why == ""
    assert info.readable is True  # 观察到的缺席
    assert f.fetch("https://x.test/p", expect=Expect.ANY).status == 200


def test_plain_403_follows_rfc_but_is_not_called_absence() -> None:
    """RFC 9309：4xx = 「不可用」，爬虫可以访问全部 —— 照做；但不能写成「站点没有这个文件」。"""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(403, headers={"content-type": "text/html"}, text="Forbidden")
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="content")

    f = _fetcher(handler)
    info = f.robots_for("https://x.test/")
    assert info.policy == "allow_all" and info.readable is False
    assert "HTTP 403" in info.why and "不能当成「站点没有这个文件」" in info.why
    assert f.fetch("https://x.test/p", expect=Expect.ANY).status == 200


def test_429_is_not_absence_and_not_a_full_disallow() -> None:
    """限流：没读到（readable=False），抓取行为是原来的（放行，限流器自己会退避）。"""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    info = _fetcher(handler).robots_for("https://x.test/")
    assert info.policy == "allow_all" and info.readable is False and "429" in info.why


def test_ignore_robots_still_fetches_content_when_robots_is_unreadable() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(503)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="content")

    f = _fetcher(handler, respect_robots=False)
    assert f.fetch("https://x.test/p", expect=Expect.ANY).status == 200


def test_disallowed_still_reports_robots_disallowed_not_unreadable() -> None:
    f = _fetcher(_only_robots(httpx.Response(200, text="User-agent: *\nDisallow: /\n")))
    p = f.probe("https://x.test/llms.txt", expect=Expect.TEXT_FILE)
    assert p.classification.reason == "robots_disallowed"


# ── 5. 读上限 ──────────────────────────────────────────────────────────────
def test_rules_after_the_old_64_kib_cut_are_now_seen() -> None:
    """修复前读 64 KiB：200 KiB 的文件里排在尾部的 Disallow 丢了，/late 被放行。"""
    body = "# filler\n" * 22000 + "User-agent: *\nDisallow: /late\n"
    assert 64 * 1024 < len(body) < ROBOTS_BYTE_CAP  # 钉住前提：超过旧上限、没超过新上限
    f = _fetcher(
        _only_robots(httpx.Response(200, headers={"content-type": "text/plain"}, text=body))
    )
    info = f.robots_for("https://x.test/")
    assert info.policy == "parsed" and info.why == ""
    assert f.robots_verdict("https://x.test/late/x") == "disallowed"


def test_a_file_over_the_new_cap_says_so() -> None:
    body = "# filler\n" * 70000 + "User-agent: *\nDisallow: /late\n"
    assert len(body) > ROBOTS_BYTE_CAP
    f = _fetcher(
        _only_robots(httpx.Response(200, headers={"content-type": "text/plain"}, text=body))
    )
    info = f.robots_for("https://x.test/")
    assert "只解析了前 512 KiB" in info.why
    # 说明里的数字要对得上**实际解析的字节数**（光比对常量会在把上限改回 64 KiB 时照样绿）
    assert len(info.raw.encode("utf-8")) == ROBOTS_BYTE_CAP
    assert f.robots_verdict("https://x.test/late/x") == "allowed"  # RFC 允许忽略上限之后的内容


def test_an_html_shell_served_as_robots_txt_is_flagged() -> None:
    shell = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text="<!doctype html><html><body>app</body></html>",
    )
    info = _fetcher(_only_robots(shell)).robots_for("https://x.test/")
    assert info.policy == "parsed"
    assert "HTML 页面" in info.why and "没有任何规则" in info.why


# ── 5b. 跳转深度：RFC 9309 §2.3.1.2「至少跟 5 跳」 ─────────────────────────────
def test_five_consecutive_redirects_are_followed() -> None:
    """RFC：爬虫应当（SHOULD）至少跟 5 跳，5 跳内到得了文件就必须按文件办。
    把 MAX_REDIRECTS 压到 4，整套件原来仍然全绿 —— 这一条是它的咬点。"""

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        hops = {"/robots.txt": "/r1", "/r1": "/r2", "/r2": "/r3", "/r3": "/r4", "/r4": "/r5"}
        if path in hops:
            return httpx.Response(302, headers={"location": hops[path]})
        assert path == "/r5", path
        return httpx.Response(200, headers={"content-type": "text/plain"}, text=RULES)

    f = _fetcher(handler)
    info = f.robots_for("https://x.test/")
    assert info.policy == "parsed" and info.readable is True
    assert "经 5 次跳转" in info.why
    assert f.robots_verdict("https://x.test/private/a") == "disallowed"


# ── 5c. UTF-8 BOM：第一行不能因为它认不出来 ──────────────────────────────────────
@pytest.mark.parametrize(
    "content_type",
    ["text/plain", "text/plain; charset=utf-8", "text/plain; charset=iso-8859-1"],
)
def test_a_utf8_bom_does_not_hide_the_first_group(content_type: str) -> None:
    """Windows 记事本存出来的 robots.txt 常带 BOM。修复前第一行 ``\ufeffUser-agent: *`` 认不出，
    后面的 ``Disallow: /`` 成了无主规则 → 整份读成「全放行」（实测 can_fetch 返回 True）。
    RFC 9309 §2.2 规定文件必须是 UTF-8，所以连 Content-Type 里声明了别的 charset 也一样处理。"""
    body = b"\xef\xbb\xbfUser-agent: *\nDisallow: /private\n"
    f = _fetcher(
        _only_robots(httpx.Response(200, headers={"content-type": content_type}, content=body))
    )
    info = f.robots_for("https://x.test/")
    assert info.raw.startswith("User-agent:"), repr(info.raw[:20])
    assert f.robots_verdict("https://x.test/private/a") == "disallowed"
    assert f.robots_verdict("https://x.test/open") == "allowed"


# ── 5d. 重试的退避不能把同域健康的兄弟 host 永久拖慢 ──────────────────────────────
def _interval(f: Fetcher, domain: str) -> float:
    return f.limiter.stats().get(domain, {"interval": 2.0})["interval"]


def test_robots_5xx_retries_do_not_widen_the_domain_pacing() -> None:
    """限速桶是 registrable domain，``note_throttled`` 把整个域的间隔翻倍且本轮不回落。
    robots.txt 503 两次再 200：原来 interval 2 → 8，之后 10 条请求耗时 20 s → 80 s；
    robots.txt 一直 503：→ 16，同域下健康的 docs.x.test 6 条请求 14 s → 112 s。
    robots.txt 自己的 5xx 只退避，不拉宽（那个 host 按 RFC 本来就整个不抓）。"""
    calls = {"n": 0}

    def flaky(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text=RULES)

    f = _fetcher(flaky)
    assert f.robots_for("https://x.test/").policy == "parsed"
    assert _interval(f, "x.test") == 2.0

    def down(req: httpx.Request) -> httpx.Response:
        if req.url.host == "www.y.test" and req.url.path == "/robots.txt":
            return httpx.Response(503)
        if req.url.path == "/robots.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=RULES)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="ok")

    g = _fetcher(down)
    assert g.robots_for("https://www.y.test/").policy == "disallow_all"
    assert _interval(g, "y.test") == 2.0, "www 的 robots.txt 挂了，不该拖慢同域健康的 docs"
    assert g.fetch("https://docs.y.test/p", expect=Expect.ANY).status == 200


def test_robots_429_still_widens_and_content_5xx_still_widens() -> None:
    """豁免只给 robots.txt 的 5xx：429 是服务端明说的「慢点」，内容请求的 503 也照旧。"""
    r429 = _fetcher(lambda req: httpx.Response(429))
    r429.robots_for("https://x.test/")
    assert _interval(r429, "x.test") == 4.0

    def content_503(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(503)

    f = _fetcher(content_503)
    f.fetch("https://x.test/p", expect=Expect.ANY)
    assert _interval(f, "x.test") > 2.0


# ── 5e. probe() 对读不到 robots.txt 的 host：不发内容请求，判 UNKNOWN ────────────────
def test_probe_does_not_fetch_when_robots_is_unreadable() -> None:
    """``probe()`` 自己有一道闸（与 ``fetch()`` 那道各自独立）。原来没有测试咬它：
    把这个分支删掉，整套件仍然全绿。``_only_robots`` 对任何内容请求都会抛 AssertionError。"""
    f = _fetcher(_only_robots(httpx.Response(503)))
    p = f.probe("https://x.test/llms.txt", expect=Expect.TEXT_FILE)
    assert p.response is None, "闸没拦住：probe 还是去抓了内容"
    assert p.verdict is Verdict.UNKNOWN
    assert p.classification.reason == "robots_unreadable"
    assert "robots_disallowed" not in p.classification.reason


# ── 5f. 位置级措辞：RFC 只对 5xx / 网络错误「要求」，跳转成环是我们的选择 ──────────────
def test_unreadable_wording_does_not_claim_the_rfc_requires_a_loop_to_block() -> None:
    from geo_audit.models import UNKNOWN_REMEDY

    remedy = UNKNOWN_REMEDY["robots_unreadable"]
    assert "要求对 5xx 和网络错误" in remedy and "允许" in remedy and "保守" in remedy, (
        "要把「RFC 要求」限定在 5xx / 网络错误上，并说明跳转成环是我们取的保守一侧"
    )

    loop = _fetcher(
        lambda req: httpx.Response(302, headers={"location": "https://x.test/robots.txt"})
    )
    p = loop.probe("https://x.test/llms.txt", expect=Expect.TEXT_FILE)
    detail = " ".join(p.classification.evidence)
    assert p.classification.reason == "robots_unreadable"
    assert "RFC" not in detail, "位置级证据不替 RFC 背书：跳转成环 RFC 只是允许当作「没有」"
    assert "不是站点写了禁止" in detail


def test_coverage_gap_for_a_robots_gated_host_does_not_say_the_root_was_requested() -> None:
    """robots 闸在请求之前就拦了：根路径一个请求都没发。原来的缺口文案写「根路径也请求了」。"""
    from types import SimpleNamespace

    from geo_audit.models import DiscoveredHost, HostRole, SiteMap
    from geo_audit.pipeline import AuditOptions, NullProgress, RunState, _stage_ai_path

    def gap_detail(reason: str) -> str:
        host = DiscoveredHost(
            host="docs.example.invalid",
            role=HostRole.DOCS,
            reachable=True,
            verdict=Verdict.UNKNOWN,
            reason=reason,
        )
        sitemap = SiteMap(
            input_domain="example.invalid",
            registrable_domain="example.invalid",
            hosts=(host,),
            apex_www=None,
            sitemap_urls={},
            pricing_url=None,
            pricing_candidates_tried=(),
            ai_path_probes=(),
            robots={},
        )
        st = RunState(sitemap=sitemap)
        options = AuditOptions(
            domain="example.invalid", contact="ci@geo-audit.invalid", replay_fixtures=True
        )
        fake = SimpleNamespace(user_agent="geo-audit/test (contact: ci@geo-audit.invalid)")
        _stage_ai_path(st, options, fake, NullProgress())  # type: ignore[arg-type]
        (gap,) = st.coverage_gaps
        return gap.detail

    for reason in ("robots_unreadable", "robots_disallowed"):
        detail = gap_detail(reason)
        assert "根路径也请求了" not in detail and "根路径一个请求都没发" in detail, detail
        assert "没能看" in detail
    # 其它原因（根路径真的请求过、判不了）保持原文
    assert "根路径也请求了" in gap_detail("control_unavailable")


# ── 6. 纯函数：状态码表 ─────────────────────────────────────────────────────
def _resp(status: int, **kw: object) -> HttpResponse:
    return HttpResponse(
        url="https://x.test/robots.txt",
        final_url=str(kw.pop("final_url", "https://x.test/robots.txt")),
        status=status,
        headers=dict(kw.pop("headers", {})),  # type: ignore[call-overload]
        body=kw.pop("body", b""),  # type: ignore[arg-type]
        **kw,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("status", "policy", "readable", "why_has"),
    [
        (404, "allow_all", True, ""),
        (410, "allow_all", True, ""),
        (401, "allow_all", False, "HTTP 401"),
        (403, "allow_all", False, "HTTP 403"),
        (418, "allow_all", False, "HTTP 418"),
        (429, "allow_all", False, "429"),
        (202, "allow_all", False, "HTTP 202"),
        (204, "allow_all", True, ""),  # 有响应、没有内容 = 空文件
        (304, "allow_all", False, "没有可跟的 Location"),
        (500, "disallow_all", False, "HTTP 500"),
        (502, "disallow_all", False, "HTTP 502"),
        (599, "disallow_all", False, "HTTP 599"),
    ],
)
def test_status_table(status: int, policy: str, readable: bool, why_has: str) -> None:
    got_policy, raw, why, got_readable = interpret_robots_response(_resp(status))
    assert (got_policy, raw, got_readable) == (policy, "", readable)
    assert why_has in why
    assert (why == "") == (why_has == "")


def test_only_unreachable_is_a_full_disallow() -> None:
    """RFC 9309 §2.3.1.4：只有 5xx / 网络错误 / 跳转成环是「不可达」→ 完全不许抓；
    其余读不到的情形（挑战页、429、4xx、缺快照）都是「不可用」→ 照常抓，只是 readable=False。"""
    full_disallow = {
        s for s in range(100, 600) if interpret_robots_response(_resp(s))[0] == "disallow_all"
    }
    assert full_disallow == set(range(500, 600))
    err = HttpResponse(
        url="u", final_url="u", status=0, headers={}, body=b"", transport_error="timeout: x"
    )
    assert interpret_robots_response(err)[0] == "disallow_all"
    for headers in ({"x-amzn-waf-action": "challenge"}, {"cf-mitigated": "challenge"}):
        policy, _, _, readable = interpret_robots_response(_resp(403, headers=headers))
        assert (policy, readable) == ("allow_all", False)


def test_network_error_and_replay_gap_and_empty_2xx() -> None:
    err = HttpResponse(
        url="u", final_url="u", status=0, headers={}, body=b"", transport_error="timeout: x"
    )
    assert interpret_robots_response(err)[0] == "disallow_all"
    gap = _resp(599, headers={"x-geo-audit-fixture": "missing"})
    policy, _, why, readable = interpret_robots_response(gap)
    assert (policy, readable) == ("allow_all", False) and "replay" in why  # 缺快照不是站点的事实
    empty = interpret_robots_response(_resp(200))
    assert (empty[0], empty[3]) == ("allow_all", True)  # 有文件、正文为空
    hop = RedirectHop(status=301, from_url="a", to_url="b")
    moved = _resp(
        200, body=b"User-agent: *\n", redirects=(hop,), final_url="https://www.x.test/robots.txt"
    )
    assert "经 1 次跳转" in interpret_robots_response(moved)[2]
