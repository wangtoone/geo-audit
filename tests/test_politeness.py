"""J 组 · 抓取合规（§3.1 那张表逐行 / 验收 A39–A42）。

§3.1 的每一行都是「一条合规约束 + 它的实现位置 + 机器可查的守卫」。这个文件
就是那一列「机器可查」。六条约束：

============================  ==========================================
约束                          守卫
============================  ==========================================
单域名 ≤1 请求/2 秒           :func:`test_rate_limit_two_seconds`（规格点名）
带真实 UA + 联系邮箱          :func:`test_ua_carries_contact` 等
不伪装浏览器                  :func:`test_no_browser_ua_anywhere`
不绕 WAF/不解 CAPTCHA/不代理  :func:`test_no_bypass_machinery_in_code`
只抓无登录公开页（robots）    :func:`test_robots_disallow_makes_no_request` 等
429 之后必须退让              :func:`test_throttle_doubles_and_honours_retry_after`
============================  ==========================================

**一秒真 sleep 都没有。** 限速下限是 2s/域，照着睡的测试要么慢要么 flaky。
:class:`FakeClock` 把 ``ratelimit`` 模块里的 ``time`` 整个换掉：``monotonic()``
读假表，``sleep()`` 把假表往前拨并记账。于是「相邻两次请求间隔 ≥ 2.0s」这条
断言测的是**限速器算出的等待时长**，比真睡 2 秒更严（真睡还会被机器负载糊掉）。
假表起点刻意设成 1_000.0 而不是 0.0：``_Bucket.last_hit`` 初值是 0.0，从 0 起表
会让**第一次** hold 也算出 2 秒欠账，与真实行为（进程启动时 monotonic 已经很大，
第一次不等）不符。

与既有测试的分工：``tests/test_infra.py`` 是搬入前就冻结的 146 条回归里的一份，
它用**真** 2 秒 sleep 测同一条约束（``test_rate_limit_serialises_same_domain``），
断言一行不许改（A4）。这里不是重复，是补三样它没有的：假时钟下的精确间隔、
CLI 侧的合规守卫（``--rate`` / ``--contact``）、以及源码级的「不绕 WAF」闸门。
"""

from __future__ import annotations

import itertools
import re
import threading
import tokenize
from pathlib import Path
from typing import Any

import httpx
import pytest

import geo_audit.fetch.ratelimit as ratelimit_mod
from geo_audit import cli
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import (
    RETRY_STATUSES,
    Fetcher,
    FetcherConfig,
    build_user_agent,
)
from geo_audit.fetch.ratelimit import (
    MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    DomainLimiter,
    registrable_domain,
)
from geo_audit.fixtures import DNS_ABSENT_KEY, FixtureResolver, FixtureStore
from geo_audit.models import NOT_EVALUATED_REASONS, UNKNOWN_REMEDY, Expect, Status, Verdict
from geo_audit.pipeline import AuditOptions, StopTransport, audit_domain

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
CONTACT = "you@yourco.com"

#: A40 的 UA 形状。规格原文照抄。
UA_PATTERN = re.compile(r"^geo-audit/\d+\.\d+\.\d+ \(\+https://[^;]+; contact: .+@.+\)$")

#: §3.1「不绕 WAF、不解 CAPTCHA、不用住宅代理」的机器判据。前五个是规格
#: 原文（A41 的 grep），后四个是同一类东西的常见入口，一并挡掉。
BYPASS_MARKERS: tuple[str, ...] = (
    "2captcha",
    "anticaptcha",
    "capsolver",
    "residential",
    "proxy_pool",
    "cloudscraper",
    "undetected_chromedriver",
    "selenium_stealth",
    "flaresolverr",
)

#: 「不伪装浏览器」的机器判据（§3.1 第三行）。整份源码原文扫，含注释与字符串 ——
#: 一个浏览器 UA 字面量出现在任何地方都没有正当理由。
BROWSER_UA_MARKERS: tuple[str, ...] = (
    "Mozilla/5.0",
    "Chrome/",
    "Safari/",
    "Edg/",
    "AppleWebKit",
)


# --------------------------------------------------------------------------- #
# 假时钟
# --------------------------------------------------------------------------- #


class FakeClock:
    """替换 ``ratelimit`` 模块里的 ``time``。只需要 ``monotonic`` 与 ``sleep``。

    ``sleep`` 不真睡，只把表往前拨并把时长记进 :attr:`slept` —— 于是测试既能
    断言「间隔 ≥ 2s」，也能断言「等待是限速器要求的，不是测试自己造的」。
    """

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    """把 ``ratelimit.time`` 整个换成假表（只影响这一个模块，用完自动还原）。"""
    fake = FakeClock()
    monkeypatch.setattr(ratelimit_mod, "time", fake)
    return fake


# --------------------------------------------------------------------------- #
# 1. 单域名 ≤1 请求 / 2 秒
# --------------------------------------------------------------------------- #


def test_min_interval_is_the_frozen_two_seconds() -> None:
    """§3.1 第一行：``MIN_INTERVAL_SECONDS = 2.0``。字面量照抄规格。"""
    assert MIN_INTERVAL_SECONDS == 2.0
    assert MAX_INTERVAL_SECONDS == 30.0


def test_rate_limit_two_seconds(clock: FakeClock) -> None:
    """§3.1 点名的这条：相邻两次请求间隔 ≥ 2.0s（A39）。

    三次 hold 落在 **三个不同 host、同一个 registrable domain** 上 ——
    ``docs.acme.test`` / ``www.acme.test`` / ``acme.test`` 共用一个 2 秒桶。
    这是规格特意强调的口径（"brevo.com / www.brevo.com / developers.brevo.com
    共用一个 2 秒桶"）：按 host 分桶会让 apex+www+docs 各烧一次配额。
    """
    limiter = DomainLimiter()
    stamps: list[float] = []
    for host in ("docs.acme.test", "www.acme.test", "acme.test"):
        with limiter.hold(host):
            stamps.append(clock.monotonic())

    gaps = [later - earlier for earlier, later in itertools.pairwise(stamps)]
    assert len(gaps) == 2
    assert all(gap >= MIN_INTERVAL_SECONDS for gap in gaps), gaps
    # 等待是限速器要求的（两次各 2.0s），不是测试自己拨的表
    assert clock.slept == [2.0, 2.0]


def test_first_request_does_not_wait(clock: FakeClock) -> None:
    """第一次 hold 不等 —— 桶是空的，没有「上一次」可言。

    这条守的是「别把合规下限写成启动惩罚」：如果第一次也睡 2 秒，
    七个画廊域的 CI 会白烧十几秒，而合规上没有任何收益。
    """
    with DomainLimiter().hold("acme.test"):
        pass
    assert clock.slept == []


def test_cross_domain_requests_do_not_wait_on_each_other(clock: FakeClock) -> None:
    """跨域并行、同域串行（§3.1）。两个不同注册域之间零等待。"""
    limiter = DomainLimiter()
    with limiter.hold("a.example"):
        pass
    with limiter.hold("b.example"):
        pass
    assert clock.slept == []
    assert registrable_domain("a.example") != registrable_domain("b.example")


def test_rate_floor_cannot_be_lowered_in_the_constructor() -> None:
    """``base_interval < 2.0`` 直接 ``raise ValueError``（§3.1 第一行）。

    不是 clamp、不是 warn。clamp 会让「我传了 0.5 所以工具在 0.5 跑」这句
    错话在调用方那边成立。
    """
    with pytest.raises(ValueError, match="合规下限"):
        DomainLimiter(0.5)
    with pytest.raises(ValueError, match="合规下限"):
        DomainLimiter(1.999)
    assert DomainLimiter(2.0).stats() == {}


def test_crawl_delay_can_only_make_us_slower(clock: FakeClock) -> None:
    """robots.txt 的 ``Crawl-delay`` 比我们严就采纳，比我们松就无视。"""
    limiter = DomainLimiter()
    limiter.set_crawl_delay("acme.test", 10.0)
    assert limiter.stats()["acme.test"]["interval"] == 10.0

    limiter.set_crawl_delay("acme.test", 0.1)  # 更松：不许把我们调快
    assert limiter.stats()["acme.test"]["interval"] == 10.0

    limiter.set_crawl_delay("acme.test", 999.0)  # 上限封顶
    assert limiter.stats()["acme.test"]["interval"] == MAX_INTERVAL_SECONDS


# --------------------------------------------------------------------------- #
# 2. 429 之后必须退让
# --------------------------------------------------------------------------- #


def test_throttle_doubles_and_honours_retry_after(clock: FakeClock) -> None:
    """§3.1 末行：间隔翻倍（上限 30s），``Retry-After`` 取两者较大（上限 120s）。

    实测出处：``www.pipedrive.com`` 对一个**确实存在**的文件返回 429。
    """
    limiter = DomainLimiter()
    wait = limiter.note_throttled("www.pipedrive.com", retry_after="60")
    assert wait == 60.0  # Retry-After 比翻倍后的 4s 大，取它
    assert limiter.stats()["pipedrive.com"]["interval"] == 4.0

    assert limiter.note_throttled("www.pipedrive.com") == 8.0  # 只增不减
    assert limiter.note_throttled("www.pipedrive.com", retry_after="1") == 16.0  # 不许被调小
    # 16 -> 32 被 MAX_INTERVAL_SECONDS 封在 30；HTTP-date/垃圾值走 ValueError 分支被吞
    assert limiter.note_throttled("www.pipedrive.com", retry_after="not-a-number") == (
        MAX_INTERVAL_SECONDS
    )
    assert limiter.stats()["pipedrive.com"]["throttle_events"] == 4


def test_no_same_host_request_inside_the_cooldown(clock: FakeClock) -> None:
    """A41：429 冷却期内不再发同 host 请求。

    「不再发」在这层的形态是「下一次 hold 必须先等满加宽后的间隔」——
    冷却由限速器强制，调用方无法绕过（``hold()`` 是唯一入口）。
    """
    limiter = DomainLimiter()
    with limiter.hold("www.pipedrive.com"):
        pass
    limiter.note_throttled("www.pipedrive.com")  # 2s -> 4s
    with limiter.hold("api.pipedrive.com"):  # 同注册域，吃同一个冷却
        pass
    assert clock.slept == [4.0]


def test_403_404_401_are_never_retried() -> None:
    """§3.2③ / §3.1 第四行：403/404/401 **不重试**。

    这条与「不绕 WAF」是同一件事：对着 403 反复敲就是在试探封锁。
    重试集合是冻结的 ``{502,503,504,507,522,524}``（外加 ``status==0``）。
    """
    assert frozenset({502, 503, 504, 507, 522, 524}) == RETRY_STATUSES
    for polite in (401, 403, 404, 410, 429, 451):
        assert polite not in RETRY_STATUSES


# --------------------------------------------------------------------------- #
# 3. UA 必须带真实联系邮箱
# --------------------------------------------------------------------------- #


def test_ua_carries_contact() -> None:
    """A40：UA 同时含版本号、项目 URL、``contact:``，且匹配规格给的正则。"""
    ua = build_user_agent(CONTACT)
    assert UA_PATTERN.match(ua), ua
    assert "geo-audit/" in ua
    assert "https://github.com/wangtoone/geo-audit" in ua
    assert f"contact: {CONTACT}" in ua


@pytest.mark.parametrize("bad", ["", "   ", "not-an-email", "nobody"])
def test_ua_refuses_a_contact_without_an_at_sign(bad: str) -> None:
    """空或不含 ``@`` 直接 ``raise ValueError``（§3.1 第二行）。

    ``build_user_agent`` 在 ``Fetcher.__init__`` 里被调用，所以这条同时意味着
    「造不出一个没有联系方式的 Fetcher」。
    """
    with pytest.raises(ValueError, match="联系邮箱"):
        build_user_agent(bad)


def test_fetcher_puts_the_ua_and_from_header_on_every_request(tmp_path: Path) -> None:
    """UA 与 ``From`` 头钉在 client 上，不是逐调用传的 —— 漏不掉。

    顺带验 §3.2④：``Accept-Encoding`` 与 ``Accept-Language`` 也钉死，
    否则对照探测与目标请求的两次响应不可比。
    """
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="ok")

    fetcher = Fetcher(
        FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
        HttpCache(tmp_path / "ua.sqlite3", ua_profile="test"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )
    try:
        fetcher.fetch("https://acme.test/llms.txt", expect=Expect.TEXT_FILE)
    finally:
        fetcher.close()

    assert seen, "一个请求都没发出去，这条测试没测到东西"
    for headers in seen:
        assert UA_PATTERN.match(headers["user-agent"]), headers["user-agent"]
        assert headers["from"] == CONTACT
        assert headers["accept-encoding"] == "gzip, deflate"
        assert headers["accept-language"] == "en"


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--replay-fixtures"],
        ["--from", "whatever.json"],
        ["--replay-fixtures", "--no-cache"],
    ],
)
def test_cli_without_contact_exits_4_in_every_mode(
    extra: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """卡点 B17a / A42：缺 ``--contact`` 一律退 4，**replay 与 --from 也不豁免**。

    规格原话：「做成可选等于没有」。豁免哪一条模式，就等于给了一个不带联系
    方式抓站的入口 —— 而 CI 自己就跑 replay，那条路正是最容易被豁免的。
    """
    monkeypatch.delenv(cli.CONTACT_ENV, raising=False)
    assert cli.main(["acme.test", *extra]) == 4


def test_cli_rejects_a_contact_that_is_not_an_email(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(cli.CONTACT_ENV, raising=False)
    assert cli.main(["acme.test", "--contact", "not-an-email"]) == 4


# --------------------------------------------------------------------------- #
# 4. --rate 只允许调慢
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("rps", ["0.6", "1", "2.0", "10", "0"])
def test_cli_rate_faster_than_the_floor_exits_4(
    rps: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """A42：``--rate`` > 0.5 直接退 4，stderr 里说清上限是 0.5。

    ``0`` 也退 4：它不是「不限速」而是「除零」，静默当成默认值会让
    「我传了 0 所以没限速」这句错话成立。
    """
    assert cli.main(["acme.test", "--contact", CONTACT, "--rate", rps]) == 4
    assert "0.5" in capsys.readouterr().err


@pytest.mark.parametrize(("rps", "expected"), [(0.5, 2.0), (0.25, 4.0), (0.1, 10.0)])
def test_slower_rate_becomes_a_wider_interval(rps: float, expected: float) -> None:
    """``--rate`` 只经 ``AuditOptions.interval`` 影响限速，且永不低于下限。"""
    options = AuditOptions(domain="acme.test", contact=CONTACT, rate=rps)
    assert options.interval == expected
    assert options.interval >= MIN_INTERVAL_SECONDS


def test_interval_floor_holds_even_if_rate_slips_past_the_cli() -> None:
    """双保险：就算有人绕过 CLI 直接构造 ``AuditOptions(rate=100)``，
    ``interval`` 也不会低于 2.0。

    合规下限有两道锁（这里 + ``DomainLimiter.__init__``），因为 CLI 校验
    是「用法层」的，库调用者绕得过去。
    """
    assert AuditOptions(domain="acme.test", contact=CONTACT, rate=100.0).interval == 2.0
    DomainLimiter(AuditOptions(domain="acme.test", contact=CONTACT, rate=100.0).interval)


# --------------------------------------------------------------------------- #
# 5. 不伪装浏览器 / 不绕 WAF
# --------------------------------------------------------------------------- #


def _src_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def _code_only(path: Path) -> str:
    """去掉注释与 docstring 之后的源码文本。

    **为什么不能直接 grep 原文**：``fetch/jsrender.py:7`` 的 docstring 里原文写着

        "no WAF bypass, no CAPTCHA solving, no residential proxies"

    那是在**声明我们不做**。规格 A41 给的 ``grep -riE "…|residential" src/``
    照原文跑会命中它 —— 于是这条闸门要么永远红、要么被人加 ``--exclude`` 松掉。
    真正要挡的是**调用与端点字面量**，那些一定出现在代码里而不是散文里。
    所以：注释与「语句开头的字符串」（docstring，以及当注释用的裸字符串）剔掉，
    其余全留 —— 包括普通字符串字面量，因为 ``"2captcha.com/in.php"`` 这种
    端点就藏在字符串里。
    """
    kept: list[str] = []
    at_statement_start = True
    with path.open("rb") as raw:
        tokens = list(tokenize.tokenize(raw.readline))
    for token in tokens:
        if token.type == tokenize.COMMENT:
            continue
        if token.type == tokenize.STRING and at_statement_start:
            continue  # docstring / 裸字符串
        if token.type in (tokenize.NEWLINE, tokenize.NL, tokenize.INDENT, tokenize.DEDENT):
            at_statement_start = True
            continue
        if token.type in (tokenize.ENCODING, tokenize.ENDMARKER):
            continue
        kept.append(token.string)
        at_statement_start = token.type == tokenize.OP and token.string == ";"
    return "\n".join(kept)


def test_no_bypass_machinery_in_code() -> None:
    """A41：源码里没有绕 WAF / 解 CAPTCHA / 住宅代理的调用。

    §3.1 定的行为是「遇挑战页判 ``BLOCKED`` 然后走开」。走开是产品决定：
    绕过去拿到的数据，甲方自己的 AI 爬虫也拿不到，报告就不成立了。
    """
    hits = [
        (str(path.relative_to(REPO)), marker)
        for path in _src_files()
        for marker in BYPASS_MARKERS
        if marker in _code_only(path).lower()
    ]
    assert hits == [], f"src/ 里出现了绕过型调用：{hits}"


def test_proxy_configuration_is_absent_from_the_http_client() -> None:
    """代理配置本身也不许有 —— 住宅代理池是通过它接进来的。

    只扫 ``fetch/`` 下的 HTTP 层（那是唯一发请求的地方），避免把别处
    不相干的 ``proxy`` 词误伤。
    """
    http_layer = sorted((SRC / "geo_audit" / "fetch").rglob("*.py"))
    hits = [
        str(path.relative_to(REPO))
        for path in http_layer
        for needle in ("proxies=", "proxy=", "proxy_mounts", "trust_env=True")
        if needle in _code_only(path)
    ]
    assert hits == [], f"HTTP 层出现了代理配置：{hits}"


def test_the_only_prose_mentions_are_declarations_that_we_do_not_do_it() -> None:
    """原文里确实提到这些词的地方，必须是「我们不做」这句话本身。

    这条是上一条的补充而不是重复：上一条挡代码，这条挡「注释里悄悄留下
    一段能开启绕过的说明/开关文档」。命中行必须带否定词。
    """
    offenders: list[str] = []
    for path in _src_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            low = line.lower()
            if not any(marker in low for marker in BYPASS_MARKERS):
                continue
            if not any(neg in low for neg in ("no ", "not ", "never", "cut", "不", "无")):
                offenders.append(f"{path.relative_to(REPO)}:{lineno}: {line.strip()}")
    assert offenders == [], f"提到绕过手段但没说「不做」的行：{offenders}"


def test_no_browser_ua_anywhere() -> None:
    """§3.1 第三行：全局唯一 UA 常量，源码里不出现浏览器 UA 形态。

    这条扫**原文**（含注释与字符串），因为一个 ``Mozilla/5.0`` 字面量出现在
    源码任何位置都没有正当理由 —— 它只有一个用途。
    """
    hits = [
        f"{path.relative_to(REPO)}: {marker}"
        for path in _src_files()
        for marker in BROWSER_UA_MARKERS
        if marker in path.read_text(encoding="utf-8")
    ]
    assert hits == [], f"src/ 里出现了浏览器 UA 形态：{hits}"


# --------------------------------------------------------------------------- #
# 6. 默认遵守 robots.txt
# --------------------------------------------------------------------------- #

_ROBOTS_BLOCK_ALL = "User-agent: *\nDisallow: /\nAllow: /robots.txt\n"
_ROBOTS_BLOCK_LLMS = "User-agent: *\nDisallow: /llms.txt\n"


class _RecordingSite:
    """记下每个请求 URL 的假站。``/robots.txt`` 给指定内容，其余一律 200 真文件。"""

    def __init__(self, robots: str) -> None:
        self.robots = robots
        self.requested: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requested.append(str(request.url))
        if request.url.path == "/robots.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=self.robots)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="# real file\n")

    @property
    def non_robots(self) -> list[str]:
        return [u for u in self.requested if not u.endswith("/robots.txt")]


def _fetcher(site: _RecordingSite, tmp_path: Path, *, respect_robots: bool = True) -> Fetcher:
    return Fetcher(
        FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=respect_robots),
        HttpCache(tmp_path / "robots.sqlite3", ua_profile="test"),
        DomainLimiter(2.0),
        transport=StopTransport(httpx.MockTransport(site.handler), threading.Event()),
    )


def test_robots_disallow_makes_no_request(tmp_path: Path, clock: FakeClock) -> None:
    """A41：被 ``Disallow`` 的路径**零请求**，且判 ``robots_disallowed``。

    这是「零请求」而不是「请求了但不看结果」—— 后者对被抓站点没有任何区别。
    """
    site = _RecordingSite(_ROBOTS_BLOCK_LLMS)
    fetcher = _fetcher(site, tmp_path)
    try:
        probe = fetcher.probe("https://acme.test/llms.txt", expect=Expect.TEXT_FILE)
    finally:
        fetcher.close()

    assert site.non_robots == [], f"对被禁路径发了请求：{site.non_robots}"
    assert probe.classification.reason == "robots_disallowed"
    assert probe.response is None


def test_a_robots_blocked_position_is_unevaluated_never_passed(
    tmp_path: Path, clock: FakeClock
) -> None:
    """被禁的位置标「无法评估 · robots 禁止」，**不标「通过」**（§7.1 / A41）。

    「我们没被允许看」是真话，「这里没问题」是假话 —— 后者会让甲方
    以为这个位置体检过了。
    """
    site = _RecordingSite(_ROBOTS_BLOCK_LLMS)
    fetcher = _fetcher(site, tmp_path)
    try:
        cls = fetcher.probe("https://acme.test/llms.txt", expect=Expect.TEXT_FILE).classification
    finally:
        fetcher.close()

    assert cls.verdict is not Verdict.OK
    assert cls.evaluated is False
    assert cls.reason in NOT_EVALUATED_REASONS
    assert UNKNOWN_REMEDY["robots_disallowed"], "被禁的位置必须给一句「怎么办」"
    assert "--ignore-robots" in UNKNOWN_REMEDY["robots_disallowed"]


def test_robots_txt_itself_is_always_fetchable(tmp_path: Path, clock: FakeClock) -> None:
    """唯一的例外：``/robots.txt`` 自身。不然规则文件本身就读不到了。"""
    site = _RecordingSite(_ROBOTS_BLOCK_ALL)
    fetcher = _fetcher(site, tmp_path)
    try:
        assert fetcher.robots_allows("https://acme.test/robots.txt") is True
        assert fetcher.robots_allows("https://acme.test/llms.txt") is False
    finally:
        fetcher.close()
    assert site.requested == ["https://acme.test/robots.txt"]


def test_ignore_robots_is_opt_in_only(tmp_path: Path, clock: FakeClock) -> None:
    """``respect_robots`` 默认 True；关掉它要显式传（CLI 是 ``--ignore-robots``）。"""
    assert FetcherConfig(contact=CONTACT).respect_robots is True

    site = _RecordingSite(_ROBOTS_BLOCK_ALL)
    fetcher = _fetcher(site, tmp_path, respect_robots=False)
    try:
        assert fetcher.robots_allows("https://acme.test/llms.txt") is True
    finally:
        fetcher.close()


def _resolver(*hosts: str) -> FixtureResolver:
    table: dict[str, dict[str, Any]] = {
        host: {"addresses": ["203.0.113.9"], "resolver": "system", "poisoned": False}
        for host in hosts
    }
    table[DNS_ABSENT_KEY] = {
        "addresses": [],
        "resolver": "none",
        "poisoned": False,
        "error": "NXDOMAIN",
    }
    return FixtureResolver(table, source="tests/test_politeness.py")


def test_a_fully_disallowed_domain_yields_zero_passes_end_to_end(
    tmp_path: Path, clock: FakeClock
) -> None:
    """全管线版：``Disallow: /`` 的站跑完，**一个「通过」都没有、一个请求都没发**。

    单元级断言只能证明 ``probe()`` 守规矩；这条证明整条管线（发现层在内）
    没有别的路绕过 ``robots_allows``。假站的非 robots 请求列表为空就是证据。
    """
    site = _RecordingSite(_ROBOTS_BLOCK_ALL)
    fetcher = _fetcher(site, tmp_path)
    try:
        report = audit_domain(
            AuditOptions(
                domain="acme.test",
                contact=CONTACT,
                only=("ai_path",),
                max_requests=0,
            ),
            fetcher=fetcher,
            store=FixtureStore(tmp_path / "empty-fixtures"),
            resolver=_resolver("acme.test", "www.acme.test"),
        )
    finally:
        fetcher.close()

    assert site.non_robots == [], f"robots 全禁的站还是发了请求：{site.non_robots}"
    assert report.counts.positions_pass == 0
    blocked = [p for p in report.positions if p.status is Status.UNKNOWN]
    assert blocked, "至少 apex/www 两格要落在「无法评估」里"
    assert all(p.unknown_reason == "robots_disallowed" for p in blocked)
    assert all(p.unknown_remedy for p in blocked)
