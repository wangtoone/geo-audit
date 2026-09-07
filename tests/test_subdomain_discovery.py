"""第 7 步：子域 / 子路径发现 —— tier 分层、请求预算、resolver 注入、WAF 第三状态。

**发现不靠爬链接**，这是 brevo 的教训：brevo.com 的裸域在 /、/pricing/、/blog/
上返回 Vercel 的纯文本 ``DEPLOYMENT_NOT_FOUND``，而 www 与 developers 都健康 ——
站内没有任何 href 指向裸域，爬链接的设计永远到不了那个坏面。所以发现是
**确定性枚举 + 站点自身声明**。

数据来源三处，都不是编的：

* ``corpus/feature-raw.json`` —— 72 域实测原始记录（六个「真文件不在朴素探测集里」
  的域的位置与状态全部引自它，每条断言旁边附了原文引文）；
* ``tests/data/soft404_expectations.json`` / ``llmsfull_expectations.json`` /
  ``index_link_expectations.json`` —— 第 5 步落地的标注（A/A'/B/C 四张表）；
* ``fixtures/index.json`` —— 实录快照，第 4b 步才落地，依赖它的测试 ``skipif`` 掉
  （跳过原因写在 reason 里，不是假绿）。

离线自足：所有跑 ``discover()`` 的测试都用 ``httpx.MockTransport`` 造的假站 +
``FixtureResolver`` 注入的 DNS，``GEO_AUDIT_FORBID_NETWORK=1``
``GEO_AUDIT_FORBID_DNS=1`` 下全部真跑，不 skip。
"""

from __future__ import annotations

import inspect
import json
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from geo_audit.checks.ai_path import (
    _DOC_HOST_RE,
    NAIVE_PATHS,
    in_naive_probe_set,
    naive_contrast,
)
from geo_audit.fetch import discovery
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter, registrable_domain
from geo_audit.fixtures import DNS_ABSENT_KEY, FixtureError, FixtureResolver, FixtureStore
from geo_audit.models import Expect, HostRole, Status, Verdict, verdict_to_status

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
DATA = REPO / "tests" / "data"
CORPUS = REPO / "corpus" / "feature-raw.json"

CONTACT = "audit@example.org"
#: 确定性对照探针路径。生产默认是 ``secrets.token_hex(12)``，回放/测试必须注入，
#: 否则每次跑出来的对照 URL 都不一样。
CONTROL_PATH = "/zzz-geo-audit-control-1234"

#: 七个画廊域（§7.4:3530 逐字）：七种形态各一份，含最难看的两份。
GALLERY_DOMAINS: tuple[str, ...] = (
    "mistral.ai",
    "deepgram.com",
    "minimax.io",
    "saleor.io",
    "tdengine.com",
    "modal.com",
    "gusto.com",
)
#: 第 7 步验收门（§9:4434）：``SiteMap.requests_spent`` 在七个画廊域上都 ≤ 90。
#: 超了就按 §3.7:1836 把 ``DEFAULT_REQUEST_BUDGET`` 调到 200。
GALLERY_REQUEST_CEILING = 90

real_index_needed = pytest.mark.skipif(
    not (FIXTURES / "index.json").exists(),
    reason="第 4b 步的实录快照还没落地（fixtures/index.json 不存在）",
)


# --------------------------------------------------------------------------- #
# 假站 + 注入式 Fetcher（离线自足，一个真请求都不发）
# --------------------------------------------------------------------------- #

#: url -> (status, content-type, body)
Pages = dict[str, tuple[int, str, str]]


class FakeSite:
    """按 URL 表回放的假站。表里没有的 URL 一律 404 + text/html。

    404 的默认值是刻意的：它同时充当「对照探针」的答案，于是
    ``host_profile.status_discriminates`` 为真 —— 一个 200 text/plain 的目标
    就能干净地判 OK，而 200 text/html 的目标会被 L2(a) 抓成软 404。
    """

    def __init__(self, pages: Pages) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requested.append(url)
        row = self.pages.get(url)
        if row is None:
            return httpx.Response(
                404, headers={"content-type": "text/html"}, text="<title>404</title>not found"
            )
        status, ctype, body = row
        return httpx.Response(status, headers={"content-type": ctype}, text=body)


def _resolver(*live_hosts: str) -> FixtureResolver:
    """只有 ``live_hosts`` 解析得出来，其余走 ``_default_absent``（NXDOMAIN）。

    「不存在的子域花 0 个 HTTP 请求」这条逻辑就是靠它在 replay 下也被测到。
    """
    table: dict[str, dict[str, Any]] = {
        host: {"addresses": ["203.0.113.10"], "resolver": "system", "poisoned": False}
        for host in live_hosts
    }
    table[DNS_ABSENT_KEY] = {
        "addresses": [],
        "resolver": "none",
        "poisoned": False,
        "error": "NXDOMAIN",
    }
    return FixtureResolver(table, source="tests/test_subdomain_discovery.py")


def _control_for(url: str) -> str:
    return f"https://{httpx.URL(url).host}{CONTROL_PATH}"


def _fetcher(site: FakeSite, tmp_path: Path, *, name: str = "cache") -> Fetcher:
    return Fetcher(
        FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
        cache=HttpCache(tmp_path / f"{name}.sqlite3", ua_profile="test"),
        limiter=DomainLimiter(2.0),
        transport=httpx.MockTransport(site.handler),
        probe_url_provider=_control_for,
    )


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """合规下限是 1 请求 / 2 秒 / 域，一次 discover() 会睡几十秒。

    这里只掐掉限流器的 sleep（限流逻辑本身仍然跑，``test_infra.py`` 里有它的
    专门断言），不动任何生产代码。
    """
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _seconds: None)


@pytest.fixture
def fetcher_factory(tmp_path: Path) -> Iterator[Callable[[FakeSite], Fetcher]]:
    made: list[Fetcher] = []

    def make(site: FakeSite) -> Fetcher:
        f = _fetcher(site, tmp_path, name=f"cache{len(made)}")
        made.append(f)
        return f

    yield make
    for f in made:
        f.close()


# --------------------------------------------------------------------------- #
# 三个实测场景（正文形态按 corpus/feature-raw.json 的记录合成）
# --------------------------------------------------------------------------- #

#: SPA 兜底壳。corpus 原文：「https://www.minimax.io/llms.txt 返回 200、
#: content-type text/html、384,052 字节，与首页 SPA 外壳完全同尺寸；实测
#: https://www.minimax.io/this-does-not-exist-xyz123 也返回 200 + 384,052 字节」
_SPA_SHELL = "<!doctype html><html><head><title>MiniMax</title></head><body>SPA</body></html>"
#: 真 llms.txt 的形态（text/plain + Markdown 索引）。
_REAL_INDEX = "# MiniMax\n\n- [Quickstart](https://platform.minimax.io/docs/quickstart.md)\n"


def _minimax_site() -> tuple[FakeSite, FixtureResolver]:
    """minimax 形态：主域软 404 + 真文件在 platform 子域的 ``/docs`` 下。

    corpus 原文：「https://platform.minimax.io/llms.txt 真 404，但
    https://platform.minimax.io/docs/llms.txt 是真文件（200 text/plain 24KB）」。
    额外加了一个 ``docs.minimax.io/llms.txt``（根路径就有真文件）用来测短路：
    它的 ``/docs/llms.txt`` 一次都不该被探。
    """
    pages: Pages = {
        "https://www.minimax.io/": (200, "text/html", _SPA_SHELL),
        "https://www.minimax.io/llms.txt": (200, "text/html", _SPA_SHELL),
        "https://www.minimax.io/llms-full.txt": (200, "text/html", _SPA_SHELL),
        "https://www.minimax.io/docs/llms.txt": (200, "text/html", _SPA_SHELL),
        "https://www.minimax.io/docs/llms-full.txt": (200, "text/html", _SPA_SHELL),
        f"https://www.minimax.io{CONTROL_PATH}": (200, "text/html", _SPA_SHELL),
        "https://platform.minimax.io/": (200, "text/html", "<title>Platform</title>"),
        "https://platform.minimax.io/docs/llms.txt": (200, "text/plain", _REAL_INDEX),
        "https://platform.minimax.io/docs/llms-full.txt": (200, "text/plain", _REAL_INDEX * 3),
        "https://docs.minimax.io/": (200, "text/html", "<title>Docs</title>"),
        "https://docs.minimax.io/llms.txt": (200, "text/plain", _REAL_INDEX),
    }
    return FakeSite(pages), _resolver("www.minimax.io", "platform.minimax.io", "docs.minimax.io")


#: corpus 原文（moonshot.ai）：「文档页顶部也明写「Fetch the complete documentation
#: index at: https://platform.kimi.ai/docs/llms.txt」」。**跨注册域**，任何前缀
#: 枚举都到不了 —— 只能靠站点自身声明。
_KIMI_BANNER_URL = "https://platform.kimi.ai/docs/llms.txt"


def _moonshot_site() -> tuple[FakeSite, FixtureResolver]:
    banner = (
        "<!doctype html><html><head><title>Moonshot</title></head><body>"
        f"<p>Fetch the complete documentation index at: {_KIMI_BANNER_URL}</p>"
        f"<a href='{_KIMI_BANNER_URL}'>docs index</a></body></html>"
    )
    pages: Pages = {
        "https://www.moonshot.ai/": (200, "text/html", banner),
        # 主域 llms.txt 是首页壳的软 404（corpus：200 + text/html + 82,460 字节）
        "https://www.moonshot.ai/llms.txt": (200, "text/html", banner),
        "https://www.moonshot.ai/llms-full.txt": (200, "text/html", banner),
        "https://www.moonshot.ai/docs/llms.txt": (200, "text/html", banner),
        "https://www.moonshot.ai/docs/llms-full.txt": (200, "text/html", banner),
        f"https://www.moonshot.ai{CONTROL_PATH}": (200, "text/html", banner),
        "https://platform.kimi.ai/": (200, "text/html", "<title>Kimi</title>"),
        _KIMI_BANNER_URL: (200, "text/plain", _REAL_INDEX),
        "https://platform.kimi.ai/docs/llms-full.txt": (200, "text/plain", _REAL_INDEX * 3),
    }
    return FakeSite(pages), _resolver("www.moonshot.ai", "platform.kimi.ai")


#: corpus 原文（gusto.com）：「https://gusto.com/llms.txt 用 curl 拿到的是 403
#: （Cloudflare「Just a moment...」挑战页）；在浏览器里通过了挑战后同源 fetch
#: 得到 200 text/plain 8,217B，是真文件」。
_CF_CHALLENGE = (
    "<!doctype html><html><head><title>Just a moment...</title></head>"
    "<body><div id='cf-wrapper'>__cf_chl_opt</div></body></html>"
)


def _waf_site() -> tuple[FakeSite, FixtureResolver]:
    """gusto（Cloudflare 403 挑战）+ pipedrive（429 限流）两种被拦形态。"""
    pages: Pages = {
        "https://gusto.com/": (403, "text/html", _CF_CHALLENGE),
        "https://gusto.com/llms.txt": (403, "text/html", _CF_CHALLENGE),
        "https://gusto.com/llms-full.txt": (403, "text/html", _CF_CHALLENGE),
        "https://gusto.com/docs/llms.txt": (403, "text/html", _CF_CHALLENGE),
        "https://gusto.com/docs/llms-full.txt": (403, "text/html", _CF_CHALLENGE),
        "https://gusto.com/.well-known/llms.txt": (403, "text/html", _CF_CHALLENGE),
        "https://docs.gusto.com/": (200, "text/html", "<title>Gusto Docs</title>"),
        "https://docs.gusto.com/llms.txt": (200, "text/plain", _REAL_INDEX),
    }
    return FakeSite(pages), _resolver("gusto.com", "docs.gusto.com")


def _pipedrive_site() -> tuple[FakeSite, FixtureResolver]:
    pages: Pages = {
        "https://www.pipedrive.com/": (200, "text/html", "<title>Pipedrive</title>"),
        # corpus：www.pipedrive.com/llms.txt 是真文件，但 HTTP 客户端吃 429
        "https://www.pipedrive.com/llms.txt": (429, "text/plain", "rate limited"),
        "https://www.pipedrive.com/llms-full.txt": (429, "text/plain", "rate limited"),
    }
    return FakeSite(pages), _resolver("www.pipedrive.com")


def _probe_urls(sitemap: Any) -> list[str]:
    return [p.url for p in sitemap.ai_path_probes]


def _verdicts(sitemap: Any) -> dict[str, Verdict]:
    return {p.url: p.verdict for p in sitemap.ai_path_probes}


# --------------------------------------------------------------------------- #
# AI 路径体检的输入契约（不依赖 discover()）
# --------------------------------------------------------------------------- #


def test_ai_path_candidates_are_the_five_recorded_positions() -> None:
    """§3.7:1786：只探根路径会把 6/72 个域读成「未采纳」。五条候选路径逐字冻结。"""
    assert discovery.AI_PATH_CANDIDATES == (
        "/llms.txt",
        "/docs/llms.txt",
        "/llms-full.txt",
        "/docs/llms-full.txt",
        "/.well-known/llms.txt",
    )


def test_tier_paths_partition_the_five_candidates() -> None:
    """四层的路径合起来恰好是 ``AI_PATH_CANDIDATES``，一条不多一条不少。

    分层是为了短路与省预算，不是为了少探位置。任何一条路径从分层表里掉出去，
    都等于悄悄缩小探测集 —— 那正是「真文件被读成没有」的成因。
    """
    union: set[str] = set()
    for tier in discovery.TIER_ORDER:
        union |= set(discovery.AI_PATHS_BY_TIER[tier])
    assert union == set(discovery.AI_PATH_CANDIDATES)
    assert discovery.AI_PATHS_BY_TIER[discovery.TIER0] == discovery.ROOT_AI_PATHS
    assert discovery.AI_PATHS_BY_TIER[discovery.TIER1] == discovery.ROOT_AI_PATHS
    assert discovery.AI_PATHS_BY_TIER[discovery.TIER3] == ("/.well-known/llms.txt",)
    # 短路配对必须覆盖 tier2 的每一条，否则那条路径永远探不到（或永远探）
    assert set(discovery.TIER2_SHORTCUT) == set(discovery.DOCS_AI_PATHS)
    assert set(discovery.TIER2_SHORTCUT.values()) == set(discovery.ROOT_AI_PATHS)


def test_ai_paths_are_probed_as_text_files() -> None:
    """卡点 S1：AI 路径探测**一律** ``Expect.TEXT_FILE``。

    改成 ``HTML_PAGE`` 会废掉抓 15/16 的主力规则 L2(a) —— 需要
    ``identical_to_control`` 那条证据时从 ``Classification.secondary_reasons`` 取
    （见 ``tests/test_soft404.py``）。这里用源码断言守着接线点：第 7 步把探测循环
    从 ``discover()`` 里提成了 ``probe_ai_paths()``，接线点也跟着移到那里。
    """
    src = inspect.getsource(discovery.probe_ai_paths)
    assert "expect=Expect.TEXT_FILE" in src
    assert "Expect.HTML_PAGE" not in src
    assert "probe_ai_paths(" in inspect.getsource(discovery.discover)
    assert Expect.TEXT_FILE.value == "text_file"


def test_docs_subpath_and_subdomain_are_both_in_the_probe_set() -> None:
    """假阴的两个方向都要覆盖：``platform.minimax.io/docs/llms.txt``（子域 + 子路径）
    与 ``platform.kimi.ai/docs/llms.txt``（跨注册域）。

    子路径靠 AI_PATH_CANDIDATES，子域靠 DOC_HOST_PREFIXES，跨注册域靠
    ``mine_declared_hosts``。三条缺一个就会把真文件读成「未采纳」。
    """
    assert "/docs/llms.txt" in discovery.AI_PATH_CANDIDATES
    prefixes = {p for p, _ in discovery.DOC_HOST_PREFIXES}
    assert "platform" in prefixes
    assert callable(discovery.mine_declared_hosts)
    # 朴素实现只探 apex/www 的两条根路径，所以这两个位置它一个都看不到。
    assert in_naive_probe_set("https://platform.minimax.io/docs/llms.txt", "minimax.io") is False
    assert in_naive_probe_set("https://platform.kimi.ai/docs/llms.txt", "moonshot.ai") is False


def test_doc_host_prefix_lists_agree_or_differ() -> None:
    """⚠️ 两份前缀清单并存（见交付说明 spec_gaps）：

    ``discovery.DOC_HOST_PREFIXES`` 有 16 项，而 §4.4:2280 的 ``_DOC_HOST_RE``
    覆盖不到 ``supportcenter``（简报说还缺 ``apidoc``，实测不缺 —— 正则里的
    ``apidocs?`` 把它盖住了）。并存会让「这是不是文档 host」的判定分叉。

    断言写成「差集要么为空、要么恰好是实测的那一项」——统一之后这条依然绿，
    但任何**新的**分叉会让它红。
    """
    prefixes = {p for p, _ in discovery.DOC_HOST_PREFIXES}
    assert len(prefixes) == 16
    missing = {p for p in prefixes if not _DOC_HOST_RE.match(f"{p}.example.com")}
    assert missing in ({"supportcenter"}, set()), f"新的分叉：{missing}"


# --------------------------------------------------------------------------- #
# discover() 的新签名
# --------------------------------------------------------------------------- #


def test_discover_accepts_the_four_new_parameters() -> None:
    """§3.7：``discover(fetcher, domain, *, tiers, wellknown, budget, resolver)``。

    四个都必须是 keyword-only 且**有默认值**，否则旧调用（``test_infra.py``
    那 146 条的隔壁）会当场断掉。
    """
    sig = inspect.signature(discovery.discover)
    for name in ("tiers", "wellknown", "budget", "resolver"):
        param = sig.parameters[name]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, name
        assert param.default is not inspect.Parameter.empty, name
    assert sig.parameters["tiers"].default == ("tier0", "tier1", "tier2", "tier3")
    assert sig.parameters["wellknown"].default is True
    assert sig.parameters["budget"].default == 120
    assert sig.parameters["resolver"].default is None


def test_sitemap_carries_tier_and_budget_bookkeeping(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """§3.9 适配 #3 的四个字段。已搬进 ``models.SiteMap``（原先由 discovery 的
    ``TieredSiteMap`` 子类临时承载，因为写它的 agent 被禁止改 models.py）。"""
    site, resolver = _minimax_site()
    sm = discovery.discover(fetcher_factory(site), "minimax.io", resolver=resolver)
    assert sm.tiers_run == discovery.TIER_ORDER
    assert isinstance(sm.requests_spent, int) and sm.requests_spent > 0
    assert sm.budget_exhausted is False
    assert sm.skipped_by_budget == ()


# --------------------------------------------------------------------------- #
# tier 短路
# --------------------------------------------------------------------------- #


def test_tiered_probing_stops_early_within_budget(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """§3.7 的两条短路，各自有实测出处，一起在 minimax 形态上验：

    1. tier2 只补根路径没拿到真文件的那条 —— ``docs.minimax.io/llms.txt`` 已判 OK，
       所以 ``docs.minimax.io/docs/llms.txt`` **一次都不许探**（但 ``llms-full``
       那条根路径是 404，它的 ``/docs/llms-full.txt`` 该探）；
    2. tier3 只在该 host 前三层全空时才探 —— 有真文件的 host 一律不碰
       ``/.well-known/llms.txt``（72 域实测 0 命中，排最后就是为了不烧预算）。
    """
    site, resolver = _minimax_site()
    sm = discovery.discover(fetcher_factory(site), "minimax.io", resolver=resolver)
    urls = _probe_urls(sm)
    verdicts = _verdicts(sm)

    # 真文件被找到了：子域 + /docs 子路径两个方向都通
    assert verdicts["https://platform.minimax.io/docs/llms.txt"] is Verdict.OK
    assert verdicts["https://docs.minimax.io/llms.txt"] is Verdict.OK

    # 短路 1：根路径已 OK 的那条不再探 /docs 版本
    assert "https://docs.minimax.io/docs/llms.txt" not in urls
    assert "https://docs.minimax.io/docs/llms-full.txt" in urls
    # 根路径 404 的 host 该探 /docs（这正是 minimax 真文件的位置）
    assert "https://platform.minimax.io/docs/llms.txt" in urls

    # 短路 2：A15 —— 有真文件的 host 上不出现 tier3
    wellknown = {u for u in urls if u.endswith("/.well-known/llms.txt")}
    assert wellknown == {"https://www.minimax.io/.well-known/llms.txt"}, (
        "只有前三层全空的 host（www 那个纯 SPA 壳）才该探 .well-known"
    )

    # 不存在的子域花 0 个 HTTP 请求：DNS 挡在 HTTP 前面。
    # apex/www 例外 —— ``probe_apex_and_www`` 按裁决 #12 无条件跑（brevo 的裸域
    # 就是靠它才看得见），所以它俩即使 DNS 不通也会各花一个请求。
    absent = [
        h
        for h in sm.hosts
        if h.reason == "dns_unresolved" and h.role not in (HostRole.APEX, HostRole.WWW)
    ]
    assert len(absent) >= 10
    for host in absent:
        assert not any(u.startswith(f"https://{host.host}/") for u in site.requested)


def test_wellknown_position_is_probed_only_when_enabled(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """``--no-wellknown -> wellknown=False``，等价去掉 tier3。"""
    site, resolver = _minimax_site()
    sm = discovery.discover(fetcher_factory(site), "minimax.io", wellknown=False, resolver=resolver)
    assert "tier3" not in sm.tiers_run
    assert not [u for u in _probe_urls(sm) if "/.well-known/" in u]
    assert not [u for u in site.requested if "/.well-known/" in u]


def test_tiers_parameter_selects_a_subset(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """只跑 tier0 时，16 个前缀一个都不该被 DNS 之外的东西碰到。"""
    site, resolver = _minimax_site()
    sm = discovery.discover(
        fetcher_factory(site), "minimax.io", tiers=("tier0",), resolver=resolver
    )
    assert sm.tiers_run == ("tier0",)
    assert {httpx.URL(u).host for u in _probe_urls(sm)} == {"www.minimax.io"}


def test_declared_host_on_another_registrable_domain_is_discovered(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """moonshot.ai 的文档站在 platform.kimi.ai —— **完全不同的注册域**。

    任何前缀枚举都到不了，只有「站点自身声明」这条路。原型只从判 OK 的 llms.txt
    正文里挖；moonshot 的主域 llms.txt 本身是软 404，所以第 7 步把挖掘源放宽到
    「所有拿到正文的响应」（见交付说明 key_decisions）——
    ``mine_declared_hosts`` 自带的「出现 ≥2 次 + host 形态 + 社交站硬排除 + 最多 3 个」
    四道闸没有放松。
    """
    site, resolver = _moonshot_site()
    sm = discovery.discover(fetcher_factory(site), "moonshot.ai", resolver=resolver)
    declared = [h for h in sm.hosts if h.role is HostRole.DECLARED]
    assert [h.host for h in declared] == ["platform.kimi.ai"]
    assert _verdicts(sm)[_KIMI_BANNER_URL] is Verdict.OK
    assert registrable_domain("platform.kimi.ai") != registrable_domain("www.moonshot.ai")


# --------------------------------------------------------------------------- #
# WAF 第三状态：BLOCKED 不判死、不丢弃
# --------------------------------------------------------------------------- #


def test_waf_blocked_host_stays_in_the_probe_set(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """gusto.com 根路径吃 Cloudflare 403 挑战页，但 llms.txt 是**真文件**。

    把它当死站丢掉就是「软 404 让采纳率虚高」的反向孪生错误 —— 虚低。所以
    BLOCKED 的 host 留在探测集里，AI 路径照探，判 UNKNOWN 而不是「没有」。
    """
    site, resolver = _waf_site()
    sm = discovery.discover(fetcher_factory(site), "gusto.com", resolver=resolver)

    apex = next(h for h in sm.hosts if h.host == "gusto.com")
    assert apex.verdict is Verdict.BLOCKED
    assert apex.reason == "waf_challenge_body"
    assert verdict_to_status(apex.verdict) is Status.UNKNOWN

    blocked = next(p for p in sm.ai_path_probes if p.url == "https://gusto.com/llms.txt")
    assert blocked.verdict is Verdict.BLOCKED
    assert blocked.classification.evaluated is False
    assert verdict_to_status(blocked.verdict) is Status.UNKNOWN
    # 同一域的真文件仍然被找到（docs 子域）
    assert _verdicts(sm)["https://docs.gusto.com/llms.txt"] is Verdict.OK


def test_rate_limited_host_is_blocked_not_dead(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """www.pipedrive.com/llms.txt 是真文件，HTTP 客户端吃 429。"""
    site, resolver = _pipedrive_site()
    sm = discovery.discover(fetcher_factory(site), "pipedrive.com", resolver=resolver)
    probe = next(p for p in sm.ai_path_probes if p.url == "https://www.pipedrive.com/llms.txt")
    assert probe.verdict is Verdict.BLOCKED
    assert probe.classification.reason == "rate_limited"
    assert probe.classification.evaluated is False
    assert probe.verdict is not Verdict.REAL404


# --------------------------------------------------------------------------- #
# 预算
# --------------------------------------------------------------------------- #


def test_budget_stops_at_a_tier_boundary_and_records_what_it_skipped(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """§3.7 的预算记账：每层开始前查一次，剩余 URL 全记入 ``skipped_by_budget``。

    被跳过的 URL 在 pipeline 里生成 ``Status.UNKNOWN(not_fetched)``，
    **绝不当成「没有这个文件」** —— 那是本工具存在理由的反面。
    """
    site, resolver = _minimax_site()
    sm = discovery.discover(fetcher_factory(site), "minimax.io", budget=6, resolver=resolver)

    assert sm.budget_exhausted is True
    assert sm.tiers_run == ("tier0",)
    assert sm.skipped_by_budget
    # tier1 的两个 live 子域（DNS 通得过的那两个）连根路径都没探到
    assert "https://platform.minimax.io/llms.txt" in sm.skipped_by_budget
    assert "https://docs.minimax.io/" in sm.skipped_by_budget
    # DNS 都不通的子域不许进 skip 清单：那会在报告里凭空造出「没看」的格子
    assert not [u for u in sm.skipped_by_budget if "api-docs.minimax.io" in u]
    # 定价页也是：「没探」与「找不到」是两种状态，后者不许被渲染成前者
    assert "https://www.minimax.io/pricing" in sm.skipped_by_budget
    assert sm.pricing_url is None
    # 跳过的 URL 一条都不许既在 skip 清单里又真被探过
    probed = set(_probe_urls(sm))
    assert not (probed & set(sm.skipped_by_budget))


def test_budget_zero_means_unlimited(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    site, resolver = _minimax_site()
    sm = discovery.discover(fetcher_factory(site), "minimax.io", budget=0, resolver=resolver)
    assert sm.budget_exhausted is False
    assert sm.skipped_by_budget == ()
    assert sm.tiers_run == discovery.TIER_ORDER


def test_default_budget_is_the_calibrated_120() -> None:
    """§3.7:1830 逐字：默认 120，实测最大分母 brevo 25 个请求，4.8 倍余量。"""
    assert discovery.DEFAULT_REQUEST_BUDGET == 120


def test_dns_robots_and_sitemap_do_not_count_against_the_budget(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    """§3.7：robots.txt / sitemap.xml / DNS 查询不是内容探测，不进预算。"""
    site, resolver = _minimax_site()
    sm = discovery.discover(fetcher_factory(site), "minimax.io", resolver=resolver)
    robots_and_sitemaps = [u for u in site.requested if u.endswith("robots.txt") or "sitemap" in u]
    assert robots_and_sitemaps, "这一跑本来就该去拿 robots/sitemap"
    assert sm.requests_spent < len(site.requested)


@real_index_needed
def test_requests_spent_stays_under_the_ceiling_on_the_gallery(tmp_path: Path) -> None:
    """第 7 步验收门（§9:4434）：七个画廊域的 ``requests_spent`` 都 ≤ 90。

    超了就按 §3.7:1836 把默认预算调到 200 —— 这条门禁的作用是让「默认 120 够不够」
    有一个实录出来的答案，而不是一个估的上界。
    """
    store = FixtureStore.default()
    over: dict[str, int] = {}
    for domain in GALLERY_DOMAINS:
        f = Fetcher(
            FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
            cache=HttpCache(tmp_path / f"{domain}.sqlite3", ua_profile="test"),
            limiter=DomainLimiter(2.0),
            transport=store.transport(),
            probe_url_provider=store.probe_url,
        )
        try:
            sm = discovery.discover(f, domain, resolver=store.resolver())
        except FixtureError as exc:  # 快照没录全 -> 优雅 skip，不假绿也不编数
            pytest.skip(f"{domain} 的实录快照不全：{exc}")
        finally:
            f.close()
        if sm.requests_spent > GALLERY_REQUEST_CEILING:
            over[domain] = sm.requests_spent
    assert not over, f"超过 {GALLERY_REQUEST_CEILING} 的域：{over}（按 §3.7 提默认预算到 200）"


# --------------------------------------------------------------------------- #
# resolver 注入：离线下不做任何真 DNS 查询
# --------------------------------------------------------------------------- #


def test_injected_resolver_is_used_instead_of_system_dns(
    fetcher_factory: Callable[[FakeSite], Fetcher],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§3.6：``resolver`` 一路传到底，``GEO_AUDIT_FORBID_DNS=1`` 下一次真查询都没有。

    DNS **不走 httpx**，所以 ``GEO_AUDIT_FORBID_NETWORK`` 那把闸拦不住它 ——
    离线 CI 会真去联网或超时（18 个候选 host × 3 个 resolver × 4s），而且
    ``DiscoveredHost.resolved_ips`` 进 JSON，L 组「两次跑逐字节相同」会随 DNS 抖动挂。
    """
    monkeypatch.setenv("GEO_AUDIT_FORBID_DNS", "1")

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("测试试图做真 DNS 查询")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    monkeypatch.setattr("geo_audit.fetch.resolve._public_resolve", _boom)

    site, resolver = _minimax_site()
    asked: list[str] = []

    def counting(host: str) -> Any:
        asked.append(host)
        return resolver(host)

    sm = discovery.discover(fetcher_factory(site), "minimax.io", resolver=counting)
    assert sm.tiers_run == discovery.TIER_ORDER
    # apex + www + 16 个前缀都过了注入的 resolver
    assert "minimax.io" in asked
    assert "www.minimax.io" in asked
    assert len(asked) >= 2 + len(discovery.DOC_HOST_PREFIXES)


def test_forbid_dns_without_a_resolver_is_a_hard_error(
    fetcher_factory: Callable[[FakeSite], Fetcher],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """没注入就抛 AssertionError —— 宁可红，也不许静默回落真网络。"""
    monkeypatch.setenv("GEO_AUDIT_FORBID_DNS", "1")
    site, _resolver_unused = _minimax_site()
    with pytest.raises(AssertionError, match="真 DNS 查询"):
        discovery.discover(fetcher_factory(site), "minimax.io")


# --------------------------------------------------------------------------- #
# A15：朴素读数 vs 真实读数
# --------------------------------------------------------------------------- #

#: 六个「真文件不在朴素探测集里」的域（§3.7:1841 逐字点名）。位置与状态全部引自
#: ``corpus/feature-raw.json`` 的 ``c3_ai_path`` 记录，note 里附原文。
#:
#: ⚠️ A15 写的是「六个域 ``naive.adopted != real.adopted``」。逐字照做会有三个域
#: 挂：minimax / moonshot / canvasmedical 的**域级**采纳结论两边都是「已采纳」
#: （真文件确实存在，只是不在朴素探的那个位置）。真正读错的是**位置级**结论，
#: 也就是 §4.5 的 ``NaiveContrast.diverges``。所以这里按 diverges 的两个方向拆表
#: （见交付说明 deviations_from_spec 第 1 条）：
#:
#:   假阳（false_positive）：朴素在它探的位置拿到 200，那个位置其实是壳；
#:   假阴（false_negative）：真文件在朴素探测集之外，朴素永远看不到它。
#:
#: 六个域每个至少命中一个方向，minimax / moonshot / canvasmedical 两个方向都命中。

#: (域, 朴素探的位置, 朴素拿到的状态码, 原文引文)
NAIVE_FALSE_POSITIVES: tuple[tuple[str, str, int, str], ...] = (
    (
        "minimax.io",
        "https://www.minimax.io/llms.txt",
        200,
        "返回 200、content-type text/html、384,052 字节，与首页 SPA 外壳完全同尺寸；"
        "实测 /this-does-not-exist-xyz123 也返回 200 + 384,052 字节",
    ),
    (
        "moonshot.ai",
        "https://www.moonshot.ai/llms.txt",
        200,
        "返回 200、content-type text/html、82,460 字节，与首页同尺寸；"
        "实测 /nonexistent-xyz-123 同样 200 + 82,460 字节",
    ),
    (
        "canvasmedical.com",
        "https://www.canvasmedical.com/llms.txt",
        200,
        "返回 200 + text/html（317KB，<title>Canvas: AI-Powered Healthcare Platform"
        " for Clinics</title>），是主站首页外壳的软 404",
    ),
)

#: (域, 真文件的位置, 原文引文)
NAIVE_FALSE_NEGATIVES: tuple[tuple[str, str, str], ...] = (
    (
        "minimax.io",
        "https://platform.minimax.io/docs/llms.txt",
        "platform.minimax.io/llms.txt 真 404，但 /docs/llms.txt 是真文件（200 text/plain 24KB）",
    ),
    (
        "moonshot.ai",
        "https://platform.kimi.ai/docs/llms.txt",
        "platform.kimi.ai/llms.txt 真 404，但 /docs/llms.txt 是真文件（15.6KB）—— "
        "跨注册域，任何前缀枚举都到不了",
    ),
    (
        "siliconflow.com",
        "https://docs.siliconflow.com/llms.txt",
        "www.siliconflow.com/llms.txt 返回 404（10 字节「Not found」，真 404）；"
        "docs.siliconflow.com/llms.txt 200 text/plain 8.2KB 真文件",
    ),
    (
        "onfleet.com",
        "https://docs.onfleet.com/llms.txt",
        "docs 子域 ok（7.8KB text/plain），主域 onfleet.com 硬 404",
    ),
    (
        "canvasmedical.com",
        "https://docs.canvasmedical.com/llms.txt",
        "docs 子域 ok（text/plain 31KB），主域 soft404 —— 真文件只在 docs 上",
    ),
    (
        "ecwid.com",
        "https://docs.ecwid.com/llms.txt",
        "docs.ecwid.com/llms.txt 200 text/markdown 10536B 真文件；"
        "主域 www.ecwid.com/llms.txt 为真 404",
    ),
)

#: A15 点名的六个域。
SIX_DOMAINS: frozenset[str] = frozenset(
    {
        "minimax.io",
        "moonshot.ai",
        "siliconflow.com",
        "onfleet.com",
        "canvasmedical.com",
        "ecwid.com",
    }
)


@pytest.mark.parametrize(("domain", "naive_url", "naive_status", "note"), NAIVE_FALSE_POSITIVES)
def test_naive_reads_a_shell_as_adopted(
    domain: str, naive_url: str, naive_status: int, note: str
) -> None:
    """假阳方向：朴素在它探的位置拿到 200，那个位置其实是首页 / SPA 壳。"""
    contrast = naive_contrast(
        probe_url=naive_url,
        apex=domain,
        http_status=naive_status,
        real_status=Status.FAIL,  # 软 404 = 这个位置的文件不存在
        actual_conclusion="未采纳（该位置是软 404）",
        why=note,
    )
    assert contrast.in_naive_probe_set is True
    assert contrast.naive_conclusion.startswith("已采纳")
    assert contrast.diverges is True
    assert contrast.direction == "false_positive"


@pytest.mark.parametrize(("domain", "real_url", "note"), NAIVE_FALSE_NEGATIVES)
def test_naive_never_sees_the_real_file(domain: str, real_url: str, note: str) -> None:
    """假阴方向：真文件在朴素探测集之外，朴素永远看不到它。

    §3.7:1841：只探根路径会把 minimax、moonshot、siliconflow、onfleet、
    canvasmedical、ecwid **6 个域**读成「未采纳」。
    """
    assert in_naive_probe_set(real_url, domain) is False
    contrast = naive_contrast(
        probe_url=real_url,
        apex=domain,
        http_status=200,
        real_status=Status.PASS,
        actual_conclusion="已采纳（真文件在朴素探测集之外）",
        why=note,
    )
    assert contrast.naive_conclusion == "未采纳（没探这个位置）"
    assert contrast.naive_method == "不在朴素探测集内"
    assert contrast.diverges is True
    assert contrast.direction == "false_negative"


def test_every_one_of_the_six_domains_is_misread_in_some_direction() -> None:
    """A15 前半：六个域一个不落，都被朴素读错（方向可以不同）。"""
    covered = {row[0] for row in NAIVE_FALSE_POSITIVES} | {row[0] for row in NAIVE_FALSE_NEGATIVES}
    assert covered == SIX_DOMAINS
    # 两个方向都读错的三个域（corpus 原文：「两个方向都会读错」）
    both = {row[0] for row in NAIVE_FALSE_POSITIVES} & {row[0] for row in NAIVE_FALSE_NEGATIVES}
    assert both == {"minimax.io", "moonshot.ai", "canvasmedical.com"}


def test_naive_probe_set_is_two_hosts_times_two_paths() -> None:
    """朴素探测集 = {apex, www} × {/llms.txt, /llms-full.txt}，就四个位置。"""
    assert NAIVE_PATHS == ("/llms.txt", "/llms-full.txt")
    assert in_naive_probe_set("https://acme.com/llms.txt", "acme.com") is True
    assert in_naive_probe_set("https://www.acme.com/llms-full.txt", "acme.com") is True
    assert in_naive_probe_set("https://docs.acme.com/llms.txt", "acme.com") is False
    assert in_naive_probe_set("https://acme.com/docs/llms.txt", "acme.com") is False


#: A15 后半的门槛：全语料上朴素读错的域数 ≥ 20。
NAIVE_MISREAD_FLOOR = 20


def _misread_domains() -> dict[str, set[str]]:
    """从第 5 步落地的标注里机械算出「朴素会读错」的域集合，按方向分组。

    四个来源，全部是标注文件里的既有字段，没有一条是这里新造的：

    ``false_positive``  A/A' 两张表 —— 朴素只看状态码，200 的软 404 一律读成
                        「已采纳」，而这些位置实际是壳；
    ``false_negative``  上面 SIX_DOMAINS 的六个域 —— 真文件不在朴素探测集里；
    ``blocked``         B 表里判 BLOCKED 的两条（gusto 403 / pipedrive 429）——
                        朴素把「被拦」读成「没有」；
    ``fake_full``       llms-full 标注里 ``counted_as_hit`` 的域 —— 朴素看到
                        llms-full.txt 200 就记「有全文」，实际是索引的字节副本。
    """
    soft404 = json.loads((DATA / "soft404_expectations.json").read_text(encoding="utf-8"))
    llmsfull = json.loads((DATA / "llmsfull_expectations.json").read_text(encoding="utf-8"))

    def reg_of(url: str) -> str:
        return registrable_domain(httpx.URL(url).host)

    groups: dict[str, set[str]] = {
        "false_positive": {reg_of(r["url"]) for r in soft404["a"] + soft404["a_prime"]},
        "false_negative": set(SIX_DOMAINS),
        "blocked": {
            reg_of(r["url"]) for r in soft404["b"] if r["expect_verdict"] == Verdict.BLOCKED.value
        },
        "fake_full": {reg_of(p["index_url"]) for p in llmsfull["pairs"] if p.get("counted_as_hit")},
    }
    return groups


def test_naive_misreads_at_least_twenty_domains_across_the_corpus() -> None:
    """A15 后半：全语料上朴素读错的域数 **≥ 20**（P0 的首页数字）。

    口径写死在 ``_misread_domains()`` 的 docstring 里：只算「AI 路径这件事的
    采纳结论被读错」的四类，**刻意不算**索引内链与 .md 约定那两类（它们是
    「采纳了但没兑现」，不是采纳结论本身读错）。把那两类也算进来是 30 个域。
    """
    groups = _misread_domains()
    union: set[str] = set()
    for domains in groups.values():
        union |= domains
    assert len(union) >= NAIVE_MISREAD_FLOOR, f"只数出 {len(union)} 个：{sorted(union)}"
    # 四类一个都不许是空的 —— 空了说明标注文件的字段名漂了，而不是「真没有」
    for name, domains in groups.items():
        assert domains, name
    # 六个点名的域必须在里面
    assert union >= SIX_DOMAINS


def test_corpus_backs_the_six_domains() -> None:
    """六个域的名字不是我起的：``corpus/feature-raw.json`` 里都有它们的实测记录。"""
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    recorded: list[str] = [
        str(dom["domain"]) for measure in corpus["measures"] for dom in measure["domains"]
    ]
    for domain in sorted(SIX_DOMAINS):
        stem = domain.split(".")[0]
        assert any(stem in name for name in recorded), domain
