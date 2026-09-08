"""核心不变量：绝不制造假通过（UNKNOWN 不许塌成 PASS）。

这个文件守两条，都是实测踩出来的：

1. **认不出的状态码不许判 OK。** ``classify_response`` 原来的落空分支是 L5 OK，
   于是任何没被前面规则命中的状态码都变成「通过」。实测扫 100–599 全空间：
   376 个非 2xx 判 ok，其中活网可达的有 400 / 406 / 408 / 409 / 411–428 /
   430–499 以及 501 / 505 / 506 / 509–519 / 528 / 529 / 531–599。
   ``_SERVER_ERROR`` 是一张显式白名单（收了 Cloudflare 的 520–530），名单外的
   5xx 就从落空分支漏成通过。

2. **缺对照探针的合成响应不许被当成「对照能区分」。** fixture 层缺探针时合成
   ``599 + x-geo-audit-fixture: missing``，而 599 恰好落在第 1 条那个洞里 ——
   于是 ``host_profile`` 得到 ``usable=True`` / ``status_discriminates=True``，
   把「我们没有这份快照」读成「这个 host 对不存在的路径会给非 2xx」的正面证据，
   位置从 UNKNOWN 塌成 OK。实测九份已发布报告里有 4 份至少一个 host 中招
   （deepgram / minimax / openstatus / tdengine）。

   ``probe_url_lenient`` 的文档一直写着「599 → host_profile 判
   control_unavailable → 那个位置走 UNKNOWN」—— 代码与文档相反，文档是对的。
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.classify import _SERVER_ERROR, classify_response
from geo_audit.fetch.client import Fetcher, FetcherConfig, build_user_agent
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import FixtureStore
from geo_audit.models import Classification, Expect, Verdict
from geo_audit.pipeline import StopTransport

CONTACT = "ci@geo-audit.invalid"

#: 没有对照探针快照的实录位置（strict 下 probe_url 会抛）。
#: 选 upstash 是因为它在 B 表里，标注写着「是真文件」—— 正好是最容易被
#: 「伪造对照 -> 判 OK」蒙过去的形状。
NO_CONTROL_URL = "https://upstash.com/llms.txt"


def _classify(status: int) -> Classification:
    return classify_response(
        status,
        {"content-type": "text/plain"},
        "boom",
        url="https://example.invalid/p",
        expect=Expect.ANY,
        final_url="https://example.invalid/p",
        redirects=(),
    )


def test_no_non_2xx_status_is_ever_judged_ok() -> None:
    """扫 100–599 全空间：非 2xx 判 OK 的必须是**零个**。

    断言写成「全空间扫描」而不是列举几个码：这个洞的成因就是白名单式枚举，
    再用枚举去守它，下一个没想到的码照样漏。
    """
    leaked = [
        st
        for st in range(100, 600)
        if _classify(st).verdict is Verdict.OK and not (200 <= st < 300)
    ]
    assert leaked == [], (
        f"这些非 2xx 状态码被判成「通过」：{leaked}。"
        "认不出的状态码必须走 UNKNOWN —— 不认定通过也不认定失败。"
    )


# 451 刻意不在这张表里：它有自己的分支（blocked / waf_status），
# 「因法律原因不可用」本来就是拦截语义，不是「我们不认识这个码」。
@pytest.mark.parametrize("status", [400, 408, 409, 418, 501, 506, 509, 511, 529, 599])
def test_unrecognised_status_goes_unknown_with_its_own_reason(status: int) -> None:
    cls = _classify(status)
    assert cls.verdict is Verdict.UNKNOWN, f"HTTP {status} 判成了 {cls.verdict.value}"
    assert cls.reason == "unexpected_status"


@pytest.mark.parametrize("status", sorted(_SERVER_ERROR))
def test_whitelisted_server_errors_keep_their_own_reason(status: int) -> None:
    """名单内的 5xx 仍然报 server_error，不许被新分支抢走。

    两者都是 UNKNOWN，但理由不同 —— 报告里 server_error 有「服务端错误」这条
    具体补救建议，笼统成 unexpected_status 等于把已经查清的事又说回不清楚。
    """
    cls = _classify(status)
    assert cls.verdict is Verdict.UNKNOWN
    assert cls.reason == "server_error"


def test_missing_control_snapshot_never_manufactures_a_pass(tmp_path: Path) -> None:
    """缺对照探针时，位置必须走 UNKNOWN/control_unavailable，**不许**是 OK。

    走的是生产侧那条完整路径（``Fetcher.probe``），不是手拼输入：这个 bug 的
    要害恰恰在 ``host_profile`` 对探针响应的推导上，手拼 HostProfile 就把病灶
    绕过去了。
    """
    store = FixtureStore.default()
    fetcher = Fetcher(
        FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
        HttpCache(tmp_path / "c.sqlite3", ua_profile=build_user_agent(CONTACT)),
        DomainLimiter(2.0),
        transport=StopTransport(store.transport(strict=False), threading.Event()),
        probe_url_provider=store.probe_url_lenient,
        resolver=store.resolver(),
    )
    try:
        profile = fetcher.host_profile(NO_CONTROL_URL)
        # 合成响应不许冒充可用对照
        assert profile.usable is False, (
            f"缺快照的合成对照被判 usable（status={profile.status}）—— "
            "「我们没有这份快照」被读成了「对照可用」。"
        )
        assert profile.status_discriminates is False, (
            "缺快照的合成对照被判「能区分」—— 那是把 fixture 缺口当成站点证据。"
        )
        probe = fetcher.probe(NO_CONTROL_URL, expect=Expect.TEXT_FILE)
        assert probe.classification.verdict is not Verdict.OK, (
            f"没有对照探测却判了 OK（reason={probe.classification.reason}）。"
        )
        assert probe.classification.reason == "control_unavailable"
    finally:
        fetcher.close()


# --------------------------------------------------------------------------- #
# 第三条：上游判不了而剪掉的下游工作，必须记成覆盖缺口
# --------------------------------------------------------------------------- #
#
# 这条守的是上面那个修复的**副作用**。索引文件的判定从 OK 变 UNKNOWN 之后，
# ``index_file_probes`` 按 P3 就不再收它（规格原文「每个判为真文件且解析出
# ≥1 条链接的索引文件各一格」），于是它里面的内链整批不查。剪枝是对的，
# 但报告若照旧写「没有额外的覆盖缺口」，等于把一个假 PASS 换成一个没披露的
# 盲区 —— 那比误判更隐蔽。
#
# 实测：developers.deepgram.com/llms.txt 的对照探针没录，判定变 UNKNOWN 之后
# 它里面 383 条内链一条都不查了，而覆盖披露照旧写「没有额外的覆盖缺口」。


def _unknown_index_probe(url: str, links: int) -> object:
    """造一个「解析得出内链、但自身判不了」的索引探测。"""
    from geo_audit.models import Classification, HttpResponse, Probe, Verdict

    body = "# Index\n\n" + "\n".join(
        f"- [Guide {i}](https://docs.example.invalid/g/{i}.md): section {i}" for i in range(links)
    )
    resp = HttpResponse(
        url=url,
        final_url=url,
        status=599,
        headers={"content-type": "text/plain"},
        body=body.encode(),
        redirects=(),
    )
    cls = Classification(Verdict.UNKNOWN, "control_unavailable", ("没能做对照探测",))
    return Probe(url, Expect.TEXT_FILE, resp, cls)


def test_pruned_index_links_are_disclosed_as_a_coverage_gap() -> None:
    from geo_audit.models import SiteMap
    from geo_audit.pipeline import (
        AuditOptions,
        NullProgress,
        RunState,
        _stage_index_links,
        index_file_probes,
    )

    url = "https://docs.example.invalid/llms.txt"
    probe = _unknown_index_probe(url, links=383)
    sitemap = SiteMap(
        input_domain="example.invalid",
        registrable_domain="example.invalid",
        hosts=(),
        apex_www=None,
        sitemap_urls={},
        pricing_url=None,
        pricing_candidates_tried=(),
        ai_path_probes=(probe,),
        robots={},
    )
    st = RunState(sitemap=sitemap)
    options = AuditOptions(domain="example.invalid", contact=CONTACT, replay_fixtures=True)

    # 前提：P3 确实把它剪掉了（否则这条测试测的不是那个副作用）
    assert index_file_probes(sitemap) == (), "P3 应当剪掉非 OK 的索引，前提不成立"

    _stage_index_links(st, options, None, NullProgress())  # type: ignore[arg-type]

    gaps = [g for g in st.coverage_gaps if url in g.where]
    assert len(gaps) == 1, (
        f"索引判不了、内链整批被剪，却没记覆盖缺口（现有 {len(st.coverage_gaps)} 条）。"
        "报告会照旧写「没有额外的覆盖缺口」—— 那是把假 PASS 换成没披露的盲区。"
    )
    gap = gaps[0]
    assert gap.reason == "control_unavailable"
    assert "383" in gap.detail, f"缺口没说清剪掉了多少条：{gap.detail}"
    assert len(gap.remedy) >= 20, "缺口必须给可执行的补救办法（A32 的 ≥20 字符）"


# --------------------------------------------------------------------------- #
# 第四条：根路径判不了而整片掉出探测集的 host，必须记成覆盖缺口
# --------------------------------------------------------------------------- #
#
# 这是「位置静默消失」的**真正**成因（第三条那个记在 index_links 层的，
# 位置记错了：实测 deepgram 的 coverage_gaps 仍是 0）。
#
# `discovery.host_is_live` 是 `verdict in (OK, BLOCKED)` —— UNKNOWN 不在里面。
# 根路径判 UNKNOWN 的 host 直接从 live_hosts 掉出去：AI 路径不探、robots 不读、
# sitemap 不读，账本上只剩一格 UNKNOWN。
#
# 那段函数自己的注释就在反驳这个结果 —— 它说 BLOCKED 的 host 必须留着，因为
# 「把它们丢掉就是软 404 让采纳率虚高的反向孪生错误 —— 虚低」。根路径 UNKNOWN
# 是同一种情形。这里不改 host_is_live（timeout / network_error 那类继续探只会
# 把预算烧在真连不上的 host 上），改的是**披露**。
#
# 实测锚点：developers.deepgram.com 的对照探针没录 → 根路径判
# UNKNOWN(control_unavailable) → 它 llms.txt 里 383 条内链一条没查，
# 而覆盖披露照旧写「没有额外的覆盖缺口」。


def test_host_dropped_at_discovery_is_disclosed_as_a_coverage_gap() -> None:
    from geo_audit.models import DiscoveredHost, HostRole, SiteMap
    from geo_audit.pipeline import AuditOptions, NullProgress, RunState, _stage_ai_path

    dropped = DiscoveredHost(
        host="docs.example.invalid",
        role=HostRole.DOCS,
        reachable=True,
        verdict=Verdict.UNKNOWN,
        reason="control_unavailable",
    )
    alive = DiscoveredHost(
        host="example.invalid",
        role=HostRole.APEX,
        reachable=True,
        verdict=Verdict.OK,
        reason="ok",
    )
    sitemap = SiteMap(
        input_domain="example.invalid",
        registrable_domain="example.invalid",
        hosts=(alive, dropped),
        apex_www=None,
        sitemap_urls={},
        pricing_url=None,
        pricing_candidates_tried=(),
        ai_path_probes=(),  # 掉出去的 host 一条探测都没有 —— 正是要披露的那件事
        robots={},
    )
    st = RunState(sitemap=sitemap)
    options = AuditOptions(domain="example.invalid", contact=CONTACT, replay_fixtures=True)

    # 只需要 user_agent：探测集是空的，check_ai_paths / check_llms_full 都不做事。
    # 传真 Fetcher 会把这条测试变成一次装配练习，而它要测的只是那段披露逻辑。
    fake_fetcher = SimpleNamespace(user_agent="geo-audit/test (contact: ci@geo-audit.invalid)")
    _stage_ai_path(st, options, fake_fetcher, NullProgress())  # type: ignore[arg-type]

    gaps = [g for g in st.coverage_gaps if dropped.host in g.where]
    assert len(gaps) == 1, (
        f"根路径判不了的 host 整片掉出探测集，却没记覆盖缺口"
        f"（现有 {len(st.coverage_gaps)} 条）。报告会写「没有额外的覆盖缺口」。"
    )
    assert gaps[0].reason == "control_unavailable"
    assert "没能看" in gaps[0].detail, "缺口必须说清这不是「没问题」"
    assert len(gaps[0].remedy) >= 20

    # 判 OK 的 host 不许被误记成盲区
    misfired = [
        g for g in st.coverage_gaps if alive.host in g.where and dropped.host not in g.where
    ]
    assert misfired == [], f"判 OK 的 host 被误记成盲区：{misfired}"
