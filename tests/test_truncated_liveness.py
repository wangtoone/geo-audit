"""截断的正文 + 存活判定：三个缺陷的回归面。

实测起点是 open-design.ai（2026-09-15 活网跑两轮）：它的 ``llms.txt`` 解析出
49 条内链，工具报 **5 活 / 2 死 / 42 判不了**。手动逐条 ``curl`` 复核的真值是
**43 活 / 2 死**（45 条唯一站内 URL）—— 42 条全部判成 ``UNKNOWN/body_truncated``，
因为那些页面正好卡在 ``LIVENESS_BYTE_CAP`` 的 64 KiB 上。

三条缺陷各有自己的一段：

1. ``body_truncated`` 是一条无条件短路 —— 正文截断就 UNKNOWN，哪怕对照探测
   已经用状态码把「存在」和「不存在」分开了。
2. ``--index-links-full`` 只到 ``AuditOptions.index_links_full`` 为止，
   **全仓没有第二个读它的地方**，帮助文案承诺的「一律全量验证」是空的。
3. 位置状态只由「测到的那几条」决定：42 条 unknown 在位置四格里一个都不出现，
   于是 49 条里 42 条没验的那一格报 PASS，整份报告落到 ``zero_clean``，
   首屏写「N 个位置全部通过」。两轮实测底层数字一个字没变，首屏却从
   「抽样率 12.7%，不能外推」翻成了「全部通过」—— 正是 README 第二节点名的那种骗法。
"""

from __future__ import annotations

import pytest

from geo_audit.checks.ai_path import (
    INDEX_LINKS_FULL_THRESHOLD,
    INDEX_LINKS_SAMPLE_SIZE,
    IndexLink,
    IndexLinkReport,
    sample_index_links,
)
from geo_audit.fetch.classify import classify_response
from geo_audit.models import Counts, Expect, HostProfile, Severity, Status, Verdict
from geo_audit.pipeline import _index_links_status, make_headline

#: 一个超过 LIVENESS_BYTE_CAP 的正文被截断后剩下的样子：只有开头那一截。
#: 内容刻意不含任何「找不到」文案，也不含 HTML —— 单看它判不出任何东西，
#: 这正是「判定只能靠状态码 + 对照探测」的场景。
TRUNCATED_BODY = "<!doctype html><html><head><title>OpenDesign</title></head><body>" + "x" * 400


def _control(
    host: str, *, status: int, content_type: str = "text/html", is_html: bool = True
) -> HostProfile:
    """同域对照探测（一条编造出来的路径）的观测。

    ``status_discriminates`` 按 ``HostProfile`` 的定义走：非 2xx 才算能区分。
    """
    return HostProfile(
        host=host,
        probe_url=f"https://{host}/geo-audit-probe-deadbeef.txt",
        status=status,
        content_type=content_type,
        norm_sha256="0" * 64,
        norm_len=200,
        norm_body_prefix="page not found " * 10,
        struct_sha256="1" * 64,
        struct_tags=80,
        final_path="/geo-audit-probe-deadbeef.txt",
        status_discriminates=not (200 <= status < 300),
        control_is_html=is_html,
        usable=True,
        probed_at=0.0,
    )


def _classify(
    status: int,
    *,
    control: HostProfile | None,
    truncated: bool = True,
    expect: Expect = Expect.ANY,
) -> object:
    return classify_response(
        status,
        {"content-type": "text/html"},
        TRUNCATED_BODY,
        url="https://open-design.ai/plugins/design-system-claude",
        expect=expect,
        control=control,
        body_truncated=truncated,
    )


# --------------------------------------------------------------------------- #
# 缺陷一 · 截断的 2xx 在「对照探测用状态码区分」的 host 上是可判的
# --------------------------------------------------------------------------- #


def test_truncated_200_is_alive_when_the_control_returns_404() -> None:
    """open-design.ai 就是这一类：对照探测 404，目标 200，正文截断。

    ``HostProfile.status_discriminates`` 的文档原文已经写了这条推理 ——
    「A host that answers a missing path with 404/410/5xx discriminates for
    EVERY kind of target, so any 2xx response from it is trustworthy without
    body comparison」。判定层原来没走到那一步就先短路了。
    """
    cls = _classify(200, control=_control("open-design.ai", status=404))
    assert cls.verdict is Verdict.OK
    assert cls.reason == "ok_control_discriminates"
    # 披露不可省：这一条是靠状态码判的，正文没读全。
    assert any("截断" in e and "未做正文指纹" in e for e in cls.evidence)


def test_truncated_200_stays_unknown_on_a_catch_all_host() -> None:
    """platform.kimi.ai 型 host：对照探测也回 200，只能靠正文指纹区分。

    而 ``liveness_only`` 的响应连 digest 都没算
    （``finalize_response(want_digests=not liveness_only)``），截断之后
    **没有任何出路** —— 这一条必须继续 UNKNOWN，放行就是假通过。
    """
    cls = _classify(200, control=_control("platform.kimi.ai", status=200))
    assert cls.verdict is Verdict.UNKNOWN
    assert cls.reason == "body_truncated"


def test_truncated_200_stays_unknown_without_a_control() -> None:
    """没有对照探测就没有放行依据 —— 缺省必须是 UNKNOWN，不是 OK。"""
    cls = _classify(200, control=None)
    assert cls.verdict is Verdict.UNKNOWN
    assert cls.reason == "body_truncated"


def test_truncated_200_stays_unknown_when_the_control_itself_is_unusable() -> None:
    """对照探测自身被挡（gusto.com 403）时，它证明不了任何事。"""
    control = _control("gusto.com", status=404)
    object.__setattr__(control, "usable", False)
    cls = _classify(200, control=control)
    assert cls.verdict is Verdict.UNKNOWN
    # 对照不可用是更靠前的一条分支，reason 落在 control_unavailable 或
    # body_truncated 都可以 —— 不可以的是落到 OK。
    assert cls.reason in {"body_truncated", "control_unavailable"}


@pytest.mark.parametrize("status", [301, 403, 429, 500, 503])
def test_truncated_non_2xx_is_never_rescued(status: int) -> None:
    """放行条件里的 2xx 不是装饰：非 2xx 一条都不许靠这条路变成通过。"""
    cls = _classify(status, control=_control("open-design.ai", status=404))
    assert cls.verdict is not Verdict.OK


def test_truncated_404_is_still_a_real_404() -> None:
    """404 分支在截断检查之前，改动不许动它（open-design.ai 那 2 条死链走这里）。"""
    cls = _classify(404, control=_control("open-design.ai", status=404))
    assert cls.verdict is Verdict.REAL404
    assert cls.reason == "status_404"


def test_untruncated_bodies_are_untouched() -> None:
    """没截断的响应走原来的整条判定链，本次改动对它们零影响。"""
    cls = _classify(200, control=_control("open-design.ai", status=404), truncated=False)
    assert cls.verdict is Verdict.OK
    assert not any("截断" in e for e in cls.evidence)


# --------------------------------------------------------------------------- #
# 缺陷二 · --index-links-full 之前是个空开关
# --------------------------------------------------------------------------- #


def _fake_links(n: int) -> list[IndexLink]:
    return [
        IndexLink(
            line_no=i,
            abs_url=f"https://acme.invalid/p{i}",
            norm_url=f"https://acme.invalid/p{i}",
            anchor_text=None,
            extractor="markdown",
        )
        for i in range(n)
    ]


def test_full_flag_bypasses_the_sampling_threshold() -> None:
    """504 条内链（C08 bytebase 那一份）在 ``full=True`` 下不许再抽样。"""
    links = _fake_links(504)
    sample, sampled = sample_index_links(links, full=True)
    assert sampled is False
    assert sample == links
    assert len(sample) == 504


def test_without_the_flag_the_threshold_still_applies() -> None:
    """反向：不传 ``full`` 时抽样行为原样保留，否则上面那条测的是「永远为真」。"""
    links = _fake_links(504)
    sample, sampled = sample_index_links(links)
    assert sampled is True
    assert len(sample) == INDEX_LINKS_SAMPLE_SIZE
    # 阈值以下无论传不传都是全量。
    under = _fake_links(INDEX_LINKS_FULL_THRESHOLD)
    assert sample_index_links(under)[1] is False
    assert sample_index_links(under, full=True)[1] is False


# --------------------------------------------------------------------------- #
# 缺陷三 · 判不了的内链占多数时，这一格不是 PASS
# --------------------------------------------------------------------------- #


def _report(*, alive: int, dead: int, unknown: int, status: Status) -> IndexLinkReport:
    links = _fake_links(alive + dead + unknown)
    return IndexLinkReport(
        index_url="https://open-design.ai/llms.txt",
        links=tuple(links),
        probed=tuple(links),
        sampled=False,
        sampled_of=len(links),
        excluded=(),
        alive=tuple(links[:alive]),
        dead=tuple(links[alive : alive + dead]),
        unknown=tuple(links[alive + dead :]),
        status=status,
        severity=Severity.INFO,
        counted_as_hit=False,
    )


def test_unknown_majority_downgrades_the_cell_to_unknown() -> None:
    """open-design.ai 修复前那一格：49 条里 42 条判不了，报的却是 PASS。"""
    report = _report(alive=5, dead=2, unknown=42, status=Status.PASS)
    assert _index_links_status(report) is Status.UNKNOWN


def test_mistral_27_link_cell_is_unknown_not_pass() -> None:
    """replay 实测锚点：mistral.ai 的 27 条内链那一格 2 活 / 0 死 / 25 判不了。

    改动前 ``grade()`` 因为 ``dead == 0`` 返回 PASS，那一格就是 PASS。
    """
    report = _report(alive=2, dead=0, unknown=25, status=Status.PASS)
    assert _index_links_status(report) is Status.UNKNOWN


def test_a_minority_of_unknowns_does_not_flip_the_cell() -> None:
    """反向：少数判不了不翻转（那些链接由调用点记进覆盖缺口，不会消失）。

    没有这一条，上面两条测的就是「只要有 unknown 就 UNKNOWN」，那是另一个口径。
    """
    report = _report(alive=40, dead=2, unknown=7, status=Status.PASS)
    assert _index_links_status(report) is Status.PASS


def test_fail_is_never_downgraded() -> None:
    """「这个位置会被读错」比「判不了」信息量更大，FAIL 不许被 unknown 盖掉。"""
    report = _report(alive=0, dead=75, unknown=200, status=Status.FAIL)
    assert _index_links_status(report) is Status.FAIL


def test_clean_cells_stay_pass() -> None:
    """零 unknown 的一格原样通过 —— 改动不许给干净的报告加噪声。"""
    report = _report(alive=47, dead=2, unknown=0, status=Status.PASS)
    assert _index_links_status(report) is Status.PASS


# --------------------------------------------------------------------------- #
# 缺陷三之二 · zero_clean 的门槛是「零条未决」，不是「大部分有结论」
# --------------------------------------------------------------------------- #


def _clean_counts(**over: int) -> Counts:
    """位置四格全绿的一份 Counts：7 通过、0 读错、0 判不了。"""
    base: dict[str, object] = {
        "positions": 15,
        "positions_pass": 7,
        "positions_fail": 0,
        "positions_unknown": 0,
        "positions_na": 8,
        "findings": 0,
        "findings_counted": 0,
        "occurrences": 0,
        "root_causes": 0,
        "by_severity": {},
        "naive_divergences": 0,
    }
    base.update(over)
    return Counts(**base)  # type: ignore[arg-type]


def _headline(unresolved: int, *, ratio: float = 1.0, unprobed: int = 0) -> tuple[str, str]:
    return make_headline(
        _clean_counts(),
        has_ai_channel=True,
        sampled_ratio=ratio,
        interrupted=False,
        index_links_unresolved=unresolved,
        index_links_unprobed=unprobed,
    )


def test_zero_unresolved_index_links_is_the_only_way_to_zero_clean() -> None:
    """一条未决都没有才算「全部通过」。"""
    headline, kind = _headline(0)
    assert kind == "zero_clean"
    assert "全部通过" in headline


def test_a_minority_of_unresolved_index_links_still_blocks_zero_clean() -> None:
    """49 条里 24 条判不了：``_index_links_status`` 不翻格（少数不作废），
    ``sampled_ratio`` 也看不见（它的分子把 unknown 算作已覆盖，而且只收
    可点击路径那一段）。没有这一条，首屏照样写「全部通过」。
    """
    headline, kind = _headline(24)
    assert kind == "zero_with_unknown"
    assert "24" in headline
    assert "全部通过" not in headline.replace("不能算「全部通过」", "")


def test_one_unresolved_link_is_enough() -> None:
    """门槛是零，不是某个比例 —— 1 条也挡。"""
    assert _headline(1)[1] == "zero_with_unknown"


def test_existing_branches_keep_priority() -> None:
    """新分支插在 zero_clean 之前，前面六条谁也不让位。"""
    # 位置级 unknown 仍然先说话（那句文案讲的是位置，不是链接）。
    headline, kind = make_headline(
        _clean_counts(positions_unknown=3),
        has_ai_channel=True,
        sampled_ratio=1.0,
        interrupted=False,
        index_links_unresolved=24,
    )
    assert kind == "zero_with_unknown"
    assert "3 个位置" in headline
    # 抽样率不足也先说话。
    headline, kind = _headline(24, ratio=0.127)
    assert kind == "zero_with_unknown"
    assert "抽样率" in headline
    # 有读错的位置永远优先。
    headline, kind = make_headline(
        _clean_counts(positions_fail=2),
        has_ai_channel=True,
        sampled_ratio=1.0,
        interrupted=False,
        index_links_unresolved=24,
    )
    assert kind == "has_fail"


def test_default_keeps_the_old_behaviour() -> None:
    """不传这个参数时行为与改动前逐字相同（调用点漏传不会静默改判）。"""
    assert make_headline(
        _clean_counts(), has_ai_channel=True, sampled_ratio=1.0, interrupted=False
    ) == _headline(0)


def test_sampled_away_index_links_also_block_zero_clean() -> None:
    """modal.com 实测：308 条内链，超阈值抽 60 条，**剩下 248 条一个请求都没发**。

    它们不在 ``n_unknown``（没探过就没有判定），不在位置四格，也不在
    ``sampled_ratio``（那个分母只收可点击路径那一段）。报告里原来没有任何
    一个数字代表这 248 条，首屏却可以写「全部通过」。
    """
    headline, kind = _headline(0, unprobed=248)
    assert kind == "zero_with_unknown"
    assert "248" in headline
    assert "抽样" in headline


def test_both_kinds_are_named_separately() -> None:
    """「探了没判出来」和「没探」是两种状态，首屏要分开说，不许合成一个数。"""
    headline, _ = _headline(33, unprobed=248)
    assert "33" in headline and "248" in headline
    assert "没能判出存活" in headline and "一个请求都没发" in headline
