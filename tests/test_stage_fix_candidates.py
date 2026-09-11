"""⑦ 修复目标这一段的接线：fix 挂上去了、两档如实披露、预算耗尽也披露。

**为什么要 pipeline 级的测试**：`fix_candidates.py` 的单元测试全绿，但第一次
真跑 CLI 才发现 replay 模式下 75 条候选全拿到合成 599，而报告对它们都写
「补一个页面」、覆盖缺口是空的 —— 单元测试看不到这个，因为它测的是函数，
不是「报告最后长什么样」。这个文件补的就是那一层。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from geo_audit.checks.fix_candidates import CandidateQuality
from geo_audit.models import Evidence, Expect, Probe, Verdict


def _finding(url: str, kind: str = "index_link_dead") -> object:
    from geo_audit.models import (
        Finding,
        PositionClass,
        Severity,
        Stage,
        make_finding_id,
    )

    return Finding(
        finding_id=make_finding_id("ai_path.index_links", url, "https://x.invalid/llms.txt"),
        kind=kind,  # type: ignore[arg-type]
        check_id="ai_path.index_links",
        title=f"llms.txt 里列的 {url} 是死链",
        severity=Severity.HIGH,
        position_class=PositionClass.AI_CHANNEL,
        stage=Stage.INDEX_LINKS,
        target=Evidence(url=url, curl_repro=f"curl '{url}'"),
        found_on="https://x.invalid/llms.txt",
    )


class _StubFetcher:
    """只实现 ⑦ 用到的那一个方法。**刻意不用真 Fetcher** —— 这条测试要验的是
    接线与披露，不是 HTTP 客户端怎么造。"""

    def __init__(self, verdict: Verdict, status: int | None) -> None:
        self.verdict = verdict
        self.status = status
        self.calls = 0

    @property
    def http_requests(self) -> int:
        """预算闸现在按**真实 HTTP 请求条数**掐（`_budget_left`），
        替身也得给出这个数，否则测的就不是真正在跑的那条路径。"""
        return self.calls

    def probe(self, url: str, *, expect: Expect = Expect.ANY, **_: object) -> Probe:
        from geo_audit.models import Classification, HttpResponse

        self.calls += 1
        resp = HttpResponse(
            url=url, final_url=url, status=self.status or 0, headers={}, body=b"", redirects=()
        )
        reason = "unexpected_status" if self.verdict is Verdict.UNKNOWN else "status_404"
        return Probe(url, expect, resp, Classification(self.verdict, reason, ("stub",)))  # type: ignore[arg-type]


def _run(verdict: Verdict, status: int | None, *, n: int = 3, max_requests: int = 0) -> object:
    from geo_audit.pipeline import AuditOptions, NullProgress, RunState, _stage_fix_candidates

    st = RunState()
    st.findings = [_finding(f"https://docs.x.invalid/docs/a/p{i}.md") for i in range(n)]
    options = AuditOptions(
        domain="x.invalid",
        contact="ci@geo-audit.invalid",
        fix_candidates=True,
        max_requests=max_requests,
    )
    fetcher = _StubFetcher(verdict, status)
    _stage_fix_candidates(st, options, fetcher, NullProgress())  # type: ignore[arg-type]
    return SimpleNamespace(state=st, fetcher=fetcher)


def test_every_dead_link_finding_gets_a_fix_hint() -> None:
    """接线之前是 0/76 —— 模板早就会渲染 FixHint，只是从来没人填过。"""
    r = _run(Verdict.REAL404, 404)
    assert all(f.fix is not None for f in r.state.findings)  # type: ignore[attr-defined]


def test_unusable_probes_are_disclosed_as_a_coverage_gap() -> None:
    """候选一条都没验成 → 必须有覆盖缺口，且必须说清「不是没有替代地址」。

    这正是第一次真跑 CLI 暴露的那个坑：报告对 75 条都写「补一个页面」、
    覆盖缺口是空的，读的人会以为我们查过了。
    """
    r = _run(Verdict.UNKNOWN, 599)
    gaps = [g for g in r.state.coverage_gaps if "修复目标" in g.where]  # type: ignore[attr-defined]
    assert len(gaps) == 1, f"没能查却没披露：{r.state.coverage_gaps}"  # type: ignore[attr-defined]
    assert "不是" in gaps[0].detail
    assert "没查到" in gaps[0].detail or "我们没查" in gaps[0].detail
    assert gaps[0].remedy, "缺口必须给可执行的补救办法"


def test_real_404_probes_are_not_disclosed_as_a_gap() -> None:
    """逐个试过、确实不存在 —— 那不是盲区，不许记成覆盖缺口（否则每份报告都挂一条）。"""
    r = _run(Verdict.REAL404, 404)
    gaps = [g for g in r.state.coverage_gaps if "修复目标" in g.where]  # type: ignore[attr-defined]
    assert gaps == [], f"「查过没有」被误记成盲区：{gaps}"


def test_the_two_tiers_produce_different_copy_in_the_report() -> None:
    unchecked = _run(Verdict.UNKNOWN, 599)
    none = _run(Verdict.REAL404, 404)
    a = unchecked.state.findings[0].fix.action  # type: ignore[attr-defined]
    b = none.state.findings[0].fix.action  # type: ignore[attr-defined]
    assert a != b, "两档在报告里长得一样 —— after 都是 None，只能靠文案区分"


def test_budget_exhaustion_is_disclosed_separately() -> None:
    """预算不够而没查 ≠ 查了没验成。两个原因，两条缺口。"""
    r = _run(Verdict.REAL404, 404, n=5, max_requests=1)
    gaps = [g for g in r.state.coverage_gaps if "修复目标" in g.where]  # type: ignore[attr-defined]
    assert gaps, "预算耗尽没披露"
    assert any("预算" in g.detail for g in gaps)
    assert any("我们没查" in g.detail for g in gaps)


def test_stage_is_off_by_default() -> None:
    """默认关：实测 mistral 的 75 条死链验完用了 166 个请求，吃穿默认的 120。"""
    from geo_audit.pipeline import AuditOptions

    assert AuditOptions(domain="x.invalid", contact="c@x.invalid").fix_candidates is False


@pytest.mark.parametrize("kind", ["llms_full_fake", "md_not_fulfilled"])
def test_non_dead_link_findings_are_left_alone(kind: str) -> None:
    """只给死链找替代地址。别的 finding 不该被塞一个「改指到」的建议。"""
    from geo_audit.pipeline import AuditOptions, NullProgress, RunState, _stage_fix_candidates

    st = RunState()
    st.findings = [_finding("https://docs.x.invalid/llms-full.txt", kind=kind)]
    _stage_fix_candidates(
        st,
        AuditOptions(domain="x.invalid", contact="c@x.invalid", fix_candidates=True),
        _StubFetcher(Verdict.REAL404, 404),  # type: ignore[arg-type]
        NullProgress(),
    )
    assert st.findings[0].fix is None
    assert CandidateQuality.EXACT  # 引用一下，保证枚举没被删
