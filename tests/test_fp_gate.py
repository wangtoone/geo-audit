"""§8.6 假阳性门禁的自验（第 12b 步）。

跑的是 ``scripts/fp_gate.py`` 里那条**生产路径**（``classify_link``），断言：

  · 六条门禁全过，且 A16 的九个字段逐个对上（42 / 25 / 25 / [] / [] / 0.0 / 1.0 / [] / []）
  · 两个分母不是摆设：在 METRICS_SET 上算 ``unused_rules`` **必然非空**，
    所以门禁 5 只能算在 COVERAGE_SET 上（卡点 S3）
  · ``test_naive_would_be_405_percent``：去噪关掉 -> 42 条全判死，其中 17 条假阳性
  · X01–X14 每一行都命中它自己声明的那条规则（A19「X01–X14 全绿」）
  · fp-gate-report.json 写得出、读得回
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))

import fp_gate  # noqa: E402
from geo_audit.checks import dead_links  # noqa: E402
from geo_audit.fixtures import FixtureStore  # noqa: E402

pytestmark = pytest.mark.gate


@pytest.fixture(scope="module")
def store() -> FixtureStore:
    return fp_gate.default_store()


@pytest.fixture(scope="module")
def metrics_labels() -> list[fp_gate.Label]:
    return fp_gate.load_labels(fp_gate.METRICS_SET_PATH)


@pytest.fixture(scope="module")
def coverage_labels() -> list[fp_gate.Label]:
    rows = fp_gate.load_labels(fp_gate.COVERAGE_EXTRA_PATH)
    rows += [
        fp_gate.Label(
            id=str(r["id"]),
            url=str(r["url"]),
            source_page=str(r.get("source_page") or ""),
            label=str(r["label"]),
            expect_rule=r.get("expect_rule"),
            provenance=str(r.get("provenance", "spec_only")),
            synthetic=True,
            domain=str(r.get("domain") or ""),
            ctx=fp_gate._context_of(r),
            raw=r,
        )
        for r in fp_gate.SPEC_ONLY_EXTRA_ROWS
    ]
    return rows


@pytest.fixture(scope="module")
def result(
    store: FixtureStore,
    metrics_labels: list[fp_gate.Label],
    coverage_labels: list[fp_gate.Label],
) -> fp_gate.GateResult:
    return fp_gate.run_gate(store, metrics_labels, coverage_labels)


def test_classify_link_is_the_production_path() -> None:
    """卡点 A1：fp_gate 不许自己另写一份判定，也不许绕开 Fetcher 直连 httpx。"""
    assert fp_gate.classify_link is dead_links.classify_link
    source = Path(fp_gate.__file__).read_text(encoding="utf-8")
    assert "httpx.Client(" not in source  # 客户端只能来自 Fetcher
    assert "transport=transport" in source and "probe_url_provider=" in source


# ═════════════════════════════════════════════════════════════════════════════
# §8.1 漂移规程 · gone 分支（第 4b 步实录后发现）
#
# 实录 598 条真快照之后，两个 label 描述的**现象已经不存在了**：
#
#   H41  www.pinterest.com/_/_/about/
#        标注记的是「首轮 curl exit=6（DNS 解析失败）、单独重测 200」，
#        期望 rule = dns_retry_second_resolver。**真快照是 302 跳转** ——
#        DNS 抖动那个现象没了，站点改成了重定向。
#        于是它落进 counted 车道并被判死 -> fp_rate 0 -> 3.85%（26/25）。
#
#   X02  crates.io/crates/helius
#        标注期望 rule = third_party_no_control（第三方站点 UA 反爬、拿不到对照）。
#        **真快照是 200** —— crates.io 现在不拦我们的 UA 了。
#
# 规程说得很清楚：现象没了就**不改断言**，标 xfail(strict=True) 并留痕，
# 让「站方修好了」这件事在测试里可见，而不是把期望值改到跟现状一致
# （那等于把回归用例悄悄删掉）。strict=True 是绊线：哪天现象回来了，
# 这几条会 XPASS 变红，逼人回来重新裁决。
#
# 该做的后续（owner）：给这两条 label 加 drift.phenomenon=gone，
# 并在 CHANGELOG 记一行「现象已被站方修复，回归用例转为历史留档」。
# ═════════════════════════════════════════════════════════════════════════════

_GONE = pytest.mark.xfail(
    strict=True,
    reason=(
        "§8.1 gone 分支：H41（pinterest DNS 抖动 -> 现在 302）与 "
        "X02（crates.io UA 反爬 -> 现在 200）的现象已被站方修掉。"
        "按规程不改断言、只留痕。现象回来则 XPASS 变红，回来重新裁决。"
    ),
)


def test_six_gates_pass(result: fp_gate.GateResult) -> None:
    assert fp_gate.check_gates(result) == []


@_GONE
def test_a16_nine_fields(result: fp_gate.GateResult) -> None:
    """A16 的九个字段。四个数同时成立靠的是卡点 S4 那条裁决（printify 计入分子）。"""
    assert result.n_candidates == 42
    assert result.n_true_dead == 25
    assert result.n_pred_dead == 25
    assert result.fp == []
    assert result.fn == []
    assert result.fp_rate == 0.0
    assert result.recall == 1.0
    assert result.wrong_rule == []
    assert result.unused_rules == []


def test_unused_rules_needs_the_coverage_denominator(
    store: FixtureStore, metrics_labels: list[fp_gate.Label]
) -> None:
    """卡点 S3：``unused_rules == []`` 与 ``n_candidates == 42`` 不可能同时成立。

    42 条只触发 6 条规则，其余 17 条一律在 X 组。v1 把五条门禁全算在 42 条上，
    所以它数学上过不去 —— 这条测试就是那个矛盾的可执行证据。
    """
    metrics_only = fp_gate.run_gate(store, metrics_labels, [])
    assert metrics_only.n_candidates == 42
    assert metrics_only.unused_rules, "42 条不可能触发全部 23 条规则"
    assert set(metrics_only.fired_rules) == {
        "reserved_example_domain",
        "api_endpoint_in_code_context",
        "cloudflare_email_protection",
        "dns_retry_second_resolver",
        "seed_url_not_on_site",
        "class_hidden_anchor",
    }


def test_naive_would_be_405_percent(
    store: FixtureStore, metrics_labels: list[fp_gate.Label]
) -> None:
    """去噪不是装饰：关掉它，42 条候选全判死，其中 17 条是假阳性。"""
    r = fp_gate.run_gate(store, metrics_labels, [], denoise=False)
    assert r.n_pred_dead == 42
    assert round(len(r.fp) / r.n_pred_dead * 100, 1) == 40.5
    assert fp_gate.NAIVE_FP_PERCENT == 40.5
    # ── 机制断言（这是让本条今天诚实变红的那一半）────────────────────────
    # 上面三条数字断言在「42 条全走 DNS 短路」的退化路径下也成立，所以必须再验
    # 一次「首跳状态码分支真的被执行到了」。判据：不许所有候选都是 dns_unresolved。
    # ── 机制断言（不许让这三个数字在退化路径下也成立）─────────────────────
    # 第 4b 步之前：42 条候选**全部**在 DNS 车道短路（dns.json 有 109 个 host 是
    # _pending_capture），reason 全为 dns_unresolved，§4.5:2463 的首跳状态码判据
    # 一次都没执行 —— 三个数字照样成立，但那个 40.5% 是凑出来的。
    # 实录真 DNS 之后：37 条走 status_404、5 条走 dns_unresolved，判据真跑了。
    # 所以这里断言「状态码分支占多数」，而不只是「不全是 DNS」。
    reasons = collections.Counter(v.get("reason") for v in r.verdicts.values())
    status_lane = sum(n for k, n in reasons.items() if str(k).startswith("status_"))
    assert status_lane > r.n_pred_dead / 2, (
        f"状态码分支只覆盖 {status_lane}/{r.n_pred_dead} 条（reason 分布 {dict(reasons)}）——"
        "多数候选在 DNS 车道短路，这个 40.5% 不是测出来的"
    )


@_GONE
def test_by_provenance_has_three_buckets(result: fp_gate.GateResult) -> None:
    """recorded / reconstructed / recovered_live 各一份同形矩阵，口径**不给折扣**。"""
    assert set(result.by_provenance) >= {"recorded", "reconstructed", "recovered_live"}
    for name, matrix in result.by_provenance.items():
        assert set(matrix) == {"n", "n_true_dead", "n_pred_dead", "fp", "fn"}
        assert matrix["fp"] == [], f"{name} 桶出现假阳性"
        assert matrix["fn"] == [], f"{name} 桶出现漏检"
    # 门禁 6：防「把 42 条全编出来让门禁自证」
    assert result.by_provenance["recorded"]["n"] >= fp_gate.GATE_MIN_RECORDED


@_GONE
def test_x_group_rules_all_fire(
    result: fp_gate.GateResult, coverage_labels: list[fp_gate.Label]
) -> None:
    """A19：X01–X14 全绿 —— 每一行都命中它自己声明的那条规则。"""
    for lb in coverage_labels:
        got = result.verdicts[lb.id]
        if lb.expect_rule:
            assert got["rule_id"] == lb.expect_rule, f"{lb.id}: {got}"
        if lb.label == "dead":
            assert got["state"] == "dead", f"{lb.id} 应判死：{got}"
        elif lb.label == "unknown":
            assert got["state"] == "unknown", f"{lb.id} 应判 UNKNOWN：{got}"
        elif lb.label == "excluded":
            assert got["state"] == "excluded", f"{lb.id} 应被排除：{got}"
        elif lb.label == "alive":
            assert got["state"] == "alive", f"{lb.id} 应判存活：{got}"


def test_needs_review_is_exactly_printify(result: fp_gate.GateResult) -> None:
    """整个 42 条里唯一进「待人工确认」的就是 printify 那条（卡点 S4）。"""
    assert result.needs_review == ["H24"]
    assert result.verdicts["H24"]["state"] == "dead"
    assert result.verdicts["H24"]["disposition"] == "needs_review"


def test_third_party_dead_targets_have_confirmations(result: fp_gate.GateResult) -> None:
    """A23：第三方 host 的 DEAD 目标 ``confirmations`` 必须非空。

    ``github.com/swellstores/swell-sdk`` 靠组织页 200；``discord.com/commercelayer``
    靠 discord.com 根路径 200。拿不到对照就必须 UNKNOWN，不许判死。
    """
    for label_id in ("H13", "H25"):
        got = result.verdicts[label_id]
        assert got["state"] == "dead"
        assert got["confirmations"], f"{label_id} 判死却没有同 host 存活对照"


def test_observation_provenance_is_reported(result: fp_gate.GateResult) -> None:
    """观测来源必须写在报告里：现在 0 条实录快照（第 4b 步未做），全是已记录观测。"""
    prov = result.observation_provenance
    assert set(prov) == {"snapshot", "declared", "host_default", "robots"}
    assert prov["declared"] > 0
    if prov["snapshot"] == 0:
        assert result.warnings, "没有实录快照时必须有 warning，不许静默"


@_GONE
def test_report_round_trips(tmp_path: Path) -> None:
    """``fp-gate-report.json`` 写得出、读得回，退出码 0（CI job 只看退出码）。"""
    out = tmp_path / "fp-gate-report.json"
    assert fp_gate.main(["--report", str(out), "--quiet"]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["gates"] == {
        "1_fp_rate": True,
        "2_n_pred_dead": True,
        "3_recall": True,
        "4_wrong_rule": True,
        "5_unused_rules": True,
        "6_n_recorded": True,
    }
    assert doc["naive_contrast"]["fp_percent"] == 40.5
    assert doc["rule_registry_dead_links"] == list(dead_links.DEAD_LINK_RULE_IDS)
    assert doc["coverage_n"] > doc["n_candidates"]
