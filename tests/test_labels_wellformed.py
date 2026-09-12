"""六个标注文件的形状与总数断言（第 5 步验收）。

这个文件只做两件事，一件都不许放松：

1. **总数与实测对齐**：42 / 16 / 18+2 / 5 / 7 / 14。数字来自六轮实测，
   不许为了让测试绿而改。
2. **A 组的 rule 归因以原型的冻结 ground truth 为准**（卡点 S1）：
   `tests/fixtures/real_cases.py` 是冻结文件，A 表每一行的 `expect_rule`
   必须与它的 `Case.expect_reason` 逐字相同。谁改了标注文件里的 rule，
   这里立刻红。

不做的事：不探网、不构造 Probe、不断言任何检查器的行为 —— 那是第 8/9/11/12/13 步的测试。
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from geo_audit.models import LinkState, Reason, Verdict

from .fixtures import real_cases as rc

DATA = Path(__file__).parent / "data"

# --------------------------------------------------------------------------- #
# 规格里的固定数字（§8.4 / §8.6 / §1 目录树 / 第 5 步验收行）
# --------------------------------------------------------------------------- #

N_DEADLINK = 42
N_DEAD = 25
N_FALSE_POSITIVE = 17
MIN_RECORDED = 12
N_A = 16
N_A_PRIME = 3
N_B_OK = 18
N_B_BLOCKED = 2
N_C = 5
N_MD = 7
N_X_BASE_IDS = 14

#: §5.3 的规则 id 注册表（RULE_REGISTRY["dead_links"]，pre 14 + post 9）。
#: 生产代码在第 12 步才写，所以这里留一份规格副本；两边都存在时下面会交叉断言。
DEAD_LINK_RULES: frozenset[str] = frozenset(
    {
        # pre（14 条）
        "url_template_placeholder",
        "reserved_example_domain",
        "non_http_scheme",
        "cloudflare_email_protection",
        "mintlify_injected_anchor",
        "fern_injected_anchor",
        "fern_console_host",
        "intellimize_endpoint",
        "framework_bind_artifact",
        "api_endpoint_in_code_context",
        "inline_display_none_anchor",
        "presigned_expiring",
        "class_hidden_anchor",
        "seed_url_not_on_site",
        # post（9 条）
        "waf_challenge",
        "hostile_400",
        "host_unprobeable",
        "third_party_no_control",
        "geo_redirect",
        "login_wall",
        "network_timeout",
        "upstream_error",
        "dns_retry_second_resolver",
    }
)

#: §8.4 的假阳性四类（honest_note 原文分类，卡点 B20）
FP_BY_RULE = {
    "reserved_example_domain": 5,
    "api_endpoint_in_code_context": 7,
    "cloudflare_email_protection": 2,
    "dns_retry_second_resolver": 2,
    "seed_url_not_on_site": 1,
}

REASON_VALUES: frozenset[str] = frozenset(Reason.__args__)  # type: ignore[attr-defined]
VERDICT_VALUES = frozenset(v.value for v in Verdict)
LINK_STATE_VALUES = frozenset(s.value for s in LinkState)


def _json(name: str) -> dict[str, Any]:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def _jsonl(name: str) -> list[dict[str, Any]]:
    lines = (DATA / name).read_text(encoding="utf-8").splitlines()
    return [json.loads(x) for x in lines if x.strip()]


@pytest.fixture(scope="module")
def soft404() -> dict[str, Any]:
    return _json("soft404_expectations.json")


@pytest.fixture(scope="module")
def llmsfull() -> dict[str, Any]:
    return _json("llmsfull_expectations.json")


@pytest.fixture(scope="module")
def index_links() -> dict[str, Any]:
    return _json("index_link_expectations.json")


@pytest.fixture(scope="module")
def md() -> dict[str, Any]:
    return _json("md_expectations.json")


@pytest.fixture(scope="module")
def rootcause() -> dict[str, Any]:
    return _json("rootcause_expectations.json")


@pytest.fixture(scope="module")
def deadlinks() -> list[dict[str, Any]]:
    return _jsonl("deadlink_labels.jsonl")


@pytest.fixture(scope="module")
def denoise_extra() -> list[dict[str, Any]]:
    return _jsonl("denoise_extra_labels.jsonl")


# --------------------------------------------------------------------------- #
# A 组：16 条 + 与冻结 ground truth 逐行对齐（卡点 S1）
# --------------------------------------------------------------------------- #


def test_a_group_is_16_positions(soft404: dict[str, Any]) -> None:
    assert len(soft404["a"]) == N_A
    assert len({e["url"] for e in soft404["a"]}) == N_A, "A 表 16 个位置必须是 16 个不同 URL"


def test_a_group_rule_histogram(soft404: dict[str, Any]) -> None:
    """15 x html_where_text_expected + 1 x notfound_copy_in_body。"""
    hist = Counter(e["expect_rule"] for e in soft404["a"])
    assert hist == {"html_where_text_expected": 15, "notfound_copy_in_body": 1}


def test_a_group_all_soft404(soft404: dict[str, Any]) -> None:
    assert {e["expect_verdict"] for e in soft404["a"]} == {Verdict.SOFT404.value}
    assert {e["expect"] for e in soft404["a"]} == {"text_file"}


@pytest.mark.parametrize("row", _json("soft404_expectations.json")["a"], ids=lambda r: r["id"])
def test_a_group_matches_frozen_ground_truth(row: dict[str, Any]) -> None:
    """A 表每一行的 expect_rule 必须与 real_cases.py 的 Case.expect_reason 逐字相同。

    real_cases.py 是冻结文件（验收标准 A4 要求与原型逐字节相同），所以它是
    仲裁者：规格 §8.3 的表与它冲突时以它为准。
    """
    group = getattr(rc, row["real_cases_group"])
    case = next(c for c in group if c.name == row["real_cases_case"])
    assert case.url == row["url"], "URL 对不上，说明 real_cases_case 指错了"
    assert case.expect_verdict == row["expect_verdict"]
    assert case.expect_reason == row["expect_rule"], (
        f"{row['id']} 的 primary rule 与冻结 ground truth 不符："
        f"real_cases={case.expect_reason} / 标注={row['expect_rule']}"
    )


def test_a_group_covers_every_frozen_soft404_case(soft404: dict[str, Any]) -> None:
    """SOFT404_CASES 的 14 条一条都不许漏；另外 2 条来自 CONTROL_ONLY_CASES。"""
    referenced = {(e["real_cases_group"], e["real_cases_case"]) for e in soft404["a"]}
    frozen = {("SOFT404_CASES", c.name) for c in rc.SOFT404_CASES}
    assert frozen <= referenced
    by_group = Counter(g for g, _ in referenced)
    assert by_group == {"SOFT404_CASES": 14, "CONTROL_ONLY_CASES": 2}


def test_a_group_secondary_reasons_are_legal(soft404: dict[str, Any]) -> None:
    for e in soft404["a"]:
        assert set(e["expect_secondary"]) <= REASON_VALUES, e["id"]
        assert e["expect_rule"] not in e["expect_secondary"], "secondary 不含 primary 自身"


def test_a_group_control_evidence_is_not_lost(soft404: dict[str, Any]) -> None:
    """minimax / moonshot 的对照证据必须落在 secondary_reasons 上（卡点 S1 的核心）。"""
    by_id = {e["id"]: e for e in soft404["a"]}
    for aid in ("A04", "A05"):
        assert "identical_to_control" in by_id[aid]["expect_secondary"]
        assert by_id[aid]["control_required"] is True


# --------------------------------------------------------------------------- #
# A' 组：3 条 + 1 条「没有对照就不许判死」
# --------------------------------------------------------------------------- #


def test_a_prime_group(soft404: dict[str, Any]) -> None:
    rows = soft404["a_prime"]
    assert len(rows) == N_A_PRIME
    for e in rows:
        assert e["expect"] == "html_page"
        assert e["expect_verdict"] == Verdict.SOFT404.value
        assert e["expect_rule"] == "identical_to_control"
        assert e["control_required"] is True


def test_a_prime_kimi_matches_frozen_reason(soft404: dict[str, Any]) -> None:
    """A'3（kimi）是唯一一条冻结 reason 就等于 identical_to_control 的。"""
    row = next(e for e in soft404["a_prime"] if e["id"] == "A'3")
    case = next(c for c in rc.CONTROL_ONLY_CASES if c.name == row["real_cases_case"])
    assert case.expect_reason == row["expect_rule"] == "identical_to_control"
    assert row["real_cases_reason_applies"] is True


def test_a_prime_minimax_moonshot_declare_the_expect_shift(soft404: dict[str, Any]) -> None:
    """A'1/A'2 与 real_cases 的 reason 不同，必须显式声明原因，不许静默偏离。"""
    for pid in ("A'1", "A'2"):
        row = next(e for e in soft404["a_prime"] if e["id"] == pid)
        assert row["real_cases_reason_applies"] is False
        assert row["real_cases_reason_note"]


def test_a_prime_control_absent_row(soft404: dict[str, Any]) -> None:
    rows = soft404["a_prime_control_absent"]
    assert len(rows) == 1
    row = rows[0]
    assert row["control"] is None
    assert row["expect_verdict_not"] == Verdict.SOFT404.value
    assert row["expect_rule_any"] is True


# --------------------------------------------------------------------------- #
# B 组：18 OK + 2 BLOCKED（= challenge 原文的 20 条反向验证真文件）
# --------------------------------------------------------------------------- #


def test_b_group_is_18_ok_plus_2_blocked(soft404: dict[str, Any]) -> None:
    rows = soft404["b"]
    assert len(rows) == N_B_OK + N_B_BLOCKED
    oks = [e for e in rows if e["expect_verdict"] == Verdict.OK.value]
    blocked = [e for e in rows if e["expect_verdict"] == Verdict.BLOCKED.value]
    assert len(oks) == N_B_OK
    assert len(blocked) == N_B_BLOCKED
    assert all(e["is_real_file"] for e in rows), "20 条全是反向验证过的真文件"
    for e in blocked:
        assert e["expect_evaluated"] is False, "被拦住的必须 evaluated is False"


def test_b_group_no_byte_assertions_outside_allowlist(soft404: dict[str, Any]) -> None:
    """§8.3：只有两处独立记录一致的才许断言字节。B 组一条都不在 allowlist 里。"""
    for e in soft404["b"]:
        assert e["expect_bytes"] is None, e["id"]


def test_b_group_frozen_reasons(soft404: dict[str, Any]) -> None:
    for e in soft404["b"]:
        if "real_cases_case" not in e:
            assert e.get("expect_rule_pending") is True, (
                f"{e['id']} 没有冻结样本又写死了 rule —— 要么标 pending，要么补 real_cases_case"
            )
            continue
        group = getattr(rc, e["real_cases_group"])
        case = next(c for c in group if c.name == e["real_cases_case"])
        assert case.url == e["url"]
        assert case.expect_reason == e["expect_rule"], e["id"]
        assert case.expect_verdict == e["expect_verdict"], e["id"]


# --------------------------------------------------------------------------- #
# C 组：5 条诚实 404（+ 1 条 500 单列）
# --------------------------------------------------------------------------- #


def test_c_group_is_5_real404(soft404: dict[str, Any]) -> None:
    rows = soft404["c"]
    assert len(rows) == N_C
    assert {e["expect_verdict"] for e in rows} == {Verdict.REAL404.value}
    assert {e["expect_rule"] for e in rows} == {"status_404"}


def test_c_unknown_is_the_500(soft404: dict[str, Any]) -> None:
    rows = soft404["c_unknown"]
    assert len(rows) == 1
    assert rows[0]["expect_verdict"] == Verdict.UNKNOWN.value
    assert rows[0]["expect_rule"] == "server_error"
    assert rows[0]["expect_evaluated"] is False


def test_every_reason_in_soft404_file_is_a_legal_reason(soft404: dict[str, Any]) -> None:
    for key in ("a", "a_prime", "b", "c", "c_unknown"):
        for e in soft404[key]:
            rule = e.get("expect_rule")
            if rule is not None:
                assert rule in REASON_VALUES, f"{e['id']}: {rule} 不在 models.Reason 里"
            assert e["expect_verdict"] in VERDICT_VALUES if "expect_verdict" in e else True


# --------------------------------------------------------------------------- #
# llms-full（F 组）
# --------------------------------------------------------------------------- #


def test_llmsfull_counted_hits_are_exactly_5(llmsfull: dict[str, Any]) -> None:
    """§4.2：按规则在 72 域上机械跑出的 counted_as_hit=True 命中恰为 5。"""
    hits = [p for p in llmsfull["pairs"] if p["counted_as_hit"]]
    assert len(hits) == 5
    assert [p["id"] for p in hits] == llmsfull["_meta"]["counted_as_hit_ids"]
    assert {p["expect_check_id"] for p in hits} == {
        "ai_path.llms_full_byte_copy",
        "ai_path.llms_full_not_fulltext",
        "ai_path.llms_full_redirect_to_index",
    }


def test_llmsfull_pairs_are_same_host_same_prefix(llmsfull: dict[str, Any]) -> None:
    """配对键 = (host, 目录)，llms.txt 与 llms-full.txt 同目录才配。"""
    for p in llmsfull["pairs"]:
        i, f = p["index_url"], p["full_url"]
        assert i.rsplit("/", 1)[0] == f.rsplit("/", 1)[0], p["id"]
        assert i.endswith("/llms.txt") and f.endswith("/llms-full.txt")


def test_llmsfull_thin_is_never_counted(llmsfull: dict[str, Any]) -> None:
    for p in llmsfull["pairs"]:
        if p["expect_check_id"] == "ai_path.llms_full_thin":
            assert p["expect_severity"] == "info"
            assert p["counted_as_hit"] is False
    resend = next(p for p in llmsfull["pairs"] if p["id"] == "B06")
    assert resend["docs_llms_full_bytes"] == 2_173_432


def test_llmsfull_pending_rows_declare_themselves(llmsfull: dict[str, Any]) -> None:
    for p in llmsfull["pairs"]:
        if p.get("expect_check_id_pending"):
            assert p["expect_check_id"] is None
            assert "待实测" in p["note"]


# --------------------------------------------------------------------------- #
# 索引内链（G 组）
# --------------------------------------------------------------------------- #


def test_index_link_cases_are_12(index_links: dict[str, Any]) -> None:
    assert len(index_links["cases"]) == 12
    assert [c["id"] for c in index_links["cases"]] == [f"C{i:02d}" for i in range(1, 13)]


def test_index_link_seven_domains_have_dead_links(index_links: dict[str, Any]) -> None:
    """§4.3：有 >=1 条死内链的域 = 7；过阈值的只有 mistral。"""
    meta = index_links["_meta"]
    assert len(meta["domains_with_dead_internal_links"]) == 7
    assert meta["over_threshold_domains"] == ["mistral.ai"]
    covered = {c["domain"] for c in index_links["cases"]} | {
        c["domain"] for c in index_links["extra"]
    }
    assert set(meta["domains_with_dead_internal_links"]) <= covered
    counted = {c["domain"] for c in index_links["cases"] if c.get("counted_as_hit")}
    assert counted == set(meta["counted_as_hit_domains"])
    # 「过阈值的只有 mistral」只在抽 10 条的口径下成立（ratio>=0.90 那一分支）；
    # 全量口径下 replicate 6 条、inngest 3 条同样过 grade() 的第二分支。两个口径都留痕。
    assert set(meta["over_threshold_domains"]) < counted


def test_index_link_mistral_is_75_of_75(index_links: dict[str, Any]) -> None:
    c01 = next(c for c in index_links["cases"] if c["id"] == "C01")
    assert (c01["n_links"], c01["n_alive"], c01["n_dead"]) == (75, 0, 75)
    assert c01["sampled"] is False, "75 <= 120 -> 全量"
    assert c01["counted_as_hit"] is True
    c02 = next(c for c in index_links["cases"] if c["id"] == "C02")
    assert c02["expect_mechanism_alive"] is True


def test_index_link_c11_triple_is_3_1_3(index_links: dict[str, Any]) -> None:
    """A13 的硬断言：双 scheme 不拆 -> (findings, root_causes, occurrences) = (3, 1, 3)。"""
    c11 = next(c for c in index_links["cases"] if c["id"] == "C11")
    assert c11["expect_triple"] == {"findings": 3, "root_causes": 1, "occurrences": 3}
    assert len(c11["dead_urls"]) == 3
    assert c11["source_lines"] == [157, 290, 296]
    for u in c11["dead_urls"]:
        assert u.count("https://") == 2, "整条一个 URL，抽取阶段不拆"


def test_index_link_counts_are_internally_consistent(index_links: dict[str, Any]) -> None:
    for c in index_links["cases"]:
        if c["kind"] != "index":
            continue
        parts = c["n_alive"] + c["n_dead"] + c["n_unknown"] + c.get("n_excluded", 0)
        assert parts <= c["n_links"], c["id"]
        if c["n_dead"] == 0:
            assert c["counted_as_hit"] is False, c["id"]


def test_index_link_unknown_never_becomes_alive(index_links: dict[str, Any]) -> None:
    """C09（pipedrive）：8 条 429 必须留在 n_unknown 里，分母只有 2。"""
    c09 = next(c for c in index_links["cases"] if c["id"] == "C09")
    assert (c09["n_alive"], c09["n_dead"], c09["n_unknown"]) == (2, 0, 8)
    assert c09["expect_status"] == "pass"


# --------------------------------------------------------------------------- #
# .md 约定
# --------------------------------------------------------------------------- #

MD_VERDICTS = frozenset(
    {
        "FULFILLED",
        "HARD_404",
        "SOFT_404_HTML",
        "SOFT_404_TEXT",
        "OPAQUE_ERROR",
        "OUT_OF_SCOPE",
        "UNDETERMINED",
    }
)
MD_SCOPES = frozenset(
    {
        "ANY_URL",
        "ANY_PAGE",
        "PREFIX",
        "DOCS_ONLY",
        "IMPLICIT_INDEX",
        "HTML_SWAP",
        "ENUMERATED",
        "UNKNOWN",
    }
)


def test_md_cases_are_7(md: dict[str, Any]) -> None:
    assert len(md["cases"]) == N_MD
    reportable = [c for c in md["cases"] if c["expect_finding"]]
    assert len(reportable) == 4
    assert [c["id"] for c in reportable] == md["_meta"]["reportable_ids"]
    assert len(md["_meta"]["out_of_scope_ids"]) == 3


def test_md_scopes_and_verdicts_are_legal(md: dict[str, Any]) -> None:
    for c in md["cases"]:
        assert c["scope"] in MD_SCOPES, c["id"]
        for s in c["samples"]:
            assert s["verdict"] in MD_VERDICTS, (c["id"], s["md_url"])


def test_md_reportable_needs_a_fulfilled_sample_and_live_twin(md: dict[str, Any]) -> None:
    """§4.4 三条佐证：范围内有 missed、有 FULFILLED 样本、HTML 双胞胎不是 404。"""
    missed = {"HARD_404", "SOFT_404_HTML", "SOFT_404_TEXT", "OPAQUE_ERROR"}
    for c in md["cases"]:
        if not c["expect_finding"]:
            continue
        in_scope = [s for s in c["samples"] if s["in_scope"]]
        bad = [s for s in in_scope if s["verdict"] in missed]
        assert bad, c["id"]
        if c["id"] != "M04":  # cloudflare 是外部样本，只记了 /network.md 一条
            assert any(s["verdict"] == "FULFILLED" for s in c["samples"]), c["id"]
        assert all(s["html_twin_status"] not in (404, 410) for s in bad), c["id"]
        assert c["expect_suppressed_by"] is None
        assert c["counted_as_hit"] is True


def test_md_out_of_scope_never_reports(md: dict[str, Any]) -> None:
    for cid in md["_meta"]["out_of_scope_ids"]:
        c = next(x for x in md["cases"] if x["id"] == cid)
        assert c["scope"] == "DOCS_ONLY"
        assert c["expect_finding"] is False
        assert any(s["verdict"] == "OUT_OF_SCOPE" for s in c["samples"]), cid


def test_md_suppressed_cases_carry_a_reason(md: dict[str, Any]) -> None:
    by_id = {c["id"]: c for c in md["suppressed_cases"]}
    assert by_id["MS01"]["expect_suppressed_by"] == "html_twin_also_404"
    assert by_id["MS02"]["expect_suppressed_by"] == "scope_unknown"
    for c in md["suppressed_cases"]:
        assert c["expect_finding"] is False


# --------------------------------------------------------------------------- #
# 根因（G 组）
# --------------------------------------------------------------------------- #


def test_rootcause_template_bug_totals(rootcause: dict[str, Any]) -> None:
    """§5.4：37 条链接 -> 7 个根因（saleor 占 2）。不是 38，也不是作废的 44。"""
    fam = rootcause["template_bug_families"]
    assert sum(f["links"] for f in fam) == 37
    assert sum(f["root_causes"] for f in fam) == 7
    assert {f["domain"] for f in fam} == {
        "tdengine.com",
        "bytebase.com",
        "copper.com",
        "canvasmedical.com",
        "brevo.com",
        "saleor.io",
    }
    assert next(f for f in fam if f["domain"] == "saleor.io")["root_causes"] == 2


def test_rootcause_canvasmedical_full_partition(rootcause: dict[str, Any]) -> None:
    cm = next(d for d in rootcause["per_domain"] if d["domain"] == "canvasmedical.com")
    assert cm["dead_links"] == 9
    assert cm["root_causes"] == 4
    assert sorted(cm["instance_counts_sorted"]) == [2, 2, 2, 3]
    assert sum(p["links"] for p in cm["partition"]) == 9
    assert {p["defect"] for p in cm["partition"]} == {
        "relative_path_prefixed",
        "route_missing",
        "deleted_help_article",
        "deleted_third_party_repo",
    }


def test_rootcause_66_is_the_pre_denoise_sum(rootcause: dict[str, Any]) -> None:
    d = rootcause["domains_66"]
    assert sum(d["by_domain"].values()) == d["total"] == 66
    assert len(d["by_domain"]) == 7


def test_rootcause_saleor_occurrences_sum_to_10(rootcause: dict[str, Any]) -> None:
    s = next(d for d in rootcause["per_domain"] if d["domain"] == "saleor.io")
    assert sum(s["occurrences"].values()) == 10
    assert s["unique_paths"] == 2 == s["root_causes"]


def test_rootcause_pending_rows_are_flagged(rootcause: dict[str, Any]) -> None:
    for d in rootcause["per_domain"]:
        if d["pending"]:
            assert "待实测" in d["note"], d["domain"]
    swell = next(d for d in rootcause["per_domain"] if d["domain"] == "swell.is")
    assert swell["xfail"] is True


def test_rootcause_defects_all_have_a_fingerprint(rootcause: dict[str, Any]) -> None:
    known = {f["defect"] for f in rootcause["defect_fingerprints"]}
    assert len(known) == 15
    for f in rootcause["template_bug_families"]:
        assert f["defect"] in known
    for d in rootcause["per_domain"]:
        assert set(d.get("defects", [])) <= known, d["domain"]


def test_rootcause_tool_vs_challenge_differs_by_exactly_printify(
    rootcause: dict[str, Any],
) -> None:
    rows = {r["口径"]: r for r in rootcause["tool_vs_challenge"]["rows"]}
    tool = rows["本工具实际"]
    challenge = rows["challenge（只算普通访客点得到的内容链接）"]
    assert tool["dead_links"] - challenge["dead_links"] == 1
    assert tool["domains"] - challenge["domains"] == 1


# --------------------------------------------------------------------------- #
# 42 条死链标注（METRICS_SET）
# --------------------------------------------------------------------------- #


def test_deadlink_labels_total_is_42(deadlinks: list[dict[str, Any]]) -> None:
    assert len(deadlinks) == N_DEADLINK
    assert len({r["id"] for r in deadlinks}) == N_DEADLINK


def test_deadlink_labels_composition(deadlinks: list[dict[str, Any]]) -> None:
    """25 真死链 + 17 假阳性 = 42；17/42 = 40.5%。"""
    labels = Counter(r["label"] for r in deadlinks)
    assert labels == {"dead": N_DEAD, "false_positive": N_FALSE_POSITIVE}
    assert round(N_FALSE_POSITIVE / N_DEADLINK * 100, 1) == 40.5


def test_deadlink_false_positive_four_classes(deadlinks: list[dict[str, Any]]) -> None:
    """§8.4 卡点 B20：四类的条数是 5 / 7 / 2 / (2+1)，v1 那版分错了。"""
    by_rule = Counter(r["expect_rule"] for r in deadlinks if r["label"] == "false_positive")
    assert dict(by_rule) == FP_BY_RULE
    assert sum(FP_BY_RULE.values()) == N_FALSE_POSITIVE


def test_deadlink_dead_rows_have_no_denoise_rule(deadlinks: list[dict[str, Any]]) -> None:
    """真死链不许挂 EXCLUDED 类规则；唯一例外是 printify 的 needs_review。"""
    for r in deadlinks:
        if r["label"] != "dead":
            continue
        if r["expect_rule"] is None:
            continue
        assert r["expect_rule"] == "class_hidden_anchor", r["id"]
        assert r["needs_review"] is True, r["id"]


def test_deadlink_printify_is_dead_plus_needs_review(deadlinks: list[dict[str, Any]]) -> None:
    """卡点 S4：n_pred_dead==25 / n_true_dead==25 / fp_rate==0 / recall==1 同时成立的那条。"""
    rows = [r for r in deadlinks if r["needs_review"]]
    assert len(rows) == 1
    row = rows[0]
    assert row["label"] == "dead"
    assert row["expect_rule"] == "class_hidden_anchor"
    assert "IRS-Form-8937" in row["url"]


def test_deadlink_rules_are_registered(deadlinks: list[dict[str, Any]]) -> None:
    used = {r["expect_rule"] for r in deadlinks if r["expect_rule"]}
    assert used <= DEAD_LINK_RULES, sorted(used - DEAD_LINK_RULES)


def test_deadlink_provenance_and_recorded_floor(deadlinks: list[dict[str, Any]]) -> None:
    """门禁第 6 条：n_recorded >= 12，防「把 42 条全编出来让门禁自证」。"""
    prov = Counter(r["provenance"] for r in deadlinks)
    assert set(prov) <= {"recorded", "reconstructed", "recovered_live"}
    n_recorded = prov["recorded"] + prov["recovered_live"]
    assert n_recorded >= MIN_RECORDED, prov
    for r in deadlinks:
        assert r["derived_from"], r["id"]
        if r["provenance"] == "reconstructed":
            assert r.get("synthetic") is True, r["id"]


def test_deadlink_per_domain_counts(deadlinks: list[dict[str, Any]]) -> None:
    """§8.4 的 25 条构成：saleor 10 / swell 12 / shopify 1 / printify 1 / commercelayer 1。"""
    dead = Counter(r["domain"] for r in deadlinks if r["label"] == "dead")
    assert dict(dead) == {
        "saleor.io": 10,
        "swell.is": 12,
        "shopify.dev": 1,
        "printify.com": 1,
        "commercelayer.io": 1,
    }


def test_deadlink_saleor_collapses_to_two_norm_urls(deadlinks: list[dict[str, Any]]) -> None:
    """10 个链接实例 -> 2 个唯一路径（第一级折叠）。"""
    saleor = [r for r in deadlinks if r["domain"] == "saleor.io"]
    norms = Counter(r["norm_url"] for r in saleor)
    assert len(norms) == 2
    assert sorted(norms.values()) == [3, 7]
    for r in saleor:
        assert "?" not in r["norm_url"], "norm_url 必须丢掉 cta / cta_page 这类跟踪 query"
        assert r["norm_url"] in r["url"].split("?")[0]


# --------------------------------------------------------------------------- #
# X 组（COVERAGE_SET 的增量）
# --------------------------------------------------------------------------- #


def test_denoise_extra_has_14_base_ids(denoise_extra: list[dict[str, Any]]) -> None:
    """X01–X14 是 14 个 fixture 用例；X05 拆成四条规则、X12b/X13a 是子变体。"""
    base = {r["base_id"] for r in denoise_extra}
    assert base == {f"X{i:02d}" for i in range(1, 15)}
    assert len(base) == N_X_BASE_IDS
    assert len({r["id"] for r in denoise_extra}) == len(denoise_extra)
    for r in denoise_extra:
        assert r["id"].startswith(r["base_id"]), r["id"]


def test_denoise_extra_labels_and_rules_are_legal(denoise_extra: list[dict[str, Any]]) -> None:
    for r in denoise_extra:
        assert r["label"] in LINK_STATE_VALUES, r["id"]
        if r["expect_rule"] is not None:
            assert r["expect_rule"] in DEAD_LINK_RULES, r["id"]
        if r.get("expect_reason") is not None:
            assert r["expect_reason"] in REASON_VALUES, r["id"]
        assert r["derived_from"], r["id"]


def test_denoise_extra_excluded_rows_all_carry_a_rule(
    denoise_extra: list[dict[str, Any]],
) -> None:
    """EXCLUDED 是「被去噪规则丢掉」的意思，所以必须指名是哪条规则。"""
    for r in denoise_extra:
        if r["label"] == LinkState.EXCLUDED.value:
            assert r["expect_rule"], r["id"]


def test_coverage_set_leaves_exactly_one_rule_without_a_fixture(
    deadlinks: list[dict[str, Any]], denoise_extra: list[dict[str, Any]]
) -> None:
    """A16 要求 COVERAGE_SET 上 unused_rules == []，但规格自己没给全 fixture。

    实测锚点齐全的 22 条规则都有 fixture；只有 `framework_bind_artifact`
    在 §5.3 里没有任何实测出处（「防 SSR 把模板字符串原样落进 href」是设计意图，
    不是观测），所以两个集合都覆盖不到它。**这个缺口是明写出来的，不是忘了。**
    补齐它需要一条真实的 `${...}` href 样本；拿到之前 A16 的 unused_rules == []
    不可能成立。
    """
    covered = {r["expect_rule"] for r in deadlinks if r["expect_rule"]}
    covered |= {r["expect_rule"] for r in denoise_extra if r["expect_rule"]}
    assert DEAD_LINK_RULES - covered == {"framework_bind_artifact"}


def test_denoise_extra_kimi_console_invoice_is_dead_with_siblings(
    denoise_extra: list[dict[str, Any]],
) -> None:
    """登录墙不许一刀切：兄弟路径全 200 -> 判 DEAD。"""
    x08 = next(r for r in denoise_extra if r["id"] == "X08")
    assert x08["label"] == LinkState.DEAD.value
    assert len(x08["sibling_controls"]) >= 3
    assert all(s["expect_status"] == 200 for s in x08["sibling_controls"])


def test_denoise_extra_unkey_chain_is_308_308_404(denoise_extra: list[dict[str, Any]]) -> None:
    x07 = next(r for r in denoise_extra if r["id"] == "X07")
    assert [h[0] for h in x07["redirect_chain"]] == [308, 308]
    assert x07["final_status"] == 404
    assert x07["label"] == LinkState.DEAD.value
    assert x07["naive_would_say"] == "alive"


def test_denoise_extra_inline_display_none_is_synthetic(
    denoise_extra: list[dict[str, Any]],
) -> None:
    """卡点 S4：这条规则在 42 条里一次都不触发，fixture 只能是合成的 X13。"""
    x13 = next(r for r in denoise_extra if r["id"] == "X13")
    assert x13["expect_rule"] == "inline_display_none_anchor"
    assert x13["synthetic"] is True
    assert 'style="display:none"' in x13["anchor_html"]
    assert x13["expect_rule"] not in {r["expect_rule"] for r in _jsonl("deadlink_labels.jsonl")}


# --------------------------------------------------------------------------- #
# measured_* 覆盖：标注说的与我们今天量到的不一样时，怎么写才不算「改断言让它绿」
# --------------------------------------------------------------------------- #

#: 允许带 measured_* 覆盖的行，以及**为什么**。钉死在这里，新增一条必须动这个
#: 常量 —— 也就是必须被 review 看见。这是 measured_* 唯一的闸：没有它，
#: 「量到什么就写什么」会退化成「红了就写上」。
MEASURED_OVERRIDES: dict[str, str] = {
    # 站点对「要 markdown」的请求 rewrite 到 /api/markdown/<path>，那里没有
    # llms.txt。标注里的 200 50,680 B 是用 */* 量的，两把尺子都对，位置落
    # UNKNOWN/accept_negotiated（详见 NOTES-terminal.md 2026-09-12 ⑧）。
    "B17": "accept_negotiated",
    # 该 host 的对照探针被 Cloudflare 挡住（robots.txt 与随机路径一律 403，
    # 隔离复验四次）。目标本身仍是 200 真文件 —— 但没有对照就判不了真伪，
    # 按 §6.4 R1 落 UNKNOWN。§8.1 的 unreachable 分支。
    "B13": "control_unavailable",
}


def test_measured_overrides_are_pinned(soft404: dict[str, Any]) -> None:
    """带 measured_* 的行必须**正好**是 MEASURED_OVERRIDES 里那几条。

    多一条少一条都红：多了说明有人拿 measured_* 抹平了一个新的分歧而没让人看见，
    少了说明某个分歧自己消失了（那是好事，但要回来把这条记录删掉）。
    """
    rows = [r for group in ("b", "c", "c_unknown") for r in soft404[group]]
    have = {r["id"]: r.get("measured_rule") for r in rows if r.get("measured_verdict")}
    assert have == MEASURED_OVERRIDES, (
        f"measured_* 覆盖的集合变了：{have} != {MEASURED_OVERRIDES}。"
        "新增一条要在这里写明理由，删一条要说明分歧为什么没了。"
    )


def test_every_measured_override_explains_itself(soft404: dict[str, Any]) -> None:
    """每条覆盖都要有 measured_note，且要说人话（不是「见上」这种）。"""
    rows = [r for group in ("b", "c", "c_unknown") for r in soft404[group]]
    for row in rows:
        if not row.get("measured_verdict"):
            continue
        note = row.get("measured_note") or ""
        assert len(note) >= 40, f"{row['id']} 的 measured_note 太短，说不清为什么：{note!r}"
        assert row["expect_verdict"] != row["measured_verdict"], (
            f"{row['id']} 的 measured_verdict 与 expect_verdict 相同，这条覆盖是多余的"
        )

