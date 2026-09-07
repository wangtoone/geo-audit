"""第 15c 步自验：schema 生成器 + JSON 输出（§8.5，验收 A44）。

守三件事：

1. **`schema/report-1.schema.json` 是生成物，不是手写物。**
   `scripts/gen_schema.py --check` 必须退出 0；改了 dataclass 忘了重新生成，
   这里就红（`test_check_mode_reports_drift` 反向验了「不一致真的会红」）。
2. **产出与 §8.5 骨架逐条对上** —— 20 项顶层 `required` 的顺序、五个 `$defs`
   枚举的取值、三条硬约束（`llm_calls` const 0 / `finding_id` 有 pattern /
   `severity_signals` 四键 required），外加 `SiteMap` 的四个 tier/预算字段。
3. **JSON 出得去、回得来**（`--from` 是 A44 的一半）：`write_json` ->
   `load_report` 往返相等，`schema_version` 不符抛 `SchemaMismatchError`（CLI 退 4），
   `strip_volatile` 把 9 个易变字段剔干净（L 组逐字节比对的前提）。

期望值全部来自 §8.5 原文与 `geo_audit.models` 的常量，**没有一处是本文件编的**：
`schema_version` 比的是 `models.SCHEMA_VERSION`，易变字段比的是
`models.VOLATILE_JSON_FIELDS`，`finding_id` 的 pattern 拿 `make_finding_id` 的
真实产出去匹配。
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, get_args

import pytest

from geo_audit import models
from geo_audit.models import (
    SCHEMA_VERSION,
    TOOL_VERSION,
    VOLATILE_JSON_FIELDS,
    ApexWwwResult,
    Classification,
    Evidence,
    Expect,
    Finding,
    HttpResponse,
    NaiveContrast,
    PositionClass,
    Probe,
    Severity,
    Stage,
    Status,
    Verdict,
    make_finding_id,
)
from geo_audit.report import json_out
from geo_audit.report.json_out import (
    Counts,
    Coverage,
    CoverageGap,
    Exclusion,
    Fragility,
    Position,
    Report,
    SchemaMismatchError,
    load_report,
    report_from_json,
    report_to_json,
    strip_volatile,
    write_json,
)
from geo_audit.rootcause import RootCause

REPO_ROOT = Path(__file__).resolve().parents[1]
GEN_SCHEMA_PY = REPO_ROOT / "scripts" / "gen_schema.py"

#: §2.10 的 20 个无默认值字段，顺序与 §8.5:4238-4243 的骨架逐字一致。
SPEC_TOP_REQUIRED = [
    "schema_version",
    "tool_version",
    "denoise_ruleset_version",
    "domain",
    "scanned_at",
    "duration_s",
    "contact",
    "user_agent",
    "headline",
    "verdict_kind",
    "positions",
    "findings",
    "root_causes",
    "naive_table",
    "fragilities",
    "coverage_gaps",
    "excluded",
    "apex_www",
    "coverage",
    "counts",
]

#: §8.5:4256-4260 的五个 $defs 枚举，逐字。
SPEC_DEFS_ENUMS = {
    "Status": ["pass", "fail", "unknown", "not_applicable"],
    "Severity": ["critical", "high", "medium", "low", "info"],
    "Stage": ["discovery", "index_file", "fulltext", "index_links", "md_channel", "human_path"],
    "PositionClass": ["sales_path", "doc_entry", "ai_channel", "nav", "body", "footer_social"],
    "FindingKind": ["soft_404", "llms_full_fake", "index_link_dead", "md_unfulfilled", "dead_link"],
}

#: §3.7 / models.SiteMap 的注释：这四个字段从子类搬进 SiteMap，就是为了让
#: schema 看得见它们。
SPEC_SITEMAP_BUDGET_FIELDS = [
    "tiers_run",
    "requests_spent",
    "budget_exhausted",
    "skipped_by_budget",
]


# --------------------------------------------------------------------------- #
# 把 scripts/gen_schema.py 当模块加载（scripts/ 不是包，也不该为了测试变成包）
# --------------------------------------------------------------------------- #


def _load_gen_schema() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_gen_schema_under_test", GEN_SCHEMA_PY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen() -> ModuleType:
    return _load_gen_schema()


@pytest.fixture(scope="module")
def schema(gen: ModuleType) -> dict[str, Any]:
    built: dict[str, Any] = gen.build_schema()
    return built


@pytest.fixture(scope="module")
def on_disk() -> dict[str, Any]:
    text = (REPO_ROOT / "schema" / "report-1.schema.json").read_text(encoding="utf-8")
    loaded: dict[str, Any] = json.loads(text)
    return loaded


# --------------------------------------------------------------------------- #
# 一份最小但字段齐全的报告 —— 往返与 jsonschema 校验都用它
# --------------------------------------------------------------------------- #


def _evidence(url: str) -> Evidence:
    return Evidence(
        url=url,
        http_status=200,
        content_type="text/plain",
        bytes_len=8217,
        curl_repro=f"curl -sSIL -A 'geo-audit/{TOOL_VERSION}' {url}",
        fetched_at="2026-09-07T00:00:00Z",
    )


def _finding() -> Finding:
    target = "https://docs.example.com/llms.txt"
    return Finding(
        finding_id=make_finding_id("ai_path.soft404", target, "https://example.com/"),
        kind="soft_404",
        check_id="ai_path.soft404",
        title="llms.txt 位置返回 200，但内容是站点兜底页",
        severity=Severity.HIGH,
        position_class=PositionClass.AI_CHANNEL,
        stage=Stage.INDEX_FILE,
        target=_evidence(target),
        control=_evidence("https://docs.example.com/geo-audit-probe-xyz123"),
        occurrences=2,
        occurrence_pages=("https://example.com/",),
        detail={"bytes": 384052, "same_as_control": True, "ratio": 1.0, "note": "同一份外壳"},
        severity_signals={
            "page_role": "docs_entry",
            "anchor": "llms.txt",
            "anchor_class": "ai_channel",
            "region": "prominent",
        },
        exposure_pages=("https://example.com/",),
        naive=NaiveContrast(
            probe_url=target,
            in_naive_probe_set=True,
            naive_method="GET <url>，跟随跳转，只看最终状态码",
            naive_conclusion="已采纳（200）",
            actual_conclusion="软 404：与随机路径同为 384,052 字节、同一份外壳",
            diverges=True,
            direction="false_negative",
            extra_requests=1,
        ),
    )


def _apex_www() -> ApexWwwResult:
    """带一个真 bytes body —— base64 往返必须被真的走一遍。"""

    def probe(url: str, body: bytes, status: int) -> Probe:
        return Probe(
            url=url,
            expect=Expect.HTML_PAGE,
            response=HttpResponse(
                url=url,
                final_url=url,
                status=status,
                headers={"content-type": "text/plain"},
                body=body,
                fetched_at=0.0,
            ),
            classification=Classification(
                verdict=Verdict.OK if status == 200 else Verdict.SOFT404,
                reason="ok" if status == 200 else "platform_deployment_missing",
            ),
        )

    return ApexWwwResult(
        apex_host="example.com",
        www_host="www.example.com",
        apex=probe("https://example.com/", b"DEPLOYMENT_NOT_FOUND\n\xf0\x9f\x92\xa1", 200),
        www=probe("https://www.example.com/", b"<!doctype html><title>ok</title>", 200),
        outcome="apex_dead",
    )


@pytest.fixture
def report() -> Report:
    finding = _finding()
    return Report(
        schema_version=SCHEMA_VERSION,
        tool_version=TOOL_VERSION,
        denoise_ruleset_version=models.DENOISE_RULESET_VERSION,
        domain="example.com",
        scanned_at="2026-09-07T00:00:00Z",
        duration_s=12.5,
        contact="ci@geo-audit.invalid",
        user_agent=(
            f"geo-audit/{TOOL_VERSION} (+https://example.com; contact: ci@geo-audit.invalid)"
        ),
        headline="6 个位置里 1 个不通",
        verdict_kind="has_fail",
        positions=(
            Position(
                position_id="index_file:docs.example.com+/llms.txt",
                stage=Stage.INDEX_FILE,
                label="② llms.txt 是真文件还是软 404",
                probe_url="https://docs.example.com/llms.txt",
                status=Status.FAIL,
                detail="软 404：与随机路径同一份外壳",
                kind="probe",
                evidence=_evidence("https://docs.example.com/llms.txt"),
                finding_ids=(finding.finding_id,),
            ),
            Position(
                position_id="md_channel:md",
                stage=Stage.MD_CHANNEL,
                label="⑤ 「任意页面加 .md」兑现了吗",
                probe_url="https://docs.example.com/guide.md",
                status=Status.NOT_APPLICABLE,
                detail="站点没有声明 .md 约定",
                kind="aggregate",
                aggregate_of=3,
                unknown_reason=None,
                unknown_remedy=None,
            ),
        ),
        findings=(finding,),
        root_causes=(
            RootCause(
                root_cause_id="RC-1",
                summary="文档站的兜底页对不存在的 .txt 也返回 200",
                fix_once="改 1 处 → 修 2 条：让 /llms.txt 缺失时返回 404",
                finding_ids=(finding.finding_id,),
                max_severity=Severity.HIGH,
                instance_count=2,
                unique_target_count=1,
                defect="soft404_catchall",
            ),
        ),
        naive_table=(finding.naive,) if finding.naive is not None else (),
        fragilities=(
            Fragility(
                fragility_id="F1",
                title="llms.txt 与文档站同一份兜底页",
                metric="1 个位置",
                why="兜底页 200 会让 AI 把外壳当正文收录",
                precedent="saleor.io 的 /cloud/* 实测同壳",
                watch_command="geo-audit example.com --contact you@example.com --fail-on high",
            ),
        ),
        coverage_gaps=(
            CoverageGap(
                where="https://app.example.com/",
                reason="needs_js",
                detail="服务端 HTML 正文不足 200 字符",
                remedy="用带渲染器的工具复核这一页",
            ),
        ),
        excluded=(
            Exclusion(
                url="https://example.com/cdn-cgi/l/email-protection",
                rule_id="cloudflare_email_protection",
                rule_desc="Cloudflare 邮箱保护端点，对爬虫恒 404，不是死链",
                found_on="https://example.com/contact",
            ),
        ),
        apex_www=_apex_www(),
        coverage=Coverage(
            checked=("ai_path", "dead_links"),
            not_checked=("js_rendering",),
            positions_total=2,
            links_extracted=41,
            links_excluded=9,
            links_verified=30,
            pages_fetched=6,
            requests_made=48,
            budget_cap=200,
        ),
        counts=Counts(
            positions=2,
            positions_pass=0,
            positions_fail=1,
            positions_unknown=0,
            positions_na=1,
            findings=1,
            findings_counted=1,
            occurrences=2,
            root_causes=1,
            by_severity={"high": 1},
            naive_divergences=1,
            naive_dead_count=0,
            audited_dead_instances=2,
        ),
    )


# --------------------------------------------------------------------------- #
# 1. schema 是生成物
# --------------------------------------------------------------------------- #


def test_check_mode_is_green(gen: ModuleType) -> None:
    """A44 的第一条：磁盘上的 schema 与当前 dataclass 一致。

    红了不要手改 JSON —— 跑 `python scripts/gen_schema.py` 重新生成，
    然后把 schema 的 diff 当**对外契约变更**来 review。
    """
    assert gen.main(["--check"]) == 0


def test_generated_bytes_equal_disk(gen: ModuleType, schema: dict[str, Any]) -> None:
    disk = (REPO_ROOT / "schema" / "report-1.schema.json").read_text(encoding="utf-8")
    assert gen.render(schema) == disk


def test_check_mode_reports_drift(
    gen: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """反向验：不一致时 `--check` 必须退非 0（否则第一条断言毫无意义）。"""
    target = tmp_path / "report-1.schema.json"
    monkeypatch.setattr(gen, "SCHEMA_PATH", target)

    assert gen.main(["--check"]) == 1  # 文件都还没有

    assert gen.main([]) == 0  # 生成一次
    assert gen.main(["--check"]) == 0  # 现在一致

    drifted = json.loads(target.read_text(encoding="utf-8"))
    drifted["$defs"]["Counts"]["properties"]["llm_calls"] = {"type": "integer"}
    target.write_text(json.dumps(drifted, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    assert gen.main(["--check"]) == 1


def test_bad_argument_is_usage_error(gen: ModuleType) -> None:
    assert gen.main(["--rewrite-everything"]) == 2


def test_skeleton_verifier_finds_nothing(gen: ModuleType, schema: dict[str, Any]) -> None:
    """`--check` 只保证「文件 == 代码」；这一条保证「代码 == §8.5 骨架」。"""
    assert gen.verify_skeleton(schema) == []


def test_skeleton_verifier_actually_bites(gen: ModuleType, schema: dict[str, Any]) -> None:
    broken = json.loads(json.dumps(schema))
    broken["required"] = list(reversed(broken["required"]))
    assert gen.verify_skeleton(broken) != []


# --------------------------------------------------------------------------- #
# 2. 产出与 §8.5 骨架逐条对上
# --------------------------------------------------------------------------- #


def test_top_level_shape(on_disk: dict[str, Any]) -> None:
    assert on_disk["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert on_disk["$id"] == "https://github.com/OWNER/geo-audit/schema/report-1.schema.json"
    assert on_disk["title"] == "geo-audit report v1"
    assert on_disk["type"] == "object"
    assert on_disk["additionalProperties"] is False
    #: 顺序也要对：§8.5 的骨架给的是有序列表，而它同时是 §2.10 的字段顺序。
    assert on_disk["required"] == SPEC_TOP_REQUIRED


def test_schema_version_is_taken_from_models(on_disk: dict[str, Any]) -> None:
    """硬约束 2：`SCHEMA_VERSION` 从 models.py 取，不许在生成器里硬编码。"""
    assert on_disk["properties"]["schema_version"] == {"const": SCHEMA_VERSION}
    assert SCHEMA_VERSION == "geo-audit/report/1"
    source = GEN_SCHEMA_PY.read_text(encoding="utf-8")
    assert SCHEMA_VERSION not in source, "生成器里出现了 schema_version 的字面量"
    assert "from geo_audit.models import SCHEMA_VERSION" in source


def test_defs_enums(on_disk: dict[str, Any]) -> None:
    for name, values in SPEC_DEFS_ENUMS.items():
        assert on_disk["$defs"][name] == {"enum": values}, name


def test_verdict_kind_and_kind_enums(on_disk: dict[str, Any]) -> None:
    assert on_disk["properties"]["verdict_kind"] == {
        "enum": ["has_fail", "zero_with_unknown", "zero_clean", "no_ai_channel", "unusable"]
    }
    assert on_disk["$defs"]["Position"]["properties"]["kind"] == {"enum": ["probe", "aggregate"]}
    assert on_disk["$defs"]["Finding"]["properties"]["confidence"] == {
        "enum": ["confirmed", "needs_review"]
    }


def test_position_block(on_disk: dict[str, Any]) -> None:
    position = on_disk["$defs"]["Position"]
    assert position["additionalProperties"] is False
    assert position["required"] == [
        "position_id",
        "stage",
        "label",
        "probe_url",
        "status",
        "detail",
        "kind",
    ]
    props = position["properties"]
    assert props["aggregate_of"] == {"type": "integer", "minimum": 1}
    assert props["unknown_reason"] == {"type": ["string", "null"]}
    assert props["unknown_remedy"] == {"type": ["string", "null"]}
    assert props["evidence"] == {"anyOf": [{"$ref": "#/$defs/Evidence"}, {"type": "null"}]}
    assert props["finding_ids"] == {"type": "array", "items": {"type": "string"}}


def test_finding_block(on_disk: dict[str, Any]) -> None:
    finding = on_disk["$defs"]["Finding"]
    assert finding["additionalProperties"] is False
    assert finding["required"] == [
        "finding_id",
        "kind",
        "check_id",
        "title",
        "severity",
        "position_class",
        "stage",
        "target",
    ]
    props = finding["properties"]
    assert props["kind"] == {"$ref": "#/$defs/FindingKind"}
    assert props["severity"] == {"$ref": "#/$defs/Severity"}
    assert props["position_class"] == {"$ref": "#/$defs/PositionClass"}
    assert props["occurrences"] == {"type": "integer", "minimum": 1}
    assert props["counted_as_hit"] == {"type": "boolean"}
    assert props["detail"] == {"type": "object"}
    assert props["exposure_pages"] == {"type": "array", "items": {"type": "string"}}
    assert props["target"] == {"$ref": "#/$defs/Evidence"}


def test_counts_block(on_disk: dict[str, Any]) -> None:
    counts = on_disk["$defs"]["Counts"]
    assert counts["additionalProperties"] is False
    assert counts["required"] == [
        "positions",
        "positions_pass",
        "positions_fail",
        "positions_unknown",
        "positions_na",
        "findings",
        "findings_counted",
        "occurrences",
        "root_causes",
        "by_severity",
        "naive_divergences",
    ]


def test_three_hard_constraints(on_disk: dict[str, Any]) -> None:
    """§8.5:4301-4303 点名的三条，check-jsonschema 之外由测试补。"""
    assert on_disk["$defs"]["Counts"]["properties"]["llm_calls"] == {"const": 0}
    assert on_disk["$defs"]["Finding"]["properties"]["finding_id"] == {
        "type": "string",
        "pattern": r"^GA-[0-9A-F]{10}$",
    }
    assert on_disk["$defs"]["Finding"]["properties"]["severity_signals"] == {
        "type": "object",
        "required": ["page_role", "anchor", "anchor_class", "region"],
    }


def test_finding_id_pattern_matches_real_ids(on_disk: dict[str, Any]) -> None:
    """pattern 不是抄来好看的：拿 `make_finding_id` 的真实产出匹配一遍。"""
    pattern = on_disk["$defs"]["Finding"]["properties"]["finding_id"]["pattern"]
    for target in ("https://a.example.com/x", "https://saleor.io/cloud/", ""):
        assert re.match(pattern, make_finding_id("dead_links.hard_404", target, None))


def test_sitemap_budget_fields_are_in_the_contract(on_disk: dict[str, Any]) -> None:
    """硬约束 3：四个 tier/预算字段从子类搬进 `models.SiteMap` 就是为了这个。

    §2.10 的 `Report` 并不引用 `SiteMap`，所以生成器把它当第二个 $defs 根显式
    带进契约（`EXTRA_DEFS_ROOTS`）—— 见交付说明 deviations。
    """
    props = on_disk["$defs"]["SiteMap"]["properties"]
    for name in SPEC_SITEMAP_BUDGET_FIELDS:
        assert name in props, name
    assert props["tiers_run"] == {"type": "array", "items": {"type": "string"}}
    assert props["requests_spent"] == {"type": "integer"}
    assert props["budget_exhausted"] == {"type": "boolean"}
    assert props["skipped_by_budget"] == {"type": "array", "items": {"type": "string"}}


def test_bytes_body_is_declared_base64(on_disk: dict[str, Any]) -> None:
    """`HttpResponse.body` 是 bytes（§8.5 的规则表没这一条，见交付说明）。"""
    assert on_disk["$defs"]["HttpResponse"]["properties"]["body"] == {
        "type": "string",
        "contentEncoding": json_out.BYTES_ENCODING,
    }


# --------------------------------------------------------------------------- #
# 3. 生成器的「搬家后零改动」
# --------------------------------------------------------------------------- #


def test_placeholder_classes_resolve_from_models_once_moved(gen: ModuleType) -> None:
    """占位区那 7 个类搬进 models.py 之后，生成器不用改一行。

    实现是「先在 geo_audit.models 里按名字找，找不到才回落 json_out」，所以
    这条断言在搬家前后都成立：models 里有了就必须用 models 那个。
    """
    seven = {"Exclusion", "Position", "CoverageGap", "Fragility", "Coverage", "Counts", "Report"}

    # 搬家**已经完成**（A6：这 7 个类现在只在 models.py 里定义一次）。
    # 原断言写的是 `set(gen.dataclasses_in(json_out)) == seven` —— 那把「占位还在
    # json_out 里」当成了不变量，于是搬完必然红。而这条测试的标题与 docstring 说的
    # 是「生成器不用改一行」，那才是真正的不变量。所以断言改成两条：
    #   1. 七个类在 models.py 里全都解析得到（搬家的终态）
    #   2. 生成器对它们的解析结果就是 models 里那个对象（不是某份残留占位）
    # 搬家前这条同样成立（那时 models 里没有，回落 json_out），
    # 所以它在搬家前后都是绿的 —— 这才是原 docstring 承诺的性质。
    for name in sorted(seven):
        resolved = gen.resolve_class(name)
        assert resolved is getattr(models, name), (
            f"{name} 没解析到 models.py 那份 —— A6 要求它只在 models 里定义一次"
        )

    placeholders = gen.dataclasses_in(json_out)
    for name in placeholders:
        resolved = gen.resolve_class(name)
        if hasattr(models, name):
            assert resolved is getattr(models, name), f"{name} 已在 models.py，必须用那一份"
        else:
            assert resolved is placeholders[name]
    assert gen.SOURCE_MODULES[0] == "geo_audit.models"


def test_models_dataclasses_are_traversable(gen: ModuleType) -> None:
    """生成器是「遍历模块里的 dataclass」，不是硬编码类列表。"""
    found = gen.dataclasses_in(models)
    assert {"SiteMap", "Finding", "Evidence", "HttpResponse"} <= set(found)
    assert gen.resolve_class("SiteMap") is models.SiteMap


def test_inline_literals_stay_inline_even_if_someone_names_them(
    gen: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§8.5 骨架里 `verdict_kind` / `Position.kind` / `confidence` 是**内联** enum。

    第 16 步的 pipeline.py 占位里已经出现了 `VerdictKind = Literal[...]` 这样的
    模块级别名。别名一旦跟着 `Report` 搬进 models.py，别名发现逻辑就会把
    `verdict_kind` 变成 `$ref` —— 对外契约的形状不能取决于「有没有人给这个
    Literal 起过名字」，所以 `INLINE_LITERAL_FIELDS` 把这三处钉死。
    """
    verdict_kind_args = (
        "has_fail",
        "zero_with_unknown",
        "zero_clean",
        "no_ai_channel",
        "unusable",
    )
    # 真表 + 一个新起的名字：FindingKind / Reason 的 $ref 照旧，只多出一个别名。
    aliases = {**gen.literal_aliases(), verdict_kind_args: "VerdictKind"}
    monkeypatch.setattr(gen, "literal_aliases", lambda: aliases)
    schema = gen.build_schema()
    assert schema["properties"]["verdict_kind"] == {"enum": list(verdict_kind_args)}
    assert "VerdictKind" not in schema["$defs"]
    assert gen.verify_skeleton(schema) == []


def test_literal_aliases_are_discovered(gen: ModuleType, on_disk: dict[str, Any]) -> None:
    """`FindingKind` / `Reason` 是 Literal 别名，名字在 get_type_hints 之后就丢了。"""
    aliases = gen.literal_aliases()
    assert aliases[get_args(models.FindingKind)] == "FindingKind"
    assert "Reason" in aliases.values()
    assert on_disk["$defs"]["Reason"]["enum"] == list(get_args(models.Reason))


# --------------------------------------------------------------------------- #
# 4. JSON 出得去、回得来（A44 的 `--from`）
# --------------------------------------------------------------------------- #


def test_round_trip_is_lossless(report: Report, tmp_path: Path) -> None:
    path = write_json(report, tmp_path / "out" / "report.json")
    assert load_report(path) == report


def test_round_trip_keeps_bytes_exactly(report: Report) -> None:
    """bytes 走 base64，不走 `default=str` 的 repr —— 否则 `--from` 回不来。"""
    back = report_from_json(report_to_json(report))
    assert report.apex_www is not None
    assert back.apex_www is not None
    assert back.apex_www.apex.response is not None
    assert report.apex_www.apex.response is not None
    assert back.apex_www.apex.response.body == report.apex_www.apex.response.body


def test_json_is_deterministic(report: Report) -> None:
    """键序不随字段声明顺序抖动（L 组逐字节比对的前提之一）。"""
    assert report_to_json(report) == report_to_json(report)
    text = report_to_json(report)
    assert text.endswith("\n")
    assert json.loads(text)["counts"]["llm_calls"] == 0


def test_enums_serialize_as_values(report: Report) -> None:
    payload = json.loads(report_to_json(report))
    assert payload["positions"][0]["status"] == "fail"
    assert payload["positions"][0]["stage"] == "index_file"
    assert payload["findings"][0]["severity"] == "high"
    assert payload["apex_www"]["apex"]["expect"] == "html_page"


def test_wrong_schema_version_raises(report: Report) -> None:
    """CLI 据此退出 4（A44 末条）。"""
    payload = json.loads(report_to_json(report))
    payload["schema_version"] = "geo-audit/report/0"
    with pytest.raises(SchemaMismatchError, match="schema_version"):
        report_from_json(json.dumps(payload))


def test_unknown_field_raises(report: Report) -> None:
    payload = json.loads(report_to_json(report))
    payload["surprise"] = 1
    with pytest.raises(SchemaMismatchError, match="不认识"):
        report_from_json(json.dumps(payload))


def test_missing_required_field_raises(report: Report) -> None:
    payload = json.loads(report_to_json(report))
    del payload["counts"]["positions_fail"]
    with pytest.raises(SchemaMismatchError, match="缺必填字段"):
        report_from_json(json.dumps(payload))


def test_bad_enum_value_raises(report: Report) -> None:
    payload = json.loads(report_to_json(report))
    payload["positions"][0]["status"] = "probably_fine"
    with pytest.raises(SchemaMismatchError, match="Status"):
        report_from_json(json.dumps(payload))


def test_bad_literal_value_raises(report: Report) -> None:
    payload = json.loads(report_to_json(report))
    payload["verdict_kind"] = "looks_ok"
    with pytest.raises(SchemaMismatchError, match="verdict_kind"):
        report_from_json(json.dumps(payload))


def test_not_json_raises(report: Report) -> None:
    with pytest.raises(SchemaMismatchError, match="不是合法 JSON"):
        report_from_json("{ not json")


def test_omitted_optional_field_falls_back_to_default(report: Report) -> None:
    """有默认值的字段可以在文件里缺席 —— 老报告不会因为新增字段就读不了。"""
    payload = json.loads(report_to_json(report))
    del payload["counts"]["llm_calls"]
    assert report_from_json(json.dumps(payload)).counts.llm_calls == 0


# --------------------------------------------------------------------------- #
# 5. strip_volatile（L 组 / A45）
# --------------------------------------------------------------------------- #


def test_volatile_field_list_comes_from_models() -> None:
    expected = {
        "scanned_at",
        "duration_s",
        "fetched_at",
        "elapsed_ms",
        "from_cache",
        "resolver_used",
        "resolved_ips",
        "probed_at",
        "requests_made",
    }
    assert set(VOLATILE_JSON_FIELDS) == expected


def _keys(obj: Any) -> set[str]:
    if isinstance(obj, dict):
        found = set(obj)
        for value in obj.values():
            found |= _keys(value)
        return found
    if isinstance(obj, list):
        found = set()
        for value in obj:
            found |= _keys(value)
        return found
    return set()


def test_strip_volatile_removes_every_volatile_key(report: Report) -> None:
    payload = json.loads(report_to_json(report))
    #: 先证明它们确实在报告里（否则这条测试是空转的）
    present = _keys(payload) & VOLATILE_JSON_FIELDS
    assert present >= {"scanned_at", "duration_s", "fetched_at", "requests_made"}
    stripped = strip_volatile(payload)
    assert _keys(stripped) & VOLATILE_JSON_FIELDS == set()
    #: 剔的是易变字段，不是内容：非易变字段一个不少
    assert stripped["counts"] == payload["counts"]
    assert stripped["findings"][0]["finding_id"] == payload["findings"][0]["finding_id"]


def test_strip_volatile_does_not_mutate_input(report: Report) -> None:
    payload = json.loads(report_to_json(report))
    before = json.dumps(payload, sort_keys=True)
    strip_volatile(payload)
    assert json.dumps(payload, sort_keys=True) == before


# --------------------------------------------------------------------------- #
# 6. 用真的 jsonschema 校验一遍（CI 的 schema job 跑 check-jsonschema，同一件事）
# --------------------------------------------------------------------------- #


def test_schema_itself_is_valid_draft_2020_12(on_disk: dict[str, Any]) -> None:
    jsonschema = pytest.importorskip("jsonschema", reason="check-jsonschema 未安装")
    jsonschema.Draft202012Validator.check_schema(on_disk)


def test_report_validates_against_schema(on_disk: dict[str, Any], report: Report) -> None:
    jsonschema = pytest.importorskip("jsonschema", reason="check-jsonschema 未安装")
    validator = jsonschema.Draft202012Validator(on_disk)
    errors = sorted(validator.iter_errors(json.loads(report_to_json(report))), key=str)
    assert errors == [], [f"{list(e.absolute_path)}: {e.message}" for e in errors]


def test_schema_rejects_a_bad_report(on_disk: dict[str, Any], report: Report) -> None:
    """契约得真能拒东西：llm_calls 非 0、finding_id 形状不对，都必须被拦。"""
    jsonschema = pytest.importorskip("jsonschema", reason="check-jsonschema 未安装")
    validator = jsonschema.Draft202012Validator(on_disk)

    payload = json.loads(report_to_json(report))
    payload["counts"]["llm_calls"] = 1
    assert list(validator.iter_errors(payload))

    payload = json.loads(report_to_json(report))
    payload["findings"][0]["finding_id"] = "ga-lowercase"
    assert list(validator.iter_errors(payload))

    payload = json.loads(report_to_json(report))
    del payload["findings"][0]["severity_signals"]["region"]
    assert list(validator.iter_errors(payload))
