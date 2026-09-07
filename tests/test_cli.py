"""CLI（§7.1 全部 flag + 七个退出码 + §7.2 进度输出）—— K 组。

逐条对着 §7.1 的 --help 全文与退出码表断言。**一个真请求都不发**：需要跑管线的
用例一律 monkeypatch ``cli.audit_domain``，只有参数校验那些连管线都进不去。

三条不许松的：

* ``--contact`` **无条件必填** —— ``--replay-fixtures`` 与 ``--from`` 也不豁免
  （卡点 B17a：做成「某些模式可省」等于给了绕过的口子）。
* ``--rate`` 只能调慢 —— 传 > 0.5 直接退 4，不是 warn 不是 clamp。
* 退出码优先级 4 > 3 > 2 > 1 > 0，且 2 压过 1。
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from geo_audit import cli
from geo_audit.checks.dead_links import DEAD_LINK_RULE_IDS
from geo_audit.models import (
    SCHEMA_VERSION,
    TOOL_VERSION,
    Evidence,
    Finding,
    PositionClass,
    PositionSeed,
    Severity,
    Stage,
    Status,
)
from geo_audit.pipeline import (
    AI_PATH_RULES,
    DENOISE_RULESET_VERSION,
    Coverage,
    PositionResult,
    Report,
    build_positions,
    count_positions,
    make_headline,
    position_id,
    sampled_ratio,
)

CONTACT = "you@yourco.com"
DOMAIN = "acmecloud.io"


# --------------------------------------------------------------------------- #
# 合成 Report（不跑管线）
# --------------------------------------------------------------------------- #


def _finding(severity: Severity = Severity.CRITICAL, *, fid: str = "GA-7F2A91C4E0") -> Finding:
    return Finding(
        finding_id=fid,
        kind="dead_link",
        check_id="dead_links.hard_404",
        title="定价页三个套餐卡片的「Talk to us」全指向 404",
        severity=severity,
        position_class=PositionClass.SALES_PATH,
        stage=Stage.HUMAN_PATH,
        target=Evidence(
            url=f"https://{DOMAIN}/cloud/pricing-page",
            http_status=404,
            curl_repro=f"curl -sSL -A 'geo-audit/{TOOL_VERSION}' 'https://{DOMAIN}/x'",
        ),
        found_on=f"https://{DOMAIN}/pricing",
        why_it_matters="销售路径上的死链",
        suppress_hint=f"不认这条：geo-audit {DOMAIN} --ignore {fid}",
        severity_signals={
            "page_role": "pricing",
            "anchor": "Talk to us",
            "anchor_class": "",
            "region": "销售路径",
        },
    )


def _report(
    *,
    statuses: tuple[Status, ...] = (Status.PASS, Status.PASS, Status.PASS, Status.PASS),
    findings: tuple[Finding, ...] = (),
    interrupted: bool = False,
) -> Report:
    skeleton = [
        PositionSeed(
            stage=Stage.DISCOVERY if i == 0 else Stage.INDEX_FILE,
            key=f"cell{i}",
            kind="probe",
            probe_url=f"https://{DOMAIN}/cell{i}",
            status=status,
            detail="合成用例",
            unknown_reason="waf_status" if status is Status.UNKNOWN else None,
            unknown_remedy=(
                "该位置返回了拦截型状态码，不是内容。被拦截 ≠ 不存在。"
                if status is Status.UNKNOWN
                else None
            ),
        )
        for i, status in enumerate(statuses)
    ]
    results = {position_id(s.stage, s.key): PositionResult(seed=s) for s in skeleton}
    positions = build_positions(skeleton, results)
    counts = count_positions(positions, findings, (), ())
    coverage = Coverage(
        checked=("ai_path",),
        not_checked=("锚点是否腐烂",),
        positions_total=counts.positions,
        interrupted=interrupted,
        requests_made=7,
        budget_cap=120,
    )
    headline, kind = make_headline(
        counts,
        has_ai_channel=True,
        sampled_ratio=sampled_ratio(coverage),
        interrupted=interrupted,
    )
    return Report(
        schema_version=SCHEMA_VERSION,
        tool_version=TOOL_VERSION,
        denoise_ruleset_version=DENOISE_RULESET_VERSION,
        domain=DOMAIN,
        scanned_at="2026-09-07 14:22 UTC",
        duration_s=1.5,
        contact=CONTACT,
        user_agent=f"geo-audit/{TOOL_VERSION} (contact: {CONTACT})",
        headline=headline,
        verdict_kind=kind,
        positions=positions,
        findings=findings,
        root_causes=(),
        naive_table=(),
        fragilities=(),
        coverage_gaps=(),
        excluded=(),
        apex_www=None,
        coverage=coverage,
        counts=counts,
    )


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """连 httpx 的门都焊死：``--from`` 那条路必须零请求（A44）。"""

    def _boom(*_a: object, **_k: object) -> httpx.Response:
        raise AssertionError("这条路不许发请求")

    monkeypatch.setattr(httpx.Client, "request", _boom)
    monkeypatch.setattr(httpx.Client, "send", _boom)


@pytest.fixture
def canned(monkeypatch: pytest.MonkeyPatch) -> None:
    """把管线换成一个合成的干净报告，用来测 CLI 自己的分支。"""
    monkeypatch.setattr(cli, "audit_domain", lambda *_a, **_k: _report())


# --------------------------------------------------------------------------- #
# --help / --version / --list-rules
# --------------------------------------------------------------------------- #

HELP_MUST_CONTAIN = ("退出码", "0.5 req/s", "--contact", "无法评估", "130")


def test_help_contains_required_strings(capsys: pytest.CaptureFixture[str]) -> None:
    """K 组 / A42：--help 必须含这五个串。"""
    assert cli.main(["--help"]) == 0
    text = capsys.readouterr().out
    for needle in HELP_MUST_CONTAIN:
        assert needle in text, needle


def test_help_lists_the_seven_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["--help"])
    text = capsys.readouterr().out
    for code in ("0 ", "1 ", "2 ", "3 ", "4 ", "130"):
        assert code in text


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == 0
    assert TOOL_VERSION in capsys.readouterr().out


def test_list_rules_prints_registry_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    """``--list-rules``：ai_path 4 条 + dead_links 23 条，退出 0，先于一切校验。"""
    assert cli.main(["--list-rules"]) == 0  # 注意：没给 --contact 也要退 0
    out = capsys.readouterr().out
    assert len(DEAD_LINK_RULE_IDS) == 23
    assert len(AI_PATH_RULES) == 4
    for rule in DEAD_LINK_RULE_IDS:
        assert f"dead_links.{rule}" in out
    for rule in AI_PATH_RULES:
        assert f"ai_path.{rule}" in out


# --------------------------------------------------------------------------- #
# --contact 无条件必填（卡点 B17a）
# --------------------------------------------------------------------------- #


def test_missing_contact_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(cli.CONTACT_ENV, raising=False)
    assert cli.main([DOMAIN]) == 4


@pytest.mark.parametrize("extra", [["--replay-fixtures"], ["--from", "whatever.json"]])
def test_missing_contact_exits_4_in_every_mode(
    extra: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """replay 与 --from **也不豁免** —— 做成可选等于没有。"""
    monkeypatch.delenv(cli.CONTACT_ENV, raising=False)
    assert cli.main([DOMAIN, *extra]) == 4


def test_contact_without_at_sign_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(cli.CONTACT_ENV, raising=False)
    assert cli.main([DOMAIN, "--contact", "not-an-email"]) == 4


def test_contact_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, canned: None) -> None:
    monkeypatch.setenv(cli.CONTACT_ENV, CONTACT)
    assert cli.main([DOMAIN, "--out", str(tmp_path / "o"), "-q"]) == 0


# --------------------------------------------------------------------------- #
# --rate 只能调慢
# --------------------------------------------------------------------------- #


def test_rate_faster_than_floor_exits_4(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([DOMAIN, "--contact", CONTACT, "--rate", "2.0"]) == 4
    err = capsys.readouterr().err
    assert "0.5" in err
    assert "只能调慢" in err


def test_rate_slower_is_accepted(tmp_path: Path, canned: None) -> None:
    assert cli.main([DOMAIN, "--contact", CONTACT, "--rate", "0.1", "--out", str(tmp_path)]) == 0


def test_rate_zero_exits_4() -> None:
    assert cli.main([DOMAIN, "--contact", CONTACT, "--rate", "0"]) == 4


# --------------------------------------------------------------------------- #
# --only / --skip / --format / 域名
# --------------------------------------------------------------------------- #


def test_unregistered_rule_id_exits_4_with_three_candidates(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """卡点 B19：``dead_links.tls_broken`` 现在是非法值，正好当负例。"""
    assert cli.main([DOMAIN, "--contact", CONTACT, "--skip", "dead_links.tls_broken"]) == 4
    err = capsys.readouterr().err
    assert "未注册的 id" in err
    assert err.count("、") == 2  # 最接近的三个候选


def test_unknown_check_id_in_only_exits_4() -> None:
    assert cli.main([DOMAIN, "--contact", CONTACT, "--only", "seo_score"]) == 4


def test_legal_ids_pass_validation(tmp_path: Path, canned: None) -> None:
    code = cli.main(
        [
            DOMAIN,
            "--contact",
            CONTACT,
            "--only",
            "ai_path",
            "--skip",
            "dead_links.waf_challenge",
            "--out",
            str(tmp_path),
        ]
    )
    assert code == 0


def test_bad_format_exits_4() -> None:
    assert cli.main([DOMAIN, "--contact", CONTACT, "--format", "pdf"]) == 4


@pytest.mark.parametrize(
    "bad", ["https://acmecloud.io", "acmecloud.io/docs", "not_a_domain", "-acme.io"]
)
def test_invalid_domain_exits_4(bad: str) -> None:
    assert cli.main([bad, "--contact", CONTACT]) == 4


def test_missing_domain_exits_4() -> None:
    assert cli.main(["--contact", CONTACT]) == 4


def test_unknown_flag_exits_4_not_2() -> None:
    """argparse 默认用 2 表示用法错误；§7.1 的 2 是「结论不可信」，所以必须改成 4。"""
    assert cli.main([DOMAIN, "--contact", CONTACT, "--no-such-flag"]) == 4


# --------------------------------------------------------------------------- #
# --render 未实现（A43）
# --------------------------------------------------------------------------- #


def test_render_flag_is_non_zero_and_prints_the_three_reasons(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main([DOMAIN, "--contact", CONTACT, "--render"]) != 0
    err = capsys.readouterr().err
    assert "Playwright" in err
    assert "2/72" in err
    assert "不绕 WAF" in err or "不解 CAPTCHA" in err


# --------------------------------------------------------------------------- #
# 输出与 --from
# --------------------------------------------------------------------------- #


def test_writes_json_and_html(tmp_path: Path, canned: None) -> None:
    out = tmp_path / "report"
    assert cli.main([DOMAIN, "--contact", CONTACT, "--out", str(out)]) == 0
    data = json.loads((out / f"{DOMAIN}.json").read_text("utf-8"))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["counts"]["llm_calls"] == 0
    html = (out / f"{DOMAIN}.html").read_text("utf-8")
    assert "<html" in html.lower()
    assert "geo-audit" in html.lower()


def test_stdout_stays_clean_for_pipes(
    tmp_path: Path, canned: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """§7.2：进度全走 stderr，stdout 留给 ``--format json`` 管道。"""
    cli.main([DOMAIN, "--contact", CONTACT, "--out", str(tmp_path)])
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "完成 · " in captured.err
    assert "报告 " in captured.err


def test_from_json_rerenders_without_any_request(
    tmp_path: Path, canned: None, no_network: None
) -> None:
    """A44：``--from`` 在 httpx 被焊死的情况下仍退 0 并产出 HTML。"""
    out = tmp_path / "one"
    assert cli.main([DOMAIN, "--contact", CONTACT, "--out", str(out), "--format", "json"]) == 0
    src = out / f"{DOMAIN}.json"
    again = tmp_path / "two"
    code = cli.main(
        ["--from", str(src), "--contact", CONTACT, "--out", str(again), "--format", "html"]
    )
    assert code == 0
    assert (again / f"{DOMAIN}.html").exists()


def test_from_json_with_wrong_schema_exits_4(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "geo-audit/report/0"}), "utf-8")
    assert cli.main(["--from", str(bad), "--contact", CONTACT]) == 4


def test_from_missing_file_exits_4(tmp_path: Path) -> None:
    assert cli.main(["--from", str(tmp_path / "nope.json"), "--contact", CONTACT]) == 4


# --------------------------------------------------------------------------- #
# 退出码优先级（A46）
# --------------------------------------------------------------------------- #


def _patch(monkeypatch: pytest.MonkeyPatch, report: Report) -> None:
    monkeypatch.setattr(cli, "audit_domain", lambda *_a, **_k: report)


def test_clean_report_exits_0(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch(monkeypatch, _report())
    assert cli.main([DOMAIN, "--contact", CONTACT, "--out", str(tmp_path)]) == 0


def test_findings_exit_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch(monkeypatch, _report(findings=(_finding(),)))
    assert cli.main([DOMAIN, "--contact", CONTACT, "--out", str(tmp_path)]) == 1


def test_unusable_exits_2_and_beats_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """gusto 型：``unknown / core > 0.5`` → 2，**即使同时有发现**（2 优先于 1）。"""
    gusto = _report(
        statuses=(Status.PASS, Status.UNKNOWN, Status.UNKNOWN, Status.UNKNOWN),
        findings=(_finding(),),
    )
    assert gusto.verdict_kind == "unusable"
    _patch(monkeypatch, gusto)
    assert cli.main([DOMAIN, "--contact", CONTACT, "--out", str(tmp_path)]) == 2


def test_unreachable_exits_3_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def boom(*_a: object, **_k: object) -> Report:
        raise cli.DomainUnreachableError("apex 与 www 都连不上")

    monkeypatch.setattr(cli, "audit_domain", boom)
    out = tmp_path / "nothing"
    assert cli.main([DOMAIN, "--contact", CONTACT, "--out", str(out)]) == 3
    assert not out.exists()


def test_fail_on_none_exits_0(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch(monkeypatch, _report(findings=(_finding(),)))
    code = cli.main([DOMAIN, "--contact", CONTACT, "--out", str(tmp_path), "--fail-on", "none"])
    assert code == 0


def test_fail_on_critical_ignores_low(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """copper 型：只有 LOW 的报告在 ``--fail-on critical`` 下退 0。"""
    _patch(monkeypatch, _report(findings=(_finding(Severity.LOW),)))
    code = cli.main([DOMAIN, "--contact", CONTACT, "--out", str(tmp_path), "--fail-on", "critical"])
    assert code == 0


def test_ignore_suppresses_a_finding(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch(monkeypatch, _report(findings=(_finding(),)))
    code = cli.main(
        [DOMAIN, "--contact", CONTACT, "--out", str(tmp_path), "--ignore", "GA-7F2A91C4E0"]
    )
    assert code == 0


def test_ignore_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    listfile = tmp_path / "ignores.txt"
    listfile.write_text("# 上季度已确认\nGA-7F2A91C4E0\n", "utf-8")
    _patch(monkeypatch, _report(findings=(_finding(),)))
    code = cli.main(
        [
            DOMAIN,
            "--contact",
            CONTACT,
            "--out",
            str(tmp_path),
            "--ignore-file",
            str(listfile),
        ]
    )
    assert code == 0


def test_ignore_does_not_touch_the_position_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """抑制一条发现 ≠ 那个位置通过了：四格计数与恒等式都不许被 --ignore 改动。"""
    base = _report(findings=(_finding(),))
    kept = cli.apply_ignores(base, ["GA-7F2A91C4E0"])
    assert kept.positions == base.positions
    assert kept.counts.positions == base.counts.positions
    assert kept.counts.findings == 0
    del monkeypatch, tmp_path


# --------------------------------------------------------------------------- #
# --naive-only / -q
# --------------------------------------------------------------------------- #


def test_naive_only_prints_the_three_column_table(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch(monkeypatch, _report())
    assert cli.main([DOMAIN, "--contact", CONTACT, "--naive-only"]) == 0
    captured = capsys.readouterr()
    assert "探测位置\t那种实现会说\t实际是" in captured.out
    # 固定措辞（附录 B-1）：不许写「任何现成工具」
    assert "只探根路径、不做对照探测的实现" in captured.err
    assert "任何现成工具" not in captured.err + captured.out


def test_quiet_prints_no_progress(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch(monkeypatch, _report())
    cli.main([DOMAIN, "--contact", CONTACT, "--out", str(tmp_path), "-q"])
    err = capsys.readouterr().err
    assert "geo-audit 0.1.0 · " not in err
    assert "完成 · " in err  # -q 也要有结束那一行


def test_progress_sink_writes_only_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    progress = cli.StderrProgress(color=False, verbose=True)
    progress.stage(1, "① 入口发现", "探 14 个位置")
    progress.row("FAIL", f"https://{DOMAIN}/llms.txt", "软 404")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[1/6] ① 入口发现" in captured.err
    assert "FAIL" in captured.err


def test_from_round_trip_is_byte_identical(tmp_path: Path, canned: None) -> None:
    """``--from`` 重出的 HTML 与首次渲染逐字节相同 —— 改模板重出报告的用法靠它。

    这条同时证明 JSON ↔ Report 的往返没有丢字段：丢了正式模板会退回最小 HTML，
    体积差一个数量级。
    """
    first = tmp_path / "first"
    assert cli.main([DOMAIN, "--contact", CONTACT, "--out", str(first), "-q"]) == 0
    again = tmp_path / "again"
    code = cli.main(
        [
            "--from",
            str(first / f"{DOMAIN}.json"),
            "--contact",
            CONTACT,
            "--out",
            str(again),
            "--format",
            "html",
        ]
    )
    assert code == 0
    assert (again / f"{DOMAIN}.html").read_bytes() == (first / f"{DOMAIN}.html").read_bytes()
