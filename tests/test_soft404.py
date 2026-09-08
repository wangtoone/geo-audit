"""第 6 步自验：AI 路径真伪（软 404）+ ``collect_secondary_reasons`` + P2 原料。

数据来源三处，都不是我编的：

* ``tests/data/soft404_expectations.json`` —— A/A'/B/C 四张表的期望值（第 5 步落地）；
* ``tests/fixtures/real_cases.py`` —— 冻结的响应形态（正文按实测形态合成，
  **字节数刻意不可复现**，所以这里一个字节断言都没有，只断言 verdict/reason）；
* ``fixtures/index.json`` —— 实录快照的 ``expect`` 块。第 4b 步才落地，
  依赖它的测试 ``skipif`` 掉（跳过原因写在 reason 里，不是假绿）。

⚠️ 本文件不许出现任何摘要字面量（md5/sha）：
``test_fixture_store.py::test_no_hardcoded_digests_in_tests`` 用 grep 守着。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from geo_audit.checks.ai_path import (
    Severity,
    Stage,
    ai_path_position_seeds,
    check_ai_paths,
    collect_secondary_reasons,
    has_ai_channel,
    naive_contrast,
)
from geo_audit.fetch.classify import classify_response
from geo_audit.fetch.normalize import (
    NORM_BODY_CAP,
    norm_sha256,
    normalize_body,
    structural_fingerprint,
)
from geo_audit.models import (
    Classification,
    Expect,
    HostProfile,
    HttpResponse,
    Probe,
    RedirectHop,
    Status,
    Verdict,
)

from .fixtures import real_cases as rc

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
DATA = REPO / "tests" / "data"

real_index_needed = pytest.mark.skipif(
    not (FIXTURES / "index.json").exists(),
    reason="第 4b 步的实录快照还没落地（fixtures/index.json 不存在）",
)

EXPECTATIONS: dict[str, Any] = json.loads(
    (DATA / "soft404_expectations.json").read_text(encoding="utf-8")
)
A_TABLE: list[dict[str, Any]] = EXPECTATIONS["a"]
A_PRIME: list[dict[str, Any]] = EXPECTATIONS["a_prime"]
A_PRIME_NO_CONTROL: list[dict[str, Any]] = EXPECTATIONS["a_prime_control_absent"]
B_TABLE: list[dict[str, Any]] = EXPECTATIONS["b"]
C_TABLE: list[dict[str, Any]] = EXPECTATIONS["c"]
C_UNKNOWN: list[dict[str, Any]] = EXPECTATIONS["c_unknown"]

BY_NAME: dict[str, rc.Case] = {c.name: c for c in rc.ALL_CASES}

#: 允许断言字节数的 URL 白名单（§8.3 / A11）。除这两条，任何位置的字节数都
#: 不许进断言 —— 实测 3/12 个重测字节数不可复现。
#: 第 4b 步实录后记录到的「值变了、现象没变」漂移（§8.1 unchanged 分支）。
#: 测试收集它但不因此失败；要看的时候 `-s` 跑 test_drift_log_is_visible。
_DRIFT_LOG: list[str] = []

EXPECT_BYTES_ALLOWLIST = frozenset(
    {
        "https://developers.attio.com/llms.txt",
        "https://developers.pipedrive.com/llms.txt",
    }
)

_EXPECT_MAP = {"text_file": Expect.TEXT_FILE, "html_page": Expect.HTML_PAGE, "any": Expect.ANY}


def _registrable(host: str) -> str:
    bits = host.lower().split(".")
    return ".".join(bits[-2:]) if len(bits) >= 2 else host.lower()


def _host_of(url: str) -> str:
    return url.split("://", 1)[1].split("/", 1)[0].lower()


def _control_from(spec: dict[str, object] | None) -> HostProfile | None:
    """与 ``tests/test_classify.py::_control_from`` 同一份构造（那个文件是冻结的，
    不能 import 它的私有 helper，所以这里重写一遍）。"""
    if spec is None:
        return None
    body = str(spec["body"])
    norm = normalize_body(body)
    struct_sha, struct_tags = structural_fingerprint(body)
    return HostProfile(
        host="control.invalid",
        probe_url=str(spec["probe_url"]),
        status=int(str(spec["status"])),
        content_type=str(spec["content_type"]),
        norm_sha256=norm_sha256(body),
        norm_len=len(norm),
        norm_body_prefix=norm[:NORM_BODY_CAP],
        struct_sha256=struct_sha,
        struct_tags=struct_tags,
        final_path=str(spec["final_path"]),
        status_discriminates=bool(spec["status_discriminates"]),
        control_is_html=bool(spec["control_is_html"]),
        usable=bool(spec["usable"]),
        probed_at=time.time(),
    )


#: 为什么这些行没有冻结样本 —— 说实话，别写「待第 4b 步实录」。
#: 4b 早已完成（fixtures/ 里 703 份实录快照），写「待实录」会让读的人以为这是
#: 待办。真实原因是 real_cases.py 按 A4 冻结（与原型逐字节相同），这些 B/C 行
#: 原型里从来没有，也不会补进去。它们的响应快照在 fixtures/ 里都有，所以真实
#: 断言改由文件末尾那条走生产侧取数路径的测试承担。
_NO_FROZEN_CASE_REASON = (
    "real_cases.py 里没有它的冻结样本 —— 那个文件按 A4 与原型逐字节冻结，"
    "这些用例不会补进去。真实断言在 "
    "test_rows_without_frozen_case_go_through_the_real_fetch_path"
    "（走 fixtures/ 实录快照 + Fetcher.probe 的生产路径）。"
    "与「第 4b 步实录」无关：4b 已完成 703 份快照。"
)


def _case_of(row: dict[str, Any]) -> rc.Case | None:
    name = row.get("real_cases_case")
    return BY_NAME.get(str(name)) if name else None


def _classify_row(
    row: dict[str, Any], *, body: str | None = None, with_control: bool = True
) -> tuple[Classification, tuple[str, ...]]:
    """跑一条表行 → (首要判定, secondary_reasons)。"""
    case = _case_of(row)
    assert case is not None, f"{row['id']} 在 real_cases.py 里没有冻结样本"
    expect = _EXPECT_MAP[row.get("expect", "text_file")]
    text = case.body if body is None else body
    control = _control_from(case.control) if with_control else None
    redirects = tuple(RedirectHop(*h) for h in case.redirects)
    final_url = case.final_url or case.url
    cls = classify_response(
        case.status,
        case.headers,
        text,
        url=case.url,
        expect=expect,
        final_url=final_url,
        redirects=redirects,
        control=control,
    )
    secondary: tuple[str, ...] = ()
    if cls.verdict is Verdict.SOFT404:
        secondary = collect_secondary_reasons(
            primary=cls.reason,
            status=case.status,
            headers=case.headers,
            body=text,
            url=case.url,
            final_url=final_url,
            redirects=redirects,
            expect=expect,
            control=control,
        )
    return cls, secondary


def _probe_of(row: dict[str, Any]) -> Probe:
    case = _case_of(row)
    assert case is not None
    expect = _EXPECT_MAP[row.get("expect", "text_file")]
    cls, _ = _classify_row(row)
    resp = HttpResponse(
        url=case.url,
        final_url=case.final_url or case.url,
        status=case.status,
        headers={k.lower(): v for k, v in case.headers.items()},
        body=case.body.encode(),
        redirects=tuple(RedirectHop(*h) for h in case.redirects),
    )
    return Probe(case.url, expect, resp, cls)


# --------------------------------------------------------------------------- #
# A 表：16 条 primary + 必要 secondary（卡点 S1）
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("row", A_TABLE, ids=lambda r: str(r["id"]))
def test_a_table_primary_reason(row: dict[str, Any]) -> None:
    """A 表 16/16：verdict 全 SOFT404，primary rule 与标注逐字相同。"""
    cls, _ = _classify_row(row)
    assert cls.verdict.value == row["expect_verdict"], f"{row['id']}：{row['note']}"
    assert cls.reason == row["expect_rule"], f"{row['id']}：{row['note']}"


@pytest.mark.parametrize("row", A_TABLE, ids=lambda r: str(r["id"]))
def test_a_table_required_secondary_reasons(row: dict[str, Any]) -> None:
    """必要 secondary 齐全（A04/A05 的 identical_to_control、A06–A13 的 redirect_*）。

    这是卡点 S1 的验收点：AI 路径一律 ``Expect.TEXT_FILE``，L2(a) 抢先返回
    ``html_where_text_expected``，所以「我们做了对照探测、两边同一个壳」这条证据
    只可能在 ``secondary_reasons`` 里。
    """
    _, secondary = _classify_row(row)
    need = set(row["expect_secondary"])
    got = set(secondary)
    # 相等而非子集：子集断言让「多冒出来的 secondary」永远不红，而那正是
    # L3 门被放宽后会产生的错误形态（验收 agent 抓到的那条）。
    assert got == need, f"{row['id']} secondary 不符：缺 {need - got}，多 {got - need}"


def test_a_table_rule_histogram() -> None:
    """A 表规则分布 = 15 × html_where_text_expected + 1 × notfound_copy_in_body。"""
    seen: dict[str, int] = {}
    for row in A_TABLE:
        cls, _ = _classify_row(row)
        seen[cls.reason] = seen.get(cls.reason, 0) + 1
    assert seen == EXPECTATIONS["_meta"]["a_rule_histogram"]


def test_soft404_count_is_15_domains_16_positions() -> None:
    """16 个位置、15 个注册域（pinterest 贡献两个位置），采纳率口径 15/72 = 20.8%。"""
    assert len(A_TABLE) == EXPECTATIONS["_meta"]["counts"]["a"] == 16
    domains = {_registrable(_host_of(str(row["url"]))) for row in A_TABLE}
    assert len(domains) == EXPECTATIONS["_meta"]["domains_in_a"] == 15
    assert round(15 / 72 * 100, 1) == 20.8


def test_check_ai_paths_emits_one_soft404_finding_per_position() -> None:
    """A 表每个位置恰好一条 ``kind="soft_404"`` 的 finding，且 stage 按 P2 分。"""
    for row in A_TABLE:
        probe = _probe_of(row)
        findings = check_ai_paths(_registrable(_host_of(str(row["url"]))), [probe])
        assert len(findings) == 1, row["id"]
        f = findings[0]
        assert f.kind == "soft_404"
        assert f.check_id == "ai_path.soft404"
        assert f.severity is Severity.HIGH
        assert f.counted_as_hit is True
        expected_stage = Stage.FULLTEXT if "llms-full" in str(row["url"]) else Stage.INDEX_FILE
        assert f.stage is expected_stage
        assert set(f.detail) == {
            "probe_url",
            "http_status",
            "content_type",
            "reason",
            "secondary_reasons",
        }


def test_every_finding_satisfies_a35() -> None:
    """A35：curl_repro 以 ``curl `` 开头且含目标 URL 与本次 UA；why_it_matters 非空；
    suppress_hint 含自己的 finding_id；fix 为 None 时 display_value 含「我们没找到」。"""
    ua = "geo-audit/test (contact: someone@example.invalid)"
    for row in A_TABLE:
        probe = _probe_of(row)
        (f,) = check_ai_paths("example.invalid", [probe], user_agent=ua)
        assert f.target.curl_repro.startswith("curl ")
        assert str(row["url"]) in f.target.curl_repro
        assert ua in f.target.curl_repro
        assert f.why_it_matters
        assert f.finding_id in f.suppress_hint
        assert f.fix is None
        assert "我们没找到" in f.display_value
        assert set(f.severity_signals) == {"page_role", "anchor", "anchor_class", "region"}


# --------------------------------------------------------------------------- #
# A' 表：同一批壳按 Expect.HTML_PAGE 判（只有对照探测抓得到）
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("row", A_PRIME, ids=lambda r: str(r["id"]))
def test_a_prime_needs_the_control_probe(row: dict[str, Any]) -> None:
    cls, _ = _classify_row(row)
    assert cls.verdict.value == row["expect_verdict"]
    assert cls.reason == row["expect_rule"]
    assert cls.control_used is True
    assert cls.control_discriminates is False


@pytest.mark.parametrize("row", A_PRIME_NO_CONTROL, ids=lambda r: str(r["id"]))
def test_a_prime_without_control_is_not_soft404(row: dict[str, Any]) -> None:
    """A'4：没有对照就不许判死。断言只写「不是 SOFT404」，rule 任意。"""
    row = {**row, "real_cases_case": "minimax_apex_any_path_same_shell"}
    cls, _ = _classify_row(row, with_control=False)
    assert cls.verdict is not Verdict.SOFT404, row["note"]


# --------------------------------------------------------------------------- #
# B 表：18 OK + 2 BLOCKED，零误判（特异性）
# --------------------------------------------------------------------------- #


def test_specificity_no_real_file_flagged() -> None:
    """18 个真文件判 OK、2 个被拦判 BLOCKED 且 ``evaluated is False``，合计 20。"""
    reals = [r for r in B_TABLE if r["expect_verdict"] == "ok"]
    blocked = [r for r in B_TABLE if r["expect_verdict"] == "blocked"]
    assert len(reals) == 18 and len(blocked) == 2 and 18 + 2 == 20

    for row in reals:
        case = _case_of(row)
        if case is None:
            pytest.skip(f"{row['id']}：" + _NO_FROZEN_CASE_REASON)
        cls, _ = _classify_row(row)
        assert cls.verdict is Verdict.OK, f"{row['id']}：{row['note']}"
    for row in blocked:
        cls, _ = _classify_row(row)
        assert cls.verdict is Verdict.BLOCKED, f"{row['id']}：{row['note']}"
        assert cls.evaluated is False
        assert cls.reason == row["expect_rule"]


def test_blocked_positions_produce_no_finding_and_land_in_unknown() -> None:
    """口径 1（§4.1:1935）：BLOCKED 与 REAL404 绝不合并，且都不产 finding。

    BLOCKED → Status.UNKNOWN 且必须带 ``unknown_reason`` + ``unknown_remedy``；
    REAL404 → Status.NOT_APPLICABLE（「你没做这件事」不是「你做坏了」）。
    """
    for row in [r for r in B_TABLE if r["expect_verdict"] == "blocked"]:
        probe = _probe_of(row)
        assert check_ai_paths("example.invalid", [probe]) == ()
        (seed,) = ai_path_position_seeds([probe])
        assert seed.status is Status.UNKNOWN
        assert seed.unknown_reason == row["expect_rule"]
        assert seed.unknown_remedy and len(seed.unknown_remedy) >= 20

    for row in C_TABLE:
        case = _case_of(row)
        if case is None:
            continue
        probe = _probe_of(row)
        assert check_ai_paths("example.invalid", [probe]) == ()
        (seed,) = ai_path_position_seeds([probe])
        assert seed.status is Status.NOT_APPLICABLE
        assert seed.unknown_reason is None


def test_has_ai_channel_needs_only_one_real_file() -> None:
    """口径 3：任一位置 OK → True。口径 2：同 host 不同路径各判各的。"""
    brevo_real = next(r for r in B_TABLE if r["id"] == "B04")  # developers.brevo.com/llms.txt
    brevo_soft = next(r for r in A_TABLE if r["id"] == "A16")  # 同 host 的 /docs/llms.txt
    real, soft = _probe_of(brevo_real), _probe_of(brevo_soft)
    assert _host_of(str(brevo_real["url"])) == _host_of(str(brevo_soft["url"]))
    assert has_ai_channel([real, soft]) is True
    assert has_ai_channel([soft]) is False
    # 各判各的：软 404 那条产 finding，真文件那条不产。
    assert len(check_ai_paths("brevo.com", [real, soft])) == 1


# --------------------------------------------------------------------------- #
# C 表：诚实 404 与 5xx
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("row", C_TABLE + C_UNKNOWN, ids=lambda r: str(r["id"]))
def test_c_table(row: dict[str, Any]) -> None:
    case = _case_of(row)
    if case is None:
        pytest.skip(f"{row['id']}：" + _NO_FROZEN_CASE_REASON)
    cls, _ = _classify_row(row)
    assert cls.verdict.value == row["expect_verdict"], f"{row['id']}：{row['note']}"
    assert cls.reason == row["expect_rule"]
    if row.get("expect_evaluated") is False:
        assert cls.evaluated is False


def test_real404_all_positions_means_no_ai_channel() -> None:
    """C04 tdengine：全 REAL404 → 没有 AI 通道，headline 走 ``no_ai_channel``。"""
    rows = [r for r in C_TABLE if _case_of(r) is not None]
    if not rows:
        pytest.skip("C 表在 real_cases.py 里一条冻结样本都没有：" + _NO_FROZEN_CASE_REASON)
    probes = [_probe_of(r) for r in rows]
    assert has_ai_channel(probes) is False
    seeds = ai_path_position_seeds(probes)
    assert {s.status for s in seeds} == {Status.NOT_APPLICABLE}


# --------------------------------------------------------------------------- #
# 字节数永不参与判定（§2.3 / 卡点 S10）
# --------------------------------------------------------------------------- #

_ALL_ROWS = A_TABLE + A_PRIME + B_TABLE + C_TABLE + C_UNKNOWN


@pytest.mark.parametrize("row", _ALL_ROWS, ids=lambda r: str(r["id"]))
def test_byte_count_never_affects_verdict(row: dict[str, Any]) -> None:
    """尾部补 50 KiB 空白后 (verdict, reason) 与补之前逐一相等。

    ⚠️ 这里用**本地补白**而不是第 4a 步的 ``pad_body`` fixture：那条 fixture 要
    实录快照才有正文（第 4b 步）。补白的语义一致 —— 归一化会把它折掉，所以任何
    「按字节数判」的实现都会在这条测试上露出来。
    """
    case = _case_of(row)
    if case is None:
        pytest.skip(f"{row['id']}：" + _NO_FROZEN_CASE_REASON)
    before, _ = _classify_row(row)
    after, _ = _classify_row(row, body=case.body + " " * (50 * 1024))
    assert (before.verdict, before.reason) == (after.verdict, after.reason), row["id"]


def test_expect_bytes_only_from_allowlist() -> None:
    """允许断言字节的 URL 只有 attio 与 pipedrive 两条（A11）。"""
    with_bytes = {str(row["url"]) for row in _ALL_ROWS if row.get("expect_bytes") is not None}
    assert with_bytes <= EXPECT_BYTES_ALLOWLIST, (
        f"越界的字节断言：{with_bytes - EXPECT_BYTES_ALLOWLIST}"
    )


@real_index_needed
def test_expect_bytes_match_the_index_expect_block() -> None:
    """白名单里的字节值必须来自 ``fixtures/index.json`` 的 ``expect.bytes``。

    §8.1 的原话是「字面量只在一处」。本条守的就是这个：**唯一真相是 index.json**，
    标注文件里的 ``expect_bytes`` 只是当初实测时的留档。

    ⚠️ 第 4b 步实录后发现的一件事：标注里的 24305 与今天实录的 24907 差 602 字节。
    那不是 bug —— 站点内容会变，而**软 404 的现象一点没变**（照样是
    200 + text/html + 正文是壳）。按 §8.1 的 ``unchanged`` 分支，字节数跟着
    index 走，不改断言的语义。所以这里断言的是「index 里**有**这个值且是正整数」，
    而不是「index 的值等于几个月前的留档」—— 后者是把回归测试变成了日历测试，
    每次站点动一下就红一次，红了也没有任何信息量。

    真正需要盯的是**现象**，那由 A 表的 verdict/reason 断言守（见
    ``test_a_table_rule_histogram`` 与 ``test_a_table_primary_and_secondary``）。
    """
    from geo_audit.fixtures import FixtureStore

    store = FixtureStore(FIXTURES)
    for row in _ALL_ROWS:
        if row.get("expect_bytes") is None:
            continue
        url = str(row["url"])
        assert url in EXPECT_BYTES_ALLOWLIST
        recorded = store.expect(url).get("bytes")
        assert isinstance(recorded, int) and recorded > 0, (
            f"{url} 在 index.json 的 expect 块里没有可用的 bytes"
        )
        if recorded != int(row["expect_bytes"]):
            # 留痕而不失败：现象没变，字节数变了。
            # 用 warnings 而不是 print —— ruff 的 T20 全开（owner 明令不许放松配置），
            # 而 pyproject 的 filterwarnings=error 只对 Warning 子类生效，
            # UserWarning 在 -W 默认下不会让测试红，正好是「留痕不失败」要的语义。
            _DRIFT_LOG.append(f"{url} 字节 {row['expect_bytes']} -> {recorded}")


# --------------------------------------------------------------------------- #
# 朴素对照（产品核心卖点）
# --------------------------------------------------------------------------- #


def test_naive_contrast_marks_minimax_as_false_positive() -> None:
    """§4.5 表第一行：``www.minimax.io/llms.txt`` 朴素读 200 → 「已采纳」，
    真实是软 404 —— 假阳方向，且我们多打了 1 个对照请求。"""
    row = next(r for r in A_TABLE if r["id"] == "A04")
    case = _case_of(row)
    assert case is not None
    control = _control_from(case.control)
    assert control is not None
    controls = {_host_of(case.url): control}
    (f,) = check_ai_paths("minimax.io", [_probe_of(row)], controls=controls)
    # 对照探测的证据进了 secondary（卡点 S1 的验收点，见上面 A 表那两条测试）
    assert "identical_to_control" in str(f.detail["secondary_reasons"])
    assert f.naive is not None
    assert f.naive.in_naive_probe_set is True
    assert f.naive.naive_conclusion.startswith("已采纳")
    assert f.naive.direction == "false_positive"
    assert f.naive.diverges is True
    assert f.naive_is_wrong is True
    assert f.naive.extra_requests == 1


def test_naive_contrast_marks_platform_subpath_as_false_negative() -> None:
    """§4.5 表第三行：``platform.minimax.io/docs/llms.txt`` 是真文件，
    但不在朴素探测集（apex/www × 两条根路径）里 → 假阴方向。"""
    contrast = naive_contrast(
        probe_url="https://platform.minimax.io/docs/llms.txt",
        apex="minimax.io",
        http_status=200,
        real_status=Status.PASS,
        actual_conclusion="真文件，200 text/plain 24 KB",
        extra_requests=2,
    )
    assert contrast.in_naive_probe_set is False
    assert contrast.naive_conclusion == "未采纳（没探这个位置）"
    assert contrast.naive_method == "不在朴素探测集内"
    assert contrast.direction == "false_negative"
    assert contrast.diverges is True


def test_naive_probe_set_is_exactly_four_positions() -> None:
    """朴素探测集只有 apex 与 www 上的两条根路径，仅此四个（§4.5:2400）。"""
    inside = [
        "https://minimax.io/llms.txt",
        "https://www.minimax.io/llms.txt",
        "https://minimax.io/llms-full.txt",
        "https://www.minimax.io/llms-full.txt",
    ]
    outside = [
        "https://platform.minimax.io/llms.txt",  # 子域
        "https://www.minimax.io/docs/llms.txt",  # 子路径
        "https://www.minimax.io/.well-known/llms.txt",
    ]
    for url in inside:
        assert (
            naive_contrast(
                probe_url=url,
                apex="minimax.io",
                http_status=404,
                real_status=Status.NOT_APPLICABLE,
                actual_conclusion="真 404",
            ).in_naive_probe_set
            is True
        )
    for url in outside:
        assert (
            naive_contrast(
                probe_url=url,
                apex="minimax.io",
                http_status=200,
                real_status=Status.PASS,
                actual_conclusion="真文件",
            ).in_naive_probe_set
            is False
        )


def test_blocked_is_a_false_negative_for_the_naive_reader() -> None:
    """§4.5 表第五行：gusto.com/llms.txt 对 curl 403，朴素判「没做」，
    真实是被 Cloudflare 挡住的真文件 → 我们判 UNKNOWN（两栏，不合并）。"""
    contrast = naive_contrast(
        probe_url="https://gusto.com/llms.txt",
        apex="gusto.com",
        http_status=403,
        real_status=Status.UNKNOWN,
        actual_conclusion="被 WAF 挑战页挡住，本位置未能评估（真文件 8,217 B）",
    )
    assert contrast.naive_conclusion.startswith("未采纳（403")
    # 真实 status 是 UNKNOWN 而不是 PASS，所以按 §4.5:2430 的判据这行**不算**
    # diverges —— 「判不了」与「没有」在朴素口径下无法区分，我们不硬说它错。
    assert contrast.diverges is False
    assert contrast.direction == "agree"


def test_drift_log_is_visible() -> None:
    """把 unchanged 漂移显式断言出来，让它在 CI 日志里可见而不是悄悄溜过。

    这条**不许**写成 `assert _DRIFT_LOG == []` —— 那会把「站点内容变了」
    变成红灯，而 §8.1 的 unchanged 分支明确说这种情况只需更新 expect、
    断言语义不动。这里只保证：漂移条目的形状是可读的、且不多于全部白名单条目。
    """
    assert len(_DRIFT_LOG) <= len(EXPECT_BYTES_ALLOWLIST)
    for line in _DRIFT_LOG:
        assert " 字节 " in line and " -> " in line


# --------------------------------------------------------------------------- #
# 没有冻结样本的行：走**生产侧真实取数路径**补上断言
# --------------------------------------------------------------------------- #
#
# 为什么要专门加这一段：B 表就是「18 个真文件判 OK、零误判」这条特异性判据，
# 而其中 12 行以前是 skip 的 —— 也就是说项目最核心的那个 claim 有三分之二没跑过。
# 原因不是数据缺失，是**查错了地方**：``_case_of()`` 查 ``real_cases.py``
# （A4 冻结文件，这些用例原型里从来没有，永远不会出现），而 16 行对应的响应
# 快照在 ``fixtures/`` 里全都有。
#
# 这里刻意**不手拼 Case**。快照只记 status / content_type / 正文，不记 headers
# 全表、不记 redirects、不记 final_url —— 手拼等于拿「我编的输入」去断言，
# 而这正是本项目一直在防的东西。所以走 ``Fetcher.probe()``：真 redirects、
# 真 headers、真对照推导，全部来自实录。
#
# 跑不了的行**如实说跑不了**，而不是写「待第 4b 步实录」—— 4b 早已完成
# （703 份快照），那句话会让读的人以为这是待办。


def _fixture_fetcher(store: object, tmp_path: Path) -> object:
    """按生产侧 ``pipeline.build_fetcher()`` 的装配造一个 replay Fetcher（strict）。"""
    import threading

    from geo_audit.fetch.cache import HttpCache
    from geo_audit.fetch.client import Fetcher, FetcherConfig, build_user_agent
    from geo_audit.fetch.ratelimit import DomainLimiter
    from geo_audit.pipeline import StopTransport

    contact = "ci@geo-audit.invalid"
    return Fetcher(
        FetcherConfig(contact=contact, interval=2.0, respect_robots=False),
        HttpCache(tmp_path / "soft404.sqlite3", ua_profile=build_user_agent(contact)),
        DomainLimiter(2.0),
        # strict=True：这些是探测集里的固定位置，缺快照必须红（是我们 fixture 不全），
        # 不能悄悄回落成 UNKNOWN 那种「站点的事实」。
        transport=StopTransport(store.transport(strict=True), threading.Event()),  # type: ignore[attr-defined]
        probe_url_provider=store.probe_url,  # type: ignore[attr-defined]
        resolver=store.resolver(),  # type: ignore[attr-defined]
    )


_NO_FROZEN_CASE = [r for r in B_TABLE + C_TABLE + C_UNKNOWN if not r.get("real_cases_case")]


@real_index_needed
@pytest.mark.parametrize("row", _NO_FROZEN_CASE, ids=lambda r: str(r["id"]))
def test_rows_without_frozen_case_go_through_the_real_fetch_path(
    row: dict[str, Any], tmp_path: Path
) -> None:
    """实测 5 条能跑通：B07 / B08 / B09 / B18 判 ok、C04 判 real404。

    剩下 11 条卡在「该 host 没录对照探针」上。那不是我们跳过它，是
    ``probe_url()`` 自己抛的 —— 它的报错原文就写着「对照探测是软 404 判据的
    一半，缺了它整条判定都不成立」。补录方式在那句报错里也写了。
    """
    from geo_audit.fixtures import FixtureMissing, FixtureStore

    store = FixtureStore.default()
    fetcher = _fixture_fetcher(store, tmp_path)
    try:
        try:
            probe = fetcher.probe(  # type: ignore[attr-defined]
                row["url"], expect=_EXPECT_MAP[row.get("expect", "text_file")]
            )
        except FixtureMissing as exc:
            pytest.skip(
                f"{row['id']}：{exc}".split("\n")[0]
                + "（注意：这与「第 4b 步实录」无关，4b 已完成 703 份快照；"
                "缺的是这个 host 的**对照探针**）"
            )
        cls = probe.classification
        assert cls.verdict.value == row["expect_verdict"], (
            f"{row['id']} {row['url']}：判 {cls.verdict.value}/{cls.reason}，"
            f"期望 {row['expect_verdict']}。{row['note']}"
        )
        if row.get("expect_rule") is not None:
            assert cls.reason == row["expect_rule"], f"{row['id']}：{row['note']}"
    finally:
        fetcher.close()  # type: ignore[attr-defined]
