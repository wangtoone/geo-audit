"""第 9 步自验：索引内链存活（§4.3）。

期望值来自 ``tests/data/index_link_expectations.json``（C01–C12 + extra 四条形态样本）。
``parse_index_links`` / ``sample_index_links`` / ``grade`` 是纯函数，**离线全量可测**；
需要发请求的那半用一个假 Prober 回放（断网闸开着，一个真请求都不许发）。
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from geo_audit.checks.ai_path import (
    INDEX_LINKS_DETAIL_KEYS,
    INDEX_LINKS_FULL_THRESHOLD,
    INDEX_LINKS_SAMPLE_SIZE,
    IndexLink,
    Severity,
    Stage,
    check_index_links,
    extract_index_links,
    grade,
    normalize_url,
    parse_index_links,
    probe_index_links,
    sample_index_links,
)
from geo_audit.models import (
    Classification,
    Expect,
    HostProfile,
    HttpResponse,
    Probe,
    Status,
    Verdict,
)

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "tests" / "data"

EXPECTATIONS: dict[str, Any] = json.loads(
    (DATA / "index_link_expectations.json").read_text(encoding="utf-8")
)
META: dict[str, Any] = EXPECTATIONS["_meta"]
CASES: list[dict[str, Any]] = EXPECTATIONS["cases"]
EXTRA: list[dict[str, Any]] = EXPECTATIONS["extra"]
INDEX_CASES = [c for c in CASES + EXTRA if c["kind"] == "index"]

_STATUS = {"pass": Status.PASS, "fail": Status.FAIL, "unknown": Status.UNKNOWN}


def _by_id(case_id: str) -> dict[str, Any]:
    return next(c for c in CASES + EXTRA if c["id"] == case_id)


# --------------------------------------------------------------------------- #
# 假 Prober（断网闸下的回放）
# --------------------------------------------------------------------------- #


class FakeProber:
    """只实现 ``Prober`` 协议的三个方法。按 URL 表回放判定，记录发过的请求。"""

    def __init__(self, verdicts: dict[str, Verdict], *, default: Verdict = Verdict.OK) -> None:
        self.verdicts = verdicts
        self.default = default
        self.requested: list[str] = []
        self.exclusions: list[tuple[str, str, str]] = []

    def probe(
        self,
        url: str,
        *,
        expect: Expect = Expect.ANY,
        liveness_only: bool = False,
        use_control: bool = True,
    ) -> Probe:
        self.requested.append(url)
        verdict = self.verdicts.get(url, self.default)
        status = {
            Verdict.OK: 200,
            Verdict.REAL404: 404,
            Verdict.SOFT404: 200,
            Verdict.BLOCKED: 429,
            Verdict.UNKNOWN: 500,
        }[verdict]
        reason = {
            Verdict.OK: "ok",
            Verdict.REAL404: "status_404",
            Verdict.SOFT404: "html_where_text_expected",
            Verdict.BLOCKED: "rate_limited",
            Verdict.UNKNOWN: "server_error",
        }[verdict]
        resp = HttpResponse(
            url=url,
            final_url=url,
            status=status,
            headers={"content-type": "text/html"},
            body=b"x",
        )
        return Probe(url, expect, resp, Classification(verdict, reason))  # type: ignore[arg-type]

    def probe_many(
        self,
        urls: Sequence[str],
        *,
        expect: Expect = Expect.ANY,
        liveness_only: bool = False,
    ) -> list[Probe]:
        return [self.probe(u, expect=expect, liveness_only=liveness_only) for u in urls]

    def note_exclusion(self, url: str, rule_id: str, why: str) -> None:
        self.exclusions.append((url, rule_id, why))


def _index_probe(index_url: str, text: str) -> Probe:
    resp = HttpResponse(
        url=index_url,
        final_url=index_url,
        status=200,
        headers={"content-type": "text/plain"},
        body=text.encode(),
    )
    return Probe(index_url, Expect.TEXT_FILE, resp, Classification(Verdict.OK, "ok"))


def _catch_all_host(host: str) -> HostProfile:
    """platform.kimi.ai 型 host：随机路径也返回 2xx → ``status_discriminates=False``。"""
    return HostProfile(
        host=host,
        probe_url=f"https://{host}/docs/geo-audit-probe",
        status=200,
        content_type="text/html",
        norm_sha256="0" * 64,
        norm_len=400,
        norm_body_prefix="quickstart " * 40,
        struct_sha256="1" * 64,
        struct_tags=120,
        final_path="/docs/geo-audit-probe",
        status_discriminates=False,
        control_is_html=True,
        usable=True,
        probed_at=0.0,
    )


# --------------------------------------------------------------------------- #
# grade()：12 条 C 组 + extra 全部按标注跑
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", INDEX_CASES, ids=lambda c: f"{c['id']}-{c['domain']}")
def test_grade_matches_the_recorded_expectation(case: dict[str, Any]) -> None:
    """每条 index 用例的 (n_alive, n_dead, n_unknown) → (status, severity, counted)。"""
    if case.get("n_dead") is None:
        pytest.skip(f"{case['id']} 只是抽取器形态样本，没记存活三元组")
    status, severity, counted = grade(
        int(case["n_alive"]), int(case["n_dead"]), int(case["n_unknown"])
    )
    assert status is _STATUS[str(case["expect_status"])], case["note"]
    assert severity is Severity[str(case["expect_severity"]).upper()]
    assert counted is bool(case["counted_as_hit"])


def test_seven_domains_have_at_least_one_dead_internal_link() -> None:
    """§4.3:2149：有 ≥1 条死内链的域恰好 **7** 个 = 11.5%（分母 61）。"""
    dead_domains = {str(c["domain"]) for c in INDEX_CASES if int(c.get("n_dead") or 0) >= 1}
    assert dead_domains == set(META["domains_with_dead_internal_links"])
    assert len(dead_domains) == 7
    assert round(7 / 61 * 100, 1) == 11.5


def test_over_threshold_set_conflicts_with_grade_and_grade_wins() -> None:
    """⚠️ 规格自相矛盾（见交付说明 spec_gaps 第 3 条）：

    §4.3:2149 与 A13 说「过阈值的只有 1 个（mistral）」，而同一节 ``grade()`` 的
    第二分支注释自己把 replicate（6 条 /index）与 inngest（3 条拼接）写成那一分支
    的锚点 —— 全量口径下至少三个域 ``counted_as_hit=True``。

    这里断言 ``grade()`` 的机械结果（可执行的那一半），并把两个集合的差异写进断言，
    差异一旦被裁决掉这条测试就会红。
    """
    counted = {
        str(c["domain"])
        for c in INDEX_CASES
        if c.get("n_dead") is not None
        and grade(int(c["n_alive"]), int(c["n_dead"]), int(c["n_unknown"]))[2]
    }
    assert (
        counted
        == set(META["counted_as_hit_domains"])
        == {
            "mistral.ai",
            "replicate.com",
            "inngest.com",
        }
    )
    # 「索引整体作废」那一支（denom >= 10 且 ratio >= 0.90）确实只有 mistral。
    wiped = {
        str(c["domain"])
        for c in INDEX_CASES
        if c.get("n_dead") is not None
        and int(c["n_alive"]) + int(c["n_dead"]) >= 10
        and int(c["n_dead"]) / (int(c["n_alive"]) + int(c["n_dead"])) >= 0.90
    }
    assert wiped == set(META["over_threshold_domains"]) == {"mistral.ai"}


def test_grade_boundaries() -> None:
    """三条分支的边界，逐条对着 §4.3:2135 的注释。"""
    assert grade(10, 0, 5) == (Status.PASS, Severity.INFO, False)  # 零死链
    assert grade(0, 75, 0) == (Status.FAIL, Severity.HIGH, True)  # mistral 75/75
    assert grade(4, 6, 0) == (Status.FAIL, Severity.HIGH, True)  # replicate 6 条 /index
    assert grade(5, 3, 0) == (Status.FAIL, Severity.HIGH, True)  # inngest 3 条拼接
    assert grade(9, 1, 0) == (Status.PASS, Severity.LOW, False)  # pingcap 1 条 -> 轻度
    assert grade(9, 2, 0) == (Status.PASS, Severity.LOW, False)  # 2 条仍是轻度
    assert grade(2, 0, 8) == (Status.PASS, Severity.INFO, False)  # pipedrive：8 条不进分母
    assert grade(0, 0, 0) == (Status.PASS, Severity.INFO, False)  # 一条都没判成


# --------------------------------------------------------------------------- #
# 四条抽取器：五种实测形态
# --------------------------------------------------------------------------- #


def test_bare_url_extractor_saves_turso() -> None:
    """C07 turso：整份文件零 markdown 语法。只用 ``](url)`` 的朴素抽取器读出 **0 条**
    并误判成空文件 —— bare 抽取器必须命中。"""
    case = _by_id("C07")
    text = "\n".join(
        [
            "# Turso",
            "https://turso.tech/docs",
            "https://turso.tech/pricing",
            "https://docs.turso.tech/quickstart",
        ]
    )
    naive = [m for m in parse_index_links(text, str(case["index_url"])) if m.extractor != "bare"]
    links = parse_index_links(text, str(case["index_url"]))
    assert len(naive) == 0, "朴素抽取器（只认 markdown 语法）在这份文件上读出 0 条"
    assert len(links) == 3
    assert {link.extractor for link in links} == {"bare"} == {str(case["extractor"])}


def test_relative_links_use_the_index_final_url_as_base() -> None:
    """C08 bytebase / mailerlite：相对路径**以该 llms.txt 的 final_url 为 base**
    绝对化，不以 apex 为 base。"""
    case = _by_id("X-idx-mailerlite-relative")
    index_url = str(case["index_url"])  # https://developers.mailerlite.com/llms.txt
    links = parse_index_links("- [Getting started](/getting-started)", index_url)
    assert len(links) == 1
    assert links[0].extractor == str(case["extractor"]) == "relative"
    assert links[0].abs_url == "https://developers.mailerlite.com/getting-started"
    assert links[0].anchor_text is None or links[0].anchor_text == ""


def test_html_a_extractor_handles_inline_markup() -> None:
    """attio /customers/llms.txt 与 close help/llms.txt 正文里直接嵌裸 HTML <a>。"""
    case = _by_id("X-idx-attio-html-a")
    text = "<a href=\"https://attio.com/customers/acme\">Acme</a> and <a href='/customers/b'>B</a>"
    links = parse_index_links(text, str(case["index_url"]))
    assert [link.extractor for link in links] == ["html_a", "html_a"]
    assert links[1].abs_url == "https://attio.com/customers/b"


def test_backtick_artifacts_are_right_stripped() -> None:
    """C06 zilliz：朴素正则把反引号吃进 URL 造成 **2 条假失败**，右剥后真实 8/8 全活。

    右剥要挡的形态是「URL 尾巴上粘了一个引号/反引号/右括号/句号」。这里三条都是
    实测里出现过的粘法。
    """
    case = _by_id("C06")
    text = "\n".join(
        [
            "- [A](https://docs.zilliz.com/a`)",  # 反引号被吃进 markdown 的 url 组
            "- [B](https://docs.zilliz.com/b”)",  # 中文右引号
            "See https://docs.zilliz.com/c, and more.",  # 裸 URL 后跟逗号
        ]
    )
    links = parse_index_links(text, str(case["index_url"]))
    assert [link.abs_url for link in links] == [
        "https://docs.zilliz.com/a",
        "https://docs.zilliz.com/b",
        "https://docs.zilliz.com/c",
    ]
    assert not any(link.abs_url.endswith(("`", ".", ",", "'", '"', "”")) for link in links)


def test_backtick_wrapped_bare_urls_are_skipped_by_the_frozen_regex() -> None:
    """⚠️ 规格后果，记在交付说明里：``LINK_RE_BARE`` 的负向回顾
    ``(?<![(<"'`])`` 会让**反引号开头**的裸 URL 整条不被抽取（不是被右剥）。

    方向是安全的（少判死链，不会造假失败），但代价是代码块里的裸 URL 一律不验 ——
    这是一条覆盖缺口，不是 bug。正则是规格逐字给定的，本步不改它。
    """
    text = "Run `https://docs.zilliz.com/z` in your terminal."
    assert parse_index_links(text, "https://docs.zilliz.com/llms.txt") == []


def test_double_scheme_is_not_split() -> None:
    """C11 inngest：一个 URL 两个 scheme，抽取阶段**不拆**，打 ``double_scheme``。

    拆开会造出站上并不存在的两个 URL，而我们要报的缺陷恰恰是「模板把两个 URL
    拼在一起了」（卡点 A16:2104）。
    """
    case = _by_id("C11")
    dead = [str(u) for u in case["dead_urls"]]
    text = "\n".join(f"- [Docs]({u})" for u in dead)
    links = parse_index_links(text, str(case["index_url"]))
    assert len(links) == len(dead) == 3
    assert {link.artifact for link in links} == {"double_scheme"} == {str(case["expect_artifact"])}
    assert [link.abs_url for link in links] == dead


def test_extractor_dedup_is_by_norm_url_and_keeps_occurrences() -> None:
    """A16：同一 norm_url 出现多次 → ``parse_index_links`` 去重成 1 条，
    但 ``extract_index_links`` 保留全部实例（occurrences 的原料）。"""
    text = "\n".join(
        [
            "- [A](https://acme.invalid/a)",
            "- [A again](https://acme.invalid/a/)",  # 去尾斜杠后同一个 norm_url
            "- [A utm](https://acme.invalid/a?utm_source=x)",  # 丢跟踪参数后同一个
            "- [B](https://acme.invalid/b)",
        ]
    )
    raw = extract_index_links(text, "https://acme.invalid/llms.txt")
    deduped = parse_index_links(text, "https://acme.invalid/llms.txt")
    assert len(raw) == 4
    assert len(deduped) == 2
    assert normalize_url("https://acme.invalid/a?utm_source=x") == normalize_url(
        "https://acme.invalid/a/"
    )


def test_mailto_and_anchor_are_not_links() -> None:
    text = "[mail](mailto:a@b.invalid) [frag](#section) [ok](https://acme.invalid/x)"
    links = parse_index_links(text, "https://acme.invalid/llms.txt")
    assert [link.abs_url for link in links] == ["https://acme.invalid/x"]


# --------------------------------------------------------------------------- #
# 等距抽样（零随机数，卡点 A13）
# --------------------------------------------------------------------------- #


def _fake_links(n: int) -> list[IndexLink]:
    return [
        IndexLink(
            line_no=i + 1,
            abs_url=f"https://acme.invalid/p{i}",
            norm_url=f"https://acme.invalid/p{i}",
            anchor_text=None,
            extractor="markdown",
        )
        for i in range(n)
    ]


def test_full_probe_under_threshold() -> None:
    """<= 120 条全量（mistral 才 75 条，全量成本可控）。"""
    links = _fake_links(INDEX_LINKS_FULL_THRESHOLD)
    sample, sampled = sample_index_links(links)
    assert sampled is False
    assert sample == links
    assert len(_fake_links(75)) == 75
    assert sample_index_links(_fake_links(75))[1] is False


def test_bytebase_504_links_are_sampled_to_sixty() -> None:
    """C08 bytebase：504 条 > 120 → 抽 60 条 = 前 20 + 中段等距 20 + 后 20。"""
    case = _by_id("C08")
    total = int(case["sampled_of"])
    assert total == 504
    links = _fake_links(total)
    sample, sampled = sample_index_links(links, domain=str(case["domain"]))
    assert sampled is True
    assert len(sample) == INDEX_LINKS_SAMPLE_SIZE == 60
    assert sample[:20] == links[:20]
    assert sample[-20:] == links[-20:]
    # 中段等距：步长 = (504-40)//20 = 23，完全由 index 决定。
    mid = links[20:-20]
    assert sample[20:40] == mid[:: max(len(mid) // 20, 1)][:20]


def test_sampling_is_deterministic_without_a_seed() -> None:
    """同一份输入抽两次逐条相同 —— 不用随机数，所以不需要种子（卡点 A13）。"""
    links = _fake_links(300)
    first, _ = sample_index_links(links)
    second, _ = sample_index_links(links)
    assert first == second
    # 换一份输入必须换一份抽样结果（证明它不是常量）。
    other, _ = sample_index_links(_fake_links(301))
    assert [link.abs_url for link in other] != [link.abs_url for link in first]


# --------------------------------------------------------------------------- #
# 端到端：去噪、分母、findings 粒度
# --------------------------------------------------------------------------- #


def test_saleor_template_placeholder_is_excluded_before_any_request() -> None:
    """C05 saleor：``.../docs/{path}.mdx`` 必须被 ``url_template_placeholder`` 排除，
    **一个请求都不发**，也不进分母。"""
    case = _by_id("C05")
    placeholder = str(case["excluded"][0]["url_shape"])
    text = "\n".join(
        [f"- [Docs]({placeholder})", *(f"- [P{i}](https://saleor.io/p{i})" for i in range(6))]
    )
    prober = FakeProber({}, default=Verdict.OK)
    report = probe_index_links(
        str(case["domain"]), _index_probe(str(case["index_url"]), text), fetcher=prober
    )
    assert report.n_links == 7 == int(case["n_links"])
    assert report.n_excluded == 1 == int(case["n_excluded"])
    assert report.n_alive == 6 == int(case["n_alive"])
    assert report.n_dead == 0
    assert placeholder not in prober.requested
    assert prober.exclusions[0][1] == str(case["excluded"][0]["expect_rule"])
    assert report.status is Status.PASS


def test_pipedrive_unknowns_stay_out_of_the_denominator() -> None:
    """C09 pipedrive：10 条里 8 条 429 → 进 unknown，分母剔掉它们，
    **一条都不许折算成 alive**。"""
    case = _by_id("C09")
    blocked = [f"https://www.pipedrive.com/p{i}" for i in range(8)]
    alive = ["https://devcommunity.pipedrive.com/x", "https://readme.io/y"]
    text = "\n".join(f"- [L]({u})" for u in [*blocked, *alive])
    prober = FakeProber(dict.fromkeys(blocked, Verdict.BLOCKED), default=Verdict.OK)
    report = probe_index_links(
        str(case["domain"]), _index_probe(str(case["index_url"]), text), fetcher=prober
    )
    assert (report.n_alive, report.n_dead, report.n_unknown) == (2, 0, 8)
    assert (report.n_alive, report.n_dead, report.n_unknown) == (
        int(case["n_alive"]),
        int(case["n_dead"]),
        int(case["n_unknown"]),
    )
    assert report.status is Status.PASS
    assert "rate_limited" in report.unknown_reasons
    assert (
        check_index_links(
            str(case["domain"]),
            _index_probe(str(case["index_url"]), text),
            fetcher=FakeProber(dict.fromkeys(blocked, Verdict.BLOCKED), default=Verdict.OK),
        )
        == ()
    )


def test_mistral_index_is_wiped_and_the_mechanism_is_alive() -> None:
    """C01 + C02：75/75 全死 → FAIL/HIGH/counted，且 ``mechanism_alive is True``
    （.md 机制本身活着，所以这是「路径废弃」不是「机制不存在」，A13 要这条）。"""
    case, mech = _by_id("C01"), _by_id("C02")
    dead = [f"https://docs.mistral.ai/guide/{i}.md" for i in range(75)]
    text = "\n".join(f"- [G{i}]({u})" for i, u in enumerate(dead))
    mech_probe = Probe(
        str(mech["url"]),
        Expect.ANY,
        HttpResponse(
            url=str(mech["url"]),
            final_url=str(mech["url"]),
            status=200,
            headers={"content-type": "text/markdown"},
            body=b"# Platform overview",
        ),
        Classification(Verdict.OK, "ok"),
    )
    report = probe_index_links(
        str(case["domain"]),
        _index_probe(str(case["index_url"]), text),
        fetcher=FakeProber(dict.fromkeys(dead, Verdict.REAL404)),
        mechanism_probe=mech_probe,
    )
    assert (report.n_links, report.n_dead, report.n_alive) == (75, 75, 0)
    assert report.sampled is False  # 75 <= 120 -> 全量
    assert report.status is Status.FAIL
    assert report.severity is Severity.HIGH
    assert report.counted_as_hit is True
    assert report.mechanism_alive is True
    assert bool(mech["expect_mechanism_alive"]) is True


def test_mechanism_alive_is_none_when_not_probed() -> None:
    """没传对照页时 ``mechanism_alive`` 是 None（「没测过」，不是 False）。"""
    text = "- [a](https://acme.invalid/a)"
    report = probe_index_links(
        "acme.invalid", _index_probe("https://acme.invalid/llms.txt", text), fetcher=FakeProber({})
    )
    assert report.mechanism_alive is None


def test_inngest_triple_is_three_findings_one_locus_three_occurrences() -> None:
    """C11 的硬断言：三元组 ``(findings=3, root_causes=1, occurrences=3)``。

    ⚠️ ``root_causes`` 的归并器是第 13 步的 ``rootcause.py``（别的 agent），这里只能
    断言它成立的**前提**：三条共享同一个 locus（同一份 llms.txt）与同一个抽取形态
    （``double_scheme`` → ``template_concat`` 指纹）。归并本身在第 13 步断言。
    """
    case = _by_id("C11")
    dead = [str(u) for u in case["dead_urls"]]
    alive = [f"https://www.inngest.com/docs/{i}" for i in range(5)]
    text = "\n".join(f"- [L]({u})" for u in [*dead, *alive])
    findings = check_index_links(
        str(case["domain"]),
        _index_probe(str(case["index_url"]), text),
        fetcher=FakeProber(dict.fromkeys(dead, Verdict.REAL404), default=Verdict.OK),
    )
    triple = case["expect_triple"]
    assert len(findings) == int(triple["findings"]) == 3
    assert sum(f.occurrences for f in findings) == int(triple["occurrences"]) == 3
    # root_causes=1 的前提：同一个 locus + 同一个缺陷形态。
    assert {f.found_on for f in findings} == {str(case["index_url"])}
    assert len({f.finding_id for f in findings}) == 3  # 三个不同 norm_url -> 三个身份
    for f in findings:
        assert f.kind == "index_link_dead"
        assert f.check_id == "ai_path.index_links"
        assert f.stage is Stage.INDEX_LINKS
        assert f.severity is Severity.HIGH
        assert f.counted_as_hit is True


def test_light_findings_are_listed_but_not_counted() -> None:
    """C03 pingcap / C12 factorialhr：1 条死链 → LOW + ``counted_as_hit=False``，
    ``display_value`` 含「轻度」——列出来但不进分子（§4.3:2147）。"""
    case = _by_id("C03")
    dead = [str(u) for u in case["dead_urls"]]
    alive = [f"https://www.pingcap.com/p{i}" for i in range(9)]
    text = "\n".join(f"- [L]({u})" for u in [*dead, *alive])
    (f,) = check_index_links(
        str(case["domain"]),
        _index_probe(str(case["index_url"]), text),
        fetcher=FakeProber(dict.fromkeys(dead, Verdict.REAL404), default=Verdict.OK),
    )
    assert f.severity is Severity.LOW
    assert f.counted_as_hit is False
    assert "轻度" in f.display_value
    assert set(f.detail) >= set(INDEX_LINKS_DETAIL_KEYS)


def test_detail_keys_are_five_plus_two_optional() -> None:
    """detail 五个固定键；抽样时才多 ``sampled`` / ``sampled_of``。"""
    small = "\n".join(f"- [L](https://docs.acmewidgets.io/p{i})" for i in range(10))
    dead = ["https://docs.acmewidgets.io/p0"]
    (f,) = check_index_links(
        "acmewidgets.io",
        _index_probe("https://docs.acmewidgets.io/llms.txt", small),
        fetcher=FakeProber(dict.fromkeys(dead, Verdict.REAL404), default=Verdict.OK),
    )
    assert set(f.detail) == set(INDEX_LINKS_DETAIL_KEYS)

    big = "\n".join(f"- [L](https://docs.acmewidgets.io/q{i})" for i in range(200))
    (g, *_) = check_index_links(
        "acmewidgets.io",
        _index_probe("https://docs.acmewidgets.io/llms.txt", big),
        fetcher=FakeProber({"https://docs.acmewidgets.io/q0": Verdict.REAL404}, default=Verdict.OK),
    )
    assert set(g.detail) == set(INDEX_LINKS_DETAIL_KEYS) | {"sampled", "sampled_of"}
    assert g.detail["sampled"] is True
    assert g.detail["sampled_of"] == 200


def test_kimi_catch_all_host_marks_alive_claims_unreliable() -> None:
    """§4.3:2155 platform.kimi.ai：该 host 对任意路径返回 200、414,072 字节、
    同一个 Quickstart 壳 → ``status_discriminates=False`` →「全活」没有信息量。"""
    text = "\n".join(f"- [L](https://platform.kimi.ai/docs/p{i})" for i in range(8))
    report = probe_index_links(
        "kimi.ai",
        _index_probe("https://platform.kimi.ai/docs/llms.txt", text),
        fetcher=FakeProber({}, default=Verdict.OK),
        control=_catch_all_host("platform.kimi.ai"),
    )
    assert report.n_dead == 0
    assert report.status is Status.PASS
    assert report.alive_claims_unreliable is True

    ordinary = probe_index_links(
        "acme.invalid",
        _index_probe("https://acme.invalid/llms.txt", text),
        fetcher=FakeProber({}, default=Verdict.OK),
        control=None,
    )
    assert ordinary.alive_claims_unreliable is False


def test_no_findings_when_nothing_is_dead() -> None:
    """C06 zilliz / C07 turso / C08 bytebase：dead == 0 → PASS/INFO，零 finding。"""
    text = "\n".join(f"- [L](https://docs.zilliz.com/p{i})" for i in range(8))
    findings = check_index_links(
        "zilliz.com",
        _index_probe("https://docs.zilliz.com/llms.txt", text),
        fetcher=FakeProber({}, default=Verdict.OK),
    )
    assert findings == ()


def test_probe_uses_abs_url_but_identity_uses_norm_url() -> None:
    """§5.4:2840：探测用 ``abs_url`` 原样（服务端可能对 query 敏感），
    归并与 finding 身份用 ``norm_url``。"""
    raw = "https://docs.acmewidgets.io/p?utm_source=llms&keep=1"
    text = f"- [L]({raw})"
    prober = FakeProber({raw: Verdict.REAL404})
    (f,) = check_index_links(
        "acmewidgets.io",
        _index_probe("https://docs.acmewidgets.io/llms.txt", text),
        fetcher=prober,
    )
    assert prober.requested == [raw]  # 原样探
    assert "utm_source" not in f.finding_id
    assert normalize_url(raw) == "https://docs.acmewidgets.io/p?keep=1"


def test_reserved_example_domains_are_excluded_before_any_request() -> None:
    """去噪表接线的反向验证：``.invalid`` / ``example.com`` 这类保留域一个请求都不发。

    这也是本文件里的合成 URL**不能**用 ``.invalid`` 的原因 —— 用了就会被去噪掉，
    测试会变成「测了个我们自己编的空集」。
    """
    text = "- [L](https://acme.invalid/p0)\n- [M](https://example.com/x)"
    prober = FakeProber({}, default=Verdict.REAL404)
    report = probe_index_links(
        "acmewidgets.io",
        _index_probe("https://docs.acmewidgets.io/llms.txt", text),
        fetcher=prober,
    )
    assert report.n_links == 2
    assert report.n_excluded == 2
    assert report.n_dead == 0
    assert prober.requested == []
    assert {rule for _, rule, _ in prober.exclusions} == {"reserved_example_domain"}


def test_c03_c04_c12_ids_are_inferred_not_from_the_spec() -> None:
    """⚠️ 交付说明用：C03 / C04 / C12 三个 id 在方案原文里**没有定义**
    （§4.3/§8.2 只钉了 C01/C02/C05–C11），标注文件按「7 个有死内链的域必须全部
    有断言」补齐并标了 ``id_assignment=inferred``。这条测试守着那个标记别被悄悄抹掉。
    """
    inferred = {c["id"] for c in CASES if c.get("id_assignment") == "inferred"}
    assert inferred == {"C03", "C04", "C12"}
    assert "C03、C04、C12" in META["count_note"] or "C03/C04/C12" in META["count_note"]
