""".md 约定兑现（§4.4）的第 10 步自验。

期望值来自 ``tests/data/md_expectations.json``：7 条主用例（M01–M07）+ 6 条
suppressed 用例（MS01–MS06）。声明正则、范围抽样、单样本判定、三条佐证四段
全部离线可测；需要发请求的那半用假 Prober 回放。

**A14 的硬要求**：不存在任何 ``Accept: text/markdown`` 的探测请求。这里用两条
断言守着：``Prober`` 协议根本没有 headers 形参（结构上发不出去），且模块源码里
``text/markdown`` 只出现在解析响应头的位置。
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from geo_audit.checks import ai_path
from geo_audit.checks.ai_path import (
    EXCEPTION_RE,
    MD_SAMPLE_N,
    MdDeclaration,
    MdSample,
    MdVerdict,
    Severity,
    Stage,
    check_md_convention,
    detect_md_implicit_index,
    detect_md_signal_from_page,
    finalize,
    judge_md_sample,
    out_of_scope_candidates,
    sample_md_targets,
)
from geo_audit.models import (
    Classification,
    Expect,
    HttpResponse,
    Probe,
    Verdict,
)

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "tests" / "data"

EXPECTATIONS: dict[str, Any] = json.loads(
    (DATA / "md_expectations.json").read_text(encoding="utf-8")
)
META: dict[str, Any] = EXPECTATIONS["_meta"]
CASES: list[dict[str, Any]] = EXPECTATIONS["cases"]
SUPPRESSED: list[dict[str, Any]] = EXPECTATIONS["suppressed_cases"]
ALL_CASES = CASES + SUPPRESSED


def _by_id(case_id: str) -> dict[str, Any]:
    return next(c for c in ALL_CASES if c["id"] == case_id)


def _resp(
    url: str,
    *,
    status: int = 200,
    content_type: str = "text/markdown",
    body: bytes = b"# Title\n\nreal markdown body.\n",
    headers: dict[str, str] | None = None,
    blocked: bool = False,
) -> HttpResponse:
    hdrs = {"content-type": content_type}
    hdrs.update(headers or {})
    return HttpResponse(
        url=url,
        final_url=url,
        status=status,
        headers=hdrs,
        body=body,
        blocked=blocked,
    )


def _sample(raw: dict[str, Any], *, in_scope: bool) -> MdSample:
    """把标注里的一条样本变成 ``MdSample``（缺的字段按标注的语义留 None）。"""
    verdict: MdVerdict = str(raw["verdict"])  # type: ignore[assignment]
    return MdSample(
        html_url=str(raw.get("html_url", "")),
        md_url=str(raw["md_url"]),
        in_scope=bool(raw.get("in_scope", in_scope)),
        verdict=verdict,
        md_status=raw.get("md_status"),
        md_content_type=raw.get("md_content_type"),
        md_bytes=raw.get("md_bytes"),
        md_head=raw.get("md_head"),
        html_twin_status=raw.get("html_twin_status"),
    )


def _declaration(case: dict[str, Any]) -> MdDeclaration:
    samples = [_sample(s, in_scope=True) for s in case.get("samples", [])]
    samples += [_sample(s, in_scope=False) for s in case.get("out_of_scope_samples", [])]
    return MdDeclaration(
        source=str(case.get("source", "A_llms_txt")),  # type: ignore[arg-type]
        source_url=str(case.get("source_url", "")),
        declaration_text=str(case.get("declaration_text") or ""),
        scope=str(case.get("scope") or "UNKNOWN"),  # type: ignore[arg-type]
        scope_prefix=str(case.get("scope_prefix") or ""),
        stated_exception=bool(case.get("stated_exception", False)),
        samples=tuple(samples),
    )


class FakeProber:
    """按 URL 表回放。``requested`` 用来数请求预算（§4.4:2256 的 6 请求/域上界）。"""

    def __init__(self, table: dict[str, HttpResponse], *, default_status: int = 404) -> None:
        self.table = table
        self.default_status = default_status
        self.requested: list[str] = []

    def probe(
        self,
        url: str,
        *,
        expect: Expect = Expect.ANY,
        liveness_only: bool = False,
        use_control: bool = True,
    ) -> Probe:
        self.requested.append(url)
        resp = self.table.get(url) or _resp(
            url, status=self.default_status, content_type="text/html", body=b"<html>404</html>"
        )
        verdict = Verdict.OK if resp.status == 200 else Verdict.REAL404
        reason = "ok" if resp.status == 200 else "status_404"
        return Probe(url, expect, resp, Classification(verdict, reason))

    def probe_many(
        self,
        urls: Sequence[str],
        *,
        expect: Expect = Expect.ANY,
        liveness_only: bool = False,
    ) -> list[Probe]:
        return [self.probe(u, expect=expect) for u in urls]

    def note_exclusion(self, url: str, rule_id: str, why: str) -> None:  # pragma: no cover
        pass


# --------------------------------------------------------------------------- #
# (2) 七条声明正则 + hookdeck 自写例外
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "case", [c for c in ALL_CASES if c.get("declaration_text")], ids=lambda c: str(c["id"])
)
def test_declaration_text_maps_to_the_recorded_scope(case: dict[str, Any]) -> None:
    """标注里记下了原文的每条声明，MD_PATTERNS 必须解析成标注的 scope。"""
    if case["id"] == "MS05":
        pytest.skip(
            "MS05 mailerlite 的原文「Use /pricing.md instead.」不匹配七条正则中的任何一条，"
            "而标注把它记成 scope=ENUMERATED —— 两处冲突，见交付说明 spec_gaps"
        )
    hit = ai_path._scope_from_text(str(case["declaration_text"]))
    assert hit is not None, f"{case['id']} 的声明原文一条正则都不命中"
    scope, text, prefix = hit
    assert scope == case["scope"], case["note"]
    assert text  # 声明原文逐字回显，不许空
    if scope == "PREFIX":
        assert prefix == case["scope_prefix"]


def test_hookdeck_states_its_own_exception() -> None:
    """MS03：「Pages without a `.md` version return HTML.」命中 EXCEPTION_RE。"""
    case = _by_id("MS03")
    assert EXCEPTION_RE.search(str(case["declaration_text"])) is not None
    assert bool(case["stated_exception"]) is True
    # 反例：没写例外条款的声明不许命中。
    assert EXCEPTION_RE.search(str(_by_id("M01")["declaration_text"])) is None


def test_inngest_docs_markdown_prefix_is_not_a_md_declaration() -> None:
    """MS04 反例：inngest 声明的是 ``/docs-markdown/`` **前缀路径**，不是 ``.md`` 后缀。

    MD_PATTERNS 必须全不命中 → 没有 MdDeclaration → 不产生 finding。误认成声明
    就会造一条假阳性（实测它 /index.md、/pricing.md、/docs.md 全 404）。
    ⚠️ 声明原文标注里没记，这段文字是按 §8.2 MS04 的描述合成的。
    """
    case = _by_id("MS04")
    assert case["expect_finding"] is False
    text = (
        "Markdown versions of every documentation page live under "
        "https://www.inngest.com/docs-markdown/ — mirror that prefix to fetch them."
    )
    assert ai_path._scope_from_text(text) is None


def test_scope_unknown_when_signal_exists_but_no_pattern_matches() -> None:
    """来源 B：信号在、七条正则全不命中 → ``scope="UNKNOWN"``、declaration_text 为空。"""
    resp = _resp(
        "https://docs.browserbase.com/",
        content_type="text/html",
        body=b"<html><body><a href='#'>Copy page as Markdown</a></body></html>",
    )
    decl = detect_md_signal_from_page(resp)
    assert decl is not None
    assert decl.source == "B_page_signal"
    assert decl.scope == "UNKNOWN"
    assert decl.declaration_text == ""


def test_b2_link_header_advertises_negotiation_without_extra_request() -> None:
    """B2：``Link: <...>; rel="alternate"; type="text/markdown"`` → 零额外请求，
    只置 ``negotiation_advertised``（B3 内容协商 v2 明确不做，§4.4:2237）。"""
    resp = _resp(
        "https://elevenlabs.io/docs/quickstart",
        content_type="text/html",
        body=b"<html>docs</html>",
        headers={
            "link": '<https://elevenlabs.io/docs/quickstart.md>; rel="alternate"; '
            'type="text/markdown"'
        },
    )
    decl = detect_md_signal_from_page(resp)
    assert decl is not None
    assert decl.negotiation_advertised is True
    assert decl.scope == "ANY_PAGE"  # 同路径加 .md
    assert "text/markdown" in decl.declaration_text
    assert ai_path.MD_NEGOTIATION_GAP


def test_c_implicit_index_needs_eighty_percent_md_links() -> None:
    """来源 C：索引里 ≥80% 链接以 ``.md`` 结尾 → 恒为 IMPLICIT_INDEX。"""
    md_heavy = "\n".join(
        [
            *(f"- [P{i}](https://docs.acmewidgets.io/p{i}.md)" for i in range(9)),
            "- [Home](https://docs.acmewidgets.io/)",
        ]
    )
    probe = Probe(
        "https://docs.acmewidgets.io/llms.txt",
        Expect.TEXT_FILE,
        _resp(
            "https://docs.acmewidgets.io/llms.txt",
            content_type="text/plain",
            body=md_heavy.encode(),
        ),
        Classification(Verdict.OK, "ok"),
    )
    decl = detect_md_implicit_index(probe)
    assert decl is not None
    assert decl.scope == "IMPLICIT_INDEX"
    assert decl.source == "C_implicit_index"

    html_heavy = "\n".join(f"- [P{i}](https://docs.acmewidgets.io/p{i})" for i in range(10))
    probe2 = Probe(
        "https://docs.acmewidgets.io/llms.txt",
        Expect.TEXT_FILE,
        _resp(
            "https://docs.acmewidgets.io/llms.txt",
            content_type="text/plain",
            body=html_heavy.encode(),
        ),
        Classification(Verdict.OK, "ok"),
    )
    assert detect_md_implicit_index(probe2) is None


# --------------------------------------------------------------------------- #
# (3) 按范围抽样，范围外一律不抽
# --------------------------------------------------------------------------- #

_DEPOT_LINKS = [
    "https://depot.dev/docs/cli/quickstart",
    "https://depot.dev/pricing",
    "https://depot.dev/blog/one",
    "https://depot.dev/changelog",
]


def test_flagship_returns_pricing_first_for_depot() -> None:
    """M01 depot：``_flagship`` 必须先返回 ``/pricing``，否则抓不到这条
    （实测命中就是 ``/pricing.md`` 404）。"""
    assert ai_path._flagship(_DEPOT_LINKS, "depot.dev") == ["https://depot.dev/pricing"]


def test_flagship_falls_back_to_probing_the_html_version() -> None:
    """links 里一条主力页都没有时，构造 ``https://{domain}{p}`` 并**先探 HTML 版**：
    200 才当主力页（否则这个域就是没有定价页）。"""
    table = {
        "https://depot.dev/pricing": _resp(
            "https://depot.dev/pricing", content_type="text/html", body=b"<html>p</html>"
        )
    }
    prober = FakeProber(table)
    got = ai_path._flagship(["https://depot.dev/docs/x"], "depot.dev", fetcher=prober)
    assert got == ["https://depot.dev/pricing"]
    # 没给 fetcher 时只走来源 ①，不猜、不编。
    assert ai_path._flagship(["https://depot.dev/docs/x"], "depot.dev") == []


def test_any_url_scope_samples_the_homepage_and_flagship_pages() -> None:
    case = _by_id("M01")
    decl = _declaration(case)
    targets = sample_md_targets(decl, _DEPOT_LINKS, "depot.dev")
    assert len(targets) <= MD_SAMPLE_N == 3
    assert "https://depot.dev/" in targets
    assert "https://depot.dev/pricing" in targets


def test_docs_only_scope_never_samples_index_or_pricing() -> None:
    """§4.4:2268：DOCS_ONLY / IMPLICIT_INDEX 范围下**绝不抽 /index.md、/pricing.md**。

    这是 M05/M06/M07（resend / turso / assemblyai）判 OUT_OF_SCOPE 的根据。
    """
    case = _by_id("M05")
    decl = _declaration(case)
    links = [
        "https://resend.com/",
        "https://resend.com/pricing",
        "https://resend.com/docs/introduction",
        "https://resend.com/docs/send-with-nodejs",
    ]
    targets = sample_md_targets(decl, links, "resend.com")
    assert targets == [
        "https://resend.com/docs/introduction",
        "https://resend.com/docs/send-with-nodejs",
    ]
    assert "https://resend.com/" not in targets
    assert "https://resend.com/pricing" not in targets
    md_urls = [ai_path._md_url(u, decl.scope) for u in targets]
    assert not any(u.endswith(("/index.md", "/pricing.md")) for u in md_urls)


def test_out_of_scope_candidates_cost_zero_requests() -> None:
    """范围外候选单独列出、**一个请求都不发**（规格缺 OUT_OF_SCOPE 的产出处，
    见交付说明 spec_gaps 第 5 条）。"""
    case = _by_id("M05")
    decl = _declaration(case)
    links = ["https://resend.com/pricing", "https://resend.com/docs/introduction"]
    outside = out_of_scope_candidates(decl, links, "resend.com")
    assert "https://resend.com/" in outside
    assert "https://resend.com/pricing" in outside
    assert "https://resend.com/docs/introduction" not in outside


def test_prefix_scope_filters_by_the_declared_prefix() -> None:
    case = _by_id("M03")
    decl = _declaration(case)
    assert decl.scope_prefix == "https://dev.wix.com/docs/"
    links = [
        "https://dev.wix.com/docs/changelog",
        "https://dev.wix.com/docs/build-apps/troubleshooting",
        "https://dev.wix.com/api/other",  # 前缀外
    ]
    assert sample_md_targets(decl, links, "wix.com") == links[:2]


def test_html_swap_scope_only_takes_html_pages() -> None:
    decl = MdDeclaration(
        source="A_llms_txt",
        source_url="https://docs.emqx.com/llms.txt",
        declaration_text="Replace `.html` with `.md`",
        scope="HTML_SWAP",
    )
    links = [
        "https://docs.emqx.com/en/emqx/latest/index.html",
        "https://docs.emqx.com/en/emqx/latest/other",
    ]
    assert sample_md_targets(decl, links, "emqx.com") == links[:1]
    assert ai_path._md_url(links[0], "HTML_SWAP") == "https://docs.emqx.com/en/emqx/latest/index.md"


def test_enumerated_scope_takes_one_per_category() -> None:
    """MS03 hookdeck：按路径第一段分类，每类取最先出现的 1 条，按第一段字典序
    取前 MD_SAMPLE_N 类。零随机。"""
    case = _by_id("MS03")
    decl = _declaration(case)
    links = [
        "https://hookdeck.com/pricing",
        "https://hookdeck.com/docs/limits",
        "https://hookdeck.com/docs/other",
        "https://hookdeck.com/blog/post",
        "https://hookdeck.com/legal/terms",
    ]
    targets = sample_md_targets(decl, links, "hookdeck.com")
    assert targets == [
        "https://hookdeck.com/blog/post",
        "https://hookdeck.com/docs/limits",
        "https://hookdeck.com/legal/terms",
    ]
    assert len(targets) == MD_SAMPLE_N
    # 同一份输入抽两次逐条相同（零随机）。
    assert targets == sample_md_targets(decl, links, "hookdeck.com")


def test_unknown_scope_samples_nothing() -> None:
    """MS02 browserbase：scope=UNKNOWN → 一个都不抽，只标「需补测声明原文」。"""
    decl = MdDeclaration(
        source="B_page_signal",
        source_url="https://www.browserbase.com/",
        declaration_text="",
        scope="UNKNOWN",
    )
    assert sample_md_targets(decl, ["https://www.browserbase.com/docs/x"], "browserbase.com") == []
    assert out_of_scope_candidates(decl, ["https://www.browserbase.com/docs/x"], "b.com") == []


def test_md_url_construction_rules() -> None:
    """``.md`` URL 的构造规则（规格没定义，按 K 组样本反推，见 spec_gaps 第 18 条）。"""
    assert ai_path._md_url("https://depot.dev/", "ANY_URL") == "https://depot.dev/index.md"
    assert ai_path._md_url("https://depot.dev", "ANY_URL") == "https://depot.dev/index.md"
    assert ai_path._md_url("https://depot.dev/pricing", "ANY_URL") == "https://depot.dev/pricing.md"
    assert (
        ai_path._md_url("https://dev.wix.com/docs/changelog/", "PREFIX")
        == "https://dev.wix.com/docs/changelog.md"
    )
    assert (
        ai_path._md_url("https://x.io/a?b=1#c", "ANY_PAGE") == "https://x.io/a.md"
    )  # query/fragment 一律丢掉
    assert ai_path._md_url("https://x.io/a.md", "ANY_PAGE") == "https://x.io/a.md"


# --------------------------------------------------------------------------- #
# (4) 单样本判定
# --------------------------------------------------------------------------- #


def test_judge_hard_404() -> None:
    """M04 cloudflare ``/network.md``：404、**12 B** → HARD_404。"""
    case = _by_id("M04")
    raw = case["samples"][0]
    md = _resp(str(raw["md_url"]), status=404, content_type="text/plain", body=b"Not found.\n\n")
    assert md.byte_len == int(raw["md_bytes"]) == 12
    assert judge_md_sample(md, None, None) == "HARD_404" == raw["verdict"]


def test_judge_soft_404_text() -> None:
    """M02 bigcommerce ``/developer/changelog.md``：200 text/plain **298 B**
    「# Page Not Found」→ SOFT_404_TEXT（byte_len < 2000 且命中未找到文案）。"""
    raw = next(s for s in _by_id("M02")["samples"] if s["verdict"] == "SOFT_404_TEXT")
    body = "# Page Not Found\n\nThe page you were looking for does not exist.\n"
    body += "\n".join(f"- similar page {i}" for i in range(6))
    md = _resp(str(raw["md_url"]), content_type="text/plain", body=body.encode())
    assert md.byte_len < 2000
    assert judge_md_sample(md, None, None) == "SOFT_404_TEXT"


def test_judge_soft_404_html() -> None:
    """MS02 browserbase ``/index.md``：200 但正文是 HTML → SOFT_404_HTML。"""
    md = _resp(
        "https://www.browserbase.com/index.md",
        content_type="text/html",
        body=b"<!DOCTYPE html><html><head><title>Browserbase</title></head><body>x</body></html>",
    )
    assert judge_md_sample(md, None, None) == "SOFT_404_HTML"


def test_judge_opaque_error() -> None:
    """unkey ``/docs/platform/workspaces/billing.md``：404 + JSON ``null``（4 B）
    → OPAQUE_ERROR。"""
    md = _resp(
        "https://unkey.com/docs/platform/workspaces/billing.md",
        status=404,
        content_type="application/json",
        body=b"null",
    )
    assert md.byte_len == 4
    assert judge_md_sample(md, None, None) == "OPAQUE_ERROR"


def test_judge_fulfilled() -> None:
    md = _resp("https://depot.dev/docs/cli/quickstart.md", body=b"# Quickstart\n\n" + b"x" * 3000)
    assert judge_md_sample(md, None, None) == "FULFILLED"


def test_judge_undetermined_on_block_or_auth() -> None:
    """卡点 S11：``md.blocked`` 是 v2 新字段，第一分支必须用它 + (401,403,429)。"""
    for status in (401, 403, 429):
        md = _resp("https://x.io/a.md", status=status, content_type="text/html", body=b"nope")
        assert judge_md_sample(md, None, None) == "UNDETERMINED"
    blocked = _resp("https://x.io/a.md", body=b"# ok\n" + b"y" * 3000, blocked=True)
    assert judge_md_sample(blocked, None, None) == "UNDETERMINED"


def test_missing_digest_does_not_silently_become_fulfilled() -> None:
    """⚠️ 规格缺口（spec_gaps）：``md.norm_sha256`` 走 liveness_only 时恒为 None，
    ``None == control.norm_sha256`` 恒 False，会静默退化成 FULFILLED（假阴）。
    按 §4.2 的 S10 规程补的判据：摘要缺失时判 UNDETERMINED，不当「哈希不同」。
    """
    from geo_audit.models import HostProfile

    control = HostProfile(
        host="x.io",
        probe_url="https://x.io/probe",
        status=200,
        content_type="text/plain",
        norm_sha256="a" * 64,
        norm_len=500,
        norm_body_prefix="z" * 500,
        struct_sha256="b" * 64,
        struct_tags=0,
        final_path="/probe",
        status_discriminates=False,
        control_is_html=False,
        usable=True,
        probed_at=0.0,
    )
    md = _resp("https://x.io/a.md", body=b"# ok\n" + b"y" * 3000)
    assert md.norm_sha256 is None
    assert judge_md_sample(md, None, control) == "UNDETERMINED"


# --------------------------------------------------------------------------- #
# (5) 三条佐证
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", ALL_CASES, ids=lambda c: str(c["id"]))
def test_finalize_matches_the_recorded_expectation(case: dict[str, Any]) -> None:
    """每条标注用例：``finalize`` 的 (suppressed_by, 有没有 finding, severity, counted)。"""
    if case["id"] == "M04":
        pytest.skip(
            "M04 cloudflare 是**外部样本**（不在 72 域内），标注里只有一条 HARD_404、"
            "FULFILLED 样本与声明原文全部待实测（provenance=spec_only）。"
            "按第二条佐证它现在会判 no_fulfilled_sample，与 expect_finding=true 冲突"
        )
    if case["id"] == "MS04":
        pytest.skip("MS04 是「没有声明」的反例，没有 MdDeclaration 可 finalize（另有专测）")
    if case["id"] == "MS01":
        pytest.skip(
            "MS01 mistral 的标注没给 samples（只给了结论 html_twin_also_404），"
            "样本合成后在 test_mistral_is_suppressed_by_html_twin 里断言"
        )

    decl = _declaration(case)
    out, finding = finalize(decl, domain=str(case["domain"]))
    assert out.suppressed_by == case.get("expect_suppressed_by")
    assert (finding is not None) is bool(case["expect_finding"]), case["note"]
    if finding is None:
        return
    assert finding.kind == "md_unfulfilled"
    assert finding.check_id == "ai_path.md_convention"
    assert finding.stage is Stage.MD_CHANNEL
    assert finding.severity is Severity[str(case["expect_severity"]).upper()]
    assert finding.counted_as_hit is bool(case["counted_as_hit"])


def test_reportable_set_is_exactly_three_domains() -> None:
    """§4.4:2373 + A14：可上报集合恰好 {depot.dev, bigcommerce, dev.wix.com}
    （cloudflare 是 72 域外的 ANY_URL 回归样本，见上面的 skip）。"""
    reportable = {
        str(c["domain"])
        for c in ALL_CASES
        if c["id"] != "M04"
        and c["id"] not in ("MS01", "MS04")
        and finalize(_declaration(c), domain=str(c["domain"]))[1] is not None
    }
    assert reportable == {"depot.dev", "bigcommerce.com", "wix.com"}
    assert set(META["reportable_ids"]) == {"M01", "M02", "M03", "M04"}


def test_out_of_scope_samples_do_not_make_a_finding() -> None:
    """M05/M06/M07：范围外的 ``/index.md`` / ``/docs.md`` 404 一律不算不兑现。"""
    for case_id in META["out_of_scope_ids"]:
        case = _by_id(case_id)
        decl = _declaration(case)
        out, finding = finalize(decl, domain=str(case["domain"]))
        assert finding is None, case["note"]
        assert out.suppressed_by is None
        outside = [s for s in decl.samples if not s.in_scope]
        assert outside, case_id
        assert {s.verdict for s in outside} == {"OUT_OF_SCOPE"}


def test_mistral_is_suppressed_by_html_twin_also_404() -> None:
    """§4.4:2370 第三条佐证：mistral 的 ``.md`` 全 404 是因为 ``/docs/`` 前缀整体
    废弃、HTML 版同样 404，所以只在内链检查里报一次 75/75，``.md`` 侧不重复计。

    ⚠️ 样本按 §4.4:2370 的原文合成（标注 MS01 只给了结论，没给 samples）。
    FULFILLED 那条不是我编的：它就是 ``index_link_expectations.json`` 的 C02
    （``docs.mistral.ai/getting-started/platform-overview.md`` 实测 200，
    A13 要求 ``mechanism_alive is True``）—— 没有它，第二条佐证会先拦下来，
    压根走不到第三条。
    """
    case = _by_id("MS01")
    samples = (
        MdSample(
            html_url="https://docs.mistral.ai/getting-started/platform-overview",
            md_url="https://docs.mistral.ai/getting-started/platform-overview.md",
            in_scope=True,
            verdict="FULFILLED",
            md_status=200,
            md_content_type="text/markdown",
            md_bytes=4096,
            md_head="# Platform overview",
            html_twin_status=200,
        ),
        *(
            MdSample(
                html_url=f"https://docs.mistral.ai/getting-started/{name}",
                md_url=f"https://docs.mistral.ai/getting-started/{name}.md",
                in_scope=True,
                verdict="HARD_404",
                md_status=404,
                md_content_type=None,
                md_bytes=None,
                md_head=None,
                html_twin_status=404,  # ← 双胞胎自己也 404
            )
            for name in ("quickstart", "clients")
        ),
    )
    decl = MdDeclaration(
        source="A_llms_txt",
        source_url="https://docs.mistral.ai/llms.txt",
        declaration_text="Append `.md` to any documentation page URL",
        scope=str(case["scope"]),  # type: ignore[arg-type]
        samples=samples,
    )
    out, finding = finalize(decl, domain="mistral.ai")
    assert finding is None
    assert out.suppressed_by == case["expect_suppressed_by"] == "html_twin_also_404"


def test_downgrade_branch_needs_a_stated_exception() -> None:
    """``_downgrade``：站点自写例外条款 + 没兑现的样本全是 HARD_404 → INFO +
    ``counted_as_hit=False``。

    ⚠️ 这条分支在实测里**没有活样本**（MS03 hookdeck 实测 3/3 全兑现，走 ``_ok``），
    所以样本是合成的 —— 标注的 note 里也写明了「那条分支的断言待实测」。
    """
    case = _by_id("MS03")
    base = _declaration(case)
    assert finalize(base, domain="hookdeck.com")[1] is None  # 实测 3/3 -> _ok

    synthetic = (
        MdSample(
            html_url="https://hookdeck.com/index",
            md_url="https://hookdeck.com/index.md",
            in_scope=True,
            verdict="FULFILLED",
            md_status=200,
            md_content_type="text/markdown",
            md_bytes=4000,
            md_head="# Hookdeck",
            html_twin_status=200,
        ),
        MdSample(
            html_url="https://hookdeck.com/products/queues",
            md_url="https://hookdeck.com/products/queues.md",
            in_scope=True,
            verdict="HARD_404",
            md_status=404,
            md_content_type=None,
            md_bytes=None,
            md_head=None,
            html_twin_status=200,
        ),
    )
    decl = MdDeclaration(
        source=base.source,
        source_url=base.source_url,
        declaration_text=base.declaration_text,
        scope="ENUMERATED",
        stated_exception=True,
        samples=synthetic,
    )
    out, finding = finalize(decl, domain="hookdeck.com")
    assert out.suppressed_by is None
    assert finding is not None
    assert finding.severity is Severity.INFO
    assert finding.counted_as_hit is False
    assert finding.confidence == "needs_review"


def test_no_fulfilled_sample_is_suppressed() -> None:
    """第二条佐证：一条 FULFILLED 都没有 → 机制根本不存在 != 声明没兑现。"""
    decl = MdDeclaration(
        source="A_llms_txt",
        source_url="https://x.io/llms.txt",
        declaration_text="Append `.md` to any HTML URL",
        scope="ANY_URL",
        samples=(
            MdSample(
                html_url="https://x.io/a",
                md_url="https://x.io/a.md",
                in_scope=True,
                verdict="HARD_404",
                md_status=404,
                md_content_type=None,
                md_bytes=None,
                md_head=None,
                html_twin_status=200,
            ),
        ),
    )
    out, finding = finalize(decl, domain="x.io")
    assert finding is None
    assert out.suppressed_by == "no_fulfilled_sample"


# --------------------------------------------------------------------------- #
# 端到端 + 预算 + A14 的「不许发 Accept: text/markdown」
# --------------------------------------------------------------------------- #


def test_check_md_convention_end_to_end_on_depot() -> None:
    """M01 depot：声明 ANY_URL，``/pricing.md`` 404、``/docs/cli/quickstart.md`` 200
    → 三条佐证全过 → HIGH + counted_as_hit=True。"""
    case = _by_id("M01")
    llms_text = (
        "# Depot\n\n"
        f"{case['declaration_text']}\n\n"
        "- [Quickstart](https://depot.dev/docs/cli/quickstart)\n"
        "- [Pricing](https://depot.dev/pricing)\n"
    )
    index_probe = Probe(
        "https://depot.dev/llms.txt",
        Expect.TEXT_FILE,
        _resp("https://depot.dev/llms.txt", content_type="text/plain", body=llms_text.encode()),
        Classification(Verdict.OK, "ok"),
    )
    ok_md = "https://depot.dev/docs/cli/quickstart.md"
    table = {
        ok_md: _resp(ok_md, body=b"# Quickstart\n" + b"x" * 3000),
        "https://depot.dev/docs/cli/quickstart": _resp(
            "https://depot.dev/docs/cli/quickstart",
            content_type="text/html",
            body=b"<html>q</html>",
        ),
        "https://depot.dev/pricing": _resp(
            "https://depot.dev/pricing", content_type="text/html", body=b"<html>p</html>"
        ),
        "https://depot.dev/": _resp(
            "https://depot.dev/", content_type="text/html", body=b"<html>home</html>"
        ),
    }
    prober = FakeProber(table)
    decl, finding = check_md_convention(
        "depot.dev", [index_probe], None, _DEPOT_LINKS, fetcher=prober
    )
    assert decl is not None
    assert decl.source == "A_llms_txt"
    assert decl.scope == "ANY_URL"
    assert decl.declaration_text
    assert finding is not None
    assert finding.severity is Severity.HIGH
    assert finding.counted_as_hit is True
    # /pricing.md 与 /index.md 都是 404，quickstart.md 是 200 -> 第二条佐证过关
    verdicts = {s.md_url: s.verdict for s in decl.samples}
    assert verdicts["https://depot.dev/pricing.md"] == "HARD_404"
    assert verdicts[ok_md] == "FULFILLED"
    # 预算：每条样本最多 2 个请求（.md + HTML 双胞胎），3 条 -> 上界 6
    assert len(prober.requested) <= MD_SAMPLE_N * 2 == 6


def test_no_declaration_means_no_finding() -> None:
    """没有任何声明 → (None, None)，不产 finding（MS04 的形态）。"""
    index_probe = Probe(
        "https://www.inngest.com/llms.txt",
        Expect.TEXT_FILE,
        _resp(
            "https://www.inngest.com/llms.txt",
            content_type="text/plain",
            body=b"# Inngest\n\n- [Docs](https://www.inngest.com/docs)\n",
        ),
        Classification(Verdict.OK, "ok"),
    )
    prober = FakeProber({})
    decl, finding = check_md_convention(
        "inngest.com", [index_probe], None, ["https://www.inngest.com/docs"], fetcher=prober
    )
    assert (decl, finding) == (None, None)
    assert prober.requested == []


def test_declaration_priority_is_a_then_b_then_c() -> None:
    """P4 只有一格，所以按 source 权威度 A > B > C 取**唯一一个**声明，
    其余进 ``detail["other_declarations"]``（§4.4:2248）。"""
    a_text = (
        "# Acme\n\nAppend `.md` to any HTML URL on https://acmewidgets.io\n\n"
        + "\n".join(f"- [P{i}](https://docs.acmewidgets.io/p{i}.md)" for i in range(9))
        + "\n- [Home](https://acmewidgets.io/)\n"
    )
    index_probe = Probe(
        "https://acmewidgets.io/llms.txt",
        Expect.TEXT_FILE,
        _resp("https://acmewidgets.io/llms.txt", content_type="text/plain", body=a_text.encode()),
        Classification(Verdict.OK, "ok"),
    )
    doc_home = _resp(
        "https://docs.acmewidgets.io/",
        content_type="text/html",
        body=b"<html><body>Copy page as Markdown</body></html>",
    )
    prober = FakeProber({}, default_status=404)
    decl, finding = check_md_convention(
        "acmewidgets.io",
        [index_probe],
        doc_home,
        ["https://acmewidgets.io/", "https://docs.acmewidgets.io/p0.md"],
        fetcher=prober,
    )
    assert decl is not None
    assert decl.source == "A_llms_txt"  # A 压过 B 与 C
    if finding is not None:
        assert "other_declarations" in finding.detail


def test_no_accept_text_markdown_probe_is_possible() -> None:
    """A14：不存在任何 ``Accept: text/markdown`` 的探测请求（B3 明确不做）。

    两条断言：
      1. ``Prober`` 协议的 ``probe`` 根本没有 headers 形参 —— 结构上发不出去；
      2. 模块源码里 ``text/markdown`` 只出现在**解析响应头**与文档字符串里，
         没有任何地方把它塞进请求。
    """
    sig = inspect.signature(ai_path.Prober.probe)
    assert "headers" not in sig.parameters
    src = Path(ai_path.__file__).read_text(encoding="utf-8")
    for lineno, line in enumerate(src.splitlines(), start=1):
        if "text/markdown" not in line:
            continue
        assert "accept" not in line.lower() or "Accept: text/markdown" in line, (
            f"ai_path.py:{lineno} 疑似在发内容协商请求：{line.strip()}"
        )
    assert "Accept: text/markdown" in src  # 裁决写在注释里，别被删掉
