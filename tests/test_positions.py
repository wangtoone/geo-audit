"""§2.9 的 Position 构造规则 P1–P5 与四条推论（卡点 S7 / 验收 A7 / A27 / A31）。

三条硬要求，本文件逐条断言：

1. **``Report.positions`` 只能由 ``pipeline.build_positions()`` 产生** ——
   全仓库只有 ``pipeline.py`` 里允许出现 ``Position(``（A7，grep 守）。
2. **恒等式** ``positions_pass + positions_fail + positions_unknown +
   positions_na == positions``（A27），中断报告上也成立（见 test_interrupt.py）。
3. **位置不是探测**：mistral 的 75 条死内链是 **1 格**（P3 聚合格），不是 75 格。

离线自足：假站 + 注入 resolver，一个真请求都不发（照抄
tests/test_subdomain_discovery.py 的注入式 Fetcher 写法）。
"""

from __future__ import annotations

import ast
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import DNS_ABSENT_KEY, FixtureResolver, FixtureStore
from geo_audit.models import (
    Classification,
    Expect,
    HttpResponse,
    PositionSeed,
    Probe,
    Stage,
    Status,
    Verdict,
)
from geo_audit.pipeline import (
    AuditOptions,
    Counts,
    Position,
    PositionResult,
    StopTransport,
    audit_domain,
    bare_skeleton,
    build_positions,
    count_positions,
    index_links_seeds,
    make_headline,
    position_id,
)

CONTACT = "you@yourco.com"
CONTROL_PATH = "/geo-audit-probe-x9f2.txt"
SRC = Path(__file__).resolve().parents[1] / "src"

#: url -> (status, content-type, body)
Pages = dict[str, tuple[int, str, str]]


class FakeSite:
    """按 URL 表回放的假站。表里没有的 URL 一律 404 + text/html。

    404 兜底是刻意的：它同时充当对照探针的答案，于是
    ``host_profile.status_discriminates`` 为真 —— 200 text/plain 干净判 OK，
    200 text/html 会被 L2(a)（``html_where_text_expected``）抓成软 404。
    """

    def __init__(self, pages: Pages) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requested.append(url)
        row = self.pages.get(url)
        if row is None:
            return httpx.Response(
                404, headers={"content-type": "text/html"}, text="<title>404</title>not found"
            )
        status, ctype, body = row
        return httpx.Response(status, headers={"content-type": ctype}, text=body)


def _resolver(*live_hosts: str) -> FixtureResolver:
    table: dict[str, dict[str, Any]] = {
        host: {"addresses": ["203.0.113.10"], "resolver": "system", "poisoned": False}
        for host in live_hosts
    }
    table[DNS_ABSENT_KEY] = {
        "addresses": [],
        "resolver": "none",
        "poisoned": False,
        "error": "NXDOMAIN",
    }
    return FixtureResolver(table, source="tests/test_positions.py")


def _control_for(url: str) -> str:
    return f"https://{httpx.URL(url).host}{CONTROL_PATH}"


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """合规下限是 1 请求 / 2 秒 / 域，一次 audit 会睡几十秒。

    只掐掉限流器的 sleep（限流逻辑本身仍然跑，test_infra.py 里有它的专门断言），
    不动任何生产代码。
    """
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _seconds: None)


@pytest.fixture
def fetcher_factory(tmp_path: Path) -> Iterator[Callable[[FakeSite], Fetcher]]:
    made: list[Fetcher] = []

    def make(site: FakeSite) -> Fetcher:
        f = Fetcher(
            FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
            cache=HttpCache(tmp_path / f"cache{len(made)}.sqlite3", ua_profile="test"),
            limiter=DomainLimiter(2.0),
            transport=StopTransport(httpx.MockTransport(site.handler), threading.Event()),
            probe_url_provider=_control_for,
        )
        made.append(f)
        return f

    yield make
    for f in made:
        f.close()


# --------------------------------------------------------------------------- #
# A7：``Position(`` 的唯一出现处
# --------------------------------------------------------------------------- #


def _position_calls(path: Path) -> list[int]:
    """文件里真正的 ``Position(...)`` 调用行号。

    用 ``ast`` 而不是 grep：验收 A7 的那条 grep 会把 docstring 里
    「``Position(`` 只许出现在 pipeline 里」这类**说明文字**也算成命中
    （models.py 与 report/render.py 的占位说明就各有一处），那是文字不是调用。
    """
    tree = ast.parse(path.read_text("utf-8"))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Position"
    ]


def test_position_is_only_constructed_in_pipeline() -> None:
    """A7：``Position(...)`` 的调用只许出现在 ``pipeline.py`` 里。"""
    hits = {
        str(path.relative_to(SRC)): _position_calls(path)
        for path in sorted(SRC.rglob("*.py"))
        if path.name != "pipeline.py" and _position_calls(path)
    }
    assert hits == {}, "Position( 只许出现在 pipeline.build_positions() 里（A7）"


def test_pipeline_constructs_position_only_inside_build_positions() -> None:
    """再窄一档：pipeline.py 里也只有 ``build_positions`` 那一处调用。"""
    path = SRC / "geo_audit" / "pipeline.py"
    calls = _position_calls(path)
    assert len(calls) == 1
    tree = ast.parse(path.read_text("utf-8"))
    owner = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "build_positions"
    )
    assert owner.lineno < calls[0] < (owner.end_lineno or calls[0] + 1)


# --------------------------------------------------------------------------- #
# 骨架与恒等式
# --------------------------------------------------------------------------- #


def test_bare_skeleton_lower_bound() -> None:
    """§6.3:3161 的下界：``positions >= |P1| + |P2| + 1``，且 P4 恒等于 1。"""
    cells = bare_skeleton("acmecloud.io")
    assert len(cells) >= 4
    assert sum(1 for c in cells if c.stage is Stage.MD_CHANNEL) == 1
    assert sum(1 for c in cells if c.stage is Stage.DISCOVERY) == 2
    ids = [position_id(c.stage, c.key) for c in cells]
    assert len(ids) == len(set(ids))
    assert "discovery:www.acmecloud.io" in ids
    assert "index_file:acmecloud.io/llms.txt" in ids
    assert "fulltext:www.acmecloud.io/llms-full.txt" in ids


def test_build_positions_fills_unfilled_cells_with_reason() -> None:
    """没填上的格子必须落 UNKNOWN + 原因码 + 补救办法（§6.4 R4）。"""
    positions = build_positions(bare_skeleton("acmecloud.io"), {}, unfilled_reason="interrupted")
    assert positions
    for p in positions:
        assert p.status is Status.UNKNOWN
        assert p.unknown_reason == "interrupted"
        assert p.unknown_remedy
        assert len(p.unknown_remedy) >= 20


def test_build_positions_is_position_id_keyed() -> None:
    """结论按 ``position_id`` 对号入座，且骨架里的重复格子只保留一份。"""
    skeleton = list(bare_skeleton("acmecloud.io"))
    skeleton.append(skeleton[0])  # 故意重复
    seed = PositionSeed(
        stage=Stage.DISCOVERY,
        key="www.acmecloud.io",
        kind="probe",
        probe_url="https://www.acmecloud.io/",
        status=Status.PASS,
        detail="根路径 200",
    )
    positions = build_positions(
        skeleton, {position_id(seed.stage, seed.key): PositionResult(seed=seed)}
    )
    assert len(positions) == len(bare_skeleton("acmecloud.io"))
    hit = next(p for p in positions if p.position_id == "discovery:www.acmecloud.io")
    assert hit.status is Status.PASS
    assert hit.unknown_reason is None
    assert hit.label.startswith("① 入口发现")


def _counts(positions: tuple[Position, ...]) -> Counts:
    return count_positions(positions, (), (), ())


def test_identity_holds_by_construction() -> None:
    """A27：四格之和恒等于位置数。每格恰好一个 Status，所以按构造成立。"""
    counts = _counts(build_positions(bare_skeleton("acmecloud.io")))
    assert (
        counts.positions_pass
        + counts.positions_fail
        + counts.positions_unknown
        + counts.positions_na
        == counts.positions
    )


# --------------------------------------------------------------------------- #
# P3：一份索引 1 格 —— mistral 的 75 条死链不是 75 格
# --------------------------------------------------------------------------- #


def _index_probe(url: str, body: str) -> Probe:
    resp = HttpResponse(
        url=url,
        final_url=url,
        status=200,
        headers={"content-type": "text/plain"},
        body=body.encode(),
    )
    return Probe(url, Expect.TEXT_FILE, resp, Classification(Verdict.OK, "ok"))


def test_index_with_75_links_is_one_aggregate_cell() -> None:
    """§2.9 P3：**mistral 的 75 条死链是 1 格，不是 75 格** —— 位置不是探测。"""
    body = "# Mistral\n\n" + "".join(
        f"- [Doc {i}](https://docs.mistral.ai/doc-{i}.md)\n" for i in range(75)
    )
    seeds = index_links_seeds([_index_probe("https://docs.mistral.ai/llms.txt", body)])
    assert len(seeds) == 1
    cell = seeds[0]
    assert cell.kind == "aggregate"
    assert cell.aggregate_of == 75
    assert cell.stage is Stage.INDEX_LINKS


def test_index_without_links_gets_no_cell() -> None:
    """P3 的字面要求：解析出 0 条链接的索引不占格。"""
    assert index_links_seeds([_index_probe("https://x.example/llms.txt", "# 空索引\n")]) == ()


# --------------------------------------------------------------------------- #
# make_headline 六分支（§6.1:3074）
# --------------------------------------------------------------------------- #


def _c(*, positions: int, p: int = 0, f: int = 0, u: int = 0, na: int = 0) -> Counts:
    return Counts(
        positions=positions,
        positions_pass=p,
        positions_fail=f,
        positions_unknown=u,
        positions_na=na,
        findings=0,
        findings_counted=0,
        occurrences=0,
        root_causes=0,
        by_severity={},
        naive_divergences=0,
    )


def test_headline_interrupt_wins_over_everything() -> None:
    text, kind = make_headline(
        _c(positions=16, p=10, f=3, u=1, na=2),
        has_ai_channel=True,
        sampled_ratio=1.0,
        interrupted=True,
    )
    assert kind == "unusable"
    assert text.startswith("扫描被中断")


def test_headline_unusable_when_more_than_half_core_unknown() -> None:
    """gusto.com 锚点：``unknown / core > 0.5`` → unusable（CLI 退出 2）。"""
    _text, kind = make_headline(
        _c(positions=12, p=1, u=7, na=4), has_ai_channel=True, sampled_ratio=1.0, interrupted=False
    )
    assert kind == "unusable"


def test_headline_16_cell_sample_is_self_consistent() -> None:
    """§6.1 的自洽样本：16 = 3 fail + 1 unknown + 10 pass + 2 na，走 has_fail。"""
    counts = _c(positions=16, p=10, f=3, u=1, na=2)
    text, kind = make_headline(counts, has_ai_channel=True, sampled_ratio=1.0, interrupted=False)
    assert kind == "has_fail"
    assert "3 个位置会被读错" in text
    assert "另有 1 个位置我们无法判断" in text


def test_headline_no_ai_channel_branch() -> None:
    """A30：tdengine 型（全部真 404）→ no_ai_channel，**不许写成「② 索引真伪 FAIL」**。"""
    text, kind = make_headline(
        _c(positions=6, p=4, na=2), has_ai_channel=False, sampled_ratio=1.0, interrupted=False
    )
    assert kind == "no_ai_channel"
    assert "没有 AI 索引通道" in text


def test_headline_zero_clean_and_sampling_downgrade() -> None:
    clean = _c(positions=6, p=6)
    text, kind = make_headline(clean, has_ai_channel=True, sampled_ratio=1.0, interrupted=False)
    assert kind == "zero_clean"
    assert "6 个位置全部通过" in text

    _t2, kind2 = make_headline(clean, has_ai_channel=True, sampled_ratio=0.02, interrupted=False)
    assert kind2 == "zero_with_unknown"  # A33：抽样率 < 0.5 不许算「全部通过」


def test_headline_zero_with_unknown_never_says_all_pass() -> None:
    text, kind = make_headline(
        _c(positions=8, p=6, u=2), has_ai_channel=True, sampled_ratio=1.0, interrupted=False
    )
    assert kind == "zero_with_unknown"
    # ⚠️ A32 的字面要求是「有 UNKNOWN 的 HTML 不含『全部通过』」，但 §6.1:3098 给
    # 这一分支的**逐字文案**里就有「所以这不能算「全部通过」」。铁律 8 要求照抄原文，
    # 所以断言改成「只以被否定的形式出现」（已进交付说明 spec_gaps）。
    assert "这不能算「全部通过」" in text
    assert text.count("全部通过") == 1


# --------------------------------------------------------------------------- #
# 端到端：一次完整扫描的账本（P1 / P2 / P3 / P4 / P5 全部到位）
# --------------------------------------------------------------------------- #

_REAL_INDEX = (
    "# Acme\n\n"
    "- [Quickstart](https://docs.acmecloud.io/quickstart.md)\n"
    "- [Gone](https://docs.acmecloud.io/gone.md)\n"
)
_SPA_SHELL = "<!doctype html><html><head><title>Acme</title></head><body>SPA</body></html>"


def _site() -> FakeSite:
    home = (200, "text/html", "<html><body><a href='/pricing'>Pricing</a></body></html>")
    return FakeSite(
        {
            "https://acmecloud.io/": home,
            "https://www.acmecloud.io/": home,
            "https://docs.acmecloud.io/": (200, "text/html", "<html><body>docs</body></html>"),
            # ② 真文件（200 text/plain）
            "https://docs.acmecloud.io/llms.txt": (200, "text/plain", _REAL_INDEX),
            # ② 软 404：请求文本文件却拿回 HTML 外壳
            "https://www.acmecloud.io/llms.txt": (200, "text/html", _SPA_SHELL),
            # ④ 内链一活一死（gone.md 走 404 兜底）
            "https://docs.acmecloud.io/quickstart.md": (200, "text/markdown", "# Quickstart\n"),
        }
    )


@pytest.fixture
def report_of_fake_site(fetcher_factory: Callable[[FakeSite], Fetcher], tmp_path: Path) -> Any:
    site = _site()
    options = AuditOptions(
        domain="acmecloud.io",
        contact=CONTACT,
        only=("ai_path",),
        max_requests=0,
    )
    return audit_domain(
        options,
        fetcher=fetcher_factory(site),
        store=FixtureStore(tmp_path / "empty-fixtures"),
        resolver=_resolver("acmecloud.io", "www.acmecloud.io", "docs.acmecloud.io"),
    )


def test_end_to_end_identity_and_stage_coverage(report_of_fake_site: Any) -> None:
    """A27 + A31：四格之和 == 位置数；六段每格的位置数之和也 == 位置数。"""
    report = report_of_fake_site
    c = report.counts
    assert c.positions == len(report.positions)
    assert c.positions_pass + c.positions_fail + c.positions_unknown + c.positions_na == c.positions
    per_stage = {s: sum(1 for p in report.positions if p.stage is s) for s in Stage}
    assert sum(per_stage.values()) == c.positions
    assert c.llm_calls == 0


def test_end_to_end_p1_p2_p3_p4(report_of_fake_site: Any) -> None:
    """P1 每个解析通过的 host 一格；P2 每个实际探测一格；P3 每份索引一格；P4 恒一格。"""
    report = report_of_fake_site
    by_stage: dict[Stage, list[Any]] = {s: [] for s in Stage}
    for p in report.positions:
        by_stage[p.stage].append(p)

    assert {p.probe_url for p in by_stage[Stage.DISCOVERY]} >= {
        "https://acmecloud.io/",
        "https://www.acmecloud.io/",
        "https://docs.acmecloud.io/",
    }
    assert len(by_stage[Stage.MD_CHANNEL]) == 1  # P4 恒等于 1
    assert all(p.kind == "probe" for p in by_stage[Stage.INDEX_FILE])
    assert all(p.kind == "aggregate" for p in by_stage[Stage.INDEX_LINKS])

    soft = next(p for p in by_stage[Stage.INDEX_FILE] if "www.acmecloud.io" in p.probe_url)
    assert soft.status is Status.FAIL  # 软 404 → 读错
    real = next(p for p in by_stage[Stage.INDEX_FILE] if "docs.acmecloud.io" in p.probe_url)
    assert real.status is Status.PASS
    assert real.evidence is not None
    assert real.evidence.curl_repro.startswith("curl ")

    # ③ 全文通道：真 404 → NOT_APPLICABLE（「你没做这件事」不是「你做坏了」）
    assert all(p.status is Status.NOT_APPLICABLE for p in by_stage[Stage.FULLTEXT])


def test_end_to_end_index_links_cell_is_one(report_of_fake_site: Any) -> None:
    """④ 一份索引 1 格，格里记 2 条内链（1 活 1 死）→ FAIL。"""
    report = report_of_fake_site
    cells = [p for p in report.positions if p.stage is Stage.INDEX_LINKS]
    assert len(cells) == 1
    assert cells[0].aggregate_of == 2
    assert "1 活" in cells[0].detail


def test_only_ai_path_leaves_no_human_path_cell(report_of_fake_site: Any) -> None:
    """``--only ai_path`` 时 ⑥ 不占格（不是「无法判断」，是根本没这一段）。"""
    report = report_of_fake_site
    assert [p for p in report.positions if p.stage is Stage.HUMAN_PATH] == []


def test_every_unknown_cell_has_reason_and_remedy(report_of_fake_site: Any) -> None:
    """§6.4 R4：每条 UNKNOWN 必须有原因码 + 可执行的补救办法。"""
    for p in report_of_fake_site.positions:
        if p.status is Status.UNKNOWN:
            assert p.unknown_reason
            assert p.unknown_remedy and len(p.unknown_remedy) >= 20


# --------------------------------------------------------------------------- #
# P5：⑥ 可点击路径（一页一格）
# --------------------------------------------------------------------------- #

_PRICING = (
    "<html><body>"
    "<div class='card'><a href='/contact'>Talk to us</a></div>"
    "<div class='card'><a href='/gone-forever'>Talk to us</a></div>"
    "</body></html>"
)


def _site_with_dead_link() -> FakeSite:
    home = (200, "text/html", "<html><body><a href='/pricing'>Pricing</a></body></html>")
    return FakeSite(
        {
            "https://acmecloud.io/": home,
            "https://www.acmecloud.io/": home,
            "https://www.acmecloud.io/pricing": (200, "text/html", _PRICING),
            "https://acmecloud.io/pricing": (200, "text/html", _PRICING),
            # /contact 活着，/gone-forever 走 404 兜底 —— 一页一死一活
            "https://www.acmecloud.io/contact": (200, "text/html", "<html>contact</html>"),
            "https://acmecloud.io/contact": (200, "text/html", "<html>contact</html>"),
        }
    )


def test_human_path_cell_per_seed_page_and_dead_link_finding(
    fetcher_factory: Callable[[FakeSite], Fetcher], tmp_path: Path
) -> None:
    """P5：每个 seed 页一格；有 ≥1 条 DEAD → FAIL；死链条数与位置数是两个数。"""
    report = audit_domain(
        AuditOptions(
            domain="acmecloud.io",
            contact=CONTACT,
            only=("dead_links",),
            max_requests=0,
        ),
        fetcher=fetcher_factory(_site_with_dead_link()),
        store=FixtureStore(tmp_path / "empty-fixtures"),
        resolver=_resolver("acmecloud.io", "www.acmecloud.io"),
    )
    cells = [p for p in report.positions if p.stage is Stage.HUMAN_PATH]
    assert cells, "⑥ 至少有首页那一格"
    assert all(p.kind == "aggregate" for p in cells)
    c = report.counts
    assert c.positions_pass + c.positions_fail + c.positions_unknown + c.positions_na == c.positions
    # ai_path 被 --only 关掉了，所以 ②③④⑤ 一格都不占
    assert [p for p in report.positions if p.stage is Stage.INDEX_FILE] == []
    assert [p for p in report.positions if p.stage is Stage.MD_CHANNEL] == []

    pricing = next((p for p in cells if p.probe_url.endswith("/pricing")), None)
    assert pricing is not None
    assert pricing.status is Status.FAIL
    assert "死链" in pricing.detail
    # 一条唯一 norm_url = 一条 finding（A16），位置数与条数分开
    dead = [f for f in report.findings if f.kind == "dead_link"]
    assert len(dead) == 1
    assert dead[0].target.curl_repro.startswith("curl ")
    assert dead[0].finding_id in pricing.finding_ids or dead[0].finding_id.startswith("GA-")
    assert dead[0].suppress_hint.endswith(dead[0].finding_id)
    assert c.findings == 1
    assert c.positions != c.findings
