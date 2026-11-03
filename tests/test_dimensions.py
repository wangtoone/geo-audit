"""首屏四维度：灰永远不折算成绿；红 > 黄 > 灰 > 绿；没有总分。"""

from __future__ import annotations

from geo_audit.checks.seo_facts import unreadable_facts
from geo_audit.dimensions import build_dimensions
from geo_audit.models import (
    CrawlerAccessFact,
    HostRobotsFacts,
    PageSeoFacts,
    Position,
    SitemapFacts,
    Stage,
    Status,
)

ALL = frozenset({"ai_path", "dead_links"})


def _page(host: str = "a.example.ai", **kw: object) -> PageSeoFacts:
    base: dict[str, object] = {
        "host": host,
        "url": f"https://{host}/",
        "final_url": f"https://{host}/",
        "status": 200,
        "title": "t",
        "h1": ("t",),
        "meta_description": None,
        "canonical": f"https://{host}/",
        "canonical_relation": "self",
        "noindex": False,
        "hreflang": (),
        "visible_text_len": 3000,
        "raw_html_tier": "full",
        "framework_signals": (),
        "delivery_hint": None,
        "flags": (),
        "unreadable_reason": None,
    }
    base.update(kw)
    return PageSeoFacts(**base)  # type: ignore[arg-type]


def _robots(
    host: str = "a.example.ai", *, readable: bool = True, baidu: str = "allowed"
) -> HostRobotsFacts:
    return HostRobotsFacts(
        host=host,
        status=200 if readable else 503,
        policy="parsed",
        readable=readable,
        why="" if readable else "5xx",
        sitemaps_declared=(),
        crawlers=(CrawlerAccessFact("Baiduspider", "search_engine", baidu),),
    )


def _sitemap(state: str, host: str = "a.example.ai", **kw: object) -> SitemapFacts:
    base: dict[str, object] = {
        "host": host,
        "state": state,
        "declared_in_robots": True,
        "url": None,
        "status": 403 if state == "blocked" else 200,
        "url_count": 5,
        "sample": (_page(),),
        "flags": (),
    }
    base.update(kw)
    return SitemapFacts(**base)  # type: ignore[arg-type]


def _pos(stage: Stage, status: Status, reason: str | None = None) -> Position:
    return Position(
        position_id=f"{stage.value}:x",
        stage=stage,
        label="x",
        probe_url="https://a.example.ai/x",
        status=status,
        detail="",
        kind="probe",
        unknown_reason=reason,
    )


def _by_key(dims: tuple[object, ...]) -> dict[str, object]:
    return {d.key: d for d in dims}  # type: ignore[attr-defined]


def test_shell_home_is_red_and_discloses_no_render_comparison() -> None:
    dims = build_dimensions(
        [],
        [_page(raw_html_tier="shell", flags=("shell_html",))],
        [_robots()],
        [_sitemap("ok")],
        checks=ALL,
    )
    d = _by_key(dims)["readable"]
    assert d.state == "red" and "空壳" in d.sentence  # type: ignore[attr-defined]
    assert "没有做渲染对比" in d.sentence  # type: ignore[attr-defined]
    assert d.not_dug >= 1  # type: ignore[attr-defined]


def test_unreadable_home_is_gray_never_green() -> None:
    dims = build_dimensions(
        [],
        [unreadable_facts("a.example.ai", "https://a.example.ai/", "waf_status")],
        [_robots()],
        [_sitemap("ok")],
        checks=ALL,
    )
    d = _by_key(dims)["readable"]
    assert d.state == "gray" and d.blocked == 1  # type: ignore[attr-defined]
    assert _by_key(dims)["indexable"].state == "gray"  # type: ignore[attr-defined]


def test_gray_three_way_split_for_indexable() -> None:
    dims = build_dimensions(
        [],
        [_page()],
        [_robots(readable=False)],
        [_sitemap("blocked"), _sitemap("absent", host="b.example.ai")],
        checks=ALL,
    )
    d = _by_key(dims)["indexable"]
    assert d.state == "gray"  # type: ignore[attr-defined]
    assert (d.not_dug, d.absent, d.blocked) == (1, 1, 1)  # type: ignore[attr-defined]


def test_noindex_and_search_engine_block_are_red_even_with_gray() -> None:
    dims = build_dimensions(
        [],
        [_page(noindex=True, flags=("noindex",))],
        [_robots(baidu="blocked_all")],
        [_sitemap("blocked")],
        checks=ALL,
    )
    d = _by_key(dims)["indexable"]
    assert d.state == "red"  # type: ignore[attr-defined]
    assert "noindex" in d.sentence and "Baiduspider" in d.sentence  # type: ignore[attr-defined]
    assert "另有没看到的" in d.sentence  # type: ignore[attr-defined]


def test_clean_facts_are_green_only_when_nothing_is_gray() -> None:
    dims = build_dimensions(
        [_pos(Stage.INDEX_FILE, Status.PASS), _pos(Stage.HUMAN_PATH, Status.PASS)],
        [_page()],
        [_robots()],
        [_sitemap("ok")],
        checks=ALL,
    )
    states = {d.key: d.state for d in dims}
    assert states == {
        "readable": "green",
        "indexable": "green",
        "ai_channel": "green",
        "dead_links": "green",
    }
    with_unknown = build_dimensions(
        [_pos(Stage.INDEX_FILE, Status.PASS), _pos(Stage.FULLTEXT, Status.UNKNOWN, "timeout")],
        [_page()],
        [_robots()],
        [_sitemap("ok")],
        checks=ALL,
    )
    assert {d.key: d.state for d in with_unknown}["ai_channel"] == "gray"


def test_no_channel_is_gray_absent_and_disabled_check_is_gray() -> None:
    dims = build_dimensions(
        [_pos(Stage.INDEX_FILE, Status.NOT_APPLICABLE)],
        [_page()],
        [_robots()],
        [_sitemap("ok")],
        checks=frozenset({"ai_path"}),
    )
    d = _by_key(dims)
    assert d["ai_channel"].state == "gray" and d["ai_channel"].absent == 1  # type: ignore[attr-defined]
    assert d["dead_links"].state == "gray"  # type: ignore[attr-defined]


def test_no_total_score_field() -> None:
    from dataclasses import fields

    from geo_audit.models import Report

    assert not [f.name for f in fields(Report) if "score" in f.name or "grade" in f.name]
