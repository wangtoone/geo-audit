"""首页 SEO 事实：只陈述、推断标明、读不到就写读不到（不是没问题）。"""

from __future__ import annotations

import pytest

from geo_audit.checks.seo_facts import (
    build_seo_facts,
    canonical_relation,
    delivery_hint,
    framework_signals,
)
from geo_audit.models import Classification, Expect, HttpResponse, Probe, Verdict

PROSE = "Real product copy about what we build. " * 60  # ~2300 字符


def _probe(body: str, *, status: int = 200, headers: dict[str, str] | None = None) -> Probe:
    h = {"content-type": "text/html; charset=utf-8", **(headers or {})}
    resp = HttpResponse(
        url="https://example.ai/",
        final_url="https://example.ai/",
        status=status,
        headers=h,
        body=body.encode(),
    )
    return Probe(
        "https://example.ai/", Expect.HTML_PAGE, resp, Classification(Verdict.OK, "ok", ())
    )


def test_full_page_facts() -> None:
    body = (
        "<html><head><title>Example</title>"
        '<meta name="description" content="d">'
        '<link rel="canonical" href="https://example.ai/">'
        '<link rel="alternate" hreflang="en" href="https://example.ai/">'
        '<link rel="alternate" hreflang="zh-CN" href="https://example.cn/">'
        f"</head><body><h1>Example</h1><main>{PROSE}</main></body></html>"
    )
    f = build_seo_facts("example.ai", _probe(body))
    assert f.raw_html_tier == "full"
    assert f.canonical_relation == "self"
    assert f.hreflang == ("en=https://example.ai/", "zh-cn=https://example.cn/")
    assert f.title == "Example" and f.h1 == ("Example",) and f.meta_description == "d"
    assert f.flags == ()


def test_canonical_to_another_host_and_noindex_are_flagged() -> None:
    body = (
        '<html><head><title>CN</title><meta name="robots" content="noindex,follow">'
        '<link rel="canonical" href="https://example.ai/">'
        f"</head><body><h1>CN</h1>{PROSE}</body></html>"
    )
    p = _probe(body)
    resp = p.response
    assert resp is not None
    cn = HttpResponse(
        url="https://example.cn/",
        final_url="https://example.cn/",
        status=200,
        headers=resp.headers,
        body=resp.body,
    )
    f = build_seo_facts("example.cn", Probe("https://example.cn/", p.expect, cn, p.classification))
    assert f.canonical_relation == "other_host"
    assert "canonical_other_host" in f.flags and "noindex" in f.flags


def test_shell_and_partial_tiers() -> None:
    shell = '<html><head><title>x</title></head><body><div id="root"></div></body></html>'
    f = build_seo_facts("example.ai", _probe(shell))
    assert f.raw_html_tier == "shell" and "shell_html" in f.flags and "h1_missing" in f.flags
    assert "spa_empty_root" in f.framework_signals
    partial = f"<html><head><title>x</title></head><body><h1>x</h1>{'word ' * 200}</body></html>"
    assert build_seo_facts("example.ai", _probe(partial)).raw_html_tier == "partial"


def test_unreadable_homepage_is_not_a_pass() -> None:
    blocked = Probe(
        "https://example.ai/",
        Expect.HTML_PAGE,
        None,
        Classification(Verdict.BLOCKED, "waf_status", ()),
    )
    f = build_seo_facts("example.ai", blocked)
    assert f.raw_html_tier == "unreadable" and f.unreadable_reason == "waf_status"
    assert f.flags == ()  # 没读到 ≠ 没问题：不产出任何「干净」标记，只写原因


@pytest.mark.parametrize(
    ("canonical", "relation"),
    [
        (None, "missing"),
        ("/", "self"),
        ("https://example.ai", "self"),
        ("https://example.ai/en", "other_path"),
        ("https://www.example.ai/", "other_host"),
        ("https://example.cn/", "other_host"),
    ],
)
def test_canonical_relation(canonical: str | None, relation: str) -> None:
    assert canonical_relation(canonical, "https://example.ai/") == relation


def test_framework_and_delivery_hints() -> None:
    assert framework_signals('<script id="__NEXT_DATA__">{}</script>') == ("nextjs",)
    assert delivery_hint({"x-vercel-cache": "HIT"}) == "prerendered_or_cached"
    assert delivery_hint({"cache-control": "private, no-store"}) == "dynamic"
    assert delivery_hint({}) is None
