"""首屏门禁：「没看到」不许写成「没问题」（combos.converge.ai 的误报回归）。

误报的两个根因各有一条测试：

* ``make_headline`` 里 ``not has_ai_channel`` 排在 ``positions_unknown`` 之前，
  且 ``> 0.5`` 漏掉恰好一半（Combos：13 个位置、9 个不适用、核心 4 个里 2 个无法判断）；
* ``needs_js`` 的 host 被当成「不在线」，llms.txt / robots.txt / sitemap.xml 一个都不探。

门禁本身（``test_gate_*``）：只要 ``positions_unknown > 0``，首屏就不得含
「没有」「全部通过」。
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

from geo_audit.fetch import discovery
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.models import (
    NOT_EVALUATED_REASONS,
    Counts,
    Position,
    Stage,
    Status,
    unknown_category,
)
from geo_audit.pipeline import AuditOptions, audit_domain, make_headline, unknown_breakdown
from tests.test_subdomain_discovery import CONTACT, FakeSite, _control_for, _resolver

FORBIDDEN_WITH_UNKNOWN = ("没有", "全部通过")


def _counts(*, positions: int, p: int = 0, f: int = 0, u: int = 0, na: int = 0) -> Counts:
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


def _unknown(url: str, reason: str) -> Position:
    return Position(
        position_id=f"discovery:{url}",
        stage=Stage.DISCOVERY,
        label=f"① 入口发现 · {url}",
        probe_url=url,
        status=Status.UNKNOWN,
        detail="x",
        kind="probe",
        unknown_reason=reason,
    )


# --------------------------------------------------------------------------- #
# make_headline
# --------------------------------------------------------------------------- #


def test_combos_shape_exactly_half_unknown_is_unusable() -> None:
    """13 个位置 = 2 通过 + 2 无法判断 + 9 不适用 → core=4，2/4 恰好 0.5。"""
    positions = [
        _unknown("https://combos.converge.ai/", "needs_js"),
        _unknown("https://converge.ai/pricing", "needs_js"),
    ]
    text, kind = make_headline(
        _counts(positions=13, p=2, u=2, na=9),
        has_ai_channel=False,
        sampled_ratio=1.0,
        interrupted=False,
        unknown_positions=positions,
    )
    assert kind == "unusable"
    assert text.startswith("未能完整评估")
    assert "combos.converge.ai" in text and "converge.ai" in text
    assert "没挖到 2（needs_js ×2）" in text
    assert "没有 AI 索引通道" not in text


def test_unknown_outranks_no_ai_channel() -> None:
    """未过半的无法判断也不许落到「没有 AI 索引通道」。"""
    text, kind = make_headline(
        _counts(positions=12, p=5, u=1, na=6),
        has_ai_channel=False,
        sampled_ratio=1.0,
        interrupted=False,
        unknown_positions=[_unknown("https://docs.example.ai/", "timeout")],
    )
    assert kind == "zero_with_unknown"
    assert text.startswith("未能完整评估：1 个位置没看到")
    assert "docs.example.ai" in text
    assert "不下结论" in text
    assert "AI 索引通道" in text


def test_no_ai_channel_still_reported_when_nothing_unknown() -> None:
    text, kind = make_headline(
        _counts(positions=6, p=4, na=2), has_ai_channel=False, sampled_ratio=1.0, interrupted=False
    )
    assert kind == "no_ai_channel"
    assert "没有 AI 索引通道" in text


@pytest.mark.parametrize("has_ai_channel", [True, False])
@pytest.mark.parametrize("fail", [0, 2])
@pytest.mark.parametrize("unknown", [1, 2, 4, 9])
@pytest.mark.parametrize("sampled", [1.0, 0.1])
def test_gate_unknown_headline_never_asserts_absence_or_all_pass(
    has_ai_channel: bool, fail: int, unknown: int, sampled: float
) -> None:
    """CI 门禁：positions_unknown > 0 ⇒ 首屏不含「没有」「全部通过」。"""
    c = _counts(positions=20, p=4, f=fail, u=unknown, na=20 - 4 - fail - unknown)
    text, _kind = make_headline(
        c, has_ai_channel=has_ai_channel, sampled_ratio=sampled, interrupted=False
    )
    for bad in FORBIDDEN_WITH_UNKNOWN:
        assert bad not in text, f"{bad!r} in {text!r}"


# --------------------------------------------------------------------------- #
# 三类归并
# --------------------------------------------------------------------------- #


def test_every_not_evaluated_reason_has_a_category() -> None:
    blocked = {r for r in NOT_EVALUATED_REASONS if unknown_category(r) == "blocked"}
    assert blocked == {
        "waf_status",
        "waf_challenge_body",
        "waf_challenge_header",
        "rate_limited",
        "login_required",
        "robots_disallowed",
        "robots_unreadable",
    }
    for r in (*NOT_EVALUATED_REASONS, "interrupted"):
        assert unknown_category(r) in ("not_dug", "blocked")
    assert unknown_category("needs_js") == "not_dug"
    assert unknown_category("interrupted") == "not_dug"


def test_breakdown_groups_by_category_and_lists_hosts() -> None:
    text = unknown_breakdown(
        [
            _unknown("https://a.example.ai/", "needs_js"),
            _unknown("https://a.example.ai/x", "timeout"),
            _unknown("https://b.example.ai/", "waf_status"),
        ]
    )
    assert "a.example.ai、b.example.ai" in text
    assert "没挖到 2（needs_js ×1、timeout ×1）" in text
    assert "被拦 1（waf_status ×1）" in text


# --------------------------------------------------------------------------- #
# needs_js 的 host 照探文本文件
# --------------------------------------------------------------------------- #

_PROSE = (
    "<html><body><main>"
    + ("Example is a real product with real prose. " * 60)
    + "</main></body></html>"
)
_SHELL = (
    "<html><head><title>Combos</title></head><body>"
    '<div id="root"></div><script src="/assets/app.js"></script></body></html>'
)


def _combos_site() -> tuple[FakeSite, object]:
    hosts = ("example.ai", "www.example.ai", "combos.example.ai")
    pages = {f"https://{h}/": (200, "text/html", _PROSE) for h in hosts[:2]}
    pages["https://combos.example.ai/"] = (200, "text/html", _SHELL)
    # 子域的 llms.txt 是 SPA 外壳（200 text/html）：真实站点最常见的形态。
    pages["https://combos.example.ai/llms.txt"] = (200, "text/html", _SHELL)
    pages["https://combos.example.ai/robots.txt"] = (200, "text/plain", "User-agent: *\nAllow: /\n")
    return FakeSite(pages), _resolver(*hosts)


@pytest.fixture
def fetcher_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[FakeSite], Fetcher]]:
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _s: None)
    made: list[Fetcher] = []

    def make(site: FakeSite) -> Fetcher:
        f = Fetcher(
            FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
            cache=HttpCache(tmp_path / "c.sqlite3", ua_profile="test"),
            limiter=DomainLimiter(2.0),
            transport=httpx.MockTransport(site.handler),
            probe_url_provider=_control_for,
        )
        made.append(f)
        return f

    yield make
    for f in made:
        f.close()


def test_needs_js_host_still_gets_text_file_probes(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    site, resolver = _combos_site()
    sm = discovery.discover(
        fetcher_factory(site),
        "combos.example.ai",
        resolver=resolver,  # type: ignore[arg-type]
    )
    probed = {p.url for p in sm.ai_path_probes}
    assert "https://combos.example.ai/llms.txt" in probed
    assert "https://combos.example.ai/llms-full.txt" in probed
    assert "combos.example.ai" in sm.robots
    assert "combos.example.ai" in sm.sitemap_urls
    # 页面正文仍然读不了：根路径位置保持无法判断，不被「照探文本文件」冲成通过。
    entered = next(h for h in sm.hosts if h.host == "combos.example.ai")
    assert entered.reason == "needs_js"


def test_combos_shape_end_to_end_headline_does_not_misreport(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    site, resolver = _combos_site()
    report = audit_domain(
        AuditOptions(domain="combos.example.ai", contact=CONTACT, use_cache=False),
        fetcher=fetcher_factory(site),
        resolver=resolver,  # type: ignore[arg-type]
    )
    unknown = report.counts.positions_unknown
    assert unknown > 0, "needs_js 的入口位置必须保持无法判断"
    assert "没有 AI 索引通道" not in report.headline
    if unknown:
        for bad in FORBIDDEN_WITH_UNKNOWN:
            assert bad not in report.headline, report.headline
        assert "combos.example.ai" in report.headline


def test_combos_shape_seo_facts_mark_shell_and_unreadable_not_clean(
    fetcher_factory: Callable[[FakeSite], Fetcher],
) -> None:
    site, resolver = _combos_site()
    report = audit_domain(
        AuditOptions(domain="combos.example.ai", contact=CONTACT, use_cache=False),
        fetcher=fetcher_factory(site),
        resolver=resolver,  # type: ignore[arg-type]
    )
    by_host = {f.host: f for f in report.seo_facts}
    assert by_host["combos.example.ai"].raw_html_tier == "shell"
    assert by_host["example.ai"].raw_html_tier == "full"
    assert "渲染对比" in "".join(report.coverage.not_checked)
