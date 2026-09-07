"""UNKNOWN 的完整性（§2.8 / A32）—— 骨架，**只写现在能跑的那半**。

规则：**UNKNOWN 永不折算成 PASS**，且每条 UNKNOWN 必须给原因码 + 可执行的补救办法。

⚠️ 归属说明：``UNKNOWN_REMEDY`` 的正式定义应在 ``src/geo_audit/models.py``（§2.8），
那个文件现在还没有它。本轮（第 6/8/9/10 步）在 ``checks/ai_path.py`` 里放了一份
**占位**，只抄了 ``NOT_EVALUATED_REASONS`` 覆盖到的 16 条 —— 缺 ``"interrupted"``
（那是第 15b 步中断报告的事）。所以：

* 覆盖 ``NOT_EVALUATED_REASONS`` 的断言现在就跑；
* A32 的完整断言 ``set(UNKNOWN_REMEDY) >= NOT_EVALUATED_REASONS | {"interrupted"}``
  等 models.py 接手后再开（skip，reason 里写明）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from geo_audit.checks.ai_path import UNKNOWN_REMEDY, ai_path_position_seeds
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.discovery import discover
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import DNS_ABSENT_KEY, FixtureResolver
from geo_audit.models import (
    NOT_EVALUATED_REASONS,
    Classification,
    Expect,
    HttpResponse,
    Probe,
    Status,
    Verdict,
    verdict_to_status,
)

try:  # models.py 接手 UNKNOWN_REMEDY 之后走这一支
    from geo_audit.models import (
        UNKNOWN_REMEDY as MODELS_UNKNOWN_REMEDY,  # type: ignore[attr-defined]
    )
except ImportError:  # 当前状态
    MODELS_UNKNOWN_REMEDY = None

models_owns_it = pytest.mark.skipif(
    MODELS_UNKNOWN_REMEDY is None,
    reason=(
        "UNKNOWN_REMEDY 的正式定义还不在 models.py 里（§2.8 待 owner 搬入）；"
        "当前只有 checks/ai_path.py 里的占位表，它按设计不含 interrupted"
    ),
)


def _probe(url: str, verdict: Verdict, reason: str) -> Probe:
    resp = HttpResponse(
        url=url, final_url=url, status=403, headers={"content-type": "text/html"}, body=b"x"
    )
    return Probe(url, Expect.TEXT_FILE, resp, Classification(verdict, reason))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 现在就能跑
# --------------------------------------------------------------------------- #


def test_unknown_never_folds_into_pass() -> None:
    """§2.2：BLOCKED / UNKNOWN → ``Status.UNKNOWN``，REAL404 → NOT_APPLICABLE。
    一个都不许变成 PASS —— 把「看不了」渲染成「没问题」就是制造假零。"""
    assert verdict_to_status(Verdict.BLOCKED) is Status.UNKNOWN
    assert verdict_to_status(Verdict.UNKNOWN) is Status.UNKNOWN
    assert verdict_to_status(Verdict.REAL404) is Status.NOT_APPLICABLE
    assert verdict_to_status(Verdict.SOFT404) is Status.FAIL
    assert verdict_to_status(Verdict.OK) is Status.PASS


#: ⚠️ 规格自己违反了 A32 的「≥ 20 字符」（见交付说明 spec_gaps）：§2.8:1146 给
#: 这两条的文案就是「网络错误。」（5 字）与「重定向层数超过 10 跳。」（11 字）。
#: 铁律 7 要求逐字照抄，所以占位表里照抄了原文，短的两条列在这里豁免。
#: owner 把文案补长之后这条豁免自动失效（断言写成「≥20 或在豁免名单里」，两边都绿）。
SHORT_BY_SPEC = frozenset({"network_error", "too_many_redirects"})


def test_placeholder_remedy_table_covers_every_not_evaluated_reason() -> None:
    """占位表必须覆盖 ``NOT_EVALUATED_REASONS`` 的全部 16 条，每条 ≥ 20 字符。"""
    assert set(UNKNOWN_REMEDY) >= NOT_EVALUATED_REASONS
    for reason, text in UNKNOWN_REMEDY.items():
        assert text.strip(), reason
        assert len(text) >= 20 or reason in SHORT_BY_SPEC, (
            f"{reason} 的补救办法太短，不可执行：{text!r}"
        )


def test_every_unknown_position_seed_carries_reason_and_remedy() -> None:
    """A32：每个 UNKNOWN 格都必须带 ``unknown_reason`` + 非空 ``unknown_remedy``。"""
    seeds = ai_path_position_seeds(
        [
            _probe("https://gusto.com/llms.txt", Verdict.BLOCKED, "waf_challenge_body"),
            _probe("https://www.pipedrive.com/llms.txt", Verdict.BLOCKED, "rate_limited"),
            _probe("https://developers.pinterest.com/llms.txt", Verdict.UNKNOWN, "server_error"),
        ]
    )
    assert len(seeds) == 3
    for seed in seeds:
        assert seed.status is Status.UNKNOWN
        assert seed.unknown_reason in NOT_EVALUATED_REASONS
        assert seed.unknown_remedy
        assert len(seed.unknown_remedy) >= 20


def test_blocked_and_real404_are_two_separate_columns() -> None:
    """§4.1 口径 1：「未采纳」与「无法判定」必须是两栏，绝不合并。

    软 404 让采纳率虚高、403/429 让它虚低 —— 两个方向都得处理。
    """
    blocked = _probe("https://gusto.com/llms.txt", Verdict.BLOCKED, "waf_challenge_body")
    real404 = _probe("https://tdengine.com/llms.txt", Verdict.REAL404, "status_404")
    statuses = {s.probe_url: s.status for s in ai_path_position_seeds([blocked, real404])}
    assert statuses["https://gusto.com/llms.txt"] is Status.UNKNOWN
    assert statuses["https://tdengine.com/llms.txt"] is Status.NOT_APPLICABLE
    assert Status.UNKNOWN is not Status.NOT_APPLICABLE


def test_real404_positions_have_no_remedy_because_nothing_is_broken() -> None:
    """REAL404 是「你没做这件事」，不是「你做坏了」，所以没有 remedy 可给。"""
    (seed,) = ai_path_position_seeds(
        [_probe("https://tdengine.com/llms.txt", Verdict.REAL404, "status_404")]
    )
    assert seed.unknown_reason is None
    assert seed.unknown_remedy is None


# --------------------------------------------------------------------------- #
# models.py 接手 UNKNOWN_REMEDY 之后开
# --------------------------------------------------------------------------- #


@models_owns_it
def test_a32_remedy_table_is_complete() -> None:
    """A32 / §2.8:1185：``set(UNKNOWN_REMEDY) >= NOT_EVALUATED_REASONS | {"interrupted"}``，
    且每条文案非空、长度 ≥ 20 字符。"""
    table = MODELS_UNKNOWN_REMEDY
    assert table is not None
    assert set(table) >= NOT_EVALUATED_REASONS | {"interrupted"}
    for reason, text in table.items():
        assert text.strip(), reason
        assert len(text) >= 20 or reason in SHORT_BY_SPEC, reason


@models_owns_it
def test_the_placeholder_table_is_gone_from_checks() -> None:
    """搬入完成后，``checks/ai_path.py`` 的占位表应该被删掉、改成 import。

    留着两份会漂移（一份改了另一份没改），而 A6 那类「每个定义恰好 1 处」的
    grep 门禁也会开始数出 2 处。
    """
    import geo_audit.checks.ai_path as mod

    assert mod.UNKNOWN_REMEDY is MODELS_UNKNOWN_REMEDY


# --------------------------------------------------------------------------- #
# 第 7 步：发现层产出的 UNKNOWN（DNS / 预算 / WAF 三个来源）
# --------------------------------------------------------------------------- #
#
# 这三类 UNKNOWN 全部出在 discovery 层，是 A32「每条 UNKNOWN 都要有原因码 +
# 可执行补救」在发现层的落地点：
#
#   dns_unresolved / dns_poisoned  —— platform.minimax.io 一次并发跑出 12 条假
#                                     DNS 失败，25 秒后重试全部 200；
#                                     www.talkie-ai.com 本机解析到 127.0.0.1。
#   not_fetched                    —— 预算耗尽，那个位置我们**没看**，
#                                     绝不能渲染成「没有这个文件」。
#   waf_challenge_body / rate_limited —— gusto 403 / pipedrive 429，真文件存在。

CONTACT = "audit@example.org"
CONTROL_PATH = "/zzz-geo-audit-control-1234"


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """掐掉限流器的 sleep（合规下限 2s/域，否则一次 discover() 要几十秒）。"""
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _seconds: None)


def _discover_fake(
    tmp_path: Path,
    pages: dict[str, tuple[int, str, str]],
    dns: dict[str, dict[str, object]],
    *,
    domain: str,
    budget: int = 120,
) -> Any:
    """在假站 + 注入 DNS 上跑一次 ``discover()``。一个真请求、一次真 DNS 都没有。"""

    def handler(request: httpx.Request) -> httpx.Response:
        row = pages.get(str(request.url))
        if row is None:
            return httpx.Response(
                404, headers={"content-type": "text/html"}, text="<title>404</title>not found"
            )
        status, ctype, body = row
        return httpx.Response(status, headers={"content-type": ctype}, text=body)

    table = dict(dns)
    table.setdefault(
        DNS_ABSENT_KEY,
        {"addresses": [], "resolver": "none", "poisoned": False, "error": "NXDOMAIN"},
    )
    fetcher = Fetcher(
        FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
        cache=HttpCache(tmp_path / "c.sqlite3", ua_profile="test"),
        limiter=DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
        probe_url_provider=lambda url: f"https://{httpx.URL(url).host}{CONTROL_PATH}",
    )
    try:
        return discover(
            fetcher,
            domain,
            budget=budget,
            resolver=FixtureResolver(table, source="tests/test_unknown.py"),
        )
    finally:
        fetcher.close()


def test_dns_failures_are_unknown_never_dead(tmp_path: Path) -> None:
    """R1/R3/R4：DNS 解析不出来、或解析到 127.0.0.1，都判 UNKNOWN，**绝不判死**。

    ``platform.minimax.io`` 一次并发跑出 12 条假 DNS 失败（25 秒后重试全部 200），
    ``www.talkie-ai.com`` 本机解析到 127.0.0.1 而公共解析器给真 Akamai 地址 ——
    把这两种当死链就是凭空造出 12 条假阳。
    """
    pages = {"https://acme.test/": (200, "text/html", "<title>Acme</title>")}
    dns: dict[str, dict[str, object]] = {
        "acme.test": {"addresses": ["203.0.113.10"], "resolver": "system", "poisoned": False},
        # 本地污染：系统解析器给 127.0.0.1，公共解析器无有效记录
        "www.acme.test": {
            "addresses": [],
            "resolver": "none",
            "poisoned": True,
            "error": "dns-poisoned: 系统解析器返回 ('127.0.0.1',)，公共解析器无有效记录",
        },
    }
    sm = _discover_fake(tmp_path, pages, dns, domain="acme.test")

    by_host = {h.host: h for h in sm.hosts}
    poisoned = by_host["www.acme.test"]
    assert poisoned.verdict is Verdict.UNKNOWN
    assert poisoned.reason == "dns_poisoned"
    assert verdict_to_status(poisoned.verdict) is Status.UNKNOWN
    assert poisoned.verdict is not Verdict.REAL404

    absent = by_host["docs.acme.test"]
    assert absent.verdict is Verdict.UNKNOWN
    assert absent.reason == "dns_unresolved"
    assert absent.evidence and "8.8.8.8" in absent.evidence[0]

    # 两个原因码都在 A32 的补救表里，且文案可执行
    for reason in ("dns_poisoned", "dns_unresolved"):
        assert reason in NOT_EVALUATED_REASONS
        assert len(UNKNOWN_REMEDY[reason]) >= 20


def test_budget_skipped_positions_are_not_fetched_not_absent(tmp_path: Path) -> None:
    """预算耗尽跳过的位置 -> ``not_fetched``（UNKNOWN），**不是「没有这个文件」**。

    A32 要求每条 UNKNOWN 都带可执行补救；``not_fetched`` 的补救就是「提高
    --max-requests 再跑」，所以这条文案必须存在且非空。
    """
    pages = {
        "https://acme.test/": (200, "text/html", "<title>Acme</title>"),
        "https://www.acme.test/": (200, "text/html", "<title>Acme www</title>"),
        "https://docs.acme.test/": (200, "text/html", "<title>Docs</title>"),
        "https://docs.acme.test/llms.txt": (200, "text/plain", "# Acme\n"),
    }
    dns: dict[str, dict[str, object]] = {
        host: {"addresses": ["203.0.113.10"], "resolver": "system", "poisoned": False}
        for host in ("acme.test", "www.acme.test", "docs.acme.test")
    }
    sm = _discover_fake(tmp_path, pages, dns, domain="acme.test", budget=6)

    assert sm.budget_exhausted is True
    assert "https://docs.acme.test/llms.txt" in sm.skipped_by_budget
    # 真文件就在被跳过的那条上 —— 报告若把它当「没有」就是纯造假
    assert "https://docs.acme.test/llms.txt" not in {p.url for p in sm.ai_path_probes}
    assert "not_fetched" in NOT_EVALUATED_REASONS
    assert UNKNOWN_REMEDY["not_fetched"].strip()
    assert verdict_to_status(Verdict.UNKNOWN) is Status.UNKNOWN


def test_waf_blocked_ai_path_is_unknown_with_a_remedy(tmp_path: Path) -> None:
    """gusto 403（Cloudflare 挑战页）/ pipedrive 429：两条都判 BLOCKED、
    ``evaluated is False``、折算 ``Status.UNKNOWN``，且补救文案可执行。"""
    challenge = (
        "<!doctype html><html><head><title>Just a moment...</title></head>"
        "<body>__cf_chl_opt</body></html>"
    )
    pages = {
        "https://acme.test/": (403, "text/html", challenge),
        "https://acme.test/llms.txt": (403, "text/html", challenge),
        "https://www.acme.test/": (200, "text/html", "<title>Acme</title>"),
        "https://www.acme.test/llms.txt": (429, "text/plain", "rate limited"),
    }
    dns: dict[str, dict[str, object]] = {
        host: {"addresses": ["203.0.113.10"], "resolver": "system", "poisoned": False}
        for host in ("acme.test", "www.acme.test")
    }
    sm = _discover_fake(tmp_path, pages, dns, domain="acme.test")

    by_url = {p.url: p for p in sm.ai_path_probes}
    waf = by_url["https://acme.test/llms.txt"]
    throttled = by_url["https://www.acme.test/llms.txt"]
    assert waf.verdict is throttled.verdict is Verdict.BLOCKED
    assert waf.classification.reason == "waf_challenge_body"
    assert throttled.classification.reason == "rate_limited"
    for probe in (waf, throttled):
        assert probe.classification.evaluated is False
        assert verdict_to_status(probe.verdict) is Status.UNKNOWN
        assert len(UNKNOWN_REMEDY[probe.classification.reason]) >= 20
