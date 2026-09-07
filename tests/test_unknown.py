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

import pytest

from geo_audit.checks.ai_path import UNKNOWN_REMEDY, ai_path_position_seeds
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
