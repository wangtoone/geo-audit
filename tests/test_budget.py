"""交互式预算：时间 ↔ 请求数一一对应；非交互不问；显式 flag 不被覆盖。"""

from __future__ import annotations

import pytest

from geo_audit.budget import (
    minutes_to_requests,
    parse_minutes,
    requests_to_minutes,
    resolve_max_requests,
)


def test_thousand_requests_is_about_33_minutes() -> None:
    assert round(requests_to_minutes(1000, 2.0)) == 33
    assert minutes_to_requests(33.3, 2.0) == 999
    assert minutes_to_requests(0.0001, 2.0) == 1  # 至少 1 个


@pytest.mark.parametrize(
    ("text", "minutes"),
    [("", None), ("  ", None), ("30", 30.0), ("30m", 30.0), ("1h", 60.0), ("90分钟", 90.0)],
)
def test_parse_minutes(text: str, minutes: float | None) -> None:
    assert parse_minutes(text) == minutes


@pytest.mark.parametrize("bad", ["abc", "0", "-5", "1.5.2h"])
def test_parse_minutes_rejects_garbage(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_minutes(bad)


def _resolve(flag: int | None, *, interactive: bool, answers: list[str]) -> tuple[int, list[str]]:
    said: list[str] = []
    asked: list[str] = []

    def ask(prompt: str) -> str:
        asked.append(prompt)
        return answers.pop(0)

    n = resolve_max_requests(flag, interactive=interactive, interval=2.0, ask=ask, say=said.append)
    return n, asked


def test_explicit_flag_is_never_overridden_or_asked() -> None:
    assert _resolve(120, interactive=True, answers=[]) == (120, [])
    assert _resolve(0, interactive=True, answers=[]) == (0, [])


def test_non_interactive_without_flag_is_unlimited_and_never_prompts() -> None:
    n, asked = _resolve(None, interactive=False, answers=[])
    assert n == 0 and asked == []


def test_interactive_converts_minutes_and_reasks_on_garbage() -> None:
    n, asked = _resolve(None, interactive=True, answers=["abc", "10"])
    assert n == 300 and len(asked) == 2
    assert "33 分钟" in asked[0] and "没挖到（超出预算）" in asked[0]


def test_interactive_blank_is_unlimited() -> None:
    assert _resolve(None, interactive=True, answers=[""])[0] == 0
