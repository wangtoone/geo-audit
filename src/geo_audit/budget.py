"""请求预算：把「想花多久」换算成请求上限。

速率被锁死在每 2 秒 1 个请求（只能调慢），所以时间和请求数一一对应：
``requests = minutes * 60 / interval``，默认 1000 个请求约 33 分钟。
预算默认不设上限；交互终端里开跑前问一次，非交互场景（CI、脚本）不问，
要限就显式传 ``--max-requests``。
"""

from __future__ import annotations

import re
from collections.abc import Callable

_UNIT = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(m|min|分钟|分|h|小时)?\s*$", re.IGNORECASE)


def minutes_to_requests(minutes: float, interval: float) -> int:
    """至少 1 个请求。``interval`` 是单域请求间隔秒数。"""
    return max(1, int(minutes * 60 / interval + 1e-9))


def requests_to_minutes(requests: int, interval: float) -> float:
    return requests * interval / 60


def parse_minutes(text: str) -> float | None:
    """``"30"`` / ``"30m"`` / ``"1h"`` / ``"90分钟"`` → 分钟数；空串 = None（不设上限）。

    读不懂或 ≤ 0 抛 ``ValueError``。
    """
    if not text.strip():
        return None
    m = _UNIT.match(text)
    if not m:
        raise ValueError(f"读不懂 {text!r}：输入分钟数，如 30、30m、1h；直接回车 = 不设上限")
    value = float(m.group(1))
    if m.group(2) and m.group(2).lower() in ("h", "小时"):
        value *= 60
    if value <= 0:
        raise ValueError("时长必须大于 0；直接回车 = 不设上限")
    return value


def prompt_text(interval: float) -> str:
    per_1000 = requests_to_minutes(1000, interval)
    return (
        f"想花多久？速率 {1 / interval:g} req/s（每 {interval:g} 秒 1 个请求），"
        f"约 1000 个请求 ≈ {per_1000:.0f} 分钟。\n"
        "时间到了没探完的位置会标「没挖到（超出预算）」。"
        "输入分钟数（如 30、1h），回车 = 不设上限: "
    )


def resolve_max_requests(
    flag: int | None,
    *,
    interactive: bool,
    interval: float,
    ask: Callable[[str], str],
    say: Callable[[str], None],
) -> int:
    """``--max-requests`` 的最终值（0 = 不限）。

    显式传了 flag 就用它，不问；没传：交互终端问时长，非交互不问、不设上限（并说一声）。
    """
    if flag is not None:
        return flag
    if not interactive:
        say("未设请求上限（--max-requests 0）；要限制请显式传 --max-requests N。")
        return 0
    while True:
        try:
            answer = ask(prompt_text(interval))
        except EOFError:
            return 0
        try:
            minutes = parse_minutes(answer)
        except ValueError as exc:
            say(str(exc))
            continue
        if minutes is None:
            return 0
        n = minutes_to_requests(minutes, interval)
        say(f"按 {minutes:g} 分钟算，请求上限 {n}。")
        return n
