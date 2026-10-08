"""两个子命令（``page`` / ``robots``）共用的 argparse 小件。

整站体检的主解析器（``cli._Parser``）早就有这条约定：**用法错误一律退 4**。argparse 自己退 2，
而 2 在这套 CLI 里是「结果不可信」、1 是「有发现」—— 脚本会把一个拼错的 flag 读成别的意思。
两个子命令原来用的是裸 ``ArgumentParser``：``geo-audit robots a.test --bogus`` 退 2，
``--timeout=-5`` 甚至是一条未捕获的 ``ValueError`` 回溯（退 1）。
"""

from __future__ import annotations

import argparse
import math
import sys
from collections.abc import Sequence
from typing import NoReturn

from geo_audit.pipeline import EXIT_OK, EXIT_USAGE

__all__ = ["UsageParser", "parse_args", "positive_seconds"]


class UsageParser(argparse.ArgumentParser):
    """用法错误退 4（见模块说明）。"""

    def error(self, message: str) -> NoReturn:
        sys.stderr.write(f"{self.prog}: 用法错误：{message}\n")
        raise SystemExit(EXIT_USAGE)


def positive_seconds(text: str) -> float:
    """``--timeout``：大于 0 的有限数（httpx 对 ``-5`` 抛 ValueError，对 ``inf`` 永不超时）。"""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"不是数字：{text!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"必须是大于 0 的有限数：{text!r}")
    return value


def parse_args(
    parser: argparse.ArgumentParser, argv: Sequence[str]
) -> tuple[argparse.Namespace | None, int]:
    """``(args, 0)``；解析失败或 ``--help`` 时 ``(None, 退出码)``（用法错 → 4，``--help`` → 0）。"""
    try:
        return parser.parse_args(list(argv)), EXIT_OK
    except SystemExit as exc:
        code = exc.code
        return None, EXIT_OK if code is None else code if isinstance(code, int) else EXIT_USAGE
