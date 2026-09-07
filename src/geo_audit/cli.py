"""命令行入口。

第 1 步只实现 ``--version``；其余 flag 在第 16 步按 §7 补齐。
进度输出一律走 ``print(file=sys.stderr)``，不引 logging（见 pyproject 的
``per-file-ignores``：本文件放开 T201，正是为了这个）。
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from geo_audit import __version__

PROG = "geo-audit"


def build_parser() -> argparse.ArgumentParser:
    """构造 argparse。第 16 步在这里补 §7 的全部 flag 与退出码。"""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="查出你的公开信息里哪些位置会被 AI 读错或读不到（零 LLM，零 API key）",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """返回进程退出码。

    退出码约定（§7.5，第 16 步实现）：0 正常 / 2 用法错 / 4 参数无效 / 130 中断。
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    del args  # 第 1 步除 --version 外无子命令；--version 由 argparse 直接退出

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
