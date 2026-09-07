"""报告渲染层（§6）。**只 re-export，不放逻辑。**

对外三样：

* :func:`render_html` —— 唯一的渲染入口。渲染即校验（自包含 / 禁词 / 四格恒等式）。
* :func:`render_chain_svg` —— 首页六格链路图（第 15b 步）。
* :data:`COPY_ZH` —— 全部中文文案。它同时是禁词的扫描面，见 ``render`` 的模块说明。
* :func:`write_json` / :func:`load_report` —— 第 15c 步 ``json_out.py`` 的出入口
  （``--format json`` 与 ``--from``）。CLI 一律从本包取，别直接 import 子模块。

包内数据文件（``template.html.j2`` / ``report.css``）由 ``importlib.resources``
从本包读取，所以这个 ``__init__.py`` 必须存在，且 wheel 必须带上这两个文件。
"""

from __future__ import annotations

from .chain_svg import render_chain_svg
from .copy_zh import COPY_ZH
from .json_out import load_report, write_json
from .render import (
    assert_counts_identity,
    assert_no_banned_words,
    assert_selfcontained,
    group_by_root_cause,
    our_copy_corpus,
    render_html,
)

__all__ = [
    "COPY_ZH",
    "assert_counts_identity",
    "assert_no_banned_words",
    "assert_selfcontained",
    "group_by_root_cause",
    "load_report",
    "our_copy_corpus",
    "render_chain_svg",
    "render_html",
    "write_json",
]
