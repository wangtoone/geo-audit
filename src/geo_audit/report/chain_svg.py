"""第一页的链路图 —— 六格横向内联 SVG（§6.1:3033 / 3060，第 15b 步）。

它回答的是首页唯一必须回答的问题：「AI 走你的链路，六段里哪几段走不通」。
**不是条目列表** —— 实测 20.8% 的域报不出条目、52.8% 只有 1–2 条，73.6% 报不出
3 条，第一页放条目列表就是一份甲方付不了费的 PDF。

三条硬约束（违反就是造假或不可访问）：

1. **六格位置数之和 == ``counts.positions``**（§6.1:3062 / A31:4510）。
   每格的位置数就是 ``sum(1 for p in positions if p.stage is s)``，六段穷尽了
   ``Stage``，所以这条按构造成立；``_assert_cell_sum`` 是为了防有人事后手改。
2. **四态形状必须可区分，不能只靠颜色**（§6.5:3264）。色盲用户与黑白打印下
   都要能分出来，所以四态各有独立几何形状 + 独立字形 + 独立描边形态：

   ==============  ============  ========  ==================================
   Status          形状          字形      描边
   ==============  ============  ========  ==================================
   PASS            圆            ✓         1px 实线
   FAIL            八边形        ✕         3px 实线（描粗边）
   UNKNOWN         菱形          ?         2px **虚线** + 45° 斜纹填充
   NOT_APPLICABLE  正方形        –         1px **点线**，无填充
   ==============  ============  ========  ==================================

3. **UNKNOWN 永不折算**（§6.4 R1）。一格里既有 FAIL 又有 UNKNOWN 时，形状取
   FAIL（那是可行动的那个），但格内明细把两个数都印出来 —— 谁都不许被藏掉。

内联、零外部请求：斜纹用 ``<pattern>`` + ``fill="url(#…)"``（是片段引用，不是
``url(http…)``，所以 ``assert_selfcontained`` 的第五条正则不会命中）。

⚠️ 返回值在模板里走 ``|safe``，理由是「我们自己生成」。但 ``Position.detail``
是**管线产出、可能含甲方数据**的字符串，所以本模块对每一处插值一律
``html.escape``，一处不漏。这是 ``|safe`` 唯一成立的前提。
"""

from __future__ import annotations

import html
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..models import Stage, Status
from .copy_zh import COPY_ZH, STAGE_LABEL, STATUS_CSS, STATUS_GLYPH, STATUS_LABEL

if TYPE_CHECKING:  # pragma: no cover - 仅类型；运行期不 import render，避免成环
    from .render import Position

# --------------------------------------------------------------------------- #
# 版面常量（单位：SVG 用户坐标 = px）
# --------------------------------------------------------------------------- #

_CELL_W = 156
_CELL_H = 98
_GAP = 22
_SHAPE_CY = 26
_SHAPE_R = 15
_DETAIL_CHARS_PER_LINE = 13
_DETAIL_MAX_LINES = 2

#: FAIL 描粗边、UNKNOWN 虚线、NOT_APPLICABLE 点线 —— 黑白打印下的第三重区分。
_STROKE: dict[Status, tuple[str, str]] = {
    Status.PASS: ("1", ""),
    Status.FAIL: ("3", ""),
    Status.UNKNOWN: ("2", "4 3"),
    Status.NOT_APPLICABLE: ("1", "1 3"),
}

#: 一格里多个 Position 归一成一个形状时的优先级（规格未定义，见交付说明）。
#: FAIL 最先（那是可行动的），UNKNOWN 次之（**绝不被 PASS 盖掉**），再 PASS，
#: 全 NOT_APPLICABLE 才是 NA。
_PRECEDENCE: tuple[Status, ...] = (Status.FAIL, Status.UNKNOWN, Status.PASS)

#: 四态在明细里的印法顺序。四个一个都不许省（§6.4 R1）。
_DETAIL_ORDER: tuple[Status, ...] = (
    Status.PASS,
    Status.FAIL,
    Status.UNKNOWN,
    Status.NOT_APPLICABLE,
)


def _reduce_status(cells: Sequence[Position]) -> Status:
    """把一段里的多个 Position 归一成这一格的形状。

    空段（该 stage 一个 Position 都没有，例如整个域都没探过 llms-full 时的 ③）
    按 ``NOT_APPLICABLE`` 画并计 0 个位置 —— A31 的六格求和要求空格子按 0 计，
    所以它必须仍然占一格。
    """
    present = {p.status for p in cells}
    for status in _PRECEDENCE:
        if status in present:
            return status
    return Status.NOT_APPLICABLE


def _cell_detail(cells: Sequence[Position]) -> str:
    """一格的明细短语。

    规格只给了「✓ 4/4」「✕ 1 软404」「✕ 75/75死」「– 未声明」「✓ 6 页」这类
    **示例**，没给生成规则（简报 spec_gaps 第 7 条）。这里定死三条：

    * 空段 → ``chain_empty_cell``（「未探测」）；
    * 恰好 1 个 Position → 直接用它的 ``detail``（示例里那些短语就是管线产出的）；
    * 多个 → 按四态计数逐格印，四态一个都不许省。
    """
    if not cells:
        return COPY_ZH["chain_empty_cell"]
    if len(cells) == 1:
        return cells[0].detail or STATUS_LABEL[cells[0].status.value]
    parts: list[str] = []
    for status in _DETAIL_ORDER:
        n = sum(1 for p in cells if p.status is status)
        if n:
            parts.append(f"{STATUS_GLYPH[status.value]} {n} {STATUS_LABEL[status.value]}")
    return " · ".join(parts)


def _shape(status: Status, cx: float, cy: float) -> str:
    """四态各自的几何形状。**形状本身就是状态**，颜色只是第四重冗余编码。"""
    width, dash = _STROKE[status]
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    css = STATUS_CSS[status.value]
    common = f'class="sh sh-{css}" stroke-width="{width}"{dash_attr}'
    r = float(_SHAPE_R)
    if status is Status.PASS:
        return f'<circle {common} cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}"/>'
    if status is Status.FAIL:
        k = r * 0.4142
        pts = (
            (cx - k, cy - r),
            (cx + k, cy - r),
            (cx + r, cy - k),
            (cx + r, cy + k),
            (cx + k, cy + r),
            (cx - k, cy + r),
            (cx - r, cy + k),
            (cx - r, cy - k),
        )
        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        return f'<polygon {common} points="{poly}"/>'
    if status is Status.UNKNOWN:
        d = r * 1.15
        diamond = (
            (cx, cy - d),
            (cx + d, cy),
            (cx, cy + d),
            (cx - d, cy),
        )
        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in diamond)
        return f'<polygon {common} points="{poly}" fill="url(#geoHatch)"/>'
    side = r * 1.7
    return (
        f'<rect {common} x="{cx - side / 2:.1f}" y="{cy - side / 2:.1f}" '
        f'width="{side:.1f}" height="{side:.1f}" fill="none"/>'
    )


def _wrap(text: str, per_line: int, max_lines: int) -> list[str]:
    """朴素定宽折行。中文按字数折，够用且确定性（报告要逐字节可复现）。"""
    lines: list[str] = []
    rest = text
    while rest and len(lines) < max_lines:
        lines.append(rest[:per_line])
        rest = rest[per_line:]
    if rest and lines:
        lines[-1] = lines[-1][: max(per_line - 1, 1)] + "…"
    return lines or [""]


def _assert_cell_sum(counts: Sequence[int], total_positions: int) -> None:
    """§6.1:3062 / A31 的硬恒等式。六段穷尽 ``Stage``，所以只可能被手改破坏。"""
    total = sum(counts)
    if total != total_positions:
        raise AssertionError(
            f"链路图六格位置数之和 {total} != 位置数 {total_positions}（§6.1:3062 / A31）"
        )


def _defs() -> str:
    """斜纹 pattern 与箭头 marker。两者都是片段引用，零外部请求。"""
    return (
        "<defs>"
        '<pattern id="geoHatch" width="6" height="6" patternTransform="rotate(45)" '
        'patternUnits="userSpaceOnUse">'
        '<line class="hatch" x1="0" y1="0" x2="0" y2="6" stroke-width="2"/>'
        "</pattern>"
        '<marker id="geoArrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" '
        'markerHeight="6" orient="auto">'
        '<path class="arrow" d="M0,0 L8,4 L0,8 Z"/></marker>'
        "</defs>"
    )


def _text(cls: str, cx: float, y: float, content: str) -> str:
    """``text-anchor: middle`` 在 report.css 里统一给 ``svg.chain text``，不逐个写。"""
    return f'<text class="{cls}" x="{cx:g}" y="{y:g}">{html.escape(content)}</text>'


def render_chain_svg(positions: Sequence[Position]) -> str:
    """六格横向链路图，返回一段内联 SVG 字符串。

    ``Stage`` 的声明顺序就是 ①..⑥，所以直接按枚举顺序铺格子；相邻两格之间画箭头
    —— 「这条链路上任何一段断掉，后面几段的内容 AI 都拿不到」（脚注在模板里）。
    """
    stages = tuple(Stage)
    buckets = [[p for p in positions if p.stage is s] for s in stages]
    counts = [len(b) for b in buckets]
    _assert_cell_sum(counts, len(positions))

    width = len(stages) * _CELL_W + (len(stages) - 1) * _GAP
    out: list[str] = [
        f'<svg class="chain" xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {_CELL_H}" width="{width}" height="{_CELL_H}" role="img" '
        f'aria-label="{html.escape(COPY_ZH["chain_alt"])}">',
        _defs(),
    ]

    for i, stage in enumerate(stages):
        cells = buckets[i]
        status = _reduce_status(cells)
        x0 = i * (_CELL_W + _GAP)
        cx = x0 + _CELL_W / 2
        out.append(
            f'<g class="cell cell-{STATUS_CSS[status.value]}" data-stage="{stage.value}" '
            f'data-shape="{status.value}" data-positions="{counts[i]}">'
        )
        out.append(
            f'<rect class="cell-box" x="{x0}" y="0" width="{_CELL_W}" height="{_CELL_H}" rx="6"/>'
        )
        out.append(_shape(status, cx, _SHAPE_CY))
        out.append(_text("glyph", cx, _SHAPE_CY + 5, STATUS_GLYPH[status.value]))
        out.append(_text("lab", cx, _SHAPE_CY + 27, STAGE_LABEL[stage]))
        out.append(_text("num", cx, _SHAPE_CY + 42, f"{counts[i]} {COPY_ZH['chain_count_suffix']}"))
        detail_lines = _wrap(_cell_detail(cells), _DETAIL_CHARS_PER_LINE, _DETAIL_MAX_LINES)
        for j, line in enumerate(detail_lines):
            out.append(_text("det", cx, _SHAPE_CY + 57 + j * 13, line))
        out.append("</g>")
        if i < len(stages) - 1:
            ax = x0 + _CELL_W + 3
            out.append(
                f'<line class="link" x1="{ax}" y1="{_SHAPE_CY}" x2="{ax + _GAP - 8}" '
                f'y2="{_SHAPE_CY}" marker-end="url(#geoArrow)"/>'
            )

    out.append("</svg>")
    return "".join(out)
