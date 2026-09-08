"""README 对报告的说法必须与报告本身对得上。

**为什么值得一条测试**：README 第一屏明写「打开看，别看我怎么形容它」，也就是
说它对外承诺那些数字是真的。而它实测过期过三处：

* 写「四份真实站点的真实扫描结果」，画廊里其实已有九份；
* 写「**画廊还缺 5 个域**…补齐要真网络重录一次」，那五份早就录完了；
* 给 `openstatus.dev` 标「**零发现**」，而判定口径修好之后它是
  「没有发现被读错的位置。但有 1 个位置我们无法判断，所以这不能算『全部通过』」。

第三条是判定改动的直接后果 —— 也就是说**每次判定口径变化都可能让 README 变成
假话**，而假话出现在最多人看的那个文件里。所以这里把三件能机械核对的事钉住：
份数、「零发现」与首屏判决是否一致、有没有报告没进表。

措辞本身核不了（散文），但上面这三条恰好覆盖了实际发生过的三种过期。
"""

from __future__ import annotations

import html
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"
REPORTS = REPO / "docs" / "reports"

#: 「九份」这类中文数词。README 是给人读的，不写阿拉伯数字。
_CN_NUM = {
    "一": 1,
    "二": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
}

needs_reports = pytest.mark.skipif(
    not REPORTS.exists() or not any(REPORTS.glob("*.html")),
    reason="docs/reports/ 里没有报告（画廊还没生成，scripts/build_gallery.py）",
)


def _headline(path: Path) -> str:
    m = re.search(r"<h1>(.*?)</h1>", path.read_text(encoding="utf-8"), re.S)
    assert m is not None, f"{path.name} 里没有 <h1> 判决句"
    return html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()


def _readme_rows() -> dict[str, str]:
    """域名 -> README 表格里那一行的说法。"""
    rows: dict[str, str] = {}
    for line in README.read_text(encoding="utf-8").splitlines():
        if not line.strip().startswith("|"):
            continue
        m = re.search(r"docs/reports/([A-Za-z0-9.\-]+)\.html", line)
        if m:
            rows[m.group(1)] = line
    return rows


@needs_reports
def test_readme_report_count_matches_the_gallery() -> None:
    n = len(list(REPORTS.glob("*.html")))
    m = re.search(r"([一二三四五六七八九十])份真实站点的真实扫描结果", README.read_text("utf-8"))
    assert m is not None, "README 里找不到「N 份真实站点的真实扫描结果」那句"
    said = _CN_NUM[m.group(1)]
    assert said == n, (
        f"README 说「{m.group(1)}份」，docs/reports/ 里实际 {n} 份。"
        "实测过期过：写「四份」时画廊里已有九份。"
    )


@needs_reports
def test_every_report_has_a_readme_row() -> None:
    have = {p.stem for p in REPORTS.glob("*.html")}
    listed = set(_readme_rows())
    missing = sorted(have - listed)
    assert missing == [], (
        f"这些报告在画廊里但 README 表格里没有：{missing}。"
        "新增报告不许静默不列 —— README 曾经写「画廊还缺 5 个域」，而那五份早就录完了。"
    )


@needs_reports
def test_zero_finding_claims_match_the_headline() -> None:
    """README 标「零发现」⟺ 首屏判决是肯定式的「N 个位置全部通过」。

    双向断言：单向只查「说了零发现的是不是真零发现」会漏掉反向漂移 ——
    一份报告变成真的全部通过、README 却还在描述它的老毛病。
    """
    bad: list[str] = []
    for dom, row in _readme_rows().items():
        path = REPORTS / f"{dom}.html"
        if not path.exists():
            continue
        head = _headline(path)
        # 肯定式：「N 个位置全部通过」。否定式「…这不能算『全部通过』」不算。
        all_pass = re.search(r"\d+\s*个位置全部通过", head) is not None
        claims_zero = "零发现" in row
        if claims_zero and not all_pass:
            bad.append(f"{dom}：README 标「零发现」，报告首屏却是「{head}」")
        if all_pass and not claims_zero:
            bad.append(f"{dom}：报告首屏是「{head}」，README 却没标「零发现」")
    assert bad == [], "README 与报告首屏不一致：\n  " + "\n  ".join(bad)
