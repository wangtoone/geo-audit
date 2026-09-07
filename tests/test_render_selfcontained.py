"""第 15a 步自验 · 自包含 / 禁词 / 安全 / 打印（A27 / A28 / A34 / A36）。

**这份测试的重点是「敌意的甲方数据」**。报告要逐字回显甲方站点的 ``<title>``、
锚文本、原始 ``<a href>`` 片段与 ``inline_style``（copper 那条
``href="https://www.linkedin.com/https://www.linkedin.com/company/copper-inc/"``
就是这么来的），所以下面这些**必须**能安全渲染出来，而不是让渲染 raise：

* 页面标题里带禁词（「完美」「一切正常」）；
* 公司名 / 锚文本里带我们禁词表里的品牌名（真有公司叫 Lighthouse）；
* ``inline_style`` 里有 ``url(https://cdn…)``、``html_snippet`` 里有 ``@import``；
* 锚文本是 ``<script>alert(1)</script>``；
* href 是 ``javascript:`` / ``data:``。

规格原文（§6.5:3243）把禁词做成对整份 HTML 的子串扫描，那样上面前两条会让
``render_html`` 直接 raise、整份报告产不出来（简报 spec_gaps 停工级 4）。
owner 已裁决：**禁词只扫我们自己生成的文案，不扫引用的证据** ——
实现是 ``render.our_copy_corpus()``，本文件逐条验它。
"""

from __future__ import annotations

import inspect
import re

import pytest
from markupsafe import escape

from geo_audit.models import Severity, Stage, Status, make_finding_id
from geo_audit.naive import NAIVE_BANNED_WORDS
from geo_audit.report import render as render_mod
from geo_audit.report import render_html
from geo_audit.report.copy_zh import COPY_ZH
from geo_audit.report.render import (
    _BANNED_WORDS,
    _FORBIDDEN,
    _SIZE_CAP,
    _our_markup,
    assert_no_banned_words,
    assert_no_external_refs,
    assert_selfcontained,
    our_copy_corpus,
)
from tests.test_report_shape import (
    UA,
    build_interrupted_report,
    build_page_one_sample,
    build_sampled_report,
    build_unusable_report,
    build_zero_finding_report,
    ev,
)

#: 每个 builder 都要过全部自包含 / 禁词 / 安全断言。
ALL_BUILDERS = (
    build_page_one_sample,
    build_zero_finding_report,
    build_unusable_report,
    build_interrupted_report,
    build_sampled_report,
)


# --------------------------------------------------------------------------- #
# 敌意甲方数据
# --------------------------------------------------------------------------- #

#: 这些串会被逐字塞进甲方数据位。它们**同时**是禁词表里的词 —— 报告必须照样产出。
HOSTILE_STRINGS = (
    "完美",
    "一切正常",
    "没有问题",
    "恭喜",
    "满分",
    "Lighthouse",
    "Ahrefs",
    "Semrush",
    "Screaming Frog",
)

#: 这些串会被 _FORBIDDEN 的后两条误读成外部资源引用（Jinja 的 autoescape 不动
#: 圆括号与 @）。render_html 的「去獠牙」那一步专门处理它们。
RESOURCE_LOOKALIKES = (
    "background: url(https://cdn.example.net/hero.png)",
    "@import url(https://fonts.example.net/x.css);",
    '<img src="http://tracker.example.net/p.gif">',
    '<link rel="stylesheet" href="https://cdn.example.net/a.css">',
    '<script src="https://cdn.example.net/a.js"></script>',
)

XSS_ANCHOR = "<script>alert(1)</script>"
JS_HREF = "javascript:alert(document.domain)"
DATA_HREF = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="


def build_hostile_report() -> object:
    """把 §6.1 的样本改成「甲方站点到处是雷」的版本。"""
    from dataclasses import replace

    base = build_page_one_sample()
    f = base.findings[0]
    hostile_title = " ".join(HOSTILE_STRINGS)
    hostile = replace(
        f,
        title=f"定价页的 CTA 全指向 404（页面标题写着「{hostile_title}」）",
        anchor_text=XSS_ANCHOR,
        html_snippet=(
            f'<a href="{JS_HREF}" style="{RESOURCE_LOOKALIKES[0]}">{XSS_ANCHOR}</a>'
            + "".join(RESOURCE_LOOKALIKES[1:])
        ),
        target=replace(
            f.target,
            url=JS_HREF,
            title=hostile_title,
            body_head=" ".join(RESOURCE_LOOKALIKES),
        ),
        control=ev(DATA_HREF, 200, "text/html"),
        occurrence_hrefs=(JS_HREF, DATA_HREF, RESOURCE_LOOKALIKES[0]),
        naive_conclusion=f"这条链接{HOSTILE_STRINGS[2]}",
        actual_conclusion=f"甲方页面自称「{hostile_title}」，实际是 404",
        found_on=DATA_HREF,
    )
    return replace(
        base,
        domain="lighthouse-perfect.example",
        findings=(hostile, *base.findings[1:]),
        excluded=(
            replace(
                base.excluded[0],
                url=RESOURCE_LOOKALIKES[1],
                found_on=JS_HREF,
            ),
            base.excluded[1],
        ),
    )


# --------------------------------------------------------------------------- #
# A27 · 自包含
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("build", ALL_BUILDERS, ids=lambda b: b.__name__)
def test_a27_five_forbidden_patterns_never_match(build: object) -> None:
    """五条禁止正则全部无匹配 —— 单文件、零外部请求。"""
    html = render_html(build())  # type: ignore[operator]
    for pattern in _FORBIDDEN:
        assert pattern.search(html) is None, pattern.pattern


def test_a27_holds_even_when_the_customer_page_looks_like_a_cdn() -> None:
    """甲方数据里的 ``url(https://…)`` / ``@import`` 不许让报告判成「不自包含」。

    这是简报 spec_gaps 倒数第 4 条那个坑：Jinja 转义不动圆括号与冒号，所以
    ``inline_style`` 里一个背景图就能让 ``assert_selfcontained`` 把整份报告毙掉。
    """
    html = render_html(build_hostile_report())  # type: ignore[arg-type]
    for pattern in _FORBIDDEN:
        assert pattern.search(html) is None, pattern.pattern
    # 去獠牙后仍然肉眼可读：字符引用渲染出来就是原字符
    assert "url&#40;https://cdn.example.net/hero.png" in html
    assert "&#64;import" in html


def test_a27_size_is_under_two_megabytes() -> None:
    for build in ALL_BUILDERS:
        html = render_html(build())
        assert len(html.encode()) < _SIZE_CAP


def test_assert_selfcontained_actually_fires() -> None:
    """闸门本身要有效 —— 逐条正则各造一个反例。"""
    cases = (
        '<link rel="stylesheet" href="x.css">',
        '<script src="x.js"></script>',
        '<img src="https://x/y.png">',
        "@import url(x.css);",
        "body{background:url(https://x/y.png)}",
    )
    for bad in cases:
        with pytest.raises(AssertionError, match="报告不是自包含的"):
            assert_selfcontained(f"<html>{bad}</html>")


def test_assert_selfcontained_fires_on_oversize() -> None:
    with pytest.raises(AssertionError, match="超过 2 MB"):
        assert_selfcontained("x" * _SIZE_CAP)


def test_no_javascript_at_all() -> None:
    """零 JS：折叠一律原生 ``<details>``（§6.5:3268）。"""
    html = render_html(build_hostile_report())  # type: ignore[arg-type]
    assert "<script" not in html.lower()
    assert " onclick=" not in html.lower()
    assert " onload=" not in html.lower()
    assert "<details>" in html  # 折叠区确实是原生的


def test_no_webfont_and_a_real_cjk_fallback_stack() -> None:
    """无 webfont（§6.5:3263）。字体栈逐字照抄规格那一行。"""
    html = render_html(build_zero_finding_report())
    assert "@font-face" not in html
    assert "fonts.googleapis.com" not in html
    assert 'font-family: -apple-system, "Segoe UI", "Noto Sans CJK SC", "PingFang SC",' in html
    assert '"Microsoft YaHei", sans-serif' in html


def test_renders_as_a_standalone_document() -> None:
    """``file://`` 打开要渲染完整：doctype + charset + 内联 <style> + 闭合 </html>。"""
    html = render_html(build_page_one_sample())
    assert html.startswith("<!doctype html>")
    assert '<meta charset="utf-8">' in html
    assert "<style>" in html and "</style>" in html
    assert html.rstrip().endswith("</html>")
    assert "<title>" in html


# --------------------------------------------------------------------------- #
# A28 · 打印
# --------------------------------------------------------------------------- #


def test_a28_print_rules_are_present() -> None:
    html = render_html(build_page_one_sample())
    assert "@page" in html
    assert "break-inside: avoid" in html
    assert "attr(href)" in html


def test_a28_details_are_force_expanded_inside_media_print() -> None:
    """``details>*{display:block!important}`` 必须在 ``@media print`` 内 ——
    打印出来不许有藏起来的证据。"""
    html = render_html(build_page_one_sample())
    at_print = html.index("@media print")
    block = html[at_print : html.index("</style>")]
    assert re.search(r"details\s*>\s*\*\s*\{\s*display:\s*block\s*!important", block)


def test_css_is_not_html_escaped() -> None:
    """CSS 必须走 ``|safe``：autoescape 会把 ``details>*`` 变成 ``details&gt;*``、
    把 ``content:"✓"`` 变成 ``content:&#34;✓&#34;``，四态形状与打印规则当场失效。"""
    html = render_html(build_page_one_sample())
    style = html[html.index("<style>") : html.index("</style>")]
    assert "&gt;" not in style
    assert "&#34;" not in style
    for glyph in ('content: "✓"', 'content: "✕"', 'content: "?"', 'content: "–"'):
        assert glyph in style


def test_dark_mode_only_redefines_tokens() -> None:
    """§6.5:3267：``:root`` 定完整浅色 token，深色块里只改 token。"""
    html = render_html(build_zero_finding_report())
    assert "@media (prefers-color-scheme: dark)" in html
    assert ':root:not([data-theme="light"])' in html


def test_body_never_scrolls_horizontally() -> None:
    """宽内容自己滚（``.wide{overflow-x:auto}``），body 永不横向滚动。"""
    html = render_html(build_page_one_sample())
    assert ".wide {\n  overflow-x: auto;\n}" in html
    assert "overflow-x: hidden" in html  # body 上那条


# --------------------------------------------------------------------------- #
# A34 · 禁词与固定措辞（附录 B）
# --------------------------------------------------------------------------- #


def test_banned_word_table_is_the_spec_table_verbatim() -> None:
    """§6.5:3222 的 11 项逐字。任务书说「九词」，规格原文是 11 项，以原文为准。"""
    assert _BANNED_WORDS == (
        "恭喜",
        "没有问题",
        "一切正常",
        "完美",
        "满分",
        "Screaming Frog",
        "Lighthouse",
        "Ahrefs",
        "Semrush",
        "任何现成工具",
        "所有工具",
    )


def test_naive_banned_table_is_a_subset() -> None:
    """naive.py 自带一份最小禁词表。两份必须收敛，先断言子集关系。"""
    assert set(NAIVE_BANNED_WORDS) <= set(_BANNED_WORDS)


@pytest.mark.parametrize("build", ALL_BUILDERS, ids=lambda b: b.__name__)
def test_our_own_copy_is_clean_on_every_fixture(build: object) -> None:
    """禁词表在渲染期生效（§6.5:3250）。扫描面 = 我们自己写的字。"""
    report = build()  # type: ignore[operator]
    corpus = our_copy_corpus(report)
    assert_no_banned_words(corpus)
    for word in _BANNED_WORDS:
        assert word not in corpus


def test_copy_corpus_covers_template_css_copy_and_headline() -> None:
    """扫描面必须真的把这四块都包进来，否则闸门有绕过的口子。"""
    report = build_page_one_sample()
    corpus = our_copy_corpus(report)
    assert report.headline in corpus
    assert COPY_ZH["chain_footnote"] in corpus
    assert "{{ chain_svg|safe }}" in corpus  # 模板源文
    assert "break-inside: avoid" in corpus  # CSS 源文


def test_assert_no_banned_words_fires_on_our_own_prose() -> None:
    """我们自己写一句禁词就必须当场被挡。"""
    for word in _BANNED_WORDS:
        with pytest.raises(AssertionError, match="报告出现禁词"):
            assert_no_banned_words(f"这个站{word}。")


def test_customer_data_with_banned_words_still_renders() -> None:
    """裁决一的核心断言：甲方页面里出现禁词**不许**让报告产不出来。

    公司名含 Lighthouse / Ahrefs 是真事，把「引用」当成「我们的结论」拦下来，
    等于让 20.8% 那批站里的一部分连报告都拿不到。
    """
    report = build_hostile_report()
    html = render_html(report)  # type: ignore[arg-type]
    for word in HOSTILE_STRINGS:
        assert word in html  # 证据逐字回显，没被篡改
    assert_no_banned_words(our_copy_corpus(report))  # 我们的文案照旧干净


def test_appendix_b1_wording_is_fixed_and_the_forbidden_claim_is_absent() -> None:
    """附录 B-1：不许写「任何现成工具都会给出错的答案」——
    实测从未跑过任何现成工具做对照。固定措辞只能是那一句。"""
    for build in ALL_BUILDERS:
        html = render_html(build())
        assert "只探根路径、不做对照探测的实现" in html
        assert "任何现成工具" not in html
        assert "所有工具" not in html


def test_zero_finding_report_has_none_of_the_three_bans() -> None:
    """§6.3 三条硬性禁令的第 1 条 + 第 2 条（第 3 条在 test_report_shape.py）。"""
    html = render_html(build_zero_finding_report())
    for word in ("恭喜", "没有问题", "一切正常", "完美", "满分"):
        assert word not in html
    html_unknown = render_html(build_unusable_report())
    assert "全部通过" not in html_unknown


def test_unknown_is_never_rendered_as_ok() -> None:
    """任务书第 3 条产品硬约束：``Status.UNKNOWN`` 永不折算成 PASS。"""
    report = build_unusable_report()
    html = render_html(report)
    assert "未能评估" in html
    assert report.counts.positions_unknown > 0
    # 「未能评估」与「没问题」在报告里严格分开，且这句话本身要印出来
    assert "「未能评估」与「没问题」在这份报告里严格分开" in html


# --------------------------------------------------------------------------- #
# A36 · 安全
# --------------------------------------------------------------------------- #


def test_a36_javascript_and_data_urls_never_reach_an_href() -> None:
    """``safe_href`` 把它们降级成 ``#``，并以纯文本展示。"""
    html = render_html(build_hostile_report())  # type: ignore[arg-type]
    assert not re.search(r'href\s*=\s*["\']\s*javascript:', html, re.I)
    assert not re.search(r'href\s*=\s*["\']\s*data:', html, re.I)
    # 但它们仍然作为证据以纯文本出现 —— 甲方要看得见自己站上写的是什么
    assert str(escape(JS_HREF)) in html
    assert str(escape(DATA_HREF)) in html


def test_a36_script_in_anchor_text_is_escaped_not_executed() -> None:
    html = render_html(build_hostile_report())  # type: ignore[arg-type]
    assert XSS_ANCHOR not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_safe_href_filter_directly() -> None:
    from geo_audit.report.render import _ENV

    f = _ENV.filters["safe_href"]
    assert f("https://example.com/x") == "https://example.com/x"
    assert f("http://example.com/x") == "http://example.com/x"
    assert f(JS_HREF) == "#"
    assert f(DATA_HREF) == "#"
    assert f("/relative") == "#"
    assert f("//evil.example") == "#"


def test_thousands_and_shorten_filters() -> None:
    from geo_audit.report.render import _ENV

    thousands = _ENV.filters["thousands"]
    shorten = _ENV.filters["shorten"]
    assert thousands(384052) == "384,052"
    assert thousands("x") == "x"
    assert shorten("a" * 100).endswith("…")
    assert len(shorten("a" * 100)) == 90
    assert shorten("abc") == "abc"


# --------------------------------------------------------------------------- #
# 渲染期闸门整体
# --------------------------------------------------------------------------- #


def test_render_html_refuses_a_report_whose_counts_were_hand_edited() -> None:
    """§6.4 R6 / A31 的恒等式在渲染期就挡（不是只在测试里）。"""
    from dataclasses import replace

    report = build_page_one_sample()
    broken = replace(report, counts=replace(report.counts, positions_unknown=0))
    with pytest.raises(AssertionError, match="四格之和"):
        render_html(broken)


def test_render_html_refuses_when_positions_and_counts_disagree() -> None:
    from dataclasses import replace

    report = build_page_one_sample()
    broken = replace(report, positions=report.positions[:-1])
    with pytest.raises(AssertionError, match=r"len\(report\.positions\)"):
        render_html(broken)


def test_render_is_deterministic() -> None:
    """L 组：同一个 Report 渲染两次逐字节相同（报告要可复现比对）。"""
    report = build_page_one_sample()
    assert render_html(report) == render_html(report)


def test_strict_undefined_is_on() -> None:
    """模板里漏一个键必须当场炸，不许静默渲染出空白（StrictUndefined）。"""
    from jinja2 import StrictUndefined, UndefinedError

    from geo_audit.report.render import _ENV

    assert _ENV.undefined is StrictUndefined
    with pytest.raises(UndefinedError):
        _ENV.from_string("{{ nope.attr }}").render()


def test_autoescape_is_on_for_strings_too() -> None:
    from geo_audit.report.render import _ENV

    assert _ENV.from_string("{{ x }}").render(x="<b>") == "&lt;b&gt;"


def test_every_stage_and_status_label_is_rendered_somewhere() -> None:
    """六格标签与四态标签都必须真的出现在报告里（页面上没有孤儿常量）。"""
    from geo_audit.models import STAGE_LABEL
    from geo_audit.report.copy_zh import STATUS_LABEL

    html = render_html(build_page_one_sample())
    for stage in Stage:
        assert STAGE_LABEL[stage] in html
    for status in Status:
        assert STATUS_LABEL[status.value] in html


def test_severity_and_finding_id_shape() -> None:
    """finding_id 形状是 ``GA-[0-9A-F]{10}``（schema 的三条硬约束之一）。"""
    report = build_page_one_sample()
    for f in report.findings:
        assert re.fullmatch(r"GA-[0-9A-F]{10}", f.finding_id)
        assert f.severity in tuple(Severity)
    assert re.fullmatch(r"GA-[0-9A-F]{10}", make_finding_id("x.y", "https://example.com/z", None))


def test_ua_is_printed_and_matches_the_compliance_shape() -> None:
    """A40 的 UA 形状 —— 页眉与 curl_repro 里印的是同一个。"""
    assert re.fullmatch(r"geo-audit/\d+\.\d+\.\d+ \(\+https://[^;]+; contact: .+@.+\)", UA)
    html = render_html(build_page_one_sample())
    assert UA in html


# ═════════════════════════════════════════════════════════════════════════════
# 自包含闸门的**扫描面**（修一处设计缺陷之后补的）
#
# 原实现是 `_defang(html)` 再 `assert_selfcontained(html)`。_defang 是对整份产物
# 的全局无差别替换，跑完之后 `_FORBIDDEN` 的第 4 条（@import）与第 5 条
# （url(http）**结构性地不可能再触发** —— 不管那两个字节序列来自甲方数据还是
# 来自我们自己的疏漏。一个永远不会红的断言不是闸门。
#
# 现在的分工（与 assert_no_banned_words 的裁决同一个思路：换扫描面而非改规则）：
#   assert_selfcontained(_our_markup(html))  扫我们自己写的那部分
#   assert_no_external_refs(html)            对整份跑前三条
#   _defang(html)                            最后跑，只为浏览器端
# ═════════════════════════════════════════════════════════════════════════════


def test_selfcontained_gate_scans_our_own_source_not_the_product() -> None:
    """闸门扫的是**我们写的源文**（模板 + CSS），不是渲染产物。

    第一版试图用 `data-customer` 标记从产物里挖掉甲方区 —— 模板里那个标记根本
    不存在，所以那版实现完全没生效。现在的定义与 `our_copy_corpus` 一致：
    源文才是我们写的字。

    这条测试同时证明两件事：
      1. 我们的源文现在是干净的（没有 @import、没有 url(http）；
      2. 甲方数据里的同一批字节序列**不会**让报告判自己不自包含 ——
         `build_hostile_report()` 的 inline_style 里就有 `url(https://cdn…)`、
         html_snippet 里就有 `@import`（本文件第 83-84 行的 fixture），
         而下面那条 A36 测试渲染它时不该红。
    """
    assert_selfcontained(_our_markup())


def test_selfcontained_gate_bites_our_own_slips() -> None:
    """反向：我们自己的源文里出现外链就必须红。一个永远不会红的断言不是闸门。"""
    for bad in (
        "<style>@import url(https://evil/x.css);</style>",
        "<style>body{background:url(https://cdn/x.png)}</style>",
        '<link rel="stylesheet" href="https://cdn/x.css">',
    ):
        with pytest.raises(AssertionError):
            assert_selfcontained(bad)
    # 片段引用不算外链（链路图的斜纹填充用的就是它）
    assert_selfcontained("<style>.hatch{fill:url(#geoHatch)}</style>")


def test_external_ref_gate_runs_on_the_whole_document() -> None:
    """`_FORBIDDEN` 的前三条对**整份产物**跑。

    它们与后两条的区别：后两条（`@import` / `url(http`）会被甲方的 CSS 值误触发
    （本文件第 83-84 行的 hostile fixture 里就有），前三条不会 —— 而且甲方数据里
    真冒出一个 `<script src=...>`，那不是「引用了外部资源」而是我们的转义漏了，
    必须当场红。
    """
    with pytest.raises(AssertionError):
        assert_no_external_refs('<p><script src="https://evil/x.js"></script></p>')
    with pytest.raises(AssertionError):
        assert_no_external_refs('<link rel="stylesheet" href="https://cdn/x.css">')
    # 甲方 CSS 值里的 url(http 不在前三条的管辖范围，扫整份也不该红
    assert_no_external_refs("<p>background: url(https://cdn.example.net/hero.png)</p>")


def test_defang_runs_last_so_the_gate_can_still_bite() -> None:
    """回归守卫：不许有人把 _defang 挪到闸门之前。

    判据是源码顺序 —— 这条性质没法从行为上测（defang 之后行为看起来是对的，
    只是闸门永远不红了，而那正是我们要防的东西）。
    """
    src = inspect.getsource(render_mod.render_html)
    # 三个闸门都必须在 _defang 之前。取各自**最后一次**出现的位置：
    # _defang 现在写在 `return _defang(html)` 里，是函数体的最后一句。
    i_defang = src.rindex("_defang(")
    for gate in ("assert_selfcontained(", "assert_no_external_refs(", "assert_no_banned_words("):
        assert src.rindex(gate) < i_defang, (
            f"{gate} 跑在 _defang 之后 —— _defang 是对整份产物的全局替换，"
            "跑完之后 _FORBIDDEN 的后两条结构性不可能触发，闸门就废了"
            "（见本文件上方那段注释）"
        )
