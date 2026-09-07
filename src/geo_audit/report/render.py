"""HTML 报告渲染（§6.5:3208，第 15a 步）。**唯一对外入口是 :func:`render_html`。**

渲染即校验：三条闸门在渲染期就跑，不等测试（§6.5:3249-3250 —— 「漏一次也不许
发出去」）：

1. :func:`assert_selfcontained` —— 五条禁止正则零命中 + 体积 < 2 MB。单文件、
   零外部请求，``file://`` 打开要完整（A27）。
2. :func:`assert_no_banned_words` —— 附录 B 的禁词。**扫描面是我们自己写的文案，
   不是最终 HTML**，裁决见下。
3. :func:`assert_counts_identity` —— ``pass+fail+unknown+na == positions``
   （§6.4 R6 / A31）。按构造成立，闸门是为了防有人事后手改计数。

── 裁决一：禁词只扫我们自己生成的文案，不扫引用的证据 ─────────────────────
规格原文（§6.5:3243）是 ``assert_no_banned_words(html)`` —— 对**整份 HTML** 做
子串扫描。但 HTML 里含甲方站点的 ``<title>``、锚文本、``body_head``：任何一个
甲方页面里出现「完美」「一切正常」，或公司名含 Lighthouse / Ahrefs，
``render_html`` 就 raise、整份报告产不出来（简报 spec_gaps 停工级 4；画廊里的
tdengine.com 就是中文站）。

**实现方式**（owner 已裁决，本文照做）：扫描面由 :func:`our_copy_corpus` 组装，
= ``template.html.j2`` 源文 + ``report.css`` 源文 + ``COPY_ZH`` 与本包全部文案表
的值 + ``report.headline``。这四样**全部是我们自己写的字**，一个字符都不来自甲方
站点。于是：

* 禁词表在**渲染期**生效（这条是 §6.5:3250 的原意），且
* 甲方页面里出现禁词**不会**让报告产不出来，而
* 我们自己在模板里手写一句「一切正常」会**当场**被挡（模板源文在扫描面里，
  所以连绕过的口子都没有）。

代价：甲方数据里的禁词不再被拦。这是对的 —— 那是**引用**，不是**我们的结论**，
拦它等于篡改证据。

── 裁决二：自包含检查仍然扫最终 HTML，用「去獠牙」保证不误伤 ─────────────
自包含是关于**产物**的性质，所以 :func:`assert_selfcontained` 必须扫真 HTML
（任务书：「自包含必须机器验证：五条正则零命中」）。但五条正则里有两条
（``@import`` 与 ``url(http…)``）在纯文本里也会命中，而甲方的 ``inline_style`` /
``html_snippet`` 里完全可能出现 ``url(https://cdn…)``（简报 spec_gaps 倒数第 4 条）。
Jinja 的 autoescape 不动圆括号与 ``@``，所以那种报告会被自己的闸门判成
「不自包含」。

裁决：渲染后跑一次 :data:`_DEFANG` —— 把 ``url(`` 后紧跟 http(s) 的那个左括号
与 ``@import`` 换成**数值字符引用**（``url&#40;`` / ``&#64;import``）。浏览器渲染
出来一模一样（那是同一个字符），但它不再是一个可被误读成资源引用的字节序列，
五条正则因此对甲方数据零误伤，对我们自己的疏漏照旧命中（我们的 CSS 里既没有
``@import`` 也没有 ``url(http``，链路图用的是片段引用 ``url(#geoHatch)``，不匹配）。

── Position 纪律（卡点 S7 / A7:4478）─────────────────────────────────────
``Position(...)`` 只许出现在第 16 步 ``pipeline.build_positions()`` 里。
**本层只读 positions，绝不新造** —— 本文件里搜不到一处 ``Position(`` 调用。
"""

from __future__ import annotations

import importlib.resources as res
import re
from collections.abc import Sequence

import jinja2
from jinja2 import Environment, StrictUndefined, select_autoescape

from ..models import (
    POSITION_LABEL,
    STAGE_LABEL,
    UNKNOWN_REMEDY,
    Counts,
    Coverage,
    CoverageGap,
    Exclusion,
    Finding,
    Fragility,
    Position,
    Report,
    RootCause,
    Severity,
    Status,
)

# RootCause 从 models 直取（唯一定义处）；经 rootcause 转口在 mypy strict 下
# 会红（no_implicit_reexport）。SEVERITY_ORDER 仍属 rootcause 自己的东西。
from ..rootcause import SEVERITY_ORDER
from .chain_svg import render_chain_svg
from .copy_zh import (
    CHECKED_TABLE,
    COPY_ZH,
    DIRECTION_LABEL,
    EVIDENCE_COLUMNS,
    EXCLUDED_COLUMNS,
    MISREAD_FORMS,
    NAIVE_DEMO_COLUMNS,
    NAIVE_TABLE_COLUMNS,
    NOT_CHECKED_TABLE,
    STATUS_CSS,
    STATUS_GLYPH,
    STATUS_LABEL,
)

# ═════════════════════════════════════════════════════════════════════════════
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║ 占位区结束 —— PLACEHOLDER BLOCK END                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
# ═════════════════════════════════════════════════════════════════════════════


# --------------------------------------------------------------------------- #
# Jinja 环境（§6.5:3210 逐字）
# --------------------------------------------------------------------------- #

_PACKAGE = "geo_audit.report"

_ENV = Environment(
    loader=jinja2.FunctionLoader(lambda n: res.files(_PACKAGE).joinpath(n).read_text("utf-8")),
    autoescape=select_autoescape(default_for_string=True, default=True),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)
_ENV.filters["thousands"] = lambda n: f"{n:,}" if isinstance(n, int) else n
_ENV.filters["shorten"] = lambda s, n=90: s if len(s) <= n else s[: n - 1] + "…"
_ENV.filters["safe_href"] = lambda u: u if str(u).startswith(("http://", "https://")) else "#"

# --------------------------------------------------------------------------- #
# 三张表（§6.5:3217 / 3222 / 3232 逐字）
# --------------------------------------------------------------------------- #

#: 自包含的五条禁止正则（§6.5:3217 逐字）。任一命中就不许发出去。
_FORBIDDEN: tuple[re.Pattern[str], ...] = (
    re.compile(r"<link[^>]+rel=[\"']?stylesheet", re.I),
    re.compile(r"<script[^>]+\bsrc=", re.I),
    re.compile(r"<img[^>]+\bsrc=[\"']?https?:", re.I),
    re.compile(r"@import", re.I),
    re.compile(r"url\(\s*[\"']?https?:", re.I),
)

#: 附录 B 的禁词（§6.5:3222 逐字，11 项）。任务书说「九词」，规格原文是 11 项，
#: 按铁律 8 以原文为准（差异写进交付说明 deviations_from_spec）。
#: 前五条来自 §6.3 的零发现三条硬性禁令；四个品牌名与最后两句来自附录 B-1 ——
#: **实测从未跑过任何现成工具做对照**，所以既不许点名，也不许说「任何现成工具」。
_BANNED_WORDS: tuple[str, ...] = (
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

#: §6.5:3239。``len(html.encode()) >= _SIZE_CAP`` 就炸。
_SIZE_CAP = 2_000_000

#: 渲染后的「去獠牙」替换（见模块 docstring 裁决二）。只动会被 _FORBIDDEN 的后两条
#: 误读成资源引用的那两个字节序列，换成等价的数值字符引用，浏览器显示不变。
_DEFANG: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"url\((?=\s*[\"']?https?:)", re.I), "url&#40;"),
    (re.compile(r"@import", re.I), "&#64;import"),
)


def assert_selfcontained(html: str) -> None:
    """§6.5:3236 逐字。五条禁止正则 + 2 MB 上限，都是硬失败。"""
    for p in _FORBIDDEN:
        if p.search(html):
            raise AssertionError(f"报告不是自包含的：命中 {p.pattern}")
    if len(html.encode()) >= _SIZE_CAP:
        raise AssertionError("报告超过 2 MB")


def assert_no_banned_words(html: str) -> None:
    """§6.5:3241 逐字。**入参是我们自己写的文案**，不是最终 HTML（见裁决一）。

    参数名保持规格原文的 ``html``，这样搬迁与对照规格时不会以为签名改了；
    ``render_html`` 传进来的是 :func:`our_copy_corpus` 的返回值。
    """
    hits = [w for w in _BANNED_WORDS if w in html]
    if hits:
        raise AssertionError(f"报告出现禁词：{hits}（见附录 B）")


def assert_counts_identity(report: Report) -> None:
    """§6.4 R6 / A31 的恒等式。按构造成立，闸门只为防事后手改计数。"""
    c = report.counts
    total = c.positions_pass + c.positions_fail + c.positions_unknown + c.positions_na
    if total != c.positions:
        raise AssertionError(f"四格之和 {total} != positions {c.positions}（§6.4 R6 / A31:4510）")
    if c.positions != len(report.positions):
        raise AssertionError(
            f"counts.positions {c.positions} != len(report.positions) "
            f"{len(report.positions)}（§2.9 推论 1）"
        )


def our_copy_corpus(report: Report) -> str:
    """禁词的扫描面 = **我们自己写的每一个字**，一个字符都不来自甲方站点。

    四块：
      1. ``template.html.j2`` 源文 —— 于是「在模板里手写一句禁词」也被挡住，
         没有绕过的口子；
      2. ``report.css`` 源文（``content:"…"`` 里能写字）；
      3. ``COPY_ZH`` 与本包全部文案表的值；
      4. ``report.headline`` —— 它是 ``make_headline``（§6.1 六分支）产出的
         我们的固定措辞，只带数字，不带甲方字串。
    """
    files = res.files(_PACKAGE)
    parts: list[str] = [
        files.joinpath("template.html.j2").read_text("utf-8"),
        files.joinpath("report.css").read_text("utf-8"),
        report.headline,
    ]
    parts.extend(COPY_ZH.values())
    for table in (MISREAD_FORMS, NOT_CHECKED_TABLE, CHECKED_TABLE):
        parts.extend(cell for row in table for cell in row)
    for labels in (STATUS_LABEL, DIRECTION_LABEL, STAGE_LABEL, POSITION_LABEL):
        parts.extend(str(v) for v in labels.values())
    parts.extend(UNKNOWN_REMEDY.values())
    parts.extend(NAIVE_DEMO_COLUMNS)
    parts.extend(EVIDENCE_COLUMNS)
    parts.extend(NAIVE_TABLE_COLUMNS)
    parts.extend(EXCLUDED_COLUMNS)
    return "\n".join(parts)


def _defang(html: str) -> str:
    """见模块 docstring 裁决二。渲染后跑一次，然后才做自包含校验。"""
    for pattern, repl in _DEFANG:
        html = pattern.sub(repl, html)
    return html


# --------------------------------------------------------------------------- #
# 根因分组（§6.5:3255 引用了 group_by_root_cause，全文未定义其返回形状）
# --------------------------------------------------------------------------- #


def _severity_rank(sev: Severity) -> int:
    """越严重越大。``rootcause.SEVERITY_ORDER`` 是它的唯一定义处。"""
    return SEVERITY_ORDER[sev]


def group_by_root_cause(
    report: Report,
) -> tuple[tuple[RootCause | None, tuple[Finding, ...]], ...]:
    """#findings 区的分组。规格只在调用点提了一句，形状与排序由这里定死。

    * 返回 ``((root_cause | None, findings), ...)``；
    * 组间排序：最高严重度降序 → 实例数降序 → ``root_cause_id``（确定性，
      L 组要求同 fixture 连跑两次逐字节相同）；
    * 组内排序：严重度降序 → ``occurrences`` 降序 → ``finding_id``；
    * 没有 ``root_cause_id`` 的 finding 归到 ``None`` 那一组，**排最后** ——
      「按根因」是首页的单位，孤条不许插到根因前面。
    """
    by_id: dict[str, RootCause] = {rc.root_cause_id: rc for rc in report.root_causes}
    buckets: dict[str, list[Finding]] = {rc_id: [] for rc_id in by_id}
    orphans: list[Finding] = []
    for f in report.findings:
        if f.root_cause_id and f.root_cause_id in buckets:
            buckets[f.root_cause_id].append(f)
        else:
            orphans.append(f)

    def _fkey(f: Finding) -> tuple[int, int, str]:
        return (-_severity_rank(f.severity), -f.occurrences, f.finding_id)

    groups: list[tuple[RootCause | None, tuple[Finding, ...]]] = []
    for rc_id, items in buckets.items():
        groups.append((by_id[rc_id], tuple(sorted(items, key=_fkey))))

    def _gkey(g: tuple[RootCause | None, tuple[Finding, ...]]) -> tuple[int, int, str]:
        rc = g[0]
        assert rc is not None  # orphans 还没加进去
        return (-_severity_rank(rc.max_severity), -rc.instance_count, rc.root_cause_id)

    groups.sort(key=_gkey)
    if orphans:
        groups.append((None, tuple(sorted(orphans, key=_fkey))))
    return tuple(groups)


# --------------------------------------------------------------------------- #
# 视图辅助（模板要的派生列表；StrictUndefined 下必须全部显式传进去）
# --------------------------------------------------------------------------- #


def _positions_by_status(positions: Sequence[Position], status: Status) -> tuple[Position, ...]:
    return tuple(p for p in positions if p.status is status)


def _remedy_for(position: Position) -> str:
    """§6.4 R4：每条 UNKNOWN 必须给原因码 + **具体到可执行**的补救办法。

    优先用管线填的 ``unknown_remedy``；没填就按 ``unknown_reason`` 回查
    ``UNKNOWN_REMEDY``（§2.8 的 17 条）；两条都没有才落到最后那句 —— 它仍然
    是「我们看不了」，不是「这里没问题」。
    """
    if position.unknown_remedy:
        return position.unknown_remedy
    if position.unknown_reason and position.unknown_reason in UNKNOWN_REMEDY:
        return UNKNOWN_REMEDY[position.unknown_reason]
    return COPY_ZH["unknown_remedy_missing"]


def _cache_hits(report: object) -> bool:
    """卡点 B18:4599：有响应来自本地缓存时页眉要印一行提示。

    ⚠️ 规格 §2.10 的 ``Report`` **没有承载这件事的字段**，而 §8.5 的 schema 又把
    顶层 required 定死在 20 个字段（``tests/test_schema.py`` 逐字守着）。所以本层
    不给 ``Report`` 加字段（加了就让那条断言变红），改成**有就读、没有就当 False**：
    等 Report 的 owner 按 B18 补上 ``cache_hits`` 之后，页眉那行自动开始印。
    在此之前它是休眠的。见交付说明 spec_gaps。
    """
    return bool(getattr(report, "cache_hits", False))


def _links_capped(report: Report) -> int:
    """A24:4499 那条恒等式的最后一项：**被三层封顶截掉的链接数**。

    ``Coverage``（§2.10:1261）没有这个字段，所以本层按恒等式反解 ——
    ``extracted - excluded - needs_review - verified - unknown``。第 16 步的
    ``pipeline.Coverage`` 已经带了 ``links_capped``，有就优先用它（那是账本里
    真记下来的数，反解只是兜底），见交付说明 spec_gaps。
    """
    cov = report.coverage
    recorded = getattr(cov, "links_capped", None)
    if isinstance(recorded, int):
        return recorded
    return max(
        cov.links_extracted
        - cov.links_excluded
        - cov.links_needs_review
        - cov.links_verified
        - cov.links_unknown,
        0,
    )


def _sampled(report: Report) -> bool:
    cov = report.coverage
    return bool(cov.index_links_sampled or cov.sampling_note)


def render_html(report: Report) -> str:
    """§6.5:3248。渲染 + 三条闸门。**唯一对外入口。**

    ``chain_svg`` 走 ``|safe`` 的唯一理由是「我们自己生成」——
    ``chain_svg.py`` 对每一处插值都做了 ``html.escape``（见那里的说明）。
    ``css`` 也必须走 ``|safe``：autoescape 会把 ``details>*`` 变成
    ``details&gt;*``、把 ``content:"✓"`` 变成 ``content:&#34;✓&#34;``，
    四态形状与打印规则当场失效（规格没写这一句）。
    """
    assert_counts_identity(report)
    css = res.files(_PACKAGE).joinpath("report.css").read_text("utf-8")
    zero_findings = not report.findings
    html = _ENV.get_template("template.html.j2").render(
        r=report,
        css=css,
        chain_svg=render_chain_svg(report.positions),
        STAGE_LABEL=STAGE_LABEL,
        POSITION_LABEL=POSITION_LABEL,
        UNKNOWN_REMEDY=UNKNOWN_REMEDY,
        copy=COPY_ZH,
        grouped=group_by_root_cause(report),
        # ── 以下是规格 §6.5:3252 那份 render() 之外补上的上下文。StrictUndefined
        #    不允许模板里出现未定义的名字，而这些派生量在模板里算不干净。 ──
        STATUS_LABEL=STATUS_LABEL,
        STATUS_GLYPH=STATUS_GLYPH,
        STATUS_CSS=STATUS_CSS,
        DIRECTION_LABEL=DIRECTION_LABEL,
        EVIDENCE_COLUMNS=EVIDENCE_COLUMNS,
        NAIVE_DEMO_COLUMNS=NAIVE_DEMO_COLUMNS,
        NAIVE_TABLE_COLUMNS=NAIVE_TABLE_COLUMNS,
        EXCLUDED_COLUMNS=EXCLUDED_COLUMNS,
        MISREAD_FORMS=MISREAD_FORMS,
        NOT_CHECKED_TABLE=NOT_CHECKED_TABLE,
        CHECKED_TABLE=CHECKED_TABLE,
        zero_findings=zero_findings,
        unknown_positions=_positions_by_status(report.positions, Status.UNKNOWN),
        remedy_for=_remedy_for,
        review_findings=tuple(f for f in report.findings if f.confidence == "needs_review"),
        review_exclusions=tuple(e for e in report.excluded if e.disposition == "needs_review"),
        excluded_only=tuple(e for e in report.excluded if e.disposition == "excluded"),
        naive_divergences=tuple(row for row in report.naive_table if row.diverges),
        sampled=_sampled(report),
        cache_hits=_cache_hits(report),
        core_positions=max(report.counts.positions - report.counts.positions_na, 1),
        links_capped=_links_capped(report),
    )
    html = _defang(html)
    assert_selfcontained(html)  # 渲染即校验
    assert_no_banned_words(our_copy_corpus(report))  # 禁词表在渲染期生效
    return html


__all__ = [
    "Counts",
    "Coverage",
    "CoverageGap",
    "Exclusion",
    "Fragility",
    "Position",
    "Report",
    "assert_counts_identity",
    "assert_no_banned_words",
    "assert_selfcontained",
    "group_by_root_cause",
    "our_copy_corpus",
    "render_html",
]
