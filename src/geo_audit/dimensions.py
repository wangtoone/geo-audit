"""首屏四个维度：红 / 黄 / 绿 / 灰 + 一句大白话。没有总分。

输入全是已经算好的事实（位置账本、首页 / robots / sitemap 事实），**不发请求、不调模型**。
规则只有两条：

* 灰（没看到）**永远不折算成绿**：某一维有任何灰，最好也只能是灰；
* 红 > 黄 > 灰 > 绿：已看到的坏事实盖过没看到的部分，但灰的计数照样显示。

「没有做渲染对比」是默认版的固定披露：计入「没挖到」的计数并写进句子，
但不把维度本身压成灰（否则默认版永远没有绿，等于不给信息）。
"""

from __future__ import annotations

from collections.abc import Sequence

from geo_audit.models import (
    DimensionVerdict,
    HostRobotsFacts,
    PageSeoFacts,
    Position,
    SitemapFacts,
    Stage,
    Status,
    unknown_category,
)

SEARCH_ENGINES = ("Googlebot", "Bingbot", "Baiduspider")
_RENDER_NOTE = "没有做渲染对比，看不到「爬虫看到的 vs 用户看到的」冲突。"


class _Tally:
    def __init__(self) -> None:
        self.red: list[str] = []
        self.yellow: list[str] = []
        self.gray: list[str] = []
        self.not_dug = 0
        self.absent = 0
        self.blocked = 0

    def gray_reason(self, text: str, reason: str | None) -> None:
        self.gray.append(text)
        if unknown_category(reason) == "blocked":
            self.blocked += 1
        else:
            self.not_dug += 1

    def verdict(self, key: str, label: str, green: str, *, note: str = "") -> DimensionVerdict:
        if self.red:
            state, parts = "red", self.red
        elif self.yellow:
            state, parts = "yellow", self.yellow
        elif self.gray:
            state, parts = "gray", self.gray
        else:
            state, parts = "green", [green]
        sentence = "；".join(parts)
        extra = [p for p in self.gray if state in ("red", "yellow")]
        if extra:
            sentence += "。另有没看到的：" + "；".join(extra)
        return DimensionVerdict(
            key=key,
            label=label,
            state=state,
            sentence=sentence + ("。" if not sentence.endswith("。") else "") + note,
            not_dug=self.not_dug,
            absent=self.absent,
            blocked=self.blocked,
        )


def _hosts(facts: Sequence[PageSeoFacts], pred: str) -> str:
    return "、".join(f.host for f in facts if pred in f.flags)


def _readable(seo: Sequence[PageSeoFacts]) -> DimensionVerdict:
    t = _Tally()
    if not seo:
        t.gray_reason("没读到任何首页", "not_fetched")
    shell = [f.host for f in seo if f.raw_html_tier == "shell"]
    partial = [f.host for f in seo if f.raw_html_tier == "partial"]
    if shell:
        t.red.append(
            f"{'、'.join(shell)} 的首页原始 HTML 几乎是空壳（推断：正文靠 JS 渲染），"
            "不跑 JS 的爬虫读不到正文"
        )
    if partial:
        t.yellow.append(f"{'、'.join(partial)} 的首页原始 HTML 里正文偏少（推断）")
    for f in seo:
        if f.raw_html_tier == "unreadable":
            t.gray_reason(f"{f.host} 的首页没读到（{f.unreadable_reason}）", f.unreadable_reason)
    t.not_dug += 1  # 固定披露：没做渲染对比
    return t.verdict(
        "readable",
        "能不能被读到",
        "已读到的首页原始 HTML 里都有完整正文（推断）",
        note=_RENDER_NOTE,
    )


def _indexable(
    seo: Sequence[PageSeoFacts],
    robots: Sequence[HostRobotsFacts],
    sitemaps: Sequence[SitemapFacts],
) -> DimensionVerdict:
    t = _Tally()
    if h := _hosts(seo, "noindex"):
        t.red.append(f"{h} 的首页带 noindex")
    if h := _hosts(seo, "canonical_other_host"):
        t.red.append(f"{h} 的首页 canonical 指向别的域名，搜索引擎可能把它当副本")
    if h := _hosts(seo, "canonical_other_path"):
        t.yellow.append(f"{h} 的首页 canonical 指向本站别的路径")
    if h := _hosts(seo, "canonical_missing"):
        t.yellow.append(f"{h} 的首页没写 canonical")
    for r in robots:
        blocked = [
            c.token for c in r.crawlers if c.token in SEARCH_ENGINES and c.access == "blocked_all"
        ]
        if blocked:
            t.red.append(f"{r.host} 的 robots.txt 把 {'、'.join(blocked)} 整站挡掉")
        if not r.readable:
            # 403 / 401 / 429 是被拦；5xx、网络错误是没挖到。
            blocked_status = r.status in (401, 403, 429)
            t.gray_reason(
                f"{r.host} 的 robots.txt 没读到",
                "robots_unreadable" if blocked_status else "network_error",
            )
    for sm in sitemaps:
        noindexed = [x for x in sm.flags if x.startswith("sample_noindex")]
        if noindexed:
            t.red.append(f"{sm.host} 的 sitemap 抽样页里有 noindex（{noindexed[0].split(':')[1]}）")
        if sm.state == "blocked":
            t.gray_reason(f"{sm.host} 的 sitemap 被拦（HTTP {sm.status}）", "waf_status")
        elif sm.state == "unreadable":
            t.gray_reason(f"{sm.host} 的 sitemap 没读到", "not_fetched")
        elif sm.state == "absent":
            t.gray.append(f"{sm.host} 确实没有 sitemap")
            t.absent += 1
        elif sm.state == "ok" and not sm.sample:
            t.gray_reason(f"{sm.host} 的 sitemap 没抽样（预算用完）", "not_fetched")
    for f in seo:
        if f.raw_html_tier == "unreadable":
            t.gray_reason(f"{f.host} 的首页没读到（{f.unreadable_reason}）", f.unreadable_reason)
    if not seo:
        t.gray_reason("没读到任何首页", "not_fetched")
    return t.verdict(
        "indexable", "能不能被索引", "已读到的首页、robots 和 sitemap 抽样页没发现挡索引的设置"
    )


def _from_positions(
    positions: Sequence[Position],
    stages: frozenset[Stage],
    *,
    key: str,
    label: str,
    enabled: bool,
    green: str,
    fail_text: str,
    empty_absent: str = "",
) -> DimensionVerdict:
    t = _Tally()
    if not enabled:
        t.gray_reason("这一项没有检查", "not_fetched")
        return t.verdict(key, label, green)
    mine = [p for p in positions if p.stage in stages]
    fails = [p for p in mine if p.status is Status.FAIL]
    if fails:
        t.red.append(fail_text.format(n=len(fails)))
    for p in mine:
        if p.status is Status.UNKNOWN:
            t.gray_reason(f"{p.label}（{p.unknown_reason}）", p.unknown_reason)
    if empty_absent and not any(p.status is Status.PASS for p in mine) and not t.gray and not fails:
        t.gray.append(empty_absent)
        t.absent += 1
    return t.verdict(key, label, green)


def build_dimensions(
    positions: Sequence[Position],
    seo_facts: Sequence[PageSeoFacts],
    robots_facts: Sequence[HostRobotsFacts],
    sitemap_facts: Sequence[SitemapFacts],
    *,
    checks: frozenset[str],
) -> tuple[DimensionVerdict, ...]:
    return (
        _readable(seo_facts),
        _indexable(seo_facts, robots_facts, sitemap_facts),
        _from_positions(
            positions,
            frozenset({Stage.INDEX_FILE, Stage.FULLTEXT, Stage.MD_CHANNEL, Stage.INDEX_LINKS}),
            key="ai_channel",
            label="AI 通道",
            enabled="ai_path" in checks,
            green="llms.txt / llms-full.txt 等 AI 通道读得对",
            fail_text="AI 通道上有 {n} 个位置会被读错",
            empty_absent="没有 llms.txt / llms-full.txt（诚实 404），AI 只能靠爬 HTML",
        ),
        _from_positions(
            positions,
            frozenset({Stage.HUMAN_PATH}),
            key="dead_links",
            label="死链",
            enabled="dead_links" in checks,
            green="抽到的可点击路径都活着",
            fail_text="{n} 条人和爬虫都会点的路径是死链",
        ),
    )
