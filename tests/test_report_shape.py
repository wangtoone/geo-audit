"""I / O 组 · 报告形态与链路图（§6.1 / §6.3 / §6.4，第 15a + 15b 步自验）。

本文件同时是**报告层的合成 fixture 工厂**：``tests/test_render_selfcontained.py``
从这里 import 那几个 builder。为什么是合成而不是实录：``fixtures/`` 正在录制中
（第 4b 步，另一个进程在写），而报告层的形态断言一条都不依赖真快照 —— 它们依赖的是
``Report`` 的形状。等第 16 步的 ``pipeline.build_positions()`` 落地后，这些 builder
应当换成从 fixture 回放出的真 ``Report``（届时按现有写法优雅 skip）。

``build_page_one_sample()`` 逐字复刻 §6.1:3015-3018 修正后的**自洽 16 格样本**：

    16 个位置 = 3 fail + 1 unknown + 10 pass + 2 na
    core = 16 - 2 = 14；unknown/core = 1/14 = 7% <= 0.5 -> 走 has_fail 分支
    逐格：①=4 全 pass、②+③=4（2 fail + 1 unknown + 1 na）、④=1 fail、
          ⑤=1 na、⑥=6 全 pass

v1 那份写「14 个位置」而四格加起来是 16、且 11/14 unknown 该走 unusable 却印
has_fail 文案（卡点 S7）—— **别再用 v1 的数**。

⚠️ ``Position(`` 只许出现在第 16 步的 ``pipeline.build_positions()`` 里（A7:4478），
那条 grep 的范围是 ``src/``；测试里构造合成位置不受它约束，报告层的 ``src/`` 代码
里一处都没有。
"""

from __future__ import annotations

import re

import pytest
from markupsafe import escape

from geo_audit.models import (
    SCHEMA_VERSION as _SCHEMA_VERSION,
)
from geo_audit.models import (
    TOOL_VERSION as _TOOL_VERSION,
)
from geo_audit.models import (
    UNKNOWN_REMEDY,
    ApexWwwResult,
    Classification,
    Evidence,
    Expect,
    Finding,
    FixHint,
    NaiveContrast,
    PositionClass,
    Probe,
    Severity,
    Stage,
    Status,
    Verdict,
    make_finding_id,
)
from geo_audit.report.chain_svg import _cell_detail, _reduce_status, render_chain_svg
from geo_audit.report.copy_zh import COPY_ZH, EVIDENCE_COLUMNS, NAIVE_DEMO_COLUMNS
from geo_audit.report.render import (
    Counts,
    Coverage,
    CoverageGap,
    Exclusion,
    Fragility,
    Position,
    Report,
    assert_counts_identity,
    group_by_root_cause,
    render_html,
)
from geo_audit.rootcause import RootCause

DENOISE_VERSION = "denoise/2026-09-07.1"
UA = "geo-audit/0.1.0 (+https://github.com/wangtoone/geo-audit; contact: you@yourco.com)"

#: §6.1 的第 2 页起 section 顺序 = 阅读顺序。id 是测试与深链的契约。
SECTION_ORDER = (
    "unknown",
    "findings",
    "review",
    "fragility",
    "evidence",
    "apex",
    "excluded",
    "naive",
    "coverage",
    "method",
)


# --------------------------------------------------------------------------- #
# 合成 fixture 工厂
# --------------------------------------------------------------------------- #


def ev(
    url: str,
    status: int | None = 200,
    ctype: str = "text/plain",
    *,
    nbytes: int | None = 7316,
    title: str | None = None,
    body_head: str | None = None,
) -> Evidence:
    """一条 Evidence。``curl_repro`` 非空是硬要求（A35），所以这里永不留空。"""
    return Evidence(
        url=url,
        http_status=status,
        content_type=ctype,
        bytes_len=nbytes,
        title=title,
        body_head=body_head,
        curl_repro=(
            f"curl -sS -o /dev/null -w '%{{http_code}} %{{url_effective}}\\n' -L -A '{UA}' '{url}'"
        ),
    )


def pos(
    stage: Stage,
    key: str,
    status: Status,
    detail: str,
    *,
    kind: str = "probe",
    url: str | None = None,
    unknown_reason: str | None = None,
    control: Evidence | None = None,
) -> Position:
    probe_url = url or f"https://example.com/{key}"
    return Position(
        position_id=f"{stage.value}:{key}",
        stage=stage,
        label=key,
        probe_url=probe_url,
        status=status,
        detail=detail,
        kind="aggregate" if kind == "aggregate" else "probe",
        evidence=ev(probe_url, 200 if status is Status.PASS else 404),
        control=control,
        unknown_reason=unknown_reason,
        unknown_remedy=UNKNOWN_REMEDY[unknown_reason] if unknown_reason else None,
    )


def page_one_positions() -> tuple[Position, ...]:
    """§6.1 的自洽 16 格样本，逐格照抄修正后的分布。"""
    out: list[Position] = []
    # ① 入口发现：4 格全 pass
    for host in ("example.com", "www.example.com", "docs.example.com", "api.example.com"):
        out.append(pos(Stage.DISCOVERY, host, Status.PASS, "入口可达", url=f"https://{host}/"))
    # ② 索引文件真伪：2 fail + 1 unknown（②③ 合计 4 格）
    out.append(
        pos(
            Stage.INDEX_FILE,
            "www.example.com+/llms.txt",
            Status.FAIL,
            "软404：请求文本却返回 HTML，与随机路径同骨架",
            url="https://www.example.com/llms.txt",
            control=ev("https://www.example.com/geo-audit-probe-x9f2.txt", 404, "text/html"),
        )
    )
    out.append(
        pos(
            Stage.INDEX_FILE,
            "docs.example.com+/llms.txt",
            Status.FAIL,
            "软404：与随机路径同为 384,052 字节、同一份外壳",
            url="https://docs.example.com/llms.txt",
        )
    )
    out.append(
        pos(
            Stage.INDEX_FILE,
            "api.example.com+/llms.txt",
            Status.UNKNOWN,
            "被 WAF 挑战页挡住，无法判定",
            url="https://api.example.com/llms.txt",
            unknown_reason="waf_challenge_body",
        )
    )
    # ③ 全文通道：1 na
    out.append(
        pos(
            Stage.FULLTEXT,
            "www.example.com+/llms-full.txt",
            Status.NOT_APPLICABLE,
            "真 404：这个位置你没做，不是做坏了",
            url="https://www.example.com/llms-full.txt",
        )
    )
    # ④ 索引内链存活：1 fail（聚合格 —— 75 条死链是 1 格，不是 75 格）
    out.append(
        pos(
            Stage.INDEX_LINKS,
            "https://docs.example.com/llms.txt",
            Status.FAIL,
            "75/75 死",
            kind="aggregate",
            url="https://docs.example.com/llms.txt",
        )
    )
    # ⑤ .md 通道：恒 1 格，这里是未声明 -> NOT_APPLICABLE
    out.append(
        pos(
            Stage.MD_CHANNEL,
            "md",
            Status.NOT_APPLICABLE,
            "未声明",
            kind="aggregate",
            url="https://example.com/",
        )
    )
    # ⑥ 可点击路径：6 个 seed 页全 pass
    for i in range(6):
        out.append(
            pos(
                Stage.HUMAN_PATH,
                f"seed{i}",
                Status.PASS,
                "本页可点击链接全部活着",
                kind="aggregate",
                url=f"https://example.com/seed{i}",
            )
        )
    return tuple(out)


def counts_from(positions: tuple[Position, ...], **kw: object) -> Counts:
    """四格计数一律**从 positions 数出来**，不手填 —— 手填就会出 v1 那种算术病。"""
    base = {
        "positions": len(positions),
        "positions_pass": sum(1 for p in positions if p.status is Status.PASS),
        "positions_fail": sum(1 for p in positions if p.status is Status.FAIL),
        "positions_unknown": sum(1 for p in positions if p.status is Status.UNKNOWN),
        "positions_na": sum(1 for p in positions if p.status is Status.NOT_APPLICABLE),
        "findings": 0,
        "findings_counted": 0,
        "occurrences": 0,
        "root_causes": 0,
        "by_severity": {},
        "naive_divergences": 0,
    }
    base.update(kw)
    return Counts(**base)  # type: ignore[arg-type]


def saleor_finding() -> Finding:
    """§6.2 的旗舰卡片，逐字照抄那份 ground truth（含 GA-7F2A91C4E0 的语义）。"""
    target_url = "https://saleor.io/cloud/pricing-page?cta=Talk+to+us&cta_page=%2Fpricing"
    return Finding(
        finding_id=make_finding_id(
            "dead_links.hard_404",
            "https://saleor.io/cloud/pricing-page",
            "https://saleor.io/pricing",
        ),
        kind="dead_link",
        check_id="dead_links.hard_404",
        title="定价页三个套餐卡片的「Talk to us」全指向 404",
        severity=Severity.CRITICAL,
        position_class=PositionClass.SALES_PATH,
        stage=Stage.HUMAN_PATH,
        target=ev(target_url, 404, "text/html", nbytes=4211, title="404 - Page not found"),
        control=ev("https://saleor.io/contact", 200, "text/html", nbytes=51200),
        found_on="https://saleor.io/pricing",
        anchor_text="Talk to us",
        html_snippet='<a href="/cloud/pricing-page?cta=Talk+to+us">Talk to us</a>',
        source_hint="定价页三张套餐卡片",
        occurrences=3,
        occurrence_pages=("https://saleor.io/pricing",),
        occurrence_hrefs=(target_url,),
        root_cause_id="rc-saleor-cloud",
        root_cause_summary="定价页三张套餐卡片的 CTA 指向已迁走的 /cloud/ 路径",
        sibling_count=2,
        fix=FixHint(
            action="replace_href",
            open_this="https://saleor.io/pricing",
            locator='三张套餐卡片里锚文本为 "Talk to us" 的按钮（共 3 处）',
            before='href="/cloud/pricing-page?cta=Talk+to+us&cta_page=%2Fpricing"',
            after='href="/contact"',
            verified_target=True,
        ),
        naive_conclusion="这条链接没问题（它不抓带 query 的链接，也不看 <title>）",
        naive_is_wrong=True,
        actual_conclusion="全站最贵的那个按钮点了没反应",
        why_it_matters="这是定价页上的询价入口，点了就 404。",
        fp_guard=("url_template_placeholder", "reserved_example_domain", "geo_redirect"),
        fp_note=(
            "如果 /cloud/pricing-page 是刻意的 404 占位（我们没有办法区分「忘了配」和「故意的」）。"
        ),
        suppress_hint="geo-audit saleor.io --ignore {id}",
        severity_signals={
            "page_role": "pricing",
            "anchor": "Talk to us",
            "anchor_class": "cta-button",
            "region": "prominent",
        },
        exposure_pages=("https://saleor.io/pricing",),
    )


def build_page_one_sample() -> Report:
    """§6.1 的 16 格样本 + 3 条发现 + 2 个根因，走 ``has_fail`` 分支。"""
    positions = page_one_positions()
    f1 = saleor_finding()
    f1 = _with_suppress(f1)
    f2 = _sibling_of(f1, "https://saleor.io/cloud/talk-to-us", occurrences=7)
    f3 = _ai_channel_finding()
    findings = (f1, f2, f3)
    root_causes = (
        RootCause(
            root_cause_id="rc-saleor-cloud",
            summary="首页连接器图标墙指向已迁走的旧文档路径",
            fix_once="改 1 处 → 修 8 条：首页连接器图标墙指向已迁走的旧文档路径",
            finding_ids=(f1.finding_id, f2.finding_id),
            max_severity=Severity.CRITICAL,
            instance_count=10,
            unique_target_count=8,
            defect="route_missing",
            source_pages=("https://saleor.io/pricing",),
            merge_axes={"locus": "pricing-cards", "defect": "route_missing"},
        ),
        RootCause(
            root_cause_id="rc-llms-full",
            summary="llms-full.txt 与 llms.txt 是同一份字节",
            fix_once="改 1 处 → 修 1 条：llms-full.txt 与 llms.txt 是同一份字节",
            finding_ids=(f3.finding_id,),
            max_severity=Severity.HIGH,
            instance_count=1,
            unique_target_count=1,
            defect="byte_copy",
            source_pages=("https://docs.example.com/llms.txt",),
            merge_axes={"defect": "byte_copy"},
        ),
    )
    naive_table = (
        NaiveContrast(
            probe_url="https://www.minimax.io/llms.txt",
            in_naive_probe_set=True,
            naive_method="GET https://www.minimax.io/llms.txt，跟随跳转，只看最终状态码",
            naive_conclusion="已采纳（200）",
            actual_conclusion="软404：请求文本却返回 HTML，与随机路径同骨架",
            diverges=True,
            direction="false_positive",
            extra_requests=1,
        ),
        NaiveContrast(
            probe_url="https://platform.minimax.io/docs/llms.txt",
            in_naive_probe_set=False,
            naive_method="不在朴素探测集内",
            naive_conclusion="未采纳（没探这个位置）",
            actual_conclusion="真文件 24 KB text/plain",
            diverges=True,
            direction="false_negative",
            extra_requests=2,
        ),
        NaiveContrast(
            probe_url="https://example.com/",
            in_naive_probe_set=True,
            naive_method="GET https://example.com/，跟随跳转，只看最终状态码",
            naive_conclusion="它往这个 host 打过请求（只打了两条根路径）",
            actual_conclusion="入口可达",
            diverges=False,
            direction="agree",
        ),
    )
    return Report(
        schema_version=_SCHEMA_VERSION,
        tool_version=_TOOL_VERSION,
        denoise_ruleset_version=DENOISE_VERSION,
        domain="example.com",
        scanned_at="2026-09-07T14:22:00Z",
        duration_s=41.2,
        contact="you@yourco.com",
        user_agent=UA,
        headline=("你的 AI 检索链路上有 3 个位置会被读错，另有 1 个位置我们无法判断。"),
        verdict_kind="has_fail",
        positions=positions,
        findings=findings,
        root_causes=root_causes,
        naive_table=naive_table,
        fragilities=default_fragilities(),
        coverage_gaps=(
            CoverageGap(
                where="https://api.example.com/llms.txt",
                reason="waf_challenge_body",
                detail="返回了挑战页而不是内容",
                remedy=UNKNOWN_REMEDY["waf_challenge_body"],
            ),
        ),
        excluded=(
            Exclusion(
                url="https://example.com/cdn-cgi/l/email-protection",
                rule_id="cloudflare_email_protection",
                rule_desc="Cloudflare 邮箱混淆产生的诱饵 href，不是站点上的真链接",
                found_on="https://example.com/contact",
            ),
            Exclusion(
                url="https://example.com/hidden-thing",
                rule_id="class_hidden_anchor",
                rule_desc="锚点的 class 里有 hidden，静态 HTML 判不了访客能否点到",
                found_on="https://example.com/",
                disposition="needs_review",
            ),
        ),
        apex_www=default_apex(),
        coverage=Coverage(
            checked=("llms.txt / llms-full.txt 真伪", "索引内链存活", "seed 页可点击链接"),
            not_checked=("锚点腐烂", "sitemap", "robots 对 AI 爬虫的放行"),
            positions_total=len(positions),
            links_extracted=337,
            links_excluded=24,
            links_needs_review=1,
            links_verified=290,
            links_unknown=0,
            pages_fetched=6,
            requests_made=118,
            budget_cap=120,
        ),
        counts=counts_from(
            positions,
            findings=3,
            findings_counted=3,
            occurrences=11,
            root_causes=2,
            by_severity={"critical": 2, "high": 1},
            naive_divergences=2,
            naive_dead_count=42,
            audited_dead_instances=25,
        ),
    )


def _with_suppress(f: Finding) -> Finding:
    """``suppress_hint`` 必须含自己的 finding_id（A35）。"""
    from dataclasses import replace

    return replace(f, suppress_hint=f.suppress_hint.format(id=f.finding_id))


def _sibling_of(f: Finding, url: str, *, occurrences: int) -> Finding:
    from dataclasses import replace

    fid = make_finding_id(f.check_id, url, f.found_on)
    return replace(
        f,
        finding_id=fid,
        title="定价页「See how Saleor fits」指向 404",
        target=ev(url, 404, "text/html", nbytes=4211, title="404 - Page not found"),
        occurrences=occurrences,
        occurrence_hrefs=(url,),
        suppress_hint=f"geo-audit saleor.io --ignore {fid}",
    )


def _ai_channel_finding() -> Finding:
    url = "https://docs.example.com/llms-full.txt"
    fid = make_finding_id("ai_path.llms_full", url, None)
    return Finding(
        finding_id=fid,
        kind="llms_full_fake",
        check_id="ai_path.llms_full",
        title="llms-full.txt 与 llms.txt 是同一份字节",
        severity=Severity.HIGH,
        position_class=PositionClass.AI_CHANNEL,
        stage=Stage.FULLTEXT,
        target=ev(url, 200, "text/plain", nbytes=7316),
        control=ev("https://docs.example.com/llms.txt", 200, "text/plain", nbytes=7316),
        root_cause_id="rc-llms-full",
        root_cause_summary="llms-full.txt 与 llms.txt 是同一份字节",
        fix=FixHint(
            action="regenerate",
            open_this="https://docs.example.com/llms-full.txt",
            locator="生成 llms-full.txt 的那段构建脚本",
            before="与 llms.txt 相同的 md5",
            after=None,
            verified_target=False,
        ),
        naive_conclusion="有全文（200 + 非空）",
        naive_is_wrong=True,
        actual_conclusion="两份文件的 raw_md5 相同，全文通道其实是索引的字节副本",
        why_it_matters="AI 拿不到比索引更多的内容。",
        detail={"ratio": 1.0, "index_bytes": 7316, "full_bytes": 7316},
        severity_signals={
            "page_role": "ai_channel",
            "anchor": "-",
            "anchor_class": "-",
            "region": "body",
        },
        suppress_hint=f"geo-audit example.com --ignore {fid}",
    )


def default_fragilities() -> tuple[Fragility, ...]:
    """F6 / F8 在任何站上都能出结论 -> 零发现报告至少能拿到 2 条（§6.3:3186）。"""
    return (
        Fragility(
            fragility_id="F8",
            title="该 host 对未知路径不返回 404",
            metric="HostProfile.status_discriminates == False",
            why="只看状态码的死链工具在这类 host 上会报 0 死链，而那个 0 是假的。",
            precedent=(
                "developers.pipedrive.com（200 + 24,907 B 兜底页）、docs.gusto.com（302→/）、"
                "docs.moderntreasury.com（302→/）、www.minimax.io（200 + 384,052 B）、"
                "platform.kimi.ai（200 + 414,072 B）"
            ),
            watch_command="geo-audit example.com --contact you@you.co --only ai_path",
        ),
        Fragility(
            fragility_id="F6",
            title="WAF 会把真文件挡成 403/429",
            metric="host profile 不可探测（HostProfile.usable is False）",
            precedent="gusto.com 403、www.pipedrive.com 429",
            why="纯 HTTP 客户端会把你的真文件读成「没有」。",
            watch_command="geo-audit example.com --contact you@you.co --rate 0.2",
        ),
    )


def default_apex() -> ApexWwwResult:
    def _probe(url: str, verdict: Verdict) -> Probe:
        return Probe(
            url=url,
            expect=Expect.HTML_PAGE,
            response=None,
            classification=Classification(verdict=verdict, reason="ok"),
        )

    return ApexWwwResult(
        apex_host="example.com",
        www_host="www.example.com",
        apex=_probe("https://example.com/", Verdict.OK),
        www=_probe("https://www.example.com/", Verdict.OK),
        outcome="both_ok",
    )


def build_zero_finding_report() -> Report:
    """§6.3 的零发现报告。20.8% 的域会拿到它 —— 这是关键交付，不是边缘情况。

    位置数 = 4 是可证下界（``positions >= |P1| + |P2| + 1(P4)`` = 1 + 2 + 1）。
    【待实测：rustdesk / modal 两个零发现 fixture 的实际 positions 数，
    第 16 步接上 pipeline 后回填成精确值。】
    """
    positions = (
        pos(Stage.DISCOVERY, "modal.com", Status.PASS, "入口可达", url="https://modal.com/"),
        pos(
            Stage.INDEX_FILE,
            "modal.com+/llms.txt",
            Status.PASS,
            "真文件（不是软 404）",
            url="https://modal.com/llms.txt",
            control=ev("https://modal.com/geo-audit-probe-x9f2.txt", 404, "text/html"),
        ),
        pos(
            Stage.FULLTEXT,
            "modal.com+/llms-full.txt",
            Status.NOT_APPLICABLE,
            "真 404：这个位置你没做",
            url="https://modal.com/llms-full.txt",
        ),
        pos(Stage.MD_CHANNEL, "md", Status.NOT_APPLICABLE, "未声明", kind="aggregate"),
        pos(
            Stage.INDEX_LINKS,
            "https://modal.com/llms.txt",
            Status.PASS,
            "30 条，全量验证，30 活 0 死",
            kind="aggregate",
            url="https://modal.com/llms.txt",
        ),
        pos(
            Stage.HUMAN_PATH,
            "seed0",
            Status.PASS,
            "本页可点击链接全部活着",
            kind="aggregate",
            url="https://modal.com/pricing",
        ),
    )
    return Report(
        schema_version=_SCHEMA_VERSION,
        tool_version=_TOOL_VERSION,
        denoise_ruleset_version=DENOISE_VERSION,
        domain="modal.com",
        scanned_at="2026-09-07T15:02:00Z",
        duration_s=22.5,
        contact="you@yourco.com",
        user_agent=UA,
        headline="4 个位置全部通过，每一条都附对照证据和可复现命令。",
        verdict_kind="zero_clean",
        positions=positions,
        findings=(),
        root_causes=(),
        naive_table=(
            NaiveContrast(
                probe_url="https://modal.com/llms.txt",
                in_naive_probe_set=True,
                naive_method="GET https://modal.com/llms.txt，跟随跳转，只看最终状态码",
                naive_conclusion="已采纳（200）",
                actual_conclusion="真文件（不是软 404）",
                diverges=False,
                direction="agree",
            ),
        ),
        fragilities=default_fragilities(),
        coverage_gaps=(),
        excluded=(),
        apex_www=default_apex(),
        coverage=Coverage(
            checked=("llms.txt 真伪", "索引内链存活"),
            not_checked=("锚点腐烂", "sitemap"),
            positions_total=len(positions),
            links_extracted=30,
            links_verified=30,
            pages_fetched=1,
            requests_made=38,
            budget_cap=120,
        ),
        counts=counts_from(positions, naive_dead_count=0, audited_dead_instances=0),
    )


def build_unusable_report() -> Report:
    """gusto.com 形态：核心位置里超过一半无法评估 -> 整份报告降级（§6.4 R5）。

    实测依据：gusto.com 全站对 curl 403（challenge 已复现），apex/www/docs 三个
    host 的根路径与 AI 路径探测全部 BLOCKED。**UNKNOWN 永不折算成 PASS。**
    """
    positions = (
        pos(Stage.DISCOVERY, "gusto.com", Status.PASS, "入口可达", url="https://gusto.com/"),
        pos(
            Stage.DISCOVERY,
            "www.gusto.com",
            Status.UNKNOWN,
            "WAF 挑战页",
            url="https://www.gusto.com/",
            unknown_reason="waf_challenge_body",
        ),
        pos(
            Stage.INDEX_FILE,
            "gusto.com+/llms.txt",
            Status.UNKNOWN,
            "WAF 挑战页，真文件存在但我们看不了",
            url="https://gusto.com/llms.txt",
            unknown_reason="waf_challenge_body",
        ),
        pos(
            Stage.INDEX_FILE,
            "docs.gusto.com+/llms.txt",
            Status.UNKNOWN,
            "该 host 对未知路径 302→首页，判不了",
            url="https://docs.gusto.com/llms.txt",
            unknown_reason="control_unavailable",
        ),
        pos(
            Stage.FULLTEXT,
            "gusto.com+/llms-full.txt",
            Status.UNKNOWN,
            "WAF 挑战页",
            url="https://gusto.com/llms-full.txt",
            unknown_reason="waf_status",
        ),
        pos(Stage.MD_CHANNEL, "md", Status.NOT_APPLICABLE, "未声明", kind="aggregate"),
        pos(
            Stage.HUMAN_PATH,
            "seed0",
            Status.UNKNOWN,
            "抓不到这一页的 HTML",
            kind="aggregate",
            url="https://gusto.com/pricing",
            unknown_reason="waf_challenge_body",
        ),
    )
    counts = counts_from(positions)
    core = counts.positions - counts.positions_na
    return Report(
        schema_version=_SCHEMA_VERSION,
        tool_version=_TOOL_VERSION,
        denoise_ruleset_version=DENOISE_VERSION,
        domain="gusto.com",
        scanned_at="2026-09-07T15:40:00Z",
        duration_s=64.0,
        contact="you@yourco.com",
        user_agent=UA,
        headline=(
            f"这次扫描不可信：{core} 个核心位置里有 {counts.positions_unknown} 个我们没能评估。"
            "下面的结论不要当结论用。"
        ),
        verdict_kind="unusable",
        positions=positions,
        findings=(),
        root_causes=(),
        naive_table=(),
        fragilities=default_fragilities(),
        coverage_gaps=(),
        excluded=(),
        apex_www=None,
        coverage=Coverage(
            checked=("llms.txt 真伪",),
            not_checked=("锚点腐烂",),
            positions_total=len(positions),
            requests_made=14,
            budget_cap=120,
        ),
        counts=counts,
    )


def build_interrupted_report() -> Report:
    """§7.5 的中断报告。位置骨架**先建后填**，所以恒等式在中断报告上照样成立。"""
    positions = (
        pos(Stage.DISCOVERY, "example.com", Status.PASS, "入口可达", url="https://example.com/"),
        pos(
            Stage.INDEX_FILE,
            "example.com+/llms.txt",
            Status.UNKNOWN,
            "还没轮到",
            url="https://example.com/llms.txt",
            unknown_reason="interrupted",
        ),
        pos(
            Stage.FULLTEXT,
            "example.com+/llms-full.txt",
            Status.UNKNOWN,
            "还没轮到",
            url="https://example.com/llms-full.txt",
            unknown_reason="interrupted",
        ),
        pos(
            Stage.MD_CHANNEL,
            "md",
            Status.UNKNOWN,
            "还没轮到",
            kind="aggregate",
            unknown_reason="interrupted",
        ),
    )
    counts = counts_from(positions)
    report = build_zero_finding_report()
    from dataclasses import replace

    return replace(
        report,
        domain="example.com",
        positions=positions,
        counts=counts,
        naive_table=(),
        headline="扫描被中断，下面只是已完成部分的结论。未跑到的位置标「无法判断」。",
        verdict_kind="unusable",
        coverage=replace(report.coverage, positions_total=len(positions), interrupted=True),
    )


def build_sampled_report() -> Report:
    """抽样率 < 50% 的形态（A33）。BigCommerce 3,696 条 / Wix 5,186 条，实测 < 2%。"""
    from dataclasses import replace

    base = build_zero_finding_report()
    return replace(
        base,
        domain="bigcommerce.com",
        headline="抽到的链接里没有发现问题。抽样率 8.1%，这个结论不能外推到全站。",
        verdict_kind="zero_with_unknown",
        coverage=replace(
            base.coverage,
            links_extracted=3696,
            links_verified=300,
            index_links_sampled=True,
            sampling_note="唯一链接 3,696 条，--max-links 300 封顶，抽样率 8.1%",
        ),
    )


# --------------------------------------------------------------------------- #
# 链路图（第 15b 步）
# --------------------------------------------------------------------------- #


def test_chain_svg_six_cells_and_sum() -> None:
    """六格横向；**六格位置数之和 == counts.positions**（§6.1:3062 / A31）。"""
    report = build_page_one_sample()
    svg = render_chain_svg(report.positions)
    cells = re.findall(r'data-stage="([a-z_]+)" data-shape="([a-z_]+)" data-positions="(\d+)"', svg)
    assert [c[0] for c in cells] == [s.value for s in Stage]
    assert sum(int(c[2]) for c in cells) == report.counts.positions == 16
    # §6.1 修正后的自洽样本：①=4 ②=3 ③=1 ④=1 ⑤=1 ⑥=6
    assert [int(c[2]) for c in cells] == [4, 3, 1, 1, 1, 6]


def test_chain_svg_is_inline_and_has_no_external_reference() -> None:
    svg = render_chain_svg(build_page_one_sample().positions)
    assert svg.startswith("<svg")
    assert "http://www.w3.org/2000/svg" in svg  # xmlns 不是一次请求
    assert '<pattern id="geoHatch"' in svg  # 斜纹底自带，不外链
    assert not re.search(r"url\(\s*[\"']?https?:", svg)
    assert "<image" not in svg and "xlink:href" not in svg
    # 有 UNKNOWN 归一到格上的报告里，斜纹是靠片段引用填的（不是 url(http…)）
    unknown_svg = render_chain_svg(build_unusable_report().positions)
    assert "url(#geoHatch)" in unknown_svg
    assert not re.search(r"url\(\s*[\"']?https?:", unknown_svg)


def test_chain_svg_four_states_are_distinguishable_without_color() -> None:
    """四态形状必须可区分 —— 色盲用户与黑白打印（§6.5:3264）。

    机器判据（简报 spec_gaps 最后一条说没给判据，这里定死）：四态各自
    **几何元素 + 字形 + 描边形态** 三样至少有两样不同，且四态两两不相同。
    """
    from geo_audit.report.chain_svg import _shape

    seen: dict[Status, tuple[str, str, str]] = {}
    for status in Status:
        frag = _shape(status, 50.0, 26.0)
        element = frag[1 : frag.index(" ")]
        stroke = re.search(r'stroke-width="([\d.]+)"', frag)
        dash = re.search(r'stroke-dasharray="([^"]+)"', frag)
        assert stroke is not None
        seen[status] = (element, stroke.group(1), dash.group(1) if dash else "solid")
    # 几何元素：圆 / 八边形 / 菱形 / 正方形 —— 四态两两不同的三元组
    assert len(set(seen.values())) == 4
    assert seen[Status.PASS][0] == "circle"
    assert seen[Status.FAIL][1] == "3"  # FAIL 描粗边
    assert seen[Status.UNKNOWN][2] != "solid"  # UNKNOWN 虚线
    assert seen[Status.NOT_APPLICABLE][2] != "solid"  # NA 点线
    assert seen[Status.UNKNOWN][2] != seen[Status.NOT_APPLICABLE][2]
    # 斜纹填充只给 UNKNOWN
    assert "url(#geoHatch)" in _shape(Status.UNKNOWN, 50.0, 26.0)
    assert "url(#geoHatch)" not in _shape(Status.FAIL, 50.0, 26.0)
    # 字形四态各不相同，且 SVG 里真印出来了
    svg = render_chain_svg(build_page_one_sample().positions)
    for glyph in ("✓", "✕", "?", "–"):
        assert glyph in svg


def test_chain_svg_empty_stage_still_counts_as_a_cell() -> None:
    """某段 0 个 Position 时仍占一格、计 0，否则 A31 的六格求和不成立。"""
    positions = tuple(p for p in build_page_one_sample().positions if p.stage is Stage.DISCOVERY)
    svg = render_chain_svg(positions)
    cells = re.findall(r'data-positions="(\d+)"', svg)
    assert len(cells) == 6
    assert sum(int(c) for c in cells) == len(positions)
    assert COPY_ZH["chain_empty_cell"] in svg


def test_chain_svg_rejects_a_hand_edited_count() -> None:
    """恒等式被破坏就必须炸（防有人事后手改计数）。"""
    from geo_audit.report.chain_svg import _assert_cell_sum

    with pytest.raises(AssertionError, match="六格位置数之和"):
        _assert_cell_sum([1, 2, 3], 7)


def test_chain_cell_never_hides_unknown_behind_fail() -> None:
    """一格里既有 FAIL 又有 UNKNOWN 时，形状取 FAIL 但明细两个数都印（§6.4 R1）。"""
    cells = [
        pos(Stage.INDEX_FILE, "a", Status.FAIL, "软404"),
        pos(Stage.INDEX_FILE, "b", Status.UNKNOWN, "WAF", unknown_reason="waf_status"),
        pos(Stage.INDEX_FILE, "c", Status.PASS, "真文件"),
    ]
    assert _reduce_status(cells) is Status.FAIL
    detail = _cell_detail(cells)
    assert "1 读错" in detail
    assert "1 无法判断" in detail
    assert "1 通过" in detail


def test_chain_cell_unknown_beats_pass() -> None:
    cells = [
        pos(Stage.DISCOVERY, "a", Status.PASS, "ok"),
        pos(Stage.DISCOVERY, "b", Status.UNKNOWN, "WAF", unknown_reason="waf_status"),
    ]
    assert _reduce_status(cells) is Status.UNKNOWN


# --------------------------------------------------------------------------- #
# 首页形态（§6.1 / §6.4）
# --------------------------------------------------------------------------- #


def test_page_one_sample_is_self_consistent() -> None:
    """§6.1:3015 修正后的样本：16 = 3 fail + 1 unknown + 10 pass + 2 na。"""
    c = build_page_one_sample().counts
    got = (
        c.positions,
        c.positions_fail,
        c.positions_unknown,
        c.positions_pass,
        c.positions_na,
    )
    assert got == (16, 3, 1, 10, 2)
    core = c.positions - c.positions_na
    assert core == 14
    assert c.positions_unknown / core <= 0.5  # 所以走 has_fail，不是 unusable


def test_counts_identity_holds_on_every_fixture() -> None:
    """A31：四格之和 == positions，在**全部** fixture 上成立，**包括中断报告**。"""
    for build in (
        build_page_one_sample,
        build_zero_finding_report,
        build_unusable_report,
        build_interrupted_report,
        build_sampled_report,
    ):
        assert_counts_identity(build())


def test_counts_identity_rejects_hand_edited_counts() -> None:
    from dataclasses import replace

    report = build_page_one_sample()
    broken = replace(report, counts=replace(report.counts, positions_pass=99))
    with pytest.raises(AssertionError, match="四格之和"):
        assert_counts_identity(broken)


def test_first_page_carries_no_item_list() -> None:
    """第一页一格条目都不放（§6.1:3013）—— 73.6% 的站报不出 3 条。

    机器判据：``<main>`` 到 ``id="findings"`` 之间不出现任何 finding_id。
    """
    html = render_html(build_page_one_sample())
    head = html[html.index("<main") : html.index('id="findings"')]
    for f in build_page_one_sample().findings:
        assert f.finding_id not in head


def test_section_order_is_the_contract() -> None:
    """第 2 页起 section 顺序 = 阅读顺序，id 是测试与深链的契约（§6.1:3053）。"""
    html = render_html(build_page_one_sample())
    where = [html.index(f'id="{sid}"') for sid in SECTION_ORDER]
    assert where == sorted(where)


def test_a26_verdict_rootcauses_unknown_are_all_early_and_before_findings() -> None:
    """A26:4505 逐字：三个 id 都在 ``<main>`` 后 4000 字符内且早于 findings。"""
    html = render_html(build_page_one_sample())
    main = html.index("<main")
    findings = html.index('id="findings"')
    for sid in ("verdict", "root-causes", "unknown"):
        at = html.index(f'id="{sid}"')
        assert at < findings, sid
        assert at - main < 4000, (sid, at - main)


def test_root_cause_block_comes_before_the_item_list() -> None:
    """根因区永远在条目列表之前（§6.1:3040）。"""
    html = render_html(build_page_one_sample())
    assert html.index('id="root-causes"') < html.index('id="findings"')
    assert "按根因：3 条发现来自 2 处改动" in html
    assert "改 1 处 → 修 8 条：首页连接器图标墙指向已迁走的旧文档路径" in html
    assert "改 1 处 → 修 1 条：llms-full.txt 与 llms.txt 是同一份字节" in html


def test_count_bar_is_always_four_cells() -> None:
    """§6.4 R1：计数条永远四格 ✓通过/✕读错/?无法判断/–不适用。"""
    html = render_html(build_page_one_sample())
    start = html.index('<div class="bar">')
    bar = html[start : html.index("</div>", start)]
    for cls in ("st-pass", "st-fail", "st-unknown", "st-na"):
        assert cls in bar
    assert "16 个位置" in bar


def test_unknown_region_precedes_findings_and_carries_a_remedy() -> None:
    """§6.4 R3 + R4 + A32：UNKNOWN 区在发现之前，每条给原因码 + 可执行补救办法。"""
    report = build_page_one_sample()
    html = render_html(report)
    assert html.index('id="unknown"') < html.index('id="findings"')
    unknown = [p for p in report.positions if p.status is Status.UNKNOWN]
    assert unknown
    for p in unknown:
        assert p.unknown_reason is not None
        assert p.unknown_remedy
        assert len(p.unknown_remedy) >= 20
        assert p.unknown_remedy[:24] in html
    assert "box-unknown" in html  # 45° 斜纹底 + 虚线边框那套形态


def test_unknown_never_collapses_into_pass() -> None:
    """A32：有 UNKNOWN 的报告不许出现**肯定式**的「全部通过」。

    A32 的真实意思是「不许把 UNKNOWN 折算成 PASS」，判据**不能**是纯子串匹配
    「全部通过」—— `make_headline` 在 `zero_with_unknown` 分支印的是 §6.1:3098 的
    逐字原文「…所以这不能算『全部通过』」，那句话的意思恰恰是**不能算**。
    纯子串会把这句正确的措辞也判成违规。

    验收时曾把这判成「15a 与 16 做了相反裁决」。实测两者都对：
    `make_headline` 的分支互斥且有序，「N 个位置全部通过」只出现在最后的
    `zero_clean` 分支，那时 `positions_unknown` 必然为 0。

    所以判据改成：**不许出现「肯定式的全部通过」**，即
    「<数字> 个位置全部通过」这个形态；带「不能算」前缀的引用形态放行。
    """
    for build in (build_page_one_sample, build_unusable_report, build_interrupted_report):
        report = build()
        assert report.counts.positions_unknown > 0
        html = render_html(report)
        assert not re.search(r"\d+\s*个位置全部通过", html), (
            "有 UNKNOWN 却印了肯定式的「N 个位置全部通过」—— UNKNOWN 被折算成 PASS 了"
        )


def test_unusable_report_is_degraded_with_a_banner() -> None:
    """§6.4 R5：超过一半核心位置 UNKNOWN -> headline 换「这次扫描不可信」+ 通栏。"""
    report = build_unusable_report()
    core = report.counts.positions - report.counts.positions_na
    assert report.counts.positions_unknown / core > 0.5
    assert report.verdict_kind == "unusable"
    html = render_html(report)
    assert "这次扫描不可信" in html
    assert "整份报告已降级" in html
    assert html.index('class="banner"') < html.index("<h1>")  # 通栏在链路图与大字之上


def test_interrupted_report_renders_with_the_fixed_banner() -> None:
    """§7.5(4) / A37：中断报告照常生成，通栏文案在 HTML 里，恒等式成立。"""
    report = build_interrupted_report()
    assert report.coverage.interrupted is True
    for p in report.positions:
        if p.status is Status.UNKNOWN:
            assert p.unknown_reason == "interrupted"
    html = render_html(report)
    assert "扫描被中断（Ctrl-C）" in html
    assert "不是你的站有问题" in html
    assert "命中缓存，不会重打已完成的请求" in html


def test_sampled_report_says_so_and_is_not_zero_clean() -> None:
    """A33：抽样率 < 50% 时 verdict_kind != zero_clean 且 HTML 含「抽样率」。"""
    report = build_sampled_report()
    assert report.verdict_kind != "zero_clean"
    html = render_html(report)
    assert "抽样率" in html
    assert "不能外推到全站" in html


# --------------------------------------------------------------------------- #
# 零发现报告（§6.3 —— 20.8% 的域会拿到它）
# --------------------------------------------------------------------------- #


def test_zero_finding_report_is_an_evidence_archive_not_a_congratulation() -> None:
    """A29 逐条：findings == ()；五个 id 齐全；fragilities >= 2；证据表行数 == positions。"""
    report = build_zero_finding_report()
    assert report.findings == ()
    html = render_html(report)
    for sid in ("chain", "naive", "fragility", "evidence", "method"):
        assert f'id="{sid}"' in html
    assert len(report.fragilities) >= 2
    # C-1 行数 == counts.positions 且 >= 4
    body = html[html.index('id="evidence"') : html.index('id="apex"')]
    rows = re.findall(r'<tr class="box-', body)
    assert len(rows) == report.counts.positions >= 4
    # 八列表头逐字
    for col in EVIDENCE_COLUMNS:
        assert f"<th>{col}</th>" in body
    # 「只看状态码」这句反向论证是零发现报告里最硬的一句话
    assert "只看状态码" in html
    assert "我们的 0 是真的" in html
    # 改名：零发现报告不叫报告
    assert "AI 可读性证据存档" in html


def test_zero_finding_report_has_at_least_two_fragilities_with_precedents() -> None:
    """F6 + F8 在任何站上都能出结论（§6.3:3186）；每条必须挂实测先例。"""
    report = build_zero_finding_report()
    assert len(report.fragilities) >= 2
    for fr in report.fragilities:
        assert fr.precedent.strip()
        assert fr.watch_command.strip()
    html = render_html(report)
    assert "developers.pipedrive.com" in html  # F8 的实测先例
    assert "gusto.com 403" in html  # F6 的实测先例


def test_evidence_row_count_equals_positions_on_every_fixture() -> None:
    for build in (build_page_one_sample, build_zero_finding_report, build_unusable_report):
        report = build()
        html = render_html(report)
        body = html[html.index('id="evidence"') : html.index('id="apex"')]
        assert len(re.findall(r'<tr class="box-', body)) == report.counts.positions


# --------------------------------------------------------------------------- #
# finding 卡片与根因分组
# --------------------------------------------------------------------------- #


def _card_of(html: str, finding_id: str) -> str:
    """取出装着这条 finding 的那一张 ``<article>``。

    不能用 ``html.index(finding_id) - 400`` 那种偏移：组内是按严重度 → 实例数
    排序的，卡片顺序与 ``report.findings`` 的顺序不一致，偏移会切进上一张卡片。
    """
    cards = [c for c in html.split("<article") if finding_id in c]
    assert len(cards) == 1, f"{finding_id} 应当只出现在一张卡片里"
    return cards[0][: cards[0].index("</article>")]


def test_finding_card_prints_all_five_blocks() -> None:
    """§6.2 五段，顺序固定：标题 → 去哪儿改 → 证据 → 对照 → 根因/申诉。"""
    report = build_page_one_sample()
    html = render_html(report)
    f = report.findings[0]
    card = _card_of(html, f.finding_id)
    assert f.title in card
    assert f.fix is not None
    assert f.fix.open_this in card
    # autoescape 会把甲方数据里的 " 转成 &#34;，所以期望值也要过一次转义 ——
    # 这条断言顺带证明了「甲方数据一律不许 |safe」这条纪律在卡片里是生效的。
    assert str(escape(f.fix.locator)) in card
    assert str(escape(f.fix.before)) in card
    assert "← 我们请求过，200" in card
    assert str(escape(f.target.curl_repro)) in card
    assert "404 - Page not found" in card
    assert "https://saleor.io/contact" in card  # 同域对照，证明不是整站反爬
    assert COPY_ZH["finding_naive_title"] in card
    for key in ("page_role", "anchor", "anchor_class", "region"):
        assert key in card
    assert f.finding_id in f.suppress_hint


def test_a35_shape_of_every_finding() -> None:
    """A35：curl_repro 以 ``curl `` 开头且含目标 URL 与本次 UA；suppress_hint 含自身 id。"""
    report = build_page_one_sample()
    for f in report.findings:
        assert f.target.curl_repro.startswith("curl ")
        assert f.target.url in f.target.curl_repro
        assert report.user_agent in f.target.curl_repro
        assert f.finding_id in f.suppress_hint
        assert f.why_it_matters
        assert f.fix is not None or "我们没找到" in f.display_value


def test_group_by_root_cause_is_deterministic_and_severest_first() -> None:
    report = build_page_one_sample()
    groups = group_by_root_cause(report)
    assert [g[0].root_cause_id if g[0] else None for g in groups] == [
        "rc-saleor-cloud",
        "rc-llms-full",
    ]
    assert sum(len(g[1]) for g in groups) == len(report.findings)
    assert group_by_root_cause(report) == groups  # 同一入参两次同结果（L 组）


def test_group_by_root_cause_puts_orphans_last() -> None:
    from dataclasses import replace

    report = build_page_one_sample()
    orphan = replace(report.findings[2], root_cause_id="")
    report = replace(report, findings=(*report.findings[:2], orphan))
    groups = group_by_root_cause(report)
    assert groups[-1][0] is None
    assert groups[-1][1] == (orphan,)


def test_needs_review_finding_gets_the_fixed_banner() -> None:
    """§6.2:3142 逐字的通栏，只给 needs_review 的卡片加。"""
    from dataclasses import replace

    report = build_page_one_sample()
    reviewed = replace(report.findings[0], confidence="needs_review")
    report = replace(report, findings=(reviewed, *report.findings[1:]))
    html = render_html(report)
    assert "静态 HTML 判不了它是否对访客可见" in html
    assert html.index('id="review"') > html.index('id="findings"')
    assert reviewed.finding_id in html[html.index('id="review"') :]


def test_excluded_links_are_listed_with_rule_ids() -> None:
    """A24：每条被排除/标记的链接都有非空 rule_id 与 rule_desc。"""
    report = build_page_one_sample()
    for e in report.excluded:
        assert e.rule_id and e.rule_desc
    html = render_html(report)
    assert "cloudflare_email_protection" in html
    # needs_review 的那条走 #review，不混进 #excluded 表
    excluded_block = html[html.index('id="excluded"') : html.index('id="naive"')]
    assert "class_hidden_anchor" not in excluded_block


def test_naive_demo_uses_the_fixed_wording_and_three_columns() -> None:
    """附录 B-1：措辞只能是「只探根路径、不做对照探测的实现」。"""
    html = render_html(build_page_one_sample())
    assert "只探根路径、不做对照探测的实现，会在你的 2 个位置上读错" in html
    for col in NAIVE_DEMO_COLUMNS:
        assert f"<th>{col}</th>" in html
    assert "geo-audit example.com --contact you@you.co --naive-only" in html
    assert "任何现成工具" not in html
    assert "所有工具" not in html


def test_naive_demo_flips_positive_when_there_is_no_divergence() -> None:
    """零 divergence 时文案翻正向（第 14 步 modal 自验的报告侧对应物）。"""
    html = render_html(build_zero_finding_report())
    assert "在这个站上没读错" in html
    assert "只探根路径、不做对照探测的实现" in html


def test_coverage_disclosure_is_on_the_first_page() -> None:
    """§6.1:3051：覆盖披露上首页，不藏附录，文案逐字。"""
    html = render_html(build_page_one_sample())
    at = html.index(
        "这份报告不检查：锚点是否腐烂、sitemap、robots 对 AI 爬虫的放行、"
        "图片/CSS 资源、事实是否冲突、内容是否过期。理由见文末。"
    )
    assert at < html.index('id="findings"')


def test_header_prints_the_five_required_fields() -> None:
    """页眉五项 + A24 的 denoise_ruleset_version + B18 的缓存提示。"""
    report = build_page_one_sample()
    html = render_html(report)
    head = html[: html.index("<main")]
    for token in (
        report.domain,
        report.scanned_at,
        report.tool_version,
        report.user_agent,
        report.denoise_ruleset_version,
    ):
        assert token in head
    # B18 的缓存提示：Report 现在**没有**承载它的字段（schema 顶层 required 锁在
    # 20 个，加字段就让 tests/test_schema.py 变红），所以那行现在是休眠的。
    assert "本次报告里有响应来自本地缓存" not in head


def test_method_section_copies_the_eight_row_not_checked_table() -> None:
    """C-4 必须照抄 §0.3 那张八行表，每条带实测理由。"""
    from geo_audit.report.copy_zh import NOT_CHECKED_TABLE

    assert len(NOT_CHECKED_TABLE) == 8
    html = render_html(build_zero_finding_report())
    method = html[html.index('id="method"') :]
    for what, why in NOT_CHECKED_TABLE:
        assert what in method
        assert why[:20] in method
    # 三个已量化的实测数字必须在（别自己重新论证）
    assert "134 条命中" in method
    assert "2/72 = 2.8%" in method


def test_cache_hint_wakes_up_when_report_grows_the_field() -> None:
    """卡点 B18:4599 的页眉提示是「有就读、没有就当 False」，不是没实现。"""
    from geo_audit.report.render import _cache_hits

    class _Grown:  # 模拟 owner 按 B18 给 Report 补上字段之后
        cache_hits = True

    assert _cache_hits(_Grown()) is True
    assert _cache_hits(build_page_one_sample()) is False


# --------------------------------------------------------------------------- #
# 与第 16 步真 Report 的对接（本文件的合成 Report 只是占位，别让它们悄悄分叉）
# --------------------------------------------------------------------------- #


def test_placeholder_dataclasses_match_the_other_two_copies() -> None:
    """七个报告层 dataclass 现在有**三份占位**，字段必须逐一相同。

    ``report/render.py``（本步）、``report/json_out.py``（第 15c 步）、
    ``pipeline.py``（第 16 步）三个写手都被铁律禁止改 models.py，于是各写了一份
    占位。搬进 models.py 时必须**三份一起删**（A6 要「恰好 1 处定义」）。
    这条断言守住「删之前它们没有分叉」。
    """
    import dataclasses

    from geo_audit import pipeline
    from geo_audit.report import json_out, render

    def sig(cls: type) -> list[tuple[str, str]]:
        return [(f.name, repr(f.default)) for f in dataclasses.fields(cls)]

    #: 第 16 步的 pipeline 比规格 §2.10 多两个字段，两个都是规格该有而没有的
    #: （见交付说明 spec_gaps）：Report.cache_hits（卡点 B18 的页眉提示）与
    #: Coverage.links_capped（A24 恒等式的最后一项）。报告层用 getattr 兼容两边。
    extra_in_pipeline = {"Report": {"cache_hits"}, "Coverage": {"links_capped"}}
    for name in (
        "Position",
        "Exclusion",
        "CoverageGap",
        "Fragility",
        "Coverage",
        "Counts",
        "Report",
    ):
        mine = sig(getattr(render, name))
        theirs = sig(getattr(json_out, name))
        assert mine == theirs, f"{name}: render 与 json_out 的占位分叉了"
        pipe = sig(getattr(pipeline, name))
        allowed = extra_in_pipeline.get(name, set())
        assert [f for f in pipe if f[0] not in allowed] == mine, (
            f"{name}: render 与 pipeline 的占位分叉了"
        )


def test_render_html_accepts_the_real_pipeline_report() -> None:
    """报告层只读 positions，所以第 16 步的真 ``Report`` 必须能直接喂进来。"""
    from tests.test_cli import _report

    real = _report()
    html = render_html(real)
    assert html.startswith("<!doctype html>")
    assert real.headline in html
    for sid in (*SECTION_ORDER, "verdict", "chain", "naive-demo"):
        assert f'id="{sid}"' in html
