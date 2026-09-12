#!/usr/bin/env python3
"""跑 replay 出真实报告，生成 GitHub Pages 画廊（§7.4(c)、§9 第 18 步）。

产出两样东西：

* ``docs/reports/<domain>.html`` —— 每个域一份单文件报告（零外部请求、零 JS）；
* ``docs/index.html`` —— 索引页：每域一行 = 域名 + 报告自己的 headline +
  四格计数 + 报告链接，另加「这些数字是哪天抓的」和跳过的域为什么没有报告。

**为什么按域名清单驱动、缺快照就跳过**

§7.4(c) 点名 7 个域（mistral.ai / deepgram.com / minimax.io / saleor.io /
tdengine.com / modal.com / gusto.com），但 ``fixtures/`` 里只有一部分域的快照
足以产出一份**不撒谎**的报告。判据是机械的，见 :func:`preflight`：
apex 与 www 的 DNS 答案必须录过（没录过 → ``FixtureResolver`` 走
``_default_absent`` 判 NXDOMAIN，报告会把「我们没录」写成「你的域名解析不了」），
有快照的 host 也必须录过 DNS（否则那台主机整段消失、快照白录），
apex 或 www 上必须至少有一条同 host 的对照探针（"每一条判定都跟一个对照探测"
这句话得有东西兜着）。

不满足的域：**跳过、在 index.html 里写明缺什么、把要补录的 urls.txt 行打到
stdout**。不崩，也不用「跑得半真半假的报告」凑数 —— 补齐要真网络，见
``scripts/capture_fixtures.py``。

**报告里的每一个数字都来自真实抓取。** ``fixtures/`` 是对这些站点的真实 HTTP
响应（含 headers、逐跳分开存，录制日期见 ``index.json`` 的 ``recorded_at``）。
replay 只是把冻结的字节重新喂给同一套判定，判定本身一个字节都不变。所以画廊页
写的是「真实站点的真实抓取 + 快照录制日期」，而不是「实时扫描」。

用法::

    GEO_AUDIT_FORBID_NETWORK=1 GEO_AUDIT_FORBID_DNS=1 python scripts/build_gallery.py
    python scripts/build_gallery.py --only mistral.ai --jobs 1
    python scripts/build_gallery.py --check-copy-only      # 只跑措辞纪律闸门

退出码：0 = 至少产出一份报告且措辞闸门通过；1 = 一份都没产出；
2 = 措辞纪律闸门失败（禁词 / 禁语出现在我们自己写的字里）。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:  # 允许不装包直接 `python scripts/build_gallery.py`
    sys.path.insert(0, str(REPO_ROOT / "src"))

from geo_audit import __version__  # noqa: E402  —— 必须在 sys.path 之后
from geo_audit.fetch.discovery import enumerate_doc_hosts  # noqa: E402
from geo_audit.fixtures import FixtureError, FixtureStore, canon_url  # noqa: E402
from geo_audit.models import Report  # noqa: E402
from geo_audit.pipeline import AuditOptions, DomainUnreachableError, audit_domain  # noqa: E402
from geo_audit.report import render_html  # noqa: E402
from geo_audit.report.copy_zh import STATUS_LABEL  # noqa: E402
from geo_audit.report.render import (  # noqa: E402
    assert_no_banned_words,
    assert_selfcontained,
)

# --------------------------------------------------------------------------- #
# 域名清单
# --------------------------------------------------------------------------- #

#: §7.4(c) 点名的 7 个域，顺序照抄规格。
SPEC_DOMAINS: tuple[str, ...] = (
    "mistral.ai",
    "deepgram.com",
    "minimax.io",
    "saleor.io",
    "tdengine.com",
    "modal.com",
    "gusto.com",
)

#: 规格之外补进来的两个域。理由写在这里而不是提交说明里，因为它是清单的一部分：
#: 规格的 7 个域里目前只有 mistral.ai / modal.com 的快照够格（见 preflight），
#: 而 rustdesk.com / openstatus.dev 是 fixtures 里另外两个够格的域，
#: 各自补上了一种规格清单里会缺掉的形态（www 与 apex 都活、apex 308 到 www）。
EXTRA_DOMAINS: tuple[str, ...] = (
    "rustdesk.com",
    "openstatus.dev",
)

GALLERY_DOMAINS: tuple[str, ...] = SPEC_DOMAINS + EXTRA_DOMAINS

#: 画廊页给报告用的联系邮箱。真网络下 ``--contact`` 是抓取礼仪的一部分，
#: 而 replay 一个请求都不发，所以这里用一个项目自己的不可投递地址，
#: 免得把某个人的邮箱印进公开页面。可用 ``--contact`` 覆盖。
DEFAULT_CONTACT = "gallery@geo-audit.invalid"

#: ``verdict_kind`` → 索引页上那一枚形态徽标。**我们自己的词**，
#: 所以要过禁词闸门；不能出现「一切正常」「没有问题」这类把 UNKNOWN 折算成
#: 通过的说法（附录 B）。
VERDICT_BADGE: dict[str, str] = {
    "has_fail": "有位置被读错",
    "zero_with_unknown": "零读错，但有位置无法判断",
    "zero_clean": "零发现",
    "no_ai_channel": "没有 AI 索引通道",
    "unusable": "这次扫描不可信",
}

# --------------------------------------------------------------------------- #
# 措辞纪律（附录 B 的禁词 + 一条禁语）
# --------------------------------------------------------------------------- #

#: 附录 B-1 的固定措辞。禁词表已经挡住「任何现成工具」「所有工具」两个词头，
#: 这里再把整句话记下来，是为了让 grep 得到的错误信息直接说清替代说法。
FORBIDDEN_CLAIM = "任何现成工具都会给出错的答案"

#: 附录 B-1 允许的替代说法。README / index.html 里凡提到「那类实现会读错」，
#: 措辞一律收敛到这一句 —— 我们从没跑过任何现成工具做对照。
ALLOWED_CLAIM = "只探根路径、不做对照探测的实现，会在你的 N 个位置上读错"

#: 措辞闸门扫哪些文件（全是**我们自己写的字**，不含甲方回显的数据）。
COPY_FILES: tuple[str, ...] = ("README.md", "CONTRIBUTING.md", "docs/index.html")


def check_copy_discipline(root: Path = REPO_ROOT) -> list[str]:
    """扫 :data:`COPY_FILES`，返回违规说明列表（空 = 通过）。

    禁词表复用 ``report.render.assert_no_banned_words``，**不在这里重抄一份** ——
    两份禁词表必然对不上，而报告那份是渲染期生效的那份。
    """
    problems: list[str] = []
    for rel in COPY_FILES:
        path = root / rel
        if not path.exists():
            continue
        text = path.read_text("utf-8")
        try:
            assert_no_banned_words(text)
        except AssertionError as exc:
            problems.append(f"{rel}: {exc}")
        if FORBIDDEN_CLAIM in text:
            problems.append(f"{rel}: 出现禁语「{FORBIDDEN_CLAIM}」，固定措辞是「{ALLOWED_CLAIM}」")
    return problems


# --------------------------------------------------------------------------- #
# 快照够不够格（preflight）
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Gap:
    """一条「要补录什么」。``urls_txt`` 是可直接粘进 fixtures/urls.txt 的行。"""

    what: str
    why: str
    urls_txt: tuple[str, ...] = ()


def _hosts_with_snapshots(store: FixtureStore, domain: str) -> set[str]:
    """本域下有快照的 host 集合。"""
    suffix = "." + domain
    hosts: set[str] = set()
    for url in store.snapshots():
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
        if host == domain or host.endswith(suffix):
            hosts.add(host)
    return hosts


def _has_control_probe(store: FixtureStore, hosts: set[str]) -> bool:
    """``hosts`` 里任一台上录过对照探针（``probe_for`` 非空）。"""
    for url, entry in store.index.items():
        if not entry.get("probe_for"):
            continue
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
        if host in hosts:
            return True
    return False


def preflight(store: FixtureStore, domain: str) -> tuple[Gap, ...]:
    """够不够格出一份不撒谎的报告。返回空元组 = 够格。

    三条判据，全部机械可查：

    P1/P2 **apex 与 www 的 DNS 答案必须录过。** ``dns.json`` 里没有条目的 host
          走 ``_default_absent``（NXDOMAIN）—— 那是「这个子域真的不存在」这条
          设计的一部分（不存在的子域花 0 个 HTTP 请求）。可它也意味着
          「我们没录」和「站点没有」在 replay 下长得一模一样，而 apex/www 是
          报告 ``apex_www`` 那一节的两个主角，我们不能替站点回答。
    P3    **有快照却没 DNS 条目的 host 一律算缺口。** 那台主机会被判 NXDOMAIN，
          于是它的快照一条都用不上（saleor.io 的 docs. 就是这样）。
    P4    **apex 或 www 上至少一条对照探针。** 一条都没有的话，AI 路径的每条
          判定都退成 UNKNOWN(control_unavailable)，报告还在，但「每一条判定都跟
          一个对照探测」这句话没有东西兜着。
    """
    gaps: list[Gap] = []
    dns_hosts = {h.lower() for h in store.dns if not h.startswith("_")}
    apex, www = domain, f"www.{domain}"

    for host in (apex, www):
        if host not in dns_hosts:
            gaps.append(
                Gap(
                    what=f"DNS: {host}",
                    why="dns.json 里没录过它的解析答案，replay 会判 NXDOMAIN —— "
                    "那是我们没录，不是站点的事实",
                    urls_txt=(f"https://{host}/", f"@control https://{host}/"),
                )
            )

    snapshot_hosts = _hosts_with_snapshots(store, domain)
    for host in sorted(snapshot_hosts - dns_hosts):
        gaps.append(
            Gap(
                what=f"DNS: {host}",
                why=f"{host} 有快照但没 DNS 条目，会被判 NXDOMAIN，快照一条都用不上",
                urls_txt=(),
            )
        )

    probe_hosts = {apex, www} | {h for h, _role in enumerate_doc_hosts(domain)}
    if not _has_control_probe(store, probe_hosts & (dns_hosts | snapshot_hosts)):
        gaps.append(
            Gap(
                what=f"对照探针: {apex}",
                why="apex/www/文档子域上一条对照探针都没录过，AI 路径判定会全退成「无法判断」",
                urls_txt=(f"@control https://{apex}/llms.txt",),
            )
        )
    return tuple(gaps)


# --------------------------------------------------------------------------- #
# 跑一个域
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Outcome:
    """一个域的结局。三种：``report`` 有值 / ``gaps`` 非空 / ``error`` 非空。"""

    domain: str
    report: Report | None = None
    gaps: tuple[Gap, ...] = ()
    error: str = ""
    #: 本次运行里真的请求过、但 fixtures 里没有快照的 URL。
    #: 站内链接是无穷集，缺是设计允许的（判 UNKNOWN），所以只作为信息输出。
    missing_snapshots: tuple[str, ...] = ()
    html_path: Path | None = None

    @property
    def published(self) -> bool:
        return self.report is not None and self.html_path is not None


def _options(domain: str, contact: str, *, live: bool = False) -> AuditOptions:
    """画廊一律跑**默认参数**：用户装完就是这套，报告里的数字才有可比性。

    ``live=True`` 打真网络。为什么需要这个开关：replay 语料只录了实测涉及的
    那些 URL，而探测集会枚举 16 个子域前缀 —— 于是九份报告里多数位置是
    「没录过」，判定层如实标成「未能评估」，首屏全变成「这次扫描不可信」。
    那个判决是对的，但一份主要在说「没能看」的报告对读者没有信息量。

    **画廊不是判定语料。** 判定的可复现性由 42 条标注 + `fp_gate.py` 保证，
    画廊只负责「这是真跑出来的九份报告」。所以这里把两件事分开：
    展示走活网，判定复现走 fixtures。
    """
    return AuditOptions(
        domain=domain,
        contact=contact,
        replay_fixtures=not live,
        # replay 下 --replay-fixtures 强制禁用缓存（卡点 B18）；
        # 活网下也关缓存，免得两次重建拿到不同新鲜度的字节。
        use_cache=False,
    )


def run_domain(domain: str, *, contact: str, store: FixtureStore, live: bool = False) -> Outcome:
    """preflight → 跑六段 → 渲染。

    ``live=False``（默认）不联网，``store`` 的 transport 是 MockTransport。
    ``live=True`` 打真网络，**跳过 preflight** —— preflight 查的是「快照够不够」，
    活网跑时那个问题不存在。
    """
    if not live:
        gaps = preflight(store, domain)
        if gaps:
            return Outcome(domain, gaps=gaps)

    missing: list[str] = []
    seen: set[str] = set()

    def before_request(url: str) -> None:
        key = canon_url(url)
        if key in seen:
            return
        seen.add(key)
        if not store.has(key):
            missing.append(key)

    try:
        report = audit_domain(
            _options(domain, contact, live=live),
            store=None if live else store,
            resolver=None if live else store.resolver(),
            before_request=None if live else before_request,
        )
    except DomainUnreachableError as exc:
        return Outcome(
            domain, error=f"apex 与 www 都不可达：{exc}", missing_snapshots=tuple(missing)
        )
    except FixtureError as exc:
        return Outcome(domain, error=f"快照层报错：{exc}", missing_snapshots=tuple(missing))

    return Outcome(domain, report=report, missing_snapshots=tuple(sorted(missing)))


# --------------------------------------------------------------------------- #
# 索引页
# --------------------------------------------------------------------------- #

INDEX_CSS = """
:root {
  color-scheme: light dark;
  --bg: #fbfbfa; --panel: #ffffff; --ink: #16181d; --ink-2: #4a5058;
  --ink-3: #6d747d; --line: #dcdfe4; --line-2: #eceef1;
  --pass: #1f7a4d; --fail: #b32626; --unknown: #7a5a12; --na: #6d747d;
  --accent: #1d4ed8; --code-bg: #f3f4f6;
  --shadow: 0 1px 2px rgba(16, 18, 22, 0.06);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14161a; --panel: #1b1e23; --ink: #e9ecf1; --ink-2: #b6bcc6;
    --ink-3: #8d949e; --line: #333941; --line-2: #262b31;
    --pass: #5fd39b; --fail: #ff8f85; --unknown: #e6c56a; --na: #9aa1ab;
    --accent: #8ab4ff; --code-bg: #22262c; --shadow: none;
  }
}
:root[data-theme="dark"] {
  --bg: #14161a; --panel: #1b1e23; --ink: #e9ecf1; --ink-2: #b6bcc6;
  --ink-3: #8d949e; --line: #333941; --line-2: #262b31;
  --pass: #5fd39b; --fail: #ff8f85; --unknown: #e6c56a; --na: #9aa1ab;
  --accent: #8ab4ff; --code-bg: #22262c; --shadow: none;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0; padding: 0 0 4rem; background: var(--bg); color: var(--ink);
  font-family: -apple-system, "Segoe UI", "Noto Sans CJK SC", "PingFang SC",
    "Microsoft YaHei", sans-serif;
  font-size: 15px; line-height: 1.62;
}
.wrap { max-width: 62rem; margin: 0 auto; padding: 2.5rem 1.25rem 0; }
h1 { font-size: 1.6rem; margin: 0 0 .35rem; letter-spacing: -.01em; }
h2 { font-size: 1.05rem; margin: 2.5rem 0 .75rem; }
.lede { color: var(--ink-2); margin: 0 0 .4rem; max-width: 46rem; }
.meta { color: var(--ink-3); font-size: .86rem; margin: .9rem 0 0; max-width: 46rem; }
code, .mono {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .88em;
}
code { background: var(--code-bg); padding: .1em .32em; border-radius: 3px; }
a { color: var(--accent); }
.row {
  display: block; background: var(--panel); border: 1px solid var(--line);
  border-radius: 6px; padding: .9rem 1.1rem; margin: 0 0 .6rem;
  box-shadow: var(--shadow); text-decoration: none; color: inherit;
}
a.row:hover { border-color: var(--accent); }
.row-top {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: .55rem .8rem;
}
.dom { font-weight: 600; font-size: 1.02rem; }
.badge {
  font-size: .74rem; letter-spacing: .02em; padding: .1rem .45rem;
  border: 1px solid var(--line); border-radius: 999px; color: var(--ink-2);
  white-space: nowrap;
}
.badge.b-fail { color: var(--fail); border-color: var(--fail); }
.badge.b-unknown { color: var(--unknown); border-color: var(--unknown); }
.badge.b-pass { color: var(--pass); border-color: var(--pass); }
.open { margin-left: auto; font-size: .84rem; color: var(--accent); }
.head { margin: .45rem 0 .1rem; color: var(--ink); }
.fix { margin: .3rem 0 0; color: var(--ink-2); font-size: .9rem; }
.cells {
  display: flex; flex-wrap: wrap; gap: .4rem; margin: .7rem 0 0;
  list-style: none; padding: 0;
}
.cells li {
  font-size: .8rem; border: 1px solid var(--line-2); border-radius: 4px;
  padding: .12rem .5rem; color: var(--ink-2); white-space: nowrap;
}
.cells li b { font-variant-numeric: tabular-nums; color: var(--ink); }
.cells li.c-fail { border-color: var(--fail); }
.cells li.c-unknown { border-color: var(--unknown); border-style: dashed; }
.cells li.c-pass { border-color: var(--pass); }
.cells li.c-na { border-style: dotted; }
.skip {
  background: var(--panel); border: 1px dashed var(--line); border-radius: 6px;
  padding: .8rem 1.1rem; margin: 0 0 .6rem;
}
.skip ul { margin: .45rem 0 0; padding-left: 1.2rem; color: var(--ink-2); font-size: .9rem; }
.skip .dom { color: var(--ink-3); }
.wide { overflow-x: auto; }
footer { color: var(--ink-3); font-size: .84rem; margin: 3rem 0 0; }
"""


def _cells(report: Report) -> str:
    """四格计数。**四态各一格，UNKNOWN 永不折算进 PASS**（§6.4 R1）。"""
    c = report.counts
    items = (
        ("fail", STATUS_LABEL["fail"], c.positions_fail),
        ("unknown", STATUS_LABEL["unknown"], c.positions_unknown),
        ("pass", STATUS_LABEL["pass"], c.positions_pass),
        ("na", STATUS_LABEL["not_applicable"], c.positions_na),
    )
    cells = "".join(
        f'<li class="c-{css}">{html.escape(label)} <b>{n}</b></li>' for css, label, n in items
    )
    return (
        f'<ul class="cells"><li>位置 <b>{c.positions}</b></li>{cells}'
        f"<li>条数 <b>{c.findings}</b></li><li>根因 <b>{c.root_causes}</b></li></ul>"
    )


def _badge_class(verdict: str) -> str:
    if verdict == "has_fail":
        return "b-fail"
    if verdict in ("zero_with_unknown", "unusable", "no_ai_channel"):
        return "b-unknown"
    return "b-pass"


def _published_row(outcome: Outcome) -> str:
    report = outcome.report
    assert report is not None
    verdict = report.verdict_kind
    badge = VERDICT_BADGE.get(verdict, verdict)
    fix = ""
    if report.root_causes:
        top = report.root_causes[0]
        fix = (
            f'<p class="fix">根因：<span class="mono">{html.escape(top.fix_once)}</span>'
            f"（{top.instance_count} 处）</p>"
        )
    return (
        f'<a class="row" href="reports/{html.escape(outcome.domain)}.html">'
        f'<span class="row-top"><span class="dom mono">{html.escape(outcome.domain)}</span>'
        f'<span class="badge {_badge_class(verdict)}">{html.escape(badge)}</span>'
        f'<span class="open">打开报告 →</span></span>'
        f'<p class="head">{html.escape(report.headline)}</p>{fix}{_cells(report)}</a>'
    )


def _skipped_row(outcome: Outcome) -> str:
    if outcome.error:
        reasons = [f"<li>{html.escape(outcome.error)}</li>"]
    else:
        reasons = [
            f"<li><span class='mono'>{html.escape(g.what)}</span> —— {html.escape(g.why)}</li>"
            for g in outcome.gaps
        ]
    return (
        f'<div class="skip"><span class="dom mono">{html.escape(outcome.domain)}</span>'
        f" · 没有报告，因为快照不全：<ul>{''.join(reasons)}</ul></div>"
    )


def render_index(
    outcomes: list[Outcome],
    *,
    recorded_at: str,
    built_at: str,
    tool_version: str,
) -> str:
    """索引页。单文件自包含 —— 和报告一样，零外部请求。"""
    published = [o for o in outcomes if o.published]
    skipped = [o for o in outcomes if not o.published]

    rows = "".join(_published_row(o) for o in published)
    skips = "".join(_skipped_row(o) for o in skipped)
    skip_block = (
        "<h2>清单里暂时没有报告的域</h2>"
        "<p class='lede'>这些域在语料里，形态也是清单里最难看的那几种，但 "
        "<code>fixtures/</code> 的快照不足以产出一份不撒谎的报告。补齐要真网络重录一次"
        "（<code>scripts/capture_fixtures.py</code>）。在那之前它们"
        "<strong>没有报告</strong>，而不是有一份半真半假的。</p>" + skips
        if skipped
        else ""
    )

    return f"""<!doctype html>
<html lang="zh-Hans">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="geo-audit {html.escape(tool_version)} build_gallery.py">
<title>geo-audit · 真实站点报告画廊</title>
<style>{INDEX_CSS}</style>
</head>
<body>
<main class="wrap">
<h1>geo-audit · 真实站点报告画廊</h1>
<p class="lede">下面每一份都是<strong>真实站点的真实抓取结果</strong>：HTTP 响应（含 headers、
逐跳分开）在 <strong>{html.escape(recorded_at)}</strong> 从这些站点上抓下来冻结进
<code>fixtures/</code>，本页的报告由同一套判定重放那些字节产出，判定一个字节都没改。
不是实时扫描，也不是构造出来的样例站。</p>
<p class="lede">先看报告，再决定要不要装。报告是单个 HTML 文件，零外部请求，
可离线转发、可直接打印、可贴进工单。</p>
<p class="meta">四格计数里「{html.escape(STATUS_LABEL["unknown"])}」是独立的一态，
永不折算进「{html.escape(STATUS_LABEL["pass"])}」。位置数与条数是两个数：
一条根因可以对应很多条实例。</p>
<p class="meta">下面有几份是「零发现」。这不是画廊挑样挑偏了 —— 72 个域的实测分布是
<strong>20.8% 一条都报不出来、52.8% 只有 1–2 条、26.4% 能报 3 条以上</strong>。
零发现报告长什么样、值不值这个页数，你自己看。</p>

<h2>报告（{len(published)} 份）</h2>
{rows}
{skip_block}

<footer>geo-audit {html.escape(tool_version)} · 本页由 <code>scripts/build_gallery.py</code>
于 {html.escape(built_at)} 生成 · 快照录制于 {html.escape(recorded_at)}</footer>
</main>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def _recorded_at(store: FixtureStore) -> str:
    days = sorted({str(e.get("recorded_at", ""))[:10] for e in store.index.values() if e})
    days = [d for d in days if d]
    if not days:
        return "（index.json 里没有 recorded_at）"
    return days[0] if days[0] == days[-1] else f"{days[0]} – {days[-1]}"


def _print_needs_network(outcomes: list[Outcome]) -> None:
    """把「要补录什么」打成可直接粘进 fixtures/urls.txt 的行。"""
    blocked = [o for o in outcomes if o.gaps]
    if not blocked:
        return
    print()
    print("── 需要真网络补录（补完再跑一次本脚本，这些域就会进画廊）──────────────")
    for o in blocked:
        print(f"# {o.domain}")
        for gap in o.gaps:
            print(f"#   缺 {gap.what} —— {gap.why}")
        lines = [line for gap in o.gaps for line in gap.urls_txt]
        for line in dict.fromkeys(lines):
            print(f"    {line}")
    print()
    print("  补录命令（先把上面的行加进 fixtures/urls.txt）：")
    print("    python scripts/capture_fixtures.py --contact you@example.com \\")
    print("        --from-file fixtures/urls.txt")
    print("    python scripts/capture_fixtures.py --contact you@example.com \\")
    print("        --from-file fixtures/urls.txt --dns-only")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="build_gallery.py",
        description="跑 replay 出真实报告 + 生成 docs/index.html（§7.4(c)）",
    )
    ap.add_argument(
        "--only", action="append", default=[], metavar="DOMAIN", help="只跑这些域（可重复）"
    )
    ap.add_argument("--out", default=str(REPO_ROOT / "docs"), metavar="DIR", help="画廊输出目录")
    ap.add_argument(
        "--contact",
        default=os.environ.get("GEO_AUDIT_CONTACT") or DEFAULT_CONTACT,
        metavar="EMAIL",
        help=f"写进 UA 的联系邮箱（默认 {DEFAULT_CONTACT}）",
    )
    ap.add_argument(
        "--jobs",
        type=int,
        default=4,
        metavar="N",
        help="并发跑几个域（限速是按域名的，跨域并发不违反 0.5 req/s）",
    )
    ap.add_argument("--check-copy-only", action="store_true", help="只跑措辞纪律闸门然后退出")
    ap.add_argument(
        "--live",
        action="store_true",
        help="打真网络跑（默认用 fixtures 回放）。画廊要有内容就得用它 —— "
        "replay 语料覆盖不到探测集里的多数位置，报告会全变成「这次扫描不可信」",
    )
    args = ap.parse_args(argv)

    # 一个域要跑好几分钟（限速 0.5 req/s，replay 也照走），进度必须实时可见。
    # 默认的块缓冲会把整份输出攒到进程结束才吐出来 —— 那时候看进度已经没意义。
    sys.stdout.reconfigure(line_buffering=True)

    if args.check_copy_only:
        problems = check_copy_discipline()
        for p in problems:
            print(f"措辞纪律：{p}", file=sys.stderr)
        print("措辞纪律闸门：" + ("失败" if problems else f"通过（扫了 {len(COPY_FILES)} 个文件）"))
        return 2 if problems else 0

    try:
        store = FixtureStore.default()
    except FixtureError as exc:
        print(f"找不到 fixtures/：{exc}", file=sys.stderr)
        return 1

    domains = tuple(args.only) if args.only else GALLERY_DOMAINS
    out_dir = Path(args.out)
    reports_dir = out_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 先写 staging，最后一次性搬进 docs/ —— 见 :func:`_publish` 的理由。
    # 目录建在 out_dir 里面（不是系统临时目录）：``Path.replace`` 只有同一文件
    # 系统上才是原子的，跨设备会抛 OSError。代价是被 SIGKILL 打断时会留一个
    # 残骸在 docs/ 下 —— 所以开跑先扫掉上一轮的，并且 .gitignore 里挡着它。
    for stale in sorted(out_dir.glob(".gallery-staging-*")):
        shutil.rmtree(stale, ignore_errors=True)
        print(f"扫掉上一轮的暂存目录 {stale.name}（上次是被强杀的）")
    staging = Path(tempfile.mkdtemp(prefix=".gallery-staging-", dir=out_dir))
    staging_reports = staging / "reports"
    staging_reports.mkdir()

    print(
        f"geo-audit {__version__} · 画廊 · {len(domains)} 个候选域 · "
        f"fixtures 录于 {_recorded_at(store)}"
    )
    mode = "**活网**（真请求）" if args.live else "replay（零网络、零 DNS）"
    print(f"{mode} · 并发 {args.jobs} · 默认参数（0.5 req/s、请求上限 120）")
    print()

    outcomes: list[Outcome] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {
            pool.submit(run_domain, d, contact=args.contact, store=store, live=args.live): d
            for d in domains
        }
        done: dict[str, Outcome] = {}
        for fut in concurrent.futures.as_completed(futures):
            domain = futures[fut]
            try:
                outcome = fut.result()
            # 一个域炸了不该带走整个画廊，所以这里兜住 Exception 并记进 index.html
            except Exception as exc:
                outcome = Outcome(domain, error=f"{type(exc).__name__}: {exc}")
            done[domain] = outcome
            _log_one(outcome, staging_reports)
        outcomes = [done[d] for d in domains]

    index = render_index(
        outcomes,
        recorded_at=_recorded_at(store),
        built_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        tool_version=__version__,
    )
    assert_selfcontained(index)
    assert_no_banned_words(index)
    _publish(outcomes, index, staging=staging, out_dir=out_dir, reports_dir=reports_dir)

    published = [o for o in outcomes if o.published]
    print()
    print(f"索引 {out_dir / 'index.html'} · {len(published)} 份报告 / {len(domains)} 个候选域")
    _print_needs_network(outcomes)

    problems = check_copy_discipline()
    for p in problems:
        print(f"措辞纪律：{p}", file=sys.stderr)
    if problems:
        return 2
    print(f"措辞纪律闸门：通过（扫了 {len(COPY_FILES)} 个文件）")
    return 0 if published else 1


def _publish(
    outcomes: list[Outcome],
    index: str,
    *,
    staging: Path,
    out_dir: Path,
    reports_dir: Path,
) -> None:
    """把这一轮的产物一次性搬进 ``docs/``：**跑完了才写盘**。

    为什么不是边跑边写（原来的做法）：2026-09-11 那次重建被系统因内存不足
    连杀 6 次，每次都在中途 —— 于是 ``docs/reports/`` 里躺着 6 份新的 + 3 份
    旧的，**而那批混合物看起来完全正常**：文件都在、每份自己都是合法 HTML、
    index.html 是上一轮的所以数字也自洽。不是恰好查了 `git status` 的话，
    它会被当成一次正常的重建提交上去。

    与内存无关，是「长任务中途被杀」的通用形态。所以判据不是「内存够不够」，
    是**中途死掉时 docs/ 必须原封不动**：报告先落 staging，全跑完、索引也渲染
    完并过了自包含 / 禁词两道闸，才 ``Path.replace`` 逐个搬过去（同一文件系统上
    是原子替换），index.html 最后写 —— 它是「这批报告」的目录，早于报告落盘
    就会指向还不存在的东西。

    **一个域失败不阻止发布**（那是它自己的 ``error`` / ``gaps``，index 里会
    写明），阻止发布的只有「整轮没跑完」—— 那种情况下这个函数根本不会被调到。
    """
    for outcome in outcomes:
        if outcome.html_path is None:
            continue
        final = reports_dir / outcome.html_path.name
        outcome.html_path.replace(final)
        outcome.html_path = final
    (out_dir / "index.html").write_text(index, "utf-8")
    (out_dir / ".nojekyll").write_text("", "utf-8")
    shutil.rmtree(staging, ignore_errors=True)


def _log_one(outcome: Outcome, reports_dir: Path) -> None:
    """一个域跑完就落 **staging** + 打一行。渲染失败也只影响这一个域。

    ``reports_dir`` 是 staging 下的那个目录，不是 ``docs/reports/`` ——
    搬家在 :func:`_publish` 里一次性做。
    """
    if outcome.report is None:
        why = outcome.error or "；".join(g.what for g in outcome.gaps)
        print(f"  跳过  {outcome.domain:<16} {why}")
        return
    try:
        page = render_html(outcome.report)
        assert_selfcontained(page)
    except (AssertionError, ValueError, TypeError, KeyError) as exc:
        outcome.report = None
        outcome.error = f"渲染失败：{type(exc).__name__}: {exc}"
        print(f"  跳过  {outcome.domain:<16} {outcome.error}")
        return
    path = reports_dir / f"{outcome.domain}.html"
    path.write_text(page, "utf-8")
    outcome.html_path = path
    c = outcome.report.counts
    extra = (
        f" · 站内链接缺快照 {len(outcome.missing_snapshots)} 条"
        if outcome.missing_snapshots
        else ""
    )
    print(
        f"  出报告 {outcome.domain:<16} {c.positions} 位置："
        f"{c.positions_fail} 读错 / {c.positions_unknown} 无法判断 / "
        f"{c.positions_pass} 通过 / {c.positions_na} 不适用 · "
        f"{len(page.encode()) // 1024} KB{extra}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
