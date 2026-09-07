"""命令行入口（第 16 步 · §7.1 / §7.2）。

进度输出一律走 ``print(file=sys.stderr)``，不引 logging（见 pyproject 的
``per-file-ignores``：本文件放开 T201，正是为了这个）。**stdout 留给
``--format json`` 管道。**

七个退出码（§7.1:3349 逐字）：

* 0   扫描完成，没有达到 ``--fail-on`` 级别的发现
* 1   扫描完成，有达到 ``--fail-on`` 级别的发现
* 2   扫描完成但结论不可信：核心位置里超过一半是「无法评估」，或扫描被中断。
      报告照常生成，但不要拿它下结论。**优先级高于 1。**
* 3   目标域完全不可达（apex 与 www 都解析失败或连不上），不生成报告
* 4   用法错误（缺 ``--contact``、``--rate`` 超上限、域名不合法、``--skip`` 传了
      未注册的规则 id、``--from`` 文件 schema 不符）
* 130 被 Ctrl-C 中断（已完成的位置照常渲染成报告，未跑的标「无法评估 · 被中断」）
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import webbrowser
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import NoReturn, cast

import jinja2

from geo_audit import __version__
from geo_audit.fetch import resolve as resolve_mod
from geo_audit.fetch.jsrender import RENDER_FLAG_MESSAGE
from geo_audit.fixtures import FixtureStore
from geo_audit.models import SCHEMA_VERSION, Status
from geo_audit.pipeline import (
    CHECK_IDS,
    DEFAULT_FAIL_ON,
    DEFAULT_FORMAT,
    DEFAULT_MAX_LINKS,
    DEFAULT_MAX_REQUESTS,
    DEFAULT_OUT_DIR,
    DEFAULT_RATE,
    DEFAULT_RESOLVERS,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_UNREACHABLE,
    EXIT_USAGE,
    RATE_TOO_FAST_MSG,
    RULE_REGISTRY,
    STAGE_LABEL,
    AuditOptions,
    DomainUnreachable,
    Report,
    audit_domain,
    count_positions,
    exit_code_for,
    interrupt_banner,
    nearest_ids,
    valid_ids,
)

PROG = "geo-audit"

#: §7.1 的联系邮箱环境变量。
CONTACT_ENV = "GEO_AUDIT_CONTACT"

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

_EPILOG = """\
必填:
  --contact EMAIL 是抓取礼仪的一部分，不可省略。也可用环境变量 GEO_AUDIT_CONTACT
  提供，缺失直接退出 4。⚠️ --replay-fixtures 与 --from 也要它：做成「某些模式可省」
  等于给了绕过的口子。

抓取行为（下限锁死，不可调快）:
  单 registrable domain 请求速率默认 0.5 req/s（每 2 秒 1 个），只允许调慢；
  传入大于 0.5 的值直接退出 4。默认遵守 robots.txt：被 Disallow 的位置会标成
  「无法评估 · robots 禁止」，不会标成「通过」。

退出码:
  0   扫描完成，没有达到 --fail-on 级别的发现
  1   扫描完成，有达到 --fail-on 级别的发现
  2   扫描完成但结论不可信：核心位置里超过一半是「无法评估」（WAF / 反爬 /
      JS 渲染），或扫描被中断。报告照常生成，但不要拿它下结论。优先级高于 1。
  3   目标域完全不可达（apex 与 www 都解析失败或连不上），不生成报告
  4   用法错误（缺 --contact、--rate 超上限、域名不合法、--skip 传了未注册的
      规则 id、--from 文件 schema 不符）
  130 被 Ctrl-C 中断（已完成的位置照常渲染成报告，未跑的标「无法评估 · 被中断」）

示例:
  geo-audit mistral.ai --contact you@yourco.com
  geo-audit example.com --contact you@yourco.com --only ai_path --out ./out
  geo-audit minimax.io --contact you@yourco.com --naive-only
  geo-audit --from ./out/example.com.json --contact you@yourco.com --format html
"""


class _Parser(argparse.ArgumentParser):
    """argparse 的用法错误默认退 2；§7.1 要求用法错误一律 4。"""

    def error(self, message: str) -> NoReturn:
        print(f"{PROG}: 用法错误：{message}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def die(code: int, msg: str) -> NoReturn:
    """打一行理由到 stderr 然后带 ``code`` 退出（§7.1:3361 直接用了 ``die(4, ...)``）。"""
    print(f"{PROG}: {msg}", file=sys.stderr)
    raise SystemExit(code)


def build_parser() -> argparse.ArgumentParser:
    """§7.1 的全部 flag。"""
    parser = _Parser(
        prog=PROG,
        usage="geo-audit DOMAIN [options]\n       geo-audit --from REPORT.json [options]",
        description=(
            "给一个域名，输出一份 HTML 报告：AI 检索你的公开信息时，"
            "哪些位置会被读错或读不到。零 LLM、零 API key、纯 HTTP + 字符串/哈希比对。"
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "domain",
        metavar="DOMAIN",
        nargs="?",
        help=(
            "要体检的域名，如 example.com（不带协议）。会自动探测 apex / www / docs / "
            "developers / api-docs / help / support 等 16 个子域前缀，以及 <domain>/docs 子路径"
        ),
    )
    parser.add_argument(
        "--contact",
        metavar="EMAIL",
        default=None,
        help=(
            "你的联系邮箱。会写进请求的 User-Agent，供被抓站点的管理员联系你。"
            f"这是抓取礼仪的一部分，不可省略。也可用环境变量 {CONTACT_ENV} 提供。缺失直接退出 4"
        ),
    )

    out = parser.add_argument_group("输出")
    out.add_argument("-o", "--out", metavar="DIR", default=DEFAULT_OUT_DIR, help="报告输出目录")
    out.add_argument(
        "--format",
        dest="formats",
        metavar="FMT",
        default=DEFAULT_FORMAT,
        help="html,json（默认 html,json，逗号分隔）",
    )
    out.add_argument(
        "--open",
        dest="open_report",
        action="store_true",
        help="渲染完成后用系统默认浏览器打开 HTML",
    )
    out.add_argument(
        "--from",
        dest="from_file",
        metavar="FILE",
        default=None,
        help="跳过所有网络请求，从既有 JSON 重新渲染 HTML。强制禁用缓存",
    )
    out.add_argument(
        "--replay-fixtures",
        action="store_true",
        help="用仓库内 fixtures/ 的冻结快照跑，零网络、零 DNS。强制禁用缓存",
    )

    checks = parser.add_argument_group("检查项")
    checks.add_argument(
        "--only",
        metavar="IDS",
        default="",
        help="只跑这些（逗号分隔）：检查 id（ai_path / dead_links）或规则 id",
    )
    checks.add_argument(
        "--skip",
        metavar="IDS",
        default="",
        help="跳过这些。取值同 --only。传入未注册的 id 直接退出 4",
    )
    checks.add_argument(
        "--list-rules", action="store_true", help="打印全部合法的检查 id 与规则 id，然后退出 0"
    )
    checks.add_argument(
        "--naive-only",
        action="store_true",
        help="只打印内置朴素基线换算的结论（只探根路径、只看最终状态码、"
        "不做对照探测）。它不额外发请求",
    )
    checks.add_argument(
        "--max-links",
        type=int,
        metavar="N",
        default=DEFAULT_MAX_LINKS,
        help="每个域最多验证多少条去噪并模板归并后的唯一目标（0 = 不限）",
    )
    checks.add_argument(
        "--max-requests",
        type=int,
        metavar="N",
        default=DEFAULT_MAX_REQUESTS,
        help="单域请求硬上限（0 = 不限）。超限的位置标「无法评估 · 超出预算」",
    )
    checks.add_argument("--index-links-full", action="store_true", help="llms.txt 内链一律全量验证")
    checks.add_argument(
        "--no-wellknown", action="store_true", help="不探 /.well-known/llms.txt（72 域实测 0 命中）"
    )
    checks.add_argument(
        "--seed",
        dest="seeds",
        metavar="URL",
        action="append",
        default=[],
        help="额外的起始页（可重复）。默认起始页：首页、/pricing、/changelog、/docs、/help",
    )

    crawl = parser.add_argument_group("抓取行为（下限锁死，不可调快）")
    crawl.add_argument(
        "--rate",
        type=float,
        metavar="RPS",
        default=DEFAULT_RATE,
        help="单 registrable domain 请求速率，默认 0.5 req/s（每 2 秒 1 个）。"
        "只允许调慢；传入大于 0.5 的值直接退出 4",
    )
    crawl.add_argument(
        "--timeout", type=float, metavar="SEC", default=DEFAULT_TIMEOUT, help="单请求超时，默认 20"
    )
    crawl.add_argument(
        "--retries",
        type=int,
        metavar="N",
        default=DEFAULT_RETRIES,
        help="瞬时失败重试次数，默认 2（403/404/401 永不重试）",
    )
    crawl.add_argument(
        "--resolver",
        metavar="IPS",
        default=DEFAULT_RESOLVERS,
        help="DNS 二次确认用的解析器。本机解析器抖动会伪造出死链，二次确认不可关闭",
    )
    crawl.add_argument(
        "--ignore-robots",
        action="store_true",
        help="忽略 robots.txt（默认遵守；被 Disallow 的位置会标成"
        "「无法评估 · robots 禁止」，不会标成「通过」）",
    )
    crawl.add_argument("--no-cache", action="store_true", help="不读不写 HTTP 缓存")
    crawl.add_argument("--cache-dir", metavar="DIR", default=None, help="缓存目录")
    crawl.add_argument(
        "--render",
        action="store_true",
        help="[未实现] 用无头浏览器渲染 JS 页面。当前退出码非 0 并打印理由",
    )

    result = parser.add_argument_group("结果与退出码")
    result.add_argument(
        "--fail-on",
        metavar="LEVEL",
        default=DEFAULT_FAIL_ON,
        choices=("critical", "high", "medium", "low", "none"),
        help="什么级别的发现算失败：critical|high|medium|low|none（默认 low）",
    )
    result.add_argument(
        "--ignore",
        dest="ignores",
        metavar="ID",
        action="append",
        default=[],
        help="抑制指定 finding（可重复）。ID 在每条发现卡片的右上角",
    )
    result.add_argument(
        "--ignore-file", metavar="FILE", default=None, help="每行一个 finding id，# 开头为注释"
    )

    misc = parser.add_argument_group("其它")
    misc.add_argument("-q", "--quiet", action="store_true", help="不打进度，结束时只打一行")
    misc.add_argument("-v", "--verbose", action="store_true", help="打每一个请求")
    misc.add_argument("--no-color", action="store_true", help="关闭颜色（非 TTY 时自动关闭）")
    misc.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    return parser


# --------------------------------------------------------------------------- #
# §7.2 进度输出（stderr，非 TTY 自动去色）
# --------------------------------------------------------------------------- #

_COLORS = {"PASS": "\033[32m", "FAIL": "\033[31m", "UNKN": "\033[33m"}
_RESET = "\033[0m"


class StderrProgress:
    """§7.2 的进度输出。**全部走 stderr**，stdout 留给 ``--format json`` 管道。"""

    def __init__(self, *, color: bool, verbose: bool) -> None:
        self.color = color
        self.verbose = verbose

    def _paint(self, state: str) -> str:
        if not self.color or state not in _COLORS:
            return state
        return f"{_COLORS[state]}{state}{_RESET}"

    def stage(self, index: int, label: str, detail: str) -> None:
        print(f"[{index}/6] {label:<12}{detail}", file=sys.stderr)

    def row(self, state: str, url: str, note: str) -> None:
        if not self.verbose and state == "PASS":
            return
        print(f"      {self._paint(state)}  {url}  {note}", file=sys.stderr)

    def note(self, text: str) -> None:
        print(text, file=sys.stderr)


# --------------------------------------------------------------------------- #
# 校验
# --------------------------------------------------------------------------- #


def resolve_contact(raw: str | None) -> str:
    """``--contact`` / ``GEO_AUDIT_CONTACT``。**任何模式都不豁免**（卡点 B17a）。"""
    contact = (raw or os.environ.get(CONTACT_ENV) or "").strip()
    if not contact or "@" not in contact:
        die(
            EXIT_USAGE,
            "必须提供联系邮箱（--contact 或 GEO_AUDIT_CONTACT）。抓取合规要求 "
            "User-Agent 里带真实联系方式，做成可选等于没有 —— "
            "--replay-fixtures 与 --from 也不豁免。",
        )
    return contact


def parse_ids(raw: str) -> tuple[str, ...]:
    return tuple(i.strip() for i in raw.split(",") if i.strip())


def check_ids(ids: Sequence[str], *, flag: str) -> None:
    """``--only`` / ``--skip`` 的每个 id 必须在注册表里，否则退 4 + 三个候选。"""
    legal = set(valid_ids())
    for i in ids:
        if i not in legal:
            candidates = "、".join(nearest_ids(i))
            die(
                EXIT_USAGE,
                f"{flag} 传了未注册的 id：{i}。最接近的三个候选：{candidates}。"
                "全部合法取值见 --list-rules。",
            )


def check_domain(raw: str | None) -> str:
    if not raw:
        die(EXIT_USAGE, "缺少 DOMAIN。用法：geo-audit example.com --contact you@yourco.com")
    domain = raw.strip().lower().rstrip(".")
    if "://" in domain or "/" in domain or not _DOMAIN_RE.match(domain):
        die(EXIT_USAGE, f"域名不合法：{raw!r}。要的是不带协议、不带路径的域名，如 example.com")
    return domain


def read_ignore_file(path: str | None) -> tuple[str, ...]:
    if not path:
        return ()
    text = Path(path).read_text("utf-8")
    return tuple(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def print_rules() -> None:
    """``--list-rules``：打印 ``RULE_REGISTRY`` 全部合法 id（ai_path 4 条 + dead_links 23 条）。"""
    for check in CHECK_IDS:
        rules = RULE_REGISTRY[check]
        print(f"{check}  （{len(rules)} 条规则）")
        for rule in rules:
            print(f"  {check}.{rule}")


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #

_COUNT_BAR = "{positions} 个位置   ✓ {p} 通过   ✕ {f} 读错   ? {u} 无法判断   – {na} 不适用"


def render_html(data: dict[str, object]) -> str:
    """把报告 JSON 渲染成自包含 HTML。

    ⚠️ **过渡实现**：正式模板是第 15a 步的 ``geo_audit.report.render_html``
    （Jinja + report.css + 十个 section）。那个包还不存在，所以这里给一个零依赖、
    零外部请求的最小版：页眉 + headline + 四格计数条 + 中断通栏 + 位置账本表。
    ``geo_audit.report`` 一落地，:func:`write_outputs` 会自动优先用它。
    """
    counts = data.get("counts")
    counts_map: dict[str, object] = counts if isinstance(counts, dict) else {}
    positions = data.get("positions")
    rows: list[str] = []
    if isinstance(positions, list):
        for item in positions:
            if not isinstance(item, dict):
                continue
            rows.append(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>".format(
                    html.escape(str(item.get("label", ""))),
                    html.escape(str(item.get("probe_url", ""))),
                    html.escape(str(item.get("status", ""))),
                    html.escape(str(item.get("detail", ""))),
                )
            )
    bar = _COUNT_BAR.format(
        positions=counts_map.get("positions", 0),
        p=counts_map.get("positions_pass", 0),
        f=counts_map.get("positions_fail", 0),
        u=counts_map.get("positions_unknown", 0),
        na=counts_map.get("positions_na", 0),
    )
    banner = str(data.get("interrupt_banner") or "")
    banner_html = f'<pre id="interrupted">{html.escape(banner)}</pre>' if banner.strip() else ""
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>geo-audit · {html.escape(str(data.get("domain", "")))}</title>
<style>
body{{font-family:-apple-system,"Segoe UI","Noto Sans CJK SC","PingFang SC",sans-serif;
margin:2rem;max-width:60rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.35rem .5rem;
text-align:left;font-size:.9rem}}
code{{word-break:break-all}}.wide{{overflow-x:auto}}
@page{{size:A4;margin:14mm}}
</style></head><body>
<header><b>{html.escape(str(data.get("domain", "")))}</b> ·
{html.escape(str(data.get("scanned_at", "")))} ·
v{html.escape(str(data.get("tool_version", "")))} ·
{html.escape(str(data.get("user_agent", "")))} ·
{html.escape(str(data.get("denoise_ruleset_version", "")))}</header>
<h1 id="verdict">{html.escape(str(data.get("headline", "")))}</h1>
{banner_html}
<p id="chain">{html.escape(bar)}</p>
<section id="positions"><h2>位置账本</h2><div class="wide"><table>
<tr><th>位置</th><th>URL</th><th>状态</th><th>结论</th></tr>
{"".join(rows)}
</table></div></section>
</body></html>
"""


def report_to_dict(report: Report) -> dict[str, object]:
    data = json.loads(report.to_json())
    if not isinstance(data, dict):  # pragma: no cover —— to_json 恒为对象
        raise TypeError("报告 JSON 不是对象")
    data["interrupt_banner"] = interrupt_banner(report)
    return data


def official_report_from_json(path: str) -> object | None:
    """``--from``：用第 15c 步的 ``load_report`` 反序列化成真 ``Report``。

    拿到了就能走正式模板（十个 section 全在）；拿不到（报告层还没落地、或占位
    类型与本步对不上）就退回 :func:`render_html` 的最小 HTML。
    schema 不符由 :func:`load_report_json` 先挡成退出码 4。
    """
    try:
        from geo_audit.report import load_report
    except ImportError:
        return None
    try:
        return cast("Callable[[str], object]", load_report)(path)
    except (AttributeError, TypeError, KeyError, ValueError) as exc:
        print(f"{PROG}: 正式反序列化失败（{exc}），退回最小自包含 HTML", file=sys.stderr)
        return None


def html_of(report: object | None, data: dict[str, object]) -> str:
    """优先用第 15a 步的正式模板（``geo_audit.report.render_html``）。

    退回 :func:`render_html` 的只有两种情况：``--from``（手里只有 JSON，没有
    ``Report`` 对象，正式的反序列化是第 15c 步的 ``load_report``），
    以及报告层与本步的占位类型还没被 owner 合并进 models.py 导致字段对不上 ——
    后者会在 stderr 上明说，不静默降级。
    """
    if report is None:
        return render_html(data)
    try:
        from geo_audit.report import render_html as render_official
    except ImportError:
        return render_html(data)
    try:
        return cast("Callable[[object], str]", render_official)(report)
    except (AttributeError, TypeError, KeyError, jinja2.TemplateError) as exc:
        print(
            f"{PROG}: 正式模板渲染失败（报告层与 pipeline 的占位类型还没合并？{exc}），"
            "退回最小自包含 HTML",
            file=sys.stderr,
        )
        return render_html(data)


def write_json_file(report: object | None, data: dict[str, object], path: Path) -> None:
    """优先用第 15c 步的确定性序列化（``geo_audit.report.write_json``）。

    退回 ``json.dumps`` 的只有「报告层还没落地」这一种情况 —— 两份序列化器必然
    对不上，所以正式那份在就一定用它。
    """
    if report is not None:
        try:
            from geo_audit.report import write_json
        except ImportError:
            pass
        else:
            try:
                cast("Callable[[object, Path], object]", write_json)(report, path)
            except (AttributeError, TypeError, KeyError, ValueError) as exc:
                print(f"{PROG}: 正式 JSON 序列化失败（{exc}），退回 json.dumps", file=sys.stderr)
            else:
                return
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), "utf-8")


def write_outputs(
    data: dict[str, object],
    *,
    out_dir: Path,
    domain: str,
    formats: Sequence[str],
    report: object | None = None,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        path = out_dir / f"{domain}.json"
        write_json_file(report, data, path)
        written.append(path)
    if "html" in formats:
        path = out_dir / f"{domain}.html"
        path.write_text(html_of(report, data), "utf-8")
        written.append(path)
    return written


def load_report_json(path: str) -> dict[str, object]:
    """``--from`` 的反序列化。schema 不符 → 退出 4（A44）。"""
    file = Path(path)
    if not file.exists():
        die(EXIT_USAGE, f"--from 指定的文件不存在：{path}")
    try:
        data = json.loads(file.read_text("utf-8"))
    except json.JSONDecodeError as exc:
        die(EXIT_USAGE, f"--from 文件不是合法 JSON：{exc}")
    got = data.get("schema_version") if isinstance(data, dict) else type(data).__name__
    if not isinstance(data, dict) or got != SCHEMA_VERSION:
        die(
            EXIT_USAGE,
            f"--from 文件 schema 不符：期望 schema_version == {SCHEMA_VERSION!r}，实际 {got!r}",
        )
    return data


def apply_ignores(report: Report, ignores: Sequence[str]) -> Report:
    """``--ignore`` / ``--ignore-file``：抑制指定 finding 并重算条数。

    位置账本不动 —— 抑制一条发现不等于那个位置通过了（headline 只看位置数）。
    """
    if not ignores:
        return report
    drop = set(ignores)
    kept = tuple(f for f in report.findings if f.finding_id not in drop)
    if len(kept) == len(report.findings):
        return report
    counts = count_positions(
        report.positions,
        kept,
        report.root_causes,
        report.naive_table,
        naive_dead_count=report.counts.naive_dead_count,
        audited_dead_instances=report.counts.audited_dead_instances,
    )
    return replace(report, findings=kept, counts=counts)


def print_naive_table(report: Report) -> None:
    """``--naive-only``：打印朴素基线的读数与我们的读数（§4.5 的三列表）。"""
    print("探测位置\t那种实现会说\t实际是")
    for row in report.naive_table:
        mark = " ←差异" if row.diverges else ""
        print(f"{row.probe_url}\t{row.naive_conclusion}\t{row.actual_conclusion}{mark}")
    print(
        f"只探根路径、不做对照探测的实现，会在你的 {report.counts.naive_divergences} 个位置上读错",
        file=sys.stderr,
    )


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main(argv: Sequence[str] | None = None) -> int:
    """返回进程退出码。决策顺序见 §7.1 与 §7.5。"""
    parser = build_parser()
    try:
        return _run(parser, argv)
    except SystemExit as exc:  # die() / argparse / --help / --version
        code = exc.code
        if code is None:
            return EXIT_OK
        return code if isinstance(code, int) else EXIT_USAGE


def _run(parser: argparse.ArgumentParser, argv: Sequence[str] | None) -> int:
    args = parser.parse_args(argv)

    # 0. --list-rules 先于一切校验（§7.1：打印然后退 0）
    if args.list_rules:
        print_rules()
        return EXIT_OK

    # 1. --render 未实现：打印三条理由，退出码非 0（A43）
    if args.render:
        print(RENDER_FLAG_MESSAGE, file=sys.stderr)
        return EXIT_USAGE

    # 2. --contact 无条件必填（卡点 B17a）
    contact = resolve_contact(args.contact)

    # 3. --rate 只能调慢（§7.1:3358）
    if args.rate > DEFAULT_RATE:
        die(EXIT_USAGE, RATE_TOO_FAST_MSG)
    if args.rate <= 0:
        die(EXIT_USAGE, "--rate 必须大于 0。" + RATE_TOO_FAST_MSG)

    only = parse_ids(args.only)
    skip = parse_ids(args.skip)
    check_ids(only, flag="--only")
    check_ids(skip, flag="--skip")

    formats = tuple(f.strip() for f in args.formats.split(",") if f.strip())
    for fmt in formats:
        if fmt not in ("html", "json"):
            die(EXIT_USAGE, f"--format 只认 html / json，收到 {fmt!r}")

    ignores = tuple(args.ignores) + read_ignore_file(args.ignore_file)
    out_dir = Path(args.out)
    color = (not args.no_color) and sys.stderr.isatty()

    # 4. --from：零网络，从既有 JSON 重出 HTML（强制禁用缓存，卡点 B18）
    if args.from_file:
        data = load_report_json(args.from_file)
        domain = str(data.get("domain") or "report")
        written = write_outputs(
            data,
            out_dir=out_dir,
            domain=domain,
            formats=formats or ("html",),
            report=official_report_from_json(args.from_file),
        )
        for path in written:
            print(f"报告 {path}", file=sys.stderr)
        _maybe_open(written, open_report=args.open_report)
        return EXIT_OK

    domain = check_domain(args.domain)

    # 5. --resolver：resolve.py 的 FALLBACK_RESOLVERS 是模块常量，没有 IP 列表注入口
    #    （见交付说明 spec_gaps）。CLI 是这个 flag 的配置点，所以在这里改它。
    resolvers = tuple(i.strip() for i in args.resolver.split(",") if i.strip())
    if not resolvers:
        die(EXIT_USAGE, "--resolver 至少要一个 IP。本机解析器抖动会伪造出死链，二次确认不可关闭。")
    resolve_mod.FALLBACK_RESOLVERS = resolvers

    store = FixtureStore.default() if args.replay_fixtures else None
    options = AuditOptions(
        domain=domain,
        contact=contact,
        only=only,
        skip=skip,
        seeds=tuple(args.seeds),
        max_links=args.max_links,
        max_requests=args.max_requests,
        index_links_full=args.index_links_full,
        wellknown=not args.no_wellknown,
        rate=args.rate,
        timeout=args.timeout,
        retries=args.retries,
        resolvers=args.resolver,
        ignore_robots=args.ignore_robots,
        # --replay-fixtures 与 --from 强制禁用缓存（卡点 B18）
        use_cache=not (args.no_cache or args.replay_fixtures),
        cache_dir=args.cache_dir,
        replay_fixtures=args.replay_fixtures,
    )

    progress = StderrProgress(color=color, verbose=args.verbose)
    if not args.quiet:
        progress.note(f"{PROG} {__version__} · {domain}")
        progress.note(f"UA: geo-audit/{__version__} (contact: {contact}) · {args.rate} req/s")
        progress.note(
            "robots.txt  已忽略（--ignore-robots）"
            if args.ignore_robots
            else "robots.txt  遵守（被 Disallow 的位置标「无法评估 · robots 禁止」）"
        )

    try:
        report = audit_domain(
            options,
            store=store,
            resolver=store.resolver() if store is not None else None,
            progress=progress if not args.quiet else None,
        )
    except DomainUnreachable as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_UNREACHABLE

    report = apply_ignores(report, ignores)

    if args.naive_only:
        print_naive_table(report)
        return exit_code_for(report, fail_on=args.fail_on)

    data = report_to_dict(report)
    written = write_outputs(data, out_dir=out_dir, domain=domain, formats=formats, report=report)
    counts = report.counts
    print(
        f"完成 · {counts.positions} 个位置：{counts.positions_fail} 读错 / "
        f"{counts.positions_unknown} 无法判断 / {counts.positions_pass} 通过 / "
        f"{counts.positions_na} 不适用 · 请求 {report.coverage.requests_made} / "
        f"上限 {report.coverage.budget_cap or '不限'} · 用时 {report.duration_s:.0f}s",
        file=sys.stderr,
    )
    if report.coverage.interrupted:
        print(interrupt_banner(report), file=sys.stderr)
    for path in written:
        print(f"报告 {path}", file=sys.stderr)
    _maybe_open(written, open_report=args.open_report)

    code = exit_code_for(report, fail_on=args.fail_on)
    if code == EXIT_INTERRUPTED:
        unknown = sum(
            1
            for p in report.positions
            if p.status is Status.UNKNOWN and p.unknown_reason == "interrupted"
        )
        print(f"（{unknown} 个位置标「无法评估 · 被中断」）", file=sys.stderr)
    return code


def _maybe_open(written: Sequence[Path], *, open_report: bool) -> None:
    if not open_report:
        return
    for path in written:
        if path.suffix == ".html":
            webbrowser.open(path.resolve().as_uri())
            return


def _stage_labels() -> tuple[str, ...]:  # pragma: no cover —— 给 --help 之外的调用方
    return tuple(STAGE_LABEL.values())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
