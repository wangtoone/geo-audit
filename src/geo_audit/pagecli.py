"""``geo-audit page URL ...``：不跑 JS，看一个页面的原始 HTML 里有什么，再对账。

和主命令（整站体检）分开：这条只抓你点名的页面，每个一次请求，沿用同一套
限速（≤0.5 req/s）、robots 闸与带联系邮箱的诚实 UA。**不改 Report 契约**，所以
不进 JSON schema —— 它的输出自成一份小 JSON（``--json``）。

退出码：0 全部通过（或没写期望）；1 有期望没满足；3 没有失败但有 unknown
（没抓到 / 被拦 / 不是 HTML），**unknown 不是 pass**；4 用法错。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from geo_audit.checks.rawhtml import (
    ExpectResult,
    PageFacts,
    PageSpec,
    evaluate_spec,
    inspect_raw_html,
    unusable_reason,
)
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig, build_user_agent
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.pipeline import EXIT_FINDINGS, EXIT_OK, EXIT_UNREACHABLE, EXIT_USAGE

PROG = "geo-audit page"
_LIST_FIELDS = (
    "title_contains",
    "h1_contains",
    "text_contains",
    "text_absent",
    "schema_types",
    "prices",
)
_SPEC_KEYS = {f.name for f in fields(PageSpec)} - {"url"}


class UsageError(Exception):
    pass


def spec_from_dict(url: str, d: dict[str, Any]) -> PageSpec:
    unknown = set(d) - _SPEC_KEYS
    if unknown:
        raise UsageError(f"{url}: 不认识的期望字段 {sorted(unknown)}（可用：{sorted(_SPEC_KEYS)}）")
    kw: dict[str, Any] = {"url": url}
    for k, v in d.items():
        if k in _LIST_FIELDS:
            items = v if isinstance(v, list) else [v]
            kw[k] = (
                tuple(float(x) for x in items) if k == "prices" else tuple(str(x) for x in items)
            )
        elif k == "min_visible_chars":
            kw[k] = int(v)
        elif k in ("indexable",):
            kw[k] = None if v is None else bool(v)
        elif k == "no_js_shell":
            kw[k] = bool(v)
    return PageSpec(**kw)


def load_spec_file(path: str) -> dict[str, PageSpec]:
    try:
        raw = json.loads(Path(path).read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise UsageError(f"读不了 --spec {path}：{exc}") from exc
    if not isinstance(raw, dict) or not all(isinstance(v, dict) for v in raw.values()):
        raise UsageError('--spec 必须是 {"URL": {期望字段...}, ...} 的 JSON 对象')
    return {u: spec_from_dict(u, v) for u, v in raw.items()}


def check_url(raw: str) -> str:
    parts = urlsplit(raw.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UsageError(f"URL 不合法：{raw!r}（要带 https://，如 https://example.com/pricing）")
    if not re.match(r"^[a-z0-9.-]+$", parts.hostname.lower()):
        raise UsageError(f"主机名不合法：{parts.hostname!r}")
    return raw.strip()


@dataclass(frozen=True, slots=True)
class PageOutcome:
    url: str
    why_unusable: str | None
    facts: PageFacts | None
    results: tuple[ExpectResult, ...]


def audit_page(fetcher: Fetcher, spec: PageSpec) -> PageOutcome:
    resp = fetcher.fetch(spec.url)
    why = unusable_reason(
        status=resp.status,
        content_type=resp.content_type,
        transport_error=resp.transport_error,
        blocked=resp.blocked,
    )
    if why is not None:
        return PageOutcome(spec.url, why, None, tuple(evaluate_spec(None, spec, why_unusable=why)))
    facts = inspect_raw_html(
        resp.body.decode("utf-8", "replace"),
        status=resp.status,
        headers=resp.headers,
        final_url=resp.final_url,
        truncated=resp.body_truncated,
    )
    return PageOutcome(spec.url, None, facts, tuple(evaluate_spec(facts, spec)))


_MARK = {"pass": "✓", "fail": "✗", "unknown": "?"}


def render_text(o: PageOutcome) -> str:
    lines = [f"== {o.url}"]
    f = o.facts
    if f is None:
        lines.append(f"  没能读到页面：{o.why_unusable}")
    else:
        lines.append(
            f"  HTTP {f.status} · 最终 URL {f.final_url or o.url}"
            + ("（正文被截断）" if f.truncated else "")
        )
        lines.append(f"  title        {f.title!r}")
        lines.append(f"  H1           {list(f.h1)!r}")
        lines.append(f"  canonical    {f.canonical}   noindex={f.noindex}")
        js = (
            "是（" + ", ".join(f.js.signals) + f"；置信 {f.js.confidence}）"
            if f.js.required
            else "否"
        )
        lines.append(f"  可见文字     {f.visible_text_len} 字符 · 像 JS 空壳：{js}")
        lines.append(
            f"  JSON-LD      {list(f.schema_types)!r}"
            + (f" · {f.schema_invalid} 段解析失败" if f.schema_invalid else "")
        )
        amounts = [f"{a:g}" for a in f.visible_amounts]
        lines.append(f"  可见金额     {amounts!r}")
        if f.offer_prices_not_visible:
            lines.append(
                f"  ⚠ JSON-LD 的价格 {list(f.offer_prices_not_visible)!r} 不在可见文字里"
                "（结构化数据与可见文字不一致）"
            )
    for r in o.results:
        lines.append(f"  {_MARK[r.verdict]} {r.name} — {r.detail}")
    return "\n".join(lines)


def outcome_to_dict(o: PageOutcome) -> dict[str, Any]:
    facts = None
    if o.facts is not None:
        facts = asdict(o.facts)
        facts.pop("text", None)
    return {
        "url": o.url,
        "unusable": o.why_unusable,
        "facts": facts,
        "results": [asdict(r) for r in o.results],
    }


def exit_code(outcomes: Sequence[PageOutcome]) -> int:
    verdicts = [r.verdict for o in outcomes for r in o.results]
    if "fail" in verdicts:
        return EXIT_FINDINGS
    if "unknown" in verdicts or any(o.why_unusable for o in outcomes):
        return EXIT_UNREACHABLE
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "不跑 JS，读页面原始 HTML（多数 AI 爬虫看到的那份），并对账你的期望。"
            "每个页面一次请求，≤0.5 req/s，遵守 robots.txt。"
        ),
        epilog="退出码：0 通过 · 1 有期望没满足 · 3 有 unknown（没抓到/被拦，不是通过）· 4 用法错",
    )
    p.add_argument("urls", nargs="*", metavar="URL", help="要看的页面（带 https://）")
    p.add_argument("--contact", help="联系邮箱，写进 UA（或环境变量 GEO_AUDIT_CONTACT）")
    p.add_argument("--spec", metavar="FILE", help='期望文件：{"URL": {"h1_contains": [...], ...}}')
    g = p.add_argument_group("期望（对命令行里的每个 URL 生效）")
    g.add_argument("--title-contains", action="append", default=[], metavar="S")
    g.add_argument("--h1-contains", action="append", default=[], metavar="S")
    g.add_argument("--contains", action="append", default=[], metavar="S", help="可见文字必须含")
    g.add_argument("--absent", action="append", default=[], metavar="S", help="可见文字不许含")
    g.add_argument(
        "--schema", action="append", default=[], metavar="TYPE", help="JSON-LD 必须有的 @type"
    )
    g.add_argument(
        "--price",
        action="append",
        default=[],
        type=float,
        metavar="N",
        help="可见文字必须出现的金额",
    )
    g.add_argument("--min-chars", type=int, metavar="N")
    g.add_argument("--indexable", action="store_true", help="必须没有 noindex")
    g.add_argument("--no-js-shell", action="store_true", help="必须不是 JS 空壳")
    p.add_argument("--ignore-robots", action="store_true")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--json", action="store_true", help="输出 JSON 而不是文本")
    return p


def run(argv: Sequence[str], *, fetcher: Fetcher | None = None) -> int:
    import os

    parser = build_parser()
    args = parser.parse_args(list(argv))
    try:
        specs: dict[str, PageSpec] = {}
        if args.spec:
            specs.update(load_spec_file(args.spec))
        cli_spec: dict[str, Any] = {
            "title_contains": args.title_contains,
            "h1_contains": args.h1_contains,
            "text_contains": args.contains,
            "text_absent": args.absent,
            "schema_types": args.schema,
            "prices": args.price,
            "min_visible_chars": args.min_chars,
            "indexable": True if args.indexable else None,
            "no_js_shell": args.no_js_shell,
        }
        cli_spec = {k: v for k, v in cli_spec.items() if v not in ([], None, False)}
        for u in args.urls:
            u = check_url(u)
            specs[u] = spec_from_dict(u, cli_spec)
        if not specs:
            raise UsageError("没有要看的页面：给一个或多个 URL，或用 --spec")
        for u in specs:
            check_url(u)
        contact = (args.contact or os.environ.get("GEO_AUDIT_CONTACT") or "").strip()
        build_user_agent(contact)  # 校验邮箱
    except (UsageError, ValueError) as exc:
        sys.stderr.write(f"{PROG}: {exc}\n")
        return EXIT_USAGE

    if fetcher is None:
        fetcher = Fetcher(
            FetcherConfig(
                contact=contact,
                interval=2.0,
                read_timeout=args.timeout,
                respect_robots=not args.ignore_robots,
            ),
            HttpCache(":memory:"),
            DomainLimiter(2.0),
        )
    outcomes = [audit_page(fetcher, s) for s in specs.values()]
    if args.json:
        sys.stdout.write(
            json.dumps([outcome_to_dict(o) for o in outcomes], ensure_ascii=False, indent=2) + "\n"
        )
    else:
        sys.stdout.write("\n\n".join(render_text(o) for o in outcomes) + "\n")
    return exit_code(outcomes)


def main(argv: Sequence[str] | None = None) -> int:
    return run(sys.argv[1:] if argv is None else argv)
