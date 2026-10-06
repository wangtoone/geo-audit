"""``geo-audit robots DOMAIN ...``：robots.txt 对各家 AI 爬虫分别怎么说。

每个 host 只取一次 ``/robots.txt``（≤0.5 req/s、带联系邮箱的诚实 UA），然后在本地按
RFC 9309 判每个爬虫：训练 / 检索 / 对话实时抓取三类，以及**哪一组规则决定了它**。
输出的是事实，不是缺陷结论 —— 「拦训练、放检索」是正当策略。**不改 Report 契约。**

退出码：0 全部读到了；3 有 host 的 robots.txt 没读到（5xx / 网络错误，那些爬虫记为
unreadable，**不是**站方禁止）；4 用法错。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

from geo_audit.checks.robots_crawlers import (
    Access,
    HostCrawlerPolicy,
    Role,
    judge_robots_crawlers,
)
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig, build_user_agent
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.pipeline import EXIT_OK, EXIT_UNREACHABLE, EXIT_USAGE

PROG = "geo-audit robots"
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

_ROLE_TITLE = {
    Role.TRAINING: "训练（采集内容训练下一代模型）",
    Role.SEARCH: "检索（建 AI 搜索的索引，拦了进不了它的库）",
    Role.USER_FETCH: "对话实时抓取（有人在对话里点名某页面时去抓）",
}
_ACCESS_TEXT = {
    Access.ALLOWED: "放行",
    Access.PARTIAL: "部分路径禁止",
    Access.BLOCKED_ALL: "全站禁止",
    Access.UNREADABLE: "没读到 robots.txt",
}
_MATCHED_TEXT = {
    "specific": "有写它名字的组",
    "wildcard": "落到 User-agent: *",
    "none": "没有它的组、也没有 * 组",
    "no_robots_txt": "站点没有 robots.txt",
    "unreadable": "—",
}


class UsageError(Exception):
    pass


def to_host(raw: str) -> str:
    s = raw.strip()
    host = (urlsplit(s).hostname if "://" in s else s.split("/", 1)[0]) or ""
    host = host.lower().rstrip(".")
    if not _HOST_RE.match(host):
        raise UsageError(f"不是合法的域名或 URL：{raw!r}（如 example.com 或 https://example.com/）")
    return host


def audit_host(fetcher: Fetcher, host: str) -> tuple[HostCrawlerPolicy, int]:
    info = fetcher.robots_for(f"https://{host}/")
    return judge_robots_crawlers(host, info.raw, info.policy), info.status


def render_text(pol: HostCrawlerPolicy, status: int) -> str:
    lines = [f"== {pol.host}  robots.txt: HTTP {status or '无响应'} · 按 {pol.policy} 处理"]
    if pol.policy == "disallow_all":
        lines.append("  没读到 robots.txt（5xx / 网络错误）：下面不是站方的决定，是我们没能看。")
    for role in Role:
        lines.append(f"  [{_ROLE_TITLE[role]}]")
        for a in pol.by_role(role):
            rule = f"：{a.deciding_rule}" if a.deciding_rule else ""
            verdict = f"{_ACCESS_TEXT[a.access]}  ← {_MATCHED_TEXT[a.matched]}{rule}"
            lines.append(f"    {a.crawler.token:<20} {verdict}")
    wild = pol.search_blocked_by_wildcard()
    if wild:
        lines.append(
            f"  ⚠ 检索类爬虫 {', '.join(wild)} 在 robots.txt 里没有出现名字，"
            "却被 User-agent: * 全站禁止。"
        )
    return "\n".join(lines)


def to_dict(pol: HostCrawlerPolicy, status: int) -> dict[str, Any]:
    return {
        "host": pol.host,
        "robots_status": status,
        "policy": pol.policy,
        "crawlers": [
            {
                "token": a.crawler.token,
                "operator": a.crawler.operator,
                "role": a.crawler.role.value,
                "access": a.access.value,
                "matched": a.matched,
                "deciding_rule": a.deciding_rule,
            }
            for a in pol.answers
        ],
        "search_blocked_by_wildcard": list(pol.search_blocked_by_wildcard()),
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "robots.txt 对各家 AI 爬虫（训练 / 检索 / 实时抓取）分别怎么说，以及哪一组规则"
            "决定了它。每个 host 一次请求，≤0.5 req/s。"
        ),
        epilog="退出码：0 全部读到 · 3 有 host 没读到 robots.txt · 4 用法错",
    )
    p.add_argument("targets", nargs="*", metavar="DOMAIN", help="域名或 URL（只取 host）")
    p.add_argument("--contact", help="联系邮箱，写进 UA（或环境变量 GEO_AUDIT_CONTACT）")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--json", action="store_true", help="输出 JSON 而不是文本")
    return p


def run(argv: Sequence[str], *, fetcher: Fetcher | None = None) -> int:
    args = build_parser().parse_args(list(argv))
    try:
        if not args.targets:
            raise UsageError(
                "没有要看的域名：geo-audit robots example.com --contact you@yourco.com"
            )
        hosts = list(dict.fromkeys(to_host(t) for t in args.targets))
        contact = (args.contact or os.environ.get("GEO_AUDIT_CONTACT") or "").strip()
        build_user_agent(contact)  # 校验邮箱
    except (UsageError, ValueError) as exc:
        sys.stderr.write(f"{PROG}: {exc}\n")
        return EXIT_USAGE

    if fetcher is None:
        fetcher = Fetcher(
            FetcherConfig(contact=contact, interval=2.0, read_timeout=args.timeout),
            HttpCache(":memory:"),
            DomainLimiter(2.0),
        )
    results = [audit_host(fetcher, h) for h in hosts]
    if args.json:
        sys.stdout.write(
            json.dumps([to_dict(p, s) for p, s in results], ensure_ascii=False, indent=2) + "\n"
        )
    else:
        sys.stdout.write("\n\n".join(render_text(p, s) for p, s in results) + "\n")
    unreadable = any(p.policy == "disallow_all" for p, _ in results)
    return EXIT_UNREACHABLE if unreadable else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    return run(sys.argv[1:] if argv is None else argv)


__all__ = ["main", "run"]
