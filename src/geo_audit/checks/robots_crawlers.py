"""robots.txt 对各家 AI 爬虫分别怎么说。零网络、零 LLM，只吃一份已抓回的 robots.txt。

## 为什么要有这张表

``Fetcher.robots_for`` 只回答一个问题：**我们自己的 UA 能不能抓**。可是「AI 读不读得到
你」是另一个问题 —— 同一个站，对训练爬虫、检索爬虫、对话中实时抓取的爬虫，常常给
三种不同的答案，而且最常见的事故恰恰藏在这个差别里：

* 想拦 OpenAI 的**训练**（GPTBot），顺手写了 ``User-agent: *`` + ``Disallow: /`` 或把
  整串 OpenAI 爬虫一起拦，结果 **OAI-SearchBot**（ChatGPT 搜索的索引）也进不来；
* 只给 GPTBot 单独写了一组，OAI-SearchBot 没有自己的组，于是落到 ``*`` 组 ——
  ``*`` 组怎么写，它就怎么走，**读 robots.txt 的人很难一眼看出来**。

所以这里不只回答「拦没拦」，还回答「**哪一组规则决定了它**」（``matched``）。

## 这不是一条 finding

``FindingKind`` 是冻结集合（``tests/test_v1_scope.py``），新增一类要先量出假阳性率。
本模块输出的是**事实表**（robots.txt 对 X 的答案），不下「这是缺陷」的结论 ——
「拦了检索爬虫」是站方可以有意为之的策略，不是 bug。函数名刻意不叫 ``check_*``
（那个前缀被 v1 范围守门盯着）。

## 解析语义（RFC 9309）

* 组 = 连续的 ``User-agent`` 行 + 之后的规则行；同名的多个组**合并**；
* 爬虫选组：产品 token **大小写不敏感、整串相等**，没有命中才落到 ``*``；
* 规则匹配：**最长匹配胜出，等长时 Allow 胜**；``*`` 通配任意串，``$`` 锚定末尾；
* 空的 ``Disallow:`` 什么都不禁止；空的 ``Allow:`` 无效；
* 第一组之前出现的规则行无主，忽略。

**不做**：百分号编码归一化（路径里带 ``%xx`` 的规则会按字面比）、500 KiB 截断。
这两条都不影响「根路径放不放行」这个主问题。

## 取不到 robots.txt 的三种结果

沿用 ``RobotsInfo.policy``：``parsed`` 按内容；``allow_all``（4xx，没有 robots.txt）全放行；
``disallow_all``（5xx / 网络错误）—— 这是**我们没能读到**，不是站方的决定，所以这里
记成 ``unreadable``，**不许**记成 ``blocked_all``。（``robots_disallowed`` 那条「你的
robots.txt 禁止抓」在这种情形下对站点是假话，别在这里复制同一个错。）
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Literal

from geo_audit.models import RobotsInfo

__all__ = [
    "CRAWLERS",
    "Access",
    "Crawler",
    "CrawlerAnswer",
    "HostCrawlerPolicy",
    "Role",
    "judge_hosts",
    "judge_path",
    "judge_robots_crawlers",
    "parse_robots",
]


class Role(str, Enum):
    TRAINING = "training"  # 采集内容用于训练下一代模型
    SEARCH = "search"  # 建「AI 搜索」的检索索引，拦了就进不了它的库
    USER_FETCH = "user_fetch"  # 有人在对话里点名某页面时实时去抓


@dataclass(frozen=True, slots=True)
class Crawler:
    token: str  # robots.txt 里 User-agent 写的产品 token
    operator: str
    role: Role


#: 刻意只收**厂商自己文档写明了 token 与用途**的几个，不求全。
#: ``Google-Extended`` 严格说是「控制 token」而不是 UA（Google 用现有爬虫去抓，
#: 只是按这个 token 决定能不能拿去训练），但对 robots.txt 的写法来说它就是一个组名。
CRAWLERS: tuple[Crawler, ...] = (
    Crawler("GPTBot", "OpenAI", Role.TRAINING),
    Crawler("OAI-SearchBot", "OpenAI", Role.SEARCH),
    Crawler("ChatGPT-User", "OpenAI", Role.USER_FETCH),
    Crawler("ClaudeBot", "Anthropic", Role.TRAINING),
    Crawler("anthropic-ai", "Anthropic", Role.TRAINING),  # 旧 token，仍常见于存量 robots.txt
    Crawler("Claude-SearchBot", "Anthropic", Role.SEARCH),
    Crawler("Claude-User", "Anthropic", Role.USER_FETCH),
    Crawler("PerplexityBot", "Perplexity", Role.SEARCH),
    Crawler("Perplexity-User", "Perplexity", Role.USER_FETCH),
    Crawler("Google-Extended", "Google", Role.TRAINING),
    Crawler("Applebot-Extended", "Apple", Role.TRAINING),
    Crawler("CCBot", "Common Crawl", Role.TRAINING),
    Crawler("Bytespider", "ByteDance", Role.TRAINING),
    Crawler("meta-externalagent", "Meta", Role.TRAINING),
)


class Access(str, Enum):
    ALLOWED = "allowed"  # 没有任何对它生效的禁止规则
    PARTIAL = "partial"  # 有禁止规则，但根路径放行；或根路径禁止、但有 Allow 重新开了口子
    BLOCKED_ALL = "blocked_all"  # 根路径被禁止，且没有任何 Allow 能重新开口 —— 全站不许
    UNREADABLE = "unreadable"  # robots.txt 5xx / 网络错误：我们没读到，不是站方的决定


Matched = Literal["specific", "wildcard", "none", "no_robots_txt", "unreadable"]


@dataclass(frozen=True, slots=True)
class CrawlerAnswer:
    crawler: Crawler
    access: Access
    #: 是哪一组规则决定了它：
    #:   specific       有写它名字的组
    #:   wildcard       没有自己的组，落到 ``User-agent: *``
    #:   none           没有它的组，也没有 ``*`` 组 → 没有规则约束它
    #:   no_robots_txt  站点没有 robots.txt（4xx）
    #:   unreadable     没读到
    matched: Matched
    #: 决定性的规则行原文，如 ``Disallow: /``；没有就是空串。给人对着 robots.txt 核对用。
    deciding_rule: str = ""


@dataclass(frozen=True, slots=True)
class HostCrawlerPolicy:
    host: str
    answers: tuple[CrawlerAnswer, ...]
    #: robots.txt 本身的状态，原样来自 ``RobotsInfo.policy``。
    policy: Literal["parsed", "allow_all", "disallow_all"]

    def by_role(self, role: Role) -> tuple[CrawlerAnswer, ...]:
        return tuple(a for a in self.answers if a.crawler.role is role)

    def blocked(self, role: Role) -> tuple[str, ...]:
        """该类里被全站禁止的爬虫 token。"""
        return tuple(a.crawler.token for a in self.by_role(role) if a.access is Access.BLOCKED_ALL)

    def search_blocked_by_wildcard(self) -> tuple[str, ...]:
        """检索类里「自己没有组、被 ``*`` 组全站禁止」的爬虫。

        这是最容易被读漏的一种：robots.txt 里没出现它的名字，它照样进不来。
        """
        return tuple(
            a.crawler.token
            for a in self.by_role(Role.SEARCH)
            if a.access is Access.BLOCKED_ALL and a.matched == "wildcard"
        )


# --------------------------------------------------------------------------- #
# 解析
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _Rule:
    allow: bool
    pattern: str
    raw: str  # 规则行原文（去注释、去首尾空白后）

    def matches(self, path: str) -> bool:
        return _glob(self.pattern, path)


_RULE_LINE = re.compile(r"^\s*([A-Za-z-]+)\s*:\s*(.*?)\s*$")


def _glob(pattern: str, path: str) -> bool:
    """RFC 9309 路径匹配：``*`` 通配任意串，末尾 ``$`` 锚定。**线性、不回溯。**

    原来是把模式编成正则（``*`` → ``.*``）再 ``re.match``：多个 ``*`` 时回溯是
    路径长度的 n 次方（4 个 ``*a`` 对 300 字符的路径要 9 秒，5 个跑不完）。
    robots.txt 是**别人站点上的不受信文本**，这不能当成「极端输入」。
    做法：按 ``*`` 切段，首段必须是前缀，中间各段贪心 ``find``，末段在锚定时必须贴尾。
    """
    anchored = pattern.endswith("$")
    parts = (pattern[:-1] if anchored else pattern).split("*")
    first = parts[0]
    if not path.startswith(first):
        return False
    if len(parts) == 1:
        return path == first if anchored else True
    pos = len(first)
    for mid in parts[1:-1]:
        at = path.find(mid, pos)
        if at < 0:
            return False
        pos = at + len(mid)
    last = parts[-1]
    if anchored:
        return path.endswith(last) and len(path) - len(last) >= pos
    return path.find(last, pos) >= 0


def parse_robots(text: str) -> dict[str, list[_Rule]]:
    """返回 ``{小写产品 token: 规则列表}``；``*`` 作为键 ``"*"``。同名组合并。"""
    groups: dict[str, list[_Rule]] = {}
    current: list[str] = []  # 当前组的 agent 列表
    in_agents = False  # 上一行是不是 User-agent（连续的 UA 行共享一组）
    for line in re.split(r"\r\n|\r|\n", text.lstrip(chr(0xFEFF))):
        content = line.split("#", 1)[0]
        m = _RULE_LINE.match(content)
        if not m:
            continue
        field, value = m.group(1).lower(), m.group(2)
        if field == "user-agent":
            if not in_agents:
                current = []
            current.append(value.lower())
            groups.setdefault(value.lower(), [])
            in_agents = True
            continue
        if field not in ("allow", "disallow"):
            # Sitemap / Crawl-delay / 未知字段**不结束** User-agent 列表（Google 参考解析器
            # 同样）：``User-agent: A`` ``Crawl-delay: 5`` ``User-agent: B`` ``Disallow: /``
            # 里 A 和 B 是同一组。只有 Allow / Disallow（哪怕值为空）才结束它。
            continue
        in_agents = False
        if not current or not value:
            continue  # 无主规则 / 空规则
        rule = _Rule(allow=(field == "allow"), pattern=value, raw=f"{m.group(1)}: {value}")
        for agent in current:
            groups[agent].append(rule)
    return groups


def _decide(rules: Iterable[_Rule], path: str) -> _Rule | None:
    """最长匹配胜出，等长 Allow 胜。无命中返回 None（= 允许）。"""
    best: _Rule | None = None
    for rule in rules:
        if not rule.matches(path):
            continue
        if (
            best is None
            or len(rule.pattern) > len(best.pattern)
            or (len(rule.pattern) == len(best.pattern) and rule.allow and not best.allow)
        ):
            best = rule
    return best


#: 判「全站不许」时探的路径。只看根路径会把 ``Disallow: /$``（只禁根页面本身）读成全站禁止。
_BLOCK_PROBES = ("/", "/a", "/a/b/c")


def _classify(rules: list[_Rule]) -> tuple[Access, str]:
    disallows = [r for r in rules if not r.allow]
    if not disallows:
        return Access.ALLOWED, ""
    root = _decide(rules, "/")
    # 只放行 /robots.txt 的 Allow 不算「开了口子」：内容照样进不去。
    reopening = [r for r in rules if r.allow and r.pattern != "/robots.txt"]
    if (
        root is not None
        and not root.allow
        and not reopening
        and all((h := _decide(rules, p)) is not None and not h.allow for p in _BLOCK_PROBES)
    ):
        return Access.BLOCKED_ALL, root.raw
    if root is not None and not root.allow:
        return Access.PARTIAL, root.raw
    return Access.PARTIAL, disallows[0].raw


def judge_robots_crawlers(
    host: str,
    raw: str,
    policy: Literal["parsed", "allow_all", "disallow_all"],
    *,
    crawlers: tuple[Crawler, ...] = CRAWLERS,
) -> HostCrawlerPolicy:
    """一个 host 的 robots.txt 对每个爬虫的答案。入参就是 ``RobotsInfo`` 的三个字段。"""
    answers: list[CrawlerAnswer] = []
    groups = parse_robots(raw) if policy == "parsed" else {}
    for c in crawlers:
        if policy == "disallow_all":
            answers.append(CrawlerAnswer(c, Access.UNREADABLE, "unreadable"))
            continue
        if policy == "allow_all":
            answers.append(CrawlerAnswer(c, Access.ALLOWED, "no_robots_txt"))
            continue
        matched, rules = _select(groups, c.token)
        if matched == "none":
            answers.append(CrawlerAnswer(c, Access.ALLOWED, "none"))
            continue
        access, rule_raw = _classify(rules)
        answers.append(CrawlerAnswer(c, access, matched, rule_raw))
    return HostCrawlerPolicy(host=host, answers=tuple(answers), policy=policy)


def _select(groups: dict[str, list[_Rule]], token: str) -> tuple[Matched, list[_Rule]]:
    """RFC 9309 选组：有写它名字的组就只看那一组（哪怕它是空的），否则落到 ``*``。"""
    key = token.lower()
    if key in groups:
        return "specific", groups[key]
    if "*" in groups:
        return "wildcard", groups["*"]
    return "none", []


def judge_path(raw: str, token: str, path: str) -> bool:
    """这份 robots.txt 允不允许 ``token`` 抓 ``path``（只吃 ``parsed`` 的内容）。

    按 RFC 9309 选组、最长匹配、等长 Allow 胜。没有它的组也没有 ``*`` 组 → 允许。
    """
    _, rules = _select(parse_robots(raw), token)
    hit = _decide(rules, path)
    return hit is None or hit.allow


def judge_hosts(robots: Mapping[str, RobotsInfo]) -> dict[str, HostCrawlerPolicy]:
    """``SiteMap.robots``（``{host: RobotsInfo}``）整张表一次判完。"""
    return {h: judge_robots_crawlers(h, info.raw, info.policy) for h, info in robots.items()}
