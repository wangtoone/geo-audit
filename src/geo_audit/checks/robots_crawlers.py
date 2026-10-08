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
    "Honors",
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


Honors = Literal["yes", "no_by_design", "unstated"]


@dataclass(frozen=True, slots=True)
class Crawler:
    token: str  # robots.txt 里 User-agent 写的产品 token
    operator: str
    role: Role
    #: 厂商**自己的文档**怎么说它遵不遵守 robots.txt：
    #:   yes           文档承诺遵守；
    #:   no_by_design  文档写明可能不遵守（用户点名的实时抓取，如 OpenAI 的
    #:                 「robots.txt rules may not apply」）——被禁止了也可能照样来；
    #:   unstated      我们读到的官方文档没有明说（**不等于它不遵守**）。
    honors_robots: Honors = "unstated"
    doc: str = ""  # 厂商文档 URL；空 = 没找到可核对的官方文档
    #: 只是 robots.txt 里的「控制 token」：没有自己的 UA 字符串、不单独抓取，
    #: 厂商用现有爬虫去抓，再按这个 token 决定拿去做什么（Google-Extended、Applebot-Extended）。
    control_token: bool = False
    #: 没有写它名字的组时，厂商文档写明**先看哪个 token 的组**（如 Applebot → Googlebot），
    #: 再落到 ``*``。
    fallback: str = ""
    note: str = ""


_OPENAI = "https://platform.openai.com/docs/bots"
_ANTHROPIC = (
    "https://support.claude.com/en/articles/"
    "8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler"
)
_PERPLEXITY = "https://docs.perplexity.ai/guides/bots"
_GOOGLE = "https://developers.google.com/search/docs/crawling-indexing/google-common-crawlers"
_APPLE = "https://support.apple.com/en-us/119829"
_META = "https://developers.facebook.com/docs/sharing/webmasters/web-crawlers"
_AMAZON = "https://developer.amazon.com/amazonbot"
_BING = (
    "https://blogs.bing.com/webmaster/september-2020/"
    "Bing-Webmaster-Tools-makes-it-easy-to-edit-and-verify-your-robots-txt"
)

#: 刻意只收**厂商自己文档写明了 token 与用途**的几个，不求全；每条的 ``doc`` 是我们读过的页面。
#: 读过但文档没明说的（Bingbot、PerplexityBot 是否遵守 robots.txt）标 ``unstated``，
#: 不替厂商补一句；没找到官方文档的（CCBot、Bytespider、anthropic-ai）``doc`` 为空。
#: 文档日期：只有 Google（2025-12-10）和 Meta（2026-05-21）页面上有日期，其余请发布前复核。
CRAWLERS: tuple[Crawler, ...] = (
    # ── 训练 ──
    Crawler("GPTBot", "OpenAI", Role.TRAINING, "yes", _OPENAI),
    Crawler("ClaudeBot", "Anthropic", Role.TRAINING, "yes", _ANTHROPIC),
    Crawler(
        "anthropic-ai",
        "Anthropic",
        Role.TRAINING,
        note="旧 token：Anthropic 当前文档只列三个爬虫，已不含它；存量 robots.txt 里仍常见",
    ),
    Crawler(
        "Google-Extended",
        "Google",
        Role.TRAINING,
        "yes",
        _GOOGLE,
        control_token=True,
        note="控制标记，不是爬虫：管 Gemini 的训练与联网检索，不影响 Google 搜索",
    ),
    Crawler(
        "Applebot-Extended",
        "Apple",
        Role.TRAINING,
        "yes",
        _APPLE,
        control_token=True,
        note="控制标记，不单独抓取：只管训练，不影响 Applebot 的搜索",
    ),
    Crawler("CCBot", "Common Crawl", Role.TRAINING, note="官方文档我们没核"),
    Crawler("Bytespider", "ByteDance", Role.TRAINING, note="官方文档我们没核"),
    Crawler("meta-externalagent", "Meta", Role.TRAINING, "yes", _META),
    Crawler(
        "Amazonbot",
        "Amazon",
        Role.TRAINING,
        "yes",
        _AMAZON,
        note="用于改进 Amazon 的产品，可能用来训练 Amazon 的模型",
    ),
    # ── 检索（建 AI 搜索 / 联网回答借用的索引）──
    Crawler("OAI-SearchBot", "OpenAI", Role.SEARCH, "yes", _OPENAI),
    Crawler("Claude-SearchBot", "Anthropic", Role.SEARCH, "yes", _ANTHROPIC),
    Crawler(
        "PerplexityBot",
        "Perplexity",
        Role.SEARCH,
        doc=_PERPLEXITY,
        note="官方文档只建议放行它，没写它是否遵守 robots.txt",
    ),
    Crawler(
        "Googlebot",
        "Google",
        Role.SEARCH,
        "yes",
        _GOOGLE,
        note="Google 搜索，含 AI Overviews / AI Mode；Gemini 联网检索借用它的索引",
    ),
    Crawler(
        "Bingbot",
        "Microsoft",
        Role.SEARCH,
        doc=_BING,
        note="Copilot 与 ChatGPT 的联网检索借用 Bing 索引（Ahrefs 的说法，我们没核）；"
        "微软文档页我们读到的内容没有明说它是否遵守 robots.txt",
    ),
    Crawler(
        "Applebot",
        "Apple",
        Role.SEARCH,
        "yes",
        _APPLE,
        fallback="Googlebot",
        note="Spotlight / Siri / Safari 的搜索；没点名它时，Apple 文档说它按 Googlebot 的组走",
    ),
    Crawler("meta-webindexer", "Meta", Role.SEARCH, "yes", _META, note="Meta AI 的搜索"),
    Crawler(
        "Amzn-SearchBot",
        "Amazon",
        Role.SEARCH,
        "yes",
        _AMAZON,
        note="没写它名字但允许其他搜索爬虫时，官方说按给其他搜索爬虫的规则走（原话较含糊，"
        "本表只按 * 组判）",
    ),
    # ── 对话中的实时抓取（用户点名某个页面）──
    Crawler(
        "ChatGPT-User",
        "OpenAI",
        Role.USER_FETCH,
        "no_by_design",
        _OPENAI,
        note="官方：用户触发的动作，「robots.txt rules may not apply」",
    ),
    Crawler("Claude-User", "Anthropic", Role.USER_FETCH, "yes", _ANTHROPIC),
    Crawler(
        "Perplexity-User",
        "Perplexity",
        Role.USER_FETCH,
        "no_by_design",
        _PERPLEXITY,
        note="官方：「generally ignores robots.txt rules」",
    ),
    Crawler(
        "meta-externalfetcher",
        "Meta",
        Role.USER_FETCH,
        "no_by_design",
        _META,
        note="官方：「may bypass robots.txt rules」",
    ),
    Crawler(
        "Amzn-User",
        "Amazon",
        Role.USER_FETCH,
        "no_by_design",
        _AMAZON,
        note="官方：「may not follow all robots.txt directives」",
    ),
)


class Access(str, Enum):
    ALLOWED = "allowed"  # 没有任何对它生效的禁止规则
    PARTIAL = "partial"  # 有禁止规则，但根路径放行；或根路径禁止、但有 Allow 重新开了口子
    BLOCKED_ALL = "blocked_all"  # 根路径被禁止，且没有任何 Allow 能重新开口 —— 全站不许
    UNREADABLE = "unreadable"  # robots.txt 5xx / 网络错误：我们没读到，不是站方的决定


Matched = Literal["specific", "fallback", "wildcard", "none", "no_robots_txt", "unreadable"]


@dataclass(frozen=True, slots=True)
class CrawlerAnswer:
    crawler: Crawler
    access: Access
    #: 是哪一组规则决定了它：
    #:   specific       有写它名字的组
    #:   fallback       没有自己的组，按厂商文档指定的后备组走（``Crawler.fallback``）
    #:   wildcard       没有自己的组，落到 ``User-agent: *``
    #:   none           没有它的组，也没有 ``*`` 组 → 没有规则约束它
    #:   no_robots_txt  站点没有 robots.txt（**观察到的** 404 / 410，不是「读不到」）
    #:   unreadable     没读到（5xx / 网络错误 / 挑战页 / 限流 / 其余 4xx / replay 缺快照）
    matched: Matched
    #: 决定性的规则行原文，如 ``Disallow: /``；没有就是空串。给人对着 robots.txt 核对用。
    deciding_rule: str = ""


@dataclass(frozen=True, slots=True)
class HostCrawlerPolicy:
    host: str
    answers: tuple[CrawlerAnswer, ...]
    #: robots.txt 本身的状态，原样来自 ``RobotsInfo.policy``。
    policy: Literal["parsed", "allow_all", "disallow_all"]
    #: 来自 ``RobotsInfo.status`` / ``RobotsInfo.why``：判「站点没有」还是「我们没读到」靠它们。
    status: int | None = None
    why: str = ""

    @property
    def unreadable(self) -> bool:
        return bool(self.answers) and all(a.access is Access.UNREADABLE for a in self.answers)

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
    status: int | None = None,
    why: str = "",
) -> HostCrawlerPolicy:
    """一个 host 的 robots.txt 对每个爬虫的答案。入参就是 ``RobotsInfo`` 的字段。

    **「站点没有 robots.txt」与「我们没读到」要分开**（``status`` 就是为这个传的）：
    只有**观察到的** 404 / 410（以及没传 status 的老调用方）才是干净的缺席 → 放行；
    5xx / 网络错误 / 挑战页 / 429 / 跳转超限（policy ``disallow_all``），以及其余 4xx 与
    replay 缺快照（policy ``allow_all`` 但 status 不是 404/410/2xx），都是 UNREADABLE ——
    RFC 9309 对 4xx 的处理是「可以访问全部」，但防火墙 / 鉴权也会给 403，
    那不是站点说了「没有」。
    """
    answers: list[CrawlerAnswer] = []
    groups = parse_robots(raw) if policy == "parsed" else {}
    clean_absence = policy == "allow_all" and (status is None or status in (404, 410))
    unreadable = policy == "disallow_all" or (
        policy == "allow_all"
        and not clean_absence
        and not (status is not None and 200 <= status < 300)
    )
    for c in crawlers:
        if unreadable:
            answers.append(CrawlerAnswer(c, Access.UNREADABLE, "unreadable"))
            continue
        if policy == "allow_all":
            # 干净的缺席，或 2xx 但正文为空（有文件、没有任何规则）
            answers.append(
                CrawlerAnswer(c, Access.ALLOWED, "no_robots_txt" if clean_absence else "none")
            )
            continue
        matched, rules = _select(groups, c.token, c.fallback)
        if matched == "none":
            answers.append(CrawlerAnswer(c, Access.ALLOWED, "none"))
            continue
        access, rule_raw = _classify(rules)
        answers.append(CrawlerAnswer(c, access, matched, rule_raw))
    return HostCrawlerPolicy(
        host=host, answers=tuple(answers), policy=policy, status=status, why=why
    )


def _select(
    groups: dict[str, list[_Rule]], token: str, fallback: str = ""
) -> tuple[Matched, list[_Rule]]:
    """RFC 9309 选组：有写它名字的组就只看那一组（哪怕它是空的）；
    没有的话，先看厂商文档指定的后备组（如 Applebot → Googlebot），再落到 ``*``。"""
    key = token.lower()
    if key in groups:
        return "specific", groups[key]
    if fallback and fallback.lower() in groups:
        return "fallback", groups[fallback.lower()]
    if "*" in groups:
        return "wildcard", groups["*"]
    return "none", []


def judge_path(raw: str, token: str, path: str) -> bool:
    """这份 robots.txt 允不允许 ``token`` 抓 ``path``（只吃 ``parsed`` 的内容）。

    按 RFC 9309 选组、最长匹配、等长 Allow 胜。没有它的组也没有 ``*`` 组 → 允许。
    """
    fallback = next((c.fallback for c in CRAWLERS if c.token.lower() == token.lower()), "")
    _, rules = _select(parse_robots(raw), token, fallback)
    hit = _decide(rules, path)
    return hit is None or hit.allow


def judge_hosts(robots: Mapping[str, RobotsInfo]) -> dict[str, HostCrawlerPolicy]:
    """``SiteMap.robots``（``{host: RobotsInfo}``）整张表一次判完。"""
    return {
        h: judge_robots_crawlers(h, info.raw, info.policy, status=info.status, why=info.why)
        for h, info in robots.items()
    }
