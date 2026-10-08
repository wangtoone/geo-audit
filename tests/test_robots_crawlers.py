"""robots.txt 按爬虫分类判定：每条用例都对应一个会被读错的真实写法。

不碰网络。真实站点的 robots.txt 走 ``test_corpus_*``，读冻结快照。
"""

from __future__ import annotations

import random
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from geo_audit.checks.robots_crawlers import (
    CRAWLERS,
    Access,
    Role,
    _Rule,  # 差分测试要和旧实现比对规则对象本身
    judge_hosts,
    judge_path,
    judge_robots_crawlers,
    parse_robots,
)
from geo_audit.models import RobotsInfo


def _answer(raw: str, token: str, policy: str = "parsed"):  # type: ignore[no-untyped-def]
    pol = judge_robots_crawlers("example.test", raw, policy)  # type: ignore[arg-type]
    return next(a for a in pol.answers if a.crawler.token == token)


# ── 「拦训练、放检索」是对的，且不能把检索爬虫误伤 ─────────────────────────
TRAIN_BLOCK_SEARCH_OPEN = """\
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: *
Allow: /
"""


def test_block_training_leave_search_open() -> None:
    pol = judge_robots_crawlers("example.test", TRAIN_BLOCK_SEARCH_OPEN, "parsed")
    assert set(pol.blocked(Role.TRAINING)) == {"GPTBot", "ClaudeBot"}
    assert pol.blocked(Role.SEARCH) == ()
    assert pol.blocked(Role.USER_FETCH) == ()
    assert _answer(TRAIN_BLOCK_SEARCH_OPEN, "OAI-SearchBot").matched == "wildcard"


# ── 最常见的事故：检索爬虫自己没有组，被 * 组全站禁止 ───────────────────────
def test_search_bot_blocked_only_through_wildcard_group() -> None:
    raw = "User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow: /\n"
    pol = judge_robots_crawlers("example.test", raw, "parsed")
    a = _answer(raw, "OAI-SearchBot")
    assert a.access is Access.BLOCKED_ALL
    assert a.matched == "wildcard"  # robots.txt 里没出现它的名字，它照样进不来
    assert a.deciding_rule == "Disallow: /"
    assert "OAI-SearchBot" in pol.search_blocked_by_wildcard()
    # 写了名字的 GPTBot 是 specific，不应出现在「被通配拦住」里
    assert _answer(raw, "GPTBot").matched == "specific"


def test_specific_group_overrides_wildcard() -> None:
    raw = "User-agent: *\nDisallow: /\n\nUser-agent: OAI-SearchBot\nAllow: /\n"
    a = _answer(raw, "OAI-SearchBot")
    assert a.access is Access.ALLOWED
    assert a.matched == "specific"
    # 别的爬虫仍落到 *，被拦
    assert _answer(raw, "GPTBot").access is Access.BLOCKED_ALL


# ── RFC 9309 解析细节 ───────────────────────────────────────────────────
def test_token_match_is_case_insensitive_and_whole_string() -> None:
    assert _answer("User-agent: gptbot\nDisallow: /\n", "GPTBot").matched == "specific"
    # 整串相等，不是子串：GPTBot-Extra 不是 GPTBot
    raw = "User-agent: GPTBot-Extra\nDisallow: /\n"
    a = _answer(raw, "GPTBot")
    assert a.access is Access.ALLOWED
    assert a.matched == "none"


def test_consecutive_user_agent_lines_share_one_group() -> None:
    raw = "User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /\n"
    assert _answer(raw, "GPTBot").access is Access.BLOCKED_ALL
    assert _answer(raw, "ClaudeBot").access is Access.BLOCKED_ALL
    assert _answer(raw, "CCBot").access is Access.ALLOWED


def test_same_agent_in_two_groups_is_merged() -> None:
    raw = "User-agent: GPTBot\nDisallow: /a/\n\nUser-agent: GPTBot\nDisallow: /b/\n"
    rules = parse_robots(raw)["gptbot"]
    assert [r.pattern for r in rules] == ["/a/", "/b/"]


def test_empty_disallow_allows_everything() -> None:
    a = _answer("User-agent: GPTBot\nDisallow:\n", "GPTBot")
    assert a.access is Access.ALLOWED


def test_longest_match_wins_and_allow_wins_ties() -> None:
    # 根被禁、但 /public/ 开了口 → partial，不是 blocked_all
    raw = "User-agent: GPTBot\nDisallow: /\nAllow: /public/\n"
    assert _answer(raw, "GPTBot").access is Access.PARTIAL
    # 等长：Allow 胜 → 根路径放行
    raw2 = "User-agent: GPTBot\nDisallow: /\nAllow: /\n"
    assert judge_path(raw2, "GPTBot", "/") is True
    assert _answer(raw2, "GPTBot").access is Access.PARTIAL  # 有禁止规则但根放行
    # 最长匹配：更长的 Disallow 压过较短的 Allow，反之亦然
    raw3 = "User-agent: GPTBot\nAllow: /docs/\nDisallow: /docs/private/\n"
    assert judge_path(raw3, "GPTBot", "/docs/a") is True
    assert judge_path(raw3, "GPTBot", "/docs/private/x") is False
    raw4 = "User-agent: GPTBot\nDisallow: /docs/\nAllow: /docs/public/\n"
    assert judge_path(raw4, "GPTBot", "/docs/public/x") is True
    assert judge_path(raw4, "GPTBot", "/docs/other") is False


def test_empty_specific_group_does_not_fall_back_to_wildcard() -> None:
    # 写了名字、但规则是空的 → 它自己的组说「全放行」，不许再去看 * 组
    raw = "User-agent: GPTBot\nDisallow:\n\nUser-agent: *\nDisallow: /\n"
    assert judge_path(raw, "GPTBot", "/") is True
    assert judge_path(raw, "CCBot", "/") is False
    assert _answer(raw, "GPTBot").matched == "specific"


def test_partial_when_only_private_paths_blocked() -> None:
    raw = "User-agent: *\nDisallow: /app/\nDisallow: /login\n"
    a = _answer(raw, "OAI-SearchBot")
    assert a.access is Access.PARTIAL
    assert a.matched == "wildcard"


def test_wildcard_and_end_anchor() -> None:
    raw = "User-agent: GPTBot\nDisallow: /*.pdf$\n"
    rules = parse_robots(raw)["gptbot"]
    assert rules[0].matches("/a/b.pdf")
    assert not rules[0].matches("/a/b.pdf?x=1")
    assert not rules[0].matches("/a/b.pdfx")
    # 它不禁根路径
    assert _answer(raw, "GPTBot").access is Access.PARTIAL


def test_comments_bom_crlf_and_orphan_rules() -> None:
    raw = (
        chr(0xFEFF)
        + "Disallow: /orphan\r\n# c\r\nUser-agent: GPTBot # inline\r\nDisallow: / # all\r\n"
    )
    assert _answer(raw, "GPTBot").access is Access.BLOCKED_ALL
    # 第一组之前的规则无主，不会漏给任何人
    assert _answer(raw, "CCBot").access is Access.ALLOWED


def test_non_rule_fields_do_not_create_rules() -> None:
    raw = "User-agent: *\nCrawl-delay: 10\nSitemap: https://x.test/s.xml\n"
    assert _answer(raw, "GPTBot").access is Access.ALLOWED


# ── 取不到 robots.txt：不许把「没读到」写成「站方禁止」───────────────────────
def test_unreachable_is_unreadable_never_blocked() -> None:
    a = _answer("", "OAI-SearchBot", policy="disallow_all")
    assert a.access is Access.UNREADABLE
    assert a.access is not Access.BLOCKED_ALL
    assert a.matched == "unreadable"


def test_no_robots_txt_is_allowed_and_says_so() -> None:
    a = _answer("", "GPTBot", policy="allow_all")
    assert a.access is Access.ALLOWED
    assert a.matched == "no_robots_txt"


def test_parsed_but_empty_file_means_no_group() -> None:
    a = _answer("", "GPTBot", policy="parsed")
    assert a.access is Access.ALLOWED
    assert a.matched == "none"


# ── 注册表与入口 ─────────────────────────────────────────────────────────
def test_registry_has_unique_tokens_and_all_three_roles() -> None:
    tokens = [c.token.lower() for c in CRAWLERS]
    assert len(tokens) == len(set(tokens))
    assert {c.role for c in CRAWLERS} == set(Role)
    # OpenAI 三个爬虫分工不同，三个 token 都得在
    openai = {c.token: c.role for c in CRAWLERS if c.operator == "OpenAI"}
    assert openai == {
        "GPTBot": Role.TRAINING,
        "OAI-SearchBot": Role.SEARCH,
        "ChatGPT-User": Role.USER_FETCH,
    }


def test_judge_hosts_maps_robotsinfo() -> None:
    info = RobotsInfo(
        host="a.test",
        fetched=True,
        status=200,
        crawl_delay=None,
        sitemaps=(),
        raw="User-agent: *\nDisallow: /\n",
        policy="parsed",
    )
    out = judge_hosts({"a.test": info})
    assert out["a.test"].search_blocked_by_wildcard() != ()


def test_judge_hosts_carries_readable_from_robotsinfo() -> None:
    """202 + 挑战头：抓取层 policy 是 allow_all（照常抓），readable 是 False。
    judge_hosts 若不把 readable 传下去，按状态码（2xx）会把它读成「读到了一份空文件」→ 放行。"""
    challenge = RobotsInfo(
        host="a.test",
        fetched=True,
        status=202,
        crawl_delay=None,
        sitemaps=(),
        raw="",
        policy="allow_all",
        why="响应头 x-amzn-waf-action: challenge（HTTP 202）：防火墙下发的是挑战页",
        readable=False,
    )
    out = judge_hosts({"a.test": challenge})["a.test"]
    assert out.unreadable and {a.access for a in out.answers} == {Access.UNREADABLE}
    assert "x-amzn-waf-action" in out.why


# ── 真实快照：和标准库 robotparser 在「根路径」上必须一致 ─────────────────────
#
# 为什么拿标准库当对照：它是别人写的、独立的实现；两者在「根路径放不放行」上若有
# 分歧，必有一个读错了真实世界的 robots.txt。（标准库是首条命中、不支持通配符，
# 所以只比根路径 —— 那是本模块 BLOCKED_ALL 的判据，不会被这两点绊到。）
#
# **它证明的是「在真实语料上两边读数一致」，不证明选组逻辑被覆盖**：变异实测
# （让 GPTBot 无视自己的组）这条仍然绿 —— 语料里没有哪个站的 GPTBot 专属组与 ``*``
# 组在根路径上答案不同。选组逻辑由上面的单元用例守（同一变异让多条单元用例红）。
def _robots_snapshots() -> list[tuple[str, str]]:
    from geo_audit.fixtures import FixtureStore

    store = FixtureStore.default()
    out: list[tuple[str, str]] = []
    for url in store.snapshots():
        if not url.endswith("/robots.txt"):
            continue
        snap = store.get(url)
        if not (200 <= snap.status < 300) or not snap.body_is_complete:
            continue
        out.append((url, store.stored_body(url).decode("utf-8", "replace")))
    return out


def test_corpus_root_decision_matches_stdlib_robotparser() -> None:
    import urllib.robotparser

    snaps = _robots_snapshots()
    assert len(snaps) >= 20, f"语料里只剩 {len(snaps)} 份 robots.txt，对照失去意义"
    disagreements: list[str] = []
    for url, body in snaps:
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(body.splitlines())
        for c in CRAWLERS:
            mine = judge_path(body, c.token, "/")
            std = rp.can_fetch(c.token, "/")
            if mine != std:
                disagreements.append(f"{url} {c.token}: mine={mine} stdlib={std}")
    assert disagreements == []


# ── 独立 review 查出并复现的四处缺陷（每条先在修复前复现过）───────────────────
def test_root_only_disallow_is_not_a_site_wide_block() -> None:
    # `/$` 只禁根页面本身；/about 照样能抓
    raw = "User-agent: *\nDisallow: /$\n"
    a = _answer(raw, "OAI-SearchBot")
    assert a.access is Access.PARTIAL
    assert judge_path(raw, "OAI-SearchBot", "/") is False
    assert judge_path(raw, "OAI-SearchBot", "/about") is True
    # 对照：真的全站禁止仍是 blocked_all，`/*` 也是
    assert _answer("User-agent: *\nDisallow: /\n", "GPTBot").access is Access.BLOCKED_ALL
    assert _answer("User-agent: *\nDisallow: /*\n", "GPTBot").access is Access.BLOCKED_ALL


def test_allow_robots_txt_alone_does_not_reopen_the_site() -> None:
    raw = "User-agent: *\nDisallow: /\nAllow: /robots.txt\n"
    assert _answer(raw, "GPTBot").access is Access.BLOCKED_ALL
    # 但 Allow 了真内容路径就不是了
    raw2 = "User-agent: *\nDisallow: /\nAllow: /docs/\n"
    assert _answer(raw2, "GPTBot").access is Access.PARTIAL


def test_non_rule_field_between_user_agents_does_not_split_the_group() -> None:
    raw = "User-agent: GPTBot\nCrawl-delay: 5\nUser-agent: ClaudeBot\nDisallow: /\n"
    assert _answer(raw, "GPTBot").access is Access.BLOCKED_ALL
    assert _answer(raw, "ClaudeBot").access is Access.BLOCKED_ALL
    raw2 = "User-agent: GPTBot\nSitemap: https://x.test/s.xml\nUser-agent: ClaudeBot\nDisallow: /\n"
    assert _answer(raw2, "GPTBot").access is Access.BLOCKED_ALL
    # 但 Allow / Disallow（哪怕值是空的）会结束 UA 列表
    raw3 = "User-agent: GPTBot\nDisallow:\nUser-agent: ClaudeBot\nDisallow: /\n"
    assert _answer(raw3, "GPTBot").access is Access.ALLOWED
    assert _answer(raw3, "ClaudeBot").access is Access.BLOCKED_ALL


def test_many_wildcards_do_not_backtrack_catastrophically() -> None:
    import time

    raw = "User-agent: *\nDisallow: /" + "*a" * 10 + "*b\n"
    started = time.monotonic()
    assert judge_path(raw, "GPTBot", "/" + "a" * 3000) is True  # 没有 b → 不匹配 → 允许
    assert time.monotonic() - started < 1.0


def test_unicode_line_separators_do_not_cut_rules() -> None:
    # str.splitlines 会在 \x85 / \x0b / \x0c 处断行，robots.txt 只认 CR / LF / CRLF
    raw = "User-agent: *\nDisallow: /a\x85Allow: /\n"
    assert judge_path(raw, "GPTBot", "/b") is True
    assert parse_robots(raw)["*"][0].pattern == "/a\x85Allow: /"


def test_glob_matcher_agrees_with_the_regex_it_replaced() -> None:
    """旧实现（``*``→``.*`` 的正则）当参照：小字母表上穷举，两边必须逐个一致。"""
    import itertools
    import re

    from geo_audit.checks.robots_crawlers import _glob

    def regex(pattern: str, path: str) -> bool:
        anchored = pattern.endswith("$")
        body = pattern[:-1] if anchored else pattern
        rx = ".*".join(re.escape(part) for part in body.split("*"))
        return re.compile(rx + ("$" if anchored else ""), re.DOTALL).match(path) is not None

    pat_alpha = "/ab*$"
    pats = {"".join(c) for n in range(1, 6) for c in itertools.product(pat_alpha, repeat=n)}
    paths = {"/" + "".join(c) for n in range(0, 6) for c in itertools.product("ab", repeat=n)}
    assert len(pats) > 500 and len(paths) > 50
    bad = [(p, q) for p in pats for q in paths if _glob(p, q) != regex(p, q)]
    assert bad[:5] == []


# ── 厂商元数据：每一条都能指到我们读过的官方文档原文 ─────────────────────────────────
def test_registry_vendor_facts() -> None:
    by = {c.token: c for c in CRAWLERS}
    # 官方文档写明「可能不遵守 robots.txt」的用户触发抓取（原文见各自 doc）
    no_by_design = {t for t, c in by.items() if c.honors_robots == "no_by_design"}
    assert no_by_design == {"ChatGPT-User", "Perplexity-User", "meta-externalfetcher", "Amzn-User"}
    assert by["Claude-User"].honors_robots == "yes"  # Anthropic 是例外：官方说 robots.txt 可控
    # 控制 token：没有自己的 UA、不单独抓取
    assert {t for t, c in by.items() if c.control_token} == {"Google-Extended", "Applebot-Extended"}
    # 后备组：Apple 文档写明的 Applebot → Googlebot，和 Bing 官方博客写明的 bingbot → msnbot → *
    assert {t: c.fallback for t, c in by.items() if c.fallback} == {
        "Applebot": "Googlebot",
        "Bingbot": "msnbot",
    }
    # 承诺或否认都必须能指到文档；没找到文档的只能是 unstated
    for c in CRAWLERS:
        if c.honors_robots != "unstated":
            assert c.doc.startswith("https://"), c.token
    # OpenAI 的三个爬虫分工（OAI-AdsBot 是广告落地页校验，不属于 AI 可见度，不收）
    assert {c.token: c.role for c in CRAWLERS if c.operator == "OpenAI"} == {
        "GPTBot": Role.TRAINING,
        "OAI-SearchBot": Role.SEARCH,
        "ChatGPT-User": Role.USER_FETCH,
    }
    # 联网检索借用的两个主流索引
    assert by["Googlebot"].role is Role.SEARCH and by["Bingbot"].role is Role.SEARCH


def test_unstated_is_not_the_same_as_does_not_honor() -> None:
    """PerplexityBot：官方文档只建议放行它，没写它是否遵守 robots.txt —— 标 unstated，不替厂商
    补一句。（Bingbot 原来也是 unstated，那是因为引的页面我们根本没读过；读了 Bing 官方博客后是
    yes。）"""
    by = {c.token: c for c in CRAWLERS}
    assert by["PerplexityBot"].honors_robots == "unstated"
    assert by["Bingbot"].honors_robots == "yes" and by["Bingbot"].fallback == "msnbot"


# ── 判定要区分「站点没有」与「我们没读到」───────────────────────────────────────────
#
# ``policy`` 是抓取层怎么做（RFC 9309），``readable`` 是我们知道多少 —— 这张表只认 ``readable``。
# 关键行是 ("allow_all", 202, False)：防火墙挑战页，抓取照常进行（没有可执行的规则），
# 但它不是「站点没有 robots.txt」。
@pytest.mark.parametrize(
    ("policy", "status", "readable", "access", "matched"),
    [
        ("allow_all", 404, True, Access.ALLOWED, "no_robots_txt"),  # 观察到的缺席
        ("allow_all", 410, True, Access.ALLOWED, "no_robots_txt"),
        ("allow_all", 200, True, Access.ALLOWED, "none"),  # 有文件、正文为空
        ("allow_all", 403, False, Access.UNREADABLE, "unreadable"),  # RFC 放行，但不是「没有」
        ("allow_all", 401, False, Access.UNREADABLE, "unreadable"),
        ("allow_all", 202, False, Access.UNREADABLE, "unreadable"),  # 防火墙挑战页：状态码看不出
        ("allow_all", 429, False, Access.UNREADABLE, "unreadable"),  # 限流，没读到
        ("allow_all", 599, False, Access.UNREADABLE, "unreadable"),  # replay 缺快照
        ("allow_all", 404, False, Access.UNREADABLE, "unreadable"),  # readable 说了算，不看状态码
        ("disallow_all", 503, False, Access.UNREADABLE, "unreadable"),
        ("disallow_all", 0, False, Access.UNREADABLE, "unreadable"),  # 网络错误
        ("disallow_all", 200, True, Access.UNREADABLE, "unreadable"),  # 自相矛盾的输入也不放行
    ],
)
def test_absence_versus_unreadable(
    policy: str, status: int, readable: bool, access: Access, matched: str
) -> None:
    pol = judge_robots_crawlers(
        "h.test",
        "",
        policy,  # type: ignore[arg-type]
        status=status,
        readable=readable,
    )
    assert {(a.access, a.matched) for a in pol.answers} == {(access, matched)}
    assert pol.unreadable is (access is Access.UNREADABLE)


@pytest.mark.parametrize(
    ("policy", "status", "access", "matched"),
    [
        ("allow_all", None, Access.ALLOWED, "no_robots_txt"),  # 没传 status：老调用方
        ("allow_all", 404, Access.ALLOWED, "no_robots_txt"),
        ("allow_all", 200, Access.ALLOWED, "none"),
        ("allow_all", 403, Access.UNREADABLE, "unreadable"),
        ("allow_all", 599, Access.UNREADABLE, "unreadable"),
        ("disallow_all", 503, Access.UNREADABLE, "unreadable"),
    ],
)
def test_without_readable_the_status_decides(
    policy: str, status: int | None, access: Access, matched: str
) -> None:
    """直接调用、手里没有 RobotsInfo（``readable=None``）：退回按 policy / status 推断。"""
    pol = judge_robots_crawlers("h.test", "", policy, status=status)  # type: ignore[arg-type]
    assert {(a.access, a.matched) for a in pol.answers} == {(access, matched)}


# ── Applebot 的后备组（Apple 文档：没点名它但点名了 Googlebot，就按 Googlebot 的组走）───────
def test_applebot_falls_back_to_the_googlebot_group_then_wildcard() -> None:
    googlebot_only = "User-agent: Googlebot\nDisallow: /\n"
    a = _answer(googlebot_only, "Applebot")
    assert (a.access, a.matched) == (Access.BLOCKED_ALL, "fallback")
    # 有它自己的组 → 只看自己的组
    own = "User-agent: Googlebot\nDisallow: /\n\nUser-agent: Applebot\nAllow: /\n"
    assert _answer(own, "Applebot").matched == "specific"
    assert _answer(own, "Applebot").access is Access.ALLOWED
    # 没有 Googlebot 的组 → 落到 *
    star = "User-agent: *\nDisallow: /private\n"
    assert _answer(star, "Applebot").matched == "wildcard"
    # 别的爬虫没有这个后备
    assert _answer(googlebot_only, "OAI-SearchBot").matched == "none"
    # judge_path 与 judge_robots_crawlers 用同一套选组
    assert judge_path(googlebot_only, "Applebot", "/x") is False
    assert judge_path(googlebot_only, "OAI-SearchBot", "/x") is True


# ══ 独立 review（PR-3）补的 ═════════════════════════════════════════════════════════════════
#
# 评审对本模块做了 66 个源码变异（50 咬住、16 存活）和 154 个注册表数据变异（64 存活）。下面每组
# 测试对应一批存活的变异；每个缺陷都先在修复前复现过。


# ── 选组：厂商后备组先于 *；组名不是子串匹配 ─────────────────────────────────────────
def test_vendor_fallback_group_comes_before_the_wildcard_group() -> None:
    """变异「先看 * 再看后备组」原来整套件全绿：没有测试同时给出 * 组和 Googlebot 组。"""
    raw = "User-agent: Googlebot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"
    a = _answer(raw, "Applebot")
    assert (a.access, a.matched) == (Access.BLOCKED_ALL, "fallback")


def test_a_group_name_that_merely_contains_the_token_does_not_hijack_it() -> None:
    """标准库的 RobotFileParser 按子串认组名：``User-agent: claude`` 会被 ClaudeBot 当成自己的组。
    RFC 9309 是整串相等。"""
    raw = "User-agent: claude\nDisallow: /\n\nUser-agent: gpt\nDisallow: /\n"
    for token in ("ClaudeBot", "GPTBot"):
        a = _answer(raw, token)
        assert (a.access, a.matched) == (Access.ALLOWED, "none"), token


def test_bingbot_follows_bingbot_then_msnbot_then_wildcard() -> None:
    """Bing 官方博客（2012-05-03）：只认一组，顺序 bingbot → msnbot（向后兼容）→ *；有 bingbot 组
    就无视文件里其余所有规则。"""
    only_msn = "User-agent: msnbot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"
    assert (_answer(only_msn, "Bingbot").access, _answer(only_msn, "Bingbot").matched) == (
        Access.BLOCKED_ALL,
        "fallback",
    )
    both = "User-agent: bingbot\nAllow: /\n\nUser-agent: msnbot\nDisallow: /\n"
    assert (_answer(both, "Bingbot").access, _answer(both, "Bingbot").matched) == (
        Access.ALLOWED,
        "specific",
    )
    star = "User-agent: *\nDisallow: /\n"
    assert (_answer(star, "Bingbot").access, _answer(star, "Bingbot").matched) == (
        Access.BLOCKED_ALL,
        "wildcard",
    )
    own_group_ignores_the_rest = (
        "User-agent: *\nDisallow: /private\n\nUser-agent: bingbot\nDisallow: /drafts\n"
    )
    assert judge_path(own_group_ignores_the_rest, "Bingbot", "/private/x") is True
    assert judge_path(own_group_ignores_the_rest, "Bingbot", "/drafts/x") is False


# ── 最长匹配 / 等长 Allow 胜：两种书写顺序都要对 ───────────────────────────────────────
def test_equal_length_allow_wins_in_either_order() -> None:
    """变异「等长时后一条胜」原来全绿：只测了 Disallow 在前、Allow 在后这一种顺序。"""
    for raw in (
        "User-agent: GPTBot\nDisallow: /x\nAllow: /x\n",
        "User-agent: GPTBot\nAllow: /x\nDisallow: /x\n",
        "User-agent: GPTBot\nAllow: /x\nDisallow: /x\nDisallow: /x\n",
    ):
        assert judge_path(raw, "GPTBot", "/x") is True, raw


def test_partial_names_the_rule_that_decided_it() -> None:
    a = _answer("User-agent: *\nDisallow: /private\n", "GPTBot")
    assert (a.access, a.deciding_rule) == (Access.PARTIAL, "Disallow: /private")


# ── 「全站禁止」不能靠三个采样路径断言 ─────────────────────────────────────────────────
def test_root_blocked_but_other_paths_open_is_partial() -> None:
    """评审复现：``Disallow: /$`` + ``Disallow: /a``：原来的三个探针路径（``/``、``/a``、
    ``/a/b/c``）恰好全被堵住 → 「全站禁止」，而 /pricing 其实放行。"""
    raw = "User-agent: *\nDisallow: /$\nDisallow: /a\n"
    assert judge_path(raw, "GPTBot", "/pricing") is True
    assert _answer(raw, "GPTBot").access is Access.PARTIAL


@pytest.mark.parametrize("own", ["/robots.txt", "/robots.txt$"])
def test_allowing_only_robots_txt_itself_does_not_reopen_the_site(own: str) -> None:
    """评审复现：``Allow: /robots.txt$`` 原来被当成「开了口子」→ 「部分路径禁止」，
    而每条内容路径都进不去。"""
    raw = f"User-agent: *\nDisallow: /\nAllow: {own}\n"
    assert judge_path(raw, "GPTBot", "/pricing") is False
    assert _answer(raw, "GPTBot").access is Access.BLOCKED_ALL


def test_a_real_opening_or_a_wildcard_block_is_classified_correctly() -> None:
    assert _answer("User-agent: *\nDisallow: /\nAllow: /public/\n", "GPTBot").access is (
        Access.PARTIAL
    )
    assert _answer("User-agent: *\nDisallow: /*\n", "GPTBot").access is Access.BLOCKED_ALL


# ── Amzn-SearchBot：厂商文档说没点名它但放行了别的搜索爬虫时，它按那些爬虫的规则走 ────────────
def _amzn(raw: str):  # type: ignore[no-untyped-def]
    pol = judge_robots_crawlers("h.test", raw, "parsed")
    return pol, next(a for a in pol.answers if a.crawler.token == "Amzn-SearchBot")


def test_amzn_searchbot_row_carries_the_vendor_caveat_when_other_search_bots_are_named() -> None:
    pol, a = _amzn("User-agent: Googlebot\nAllow: /\n\nUser-agent: *\nDisallow: /\n")
    assert (a.access, a.matched) == (Access.BLOCKED_ALL, "wildcard")
    assert "Amazon 文档" in a.caveat
    assert "Amzn-SearchBot" not in pol.search_blocked_by_wildcard()
    assert "OAI-SearchBot" in pol.search_blocked_by_wildcard()  # 没有提醒的照旧报


def test_amzn_searchbot_has_no_caveat_when_nobody_else_is_named_or_it_has_its_own_group() -> None:
    pol, a = _amzn("User-agent: *\nDisallow: /\n")
    assert a.caveat == "" and "Amzn-SearchBot" in pol.search_blocked_by_wildcard()
    _, own = _amzn("User-agent: Amzn-SearchBot\nDisallow: /\n\nUser-agent: Googlebot\nAllow: /\n")
    assert (own.matched, own.caveat) == ("specific", "")


def test_amzn_caveat_only_counts_other_search_bots_not_training_crawlers() -> None:
    """Amazon 的原话是「放行了别的**搜索**爬虫」：只点名了训练爬虫（GPTBot）时，没有任何搜索爬虫的
    规则可以让它去跟，caveat 不该出现，它照常落到 * 组、照常出现在「被通配拦住」的提醒里。"""
    pol, a = _amzn("User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow: /\n")
    assert a.caveat == "" and "Amzn-SearchBot" in pol.search_blocked_by_wildcard()


# ── 状态码一路传到判定表（RobotsInfo → judge_hosts） ─────────────────────────────────────
def test_judge_hosts_does_not_call_a_200_empty_file_a_missing_robots_txt() -> None:
    info = RobotsInfo(
        host="a.test",
        fetched=True,
        status=200,
        crawl_delay=None,
        sitemaps=(),
        raw="",
        policy="allow_all",
        readable=True,
    )
    answers = judge_hosts({"a.test": info})["a.test"].answers
    assert {a.matched for a in answers} == {"none"}  # 不是 no_robots_txt


# ── 注册表：每个字段逐条钉住 ─────────────────────────────────────────────────────────────
#
# 评审的 154 个数据变异里 64 个存活（11 条 honors_robots yes→unstated、21 条 doc 换成别家的、
# 16 条 role 翻转 …）。这张表是「我们读到的厂商文档」的副本：改它之前先去读那页文档，并把依据写在
# 旁边。doc 只钉 host（文档的路径会搬家，host 不会换成别的厂商）。
_T, _S, _U = Role.TRAINING, Role.SEARCH, Role.USER_FETCH
_EXPECTED_REGISTRY = {
    # token: (operator, role, honors_robots, doc host, control_token, fallback)
    "GPTBot": ("OpenAI", _T, "yes", "developers.openai.com", False, ""),
    "ClaudeBot": ("Anthropic", _T, "yes", "support.claude.com", False, ""),
    "anthropic-ai": ("Anthropic", _T, "unstated", "", False, ""),  # 当前文档只列三个爬虫
    "Google-Extended": ("Google", _T, "yes", "developers.google.com", True, ""),
    "Applebot-Extended": ("Apple", _T, "yes", "support.apple.com", True, ""),
    "CCBot": ("Common Crawl", _T, "unstated", "", False, ""),  # 官方文档我们没核
    "Bytespider": ("ByteDance", _T, "unstated", "", False, ""),  # 官方文档我们没核
    "meta-externalagent": ("Meta", _T, "yes", "developers.facebook.com", False, ""),
    "Amazonbot": ("Amazon", _T, "yes", "developer.amazon.com", False, ""),
    "OAI-SearchBot": ("OpenAI", _S, "yes", "developers.openai.com", False, ""),
    "Claude-SearchBot": ("Anthropic", _S, "yes", "support.claude.com", False, ""),
    "PerplexityBot": ("Perplexity", _S, "unstated", "docs.perplexity.ai", False, ""),
    "Googlebot": ("Google", _S, "yes", "developers.google.com", False, ""),
    "Bingbot": ("Microsoft", _S, "yes", "blogs.bing.com", False, "msnbot"),  # Bing 官方博客 2012
    "Applebot": ("Apple", _S, "yes", "support.apple.com", False, "Googlebot"),
    "meta-webindexer": ("Meta", _S, "yes", "developers.facebook.com", False, ""),
    "Amzn-SearchBot": ("Amazon", _S, "yes", "developer.amazon.com", False, ""),
    "ChatGPT-User": ("OpenAI", _U, "no_by_design", "developers.openai.com", False, ""),
    "Claude-User": ("Anthropic", _U, "yes", "support.claude.com", False, ""),
    "Perplexity-User": ("Perplexity", _U, "no_by_design", "docs.perplexity.ai", False, ""),
    "meta-externalfetcher": ("Meta", _U, "no_by_design", "developers.facebook.com", False, ""),
    "Amzn-User": ("Amazon", _U, "no_by_design", "developer.amazon.com", False, ""),
}


def test_every_registry_field_is_pinned() -> None:
    actual = {
        c.token: (
            c.operator,
            c.role,
            c.honors_robots,
            urlsplit(c.doc).hostname or "",
            c.control_token,
            c.fallback,
        )
        for c in CRAWLERS
    }
    assert actual == _EXPECTED_REGISTRY


def test_every_doc_is_https_and_registry_dates_are_not_invented() -> None:
    for c in CRAWLERS:
        assert c.doc == "" or c.doc.startswith("https://"), c.token
    import geo_audit.checks.robots_crawlers as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    # 评审：注释里写过「Google 2025-12-10」，而它读的那页（google-common-crawlers）标的是
    # 2026-07-14；
    # 2025-12-10 是另一页（ai-features），注册表没引。日期只写读到那一页时它自己标的。
    assert "2025-12-10" not in src


# ── 不受信文本：解析必须线性 ─────────────────────────────────────────────────────────────
#
# robots.txt 是别人站点上的文本，读上限现在是 512 KiB。``_RULE_LINE`` 原来是
# ``^\s*([A-Za-z-]+)\s*:\s*(.*?)\s*$``：值里有一长串尾随空白、后面又跟一个非空白字符时，惰性 ``.*?``
# 每前进一格就让 ``\s*$`` 把整串空白重扫一遍 —— 平方级（评审实测 16k 空白 0.52 s、64k 9.5 s、
# 128k 38 s；512 KiB 约 10 分钟）。
_OLD_RULE_LINE = re.compile(r"^\s*([A-Za-z-]+)\s*:\s*(.*?)\s*$")


def _old_parse_robots(text: str):  # type: ignore[no-untyped-def]
    """修复前的实现，原样保留作差分测试的对照（只有那条正则不同）。"""
    groups: dict[str, list[_Rule]] = {}
    current: list[str] = []
    in_agents = False
    for line in re.split(r"\r\n|\r|\n", text.lstrip(chr(0xFEFF))):
        content = line.split("#", 1)[0]
        m = _OLD_RULE_LINE.match(content)
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
            continue
        in_agents = False
        if not current or not value:
            continue
        rule = _Rule(allow=(field == "allow"), pattern=value, raw=f"{m.group(1)}: {value}")
        for agent in current:
            groups[agent].append(rule)
    return groups


_FIELDS = [
    "user-agent",
    "User-Agent",
    "allow",
    "Disallow",
    "sitemap",
    "crawl-delay",
    "x",
    "",
    "a-b",
]
_SEPS = [":", " :", ": ", " : ", "\t:\t", "::", "", ":\u00a0"]
_VALUES = [
    "*",
    "/",
    "/a",
    "/a/b",
    "/*.pdf$",
    "GPTBot",
    "gptbot",
    "/x y",
    "/x\ty",
    "/p?q=1",
    "  ",
    "",
]
_VALUES += ["/a#b", "#only", "/\u00a0x", "/x\u3000", "/x\u2003", "a" * 40, "\u00e9"]
_PRE = ["", " ", "\t", "\u00a0", "\u3000", "\ufeff", "  \t "]
_POST = ["", " ", "\t", "  \t ", "\u00a0", "\u3000", "\x0b", "\x0c", "\x1c", "\u2028", "\x85"]
_COMMENTS = ["", "", "", " # c", "#c", "\t#"]


def _fuzz_document(rng: random.Random) -> str:
    lines = []
    for _ in range(rng.randint(1, 40)):
        line = (
            rng.choice(_PRE)
            + rng.choice(_FIELDS)
            + rng.choice(_SEPS)
            + rng.choice(_VALUES)
            + rng.choice(_COMMENTS)
            + rng.choice(_POST)
        )
        lines.append(line)
    return rng.choice(["\n", "\r\n", "\r"]).join(lines)


def test_parse_robots_output_is_identical_to_the_pre_fix_implementation() -> None:
    """3000 篇随机文档（各种空白 / 分隔符 / 注释 / 行终止符 / Unicode 空白）+ 全部冻结的
    robots.txt：
    规则对象逐个相等。线性化不许改解析结果。"""
    rng = random.Random(20261008)
    for i in range(3000):
        doc = _fuzz_document(rng)
        assert parse_robots(doc) == _old_parse_robots(doc), (i, doc)
    snaps = _robots_snapshots()
    assert len(snaps) >= 20
    for url, body in snaps:
        assert parse_robots(body) == _old_parse_robots(body), url


@pytest.mark.parametrize(
    "make",
    [
        lambda n: "User-agent: *\nDisallow: /a" + " " * n + "b\n",  # 评审复现的那一行
        lambda n: ("Disallow: /a" + " " * 1000 + "b\n") * (n // 1000),
        lambda n: "User-agent:" + " " * n + "x\n",
        lambda n: "a" * n + "\n",
        lambda n: ":" * n + "\n",
        lambda n: "#" * n + "\n",
        lambda n: " " * n + "x\n",
        lambda n: "a" + " " * n + "\n",
        lambda n: "Disallow:" + "\t" * n + "/x" + "\t" * n + "y\n",
    ],
    ids=[
        "trailing-spaces",
        "many-lines",
        "ua-spaces",
        "letters",
        "colons",
        "hashes",
        "leading",
        "only-trail",
        "tabs",
    ],
)
def test_parsing_a_hostile_one_mebibyte_file_is_linear(make) -> None:  # type: ignore[no-untyped-def]
    # 先用小的探一下：平方级的实现在 50k 就要 ~6 s，不必等 1 MB 跑完（那要半小时）才红
    for n in (50_000, 1_000_000):
        doc = make(n)
        t = time.perf_counter()
        parse_robots(doc)
        elapsed = time.perf_counter() - t
        assert elapsed < 2.0, (
            f"n={n}: {elapsed:.1f}s（线性实现是毫秒级；平方级在 128 KiB 就要 38 s）"
        )


def test_judging_a_hostile_512_kib_file_end_to_end_is_fast() -> None:
    """整条路径（解析 + 22 个爬虫的判定）：同一组规则只判一次，大文件不会被乘以 22。"""
    raw = "User-agent: *\nDisallow: /\n" + "".join(f"Disallow: /p{i}/*x$\n" for i in range(20000))
    t = time.perf_counter()
    pol = judge_robots_crawlers("h.test", raw, "parsed")
    elapsed = time.perf_counter() - t
    assert elapsed < 5.0, f"{elapsed:.1f}s"
    assert {a.access for a in pol.answers} == {Access.BLOCKED_ALL}
