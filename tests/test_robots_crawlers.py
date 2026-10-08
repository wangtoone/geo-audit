"""robots.txt 按爬虫分类判定：每条用例都对应一个会被读错的真实写法。

不碰网络。真实站点的 robots.txt 走 ``test_corpus_*``，读冻结快照。
"""

from __future__ import annotations

import pytest

from geo_audit.checks.robots_crawlers import (
    CRAWLERS,
    Access,
    Role,
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
# 组在根路径上答案不同。选组逻辑由上面的单元用例守（同一变异让 3 条红）。
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
    # 后备组只有 Apple 文档写明的这一条
    assert {t: c.fallback for t, c in by.items() if c.fallback} == {"Applebot": "Googlebot"}
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
    """PerplexityBot / Bingbot：官方文档我们读到的内容没有明说 —— 标 unstated，不替厂商补一句。"""
    by = {c.token: c for c in CRAWLERS}
    assert by["PerplexityBot"].honors_robots == "unstated"
    assert by["Bingbot"].honors_robots == "unstated"


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
