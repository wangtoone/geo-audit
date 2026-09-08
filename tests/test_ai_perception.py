"""L1 对账：五种判定 + 多数票 + 引用与正文的区分。

这一层是确定性的，所以测试也能是确定性的 —— 不需要任何 key。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from geo_audit.checks.ai_perception import (
    MAJORITY_MIN,
    PerceptionStatus,
    extract_urls,
    normalise_for_compare,
    reconcile,
)

DEAD = "https://docs.x.invalid/docs/agents/agents_and_conversations.md"
ALIVE = "https://docs.x.invalid/docs/agents/index.md"
UNSEEN = "https://docs.x.invalid/docs/somewhere/else.md"

DEAD_SET = frozenset({normalise_for_compare(DEAD)})
ALIVE_SET = frozenset({normalise_for_compare(ALIVE)})

QUESTION = SimpleNamespace(
    qid="q1",
    topic="Agents & Conversations",
    text="Where can I find the x.invalid documentation page about Agents & Conversations?",
    known_dead_url=DEAD,
    curl_repro=f"curl -sSL '{DEAD}'",
)


def _answers(*texts: str, citations: tuple[str, ...] = ()) -> list[object]:
    return [
        SimpleNamespace(text=t, citations=citations, retrieval_used=bool(citations)) for t in texts
    ]


def _rec(*texts: str, citations: tuple[str, ...] = ()) -> object:
    return reconcile(
        QUESTION, _answers(*texts, citations=citations), dead_urls=DEAD_SET, alive_urls=ALIVE_SET
    )


# --------------------------------------------------------------------------- #
# 抽取与归一
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("See https://a.invalid/x.md for details.", ("https://a.invalid/x.md",)),
        ("Try (https://a.invalid/x.md).", ("https://a.invalid/x.md",)),
        ("[docs](https://a.invalid/x.md)", ("https://a.invalid/x.md",)),
        ("链接是 https://a.invalid/x.md。", ("https://a.invalid/x.md",)),
        ("no url here", ()),
    ],
)
def test_extract_urls_strips_trailing_punctuation(text: str, expected: tuple[str, ...]) -> None:
    """模型爱把 URL 包在括号或句号里。连着抽会造出一条「带句号的 URL」，
    然后它和死链集永远比不上 —— 那会把 CITES_DEAD 静默降级成 UNVERIFIABLE。"""
    assert extract_urls(text) == expected


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("https://A.INVALID/x", "https://a.invalid/x"),
        ("https://a.invalid/x/", "https://a.invalid/x"),
        ("https://a.invalid/x#frag", "https://a.invalid/x"),
    ],
)
def test_normalise_is_lossless_on_host_slash_fragment(a: str, b: str) -> None:
    assert normalise_for_compare(a) == normalise_for_compare(b)


def test_normalise_keeps_path_case_and_query() -> None:
    """路径大小写与 query 不许归一 —— 多数服务器对它们敏感，
    归一过头会把两条不同 URL 判成同一条，那是在制造假发现。"""
    assert normalise_for_compare("https://a.invalid/X") != normalise_for_compare(
        "https://a.invalid/x"
    )
    assert normalise_for_compare("https://a.invalid/x?a=1") != normalise_for_compare(
        "https://a.invalid/x"
    )


# --------------------------------------------------------------------------- #
# 五种判定
# --------------------------------------------------------------------------- #


def test_cites_dead_is_the_money_finding() -> None:
    f = _rec(*[f"Use {DEAD}"] * 5)
    assert f.status is PerceptionStatus.CITES_DEAD
    assert f.is_hit
    assert f.model_url == normalise_for_compare(DEAD)
    assert f.n_votes_for_model_url == 5
    assert f.curl_repro.startswith("curl "), "必须带 v1 的复现命令，甲方要能自查"


def test_match_when_model_gives_a_url_we_measured_alive() -> None:
    f = _rec(*[f"See {ALIVE}"] * 5)
    assert f.status is PerceptionStatus.MATCH
    assert not f.is_hit


def test_unverifiable_when_we_never_measured_that_url() -> None:
    """没测过就说不知道 —— 不为了凑一个结论去补发请求。"""
    f = _rec(*[f"See {UNSEEN}"] * 5)
    assert f.status is PerceptionStatus.UNVERIFIABLE
    assert not f.is_hit


def test_no_url_when_the_model_gives_none() -> None:
    f = _rec("I don't have that information.", "Please contact support.")
    assert f.status is PerceptionStatus.NO_URL
    assert f.n_with_url == 0


def test_unstable_when_no_majority() -> None:
    """同一个问题问 5 次，文档被指到 3 个不同地址 —— 不判谁对谁错，只报不稳。"""
    f = _rec(f"a {DEAD}", f"b {ALIVE}", f"c {UNSEEN}", f"d {ALIVE}", f"e {UNSEEN}")
    assert f.status is PerceptionStatus.UNSTABLE
    assert f.is_hit
    assert f.n_distinct_urls == 3
    assert f.model_url == "", "没有多数就不许挑一个当「模型的答案」"


def test_majority_wins_even_with_dissent() -> None:
    f = _rec(*[f"x {DEAD}"] * MAJORITY_MIN, f"y {ALIVE}", f"z {UNSEEN}")
    assert f.status is PerceptionStatus.CITES_DEAD
    assert f.n_votes_for_model_url == MAJORITY_MIN
    assert f.n_distinct_urls == 3, "多数票选出答案，但不稳定程度仍要如实记下来"


def test_single_distinct_url_below_majority_is_not_unstable() -> None:
    """只有 2 次给了 URL、且都是同一条 —— 那是样本少，不是说法不一。"""
    f = _rec(f"x {DEAD}", f"y {DEAD}", "no idea", "ask support", "unknown")
    assert f.status is PerceptionStatus.CITES_DEAD
    assert f.n_distinct_urls == 1


def test_first_url_per_sample_is_the_answer() -> None:
    """问的是「文档在哪」，模型常先给入口再罗列一堆相关页。取全部会让多数票
    被噪声稀释，所以每次采样只取第一个 URL。"""
    noisy = f"Start at {DEAD}. Related: {ALIVE} and {UNSEEN}."
    f = _rec(*[noisy] * 5)
    assert f.status is PerceptionStatus.CITES_DEAD
    assert f.model_url == normalise_for_compare(DEAD)


# --------------------------------------------------------------------------- #
# 引用 vs 正文里出现
# --------------------------------------------------------------------------- #


def test_cited_and_stated_only_are_different_things() -> None:
    """``cited`` 是模型自己报告它检索到了这一页（检索分支，改站救得了）；
    ``stated_only`` 只在正文里出现，可能来自参数记忆 —— 而作用域声明明写
    那部分「改站救不了，本工具也测不了」。两类混在一起就是把「测得了的」
    和「测不了的」算成同一个数。"""
    stated = _rec(*[f"See {DEAD}"] * 5)
    assert stated.evidence_kind == "stated_only"
    assert stated.n_cited == 0

    cited = _rec(*[f"See {DEAD}"] * 5, citations=(DEAD,))
    assert cited.evidence_kind == "cited"
    assert cited.n_cited == 5


def test_citations_are_not_parsed_out_of_the_answer_text() -> None:
    """引用只收结构化字段。正文里出现 URL **不算**引用 —— 模型会编 URL。"""
    f = _rec(*[f"According to {DEAD} you can…"] * 5)
    assert f.n_cited == 0
    assert f.evidence_kind == "stated_only"


def test_finding_carries_absolute_numbers_only() -> None:
    """A58：这一层只报绝对数。分母是 5，百分比会骗人。"""
    f = _rec(*[f"x {DEAD}"] * 3, f"y {ALIVE}", "no idea")
    for name in ("n_samples", "n_with_url", "n_distinct_urls", "n_votes_for_model_url", "n_cited"):
        value = getattr(f, name)
        assert isinstance(value, int), f"{name} 不是整数：{value!r}"
    assert not any(isinstance(getattr(f, name), float) for name in f.__slots__), (
        "对账结果里出现了浮点数 —— 那通常意味着有人算了个比率"
    )


# --------------------------------------------------------------------------- #
# 真数据抓出来的：Markdown 强调符
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text",
    [
        "**https://a.invalid/x**",
        "Here it is:\n\n**https://a.invalid/x**\n\nThat's the page.",
        "见 __https://a.invalid/x__",
        "*https://a.invalid/x*",
    ],
)
def test_markdown_emphasis_is_stripped_from_urls(text: str) -> None:
    """第一版漏了 `*`，真数据一跑就露了。

    实测 15 份回答里模型写的是 ``**https://docs.mistral.ai/studio-api/agents/agents-api**``，
    于是同一条 URL 被拆成两个「不同 URL」：多数票从 5 稀释到 4、
    n_distinct_urls 虚报成 2、而且带 ** 的串跟检索结果里的干净 URL 匹配不上，
    把 cited 误判成 stated_only。**一个 bug 三个症状，全是静默的。**
    """
    assert extract_urls(text) == ("https://a.invalid/x",)


def test_emphasis_does_not_split_the_majority_vote() -> None:
    """同一条 URL 有的样本带 **、有的不带，必须算同一票。"""
    f = reconcile(
        QUESTION,
        _answers(f"**{DEAD}**", f"{DEAD}", f"see **{DEAD}**", f"{DEAD}.", f"**{DEAD}**"),
        dead_urls=DEAD_SET,
        alive_urls=ALIVE_SET,
    )
    assert f.n_distinct_urls == 1, f"同一条 URL 被拆成 {f.n_distinct_urls} 个：{f.distinct_urls}"
    assert f.n_votes_for_model_url == 5
    assert f.status is PerceptionStatus.CITES_DEAD


def test_emphasis_does_not_break_citation_matching() -> None:
    """正文里带 ** 的 URL 要能和结构化引用里的干净 URL 对上，否则 cited 变 stated_only。"""
    f = reconcile(
        QUESTION,
        _answers(*[f"**{DEAD}**"] * 5, citations=(DEAD,)),
        dead_urls=DEAD_SET,
        alive_urls=ALIVE_SET,
    )
    assert f.evidence_kind == "cited"
    assert f.n_cited == 5
