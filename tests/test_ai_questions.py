"""L1 出题：ground truth 可溯源（A55）+ 三条可判定规则。

数据来源是**已提交的实录快照** `fixtures/snapshots/docs.mistral.ai/llms.txt`，
并且走真解析器 `parse_index_links` —— 不手拼 IndexLink。理由与
`test_soft404.py` 末尾那段一样：手拼等于拿「我编的输入」去断言，而 anchor
是不是站点原文正是 A55 要守的东西。
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from geo_audit.ai.questions import (
    MAX_QUESTIONS,
    build_questions,
    dead_link_facts,
)
from geo_audit.checks.ai_path import parse_index_links

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
INDEX_URL = "https://docs.mistral.ai/llms.txt"

needs_index = pytest.mark.skipif(
    not (FIXTURES / "index.json").exists(),
    reason="fixtures/index.json 不在（第 4b 步的实录快照）",
)


def _snapshot_body(url: str) -> str:
    entry = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))["snapshots"][url]
    return gzip.decompress((FIXTURES / (entry["path"] + ".body.gz")).read_bytes()).decode(
        "utf-8", "replace"
    )


def _report_from_index(body: str, *, domain: str = "mistral.ai") -> object:
    """把索引里的内链全当「已证实死」造一份最小 Report 替身。

    mistral 那份实测就是 **75 条内链 75 条死**，所以「全死」不是我编的极端情形，
    而是那份报告的真实结论。
    """
    findings = [
        SimpleNamespace(
            kind="index_link_dead",
            anchor_text=link.anchor_text,
            found_on=INDEX_URL,
            finding_id=f"f{i:03d}",
            target=SimpleNamespace(url=link.abs_url, curl_repro=f"curl -sSL '{link.abs_url}'"),
        )
        for i, link in enumerate(parse_index_links(body, INDEX_URL))
    ]
    return SimpleNamespace(domain=domain, findings=findings)


@needs_index
def test_index_snapshot_really_has_anchors() -> None:
    """前提：实录索引里 75 条内链都带 anchor。前提不成立的话下面全是空跑。"""
    body = _snapshot_body(INDEX_URL)
    links = parse_index_links(body, INDEX_URL)
    assert len(links) == 75, f"实录是 75 条内链，现在 {len(links)} 条 —— 快照变了？"
    without = [link.abs_url for link in links if not link.anchor_text]
    assert without == [], f"这些内链没有 anchor：{without[:5]}"


@needs_index
def test_a55_every_question_topic_is_verbatim_in_the_index() -> None:
    """A55：每条 decidable 问题的 ground truth 必须能在快照里逐字搜到。

    这里的 ground truth 有两半，两半都要能搜到：
      * ``topic``（索引给这条链接的标签）
      * ``known_dead_url``（索引里列的那条 URL）
    搜不到就说明它是我们加工出来的，不是站点原文 —— 那这道题的「正确答案」
    就是我们自己编的。
    """
    body = _snapshot_body(INDEX_URL)
    questions = build_questions(_report_from_index(body), index_body=body)
    assert questions, "一道题都没出，A55 会变成空跑"

    missing: list[str] = []
    for q in questions:
        if q.topic not in body:
            missing.append(f"topic {q.topic!r}")
        # URL 在索引里可能是相对写法，比对末段路径而不是整串
        tail = q.known_dead_url.split("://", 1)[-1].split("/", 1)[-1]
        if tail and tail not in body:
            missing.append(f"url tail {tail!r}")
    assert missing == [], "这些 ground truth 在索引快照里搜不到：\n  " + "\n  ".join(missing)


@needs_index
def test_questions_respect_the_cap_and_spread_across_paths() -> None:
    """上限生效，且不许 15 道题全挤在一个目录下。"""
    body = _snapshot_body(INDEX_URL)
    questions = build_questions(_report_from_index(body), index_body=body)
    assert len(questions) <= MAX_QUESTIONS

    from geo_audit.ai.questions import _path_family

    families = {_path_family(q.known_dead_url) for q in questions}
    assert len(families) >= 3, (
        f"{len(questions)} 道题只落在 {families} 这些路径族里 —— "
        "那测的是「模型知不知道这一批文档」，不是「模型会不会发死链」。"
    )


@needs_index
def test_generic_topics_are_dropped_not_asked() -> None:
    """'Overview' 这类笼统主题必须丢弃，而不是硬出题。"""
    body = _snapshot_body(INDEX_URL)
    report = _report_from_index(body)
    facts = dead_link_facts(report)
    assert facts, "取不到死链事实"

    # 掺一条笼统主题进去
    poisoned = SimpleNamespace(
        domain="mistral.ai",
        findings=[
            *report.findings,  # type: ignore[attr-defined]
            SimpleNamespace(
                kind="index_link_dead",
                anchor_text="Overview",
                found_on=INDEX_URL,
                finding_id="fgeneric",
                target=SimpleNamespace(
                    url="https://docs.mistral.ai/docs/overview.md", curl_repro="curl x"
                ),
            ),
        ],
    )
    questions = build_questions(poisoned, cap=99, index_body=body)
    assert "Overview" not in {q.topic for q in questions}, "笼统主题被出成了题"


def test_same_topic_two_urls_is_undecidable() -> None:
    """同一主题指向两条不同死 URL → 判不了模型答错没有 → 丢弃。"""
    report = SimpleNamespace(
        domain="x.invalid",
        findings=[
            SimpleNamespace(
                kind="index_link_dead",
                anchor_text="Webhooks",
                found_on="https://x.invalid/llms.txt",
                finding_id="a",
                target=SimpleNamespace(url="https://x.invalid/a/webhooks.md", curl_repro="c"),
            ),
            SimpleNamespace(
                kind="index_link_dead",
                anchor_text="Webhooks",
                found_on="https://x.invalid/llms.txt",
                finding_id="b",
                target=SimpleNamespace(url="https://x.invalid/b/webhooks.md", curl_repro="c"),
            ),
        ],
    )
    assert build_questions(report, cap=99) == ()


def test_only_index_link_dead_becomes_a_question() -> None:
    """普通站内死链不进 L1 探测集（见 dead_link_facts 的文档串）。"""
    report = SimpleNamespace(
        domain="x.invalid",
        findings=[
            SimpleNamespace(
                kind="dead_link",
                anchor_text="Pricing details",
                found_on="https://x.invalid/",
                finding_id="a",
                target=SimpleNamespace(url="https://x.invalid/pricing-old", curl_repro="c"),
            )
        ],
    )
    assert dead_link_facts(report) == ()
    assert build_questions(report, cap=99) == ()


# --------------------------------------------------------------------------- #
# 三条可判定规则在**真语料**上确实会触发
# --------------------------------------------------------------------------- #
#
# 为什么要这一条：mistral 那 75 条 anchor 一条都没被过滤掉，也就是说「笼统」与
# 「同名」两条规则在唯一那份端到端跑过的数据上从没生效 —— 只有合成测试证明过。
# 一条从不触发的规则会被下一个人当死代码删掉。
#
# 实测全部 50 份 200 且正文完整的 llms.txt、9787 条 anchor：
#     太短    1517 条
#     笼统      67 条（Overview 20 / Introduction 12 / Getting started 14 / …）
#     同名    1009 条（例：depot.dev 有两条都标 authentication）
# 断言用宽下界，语料变了不会误红，但规则被删掉一定会红。


@needs_index
def test_decidability_rules_fire_on_the_real_corpus() -> None:
    import collections
    import gzip

    from geo_audit.ai.questions import _MIN_TOPIC_CHARS, _TOO_GENERIC

    index = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))["snapshots"]
    files = {
        url: e
        for url, e in index.items()
        if url.endswith("llms.txt") and e["status"] == 200 and e["body_storage"] == "full"
    }
    assert len(files) >= 30, f"只有 {len(files)} 份可用索引，样本太小"

    short = generic = duplicate = total = 0
    for url, entry in files.items():
        body = gzip.decompress((FIXTURES / (entry["path"] + ".body.gz")).read_bytes()).decode(
            "utf-8", "replace"
        )
        anchors = [(link.anchor_text or "").strip() for link in parse_index_links(body, url)]
        total += len(anchors)
        for a in anchors:
            if len(a) < _MIN_TOPIC_CHARS:
                short += 1
            elif a.lower() in _TOO_GENERIC:
                generic += 1
        counts = collections.Counter(a.lower() for a in anchors if a)
        duplicate += sum(n for n in counts.values() if n > 1)

    assert total >= 5000, f"anchor 总数只有 {total}，语料被削过？"
    assert short >= 500, f"「太短」规则只命中 {short} 条 —— 规则被改松了？"
    assert generic >= 20, f"「笼统」规则只命中 {generic} 条 —— 规则被删了？"
    assert duplicate >= 100, f"「同名」规则只命中 {duplicate} 条 —— 规则被删了？"
