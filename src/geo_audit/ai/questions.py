"""出题：从 v1 已证实的事实反向生成问题。**零 LLM。**

## 为什么不抽「站点事实」

§11.1.2 的原设计是抽 `SiteFacts`（price / free_tier / capability / limit /
version / format）当 ground truth，再拿模型说的值去比。**实测做不出可靠的
ground truth。** 11 张价格页快照全读到了，但金额归不到套餐上：

    mistral.ai/pricing/  金额 ['0','1','5.99','10','14.99','15','24.99']
    modal.com/pricing    金额 ['0.00','0','0.09','3','3.95','10','30']

难的不是找数字，是把数字归到某个套餐上 —— 那页同时有按 token 计价和订阅档。
而 §11.1.2 自己的「封闭可判定」第三条就写着：值不许依赖未在问题里说明的限定
条件（套餐 / 地区 / 币种 / 周期）。这一条过不了，price 类问题就没有唯一
ground truth，出了题也判不了。

## 改用的口径：v1 已经带证据证实的死 URL

v1 对 `docs.mistral.ai/llms.txt` 的结论是 **75 条内链 75 条死**，每条都有
`curl_repro` 可复现。那就是精确的 ground truth，不需要再抽任何东西：

    问：Where can I find {domain} documentation about {topic}?
    模型答：https://docs.mistral.ai/docs/agents/agents_and_conversations.md
    v1 已证实：该 URL 死  →  模型正在把一个 404 交给你的客户

主题（`topic`）不是我编的，是**索引文件自己给这条链接的标签**：
`- [Agents & Conversations](https://…/agents_and_conversations.md): …`
实测 mistral 那份 75/75 条都带 anchor。这让 A55（ground truth 可溯源）成立 ——
主题与 URL 都能在索引快照里逐字搜到。

归因也因此是精确的而不是概率的：URL 恒等即命中，用不上 BM25 推测。
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

__all__ = [
    "MAX_QUESTIONS",
    "Question",
    "QuestionKind",
    "build_questions",
    "dead_link_facts",
]

#: B 口径只有一类问题：文档 URL。值比对那几类（price/limit/…）见模块文档串。
QuestionKind = Literal["doc_url"]

#: 硬上限。§11.1.6 的成本估算按 15 题 × 5 采样 = 75 次调用、单域 ≤ $0.50。
MAX_QUESTIONS = 15

#: 太笼统的主题不出题：问「X 关于 Overview 的文档在哪」没有唯一答案，
#: 模型给任何一页都算对，这题判不了。实测 mistral 的 75 条里命中
#: Introduction / Overview 各若干。
_TOO_GENERIC = frozenset(
    {
        "overview",
        "introduction",
        "intro",
        "docs",
        "documentation",
        "getting started",
        "guide",
        "guides",
        "reference",
        "api",
        "api reference",
        "home",
        "index",
        "faq",
        "changelog",
    }
)

#: 主题最短长度。'AI' 这种两字母缩写也能唯一，但 'a' 不能。
_MIN_TOPIC_CHARS = 3


@dataclass(frozen=True, slots=True)
class DeadLinkFact:
    """v1 已证实的一条死链。字段全部来自 Report，没有新观测。"""

    url: str
    topic: str  # 索引给它的 anchor 文本，逐字
    listed_on: str  # 列出它的索引 URL
    curl_repro: str  # v1 的复现命令
    finding_id: str


@dataclass(frozen=True, slots=True)
class Question:
    """一道给模型的题。``decidable=False`` 的不进探测集。"""

    qid: str
    kind: QuestionKind
    text: str  # 给模型看的问题（英文）
    topic: str  # 对账与溯源用，逐字来自索引
    known_dead_url: str  # v1 已证实死的那条 URL
    listed_on: str
    curl_repro: str
    decidable: bool
    undecidable_why: str = ""


def _qid(domain: str, kind: str, topic: str) -> str:
    raw = f"{domain}|{kind}|{topic.strip().lower()}"
    return hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def dead_link_facts(report: object) -> tuple[DeadLinkFact, ...]:
    """从 v1 的 Report 里取「索引内链已证实死」的事实。

    只收 ``kind == "index_link_dead"``：那是唯一一类「公开索引主动把这条 URL
    交给 LLM，而它是死的」的 finding —— 也就是模型最可能照着念的那批。
    站内普通死链（人点得到的）不进这里：模型不一定会给出那些 URL，
    出了题也多半判成 UNVERIFIABLE，白花钱。
    """
    out: list[DeadLinkFact] = []
    for finding in getattr(report, "findings", ()):
        if getattr(finding, "kind", "") != "index_link_dead":
            continue
        target = getattr(finding, "target", None)
        url = getattr(target, "url", "") if target is not None else ""
        if not url:
            continue
        out.append(
            DeadLinkFact(
                url=url,
                topic=(getattr(finding, "anchor_text", None) or "").strip(),
                listed_on=getattr(finding, "found_on", None) or "",
                curl_repro=getattr(target, "curl_repro", "") or "",
                finding_id=getattr(finding, "finding_id", "") or "",
            )
        )
    return tuple(out)


def _path_family(url: str) -> str:
    """URL 的前两段路径，用来把题分散开。

    不做这一步的话，mistral 的 15 道题会全落在 ``/docs/agents/`` 下面 ——
    那测的是「模型知不知道 agents 那批文档」，不是「模型会不会发死链」。
    """
    parts = [p for p in urlsplit(url).path.split("/") if p][:2]
    return "/".join(parts) or "/"


def build_questions(
    report: object,
    *,
    cap: int = MAX_QUESTIONS,
    index_body: str | None = None,
) -> tuple[Question, ...]:
    """从 v1 的 Report 生成封闭可判定的问题。

    三条判定规则，缺一即 ``decidable=False``（**丢弃而不是硬出题**）：

    1. **主题非空且不笼统**。'Overview' 这类词模型给任何一页都算对。
    2. **主题唯一**。同一主题指向两条不同的死 URL → 判不了「模型答错没有」。
    3. **主题可溯源**。传了 ``index_body`` 时，主题必须能在索引正文里逐字搜到
       —— 这是 A55 的判据。搜不到说明 anchor 是我们加工出来的，不是站点原文。

    出题上限与分散：按路径族轮转取，每族先取一条，再回头补第二条。
    """
    facts = dead_link_facts(report)
    domain = getattr(report, "domain", "") or ""

    by_topic: dict[str, list[DeadLinkFact]] = {}
    for fact in facts:
        by_topic.setdefault(fact.topic.lower(), []).append(fact)

    candidates: list[Question] = []
    for fact in facts:
        why = _undecidable_reason(fact, by_topic, index_body)
        candidates.append(
            Question(
                qid=_qid(domain, "doc_url", fact.topic),
                kind="doc_url",
                text=(
                    f"Where can I find the {domain} documentation page about "
                    f"{fact.topic}? Reply with the URL."
                ),
                topic=fact.topic,
                known_dead_url=fact.url,
                listed_on=fact.listed_on,
                curl_repro=fact.curl_repro,
                decidable=why == "",
                undecidable_why=why,
            )
        )

    decidable = [q for q in candidates if q.decidable]
    return tuple(_spread(decidable, cap=cap))


def _undecidable_reason(
    fact: DeadLinkFact,
    by_topic: dict[str, list[DeadLinkFact]],
    index_body: str | None,
) -> str:
    topic = fact.topic
    if len(topic) < _MIN_TOPIC_CHARS:
        return f"主题太短（{topic!r}），问不出唯一答案"
    if topic.lower() in _TOO_GENERIC:
        return f"主题太笼统（{topic!r}），模型给任何一页都算对"
    same = by_topic.get(topic.lower(), ())
    distinct = {f.url for f in same}
    if len(distinct) > 1:
        return f"同一主题指向 {len(distinct)} 条不同死 URL，判不了模型答错没有"
    if index_body is not None and topic not in index_body:
        return "主题在索引正文里搜不到（A55：ground truth 必须可溯源）"
    return ""


def _spread(questions: Sequence[Question], *, cap: int) -> Iterable[Question]:
    """按路径族轮转，避免 15 道题全挤在一个目录下。"""
    families: dict[str, list[Question]] = {}
    for q in questions:
        families.setdefault(_path_family(q.known_dead_url), []).append(q)
    order = sorted(families)
    picked: list[Question] = []
    depth = 0
    while len(picked) < cap:
        added = False
        for fam in order:
            bucket = families[fam]
            if depth < len(bucket):
                picked.append(bucket[depth])
                added = True
                if len(picked) >= cap:
                    break
        if not added:
            break
        depth += 1
    return picked
