"""对账：模型说的 URL vs v1 已证实的死链。**零 LLM，确定性。**

这一层是 §11.0 那条架构原则落地的地方：LLM 只负责被问和回答，
**判定在这里，而这里没有 LLM**。函数签名里不许出现任何 client 类型（A54），
`tests/test_ai_boundary.py` 按 AST 与类型注解守着（A52 / A54）。

## 判据

一道题问「{domain} 关于 {topic} 的文档在哪」，模型回一个 URL。四种情形：

    CITES_DEAD     模型给的 URL 正是 v1 已证实死的那条 → **模型在把 404 交给你的客户**
    MATCH          模型给的 URL v1 测过且活
    UNVERIFIABLE   模型给的 URL 我们没测过 —— 老实说不知道，不额外发请求去查
    NO_URL         回答里没有 URL

外加一条横向判据：

    UNSTABLE       n 次采样里出现 ≥2 个不同 URL 且没有多数（≥3）

**UNSTABLE 是这一层最不需要争论的产出**：它不判谁对谁错，只指出「同一个问题
问 5 次，你的文档被指到 3 个不同地址」。

## 「引用」与「正文里出现」要分开

``citations`` 只收结构化引用字段；回答正文里的 URL 单独抽。两者的含义不同：

* ``cited``       —— 模型自己报告它检索到了这一页，属于检索分支，改站救得了；
* ``stated_only`` —— 只在正文里出现。可能来自参数记忆，而 §11.1.1 的作用域声明
  明写「模型凭训练记忆回答的部分，改站救不了，本工具也测不了」。

所以报告里这两类必须分开印。混在一起就是把「我们测得了的」和「我们测不了的」
算成同一个数。
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Literal

__all__ = [
    "MAJORITY_MIN",
    "EvidenceKind",
    "PerceptionFinding",
    "PerceptionStatus",
    "extract_urls",
    "normalise_for_compare",
    "reconcile",
]

#: n=5 里同一个 URL 出现 ≥3 次才算「模型的答案」。§11.1.4。
MAJORITY_MIN = 3

EvidenceKind = Literal["cited", "stated_only", "none"]


class PerceptionStatus(str, Enum):
    CITES_DEAD = "cites_dead"
    MATCH = "match"
    UNVERIFIABLE = "unverifiable"
    NO_URL = "no_url"
    UNSTABLE = "unstable"


#: 从回答正文里抽 URL。刻意不收尾部标点、右括号与 Markdown 强调符 ——
#: 模型爱把 URL 包在括号、句号或 `**` 里，连着抽会造出一条「带 ** 的 URL」，
#: 然后和死链集永远比不上。
#:
#: **`*` 这一条是真数据抓出来的，不是我想到的。** 第一版只排除了句读和右括号，
#: 实测 15 份回答里模型写的是
#:     **https://docs.mistral.ai/studio-api/agents/agents-api**
#: 于是同一条 URL 被拆成两个「不同 URL」：多数票从 5 稀释到 4、
#: n_distinct_urls 虚报成 2、而且带 ** 的串跟检索结果里的干净 URL 匹配不上，
#: 把 `cited` 误判成 `stated_only`。一个 bug 三个症状。
#: 也排除**全部控制字符**（\x00-\x1f、\x7f）。RFC 3986 本来就不许它们出现在
#: URI 里，而模型回答是自由文本、什么都可能带。实测：
#:     "See https://a.invalid/x\x1b[2J\x1b[He\x07vil"
#: 会被抽成一条带清屏转义序列与响铃的「URL」，而这串要进报告 HTML、
#: 也会被 scripts/l1_reconcile.py 原样打到终端 —— 终端转义序列可以清屏、
#: 改标题、伪造后续输出。
_URL_RE = re.compile(r"https?://[^\s<>\"'`)\]},*；。，\x00-\x1f\x7f]+")

#: 比对前要削掉的尾部字符（Markdown 链接与强调、句读）。
_TRAILING = ".,;:!?)]}'\"`>*_"


def extract_urls(text: str) -> tuple[str, ...]:
    """从自由文本里抽 URL，按出现顺序去重。"""
    seen: dict[str, None] = {}
    for raw in _URL_RE.findall(text or ""):
        url = raw.rstrip(_TRAILING)
        if url:
            seen.setdefault(url, None)
    return tuple(seen)


def normalise_for_compare(url: str) -> str:
    """比对用的归一形态。

    只做三件**无损**的事：小写 host、削尾部斜杠、去掉 fragment。
    刻意不动 query，也不动大小写路径 —— 路径大小写在多数服务器上是敏感的，
    归一过头会把两条不同的 URL 判成同一条，那是在制造假发现。
    """
    url = (url or "").strip().rstrip(_TRAILING)
    if not url:
        return ""
    url = url.split("#", 1)[0]
    scheme, _, rest = url.partition("://")
    if not rest:
        return url.rstrip("/")
    host, slash, tail = rest.partition("/")
    return f"{scheme.lower()}://{host.lower()}{slash}{tail}".rstrip("/")


@dataclass(frozen=True, slots=True)
class PerceptionFinding:
    """一道题的对账结果。全部是**绝对数**，不含百分比（A58：分母太小）。"""

    qid: str
    topic: str
    question_text: str
    status: PerceptionStatus
    evidence_kind: EvidenceKind

    model_url: str = ""  # 多数票选出的 URL（没有多数则为空）
    known_dead_url: str = ""  # v1 已证实死的那条
    curl_repro: str = ""  # v1 的复现命令，甲方可自查

    n_samples: int = 0
    n_with_url: int = 0
    n_distinct_urls: int = 0
    n_votes_for_model_url: int = 0
    n_cited: int = 0  # 结构化引用里出现该 URL 的次数
    distinct_urls: tuple[str, ...] = ()

    @property
    def is_hit(self) -> bool:
        """只有 CITES_DEAD 与 UNSTABLE 算发现。其余是「对」或「不知道」。"""
        return self.status in (PerceptionStatus.CITES_DEAD, PerceptionStatus.UNSTABLE)


def reconcile(
    question: object,
    answers: Sequence[object],
    *,
    dead_urls: frozenset[str],
    alive_urls: frozenset[str] = frozenset(),
) -> PerceptionFinding:
    """把模型断言与 v1 已证实的事实机械对账。

    ``question`` / ``answers`` 收的是**纯数据**（ai.questions.Question /
    ai.answers.ModelAnswer），不是 client —— A54 就是守这一条。
    这里刻意用 ``object`` 加 getattr 取字段，避免 checks/ 反向 import ai/
    造成判定层与 LLM 层的耦合。

    ``dead_urls`` / ``alive_urls`` 都传归一后的形态；本函数对模型给的 URL
    也走同一个 :func:`normalise_for_compare`，两边同一把尺子。
    """
    qid = str(getattr(question, "qid", ""))
    topic = str(getattr(question, "topic", ""))
    text = str(getattr(question, "text", ""))
    known_dead = str(getattr(question, "known_dead_url", ""))
    curl = str(getattr(question, "curl_repro", ""))

    per_sample: list[tuple[str, ...]] = []
    cited_norm: Counter[str] = Counter()
    for answer in answers:
        urls = extract_urls(str(getattr(answer, "text", "")))
        per_sample.append(tuple(normalise_for_compare(u) for u in urls if u))
        for c in getattr(answer, "citations", ()) or ():
            n = normalise_for_compare(str(c))
            if n:
                cited_norm[n] += 1

    n_samples = len(per_sample)
    #: 每次采样只取**第一个** URL 当「这次的答案」。理由：问的是「文档在哪」，
    #: 模型常先给正确入口再罗列一堆相关页；取全部会让多数票被噪声稀释。
    firsts = [urls[0] for urls in per_sample if urls]
    votes = Counter(firsts)
    distinct = tuple(sorted(votes))

    def _mk(
        status: PerceptionStatus,
        evidence_kind: EvidenceKind,
        *,
        model_url: str = "",
        n_votes: int = 0,
        n_cited: int = 0,
    ) -> PerceptionFinding:
        """显式构造。**刻意不用 dict 展开** —— mypy strict 下 ``**dict[str, object]``
        过不了，而为了让它过把 dict 标成 Any 就等于把这个 dataclass 的类型检查
        整个关掉。啰嗦一点换真检查。"""
        return PerceptionFinding(
            qid=qid,
            topic=topic,
            question_text=text,
            status=status,
            evidence_kind=evidence_kind,
            model_url=model_url,
            known_dead_url=known_dead,
            curl_repro=curl,
            n_samples=n_samples,
            n_with_url=len(firsts),
            n_distinct_urls=len(distinct),
            n_votes_for_model_url=n_votes,
            n_cited=n_cited,
            distinct_urls=distinct,
        )

    if not firsts:
        return _mk(PerceptionStatus.NO_URL, "none")

    top_url, top_n = votes.most_common(1)[0]
    if top_n < MAJORITY_MIN and len(distinct) > 1:
        # 没有多数且说法不一 —— 不去猜哪个是「模型的答案」。
        return _mk(
            PerceptionStatus.UNSTABLE,
            "cited" if cited_norm else "stated_only",
            n_votes=top_n,
            n_cited=sum(cited_norm.values()),
        )

    n_cited = cited_norm.get(top_url, 0)
    evidence: EvidenceKind = "cited" if n_cited else "stated_only"
    if top_url in dead_urls:
        status = PerceptionStatus.CITES_DEAD
    elif top_url in alive_urls:
        status = PerceptionStatus.MATCH
    else:
        status = PerceptionStatus.UNVERIFIABLE
    return _mk(status, evidence, model_url=top_url, n_votes=top_n, n_cited=n_cited)
