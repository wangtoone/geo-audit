"""模型回答的数据类型 + 回放层。**本模块零 LLM**（真发调用在 ai/probe.py）。

## 为什么回答也要走 fixture

v1 的每一条判定都能离线复现，靠的是 703 份实录 HTTP 快照。AI 层不该例外 ——
模型回答同样是**一次外部观测**：花钱、有时延、不可复现。所以这里用同一套架构：
录一次，永久重放。

这带来的直接好处是：**这一层真正值钱的部分（对账与归因）不需要 key 就能全测。**
对账逻辑是确定性的，它只关心「模型说了哪个 URL」，不关心那句话是谁生成的。

没有录过的问题在回放时**不静默跳过**：抛 ``AnswerMissing``，由调用方决定是
报「AI 层未运行」还是补录（A53）。这与 fixture 层「绝不静默回落真网络」是
同一条纪律。
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

__all__ = [
    "N_SAMPLES",
    "TEMPERATURE",
    "AnswerMissing",
    "AnswerStore",
    "ModelAnswer",
    "RetrievalMode",
]

#: 每题重采样次数。§11.1.3 定 5：少于 5 判不出 UNSTABLE（需要「≥2 个不同值」
#: 且多数票 ≥3），多于 5 只是线性加钱。
N_SAMPLES = 5

#: 固定 0。不是为了「更准」，是为了让「同一问题被讲成三个样」这个结论
#: 归因到检索差异，而不是归因到我们自己把温度调高了。
TEMPERATURE = 0.0

#: §11.1.3 的两种口径。选定后必须印在报告里。
RetrievalMode = str  # Literal["forced", "natural"]，避免 checks/ 侧的 import 依赖


class AnswerMissing(LookupError):  # noqa: N818 —— 与 fixtures.FixtureMissing 同一命名风格，刻意不加 Error 后缀
    """回放时这道题没有录过的回答。**不静默跳过。**"""


@dataclass(frozen=True, slots=True)
class ModelAnswer:
    """一次模型回答。字段全部是**观测**，不含任何判定。

    ``citations`` 只收结构化引用字段（OpenAI Responses API 的 ``url_citation``
    / Perplexity Sonar 的对应字段），**不解析回答正文里的链接** —— 模型会编
    URL，正文里的链接不是它「引用」的证据。正文里的 URL 由 checks/ 侧单独抽，
    那属于「模型说了什么」，与「模型看了什么」是两件事。
    """

    qid: str
    model: str  # 写死版本号，不许用 latest 别名
    sample_idx: int
    text: str
    citations: tuple[str, ...] = ()
    retrieval_used: bool = False
    cost_usd: float = 0.0
    probed_at: str = ""
    retrieval_mode: RetrievalMode = "forced"


@dataclass(frozen=True, slots=True)
class AnswerStore:
    """已录回答的回放层。按 ``qid`` 取。

    磁盘形态是一个 JSON：``{"model": ..., "answers": [ModelAnswer, ...]}``。
    刻意不按 URL 分文件 —— 回答集很小（15 题 × 5 采样），一个文件便于 review
    diff（「模型的说法变了」应当在 PR 里看得见）。
    """

    path: Path
    model: str = ""
    _by_qid: dict[str, tuple[ModelAnswer, ...]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | str) -> AnswerStore:
        p = Path(path)
        if not p.exists():
            return cls(path=p)
        raw = json.loads(p.read_text(encoding="utf-8"))
        by_qid: dict[str, list[ModelAnswer]] = {}
        for item in raw.get("answers", ()):
            answer = ModelAnswer(**item)
            by_qid.setdefault(answer.qid, []).append(answer)
        return cls(
            path=p,
            model=raw.get("model", ""),
            _by_qid={k: tuple(sorted(v, key=lambda a: a.sample_idx)) for k, v in by_qid.items()},
        )

    def has(self, qid: str) -> bool:
        return qid in self._by_qid

    def get(self, qid: str) -> tuple[ModelAnswer, ...]:
        try:
            return self._by_qid[qid]
        except KeyError as exc:
            raise AnswerMissing(
                f"没有录过 qid={qid} 的模型回答。回放模式绝不静默跳过 —— "
                f"要么补录（ai/probe.py --record），要么按 A53 在报告里印明「AI 层未运行」。"
            ) from exc

    @property
    def n_questions(self) -> int:
        return len(self._by_qid)

    def dump(self, answers: Sequence[ModelAnswer], *, model: str) -> None:
        """录制侧用。按 (qid, sample_idx) 排序落盘，保证 diff 稳定。"""
        payload = {
            "model": model,
            "answers": [asdict(a) for a in sorted(answers, key=lambda a: (a.qid, a.sample_idx))],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
