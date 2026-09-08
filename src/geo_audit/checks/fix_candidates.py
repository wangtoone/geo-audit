"""死链的修复候选：机械路径变换 + **我们自己验活**。零 LLM。

## 为什么这一层先做、且不需要 AI

实测 mistral 的 75 条死链，抽样 10 条套一条机械规则（`/docs/X.md` → `/X`），
**7 条直接 200**。也就是说这批死链的修复目标大部分推得出来，一个 LLM 都不用。

    ✓ 200  /agents/connectors/websearch          原 /docs/agents/connectors/websearch.md
    ✓ 200  /deployment/cloud/ibm-watsonx         原 /docs/deployment/cloud/ibm-watsonx.md
    ✗ 404  /agents/agents_and_conversations      原 /docs/agents/agents_and_conversations.md

没中的那 3 条正是文档被真重组过的（模型说 Agents & Conversations 现在在
`/studio-api/agents/agents-api`，实测 200 —— 那是机械规则推不出来的）。

**于是 AI 层的价值变成可测量的**：它是机械基线之上的增量，而不是一句
「有了 AI 就更好」。这与 v1 的朴素对照是同一套口径。

## 判定权不外借

变换只**提出**候选，活不活由我们自己发一个请求决定。命中 2xx 才写进
``FixHint.after`` 且 ``verified_target=True``；一条都没中就 ``after=None``、
``verified_target=False``，报告照 §2.6 写「我们没找到明显的正确目标」——
**绝不编一个**。模型提的候选走同一条验证路径，一视同仁。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from geo_audit.models import FixHint, Verdict

__all__ = [
    "MAX_MECHANICAL_TRIES",
    "MAX_MODEL_TRIES",
    "MAX_TRIES_PER_URL",
    "TRANSFORMS",
    "CandidateResult",
    "Transform",
    "apply_transforms",
    "find_fix_candidate",
]

#: 每条死链最多试几个**机械**候选。必须有上限：75 条死链 × 5 个候选 = 375 个
#: 请求，按 0.5 req/s 是 12 分钟，会把默认请求预算整个吃掉。
MAX_MECHANICAL_TRIES = 3

#: 模型候选**单独一个预算**，不与机械候选共享。
#:
#: 第一版共用一个 `MAX_TRIES_PER_URL = 4`，实测立刻炸：
#: `/docs/agents/agents_and_conversations.md` 的四条机械变换正好产出 4 个候选，
#: 把额度吃干净，于是 `model_candidates[:0]` —— **模型给的那条一次都没验**。
#: 而 AI 层的全部意义就在那一条上（机械规则推不出「文档被重组到
#: /studio-api/agents/agents-api」），却被上限静默吞掉了。
#: 一个会悄悄饿死最有价值那次探测的上限，比没有上限更糟。
MAX_MODEL_TRIES = 2

#: 单条死链的总上限，只用于对外声明与测试断言。
MAX_TRIES_PER_URL = MAX_MECHANICAL_TRIES + MAX_MODEL_TRIES


@dataclass(frozen=True, slots=True)
class Transform:
    """一条命名的路径变换。``rule_id`` 会进报告 —— 读的人要知道我们怎么猜的。"""

    rule_id: str
    why: str
    fn: Callable[[str], str | None]


def _split(url: str) -> tuple[str, str, str]:
    parts = urlsplit(url)
    return parts.scheme, parts.netloc, parts.path


def _rebuild(scheme: str, netloc: str, path: str) -> str:
    return urlunsplit((scheme, netloc, path, "", ""))


def _drop_md(url: str) -> str | None:
    scheme, netloc, path = _split(url)
    if not path.endswith(".md"):
        return None
    return _rebuild(scheme, netloc, path[:-3])


def _drop_docs_prefix(url: str) -> str | None:
    scheme, netloc, path = _split(url)
    if not path.startswith("/docs/"):
        return None
    return _rebuild(scheme, netloc, path[5:])


def _drop_both(url: str) -> str | None:
    step = _drop_md(url)
    if step is None:
        return None
    return _drop_docs_prefix(step) or step


def _underscore_to_hyphen(url: str) -> str | None:
    """末段 ``_`` → ``-``。文档站换生成器时最常见的一次 slug 迁移。"""
    stripped = _drop_both(url) or url
    scheme, netloc, path = _split(stripped)
    head, _, tail = path.rpartition("/")
    if "_" not in tail:
        return None
    return _rebuild(scheme, netloc, f"{head}/{tail.replace('_', '-')}")


#: 按先验命中率排序。实测 mistral：``drop_both`` 一条就吃掉 7/10。
TRANSFORMS: tuple[Transform, ...] = (
    Transform(
        "drop_both",
        "llms.txt 惯例是给机器列 .md 变体，且这里多了一层 /docs 前缀；两个一起去掉",
        _drop_both,
    ),
    Transform("drop_md", "只去掉给机器用的 .md 后缀", _drop_md),
    Transform("drop_docs_prefix", "只去掉多出来的 /docs 前缀", _drop_docs_prefix),
    Transform(
        "underscore_to_hyphen",
        "末段下划线换成连字符（换文档生成器时最常见的一次 slug 迁移）",
        _underscore_to_hyphen,
    ),
)


def apply_transforms(dead_url: str) -> tuple[tuple[str, Transform], ...]:
    """产出去重后的候选，按 :data:`TRANSFORMS` 的顺序。**不发请求。**"""
    seen: dict[str, Transform] = {}
    for transform in TRANSFORMS:
        candidate = transform.fn(dead_url)
        if not candidate or candidate == dead_url:
            continue
        seen.setdefault(candidate, transform)
    return tuple(seen.items())[:MAX_MECHANICAL_TRIES]


@dataclass(frozen=True, slots=True)
class CandidateResult:
    """一次候选验证的结果。``fix`` 的 ``verified_target`` 只在 2xx 时为 True。"""

    dead_url: str
    fix: FixHint
    tried: tuple[tuple[str, str, int | None], ...]  # (候选, rule_id, 状态码)
    source: str  # "mechanical" | "model" | "none"


def find_fix_candidate(
    dead_url: str,
    *,
    probe: Callable[[str], tuple[int | None, Verdict]],
    model_candidates: Sequence[str] = (),
    locator: str = "",
) -> CandidateResult:
    """给一条死链找一个**验证过**的替代地址。

    ``probe`` 是注入的验活函数（生产侧包 ``Fetcher.probe``）—— 这里刻意不直接收
    Fetcher：判定层不该知道 HTTP 客户端怎么造，测试也能塞一个纯字典替身。

    顺序：先机械变换（不要钱、可解释），再模型给的候选（覆盖真重组的情形）。
    **两者走同一条验证路径**，模型提的不因为「是 AI 说的」而豁免验活。
    """
    tried: list[tuple[str, str, int | None]] = []

    for candidate, transform in apply_transforms(dead_url):
        status, verdict = probe(candidate)
        tried.append((candidate, transform.rule_id, status))
        if verdict is Verdict.OK and status is not None and 200 <= status < 300:
            return CandidateResult(
                dead_url=dead_url,
                fix=FixHint(
                    action=f"把索引里这条改指到 {candidate}",
                    open_this=locator or dead_url,
                    locator=locator,
                    before=dead_url,
                    after=candidate,
                    verified_target=True,
                ),
                tried=tuple(tried),
                source="mechanical",
            )

    for candidate in model_candidates[:MAX_MODEL_TRIES]:
        if candidate == dead_url or any(candidate == t[0] for t in tried):
            continue
        status, verdict = probe(candidate)
        tried.append((candidate, "model_proposed", status))
        if verdict is Verdict.OK and status is not None and 200 <= status < 300:
            return CandidateResult(
                dead_url=dead_url,
                fix=FixHint(
                    action=f"把索引里这条改指到 {candidate}",
                    open_this=locator or dead_url,
                    locator=locator,
                    before=dead_url,
                    after=candidate,
                    verified_target=True,
                ),
                tried=tuple(tried),
                source="model",
            )

    return CandidateResult(
        dead_url=dead_url,
        fix=FixHint(
            action="补一个页面，或把索引里这条删掉",
            open_this=locator or dead_url,
            locator=locator,
            before=dead_url,
            after=None,
            verified_target=False,
        ),
        tried=tuple(tried),
        source="none",
    )
