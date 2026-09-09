"""死链的修复候选：机械路径变换 + **我们自己验活**。零 LLM。

## 为什么这一层先做、且不需要 AI

mistral 的 75 条死链，**全量实测：机械命中 38 / 75**，一个 LLM 都不用。
按规则拆开（166 个验证请求）：

    drop_both              37 命中   ← 一条吃掉 38 里的 37
    drop_docs_prefix        1 命中
    underscore_to_hyphen    0 命中

**先前抽样 10 条得到 7/10，我据此外推「大部分」，全量一跑砍掉一半。**
留这句在这里：抽样外推在这个项目里已经错过两次（另一次是闸门 B 的
6.3% → 2.5%），下次先跑全量再下结论。

没中的 37 条是文档被**真重组**过的，机械规则推不出来。而那正是 AI 层挣钱的
地方：实测问过的 3 题里有 2 题的死链落在这 37 条内，模型两条都给出了验证过
200 的目标：

    /docs/agents/agents_and_conversations.md       机械 ✗ → /studio-api/agents/agents-api  200
    /docs/capabilities/audio_and_transcription.md  机械 ✗ → /studio/audio/overview         200

**于是 AI 层的价值是可测量的增量**（机械基线之上多修好几条），而不是一句
「有了 AI 就更好」。这与 v1 的朴素对照是同一套口径。

## 判定权不外借

变换只**提出**候选，活不活由我们自己发一个请求决定。命中 2xx 才写进
``FixHint.after`` 且 ``verified_target=True``；一条都没中就 ``after=None``、
``verified_target=False``，报告照 §2.6 写「我们没找到明显的正确目标」——
**绝不编一个**。模型提的候选走同一条验证路径，一视同仁。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from urllib.parse import urlsplit, urlunsplit

from geo_audit.models import FixHint, Verdict

__all__ = [
    "MAX_MECHANICAL_TRIES",
    "MAX_MODEL_TRIES",
    "MAX_TRIES_PER_URL",
    "TRANSFORMS",
    "CandidateQuality",
    "CandidateResult",
    "Transform",
    "apply_transforms",
    "find_fix_candidate",
    "grade_candidates",
]

#: 每条死链最多试几个**机械**候选。**这个数由实测定，不是猜的。**
#:
#: 全量 75 条实测：命中 38 条全部来自前两条规则（drop_both 37 + drop_docs_prefix 1），
#: 第三条 underscore_to_hyphen 是 0/37。所以设 2 —— 拿到 38/38 的命中，
#: 而请求量从 4 次/条砍到 2 次（166 → 约 90）。
#: 想调大要先拿新语料的实测数字，别凭「多试几个总没坏处」。
MAX_MECHANICAL_TRIES = 2

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


#: 按**实测**命中率排序（全量 75 条）：drop_both 37 / drop_docs_prefix 1 /
#: underscore_to_hyphen 0。
#:
#: ``drop_md`` 已删 —— 它零命中，而且**是构造上必然的**：``_drop_both`` 在没有
#: /docs 前缀时会回落成 drop_md 的结果，所以它永远产不出**不同的**候选，
#: 一定被 apply_transforms 的去重吃掉。那不是「没测到」，是冗余。
TRANSFORMS: tuple[Transform, ...] = (
    Transform(
        "drop_both",
        "llms.txt 惯例是给机器列 .md 变体，且这里多了一层 /docs 前缀；两个一起去掉",
        _drop_both,
    ),
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


class CandidateQuality(str, Enum):
    """候选的质量档。**「验通 200」不等于「修好了」。**

    实测 mistral 那 35 条机械修不了的死链，模型给的候选里有 3 条虽然 200，
    但不是真正的替代：

        2× /guides/finetuning   ← ' 02 Prepare Dataset' 与
                                   'download the validation and reformat script' 都指到这里
        1× /                    ← 'Welcome to Mistral AI Documentation'

    多条死链落到同一页，说明那多半是**父页面**；拿站点首页当替代更不算修好。
    把这三条混进「修好了」，报告的数字就虚了 3 条。

    这两条判据都是确定性的（候选去重计数、根路径检测），**不需要任何模型参与**。
    刻意只留这两条：观测到的数据只支持这两条，第三条（按路径段数猜父子）在
    实测样本上就不成立 —— `/guides/finetuning` 与
    `/guides/finetuning_sections/_02_prepare_dataset` 只差一段，按段数判分不出。
    """

    EXACT = "exact"
    DOWNGRADED = "downgraded"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class CandidateResult:
    """一次候选验证的结果。``fix`` 的 ``verified_target`` 只在 2xx 时为 True。"""

    dead_url: str
    fix: FixHint
    tried: tuple[tuple[str, str, int | None], ...]  # (候选, rule_id, 状态码)
    source: str  # "mechanical" | "model" | "none"
    #: 质量档。**单条判不出 DOWNGRADED 的「父页面」那一半** —— 那要看整轮里
    #: 有没有别的死链也指到同一个候选，所以由 :func:`grade_candidates` 事后统一打。
    quality: CandidateQuality = CandidateQuality.NONE
    downgrade_why: str = ""


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


def _is_site_root(url: str) -> bool:
    _, _, path = _split(url)
    return path.strip("/") == ""


def grade_candidates(results: Sequence[CandidateResult]) -> tuple[CandidateResult, ...]:
    """整轮统一打质量档。**必须整轮一起看**，单条看不出父页面。

    两条判据，都是确定性的：

    1. **候选是站点根路径** → 拿首页当替代不算修好。
       实测：'Welcome to Mistral AI Documentation' 的候选就是 ``/``。
    2. **≥2 条死链指到同一个候选** → 那多半是父页面，不是各自的替代。
       实测：' 02 Prepare Dataset' 与 'download the validation and reformat script'
       都指到 ``/guides/finetuning``。

    刻意不加第三条「按路径段数猜父子」：实测样本上它就不成立
    （``/guides/finetuning`` 与 ``/guides/finetuning_sections/_02_prepare_dataset``
    只差一段，按段数分不出父子）。**数据不支持的判据不写。**
    """
    claims: dict[str, int] = {}
    for r in results:
        after = r.fix.after
        if after and r.fix.verified_target:
            claims[after.rstrip("/")] = claims.get(after.rstrip("/"), 0) + 1

    out: list[CandidateResult] = []
    for r in results:
        after = r.fix.after
        if not after or not r.fix.verified_target:
            out.append(replace(r, quality=CandidateQuality.NONE, downgrade_why=""))
            continue
        if _is_site_root(after):
            out.append(
                replace(
                    r,
                    quality=CandidateQuality.DOWNGRADED,
                    downgrade_why="候选是站点首页 —— 把一条具体页面的死链改指首页不算修好",
                )
            )
            continue
        n = claims.get(after.rstrip("/"), 0)
        if n >= 2:
            out.append(
                replace(
                    r,
                    quality=CandidateQuality.DOWNGRADED,
                    downgrade_why=(
                        f"另有 {n - 1} 条死链也指到这个候选 —— 那多半是父页面，不是各自的替代"
                    ),
                )
            )
            continue
        out.append(replace(r, quality=CandidateQuality.EXACT, downgrade_why=""))
    return tuple(out)
