"""真发模型调用。**全仓唯一一个**。

## 三条设计约束

1. **不加 SDK 依赖。** 直接用已经在依赖里的 httpx 打 Responses API。
   装一个 `openai` 包只为发一个 POST，换来的是一条会自己变的依赖 ——
   而这个工具的卖点之一就是 `uvx geo-audit` 一行能跑。
2. **transport 可注入。** 与 `fetch.client.Fetcher` 同一个形状。于是请求怎么构造、
   响应怎么解析，全都能用 `httpx.MockTransport` 离线测 —— 不要 key、不花钱。
   留给真 key 才能验的只剩「端点本身是不是这个样子」。
3. **降级不许静默。** 没 key / 超预算 / 超时，抛 :class:`ProbeUnavailable`，
   由调用方按 A53 在报告里印明「AI 层未运行」。**不返回空列表** ——
   空列表会被下游当成「问了，模型没说什么」，那是把「没能测」写成「测了」。

## 引用只收结构化字段

回答正文里的 URL 不算引用（模型会编 URL）。这里只解析 Responses API 的
``url_citation`` 注解与 ``web_search_call`` 的来源。拿不到结构化引用的模型，
``citations=()`` 且 ``retrieval_used=False``，该次回答只进「一致/冲突」统计，
不进归因 —— 见 checks/ai_perception.py 里 cited 与 stated_only 的区分。
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass

import httpx

from geo_audit.ai.answers import N_SAMPLES, TEMPERATURE, ModelAnswer

__all__ = [
    "AI_BUDGET_USD_DEFAULT",
    "DEFAULT_MODEL",
    "OPENAI_RESPONSES_URL",
    "ProbeConfig",
    "ProbeUnavailable",
    "probe_question",
    "probe_questions",
]

#: §11.1.6：单域名 AI 层硬上限。超了立即停，已完成的题照常出。
AI_BUDGET_USD_DEFAULT = 0.50

#: 写死版本号。**不许用 latest 别名** —— 那会让「模型的说法变了」和
#: 「我们换了模型」变成同一件事，报告里就分不清了。
DEFAULT_MODEL = "gpt-4.1-2025-04-14"

OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"

#: 环境变量名。刻意不接 CLI 传 key —— key 出现在命令行会进 shell history。
API_KEY_ENV = "GEO_AUDIT_AI_API_KEY"


class ProbeUnavailable(RuntimeError):  # noqa: N818 —— 与 fixtures.FixtureMissing 同风格，不加 Error 后缀
    """AI 层跑不了。**调用方必须在报告里印明，不许静默跳过**（A53）。"""


@dataclass(frozen=True, slots=True)
class ProbeConfig:
    model: str = DEFAULT_MODEL
    n_samples: int = N_SAMPLES
    budget_usd: float = AI_BUDGET_USD_DEFAULT
    timeout_s: float = 60.0
    #: forced：显式开 web search，把检索触发率拉到接近 100%。
    #: 报告里必须写明「这是强制检索条件下的上界，不是自然分布」（§11.1.3）。
    retrieval_mode: str = "forced"


def _api_key() -> str:
    key = (os.environ.get(API_KEY_ENV) or "").strip()
    if not key:
        raise ProbeUnavailable(
            f"没有设 {API_KEY_ENV}，AI 层跑不了。"
            "按 A53 报告里要印明「AI 层未运行」——「没能测」不是「测了没问题」。"
        )
    return key


def _payload(question_text: str, cfg: ProbeConfig) -> dict[str, object]:
    body: dict[str, object] = {
        "model": cfg.model,
        "input": question_text,
        "temperature": TEMPERATURE,
    }
    if cfg.retrieval_mode == "forced":
        # 强制开检索工具。natural 模式下不传，让模型自己决定要不要搜。
        body["tools"] = [{"type": "web_search"}]
        body["tool_choice"] = "required"
    return body


def _citations(data: object) -> tuple[str, ...]:
    """只从结构化字段取引用。**不碰回答正文。**"""
    urls: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("type") == "url_citation":
                url = node.get("url")
                if isinstance(url, str) and url:
                    urls.append(url)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    seen: dict[str, None] = {}
    for u in urls:
        seen.setdefault(u, None)
    return tuple(seen)


def _answer_text(data: object) -> str:
    """把 Responses API 的输出拼成纯文本。

    形态随版本变过好几轮，所以这里**遍历取所有 output_text**而不是按固定路径取
    —— 按固定路径取的话，端点小改一次就静默返回空串，然后所有题变成 NO_URL，
    看起来像「模型什么都不知道」。
    """
    chunks: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("type") == "output_text" and isinstance(node.get("text"), str):
                chunks.append(node["text"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    if not chunks and isinstance(data, dict) and isinstance(data.get("output_text"), str):
        chunks.append(data["output_text"])
    return "\n".join(chunks).strip()


def _cost_usd(data: object) -> float:
    """从 usage 估价。取不到就返回 0 —— **不瞎猜**，预算宁可低估也不虚报。"""
    if not isinstance(data, dict):
        return 0.0
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return 0.0
    # 单价随模型变，这里只把 token 数记下来交给调用方；成本估算不进判定。
    tokens = usage.get("total_tokens")
    return float(tokens) / 1_000_000 * 5.0 if isinstance(tokens, (int, float)) else 0.0


def probe_question(
    question: object,
    cfg: ProbeConfig,
    *,
    transport: httpx.BaseTransport | None = None,
    api_key: str | None = None,
    spent_usd: float = 0.0,
) -> tuple[ModelAnswer, ...]:
    """问一道题，采样 ``cfg.n_samples`` 次。

    ``transport`` 注入点存在的唯一理由是可测性：喂 ``httpx.MockTransport``
    就能离线验请求构造与响应解析。生产路径传 None，走真网络。
    """
    key = api_key if api_key is not None else _api_key()
    qid = str(getattr(question, "qid", ""))
    text = str(getattr(question, "text", ""))
    out: list[ModelAnswer] = []
    spent = spent_usd
    client = httpx.Client(
        transport=transport,
        timeout=cfg.timeout_s,
        headers={"authorization": f"Bearer {key}", "content-type": "application/json"},
    )
    try:
        for idx in range(cfg.n_samples):
            if spent >= cfg.budget_usd:
                # 超预算立即停。已完成的照常返回，调用方按 §11.1.6 在报告里写
                # 「AI 层因预算截断，覆盖 N/M 题」。
                break
            resp = client.post(OPENAI_RESPONSES_URL, json=_payload(text, cfg))
            if resp.status_code >= 400:
                raise ProbeUnavailable(
                    f"模型接口返回 {resp.status_code}：{resp.text[:200]}。"
                    "AI 层未运行，报告里要印明（A53）。"
                )
            data = json.loads(resp.text)
            citations = _citations(data)
            cost = _cost_usd(data)
            spent += cost
            out.append(
                ModelAnswer(
                    qid=qid,
                    model=cfg.model,
                    sample_idx=idx,
                    text=_answer_text(data),
                    citations=citations,
                    retrieval_used=bool(citations),
                    cost_usd=cost,
                    probed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    retrieval_mode=cfg.retrieval_mode,
                )
            )
    finally:
        client.close()
    return tuple(out)


def probe_questions(
    questions: Sequence[object],
    cfg: ProbeConfig,
    *,
    transport: httpx.BaseTransport | None = None,
    api_key: str | None = None,
) -> tuple[tuple[ModelAnswer, ...], float]:
    """问全部题，返回 (回答, 已花费)。预算耗尽即停，**不静默补零**。"""
    all_answers: list[ModelAnswer] = []
    spent = 0.0
    for question in questions:
        if spent >= cfg.budget_usd:
            break
        answers = probe_question(
            question, cfg, transport=transport, api_key=api_key, spent_usd=spent
        )
        all_answers.extend(answers)
        spent += sum(a.cost_usd for a in answers)
    return tuple(all_answers), spent
