"""真发调用那一层：用 MockTransport 离线测，不要 key、不花钱。

能这么测是因为 ``probe_question`` 收一个可注入的 transport ——
与 ``fetch.client.Fetcher`` 同一个形状。于是请求怎么构造、响应怎么解析、
预算闸怎么停，全都验得到。留给真 key 才能验的只剩「端点本身是不是这个样子」。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from geo_audit.ai.probe import (
    API_KEY_ENV,
    OPENAI_RESPONSES_URL,
    ProbeConfig,
    ProbeUnavailable,
    probe_question,
    probe_questions,
)

Q = SimpleNamespace(qid="q1", text="Where can I find the docs about Webhooks?")


def _resp(text: str, *, citations: tuple[str, ...] = (), tokens: int = 1000) -> dict[str, object]:
    """照 Responses API 的形态造回包：output_text 藏在嵌套结构里。"""
    content: list[dict[str, object]] = [{"type": "output_text", "text": text, "annotations": []}]
    if citations:
        content[0]["annotations"] = [{"type": "url_citation", "url": u} for u in citations]
    return {
        "output": [{"type": "message", "role": "assistant", "content": content}],
        "usage": {"total_tokens": tokens},
    }


def _transport(
    payloads: list[dict[str, object]],
    *,
    seen: list[dict[str, object]] | None = None,
    status: int = 200,
) -> httpx.MockTransport:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(json.loads(request.content.decode()))
        i = min(calls["n"], len(payloads) - 1)
        calls["n"] += 1
        return httpx.Response(status, json=payloads[i])

    return httpx.MockTransport(handler)


# --------------------------------------------------------------------------- #
# 降级
# --------------------------------------------------------------------------- #


def test_no_key_raises_instead_of_returning_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """没 key 必须**抛**，不许返回空列表。

    返回空列表会被下游当成「问了，模型没说什么」→ 全部 NO_URL ——
    那是把「没能测」写成「测了」，正是 A53 要挡的。
    """
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    with pytest.raises(ProbeUnavailable, match=API_KEY_ENV):
        probe_question(Q, ProbeConfig())


def test_http_error_raises_probe_unavailable() -> None:
    t = _transport([{"error": {"message": "no credit"}}], status=429)
    with pytest.raises(ProbeUnavailable, match="429"):
        probe_question(Q, ProbeConfig(n_samples=1), transport=t, api_key="k")


# --------------------------------------------------------------------------- #
# 请求构造
# --------------------------------------------------------------------------- #


def test_forced_mode_turns_on_web_search_and_pins_temperature() -> None:
    seen: list[dict[str, object]] = []
    t = _transport([_resp("see https://a.invalid/x")], seen=seen)
    probe_question(Q, ProbeConfig(n_samples=1), transport=t, api_key="k")
    assert len(seen) == 1
    body = seen[0]
    assert body["temperature"] == 0.0, "温度必须固定 —— 否则「说法不稳」归因不到检索差异"
    assert body["tools"] == [{"type": "web_search"}]
    assert body["tool_choice"] == "required"
    assert "latest" not in str(body["model"]), "模型名不许用 latest 别名"


def test_natural_mode_does_not_force_retrieval() -> None:
    seen: list[dict[str, object]] = []
    t = _transport([_resp("x")], seen=seen)
    probe_question(
        Q,
        ProbeConfig(n_samples=1, retrieval_mode="natural"),
        transport=t,
        api_key="k",
    )
    assert "tools" not in seen[0]


def test_n_samples_is_honoured() -> None:
    seen: list[dict[str, object]] = []
    t = _transport([_resp("x")], seen=seen)
    answers = probe_question(Q, ProbeConfig(n_samples=5), transport=t, api_key="k")
    assert len(answers) == 5 == len(seen)
    assert [a.sample_idx for a in answers] == [0, 1, 2, 3, 4]


# --------------------------------------------------------------------------- #
# 响应解析
# --------------------------------------------------------------------------- #


def test_output_text_is_walked_not_path_indexed() -> None:
    """按固定路径取 output_text 的话，端点小改一次就静默返回空串，
    然后所有题变 NO_URL —— 看起来像「模型什么都不知道」。所以遍历取。"""
    weird = {"data": {"nested": [{"deeper": [{"type": "output_text", "text": "hello there"}]}]}}
    t = _transport([weird])
    answers = probe_question(Q, ProbeConfig(n_samples=1), transport=t, api_key="k")
    assert answers[0].text == "hello there"


def test_citations_come_from_structured_annotations_only() -> None:
    """正文里的 URL **不算**引用 —— 模型会编 URL。"""
    body = _resp("According to https://fake.invalid/made-up you can…")
    t = _transport([body])
    a = probe_question(Q, ProbeConfig(n_samples=1), transport=t, api_key="k")[0]
    assert a.citations == (), "正文里的 URL 被当成了结构化引用"
    assert a.retrieval_used is False

    cited = _resp("see below", citations=("https://real.invalid/page",))
    a2 = probe_question(Q, ProbeConfig(n_samples=1), transport=_transport([cited]), api_key="k")[0]
    assert a2.citations == ("https://real.invalid/page",)
    assert a2.retrieval_used is True


def test_url_citations_are_deduplicated_in_order() -> None:
    body = _resp(
        "x", citations=("https://a.invalid/1", "https://a.invalid/1", "https://a.invalid/2")
    )
    a = probe_question(Q, ProbeConfig(n_samples=1), transport=_transport([body]), api_key="k")[0]
    assert a.citations == ("https://a.invalid/1", "https://a.invalid/2")


def test_endpoint_is_the_responses_api() -> None:
    """端点写在常量里，改了要能看见 —— 它是这一层唯一没法离线验真的部分。"""
    assert OPENAI_RESPONSES_URL == "https://api.openai.com/v1/responses"


# --------------------------------------------------------------------------- #
# 预算
# --------------------------------------------------------------------------- #


def test_budget_stops_probing_and_keeps_what_finished() -> None:
    """超预算立即停，已完成的题照常返回 —— 不是整批作废。"""
    seen: list[dict[str, object]] = []
    # 每次 1e6 token → 每次 $5，预算 $0.5 时第一次就超
    t = _transport([_resp("x", tokens=1_000_000)], seen=seen)
    qs = [SimpleNamespace(qid=f"q{i}", text="t") for i in range(4)]
    answers, spent = probe_questions(
        qs, ProbeConfig(n_samples=1, budget_usd=0.5), transport=t, api_key="k"
    )
    assert len(seen) == 1, "超预算之后还在继续发请求"
    assert len(answers) == 1
    assert spent > 0.5


def test_cost_is_zero_when_usage_missing_not_guessed() -> None:
    """取不到 usage 就记 0 —— 预算宁可低估也不虚报（虚报会提前掐掉探测）。"""
    t = _transport([{"output": [{"content": [{"type": "output_text", "text": "x"}]}]}])
    a = probe_question(Q, ProbeConfig(n_samples=1), transport=t, api_key="k")[0]
    assert a.cost_usd == 0.0
