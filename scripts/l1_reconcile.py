#!/usr/bin/env python3
"""L1 端到端：v1 报告 + 回答快照 → 对账结果。**零 LLM。**

    python scripts/l1_reconcile.py REPORT.json --answers ANSWERS.json

这个脚本是 L1 的可跑证明：判定完全确定性，同一份输入必得同一份输出。
它不接 key、不发请求 —— 真发调用在 ai/probe.py，录制在 scripts/record_answers.py，
三件事刻意分开。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from geo_audit.ai.answers import AnswerStore  # noqa: E402
from geo_audit.ai.questions import build_questions  # noqa: E402
from geo_audit.checks.ai_perception import (  # noqa: E402
    PerceptionStatus,
    normalise_for_compare,
    reconcile,
)

_LABEL = {
    PerceptionStatus.CITES_DEAD: "把死链交出去",
    PerceptionStatus.MATCH: "答对（v1 测过是活的）",
    PerceptionStatus.UNVERIFIABLE: "我们没测过这条 URL",
    PerceptionStatus.NO_URL: "没给 URL",
    PerceptionStatus.UNSTABLE: "说法不稳",
}


def _report_stub(raw: dict[str, object]) -> object:
    findings = []
    for f in raw.get("findings", ()):  # type: ignore[union-attr]
        target = f.get("target") or {}
        findings.append(
            SimpleNamespace(
                kind=f.get("kind"),
                anchor_text=f.get("anchor_text"),
                found_on=f.get("found_on"),
                finding_id=f.get("finding_id"),
                target=SimpleNamespace(
                    url=target.get("url", ""), curl_repro=target.get("curl_repro", "")
                ),
            )
        )
    return SimpleNamespace(domain=raw.get("domain", ""), findings=findings)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="l1_reconcile.py", description=__doc__)
    ap.add_argument("report", metavar="REPORT.json", help="v1 的 JSON 报告")
    ap.add_argument("--answers", required=True, metavar="PATH", help="回答快照")
    args = ap.parse_args(argv)

    raw = json.loads(Path(args.report).read_text(encoding="utf-8"))
    report = _report_stub(raw)
    questions = build_questions(report, cap=999)
    store = AnswerStore.load(args.answers)

    # 死链集与活链集都来自 v1 的报告，**不是这里新测的**。
    dead = frozenset(normalise_for_compare(q.known_dead_url) for q in questions)
    alive: frozenset[str] = frozenset()

    asked = [q for q in questions if store.has(q.qid)]
    if not asked:
        print("回答快照里没有任何一道题的回答 —— AI 层未运行（A53）。")
        return 0

    print(f"域名 {report.domain}   被试 {store.model or '未标注'}")  # type: ignore[attr-defined]
    print(f"出题 {len(questions)} 道，其中录过回答的 {len(asked)} 道\n")

    tally: dict[PerceptionStatus, int] = {}
    for q in asked:
        f = reconcile(q, store.get(q.qid), dead_urls=dead, alive_urls=alive)
        tally[f.status] = tally.get(f.status, 0) + 1
        mark = "  ← 发现" if f.is_hit else ""
        print(f"[{f.qid}] {_LABEL[f.status]}{mark}")
        print(f"    题面      {f.question_text}")
        print(f"    v1 已证实死 {f.known_dead_url}")
        print(f"    模型给的   {f.model_url or '（没有多数）'}")
        print(
            f"    采样 {f.n_samples} 次 / 给了 URL {f.n_with_url} 次 / "
            f"不同 URL {f.n_distinct_urls} 个 / 多数票 {f.n_votes_for_model_url} / "
            f"检索结果里见过 {f.n_cited} 次（{f.evidence_kind}）"
        )
        if f.n_distinct_urls > 1:
            for u in f.distinct_urls:
                print(f"      · {u}")
        print()

    print("汇总（绝对数，不报百分比 —— 分母太小）：")
    for status, n in sorted(tally.items(), key=lambda kv: kv[0].value):
        print(f"  {_LABEL[status]:22} {n} 道")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
