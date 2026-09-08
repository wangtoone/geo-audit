#!/usr/bin/env python3
"""把一批模型回答录成 L1 的回答快照（AnswerStore 的磁盘形态）。

输入是一个 JSON：``{"model": ..., "answers": [{qid, sample_idx, answer_text,
url, all_urls, used_web_search, search_result_urls}, ...]}``。

**为什么单列一个脚本**：录制与判定必须分开。判定（checks/ai_perception.py）
只看「模型说了哪个 URL」，不关心那句话是谁生成的、怎么生成的 —— 所以录制侧
可以是真 API、可以是别的 harness，判定侧一行都不用改。

映射规则（两条，都不许含糊）：

* ``search_result_urls``  → ``citations``。那是「被试真的在检索结果里看见了这些
  URL」，对应结构化引用。**回答正文里的 URL 不进这里** —— 模型会编 URL。
* ``used_web_search``     → ``retrieval_used``。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from geo_audit.ai.answers import AnswerStore, ModelAnswer  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="record_answers.py", description=__doc__)
    ap.add_argument("input", metavar="JSON", help="回答 JSON")
    ap.add_argument("--out", required=True, metavar="PATH", help="快照落盘路径")
    ap.add_argument(
        "--model",
        default="",
        metavar="NAME",
        help="被试标识。**不许留空也不许写 latest 别名** —— 否则「模型的说法变了」"
        "和「我们换了被试」会变成同一件事",
    )
    ap.add_argument("--probed-at", default="", metavar="TS", help="录制时间戳（ISO8601）")
    args = ap.parse_args(argv)

    if not args.model or "latest" in args.model:
        ap.error("--model 必填且不许含 latest")

    raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
    items = raw["answers"] if isinstance(raw, dict) else raw

    answers: list[ModelAnswer] = []
    for item in items:
        answers.append(
            ModelAnswer(
                qid=str(item["qid"]),
                model=args.model,
                sample_idx=int(item["sample_idx"]),
                text=str(item.get("answer_text") or ""),
                # 只收检索结果里看见的 URL。正文里的 URL 由判定侧单独抽 ——
                # 「模型说了什么」与「模型看了什么」是两件事。
                citations=tuple(dict.fromkeys(item.get("search_result_urls") or ())),
                retrieval_used=bool(item.get("used_web_search")),
                cost_usd=0.0,
                probed_at=args.probed_at,
                retrieval_mode="forced",
            )
        )

    store = AnswerStore(path=Path(args.out))
    store.dump(answers, model=args.model)
    by_qid: dict[str, int] = {}
    for a in answers:
        by_qid[a.qid] = by_qid.get(a.qid, 0) + 1
    print(f"已写 {args.out}：{len(answers)} 份回答 / {len(by_qid)} 道题")
    for qid, n in sorted(by_qid.items()):
        print(f"  {qid}  {n} 次采样")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
