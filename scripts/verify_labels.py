#!/usr/bin/env python
"""标注可溯源性检查（§8.4 卡点 S6c / 验收标准 A18）。

它回答一个问题：**这 42 条死链标注是不是编出来让门禁自证的？**

判据（对 `tests/data/deadlink_labels.jsonl` 的每一行）：

  provenance == "recorded"       URL 原文必须能在 corpus/feature-raw.json 里搜到，
                                 并且必须能在 derived_from 指向的那个 JSON 节点的文本里搜到。
                                 **不通过就红。**
  provenance == "reconstructed"  必须有非空 derived_from、synthetic is True；
                                 derived_from 必须能解析到 corpus 的真实节点，
                                 且该节点文本里能解析出一个 >= 同组重建条数的数字
                                 （「共 N 条」那句原文）；
                                 若带 corpus_evidence，该串必须在 corpus 里逐字存在。
  provenance == "recovered_live" 由 capture_fixtures.py --recover-h-group --live 升级而来，
                                 按 recorded 的口径验，另外要求有 recorded_at。

门禁条件：`n_recorded >= 12`（§8.6 第 6 条）。

`tests/data/denoise_extra_labels.jsonl`（X 组）按同样口径验，但多一档
`provenance == "spec_only"`：URL 只出现在 IMPLEMENTATION-v2.md 的实测锚点里
（corpus 是逐域汇总，不逐条存 URL），此时只要求 derived_from 指向方案正文。
X 组不进 fp 指标分母（§8.6 的 METRICS_SET / COVERAGE_SET 之分），所以它没有
`n_recorded` 下界。

退出码：0 = 全过；1 = 有条目不可溯源；2 = 用法/文件问题。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "corpus" / "feature-raw.json"
METRICS_SET = REPO / "tests" / "data" / "deadlink_labels.jsonl"
COVERAGE_EXTRA = REPO / "tests" / "data" / "denoise_extra_labels.jsonl"

#: §8.4：recorded 条数下界，写成 gate 条件
MIN_RECORDED = 12
#: §8.4：42 条的构成
EXPECT_TOTAL = 42
EXPECT_DEAD = 25
EXPECT_FALSE_POSITIVE = 17
#: 假阳性四类的条数（honest_note 原文分类）
EXPECT_FP_BY_RULE = {
    "reserved_example_domain": 5,
    "api_endpoint_in_code_context": 7,
    "cloudflare_email_protection": 2,
    "dns_retry_second_resolver": 2,
    "seed_url_not_on_site": 1,
}

PROVENANCE_RECORDED = frozenset({"recorded", "recovered_live"})
PROVENANCE_ALL = frozenset({"recorded", "recovered_live", "reconstructed", "spec_only"})

_PATH_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]")
_INT_RE = re.compile(r"\d+")


class TraceabilityError(Exception):
    """一条标注不可溯源。"""


def load_corpus() -> tuple[dict[str, Any], str]:
    if not CORPUS.exists():
        print(f"FATAL 找不到 {CORPUS}", file=sys.stderr)
        raise SystemExit(2)
    text = CORPUS.read_text(encoding="utf-8")
    return json.loads(text), text


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        print(f"FATAL 找不到 {path}", file=sys.stderr)
        raise SystemExit(2)
    rows: list[dict[str, Any]] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:  # pragma: no cover - 手改坏了才会走到
            print(f"FATAL {path.name}:{n} 不是合法 JSON：{exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    return rows


def resolve(corpus: dict[str, Any], dotted: str) -> Any:
    """把 `measures[7].domains[7].c1_dead_links.examples[0]` 解析成节点。

    解析不到（比如 derived_from 指向 IMPLEMENTATION-v2.md）返回 None。
    """
    node: Any = corpus
    for m in _PATH_RE.finditer(dotted):
        key, idx = m.group(1), m.group(2)
        try:
            node = node[key] if key is not None else node[int(idx)]
        except (KeyError, IndexError, TypeError):
            return None
    return node


def node_text(node: Any) -> str:
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    return json.dumps(node, ensure_ascii=False)


def check_row(
    row: dict[str, Any],
    corpus: dict[str, Any],
    corpus_text: str,
    *,
    group_size: int,
    allow_spec_only: bool,
) -> None:
    rid = row.get("id") or "<无 id>"
    prov = row.get("provenance")
    if prov not in PROVENANCE_ALL:
        raise TraceabilityError(f"{rid}: provenance={prov!r} 不是合法档位")
    if prov == "spec_only" and not allow_spec_only:
        raise TraceabilityError(f"{rid}: METRICS_SET 不许出现 provenance=spec_only")

    derived = (row.get("derived_from") or "").strip()
    if not derived:
        raise TraceabilityError(f"{rid}: derived_from 为空")

    url = row.get("url")
    evidence = row.get("corpus_evidence")

    if prov == "spec_only":
        if not derived.startswith("IMPLEMENTATION-v2.md"):
            raise TraceabilityError(
                f"{rid}: spec_only 的 derived_from 必须指向 IMPLEMENTATION-v2.md，实为 {derived!r}"
            )
        if evidence and evidence not in corpus_text:
            raise TraceabilityError(f"{rid}: corpus_evidence 在 corpus 里搜不到：{evidence!r}")
        return

    node = resolve(corpus, derived)
    if node is None:
        raise TraceabilityError(f"{rid}: derived_from 在 corpus 里解析不到：{derived!r}")
    text = node_text(node)

    if prov in PROVENANCE_RECORDED:
        if not url:
            raise TraceabilityError(f"{rid}: recorded 却没有 url")
        if url not in corpus_text:
            raise TraceabilityError(f"{rid}: recorded 但 URL 原文在 corpus 里搜不到：{url}")
        if url not in text and not (evidence and evidence in text):
            raise TraceabilityError(
                f"{rid}: recorded 的 URL 不在 derived_from 指向的节点里（{derived}）。"
                f"要么改 derived_from，要么给一个出现在该节点里的 corpus_evidence"
            )
        if prov == "recovered_live" and not row.get("recorded_at"):
            raise TraceabilityError(f"{rid}: recovered_live 必须记录 recorded_at")
        return

    # reconstructed
    if row.get("synthetic") is not True:
        raise TraceabilityError(f"{rid}: reconstructed 必须带 synthetic: true")
    numbers = [int(x) for x in _INT_RE.findall(text)]
    if not numbers:
        raise TraceabilityError(
            f"{rid}: reconstructed 的 derived_from 节点里解析不出任何数字（{derived}）"
        )
    if max(numbers) < group_size:
        raise TraceabilityError(
            f"{rid}: reconstructed 的原文最大计数 {max(numbers)} "
            f"< 同组重建条数 {group_size}（{derived}）"
        )
    if evidence and evidence not in corpus_text:
        raise TraceabilityError(f"{rid}: corpus_evidence 在 corpus 里搜不到：{evidence!r}")


def check_composition(rows: list[dict[str, Any]], problems: list[str]) -> None:
    """42 条的构成：25 真死链 + 17 假阳性，假阳性按四类分。"""
    if len(rows) != EXPECT_TOTAL:
        problems.append(f"总条数 {len(rows)} != {EXPECT_TOTAL}")
    ids = [r.get("id") for r in rows]
    dup = [i for i, c in Counter(ids).items() if c > 1]
    if dup:
        problems.append(f"id 重复：{dup}")
    labels = Counter(r.get("label") for r in rows)
    if labels.get("dead") != EXPECT_DEAD:
        problems.append(f"label=dead 的条数 {labels.get('dead')} != {EXPECT_DEAD}")
    if labels.get("false_positive") != EXPECT_FALSE_POSITIVE:
        problems.append(
            f"label=false_positive 的条数 {labels.get('false_positive')} != {EXPECT_FALSE_POSITIVE}"
        )
    by_rule = Counter(r.get("expect_rule") for r in rows if r.get("label") == "false_positive")
    for rule, n in EXPECT_FP_BY_RULE.items():
        if by_rule.get(rule) != n:
            problems.append(f"假阳性类 {rule} 的条数 {by_rule.get(rule)} != {n}")
    extra = set(by_rule) - set(EXPECT_FP_BY_RULE)
    if extra:
        problems.append(f"假阳性里出现了四类之外的 expect_rule：{sorted(extra)}")


def verify(
    path: Path,
    *,
    allow_spec_only: bool,
    corpus: dict[str, Any],
    corpus_text: str,
    enforce_min_recorded: bool,
) -> tuple[int, list[str]]:
    rows = load_jsonl(path)
    problems: list[str] = []

    groups: dict[str, int] = defaultdict(int)
    for r in rows:
        if r.get("provenance") == "reconstructed":
            groups[r.get("derived_from") or ""] += 1

    for r in rows:
        size = (
            groups.get(r.get("derived_from") or "", 1)
            if r.get("provenance") == "reconstructed"
            else 1
        )
        try:
            check_row(r, corpus, corpus_text, group_size=size, allow_spec_only=allow_spec_only)
        except TraceabilityError as exc:
            problems.append(str(exc))

    n_recorded = sum(1 for r in rows if r.get("provenance") in PROVENANCE_RECORDED)
    if enforce_min_recorded:
        check_composition(rows, problems)
        if n_recorded < MIN_RECORDED:
            problems.append(f"n_recorded = {n_recorded} < {MIN_RECORDED}（§8.6 门禁第 6 条）")

    prov = Counter(r.get("provenance") for r in rows)
    print(f"── {path.relative_to(REPO)}")
    print(f"   条数 {len(rows)}；provenance {dict(sorted(prov.items()))}")
    if enforce_min_recorded:
        print(f"   n_recorded = {n_recorded}（下界 {MIN_RECORDED}）")
    return n_recorded, problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true", help="只打结论")
    args = ap.parse_args(argv)

    corpus, corpus_text = load_corpus()
    problems: list[str] = []

    _, p1 = verify(
        METRICS_SET,
        allow_spec_only=False,
        corpus=corpus,
        corpus_text=corpus_text,
        enforce_min_recorded=True,
    )
    problems += p1
    _, p2 = verify(
        COVERAGE_EXTRA,
        allow_spec_only=True,
        corpus=corpus,
        corpus_text=corpus_text,
        enforce_min_recorded=False,
    )
    problems += p2

    if problems:
        print(f"\n不可溯源 / 构成不对 {len(problems)} 处：", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(
            "\n全部标注可溯源：recorded 逐条能在 corpus/feature-raw.json 里搜到，"
            "reconstructed 逐条有 derived_from + synthetic + 计数下界。"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
