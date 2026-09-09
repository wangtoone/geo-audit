"""L1 校准：模型的自评**不能**当闸门。这是一个数字，不是一句主张。

## 这份数据怎么来的

mistral.ai 的 75 条索引内链全死（v1 实测）。机械规则（`/docs/X.md` → `/X`）
修好 38 条。余下 37 条里取 35 条，每条**各开一个全新上下文**问「这页在哪」——
被试不知道有死链这回事、不知道实验目的、答完即弃。它给的候选由**我们自己
发请求验活**，模型的 `confident` 自评只记下来当数据。

## 数字

    自称有把握 32 条 → 实测验通 25，**错 7 条**
    自称没把握  3 条 → 实测验通  2 条

也就是说：**拿 confident 当闸门，会发布 7 条错目标、同时丢掉 2 条对的。**
那 7 条全是 404 —— 甲方照着改，会改到另一个 404。

这比引 ContraDoc 的 34.7% 更贴身，因为它是这个工具自己语料上的数字。
它也是 `FixHint.verified_target` 那条契约的实测依据：**去掉验证，这份报告会有
7 条把人引到 404 的建议。**

## 这个文件在防什么

防的不是"数据变了"，是**有人哪天把验证省掉、改成信模型自评**（"模型都说有
把握了，何必再发一个请求"）。那样省下 35 个请求，换来 7 条错建议。
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "tests" / "data" / "l1_calibration.json"


def _rows() -> list[dict[str, object]]:
    raw = json.loads(DATA.read_text(encoding="utf-8"))
    rows = raw["rows"]
    assert isinstance(rows, list)
    return rows


def test_calibration_data_is_present_and_sane() -> None:
    rows = _rows()
    assert len(rows) == 35, f"校准样本应为 35 条，现在 {len(rows)}"
    for r in rows:
        assert r["dead_url"].startswith("https://"), r  # type: ignore[union-attr]
        assert isinstance(r["model_said_confident"], bool)
        assert isinstance(r["verified_alive"], bool)


def test_model_confidence_is_not_a_usable_gate() -> None:
    """自称有把握的里面有实测 404 的 —— 所以自评不能当闸门。

    断言写成「至少有 N 条自称有把握却是错的」而不是「恰好 7 条」：
    语料刷新后数字会动，但**只要还有一条，结论就成立**。
    数字降到 0 才需要回来重新裁决（那说明模型的校准变好了，是好消息，
    但也说明这条论据要换新证据）。
    """
    rows = _rows()
    confident_wrong = [r for r in rows if r["model_said_confident"] and not r["verified_alive"]]
    assert confident_wrong, (
        "这一批里没有「自称有把握却验不通」的样本了 —— "
        "模型校准变好是好事，但 FixHint.verified_target 的实测依据要换新证据，"
        "别把这条测试删掉了当没事。"
    )
    assert len(confident_wrong) >= 5, (
        f"自称有把握却错的只有 {len(confident_wrong)} 条（实录 7 条）—— 数据被改过？"
    )


def test_unconfident_answers_are_not_worthless_either() -> None:
    """自称没把握的里面也有对的 —— 所以用自评做**否定**筛选也会丢东西。"""
    rows = _rows()
    unconfident = [r for r in rows if not r["model_said_confident"]]
    assert unconfident, "样本里没有自称没把握的"
    right = [r for r in unconfident if r["verified_alive"]]
    assert right, (
        "自称没把握的全错了 —— 那自评至少能当否定筛选用，"
        "这条论据要重新裁决（实录是 3 条里 2 条对）。"
    )


def test_verification_is_what_produces_the_number() -> None:
    """每一条 verified_alive 都必须有一个真状态码撑着，不许是猜的。"""
    for r in _rows():
        status = str(r["status"])
        if r["verified_alive"]:
            assert status.startswith("2"), f"标了 verified_alive 但状态码是 {status}：{r}"
        elif r["candidate"]:
            assert status and status != "-", f"有候选却没有状态码：{r}"


def test_the_headline_numbers_hold() -> None:
    """把对外引用的那两个数固定住：验通 27 / 35，自称有把握里错 7。"""
    rows = _rows()
    alive = sum(1 for r in rows if r["verified_alive"])
    confident_wrong = sum(1 for r in rows if r["model_said_confident"] and not r["verified_alive"])
    assert alive == 27, f"验通条数变了：{alive}（实录 27）"
    assert confident_wrong == 7, f"自称有把握却错的条数变了：{confident_wrong}（实录 7）"
