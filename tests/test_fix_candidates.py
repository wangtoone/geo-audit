"""修复候选：机械变换 + 我们自己验活。零 LLM、确定性。

验活函数是注入的，所以整条链路离线可测 —— 不发一个真请求。
"""

from __future__ import annotations

import pytest

from geo_audit.checks.fix_candidates import (
    MAX_MECHANICAL_TRIES,
    MAX_MODEL_TRIES,
    MAX_TRIES_PER_URL,
    TRANSFORMS,
    CandidateQuality,
    apply_transforms,
    find_fix_candidate,
    grade_candidates,
)
from geo_audit.models import Verdict

DEAD = "https://docs.mistral.ai/docs/deployment/cloud/aws.md"
LIVE = "https://docs.mistral.ai/deployment/cloud/aws"


def _probe(alive: set[str]):
    """返回一个纯字典替身：命中就 200/OK，否则 404/REAL404。"""

    def probe(url: str) -> tuple[int | None, Verdict]:
        return (200, Verdict.OK) if url in alive else (404, Verdict.REAL404)

    return probe


# --------------------------------------------------------------------------- #
# 变换本身（不发请求）
# --------------------------------------------------------------------------- #


def test_drop_both_is_tried_first() -> None:
    """实测 mistral 抽样 10 条里 drop_both 一条就吃掉 7 条，所以它排第一。"""
    cands = apply_transforms(DEAD)
    assert cands, "一个候选都没产出"
    assert cands[0][0] == LIVE
    assert cands[0][1].rule_id == "drop_both"


def test_candidates_are_deduplicated_and_capped() -> None:
    cands = apply_transforms(DEAD)
    urls = [c for c, _ in cands]
    assert len(urls) == len(set(urls)), f"候选有重复：{urls}"
    assert len(cands) <= MAX_MECHANICAL_TRIES


def test_transforms_that_do_not_apply_produce_nothing() -> None:
    """路径里没有 .md、也没有 /docs/ 前缀时不许硬造候选。"""
    assert apply_transforms("https://x.invalid/plain/page") == ()


def test_underscore_rule_fires_only_on_the_last_segment() -> None:
    """直接测规则本身，不经过 ``apply_transforms`` 的额度裁剪。

    这条一开始是断言在候选清单里 —— 结果 `MAX_MECHANICAL_TRIES` 收到 3 之后，
    排第 4 的下划线规则被整个切掉，测试红了。**规则语义与额度裁剪是两件事**，
    混在一条断言里，改额度会误伤规则的测试。
    """
    rule = next(t for t in TRANSFORMS if t.rule_id == "underscore_to_hyphen")
    got = rule.fn("https://x.invalid/docs/getting_started/model_selection.md")
    assert got == "https://x.invalid/getting_started/model-selection"
    # 中间那段的下划线不许动 —— 只有末段是 slug
    assert got is not None and "getting-started" not in got


@pytest.mark.parametrize("transform", TRANSFORMS, ids=lambda t: t.rule_id)
def test_every_transform_explains_itself(transform: object) -> None:
    """``rule_id`` 会进报告，``why`` 要能让读的人判断这个猜测合不合理。"""
    assert len(getattr(transform, "why", "")) >= 15


# --------------------------------------------------------------------------- #
# 验活与 FixHint 的契约
# --------------------------------------------------------------------------- #


def test_verified_target_requires_a_real_2xx() -> None:
    r = find_fix_candidate(DEAD, probe=_probe({LIVE}), locator="llms.txt:12")
    assert r.source == "mechanical"
    assert r.fix.verified_target is True
    assert r.fix.after == LIVE
    assert r.fix.before == DEAD
    assert r.fix.locator == "llms.txt:12"


def test_no_candidate_alive_means_no_invented_target() -> None:
    """一条都没中 → after=None、verified_target=False。

    §2.6 的原文是「绝不编一个」。编一个的代价是甲方照着改，改到另一个 404。
    """
    r = find_fix_candidate(DEAD, probe=_probe(set()))
    assert r.source == "none"
    assert r.fix.after is None
    assert r.fix.verified_target is False
    assert "补一个页面" in r.fix.action


def test_model_candidate_is_verified_not_trusted() -> None:
    """模型提的候选走同一条验活路径，不因为「是 AI 说的」而豁免。"""
    reorganised = "https://docs.mistral.ai/studio-api/agents/agents-api"
    dead = "https://docs.mistral.ai/docs/agents/agents_and_conversations.md"
    # 机械变换全 404（文档被真重组过），模型给的那条活
    r = find_fix_candidate(dead, probe=_probe({reorganised}), model_candidates=[reorganised])
    assert r.source == "model"
    assert r.fix.after == reorganised
    assert r.fix.verified_target is True


def test_model_candidate_that_is_dead_is_rejected() -> None:
    """模型给的候选也会是死的 —— 那就不产建议，而不是照抄。"""
    dead = "https://docs.mistral.ai/docs/agents/agents_and_conversations.md"
    r = find_fix_candidate(
        dead, probe=_probe(set()), model_candidates=["https://x.invalid/made-up"]
    )
    assert r.fix.verified_target is False
    assert r.fix.after is None
    assert any(t[1] == "model_proposed" for t in r.tried), "模型候选没被记进 tried"


def test_mechanical_wins_over_model_when_both_alive() -> None:
    """机械变换优先：不要钱、可解释、且它命中就说明根因是路径写错而非重组。"""
    r = find_fix_candidate(
        DEAD,
        probe=_probe({LIVE, "https://other.invalid/x"}),
        model_candidates=["https://other.invalid/x"],
    )
    assert r.source == "mechanical"
    assert r.fix.after == LIVE


def test_tried_list_records_every_attempt_with_its_rule() -> None:
    """报告要能写「我们试了这几个、各自什么状态」—— 那是这个猜测的可审计性。"""
    r = find_fix_candidate(DEAD, probe=_probe(set()))
    assert r.tried, "没有记下任何尝试"
    for candidate, rule_id, status, verdict in r.tried:
        assert candidate.startswith("http")
        assert rule_id
        assert status == 404
        assert verdict is Verdict.REAL404


def test_total_requests_are_capped_per_url() -> None:
    """75 条死链 × 无上限候选会把默认请求预算整个吃掉。"""
    r = find_fix_candidate(
        "https://x.invalid/docs/a_b/c_d.md",
        probe=_probe(set()),
        model_candidates=["https://x.invalid/1", "https://x.invalid/2", "https://x.invalid/3"],
    )
    assert len(r.tried) <= MAX_TRIES_PER_URL


def test_mechanical_candidates_never_starve_the_model_candidate() -> None:
    """机械候选把额度吃满时，模型候选仍然要验得到。

    第一版共用一个上限，实测 `/docs/agents/agents_and_conversations.md` 的四条
    机械变换正好把 4 个额度吃干净 → `model_candidates[:0]` → **模型给的那条
    一次都没验**。而 AI 层的全部意义就在那一条上。
    """
    dead = "https://docs.mistral.ai/docs/agents/agents_and_conversations.md"
    reorganised = "https://docs.mistral.ai/studio-api/agents/agents-api"
    mech = [c for c, _ in apply_transforms(dead)]
    assert len(mech) == MAX_MECHANICAL_TRIES, (
        f"这条 URL 的机械候选只有 {len(mech)} 个，撑不满额度，这条测试就测不到那个坑"
    )
    r = find_fix_candidate(dead, probe=_probe({reorganised}), model_candidates=[reorganised])
    assert r.source == "model", f"模型候选被机械候选饿死了：tried={r.tried}"
    assert r.fix.verified_target is True
    assert MAX_MODEL_TRIES >= 1


# --------------------------------------------------------------------------- #
# 上限与规则集由实测定，不由「多试几个总没坏处」定
# --------------------------------------------------------------------------- #


def test_cap_is_the_measured_number() -> None:
    """全量 75 条实测：38 条命中全部来自前两条规则，第三条 0/37。

    所以上限是 2。这条测试的作用不是防止改动，是**逼下一次改动带上新数字** ——
    先前抽样 10 条得 7/10、据此外推「大部分」，全量一跑是 38/75，砍掉一半。
    """
    assert MAX_MECHANICAL_TRIES == 2
    assert [t.rule_id for t in TRANSFORMS][:2] == ["drop_both", "drop_docs_prefix"]


def test_drop_md_is_not_a_separate_rule_because_it_is_redundant() -> None:
    """``drop_md`` 不在规则集里，而且**是构造上必然的冗余**，不只是零命中。

    ``_drop_both`` 在没有 /docs 前缀时会回落成 drop_md 的结果，所以单列
    drop_md 永远产不出不同的候选 —— 一定被 apply_transforms 的去重吃掉。
    """
    assert "drop_md" not in [t.rule_id for t in TRANSFORMS]

    # 没有 /docs 前缀时，drop_both 的产出就等于「只去 .md」
    no_prefix = "https://x.invalid/guides/evaluation.md"
    both = next(t for t in TRANSFORMS if t.rule_id == "drop_both")
    assert both.fn(no_prefix) == "https://x.invalid/guides/evaluation"


def test_drop_both_handles_prefix_and_suffix_together() -> None:
    """实测这一条吃掉 38 里的 37，所以它排第一、且必须两件事一起做。"""
    both = next(t for t in TRANSFORMS if t.rule_id == "drop_both")
    assert (
        both.fn("https://docs.mistral.ai/docs/guides/evaluation.md")
        == "https://docs.mistral.ai/guides/evaluation"
    )


# --------------------------------------------------------------------------- #
# 三档质量：验通 200 ≠ 修好了
# --------------------------------------------------------------------------- #
#
# 用例全部来自实测。mistral 那 35 条机械修不了的死链，模型给的候选里有 3 条
# 虽然 200 但不是真正的替代：
#     2× /guides/finetuning   ← ' 02 Prepare Dataset' 与
#                                'download the validation and reformat script'
#     1× /                    ← 'Welcome to Mistral AI Documentation'
# 把这三条混进「修好了」，报告的数字就虚了 3 条。


def _result(dead: str, after: str | None) -> object:
    from geo_audit.checks.fix_candidates import CandidateResult
    from geo_audit.models import FixHint

    return CandidateResult(
        dead_url=dead,
        fix=FixHint(
            action="x",
            open_this=dead,
            locator="",
            before=dead,
            after=after,
            verified_target=after is not None,
        ),
        tried=(),
        source="model" if after else "none",
    )


def test_site_root_candidate_is_downgraded_not_counted_as_fixed() -> None:
    """实测：'Welcome to Mistral AI Documentation' 的候选就是 `/`。"""
    graded = grade_candidates(
        [
            _result(
                "https://docs.mistral.ai/docs/getting-started/docs_introduction.md",
                "https://docs.mistral.ai/",
            )
        ]
    )
    assert graded[0].quality is CandidateQuality.DOWNGRADED
    assert "首页" in graded[0].downgrade_why


def test_two_dead_links_claiming_one_candidate_are_downgraded() -> None:
    """实测：两条死链都指到 /guides/finetuning —— 那多半是父页面。"""
    parent = "https://docs.mistral.ai/guides/finetuning"
    graded = grade_candidates(
        [
            _result(
                "https://docs.mistral.ai/docs/guides/finetuning_sections/_02_prepare_dataset.md",
                parent + "/",
            ),
            _result(
                "https://docs.mistral.ai/docs/guides/finetuning_sections/_03_e2e_examples.md",
                parent,
            ),
        ]
    )
    assert all(g.quality is CandidateQuality.DOWNGRADED for g in graded)
    assert all("父页面" in g.downgrade_why for g in graded)


def test_a_unique_deep_candidate_is_exact() -> None:
    graded = grade_candidates(
        [
            _result(
                "https://docs.mistral.ai/docs/capabilities/moderation.md",
                "https://docs.mistral.ai/capabilities/guardrailing",
            )
        ]
    )
    assert graded[0].quality is CandidateQuality.EXACT
    assert graded[0].downgrade_why == ""


def test_unverified_candidate_is_none_tier() -> None:
    graded = grade_candidates([_result("https://docs.mistral.ai/docs/x.md", None)])
    assert graded[0].quality is CandidateQuality.NONE


def test_grading_needs_the_whole_round_not_one_result() -> None:
    """单条看不出父页面 —— 这就是 grade_candidates 收整轮而不是收单条的理由。"""
    parent = "https://docs.mistral.ai/guides/finetuning"
    alone = grade_candidates([_result("https://docs.mistral.ai/docs/a.md", parent)])
    assert alone[0].quality is CandidateQuality.EXACT, "单条时无从判断，只能算 EXACT"

    together = grade_candidates(
        [
            _result("https://docs.mistral.ai/docs/a.md", parent),
            _result("https://docs.mistral.ai/docs/b.md", parent),
        ]
    )
    assert all(g.quality is CandidateQuality.DOWNGRADED for g in together)


def test_no_segment_count_heuristic_is_used() -> None:
    """刻意**没有**「按路径段数猜父子」这条规则 —— 实测样本上它不成立。

    /guides/finetuning 与 /guides/finetuning_sections/_02_prepare_dataset 只差
    一段，按段数判分不出父子。数据不支持的判据不写。
    """
    graded = grade_candidates(
        [
            _result(
                "https://docs.mistral.ai/docs/guides/finetuning_sections/_02_prepare_dataset.md",
                "https://docs.mistral.ai/guides/finetuning",
            )
        ]
    )
    assert graded[0].quality is CandidateQuality.EXACT, (
        "只有一条死链指向它时不许因为「路径更短」就降级 —— 那条启发式没有数据支持"
    )


# --------------------------------------------------------------------------- #
# 第四档：「没能查」与「查过没有」必须分开
# --------------------------------------------------------------------------- #
#
# 实测踩过：replay 模式下候选响应没录进 fixtures，75 条候选全拿到合成 599，
# 而第一版把它们和「查过确实没有」一起塞进 NONE —— 报告于是对 75 条都写
# 「补一个页面」，读的人会以为我们查过了。那是「没能看 ≠ 没问题」这条铁律
# 在修复建议上的同一个破法。


def _probe_unknown() -> object:
    def probe(url: str) -> tuple[int | None, Verdict]:
        return (599, Verdict.UNKNOWN)  # fixture 缺失时的合成答复

    return probe


def _probe_real404() -> object:
    def probe(url: str) -> tuple[int | None, Verdict]:
        return (404, Verdict.REAL404)

    return probe


def test_all_attempts_unusable_is_unchecked_not_none() -> None:
    r = find_fix_candidate(DEAD, probe=_probe_unknown())  # type: ignore[arg-type]
    assert r.quality is CandidateQuality.UNCHECKED
    assert r.source == "unchecked"
    assert r.fix.after is None
    assert "不是" in r.fix.action and "没查到" in r.fix.action


def test_attempts_that_really_404_are_none_not_unchecked() -> None:
    """逐个试过、确实不存在 —— 那才是「补一个页面」。"""
    r = find_fix_candidate(DEAD, probe=_probe_real404())  # type: ignore[arg-type]
    assert r.quality is CandidateQuality.NONE
    assert r.source == "none"
    assert "试过" in r.fix.action


def test_the_two_tiers_read_differently_to_a_human() -> None:
    """两档的 after 都是 None，所以**只能靠文案区分** —— 那就必须真的不同。"""
    unchecked = find_fix_candidate(DEAD, probe=_probe_unknown())  # type: ignore[arg-type]
    none = find_fix_candidate(DEAD, probe=_probe_real404())  # type: ignore[arg-type]
    assert unchecked.fix.after is none.fix.after is None
    assert unchecked.fix.action != none.fix.action


def test_grading_does_not_overwrite_unchecked_with_none() -> None:
    """grade_candidates 不许把「没能查」又压回「查过没有」。"""
    r = find_fix_candidate(DEAD, probe=_probe_unknown())  # type: ignore[arg-type]
    graded = grade_candidates([r])
    assert graded[0].quality is CandidateQuality.UNCHECKED


def test_tried_records_the_verdict_not_just_the_status() -> None:
    """光看状态码分不出「599 是 fixture 缺失」还是「站点真返回 599」——
    所以 tried 里必须带 verdict。"""
    r = find_fix_candidate(DEAD, probe=_probe_unknown())  # type: ignore[arg-type]
    assert r.tried
    for entry in r.tried:
        assert len(entry) == 4, f"tried 条目少了 verdict：{entry}"
        assert entry[3] is Verdict.UNKNOWN


def test_partial_inability_is_unchecked_not_none() -> None:
    """混合情形：有的候选真 404、有的没判成 → **不许**说「试过都不存在」。

    第一版判据是 `all(UNKNOWN)`，于是「两条机械候选 404 + 模型候选没判成」
    被算进 NONE，报告写「逐个试过都不存在」—— 而其中一条根本没判成。
    实测 mistral 那 75 条里这种混合情形是多数。
    """
    seen: list[str] = []

    def probe(url: str) -> tuple[int | None, Verdict]:
        seen.append(url)
        # 机械候选（前两个）真 404，模型候选没判成
        return (404, Verdict.REAL404) if len(seen) <= 2 else (200, Verdict.UNKNOWN)

    r = find_fix_candidate(
        DEAD, probe=probe, model_candidates=["https://docs.mistral.ai/new/place"]
    )
    assert r.quality is CandidateQuality.UNCHECKED, (
        f"混合情形被判成 {r.quality.value} —— 那会让报告说「试过都不存在」"
    )
    assert "没查到" in r.fix.action


def test_all_real_404_is_still_none() -> None:
    """全部真 404 才是「逐个试过、确实不存在」。判据收紧了不能把这一档也吞掉。"""
    r = find_fix_candidate(DEAD, probe=_probe_real404(), model_candidates=[])  # type: ignore[arg-type]
    assert r.quality is CandidateQuality.NONE
    assert "试过" in r.fix.action
