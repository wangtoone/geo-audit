"""第 7 步（子域 / 子路径发现）的测试骨架 —— **只写现在能跑的那半**。

⚠️ 归属说明：``discover()`` 的四个新参数（tiers / wellknown / budget / resolver）
属**第 7 步**，不是本轮（第 6/8/9/10 步）的产出。所以：

* 只依赖现有符号（``AI_PATH_CANDIDATES`` / ``DOC_HOST_PREFIXES`` / ``Expect``）
  的断言 —— 现在就跑，这些是 AI 路径体检的**输入契约**，塌了第 6 步全错；
* 依赖新签名的断言 —— ``skip``，reason 里写明「第 7 步开」。

本文件由第 6/8/9/10 步的 agent 建立，第 7 步的 owner 接手后把 skip 换成真断言。
"""

from __future__ import annotations

import inspect

import pytest

from geo_audit.checks.ai_path import _DOC_HOST_RE, in_naive_probe_set
from geo_audit.fetch import discovery
from geo_audit.models import Expect

#: 第 7 步要给 ``discover()`` 加的四个参数（§3.7）。四个都到齐了这些 skip 才该拆。
STEP7_DISCOVER_PARAMS = ("tiers", "wellknown", "budget", "resolver")


def _discover_params() -> set[str]:
    return set(inspect.signature(discovery.discover).parameters)


step7_needed = pytest.mark.skipif(
    not set(STEP7_DISCOVER_PARAMS) <= _discover_params(),
    reason=(
        "第 7 步还没落地：discover() 还没有 tiers/wellknown/budget/resolver 四个参数"
        f"（当前签名：{sorted(_discover_params())}）"
    ),
)


# --------------------------------------------------------------------------- #
# 现在就能跑：AI 路径体检的输入契约
# --------------------------------------------------------------------------- #


def test_ai_path_candidates_are_the_five_recorded_positions() -> None:
    """§3.7:1786：只探根路径会把 6/72 个域读成「未采纳」。五条候选路径逐字冻结。"""
    assert discovery.AI_PATH_CANDIDATES == (
        "/llms.txt",
        "/docs/llms.txt",
        "/llms-full.txt",
        "/docs/llms-full.txt",
        "/.well-known/llms.txt",
    )


def test_ai_paths_are_probed_as_text_files() -> None:
    """卡点 S1：AI 路径探测**一律** ``Expect.TEXT_FILE``。

    改成 ``HTML_PAGE`` 会废掉抓 15/16 的主力规则 L2(a) —— 需要
    ``identical_to_control`` 那条证据时从 ``Classification.secondary_reasons`` 取
    （见 ``tests/test_soft404.py``）。这里用源码断言守着接线点。
    """
    src = inspect.getsource(discovery.discover)
    assert "for path in AI_PATH_CANDIDATES:" in src
    ai_block = src.split("for path in AI_PATH_CANDIDATES:", 1)[1][:400]
    assert "expect=Expect.TEXT_FILE" in ai_block
    assert "Expect.HTML_PAGE" not in ai_block
    assert Expect.TEXT_FILE.value == "text_file"


def test_docs_subpath_and_subdomain_are_both_in_the_probe_set() -> None:
    """假阴的两个方向都要覆盖：``platform.minimax.io/docs/llms.txt``（子域 + 子路径）
    与 ``platform.kimi.ai/docs/llms.txt``（跨注册域）。

    子路径靠 AI_PATH_CANDIDATES，子域靠 DOC_HOST_PREFIXES，跨注册域靠
    ``mine_declared_hosts``。三条缺一个就会把真文件读成「未采纳」。
    """
    assert "/docs/llms.txt" in discovery.AI_PATH_CANDIDATES
    prefixes = {p for p, _ in discovery.DOC_HOST_PREFIXES}
    assert "platform" in prefixes
    assert callable(discovery.mine_declared_hosts)
    # 朴素实现只探 apex/www 的两条根路径，所以这两个位置它一个都看不到。
    assert in_naive_probe_set("https://platform.minimax.io/docs/llms.txt", "minimax.io") is False
    assert in_naive_probe_set("https://platform.kimi.ai/docs/llms.txt", "moonshot.ai") is False


def test_doc_host_prefix_lists_agree_or_differ() -> None:
    """⚠️ 两份前缀清单并存（见交付说明 spec_gaps）：

    ``discovery.DOC_HOST_PREFIXES`` 有 16 项，而 §4.4:2280 的 ``_DOC_HOST_RE``
    覆盖不到 ``supportcenter``（简报说还缺 ``apidoc``，实测不缺 —— 正则里的
    ``apidocs?`` 把它盖住了）。并存会让「这是不是文档 host」的判定分叉。

    断言写成「差集要么为空、要么恰好是实测的那一项」——第 7 步统一之后这条依然绿，
    但任何**新的**分叉会让它红。
    """
    prefixes = {p for p, _ in discovery.DOC_HOST_PREFIXES}
    assert len(prefixes) == 16
    missing = {p for p in prefixes if not _DOC_HOST_RE.match(f"{p}.example.com")}
    assert missing in ({"supportcenter"}, set()), f"新的分叉：{missing}"


# --------------------------------------------------------------------------- #
# 第 7 步开：依赖 discover() 新签名的部分
# --------------------------------------------------------------------------- #


@step7_needed
def test_discover_accepts_the_four_new_parameters() -> None:
    """第 7 步：``discover(fetcher, domain, *, tiers, wellknown, budget, resolver)``。"""
    params = _discover_params()
    for name in STEP7_DISCOVER_PARAMS:
        assert name in params


@step7_needed
def test_tiered_probing_stops_early_within_budget() -> None:
    """第 7 步：tier 逻辑与预算上限（§3.7）。tier 1 命中真文件后不再打 tier 2/3。"""
    pytest.skip("第 7 步的 owner 写：需要 discover() 的 tiers/budget 语义定下来")


@step7_needed
def test_wellknown_position_is_probed_only_when_enabled() -> None:
    """第 7 步：``/.well-known/llms.txt`` 由 ``wellknown`` 参数开关。"""
    pytest.skip("第 7 步的 owner 写：需要 discover() 的 wellknown 语义定下来")


@step7_needed
def test_injected_resolver_is_used_instead_of_system_dns() -> None:
    """第 7 步：``resolver`` 注入后 discovery 不碰系统 DNS（断网/断 DNS 闸下可跑）。"""
    pytest.skip("第 7 步的 owner 写：需要 discover() 的 resolver 注入点定下来")
