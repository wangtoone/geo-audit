"""F 组 · v1 范围守门（§8.7 F 行 / 验收 A38 / 部分 A6）。

**这个文件的全部意义是「变红」。** 方案 §2.5:942 在 ``FindingKind`` 上方写着：

    ⚠️ 冻结集合。**多一个就让 tests/test_v1_scope.py 变红**，迫使加范围必须显式
    改测试并给出假阳性率。这是防 v1 范围被悄悄放宽的机器闸门。

所以下面每条断言都不是「检查功能对不对」，而是「检查有没有人在没走流程的情况下
把范围拉宽了」。断言一旦挡路，正确做法是**改这个文件并附上新范围的假阳性率**，
不是把断言删掉。

守三样东西：

1. **``FINDING_KINDS`` 恰好 5 个**，且它的三份副本（``FindingKind`` Literal、
   ``FINDING_KINDS`` frozenset、``schema/report-1.schema.json`` 的 ``$defs.FindingKind``
   枚举）逐字相同 —— 三份里任意一份漂了，对外契约就和代码打架。
2. **明确砍掉的两整类没偷偷做**：
   * **过期信号（C2 stale）** —— 实测 21 条里推翻 1、降级 3、重复计 3，判据是
     「页面上的年份/版本看着旧」，没有客观裁判，砍掉。
   * **事实冲突（C4，跨页比对）** —— 自动化版从没跑过，假阳性率是**空的**。
     方案 §0 的规矩是「没有实测假阳性率的检查不许进 v1」，所以砍掉。
   守法：扫**冻结 id 命名空间**（FINDING_KINDS / valid_ids / Reason / Stage /
   PositionClass / Severity）里有没有这两类的词根，再扫 ``geo_audit.checks`` 里
   有没有第五个 ``check_*`` 子检查。**不扫散文** —— ``jsrender.py`` 与
   ``discovery.py`` 的注释里正好写着「这两类被砍了」，扫散文会把「声明砍掉」
   本身当成命中（详见 :data:`CUT_SCOPE_MARKERS` 的说明）。
3. **``CHECK_IDS`` 只有 ai_path 与 dead_links**，``RULE_REGISTRY`` 恰好
   ai_path 4 条 + dead_links 23 条（§5.3 / 卡点 B19）。

外加 A6 的一半：``models.py`` 是数据结构的唯一定义处。用 AST 数 ``ClassDef``
而不是 ``grep -c "class Verdict"`` —— 实测 ``grep`` 会把 ``models.py:599`` 与
``checks/ai_path.py:93`` 那两条「验收 A6 用 grep 数这个」的注释本身数进去
（原样跑规格给的 grep 命令，Severity 与 PositionClass 各得 3 条命中）。
A6 的意思是「类只定义一处」，AST 数的就是这个，且不会被注释骗。
（A7「``Position(`` 只在 ``build_positions()``」已由 ``test_positions.py`` 守着，
这里不重复。）
"""

from __future__ import annotations

import ast
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, get_args

import httpx
import pytest

import geo_audit.fetch.ratelimit as ratelimit_mod
from geo_audit.checks import ai_path as ai_path_mod
from geo_audit.checks import dead_links as dead_links_mod
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig, build_user_agent
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import FixtureStore
from geo_audit.models import (
    FINDING_KINDS,
    FindingKind,
    PositionClass,
    Reason,
    Severity,
    Stage,
)
from geo_audit.pipeline import (
    AI_PATH_RULES,
    CHECK_IDS,
    RULE_REGISTRY,
    AuditOptions,
    Report,
    StopTransport,
    audit_domain,
    valid_ids,
)

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
SCHEMA = REPO / "schema" / "report-1.schema.json"
CONTACT = "you@yourco.com"

# --------------------------------------------------------------------------- #
# 冻结常量：**照抄规格，不从被测代码 import**
# --------------------------------------------------------------------------- #
# 从 models 里 import 再断言「等于自己」是零信息量的。所以这里把 §2.5:942 的
# 五个字面量抄一遍，让「改 models 里那个集合」必然与这里打架。

FROZEN_FINDING_KINDS: frozenset[str] = frozenset(
    ("soft_404", "llms_full_fake", "index_link_dead", "md_unfulfilled", "dead_link")
)

#: §5.3 / 卡点 B19：两个 check、4 + 23 条规则。
FROZEN_CHECK_IDS: tuple[str, ...] = ("ai_path", "dead_links")
FROZEN_AI_PATH_RULES: tuple[str, ...] = ("soft404", "llms_full", "index_links", "md_convention")
FROZEN_DEAD_LINK_RULE_COUNT = 23

#: §6.1 链路图六格 = Stage 的六个取值。第七段就是新范围。
FROZEN_STAGES: tuple[str, ...] = (
    "discovery",
    "index_file",
    "fulltext",
    "index_links",
    "md_channel",
    "human_path",
)

#: 被砍两类的词根。**刻意不含裸 "stale" 与裸 "conflict"**：
#: ``rootcause.py`` 的缺陷指纹里有 ``stale_path_after_migration``（文档迁移后的
#: 旧路径，是死链的根因，不是「内容过期信号」），``dead_links`` 规则里有
#: ``presigned_expiring``（预签名 URL 自带过期时间）—— 两者都在 v1 范围内且
#: 名正言顺。裸词根会把它们误杀，于是这条闸门会被人以「误报太多」为由删掉，
#: 那就等于没有闸门。所以只收窄到真正指向被砍两类的组合词。
CUT_SCOPE_MARKERS: tuple[str, ...] = (
    # C2 过期信号（整类砍）
    "stale_content",
    "stale_signal",
    "stale_copy",
    "content_stale",
    "outdated",
    "out_of_date",
    "expired_content",
    "year_drift",
    "old_year",
    "version_drift",
    "last_updated",
    "freshness",
    # C4 事实冲突 / 跨页比对（整类砍）
    "fact_conflict",
    "conflicting_fact",
    "cross_page",
    "crosspage",
    "contradict",
    "price_mismatch",
    "inconsistent_across",
)

#: v1 的四个子检查，一个不多。第五个 ``check_*`` 就是新范围。
FROZEN_SUBCHECKS: frozenset[str] = frozenset(
    ("check_ai_paths", "check_llms_full", "check_index_links", "check_md_convention")
)

#: A6 点名的七个：五个判定枚举 + LinkContext + Exclusion。
#: （``EligibilityExclusion`` 是另一个名字，A6 明确允许并存。）
A6_NAMES: tuple[str, ...] = (
    "Verdict",
    "LinkState",
    "Status",
    "Severity",
    "PositionClass",
    "LinkContext",
    "Exclusion",
)


# --------------------------------------------------------------------------- #
# 1. FINDING_KINDS 的三份副本必须逐字相同
# --------------------------------------------------------------------------- #


def test_finding_kinds_is_exactly_the_frozen_five() -> None:
    """A38：``set(FINDING_KINDS)`` 恰好 5 个。

    多一个就红。加范围的正确姿势：改 :data:`FROZEN_FINDING_KINDS`，并在 PR 里
    附上新那类在实测语料上的假阳性率 —— 这是 §0 的准入条件，不是形式主义。
    """
    assert set(FINDING_KINDS) == FROZEN_FINDING_KINDS
    assert len(FINDING_KINDS) == 5


def test_finding_kind_literal_matches_the_frozenset() -> None:
    """``FindingKind`` Literal 与 ``FINDING_KINDS`` frozenset 是同一份内容的两种写法。

    它们在 models.py 里是**两条独立的字面量**（一个给 mypy，一个给运行期），
    所以会各自漂移。这条断言把两者钉在一起。
    """
    assert set(get_args(FindingKind)) == FROZEN_FINDING_KINDS


def test_schema_finding_kind_enum_matches_the_frozenset() -> None:
    """对外契约（schema）里的第三份副本也必须一致。

    ``schema/report-1.schema.json`` 是唯一对外契约（§2.8 删掉了 ``FindingDict``），
    CI 用 ``check-jsonschema`` 校验真报告。如果它比代码宽，一个范围外的 kind
    能通过校验；如果它比代码窄，真报告会校验失败。两个方向都要挡。
    """
    doc = json.loads(SCHEMA.read_text(encoding="utf-8"))
    enum = doc["$defs"]["FindingKind"]["enum"]
    assert set(enum) == FROZEN_FINDING_KINDS
    assert len(enum) == len(FROZEN_FINDING_KINDS), "schema 枚举里有重复项"


# --------------------------------------------------------------------------- #
# 2. 砍掉的两整类没偷偷做
# --------------------------------------------------------------------------- #


def _frozen_id_namespaces() -> dict[str, tuple[str, ...]]:
    """全部「对外可见的 id / 枚举取值」命名空间。

    只扫这些**闭集合**，不扫源码散文。理由见模块 docstring：注释里写着
    「stale 与 fact conflict 被砍了」，扫散文会把声明本身当成命中。
    而一个偷偷加进来的检查必然要在这些命名空间里露头 —— 它得有 kind、
    有 rule id、有 reason 才能进报告。
    """
    return {
        "FINDING_KINDS": tuple(sorted(FINDING_KINDS)),
        "valid_ids()": valid_ids(),
        "Reason": tuple(get_args(Reason)),
        "Stage": tuple(s.value for s in Stage),
        "PositionClass": tuple(p.value for p in PositionClass),
        "Severity": tuple(s.value for s in Severity),
        "DEAD_LINK_RULE_IDS": tuple(dead_links_mod.DEAD_LINK_RULE_IDS),
    }


@pytest.mark.parametrize("namespace", sorted(_frozen_id_namespaces()))
def test_cut_scope_has_no_id_anywhere(namespace: str) -> None:
    """过期信号与事实冲突这两整类，在任何 id 命名空间里都没有落脚点。

    实测把它们砍了的理由（写在这里，因为断言本身看不出理由）：

    * **过期信号 21 条**：复核后推翻 1 条、降级 3 条、重复计 3 条 —— 判据是
      「页面上的年份看着旧」，没有客观裁判，剩下的样本也撑不起一个检查。
    * **事实冲突**：自动化版从没跑过，假阳性率是**空的**。§0 不许没有实测
      假阳性率的检查进 v1。
    """
    values = _frozen_id_namespaces()[namespace]
    hits = [
        (value, marker)
        for value in values
        for marker in CUT_SCOPE_MARKERS
        if marker in value.lower()
    ]
    assert hits == [], f"{namespace} 里出现了被砍范围的 id：{hits}"


def test_subchecks_are_exactly_the_four_v1_ones() -> None:
    """``geo_audit.checks`` 里的 ``check_*`` 入口恰好四个。

    第五个子检查（比如 ``check_stale_signals`` / ``check_fact_conflicts``）
    一落地，这条就红。这是「整类没偷偷做」最直接的机器判据 —— 一个检查
    总得有个入口函数。
    """
    found = {
        name
        for module in (ai_path_mod, dead_links_mod)
        for name in vars(module)
        if name.startswith("check_") and callable(getattr(module, name))
    }
    assert found == FROZEN_SUBCHECKS


def test_stage_enum_is_still_the_six_chain_cells() -> None:
    """链路图六格（§6.1）就是范围的可视化。第七段 = 新范围。

    过期信号本来会是「⑦ 内容新鲜度」那一格；这条断言让它加不进来而不被发现。
    """
    assert tuple(s.value for s in Stage) == FROZEN_STAGES


# --------------------------------------------------------------------------- #
# 3. CHECK_IDS / RULE_REGISTRY
# --------------------------------------------------------------------------- #


def test_check_ids_are_exactly_two() -> None:
    assert CHECK_IDS == FROZEN_CHECK_IDS


def test_rule_registry_is_four_plus_twentythree() -> None:
    """§5.3 / 卡点 B19：ai_path 4 条 + dead_links 23 条，一条不多一条不少。"""
    assert set(RULE_REGISTRY) == set(FROZEN_CHECK_IDS)
    assert RULE_REGISTRY["ai_path"] == FROZEN_AI_PATH_RULES
    assert len(RULE_REGISTRY["dead_links"]) == FROZEN_DEAD_LINK_RULE_COUNT
    assert len(set(RULE_REGISTRY["dead_links"])) == FROZEN_DEAD_LINK_RULE_COUNT, "有重复 rule id"


def test_valid_ids_is_two_checks_plus_twentyseven_rules() -> None:
    """``--list-rules`` 打印的就是它：2 + 4 + 23 = 29 个合法 id，无重复。"""
    ids = valid_ids()
    assert len(ids) == 2 + 4 + FROZEN_DEAD_LINK_RULE_COUNT == 29
    assert len(set(ids)) == len(ids)
    assert all(i.split(".", 1)[0] in FROZEN_CHECK_IDS for i in ids)


def test_dead_link_rules_have_a_single_definition_point() -> None:
    """``RULE_REGISTRY["dead_links"]`` 直接**是** ``dead_links.DEAD_LINK_RULE_IDS``。

    不是「内容相等」而是同一个对象：内容相等允许有第二份字面量，那份会漂。
    ``checks/dead_links.py:138`` 的注释也说了它是唯一定义处，这里把它钉住。
    ``AI_PATH_RULES`` 同理由 pipeline 独占。
    """
    assert RULE_REGISTRY["dead_links"] is dead_links_mod.DEAD_LINK_RULE_IDS
    assert RULE_REGISTRY["ai_path"] is AI_PATH_RULES


# --------------------------------------------------------------------------- #
# 4. A6 的一半：数据结构只在 models.py 定义一处
# --------------------------------------------------------------------------- #


def _class_defs() -> dict[str, list[str]]:
    """``src/`` 下每个类名 → 定义它的文件（相对路径）列表。AST，不是 grep。"""
    out: dict[str, list[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                out.setdefault(node.name, []).append(str(path.relative_to(REPO)))
    return out


@pytest.mark.parametrize("name", A6_NAMES)
def test_a6_named_types_are_defined_once_and_in_models(name: str) -> None:
    """A6 点名的七个类型，各恰好 1 处定义，且都在 ``models.py``。"""
    where = _class_defs().get(name, [])
    assert where == ["src/geo_audit/models.py"], f"{name} 的定义处：{where}"


def test_every_models_class_is_defined_exactly_once_in_src() -> None:
    """A6 的一般化：``models.py`` 里定义的每个类，在 ``src/`` 全域只有那一处。

    比逐个点名强：新加的数据结构自动进这条闸门，不用记得来这里加名字。
    第 3 步的 ``fetch/models.py`` 是 re-export shim（``from ... import``，
    不是 ``class``），所以不会被数进来 —— 这正是 shim 的设计意图。
    """
    defs = _class_defs()
    models_rel = "src/geo_audit/models.py"
    models_classes = sorted(n for n, where in defs.items() if models_rel in where)
    assert len(models_classes) >= 17, f"models.py 里只解析到 {len(models_classes)} 个类"
    dupes = {n: defs[n] for n in models_classes if len(defs[n]) != 1}
    assert dupes == {}, f"这些 models 类型在 src/ 里有第二处定义：{dupes}"


# --------------------------------------------------------------------------- #
# 5. 全管线不产出范围外的 finding
# --------------------------------------------------------------------------- #
#
# 上面全是静态断言。静态断言挡不住「常量没动，但 finding 的 kind 是运行期拼出来
# 的」这种情况 —— ``Finding.kind`` 没有 ``__post_init__`` 校验（models.py 实测），
# 所以只有真跑一遍管线才知道产出的 kind 到底在不在集合里。
#
# ⚠️ 限速：一次真 CLI 跑 mistral.ai 要 ~287s（2s/域守着）。这里注入一个
# 掐掉了 sleep 的 limiter，四个域合计 < 2s。限速逻辑本身在
# ``test_politeness.py`` 与 ``test_infra.py`` 里有专门断言，不靠这里覆盖。

#: 四个已验证 replay 能跑通的域（apex/www 根路径与对照探针的快照都齐）。
REPLAY_DOMAINS: tuple[str, ...] = ("mistral.ai", "modal.com", "rustdesk.com", "openstatus.dev")

#: §8.7 F 行点名的两个域。**当前 fixtures 里没有它们的根路径快照**
#: （``fixtures/index.json`` 只有 ``sso.teachable.com`` 两条，onfleet 零条），
#: 补录需要真网络（第 4b 步）。所以点名的那两条走 skipif，录进来自动生效。
NAMED_CUT_SCOPE_DOMAINS: tuple[str, ...] = ("teachable.com", "onfleet.com")


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """只掐限流器的 sleep，限流逻辑照常跑（同 ``test_positions.py`` 的做法）。"""
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _seconds: None)


@pytest.fixture(scope="module")
def store() -> FixtureStore:
    return FixtureStore.default()


@pytest.fixture
def replay(store: FixtureStore, tmp_path: Path) -> Iterator[Any]:
    """跑一次 replay 管线。装配照抄 ``pipeline.build_fetcher()``，只换 limiter。

    换 limiter 的原因：``build_fetcher`` 用的 ``InterruptibleLimiter`` 等在
    ``stop.wait(timeout=gap)`` 上，掐 ``time.sleep`` 掐不到它。
    """
    made: list[Fetcher] = []

    def run(domain: str) -> Report:
        options = AuditOptions(
            domain=domain,
            contact=CONTACT,
            replay_fixtures=True,
            use_cache=False,
        )
        fetcher = Fetcher(
            FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
            HttpCache(tmp_path / f"cache{len(made)}.sqlite3", ua_profile=build_user_agent(CONTACT)),
            DomainLimiter(2.0),
            transport=StopTransport(store.transport(strict=False), threading.Event()),
            probe_url_provider=store.probe_url_lenient,
            resolver=store.resolver(),
        )
        made.append(fetcher)
        return audit_domain(options, fetcher=fetcher, store=store, resolver=store.resolver())

    yield run
    for fetcher in made:
        fetcher.close()


def _assert_in_scope(report: Report) -> None:
    for finding in report.findings:
        assert finding.kind in FROZEN_FINDING_KINDS, f"{finding.finding_id} 的 kind 出了范围"
        prefix = finding.check_id.split(".", 1)[0]
        assert prefix in FROZEN_CHECK_IDS, f"{finding.check_id} 不属于任何注册的 check"
        blob = f"{finding.kind}|{finding.check_id}".lower()
        assert not any(m in blob for m in CUT_SCOPE_MARKERS), f"{finding.check_id} 像被砍的那两类"


@pytest.mark.parametrize("domain", REPLAY_DOMAINS)
def test_pipeline_never_emits_a_finding_outside_the_frozen_scope(domain: str, replay: Any) -> None:
    """A38 的运行期一半：四个域全管线跑完，一条范围外的 finding 都没有。

    ``check_id`` 只断言**前缀**在 ``CHECK_IDS`` 里，不断言整串在 ``valid_ids()``
    里：``ai_path.llms_full_byte_copy``（实测 mistral / modal / rustdesk /
    openstatus 都产它）比 ``RULE_REGISTRY`` 里的 ``ai_path.llms_full`` 更细一层，
    这是 ``checks/ai_path.py:707`` 明写的设计（"具体规则放 check_id"），
    不是漂移。范围守门要守的是「有没有第三个 check」，那由前缀断言守住。
    """
    report = replay(domain)
    _assert_in_scope(report)
    assert report.counts.llm_calls == 0, "v1 是零 LLM 的（A22）"


@pytest.mark.parametrize("domain", NAMED_CUT_SCOPE_DOMAINS)
def test_named_domains_produce_no_cut_scope_findings(domain: str, replay: Any) -> None:
    """§8.7 F 行点名的两条：teachable.com 不产 ``{year}``/过期类，
    onfleet.com 不产 conflict 类。

    这两个域的根路径快照现在**没录**（见 :data:`NAMED_CUT_SCOPE_DOMAINS` 的注释），
    补录要真网络，所以这条会 skip 并说清缺什么。录进来之后自动生效、无需改代码。
    """
    store_ = FixtureStore.default()
    missing = [u for u in (f"https://{domain}/", f"https://www.{domain}/") if not store_.has(u)]
    if missing:
        pytest.skip(
            f"fixtures 里缺 {domain} 的根路径快照 {missing}；"
            "补录需要真网络（第 4b 步：scripts/capture_fixtures.py --live）"
        )
    _assert_in_scope(replay(domain))


def test_the_pacing_shortcut_did_not_leak_into_src() -> None:
    """上面那个 ``_no_pacing`` 只许在测试里存在。

    ``ratelimit`` 模块必须仍然握着真 ``time`` 模块（monkeypatch 是 per-test 的）：
    如果哪天有人为了让测试快而在 ``src/`` 里加了「测试模式不限速」的开关，
    合规声明就成了假话。这条是那种开关的探测器。
    """
    assert ratelimit_mod.time.sleep is not None
    assert getattr(ratelimit_mod.time, "__name__", "") == "time"
    src_text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(SRC.rglob("*.py")))
    for smell in ("PYTEST_CURRENT_TEST", "GEO_AUDIT_NO_RATE_LIMIT", "if TESTING"):
        assert smell not in src_text, f"src/ 里出现了绕限速的测试后门：{smell}"


def test_httpx_is_the_only_transport_the_scope_allows() -> None:
    """守门的边角：范围里没有「浏览器渲染」这一档（``--render`` 未实现且退非 0）。

    放在 F 组是因为它也是范围问题：JS 渲染一旦真做了，soft404 的判据、
    假阳性率、合规声明（不伪装浏览器）三样全部要重估。
    """
    assert issubclass(httpx.MockTransport, httpx.BaseTransport)
    jsrender = (SRC / "geo_audit" / "fetch" / "jsrender.py").read_text(encoding="utf-8")
    for engine in ("playwright", "selenium", "pyppeteer", "puppeteer"):
        assert f"import {engine}" not in jsrender, f"jsrender 真接了 {engine}"
