"""L 组 · 确定性（§8.7 L 行 / 验收 A45 / 卡点 B18）。

「同一份 fixture 连跑两次，JSON 去掉 ``VOLATILE_JSON_FIELDS`` 后逐字节相同。」
这条是整份报告可信度的地基：报告里每个数字都要能被甲方复核，而一个跑两次
不一样的工具没法复核 —— 甲方改完再跑，分不清变化是自己改的还是工具抖的。

要挡的三个抖动源（各有一条断言）：

1. **时钟与环境** —— 剔掉 ``VOLATILE_JSON_FIELDS`` 那 9 个字段再比。
   :func:`test_volatile_fields_really_do_vary` 证明这个剔除**不是**装饰性的：
   不剔的话两次跑出来的 JSON 确实不同（实测 ``duration_s`` / ``elapsed_ms`` /
   ``fetched_at`` / ``from_cache`` / ``requests_made`` / ``resolver_used`` /
   ``scanned_at`` 七个键在 mistral.ai 的报告里都出现）。
2. **缓存造成的假绿** —— 卡点 B18 / §7.1 原话：「否则 L 组『连跑两次逐字节
   相同』可能只是因为第二次全命中缓存，是假绿」。所以第二次强制 ``--no-cache``，
   而 ``--replay-fixtures`` 本身就强制禁用缓存（:func:`test_replay_forces_cache_off`
   验证它真的实现了，不只是写在 ``--help`` 里）。
3. **随机数** —— 抽样必须带种子（卡点 A13'），对照探针 URL 在 replay 下必须
   由 fixture 反查而不是 ``secrets.token_hex``（§3.3 / §3.9 适配 #6）。

────────────────────────────────────────────────────────────────────────────
**为什么「跑两次」有两条测试**

* :func:`test_two_full_cli_runs_are_byte_identical` 走**真 CLI**（``cli.main``，
  参数解析 → 管线 → 写 JSON 全链路），因此也真守 2s/域的限速 ——
  一次 mistral.ai ≈ **287 秒**（实测），两次接近 10 分钟。这个代价换来的是
  「``--replay-fixtures`` 这条命令行本身是确定的」，包括 CLI 层的排序、
  写盘、格式化。所以它标 ``@pytest.mark.live``，默认不跑。
* :func:`test_two_pipeline_runs_are_byte_identical` 走 ``audit_domain()``，
  注入 fixture store 与一个掐掉了 sleep 的 limiter，四个域合计 < 3 秒，
  **进默认套件**。它测的是同一条性质里真正会坏的那部分（判定、归并、
  排序、id 生成），漏掉的只有 CLI 那一层薄壳。

两条都要有：只留快的，CLI 层的不确定性（比如某天有人在文件名里塞了时间戳）
没人挡；只留慢的，默认套件里这条性质等于没测 —— 而实测教训是「门禁全绿但
没人跑端到端」。
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from geo_audit import cli
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig, build_user_agent
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import FixtureStore, sample_deterministic
from geo_audit.models import VOLATILE_JSON_FIELDS
from geo_audit.pipeline import (
    AuditOptions,
    Report,
    StopTransport,
    audit_domain,
    cache_path,
)
from geo_audit.report.json_out import report_to_json, strip_volatile

CONTACT = "you@yourco.com"

#: 已验证 replay 能跑通的四个域（apex/www 根路径与对照探针快照都齐）。
#: 其余域可能缺根路径或对照探针的快照，补录需要真网络（第 4b 步）。
REPLAY_DOMAINS: tuple[str, ...] = ("mistral.ai", "modal.com", "rustdesk.com", "openstatus.dev")

#: 真 CLI 那条只跑旗舰域。多加一个域 ≈ 多 5 分钟（2s/域 × 请求数）。
LIVE_CLI_DOMAIN = "mistral.ai"

#: §2.1:510 那 9 个字段。**照抄规格，不从 models import** —— import 再断言
#: 「等于自己」是零信息量的，而这里要的是「名单被改动时必须两处一起改」。
FROZEN_VOLATILE_FIELDS: frozenset[str] = frozenset(
    {
        "scanned_at",
        "duration_s",
        "fetched_at",
        "elapsed_ms",
        "from_cache",
        "resolver_used",
        "resolved_ips",
        "probed_at",
        "requests_made",
    }
)


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #


def _canonical(payload: str) -> str:
    """报告 JSON → 可逐字节比对的规范串（剔掉易变字段 + 键排序）。"""
    return json.dumps(
        strip_volatile(json.loads(payload)),
        sort_keys=True,
        ensure_ascii=False,
        indent=2,
    )


def _all_keys(obj: Any, acc: set[str]) -> set[str]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            acc.add(key)
            _all_keys(value, acc)
    elif isinstance(obj, list):
        for value in obj:
            _all_keys(value, acc)
    return acc


@pytest.fixture(autouse=True)
def _no_pacing(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """掐掉限流器的 sleep（同 ``test_positions.py``）。

    ``live`` 那条**不掐** —— 它的全部意义就是「真 CLI、真限速、跑两遍还一样」。
    """
    if request.node.get_closest_marker("live") is not None:
        return
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _seconds: None)


@pytest.fixture(scope="module")
def store() -> FixtureStore:
    return FixtureStore.default()


@pytest.fixture
def replay(store: FixtureStore, tmp_path: Path) -> Iterator[Callable[[str], Report]]:
    """跑一次 replay 管线。装配照抄 ``pipeline.build_fetcher()``，只换 limiter。

    换 limiter 的原因：``build_fetcher`` 用的 ``InterruptibleLimiter`` 等在
    ``stop.wait(timeout=gap)`` 上，掐 ``time.sleep`` 掐不到它。缓存每次给一个
    新的 tmp 文件，所以「第二次全命中缓存」这种假绿在这里结构上就不可能 ——
    与 CLI 那条靠 ``--no-cache`` 达到的是同一件事。
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


# --------------------------------------------------------------------------- #
# 1. 易变字段名单
# --------------------------------------------------------------------------- #


def test_volatile_field_list_matches_the_spec() -> None:
    """§2.1:510 那 9 个字段，一个不多一个不少。

    加一个就等于「这个字段的确定性不再被守」，所以必须同时改规格与这里。
    """
    assert set(VOLATILE_JSON_FIELDS) == FROZEN_VOLATILE_FIELDS


def test_volatile_fields_really_do_vary(replay: Callable[[str], Report]) -> None:
    """剔除**不是**装饰性的：不剔的话两次跑出来的 JSON 确实不同。

    这条是整个 L 组的守卫的守卫。如果哪天 ``strip_volatile`` 被写成空操作、
    或者易变字段全被去掉了，「连跑两次逐字节相同」就会**因为无事可比**而变绿 ——
    那是最坏的一种假绿：闸门还在，但它不再检查任何东西。
    """
    first = report_to_json(replay(LIVE_CLI_DOMAIN))
    second = report_to_json(replay(LIVE_CLI_DOMAIN))
    assert first != second, "两次原始 JSON 居然相同 —— 易变字段可能已经从报告里消失"

    present = _all_keys(json.loads(first), set()) & set(VOLATILE_JSON_FIELDS)
    assert present, "报告里一个易变字段都没有，strip_volatile 无事可做"
    assert _canonical(first) == _canonical(second)


def test_strip_volatile_removes_the_keys_at_every_depth() -> None:
    """按键名剔、不看层级（``fetched_at`` 在 Evidence 与 HttpResponse 里都要剔）。"""
    nested = {
        "domain": "acme.test",
        "scanned_at": "2026-09-08 10:00 UTC",
        "positions": [{"probed_at": "x", "evidence": {"fetched_at": "y", "url": "u"}}],
    }
    stripped = strip_volatile(nested)
    assert _all_keys(stripped, set()) & set(VOLATILE_JSON_FIELDS) == set()
    assert stripped["domain"] == "acme.test"
    assert stripped["positions"][0]["evidence"]["url"] == "u"


# --------------------------------------------------------------------------- #
# 2. 缓存不许造成假绿（卡点 B18）
# --------------------------------------------------------------------------- #


class _CaughtOptionsError(Exception):
    """抓到 ``AuditOptions`` 就用它蹦出 CLI。

    **不能用 ``SystemExit``**：``cli.main()`` 把 ``SystemExit`` 接住并翻成退出码
    （``die()`` / argparse / ``--help`` 都走那条路），于是 ``pytest.raises``
    永远等不到 —— 实测就是这么红的。用一个自定义异常，``main`` 不认它，
    它会原样冒出来。
    """


def _captured_options(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> AuditOptions:
    """跑一遍 CLI 的参数装配，把它交给管线的 ``AuditOptions`` 抓出来。

    管线本身被换掉 —— 这里只想看 CLI 怎么解释 flag，不想跑扫描。
    """
    seen: list[AuditOptions] = []

    def fake_audit(options: AuditOptions, **_kwargs: object) -> Report:
        seen.append(options)
        raise _CaughtOptionsError

    monkeypatch.setattr(cli, "audit_domain", fake_audit)
    with pytest.raises(_CaughtOptionsError):
        cli.main(argv)
    assert seen, "CLI 没走到管线，参数装配没抓到"
    return seen[0]


def test_replay_forces_cache_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``--replay-fixtures`` **强制禁用缓存**（§7.1 那张表 / 卡点 B18）。

    规格把这条写成表格里的一行；这里验它真的落成了代码，而不只是 ``--help``
    里的一句承诺。判据两层：``use_cache`` 为假，且 ``cache_path()`` 指向一个
    一次性临时目录（不是用户的持久缓存目录）。
    """
    options = _captured_options(
        monkeypatch,
        [LIVE_CLI_DOMAIN, "--contact", CONTACT, "--replay-fixtures", "--out", str(tmp_path), "-q"],
    )
    assert options.replay_fixtures is True
    assert options.use_cache is False

    path = cache_path(options)
    assert path is not None
    assert "geo-audit-nocache-" in str(path), path


def test_no_cache_flag_also_forces_a_throwaway_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """L 组第二次跑用的就是这个 flag。默认（不传）才落到持久缓存。"""
    with_flag = _captured_options(
        monkeypatch,
        [LIVE_CLI_DOMAIN, "--contact", CONTACT, "--no-cache", "--out", str(tmp_path), "-q"],
    )
    assert with_flag.use_cache is False
    assert "geo-audit-nocache-" in str(cache_path(with_flag))

    default = _captured_options(
        monkeypatch, [LIVE_CLI_DOMAIN, "--contact", CONTACT, "--out", str(tmp_path), "-q"]
    )
    assert default.use_cache is True
    assert cache_path(default) is None, "默认要落到平台缓存目录，由 HttpCache 自己决定"


def test_two_throwaway_cache_paths_never_collide() -> None:
    """两次 ``--no-cache`` 拿到的是两个不同的临时库。

    共用一个的话，第二次跑照样会命中第一次的缓存 —— 正是 B18 要防的假绿。
    """
    options = AuditOptions(domain="acme.test", contact=CONTACT, use_cache=False)
    assert cache_path(options) != cache_path(options)


# --------------------------------------------------------------------------- #
# 3. 随机数必须带种子
# --------------------------------------------------------------------------- #


def test_sample_deterministic_is_stable_across_calls() -> None:
    """卡点 A13'：抽样带种子，两次结果相同。

    没种子的后果不是「抽得不好」，而是「补录一次换一批 URL」——
    ``fixtures/index.json`` 每次 diff 都是全量，且 L 组必红。
    """
    items = [f"https://docs.acme.test/page-{i}" for i in range(200)]
    first = sample_deterministic(items, 3, seed="acme.test|cluster-7")
    second = sample_deterministic(items, 3, seed="acme.test|cluster-7")
    assert first == second
    assert len(first) == 3
    assert first == sorted(first), "输出要排序，否则顺序本身是一个抖动源"


def test_sample_deterministic_differs_per_seed() -> None:
    """同域不同簇、异域同簇都要抽出不同的样本 —— 否则种子形同虚设。

    种子形状是 ``f"{domain}|{cluster_key}"``（§5.2）。
    """
    items = [f"https://docs.acme.test/page-{i}" for i in range(200)]
    same_domain_other_cluster = sample_deterministic(items, 3, seed="acme.test|cluster-8")
    other_domain = sample_deterministic(items, 3, seed="other.test|cluster-7")
    baseline = sample_deterministic(items, 3, seed="acme.test|cluster-7")
    assert baseline != same_domain_other_cluster
    assert baseline != other_domain


def test_sample_deterministic_returns_everything_below_the_limit() -> None:
    """不够 limit 就全给（且排序、去重）—— 这一支压根不碰随机数。"""
    items = ["https://b.test/2", "https://a.test/1", "https://b.test/2"]
    assert sample_deterministic(items, 60, seed="whatever") == [
        "https://a.test/1",
        "https://b.test/2",
    ]


def test_control_probe_url_is_deterministic_under_replay(store: FixtureStore) -> None:
    """对照探针 URL 在 replay 下由 fixture 反查，同 host 恒定、异 host 不同。

    §3.3 / §3.9 适配 #6：生产路径的 ``Fetcher.control_url()`` 用
    ``secrets.token_hex(12)``，**每次都不一样**（下一条断言证明它），
    所以 replay 必须注入 ``probe_url_provider`` —— 否则快照永远命不中，
    而且报告里的对照 URL 每跑一次都变，L 组必红。
    """
    target = "https://docs.mistral.ai/llms.txt"
    assert store.probe_url(target) == store.probe_url(target)
    # 同 host 的另一个位置复用同一条探针（host_profile 本身就按 host 缓存）
    assert store.probe_url(target) == store.probe_url("https://docs.mistral.ai/llms-full.txt")

    lenient_a = store.probe_url_lenient("https://never-recorded.invalid/x")
    lenient_b = store.probe_url_lenient("https://never-recorded.invalid/y")
    lenient_c = store.probe_url_lenient("https://other-host.invalid/x")
    assert lenient_a == lenient_b, "宽容版也必须按 host 确定"
    assert lenient_a != lenient_c, "不同 host 必须拿到不同探针，否则对照没有意义"


def test_production_control_url_is_intentionally_random() -> None:
    """反面：生产路径的对照 URL **故意**每次不同（不能被站点缓存/预测）。

    这条不是在测确定性，而是在说明上一条为什么必须存在 —— 两者是同一个
    设计决定的两半，写在一起免得有人把随机那半"顺手修成确定的"。
    """
    url = "https://acme.test/llms.txt"
    assert Fetcher.control_url(url) != Fetcher.control_url(url)


# --------------------------------------------------------------------------- #
# 4. 连跑两次逐字节相同 —— 快的那条（默认套件）
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("domain", REPLAY_DOMAINS)
def test_two_pipeline_runs_are_byte_identical(domain: str, replay: Callable[[str], Report]) -> None:
    """A45 的默认套件版：``audit_domain()`` 连跑两次，剔掉易变字段后逐字节相同。

    绕过限速（注入的 limiter 掐了 sleep），所以四个域合计 < 3 秒。
    真 CLI 那条见 :func:`test_two_full_cli_runs_are_byte_identical`（``-m live``）。
    """
    first = _canonical(report_to_json(replay(domain)))
    second = _canonical(report_to_json(replay(domain)))
    assert first == second


@pytest.mark.parametrize("domain", REPLAY_DOMAINS)
def test_finding_ids_are_stable_across_runs(domain: str, replay: Callable[[str], Report]) -> None:
    """A45：``finding_id`` 跨两次不变。

    单列出来是因为它有独立的后果：id 是 ``--ignore <ID>`` 的取值，也印在报告
    卡片右上角。抖一次，甲方昨天写进 CI 的抑制清单今天全部失效。
    """
    first = [f.finding_id for f in replay(domain).findings]
    second = [f.finding_id for f in replay(domain).findings]
    assert first == second
    assert len(set(first)) == len(first), "同一次跑里 finding_id 撞了"


def test_position_and_rootcause_order_is_stable(replay: Callable[[str], Report]) -> None:
    """顺序也是内容：位置表与根因表的排序不许随字典遍历顺序抖。

    这条被 :func:`test_two_pipeline_runs_are_byte_identical` 覆盖了一部分，
    但单列出来能让失败信息直接指出「是顺序变了」而不是「几千行 JSON 有差异」。
    """
    first = replay(LIVE_CLI_DOMAIN)
    second = replay(LIVE_CLI_DOMAIN)
    assert [p.probe_url for p in first.positions] == [p.probe_url for p in second.positions]
    assert [r.fix_once for r in first.root_causes] == [r.fix_once for r in second.root_causes]
    assert [e.url for e in first.excluded] == [e.url for e in second.excluded]


# --------------------------------------------------------------------------- #
# 5. 连跑两次逐字节相同 —— 真 CLI 那条（-m live）
# --------------------------------------------------------------------------- #


@pytest.fixture
def live_selected(pytestconfig: pytest.Config) -> None:
    """``live`` 标记本身只是**分类**，pytest 不会因为它就跳过。

    ``pyproject.toml`` 把 ``live`` 注册成「默认不跑（-m live 显式开启）」，
    但那句话没有执行点：不带 ``-m`` 的 ``pytest`` 会把 live 那条也跑掉 ——
    于是 §9 第 17 步的自验命令 ``uv run pytest`` 会卡十分钟。仓库里在本步之前
    没有任何 live 测试，所以这个口子一直没露出来。

    ``tests/conftest.py`` 不是本步的文件（不许改），所以守卫落在这里：
    只有命令行显式选了 live 才真跑。``-m "not live"`` 由 pytest 自己就
    deselect 了，这个 fixture 根本不会被求值。
    """
    expression = (pytestconfig.getoption("-m", default="") or "").replace(" ", "")
    if "live" not in expression or "notlive" in expression:
        pytest.skip(
            "真 CLI 那条要 -m live 显式开启：它守 2s/域限速，一次 mistral.ai ≈ 287s，"
            "两次接近 10 分钟。快的那条（test_two_pipeline_runs_are_byte_identical）"
            "已经在默认套件里"
        )


@pytest.mark.live
def test_two_full_cli_runs_are_byte_identical(live_selected: None, tmp_path: Path) -> None:
    """A45 的真 CLI 版：``geo-audit <域> --replay-fixtures`` 连跑两次逐字节相同，
    **第二次强制 ``--no-cache``**。

    标 ``live`` 的唯一原因是**时间**：真 CLI 守 2s/域的限速，一次 mistral.ai
    实测 287 秒，两次接近 10 分钟。它不打真网络（``--replay-fixtures`` 全程
    读冻结快照），所以在离线机器上跑 ``-m live`` 也能过。

    ``--no-cache`` 是卡点 B18 点名要的：replay 本身已经强制禁用缓存
    （:func:`test_replay_forces_cache_off` 验过），这里再显式传一次，
    是为了让「第二次不许吃缓存」这条纪律写在命令行上而不是靠实现细节兜着 ——
    哪天 replay 的强制禁用被人放松了，这条命令行照样是对的。

    跑法::

        GEO_AUDIT_FORBID_NETWORK=1 GEO_AUDIT_FORBID_DNS=1 \\
          .venv/bin/python -m pytest tests/test_determinism.py -m live -q
    """
    outputs: list[str] = []
    for run_index, extra in enumerate(([], ["--no-cache"])):
        out_dir = tmp_path / f"run{run_index}"
        code = cli.main(
            [
                LIVE_CLI_DOMAIN,
                "--contact",
                CONTACT,
                "--replay-fixtures",
                "--format",
                "json",
                "--out",
                str(out_dir),
                "-q",
                *extra,
            ]
        )
        # 0 = 无发现、1 = 有发现、2 = 结论不可信。三者都算「跑完了」；
        # 3（不可达）与 4（用法错误）说明这条测试的前提就不成立。
        assert code in (0, 1, 2), f"第 {run_index + 1} 次跑退出码 {code}"
        written = sorted(out_dir.rglob("*.json"))
        assert len(written) == 1, f"期望恰好一份 JSON，实得 {written}"
        outputs.append(_canonical(written[0].read_text(encoding="utf-8")))

    assert outputs[0] == outputs[1]
