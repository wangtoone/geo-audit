"""编排管线（第 16 步 · §7）——把六段检查串成一份 ``Report``。

本模块是 **``Position(`` 的唯一合法出现处**（§2.9:1190 / 验收 A7）。
``Report.positions`` 只能由 :func:`build_positions` 产生：报告层只读，绝不新造。
第 6 步的 ``checks/ai_path.py`` 产出的是 ``PositionSeed``（原料），本模块把 seed
一对一变成 ``Position``。

中断路径（§7.5 / 卡点 B24）三条硬约束：

* **不装 signal handler** —— ``signal.SIGINT`` handler 在 worker 线程里不会触发
  （Python 只在主线程投递信号），装了也是假的。这里用协作式取消标志
  :class:`RunState`.``stop``。
* **可中断等待** —— 限速等待走 ``stop.wait(timeout=remaining)``
  （:class:`InterruptibleLimiter`），不用 ``time.sleep``。
* **位置骨架先建后填** —— :func:`skeleton_seeds` 在任何请求之前就把全部格子造好，
  再把结论填进去；没填上的格子留 ``Status.UNKNOWN`` + ``unknown_reason``。
  所以恒等式 ``pass + fail + unknown + na == positions`` 在中断报告上照样成立。
"""

from __future__ import annotations

import difflib
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit

import httpx

from geo_audit.checks import dead_links as dl
from geo_audit.checks.ai_path import (
    IndexLinkReport,
    ai_path_position_seeds,
    check_ai_paths,
    check_llms_full,
    check_md_convention,
    evidence_of,
    findings_from_index_report,
    has_ai_channel,
    parse_index_links,
    probe_index_links,
)
from geo_audit.checks.fix_candidates import (
    CandidateQuality,
    CandidateResult,
    find_fix_candidate,
    grade_candidates,
)
from geo_audit.extract import LinkTarget, PageExtraction, extract_page
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig, build_user_agent
from geo_audit.fetch.denoise import EligibilityExclusion, position_class_of
from geo_audit.fetch.discovery import DEFAULT_TIERS, discover
from geo_audit.fetch.ratelimit import MIN_INTERVAL_SECONDS, DomainLimiter, registrable_domain
from geo_audit.fetch.resolve import HostResolver
from geo_audit.fixhint import suggest_fix
from geo_audit.fixtures import FixtureError, FixtureStore, sample_deterministic
from geo_audit.models import (
    DENOISE_RULESET_VERSION,
    POSITION_LABEL,
    SCHEMA_VERSION,
    SEVERITY_BY_POSITION,
    SEVERITY_RANK,
    STAGE_LABEL,
    TOOL_VERSION,
    UNKNOWN_REMEDY,
    Counts,
    Coverage,
    CoverageGap,
    Evidence,
    Exclusion,
    Expect,
    Finding,
    Fragility,
    HostProfile,
    HostRole,
    LinkState,
    NaiveContrast,
    Position,
    PositionClass,
    PositionSeed,
    Probe,
    Report,
    RootCause,
    Severity,
    SiteMap,
    Stage,
    Status,
    Verdict,
    VerdictKind,
    verdict_to_status,
)
from geo_audit.naive import NaiveEmulator, divergences
from geo_audit.rootcause import (
    DEAD_LINK_CHECK_ID,
    DeadInstance,
    DeadTarget,
    ProbeLedger,
    fold_instances,
    merge_root_causes,
    url_host,
)

# ═════════════════════════════════════════════════════════════════════════════
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║ 占位区结束 —— PLACEHOLDER BLOCK END                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
# ═════════════════════════════════════════════════════════════════════════════


# --------------------------------------------------------------------------- #
# 规则注册表（§5.3:2808）—— ``--list-rules`` / ``--only`` / ``--skip`` 的唯一真源
# --------------------------------------------------------------------------- #

#: ai_path 的四条规则 id（§5.3）。dead_links 那 23 条由 checks/dead_links.py 导出，
#: 这里只拼装，不重写（那边是唯一定义处）。
AI_PATH_RULES: tuple[str, ...] = ("soft404", "llms_full", "index_links", "md_convention")

CHECK_IDS: tuple[str, ...] = ("ai_path", "dead_links")

RULE_REGISTRY: dict[str, tuple[str, ...]] = {
    "ai_path": AI_PATH_RULES,
    "dead_links": dl.DEAD_LINK_RULE_IDS,
}


def valid_ids() -> tuple[str, ...]:
    """全部合法的检查 id 与规则 id，顺序稳定（``--list-rules`` 也按它打印）。"""
    out: list[str] = []
    for check in CHECK_IDS:
        out.append(check)
        out.extend(f"{check}.{rule}" for rule in RULE_REGISTRY[check])
    return tuple(out)


def nearest_ids(bad: str, *, limit: int = 3) -> tuple[str, ...]:
    """给非法 id 挑最接近的三个候选（§5.3:2832）。"""
    return tuple(difflib.get_close_matches(bad, valid_ids(), n=limit, cutoff=0.0))


# --------------------------------------------------------------------------- #
# CLI 默认值与上限（§7.1:3278-3364 照抄）
# --------------------------------------------------------------------------- #

DEFAULT_OUT_DIR = "./geo-audit-report"
DEFAULT_FORMAT = "html,json"
DEFAULT_MAX_LINKS = 300
DEFAULT_MAX_REQUESTS = 120
INDEX_LINKS_FULL_DEFAULT_THRESHOLD = 120
DEFAULT_RATE = 0.5
DEFAULT_TIMEOUT = 20.0
DEFAULT_RETRIES = 2
DEFAULT_RESOLVERS = "8.8.8.8,1.1.1.1"
DEFAULT_FAIL_ON = "low"
CONTACT_ENV = "GEO_AUDIT_CONTACT"
RATE_TOO_FAST_MSG = "--rate 只能调慢。合规约束是单域名 ≤1 请求/2 秒（0.5 req/s），不可绕过。"

#: §7.1:3349 的七个退出码。
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_UNTRUSTED = 2
EXIT_UNREACHABLE = 3
EXIT_USAGE = 4
EXIT_RENDER_UNIMPLEMENTED = 4  # ``--render`` 未实现：用法错误的一种（见交付说明）
EXIT_INTERRUPTED = 130

#: §0.3 的「我们不查什么」八行，报告 C-4 区与 coverage.not_checked 共用。
NOT_CHECKED: tuple[str, ...] = (
    "内容是否过期（通用「旧年份」正则两批样本 134 命中 0 真信号 / 296 命中 2 真信号）",
    "事实是否自相冲突",
    "锚点（#fragment）是否腐烂",
    "定价页 ↔ 文档的口径比对",
    "定期扫描 / 监控",
    "托管 web 版（会让 --contact 这条合规约束当场失效）",
    "Playwright 渲染（合规不绕 WAF，且实测只有 2/72 = 2.8% 盲区）",
    "--serve 本地服务",
)

CHECKED_LABELS: dict[str, str] = {
    "ai_path": "AI 路径体检（llms.txt / llms-full.txt / .md 通道，每条判定跟一个对照探测）",
    "dead_links": "死链（只报人和 AI 都会点、点了就 404 的，按根因归并、按位置分级）",
}

#: §7.5(4) 的中断通栏，三行固定文案。
INTERRUPT_BANNER_TEMPLATE = (
    "⚠ 扫描被中断（Ctrl-C）。已完成 {done} 个位置，未跑到 {missing} 个。\n"
    "下面的「无法判断」里有 {missing} 个只是没轮到，不是你的站有问题。\n"
    "接着跑：geo-audit {domain} --contact {contact} （命中缓存，不会重打已完成的请求）"
)


# --------------------------------------------------------------------------- #
# 中断路径的基础件（§7.5:3535 照抄）
# --------------------------------------------------------------------------- #


# ruff 的 N818 要求异常类名以 Error 结尾。这一条**只对 Cancelled 例外**：
# 规格 §7.5:3545 逐字写的就是 `class Cancelled(Exception): ...`，而铁律 8 要求
# 规格给了具体名字的照抄。姊妹类 DomainUnreachableError 没有这层背书，已按 N818 改名
# （同轮的 json_out.py 遇到同一条规则也是选择改名成 SchemaMismatchError）。
class Cancelled(Exception):  # noqa: N818 —— 规格 §7.5:3545 逐字指名，见上方注释
    """协作式取消：取消标志置起后，下一个请求发出前抛它。"""


class DomainUnreachableError(Exception):
    """apex 与 www 都解析失败或连不上（退出码 3，**不生成报告**）。"""


@dataclass
class RunState:
    """一次扫描的可变状态。

    §7.5:3538 给的三个字段是 ``stop`` / ``done_positions`` / ``lock``。这里把
    ``done_positions: list[Position]`` 换成 ``results: dict[str, PositionResult]``：
    验收 A7 只许 :func:`build_positions` 里出现 ``Position(``，所以 stage 代码
    根本造不出 ``Position`` 对象，只能交回「填格子的原料」。其余字段是把部分
    结果攒起来给 :func:`_assemble`（中断时也要出报告，所以必须可增量累积）。
    """

    stop: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    skeleton: list[PositionSeed] = field(default_factory=list)
    results: dict[str, PositionResult] = field(default_factory=dict)

    sitemap: SiteMap | None = None
    controls: dict[str, HostProfile] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    root_causes: list[RootCause] = field(default_factory=list)
    excluded: list[Exclusion] = field(default_factory=list)
    coverage_gaps: list[CoverageGap] = field(default_factory=list)
    index_reports: list[IndexLinkReport] = field(default_factory=list)
    #: 第 4 段（索引内链）收集的死链实例，供根因归并用。第 6 段（可点击路径）
    #: 的实例在 `_emit_dead_link_findings` 里自成一路，两段各归并自己的
    #: —— 它们的 locus 口径不同（文本文件没有 DOM 容器）。
    dead_instances: list[DeadInstance] = field(default_factory=list)

    requests_made: int = 0
    pages_fetched: int = 0
    links_extracted: int = 0
    links_excluded: int = 0
    links_needs_review: int = 0
    links_verified: int = 0
    links_unknown: int = 0
    links_capped: int = 0
    links_instances: int = 0
    links_unique_total: int = 0
    naive_dead_count: int = 0
    audited_dead_instances: int = 0
    index_links_sampled: bool = False
    sampling_note: str = ""

    def cancelled(self) -> bool:
        return self.stop.is_set()

    def check(self) -> None:
        """每个 stage 结束、每个请求发出前调它（§7.5:3541）。"""
        if self.stop.is_set():
            raise Cancelled


@dataclass(frozen=True, slots=True)
class PositionResult:
    """一格填好的结论 = seed + 报告层证据。

    ``PositionSeed``（models.py，§2.9 的原料）装不下 ``evidence`` / ``control`` /
    ``finding_ids``，而这三项是报告的证据存档表（C-1 八列）要的。
    """

    seed: PositionSeed
    evidence: Evidence | None = None
    control: Evidence | None = None
    naive: NaiveContrast | None = None
    finding_ids: tuple[str, ...] = ()


class InterruptibleLimiter(DomainLimiter):
    """限速等待改成 ``stop.wait(timeout=remaining)``（§7.5(2)）。

    ``fetch/ratelimit.py`` 的 ``DomainLimiter.hold()`` 用的是 ``time.sleep(gap)``，
    Ctrl-C 之后会挂在 2 秒限速里；而那个文件是冻结件（改一下就可能破 146 条回归
    测试），本步不许动。所以只在这里覆盖 ``hold()``，语义与父类逐行相同，
    只把睡眠换成可唤醒的等待。已进交付说明的 spec_gaps。
    """

    def __init__(self, base_interval: float, stop: threading.Event) -> None:
        super().__init__(base_interval)
        self._stop = stop

    @contextmanager
    def hold(self, host: str, *, requests: int = 1) -> Iterator[None]:
        del requests  # 与父类同参；本实现不按条数放宽间隔
        bucket = self._bucket(registrable_domain(host))
        bucket.lock.acquire()
        try:
            gap = bucket.interval - (time.monotonic() - bucket.last_hit)
            if gap > 0 and self._stop.wait(timeout=gap):
                raise Cancelled  # 等待期间被取消：这个请求不发
            yield
        finally:
            bucket.last_hit = time.monotonic()
            bucket.lock.release()


class StopTransport(httpx.BaseTransport):
    """每个请求发出前检查取消标志（§7.5(2) 说的是 ``Fetcher._raw_request`` 开头，
    但 ``fetch/client.py`` 是冻结件，所以落在 transport 这一层 —— 位置等价：
    它比 ``_raw_request`` 更靠里，一个请求都漏不掉）。

    ``before_request`` 是测试注入点：**在主线程的 stage 循环里**被调用，
    测试用它在第 N 个请求时置起 stop 并抛 ``KeyboardInterrupt``。
    零真信号、零 sleep、零时序依赖。
    """

    def __init__(
        self,
        inner: httpx.BaseTransport,
        stop: threading.Event,
        *,
        before_request: Callable[[str], None] | None = None,
        counter: Callable[[], None] | None = None,
    ) -> None:
        self._inner = inner
        self._stop = stop
        self._before = before_request
        self._counter = counter

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self._before is not None:
            self._before(str(request.url))
        if self._stop.is_set():
            raise Cancelled
        if self._counter is not None:
            self._counter()
        return self._inner.handle_request(request)


# --------------------------------------------------------------------------- #
# 参数包与进度输出
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AuditOptions:
    """CLI → pipeline 的参数包。字段名与 §7.1 的 flag 一一对应。"""

    domain: str
    contact: str
    only: tuple[str, ...] = ()
    skip: tuple[str, ...] = ()
    seeds: tuple[str, ...] = ()
    max_links: int = DEFAULT_MAX_LINKS
    max_requests: int = DEFAULT_MAX_REQUESTS
    index_links_full: bool = False
    wellknown: bool = True
    rate: float = DEFAULT_RATE
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    resolvers: str = DEFAULT_RESOLVERS
    ignore_robots: bool = False
    use_cache: bool = True
    cache_dir: str | None = None
    replay_fixtures: bool = False
    #: 给每条死链找一个**验证过**的替代地址。默认关：它要额外发请求
    #: （实测 mistral 的 75 条死链用了 166 个），会把默认的 120 上限直接吃穿。
    #: 开了之后按剩余预算尽力做，做不完的如实记成覆盖缺口。
    fix_candidates: bool = False
    #: 模型给的候选（qid 无关，按死链 URL 索引）。没有就只跑机械变换。
    model_candidates: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def interval(self) -> float:
        """``--rate`` → 单域名请求间隔秒数。0.5 req/s = 每 2 秒 1 个。"""
        return max(MIN_INTERVAL_SECONDS, 1.0 / self.rate) if self.rate > 0 else MIN_INTERVAL_SECONDS


class ProgressSink(Protocol):
    """§7.2 的进度输出口。pipeline 只发事件，格式与颜色全在 CLI 侧。"""

    def stage(self, index: int, label: str, detail: str) -> None: ...

    def row(self, state: str, url: str, note: str) -> None: ...

    def note(self, text: str) -> None: ...


class NullProgress:
    """``-q`` 与库调用用的空实现。"""

    def stage(self, index: int, label: str, detail: str) -> None:
        del index, label, detail

    def row(self, state: str, url: str, note: str) -> None:
        del state, url, note

    def note(self, text: str) -> None:
        del text


# --------------------------------------------------------------------------- #
# 检查开关（``--only`` / ``--skip``）
# --------------------------------------------------------------------------- #


def enabled_checks(options: AuditOptions) -> frozenset[str]:
    """哪些检查要跑。``--only`` 里带 ``<check>.<rule>`` 也算开了这个 check。"""
    wanted = set(CHECK_IDS)
    if options.only:
        wanted = {i.split(".", 1)[0] for i in options.only}
    for i in options.skip:
        if "." not in i:
            wanted.discard(i)
    return frozenset(wanted)


def enabled_rules(options: AuditOptions, check: str) -> frozenset[str]:
    """一个 check 里哪些规则要跑。"""
    rules = set(RULE_REGISTRY[check])
    only_rules = {i.split(".", 1)[1] for i in options.only if i.startswith(f"{check}.")}
    if only_rules:
        rules &= only_rules
    for i in options.skip:
        if i.startswith(f"{check}."):
            rules.discard(i.split(".", 1)[1])
    return frozenset(rules)


# --------------------------------------------------------------------------- #
# Position 构造（§2.9 P1–P5）—— ``Position(`` 的唯一出现处
# --------------------------------------------------------------------------- #


def position_id(stage: Stage, key: str) -> str:
    """§2.9:1197：稳定 id = ``f"{stage.value}:{key}"``。"""
    return f"{stage.value}:{key}"


def position_label(stage: Stage, key: str) -> str:
    """中文标签，直接显示。"""
    return f"{STAGE_LABEL[stage]} · {key}"


def build_positions(
    skeleton: Sequence[PositionSeed],
    results: Mapping[str, PositionResult] | None = None,
    *,
    unfilled_reason: str = "not_fetched",
) -> tuple[Position, ...]:
    """骨架 + 结论 → ``Position`` 元组。**本仓库唯一允许 ``Position(`` 的地方。**

    ``skeleton`` 是 §2.9 构造表生成的**全部**格子（P1–P5，先建），``results`` 是
    已经跑出结论的格子（后填）。没填上的格子留 ``Status.UNKNOWN`` +
    ``unknown_reason=unfilled_reason``（中断时传 ``"interrupted"``，预算耗尽时是
    ``"not_fetched"``）+ 对应的 ``UNKNOWN_REMEDY``。

    每格恰好一个 ``Status``，所以恒等式
    ``pass + fail + unknown + na == positions``（A27）**按构造成立** ——
    中断报告上也成立。
    """
    table = results or {}
    out: list[Position] = []
    seen: set[str] = set()
    for cell in skeleton:
        pid = position_id(cell.stage, cell.key)
        if pid in seen:  # 骨架去重：同一格只许出现一次
            continue
        seen.add(pid)
        found = table.get(pid)
        seed = found.seed if found is not None else cell
        reason = seed.unknown_reason
        remedy = seed.unknown_remedy
        if seed.status is Status.UNKNOWN and not reason:
            reason = unfilled_reason
            remedy = UNKNOWN_REMEDY[unfilled_reason]
        if seed.status is Status.UNKNOWN and not remedy:
            remedy = UNKNOWN_REMEDY.get(
                reason or unfilled_reason,
                "本位置未能评估，补救办法未登记（UNKNOWN_REMEDY 缺这条，见 §2.8）。",
            )
        out.append(
            Position(
                position_id=pid,
                stage=seed.stage,
                label=position_label(seed.stage, seed.key),
                probe_url=seed.probe_url,
                status=seed.status,
                detail=seed.detail or (reason or ""),
                kind=seed.kind,
                aggregate_of=seed.aggregate_of,
                unknown_reason=reason if seed.status is Status.UNKNOWN else None,
                unknown_remedy=remedy if seed.status is Status.UNKNOWN else None,
                evidence=found.evidence if found is not None else None,
                control=found.control if found is not None else None,
                naive=found.naive if found is not None else None,
                finding_ids=found.finding_ids if found is not None else (),
            )
        )
    return tuple(out)


def _unknown_seed(
    stage: Stage,
    key: str,
    probe_url: str,
    *,
    kind: Literal["probe", "aggregate"] = "probe",
    detail: str = "",
    aggregate_of: int = 1,
) -> PositionSeed:
    """一个还没有结论的空格子（骨架用）。"""
    return PositionSeed(
        stage=stage,
        key=key,
        kind=kind,
        probe_url=probe_url,
        status=Status.UNKNOWN,
        detail=detail,
        aggregate_of=aggregate_of,
    )


def bare_skeleton(domain: str) -> tuple[PositionSeed, ...]:
    """**一个请求都还没发**时的骨架：P1 两格 + P2 四格 + P4 一格。

    §6.3:3161 的下界推导：``positions >= |P1| + |P2| + 1``，P1 >= 1（apex 或 www
    至少一个能解析，否则退出码 3）、P2 >= 2（tier0 两条根路径）→ ``positions >= 4``。
    Ctrl-C 打在入口发现阶段时，报告靠这份骨架照样出得来。
    """
    apex = domain.strip().lower().lstrip(".")
    hosts = (apex, f"www.{apex}")
    cells: list[PositionSeed] = []
    for host in hosts:
        cells.append(_unknown_seed(Stage.DISCOVERY, host, f"https://{host}/"))
    for host in hosts:
        for path in ("/llms.txt", "/llms-full.txt"):
            stage = Stage.FULLTEXT if "llms-full" in path else Stage.INDEX_FILE
            cells.append(_unknown_seed(stage, f"{host}{path}", f"https://{host}{path}"))
    cells.append(_unknown_seed(Stage.MD_CHANNEL, "md", f"https://{apex}/", kind="aggregate"))
    return tuple(cells)


def discovery_position_seeds(sitemap: SiteMap) -> tuple[PositionSeed, ...]:
    """§2.9 P1：每个**被 DNS 解析通过并实际请求了根路径**的 host 各一格。

    DNS 都没过的 host 一个请求都没花（``probe_host_root`` 的短路），按 P1 的字面
    要求不进账本 —— 否则 16 个前缀枚举会给每个域凭空加 14 格「无法判断」。
    """
    seeds: list[PositionSeed] = []
    for host in sitemap.hosts:
        if host.reason in ("dns_unresolved", "dns_poisoned"):
            continue
        status = verdict_to_status(host.verdict)
        reason = host.reason if status is Status.UNKNOWN else None
        seeds.append(
            PositionSeed(
                stage=Stage.DISCOVERY,
                key=host.host,
                kind="probe",
                probe_url=f"https://{host.host}/",
                status=status,
                detail="；".join(host.evidence) or host.reason,
                unknown_reason=reason,
                unknown_remedy=UNKNOWN_REMEDY.get(reason) if reason else None,
            )
        )
    return tuple(seeds)


def budget_skipped_seeds(sitemap: SiteMap) -> tuple[PositionSeed, ...]:
    """预算耗尽被跳过的 AI 路径：``UNKNOWN(not_fetched)``，
    **绝不当成「没有这个文件」**（``discovery.discover`` 的 docstring 点名要求）。"""
    seeds: list[PositionSeed] = []
    probed = {p.url for p in sitemap.ai_path_probes}
    for url in sitemap.skipped_by_budget:
        if url in probed:
            continue
        parts = urlsplit(url)
        stage = Stage.FULLTEXT if "llms-full" in parts.path.lower() else Stage.INDEX_FILE
        seeds.append(
            PositionSeed(
                stage=stage,
                key=f"{(parts.hostname or '').lower()}{parts.path}",
                kind="probe",
                probe_url=url,
                status=Status.UNKNOWN,
                detail="超出 --max-requests 预算，本位置未探测",
                unknown_reason="not_fetched",
                unknown_remedy=UNKNOWN_REMEDY["not_fetched"],
            )
        )
    return tuple(seeds)


def index_file_probes(sitemap: SiteMap) -> tuple[Probe, ...]:
    """判为真文件、且不是 llms-full 的索引探测（P3 的候选）。"""
    out: list[Probe] = []
    for probe in sitemap.ai_path_probes:
        if probe.verdict is not Verdict.OK or probe.response is None:
            continue
        if "llms-full" in urlsplit(probe.url).path.lower():
            continue
        out.append(probe)
    return tuple(out)


def index_links_seeds(probes: Sequence[Probe]) -> tuple[PositionSeed, ...]:
    """§2.9 P3：每个**判为真文件且解析出 ≥1 条链接的索引文件**各一格。

    **mistral 的 75 条死链是 1 格，不是 75 格** —— 位置不是探测。
    """
    seeds: list[PositionSeed] = []
    for probe in probes:
        resp = probe.response
        if resp is None:
            continue
        links = parse_index_links(resp.text, resp.final_url)
        if not links:
            continue
        seeds.append(
            _unknown_seed(
                Stage.INDEX_LINKS,
                resp.final_url,
                resp.final_url,
                kind="aggregate",
                detail=f"{len(links)} 条内链待验证",
                aggregate_of=len(links),
            )
        )
    return tuple(seeds)


def seed_page_urls(sitemap: SiteMap, extra: Sequence[str] = ()) -> tuple[str, ...]:
    """⑥ 的起始页清单。§7.1 的默认起始页：首页、/pricing、/changelog、/docs、/help。"""
    apex = sitemap.registrable_domain or sitemap.input_domain
    live = {h.host for h in sitemap.hosts if h.verdict in (Verdict.OK, Verdict.BLOCKED)}
    primary = next((h for h in (f"www.{apex}", apex) if h in live), apex)
    urls: list[str] = [f"https://{primary}/"]
    urls.append(sitemap.pricing_url or f"https://{primary}/pricing")
    urls.append(f"https://{primary}/changelog")
    docs = next((h.host for h in sitemap.hosts if h.role is HostRole.DOCS and h.host in live), None)
    urls.append(f"https://{docs}/" if docs else f"https://{primary}/docs")
    helps = next(
        (h.host for h in sitemap.hosts if h.role is HostRole.SUPPORT and h.host in live), None
    )
    urls.append(f"https://{helps}/" if helps else f"https://{primary}/help")
    urls.extend(extra)
    return tuple(dict.fromkeys(urls))[: dl.MAX_SEED_PAGES]


def human_path_seeds(urls: Sequence[str]) -> tuple[PositionSeed, ...]:
    """§2.9 P5：每个 seed 页一格（``kind="aggregate"``）。

    ⚠️ P5 的字面要求是「每个**实际抓取成功的** seed 页各一格」，但 §7.5(3) 要求
    骨架在发请求**之前**就建好。两条要求只能同时满足成这样：候选 seed 页先各占
    一格，抓不下来的那格落 ``UNKNOWN`` + 抓取失败的原因码 —— 不是丢掉。
    丢掉等于把「我们没看到」变成「这一页没问题」。已进交付说明的 deviations。
    """
    return tuple(
        _unknown_seed(Stage.HUMAN_PATH, url, url, kind="aggregate", detail="待抓取") for url in urls
    )


def skeleton_seeds(
    sitemap: SiteMap,
    *,
    checks: frozenset[str],
    seed_pages: Sequence[str],
) -> tuple[PositionSeed, ...]:
    """§2.9 构造表的全部格子（P1–P5），**不发任何请求**。"""
    cells: list[PositionSeed] = list(discovery_position_seeds(sitemap))  # P1
    if "ai_path" in checks:
        cells.extend(ai_path_position_seeds(sitemap.ai_path_probes))  # P2
        cells.extend(budget_skipped_seeds(sitemap))  # P2（被预算跳过的）
        cells.extend(index_links_seeds(index_file_probes(sitemap)))  # P3
        cells.append(  # P4 恒等于 1
            _unknown_seed(
                Stage.MD_CHANNEL,
                "md",
                f"https://{sitemap.registrable_domain}/",
                kind="aggregate",
                detail="待判定",
            )
        )
    if "dead_links" in checks:
        cells.extend(human_path_seeds(seed_pages))  # P5
    return tuple(cells)


# --------------------------------------------------------------------------- #
# 计数、headline、退出码
# --------------------------------------------------------------------------- #


def sampled_ratio(cov: Coverage) -> float:
    """§3.8:1880：= 实际验证到状态的唯一目标数 / 归并后的唯一目标总数。

    分母 = ``links_extracted``（**去噪并模板归并后的唯一 norm_url 数**）减掉
    ``links_excluded``；分子 = ``links_verified + links_unknown``。
    **没有可点击链接时返回 1.0，不是 0.0。**
    """
    denom = cov.links_extracted - cov.links_excluded
    if denom <= 0:
        return 1.0
    return min(1.0, (cov.links_verified + cov.links_unknown) / denom)


def make_headline(
    c: Counts, *, has_ai_channel: bool, sampled_ratio: float, interrupted: bool
) -> tuple[str, VerdictKind]:
    """§6.1:3074 六分支逐字，互斥且穷尽。返回 ``(headline, verdict_kind)``。"""
    core = max(c.positions - c.positions_na, 1)

    if interrupted:  # 卡点 B24：中断优先于一切
        return (
            "扫描被中断，下面只是已完成部分的结论。未跑到的位置标「无法判断」。",
            "unusable",
        )
    if c.positions_unknown / core > 0.5:
        return (
            f"这次扫描不可信：{core} 个核心位置里有 {c.positions_unknown} 个我们没能评估。"
            f"下面的结论不要当结论用。",
            "unusable",
        )
    if c.positions_fail and c.positions_unknown:
        return (
            f"你的 AI 检索链路上有 {c.positions_fail} 个位置会被读错，"
            f"另有 {c.positions_unknown} 个位置我们无法判断。",
            "has_fail",
        )
    if c.positions_fail:
        return (f"你的 AI 检索链路上有 {c.positions_fail} 个位置会被读错。", "has_fail")
    if not has_ai_channel:
        return (
            "你的站没有 AI 索引通道（llms.txt / llms-full.txt 全部诚实 404）。"
            "AI 只能靠爬你的 HTML —— 这份报告检查的是它爬不爬得通。",
            "no_ai_channel",
        )
    if c.positions_unknown:
        return (
            f"没有发现被读错的位置。但有 {c.positions_unknown} 个位置我们无法判断，"
            f"所以这不能算「全部通过」。",
            "zero_with_unknown",
        )
    if sampled_ratio < 0.5:
        return (
            f"抽到的链接里没有发现问题。抽样率 {sampled_ratio:.1%}，这个结论不能外推到全站。",
            "zero_with_unknown",
        )
    return (
        f"{c.positions_pass} 个位置全部通过，每一条都附对照证据和可复现命令。",
        "zero_clean",
    )


def count_positions(
    positions: Sequence[Position],
    findings: Sequence[Finding],
    root_causes: Sequence[RootCause],
    naive_table: Sequence[NaiveContrast],
    *,
    naive_dead_count: int = 0,
    audited_dead_instances: int = 0,
) -> Counts:
    """四格计数 + 条数。**位置数与条数是两个数，报告里必须分开显示**（§2.9 推论 4）。"""
    by_severity: dict[str, int] = {s.value: 0 for s in SEVERITY_RANK}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
    return Counts(
        positions=len(positions),
        positions_pass=sum(1 for p in positions if p.status is Status.PASS),
        positions_fail=sum(1 for p in positions if p.status is Status.FAIL),
        positions_unknown=sum(1 for p in positions if p.status is Status.UNKNOWN),
        positions_na=sum(1 for p in positions if p.status is Status.NOT_APPLICABLE),
        findings=len(findings),
        findings_counted=sum(1 for f in findings if f.counted_as_hit),
        occurrences=sum(f.occurrences for f in findings),
        root_causes=len(root_causes),
        by_severity=by_severity,
        naive_divergences=len(divergences(naive_table)),
        naive_dead_count=naive_dead_count,
        audited_dead_instances=audited_dead_instances,
        llm_calls=0,
    )


def fail_on_reached(findings: Sequence[Finding], fail_on: str) -> bool:
    """有没有达到 ``--fail-on`` 级别的发现。``none`` = 永不失败。"""
    if fail_on == "none":
        return False
    floor = SEVERITY_RANK.index(Severity(fail_on))
    return any(SEVERITY_RANK.index(f.severity) <= floor for f in findings if f.counted_as_hit)


def exit_code_for(report: Report, *, fail_on: str = DEFAULT_FAIL_ON) -> int:
    """§7.1:3349 的优先级：130 > 2 > 1 > 0（4 与 3 在跑之前就决定了）。"""
    if report.coverage.interrupted:
        return EXIT_INTERRUPTED
    if report.verdict_kind == "unusable":
        return EXIT_UNTRUSTED
    if fail_on_reached(report.findings, fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def interrupt_banner(report: Report) -> str:
    """§7.5(4) 的固定通栏文案（三行）。非中断报告返回空串。"""
    if not report.coverage.interrupted:
        return ""
    missing = sum(
        1
        for p in report.positions
        if p.status is Status.UNKNOWN and p.unknown_reason == "interrupted"
    )
    return INTERRUPT_BANNER_TEMPLATE.format(
        done=report.counts.positions - missing,
        missing=missing,
        domain=report.domain,
        contact=report.contact,
    )


# --------------------------------------------------------------------------- #
# 结构性脆弱点（§6.3 F1–F8）
# --------------------------------------------------------------------------- #


def build_fragilities(
    domain: str,
    controls: Mapping[str, HostProfile],
    index_reports: Sequence[IndexLinkReport],
) -> tuple[Fragility, ...]:
    """F1 / F6 / F8 三条。**F6 与 F8 在任何站上都能出结论**（§6.3:3186），
    所以零发现报告至少拿到 2 条。

    F2 / F3 / F4 / F5 / F7 需要跨 pair 的字节与指纹信息，规格没给生产者，
    本步不编 —— 已进交付说明的 spec_gaps。
    """
    out: list[Fragility] = []
    watch = f"geo-audit {domain} --contact you@yourco.com --format json"

    for report in index_reports:
        if len(report.links) < 20:
            continue
        prefixes: dict[str, int] = {}
        for link in report.links:
            head = "/".join(urlsplit(link.abs_url).path.split("/")[:3])
            prefixes[head] = prefixes.get(head, 0) + 1
        top, hits = max(prefixes.items(), key=lambda kv: kv[1])
        share = hits / len(report.links)
        if share >= 0.90:
            out.append(
                Fragility(
                    fragility_id="F1",
                    title="索引单点依赖",
                    metric=f"{report.index_url}：{len(report.links)} 条链接里 "
                    f"{hits} 条（{share:.0%}）挤在 {top} 下",
                    why="这个前缀一改路径，索引里几乎每一条都同时失效。",
                    precedent=(
                        "docs.mistral.ai/llms.txt 75 条链接 75/75 全 404，"
                        "而 /getting-started/platform-overview.md 是 200 —— 机制活着，索引全烂"
                    ),
                    watch_command=watch,
                )
            )

    unusable = sorted(h for h, p in controls.items() if not p.usable)
    out.append(
        Fragility(
            fragility_id="F6",
            title="WAF 会把真文件挡成 403/429",
            metric=(
                f"不可探测的 host：{', '.join(unusable)}"
                if unusable
                else "本次全部 host 的对照探测都可用（0 个被挡）"
            ),
            why="被拦截 ≠ 不存在。纯 HTTP 客户端在这类 host 上会把真文件读成「没有」。",
            precedent="gusto.com 403、www.pipedrive.com 429",
            watch_command=watch,
        )
    )

    blind = sorted(h for h, p in controls.items() if p.usable and not p.status_discriminates)
    out.append(
        Fragility(
            fragility_id="F8",
            title="该 host 对未知路径不返回 404",
            metric=(
                f"对随机路径不返回 404 的 host：{', '.join(blind)}"
                if blind
                else "本次全部 host 对随机路径都返回了非 2xx（状态码可判别）"
            ),
            why="这种 host 上任何只看状态码的工具都会报 0 死链，那个 0 是假的。",
            precedent=(
                "developers.pipedrive.com（200 + 24,907 B 兜底页）、docs.gusto.com（302→/）、"
                "docs.moderntreasury.com（302→/）、www.minimax.io（200 + 384,052 B）、"
                "platform.kimi.ai（200 + 414,072 B）"
            ),
            watch_command=watch,
        )
    )
    return tuple(out)


# --------------------------------------------------------------------------- #
# Fetcher 组装
# --------------------------------------------------------------------------- #


def cache_path(options: AuditOptions) -> Path | None:
    """HTTP 缓存文件位置。

    ``--no-cache``（含 ``--from`` / ``--replay-fixtures`` 强制禁用缓存那条，卡点 B18）
    指到一个**一次性临时文件**：既不读也不写持久缓存，进程结束就作废。
    ``HttpCache`` 没有「不缓存」模式（构造时就建 sqlite），这是不改冻结件的最短路。
    """
    if not options.use_cache:
        return Path(tempfile.mkdtemp(prefix="geo-audit-nocache-")) / "http.sqlite3"
    if options.cache_dir:
        return Path(options.cache_dir) / "http.sqlite3"
    return None  # 平台缓存目录下的 geo-audit/http.sqlite3


def build_fetcher(
    options: AuditOptions,
    *,
    stop: threading.Event,
    store: FixtureStore | None = None,
    before_request: Callable[[str], None] | None = None,
    counter: Callable[[], None] | None = None,
) -> Fetcher:
    """按 CLI 参数造 Fetcher。``--from`` / ``--replay-fixtures`` 强制禁用缓存（卡点 B18）。"""
    config = FetcherConfig(
        contact=options.contact,
        interval=options.interval,
        read_timeout=options.timeout,
        respect_robots=not options.ignore_robots,
    )
    # strict=False：站内抓到的链接是无穷集，缺快照返回 599 走 UNKNOWN。
    # 探测集里的固定位置由 store.probe_url() / FixtureResolver 各自的 strict 检查守着，
    # 那些缺了照样红 —— 区别是「我们 fixture 不全」还是「站内链接没录过」。
    inner: httpx.BaseTransport = (
        store.transport(strict=False) if store is not None else httpx.HTTPTransport()
    )
    transport = StopTransport(inner, stop, before_request=before_request, counter=counter)
    cache = HttpCache(path=cache_path(options), ua_profile=build_user_agent(options.contact))
    return Fetcher(
        config,
        cache,
        InterruptibleLimiter(options.interval, stop),
        transport=transport,
        # 宽容版：从没出现在实测里的子域缺对照探针是正常的，
        # 那个位置判 UNKNOWN（control_unavailable），不该让整份报告产不出来。
        probe_url_provider=store.probe_url_lenient if store is not None else None,
        # **必须传**：Fetcher 在传输失败时自己会做一次 resolve.R1–R4 的 DNS 二次
        # 确认，那条路径不经过 discover(resolver=...)。不传的话 --replay-fixtures
        # 在离线下会撞断网闸（实测 mistral.ai 就是这么崩的）。
        # 上一轮给 Fetcher 加了注入点、也给 fp_gate 接上了，唯独漏了这个生产调用侧。
        resolver=store.resolver() if store is not None else None,
    )


# --------------------------------------------------------------------------- #
# 六段
# --------------------------------------------------------------------------- #

_UNREACHABLE_REASONS = frozenset({"dns_unresolved", "dns_poisoned", "network_error", "timeout"})


def domain_unreachable(sitemap: SiteMap) -> bool:
    """apex 与 www 都解析失败或连不上 → 退出码 3。

    ⚠️ **BLOCKED 不算不可达**：gusto.com 全站对 curl 403，报告照常生成、退出码 2
    （§2.9 的 gusto 锚点）。把被拦截算成不可达就把它错杀成 3。
    """
    core = [h for h in sitemap.hosts if h.role in (HostRole.APEX, HostRole.WWW)]
    if not core:
        return True
    return all(h.verdict is Verdict.UNKNOWN and h.reason in _UNREACHABLE_REASONS for h in core)


def _controls_of(fetcher: Fetcher, sitemap: SiteMap) -> dict[str, HostProfile]:
    """已经缓存的 host profile（对照探测基线）。**零新请求** —— 只读缓存。"""
    out: dict[str, HostProfile] = {}
    hosts = {h.host for h in sitemap.hosts}
    hosts.update((urlsplit(p.url).hostname or "").lower() for p in sitemap.ai_path_probes)
    for host in hosts:
        profile = fetcher.cache.get_profile(host)
        if profile is not None:
            out[host] = profile
    return out


def _exclusion(url: str, ex: EligibilityExclusion, *, found_on: str | None = None) -> Exclusion:
    """判定期的轻版本 → 报告层的富版本（§2.6 的裁决：两者并存）。"""
    provenance: Literal["measured", "single_case"] = (
        "single_case" if ex.provenance == "single_case" else "measured"
    )
    disposition: Literal["excluded", "needs_review"] = (
        "needs_review" if ex.disposition == "needs_review" else "excluded"
    )
    return Exclusion(
        url=url,
        rule_id=ex.rule_id,
        rule_desc=ex.reason,
        found_on=found_on,
        provenance=provenance,
        disposition=disposition,
    )


def _fill(st: RunState, result: PositionResult) -> None:
    with st.lock:
        st.results[position_id(result.seed.stage, result.seed.key)] = result


def _stage_ai_path(
    st: RunState, options: AuditOptions, fetcher: Fetcher, prog: ProgressSink
) -> None:
    """② ③ 索引文件真伪 + 全文通道。判定来自 discovery 已抓的响应，**零新请求**。"""
    sitemap = st.sitemap
    if sitemap is None:
        return

    # 根路径判不了的 host 会整片掉出探测集，**那必须记成覆盖缺口。**
    #
    # `discovery.host_is_live` 是 `verdict in (OK, BLOCKED)` —— UNKNOWN 不在里面。
    # 于是根路径判 UNKNOWN 的 host 从 `live_hosts` 掉出去：AI 路径不探、
    # robots 不读、sitemap 不读，账本上只剩一格 UNKNOWN，下游整片静默消失。
    #
    # 那段函数自己的注释就在反驳这个结果：它说 BLOCKED 的 host 必须留着，
    # 因为「把它们丢掉就是软 404 让采纳率虚高的**反向孪生错误 —— 虚低**」。
    # 根路径 UNKNOWN 是同一种情形（我们不知道），丢掉同样是虚低。
    #
    # 这里不改 `host_is_live`：`timeout` / `network_error` 那类 UNKNOWN 继续探
    # 只会把预算烧在一个真的连不上的 host 上。改的是**披露** —— 报告必须说出
    # 「这个 host 我们发现了、但没能探它的 AI 路径」，而不是写「没有额外的覆盖缺口」。
    #
    # 实测：developers.deepgram.com 的对照探针没录 → 根路径判
    # UNKNOWN(control_unavailable) → 它的 llms.txt 里 383 条内链一条没查，
    # 而覆盖披露照旧写「没有额外的覆盖缺口」。
    probed_hosts = {(urlsplit(pr.url).hostname or "").lower() for pr in sitemap.ai_path_probes}
    for dh in sitemap.hosts:
        if dh.reason in ("dns_unresolved", "dns_poisoned"):
            continue  # DNS 都没过，一个请求都没花，按 P1 本来就不进账本
        if verdict_to_status(dh.verdict) is not Status.UNKNOWN:
            continue
        if dh.host.lower() in probed_hosts:
            continue  # 探到了，不是盲区
        st.coverage_gaps.append(
            CoverageGap(
                where=f"① 入口发现 · https://{dh.host}/",
                reason=dh.reason,
                detail=(
                    f"这个 host 解析通了、根路径也请求了，但判不了"
                    f"（{dh.reason}），于是它的 AI 路径（llms.txt / llms-full.txt /"
                    f" .md 通道）一条都没探，robots.txt 与 sitemap.xml 也没读。"
                    "这不是「这个 host 没问题」，是「我们没能看」。"
                ),
                remedy=UNKNOWN_REMEDY.get(
                    dh.reason,
                    "先让这个 host 的根路径能判定，它下面的位置才进得了账本。",
                ),
            )
        )

    rules = enabled_rules(options, "ai_path")
    seeds = ai_path_position_seeds(sitemap.ai_path_probes)
    by_probe = {p.url: p for p in sitemap.ai_path_probes}

    findings: list[Finding] = []
    if "soft404" in rules:
        findings.extend(
            check_ai_paths(
                options.domain,
                sitemap.ai_path_probes,
                controls=st.controls,
                user_agent=fetcher.user_agent,
            )
        )
    if "llms_full" in rules:
        findings.extend(
            check_llms_full(options.domain, sitemap.ai_path_probes, user_agent=fetcher.user_agent)
        )
    st.findings.extend(findings)

    ids_by_url: dict[str, list[str]] = {}
    for f in findings:
        ids_by_url.setdefault(f.target.url, []).append(f.finding_id)

    index_cells = sum(1 for s in seeds if s.stage is Stage.INDEX_FILE)
    full_cells = sum(1 for s in seeds if s.stage is Stage.FULLTEXT)
    prog.stage(2, STAGE_LABEL[Stage.INDEX_FILE], f"{index_cells} 个位置")
    prog.stage(3, STAGE_LABEL[Stage.FULLTEXT], f"{full_cells} 个位置")
    for seed in seeds:
        probe = by_probe.get(seed.probe_url)
        resp = probe.response if probe is not None else None
        host = (urlsplit(seed.probe_url).hostname or "").lower()
        control = st.controls.get(host)
        _fill(
            st,
            PositionResult(
                seed=seed,
                evidence=(
                    evidence_of(resp, user_agent=fetcher.user_agent) if resp is not None else None
                ),
                control=(
                    Evidence(
                        url=control.probe_url,
                        http_status=control.status,
                        content_type=control.content_type or None,
                        curl_repro=f"curl -sSL -A '{fetcher.user_agent}' '{control.probe_url}'",
                    )
                    if control is not None
                    else None
                ),
                finding_ids=tuple(ids_by_url.get(seed.probe_url, ())),
            ),
        )
        prog.row(_progress_state(seed.status), seed.probe_url, seed.detail[:80])


def _progress_state(status: Status) -> str:
    return {
        Status.PASS: "PASS",
        Status.FAIL: "FAIL",
        Status.UNKNOWN: "UNKN",
        Status.NOT_APPLICABLE: "N/A ",
    }[status]


def _stage_index_links(
    st: RunState, options: AuditOptions, fetcher: Fetcher, prog: ProgressSink
) -> None:
    """④ 索引内链存活。**一份索引 1 格**（mistral 的 75 条死链是 1 格）。"""
    sitemap = st.sitemap
    if sitemap is None or "index_links" not in enabled_rules(options, "ai_path"):
        return

    # 上游判不了 → 这份索引的内链整批不查，**而那必须记成覆盖缺口。**
    #
    # 为什么单列这一段：``index_file_probes`` 按 P3 只收 verdict 为 OK 的索引
    # （规格原文「每个**判为真文件且解析出 ≥1 条链接的索引文件**各一格」）。
    # 剪枝本身是对的 —— 分不清真文件和一壳打天下的时候，「文件里的链接」很可能
    # 根本不是一份链接清单。但剪掉之后报告若仍写「没有额外的覆盖缺口」，
    # 就等于把一个假 PASS 换成一个没披露的盲区，那比误判更隐蔽。
    #
    # 实测：developers.deepgram.com/llms.txt 的对照探针没录，判定从 OK 变成
    # UNKNOWN(control_unavailable) 之后，它里面 383 条内链一条都不查了，
    # 而那份报告的覆盖披露照旧写着「没有额外的覆盖缺口」。
    #
    # 判据刻意只收 UNKNOWN：判成 SOFT404 是**有结论**（那格是 FAIL），
    # 不是盲区；REAL404 的索引本来也解析不出链接。
    for probe in sitemap.ai_path_probes:
        resp = probe.response
        if probe.verdict is not Verdict.UNKNOWN or resp is None:
            continue
        if "llms-full" in urlsplit(probe.url).path.lower():
            continue
        n_links = len(parse_index_links(resp.text, resp.final_url))
        if n_links == 0:
            continue
        st.coverage_gaps.append(
            CoverageGap(
                where=f"④ 索引内链存活 · {probe.url}",
                reason=probe.classification.reason,
                detail=(
                    f"这份索引解析出 {n_links} 条内链，但我们没能判定它本身是不是真文件"
                    f"（{probe.classification.reason}），所以这 {n_links} 条一条都没查。"
                ),
                remedy=UNKNOWN_REMEDY.get(
                    probe.classification.reason,
                    "先让这份索引本身能判定，它的内链才有意义。",
                ),
            )
        )

    total_dead = 0
    total_alive = 0
    for probe in index_file_probes(sitemap):
        st.check()
        resp = probe.response
        if resp is None:
            continue
        key = resp.final_url
        pid = position_id(Stage.INDEX_LINKS, key)
        if pid not in {position_id(s.stage, s.key) for s in st.skeleton}:
            continue  # 这份索引没解析出链接，按 P3 不占格
        if not _budget_left(st, options):
            continue  # 格子留 UNKNOWN(not_fetched)
        host = (urlsplit(probe.url).hostname or "").lower()
        report = probe_index_links(
            options.domain, probe, fetcher=fetcher, control=st.controls.get(host)
        )
        st.index_reports.append(report)
        st.requests_made += len(report.probed)
        st.index_links_sampled = st.index_links_sampled or report.sampled
        if report.sampled:
            st.sampling_note = (
                f"{report.index_url} 的内链抽样："
                f"{len(report.probed)}/{report.sampled_of}（抽样，非全量）"
            )
        findings = findings_from_index_report(
            report, domain=options.domain, user_agent=fetcher.user_agent
        )
        # 死内链也要进根因归并。§6.1 的产品约束是「价值密度在位置和根因，不在条数」
        # （实测：94 条死链里 66 条挤在 7 个域名上），而 mistral 的 75 条内链**全部
        # 来自同一份 llms.txt 的同一次路径迁移** —— 报 75 条是把「改 1 处修 75 条」
        # 拆成了 75 个待办。
        # 原来 merge_root_causes 只接在第 6 段（可点击路径），第 4 段的 findings
        # 直接 extend 进去、root_cause_id 全空。实测第一份真报告就是
        # findings=75 / root_causes=0。
        # source_page 用索引文件本身：这些链接确实"出现在"那个文件里，
        # 而 container_sig 留空 —— 文本文件没有 DOM 容器，归并靠 path_shape。
        if report.dead:
            # finding_id 必须原样带过来：findings_from_index_report 用
            # check_id="ai_path.index_links" 算的，而 DeadTarget.identity 的兜底
            # 写死 DEAD_LINK_CHECK_ID —— 不传就是两套不交的 id，回填 0 条命中。
            fid_by_url = {f.target.url: f.finding_id for f in findings}
            st.dead_instances.extend(
                DeadInstance(
                    abs_url=link.abs_url,
                    source_page=report.index_url,
                    raw_href=link.abs_url,
                    anchor_text=link.anchor_text or "",
                    severity=report.severity,
                    finding_id=fid_by_url.get(link.abs_url, ""),
                )
                for link in report.dead
            )
        st.findings.extend(findings)
        st.excluded.extend(
            _exclusion(url, ex, found_on=report.index_url) for url, ex in report.excluded
        )
        total_dead += report.n_dead
        total_alive += report.n_alive
        detail = (
            f"{report.n_links} 条内链：{report.n_alive} 活 / {report.n_dead} 死 / "
            f"{report.n_unknown} 判不了"
        )
        reason = report.unknown_reasons[0] if report.unknown_reasons else "not_fetched"
        _fill(
            st,
            PositionResult(
                seed=PositionSeed(
                    stage=Stage.INDEX_LINKS,
                    key=key,
                    kind="aggregate",
                    probe_url=key,
                    status=report.status,
                    detail=detail,
                    aggregate_of=report.n_links,
                    unknown_reason=reason if report.status is Status.UNKNOWN else None,
                    unknown_remedy=(
                        UNKNOWN_REMEDY.get(reason) if report.status is Status.UNKNOWN else None
                    ),
                ),
                evidence=evidence_of(resp, user_agent=fetcher.user_agent),
                finding_ids=tuple(f.finding_id for f in findings),
            ),
        )
        prog.row(_progress_state(report.status), key, detail)
    # 索引内链的根因归并（§5.4）。放在这一段的收尾：此时本段全部死链实例已收齐。
    # mistral 的 75 条内链归成 1 条根因 —— 它们全部来自同一份 llms.txt 的同一次
    # 路径迁移，报 75 条等于把「改 1 处修 75 条」拆成 75 个待办。
    if st.dead_instances:
        targets = fold_instances(st.dead_instances)
        causes = merge_root_causes(targets, audited_domain=options.domain)
        st.root_causes.extend(causes)
        # 回填 root_cause_id / root_cause_summary / sibling_count。
        # finding 的身份是 norm_url（rootcause.normalize_url 那一份唯一口径），
        # 而 findings_from_index_report 用的 finding_id 也是从它算的，所以对得上。
        by_fid = {fid: c for c in causes for fid in c.finding_ids}
        if by_fid:
            st.findings[:] = [
                (
                    replace(
                        f,
                        root_cause_id=by_fid[f.finding_id].root_cause_id,
                        root_cause_summary=by_fid[f.finding_id].summary,
                        sibling_count=by_fid[f.finding_id].unique_target_count,
                    )
                    if f.finding_id in by_fid
                    else f
                )
                for f in st.findings
            ]
    prog.stage(4, STAGE_LABEL[Stage.INDEX_LINKS], f"FAIL {total_dead} 死 / {total_alive} 活")


def _stage_md_channel(
    st: RunState, options: AuditOptions, fetcher: Fetcher, prog: ProgressSink
) -> None:
    """⑤ .md 通道。**恒一格**，无论有几处声明（§2.9 P4）。"""
    sitemap = st.sitemap
    if sitemap is None or "md_convention" not in enabled_rules(options, "ai_path"):
        return
    key = "md"
    probes = index_file_probes(sitemap)
    links: list[str] = []
    for probe in probes:
        resp = probe.response
        if resp is not None:
            links.extend(link.abs_url for link in parse_index_links(resp.text, resp.final_url))
    if not _budget_left(st, options):
        prog.stage(5, STAGE_LABEL[Stage.MD_CHANNEL], "超出预算，未评估")
        return

    decl, finding = check_md_convention(
        options.domain,
        probes,
        None,
        links,
        fetcher=fetcher,
        controls=st.controls,
        user_agent=fetcher.user_agent,
    )
    if decl is None:
        seed = PositionSeed(
            stage=Stage.MD_CHANNEL,
            key=key,
            kind="aggregate",
            probe_url=f"https://{sitemap.registrable_domain}/",
            status=Status.NOT_APPLICABLE,
            detail="未声明「任意页面加 .md」约定",
        )
        _fill(st, PositionResult(seed=seed))
        prog.stage(5, STAGE_LABEL[Stage.MD_CHANNEL], "未声明 → 不适用")
        return

    st.requests_made += 2 * sum(1 for s in decl.samples if s.in_scope)
    if finding is not None:
        st.findings.append(finding)
    if decl.suppressed_by is not None:
        status = Status.NOT_APPLICABLE
        detail = f"有声明但判据不足，按设计不报：{decl.suppressed_by}"
    elif finding is not None and finding.counted_as_hit:
        status = Status.FAIL
        detail = finding.display_value or "声明的 .md 约定没兑现"
    elif finding is not None:
        status = Status.PASS
        detail = "声明里写了例外条款，降级为提示"
    else:
        status = Status.PASS
        detail = "声明范围内的抽样全部拿到 markdown"
    if decl.negotiation_advertised:
        st.coverage_gaps.append(
            CoverageGap(
                where=decl.source_url,
                reason="not_fetched",
                detail="站点通过内容协商提供 markdown，本工具只检查 .md 后缀通道",
                remedy="要检查协商通道请用 curl -H 'Accept: text/markdown' 自查。",
            )
        )
    _fill(
        st,
        PositionResult(
            seed=PositionSeed(
                stage=Stage.MD_CHANNEL,
                key=key,
                kind="aggregate",
                probe_url=decl.source_url,
                status=status,
                detail=detail,
                aggregate_of=max(1, len(decl.samples)),
            ),
            finding_ids=(finding.finding_id,) if finding is not None else (),
        ),
    )
    prog.stage(5, STAGE_LABEL[Stage.MD_CHANNEL], detail[:40])


def _budget_left(st: RunState, options: AuditOptions) -> bool:
    """``--max-requests`` 记账。0 = 不限。"""
    if options.max_requests <= 0:
        return True
    spent = st.requests_made + (st.sitemap.requests_spent if st.sitemap is not None else 0)
    return spent < options.max_requests


def _stage_human_path(
    st: RunState,
    options: AuditOptions,
    fetcher: Fetcher,
    prog: ProgressSink,
    *,
    store: FixtureStore | None,
    resolver: HostResolver | None,
    seed_pages: Sequence[str],
) -> None:
    """⑥ 可点击路径。一页一格（P5），一条唯一 norm_url 一条 finding（A16）。"""
    sitemap = st.sitemap
    if sitemap is None:
        return
    if store is None:
        # ``dead_links.classify_link`` 的签名要求一个 FixtureStore（它用 store.has()
        # 判「这次判定是不是回放来的」）。拿不到 fixtures/ 时不静默降级：
        # 本段全部格子留 UNKNOWN(not_fetched) + 一条 CoverageGap。
        st.coverage_gaps.append(
            CoverageGap(
                where="⑥ 可点击路径",
                reason="not_fetched",
                detail="找不到 fixtures/ 索引，死链检查需要它来标记回放来源",
                remedy="设 GEO_AUDIT_FIXTURES 指向 fixtures/ 目录，或重装带 fixtures 的 wheel。",
            )
        )
        prog.stage(6, STAGE_LABEL[Stage.HUMAN_PATH], "缺 fixtures 索引，未评估")
        return
    pages: list[tuple[str, str, PageExtraction]] = []
    for url in seed_pages:
        st.check()
        if not _budget_left(st, options):
            break
        role = _role_of(url, sitemap)
        probe = fetcher.probe(url, expect=Expect.HTML_PAGE)
        st.requests_made += 1
        resp = probe.response
        if probe.verdict is not Verdict.OK or resp is None or not resp.body:
            reason = probe.classification.reason
            _fill(
                st,
                PositionResult(
                    seed=PositionSeed(
                        stage=Stage.HUMAN_PATH,
                        key=url,
                        kind="aggregate",
                        probe_url=url,
                        status=(
                            Status.NOT_APPLICABLE
                            if probe.verdict is Verdict.REAL404
                            else Status.UNKNOWN
                        ),
                        detail=f"起始页抓不下来：HTTP "
                        f"{resp.status if resp is not None else 0} / {reason}",
                        unknown_reason=(reason if probe.verdict is not Verdict.REAL404 else None),
                        unknown_remedy=(
                            UNKNOWN_REMEDY.get(reason)
                            if probe.verdict is not Verdict.REAL404
                            else None
                        ),
                    ),
                    evidence=(
                        evidence_of(resp, user_agent=fetcher.user_agent)
                        if resp is not None
                        else None
                    ),
                ),
            )
            prog.row(_progress_state(Status.UNKNOWN), url, reason)
            continue
        st.pages_fetched += 1
        extraction = extract_page(resp.text, source_page=resp.final_url, source_role=role)
        st.links_instances += len(extraction.targets)
        st.links_capped += sum(g.dropped for g in extraction.gaps)
        for gap in extraction.gaps:
            st.coverage_gaps.append(
                CoverageGap(
                    where=gap.source_page,
                    reason=gap.reason,
                    detail=f"{gap.layer} 封顶 {gap.limit}，截掉 {gap.dropped} 条",
                    remedy="用 --max-links 0 取消上限重跑可以覆盖它。",
                )
            )
        pages.append((url, role, extraction))

    # 唯一目标（去噪前的归并按 norm_url）+ ``--max-links`` 确定性分层抽样。
    unique: dict[str, LinkTarget] = {}
    for _url, _role, extraction in pages:
        for target in extraction.targets:
            unique.setdefault(target.norm_url, target)
    st.links_unique_total = len(unique)
    # A24 的恒等式口径：links_extracted 是**归并后的唯一目标数**，
    # 四个桶（excluded / needs_review / verified / unknown）互斥，剩下的就是被封顶
    # 或被抽样截掉的那一段。实例数另记在 st.links_instances 里（进度行用）。
    st.links_extracted += len(unique)
    planned = sorted(unique)
    if options.max_links > 0 and len(planned) > options.max_links:
        planned = sample_deterministic(planned, options.max_links, seed=options.domain)
        st.links_capped += len(unique) - len(planned)
        st.sampling_note = (
            f"可点击链接 {len(unique)} 条超过 --max-links {options.max_links}，"
            f"改为确定性分层抽样 {len(planned)} 条（抽样，非全量）"
        )
    plan = set(planned)

    verdicts: dict[str, dl.LinkVerdict] = {}
    host_cache: dict[str, dl.HostFacts] = {}
    extracted = frozenset(unique)
    # ``classify_link`` 的签名要一个 httpx.Client（那是「调用方手里只有 client」
    # 的退化路）。我们一律传 fetcher=，所以这个 client 实际不发请求；给它一个
    # 与本次同源的 transport，免得退化路万一被走到时绕过回放。
    with closing(httpx.Client(transport=store.transport())) as client:
        for norm in planned:
            st.check()
            if not _budget_left(st, options):
                break
            target = unique[norm]
            verdict = dl.classify_link(
                target.abs_url,
                source_page=target.source_page,
                ctx=target.ctx,
                client=client,
                store=store,
                fetcher=fetcher,
                source_role=target.source_role,
                audited_domain=sitemap.registrable_domain,
                raw_href=target.raw_href,
                region=target.region,
                extracted_norm_urls=extracted,
                resolver=resolver,
                host_cache=host_cache,
            )
            st.requests_made += verdict.requests_spent
            verdicts[norm] = verdict
            if verdict.state is LinkState.EXCLUDED:
                st.links_excluded += 1
                st.excluded.extend(
                    _exclusion(verdict.url, ex, found_on=target.source_page)
                    for ex in verdict.exclusions
                )
            elif verdict.disposition == "needs_review":
                st.links_needs_review += 1  # 仍然进死链分子（卡点 S4），但自己一桶
            elif verdict.state is LinkState.UNKNOWN:
                st.links_unknown += 1
            else:
                st.links_verified += 1
            if verdict.naive_would_say == "死链":
                st.naive_dead_count += 1

    # 每页一格（P5）
    instances: list[DeadInstance] = []
    for url, _role, extraction in pages:
        dead = alive = judged = eligible = 0
        for target in extraction.targets:
            got = verdicts.get(target.norm_url)
            if got is None or got.state is LinkState.EXCLUDED:
                continue
            eligible += 1
            if got.state is LinkState.DEAD:
                dead += 1
                judged += 1
                instances.append(
                    DeadInstance(
                        abs_url=target.abs_url,
                        source_page=target.source_page,
                        container_sig=target.container_sig,
                        raw_href=target.raw_href,
                        anchor_text=target.ctx.anchor_text or target.anchor_label,
                        severity=SEVERITY_BY_POSITION[_position_class(target, got)],
                    )
                )
            elif got.state is LinkState.ALIVE:
                alive += 1
                judged += 1
        eligible += sum(1 for t in extraction.targets if t.norm_url not in plan)
        if dead:
            status, detail = Status.FAIL, f"{dead} 条死链 / {alive} 条活"
        elif alive:
            status, detail = Status.PASS, f"{alive} 条可点击链接全部活着"
        elif eligible == 0:
            status, detail = Status.NOT_APPLICABLE, "这一页没有可判定的可点击链接"
        else:
            status, detail = Status.UNKNOWN, f"{eligible} 条链接一条都没判成"
        _fill(
            st,
            PositionResult(
                seed=PositionSeed(
                    stage=Stage.HUMAN_PATH,
                    key=url,
                    kind="aggregate",
                    probe_url=url,
                    status=status,
                    detail=detail,
                    aggregate_of=max(1, len(extraction.targets)),
                    unknown_reason="not_fetched" if status is Status.UNKNOWN else None,
                    unknown_remedy=(
                        UNKNOWN_REMEDY["not_fetched"] if status is Status.UNKNOWN else None
                    ),
                ),
            ),
        )
        prog.row(_progress_state(status), url, detail)

    st.audited_dead_instances = len(instances)
    if instances:
        _emit_dead_link_findings(
            st, options, fetcher, instances=instances, verdicts=verdicts, sitemap=sitemap
        )
    prog.stage(
        6,
        STAGE_LABEL[Stage.HUMAN_PATH],
        f"抽取 {st.links_instances} → 归并 {st.links_unique_total} → "
        f"验证 {len(planned)} → 死 {len(instances)}",
    )


def _role_of(url: str, sitemap: SiteMap) -> str:
    path = urlsplit(url).path.rstrip("/")
    host = (urlsplit(url).hostname or "").lower()
    if not path:
        docs = {h.host for h in sitemap.hosts if h.role is HostRole.DOCS}
        return "docs_home" if host in docs else "home"
    for role, marker in (
        ("pricing", "pricing"),
        ("pricing", "plans"),
        ("changelog", "changelog"),
        ("docs_home", "docs"),
        ("help", "help"),
    ):
        if marker in path:
            return role
    return "home"


def _position_class(target: LinkTarget, verdict: dl.LinkVerdict) -> PositionClass:
    if verdict.position_class is not None:
        return verdict.position_class
    return position_class_of(
        target.abs_url, target.ctx, source_role=target.source_role, region=target.region
    )


def _emit_dead_link_findings(
    st: RunState,
    options: AuditOptions,
    fetcher: Fetcher,
    *,
    instances: Sequence[DeadInstance],
    verdicts: Mapping[str, dl.LinkVerdict],
    sitemap: SiteMap,
) -> None:
    """死链 finding + 根因归并。一条唯一 ``norm_url`` = 一条 finding（A16）。"""
    statuses: dict[str, int] = {}
    host_ok: dict[str, int] = {}
    alive_links: set[str] = set()
    for norm, verdict in verdicts.items():
        if verdict.status is None:
            continue
        statuses[norm] = verdict.status
        if verdict.state is LinkState.ALIVE:
            alive_links.add(norm)
            host = url_host(norm)
            host_ok[host] = host_ok.get(host, 0) + 1
    flat_sitemap = tuple(u for urls in sitemap.sitemap_urls.values() for u in urls)
    ledger = ProbeLedger(
        statuses=statuses,
        sitemap_urls=flat_sitemap,
        host_ok_counts=host_ok,
        alive_site_links=frozenset(alive_links),
    )
    targets = fold_instances(instances)
    causes = merge_root_causes(targets, ledger=ledger, audited_domain=sitemap.registrable_domain)
    st.root_causes.extend(causes)
    cause_of: dict[str, RootCause] = {}
    for cause in causes:
        for fid in cause.finding_ids:
            cause_of[fid] = cause

    for target in targets:
        got = verdicts.get(target.norm_url)
        if got is None:
            continue
        st.findings.append(
            _dead_link_finding(
                target,
                got,
                options=options,
                fetcher=fetcher,
                cause=cause_of.get(target.identity),
                sitemap_urls=flat_sitemap,
            )
        )


def _dead_link_finding(
    target: DeadTarget,
    verdict: dl.LinkVerdict,
    *,
    options: AuditOptions,
    fetcher: Fetcher,
    cause: RootCause | None,
    sitemap_urls: Sequence[str],
) -> Finding:
    """一条死链的报告卡片（§6.2 的五段呈现所需字段全部填满）。"""
    ua = fetcher.user_agent
    position = verdict.position_class or PositionClass.BODY
    severity = SEVERITY_BY_POSITION[position]
    fid = target.identity
    fix = suggest_fix(
        target.abs_url,
        source_page=target.source_page,
        severity=severity,
        prober=fetcher,
        sitemap_urls=sitemap_urls,
        locator=f"锚文本「{target.anchor_text}」的链接（{target.locus}）",
    )
    evidence = Evidence(
        url=target.abs_url,
        http_status=verdict.status,
        final_url=verdict.final_url or target.abs_url,
        curl_repro=f"curl -sSL -A '{ua}' '{target.abs_url}'",
    )
    control = (
        Evidence(
            url=verdict.confirmations[0][0],
            http_status=verdict.confirmations[0][1],
            curl_repro=f"curl -sSL -A '{ua}' '{verdict.confirmations[0][0]}'",
        )
        if verdict.confirmations
        else None
    )
    return Finding(
        finding_id=fid,
        kind="dead_link",
        check_id=DEAD_LINK_CHECK_ID,
        title=f"{target.source_page} 上的「{target.anchor_text or target.abs_url}」点了就 404",
        severity=severity,
        position_class=position,
        stage=Stage.HUMAN_PATH,
        target=evidence,
        control=control,
        found_on=target.source_page,
        anchor_text=target.anchor_text or None,
        occurrences=target.occurrences,
        occurrence_pages=target.occurrence_pages,
        occurrence_hrefs=target.occurrence_hrefs,
        root_cause_id=cause.root_cause_id if cause is not None else "",
        root_cause_summary=cause.summary if cause is not None else "",
        sibling_count=cause.unique_target_count if cause is not None else 1,
        fix=fix.hint,
        naive_conclusion=f"只看首跳状态码的实现会说：{verdict.naive_would_say or '活的'}",
        naive_is_wrong=verdict.naive_would_say == "活的",
        actual_conclusion=f"HTTP {verdict.status}，同 host 有活着的对照",
        confidence=verdict.confidence,
        why_it_matters=(
            f"这条链接在「{POSITION_LABEL[position]}」上。"
            "人点了拿到 404，AI 抓到的也是 404 —— 这一段链路对两边同时断掉。"
        ),
        fp_guard=verdict.evidence,
        fp_note=(
            "静态 HTML 判不了它是否对访客可见，请人工看一眼。"
            if verdict.disposition == "needs_review"
            else None
        ),
        suppress_hint=f"不认这条：geo-audit {options.domain} --ignore {fid}",
        display_value=f"HTTP {verdict.status}",
        detail={"rule_id": verdict.rule_id, "reason": verdict.reason},
        counted_as_hit=verdict.counted_dead,
        severity_signals={
            "page_role": target.source_page,
            "anchor": target.anchor_text,
            "anchor_class": verdict.exclusions[0].rule_id if verdict.exclusions else "",
            "region": POSITION_LABEL[position],
        },
        exposure_pages=target.occurrence_pages or (target.source_page,),
    )


# --------------------------------------------------------------------------- #
# 组装
# --------------------------------------------------------------------------- #


def _assemble(
    st: RunState,
    options: AuditOptions,
    *,
    user_agent: str,
    scanned_at: str,
    duration_s: float,
    interrupted: bool,
    checks: frozenset[str],
) -> Report:
    positions = build_positions(
        st.skeleton, st.results, unfilled_reason="interrupted" if interrupted else "not_fetched"
    )
    sitemap = st.sitemap
    naive_rows: tuple[NaiveContrast, ...] = ()
    if sitemap is not None:
        naive_rows = NaiveEmulator().rows(sitemap, positions)
    counts = count_positions(
        positions,
        st.findings,
        st.root_causes,
        naive_rows,
        naive_dead_count=st.naive_dead_count,
        audited_dead_instances=st.audited_dead_instances,
    )
    coverage = Coverage(
        checked=tuple(CHECKED_LABELS[c] for c in CHECK_IDS if c in checks),
        not_checked=NOT_CHECKED,
        positions_total=counts.positions,
        links_extracted=st.links_extracted,
        links_excluded=st.links_excluded,
        links_needs_review=st.links_needs_review,
        links_verified=st.links_verified,
        links_unknown=st.links_unknown,
        pages_fetched=st.pages_fetched,
        index_links_sampled=st.index_links_sampled,
        sampling_note=st.sampling_note,
        robots_respected=not options.ignore_robots,
        requests_made=st.requests_made + (sitemap.requests_spent if sitemap is not None else 0),
        budget_cap=options.max_requests,
        interrupted=interrupted,
    )
    channel = has_ai_channel(sitemap.ai_path_probes) if sitemap is not None else False
    headline, kind = make_headline(
        counts,
        has_ai_channel=channel,
        sampled_ratio=sampled_ratio(coverage),
        interrupted=interrupted,
    )
    return Report(
        schema_version=SCHEMA_VERSION,
        tool_version=TOOL_VERSION,
        denoise_ruleset_version=DENOISE_RULESET_VERSION,
        domain=options.domain,
        scanned_at=scanned_at,
        duration_s=round(duration_s, 3),
        contact=options.contact,
        user_agent=user_agent,
        headline=headline,
        verdict_kind=kind,
        positions=positions,
        findings=tuple(st.findings),
        root_causes=tuple(st.root_causes),
        naive_table=naive_rows,
        fragilities=build_fragilities(options.domain, st.controls, st.index_reports),
        coverage_gaps=tuple(st.coverage_gaps),
        excluded=tuple(st.excluded),
        apex_www=sitemap.apex_www if sitemap is not None else None,
        coverage=coverage,
        counts=counts,
    )


def audit_domain(
    options: AuditOptions,
    *,
    fetcher: Fetcher | None = None,
    store: FixtureStore | None = None,
    resolver: HostResolver | None = None,
    progress: ProgressSink | None = None,
    state: RunState | None = None,
    before_request: Callable[[str], None] | None = None,
) -> Report:
    """跑完六段，产出一份 ``Report``。

    中断（§7.5）：主线程收到 ``KeyboardInterrupt``（或 transport 抛 ``Cancelled``）
    → 置起 ``stop`` → 已完成的格子照常渲染、未跑到的格子标
    ``UNKNOWN(interrupted)`` → ``coverage.interrupted = True`` →
    ``verdict_kind = "unusable"`` → CLI 退出 130。

    apex 与 www 都不可达 → 抛 :class:`DomainUnreachableError`（退出码 3，不生成报告）。
    """
    st = state or RunState()
    prog = progress or NullProgress()
    checks = enabled_checks(options)
    started = time.monotonic()
    scanned_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    st.skeleton = list(bare_skeleton(options.domain))  # 先建：一个请求都还没发

    own = fetcher is None
    active = fetcher or build_fetcher(
        options, stop=st.stop, store=store, before_request=before_request
    )
    interrupted = False
    try:
        try:
            _run_stages(
                st,
                options,
                active,
                prog,
                store=store,
                resolver=resolver,
                checks=checks,
            )
        except (KeyboardInterrupt, Cancelled):
            interrupted = True
            st.stop.set()
    finally:
        if own:
            with suppress(Exception):
                active.close()
    return _assemble(
        st,
        options,
        user_agent=active.user_agent,
        scanned_at=scanned_at,
        duration_s=time.monotonic() - started,
        interrupted=interrupted,
        checks=checks,
    )


def _default_store() -> FixtureStore | None:
    """仓库内 / wheel 内的 fixtures 索引。找不到就返回 None（见 ⑥ 的处理）。"""
    try:
        return FixtureStore.default()
    except FixtureError:
        return None


def _run_stages(
    st: RunState,
    options: AuditOptions,
    fetcher: Fetcher,
    prog: ProgressSink,
    *,
    store: FixtureStore | None,
    resolver: HostResolver | None,
    checks: frozenset[str],
) -> None:
    """① → ⑥。每段开始前检查取消标志。"""
    st.check()
    sitemap = discover(
        fetcher,
        options.domain,
        tiers=DEFAULT_TIERS,
        wellknown=options.wellknown,
        budget=options.max_requests,
        resolver=resolver,
    )
    st.sitemap = sitemap
    if domain_unreachable(sitemap):
        raise DomainUnreachableError(
            f"{options.domain}：apex 与 www 都解析失败或连不上，不生成报告。"
        )
    st.controls = _controls_of(fetcher, sitemap)
    seed_pages = seed_page_urls(sitemap, options.seeds)
    # 骨架就位（先建后填）：这一步之后格数不再变化。
    st.skeleton = list(skeleton_seeds(sitemap, checks=checks, seed_pages=seed_pages))
    found = sum(1 for p in sitemap.ai_path_probes if p.verdict is Verdict.OK)
    prog.stage(
        1,
        STAGE_LABEL[Stage.DISCOVERY],
        f"探 {len(sitemap.ai_path_probes)} 个位置 … {found} 处有文件",
    )

    if "ai_path" in checks:
        st.check()
        _stage_ai_path(st, options, fetcher, prog)
        st.check()
        _stage_index_links(st, options, fetcher, prog)
        st.check()
        _stage_md_channel(st, options, fetcher, prog)
    if options.fix_candidates:
        st.check()
        _stage_fix_candidates(st, options, fetcher, prog)
    if "dead_links" in checks:
        st.check()
        _stage_human_path(
            st,
            options,
            fetcher,
            prog,
            store=store or _default_store(),
            resolver=resolver,
            seed_pages=seed_pages,
        )
    st.check()


__all__ = [
    "AI_PATH_RULES",
    "CHECK_IDS",
    "DEFAULT_FAIL_ON",
    "DEFAULT_FORMAT",
    "DEFAULT_MAX_LINKS",
    "DEFAULT_MAX_REQUESTS",
    "DEFAULT_OUT_DIR",
    "DEFAULT_RATE",
    "DEFAULT_RESOLVERS",
    "DEFAULT_RETRIES",
    "DEFAULT_TIMEOUT",
    "EXIT_FINDINGS",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "EXIT_UNREACHABLE",
    "EXIT_UNTRUSTED",
    "EXIT_USAGE",
    "INTERRUPT_BANNER_TEMPLATE",
    "RATE_TOO_FAST_MSG",
    "RULE_REGISTRY",
    "SEVERITY_BY_POSITION",
    "SEVERITY_RANK",
    "STAGE_LABEL",
    "AuditOptions",
    "Cancelled",
    "Counts",
    "Coverage",
    "CoverageGap",
    "DomainUnreachableError",
    "Exclusion",
    "Fragility",
    "InterruptibleLimiter",
    "NullProgress",
    "Position",
    "PositionResult",
    "ProgressSink",
    "Report",
    "RunState",
    "StopTransport",
    "audit_domain",
    "build_fetcher",
    "build_positions",
    "count_positions",
    "exit_code_for",
    "interrupt_banner",
    "make_headline",
    "nearest_ids",
    "sampled_ratio",
    "skeleton_seeds",
    "valid_ids",
]


def _stage_fix_candidates(
    st: RunState, options: AuditOptions, fetcher: Fetcher, prog: ProgressSink
) -> None:
    """⑦ 给每条死链找一个**验证过**的替代地址。

    **为什么默认关**：实测 mistral 的 75 条死链，机械变换验完用了 166 个请求，
    直接吃穿默认的 120 上限。开了之后按剩余预算尽力做，剩下的如实记成覆盖缺口
    —— 不是静默少做。

    **判定权不外借**：机械变换与模型候选走**同一条**验活路径，模型提的不因为
    「是 AI 说的」而豁免。实测依据在 tests/data/l1_calibration.json：模型自称
    有把握的 32 条里有 7 条是 404，拿它的自评当闸门会发布 7 条把人引到 404
    的建议。
    """
    dead_kinds = ("index_link_dead", "dead_link")
    targets = [(i, f) for i, f in enumerate(st.findings) if f.kind in dead_kinds and f.fix is None]
    if not targets:
        return

    def probe(url: str) -> tuple[int | None, Verdict]:
        # **不用 liveness_only。** 第一版用了，实测 75 条候选里 73 条判成
        # UNKNOWN/body_truncated —— 因为 LIVENESS_BYTE_CAP 是 64 KiB，而这些
        # 文档页正好卡在 65,536 字节，截断之后判定层按设计「不做指纹判定」。
        #
        # 那个 64 KiB 上限本身是对的（截断正文的哈希跟完整正文不同，是测量假象）。
        # 错在我选了它：**「这页适不适合当替代」是内容问题，不是存活问题。**
        # 为省流量选 liveness_only，省下来的代价是拿到了错答案 —— 工具只找到
        # 2 条替代地址，而实际有几十条。
        #
        # 走完整内容路径之后判定层能真正指纹，于是一个 200 的兜底页会被判成
        # 软 404 而**不**被当成修复目标 —— 那正是这里需要的严格：把「200 但其实
        # 是兜底页」的地址写进建议，甲方改完还是错的。
        st.requests_made += 1
        p = fetcher.probe(url, expect=Expect.ANY)
        resp = p.response
        return (resp.status if resp is not None else None, p.verdict)

    results: dict[int, CandidateResult] = {}
    skipped = 0
    for idx, finding in targets:
        st.check()
        if not _budget_left(st, options):
            skipped += 1
            continue
        results[idx] = find_fix_candidate(
            finding.target.url,
            probe=probe,
            model_candidates=options.model_candidates.get(finding.target.url, ()),
            locator=finding.found_on or "",
        )

    graded = dict(zip(results, grade_candidates(list(results.values())), strict=True))
    findings = list(st.findings)
    for idx, result in graded.items():
        findings[idx] = replace(findings[idx], fix=result.fix)
    st.findings = findings

    exact = sum(1 for r in graded.values() if r.quality is CandidateQuality.EXACT)
    downgraded = sum(1 for r in graded.values() if r.quality is CandidateQuality.DOWNGRADED)
    none = sum(1 for r in graded.values() if r.quality is CandidateQuality.NONE)
    unchecked = sum(1 for r in graded.values() if r.quality is CandidateQuality.UNCHECKED)
    prog.stage(
        7,
        "⑦ 修复目标",
        f"精确 {exact} / 降级 {downgraded} / 查过没有 {none} / 没能查 {unchecked}"
        + (f" / 预算不够未查 {skipped}" if skipped else ""),
    )

    if unchecked:
        # **必须披露。** 「候选一条都没验成」与「查过确实没有替代地址」在报告里
        # 长得一样（都是 after=None），而含义相反。实测 replay 模式下候选响应
        # 没录进 fixtures，75 条全落这一档 —— 不说的话读的人会以为我们查过了。
        st.coverage_gaps.append(
            CoverageGap(
                where="⑦ 修复目标",
                reason="not_fetched",
                detail=(
                    f"{unchecked} 条死链的候选替代地址**一条都没能验证**"
                    "（缺快照或请求失败）。这不是「它们没有替代地址」，是我们没查到。"
                    f"另有 {none} 条是逐个试过、确实不存在。"
                ),
                remedy=(
                    "replay 模式下候选地址要先实录："
                    "在 fixtures/urls.txt 里补这些候选后跑 capture_fixtures.py --live；"
                    "或者去掉 --replay-fixtures 直接打活网。"
                ),
            )
        )

    if skipped:
        st.coverage_gaps.append(
            CoverageGap(
                where="⑦ 修复目标",
                reason="not_fetched",
                detail=(
                    f"还有 {skipped} 条死链没找替代地址：请求预算用完了。"
                    f"已查 {len(graded)} 条。这不是「那些没有替代地址」，是「我们没查」。"
                ),
                remedy=(
                    f"用 --max-requests {options.max_requests * 2} 重跑，"
                    "或 --only ai_path 缩小范围。"
                ),
            )
        )
