"""Ctrl-C 中断路径（§7.5 / 卡点 B24 / A37 / N 组）。

五条断言（§7.5(6) 逐条）：报告生成了、``counts`` 恒等式成立、未跑位置的
``unknown_reason == "interrupted"``、通栏文案在 HTML 里、CLI 退出 130。

**零真信号、零时序依赖、零 sleep。** 做法：注入一个请求计数器（
``pipeline.StopTransport(before_request=...)``），在第 3 个请求时于**主线程**的
stage 循环里 ``st.stop.set()`` 并 ``raise KeyboardInterrupt``。

另外三条是「实现方式本身」的断言（B24 点名的三个坑）：

* ``pipeline.py`` 里**没有** signal handler —— ``signal.SIGINT`` handler 在 worker
  线程里不会触发（Python 只在主线程投递信号），装了也是假的；
* 限速等待走 ``stop.wait(timeout=...)`` 而**不是** ``time.sleep`` ——
  否则中断会挂在 2 秒限速里；
* 位置骨架**先建后填** —— 中断报告上恒等式照样成立。
"""

from __future__ import annotations

import ast
import signal
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from geo_audit import cli
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import DNS_ABSENT_KEY, FixtureResolver, FixtureStore
from geo_audit.models import Status
from geo_audit.pipeline import (
    INTERRUPT_BANNER_TEMPLATE,
    AuditOptions,
    Cancelled,
    InterruptibleLimiter,
    Report,
    RunState,
    StopTransport,
    audit_domain,
    exit_code_for,
    interrupt_banner,
)

CONTACT = "you@yourco.com"
DOMAIN = "acmecloud.io"
SRC = Path(__file__).resolve().parents[1] / "src"

_REAL_INDEX = (
    "# Acme\n\n"
    "- [Quickstart](https://docs.acmecloud.io/quickstart.md)\n"
    "- [Gone](https://docs.acmecloud.io/gone.md)\n"
)
_HOME = "<html><body><a href='/pricing'>Pricing</a></body></html>"

Pages = dict[str, tuple[int, str, str]]


class FakeSite:
    """按 URL 表回放的假站；表里没有的一律 404 + text/html（同时充当对照探针答案）。"""

    def __init__(self, pages: Pages) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requested.append(url)
        row = self.pages.get(url)
        if row is None:
            return httpx.Response(
                404, headers={"content-type": "text/html"}, text="<title>404</title>not found"
            )
        status, ctype, body = row
        return httpx.Response(status, headers={"content-type": ctype}, text=body)


def _site() -> FakeSite:
    return FakeSite(
        {
            f"https://{DOMAIN}/": (200, "text/html", _HOME),
            f"https://www.{DOMAIN}/": (200, "text/html", _HOME),
            f"https://docs.{DOMAIN}/": (200, "text/html", "<html><body>docs</body></html>"),
            f"https://docs.{DOMAIN}/llms.txt": (200, "text/plain", _REAL_INDEX),
            f"https://www.{DOMAIN}/llms.txt": (200, "text/plain", _REAL_INDEX),
        }
    )


def _resolver() -> FixtureResolver:
    table: dict[str, dict[str, Any]] = {
        host: {"addresses": ["203.0.113.10"], "resolver": "system", "poisoned": False}
        for host in (DOMAIN, f"www.{DOMAIN}", f"docs.{DOMAIN}")
    }
    table[DNS_ABSENT_KEY] = {
        "addresses": [],
        "resolver": "none",
        "poisoned": False,
        "error": "NXDOMAIN",
    }
    return FixtureResolver(table, source="tests/test_interrupt.py")


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """限流器的 sleep 掐掉（限流逻辑本身在 test_infra.py 里另有断言）。

    ⚠️ 本文件的中断断言**不依赖**这个 fixture：它们靠取消标志，不靠时间。
    """
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time.sleep", lambda _seconds: None)


def _fetcher(
    site: FakeSite,
    tmp_path: Path,
    *,
    stop: threading.Event,
    before_request: Callable[[str], None] | None = None,
) -> Fetcher:
    return Fetcher(
        FetcherConfig(contact=CONTACT, interval=2.0, respect_robots=False),
        cache=HttpCache(tmp_path / "cache.sqlite3", ua_profile="test"),
        limiter=DomainLimiter(2.0),
        transport=StopTransport(
            httpx.MockTransport(site.handler), stop, before_request=before_request
        ),
        probe_url_provider=lambda url: f"https://{httpx.URL(url).host}/geo-audit-probe-x9f2.txt",
    )


@pytest.fixture
def interrupted_report(tmp_path: Path) -> Iterator[Report]:
    """在第 3 个请求处中断的一次真实扫描（零信号、零 sleep）。"""
    site = _site()
    state = RunState()
    seen: list[str] = []

    def counter(url: str) -> None:
        seen.append(url)
        if len(seen) == 3:
            state.stop.set()  # 通知所有 worker
            raise KeyboardInterrupt  # 主线程的 stage 循环里抛，与真 Ctrl-C 同路

    fetcher = _fetcher(site, tmp_path, stop=state.stop, before_request=counter)
    try:
        yield audit_domain(
            AuditOptions(domain=DOMAIN, contact=CONTACT, max_requests=0),
            fetcher=fetcher,
            store=FixtureStore(tmp_path / "empty-fixtures"),
            resolver=_resolver(),
            state=state,
        )
    finally:
        fetcher.close()
    assert len(seen) == 3, "中断之后不许再发请求"


# --------------------------------------------------------------------------- #
# §7.5(6) 的五条
# --------------------------------------------------------------------------- #


def test_report_is_still_produced(interrupted_report: Report) -> None:
    """(1) 报告生成了，且明说自己不可信（§7.5(5)）。"""
    report = interrupted_report
    assert report.coverage.interrupted is True
    assert report.verdict_kind == "unusable"
    assert report.headline.startswith("扫描被中断")
    assert report.counts.positions >= 4  # 骨架先建，所以格子在


def test_counts_identity_holds_on_interrupted_report(interrupted_report: Report) -> None:
    """(2) A27 恒等式在中断报告上照样成立 —— 这正是「先建后填」的目的。"""
    c = interrupted_report.counts
    assert c.positions == len(interrupted_report.positions)
    assert c.positions_pass + c.positions_fail + c.positions_unknown + c.positions_na == c.positions
    assert c.positions_unknown >= 1


def test_unfilled_positions_are_marked_interrupted(interrupted_report: Report) -> None:
    """(3) 未跑到的格子 ``unknown_reason == "interrupted"`` + 有补救办法。"""
    interrupted = [
        p
        for p in interrupted_report.positions
        if p.status is Status.UNKNOWN and p.unknown_reason == "interrupted"
    ]
    assert interrupted, "至少有一格没轮到"
    for p in interrupted:
        assert p.unknown_remedy
        assert "中断" in p.unknown_remedy


def test_banner_text_is_fixed_and_lands_in_html(interrupted_report: Report) -> None:
    """(4) 通栏三行固定文案（§7.5(4)）出现在 HTML 里。"""
    banner = interrupt_banner(interrupted_report)
    missing = sum(
        1
        for p in interrupted_report.positions
        if p.status is Status.UNKNOWN and p.unknown_reason == "interrupted"
    )
    assert banner == INTERRUPT_BANNER_TEMPLATE.format(
        done=interrupted_report.counts.positions - missing,
        missing=missing,
        domain=DOMAIN,
        contact=CONTACT,
    )
    assert banner.startswith("⚠ 扫描被中断（Ctrl-C）。")
    assert "只是没轮到，不是你的站有问题" in banner
    assert "命中缓存，不会重打已完成的请求" in banner

    html = cli.render_html(cli.report_to_dict(interrupted_report))
    assert "扫描被中断（Ctrl-C）" in html
    assert 'id="interrupted"' in html


def test_cli_exits_130(
    interrupted_report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(5) CLI 退出 130，且 130 压过 2 与 1。"""
    assert exit_code_for(interrupted_report) == 130
    monkeypatch.setattr(cli, "audit_domain", lambda *_a, **_k: interrupted_report)
    code = cli.main(
        [DOMAIN, "--contact", CONTACT, "--out", str(tmp_path / "out"), "--format", "json,html"]
    )
    assert code == 130
    assert (tmp_path / "out" / f"{DOMAIN}.html").exists()


# --------------------------------------------------------------------------- #
# B24 点名的三个坑
# --------------------------------------------------------------------------- #


def test_no_signal_handler_anywhere_in_pipeline() -> None:
    """**不许装 signal handler** —— worker 线程里根本不会触发它（§7.5(1)）。"""
    text = (SRC / "geo_audit" / "pipeline.py").read_text("utf-8")
    tree = ast.parse(text)
    imported_signal = any(
        isinstance(node, ast.Import) and any(a.name == "signal" for a in node.names)
        for node in ast.walk(tree)
    )
    assert not imported_signal, "pipeline.py 不许 import signal"
    assert "signal.signal(" not in text
    # 提到 signal.SIGINT 的只许是 docstring 里「为什么不装」那段说明。
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "SIGINT" in line:
            assert lineno < 40, f"第 {lineno} 行不该出现 SIGINT（只许在模块 docstring 里解释）"


def test_sigint_handler_untouched_by_a_scan(interrupted_report: Report) -> None:
    """跑完一次（被中断的）扫描后，进程的 SIGINT handler 还是 Python 默认的。"""
    assert interrupted_report.coverage.interrupted  # 确保扫描真跑过
    assert signal.getsignal(signal.SIGINT) in (signal.default_int_handler, signal.SIG_DFL)


def test_limiter_waits_on_the_stop_flag_not_time_sleep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``DomainLimiter.hold()`` 的 ``time.sleep`` 换成 ``stop.wait(timeout=remaining)``。

    做法：把 ``ratelimit.time.sleep`` 换成「一被调用就炸」。取消标志已置起时
    ``hold()`` 必须立刻抛 ``Cancelled``，一秒都不睡。
    """
    monkeypatch.setattr(
        "geo_audit.fetch.ratelimit.time.sleep",
        lambda _s: pytest.fail("中断路径不许用 time.sleep（§7.5(2)）"),
    )
    stop = threading.Event()
    limiter = InterruptibleLimiter(2.0, stop)
    with limiter.hold(f"www.{DOMAIN}"):  # 第一次：last_hit == 0，没有等待
        pass
    stop.set()
    with pytest.raises(Cancelled), limiter.hold(f"www.{DOMAIN}"):
        pytest.fail("取消标志置起后不许把请求放出去")


def test_stop_flag_alone_produces_an_interrupted_report(tmp_path: Path) -> None:
    """取消标志置起后，``StopTransport`` 在**请求发出前**抛 ``Cancelled``。

    这条覆盖 worker 侧的路径：worker 拿到的不是 KeyboardInterrupt（信号只投给
    主线程），而是协作式取消标志。
    """
    site = _site()
    state = RunState()
    state.stop.set()
    fetcher = _fetcher(site, tmp_path, stop=state.stop)
    try:
        report = audit_domain(
            AuditOptions(domain=DOMAIN, contact=CONTACT),
            fetcher=fetcher,
            store=FixtureStore(tmp_path / "empty-fixtures"),
            resolver=_resolver(),
            state=state,
        )
    finally:
        fetcher.close()
    assert site.requested == [], "取消标志置起后一个请求都不许发"
    assert report.coverage.interrupted is True
    c = report.counts
    assert c.positions_pass + c.positions_fail + c.positions_unknown + c.positions_na == c.positions
    assert c.positions_unknown == c.positions  # 一格都没填上


def test_skeleton_is_built_before_any_request(tmp_path: Path) -> None:
    """「先建后填」：一个请求都还没发时，骨架已经有 P1/P2/P4 的格子。"""
    state = RunState()
    state.stop.set()
    site = _site()
    fetcher = _fetcher(site, tmp_path, stop=state.stop)
    try:
        audit_domain(
            AuditOptions(domain=DOMAIN, contact=CONTACT),
            fetcher=fetcher,
            store=FixtureStore(tmp_path / "empty-fixtures"),
            resolver=_resolver(),
            state=state,
        )
    finally:
        fetcher.close()
    keys = {f"{c.stage.value}:{c.key}" for c in state.skeleton}
    assert "md_channel:md" in keys
    assert f"discovery:www.{DOMAIN}" in keys
    assert f"index_file:{DOMAIN}/llms.txt" in keys
