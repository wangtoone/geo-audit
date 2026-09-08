"""测试全局装闸：断网 + 断 DNS（§3.6）。

**为什么必须有这个文件**：第 4a 步的验收 agent 实测发现，`GEO_AUDIT_FORBID_NETWORK`
在 `src/` 里**没有任何执行点** —— 只有 `scripts/capture_fixtures.py` 与
`scripts/refresh_fixtures.py` 自己看它。也就是说 CI 那条

    GEO_AUDIT_FORBID_NETWORK=1 GEO_AUDIT_FORBID_DNS=1 pytest -m "not live"

里的第一个环境变量当时是装饰性的：一条真发 httpx 请求的测试会静默联网通过。
那正是 §8.1 明令禁止的「静默回落真网络」，只不过发生在测试侧。

`GEO_AUDIT_FORBID_DNS` 有真实执行点（`fetch/resolve.py` 的 `resolve_host` 在未注入
resolver 时直接抛 AssertionError），但那只挡住走 `resolve_host` 的路径；
`socket.getaddrinfo` 与 `_public_resolve` 被直接调用时挡不住，所以这里一并封。

闸只在环境变量为 "1" 时生效，且 **`live` 标记的测试豁免** —— 那些测试的全部意义
就是打真网络（第 4b 步录快照、fixture 新鲜度周检）。
"""

from __future__ import annotations

import os
import socket
from collections.abc import Callable, Iterator
from typing import Any, NoReturn

import httpx
import pytest

from geo_audit.fetch.cache import open_connection_count


def _boom(message: str) -> Callable[..., NoReturn]:
    """返回一个「一被调用就炸」的替身。

    炸而不是返回假数据：假数据会让测试变成「测了个我们自己编的东西」，
    而 AssertionError 会立刻指出是哪条测试想摸网络。
    """

    def _explode(*args: Any, **kwargs: Any) -> NoReturn:
        target = args[0] if args else ""
        raise AssertionError(f"{message}：{target!r}。离线 CI 下必须用 fixture 回放（见 §8.1）。")

    return _explode


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    if request.node.get_closest_marker("live") is not None:
        return  # live 测试就是要打真网络

    if os.environ.get("GEO_AUDIT_FORBID_NETWORK") == "1":
        # 只封真 transport。httpx.MockTransport 是另一个类，fixture 回放照常工作。
        monkeypatch.setattr(
            httpx.HTTPTransport, "handle_request", _boom("测试试图访问真网络"), raising=True
        )

    if os.environ.get("GEO_AUDIT_FORBID_DNS") == "1":
        # socket.getaddrinfo 指定不了 nameserver，所以 R1–R4 用纯 stdlib 写不出来；
        # dnspython 是硬依赖。两条路都要封。
        monkeypatch.setattr(socket, "getaddrinfo", _boom("测试试图做真 DNS 查询"), raising=True)
        monkeypatch.setattr(
            "geo_audit.fetch.resolve._public_resolve",
            _boom("测试试图做真 DNS 查询"),
            raising=True,
        )


@pytest.fixture(autouse=True)
def _no_leaked_sqlite_connections() -> Iterator[None]:
    """每条测试跑完，检查它有没有漏下开着的 sqlite 连接。

    **为什么值得一条 autouse 闸**：漏关的连接在 Python 3.13 上会在 GC 时发
    ``ResourceWarning``，撞上 ``filterwarnings = error`` 直接变成错误 —— 但
    pytest 把它算在「GC 恰好触发时正在跑的那条测试」头上。实测被连坐的三条
    （``test_no_bypass_machinery_in_code`` / ``test_a6_named_types...`` /
    ``test_a27_five_forbidden_patterns...``）都是纯扫源文、一个 HTTP 请求都不发
    的测试，而报错指向 ``coverage/collector.py`` 和 ``httpx/_models.py`` ——
    顺着报错找病因是找不到的，实测烧掉两轮 CI。

    这条闸把它变成：**漏的那条测试自己红**，并且在 3.11/3.12 上一样红，
    不用等 3.13 的 ResourceWarning 才发现。

    比的是差值而不是绝对值：会话级 fixture 合法地跨测试持有连接，
    只有「本条测试新开、又没关掉」才算漏。
    """
    before = open_connection_count()
    yield
    after = open_connection_count()
    assert after <= before, (
        f"这条测试漏了 {after - before} 条没关的 sqlite 连接"
        f"（进入时 {before} 条，退出时 {after} 条）。"
        "漏关的连接在 3.13 上会变成 ResourceWarning，并且会算在别的测试头上 —— "
        "请在这条测试里显式 close()（Fetcher.close() 会连 cache 一起关）。"
    )
