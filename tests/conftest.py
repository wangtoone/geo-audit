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
from collections.abc import Callable
from typing import Any, NoReturn

import httpx
import pytest


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
