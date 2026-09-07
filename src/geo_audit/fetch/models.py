"""Re-export shim —— 本文件不定义任何东西。

数据结构的唯一定义处是 ``geo_audit/models.py``（§3.9 适配 #1）。
这层 shim 存在的唯一理由：冻结的回归测试写着
``from geo_audit.fetch.models import Expect, HostProfile, HttpResponse, RedirectHop, Verdict``，
留着它，A4 的 ``git diff`` 才真的是三个测试文件 0 行改动。

**生产代码一律 ``from ..models import ...``，不要走这里。**
显式列名 + ``__all__``（不用 ``import *``）是为了 mypy strict 的
``no_implicit_reexport``：星号导入的名字不算 re-export，会报错。
"""

from __future__ import annotations

from geo_audit.models import (
    DENOISE_RULESET_VERSION,
    NOT_EVALUATED_REASONS,
    SCHEMA_VERSION,
    TOOL_VERSION,
    VOLATILE_JSON_FIELDS,
    ApexWwwResult,
    Classification,
    DiscoveredHost,
    Expect,
    FindingStatus,
    HostProfile,
    HostRole,
    HttpResponse,
    JsAssessment,
    LinkContext,
    LinkState,
    Probe,
    RedirectHop,
    RobotsInfo,
    SiteMap,
    Status,
    Verdict,
    finalize_response,
    link_state_to_status,
    verdict_to_status,
)

__all__ = [
    "DENOISE_RULESET_VERSION",
    "NOT_EVALUATED_REASONS",
    "SCHEMA_VERSION",
    "TOOL_VERSION",
    "VOLATILE_JSON_FIELDS",
    "ApexWwwResult",
    "Classification",
    "DiscoveredHost",
    "Expect",
    "FindingStatus",
    "HostProfile",
    "HostRole",
    "HttpResponse",
    "JsAssessment",
    "LinkContext",
    "LinkState",
    "Probe",
    "RedirectHop",
    "RobotsInfo",
    "SiteMap",
    "Status",
    "Verdict",
    "finalize_response",
    "link_state_to_status",
    "verdict_to_status",
]
