"""两个新的理由码：``waf_challenge_header`` 与 ``robots_unreadable``。

## 为什么要拆出新码，而不是继续借用旧的

* ``waf_challenge_body`` 的意思是「正文长得像挑战页」—— 我们的猜测。响应头
  （``cf-mitigated`` / ``x-amzn-waf-action``）是厂商保证的事实，证据强度不同，
  报告里要说清是哪一种触发的。借用旧码，读报告的人看到 ``body`` 会去翻正文，翻不到。
* ``robots_disallowed`` 的补救文案是「你的 robots.txt 禁止抓这个路径，我们遵守了」。
  robots.txt **读不到**（5xx / 网络错误 / 挑战页 / 限流 / 跳转过多）时再用它，
  对站点是一句假话 —— 站点什么都没禁止，是我们没能看。两种状态必须分开。

契约影响：``schema/report-1.schema.json`` 的 ``Reason`` 枚举多两个值（只增不减，
``SCHEMA_VERSION`` 不变）；``DENOISE_RULESET_VERSION`` / ``TABLE_VERSION`` 随指纹表一起 bump。
"""

from __future__ import annotations

import re
from typing import get_args

import pytest

from geo_audit.fetch import fingerprints as fp
from geo_audit.fetch.classify import classify_response, is_blocked
from geo_audit.models import (
    DENOISE_RULESET_VERSION,
    NOT_EVALUATED_REASONS,
    UNKNOWN_REMEDY,
    Expect,
    Reason,
    Status,
    Verdict,
    verdict_to_status,
)

CF_BODY = (
    "<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"
)


@pytest.mark.parametrize("code", ["waf_challenge_header", "robots_unreadable"])
def test_new_reason_is_wired_into_every_enumeration(code: str) -> None:
    assert code in get_args(Reason)
    assert code in NOT_EVALUATED_REASONS  # 渲染器必须把它放进「未能评估」区
    assert len(UNKNOWN_REMEDY[code]) > 40  # 每条 UNKNOWN 都要有可执行的补救办法（A32）


def test_the_two_robots_reasons_do_not_blame_the_site_for_what_we_could_not_read() -> None:
    unreadable = UNKNOWN_REMEDY["robots_unreadable"]
    assert "不是说你的 robots.txt 写了禁止" in unreadable
    assert "RFC 9309" in unreadable
    # 而 robots_disallowed 那条文案是「你写了禁止」，两条不能混
    assert "禁止抓这个路径" in UNKNOWN_REMEDY["robots_disallowed"]
    assert "禁止抓这个路径" not in unreadable


# ── 响应头触发 → waf_challenge_header；只有正文触发 → 仍是 waf_challenge_body ─────────
def test_header_trigger_gets_the_header_reason() -> None:
    hit = is_blocked(403, {"cf-mitigated": "challenge"}, CF_BODY, url="https://x.test/")
    assert hit is not None and hit[1] == "waf_challenge_header"


def test_body_only_trigger_keeps_the_body_reason() -> None:
    """没有厂商头、只有正文指纹（旧行为）：理由码不变 —— 别让已有的报告悄悄换码。"""
    hit = is_blocked(403, {"content-type": "text/html"}, CF_BODY, url="https://x.test/")
    assert hit is not None and hit[1] == "waf_challenge_body"


def test_vercel_challenge_429_is_a_challenge_not_a_rate_limit() -> None:
    """tenderly.co 的真实形态：429 + x-vercel-mitigated: challenge。以前判 rate_limited
    （补救文案是「用 --rate 调慢」），其实是挑战页，调慢没用。"""
    hdr = {"x-vercel-mitigated": "challenge", "x-vercel-challenge-token": "t"}
    hit = is_blocked(429, hdr, "", url="https://tenderly.co/")
    assert hit is not None and hit[1] == "waf_challenge_header"
    # 没有那个头的 429 仍然是限流
    plain = is_blocked(429, {"retry-after": "30"}, "", url="https://tenderly.co/")
    assert plain is not None and plain[1] == "rate_limited"


# ── robots_unreadable 的分类 ───────────────────────────────────────────────
@pytest.mark.parametrize(
    "err",
    [
        "robots_unreadable: HTTP 503",
        "robots_unreadable: 防火墙挑战页（x-amzn-waf-action: challenge，HTTP 202）",
        "robots_unreadable: timeout",
    ],
)
def test_unreadable_robots_is_unknown_with_its_own_reason(err: str) -> None:
    c = classify_response(
        0, {}, "", url="https://x.test/llms.txt", expect=Expect.TEXT_FILE, transport_error=err
    )
    assert c.verdict is Verdict.UNKNOWN
    assert verdict_to_status(c.verdict) is Status.UNKNOWN
    assert c.reason == "robots_unreadable"
    assert "不是站点写了禁止" in c.evidence[0]
    assert err.split(":", 1)[1].strip() in c.evidence[0]  # 具体原因要带在证据里


def test_disallowed_robots_keeps_its_reason() -> None:
    c = classify_response(
        0, {}, "", url="https://x.test/p", transport_error="robots_disallowed: /p"
    )
    assert c.reason == "robots_disallowed"


def test_the_two_version_constants_stay_in_sync() -> None:
    """models.py 的注释写着 DENOISE_RULESET_VERSION「与 fingerprints.TABLE_VERSION 同源」——
    指纹表一改就要两处一起动，否则跨版本的 fp-gate 报告没法比。原来全靠人记，现在钉住。"""
    expected = f"denoise/{fp.TABLE_VERSION}"
    assert expected == DENOISE_RULESET_VERSION
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}\.\d+", fp.TABLE_VERSION)
