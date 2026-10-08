"""两个新的理由码：``waf_challenge_header`` 与 ``robots_unreadable``。

## 为什么要拆出新码，而不是继续借用旧的

* ``waf_challenge_body`` 的意思是「正文长得像挑战页」—— 我们的猜测。响应头
  （``cf-mitigated`` / ``x-amzn-waf-action``）是厂商保证的事实，证据强度不同，
  报告里要说清是哪一种触发的。借用旧码，读报告的人看到 ``body`` 会去翻正文，翻不到。
* ``robots_disallowed`` 的补救文案是「你的 robots.txt 禁止抓这个路径，我们遵守了」。
  robots.txt **读不到**（5xx / 网络错误 / 跳转成环或超限）时再用它，
  对站点是一句假话 —— 站点什么都没禁止，是我们没能看。两种状态必须分开。
  （防火墙挑战页、429、其余 4xx 是 RFC 9309 的「不可用」，抓取照常进行，不走这个码。）

契约影响：``schema/report-1.schema.json`` 的 ``Reason`` 枚举多两个值（只增不减，
``SCHEMA_VERSION`` 不变）；``DENOISE_RULESET_VERSION`` / ``TABLE_VERSION`` 随指纹表一起 bump。
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
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


def test_the_challenge_remedy_names_every_header_in_the_table_and_the_odd_statuses() -> None:
    """补救文案是手写的，指纹表是另一处：表里加一个头，文案不跟着改，读报告的人就被告知
    「响应头（cf-mitigated 或 x-amzn-waf-action）」，而实际触发的是第三个头。"""
    remedy = UNKNOWN_REMEDY["waf_challenge_header"]
    for name, _values in fp.CHALLENGE_HEADERS:
        assert name in remedy, f"{name} 在指纹表里，补救文案没提它"
    assert "202" in remedy and "429" in remedy  # 不是只有 403
    assert "不是限流" in remedy  # tenderly.co：Vercel 的挑战是 429，但调慢没用


def test_the_two_robots_reasons_do_not_blame_the_site_for_what_we_could_not_read() -> None:
    unreadable = UNKNOWN_REMEDY["robots_unreadable"]
    assert "不是说你的 robots.txt 写了禁止" in unreadable
    assert "RFC 9309" in unreadable
    # RFC 只对 5xx / 网络错误「要求」不抓；跳转成环 / 超限它只是允许当作「没有」，不能说成要求
    assert "要求对 5xx 和网络错误" in unreadable
    assert "允许" in unreadable and "保守" in unreadable
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
        "robots_unreadable: HTTP 503（服务端错误），没读到",
        "robots_unreadable: redirect loop",
        "robots_unreadable: too many redirects (>10)",
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
    # RFC 9309 只对 5xx / 网络错误「要求」不抓，跳转成环是我们取的保守一侧：位置级证据不替 RFC 背书
    assert "RFC" not in c.evidence[0], c.evidence[0]


def test_disallowed_robots_keeps_its_reason() -> None:
    c = classify_response(
        0, {}, "", url="https://x.test/p", transport_error="robots_disallowed: /p"
    )
    assert c.reason == "robots_disallowed"


# ── 指纹表改了就必须 bump 版本 ─────────────────────────────────────────────────
#
# 上面那条只能证明两个版本常量**彼此一致**。把两个都改回旧值、或者改了表却一个都没动，
# 它都是绿的 —— 而已发布报告的页眉里写着 denoise 规则集版本，两张不同的表不能共用一个版本号。
# 这里把「版本 → 表内容摘要」钉在一起：表（模块里所有大写常量）一变，摘要就变，测试红，
# 提示信息告诉你该 bump 哪个常量、改哪个文件。
PIN_FILE = Path(__file__).parent / "data" / "fingerprint_table_pin.json"


def _canon(value: object) -> object:
    if isinstance(value, re.Pattern):
        return ["re", value.pattern, value.flags]
    if isinstance(value, (set, frozenset)):
        return sorted((_canon(v) for v in value), key=repr)
    if isinstance(value, (tuple, list)):
        return [_canon(v) for v in value]
    if isinstance(value, dict):
        return sorted(([_canon(k), _canon(v)] for k, v in value.items()), key=repr)
    return value


def fingerprint_table_digest() -> str:
    table = {
        name: _canon(getattr(fp, name))
        for name in sorted(dir(fp))
        if name.isupper() and name != "TABLE_VERSION"
    }
    blob = json.dumps(table, sort_keys=True, ensure_ascii=False, default=repr)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def test_changing_the_fingerprint_table_requires_a_version_bump() -> None:
    pin = json.loads(PIN_FILE.read_text(encoding="utf-8"))
    digest = fingerprint_table_digest()
    assert (fp.TABLE_VERSION, digest) == (pin["table_version"], pin["table_digest"]), (
        f"指纹表现在是 版本 {fp.TABLE_VERSION} / 摘要 {digest}，{PIN_FILE.name} 里钉的是 "
        f"{pin['table_version']} / {pin['table_digest']}。\n"
        "改了表：把 fingerprints.TABLE_VERSION 升一位（models.DENOISE_RULESET_VERSION 由下一条"
        f"测试保证跟着改），再把 {PIN_FILE.name} 更新成新值；没改表却红了：说明有人只动了版本号。"
    )


def test_the_two_version_constants_stay_in_sync() -> None:
    """models.py 的注释写着 DENOISE_RULESET_VERSION「与 fingerprints.TABLE_VERSION 同源」——
    指纹表一改就要两处一起动，否则跨版本的 fp-gate 报告没法比。原来全靠人记，现在钉住。"""
    expected = f"denoise/{fp.TABLE_VERSION}"
    assert expected == DENOISE_RULESET_VERSION
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}\.\d+", fp.TABLE_VERSION)
