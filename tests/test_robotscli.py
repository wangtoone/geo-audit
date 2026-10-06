"""``geo-audit robots``：端到端（MockTransport，不碰网络）。"""

from __future__ import annotations

import json
import time
import types

import httpx
import pytest

from geo_audit import cli
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.robotscli import run, to_host

ARGS = ["--contact", "ci@geo-audit.invalid"]

TRAIN_BLOCKED = """\
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: *
Allow: /
Disallow: /workspace/
"""


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """限速下限（2s）是合规约束，测试里不能调低 —— 改成**记录**要睡多久、但不真睡。"""
    slept: list[float] = []
    fake = types.SimpleNamespace(monotonic=time.monotonic, sleep=slept.append)
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time", fake)
    return slept


def _fetcher(robots: dict[str, tuple[int, str]]) -> Fetcher:
    def handler(req: httpx.Request) -> httpx.Response:
        status, body = robots.get(req.url.host, (404, ""))
        return httpx.Response(status, headers={"content-type": "text/plain"}, text=body)

    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )


def test_train_blocked_search_open(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["a.test", *ARGS], fetcher=_fetcher({"a.test": (200, TRAIN_BLOCKED)}))
    out = capsys.readouterr().out
    assert rc == 0
    line = {ln.split()[0]: ln for ln in out.splitlines() if ln.startswith("    ")}
    assert "GPTBot" in line
    assert "全站禁止" in line["GPTBot"] and "有写它名字的组" in line["GPTBot"]
    assert "全站禁止" in line["ClaudeBot"]
    assert "部分路径禁止" in line["OAI-SearchBot"]  # 只禁 /workspace/
    assert "落到 User-agent: *" in line["OAI-SearchBot"]
    assert "⚠" not in out


def test_search_bot_blocked_via_wildcard_is_called_out(capsys: pytest.CaptureFixture[str]) -> None:
    raw = "User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow: /\n"
    rc = run(["a.test", *ARGS], fetcher=_fetcher({"a.test": (200, raw)}))
    out = capsys.readouterr().out
    assert rc == 0
    assert "⚠ 检索类爬虫" in out and "OAI-SearchBot" in out


def test_unreadable_robots_is_not_reported_as_blocked(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["a.test", *ARGS], fetcher=_fetcher({"a.test": (503, "")}))
    out = capsys.readouterr().out
    assert rc == 3
    assert "没读到 robots.txt" in out
    assert "全站禁止" not in out  # 没读到 ≠ 站方禁止


def test_missing_robots_txt_is_allow_all_and_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run(["a.test", *ARGS], fetcher=_fetcher({}))  # 404
    out = capsys.readouterr().out
    assert rc == 0
    assert "站点没有 robots.txt" in out and "放行" in out


def test_json_output_shape_and_multiple_hosts(capsys: pytest.CaptureFixture[str]) -> None:
    f = _fetcher({"a.test": (200, TRAIN_BLOCKED), "b.test": (404, "")})
    rc = run(["https://a.test/pricing", "b.test", "a.test", "--json", *ARGS], fetcher=f)
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert [d["host"] for d in data] == ["a.test", "b.test"]  # URL 取 host，重复去掉
    gpt = next(c for c in data[0]["crawlers"] if c["token"] == "GPTBot")
    assert gpt == {
        "token": "GPTBot",
        "operator": "OpenAI",
        "role": "training",
        "access": "blocked_all",
        "matched": "specific",
        "deciding_rule": "Disallow: /",
    }
    assert data[1]["policy"] == "allow_all"


def test_politeness_between_hosts(_no_real_sleep: list[float]) -> None:
    # 同一注册域的两个 host 共用一个限速桶：第二次请求前必须被要求等满 ~2s
    f = _fetcher({"a.example.test": (200, ""), "b.example.test": (200, "")})
    assert run(["a.example.test", "b.example.test", *ARGS], fetcher=f) == 0
    assert _no_real_sleep and max(_no_real_sleep) > 1.5


@pytest.mark.parametrize(
    ("raw", "host"),
    [
        ("Example.COM", "example.com"),
        ("https://www.example.com/a/b?x=1", "www.example.com"),
        ("example.com/pricing", "example.com"),
        ("example.com.", "example.com"),
    ],
)
def test_to_host(raw: str, host: str) -> None:
    assert to_host(raw) == host


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["nodot", *ARGS],
        ["http://", *ARGS],
        ["exa mple.com", *ARGS],
        ["example.com"],
        ["example.com", "--contact", "x"],
    ],
)
def test_usage_errors_exit_4(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEO_AUDIT_CONTACT", raising=False)
    assert run(argv, fetcher=_fetcher({})) == 4


def test_main_dispatches_robots_and_domain_mode_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEO_AUDIT_CONTACT", raising=False)
    assert cli.main(["robots"]) == 4  # 进了子命令（没有域名）
    assert cli.build_parser().parse_args(["example.com"]).domain == "example.com"
