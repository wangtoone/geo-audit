"""``geo-audit page``：端到端（MockTransport，不碰网络）。"""

from __future__ import annotations

import json
import time
import types
from pathlib import Path

import httpx
import pytest

from geo_audit import cli
from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.pagecli import run

PRICING_OK = (
    "<html><head><title>Official Pricing</title></head><body>"
    "<h1>Meshy Official Pricing Plans</h1><p>Pro $20, Studio $70</p></body></html>"
)
PRICING_BAD = (
    "<html><head><title>Pricing</title></head><body><h1>Pricing</h1><p>Pro $0</p></body></html>"
)


def _fetcher(pages: dict[str, tuple[int, str]], robots: str = "") -> Fetcher:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=robots)
        status, body = pages.get(req.url.path, (404, "nope"))
        return httpx.Response(status, headers={"content-type": "text/html"}, text=body)

    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
        HttpCache(":memory:"),
        DomainLimiter(2.0),
        transport=httpx.MockTransport(handler),
    )


ARGS = ["--contact", "ci@geo-audit.invalid"]


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """限速下限（2s）是合规约束，测试里不能调低 —— 改成**记录**要睡多久、但不真睡。"""
    slept: list[float] = []
    fake = types.SimpleNamespace(monotonic=time.monotonic, sleep=slept.append)
    monkeypatch.setattr("geo_audit.fetch.ratelimit.time", fake)
    return slept


def test_all_pass_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    f = _fetcher({"/pricing": (200, PRICING_OK)})
    rc = run(
        [
            "https://x.test/pricing",
            *ARGS,
            "--h1-contains",
            "Official Pricing Plans",
            "--price",
            "20",
        ],
        fetcher=f,
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "✓ H1 含" in out and "✗" not in out


def test_failed_expectation_exits_1_and_says_why(capsys: pytest.CaptureFixture[str]) -> None:
    f = _fetcher({"/pricing": (200, PRICING_BAD)})
    rc = run(
        [
            "https://x.test/pricing",
            *ARGS,
            "--h1-contains",
            "Official Pricing Plans",
            "--price",
            "20",
        ],
        fetcher=f,
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "✗ H1 含「Official Pricing Plans」" in out
    assert "✗ 可见文字含金额 20" in out


def test_unreachable_page_is_unknown_exit_3_never_pass(capsys: pytest.CaptureFixture[str]) -> None:
    f = _fetcher({})  # /pricing → 404
    rc = run(["https://x.test/pricing", *ARGS, "--h1-contains", "x"], fetcher=f)
    out = capsys.readouterr().out
    assert rc == 3
    assert "? H1 含" in out and "404" in out


def test_robots_disallow_is_unknown_not_fail(capsys: pytest.CaptureFixture[str]) -> None:
    f = _fetcher({"/pricing": (200, PRICING_OK)}, robots="User-agent: *\nDisallow: /\n")
    rc = run(["https://x.test/pricing", *ARGS, "--h1-contains", "x"], fetcher=f)
    out = capsys.readouterr().out
    assert rc == 3
    assert "robots_disallowed" in out
    assert "✗" not in out


def test_facts_only_without_expectations_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    f = _fetcher({"/p": (200, PRICING_OK)})
    assert run(["https://x.test/p", *ARGS], fetcher=f) == 0
    assert "可见金额" in capsys.readouterr().out


def test_spec_file_and_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps(
            {
                "https://x.test/pricing": {
                    "h1_contains": "Official Pricing Plans",
                    "prices": [20, 70],
                },
                "https://x.test/other": {"min_visible_chars": 100000},
            }
        )
    )
    f = _fetcher({"/pricing": (200, PRICING_OK), "/other": (200, "<p>tiny</p>")})
    rc = run(["--spec", str(spec), "--json", *ARGS], fetcher=f)
    data = json.loads(capsys.readouterr().out)
    assert rc == 1  # /other 不够长
    assert [d["url"] for d in data] == ["https://x.test/pricing", "https://x.test/other"]
    assert {r["verdict"] for r in data[0]["results"]} == {"pass"}
    assert data[1]["results"][0]["verdict"] == "fail"
    assert "text" not in data[0]["facts"]  # 全文不进 JSON


@pytest.mark.parametrize(
    "argv",
    [
        [],  # 没有页面
        ["not-a-url", *ARGS],
        ["ftp://x.test/a", *ARGS],
        ["https://x.test/a"],  # 没有联系邮箱
        ["https://x.test/a", "--contact", "nope"],  # 邮箱不合法
    ],
)
def test_usage_errors_exit_4(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEO_AUDIT_CONTACT", raising=False)
    assert run(argv, fetcher=_fetcher({})) == 4


def test_unknown_spec_key_is_a_usage_error(tmp_path: Path) -> None:
    spec = tmp_path / "s.json"
    spec.write_text(json.dumps({"https://x.test/a": {"h1_contian": ["typo"]}}))
    assert run(["--spec", str(spec), *ARGS], fetcher=_fetcher({})) == 4


def test_main_dispatches_page_subcommand_and_domain_mode_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GEO_AUDIT_CONTACT", raising=False)
    assert cli.main(["page"]) == 4  # 进了子命令（没有 URL）
    # 整站体检的解析不受影响：example.com 仍是位置参数
    assert cli.build_parser().parse_args(["example.com"]).domain == "example.com"


def test_politeness_is_preserved_between_robots_and_page(_no_real_sleep: list[float]) -> None:
    f = _fetcher({"/pricing": (200, PRICING_OK)})
    assert run(["https://x.test/pricing", *ARGS], fetcher=f) == 0
    # robots.txt 一次、页面一次，同一域 → 第二次请求前必须被要求等满 ~2s
    assert _no_real_sleep, "没有任何限速等待：同域连发两次请求却没有被拉开"
    assert max(_no_real_sleep) > 1.5
