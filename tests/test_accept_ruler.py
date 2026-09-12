"""第二把尺子（``Accept: */*``）—— 同一个位置换个请求头就换一个答案。

**这个功能是被实测逼出来的**，不是设计出来的。2026-09-12 把语料里 100 个 AI
路径位置各用两种 Accept 头量了一遍（每条都独立进程、双向顺序复验），9 个位置
的答案取决于这个头：

    主尺子 404 / */* 200 真文件
      www.openstatus.dev/llms.txt      404 483 B      ->  200 52,530 B
      www.openstatus.dev/llms-full.txt 404 488 B      ->  200 27,587 B(gz)
      dev.wix.com/docs/llms.txt        404 207 B      ->  200 6,619 B
      dev.wix.com/docs/llms-full.txt   404 212 B      ->  200 9,001,715 B

    主尺子 markdown / */* HTML 页面壳
      api-docs.ecwid.com/llms.txt            2,984 B md  ->  82,537 B html
      developers.attio.com/llms.txt            760 B md  ->  33,071 B html
      developers.pipedrive.com/llms.txt        283 B md  ->   6,314 B html
      developers.printify.com/llms.txt      51,889 B md  ->  55,012 B html
      docs.moderntreasury.com/llms-full.txt    662 B md  ->  95,467 B html

病因：主尺子 ``ACCEPT_TEXT`` 里点名要 ``text/markdown``，而这些站点对
「要 markdown」的请求走另一个 handler（Next.js 的
``x-nextjs-rewritten-path: /api/markdown/<path>`` 是现场抓到的证据）。

两个方向是同一个病：**拿一把尺子的读数去讲另一把尺子下的事实**。所以判定不挑
边 —— 两把不一致时这个位置落 UNKNOWN/accept_negotiated，两边读数都进证据。

（一条一开始入选、复验后被剔除的：gusto.com/llms.txt。第一轮 old 403 / star 200
看着像同一个病，隔离重测三种 Accept 全是 403 —— 那是 Cloudflare 的状态，
不是 Accept。共享 cookie + 连发请求造出来的假差异。）
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import httpx
import pytest

from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import ACCEPT_HTML, ACCEPT_TEXT, Fetcher, FetcherConfig
from geo_audit.fetch.ratelimit import DomainLimiter
from geo_audit.fixtures import (
    ACCEPT_STAR,
    FixtureMissing,
    FixtureStore,
    fixture_key,
    parse_urls_txt,
    snapshot_path,
    split_fixture_key,
)
from geo_audit.models import Expect, Verdict
from geo_audit.pipeline import StopTransport

CONTACT = "ci@geo-audit.invalid"
URL = "https://variant.invalid/llms.txt"


# --------------------------------------------------------------------------- #
# 一、变体键
# --------------------------------------------------------------------------- #


def test_variant_key_round_trips() -> None:
    key = fixture_key(URL, "star")
    assert key != fixture_key(URL)
    assert split_fixture_key(key) == (URL, "star")
    # 幂等：已经带标记的键再过一次不会套两层
    assert fixture_key(key) == key
    assert fixture_key(key, "star") == key


def test_variant_has_its_own_file() -> None:
    """两把尺子的快照落两个文件 —— 否则后录的会把先录的覆盖掉。"""
    assert snapshot_path(URL) != snapshot_path(fixture_key(URL, "star"))
    assert "accept-star" in snapshot_path(fixture_key(URL, "star"))


def _store_with_both_rulers(tmp_path: Path) -> FixtureStore:
    store = FixtureStore(tmp_path)
    store.put_snapshot(
        URL,
        status=404,
        headers={"content-type": "text/markdown"},
        body=b"# 404 - Not Found\n",
    )
    store.put_snapshot(
        URL,
        status=200,
        headers={"content-type": "text/plain"},
        body=b"# real file\n\n- [a](https://variant.invalid/a)\n",
        accept_variant="star",
    )
    return store


def test_replay_picks_the_snapshot_that_matches_the_accept_header(tmp_path: Path) -> None:
    store = _store_with_both_rulers(tmp_path)
    transport = store.transport()

    def fetch(accept: str) -> httpx.Response:
        request = httpx.Request("GET", URL, headers={"accept": accept})
        return transport.handle_request(request)

    assert fetch(ACCEPT_TEXT).status_code == 404
    assert fetch(ACCEPT_STAR).status_code == 200
    # 主尺子那份不会被变体顶掉，两边各读各的
    assert b"real file" in fetch(ACCEPT_STAR).read()
    assert b"Not Found" in fetch(ACCEPT_TEXT).read()


def test_a_missing_variant_never_falls_back_to_the_main_ruler(tmp_path: Path) -> None:
    """没录过变体 -> 598「没量过」，**不许**把主尺子那份端出来充数。

    回落是最容易写出来的那种「合理的省事」，而它的代价是报告会说
    「两把尺子一致」—— 一句它没资格说的话。
    """
    store = FixtureStore(tmp_path)
    store.put_snapshot(
        URL,
        status=404,
        headers={"content-type": "text/markdown"},
        body=b"MAIN-RULER-BODY",
    )
    request = httpx.Request("GET", URL, headers={"accept": ACCEPT_STAR})
    resp = store.transport().handle_request(request)
    assert resp.status_code == FixtureStore.MISSING_VARIANT_STATUS
    assert resp.headers["x-geo-audit-fixture"] == "accept-variant-missing"
    assert b"MAIN-RULER-BODY" not in resp.read()


def test_missing_variant_does_not_raise_even_in_strict_mode(tmp_path: Path) -> None:
    """strict 只管主尺子：主尺子缺快照是我们 fixture 不全，必须抛；
    第二把尺子缺的是一次对照测量，有诚实说法，不抛。"""
    store = FixtureStore(tmp_path)
    store.put_snapshot(URL, status=200, headers={"content-type": "text/plain"}, body=b"x")
    strict = store.transport(strict=True)
    assert (
        strict.handle_request(
            httpx.Request("GET", URL, headers={"accept": ACCEPT_STAR})
        ).status_code
        == FixtureStore.MISSING_VARIANT_STATUS
    )
    with pytest.raises(FixtureMissing):
        strict.handle_request(
            httpx.Request("GET", "https://variant.invalid/nope", headers={"accept": ACCEPT_TEXT})
        )


def test_rebuild_index_keeps_the_two_apart(tmp_path: Path) -> None:
    """从磁盘重建索引时变体不能塌成一条 —— 它们的 meta 里 canon_url 是同一个。"""
    store = _store_with_both_rulers(tmp_path)
    store.rebuild_index()
    assert store.has(URL) and store.has(URL, variant="star")
    assert store.get(URL).status == 404
    assert store.get(URL, variant="star").status == 200


def test_urls_txt_directive_parses() -> None:
    (spec,) = parse_urls_txt("@accept-star https://x.invalid/llms.txt  # 注释")
    assert (spec.kind, spec.url) == ("accept_star", "https://x.invalid/llms.txt")
    # 它录的是变体键，不是「这一行的 URL 本身」，所以 urls 为空（与 @control 同理）
    assert spec.urls == ()


# --------------------------------------------------------------------------- #
# 二、什么算差异
# --------------------------------------------------------------------------- #


def _resp(status: int, ct: str, body: bytes) -> Any:
    from geo_audit.fetch.client import HttpResponse

    return HttpResponse(
        url=URL, final_url=URL, status=status, headers={"content-type": ct}, body=body
    )


@pytest.mark.parametrize(
    ("first", "second", "expect_diff"),
    [
        # 一边说有、一边说没有 —— openstatus.dev / dev.wix.com 的形态
        ((404, "text/markdown", b"# 404"), (200, "text/plain", b"# real"), True),
        # 一边文本、一边 HTML 页面壳 —— ecwid / attio / printify 的形态
        ((200, "text/markdown", b"# real"), (200, "text/html", b"<!doctype html><html>"), True),
        # text/markdown 与 text/plain 是同一份文本的两种叫法（实测 6 个 host）
        ((200, "text/markdown", b"# real"), (200, "text/plain", b"# real"), False),
        # 字节数差一点（时间戳 / nonce）不算 —— 那种噪声正是 40.5% 假阳性那一课
        ((200, "text/plain", b"# real 12:00"), (200, "text/plain", b"# real 12:01"), False),
        # 两边都非 2xx：都说没有，没有分歧
        ((404, "text/markdown", b"a"), (410, "text/plain", b"b"), False),
    ],
)
def test_what_counts_as_a_disagreement(
    first: tuple[int, str, bytes], second: tuple[int, str, bytes], expect_diff: bool
) -> None:
    diffs = Fetcher._ruler_diffs(_resp(*first), _resp(*second))
    assert bool(diffs) is expect_diff, diffs


# --------------------------------------------------------------------------- #
# 三、端到端：走 Fetcher.probe 的生产路径
# --------------------------------------------------------------------------- #


def _fetcher(store: FixtureStore, tmp_path: Path, **cfg: Any) -> Fetcher:
    contact = CONTACT
    return Fetcher(
        FetcherConfig(contact=contact, interval=2.0, respect_robots=False, **cfg),
        HttpCache(tmp_path / "c.sqlite3", ua_profile=f"ua-{cfg}"),
        DomainLimiter(2.0),
        transport=StopTransport(store.transport(strict=False), threading.Event()),
        probe_url_provider=store.probe_url_lenient,
        resolver=store.resolver(),
    )


def test_disagreement_becomes_unknown_with_both_readings(tmp_path: Path) -> None:
    store = _store_with_both_rulers(tmp_path)
    store.write_dns({"variant.invalid": {"addresses": ["203.0.113.7"], "resolver": "fixture"}})
    fetcher = _fetcher(store, tmp_path)
    try:
        cls = fetcher.probe(URL, expect=Expect.TEXT_FILE).classification
    finally:
        fetcher.close()
    assert cls.verdict is Verdict.UNKNOWN
    assert cls.reason == "accept_negotiated"
    assert not cls.evaluated, "换个头就换答案的位置不能算「评估过了」"
    joined = "\n".join(cls.evidence)
    assert "404" in joined and "200" in joined, joined
    assert ACCEPT_STAR in joined and ACCEPT_TEXT in joined, joined
    assert "curl" in joined, "两边读数都要能被读者自己复现"


def test_agreement_leaves_the_verdict_alone(tmp_path: Path) -> None:
    """两把尺子一致时**不动原判定** —— 那是强化，不是新结论。"""
    store = FixtureStore(tmp_path)
    body = b"# real file\n\n- [a](https://variant.invalid/a)\n"
    for variant in (None, "star"):
        store.put_snapshot(
            URL,
            status=200,
            headers={"content-type": "text/plain"},
            body=body,
            accept_variant=variant,
        )
    store.write_dns({"variant.invalid": {"addresses": ["203.0.113.7"], "resolver": "fixture"}})
    with_ruler = _fetcher(store, tmp_path)
    try:
        cls = with_ruler.probe(URL, expect=Expect.TEXT_FILE).classification
    finally:
        with_ruler.close()
    (tmp_path / "cache-off").mkdir()
    without = _fetcher(store, tmp_path / "cache-off", second_ruler=False)
    try:
        baseline = without.probe(URL, expect=Expect.TEXT_FILE).classification
    finally:
        without.close()
    # 判定与「根本没有第二把尺子」时逐字相同（这个 tmp 语料没有对照探针，
    # 所以两边都是 UNKNOWN/control_unavailable —— 要的就是「没被动过」）
    assert (cls.verdict, cls.reason) == (baseline.verdict, baseline.reason)
    assert cls.reason != "accept_negotiated"
    assert any("都一致" in e for e in cls.evidence), cls.evidence


def test_not_measured_is_said_out_loud(tmp_path: Path) -> None:
    """没量过第二把尺子时，既不改判定，也不许写成「一致」。"""
    store = FixtureStore(tmp_path)
    store.put_snapshot(
        URL,
        status=200,
        headers={"content-type": "text/plain"},
        body=b"# real file\n\n- [a](https://variant.invalid/a)\n",
    )
    store.write_dns({"variant.invalid": {"addresses": ["203.0.113.7"], "resolver": "fixture"}})
    fetcher = _fetcher(store, tmp_path)
    try:
        cls = fetcher.probe(URL, expect=Expect.TEXT_FILE).classification
    finally:
        fetcher.close()
    assert cls.reason != "accept_negotiated"
    joined = "\n".join(cls.evidence)
    assert "没有测量数据" in joined, joined
    assert "一致" not in joined, joined


def test_the_second_ruler_can_be_turned_off_and_then_costs_nothing(tmp_path: Path) -> None:
    """关掉开关就一条额外请求都不发（预算是真金白银，得能验）。"""
    store = _store_with_both_rulers(tmp_path)
    store.write_dns({"variant.invalid": {"addresses": ["203.0.113.7"], "resolver": "fixture"}})
    off = _fetcher(store, tmp_path, second_ruler=False)
    try:
        off.probe(URL, expect=Expect.TEXT_FILE)
        spent_off = off.http_requests
    finally:
        off.close()
    (tmp_path / "on").mkdir()
    on = _fetcher(store, tmp_path / "on", second_ruler=True)
    try:
        on.probe(URL, expect=Expect.TEXT_FILE)
        spent_on = on.http_requests
    finally:
        on.close()
    assert spent_on == spent_off + 1


def test_html_positions_do_not_pay_for_a_second_ruler(tmp_path: Path) -> None:
    """只有文本位置量两把尺子。普通页面本来就该是 HTML，量了也没有可读的差异，
    而每个位置 +1 条请求会把预算吃掉一大截。"""
    store = FixtureStore(tmp_path)
    store.put_snapshot(
        "https://variant.invalid/page",
        status=200,
        headers={"content-type": "text/html"},
        body=b"<!doctype html><html><body>" + b"x" * 500 + b"</body></html>",
    )
    store.write_dns({"variant.invalid": {"addresses": ["203.0.113.7"], "resolver": "fixture"}})
    fetcher = _fetcher(store, tmp_path)
    try:
        fetcher.probe("https://variant.invalid/page", expect=Expect.HTML_PAGE)
        assert fetcher.http_requests == 2, "目标 + 对照探针，没有第三条"
    finally:
        fetcher.close()
    assert ACCEPT_HTML  # 引用一下，说明这条走的是 HTML 尺子


# --------------------------------------------------------------------------- #
# 四、被拦住的一侧不算「答案取决于请求头」
# --------------------------------------------------------------------------- #


def test_a_blocked_side_is_not_an_accept_finding(tmp_path: Path) -> None:
    """一边 200、一边 403 挑战页 —— 那是 WAF 的状态，不是 Accept 的作用。

    实测撞到两次（dev.hume.ai 与 gusto.com），两次都会被误读成
    「答案取决于请求头」。归因错了比不归因更糟：它听起来很具体。
    """
    store = FixtureStore(tmp_path)
    store.put_snapshot(
        URL,
        status=200,
        headers={"content-type": "text/plain"},
        body=b"# real file\n\n- [a](https://variant.invalid/a)\n",
    )
    store.put_snapshot(
        URL,
        status=403,
        headers={"content-type": "text/html"},
        body=b"<!doctype html><html><title>Just a moment...</title></html>",
        accept_variant="star",
    )
    store.write_dns({"variant.invalid": {"addresses": ["203.0.113.7"], "resolver": "fixture"}})
    fetcher = _fetcher(store, tmp_path)
    try:
        cls = fetcher.probe(URL, expect=Expect.TEXT_FILE).classification
    finally:
        fetcher.close()
    assert cls.reason != "accept_negotiated"
    joined = "\n".join(cls.evidence)
    assert "不可比" in joined, joined


def test_redirect_hops_do_not_count_as_a_content_type_difference() -> None:
    """两边都不是 2xx 时不比正文类型：301 的空正文 / 404 页长什么样都不说明
    这个位置「是什么」。实测 docs.moderntreasury.com 的那一跳就是
    301 text/plain vs 301 text/html。"""
    assert (
        Fetcher._ruler_diffs(_resp(301, "text/plain", b""), _resp(301, "text/html", b"<html>"))
        == ()
    )
