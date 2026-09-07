"""fixture 存储层的测试（门禁 M，§8.1 / §8.2）。

**这个文件里一个字面量摘要都没有。** md5 与字节数只在 ``fixtures/index.json``
的 ``expect`` 块里出现一次，这里一律从 ``store.expect(url)`` 读 —— 活网漂移时
改的是 index.json 一处，不是散在测试里的十处（卡点 A51）。
``test_no_hardcoded_digests_in_tests`` 用 grep 守着这条。

跑法（CI 的 test job 恒开两把闸）::

    GEO_AUDIT_FORBID_NETWORK=1 GEO_AUDIT_FORBID_DNS=1 pytest tests/test_fixture_store.py -q

**快照分两处**：

- ``fixtures/`` 根目录 = 第 4b 步实录的真快照。它还没录时，用到它的测试
  ``skipif`` 掉（不是假绿：跳过的原因写在 reason 里）。
- ``fixtures/handwritten/`` = 第 4a 步**手写**的自检快照。host 全是 ``.invalid``
  保留域、正文是造的、每条 meta 都标了 ``handwritten: true``，所以不可能被
  误当成实测 ground truth。重新生成：
  ``python scripts/capture_fixtures.py --write-selftest-fixtures
  --fixtures-dir fixtures/handwritten``
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from geo_audit.fetch.cache import HttpCache
from geo_audit.fetch.client import ACCEPT_TEXT, Fetcher, FetcherConfig
from geo_audit.fetch.resolve import resolve_host
from geo_audit.fixtures import (
    BODY_FULL_MAX,
    BODY_TRUNCATED_MAX,
    DNS_ABSENT_KEY,
    DRIFT_PHENOMENA,
    EXPAND_EXTRACTORS,
    HDR_BODY_STORAGE,
    TRUNCATED_PREFIX_BYTES,
    BodyNotStored,
    DnsFixtureMissing,
    FixtureMissing,
    FixtureStore,
    body_storage_for,
    canon_url,
    hosts_of,
    load_urls_txt,
    parse_urls_txt,
    sample_deterministic,
    snapshot_path,
)
from geo_audit.models import Expect, Verdict

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
HANDWRITTEN = FIXTURES / "handwritten"

#: 手写自检快照里的几条 URL。全是 .invalid 保留域，不可能是实录。
SELF_LLMS = "https://fixture-selftest.invalid/llms.txt"
SELF_ROBOTS = "https://fixture-selftest.invalid/robots.txt"
SELF_REDIRECT = "https://redirect-selftest.invalid/llms-full.txt"
SELF_REDIRECT_TARGET = "https://target-selftest.invalid/"
SELF_BIG = "https://big-selftest.invalid/llms-full.txt"
SELF_HUGE = "https://huge-selftest.invalid/llms-full.txt"
SELF_TIMEOUT = "https://timeout-selftest.invalid/llms.txt"

real_index_needed = pytest.mark.skipif(
    not (FIXTURES / "index.json").exists(),
    reason="第 4b 步的实录快照还没落地（fixtures/index.json 不存在）",
)
urls_txt_needed = pytest.mark.skipif(
    not (FIXTURES / "urls.txt").exists(),
    reason="fixtures/urls.txt 还没落地",
)


@pytest.fixture
def store() -> FixtureStore:
    """手写自检快照的 store。"""
    return FixtureStore(HANDWRITTEN)


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """把限速器的 2.0s/域压成 0。

    ``DomainLimiter`` 拒绝 <2.0s 的 interval（合规下限，不许为了测试放宽），
    所以这里改的是时钟而不是配置 —— 与「同 host 相邻请求间隔 ≥2.0s」那条
    合规断言不冲突：它测的是限速器要不要睡，这里只是不真睡。
    """
    monkeypatch.setattr(time, "sleep", lambda _s: None)


def make_fetcher(store: FixtureStore, tmp_path: Path, **kw: Any) -> Fetcher:
    """一个**真正的** Fetcher，只把 transport 与探针 URL 换成 fixture 的。

    卡点 A1：门禁与测试必须跑生产那条路（限速器、缓存、跟跳转、对照探测全在），
    绕开 Fetcher 直连 httpx 测的不是生产代码。
    """
    return Fetcher(
        FetcherConfig(contact="ci@geo-audit.invalid", **kw),
        cache=HttpCache(path=tmp_path / "http.sqlite3"),
        transport=store.transport(),
        probe_url_provider=store.probe_url,
    )


# --------------------------------------------------------------------------- #
# canon_url / snapshot_path
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Docs.Mistral.AI/llms.txt", "https://docs.mistral.ai/llms.txt"),
        ("https://docs.mistral.ai:443/llms.txt", "https://docs.mistral.ai/llms.txt"),
        ("http://ed.link:80/llms.txt", "http://ed.link/llms.txt"),
        ("https://modal.com", "https://modal.com/"),
        ("https://modal.com/llms.txt#frag", "https://modal.com/llms.txt"),
        ("  https://modal.com/llms.txt  ", "https://modal.com/llms.txt"),
        ("https://docs.mistral.ai./llms.txt", "https://docs.mistral.ai/llms.txt"),
        ("//docs.mistral.ai/llms.txt", "https://docs.mistral.ai/llms.txt"),
    ],
)
def test_canon_url_normalises_only_the_uncontroversial(raw: str, expected: str) -> None:
    assert canon_url(raw) == expected


def test_canon_url_keeps_what_the_judgement_depends_on() -> None:
    """path 大小写、末尾斜杠、query 一律保留。

    ``close.com`` 那条 presigned URL 的判据（``X-Amz-Expires=604800``，7 天后
    必过期）整个就在 query 里；``/plans`` 与 ``/plans/`` 是两条不同的探测位置。
    """
    assert canon_url("https://x.invalid/Docs/A.TXT") == "https://x.invalid/Docs/A.TXT"
    assert canon_url("https://x.invalid/plans") != canon_url("https://x.invalid/plans/")
    q = "https://s3.invalid/logo.png?X-Amz-Expires=604800&X-Amz-Signature=abc"
    assert canon_url(q) == q
    # query 顺序是服务端语义，不许排序
    assert canon_url("https://x.invalid/a?b=1&a=2") == "https://x.invalid/a?b=1&a=2"


def test_snapshot_path_shape() -> None:
    stem = snapshot_path("https://developers.brevo.com/docs/llms.txt")
    assert re.fullmatch(r"snapshots/developers\.brevo\.com/docs-llms\.txt-[0-9a-f]{8}", stem)
    # 元数据与正文同主干、不同扩展名（§8.1 决定 3：分离存）
    assert stem + ".meta.json" != stem + ".body.gz"


def test_snapshot_path_is_a_function_of_canon_url_only() -> None:
    """同一个位置的不同写法必须落到同一条快照，否则会录出两份。"""
    assert snapshot_path("HTTPS://Modal.com:443/llms.txt#x") == snapshot_path(
        "https://modal.com/llms.txt"
    )
    assert snapshot_path("https://modal.com/a") != snapshot_path("https://modal.com/b")


def test_snapshot_path_survives_a_pathological_path() -> None:
    """504 条 ``/xxx.md`` 里难免有超长路径；slug 截断后靠 sha1 后缀保唯一。"""
    long_a = "https://x.invalid/" + "a" * 300
    long_b = "https://x.invalid/" + "a" * 301
    assert len(Path(snapshot_path(long_a)).name) < 120
    assert snapshot_path(long_a) != snapshot_path(long_b)
    assert snapshot_path("https://x.invalid/").endswith(
        snapshot_path("https://x.invalid/").rsplit("/", 1)[-1]
    )


# --------------------------------------------------------------------------- #
# 三档 body_storage
# --------------------------------------------------------------------------- #


def test_body_storage_tiers_at_the_boundaries() -> None:
    assert body_storage_for(0) == "full"
    assert body_storage_for(BODY_FULL_MAX) == "full"
    assert body_storage_for(BODY_FULL_MAX + 1) == "truncated"
    assert body_storage_for(BODY_TRUNCATED_MAX) == "truncated"
    assert body_storage_for(BODY_TRUNCATED_MAX + 1) == "digest_only"


def test_body_storage_tiers_on_the_measured_outliers() -> None:
    """§8.1/§8.2 点名的那几条必须落在方案说的那一档。

    字节数逐字照抄 §8.2 的 ``@pair`` 注释与 §8.1 的正文，不自己编。
    """
    assert body_storage_for(715_130) == "full"  # api-docs.ecwid.com 最大的软 404 正文
    assert body_storage_for(1_217_592) == "truncated"  # developer.squareup.com llms-full
    assert body_storage_for(3_564_760) == "truncated"  # liveblocks.io 3.5 MB
    assert body_storage_for(4_300_000) == "truncated"  # docs.canvasmedical.com 4.3 MB
    assert body_storage_for(9_002_064) == "digest_only"  # dev.wix.com 9 MB
    assert body_storage_for(19_977_336) == "digest_only"  # docs.customer.io


def test_full_tier_body_matches_the_expect_block(store: FixtureStore) -> None:
    body = store.body(SELF_LLMS)
    exp = store.expect(SELF_LLMS)
    assert len(body) == exp["bytes"]
    assert store.digests(SELF_LLMS)["raw_md5"] == exp["raw_md5"]


def test_truncated_tier_refuses_to_hand_out_a_body(store: FixtureStore) -> None:
    snap = store.get(SELF_BIG)
    assert snap.body_storage == "truncated"
    assert snap.stored_bytes == TRUNCATED_PREFIX_BYTES
    assert snap.body_bytes > snap.stored_bytes
    with pytest.raises(BodyNotStored) as err:
        store.body(SELF_BIG)
    assert "truncated" in str(err.value)
    # size/md5 仍然可用 —— 它们是录制时对**完整流**算的
    assert store.digests(SELF_BIG)["bytes"] == snap.body_bytes


def test_digest_only_tier_stores_no_body_at_all(store: FixtureStore) -> None:
    snap = store.get(SELF_HUGE)
    assert snap.body_storage == "digest_only"
    assert snap.body_file is None
    assert not (HANDWRITTEN / (snap.path + ".body.gz")).exists()
    with pytest.raises(BodyNotStored):
        store.body(SELF_HUGE)
    assert store.digests(SELF_HUGE)["bytes"] == snap.body_bytes


def test_replayed_truncated_body_is_marked_so_nobody_hashes_it(store: FixtureStore) -> None:
    """截断档重放出去的响应必须自带标记。

    这是 ``BodyNotStored`` 之外的第二道闸：``store.body()`` 拦得住直接读，
    拦不住「用 transport 抓一遍再算 md5」。所以重放响应上带
    ``x-geo-audit-fixture-body``，且那个 md5 与真 md5 **故意**不同 ——
    任何拿重放正文算哈希的代码都会当场露馅，而不是悄悄给出错的结论。
    """
    request = httpx.Request("GET", SELF_BIG)
    resp = store.replay(request)
    assert resp.headers[HDR_BODY_STORAGE] == "truncated"
    assert len(resp.content) == TRUNCATED_PREFIX_BYTES
    assert store.digests(SELF_BIG)["raw_md5"] not in resp.text


# --------------------------------------------------------------------------- #
# 缺失快照：抛，且带可复制的命令
# --------------------------------------------------------------------------- #


def test_missing_snapshot_raises_with_a_copy_pasteable_command(store: FixtureStore) -> None:
    with pytest.raises(FixtureMissing) as err:
        store.get("https://never-recorded.invalid/llms.txt")
    msg = str(err.value)
    assert "capture_fixtures.py" in msg  # 门禁 M
    assert "https://never-recorded.invalid/llms.txt" in msg
    assert "--contact" in msg


def test_transport_never_falls_back_to_the_live_network(
    store: FixtureStore, tmp_path: Path
) -> None:
    """缺快照时 transport 抛，**不**去打真网络。"""
    with make_fetcher(store, tmp_path) as f, pytest.raises(FixtureMissing):
        f.fetch("https://never-recorded.invalid/llms.txt")


def test_index_entry_missing_on_disk_also_raises(store: FixtureStore, tmp_path: Path) -> None:
    """index.json 里有、磁盘上没有 —— 也必须抛，不许当成空正文。"""
    work = tmp_path / "fx"
    shutil.copytree(HANDWRITTEN, work)
    snap = FixtureStore(work).get(SELF_LLMS)
    (work / (snap.path + ".meta.json")).unlink()
    with pytest.raises(FixtureMissing) as err:
        FixtureStore(work).get(SELF_LLMS)
    assert "capture_fixtures.py" in str(err.value)


# --------------------------------------------------------------------------- #
# transport()：喂给真 Fetcher
# --------------------------------------------------------------------------- #


def test_fetcher_replays_a_frozen_response(
    store: FixtureStore, tmp_path: Path, no_sleep: None
) -> None:
    with make_fetcher(store, tmp_path) as f:
        resp = f.fetch(SELF_LLMS, expect=Expect.TEXT_FILE)
    exp = store.expect(SELF_LLMS)
    assert resp.status == 200
    assert resp.content_type == "text/plain"
    assert resp.byte_len == exp["bytes"]
    # 摘要由 finalize_response 现算，和 index.json 的 expect 块对上才算重放对了
    assert resp.raw_md5 == exp["raw_md5"]
    assert not resp.body_truncated


def test_fetcher_follows_the_recorded_redirect_hop_by_hop(
    store: FixtureStore, tmp_path: Path, no_sleep: None
) -> None:
    """§8.1 决定 2：逐跳单独存，让 Fetcher 自己跟 3xx。

    于是「必须跟随 3xx」这条规则也在测试范围里 —— 如果谁把跟跳转改坏了，
    这条会红，而不是等到线上把 302 当成死链。
    """
    with make_fetcher(store, tmp_path) as f:
        resp = f.fetch(SELF_REDIRECT)
    assert [h.status for h in resp.redirects] == [302]
    assert resp.redirects[0].to_url == SELF_REDIRECT_TARGET
    assert resp.final_url == SELF_REDIRECT_TARGET
    assert resp.status == 200
    assert resp.is_html


def test_recorded_transport_error_replays_as_an_httpx_exception(
    store: FixtureStore, tmp_path: Path, no_sleep: None
) -> None:
    """录到的传输失败（status == 0）重放成同类异常。

    这条让 DNS 二次意见 / 重试那两段代码在 replay 下也走得到 —— 否则
    ``platform.minimax.io`` 那 12 条假 DNS 失败的回归用例根本没法离线跑。
    """
    snap = store.get(SELF_TIMEOUT)
    assert snap.status == 0
    assert snap.transport_error
    with make_fetcher(store, tmp_path) as f:
        resp = f.fetch(SELF_TIMEOUT)
    assert resp.status == 0
    assert resp.transport_error is not None


def test_replay_matches_on_the_host_header_when_the_ip_is_pinned(store: FixtureStore) -> None:
    """resolve.R2 会把请求打到 IP 上、用 Host 头保留原域名（等价 curl --resolve）。

    索引键必须落回原域名那条，否则 pin 过的重试永远命不中快照。
    """
    request = httpx.Request(
        "GET",
        "https://203.0.113.10/llms.txt",
        headers={"Host": "fixture-selftest.invalid"},
    )
    assert FixtureStore.url_of_request(request) == SELF_LLMS
    assert store.replay(request).status_code == 200


def test_replay_strips_only_the_transfer_headers(store: FixtureStore) -> None:
    """判据用得到的 header 一个都不许剥。"""
    resp = store.replay(httpx.Request("GET", SELF_REDIRECT))
    assert resp.status_code == 302
    assert resp.headers["location"] == SELF_REDIRECT_TARGET
    assert "content-encoding" not in resp.headers
    assert resp.headers["server"] == "selftest"


# --------------------------------------------------------------------------- #
# probe_url()：对照探针的重放
# --------------------------------------------------------------------------- #


def test_probe_url_resolves_through_the_probe_for_index(store: FixtureStore) -> None:
    probe = store.probe_url(SELF_LLMS)
    assert store.get(probe).probe_for == SELF_LLMS
    assert "geo-audit-probe-" in probe
    # 确定性：同一个 URL 问两次必须是同一条，否则快照永远命不中
    assert store.probe_url(SELF_LLMS) == probe


def test_probe_url_falls_back_within_the_same_host(store: FixtureStore) -> None:
    """对照探针的语义是「这个 host 拿一个不可能存在的路径怎么回」，同 host 通用。

    ``host_profile`` 本身就是按 host 缓存的，所以同 host 的别的位置也该拿到它。
    """
    assert store.probe_url(SELF_ROBOTS) == store.probe_url(SELF_LLMS)


def test_probe_url_missing_says_to_add_an_at_control_line(store: FixtureStore) -> None:
    with pytest.raises(FixtureMissing) as err:
        store.probe_url("https://no-control.invalid/llms.txt")
    msg = str(err.value)
    assert "@control https://no-control.invalid/llms.txt" in msg
    assert "capture_fixtures.py" in msg


def test_probe_runs_end_to_end_on_the_frozen_control(
    store: FixtureStore, tmp_path: Path, no_sleep: None
) -> None:
    """整条生产路径：robots -> 目标 -> 对照探针 -> 判定，全部走冻结快照。"""
    with make_fetcher(store, tmp_path) as f:
        robots = f.robots_for(SELF_LLMS)
        assert robots.fetched
        probe = f.probe(SELF_LLMS, expect=Expect.TEXT_FILE)
    assert probe.response is not None
    assert probe.response.raw_md5 == store.expect(SELF_LLMS)["raw_md5"]
    # 对照探针 404、目标是真 text/plain 正文 -> 判活
    assert probe.classification.verdict is Verdict.OK
    profile = store.get(store.probe_url(SELF_LLMS))
    assert profile.status == 404


# --------------------------------------------------------------------------- #
# dns.json / FixtureResolver
# --------------------------------------------------------------------------- #


def test_resolver_replays_frozen_answers(store: FixtureStore) -> None:
    resolver = store.resolver()
    res = resolver("fixture-selftest.invalid")
    assert res.ok
    assert res.resolver == "system"


def test_resolver_uses_default_absent_for_unknown_hosts(store: FixtureStore) -> None:
    """§3.6：不在表里的 host 走 ``_default_absent``。

    这让「不存在的子域花 0 个 HTTP 请求」那条逻辑在 replay 下也测得到。
    """
    res = store.resolver()("nobody-here.invalid")
    assert res.addresses == ()
    assert not res.ok
    assert res.error


def test_resolver_replays_the_two_measured_dns_shapes(store: FixtureStore) -> None:
    """§3.6 的两个实测形态：本机污染但公共解析器有真地址；双 resolver NXDOMAIN。"""
    poisoned = store.resolver()("poisoned-selftest.invalid")
    assert poisoned.resolver == "8.8.8.8"
    assert poisoned.ok  # 本机答 127.0.0.1，但公共解析器给了真地址 -> 不是死站
    dead = store.resolver()("dead-selftest.invalid")
    assert dead.addresses == ()
    assert dead.resolver == "none"


def test_resolve_host_accepts_the_fixture_resolver_under_forbid_dns(
    store: FixtureStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GEO_AUDIT_FORBID_DNS=1`` 下注入 resolver 能跑，不注入必须炸。"""
    monkeypatch.setenv("GEO_AUDIT_FORBID_DNS", "1")
    res = resolve_host("fixture-selftest.invalid", resolver=store.resolver())
    assert res.ok
    with pytest.raises(AssertionError):
        resolve_host("fixture-selftest.invalid")


def test_resolver_without_a_default_row_raises_with_a_command() -> None:
    from geo_audit.fixtures import FixtureResolver

    resolver = FixtureResolver({"a.invalid": {"addresses": ["203.0.113.1"]}})
    with pytest.raises(DnsFixtureMissing) as err:
        resolver("b.invalid")
    assert "capture_fixtures.py" in str(err.value)
    assert DNS_ABSENT_KEY in str(err.value)


def test_store_without_any_dns_table_refuses_to_guess(tmp_path: Path) -> None:
    with pytest.raises(DnsFixtureMissing):
        FixtureStore(tmp_path).resolver()


# --------------------------------------------------------------------------- #
# index.json：expect / drift / 幂等
# --------------------------------------------------------------------------- #


def test_every_snapshot_has_an_expect_block(store: FixtureStore) -> None:
    """``expect`` 是字面量断言的唯一出处，所以每条都得有。"""
    for canon in store.snapshots():
        exp = store.expect(canon)
        assert set(exp) >= {"raw_md5", "bytes"}, canon


def test_rebuild_index_is_idempotent(tmp_path: Path) -> None:
    """门禁 M：``_rebuild_index`` 幂等（``git diff --exit-code`` 退出 0）。"""
    work = tmp_path / "fx"
    shutil.copytree(HANDWRITTEN, work)
    before = (work / "index.json").read_bytes()
    s1 = FixtureStore(work)
    assert s1.rebuild_index() == []
    once = (work / "index.json").read_bytes()
    assert once == before, "重建结果与提交进仓库的 index.json 不一致"
    FixtureStore(work).rebuild_index()
    assert (work / "index.json").read_bytes() == once


def test_rebuild_index_keeps_curated_expect_and_drift(tmp_path: Path) -> None:
    """机械字段重算，人工策展的 expect / drift / comment 一个字不动。

    这是漂移规程的地基：改的是 index.json 一处，重建不许把它冲掉。
    """
    work = tmp_path / "fx"
    shutil.copytree(HANDWRITTEN, work)
    s = FixtureStore(work)
    s.set_drift(
        SELF_LLMS, {"phenomenon": "unchanged", "date": "2026-09-07", "old": "x", "new": "y"}
    )
    s.set_expect(SELF_LLMS, {"raw_md5": "deliberately-stale", "bytes": 1})
    FixtureStore(work).rebuild_index()
    after = FixtureStore(work)
    assert after.expect(SELF_LLMS)["raw_md5"] == "deliberately-stale"
    assert after.drift(SELF_LLMS) is not None
    assert after.drift(SELF_LLMS)["phenomenon"] == "unchanged"  # type: ignore[index]
    assert after.get(SELF_LLMS).comment  # comment 也保住了


def test_check_expect_reports_the_drift_that_capture_must_not_swallow(tmp_path: Path) -> None:
    work = tmp_path / "fx"
    shutil.copytree(HANDWRITTEN, work)
    s = FixtureStore(work)
    real = s.digests(SELF_LLMS)
    assert (
        s.check_expect(SELF_LLMS, raw_md5=str(real["raw_md5"]), body_bytes=int(real["bytes"])) == []
    )
    s.set_expect(SELF_LLMS, {"raw_md5": "0" * 32, "bytes": 1})
    problems = s.check_expect(
        SELF_LLMS, raw_md5=str(real["raw_md5"]), body_bytes=int(real["bytes"])
    )
    assert len(problems) == 2


def test_check_expect_is_empty_when_nothing_drifted(store: FixtureStore) -> None:
    real = store.digests(SELF_LLMS)
    assert (
        store.check_expect(SELF_LLMS, raw_md5=str(real["raw_md5"]), body_bytes=int(real["bytes"]))
        == []
    )


def test_set_drift_rejects_an_off_menu_phenomenon(tmp_path: Path) -> None:
    """漂移只有四个分支，不许临场发挥（§8.1 那张表）。"""
    work = tmp_path / "fx"
    shutil.copytree(HANDWRITTEN, work)
    s = FixtureStore(work)
    with pytest.raises(ValueError, match="phenomenon"):
        s.set_drift(SELF_LLMS, {"phenomenon": "whatever"})
    for phenomenon in DRIFT_PHENOMENA:
        s.set_drift(SELF_LLMS, {"phenomenon": phenomenon})


def test_put_snapshot_refuses_to_overwrite_by_default(tmp_path: Path) -> None:
    """已冻结的快照是断言的一部分，覆盖它等于改测试。"""
    work = tmp_path / "fx"
    shutil.copytree(HANDWRITTEN, work)
    s = FixtureStore(work)
    original = s.digests(SELF_LLMS)
    kept = s.put_snapshot(
        SELF_LLMS, status=200, headers={"content-type": "text/plain"}, body=b"different"
    )
    assert kept.raw_md5 == original["raw_md5"]
    replaced = s.put_snapshot(
        SELF_LLMS,
        status=200,
        headers={"content-type": "text/plain"},
        body=b"different",
        overwrite=True,
    )
    assert replaced.raw_md5 != original["raw_md5"]
    # 但 expect 块不会被录制脚本改掉 —— 那要走 drift 规程
    assert s.expect(SELF_LLMS)["raw_md5"] == original["raw_md5"]


def test_gzip_bodies_are_byte_reproducible(tmp_path: Path) -> None:
    """``mtime=0``：同一份正文录两次必须是同一个文件，否则 git diff 永远不干净。"""
    a, b = tmp_path / "a", tmp_path / "b"
    for root in (a, b):
        FixtureStore(root).put_snapshot(
            "https://x.invalid/llms.txt",
            status=200,
            headers={"content-type": "text/plain"},
            body=b"same bytes\n",
            recorded_at="2026-09-07T00:00:00Z",
        )
    stem = snapshot_path("https://x.invalid/llms.txt")
    assert (a / (stem + ".body.gz")).read_bytes() == (b / (stem + ".body.gz")).read_bytes()
    assert (a / "index.json").read_bytes() == (b / "index.json").read_bytes()


def test_handwritten_snapshots_say_so(store: FixtureStore) -> None:
    """手写的快照必须自己标明是手写的，不许混进 ground truth。"""
    doc = json.loads((HANDWRITTEN / "index.json").read_text(encoding="utf-8"))
    assert doc["_handwritten"] is True
    assert "不是实录" in doc["_note"]
    for canon in store.snapshots():
        assert store.get(canon).handwritten, canon
        assert canon.split("/")[2].endswith(".invalid"), f"{canon} 不是保留域"


def test_default_honours_the_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEO_AUDIT_FIXTURES", str(HANDWRITTEN))
    assert FixtureStore.default().snapshots() == FixtureStore(HANDWRITTEN).snapshots()


# --------------------------------------------------------------------------- #
# urls.txt（§8.2 的机器检查）
# --------------------------------------------------------------------------- #


def test_parse_urls_txt_handles_all_four_line_kinds() -> None:
    specs = parse_urls_txt(
        "\n".join(
            [
                "# 注释行，不算",
                "",
                "https://a.invalid/llms.txt      # A01 200 html 壳",
                "@control https://a.invalid/llms.txt",
                "@expand https://a.invalid/llms.txt markdown 75   # C01 75 条内链",
                "@pair https://b.invalid/llms.txt https://b.invalid/llms-full.txt  # md5 相同",
            ]
        )
    )
    assert [s.kind for s in specs] == ["url", "control", "expand", "pair"]
    assert specs[0].urls == ("https://a.invalid/llms.txt",)
    # @control 行本身不录目标，只录探针（探针 URL 录制时才生成）
    assert specs[1].urls == ()
    assert specs[1].comment.startswith("A01")  # 继承被对照 URL 的注释
    assert specs[1].raw_comment is None
    assert (specs[2].extractor, specs[2].limit) == ("markdown", 75)
    assert specs[3].urls == ("https://b.invalid/llms.txt", "https://b.invalid/llms-full.txt")


@pytest.mark.parametrize(
    "bad",
    [
        "@control https://a.invalid/x https://b.invalid/y",
        "@expand https://a.invalid/x markdown",
        "@expand https://a.invalid/x nosuchextractor 10",
        "@pair https://a.invalid/x",
        "@whatever https://a.invalid/x",
        "https://a.invalid/x https://b.invalid/y   # 两个 URL",
    ],
)
def test_parse_urls_txt_rejects_malformed_lines(bad: str) -> None:
    with pytest.raises(ValueError, match=r"urls\.txt:1"):
        parse_urls_txt(bad)


@urls_txt_needed
def test_urls_txt_shape() -> None:
    """§8.2 的机器检查，逐条照抄。

    「改了这个数就必须改这条断言」—— 所以这里的 270/212/26/17/15 不是我算出来的，
    是 §8.2 标题里写死的。
    """
    lines = load_urls_txt(FIXTURES)
    assert len(lines) == 270
    assert sum(1 for x in lines if x.kind == "url") == 212
    assert sum(1 for x in lines if x.kind == "control") == 26
    assert sum(1 for x in lines if x.kind == "expand") == 17
    assert sum(1 for x in lines if x.kind == "pair") == 15
    urls = [canon_url(x.url) for x in lines if x.kind == "url"]
    assert len(set(urls)) == 212, "URL 行不许重复"


@urls_txt_needed
def test_urls_txt_lines_carry_their_purpose() -> None:
    """每行必须有用途注释 —— 除了自我说明的 ``/robots.txt``。

    §8.2 自己矛盾：它的机器检查写 ``assert all(l.comment ...)``，可它给出的全文里
    L 组 8 条 ``robots.txt`` 一条注释都没有。这里不替作者编用途，而是把豁免收窄到
    「路径就是 /robots.txt」这一种自我说明的形状 —— 补了注释这条照样过。
    """
    offenders = [
        (x.lineno, x.url)
        for x in load_urls_txt(FIXTURES)
        if not x.comment and not x.url.endswith("/robots.txt")
    ]
    assert offenders == []


@urls_txt_needed
def test_every_host_in_urls_txt_has_a_dns_entry() -> None:
    """§8.1 决定 4：缺一个就红。"""
    table = json.loads((FIXTURES / "dns.json").read_text(encoding="utf-8"))
    missing = sorted(hosts_of(load_urls_txt(FIXTURES)) - set(table))
    assert missing == []


@urls_txt_needed
def test_at_control_targets_appear_earlier_in_the_file() -> None:
    """``@control`` 要能继承注释、录制时也要先见过目标，所以必须排在目标后面。"""
    seen: set[str] = set()
    for spec in load_urls_txt(FIXTURES):
        if spec.kind == "control":
            assert canon_url(spec.url) in seen, f"urls.txt:{spec.lineno} @control 排在目标前面"
        for u in spec.urls:
            seen.add(canon_url(u))


@urls_txt_needed
def test_at_expand_lines_are_well_formed() -> None:
    """``@expand`` 的抽取器与条数必须能直接喂给录制脚本。

    这里**故意不**要求父文件在前面有独立的 URL 行：§8.2 给出的全文里 17 条
    ``@expand`` 有 10 条（inngest / replicate / pingcap / bytebase / turso /
    zilliz / attio-customers / close / mailerlite / factorialhr）的父文件从没
    单独列过。所以 ``capture_fixtures.py`` 在父文件缺席时**先把父文件录下来**
    再展开，而不是要求作者补 10 行 —— 展开本来就必须先有父文件的正文。
    """
    for spec in load_urls_txt(FIXTURES):
        if spec.kind == "expand":
            assert spec.extractor in EXPAND_EXTRACTORS, spec
            assert spec.limit and spec.limit > 0, spec


@urls_txt_needed
@real_index_needed
def test_every_a_group_soft404_has_a_frozen_control_probe() -> None:
    """门禁 M：``store.probe_url()`` 对 16 个软 404 位置全部可解析。

    A 组名单不在这里硬编码 —— 它就是 urls.txt 里带 ``@control`` 的那些行。
    """
    store = FixtureStore(FIXTURES)
    for spec in load_urls_txt(FIXTURES):
        if spec.kind == "control":
            assert store.probe_url(spec.url) is not None


# --------------------------------------------------------------------------- #
# @expand 的抽取器（scripts/capture_fixtures.py）
# --------------------------------------------------------------------------- #


def _load_capture_module() -> Any:
    """按路径加载 ``scripts/capture_fixtures.py``（scripts/ 不是 package）。"""
    path = REPO / "scripts" / "capture_fixtures.py"
    spec = importlib.util.spec_from_file_location("capture_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("extractor", "body", "expected"),
    [
        (
            "markdown",
            "- [Quickstart](/getting-started/quickstart)\n- [Ext](https://x.invalid/a)\n",
            ["https://docs.invalid/getting-started/quickstart", "https://x.invalid/a"],
        ),
        (
            "bare",
            "see https://docs.invalid/a and https://docs.invalid/b.\n",
            ["https://docs.invalid/a", "https://docs.invalid/b"],
        ),
        (
            "relative",
            "docs: /docs/intro.md and /docs/api.md\n",
            ["https://docs.invalid/docs/intro.md", "https://docs.invalid/docs/api.md"],
        ),
        (
            "html_a",
            "<a href=\"/x\">x</a><a href='https://y.invalid/z'>z</a>",
            ["https://docs.invalid/x", "https://y.invalid/z"],
        ),
    ],
)
def test_expand_extractors(extractor: str, body: str, expected: list[str]) -> None:
    module = _load_capture_module()
    got = module.extract_links(body, extractor=extractor, base_url="https://docs.invalid/llms.txt")
    assert got == expected


def test_expand_extractors_skip_non_http_schemes() -> None:
    module = _load_capture_module()
    body = "[mail](mailto:a@b.invalid) [anchor](#x) [js](javascript:void(0)) [ok](/ok)"
    assert module.extract_links(body, extractor="markdown", base_url="https://d.invalid/l.txt") == [
        "https://d.invalid/ok"
    ]


def test_expand_sampling_is_deterministic() -> None:
    """bytebase 那 504 条只录抽中的 60 条，抽样必须可复现。

    否则每次补录都换一批 URL，index.json 每回 diff 都是全量。
    """
    items = [f"https://x.invalid/{i}.md" for i in range(504)]
    first = sample_deterministic(items, 60, seed="https://www.bytebase.com/llms.txt")
    second = sample_deterministic(items, 60, seed="https://www.bytebase.com/llms.txt")
    assert first == second
    assert len(first) == 60
    assert first != sample_deterministic(items, 60, seed="https://other.invalid/llms.txt")
    # 不够 limit 就全给
    assert sample_deterministic(items[:5], 60, seed="x") == sorted(items[:5])


# --------------------------------------------------------------------------- #
# 反硬编码（卡点 A51 / 门禁 M）
# --------------------------------------------------------------------------- #

#: 三个搬自原型的冻结文件。验收标准 A4 要求它们与搬入前**逐字节相同**，
#: 所以它们不参与这条 grep。它们里面的十六进制串也不是实测摘要，是手造的
#: 占位哈希（``dead`` + ``beef`` 那一路），跟活网漂移无关。
FROZEN_TEST_FILES = frozenset(
    {"tests/test_classify.py", "tests/test_infra.py", "tests/fixtures/real_cases.py"}
)

_HEX_RUN = re.compile(r"\b[0-9a-f]{16,}\b")


def test_no_hardcoded_digests_in_tests() -> None:
    """``tests/`` 下不许出现 ``e7475c34`` 这类摘要串（index.json 之外）。

    这是全项目最贵资产的防漂移设计：字面量只在 ``fixtures/index.json`` 的
    ``expect`` 块里出现一次，测试从那里读。活网一漂，改一处。
    """
    offenders: list[str] = []
    for path in sorted((REPO / "tests").rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        if rel in FROZEN_TEST_FILES:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for hit in _HEX_RUN.findall(line):
                offenders.append(f"{rel}:{lineno} {hit}")
    assert offenders == [], (
        "把这些摘要搬进 fixtures/index.json 的 expect 块，测试改成从 store.expect() 读：\n"
        + "\n".join(offenders)
    )


def test_the_anti_hardcoding_check_can_actually_fail() -> None:
    """反向验证：这条 grep 不是装饰。

    样例摘要是**现算**的，不是抄进来的字面量 —— 否则这条测试自己就会被上面
    那条 grep 抓住（写完第一版就当场撞上了）。
    """
    sample = hashlib.md5(b"drift", usedforsecurity=False).hexdigest()
    assert _HEX_RUN.findall(f"assert md5 == {sample!r}")
    assert not _HEX_RUN.findall("assert md5 == store.expect(url)['raw_md5']")


def test_accept_text_is_what_the_text_file_positions_ask_for() -> None:
    """守一下重放的前提：TEXT_FILE 位置发的 Accept 头是固定的。

    快照是按 URL 索引的，不按 Accept 分片；这条断言让「换了 Accept 就该重录」
    这件事至少有人看见。
    """
    assert "text/plain" in ACCEPT_TEXT
