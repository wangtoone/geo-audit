"""第 8 步自验：llms-full 造假（§4.2）。

期望值全部来自 ``tests/data/llmsfull_expectations.json``（第 5 步落地的 15 对）。
正文是**按标注的字节数与形态合成的**：实测报告自己写明 3/12 个重测字节数不可复现，
所以能冻结的只有「形态 + 分支」，不是正文原文。真正的正文与三个 md5 在
``fixtures/index.json`` 的 ``expect`` 块里（第 4b 步实录），依赖它的测试 skip 掉。

④ 正常打包那五对的真实体量是 9 MB–20 MB。测试里**不materialize**那么大的正文：
分两条断言 ——（a）标注里记录的膨胀比本身 >= 3.0，说明 ④ 的闸会放行；
（b）同形态的等比缩小样本跑 ``check_llms_full`` 零 finding。

⚠️ 本文件不许出现摘要字面量（md5/sha），grep 守着。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from geo_audit.checks.ai_path import (
    LLMS_FULL_DETAIL_KEYS,
    Severity,
    Stage,
    check_llms_full,
    index_shape,
)
from geo_audit.models import (
    Classification,
    Expect,
    HttpResponse,
    Probe,
    RedirectHop,
    Verdict,
    finalize_response,
)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
DATA = REPO / "tests" / "data"

real_index_needed = pytest.mark.skipif(
    not (FIXTURES / "index.json").exists(),
    reason="第 4b 步的实录快照还没落地（fixtures/index.json 不存在）",
)

EXPECTATIONS: dict[str, Any] = json.loads(
    (DATA / "llmsfull_expectations.json").read_text(encoding="utf-8")
)
PAIRS: list[dict[str, Any]] = EXPECTATIONS["pairs"]
META: dict[str, Any] = EXPECTATIONS["_meta"]

#: ④ 正常打包的等比缩小上限。真实 9 MB–20 MB 的正文在测试里没有信息量，
#: 决定分支的是膨胀比，不是绝对体量。
NORMAL_SCALE_CAP = 200_000


def _by_id(pair_id: str) -> dict[str, Any]:
    return next(p for p in PAIRS if p["id"] == pair_id)


# --------------------------------------------------------------------------- #
# 正文合成器：三种形态，字节数可精确命中
# --------------------------------------------------------------------------- #


def _index_body(target_bytes: int, *, brand: str = "acme") -> str:
    """纯索引形态：几乎每行都是 markdown 链接行（link_ratio 接近 1.0）。"""
    lines = [f"# {brand}", ""]
    i = 0
    while len(("\n".join(lines)).encode()) < target_bytes:
        lines.append(f"- [Guide {i}](https://docs.{brand}.invalid/guide/{i}.md): section {i}")
        i += 1
    return _pad(("\n".join(lines)), target_bytes)


def _prose_body(target_bytes: int, *, brand: str = "acme") -> str:
    """全站打包形态：整段正文，没有链接行 —— ④ 的 prose 闸看的就是这个。"""
    lines = [f"# {brand} full documentation", ""]
    i = 0
    while len(("\n".join(lines)).encode()) < target_bytes:
        lines.append(
            f"Chapter {i}. This paragraph is real prose, not an index line. "
            f"It describes configuration, troubleshooting and quotas in module {i}."
        )
        i += 1
    return _pad(("\n".join(lines)), target_bytes)


def _pad(body: str, target_bytes: int) -> str:
    """补/截到目标字节数。补的是**空白行**：``index_shape`` 只看非空行，所以补白
    既不改 link_ratio 也不改 prose 字符数 —— 与 ``test_byte_count_never_affects_verdict``
    同一个道理。"""
    raw = body.encode()
    if len(raw) >= target_bytes:
        return raw[:target_bytes].decode(errors="ignore")
    return body + "\n" + " " * (target_bytes - len(raw) - 1)


def _probe(
    url: str,
    body: str,
    *,
    content_type: str = "text/plain; charset=utf-8",
    status: int = 200,
    final_url: str | None = None,
    redirects: tuple[RedirectHop, ...] = (),
) -> Probe:
    resp = finalize_response(
        HttpResponse(
            url=url,
            final_url=final_url or url,
            status=status,
            headers={"content-type": content_type},
            body=body.encode(),
            redirects=redirects,
        ),
        want_digests=True,
    )
    return Probe(url, Expect.TEXT_FILE, resp, Classification(Verdict.OK, "ok"))


def _pair_probes(pair: dict[str, Any], *, index_bytes: int, full_bytes: int) -> list[Probe]:
    """按 ``branch`` 合成一对探测。"""
    branch = str(pair["branch"])
    index_url, full_url = str(pair["index_url"]), str(pair["full_url"])
    brand = str(pair["domain"]).split(".")[0]

    if branch == "①redirect_to_index":
        body = _index_body(index_bytes, brand=brand)
        index = _probe(index_url, body)
        full = _probe(
            full_url,
            body,
            final_url=index_url,
            redirects=(RedirectHop(302, full_url, index_url),),
        )
        return [index, full]
    if branch == "②byte_copy":
        body = _index_body(index_bytes, brand=brand)
        return [_probe(index_url, body), _probe(full_url, body)]
    if branch == "③not_fulltext":
        return [
            _probe(index_url, _index_body(index_bytes, brand=brand)),
            _probe(full_url, _index_body(full_bytes, brand=brand + "x")),
        ]
    if branch == "④normal":
        return [
            _probe(index_url, _index_body(index_bytes, brand=brand)),
            _probe(full_url, _prose_body(full_bytes, brand=brand)),
        ]
    if branch.startswith("⑤thin"):
        # 灰区：偏大一点点但仍是纯索引形态（link_ratio > 0.5）。
        return [
            _probe(index_url, _index_body(index_bytes, brand=brand)),
            _probe(full_url, _index_body(full_bytes, brand=brand)),
        ]
    raise AssertionError(f"未知分支 {branch}")


def _scaled(pair: dict[str, Any]) -> tuple[int, int] | None:
    """(index_bytes, full_bytes)。④ 那五对按 NORMAL_SCALE_CAP 等比缩小。"""
    ib, fb = pair["index_bytes"], pair["full_bytes"]
    if ib is None or fb is None:
        return None
    if pair["branch"] == "④normal" and fb > NORMAL_SCALE_CAP:
        ratio = fb / max(ib, 1)
        return int(ib), int(min(NORMAL_SCALE_CAP, max(ib * ratio, ib * 3 + 1)))
    return int(ib), int(fb)


# --------------------------------------------------------------------------- #
# 15 对逐条断言
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("pair", PAIRS, ids=lambda p: f"{p['id']}-{p['domain']}")
def test_pair_lands_on_the_recorded_branch(pair: dict[str, Any]) -> None:
    if pair.get("expect_check_id_pending"):
        pytest.skip(
            f"{pair['id']} 待实测：ratio {pair['ratio']} 落在灰区，出 thin(INFO) 还是 None "
            f"取决于 index_shape(full).link_ratio 是否 > 0.5，正文没冻结前不许写死"
        )
    scaled = _scaled(pair)
    if scaled is None:
        pytest.skip(f"{pair['id']} 的字节数原文未记（{pair['note']}）—— 待 fixture 回填")
    index_bytes, full_bytes = scaled
    probes = _pair_probes(pair, index_bytes=index_bytes, full_bytes=full_bytes)
    findings = check_llms_full(str(pair["domain"]), probes)

    if pair["expect_check_id"] is None:
        assert findings == (), f"{pair['id']} 是正常打包，一条都不许报：{pair['note']}"
        return
    assert len(findings) == 1, pair["id"]
    f = findings[0]
    assert f.check_id == pair["expect_check_id"]
    assert f.kind == "llms_full_fake"
    assert f.stage is Stage.FULLTEXT
    assert f.severity is Severity[str(pair["expect_severity"]).upper()]
    assert f.counted_as_hit is bool(pair["counted_as_hit"])
    assert set(f.detail) == set(LLMS_FULL_DETAIL_KEYS)


def test_recorded_ratios_of_normal_packages_clear_the_gate() -> None:
    """④ 五个正常打包：**用标注里记录的真实字节数**验证膨胀比闸会放行。

    这一条不合成正文（真实体量 9 MB–20 MB），只算比 —— 它挡住的是「有人把
    ③/④ 的阈值改小」这类回归。
    """
    normals = [
        p for p in PAIRS if p["branch"] == "④normal" and p["index_bytes"] and p["full_bytes"]
    ]
    # ④ 共七对（B07–B12、B15），其中三对的 index_bytes 是 null，算不了比：
    #   B07 resend /docs/（原文只记「52KB」）、B12 commercelayer（三处记录互不相同）、
    #   B15 platform.minimax.io（只记了 KB 量级）。
    pending = {p["id"] for p in PAIRS if p["branch"] == "④normal"} - {p["id"] for p in normals}
    assert pending == {"B07", "B12", "B15"}, f"④ 待回填的对变了：{pending}"
    assert len(normals) == 4
    for pair in normals:
        ratio = round(int(pair["full_bytes"]) / max(int(pair["index_bytes"]), 1), 3)
        assert ratio >= 3.0, f"{pair['id']} {pair['domain']} 的膨胀比 {ratio} 过不了 ④ 的闸"


def test_counted_as_hit_is_exactly_five_domains() -> None:
    """§4.2 尾（2051）+ A12：``counted_as_hit=True`` 恰为 **5** 个域。"""
    expected_ids = set(META["counted_as_hit_ids"])
    expected_domains = {str(_by_id(i)["domain"]) for i in expected_ids}
    assert META["counted_as_hit_total"] == 5
    assert len(expected_domains) == 5

    hit_domains: set[str] = set()
    skipped: list[str] = []
    for pair in PAIRS:
        scaled = _scaled(pair)
        if scaled is None or pair.get("expect_check_id_pending"):
            skipped.append(str(pair["id"]))
            continue
        probes = _pair_probes(pair, index_bytes=scaled[0], full_bytes=scaled[1])
        for f in check_llms_full(str(pair["domain"]), probes):
            if f.counted_as_hit:
                hit_domains.add(str(pair["domain"]))
    assert hit_domains == expected_domains, f"跳过的对：{skipped}"


def test_resend_is_warn_not_hit() -> None:
    """§4.2:2056 全文照抄的断言：resend 根那对是 INFO + 不进分子，且
    ``docs_llms_full_bytes`` 填的是 ``/docs/llms-full.txt`` 的实测字节。

    这一条同时验证 ``check_llms_full`` 的**两趟**：第二对（/docs/）判 ④ 放行，
    它的字节数被回填进第一对的 detail（规格没说谁回填，见交付说明 spec_gaps）。
    """
    thin_pair = _by_id("B06")  # resend.com/llms.txt vs /llms-full.txt
    docs_pair = _by_id("B07")  # resend.com/docs/llms.txt vs /docs/llms-full.txt
    docs_full_bytes = int(docs_pair["full_bytes"])

    probes = _pair_probes(
        thin_pair,
        index_bytes=int(thin_pair["index_bytes"]),
        full_bytes=int(thin_pair["full_bytes"]),
    )
    # /docs/ 那对：真全文。index_bytes 原文未记（52 KB 量级），取一个小于全文
    # 三分之一的值即可，决定分支的是「比 >= 3」。
    probes += _pair_probes(docs_pair, index_bytes=52_000, full_bytes=docs_full_bytes)

    fs = check_llms_full("resend.com", probes)
    thin = [f for f in fs if f.check_id == "ai_path.llms_full_thin"]
    assert len(thin) == 1
    assert thin[0].severity is Severity.INFO
    assert thin[0].counted_as_hit is False
    assert thin[0].detail["docs_llms_full_bytes"] == docs_full_bytes


def test_same_domain_two_pairs_are_judged_separately() -> None:
    """卡点 S10：一个域可以有多对，各判各的（返回 tuple 不是 Optional）。"""
    thin_pair, docs_pair = _by_id("B06"), _by_id("B07")
    probes = _pair_probes(
        thin_pair,
        index_bytes=int(thin_pair["index_bytes"]),
        full_bytes=int(thin_pair["full_bytes"]),
    )
    probes += _pair_probes(docs_pair, index_bytes=52_000, full_bytes=int(docs_pair["full_bytes"]))
    fs = check_llms_full("resend.com", probes)
    # 根那对报 thin，/docs/ 那对零 finding。
    assert len(fs) == 1
    assert "/docs/" not in str(fs[0].detail["full_url"])


def test_missing_digests_are_never_treated_as_different_hashes() -> None:
    """卡点 S10：``raw_md5`` / ``norm_sha256`` 是 None（只查存活的 64 KiB 档）时
    判 UNKNOWN 而不是「哈希不同」—— 一条 finding 都不许产。"""
    pair = _by_id("B01")  # 真实是字节副本，有摘要时必报
    body = _index_body(int(pair["index_bytes"]))
    with_digests = [
        _probe(str(pair["index_url"]), body),
        _probe(str(pair["full_url"]), body),
    ]
    assert len(check_llms_full("deepgram.com", with_digests)) == 1

    # 同一批响应，只是没算摘要（want_digests=False 的那一档）。
    def bare(url: str) -> Probe:
        resp = HttpResponse(
            url=url,
            final_url=url,
            status=200,
            headers={"content-type": "text/plain"},
            body=body.encode(),
        )
        assert resp.raw_md5 is None and resp.norm_sha256 is None
        return Probe(url, Expect.TEXT_FILE, resp, Classification(Verdict.OK, "ok"))

    assert (
        check_llms_full("deepgram.com", [bare(str(pair["index_url"])), bare(str(pair["full_url"]))])
        == ()
    )


def test_only_ok_pairs_are_judged() -> None:
    """软 404 / 404 / 被拦各归各的子检查，llms-full 这里不重复计。"""
    pair = _by_id("B01")
    body = _index_body(int(pair["index_bytes"]))
    index = _probe(str(pair["index_url"]), body)
    full = _probe(str(pair["full_url"]), body)
    soft = Probe(
        full.url,
        Expect.TEXT_FILE,
        full.response,
        Classification(Verdict.SOFT404, "html_where_text_expected"),
    )
    assert check_llms_full("deepgram.com", [index, soft]) == ()


def test_pairs_only_match_within_the_same_host_and_prefix() -> None:
    """配对键 = (host, path[:path.rfind("/")])：llms.txt 与 llms-full.txt **同目录才配**。"""
    body = _index_body(4_000)
    root_index = _probe("https://acme.invalid/llms.txt", body)
    docs_full = _probe("https://acme.invalid/docs/llms-full.txt", body)
    # 同 host 但不同目录 -> 不配对 -> 不判「字节副本」。
    assert check_llms_full("acme.invalid", [root_index, docs_full]) == ()

    other_host_full = _probe("https://docs.acme.invalid/llms-full.txt", body)
    assert check_llms_full("acme.invalid", [root_index, other_host_full]) == ()


def test_index_shape_separates_index_from_prose() -> None:
    """``index_shape`` 是 ④/⑤ 的唯一判据，两端形态必须分得开。"""
    link_ratio, prose = index_shape(_index_body(4_000))
    assert link_ratio > 0.5
    assert prose == 0  # 纯索引没有正文字符（标题行与链接行都不计）

    link_ratio2, prose2 = index_shape(_prose_body(4_000))
    assert link_ratio2 == 0.0
    assert prose2 > 1_000

    assert index_shape("") == (0.0, 0)


def test_redirect_comparison_is_normalized() -> None:
    """① 的比较去 query、去尾斜杠、大小写不敏感（§4.2:1992）。"""
    body = _index_body(415)
    index_url = "https://docs.bigcommerce.invalid/llms.txt"
    index = _probe(index_url, body)
    full = _probe(
        "https://docs.bigcommerce.invalid/llms-full.txt",
        body,
        final_url="https://DOCS.bigcommerce.invalid/llms.txt/?x=1",
    )
    (f,) = check_llms_full("bigcommerce.invalid", [index, full])
    assert f.check_id == "ai_path.llms_full_redirect_to_index"


def test_every_finding_carries_the_naive_contrast() -> None:
    """产品核心卖点：每条 finding 都能回答「只探根路径的工具会怎么读」。

    upstash 的 ``/llms-full.txt`` 在**根路径**上（朴素探测集内的四个位置之一），
    朴素读数 200 → 「已采纳」，真实是「比 llms.txt 还小」→ 假阳方向，而我们
    **零额外请求**就看出来了（llms.txt 本来就要抓，§4.5 表第二行的口径）。
    """
    pair = _by_id("B04")  # upstash.com/llms.txt vs /llms-full.txt
    probes = _pair_probes(
        pair, index_bytes=int(pair["index_bytes"]), full_bytes=int(pair["full_bytes"])
    )
    (f,) = check_llms_full("upstash.com", probes)
    assert f.naive is not None
    assert f.naive.in_naive_probe_set is True
    assert f.naive.naive_conclusion.startswith("已采纳")
    assert f.naive.direction == "false_positive"
    assert f.naive.extra_requests == 0
    assert f.naive_is_wrong is True


def test_subdomain_positions_are_outside_the_naive_probe_set() -> None:
    """⚠️ 规格自相矛盾，见交付说明 spec_gaps：

    §4.5:2400 把朴素探测集定死为「apex 与 www 上的两条根路径，**仅此四个**」，
    而同一节的对照表第二行又把 ``developers.deepgram.com/llms-full.txt`` 列成
    「朴素读数 200 → 有全文」的假阳样本 —— 那个 host 压根不在集内。

    这里断言的是**机制**（集合定义那半），因为它是可执行的那一半：子域上的位置
    naive_conclusion 固定「未采纳（没探这个位置）」。裁决落地后改这条断言。
    """
    pair = _by_id("B01")  # developers.deepgram.com
    body = _index_body(int(pair["index_bytes"]))
    probes = [_probe(str(pair["index_url"]), body), _probe(str(pair["full_url"]), body)]
    (f,) = check_llms_full("deepgram.com", probes)
    assert f.naive is not None
    assert f.naive.in_naive_probe_set is False
    assert f.naive.naive_conclusion == "未采纳（没探这个位置）"


@real_index_needed
def test_the_three_md5s_come_from_the_index_expect_block() -> None:
    """三个字节副本的 md5 必须与 ``fixtures/index.json`` 的 expect 块逐字相同。

    断言写成「index.json 里 llms.txt 与 llms-full.txt 的 raw_md5 相等」——
    摘要字面量一个都不进测试文件（A11 / 门禁 M）。
    """
    from geo_audit.fixtures import FixtureStore

    store = FixtureStore(FIXTURES)
    for pair_id in ("B01", "B02", "B03"):
        pair = _by_id(pair_id)
        index_expect = store.expect(str(pair["index_url"]))
        full_expect = store.expect(str(pair["full_url"]))
        assert index_expect["raw_md5"] == full_expect["raw_md5"], pair_id
        assert index_expect["bytes"] == full_expect["bytes"] == pair["full_bytes"]
