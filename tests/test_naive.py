"""第 14 步 · 朴素基线换算器（`src/geo_audit/naive.py`，§4.5）。

两组 ground truth 全部来自 `corpus/feature-raw.json` 的 72 域实跑记录，逐条在
用例旁边注明出处。**不依赖 `fixtures/index.json`**（第 4b 步才实录），所以这些
用例在离线 CI 下无条件可跑，不需要 skip。

三条卡点在这里各有对应用例：

* 换算器不发请求 —— :func:`test_source_has_no_http_call` 直接 grep 源码，
  :func:`test_emulator_is_stateless` 断言它连一个实例属性都没有；
* minimax 的真文件是 `platform.minimax.io/docs/llms.txt`、**24 KB**
  —— :func:`test_minimax_real_file_is_24kb_not_8_2kb`；
* modal 0 行 diverges 且文案翻正向 —— :func:`test_modal_zero_divergence_flips_copy`。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from geo_audit import naive
from geo_audit.models import (
    Evidence,
    HttpResponse,
    NaiveContrast,
    RedirectHop,
    SiteMap,
    Stage,
    Status,
)
from geo_audit.naive import NaiveEmulator, _conclusions_differ

# --------------------------------------------------------------------------- #
# 测试替身
#
# §2.9 的 `Position` 还不在 models.py 里（只有 `PositionSeed`，而 seed 没有
# evidence / control）。换算器只读六个字段，所以这里用一个满足
# `naive.PositionLike` 结构协议的最小 dataclass 当替身 —— **不是**在 tests 里
# 重定义 Position（A6/A7 都不许），第 16 步真 Position 落地后把这个替身删掉即可。
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Pos:
    stage: Stage
    probe_url: str
    status: Status
    detail: str
    evidence: Evidence | None = None
    control: Evidence | None = None


def sitemap_for(domain: str) -> SiteMap:
    """换算器只读 `registrable_domain` 一个字段，其余给空值即可。"""
    return SiteMap(
        input_domain=domain,
        registrable_domain=domain,
        hosts=(),
        apex_www=None,
        sitemap_urls={},
        pricing_url=None,
        pricing_candidates_tried=(),
        ai_path_probes=(),
        robots={},
    )


def ev(url: str, status: int, ctype: str = "text/plain") -> Evidence:
    return Evidence(url=url, http_status=status, content_type=ctype, curl_repro=f"curl -sS {url}")


def rows_of(domain: str, positions: list[Pos]) -> tuple[NaiveContrast, ...]:
    return NaiveEmulator().rows(sitemap_for(domain), positions)


def by_url(rows: tuple[NaiveContrast, ...], url: str) -> NaiveContrast:
    (hit,) = [r for r in rows if r.probe_url == url]
    return hit


# --------------------------------------------------------------------------- #
# minimax.io —— corpus/feature-raw.json 的 c3_ai_path 逐条抄下来
#
# "https://www.minimax.io/llms.txt 返回 200、content-type text/html、384,052 字节，
#  与首页 SPA 外壳完全同尺寸；实测 https://www.minimax.io/this-does-not-exist-xyz123
#  也返回 200 + 384,052 字节，证明该站对任意路径都回同一个壳，判 soft404。
#  https://platform.minimax.io/llms.txt 真 404，但
#  https://platform.minimax.io/docs/llms.txt 是真文件（200 text/plain 24KB）"
#  "https://platform.minimax.io/docs/llms-full.txt ok（725KB text/plain）；根路径下无"
#
# ⚠️ `www.minimax.io/llms-full.txt` 与 apex 侧（不带 www）的读数 corpus **没有记**
# —— §4.5:2448-2450 明写了这一点，所以这里一行都不编。也正因如此下面的 divergence
# 用例断言的是**集合下界**（`>= 2`），精确条数留到第 4b 步实录 fixture 后回填。
# --------------------------------------------------------------------------- #

MINIMAX_SOFT404_URL = "https://www.minimax.io/llms.txt"
MINIMAX_REAL_FILE_URL = "https://platform.minimax.io/docs/llms.txt"
MINIMAX_REAL_FILE_DETAIL = "真文件，200 text/plain 24 KB"


def minimax_positions() -> list[Pos]:
    # 对照探测那条 URL 在实跑里带一段随机 token，这里刻意不写成十六进制串 ——
    # tests/test_fixture_store.py::test_no_hardcoded_digests_in_tests 会把任何
    # 长十六进制串当成摘要字面量拦下（A11），而这段 token 跟摘要毫无关系。
    control = Evidence(
        url="https://www.minimax.io/geo-audit-probe-does-not-exist.txt",
        http_status=200,
        content_type="text/html",
        bytes_len=384_052,
        curl_repro="curl -sS https://www.minimax.io/geo-audit-probe-does-not-exist.txt",
    )
    return [
        Pos(Stage.DISCOVERY, "https://www.minimax.io/", Status.PASS, "入口可达"),
        Pos(Stage.DISCOVERY, "https://platform.minimax.io/", Status.PASS, "入口可达"),
        Pos(
            Stage.INDEX_FILE,
            MINIMAX_SOFT404_URL,
            Status.FAIL,
            "软 404：与随机路径同为 384,052 字节、同一份外壳",
            evidence=ev(MINIMAX_SOFT404_URL, 200, "text/html"),
            control=control,
        ),
        Pos(
            Stage.INDEX_FILE,
            "https://platform.minimax.io/llms.txt",
            Status.NOT_APPLICABLE,
            "真 404，这个位置没做",
            evidence=ev("https://platform.minimax.io/llms.txt", 404, "text/html"),
        ),
        Pos(
            Stage.INDEX_FILE,
            MINIMAX_REAL_FILE_URL,
            Status.PASS,
            MINIMAX_REAL_FILE_DETAIL,
            evidence=ev(MINIMAX_REAL_FILE_URL, 200),
        ),
        Pos(
            Stage.FULLTEXT,
            "https://platform.minimax.io/docs/llms-full.txt",
            Status.PASS,
            "真全文，200 text/plain 725 KB",
            evidence=ev("https://platform.minimax.io/docs/llms-full.txt", 200),
        ),
    ]


# --------------------------------------------------------------------------- #
# modal.com —— corpus/feature-raw.json：
#   "ok（https://modal.com/llms.txt 与 /docs/llms.txt 同一份真文件，25250 字节）"
#   "llms_full_status: ok，真内容 2.29MB"
# --------------------------------------------------------------------------- #


def modal_positions() -> list[Pos]:
    return [
        Pos(Stage.DISCOVERY, "https://modal.com/", Status.PASS, "入口可达"),
        Pos(
            Stage.INDEX_FILE,
            "https://modal.com/llms.txt",
            Status.PASS,
            "真文件，200 text/plain 25,250 字节",
            evidence=ev("https://modal.com/llms.txt", 200),
        ),
        Pos(
            Stage.INDEX_FILE,
            "https://modal.com/docs/llms.txt",
            Status.PASS,
            "真文件，与根路径那份同一字节",
            evidence=ev("https://modal.com/docs/llms.txt", 200),
        ),
        Pos(
            # 待实测：corpus 只写了「llms_full_status: ok，真内容 2.29MB」，没记 URL。
            # 根路径下的 llms.txt 是真文件，所以把全文位置也记在根路径上。
            Stage.FULLTEXT,
            "https://modal.com/llms-full.txt",
            Status.PASS,
            "真全文，2.29 MB",
            evidence=ev("https://modal.com/llms-full.txt", 200),
        ),
    ]


# --------------------------------------------------------------------------- #
# 卡点一：纯换算器，不持 client、不发任何请求
# --------------------------------------------------------------------------- #

NAIVE_SOURCE = Path(naive.__file__).read_text("utf-8")


def test_source_has_no_http_call() -> None:
    """第 14 步的自证 grep：源码里不许出现任何真实 HTTP 调用。

    要求的是**零命中**，一个例外都不留 —— 连注释和 docstring 里都不写这几个
    字面量，好让验收那条 grep 的输出干净到没有例外要解释。
    """
    pattern = re.compile(r"httpx|requests\.|urlopen|\.get\(|fetch")
    hits = [
        (i, line)
        for i, line in enumerate(NAIVE_SOURCE.splitlines(), start=1)
        if pattern.search(line)
    ]
    assert hits == [], f"naive.py 出现了疑似真实 HTTP 调用：{hits}"


def test_source_never_imports_a_client() -> None:
    for forbidden in ("httpx", "urllib.request", "fetch.client", "GeoClient"):
        assert forbidden not in NAIVE_SOURCE


def test_emulator_is_stateless() -> None:
    """连一个实例属性都不许有 —— 有属性就可能有 client。"""
    emu = NaiveEmulator()
    assert NaiveEmulator.__slots__ == ()
    assert not hasattr(emu, "__dict__")
    with pytest.raises(AttributeError):
        emu.client = object()  # type: ignore[attr-defined]


def test_rows_needs_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """conftest 的断网闸已经 autouse 生效；这里再确认换算器在闸下照样出全表。"""
    monkeypatch.setenv("GEO_AUDIT_FORBID_NETWORK", "1")
    assert len(rows_of("minimax.io", minimax_positions())) == 6


# --------------------------------------------------------------------------- #
# 行来源：①②③ 三段各一行，④⑤⑥ 一行都不进
# --------------------------------------------------------------------------- #


def test_row_source_is_exactly_the_first_three_stages() -> None:
    positions = [
        Pos(Stage.DISCOVERY, "https://x.io/", Status.PASS, "入口可达"),
        Pos(Stage.INDEX_FILE, "https://x.io/llms.txt", Status.PASS, "真文件"),
        Pos(Stage.FULLTEXT, "https://x.io/llms-full.txt", Status.PASS, "真全文"),
        Pos(Stage.INDEX_LINKS, "https://x.io/llms.txt", Status.FAIL, "75/75 死"),
        Pos(Stage.MD_CHANNEL, "https://x.io/docs.md", Status.NOT_APPLICABLE, "未声明"),
        Pos(Stage.HUMAN_PATH, "https://x.io/pricing", Status.PASS, "6 页"),
    ]
    rows = rows_of("x.io", positions)
    assert len(rows) == 3
    assert {r.probe_url for r in rows} == {
        "https://x.io/",
        "https://x.io/llms.txt",
        "https://x.io/llms-full.txt",
    }


def test_naive_probe_set_is_exactly_four_positions() -> None:
    """§4.5:2396-2398：apex 与 www 上的两条根路径，仅此四个。"""
    emu = NaiveEmulator()
    sm = sitemap_for("acme.com")
    inside = [
        "https://acme.com/llms.txt",
        "https://acme.com/llms-full.txt",
        "https://www.acme.com/llms.txt",
        "https://www.acme.com/llms-full.txt",
    ]
    outside = [
        "https://acme.com/",
        "https://acme.com/docs/llms.txt",
        "https://docs.acme.com/llms.txt",
        "https://acme.com/llms.txt.bak",
        "https://acme.com/.well-known/llms.txt",
    ]
    assert all(emu._in_naive_set(u, sm) for u in inside)
    assert not any(emu._in_naive_set(u, sm) for u in outside)


# --------------------------------------------------------------------------- #
# A34（:4513）+ §4.5:2452-2461：minimax 的两个方向
# --------------------------------------------------------------------------- #


def test_minimax_naive_divergences() -> None:
    rows = rows_of("minimax.io", minimax_positions())
    div = {r.probe_url for r in rows if r.diverges}
    # 硬断言（两条都能从 corpus/feature-raw.json 复算）
    assert MINIMAX_SOFT404_URL in div  # 假阳
    assert MINIMAX_REAL_FILE_URL in div  # 假阴
    assert {r.direction for r in rows if r.diverges} == {"false_positive", "false_negative"}
    # 【待实测：apex 侧与 /llms-full.txt 的读数 corpus 没记（§4.5:2448），
    #  第 4b 步录完 fixture 后把 EXPECT_N 改成实际值并把这句改成 ==】
    assert len(div) >= 2
    assert naive.divergences(rows) == tuple(r for r in rows if r.diverges)


def test_minimax_false_positive_row_reads_200_as_adopted() -> None:
    row = by_url(rows_of("minimax.io", minimax_positions()), MINIMAX_SOFT404_URL)
    assert row.in_naive_probe_set is True
    assert row.naive_method == f"GET {MINIMAX_SOFT404_URL}，跟随跳转，只看最终状态码"
    assert row.naive_conclusion == "已采纳（200）"  # §2.6:1002 的字面量
    assert row.actual_conclusion == "软 404：与随机路径同为 384,052 字节、同一份外壳"
    assert row.direction == "false_positive"
    assert row.extra_requests == 1  # §4.5:2441 —— 多打的那 1 个是对照路径


def test_minimax_real_file_is_24kb_not_8_2kb() -> None:
    """卡点：minimax 的真文件统一为 platform.minimax.io/docs/llms.txt，**24 KB**。

    8.2 KB 是 gusto.com 那份被 Cloudflare 挡住的真文件（8,217 B，§4.5:2445），
    两者别串。
    """
    assert "24 KB" in MINIMAX_REAL_FILE_DETAIL
    assert "8.2 KB" not in MINIMAX_REAL_FILE_DETAIL
    row = by_url(rows_of("minimax.io", minimax_positions()), MINIMAX_REAL_FILE_URL)
    assert row.in_naive_probe_set is False
    assert row.naive_method == "不在朴素探测集内"
    assert row.naive_conclusion == "未采纳（没探这个位置）"  # §2.6:1002 的字面量
    assert row.actual_conclusion == MINIMAX_REAL_FILE_DETAIL
    assert row.direction == "false_negative"
    assert row.extra_requests == 2  # §4.5:2443 —— 子域 + /docs 子路径


def test_minimax_real_404_position_does_not_diverge() -> None:
    """platform.minimax.io/llms.txt 是真 404（NOT_APPLICABLE）。

    朴素没探过它、我们判「这个位置没做」—— 两边都没说它是通道，不算读错。
    """
    row = by_url(rows_of("minimax.io", minimax_positions()), "https://platform.minimax.io/llms.txt")
    assert row.diverges is False
    assert row.direction == "agree"


def test_minimax_discovery_rows_do_not_diverge() -> None:
    """入口发现段照样出行，但不参与「采纳 / 未采纳」的对错判定。

    照 §4.5:2412 原样写会把每个 DISCOVERY 位置都算成假阴（根路径永不在
    NAIVE_PATHS 里，而这些位置通常是 PASS），modal 的 `naive_divergences == 0`
    就永远不可能成立。裁决见 naive.rows() 里那段注释。
    """
    rows = rows_of("minimax.io", minimax_positions())
    disc = [r for r in rows if r.probe_url.endswith(".io/")]
    assert len(disc) == 2
    assert not any(r.diverges for r in disc)
    assert {r.direction for r in disc} == {"agree"}
    touched = by_url(rows, "https://www.minimax.io/")
    untouched = by_url(rows, "https://platform.minimax.io/")
    assert touched.naive_conclusion == naive.CONCLUSION_HOST_TOUCHED
    assert untouched.naive_conclusion == naive.CONCLUSION_HOST_UNTOUCHED
    assert all(r.why == naive.WHY_DISCOVERY for r in disc)


def test_minimax_headline_counts_only_diverging_rows() -> None:
    rows = rows_of("minimax.io", minimax_positions())
    n = len(naive.divergences(rows))
    assert naive.headline(rows) == f"只探根路径、不做对照探测的实现，会在你的 {n} 个位置上读错"


# --------------------------------------------------------------------------- #
# 第 14 步验收：modal 0 行 diverges 且文案翻正向
# --------------------------------------------------------------------------- #


def test_modal_zero_divergence_flips_copy() -> None:
    rows = rows_of("modal.com", modal_positions())
    assert naive.divergences(rows) == ()
    assert {r.direction for r in rows} == {"agree"}
    line = naive.headline(rows)
    assert line == "只探根路径、不做对照探测的实现，在这个站上没读错"
    assert naive.NAIVE_FIXED_PHRASE in line  # A34 要求所有报告都含这句
    assert "读错" in line


def test_modal_docs_copy_is_not_counted_as_false_negative() -> None:
    """modal.com/llms.txt 与 /docs/llms.txt 是同一份真文件。

    朴素实现在根路径上已经**正确地**拿到了它，对这个站的结论没错；/docs/ 下那份
    它没探到，但结论不变，所以不计读错 —— 否则「朴素实现在这个站上没读错」就是假话。
    """
    row = by_url(rows_of("modal.com", modal_positions()), "https://modal.com/docs/llms.txt")
    assert row.in_naive_probe_set is False
    assert row.naive_conclusion == "未采纳（没探这个位置）"
    assert row.diverges is False
    assert row.direction == "agree"
    assert row.why == naive.WHY_NAIVE_GOT_IT_RIGHT
    assert row.extra_requests == 1  # /docs 子路径，host 就是 apex，无对照探测


def test_suppression_needs_a_position_that_is_both_in_set_and_pass() -> None:
    """压制条件必须两条同时成立，缺一不可 —— 否则 minimax 的假阴会被吃掉。

    minimax 的 www/llms.txt 在朴素探测集内、朴素读数也是「已采纳」，但我们判 FAIL
    （软 404），所以它不算「朴素正确地找到了通道」。
    """
    emu = NaiveEmulator()
    assert emu._naive_found_real_file(sitemap_for("modal.com"), modal_positions()) is True
    assert emu._naive_found_real_file(sitemap_for("minimax.io"), minimax_positions()) is False


# --------------------------------------------------------------------------- #
# `_conclusions_differ` / `_verdict_from_status` / `_direction`
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("naive_c", "real", "expected"),
    [
        ("已采纳（200）", Status.PASS, False),
        ("已采纳（200）", Status.FAIL, True),  # 假阳
        ("已采纳（200）", Status.UNKNOWN, True),  # UNKNOWN 永不折算成 PASS
        ("已采纳（200）", Status.NOT_APPLICABLE, True),
        ("未采纳（没探这个位置）", Status.PASS, True),  # 假阴
        ("未采纳（没探这个位置）", Status.FAIL, False),
        ("未采纳（404）", Status.NOT_APPLICABLE, False),
        ("判不了（没有抓到响应）", Status.PASS, False),  # 既不说好也不说坏
        ("它从没往这个 host 打过请求", Status.PASS, False),
    ],
)
def test_conclusions_differ_truth_table(naive_c: str, real: Status, expected: bool) -> None:
    assert _conclusions_differ(naive_c, real, "随便什么实际结论") is expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, "已采纳（200）"),
        (204, "已采纳（204）"),
        (299, "已采纳（299）"),
        (301, "未采纳（301）"),  # 跟完跳转还是 3xx，朴素就当没有
        (403, "未采纳（403）"),
        (404, "未采纳（404）"),
        (429, "未采纳（429）"),
        (500, "未采纳（500）"),
        (None, "判不了（没有抓到响应）"),
    ],
)
def test_verdict_from_status_wording(status: int | None, expected: str) -> None:
    """朴素读数只看跟完跳转后的最终状态码。2xx 一律「已采纳」——软 404 的盲区就在这。"""
    assert NaiveEmulator()._verdict_from_status("https://acme.com/llms.txt", status) == expected


def test_rows_never_emit_over_report_direction() -> None:
    """`over_report`（resend.com/index.md，§4.5:2447）是 ⑤ .md 段的位置。

    按行来源它根本不进这张表，所以换算器永不产出这个方向。
    """
    for domain, positions in (
        ("minimax.io", minimax_positions()),
        ("modal.com", modal_positions()),
    ):
        assert "over_report" not in {r.direction for r in rows_of(domain, positions)}


# --------------------------------------------------------------------------- #
# §4.5 表里另外两条实测样本：口径落地后它们的真实归类
# --------------------------------------------------------------------------- #


def test_gusto_blocked_real_file_reads_as_agree_not_false_negative() -> None:
    """gusto.com/llms.txt：真文件 8,217 B，但对纯 HTTP 客户端一律 403。

    §4.5:2445 把它列在「假阴」一行，但 §4.5:2430-2436 给的可执行判据是
    「朴素说未采纳 **而真实 status 是 PASS**」—— 被 WAF 挡住的位置我们判 UNKNOWN，
    而 UNKNOWN 永不折算成 PASS（models.Status 的 docstring）。两处对不上时以可执行
    判据为准，见交付说明 spec_gaps。
    """
    url = "https://gusto.com/llms.txt"
    rows = rows_of(
        "gusto.com",
        [
            Pos(
                Stage.INDEX_FILE,
                url,
                Status.UNKNOWN,
                "真文件被 Cloudflare 挡住（浏览器过挑战后 200 text/plain 8,217 B）",
                evidence=ev(url, 403, "text/html"),
            )
        ],
    )
    row = by_url(rows, url)
    assert row.in_naive_probe_set is True
    assert row.naive_conclusion == "未采纳（403）"
    assert row.diverges is False
    assert row.direction == "agree"
    assert row.extra_requests == 0  # §4.5:2445 —— 改的是判定，不是请求


def test_deepgram_subdomain_is_outside_the_naive_probe_set() -> None:
    """developers.deepgram.com/llms-full.txt：与 llms.txt 同一个 md5（e7475c34…、73,878 B）。

    §4.5:2442 把它列成「朴素 200 → 有全文」的假阳，但 NAIVE_HOSTS 只有 apex 与 www
    两个 host（§4.5:2397），朴素实现根本不会去探 `developers.` 这个子域。按常量走，
    这一行落在探测集外；两处对不上，见交付说明 spec_gaps。
    """
    url = "https://developers.deepgram.com/llms-full.txt"
    row = by_url(
        rows_of(
            "deepgram.com",
            [
                Pos(
                    Stage.FULLTEXT,
                    url,
                    Status.FAIL,
                    "与 llms.txt 的 md5 相同（e7475c34…、73,878 B）—— 一个字正文都没有",
                    evidence=ev(url, 200),
                )
            ],
        ),
        url,
    )
    assert row.in_naive_probe_set is False
    assert row.naive_conclusion == "未采纳（没探这个位置）"
    assert row.direction == "agree"


# --------------------------------------------------------------------------- #
# 禁词表零命中
# --------------------------------------------------------------------------- #


def test_banned_words_zero_hit_on_every_generated_string() -> None:
    """本模块产出的每一个字符串都过一遍最小禁词表。"""
    texts: list[str] = []
    for domain, positions in (
        ("minimax.io", minimax_positions()),
        ("modal.com", modal_positions()),
    ):
        rows = rows_of(domain, positions)
        texts.append(naive.headline(rows))
        for r in rows:
            texts += [r.naive_method, r.naive_conclusion, r.why]
    for t in texts:
        assert naive.banned_word_hits(t) == (), t
    naive.assert_no_banned_words(*texts)


def test_banned_word_gate_actually_fires() -> None:
    assert naive.banned_word_hits("一切正常，恭喜") == ("恭喜", "一切正常")
    with pytest.raises(AssertionError, match="禁词"):
        naive.assert_no_banned_words("这个站一切正常")


def test_module_copy_never_says_any_off_the_shelf_tool() -> None:
    """§0.4:65 —— 报告里不许写「任何现成工具都会给出错的答案」。"""
    for text in (naive.HEADLINE_WRONG, naive.HEADLINE_CLEAN):
        assert naive.NAIVE_FIXED_PHRASE in text
        assert naive.banned_word_hits(text) == ()


# --------------------------------------------------------------------------- #
# 死链侧的朴素读数（§4.5:2463-2465，X07 unkey）
# --------------------------------------------------------------------------- #


def unkey_x07() -> HttpResponse:
    """X07（§8.2:3891）：unkey 的 billing 链路是 (308, 308, 404)。"""
    first = "https://unkey.com/docs/platform/workspaces/billing"
    mid = "https://unkey.com/docs/platform/workspaces/billing/"
    last = "https://unkey.com/docs/billing"
    return HttpResponse(
        url=first,
        final_url=last,
        status=404,
        headers={"content-type": "text/html"},
        body=b"<html><body>Page not found</body></html>",
        redirects=(RedirectHop(308, first, mid), RedirectHop(308, mid, last)),
    )


def test_naive_dead_count_uses_first_hop_status() -> None:
    resp = unkey_x07()
    assert naive.naive_first_hop_status(resp) == 308
    assert naive.naive_link_is_dead(naive.naive_first_hop_status(resp)) is False
    assert resp.status == 404  # 我们判 DEAD，朴素判 ALIVE —— 这就是对照面


def test_naive_first_hop_status_without_redirects() -> None:
    resp = HttpResponse(
        url="https://acme.com/gone",
        final_url="https://acme.com/gone",
        status=404,
        headers={},
        body=b"",
    )
    assert naive.naive_first_hop_status(resp) == 404
    assert naive.naive_first_hop_status(None) is None


@pytest.mark.parametrize(
    ("status", "dead"),
    [
        (None, False),
        (200, False),
        (308, False),
        (399, False),
        (400, True),
        (404, True),
        (503, True),
    ],
)
def test_naive_link_is_dead_threshold(status: int | None, dead: bool) -> None:
    """口径：首跳状态码 >= 400 即判死。没有状态码就判不死。"""
    assert naive.naive_link_is_dead(status) is dead


def test_naive_dead_count_counts_first_hops() -> None:
    assert naive.naive_dead_count([308, 404, 200, None, 500, 403]) == 3
    assert naive.naive_dead_count([]) == 0
