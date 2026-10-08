"""``fetch/normalize.py`` 的标记剥离必须是线性的 —— 而且输出与旧的正则实现逐字节相同。

## 缺陷

``visible_text`` / ``normalize_body`` / ``structural_fingerprint`` 用五条正则剥标记：
``<!--.*?-->``、``<(script|style|…)\\b[^>]*>.*?</\\1\\s*>``、``<(script|link|meta)\\b[^>]*/?>``、
``<!doctype[^>]*>``、``<[^>]+>``，外加 ``<title[^>]*>(.*?)</title>``。它们对「开了没关」的标记
都是平方级：每个没闭合的开头都会把整个剩余输入再扫一遍。100 KB 的 ``<script>`` × 12500 要 2.3 s、
``<!--`` × 25000 要 5.8 s、``<link`` × 20000 要 5.3 s；1 MB 的 ``<`` 要几分钟（评审实测 211 s）。
而 ``Fetcher.fetch`` 对**每一个**响应都会调 ``finalize_response`` → ``normalize_body`` →
``visible_text``，所以一个恶意（或者只是坏掉的）页面就能让一次体检卡住。

## 这组测试怎么证明「没改行为」

旧实现原样留在本文件里当**对照（oracle）**，与新实现比：

1. 全部冻结响应（真实站点的正文，含好几 MB 的 llms-full）；
2. 两万篇由「标记词汇表」随机拼出来的文档 —— 词汇表专挑会让正则和手写扫描器分歧的写法：没闭合的
   ``<script`` / ``<!--``、``<>``、``<<>``、``<!-->``、``</SCRIPT >``、``<ſcript>``
   （``re.IGNORECASE`` 把 ``ſ`` 当成 ``s``，而反向引用 ``\\1`` 不这样比）、``<svg-icon>``
   （``\\b`` 在 ``-`` 前成立）、嵌在开标签里的 ``<script``；
3. 一组逐条写出来的边角。

线性靠下面的计时守卫：先拿 100 KB 探一下（平方级的实现在这儿就要 2-6 s，不必等 1 MB 跑完），
再上 1 MB。
"""

from __future__ import annotations

import hashlib
import random
import re
import time
import unicodedata

import pytest

from geo_audit.fetch import normalize as nm
from geo_audit.fixtures import FixtureStore

# ── 旧实现（逐字保留，当对照）─────────────────────────────────────────────────
_OLD_BLOCK_RE = re.compile(
    r"<(script|style|noscript|svg|template|iframe)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_OLD_SELF_CLOSING_NOISE_RE = re.compile(r"<(script|link|meta)\b[^>]*/?>", re.IGNORECASE)
_OLD_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_OLD_DOCTYPE_RE = re.compile(r"<!doctype[^>]*>", re.IGNORECASE)
_OLD_TAG_RE = re.compile(r"<[^>]+>")
_OLD_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _old_visible_text(body: str) -> str:
    text = nm.strip_bom(body)
    text = _OLD_COMMENT_RE.sub(" ", text)
    text = _OLD_BLOCK_RE.sub(" ", text)
    text = _OLD_SELF_CLOSING_NOISE_RE.sub(" ", text)
    text = _OLD_DOCTYPE_RE.sub(" ", text)
    text = _OLD_TAG_RE.sub(" ", text)
    for entity, repl in nm._ENTITIES.items():
        text = text.replace(entity, repl)
    text = unicodedata.normalize("NFKC", text)
    return nm._WS_RE.sub(" ", text).strip()


def _old_normalize_body(body: str) -> str:
    text = _old_visible_text(body).lower()
    for pattern in nm._VOLATILE_PATTERNS:
        text = pattern.sub(" ", text)
    return nm._WS_RE.sub(" ", text).strip()


def _old_structural_fingerprint(body: str) -> tuple[str, int]:
    stripped = _OLD_COMMENT_RE.sub(" ", body)
    stripped = _OLD_BLOCK_RE.sub(" ", stripped)
    tags = [f"{slash}{name.lower()}" for slash, name in nm._TAG_NAME_RE.findall(stripped)]
    tokens: list[str] = []
    for raw in nm._ID_CLASS_RE.findall(stripped[:200000]):
        for tok in raw.split():
            cleaned = tok
            for pattern in nm._VOLATILE_PATTERNS:
                cleaned = pattern.sub("", cleaned)
            if cleaned and not cleaned.isdigit():
                tokens.append(cleaned.lower())
    title = _OLD_TITLE_RE.search(body)
    title_text = nm._WS_RE.sub(" ", (title.group(1) if title else "")).strip().lower()
    skeleton = "|".join(tags[:4000]) + "#" + "|".join(sorted(set(tokens))[:400]) + "#" + title_text
    return hashlib.sha256(skeleton.encode("utf-8")).hexdigest(), len(tags)


def _same(body: str) -> None:
    assert nm.visible_text(body) == _old_visible_text(body), body[:200]
    assert nm.normalize_body(body) == _old_normalize_body(body), body[:200]
    assert nm.structural_fingerprint(body) == _old_structural_fingerprint(body), body[:200]
    old_title = _OLD_TITLE_RE.search(body)
    assert nm._first_title(body) == (old_title.group(1) if old_title else None), body[:200]


# ── 1. 全部冻结响应 ──────────────────────────────────────────────────────────
def test_identical_output_on_every_frozen_response() -> None:
    store = FixtureStore.default()
    urls = list(store.snapshots())
    assert len(urls) >= 1000, f"语料里只剩 {len(urls)} 条快照，这条对照失去意义"
    for url in urls:
        _same(store.stored_body(url).decode("utf-8", "replace"))


# ── 2. 随机文档 ──────────────────────────────────────────────────────────────
_TOKENS = [
    "<!--", "-->", "<!---->", "<!-->", "<!--x-->",
    "<script>", "<script", "<script ", "</script>", "</SCRIPT >", "</script\n>", "</script",
    "<style>", "</style>", "<svg", "<svg>", "</svg>", "<noscript>", "</noscript>",
    "<template>", "</template>", "<iframe src=x>", "</iframe>",
    "<link rel=a>", "<link", "<meta charset=x/>", "<meta", "<!doctype html>", "<!DOCTYPE",
    "<!doctype",
    "<title>", "</title>", "<TITLE >", "</TITLE>", "<titlex>", "<title",
    "<", ">", "<>", "<<", ">>", "< >", "<a href=\">\">", "<a href='x'>", "</a>", "<p>", "<br/>",
    "text", " ", "  ", "\n", "\t", "&amp;", "&lt;", "&nbsp;", "&#39;", "&quot;", "é", "x" * 5,
    "ſ", "K", "<ſcript>", "</ſcript>", "<Script>", "<scripts>",
    "<svg-icon>", "</svg-icon>", "<style-x>", " ", " ", "﻿", "　",
    "id=\"a b\"", "class='c d'", "<div id=\"x\" class=\"y z\">", "2026-10-08T10:00:00Z",
    "01234567" + "89abcdef" * 2, "?v=123",
]  # fmt: skip


def _fuzz_document(rng: random.Random) -> str:
    return "".join(rng.choice(_TOKENS) for _ in range(rng.randint(1, 60)))


def test_identical_output_on_twenty_thousand_fuzzed_documents() -> None:
    rng = random.Random(20261008)
    for _ in range(20000):
        _same(_fuzz_document(rng))


@pytest.mark.parametrize(
    "body",
    [
        "",
        "plain text",
        "<>",
        "<<>",
        "<<",
        "a<b",
        "<a",
        "<!-->x",
        "<!--->x",  # 开头的 ``--`` 不能同时算作结尾 ``-->`` 的一部分
        "a<!--->b-->c",
        "<!---->x",
        "<!-- a --> b <!-- c",
        "<!-- a --> b <!-- c --> d",
        "<script>a</script>b<script>c",
        "<script>a<style>b</style>c",  # 没闭合的 script 里面又有一个闭合的 style
        "<script>a<style>b",  # 两种都没闭合
        "<style>x</style><script>y</script>z",
        "<SCRIPT>x</script>",
        "<script>x</SCRIPT  >y",
        "<script>x</script\n>y",
        "<script>x</script",
        "<script>x</scripts>y</script>",
        "<scripts>x</script>",  # \b 不成立：不是 script 开标签
        "<svg-icon>x</svg>",  # \b 在 - 前成立：当成 svg 开标签
        "<svg-icon>x</svg-icon>y",
        "<ſcript>x</script>y",  # re.I：ſ ≡ s
        "<script>x</ſcript>y",
        "<script <script>x</script>y",  # 开标签里嵌着另一个 <script
        "<script <script x>y",
        "<link a>b<meta c/>d<script e>f",
        "<link a b<meta c>d",
        "<!doctype html><html>x",
        "<!DOCTYPE>x<!doctype",
        "<title>T</title>",
        "<title>T",
        "<title><title>A</title>",
        "<titlex>T</title>",
        "<TITLE >A</TITLE>x<title>B</title>",
        '<a href=">">x',
        "&amp;&lt;b&gt;&nbsp;&#39;&quot;&apos;",
        "﻿￾<p>bom</p>",
        "x" * 50 + "<" + "y" * 50,
    ],
)
def test_identical_output_on_hand_written_edge_cases(body: str) -> None:
    _same(body)


# ── 3. 计时守卫：线性 ────────────────────────────────────────────────────────
_PATHOLOGICAL = {
    "unclosed-script": lambda n: "<script>" * (n // 8),
    "unclosed-comment": lambda n: "<!--" * (n // 4),
    "lone-lt": lambda n: "<" * n,
    "unclosed-style": lambda n: "<style>" * (n // 7),
    "unclosed-svg": lambda n: "<svg" * (n // 4),
    "unclosed-link": lambda n: "<link" * (n // 5),
    "unclosed-meta": lambda n: "<meta" * (n // 5),
    "unclosed-doctype": lambda n: "<!doctype" * (n // 9),
    "unclosed-title": lambda n: "<title>" * (n // 7),
    "open-tags-no-gt": lambda n: "<a" * (n // 2),
    "mixed-unclosed": lambda n: "<script <style <svg <!-- <link " * (n // 33),
    "script-in-open-tag": lambda n: "<script " * (n // 8) + ">",
}


@pytest.mark.parametrize("name", list(_PATHOLOGICAL))
def test_stripping_hostile_input_is_linear(name: str) -> None:
    make = _PATHOLOGICAL[name]
    # 先探 100 KB：旧的正则实现在这儿就是 0.5-6 s，平方级的回归不用等 1 MB 跑完才红
    for size, limit in ((100_000, 0.4), (1_000_000, 3.0)):
        body = make(size)
        for fn in (nm.visible_text, nm.normalize_body, nm.structural_fingerprint):
            t = time.perf_counter()
            fn(body)
            elapsed = time.perf_counter() - t
            assert elapsed < limit, f"{fn.__name__}({name}, {size}) {elapsed:.2f}s"


def test_a_fetch_of_a_hostile_page_is_not_stalled() -> None:
    """评审的原始复现：``Fetcher.fetch`` 一个 100 KB 的恶意 200 页，旧代码 4.5 s（``<script>``）
    / 11 s（``<!--``）。走真实的抓取路径（含 ``finalize_response``）。"""
    import types

    import httpx

    import geo_audit.fetch.client as client_mod
    import geo_audit.fetch.ratelimit as ratelimit_mod
    from geo_audit.fetch.cache import HttpCache
    from geo_audit.fetch.client import Fetcher, FetcherConfig
    from geo_audit.fetch.ratelimit import DomainLimiter

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<!--" * 25000)

    fake = types.SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=lambda s: None)
    saved = (ratelimit_mod.time, client_mod.time)
    ratelimit_mod.time = fake  # type: ignore[assignment]
    client_mod.time = fake  # type: ignore[assignment]
    try:
        f = Fetcher(
            FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
            HttpCache(":memory:"),
            DomainLimiter(2.0),
            transport=httpx.MockTransport(handler),
        )
        t = time.perf_counter()
        resp = f.fetch("https://x.test/page")
        elapsed = time.perf_counter() - t
    finally:
        ratelimit_mod.time, client_mod.time = saved  # type: ignore[assignment]
    assert resp.status == 200 and resp.norm_sha256 is not None
    assert elapsed < 0.5, f"{elapsed:.2f}s"
