"""``fetch/normalize.py`` 的标记剥离必须是线性的 —— 而且输出与旧的正则实现逐字节相同。

## 缺陷

``visible_text`` / ``normalize_body`` / ``structural_fingerprint`` 用五条正则剥标记：
``<!--.*?-->``、``<(script|style|…)\\b[^>]*>.*?</\\1\\s*>``、``<(script|link|meta)\\b[^>]*/?>``、
``<!doctype[^>]*>``、``<[^>]+>``，外加 ``<title[^>]*>(.*?)</title>``。它们对「开了没关」的标记
都是平方级：每个没闭合的开头都会把整个剩余输入再扫一遍。100 KB 的 ``<script>`` × 12500 要 2.3 s、
``<!--`` × 25000 要 5.8 s、``<link`` × 20000 要 5.3 s；1 MB 的 ``<`` 要几分钟（评审实测 211 s）。
``Fetcher.fetch`` 对每一个读完整正文的响应都会调 ``finalize_response`` → ``norm_sha256`` →
``visible_text``（只查存活的探测、被截断/空的正文、缓存命中除外），检查层还会对同一份正文再算一遍，
所以一个恶意（或者只是坏掉的）页面就能让一次体检卡住。

范围：这里只管**标记剥离**。同一条路径上还有别的卡顿（CPython 3.11 的 NFKC 对一长串
组合符是平方级），它不在本文件的保证里；``fetch/jsrender.py`` 的标签信号见
``test_jsrender_linear.py``。

## 这组测试怎么证明「没改行为」

旧实现原样留在本文件里当**对照（oracle）**，与新实现比 —— 五个阶段各自比，三个公开函数也比：

1. 全部冻结响应（真实站点的正文，最大一条约 1 MB）；
2. 两万篇由「标记词汇表」随机拼出来的文档 —— 词汇表专挑会让正则和手写扫描器分歧的写法：没闭合的
   ``<script`` / ``<!--``、``<>``、``<<>``、``<!-->``、``</SCRIPT >``、``<ſcript>`` /
   ``<scrıpt>``（``re.IGNORECASE`` 把 ``ſ`` 当成 ``s``、``ı`` 当成 ``i``，
   而反向引用 ``\\1`` 不这样比）、``<svg-icon>``（``\\b`` 在 ``-`` 前成立）、
   嵌在开标签里的 ``<script``、``</title >``；
3. 两万篇由「六个块标签名的全部 1404 种合法拼写」拼出来的文档 —— 专打 ``unclosed`` 的键；
4. 一组逐条写出来的边角；
5. 超大输入：前面垫 100 KB / 1 MiB / 4 MiB 的普通文字再接一个标记，以及单个超过 100 KB / 4 MiB 的
   注释、标签、块、标题 —— 证明实现里没有藏着任何「只看前 N 字节」的上限。

线性靠计时守卫：每个病态家族先探 100 KB（多数平方级的实现在这儿就已经超限，不必等大的跑完），
再上 1 MB 和 4 MB。4 MB 这一档是给「每次只是 memchr 扫一遍」的平方级准备的 —— 它们在 1 MB 上
只要 1-2 s，躲得过 1 MB 的线。
"""

from __future__ import annotations

import hashlib
import itertools
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


def _same_stages(text: str) -> None:
    """五个阶段各自与它的旧正则比。比最终输出严：最终输出会把多出来的空格折叠掉，一个阶段
    「少吃一个标签、多吐一个空格」在那里是看不见的。"""
    assert nm._strip_comments(text) == _OLD_COMMENT_RE.sub(" ", text), ("comments", text[:200])
    assert nm._strip_blocks(text) == _OLD_BLOCK_RE.sub(" ", text), ("blocks", text[:200])
    noise = nm._strip_open_tags(text, nm._NOISE_OPEN_RE)
    assert noise == _OLD_SELF_CLOSING_NOISE_RE.sub(" ", text), ("noise", text[:200])
    doctype = nm._strip_open_tags(text, nm._DOCTYPE_OPEN_RE)
    assert doctype == _OLD_DOCTYPE_RE.sub(" ", text), ("doctype", text[:200])
    assert nm._strip_tags(text) == _OLD_TAG_RE.sub(" ", text), ("tags", text[:200])


def _same_title(body: str) -> None:
    old_title = _OLD_TITLE_RE.search(body)
    assert nm._first_title(body) == (old_title.group(1) if old_title else None), body[:200]


def _same(body: str) -> None:
    _same_stages(body)
    assert nm.visible_text(body) == _old_visible_text(body), body[:200]
    assert nm.normalize_body(body) == _old_normalize_body(body), body[:200]
    assert nm.structural_fingerprint(body) == _old_structural_fingerprint(body), body[:200]
    _same_title(body)


def _same_big(body: str) -> None:
    """超大输入用：不算 ``normalize_body``。它在 ``visible_text`` 之上只多了一组与剥标记无关的
    正则，对 4 MiB 的文字要多花好几秒，却不会多证明什么。"""
    _same_stages(body)
    assert nm.visible_text(body) == _old_visible_text(body), body[:200]
    assert nm.structural_fingerprint(body) == _old_structural_fingerprint(body), body[:200]
    _same_title(body)


# ── 1. 全部冻结响应 ──────────────────────────────────────────────────────────
def test_identical_output_on_every_frozen_response() -> None:
    store = FixtureStore.default()
    urls = list(store.snapshots())
    assert len(urls) >= 1000, f"语料里只剩 {len(urls)} 条快照，这条对照失去意义"
    for url in urls:
        _same(store.stored_body(url).decode("utf-8", "replace"))


# ── 2. 随机文档（标记词汇表）─────────────────────────────────────────────────
_TOKENS = [
    "<!--", "-->", "<!---->", "<!-->", "<!--x-->",
    "<script>", "<script", "<script ", "</script>", "</SCRIPT >", "</script\n>", "</script",
    "<style>", "</style>", "<svg", "<svg>", "</svg>", "<noscript>", "</noscript>",
    "<template>", "</template>", "<iframe src=x>", "</iframe>",
    "<link rel=a>", "<link", "<meta charset=x/>", "<meta", "<!doctype html>", "<!DOCTYPE",
    "<!doctype",
    "<title>", "</title>", "<TITLE >", "</TITLE>", "<titlex>", "<title",
    "</title >", "</title\n>", "<title\n>",
    "<", ">", "<>", "<<", ">>", "< >", "<a href=\">\">", "<a href='x'>", "</a>", "<p>", "<br/>",
    "text", " ", "  ", "\n", "\t", "&amp;", "&lt;", "&nbsp;", "&#39;", "&quot;", "é", "x" * 5,
    "ſ", "K", "<ſcript>", "</ſcript>", "<Script>", "<scripts>",
    "ı", "İ", "<scrıpt>", "</scrıpt>", "<scrIpt>", "</scrIpt>",
    "<İframe>", "<ıframe>", "</İframe>", "</ıframe>",
    "<svg-icon>", "</svg-icon>", "<style-x>", " ", " ", "﻿", "　",
    "id=\"a b\"", "class='c d'", "<div id=\"x\" class=\"y z\">", "2026-10-08T10:00:00Z",
    "01234567" + "89abcdef" * 2, "?v=123",
]  # fmt: skip


def _fuzz_document(rng: random.Random) -> str:
    return "".join(rng.choice(_TOKENS) for _ in range(rng.randint(1, 60)))


def test_identical_output_on_twenty_thousand_fuzzed_documents() -> None:
    rng = random.Random(20261008)
    for _ in range(20000):
        _same(_fuzz_document(rng))


# ── 3. 随机文档（块标签名的全部合法拼写）─────────────────────────────────────
_BLOCK_NAMES = ("script", "style", "noscript", "svg", "template", "iframe")


def _spellings(name: str) -> list[str]:
    """``name`` 的每一种拼写，只要 ``re.IGNORECASE`` 还把它当成这个名字：每个字母大小写任意，
    ``s`` 还可以是 ``ſ``（U+017F），``i`` 还可以是 ``ı``（U+0131）或 ``İ``（U+0130）。"""
    extra = {"s": "ſ", "i": "ıİ"}
    letters = [sorted({c, c.upper(), *extra.get(c, "")}) for c in name]
    return ["".join(p) for p in itertools.product(*letters)]


_SPELLINGS = {name: _spellings(name) for name in _BLOCK_NAMES}
_ALL_SPELLINGS = [sp for name in _BLOCK_NAMES for sp in _SPELLINGS[name]]


def _spelling_document(rng: random.Random) -> str:
    """同一个名字的两三种拼写互相当开标签和闭标签 —— 键对不对，全看它们碰不碰得到一起。"""
    name = rng.choice(_BLOCK_NAMES)
    pool = [rng.choice(_SPELLINGS[name]) for _ in range(rng.randint(2, 3))]
    if rng.random() < 0.3:
        pool.append(rng.choice(_ALL_SPELLINGS))
    parts: list[str] = []
    for _ in range(rng.randint(1, 14)):
        sp = rng.choice(pool)
        kind = rng.randrange(7)
        if kind == 0:
            parts.append(f"<{sp}>")
        elif kind == 1:
            parts.append(f"<{sp}")
        elif kind == 2:
            parts.append(f"</{sp}>")
        elif kind == 3:
            parts.append(f"</{sp} >")
        elif kind == 4:
            parts.append(f"<{sp} a=1>")
        else:
            parts.append(rng.choice(["x", " ", "<", ">", "<!--", "-->"]))
    return "".join(parts)


def test_identical_output_on_twenty_thousand_documents_of_block_spellings() -> None:
    rng = random.Random(20261009)
    for _ in range(20000):
        _same(_spelling_document(rng))


def test_block_spelling_universe_is_what_the_unclosed_key_assumes() -> None:
    """``unclosed`` 的键是「拼写 ``.lower()``」。这条测试把键靠的前提逐条写成断言：

    * 合法拼写一共 1404 种、键 20 个（没有这个量级，``unclosed`` 的剪枝就不值得）；
    * 每种拼写都被开标签的正则认出来，而且用同样的拼写就能被旧正则闭合；
    * 同一个键的所有拼写，被**同一批**闭标签闭合（键只会把等价的拼写并在一起）。

    闭标签只需要在同一个名字的拼写里挑：能被 ``\\1`` 认作同一个开标签的串，逐字符 ``lower()``
    之后必须相等，而这六个名字里的字符只有这几类大小写等价。
    """
    assert len(_ALL_SPELLINGS) == 1404
    assert len({sp.lower() for sp in _ALL_SPELLINGS}) == 20
    for sp in _ALL_SPELLINGS:
        assert nm._BLOCK_OPEN_RE.match(f"<{sp}>"), sp
        assert _OLD_BLOCK_RE.fullmatch(f"<{sp}>x</{sp}>"), sp
    for name in _BLOCK_NAMES:
        closers_of: dict[str, frozenset[str]] = {}
        for opening in _SPELLINGS[name]:
            closed_by = frozenset(
                c for c in _SPELLINGS[name] if _OLD_BLOCK_RE.fullmatch(f"<{opening}>x</{c}>")
            )
            assert closed_by, opening
            assert closers_of.setdefault(opening.lower(), closed_by) == closed_by, opening


def test_backreference_premises_of_the_unclosed_key() -> None:
    """键为什么必须是 ``str.lower()``：靠 ``re`` 的这几条行为。哪天 CPython 改了，这里先红，
    而不是静悄悄地输出不同的文本。"""

    def closes(opening: str, closing: str) -> bool:
        return _OLD_BLOCK_RE.fullmatch(f"<{opening}>x</{closing}>") is not None

    assert closes("İframe", "iframe")  # ``\1`` 把 İ 小写成 i ……
    assert not closes("ıframe", "iframe")  # …… 但 ı 不是 i
    assert not closes("ſcript", "script")  # ſ 不是 s
    assert closes("ſcript", "ſcript")
    # 字面量上 ``re.IGNORECASE`` 则把它们当成同一个字母：开标签认得 ſ 和 ı
    assert nm._BLOCK_OPEN_RE.match("<ſcript>")
    assert nm._BLOCK_OPEN_RE.match("<scrıpt>")
    # 所以键不能是 casefold()（它把 ſ 折成 s）
    assert "ſ".casefold() == "s"
    assert "ſ".lower() != "s"
    assert "ı".lower() != "i"


# ── 4. 逐条写出来的边角 ──────────────────────────────────────────────────────
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
        "<ſcript><script>x</script>",  # ſ 与 s 是两个反向引用：键不能用 casefold()
        "<script><ſcript>x</ſcript>",
        "<scrıpt><scrIpt>x</scrIpt>",  # ı 与 I 同理：键不能把 ı 折成 i
        "<scrIpt><scrıpt>x</scrıpt>",
        "<İframe>x</iframe>y",  # \1 把 İ 当成 i：能闭合
        "<ıframe>x</iframe>y",  # ……但 ı 不是 i：不能闭合
        "<ıframe>x</ıframe>y",
        "<iframe>x</İframe>y",
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
        "<title>T</title >x</title>",  # ``</title >`` 不是闭合标签
        "<title\n>T</title>",
        "<title>T</TITLE>",
        "<TITLE>a</title>",
        '<a href=">">x',
        "&amp;&lt;b&gt;&nbsp;&#39;&quot;&apos;",
        "﻿￾<p>bom</p>",
        "x" * 50 + "<" + "y" * 50,
    ],
)
def test_identical_output_on_hand_written_edge_cases(body: str) -> None:
    _same(body)


# ── 5. 超大输入：没有藏着「只看前 N 字节」的上限 ─────────────────────────────
def _filler(n: int) -> str:
    return "ab " * (n // 3) + "a" * (n % 3)


_AFTER_FILLER = {
    "comment": "<!-- c -->y",
    "tag": "<b>y</b>",
    "block": "<script>evil</script>y",
    "title": "<title>T</title>",
    "noise-tag": "<link rel=a>y",
    "doctype": "<!doctype html>y",
}


@pytest.mark.parametrize("construct", list(_AFTER_FILLER))
@pytest.mark.parametrize("size", [100_001, 1_048_577, 4_194_305])
def test_a_construct_after_a_long_prefix_is_still_recognised(size: int, construct: str) -> None:
    """前面垫的字数刚好越过 10 万、1 MiB、4 MiB：任何「只在前 N 字节里找」的上限都会在这儿露馅。"""
    _same_big(_filler(size) + _AFTER_FILLER[construct])


_LONG_CONSTRUCT = {
    "comment": lambda n: "<!-- " + "x" * n + " -->y",
    "tag": lambda n: "<a " + "x" * n + ">y",
    "block": lambda n: "<script>" + "x" * n + "</script>y",
    "title": lambda n: "<title>" + "x" * n + "</title>",
    "noise-tag": lambda n: "<link a=" + "x" * n + ">y",
    "doctype": lambda n: "<!doctype " + "x" * n + ">y",
}


@pytest.mark.parametrize("construct", list(_LONG_CONSTRUCT))
@pytest.mark.parametrize("size", [100_001, 4_194_305])
def test_a_single_very_long_construct_is_still_recognised(size: int, construct: str) -> None:
    """单个结构本身就超过 10 万 / 4 MiB 字节：不能因为「太长」就当成没闭合。"""
    _same_big(_LONG_CONSTRUCT[construct](size))


# ── 6. 计时守卫：线性 ────────────────────────────────────────────────────────
def _every_spelling_unclosed(n: int) -> str:
    """1404 种拼写的开标签各自带着 ``>``，却谁也没有闭标签：新实现只需要对 20 个键各扫一遍，
    把键换成原样拼写（或者换成别的更碎的东西）就是 1404 遍。后面的 ``</`` 让每一遍都不便宜。"""
    head = "".join(f"<{sp}>" for sp in _ALL_SPELLINGS)
    return head + "</" * max(0, (n - len(head)) // 2)


_PATHOLOGICAL = {
    "unclosed-script": lambda n: "<script>" * (n // 8),
    "unclosed-comment": lambda n: "<!--" * (n // 4),
    "lone-lt": lambda n: "<" * n,
    "lone-lt-then-gt": lambda n: "<" * n + ">",
    "unclosed-style": lambda n: "<style>" * (n // 7),
    "unclosed-svg": lambda n: "<svg" * (n // 4),
    "unclosed-link": lambda n: "<link" * (n // 5),
    "unclosed-meta": lambda n: "<meta" * (n // 5),
    "unclosed-doctype": lambda n: "<!doctype" * (n // 9),
    "unclosed-title": lambda n: "<title>" * (n // 7),
    "title-open-no-gt": lambda n: "<title" * (n // 6),
    "open-tags-no-gt": lambda n: "<a" * (n // 2),
    "mixed-unclosed": lambda n: "<script <style <svg <!-- <link " * (n // 33),
    "script-in-open-tag": lambda n: "<script " * (n // 8) + ">",
    # 一个没闭合的 <style> 夹在一串成功的 <script> 之间：成功不能清掉「style 没有闭标签」的记录
    "unclosed-between-closed": lambda n: "<style><script>x</script>" * (n // 25),
    "every-spelling-unclosed": _every_spelling_unclosed,
}

# (输入字节数, 每次调用的秒数上限)。上限留的是 10 倍以上的余量：这里要抓的是平方级，不是常数。
_LADDER = ((100_000, 0.4), (1_000_000, 3.0), (4_000_000, 8.0))


@pytest.mark.parametrize("name", list(_PATHOLOGICAL))
def test_stripping_hostile_input_is_linear(name: str) -> None:
    make = _PATHOLOGICAL[name]
    for size, limit in _LADDER:
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
        with Fetcher(
            FetcherConfig(contact="ci@geo-audit.invalid", interval=2.0),
            HttpCache(":memory:"),
            DomainLimiter(2.0),
            transport=httpx.MockTransport(handler),
        ) as f:
            t = time.perf_counter()
            resp = f.fetch("https://x.test/page")
            elapsed = time.perf_counter() - t
    finally:
        ratelimit_mod.time, client_mod.time = saved  # type: ignore[assignment]
    assert resp.status == 200 and resp.norm_sha256 is not None
    assert elapsed < 0.5, f"{elapsed:.2f}s"
