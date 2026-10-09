"""``checks/ai_path.py`` 里 ``Link`` 响应头那条正则必须是线性的 —— 而且结果与旧正则完全相同。

## 缺陷

``detect_md_signal_from_page`` 用一条正则在 ``Link`` 响应头里找「markdown 替代版本」::

    <(?P<url>[^>]+)>\\s*;[^,]*rel\\s*=\\s*"?alternate"?[^,]*type\\s*=\\s*"?text/markdown"?

响应头是被体检的站点自己发的，httpcore 允许整个响应头块到 100 KiB（``MAX_INCOMPLETE_EVENT_SIZE``）。
这条正则对 ``<a>; rel=alternate `` 重复 N 次是 O(N^3)：25,000 字符二十秒以上（空闲的笔记本 22 s，
忙的机器上量到 59 s），50,000 字符超过 60 s；对 ``<`` 重复 N 次是 O(N^2)：100,000 字符十几秒。
每个 ``<`` 都把整个头再扫一遍，每个
``rel=alternate`` 又把它后面的头再扫一遍找 ``type=``。

## 这组测试怎么证明「没改行为」

旧正则原样留在本文件里当**对照（oracle）**，与新函数 ``_alternate_markdown_url`` 比 ——
返回的 ``url`` 组（或 ``None``）：

1. 全部冻结响应里的每一个响应头值（含 192 个真实的 ``Link`` 头，其中 43 个命中），每个 ``Link``
   头再做大小写、去掉首个 ``<``、前面垫一段、逗号换分号等变体；
2. 十万个由「标记词汇表」随机拼出来的头（含 ``\\s`` 接受的每一个空白字符、``K`` 开尔文符号、
   ``ſ`` / ``ı``），四万个按结构拼出来的 ``Link`` 头（一到四个条目、参数顺序随机、随机改 0-3 处，
   约四成一处不改；参数里有差一点的写法：单引号、``:`` 代替 ``=``、``rev=``、``text/x-markdown``），
   两组都断言各种结果出现了足够多次 —— fuzz 不是空转；
3. 穷举：一个 8 词字母表上所有不超过 6 个词的序列；8 条命中或差一点命中的种子头的每一种「改一个
   词」，其中两条的每一种「改两个词」；
4. 一组逐条写出来的边角：``<>``、条目之间的逗号、``type`` 在 ``rel`` 之前、``rel`` 与
   ``type`` 被逗号隔开、每个 ``\\s`` 位置上的每一种空白、大小写、嵌套的 ``<``；
5. 大输入：几十万个「走不通」的条目（逗号隔开，旧正则对它们也是线性的）再接一个匹配的条目。

## 它证明不了什么

* 大输入只覆盖上面列出的形状，证明不了「实现里不存在任何上限」；
* 计时守卫有两道。**增长倍数**：同一个家族，最大一档 / 四分之一大小的耗时（线性约 4，平方约
  16；用 CPU 时间量，不受 CPU 被别的进程抢走的影响），但四分之一大小那一档快于 30 ms 的家族
  （大部分）不看倍数。**绝对上限**：每 MB 10 s 再加 0.5 s，放得很宽；「输出不变但平方」的
  写法大多是被它（或大输入对照测试的 ``SIGALRM`` 期限）杀掉的。靠计时抓不到常数级的退化；
  Windows 上没有 ``SIGALRM``，大输入的对照测试遇到平方级退化会挂住而不是失败（POSIX 的几格会先红）。
"""

from __future__ import annotations

import contextlib
import random
import re
import signal
import sys
import time
from collections.abc import Callable, Iterator

import pytest

from geo_audit.checks import ai_path as ap
from geo_audit.fixtures import FixtureStore
from geo_audit.models import HttpResponse

#: ``\s`` 接受的每一个字符（枚举出来的，不是手挑的）；用 chr() 构造，不在源码里打不可见字符
_ALL_WS = [c for c in map(chr, range(0x10000)) if re.fullmatch(r"\s", c)]
_KELVIN = chr(0x212A)  # ``K``：re.I 下与 ``k`` 等价（``markdown`` 里有一个 k）
_LONG_S = chr(0x17F)  # ``ſ``
_DOTLESS_I = chr(0x131)  # ``ı``


def test_the_whitespace_alphabet_is_enumerated_not_listed_by_hand() -> None:
    assert len(_ALL_WS) >= 25
    for must in (" ", "\t", "\n", "\x1f", chr(0xA0), chr(0x2028), chr(0x3000)):
        assert must in _ALL_WS, hex(ord(must))


# ── 旧实现（逐字保留，当对照）─────────────────────────────────────────────────
_OLD_LINK_HEADER_RE = re.compile(
    r"<(?P<url>[^>]+)>\s*;[^,]*rel\s*=\s*\"?alternate\"?[^,]*type\s*=\s*\"?text/markdown\"?", re.I
)


def _old_url(header: str) -> str | None:
    m = _OLD_LINK_HEADER_RE.search(header)
    return m.group("url") if m else None


@contextlib.contextmanager
def _deadline(seconds: float) -> Iterator[None]:
    """只在有 ``SIGALRM`` 的平台上生效（Windows 上什么也不做）：大输入上一旦出现平方级退化，
    对照测试会挂几个小时，而不是失败；有了期限它就在 ``seconds`` 秒后报错。"""
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def _expired(signum: int, frame: object) -> None:
        raise TimeoutError(f"{seconds:.0f}s 内没有答案：超线性退化？")

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _same(header: str) -> None:
    assert ap._alternate_markdown_url(header) == _old_url(header), header[:300]


#: 一个匹配的条目：之后各处拼进去
_GOOD = '<https://x.test/a.md>; rel="alternate"; type="text/markdown"'


# ── 1. 全部冻结响应 ──────────────────────────────────────────────────────────
def _variants(header: str) -> list[str]:
    return [
        header,
        header.upper(),
        header.lower(),
        header.swapcase(),
        header.replace("<", "", 1),
        header.replace(",", ";"),
        header.replace(";", ","),
        header.replace("rel", "Rel ", 1).replace("=", " = ", 1),
        "<z>; " + header,
        "<z>;, " + header,
        header + ", " + header,
    ]


def test_identical_results_on_every_frozen_response_header() -> None:
    store = FixtureStore.default()
    keys = list(store.snapshots())
    assert len(keys) >= 1000, f"语料里只剩 {len(keys)} 条快照，这条对照失去意义"
    values = 0
    link_headers: list[str] = []
    for key in keys:
        for name, value in store.get(key).headers.items():
            values += 1
            _same(value)
            if name == "link":
                link_headers.append(value)
    assert values >= 10_000, values
    matched = 0
    for header in link_headers:
        for variant in _variants(header):
            _same(variant)
            matched += _old_url(variant) is not None
    # 语料里有真实的命中（43 / 192），变体里也要有：这条对照不是在比一堆 None
    assert len(link_headers) >= 100, len(link_headers)
    assert matched >= 100, matched
    assert sum(_old_url(h) is None for h in link_headers) >= 50


# ── 2. 随机头（标记词汇表）───────────────────────────────────────────────────
_TOKENS = [
    "<",
    ">",
    "<>",
    ";",
    ",",
    " ",
    "  ",
    "\t",
    "rel",
    "REL",
    "Rel",
    "=",
    " =",
    "= ",
    "alternate",
    "ALTERNATE",
    "alternates",
    '"',
    "'",
    "type",
    "TYPE",
    "text/markdown",
    "TEXT/MARKDOWN",
    "text/html",
    "text/",
    "markdown",
    "a",
    "x",
    "/",
    "http://x/",
    "<a>",
    "<a>;",
    "; rel=alternate",
    "; type=text/markdown",
    'rel="alternate"',
    'type="text/markdown"',
    "rel = alternate",
    "type = text/markdown",
    "relalternate",
    "text/markdownx",
    "text/mar" + _KELVIN + "down",
    "alterna" + _LONG_S + "te",
    _DOTLESS_I,
    *_ALL_WS,
]
#: 一个词就让 ``search`` 命中的复合词：让随机头里命中的比例不至于太低
_BIG_TOKENS = [
    _GOOD,
    "<a>; rel=alternate; type=text/markdown",
    "<a> ;rel=alternate type=text/markdown",
    "<a>;rel=alternate,type=text/markdown",
    "<a>;type=text/markdown;rel=alternate",
]


def _fuzz_header(rng: random.Random) -> str:
    parts: list[str] = []
    for _ in range(rng.randint(0, 14)):
        parts.append(rng.choice(_BIG_TOKENS if rng.random() < 0.12 else _TOKENS))
    return "".join(parts)


def test_identical_results_on_a_hundred_thousand_fuzzed_headers() -> None:
    rng = random.Random(20261009)
    matched = 0
    n = 100_000
    for _ in range(n):
        header = _fuzz_header(rng)
        _same(header)
        matched += _old_url(header) is not None
    assert n * 0.04 <= matched <= n * 0.9, matched  # 两种结果都出现得足够多


# ── 3. 按结构拼出来的 Link 头 ────────────────────────────────────────────────
_URLS = [
    "https://x.test/a.md",
    "/docs/a",
    "a",
    "a<b",
    "a,b",
    "x y",
    "http://[",
    "u;v",
    "rel=alternate",
]
_REL_FORMS = [
    'rel="alternate"',
    "rel=alternate",
    "REL = Alternate",
    'rel = "alternate"',
    'rel="alternate"x',
    'rel="alternate',
    "rel=alternates",
    "rel=canonical",
    'rel="stylesheet alternate"',
    "rel",
    "rel='alternate'",  # 单引号不算
    "rel:alternate",
    "rel==alternate",
    "rev=alternate",
]
_TYPE_FORMS = [
    'type="text/markdown"',
    "type=text/markdown",
    "TYPE = Text/Markdown",
    'type = "text/markdown"',
    "type=text/html",
    'type="text/markdown',
    "type=text/markdown; charset=utf-8",
    "type=text/markdownx",
    "type='text/markdown'",  # 单引号不算
    "type:text/markdown",
    "type=text/x-markdown",
]
_OTHER_FORMS = ['title="x"', "hreflang=en", "anchor=a,b", "media=print", "x"]
_WS = ["", " ", "  ", "\t", chr(0xA0), chr(0x3000)]
_SEPS = [", ", ",", " , ", ";", ""]


def _structured_header(rng: random.Random) -> str:
    """一到四个条目，参数顺序随机，再随机改 0-3 处。"""
    entries: list[str] = []
    for _ in range(rng.randint(1, 4)):
        params: list[str] = []
        if rng.random() < 0.85:
            params.append(rng.choice(_REL_FORMS))
        if rng.random() < 0.85:
            params.append(rng.choice(_TYPE_FORMS))
        params.extend(rng.sample(_OTHER_FORMS, rng.randint(0, 2)))
        if rng.random() < 0.3:
            rng.shuffle(params)
        sep = rng.choice(["; ", ";", " ; ", ";\t"])
        entries.append(
            "<"
            + rng.choice(_URLS)
            + ">"
            + rng.choice(_WS)
            + ";"
            + rng.choice(_WS)
            + sep.join(params)
        )
    header = rng.choice(_SEPS).join(entries)
    for _ in range(rng.randint(0, 3) if rng.random() < 0.5 else 0):
        at = rng.randint(0, len(header))
        what = rng.randint(0, 3)
        if what == 0:
            header = header[:at] + header[at + 1 :]
        elif what == 1:
            header = header[:at] + rng.choice(_TOKENS) + header[at:]
        elif what == 2:
            header = header[:at] + rng.choice([",", ";", ">", "<", '"', " "]) + header[at + 1 :]
        else:
            header = header[:at] + header[at:].replace(",", ";", 1)
    return header


def test_identical_results_on_forty_thousand_structured_headers() -> None:
    rng = random.Random(20261010)
    first_entry = later_entry = rel_and_type_but_no_match = no_match = 0
    for _ in range(40_000):
        header = _structured_header(rng)
        _same(header)
        url = _old_url(header)
        if url is None:
            no_match += 1
            low = header.lower()
            rel_and_type_but_no_match += "rel" in low and "text/markdown" in low
        elif header.startswith("<" + url + ">"):
            first_entry += 1
        else:
            later_entry += 1
    assert first_entry >= 2_000 and later_entry >= 500, (first_entry, later_entry)
    assert rel_and_type_but_no_match >= 2_000, rel_and_type_but_no_match  # 「差一点」的负例
    assert no_match >= 10_000, no_match


# ── 4. 穷举 ──────────────────────────────────────────────────────────────────
def _all_sequences(alphabet: list[str], max_len: int) -> Iterator[str]:
    layer = [""]
    yield ""
    for _ in range(max_len):
        layer = [s + t for s in layer for t in alphabet]
        yield from layer


def test_identical_results_on_every_short_sequence_of_whole_pieces() -> None:
    alphabet = ["<x>;", "<", ">", ",", " ", "rel=alternate", "type=text/markdown", "x"]
    n = matched = 0
    for header in _all_sequences(alphabet, 6):
        _same(header)
        n += 1
        matched += _old_url(header) is not None
    assert n == sum(len(alphabet) ** k for k in range(7))
    assert matched >= 3_000, matched


#: 命中或差一点命中的头，拆成最小的词；下面对它们做「改一个词」「改两个词」的穷举
_SEEDS = [
    "<|x|>|;| |rel|=|alternate|;| |type|=|text/markdown",
    '<|x|>| |;|rel| |=| |"|alternate|"|;|type|=|"|text/markdown|"',
    "<|x|>|;|type|=|text/markdown|;|rel|=|alternate",
    "<|x|>|;|rel|=|alternate|,|type|=|text/markdown",
    "<|y|>|;|z|,|<|x|>|;|rel|=|alternate|;|type|=|text/markdown",
    "<|x|>|;|rel|=|alternate|;|y|,|type|=|text/markdown",
    "<|x|>|;|rel|=|alternate|;|<|y|>|;|type|=|text/markdown",
    "<|x|<|y|>|;|rel|=|alternate|type|=|text/markdown",
]
_PIECES = [
    "<",
    ">",
    ";",
    ",",
    " ",
    "=",
    '"',
    "rel",
    "alternate",
    "type",
    "text/markdown",
    "x",
    "<x>",
]


def _single_edits(tokens: list[str]) -> Iterator[list[str]]:
    for i in range(len(tokens)):
        yield [*tokens[:i], *tokens[i + 1 :]]  # 删掉一个词
        for piece in _PIECES:
            yield [*tokens[:i], piece, *tokens[i + 1 :]]  # 换掉一个词
    for i in range(len(tokens) + 1):
        for piece in _PIECES:
            yield [*tokens[:i], piece, *tokens[i:]]  # 插进一个词


def test_identical_results_after_every_single_edit_of_the_seed_headers() -> None:
    n = matched = 0
    for seed in _SEEDS:
        tokens = seed.split("|")
        for edited in _single_edits(tokens):
            header = "".join(edited)
            _same(header)
            n += 1
            matched += _old_url(header) is not None
    assert n >= 2_000 and matched >= 300, (n, matched)


def test_identical_results_after_every_double_edit_of_two_seed_headers() -> None:
    n = matched = 0
    for seed in (_SEEDS[0], _SEEDS[4]):
        for once in _single_edits(seed.split("|")):
            for twice in _single_edits(once):
                header = "".join(twice)
                _same(header)
                n += 1
                matched += _old_url(header) is not None
    assert n >= 100_000 and matched >= 5_000, (n, matched)


# ── 5. 手写的边角 ────────────────────────────────────────────────────────────
_EDGE_CASES = [
    "",
    "<",
    ">",
    "<>",
    _GOOD,
    '<a>; rel="alternate"; type="text/markdown"',
    "<a>;rel=alternate;type=text/markdown",
    "<a> ;rel=alternate;type=text/markdown",
    "<a>\t;\trel\t=\talternate\ttype\t=\ttext/markdown",
    "<a> ; rel = alternate ; type = text/markdown",
    "<a>; rel=alternate",  # 没有 type
    "<a>; type=text/markdown",  # 没有 rel
    "<a>; type=text/markdown; rel=alternate",  # type 在 rel 之前
    "<a>; rel=alternate, type=text/markdown",  # 被逗号隔开
    "<a>; rel=alternate; type=text/markdown, <b>; rel=alternate; type=text/markdown",
    "<a>; foo, <b>; rel=alternate; type=text/markdown",  # 第二个条目命中
    "<a>; foo, rel=alternate; type=text/markdown",  # 逗号之后的 rel / type 不属于 <a>
    "<a>, <b>; rel=alternate; type=text/markdown",
    "<a>; rel=canonical, <b>; rel=alternate; type=text/markdown",
    "<a><b>; rel=alternate; type=text/markdown",  # 第一个 > 之后不是 ;
    "<a<b>; rel=alternate; type=text/markdown",  # url 里有 <
    "<a>b>; rel=alternate; type=text/markdown",
    "<>; rel=alternate; type=text/markdown",  # 空 url
    "<><a>; rel=alternate; type=text/markdown",
    "<>;<a>; rel=alternate; type=text/markdown",
    "<<>; rel=alternate; type=text/markdown",
    "<a,b>; rel=alternate; type=text/markdown",  # url 里有逗号
    "<a;b>; rel=alternate; type=text/markdown",
    "<a>x; rel=alternate; type=text/markdown",  # > 与 ; 之间有杂物
    "<a>;; rel=alternate; type=text/markdown",
    "<a>;,rel=alternate; type=text/markdown",
    "<a>; ,rel=alternate; type=text/markdown",
    "<a>;rel=alternate;,type=text/markdown",
    "<a>; xrel=alternate; xtype=text/markdown",  # 没有词边界
    "<a>; rel=alternate type=text/markdown",
    "<a>; rel=alternatetype=text/markdown",
    "<a>; rel=alternatealternate; type=text/markdown",
    "<a>; relrel=alternate; type=text/markdown",
    "<a>; rel =alternate; type =text/markdown",
    "<a>; rel= alternate; type= text/markdown",
    "<a>; rel=  alternate; type=text/markdown",  # = 之后的空白吃掉了，alternate 仍然紧跟
    'rel="alternate"; type="text/markdown"; <a>',
    '<a>; rel="alternate',
    '<a>; rel=alternate"; type=text/markdown"',
    "<a>; rel='alternate'; type='text/markdown'",  # 单引号不算
    '<a>; rel=" alternate"; type=text/markdown',
    '<a>; rel="alternate"; type=" text/markdown"',
    "<a>; rel=alternate; type=text/markdowns",
    "<a>; rel=alternate; type=text/markdow",
    "<a>; rel=alternat; type=text/markdown",
    "<a>; rel=alternate; type=text/html; type=text/markdown",
    "<a>; rel=alternate; rel=alternate; type=text/markdown",
    "<a>; rel=alternate type=text/markdown type=text/markdown",
    "<a>; type=text/markdown rel=alternate type=text/markdown",
    "<a>; rel=alternate; foo=<b>; type=text/markdown",  # 参数里有 < >
    "<a>; rel=alternate; foo=>; type=text/markdown",
    "<a>; rel=alternate; <b>; type=text/markdown",
    "<a> <b>; rel=alternate; type=text/markdown",
    "<a>;<b>; rel=alternate; type=text/markdown",
    "<a>; <b>; rel=alternate; type=text/markdown",
    "<a>; rel=alternate; type=text/markdown;",
    "<a>; rel=alternate; type=text/markdown,",
    ",<a>; rel=alternate; type=text/markdown",
    ";<a>; rel=alternate; type=text/markdown",
    " <a>; rel=alternate; type=text/markdown",
    "x<a>; rel=alternate; type=text/markdown",
    "<a>\n; rel=alternate; type=text/markdown",
    "<a>;\nrel=alternate;\ntype=text/markdown",
    "<a>; rel=alternate;" + " " * 2_000 + "type=text/markdown",
    "<a>" + " " * 2_000 + "; rel=alternate; type=text/markdown",
    "<a>; rel" + " " * 2_000 + "= alternate; type=text/markdown",
    "<a>; rel=" + " " * 2_000 + "alternate; type=text/markdown",
    "<a>; rel=alternate; type" + " " * 2_000 + "= text/markdown",
    "<a>; rel=alternate; type=" + " " * 2_000 + "text/markdown",
    "<a>; rel=alternate; type=text/MARKDOWN",
    "<a>; REL=ALTERNATE; TYPE=TEXT/MARKDOWN",
    "<a>; rel=alternate; type=text/mar" + _KELVIN + "down",
    "<a>; rel=alterna" + _LONG_S + "te; type=text/markdown",
    "<a>; rel='alternate'; type=text/markdown",  # 每个差一点的写法都配上另一半有效的
    "<a>; rel=alternate; type='text/markdown'",
    "<a>; rel:alternate; type=text/markdown",
    "<a>; rel=alternate; type:text/markdown",
    "<a>; rel=alternate; type=text/x-markdown",
    "<a>; rev=alternate; type=text/markdown",
    "<a>; rel==alternate; type=text/markdown",
    "<a>; rel=alternate; type=text/markdown, <b>; rel=alternate",
    "<a>; rel=alternate, <b>; type=text/markdown",
    "<a>; rel=alternate, <b>; rel=alternate; type=text/markdown",
    "<a>; type=text/markdown, <b>; rel=alternate; type=text/markdown",
    "<a>;" + "x," * 50 + " <b>; rel=alternate; type=text/markdown",
    "<a>;" + "x;" * 50 + " rel=alternate; type=text/markdown",
    "<a>; rel=alternate; " + "x," * 50 + "type=text/markdown",
    "<a>; " + "rel=alternate; " * 50 + "type=text/markdown",
    "<a>; " + "type=text/markdown; " * 50 + "rel=alternate",
    "<a>; " + "type=text/markdown; " * 50 + "rel=alternate; type=text/markdown",
    "<a>; rel=alternate" * 50 + "; type=text/markdown",
    "<a>," * 50 + "<a>; rel=alternate; type=text/markdown",
    "<a>;," * 50 + "<a>; rel=alternate; type=text/markdown",
    "<a>" * 50 + "; rel=alternate; type=text/markdown",
    "<" * 50 + "a>; rel=alternate; type=text/markdown",
    "<" * 50 + ">" + "; rel=alternate; type=text/markdown",
    "<" * 50 + "a>" + ">" * 50 + "; rel=alternate; type=text/markdown",
]


@pytest.mark.parametrize(
    "header", _EDGE_CASES, ids=[f"edge{i:03d}" for i in range(len(_EDGE_CASES))]
)
def test_identical_results_on_hand_written_edge_cases(header: str) -> None:
    _same(header)


def test_identical_results_on_case_variants_of_the_edge_cases() -> None:
    for header in _EDGE_CASES:
        for variant in (header.upper(), header.lower(), header.swapcase(), header.title()):
            _same(variant)


def test_the_edge_cases_contain_both_matches_and_misses() -> None:
    hits = sum(_old_url(h) is not None for h in _EDGE_CASES)
    assert 20 <= hits <= len(_EDGE_CASES) - 20, hits


#: 每个 ``\s`` 位置：(前缀, 后缀) 之间塞一个空白字符
_WS_SLOTS = [
    ("<a>", "; rel=alternate; type=text/markdown"),  # > 与 ; 之间
    ("<a>;", "rel=alternate; type=text/markdown"),  # ; 之后
    ("<a>; rel", "=alternate; type=text/markdown"),  # rel 与 = 之间
    ("<a>; rel=", "alternate; type=text/markdown"),  # = 之后
    ("<a>; rel=alternate; type", "=text/markdown"),  # type 与 = 之间
    ("<a>; rel=alternate; type=", "text/markdown"),  # = 之后
    ("<a>; rel=alternate; ", "type=text/markdown"),
]


def test_every_whitespace_character_in_every_whitespace_slot() -> None:
    hits = 0
    for ws in _ALL_WS:
        for head, tail in _WS_SLOTS:
            for header in (head + ws + tail, head + ws + ws + tail, head + tail):
                _same(header)
                hits += _old_url(header) is not None
    assert hits >= 5 * len(_ALL_WS), hits


# ── 6. 大输入：旧正则对这些形状也是线性的，直接对着比 ───────────────────────────
def _same_big(header: str) -> None:
    with _deadline(120):
        _same(header)


@pytest.mark.parametrize("count", [1_000, 100_000, 400_000])
@pytest.mark.parametrize(
    "unit",
    [
        "<a>;x, ",
        "<a>; rel=alternate, ",
        "<a>; type=text/markdown; rel=alternate, ",
        "<a>; rel=alternate; type=text/html, ",
        "<a> ,",
        "<>, ",
    ],
)
def test_a_match_after_many_dead_entries_is_still_found(unit: str, count: int) -> None:
    _same_big(unit * count + "<z>; rel=alternate; type=text/markdown")
    _same_big(unit * count + "<z>; rel=alternate")
    _same_big(unit * count)


def test_the_match_after_many_dead_entries_is_the_last_one() -> None:
    header = "<a>;x, " * 100_000 + "<z>; rel=alternate; type=text/markdown"
    assert ap._alternate_markdown_url(header) == "z"
    assert ap._alternate_markdown_url("<a>;x, " * 100_000) is None


@pytest.mark.parametrize("size", [100_001, 1_048_577, 4_194_305])
def test_a_match_after_a_long_prefix_is_still_found(size: int) -> None:
    assert ap._alternate_markdown_url("x" * size + "<z>; rel=alternate; type=text/markdown") == "z"
    assert ap._alternate_markdown_url("," * size + "<z>; rel=alternate; type=text/markdown") == "z"
    assert ap._alternate_markdown_url(" " * size + "<z>; rel=alternate; type=text/markdown") == "z"
    assert ap._alternate_markdown_url("<" * size + "z>; rel=alternate; type=text/markdown") == (
        "<" * (size - 1) + "z"
    )
    assert (
        ap._alternate_markdown_url("<z>" + " " * size + "; rel=alternate; type=text/markdown")
        == "z"
    )
    assert (
        ap._alternate_markdown_url("<z>; rel=alternate;" + " " * size + "type=text/markdown") == "z"
    )
    assert (
        ap._alternate_markdown_url("<z>; rel=alternate" + ";" * size + "type=text/markdown") == "z"
    )
    assert ap._alternate_markdown_url(
        "<" + "u" * size + ">; rel=alternate; type=text/markdown"
    ) == ("u" * size)


# ── 7. 计时守卫：线性 ────────────────────────────────────────────────────────
#: 家族 -> (生成函数, 「密」吗)。密 = 由大量很小的条目组成：实现里每个条目都要付 Python 层面的
#: 循环开销，所以它们的阶梯只到 1.6 MB；其余每个字节都便宜，阶梯到 4 MB。后面括号里是旧正则在
#: 25 KB 上的耗时，只是备忘。
_PATHOLOGICAL: dict[str, tuple[Callable[[int], str], bool]] = {
    "lt-only": (lambda n: "<" * n, False),  # 旧：平方，100 KB 16 s
    # 很多个 ``<`` 共用远处的同一个 ``>``：每个 ``<`` 各自去找 ``>`` 就是平方级
    "many-lt-one-gt": (lambda n: "<" * n + ">", False),
    "many-lt-one-gt-then-semicolon": (lambda n: "<" * n + ">;", False),
    # 同一个 ``>`` 之后各种「走不通」的收尾：每条路径都得是「从 gt 之后继续」，
    # 从 ``<`` 之后重来就是平方级（这三条路径上 ``<`` 的重扫各自只在这里露出来）
    "many-lt-one-gt-then-rel-comma-type": (
        lambda n: "<" * n + ">; rel=alternate, type=text/markdown",
        False,
    ),
    "many-lt-one-gt-then-rel-only": (lambda n: "<" * n + ">; rel=alternate", False),
    "many-lt-one-gt-then-type-before-rel": (
        lambda n: "<" * n + ">; type=text/markdown; rel=alternate",
        False,
    ),
    "gt-only": (lambda n: ">" * n, False),
    "no-lt": (lambda n: "x" * n, False),
    "lt-a-no-gt": (lambda n: "<a" * (n // 2), False),
    "spaces-after-gt": (lambda n: "<a>" + " " * n + "x", False),
    "spaces-after-semicolon": (lambda n: "<a>;" + " " * n, False),
    "rel-then-spaces": (lambda n: "<a>;rel" + " " * n + "x", False),
    "rel-eq-then-spaces": (lambda n: "<a>;rel=" + " " * n + "x", False),
    "type-then-spaces": (lambda n: "<a>;rel=alternate type" + " " * n + "x", False),
    "commas-only": (lambda n: "," * n, False),
    "one-entry-many-commas": (lambda n: "<a>;" + "," * n, False),
    # 很多个「走不通」的小条目：「搜到头再比」「每个条目重扫余下的头」这类自然的平方 / 立方级
    # 写法，只有在这些家族上才露出来（没有 ``>`` 的家族里它们都提前结束了）
    "entries-no-semicolon": (lambda n: "<a> " * (n // 4), True),
    "entries-semicolon-no-rel": (lambda n: "<a>;x " * (n // 6), True),  # 旧：平方
    "entries-rel-no-type": (
        lambda n: "<a>; rel=alternate " * (n // 20),
        True,
    ),  # 旧：立方，25 KB 22 s
    "entries-type-no-rel": (lambda n: "<a>; type=text/markdown " * (n // 24), True),
    "entries-rel-then-comma-type-at-the-end": (
        lambda n: "<a>; rel=alternate," * (n // 19) + "type=text/markdown",
        True,
    ),
    "entries-comma-then-rel-at-the-end": (
        lambda n: "<a>;x," * (n // 6) + "rel=alternate; type=text/markdown",
        True,
    ),
    # 很多个条目共用同一个远处的逗号：每个条目各自去找逗号就是平方级
    "entries-then-one-comma-then-rel": (
        lambda n: "<a>;x " * (n // 6) + ", rel=alternate; type=text/markdown",
        True,
    ),
    # 许多条目共用同一处远方的 rel…alternate，紧接着它就是一个又长又贵的 type…text/markdown：
    # 每个条目都问「rel 结尾处的下一个 type」，答案的起点恰好等于被问的位置；缓存判断里把
    # ``>=`` 写成 ``>``，就会每个条目都重搜那一长串空白
    "entries-then-glued-rel-type-with-long-whitespace": (
        lambda n: "<a>;x," * (n // 12) + "rel=alternatetype" + " " * (n // 2) + "=text/markdown",
        True,
    ),
    "entries-empty-segments": (
        lambda n: "<a>;," * (n // 5) + "rel=alternate; type=text/markdown",
        True,
    ),
    "entries-type-before-rel": (
        lambda n: "<a>; type=text/markdown; rel=alternate, " * (n // 41),
        True,
    ),
    "entries-rel-then-type-html": (
        lambda n: "<a>; rel=alternate; type=text/html " * (n // 36),
        True,
    ),
    "entries-two-rels-one-type-far": (
        lambda n: "<a>; rel=alternate; rel=alternate " * (n // 35) + "type=text/markdown",
        True,
    ),
    "entries-ok-with-commas": (
        lambda n: "<a>; rel=alternate; type=text/html, " * (n // 38),
        True,
    ),
    "entries-gt-inside-params": (lambda n: "<a>; x=>, " * (n // 10), True),
    "entries-lt-inside-params": (lambda n: "<a>; x=<, " * (n // 10), True),
    "mixed": (
        lambda n: "<a>;x, <>, <b> ;rel=alternate, <c>;type=text/markdown, " * (n // 52),
        True,
    ),
}

_SIZES = {
    False: (20_000, 100_000, 1_000_000, 4_000_000),
    True: (20_000, 100_000, 400_000, 1_600_000),
}
#: 最大一档的耗时 / 四分之一大小的耗时：线性约 4（缓存效应最多到 6），平方约 16
_MAX_GROWTH = 10.0
#: 四分之一大小那一档快于此就不看倍数（噪声比信号大），只看绝对上限
_MIN_MEASURABLE = 0.03


def _limit(size: int) -> float:
    """每次调用的秒数上限：每 MB 10 s 再加 0.5 s。只兜住立方级 / 指数级的爆炸，余量很大
    （CI 带 ``--cov``，Python 3.11 的逐行插桩会把循环密集的家族拖慢 4 倍左右）。"""
    return 0.5 + size / 100_000


#: 用 CPU 时间量：CPU 被别的进程抢走时（CI 上的邻居、同时跑的测试）墙钟会成倍变慢，而且短的
#: 那一档比长的那一档更容易被撞上，增长倍数就假红。Windows 的 ``process_time`` 只有 15.6 ms 的
#: 分辨率（比 30 ms 的下限还粗），那里只能用墙钟。
_CLOCK = time.perf_counter if sys.platform == "win32" else time.process_time


def _timed(header: str, limit: float) -> float:
    t = _CLOCK()
    with _deadline(limit * 3):
        ap._alternate_markdown_url(header)
    return _CLOCK() - t


@pytest.mark.parametrize("name", list(_PATHOLOGICAL))
def test_link_header_search_on_hostile_input_is_linear(name: str) -> None:
    make, dense = _PATHOLOGICAL[name]
    sizes = _SIZES[dense]
    times: dict[int, float] = {}
    for size in sizes:  # 先小后大：立方级的写法在 20 KB 上就已经超限，不必等大的跑完
        times[size] = _timed(make(size), _limit(size))
        assert times[size] < _limit(size), (
            f"{name} {size}: {times[size]:.2f}s > {_limit(size):.1f}s"
        )
    small, big = sizes[-2], sizes[-1]
    if times[small] < _MIN_MEASURABLE:
        return
    if times[big] > _MAX_GROWTH * times[small]:
        # 重测一次：大的那次调用里碰上的一次停顿，看起来就像超线性增长
        times[small] = min(times[small], _timed(make(small), _limit(small)))
        times[big] = min(times[big], _timed(make(big), _limit(big)))
        if times[small] < _MIN_MEASURABLE:
            return  # 重测显示小的那一档其实低于下限：这个比值没有意义，只看上面的绝对上限
    growth = times[big] / times[small]
    assert growth <= _MAX_GROWTH, (
        f"{name}: {small} B {times[small]:.3f}s -> {big} B {times[big]:.3f}s, "
        f"x{growth:.1f} for x{big // small} the size"
    )


@pytest.mark.parametrize("name", list(_PATHOLOGICAL))
def test_identical_results_on_the_hostile_families_when_small(name: str) -> None:
    """上面的计时守卫只计时、不看结果；这里在旧正则还跑得动的小尺寸上把结果比一遍
    （旧正则对其中几个家族是立方级，3,000 字符是 0.1 s 量级）。"""
    make, _dense = _PATHOLOGICAL[name]
    header = make(3_000)
    _same(header)
    _same(header + ", <z>; rel=alternate; type=text/markdown")
    _same(header + " <z>; rel=alternate; type=text/markdown")
    _same("<z>; rel=alternate; type=text/markdown, " + header)


def test_a_hostile_link_header_does_not_stall_the_page_signal() -> None:
    """评审里的原始复现：旧代码对 25,000 字符的 ``<a>; rel=alternate `` 重复头就要二十秒以上，
    100 KB 按立方外推要半小时以上。走真实的函数（含可见文字、横幅、``Link`` 头）。"""
    header = ("<a>; rel=alternate " * 6_000)[:100_000]
    resp = HttpResponse(
        url="https://docs.acme.invalid/",
        final_url="https://docs.acme.invalid/",
        status=200,
        headers={"content-type": "text/html", "link": header},
        body=b"<html><body><p>docs</p></body></html>",
    )
    with _deadline(30):
        decl = ap.detect_md_signal_from_page(resp)
    assert decl is None


# ── 8. 接线：函数的结果真的被 ``detect_md_signal_from_page`` 用上了 ───────────────
def _page(link: str | None, url: str = "https://docs.acme.invalid/guide/start") -> HttpResponse:
    headers = {"content-type": "text/html"}
    if link is not None:
        headers["link"] = link
    return HttpResponse(
        url=url,
        final_url=url,
        status=200,
        headers=headers,
        body=b"<html><body><p>docs</p></body></html>",
    )


def test_a_matching_link_header_sets_the_declaration_from_its_url() -> None:
    same_path = _page(
        '<https://docs.acme.invalid/guide/start.md>; rel="alternate"; type="text/markdown"'
    )
    decl = ap.detect_md_signal_from_page(same_path)
    assert decl is not None
    assert decl.negotiation_advertised is True
    assert decl.scope == "ANY_PAGE"
    assert decl.declaration_text == (
        'Link: <https://docs.acme.invalid/guide/start.md>; rel="alternate"; type="text/markdown"'
    )

    elsewhere = _page('</md/index.md>; rel="alternate"; type="text/markdown"')
    decl = ap.detect_md_signal_from_page(elsewhere)
    assert decl is not None
    assert decl.negotiation_advertised is True
    assert decl.scope == "PREFIX"
    assert decl.scope_prefix == "https://docs.acme.invalid/md/"


def test_a_relative_link_url_is_resolved_against_the_final_url_of_the_page() -> None:
    """页面经过跳转：相对的 Link url 要以**最终**地址为基准，而不是最初请求的那个。"""
    link = '</md/page.md>; rel="alternate"; type="text/markdown"'
    redirected = HttpResponse(
        url="https://old.example.test/start",
        final_url="https://docs.example.test/guide/page",
        status=200,
        headers={"content-type": "text/html", "link": link},
        body=b"<html><body><p>docs</p></body></html>",
    )
    decl = ap.detect_md_signal_from_page(redirected)
    assert decl is not None
    assert decl.scope == "PREFIX"
    assert decl.scope_prefix == "https://docs.example.test/md/"
    assert decl.source_url == "https://docs.example.test/guide/page"
    assert "https://docs.example.test/md/page.md" in decl.declaration_text

    # 同路径加 .md：与最终地址比，不与最初地址比
    same_path = HttpResponse(
        url="https://old.example.test/start",
        final_url="https://docs.example.test/guide/page",
        status=200,
        headers={
            "content-type": "text/html",
            "link": (
                '<https://docs.example.test/guide/page.md>; rel="alternate"; type="text/markdown"'
            ),
        },
        body=b"<html><body><p>docs</p></body></html>",
    )
    decl = ap.detect_md_signal_from_page(same_path)
    assert decl is not None
    assert decl.scope == "ANY_PAGE"


def test_a_link_header_without_the_markdown_alternate_is_not_a_signal() -> None:
    for link in (
        None,
        "",
        '<https://docs.acme.invalid/guide/start.md>; rel="alternate"',
        '<https://docs.acme.invalid/guide/start.md>; type="text/markdown"',
        '<https://docs.acme.invalid/x>; rel="canonical"',
        (
            '<https://docs.acme.invalid/a>; rel="alternate", '
            '<https://docs.acme.invalid/b>; type="text/markdown"'
        ),
    ):
        assert ap.detect_md_signal_from_page(_page(link)) is None, link


def test_the_second_entry_of_the_header_is_the_one_that_is_used() -> None:
    link = (
        '<https://docs.acme.invalid/other>; rel="canonical", '
        '<https://docs.acme.invalid/guide/start.md>; rel="alternate"; type="text/markdown"'
    )
    decl = ap.detect_md_signal_from_page(_page(link))
    assert decl is not None
    assert decl.scope == "ANY_PAGE"


# ── 9. 只往前走的搜索 ────────────────────────────────────────────────────────
_SEARCH_PIECES = [
    "rel=alternate",
    "type=text/markdown",
    "rel",
    "=",
    "alternate",
    " ",
    "x",
    '"',
    "type",
    "text/markdown",
    ",",
    "<a>;",
    "ab",
    "abb",
    "b",
]


@pytest.mark.parametrize(
    "pattern", [ap._REL_ALTERNATE_RE, ap._TYPE_MARKDOWN_RE, re.compile(r"ab+")]
)
def test_search_from_remembers_the_last_hit_without_changing_the_answer(
    pattern: re.Pattern[str],
) -> None:
    rng = random.Random(7)
    found = missing = reused = 0
    for _ in range(3_000):
        text = "".join(rng.choice(_SEARCH_PIECES) for _ in range(rng.randint(0, 25)))
        positions = sorted(rng.randint(0, len(text) + 1) for _ in range(rng.randint(1, 8)))
        searcher = ap._SearchFrom(pattern, text)
        previous: re.Match[str] | None = None
        for pos in positions:
            want = pattern.search(text, pos)
            got = searcher.at_or_after(pos)
            assert (got.span() if got else None) == (want.span() if want else None), (text, pos)
            found += want is not None
            missing += want is None
            reused += got is not None and got is previous
            previous = got
    assert found >= 1_000 and missing >= 1_000 and reused >= 500, (found, missing, reused)


@pytest.mark.parametrize(
    "pattern", [ap._REL_ALTERNATE_RE, ap._TYPE_MARKDOWN_RE, re.compile(r"ab+")]
)
def test_search_from_is_right_for_any_order_of_positions(pattern: re.Pattern[str]) -> None:
    """只有「只增不减」才保证线性，但答案对任何顺序都得是对的（位置往回走时重搜一遍）。"""
    rng = random.Random(8)
    backwards = 0
    for _ in range(3_000):
        text = "".join(rng.choice(_SEARCH_PIECES) for _ in range(rng.randint(0, 25)))
        searcher = ap._SearchFrom(pattern, text)
        last = -1
        for _ in range(rng.randint(2, 8)):
            pos = rng.randint(0, len(text) + 1)
            backwards += pos < last
            want = pattern.search(text, pos)
            got = searcher.at_or_after(pos)
            assert (got.span() if got else None) == (want.span() if want else None), (text, pos)
            last = pos
    assert backwards >= 3_000, backwards


@pytest.mark.parametrize("pattern", [ap._REL_ALTERNATE_RE, ap._TYPE_MARKDOWN_RE])
def test_search_from_reuses_a_hit_that_starts_exactly_at_the_asked_position(
    pattern: re.Pattern[str],
) -> None:
    """起点恰好等于被问位置的命中也是缓存命中：不再搜第二遍（计时测试里的
    ``entries-then-glued-rel-type-with-long-whitespace`` 从另一头看的是同一件事）。"""
    word = "rel=alternate" if pattern is ap._REL_ALTERNATE_RE else "type=text/markdown"
    searcher = ap._SearchFrom(pattern, "xx" + word + "yy")
    first = searcher.at_or_after(0)
    assert first is not None
    assert searcher.at_or_after(first.start()) is first
    assert searcher.at_or_after(first.start()) is first
    assert searcher.at_or_after(first.start() + 1) is None  # 之后没有了：记住的「没有」也是缓存
