"""``checks/ai_path.py`` 里链接抽取的四条正则必须是线性的 —— 而且结果与旧正则完全相同。

## 缺陷

llms.txt 是被体检的站点自己提供的，一行可以有几 MB。``extract_index_links`` 对每一行跑三条
``finditer``（markdown ``[text](url)``、``/`` 开头的相对路径、内嵌 ``<a href>``），``index_shape``
对每一行跑一条 ``re.match``（「是不是链接行」）。它们对「开了没法闭合」的开头都把整行余下的部分
再扫一遍：一行里 N 个 ``<a ``（后面没有 ``href=``）或 N 个 ``[x](``（后面没有 ``)``）是 O(N^2)，
``\\s*[-*]?\\s*`` 对一长串空白还要回溯。64 KB 的 ``<a `` 或空白要几秒，再大按平方涨（长度每翻一倍
慢 4 倍）。

范围：这里只管这四条。同一个文件里的 ``_TITLE_RE`` 只看响应正文的前 2 万个字符（最坏实测 0.12 s），
没有动。``_LINK_HEADER_RE``（``Link`` 响应头）也没有动，但它**不是**有界的小问题：httpcore 允许整个
响应头块到 100 KiB，而它对重复的 ``<a>; rel=alternate `` 是立方级（25,000 字符 22 s），另行处理。

## 这组测试怎么证明「没改行为」

旧的四条正则、``LINK_RE_BARE``、旧的 ``extract_index_links`` 与 ``index_shape`` 原样留在本文件里当
**对照（oracle）**，与新实现比 —— 三个生成器各自吐出的匹配（文本、url、顺序）、是 / 否函数的答案、
整个 ``extract_index_links`` 的返回值（连同「抛了什么异常」：``urljoin`` 遇到 ``http://[`` 会抛
``ValueError``，新旧必须一起抛）、``index_shape`` 的返回值：

1. 全部冻结响应（真实站点的正文）；
2. 两万篇由「标记词汇表」随机拼出来的文档（含 ``splitlines`` 会切开的每一种分隔符、``\\s`` 接受的
   每一个空白字符、不成对的括号和引号），三万篇「已知有链接的行随机改 1-4 处」的文档，以及两万篇按
   结构拼出来的链接列表；它们都断言各种结果出现了足够多次 —— fuzz 不是空转；
3. 一组逐条写出来的边角：嵌套的 ``[``、同一个标签里的几个 ``href=``、url 里的 ``>``、每个
   ``\\s`` 位置上的每一种空白、大小写；
4. 编辑距离 1 的邻域：二十几条写得规规矩矩的链接行，每个位置删 / 换 / 插一个字符，字符取自约
   300 个（Latin-1 全部、每个行内的 ``\\s``、全角括号、零宽字符、NUL、反引号、``•``、``·``……）：专打
   「没有任何字母表想到会出现的字符」（项目符号集里多一个 ``+``、url 的终止符里多一个 NUL、收尾引号
   里多一个反斜杠……这类放宽字符集的错误，别的测试看不见）；
5. 超大输入：一行里前面垫 100 KB / 1 MiB / 4 MiB / 8 MiB 的普通文字再接一个链接，前面有一万到
   几十万个「走不通」的开头再接一个链接，单个超过 100 KB / 4 MiB 的文本、url、属性段、空白。

## 它证明不了什么

* 超大输入只覆盖上面列出的尺寸和形状，证明不了「实现里不存在任何上限」；
* 计时守卫有两道。**增长倍数**：同一个家族，最大一档 / 四分之一大小的耗时（线性约 4，平方约
  16；用 CPU 时间量，不受 CPU 被别的进程抢走的影响），但四分之一大小那一档快于 30 ms 的家族
  （约一半）不看倍数。
  **绝对上限**：每 MB 10 s 再加 0.5 s，放得很宽；「输出不变但平方」的写法实际上是被它（或超大输入
  对照测试的 ``SIGALRM`` 期限）杀掉的，增长倍数只是能量得出来的家族上多一层保险。靠墙钟抓不到
  常数级的退化；Windows 上没有 ``SIGALRM``，超大输入的对照测试遇到平方级退化会挂住而不是失败
  （POSIX 的几格会先红）。
"""

from __future__ import annotations

import contextlib
import random
import re
import signal
import sys
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from geo_audit.checks import ai_path as ap
from geo_audit.fixtures import FixtureStore

BASE = "https://acme.invalid/docs/llms.txt"

#: ``\s`` 接受的每一个字符（枚举出来的，不是手挑的）；用 chr() 构造，不在源码里打不可见字符
_ALL_WS = [c for c in map(chr, range(0x10000)) if re.fullmatch(r"\s", c)]
#: ``str.splitlines`` 会把它们当行分隔符，所以不会出现在一行的里面
_LINE_BREAKS = [c for c in _ALL_WS if len(("a" + c + "b").splitlines()) == 2]
_INLINE_WS = [c for c in _ALL_WS if c not in _LINE_BREAKS]


def test_the_whitespace_alphabets_are_enumerated_not_listed_by_hand() -> None:
    assert len(_ALL_WS) >= 25 and len(_LINE_BREAKS) >= 8 and len(_INLINE_WS) >= 15
    for must in (" ", "\t", "\x1f", chr(0xA0), chr(0x3000)):
        assert must in _INLINE_WS, hex(ord(must))
    for must in ("\n", "\r", "\x0b", "\x0c", "\x1c", "\x85", chr(0x2028), chr(0x2029)):
        assert must in _LINE_BREAKS, hex(ord(must))


# ── 旧实现（逐字保留，当对照）─────────────────────────────────────────────────
_OLD_MARKDOWN_RE = re.compile(r"\[(?P<text>[^\]]*)\]\((?P<url>[^)\s]+)\)")
_OLD_BARE_RE = re.compile(r"(?<![(<\"'`])\bhttps?://[^\s`)>\"'\]]+")
_OLD_HTML_A_RE = re.compile(r"<a[^>]+href=[\"'](?P<url>[^\"']+)[\"']", re.I)
_OLD_RELATIVE_RE = re.compile(r"\[[^\]]*\]\((?P<url>/[^)\s]+)\)")
#: 旧的相对路径正则没有「文本」组（调用方也不用文本）。加一个捕获组不改变它匹配什么：下面的副本只
#: 用来核对 ``_bracket_links(relative=True)`` 吐出的文本；``_same_line`` 另外断言它与原正则的匹配
#: 位置完全相同。
_OLD_RELATIVE_WITH_TEXT_RE = re.compile(r"\[(?P<text>[^\]]*)\]\((?P<url>/[^)\s]+)\)")
_OLD_LINKY_LINE_RE = re.compile(r"\s*[-*]?\s*\[.+?\]\(.+?\)")


def _old_extract_index_links(text: str, base_url: str) -> list[ap.IndexLink]:
    out: list[ap.IndexLink] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        raws: list[Any] = []
        for m in _OLD_RELATIVE_RE.finditer(line):
            raws.append(("relative", m.group("url"), None))
        for m in _OLD_MARKDOWN_RE.finditer(line):
            raws.append(("markdown", m.group("url"), m.group("text")))
        for m in _OLD_HTML_A_RE.finditer(line):
            raws.append(("html_a", m.group("url"), None))
        for m in _OLD_BARE_RE.finditer(line):
            raws.append(("bare", m.group(0), None))

        seen_on_line: set[str] = set()
        for extractor, raw, anchor in raws:
            link = ap._mk_link(
                line_no=line_no,
                raw=raw,
                base_url=base_url,
                anchor_text=anchor,
                extractor=extractor,
            )
            if link is None or link.abs_url in seen_on_line:
                continue
            seen_on_line.add(link.abs_url)
            out.append(link)
    return out


def _old_index_shape(text: str) -> tuple[float, int]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    linky = sum(1 for ln in lines if _OLD_LINKY_LINE_RE.match(ln))
    prose = sum(
        len(ln) for ln in lines if not ln.lstrip().startswith(("#", "-", "*")) and "](" not in ln
    )
    return ((linky / len(lines)) if lines else 0.0, prose)


def _outcome(fn: Callable[[], Any]) -> tuple[str, Any]:
    """返回值，或者抛出的异常类型 —— 新旧必须一起抛（``urljoin`` 遇到 ``http://[`` 会抛）。"""
    try:
        return ("ok", fn())
    except Exception as exc:
        return ("raised", type(exc).__name__)


@contextlib.contextmanager
def _deadline(seconds: float) -> Iterator[None]:
    """只在有 ``SIGALRM`` 的平台上生效（Windows 上什么也不做）：超大输入上一旦出现平方级退化，
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


def _same_line(line: str) -> None:
    """三个生成器吐出的匹配（文本、url、顺序）和是 / 否函数的答案，对着旧正则逐个比。"""
    markdown = [(m.group("text"), m.group("url")) for m in _OLD_MARKDOWN_RE.finditer(line)]
    assert list(ap._bracket_links(line, relative=False)) == markdown, ("markdown", line[:300])
    relative = [m.group("url") for m in _OLD_RELATIVE_RE.finditer(line)]
    got_relative = list(ap._bracket_links(line, relative=True))
    assert [u for _t, u in got_relative] == relative, ("relative", line[:300])
    with_text = list(_OLD_RELATIVE_WITH_TEXT_RE.finditer(line))
    assert [m.span() for m in with_text] == [m.span() for m in _OLD_RELATIVE_RE.finditer(line)]
    assert [t for t, _u in got_relative] == [m.group("text") for m in with_text], (
        "relative text",
        line[:300],
    )
    html_a = [m.group("url") for m in _OLD_HTML_A_RE.finditer(line)]
    assert list(ap._html_a_links(line)) == html_a, ("html_a", line[:300])
    assert ap._is_linky_line(line) == bool(_OLD_LINKY_LINE_RE.match(line)), ("linky", line[:300])


def _same_lines(text: str) -> None:
    for line in text.splitlines():
        _same_line(line)


def _same_functions(text: str) -> None:
    got = _outcome(lambda: ap.extract_index_links(text, BASE))
    assert got == _outcome(lambda: _old_extract_index_links(text, BASE)), text[:300]
    assert ap.index_shape(text) == _old_index_shape(text), text[:300]


def _same(text: str) -> None:
    _same_lines(text)
    _same_functions(text)


def _same_big(text: str, *, functions: bool = True) -> None:
    """超大输入用：外加期限（这些输入上旧正则都是线性的，几秒就够）。链接成千上万条时
    （``functions=False``）只比三个生成器：整个函数每条链接还要付一次 ``urljoin``。"""
    with _deadline(120):
        _same_lines(text)
        if functions:
            _same_functions(text)


# ── 1. 全部冻结响应 ──────────────────────────────────────────────────────────
def test_identical_results_on_every_frozen_response() -> None:
    store = FixtureStore.default()
    keys = list(store.snapshots())
    assert len(keys) >= 1000, f"语料里只剩 {len(keys)} 条快照，这条对照失去意义"
    raised = 0
    for key in keys:
        body = store.stored_body(key).decode("utf-8", "replace")
        _same(body)
        raised += _outcome(lambda b=body: ap.extract_index_links(b, BASE))[0] == "raised"
    # 语料里有几篇正文（modal.com 的 llms-full.txt 等）会让 urljoin 抛 ValueError：新旧一起抛
    assert raised >= 1, "语料里不再有会抛异常的正文：``_outcome`` 这条路径失去了覆盖"


# ── 2. 随机文档（标记词汇表）─────────────────────────────────────────────────
_TOKENS = [
    "[", "]", "(", ")", "[a]", "[x](", "](", "[x]", "[]", "()", "[](", "[](/", "](/", "](/x)",
    "[x](/y)", "[x](y)", "[x](/)", "[x](//h/p)", "[x](http://h/p)", "[x](y z)", "[ x ]( y )",
    "/", "/a", "//", "http://x/y", "https://h/p?q=1", "http://[", "https://[::1]/x", "u", "x", "ab",
    " ", "  ", "\t", "\n", "\r\n", *_ALL_WS, "-", "*", "- ", "* ", "-- ", "#", "# ",
    "<a", "<A", "<a ", "<abbr ", "<article ", "<a>", "<a  >", "</a>", "href=", "HREF=", "Href=",
    "href='", 'href="', "href=u", "href=''", 'href=""', "'", '"', ">", "<", "`", "“", "”",
    '<a href="u">', "<a href='v'>", '<a href="u" href="w">', "<a x=1 href='h' y=2>", "<a href=\">",
    "https://bare.example/p", "(https://paren.example/p)", "x" * 50, "é",
]  # fmt: skip


def _fuzz_document(rng: random.Random) -> str:
    return "".join(rng.choice(_TOKENS) for _ in range(rng.randint(1, 30)))


def test_identical_results_on_twenty_thousand_fuzzed_documents() -> None:
    rng = random.Random(20261009)
    outcomes = {n: [0, 0] for n in ("markdown", "relative", "html_a", "linky")}
    raised = links = 0
    for _ in range(20000):
        text = _fuzz_document(rng)
        _same(text)
        for line in text.splitlines():
            _count(outcomes, line)
        kind, got = _outcome(lambda t=text: ap.extract_index_links(t, BASE))
        raised += kind == "raised"
        links += len(got) if kind == "ok" else 0
    _assert_not_idle(outcomes, 1000)
    # 整个函数的对照：抛异常的文档（比的是「新旧一起抛」）和正常返回链接的文档都要出现足够多次
    assert 1000 <= raised <= 15000 and links >= 10000, (raised, links)


# ── 3. 已知有链接的行，随机改 1-4 处（专打边界）与按结构拼的链接列表 ─────────────
_SEED_LINES = [
    "- [Getting started](/getting-started)",
    "* [API](https://acme.invalid/api) - the api",
    "  [a](b)",
    "[x](/y/z.md): notes",
    "<a href=\"/docs/a\">docs</a> and <a href='/docs/b'>more</a>",
    "see <A HREF='/x'>x</A>",
    '<a class=link href="https://acme.invalid/p" target=_blank>p</a>',
    "[one](/1) [two](/2) [three](https://acme.invalid/3)",
    "text https://acme.invalid/bare and (https://acme.invalid/in-parens) text",
    "[a [nested] b](/c)",
    "[x](y z) [x](/q)",
]
_EDIT_ALPHABET = [
    *"[]()<>/'\"= -*#ahrefAHREFxy", "](", "[x](", "<a ", "href=", "href='", 'href="', "http://[",
    *_INLINE_WS,
]  # fmt: skip


def _mutated_seed(rng: random.Random) -> str:
    text = rng.choice(_SEED_LINES) + rng.choice(["", " ", "\n", "\n" + rng.choice(_SEED_LINES)])
    for _ in range(rng.randint(1, 4)):
        i = rng.randint(0, len(text))
        op = rng.randrange(4)
        if op == 0:
            text = text[:i] + text[i + 1 :]  # delete one character
        elif op == 1:
            text = text[:i] + rng.choice(_EDIT_ALPHABET) + text[i:]  # insert
        elif op == 2:
            text = text[:i] + rng.choice(_EDIT_ALPHABET) + text[i + 1 :]  # replace
        else:
            j = rng.randint(i, len(text))
            text = text[:j] + text[i:j] + text[j:]  # repeat a slice
    return text


def _count(outcomes: dict[str, list[int]], line: str) -> None:
    got = {
        "markdown": bool(list(ap._bracket_links(line, relative=False))),
        "relative": bool(list(ap._bracket_links(line, relative=True))),
        "html_a": bool(list(ap._html_a_links(line))),
        "linky": ap._is_linky_line(line),
    }
    for name, hit in got.items():
        outcomes[name][hit] += 1


def _assert_not_idle(outcomes: dict[str, list[int]], floor: int) -> None:
    for name, (no, yes) in outcomes.items():
        assert no >= floor and yes >= floor, f"fuzz 空转：{name} 的否/是只有 {no}/{yes}"


def test_identical_results_on_thirty_thousand_edited_seed_documents() -> None:
    rng = random.Random(20261010)
    outcomes = {n: [0, 0] for n in ("markdown", "relative", "html_a", "linky")}
    for _ in range(30000):
        text = _mutated_seed(rng)
        _same(text)
        for line in text.splitlines():
            _count(outcomes, line)
    _assert_not_idle(outcomes, 2000)


def _structured_line(rng: random.Random) -> str:
    def ws() -> str:
        return rng.choice(["", "", " ", "  ", "\t", rng.choice(_INLINE_WS)])

    def url() -> str:
        return rng.choice(
            ["/a", "/a/b.md", "https://h.invalid/p", "//h/p", "/", "a/b", "#top", "/x?y=(1)", "u"]
        )

    def text() -> str:
        return rng.choice(["t", "two words", "", "a [b] c", "`code`", " ", "x" * 20])

    parts: list[str] = [ws(), rng.choice(["", "", "-", "*", "- ", "1. "]) + ws()]
    for _ in range(rng.randint(1, 4)):
        kind = rng.randrange(6)
        if kind <= 1:
            close = rng.choice([")", ")", ")", " )", ""])
            title = rng.choice(["", ' "title"'])
            parts.append(f"[{text()}]({ws()}{url()}{title}{close})")
        elif kind == 2:
            quote = rng.choice(["'", '"', "", "'\""])
            attrs = rng.choice(["", " class=x", " target=_blank", " data-a='>'"])
            parts.append(f"<a{attrs} href={quote[:1]}{url()}{quote[-1:]}{attrs}>{text()}</a>")
        elif kind == 3:
            parts.append(rng.choice(["[", "]", "](", "<a ", "<a>", "(", ")", "href=", "'", '"']))
        elif kind == 4:
            parts.append(rng.choice(["https://bare.example/p", "(https://paren.example)", "x"]))
        else:
            parts.append(ws())
        parts.append(rng.choice(["", " ", ", ", " - "]))
    return "".join(parts)


def test_identical_results_on_twenty_thousand_structured_documents() -> None:
    rng = random.Random(20261011)
    outcomes = {n: [0, 0] for n in ("markdown", "relative", "html_a", "linky")}
    for _ in range(20000):
        text = "\n".join(_structured_line(rng) for _ in range(rng.randint(1, 5)))
        _same(text)
        for line in text.splitlines():
            _count(outcomes, line)
    _assert_not_idle(outcomes, 1000)


# ── 3b. 编辑距离 1 的邻域：专打「没有任何字母表想到会出现的字符」 ────────────────────────
def _neighbourhood_pool() -> list[str]:
    pool = [chr(c) for c in range(256)]  # Latin-1 全部：NUL、控制符、反斜杠、反引号、´、·……
    pool += _ALL_WS
    pool += [
        chr(c)
        for c in (
            0x0301, 0x0316, 0x200B, 0x200E, 0x200F, 0x202E, 0x2060, 0xFEFF,  # 组合符、零宽、BOM
            0x2013, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x3002,  # 破折号、弯引号、``•``、``。``
            0x3010, 0x3011, 0x4E2D, 0xFF08, 0xFF09, 0xFF3B, 0xFF3D,  # 全角括号、汉字
            0x017F, 0x0130, 0x0131, 0x212A, 0x1F600,  # ſ İ ı K、emoji
        )
    ]  # fmt: skip
    # ``str.splitlines()`` 切出来的行里不会有换行符；有换行符的字符在这里没有意义
    return [c for c in dict.fromkeys(pool) if len(("a" + c + "b").splitlines()) == 1]


_NEIGHBOUR_SEEDS = [
    "[a](b)", "[a](/b)", "[a](/)", "- [a](b)", "* [a](/b)", "  - [text](https://h.example/p)",
    "[a](b)[c](d)", "[a](b) [c](/d)", "[a](x y) [c](/d)", "[](b)", "[a]()", "[a [b](c) d](e)",
    "- [a](b) text", "text [a](b) more [c](/d) end", "-[a](b)", "\t[a](b)", "[a](b", "[a]",
    "<a href='u'>", '<a href="u">', "<A HREF='u'>", "<a x=1 href='u' y>", '<a href="u" href="w">',
    "<a href='u'><a href='v'>", '<a href="x>y">', "<abbr href='u'>", "<a href=",
    "[a](b) <a href='u'>", "https://bare.example/p [a](b)",
]  # fmt: skip


def _one_edit(seed: str, pool: list[str]) -> Iterator[str]:
    for i in range(len(seed)):
        yield seed[:i] + seed[i + 1 :]  # 删
        for c in pool:
            if c != seed[i]:
                yield seed[:i] + c + seed[i + 1 :]  # 换
    for i in range(len(seed) + 1):
        for c in pool:
            yield seed[:i] + c + seed[i:]  # 插


def test_identical_results_in_the_one_edit_neighbourhood_of_valid_links() -> None:
    pool = _neighbourhood_pool()
    assert len(pool) >= 280, len(pool)
    for must in ("\x00", "\\", "`", "\u00b4", "\u00b7", "\u200b", "\u3002", "\u2022", "+", "0"):
        assert must in pool, hex(ord(must))
    outcomes = {n: [0, 0] for n in ("markdown", "relative", "html_a", "linky")}
    n = 0
    for seed in _NEIGHBOUR_SEEDS:
        for line in _one_edit(seed, pool):
            _same_line(line)
            _count(outcomes, line)
            n += 1
    assert n >= 150_000, n
    _assert_not_idle(outcomes, 5000)


# ── 4. 逐条写出来的边角 ──────────────────────────────────────────────────────
_EDGE_CASES = [
    "",
    "plain text",
    "# heading",
    # --- markdown / 相对路径 -------------------------------------------------------
    "[a](b)",
    "[a](/b)",
    "[a](/)",
    "[a](//b)",
    "[a](/ b)",
    "[a]()",
    "[a](",
    "[a]",
    "[a](b",
    "[a](b c)",
    "[a]( b)",
    "[a](b )",
    "[](b)",
    "[](/b)",
    "[a](b)c)",
    "[a]((b)",
    "[a](b(c))",
    "[a](/b(c))",
    "[[a](b)",
    "[a]](b)",
    "[a [b](c) d](e)",
    "[a](b)]",
    "]a[(b)",
    "[a][b](c)",
    "[a](b)[c]",
    "[a] [b](c)",
    "[[]](b)",
    "[a](b)[c](/d)[e](f)",
    "[a](/b) [c](/d)",
    "[a]x[b](c)",
    "[a](b c)[d](e)",
    "[a]([b](c)",
    "[a](b)(c)",
    "[a]((",
    "[a](()",
    "[a](/(",
    "[a](http://[)",
    "[a](https://[::1]/x)",
    "[a](b)[c](http://[)",
    "text [a](b) text [c](/d)",
    '[a](b"c)',
    "[a](b'c)",
    "[ a ]( b )",
    "[a](<b>)",
    "[a](`b`)",
    "[a](b)" + chr(0x301),
    # --- <a href> ----------------------------------------------------------------
    '<a href="u">',
    "<a href='u'>",
    '<A HREF="u">',
    "<a href=u>",
    '<a href="">',
    "<a href=''>",
    '<a href="u" href="w">',
    '<a href=\'u\' class="c" href="w">',
    "<a x=\"href='u'\">",
    '<a>href="u"',
    '<ahref="u">',
    '<a  href="u">',
    '<a\thref="u">',
    '<a href ="u">',
    '<a href= "u">',
    '<abbr href="u">',
    "<article href='u'>",
    '<a href="u>v">',
    '<a href=">u">',
    '<a href="u"',
    '<a href="u',
    "<a href=\"u'",
    "<a href='u\"",
    '<a href="u"<a href="v">',
    '<a <a href="u">',
    '<a x> <a href="u">',
    '<a href="u" > <a href="v">',
    '<a href="u">x</a><a href="v">y</a>',
    '<a href="x><b>y">',
    "<a",
    "<a ",
    "<a>",
    "<a >",
    "<a href='",
    '<a href="',
    "<a href=''>",
    "<a href='u'",
    "<a  >href='u'>",
    "<a x href='u'",
    '<a href="u" x=">" href="w">',
    '<a href="1"><a href="2"><a href="3">',
    "<a href='u'>[b](c)",
    "[b](c)<a href='u'>",
    "<a href='[b](c)'>",
    "<a href='href='x'>",  # 两个 href= 首尾相接：后一个是最靠右的有效候选
    "<a href=\"href='x'\">",
    "<a href='href=\"x\"'>",
    "<a href=''href='x'>",
    "<a href='a'href='b'>",
    # --- 链接行 ------------------------------------------------------------------
    "- [a](b)",
    "* [a](b)",
    "  - [a](b)",
    "-[a](b)",
    "- - [a](b)",
    "-- [a](b)",
    "* *[a](b)",
    " [a](b)",
    "x [a](b)",
    "[a]x](b)",
    "[a](x](b)",
    "[a](]b)",
    "-",
    "- ",
    "* ",
    "-[",
    "- [",
    "- []",
    "- [](",
    "- [a](",
    "- [a]()",
    "- [a](b",
    "- [ ]( )",
    "\t- [a](b)",
    "1. [a](b)",
    "> [a](b)",
    # --- 裸 URL（没动，但整个函数要一起比）---------------------------------------
    "https://bare.example/p",
    "(https://paren.example/p)",
    "see https://a.example/b, ok",
    "https://[",
    "x https://[ y",
    "https://a.example/b https://[",
    # --- 每一种空白放进每一个能出现的位置（行内空白）-------------------------------
    *[f"[a]({c}b)" for c in _INLINE_WS],
    *[f"[a](b{c})" for c in _INLINE_WS],
    *[f"[a](b{c}c)" for c in _INLINE_WS],
    *[f"[a{c}b](/c)" for c in _INLINE_WS],
    *[f"{c}[a](b)" for c in _INLINE_WS],
    *[f"-{c}[a](b)" for c in _INLINE_WS],
    *[f"{c}-{c}{c}[a](b)" for c in _INLINE_WS],
    *[f"<a{c}href='u'>" for c in _INLINE_WS],
    *[f"<a href{c}='u'>" for c in _INLINE_WS],
    *[f"<a href='u'{c}>" for c in _INLINE_WS],
    *[f"<a href='{c}u'>" for c in _INLINE_WS],
    *[f"<a href='u{c}v'>" for c in _INLINE_WS],
    # 行分隔符：splitlines 把它们切成两行
    *[f"[a]({c}b)" for c in _LINE_BREAKS],
    *[f"- [a](b){c}- [c](/d)" for c in _LINE_BREAKS],
    *[f"<a{c}href='u'>" for c in _LINE_BREAKS],
    *[f"{c}{c}[a](b){c}" for c in _LINE_BREAKS],
    # 长一点的空白
    "[a](" + " " * 101 + "b)",
    "  " * 500 + "[a](b)",
    "  " * 500 + "x",
    " " * 1001 + "-" + " " * 1001 + "[a](b)",
]


@pytest.mark.parametrize("text", _EDGE_CASES, ids=[f"edge{i:03d}" for i in range(len(_EDGE_CASES))])
def test_identical_results_on_hand_written_edge_cases(text: str) -> None:
    _same(text)


def test_identical_results_on_case_variants_of_the_edge_cases() -> None:
    """``<a`` 和 ``href=`` 带 ``re.I``，其余不带：每条边角整体转成大写 / 小写 / 大小写互换再比。"""
    for text in _EDGE_CASES:
        if len(text) > 5000:
            continue
        for variant in (text.upper(), text.lower(), text.swapcase()):
            _same(variant)


# ── 5. 超大输入 ──────────────────────────────────────────────────────────────
def _plain(n: int) -> str:
    return "ab " * (n // 3) + "a" * (n % 3)


_AFTER_PREFIX = {
    "markdown": "[a](b)",
    "relative": "[a](/b)",
    "html_a": "<a href='u'>",
    "bare-and-markdown": "https://a.example/b [c](d)",
}
# 前面垫的字数刚好越过 10 万、1 MiB、4 MiB；8 MiB 是 Fetcher 交付的正文上限
_PREFIX_CASES = [(s, c) for s in (100_001, 1_048_577, 4_194_305) for c in _AFTER_PREFIX] + [
    (8_388_001, c) for c in ("markdown", "html_a")
]


@pytest.mark.parametrize(
    ("size", "construct"), _PREFIX_CASES, ids=[f"{s}-{c}" for s, c in _PREFIX_CASES]
)
def test_a_link_after_a_long_prefix_on_one_line_is_still_found(size: int, construct: str) -> None:
    """一行里前面垫了很多普通文字：任何「只在前 N 字节里找」的上限，只要 N 在这几个尺寸以内，
    都会在这儿露馅。"""
    _same_big(_plain(size) + _AFTER_PREFIX[construct])


_LONG_CONSTRUCT = {
    "long-link-text": lambda n: "[" + "x" * n + "](u)",
    "long-url": lambda n: "[a](" + "u" * n + ")",
    "long-relative-url": lambda n: "[a](/" + "u" * n + ")",
    "long-link-text-and-url": lambda n: "[" + "x" * n + "](/" + "y" * n + ")",
    "long-attribute-run": lambda n: "<a " + "x " * (n // 2) + "href='u'>",
    "long-attribute-run-after": lambda n: "<a href='u' " + "x " * (n // 2) + ">",
    "many-hrefs-in-one-tag": lambda n: "<a " + "href='x' " * (n // 9) + ">",
    "long-html-url": lambda n: "<a href='" + "u" * n + "'>",
    "html-url-made-of-gt": lambda n: "<a href='" + ">" * n + "'>",
    "html-url-with-lots-of-hrefs": lambda n: "<a href='" + "href=" * (n // 5) + "'>",
    "long-whitespace-then-link": lambda n: " " * n + "[a](b)",
    "linky-long-text-and-url": lambda n: "- [" + "x" * n + "](" + "y" * n + ")",
    "linky-text-never-closes": lambda n: "[" + "x" * n,
    "long-url-never-closes": lambda n: "[a](" + "u" * n,
}


@pytest.mark.parametrize("construct", list(_LONG_CONSTRUCT))
@pytest.mark.parametrize("size", [100_001, 4_194_305])
def test_a_single_very_long_construct_is_still_recognised(size: int, construct: str) -> None:
    """单个结构本身就超过 10 万 / 4 MiB 字节：不能因为「太长」就当成没匹配。"""
    _same_big(_LONG_CONSTRUCT[construct](size))


# 开头「走不通」的很多个，后面再跟一个能成的：任何「看了 N 个就放弃」的守卫都会在这儿露馅。
# 这些走不通的开头每个在旧正则上都是 O(1)，所以旧正则仍是线性的，可以拿来当对照。
_MANY_DEAD = {
    "brackets-then-space": ("[x] ", "[a](b)"),
    "brackets-then-text": ("[x]x", "[a](/b)"),
    "url-with-a-space": ("[x](u v)", "[a](b)"),
    "anchor-without-href": ("<a x>", "<a href='u'>"),
    "anchor-with-unquoted-href": ("<a href=u>", "<a href='v'>"),
    "anchor-with-empty-href": ("<a href=''>", "<a href='v'>"),
    "empty-url": ("[x]()", "[a](b)"),
}
_MANY_DEAD_CASES = [(name, n) for name in _MANY_DEAD for n in (1_000, 100_000)] + [
    ("brackets-then-space", 1_000_000),
    ("anchor-without-href", 1_000_000),
]


@pytest.mark.parametrize(
    ("name", "count"), _MANY_DEAD_CASES, ids=[f"{n}-{c}" for n, c in _MANY_DEAD_CASES]
)
def test_a_link_after_many_dead_openings_is_still_found(name: str, count: int) -> None:
    dead, live = _MANY_DEAD[name]
    _same_big(dead * count + live, functions=count <= 1_000)


@pytest.mark.parametrize("count", [1_000, 100_000, 400_000])
@pytest.mark.parametrize(
    "unit", ["[a](/b) ", "[a](b)", "<a href='u'>", "<a href='u' href='v'>", "[a](b) <a href='u'>"]
)
def test_many_links_on_one_line_are_all_found(unit: str, count: int) -> None:
    """成千上万条链接挤在一行里：每一条都要按原来的顺序吐出来。"""
    _same_big(unit * count, functions=count <= 1_000)


def test_the_hostile_line_that_the_old_regexes_choke_on_is_answered_the_same_when_small() -> None:
    """旧正则在这些行上是平方级的，所以只能比小的；大的在下面的计时守卫里只计时。"""
    for unit in ("<a ", "[x](", "[x](/", "[x]()", "[x](u ", "[", "]", "<a href=", '<a href="'):
        for n in (1, 2, 7, 50, 400):
            _same(unit * n)
            _same(unit * n + "[a](b)")
            _same(unit * n + "<a href='u'>")
    for n in (0, 1, 2, 7, 50, 400, 3000):
        _same(" " * n + "x")
        _same(" " * n + "[a](b)")
        _same(" " * n + "-" + " " * n + "[a](b")
        _same("-" + " " * n + "[a" + " " * n + "](b)")


# ── 6. 计时守卫：线性 ────────────────────────────────────────────────────────
def _scan(line: str) -> None:
    """被改的那四样东西：三个生成器和是 / 否函数，对同一行各跑一遍（把结果吃掉）。"""
    for _ in ap._bracket_links(line, relative=False):
        pass
    for _ in ap._bracket_links(line, relative=True):
        pass
    for _ in ap._html_a_links(line):
        pass
    ap._is_linky_line(line)


#: 家族 -> (生成函数, 「密」吗)。密 = 由大量很小的结构组成：实现里每个结构都要付 Python 层面的
#: 循环开销，所以它们的阶梯只到 2 MB；其余每个字节都便宜，阶梯到 4 MB（每次只是 str.find 的平方级
#: 在 1 MB 上躲得过 1 MB 的线）。后面括号里是旧正则在 100 KB 上的耗时，只是备忘。
_PATHOLOGICAL = {
    "open-brackets": (lambda n: "[" * n, False),
    "close-brackets": (lambda n: "]" * n, False),
    "bracket-text-never-closes": (lambda n: "[a" * (n // 2), False),
    # 很多个 ``[`` 共用远处的同一个 ``]``：每个 ``[`` 各自去找 ``]`` 就是平方级（每次只是 str.find）
    "opens-then-one-close": (lambda n: "[" * n + "]x", False),
    "opens-then-one-dead-link": (lambda n: "[" * n + "](u v)", False),
    "anchor-open-no-gt": (lambda n: "<a " * (n // 3), False),  # 旧：平方（64 KB 要几秒）
    "anchor-href-no-gt": (lambda n: "<a href=" * (n // 8), False),
    "anchor-href-quote-no-gt": (lambda n: '<a href="' * (n // 9), False),
    "anchor-one-gt-at-the-end": (lambda n: "<a x " * (n // 5) + ">", False),
    "spaces-then-x": (lambda n: " " * n + "x", False),  # 旧：平方（64 KB 要几秒）
    "spaces-then-bracket": (lambda n: " " * n + "[", False),
    "url-never-closes": (lambda n: "[a](" + "u" * n, False),
    "url-of-open-parens": (lambda n: "[a](" + "(" * n, False),
    "link-text-never-closes": (lambda n: "[" + "a" * n, False),
    "bracket-url-spaces": (lambda n: "[a](" + " " * n + ")", False),
    # 很多个「走不通」的小结构：「搜到行尾再比」「每个结构复制一份余下的行」这类自然的平方级写法，
    # 只有在这些家族上才露出来（没有 ``]`` / ``>`` 的家族里它们都提前结束了）
    "markdown-no-close": (lambda n: "[x](" * (n // 4), True),  # 旧：平方
    "markdown-url-then-space": (lambda n: "[x](u " * (n // 6), True),
    "relative-no-close": (lambda n: "[x](/" * (n // 5), True),
    "bracket-pairs": (lambda n: "[]" * (n // 2), True),
    "bracket-word": (lambda n: "[x]x" * (n // 4), True),
    "markdown-empty-url": (lambda n: "[x]()" * (n // 5), True),
    "anchor-plain": (lambda n: "<a>" * (n // 3), True),
    "anchor-class": (lambda n: "<a class=x>" * (n // 11), True),
    "anchor-href-unquoted": (lambda n: "<a href=x>" * (n // 10), True),
    "anchor-href-empty": (lambda n: '<a href="">' * (n // 11), True),
    "anchor-href-then-gt": (lambda n: '<a href=">x">' * (n // 13), True),
    "anchor-two-hrefs-dead": (lambda n: "<a href=x href=y>" * (n // 17), True),
    "markdown-ok": (lambda n: "[x](y)" * (n // 6), True),
    "relative-ok": (lambda n: "[x](/y)" * (n // 7), True),
    "anchor-ok": (lambda n: "<a href='x'>" * (n // 12), True),
    "anchor-many-hrefs-one-tag": (lambda n: "<a " + "href='x' " * (n // 9) + ">", True),
    "mixed": (lambda n: "[x](/y)<a href='z'>[x](u <a [a]" * (n // 33), True),
}

_SIZES = {
    False: (20_000, 100_000, 1_000_000, 4_000_000),
    True: (20_000, 100_000, 500_000, 2_000_000),
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


def _timed(line: str, limit: float) -> float:
    t = _CLOCK()
    with _deadline(limit * 3):
        _scan(line)
    return _CLOCK() - t


@pytest.mark.parametrize("name", list(_PATHOLOGICAL))
def test_link_extraction_on_hostile_input_is_linear(name: str) -> None:
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
    """上面的计时守卫只计时、不看结果；这里在旧正则还跑得动的小尺寸上把结果比一遍。"""
    make, _dense = _PATHOLOGICAL[name]
    line = make(4_000)
    _same(line)
    _same(line + "[a](b)<a href='u'>")


@pytest.mark.parametrize("name", ["anchor-open-no-gt", "markdown-no-close", "spaces-then-x"])
def test_extracting_from_a_hostile_file_is_not_stalled(name: str) -> None:
    """评审里的原始复现：旧代码对一行 100 KB 的这类输入，``extract_index_links`` / ``index_shape``
    各要几秒到十几秒。走真实的函数（含 ``urljoin``）。"""
    line = _PATHOLOGICAL[name][0](100_000)
    t = time.perf_counter()
    with _deadline(30):
        ap.extract_index_links(line + "\n" + line, BASE)
        ap.index_shape(line + "\n" + line)
    assert time.perf_counter() - t < 1.5
