"""``fetch/jsrender.py`` 的五个标签信号必须是线性的 —— 而且「是 / 否」与旧的单条正则完全相同。

## 缺陷

``detect_js_dependency`` 用八条正则找「需要 JS」的信号，其中五条长成
``<div[^>]+id=…[^>]*>…``、``<script[^>]+src=``、``<noscript[^>]*>…`` 的样子。
``[^>]+`` 先吃到下一个 ``>``（没有就吃到页面末尾），再一个字符一个字符地退回去
找 ``id=``；每个 ``<div`` 开头都把同一段文字重来一遍。20 KB 的 ``<div id='app'``
× N（没有 ``>``）要 8 s，50 KB 起超过 20 s（立方级）；``<div `` × N 100 KB
要 14 s、``<script `` × N 要 2.8 s（平方级）。``classify_response`` 对每个没被判成
拦截页 / 404 / 5xx 的 HTML 响应都调它（``geo-audit page`` 也调），所以一个恶意
（或者只是坏掉的）页面就能让一次体检卡住。

范围：这里只管 jsrender 的信号。同一仓库里别处的正则（例如
``checks/ai_path.py``）不在本文件的保证里。

## 这组测试怎么证明「没改行为」

八个信号在 ``detect_js_dependency`` 里都只当「是 / 否」用。旧的单条正则原样留在
本文件里当**对照（oracle）**，旧的 ``detect_js_dependency`` 也整份留着（连同它用的
两个阈值和三条没改的正则，不从被测模块里取），与新实现比：

1. 全部冻结响应（真实站点的正文 + 它们的状态码与响应头）；
2. 两万篇由「标记词汇表」随机拼出来的文档 —— 词汇表专挑会让正则和手写扫描器分歧
   的写法：``>`` 的位置、``</div >``、注释、``<!-->``、``\\s`` 接受的**每一个**
   空白字符（枚举出来的）、不带引号的 ``id=``、``<ſcript``（``re.IGNORECASE`` 把
   ``ſ`` 当成 ``s``）、``<dıv``。词汇表对复合信号几乎没有「是」，所以另有两个生成器；
3. 两万篇「按结构拼出来」的页面（挂载点 + 注释 + 至多三个标签 + ``<script``、
   noscript + 距离恰好在 600 字上下的需求短语、redoc / swagger），以及三万篇「已知为
   是的种子页随机改 1-4 处」的页面（专打边界）。两者都断言每个信号的「是」和「否」
   出现了足够多次 —— fuzz 不是空转 —— 并对每一篇比对整份 ``JsAssessment``；
4. 一组逐条写出来的边角：noscript 的 600 字窗口两侧、500 字的「文字太少」线两侧、
   每个 ``\\s`` 位置上的每一种空白、上百上千个空白字符的长串；
5. 超大输入。Fetcher 交付的正文最多 8 MiB（``MAX_CACHE_BODY``），所以最大一档取
   8 MiB：前面垫 100 KB / 1 MiB / 4 MiB / 8 MiB 的普通文字或「只有标记」的文字再接
   一个信号；信号前面有上千到上百万个标签、上万个注释候选；单个超过 100 KB /
   4 MiB 的属性段、注释、空白。

## 它证明不了什么

* 超大输入只覆盖上面列出的尺寸和形状：证明不了「实现里不存在任何上限」，只能保证
  这些尺寸以内没有；
* 计时守卫靠**增长倍数**抓平方级：同一个家族，最大一档的耗时 / 四分之一大小的耗时，
  线性约 4 倍，平方约 16 倍。这与机器速度、``--cov`` 插桩（CI 带它）无关；绝对时间
  上限（每 MB 10 s 加 0.5 s）只是兜底，余量很大。靠墙钟抓不到常数级的退化，也不是
  每一种慢写法都抓得到；这里的家族是对着「自然的平方级写法」逐个试出来的。
"""

from __future__ import annotations

import contextlib
import random
import re
import signal
import time
from collections.abc import Iterator

import pytest

from geo_audit.fetch import jsrender as js
from geo_audit.fixtures import FixtureStore, split_fixture_key
from geo_audit.models import JsAssessment

# 例外拼写和空白一律用 chr() 构造，不在源码里直接打不可见字符。
_DOTLESS_I = chr(0x131)  # re.I：i ~ ı
_DOTTED_I = chr(0x130)  # re.I：i ~ İ
_LONG_S = chr(0x17F)  # re.I：s ~ ſ
#: ``\s`` 接受的每一个字符（枚举出来的，不是手挑的）
_ALL_WS = [c for c in map(chr, range(0x10000)) if re.fullmatch(r"\s", c)]


def test_the_whitespace_alphabet_is_the_whole_of_backslash_s() -> None:
    """生成器里的空白是枚举出来的；这条只确认枚举没有退化成手挑的几个。"""
    assert len(_ALL_WS) >= 25
    must_have = (
        " ",
        "\t",
        "\n",
        "\x0b",
        "\x0c",
        "\x1c",
        "\x85",
        chr(0xA0),
        chr(0x2028),
        chr(0x3000),
    )
    for must in must_have:
        assert must in _ALL_WS, hex(ord(must))


# ── 旧实现（逐字保留，当对照）─────────────────────────────────────────────────
_OLD_EMPTY_MOUNT_RE = re.compile(
    r"<div[^>]+id=[\"'](?:root|app|__next|__nuxt|application|main-content)[\"'][^>]*>\s*</div>",
    re.I,
)
_OLD_MOUNT_THEN_SCRIPT_RE = re.compile(
    r"<div[^>]+id=[\"'](?:root|app|__next|__nuxt)[\"'][^>]*>\s*(?:<!--.*?-->\s*)?</div>\s*(?:<[^>]+>\s*){0,3}<script",
    re.I | re.S,
)
_OLD_API_DOC_SPA_RE = re.compile(
    r"<redoc\b|<div[^>]+id=[\"']redoc[\"']|<rapi-doc\b|id=[\"']swagger-ui[\"']\s*>\s*</div>"
    r"|Redoc\.init\(|SwaggerUIBundle\(",
    re.I,
)
_OLD_NOSCRIPT_DEMAND_RE = re.compile(
    r"<noscript[^>]*>(?:(?!</noscript>).){0,600}"
    r"(?:enable\s+javascript|requires\s+javascript|javascript\s+(?:is\s+)?(?:required|disabled)"
    r"|需要?启用\s*javascript|请开启\s*javascript)",
    re.I | re.S,
)
_OLD_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=", re.I)
# 这三条和两个阈值本 PR 没动；在这里留一份逐字副本，被测模块里它们变了这里就红。
_OLD_EMPTY_SHELL_TEXT_LEN = 200
_OLD_THIN_TEXT_LEN = 500
_OLD_NUXT_RE = re.compile(r"window\.__NUXT__|data-server-rendered=[\"']false[\"']", re.I)
_OLD_NEXT_DATA_RE = re.compile(r"id=[\"']__NEXT_DATA__[\"']", re.I)
_OLD_CONTENT_ELEMENT_RE = re.compile(r"<(?:p|li|h2|h3|article|table|dd)\b", re.I)

#: 信号名 -> (旧正则, 新的是/否函数)
_PREDICATES = {
    "script_src": (_OLD_SCRIPT_SRC_RE, js._has_script_src),
    "empty_mount": (_OLD_EMPTY_MOUNT_RE, js._has_empty_mount),
    "mount_then_script": (_OLD_MOUNT_THEN_SCRIPT_RE, js._has_mount_then_script),
    "api_doc_spa": (_OLD_API_DOC_SPA_RE, js._has_api_doc_spa),
    "noscript_demand": (_OLD_NOSCRIPT_DEMAND_RE, js._has_noscript_demand),
}


def _old_detect_js_dependency(
    status: int, headers: dict[str, str], body: str, *, url: str = ""
) -> JsAssessment:
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type and content_type not in ("text/html", "application/xhtml+xml"):
        return JsAssessment(False, "high", ("non_html_body",), len(body), len(body))

    text = js.visible_text(body)
    vlen, rlen = len(text), len(body)
    hard: list[str] = []
    soft: list[str] = []

    has_script_src = bool(_OLD_SCRIPT_SRC_RE.search(body))

    if vlen < _OLD_EMPTY_SHELL_TEXT_LEN and has_script_src and rlen > 5 * max(vlen, 1):
        hard.append(f"empty_shell(visible={vlen},raw={rlen})")

    if _OLD_MOUNT_THEN_SCRIPT_RE.search(body) or (
        _OLD_EMPTY_MOUNT_RE.search(body) and vlen < _OLD_THIN_TEXT_LEN
    ):
        hard.append("empty_spa_mount")

    if _OLD_API_DOC_SPA_RE.search(body):
        hard.append("api_doc_spa(redoc/swagger/rapidoc)")

    if _OLD_NOSCRIPT_DEMAND_RE.search(body):
        soft.append("noscript_demands_js")
    if _OLD_NUXT_RE.search(body):
        soft.append("nuxt_client_only")
    if _OLD_NEXT_DATA_RE.search(body) and not _OLD_CONTENT_ELEMENT_RE.search(body):
        soft.append("next_data_without_content_elements")
    if vlen < _OLD_THIN_TEXT_LEN and has_script_src and rlen > 3000:
        soft.append(f"thin_text({vlen})")
    if not _OLD_CONTENT_ELEMENT_RE.search(body) and rlen > 2000:
        soft.append("no_content_elements")

    if hard:
        return JsAssessment(True, "high", tuple(hard + soft), vlen, rlen)
    if len(soft) >= 2:
        return JsAssessment(True, "low", tuple(soft), vlen, rlen)
    return JsAssessment(False, "high", tuple(soft), vlen, rlen)


_HTML = {"content-type": "text/html"}


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


def _same_predicates(body: str) -> None:
    for name, (old, new) in _PREDICATES.items():
        assert bool(old.search(body)) == new(body), (name, body[:300])


def _same_assessment(status: int, headers: dict[str, str], body: str) -> None:
    got = js.detect_js_dependency(status, headers, body)
    assert got == _old_detect_js_dependency(status, headers, body), body[:300]


def _same(body: str) -> None:
    _same_predicates(body)
    _same_assessment(200, _HTML, body)


def _same_big(body: str) -> None:
    """超大输入用：同 ``_same``，外加期限（旧正则在这些输入上都是线性的，几秒就够）。"""
    with _deadline(120):
        _same(body)


# ── 1. 全部冻结响应 ──────────────────────────────────────────────────────────
def test_identical_answers_on_every_frozen_response() -> None:
    store = FixtureStore.default()
    keys = list(store.snapshots())
    assert len(keys) >= 1000, f"语料里只剩 {len(keys)} 条快照，这条对照失去意义"
    for key in keys:
        url, variant = split_fixture_key(key)
        snap = store.get(url, variant=variant)
        body = store.stored_body(key).decode("utf-8", "replace")
        _same_predicates(body)
        _same_assessment(snap.status, snap.headers, body)


# ── 2. 随机文档（标记词汇表）─────────────────────────────────────────────────
_TOKENS = [
    "<div", "<DIV", "<div ", "<Div\n", f"<d{_DOTLESS_I}v ", f"<d{_DOTTED_I}v ", "<divx ",
    "id='app'", 'id="root"', 'id="__next"', "id='__nuxt'", "id='application'",
    "id='main-content'", "id='redoc'", "id='swagger-ui'", "id=app", "ID='APP'", "id = 'app'",
    "id='app", "id='apps'", " id='app' ", "data-x=\"id='app'\"",
    ">", "<", "<>", "<<", ">>", "/>", " >", "\n>", "</div>", "</DIV >", "</div\n>", "</ div>",
    "<!--", "-->", "<!---->", "<!-- x -->", "<!-->", "<!--->", "--!>",
    "<script", "<script ", "<script src=x>", "<script src='a'>", "<SCRIPT SRC=x", "<scriptsrc=x",
    f"<{_LONG_S}cript src=x>", "<scripts ", "src=", "SRC=", f"{_LONG_S}rc=", "</script>",
    "<noscript>", "<noscript ", "<noscript x>", "</noscript>", "</NOSCRIPT>",
    f"</no{_LONG_S}cript>", f"<no{_LONG_S}cript>", "<noscripts>",
    "enable javascript", "Enable  JavaScript", "requires\tjavascript", "javascript is required",
    "javascript disabled", "javascript required", "javascript  is  disabled",
    "需要启用javascript", "需启用 JavaScript", "请开启 javascript", "enablejavascript",
    "<redoc", "<redocs", "<rapi-doc", "<rapi-docx", "Redoc.init(", "SwaggerUIBundle(",
    "<p>", "<li>", "<h2>", "<table>", "<span>", "<b>", "<a href='x'>",
    "id='__NEXT_DATA__'", "window.__NUXT__", "data-server-rendered='false'",
    " ", "  ", "\n", "\t", *_ALL_WS, "x", "x" * 20, "é", _DOTLESS_I, _DOTTED_I, _LONG_S,
    "x" * 300, "x" * 599, "<span>y</span>" * 120,
]  # fmt: skip


def _fuzz_document(rng: random.Random) -> str:
    return "".join(rng.choice(_TOKENS) for _ in range(rng.randint(1, 40)))


def test_identical_answers_on_twenty_thousand_fuzzed_documents() -> None:
    rng = random.Random(20261008)
    for _ in range(20000):
        _same(_fuzz_document(rng))


# ── 3. 随机页面（按结构拼）──────────────────────────────────────────────────
_MOUNT_IDS = [
    "id='app'", 'id="root"', 'id="__next"', "id='__nuxt'", "id='application'", "id='main-content'",
    "id='redoc'", "ID='App'", "id=app", "id='apps'", "id='root", "data-x=\"id='app'\"",
]  # fmt: skip
_WS = ["", "", " ", " ", "\n", "  ", "\t", *_ALL_WS]
_PHRASES = [
    "enable javascript", "Enable  JavaScript", "requires\njavascript", "javascript is required",
    "javascript disabled", "需要启用javascript", "请开启 javascript", "enablejavascript",
    "enable javascrip",
]  # fmt: skip


def _mount_block(rng: random.Random) -> str:
    attrs = rng.choice(["", " class=x", " data-reactroot", "\n"]) + " " + rng.choice(_MOUNT_IDS)
    attrs += rng.choice(["", "", " class=y", "/", " data-a='>'"])
    opening = (
        rng.choice(["<div", "<div", "<DIV", f"<d{_DOTLESS_I}v"])
        + attrs
        + rng.choice([">", ">", ">", " >", "/>"])
    )
    inner = rng.choice(
        ["", "", rng.choice(_WS), "<!-- c -->", " <!-- c --> ", "<!-- a --> b <!-- c -->",
         "<!--", "<!---->", "<!-->", "<span></span>", "<!-- a -->\n<!-- b -->"]
    )  # fmt: skip
    close = rng.choice(
        ["</div>", "</div>", "</div>", "</DIV>", "</div >", "</div\n>", "</ div>", "</divx>"]
    )
    tags = "".join(
        rng.choice(["<a href=x>", "<span>", "</b>", "<!-- t -->", rng.choice(_WS), "<br/>"])
        for _ in range(rng.choice([0, 0, 1, 2, 3, 4]))
    )
    script = rng.choice(
        [
            "<script src=/a.js></script>",
            "<script>",
            "<SCRIPT",
            f"<{_LONG_S}cript",
            "<scripts>",
            "",
            "",
        ]
    )
    return opening + inner + rng.choice(_WS) + close + rng.choice(_WS) + tags + script


def _noscript_block(rng: random.Random) -> str:
    gap = rng.choice([0, 3, 80, 590, 598, 599, 600, 601, 602, 650, 1200]) + rng.choice([0, 0, 1])
    opening = rng.choice(
        ["<noscript>", "<noscript>", "<NOSCRIPT >", "<noscript x='>'>", "<noscript"]
    )
    early_close = rng.choice(["", "", "", "</noscript>", "</NoScript >"])
    # the closer may sit before the phrase (then the phrase is out of reach) or after it
    filler = rng.choice(["x", " ", "<b>"]) * gap
    cut = rng.randint(0, len(filler)) if early_close else 0
    body = filler[:cut] + early_close + filler[cut:] if early_close else filler
    return opening + body + rng.choice(_PHRASES) + rng.choice(["</noscript>", "", "</NOSCRIPT>"])


def _script_block(rng: random.Random) -> str:
    return rng.choice(
        [
            "<script src=a.js>", "<script async src='a.js'>", "<script>src=x</script>",
            "<script\nsrc=a>", "<SCRIPT SRC=a", "<script", "<scriptsrc=a>",
            f"<{_LONG_S}cript src=a>", "<script data-x='>' src=a>", "<script src=",
            "<script  >src=",
        ]
    )  # fmt: skip


def _doc_block(rng: random.Random) -> str:
    return rng.choice(
        [
            "<redoc spec-url=x>", "<redocs>", "<rapi-doc>", "<div id='redoc'></div>",
            "<div  id=\"redoc\"", "<div id=redoc>", "<div id='swagger-ui'></div>",
            "id='swagger-ui' >\n</div>", "id='swagger-ui'>x</div>", "Redoc.init(spec)",
            "SwaggerUIBundle(", "<div class=a><b id='redoc'>",
        ]
    )  # fmt: skip


def _noise(rng: random.Random) -> str:
    return rng.choice(
        ["<p>text</p>", "<h2>t</h2>", "<span>", " ", "\n", "<!-- c -->", "<a href=x>", ">", "<",
         "x" * rng.choice([5, 300, 700]), "id='__NEXT_DATA__'", "window.__NUXT__"]
    )  # fmt: skip


_BLOCKS = [_mount_block, _noscript_block, _script_block, _doc_block, _noise, _noise]


def _structured_page(rng: random.Random) -> str:
    return "".join(rng.choice(_BLOCKS)(rng) for _ in range(rng.randint(1, 6)))


def _pad(rng: random.Random) -> str:
    """让 ``rlen`` / ``vlen`` 跨过 ``detect_js_dependency`` 里 2000 / 3000 / 200 / 500 的线。"""
    return rng.choice(["", "", "<i></i>" * 400, "word " * 150, "<p>x</p>" * 60, "<i></i>" * 100])


def test_identical_answers_on_twenty_thousand_structured_pages() -> None:
    rng = random.Random(20261009)
    outcomes = {name: [0, 0] for name in _PREDICATES}
    for _ in range(20000):
        page = _structured_page(rng)
        _same_predicates(page)
        for name, (old, _new) in _PREDICATES.items():
            outcomes[name][bool(old.search(page))] += 1
        # whole-function equality, also across the length thresholds
        _same_assessment(200, _HTML, page + _pad(rng))
    for name, (no, yes) in outcomes.items():
        assert no >= 500 and yes >= 500, f"fuzz 空转：{name} 的否/是只有 {no}/{yes}"


# ── 3b. 已知为「是」的页面，随机改 1-4 处（专打边界）─────────────────────────
_SEED_PAGES = [
    "<div id='app'></div><script src=x></script>",
    '<div class="a" id="root"><!-- c --></div><b><i><script>',
    "<div id='__next'>\n</div>\n<script src='/_next/a.js'>",
    "<div id='main-content'> </div>",
    "<noscript>Please enable JavaScript</noscript>",
    "<noscript class=x>" + "x" * 20 + "javascript is required</noscript>",
    "<noscript>x</noscript><noscript>requires javascript",
    "<div id='redoc'></div>",
    "<redoc spec-url=x></redoc>",
    "<div id='swagger-ui'>\n</div>",
    "<script async src='a.js'></script>",
    "<div id='app'><!-- a --><!-- b --></div> <a> <script",
]
_EDIT_ALPHABET = [
    *"<>/!-='\" \nxdivscriptnoes", "</div>", "<!--", "-->", "<script", "id=", "src=",
    _LONG_S, _DOTLESS_I, _DOTTED_I, *_ALL_WS,
]  # fmt: skip


def _mutated_seed(rng: random.Random) -> str:
    page = rng.choice(_SEED_PAGES) + rng.choice(["", rng.choice(_SEED_PAGES)])
    for _ in range(rng.randint(1, 4)):
        i = rng.randint(0, len(page))
        op = rng.randrange(4)
        if op == 0:
            page = page[:i] + page[i + 1 :]  # delete one character
        elif op == 1:
            page = page[:i] + rng.choice(_EDIT_ALPHABET) + page[i:]  # insert
        elif op == 2:
            page = page[:i] + rng.choice(_EDIT_ALPHABET) + page[i + 1 :]  # replace
        else:
            j = rng.randint(i, len(page))
            page = page[:j] + page[i:j] + page[j:]  # repeat a slice
    return page


def test_identical_answers_on_thirty_thousand_edited_seed_pages() -> None:
    rng = random.Random(20261010)
    outcomes = {name: [0, 0] for name in _PREDICATES}
    for _ in range(30000):
        page = _mutated_seed(rng)
        _same_predicates(page)
        for name, (old, _new) in _PREDICATES.items():
            outcomes[name][bool(old.search(page))] += 1
        _same_assessment(200, _HTML, page + _pad(rng))
    for name, (no, yes) in outcomes.items():
        assert no >= 2000 and yes >= 2000, f"fuzz 空转：{name} 的否/是只有 {no}/{yes}"


# ── 4. 逐条写出来的边角 ──────────────────────────────────────────────────────
def _noscript_at(distance: int, *, closer_before_phrase: bool = False) -> str:
    """``<noscript>`` 之后第 ``distance`` 个字符处开始需求短语。"""
    gap = "x" * distance
    if closer_before_phrase:
        gap = gap[: distance // 2] + "</noscript>" + gap[distance // 2 :]
    return "<noscript>" + gap + "enable javascript"


_EDGE_CASES = [
    "",
    "plain text",
    # --- 挂载点 -------------------------------------------------------------
    "<div id='app'></div><script src=x></script>",
    "<div id='app'></div>",
    '<div id="root"><!-- c --></div><script>',
    '<div id="root"><!-- c --></div>',
    "<div id='app'> \n </div>",
    "<div id='app'>x</div>",
    "<div id='app'></div ><script",
    "<div id='app'></ div><script",
    "<div id='application'></div>",  # 只有 empty_mount 认 application / main-content
    "<div id='main-content'></div><script",
    "<div id='application'></div><script",
    "<div id='app'></div><a><b><i><script",  # 三个标签再 <script：可以
    "<div id='app'></div><a><b><i><u><script",  # 四个：不行
    "<div id='app'></div>  <a>  <b>\n<script",
    "<div id='app'></div><script",
    "<div id='app'></div><scripts",
    "<div id='app'></div><SCRIPT",
    f"<div id='app'></div><{_LONG_S}cript",
    "<div id='app'><!-- a --></div><script",
    "<div id='app'><!-- a --><!-- b --></div><script",  # 第二个注释里的 --> 才接 </div>
    "<div id='app'><!-- a --> b <!-- c --></div><script",
    "<div id='app'><!-- a --> b</div><script",
    "<div id='app'><!-- a </div><script",  # 注释没闭合
    "<div id='app'><!-- a --></div></div><script",
    "<div id='app'><!-- a --> </div> <script",
    "<div id='app'><!---->  </div><script",
    "<div id='app'><!-->--></div><script",  # <!-- 自己的 -- 不能当 --> 的一部分
    "<div id='app'><!--->--></div><script",
    "<div id='app'><!-- --></div><!-- x --></div><script",
    "<div id='app'><!--</div><script>-->",
    "<div id='app'></div><!-- x --><script",  # 注释在 </div> 之后：不能算「标签」
    "<div id=app></div><script",  # 没引号：不认
    "<div id=\"app'></div><script",
    "<div id='app\"></div><script",
    "<div ID='APP'></div><script",
    "<div id='apps'></div><script",
    "<divid='app'></div><script",  # <div 与 id 之间至少一个字符
    "<div\nid='app'></div><script",
    "<div id='app'",
    "<div id='app'/>",
    "<div id='app'/></div><script",
    "<div id='app' data-x='>'></div><script",
    "<div data-x='>' id='app'></div><script",  # id 在第一个 > 后面：不算
    "<div class=a><div id='app'></div><script",
    "<div <div id='app'></div><script",
    "<div id='x' <div id='app'></div><script",
    "<div\n<div  id='app'>\n</div><script",
    f"<d{_DOTLESS_I}v id='app'></div><script",  # re.I 把 ı / İ 当成 i
    f"<d{_DOTTED_I}v id='app'></div><script",
    f"<div id='app'></d{_DOTLESS_I}v><script",
    "<div>id='app'</div><script",
    "<p>id='app'</p><div></div><script>",
    "<div id='app'><div id='root'></div></div><script",
    "<div id='app'></div><div id='root'></div><script",
    "<div id='app'>text</div><div id='root'></div><script",
    "<div id='app'>text</div> <div id='root'></div> <script",
    "<div id='app'><!-- x --></div> " * 3 + "<script",
    "<div class=a></div><div id='app'>",  # id 在后一个标签里：不能算前一个
    "<div class=a><div id='app'></div><script",  # 标签紧挨着上一个 > 开头
    "<div id='app'><!---></div><script",  # <!-- 自己的 -- 不能当 --> 用
    "<div id='app'><!--></div><script",
    "<div id='app'><!----></div><script",
    "<div id='app'><!-- a --></div> x <!-- b --></div><script",  # 第一个候选接不上，第二个可以
    "<div id='app'>x</div><div id='root'><!-- c --></div><script",
    "<div id='app'>x</div><div id='root'></div><script",
    "<div id='app'><!-- c -->x</div><div id='root'><!-- c --></div><script",
    "<div id='app'><!-- c -->x</div>" * 4 + "<div id='root'><!-- d --></div><script",
    # 注释分支失败（记住失败）之后，后面的挂载点仍然要看：不论它带不带注释
    "<div id='app'><!--x-->y</div><div id='app'><!--<div id='app'></div><script",
    "<div id='app'><!--x-->y</div><div id='app'></div><script",
    "<div id='app'><!--x-->y</div><div id='app'><!--x--></div><script",
    "<div id='app'> <!---></div><script",  # <!-- 前面的空白要先跳过
    "<div id='app'> <!--x--></div><script",
    *[f"<div id='main-content'></div>{'x' * k}" for k in (0, 1, 498, 499, 500, 501, 502)],
    *[f"<div id='root'></div>{'x' * k}<script src=a>" for k in (0, 499, 500)],
    # \s 接受的每一种空白，放进每一个 \s 能出现的位置
    *[f"<div id='app'>{c}</div>" for c in _ALL_WS],
    *[f"<div id='app'>{c}<!--x-->{c}</div>{c}<a>{c}<script" for c in _ALL_WS],
    *[f"<div id='app'></div>{c}<a>{c}<b>{c}<script" for c in _ALL_WS],
    # --- script src -----------------------------------------------------------
    "<script src=x>",
    "<script>src=x</script>",
    "<script src=",
    "<scriptsrc=x>",
    "<script  src=x",
    "<script\tsrc=x>",
    "<script data-a='>' src=x>",
    "<script <script src=x>",
    "<SCRIPT SRC=x>",
    f"<{_LONG_S}cript {_LONG_S}rc=x>",
    "<script x=y>src=a",
    "<script>",
    "<script ",
    "<script x",
    "<a><script x><b src=x>",
    # --- redoc / swagger ------------------------------------------------------
    "<redoc>",
    "<redocs>",
    "<redoc-x>",
    "<rapi-doc>",
    "<rapi-docs>",
    "<div id='redoc'>",
    '<div id="redoc"',
    "<div id=\"redoc'>",  # 前后引号不一致也算
    "<div id='redoc\">",
    "<div ID='REDOC'>",
    "<REDOC>",
    "<Rapi-Doc>",
    "<div  id='redoc'",
    "<divid='redoc'>",
    "<div id=redoc>",
    "<div data-a='>' id='redoc'>",
    "<div id='swagger-ui'></div>",
    "id='swagger-ui' > </div>",
    "id='swagger-ui'>x</div>",
    "id=\"swagger-ui'>\n</div>",
    "id='swagger-ui\"></div>",
    "ID='SWAGGER-UI'></div>",
    "REDOC.INIT(x)",
    "swaggeruibundle(x)",
    'id="swagger-ui"\n>\n</div>',
    "Redoc.init(x)",
    "SwaggerUIBundle(x)",
    "Redoc.init",
    *[f"id='swagger-ui'{c}>{c}</div>" for c in _ALL_WS],
    "id='swagger-ui'" + " " * 1001 + ">" + " " * 1001 + "</div>",
    # --- noscript ---------------------------------------------------------------
    "<noscript>enable javascript</noscript>",
    "<noscript>Please ENABLE  JavaScript</noscript>",
    "<noscript>javascript is required</noscript>",
    "<noscript>javascript required</noscript>",
    "<noscript>需要启用 JavaScript</noscript>",
    "<noscript>请开启javascript</noscript>",
    "<noscript></noscript>enable javascript",  # 在 </noscript> 之后：够不着
    "<noscript></noscript><noscript>enable javascript",
    "<noscript>a</noscript> enable javascript <noscript>",
    "<noscript></noscript>enable javascript <noscript>zzz",  # 缓存的短语在 </noscript> 之后
    "<noscript>a</noscript><noscript>enable javascript",  # 缓存的 </noscript> 在这个标签前
    "<noscript>x</noscript>" + "y" * 700 + "<noscript>enable javascript",
    "<noscript",
    "<noscript x='>'>enable javascript",
    "<noscripts>enable javascript",
    f"<no{_LONG_S}cript>enable javascript",
    "<noscript>enable javascript",
    f"<noscript>x</no{_LONG_S}cript>enable javascript",
    "<noscript>x</NoScript >enable javascript",
    "<noscript></noscript>" * 3 + "enable javascript",
    _noscript_at(0),
    _noscript_at(599),
    _noscript_at(600),  # 窗口最后一格：够得着
    _noscript_at(601),  # 差一格：够不着
    _noscript_at(602),
    _noscript_at(600, closer_before_phrase=True),
    _noscript_at(10, closer_before_phrase=True),
    _noscript_at(1, closer_before_phrase=True),
    "<noscript>" + "x" * 590 + "</noscript>" + "enable javascript",
    "<noscript>" + "x" * 590 + "enable javascript</noscript>",
    "<noscript>x</noscript>" * 5 + "<noscript>enable javascript",
    "<noscript>" * 3 + "x" * 598 + "enable javascript",
    "<noscript>x" + "<noscript>" * 3 + "enable javascript",
    "<noscript>" + "<noscript>" * 70 + "enable javascript",  # 后面的 <noscript> 离短语更近
    # 短语自己可以超出窗口：窗口只管它从哪里开始
    "<noscript>" + "x" * 590 + "enable" + " " * 50 + "javascript",
    "<noscript>" + "x" * 600 + "enable" + " " * 50 + "javascript",
    "<noscript>" + "x" * 601 + "enable" + " " * 50 + "javascript",
    "<noscript>" + "x" * 600 + "enable" + " " * 200 + "javascript",
    "<noscript>" + "x" * 600 + "enable" + " " * 1200 + "javascript",
    "<noscript>enable" + " " * 101 + "javascript",
    "<noscript>javascript" + " " * 101 + "is" + " " * 101 + "required",
    # 第一个 <noscript> 看不到 </noscript>（太远），第二个的 </noscript> 紧挨着它：窗口要在那里截断
    "<noscript>" + "x" * 100_001 + "<noscript></noscript>enable javascript",
    *[f"<noscript>enable{c}javascript" for c in _ALL_WS],
    *[f"<noscript>javascript{c}is{c}required" for c in _ALL_WS],
    # --- 杂项 ---------------------------------------------------------------
    "<div id='app'></div><noscript>enable javascript</noscript><script src=a>",
    "id='__NEXT_DATA__'",
    "id='__NEXT_DATA__'<p>",
    "ID='__next_data__'",
    "id='__NEXT_DATA__\"",
    "id=\"__NEXT_DATA__'",
    'ID="__Next_Data__"<p>',
    "window.__NUXT__",
    "WINDOW.__nuxt__",
    "data-server-rendered='false'",
    'DATA-SERVER-RENDERED="False"',
    "<script src=x></script>" + "<i></i>" * 500,
    "<div id='root'></div><script src=x></script>" + "<i></i>" * 600,
    "<p>" + "word " * 200 + "</p><script src=x></script>" + "<i></i>" * 500,
]


@pytest.mark.parametrize("body", _EDGE_CASES, ids=[f"edge{i:03d}" for i in range(len(_EDGE_CASES))])
def test_identical_answers_on_hand_written_edge_cases(body: str) -> None:
    _same(body)


@pytest.mark.parametrize("with_content_element", [False, True])
@pytest.mark.parametrize("rlen", [1999, 2000, 2001, 2002, 2999, 3000, 3001, 3002, 10_000])
@pytest.mark.parametrize("vlen", [0, 199, 200, 201, 499, 500, 501])
def test_identical_answers_across_the_length_thresholds(
    vlen: int, rlen: int, with_content_element: bool
) -> None:
    """``detect_js_dependency`` 在可见文字 200 / 500 字、原始 2000 / 3000 字处各画一条线。这里把
    页面的这两个长度分别摆在每条线的两侧：``<script src>`` 开着，注释垫到刚好的原始长度。"""
    head = "<script src=x></script>" + ("<p></p>" if with_content_element else "") + "x" * vlen
    pad = rlen - len(head)
    assert pad >= 7
    body = head + "<!--" + "-" * (pad - 7) + "-->"
    assert len(body) == rlen
    _same(body)


def test_identical_answers_on_case_variants_of_the_edge_cases() -> None:
    """``re.I`` 要留在每一个字面量上：把每条边角整体转成大写 / 小写 / 大小写互换，再比一遍。"""
    for body in _EDGE_CASES:
        if len(body) > 5000:
            continue
        for variant in (body.upper(), body.lower(), body.swapcase()):
            _same(variant)


def test_text_files_are_not_scanned() -> None:
    """非 HTML 响应一进来就返回，不碰任何信号（旧行为）。"""
    body = "<div id='app'></div><script src=x>" * 5
    got = js.detect_js_dependency(200, {"content-type": "text/plain"}, body)
    assert got == _old_detect_js_dependency(200, {"content-type": "text/plain"}, body)
    assert got.signals == ("non_html_body",)


# ── 5. 超大输入 ──────────────────────────────────────────────────────────────
def _filler(n: int) -> str:
    return "ab " * (n // 3) + "a" * (n % 3)


_AFTER_FILLER = {
    "mount-then-script": "<div id='app'></div><script src=x></script>",
    "empty-mount": "<div id='main-content'></div>",
    "script-src": "<script src=x>",
    "redoc": "<div id='redoc'>",
    "swagger": "id='swagger-ui'></div>",
    "noscript": "<noscript>enable javascript</noscript>",
}
# 前面垫的字数刚好越过 10 万、1 MiB、4 MiB；8 MiB 是 Fetcher 交付的正文上限
_PREFIX_CASES = [(size, c) for size in (100_001, 1_048_577, 4_194_305) for c in _AFTER_FILLER] + [
    (8_388_001, c) for c in ("mount-then-script", "script-src", "noscript")
]


@pytest.mark.parametrize(
    ("size", "construct"), _PREFIX_CASES, ids=[f"{s}-{c}" for s, c in _PREFIX_CASES]
)
def test_a_signal_after_a_long_prefix_is_still_found(size: int, construct: str) -> None:
    """任何「只在前 N 字节里找」的上限，只要 N 在这几个尺寸以内，都会在这儿露馅。"""
    _same_big(_filler(size) + _AFTER_FILLER[construct])


_MARKUP_AFTER = {
    "empty-mount": "<div id='main-content'></div>",
    "mount-then-script": "<div id='app'></div><script src=x></script>",
    "script-src": "<script src=x>",
}


@pytest.mark.parametrize("construct", list(_MARKUP_AFTER))
@pytest.mark.parametrize("size", [100_001, 1_048_577, 4_194_305])
def test_a_page_with_no_text_and_a_long_markup_prefix_is_still_assessed(
    size: int, construct: str
) -> None:
    """可见文字很少的页面，``empty_mount`` / ``empty_shell`` / ``thin_text`` 才起作用。前面垫的是
    只有标记的 ``<i></i>``：可见文字仍是 0，整份评估（不只是单个信号）要和旧的一样。"""
    _same_big("<i></i>" * (size // 7) + _MARKUP_AFTER[construct])


_MANY = {
    # 信号前面有成千上万个不匹配的标签 / 注释候选：任何「看了 N 个就放弃」的守卫都会在这儿露馅
    "div-tags-then-mount-and-script": lambda n: "<div>" * n + "<div id='app'></div><script",
    "div-tags-then-empty-mount": lambda n: "<div>" * n + "<div id='main-content'></div>",
    "div-tags-then-redoc": lambda n: "<div>" * n + "<div id='redoc'>",
    "script-tags-then-src": lambda n: "<script>" * n + "<script src=x>",
    "noscript-pairs-then-demand": lambda n: (
        "<noscript></noscript>" * n + "<noscript>enable javascript"
    ),
    "comment-candidates-then-script": lambda n: (
        "<div id='app'><!--" + "--></div>x" * n + "--></div><script"
    ),
    "plain-mounts-then-comment-mount": lambda n: (
        "<div id='app'>x</div>" * n + "<div id='root'><!-- c --></div><script"
    ),
    "dead-comment-mounts-then-plain-mount": lambda n: (
        "<div id='app'><!--x-->y</div>" * n + "<div id='app'></div><script"
    ),
}
# 「带注释的挂载点」连成一长串时，旧的 ``<!--.*?-->`` 对每一个挂载点都扫到页面末尾（旧实现
# 自己就是平方级），所以这一族只能取旧正则还跑得动的个数。
_QUADRATIC_FOR_THE_OLD_REGEX = {"dead-comment-mounts-then-plain-mount"}
_MANY_CASES = [
    (name, n)
    for name in _MANY
    for n in ((1_000, 3_000) if name in _QUADRATIC_FOR_THE_OLD_REGEX else (1_000, 100_000))
] + [
    ("div-tags-then-mount-and-script", 1_000_001),
    ("script-tags-then-src", 400_000),
    ("noscript-pairs-then-demand", 300_000),
    ("comment-candidates-then-script", 400_000),
]


@pytest.mark.parametrize(("name", "count"), _MANY_CASES, ids=[f"{n}-{c}" for n, c in _MANY_CASES])
def test_a_signal_after_many_tags_or_candidates_is_still_found(name: str, count: int) -> None:
    _same_big(_MANY[name](count))


_LONG_CONSTRUCT = {
    # 挂载点标签自己的属性段很长，id 在最后
    "long-attributes": lambda n: "<div " + "x " * (n // 2) + "id='app'></div><script",
    "long-attributes-script-src": lambda n: "<script " + "x " * (n // 2) + "src=a>",
    "long-attributes-redoc": lambda n: "<div " + "x " * (n // 2) + "id='redoc'>",
    "long-attributes-noscript": lambda n: "<noscript " + "x " * (n // 2) + ">enable javascript",
    # id 在最前，其后是很长的属性段
    "long-tail-attributes": lambda n: "<div id='app' " + "x " * (n // 2) + "></div><script",
    "long-comment": lambda n: "<div id='app'><!-- " + "x" * n + " --></div><script",
    "long-gap-between-tags": lambda n: "<div id='app'></div><a " + "x " * (n // 2) + "><script",
    # 每一个 \s* / \s+ 的位置都来一次超长的空白
    "long-whitespace": lambda n: "<div id='app'>" + " " * n + "</div>" + " " * n + "<script",
    "long-whitespace-after-comment": lambda n: "<div id='app'><!--x-->" + " " * n + "</div><script",
    "long-whitespace-between-tags": lambda n: (
        "<div id='app'></div>" + " " * n + "<a>" + " " * n + "<script"
    ),
    "long-whitespace-in-phrase": lambda n: "<noscript>enable" + " " * n + "javascript",
    "long-whitespace-in-late-phrase": lambda n: (
        "<noscript>" + "x" * 600 + "enable" + " " * n + "javascript"
    ),
    "long-whitespace-swagger": lambda n: "id='swagger-ui'" + " " * n + ">" + " " * n + "</div>",
}


@pytest.mark.parametrize("construct", list(_LONG_CONSTRUCT))
@pytest.mark.parametrize("size", [100_001, 4_194_305])
def test_a_single_very_long_construct_is_still_recognised(size: int, construct: str) -> None:
    """单个结构本身就超过 10 万 / 4 MiB 字节：不能因为「太长」就当成没匹配。"""
    _same_big(_LONG_CONSTRUCT[construct](size))


# ── 6. 计时守卫：线性 ────────────────────────────────────────────────────────
#: 家族 -> (生成函数, 「密」吗)。密 = 由大量很小的、带 ``>`` 的标签组成：实现里每个标签都要付
#: Python 层面的循环开销，所以它们的阶梯只到 2 MB；其余（没有 ``>``、整段共用最后那一个
#: ``>``、很长的空白……）每个字节都便宜，阶梯到 4 MB（每次只是 memchr 的平方级在 1 MB 上躲得过）。
_PATHOLOGICAL = {
    "div-id-no-gt": (lambda n: "<div id='app'" * (n // 13), False),
    "div-no-gt": (lambda n: "<div " * (n // 5), False),
    "script-no-gt": (lambda n: "<script " * (n // 8), False),
    "noscript-no-gt": (lambda n: "<noscript " * (n // 10), False),
    "redoc-no-gt": (lambda n: "<div id='redoc'" * (n // 15), False),
    "swagger-spaces": (lambda n: "id='swagger-ui' " * (n // 16), False),
    "mount-then-whitespace": (lambda n: ("<div id='app'>" + " " * 1000) * (n // 1014), False),
    "whitespace-after-mount": (lambda n: "<div id=app>" + " " * n, False),
    "mixed": (lambda n: "<div id='app' <script <noscript <div " * (n // 40), False),
    # 一长串开头共用结尾的那一个 ``>``：每个开头各自去找 ``>`` 就是平方级（每次只是 memchr）
    "div-id-one-gt-at-the-end": (lambda n: "<div id='app' " * (n // 14) + ">", False),
    "script-one-gt-at-the-end": (lambda n: "<script " * (n // 8) + ">", False),
    "noscript-one-gt-at-the-end": (lambda n: "<noscript " * (n // 10) + ">", False),
    "redoc-one-gt-at-the-end": (lambda n: "<div id='redoc' " * (n // 16) + ">", False),
    "comment-candidates-long-tails": (
        lambda n: "<div id=app><!--" + ("--></div><a " + "x" * 400 + ">") * (n // 415),
        False,
    ),
    # 很多带 ``>`` 的小标签。「搜到页面末尾再和标签末尾比」「每个标签复制一份页面」这类
    # 看起来很自然的平方级写法，只有在这些家族上才露出来（没有 ``>`` 的家族里它们都提前结束）
    "div-plain": (lambda n: "<div>" * (n // 5), True),
    "div-class": (lambda n: "<div class=a>" * (n // 13), True),
    "div-other-id": (lambda n: "<div id=x>" * (n // 10), True),
    "script-plain": (lambda n: "<script>" * (n // 8), True),
    "script-no-src": (lambda n: "<script async>" * (n // 14), True),
    "noscript-never-closed": (lambda n: "<noscript>" * (n // 10), True),
    "noscript-pairs": (lambda n: "<noscript></noscript>" * (n // 21), True),
    "noscript-phrase-only-at-the-end": (
        lambda n: "<noscript>" * (n // 10) + "enable javascript",
        True,
    ),
    "noscript-partial-phrases": (lambda n: "<noscript>enable " * (n // 17), True),
    "noscript-near-phrases": (
        lambda n: "<noscript>x</noscript>enable javascript " * (n // 41),
        True,
    ),
    "mount-never-closed": (lambda n: "<div id='app'>" * (n // 14), True),
    "mount-complete": (lambda n: "<div id='app'></div>" * (n // 20), True),
    "mount-unclosed-comment": (lambda n: "<div id='app'><!--" * (n // 18), True),
    "mount-then-tag-run": (lambda n: "<div id='app'></div><" * (n // 21), True),
    "mount-closed-comments": (lambda n: "<div id='app'><!-- x --></div> " * (n // 31), True),
    "mount-comment-then-tags": (
        lambda n: "<div id='app'><!-- x --></div><b><i><u>" * (n // 41),
        True,
    ),
    "mount-plain-comment-alternating": (
        lambda n: "<div id='app'></div>x<div id='app'><!-- x -->y</div> " * (n // 52),
        True,
    ),
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


def _timed(body: str, limit: float) -> float:
    t = time.perf_counter()
    with _deadline(limit * 3):
        js.detect_js_dependency(200, _HTML, body)
    return time.perf_counter() - t


@pytest.mark.parametrize("name", list(_PATHOLOGICAL))
def test_signals_on_hostile_input_are_linear(name: str) -> None:
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
    growth = times[big] / times[small]
    assert growth <= _MAX_GROWTH, (
        f"{name}: {small} B {times[small]:.3f}s -> {big} B {times[big]:.3f}s, "
        f"x{growth:.1f} for x{big // small} the size"
    )


@pytest.mark.parametrize("name", list(_PATHOLOGICAL))
def test_identical_answers_on_the_hostile_families(name: str) -> None:
    """上面的计时守卫只计时、不看答案；这里在旧正则还跑得动的小尺寸上把答案比一遍。"""
    make, _dense = _PATHOLOGICAL[name]
    page = make(4_000)
    _same(page)
    _same(page + "enable javascript</noscript></div><script src=x>")


def test_classifying_a_hostile_page_is_not_stalled() -> None:
    """评审里的原始复现：``classify_response`` 一个 20 KB 的 ``<div id='app'`` × N 的 200 页，旧代码
    7 s（立方级，50 KB 起超过 20 s）。走真实的分类路径。"""
    from geo_audit.fetch.classify import classify_response
    from geo_audit.models import Expect

    body = "<!doctype html><html>" + "<div id='app'" * 1600
    t = time.perf_counter()
    classify_response(200, _HTML, body, url="https://x.test/p", expect=Expect.HTML_PAGE)
    assert time.perf_counter() - t < 0.5
    # 同一页被当成「该是文本文件」（llms.txt 回了 HTML）时走另一条分支，也过 detect_js_dependency
    t = time.perf_counter()
    classify_response(200, _HTML, body, url="https://x.test/llms.txt", expect=Expect.TEXT_FILE)
    assert time.perf_counter() - t < 0.5
