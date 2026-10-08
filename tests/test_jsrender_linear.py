"""``fetch/jsrender.py`` 的五个标签信号必须是线性的 —— 而且「是 / 否」与旧的单条正则完全相同。

## 缺陷

``detect_js_dependency`` 用八条正则找「需要 JS」的信号，其中五条长成
``<div[^>]+id=…[^>]*>…``、``<script[^>]+src=``、``<noscript[^>]*>…`` 的样子。
``[^>]+`` 先吃到下一个 ``>``（没有就吃到页面末尾），再一个字符一个字符地退回去
找 ``id=``；每个 ``<div`` 开头都把同一段文字重来一遍。20 KB 的 ``<div id='app'``
× N（没有 ``>``）要 8 s，50 KB 起超过 20 s（立方级）；``<div `` × N 100 KB
要 14 s、``<script `` × N 要 2.8 s（平方级）。``classify_response`` 对每个 HTML
响应都调它，所以一个恶意（或者只是坏掉的）页面就能让一次体检卡住。

范围：这里只管 jsrender 的信号。同一仓库里别处的正则（例如
``checks/ai_path.py``）不在本文件的保证里。

## 这组测试怎么证明「没改行为」

八个信号在 ``detect_js_dependency`` 里都只当「是 / 否」用。旧的单条正则原样留在
本文件里当**对照（oracle）**，旧的 ``detect_js_dependency`` 也整份留着，与新实现比：

1. 全部冻结响应（真实站点的正文 + 它们的状态码与响应头）；
2. 两万篇由「标记词汇表」随机拼出来的文档 —— 词汇表专挑会让正则和手写扫描器分歧
   的写法：``>`` 的位置、``</div >``、注释、``<!-->``、``\\s`` 的各种空白
   （``\\xa0``、``\\u2028``）、不带引号的 ``id=``、``<ſcript``
   （``re.IGNORECASE`` 把 ``ſ`` 当成 ``s``）、``<dıv``；
3. 两万篇「按结构拼出来」的页面（挂载点 + 注释 + 至多三个标签 + ``<script``、
   noscript + 距离恰好在 600 字上下的需求短语、redoc / swagger），并断言每个信号的
   「是」和「否」都出现了足够多次 —— fuzz 不是空转；
4. 一组逐条写出来的边角，含 noscript 的 600 字窗口两侧；
5. 超大输入：前面垫 100 KB / 1 MiB / 4 MiB 的普通文字再接一个信号，以及单个超过
   100 KB / 4 MiB 的属性段、注释、空白 —— 证明实现里没有藏着任何「只看前 N 字节」
   的上限。

线性靠计时守卫：每个病态家族先探 100 KB（平方级的实现在这儿就已经超限），再上
1 MB 和 4 MB。4 MB 这一档是给「每次只是 memchr 扫一遍」的平方级准备的 —— 它们在
1 MB 上躲得过 1 MB 的线。
"""

from __future__ import annotations

import random
import re
import time

import pytest

from geo_audit.fetch import jsrender as js
from geo_audit.fixtures import FixtureStore, split_fixture_key
from geo_audit.models import JsAssessment

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

    if vlen < js.EMPTY_SHELL_TEXT_LEN and has_script_src and rlen > 5 * max(vlen, 1):
        hard.append(f"empty_shell(visible={vlen},raw={rlen})")

    if _OLD_MOUNT_THEN_SCRIPT_RE.search(body) or (
        _OLD_EMPTY_MOUNT_RE.search(body) and vlen < js.THIN_TEXT_LEN
    ):
        hard.append("empty_spa_mount")

    if _OLD_API_DOC_SPA_RE.search(body):
        hard.append("api_doc_spa(redoc/swagger/rapidoc)")

    if _OLD_NOSCRIPT_DEMAND_RE.search(body):
        soft.append("noscript_demands_js")
    if js._NUXT_RE.search(body):
        soft.append("nuxt_client_only")
    if js._NEXT_DATA_RE.search(body) and not js._CONTENT_ELEMENT_RE.search(body):
        soft.append("next_data_without_content_elements")
    if vlen < js.THIN_TEXT_LEN and has_script_src and rlen > 3000:
        soft.append(f"thin_text({vlen})")
    if not js._CONTENT_ELEMENT_RE.search(body) and rlen > 2000:
        soft.append("no_content_elements")

    if hard:
        return JsAssessment(True, "high", tuple(hard + soft), vlen, rlen)
    if len(soft) >= 2:
        return JsAssessment(True, "low", tuple(soft), vlen, rlen)
    return JsAssessment(False, "high", tuple(soft), vlen, rlen)


_HTML = {"content-type": "text/html"}


def _same_predicates(body: str) -> None:
    for name, (old, new) in _PREDICATES.items():
        assert bool(old.search(body)) == new(body), (name, body[:300])


def _same_assessment(status: int, headers: dict[str, str], body: str) -> None:
    got = js.detect_js_dependency(status, headers, body)
    assert got == _old_detect_js_dependency(status, headers, body), body[:300]


def _same(body: str) -> None:
    _same_predicates(body)
    _same_assessment(200, _HTML, body)


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
    "<div", "<DIV", "<div ", "<Div\n", "<dıv ", "<dİv ", "<divx ",
    "id='app'", 'id="root"', 'id="__next"', "id='__nuxt'", "id='application'",
    "id='main-content'", "id='redoc'", "id='swagger-ui'", "id=app", "ID='APP'", "id = 'app'",
    "id='app", "id='apps'", " id='app' ", "data-x=\"id='app'\"",
    ">", "<", "<>", "<<", ">>", "/>", " >", "\n>", "</div>", "</DIV >", "</div\n>", "</ div>",
    "<!--", "-->", "<!---->", "<!-- x -->", "<!-->", "<!--->", "--!>",
    "<script", "<script ", "<script src=x>", "<script src='a'>", "<SCRIPT SRC=x", "<scriptsrc=x",
    "<ſcript src=x>", "<scripts ", "src=", "SRC=", "ſrc=", "</script>",
    "<noscript>", "<noscript ", "<noscript x>", "</noscript>", "</NOSCRIPT>", "</noſcript>",
    "<noſcript>", "<noscripts>",
    "enable javascript", "Enable  JavaScript", "requires\tjavascript", "javascript is required",
    "javascript disabled", "javascript required", "javascript  is  disabled",
    "需要启用javascript", "需启用 JavaScript", "请开启 javascript", "enablejavascript",
    "<redoc", "<redocs", "<rapi-doc", "<rapi-docx", "Redoc.init(", "SwaggerUIBundle(",
    "<p>", "<li>", "<h2>", "<table>", "<span>", "<b>", "<a href='x'>",
    "id='__NEXT_DATA__'", "window.__NUXT__", "data-server-rendered='false'",
    " ", "  ", "\n", "\t", " ", " ", "\x85", "\x1c", "　", "x", "x" * 20, "é",
    "ı", "İ", "ſ", "K",
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
_WS = ["", "", " ", "\n", "  ", "\t", " ", " ", "\x85", "　"]
_PHRASES = [
    "enable javascript", "Enable  JavaScript", "requires\njavascript", "javascript is required",
    "javascript disabled", "需要启用javascript", "请开启 javascript", "enablejavascript",
    "enable javascrip",
]  # fmt: skip


def _mount_block(rng: random.Random) -> str:
    attrs = rng.choice(["", " class=x", " data-reactroot", "\n"]) + " " + rng.choice(_MOUNT_IDS)
    attrs += rng.choice(["", "", " class=y", "/", " data-a='>'"])
    opening = (
        rng.choice(["<div", "<div", "<DIV", "<dıv"])
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
        ["<script src=/a.js></script>", "<script>", "<SCRIPT", "<ſcript", "<scripts>", "", ""]
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
            "<script\nsrc=a>", "<SCRIPT SRC=a", "<script", "<scriptsrc=a>", "<ſcript src=a>",
            "<script data-x='>' src=a>", "<script src=", "<script  >src=",
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
_EDIT_ALPHABET = [*"<>/!-='\" \nxdivscriptnoes", "</div>", "<!--", "-->", "<script", "id=", "src=",
                  "\u017f", "\u0131", "\u0130", "\u00a0", "\u2028"]  # fmt: skip


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
    for k in range(30000):
        page = _mutated_seed(rng)
        _same_predicates(page)
        for name, (old, _new) in _PREDICATES.items():
            outcomes[name][bool(old.search(page))] += 1
        if k % 3 == 0:
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


@pytest.mark.parametrize(
    "body",
    [
        "",
        "plain text",
        # --- 挂载点 -------------------------------------------------------------
        "<div id='app'></div><script src=x></script>",
        "<div id='app'></div>",
        '<div id="root"><!-- c --></div><script>',
        '<div id="root"><!-- c --></div>',
        "<div id='app'> \n </div>",
        "<div id='app'> </div>",  # \s 认 NBSP
        "<div id='app'> </div>",
        "<div id='app'>\x1c</div>",
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
        "<div id='app'></div><ſcript",
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
        "<dıv id='app'></div><script",  # re.I 把 ı / İ 当成 i
        "<dİv id='app'></div><script",
        "<div id='app'></dıv><script",
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
        *[f"<div id='main-content'></div>{'x' * k}" for k in (0, 1, 498, 499, 500, 501, 502)],
        *[f"<div id='root'></div>{'x' * k}<script src=a>" for k in (0, 499, 500)],
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
        "<ſcript ſrc=x>",
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
        "<div  id='redoc'",
        "<divid='redoc'>",
        "<div id=redoc>",
        "<div data-a='>' id='redoc'>",
        "<div id='swagger-ui'></div>",
        "id='swagger-ui' > </div>",
        "id='swagger-ui'>x</div>",
        'id="swagger-ui"\n>\n</div>',
        "Redoc.init(x)",
        "SwaggerUIBundle(x)",
        "Redoc.init",
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
        "<noſcript>enable javascript",
        "<noscript>enable javascript",
        "<noscript>x</noſcript>enable javascript",
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
        "<noscript>" + "x" * 590 + "enable" + " " * 50 + "javascript",  # 短语自己可以超出窗口
        "<noscript>" + "x" * 600 + "enable" + " " * 50 + "javascript",
        "<noscript>" + "x" * 601 + "enable" + " " * 50 + "javascript",
        "<noscript>x</noscript>" * 5 + "<noscript>enable javascript",
        "<noscript>" * 3 + "x" * 598 + "enable javascript",
        "<noscript>x" + "<noscript>" * 3 + "enable javascript",
        "<noscript>" + "<noscript>" * 70 + "enable javascript",  # 后面的 <noscript> 离短语更近
        # --- 杂项 ---------------------------------------------------------------
        "<div id='app'></div><noscript>enable javascript</noscript><script src=a>",
        "id='__NEXT_DATA__'",
        "id='__NEXT_DATA__'<p>",
        "window.__NUXT__",
        "data-server-rendered='false'",
        "<script src=x></script>" + "<i></i>" * 500,
        "<div id='root'></div><script src=x></script>" + "<i></i>" * 600,
        "<p>" + "word " * 200 + "</p><script src=x></script>" + "<i></i>" * 500,
    ],
)
def test_identical_answers_on_hand_written_edge_cases(body: str) -> None:
    _same(body)


def test_text_files_are_not_scanned() -> None:
    """非 HTML 响应一进来就返回，不碰任何信号（旧行为）。"""
    body = "<div id='app'></div><script src=x>" * 5
    got = js.detect_js_dependency(200, {"content-type": "text/plain"}, body)
    assert got == _old_detect_js_dependency(200, {"content-type": "text/plain"}, body)
    assert got.signals == ("non_html_body",)


# ── 5. 超大输入：没有藏着「只看前 N 字节」的上限 ─────────────────────────────
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


@pytest.mark.parametrize("construct", list(_AFTER_FILLER))
@pytest.mark.parametrize("size", [100_001, 1_048_577, 4_194_305])
def test_a_signal_after_a_long_prefix_is_still_found(size: int, construct: str) -> None:
    """前面垫的字数刚好越过 10 万、1 MiB、4 MiB：任何「只在前 N 字节里找」的上限都会在这儿露馅。"""
    _same(_filler(size) + _AFTER_FILLER[construct])


_LONG_CONSTRUCT = {
    # 挂载点标签自己的属性段很长，id 在最后
    "long-attributes": lambda n: "<div " + "x " * (n // 2) + "id='app'></div><script",
    "long-attributes-script-src": lambda n: "<script " + "x " * (n // 2) + "src=a>",
    "long-attributes-redoc": lambda n: "<div " + "x " * (n // 2) + "id='redoc'>",
    "long-attributes-noscript": lambda n: "<noscript " + "x " * (n // 2) + ">enable javascript",
    # id 在最前，其后是很长的属性段
    "long-tail-attributes": lambda n: "<div id='app' " + "x " * (n // 2) + "></div><script",
    "long-comment": lambda n: "<div id='app'><!-- " + "x" * n + " --></div><script",
    "long-whitespace": lambda n: "<div id='app'>" + " " * n + "</div>" + " " * n + "<script",
    "long-gap-between-tags": lambda n: "<div id='app'></div><a " + "x " * (n // 2) + "><script",
}


@pytest.mark.parametrize("construct", list(_LONG_CONSTRUCT))
@pytest.mark.parametrize("size", [100_001, 4_194_305])
def test_a_single_very_long_construct_is_still_recognised(size: int, construct: str) -> None:
    """单个结构本身就超过 10 万 / 4 MiB 字节：不能因为「太长」就当成没匹配。"""
    _same(_LONG_CONSTRUCT[construct](size))


# ── 6. 计时守卫：线性 ────────────────────────────────────────────────────────
_PATHOLOGICAL = {
    "div-id-no-gt": lambda n: "<div id='app'" * (n // 13),
    "div-no-gt": lambda n: "<div " * (n // 5),
    "script-no-gt": lambda n: "<script " * (n // 8),
    "noscript-no-gt": lambda n: "<noscript " * (n // 10),
    "noscript-never-closed": lambda n: "<noscript>" * (n // 10),
    "noscript-phrase-only-at-the-end": lambda n: "<noscript>" * (n // 10) + "enable javascript",
    "noscript-partial-phrases": lambda n: "<noscript>enable " * (n // 17),
    "mount-never-closed": lambda n: "<div id='app'>" * (n // 14),
    "mount-unclosed-comment": lambda n: "<div id='app'><!--" * (n // 18),
    "mount-then-tag-run": lambda n: "<div id='app'></div><" * (n // 21),
    "mount-closed-comments": lambda n: "<div id='app'><!-- x --></div> " * (n // 31),
    "mount-comment-then-tags": lambda n: "<div id='app'><!-- x --></div><b><i><u>" * (n // 41),
    "redoc-no-gt": lambda n: "<div id='redoc'" * (n // 15),
    "swagger-spaces": lambda n: "id='swagger-ui' " * (n // 16),
    "mount-then-whitespace": lambda n: ("<div id='app'>" + " " * 1000) * (n // 1014),
    "mixed": lambda n: "<div id='app' <script <noscript <div " * (n // 40),
    # 一长串开头共用结尾的那一个 ``>``：每个开头各自去找 ``>`` 就是平方级（每次只是 memchr）
    "div-id-one-gt-at-the-end": lambda n: "<div id='app' " * (n // 14) + ">",
    "script-one-gt-at-the-end": lambda n: "<script " * (n // 8) + ">",
    "noscript-one-gt-at-the-end": lambda n: "<noscript " * (n // 10) + ">",
    "redoc-one-gt-at-the-end": lambda n: "<div id='redoc' " * (n // 16) + ">",
}

# (输入字节数, 每次调用的秒数上限)。上限留的是 10 倍以上的余量：这里要抓的是平方级，不是常数。
_LADDER = ((100_000, 0.4), (1_000_000, 3.0), (4_000_000, 8.0))


@pytest.mark.parametrize("name", list(_PATHOLOGICAL))
def test_signals_on_hostile_input_are_linear(name: str) -> None:
    make = _PATHOLOGICAL[name]
    for size, limit in _LADDER:
        body = make(size)
        t = time.perf_counter()
        js.detect_js_dependency(200, _HTML, body)
        elapsed = time.perf_counter() - t
        assert elapsed < limit, f"detect_js_dependency({name}, {size}) {elapsed:.2f}s"


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
