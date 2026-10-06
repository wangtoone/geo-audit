"""AI 爬虫「看到的」那份原始 HTML：事实提取 + 对账。零网络、零 LLM。

## 为什么要有它

多数 AI 爬虫不执行 JS，读的就是服务器吐出来的那份 HTML。Meshy 的真实事故：

* 定价页静态 HTML 里价格渲染成 ``$0`` → Bing / ChatGPT 的爬虫把所有套餐读成免费；
* ``/3d-models`` 是纯 JS 渲染 → 爬虫和 LLM 拿到的是一个空白页。

两件事浏览器里都**看不出来**（浏览器会跑 JS、会显示对的价格），只有「不跑 JS 读原始
HTML」这把尺子量得出。这个模块就是那把尺子：给一份 HTML，说出里面有什么；再拿一份
**期望**（页面应该包含什么）对账。

## 两层，别混

1. :func:`inspect_raw_html` 只陈述**事实**：title / H1 / JSON-LD 类型 / 可见文字长度 /
   价格 token / 是否像 JS 空壳。不下结论 —— ``$0`` 对免费档是对的，不是缺陷。
2. :func:`evaluate_spec` 拿人写的**期望**去对：期望从哪来（changelog 里「定价页 H1 改为
   X」、产品说「应该有 Product schema」）是人的判断，工具只负责说「原始 HTML 里有没有」。

## ``unknown`` 的规矩（项目一贯的）

页面没抓到 / 被 WAF 拦 / robots 不让抓 / 不是 HTML，期望一律 ``unknown``，**绝不**是
``fail`` 也不是 ``pass``。正文被截断时，「没找到」同样只能是 ``unknown``
（可能在被截掉的部分里）；「找到了」仍是 ``pass``。

## 不做

不跑 JS（``jsrender.py`` 写明 v1 不带渲染器，且合规约束不碰无头浏览器）；不冒充任何
AI 爬虫的 UA —— 用的是工具自己那条带联系邮箱的诚实 UA。所以它回答的是「**不执行 JS 的
爬虫**能不能读到」，不回答「OpenAI 的爬虫能不能进来」（那是 WAF 层，另一个问题）。
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Literal

from geo_audit.fetch.jsrender import detect_js_dependency
from geo_audit.fetch.normalize import visible_text
from geo_audit.models import JsAssessment

__all__ = [
    "ExpectResult",
    "PageFacts",
    "PageSpec",
    "evaluate_spec",
    "inspect_raw_html",
    "parse_amounts",
    "unusable_reason",
]


# --------------------------------------------------------------------------- #
# 事实
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PageFacts:
    status: int
    final_url: str
    content_type: str
    truncated: bool
    title: str | None
    h1: tuple[str, ...]
    meta_description: str | None
    canonical: str | None
    #: meta robots 或 X-Robots-Tag 里有 noindex
    noindex: bool
    visible_text_len: int
    js: JsAssessment
    #: JSON-LD 里出现的 ``@type``（展开 ``@graph`` 与数组，去重保序）
    schema_types: tuple[str, ...]
    #: 解析不了的 ``<script type="application/ld+json">`` 个数（坏 JSON-LD 等于没有）
    schema_invalid: int
    #: JSON-LD 里 Offer 的 price 值（原样字符串）
    offer_prices: tuple[str, ...]
    #: 可见文字里的金额（数值，去重升序）；``$0`` → 0.0
    visible_amounts: tuple[float, ...]
    #: JSON-LD 的价格里，**不在**可见文字金额里的 —— Google 要求结构化数据与可见文字一致，
    #: 对不上通常是一边改了另一边没改
    offer_prices_not_visible: tuple[str, ...]
    #: 页面里完整的可见文字（NFKC、折叠空白）。对账用，不进 JSON 输出
    text: str = field(repr=False, default="")


class _Scan(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: list[str] = []
        self.in_title = False
        self.h1: list[list[str]] = []
        self.in_h1 = 0
        self.meta: dict[str, str] = {}
        self.canonical: str | None = None
        self.ld_blocks: list[list[str]] = []
        self.in_ld = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self.in_title = True
        elif tag == "h1":
            self.in_h1 += 1
            self.h1.append([])
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name and "content" in a:
                self.meta.setdefault(name, a["content"])
        elif tag == "link":
            if "canonical" in a.get("rel", "").lower().split() and self.canonical is None:
                self.canonical = a.get("href") or None
        elif tag == "script" and "ld+json" in a.get("type", "").lower():
            self.in_ld = True
            self.ld_blocks.append([])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        elif tag == "h1" and self.in_h1:
            self.in_h1 -= 1
        elif tag == "script":
            self.in_ld = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title.append(data)
        if self.in_h1 and self.h1:
            self.h1[-1].append(data)
        if self.in_ld and self.ld_blocks:
            self.ld_blocks[-1].append(data)


def _squash(s: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", s)).strip()


_AMOUNT = re.compile(r"(?<![\w.])[$€£¥]\s?(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?")


def parse_amounts(text: str) -> tuple[float, ...]:
    """文字里带货币符号的金额，数值化、去重、升序。``$1,299.50`` → 1299.5。"""
    out: set[float] = set()
    for m in _AMOUNT.finditer(text):
        whole = m.group(1).replace(",", "")
        out.add(float(f"{whole}.{m.group(2)}" if m.group(2) else whole))
    return tuple(sorted(out))


def _walk_ld(node: Any, types: list[str], prices: list[str]) -> None:
    if isinstance(node, list):
        for x in node:
            _walk_ld(x, types, prices)
        return
    if not isinstance(node, dict):
        return
    t = node.get("@type")
    for name in t if isinstance(t, list) else [t]:
        if isinstance(name, str) and name not in types:
            types.append(name)
    for key in ("price", "lowPrice", "highPrice"):
        v = node.get(key)
        if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v).strip():
            prices.append(str(v).strip())
    for v in node.values():
        if isinstance(v, (dict, list)):
            _walk_ld(v, types, prices)


def _price_to_float(s: str) -> float | None:
    try:
        return float(s.replace(",", ""))
    except ValueError:
        return None


def inspect_raw_html(
    body: str,
    *,
    status: int,
    headers: dict[str, str],
    final_url: str = "",
    truncated: bool = False,
) -> PageFacts:
    """陈述这份 HTML 里有什么。不下结论。"""
    scan = _Scan()
    scan.feed(body)
    scan.close()

    types: list[str] = []
    prices: list[str] = []
    invalid = 0
    for chunk in scan.ld_blocks:
        raw = "".join(chunk).strip()
        if not raw:
            continue
        try:
            _walk_ld(json.loads(raw), types, prices)
        except ValueError:
            invalid += 1

    text = _squash(visible_text(body))
    amounts = parse_amounts(text)
    not_visible = tuple(
        p
        for p in dict.fromkeys(prices)
        if (v := _price_to_float(p)) is not None and v not in amounts
    )
    robots_meta = scan.meta.get("robots", "").lower()
    robots_hdr = headers.get("x-robots-tag", "").lower()
    title = _squash("".join(scan.title)) if scan.title else None
    return PageFacts(
        status=status,
        final_url=final_url,
        content_type=headers.get("content-type", "").split(";")[0].strip().lower(),
        truncated=truncated,
        title=title or None,
        h1=tuple(h for h in (_squash("".join(x)) for x in scan.h1) if h),
        meta_description=_squash(scan.meta["description"]) if "description" in scan.meta else None,
        canonical=scan.canonical,
        noindex="noindex" in robots_meta or "noindex" in robots_hdr,
        visible_text_len=len(text),
        js=detect_js_dependency(status, headers, body, url=final_url),
        schema_types=tuple(types),
        schema_invalid=invalid,
        offer_prices=tuple(dict.fromkeys(prices)),
        visible_amounts=amounts,
        offer_prices_not_visible=not_visible,
        text=text,
    )


# --------------------------------------------------------------------------- #
# 对账
# --------------------------------------------------------------------------- #

Verdict = Literal["pass", "fail", "unknown"]


@dataclass(frozen=True, slots=True)
class PageSpec:
    """人写的期望。字段全可选；没写的不检查。字符串比较：NFKC、折叠空白、不分大小写。"""

    url: str = ""
    title_contains: tuple[str, ...] = ()
    h1_contains: tuple[str, ...] = ()
    #: 可见文字里必须出现（title 也算可见文字，见 ``visible_text``）
    text_contains: tuple[str, ...] = ()
    #: 可见文字里不许出现（子串匹配：``$0`` 会命中 ``$0.99``，要精确判价格用 ``prices``）
    text_absent: tuple[str, ...] = ()
    #: JSON-LD 里必须有这些 ``@type``
    schema_types: tuple[str, ...] = ()
    #: 可见文字里必须出现这些金额（数值比较，``$1,299`` 与 ``1299`` 等价）
    prices: tuple[float, ...] = ()
    min_visible_chars: int | None = None
    #: True = 必须可被索引（没有 noindex）；False = 必须 noindex
    indexable: bool | None = None
    #: 不是 JS 空壳
    no_js_shell: bool = False


@dataclass(frozen=True, slots=True)
class ExpectResult:
    name: str
    verdict: Verdict
    detail: str


def unusable_reason(
    *, status: int, content_type: str, transport_error: str | None, blocked: bool
) -> str | None:
    """这次抓取能不能拿来对账。能 → None；不能 → 一句理由（期望将全部 ``unknown``）。"""
    if transport_error:
        return f"没抓到（{transport_error}）"
    if blocked:
        return f"被站方拦截（HTTP {status}），拦截 ≠ 页面内容"
    if not 200 <= status < 300:
        return f"HTTP {status}，不是一个可读的页面"
    if content_type and content_type not in ("text/html", "application/xhtml+xml"):
        return f"返回的是 {content_type}，不是 HTML"
    return None


def _norm(s: str) -> str:
    return _squash(s).casefold()


def _fmt_amount(v: float) -> str:
    return f"{v:g}"


def evaluate_spec(
    facts: PageFacts | None, spec: PageSpec, *, why_unusable: str | None = None
) -> list[ExpectResult]:
    """对账。``facts is None`` 或 ``why_unusable`` 非空 → 每条期望都是 unknown。"""
    results: list[ExpectResult] = []

    def add(name: str, verdict: Verdict, detail: str) -> None:
        results.append(ExpectResult(name, verdict, detail))

    names = _spec_names(spec)
    if facts is None or why_unusable:
        for n in names:
            add(n, "unknown", why_unusable or "没有页面数据")
        return results

    text = _norm(facts.text)
    trunc_note = "（正文被截断，没找到不等于不存在）"

    def missing(name: str, what: str) -> None:
        if facts.truncated:
            add(name, "unknown", f"{what}{trunc_note}")
        else:
            add(name, "fail", what)

    for s in spec.title_contains:
        n = f"title 含「{s}」"
        if facts.title is not None and _norm(s) in _norm(facts.title):
            add(n, "pass", f"title = {facts.title!r}")
        else:
            missing(n, f"title = {facts.title!r}")
    for s in spec.h1_contains:
        n = f"H1 含「{s}」"
        if any(_norm(s) in _norm(h) for h in facts.h1):
            add(n, "pass", f"H1 = {list(facts.h1)!r}")
        else:
            missing(n, f"H1 = {list(facts.h1)!r}")
    for s in spec.text_contains:
        n = f"原始 HTML 可见文字含「{s}」"
        if _norm(s) in text:
            add(n, "pass", "找到")
        else:
            missing(n, f"没找到（可见文字共 {facts.visible_text_len} 字符）")
    for s in spec.text_absent:
        n = f"原始 HTML 可见文字不含「{s}」"
        if _norm(s) in text:
            add(n, "fail", "出现了")
        elif facts.truncated:
            add(n, "unknown", f"没出现，但{trunc_note}")
        else:
            add(n, "pass", "没出现")
    for s in spec.schema_types:
        n = f"JSON-LD 含 {s}"
        if s in facts.schema_types:
            add(n, "pass", f"类型 = {list(facts.schema_types)!r}")
        else:
            bad = (
                f"，另有 {facts.schema_invalid} 段 JSON-LD 解析失败" if facts.schema_invalid else ""
            )
            missing(n, f"类型 = {list(facts.schema_types)!r}{bad}")
    for v in spec.prices:
        n = f"可见文字含金额 {_fmt_amount(v)}"
        if v in facts.visible_amounts:
            add(n, "pass", "找到")
        else:
            missing(n, f"页面里的金额 = {[_fmt_amount(x) for x in facts.visible_amounts]!r}")
    if spec.min_visible_chars is not None:
        n = f"可见文字 ≥ {spec.min_visible_chars} 字符"
        ok = facts.visible_text_len >= spec.min_visible_chars
        add(n, "pass" if ok else "fail", f"实际 {facts.visible_text_len}")
    if spec.indexable is not None:
        n = "可被索引" if spec.indexable else "带 noindex"
        ok = (not facts.noindex) == spec.indexable
        add(n, "pass" if ok else "fail", f"noindex = {facts.noindex}")
    if spec.no_js_shell:
        n = "不是 JS 空壳"
        if facts.js.required:
            add(n, "fail", f"信号 {list(facts.js.signals)!r}（置信 {facts.js.confidence}）")
        else:
            add(n, "pass", f"可见文字 {facts.visible_text_len} 字符")
    return results


def _spec_names(spec: PageSpec) -> list[str]:
    out = [f"title 含「{s}」" for s in spec.title_contains]
    out += [f"H1 含「{s}」" for s in spec.h1_contains]
    out += [f"原始 HTML 可见文字含「{s}」" for s in spec.text_contains]
    out += [f"原始 HTML 可见文字不含「{s}」" for s in spec.text_absent]
    out += [f"JSON-LD 含 {s}" for s in spec.schema_types]
    out += [f"可见文字含金额 {_fmt_amount(v)}" for v in spec.prices]
    if spec.min_visible_chars is not None:
        out.append(f"可见文字 ≥ {spec.min_visible_chars} 字符")
    if spec.indexable is not None:
        out.append("可被索引" if spec.indexable else "带 noindex")
    if spec.no_js_shell:
        out.append("不是 JS 空壳")
    return out
