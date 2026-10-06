"""原始 HTML 检查：每条用例对应一个会被读错的真实形态（Meshy 的三次事故 + 解析细节）。

HTML 都是手写的最小样本，不碰网络、不依赖第三方快照。
"""

from __future__ import annotations

from geo_audit.checks.rawhtml import (
    PageSpec,
    evaluate_spec,
    inspect_raw_html,
    parse_amounts,
    unusable_reason,
)

H = {"content-type": "text/html; charset=utf-8"}


def _facts(body: str, **kw):  # type: ignore[no-untyped-def]
    return inspect_raw_html(body, status=200, headers=H, **kw)


def _verdicts(facts, spec, why=None):  # type: ignore[no-untyped-def]
    return {r.name: r.verdict for r in evaluate_spec(facts, spec, why_unusable=why)}


PAGE = """<!doctype html><html><head>
<title>Pricing &amp; Plans | Acme</title>
<meta name="description" content="Pick a plan">
<link rel="canonical" href="https://acme.test/pricing">
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[
 {"@type":"Product","name":"Acme","offers":[{"@type":"Offer","price":"20","priceCurrency":"USD"},
                                             {"@type":"Offer","price":"1,299"}]},
 {"@type":["FAQPage","WebPage"]}]}
</script></head><body>
<h1>Acme <span>Pricing</span></h1>
<p>Pro is $20 per month. Team is $1,299.50 a year. Starter is $0.</p>
<script>var x = "$999 hidden in script";</script>
</body></html>"""


def test_basic_facts() -> None:
    f = _facts(PAGE, final_url="https://acme.test/pricing")
    assert f.title == "Pricing & Plans | Acme"
    assert f.h1 == ("Acme Pricing",)
    assert f.meta_description == "Pick a plan"
    assert f.canonical == "https://acme.test/pricing"
    assert f.noindex is False
    assert set(f.schema_types) == {"Product", "Offer", "FAQPage", "WebPage"}
    assert f.schema_invalid == 0


def test_amounts_are_numeric_and_skip_scripts() -> None:
    f = _facts(PAGE)
    assert f.visible_amounts == (0.0, 20.0, 1299.5)  # 脚本里的 $999 不算可见
    assert parse_amounts("$1,299 and €5.5 and £0") == (0.0, 5.5, 1299.0)
    assert parse_amounts("v1.20 costs 20 dollars") == ()  # 没有货币符号不算


def test_schema_price_not_visible_is_reported() -> None:
    # JSON-LD 写 20 和 1,299；可见文字有 20 和 1299.5 → 1,299 对不上
    f = _facts(PAGE)
    assert f.offer_prices == ("20", "1,299")
    assert f.offer_prices_not_visible == ("1,299",)


def test_invalid_jsonld_counts_as_invalid_not_as_types() -> None:
    body = '<script type="application/ld+json">{"@type": "Product",}</script><p>x</p>'
    f = _facts(body)
    assert f.schema_types == ()
    assert f.schema_invalid == 1


def test_noindex_from_meta_and_header() -> None:
    assert _facts('<meta name="robots" content="NOINDEX, follow"><p>x</p>').noindex
    f = inspect_raw_html("<p>x</p>", status=200, headers={**H, "x-robots-tag": "noindex"})
    assert f.noindex


# ── Meshy 事故一：价格渲染成 $0 ─────────────────────────────────────────────
def test_pricing_page_whose_prices_all_became_zero_fails_the_price_expectation() -> None:
    zero = "<h1>Pricing</h1><p>Pro $0</p><p>Studio $0</p>"
    spec = PageSpec(prices=(20.0, 70.0))
    v = _verdicts(_facts(zero), spec)
    assert set(v.values()) == {"fail"}
    # 同一份期望打在正确的页面上必须过 —— 否则这条只是「永远红」
    ok = "<h1>Pricing</h1><p>Pro $20</p><p>Studio $70</p>"
    assert set(_verdicts(_facts(ok), spec).values()) == {"pass"}


# ── Meshy 事故二：纯 JS 页面，爬虫看到空白页 ────────────────────────────────
JS_SHELL = (
    "<!doctype html><html><head><title>Models</title>"
    '<script src="/a.js"></script><script src="/b.js"></script></head>'
    '<body><div id="root"></div><script>window.__BOOT__=1</script>'
    + "<!-- pad -->" * 400
    + "</body></html>"
)


def test_js_shell_is_flagged_and_content_expectation_fails() -> None:
    f = _facts(JS_SHELL)
    assert f.js.required is True
    v = _verdicts(f, PageSpec(no_js_shell=True, text_contains=("3D models",)))
    assert v["不是 JS 空壳"] == "fail"
    assert v["原始 HTML 可见文字含「3D models」"] == "fail"


# ── 事故三（今晚实测）：套餐价格只在 JSON-LD、不在可见文字 ─────────────────────
def test_prices_only_in_jsonld_are_visible_to_neither_expectation_nor_text() -> None:
    body = (
        '<script type="application/ld+json">{"@type":"Offer","price":"20"}</script>'
        "<h1>Pricing</h1><p>Compare plans</p>"
    )
    f = _facts(body)
    assert f.visible_amounts == ()
    assert f.offer_prices_not_visible == ("20",)
    assert _verdicts(f, PageSpec(prices=(20.0,)))["可见文字含金额 20"] == "fail"


# ── 期望的比较规则 ─────────────────────────────────────────────────────────
def test_string_expectations_ignore_case_whitespace_and_width() -> None:
    f = _facts(
        "<title>Meshy  Official\nPricing</title>"
        "<h1>Meshy Official Pricing Plans</h1><p>ＦＡＱ here</p>"
    )
    spec = PageSpec(
        title_contains=("meshy official pricing",),
        h1_contains=("official pricing plans",),
        text_contains=("faq HERE",),  # 全角 ＦＡＱ 经 NFKC 归一
    )
    assert set(_verdicts(f, spec).values()) == {"pass"}


def test_h1_expectation_fails_when_h1_differs() -> None:
    f = _facts("<h1>Meshy Pricing &amp; Plans</h1>")
    v = _verdicts(f, PageSpec(h1_contains=("Meshy Official Pricing Plans",)))
    assert list(v.values()) == ["fail"]


def test_text_absent_and_schema_types() -> None:
    f = _facts(PAGE)
    assert (
        _verdicts(f, PageSpec(text_absent=("hidden in script",)))[
            "原始 HTML 可见文字不含「hidden in script」"
        ]
        == "pass"
    )
    assert (
        _verdicts(f, PageSpec(text_absent=("Starter",)))["原始 HTML 可见文字不含「Starter」"]
        == "fail"
    )
    v = _verdicts(f, PageSpec(schema_types=("Product", "HowTo")))
    assert v == {"JSON-LD 含 Product": "pass", "JSON-LD 含 HowTo": "fail"}


def test_min_chars_indexable_and_nothing_checked_when_spec_empty() -> None:
    f = _facts("<p>short</p>")
    assert _verdicts(f, PageSpec(min_visible_chars=100))["可见文字 ≥ 100 字符"] == "fail"
    assert _verdicts(f, PageSpec(indexable=True))["可被索引"] == "pass"
    assert evaluate_spec(f, PageSpec()) == []


# ── unknown 的规矩：没抓到 / 被拦 / 不是 HTML / 被截断 都不许变成 fail 或 pass ───
def test_unusable_fetch_makes_every_expectation_unknown() -> None:
    spec = PageSpec(h1_contains=("x",), prices=(20.0,), no_js_shell=True, indexable=True)
    v = _verdicts(None, spec, why="没抓到（timeout）")
    assert len(v) == 4 and set(v.values()) == {"unknown"}


def test_unusable_reason_cases() -> None:
    def r(**kw):  # type: ignore[no-untyped-def]
        base = {
            "status": 200,
            "content_type": "text/html",
            "transport_error": None,
            "blocked": False,
        }
        return unusable_reason(**{**base, **kw})

    assert r() is None
    assert "timeout" in (r(status=0, transport_error="timeout") or "")
    assert "拦截" in (r(status=403, blocked=True) or "")
    assert "404" in (r(status=404) or "")
    assert "application/json" in (r(content_type="application/json") or "")
    assert r(content_type="") is None  # 没写 content-type 不当成非 HTML


def test_truncated_body_turns_not_found_into_unknown_but_found_stays_pass() -> None:
    f = _facts("<h1>Pricing</h1><p>Pro $20</p>", truncated=True)
    v = _verdicts(
        f, PageSpec(prices=(20.0, 70.0), text_absent=("nonexistent",), text_contains=("Pro",))
    )
    assert v["可见文字含金额 20"] == "pass"
    assert v["可见文字含金额 70"] == "unknown"
    assert v["原始 HTML 可见文字不含「nonexistent」"] == "unknown"
    assert v["原始 HTML 可见文字含「Pro」"] == "pass"
    # 「出现了」不受截断影响，仍是 fail
    assert _verdicts(f, PageSpec(text_absent=("Pro",)))["原始 HTML 可见文字不含「Pro」"] == "fail"
