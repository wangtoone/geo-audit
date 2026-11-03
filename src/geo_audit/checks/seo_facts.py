"""首页的 SEO 事实：noindex / canonical / hreflang / title / H1 / 原始 HTML 三档 / 框架特征。

只陈述从**已经拿到的**首页响应里读出来的东西，**不发任何请求**（discovery 探根路径时
本来就 GET 了这页）。不跑 JS：三档、框架特征、缓存头得出的「静态 / 服务端渲染」都是
**推断**，字段名与文案里都带着「推断」。读不到的首页（被拦、超时、没拿到）一律落
``raw_html_tier="unreadable"`` 并写原因，**不是**「没问题」。
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from geo_audit.checks.rawhtml import inspect_raw_html
from geo_audit.models import HttpResponse, PageSeoFacts, Probe

#: 可见文字字符数分档（不跑 JS）。< 200 与 ``detect_js_dependency`` 的 needs_js 门槛一致。
SHELL_BELOW = 200
FULL_FROM = 1500

#: 只扫正文前这么多字节找框架特征：特征都在 <head> / 根容器附近。
_SCAN_BYTES = 400_000

_FRAMEWORKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nextjs", re.compile(r"__NEXT_DATA__|/_next/static/|self\.__next_f")),
    ("nuxt", re.compile(r'id=["\']__nuxt["\']|window\.__NUXT__')),
    ("gatsby", re.compile(r'id=["\']___gatsby["\']')),
    ("astro", re.compile(r"<astro-island")),
    ("angular", re.compile(r"\bng-version=")),
    ("react_root", re.compile(r"data-reactroot")),
    ("spa_empty_root", re.compile(r'<div[^>]+id=["\'](?:root|app)["\'][^>]*>\s*</div>')),
)


def framework_signals(body: str) -> tuple[str, ...]:
    head = body[:_SCAN_BYTES]
    return tuple(name for name, pat in _FRAMEWORKS if pat.search(head))


def delivery_hint(headers: dict[str, str]) -> str | None:
    """从缓存相关响应头粗分「预渲染/缓存」与「按请求动态生成」。**推断**，读不出就是 None。"""
    h = {k.lower(): v.lower() for k, v in headers.items()}
    if (
        h.get("x-vercel-cache") in {"hit", "prerender", "stale"}
        or h.get("x-nextjs-cache") in {"hit", "stale", "prerender"}
        or "x-nextjs-prerender" in h
        or h.get("cf-cache-status") == "hit"
        or (h.get("age", "0").strip().isdigit() and int(h.get("age", "0")) > 0)
    ):
        return "prerendered_or_cached"
    cc = h.get("cache-control", "")
    if "no-store" in cc or "private" in cc or "no-cache" in cc:
        return "dynamic"
    return None


def _path(url: str) -> str:
    return urlsplit(url).path.rstrip("/") or "/"


def canonical_relation(canonical: str | None, page_url: str) -> str:
    """``self`` | ``other_path`` | ``other_host`` | ``missing``。www 与裸域算不同 host。"""
    if not canonical:
        return "missing"
    target = urljoin(page_url, canonical)
    t, p = urlsplit(target), urlsplit(page_url)
    if (t.hostname or "").lower() != (p.hostname or "").lower():
        return "other_host"
    return "self" if _path(target) == _path(page_url) else "other_path"


def _tier(visible_text_len: int) -> str:
    if visible_text_len < SHELL_BELOW:
        return "shell"
    return "partial" if visible_text_len < FULL_FROM else "full"


def unreadable_facts(host: str, url: str, reason: str) -> PageSeoFacts:
    return PageSeoFacts(
        host=host,
        url=url,
        final_url=url,
        status=None,
        title=None,
        h1=(),
        meta_description=None,
        canonical=None,
        canonical_relation="missing",
        noindex=False,
        hreflang=(),
        visible_text_len=0,
        raw_html_tier="unreadable",
        framework_signals=(),
        delivery_hint=None,
        flags=(),
        unreadable_reason=reason,
    )


def build_seo_facts(host: str, probe: Probe) -> PageSeoFacts:
    """首页 ``Probe`` → 事实。没拿到正文（网络错误、被拦、非 HTML）→ unreadable。"""
    url = probe.url
    resp: HttpResponse | None = probe.response
    if resp is None or not resp.body or resp.status == 0:
        return unreadable_facts(host, url, probe.classification.reason)
    ctype = resp.headers.get("content-type", "").lower()
    if "html" not in ctype and "<html" not in resp.body[:2048].decode("utf-8", "replace").lower():
        return unreadable_facts(host, url, "not_html")
    body = resp.body.decode("utf-8", "replace")
    facts = inspect_raw_html(
        body,
        status=resp.status,
        headers=resp.headers,
        final_url=resp.final_url,
        truncated=resp.body_truncated,
    )
    page_url = resp.final_url or url
    relation = canonical_relation(facts.canonical, page_url)
    tier = _tier(facts.visible_text_len)
    flags: list[str] = []
    if not (200 <= resp.status < 300):
        flags.append(f"status_{resp.status}")
    if facts.noindex:
        flags.append("noindex")
    if relation in ("other_host", "other_path", "missing"):
        flags.append(f"canonical_{relation}")
    if not facts.title:
        flags.append("title_missing")
    if not facts.h1:
        flags.append("h1_missing")
    elif len(facts.h1) > 1:
        flags.append("h1_multiple")
    if tier != "full":
        flags.append(f"{tier}_html")
    return PageSeoFacts(
        host=host,
        url=url,
        final_url=page_url,
        status=resp.status,
        title=facts.title,
        h1=facts.h1,
        meta_description=facts.meta_description,
        canonical=facts.canonical,
        canonical_relation=relation,
        noindex=facts.noindex,
        hreflang=facts.hreflang,
        visible_text_len=facts.visible_text_len,
        raw_html_tier=tier,
        framework_signals=framework_signals(body),
        delivery_hint=delivery_hint(resp.headers),
        flags=tuple(flags),
        unreadable_reason=None,
    )
