"""AI 引用了哪些**不是你的**站。零 LLM 判定。

## 这个检查为什么必须靠 AI 层才存在

v1 只扫用户给的那个注册域。它看不见「AI 在拿别的 host 回答关于你的问题」——
而实测这件事很大：mistral.ai 那两批 50 份回答里，检索结果出现的 host 排名是

    589× docs.mistral.ai
     41× mistral.ai
     34× github.com
     32× platform-docs-public.pages.dev      ← 第 4 名
      3× platform-docs-internal.vercel.app

后两个是**预览部署**。实测两条结论都很硬：

* ``platform-docs-public.pages.dev`` —— **DNS 根本解析不出来**
  （``curl: (6) Could not resolve host``），而它被引用 32 次。
  也就是说 AI 正在把一个连存在都不存在的 host 推荐给你的用户。
* ``platform-docs-internal.vercel.app`` —— 名字写着 internal，实测 200，
  ``<title>Documentation - Mistral AI</title>``，而且 **robots.txt 返回的是
  SPA 外壳**（即根本没有 robots.txt），所以没有任何东西拦爬虫。

## 判定权仍然在我们

模型只提供 **host 名单**（它引用了谁）。这些 host 活不活、解析不解析、有没有
robots.txt，全部由我们自己发请求决定。所以这个模块零 LLM，函数签名里也没有
任何 client —— 与 checks/ 下其他模块一视同仁（A52 / A54）。
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

__all__ = [
    "PREVIEW_SUFFIXES",
    "PRE_PRODUCTION_MARKERS",
    "HostClass",
    "OffsiteHost",
    "classify_host",
    "collect_hosts",
    "judge_offsite_hosts",
]

#: 预览/托管平台的域名后缀。命中即「这不是一个正式的品牌域」。
#: 刻意用后缀白名单而不是「不等于主域就算」—— 后者会把 github.com、
#: huggingface.co 这类正常的第三方来源全报成问题。
PREVIEW_SUFFIXES: tuple[str, ...] = (
    ".pages.dev",  # Cloudflare Pages
    ".vercel.app",
    ".netlify.app",
    ".workers.dev",
    ".onrender.com",
    ".herokuapp.com",
    ".surge.sh",
    ".fly.dev",
    ".railway.app",
    ".gitbook.io",
    ".readthedocs.io",
    ".github.io",
)

#: host 名字里出现即「这看起来不该对外」。**只用名字，不猜内容。**
PRE_PRODUCTION_MARKERS: tuple[str, ...] = (
    "internal",
    "staging",
    "preview",
    "sandbox",
    "test",
    "uat",
    "qa-",
    "-qa",
)


class HostClass(str, Enum):
    OWN = "own"  # 与被审计域同一个注册域
    PREVIEW = "preview"  # 预览/托管平台域，且内容看起来是你的
    THIRD_PARTY = "third_party"  # 正常的第三方来源（github / 维基 / 博客）


@dataclass(frozen=True, slots=True)
class OffsiteHost:
    """一个被 AI 引用过的 host，以及**我们自己测出来**的事实。"""

    host: str
    host_class: HostClass
    citations: int
    resolvable: bool | None = None  # None = 还没测
    status: int | None = None
    has_robots: bool | None = None
    pre_production_marker: str = ""

    @property
    def is_finding(self) -> bool:
        """够得上一条发现的两种情形。

        1. 被引用的 host **解析不出来** —— AI 在推荐一个不存在的地址；
        2. 预览域**活着**且名字带 internal/staging 之类 —— 那不该对外。

        「预览域活着但名字正常」（比如 ``docs-public.pages.dev``）不单独报 ——
        那可能是有意公开的镜像，报了就是误判。只在它**同时**解析不出来或带
        预生产标记时才算。
        """
        if self.host_class is HostClass.OWN:
            return False
        if self.resolvable is False:
            return True
        return self.host_class is HostClass.PREVIEW and bool(self.pre_production_marker)


def _registrable(host: str) -> str:
    parts = [p for p in host.lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def classify_host(host: str, *, audited_domain: str) -> HostClass:
    h = host.lower().strip(".")
    if not h:
        return HostClass.THIRD_PARTY
    if _registrable(h) == _registrable(audited_domain):
        return HostClass.OWN
    if any(h.endswith(suffix) for suffix in PREVIEW_SUFFIXES):
        return HostClass.PREVIEW
    return HostClass.THIRD_PARTY


def _marker(host: str) -> str:
    h = host.lower()
    return next((m for m in PRE_PRODUCTION_MARKERS if m in h), "")


def collect_hosts(urls: Iterable[str]) -> dict[str, int]:
    """URL 列表 → host 计数。只做统计，不做判定。"""
    counts: dict[str, int] = {}
    for url in urls:
        host = (urlsplit(url).hostname or "").lower()
        if host:
            counts[host] = counts.get(host, 0) + 1
    return counts


def judge_offsite_hosts(
    urls: Sequence[str],
    *,
    audited_domain: str,
    probe: Callable[[str], tuple[bool, int | None, bool | None]],
    min_citations: int = 2,
) -> tuple[OffsiteHost, ...]:
    """把 AI 引用过的 URL 收成 host 事实表。

    ``probe(host)`` 返回 ``(resolvable, status, has_robots)`` —— 注入式，
    所以整条链路离线可测。生产侧包 DNS 解析 + 一次根路径请求 + 一次 robots.txt。

    ``min_citations`` 默认 2：只被引用过一次的 host 大概率是噪声，
    发一次请求去查它不值 —— 而**发请求是有预算的**。
    """
    counts = collect_hosts(urls)
    out: list[OffsiteHost] = []
    for host, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        host_class = classify_host(host, audited_domain=audited_domain)
        if host_class is HostClass.OWN or n < min_citations:
            out.append(
                OffsiteHost(
                    host=host,
                    host_class=host_class,
                    citations=n,
                    pre_production_marker=_marker(host),
                )
            )
            continue
        resolvable, status, has_robots = probe(host)
        out.append(
            OffsiteHost(
                host=host,
                host_class=host_class,
                citations=n,
                resolvable=resolvable,
                status=status,
                has_robots=has_robots,
                pre_production_marker=_marker(host),
            )
        )
    return tuple(out)
