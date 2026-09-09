"""AI 引用了哪些不是你的站。用例全部来自实测。

实测语料：mistral.ai 的两批 50 份回答，检索结果里出现 83 个不同 host。
"""

from __future__ import annotations

import pytest

from geo_audit.checks.offsite_hosts import (
    PREVIEW_SUFFIXES,
    HostClass,
    classify_host,
    collect_hosts,
    judge_offsite_hosts,
)

DOMAIN = "mistral.ai"

#: 实测排名前几的 host（引用次数是真的）。
REAL_HOSTS = {
    "docs.mistral.ai": 589,
    "mistral.ai": 41,
    "github.com": 34,
    "platform-docs-public.pages.dev": 32,
    "docs.aws.amazon.com": 22,
    "huggingface.co": 17,
    "platform-docs-internal.vercel.app": 3,
}


def _urls() -> list[str]:
    return [f"https://{h}/p/{i}" for h, n in REAL_HOSTS.items() for i in range(n)]


def _probe(
    alive: set[str], *, robots: set[str] = frozenset(), unresolvable: set[str] = frozenset()
):
    def probe(host: str) -> tuple[bool, int | None, bool | None]:
        if host in unresolvable:
            return (False, None, None)
        return (True, 200 if host in alive else 404, host in robots)

    return probe


# --------------------------------------------------------------------------- #
# 分类
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("docs.mistral.ai", HostClass.OWN),
        ("mistral.ai", HostClass.OWN),
        ("platform-docs-public.pages.dev", HostClass.PREVIEW),
        ("platform-docs-internal.vercel.app", HostClass.PREVIEW),
        ("github.com", HostClass.THIRD_PARTY),
        ("huggingface.co", HostClass.THIRD_PARTY),
        ("docs.aws.amazon.com", HostClass.THIRD_PARTY),
        ("en.wikipedia.org", HostClass.THIRD_PARTY),
    ],
)
def test_classification_uses_a_suffix_allowlist(host: str, expected: HostClass) -> None:
    """**不是「不等于主域就算问题」** —— 那会把 github / 维基 / AWS 文档全报成问题。

    实测那 83 个 host 里绝大多数是正常的第三方来源。只有预览平台后缀
    （.pages.dev / .vercel.app / …）才值得看一眼。
    """
    assert classify_host(host, audited_domain=DOMAIN) is expected


def test_preview_suffixes_cover_the_platforms_seen_in_the_wild() -> None:
    for suffix in (".pages.dev", ".vercel.app", ".netlify.app", ".github.io"):
        assert suffix in PREVIEW_SUFFIXES


def test_collect_hosts_counts_only() -> None:
    counts = collect_hosts(_urls())
    assert counts["docs.mistral.ai"] == 589
    assert counts["platform-docs-public.pages.dev"] == 32


# --------------------------------------------------------------------------- #
# 判定（两种够得上发现的情形）
# --------------------------------------------------------------------------- #


def test_unresolvable_cited_host_is_a_finding() -> None:
    """实测：platform-docs-public.pages.dev **DNS 解析不出来**，却被引用 32 次。

    这是「AI 还在推荐一个连存在都不存在的地址」—— 也是这个项目最初那个想法
    （旧页面 AI 还能抓到）的实证，而且更严重。
    """
    hosts = judge_offsite_hosts(
        _urls(),
        audited_domain=DOMAIN,
        probe=_probe(alive=set(), unresolvable={"platform-docs-public.pages.dev"}),
    )
    hit = next(h for h in hosts if h.host == "platform-docs-public.pages.dev")
    assert hit.resolvable is False
    assert hit.is_finding
    assert hit.citations == 32


def test_live_preview_with_internal_in_the_name_is_a_finding() -> None:
    """实测：platform-docs-internal.vercel.app 活着、200、且没有 robots.txt。"""
    hosts = judge_offsite_hosts(
        _urls(),
        audited_domain=DOMAIN,
        probe=_probe(alive={"platform-docs-internal.vercel.app"}),
        min_citations=2,
    )
    hit = next(h for h in hosts if h.host == "platform-docs-internal.vercel.app")
    assert hit.pre_production_marker == "internal"
    assert hit.is_finding
    assert hit.has_robots is False


def test_live_preview_without_a_marker_is_not_a_finding() -> None:
    """名字正常的预览域**不单独报** —— 那可能是有意公开的镜像，报了就是误判。"""
    urls = [f"https://docs-mirror.pages.dev/p/{i}" for i in range(5)]
    hosts = judge_offsite_hosts(
        urls, audited_domain=DOMAIN, probe=_probe(alive={"docs-mirror.pages.dev"})
    )
    hit = next(h for h in hosts if h.host == "docs-mirror.pages.dev")
    assert hit.host_class is HostClass.PREVIEW
    assert not hit.is_finding, "有意公开的镜像被报成问题了"


def test_own_and_third_party_hosts_are_never_findings() -> None:
    hosts = judge_offsite_hosts(_urls(), audited_domain=DOMAIN, probe=_probe(alive=set()))
    for h in hosts:
        if h.host_class in (HostClass.OWN, HostClass.THIRD_PARTY):
            assert not h.is_finding, f"{h.host} 被误报"


def test_own_hosts_are_never_probed() -> None:
    """自己的域由 v1 负责扫，这里不重复发请求。"""
    probed: list[str] = []

    def probe(host: str) -> tuple[bool, int | None, bool | None]:
        probed.append(host)
        return (True, 200, True)

    judge_offsite_hosts(_urls(), audited_domain=DOMAIN, probe=probe)
    assert "docs.mistral.ai" not in probed
    assert "mistral.ai" not in probed


def test_single_citation_hosts_are_not_probed() -> None:
    """只被引用一次的大概率是噪声 —— **发请求是有预算的**。"""
    probed: list[str] = []

    def probe(host: str) -> tuple[bool, int | None, bool | None]:
        probed.append(host)
        return (True, 200, True)

    judge_offsite_hosts(
        ["https://one-off.pages.dev/x", *_urls()],
        audited_domain=DOMAIN,
        probe=probe,
        min_citations=2,
    )
    assert "one-off.pages.dev" not in probed
