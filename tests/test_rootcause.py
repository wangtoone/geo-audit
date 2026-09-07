"""G 组 · 根因归并 + 修复建议的第 13 步自验（§5.4 / §5.5，验收 A21）。

期望值来自 ``tests/data/rootcause_expectations.json``；每一条死链 URL 都来自
``corpus/feature-raw.json`` 的 ``c1_dead_links.examples``（第 5 步的 I 组录制清单
§8.2:3922-3950 是同一批），不是本文件编的。三处「按定义推得」的对照状态码在
各自的常量上标了出处。

两条核心断言（§5.4:2905 逐字要求写成两条独立的、各自可单独定位失败的）：
    * ``test_template_bug_family_totals``  —— 模板族 **37 条链接 → 7 个根因**
    * ``test_canvasmedical_full_partition`` —— canvasmedical 全量 **9 → 4**

它们各有一份「读期望表」和一份「跑引擎」的版本：前者守住表本身不被改，
后者守住 ``merge_root_causes`` 真能算出这两个数。
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from geo_audit.fixhint import (
    CANDIDATE_ORDER,
    FIXHINT_MAX_REQUESTS,
    NEAREST_LAST_SEGMENT_MAX_DISTANCE,
    NO_FIX_MESSAGE,
    FixResult,
    drop_last_segment,
    nearest_sitemap_url,
    reportable_fix,
    severity_at_least,
    sibling_host,
    strip_duplicated_prefix,
    suggest_fix,
    swap_host,
)
from geo_audit.models import (
    Classification,
    Expect,
    FixHint,
    HttpResponse,
    Probe,
    Severity,
    Verdict,
)
from geo_audit.rootcause import (
    DEFECT_DETECT,
    DEFECT_FALLBACK,
    DEFECT_FIX,
    DEFECT_IDS,
    DEFECT_LABEL,
    DEFECT_UNKNOWN,
    HOST_VERDICT_DOMAIN_DEAD,
    HOST_VERDICT_PARTIAL_DEAD,
    SEVERITY_ORDER,
    DeadInstance,
    DeadTarget,
    ProbeLedger,
    RootCause,
    common_prefix_segments,
    detect_defect,
    edit_distance,
    fold_instances,
    host_verdict,
    merge_root_causes,
    normalize_url,
    root_causes_from_instances,
    source_locus,
)

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "tests" / "data"
FIXTURE_INDEX = REPO / "fixtures" / "index.json"

EXPECTATIONS: dict[str, Any] = json.loads(
    (DATA / "rootcause_expectations.json").read_text(encoding="utf-8")
)
FAMILIES: list[dict[str, Any]] = EXPECTATIONS["template_bug_families"]
PER_DOMAIN: list[dict[str, Any]] = EXPECTATIONS["per_domain"]

real_index_needed = pytest.mark.skipif(
    not FIXTURE_INDEX.exists(),
    reason="实录快照还没录（第 4b 步）——不许编快照，优雅跳过",
)


def load_expectations() -> dict[str, Any]:
    """§5.4:2906 的测试代码里就叫这个名字。"""
    return EXPECTATIONS


def expectation_for(domain: str) -> dict[str, Any]:
    return next(row for row in PER_DOMAIN if row["domain"] == domain)


# ═════════════════════════════════════════════════════════════════════════════
# 实测输入 —— 六个模板 bug 族 + canvasmedical 全量 + swell 全量
# 每族给一个 ``(instances, ledger, audited_domain)`` 工厂。
# ═════════════════════════════════════════════════════════════════════════════


def _inst(
    url: str,
    page: str,
    *,
    container: str = "block",
    anchor: str = "",
    severity: Severity = Severity.MEDIUM,
    raw_href: str = "",
) -> DeadInstance:
    return DeadInstance(
        abs_url=url,
        source_page=page,
        container_sig=container,
        anchor_text=anchor,
        severity=severity,
        raw_href=raw_href,
    )


# ── tdengine：首页开源版区块的连接器图标墙，8 个语言全指旧路径 ────────────────
TDENGINE_PAGE = "https://tdengine.com/"
TDENGINE_LANGS = ("java", "python", "go", "rust", "csharp", "cpp", "node", "r-lang")
TDENGINE_DEAD = tuple(f"https://docs.tdengine.com/reference/connector/{s}/" for s in TDENGINE_LANGS)
#: corpus 原文：「文档站已把路径迁到 /developer-guide/connectors-reference/*
#: （sitemap.xml 里有 java/go/csharp/cpp 等新路径）」。`*` 与「等」是原话，
#: 所以这里把 8 个语言都列进 sitemap；I 组另录了 …/connectors-reference/ 为 200。
TDENGINE_SITEMAP = (
    "https://docs.tdengine.com/developer-guide/connectors-reference/",
    *(
        f"https://docs.tdengine.com/developer-guide/connectors-reference/{s}"
        for s in TDENGINE_LANGS
    ),
)


def tdengine_case() -> tuple[tuple[DeadInstance, ...], ProbeLedger, str]:
    instances = tuple(
        _inst(u, TDENGINE_PAGE, container="home-connector-wall", anchor=lang.upper())
        for u, lang in zip(TDENGINE_DEAD, TDENGINE_LANGS, strict=True)
    )
    ledger = ProbeLedger(
        statuses={
            **{normalize_url(u): 404 for u in TDENGINE_DEAD},
            normalize_url(TDENGINE_SITEMAP[0]): 200,
        },
        sitemap_urls=TDENGINE_SITEMAP,
        host_ok_counts={"docs.tdengine.com": 1},
    )
    return instances, ledger, "tdengine.com"


# ── bytebase：changelog 页导航 6 条写成了 www 下的相对路径 ────────────────────
BYTEBASE_PAGE = "https://www.bytebase.com/changelog/"
BYTEBASE_DEAD: tuple[tuple[str, str], ...] = (
    ("https://www.bytebase.com/introduction/what-is-bytebase", "Get Started"),
    ("https://www.bytebase.com/change-database/change-workflow", "Change Management"),
    ("https://www.bytebase.com/security/database-permission/overview", "Access Control"),
    ("https://www.bytebase.com/tutorials/first-schema-change", "Tutorials"),
    ("https://www.bytebase.com/get-started/self-host/deploy-with-docker", "Fresh install"),
    ("https://www.bytebase.com/get-started/self-host/upgrade", "Upgrade"),
)


def bytebase_case() -> tuple[tuple[DeadInstance, ...], ProbeLedger, str]:
    instances = tuple(
        _inst(u, BYTEBASE_PAGE, container="changelog-nav", anchor=a) for u, a in BYTEBASE_DEAD
    )
    statuses: dict[str, int] = {}
    for url, _ in BYTEBASE_DEAD:
        statuses[normalize_url(url)] = 404
        # corpus 原文：「同名的 docs.bytebase.com 路径全部 200」
        statuses[normalize_url(url.replace("www.", "docs."))] = 200
    ledger = ProbeLedger(statuses=statuses, host_ok_counts={"docs.bytebase.com": 6})
    return instances, ledger, "bytebase.com"


# ── copper：Intercom 帮助中心页脚四个社交图标，字段填了整条 URL ───────────────
COPPER_PAGE = "https://support.copper.com/en/"
COPPER_DEAD = (
    "https://www.facebook.com/https://www.facebook.com/CopperInc/",
    "https://www.instagram.com/https://www.instagram.com/copper.crm",
    "https://www.linkedin.com/https://www.linkedin.com/company/copper-inc/",
    "https://www.youtube.com/https://www.youtube.com/c/CopperInc",
)


def copper_case() -> tuple[tuple[DeadInstance, ...], ProbeLedger, str]:
    instances = tuple(
        _inst(u, COPPER_PAGE, container="footer-social", severity=Severity.LOW, raw_href=u)
        for u in COPPER_DEAD
    )
    ledger = ProbeLedger(statuses={normalize_url(u): 404 for u in COPPER_DEAD})
    return instances, ledger, "copper.com"


# ── canvasmedical：9 条死链全在 release notes 一页上 ─────────────────────────
CANVAS_PAGE = "https://docs.canvasmedical.com/product-updates/release-notes/"
CANVAS_RELATIVE = (
    "https://docs.canvasmedical.com/product-updates/release-notes/sdk/layout-effect/",
    "https://docs.canvasmedical.com/product-updates/release-notes/sdk/effect-notes/",
    "https://docs.canvasmedical.com/product-updates/release-notes/product-updates/commands-module/",
)
CANVAS_ROUTE_MISSING = (
    "https://docs.canvasmedical.com/sdk/canvas-cli/",
    "https://docs.canvasmedical.com/documentation/pdf-annotations/",
)
CANVAS_HELP = (
    "https://help.canvasmedical.com/articles/7998893827-managing-conditions",
    "https://canvas-medical.help.usepylon.com/articles/7998893827-managing-conditions",
)
CANVAS_REPO = (
    "https://github.com/canvas-medical/canvas-plugins/blob/main/example-plugins/"
    "example_patient_sync/README.md",
    "https://github.com/canvas-medical/canvas-plugins/blob/main/example-plugins/"
    "vitals_visualizer_plugin/README.md",
)
CANVAS_DEAD_9 = (*CANVAS_RELATIVE, *CANVAS_ROUTE_MISSING, *CANVAS_HELP, *CANVAS_REPO)
#: corpus 逐字录了第一条的对照：「正确的 https://docs.canvasmedical.com/
#: sdk/layout-effect/ 是 200」。另两条只写了「同类相对路径 bug」——而
#: relative_path_prefixed 这条指纹的定义就是「剥掉当前页路径前缀后该 URL 返回
#: 200」，所以另两条剥出来的路径按定义必须 200。这里据此填对照，不是编数。
CANVAS_STRIPPED_OK = (
    "https://docs.canvasmedical.com/sdk/layout-effect/",
    "https://docs.canvasmedical.com/sdk/effect-notes/",
    "https://docs.canvasmedical.com/product-updates/commands-module/",
)
CANVAS_REPO_CONTROL = "https://github.com/canvas-medical/canvas-plugins"


def canvasmedical_case() -> tuple[tuple[DeadInstance, ...], ProbeLedger, str]:
    """9 条死链同页同容器（corpus 每条都标了「同页」，§8.2 也只录了这一个源页）。

    ⚠️ 简报 spec_gaps#20 担心的是 ``deleted_help_article`` 那两条跨 host 连不上
    E1：E1 第二支要求同 host，两条不同 host，只能靠「source_locus 相同」。这里
    9 条同 locus，所以 E1 第一支成立；同时 E2 不会把不同 defect 的族串起来 ——
    ``/product-updates/…`` 与 ``/sdk/…`` / ``/articles/…`` / ``/canvas-medical/…``
    的公共前缀是 0 段，够不上 E2 的 ≥1 段门槛。
    """
    instances = tuple(_inst(u, CANVAS_PAGE, container="release-notes-body") for u in CANVAS_DEAD_9)
    statuses = {
        **{normalize_url(u): 404 for u in CANVAS_DEAD_9},
        **{normalize_url(u): 200 for u in CANVAS_STRIPPED_OK},
        normalize_url(CANVAS_REPO_CONTROL): 200,
    }
    ledger = ProbeLedger(
        statuses=statuses,
        host_ok_counts={"docs.canvasmedical.com": 3, "github.com": 1},
    )
    return instances, ledger, "canvasmedical.com"


# ── saleor：10 个链接实例 → 2 个唯一路径 ────────────────────────────────────
SALEOR_HOME = "https://saleor.io/"
SALEOR_PRICING = "https://saleor.io/pricing"
SALEOR_TALK = "https://saleor.io/cloud/talk-to-us?cta=See+how+Saleor+fits&cta_page=%2F"
SALEOR_PRICING_CTA = "https://saleor.io/cloud/pricing-page?cta=Talk+to+us&cta_page=%2Fpricing"


def saleor_case() -> tuple[tuple[DeadInstance, ...], ProbeLedger, str]:
    """occurrences 7 / 3：corpus 给了「10 个链接实例」+ pricing 页「共 3 处」。"""
    instances = tuple(
        [
            _inst(
                SALEOR_TALK,
                SALEOR_HOME,
                container="home-cta",
                anchor="See how Saleor fits",
                severity=Severity.CRITICAL,
            )
        ]
        * 7
        + [
            _inst(
                SALEOR_PRICING_CTA,
                SALEOR_PRICING,
                container="pricing-card",
                anchor="Talk to us",
                severity=Severity.CRITICAL,
            )
        ]
        * 3
    )
    ledger = ProbeLedger(
        statuses={
            normalize_url(SALEOR_TALK): 404,
            normalize_url(SALEOR_PRICING_CTA): 404,
            "https://saleor.io/talk-to-us": 404,
            "https://saleor.io/contact": 200,
        },
        sitemap_urls=("https://saleor.io/contact", "https://saleor.io/pricing"),
        host_ok_counts={"saleor.io": 2},
    )
    return instances, ledger, "saleor.io"


# ── brevo：markdown 族 6 条 + 旧品牌域名族 5 条 + 正文两条 + 本域一条 = 14 ──
BREVO_PAGE = "https://developers.brevo.com/changelog"
#: corpus 逐字录了 createdomain 那条完整 URL，并写「同型还有 deletedomain /
#: getdomains / getallexternalfeeds / updatecontact / updatebatchcontacts」——
#: 这里按同一串形状换 reference 名补全另 5 条（与 deadlink_labels.jsonl 里
#: provenance="reconstructed" 的做法一致：保形，不编新形态）。
BREVO_MD_REFS = (
    "createdomain",
    "deletedomain",
    "getdomains",
    "getallexternalfeeds",
    "updatecontact",
    "updatebatchcontacts",
)
BREVO_MARKDOWN = tuple(
    "https://developers.brevo.com/%5Bhttps:/developers.sendinblue.com/reference/"
    f"{ref}%5D(https:/developers.sendinblue.com/reference/{ref})"
    for ref in BREVO_MD_REFS
)
BREVO_LEGACY = (
    "https://developers.sendinblue.com/reference/sendtransacsms",
    "https://developers.sendinblue.com/reference/updatebatchcontacts",
    "https://developers.sendinblue.com/reference/contacts-7",
    "https://developers.sendinblue.com/changelog/attribute-deprecation-in-contact-export-endpoint",
    "https://developers.sendinblue.com/changelog/"
    "new-custom-filter-added-for-export-contacts-api-route",
)
BREVO_BODY_GUIDE = (
    "https://developers.brevo.com/docs/api-clients/python",
    "https://developers.brevo.com/docs/api-clients/node-js",
)
BREVO_OWN_DOMAIN = "https://developers.brevo.com/reference/sendtransacsms"
#: corpus：「同页上另有 15 条 sendinblue 链接仍然 200，所以不能整域名一刀切」
BREVO_LEGACY_HOST_ALIVE = 15


def _brevo_ledger() -> ProbeLedger:
    statuses: dict[str, int] = {
        **{normalize_url(u): 404 for u in BREVO_MARKDOWN},
        **{normalize_url(u): 404 for u in BREVO_LEGACY},
        **{normalize_url(u): 404 for u in BREVO_BODY_GUIDE},
        normalize_url(BREVO_OWN_DOMAIN): 404,
        # I 组录的 200 对照
        "https://developers.sendinblue.com/": 200,
        "https://developers.brevo.com/docs/api-clients": 200,
    }
    return ProbeLedger(
        statuses=statuses,
        host_ok_counts={
            "developers.sendinblue.com": BREVO_LEGACY_HOST_ALIVE,
            "developers.brevo.com": 1,
        },
    )


def brevo_markdown_case() -> tuple[tuple[DeadInstance, ...], ProbeLedger, str]:
    """6 条**各在自己的 changelog 条目里**（最保守的容器假设）。

    这么放还能归成 1 个根因，靠的是 E1 第二支：同 host + 公共前缀 ≥2 段
    （``/%5Bhttps:/developers.sendinblue.com/reference/…``）。也就是说这一族
    不依赖 container_sig 怎么切，实录快照回填后不会翻。
    """
    instances = tuple(
        _inst(u, BREVO_PAGE, container=f"changelog-entry-{i}", raw_href=u)
        for i, u in enumerate(BREVO_MARKDOWN)
    )
    return instances, _brevo_ledger(), "brevo.com"


def brevo_legacy_case() -> tuple[tuple[DeadInstance, ...], ProbeLedger, str]:
    """5 条旧品牌域名残留，同一个链接块里（corpus 只说「同页」，容器待实测）。"""
    instances = tuple(
        _inst(u, BREVO_PAGE, container="changelog-legacy-links") for u in BREVO_LEGACY
    )
    return instances, _brevo_ledger(), "brevo.com"


# ── swell：12 条全在 changelog 一页（deadlink_labels.jsonl H11–H22）─────────
SWELL_PAGE = "https://www.swell.is/changelog"
SWELL_DEAD = (
    "https://www.swell.is/help/integrations/hubspot",
    "https://developers.swell.is/backend-api/events/the-events-model",
    "https://github.com/swellstores/swell-sdk",
    "https://developers.swell.is/storefronts/storefront-apps/builder-io",
    "https://www.swell.is/help/storefronts/themes/origin",
    "https://www.swell.is/help/storefronts/themes/storefront-editor",
    "https://www.swell.is/help/storefronts/themes/storefront-imagery",
    "https://www.swell.is/help/integrations/payment-integrations/affirm",
    "https://www.swell.is/help/integrations/google-pay-and-apple-pay-for-braintree",
    "https://www.swell.is/help/integrations/paysafecard",
    "https://www.swell.is/help/integrations/quickpay",
    "https://www.swell.is/help/integrations/smartystreets",
)


def swell_case() -> tuple[tuple[DeadInstance, ...], ProbeLedger, str]:
    instances = tuple(_inst(u, SWELL_PAGE, container="changelog-body") for u in SWELL_DEAD)
    ledger = ProbeLedger(
        statuses={
            **{normalize_url(u): 404 for u in SWELL_DEAD},
            "https://github.com/swellstores": 200,  # H13 的 sibling_control
        },
        host_ok_counts={"github.com": 1},
    )
    return instances, ledger, "swell.is"


def run_case(
    case: tuple[Sequence[DeadInstance], ProbeLedger, str],
) -> tuple[RootCause, ...]:
    instances, ledger, domain = case
    return root_causes_from_instances(instances, ledger=ledger, audited_domain=domain)


#: 模板 bug 族的六个工厂，键与期望表的 domain 对齐。
FAMILY_CASES = {
    "tdengine.com": tdengine_case,
    "bytebase.com": bytebase_case,
    "copper.com": copper_case,
    "canvasmedical.com": canvasmedical_case,  # 只用第①区，见 family_root_causes
    "brevo.com": brevo_markdown_case,
    "saleor.io": saleor_case,
}


def family_root_causes(domain: str) -> tuple[RootCause, ...]:
    """按期望表的族口径跑引擎：canvasmedical 只取第①区（3 条相对路径）。"""
    if domain == "canvasmedical.com":
        _, ledger, audited = canvasmedical_case()
        instances = tuple(
            _inst(u, CANVAS_PAGE, container="release-notes-body") for u in CANVAS_RELATIVE
        )
        return root_causes_from_instances(instances, ledger=ledger, audited_domain=audited)
    return run_case(FAMILY_CASES[domain]())


def root_causes_for(domain: str) -> tuple[RootCause, ...]:
    """§5.4:2911 的测试代码里就叫这个名字（全量口径，不是族口径）。"""
    cases = {
        "tdengine.com": tdengine_case,
        "bytebase.com": bytebase_case,
        "copper.com": copper_case,
        "canvasmedical.com": canvasmedical_case,
        "saleor.io": saleor_case,
        "swell.is": swell_case,
    }
    return run_case(cases[domain]())


# ═════════════════════════════════════════════════════════════════════════════
# 第一级折叠：normalize_url + fold_instances
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # saleor 的 10 个实例折成 2 个唯一路径就靠这一步
        (SALEOR_TALK, "https://saleor.io/cloud/talk-to-us"),
        ("https://saleor.io/cloud/talk-to-us#top", "https://saleor.io/cloud/talk-to-us"),
        ("https://saleor.io/cloud/talk-to-us/", "https://saleor.io/cloud/talk-to-us"),
        ("https://SALEOR.io/Cloud", "https://saleor.io/Cloud"),  # host 小写，path 不动
        ("https://x.com/?utm_source=nav&utm_medium=x", "https://x.com/"),
        ("https://x.com/a?ref=nav&fbclid=1&gclid=2&source=home", "https://x.com/a"),
        ("https://x.com/a?page=2", "https://x.com/a?page=2"),  # 非跟踪型 query 保留
        ("https://x.com/", "https://x.com/"),
        # 空 path 与 / 折成同一个身份（与 extract.normalize_url 的唯一差异）
        ("https://x.com", "https://x.com/"),
    ],
)
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


def test_normalize_url_is_the_only_identity_ruleset() -> None:
    """§5.4:2838 的口径就是 finding 身份 —— 三种写法必须折成同一个 norm_url。"""
    variants = (
        SALEOR_TALK,
        "https://saleor.io/cloud/talk-to-us/",
        "https://SALEOR.io/cloud/talk-to-us#pricing",
    )
    assert len({normalize_url(u) for u in variants}) == 1


def test_saleor_ten_instances_fold_into_two_findings() -> None:
    instances, _, _ = saleor_case()
    targets = fold_instances(instances)
    assert len(targets) == 2
    assert [t.occurrences for t in targets] == [7, 3]
    assert sum(t.occurrences for t in targets) == 10
    expected = expectation_for("saleor.io")["occurrences"]
    assert {t.norm_url: t.occurrences for t in targets} == expected


def test_fold_keeps_raw_urls_for_probing() -> None:
    """探测用 abs_url 原样探（服务端可能对 query 敏感），只有归并用 norm_url。"""
    target = fold_instances(saleor_case()[0])[0]
    assert target.abs_url == SALEOR_TALK
    assert target.abs_url != target.norm_url
    assert target.occurrence_hrefs == (SALEOR_TALK,)


def test_fold_takes_worst_severity_in_the_group() -> None:
    targets = fold_instances(
        (
            _inst(SALEOR_TALK, SALEOR_HOME, severity=Severity.LOW),
            _inst(SALEOR_TALK, SALEOR_PRICING, severity=Severity.CRITICAL),
        )
    )
    assert len(targets) == 1
    assert targets[0].severity is Severity.CRITICAL
    assert targets[0].occurrence_pages == (SALEOR_HOME, SALEOR_PRICING)


def test_common_prefix_and_locus_helpers() -> None:
    assert common_prefix_segments(CANVAS_RELATIVE[0], CANVAS_RELATIVE[1]) == 3
    assert common_prefix_segments(CANVAS_RELATIVE[0], CANVAS_ROUTE_MISSING[0]) == 0
    # 同一篇文章挂在两个 host 上：路径逐段相同（/articles/<同一个 id>）
    assert common_prefix_segments(*CANVAS_HELP) == 2
    assert common_prefix_segments(SALEOR_TALK, SALEOR_PRICING_CTA) == 1  # < 2 → E1 连不上
    assert source_locus("p", "c") == "p|c"
    assert edit_distance("daniliwoz", "danilowoz") == 1  # 一次替换（i↔o），≤2


# ═════════════════════════════════════════════════════════════════════════════
# 14 条缺陷指纹 + 1 条兜底
# ═════════════════════════════════════════════════════════════════════════════


def test_defect_table_is_complete() -> None:
    """15 行 = 14 条指纹 + 1 条兜底；每条都有检测口径、一句话修复、中文名。"""
    assert len(DEFECT_IDS) == 15
    assert DEFECT_IDS[-1] == DEFECT_FALLBACK
    assert len(set(DEFECT_IDS)) == 15
    for defect in DEFECT_IDS:
        assert DEFECT_DETECT[defect]
        assert DEFECT_FIX[defect]
        assert DEFECT_LABEL[defect]
    # 期望表里 defect_fingerprints 也是 15 行，两边逐条对齐
    assert {row["defect"] for row in EXPECTATIONS["defect_fingerprints"]} == set(DEFECT_IDS)


def test_deleted_help_article_is_the_v2_addition() -> None:
    """v1 缺这条指纹，canvasmedical 那 2 条只能落 route_missing，根因数就算不对。"""
    assert "deleted_help_article" in DEFECT_IDS
    row = next(
        r for r in EXPECTATIONS["defect_fingerprints"] if r["defect"] == "deleted_help_article"
    )
    assert row["note"] == "v2 新增指纹"


def _detect_one(
    url: str,
    page: str,
    ledger: ProbeLedger,
    *,
    audited_domain: str = "",
    anchor: str = "",
    raw_href: str = "",
    peers: Sequence[DeadTarget] = (),
) -> str:
    target = DeadTarget.from_instance(
        _inst(url, page, anchor=anchor, raw_href=raw_href),
    )
    return detect_defect(target, ledger, audited_domain=audited_domain, peers=peers).defect


def test_defect_url_concatenated_twice() -> None:
    _, ledger, domain = copper_case()
    for url in COPPER_DEAD:
        assert (
            _detect_one(url, COPPER_PAGE, ledger, audited_domain=domain, raw_href=url)
            == "url_concatenated_twice"
        )


def test_defect_markdown_link_not_rendered() -> None:
    _, ledger, domain = brevo_markdown_case()
    for url in BREVO_MARKDOWN:
        assert (
            _detect_one(url, BREVO_PAGE, ledger, audited_domain=domain, raw_href=url)
            == "markdown_link_not_rendered"
        )


def test_defect_mailto_as_relative_path() -> None:
    """pingcap：release notes 页 5 处，锚文本显示 support@pingcap.com。"""
    url = "https://docs.pingcap.com/tidbcloud/mailto:support@pingcap.com/"
    page = "https://docs.pingcap.com/tidbcloud/tidb-cloud-release-notes/"
    ledger = ProbeLedger(statuses={normalize_url(url): 404})
    assert (
        _detect_one(url, page, ledger, audited_domain="pingcap.com", anchor="support@pingcap.com")
        == "mailto_as_relative_path"
    )


def test_defect_relative_path_prefixed() -> None:
    _, ledger, domain = canvasmedical_case()
    for url in CANVAS_RELATIVE:
        assert (
            _detect_one(url, CANVAS_PAGE, ledger, audited_domain=domain) == "relative_path_prefixed"
        )


def test_defect_wrong_host() -> None:
    _, ledger, domain = bytebase_case()
    for url, anchor in BYTEBASE_DEAD:
        assert _detect_one(url, BYTEBASE_PAGE, ledger, audited_domain=domain, anchor=anchor) == (
            "wrong_host"
        )


def test_defect_stale_path_after_migration() -> None:
    _, ledger, domain = tdengine_case()
    for url in TDENGINE_DEAD:
        assert (
            _detect_one(url, TDENGINE_PAGE, ledger, audited_domain=domain)
            == "stale_path_after_migration"
        )


def test_defect_suffix_artifact() -> None:
    """replicate：docs/llms.txt 里 6 条 /index 结尾的链接全 404，去掉就 200。"""
    url = "https://replicate.com/docs/topics/billing/index"
    ledger = ProbeLedger(
        statuses={
            normalize_url(url): 404,
            "https://replicate.com/docs/topics/billing": 200,
        }
    )
    page = "https://replicate.com/docs/llms.txt"
    assert _detect_one(url, page, ledger, audited_domain="replicate.com") == "suffix_artifact"


def test_defect_template_concat_is_not_url_concatenated_twice() -> None:
    """inngest 的形态与 copper 的形态必须落到不同的两条指纹上（规格两处锚点）。"""
    url = "https://www.inngest.com/docs-markdownhttps://agentkit.inngest.com"
    ledger = ProbeLedger(statuses={normalize_url(url): 404})
    assert (
        _detect_one(url, "https://www.inngest.com/llms.txt", ledger, audited_domain="inngest.com")
        == "template_concat"
    )


def test_defect_typo_vs_anchor_text() -> None:
    """liveblocks：href 拼成 daniliwoz，锚文本却是 @danilowoz。"""
    url = "https://github.com/daniliwoz"
    ledger = ProbeLedger(
        statuses={normalize_url(url): 404, "https://github.com/ctnicholas": 200},
        host_ok_counts={"github.com": 1},
    )
    assert (
        _detect_one(
            url,
            "https://liveblocks.io/changelog",
            ledger,
            audited_domain="liveblocks.io",
            anchor="@danilowoz",
        )
        == "typo_vs_anchor_text"
    )


def test_defect_renamed_social_handle() -> None:
    """baseten：文档站链 x.com/basetenco（404），营销站链 x.com/baseten（200）。"""
    url = "https://x.com/basetenco"
    ledger = ProbeLedger(
        statuses={
            normalize_url(url): 404,
            "https://x.com/baseten": 200,
            "https://x.com/openai": 200,  # 纯对照探测，不是营销站链的
        },
        alive_site_links=frozenset({"https://x.com/baseten"}),
        host_ok_counts={"x.com": 2},
    )
    verdict = detect_defect(
        DeadTarget.from_instance(_inst(url, "https://docs.baseten.co/overview")),
        ledger,
        audited_domain="baseten.co",
    )
    assert verdict.defect == "renamed_social_handle"
    assert verdict.control_url == "https://x.com/baseten"


def test_defect_deleted_third_party_repo() -> None:
    _, ledger, domain = swell_case()
    assert (
        _detect_one(
            "https://github.com/swellstores/swell-sdk",
            SWELL_PAGE,
            ledger,
            audited_domain=domain,
            anchor="New product methods in Swell SDK",
        )
        == "deleted_third_party_repo"
    )


def test_defect_deleted_help_article_needs_both_hosts() -> None:
    """一条单独看不出来，两条（原 host + 真身 host）放一起才成立。"""
    _, ledger, domain = canvasmedical_case()
    peers = fold_instances(
        tuple(_inst(u, CANVAS_PAGE, container="release-notes-body") for u in CANVAS_HELP)
    )
    for url in CANVAS_HELP:
        assert (
            _detect_one(url, CANVAS_PAGE, ledger, audited_domain=domain, peers=peers)
            == "deleted_help_article"
        )
    # 只有原 host 那一条时不成立（真身没被抽到就没有第二个 host 的证据）
    alone = fold_instances((_inst(CANVAS_HELP[0], CANVAS_PAGE),))
    assert (
        _detect_one(CANVAS_HELP[0], CANVAS_PAGE, ledger, audited_domain=domain, peers=alone)
        != "deleted_help_article"
    )


def test_defect_dead_third_party_site() -> None:
    """voyageai → xayn.com 根路径直接返回「404 page not found」。"""
    url = "https://xayn.com/"
    ledger = ProbeLedger(statuses={normalize_url(url): 404})
    assert (
        _detect_one(url, "https://www.voyageai.com/", ledger, audited_domain="voyageai.com")
        == "dead_third_party_site"
    )


def test_dead_third_party_site_does_not_fire_when_root_is_alive() -> None:
    """replicate → replicatestatus.com/feed 404 但根域 200，不能整站判死。"""
    url = "https://replicatestatus.com/feed"
    ledger = ProbeLedger(
        statuses={normalize_url(url): 404, "https://replicatestatus.com/": 200},
        host_ok_counts={"replicatestatus.com": 1},
    )
    defect = _detect_one(
        url, "https://replicate.com/changelog", ledger, audited_domain="replicate.com"
    )
    assert defect != "dead_third_party_site"
    assert defect == DEFECT_UNKNOWN  # 第三方 host、对照不足 → 不归因，也不进归并


def test_defect_legacy_brand_domain_never_kills_the_whole_host() -> None:
    _, ledger, domain = brevo_legacy_case()
    for url in BREVO_LEGACY:
        verdict = detect_defect(
            DeadTarget.from_instance(_inst(url, BREVO_PAGE)),
            ledger,
            audited_domain=domain,
        )
        assert verdict.defect == "legacy_brand_domain"
        assert f"另有 {BREVO_LEGACY_HOST_ALIVE} 条" in verdict.evidence
    assert host_verdict("developers.sendinblue.com", ledger) != HOST_VERDICT_DOMAIN_DEAD
    assert host_verdict("developers.sendinblue.com", ledger) == HOST_VERDICT_PARTIAL_DEAD


def test_defect_route_missing_is_the_fallback() -> None:
    _, ledger, domain = saleor_case()
    assert (
        _detect_one(SALEOR_TALK, SALEOR_HOME, ledger, audited_domain=domain, anchor="See how")
        == DEFECT_FALLBACK
    )


def test_upstream_given_defect_wins() -> None:
    """标注文件/上游已经定了 defect 时不再重判（deadlink_labels.jsonl 就给了）。"""
    target = DeadTarget.from_instance(
        DeadInstance(abs_url=SALEOR_TALK, source_page=SALEOR_HOME, defect="route_missing")
    )
    assert detect_defect(target, ProbeLedger()).defect == "route_missing"


# ═════════════════════════════════════════════════════════════════════════════
# 两条核心断言 —— 各自可单独定位失败
# ═════════════════════════════════════════════════════════════════════════════


def test_template_bug_family_totals() -> None:
    """§5.4:2906 逐字：37 → 7，不是 38 → 7，也不是作废的 44 → 7。"""
    fam = load_expectations()["template_bug_families"]
    assert sum(f["links"] for f in fam) == 37
    assert sum(f["root_causes"] for f in fam) == 7
    assert {f["domain"] for f in fam} == {
        "tdengine.com",
        "bytebase.com",
        "copper.com",
        "canvasmedical.com",
        "brevo.com",
        "saleor.io",
    }


def test_template_bug_family_totals_from_engine() -> None:
    """同一个 37 → 7，这次是真跑引擎算出来的（8+6+4+3+6+10 = 37，saleor 占 2）。"""
    links = 0
    root_causes = 0
    for family in FAMILIES:
        rcs = family_root_causes(family["domain"])
        got_links = sum(rc.instance_count for rc in rcs)
        assert got_links == family["links"], family["domain"]
        assert len(rcs) == family["root_causes"], family["domain"]
        assert {rc.defect for rc in rcs} == {family["defect"]}, family["domain"]
        links += got_links
        root_causes += len(rcs)
    assert (links, root_causes) == (37, 7)


def test_canvasmedical_full_partition() -> None:
    """§5.4:2911 逐字：全量 9 → 4，四个 defect 齐全，instance_count 排序 [2,2,2,3]。"""
    rcs = root_causes_for("canvasmedical.com")
    assert len(rcs) == 4
    assert {rc.defect for rc in rcs} == {
        "relative_path_prefixed",
        "route_missing",
        "deleted_help_article",
        "deleted_third_party_repo",
    }
    assert sorted(rc.instance_count for rc in rcs) == [2, 2, 2, 3]


def test_canvasmedical_partition_matches_expectations_file() -> None:
    """期望表 partition 的每一区（defect + links + urls）都要对得上。"""
    rcs = root_causes_for("canvasmedical.com")
    by_defect = {rc.defect: rc for rc in rcs}
    for part in expectation_for("canvasmedical.com")["partition"]:
        rc = by_defect[part["defect"]]
        assert rc.unique_target_count == part["links"]
        assert rc.instance_count == part["links"]
    assert expectation_for("canvasmedical.com")["instance_counts_sorted"] == sorted(
        rc.instance_count for rc in rcs
    )


def test_canvasmedical_relative_family_evidence_quotes_the_200() -> None:
    """G 组硬要求：相对路径族的证据句里必须有「/sdk/layout-effect/ 返回 200」。"""
    rc = next(
        rc for rc in root_causes_for("canvasmedical.com") if rc.defect == "relative_path_prefixed"
    )
    # G 组行文里的原话是「`/sdk/layout-effect/` 返回 200」，逐字守住
    assert "/sdk/layout-effect/ 返回 200" in rc.summary
    assert rc.summary.count("404，剥掉当前页前缀") == 3  # 三条各自带一句可复核的证据


# ═════════════════════════════════════════════════════════════════════════════
# 逐域全量（每个域自己的死链 → 自己的根因数）
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    ("domain", "links", "root_causes"),
    [
        ("tdengine.com", 8, 1),
        ("bytebase.com", 6, 1),
        ("copper.com", 4, 1),
        ("saleor.io", 10, 2),
        ("canvasmedical.com", 9, 4),
    ],
)
def test_per_domain_root_cause_counts(domain: str, links: int, root_causes: int) -> None:
    row = expectation_for(domain)
    assert (row["dead_links"], row["root_causes"]) == (links, root_causes)
    assert row["pending"] is False
    rcs = root_causes_for(domain)
    assert len(rcs) == root_causes
    assert sum(rc.instance_count for rc in rcs) == links


def test_brevo_markdown_and_legacy_subfamilies() -> None:
    """brevo 全量 14 → 4 标着 pending；两个已确定的子族（6→1、5→1）现在就守住。"""
    row = expectation_for("brevo.com")
    assert row["pending"] is True
    subs = {s["defect"]: s for s in row["sub_families"]}

    md = run_case(brevo_markdown_case())
    assert len(md) == subs["markdown_link_not_rendered"]["root_causes"] == 1
    assert md[0].instance_count == subs["markdown_link_not_rendered"]["links"] == 6
    assert md[0].defect == "markdown_link_not_rendered"

    legacy = run_case(brevo_legacy_case())
    assert len(legacy) == subs["legacy_brand_domain"]["root_causes"] == 1
    assert legacy[0].instance_count == subs["legacy_brand_domain"]["links"] == 5
    assert f"另有 {BREVO_LEGACY_HOST_ALIVE} 条" in legacy[0].summary


@real_index_needed
def test_brevo_full_14_into_4() -> None:
    """brevo 全量 14 → 4 的分区依赖 changelog 页真实的容器切分（期望表 pending）。

    第 12/13 步的实录快照回填后才能定：``/docs/api-clients/{python,node-js}``
    与 ``/reference/sendtransacsms`` 是否同一个 container_sig —— 同则 3 个根因，
    异则 4 个。没有快照就跳过，不许拿编的容器去凑那个 4。
    """
    pytest.skip("需要 developers.brevo.com/changelog 的实录快照才能定容器切分")


@pytest.mark.xfail(
    reason="§5.4:2897 明写「先按 1 个根因写占位断言并标 xfail」；12 条按 E1/E2 实际分 4 族",
)
def test_swell_placeholder_one_root_cause() -> None:
    row = expectation_for("swell.is")
    assert row["pending"] is True and row["xfail"] is True
    assert len(root_causes_for("swell.is")) == row["root_causes"] == 1


def test_swell_twelve_links_are_all_on_one_page() -> None:
    """占位断言之外，能确定的部分照样测：12 条全在 changelog 一页上。"""
    instances, _, _ = swell_case()
    assert len(instances) == expectation_for("swell.is")["dead_links"] == 12
    assert {i.source_page for i in instances} == {SWELL_PAGE}


# ═════════════════════════════════════════════════════════════════════════════
# A21：每条 RootCause 的 merge_axes / fix_once / defect 都非空
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "domain",
    ["tdengine.com", "bytebase.com", "copper.com", "saleor.io", "canvasmedical.com", "swell.is"],
)
def test_every_root_cause_is_auditable(domain: str) -> None:
    for rc in root_causes_for(domain):
        assert rc.merge_axes, rc
        assert set(rc.merge_axes) == {"defect", "source_locus", "path_prefix", "edges"}
        assert all(v != "" for k, v in rc.merge_axes.items() if k != "path_prefix")
        assert rc.fix_once
        assert rc.defect
        assert rc.defect != DEFECT_UNKNOWN
        assert rc.root_cause_id.startswith("RC-")
        assert rc.finding_ids
        assert rc.unique_target_count == len(rc.finding_ids)
        assert rc.instance_count >= rc.unique_target_count
        assert rc.summary
        assert rc.source_pages


def test_fix_once_says_how_many_one_change_fixes() -> None:
    rc = root_causes_for("tdengine.com")[0]
    assert rc.fix_once.startswith("改 1 处 → 修 8 条")
    assert DEFECT_FIX["stale_path_after_migration"] in rc.fix_once
    assert rc.merge_axes["edges"] in ("E1", "E1,E2", "E2")


def test_root_cause_ids_are_stable_and_order_independent() -> None:
    instances, ledger, domain = canvasmedical_case()
    forward = root_causes_from_instances(instances, ledger=ledger, audited_domain=domain)
    backward = root_causes_from_instances(
        tuple(reversed(instances)), ledger=ledger, audited_domain=domain
    )
    assert [rc.root_cause_id for rc in forward] == [rc.root_cause_id for rc in backward]


def test_max_severity_is_the_worst_member() -> None:
    rcs = root_causes_for("saleor.io")
    assert all(rc.max_severity is Severity.CRITICAL for rc in rcs)
    assert SEVERITY_ORDER[Severity.CRITICAL] > SEVERITY_ORDER[Severity.LOW]
    assert root_causes_for("copper.com")[0].max_severity is Severity.LOW


def test_saleor_is_two_root_causes_not_one_not_ten() -> None:
    """同 defect、同 host，但公共前缀只有 1 段（/cloud）且不同源页 → 连不上边。"""
    rcs = root_causes_for("saleor.io")
    assert len(rcs) == 2
    assert sorted(rc.instance_count for rc in rcs) == [3, 7]
    assert all(rc.unique_target_count == 1 for rc in rcs)


def test_two_sevens_are_different_rulesets() -> None:
    """「66 条挤在 7 个域」与「37 条来自 7 个模板 bug」是两套不同的 7。"""
    domains = EXPECTATIONS["domains_66"]
    assert domains["total"] == 66
    assert sum(domains["by_domain"].values()) == 66
    assert len(domains["by_domain"]) == 7
    assert len(FAMILIES) == 6  # 六个域，七个根因（saleor 占 2）
    assert sum(f["root_causes"] for f in FAMILIES) == 7
    assert domains["after_denoise_total"] == 63


def test_empty_input_is_no_root_cause() -> None:
    assert merge_root_causes(()) == ()


# ═════════════════════════════════════════════════════════════════════════════
# §5.5 修复建议
# ═════════════════════════════════════════════════════════════════════════════


class FakeProber:
    """按状态码表回放。``calls`` 记账，「≤4 请求」就靠它测。"""

    def __init__(self, statuses: dict[str, int], *, soft404: frozenset[str] = frozenset()) -> None:
        self._statuses = {normalize_url(k): v for k, v in statuses.items()}
        self._soft404 = frozenset(normalize_url(u) for u in soft404)
        self.calls: list[str] = []

    def probe(
        self,
        url: str,
        *,
        expect: Expect = Expect.ANY,
        liveness_only: bool = False,
    ) -> Probe:
        self.calls.append(url)
        key = normalize_url(url)
        status = self._statuses.get(key, 404)
        soft = key in self._soft404
        verdict = Verdict.OK if status == 200 and not soft else Verdict.REAL404
        resp = HttpResponse(
            url=url,
            final_url=url,
            status=status,
            headers={"content-type": "text/html"},
            body=b"",
        )
        return Probe(
            url=url,
            expect=expect,
            response=resp,
            classification=Classification(
                verdict=verdict,
                reason="ok" if verdict is Verdict.OK else "status_404",
            ),
        )


def test_candidate_a_swap_host_bytebase() -> None:
    """a) 换 host：www.bytebase.com/introduction/what-is-bytebase → docs. 200。"""
    row = next(r for r in EXPECTATIONS["fixhint_verified"] if r["domain"] == "bytebase.com")
    prober = FakeProber({row["after"]: row["after_status"]})
    result = suggest_fix(
        row["before"],
        source_page=BYTEBASE_PAGE,
        severity=Severity.MEDIUM,
        prober=prober,
    )
    assert result.hint is not None
    assert result.hint.after == row["after"]
    assert result.hint.verified_target is True
    assert result.requests == 1
    assert prober.calls == [row["after"]]


def test_candidate_b_strip_duplicated_prefix_canvasmedical() -> None:
    """b) 剥掉重复的路径前缀。期望表把 host 写成 www.，corpus 实测是 docs.（照 corpus）。"""
    before = CANVAS_RELATIVE[0]
    after = CANVAS_STRIPPED_OK[0]
    prober = FakeProber({after: 200})
    result = suggest_fix(before, source_page=CANVAS_PAGE, severity=Severity.HIGH, prober=prober)
    assert result.hint is not None
    assert result.hint.after == after
    assert result.requests <= FIXHINT_MAX_REQUESTS
    assert [a.candidate for a in result.attempts][-1] == "b_strip_dup_prefix"


def test_candidate_c_drop_last_segment_brevo() -> None:
    """c) 去掉最后一段：/docs/api-clients/python → /docs/api-clients 200。"""
    row = next(r for r in EXPECTATIONS["fixhint_verified"] if r["domain"] == "brevo.com")
    prober = FakeProber({row["after"]: row["after_status"]})
    result = suggest_fix(
        row["before"], source_page=BREVO_PAGE, severity=Severity.MEDIUM, prober=prober
    )
    assert result.hint is not None
    assert result.hint.after == row["after"]
    assert result.requests <= FIXHINT_MAX_REQUESTS
    assert result.attempts[-1].candidate == "c_drop_last_segment"


def test_candidate_d_nearest_sitemap_path_tdengine() -> None:
    """d) sitemap.xml 里最近似路径：末段 java 完全相同 → 新路径命中 200。"""
    before = TDENGINE_DEAD[0]
    after = "https://docs.tdengine.com/developer-guide/connectors-reference/java"
    prober = FakeProber({after: 200})
    result = suggest_fix(
        before,
        source_page=TDENGINE_PAGE,
        severity=Severity.MEDIUM,
        prober=prober,
        sitemap_urls=TDENGINE_SITEMAP,
    )
    assert result.hint is not None
    assert result.hint.after == after
    assert result.attempts[-1].candidate == "d_sitemap_near"
    assert result.requests <= FIXHINT_MAX_REQUESTS


def test_fixhint_never_exceeds_four_requests() -> None:
    """四个候选全不命中：恰好 4 个请求，一个不多，且 fix=None。"""
    prober = FakeProber({})
    result = suggest_fix(
        CANVAS_RELATIVE[0],
        source_page=CANVAS_PAGE,
        severity=Severity.HIGH,
        prober=prober,
        sitemap_urls=("https://docs.canvasmedical.com/sdk/layout-effects/",),
    )
    assert result.requests == FIXHINT_MAX_REQUESTS == 4
    assert len(prober.calls) == 4
    assert {a.candidate for a in result.attempts} == set(CANDIDATE_ORDER)
    assert result.hint is None
    assert result.message == NO_FIX_MESSAGE


def test_fixhint_gives_up_instead_of_inventing_saleor() -> None:
    """saleor：/contact 才是对的，但四个机械候选一个都到不了 → 就说不知道。

    期望表的 fixhint_verified 里 saleor 那行是「sibling control + fix.after」，
    不是四个候选之一 —— 见交付说明 deviations。宁可没建议，不许编。
    """
    prober = FakeProber({"https://saleor.io/contact": 200})
    result = suggest_fix(
        SALEOR_TALK,
        source_page=SALEOR_HOME,
        severity=Severity.CRITICAL,
        prober=prober,
        sitemap_urls=("https://saleor.io/contact", "https://saleor.io/pricing"),
    )
    assert result.hint is None
    assert result.message == NO_FIX_MESSAGE
    assert "https://saleor.io/contact" not in [a.url for a in result.attempts]


def test_unverified_fix_can_never_reach_the_report() -> None:
    """``verified_target=False`` 的建议一律挡掉 —— 这层唯一会真伤人的失败模式。"""
    faked = FixHint(
        action="改成这个",
        open_this=SALEOR_HOME,
        locator="锚点",
        before=SALEOR_TALK,
        after="https://saleor.io/contact",
        verified_target=False,
    )
    assert reportable_fix(faked) is None
    assert reportable_fix(None) is None
    no_after = FixHint(
        action="改成这个",
        open_this=SALEOR_HOME,
        locator="锚点",
        before=SALEOR_TALK,
        after=None,
        verified_target=True,
    )
    assert reportable_fix(no_after) is None


def test_soft404_200_is_not_a_verified_target() -> None:
    """200 但是兜底壳页 → 不算命中（不然修复目标就是另一个坑）。"""
    after = CANVAS_STRIPPED_OK[0]
    prober = FakeProber({after: 200}, soft404=frozenset({after}))
    result = suggest_fix(
        CANVAS_RELATIVE[0], source_page=CANVAS_PAGE, severity=Severity.HIGH, prober=prober
    )
    assert result.hint is None
    assert any(a.status == 200 and not a.hit for a in result.attempts)


def test_fixhint_only_for_medium_and_up() -> None:
    """copper 那四个页脚社交图标是 LOW，一个请求都不该花。"""
    prober = FakeProber({})
    result = suggest_fix(COPPER_DEAD[0], severity=Severity.LOW, prober=prober)
    assert result == FixResult(None, (), skipped_reason="severity_below_medium")
    assert prober.calls == []
    assert severity_at_least(Severity.MEDIUM, Severity.MEDIUM)
    assert not severity_at_least(Severity.LOW, Severity.MEDIUM)


def test_candidate_transforms_are_pure_and_declineable() -> None:
    """四个变换都能「没得变就返回 None」，不花请求。"""
    assert swap_host("https://www.bytebase.com/a") == "https://docs.bytebase.com/a"
    assert sibling_host("docs.bytebase.com") == "www.bytebase.com"
    assert sibling_host("bytebase.com") == "docs.bytebase.com"
    assert sibling_host("localhost") is None
    assert strip_duplicated_prefix(CANVAS_RELATIVE[0], CANVAS_PAGE) == CANVAS_STRIPPED_OK[0]
    assert strip_duplicated_prefix(CANVAS_ROUTE_MISSING[0], CANVAS_PAGE) is None
    assert strip_duplicated_prefix(CANVAS_RELATIVE[0], "https://example.com/") is None
    assert drop_last_segment("https://developers.brevo.com/docs/api-clients/python") == (
        "https://developers.brevo.com/docs/api-clients"
    )
    assert drop_last_segment("https://x.com/onlyone") is None


def test_nearest_sitemap_triple_ordering() -> None:
    """三元组排序：末段完全相同 > 末段编辑距离小 > 公共前缀段数多。"""
    target = "https://docs.tdengine.com/reference/connector/java/"
    sitemap = (
        "https://docs.tdengine.com/reference/connector/javax",  # 距离 1
        "https://docs.tdengine.com/developer-guide/connectors-reference/java",  # 完全相同
    )
    assert nearest_sitemap_url(target, sitemap) == sitemap[1]
    # 末段编辑距离 > 3 → 视为不命中
    assert nearest_sitemap_url(target, ("https://docs.tdengine.com/a/rust",)) is None
    assert edit_distance("java", "rust") > NEAREST_LAST_SEGMENT_MAX_DISTANCE
    assert nearest_sitemap_url(target, ()) is None
    # sitemap 里就是它自己 → 不当修复目标
    assert nearest_sitemap_url(target, (target,)) is None
