"""§5.3 去噪规则 + §5.6 位置分级的单元断言（第 12a 步）。

这里**不发任何请求、不碰 transport**：post 阶段的规则拿手搓的 ``Probe`` 喂，
pre 阶段的规则本来就一个请求都不发。集合级的断言（42 条混淆矩阵、X01–X14 的
规则归因、六条门禁）在 ``tests/test_fp_gate.py``。

去噪是这个检查的全部价值：实测去噪前 42 条判死只有 25 条真（假阳性 40.5%），
去噪后 0%（n=51）。所以每一条规则都要有一条「它命中」和一条「它不许误吃」的
断言 —— ``test_infra.py::test_real_dead_links_survive_denoise`` 盯的是后者的
原型那 11 条，这里补新写的三条 + 九条 post。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from geo_audit.checks.dead_links import (
    CALIBRATION_DIFF_NOTE,
    CHALLENGE_DEAD_DOMAINS,
    CHALLENGE_DEAD_LINKS,
    DEAD_LINK_POST_RULES,
    DEAD_LINK_PRE_RULES,
    DEAD_LINK_RULE_IDS,
    RAW_DEAD_LINKS,
    TOOL_DEAD_DOMAINS,
    TOOL_DEAD_LINKS,
    _geo_redirect,
    _hostile_400,
    _login_wall,
    _transport_error_kind,
    _upstream_error,
    host_unprobeable,
    is_dead,
    seed_origin_of,
)
from geo_audit.fetch.classify import classify_response
from geo_audit.fetch.denoise import (
    SEVERITY_FOOTER_SOCIAL,
    SEVERITY_OTHER,
    SEVERITY_SALES_PATH,
    SEVERITY_TUTORIAL_EXIT,
    anchor_label_of,
    class_tokens_of,
    classify_link_eligibility,
    classify_link_pre,
    position_class_of,
    region_of_context,
    severity_of,
)
from geo_audit.models import (
    Expect,
    HostProfile,
    HttpResponse,
    LinkContext,
    PositionClass,
    Probe,
    RedirectHop,
)

REPO = Path(__file__).resolve().parent.parent
METRICS_LABELS = REPO / "tests" / "data" / "deadlink_labels.jsonl"
EXTRA_LABELS = REPO / "tests" / "data" / "denoise_extra_labels.jsonl"


def _rows(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _probe(
    url: str,
    status: int,
    body: str = "",
    *,
    headers: dict[str, str] | None = None,
    redirects: tuple[RedirectHop, ...] = (),
    transport_error: str | None = None,
    final_url: str | None = None,
    expect: Expect = Expect.ANY,
    control: HostProfile | None = None,
) -> Probe:
    """手搓一个 Probe。判定链路与生产一致（同一个 classify_response）。"""
    resp = HttpResponse(
        url=url,
        final_url=final_url or url,
        status=status,
        headers=headers or ({"content-type": "text/html"} if status else {}),
        body=body.encode("utf-8"),
        redirects=redirects,
        transport_error=transport_error,
    )
    cls = classify_response(
        status,
        resp.headers,
        body,
        url=url,
        expect=expect,
        final_url=resp.final_url,
        redirects=redirects,
        control=control,
        transport_error=transport_error,
    )
    return Probe(url, expect, resp, cls)


def _profile(
    host: str, *, status: int = 404, discriminates: bool = True, usable: bool = True
) -> HostProfile:
    return HostProfile(
        host=host,
        probe_url=f"https://{host}/geo-audit-probe-x",
        status=status,
        content_type="text/html",
        norm_sha256="0" * 64,
        norm_len=10,
        norm_body_prefix="",
        struct_sha256="0" * 64,
        struct_tags=3,
        final_path="/geo-audit-probe-x",
        status_discriminates=discriminates,
        control_is_html=True,
        usable=usable,
        probed_at=0.0,
    )


# --------------------------------------------------------------------------- #
# 规则清单
# --------------------------------------------------------------------------- #


def test_rule_registry_shape() -> None:
    """§5.3 定死 pre 14 条 + post 9 条，id 不许重、不许漏。"""
    assert len(DEAD_LINK_PRE_RULES) == 14
    assert len(DEAD_LINK_POST_RULES) == 9
    assert len(set(DEAD_LINK_RULE_IDS)) == 23
    # 三条新写的必须在表里（卡点 B22：原型里根本不存在这三条）
    for rid in ("presigned_expiring", "class_hidden_anchor", "seed_url_not_on_site"):
        assert rid in DEAD_LINK_PRE_RULES


def test_labels_composition_is_the_gate_denominator() -> None:
    """42 = 25 真死 + 17 假阳性。这两个数就是 §8.6 的分母。"""
    rows = _rows(METRICS_LABELS)
    assert len(rows) == 42
    assert sum(1 for r in rows if r["label"] == "dead") == 25
    assert sum(1 for r in rows if r["label"] == "false_positive") == 17
    extra = _rows(EXTRA_LABELS)
    assert len({r["base_id"] for r in extra}) == 14  # X01–X14


# --------------------------------------------------------------------------- #
# pre：三条新规则
# --------------------------------------------------------------------------- #


def test_presigned_expiring_excludes_self_expiring_urls() -> None:
    """close 的 llms.txt 里 logo 用 AWS 预签名，7 天后自烂一条。规则只看 URL。"""
    aws = (
        "https://close-com-marketing.s3.amazonaws.com/logo.png"
        "?X-Amz-Date=20260906T165455Z&X-Amz-Expires=604800&X-Amz-Signature=deadbeef"
    )
    ex = classify_link_pre(aws)
    assert ex is not None and ex.rule_id == "presigned_expiring"
    assert ex.disposition == "excluded"

    gcs = classify_link_pre("https://storage.googleapis.com/b/logo.png?X-Goog-Expires=3600")
    assert gcs is not None and gcs.rule_id == "presigned_expiring"

    azure = classify_link_pre("https://acct.blob.core.windows.net/c/logo.png?se=2026-09-14&sig=abc")
    assert azure is not None and azure.rule_id == "presigned_expiring"

    # 普通带 query 的图片 URL 不许被吃
    assert classify_link_pre("https://close.com/logo.png?v=3") is None


def test_class_hidden_anchor_is_needs_review_not_excluded() -> None:
    """卡点 S4：printify 的 IRS Form 8937 是 **class 隐藏**，处置是 needs_review。

    它**仍然计入死链分子**，只是 finding.confidence 变成 needs_review 并进报告的
    「待人工确认」区。这条是本工具 87 与 challenge 86 的那 1 条差。
    """
    url = "https://printify.com/wp-content/uploads/2024/12/Printify-Inc.-IRS-Form-8937.pdf"
    ctx = LinkContext(
        source_page="https://printify.com/",
        anchor_text="IRS Form 8937",
        anchor_html=f'<a class="nav-link hidden" href="{url}">IRS Form 8937</a>',
    )
    ex = classify_link_pre(url, ctx)
    assert ex is not None
    assert ex.rule_id == "class_hidden_anchor"
    assert ex.disposition == "needs_review"
    assert ex.provenance == "single_case"


@pytest.mark.parametrize(
    "class_attr",
    [
        "md:hidden",  # Tailwind：桌面可见
        "sm:hidden lg:block",
        "hidden md:block",  # 有响应式可见覆盖 token
        "hidden-print",  # 不是裸 hidden
    ],
)
def test_class_hidden_anchor_narrowed_to_bare_hidden(class_attr: str) -> None:
    """收窄的理由：``md:hidden`` 在桌面**是可见的**，静态 HTML 判不了外部样式表。"""
    ctx = LinkContext(source_page="p", anchor_html=f'<a class="{class_attr}" href="/x">x</a>')
    assert classify_link_pre("https://printify.com/x.pdf", ctx) is None


def test_seed_url_not_on_site() -> None:
    """电商批那条「我自己塞进种子的猜测 URL」（Square 定价页候选之一，404）。

    ``pricing_candidates_tried`` 里那些 404 的候选**一条都不许进死链**。
    """
    url = "https://developer.squareup.com/pricing"
    assert seed_origin_of(url, audited_domain="squareup.com") == "PRICING_CANDIDATES"
    ex = classify_link_pre(url, seed_origin="PRICING_CANDIDATES")
    assert ex is not None and ex.rule_id == "seed_url_not_on_site"

    # 站上真的抽到过这条 -> 它不是「我们猜的」，照常判
    assert (
        classify_link_pre(
            url, seed_origin="PRICING_CANDIDATES", extracted_norm_urls=frozenset({url})
        )
        is None
    )
    # 首页不是「猜的候选」：抓取起点不许被这条规则吃掉
    assert seed_origin_of("https://squareup.com/", audited_domain="squareup.com") is None
    # 别人家的 /pricing 也不是我们猜的
    assert seed_origin_of("https://stripe.com/pricing", audited_domain="squareup.com") is None
    # llms.txt 候选归 AI_PATH_CANDIDATES
    assert seed_origin_of("https://squareup.com/llms.txt", audited_domain="squareup.com") == (
        "AI_PATH_CANDIDATES"
    )


def test_framework_bind_artifact_covers_dollar_brace() -> None:
    """第 12 步要补的那一段：原型正则不含 ``^\\$\\{``（§3.10）。"""
    ex = classify_link_pre("${bindHref}")
    assert ex is not None and ex.rule_id == "framework_bind_artifact"
    # 原型那半边（`{{`）照旧
    assert classify_link_eligibility("{{ item.href }}") is not None
    # raw_href 与 abs_url 不同时判 raw_href
    ex2 = classify_link_pre("https://example.invalid/x", raw_href="${'/' + slug}")
    assert ex2 is not None and ex2.rule_id == "framework_bind_artifact"


def test_pre_rules_do_not_eat_real_dead_links() -> None:
    """42 条标注里 25 条真死链，一条都不许被 pre 规则吃掉（含新写的三条）。"""
    for row in _rows(METRICS_LABELS):
        if row["label"] != "dead":
            continue
        ctx = LinkContext(
            source_page=str(row.get("source_page") or ""),
            anchor_text=str(row.get("anchor_text") or ""),
            anchor_html=str(row.get("anchor_html") or ""),
            surrounding_html=str(row.get("surrounding_html") or ""),
        )
        ex = classify_link_pre(row["url"], ctx)
        if row.get("needs_review"):
            # printify 那条（H24）：标注行只在 note 里写了「该 <a> 的 class 含
            # hidden」，没有 anchor_html / class_tokens 字段（models.LinkContext
            # 也还没有那两个字段），所以拿标注行原样喂时这条规则命不中 —— 那正是
            # 它**不该**改变判死结论的证明。补上已记录的 class 之后它会命中
            # needs_review，见 test_tool_total_differs_from_challenge_by_exactly_printify。
            assert ex is None
        else:
            assert ex is None, f"{row['id']} {row['url']} 被 pre 规则误吃：{ex}"


def test_mailto_in_path_survives_but_mailto_scheme_does_not() -> None:
    """§5.3 的那个陷阱：``non_http_scheme`` 判 scheme，**path 里含 mailto: 的不丢**。

    pingcap 那条 ``docs.pingcap.com/tidbcloud/mailto:support@pingcap.com/`` 是真死链
    （``mailto_as_relative_path`` 指纹），锚文本显示邮箱、release notes 页 5 处。
    """
    assert classify_link_pre("mailto:support@pingcap.com") is not None
    assert (
        classify_link_pre("https://docs.pingcap.com/tidbcloud/mailto:support@pingcap.com/") is None
    )


# --------------------------------------------------------------------------- #
# 上下文解析（LinkContext 没有 class_tokens / anchor_label / region 字段）
# --------------------------------------------------------------------------- #


def test_class_tokens_and_anchor_label_come_from_anchor_html() -> None:
    ctx = LinkContext(
        source_page="p",
        anchor_html='<a class="btn hidden" aria-label="Discord" href="https://discord.com/x"></a>',
    )
    assert class_tokens_of(ctx) == ("btn", "hidden")
    # commercelayer 的 Discord 只有 aria-label，**必须算「有可见内容」**
    assert anchor_label_of(ctx) == "Discord"
    # tdengine 首页连接器图标墙：anchor_label 来自 <img alt>
    icon = LinkContext(source_page="p", anchor_html='<a href="/x"><img alt="Java"></a>')
    assert anchor_label_of(icon) == "Java"
    assert class_tokens_of(LinkContext(source_page="p")) == ()


def test_region_of_context_footer_wins() -> None:
    """copper 的四个社交图标在 footer 里、class 含 social-btn，两条正则同时命中。"""
    footer = LinkContext(
        source_page="p",
        anchor_html='<a class="btn social-btn" href="https://x.com/tinybirdco"></a>',
        surrounding_html='<footer class="site-footer">...</footer>',
    )
    assert region_of_context(footer) == "footer"
    card = LinkContext(
        source_page="p",
        anchor_html='<a class="btn" href="/x">Talk to us</a>',
        surrounding_html='<div class="pricing-card">',
    )
    assert region_of_context(card) == "prominent"
    body = LinkContext(source_page="p", surrounding_html="<p>详见<a href='/x'>这里</a></p>")
    assert region_of_context(body) == "body"


def test_region_regexes_match_extract() -> None:
    """denoise 的退化 region 判据必须与 extract.region_of 的两条正则逐字相同。"""
    from geo_audit import extract
    from geo_audit.fetch import denoise

    assert denoise._REGION_PROMINENT_RE.pattern == extract._PROMINENT_CLS.pattern
    assert denoise._REGION_FOOTER_RE.pattern == extract._FOOTER_CLS.pattern


# --------------------------------------------------------------------------- #
# §5.6 位置分级（十行实测样本）
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url,anchor,anchor_html,role,region,expected",
    [
        # saleor 定价页三张套餐卡的 "Talk to us"
        (
            "https://saleor.io/cloud/pricing-page",
            "Talk to us",
            "",
            "pricing",
            "prominent",
            PositionClass.SALES_PATH,
        ),
        # saleor 首页 "See how Saleor fits"
        (
            "https://saleor.io/cloud/talk-to-us",
            "See how Saleor fits",
            "",
            "home",
            "prominent",
            PositionClass.SALES_PATH,
        ),
        # unkey 定价页 "Read the docs"（308->308->404）—— 落 DOC_ENTRY 而不是 SALES_PATH
        (
            "https://unkey.com/docs/platform/workspaces/billing",
            "Read the docs",
            "",
            "pricing",
            "prominent",
            PositionClass.DOC_ENTRY,
        ),
        # openstatus 教程里的 "Example repository"
        (
            "https://github.com/openstatushq/examples",
            "Example repository",
            "",
            "docs_content",
            "body",
            PositionClass.DOC_ENTRY,
        ),
        # tdengine 首页连接器图标墙：无锚文本，anchor_label 来自 <img alt>
        (
            "https://docs.tdengine.com/reference/connector/java/",
            "",
            '<a href="/reference/connector/java/"><img alt="Java documentation"></a>',
            "home",
            "prominent",
            PositionClass.DOC_ENTRY,
        ),
        # bytebase changelog 导航 6 条
        (
            "https://www.bytebase.com/introduction/what-is-bytebase",
            "What is Bytebase",
            "",
            "changelog",
            "prominent",
            PositionClass.NAV,
        ),
        # brevo「详见这里」正文链接
        (
            "https://developers.brevo.com/docs/api-clients/python",
            "这里",
            "",
            "changelog",
            "body",
            PositionClass.BODY,
        ),
        # tinybird x.com/tinybirdco（社交 host 直接落底）
        (
            "https://x.com/tinybirdco",
            "Twitter",
            "",
            "docs_content",
            "body",
            PositionClass.FOOTER_SOCIAL,
        ),
        # copper 页脚四个社交图标
        (
            "https://www.linkedin.com/company/copper-inc/",
            "",
            "",
            "home",
            "footer",
            PositionClass.FOOTER_SOCIAL,
        ),
        # "get started free" 在 SALES_KW 里 -> SALES_PATH（实测都是注册入口）
        (
            "https://example.invalid/start",
            "Get started free",
            "",
            "home",
            "prominent",
            PositionClass.SALES_PATH,
        ),
        # ⚠️ 而**裸** "Get started" 只在 DOCS_ENTRY_KW 里 -> DOC_ENTRY。
        # §5.6 的 docstring 说「"get started" 同时在两张表里 -> 先命中 SALES_KW」，
        # 但它自己给的两张关键词表里 SALES_KW 只有 "get started free"。关键词表是
        # 逐字照抄的那一半，所以按表走（见交付说明 spec_gaps）。
        (
            "https://example.invalid/start",
            "Get started",
            "",
            "home",
            "prominent",
            PositionClass.DOC_ENTRY,
        ),
    ],
)
def test_position_class_of_measured_rows(
    url: str, anchor: str, anchor_html: str, role: str, region: str, expected: PositionClass
) -> None:
    ctx = LinkContext(source_page="p", anchor_text=anchor, anchor_html=anchor_html)
    assert position_class_of(url, ctx, source_role=role, region=region) is expected


def test_ai_channel_wins_over_everything() -> None:
    """mistral llms.txt 的 75 条内链一律 AI_CHANNEL（from_text_file=True）。"""
    ctx = LinkContext(
        source_page="https://docs.mistral.ai/llms.txt",
        anchor_text="Talk to us",
        from_text_file=True,
    )
    assert position_class_of("https://x.com/mistralai", ctx, source_role="ai_path") is (
        PositionClass.AI_CHANNEL
    )


def test_prominent_home_link_to_docs_is_doc_entry() -> None:
    """首页/定价页显眼位置 + 目标像文档 -> DOC_ENTRY，否则 SALES_PATH。"""
    ctx = LinkContext(source_page="p")
    assert (
        position_class_of(
            "https://docs.foo.invalid/guides/x", ctx, source_role="home", region="prominent"
        )
        is PositionClass.DOC_ENTRY
    )
    assert (
        position_class_of(
            "https://foo.invalid/cloud/x", ctx, source_role="home", region="prominent"
        )
        is PositionClass.SALES_PATH
    )


def test_legacy_wrapper_diverges_on_purpose() -> None:
    """原型 ``severity_of`` 与 §5.6 ``position_class_of`` 的差异是**设计**，不是 bug。

    冻结测试 ``test_infra.py::test_severity_tiers`` 断言的是前者，所以它必须原样
    保留；后者是报告层要的六档。两处最显眼的分叉：
      · unkey 的 "Read the docs"：severity_of -> sales_path，position -> DOC_ENTRY
      · 社交 host：severity_of 只看 host，position 先看 from_text_file
    """
    ctx = LinkContext(source_page="https://www.unkey.com/pricing", anchor_text="Read the docs")
    assert severity_of("https://unkey.com/docs/platform/workspaces/billing", ctx) == (
        SEVERITY_SALES_PATH
    )
    assert (
        position_class_of(
            "https://unkey.com/docs/platform/workspaces/billing",
            ctx,
            source_role="pricing",
            region="prominent",
        )
        is PositionClass.DOC_ENTRY
    )

    # 四个 SEVERITY_* 常量与 severity_of 的行为一个字都不许动（铁律 3）
    assert (
        SEVERITY_SALES_PATH,
        SEVERITY_TUTORIAL_EXIT,
        SEVERITY_FOOTER_SOCIAL,
        SEVERITY_OTHER,
    ) == (
        "sales_path",
        "tutorial_exit",
        "footer_social",
        "other",
    )
    social = LinkContext(source_page="p")
    assert severity_of("https://x.com/tinybirdco", social) == SEVERITY_FOOTER_SOCIAL
    assert severity_of("https://saleor.io/cloud/x", social) == SEVERITY_OTHER


# --------------------------------------------------------------------------- #
# post：九条规则
# --------------------------------------------------------------------------- #


def test_waf_challenge_needs_the_control_sample() -> None:
    """tenderly 首轮 27 条 429 全是假的。证伪动作是对照样本：随机路径也 429。

    按松口径算，垂直行业批的死链会从 10 变成 51（5 倍虚高）。
    """
    challenge = "<title>Just a moment...</title><div>__cf_chl_opt</div>"
    target = _probe(
        "https://tenderly.co/this-page-definitely-does-not-exist-xyz123", 429, challenge
    )
    root = _probe("https://tenderly.co/", 429, challenge)
    control = _profile("tenderly.co", status=429, discriminates=False, usable=False)
    assert host_unprobeable(root, control) is True
    # 429 既不进死链分子，也不进「已验证存活」
    assert is_dead(target, control, (), ()) is False


def test_host_unprobeable_needs_both_probes_bad() -> None:
    """**只有一条不可信不算** —— 那是正常的软 404 场景（卡点 2）。"""
    root_ok = _probe("https://saleor.io/", 200, "<h1>Saleor</h1>")
    control_ok = _profile("saleor.io", status=404, discriminates=True)
    assert host_unprobeable(root_ok, control_ok) is False
    # 根路径被拦（403）但对照探针老实回 404 -> **只有一条不可信，不算**：
    # 这个 host 照样能区分「有」和「没有」，是正常的软 404 场景。
    root_blocked = _probe("https://saleor.io/", 403)
    assert host_unprobeable(root_blocked, control_ok) is False
    # 两条都不可信才算：根路径 200 且整站一张壳（对照探针也 200，区分不了）
    catch_all = _profile("spa.invalid", status=200, discriminates=False)
    assert host_unprobeable(root_ok, catch_all) is True


def test_hostile_400_is_unknown_not_dead() -> None:
    """``facebook.com/CopperInc``（**写对的那条**）也返 400。"""
    probe = _probe("https://www.facebook.com/CopperInc", 400)
    assert _hostile_400("https://www.facebook.com/CopperInc", probe) is True
    # 别的 host 上 400 不许套这条
    assert _hostile_400("https://saleor.io/x", _probe("https://saleor.io/x", 400)) is False


def test_upstream_error_covers_520_530() -> None:
    """``twitter.com/pinterest/`` 520；``manpages.ubuntu.com`` 503。"""
    assert _upstream_error(_probe("http://twitter.com/pinterest/", 520)) is True
    assert _upstream_error(_probe("https://manpages.ubuntu.com/", 503)) is True
    assert _upstream_error(_probe("https://saleor.io/x", 404)) is False


def test_geo_redirect_two_shapes() -> None:
    """出口在新加坡时 klaviyo / zendesk 的链接被 geo-redirect 到 /sg/ 之后才 404。"""
    # 形态 ②：手上的 URL 已经是被 geo-redirect 之后的那条，对照物是源页路径
    probe = _probe("https://www.klaviyo.com/sg/pricing", 404)
    assert (
        _geo_redirect(
            "https://www.klaviyo.com/sg/pricing",
            probe,
            source_page="https://www.klaviyo.com/pricing",
        )
        is True
    )
    # 形态 ①：跳转链把地区段插进来
    hops = (
        RedirectHop(
            302, "https://support.zendesk.com/hc/en-us", "https://support.zendesk.com/sg/hc/en-us"
        ),
    )
    inserted = _probe(
        "https://support.zendesk.com/hc/en-us",
        404,
        redirects=hops,
        final_url="https://support.zendesk.com/sg/hc/en-us",
    )
    assert _geo_redirect("https://support.zendesk.com/hc/en-us", inserted, source_page="") is True
    # 站点自己就有 /us/ 前缀（源页也在 /us/ 下）-> 不是 geo 跳转
    same = _probe("https://foo.invalid/us/pricing", 404)
    assert (
        _geo_redirect("https://foo.invalid/us/pricing", same, source_page="https://foo.invalid/us/")
        is False
    )


def test_login_wall_is_not_a_blanket_rule() -> None:
    """三个反例定的表。moonshot 那条**兄弟全 200 所以是真路由缺失**。"""
    teachable = _probe("https://sso.teachable.com/secure/enroll", 403)
    assert _login_wall("https://sso.teachable.com/secure/enroll", teachable, ()) is True

    loop = _probe("https://app.moderntreasury.com/", 0, transport_error="redirect loop")
    assert _login_wall("https://app.moderntreasury.com/", loop, ()) is True

    invoice = _probe("https://platform.kimi.ai/console/invoice", 404)
    siblings = (
        ("https://platform.kimi.ai/console/account", 200),
        ("https://platform.kimi.ai/console/api-keys", 200),
        ("https://platform.kimi.ai/console", 200),
    )
    assert _login_wall("https://platform.kimi.ai/console/invoice", invoice, siblings) is False
    assert is_dead(invoice, _profile("platform.kimi.ai"), siblings, ()) is True


def test_network_timeout_kinds() -> None:
    """``transport_error ∈ {timeout, tls, reset, max_redirects}``。"""
    assert _transport_error_kind("timeout: ConnectTimeout()") == "timeout"
    assert _transport_error_kind("SSLError: handshake failure") == "tls"
    assert _transport_error_kind("ConnectError: connection reset by peer") == "reset"
    assert _transport_error_kind("too many redirects (>10)") == "max_redirects"
    assert _transport_error_kind(None) is None
    assert _transport_error_kind("HTTP 404") is None


def test_is_dead_whitelist() -> None:
    """只有四种算 DEAD。202 算 ALIVE；400/405/451/5xx 一律 UNKNOWN。"""
    profile = _profile("saleor.io")
    assert is_dead(_probe("https://saleor.io/x", 404), profile, (), ()) is True
    assert is_dead(_probe("https://saleor.io/x", 410), profile, (), ()) is True
    # app.baseten.co 系列返 202
    assert is_dead(_probe("https://app.baseten.co/x", 202, "<h1>ok</h1>"), profile, (), ()) is False
    for status in (400, 405, 451, 500, 503):
        assert is_dead(_probe("https://saleor.io/x", status), profile, (), ()) is False


def test_is_dead_dns_needs_two_resolvers() -> None:
    """``>=2 个 resolver NXDOMAIN`` 才判死。裸一句 NXDOMAIN 不够。"""
    from geo_audit.fetch.resolve import Resolution

    probe = _probe("http://next.js/", 0, transport_error="ConnectError: could not resolve")
    two = Resolution(
        "next.js", (), "none", poisoned=False, error="NXDOMAIN on system/8.8.8.8/1.1.1.1"
    )
    assert is_dead(probe, None, (), (), dns=two) is True
    bare = Resolution("developers.swell.is", (), "none", poisoned=False, error="NXDOMAIN")
    assert is_dead(probe, None, (), (), dns=bare) is False
    answered = Resolution("cog.run", ("104.18.17.10",), "8.8.8.8", poisoned=False)
    assert is_dead(probe, None, (), (), dns=answered) is False


def test_needs_review_does_not_change_is_dead() -> None:
    """卡点 S4：命中 needs_review 的规则**不改变 is_dead 的结论**。"""
    url = "https://printify.com/wp-content/uploads/2024/12/Printify-Inc.-IRS-Form-8937.pdf"
    ctx = LinkContext(
        source_page="https://printify.com/",
        anchor_html=f'<a class="hidden" href="{url}">IRS Form 8937</a>',
    )
    hit = classify_link_pre(url, ctx)
    assert hit is not None and hit.disposition == "needs_review"
    probe = _probe(url, 404)
    assert is_dead(probe, _profile("printify.com"), (), (hit,)) is True
    # 换成 EXCLUDED 档的规则就必须翻面
    excluded = classify_link_pre("https://example.com/image.jpg")
    assert excluded is not None and excluded.disposition == "excluded"
    assert is_dead(probe, _profile("printify.com"), (), (excluded,)) is False


# --------------------------------------------------------------------------- #
# 口径差（卡点 S4）：不许藏
# --------------------------------------------------------------------------- #


def test_tool_total_differs_from_challenge_by_exactly_printify() -> None:
    """本工具 87 条 / 26 域 vs challenge 86 条 / 25 域 —— 差的正好是 printify 那 1 条。

    它在 42 条标注里 ``label="dead"`` + ``needs_review=true``，工具**预测它为
    DEAD**，Exclusion 日志里那条的 ``disposition == "needs_review"``。
    这不是 bug，是「静态 HTML 判不了 class 隐藏」这条约束的代价。
    """
    assert TOOL_DEAD_LINKS - CHALLENGE_DEAD_LINKS == 1
    assert TOOL_DEAD_DOMAINS - CHALLENGE_DEAD_DOMAINS == 1
    # 各批原始 94 -> challenge 86：剔掉 7 条框架/机器产物 + printify 1
    assert RAW_DEAD_LINKS - CHALLENGE_DEAD_LINKS == 8
    assert RAW_DEAD_LINKS - TOOL_DEAD_LINKS == 7
    assert "printify" in CALIBRATION_DIFF_NOTE and "needs_review" in CALIBRATION_DIFF_NOTE

    printify = [r for r in _rows(METRICS_LABELS) if r["id"] == "H24"]
    assert len(printify) == 1
    row = printify[0]
    assert row["label"] == "dead" and row["needs_review"] is True
    assert row["expect_rule"] == "class_hidden_anchor"

    url = row["url"]
    ctx = LinkContext(
        source_page=row["source_page"],
        anchor_text=row["anchor_text"],
        anchor_html=f'<a class="menu-item hidden" href="{url}">IRS Form 8937</a>',
    )
    hit = classify_link_pre(url, ctx)
    assert hit is not None
    assert hit.rule_id == "class_hidden_anchor"
    assert hit.disposition == "needs_review"
    # inline_display_none_anchor 在 42 条里一条都不命中（它的 fixture 是 X13）
    assert (
        classify_link_pre(
            url, LinkContext(source_page=row["source_page"], anchor_text=row["anchor_text"])
        )
        is None
    )


# --------------------------------------------------------------------------- #
# classify_link 的两条调用形态
# --------------------------------------------------------------------------- #


def test_classify_link_without_fetcher_uses_the_plain_client() -> None:
    """规格给的签名是 ``client: httpx.Client``，所以没有 Fetcher 时也得能跑。

    这条退化路只有一次请求、没有对照探针，所以它拿不到同 host 存活对照 ——
    于是 404 落 ``third_party_no_control`` 而不是判死。**这正是想要的方向**：
    证据不够就说判不了，绝不判死。
    """
    import httpx

    from geo_audit.checks.dead_links import LinkVerdict, classify_link
    from geo_audit.fixtures import FixtureStore
    from geo_audit.models import LinkState

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/cloud/talk-to-us":
            return httpx.Response(404, headers={"content-type": "text/html"}, text=_DEAD_HTML)
        return httpx.Response(404, headers={"content-type": "text/html"}, text=_DEAD_HTML)

    store = FixtureStore(REPO / "fixtures")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        # pre 规则先拦下来的那种：一次请求都不发
        excluded = classify_link(
            "https://example.com/image.jpg",
            source_page="https://developers.printful.com/docs/",
            ctx=LinkContext(source_page="https://developers.printful.com/docs/"),
            client=client,
            store=store,
        )
        assert excluded.state is LinkState.EXCLUDED
        assert excluded.rule_id == "reserved_example_domain"
        assert excluded.requests_spent == 0

        unknown = classify_link(
            "https://saleor.io/cloud/talk-to-us",
            source_page="https://saleor.io/",
            ctx=LinkContext(source_page="https://saleor.io/", anchor_text="See how Saleor fits"),
            client=client,
            store=store,
        )
        assert unknown.state is LinkState.UNKNOWN
        assert unknown.rule_id == "third_party_no_control"
        assert unknown.position_class is PositionClass.SALES_PATH

    dead = LinkVerdict(url="https://saleor.io/x", state=LinkState.DEAD)
    assert dead.counted_dead is True
    assert LinkVerdict(url="https://x.invalid/y", state=LinkState.EXCLUDED).counted_dead is False


_DEAD_HTML = "<!doctype html><title>404 - Page not found</title>"
