"""§5.1 链接抽取 + §5.2 三个 DOM 上下文函数的测试（第 11 步）。

**§5.2 的 13 组锚点是这一步真正的门禁**：6 组 `path_shape` + 4 组 `container_sig`
+ 3 组 `region_of`，逐条照抄规格给的「输入 HTML → 期望输出」。三个函数都是纯函数、
只吃 HTML 字符串，**不需要实录快照**，所以这一批断言在第 4b 步之前就能全绿。

需要实录快照的那几条（upstash 最大簇 >= 800、canvasmedical 9 条在 cap=300 下不丢）
按 ``tests/test_fixture_store.py`` 的写法 ``skipif`` 掉 —— 跳过的原因写在 reason 里，
不是假绿，也不为了让它过而编造快照。

跑法（CI 的 test job 恒开两把闸）::

    GEO_AUDIT_FORBID_NETWORK=1 GEO_AUDIT_FORBID_DNS=1 pytest tests/test_extract.py -q
"""

from __future__ import annotations

from pathlib import Path

import pytest
from selectolax.lexbor import LexborHTMLParser, LexborNode

from geo_audit.extract import (
    CLUSTER_MIN_SIZE,
    CLUSTER_SAMPLE_N,
    DEFAULT_MAX_LINKS,
    MAX_ANCHORS_PER_PAGE,
    MAX_TARGETS_PER_PAGE,
    LinkTarget,
    build_template_clusters,
    cluster_exhaust_plan,
    cluster_probe_plan,
    container_sig,
    extract_links,
    extract_page,
    in_code_block,
    normalize_url,
    path_shape,
    region_of,
)
from geo_audit.fixtures import FixtureStore

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
DATA = Path(__file__).resolve().parent / "data"

real_index_needed = pytest.mark.skipif(
    not (FIXTURES / "index.json").exists(),
    reason="第 4b 步的实录快照还没落地（fixtures/index.json 不存在）",
)
position_expectations_needed = pytest.mark.skipif(
    not (DATA / "position_expectations.json").exists(),
    reason=(
        "tests/data/position_expectations.json 还没落地"
        "（第 11 步录完 fixture 才回填，§5.1 行 2523-2525）"
    ),
)

#: J 组的源页（fixtures/urls.txt:283）：自带 898 条 Redis 命令导航。
UPSTASH_SEED = "https://upstash.com/docs/redis/overall/getstarted"

#: I 组的源页（fixtures/urls.txt:263）：canvasmedical 9 条死链全在这一页。
CANVAS_SEED = "https://docs.canvasmedical.com/product-updates/release-notes/"

#: 那 9 条（fixtures/urls.txt:264-274 里逐字抄下来的，一条不改）。
CANVAS_DEAD_9 = (
    "https://docs.canvasmedical.com/product-updates/release-notes/sdk/layout-effect/",
    "https://docs.canvasmedical.com/product-updates/release-notes/sdk/effect-notes/",
    "https://docs.canvasmedical.com/product-updates/release-notes/product-updates/commands-module/",
    "https://docs.canvasmedical.com/sdk/canvas-cli/",
    "https://docs.canvasmedical.com/documentation/pdf-annotations/",
    "https://help.canvasmedical.com/articles/7998893827-managing-conditions",
    "https://canvas-medical.help.usepylon.com/articles/7998893827-managing-conditions",
    "https://github.com/canvas-medical/canvas-plugins/blob/main/example-plugins/"
    "example_patient_sync/README.md",
    "https://github.com/canvas-medical/canvas-plugins/blob/main/example-plugins/"
    "vitals_visualizer_plugin/README.md",
)


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #


def _anchors(html: str) -> list[LexborNode]:
    return list(LexborHTMLParser(html).css("a"))


def _first_anchor(html: str) -> LexborNode:
    nodes = _anchors(html)
    assert nodes, "测试 HTML 里没有 <a>"
    return nodes[0]


def _fake_target(
    norm_url: str,
    *,
    source_page: str = "https://example.invalid/",
    sig: str = "ul.nav[n30+]",
    shape: str = "/redis/commands/*",
    dom_index: int = 0,
) -> LinkTarget:
    """只给簇归并/探测计划用的最小 LinkTarget（不经 HTML，纯构造）。"""
    from geo_audit.models import LinkContext

    return LinkTarget(
        raw_href=norm_url,
        abs_url=norm_url,
        norm_url=norm_url,
        source_page=source_page,
        source_role="docs_content",
        ctx=LinkContext(source_page=source_page),
        container_sig=sig,
        region="body",
        path_shape=shape,
        anchor_label="",
        class_tokens=(),
        inline_style="",
        in_code_block=False,
        dom_index=dom_index,
    )


# --------------------------------------------------------------------------- #
# §5.2 锚点组 1/3：path_shape（6 组，行 2592-2597）
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/reference/connector/java/", "/reference/connector/*"),
        ("/redis/commands/append", "/redis/commands/*"),
        # 「其余整体折成一个 *」，**不是** /docs/topics/*/*（卡点 S12）
        ("/docs/topics/billing/index", "/docs/topics/*"),
        ("/a/b/c/d/e/f", "/a/b/*"),
        ("/pricing", "/pricing"),  # 段数 <= keep 时原样
        ("/", "/"),
    ],
)
def test_path_shape_anchors(path: str, expected: str) -> None:
    assert path_shape(path) == expected


def test_path_shape_never_emits_multiple_stars() -> None:
    """卡点 S12 的反面守卫：深度再大也只有一个 `*`。"""
    assert path_shape("/a/b/c/d/e/f/g/h").count("*") == 1


def test_path_shape_keep_is_configurable() -> None:
    assert path_shape("/docs/topics/billing/index", keep=3) == "/docs/topics/billing/*"


# --------------------------------------------------------------------------- #
# §5.2 锚点组 2/3：container_sig（4 组，行 2624-2661）
# --------------------------------------------------------------------------- #

#: 锚点 A —— tdengine 首页连接器图标墙。8 个 `<a>`、无 id、class 含构建 hash。
#: 8 条语言取自 fixtures/urls.txt:250-257 的实录 URL。
ANCHOR_A_HTML = (
    """<body><div class="connector-grid Home_grid__a91f3">
"""
    + "".join(
        f'<a href="/reference/connector/{lang}/"><img alt="{lang}"></a>'
        for lang in ("java", "python", "go", "rust", "csharp", "cpp", "node", "r-lang")
    )
    + """
</div></body>"""
)

#: 锚点 B —— bytebase changelog 页的文档链接导航，6 个 `<a>`。
ANCHOR_B_HTML = (
    """<body><ul id="changelog-links" class="list css-9x2k1">
"""
    + "".join(
        f'<a href="/introduction/{slug}">{slug}</a>'
        for slug in (
            "what-is-bytebase",
            "quick-start",
            "supported-databases",
            "architecture",
            "faq",
            "roadmap",
        )
    )
    + """
</ul></body>"""
)

#: 锚点 C —— saleor 首页 hero 的单个 CTA。
ANCHOR_C_HTML = (
    '<body><section class="hero"><div class="cta">'
    '<a href="/cloud/talk-to-us?cta=See+how+Saleor+fits&cta_page=%2F">See how Saleor fits</a>'
    "</div></section></body>"
)

#: 锚点 D —— saleor 定价页三张套餐卡的 Talk to us。
ANCHOR_D_HTML = (
    '<body><div class="plans">'
    + '<div class="card"><a href="/cloud/pricing-page?cta=Talk+to+us">Talk to us</a></div>' * 3
    + "</div></body>"
)


def test_container_sig_anchor_a_tdengine_icon_wall() -> None:
    """Home_grid__a91f3 被 _CLASS_HASH_RE 剔掉；8 个 a 落在 n8-29 档。"""
    for node in _anchors(ANCHOR_A_HTML):
        assert container_sig(node) == "div.connector-grid[n8-29]"


def test_container_sig_anchor_b_bytebase_nav() -> None:
    """id 原样保留；css-9x2k1 剔掉；6 个 a 落 n3-7 档。"""
    for node in _anchors(ANCHOR_B_HTML):
        assert container_sig(node) == "ul#changelog-links.list[n3-7]"


def test_container_sig_anchor_c_saleor_hero_solo() -> None:
    """向上 6 层都没有 LIST_TAGS，也没有任何祖先含 >= 3 个 `<a>` → 退化成 solo:。"""
    assert container_sig(_first_anchor(ANCHOR_C_HTML)) == "solo:div.cta[n1-2]"


def test_container_sig_anchor_d_saleor_plan_cards() -> None:
    """.plans 有 3 个 `<a>`，满足 C-b（非 LIST_TAGS 的中间层 .card 要穿透计数）。"""
    for node in _anchors(ANCHOR_D_HTML):
        assert container_sig(node) == "div.plans[n3-7]"


def test_container_sig_c_and_d_stay_two_root_causes() -> None:
    """C 与 D 的 container_sig 不同、source_page 不同、公共前缀只有 /cloud = 1 段
    → E1、E2 都不成立 → **保持 2 个根因**（实测口径「10 条 = 2 个唯一路径」）。
    """
    sig_c = container_sig(_first_anchor(ANCHOR_C_HTML))
    sig_d = container_sig(_first_anchor(ANCHOR_D_HTML))
    assert sig_c != sig_d


def test_container_sig_has_no_dom_path() -> None:
    """签名里不含 dom_path —— 外面多包几层 div 不许改变签名（卡点 S12）。"""
    plain = container_sig(_first_anchor(ANCHOR_A_HTML))
    wrapped = ANCHOR_A_HTML.replace("<body>", "<body><div><div><section>").replace(
        "</body>", "</section></div></div></body>"
    )
    assert container_sig(_first_anchor(wrapped)) == plain


def test_container_sig_buckets_are_four_discrete_levels() -> None:
    """anchor 计数四档离散化：加一条导航项不许把整簇打散。"""

    def sig_with(n: int) -> str:
        html = '<body><div class="menu">' + '<a href="/x">x</a>' * n + "</div></body>"
        return container_sig(_first_anchor(html))

    assert sig_with(1).endswith("[n1-2]")
    assert sig_with(2).endswith("[n1-2]")
    assert sig_with(3).endswith("[n3-7]")
    assert sig_with(7).endswith("[n3-7]")
    assert sig_with(8).endswith("[n8-29]")
    assert sig_with(29).endswith("[n8-29]")
    assert sig_with(30).endswith("[n30+]")
    assert sig_with(898).endswith("[n30+]")
    # 关键性质：8 条与 9 条同档
    assert sig_with(8) == sig_with(9)


def test_container_sig_strips_framework_hash_classes() -> None:
    """框架生成的随机 class 一个都不许进指纹（换一次构建就换一个指纹 = 簇全散）。"""
    html = (
        '<body><div class="grid css-1a2b3c Layout_nav__x7f2q sidebar-9f8e7d6c">'
        + '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>'
        + "</div></body>"
    )
    assert container_sig(_first_anchor(html)) == "div.grid[n3-7]"


def test_container_sig_class_tokens_sorted_and_capped_at_four() -> None:
    html = (
        '<body><div class="zeta echo delta charlie bravo alpha">'
        + '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>'
        + "</div></body>"
    )
    assert container_sig(_first_anchor(html)) == "div.alpha.bravo.charlie.delta[n3-7]"


def test_container_sig_id_without_class() -> None:
    """规格四组锚点没覆盖「有 id 无 class」（spec_gaps#20）。这里定死：不出现 `.`。"""
    html = '<body><ul id="toc"><a href="/a">a</a><a href="/b">b</a></ul></body>'
    assert container_sig(_first_anchor(html)) == "ul#toc[n1-2]"


def test_container_sig_max_depth_degrades_to_solo() -> None:
    """超过 6 层还没找到列表型容器 → 退化成 anchor.parent + "solo:" 前缀。"""
    html = (
        "<body>"
        + '<div class="l1"><div class="l2"><div class="l3"><div class="l4">'
        + '<div class="l5"><div class="l6"><div class="l7"><div class="leaf">'
        + '<a href="/x">x</a>'
        + "</div></div></div></div></div></div></div></div>"
        + '<ul class="far"><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a></ul>'
        + "</body>"
    )
    assert container_sig(_first_anchor(html)) == "solo:div.leaf[n1-2]"


def test_container_sig_list_tag_wins_over_anchor_count() -> None:
    """C-a 先命中：锚点在 `<ul>` 里时容器就是那个 ul，不会再向上找 div。"""
    html = (
        '<body><div class="wrapper"><ul class="cmds">'
        + "".join(f'<a href="/redis/commands/{i}">c{i}</a>' for i in range(10))
        + "</ul></div></body>"
    )
    assert container_sig(_first_anchor(html)) == "ul.cmds[n8-29]"


# --------------------------------------------------------------------------- #
# §5.2 锚点组 3/3：region_of（3 组，行 2683-2687）
# --------------------------------------------------------------------------- #


def test_region_of_anchor_footer_wins_over_prominent() -> None:
    """`<footer class="site-footer"><a class="btn social">` → footer（**不是** prominent）。"""
    html = (
        '<body><footer class="site-footer">'
        '<a class="btn social" href="https://x.com/tinybirdco">Twitter</a>'
        "</footer></body>"
    )
    assert region_of(_first_anchor(html)) == "footer"


def test_region_of_anchor_pricing_card_is_prominent() -> None:
    html = (
        '<body><div class="pricing-card">'
        '<a class="btn" href="/cloud/pricing-page">Talk to us</a>'
        "</div></body>"
    )
    assert region_of(_first_anchor(html)) == "prominent"


def test_region_of_anchor_paragraph_is_body() -> None:
    html = '<body><p>详见<a href="/x">这里</a></p></body>'
    assert region_of(_first_anchor(html)) == "body"


def test_region_of_copper_social_btn_in_footer() -> None:
    """copper 的四个社交图标：容器 class 含 "social-btn"，两条正则同时命中 →
    必须判 footer（卡点 S12 问的那个冲突）。
    """
    html = (
        '<body><footer><div class="social-btn-row">'
        '<a href="https://www.linkedin.com/company/copper-inc/">in</a>'
        "</div></footer></body>"
    )
    assert region_of(_first_anchor(html)) == "footer"


def test_region_of_uses_any_ancestor_not_nearest() -> None:
    """页脚里的 CTA 按钮：最近祖先只有 btn（prominent），任意祖先里有 footer。"""
    html = (
        "<body><footer><div><div><div><span>"
        '<a class="btn" href="/pricing">See pricing</a>'
        "</span></div></div></div></footer></body>"
    )
    assert region_of(_first_anchor(html)) == "footer"


def test_region_of_nav_is_prominent() -> None:
    html = '<body><nav class="topbar"><a href="/pricing">Pricing</a></nav></body>'
    assert region_of(_first_anchor(html)) == "prominent"


# --------------------------------------------------------------------------- #
# in_code_block（行 2679：与上面两个函数共用同一套向上遍历）
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tag", ["code", "pre", "kbd", "samp"])
def test_in_code_block_true_for_code_tags(tag: str) -> None:
    html = (
        f'<body><p><{tag}><a href="https://api.printful.com/v2/orders/123">x</a></{tag}></p></body>'
    )
    assert in_code_block(_first_anchor(html)) is True


def test_in_code_block_false_in_prose() -> None:
    html = '<body><p><a href="https://resend.com/docs/api-reference/emails/send-email">x</a></p></body>'
    assert in_code_block(_first_anchor(html)) is False


# --------------------------------------------------------------------------- #
# §5.1 抽取器：只读 `<a href>`
# --------------------------------------------------------------------------- #

#: 抽取器负例集合。除了第一条真 href，**一条都不许取**。
FRAMEWORK_BIND_HTML = """<body>
<a href="/real">真链接</a>
<a :href="/alpine">Alpine 绑定</a>
<a x-bind:href="/alpine-long">Alpine 长写法</a>
<a v-bind:href="/vue">Vue 绑定</a>
<a [href]="/angular">Angular 绑定</a>
<a data-href="/data">data-*</a>
<a>没有 href</a>
<a href="">空 href</a>
<link rel="mcp-server-card" href="/mcp-card.json">
<img src="/pic.png" srcset="/pic2x.png 2x">
<script>var u = "/from-script";</script>
<script type="application/ld+json">{"url": "/from-jsonld"}</script>
</body>"""


def test_extract_only_reads_a_href() -> None:
    """`:href` / `x-bind:href` / `v-bind:href` / `[href]` 一条都不许取。

    mailerlite 那条 400 就是抽取器把 Alpine.js 的 `:href` 当 href 造成的；
    Datadog 那 10 条「自相矛盾」同理。`<link rel="mcp-server-card">`（close.com）
    也顺手排掉了 —— 不需要为它专门写规则。
    """
    targets = extract_links(
        FRAMEWORK_BIND_HTML, source_page="https://example.invalid/", source_role="home"
    )
    assert [t.raw_href for t in targets] == ["/real"]


@pytest.mark.parametrize(
    "attr",
    [":href", "x-bind:href", "v-bind:href", "[href]", "data-href", "xlink:href"],
)
def test_extract_rejects_every_bind_attribute_shape(attr: str) -> None:
    html = f'<body><a {attr}="/nope">x</a></body>'
    assert extract_links(html, source_page="https://example.invalid/", source_role="home") == []


def test_extract_accepts_uppercase_href_attribute() -> None:
    """HTML 属性名大小写不敏感，`HREF=` 是同一个属性（lexbor 已小写化）。"""
    targets = extract_links(
        '<body><a HREF="/up">x</a></body>',
        source_page="https://example.invalid/",
        source_role="home",
    )
    assert [t.raw_href for t in targets] == ["/up"]


def test_extract_keeps_non_http_schemes_for_the_denoise_stage() -> None:
    """`mailto:` 不在抽取阶段丢 —— 第 12 步的 `non_http_scheme` 判的是 raw_href。"""
    targets = extract_links(
        '<body><a href="mailto:support@pingcap.com">support@pingcap.com</a></body>',
        source_page="https://docs.pingcap.com/tidbcloud/release-notes",
        source_role="changelog",
    )
    assert [t.raw_href for t in targets] == ["mailto:support@pingcap.com"]


def test_extract_fills_dom_context() -> None:
    """一条链接抽完必须带齐四个 DOM 上下文 + LinkContext。"""
    html = (
        '<body><div class="plans"><div class="card">'
        '<a href="/cloud/pricing-page?cta=Talk+to+us" aria-label="Talk to us">Talk to us</a>'
        "</div>"
        + '<div class="card"><a href="/cloud/pricing-page?cta=Talk+to+us">Talk to us</a></div>' * 2
        + "</div></body>"
    )
    (first, *_rest) = extract_links(
        html, source_page="https://saleor.io/pricing", source_role="pricing"
    )
    assert first.abs_url == "https://saleor.io/cloud/pricing-page?cta=Talk+to+us"
    assert first.norm_url == "https://saleor.io/cloud/pricing-page"
    assert first.container_sig == "div.plans[n3-7]"
    assert first.region == "prominent"
    assert first.path_shape == "/cloud/pricing-page"
    assert first.ctx.anchor_text == "Talk to us"
    assert first.anchor_label == "Talk to us"
    assert first.source_role == "pricing"
    assert first.ctx.source_page == "https://saleor.io/pricing"
    assert first.in_code_block is False
    assert first.dom_index == 0


def test_extract_anchor_label_falls_back_to_img_alt() -> None:
    """图标链接没有锚文本 —— 位置分级要靠 `<img alt>`（tdengine 那面图标墙）。"""
    targets = extract_links(ANCHOR_A_HTML, source_page="https://tdengine.com/", source_role="home")
    assert [t.anchor_label for t in targets][:2] == ["java", "python"]


def test_extract_resolves_relative_hrefs_against_source_page() -> None:
    targets = extract_links(
        '<body><a href="sdk/layout-effect/">x</a></body>',
        source_page=CANVAS_SEED,
        source_role="changelog",
    )
    assert targets[0].abs_url == (
        "https://docs.canvasmedical.com/product-updates/release-notes/sdk/layout-effect/"
    )


# --------------------------------------------------------------------------- #
# §5.4 第一级折叠：normalize_url
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # saleor 的 10 个实例折成 2 个唯一路径就靠这一步
        (
            "https://saleor.io/cloud/talk-to-us?cta=See+how+Saleor+fits&cta_page=%2F",
            "https://saleor.io/cloud/talk-to-us",
        ),
        ("https://saleor.io/cloud/talk-to-us#top", "https://saleor.io/cloud/talk-to-us"),
        ("https://saleor.io/cloud/talk-to-us/", "https://saleor.io/cloud/talk-to-us"),
        ("https://SALEOR.io/Cloud", "https://saleor.io/Cloud"),  # host 小写，path 不动
        ("https://x.com/?utm_source=nav&utm_medium=x", "https://x.com/"),
        ("https://x.com/a?ref=nav&fbclid=1&gclid=2&source=home", "https://x.com/a"),
        ("https://x.com/a?page=2", "https://x.com/a?page=2"),  # 非跟踪型 query 保留
        ("https://x.com/", "https://x.com/"),  # 根路径的 / 保留
    ],
)
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


def test_normalize_url_is_only_for_merging_not_probing() -> None:
    """探测用 abs_url 原样（服务端可能对 query 敏感），只有归并用 norm_url。"""
    targets = extract_links(
        '<body><a href="/cloud/talk-to-us?cta=See+how+Saleor+fits&cta_page=%2F">x</a></body>',
        source_page="https://saleor.io/",
        source_role="home",
    )
    assert targets[0].abs_url.endswith("?cta=See+how+Saleor+fits&cta_page=%2F")
    assert targets[0].norm_url == "https://saleor.io/cloud/talk-to-us"


# --------------------------------------------------------------------------- #
# §5.2 模板归并
# --------------------------------------------------------------------------- #


def test_clusters_merge_tdengine_icon_wall_into_one() -> None:
    """8 条同 source_page、同 container_sig、同 path_shape → 1 个簇 → 1 个根因。"""
    targets = extract_links(ANCHOR_A_HTML, source_page="https://tdengine.com/", source_role="home")
    clusters = build_template_clusters(targets)
    assert len(clusters) == 1
    (key, members) = next(iter(clusters.items()))
    assert len(members) == 8
    assert key == "https://tdengine.com/|div.connector-grid[n8-29]|/reference/connector/*"


def test_clusters_keep_saleor_at_two() -> None:
    """C（首页 hero）与 D（定价页套餐卡）必须落在两个簇里 —— 实测口径是 2 个根因。"""
    targets = extract_links(ANCHOR_C_HTML, source_page="https://saleor.io/", source_role="home")
    targets += extract_links(
        ANCHOR_D_HTML, source_page="https://saleor.io/pricing", source_role="pricing"
    )
    assert len(build_template_clusters(targets)) == 2


def test_cluster_key_is_the_three_tuple() -> None:
    """簇键 = (source_page, container_sig, path_shape)。三段有一段不同就是两个簇。"""
    a = _fake_target("https://x.invalid/redis/commands/append", shape="/redis/commands/*")
    b = _fake_target("https://x.invalid/redis/json/set", shape="/redis/json/*")
    c = _fake_target("https://x.invalid/redis/commands/get", sig="ul.other[n30+]")
    d = _fake_target("https://x.invalid/redis/commands/set", source_page="https://x.invalid/other")
    assert len(build_template_clusters([a, b, c, d])) == 4
    assert len(build_template_clusters([a, a])) == 1


def test_cluster_probe_plan_probes_everything_below_min_size() -> None:
    cluster = [_fake_target(f"https://x.invalid/redis/commands/c{i}") for i in range(7)]
    plan = cluster_probe_plan(cluster, domain="x.invalid", cluster_key="k")
    assert plan == cluster


def test_cluster_probe_plan_samples_five_first_last_and_three_random() -> None:
    """size >= 8 → 首、末、随机 3，恰好 5 条（upstash: 898 → 5）。"""
    cluster = [_fake_target(f"https://upstash.com/redis/commands/c{i}") for i in range(898)]
    plan = cluster_probe_plan(cluster, domain="upstash.com", cluster_key="k")
    assert len(plan) == CLUSTER_SAMPLE_N == 5
    assert plan[0] is cluster[0]
    assert plan[1] is cluster[-1]
    assert len({t.norm_url for t in plan}) == 5


def test_cluster_probe_plan_is_deterministic() -> None:
    """卡点 S13：种子固定为 f"{domain}|{cluster_key}"，连跑两次必须逐条相同。

    L 组的「连跑两次逐字节相同」就靠这一条。
    """
    cluster = [_fake_target(f"https://upstash.com/redis/commands/c{i}") for i in range(898)]
    first = cluster_probe_plan(cluster, domain="upstash.com", cluster_key="k")
    second = cluster_probe_plan(cluster, domain="upstash.com", cluster_key="k")
    assert [t.norm_url for t in first] == [t.norm_url for t in second]


def test_cluster_probe_plan_seed_depends_on_domain_and_key() -> None:
    """不同域/不同簇不共用同一批抽样（否则「随机 3」等于固定 3）。"""
    cluster = [_fake_target(f"https://x.invalid/redis/commands/c{i}") for i in range(60)]
    a = cluster_probe_plan(cluster, domain="a.invalid", cluster_key="k")
    b = cluster_probe_plan(cluster, domain="b.invalid", cluster_key="k")
    c = cluster_probe_plan(cluster, domain="a.invalid", cluster_key="other")
    assert [t.norm_url for t in a] != [t.norm_url for t in b]
    assert [t.norm_url for t in a] != [t.norm_url for t in c]


def test_cluster_exhaust_plan_probes_tdengine_cluster_eight_times() -> None:
    """tdengine：抽样 5 条全 404 → 穷举剩余 3 条 → 8/8 全死，**簇探 8 次**，一条不漏。"""
    targets = extract_links(ANCHOR_A_HTML, source_page="https://tdengine.com/", source_role="home")
    (key, members) = next(iter(build_template_clusters(targets).items()))
    sampled = cluster_probe_plan(members, domain="tdengine.com", cluster_key=key)
    rest = cluster_exhaust_plan(members, domain="tdengine.com", cluster_key=key)
    assert len(sampled) == 5
    assert len(rest) == 3
    probed = [t.norm_url for t in (*sampled, *rest)]
    assert len(probed) == len(set(probed)) == len(members) == CLUSTER_MIN_SIZE == 8


def test_cluster_exhaust_plan_caps_at_sixty() -> None:
    cluster = [_fake_target(f"https://upstash.com/redis/commands/c{i}") for i in range(898)]
    rest = cluster_exhaust_plan(cluster, domain="upstash.com", cluster_key="k")
    assert len(rest) == 55  # 60 的上限里扣掉抽样已探的那 5 条


# --------------------------------------------------------------------------- #
# §5.1 三层封顶的 L-a / L-b（L-c 在第 12a 步的 dead_links.py）
# --------------------------------------------------------------------------- #


def test_layer_a_truncates_at_four_hundred_anchors() -> None:
    """L-a：单页原始 `<a href>` > 400 → 按 DOM 顺序截断 + CoverageGap(not_fetched)。"""
    html = "<body>" + "".join(f'<a href="/p{i}">{i}</a>' for i in range(500)) + "</body>"
    # 只看 L-a：把 L-b 关掉，否则 120 条的那一层会盖住这一层的效果
    page = extract_page(
        html, source_page="https://example.invalid/", source_role="home", max_targets=None
    )
    assert page.anchors_seen == 500
    assert len(page.targets) == MAX_ANCHORS_PER_PAGE == 400
    assert page.targets[0].raw_href == "/p0"
    assert page.targets[-1].raw_href == "/p399"
    gaps = [g for g in page.gaps if g.layer == "page_anchors"]
    assert [(g.reason, g.limit, g.dropped) for g in gaps] == [("not_fetched", 400, 100)]


def test_layer_b_caps_unique_targets_per_page() -> None:
    """L-b：单页归并后唯一目标 > 120 → 同样截断 + 记 gap。"""
    html = (
        "<body>"
        + "".join(f'<div class="row"><a href="/topic/{i}">{i}</a></div>' for i in range(200))
        + "</body>"
    )
    page = extract_page(html, source_page="https://example.invalid/", source_role="docs_home")
    assert page.probe_targets == MAX_TARGETS_PER_PAGE == 120
    gaps = [g for g in page.gaps if g.layer == "page_targets"]
    assert [(g.reason, g.limit, g.dropped) for g in gaps] == [("not_fetched", 120, 80)]


def test_layer_b_counts_a_big_cluster_as_its_probe_plan() -> None:
    """upstash 那种 898 条同簇的页**不许被 L-b 砍掉** —— 它只花 5 个预算。

    规格这一层的口径不闭合（spec_gaps#25：898 条同簇算 898 还是算 5）。这里定死
    「算 5」，否则 `cluster_probe_plan` 的 898 → 5 白做、大簇会先被 L-b 切成 120。
    """
    html = (
        '<body><ul class="cmds">'
        + "".join(f'<a href="/redis/commands/c{i}">c{i}</a>' for i in range(300))
        + "</ul></body>"
    )
    page = extract_page(html, source_page="https://upstash.com/docs", source_role="docs_home")
    assert page.anchors_seen == 300
    assert len(page.targets) == 300  # 一条没丢
    assert page.probe_targets == CLUSTER_SAMPLE_N == 5
    assert page.gaps == ()


def test_layer_b_repeated_instances_of_one_target_cost_one_budget() -> None:
    """同一个 norm_url 的多个实例只占 1 个预算（saleor 的 10 实例 → 2 目标）。"""
    html = (
        "<body>"
        + '<div class="card"><a href="/cloud/talk-to-us?cta=a">x</a></div>' * 5
        + '<div class="card"><a href="/cloud/pricing-page?cta=b">y</a></div>' * 5
        + "</body>"
    )
    page = extract_page(html, source_page="https://saleor.io/", source_role="home")
    assert len(page.targets) == 10
    assert len({t.norm_url for t in page.targets}) == 2
    assert page.probe_targets == 2


def test_caps_can_be_disabled_for_replay() -> None:
    html = "<body>" + "".join(f'<a href="/p{i}">{i}</a>' for i in range(500)) + "</body>"
    page = extract_page(
        html,
        source_page="https://example.invalid/",
        source_role="home",
        max_anchors=None,
        max_targets=None,
    )
    assert len(page.targets) == 500
    assert page.gaps == ()


# --------------------------------------------------------------------------- #
# 需要第 4b 步实录快照的断言 —— 优雅 skip，不假绿
# --------------------------------------------------------------------------- #


@real_index_needed
def test_upstash_largest_cluster_is_probed_five_times() -> None:
    """upstash 的 getstarted 页自带 898 条 Redis 命令导航 → 最大簇 >= 800，只探 5 次。

    ⚠️ 这里必须关掉 L-a（`max_anchors=None`）：规格的 L-a 把单页原始 `<a>` 封在
    400，而这条验收要求最大簇 >= 800 —— 两条规格数字互相矛盾（见交付说明
    spec_gaps）。关掉封顶测的是**归并本身**对不对。
    """
    store = FixtureStore(FIXTURES)
    if not store.has(UPSTASH_SEED):
        pytest.skip(f"实录快照里没有 {UPSTASH_SEED}")
    html = store.body(UPSTASH_SEED).decode("utf-8", "replace")
    page = extract_page(
        html,
        source_page=UPSTASH_SEED,
        source_role="docs_content",
        max_anchors=None,
        max_targets=None,
    )
    clusters = build_template_clusters(page.targets)
    key, biggest = max(clusters.items(), key=lambda kv: len(kv[1]))
    assert len(biggest) >= 800
    plan = cluster_probe_plan(biggest, domain="upstash.com", cluster_key=key)
    assert len(plan) == CLUSTER_SAMPLE_N == 5


@real_index_needed
@position_expectations_needed
def test_budget_keeps_all_measured_findings() -> None:
    """canvasmedical 那 9 条死链在 cap=300 下**一条不丢**（§5.1 卡点 B20c）。

    实测 `links_checked = 390 > 300`，所以「300 的上限不丢任何一条实测发现」这句话
    必须用实录快照验证：若归并后的唯一目标数 > 300，按 §5.1 的裁决要把默认
    `--max-links` 提到 500 并同步改这条断言与 §7.1 的帮助文本。
    """
    store = FixtureStore(FIXTURES)
    if not store.has(CANVAS_SEED):
        pytest.skip(f"实录快照里没有 {CANVAS_SEED}")
    html = store.body(CANVAS_SEED).decode("utf-8", "replace")
    page = extract_page(html, source_page=CANVAS_SEED, source_role="changelog")
    kept = {t.norm_url for t in page.targets}
    missing = [u for u in CANVAS_DEAD_9 if normalize_url(u) not in kept]
    assert missing == [], f"三层封顶丢掉了已标注的死链：{missing}"
    assert page.probe_targets <= DEFAULT_MAX_LINKS
