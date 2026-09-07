"""§5.1 链接抽取 + §5.2 模板化重复导航归并（第 11 步）。

这个模块只做两件事，**一次请求都不发**：

1. 从一页 HTML 里抽出可点击链接（**只读 `<a href>`**），给每条链接算好
   `container_sig` / `region` / `path_shape` / `in_code_block` 四个 DOM 上下文，
   连同 `LinkContext` 一起装进 `LinkTarget`；
2. 把模板化的重复导航归并成簇（`build_template_clusters`），并给出「抽样证活、
   穷举证死」的探测计划（`cluster_probe_plan` / `cluster_exhaust_plan`）。

死链判定、去噪规则接线、根因归并都不在这里（分别是第 12a / 12b / 13 步）。

**为什么必须有模板归并**：实测 upstash 一页就有 898 条 Redis 命令索引的重复导航、
零死链。不归并就要烧 898 次请求换 0 条发现，而且条目率被彻底稀释。

**为什么 `:href` 一条都不许取**：mailerlite 那条 400 就是抽取器把 Alpine.js 的
`:href` 当成 `href` 造成的假象；Datadog 那 10 条「自相矛盾」同理 —— 在未执行 JS 的
HTML 上取框架绑定属性的值，取到的不是链接。
"""

from __future__ import annotations

import random
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from selectolax.lexbor import LexborHTMLParser, LexborNode

from .models import LinkContext

# --------------------------------------------------------------------------- #
# 常量（§5.1 / §5.2，逐字照抄规格）
# --------------------------------------------------------------------------- #

#: 三层封顶。L-a / L-b 在本模块执行；L-c（`--max-links`，每域）在第 12a 步的
#: ``checks/dead_links.py`` 里执行（那一层要的「确定性分层抽样」规格没定义，
#: 见交付说明里的 spec_gaps）。
MAX_ANCHORS_PER_PAGE = 400  # L-a 单页原始 <a href> 条数（去噪前）
MAX_TARGETS_PER_PAGE = 120  # L-b 单页「模板归并后」的唯一 norm_url 数
DEFAULT_MAX_LINKS = 300  # L-c 每域去噪后 + 归并后的唯一 norm_url 数

CLUSTER_MIN_SIZE = 8  # size < 8 的簇全探
CLUSTER_SAMPLE_N = 5  # size >= 8 先探 5 条 = 首、末、随机 3
CLUSTER_EXHAUST_N = 60  # 抽样里出现 DEAD 后升级穷举的上限

#: `<a>` 前后各取多少字符做 `surrounding_html`（§2.7 建议 400）。
SURROUNDING_WINDOW = 400

Region = Literal["prominent", "body", "footer"]

# ── path_shape ─────────────────────────────────────────────────────────────
#: 规格在 `path_shape` 段给了这两个正则（行 2585-2586），但它给的实现里一次都没
#: 用到（只按 `keep` 截断）。这里保留定义、**不启用** —— 启用就等于自己发明
#: 「把数字/hash 型末段折成 `*`」这一步，会改变簇键。见 spec_gaps。
_NUMERIC_RE = re.compile(r"^\d+$")
_HASHY_RE = re.compile(r"^[0-9a-f]{8,}$|^[0-9a-f-]{20,}$", re.I)

# ── container_sig ──────────────────────────────────────────────────────────
#: 「列表型容器」判据 C-a：标签名 ∈ LIST_TAGS。
LIST_TAGS = frozenset({"ul", "ol", "nav", "table", "tbody", "dl", "menu"})

#: 框架生成的随机 class token（每次构建都变）必须剔掉，否则同一个容器换一次构建
#: 就换一个指纹，簇全打散。
#:
#: ⚠️ 偏离规格一处（必须偏离）：规格给的第三条分支是
#: ``^[a-z]+_[a-z0-9]{5,}__[a-z0-9]{5,}$``，它**匹配不了自己给的两个例子** ——
#: ``Home_grid__a91f3``（锚点 A 的期望输出要求它被剔掉）与注释里的
#: ``Layout_nav__x7f2q``，两者中段都只有 3–4 个字符（grid / nav）。锚点是
#: ground truth，所以中段的 ``{5,}`` 放宽成 ``+``，hash 段仍要求 >= 5 位。
#: 见 spec_gaps。
_CLASS_HASH_RE = re.compile(
    r"^(?:[a-z]+[-_])?[0-9a-f]{5,}$|^css-[0-9a-z]+$|^[a-z]+[-_][a-z0-9]+__[a-z0-9]{5,}$",
    re.I,
)

#: 容器 class 最多进签名的 token 数（排序后取前 4 个）。
_MAX_CLASS_TOKENS = 4

# ── region ─────────────────────────────────────────────────────────────────
_PROMINENT_CLS = re.compile(
    r"pricing|plan|tier|package|card|cta|hero|banner|nav|navbar|header|topbar|pill|button|btn"
)
_FOOTER_CLS = re.compile(r"footer|social|legal|copyright|colophon|bottom")

#: `in_code_block` 的标签集（行 2679）。
_CODE_TAGS = frozenset({"code", "pre", "kbd", "samp"})

#: 向上遍历的硬上限。畸形 HTML 理论上不会出环（lexbor 建的是树），这只是防御。
_MAX_ANCESTORS = 200

# ── normalize_url（§5.4 第一级折叠）────────────────────────────────────────
#: 跟踪型 query key（行 2838）。另外所有 ``utm_*`` 前缀一律丢。
_TRACKING_QUERY_KEYS = frozenset({"ref", "cta", "cta_page", "source", "fbclid", "gclid"})

#: `mailto:` / `tel:` / `javascript:` 由第 12 步的 `non_http_scheme` 规则记进排除
#: 日志（它判的是 `raw_href` 的 scheme），所以抽取阶段**照样抽出来**，不在这里丢。

#: 簇键三段之间的分隔符。用竖线：source_page 是 URL、container_sig 与 path_shape
#: 都不含它。
_CLUSTER_KEY_SEP = "|"


# --------------------------------------------------------------------------- #
# path_shape（规格给了完整实现，逐字照抄）
# --------------------------------------------------------------------------- #


def path_shape(path: str, keep: int = 2) -> str:
    """把路径压成形状签名：保留前 ``keep`` 段字面量，**其余整体折成一个 `*`**。

    定死「整体折成一个 `*`」而不是「逐段折成 `*`」（卡点 S12）——
    ``path_shape("/docs/topics/billing/index")`` 是 ``"/docs/topics/*"``，
    不是 ``"/docs/topics/*/*"``。深度 >= 4 时两种实现才分叉，所以必须明说。
    """
    segs = [s for s in path.split("/") if s]
    if len(segs) <= keep:
        return "/" + "/".join(segs)
    return "/" + "/".join(segs[:keep]) + "/*"


def _bucket(n: int) -> str:
    """anchor 计数四档离散化。**不写精确数** —— 一次内容更新加一条导航项就会把
    整簇打散（卡点 S12）。
    """
    if n <= 2:
        return "n1-2"
    if n <= 7:
        return "n3-7"
    if n <= 29:
        return "n8-29"
    return "n30+"


# --------------------------------------------------------------------------- #
# DOM 遍历小工具
# --------------------------------------------------------------------------- #


def _tag_of(node: LexborNode) -> str:
    """selectolax 在 mypy 眼里是 ``Any``，所有取值都要显式收成 ``str``。"""
    return str(node.tag or "")


def _attr(node: LexborNode, name: str) -> str:
    value = node.attributes.get(name)
    return "" if value is None else str(value)


def _class_tokens(node: LexborNode) -> tuple[str, ...]:
    return tuple(_attr(node, "class").split())


def _element_children(node: LexborNode) -> Iterator[LexborNode]:
    for child in node.iter(include_text=False):
        if child.is_element_node:
            yield child


def _ancestors(node: LexborNode) -> Iterator[LexborNode]:
    """从 ``node.parent`` 起一路向上，含 ``<body>``，到根为止。"""
    current = node.parent
    for _ in range(_MAX_ANCESTORS):
        if current is None:
            return
        yield current
        current = current.parent


def _count_anchors_not_crossing_list(node: LexborNode) -> int:
    """判据 C-b 的计数：``node`` 的子孙里有几个 `<a>`。

    「不限层数，但不跨越另一个 LIST_TAGS 容器」（行 2601-2603）在规格里不闭合
    （spec_gaps#19）。这里取「遇到 LIST_TAGS 子元素就**不再下钻**，它里面的 `<a>`
    计 0」这一读法：

    - 锚点 D（``div.plans > div.card > a`` × 3）证明**非 LIST_TAGS 的中间层要穿透
      计数**，这两条并不冲突；
    - 从锚点向上走时，只要锚点自己在 `ul` / `nav` 里，C-a 会先于 C-b 命中，
      所以这个读法对「容器落在哪一层」几乎不产生影响（差别只出现在锚点自身**不在**
      列表里、而兄弟链接都在别的列表里的场合）。
    """
    total = 0
    stack = list(_element_children(node))
    while stack:
        current = stack.pop()
        tag = _tag_of(current)
        if tag == "a":
            total += 1
            continue
        if tag in LIST_TAGS:
            continue  # 不跨越另一个列表型容器
        stack.extend(_element_children(current))
    return total


def _stable_class_tokens(node: LexborNode) -> tuple[str, ...]:
    """剔掉 hash 型 token 后**排序**，最多取前 4 个。"""
    tokens = [t for t in _class_tokens(node) if not _CLASS_HASH_RE.match(t)]
    return tuple(sorted(tokens)[:_MAX_CLASS_TOKENS])


# --------------------------------------------------------------------------- #
# container_sig / region_of / in_code_block（§5.2 三个 DOM 函数）
# --------------------------------------------------------------------------- #


def container_sig(anchor: LexborNode, *, max_depth: int = 6) -> str:
    """从锚点向上找**最近的列表型容器**，返回它的稳定签名。

    步骤（全部确定性）：

    1. 从 ``anchor.parent`` 起向上走，最多 ``max_depth=6`` 层。第一个满足
       C-a（tag ∈ :data:`LIST_TAGS`）或 C-b（子孙里有 >= 3 个 `<a>`）的祖先即为
       容器。走到 ``<body>`` 或超过 6 层仍没有 → 容器 = ``anchor.parent``（退化），
       签名前缀记 ``"solo:"``。
    2. 签名 = ``{tag}#{id}.{sorted stable class tokens}[{四档 anchor 计数}]``。
       id 原样保留（人写的，稳定）；class 剔掉 hash 型 token 后排序取前 4；
       anchor 计数按四档离散化。
    3. 签名里**不含 dom_path** —— 层级会随包装 div 的增减而变。

    ⚠️ 偏离规格一处（锚点是 ground truth）：规格给的 f-string 是
    ``f"{tag}#{id_or_empty}.{'.'.join(...)}[{n}]"``，代入锚点 A 会得到
    ``"div#.connector-grid[n8-29]"``，而四组锚点的期望输出都要求 id 为空时
    **不出现 `#`**、class 为空时不出现 `.`。所以落成条件拼接（spec_gaps#20）。
    """
    container: LexborNode | None = None
    prefix = ""
    node = anchor.parent
    for _ in range(max_depth):
        if node is None or _tag_of(node) in {"body", "html"}:
            break
        if _tag_of(node) in LIST_TAGS or _count_anchors_not_crossing_list(node) >= 3:
            container = node
            break
        node = node.parent
    if container is None:
        container = anchor.parent
        prefix = "solo:"
    if container is None:  # 极端：游离的 <a>，没有父节点
        return "solo:[n1-2]"

    parts = [_tag_of(container)]
    node_id = _attr(container, "id")
    if node_id:
        parts.append("#" + node_id)
    tokens = _stable_class_tokens(container)
    if tokens:
        parts.append("." + ".".join(tokens))
    n_anchors = len(container.css("a"))
    return prefix + "".join(parts) + f"[{_bucket(n_anchors)}]"


def region_of(anchor: LexborNode) -> Region:
    """判定顺序即优先级，**footer 赢**（卡点 S12 问的那个冲突）。

    1. 从 anchor 向上走**到 `<body>` 为止（不限层数）**，把每一级祖先的 tag 名与
       class token 拼成一个 haystack。用「任意祖先」而不是「最近祖先」：页脚里的
       CTA 按钮 class 常含 ``btn``，只看最近祖先会把它判成 prominent。
    2. haystack 里出现 ``<footer>`` 标签 或 :data:`_FOOTER_CLS` 命中 → ``"footer"``
       （copper 的四个社交图标就在 footer 里一个 class 含 ``social-btn`` 的容器上，
       两条正则同时命中，必须判 footer）。
    3. 否则 :data:`_PROMINENT_CLS` 命中 → ``"prominent"``；都不命中 → ``"body"``。
    """
    tags: list[str] = []
    pieces: list[str] = []
    for ancestor in _ancestors(anchor):
        tag = _tag_of(ancestor)
        tags.append(tag)
        pieces.append(tag)
        pieces.extend(_class_tokens(ancestor))
        if tag == "body":
            break
    haystack = " ".join(pieces).lower()
    if "footer" in tags or _FOOTER_CLS.search(haystack):
        return "footer"
    if _PROMINENT_CLS.search(haystack):
        return "prominent"
    return "body"


def in_code_block(anchor: LexborNode) -> bool:
    """锚点是否在代码块里（`code` / `pre` / `kbd` / `samp`）。

    与 `container_sig` / `region_of` 共用同一套向上遍历（行 2679）。
    `api_endpoint_in_code_context` 这条去噪规则要它。
    """
    return any(_tag_of(a) in _CODE_TAGS for a in _ancestors(anchor))


# --------------------------------------------------------------------------- #
# normalize_url（§5.4 第一级折叠：目标身份）
# --------------------------------------------------------------------------- #


def normalize_url(url: str) -> str:
    """目标身份折叠：丢 fragment、丢跟踪型 query、去尾斜杠、host 小写。

    ⚠️ **探测时用 `abs_url` 原样探**（服务端可能对 query 敏感），只有归并用
    `norm_url`（行 2841）。

    规格只给了这一句行为描述，没给实现（spec_gaps#17），所以这里把三处自由度定死：
    根路径 ``/`` 保留（不折成空）、query 顺序保留（只删不排）、无值参数
    （``?a``）会被规范成 ``a=``。
    """
    parts = urlsplit(url.strip())
    pairs = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_QUERY_KEYS and not k.lower().startswith("utm_")
    ]
    path = parts.path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, urlencode(pairs), ""))


def _domain_of(url: str) -> str:
    return urlsplit(url).netloc.lower()


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LinkTarget:
    """一条抽出来的可点击链接 + 它的 DOM 上下文。

    ⚠️ `container_sig` / `region` / `class_tokens` / `inline_style` /
    `anchor_label` / `raw_href` / `in_code_block` 这些字段按 §2.7 本该长在
    `models.LinkContext` 上，但仓库里的 `LinkContext` 只有原型的 5 个字段，而
    `models.py` 这一步不许改（spec_gaps#1）。所以先挂在 `LinkTarget` 上，
    下游（第 12/13 步）从这里读；`LinkContext` 补齐字段后再搬回去。
    """

    raw_href: str  # `<a href>` 的原始属性值（去噪规则要看它的原样）
    abs_url: str  # urljoin(source_page, raw_href)，探测用这个
    norm_url: str  # normalize_url(abs_url)，归并用这个
    source_page: str
    source_role: str  # home / pricing / changelog / docs_home / ...
    ctx: LinkContext
    container_sig: str
    region: Region
    path_shape: str
    anchor_label: str  # aria-label / title / 图标链接的 <img alt>
    class_tokens: tuple[str, ...]
    inline_style: str
    in_code_block: bool
    dom_index: int  # 该页 DOM 顺序里的序号，封顶截断按它

    @property
    def cluster_key(self) -> str:
        """簇键 = (source_page, container_sig, path_shape(path, keep=2))。"""
        return _CLUSTER_KEY_SEP.join((self.source_page, self.container_sig, self.path_shape))


@dataclass(frozen=True, slots=True)
class LinkGap:
    """被封顶截掉的那一段。

    规格要的是 ``CoverageGap(reason="not_fetched")``，但 `models.py` 里现在没有
    `CoverageGap`（也没有 `Coverage.links_capped`，见 spec_gaps#26），而
    `models.py` 不许改。所以先落成本模块的窄类型，字段名与语义与规格对齐，
    第 12b 步接 `Coverage` 时再映射。
    """

    reason: Literal["not_fetched"]
    layer: Literal["page_anchors", "page_targets"]  # L-a / L-b
    source_page: str
    limit: int
    dropped: int


@dataclass(frozen=True, slots=True)
class PageExtraction:
    """一页的抽取结果。`extract_links()` 只要 `targets`，封顶记账要看 `gaps`。"""

    targets: tuple[LinkTarget, ...]
    anchors_seen: int  # 该页 <a href> 原始条数（封顶前）
    probe_targets: int  # 该页归并后要花的请求数（L-b 计的就是这个）
    gaps: tuple[LinkGap, ...]


# --------------------------------------------------------------------------- #
# 抽取
# --------------------------------------------------------------------------- #


def _href_of(node: LexborNode) -> str | None:
    """取 `<a>` 的 href，**属性名必须精确等于 `href`**。

    `:href` / `x-bind:href` / `v-bind:href` / `[href]` 一概不取 —— 那是框架绑定
    属性，在未执行 JS 的 HTML 上取它的值等于自己造假链接（mailerlite 那条 400、
    Datadog 那 10 条「自相矛盾」都是这么来的）。

    大写 `HREF=` 是同一个属性（HTML 规范大小写不敏感，lexbor 已经小写化），照取。
    """
    if "href" not in node.attributes:
        return None
    raw = _attr(node, "href")
    return raw if raw.strip() else None


def _anchor_label(node: LexborNode) -> str:
    """图标链接没有锚文本，位置分级（§5.6）要靠 aria-label / title / img alt。"""
    for name in ("aria-label", "title"):
        value = _attr(node, name).strip()
        if value:
            return value
    img = node.css_first("img")
    if img is not None:
        alt = _attr(img, "alt").strip()
        if alt:
            return alt
    return ""


def _surrounding_html(node: LexborNode, anchor_html: str) -> str:
    """锚点前后各 `SURROUNDING_WINDOW` 字符。

    selectolax 不给源码偏移，所以从祖先的 `html` 里定位锚点自身的 HTML 再切窗口。
    找不到（HTML 被重写过）就退回 `anchor_html`，绝不返回整页。
    """
    want = len(anchor_html) + 2 * SURROUNDING_WINDOW
    for ancestor in _ancestors(node):
        outer = str(ancestor.html or "")
        index = outer.find(anchor_html)
        if index < 0:
            continue
        if len(outer) >= want or _tag_of(ancestor) in {"body", "html"}:
            start = max(0, index - SURROUNDING_WINDOW)
            end = index + len(anchor_html) + SURROUNDING_WINDOW
            return outer[start:end]
    return anchor_html


def _target_of(
    node: LexborNode, *, source_page: str, source_role: str, dom_index: int, from_text_file: bool
) -> LinkTarget | None:
    raw = _href_of(node)
    if raw is None:
        return None
    anchor_html = str(node.html or "")
    abs_url = urljoin(source_page, raw)
    ctx = LinkContext(
        source_page=source_page,
        anchor_text=" ".join((node.text() or "").split()),
        anchor_html=anchor_html,
        surrounding_html=_surrounding_html(node, anchor_html),
        from_text_file=from_text_file,
    )
    return LinkTarget(
        raw_href=raw,
        abs_url=abs_url,
        norm_url=normalize_url(abs_url),
        source_page=source_page,
        source_role=source_role,
        ctx=ctx,
        container_sig=container_sig(node),
        region=region_of(node),
        path_shape=path_shape(urlsplit(abs_url).path),
        anchor_label=_anchor_label(node),
        class_tokens=_class_tokens(node),
        inline_style=_attr(node, "style"),
        in_code_block=in_code_block(node),
        dom_index=dom_index,
    )


def extract_page(
    html: str,
    *,
    source_page: str,
    source_role: str,
    max_anchors: int | None = MAX_ANCHORS_PER_PAGE,
    max_targets: int | None = MAX_TARGETS_PER_PAGE,
    from_text_file: bool = False,
) -> PageExtraction:
    """抽一页的 `<a href>` 并执行 L-a / L-b 两层封顶。

    - L-a：单页原始 `<a href>` > `max_anchors`（400）→ 按 DOM 顺序截断 +
      `LinkGap(reason="not_fetched")`。
    - L-b：单页**模板归并后**的唯一 norm_url > `max_targets`（120）→ 同上。

    L-b 计的是「归并后」，所以一个 >= 8 条的簇只按它的探测计划记 5 条
    （`cluster_probe_plan`），不是按成员数记。规格里这一层的口径不闭合
    （spec_gaps#25：upstash 一页 898 条同簇算 898 还是 5），这里取「算 5」——
    否则 `cluster_probe_plan` 的 898 → 5 白做，而且 L-b 会先把大簇砍成 120。

    `max_anchors=None` / `max_targets=None` 表示不封顶（回放实录快照、验证
    「最大簇 >= 800」这类断言时要用）。
    """
    tree = LexborHTMLParser(html)
    nodes = [n for n in tree.css("a") if _href_of(n) is not None]
    anchors_seen = len(nodes)
    gaps: list[LinkGap] = []
    if max_anchors is not None and anchors_seen > max_anchors:
        gaps.append(
            LinkGap(
                reason="not_fetched",
                layer="page_anchors",
                source_page=source_page,
                limit=max_anchors,
                dropped=anchors_seen - max_anchors,
            )
        )
        nodes = nodes[:max_anchors]

    targets: list[LinkTarget] = []
    for index, node in enumerate(nodes):
        target = _target_of(
            node,
            source_page=source_page,
            source_role=source_role,
            dom_index=index,
            from_text_file=from_text_file,
        )
        if target is not None:
            targets.append(target)

    kept, dropped, probe_targets = _apply_target_cap(targets, max_targets)
    if dropped:
        assert max_targets is not None
        gaps.append(
            LinkGap(
                reason="not_fetched",
                layer="page_targets",
                source_page=source_page,
                limit=max_targets,
                dropped=dropped,
            )
        )
    return PageExtraction(
        targets=tuple(kept),
        anchors_seen=anchors_seen,
        probe_targets=probe_targets,
        gaps=tuple(gaps),
    )


def extract_links(html: str, *, source_page: str, source_role: str) -> list[LinkTarget]:
    """`extract_page()` 的便捷壳：只要链接列表。"""
    return list(extract_page(html, source_page=source_page, source_role=source_role).targets)


def _charged_norm_urls(targets: Sequence[LinkTarget]) -> set[str]:
    """归并后真正要花请求的那些 norm_url（大簇只算它的探测计划）。"""
    charged: set[str] = set()
    for key, members in build_template_clusters(targets).items():
        domain = _domain_of(members[0].source_page)
        for target in cluster_probe_plan(members, domain=domain, cluster_key=key):
            charged.add(target.norm_url)
    return charged


def _apply_target_cap(
    targets: Sequence[LinkTarget], limit: int | None
) -> tuple[list[LinkTarget], int, int]:
    """L-b：按「归并后要花的请求数」封顶，返回 (保留, 丢弃条数, 归并后目标数)。

    只有「要花请求」的 norm_url 计入预算；大簇里被抽样跳过的成员成本 0，所以
    upstash 那种 898 条同簇的页不会被 L-b 砍掉（它只花 5 个预算）。
    """
    charged = _charged_norm_urls(targets)
    kept: list[LinkTarget] = []
    kept_urls: set[str] = set()
    budget = 0
    dropped = 0
    for target in targets:
        if target.norm_url in kept_urls:
            kept.append(target)
            continue
        cost = 1 if target.norm_url in charged else 0
        if limit is not None and budget + cost > limit:
            dropped += 1
            continue
        budget += cost
        kept_urls.add(target.norm_url)
        kept.append(target)
    return kept, dropped, budget


# --------------------------------------------------------------------------- #
# 模板归并（§5.2）
# --------------------------------------------------------------------------- #


def build_template_clusters(targets: Sequence[LinkTarget]) -> dict[str, list[LinkTarget]]:
    """按簇键 (source_page, container_sig, path_shape) 归并。

    返回的 dict 按「簇首次出现的 DOM 顺序」排列（Python dict 保序），簇内保持
    DOM 顺序 —— `cluster_probe_plan` 的「首、末」和随机种子都依赖这个稳定顺序。
    """
    clusters: dict[str, list[LinkTarget]] = {}
    for target in targets:
        clusters.setdefault(target.cluster_key, []).append(target)
    return clusters


def cluster_probe_plan(
    cluster: Sequence[LinkTarget], *, domain: str, cluster_key: str
) -> list[LinkTarget]:
    """**抽样证活，穷举证死。**

    size >= 8：先探 5 条 = 首、末、随机 3

    - 5 条全 ALIVE → 整簇判 ALIVE，记 1 条 note，花 5 次请求（upstash: 898 → 5）
    - 出现 >= 1 条 DEAD → 升级为全簇穷举（`cluster_exhaust_plan`），上限 60 条
      （tdengine 首页连接器图标墙 8 条同簇、path_shape=``/reference/connector/*``，
      抽样 5 条全 404 → 穷举剩余 3 条 → 8/8 全死，一条不漏）
    - 5 条里混着 UNKNOWN → 整簇 UNKNOWN

    size < 8：全探。

    ⚠️ 卡点 S13：「随机 3」必须有种子，否则 L 组「连跑两次逐字节相同」会挂。
    种子固定为 ``f"{domain}|{cluster_key}"``。

    这条规则的正当性：死链是产品的交付物，宁可为它多花请求；存活不是交付物，
    抽样够用。
    """
    if len(cluster) < CLUSTER_MIN_SIZE:
        return list(cluster)
    rnd = random.Random(f"{domain}|{cluster_key}")  # noqa: S311  抽样，非密码学用途
    middle = list(cluster[1:-1])
    picked = rnd.sample(middle, CLUSTER_SAMPLE_N - 2)
    return [cluster[0], cluster[-1], *picked]


def cluster_exhaust_plan(
    cluster: Sequence[LinkTarget],
    *,
    domain: str,
    cluster_key: str,
    limit: int = CLUSTER_EXHAUST_N,
) -> list[LinkTarget]:
    """抽样里出现 DEAD 后的升级计划：**全簇穷举**，上限 `limit`（60）。

    返回的是「还要补探的那些」——抽样已经探过的 5 条不重复计费，**抽样 + 穷举合计
    不超过 `limit`**。所以 tdengine 那个 8 条的簇总共探 ``5 + 3 == 8`` 次、一条不漏，
    而 upstash 那个 898 条的簇合计探 ``5 + 55 == 60`` 次就停。

    ⚠️ DEAD 与 UNKNOWN 同时出现时走哪条分支，规格没定（spec_gaps#23）。按
    「穷举证死」的原则应该穷举，但这个裁决属于第 12a 步的判定接线，不在本模块。
    """
    if len(cluster) < CLUSTER_MIN_SIZE:
        return []
    sampled = cluster_probe_plan(cluster, domain=domain, cluster_key=cluster_key)
    probed = {id(t) for t in sampled}
    budget = max(0, limit - len(sampled))
    rest = [t for t in cluster if id(t) not in probed]
    return rest[:budget]
