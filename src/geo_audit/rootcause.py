"""§5.4 缺陷指纹与根因归并（IMPLEMENTATION-v2.md 行 2836–2913）。

两级折叠，价值密度全在这一层：94 条死链里 **66 条挤在 7 个域名上**，而这 66 条里
**37 条只来自 7 个模板 bug**。同一个模板/组件/导航产生的死链必须归成一条根因 ——
报 20 条等于让甲方自己去找那一处改动。

**第一级 · 目标身份折叠**（``normalize_url`` + ``fold_instances``）：丢 fragment、
丢跟踪型 query、去尾斜杠、host 小写。saleor 的 10 个链接实例折成 2 个唯一路径
（``/cloud/talk-to-us`` 7 次、``/cloud/pricing-page`` 3 次）= 2 条 finding。
⚠️ 探测时用 ``abs_url`` 原样探（服务端可能对 query 敏感），只有归并用 ``norm_url``。

**第二级 · 源侧根因归并**（``merge_root_causes``）：并查集，三条轴 +
两条建边规则（E1/E2，见 ``_edge_kind``）。

**14 条缺陷指纹 + 1 条兜底**（``DEFECT_IDS``）：``deleted_help_article`` 是 v2 新增的
第 14 条（v1 缺它，canvasmedical 那 2 条只能落进 ``route_missing``，根因数算不对）。

实测锚点（``tests/test_rootcause.py`` 逐条守着）：
    tdengine 8 → 1、bytebase 6 → 1、copper 4 → 1、canvasmedical① 3 → 1、
    brevo markdown 6 → 1、saleor 10 → 2；模板族合计 **37 条链接 → 7 个根因**；
    canvasmedical 全量 **9 → 4**，四个 defect 齐全，instance_count 排序 [2,2,2,3]。
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .fetch.ratelimit import registrable_domain

# RootCause 已按本文件原占位注释里的三步搬进 models.py（A6：唯一定义处）。
from .models import RootCause, Severity, make_finding_id

# ═════════════════════════════════════════════════════════════════════════════
# ═════════════════════════════════════════════════════════════════════════════


# --------------------------------------------------------------------------- #
# 第一级：目标身份折叠（§5.4:2838）
# --------------------------------------------------------------------------- #

#: §5.4:2838 点名的跟踪型 query 参数名（``utm_*`` 另按前缀丢）。
TRACKING_QUERY_KEYS = frozenset({"ref", "cta", "cta_page", "source", "fbclid", "gclid"})

#: 死链检查的 check_id。``make_finding_id`` 的第一个入参。
DEAD_LINK_CHECK_ID = "dead_links.hard_404"

#: Severity 的比较用序（models.py 只给了枚举，没给序 —— 见交付说明 spec_gaps）。
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def normalize_url(url: str) -> str:
    """§5.4:2838 的口径，**finding 身份的唯一口径**。

    丢 fragment、丢跟踪型 query（``utm_*`` / ``ref`` / ``cta`` / ``cta_page`` /
    ``source`` / ``fbclid`` / ``gclid``）、去尾斜杠、host 小写。

    规格只给了这一句行为描述，三处自由度在这里定死（与 ``extract.normalize_url``
    的既有实现一致，保证 owner 把那份改成 re-export 时行为不变）：
      * query 顺序保留（只删不排），无值参数 ``?a`` 规范成 ``a=``；
      * path 不改大小写（``https://SALEOR.io/Cloud`` → ``https://saleor.io/Cloud``）；
      * 空 path 与 ``/`` 都折成 ``/`` —— 两者是同一个资源，不折会让身份分叉。
        （``extract.normalize_url`` 现在把空 path 留空，是本函数与它唯一的差异；
        见交付说明 key_decisions。）
    """
    parts = urlsplit(url.strip())
    kept = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in TRACKING_QUERY_KEYS and not k.lower().startswith("utm_")
    ]
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, urlencode(kept), ""))


def url_host(url: str) -> str:
    """取小写 host（不含端口）。"""
    return (urlsplit(url).hostname or "").lower()


def path_segments(url_or_path: str) -> tuple[str, ...]:
    """路径按段切开，空段丢掉。``/a/b/`` 与 ``/a/b`` 同为 ``("a", "b")``。"""
    path = urlsplit(url_or_path).path if "//" in url_or_path else url_or_path
    return tuple(seg for seg in path.split("/") if seg)


def common_prefix_segments(a: str, b: str) -> int:
    """两个 URL/路径的最长公共路径前缀**段数**（轴 B）。"""
    sa, sb = path_segments(a), path_segments(b)
    n = 0
    for x, y in zip(sa, sb, strict=False):
        if x != y:
            break
        n += 1
    return n


def source_locus(source_page: str, container_sig: str) -> str:
    """轴 A：``source_locus = (source_page, container_sig)``（§5.2 的可执行定义）。"""
    return f"{source_page}|{container_sig}"


def edit_distance(a: str, b: str) -> int:
    """Levenshtein 距离。``typo_vs_anchor_text`` 与 fixhint 候选 d) 共用。"""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def with_path(url: str, path: str) -> str:
    """换掉 URL 的 path，其余部分不动（补回开头的 ``/``）。"""
    parts = urlsplit(url)
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _keeps_trailing_slash(path: str) -> bool:
    return path.endswith("/") and path != "/"


# --------------------------------------------------------------------------- #
# 缺陷指纹表（§5.4:2846-2871）
# --------------------------------------------------------------------------- #

#: 兜底指纹：站内路由缺失。saleor ``/cloud/*``、moonshot ``/console/invoice``、
#: canvasmedical ``/sdk/canvas-cli/`` 与 ``/documentation/pdf-annotations/``。
DEFECT_FALLBACK = "route_missing"

#: 证据不足、连兜底都不敢给（第三方 host 且没有任何对照）时的取值。
#: E1 明令「defect 相同**且 != unknown**」才连边，所以它永不参与归并。
DEFECT_UNKNOWN = "unknown"

#: 14 条指纹 + 1 条兜底 = 规格表的 15 行。**顺序即检测优先级**。
DEFECT_IDS: tuple[str, ...] = (
    "url_concatenated_twice",
    "markdown_link_not_rendered",
    "mailto_as_relative_path",
    "relative_path_prefixed",
    "wrong_host",
    "stale_path_after_migration",
    "suffix_artifact",
    "template_concat",
    "typo_vs_anchor_text",
    "renamed_social_handle",
    "deleted_third_party_repo",
    "deleted_help_article",
    "dead_third_party_site",
    "legacy_brand_domain",
    DEFECT_FALLBACK,
)

#: 规格表「检测」列，逐字照抄，直接印在报告上供甲方复核。
DEFECT_DETECT: dict[str, str] = {
    "url_concatenated_twice": 'url.count("https://") > 1',
    "markdown_link_not_rendered": "raw_href 含 `](` 或 `%5Bhttp`",
    "mailto_as_relative_path": "path 里含 `mailto:`",
    "relative_path_prefixed": "剥掉当前页路径前缀后该 URL 返回 200",
    "wrong_host": "同名路径在兄弟 host（docs./developers./www./apex）上返回 200",
    "stale_path_after_migration": "sitemap.xml 里有同末段的现存路径",
    "suffix_artifact": "去掉 `/index`、`.html`、尾斜杠后返回 200",
    "template_concat": "正则 `https?://.+https?://`",
    "typo_vs_anchor_text": "路径末段与锚文本编辑距离 ≤2",
    "renamed_social_handle": "同社交 host 上营销站链的另一个 handle 200",
    "deleted_third_party_repo": "GitHub/GitLab 组织页 200 但仓库路径 404",
    "deleted_help_article": "同一篇帮助中心文章在**两个** host 上都 404（原 host + 真身 host）",
    "dead_third_party_site": "该第三方 host 根路径也 404",
    "legacy_brand_domain": "死目标的注册域 ≠ 被审计域，且同 host 已确认 ≥3 条 200",
    DEFECT_FALLBACK: "兜底",
}

#: 规格表「一句话修复」列，逐字照抄。``fix_once`` 就是拿它拼的。
DEFECT_FIX: dict[str, str] = {
    "url_concatenated_twice": "后台字段改成 handle/路径，或去掉模板前缀",
    "markdown_link_not_rendered": "修 changelog 的 markdown 渲染",
    "mailto_as_relative_path": '改成 `href="mailto:..."`',
    "relative_path_prefixed": "改成绝对路径（以 `/` 开头）",
    "wrong_host": "href 换成文档子域的绝对 URL",
    "stale_path_after_migration": "批量替换或加 301",
    "suffix_artifact": "批量去掉尾部后缀",
    "template_concat": "修 llms.txt 生成模板",
    "typo_vs_anchor_text": "按锚文本改路径",
    "renamed_social_handle": "统一到营销站的那个 handle",
    "deleted_third_party_repo": "换现存仓库或删链",
    "deleted_help_article": "撤链或指到现存文章",
    "dead_third_party_site": "撤链或换镜像",
    "legacy_brand_domain": "逐条迁移到新域",
    DEFECT_FALLBACK: "补页面或改指到现存页",
    DEFECT_UNKNOWN: "先人工看一眼这条是不是真死",
}

#: 报告里的中文名，进 ``RootCause.summary``。
DEFECT_LABEL: dict[str, str] = {
    "url_concatenated_twice": "URL 被拼了两次",
    "markdown_link_not_rendered": "markdown 链接没渲染",
    "mailto_as_relative_path": "mailto 当成相对路径",
    "relative_path_prefixed": "相对路径被当前页前缀吃掉",
    "wrong_host": "写在了错误的 host 上",
    "stale_path_after_migration": "文档迁移后的旧路径",
    "suffix_artifact": "多余的路径后缀",
    "template_concat": "模板前缀拼接外链",
    "typo_vs_anchor_text": "路径拼错（锚文本才是对的）",
    "renamed_social_handle": "社交账号改名后没跟着改",
    "deleted_third_party_repo": "第三方仓库已删或改名",
    "deleted_help_article": "帮助中心文章已删",
    "dead_third_party_site": "第三方站点整站已死",
    "legacy_brand_domain": "旧品牌域名残留",
    DEFECT_FALLBACK: "站内路由缺失",
    DEFECT_UNKNOWN: "未归因",
}

#: ``wrong_host`` 的兄弟 host 前缀（§5.4 表 + §5.5 候选 a 同一份口径）。
SIBLING_HOST_PREFIXES: tuple[str, ...] = ("www.", "docs.", "developers.", "api.")

#: ``deleted_third_party_repo`` 只认这两个代码托管站（规格表原文 GitHub/GitLab）。
CODE_HOSTS = frozenset({"github.com", "gitlab.com", "www.github.com", "www.gitlab.com"})

#: ``renamed_social_handle`` 的社交 host。与 §5.6 的 SOCIAL_HOSTS 同源；
#: §5.6 的那份属 position.py（不是本文件的活），所以这里只留本指纹用得到的。
SOCIAL_HOSTS = frozenset(
    {
        "x.com",
        "twitter.com",
        "linkedin.com",
        "www.linkedin.com",
        "facebook.com",
        "www.facebook.com",
        "youtube.com",
        "www.youtube.com",
        "instagram.com",
        "www.instagram.com",
        "mastodon.social",
        "bsky.app",
    }
)

#: ``deleted_help_article`` 认帮助中心 host 的标记（canvasmedical 实测那两个：
#: ``help.canvasmedical.com`` 与真身 ``canvas-medical.help.usepylon.com``）。
HELP_HOST_MARKERS: tuple[str, ...] = (
    "help.",
    ".help.",
    "support.",
    "intercom.help",
    "zendesk.com",
    "usepylon.com",
    "helpscoutdocs.com",
)

#: ``legacy_brand_domain`` 的门槛：同 host 已确认 200 的条数 ≥ 3 才算「不能一刀切」。
#: brevo 实测 15 条（developers.sendinblue.com 5 条 404、同页另有 15 条 200）。
LEGACY_HOST_MIN_ALIVE = 3

#: host 级判定。G 组断言 ``host_verdicts["developers.sendinblue.com"] != "DOMAIN_DEAD"``。
HOST_VERDICT_DOMAIN_DEAD = "DOMAIN_DEAD"
HOST_VERDICT_PARTIAL_DEAD = "PARTIAL_DEAD"
HOST_VERDICT_ALIVE = "ALIVE"

_DOUBLE_SCHEME_RE = re.compile(r"https?://.+https?://", re.I)
#: ``url_concatenated_twice`` 与 ``template_concat`` 的分界：第二个 scheme 紧贴在
#: 第一个 host 的路径分隔符后面 = 后台字段填了整条 URL（copper 四个社交图标）；
#: 别的形态（inngest ``/docs-markdownhttps://…``）归 ``template_concat``。
_CONCAT_AFTER_HOST_RE = re.compile(r"^https?://[^/]+/https?://", re.I)
_SUFFIX_ARTIFACTS: tuple[str, ...] = ("/index", ".html")


@dataclass(frozen=True, slots=True)
class ProbeLedger:
    """已经探过的账本。**本模块一个请求都不发**，只读上游探测留下的证据。

    这样根因归并可以完全离线复算（G 组断言就是这么跑的），也避免同一个 URL
    被指纹检测重复探。``fixhint.py`` 才是唯一还会新发请求的地方（≤4 请求/条）。
    """

    #: norm_url -> 状态码（0 = transport error）。命中 200 才算「活着」。
    statuses: Mapping[str, int] = field(default_factory=dict)
    #: 被审计站 sitemap.xml 里的 URL（``SiteMap.sitemap_urls`` 摊平即可）。
    sitemap_urls: tuple[str, ...] = ()
    #: host -> 该 host 上已确认 200 的条数。``legacy_brand_domain`` 的门槛。
    host_ok_counts: Mapping[str, int] = field(default_factory=dict)
    #: 被审计站自己链出去、且已确认 200 的 URL（营销站那份）。
    #: ``renamed_social_handle`` 靠它区分「营销站链的另一个 handle」与纯对照探测。
    alive_site_links: frozenset[str] = frozenset()

    def status_of(self, url: str) -> int | None:
        return self.statuses.get(normalize_url(url))

    def is_ok(self, url: str) -> bool:
        return self.status_of(url) == 200

    def is_missing(self, url: str) -> bool:
        return self.status_of(url) in (404, 410)

    def host_ok_count(self, host: str) -> int:
        return self.host_ok_counts.get(host.lower(), 0)

    def sitemap_paths(self) -> tuple[str, ...]:
        return tuple(urlsplit(u).path for u in self.sitemap_urls)


def host_verdict(host: str, ledger: ProbeLedger) -> str:
    """host 级判定。**只要同 host 还有 200，就不许整域判死。**

    brevo 实测：``developers.sendinblue.com`` 5 条 404，同页另有 15 条 200 ——
    整域名一刀切会把 15 条活链接一起报死。规格 §5.4 只给了这条约束的自然语言
    版（G 组断言 ``!= "DOMAIN_DEAD"``），没给函数；见交付说明 spec_gaps。
    """
    host = host.lower()
    alive = ledger.host_ok_count(host)
    dead = sum(1 for u, st in ledger.statuses.items() if url_host(u) == host and st in (404, 410))
    if alive and dead:
        return HOST_VERDICT_PARTIAL_DEAD
    if alive or not dead:
        return HOST_VERDICT_ALIVE
    return HOST_VERDICT_DOMAIN_DEAD


# --------------------------------------------------------------------------- #
# 归并的输入单位
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class DeadInstance:
    """一个 ``<a href>`` 出现实例（第一级折叠**之前**的粒度）。

    saleor 首页那 7 个 CTA 是 7 个 DeadInstance、1 个 DeadTarget。
    """

    abs_url: str
    source_page: str
    container_sig: str = ""
    raw_href: str = ""
    anchor_text: str = ""
    severity: Severity = Severity.MEDIUM
    #: 上游（标注文件 / dead_links.py）已经定了 defect 就填这里，检测直接跳过。
    defect: str = ""
    #: 上游已经算好 finding_id 就填这里（``DeadTarget.identity`` 会优先用它）。
    #:
    #: 为什么必须能传：``identity`` 的兜底算法写死了 ``DEAD_LINK_CHECK_ID``
    #: （``dead_links.*``），而 ``make_finding_id`` 把 check_id 算进哈希 ——
    #: 于是索引内链（check_id = ``ai_path.index_links``）在两侧会算出**完全不交**
    #: 的两套 id，根因回填 0 条命中。实测第一份真报告就是这样：
    #: 75 条 finding、1 条根因、交集 0。
    finding_id: str = ""


@dataclass(frozen=True, slots=True)
class DeadTarget:
    """一条 finding 的归并原料：**一个唯一 norm_url**（§2.7 卡点 A16）。

    ``dead_links.py``（第 12 步）落地后由它产出；``from_finding`` 是那时的适配口。
    """

    norm_url: str
    abs_url: str
    source_page: str
    container_sig: str = ""
    raw_href: str = ""
    anchor_text: str = ""
    occurrences: int = 1
    occurrence_pages: tuple[str, ...] = ()
    occurrence_hrefs: tuple[str, ...] = ()
    severity: Severity = Severity.MEDIUM
    defect: str = ""
    finding_id: str = ""

    @property
    def identity(self) -> str:
        """finding_id。上游没给就按 §2.10 的口径现算（target_url 传 norm_url）。"""
        return self.finding_id or make_finding_id(
            DEAD_LINK_CHECK_ID, self.norm_url, self.source_page
        )

    @property
    def locus(self) -> str:
        return source_locus(self.source_page, self.container_sig)

    @property
    def host(self) -> str:
        return url_host(self.norm_url)

    @classmethod
    def from_instance(cls, inst: DeadInstance) -> DeadTarget:
        return fold_instances([inst])[0]


def fold_instances(instances: Sequence[DeadInstance]) -> tuple[DeadTarget, ...]:
    """第一级折叠：按 ``normalize_url`` 把实例合成唯一目标。

    saleor 10 个实例 → 2 条 finding，``occurrences`` 分别 7 / 3，合计 10。
    首次出现的那个实例定 ``source_page`` / ``container_sig``（= 归并用的 locus），
    其余实例只进 ``occurrence_pages`` / ``occurrence_hrefs``；``severity`` 取组内最高
    （一条 finding 取它所有实例里最严重的那个位置，§5.6 同一口径）。
    """
    order: list[str] = []
    groups: dict[str, list[DeadInstance]] = {}
    for inst in instances:
        key = normalize_url(inst.abs_url)
        if key not in groups:
            order.append(key)
            groups[key] = []
        groups[key].append(inst)

    out: list[DeadTarget] = []
    for key in order:
        group = groups[key]
        head = group[0]
        pages: list[str] = []
        hrefs: list[str] = []
        for inst in group:
            if inst.source_page not in pages:
                pages.append(inst.source_page)
            if inst.abs_url not in hrefs:
                hrefs.append(inst.abs_url)
        out.append(
            DeadTarget(
                # 上游的 finding_id 原样带过来，别让 identity 走兜底算法
                # （兜底会用 DEAD_LINK_CHECK_ID，算出另一套 id）。
                finding_id=head.finding_id,
                norm_url=key,
                abs_url=head.abs_url,
                source_page=head.source_page,
                container_sig=head.container_sig,
                raw_href=head.raw_href or next((i.raw_href for i in group if i.raw_href), ""),
                anchor_text=head.anchor_text
                or next((i.anchor_text for i in group if i.anchor_text), ""),
                occurrences=len(group),
                occurrence_pages=tuple(pages),
                occurrence_hrefs=tuple(hrefs),
                severity=max((i.severity for i in group), key=lambda s: SEVERITY_ORDER[s]),
                defect=next((i.defect for i in group if i.defect), ""),
            )
        )
    return tuple(out)


# --------------------------------------------------------------------------- #
# 指纹检测
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class DefectVerdict:
    """一条死目标的归因结果。``evidence`` 是可复核的证据句，直接印在报告上。"""

    defect: str
    evidence: str
    control_url: str | None = None

    @property
    def detect(self) -> str:
        return DEFECT_DETECT.get(self.defect, "")


def _sibling_hosts(host: str) -> tuple[str, ...]:
    """兄弟 host：docs. / developers. / www. / api. 与 apex，去掉自己。"""
    apex = registrable_domain(host)
    out = [apex, *(prefix + apex for prefix in SIBLING_HOST_PREFIXES)]
    return tuple(h for h in dict.fromkeys(out) if h != host)


def _is_help_host(host: str) -> bool:
    return any(marker in host for marker in HELP_HOST_MARKERS)


def _detect_relative_path_prefixed(target: DeadTarget, ledger: ProbeLedger) -> DefectVerdict | None:
    src_segs = path_segments(target.source_page)
    tgt_path = urlsplit(target.norm_url).path
    tgt_segs = path_segments(tgt_path)
    if not src_segs or len(tgt_segs) <= len(src_segs):
        return None
    if url_host(target.source_page) != target.host:
        return None
    if tgt_segs[: len(src_segs)] != src_segs:
        return None
    rest = "/" + "/".join(tgt_segs[len(src_segs) :])
    if _keeps_trailing_slash(urlsplit(target.abs_url).path):
        rest += "/"
    stripped = with_path(target.norm_url, rest)
    if not ledger.is_ok(stripped):
        return None
    return DefectVerdict(
        "relative_path_prefixed",
        f"{target.norm_url} 404，剥掉当前页前缀 /{'/'.join(src_segs)}/ 后 {rest} 返回 200",
        stripped,
    )


def _detect_wrong_host(target: DeadTarget, ledger: ProbeLedger) -> DefectVerdict | None:
    path = urlsplit(target.abs_url).path
    for sibling in _sibling_hosts(target.host):
        candidate = with_path(f"https://{sibling}/", path)
        if ledger.is_ok(candidate):
            return DefectVerdict(
                "wrong_host",
                f"{target.norm_url} 404，同名路径在 {sibling} 上返回 200",
                normalize_url(candidate),
            )
    return None


def _detect_stale_path(target: DeadTarget, ledger: ProbeLedger) -> DefectVerdict | None:
    segs = path_segments(target.norm_url)
    if not segs:
        return None
    last = segs[-1]
    tgt_path = urlsplit(target.norm_url).path.rstrip("/")
    for url in ledger.sitemap_urls:
        sm_segs = path_segments(url)
        if not sm_segs or sm_segs[-1] != last:
            continue
        if urlsplit(url).path.rstrip("/") == tgt_path:
            continue
        return DefectVerdict(
            "stale_path_after_migration",
            f"{target.norm_url} 404，sitemap.xml 里同末段的现存路径是 {urlsplit(url).path}",
            normalize_url(url),
        )
    return None


def _detect_suffix_artifact(target: DeadTarget, ledger: ProbeLedger) -> DefectVerdict | None:
    path = urlsplit(target.abs_url).path
    candidates: list[str] = []
    for suffix in _SUFFIX_ARTIFACTS:
        if path.endswith(suffix):
            candidates.append(path[: -len(suffix)] or "/")
    if _keeps_trailing_slash(path):
        candidates.append(path.rstrip("/") or "/")
    for cand in candidates:
        stripped = with_path(target.norm_url, cand)
        if ledger.is_ok(stripped):
            return DefectVerdict(
                "suffix_artifact",
                f"{target.norm_url} 404，去掉尾部后缀后 {cand} 返回 200",
                normalize_url(stripped),
            )
    return None


def _detect_typo_vs_anchor(target: DeadTarget) -> DefectVerdict | None:
    segs = path_segments(target.norm_url)
    anchor = target.anchor_text.strip().lstrip("@").strip()
    if not segs or not anchor or " " in anchor:
        return None
    last = segs[-1]
    dist = edit_distance(last.lower(), anchor.lower())
    if dist == 0 or dist > 2:
        return None
    return DefectVerdict(
        "typo_vs_anchor_text",
        f"{target.norm_url} 404，路径末段 {last} 与锚文本 {target.anchor_text} 编辑距离 {dist}",
    )


def _detect_renamed_social_handle(target: DeadTarget, ledger: ProbeLedger) -> DefectVerdict | None:
    if target.host not in SOCIAL_HOSTS:
        return None
    if len(path_segments(target.norm_url)) != 1:
        return None
    for url in sorted(ledger.alive_site_links):
        if url_host(url) != target.host or len(path_segments(url)) != 1:
            continue
        if normalize_url(url) == target.norm_url or not ledger.is_ok(url):
            continue
        return DefectVerdict(
            "renamed_social_handle",
            f"{target.norm_url} 404，同 host 上营销站链的另一个 handle {url} 返回 200",
            normalize_url(url),
        )
    return None


def _detect_deleted_third_party_repo(
    target: DeadTarget, ledger: ProbeLedger
) -> DefectVerdict | None:
    if target.host not in CODE_HOSTS:
        return None
    segs = path_segments(target.norm_url)
    if len(segs) < 2:
        return None
    for depth in (2, 1):
        control = with_path(target.norm_url, "/" + "/".join(segs[:depth]))
        if ledger.is_ok(control):
            what = "仓库" if depth == 2 else "组织页"
            return DefectVerdict(
                "deleted_third_party_repo",
                f"{target.norm_url} 404，而{what} {control} 返回 200",
                normalize_url(control),
            )
    return None


def _detect_deleted_help_article(
    target: DeadTarget, peers: Sequence[DeadTarget]
) -> DefectVerdict | None:
    tgt_path = urlsplit(target.norm_url).path.rstrip("/")
    if not tgt_path or tgt_path == "/":
        return None
    for peer in peers:
        if peer.norm_url == target.norm_url or peer.host == target.host:
            continue
        if urlsplit(peer.norm_url).path.rstrip("/") != tgt_path:
            continue
        if not (_is_help_host(target.host) or _is_help_host(peer.host)):
            continue
        return DefectVerdict(
            "deleted_help_article",
            f"同一篇文章在两个 host 上都 404：{target.norm_url} 与真身 {peer.norm_url}",
        )
    return None


def _detect_dead_third_party_site(
    target: DeadTarget, ledger: ProbeLedger, *, audited_domain: str
) -> DefectVerdict | None:
    if not audited_domain or registrable_domain(target.host) == registrable_domain(audited_domain):
        return None
    root = f"https://{target.host}/"
    if not ledger.is_missing(root):
        return None
    return DefectVerdict(
        "dead_third_party_site",
        f"{target.norm_url} 404，该第三方 host 的根路径 {root} 也 404",
        normalize_url(root),
    )


def _detect_legacy_brand_domain(
    target: DeadTarget, ledger: ProbeLedger, *, audited_domain: str
) -> DefectVerdict | None:
    if not audited_domain or registrable_domain(target.host) == registrable_domain(audited_domain):
        return None
    alive = ledger.host_ok_count(target.host)
    if alive < LEGACY_HOST_MIN_ALIVE:
        return None
    return DefectVerdict(
        "legacy_brand_domain",
        f"{target.norm_url} 404，但同 host（{target.host}）另有 {alive} 条 200 —— "
        f"不能整域名一刀切（host 判定 {host_verdict(target.host, ledger)}）",
    )


def detect_defect(
    target: DeadTarget,
    ledger: ProbeLedger,
    *,
    audited_domain: str = "",
    peers: Sequence[DeadTarget] = (),
) -> DefectVerdict:
    """§5.4 缺陷指纹表，**按表的行序判**（顺序即优先级）。

    ``target.defect`` 非空（上游/标注已定）就原样返回，只补一句证据。

    两处与表的字面检测不同，都记在交付说明 deviations 里：
      * ``url_concatenated_twice`` 表里写 ``url.count("https://") > 1``，但那条也会
        吃掉 inngest 的 ``template_concat`` 锚点（两条实测锚点会打架）。这里要求
        第二个 scheme 紧贴第一个 host 的 ``/``（copper 的形态），其余交给
        ``template_concat``。
      * ``markdown_link_not_rendered`` 表里只说看 ``raw_href``；``raw_href`` 缺失时
        这里退回看 ``abs_url``（``](`` / ``%5Bhttp`` 不会出现在正常 URL 里）。
    """
    if target.defect:
        return DefectVerdict(
            target.defect,
            f"{target.norm_url} 404（归因由上游给定：{DEFECT_DETECT.get(target.defect, '')}）",
        )

    url = target.abs_url
    href = target.raw_href or url

    if _CONCAT_AFTER_HOST_RE.match(url) and url.lower().count("https://") > 1:
        return DefectVerdict(
            "url_concatenated_twice",
            f"{url} —— host 后面又接了一整条 URL，模板把前缀拼了两次",
        )

    if "](" in href or "%5bhttp" in href.lower():
        return DefectVerdict(
            "markdown_link_not_rendered",
            f"{url} —— 服务端返回的 <a href> 里就带着 markdown 语法，用户点得到",
        )

    if "mailto:" in urlsplit(url).path.lower():
        return DefectVerdict(
            "mailto_as_relative_path",
            f"{url} —— mailto: 被当成相对路径写进了 href",
        )

    for detector in (
        _detect_relative_path_prefixed,
        _detect_wrong_host,
        _detect_stale_path,
        _detect_suffix_artifact,
    ):
        found = detector(target, ledger)
        if found is not None:
            return found

    if _DOUBLE_SCHEME_RE.search(url):
        return DefectVerdict(
            "template_concat",
            f"{url} —— 一条 URL 里出现了两个 scheme，是生成模板拼坏的",
        )

    typo = _detect_typo_vs_anchor(target)
    if typo is not None:
        return typo

    for ctx_detector in (_detect_renamed_social_handle, _detect_deleted_third_party_repo):
        found = ctx_detector(target, ledger)
        if found is not None:
            return found

    help_article = _detect_deleted_help_article(target, peers)
    if help_article is not None:
        return help_article

    for domain_detector in (_detect_dead_third_party_site, _detect_legacy_brand_domain):
        found = domain_detector(target, ledger, audited_domain=audited_domain)
        if found is not None:
            return found

    if audited_domain and registrable_domain(target.host) != registrable_domain(audited_domain):
        # 第三方 host 且一条对照都没有 —— 兜底 route_missing 是站内口径，
        # 套到第三方身上就是替别人家的路由背书。宁可 unknown，不进归并。
        return DefectVerdict(
            DEFECT_UNKNOWN,
            f"{target.norm_url} 404，但这是第三方 host 且没有任何同 host 对照，不归因",
        )

    return DefectVerdict(DEFECT_FALLBACK, f"{target.norm_url} 404，站内没有这个路由")


# --------------------------------------------------------------------------- #
# 第二级：并查集归并（§5.4:2843-2852）
# --------------------------------------------------------------------------- #

#: E1 第二支的门槛：同 host 且公共前缀 ≥ 2 段。
E1_MIN_PREFIX_SEGMENTS = 2
#: E2 的两个门槛：公共前缀 ≥ 1 段，且该 locus 内死目标数 ≥ 3。
E2_MIN_PREFIX_SEGMENTS = 1
E2_MIN_LOCUS_DEAD = 3


class _UnionFind:
    """按秩合并 + 路径压缩。归并次序不影响结果（G 组断言要可复算）。"""

    def __init__(self, n: int) -> None:
        self._parent = list(range(n))
        self._rank = [0] * n

    def find(self, i: int) -> int:
        while self._parent[i] != i:
            self._parent[i] = self._parent[self._parent[i]]
            i = self._parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1


def _edge_kind(
    a: DeadTarget,
    da: str,
    b: DeadTarget,
    db: str,
    *,
    locus_dead: Mapping[str, int],
) -> str | None:
    """§5.4:2848-2852 的两条建边规则。任一成立即连边，返回命中的那条的 id。

    E1: defect 相同（且 != "unknown"）且（source_locus 相同 或 同 host 且公共前缀 >= 2 段）
    E2: source_locus 相同 且 公共前缀 >= 1 段 且 该 locus 内死目标数 >= 3
    """
    prefix = common_prefix_segments(a.norm_url, b.norm_url)
    same_locus = a.locus == b.locus
    if da == db and da != DEFECT_UNKNOWN:
        if same_locus:
            return "E1"
        if a.host == b.host and prefix >= E1_MIN_PREFIX_SEGMENTS:
            return "E1"
    if (
        same_locus
        and prefix >= E2_MIN_PREFIX_SEGMENTS
        and locus_dead.get(a.locus, 0) >= E2_MIN_LOCUS_DEAD
    ):
        return "E2"
    return None


def _root_cause_id(finding_ids: Sequence[str]) -> str:
    raw = "|".join(sorted(finding_ids))
    return "RC-" + hashlib.sha256(raw.encode()).hexdigest()[:10].upper()


#: summary 里最多带几句证据（多了甲方不看，少了复核不了）。
MAX_EVIDENCE_SENTENCES = 3


def _summarize(
    members: Sequence[DeadTarget],
    verdicts: Mapping[str, DefectVerdict],
    defect: str,
    instance_count: int,
) -> str:
    pages = tuple(dict.fromkeys(m.source_page for m in members))
    where = pages[0] if len(pages) == 1 else f"{pages[0]} 等 {len(pages)} 页"
    evidence = [
        verdicts[m.norm_url].evidence
        for m in sorted(members, key=lambda m: m.norm_url)
        if verdicts[m.norm_url].defect == defect
    ][:MAX_EVIDENCE_SENTENCES]
    head = (
        f"{where}：{len(members)} 个唯一目标 / {instance_count} 个链接实例"
        f"命中「{DEFECT_LABEL.get(defect, defect)}」（{DEFECT_DETECT.get(defect, '')}）"
    )
    if not evidence:
        return head
    return head + "。证据：" + "；".join(evidence)


def _group_path_prefix(members: Sequence[DeadTarget]) -> str:
    """组内所有目标的最长公共路径前缀（轴 B），进 ``merge_axes`` 供审计。"""
    segs = path_segments(members[0].norm_url)
    for m in members[1:]:
        other = path_segments(m.norm_url)
        keep = 0
        for x, y in zip(segs, other, strict=False):
            if x != y:
                break
            keep += 1
        segs = segs[:keep]
    return "/" + "/".join(segs)


def merge_root_causes(
    targets: Sequence[DeadTarget],
    *,
    ledger: ProbeLedger | None = None,
    audited_domain: str = "",
) -> tuple[RootCause, ...]:
    """第二级折叠：源侧根因归并。**一条 RootCause = 甲方改一处。**

    返回顺序：instance_count 降序、max_severity 降序、root_cause_id 升序 ——
    与请求次序无关，可复算。每条 ``RootCause`` 的 ``merge_axes`` / ``fix_once`` /
    ``defect`` 都非空（A21 硬要求）。
    """
    if not targets:
        return ()
    book = ledger if ledger is not None else ProbeLedger()
    verdicts = {
        t.norm_url: detect_defect(t, book, audited_domain=audited_domain, peers=targets)
        for t in targets
    }
    locus_dead: dict[str, int] = {}
    for t in targets:
        locus_dead[t.locus] = locus_dead.get(t.locus, 0) + 1

    uf = _UnionFind(len(targets))
    edges: dict[int, set[str]] = {}
    for i, a in enumerate(targets):
        for j in range(i + 1, len(targets)):
            b = targets[j]
            kind = _edge_kind(
                a,
                verdicts[a.norm_url].defect,
                b,
                verdicts[b.norm_url].defect,
                locus_dead=locus_dead,
            )
            if kind is None:
                continue
            uf.union(i, j)
            edges.setdefault(i, set()).add(kind)
            edges.setdefault(j, set()).add(kind)

    groups: dict[int, list[int]] = {}
    for i in range(len(targets)):
        groups.setdefault(uf.find(i), []).append(i)

    out: list[RootCause] = []
    for idxs in groups.values():
        members = [targets[i] for i in idxs]
        kinds = sorted({k for i in idxs for k in edges.get(i, set())}) or ["none"]
        counts: dict[str, int] = {}
        for m in members:
            d = verdicts[m.norm_url].defect
            counts[d] = counts.get(d, 0) + 1
        # 组内 defect 取「条数最多、非 unknown 优先、id 字典序」——E2 可以把不同
        # defect 连到一起（同 locus 的兄弟一起坏），这时报告要说主导的那一种。
        defect = sorted(counts, key=lambda d: (-counts[d], d == DEFECT_UNKNOWN, d))[0]
        finding_ids = tuple(m.identity for m in members)
        instance_count = sum(m.occurrences for m in members)
        out.append(
            RootCause(
                root_cause_id=_root_cause_id(finding_ids),
                summary=_summarize(members, verdicts, defect, instance_count),
                fix_once=(
                    f"改 1 处 → 修 {len(members)} 条"
                    f"（{instance_count} 个链接实例）：{DEFECT_FIX.get(defect, '')}"
                ),
                finding_ids=finding_ids,
                max_severity=max((m.severity for m in members), key=lambda s: SEVERITY_ORDER[s]),
                instance_count=instance_count,
                unique_target_count=len(finding_ids),
                defect=defect,
                source_pages=tuple(dict.fromkeys(m.source_page for m in members)),
                merge_axes={
                    "defect": defect,
                    "source_locus": members[0].locus,
                    "path_prefix": _group_path_prefix(members),
                    "edges": ",".join(kinds),
                },
            )
        )
    out.sort(
        key=lambda rc: (-rc.instance_count, -SEVERITY_ORDER[rc.max_severity], rc.root_cause_id)
    )
    return tuple(out)


def root_causes_from_instances(
    instances: Sequence[DeadInstance],
    *,
    ledger: ProbeLedger | None = None,
    audited_domain: str = "",
) -> tuple[RootCause, ...]:
    """两级折叠一把跑完：实例 → 唯一目标 → 根因。"""
    return merge_root_causes(
        fold_instances(instances), ledger=ledger, audited_domain=audited_domain
    )
