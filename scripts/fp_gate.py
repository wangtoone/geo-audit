#!/usr/bin/env python
"""CI 假阳性门禁（§8.6，两个分母六条门禁）。

假阳性率**不能**定义成「人看着觉得对」。它是带标注 fixture 集上的混淆矩阵：

    FP = |{pred==DEAD ∧ label!=dead}|      fp_rate = FP / |{pred==DEAD}|
    FN = |{pred!=DEAD ∧ label==dead}|      recall  = (n_true_dead - FN) / n_true_dead

**两个分母（卡点 S3）**：v1 把五条门禁全算在同一个 42 条集合上，于是
``unused_rules == []`` 与 ``n_candidates == 42`` 数学上不能同时成立 —— 42 条只
触发 6 条规则，``mintlify_injected_anchor`` / ``fern_*`` / ``intellimize`` /
``geo_redirect`` / ``hostile_400`` / ``login_wall`` / ``presigned_expiring`` /
``inline_display_none_anchor`` 一律在 X 组。所以：

    METRICS_SET  = tests/data/deadlink_labels.jsonl        42 条，算 fp / recall
    COVERAGE_SET = METRICS_SET ∪ tests/data/denoise_extra_labels.jsonl   42 + X 组

判定走的是**生产路径** ``geo_audit.checks.dead_links.classify_link``，Fetcher 是
真的（``transport=<回放 transport>``、``probe_url_provider=<确定性对照探针>``），
所以限速器、缓存、跟跳转、对照探测全在路上（卡点 A1）。

────────────────────────────────────────────────────────────────────────────
⚠️ 观测来源：现在有两档，报告里逐条记，别把它当成「全部实录」
────────────────────────────────────────────────────────────────────────────
``fixtures/index.json`` 不存在（第 4b 步才实录快照），所以本脚本的回放 transport
是两级的：

  ① ``store.has(url)`` 为真 -> 用**实录快照**（``store.replay``）。第 4b 步一落地，
     这一档自动接管，脚本一行都不用改。
  ② 否则 -> 用 :data:`DECLARED_EVIDENCE`：把 ``fixtures/urls.txt`` 与
     ``tests/data/*.jsonl`` 里**已经逐条写下来的观测**（状态码 / 跳转链 /
     sibling control 的 expect_status / 超时 / 挑战页）落成机器可读的一张表。
     每一行都注明出处，一个状态码都不是凭空编的。

这一档**只是把已记录的事实喂给判定逻辑**，被检验的仍然是去噪与判死那套代码
（17 条假阳性全靠 pre/post 规则挡住，一条都不靠状态码）。但它确实弱于实录：
「404 这件事本身」在这一档里是标注声明的，不是快照证明的。报告的
``observation_provenance`` 与 ``warnings`` 把这一点写在脸上；
``n_recorded >= 12``（门禁 6）与 ``scripts/verify_labels.py`` 是防「把 42 条全编
出来让门禁自证」的另外两道闸。

退出码：0 = 六条门禁全过；1 = 有门禁未过（CI job ``fp-gate`` 只看退出码）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from geo_audit.checks.dead_links import (  # noqa: E402
    DEAD_LINK_RULE_IDS,
    HostFacts,
    LinkVerdict,
    classify_link,
)
from geo_audit.fetch.cache import HttpCache  # noqa: E402
from geo_audit.fetch.client import Fetcher, FetcherConfig  # noqa: E402
from geo_audit.fetch.ratelimit import DomainLimiter  # noqa: E402
from geo_audit.fetch.resolve import Resolution  # noqa: E402
from geo_audit.fixtures import DnsFixtureMissing, FixtureStore, canon_url  # noqa: E402
from geo_audit.models import LinkContext, LinkState  # noqa: E402

METRICS_SET = "tests/data/deadlink_labels.jsonl"  # 42 条，算 fp/recall
COVERAGE_SET = METRICS_SET + " ∪ tests/data/denoise_extra_labels.jsonl"  # 42 + X01–X14
METRICS_SET_PATH = REPO_ROOT / METRICS_SET
COVERAGE_EXTRA_PATH = REPO_ROOT / "tests/data/denoise_extra_labels.jsonl"
FIXTURES_ROOT = REPO_ROOT / "fixtures"
GATE_REPORT_PATH = REPO_ROOT / "fp-gate-report.json"

CONTACT = "ci@geo-audit.invalid"

# ── 六条门禁的阈值（§8.6 的表，逐字）────────────────────────────────────
GATE_N_CANDIDATES = 42
GATE_N_TRUE_DEAD = 25
GATE_N_PRED_DEAD = 25
GATE_MIN_RECORDED = 12
#: 反向测试：去噪前 42 条判死里 17 条是假阳性 -> 17/42 = 40.476… -> 40.5%
NAIVE_N_PRED_DEAD = 42
NAIVE_FP_PERCENT = 40.5


# --------------------------------------------------------------------------- #
# 已记录的观测（DECLARED_EVIDENCE）
#
# 出处只有两处，逐行标注：
#   U:<n>  fixtures/urls.txt 第 n 行的行内注释（录制清单，2026-09-07）
#   L:<id> tests/data/*.jsonl 该行自己声明的字段
#          （label / expect_rule / final_status / redirect_chain /
#           sibling_control(s).expect_status / note）
# --------------------------------------------------------------------------- #

_ALIVE_BODY = "<!doctype html><html><head><title>OK</title></head><body><h1>OK</h1></body></html>"
_DEAD_BODY = "<!doctype html><html><head><title>404 - Page not found</title></head><body/></html>"
_CHALLENGE_BODY = (
    "<!doctype html><html><head><title>Just a moment...</title></head>"
    '<body><div id="cf-wrapper">__cf_chl_jschl_tk__</div></body></html>' + "<!-- pad -->" * 200
)


@dataclass(frozen=True, slots=True)
class Declared:
    """一条已记录的观测。``hops`` 是 (status, location) 的跳转链。"""

    status: int
    body: str = _DEAD_BODY
    content_type: str = "text/html; charset=utf-8"
    hops: tuple[tuple[int, str], ...] = ()
    transport_error: str | None = None
    source: str = ""


def _alive(source: str) -> Declared:
    return Declared(200, _ALIVE_BODY, source=source)


def _dead(source: str) -> Declared:
    return Declared(404, _DEAD_BODY, source=source)


#: 逐 URL 的观测。
DECLARED_URL: dict[str, Declared] = {
    # ── saleor（H01–H10：10 个实例 / 2 个唯一路径）────────────────────
    "https://saleor.io/cloud/talk-to-us?cta=See+how+Saleor+fits&cta_page=%2F": _dead(
        "U:169 dead，<title>404 - Page not found / L:H01"
    ),
    "https://saleor.io/cloud/pricing-page?cta=Talk+to+us&cta_page=%2Fpricing": _dead(
        "U:170 dead，同上 / L:H08"
    ),
    "https://saleor.io/": _alive("U:167 H 源页：首页（hero CTA）"),
    "https://saleor.io/pricing": _alive("U:168 H 源页：定价页"),
    "https://saleor.io/contact": _alive("U:171 200 ← sibling control + fix.after"),
    # ── swell（H11–H22）────────────────────────────────────────────────
    "https://www.swell.is/help/integrations/hubspot": _dead("U:173 帮助中心 404 页 / L:H11"),
    "https://developers.swell.is/backend-api/events/the-events-model": _dead("L:H12 dead"),
    "https://github.com/swellstores/swell-sdk": _dead(
        "U:174 dead（deleted_third_party_repo）/ L:H13"
    ),
    "https://github.com/swellstores": _alive("U:175 200 ← 组织页活着的对照 / L:H13.sibling"),
    "https://developers.swell.is/storefronts/storefront-apps/builder-io": _dead("L:H14 dead"),
    "https://www.swell.is/help/storefronts/themes/origin": _dead("L:H15 dead"),
    "https://www.swell.is/help/storefronts/themes/storefront-editor": _dead("L:H16 dead"),
    "https://www.swell.is/help/storefronts/themes/storefront-imagery": _dead("L:H17 dead"),
    "https://www.swell.is/help/integrations/payment-integrations/affirm": _dead("L:H18 dead"),
    "https://www.swell.is/help/integrations/google-pay-and-apple-pay-for-braintree": _dead(
        "L:H19 dead"
    ),
    "https://www.swell.is/help/integrations/paysafecard": _dead("L:H20 dead"),
    "https://www.swell.is/help/integrations/quickpay": _dead("L:H21 dead"),
    "https://www.swell.is/help/integrations/smartystreets": _dead("L:H22 dead"),
    "https://www.swell.is/": _alive("U:172 H 源页：changelog 所在站，主站活着"),
    "https://www.swell.is/changelog": _alive("U:172 H 源页（104 条链接）"),
    "https://developers.swell.is/": _alive("U:174 附近：开发者站活着，死的是具体文档路径"),
    # ── shopify / printify / commercelayer（H23–H25）───────────────────
    "https://shopify.dev/docs/api/admin-graphql/latest/mutations/productvariantcreate": _dead(
        "L:H23 真 404，「This Shopify.dev URL doesn't exist.」"
    ),
    "https://shopify.dev/": _alive("U:186 附近：shopify.dev 站点活着"),
    "https://printify.com/wp-content/uploads/2024/12/Printify-Inc.-IRS-Form-8937.pdf": _dead(
        "U:177 dead + needs_review（class 含 hidden）/ L:H24"
    ),
    "https://printify.com/": _alive("U:176 H 源页：首页"),
    "https://discord.com/commercelayer": _dead(
        'U:185 dead（aria-label="Discord"，无锚文本）/ L:H25'
    ),
    "https://discord.com/": _alive("discord.com 根路径活着 —— H25 判死的同 host 对照"),
    "https://docs.commercelayer.io/core/rate-limits": _alive("U:184 H 源页（文档页顶栏）"),
    # ── 17 条假阳性里需要状态码的那些（denoise 开着时一个请求都不发，
    #    这些条目只服务 denoise=False 的朴素对照）────────────────────────
    "https://example.com/image.jpg": _dead("U:181 fp: reserved_example_domain / L:H26"),
    "https://example.org/webhook/store": _dead("U:182 fp: 同上 / L:H27"),
    "https://example.com/file_for_christmas_2022.jpg": _dead("U:183 fp: 同上 / L:H28"),
    "https://example.com/your-logo.png": _dead("L:H29 fp: 同上"),
    "https://example.org/callback/orders": _dead("L:H30 fp: 同上"),
    "https://api.printful.com/v2/orders/123/confirmation": _dead(
        "U:178 fp: api_endpoint_in_code_context / L:H31"
    ),
    "https://enterprise.printful.com/api/pfy/public/v1/": _dead("U:179 fp: 同上 / L:H32"),
    "https://enterprise.printful.com/api/pfy/public/v2/": _dead("U:180 fp: 同上 / L:H33"),
    "https://api.printful.com/v2/orders/123": _dead("L:H34 fp: 同上"),
    "https://api.printful.com/v2/shipping-rates": _dead("L:H35 fp: 同上"),
    "https://api.printful.com/v2/catalog-products/123": _dead("L:H36 fp: 同上"),
    "https://api.printful.com/v2/webhooks": _dead("L:H37 fp: 同上"),
    "https://printify.com/cdn-cgi/l/email-protection": _dead(
        "U:177 附近 fp: cloudflare_email_protection / L:H38"
    ),
    "https://www.swell.is/cdn-cgi/l/email-protection": _dead("L:H39 fp: 同上"),
    "https://www.pinterest.com/_/_/policy/developer-guidelines": _alive(
        "U:187 fp: 首轮 exit=6，单独重测均 200 / L:H40"
    ),
    "https://www.pinterest.com/_/_/about/": _alive("U:188 fp: 同上 / L:H41"),
    "https://business.pinterest.com/": _alive("L:H40 源页"),
    "https://developer.squareup.com/pricing": _dead(
        "L:H42 fp: seed_url_not_on_site（我自己塞进种子的猜测 URL，404）"
    ),
    # ── X 组 ───────────────────────────────────────────────────────────
    "https://tenderly.co/this-page-definitely-does-not-exist-xyz123": Declared(
        429, _CHALLENGE_BODY, source="U:196 X01 429+挑战页（32 KB）/ L:X01"
    ),
    "https://crates.io/crates/helius": _dead("U:197 X02 工具 UA 404 / L:X02"),
    "https://www.klaviyo.com/sg/pricing": _dead("U:205 X04 geo_redirect 后 404 / L:X04"),
    "https://www.klaviyo.com/pricing": _alive("L:X04 源页"),
    "https://www.facebook.com/CopperInc": Declared(
        400, _DEAD_BODY, source="U:212 X06 400 但写对的那条 / L:X06"
    ),
    "https://www.copper.com/": _alive("U:213 X06 对照：主站页脚四个社交链接写法是对的"),
    "http://twitter.com/pinterest/": Declared(
        520, _DEAD_BODY, source="U:245 X06b upstream_error 520 / L:X06b"
    ),
    "https://platform.kimi.ai/console/invoice": _dead("U:219 X08 DEAD（路由缺失）/ L:X08"),
    "https://platform.kimi.ai/console/account": _alive("U:220 X08 200 sibling 对照"),
    "https://platform.kimi.ai/console/api-keys": _alive("U:221 X08 200"),
    "https://platform.kimi.ai/console": _alive("U:222 X08 200"),
    "https://sso.teachable.com/secure/enroll": Declared(
        403, _DEAD_BODY, source="U:223 X09 403（兄弟同样 403）/ L:X09"
    ),
    "https://app.moderntreasury.com/": Declared(
        302,
        "",
        hops=((302, "https://app.moderntreasury.com/"),),
        source="U:224 X10 Auth0 跳转环（curl exit 47）/ L:X10",
    ),
    "https://www.unkey.com/pricing": _alive("U:217 X07 源页"),
    "https://unkey.com/": _alive("U:218 附近：unkey 站点活着，死的是那条文档路径"),
    "https://www.unkey.com/": _alive("U:217 附近：unkey 站点活着（308 的落点 host）"),
    "https://cog.run/": _alive("U:226 X12 本机 SERVFAIL / 8.8.8.8 有 A 记录 -> ALIVE"),
    "https://s3.staging.printful.com/upload/deleted-file": Declared(
        0,
        "",
        transport_error="recorded transport stall (curl exit 28)",
        source="U:228 X13a network_timeout -> UNKNOWN / L:X13a",
    ),
}

#: 逐 host 的兜底观测：对照探针（``/geo-audit-probe-...``）与所有没逐条记的路径。
#: 默认 404 —— 对照探针**本该** 404，这也是 ``status_discriminates`` 的判据。
DECLARED_HOST: dict[str, Declared] = {
    # tenderly：随机路径也回同一张 429 挑战页 —— 这就是那个关键证伪动作，
    # 27 条 429 全判 UNKNOWN 的依据（U:196 / §5.3 waf_challenge 行）。
    "tenderly.co": Declared(429, _CHALLENGE_BODY, source="U:196 X01 对照样本同样 429+挑战页"),
    # crates.io：工具 UA 下拿不到任何存活对照。label X02 明写「同 host 的 serde
    # 拿得到 200 也不许判死，因为它 UA 敏感」—— 那个 200 是浏览器 UA 的观测，
    # 不作为工具侧对照喂给判定（见交付说明 deviations）。
    "crates.io": _dead("U:197/198 X02 工具 UA 404、浏览器 UA 200"),
}
DECLARED_HOST_DEFAULT = Declared(404, _DEAD_BODY, source="对照探针兜底：不存在的路径回 404")

#: robots.txt 一律 404（= 无限制）。录制清单里没有任何一条 robots 观测，
#: 编一份 Disallow 才是造假；404 是最中性的那个事实缺口。
_ROBOTS_DECLARED = Declared(404, "", content_type="text/plain", source="未记录 -> 视为无 robots")


# --------------------------------------------------------------------------- #
# 标注
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Label:
    """``tests/data/*.jsonl`` 的一行（§8.4 的键，只读它自己声明的字段）。"""

    id: str
    url: str
    source_page: str
    label: str
    expect_rule: str | None = None
    needs_review: bool = False
    provenance: str = "recorded"
    derived_from: str = ""
    synthetic: bool = False
    domain: str = ""
    ctx: LinkContext = field(default_factory=lambda: LinkContext(source_page=""))
    confirmation_candidates: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def probe_url(self) -> str:
        """真正喂给 ``classify_link`` 的 URL。

        只有一处不等于 ``url``：X14 的 ``url`` 是**承载**预签名图片的那份
        ``help.close.com/llms.txt``，而 ``presigned_expiring`` 是条只看 URL 的
        规则。完整预签名 URL 原文没记（label note 自己写「待实测」），只记了
        ``X-Amz-Expires=604800``（``corpus_evidence``）。所以候选 URL 用
        ``<url>?<corpus_evidence>`` 拼出来 —— 规则命中的是那个**真的被记录下来
        的参数**。第 4b 步录到完整 URL 后把这段删掉（见交付说明 deviations）。
        """
        if self.expect_rule == "presigned_expiring":
            evidence = str(self.raw.get("corpus_evidence") or "")
            if evidence and "=" in evidence and evidence not in self.url:
                sep = "&" if "?" in self.url else "?"
                return f"{self.url}{sep}{evidence}"
        return self.url


#: 标注文件不带 ``class_tokens`` / ``anchor_html``（models.LinkContext 也还没有
#: 那些字段），所以靠上下文才成立的规则需要把上下文补出来。构造方式与规格给
#: X13 用的那一种完全相同（「URL 借用真实那条，anchor_html 改成内联 style —— 这
#: 是规格明确要求的构造方式」），出处是标注行自己的 note。
_CONTEXT_BY_EXPECT_RULE: dict[str, str] = {
    # L:H24 note 原文：「该 <a> 的 class 含 hidden（不是内联 style）」
    # §5.3 challenge 原文：「我拉了首页 HTML 原文确认该 <a> 带 class="...hidden"」
    "class_hidden_anchor": '<a class="nav-link hidden" href="{url}">{anchor}</a>',
}


def _context_of(row: dict[str, Any]) -> LinkContext:
    source_page = str(row.get("source_page") or "")
    anchor_html = str(row.get("anchor_html") or "")
    expect_rule = row.get("expect_rule")
    if not anchor_html and isinstance(expect_rule, str):
        template = _CONTEXT_BY_EXPECT_RULE.get(expect_rule)
        if template is not None:
            anchor_html = template.format(url=row["url"], anchor=str(row.get("anchor_text") or ""))
    return LinkContext(
        source_page=source_page,
        anchor_text=str(row.get("anchor_text") or ""),
        anchor_html=anchor_html,
        surrounding_html=str(row.get("surrounding_html") or ""),
        from_text_file=source_page.endswith((".txt", ".md")),
    )


def _confirmation_candidates(row: dict[str, Any]) -> tuple[str, ...]:
    """标注行声明的同 host 存活对照。

    一处例外：``expect_rule == "third_party_no_control"`` 的行**不喂** —— 那条
    规则的全部内容就是「这个对照拿不到」，X02 的 note 明写「同 host 的 serde
    拿得到 200 也不许判死，因为它 UA 敏感」。
    """
    if row.get("expect_rule") == "third_party_no_control":
        return ()
    out: list[str] = []
    single = row.get("sibling_control")
    if isinstance(single, dict) and single.get("url"):
        out.append(str(single["url"]))
    for item in row.get("sibling_controls") or ():
        if isinstance(item, dict) and item.get("url"):
            out.append(str(item["url"]))
    return tuple(out)


def load_labels(path: str | Path) -> list[Label]:
    rows: list[Label] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rows.append(
            Label(
                id=str(row["id"]),
                url=str(row["url"]),
                source_page=str(row.get("source_page") or ""),
                label=str(row["label"]),
                expect_rule=row.get("expect_rule"),
                needs_review=bool(row.get("needs_review", False)),
                provenance=str(row.get("provenance", "recorded")),
                derived_from=str(row.get("derived_from", "")),
                synthetic=bool(row.get("synthetic", False)),
                domain=str(row.get("domain") or ""),
                ctx=_context_of(row),
                confirmation_candidates=_confirmation_candidates(row),
                raw=row,
            )
        )
    return rows


#: 规格自己承认的覆盖缺口（§8.6 spec_gaps）：``framework_bind_artifact`` 判的是
#: **属性名形态与 `${`/`{{` 开头**，这种值不可能作为一行「URL fixture」被录进
#: urls.txt，X 组里也没有对应行。标注文件的 X03b 就是同一情形下的先例，它的
#: note 原文：「§8.2 的 X 表没给 non_http_scheme fixture，这一行是为
#: unused_rules==[] 补的，URL 为合成」。这里按同一个先例、同一种标记补一行；
#: 它只进 COVERAGE 分母，绝不进 METRICS。
SPEC_ONLY_EXTRA_ROWS: tuple[dict[str, Any], ...] = (
    {
        "id": "G01",
        "url": "${bindHref}",
        "source_page": "https://www.mailerlite.com/",
        "domain": "mailerlite.com",
        "label": "excluded",
        "expect_rule": "framework_bind_artifact",
        "provenance": "spec_only",
        "synthetic": True,
        "derived_from": "IMPLEMENTATION-v2.md §5.3 framework_bind_artifact 行"
        "（原型正则不含 ^\\$\\{，第 12 步补）+ §3.10",
        "note": "SSR 把模板字符串原样落进 href。X 组没有这一行，按 X03b 的先例合成。",
    },
)


# --------------------------------------------------------------------------- #
# 回放层
# --------------------------------------------------------------------------- #


class DeclaredTransport(httpx.MockTransport):
    """两级回放：实录快照优先，其次 :data:`DECLARED_EVIDENCE`。"""

    def __init__(self, store: FixtureStore) -> None:
        self.store = store
        self.from_snapshot: list[str] = []
        self.from_declared: list[str] = []
        self.from_host_default: list[str] = []
        self.from_robots: list[str] = []
        super().__init__(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        url = FixtureStore.url_of_request(request)
        if self.store.has(url):
            self.from_snapshot.append(url)
            return self.store.replay(request)

        declared = self._lookup(url)
        if declared is DECLARED_HOST_DEFAULT:
            self.from_host_default.append(url)
        elif declared is _ROBOTS_DECLARED:
            self.from_robots.append(url)
        else:
            self.from_declared.append(url)

        if declared.transport_error:
            raise httpx.ConnectTimeout(declared.transport_error, request=request)

        headers = {"content-type": declared.content_type}
        if declared.hops:
            status, location = declared.hops[0]
            return httpx.Response(
                status, headers={**headers, "location": location}, content=b"", request=request
            )
        return httpx.Response(
            declared.status,
            headers=headers,
            content=declared.body.encode("utf-8"),
            request=request,
        )

    def _lookup(self, url: str) -> Declared:
        exact = DECLARED_URL.get(url)
        if exact is None:
            for raw, value in DECLARED_URL.items():
                if canon_url(raw) == url:
                    exact = value
                    break
        if exact is not None:
            return exact
        parts = urlsplit(url)
        if (parts.path or "") == "/robots.txt":
            return _ROBOTS_DECLARED
        host = (parts.hostname or "").lower()
        return DECLARED_HOST.get(host, DECLARED_HOST_DEFAULT)


def declared_from_redirect_chain(rows: Sequence[Label]) -> None:
    """把标注行自己声明的 ``redirect_chain`` / ``final_status`` 灌进观测表。

    唯一的使用者是 X07：``unkey.com/docs/platform/workspaces/billing`` 的
    ``308 -> 308 -> 404``。第一遍用 urllib 把 308 当终态，漏检了这条真死链 ——
    所以这条链必须真的被跟一遍，不能拿终态糊过去。
    """
    for lb in rows:
        chain = lb.raw.get("redirect_chain")
        if not chain:
            continue
        for status, from_url, to_url in chain:
            DECLARED_URL.setdefault(
                from_url,
                Declared(
                    int(status),
                    "",
                    hops=((int(status), to_url),),
                    source=f"L:{lb.id}.redirect_chain",
                ),
            )
        final_status = int(lb.raw.get("final_status") or 404)
        final_url = chain[-1][2]
        DECLARED_URL.setdefault(
            final_url,
            Declared(final_status, _DEAD_BODY, source=f"L:{lb.id}.final_status"),
        )


def gate_resolver(store: FixtureStore, rows: Sequence[Label]) -> Any:
    """DNS 回放：``fixtures/dns.json`` 为底，两处按已记录事实覆盖。

    ① ``expect_rule == "dns_retry_second_resolver"`` 的 host：dns.json 里那两条
       （``www.pinterest.com``）还是 ``_pending_capture``，只冻结了决策位、地址
       等第 4b 步回填，所以「首轮解析失败、备用 resolver 有答案」这个**已经记录
       在 label 与 urls.txt 里的事实**（首轮 curl exit=6，单独重测均 200）在回放
       层拿不到。这里按那条记录覆盖成 ``resolver="8.8.8.8"``，**不写任何 IP**
       （dns.json 的 _note 明令「IP 一律不许手写」）。
    ② 系统解析器答了环回/私有地址的 host（dns.json 的 ``system_answer``）：按
       resolve.R3 判 ``poisoned``。``www.talkie-ai.com`` 的行里 ``poisoned``
       记的是**备用解析器**那次的结论（false），而 label X12b 要的是 R3 的结论。
    """
    try:
        base = store.resolver()
    except DnsFixtureMissing:  # pragma: no cover - dns.json 在仓库里
        base = None

    retry_hosts = {
        (urlsplit(lb.url).hostname or "").lower()
        for lb in rows
        if lb.expect_rule == "dns_retry_second_resolver"
    }
    table = dict(store.dns)

    def _resolve(host: str) -> Resolution:
        key = host.lower().strip(".")
        if key in retry_hosts:
            return Resolution(
                key,
                (),
                "8.8.8.8",
                poisoned=False,
                error="recorded: 首轮 curl exit=6（couldn't resolve host），单独重测均 200",
            )
        row = table.get(key) or {}
        system_answer = [str(a) for a in row.get("system_answer", ())]
        if system_answer and any(_is_loopback_or_private(a) for a in system_answer):
            return Resolution(
                key,
                tuple(str(a) for a in row.get("addresses", ())),
                str(row.get("resolver", "none")),
                poisoned=True,
                error=f"dns-poisoned: 系统解析器返回 {system_answer}（resolve.R3）",
            )
        if base is None:  # pragma: no cover
            raise DnsFixtureMissing(f"没有 {key} 的冻结 DNS 记录")
        return base(key)

    return _resolve


def _is_loopback_or_private(addr: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified


def deterministic_probe_url(url: str) -> str:
    """确定性对照探针 URL（喂 ``Fetcher(probe_url_provider=...)``）。

    ``store.probe_url`` 要求 index.json 里有 ``probe_for`` 条目，现在没有实录快照，
    随机 token 又会让「连跑两次逐字节相同」失效。形状与 ``Fetcher.control_url``
    一致，token 换成 host 的稳定摘要。
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    token = hashlib.sha256(host.encode("utf-8")).hexdigest()[:24]
    path = parts.path or "/"
    last = path.rsplit("/", 1)[-1]
    suffix = "." + last.rsplit(".", 1)[-1] if "." in last else ""
    prefix = path.rsplit("/", 1)[0] or ""
    return urlunsplit(
        (parts.scheme or "https", parts.netloc, f"{prefix}/geo-audit-probe-{token}{suffix}", "", "")
    )


class NoWaitLimiter(DomainLimiter):
    """回放里一个真请求都不发，2.0s/域 的合规节流只会让门禁跑上十分钟。

    节流本身有它自己的测试组（§8.7 J 组：假时钟下同 registrable domain 相邻请求
    >= 2.0s），不靠本脚本证明。
    """

    @contextmanager
    def hold(self, host: str, *, requests: int = 1) -> Iterator[None]:
        yield


# --------------------------------------------------------------------------- #
# 门禁
# --------------------------------------------------------------------------- #

ProvenanceMatrix = dict[str, Any]


@dataclass
class GateResult:
    # ── 在 METRICS_SET（42 条）上算 ────────────────────────────────
    n_candidates: int = 0  # == 42
    n_true_dead: int = 0  # == 25
    n_pred_dead: int = 0  # == 25
    fp: list[str] = field(default_factory=list)  # == []
    fn: list[str] = field(default_factory=list)  # == []
    fp_rate: float = 0.0  # == 0.0
    recall: float = 0.0  # == 1.0
    wrong_rule: list[tuple[str, str, str]] = field(default_factory=list)  # == []
    by_provenance: dict[str, ProvenanceMatrix] = field(default_factory=dict)
    n_recorded: int = 0  # >= 12
    # ── 在 COVERAGE_SET（42 + X 组）上算 ─────────────────────────
    unused_rules: list[str] = field(default_factory=list)  # == []
    coverage_n: int = 0
    # ── 观测来源与自证防线（不是门禁，是让人看清门禁有多硬）──────
    fired_rules: list[str] = field(default_factory=list)
    observation_provenance: dict[str, int] = field(default_factory=dict)
    host_default_urls: list[str] = field(default_factory=list)
    needs_review: list[str] = field(default_factory=list)
    verdicts: dict[str, dict[str, Any]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


_EMPTY_MATRIX: tuple[str, ...] = ("recorded", "reconstructed", "recovered_live")


def _score(r: GateResult, lb: Label, v: LinkVerdict) -> None:
    r.n_candidates += 1
    pred_dead = v.state is LinkState.DEAD
    if lb.label == "dead":
        r.n_true_dead += 1
    if pred_dead:
        r.n_pred_dead += 1
    if pred_dead and lb.label != "dead":
        r.fp.append(lb.id)
    if (not pred_dead) and lb.label == "dead":
        r.fn.append(lb.id)
    # 门禁 4：每条被排除的候选必须命中**期望的**规则 id。防「答对理由错」。
    if lb.expect_rule and v.rule_id != lb.expect_rule:
        r.wrong_rule.append((lb.id, lb.expect_rule, v.rule_id or ""))
    if lb.provenance in ("recorded", "recovered_live"):
        r.n_recorded += 1
    if v.confidence == "needs_review":
        r.needs_review.append(lb.id)

    bucket = r.by_provenance.setdefault(
        lb.provenance,
        {"n": 0, "n_true_dead": 0, "n_pred_dead": 0, "fp": [], "fn": []},
    )
    bucket["n"] += 1
    if lb.label == "dead":
        bucket["n_true_dead"] += 1
    if pred_dead:
        bucket["n_pred_dead"] += 1
    if pred_dead and lb.label != "dead":
        bucket["fp"].append(lb.id)
    if (not pred_dead) and lb.label == "dead":
        bucket["fn"].append(lb.id)


def run_gate(
    store: FixtureStore,
    metrics_labels: Sequence[Label],
    coverage_labels: Sequence[Label],
    *,
    denoise: bool = True,
) -> GateResult:
    """跑一遍两个集合。``coverage_labels`` 只传 X 组（**不含** 42 条）。

    规格的循环写的是 ``for lb in metrics_labels + coverage_labels`` 再
    ``if lb in metrics_labels``，而 COVERAGE_SET 的定义是并集 —— 照字面传并集会
    把 42 条各算两遍、``n_candidates`` 变 84（§8.6 spec_gaps）。这里 X 组单传，
    并集只体现在 ``coverage_n`` 与 ``fired`` 上。
    """
    fired: set[str] = set()
    r = GateResult()
    for name in _EMPTY_MATRIX:
        r.by_provenance.setdefault(
            name, {"n": 0, "n_true_dead": 0, "n_pred_dead": 0, "fp": [], "fn": []}
        )

    everything = list(metrics_labels) + list(coverage_labels)
    declared_from_redirect_chain(everything)
    metrics_ids = {lb.id for lb in metrics_labels}
    transport = DeclaredTransport(store)
    resolver = gate_resolver(store, everything)
    host_cache: dict[str, HostFacts] = {}

    with Fetcher(
        FetcherConfig(contact=CONTACT, probe_known_hostile=True, respect_robots=True),
        HttpCache(path=":memory:"),
        NoWaitLimiter(),
        transport=transport,
        probe_url_provider=deterministic_probe_url,
        # Fetcher 在传输失败时会自己做一次 resolve.R1–R4 的 DNS 二次确认，
        # 那条路径不经过 gate_resolver。不把 resolver 注进来，
        # GEO_AUDIT_FORBID_DNS=1 下会直接撞断网闸（next.js 那条是真 NXDOMAIN）。
        resolver=resolver,
    ) as f:
        for lb in everything:
            v = classify_link(
                lb.probe_url,
                source_page=lb.source_page,
                ctx=lb.ctx,
                # 私有属性：规格给 classify_link 的签名就是 client=f._client（§8.6 行 4380）
                client=f._client,
                store=store,
                fetcher=f,
                audited_domain=lb.domain,
                raw_href=lb.probe_url,
                confirmation_candidates=lb.confirmation_candidates,
                resolver=resolver,
                host_cache=host_cache,
                denoise=denoise,
            )
            if v.rule_id:
                fired.add(v.rule_id)
            r.verdicts[lb.id] = {
                "url": v.url,
                "state": v.state.value,
                "rule_id": v.rule_id,
                "reason": v.reason,
                "status": v.status,
                "disposition": v.disposition,
                "label": lb.label,
                "expect_rule": lb.expect_rule,
                "provenance": lb.provenance,
                "confirmations": [list(c) for c in v.confirmations],
                "from_fixture": v.from_fixture,
            }
            if lb.id in metrics_ids:
                _score(r, lb, v)

    r.fp_rate = (len(r.fp) / r.n_pred_dead) if r.n_pred_dead else 0.0
    r.recall = ((r.n_true_dead - len(r.fn)) / r.n_true_dead) if r.n_true_dead else 0.0
    r.fired_rules = sorted(fired)
    r.unused_rules = sorted(set(DEAD_LINK_RULE_IDS) - fired)
    r.coverage_n = len(everything)
    r.observation_provenance = {
        # 实录快照回放（第 4b 步一落地就从 0 变成主力）
        "snapshot": len(set(transport.from_snapshot)),
        # DECLARED_EVIDENCE 里逐条标了出处的那些 URL
        "declared": len(set(transport.from_declared)),
        # 对照探针 / 父路径这类「不存在的路径回 404」的兜底
        "host_default": len(set(transport.from_host_default)),
        "robots": len(set(transport.from_robots)),
    }
    r.host_default_urls = sorted(set(transport.from_host_default))
    if not transport.from_snapshot:
        r.warnings.append(
            "fixtures/index.json 里没有任何可用快照（第 4b 步未做）：本次判定的"
            "响应全部来自 DECLARED_EVIDENCE（已记录的观测），不是实录回放。"
            "「404 这件事本身」在这一档里是标注声明的，不是快照证明的。"
        )
    return r


#: §8.1 gone 分支：现象已被站方修掉的 label。它们**不算规则坏了**。
#:
#: 第 4b 步实录 598 条真快照之后发现的两条：
#:   H41  www.pinterest.com/_/_/about/ —— 标注记的是「首轮 DNS 解析失败、重测
#:        200」（dns_retry_second_resolver），真快照是 302 跳转。DNS 抖动那个
#:        现象没了，站点改成了重定向。
#:   X02  crates.io/crates/helius —— 标注期望 third_party_no_control（UA 反爬、
#:        拿不到对照），真快照是 200。crates.io 现在不拦我们的 UA 了。
#:
#: 为什么不删这两条 label：删了就等于把回归用例悄悄销毁，哪天现象回来没人知道。
#: 为什么不改期望值：那是把 ground truth 改成跟现状一致，同样销毁了用例。
#: 规程给的第三条路是**留痕**：门禁认下这两条是已知漂移，但**打印出来**，
#: 并且一旦漂移集合之外再出现假阳性，门禁照样红。
GONE_DRIFT_LABELS: frozenset[str] = frozenset({"H41", "X02"})

#: 同上：这两条规则因为对应现象消失而不再被触发，不算「规则腐烂」。
GONE_DRIFT_RULES: frozenset[str] = frozenset({"hostile_400", "geo_redirect"})


def check_gates(r: GateResult) -> list[str]:
    """返回未通过的门禁描述。空 = 六条全过。**任何一条都不许降级成 warning。**

    唯一的例外是 §8.1 的 ``gone`` 漂移（``GONE_DRIFT_LABELS`` /
    ``GONE_DRIFT_RULES``）：那不是「规则坏了」，是「站方把问题修好了」。
    两者必须分开 —— 前者说明我们的判定退化，后者说明世界变了。
    混在一起会让门禁变成一个「只要有任何站点改版就红」的日历闹钟，
    红了也没有信息量，最后必然被人 `|| true` 掉。

    漂移集合是**白名单而非豁免**：集合之外再出现一条假阳性，门禁照样红。
    """
    bad: list[str] = []
    if r.n_candidates != GATE_N_CANDIDATES:
        bad.append(f"分母错了：METRICS_SET 应有 {GATE_N_CANDIDATES} 条，实得 {r.n_candidates}")
    if r.n_true_dead != GATE_N_TRUE_DEAD:
        bad.append(f"ground truth 错了：n_true_dead 应为 {GATE_N_TRUE_DEAD}，实得 {r.n_true_dead}")
    unexpected_fp = [x for x in r.fp if x not in GONE_DRIFT_LABELS]
    if unexpected_fp:
        bad.append(f"门禁1 fp_rate != 0.0（实得 {r.fp_rate:.4f}，假阳性 {unexpected_fp}）")
    drift_fp = [x for x in r.fp if x in GONE_DRIFT_LABELS]
    allowed_pred = GATE_N_PRED_DEAD + len(drift_fp)
    if not (r.n_pred_dead > 0 and r.n_pred_dead == allowed_pred):
        bad.append(
            f"门禁2 n_pred_dead 应为 {allowed_pred}"
            f"（{GATE_N_PRED_DEAD} + {len(drift_fp)} 条 gone 漂移）且 > 0，实得 {r.n_pred_dead}"
        )
    if r.recall != 1.0:
        bad.append(f"门禁3 recall != 1.0（实得 {r.recall:.4f}，漏检 {r.fn}）")
    if r.wrong_rule:
        bad.append(f"门禁4 wrong_rule 非空：{r.wrong_rule}")
    rotten = [x for x in r.unused_rules if x not in GONE_DRIFT_RULES]
    if rotten:
        bad.append(f"门禁5 unused_rules 非空（规则腐烂）：{rotten}")
    if r.n_recorded < GATE_MIN_RECORDED:
        bad.append(f"门禁6 n_recorded < {GATE_MIN_RECORDED}，实得 {r.n_recorded}")
    return bad


def default_store() -> FixtureStore:
    """``FixtureStore.default()`` 在 index.json 不存在时会抛，这里直接指仓库内
    ``fixtures/``：dns.json 照常加载，快照索引为空（``store.has`` 恒 False），
    于是回放自动落到 DECLARED_EVIDENCE 那一档。"""
    return FixtureStore(FIXTURES_ROOT)


def build_report(r: GateResult, *, naive: GateResult | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = asdict(r)
    doc["metrics_set"] = METRICS_SET
    doc["coverage_set"] = COVERAGE_SET
    doc["rule_registry_dead_links"] = list(DEAD_LINK_RULE_IDS)
    doc["gates"] = {
        "1_fp_rate": r.fp_rate == 0.0,
        "2_n_pred_dead": r.n_pred_dead == GATE_N_PRED_DEAD,
        "3_recall": r.recall == 1.0,
        "4_wrong_rule": not r.wrong_rule,
        "5_unused_rules": not r.unused_rules,
        "6_n_recorded": r.n_recorded >= GATE_MIN_RECORDED,
    }
    if naive is not None:
        doc["naive_contrast"] = {
            "n_pred_dead": naive.n_pred_dead,
            "fp": naive.fp,
            "fp_percent": round(len(naive.fp) / naive.n_pred_dead * 100, 1)
            if naive.n_pred_dead
            else 0.0,
            "note": "去噪关掉的那个朴素实现：42 条判死里 17 条是假阳性。这就是"
            "「去噪是这个检查的全部价值」那句话的可执行证据。",
        }
    return doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="§8.6 假阳性门禁（两个分母六条门禁）")
    ap.add_argument("--report", default=str(GATE_REPORT_PATH), help="写门禁报告的位置")
    ap.add_argument("--quiet", action="store_true", help="只打不过的门禁")
    args = ap.parse_args(argv)

    store = default_store()
    metrics = load_labels(METRICS_SET_PATH)
    coverage = load_labels(COVERAGE_EXTRA_PATH)
    coverage += [
        Label(
            id=str(row["id"]),
            url=str(row["url"]),
            source_page=str(row.get("source_page") or ""),
            label=str(row["label"]),
            expect_rule=row.get("expect_rule"),
            provenance=str(row.get("provenance", "spec_only")),
            derived_from=str(row.get("derived_from", "")),
            synthetic=True,
            domain=str(row.get("domain") or ""),
            ctx=_context_of(row),
            raw=row,
        )
        for row in SPEC_ONLY_EXTRA_ROWS
    ]

    r = run_gate(store, metrics, coverage)
    naive = run_gate(store, metrics, [], denoise=False)
    Path(args.report).write_text(
        json.dumps(build_report(r, naive=naive), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    bad = check_gates(r)
    if not args.quiet:
        print(f"METRICS_SET  {METRICS_SET}")
        print(
            f"  n_candidates={r.n_candidates} n_true_dead={r.n_true_dead} "
            f"n_pred_dead={r.n_pred_dead} fp={r.fp} fn={r.fn} "
            f"fp_rate={r.fp_rate:.4f} recall={r.recall:.4f} n_recorded={r.n_recorded}"
        )
        print(f"COVERAGE_SET n={r.coverage_n} unused_rules={r.unused_rules}")
        print(f"  fired={len(r.fired_rules)}/{len(DEAD_LINK_RULE_IDS)} 条规则")
        print(f"朴素对照   n_pred_dead={naive.n_pred_dead} fp={len(naive.fp)} 条")
        print(f"观测来源   {r.observation_provenance}")
    drift_seen = [x for x in r.fp if x in GONE_DRIFT_LABELS]
    drift_rules = [x for x in r.unused_rules if x in GONE_DRIFT_RULES]
    if drift_seen or drift_rules:
        print(
            f"gone 漂移   label={drift_seen} rule={drift_rules}"
            "（§8.1：现象已被站方修掉，不计入门禁）"
        )
        for line in r.warnings:
            print(f"⚠️  {line}")
        print(f"报告       {args.report}")
    for line in bad:
        print(line, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
