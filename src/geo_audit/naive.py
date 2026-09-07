"""§4.5 朴素对照 —— 随包发布的朴素参照实现，**纯换算器**。

这个模块是产品的核心卖点，不是彩蛋。软 404 会让 llms.txt 的采纳率**虚高**、
403/429 会让它**虚低**，两个方向都得处理（§4.1:1937）。规格记下来的量级是
**软 404 15/72 = 20.8%**（16 个位置 / 15 个域，§1.1:36 + A10:4482）：这些位置
`/llms.txt` 返回 200 + text/html，只看最终状态码的实现一律读成「已采纳」。
所以报告里每条 finding 都要能并排展示「一个只探根路径的工具会得出什么结论」。

（第 14 步任务书另给了一组「朴素读成 76%、真实 60%，50 个域名里 8 个软 404」的
口径。规格全文与 `corpus/feature-raw.json` 里都查不到这三个数，**待核**；本文件
的行为不依赖它们，只依赖上面那条已记录的量级。）

**硬约束（卡点 A15'，§4.5:2382-2394 / §10 A15':4589）**：本模块

* **不持有 client、不发任何请求**；
* 只吃我们**已经抓到的那一批响应**重新读一遍，所以对照表是两个实现在**同一批
  响应**上的并排读数，而不是对一个假想对手的推算；
* `--naive-only` 因此也不额外打请求。

自证方式（第 14 步验收）：用 HTTP 客户端名、打开 URL 的 stdlib 函数名、按键取值的
方法名、以及抓取字样这四类关键词 grep 本文件，应当**零命中**。所以本文件刻意不
import 任何客户端、不调用 `dict` 的按键取值方法、也不引用证据结构里那个带抓取时刻
字样的字段名 —— 连注释与 docstring 里都不写这些字面量，好让那条 grep 的输出干净到
没有例外要解释。对应用例：`tests/test_naive.py::test_source_has_no_http_call`。

**行来源**（§4.5:2400-2405）：`Stage.DISCOVERY` / `INDEX_FILE` / `FULLTEXT` 三段的
每一个 Position 各一行。④⑤⑥ 三段不进这张表 —— 朴素实现连「索引里列的链接要不要
验」这个问题都不问，并排展示会变成我们自说自话；死链侧的差异化用另一个口径
（`counts.naive_dead_count`，见本文件末尾的 :func:`naive_dead_count`）。
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Literal, Protocol
from urllib.parse import urlsplit

from .models import Evidence, HttpResponse, NaiveContrast, SiteMap, Stage, Status

# --------------------------------------------------------------------------- #
# 文案常量
#
# 规格（§2.6:1000-1002）只给了两条字面量：「已采纳（200）」与
# 「未采纳（没探这个位置）」。朴素实现**探过但拿到 404/403/500** 的那些位置该印
# 什么、以及入口发现段该印什么，规格全文没给（见交付说明 spec_gaps）。这里按
# 「前缀承载语义」的方式补齐：`_conclusions_differ` 只认「已采纳」/「未采纳」两个
# 前缀，其余一律不参与对错判定。
# --------------------------------------------------------------------------- #

#: 「朴素说这个位置采纳了」。`_conclusions_differ` 的假阳分支认这个前缀。
ADOPTED_PREFIX = "已采纳"
#: 「朴素说这个位置没采纳」。`_conclusions_differ` 的假阴分支认这个前缀。
NOT_ADOPTED_PREFIX = "未采纳"

#: §2.6:1002 字面量。朴素探测集之外的位置固定印这句 —— 假阴方向的差异化就靠它。
CONCLUSION_NOT_PROBED = f"{NOT_ADOPTED_PREFIX}（没探这个位置）"
#: 响应没记到（例如扫描被 Ctrl-C 打断）时的读数。既不算已采纳也不算未采纳。
CONCLUSION_NO_RESPONSE = "判不了（没有抓到响应）"
#: 入口发现段：朴素实现往这个 host 打过请求（它那两条根路径就打在这儿）。
CONCLUSION_HOST_TOUCHED = "它往这个 host 打过请求（只打了两条根路径）"
#: 入口发现段：朴素实现从没往这个 host 打过请求（它不做子域发现）。
CONCLUSION_HOST_UNTOUCHED = "它从没往这个 host 打过请求"

#: §4.5:2427 字面量。
METHOD_NOT_IN_SET = "不在朴素探测集内"
#: §4.5:2418 字面量模板。
METHOD_PROBED = "GET {url}，跟随跳转，只看最终状态码"

WHY_DISCOVERY = (
    "入口发现段不进「采纳 / 未采纳」的对错判定：朴素实现在这一段上根本不下结论，"
    "判它对错就是我们自说自话。它没碰过的 host 见「它从没往这个 host 打过请求」那几行。"
)
WHY_NAIVE_GOT_IT_RIGHT = (
    "朴素实现已经在根路径上拿到了一份真文件，它对这个站给出的「已采纳」本来就是对的；"
    "这个位置它没探到，但不改变结论，所以不计读错。"
)

#: §0.4 约束二（:65）+ §10 A34（:4513）要求所有报告 HTML 都含这句固定措辞。
#: 报告里**不许**写「任何现成工具都会给出错的答案」—— 实测从未跑过任何现成工具做对照。
NAIVE_FIXED_PHRASE = "只探根路径、不做对照探测的实现"
#: §6.1:3034 固定措辞。
HEADLINE_WRONG = NAIVE_FIXED_PHRASE + "，会在你的 {n} 个位置上读错"
#: 零 divergence 时翻成正向（第 14 步验收：modal 0 行 diverges 且文案要翻正向）。
#: 措辞刻意避开禁词表（§6.5:3226 的「没有问题」/「一切正常」/「完美」/「满分」）。
HEADLINE_CLEAN = NAIVE_FIXED_PHRASE + "，在这个站上没读错"

#: 本文件自带的**最小**禁词表。完整表在 §6.5:3222-3226 的 `render.py::_BANNED_WORDS`
#: （第 15a 步的文件，不是本文件）。这里只留本模块自己产出的文案可能踩到的那几条，
#: 外加 §0.4:65 明令禁止的两句「任何现成工具」/「所有工具」。
#: **将来要合并**：两份表必须收敛成一份，见交付说明 spec_gaps。
NAIVE_BANNED_WORDS: tuple[str, ...] = (
    "恭喜",
    "没有问题",
    "一切正常",
    "完美",
    "满分",
    "任何现成工具",
    "所有工具",
)


def banned_word_hits(text: str) -> tuple[str, ...]:
    """返回 ``text`` 命中的禁词（按 :data:`NAIVE_BANNED_WORDS` 的顺序）。纯查询。"""
    return tuple(w for w in NAIVE_BANNED_WORDS if w in text)


def assert_no_banned_words(*texts: str) -> None:
    """本模块自己产出的文案的自检闸。命中就炸，别等渲染期。"""
    hits = tuple(dict.fromkeys(h for t in texts for h in banned_word_hits(t)))
    if hits:
        raise AssertionError(f"朴素对照文案出现禁词：{list(hits)}（见附录 B）")


class PositionLike(Protocol):
    """换算器需要的 Position 字段，写成结构化协议。

    §2.9 的 ``Position`` **目前不在** ``models.py`` 里（那里只有 ``PositionSeed``，
    而 seed 没有 ``evidence`` / ``control`` 两个字段，正是本模块要读的）。铁律禁止
    本步往 models.py 加类，A6 也禁止在别处重定义同名类，所以这里只声明「我读哪几个
    字段」。第 16 步的真 ``Position``（stage / probe_url / status / detail /
    evidence / control 全都有）天然满足本协议，届时把类型注解换掉即可。
    """

    @property
    def stage(self) -> Stage: ...

    @property
    def probe_url(self) -> str: ...

    @property
    def status(self) -> Status: ...

    @property
    def detail(self) -> str: ...

    @property
    def evidence(self) -> Evidence | None: ...

    @property
    def control(self) -> Evidence | None: ...


def _conclusions_differ(naive_conclusion: str, real_status: Status, actual: str) -> bool:
    """朴素说「已采纳」而真实 status 不是 PASS  -> True（假阳方向）
    朴素说「未采纳」而真实 status 是 PASS      -> True（假阴方向）
    其余                                       -> False

    （判据与签名照抄 §4.5:2430-2436。``actual`` 规格里有、判据里用不上：结论文案
    本身已经把语义编码在前缀里了，再解析一遍中文正文只会引入新的歧义。）
    """
    del actual
    if naive_conclusion.startswith(ADOPTED_PREFIX):
        return real_status is not Status.PASS
    if naive_conclusion.startswith(NOT_ADOPTED_PREFIX):
        return real_status is Status.PASS
    return False


class NaiveEmulator:
    """随包发布的朴素参照实现。**它自己不持有 client、不发任何请求。**

    它是一个纯函数式的"读数换算器"：输入我们已经抓到的 observations，
    输出"只探根路径、只看最终状态码、不做对照探测的实现会得出什么"。

    这样做的三个后果，都是我们要的：
      1. 报告首页那张对照表是**两个实现在同一批响应上的并排读数**，
         不是对一个假想对手的推算；
      2. --naive-only 也不额外打请求（它跑完整 pipeline 但只渲染左半边）；
      3. 表里会出现"朴素实现不会去探的位置"，那一行的 naive_conclusion 固定是
         「未采纳（没探这个位置）」—— 假阴方向的差异化就靠这些行。
    """

    __slots__ = ()  # 无状态：连一个属性都不许有，更不可能有 client

    #: 朴素实现会探的位置：apex 与 www 上的两条根路径。仅此四个。
    NAIVE_HOSTS = ("{apex}", "www.{apex}")
    NAIVE_PATHS = ("/llms.txt", "/llms-full.txt")

    # ---- 对外唯一入口 ---------------------------------------------------- #

    def rows(
        self, sitemap: SiteMap, positions: Sequence[PositionLike]
    ) -> tuple[NaiveContrast, ...]:
        """**每个 stage in (DISCOVERY, INDEX_FILE, FULLTEXT) 的 Position 各一行。**

        ④⑤⑥ 三段不进这张表：朴素实现连"索引里的链接要不要验"这个问题都不问，
        并排展示会变成我们自说自话。死链侧的差异化用另一个字段
        （counts.naive_dead_count，按"首跳状态码 >= 400 即判死"算）。
        """
        apex = sitemap.registrable_domain.lower()
        naive_got_it_right = self._naive_found_real_file(sitemap, positions)
        out: list[NaiveContrast] = []
        for p in positions:
            if p.stage not in (Stage.DISCOVERY, Stage.INDEX_FILE, Stage.FULLTEXT):
                continue
            in_naive_set = self._in_naive_set(p.probe_url, sitemap)
            why = ""
            if p.stage is Stage.DISCOVERY:
                # 卡点：DISCOVERY 位置的 probe_url 是 host 根路径，永不落在
                # NAIVE_PATHS 里，照 §4.5:2412 的写法会一律算成假阴，于是每个
                # 「零发现」域（modal / rustdesk）的 naive_divergences 都不可能是 0，
                # A34:4513 与第 14 步验收（modal 0 行 diverges）必然对撞。
                # 裁决：入口发现段照样出行（规格要「三段各一行」），但读数印的是
                # 「它碰过 / 没碰过这个 host」而不是采纳与否 —— 这两句都不带
                # 已采纳/未采纳前缀，_conclusions_differ 因此恒返回 False。
                naive_c = (
                    CONCLUSION_HOST_TOUCHED
                    if self._host_in_naive_set(p.probe_url, apex)
                    else CONCLUSION_HOST_UNTOUCHED
                )
                method = METHOD_NOT_IN_SET
                why = WHY_DISCOVERY
            elif not in_naive_set:
                naive_c, method = CONCLUSION_NOT_PROBED, METHOD_NOT_IN_SET
            else:
                # 朴素读数 = 跟完跳转的最终状态码，正文与对照一概不看
                st = p.evidence.http_status if p.evidence else None
                naive_c = self._verdict_from_status(p.probe_url, st)
                method = METHOD_PROBED.format(url=p.probe_url)
            actual_c = p.detail
            diverges = _conclusions_differ(naive_c, p.status, actual_c)
            direction: Literal["false_positive", "false_negative", "agree"]
            direction = self._direction(naive_c, p.status)
            if diverges and direction == "false_negative" and naive_got_it_right:
                # 朴素实现在它自己的探测集里已经**正确地**找到了真文件，也就是它
                # 对这个站的结论没错。这个位置它没探到，但不改变结论 —— 记成
                # 「读错了一个位置」会把 modal 这种站算出假的 divergence。
                diverges, direction, why = False, "agree", WHY_NAIVE_GOT_IT_RIGHT
            row = NaiveContrast(
                probe_url=p.probe_url,
                in_naive_probe_set=in_naive_set,
                naive_method=method,
                naive_conclusion=naive_c,
                actual_conclusion=actual_c,
                diverges=diverges,
                direction=direction,
                extra_requests=self._extra(p, apex=apex),
                why=why,
            )
            assert_no_banned_words(row.naive_method, row.naive_conclusion, row.why)
            out.append(row)
        return tuple(out)

    # ---- 私有助手（§4.5:2411-2423 只给了调用点，签名与函数体本步自定）------ #

    def _in_naive_set(self, probe_url: str, sitemap: SiteMap) -> bool:
        """这个位置在朴素探测集内吗 = apex/www 两个 host × 两条根路径，仅此四个。"""
        apex = sitemap.registrable_domain.lower()
        return self._host_in_naive_set(probe_url, apex) and self._path_in_naive_set(probe_url)

    def _host_in_naive_set(self, probe_url: str, apex: str) -> bool:
        host = (urlsplit(probe_url).hostname or "").lower()
        return host in tuple(h.format(apex=apex) for h in self.NAIVE_HOSTS)

    def _path_in_naive_set(self, probe_url: str) -> bool:
        return (urlsplit(probe_url).path or "/").lower() in self.NAIVE_PATHS

    def _verdict_from_status(self, probe_url: str, status: int | None) -> str:
        """只看**跟完跳转后的最终状态码**。2xx 一律「已采纳」—— 软 404 的盲区就在这。

        （``probe_url`` 在规格给的调用点里有，判据用不上；保留是为了签名与
        §4.5:2419 一致，将来若要按 host 分档也不用改调用点。）
        """
        del probe_url
        if status is None:
            return CONCLUSION_NO_RESPONSE
        if 200 <= status < 300:  # 规格就是按 2xx 划线
            return f"{ADOPTED_PREFIX}（{status}）"
        return f"{NOT_ADOPTED_PREFIX}（{status}）"

    def _extra(self, p: PositionLike, *, apex: str) -> int:
        """我们比朴素多打了几个请求才看出这个位置的真相（§4.5 表的最后一列）。

        三项相加，每项 0/1：非 apex/www 的 host 要先发现（子域枚举或声明挖掘）、
        非根路径要先猜出候选、软 404 要靠同 host 对照探测。实测锚点：
        `www.minimax.io/llms.txt` = 1（对照路径）、
        `platform.minimax.io/docs/llms.txt` = 2（子域 + /docs 子路径）。
        """
        n = 0
        if not self._host_in_naive_set(p.probe_url, apex):
            n += 1  # 子域发现 / 声明挖掘
        if not self._path_in_naive_set(p.probe_url):
            n += 1  # 子路径候选
        if p.control is not None:
            n += 1  # 同 host 对照探测
        return n

    def _direction(
        self, naive_c: str, real: Status
    ) -> Literal["false_positive", "false_negative", "agree"]:
        """与 `_conclusions_differ` 同一判据的方向版。

        `NaiveContrast.direction` 还有第四个取值 `over_report`（§4.5 表的
        resend.com/index.md 那行），但那是 ⑤ `.md` 段的位置，按行来源根本不进
        这张表，所以本函数永不产出它。
        """
        if naive_c.startswith(ADOPTED_PREFIX) and real is not Status.PASS:
            return "false_positive"
        if naive_c.startswith(NOT_ADOPTED_PREFIX) and real is Status.PASS:
            return "false_negative"
        return "agree"

    def _naive_found_real_file(self, sitemap: SiteMap, positions: Sequence[PositionLike]) -> bool:
        """朴素实现在它那四个位置里，有没有**正确地**拿到过一份真文件？

        判据 = 存在一个 ②/③ 段位置，同时满足「在朴素探测集内」「朴素读数是已采纳」
        「我们的判定是 PASS」。为真时它对这个站的结论（做了 AI 路径）本来就是对的，
        探测集外的位置就不再算它读错 —— 否则 modal.com 这种「根路径与 /docs/ 下是
        同一份真文件」的站会被算出假的假阴。
        """
        for p in positions:
            if p.stage not in (Stage.INDEX_FILE, Stage.FULLTEXT):
                continue
            if p.status is not Status.PASS:
                continue
            if not self._in_naive_set(p.probe_url, sitemap):
                continue
            st = p.evidence.http_status if p.evidence else None
            if self._verdict_from_status(p.probe_url, st).startswith(ADOPTED_PREFIX):
                return True
        return False


# --------------------------------------------------------------------------- #
# 对外便利函数（渲染层消费）
# --------------------------------------------------------------------------- #


def divergences(rows: Sequence[NaiveContrast]) -> tuple[NaiveContrast, ...]:
    """对照表里朴素实现读错的那些行。`counts.naive_divergences` 就是它的长度。"""
    return tuple(r for r in rows if r.diverges)


def headline(rows: Sequence[NaiveContrast]) -> str:
    """首页差异化演示区的那句大字。零 divergence 时翻成正向文案。

    两句都含固定措辞「只探根路径、不做对照探测的实现」（A34:4513 逐字要求），
    且都不含禁词。
    """
    n = len(divergences(rows))
    text = HEADLINE_CLEAN if n == 0 else HEADLINE_WRONG.format(n=n)
    assert_no_banned_words(text)
    return text


# --------------------------------------------------------------------------- #
# 死链侧的朴素读数（§4.5:2463-2465）
#
# 对照表只覆盖 ①②③ 三段。④⑤⑥ 的差异化走这个口径：对每条**已抽取且未被去噪
# 排除**的链接，按「**首跳**状态码 >= 400 即判死」算。X07（unkey
# 308 -> 308 -> 404）就是这个口径的对照面：朴素看首跳 308 会判 ALIVE。
# 这也是 §8.6 `test_naive_would_be_405_percent` 的口径。
# --------------------------------------------------------------------------- #


def naive_first_hop_status(response: HttpResponse | None) -> int | None:
    """首跳状态码：有跳转链就取第一跳，否则就是最终状态码。不发请求。"""
    if response is None:
        return None
    if response.redirects:
        return response.redirects[0].status
    return response.status


def naive_link_is_dead(first_hop_status: int | None) -> bool:
    """朴素死链判定：首跳状态码 >= 400 即判死。没有状态码就判不死。"""
    return first_hop_status is not None and first_hop_status >= 400


def naive_dead_count(first_hop_statuses: Iterable[int | None]) -> int:
    """`counts.naive_dead_count`：按首跳口径数出来的「朴素实现会报几条死链」。"""
    return sum(1 for s in first_hop_statuses if naive_link_is_dead(s))
