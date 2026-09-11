"""报告的全部中文文案常量（§1.1:148 指定的落点）。

**为什么所有文案都必须集中在这里**：§6.5:3250 要求禁词检查在**渲染期**生效
（不是只在测试里）。而禁词只能扫「我们自己写的话」—— 一旦扫到甲方站点的
``<title>`` / 锚文本 / ``body_head``，任何一个页面里出现「完美」「一切正常」
或公司名含 Lighthouse，``render_html`` 就会 raise、整份报告产不出来
（简报 spec_gaps 停工级 4）。所以：

* 我们写的每一句话都在 ``COPY_ZH``（或本文件的表常量）里 —— 它是禁词的**扫描面**；
* 模板里不许再出现散装中文散文，只许 ``{{ copy["key"] }}``；
* 甲方数据只经 Jinja autoescape 输出，**永不进禁词扫描面**。

规格从未列出 ``COPY_ZH`` 的键集（简报 spec_gaps 第 6 条），下面这套键由
``template.html.j2`` 的实际需要定义，键名与所在区块一一对应（``verdict_*`` /
``chain_*`` / ``naive_*`` / ``root_cause_*`` / ``unknown_*`` / ``finding_*`` /
``review_*`` / ``fragility_*`` / ``evidence_*`` / ``misread_*`` / ``apex_*`` /
``excluded_*`` / ``coverage_*`` / ``method_*``）。全表写进交付说明的
``deviations_from_spec``。

⚠️ 本文件的每一个字符串都会被 ``assert_no_banned_words`` 扫。附录 B 的三句话
一句都不许出现，特别是**不许写「任何现成工具都会给出错的答案」** —— 实测从未
跑过任何现成工具做对照，固定措辞只能是「只探根路径、不做对照探测的实现」。
"""

from __future__ import annotations

from ..naive import HEADLINE_CLEAN, HEADLINE_WRONG, NAIVE_FIXED_PHRASE

# ═════════════════════════════════════════════════════════════════════════════
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║ 占位区开始 —— PLACEHOLDER BLOCK BEGIN                                     ║
# ║                                                                           ║
# ║ ``STAGE_LABEL`` 与 ``POSITION_LABEL`` 的**正式定义应在                    ║
# ║ src/geo_audit/models.py**（规格 §2.5，行 868–875 与 909–916）。仓库现状：  ║
# ║ models.py 有 Stage / PositionClass 两个枚举，但**这两张标签表没有**，      ║
# ║ 而铁律 1 禁止本 agent 改 models.py。                                      ║
# ║                                                                           ║
# ║ 放在 copy_zh.py 而不是 render.py 的理由：它们是纯中文文案表，正好是本文件   ║
# ║ 的职责；而 render.py 与 chain_svg.py 都要用，放 render.py 会让             ║
# ║ chain_svg -> render -> chain_svg 成环。搬入 models.py 时是纯剪贴：         ║
# ║   1. 把两张表剪到 models.py 的 PositionClass 之后；                       ║
# ║   2. 本文件改成 ``from ..models import POSITION_LABEL, STAGE_LABEL``       ║
# ║      并继续 re-export（模板与 chain_svg 从 copy_zh 取，不用改）。         ║
# ║ 先例：rootcause.py 的 RootCause、extract.py 的 LinkTarget 同一条 spec_gap。║
# ╚═══════════════════════════════════════════════════════════════════════════╝

#: 链路图六格的标签（§2.5:868 逐字）。序号 ①..⑥ 就在文案里，别处不再另编号。
#: ⚠️ §6.1:3031 的版面示例印的是「② 索引真伪 / ④ 索引内链 / ⑤ .md / ⑥ 可点击」，
#: 与本表逐字不同（简报 spec_gaps 第 12 条）。裁决：**一律以本表为准**，
#: 否则同一个词在首页和第 2 页两种写法。
#: 位置类别的标签（§2.5:909 逐字）。严重度由位置决定，不由条数决定 —— 所以
#: finding 卡片的抬头是「CRITICAL · 销售路径」而不是规则名。
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║ 占位区结束 —— PLACEHOLDER BLOCK END                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
# ═════════════════════════════════════════════════════════════════════════════


# --------------------------------------------------------------------------- #
# 表常量（列表 / 表格，不进 COPY_ZH 的扁平字符串表）
# --------------------------------------------------------------------------- #

#: 首页差异化演示区的三列表头（§6.1:3045 逐字）。
NAIVE_DEMO_COLUMNS: tuple[str, str, str] = ("探测位置", "那种实现会说", "实际是")

#: C-1 证据存档表的八列（§6.3:3151 逐字，逐 Position 一行）。
EVIDENCE_COLUMNS: tuple[str, ...] = (
    "段",
    "URL",
    "状态码",
    "content-type",
    "字节",
    "对照路径",
    "对照返回",
    "结论",
)

#: 朴素对照全表的列（§2.6 NaiveRow 的字段顺序）。
NAIVE_TABLE_COLUMNS: tuple[str, ...] = (
    "探测位置",
    "朴素方法",
    "那种实现会说",
    "实际是",
    "有分歧",
    "多打的请求",
    "方向",
)

#: 被去噪排除的链接清单的列（§6.1 #excluded 区，A24 要 rule_id 与 rule_desc 都印）。
EXCLUDED_COLUMNS: tuple[str, ...] = ("URL", "rule_id", "规则说明", "出现在", "证据强度", "处置")

#: ``NaiveRow.direction`` 四个取值的中文标签。``over_report`` 是 models.NaiveContrast
#: 比 §2.6 NaiveRow 多出来的那一档（「朴素多报了一条，我们按范围压住」）。
DIRECTION_LABEL: dict[str, str] = {
    "false_positive": "假阳（它说采纳了，其实没有）",
    "false_negative": "假阴（它说没有，其实有真文件）",
    "over_report": "过报（它报了一条，我们按范围不报）",
    "agree": "一致",
}

#: 位置四态的中文标签。**四格永远是这四个，UNKNOWN 永不折算**（§6.4 R1）。
STATUS_LABEL: dict[str, str] = {
    "pass": "通过",
    "fail": "读错",
    "unknown": "无法判断",
    "not_applicable": "不适用",
}

#: 四态的 CSS 后缀（§6.5:3264 的 ``.st-pass`` / ``.st-fail`` / ``.st-unknown`` /
#: ``.st-na`` 逐字）。``Status.NOT_APPLICABLE.value`` 是 ``not_applicable``，
#: 而规格的 class 名是 ``st-na`` —— 这张表就是那一处折算，别在模板里现拼。
STATUS_CSS: dict[str, str] = {
    "pass": "pass",
    "fail": "fail",
    "unknown": "unknown",
    "not_applicable": "na",
}

#: 四态的字形。CSS 用 ``::before`` 再印一次，SVG 里直接画 —— 状态不靠颜色单独承载
#: （§6.5:3264，色盲用户与黑白打印）。
STATUS_GLYPH: dict[str, str] = {
    "pass": "✓",
    "fail": "✕",
    "unknown": "?",
    "not_applicable": "–",
}

#: C-2「别人的工具会怎么误判你」的三种可自动检出的误判形态（§6.3:3168 逐字）。
#: 第三条是零发现报告里最硬的一句话，A29 断言 HTML 含「只看状态码」。
MISREAD_FORMS: tuple[tuple[str, str], ...] = (
    (
        "你的真文件会被读成「没有」",
        "WAF / 限流会把纯 HTTP 客户端拦掉（实测 gusto.com 403、www.pipedrive.com 429）；"
        "真文件在子域或 /docs 下而根路径 404 或软 404（实测 minimax、moonshot、"
        "siliconflow、onfleet、canvasmedical、ecwid 六家）。",
    ),
    (
        "你的 0 死链会被读成「有死链」",
        "站上有 Cloudflare 的 /cdn-cgi/l/email-protection 诱饵 href、有 example.com 占位、"
        "有 Alpine/Vue 的 :href、有 {templateID} 这类模板占位。"
        "实测：这类噪声能让死链数从 25 虚报成 42（+68%）。",
    ),
    (
        "你的 0 死链其实是假的 0",
        "你的站对未知路径返回 200 或 302 而不是 404（实测 developers.pipedrive.com 的 "
        "24,907 B 兜底页、docs.gusto.com 与 docs.moderntreasury.com 的 302→首页、"
        "platform.kimi.ai 的 414,072 B Quickstart 页）。"
        "这种站上任何只看状态码的死链工具都会报 0 死链，那个 0 是假的。"
        "我们是用正文/骨架比对得出的 0，所以我们的 0 是真的。",
    ),
)

#: C-4「我们没查什么」= §0.3:46 那张八行表，逐字照抄，**别自己重新论证**。
NOT_CHECKED_TABLE: tuple[tuple[str, str], ...] = (
    (
        "过期信号整类（含附录）",
        "通用旧年份正则：batch1 扫出 134 条命中、真信号 0；CN 批扫出 296 处、真信号 2。"
        "两批独立同结论。而且还高假阴 —— snipcart 的真信号 "
        "「© All rights reserved, Snipcart inc. 2023」被自家正则的 inc. 句点截断漏掉。"
        "三条收窄规则没有命中率、没有假阳性率、没有回归用例，三样全无。",
    ),
    (
        "事实冲突（套餐名枚举 / 同页矛盾 / 档位↔功能映射）",
        "8/72、6/72 这些数是人工逐域推出来的，自动化版本从来没跑过，这一整块的假阳性率是空的。"
        "且「属性对」这个单位实测伸缩 15 倍（bigcommerce 把一整张套餐枚举记成 1 对，"
        "baseten 把同型 GPU 表记成 17 对，together 14 个模型记成 37 对）。",
    ),
    (
        "锚点腐烂（#xxx 在目标页不存在）",
        "本轮未做系统性检测，只偶得 1 例（gusto #minimum-api-version）。命中率未知。"
        "不做的理由是实现成本，不是命中率低。",
    ),
    (
        "通用定价页↔文档数值比对",
        "15 个域完全没有可比面（必然 0）；单位不可定义；20% 的冲突以 llms.txt 为一侧"
        "（已否决功能）。",
    ),
    (
        "定期扫描 / 健康分订阅",
        "中位数落在 1–2 条区间，73.6% 的站报不出 3 条。注意：「两次扫描之间没有新增」"
        "是无证据的时序断言（全部数据是单一时间点横截面），准确表述是"
        "「我们没有纵向数据，无法承诺订阅价值」。",
    ),
    (
        "托管 web 版（输入任意域名就发请求的公开端点）",
        "它会让 --contact 这条合规约束当场失效，且等于开放抓取代理。",
    ),
    (
        "浏览器渲染 / Playwright",
        "uvx 一行可跑是硬需求；Playwright 要另外 playwright install（约 300 MB）。"
        "已量化的代价：确认的 JS 盲区只有 help.spoton.com 与 docs.lawmatics.com = "
        "2/72 = 2.8%。这两家判 UNKNOWN，绝不判「干净」。",
    ),
    (
        "--serve 本地表单页",
        "HTTP server 是纯 scope creep + 安全面。非命令行用户走 GitHub Action。",
    ),
)

#: 报告**查了什么**（与 NOT_CHECKED_TABLE 成对，§0.2 的两类检查）。
CHECKED_TABLE: tuple[tuple[str, str], ...] = (
    (
        "C3 · AI 检索链路体检",
        "llms.txt / llms-full.txt 是真文件还是软 404、全文通道是不是索引的字节副本、"
        "索引里列的链接活着几条、「任意页面加 .md」这个约定兑现了没有。"
        "每一条都配同域随机路径对照探测。",
    ),
    (
        "C1 · 人和爬虫共用的可点击路径",
        "seed 页上抽取的 <a href>，点了就 404 的那些。带 23 条去噪规则与两级根因归并。",
    ),
)

# --------------------------------------------------------------------------- #
# COPY_ZH —— 扁平文案表。模板里只许写 {{ copy["key"] }}
# --------------------------------------------------------------------------- #

COPY_ZH: dict[str, str] = {
    # ── 文档与页眉 ────────────────────────────────────────────────────────
    "doc_title": "geo-audit · {domain} · AI 检索链路体检",
    "doc_title_zero": "geo-audit · {domain} · AI 可读性证据存档",
    "header_tool": "geo-audit",
    "header_ua": "UA",
    "header_denoise": "去噪清单",
    "header_cache_note": "本次报告里有响应来自本地缓存。要强制重打请加 --no-cache。",
    "skip_to_main": "跳到正文",
    # ── #verdict 判决区 ──────────────────────────────────────────────────
    "verdict_title": "判决",
    "count_bar_positions": "{positions} 个位置",
    "count_bar_note": "四格之和恒等于位置数。「无法判断」永不折算进「通过」——"
    "「我们看不了」和「你这里没问题」是两件事。",
    "verdict_zero_intro": "这次没有可上报的发现。零发现不等于干净，所以这份东西叫"
    "「AI 可读性证据存档」：下面四块是这个 0 的全部依据，你可以逐行复现。",
    "interrupt_banner": "⚠ 扫描被中断（Ctrl-C）。已完成 {done} 个位置，未跑到 {todo} 个。\n"
    "下面的「无法判断」里有 {todo} 个只是没轮到，不是你的站有问题。\n"
    "接着跑：geo-audit {domain} --contact <you> （命中缓存，不会重打已完成的请求）",
    "unusable_banner": "⚠ 这次扫描的核心位置里超过一半我们没能评估（{unknown}/{core}），"
    "整份报告已降级。下面的结论不要当结论用，先按「未能评估」区的补救办法重跑。",
    "sampling_banner": "⚠ 本次是抽样，不是全量：{note}。抽到的范围之外我们不外推。",
    # ── #chain 链路图 ────────────────────────────────────────────────────
    "chain_title": "AI 检索链路六段",
    "chain_footnote": "这条链路上任何一段断掉，后面几段的内容 AI 都拿不到。",
    "chain_empty_cell": "未探测",
    "chain_count_suffix": "个位置",
    "chain_alt": "六段链路图：每格是一段，格内是该段的状态与位置数，六格位置数之和等于总位置数。",
    # ── 首页差异化演示区（#naive-demo）─────────────────────────────────
    "naive_demo_title": "差异化演示",
    # §6.1:3034 / A34 的固定措辞。**唯一定义在 naive.py**（NAIVE_FIXED_PHRASE），
    # 这里只引用 —— 报告里不许写「任何现成工具都会给出错的答案」，实测从未跑过
    # 任何现成工具做对照（附录 B-1）。
    "naive_demo_headline": HEADLINE_WRONG,
    "naive_demo_footnote": "自己复现 → geo-audit {domain} --contact you@you.co --naive-only",
    "naive_demo_none": HEADLINE_CLEAN + "。差异化演示区因此是空的 —— "
    "这是这个域的性质，不是我们少做了对照。",
    "naive_demo_why": "这一块的作用不是炫技，是让「我拿别的东西查过，没这条」这句话失效："
    "我们先说出那类实现在这里会得出什么、以及它少做了哪一步。",
    # ── #root-causes 根因区（永远在条目列表之前）────────────────────────
    "root_cause_title": "按根因",
    "root_cause_headline": "按根因：{findings} 条发现来自 {root_causes} 处改动",
    "root_cause_line": "改 1 处 → 修 {n} 条：{summary}",
    "root_cause_none": "本次没有需要归并的根因。",
    "root_cause_triple": "口径：{findings} 条 finding / {root_causes} 处根因 / "
    "{occurrences} 个链接实例 —— 三个数各有各的意思，不许混着说。",
    # ── 首页覆盖披露（上首页，不藏附录）─────────────────────────────────
    "coverage_disclosure": "这份报告不检查：锚点是否腐烂、sitemap、robots 对 AI 爬虫的放行、"
    "图片/CSS 资源、事实是否冲突、内容是否过期。理由见文末。",
    # ── #unknown 未能评估区（排在发现之前）─────────────────────────────
    "unknown_title": "未能评估",
    "unknown_intro": "把「我们没看到」误读成「没问题」的代价，比漏一条 LOW 死链大得多，"
    "所以这一区排在发现之前。这些位置既不计死链也不计存活。",
    "unknown_none": "本次扫描没有「无法判断」的位置。",
    "unknown_reason_label": "原因码",
    "unknown_remedy_label": "补救办法",
    # §6.4 R4 的兜底：管线既没填 unknown_remedy、原因码也不在 UNKNOWN_REMEDY 的
    # 17 条里时印这句。它仍然是「我们看不了」，**不是「这里没问题」**。
    "unknown_remedy_missing": "这个位置我们没能评估，而且连原因码都没记全 ——这是本工具的缺陷，"
    "请带上这份报告开一个 issue。在拿到原因之前，这一格既不计死链也不计存活。",
    "unknown_position_label": "位置",
    # ── #findings 发现区 ─────────────────────────────────────────────────
    "findings_title": "发现（按根因分组）",
    "findings_none": "本次没有可上报的发现。这不代表你的站没有可改的地方 ——"
    "见下面的「证据存档」与「下次会先坏在哪」。",
    "findings_group_ungrouped": "未归并（各自独立的一处改动）",
    "findings_group_line": "改 1 处 → 修 {n} 条 · {instances} 个链接实例 · 最高 {severity}",
    "finding_suppress_button": "抑制这条",
    "finding_fix_title": "去哪儿改",
    "finding_fix_open": "打开",
    "finding_fix_locator": "定位",
    "finding_fix_before": "现在",
    "finding_fix_after": "改成",
    "finding_fix_verified": "← 我们请求过，200",
    "finding_fix_unverified": "我们没找到明显的正确目标，所以这里不编一个替换地址。",
    "finding_fix_missing": "我们没找到明显的正确目标。",
    "finding_evidence_title": "证据",
    "finding_evidence_target": "目标",
    "finding_evidence_control": "同域",
    "finding_evidence_control_why": "同域对照返回正常，所以这不是整站反爬。",
    "finding_evidence_control_missing": "同域对照本身不可用，所以这一条的判定作废，"
    "已按「无法评估」处理。",
    "finding_evidence_repro": "复现",
    "finding_naive_title": NAIVE_FIXED_PHRASE + "会说",
    "finding_actual_title": "实际是",
    "finding_sibling_line": "同根因还有 {n} 条 finding",
    "finding_occurrence_line": "这个目标在站上出现 {n} 次（{pages} 个页面）",
    "finding_fp_note_label": "这条会误报的情况",
    "finding_fp_guard_label": "已排除的可能（通过了这些去噪规则才报出来）",
    "finding_severity_signals_label": "严重度依据",
    "finding_suppress_label": "不认这条",
    "finding_plaintext_summary": "纯文本版（手选复制）",
    "finding_kind_label": "种类",
    "finding_stage_label": "所在段",
    "finding_position_label": "位置类别",
    # ── #review 待人工确认区 ─────────────────────────────────────────────
    "review_title": "待人工确认",
    "review_intro": "下面这些我们判它死了，但静态 HTML 判不了它是否对访客可见。"
    "我们打 needs_review 而不是丢弃，也不进首页分子。",
    "needs_review_banner": "这一条我们判它死了，但静态 HTML 判不了它是否对访客可见"
    "（它的 class 里有 hidden）。请人工看一眼：如果访客确实点不到它，加 --ignore GA-XXXX。",
    "review_none": "本次没有需要人工确认的条目。",
    # ── #fragility 结构性脆弱点 ─────────────────────────────────────────
    "fragility_title": "下次会先坏在哪 · 结构性脆弱点",
    "fragility_intro": "每条都挂一个实测先例，并给一条能直接放进 CI 的命令。"
    "这一区不是预测，是「这个形状在语料里已经坏过」。",
    "fragility_metric": "判据",
    "fragility_why": "为什么危险",
    "fragility_precedent": "实测先例",
    "fragility_watch": "放进 CI 的一条命令",
    "fragility_none": "本次没有产出结构性脆弱点。",
    # ── #evidence C-1 证据存档表 ────────────────────────────────────────
    "evidence_title": "我们替你验了什么 · 证据存档",
    "evidence_intro": "逐位置一行，行数恒等于位置数。每行都带一条可粘贴的 curl。",
    "evidence_rows_note": "共 {n} 行 == {positions} 个位置。",
    "evidence_curl_summary": "curl",
    "evidence_control_none": "—",
    # ── #misread C-2 别人的工具会怎么误判你 ─────────────────────────────
    "misread_title": "别人的工具会怎么误判你",
    "misread_intro": "三种可自动检出的误判形态。这一块是零发现报告真正的付费点："
    "你拿到的 0 与别处拿到的 0，来源不一样。",
    # ── #apex 裸域/www ──────────────────────────────────────────────────
    "apex_title": "裸域 / www 双向探测",
    "apex_single_case": "证据强度 single_case：全语料只有一例（brevo 的裸域返回 Vercel 的"
    "纯文本 DEPLOYMENT_NOT_FOUND，而 www 与 developers 子域都正常）。"
    "n=1 不够格进首页计数，所以这一区单列。",
    "apex_none": "本次没有裸域 / www 双向探测结果。",
    "apex_outcome_label": "结论",
    # ── #excluded 被去噪排除的链接 ──────────────────────────────────────
    "excluded_title": "被去噪排除的链接",
    "excluded_intro": "逐条留痕，带 rule_id。实测教训：五个批次排除了 "
    "/cdn-cgi/l/email-protection、另几个批次没排 —— 同一个东西两套口径，"
    "所以这里必须逐条列。",
    "excluded_none": "本次没有被去噪排除的链接。",
    # ── #naive 朴素对照全表 ─────────────────────────────────────────────
    "naive_title": "朴素对照全表",
    "naive_intro": "同一批已抓响应上的两个读数：左边只用「跟完跳转的最终状态码」推，"
    "右边是我们的判定。朴素侧不额外发一个请求 —— 它是换算器，不是第二次扫描。",
    "naive_rows_note": "只有 ① 入口发现 / ② 索引文件真伪 / ③ 全文通道 三段的位置进这张表；"
    "④⑤⑥ 的差异化走下面那行死链口径对比。",
    "naive_dead_line": "死链口径对比：只看首跳状态码（>= 400 即判死）会数出 {naive} 条；"
    "我们经去噪与正文比对后是 {ours} 条链接实例。",
    "naive_diverge_count": "有分歧 {n} 条。",
    "naive_none": "本次没有可对照的朴素读数。",
    # ── #coverage 覆盖披露 ──────────────────────────────────────────────
    "coverage_title": "覆盖披露",
    "coverage_checked": "查了什么",
    "coverage_not_checked": "不查什么（摘要，理由见「方法」）",
    "coverage_positions": "位置数 {positions}",
    "coverage_identity": "链接账本：抽取 {extracted} = 排除 {excluded} + 待人工 {needs_review}"
    " + 已验证 {verified} + 无法判断 {unknown} + 被封顶截掉 {capped}",
    "coverage_pages": "抓到的页面 {pages} 个",
    "coverage_requests": (
        "HTTP 请求 {http} / 上限 {cap}（其中不同 URL {made} 个；"
        "差额是跳转每一跳、robots.txt 与重试）"
    ),
    "coverage_robots_on": "robots.txt 的 Disallow 我们遵守了：命中的路径零请求，判"
    "「无法判断（robots_disallowed）」。「我们没被允许看」是真话。",
    "coverage_robots_off": "本次带了 --ignore-robots，robots.txt 的 Disallow 未被遵守。",
    "coverage_sampling": "抽样：{note}",
    "coverage_sampling_none": "本次未触发抽样。",
    "coverage_llm": "LLM 调用 {n} 次（这个工具零 LLM、零 API key，所以它恒为 0）。",
    "coverage_gap_title": "这些地方我们想看但没看到",
    "coverage_gap_none": "没有额外的覆盖缺口。",
    "coverage_gap_where": "位置",
    "coverage_gap_reason": "原因码",
    "coverage_gap_remedy": "补救办法",
    # ── #method 方法与不检查什么 ────────────────────────────────────────
    "method_title": "方法，与不检查什么",
    "method_intro": "这个工具零 LLM、零 API key。判定全部来自 HTTP 观测 + 同域随机路径"
    "对照探测 + 正文/骨架归一化比对。下面两张表是范围本身，不是免责声明。",
    "method_not_checked_title": "明确不做，以及为什么（引实测，不重新论证）",
    "method_checked_title": "做什么",
    "method_col_what": "项",
    "method_col_why": "实测理由",
    "method_naive_note": "报告里凡提到「那类实现会读错」，措辞一律是"
    "「只探根路径、不做对照探测的实现」——"
    "我们没有拿任何一款现成产品跑过对照，所以不会替它们下结论。",
    "method_unknown_note": "「未能评估」与「没问题」在这份报告里严格分开："
    "Status.UNKNOWN 永不折算成通过。实测依据：help.spoton.com 与 docs.lawmatics.com "
    "的文档站是纯 JS SPA，它们的「零发现」是抓取能力问题，不是站点干净。",
    "method_positions_note": "首页大字只用位置数，条目数单列 —— 位置数回答「链路哪几段走不通」，"
    "条目数回答「有几条要改」，两个数不能互相顶替。",
    "footer_note": "本报告为单文件 HTML，无任何外部请求，可离线转发与打印。",
}
