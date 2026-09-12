"""没观测过的响应，绝不许产出任何关于站点的结论（L0）。

## 这是发出去之后才发现的

`www.modal.com/llms-full.txt` 从来没录过 → fixture 层合成
`599 + x-geo-audit-fixture: missing`。而 `www.modal.com` 的**对照探针录过**
（真 404、能区分），于是 `ok_control_discriminates` 那条分支命中
（「host 对不存在的路径给 404，这个路径给了别的，所以文件是真的」）→ 判 **OK**。

接着 llms_full 的配对判定看到索引与全文都是那 44 字节占位符、比值 1.0，产出：

    HIGH「llms-full.txt 与 llms.txt 是同一份字节（一个字正文都没有）」

而 modal.com 实际有一份 **2,292,505 B** 的真全文。**七份已发布报告里 10 条这样的
不实指控**，而且报告自己把 `fixture missing: this URL was never recorded` 印在
证据栏里 —— 一边说没抓过，一边给 HIGH 结论。

`ok_control_discriminates` 的推理对**真实响应**是成立的；错在它没问一句
「这个响应是真观测来的吗」。修在 `classify_response` 入口，一次盖住所有分支。

## 三层断言，缺一层都不够

1. `classify_response` 对带标记的响应必须判 `UNKNOWN/not_fetched`；
2. `check_llms_full` 对合成配对必须产出 **0** 条 finding；
3. **已发布的报告里不许出现建立在「never recorded」上的 finding。**
   第 3 层才是真正的闸 —— 今天的教训正是「单元测试全绿而产物是错的」。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from geo_audit.checks.ai_path import check_llms_full
from geo_audit.fetch.classify import classify_response
from geo_audit.fetch.normalize import norm_sha256, normalize_body, structural_fingerprint
from geo_audit.models import (
    Expect,
    HostProfile,
    HttpResponse,
    Probe,
    Verdict,
    finalize_response,
)

REPO = Path(__file__).resolve().parents[1]
REPORTS = REPO / "docs" / "reports"

#: fixture 层缺快照时合成的那条响应（fixtures.py 的 `_replay_lenient`）。
MISSING_BODY = "fixture missing: this URL was never recorded"
MISSING_HEADERS = {"content-type": "text/plain", "x-geo-audit-fixture": "missing"}


def _discriminating_control(host: str) -> HostProfile:
    """真录过的对照：404 且能区分 —— 正是让洞打开的那个条件。"""
    body = "Not Found"
    norm = normalize_body(body)
    struct_sha, struct_tags = structural_fingerprint(body)
    return HostProfile(
        host=host,
        probe_url=f"https://{host}/geo-audit-probe-deadbeef.txt",
        status=404,
        content_type="text/plain",
        norm_sha256=norm_sha256(body),
        norm_len=len(norm),
        norm_body_prefix=norm[:400],
        struct_sha256=struct_sha,
        struct_tags=struct_tags,
        final_path="/geo-audit-probe-deadbeef.txt",
        status_discriminates=True,
        control_is_html=True,
        usable=True,
        probed_at=0.0,
    )


def _synthetic_probe(url: str, expect: Expect = Expect.TEXT_FILE) -> Probe:
    host = url.split("/")[2]
    resp = HttpResponse(
        url=url,
        final_url=url,
        status=599,
        headers=MISSING_HEADERS,
        body=MISSING_BODY.encode(),
        redirects=(),
    )
    cls = classify_response(
        599,
        MISSING_HEADERS,
        MISSING_BODY,
        url=url,
        expect=expect,
        final_url=url,
        redirects=(),
        control=_discriminating_control(host),
    )
    return Probe(url, expect, resp, cls)


# --------------------------------------------------------------------------- #
# 一层：判定
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("expect", [Expect.ANY, Expect.TEXT_FILE, Expect.HTML_PAGE])
def test_marker_response_is_never_anything_but_not_fetched(expect: Expect) -> None:
    """**带能区分的真对照也不许翻成 OK** —— 那正是发出去那 10 条的成因。"""
    url = "https://www.modal.com/llms-full.txt"
    cls = classify_response(
        599,
        MISSING_HEADERS,
        MISSING_BODY,
        url=url,
        expect=expect,
        final_url=url,
        redirects=(),
        control=_discriminating_control("www.modal.com"),
    )
    assert cls.verdict is Verdict.UNKNOWN, f"没观测过的响应判成了 {cls.verdict.value}"
    assert cls.reason == "not_fetched"


def test_the_guard_runs_before_every_other_branch() -> None:
    """把能触发各个分支的条件全塞进去，仍然只能是 not_fetched。

    这条防的是「有人把 L0 挪到某条分支后面」——挪了就会有一种输入绕过它。
    """
    url = "https://www.modal.com/llms.txt"
    for kwargs in (
        {"robots_disallowed": True},
        {"transport_error": "timeout"},
        {"body_truncated": True},
    ):
        cls = classify_response(
            599,
            MISSING_HEADERS,
            MISSING_BODY,
            url=url,
            expect=Expect.TEXT_FILE,
            final_url=url,
            redirects=(),
            control=_discriminating_control("www.modal.com"),
            **kwargs,  # type: ignore[arg-type]
        )
        assert cls.reason == "not_fetched", f"{kwargs} 下绕过了 L0：{cls.reason}"


# --------------------------------------------------------------------------- #
# 二层：检查
# --------------------------------------------------------------------------- #


def test_llms_full_produces_nothing_from_a_synthetic_pair() -> None:
    """索引与全文都没录过 → 0 条 finding。

    发出去那 10 条全部长这个形状：两边都是 44 字节的同一句占位符，
    比值 1.0，于是被判成「字节副本、一个字正文都没有」。
    """
    index = _synthetic_probe("https://www.modal.com/llms.txt")
    full = _synthetic_probe("https://www.modal.com/llms-full.txt")
    assert index.verdict is Verdict.UNKNOWN and full.verdict is Verdict.UNKNOWN
    findings = check_llms_full("modal.com", [index, full])
    assert findings == (), f"从没抓过的一对产出了 finding：{[f.title for f in findings]}"


def test_a_real_pair_still_gets_judged() -> None:
    """闸收紧了不能把真实配对也吞掉 —— 否则这个检查等于删了。"""

    def real(url: str, body: str) -> Probe:
        headers = {"content-type": "text/plain"}
        # 必须过 finalize_response 算摘要：_judge_pair 在 raw_md5 为 None 时
        # 直接 return None（卡点 S10：None 绝不当「哈希不同」）。不算摘要的话
        # 这条测试会「因为算不出哈希」而绿，测不到它想测的东西。
        resp = finalize_response(
            HttpResponse(
                url=url,
                final_url=url,
                status=200,
                headers=headers,
                body=body.encode(),
                redirects=(),
            ),
            want_digests=True,
        )
        cls = classify_response(
            200,
            headers,
            body,
            url=url,
            expect=Expect.TEXT_FILE,
            final_url=url,
            redirects=(),
            control=_discriminating_control(url.split("/")[2]),
        )
        return Probe(url, Expect.TEXT_FILE, resp, cls)

    same = "# Docs\n\n- [a](https://x.invalid/a.md): first\n- [b](https://x.invalid/b.md): second\n"
    index = real("https://x.invalid/llms.txt", same)
    full = real("https://x.invalid/llms-full.txt", same)
    assert index.verdict is Verdict.OK and full.verdict is Verdict.OK
    findings = check_llms_full("x.invalid", [index, full])
    assert findings, "真实的「全文就是索引副本」配对不再被判出来了 —— 闸收得过头"


# --------------------------------------------------------------------------- #
# 三层：产物（今天的教训 —— 单元测试全绿而报告是错的）
# --------------------------------------------------------------------------- #


needs_reports = pytest.mark.skipif(
    not REPORTS.exists() or not any(REPORTS.glob("*.html")),
    reason="docs/reports/ 里没有报告",
)


@needs_reports
def test_no_published_report_builds_a_finding_on_a_missing_snapshot() -> None:
    """**已发布的报告里不许出现「never recorded」。**

    这是唯一能抓住实际发生过那件事的断言：判定函数改对了，但产物是上一版
    代码生成的、还挂在 GitHub Pages 上。单元测试对此一无所知。
    """
    offenders: list[str] = []
    for path in sorted(REPORTS.glob("*.html")):
        n = path.read_text(encoding="utf-8").count("never recorded")
        if n:
            offenders.append(f"{path.name}: {n} 处")
    assert offenders == [], (
        "这些报告里的 finding 建立在「我们从没抓过这个 URL」的合成响应上：\n  "
        + "\n  ".join(offenders)
        + "\n跑 scripts/build_gallery.py 重建。"
    )


@needs_reports
def test_zero_finding_reports_do_not_display_graded_findings() -> None:
    """首屏写「N 个位置全部通过」的报告，不许同时挂着 HIGH/MEDIUM 条目。

    实测 modal.com 那份就是这样：headline 说 9 个位置全部通过，正文一条 HIGH。
    两句话不能同时成立 —— 而没有任何闸在管它们的一致性。
    """
    bad: list[str] = []
    for path in sorted(REPORTS.glob("*.html")):
        html = path.read_text(encoding="utf-8")
        m = re.search(r"<h1>(.*?)</h1>", html, re.S)
        if not m or not re.search(r"\d+\s*个位置全部通过", m.group(1)):
            continue
        graded = len(re.findall(r'class="f-sev sev-(?:high|medium)"', html))
        if graded:
            bad.append(f"{path.name}: 首屏说全部通过，却有 {graded} 条 HIGH/MEDIUM")
    assert bad == [], "报告自相矛盾：\n  " + "\n  ".join(bad)


@needs_reports
def test_report_json_schema_still_validates() -> None:
    """顺手确认 schema 文件在位（重建报告时会被 CI 的 schema job 用到）。"""
    schema = REPO / "schema" / "report-1.schema.json"
    assert schema.exists()
    assert json.loads(schema.read_text(encoding="utf-8"))["$schema"]


# --------------------------------------------------------------------------- #
# 报告不许自相矛盾：「是死链」与「判定作废」不能同时出现在一条 finding 里
# --------------------------------------------------------------------------- #


@needs_reports
def test_no_finding_asserts_and_retracts_itself() -> None:
    """一条 finding 里不许同时有肯定结论和「判定作废」。

    实测 mistral 那份 **75 条**死链，每一条都同时写着：

        标题「llms.txt 里列的 …/sfcortex.md 是死链」
        证据「同域对照本身不可用，所以这一条的判定作废，已按「无法评估」处理。」

    成因：模板在 `f.control` 为空时**无条件**印那句，而死链判据靠状态码、
    本来就不需要对照。第一版按 `CONTROL_DEPENDENT_KINDS`（kind）分流。

    2026-09-12 又抓到同一个病的第二形态：kind 分流不够细。tdengine 那条

        标题「…/docs/llms.txt 返回 200 但内容不是文本文件（软 404）」·HIGH·计进「读错」
        证据「同域对照本身不可用，所以这一条的判定作废，已按「无法评估」处理。」

    是 `soft_404`（确实属于依赖对照的那一族），但**它自己**判的依据是
    `html_where_text_expected` —— 一条不需要对照的确定性规则。现在按
    `CONTROL_DEPENDENT_REASONS`（这一条用没用到对照读数）分流，
    所以这条测试也从只看死链扩到看任何已经下了肯定结论的标题。
    """
    import re as _re

    bad: list[str] = []
    for path in sorted(REPORTS.glob("*.html")):
        html_text = path.read_text(encoding="utf-8")
        # 按 finding 块切开，逐块看
        blocks = _re.split(r'<div class="f-title">', html_text)[1:]
        for block in blocks:
            title = block.split("<", 1)[0]
            body = (
                block[: block.find('<div class="f-title">')]
                if '<div class="f-title">' in block
                else block
            )
            # 「判定作废」只有一种成立的处境：这一条**确实**依赖对照读数，
            # 而对照拿不到。标题里已经下了肯定结论的（是死链 / 是软 404），
            # 都不许再说自己作废。
            asserts_something = "是死链" in title or "软 404" in title
            if "判定作废" in body and asserts_something:
                bad.append(f"{path.name}: {title[:56]}")
    assert bad == [], (
        "这些 finding 一边断言、一边说判定作废：\n  "
        + "\n  ".join(bad[:8])
        + (f"\n  …共 {len(bad)} 条" if len(bad) > 8 else "")
    )
