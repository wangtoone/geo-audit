"""架构门禁：LLM 永远不当裁判（A52 / A54）。

这是 §11.0 唯一的架构原则，也是前三轮失败的共同病因。判定必须写在 ``checks/``
里，而 ``checks/`` 里不许有 LLM —— 不靠自觉，靠这两条门禁。

## 为什么不用规格给的 grep

§11.5 的 A52 写的验法是

    grep -rE "anthropic|openai|/v1/(chat|messages|responses)" src/geo_audit/{checks,report}/

**它第一天就会误报。** 实测 ``checks/dead_links.py`` 里有一句注释是

    200 排除 x.com 整体反爬；baseten 的 ``x.com/basetenco`` 靠 openai / …

那是拿 openai 当 URL 举例的注释，不是 LLM 调用。文本 grep 分不出注释与代码，
于是门禁要么误报（然后被人 `|| true` 掉），要么放宽正则（然后漏掉真调用）。

所以这里改成走 **AST**：注释天然不在 AST 里。检查三件事 ——
import 了哪个模块、调用了哪个属性链、字符串里有没有 API 端点。
单纯提到 "openai" 这个词的文档串不算违规，``https://api.openai.com`` 算。
"""

from __future__ import annotations

import ast
import inspect
import typing
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "geo_audit"

#: 判定层：这两个目录下不许出现 LLM 调用。
JUDGEMENT_DIRS = ("checks", "report")

#: 已知的 LLM SDK 顶层模块名。
LLM_MODULES = frozenset({"anthropic", "openai", "google.generativeai", "cohere", "litellm"})

#: 字符串里出现即视为 API 端点（提到模块名不算，端点算）。
LLM_ENDPOINT_MARKERS = (
    "api.openai.com",
    "api.anthropic.com",
    "/v1/chat/completions",
    "/v1/messages",
    "/v1/responses",
    "generativelanguage.googleapis.com",
)


def _py_files(*rel: str) -> list[Path]:
    out: list[Path] = []
    for r in rel:
        out.extend(sorted((SRC / r).rglob("*.py")))
    return out


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in LLM_MODULES:
                    bad.append(f"{path.name}:{node.lineno} import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in LLM_MODULES:
                bad.append(f"{path.name}:{node.lineno} from {node.module} import …")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for marker in LLM_ENDPOINT_MARKERS:
                if marker in node.value:
                    bad.append(f"{path.name}:{node.lineno} 字符串含 API 端点 {marker!r}")
    return bad


def test_a52_judgement_layer_has_no_llm() -> None:
    """checks/ 与 report/ 下零 LLM 调用。"""
    files = _py_files(*JUDGEMENT_DIRS)
    assert files, f"扫不到文件，SRC 路径不对？{SRC}"
    bad = [v for f in files for v in _violations(f)]
    assert bad == [], (
        "判定层出现了 LLM 调用：\n  "
        + "\n  ".join(bad)
        + "\n判定必须是确定性的（§11.0）。要用 LLM，放到 ai/ 包里，"
        "把它的产出当**输入**传进 checks/，而不是让它当裁判。"
    )


def test_a52_gate_would_catch_a_real_import(tmp_path: Path) -> None:
    """闸门自检：真的 import 必须被抓到，只提到名字的注释/文档串不许误报。

    这条存在的理由是规格给的 grep 版本会把一句注释判成违规 —— 一个会误报的
    门禁最终会被 `|| true` 掉，等于没有。
    """
    real = tmp_path / "real.py"
    real.write_text("import openai\nx = openai.chat\n", encoding="utf-8")
    assert _violations(real), "真 import 没被抓到，门禁是坏的"

    innocent = tmp_path / "innocent.py"
    innocent.write_text(
        '"""baseten 的 x.com/basetenco 靠 openai 那条横幅才找得到。"""\n'
        "# 这里提到 anthropic 只是举例\n"
        'NOTE = "openai 是一个公司名"\n',
        encoding="utf-8",
    )
    assert _violations(innocent) == [], (
        f"注释/文档串里提到模块名被误判成违规：{_violations(innocent)}"
    )

    endpoint = tmp_path / "endpoint.py"
    endpoint.write_text('URL = "https://api.openai.com/v1/responses"\n', encoding="utf-8")
    assert _violations(endpoint), "字符串里的 API 端点没被抓到"


#: 名字里出现即视为 LLM 入口。**刻意不含裸 `client`** —— 实测
#: ``dead_links.classify_link`` 收的是 ``client: httpx.Client``，那是 HTTP 客户端，
#: 完全正当。按名字判会把它误报，而一个会误报的门禁最终会被 `|| true` 掉。
#: 判据落在**类型注解**上，名字只兜住明确无歧义的那几个。
LLM_PARAM_NAMES = frozenset({"llm", "llm_client", "model_client", "openai", "anthropic"})

#: 判定入口。前三个已存在，后三个是 v0.2–v0.4 落地后自动纳入。
JUDGE_CANDIDATES = (
    "classify_link",
    "check_ai_paths",
    "check_index_links",
    "reconcile",
    "attribute",
    "resolve_conflict",
)


def _signature_violations(fn: object, label: str) -> list[str]:
    bad: list[str] = []
    sig = inspect.signature(fn)  # type: ignore[arg-type]
    for pname, param in sig.parameters.items():
        if pname.lower() in LLM_PARAM_NAMES:
            bad.append(f"{label} 收了参数 {pname}")
        ann = param.annotation
        text = str(ann if isinstance(ann, str) else getattr(ann, "__name__", ann)).lower()
        hit = next((m for m in LLM_MODULES if m in text), None)
        if hit is not None:
            bad.append(f"{label}({pname}) 注解含 LLM 类型：{param.annotation}")
        if "ai.probe" in text:
            bad.append(f"{label}({pname}) 注解引用了 ai.probe（那是唯一真发调用的模块）")
    return bad


def test_a54_judgement_signatures_take_no_llm_client() -> None:
    """判定函数不许收到「能发 LLM 请求的东西」（§11.5 A54）。

    判据是**类型注解**，不是参数名。HTTP 客户端叫 client 是正常命名；
    真正要挡的是注解指向 LLM SDK 或 ``ai.probe`` 的参数。
    """
    from geo_audit.checks import ai_path, dead_links

    checked = 0
    bad: list[str] = []
    for mod in (ai_path, dead_links):
        for name in JUDGE_CANDIDATES:
            fn = getattr(mod, name, None)
            if fn is None or not callable(fn):
                continue
            checked += 1
            bad.extend(_signature_violations(fn, f"{mod.__name__}.{name}"))
    assert checked >= 2, f"一个判定入口都没查到（查了 {checked} 个），门禁是空跑的"
    assert bad == [], "判定函数签名里出现了 LLM client：\n  " + "\n  ".join(bad)


def test_a54_gate_catches_a_real_llm_param_and_spares_http() -> None:
    """闸门自检：LLM 类型的参数必须被抓到，``httpx.Client`` 不许被误报。

    第一版这条门禁按参数名判，把 ``classify_link(client: httpx.Client)`` 报成
    违规 —— 那是我自己写错了闸，不是代码有问题。留这条测试免得改回去。
    """
    import httpx

    def innocent(url: str, *, client: httpx.Client, fetcher: object = None) -> None:
        """HTTP 客户端叫 client 是正常命名。"""

    def guilty(url: str, *, llm_client: object) -> None:
        """名字明确是 LLM。"""

    def guilty_by_type(url: str, *, helper: openai.OpenAI) -> None:  # noqa: F821
        """注解指向 LLM SDK。"""

    assert _signature_violations(innocent, "innocent") == [], "httpx.Client 被误报成 LLM client"
    assert _signature_violations(guilty, "guilty"), "llm_client 参数没被抓到"
    assert _signature_violations(guilty_by_type, "guilty_by_type"), "LLM 类型注解没被抓到"


def test_ai_package_declares_the_boundary() -> None:
    """``ai/__init__.py`` 必须写明它是唯一允许 import LLM 的地方。

    不是为了好看：这条边界只有写在包的文档串里，下一个人加模块时才看得见。
    """
    import geo_audit.ai as ai_pkg

    doc = inspect.getdoc(ai_pkg) or ""
    for must in ("唯一允许", "裁判", "A53"):
        assert must in doc, f"ai/__init__.py 的文档串缺「{must}」这层意思"


@pytest.mark.parametrize("mod_name", ["geo_audit.checks.ai_path", "geo_audit.checks.dead_links"])
def test_judgement_modules_import_nothing_from_ai_probe(mod_name: str) -> None:
    """判定模块不许 import ``ai.probe``（那是唯一真发模型调用的模块）。

    允许 checks/ 用 ai/ 里的**纯数据类型**（比如 ModelAnswer），那是「把 LLM 的
    产出当输入」；不允许它拿到能发请求的东西 —— 那就是让裁判自己去问了。
    """
    mod = typing.cast("object", __import__(mod_name, fromlist=["_"]))
    src = Path(inspect.getfile(mod))  # type: ignore[arg-type]
    tree = ast.parse(src.read_text(encoding="utf-8"))
    bad = [
        f"{src.name}:{n.lineno}"
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and (n.module or "").endswith("ai.probe")
    ]
    assert bad == [], f"{mod_name} import 了 ai.probe：{bad}"
