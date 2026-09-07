#!/usr/bin/env python3
"""把 ``geo_audit.models.Report`` 的字段树转成 JSON Schema draft 2020-12（§8.5）。

规则（够用就行，不做通用 dataclass->schema 库）：
  str/int/float/bool          -> type
  X | None                    -> ["...", "null"]
  Literal[...] / str Enum     -> enum
  tuple[T, ...] / list[T]     -> array + items
  dict[str, T]                -> object + additionalProperties
  frozen dataclass            -> object + properties + required（无默认值的字段进 required）
输出 schema/report-1.schema.json。CI 的 lint job 跑
`python scripts/gen_schema.py --check` 断言文件与代码一致（不一致就红），
所以"改了 dataclass 忘了改 schema"这件事不可能发生。

（以上为 §8.5:4217-4226 原文。以下是实现说明。）

**为什么必须生成、不许手写**（卡点 B23）：`schema/report-1.schema.json` 是这个
工具**唯一的对外契约** —— v2 删掉了 `FindingDict`（原先自称「CLI --json 输出的
稳定公开契约」），理由是两份契约必然对不上、留着有一天会骗人。手抄一份 JSON
就是把 `FindingDict` 换个文件名请回来。

三点实现决定（规格没写，见交付说明）：

1. **根类按名字在模块表里查，不硬编码 import。** `SOURCE_MODULES` 里
   `geo_audit.models` 排在前面，`geo_audit.report.json_out` 在后。`Report` /
   `Position` / `Counts` 等 7 个类现在还在 `json_out.py` 的占位区里（写它们的
   agent 被禁止改 models.py），搬进 models.py 之后本文件**一行都不用改**。
2. **五处类型内省拿不到的约束走 `FIELD_OVERRIDES`**（const / pattern /
   minimum / severity_signals.required）。覆盖表自己也会漂移，所以
   `verify_skeleton()` 反过来断言每条 override 都真的落在了产出里 —— 字段一改名，
   `--check` 当场红。
3. **`bytes` 编码成 base64 字符串**（§8.5 的规则表没有 bytes，而
   `HttpResponse.body` 是 bytes）。与 `report/json_out.py` 的 `_encode` 同源。

`--check` 之外还有一道 `verify_skeleton()`：它把产出与 §8.5 骨架逐条对照
（20 项顶层 required 的**顺序**、五个 $defs 枚举的取值、三条硬约束）。生成器
自己写错也会红，不是只有「文件与代码不一致」才红。
"""

from __future__ import annotations

import dataclasses
import difflib
import importlib
import json
import sys
import types
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:  # 允许不装包直接 `python scripts/gen_schema.py`
    sys.path.insert(0, str(REPO_ROOT / "src"))

from geo_audit.models import SCHEMA_VERSION  # noqa: E402  —— 必须在 sys.path 之后

# --------------------------------------------------------------------------- #
# §8.5 骨架的字面量（行 4234–4297，逐字照抄）
# --------------------------------------------------------------------------- #

SCHEMA_PATH = REPO_ROOT / "schema" / "report-1.schema.json"

SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
#: 字面 OWNER —— §8.5:4236 就是这么写的，不许自己换成仓库名（换了 CI 的
#: check-jsonschema 与已发出去的报告里的 $id 就对不上了）。
SCHEMA_ID = "https://github.com/OWNER/geo-audit/schema/report-1.schema.json"
SCHEMA_TITLE = "geo-audit report v1"

TOP_REQUIRED = [
    "schema_version",
    "tool_version",
    "denoise_ruleset_version",
    "domain",
    "scanned_at",
    "duration_s",
    "contact",
    "user_agent",
    "headline",
    "verdict_kind",
    "positions",
    "findings",
    "root_causes",
    "naive_table",
    "fragilities",
    "coverage_gaps",
    "excluded",
    "apex_www",
    "coverage",
    "counts",
]

VERDICT_KIND_ENUM = ["has_fail", "zero_with_unknown", "zero_clean", "no_ai_channel", "unusable"]

DEFS_ENUMS = {
    "Status": ["pass", "fail", "unknown", "not_applicable"],
    "Severity": ["critical", "high", "medium", "low", "info"],
    "Stage": ["discovery", "index_file", "fulltext", "index_links", "md_channel", "human_path"],
    "PositionClass": ["sales_path", "doc_entry", "ai_channel", "nav", "body", "footer_social"],
    "FindingKind": ["soft_404", "llms_full_fake", "index_link_dead", "md_unfulfilled", "dead_link"],
}

POSITION_REQUIRED = ["position_id", "stage", "label", "probe_url", "status", "detail", "kind"]
POSITION_KIND_ENUM = ["probe", "aggregate"]
FINDING_REQUIRED = [
    "finding_id",
    "kind",
    "check_id",
    "title",
    "severity",
    "position_class",
    "stage",
    "target",
]
FINDING_ID_PATTERN = r"^GA-[0-9A-F]{10}$"
CONFIDENCE_ENUM = ["confirmed", "needs_review"]
SEVERITY_SIGNALS_REQUIRED = ["page_role", "anchor", "anchor_class", "region"]
COUNTS_REQUIRED = [
    "positions",
    "positions_pass",
    "positions_fail",
    "positions_unknown",
    "positions_na",
    "findings",
    "findings_counted",
    "occurrences",
    "root_causes",
    "by_severity",
    "naive_divergences",
]

#: §3.7 的 tier / 预算四字段。它们刚从 `discovery.TieredSiteMap` 子类搬进
#: `models.SiteMap`，**正是为了让 schema 能看到它们**（models.py 的注释写明了
#: 这条理由）。§2.10 的 `Report` 并不引用 `SiteMap`，所以这里把它作为**第二个
#: $defs 根**显式带进契约 —— 见交付说明 deviations。
SITEMAP_BUDGET_FIELDS = ["tiers_run", "requests_spent", "budget_exhausted", "skipped_by_budget"]

# --------------------------------------------------------------------------- #
# 类型来源
# --------------------------------------------------------------------------- #

#: 按优先级排列。前面的模块里有同名 dataclass 就用前面的 —— 占位类搬进
#: models.py 之后，本文件不用改一行。
SOURCE_MODULES = ("geo_audit.models", "geo_audit.report.json_out")

ROOT_CLASS_NAME = "Report"
#: 除根类之外还要进 $defs 的类（理由见 SITEMAP_BUDGET_FIELDS）。
EXTRA_DEFS_ROOTS = ("SiteMap",)

#: §8.5 骨架把这些字段写成**内联** enum（行 4245、4266、4285），即使它们的
#: Literal 后来被抽成模块级别名（第 16 步的 pipeline.py 占位里就已经有一个
#: `VerdictKind = Literal[...]`）也不许改成 $ref —— 否则 `verdict_kind` 的形状
#: 会随「有没有人给它起过名字」变化，而那是对外契约的形状。
INLINE_LITERAL_FIELDS = frozenset(
    {("Report", "verdict_kind"), ("Position", "kind"), ("Finding", "confidence")}
)

#: 类型内省拿不到的五处约束（§8.5:4244 / 4267 / 4275 / 4283 / 4290）。
#: 键是 (类名, 字段名)。`verify_skeleton()` 断言每一条都真落进了产出。
FIELD_OVERRIDES: dict[tuple[str, str], dict[str, Any]] = {
    ("Report", "schema_version"): {"const": SCHEMA_VERSION},
    ("Counts", "llm_calls"): {"const": 0},
    ("Finding", "finding_id"): {"type": "string", "pattern": FINDING_ID_PATTERN},
    ("Finding", "occurrences"): {"type": "integer", "minimum": 1},
    # §8.5:4287 骨架把 detail 写成裸 object：值类型是 `str | int | float | bool`
    # 的四支联合，写进 additionalProperties 会让契约比骨架严。
    ("Finding", "detail"): {"type": "object"},
    ("Finding", "severity_signals"): {"type": "object", "required": SEVERITY_SIGNALS_REQUIRED},
    ("Position", "aggregate_of"): {"type": "integer", "minimum": 1},
}

_NONE_TYPE = type(None)
_UNION_ORIGINS = (types.UnionType, Union)
_SCALARS: dict[Any, dict[str, Any]] = {
    bool: {"type": "boolean"},  # 必须排在 int 前面：bool 是 int 的子类
    int: {"type": "integer"},
    float: {"type": "number"},
    str: {"type": "string"},
    bytes: {"type": "string", "contentEncoding": "base64"},
}


class SchemaGenError(RuntimeError):
    """生成器遇到规则表没覆盖的类型。绝不悄悄发一个空 schema。"""


def _modules() -> list[types.ModuleType]:
    mods = []
    for name in SOURCE_MODULES:
        try:
            mods.append(importlib.import_module(name))
        except ImportError:  # pragma: no cover —— 占位模块被删/搬走时的正常情况
            continue
    if not mods:
        raise SchemaGenError(f"一个都 import 不到：{SOURCE_MODULES}")
    return mods


def dataclasses_in(module: types.ModuleType) -> dict[str, type]:
    """模块里**自己定义**的 dataclass（import 进来的不算）。

    按名字遍历而不是硬编码类列表：这是「占位类搬进 models.py 后零改动」的
    全部实现（§9 第 15c 步的要求）。
    """
    found: dict[str, type] = {}
    for name, obj in vars(module).items():
        if (
            isinstance(obj, type)
            and dataclasses.is_dataclass(obj)
            and obj.__module__ == module.__name__
        ):
            found[name] = obj
    return found


def resolve_class(name: str) -> type:
    """按 ``SOURCE_MODULES`` 的优先级找一个 dataclass。"""
    for module in _modules():
        found = dataclasses_in(module)
        if name in found:
            return found[name]
    raise SchemaGenError(
        f"在 {SOURCE_MODULES} 里都找不到 dataclass `{name}` —— "
        "它要么还没落地，要么被搬到了别的模块（改 SOURCE_MODULES）"
    )


def literal_aliases() -> dict[tuple[Any, ...], str]:
    """模块级 ``Literal`` 别名 -> 名字（``FindingKind`` / ``Reason``）。

    ``get_type_hints`` 之后别名的名字就丢了（`Literal["a","b"]` 与
    `FindingKind` 是同一个对象），拿不到「FindingKind」这个名字去发 $ref。
    这里反查一遍模块的顶层，同样是「遍历模块」而不是硬编码一张表：
    §2.5 再加一个别名，生成器自动认。

    Report 里的**内联** Literal（`verdict_kind` / `Position.kind` /
    `confidence`）取值集合与任何别名都不同，所以照 §8.5 骨架留在原地当内联
    enum，不会被误认成别名。
    """
    aliases: dict[tuple[Any, ...], str] = {}
    for module in _modules():
        for name, obj in vars(module).items():
            if get_origin(obj) is Literal:
                aliases.setdefault(get_args(obj), name)
    return aliases


# --------------------------------------------------------------------------- #
# 类型 -> schema 片段
# --------------------------------------------------------------------------- #


def enum_schema(cls: type[Enum]) -> dict[str, Any]:
    """``str`` 枚举 -> ``{"enum": [...]}``，取值顺序 = 声明顺序。"""
    return {"enum": [member.value for member in cls]}


def _nullable(sub: dict[str, Any]) -> dict[str, Any]:
    """``X | None``。标量走 ``type: [..., "null"]``，$ref / enum 走 anyOf。

    ``evidence`` 那一支的 anyOf 形状是 §8.5:4271 骨架给的。
    """
    if "$ref" in sub or "enum" in sub or "const" in sub:
        return {"anyOf": [sub, {"type": "null"}]}
    kind = sub["type"]
    types_list = list(kind) if isinstance(kind, list) else [kind]
    return {**sub, "type": [*types_list, "null"]}


def json_type(
    tp: Any, *, defs: dict[str, Any], where: str, use_aliases: bool = True
) -> dict[str, Any]:
    """一个字段类型 -> 一个 schema 片段。``where`` 只用于报错定位。

    ``use_aliases=False`` 时 Literal 一律发内联 enum，不查别名表
    （``INLINE_LITERAL_FIELDS`` 用它把骨架里的内联 enum 钉死）。
    """
    origin = get_origin(tp)

    if origin in _UNION_ORIGINS:
        args = get_args(tp)
        non_none = [a for a in args if a is not _NONE_TYPE]
        optional = len(non_none) != len(args)
        if len(non_none) == 1:
            sub = json_type(non_none[0], defs=defs, where=where)
            return _nullable(sub) if optional else sub
        # 多支标量联合（`dict[str, str | int | float | bool]` 的值类型）。
        # 规则表没有这一条，但它在 Finding.detail 上真实存在；合成一个
        # `type: [...]` 是无歧义的，比 raise 更有用（见交付说明）。
        kinds: list[str] = []
        for branch in non_none:
            sub = json_type(branch, defs=defs, where=where)
            if list(sub) != ["type"] or not isinstance(sub["type"], str):
                raise SchemaGenError(f"{where}：联合里有非标量分支 {branch!r}，规则表没覆盖")
            kinds.append(sub["type"])
        if optional:
            kinds.append("null")
        return {"type": kinds}

    if origin is Literal:
        args = get_args(tp)
        alias = literal_aliases().get(args) if use_aliases else None
        if alias is not None:
            defs.setdefault(alias, {"enum": list(args)})
            return {"$ref": f"#/$defs/{alias}"}
        return {"enum": list(args)}

    if origin in (tuple, list):
        args = get_args(tp)
        homogeneous = origin is list or (len(args) == 2 and args[1] is Ellipsis)
        if homogeneous:
            return {"type": "array", "items": json_type(args[0], defs=defs, where=where)}
        # 定长异质 tuple（`SiteMap.pricing_candidates_tried` 是
        # `tuple[tuple[str, Verdict], ...]`）。draft 2020-12 用 prefixItems +
        # min/maxItems 表达「恰好这几项、逐位定型」；规则表没这一条，见交付说明。
        return {
            "type": "array",
            "prefixItems": [json_type(a, defs=defs, where=where) for a in args],
            "minItems": len(args),
            "maxItems": len(args),
        }

    if origin is dict:
        key_tp, val_tp = get_args(tp)
        if key_tp is not str:
            raise SchemaGenError(f"{where}：契约只支持 dict[str, T]，拿到 {tp}")
        return {
            "type": "object",
            "additionalProperties": json_type(val_tp, defs=defs, where=where),
        }

    if isinstance(tp, type):
        for scalar, frag in _SCALARS.items():
            if tp is scalar:
                return dict(frag)
        if issubclass(tp, Enum):
            defs.setdefault(tp.__name__, enum_schema(tp))
            return {"$ref": f"#/$defs/{tp.__name__}"}
        if dataclasses.is_dataclass(tp):
            name = tp.__name__
            if name not in defs:
                defs[name] = {}  # 先占位，防自引用类型无限递归
                defs[name] = dataclass_schema(tp, defs=defs)
            return {"$ref": f"#/$defs/{name}"}

    raise SchemaGenError(f"{where}：规则表没覆盖的类型 {tp!r}")


def dataclass_schema(cls: type, *, defs: dict[str, Any]) -> dict[str, Any]:
    """frozen dataclass -> object + properties + required。

    required = **无默认值**的字段（§8.5:4225）。``additionalProperties: false``
    是骨架对 Position / Finding / Counts / 顶层都写了的，这里对每个 dataclass
    一律加上：对外契约多一个字段就该红，不该被静默接受。
    """
    hints = get_type_hints(cls)
    props: dict[str, Any] = {}
    for f in dataclasses.fields(cls):
        override = FIELD_OVERRIDES.get((cls.__name__, f.name))
        if override is not None:
            props[f.name] = dict(override)
            continue
        props[f.name] = json_type(
            hints[f.name],
            defs=defs,
            where=f"{cls.__name__}.{f.name}",
            use_aliases=(cls.__name__, f.name) not in INLINE_LITERAL_FIELDS,
        )
    required = [
        f.name
        for f in dataclasses.fields(cls)
        if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
    ]
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": props,
        "required": required,
    }


def build_schema() -> dict[str, Any]:
    """顶层：返回 §8.5 骨架那棵树。"""
    defs: dict[str, Any] = {}
    root = dataclass_schema(resolve_class(ROOT_CLASS_NAME), defs=defs)
    for name in EXTRA_DEFS_ROOTS:
        json_type(resolve_class(name), defs=defs, where=f"<extra:{name}>")
    return {
        "$schema": SCHEMA_DIALECT,
        "$id": SCHEMA_ID,
        "title": SCHEMA_TITLE,
        **root,
        "$defs": defs,
    }


# --------------------------------------------------------------------------- #
# 与 §8.5 骨架逐条对照
# --------------------------------------------------------------------------- #


def _at(schema: dict[str, Any], cls_name: str, field_name: str) -> Any:
    """取 ``cls_name.field_name`` 的 schema 片段（根类走顶层 properties）。"""
    holder = schema if cls_name == ROOT_CLASS_NAME else schema["$defs"].get(cls_name, {})
    return holder.get("properties", {}).get(field_name)


def verify_skeleton(schema: dict[str, Any]) -> list[str]:
    """返回与 §8.5 骨架不符之处；空列表 = 全对。

    存在的理由：`--check` 只保证「文件 == 代码」，它不保证「代码 == 规格」。
    dataclass 改一个字段名、覆盖表忘了跟，`--check` 只会让人 `gen_schema.py`
    重写一遍就绿了 —— 那正是漂移。这里把骨架的 20 项 required（含顺序）、
    五个枚举的取值、三条硬约束、七条 override 全部钉住。
    """
    bad: list[str] = []

    def want(label: str, got: Any, expected: Any) -> None:
        if got != expected:
            bad.append(f"{label}：产出 {got!r}，§8.5 要 {expected!r}")

    want("$schema", schema.get("$schema"), SCHEMA_DIALECT)
    want("$id", schema.get("$id"), SCHEMA_ID)
    want("title", schema.get("title"), SCHEMA_TITLE)
    want("type", schema.get("type"), "object")
    want("additionalProperties", schema.get("additionalProperties"), False)
    want("required", schema.get("required"), TOP_REQUIRED)

    defs = schema.get("$defs", {})
    for name, values in DEFS_ENUMS.items():
        want(f"$defs/{name}", defs.get(name), {"enum": values})

    want("verdict_kind", _at(schema, "Report", "verdict_kind"), {"enum": VERDICT_KIND_ENUM})
    for field_name, ref in (
        ("positions", "Position"),
        ("findings", "Finding"),
        ("root_causes", "RootCause"),
    ):
        want(
            field_name,
            _at(schema, "Report", field_name),
            {"type": "array", "items": {"$ref": f"#/$defs/{ref}"}},
        )
    want("counts", _at(schema, "Report", "counts"), {"$ref": "#/$defs/Counts"})

    want(
        "Position/additionalProperties", defs.get("Position", {}).get("additionalProperties"), False
    )
    want("Position/required", defs.get("Position", {}).get("required"), POSITION_REQUIRED)
    want("Position.kind", _at(schema, "Position", "kind"), {"enum": POSITION_KIND_ENUM})
    want("Position.stage", _at(schema, "Position", "stage"), {"$ref": "#/$defs/Stage"})
    want("Position.status", _at(schema, "Position", "status"), {"$ref": "#/$defs/Status"})
    for field_name in ("unknown_reason", "unknown_remedy"):
        want(
            f"Position.{field_name}",
            _at(schema, "Position", field_name),
            {"type": ["string", "null"]},
        )
    want(
        "Position.evidence",
        _at(schema, "Position", "evidence"),
        {"anyOf": [{"$ref": "#/$defs/Evidence"}, {"type": "null"}]},
    )
    want(
        "Position.finding_ids",
        _at(schema, "Position", "finding_ids"),
        {"type": "array", "items": {"type": "string"}},
    )

    want("Finding/additionalProperties", defs.get("Finding", {}).get("additionalProperties"), False)
    want("Finding/required", defs.get("Finding", {}).get("required"), FINDING_REQUIRED)
    want("Finding.kind", _at(schema, "Finding", "kind"), {"$ref": "#/$defs/FindingKind"})
    want("Finding.severity", _at(schema, "Finding", "severity"), {"$ref": "#/$defs/Severity"})
    want(
        "Finding.position_class",
        _at(schema, "Finding", "position_class"),
        {"$ref": "#/$defs/PositionClass"},
    )
    want("Finding.counted_as_hit", _at(schema, "Finding", "counted_as_hit"), {"type": "boolean"})
    want("Finding.confidence", _at(schema, "Finding", "confidence"), {"enum": CONFIDENCE_ENUM})
    want(
        "Finding.exposure_pages",
        _at(schema, "Finding", "exposure_pages"),
        {"type": "array", "items": {"type": "string"}},
    )
    want("Finding.target", _at(schema, "Finding", "target"), {"$ref": "#/$defs/Evidence"})

    want("Counts/additionalProperties", defs.get("Counts", {}).get("additionalProperties"), False)
    want("Counts/required", defs.get("Counts", {}).get("required"), COUNTS_REQUIRED)

    # 三条硬约束（§8.5:4301-4303）+ 其余四条 override：每条都必须真落进产出。
    for (cls_name, field_name), frag in FIELD_OVERRIDES.items():
        want(f"override {cls_name}.{field_name}", _at(schema, cls_name, field_name), frag)

    # SiteMap 的四个 tier / 预算字段（models.py 把它们从子类搬进来就是为了这个）。
    sitemap_props = defs.get("SiteMap", {}).get("properties", {})
    missing = [f for f in SITEMAP_BUDGET_FIELDS if f not in sitemap_props]
    if missing:
        bad.append(f"$defs/SiteMap 缺 tier/预算字段 {missing}（§3.7 / models.SiteMap 的注释）")

    return bad


def render(schema: dict[str, Any]) -> str:
    """schema -> 磁盘上的字节。``sort_keys`` 让产出不随字段声明顺序抖动。"""
    return json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


USAGE = "用法：python scripts/gen_schema.py [--check]"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    unknown = [a for a in args if a != "--check"]
    if unknown:
        print(f"不认识的参数 {unknown}。{USAGE}", file=sys.stderr)
        return 2
    check = "--check" in args

    schema = build_schema()
    problems = verify_skeleton(schema)
    if problems:
        print("产出与 §8.5 骨架不符，schema 未写盘：", file=sys.stderr)
        for line in problems:
            print(f"  - {line}", file=sys.stderr)
        return 1

    want = render(schema)
    if check:
        if not SCHEMA_PATH.exists():
            print(
                f"{SCHEMA_PATH} 不存在。跑一次 `python scripts/gen_schema.py` 生成。",
                file=sys.stderr,
            )
            return 1
        have = SCHEMA_PATH.read_text(encoding="utf-8")
        if have != want:
            print(
                "".join(
                    difflib.unified_diff(
                        have.splitlines(True),
                        want.splitlines(True),
                        "schema/report-1.schema.json（磁盘）",
                        "generated（当前 dataclass）",
                    )
                ),
                file=sys.stderr,
            )
            print(
                "dataclass 与 schema 不一致。跑 `python scripts/gen_schema.py` 重新生成，"
                "并把 schema 的变化当成对外契约变更来 review。",
                file=sys.stderr,
            )
            return 1
        return 0

    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(want, encoding="utf-8")
    shown = SCHEMA_PATH
    if SCHEMA_PATH.is_relative_to(REPO_ROOT):  # 测试会把 SCHEMA_PATH 指到 tmp_path
        shown = SCHEMA_PATH.relative_to(REPO_ROOT)
    print(f"已写 {shown}（{len(want)} 字节）")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
