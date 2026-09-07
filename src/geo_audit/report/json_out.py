"""JSON 报告的序列化与反序列化（§8.5 / A44）。

**这是 `--format json` 的唯一序列化器。** 对外契约只有一份：
`schema/report-1.schema.json`，由 `scripts/gen_schema.py` 从本文件（或搬入
`models.py` 之后的）dataclass 树生成，CI 跑 `--check` 防漂移。所以这里的编码
规则与生成器的类型规则**必须一一对应**，改一处就要改另一处，`--check` 会当场
把不一致打出来。

对应关系（左边是 Python 类型，右边是 JSON 形态 + schema 片段）：

    str / int / float / bool    -> 同名标量           {"type": ...}
    None                        -> null              {"type": [..., "null"]}
    Enum(str, Enum)             -> 成员的 .value      {"enum": [...]}
    Literal[...]                -> 字面量             {"enum": [...]}
    tuple[T, ...] / list[T]     -> array              {"type": "array", "items": ...}
    dict[str, T]                -> object            {"type": "object", "additionalProperties": ...}
    frozen dataclass            -> object            {"properties": ..., "required": ...}
    bytes                       -> base64 字符串      {"type": "string",
                                                    "contentEncoding": "base64"}

`bytes` 那一行是本文件自己定的（§8.5 的规则表没有 bytes，而
``HttpResponse.body`` 是 bytes —— 见交付说明 deviations/spec_gaps）。选 base64
而不是 §2.10 ``Report.to_json()`` 的 ``default=str``：``default=str`` 出来的是
``"b'<!doctype html>…'"`` 这种 repr，``--from``（A44）反序列化不回去，等于对外
契约里有一个只能看不能用的字段。

反序列化（``--from``）的失败一律抛 ``SchemaMismatchError``，CLI 据此退出 4。
"""

from __future__ import annotations

import base64
import dataclasses
import json
import types
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints

from geo_audit.models import (
    SCHEMA_VERSION,
    VOLATILE_JSON_FIELDS,
    Counts,
    Coverage,
    CoverageGap,
    Exclusion,
    Fragility,
    Position,
    Report,
)

# ═════════════════════════════════════════════════════════════════════════════
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║ 占位区结束 —— PLACEHOLDER BLOCK END                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
# ═════════════════════════════════════════════════════════════════════════════


class SchemaMismatchError(ValueError):
    """``--from`` 的文件与本版本的契约对不上。CLI 据此退出 4。

    触发条件：``schema_version`` 不等于 ``models.SCHEMA_VERSION``，或字段树
    对不上（多字段、缺无默认值的字段、类型不符、枚举取值不在表内）。
    **不做静默宽容** —— 悄悄吃掉不认识的字段会让「我读到的报告」与「文件里的
    报告」是两个东西。
    """


#: JSON 里 bytes 字段的编码方式。与 gen_schema.json_type 的 bytes 分支同源。
BYTES_ENCODING = "base64"

_NONE_TYPE = type(None)
_UNION_ORIGINS = (types.UnionType, Union)


# --------------------------------------------------------------------------- #
# 序列化
# --------------------------------------------------------------------------- #


def _encode(value: Any, *, path: str) -> Any:
    """把 dataclass 树递归转成 json 模块认得的原生对象。

    不用 ``dataclasses.asdict`` + ``default=str``：那条路对 bytes 与 Enum 的
    产出取决于 json 编码器的隐式行为（``str`` 子类的枚举会漏成成员值、bytes
    会漏成 repr），而对外契约不能建在隐式行为上。
    """
    # Enum 必须在 str 之前判：``class Status(str, Enum)`` 的成员 **是** str。
    if isinstance(value, Enum):
        return value.value
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            f.name: _encode(getattr(value, f.name), path=f"{path}.{f.name}")
            for f in dataclasses.fields(value)
        }
    if isinstance(value, list | tuple):
        return [_encode(v, path=f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        return {str(k): _encode(v, path=f"{path}.{k}") for k, v in value.items()}
    raise TypeError(f"{path}：不知道怎么把 {type(value).__name__} 放进 JSON 契约")


def report_to_json(report: Report) -> str:
    """报告 -> JSON 文本（末尾带换行）。

    ``sort_keys=True`` 是确定性的一半（另一半是 L 组的 ``strip_volatile``）：
    键序不许随 dataclass 字段顺序变化，否则「连跑两次逐字节相同」会被一次无关
    的字段重排搞红。
    """
    payload = _encode(report, path="$")
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_json(report: Report, path: str | Path) -> Path:
    """把报告写到 ``path``（父目录不存在就建），返回写入的路径。"""
    out = Path(path)
    if out.parent != Path():
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report_to_json(report), encoding="utf-8")
    return out


# --------------------------------------------------------------------------- #
# 反序列化（--from，A44）
# --------------------------------------------------------------------------- #


def _decode_union(tp: Any, value: Any, *, path: str) -> Any:
    args = get_args(tp)
    non_none = [a for a in args if a is not _NONE_TYPE]
    if value is None:
        if len(non_none) != len(args):
            return None
        raise SchemaMismatchError(f"{path}：这个字段不允许 null")
    if len(non_none) == 1:
        return _decode(non_none[0], value, path=path)
    # 多支标量联合（``dict[str, str | int | float | bool]`` 的值类型）：
    # 按实际值挑一支。bool 必须先试，它是 int 的子类。
    for candidate in sorted(non_none, key=lambda a: a is not bool):
        if isinstance(candidate, type) and type(value) is candidate:
            return _decode(candidate, value, path=path)
    raise SchemaMismatchError(f"{path}：{type(value).__name__} 不属于 {tp}")


def _decode_dataclass(cls: Any, value: Any, *, path: str) -> Any:
    if not isinstance(value, dict):
        raise SchemaMismatchError(f"{path}：期望 object，拿到 {type(value).__name__}")
    hints = get_type_hints(cls)
    known = {f.name for f in dataclasses.fields(cls)}
    extra = sorted(set(value) - known)
    if extra:
        raise SchemaMismatchError(f"{path}：{cls.__name__} 不认识这些字段 {extra}")
    kwargs: dict[str, Any] = {}
    for f in dataclasses.fields(cls):
        if f.name not in value:
            has_default = (
                f.default is not dataclasses.MISSING or f.default_factory is not dataclasses.MISSING
            )
            if has_default:
                continue
            raise SchemaMismatchError(f"{path}：{cls.__name__} 缺必填字段 {f.name}")
        kwargs[f.name] = _decode(hints[f.name], value[f.name], path=f"{path}.{f.name}")
    return cls(**kwargs)


def _decode_scalar(tp: type, value: Any, *, path: str) -> Any:
    if tp is bool:
        if not isinstance(value, bool):
            raise SchemaMismatchError(f"{path}：期望 boolean，拿到 {type(value).__name__}")
        return value
    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SchemaMismatchError(f"{path}：期望 integer，拿到 {type(value).__name__}")
        return value
    if tp is float:
        # JSON 的 1 与 1.0 是同一个数，整数字面量必须接受，否则往返会假红。
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise SchemaMismatchError(f"{path}：期望 number，拿到 {type(value).__name__}")
        return float(value)
    if tp is str:
        if not isinstance(value, str):
            raise SchemaMismatchError(f"{path}：期望 string，拿到 {type(value).__name__}")
        return value
    if tp is bytes:
        if not isinstance(value, str):
            raise SchemaMismatchError(f"{path}：期望 base64 string，拿到 {type(value).__name__}")
        try:
            return base64.b64decode(value.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError) as exc:
            raise SchemaMismatchError(f"{path}：不是合法的 base64（{exc}）") from exc
    raise SchemaMismatchError(f"{path}：契约里不该出现 {tp!r}")


def _decode(tp: Any, value: Any, *, path: str) -> Any:
    """按类型注解把原生 JSON 对象还原成 dataclass 树。

    与 ``_encode`` / ``gen_schema.json_type`` 的分支表逐条对应。
    """
    origin = get_origin(tp)
    if origin in _UNION_ORIGINS:
        return _decode_union(tp, value, path=path)
    if origin is Literal:
        allowed = get_args(tp)
        if value not in allowed:
            raise SchemaMismatchError(f"{path}：{value!r} 不在 {list(allowed)} 里")
        return value
    if origin in (tuple, list):
        if not isinstance(value, list):
            raise SchemaMismatchError(f"{path}：期望 array，拿到 {type(value).__name__}")
        args = get_args(tp)
        if origin is list or (len(args) == 2 and args[1] is Ellipsis):
            item_tp = args[0]
            items = [_decode(item_tp, v, path=f"{path}[{i}]") for i, v in enumerate(value)]
            return tuple(items) if origin is tuple else items
        # 定长异质 tuple（`SiteMap.pricing_candidates_tried` 那种）。schema 侧是
        # prefixItems + min/maxItems，这里就得逐位定型。
        if len(value) != len(args):
            raise SchemaMismatchError(f"{path}：期望 {len(args)} 项，拿到 {len(value)} 项")
        return tuple(
            _decode(a, v, path=f"{path}[{i}]")
            for i, (a, v) in enumerate(zip(args, value, strict=True))
        )
    if origin is dict:
        if not isinstance(value, dict):
            raise SchemaMismatchError(f"{path}：期望 object，拿到 {type(value).__name__}")
        key_tp, val_tp = get_args(tp)
        if key_tp is not str:
            raise SchemaMismatchError(f"{path}：契约只支持 dict[str, T]，拿到 {tp}")
        return {k: _decode(val_tp, v, path=f"{path}.{k}") for k, v in value.items()}
    if isinstance(tp, type):
        if issubclass(tp, Enum):
            try:
                return tp(value)
            except ValueError as exc:
                raise SchemaMismatchError(f"{path}：{value!r} 不是 {tp.__name__} 的取值") from exc
        if dataclasses.is_dataclass(tp):
            return _decode_dataclass(tp, value, path=path)
        return _decode_scalar(tp, value, path=path)
    raise SchemaMismatchError(f"{path}：不支持的类型注解 {tp!r}")


def report_from_json(text: str) -> Report:
    """``--from`` 的反序列化。

    先卡 ``schema_version``、再逐字段还原。**版本先卡**：跨版本的文件字段树
    大概率也对不上，但那时报「字段 X 不认识」是误导，真实原因是版本不同。
    """
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaMismatchError(f"不是合法 JSON：{exc}") from exc
    if not isinstance(payload, dict):
        raise SchemaMismatchError(f"报告根必须是 object，拿到 {type(payload).__name__}")
    got = payload.get("schema_version")
    if got != SCHEMA_VERSION:
        raise SchemaMismatchError(f"schema_version 是 {got!r}，本版本只认 {SCHEMA_VERSION!r}")
    decoded = _decode(Report, payload, path="$")
    if not isinstance(decoded, Report):  # pragma: no cover —— 防御性，_decode 已保证
        raise SchemaMismatchError("反序列化没有得到 Report")
    return decoded


def load_report(path: str | Path) -> Report:
    """从磁盘读一份 JSON 报告（``--from``）。读不到文件让 OSError 直接冒出去。"""
    return report_from_json(Path(path).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# 确定性比对（L 组，A45）
# --------------------------------------------------------------------------- #


def strip_volatile(obj: Any) -> Any:
    """递归剔掉 ``models.VOLATILE_JSON_FIELDS`` 里的键，返回新对象。

    这些字段随环境变化（时间戳、耗时、缓存命中、用了哪个 resolver、解析到哪些
    IP、发了几个请求），留着比对必红；剔掉之后「同一份 fixture 连跑两次逐字节
    相同」才是在测确定性而不是在测时钟。

    只按**键名**剔，不看层级 —— 名单里的键名在契约里各只有一个含义
    （``fetched_at`` 在 Evidence 与 HttpResponse 里都是「什么时候抓的」）。
    """
    if isinstance(obj, dict):
        return {k: strip_volatile(v) for k, v in obj.items() if k not in VOLATILE_JSON_FIELDS}
    if isinstance(obj, list):
        return [strip_volatile(v) for v in obj]
    return obj


__all__ = [
    "BYTES_ENCODING",
    "Counts",
    "Coverage",
    "CoverageGap",
    "Exclusion",
    "Fragility",
    "Position",
    "Report",
    "SchemaMismatchError",
    "load_report",
    "report_from_json",
    "report_to_json",
    "strip_volatile",
    "write_json",
]
