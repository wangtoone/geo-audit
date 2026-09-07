# 参与开发

## fixture 纪律

`fixtures/` 下是冻结的第三方 HTTP 快照，是全部判定规则的客观裁判。

**不许把字面量摘要（md5、字节数）写进测试**——一律放进 `fixtures/index.json` 的
`expect` 块，测试从那里读。`test_no_hardcoded_digests_in_tests` 用 grep 守着这条。

活网漂移的四分支规程（§8.1）在第 4a 步随 `fixtures.py` 一起落地。

## 提交前

```bash
uv sync --extra dev
uv run ruff check . && uv run ruff format --check . && uv run mypy
GEO_AUDIT_FORBID_NETWORK=1 GEO_AUDIT_FORBID_DNS=1 uv run pytest -m "not live"
```
