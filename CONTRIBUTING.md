# 参与开发

## 提交前

```bash
uv sync --extra dev
uv run ruff check . && uv run ruff format --check . && uv run mypy
GEO_AUDIT_FORBID_NETWORK=1 GEO_AUDIT_FORBID_DNS=1 uv run pytest -m "not live"
```

两把断网闸都要设。DNS 不走 httpx，所以 `GEO_AUDIT_FORBID_NETWORK` 拦不住它，
`GEO_AUDIT_FORBID_DNS` 是单独的一把。**任何一条测试想摸真网络都应该当场失败**，
而不是在别人的机器上偶发地绿。

## lint 的规矩

`[tool.ruff]` 的 `ignore` 只有 `S101 RUF001 RUF002 RUF003 UP042` 五条，
每条在 `pyproject.toml` 里都写了为什么。

**lint 挡路时改代码，不改配置。** `src/` 里不许撒 `noqa`。
一条规则真的误报到没法改代码，那是一个 issue + reviewer 确认的事，不是顺手加一行。

`tests/test_classify.py`、`tests/test_infra.py`、`tests/fixtures/real_cases.py`
在 `extend-exclude` 里：它们是搬入前逐字节冻结的 ground truth，
formatter 排一次 import 就破了「与搬入前 0 行差异」这条验收。别对它们跑
`ruff check --fix` 或 `ruff format`。

同理，**永远不要跑 `ruff format .` 或 `ruff check . --fix`**，只对自己改的文件跑。

## fixture 纪律

`fixtures/` 下是冻结的第三方 HTTP 快照，是全部判定规则的客观裁判。
存的是完整响应（含 headers）、**逐跳单独存**，DNS 答案也冻结在 `fixtures/dns.json`。

**不许把字面量摘要（md5、字节数）写进测试** —— 一律放进 `fixtures/index.json` 的
`expect` 块，测试从那里读（`FixtureStore.expect()`）。
`test_no_hardcoded_digests_in_tests` 用 grep 守着这条。

补录快照：先把 URL 加进 `fixtures/urls.txt`（语法见文件头的注释：
裸 URL / `@control` / `@expand` / `@pair`），然后

```bash
python scripts/capture_fixtures.py --contact you@example.com --from-file fixtures/urls.txt
python scripts/capture_fixtures.py --contact you@example.com --from-file fixtures/urls.txt --dns-only
```

`urls.txt` 里出现过的每个 host 都必须在 `dns.json` 里有条目。
不在表里的 host 走 `_default_absent`（NXDOMAIN）—— 这是「不存在的子域花 0 个 HTTP
请求」那条逻辑的测试面，但它也意味着**「我们没录」和「站点没有」在 replay 下长得
一模一样**。所以漏录一个 host 不会报错，只会让报告替站点说一句我们没验证过的话。

已冻结的快照默认**不覆盖**（`put_snapshot(overwrite=False)`）。覆盖它等于改测试：
要覆盖必须显式 `--overwrite`，且单独一个 commit，message 前缀 `fixture:`。

### 活网漂移的四分支（§8.1）

`scripts/refresh_fixtures.py --check` 对活网重抓并 diff（`fixture-freshness.yml`
每周一跑一次，**只开 issue，不阻塞 PR**）。有漂移时按现象分四种处理，
判据与文案的唯一定义处是 `fixtures.DRIFT_PLAYBOOK`：

| `drift.phenomenon` | 情况 | 怎么办 |
|---|---|---|
| `unchanged` | 值变了、现象没变 | 更新 `index.json` 的 `expect`，断言照样从 `expect` 读。普通 PR，commit 前缀 `fixture:` |
| `gone` | 现象没了（站方修好了） | **不改断言**：标 `gone` + 给用例加 `pytest.mark.xfail(strict=True)`，CHANGELOG 记一行「现象已被站方修复，回归用例转为历史留档」。需要一个 issue + reviewer 确认 |
| `unreachable` | 拿不到了（403 / 超时 / 域名没了） | 标 `unreachable`，继续用旧快照跑 —— 这正是冻结的意义。无需批准 |
| `presigned_expiring` | 必然过期的预签名 URL | fixture 就是过期后的状态；规则只看 URL 不看响应 |

把「现象没了」处理成「改断言让它绿」，就是把回归测试变成许愿池。别这么干。

## 报告与文案

报告是**单个 HTML 文件**：零外部请求、零 JS、零 webfont。`render_html` 渲染即校验，
三道闸门都在渲染期生效（不是只在测试里）：

1. `assert_selfcontained` —— 五条禁止正则 + 2 MB 上限；
2. `assert_no_banned_words` —— 附录 B 的禁词，**扫描面是 `our_copy_corpus(report)`
   （我们自己写的每一个字）**，不扫甲方页面回显的数据。甲方站点上出现禁词不该让
   报告产不出来 —— 那是引用，不是我们的结论；
3. `assert_counts_identity` —— 四格之和恒等于位置数。

⚠️ `_defang` 必须**最后**跑（它把两个会被自包含正则误读成外部引用的字节序列换成
等价的数值字符引用）。有一条源码顺序断言守着这个次序，别把它挪到闸门前面。

### 措辞纪律

**「无法判断」是独立的一态，永不折算成「通过」。** 这不是文案偏好，是 §6.4 R1。

我们从来没有跑过别的工具做对照，所以**不许**点名任何产品、也不许写「凡是现成的
东西都会答错」这类全量断言。要说那类实现会读错，固定措辞只有一句：

> 只探根路径、不做对照探测的实现，会在你的 N 个位置上读错。

它说的是一种**实现方式**在**这个站的这几个位置**上的行为，可以逐条复现；
全量断言不行。

禁词表（11 项）的唯一定义处是 `report/render._BANNED_WORDS`，被禁的整句话记在
`scripts/build_gallery.py` 的 `FORBIDDEN_CLAIM`（**本文件里不写出那句话本身** ——
闸门是纯字符串匹配，分不清「在用它」和「在禁它」，为了留一句例子给闸门开后门
不值得）。`README.md` / `CONTRIBUTING.md` / `docs/index.html` 都守这条：

```bash
python scripts/build_gallery.py --check-copy-only
```

## 报告画廊

```bash
GEO_AUDIT_FORBID_NETWORK=1 GEO_AUDIT_FORBID_DNS=1 python scripts/build_gallery.py
```

跑 replay 出 `docs/reports/*.html` + `docs/index.html`（GitHub Pages 的内容）。
清单在 `scripts/build_gallery.py` 的 `GALLERY_DOMAINS`。

一个域要进画廊，快照得够格（判据在 `preflight()`：apex 与 www 的 DNS 答案录过、
有快照的 host 也录过 DNS、apex/www/文档子域上至少一条对照探针）。
**不够格的域跳过**，脚本会把要补录的 `urls.txt` 行打出来，`docs/index.html` 里也
写明缺什么。补齐要真网络。

**不许为了让画廊好看而手改 `docs/` 里的 HTML。** 那些文件是产物，`pages.yml`
每次发布都重跑一遍脚本，手改会被覆盖 —— 而且画廊是我们唯一对外展示判定的地方，
它必须由当前代码现产。

## CI 的六个 job

| job | 守什么 |
|---|---|
| `lint` | ruff check / ruff format --check / mypy |
| `test` | 3 个 OS × 3 个 Python，**断网**跑 `pytest -m "not live"` + coverage |
| `labels` | 每条 `provenance=recorded` 的标注 URL 都能在 `corpus/feature-raw.json` 里搜到 |
| `fp-gate` | §8.6 的六条假阳性硬条件 |
| `schema` | `schema/report-1.schema.json` 与真报告的 JSON 对得上 |
| `smoke-uvx` | 装成 wheel 跑一次，验证 `force-include` 把 `fixtures/` 带进去了、报告自包含 |

`scripts/gen_schema.py --check` 断言 schema 与 dataclass 一致，
所以「改了 dataclass 忘了改 schema」不可能溜过去 —— 别手写那个 JSON。

## 提交信息

普通改动照常写。两类要加前缀：

- `fixture:` —— 动了 `fixtures/` 下任何东西，单独一个 commit；
- `corpus:` —— 动了 `corpus/` 或 `tests/data/` 下的标注。
