"""画廊落盘：**跑完了才写盘**。

守的是 2026-09-11 那个形态：重建被系统因内存不足连杀 6 次，每次都在中途，
于是 ``docs/reports/`` 里躺着 6 份新的 + 3 份旧的。那批混合物**看起来完全
正常** —— 文件都在、每份自己都是合法 HTML、index.html 还是上一轮的所以数字
也自洽。不是恰好查了 `git status` 的话，它会被当成一次正常重建提交上去。

所以这里断言的不是「内存够用」，是：**中途死掉时 docs/ 必须一个字节都没动**。

反向验证（这条测试真的守得住吗）：把 ``build_gallery._log_one`` 的落盘目标从
staging 改回 ``docs/reports/``，``test_a_crash_midway_leaves_docs_untouched``
立刻红。改回来才绿。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))

import build_gallery  # noqa: E402


class _BoomError(Exception):
    """一个域自己炸了（站点抽风、渲染 bug）—— 会被 main 里的 except 兜住。"""


class _FakeCounts:
    positions = 4
    positions_fail = 1
    positions_unknown = 1
    positions_pass = 1
    positions_na = 1


class _FakeReport:
    """``_log_one`` 打那行日志要读 ``report.counts`` 的五个数，给到就行。

    不造真 Report：测的是**落盘时机**，不是渲染，渲染在下面被整体替掉了。
    """

    counts = _FakeCounts()


def _fake_outcome(domain: str) -> Any:
    return build_gallery.Outcome(domain=domain, report=_FakeReport())  # type: ignore[arg-type]


@pytest.fixture
def docs(tmp_path: Path) -> Path:
    """一个「上一轮已经发布过」的 docs/：三份旧报告 + 一份旧索引。"""
    out = tmp_path / "docs"
    (out / "reports").mkdir(parents=True)
    for d in ("a.com", "b.com", "c.com"):
        (out / "reports" / f"{d}.html").write_text(f"<h1>OLD {d}</h1>", "utf-8")
    (out / "index.html").write_text("<h1>OLD index</h1>", "utf-8")
    return out


#: staging 目录名的前缀（与 build_gallery 里 mkdtemp 的 prefix 同一个字面量）。
STAGING = ".gallery-staging-"


def _snapshot(out: Path) -> dict[str, str]:
    """**已发布的那一面**：staging 残骸不算，它对读者不可见、也被 .gitignore 挡着。"""
    return {
        str(p.relative_to(out)): p.read_text("utf-8")
        for p in sorted(out.rglob("*"))
        if p.is_file() and not p.relative_to(out).parts[0].startswith(STAGING)
    }


def _run(
    out: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    crash_on: str | None,
    domains: tuple[str, ...],
    crash_with: type[BaseException] = _BoomError,
) -> int:
    """跑一次 main()，把「跑一个域」换成可控的替身。

    ``crash_with`` 分两种崩法，它们在 ``main`` 里走的是**不同的路**：
    ``_BoomError``（Exception）会被「一个域炸了不该带走整个画廊」那个 except 兜住，
    ``KeyboardInterrupt``（BaseException）兜不住，等于整个进程没了。
    """
    monkeypatch.setattr(build_gallery, "GALLERY_DOMAINS", domains)
    monkeypatch.setattr(build_gallery, "render_html", lambda report: "<h1>NEW</h1>")
    monkeypatch.setattr(build_gallery, "assert_selfcontained", lambda page: None)
    monkeypatch.setattr(build_gallery, "assert_no_banned_words", lambda page: None)
    monkeypatch.setattr(build_gallery, "render_index", lambda *a, **k: "<h1>NEW index</h1>")
    monkeypatch.setattr(build_gallery, "check_copy_discipline", lambda: [])
    monkeypatch.setattr(build_gallery, "_recorded_at", lambda store: "2026-09-07")
    monkeypatch.setattr(build_gallery.FixtureStore, "default", classmethod(lambda cls: object()))

    def fake_run_domain(domain: str, **kwargs: Any) -> Any:
        if domain == crash_on:
            raise crash_with(f"{domain} 上崩了")
        return _fake_outcome(domain)

    monkeypatch.setattr(build_gallery, "run_domain", fake_run_domain)
    # --jobs 1：要的是确定的先后顺序，不然「崩之前跑过几个」不稳定
    return build_gallery.main(["--out", str(out), "--jobs", "1"])


def test_a_crash_midway_leaves_docs_untouched(docs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """第二个域上进程没了 —— docs/ 必须与跑之前逐字节相同。

    注意崩的方式：``run_domain`` 抛的异常被 ``main`` 里那个 ``except Exception``
    兜住（一个域炸了不该带走整个画廊），所以这里用 ``_BoomError`` 会被兜掉。
    真正模拟「整个进程没了」的是 ``BaseException`` —— 用 KeyboardInterrupt。
    """
    before = _snapshot(docs)
    with pytest.raises(KeyboardInterrupt):
        _run(
            docs,
            monkeypatch,
            crash_on="b.com",
            domains=("a.com", "b.com", "c.com"),
            crash_with=KeyboardInterrupt,
        )
    after = _snapshot(docs)
    stale = {k: v for k, v in after.items() if before.get(k) != v}
    assert stale == {}, (
        f"中途被杀之后 docs/ 变了：{sorted(stale)} —— "
        "这正是「6 份新 + 3 份旧、看起来完全正常」那个形态。"
    )


def test_a_full_run_replaces_every_report_and_the_index(
    docs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """跑完整一轮：三份报告与索引都换成新的，staging 不留残骸。"""
    rc = _run(docs, monkeypatch, crash_on=None, domains=("a.com", "b.com", "c.com"))
    assert rc == 0
    for d in ("a.com", "b.com", "c.com"):
        assert (docs / "reports" / f"{d}.html").read_text("utf-8") == "<h1>NEW</h1>"
    assert (docs / "index.html").read_text("utf-8") == "<h1>NEW index</h1>"
    assert [p.name for p in docs.iterdir() if p.name.startswith(STAGING)] == []


def test_one_domain_failing_does_not_hold_back_the_others(
    docs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """一个域自己炸了照发 —— 阻止发布的只有「整轮没跑完」。

    这条是上一条的反面：没有它，「跑完才写盘」很容易被实现成「有一个失败就
    整轮不发」，那会让画廊在任何一个站点抽风时整片消失。
    """
    rc = _run(docs, monkeypatch, crash_on="b.com", domains=("a.com", "b.com", "c.com"))
    assert rc == 0
    assert (docs / "reports" / "a.com.html").read_text("utf-8") == "<h1>NEW</h1>"
    assert (docs / "reports" / "c.com.html").read_text("utf-8") == "<h1>NEW</h1>"
    # b.com 这一轮没产出，旧的那份**留在原地**（index.html 里会写明它为什么没报告）
    assert (docs / "reports" / "b.com.html").read_text("utf-8") == "<h1>OLD b.com</h1>"


def test_a_killed_run_leaves_only_a_gitignored_staging_dir(
    docs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """被强杀时留下的残骸必须是**挡在 .gitignore 里的那个名字**。

    SIGKILL 下没有清理的机会，所以残骸不可避免；能保证的是它不会被误提交、
    也不会被下一轮当成产物。这条测试把「名字前缀」与「.gitignore 的那行」钉在
    一起 —— 改了其中一个而没改另一个，这里红。
    """
    with pytest.raises(KeyboardInterrupt):
        _run(
            docs,
            monkeypatch,
            crash_on="b.com",
            domains=("a.com", "b.com", "c.com"),
            crash_with=KeyboardInterrupt,
        )

    leftovers = [p.name for p in docs.iterdir() if p.is_dir() and p.name != "reports"]
    assert leftovers and all(n.startswith(STAGING) for n in leftovers), leftovers
    gitignore = (REPO / ".gitignore").read_text("utf-8")
    assert f"docs/{STAGING}*/" in gitignore, (
        f".gitignore 没挡住 docs/{STAGING}*/ —— 被强杀那次的残骸会进 git status，而它长得像产物。"
    )


def test_the_next_run_sweeps_the_leftover(docs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """下一轮开跑先扫掉上一轮的残骸，不让它们攒起来。"""
    (docs / f"{STAGING}dead1").mkdir()
    (docs / f"{STAGING}dead2" / "reports").mkdir(parents=True)
    rc = _run(docs, monkeypatch, crash_on=None, domains=("a.com",))
    assert rc == 0
    assert [p.name for p in docs.iterdir() if p.name.startswith(STAGING)] == []
