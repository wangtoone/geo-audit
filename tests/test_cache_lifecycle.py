"""HttpCache 的连接生命周期：close() 必须**真的**关掉每一条连接。

**为什么单独一个文件**：这条曾经连挂三轮 CI，且每轮都只在 Python 3.13 上红。
病因链是：

1. 连接存在 ``threading.local`` 里，线程池每个 worker 各开一条；
2. ``close()`` 在主线程跑，默认 ``check_same_thread=True`` 下关一条 worker 建的
   连接会抛 ``sqlite3.ProgrammingError``；
3. 那句 ``with suppress(sqlite3.Error)`` 把它吞了 —— 连接从没真关上；
4. 3.13 起 ``sqlite3.Connection`` 析构时发 ``ResourceWarning``，撞上
   ``filterwarnings = error`` 变成错误；
5. 而 pytest 把它算在「GC 恰好触发时正在跑的那条测试」头上 —— 三条纯扫源文、
   一个 HTTP 请求都不发的测试被连坐报红，所以顺着报错的文件名根本找不到病因。

所以这里的断言刻意绕开 ``ResourceWarning`` 本身（那是 3.13 才有的现象），
直接断言**连接确实关了** —— 关上的连接不可能再发那条警告，这个判据在所有
版本上都能红。
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from geo_audit.fetch.cache import HttpCache


def _touch_from_threads(cache: HttpCache, n: int) -> None:
    """让 n 个**别的**线程各开一条连接（复现线程池的形状）。"""
    errors: list[Exception] = []

    def worker() -> None:
        try:
            cache._conn().execute("SELECT 1").fetchone()
        except Exception as exc:  # 线程里的异常要带回主线程，否则 join() 之后静默通过
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"worker 线程用缓存就炸了：{errors!r}"


def _is_closed(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("SELECT 1")
    except sqlite3.ProgrammingError as exc:
        return "closed" in str(exc).lower()
    return False


def test_close_actually_closes_connections_opened_in_other_threads(tmp_path: Path) -> None:
    cache = HttpCache(tmp_path / "c.sqlite3")
    _touch_from_threads(cache, 4)

    # 主线程那条（__init__ 建表时开的）+ 4 条 worker 的
    conns = list(cache._all_conns)
    assert len(conns) == 5, f"应有 5 条连接（1 主 + 4 worker），实际 {len(conns)}"

    cache.close()

    # 判据一：close 自己没有偷偷失败
    assert cache.close_failures == [], (
        f"close() 关不掉 {len(cache.close_failures)} 条连接：{cache.close_failures}。"
        "这正是三轮 CI 的病因 —— 别再用 suppress 把它吞回去。"
    )
    # 判据二：每一条都真关了（不是「close 没报错」而已）
    still_open = [i for i, c in enumerate(conns) if not _is_closed(c)]
    assert still_open == [], f"这些连接 close() 后还是开着：{still_open}"


def test_cross_thread_close_would_fail_without_check_same_thread(tmp_path: Path) -> None:
    """把病因本身钉死：**没有** check_same_thread=False 时跨线程 close 会抛。

    这条不测我们的代码，测的是我们依赖的那条 sqlite3 行为。它在的意义是：
    哪天有人把 ``check_same_thread=False`` 删掉说「这个参数看着没用」，
    上面那条测试会红，而这条告诉他红的原因是什么。

    **收尾必须由 worker 线程自己做。** 第一版写成「主线程试关失败后换一条新连接
    收尾」，结果那条关不掉的连接被引用一覆盖就成了孤儿，GC 时照样发
    ResourceWarning —— 等于用一条记录病因的测试复现了同一个病，3.13 上直接
    把 test_classify 里一条无关的用例带红了。``check_same_thread=True`` 下只有
    建连接的线程能关它，所以这里用一个 Event 让 worker 等主线程验完再自己收尾。
    """
    path = tmp_path / "raw.sqlite3"
    box: list[sqlite3.Connection] = []
    closed_ok: list[bool] = []
    created, may_close = threading.Event(), threading.Event()

    def worker() -> None:
        conn = sqlite3.connect(path, check_same_thread=True)
        box.append(conn)
        created.set()
        may_close.wait(timeout=10)
        conn.close()  # 只有本线程关得掉
        closed_ok.append(True)

    t = threading.Thread(target=worker)
    t.start()
    try:
        assert created.wait(timeout=10), "worker 没能建起连接"
        with pytest.raises(sqlite3.ProgrammingError, match="same thread") as caught:
            box[0].close()
        # 而且它是 sqlite3.Error 的子类 —— 所以 suppress(sqlite3.Error) 会吞掉它
        assert isinstance(caught.value, sqlite3.Error)
    finally:
        may_close.set()
        t.join(timeout=10)
    # 收尾成不成，只能由建它的那个线程说 —— 主线程再去 execute 一下探状态，
    # 撞到的是 "same thread" 还是 "closed database" 跟 CPython 版本有关，
    # 拿它当判据本身就是个坑。
    assert closed_ok == [True], "worker 线程没把连接收干净"


def test_close_is_idempotent(tmp_path: Path) -> None:
    cache = HttpCache(tmp_path / "c.sqlite3")
    _touch_from_threads(cache, 2)
    cache.close()
    cache.close()  # 重复调用不许抛、也不许记新的失败
    assert cache.close_failures == []
