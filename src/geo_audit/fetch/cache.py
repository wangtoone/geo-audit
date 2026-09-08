"""On-disk HTTP cache.

Decisions
---------
* SQLite, not a file tree.  One empirical run checked 11,609 links; a
  file-per-URL tree works but SQLite gives atomic writes, one file to delete,
  and cheap aggregate queries ("was this domain ever blocked in this run?").
  stdlib only, zero dependencies.

* Two TTLs, and this is the important part.  Successful/definitive responses
  (2xx, 3xx, 404, 410) live 6 hours: re-running the same domain inside one
  working session -- the actual repeat pattern -- costs nothing.  Non-verdicts
  (blocked, 5xx, network errors, needs_js) live 15 minutes, because those are
  exactly the ones worth retrying, and caching them for 6 hours would freeze a
  false zero into the report.

* Host control probes are cached separately, keyed by host, not by URL.  A
  domain-wide audit probes 6 AI paths x 4 hosts; per-URL control probes would
  cost 24 extra requests, per-host costs 4.  At 2 s/request that is 40 s saved
  on every run.

* The cache key includes the User-Agent profile.  Changing the UA changes what
  a WAF does, so a body fetched under a different UA is not a substitute.

* Bodies over MAX_CACHE_BODY are stored truncated with ``body_truncated=1``,
  and the classifier turns that into UNKNOWN rather than guessing.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from ..models import HostProfile, HttpResponse, RedirectHop

#: 8 MiB.  The largest real file in the fixture set is
#: docs.canvasmedical.com/llms-full.txt at ~4.3 MB, followed by
#: platform.kimi.ai/docs/llms-full.txt at 754 KB and mistral's at 992 KB.
#: 8 MiB leaves headroom without letting one pathological response blow up the
#: cache file.
MAX_CACHE_BODY = 8 * 1024 * 1024

TTL_DEFINITIVE = 6 * 3600
TTL_INDETERMINATE = 15 * 60

_DEFINITIVE_STATUSES = frozenset({200, 201, 204, 301, 302, 303, 307, 308, 404, 410})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS responses (
    key           TEXT PRIMARY KEY,
    url           TEXT NOT NULL,
    final_url     TEXT NOT NULL,
    host          TEXT NOT NULL,
    status        INTEGER NOT NULL,
    headers       TEXT NOT NULL,
    body          BLOB NOT NULL,
    redirects     TEXT NOT NULL,
    elapsed_ms    INTEGER NOT NULL DEFAULT 0,
    body_truncated INTEGER NOT NULL DEFAULT 0,
    transport_error TEXT,
    fetched_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS responses_host ON responses(host);

CREATE TABLE IF NOT EXISTS host_profiles (
    host          TEXT PRIMARY KEY,
    probe_url     TEXT NOT NULL,
    status        INTEGER NOT NULL,
    content_type  TEXT NOT NULL,
    norm_sha256   TEXT NOT NULL,
    norm_len      INTEGER NOT NULL,
    norm_body_prefix TEXT NOT NULL,
    struct_sha256 TEXT NOT NULL,
    struct_tags   INTEGER NOT NULL,
    final_path    TEXT NOT NULL,
    status_discriminates INTEGER NOT NULL,
    control_is_html INTEGER NOT NULL,
    usable        INTEGER NOT NULL,
    probed_at     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "geo-audit"


@dataclass(frozen=True, slots=True)
class CachePolicy:
    read: bool = True
    write: bool = True
    #: Never touch the network.  Used by tests and by report re-rendering.
    offline: bool = False


class HttpCache:
    """Thread-safe SQLite-backed cache."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        policy: CachePolicy | None = None,
        ua_profile: str = "default",
    ) -> None:
        self.policy = policy or CachePolicy()
        self.ua_profile = ua_profile
        if path is None:
            d = default_cache_dir()
            d.mkdir(parents=True, exist_ok=True)
            path = d / "http.sqlite3"
        self.path = Path(path)
        self._local = threading.local()
        # threading.local 只让**本线程**拿得到自己的连接，close() 却要关掉全部 ——
        # 所以另存一份总账。
        self._all_conns: list[sqlite3.Connection] = []
        self._all_lock = threading.Lock()
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    # -- plumbing --------------------------------------------------------- #

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
            with self._all_lock:
                self._all_conns.append(conn)
        return conn

    def close(self) -> None:
        """关掉本实例开过的**全部**连接（含其他线程开的）。

        **为什么必须有这个方法**：连接存在 ``threading.local`` 里，线程池的每个
        worker 各开一条，原来全靠 GC 回收。Python 3.13 起 ``sqlite3.Connection``
        在析构时会发 ``ResourceWarning``，而 pyproject 的 ``filterwarnings = error``
        把它升成错误 —— CI 上 3.13 的 24 条测试就是这么挂的
        （``Exception ignored in: <sqlite3.Connection object>``，不是断言错）。
        本地 3.12 不报，所以只有跑 CI 才看得见。

        幂等：重复调用无副作用。关不掉的连接（别的线程正在用）忽略异常 ——
        close 的语义是「尽力释放」，不该因为清理失败而让调用方崩。
        """
        with self._all_lock:
            conns, self._all_conns = self._all_conns, []
        for conn in conns:
            with suppress(sqlite3.Error):
                conn.close()
        self._local = threading.local()

    def __enter__(self) -> HttpCache:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def key(self, method: str, url: str, accept: str) -> str:
        raw = f"{method.upper()}\n{url}\n{accept}\n{self.ua_profile}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def ttl_for(status: int, transport_error: str | None) -> int:
        if transport_error:
            return TTL_INDETERMINATE
        return TTL_DEFINITIVE if status in _DEFINITIVE_STATUSES else TTL_INDETERMINATE

    # -- responses -------------------------------------------------------- #

    def get(self, method: str, url: str, accept: str) -> HttpResponse | None:
        if not self.policy.read:
            return None
        row = (
            self._conn()
            .execute(
                "SELECT url, final_url, status, headers, body, redirects, elapsed_ms,"
                " body_truncated, transport_error, fetched_at FROM responses WHERE key=?",
                (self.key(method, url, accept),),
            )
            .fetchone()
        )
        if row is None:
            return None
        (
            r_url,
            final_url,
            status,
            headers,
            body,
            redirects,
            elapsed,
            truncated,
            terr,
            fetched_at,
        ) = row
        if time.time() - fetched_at > self.ttl_for(status, terr):
            return None
        return HttpResponse(
            url=r_url,
            final_url=final_url,
            status=status,
            headers=json.loads(headers),
            body=body,
            redirects=tuple(RedirectHop(**h) for h in json.loads(redirects)),
            elapsed_ms=elapsed,
            from_cache=True,
            body_truncated=bool(truncated),
            transport_error=terr,
            fetched_at=fetched_at,
        )

    def put(self, response: HttpResponse, accept: str, method: str = "GET") -> None:
        if not self.policy.write:
            return
        body = response.body[:MAX_CACHE_BODY]
        truncated = response.body_truncated or len(response.body) > MAX_CACHE_BODY
        from urllib.parse import urlsplit

        self._conn().execute(
            "INSERT OR REPLACE INTO responses (key,url,final_url,host,status,headers,"
            "body,redirects,elapsed_ms,body_truncated,transport_error,fetched_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                self.key(method, response.url, accept),
                response.url,
                response.final_url,
                (urlsplit(response.url).hostname or "").lower(),
                response.status,
                json.dumps(response.headers, sort_keys=True),
                body,
                json.dumps(
                    [
                        h.__dict__
                        if hasattr(h, "__dict__")
                        else {"status": h.status, "from_url": h.from_url, "to_url": h.to_url}
                        for h in response.redirects
                    ]
                ),
                response.elapsed_ms,
                int(truncated),
                response.transport_error,
                response.fetched_at,
            ),
        )

    # -- host profiles ---------------------------------------------------- #

    def get_profile(self, host: str) -> HostProfile | None:
        if not self.policy.read:
            return None
        row = (
            self._conn()
            .execute(
                "SELECT host,probe_url,status,content_type,norm_sha256,norm_len,"
                "norm_body_prefix,struct_sha256,struct_tags,final_path,"
                "status_discriminates,control_is_html,usable,probed_at"
                " FROM host_profiles WHERE host=?",
                (host.lower(),),
            )
            .fetchone()
        )
        if row is None:
            return None
        probed_at = row[13]
        ttl = TTL_DEFINITIVE if row[12] else TTL_INDETERMINATE
        if time.time() - probed_at > ttl:
            return None
        return HostProfile(
            host=row[0],
            probe_url=row[1],
            status=row[2],
            content_type=row[3],
            norm_sha256=row[4],
            norm_len=row[5],
            norm_body_prefix=row[6],
            struct_sha256=row[7],
            struct_tags=row[8],
            final_path=row[9],
            status_discriminates=bool(row[10]),
            control_is_html=bool(row[11]),
            usable=bool(row[12]),
            probed_at=probed_at,
        )

    def put_profile(self, profile: HostProfile) -> None:
        if not self.policy.write:
            return
        self._conn().execute(
            "INSERT OR REPLACE INTO host_profiles (host,probe_url,status,content_type,"
            "norm_sha256,norm_len,norm_body_prefix,struct_sha256,struct_tags,final_path,"
            "status_discriminates,control_is_html,usable,probed_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                profile.host.lower(),
                profile.probe_url,
                profile.status,
                profile.content_type,
                profile.norm_sha256,
                profile.norm_len,
                profile.norm_body_prefix,
                profile.struct_sha256,
                profile.struct_tags,
                profile.final_path,
                int(profile.status_discriminates),
                int(profile.control_is_html),
                int(profile.usable),
                profile.probed_at,
            ),
        )

    # -- housekeeping ----------------------------------------------------- #

    def purge_expired(self) -> int:
        now = time.time()
        cur = self._conn().execute(
            "DELETE FROM responses WHERE"
            " (transport_error IS NOT NULL AND ? - fetched_at > ?)"
            " OR (transport_error IS NULL AND status NOT IN"
            " (200,201,204,301,302,303,307,308,404,410)"
            "     AND ? - fetched_at > ?)"
            " OR (? - fetched_at > ?)",
            (now, TTL_INDETERMINATE, now, TTL_INDETERMINATE, now, TTL_DEFINITIVE),
        )
        return cur.rowcount or 0

    def clear(self) -> None:
        conn = self._conn()
        conn.execute("DELETE FROM responses")
        conn.execute("DELETE FROM host_profiles")
