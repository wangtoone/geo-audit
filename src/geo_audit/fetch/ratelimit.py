"""Per-domain rate limiting and adaptive backoff.

Decisions
---------
* Bucket key = **registrable domain**, not host.  The compliance constraint is
  "<=1 request / 2 s per domain", and the WAF hits in the empirical run
  (gusto.com Cloudflare 403, www.pipedrive.com 429) are enforced at the
  registrable-domain level, so keying on host would let apex + www + docs each
  burn a full request per second against the same edge.  Cost: an audit of one
  domain touching apex + www + docs serializes at 2 s intervals.  A typical
  audit is ~60 requests => ~2 minutes.  Acceptable.

* Adaptive backoff on 429 / 503.  Honour ``Retry-After`` when present; double
  the domain's interval on every throttle signal, cap 30 s, and never decay it
  back down inside one run.  This is the direct answer to www.pipedrive.com
  returning 429 on a file that actually exists.

* Concurrency model: threads, not asyncio.  See client.py for the reasoning.
  The limiter therefore has to be thread-safe, and it has to be able to hold a
  domain across *two* requests atomically -- the target and its control probe
  must be adjacent (FEATURE-PRIORITY.md P0: "对照请求与目标请求必须同一会话、
  同一 UA、同一 Accept-Encoding、间隔 < 5s").  ``hold()`` provides that.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

#: Compliance floor.  Never configurable below this value.
MIN_INTERVAL_SECONDS = 2.0
MAX_INTERVAL_SECONDS = 30.0

# Minimal public-suffix handling.  A bundled table beats `tldextract` here
# because tldextract downloads the PSL at runtime, and a CLI that phones home
# on first use is both a compliance smell and an offline-hostile design.  A
# wrong answer degrades to *more conservative* bucketing (two hosts share one
# bucket), never to a wrong verdict, so a small table is enough.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "com.br",
        "com.mx",
        "com.ar",
        "com.co",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "co.in",
        "net.in",
        "org.in",
        "co.nz",
        "co.za",
        "com.sg",
        "com.hk",
        "com.tw",
        "com.tr",
        "co.kr",
        "or.kr",
        "github.io",
        "gitlab.io",
        "vercel.app",
        "netlify.app",
        "pages.dev",
        "workers.dev",
        "herokuapp.com",
        "readme.io",
        "zendesk.com",
        "intercom.help",
        "usepylon.com",
    }
)


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1.

    Verified on the awkward hosts in the fixture set:
      docs.mistral.ai        -> mistral.ai
      platform.kimi.ai       -> kimi.ai
      ed.link                -> ed.link        (single-label TLD)
      www.voyageai.com       -> voyageai.com
      pipedrive.readme.io    -> pipedrive.readme.io  (readme.io is a hosting
                                suffix, so each tenant gets its own bucket --
                                which is what we want, they are separate sites)
      support.goshippo.com   -> goshippo.com
    """
    host = host.lower().strip(".")
    if not host or host.replace(".", "").isdigit():
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    for depth in (3, 2):
        if len(labels) >= depth + 1:
            candidate = ".".join(labels[-depth:])
            if candidate in _MULTI_LABEL_SUFFIXES:
                return ".".join(labels[-(depth + 1) :])
    return ".".join(labels[-2:])


@dataclass
class _Bucket:
    interval: float = MIN_INTERVAL_SECONDS
    last_hit: float = 0.0
    lock: threading.RLock = field(default_factory=threading.RLock)
    throttle_events: int = 0


class DomainLimiter:
    """Thread-safe, per-registrable-domain pacing gate."""

    def __init__(self, base_interval: float = MIN_INTERVAL_SECONDS) -> None:
        if base_interval < MIN_INTERVAL_SECONDS:
            raise ValueError(f"base_interval {base_interval} 低于合规下限 {MIN_INTERVAL_SECONDS}s")
        self._base = base_interval
        self._buckets: dict[str, _Bucket] = {}
        self._registry_lock = threading.Lock()

    def _bucket(self, domain: str) -> _Bucket:
        with self._registry_lock:
            b = self._buckets.get(domain)
            if b is None:
                b = _Bucket(interval=self._base)
                self._buckets[domain] = b
            return b

    def set_crawl_delay(self, host: str, delay: float) -> None:
        """Honour robots.txt ``Crawl-delay`` when it is stricter than ours."""
        if delay and delay > 0:
            b = self._bucket(registrable_domain(host))
            with b.lock:
                b.interval = max(b.interval, min(delay, MAX_INTERVAL_SECONDS))

    def note_throttled(self, host: str, retry_after: str | None = None) -> float:
        """Record a 429/503 and widen this domain's interval.  Returns the
        number of seconds the caller should sleep before any retry."""
        b = self._bucket(registrable_domain(host))
        with b.lock:
            b.throttle_events += 1
            b.interval = min(b.interval * 2, MAX_INTERVAL_SECONDS)
            wait = b.interval
        if retry_after:
            # HTTP-date form raises ValueError; the doubled interval is enough there.
            with contextlib.suppress(ValueError):
                wait = max(wait, min(float(retry_after.strip()), 120.0))
        return wait

    @contextmanager
    def hold(self, host: str, *, requests: int = 1) -> Iterator[None]:
        """Acquire the domain and pace it, releasing only after the block ends.

        ``requests=2`` is used for a target + control-probe pair so nothing
        else can interleave between them, which is what keeps the two probes
        within one interval of each other.
        """
        domain = registrable_domain(host)
        b = self._bucket(domain)
        b.lock.acquire()
        try:
            gap = b.interval - (time.monotonic() - b.last_hit)
            if gap > 0:
                time.sleep(gap)
            yield
        finally:
            b.last_hit = time.monotonic()
            b.lock.release()

    def stats(self) -> dict[str, dict[str, float]]:
        with self._registry_lock:
            return {
                d: {"interval": b.interval, "throttle_events": b.throttle_events}
                for d, b in self._buckets.items()
            }
