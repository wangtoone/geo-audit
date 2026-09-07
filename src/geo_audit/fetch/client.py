"""The Fetcher: sync httpx + threads, manual redirect following, retries,
control probing, robots.txt.

Why sync httpx with a thread pool, not asyncio
----------------------------------------------
The binding constraint is <=1 request / 2 s **per domain**.  Inside one domain
the work is therefore serial no matter what the concurrency model is: mistral's
75 internal links all live on docs.mistral.ai, so they cost 75 x 2 s = 150 s
whether the code awaits or blocks.  Async buys nothing there.

The parallelism that does pay is *across* domains -- the dead-link phase in the
empirical run touched thousands of links spread over hundreds of external
hosts.  A bounded ThreadPoolExecutor gets that speedup while leaving the
classifier, the normalizer (difflib, sha256 -- CPU work) and every call site
plainly synchronous and plainly testable.  Async would spread `await` through
every check module in exchange for a speedup the rate limiter forbids.

Why GET and not HEAD
--------------------
Soft-404 detection needs the body.  developers.brevo.com/docs/llms.txt is
200 + text/plain + 44 bytes of "# Page Not Found": status and content-type are
both innocent, and HEAD would return exactly the innocent part.  So: always
GET, with a streamed read and a byte cap.  Liveness-only checks cap at 64 KiB.

Why redirects are followed manually
-----------------------------------
Five separate empirical failures make the chain itself evidence:
  * unkey.com/docs/platform/workspaces/billing -- 308 -> 308 -> 404.  The first
    pass used urllib, recorded the 308 as terminal, and MISSED a real dead
    link on the pricing page's "Read the docs" button.
  * support.freshbooks.com/llms.txt -- 307 -> /hc/en-us -> 200 text/html.
    Following blind yields a false "llms.txt exists".
  * api-docs.ecwid.com/llms.txt -- 302 -> docs.ecwid.com/ -> 200.  Same.
  * docs.moderntreasury.com/<anything> -- 302 -> "/".  Every dead link on that
    host masquerades as a 200.
  * app.moderntreasury.com -- Auth0 redirect ring, curl error 47.  Must become
    UNKNOWN, never dead.
"""

from __future__ import annotations

import secrets
import threading
import time
import urllib.robotparser
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from ..models import (
    Classification,
    Expect,
    HostProfile,
    HttpResponse,
    Probe,
    RedirectHop,
    RobotsInfo,
    Verdict,
    finalize_response,
)
from . import fingerprints as fp
from .cache import MAX_CACHE_BODY, HttpCache
from .classify import classify_response, looks_like_html
from .normalize import (
    NORM_BODY_CAP,
    norm_sha256,
    normalize_body,
    structural_fingerprint,
)
from .ratelimit import DomainLimiter, registrable_domain
from .resolve import resolve_host

__version__ = "0.1.0"

MAX_REDIRECTS = 10
LIVENESS_BYTE_CAP = 64 * 1024
CONTENT_BYTE_CAP = MAX_CACHE_BODY

#: Retried: transient transport failures and gateway errors only.
#: NOT retried: 403 / 404 / 401 -- those are verdicts, not accidents.  Retrying
#: a 403 just spends the rate-limit budget re-confirming a WAF.
RETRY_STATUSES = frozenset({502, 503, 504, 507, 522, 524})
RETRY_ATTEMPTS = 3
RETRY_BACKOFF = (2.0, 6.0)

ACCEPT_TEXT = "text/plain, text/markdown, text/*;q=0.9, */*;q=0.1"
ACCEPT_HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


@dataclass(frozen=True, slots=True)
class FetcherConfig:
    contact: str
    interval: float = 2.0
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    max_workers: int = 8
    respect_robots: bool = True
    verify_tls: bool = True
    #: When False, skip requests to hosts on KNOWN_BOT_HOSTILE_SUFFIXES and
    #: mark them BLOCKED without spending a request.  Saves budget; the general
    #: status rule still decides anything not on the list.
    probe_known_hostile: bool = False


def build_user_agent(contact: str) -> str:
    """Real UA + contact address, as the compliance constraint requires.

    ``contact`` is mandatory (resolved from --contact / GEO_AUDIT_CONTACT /
    config).  The CLI refuses to run without it: an optional contact address
    is one nobody sets, which would make the compliance claim false in
    practice.
    """
    if not contact or "@" not in contact:
        raise ValueError(
            "必须提供联系邮箱（--contact 或 GEO_AUDIT_CONTACT）。"
            "抓取合规要求 User-Agent 里带真实联系方式，做成可选等于没有。"
        )
    return f"geo-audit/{__version__} (+https://github.com/wangtoone/geo-audit; contact: {contact})"


class Fetcher:
    """Rate-limited, cached, redirect-aware HTTP client."""

    def __init__(
        self,
        config: FetcherConfig,
        cache: HttpCache | None = None,
        limiter: DomainLimiter | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        probe_url_provider: Callable[[str], str] | None = None,
    ) -> None:
        """§3.9 适配 #4：加两个 keyword-only 注入点。

        ``transport``           —— 生产代码与 fixture 回放都从这里塞 MockTransport，
                                   不必像冻结测试那样直接赋私有属性 ``_client``
                                   （那条测试仍然有效，这里只是给出正路）。
        ``probe_url_provider``  —— 对照探针 URL 的来源（§3.3）。默认随机；
                                   fixture 回放时注入确定性实现，否则每次跑出来的
                                   对照 URL 都不一样，快照永远命不中。
        """
        self.config = config
        self.user_agent = build_user_agent(config.contact)
        self.cache = cache or HttpCache(ua_profile=self.user_agent)
        self.limiter = limiter or DomainLimiter(config.interval)
        self._probe_url_provider = probe_url_provider
        self._client = httpx.Client(
            transport=transport,
            follow_redirects=False,  # followed manually; the chain is evidence
            timeout=httpx.Timeout(
                connect=config.connect_timeout,
                read=config.read_timeout,
                write=5.0,
                pool=5.0,
            ),
            headers={
                "User-Agent": self.user_agent,
                "From": config.contact,
                "Accept-Encoding": "gzip, deflate",  # pinned: target and control
                "Accept-Language": "en",  # must be byte-identical
            },
            verify=config.verify_tls,
            http2=False,
        )
        self._robots: dict[str, RobotsInfo] = {}
        self._robots_parsers: dict[str, urllib.robotparser.RobotFileParser] = {}
        self._robots_lock = threading.Lock()
        self._exclusion_log: list[tuple[str, str, str]] = []  # (url, rule_id, why)

    # ------------------------------------------------------------------ #
    # low-level
    # ------------------------------------------------------------------ #

    def _raw_request(
        self, url: str, *, accept: str, byte_cap: int, pinned_ip: str | None = None
    ) -> HttpResponse:
        """One HTTP exchange, no redirect following, no rate limiting.

        ``pinned_ip`` implements resolve.R2: connect to a specific address
        while keeping the original Host header and TLS SNI, so a request that
        the local resolver could not route still gets a real answer.
        """
        started = time.monotonic()
        headers = {"Accept": accept}
        request_url = url
        if pinned_ip:
            parts = urlsplit(url)
            host = parts.hostname or ""
            netloc = pinned_ip if not parts.port else f"{pinned_ip}:{parts.port}"
            request_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))
            headers["Host"] = host
        try:
            with self._client.stream(
                "GET",
                request_url,
                headers=headers,
                extensions={"sni_hostname": urlsplit(url).hostname} if pinned_ip else None,
            ) as resp:
                chunks: list[bytes] = []
                total = 0
                truncated = False
                for chunk in resp.iter_bytes(65536):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= byte_cap:
                        truncated = True
                        break
                body = b"".join(chunks)[:byte_cap]
                return HttpResponse(
                    url=url,
                    final_url=url,
                    status=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=body,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    body_truncated=truncated,
                )
        except httpx.TimeoutException as exc:
            return self._error_response(url, f"timeout: {exc!r}", started)
        except httpx.TooManyRedirects as exc:  # pragma: no cover - manual chain
            return self._error_response(url, f"too many redirects: {exc!r}", started)
        except httpx.HTTPError as exc:
            return self._error_response(url, f"{type(exc).__name__}: {exc}", started)

    @staticmethod
    def _error_response(url: str, err: str, started: float) -> HttpResponse:
        return HttpResponse(
            url=url,
            final_url=url,
            status=0,
            headers={},
            body=b"",
            elapsed_ms=int((time.monotonic() - started) * 1000),
            transport_error=err,
        )

    # ------------------------------------------------------------------ #
    # robots
    # ------------------------------------------------------------------ #

    def robots_for(self, url: str) -> RobotsInfo:
        host = (urlsplit(url).hostname or "").lower()
        scheme = urlsplit(url).scheme or "https"
        with self._robots_lock:
            cached = self._robots.get(host)
        if cached is not None:
            return cached
        robots_url = f"{scheme}://{host}/robots.txt"
        with self.limiter.hold(host):
            resp = self._raw_request(robots_url, accept="text/plain", byte_cap=LIVENESS_BYTE_CAP)
        raw = resp.text if resp.status == 200 else ""
        parser = urllib.robotparser.RobotFileParser()
        parser.parse(raw.splitlines())
        sitemaps = tuple(
            line.split(":", 1)[1].strip()
            for line in raw.splitlines()
            if line.lower().startswith("sitemap:")
        )
        delay = None
        try:
            d = parser.crawl_delay(self.user_agent)
            delay = float(d) if d else None
        except Exception:  # pragma: no cover
            delay = None
        if delay:
            self.limiter.set_crawl_delay(host, delay)
        info = RobotsInfo(
            host=host,
            fetched=resp.status == 200,
            status=resp.status,
            crawl_delay=delay,
            sitemaps=sitemaps,
            raw=raw,
        )
        with self._robots_lock:
            self._robots[host] = info
            self._robots_parsers[host] = parser
        return info

    def robots_allows(self, url: str) -> bool:
        """Honour robots.txt for everything except /robots.txt itself.

        A robots-blocked position becomes UNKNOWN / robots_disallowed, i.e. it
        lands in the report's 未能评估 region.  That is the honest outcome:
        "we were not allowed to look" is a true statement, "no problem here"
        is not.  --no-robots exists for auditing your own property.
        """
        if not self.config.respect_robots:
            return True
        if urlsplit(url).path == "/robots.txt":
            return True
        host = (urlsplit(url).hostname or "").lower()
        if host not in self._robots_parsers:
            self.robots_for(url)
        parser = self._robots_parsers.get(host)
        if parser is None:
            return True
        return parser.can_fetch(self.user_agent, url)

    # ------------------------------------------------------------------ #
    # fetch with redirects + retries + DNS second opinion
    # ------------------------------------------------------------------ #

    def fetch(
        self,
        url: str,
        *,
        expect: Expect = Expect.ANY,
        liveness_only: bool = False,
        use_cache: bool = True,
    ) -> HttpResponse:
        """Fetch ``url``, following redirects and recording the chain."""
        accept = ACCEPT_TEXT if expect is Expect.TEXT_FILE else ACCEPT_HTML
        byte_cap = LIVENESS_BYTE_CAP if liveness_only else CONTENT_BYTE_CAP

        if use_cache:
            hit = self.cache.get("GET", url, accept)
            if hit is not None:
                return hit

        host = (urlsplit(url).hostname or "").lower()
        if not self.config.probe_known_hostile and any(
            host == s or host.endswith("." + s) for s in fp.KNOWN_BOT_HOSTILE_SUFFIXES
        ):
            resp = HttpResponse(
                url=url,
                final_url=url,
                status=403,
                headers={"content-type": "text/plain"},
                body=b"skipped: known bot-hostile vendor host",
            )
            self.cache.put(resp, accept)
            return resp

        resp = self._fetch_chain(url, accept=accept, byte_cap=byte_cap)
        # §3.9 适配 #5：读完 body 的这一刻一次性算好三个摘要再入缓存。
        # liveness_only（64 KiB 上限的外链存活检查）不算 —— 截断正文的哈希
        # 跟完整正文的哈希不同，那是测量假象不是发现。
        resp = finalize_response(resp, want_digests=not liveness_only)
        self.cache.put(resp, accept)
        return resp

    def _fetch_chain(self, url: str, *, accept: str, byte_cap: int) -> HttpResponse:
        current = url
        hops: list[RedirectHop] = []
        seen: set[str] = set()

        for _ in range(MAX_REDIRECTS + 1):
            if current in seen:
                return HttpResponse(
                    url=url,
                    final_url=current,
                    status=0,
                    headers={},
                    body=b"",
                    redirects=tuple(hops),
                    transport_error="redirect loop",
                )
            seen.add(current)

            resp = self._attempt(current, accept=accept, byte_cap=byte_cap)

            if 300 <= resp.status < 400 and "location" in resp.headers:
                target = urljoin(current, resp.headers["location"])
                hops.append(RedirectHop(status=resp.status, from_url=current, to_url=target))
                current = target
                continue

            return HttpResponse(
                url=url,
                final_url=current,
                status=resp.status,
                headers=resp.headers,
                body=resp.body,
                redirects=tuple(hops),
                elapsed_ms=resp.elapsed_ms,
                body_truncated=resp.body_truncated,
                transport_error=resp.transport_error,
            )

        return HttpResponse(
            url=url,
            final_url=current,
            status=0,
            headers={},
            body=b"",
            redirects=tuple(hops),
            transport_error=f"too many redirects (>{MAX_REDIRECTS})",
        )

    def _attempt(self, url: str, *, accept: str, byte_cap: int) -> HttpResponse:
        """One hop, with retries, throttle backoff and the DNS second opinion."""
        host = (urlsplit(url).hostname or "").lower()
        last: HttpResponse | None = None

        for attempt in range(RETRY_ATTEMPTS):
            with self.limiter.hold(host):
                resp = self._raw_request(url, accept=accept, byte_cap=byte_cap)
            last = resp

            if resp.status == 0 and _is_dns_error(resp.transport_error):
                # resolve.R1/R2/R3 -- never let a resolver hiccup become a
                # dead link.  This is the platform.minimax.io case: 12 false
                # positives in one run.
                resolution = resolve_host(host)
                if resolution.poisoned:
                    return self._error_response(
                        url, f"dns-poisoned: {resolution.error}", time.monotonic()
                    )
                if resolution.ok and resolution.resolver != "system":
                    with self.limiter.hold(host):
                        pinned = self._raw_request(
                            url,
                            accept=accept,
                            byte_cap=byte_cap,
                            pinned_ip=resolution.addresses[0],
                        )
                    if pinned.status:
                        return pinned
                if not resolution.ok:
                    return self._error_response(
                        url,
                        f"dns-unresolved after {len(resolution.addresses)} answers "
                        f"from system+{','.join(('8.8.8.8', '1.1.1.1'))}: {resolution.error}",
                        time.monotonic(),
                    )

            if resp.status == 429 or (resp.status in RETRY_STATUSES):
                wait = self.limiter.note_throttled(host, resp.headers.get("retry-after"))
                if attempt < RETRY_ATTEMPTS - 1 and resp.status != 429:
                    time.sleep(min(wait, RETRY_BACKOFF[min(attempt, 1)]))
                    continue
                return resp

            if resp.status == 0 and attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_BACKOFF[min(attempt, 1)])
                continue

            return resp

        return last or self._error_response(url, "no attempt made", time.monotonic())

    # ------------------------------------------------------------------ #
    # control probe / host profile
    # ------------------------------------------------------------------ #

    @staticmethod
    def control_url(url: str, *, with_extension: bool = True) -> str:
        """Build a same-host path that cannot exist.

        Two shapes are needed.  A bare random path catches hosts that answer
        everything with one shell (www.minimax.io, www.moonshot.ai).  A random
        path *with the target's extension* catches hosts that route by
        extension -- some serve /x.txt from a static handler and /x from the
        SPA router, so a bare probe would wrongly look "discriminating".
        """
        parts = urlsplit(url)
        # §3.9 适配 #6：原来是 random.choices(...) —— ruff S311（random 不适合
        # 密码学用途）。换 secrets.token_hex(12)：同样 24 个 hex 字符，形状不变，
        # 「两次调用结果不同」那条冻结断言照样过。确定性由 probe_url_provider
        # 注入提供，不由本函数提供。
        token = secrets.token_hex(12)
        path = parts.path
        suffix = ""
        if with_extension and "." in path.rsplit("/", 1)[-1]:
            suffix = "." + path.rsplit(".", 1)[-1]
        prefix = path.rsplit("/", 1)[0] or ""
        return urlunsplit(
            (parts.scheme, parts.netloc, f"{prefix}/geo-audit-probe-{token}{suffix}", "", "")
        )

    def _probe_url(self, url: str) -> str:
        """对照探针 URL。有注入就用注入的，否则退回随机 control_url。"""
        if self._probe_url_provider is not None:
            return self._probe_url_provider(url)
        return self.control_url(url)

    def host_profile(self, url: str, *, refresh: bool = False) -> HostProfile:
        """What does this host do with a path that cannot exist?

        Probed once per host and cached (see cache.py for the budget maths).
        Records two separate facts -- ``status_discriminates`` (the control
        returned a non-2xx status) and ``control_is_html`` -- because whether
        they *discriminate* depends on what the caller asked for.  An HTML
        control proves a text file is real; it proves nothing about an HTML
        page.  classify() makes that call; see the catch-all-shell note there.
        """
        host = (urlsplit(url).hostname or "").lower()
        if not refresh:
            cached = self.cache.get_profile(host)
            if cached is not None:
                return cached

        probe = self._probe_url(url)
        resp = self.fetch(probe, expect=Expect.ANY, use_cache=False)
        body = resp.text
        ctype = resp.content_type
        blocked = classify_response(
            resp.status,
            resp.headers,
            body,
            url=probe,
            expect=Expect.ANY,
            final_url=resp.final_url,
            redirects=resp.redirects,
            transport_error=resp.transport_error,
        )
        usable = blocked.verdict not in (Verdict.BLOCKED, Verdict.UNKNOWN)

        # Record the two facts separately; whether they *discriminate* depends
        # on what the caller asked for, so that decision belongs to classify().
        status_discriminates = usable and not (200 <= resp.status < 300)
        control_is_html = looks_like_html(body, ctype)

        norm = normalize_body(body)
        struct_sha, struct_tags = structural_fingerprint(body)
        profile = HostProfile(
            host=host,
            probe_url=probe,
            status=resp.status,
            content_type=ctype,
            norm_sha256=norm_sha256(body),
            norm_len=len(norm),
            norm_body_prefix=norm[:NORM_BODY_CAP],
            struct_sha256=struct_sha,
            struct_tags=struct_tags,
            final_path=urlsplit(resp.final_url).path or "/",
            status_discriminates=status_discriminates,
            control_is_html=control_is_html,
            usable=usable,
            probed_at=time.time(),
        )
        self.cache.put_profile(profile)
        return profile

    # ------------------------------------------------------------------ #
    # the API checks actually call
    # ------------------------------------------------------------------ #

    def probe(
        self,
        url: str,
        *,
        expect: Expect = Expect.ANY,
        liveness_only: bool = False,
        use_control: bool = True,
    ) -> Probe:
        """Fetch + classify one position.  This is the unit checks consume.

        A SOFT404 verdict that rests on the cached control profile is
        re-confirmed with a fresh control probe before it is returned, so the
        positive rests on two probes taken within one rate-limit interval of
        each other (FEATURE-PRIORITY.md P0 requires target and control to be
        adjacent).  The extra request is spent only on positives -- ~20% of
        positions -- so the budget cost is small and the evidence is tight.
        """
        if not self.robots_allows(url):
            return Probe(
                url,
                expect,
                None,
                classify_response(0, {}, "", url=url, expect=expect, robots_disallowed=True),
            )

        resp = self.fetch(url, expect=expect, liveness_only=liveness_only)
        control = self.host_profile(url) if use_control else None
        cls = classify_response(
            resp.status,
            resp.headers,
            resp.text,
            url=url,
            expect=expect,
            final_url=resp.final_url,
            redirects=resp.redirects,
            control=control,
            transport_error=resp.transport_error,
            body_truncated=resp.body_truncated,
        )

        if cls.verdict is Verdict.SOFT404 and cls.reason in (
            "identical_to_control",
            "near_identical_to_control",
        ):
            cls = self._confirm_soft404(url, resp, expect, cls)

        return Probe(url, expect, resp, cls)

    def _confirm_soft404(
        self, url: str, resp: HttpResponse, expect: Expect, first: Classification
    ) -> Classification:
        fresh = self.host_profile(url, refresh=True)
        second = classify_response(
            resp.status,
            resp.headers,
            resp.text,
            url=url,
            expect=expect,
            final_url=resp.final_url,
            redirects=resp.redirects,
            control=fresh,
            transport_error=resp.transport_error,
            body_truncated=resp.body_truncated,
        )
        if second.verdict is Verdict.SOFT404:
            return Classification(
                Verdict.SOFT404,
                first.reason,
                (*first.evidence, f"已用第二次即时对照探测 {fresh.probe_url} 复核，结论一致"),
                naive_would_say=first.naive_would_say,
                needs_js=first.needs_js,
                control_used=True,
                control_discriminates=False,
            )
        return Classification(
            Verdict.UNKNOWN,
            "control_unavailable",
            (*first.evidence, "第二次对照探测结论不一致，判定不稳定，本位置计入「未能评估」"),
            control_used=True,
        )

    def probe_many(
        self,
        urls: Sequence[str],
        *,
        expect: Expect = Expect.ANY,
        liveness_only: bool = False,
        use_control: bool = True,
        on_result: Callable[[Probe], None] | None = None,
    ) -> list[Probe]:
        """Probe many URLs, parallel across domains, serial within a domain.

        Work is grouped by registrable domain and each group is handed to one
        worker, so the limiter never has two threads queued on the same bucket
        (which would waste worker slots blocking on a lock).
        """
        groups: dict[str, list[str]] = {}
        for u in urls:
            groups.setdefault(registrable_domain(urlsplit(u).hostname or ""), []).append(u)

        results: list[Probe] = []
        lock = threading.Lock()

        def run_group(batch: Iterable[str]) -> None:
            for u in batch:
                p = self.probe(
                    u, expect=expect, liveness_only=liveness_only, use_control=use_control
                )
                with lock:
                    results.append(p)
                if on_result:
                    on_result(p)

        workers = max(1, min(self.config.max_workers, len(groups)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(run_group, groups.values()))
        return results

    # ------------------------------------------------------------------ #

    def exclusion_log(self) -> list[tuple[str, str, str]]:
        """(url, rule_id, reason) for every link the de-noise table dropped.

        Required, not optional: FEATURE-PRIORITY.md §5 documents what happens
        without it -- five batches excluded /cdn-cgi/l/email-protection and
        three did not, which silently made the batches non-comparable.
        """
        return list(self._exclusion_log)

    def note_exclusion(self, url: str, rule_id: str, why: str) -> None:
        self._exclusion_log.append((url, rule_id, why))

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Fetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _is_dns_error(err: str | None) -> bool:
    if not err:
        return False
    e = err.lower()
    return any(
        token in e
        for token in (
            "resolve",
            "nodename",
            "name or service",
            "servfail",
            "getaddrinfo",
            "temporary failure in name resolution",
            "connecterror",
            "no address associated",
        )
    )
