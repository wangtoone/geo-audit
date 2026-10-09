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
from dataclasses import dataclass, replace
from typing import Final, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx

from ..fixtures import ACCEPT_STAR, FixtureStore
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
from .classify import (
    challenge_header,
    classify_response,
    is_blocked,
    looks_like_html,
    mark_blocked,
)
from .normalize import (
    NORM_BODY_CAP,
    norm_sha256,
    normalize_body,
    structural_fingerprint,
)
from .ratelimit import DomainLimiter, registrable_domain
from .resolve import HostResolver, resolve_host
from .urlsafe import (
    INVALID_URL_ERROR,
    REJECTED_URL_ERROR,
    invalid_redirect_error,
    invalid_url_error,
    join_or_none,
    rejected_url_error,
    split_or_none,
)

__version__ = "0.1.0"

MAX_REDIRECTS = 10
LIVENESS_BYTE_CAP = 64 * 1024
#: RFC 9309 §2.5：爬虫「必须能解析至少 500 KiB」的 robots.txt。原来读 LIVENESS_BYTE_CAP（64 KiB），
#: 一份 200 KiB 的 robots.txt 在 64 KiB 之后的规则全丢 —— 而丢掉的常常是尾部的 Disallow。
ROBOTS_BYTE_CAP = 512 * 1024
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
    #: 文本位置（llms.txt 这类）判完之后，再用 ``Accept: */*`` 量一次，
    #: 两把尺子答案不同就判 UNKNOWN/accept_negotiated。见
    #: :meth:`Fetcher._second_ruler`。关掉它等于**只用一把尺子报结论** ——
    #: 实测那会在 9/100 个位置上给出与另一类抓取器相反的结论。
    second_ruler: bool = True


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


def interpret_robots_response(
    resp: HttpResponse,
) -> tuple[Literal["parsed", "allow_all", "disallow_all"], str, str, bool]:
    """一次 ``/robots.txt`` 抓取 → ``(policy, 要解析的文本, why, readable)``。纯函数。

    **两件事分开：``policy`` 是我们怎么做，``readable`` 是我们知道多少。** 混在一起会出两种错：
    为了「别说假话」把挑战页也当成全禁止，整站体检就不再往下抓（实测 gusto.com 从 19 个位置掉到
    14 个，原来每个位置上具体的「防火墙挑战」证据全没了）；或者为了「别丢覆盖」继续报「站点没有」。

    ``policy`` 按 RFC 9309 §2.3.1：2xx 按内容；4xx 是「不可用」→ 可以访问全部（MAY）；5xx / 网络
    错误是「不可达」→ **必须**视同完全不许抓（§2.3.1.4）。跳转成环 / 超过 10 跳，RFC §2.3.1.2 只说
    「爬虫 MAY 当作不可用」（= 放行）；这里取更保守的一侧不抓 —— 那是我们的选择，不是 RFC 的要求。
    ``readable`` 只在**真读到了一份 robots.txt（含观察到的 404 / 410）**时为 True。

    ======================  ============  =========  ==========================================
    读到的                    policy        readable   说明
    ======================  ============  =========  ==========================================
    2xx（含跟跳转之后）        parsed        True       按内容办；空正文 → allow_all
    404 / 410                allow_all     True       **观察到的**缺席，``why`` 里只有跳转说明
    其余 4xx（401 / 403 …）    allow_all     False      RFC 视为「没有」；防火墙 / 鉴权也会给 403
    429                      allow_all     False      限流，没读到（原来的行为：放行）
    任何状态码 + 挑战头         allow_all     False      防火墙下发的挑战页不是 robots.txt（AWS 的
                                                    是 **202**，Cloudflare 的是 403）
    3xx 没有 Location         allow_all     False      跳不过去
    202（没有挑战头）          allow_all     False      「已接受、还没处理完」，不是这份文件的表示
    2xx 的 HTML，正文是挑战页   allow_all     False      没带挑战头的挑战页（旧式 Cloudflare 页等）
    5xx / 网络错误            disallow_all  False      RFC 9309 §2.3.1.4（MUST）：视同完全不许抓
    跳转成环 / 超过 10 跳      disallow_all  False      RFC 只是允许当作「不可用」；我们取保守一侧
    replay 缺快照（合成 599）   allow_all     False      不是站点的事实，why 里写明
    ======================  ============  =========  ==========================================

    ``why`` 是给人看的原因，进 ``RobotsInfo.why``。
    """
    status = resp.status
    hops = len(resp.redirects)
    via = f"经 {hops} 次跳转取自 {resp.final_url}" if hops else ""
    if resp.headers.get("x-geo-audit-fixture") == "missing":
        return "allow_all", "", "replay：没有这份 robots.txt 的冻结快照，不是站点的事实", False
    if status == 0:
        return "disallow_all", "", f"没读到：{resp.transport_error or '无响应'}", False
    hit = challenge_header(resp.headers)
    if hit is not None:
        why = f"响应头 {hit[0]}: {hit[1]}（HTTP {status}）：防火墙下发的是挑战页，不是 robots.txt"
        return "allow_all", "", why, False
    if status == 202:
        # 202 Accepted =「请求收到了，还没处理完」，不是这份资源的表示（RFC 9110 §15.3.3）。
        # AWS WAF 的 Challenge 就是 202，带 x-amzn-waf-action 头的上面已经认出来了；没有头的
        # 202 也不能读成「一份空的 robots.txt」→ 每个爬虫「放行」。
        return "allow_all", "", "HTTP 202（请求已接受，但没有返回文件），不是 robots.txt", False
    if 200 <= status < 300:
        # RFC 9309 §2.2：必须是 UTF-8。用 utf-8-sig 去掉开头的 BOM（Windows 记事本存出来的
        # robots.txt 常带）—— 否则第一行 ``\ufeffUser-agent: *`` 认不出来，后面的 Disallow 变成
        # 无主规则，整份文件读成「全放行」。也不按 Content-Type 的 charset 解码：协议没给它位置。
        raw = resp.body.decode("utf-8-sig", errors="replace")
        notes = [via] if via else []
        if resp.body_truncated:
            notes.append(
                f"超过 {ROBOTS_BYTE_CAP // 1024} KiB，只解析了前 {ROBOTS_BYTE_CAP // 1024} KiB"
            )
        has_rules = any(
            line.strip().lower().startswith(("user-agent:", "allow:", "disallow:", "sitemap:"))
            for line in raw.splitlines()
        )
        if raw and not has_rules and looks_like_html(raw, resp.content_type):
            # 没带挑战头、但正文就是挑战页（旧式 Cloudflare「Just a moment」页、Incapsula 的
            # 200 墙）：和位置判定用同一个 is_blocked，「这个站的内容页会被判被拦」与「它的
            # robots.txt 是挑战页」就不会各说各话。只在没有任何规则行时才问 —— 真有规则的文件，
            # 哪怕被标成 text/html 也照读。
            gate = is_blocked(status, resp.headers, raw, url=resp.final_url)
            if gate is not None:
                return "allow_all", "", f"返回的是防火墙的挑战页，不是 robots.txt：{gate[2]}", False
            notes.append("返回的是 HTML 页面（多半是 SPA 外壳），没有任何规则")
        return ("parsed" if raw else "allow_all"), raw, "；".join(notes), True
    if status in (404, 410):
        return "allow_all", "", via, True
    if status == 429:
        return "allow_all", "", "HTTP 429 限流，没读到", False
    if status >= 500:
        return "disallow_all", "", f"HTTP {status}（服务端错误），没读到", False
    if 300 <= status < 400:
        return "allow_all", "", f"HTTP {status} 没有可跟的 Location，没读到", False
    why = (
        f"HTTP {status}：按 RFC 9309 视为没有 robots.txt，但这也可能是防火墙 / 鉴权拦了我们，"
        "不能当成「站点没有这个文件」"
    )
    return "allow_all", "", why, False


class _NoCookies(httpx.Cookies):
    """永远为空的 cookie jar。

    httpx 没有「关掉 cookie」的开关：`cookies=None` 只是不给初始值，响应里的
    Set-Cookie 照样会被 `extract_cookies` 写进 jar。这里让写入变成 no-op ——
    比每次请求后手动 `clear()` 可靠，因为不依赖调用方记得清。
    """

    def extract_cookies(self, response: object) -> None:
        return None

    def set_cookie_header(self, request: object) -> None:
        return None


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
        resolver: HostResolver | None = None,
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
        # DNS 注入点。**必须有**：本类在传输失败时会自己做一次 resolve.R1–R4 的
        # 二次确认（下面 _fetch_chain 里那处），那条路径绕过了 discover(resolver=...)。
        # 第 7 步只把 discovery.py 的两个调用点接上了注入点，漏了这里 ——
        # 于是 GEO_AUDIT_FORBID_DNS=1 下 fp_gate 的 7 条测试全部撞上断网闸。
        self._resolver = resolver
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
            # **关掉 cookie jar。** httpx 默认开着，于是站点发的 Set-Cookie 会被
            # 存下来、在后续请求里自动回放。实测：
            #     第 1 次请求 Cookie: None
            #     第 3 次请求 Cookie: sid=SECRET123      ← 第 1 次响应发的
            #
            # 两个后果，第二个更要命：
            # 1. 我们不是登录用户，却在假装持有会话状态 —— 抓到的可能是
            #    「半登录态」的页面，那不是匿名 AI 爬虫看到的东西；
            # 2. **目标页与对照探针会带不同的 cookie**，两边就不是同一把尺子了。
            #    而整个软 404 判定就靠「同 host 随机路径对照」——尺子不同，
            #    正文/骨架比对的差异可能来自 cookie 而不是站点行为。
            cookies=None,
        )
        # `client.cookies = x` 的 setter 会把传进去的东西重新包成 `Cookies(x)`,
        # 子类直接被丢掉（实测：赋值后 cookie 照样回放）。所以写私有属性。
        # 这是对 httpx 内部的依赖，用一条断言钉住：哪天它改名，测试立刻红，
        # 而不是悄悄退回「带 cookie 抓取」。
        assert hasattr(self._client, "_cookies"), "httpx.Client 没有 _cookies 了，改法要重写"
        self._client._cookies = _NoCookies()
        self._robots: dict[str, RobotsInfo] = {}
        self._robots_parsers: dict[str, urllib.robotparser.RobotFileParser] = {}
        self._robots_lock = threading.Lock()
        self._exclusion_log: list[tuple[str, str, str]] = []  # (url, rule_id, why)
        #: 真实发出去的 HTTP 请求条数（含跳转每一跳、robots.txt、重试）。
        #: 与 DiscoveryBudget.spent（逻辑 URL）是两个数，报告里要分开印。
        self._http_requests = 0
        self._http_lock = threading.Lock()

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
        # **真实 HTTP 请求计数。** 这是全仓唯一一次 HTTP 交换的出口，
        # 所以也是唯一能说清「到底发了几条」的地方。
        #
        # 为什么要单独记：`DiscoveryBudget` 记的是**逻辑 URL**（同一 URL 只记
        # 一次、对照探针按 host 记一次），而 CLI 的 `--max-requests` 与报告里的
        # 「请求 N / 上限 M」两处都写着「请求」。实测一次 probe（记 2 个预算
        # 单位）在 9 跳跳转链上打出 **21 条**真实请求 —— 10.5 倍。
        # 用户设 120 以为是 120 条，最坏情况上千条。
        with self._http_lock:
            self._http_requests += 1
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
        except (httpx.InvalidURL, UnicodeError) as exc:
            # 请求建不出来 / 主机名编不成 DNS 标签（``a..b``：空标签，socket 的 idna 编码抛
            # UnicodeError，它不是 httpx.HTTPError）：站点写的 URL 有问题，不是网络故障，
            # 也没有响应。上游的 ``split_or_none`` 拦得住 httpx 认得的那些，这里兜其余的。
            return self._error_response(url, rejected_url_error(url, exc), started)

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
        # 走 _fetch_chain，不再是单发的 _raw_request：
        #   * 跟跳转（RFC 9309 §2.3.1.2：至少跟 5 跳，「可达就必须按文件里的规则办」）。
        #     原来 301 / 308 的 robots.txt 被当成「没有 robots.txt」放行全部；
        #   * 每一跳都过限流器、5xx 重试、DNS 二次确认。原来一次 503、一次 DNS 抖动
        #     就让这个 host 在这一轮里**全部**不许抓，而且结果缓存一整轮；
        #   * 读上限 512 KiB（RFC 要求至少解析 500 KiB），原来是 64 KiB。
        resp = self._fetch_chain(
            robots_url, accept="text/plain", byte_cap=ROBOTS_BYTE_CAP, robots=True
        )
        policy, raw, why, readable = interpret_robots_response(resp)
        parser = urllib.robotparser.RobotFileParser()
        if policy == "disallow_all":
            parser.parse(["User-agent: *", "Disallow: /"])
        else:
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
            fetched=200 <= resp.status < 300,
            status=resp.status,
            crawl_delay=delay,
            sitemaps=sitemaps,
            raw=raw,
            policy=policy,
            why=why,
            readable=readable,
        )
        with self._robots_lock:
            self._robots[host] = info
            self._robots_parsers[host] = parser
        return info

    def robots_verdict(self, url: str) -> Literal["allowed", "disallowed", "unreadable"]:
        """robots 闸的三态结果。**「没读到」与「站方写了禁止」是两件事**。

        * ``disallowed``  读到了 robots.txt，它对我们的 UA 说不许抓这个路径；
        * ``unreadable``  不可达：5xx / 网络错误（RFC 9309 §2.3.1.4 **要求**视同完全不许抓），
          以及跳转成环 / 超限（RFC §2.3.1.2 只是**允许**当作不可用；我们取保守一侧）。照样不抓 ——
          但报告里不能写成「你的 robots.txt 禁止」，那对站点是假话：站点什么都没禁止，是我们没能看。
          （防火墙挑战页、429、其余 4xx 是 RFC 的「不可用」，照常抓；它们在
          ``RobotsInfo.readable`` 里记为没读到，位置各自的判定会带上具体证据。）
        """
        if not self.config.respect_robots:
            return "allowed"
        if urlsplit(url).path == "/robots.txt":
            return "allowed"
        host = (urlsplit(url).hostname or "").lower()
        if host not in self._robots_parsers:
            self.robots_for(url)
        info = self._robots.get(host)
        if info is not None and info.policy == "disallow_all":
            return "unreadable"
        parser = self._robots_parsers.get(host)
        if parser is None:
            return "allowed"
        return "allowed" if parser.can_fetch(self.user_agent, url) else "disallowed"

    def robots_allows(self, url: str) -> bool:
        """Honour robots.txt for everything except /robots.txt itself.

        A robots-blocked position becomes UNKNOWN / robots_disallowed, and one whose
        robots.txt we could not read becomes UNKNOWN / robots_unreadable; both land in
        the report's 未能评估 region.  That is the honest outcome:
        "we were not allowed to look" is a true statement, "no problem here"
        is not.  --no-robots exists for auditing your own property.
        """
        return self.robots_verdict(url) == "allowed"

    def _robots_block_marker(self, url: str, verdict: str) -> str:
        """``classify_response`` 认的 transport_error 前缀。"""
        if verdict == "unreadable":
            host = (urlsplit(url).hostname or "").lower()
            info = self._robots.get(host)
            return f"robots_unreadable: {(info.why if info else '') or 'robots.txt 读不到'}"
        return f"robots_disallowed: {urlsplit(url).path or '/'}"

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
        accept_override: str | None = None,
    ) -> HttpResponse:
        """Fetch ``url``, following redirects and recording the chain.

        ``accept_override`` 换掉按 ``expect`` 推出来的 Accept 头。**这不是调味
        品**：实测 9 个 AI 路径位置的答案取决于这个头（见 ``ACCEPT_STAR`` 与
        :meth:`_second_ruler`），所以「用哪把尺子量的」必须由调用方说了算，
        而且要能进证据。缓存键本来就含 accept，两把尺子不会互相顶掉。
        """
        accept = accept_override or (ACCEPT_TEXT if expect is Expect.TEXT_FILE else ACCEPT_HTML)
        byte_cap = LIVENESS_BYTE_CAP if liveness_only else CONTENT_BYTE_CAP

        # ---- 先看 URL 能不能解析：站点给的链接 / 跳转 / sitemap 里什么都可能有 ---------
        # ``http://[``、``https://[your-domain]/``、``http://h:abc/`` 这类字符串 urllib 会抛
        # ValueError，而下面每一步（robots 闸、限速器、缓存、请求）都要解析 URL。一个请求都没发、
        # 也没有任何东西可以重试：按「没发出去」报（UNKNOWN / network_error，证据里带着原串）。
        if split_or_none(url) is None:
            return HttpResponse(
                url=url,
                final_url=url,
                status=0,
                headers={},
                body=b"",
                transport_error=invalid_url_error(url),
            )

        # ---- robots 闸。**排在缓存之前** ------------------------------------
        #
        # `robots_allows()` 原来只有一个调用方 —— `probe()`。于是走 `fetch()`
        # 的路径全部绕过了它：**sitemap 抓取**（discovery.py 的
        # `fetch_sitemap_urls`，最多 5+5 条）、**对照探针**（`host_profile`）、
        # 以及录制脚本。而 `robots_allows` 自己的文档串写的是
        # 「honour robots.txt for **everything** except /robots.txt itself」。
        #
        # 最要紧的情形是 `Disallow: /`：那样的站原本仍会被抓 sitemap 与对照探针。
        #
        # 放在缓存命中**之前**：一条早先（比如 --no-robots 那轮）缓存过的响应
        # 不该让这次绕过检查。robots.txt 自身由 `robots_allows` 里的路径判断豁免，
        # 它走 `_raw_request` 不经过这里。
        gate = self.robots_verdict(url)
        if gate != "allowed":
            resp = HttpResponse(
                url=url,
                final_url=url,
                status=0,
                headers={},
                body=b"",
                # classify_response 认这个前缀 → UNKNOWN/robots_disallowed（站方写了禁止）
                # 或 UNKNOWN/robots_unreadable（我们没读到 robots.txt）。
                # 不用 status 403 之类的真状态码：那会被判成「站点拦了我们」，
                # 而这里是**我们自己决定不抓**，两件事在报告里不该长得一样。
                transport_error=self._robots_block_marker(url, gate),
            )
            return resp

        if use_cache:
            hit = self.cache.get("GET", url, accept)
            if hit is not None:
                return mark_blocked(hit)

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
            return mark_blocked(resp)

        resp = self._fetch_chain(url, accept=accept, byte_cap=byte_cap)
        # §3.9 适配 #5：读完 body 的这一刻一次性算好三个摘要再入缓存。
        # liveness_only（64 KiB 上限的外链存活检查）不算 —— 截断正文的哈希
        # 跟完整正文的哈希不同，那是测量假象不是发现。
        resp = finalize_response(resp, want_digests=not liveness_only)
        self.cache.put(resp, accept)
        return mark_blocked(resp)

    def _fetch_chain(
        self, url: str, *, accept: str, byte_cap: int, robots: bool = False
    ) -> HttpResponse:
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

            resp = self._attempt(current, accept=accept, byte_cap=byte_cap, robots=robots)

            if 300 <= resp.status < 400 and "location" in resp.headers:
                location = resp.headers["location"]
                target = join_or_none(current, location)
                if target is None:
                    # 站点的 3xx 指向一个解析不了的地址（``Location: http://[``）：跟不过去。
                    # 和「redirect loop」「too many redirects」一样走 status 0 + transport_error，
                    # 分类器记成 UNKNOWN / network_error，证据里带着那个 Location 的原串。
                    return HttpResponse(
                        url=url,
                        final_url=current,
                        status=0,
                        headers={},
                        body=b"",
                        redirects=tuple(hops),
                        transport_error=invalid_redirect_error(location),
                    )
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

    def _attempt(
        self, url: str, *, accept: str, byte_cap: int, robots: bool = False
    ) -> HttpResponse:
        """One hop, with retries, throttle backoff and the DNS second opinion.

        ``robots=True``：这一跳属于 /robots.txt 的读取。它的 5xx 只做重试间的退避睡眠，**不**
        调 :meth:`DomainLimiter.note_throttled`。限速桶是 registrable domain，那个调用会把整个域
        的间隔翻倍且本轮不回落 —— 一个 host 的 robots.txt 503 两次，同域下健康的兄弟 host 这一轮
        每条请求都慢 4 倍（实测 6 条请求 14 s → 112 s）；robots.txt 一直 503 的 host 本身按 RFC 就
        整个不抓了，没有「抓得太快」可言。429 仍是服务端明说的「慢点」，照常拉宽。
        """
        host = (urlsplit(url).hostname or "").lower()
        last: HttpResponse | None = None

        for attempt in range(RETRY_ATTEMPTS):
            with self.limiter.hold(host):
                resp = self._raw_request(url, accept=accept, byte_cap=byte_cap)
            last = resp

            if resp.status == 0 and (resp.transport_error or "").startswith(
                (INVALID_URL_ERROR, REJECTED_URL_ERROR)
            ):
                # URL / 主机名有问题，请求发不出去：重试不会变，也不是 DNS 抖动，别去问第二意见
                return resp

            if resp.status == 0 and _is_dns_error(resp.transport_error):
                # resolve.R1/R2/R3 -- never let a resolver hiccup become a
                # dead link.  This is the platform.minimax.io case: 12 false
                # positives in one run.
                resolution = resolve_host(host, resolver=self._resolver)
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

            if challenge_header(resp.headers) is not None:
                # 响应头说这是防火墙下发的挑战页：那是对「我们」（UA / IP）的判决，不是负载信号。
                # 放慢没用，重试也不会变 —— Cloudflare 的 503 挑战重试两次只是多打两个请求，
                # Vercel 的 429 挑战会把整个域的间隔 2→4→8→16→30 s 拉宽，一个全站被挑战的域
                # 就要按 30 s 一个请求去跑完预算。真正的限流（没有挑战头的 429 / 503）不受影响。
                return resp

            if resp.status == 429 or (resp.status in RETRY_STATUSES):
                if robots and resp.status != 429:
                    wait = RETRY_BACKOFF[min(attempt, 1)]
                else:
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

        A URL that cannot be parsed (a link the audited site wrote as ``http://[``) is not
        requested: UNKNOWN / network_error, with the string in the evidence.
        """
        if split_or_none(url) is None:
            return Probe(
                url,
                expect,
                None,
                classify_response(
                    0,
                    {},
                    "",
                    url=url,
                    expect=expect,
                    transport_error=invalid_url_error(url),
                ),
            )
        gate = self.robots_verdict(url)
        if gate == "disallowed":
            return Probe(
                url,
                expect,
                None,
                classify_response(0, {}, "", url=url, expect=expect, robots_disallowed=True),
            )
        if gate == "unreadable":
            return Probe(
                url,
                expect,
                None,
                classify_response(
                    0,
                    {},
                    "",
                    url=url,
                    expect=expect,
                    transport_error=self._robots_block_marker(url, gate),
                ),
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

        if self._wants_second_ruler(expect, liveness_only, resp, cls):
            cls = self._second_ruler(url, resp, cls)

        return Probe(url, expect, resp, cls)

    # ------------------------------------------------------------------ #
    # 第二把尺子（Accept 对照）
    # ------------------------------------------------------------------ #

    #: 主尺子与第二把尺子之间，什么样的差异**算差异**。
    #:
    #: 只认两条，都是「换个 Accept 头就换一个结论」级别的：
    #:
    #: 1. 2xx 与非 2xx（一边说有、一边说没有）；
    #: 2. HTML 与非 HTML（一边拿到文本文件、一边拿到页面壳 —— 后者正是
    #:    ``html_where_text_expected`` 这条软 404 判据要抓的东西）。
    #:
    #: **不认**：字节数差几十（时间戳、nonce）、``text/markdown`` 与
    #: ``text/plain``（同一份文本的两种叫法，实测 6 个 host 如此）。
    #: 把那些也算成差异会让每份报告都挂满噪声，而噪声正是这个仓库
    #: 40.5% 假阳性那一课的来源。
    _RULER_DIFF_KINDS: Final = ("状态码", "正文类型")

    #: 主尺子这一侧根本没拿到答案时，第二把尺子无从对比 —— 一条请求都不发。
    #: 判据是 reason 而不是状态码：这几条的共同点是「我们没测到」，
    #: 拿另一把尺子再问一遍既不会产生对比，也不会变出第一次没有的信息。
    _NO_FIRST_READING: Final = frozenset(
        {
            "not_fetched",
            "robots_disallowed",
            "robots_unreadable",
            "interrupted",
            "network_error",
            "timeout",
        }
    )

    def _wants_second_ruler(
        self, expect: Expect, liveness_only: bool, resp: HttpResponse, cls: Classification
    ) -> bool:
        """要不要为这个位置多花一条请求。

        只有文本位置量两把尺子（普通页面本来就该是 HTML，量了没有可读的差异），
        ``liveness_only`` 的外链存活检查不量（那问的是「在不在」不是「是什么」），
        主尺子没读数的也不量（见 :data:`_NO_FIRST_READING`）。

        最后一条不只是省钱：replay 语料里多数站内位置就是「没录过」，
        照量会给每个这样的位置加一次 2 秒限速等待，画廊重建从几分钟涨到十几分钟，
        换来的全是「第二把尺子也没测到」这种一句有效信息都没有的证据行。
        """
        return (
            expect is Expect.TEXT_FILE
            and self.config.second_ruler
            and not liveness_only
            and cls.reason not in self._NO_FIRST_READING
            and not resp.transport_error
        )

    def _second_ruler(self, url: str, first: HttpResponse, cls: Classification) -> Classification:
        """用 ``Accept: */*`` 再量一次这个文本位置，两把尺子不一致就判 UNKNOWN。

        **为什么值得多花一条请求**：我们的主尺子（``ACCEPT_TEXT``）里点名要
        ``text/markdown``，而实测 100 个 AI 路径位置里有 9 个的答案取决于这个头：

        - ``www.openstatus.dev`` 与 ``dev.wix.com`` 的 llms.txt / llms-full.txt：
          主尺子拿到 **404**（站点把「要 markdown」的请求 rewrite 到
          ``/api/markdown/<path>``，那里没有 llms.txt），``*/*`` 拿到 **200 真文件**。
          只用主尺子报，就是对一个健在的文件说「它 404」。
        - ``api-docs.ecwid.com`` / ``developers.attio.com`` /
          ``developers.pipedrive.com`` / ``developers.printify.com`` /
          ``docs.moderntreasury.com``：反过来 —— 主尺子拿到 markdown 正文，
          ``*/*`` 拿到 HTML 页面壳。只用主尺子报，就是把一个对多数抓取器表现为
          页面壳的位置说成「通过」。

        两个方向都是同一个病：**拿一把尺子的读数去讲另一把尺子下的事实**。
        所以这里不挑边、也不替读者决定哪一把才算数 —— 两把不一致时，这个位置
        的诚实结论是「取决于请求头」，按 §6.4 R1 落 UNKNOWN 并把两边读数都写进
        证据（每一边都带各自的 curl 复现命令）。

        一致时**不动原判定**，只加一行「两把尺子一致」的证据 —— 那是这条结论
        的强化，不是新结论。
        """
        second = self.fetch(url, expect=Expect.TEXT_FILE, accept_override=ACCEPT_STAR)
        if second.status == FixtureStore.MISSING_VARIANT_STATUS:
            return replace(
                cls,
                evidence=(
                    *cls.evidence,
                    f"第二把尺子（Accept: {ACCEPT_STAR}）在本位置没有测量数据",
                ),
            )

        blocked = self._ruler_blocked(url, first, second)
        if blocked:
            return replace(cls, evidence=(*cls.evidence, blocked))

        diffs = self._ruler_diffs(first, second)
        if not diffs:
            return replace(
                cls,
                evidence=(
                    *cls.evidence,
                    f"用 Accept: {ACCEPT_STAR} 再量一次，{'、'.join(self._RULER_DIFF_KINDS)}都一致",
                ),
            )
        return Classification(
            Verdict.UNKNOWN,
            "accept_negotiated",
            (
                f"这个位置的答案取决于请求头：{'；'.join(diffs)}",
                f"主尺子 Accept: {ACCEPT_TEXT} -> {self._ruler_line(first)}",
                f"第二把尺子 Accept: {ACCEPT_STAR} -> {self._ruler_line(second)}",
                f"复现：curl -sSL -H 'Accept: {ACCEPT_TEXT}' -o /dev/null "
                f"-w '%{{http_code}} %{{content_type}} %{{size_download}}' {url}"
                f"，再把 Accept 换成 {ACCEPT_STAR} 跑一遍",
                # 原判定的证据降级留在后面：它是**主尺子那一侧**的判读，不是这个
                # 位置的结论。不加这个前缀，报告读起来会是「HTTP 404（状态码正确）」
                # 紧跟着「答案取决于请求头」—— 前半句听着像已经定案了。
                *(f"（主尺子那一侧的判读：{e}）" for e in cls.evidence),
            ),
            naive_would_say=cls.naive_would_say,
            needs_js=cls.needs_js,
            control_used=cls.control_used,
            control_discriminates=cls.control_discriminates,
            secondary_reasons=cls.all_reasons if cls.reason != "accept_negotiated" else (),
        )

    @staticmethod
    def _ruler_blocked(url: str, first: HttpResponse, second: HttpResponse) -> str | None:
        """有一边被拦住了就不许比 —— **拦截不是答案**。

        实测撞到两次，两次都会被误读成「答案取决于请求头」：

        - ``dev.hume.ai/llms.txt``：录第二把尺子那天我们的 IP 已经被 Cloudflare
          盯上，``*/*`` 拿到 403 挑战页，而主尺子那份是五天前录的 200。
        - ``gusto.com/llms.txt``：反过来，主尺子那份是 403、第二把尺子 200。
          隔离复验（独立进程、双向顺序、不复用 cookie）三种 Accept 全是 403 ——
          差异来自 WAF 的状态，与 Accept 无关。

        把这种差异归因给 Accept，等于用一句听起来很具体的话掩盖「我们没量到」。
        """
        for label, resp in (("主尺子", first), ("第二把尺子", second)):
            hit = is_blocked(resp.status, dict(resp.headers), resp.text, url=url)
            if hit:
                return (
                    f"{label}这一侧被拦住了（{hit[2]}），两把尺子不可比 —— "
                    "本位置没有 Accept 层面的结论"
                )
        return None

    @staticmethod
    def _ruler_diffs(first: HttpResponse, second: HttpResponse) -> tuple[str, ...]:
        """两把尺子之间**算数**的差异。判据见 :data:`_RULER_DIFF_KINDS`。"""
        out: list[str] = []
        ok1, ok2 = 200 <= first.status < 300, 200 <= second.status < 300
        if ok1 != ok2:
            out.append(f"状态码 {first.status} vs {second.status}")
        if not (ok1 and ok2):
            # 非 2xx 的正文类型没有可比性：404 页与 301 的空正文长什么样都不说明
            # 这个位置「是什么」。只在两边都 2xx 时比正文类型。
            return tuple(out)
        html1 = looks_like_html(first.text, first.headers.get("content-type", ""))
        html2 = looks_like_html(second.text, second.headers.get("content-type", ""))
        if html1 != html2:
            out.append(
                "正文类型 " + " vs ".join("HTML 页面" if h else "文本文件" for h in (html1, html2))
            )
        return tuple(out)

    @staticmethod
    def _ruler_line(resp: HttpResponse) -> str:
        ct = resp.headers.get("content-type", "").split(";")[0].strip() or "（无 content-type）"
        return f"{resp.status} {ct} {len(resp.body):,} 字节"

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
            parts = split_or_none(u)  # 解析不了的 URL 归到空 host 那一组，``probe`` 会如实报告
            host = (parts.hostname or "") if parts is not None else ""
            groups.setdefault(registrable_domain(host), []).append(u)

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

    @property
    def http_requests(self) -> int:
        """真实发出去的 HTTP 请求条数。

        与预算记的「逻辑 URL」不是一个数：跳转的每一跳、robots.txt、重试
        都算一条。报告里两个数都要印 —— 只印前者会让读者以为我们很克制。
        """
        with self._http_lock:
            return self._http_requests

    def note_exclusion(self, url: str, rule_id: str, why: str) -> None:
        self._exclusion_log.append((url, rule_id, why))

    def close(self) -> None:
        self._client.close()
        # 连 cache 的 sqlite 连接一起关：3.13 起未关的连接在 GC 里发
        # ResourceWarning，而 filterwarnings=error 把它升成错误（CI 上挂了 24 条）。
        self.cache.close()

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
