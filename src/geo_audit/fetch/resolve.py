"""DNS resolution with a mandatory second opinion.

This module exists because of one measurement: on a single domain
(platform.minimax.io) the first pass produced **12 dead links that were all
false positives** -- the local resolver returned "Could not resolve host" and a
retry 25 s later returned 200 for every one of them.  Two more cases in the
same run:

  * ``cog.run`` -- local ``host cog.run`` gives SERVFAIL, curl returns 000, but
    ``dig @8.8.8.8`` has an A record (104.18.17.10) and a ``--resolve``-pinned
    request returns 200.
  * ``www.talkie-ai.com`` -- local resolver answers **127.0.0.1**; 8.8.8.8 and
    1.1.1.1 both return a real Akamai address.  Local DNS poisoning, not a
    dead site.

Rules, all mandatory:

  R1  A resolution failure is never a dead link.  Re-resolve through the
      fallback resolvers before drawing any conclusion.
  R2  If a fallback resolver answers, pin the request to that address (keeping
      the original Host header and SNI) and retry.
  R3  Any answer inside loopback / link-local / RFC1918 / 0.0.0.0/8 is treated
      as poisoned -- verdict UNKNOWN with reason ``dns_poisoned``, never dead.
  R4  If every resolver fails, verdict UNKNOWN with reason ``dns_unresolved``.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

try:  # pragma: no cover - import guard
    import dns.resolver as _dnspython

    HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover
    _dnspython = None  # type: ignore[assignment]
    HAVE_DNSPYTHON = False

#: Public resolvers used for the second (and third) opinion.  Chosen because
#: they are the two the empirical run actually verified against.
FALLBACK_RESOLVERS: tuple[str, ...] = ("8.8.8.8", "1.1.1.1")

DNS_TIMEOUT = 4.0


@dataclass(frozen=True, slots=True)
class Resolution:
    host: str
    addresses: tuple[str, ...]
    #: "system" | "8.8.8.8" | "1.1.1.1" | "none"
    resolver: str
    poisoned: bool
    error: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.addresses) and not self.poisoned


def _is_bogus(addr: str) -> bool:
    """R3.  Addresses that cannot be a real public site."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
    )


def _system_resolve(host: str) -> tuple[tuple[str, ...], str | None]:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return (), f"getaddrinfo: {exc}"
    except OSError as exc:  # pragma: no cover
        return (), f"socket: {exc}"
    return tuple(dict.fromkeys(i[4][0] for i in infos)), None


def _public_resolve(host: str, nameserver: str) -> tuple[tuple[str, ...], str | None]:
    if not HAVE_DNSPYTHON:  # pragma: no cover
        return (), "dnspython 未安装，无法做第二解析器复测"
    resolver = _dnspython.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    out: list[str] = []
    err: str | None = None
    for rdtype in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, rdtype)
            out.extend(str(r) for r in answer)
        except Exception as exc:  # dnspython raises a wide family
            err = f"{nameserver} {rdtype}: {type(exc).__name__}"
    return tuple(dict.fromkeys(out)), (None if out else err)


def resolve_host(host: str) -> Resolution:
    """Resolve ``host``, escalating through the fallback resolvers.

    Never raises.  The returned ``Resolution`` is the only input the fetcher
    needs to decide between "retry pinned", "unknown/dns_poisoned" and
    "unknown/dns_unresolved".
    """
    host = host.lower().strip(".")

    addrs, err = _system_resolve(host)
    good = tuple(a for a in addrs if not _is_bogus(a))
    if good:
        return Resolution(host, good, "system", poisoned=False)

    system_was_poisoned = bool(addrs) and not good

    for ns in FALLBACK_RESOLVERS:
        addrs2, err2 = _public_resolve(host, ns)
        good2 = tuple(a for a in addrs2 if not _is_bogus(a))
        if good2:
            # R2/R3: the fallback disagrees with the system resolver.  Trust
            # the fallback and say so, so the report can explain the retry.
            return Resolution(host, good2, ns, poisoned=False)
        err = err or err2

    if system_was_poisoned:
        return Resolution(
            host,
            (),
            "none",
            poisoned=True,
            error=f"dns-poisoned: 系统解析器返回 {addrs}，公共解析器无有效记录",
        )
    return Resolution(host, (), "none", poisoned=False, error=err or "resolve failed")
