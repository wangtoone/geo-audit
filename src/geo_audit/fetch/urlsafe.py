"""Parse URLs that come from the audited site without letting a malformed one abort the audit.

``urllib.parse`` raises ``ValueError`` for URLs a browser would also refuse: an unbalanced or
non-address bracket in the host (``http://[``, ``https://[your-domain]/docs`` - a placeholder
that is common in API docs), a port that is not a number (``http://h:abc/``, which ``urlsplit``
accepts and ``.port`` rejects), a host whose NFKC form contains ``/`` or ``@`` (``http://℀/``).
``httpx`` - the library every request goes through - refuses more: an IPv4 address with a field
over 255 (``http://256.256.256.256/``), a control character anywhere in the URL, a host that is
not valid IDNA (``http://xn--/``, a zero-width space), more than 65536 characters; and a host
with an empty or over-long DNS label (``http://a..b/``) makes ``socket.getaddrinfo`` raise
``UnicodeError``. Every one of those strings is data the audited site hands us - a redirect
``Location``, an ``href``, an ``llms.txt`` link, a sitemap ``<loc>`` - so none of them may raise
past the place that read it.

Two questions, two functions, because they are asked in different places and cost different
amounts:

* :func:`split_or_none` - can urllib *parse* it? Every ``urlsplit(...)`` / ``.hostname`` /
  ``.port`` / ``.path`` further down is safe on a string that passes. Cheap (about a microsecond);
  this is the guard for code that only takes URLs apart.
* :func:`requestable` - can the HTTP stack *send* it? ``split_or_none`` plus what ``httpx`` and DNS
  insist on. About seven microseconds and linear in the length of the URL; this is the guard for
  code that is about to make a request.

Both return ``None`` / ``False`` instead of raising, and the caller decides what the audit says
about the URL (see ``UNPARSEABLE_*``).
"""

from __future__ import annotations

from urllib.parse import SplitResult, urljoin, urlsplit

import httpx

#: ``Exclusion.rule_id`` / ``EligibilityExclusion.rule_id`` of a link whose URL cannot be requested.
UNPARSEABLE_RULE_ID = "unparseable_url"
#: What the report says about such a link (``Exclusion.rule_desc``). It states what the tool did
#: not do; whether the link is broken on the site is not for the tool to say - a leaked
#: placeholder in a code sample looks the same.
UNPARSEABLE_REASON = (
    "URL 无法解析或发不出请求（urllib 或 httpx 拒绝它，例如 http://[ 、"
    "https://[your-domain]/ 、http://256.256.256.256/ ），本工具没有检查这条链接，"
    "既不判死也不判活"
)

#: ``HttpResponse.transport_error`` prefixes of a request that was never made because the URL
#: (or the ``Location`` a 3xx pointed to) cannot be requested. The messages quote the site's own
#: URL, so ``classify_response`` and ``dead_links._transport_error_kind`` match these prefixes
#: *before* any substring test (a URL containing "timeout" is not a timeout).
INVALID_URL_ERROR = "invalid URL (cannot be parsed)"
INVALID_REDIRECT_ERROR = "invalid redirect Location (cannot be parsed)"
#: The same, for what :func:`requestable` let through but the HTTP stack refused while making the
#: request or reading the response (a ``Location`` httpx cannot decode): deterministic, so the
#: fetcher neither retries it nor asks DNS for a second opinion.
REJECTED_URL_ERROR = "URL rejected by the HTTP stack"
URL_ERROR_PREFIXES = (INVALID_URL_ERROR, INVALID_REDIRECT_ERROR, REJECTED_URL_ERROR)

#: RFC 1035 §2.3.4: a label is 1-63 octets and a name at most 253 (without the trailing dot).
MAX_DNS_LABEL = 63
MAX_DNS_NAME = 253

__all__ = [
    "INVALID_REDIRECT_ERROR",
    "INVALID_URL_ERROR",
    "REJECTED_URL_ERROR",
    "UNPARSEABLE_REASON",
    "UNPARSEABLE_RULE_ID",
    "URL_ERROR_PREFIXES",
    "dns_name",
    "invalid_redirect_error",
    "invalid_url_error",
    "is_url_error",
    "join_or_none",
    "rejected_url_error",
    "requestable",
    "split_or_none",
]


def invalid_url_error(url: str) -> str:
    """``transport_error`` for a URL we were asked to fetch and cannot request (quoted)."""
    return f"{INVALID_URL_ERROR}: {url[:200]!r}"


def invalid_redirect_error(location: str) -> str:
    """``transport_error`` for a 3xx whose ``Location`` cannot be requested (quoted)."""
    return f"{INVALID_REDIRECT_ERROR}: {location[:200]!r}"


def rejected_url_error(url: str, exc: Exception) -> str:
    """``transport_error`` for a request the HTTP stack refused for a reason about the URL."""
    return (
        f"{REJECTED_URL_ERROR}: {type(exc).__name__}: {str(exc)[:200]} (requesting {url[:200]!r})"
    )


def is_url_error(transport_error: str | None) -> bool:
    """Is ``transport_error`` one of the three above (not a network fault, not a site answer)?"""
    return bool(transport_error) and (transport_error or "").startswith(URL_ERROR_PREFIXES)


def split_or_none(url: str) -> SplitResult | None:
    """``urlsplit(url)``, or ``None`` when urllib cannot parse it.

    ``SplitResult.port`` validates lazily (``urlsplit`` itself accepts ``http://h:abc/x``), and
    the fetcher reads it, so it is read here too: a string that passes can go through every
    ``urlsplit(...).hostname`` / ``.port`` / ``.path`` call of the audit. It does *not* mean the
    string can be requested (see :func:`requestable`), nor that it is a URL at all (``/a/b`` and
    ``mailto:x`` pass).
    """
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - validated lazily: ValueError for a port that is not a number
    except ValueError:
        return None
    return parts


def join_or_none(base: str, ref: str) -> str | None:
    """``urljoin(base, ref)``, or ``None`` when ``ref`` (or the joined URL) cannot be parsed."""
    try:
        joined = urljoin(base, ref)
    except ValueError:
        return None
    return joined if split_or_none(joined) is not None else None


def requestable(url: str) -> bool:
    """Can the HTTP stack send a request to ``url``?

    ``split_or_none`` plus what ``httpx`` insists on (``httpx.URL(url).host`` is where its IDNA
    decoding runs; ``idna.IDNAError`` is a ``ValueError``) plus what DNS insists on: every label of
    the host is 1-63 octets and the name at most 253, otherwise ``socket.getaddrinfo`` raises
    ``UnicodeError`` (``a..b``). A URL without a host (a relative path, ``mailto:x``) has no
    labels to check and passes; whether such a URL *should* be requested is not this function's
    question. An IP literal passes too: no label of one is empty or over 63 octets.
    """
    if split_or_none(url) is None:
        return False
    try:
        target = httpx.URL(url)
        target.host  # noqa: B018 - InvalidURL / IDNAError: the request could not be built
        host = target.raw_host.decode("ascii")
    except (ValueError, httpx.InvalidURL):
        return False
    if not host:
        return True
    name = host.rstrip(".")
    return len(name) <= MAX_DNS_NAME and all(
        0 < len(label) <= MAX_DNS_LABEL for label in name.split(".")
    )


def dns_name(url: str) -> str:
    """The A-label host ``httpx`` would connect to for ``url`` (punycode for an IDN host), or "".

    ``urlsplit(url).hostname`` is the Unicode form, which the stdlib's IDNA-2003 codec - what
    ``socket.getaddrinfo`` uses - refuses for hosts that are valid IDNA-2008 (an Arabic label that
    ends in a digit). DNS lookups made on behalf of a URL use this name instead, so the lookup asks
    about the same host the request did.
    """
    try:
        return httpx.URL(url).raw_host.decode("ascii")
    except (ValueError, httpx.InvalidURL):
        return ""
