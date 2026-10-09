"""Parse URLs that come from the audited site without letting a malformed one abort the audit.

``urllib.parse`` raises ``ValueError`` for URLs a browser would also refuse: an unbalanced or
non-address bracket in the host (``http://[``, ``https://[your-domain]/docs`` - a placeholder
that is common in API docs), a port that is not a number (``http://h:abc/``, which ``urlsplit``
accepts and ``.port`` rejects), a host whose NFKC form contains ``/`` or ``@`` (``http://℀/``).
``httpx`` - the parser every request goes through - refuses more: an IPv4 address with a field
over 255 (``http://256.256.256.256/``), a control character anywhere in the URL, a host that
is not valid IDNA (``http://xn--/``, a zero-width space), more than 65536 characters.
Every one of those strings is data the audited site hands us - a redirect ``Location``, an
``href``, an ``llms.txt`` link, a sitemap ``<loc>`` - so none of them may raise past the place
that read it. These two functions are that place: they return ``None`` instead of raising, and
the caller decides what the audit says about the URL (see ``UNPARSEABLE_*``).
"""

from __future__ import annotations

from urllib.parse import SplitResult, urljoin, urlsplit

import httpx

#: ``Exclusion.rule_id`` / ``EligibilityExclusion.rule_id`` of a link whose URL cannot be parsed.
UNPARSEABLE_RULE_ID = "unparseable_url"
#: What the report says about such a link (``Exclusion.rule_desc``).
UNPARSEABLE_REASON = (
    "URL 无法解析（urllib 拒绝它，例如 ``http://[`` 或 ``https://[your-domain]/``），"
    "请求发不出去，本工具没有检查它；这条链接本身就是被体检站点上的一处缺陷"
)

#: ``HttpResponse.transport_error`` prefixes of a request that was never made because the URL
#: (or the ``Location`` a 3xx pointed to) cannot be parsed. ``classify_response`` files them under
#: ``UNKNOWN / network_error``; ``dead_links.classify_link`` matches the redirect one by its
#: prefix (an unrecognised transport error would otherwise fall through to "not dead, so alive").
INVALID_URL_ERROR = "invalid URL (cannot be parsed)"
INVALID_REDIRECT_ERROR = "invalid redirect Location (cannot be parsed)"
#: The same, for what ``split_or_none`` let through but the HTTP stack refused while making the
#: request (an empty DNS label, ``a..b``) or reading the response (a ``Location`` httpx cannot
#: decode): deterministic, so the fetcher neither retries it nor asks DNS for a second opinion.
REJECTED_URL_ERROR = "URL rejected by the HTTP stack"

__all__ = [
    "INVALID_REDIRECT_ERROR",
    "INVALID_URL_ERROR",
    "REJECTED_URL_ERROR",
    "UNPARSEABLE_REASON",
    "UNPARSEABLE_RULE_ID",
    "invalid_redirect_error",
    "invalid_url_error",
    "join_or_none",
    "rejected_url_error",
    "split_or_none",
]


def invalid_url_error(url: str) -> str:
    """``transport_error`` for a URL we were asked to fetch and cannot parse (quoted)."""
    return f"{INVALID_URL_ERROR}: {url[:200]!r}"


def rejected_url_error(url: str, exc: Exception) -> str:
    """``transport_error`` for a request the HTTP stack refused for a reason about the URL."""
    return (
        f"{REJECTED_URL_ERROR}: {type(exc).__name__}: {str(exc)[:200]} (requesting {url[:200]!r})"
    )


def invalid_redirect_error(location: str) -> str:
    """``transport_error`` for a 3xx whose ``Location`` cannot be parsed (quoted)."""
    return f"{INVALID_REDIRECT_ERROR}: {location[:200]!r}"


def split_or_none(url: str) -> SplitResult | None:
    """``urlsplit(url)``, or ``None`` when the URL cannot be parsed - or cannot be requested.

    ``SplitResult.port`` validates lazily (``urlsplit`` itself accepts ``http://h:abc/x``), and
    the fetcher reads it, so it is read here too: a URL that passes this check can go through
    every ``urlsplit(...).hostname`` / ``.port`` / ``.path`` call of the audit. ``httpx.URL``
    is what the request is built from, and it refuses URLs ``urlsplit`` accepts, so it is asked
    as well (``.host`` is where its IDNA decoding runs; ``idna.IDNAError`` is a ``ValueError``).
    """
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - validated lazily: ValueError for a port that is not a number
        httpx.URL(url).host  # noqa: B018 - InvalidURL / IDNAError: the request could not be built
    except (ValueError, httpx.InvalidURL):
        return None
    return parts


def join_or_none(base: str, ref: str) -> str | None:
    """``urljoin(base, ref)``, or ``None`` when ``ref`` (or the joined URL) cannot be parsed."""
    try:
        joined = urljoin(base, ref)
    except ValueError:
        return None
    return joined if split_or_none(joined) is not None else None
