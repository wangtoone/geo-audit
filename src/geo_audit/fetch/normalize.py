"""Body normalization + fingerprinting.

Why normalization is not optional: the soft-404 control comparison compares a
target body to the body of a path that cannot exist.  SPA shells inject a CSP
nonce, a build hash, a route name and a timestamp on every request, so raw
sha256 differs even when the two pages are the same shell.  Normalizing first
is what lets rule (i) -- "identical to control" -- fire at all.

Why byte length is absent from every decision path: FEATURE-PRIORITY.md §5
re-measured 12 byte counts and 3 did not reproduce.  Byte length is kept only
as report-display metadata (HttpResponse.byte_len).
"""

from __future__ import annotations

import difflib
import hashlib
import re
import unicodedata

# --------------------------------------------------------------------------- #
# Markup stripping -- linear time, on purpose
# --------------------------------------------------------------------------- #
# These used to be five ``re.sub`` calls: ``<!--.*?-->``,
# ``<(script|style|...)\b[^>]*>.*?</\1\s*>``, ``<(script|link|meta)\b[^>]*/?>``,
# ``<!doctype[^>]*>`` and ``<[^>]+>``.  Every one of them rescans to the end of the input from each
# opening token that is never closed, so a page with N unclosed ``<script>`` / ``<!--`` / ``<``
# took O(N^2): 100 KB took 2-6 s, 1 MB of ``<`` took minutes.  And ``Fetcher.fetch`` runs this on
# EVERY response (``finalize_response`` -> ``normalize_body``), so a hostile -- or merely broken
# -- page could stall an audit.
#
# The helpers below produce byte-identical output (tests keep the regex versions as the oracle and
# compare them on every frozen response and on thousands of fuzzed documents) using one rule:
# if an opening token cannot be completed -- there is no ``>`` / ``-->`` / closing tag after it --
# no LATER opening token of the same kind can be completed either (their search starts further
# right), so the scan can stop looking for that kind.  ``str.find`` does the actual scanning.

# The opening token of a block (``<script`` etc., ``\b`` after the name); the spelling is captured.
_BLOCK_OPEN_RE = re.compile(r"<(?P<n>script|style|noscript|svg|template|iframe)\b", re.IGNORECASE)
# The original per-block pattern, kept verbatim and applied ANCHORED at one opening token.  Not
# rebuilt from the name: ``\1`` compares the closing tag with the captured text through the regex
# engine's *lower-casing* (``K`` ~ ``k``, but ``\u017f`` is NOT ``s``), which is not the same
# equivalence ``re.IGNORECASE`` uses for a literal (``\u017f`` ~ ``s``).  Re-implementing either
# changes the output for exotic spellings such as ``<\u017fcript>``; reusing the regex cannot.
_BLOCK_AT_RE = re.compile(
    r"<(script|style|noscript|svg|template|iframe)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_NOISE_OPEN_RE = re.compile(r"<(?:script|link|meta)\b", re.IGNORECASE)
_DOCTYPE_OPEN_RE = re.compile(r"<!doctype", re.IGNORECASE)
_TITLE_OPEN_RE = re.compile(r"<title", re.IGNORECASE)
_TITLE_CLOSE_RE = re.compile(r"</title>", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")


def _strip_comments(text: str) -> str:
    """``re.sub(r"<!--.*?-->", " ", text, flags=re.S)``"""
    out: list[str] = []
    keep_from = 0
    while True:
        start = text.find("<!--", keep_from)
        if start < 0:
            break
        end = text.find("-->", start + 4)
        if end < 0:
            break  # unclosed: no later ``<!--`` can be closed either
        out.append(text[keep_from:start])
        out.append(" ")
        keep_from = end + 3
    out.append(text[keep_from:])
    return "".join(out)


def _strip_blocks(text: str) -> str:
    r"""``re.sub(r"<(script|style|noscript|svg|template|iframe)\b[^>]*>.*?</\1\s*>", " ", ...)``"""
    out: list[str] = []
    keep_from = 0  # start of the text not yet copied to ``out``
    scan = 0  # where to look for the next opening token
    # Spellings (case-folded) whose closing tag is known not to exist after some point.  A later
    # opening with the same spelling needs the same closing tag from further right: it cannot
    # succeed either.  The key is the *spelling*, not the tag name: ``<\u017fcript>`` and
    # ``<script>`` are different back-references, and a missing ``</\u017fcript>`` says nothing
    # about ``</script>``.
    unclosed: set[str] = set()
    while True:
        m = _BLOCK_OPEN_RE.search(text, scan)
        if m is None:
            break
        spelling = m.group("n").lower()
        if spelling in unclosed:
            scan = m.start() + 1
            continue
        if text.find(">", m.end()) < 0:
            break  # no ``>`` anywhere after this: no later opening token can end either
        whole = _BLOCK_AT_RE.match(text, m.start())
        if whole is None:
            unclosed.add(spelling)
            scan = m.start() + 1
            continue
        out.append(text[keep_from : m.start()])
        out.append(" ")
        keep_from = scan = whole.end()
    out.append(text[keep_from:])
    return "".join(out)


def _strip_open_tags(text: str, opening: re.Pattern[str]) -> str:
    """``re.sub(<opening>[^>]*>, " ", text)``: from the opening token up to the first ``>``."""
    out: list[str] = []
    keep_from = 0
    scan = 0
    while True:
        m = opening.search(text, scan)
        if m is None:
            break
        gt = text.find(">", m.end())
        if gt < 0:
            break
        out.append(text[keep_from : m.start()])
        out.append(" ")
        keep_from = scan = gt + 1
    out.append(text[keep_from:])
    return "".join(out)


def _strip_tags(text: str) -> str:
    """``re.sub(r"<[^>]+>", " ", text)``"""
    out: list[str] = []
    keep_from = 0
    scan = 0
    while True:
        start = text.find("<", scan)
        if start < 0:
            break
        gt = text.find(">", start + 1)
        if gt < 0:
            break
        if gt == start + 1:  # ``<>``: ``[^>]+`` needs at least one character
            scan = start + 1
            continue
        out.append(text[keep_from:start])
        out.append(" ")
        keep_from = scan = gt + 1
    out.append(text[keep_from:])
    return "".join(out)


def _first_title(body: str) -> str | None:
    """``re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)`` -> group 1, or ``None``."""
    m = _TITLE_OPEN_RE.search(body)
    if m is None:
        return None
    gt = body.find(">", m.end())
    if gt < 0:
        return None
    close = _TITLE_CLOSE_RE.search(body, gt + 1)
    if close is None:
        return None  # a later ``<title`` starts further right: it cannot be closed either
    return body[gt + 1 : close.start()]


# Per-request noise that changes on every hit.  Stripped so control comparison
# is stable.  Ordering matters: longest/most specific patterns first.
_VOLATILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # ISO-8601 timestamps
    re.compile(r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?"),
    # uuid v1-v5
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    # long hex runs: build hashes, nonces, etags, sri digests
    re.compile(r"\b[0-9a-f]{16,}\b"),
    # base64-ish nonces
    re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b"),
    # epoch seconds / millis
    re.compile(r"\b1[6-9]\d{8,11}\b"),
    # cache-busting query strings
    re.compile(r"[?&](?:v|ver|version|t|ts|hash|build|_)=[^\s\"'&]+"),
)

_ENTITIES = {
    "&nbsp;": " ",
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&#39;": "'",
    "&apos;": "'",
}

#: Bodies shorter than this (after normalization) are never compared by
#: similarity ratio -- difflib gives spuriously high scores on tiny strings.
MIN_SIMILARITY_LEN = 200

#: Threshold for "near identical to control".  0.90 chosen because the two
#: observed SPA-shell pairs (minimax 384052 B, moonshot 82460 B) are byte
#: identical (ratio 1.0) while the closest *legitimate* pair in the fixture
#: set -- a real llms.txt vs its host's 404 page -- scores below 0.30.
SIMILARITY_THRESHOLD = 0.90


def strip_bom(text: str) -> str:
    return text.lstrip("﻿￾")


def visible_text(body: str) -> str:
    """Extract reader-visible text from HTML (or pass plain text through).

    Keeps <title> content -- it is the single most diagnostic string in the
    fixture set (saleor's dead CTA pages have <title>404 - Page not found</title>,
    ed.link's shell has <title>Edlink Dashboard</title>).
    """
    text = strip_bom(body)
    text = _strip_comments(text)
    text = _strip_blocks(text)
    text = _strip_open_tags(text, _NOISE_OPEN_RE)
    text = _strip_open_tags(text, _DOCTYPE_OPEN_RE)
    text = _strip_tags(text)
    for entity, repl in _ENTITIES.items():
        text = text.replace(entity, repl)
    text = unicodedata.normalize("NFKC", text)
    return _WS_RE.sub(" ", text).strip()


def normalize_body(body: str) -> str:
    """Canonical form used for fingerprinting and similarity.

    Deterministic, idempotent, and free of per-request noise.
    """
    text = visible_text(body).lower()
    for pattern in _VOLATILE_PATTERNS:
        text = pattern.sub(" ", text)
    return _WS_RE.sub(" ", text).strip()


def norm_sha256(body: str) -> str:
    return hashlib.sha256(normalize_body(body).encode("utf-8")).hexdigest()


def raw_sha256(body: bytes) -> str:
    """Byte-exact digest.

    Used only by the llms-full check, where a byte-identical copy IS the
    finding: deepgram e7475c344df3d6dc1bf7749c7e470674 (73878 B),
    elevenlabs b8b7351708898cbb7ea152cf20e55ff5 (206764 B),
    hume fd5cc659d97450a2de4509c102d98d10 (16412 B) -- all three are
    llms-full.txt byte-identical to llms.txt, all three on Fern.
    """
    return hashlib.sha256(body).hexdigest()


def md5_hex(body: bytes) -> str:
    """MD5 of raw bytes, kept because the empirical record is in MD5 and the
    report quotes those digests verbatim as evidence."""
    return hashlib.md5(body, usedforsecurity=False).hexdigest()


#: Prefix length kept for similarity comparison.  Bounded so a 4.3 MB
#: llms-full (canvasmedical docs) does not turn difflib into an O(n^2) stall.
NORM_BODY_CAP = 20000


def similarity_norm(a_norm: str, b_norm: str) -> float:
    """Similarity of two ALREADY-normalized strings, in [0, 1].

    Returns 0.0 when either side is shorter than MIN_SIMILARITY_LEN, so a
    caller can never accidentally treat a tiny body as a match -- difflib
    gives spuriously high ratios on short strings, and a 44-byte
    "# Page Not Found" body must be judged by copy rules, not by ratio.
    """
    if len(a_norm) < MIN_SIMILARITY_LEN or len(b_norm) < MIN_SIMILARITY_LEN:
        return 0.0
    return difflib.SequenceMatcher(
        None, a_norm[:NORM_BODY_CAP], b_norm[:NORM_BODY_CAP], autojunk=False
    ).ratio()


def similarity(a: str, b: str) -> float:
    """Similarity of two raw bodies (normalizes both first)."""
    return similarity_norm(normalize_body(a), normalize_body(b))


# --------------------------------------------------------------------------- #
# Structural fingerprint
# --------------------------------------------------------------------------- #
# Needed because an SPA shell has almost no visible text: strip the markup from
# www.minimax.io's 384 KB shell and you are left with the <title> and nothing
# else.  normalize_body() therefore collapses *every* empty shell to a nearly
# empty string, and comparing those by content digest would make two entirely
# different empty shells look identical -- a false positive waiting to happen.
#
# The structural fingerprint compares the markup skeleton instead: the ordered
# tag sequence plus id/class tokens plus the title.  Two hits on the same SPA
# shell agree; two different sites' shells do not.

_TAG_NAME_RE = re.compile(r"<\s*(/?)([a-zA-Z][a-zA-Z0-9-]*)")
_ID_CLASS_RE = re.compile(r"\b(?:id|class)\s*=\s*[\"\']([^\"\']{0,120})[\"\']", re.I)

#: A skeleton with fewer tags than this is too thin to identify anything.
MIN_STRUCT_TAGS = 30


def structural_fingerprint(body: str) -> tuple[str, int]:
    """Return (sha256 of the markup skeleton, number of tags).

    Volatile attribute values (nonces, build hashes, cache-busting query
    strings) never enter the skeleton, so the digest is stable across requests
    while remaining specific to one site's shell.
    """
    stripped = _strip_comments(body)
    stripped = _strip_blocks(stripped)
    tags = [f"{slash}{name.lower()}" for slash, name in _TAG_NAME_RE.findall(stripped)]
    tokens: list[str] = []
    for raw in _ID_CLASS_RE.findall(stripped[:200000]):
        for tok in raw.split():
            cleaned = tok
            for pattern in _VOLATILE_PATTERNS:
                cleaned = pattern.sub("", cleaned)
            if cleaned and not cleaned.isdigit():
                tokens.append(cleaned.lower())
    title = _first_title(body)
    title_text = _WS_RE.sub(" ", title or "").strip().lower()
    skeleton = "|".join(tags[:4000]) + "#" + "|".join(sorted(set(tokens))[:400]) + "#" + title_text
    return hashlib.sha256(skeleton.encode("utf-8")).hexdigest(), len(tags)
