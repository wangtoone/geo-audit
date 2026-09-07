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

# Blocks removed wholesale before text extraction.
_BLOCK_RE = re.compile(
    r"<(script|style|noscript|svg|template|iframe)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_SELF_CLOSING_NOISE_RE = re.compile(r"<(script|link|meta)\b[^>]*/?>", re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_DOCTYPE_RE = re.compile(r"<!doctype[^>]*>", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

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
    text = _COMMENT_RE.sub(" ", text)
    text = _BLOCK_RE.sub(" ", text)
    text = _SELF_CLOSING_NOISE_RE.sub(" ", text)
    text = _DOCTYPE_RE.sub(" ", text)
    text = _TAG_RE.sub(" ", text)
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
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

#: A skeleton with fewer tags than this is too thin to identify anything.
MIN_STRUCT_TAGS = 30


def structural_fingerprint(body: str) -> tuple[str, int]:
    """Return (sha256 of the markup skeleton, number of tags).

    Volatile attribute values (nonces, build hashes, cache-busting query
    strings) never enter the skeleton, so the digest is stable across requests
    while remaining specific to one site's shell.
    """
    stripped = _COMMENT_RE.sub(" ", body)
    stripped = _BLOCK_RE.sub(" ", stripped)
    tags = [f"{slash}{name.lower()}" for slash, name in _TAG_NAME_RE.findall(stripped)]
    tokens: list[str] = []
    for raw in _ID_CLASS_RE.findall(stripped[:200000]):
        for tok in raw.split():
            cleaned = tok
            for pattern in _VOLATILE_PATTERNS:
                cleaned = pattern.sub("", cleaned)
            if cleaned and not cleaned.isdigit():
                tokens.append(cleaned.lower())
    title = _TITLE_RE.search(body)
    title_text = _WS_RE.sub(" ", (title.group(1) if title else "")).strip().lower()
    skeleton = "|".join(tags[:4000]) + "#" + "|".join(sorted(set(tokens))[:400]) + "#" + title_text
    return hashlib.sha256(skeleton.encode("utf-8")).hexdigest(), len(tags)
