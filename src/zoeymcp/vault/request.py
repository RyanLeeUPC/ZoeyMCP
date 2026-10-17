"""Request policy as pure functions: path normalization and matching, query and header policy,
and response scrubbing (design §4.1, §4.2).

Nothing here does I/O, so every rule can be tested directly and exhaustively.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote_to_bytes, urlencode

from ..common.policy.paths import SEGMENT_CHARS, PathPattern, parse_path_pattern
from ..common.policy.schema import QueryPolicy, RegexParam, Rule

MAX_PATH_BYTES = 4096
MAX_QUERY_BYTES = 8192
MAX_QUERY_FIELDS = 100
_PERCENT = re.compile(rb"%(?![0-9A-Fa-f]{2})")


class RequestRejected(ValueError):
    """A request ZoeyMCP refuses. ``reason`` is for logs, never for the response body."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# --- paths -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedPath:
    segments: tuple[str, ...]
    trailing_slash: bool = False

    @property
    def text(self) -> str:
        """The decoded path, e.g. ``/2.0/user/``."""
        body = "/".join(self.segments)
        if not self.segments:
            return "/"
        return "/" + body + ("/" if self.trailing_slash else "")

    def encoded(self) -> str:
        """The path as sent upstream, each segment percent-encoded again."""
        if not self.segments:
            return "/"
        body = "/".join(quote(s, safe="!$&'()*+,;=:@~-._") for s in self.segments)
        return "/" + body + ("/" if self.trailing_slash else "")

    def without_first(self) -> NormalizedPath:
        rest = self.segments[1:]
        return NormalizedPath(rest, self.trailing_slash if rest else False)


def normalize_path(raw: bytes) -> NormalizedPath:
    """Normalize a raw (still percent-encoded) request path, or raise :class:`RequestRejected`.

    The path is split on ``/`` *before* decoding, so an encoded slash can never become a segment
    boundary. Each segment is then decoded exactly once, and anything ambiguous is refused:
    encoded slashes or backslashes, ``%`` left after decoding (double encoding), ``.``/``..``,
    empty segments, non-ASCII, and characters outside the allowed set.
    """
    if len(raw) > MAX_PATH_BYTES:
        raise RequestRejected("path too long")
    if not raw.startswith(b"/"):
        raise RequestRejected("path must start with '/'")
    if any(b < 0x21 or b > 0x7E for b in raw):
        raise RequestRejected("path has raw non-printable or non-ASCII bytes")
    if _PERCENT.search(raw):
        raise RequestRejected("malformed percent-encoding")
    if raw == b"/":
        return NormalizedPath(())
    body = raw[1:]
    trailing = body.endswith(b"/")
    if trailing:
        body = body[:-1]
    segments: list[str] = []
    for part in body.split(b"/"):
        if not part:
            raise RequestRejected("empty path segment")
        decoded = unquote_to_bytes(part)
        try:
            text = decoded.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RequestRejected("non-ASCII path segment") from exc
        if "/" in text or "\\" in text:
            raise RequestRejected("slash or backslash inside a path segment")
        if "%" in text:
            raise RequestRejected("double percent-encoding")
        if text in (".", ".."):
            raise RequestRejected("dot segment in path")
        if not SEGMENT_CHARS.match(text):
            raise RequestRejected("path segment has characters that aren't allowed")
        segments.append(text)
    return NormalizedPath(tuple(segments), trailing)


def match_pattern(pattern: PathPattern, path: NormalizedPath) -> dict[str, str] | None:
    """Captures if ``pattern`` matches ``path``, else ``None``."""
    captures: dict[str, str] = {}
    segments = path.segments
    for index, segment in enumerate(pattern.segments):
        if segment.kind == "globstar":
            return captures
        if index >= len(segments):
            return None
        actual = segments[index]
        if segment.kind == "literal":
            if actual != segment.value:
                return None
        elif segment.kind == "capture":
            captures[segment.value] = actual
    if len(segments) != len(pattern.segments):
        return None
    if path.trailing_slash != pattern.trailing_slash:
        return None
    return captures


def _param_allows(constraint: list[str] | RegexParam, value: str) -> bool:
    if isinstance(constraint, RegexParam):
        return re.fullmatch(constraint.regex, value) is not None
    return value in constraint


def rule_matches(rule: Rule, method: str, path: NormalizedPath) -> bool:
    if method not in rule.methods:
        return False
    for source in rule.paths:
        captures = match_pattern(parse_path_pattern(source), path)
        if captures is None:
            continue
        if all(
            _param_allows(rule.params[name], value)
            for name, value in captures.items()
            if name in rule.params
        ):
            return True
    return False


def find_rule(rules: Sequence[Rule], method: str, path: NormalizedPath) -> int | None:
    """Index of the first rule allowing ``method`` on ``path``."""
    for index, rule in enumerate(rules):
        if rule_matches(rule, method, path):
            return index
    return None


# --- query -------------------------------------------------------------------------------------


def parse_query(raw: bytes) -> list[tuple[str, str]]:
    if len(raw) > MAX_QUERY_BYTES:
        raise RequestRejected("query string too long")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RequestRejected("query string has raw non-ASCII bytes") from exc
    if _PERCENT.search(raw):
        raise RequestRejected("malformed percent-encoding in query")
    try:
        return parse_qsl(
            text, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS, errors="strict"
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise RequestRejected(f"query string refused: {exc}") from exc


def apply_query_policy(
    params: Iterable[tuple[str, str]],
    policy: QueryPolicy,
    *,
    remove: Iterable[str] = (),
    add: Iterable[tuple[str, str]] = (),
) -> list[tuple[str, str]]:
    """Apply a route's query policy.

    ``remove`` names parameters the vault always takes out (the placeholder, the credential's
    parameter); ``add`` is appended last (the credential).
    """
    removed = set(remove) | set(policy.strip) | set(policy.force)
    result: list[tuple[str, str]] = []
    for name, value in params:
        if name in removed:
            continue
        if policy.allow is not None and name not in policy.allow:
            raise RequestRejected(f"query parameter {name!r} isn't allowed")
        result.append((name, value))
    result.extend(policy.force.items())
    result.extend(add)
    return result


def encode_query(params: Sequence[tuple[str, str]]) -> str:
    return urlencode(params, quote_via=quote, safe="-._~")


# --- headers -----------------------------------------------------------------------------------

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)
_DROP_REQUEST = HOP_BY_HOP | {
    "host",
    "authorization",
    "cookie",
    "content-length",
    "accept-encoding",
    "expect",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
}
_DROP_RESPONSE = HOP_BY_HOP | {
    "set-cookie",
    "set-cookie2",
    "content-length",
    "content-encoding",
    "strict-transport-security",
    "alt-svc",
}
INTERNAL_HEADER_PREFIX = "x-zoeymcp-"

Headers = list[tuple[str, str]]


def _connection_tokens(headers: Iterable[tuple[str, str]]) -> set[str]:
    tokens: set[str] = set()
    for name, value in headers:
        if name.lower() == "connection":
            tokens.update(t.strip().lower() for t in value.split(",") if t.strip())
    return tokens


def filter_request_headers(
    headers: Iterable[tuple[str, str]], *, drop: Iterable[str] = ()
) -> Headers:
    """Headers to forward upstream: no hop-by-hop, caller credentials, forwarding or internal
    headers, plus ``Accept-Encoding: identity`` so responses can be scrubbed."""
    headers = list(headers)
    dropped = _DROP_REQUEST | _connection_tokens(headers) | {d.lower() for d in drop}
    kept = [
        (name, value)
        for name, value in headers
        if name.lower() not in dropped and not name.lower().startswith(INTERNAL_HEADER_PREFIX)
    ]
    kept.append(("accept-encoding", "identity"))
    return kept


def filter_response_headers(headers: Iterable[tuple[str, str]]) -> Headers:
    """Headers to return to the caller: no hop-by-hop, no cookies (an upstream session cookie is
    a credential the caller must never hold), no encodings the vault already decoded."""
    headers = list(headers)
    dropped = _DROP_RESPONSE | _connection_tokens(headers)
    return [
        (name, value)
        for name, value in headers
        if name.lower() not in dropped and not name.lower().startswith(INTERNAL_HEADER_PREFIX)
    ]


# --- scrubbing ---------------------------------------------------------------------------------

REDACTED = b"[REDACTED]"
_MIN_VARIANT = 4


def secret_variants(secret: str, *, basic_user: str | None = None) -> list[bytes]:
    """The forms an echoed secret may take in a response, longest first.

    Secrets shorter than four characters get no variants: matching them would redact ordinary
    text, and no real credential is that short.
    """
    if len(secret) < _MIN_VARIANT:
        return []
    forms = {
        secret,
        quote(secret, safe=""),
        quote(secret, safe="").lower(),
        json.dumps(secret)[1:-1],
        json.dumps(secret, ensure_ascii=False)[1:-1],
        base64.b64encode(secret.encode()).decode(),
        base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
    }
    if basic_user is not None:
        forms.add(base64.b64encode(f"{basic_user}:{secret}".encode()).decode())
    encoded = {form.encode("utf-8") for form in forms if len(form) >= _MIN_VARIANT}
    return sorted(encoded, key=len, reverse=True)


def scrub(data: bytes, variants: Sequence[bytes]) -> tuple[bytes, int]:
    """Replace every variant in ``data`` with ``[REDACTED]``. Returns the data and the count."""
    count = 0
    for variant in variants:
        hits = data.count(variant)
        if hits:
            count += hits
            data = data.replace(variant, REDACTED)
    return data, count


def scrub_headers(
    headers: Iterable[tuple[str, str]], variants: Sequence[bytes]
) -> tuple[Headers, int]:
    total = 0
    result: Headers = []
    for name, value in headers:
        cleaned, count = scrub(value.encode("latin-1", "replace"), variants)
        total += count
        result.append((name, cleaned.decode("latin-1")))
    return result, total
