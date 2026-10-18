"""Request policy as pure functions: path normalization, query and header policy, and response
scrubbing (design §4.1, §4.2), streams included (M3 design J.2). Rule matching is in
``common/policy/match.py``.

Nothing here does I/O, so every rule can be tested directly and exhaustively.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable, Sequence
from urllib.parse import parse_qsl, quote, quote_plus, unquote_to_bytes, urlencode

from ..common.policy.match import NormalizedPath, rule_matches
from ..common.policy.paths import SEGMENT_CHARS
from ..common.policy.schema import QueryPolicy, Rule

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
        base64.b64encode(secret.encode()).decode(),
        base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
    }
    for escaped in (json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1]):
        forms.add(escaped)
        # PHP's json_encode, among others, writes "/" as "\/".
        forms.add(escaped.replace("/", "\\/"))
    if basic_user is not None:
        forms.add(base64.b64encode(f"{basic_user}:{secret}".encode()).decode())
    encoded = {form.encode("utf-8") for form in forms if len(form) >= _MIN_VARIANT}
    return sorted(encoded, key=len, reverse=True)


def oauth_basic_credentials(client_id: str, client_secret: str) -> str:
    """The Basic credentials of an OAuth client (RFC 6749 section 2.3.1).

    Both parts are form-urlencoded before they're joined, so a ``:`` in the client ID can't move
    the split. This is what the vault sends, and what :func:`oauth_client_variants` scrubs.
    """
    pair = f"{quote_plus(client_id)}:{quote_plus(client_secret)}"
    return base64.b64encode(pair.encode("ascii")).decode("ascii")


def oauth_client_variants(client_id: str, client_secret: str) -> list[bytes]:
    """The forms an echoed OAuth client secret may take, longest first.

    These are :func:`secret_variants`, plus the secret form-urlencoded as in a token request body,
    plus the Basic credentials as sent.
    """
    if len(client_secret) < _MIN_VARIANT:
        return []
    forms = set(secret_variants(client_secret))
    forms.add(quote_plus(client_secret).encode("ascii"))
    forms.add(oauth_basic_credentials(client_id, client_secret).encode("ascii"))
    return sorted(forms, key=len, reverse=True)


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


# --- streams (M3 design J.2) -------------------------------------------------------------------

# The longest SSE event or NDJSON line a stream may carry, line breaks included. It's above the
# largest upstream message the gateway takes (16 MiB), so no stream an MCP client can read ends.
MAX_STREAM_EVENT_BYTES = 17 * 1024 * 1024
_CR = 0x0D
_LF = 0x0A
_COLON = 0x3A
_LINE_BREAK = re.compile(rb"[\r\n]")
_LF_BREAK = re.compile(rb"\n")


class StreamEventTooLarge(ValueError):
    """An SSE event or NDJSON line over the limit. The stream ends there, without it."""

    def __init__(self, size: int) -> None:
        self.size = size
        super().__init__(f"a stream event of at least {size} bytes is over the limit")


class SSEScrubber:
    r"""Scrubs a ``text/event-stream`` one event at a time.

    Bytes are held until their event ends with a blank line, then scrubbed and released, so a
    secret split across chunks is still caught. A line ends with ``\n``, ``\r\n`` or ``\r``. A
    comment line (``:``) at the start of an event is released when it ends, so keep-alives pass at
    once. Nothing is held beyond one event. An event longer than ``max_event_bytes`` raises
    :class:`StreamEventTooLarge`.

    No secret variant contains a line break, so scrubbing event by event is the same as scrubbing
    the whole stream.
    """

    def __init__(
        self, variants: Sequence[bytes], *, max_event_bytes: int = MAX_STREAM_EVENT_BYTES
    ) -> None:
        self._variants = variants
        self._max = max_event_bytes
        self._held = bytearray()
        # Where the current line starts, and where the next search for a line break starts. Each
        # byte is looked at once, so a long line costs no more than its length.
        self._line_start = 0
        self._scanned = 0
        self.scrubbed = 0

    def feed(self, chunk: bytes) -> bytes:
        """Take the next chunk and return what may be sent now."""
        out = bytearray()
        held = self._held
        held += chunk
        while found := _LINE_BREAK.search(held, max(self._line_start, self._scanned)):
            index = found.start()
            end = index + 1
            # (A \r first in the buffer ended a blank line and went out, so index 0 is no \r\n.)
            if held[index] == _LF and index and held[index - 1] == _CR:
                # The \n of a \r\n split across chunks: the \r ended the line already. (When
                # that \r ended an event, the \n is first in an empty buffer instead, and goes
                # out alone as a blank line. The bytes the reader gets are the same.)
                self._line_start = end
                continue
            if held[index] == _CR and end < len(held) and held[end] == _LF:
                end += 1
            blank = index == self._line_start
            self._line_start = end
            # A comment line first in the buffer: anything before it has been released.
            if blank or held[0] == _COLON:
                out += self._release(end)
        # What's left from the line start on has no line break.
        self._scanned = len(held)
        if len(held) > self._max:
            raise StreamEventTooLarge(len(held))
        return bytes(out)

    def finish(self) -> bytes:
        """Return what's left when the stream ends (an event that never ended), scrubbed."""
        return self._release(len(self._held))

    def _release(self, end: int) -> bytes:
        if end > self._max:
            raise StreamEventTooLarge(end)
        event, count = scrub(bytes(self._held[:end]), self._variants)
        del self._held[:end]
        self._line_start = self._scanned = 0
        self.scrubbed += count
        return event


class NDJSONScrubber:
    r"""Scrubs an ``application/x-ndjson`` stream one line at a time, as :class:`SSEScrubber` does
    events. A line ends with ``\n``. A line longer than ``max_line_bytes`` raises
    :class:`StreamEventTooLarge`.
    """

    def __init__(
        self, variants: Sequence[bytes], *, max_line_bytes: int = MAX_STREAM_EVENT_BYTES
    ) -> None:
        self._variants = variants
        self._max = max_line_bytes
        self._held = bytearray()
        self._scanned = 0
        self.scrubbed = 0

    def feed(self, chunk: bytes) -> bytes:
        """Take the next chunk and return what may be sent now."""
        held = self._held
        held += chunk
        start = 0
        while found := _LF_BREAK.search(held, self._scanned):
            end = found.end()
            if end - start > self._max:
                raise StreamEventTooLarge(end - start)
            start = self._scanned = end
        if len(held) - start > self._max:
            raise StreamEventTooLarge(len(held) - start)
        out = self._release(start)
        self._scanned = len(held)
        return out

    def finish(self) -> bytes:
        """Return what's left when the stream ends (a line with no line break), scrubbed."""
        return self._release(len(self._held))

    def _release(self, end: int) -> bytes:
        lines, count = scrub(bytes(self._held[:end]), self._variants)
        del self._held[:end]
        self.scrubbed += count
        return lines
