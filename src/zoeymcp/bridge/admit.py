"""Admission to the bridge's one endpoint (M7 design C.4's table, C.5, M.3; SPEC-4, SPEC-5, X13,
X17). Pure and mutation-tested; :mod:`.server` reads the request around these decisions.

:func:`head` runs before any body byte is read, in the table's order: the path (404), the
method (405), no ``Origin`` (403: the vault never sends one), the token (403, the same empty
body for every reason), and for a POST one ``Content-Type: application/json`` and one
``Content-Length`` of at most ``--max-message-bytes`` (415, 411, 413). Then the era's rules
that need no body: a **legacy** bridge answers a ``MCP-Protocol-Version`` it doesn't serve (a
modern probe) with 400, as a legacy server must, which the SDK's ``auto`` mode takes as the
signal to fall back (C.5), and an unknown or ended ``Mcp-Session-Id`` with 404; a **modern**
one answers GET and DELETE with 405 and ignores ``Mcp-Session-Id``.

:func:`body` takes the body: one JSON-RPC request or notification (400 ``-32600``). A legacy
bridge starts a session only for an ``initialize`` sent without one, and answers any other
message without one with 400. A modern bridge refuses ``initialize`` (400 ``-32022`` whose
``data.supported`` names the versions it serves) and checks a request's routing headers against
its body (400 ``-32020``; ``Mcp-Name`` in the Base64 sentinel form decoded first; any
``Mcp-Param-*`` header is passed on unchecked, SPEC-5). Every notification is answered 202 with
an empty body in both eras (SPEC-4); only a legacy ``notifications/initialized`` reaches the
child as it is, and a legacy ``notifications/cancelled`` through the relay.

``Host`` is never read: over a standard-tier bridge's socket the vault sends ``bridge.invalid``
for every bridge (``vault/netclient.py``'s ``BRIDGE_BASE``), in the hardened tier it names the
bridge's alias, and a remote bridge sits behind its own front. The hop's authentication in every
placement is the route's header credential, ``Authorization: Bearer <token>``, whose SHA-256 is
compared in constant time with ``ZOEYMCP_BRIDGE_TOKEN_SHA256`` (:class:`BridgeTokenHash`).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ..common.logs import refuse_type
from .framing import LEGACY_VERSIONS, MESSAGE_MAX, MODERN_VERSIONS, Era, Message, parse

PATH: Final = "/mcp"
METHODS: Final = ("POST", "GET", "DELETE")
# JSON-RPC error codes: the specification's, and MCP 2026-07-28's HeaderMismatch and
# UnsupportedProtocolVersion.
INVALID_REQUEST: Final = -32600
HEADER_MISMATCH: Final = -32020
UNSUPPORTED_PROTOCOL_VERSION: Final = -32022
PROTOCOL_VERSION_META: Final = "io.modelcontextprotocol/protocolVersion"
# The routing headers a modern request carries, by their lower-case names.
VERSION_HEADER: Final = "mcp-protocol-version"
METHOD_HEADER: Final = "mcp-method"
NAME_HEADER: Final = "mcp-name"
ROUTING_HEADERS: Final = (VERSION_HEADER, METHOD_HEADER, NAME_HEADER)
SESSION_HEADER: Final = "mcp-session-id"
# The methods whose Mcp-Name mirrors a body parameter, and which one.
NAME_BEARING: Final[Mapping[str, str]] = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}
INITIALIZED: Final = "notifications/initialized"
CANCELLED: Final = "notifications/cancelled"

_HASH = re.compile(r"sha256:([0-9a-f]{64})")
_SENTINEL = re.compile(r"=\?base64\?(.*)\?=")
_LENGTH = re.compile(r"[0-9]{1,20}")
_JSON_TYPES: Final = ("application/json", "application/json;charset=utf-8")

# What an admitted message does: start a legacy session's child with it, relay it as a request,
# write it to the child as it is, resolve it as a cancel, or only accept it.
Action = Literal["start", "relay", "notify", "cancel", "accept"]


class BridgeTokenHash:
    """``ZOEYMCP_BRIDGE_TOKEN_SHA256``, as ``zoeymcp secret set --generate`` prints it: the only
    form of the token the bridge holds (X14). Its ``repr`` hides it, and logging it raises (M7
    design M.5)."""

    __slots__ = ("_digest",)

    def __init__(self, value: str) -> None:
        found = _HASH.fullmatch(value)
        if found is None:
            raise ValueError(
                "ZOEYMCP_BRIDGE_TOKEN_SHA256 isn't sha256: and 64 lower-case hex digits"
            )
        self._digest = bytes.fromhex(found.group(1))

    def admits(self, values: Sequence[str]) -> bool:
        """Exactly one ``Authorization`` value, ``Bearer <token>``, whose token hashes to this."""
        if len(values) != 1:
            return False
        scheme, _, token = values[0].partition(" ")
        if scheme.lower() != "bearer" or not token:
            return False
        digest = hashlib.sha256(token.encode("latin-1")).digest()
        return hmac.compare_digest(digest, self._digest)

    def __repr__(self) -> str:
        return "BridgeTokenHash(***)"


refuse_type(BridgeTokenHash)


@dataclass(frozen=True)
class Refusal:
    """An answer the bridge makes itself (M.3). ``reason`` is for ``bridge_refused``; the client
    sees only the status and, for a 400 or a 404 on a session, a JSON-RPC error."""

    status: int
    reason: str
    code: int | None = None
    message: str = ""
    data: Any = None
    rpc_id: Any = None
    allow: str = ""

    def body(self) -> bytes:
        if self.code is None:
            return b""
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        answer = {"jsonrpc": "2.0", "id": self.rpc_id, "error": error}
        return json.dumps(answer, separators=(",", ":")).encode("utf-8")

    def headers(self) -> list[tuple[str, str]]:
        found = []
        if self.code is not None:
            found.append(("content-type", "application/json"))
        if self.allow:
            found.append(("allow", self.allow))
        return found


NOT_FOUND: Final = Refusal(404, "path")
METHOD_REFUSED: Final = Refusal(405, "method", allow="GET, POST, DELETE")
ERA_METHOD: Final = Refusal(405, "era_method", allow="POST")
ORIGIN: Final = Refusal(403, "origin")
TOKEN: Final = Refusal(403, "token")
CONTENT_TYPE: Final = Refusal(415, "content_type")
LENGTH: Final = Refusal(411, "length")
TOO_LARGE: Final = Refusal(413, "too_large")
VERSION: Final = Refusal(
    400, "version", INVALID_REQUEST, "Bad Request: unsupported protocol version"
)
SESSION_REPEATED: Final = Refusal(
    400, "session_repeated", INVALID_REQUEST, "Bad Request: Mcp-Session-Id appears more than once"
)
SESSION_UNKNOWN: Final = Refusal(
    404, "session_unknown", INVALID_REQUEST, "Not Found: unknown or ended session"
)
# The relay's and the session table's own answers (C.4, C.5, M.3; N: not ready until the probe
# passed).
BUSY: Final = Refusal(503, "bridge_busy")
SESSIONS_FULL: Final = Refusal(503, "sessions_full")
CHILD_EXITED: Final = Refusal(502, "child_exited")
NOT_READY: Final = Refusal(503, "not_ready")


def session_missing(rpc_id: Any = None) -> Refusal:
    return Refusal(
        400, "session_missing", INVALID_REQUEST, "Bad Request: missing session ID", rpc_id=rpc_id
    )


@dataclass(frozen=True)
class Head[S]:
    """A request :func:`head` let through: its method, the legacy session it names (None when
    it names none), and a modern request's routing headers as sent, by lower-case name."""

    method: str
    session: S | None = None
    routing: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class Admitted:
    """A body :func:`body` let through, and what to do with it."""

    message: Message
    action: Action

    @property
    def accepted(self) -> bool:
        """Answered 202 with an empty body: a notification, in either era."""
        return self.action in ("notify", "cancel", "accept")


def _values(headers: Sequence[tuple[bytes, bytes]], name: str) -> tuple[str, ...]:
    key = name.encode("ascii")
    return tuple(value.decode("latin-1") for header, value in headers if header.lower() == key)


def _json_type(value: str) -> bool:
    return value.lower().replace(" ", "").replace('"', "") in _JSON_TYPES


def _content(headers: Sequence[tuple[bytes, bytes]], max_bytes: int) -> Refusal | None:
    types = _values(headers, "content-type")
    if len(types) != 1 or not _json_type(types[0]):
        return CONTENT_TYPE
    lengths = _values(headers, "content-length")
    if len(lengths) != 1 or not _LENGTH.fullmatch(lengths[0]):
        return LENGTH
    if int(lengths[0]) > max_bytes:
        return TOO_LARGE
    return None


def head[S](
    era: Era,
    method: str,
    path: str,
    headers: Sequence[tuple[bytes, bytes]],
    *,
    token: BridgeTokenHash,
    find: Callable[[str], S | None],
    max_bytes: int = MESSAGE_MAX,
) -> Head[S] | Refusal:
    """Rows 1 to 6 of C.4's table, before any body byte is read. ``headers`` are the request's
    as received (ASGI's), so a repeated header is seen; ``find`` looks a legacy session up."""
    if path != PATH:
        return NOT_FOUND
    if method not in METHODS:
        return METHOD_REFUSED
    if _values(headers, "origin"):
        return ORIGIN
    if not token.admits(_values(headers, "authorization")):
        return TOKEN
    if method == "POST" and (refused := _content(headers, max_bytes)) is not None:
        return refused
    if era == "modern":
        if method != "POST":
            return ERA_METHOD
        return Head(method, routing={name: _values(headers, name) for name in ROUTING_HEADERS})
    versions = _values(headers, VERSION_HEADER)
    if len(versions) > 1 or (versions and versions[0] not in LEGACY_VERSIONS):
        return VERSION
    ids = _values(headers, SESSION_HEADER)
    if len(ids) > 1:
        return SESSION_REPEATED
    if not ids:
        return Head(method) if method == "POST" else session_missing()
    session = find(ids[0])
    if session is None:
        return SESSION_UNKNOWN
    return Head(method, session)


def decode_name(value: str) -> str | None:
    """An ``Mcp-Name`` value: as written, or decoded from the ``=?base64?...?=`` sentinel. A
    sentinel that isn't canonical Base64 of UTF-8 is None, so it never matches by accident."""
    found = _SENTINEL.fullmatch(value)
    if found is None:
        return value
    payload = found.group(1)
    try:
        decoded = base64.b64decode(payload, validate=True)
    except binascii.Error:
        return None
    if base64.b64encode(decoded).decode("ascii") != payload:
        return None
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def mismatch(routing: Mapping[str, tuple[str, ...]], message: Mapping[str, Any]) -> str | None:
    """Row 7: why a modern request's routing headers disagree with its body, or None. Each
    header must be sent once and equal its body field; ``Mcp-Name`` only on the methods that
    name something."""
    for name in ROUTING_HEADERS:
        if len(routing.get(name, ())) > 1:
            return f"{name} appears more than once"
    params = message.get("params", {})
    meta = params.get("_meta")
    version = meta.get(PROTOCOL_VERSION_META) if isinstance(meta, dict) else None
    if routing.get(VERSION_HEADER, ()) != (version,):
        return f"{VERSION_HEADER} doesn't match the request's _meta protocol version"
    if routing.get(METHOD_HEADER, ()) != (message["method"],):
        return f"{METHOD_HEADER} doesn't match the request's method"
    key = NAME_BEARING.get(message["method"])
    if key is None:
        return None
    names = routing.get(NAME_HEADER, ())
    decoded = decode_name(names[0]) if names else None
    if decoded is None or decoded != params.get(key):
        return f"{NAME_HEADER} doesn't match the request's {key}"
    return None


def _unsupported(message: Mapping[str, Any]) -> Refusal:
    requested = message.get("params", {}).get("protocolVersion")
    data = {
        "supported": list(MODERN_VERSIONS),
        "requested": requested if isinstance(requested, str) else "",
    }
    return Refusal(
        400,
        "initialize_modern",
        UNSUPPORTED_PROTOCOL_VERSION,
        "Unsupported protocol version",
        data,
        message["id"],
    )


def body[S](
    era: Era, seen: Head[S], data: bytes, *, max_bytes: int = MESSAGE_MAX
) -> Admitted | Refusal:
    """Rows 6 to 9 of C.4's table, on the body of a request whose head :func:`head` let
    through (``seen``)."""
    message = parse(data, max_bytes)
    if not isinstance(message, Message) or message.kind not in ("request", "notification"):
        return Refusal(
            400, "invalid", INVALID_REQUEST, "the body isn't one JSON-RPC request or notification"
        )
    value = message.value
    method = value["method"]
    request = message.kind == "request"
    rpc_id = value.get("id")
    if era == "legacy":
        if request and method == "initialize":
            if seen.session is not None:
                return Refusal(
                    400,
                    "initialize_in_session",
                    INVALID_REQUEST,
                    "Bad Request: initialize is sent without a session",
                    rpc_id=rpc_id,
                )
            return Admitted(message, "start")
        if seen.session is None:
            return session_missing(rpc_id)
        if request:
            return Admitted(message, "relay")
        notifications: dict[str, Action] = {INITIALIZED: "notify", CANCELLED: "cancel"}
        return Admitted(message, notifications.get(method, "accept"))
    if not request:
        return Admitted(message, "accept")
    if method == "initialize":
        return _unsupported(value)
    found = mismatch(seen.routing, value)
    if found is not None:
        return Refusal(400, "header_mismatch", HEADER_MISMATCH, found, rpc_id=rpc_id)
    return Admitted(message, "relay")
