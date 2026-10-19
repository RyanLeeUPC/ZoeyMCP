"""Admission decisions for the client-facing server (M3 design E.2, E.3).

Every decision here is a pure function or a small bounded structure, so the ASGI glue in
``app.py`` only reads inputs and writes answers. The order of the checks is the design's, and no
body byte is read before the identity and server checks have passed.

Identity comes from the bearer token alone: its SHA-256 is compared with every client's hash,
with no early exit, and then the client's source networks are checked against the direct peer.
Every identity failure gets the same 401, so the answer doesn't say which check failed; the
reason goes to the log only. A session id is never an identity.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from ..common import canonical
from ..common.logs import refuse_type
from ..common.policy.schema import NAME_PATTERN
from ..common.policy.view import ViewClient, ViewGateway, ViewRemoteServer

MODERN_VERSION = "2026-07-28"
SUPPORTED_VERSIONS = frozenset({MODERN_VERSION, "2025-11-25", "2025-06-18"})
METHODS = frozenset({"POST", "GET", "DELETE"})
RPC_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "ping",
        "server/discover",
        "tools/list",
        "tools/call",
        "subscriptions/listen",
        "notifications/cancelled",
    }
)
MAX_BODY_DEPTH = 64
SESSION_CAPACITY = 4096

_PATH = re.compile(r"/s/(" + NAME_PATTERN.removeprefix("^").removesuffix("$") + r")/mcp")
_TOKEN = re.compile(r"[A-Za-z0-9._~-]{1,256}")
_PORT = re.compile(r"[0-9]{1,5}")
_JSON_TYPE = re.compile(r"application/json(?:\s*;.*)?", re.IGNORECASE)

# The fixed message for each refusal status. Nothing about the request appears in it.
STATUS_MESSAGES: Mapping[int, str] = {
    400: "bad request",
    401: "unauthorized",
    403: "forbidden",
    404: "not found",
    405: "method not allowed",
    413: "request too large",
    421: "misdirected request",
    429: "too many requests",
    503: "gateway unavailable",
}
# JSON-RPC errors that aren't about the HTTP request as a whole name the error instead.
RPC_MESSAGES: Mapping[int, str] = {-32601: "method not found", -32700: "parse error"}


@dataclass(frozen=True)
class Refusal:
    """An HTTP-level refusal. ``reason`` is for the log only, never the answer."""

    status: int
    reason: str
    rpc_code: int = -32600


def refusal_body(refusal: Refusal) -> bytes:
    """The JSON-RPC error body every HTTP-level refusal carries."""
    message = RPC_MESSAGES.get(refusal.rpc_code) or STATUS_MESSAGES[refusal.status]
    error = {"code": refusal.rpc_code, "message": message}
    return json.dumps({"jsonrpc": "2.0", "id": None, "error": error}).encode()


def refusal_headers(refusal: Refusal) -> list[tuple[str, str]]:
    headers = [("content-type", "application/json")]
    if refusal.status == 401:
        headers.append(("www-authenticate", 'Bearer realm="zoeymcp"'))
    if refusal.status == 429:
        headers.append(("retry-after", "1"))
    return headers


# --- steps 1-5: path, freshness, Host, Origin, method -----------------------------------------


def server_from_path(path: str) -> str | None:
    """Step 1: the server name in ``/s/<name>/mcp``, or None for any other path."""
    match = _PATH.fullmatch(path)
    return match.group(1) if match else None


def is_fresh(age: float | None, max_stale: int) -> bool:
    """Step 2: a snapshot exists and is no older than ``policy_max_stale`` seconds."""
    return age is not None and 0 <= age <= max_stale


def host_name(header: str | None) -> str | None:
    """The host in a ``Host`` header: lowercased, port and IPv6 brackets removed.

    None for a missing or malformed header, including an IPv6 address without brackets.
    """
    if not header:
        return None
    if header.startswith("["):
        end = header.find("]")
        if end < 0:
            return None
        host, rest = header[1:end], header[end + 1 :]
        if ":" not in host:
            return None
    else:
        host, colon, port = header.partition(":")
        if ":" in port:
            return None  # an IPv6 address without brackets
        rest = colon + port
    if rest and not (rest.startswith(":") and _PORT.fullmatch(rest[1:])):
        return None
    return host.lower() or None


def host_allowed(header: str | None, hosts: Sequence[str]) -> bool:
    """Step 3."""
    host = host_name(header)
    return host is not None and host in {allowed.lower() for allowed in hosts}


def origin_allowed(header: str | None, origins: Sequence[str]) -> bool:
    """Step 4: no ``Origin`` is fine; a present one must be listed, and ``null`` never is.

    Policy origins are already in the form browsers send (lower case, no default port).
    """
    if header is None:
        return True
    return header != "null" and header in origins


def method_allowed(method: str) -> bool:
    """Step 5."""
    return method in METHODS


# --- step 6: identity --------------------------------------------------------------------------


class ClientToken:
    """A client token as an agent presented it. Its ``repr`` hides it, and logging it raises."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def sha256(self) -> str:
        """``sha256:`` and the hex digest, as ``token_sha256`` holds it."""
        return "sha256:" + hashlib.sha256(self._value.encode()).hexdigest()

    def __repr__(self) -> str:
        return "ClientToken(***)"


refuse_type(ClientToken)


def bearer_token(values: Sequence[str]) -> ClientToken | None:
    """The token from exactly one ``Authorization: Bearer <token>`` header, or None."""
    if len(values) != 1:
        return None
    scheme, space, token = values[0].partition(" ")
    if not space or scheme.lower() != "bearer" or _TOKEN.fullmatch(token) is None:
        return None
    return ClientToken(token)


def identify(token: ClientToken, clients: Mapping[str, ViewClient]) -> str | None:
    """The client whose ``token_sha256`` matches ``token``.

    Every client's hash is compared, with no early exit, so the time taken doesn't depend on
    which client matched or whether any did.
    """
    presented = token.sha256().encode()
    found: str | None = None
    for name, client in clients.items():
        if hmac.compare_digest(presented, client.token_sha256.encode()) and found is None:
            found = name
    return found


def source_allowed(peer: str | None, sources: Sequence[str]) -> bool:
    """A client with ``sources`` is accepted only from a direct peer inside one of them.

    ``X-Forwarded-For`` is never consulted: behind a proxy, ``peer`` is the proxy.
    """
    if not sources:
        return True
    if peer is None:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address in ipaddress.ip_network(source, strict=False) for source in sources)


def authenticate(
    authorization: Sequence[str], peer: str | None, gateway: ViewGateway
) -> str | Refusal:
    """Step 6: the client's name, or the one 401 every identity failure gets."""
    token = bearer_token(authorization)
    if token is None:
        return Refusal(401, "no usable bearer token")
    name = identify(token, gateway.clients)
    if name is None:
        return Refusal(401, "unknown token")
    if not source_allowed(peer, gateway.clients[name].sources):
        return Refusal(401, "source not allowed")
    return name


def revoked(old: ViewGateway, new: ViewGateway) -> frozenset[tuple[str, str]]:
    """The (client, server) pairs a new view takes away (M3 design D.3).

    A pair is revoked when the client is gone, its token or source networks changed, it is no
    longer assigned the server, or the server is no longer one this version serves. Requests in
    flight for a revoked pair are stopped: the next request would be refused anyway.
    """
    gone: set[tuple[str, str]] = set()
    for name, client in old.clients.items():
        now = new.clients.get(name)
        same = (
            now is not None
            and now.token_sha256 == client.token_sha256
            and now.sources == client.sources
        )
        for server in client.servers:
            if not isinstance(old.servers.get(server), ViewRemoteServer):
                continue  # never served, so nothing can be in flight
            kept = (
                same
                and now is not None
                and server in now.servers
                and isinstance(new.servers.get(server), ViewRemoteServer)
            )
            if not kept:
                gone.add((name, server))
    return frozenset(gone)


# --- steps 7-8: server and protocol version -------------------------------------------------------


def server_for(gateway: ViewGateway, client: str, name: str) -> ViewRemoteServer | Refusal:
    """Step 7: the server, if it exists, is remote, and is assigned to the client.

    The same 404 for all three, so a client learns nothing about servers it isn't given.
    """
    server = gateway.servers.get(name)
    if server is None or name not in gateway.clients[client].servers:
        return Refusal(404, "server not assigned")
    if not isinstance(server, ViewRemoteServer):
        return Refusal(404, "server kind not served")
    return server


VersionCheck = Literal["ok", "needs_initialize"]


def check_version(header: str | None, method: str) -> VersionCheck | Refusal:
    """Step 8. Without a header, only a POST that turns out to be ``initialize`` is allowed."""
    if header is None:
        if method != "POST":
            return Refusal(400, "no protocol version")
        return "needs_initialize"
    if header not in SUPPORTED_VERSIONS:
        return Refusal(400, "unsupported protocol version")
    return "ok"


# --- step 9 and E.3: session bindings ---------------------------------------------------------


@dataclass
class _Session:
    client: str
    server: str
    last_seen: float
    in_flight: int = 0


@dataclass
class SessionBindings:
    """Which (client, server) each legacy session id belongs to.

    Bounded (least recently used first out) and expiring: a session with no request in flight
    expires ``idle_timeout`` seconds after its last one. An open GET stream is a request in
    flight, so it keeps its session, as the SDK's own idle timer does.
    """

    idle_timeout: float
    capacity: int = SESSION_CAPACITY
    _sessions: OrderedDict[str, _Session] = field(default_factory=OrderedDict)

    def _live(self, session_id: str, now: float) -> _Session | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.in_flight == 0 and now - session.last_seen > self.idle_timeout:
            del self._sessions[session_id]
            return None
        return session

    def bind(self, session_id: str, client: str, server: str, now: float) -> None:
        """Record a session id the SDK minted in a response to this (client, server)."""
        existing = self._live(session_id, now)
        if existing is not None and (existing.client, existing.server) != (client, server):
            return  # never rebind a live session to someone else
        if existing is None:
            self._sessions[session_id] = _Session(client, server, now)
        self._sessions.move_to_end(session_id)
        while len(self._sessions) > self.capacity:
            oldest = next(iter(self._sessions))
            if self._sessions[oldest].in_flight:
                break  # nothing idle to evict
            del self._sessions[oldest]

    def allowed(self, session_id: str, client: str, server: str, now: float) -> bool:
        """Step 9: the session is live and bound to exactly this client and server path."""
        session = self._live(session_id, now)
        return session is not None and (session.client, session.server) == (client, server)

    def begin(self, session_id: str, now: float) -> None:
        session = self._live(session_id, now)
        if session is not None:
            session.in_flight += 1
            session.last_seen = now
            self._sessions.move_to_end(session_id)

    def end(self, session_id: str, now: float) -> None:
        session = self._sessions.get(session_id)
        if session is not None:
            session.in_flight = max(0, session.in_flight - 1)
            session.last_seen = now

    def drop(self, session_id: str) -> None:
        """After a successful DELETE."""
        self._sessions.pop(session_id, None)

    def count(self, client: str, now: float) -> int:
        """Live sessions of one client, for ``max_sessions_per_client``."""
        return sum(
            1
            for session_id in list(self._sessions)
            if (session := self._live(session_id, now)) is not None and session.client == client
        )


# --- step 10: per-client limits ---------------------------------------------------------------


@dataclass
class ClientCounters:
    """Requests and long-lived streams in flight, per client, and the reply slots in use per
    session: each legacy prompt waiting on a session reserves one, so a client at its
    concurrency cap can still deliver its operator's answer (M4 design D.3)."""

    requests: dict[str, int] = field(default_factory=dict)
    streams: dict[str, int] = field(default_factory=dict)
    replies: dict[str, int] = field(default_factory=dict)

    def try_acquire(
        self, client: str, *, stream: bool, max_requests: int, max_streams: int
    ) -> bool:
        if self.requests.get(client, 0) >= max_requests:
            return False
        if stream and self.streams.get(client, 0) >= max_streams:
            return False
        self.requests[client] = self.requests.get(client, 0) + 1
        if stream:
            self.streams[client] = self.streams.get(client, 0) + 1
        return True

    def try_add_stream(self, client: str, *, max_streams: int) -> bool:
        """A request already counted turned out to be a long-lived stream."""
        if self.streams.get(client, 0) >= max_streams:
            return False
        self.streams[client] = self.streams.get(client, 0) + 1
        return True

    def release(self, client: str, *, stream: bool) -> None:
        self.requests[client] = max(0, self.requests.get(client, 0) - 1)
        if stream:
            self.streams[client] = max(0, self.streams.get(client, 0) - 1)

    def try_acquire_reply(self, session_sha256: str, *, waiting: int) -> bool:
        """A reply slot of this session, if one of its ``waiting`` prompts' slots is free."""
        if self.replies.get(session_sha256, 0) >= waiting:
            return False
        self.replies[session_sha256] = self.replies.get(session_sha256, 0) + 1
        return True

    def release_reply(self, session_sha256: str) -> None:
        left = self.replies.get(session_sha256, 0) - 1
        if left > 0:
            self.replies[session_sha256] = left
        else:
            self.replies.pop(session_sha256, None)


def too_many(reason: str) -> Refusal:
    return Refusal(429, reason)


# --- steps 11-12: the body --------------------------------------------------------------------


def check_content(
    content_type: str | None, content_length: str | None, max_bytes: int
) -> Refusal | None:
    """Step 11, before reading: a JSON content type and a declared length within the limit.

    The streamed read must still stop at ``max_bytes``: ``Content-Length`` may be absent.
    """
    if content_type is None or _JSON_TYPE.fullmatch(content_type.strip()) is None:
        return Refusal(400, "not application/json")
    if content_length is not None:
        if not content_length.isascii() or not content_length.isdigit():
            return Refusal(400, "bad content length")
        if int(content_length) > max_bytes:
            return Refusal(413, "body over the limit")
    return None


def parse_message(body: bytes, max_bytes: int) -> dict[str, Any] | Refusal:
    """Step 11: one strict JSON object. A batch, or anything else, is refused."""
    if len(body) > max_bytes:
        return Refusal(413, "body over the limit")
    try:
        message = canonical.loads_strict(body, max_bytes=max_bytes, max_depth=MAX_BODY_DEPTH)
    except canonical.JSONRejected:
        return Refusal(400, "not strict JSON", rpc_code=-32700)
    if not isinstance(message, dict):
        return Refusal(400, "not one JSON-RPC object")
    return message


def is_response(message: Mapping[str, Any]) -> bool:
    """A JSON-RPC response: no ``method``, an ``id``, and exactly one of ``result`` and
    ``error``."""
    request_id = message.get("id")
    if "method" in message or isinstance(request_id, bool):
        return False
    if not isinstance(request_id, str | int):
        return False
    return ("result" in message) != ("error" in message)


def check_rpc(
    message: Mapping[str, Any],
    version: VersionCheck,
    modern: bool,
    *,
    answer_expected: bool = False,
) -> Refusal | None:
    """Step 12: a request or notification this gateway serves, or an agent's answer.

    A client response (no ``method``) is admitted only with ``answer_expected``: on a legacy
    session bound to this client and server, with a prompt waiting on it, in a small body
    (M4 design D.3). An unknown method gets ``-32601``, with HTTP 404 on modern requests and
    200 on legacy ones, as each era expects.
    """
    method = message.get("method")
    if method is None:
        if answer_expected and not modern and is_response(message):
            return None
        return Refusal(400, "a client response, and no prompt is waiting for one")
    if not isinstance(method, str) or method not in RPC_METHODS:
        return Refusal(404 if modern else 200, "method not served", rpc_code=-32601)
    if version == "needs_initialize" and method != "initialize":
        return Refusal(400, "no protocol version")
    return None
