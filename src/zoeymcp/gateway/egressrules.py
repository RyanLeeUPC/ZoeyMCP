"""The egress filter's decisions: what the gateway may send upstream (M3 design F.2).

The filter is a wrapping transport around each upstream connection's HTTP client, and it checks
every request the SDK sends before it leaves. This module holds its decisions, pure. It pins the
SDK's behaviour on purpose: anything new the SDK starts sending is refused and logged, and the
SDK contract tests tell a harmless shape change from a leak.

A request may go only to the connection's own origin and vault path, carry only the listed
headers, and have one of a few body shapes. A ``tools/call`` must carry exactly the arguments the
pipeline validated: its ``(name, digest(arguments))`` must match a registration, which it uses up
(G9). Nothing that would open a back channel goes out: no declared client capability, no
``requestState`` or ``inputResponses`` retry, no trace context.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..common import canonical
from .access import SUPPORTED_VERSIONS

METHODS = frozenset({"POST", "GET", "DELETE"})
HEADERS = frozenset(
    {
        "host",
        "accept",
        "accept-encoding",
        "connection",
        "content-type",
        "content-length",
        "user-agent",
        "mcp-protocol-version",
        "mcp-session-id",
        "mcp-method",
        "mcp-name",
        "last-event-id",
    }
)
PARAM_HEADER_PREFIX = "mcp-param-"
GATEWAY_KEY_HEADER = "x-zoeymcp-gateway"  # hardened tier only
# The SDK sends this on the legacy GET stream, with this value only.
CACHE_CONTROL = ("cache-control", "no-store")
REQUESTS = frozenset(
    {"initialize", "server/discover", "tools/list", "tools/call", "subscriptions/listen", "ping"}
)
NOTIFICATIONS = frozenset({"notifications/initialized", "notifications/cancelled"})
META_KEYS = frozenset(
    {
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientCapabilities",
        "io.modelcontextprotocol/clientInfo",
        "progressToken",
    }
)
CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
CALL_PARAMS = frozenset({"name", "arguments", "_meta"})
MAX_BODY_BYTES = 16 * 2**20


@dataclass(frozen=True)
class Outgoing:
    """One request as the transport sees it. Header names may be in any case."""

    method: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    headers: Sequence[tuple[str, str]]
    body: bytes


@dataclass(frozen=True)
class Target:
    """Where one connection may send: its origin and its vault path."""

    scheme: str
    host: str
    port: int | None
    path: str
    hardened: bool = False


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str = ""
    # For a POST: "request <method>", "notification <method>" or "response", for the log.
    kind: str = ""


@dataclass
class CallRegistry:
    """The ``(tool, digest(arguments))`` pairs the pipeline validated and may send, once each."""

    _pending: Counter[tuple[str, str]] = field(default_factory=Counter)

    def register(self, tool: str, digest: str) -> None:
        self._pending[(tool, digest)] += 1

    def withdraw(self, tool: str, digest: str) -> None:
        """A registered call that never went out (cancelled, or refused before sending)."""
        if self._pending[(tool, digest)] > 0:
            self._pending[(tool, digest)] -= 1
        if self._pending[(tool, digest)] == 0:
            del self._pending[(tool, digest)]

    def consume(self, tool: str, digest: str) -> bool:
        if self._pending[(tool, digest)] <= 0:
            self._pending.pop((tool, digest), None)
            return False
        self.withdraw(tool, digest)
        return True

    def __len__(self) -> int:
        return sum(self._pending.values())


def _refuse(reason: str, kind: str = "") -> Verdict:
    return Verdict(False, reason, kind)


def check_headers(method: str, headers: Sequence[tuple[str, str]], hardened: bool) -> str | None:
    """Why the headers can't go out, or None."""
    for name, value in headers:
        lowered = name.lower()
        if lowered in HEADERS or lowered.startswith(PARAM_HEADER_PREFIX):
            if lowered == "mcp-protocol-version" and value not in SUPPORTED_VERSIONS:
                return "unsupported protocol version header"
            continue
        if lowered == GATEWAY_KEY_HEADER and hardened:
            continue
        if (lowered, value) == CACHE_CONTROL and method == "GET":
            continue
        return f"header {lowered} not allowed"
    return None


def _capabilities_empty(value: object) -> bool:
    return isinstance(value, dict) and not value


def _check_meta(params: Mapping[str, Any]) -> str | None:
    meta = params.get("_meta", {})
    if not isinstance(meta, dict):
        return "_meta is not an object"
    extra = set(meta) - META_KEYS
    if extra:
        return "_meta key not allowed"
    if CAPABILITIES_META_KEY in meta and not _capabilities_empty(meta[CAPABILITIES_META_KEY]):
        return "a client capability is declared"
    return None


def _check_request(message: Mapping[str, Any], registry: CallRegistry) -> Verdict:
    method = message["method"]
    kind = f"request {method}"
    if method not in REQUESTS:
        return _refuse("request method not allowed", kind)
    params = message.get("params", {})
    if not isinstance(params, dict):
        return _refuse("params is not an object", kind)
    problem = _check_meta(params)
    if problem is not None:
        return _refuse(problem, kind)
    if method == "initialize" and not _capabilities_empty(params.get("capabilities", {})):
        return _refuse("a client capability is declared", kind)
    if method == "tools/call":
        if not set(params) <= CALL_PARAMS:
            return _refuse("tools/call carries more than name and arguments", kind)
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _refuse("tools/call name or arguments malformed", kind)
        if not registry.consume(name, canonical.digest(arguments)):
            return _refuse("tools/call not registered by the pipeline", kind)
    return Verdict(True, kind=kind)


def _check_body(body: bytes, registry: CallRegistry) -> Verdict:
    try:
        message = canonical.loads_strict(body, max_bytes=MAX_BODY_BYTES)
    except canonical.JSONRejected:
        return _refuse("body is not strict JSON")
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _refuse("body is not one JSON-RPC message")
    method = message.get("method")
    if method is None:
        if "id" not in message:
            return _refuse("response without an id", "response")
        if "error" in message and "result" not in message:
            return Verdict(True, kind="response")
        if message.get("result") == {} and "error" not in message:
            return Verdict(True, kind="response")
        return _refuse("a response with a result", "response")
    if not isinstance(method, str):
        return _refuse("method is not a string")
    if "id" in message:
        return _check_request(message, registry)
    kind = f"notification {method}"
    if method not in NOTIFICATIONS:
        return _refuse("notification not allowed", kind)
    params = message.get("params", {})
    if not isinstance(params, dict):
        return _refuse("params is not an object", kind)
    problem = _check_meta(params)
    return Verdict(True, kind=kind) if problem is None else _refuse(problem, kind)


def check(request: Outgoing, target: Target, registry: CallRegistry) -> Verdict:
    """Whether ``request`` may leave on the connection for ``target``.

    The origin is checked as well as the path: the SDK follows a same-origin redirect, and an
    http-to-https upgrade on the same host, whatever ``follow_redirects`` says.
    """
    if request.method not in METHODS:
        return _refuse("method not allowed")
    origin = (request.scheme.lower(), request.host.lower(), request.port)
    if origin != (target.scheme, target.host.lower(), target.port):
        return _refuse("another origin")
    if request.path != target.path or request.query:
        return _refuse("another path")
    problem = check_headers(request.method, request.headers, target.hardened)
    if problem is not None:
        return _refuse(problem)
    if request.method != "POST":
        return Verdict(True) if not request.body else _refuse(f"{request.method} with a body")
    return _check_body(request.body, registry)
