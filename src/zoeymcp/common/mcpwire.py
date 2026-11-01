"""What MCP traffic the gateway sends, and the routing-header rule (M8 design G-19, B.2).

One place for both, so the gateway's egress filter (:mod:`zoeymcp.gateway.egressrules`), the
bridge's admission (:mod:`zoeymcp.bridge.admit`) and the vault's envelope reader (M8) read the
same method sets, ``_meta`` keys and header allowlist, and decode ``Mcp-Name`` the same way. Each
moved here unchanged:

- the requests, notifications, ``_meta`` keys and headers the egress filter lets out (M3 design
  F.2; M6 design L.4, L.6 for the kinds beyond tools);
- the routing headers of a modern request, and :func:`mismatch`, why they disagree with its body
  (M7 design C.4 row 7), with :func:`decode_name` for ``Mcp-Name``'s Base64 sentinel form.

Pure and standard library only.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import Any, Final

# The headers the gateway's egress filter lets out, by their lower-case names.
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
REQUESTS = frozenset(
    {"initialize", "server/discover", "tools/list", "tools/call", "subscriptions/listen", "ping"}
)
# The requests of the kinds beyond tools, by the enable entry that allows them (L.4, L.6).
KIND_REQUESTS: Mapping[str, frozenset[str]] = {
    "prompts": frozenset({"prompts/list", "prompts/get"}),
    "resources": frozenset({"resources/list", "resources/templates/list", "resources/read"}),
    "completions": frozenset({"completion/complete"}),
}
NOTIFICATIONS = frozenset({"notifications/initialized", "notifications/cancelled"})
META_KEYS = frozenset(
    {
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientCapabilities",
        "io.modelcontextprotocol/clientInfo",
        "progressToken",
    }
)

PROTOCOL_VERSION_META: Final = "io.modelcontextprotocol/protocolVersion"
# The routing headers a modern request carries, by their lower-case names.
VERSION_HEADER: Final = "mcp-protocol-version"
METHOD_HEADER: Final = "mcp-method"
NAME_HEADER: Final = "mcp-name"
ROUTING_HEADERS: Final = (VERSION_HEADER, METHOD_HEADER, NAME_HEADER)
# The methods whose Mcp-Name mirrors a body parameter, and which one.
NAME_BEARING: Final[Mapping[str, str]] = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}

_SENTINEL = re.compile(r"=\?base64\?(.*)\?=")


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
