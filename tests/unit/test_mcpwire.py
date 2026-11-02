"""What MCP traffic the gateway sends, and the routing-header rule (M8 design G-19, B.2; O.3
``test_mcpwire.py``).

Moved from the gateway's egress filter and the bridge's admission without a change, so these pin
the old behaviour byte for byte: each set as it was, both modules reading the same objects, and
every branch of :func:`mismatch` with its message, :func:`decode_name` on each sentinel form.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from tests.unit.plainid import plain_id
from zoeymcp.bridge import admit
from zoeymcp.common import mcpwire
from zoeymcp.common.mcpwire import decode_name, mismatch
from zoeymcp.gateway import egressrules

MODERN = "2026-07-28"
VERSION_OK = {"mcp-protocol-version": (MODERN,)}


def message(method: str, params: Any = None) -> dict[str, Any]:
    found: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        found["params"] = params
    return found


def meta(**params: Any) -> dict[str, Any]:
    """Params carrying the modern protocol version in ``_meta``."""
    return {"_meta": {"io.modelcontextprotocol/protocolVersion": MODERN}, **params}


def sentinel(text: str) -> str:
    return "=?base64?" + base64.b64encode(text.encode()).decode("ascii") + "?="


# --- the sets -----------------------------------------------------------------------------------


def test_the_sets_are_the_egress_filters() -> None:
    assert {
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
    } == mcpwire.HEADERS
    assert {
        "initialize",
        "server/discover",
        "tools/list",
        "tools/call",
        "subscriptions/listen",
        "ping",
    } == mcpwire.REQUESTS
    assert {
        "prompts": {"prompts/list", "prompts/get"},
        "resources": {"resources/list", "resources/templates/list", "resources/read"},
        "completions": {"completion/complete"},
    } == mcpwire.KIND_REQUESTS
    assert {"notifications/initialized", "notifications/cancelled"} == mcpwire.NOTIFICATIONS
    assert {
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientCapabilities",
        "io.modelcontextprotocol/clientInfo",
        "progressToken",
    } == mcpwire.META_KEYS
    assert mcpwire.PARAM_HEADER_PREFIX == "mcp-param-"
    sets = (mcpwire.HEADERS, mcpwire.REQUESTS, mcpwire.NOTIFICATIONS, mcpwire.META_KEYS)
    assert all(isinstance(value, frozenset) for value in sets)
    assert all(isinstance(value, frozenset) for value in mcpwire.KIND_REQUESTS.values())


def test_methods_is_every_method_the_gateway_sends() -> None:
    """B.2 E6: the requests of every kind and the notifications, and nothing else."""
    assert {
        "initialize",
        "server/discover",
        "tools/list",
        "tools/call",
        "subscriptions/listen",
        "ping",
        "prompts/list",
        "prompts/get",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "completion/complete",
        "notifications/initialized",
        "notifications/cancelled",
    } == mcpwire.METHODS
    assert isinstance(mcpwire.METHODS, frozenset)


def test_the_routing_names_are_the_bridges() -> None:
    assert mcpwire.PROTOCOL_VERSION_META == "io.modelcontextprotocol/protocolVersion"
    assert mcpwire.ROUTING_HEADERS == ("mcp-protocol-version", "mcp-method", "mcp-name")
    assert (mcpwire.VERSION_HEADER, mcpwire.METHOD_HEADER, mcpwire.NAME_HEADER) == (
        mcpwire.ROUTING_HEADERS
    )
    assert mcpwire.NAME_BEARING == {
        "tools/call": "name",
        "prompts/get": "name",
        "resources/read": "uri",
    }


def test_the_egress_filter_and_the_bridge_read_the_same_objects() -> None:
    assert egressrules.HEADERS is mcpwire.HEADERS
    assert egressrules.REQUESTS is mcpwire.REQUESTS
    assert egressrules.KIND_REQUESTS is mcpwire.KIND_REQUESTS
    assert egressrules.NOTIFICATIONS is mcpwire.NOTIFICATIONS
    assert egressrules.META_KEYS is mcpwire.META_KEYS
    assert egressrules.PARAM_HEADER_PREFIX is mcpwire.PARAM_HEADER_PREFIX
    assert admit.decode_name is mcpwire.decode_name
    assert admit.mismatch is mcpwire.mismatch
    assert admit.PROTOCOL_VERSION_META is mcpwire.PROTOCOL_VERSION_META


# --- decode_name --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "decoded"),
    [
        ("plain", "plain"),
        ("", ""),
        ("=?base64?aGk=?=", "hi"),
        ("=?base64??=", ""),
        (sentinel("café"), "café"),
        ("=?base64?aGk?=", None),  # not padded
        ("=?base64?aGl=?=", None),  # not canonical
        ("=?base64?a*k=?=", None),  # not Base64
        ("=?base64?a Gk=?=", None),  # a stray character, which a lenient decode would drop
        ("=?base64?/w==?=", None),  # not UTF-8
        ("=?base64?é?=", None),  # not ASCII, as a latin-1 header can be (D-245)
        ("x=?base64?aGk=?=", "x=?base64?aGk=?="),  # not the whole value: as written
        ("=?base64?aGk=?=x", "=?base64?aGk=?=x"),
        ("=?BASE64?aGk=?=", "=?BASE64?aGk=?="),
    ],
    ids=plain_id,
)
def test_decode_name(value: str, decoded: str | None) -> None:
    assert decode_name(value) == decoded


# --- mismatch -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("routing", "sent", "reason"),
    [
        (
            {"mcp-protocol-version": (MODERN, MODERN)},
            message("tools/list", meta()),
            "mcp-protocol-version appears more than once",
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/list", "tools/list")},
            message("tools/list", meta()),
            "mcp-method appears more than once",
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/call",), "mcp-name": ("a", "a")},
            message("tools/call", meta(name="a")),
            "mcp-name appears more than once",
        ),
        (
            {"mcp-method": ("tools/list",)},
            message("tools/list", meta()),
            "mcp-protocol-version doesn't match the request's _meta protocol version",
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/list",)},
            message("tools/list"),
            "mcp-protocol-version doesn't match the request's _meta protocol version",
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/list",)},
            message("tools/list", {"_meta": ["not", "an", "object"]}),
            "mcp-protocol-version doesn't match the request's _meta protocol version",
        ),
        (
            {"mcp-protocol-version": ("2025-11-25",), "mcp-method": ("tools/list",)},
            message("tools/list", meta()),
            "mcp-protocol-version doesn't match the request's _meta protocol version",
        ),
        (
            VERSION_OK,
            message("tools/list", meta()),
            "mcp-method doesn't match the request's method",
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/call",)},
            message("tools/list", meta()),
            "mcp-method doesn't match the request's method",
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/call",)},
            message("tools/call", meta(name="echo")),
            "mcp-name doesn't match the request's name",
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/call",), "mcp-name": ("other",)},
            message("tools/call", meta(name="echo")),
            "mcp-name doesn't match the request's name",
        ),
        (
            {**VERSION_OK, "mcp-method": ("prompts/get",), "mcp-name": ("=?base64?aGk?=",)},
            message("prompts/get", meta(name="=?base64?aGk?=")),
            "mcp-name doesn't match the request's name",
        ),
        (
            {**VERSION_OK, "mcp-method": ("resources/read",), "mcp-name": ("u",)},
            message("resources/read", meta(name="u")),
            "mcp-name doesn't match the request's uri",
        ),
    ],
    ids=plain_id,
)
def test_a_routing_header_that_disagrees(
    routing: dict[str, tuple[str, ...]], sent: dict[str, Any], reason: str
) -> None:
    assert mismatch(routing, sent) == reason


@pytest.mark.parametrize(
    ("routing", "sent"),
    [
        ({**VERSION_OK, "mcp-method": ("tools/list",)}, message("tools/list", meta())),
        # Mcp-Name is read only on the methods that name something.
        (
            {**VERSION_OK, "mcp-method": ("tools/list",), "mcp-name": ("x",)},
            message("tools/list", meta()),
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/call",), "mcp-name": ("echo",)},
            message("tools/call", meta(name="echo")),
        ),
        (
            {**VERSION_OK, "mcp-method": ("tools/call",), "mcp-name": (sentinel("café"),)},
            message("tools/call", meta(name="café")),
        ),
        (
            {**VERSION_OK, "mcp-method": ("resources/read",), "mcp-name": ("file:///a",)},
            message("resources/read", meta(uri="file:///a")),
        ),
    ],
    ids=plain_id,
)
def test_routing_headers_that_agree(
    routing: dict[str, tuple[str, ...]], sent: dict[str, Any]
) -> None:
    assert mismatch(routing, sent) is None


def test_each_header_is_counted_before_any_is_compared() -> None:
    """A repeated ``Mcp-Name`` is reported even when the version and method are wrong too."""
    routing = {"mcp-protocol-version": ("x",), "mcp-method": ("y",), "mcp-name": ("a", "b")}
    assert mismatch(routing, message("tools/call", meta(name="a"))) == (
        "mcp-name appears more than once"
    )
