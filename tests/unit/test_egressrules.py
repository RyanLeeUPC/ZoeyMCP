"""The egress filter's decisions (M3 design F.2)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp import types

from tests.sdk import test_client_contract as contract
from zoeymcp.common import canonical
from zoeymcp.gateway import egressrules
from zoeymcp.gateway.egressrules import (
    CallRegistry,
    Outgoing,
    Target,
    Verdict,
    check,
    check_headers,
)

TARGET = Target(scheme="http", host="vault.invalid", port=None, path="/notes/mcp")
HARDENED = Target(scheme="http", host="vault", port=8080, path="/notes/mcp", hardened=True)
CAPS = "io.modelcontextprotocol/clientCapabilities"
BASE_HEADERS = [
    ("Host", "vault.invalid"),
    ("Accept", "application/json, text/event-stream"),
    ("Content-Type", "application/json"),
    ("Content-Length", "10"),
    ("MCP-Protocol-Version", "2026-07-28"),
    ("User-Agent", "python-httpx/1"),
]


def request(
    body: Any = None,
    *,
    method: str = "POST",
    headers: list[tuple[str, str]] | None = None,
    target: Target = TARGET,
    path: str | None = None,
    query: str = "",
    scheme: str | None = None,
    host: str | None = None,
    port: int | str | None = "same",
) -> Outgoing:
    raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    return Outgoing(
        method=method,
        scheme=scheme or target.scheme,
        host=host or target.host,
        port=target.port if port == "same" else port,  # type: ignore[arg-type]
        path=target.path if path is None else path,
        query=query,
        headers=BASE_HEADERS if headers is None else headers,
        body=raw,
    )


def rpc(method: str, params: dict[str, Any] | None = None, *, id: int | None = 1) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        message["id"] = id
    if params is not None:
        message["params"] = params
    return message


def call(name: str, arguments: Any, **extra: Any) -> dict[str, Any]:
    return rpc("tools/call", {"name": name, "arguments": arguments, **extra})


def verdict(
    outgoing: Outgoing, registry: CallRegistry | None = None, target: Target = TARGET
) -> Verdict:
    return check(outgoing, target, registry if registry is not None else CallRegistry())


def registered(name: str, arguments: dict[str, Any]) -> CallRegistry:
    registry = CallRegistry()
    registry.register(name, canonical.digest(arguments))
    return registry


# --- the lists match the SDK contract tests --------------------------------------------------


def test_the_allowlists_are_the_contract_tests() -> None:
    assert egressrules.HEADERS | {egressrules.CACHE_CONTROL[0]} == contract.EGRESS_HEADERS
    assert egressrules.REQUESTS == contract.EGRESS_REQUESTS
    assert egressrules.KIND_REQUESTS == contract.EGRESS_KIND_REQUESTS
    assert egressrules.NOTIFICATIONS == contract.EGRESS_NOTIFICATIONS
    assert egressrules.META_KEYS == contract.EGRESS_META_KEYS
    assert egressrules.CALL_PARAMS == contract.EGRESS_CALL_PARAMS
    assert egressrules.KIND_PARAMS == contract.EGRESS_KIND_PARAMS
    assert egressrules.CAPABILITIES_META_KEY == types.CLIENT_CAPABILITIES_META_KEY


# --- method, origin, path --------------------------------------------------------------------


def test_a_plain_request_goes_out() -> None:
    assert verdict(request(rpc("tools/list"))) == Verdict(True, kind="request tools/list")


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_get_and_delete_without_a_body(method: str) -> None:
    assert verdict(request(method=method)) == Verdict(True)


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_get_and_delete_with_a_body_are_refused(method: str) -> None:
    assert verdict(request(rpc("ping"), method=method)) == Verdict(False, f"{method} with a body")


@pytest.mark.parametrize("method", ["PUT", "PATCH", "HEAD", "OPTIONS", "post"])
def test_other_methods(method: str) -> None:
    assert verdict(request(rpc("ping"), method=method)) == Verdict(False, "method not allowed")


@pytest.mark.parametrize(
    "changes",
    [
        {"scheme": "https"},  # the SDK follows an http-to-https upgrade on the same host
        {"host": "evil.example"},
        {"port": 8080},
        {"host": "vault.invalid.evil"},
    ],
)
def test_another_origin_is_refused(changes: dict[str, Any]) -> None:
    assert verdict(request(rpc("ping"), **changes)) == Verdict(False, "another origin")


def test_the_origin_compares_host_case_insensitively() -> None:
    assert verdict(request(rpc("ping"), host="VAULT.invalid")).allowed
    assert verdict(request(rpc("ping"), scheme="HTTP")).allowed


def test_the_hardened_origin_includes_the_port() -> None:
    assert verdict(request(rpc("ping"), target=HARDENED), target=HARDENED).allowed
    assert verdict(request(rpc("ping"), target=HARDENED, port=None), target=HARDENED) == Verdict(
        False, "another origin"
    )


@pytest.mark.parametrize(
    ("path", "query"),
    [
        ("/mail/send", ""),  # a same-origin 307 the SDK would follow
        ("/notes/mcp/", ""),
        ("/notes/mcp/../mail", ""),
        ("/NOTES/mcp", ""),
        ("/notes/mcp", "x=1"),
    ],
)
def test_another_path_or_a_query_is_refused(path: str, query: str) -> None:
    assert verdict(request(rpc("ping"), path=path, query=query)) == Verdict(False, "another path")


# --- headers ---------------------------------------------------------------------------------


def test_every_allowed_header() -> None:
    headers = [(name, "x") for name in sorted(egressrules.HEADERS - {"mcp-protocol-version"})]
    headers += [("Mcp-Param-Region", "eu"), ("mcp-protocol-version", "2025-06-18")]
    assert check_headers("POST", headers, hardened=False) is None


@pytest.mark.parametrize(
    "name",
    [
        "Authorization",
        "Cookie",
        "traceparent",
        "tracestate",
        "baggage",
        "X-Forwarded-For",
        "Origin",
    ],
)
def test_other_headers_are_refused(name: str) -> None:
    assert (
        check_headers("POST", [(name, "x")], hardened=False) == f"header {name.lower()} not allowed"
    )


def test_the_gateway_key_only_in_the_hardened_tier() -> None:
    assert check_headers("POST", [("X-ZoeyMCP-Gateway", "zgw1-x")], hardened=True) is None
    assert (
        check_headers("POST", [("X-ZoeyMCP-Gateway", "zgw1-x")], hardened=False)
        == "header x-zoeymcp-gateway not allowed"
    )


def test_cache_control_only_no_store_on_get() -> None:
    assert check_headers("GET", [("Cache-Control", "no-store")], hardened=False) is None
    assert check_headers("POST", [("Cache-Control", "no-store")], hardened=False) is not None
    assert check_headers("GET", [("Cache-Control", "max-age=0")], hardened=False) is not None
    assert check_headers("GET", [("Cache-Control", "No-Store")], hardened=False) is not None


@pytest.mark.parametrize("version", ["2025-03-26", "", "latest"])
def test_the_protocol_version_header_must_be_supported(version: str) -> None:
    assert (
        check_headers("POST", [("MCP-Protocol-Version", version)], hardened=False)
        == "unsupported protocol version header"
    )


def test_a_refused_header_refuses_the_request() -> None:
    outgoing = request(rpc("ping"), headers=[*BASE_HEADERS, ("Authorization", "Bearer x")])
    assert verdict(outgoing) == Verdict(False, "header authorization not allowed")


# --- POST bodies -----------------------------------------------------------------------------


@pytest.mark.parametrize("method", sorted(egressrules.REQUESTS - {"tools/call"}))
def test_allowed_requests(method: str) -> None:
    assert verdict(request(rpc(method, {}))) == Verdict(True, kind=f"request {method}")


def test_requests_without_params() -> None:
    assert verdict(request(rpc("ping"))).allowed


@pytest.mark.parametrize(
    "method",
    ["sampling/createMessage", "resources/list", "prompts/get", "logging/setLevel", "tasks/get"],
)
def test_other_requests_are_refused(method: str) -> None:
    assert verdict(request(rpc(method, {}))) == Verdict(
        False, "request method not allowed", f"request {method}"
    )


# Each request of a kind beyond tools, the enable entry that allows it, and params it may carry.
KIND_REQUESTS = [
    ("prompts", "prompts/list", {"cursor": "c"}),
    ("prompts", "prompts/get", {"name": "brainstorm", "arguments": {"topic": "x"}}),
    ("resources", "resources/list", {"cursor": "c"}),
    ("resources", "resources/templates/list", {"cursor": "c"}),
    ("resources", "resources/read", {"uri": "notes://index"}),
    (
        "completions",
        "completion/complete",
        {
            "ref": {"type": "ref/prompt", "name": "brainstorm"},
            "argument": {"name": "topic", "value": "a"},
            "context": {"arguments": {}},
        },
    ),
]


def enabling(*entries: str) -> Target:
    return Target(
        scheme="http",
        host="vault.invalid",
        port=None,
        path="/notes/mcp",
        enabled=frozenset(entries),
    )


@pytest.mark.parametrize(("entry", "method", "params"), KIND_REQUESTS)
def test_a_kinds_request_goes_out_only_where_the_server_enables_it(
    entry: str, method: str, params: dict[str, Any]
) -> None:
    """M6 design L.4, L.6: a server's connection asks for the kinds it enables, and only
    those; the other entries never stand in for one."""
    others = {"prompts", "resources", "completions", "sampling"} - {entry}
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", CAPS: {}}
    outgoing = request(rpc(method, {**params, "_meta": meta}))
    assert verdict(outgoing, target=enabling(entry)) == Verdict(True, kind=f"request {method}")
    for target in (TARGET, enabling(*others)):
        assert verdict(outgoing, target=target) == Verdict(
            False, "request method not allowed", f"request {method}"
        )


@pytest.mark.parametrize(
    ("entry", "method"),
    [
        ("prompts", "prompts/get"),
        ("resources", "resources/read"),
        ("completions", "completion/complete"),
    ],
)
@pytest.mark.parametrize("extra", ["requestState", "inputResponses", "task", "other"])
def test_a_get_read_or_complete_carries_only_its_own_params(
    entry: str, method: str, extra: str
) -> None:
    """No requestState or inputResponses retry, nor anything else, goes out on them (L.6)."""
    outgoing = request(rpc(method, {extra: "x"}))
    assert verdict(outgoing, target=enabling(entry)) == Verdict(
        False, f"{method} carries more than its own params", f"request {method}"
    )


def test_each_kinds_params() -> None:
    assert {
        "prompts/get": frozenset({"name", "arguments", "_meta"}),
        "resources/read": frozenset({"uri", "_meta"}),
        "completion/complete": frozenset({"ref", "argument", "context", "_meta"}),
    } == egressrules.KIND_PARAMS


def test_a_kinds_request_still_refuses_a_declared_capability() -> None:
    outgoing = request(rpc("prompts/get", {"name": "a", "_meta": {CAPS: {"sampling": {}}}}))
    assert verdict(outgoing, target=enabling("prompts")) == Verdict(
        False, "a client capability is declared", "request prompts/get"
    )


def test_the_requests_for_each_enable_list() -> None:
    assert egressrules.requests_for(frozenset()) == egressrules.REQUESTS
    assert egressrules.requests_for(frozenset({"prompts", "sampling"})) == (
        egressrules.REQUESTS | {"prompts/list", "prompts/get"}
    )
    assert egressrules.requests_for(frozenset({"completions"})) == (
        egressrules.REQUESTS | {"completion/complete"}
    )
    assert egressrules.requests_for(frozenset({"resources", "prompts"})) == (
        egressrules.REQUESTS
        | {"prompts/list", "prompts/get", "resources/list", "resources/templates/list"}
        | {"resources/read"}
    )


@pytest.mark.parametrize("method", sorted(egressrules.NOTIFICATIONS))
def test_allowed_notifications(method: str) -> None:
    assert verdict(request(rpc(method, {"requestId": 1}, id=None))) == Verdict(
        True, kind=f"notification {method}"
    )


@pytest.mark.parametrize("method", ["notifications/roots/list_changed", "notifications/progress"])
def test_other_notifications_are_refused(method: str) -> None:
    assert verdict(request(rpc(method, {}, id=None))) == Verdict(
        False, "notification not allowed", f"notification {method}"
    )


def test_notification_params_and_meta_are_checked() -> None:
    bad_params = request(rpc("notifications/cancelled", None, id=None) | {"params": [1]})
    assert verdict(bad_params) == Verdict(
        False, "params is not an object", "notification notifications/cancelled"
    )
    bad_meta = request(
        rpc("notifications/initialized", {"_meta": {"traceparent": "00-x"}}, id=None)
    )
    assert verdict(bad_meta) == Verdict(
        False, "_meta key not allowed", "notification notifications/initialized"
    )


@pytest.mark.parametrize(
    "response",
    [
        {"jsonrpc": "2.0", "id": 7, "error": {"code": -32601, "message": "Method not found"}},
        {"jsonrpc": "2.0", "id": "x", "result": {}},  # the answer to a legacy ping
    ],
)
def test_allowed_responses(response: dict[str, Any]) -> None:
    assert verdict(request(response)) == Verdict(True, kind="response")


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        ({"jsonrpc": "2.0", "id": 7, "result": {"action": "accept"}}, "a response with a result"),
        ({"jsonrpc": "2.0", "id": 7, "result": {"roots": []}}, "a response with a result"),
        (
            {"jsonrpc": "2.0", "id": 7, "result": {}, "error": {"code": 1}},
            "a response with a result",
        ),
        ({"jsonrpc": "2.0", "id": 7}, "a response with a result"),
        ({"jsonrpc": "2.0", "result": {}}, "response without an id"),
    ],
)
def test_other_responses_are_refused(response: dict[str, Any], reason: str) -> None:
    assert verdict(request(response)) == Verdict(False, reason, "response")


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"{", "body is not strict JSON"),
        (b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}', "body is not strict JSON"),
        (b"[]", "body is not one JSON-RPC message"),
        (json.dumps([rpc("ping")]).encode(), "body is not one JSON-RPC message"),
        (json.dumps({"id": 1, "method": "ping"}).encode(), "body is not one JSON-RPC message"),
        (
            json.dumps({"jsonrpc": "1.0", "id": 1, "method": "ping"}).encode(),
            "body is not one JSON-RPC message",
        ),
        (json.dumps({"jsonrpc": "2.0", "id": 1, "method": 5}).encode(), "method is not a string"),
        (b"", "body is not strict JSON"),
    ],
)
def test_malformed_bodies(body: bytes, reason: str) -> None:
    assert verdict(request(body)) == Verdict(False, reason)


def test_the_body_size_cap() -> None:
    assert egressrules.MAX_BODY_BYTES == 16 * 2**20
    big = json.dumps(rpc("ping", {"_meta": {"progressToken": "x" * (16 * 2**20)}})).encode()
    assert verdict(request(big)) == Verdict(False, "body is not strict JSON")


# --- _meta and capabilities ------------------------------------------------------------------


def test_allowed_meta_keys() -> None:
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        CAPS: {},
        "io.modelcontextprotocol/clientInfo": {"name": "zoeymcp-gateway", "version": "1"},
        "progressToken": 3,
    }
    assert verdict(request(rpc("tools/list", {"_meta": meta}))).allowed


@pytest.mark.parametrize("key", ["traceparent", "io.modelcontextprotocol/logLevel", "x"])
def test_other_meta_keys_are_refused(key: str) -> None:
    assert verdict(request(rpc("tools/list", {"_meta": {key: "v"}}))) == Verdict(
        False, "_meta key not allowed", "request tools/list"
    )


def test_meta_must_be_an_object() -> None:
    assert verdict(request(rpc("tools/list", {"_meta": []}))) == Verdict(
        False, "_meta is not an object", "request tools/list"
    )
    assert verdict(request(rpc("tools/list", []))) == Verdict(  # type: ignore[arg-type]
        False, "params is not an object", "request tools/list"
    )


@pytest.mark.parametrize(
    "declared",
    [
        {"sampling": {}},
        {"elicitation": {"form": {}}},
        {"roots": {}},
        {"tasks": {}},
        {"experimental": {}},
        {"x": {}},
        [],
        None,
    ],
)
def test_any_declared_capability_is_refused(declared: Any) -> None:
    in_meta = request(rpc("server/discover", {"_meta": {CAPS: declared}}))
    assert verdict(in_meta) == Verdict(
        False, "a client capability is declared", "request server/discover"
    )
    in_initialize = request(
        rpc("initialize", {"capabilities": declared, "protocolVersion": "2025-06-18"})
    )
    assert verdict(in_initialize) == Verdict(
        False, "a client capability is declared", "request initialize"
    )


def test_initialize_with_no_capabilities() -> None:
    assert verdict(
        request(rpc("initialize", {"capabilities": {}, "protocolVersion": "2025-06-18"}))
    ).allowed
    assert verdict(request(rpc("initialize", {"protocolVersion": "2025-06-18"}))).allowed


# --- tools/call ------------------------------------------------------------------------------


def test_a_registered_call_goes_out_once() -> None:
    arguments = {"text": "hi", "n": 1.5}
    registry = registered("echo", arguments)
    assert verdict(request(call("echo", arguments)), registry) == Verdict(
        True, kind="request tools/call"
    )
    assert len(registry) == 0
    assert verdict(request(call("echo", arguments)), registry) == Verdict(
        False, "tools/call not registered by the pipeline", "request tools/call"
    )


def test_the_arguments_are_matched_by_canonical_digest() -> None:
    registry = registered("echo", {"b": 1, "a": "x"})
    body = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"echo","arguments":{"a":"x","b":1}}}'
    )
    assert verdict(request(body), registry).allowed


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("echo", {"text": "hi!"}),  # other arguments
        ("echo", {"text": "hi", "extra": 1}),
        ("other", {"text": "hi"}),  # another tool
        ("echo", {"text": "hi", "n": 1}),
    ],
)
def test_an_unregistered_call_is_refused(name: str, arguments: dict[str, Any]) -> None:
    registry = registered("echo", {"text": "hi", "n": 1.0})
    assert verdict(request(call(name, arguments)), registry) == Verdict(
        False, "tools/call not registered by the pipeline", "request tools/call"
    )
    assert len(registry) == 1  # nothing consumed


def test_missing_arguments_mean_an_empty_object() -> None:
    registry = registered("ping_tool", {})
    assert verdict(request(rpc("tools/call", {"name": "ping_tool"})), registry).allowed


@pytest.mark.parametrize(
    "extra", [{"requestState": "opaque"}, {"inputResponses": {}}, {"task": {}}]
)
def test_a_retry_or_extra_param_is_refused(extra: dict[str, Any]) -> None:
    registry = registered("echo", {"text": "hi"})
    assert verdict(request(call("echo", {"text": "hi"}, **extra)), registry) == Verdict(
        False, "tools/call carries more than name and arguments", "request tools/call"
    )
    assert len(registry) == 1


@pytest.mark.parametrize(
    "params", [{"name": 5, "arguments": {}}, {"name": "echo", "arguments": [1]}]
)
def test_malformed_calls(params: dict[str, Any]) -> None:
    assert verdict(request(rpc("tools/call", params))) == Verdict(
        False, "tools/call name or arguments malformed", "request tools/call"
    )


def test_a_call_with_bad_meta_is_refused_before_consuming() -> None:
    registry = registered("echo", {"text": "hi"})
    body = call("echo", {"text": "hi"}, _meta={"traceparent": "00-x"})
    assert verdict(request(body), registry) == Verdict(
        False, "_meta key not allowed", "request tools/call"
    )
    assert len(registry) == 1


# --- the registry ----------------------------------------------------------------------------


def test_registrations_count() -> None:
    registry = CallRegistry()
    registry.register("a", "d1")
    registry.register("a", "d1")
    registry.register("b", "d2")
    assert len(registry) == 3
    assert registry.consume("a", "d1")
    assert registry.consume("a", "d1")
    assert not registry.consume("a", "d1")
    assert len(registry) == 1


def test_withdraw() -> None:
    registry = CallRegistry()
    registry.register("a", "d1")
    registry.withdraw("a", "d1")
    registry.withdraw("a", "d1")
    assert len(registry) == 0
    assert not registry.consume("a", "d1")
    assert not registry._pending  # nothing left behind, even for refused lookups
