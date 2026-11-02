"""The vault's envelope reader (M8 design B.2; O.3 ``test_envelope.py``).

Each rule E1-E19 refuses with its reason and pointer and lets its honest neighbour through; E12's
era rows (the version header against ``_meta``, both headers required at 2026-07-28, absent
allowed at earlier eras); NFKC and case variants of a held name; hostile strings kept as sent; and
the round-trip property: every admitted envelope's canonical form re-admits to itself.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Sequence
from typing import Any, get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.unit.plainid import plain_id
from zoeymcp.bridge import framing
from zoeymcp.common import canonical, envelope, mcpwire
from zoeymcp.common.canonical import MAX_SAFE_INTEGER
from zoeymcp.common.envelope import (
    MAX_HELD_BODY,
    Admitted,
    Cancel,
    Envelope,
    Held,
    Marker,
    Pass,
    Refuse,
    admit,
    marker,
)
from zoeymcp.common.policy import schema
from zoeymcp.gateway import access
from zoeymcp.vault import app

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
# The route holds send_mail on this path and delete_all on another of its servers' paths.
TOOLS = frozenset({"send_mail"})
LISTED = frozenset({"send_mail", "read_mail"})
NAMES = frozenset({"send_mail", "delete_all"})
JSON_TYPE = ("content-type", "application/json")
MARK = "v1; ref=0123456789abcdef; client=assistant; wait=block; epoch=0123456789ab"
MARKED = Marker("0123456789abcdef", "assistant", "block", "0123456789ab", None)


def call(name: Any = "send_mail", **extra: Any) -> dict[str, Any]:
    """A ``tools/call``; ``extra`` replaces or adds top-level members, ``params`` included."""
    message: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": name, "arguments": {"to": "a@example.org"}},
    }
    return {**message, **extra}


def params(**members: Any) -> dict[str, Any]:
    return {"name": "send_mail", **members}


def modern(name: str = "send_mail", **members: Any) -> dict[str, Any]:
    """A modern ``tools/call``: its ``_meta`` carries the protocol version."""
    meta = {mcpwire.PROTOCOL_VERSION_META: MODERN}
    return call(params={"name": name, "arguments": {}, "_meta": meta, **members})


def request(method: str, **extra: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": method, **extra}


def encoded(message: Any) -> bytes:
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode()


def read(
    sent: Any,
    headers: Sequence[tuple[str, str]] = (JSON_TYPE,),
    query: str = "",
    *,
    tools: frozenset[str] = TOOLS,
    names: frozenset[str] = NAMES,
    listed: frozenset[str] = LISTED,
    held_ids: Callable[[str | int], bool] = lambda _id: False,
    used_refs: Callable[[str], bool] = lambda _ref: False,
) -> Admitted:
    """``sent`` is a message to encode, or the body's bytes as they are."""
    body = sent if isinstance(sent, bytes) else encoded(sent)
    return admit(body, headers, query, tools, listed, names, held_ids, used_refs)


def held(sent: Any = None, *headers: tuple[str, str], **options: Any) -> Envelope:
    found = read(call() if sent is None else sent, (JSON_TYPE, *headers), **options)
    assert isinstance(found, Held), found
    return found.envelope


def routing(name: str = "send_mail", method: str = "tools/call") -> list[tuple[str, str]]:
    return [("mcp-protocol-version", MODERN), ("mcp-method", method), ("mcp-name", name)]


def sentinel(text: str) -> str:
    return "=?base64?" + base64.b64encode(text.encode()).decode("ascii") + "?="


# --- the constants ------------------------------------------------------------------------------


def test_the_constants() -> None:
    assert {"tools/call"} == envelope.HELD_METHODS
    assert MAX_HELD_BODY == 1024 * 1024
    assert MAX_HELD_BODY < app.MAX_REQUEST_BYTES  # B.1: below the vault's own cap
    assert envelope.MODERN_VERSION == access.MODERN_VERSION
    assert (envelope.MODERN_VERSION,) == framing.MODERN_VERSIONS
    assert mcpwire.HEADERS | {"x-zoeymcp-held", "x-zoeymcp-gateway"} == envelope.ADMITTED_HEADERS
    assert envelope.GATEWAY_KEY_HEADER == app.GATEWAY_HEADER
    assert {"name", "arguments", "_meta"} == envelope.CALL_MEMBERS


def test_the_grammars_are_the_policys() -> None:
    """E18's tool name is the policy's ``ToolName``; the marker's client a policy ``Name``."""
    tool_name = get_args(schema.ToolName)[1].pattern
    assert tool_name == "^" + envelope._TOOL_NAME.pattern + "$"
    assert schema.NAME_PATTERN == r"^[a-z0-9][a-z0-9_-]{0,62}$"
    assert schema.NAME_PATTERN[1:-1] in envelope._MARKER.pattern
    assert envelope._TOOL_NAME.pattern in envelope._MARKER.pattern


@pytest.mark.parametrize(
    ("reason", "status"),
    [("content_type", 415), ("too_large", 413), ("ref_reused", 409), ("json", 400)],
)
def test_each_refusal_has_its_status(reason: envelope.Reason, status: int) -> None:
    assert Refuse(reason).status == status


# --- what passes --------------------------------------------------------------------------------


def test_a_held_call() -> None:
    found = read(call())
    assert found == Held(Envelope(7, "send_mail", {"to": "a@example.org"}, None), None)


def test_a_held_call_without_arguments_has_none() -> None:
    assert held(call(params={"name": "send_mail"})).arguments == {}


def test_a_held_call_keeps_its_meta() -> None:
    meta = {"progressToken": "p-1", mcpwire.PROTOCOL_VERSION_META: LEGACY}
    sent = call(params=params(_meta=meta))
    assert held(sent, ("mcp-protocol-version", LEGACY)).meta == meta
    assert held(call(params=params(_meta={}))).meta == {}


def test_a_marked_held_call_carries_its_marker() -> None:
    found = read(call(), [JSON_TYPE, ("X-ZoeyMCP-Held", MARK)])
    assert isinstance(found, Held)
    assert found.marker == MARKED


@pytest.mark.parametrize(
    "sent",
    [
        request("tools/list"),
        request("initialize", params={"protocolVersion": LEGACY}),
        request("prompts/get", params={"name": "p"}),
        request("completion/complete"),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}},
        {"jsonrpc": "2.0", "id": 4, "error": {"code": -1, "message": "no"}},
        {"jsonrpc": "2.0", "id": "s", "result": {}},
        # An unheld tool on a held route's path: E10 isn't read for it.
        call(params={"name": "read_mail", "arguments": [], "task": {}}),
        # Held on another server's path of the route, and listed here: not held here.
        call("delete_all"),
    ],
    ids=plain_id,
)
def test_what_the_gateway_sends_beside_a_held_call_passes(sent: dict[str, Any]) -> None:
    listed = LISTED | {"delete_all"}
    assert read(sent, listed=listed) == Pass(False)
    assert read(sent, [JSON_TYPE, ("x-zoeymcp-held", MARK)], listed=listed) == Pass(True)


def test_the_canonical_form_is_the_forwarded_bytes() -> None:
    found = Envelope("r-1", "send_mail", {"b": [1.5, None], "a": "\u00e9"}, {"progressToken": 2})
    assert found.canonical() == (
        b'{"id":"r-1","jsonrpc":"2.0","method":"tools/call","params":{"_meta":'
        b'{"progressToken":2},"arguments":{"a":"\xc3\xa9","b":[1.5,null]},"name":"send_mail"}}'
    )
    unmeta = Envelope(1, "send_mail", {}, None).canonical()
    assert unmeta == (
        b'{"id":1,"jsonrpc":"2.0","method":"tools/call",'
        b'"params":{"arguments":{},"name":"send_mail"}}'
    )


def test_an_envelope_has_no_repr_of_its_arguments() -> None:
    shown = repr(Envelope(1, "send_mail", {"secret": "hunter2"}, None))
    assert "hunter2" not in shown
    assert "send_mail" not in shown


# --- E1, E2, E16, E17: around the body ----------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "application/json",
        "Application/JSON",
        "application/json;charset=utf-8",
        "application/json; charset=UTF-8",
        "application/json \t; \tcharset=utf-8",
    ],
)
def test_the_json_content_types(value: str) -> None:
    assert isinstance(read(call(), [("Content-Type", value)]), Held)


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("content-type", "text/plain")],
        [("content-type", "application/json; charset=latin-1")],
        [("content-type", 'application/json; charset="utf-8"')],
        [("content-type", "application/json; charset=utf-8; x=1")],
        [("content-type", "application/jsonx")],
        [("content-type", " application/json")],
        [JSON_TYPE, JSON_TYPE],
    ],
    ids=plain_id,
)
def test_e1_content_type(headers: list[tuple[str, str]]) -> None:
    assert read(call(), headers) == Refuse("content_type")


@pytest.mark.parametrize("value", ["gzip", "identity", ""])
def test_e2_any_content_encoding(value: str) -> None:
    assert read(call(), [JSON_TYPE, ("Content-Encoding", value)]) == Refuse("content_encoding")


@pytest.mark.parametrize(
    "name",
    [
        "authorization",
        "Idempotency-Key",
        "prefer",
        "x-http-method-override",
        "cookie",
        "x-zoeymcp-egress",
        "x-zoeymcp-approval",
        "transfer-encoding",
        "cache-control",
    ],
)
def test_e16_a_header_outside_the_gateways_allowlist(name: str) -> None:
    assert read(call(), [JSON_TYPE, (name, "1")]) == Refuse("header_extra")
    assert read(request("tools/list"), [JSON_TYPE, (name, "1")]) == Refuse("header_extra")


def test_e16_every_header_the_gateway_sends_is_admitted() -> None:
    headers = [
        JSON_TYPE,
        ("Host", "vault"),
        ("Accept", "application/json, text/event-stream"),
        ("Accept-Encoding", "gzip"),
        ("Connection", "keep-alive"),
        ("Content-Length", "100"),
        ("User-Agent", "python-httpx"),
        ("MCP-Protocol-Version", LEGACY),
        ("Mcp-Session-Id", "s-1"),
        ("Mcp-Name", "send_mail"),
        ("Last-Event-ID", "e-1"),
        ("X-ZoeyMCP-Gateway", "key"),
        ("X-ZoeyMCP-Held", MARK),
    ]
    assert {name.lower() for name, _value in headers} == envelope.ADMITTED_HEADERS - {"mcp-method"}
    assert read(call(), headers) == Held(held(), MARKED)
    sent = [JSON_TYPE, ("Mcp-Param-Region", "eu")]
    assert read(call("read_mail", params={"name": "read_mail"}), sent) == Pass(False)


@pytest.mark.parametrize("query", ["a=1", "token=x", "="])
def test_e17_any_query_string(query: str) -> None:
    assert read(call(), query=query) == Refuse("query")
    assert read(request("tools/list"), query=query) == Refuse("query")


def test_the_header_rules_come_first() -> None:
    """Nothing in the body is read for a request refused around it."""
    assert read(b"\xff", [("content-type", "text/plain")]) == Refuse("content_type")
    assert read(b"\xff", [JSON_TYPE, ("content-encoding", "gzip")]) == Refuse("content_encoding")
    assert read(b"\xff", [JSON_TYPE, ("prefer", "x")]) == Refuse("header_extra")
    assert read(b"\xff", query="a") == Refuse("query")
    assert read(b"\xff", [JSON_TYPE, ("x-zoeymcp-held", "v1")]) == Refuse("marker")


# --- E3 to E5: one strict JSON object -----------------------------------------------------------


def padded(size: int) -> bytes:
    """A held call of exactly ``size`` bytes."""
    empty = encoded(call(params=params(arguments={"pad": ""})))
    return encoded(call(params=params(arguments={"pad": "x" * (size - len(empty))})))


def test_e3_the_size_cap() -> None:
    assert len(padded(MAX_HELD_BODY)) == MAX_HELD_BODY
    assert isinstance(read(padded(MAX_HELD_BODY)), Held)
    assert read(padded(MAX_HELD_BODY + 1)) == Refuse("too_large")
    assert Refuse("too_large").status == 413


@pytest.mark.parametrize(
    "body",
    [
        b"\xef\xbb\xbf" + encoded(call()),
        encoded(call(params=params(arguments={"a": "x"}))).replace(b'"x"', b'"\xff"'),
        encoded(call(params=params(arguments={"a": "x"}))).replace(b'"x"', b'"\xed\xa0\x80"'),
    ],
    ids=["bom", "invalid", "encoded_surrogate"],
)
def test_e3_encoding(body: bytes) -> None:
    assert read(body) == Refuse("encoding")


@pytest.mark.parametrize(
    "body",
    [
        b'{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"tools/list"}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_mail",'
        b'"arguments":{"a":1,"a":2}}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":NaN}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":-Infinity}}',
        b'{"jsonrpc":"2.0","id":9007199254740992,"method":"tools/list"}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":"\\ud800"}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":'
        + b"[" * 63
        + b"]" * 63
        + b"}}",
        # Not JSON number tokens at all (E9's examples, refused before E9 can read them).
        b'{"jsonrpc":"2.0","id":01,"method":"tools/list"}',
        b'{"jsonrpc":"2.0","id":+1,"method":"tools/list"}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list"} x',
        b"",
    ],
    ids=plain_id,
)
def test_e4_strict_parse(body: bytes) -> None:
    assert read(body) == Refuse("json")


def test_e4_depth_64_is_kept() -> None:
    deep = b"[" * 62 + b"]" * 62
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":' + deep + b"}}"
    assert read(body) == Pass(False)


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (encoded([call()]), "batch"),
        (b"[]", "batch"),
        (b"1", "not_object"),
        (b'"tools/call"', "not_object"),
        (b"null", "not_object"),
        (b"true", "not_object"),
    ],
    ids=plain_id,
)
def test_e5_one_object(body: bytes, reason: envelope.Reason) -> None:
    assert read(body) == Refuse(reason)


# --- E6 to E8: the message ----------------------------------------------------------------------


@pytest.mark.parametrize("version", [None, "1.0", 2.0, "2.0 "])
def test_e6_jsonrpc(version: Any) -> None:
    sent = call(jsonrpc=version)
    if version is None:
        del sent["jsonrpc"]
    assert read(sent) == Refuse("jsonrpc", "/jsonrpc")
    assert read({**sent, "method": "tools/list"}) == Refuse("jsonrpc", "/jsonrpc")


@pytest.mark.parametrize(
    "method",
    [
        None,
        3,
        "",
        "tools/delete",
        "sampling/createMessage",
        "notifications/progress",
        "tools/list ",
        "tools/call/",
        "tool\u017f/call",  # case-folds to tools/call, but isn't in the method grammar
        "x" * 129,
    ],
    ids=plain_id,
)
def test_e6_method_form(method: Any) -> None:
    assert read(call(method=method)) == Refuse("method_form", "/method")


@pytest.mark.parametrize(
    "sent",
    [
        # A cancel shaped as a request, naming a held request: refused, not consumed.
        request("notifications/cancelled", params={"requestId": 9}),
        request("notifications/initialized"),
        {"jsonrpc": "2.0", "method": "tools/list"},
        {"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": LEGACY}},
        {"jsonrpc": "2.0", "method": "prompts/get", "params": {"name": "p"}},
    ],
    ids=plain_id,
)
def test_e6_a_request_has_an_id_and_a_notification_none(sent: dict[str, Any]) -> None:
    assert read(sent, held_ids=lambda _id: True) == Refuse("method_form", "/method")


@pytest.mark.parametrize(
    "sent",
    [
        {"jsonrpc": "2.0", "result": {}},
        {"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
        {"jsonrpc": "2.0", "id": 1, "result": []},
        {"jsonrpc": "2.0", "id": 1, "result": None},
        {"jsonrpc": "2.0", "id": 1, "error": {}, "result": {}},
        {"jsonrpc": "2.0", "id": 1},
        {"jsonrpc": "2.0", "error": {"code": 1}},
    ],
    ids=plain_id,
)
def test_e6_only_the_two_responses_the_gateway_sends(sent: dict[str, Any]) -> None:
    assert read(sent) == Refuse("method_form")


@pytest.mark.parametrize("method", ["Tools/call", "TOOLS/CALL", "tools/Call"])
def test_e7_method_case(method: str) -> None:
    assert read(call(method=method)) == Refuse("method_case", "/method")


@pytest.mark.parametrize(
    "value",
    [None, True, False, 1.5, 1.0, [1], {"a": 1}, "x" * 129, "caf\u00e9", "a\nb", "a\u007fb"],
    ids=plain_id,
)
def test_e8_a_held_methods_id(value: Any) -> None:
    assert read(call(id=value)) == Refuse("id", "/id")
    assert read(call("read_mail", id=value)) == Refuse("id", "/id")


def test_e8_a_held_method_needs_an_id() -> None:
    sent = call()
    del sent["id"]
    assert read(sent) == Refuse("id", "/id")
    # Not a held method: a notification has none.
    assert read({"jsonrpc": "2.0", "method": "notifications/initialized"}) == Pass(False)


@pytest.mark.parametrize(
    "value", [0, -1, MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER, "", "x" * 128, " ~!", "r-1"]
)
def test_e8_the_ids_a_held_call_keeps(value: str | int) -> None:
    assert held(call(id=value)).id == value


# --- E9 to E11: a held call's numbers, params and _meta -----------------------------------------


def test_e9_e11_and_e13_read_a_held_call_only() -> None:
    unheld = encoded(call(params={"name": "read_mail", "arguments": {"n": 0}, "_meta": {"x": 1}}))
    headers = [JSON_TYPE, ("mcp-param-region", "eu")]
    assert read(unheld.replace(b'"n":0', b'"n":-0'), headers) == Pass(False)
    listing = encoded(request("tools/list", params={"cursor": 0}))
    assert read(listing.replace(b'"cursor":0', b'"cursor":1e5')) == Pass(False)


@pytest.mark.parametrize(
    ("token", "pointer"),
    [
        ("-0", "/params/arguments/n"),
        ("1.50", "/params/arguments/n"),
        ("1e5", "/params/arguments/n"),
        ("1E5", "/params/arguments/n"),
        ("1.0e1", "/params/arguments/n"),
        ("100000000000000000000.0", "/params/arguments/n"),
        ("0.10000000000000000001", "/params/arguments/n"),
    ],
)
def test_e9_a_number_that_doesnt_round_trip(token: str, pointer: str) -> None:
    body = encoded(call(params=params(arguments={"n": 0}))).replace(
        b'"n":0', f'"n":{token}'.encode()
    )
    assert read(body) == Refuse("number", pointer)


@pytest.mark.parametrize("token", ["0", "-1", "1.5", "-0.0", "1e+16", "5e-324", "0.1", "1.0"])
def test_e9_the_numbers_that_round_trip(token: str) -> None:
    body = encoded(call(params=params(arguments={"n": 0}))).replace(
        b'"n":0', f'"n":{token}'.encode()
    )
    assert held(body).arguments == {"n": json.loads(token)}


def test_e9_points_at_the_first_number_in_the_body() -> None:
    arguments = {"a/b": [1, 2, {"~c": 0}], "z": 0}
    body = encoded(call(params=params(arguments=arguments)))
    first = body.replace(b'"~c":0', b'"~c":-0').replace(b'"z":0', b'"z":1E1')
    assert read(first) == Refuse("number", "/params/arguments/a~1b/2/~0c")
    second = body.replace(b"[1,2", b"[1,2.50")
    assert read(second) == Refuse("number", "/params/arguments/a~1b/1")
    meta = encoded(call(params=params(_meta={"progressToken": 0})))
    assert read(meta.replace(b":0}", b":-0}")) == Refuse("number", "/params/_meta/progressToken")


def test_e9_reads_the_whole_body() -> None:
    assert read(encoded(call(id=0)).replace(b'"id":0', b'"id":-0')) == Refuse("number", "/id")


@pytest.mark.parametrize(
    ("members", "pointer"),
    [
        ({"task": {"ttl": 1}}, "/params/task"),
        ({"arguments": {}, "a/b": 1}, "/params/a~1b"),
        ({"arguments": []}, "/params/arguments"),
        ({"arguments": None}, "/params/arguments"),
        ({"arguments": "{}"}, "/params/arguments"),
    ],
    ids=plain_id,
)
def test_e10_params(members: dict[str, Any], pointer: str) -> None:
    assert read(call(params=params(**members))) == Refuse("params", pointer)


@pytest.mark.parametrize(
    ("meta", "pointer"),
    [
        ([], "/params/_meta"),
        (None, "/params/_meta"),
        ("x", "/params/_meta"),
        (
            {"progressToken": 1, "io.modelcontextprotocol/logLevel": "info"},
            "/params/_meta/io.modelcontextprotocol~1logLevel",
        ),
        ({"x": 1}, "/params/_meta/x"),
    ],
    ids=plain_id,
)
def test_e11_meta(meta: Any, pointer: str) -> None:
    assert read(call(params=params(_meta=meta))) == Refuse("meta", pointer)


def test_e11_every_meta_key_the_gateway_sends() -> None:
    meta: dict[str, Any] = {key: {} for key in mcpwire.META_KEYS} | {
        mcpwire.PROTOCOL_VERSION_META: MODERN
    }
    found = held(call(params=params(_meta=meta)), *routing())
    assert found.meta == meta


# --- E12: the routing headers -------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("mcp-protocol-version", LEGACY)],
        [("mcp-protocol-version", "2025-06-18"), ("mcp-name", "send_mail")],
        [("mcp-name", sentinel("send_mail"))],
        [("mcp-method", "tools/call")],
        [("mcp-protocol-version", LEGACY), ("mcp-method", "tools/call"), ("mcp-name", "send_mail")],
    ],
    ids=plain_id,
)
def test_e12_earlier_eras_may_leave_them_out(headers: list[tuple[str, str]]) -> None:
    assert isinstance(read(call(), [JSON_TYPE, *headers]), Held)


@pytest.mark.parametrize(
    "headers",
    [
        [("mcp-protocol-version", LEGACY), ("mcp-protocol-version", LEGACY)],
        [("mcp-method", "tools/call"), ("Mcp-Method", "tools/call")],
        [("mcp-name", "send_mail"), ("mcp-name", "send_mail")],
        [("mcp-name", "read_mail")],
        [("mcp-name", "=?base64?c2VuZF9tYWls=?=")],  # not canonical Base64
        [("mcp-method", "tools/list")],
        [("mcp-method", "Tools/call")],
    ],
    ids=plain_id,
)
def test_e12_earlier_eras_check_what_is_sent(headers: list[tuple[str, str]]) -> None:
    assert read(call(), [JSON_TYPE, *headers]) == Refuse("header_mismatch")


def test_e12_a_body_carrying_its_version_needs_the_header() -> None:
    meta = params(_meta={mcpwire.PROTOCOL_VERSION_META: LEGACY})
    assert isinstance(read(call(params=meta), [JSON_TYPE, ("mcp-protocol-version", LEGACY)]), Held)
    for headers in ([], [("mcp-protocol-version", "2025-06-18")], [("mcp-name", "send_mail")]):
        assert read(call(params=meta), [JSON_TYPE, *headers]) == Refuse("header_mismatch")
    odd = params(_meta={mcpwire.PROTOCOL_VERSION_META: 5})
    assert read(call(params=odd), [JSON_TYPE, ("mcp-protocol-version", "5")]) == (
        Refuse("header_mismatch")
    )


def test_e12_the_modern_era_requires_them() -> None:
    assert isinstance(read(modern(), [JSON_TYPE, *routing()]), Held)
    assert isinstance(read(modern(), [JSON_TYPE, *routing(sentinel("send_mail"))]), Held)
    for missing in range(3):
        headers = routing()
        del headers[missing]
        assert read(modern(), [JSON_TYPE, *headers]) == Refuse("header_mismatch"), missing


@pytest.mark.parametrize(
    ("sent", "headers"),
    [
        # The version header against _meta: the body's version needs the header, and equal.
        (modern(), [("mcp-method", "tools/call"), ("mcp-name", "send_mail")]),
        (modern(), [("mcp-protocol-version", LEGACY), ("mcp-method", "tools/call")]),
        # The modern header needs the body's version.
        (call(), routing()),
        (call(params=params(_meta={})), routing()),
        (modern(), [*routing()[:2], ("mcp-name", "read_mail")]),
        (modern(), [*routing()[:2], ("mcp-name", "=?base64?/w==?=")]),
        # A modern body that names nothing to compare.
        (request("tools/list", params=[1]), routing(method="tools/list")),
        (request("tools/list", params=None), routing(method="tools/list")),
    ],
    ids=plain_id,
)
def test_e12_modern_disagreements(sent: dict[str, Any], headers: list[tuple[str, str]]) -> None:
    assert read(sent, [JSON_TYPE, *headers]) == Refuse("header_mismatch")


def test_e12_holds_whatever_the_method() -> None:
    listing = request("tools/list", params={"_meta": {mcpwire.PROTOCOL_VERSION_META: MODERN}})
    headers = [("mcp-protocol-version", MODERN), ("mcp-method", "tools/list")]
    assert read(listing, [JSON_TYPE, *headers]) == Pass(False)
    assert read(listing, [JSON_TYPE, headers[0]]) == Refuse("header_mismatch")
    # Mcp-Name is read only on a method that names something, as the bridge reads it.
    assert read(request("tools/list"), [JSON_TYPE, ("mcp-name", "x")]) == Pass(False)
    prompt = request("prompts/get", params={"name": "p"})
    assert read(prompt, [JSON_TYPE, ("mcp-name", "p")]) == Pass(False)
    assert read(prompt, [JSON_TYPE, ("mcp-name", "q")]) == Refuse("header_mismatch")
    # A sentinel that doesn't decode never equals an absent field.
    unnamed = request("prompts/get", params={})
    assert read(unnamed, [JSON_TYPE, ("mcp-name", "=?base64?aGk?=")]) == Refuse("header_mismatch")
    assert read(request("prompts/get"), [JSON_TYPE, ("mcp-name", "x")]) == (
        Refuse("header_mismatch")
    )


def test_e12_a_response_names_nothing() -> None:
    answer = {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert read(answer, [JSON_TYPE, ("mcp-protocol-version", MODERN)]) == Pass(False)
    assert read(answer, [JSON_TYPE, ("mcp-method", "tools/call")]) == Refuse("header_mismatch")
    assert read(answer, [JSON_TYPE, ("mcp-name", "send_mail")]) == Refuse("header_mismatch")


# --- E13 to E15, E18, E19: a held call's headers and name ---------------------------------------


def test_e13_param_headers_on_a_held_call() -> None:
    assert read(call(), [JSON_TYPE, ("Mcp-Param-Region", "eu")]) == Refuse("param_headers")
    assert read(modern(), [JSON_TYPE, *routing(), ("mcp-param-to", "a")]) == (
        Refuse("param_headers")
    )


@pytest.mark.parametrize(
    "value",
    [
        "v1",
        MARK.upper(),
        MARK.replace("v1", "v2"),
        MARK.replace("0123456789abcdef", "0123456789abcde"),
        MARK.replace("0123456789abcdef", "0123456789ABCDEF"),
        MARK.replace("epoch=0123456789ab", "epoch=0123456789a"),
        MARK.replace("assistant", "Assistant"),
        MARK.replace("assistant", "-a"),
        MARK.replace("assistant", "a" * 64),
        MARK.replace("block", "never"),
        MARK.replace("; ", ";"),
        MARK + "; tool=",
        MARK + "; tool=a b",
        MARK + "; tool=" + "a" * 129,
        MARK + "; other=1",
        MARK + ";",
        " " + MARK,
    ],
    ids=plain_id,
)
def test_e14_a_malformed_marker(value: str) -> None:
    headers = [JSON_TYPE, ("x-zoeymcp-held", value)]
    assert marker(headers) == Refuse("marker")
    assert read(call(), headers) == Refuse("marker")
    assert read(request("tools/list"), headers) == Refuse("marker")


def test_e14_a_marker_sent_twice() -> None:
    headers = [JSON_TYPE, ("x-zoeymcp-held", MARK), ("X-ZoeyMCP-Held", MARK)]
    assert marker(headers) == Refuse("marker")
    assert read(call(), headers) == Refuse("marker")


def test_e14_the_markers_fields() -> None:
    assert marker([JSON_TYPE]) is None
    assert marker([("x-zoeymcp-held", MARK)]) == MARKED
    pending = MARK.replace("block", "pending").replace("assistant", "a" * 63) + "; tool=Send.it-1"
    assert marker([("x-zoeymcp-held", pending)]) == Marker(
        "0123456789abcdef", "a" * 63, "pending", "0123456789ab", "Send.it-1"
    )


@pytest.mark.parametrize(
    "name",
    [
        "SEND_MAIL",
        "Send_Mail",
        " send_mail",
        "send_mail\t",
        "send_mail\u00a0",  # no-break space, which NFKC makes a space
        "\uff53end_mail",  # fullwidth s
        "send_maIl",
        "DELETE_ALL",  # a variant of a name held on another path of the route
        "send_mai\u217c",  # small roman numeral fifty, which NFKC makes an l
    ],
    ids=plain_id,
)
def test_e15_a_variant_of_a_held_name(name: str) -> None:
    listed = LISTED | {name}
    assert read(call(name, params=params(name=name)), listed=listed) == (
        Refuse("name_variant", "/params/name")
    )


def test_e15_reads_this_paths_held_names_too() -> None:
    sent = call(params=params(name="SEND_MAIL"))
    assert read(sent, names=frozenset()) == Refuse("name_variant", "/params/name")


@pytest.mark.parametrize(
    "name",
    [
        "send_\u200bmail",  # zero-width space, which NFKC keeps
        "send_\u00admail",  # soft hyphen, which NFKC keeps too
        "send mail",
        "",
        "a" * 129,
    ],
    ids=plain_id,
)
def test_e18_outside_the_tool_name_grammar(name: str) -> None:
    """Refused even when the vault's policy lists it."""
    sent = call(params=params(name=name))
    assert read(sent, listed=LISTED | {name}) == Refuse("unlisted", "/params/name")


@pytest.mark.parametrize("name", ["delete_all", "unknown", "Read_mail", 5, None], ids=plain_id)
def test_e18_unlisted(name: Any) -> None:
    """``delete_all`` is held on another path of the route, and not listed on this one."""
    assert read(call(params=params(name=name)), names=frozenset({"delete_all"})) == (
        Refuse("unlisted", "/params/name")
    )


@pytest.mark.parametrize("sent_params", [[1], None, "send_mail"], ids=plain_id)
def test_e18_a_call_without_a_name(sent_params: Any) -> None:
    assert read(call(params=sent_params)) == Refuse("unlisted", "/params/name")
    no_params = call()
    del no_params["params"]
    assert read(no_params) == Refuse("unlisted", "/params/name")


def test_e18_a_held_name_is_listed_too() -> None:
    """Skew fails closed (Z5): a held tool the vault's policy doesn't list is refused."""
    assert read(call(), listed=frozenset({"read_mail"})) == Refuse("unlisted", "/params/name")


def test_e19_a_reused_ref() -> None:
    asked: list[str] = []

    def used(ref: str) -> bool:
        asked.append(ref)
        return True

    headers = [JSON_TYPE, ("x-zoeymcp-held", MARK)]
    assert read(call(), headers, used_refs=used) == Refuse("ref_reused")
    assert asked == ["0123456789abcdef"]
    assert read(call(), used_refs=used) == Held(held(), None)
    assert asked == ["0123456789abcdef"]
    found = read(call(), headers, used_refs=lambda ref: ref != MARKED.ref)
    assert found == Held(held(), MARKED)


# --- a legacy cancel ----------------------------------------------------------------------------


def cancel(request_id: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": request_id, "reason": "gone"},
    }


@pytest.mark.parametrize("request_id", [3, "r-3"])
def test_a_cancel_of_a_held_request(request_id: str | int) -> None:
    asked: list[str | int] = []

    def holds(found: str | int) -> bool:
        asked.append(found)
        return True

    headers = [JSON_TYPE, ("mcp-protocol-version", LEGACY), ("mcp-session-id", "s")]
    assert read(cancel(request_id), headers, held_ids=holds) == Cancel(request_id)
    assert asked == [request_id]


def test_a_cancel_naming_no_held_request_passes() -> None:
    asked: list[str | int] = []

    def holds(found: str | int) -> bool:
        asked.append(found)
        return False

    assert read(cancel(3), held_ids=holds) == Pass(False)
    assert asked == [3]
    for request_id in (True, None, 1.5, [3]):
        assert read(cancel(request_id), held_ids=holds) == Pass(False)
    assert asked == [3]
    unparamed = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": [3]}
    assert read(unparamed, held_ids=holds) == Pass(False)
    # Only a cancel is one: another notification naming a held id passes.
    other = {**cancel(3), "method": "notifications/initialized"}
    assert read(other, held_ids=lambda _id: True) == Pass(False)


def test_a_cancel_is_read_by_the_rules_first() -> None:
    sent = cancel(3)
    assert read(sent, [JSON_TYPE, ("prefer", "x")], held_ids=lambda _id: True) == (
        Refuse("header_extra")
    )
    sent["jsonrpc"] = "1.0"
    assert read(sent, held_ids=lambda _id: True) == Refuse("jsonrpc", "/jsonrpc")


# --- hostile strings and the round trip ---------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "\u202eexe.txt",
        "line\nbreak",
        "\u0000",
        "\u200b",
        "\U0001f600",
        "Approve? [yes]",
        "pending 0123456789abcdef",
        "</pre><b>x</b>",
    ],
    ids=plain_id,
)
def test_hostile_argument_strings_are_kept_as_sent(value: str) -> None:
    """The reader refuses ambiguity, not content: what a hostile string shows is the text
    rules' to judge (B.3)."""
    found = held(call(params=params(arguments={value: value, "list": [value]})))
    assert found.arguments == {value: value, "list": [value]}


_json = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(alphabet=st.characters(codec="utf-8"), max_size=8),
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(st.text(alphabet=st.characters(codec="utf-8"), max_size=6), children)
    ),
    max_leaves=12,
)
_ids = st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER) | st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=128
)
_metas = st.none() | st.dictionaries(st.sampled_from(sorted(mcpwire.META_KEYS)), _json)
_envelopes = st.builds(
    Envelope,
    _ids,
    st.sampled_from(sorted(TOOLS)),
    st.dictionaries(st.text(alphabet=st.characters(codec="utf-8"), max_size=6), _json, max_size=5),
    _metas,
)


@settings(max_examples=100, deadline=None)
@given(_envelopes)
def test_every_admitted_envelope_re_admits_to_itself(sent: Envelope) -> None:
    # A _meta protocol version makes the call modern-shaped, so its headers go with it.
    version = (sent.meta or {}).get(mcpwire.PROTOCOL_VERSION_META)
    headers = [JSON_TYPE]
    if version is not None:
        if not isinstance(version, str):
            return
        name = sentinel(sent.name)
        headers += [("mcp-protocol-version", version), ("mcp-method", "tools/call")]
        headers += [("mcp-name", name)]
    found = read(sent.canonical(), headers)
    assert found == Held(sent, None)
    assert isinstance(found, Held)
    assert found.envelope.canonical() == sent.canonical()
    # B.3: the digest of the rendered arguments is the digest of the forwarded ones.
    forwarded = json.loads(found.envelope.canonical())["params"]["arguments"]
    assert canonical.digest(sent.arguments) == canonical.digest(forwarded)
