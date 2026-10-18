"""Admission decisions and session bindings (M3 design E.2, E.3)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import ViewGateway, ViewRemoteServer
from zoeymcp.gateway import access, logs
from zoeymcp.gateway.access import (
    ClientCounters,
    ClientToken,
    Refusal,
    SessionBindings,
    authenticate,
    bearer_token,
    check_content,
    check_rpc,
    check_version,
    host_allowed,
    host_name,
    identify,
    is_fresh,
    method_allowed,
    origin_allowed,
    parse_message,
    refusal_body,
    refusal_headers,
    server_for,
    server_from_path,
    source_allowed,
)

TOKENS = {"alpha": "zgc1-alpha-token", "beta": "zgc1-beta-token", "gamma": "zgc1-gamma-token"}
REMOTE: dict[str, Any] = {
    "kind": "remote",
    "vault_path": "/notes/mcp",
    "tools": {"include": [], "allow": [], "approve": []},
    "review": {},
    "on_drift": "hide",
    "shared_session": False,
    "wrap_results": False,
    "enable": [],
    "era": "auto",
    "drift_check_interval": 300,
    "call_timeout": None,
}


def gateway(**changes: Any) -> ViewGateway:
    raw: dict[str, Any] = {
        "hosts": ["localhost", "127.0.0.1", "::1", "Gateway.Example"],
        "origins": ["https://app.example", "http://localhost:3000"],
        "limits": {},
        "approvals": {},
        "clients": {
            "alpha": {
                "token_sha256": hash_token(TOKENS["alpha"]),
                "servers": ["notes", "mail"],
                "sources": [],
            },
            "beta": {
                "token_sha256": hash_token(TOKENS["beta"]),
                "servers": ["notes"],
                "sources": ["10.0.0.0/8", "fd00::/8"],
            },
            "gamma": {"token_sha256": hash_token(TOKENS["gamma"]), "servers": [], "sources": []},
        },
        "servers": {"notes": REMOTE, "mail": {"kind": "toolkit"}, "other": REMOTE},
    }
    raw.update(changes)
    return ViewGateway.model_validate(raw)


# --- steps 1-5 -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "name"),
    [
        ("/s/notes/mcp", "notes"),
        ("/s/a/mcp", "a"),
        ("/s/n0-te_s/mcp", "n0-te_s"),
        ("/s/" + "a" * 63 + "/mcp", "a" * 63),
        ("/s/notes/mcp/", None),
        ("/s/notes/mcp/x", None),
        ("/s//mcp", None),
        ("/s/Notes/mcp", None),
        ("/s/-notes/mcp", None),
        ("/s/" + "a" * 64 + "/mcp", None),
        ("/s/no.tes/mcp", None),
        ("/x/notes/mcp", None),
        ("/s/notes/MCP", None),
        ("s/notes/mcp", None),
        ("/s/notes/mcp\n", None),
        ("/.well-known/oauth-protected-resource", None),
        ("/healthz", None),
    ],
)
def test_server_from_path(path: str, name: str | None) -> None:
    assert server_from_path(path) == name


def test_freshness() -> None:
    assert is_fresh(0, 300)
    assert is_fresh(300, 300)
    assert not is_fresh(300.01, 300)
    assert not is_fresh(None, 300)
    assert not is_fresh(-1, 300)  # a clock that went backwards is not fresh


@pytest.mark.parametrize(
    ("header", "host"),
    [
        ("localhost", "localhost"),
        ("localhost:8090", "localhost"),
        ("LocalHost:8090", "localhost"),
        ("127.0.0.1:1", "127.0.0.1"),
        ("[::1]", "::1"),
        ("[::1]:8090", "::1"),
        ("[FD00::1]:8090", "fd00::1"),
        (None, None),
        ("", None),
        (":8090", None),
        ("::1", None),  # IPv6 without brackets
        ("::1:8090", None),
        ("[::1", None),
        ("[::1]x", None),
        ("[::1]:", None),
        ("[::1]:80a", None),
        ("[localhost]", None),  # brackets are for IPv6 only
        ("localhost:", None),
        ("localhost:80:90", None),
        ("localhost:123456", None),
        ("localhost: 80", None),
    ],
)
def test_host_name(header: str | None, host: str | None) -> None:
    assert host_name(header) == host


def test_host_allowed() -> None:
    hosts = gateway().hosts
    assert host_allowed("localhost:8090", hosts)
    assert host_allowed("[::1]:8090", hosts)
    assert host_allowed("gateway.example", hosts)  # policy entries match case-insensitively
    assert not host_allowed("evil.example", hosts)
    assert not host_allowed("localhost.", hosts)
    assert not host_allowed(None, hosts)


def test_origin_allowed() -> None:
    origins = gateway().origins
    assert origin_allowed(None, origins)
    assert origin_allowed("https://app.example", origins)
    assert origin_allowed("http://localhost:3000", origins)
    assert not origin_allowed("null", origins)
    assert not origin_allowed("null", ["null"])
    assert not origin_allowed("https://app.example:443", origins)
    assert not origin_allowed("https://evil.example", origins)
    assert not origin_allowed("", origins)


@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
def test_methods_allowed(method: str) -> None:
    assert method_allowed(method)


@pytest.mark.parametrize("method", ["PUT", "PATCH", "OPTIONS", "HEAD", "post", ""])
def test_other_methods_refused(method: str) -> None:
    assert not method_allowed(method)


# --- step 6 ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("values", "token"),
    [
        (["Bearer abc"], "abc"),
        (["bearer abc"], "abc"),
        (["BEARER a.b_c~d-e"], "a.b_c~d-e"),
        (["Bearer " + "x" * 256], "x" * 256),
        ([], None),
        (["Bearer abc", "Bearer abc"], None),
        (["Basic abc"], None),
        (["Bearer"], None),
        (["Bearer "], None),
        (["Bearer  abc"], None),
        (["Bearer abc def"], None),
        (["Bearer ab/c"], None),
        (["Bearer " + "x" * 257], None),
        (["Bearer abc\n"], None),
        (["abc"], None),
    ],
)
def test_bearer_token(values: list[str], token: str | None) -> None:
    found = bearer_token(values)
    assert (found.reveal() if found is not None else None) == token


def test_a_client_token_hides_itself_and_refuses_logging() -> None:
    token = ClientToken("zgc1-abc")
    assert repr(token) == "ClientToken(***)"
    assert "zgc1-abc" not in f"{token!r} {token}"
    assert token.sha256() == "sha256:" + hashlib.sha256(b"zgc1-abc").hexdigest()
    with pytest.raises(TypeError, match="refusing to log a secret"):
        logs.event("x", token=token)
    with pytest.raises(TypeError, match="refusing to log a secret"):
        logs.event("x", tokens=[token])


def test_identify() -> None:
    clients = gateway().clients
    assert identify(ClientToken(TOKENS["alpha"]), clients) == "alpha"
    assert identify(ClientToken(TOKENS["gamma"]), clients) == "gamma"
    assert identify(ClientToken("zgc1-unknown"), clients) is None
    assert identify(ClientToken(TOKENS["alpha"]), {}) is None


def test_every_client_hash_is_compared(monkeypatch: pytest.MonkeyPatch) -> None:
    compared: list[bytes] = []

    def counting(a: bytes, b: bytes) -> bool:
        compared.append(b)
        return a == b

    monkeypatch.setattr("zoeymcp.gateway.access.hmac.compare_digest", counting)
    clients = gateway().clients
    for token in (TOKENS["alpha"], TOKENS["gamma"], "zgc1-unknown"):
        compared.clear()
        identify(ClientToken(token), clients)
        assert compared == [client.token_sha256.encode() for client in clients.values()]


def test_the_first_match_wins_when_hashes_repeat() -> None:
    raw = gateway().model_dump()
    raw["clients"]["delta"] = dict(raw["clients"]["alpha"])
    assert identify(ClientToken(TOKENS["alpha"]), ViewGateway.model_validate(raw).clients) == (
        "alpha"
    )


@pytest.mark.parametrize(
    ("peer", "allowed"),
    [
        ("10.1.2.3", True),
        ("::ffff:10.1.2.3", True),  # IPv4-mapped
        ("fd00::5", True),
        ("11.0.0.1", False),
        ("fe80::1", False),
        (None, False),
        ("not an address", False),
        ("10.1.2.3:5000", False),
    ],
)
def test_source_allowed(peer: str | None, allowed: bool) -> None:
    assert source_allowed(peer, ["10.0.0.0/8", "fd00::/8"]) is allowed


def test_no_sources_means_any_peer() -> None:
    assert source_allowed(None, [])
    assert source_allowed("203.0.113.9", [])


def test_authenticate() -> None:
    view = gateway()
    assert authenticate([f"Bearer {TOKENS['alpha']}"], None, view) == "alpha"
    assert authenticate([f"Bearer {TOKENS['beta']}"], "10.9.9.9", view) == "beta"


@pytest.mark.parametrize(
    ("authorization", "peer", "reason"),
    [
        ([], "10.0.0.1", "no usable bearer token"),
        (["Basic eHg="], "10.0.0.1", "no usable bearer token"),
        (["Bearer zgc1-unknown"], "10.0.0.1", "unknown token"),
        ([f"Bearer {TOKENS['beta']}"], "192.0.2.1", "source not allowed"),
        ([f"Bearer {TOKENS['beta']}"], None, "source not allowed"),
    ],
)
def test_every_identity_failure_is_the_same_401(
    authorization: list[str], peer: str | None, reason: str
) -> None:
    refusal = authenticate(authorization, peer, gateway())
    assert isinstance(refusal, Refusal)
    assert (refusal.status, refusal.rpc_code, refusal.reason) == (401, -32600, reason)
    assert refusal_body(refusal) == refusal_body(Refusal(401, "anything"))
    assert refusal_headers(refusal) == refusal_headers(Refusal(401, "anything"))


# --- steps 7-8 -------------------------------------------------------------------------------


def test_server_for() -> None:
    view = gateway()
    server = server_for(view, "alpha", "notes")
    assert isinstance(server, ViewRemoteServer)
    assert server.vault_path == "/notes/mcp"


@pytest.mark.parametrize(
    ("client", "name", "reason"),
    [
        ("alpha", "missing", "server not assigned"),
        ("alpha", "other", "server not assigned"),  # exists, not assigned
        ("gamma", "notes", "server not assigned"),
        ("alpha", "mail", "server kind not served"),  # assigned, a toolkit
    ],
)
def test_server_refusals_are_one_404(client: str, name: str, reason: str) -> None:
    refusal = server_for(gateway(), client, name)
    assert refusal == Refusal(404, reason)
    assert refusal_body(refusal) == refusal_body(Refusal(404, "x"))


@pytest.mark.parametrize("version", ["2026-07-28", "2025-11-25", "2025-06-18"])
@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
def test_supported_versions(version: str, method: str) -> None:
    assert check_version(version, method) == "ok"


@pytest.mark.parametrize("version", ["2025-03-26", "2024-11-05", "", "2026-07-28 ", "latest"])
def test_other_versions_are_refused(version: str) -> None:
    assert check_version(version, "POST") == Refusal(400, "unsupported protocol version")


def test_without_a_version_only_a_post_may_initialize() -> None:
    assert check_version(None, "POST") == "needs_initialize"
    assert check_version(None, "GET") == Refusal(400, "no protocol version")
    assert check_version(None, "DELETE") == Refusal(400, "no protocol version")


# --- step 9: sessions ------------------------------------------------------------------------


def test_a_session_is_bound_to_client_and_server() -> None:
    sessions = SessionBindings(idle_timeout=1800)
    sessions.bind("s1", "alpha", "notes", now=0)
    assert sessions.allowed("s1", "alpha", "notes", now=1)
    assert not sessions.allowed("s1", "beta", "notes", now=1)  # another client
    assert not sessions.allowed("s1", "alpha", "other", now=1)  # another server path
    assert not sessions.allowed("s2", "alpha", "notes", now=1)  # unknown


def test_a_live_session_is_never_rebound() -> None:
    sessions = SessionBindings(idle_timeout=1800)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.bind("s1", "beta", "notes", now=1)
    assert sessions.allowed("s1", "alpha", "notes", now=2)
    assert not sessions.allowed("s1", "beta", "notes", now=2)


def test_an_idle_session_expires() -> None:
    sessions = SessionBindings(idle_timeout=100)
    sessions.bind("s1", "alpha", "notes", now=0)
    assert sessions.allowed("s1", "alpha", "notes", now=100)
    assert not sessions.allowed("s1", "alpha", "notes", now=100.5)
    # Expired, so the id can be bound again (the SDK would never reuse one, but nothing breaks).
    sessions.bind("s1", "beta", "notes", now=101)
    assert sessions.allowed("s1", "beta", "notes", now=101)


def test_a_request_in_flight_keeps_its_session() -> None:
    sessions = SessionBindings(idle_timeout=100)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.begin("s1", now=50)  # an open GET stream
    assert sessions.allowed("s1", "alpha", "notes", now=10_000)
    sessions.end("s1", now=10_000)
    assert sessions.allowed("s1", "alpha", "notes", now=10_100)
    assert not sessions.allowed("s1", "alpha", "notes", now=10_101)


def test_each_request_moves_the_idle_clock() -> None:
    sessions = SessionBindings(idle_timeout=100)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.begin("s1", now=90)
    sessions.end("s1", now=95)
    assert sessions.allowed("s1", "alpha", "notes", now=195)
    assert not sessions.allowed("s1", "alpha", "notes", now=196)


def test_begin_and_end_on_unknown_or_expired_sessions_do_nothing() -> None:
    sessions = SessionBindings(idle_timeout=100)
    sessions.begin("nope", now=0)
    sessions.end("nope", now=0)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.begin("s1", now=500)  # already expired: not revived
    assert not sessions.allowed("s1", "alpha", "notes", now=500)


def test_end_never_goes_below_zero() -> None:
    sessions = SessionBindings(idle_timeout=100)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.end("s1", now=0)
    sessions.end("s1", now=0)
    sessions.begin("s1", now=0)
    sessions.end("s1", now=0)
    assert not sessions.allowed("s1", "alpha", "notes", now=101)


def test_drop_after_delete() -> None:
    sessions = SessionBindings(idle_timeout=1800)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.drop("s1")
    sessions.drop("s1")
    assert not sessions.allowed("s1", "alpha", "notes", now=1)


def test_bindings_are_bounded_least_recently_used_first() -> None:
    sessions = SessionBindings(idle_timeout=1800, capacity=2)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.bind("s2", "alpha", "notes", now=1)
    sessions.begin("s1", now=2)
    sessions.end("s1", now=2)  # s1 is now the most recent
    sessions.bind("s3", "alpha", "notes", now=3)
    assert sessions.allowed("s1", "alpha", "notes", now=4)
    assert not sessions.allowed("s2", "alpha", "notes", now=4)
    assert sessions.allowed("s3", "alpha", "notes", now=4)


def test_a_session_in_flight_is_never_evicted() -> None:
    sessions = SessionBindings(idle_timeout=1800, capacity=1)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.begin("s1", now=0)
    sessions.bind("s2", "alpha", "notes", now=1)
    assert sessions.allowed("s1", "alpha", "notes", now=2)
    assert sessions.allowed("s2", "alpha", "notes", now=2)


def test_the_default_capacity() -> None:
    assert SessionBindings(idle_timeout=1).capacity == access.SESSION_CAPACITY == 4096


def test_count_per_client() -> None:
    sessions = SessionBindings(idle_timeout=100)
    sessions.bind("s1", "alpha", "notes", now=0)
    sessions.bind("s2", "alpha", "other", now=50)
    sessions.bind("s3", "beta", "notes", now=50)
    assert sessions.count("alpha", now=60) == 2
    assert sessions.count("beta", now=60) == 1
    assert sessions.count("alpha", now=120) == 1  # s1 expired
    assert sessions.count("gamma", now=60) == 0


# --- step 10: limits -------------------------------------------------------------------------


def test_concurrent_requests_per_client() -> None:
    counters = ClientCounters()
    assert counters.try_acquire("alpha", stream=False, max_requests=2, max_streams=1)
    assert counters.try_acquire("alpha", stream=False, max_requests=2, max_streams=1)
    assert not counters.try_acquire("alpha", stream=False, max_requests=2, max_streams=1)
    assert counters.try_acquire("beta", stream=False, max_requests=2, max_streams=1)
    counters.release("alpha", stream=False)
    assert counters.try_acquire("alpha", stream=False, max_requests=2, max_streams=1)


def test_streams_count_as_requests_and_streams() -> None:
    counters = ClientCounters()
    assert counters.try_acquire("alpha", stream=True, max_requests=3, max_streams=1)
    assert not counters.try_acquire("alpha", stream=True, max_requests=3, max_streams=1)
    assert counters.requests["alpha"] == 1  # the refused stream took nothing
    assert counters.try_acquire("alpha", stream=False, max_requests=3, max_streams=1)
    counters.release("alpha", stream=True)
    assert counters.streams["alpha"] == 0
    assert counters.requests["alpha"] == 1
    assert counters.try_acquire("alpha", stream=True, max_requests=3, max_streams=1)


def test_a_counted_request_can_become_a_stream() -> None:
    counters = ClientCounters()
    assert counters.try_acquire("alpha", stream=False, max_requests=3, max_streams=1)
    assert counters.try_add_stream("alpha", max_streams=1)
    assert counters.streams["alpha"] == 1
    assert counters.requests["alpha"] == 1
    assert counters.try_acquire("alpha", stream=False, max_requests=3, max_streams=1)
    assert not counters.try_add_stream("alpha", max_streams=1)
    assert counters.streams["alpha"] == 1
    counters.release("alpha", stream=True)
    assert counters.streams["alpha"] == 0


def test_release_never_goes_below_zero() -> None:
    counters = ClientCounters()
    counters.release("alpha", stream=True)
    assert counters.requests["alpha"] == 0
    assert counters.streams["alpha"] == 0


def test_a_limit_refusal_is_429_with_retry_after() -> None:
    refusal = access.too_many("streams")
    assert refusal == Refusal(429, "streams")
    assert ("retry-after", "1") in refusal_headers(refusal)


# --- steps 11-12: the body -------------------------------------------------------------------


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
        " application/json ",
    ],
)
def test_json_content_types(content_type: str) -> None:
    assert check_content(content_type, "10", 100) is None


@pytest.mark.parametrize(
    "content_type",
    [None, "", "text/plain", "application/jsonx", "application/json-seq", "text/json"],
)
def test_other_content_types(content_type: str | None) -> None:
    assert check_content(content_type, "10", 100) == Refusal(400, "not application/json")


def test_content_length() -> None:
    assert check_content("application/json", None, 100) is None
    assert check_content("application/json", "100", 100) is None
    assert check_content("application/json", "101", 100) == Refusal(413, "body over the limit")
    for bad in ("-1", "1e3", " 10", "\u0661\u0660", ""):
        assert check_content("application/json", bad, 100) == Refusal(400, "bad content length")


def test_parse_message() -> None:
    assert parse_message(b'{"jsonrpc":"2.0","id":1,"method":"ping"}', 100) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping",
    }
    assert parse_message(b"{}" + b" " * 99, 100) == Refusal(413, "body over the limit")


@pytest.mark.parametrize(
    "body",
    [b"{", b'{"a":1,"a":2}', b"NaN", b'{"x":9007199254740992}', b'"\\ud800"', b"\xff"],
)
def test_strict_json_or_a_parse_error(body: bytes) -> None:
    assert parse_message(body, 1000) == Refusal(400, "not strict JSON", rpc_code=-32700)


def test_parse_depth_is_64() -> None:
    assert isinstance(parse_message(b"[" * 63 + b"]" * 63, 1000), Refusal)
    deep = b'{"a":' * 63 + b"1" + b"}" * 63
    assert isinstance(parse_message(deep, 1000), dict)
    deeper = b'{"a":' * 65 + b"1" + b"}" * 65
    assert parse_message(deeper, 1000) == Refusal(400, "not strict JSON", rpc_code=-32700)


@pytest.mark.parametrize(
    "body", [b"[]", b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]', b"1", b"null"]
)
def test_a_batch_or_non_object_is_refused(body: bytes) -> None:
    assert parse_message(body, 1000) == Refusal(400, "not one JSON-RPC object")


@pytest.mark.parametrize("method", sorted(access.RPC_METHODS))
def test_served_methods(method: str) -> None:
    assert check_rpc({"method": method}, "ok", modern=True) is None


def test_unknown_methods_by_era() -> None:
    assert check_rpc({"method": "sampling/createMessage"}, "ok", modern=True) == Refusal(
        404, "method not served", rpc_code=-32601
    )
    assert check_rpc({"method": "resources/list"}, "ok", modern=False) == Refusal(
        200, "method not served", rpc_code=-32601
    )
    assert check_rpc({"method": 5}, "ok", modern=False) == Refusal(
        200, "method not served", rpc_code=-32601
    )


def test_a_client_response_is_refused() -> None:
    refusal = check_rpc({"id": 1, "result": {}}, "ok", modern=False)
    assert isinstance(refusal, Refusal)
    assert refusal.status == 400


def test_without_a_version_header_only_initialize() -> None:
    assert check_rpc({"method": "initialize"}, "needs_initialize", modern=False) is None
    assert check_rpc({"method": "tools/list"}, "needs_initialize", modern=False) == Refusal(
        400, "no protocol version"
    )


# --- the answers -----------------------------------------------------------------------------


@pytest.mark.parametrize("status", sorted(access.STATUS_MESSAGES))
def test_refusal_bodies_hold_a_fixed_message(status: int) -> None:
    body = json.loads(refusal_body(Refusal(status, "secret reason with a token zgc1-x")))
    assert body == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": access.STATUS_MESSAGES[status]},
    }


def test_rpc_refusals_name_the_error() -> None:
    assert json.loads(refusal_body(Refusal(200, "x", rpc_code=-32601)))["error"] == {
        "code": -32601,
        "message": "method not found",
    }
    assert json.loads(refusal_body(Refusal(400, "x", rpc_code=-32700)))["error"] == {
        "code": -32700,
        "message": "parse error",
    }


def test_refusal_headers() -> None:
    assert refusal_headers(Refusal(401, "x")) == [
        ("content-type", "application/json"),
        ("www-authenticate", 'Bearer realm="zoeymcp"'),
    ]
    assert refusal_headers(Refusal(404, "x")) == [("content-type", "application/json")]
