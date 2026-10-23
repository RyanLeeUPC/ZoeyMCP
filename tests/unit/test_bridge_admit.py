"""Admission to the bridge's endpoint (M7 design C.4's table, C.5, M.3; SPEC-4, SPEC-5, X13, X17;
O.2 ``test_bridge_admit.py``).

Each row both ways, in both eras where it differs: the path, the method, an ``Origin``, the
token (one body for every identity failure, decided before the body), the content type and
length, the legacy session rules (400 and 404, and its 400 to a modern version header), the
modern routing headers (an encoded ``Mcp-Name``, a protocol version that disagrees, a session id
ignored) and ``initialize`` refusal, and a notification's 202.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from zoeymcp.bridge import admit
from zoeymcp.bridge.admit import (
    BUSY,
    CHILD_EXITED,
    NOT_READY,
    SESSIONS_FULL,
    Admitted,
    BridgeTokenHash,
    Head,
    Refusal,
    body,
    decode_name,
    head,
    mismatch,
)
from zoeymcp.bridge.framing import Era, Message

TOKEN = "bridge-token-0123456789-abcdefghijklmnopq"
HASH = BridgeTokenHash("sha256:" + hashlib.sha256(TOKEN.encode()).hexdigest())
SESSIONS = {"known-session": "the session"}
MODERN = "2026-07-28"
LEGACY = "2025-11-25"
BODY = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'


def headers(
    *extra: tuple[str, str], token: str | None = TOKEN, post: bool = True
) -> list[tuple[bytes, bytes]]:
    found = []
    if token is not None:
        found.append(("authorization", f"Bearer {token}"))
    if post:
        found += [("content-type", "application/json"), ("content-length", "40")]
    found += extra
    return [(name.encode(), value.encode("latin-1")) for name, value in found]


def check(
    era: Era,
    method: str = "POST",
    path: str = "/mcp",
    sent: Sequence[tuple[bytes, bytes]] | None = None,
    max_bytes: int = 100,
) -> Head[str] | Refusal:
    return head(
        era,
        method,
        path,
        headers() if sent is None else sent,
        token=HASH,
        find=SESSIONS.get,
        max_bytes=max_bytes,
    )


def request(method: str, params: Mapping[str, Any] | None = None, rpc_id: Any = 7) -> bytes:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if rpc_id is not None:
        message["id"] = rpc_id
    if params is not None:
        message["params"] = params
    return json.dumps(message).encode()


def modern(method: str, params: Mapping[str, Any] | None = None) -> bytes:
    meta = {"io.modelcontextprotocol/protocolVersion": MODERN}
    return request(method, {**(params or {}), "_meta": meta})


def routing(**values: str | tuple[str, ...]) -> dict[str, tuple[str, ...]]:
    return {
        name.replace("_", "-"): value if isinstance(value, tuple) else (value,)
        for name, value in values.items()
    }


def modern_head(**values: str | tuple[str, ...]) -> Head[str]:
    return Head("POST", routing=routing(**values))


def answer(refused: Refusal) -> tuple[int, int, Any]:
    """The status, and the JSON-RPC error's code and data, as the client sees them."""
    sent = json.loads(refused.body())
    return refused.status, sent["error"]["code"], sent["error"].get("data")


# --- the token ----------------------------------------------------------------------------------


def test_the_token_hash_is_sha256_hex() -> None:
    BridgeTokenHash("sha256:" + "0" * 64)
    for bad in (
        "",
        "sha256:" + "0" * 63,
        "sha256:" + "A" * 64,
        "SHA256:" + "0" * 64,
        "0" * 64,
        "sha256:" + "0" * 64 + "\n",
    ):
        with pytest.raises(ValueError, match=r"^ZOEYMCP_BRIDGE_TOKEN_SHA256 isn't sha256: and 64"):
            BridgeTokenHash(bad)
    assert repr(HASH) == "BridgeTokenHash(***)"
    assert TOKEN not in repr(HASH)


def test_the_token_admits_one_bearer_value() -> None:
    assert HASH.admits([f"Bearer {TOKEN}"])
    assert HASH.admits([f"bearer {TOKEN}"])
    assert not HASH.admits([])
    assert not HASH.admits([f"Bearer {TOKEN}", f"Bearer {TOKEN}"])
    assert not HASH.admits([f"Basic {TOKEN}"])
    assert not HASH.admits([TOKEN])
    assert not HASH.admits(["Bearer "])
    assert not HASH.admits([f"Bearer {TOKEN}x"])
    assert not HASH.admits([f"Bearer  {TOKEN}"])
    assert not HASH.admits([f"Bearer {TOKEN[:-1]}"])


# --- rows 1 to 5: before the body ---------------------------------------------------------------


@pytest.mark.parametrize("era", ["legacy", "modern"])
def test_the_path_is_mcp(era: Era) -> None:
    for path in (
        "/",
        "/mcp/",
        "/MCP",
        "/.well-known/oauth-protected-resource",
        "/register",
        "/token",
        "/authorize",
    ):
        refused = check(era, path=path, sent=[])
        assert refused == Refusal(404, "path")
        assert refused.body() == b""
        assert refused.headers() == []
    assert isinstance(check(era), Head)


@pytest.mark.parametrize("era", ["legacy", "modern"])
def test_the_method(era: Era) -> None:
    for method in ("PUT", "PATCH", "OPTIONS", "HEAD", "post"):
        refused = check(era, method, sent=[])
        assert isinstance(refused, Refusal)
        assert (refused.status, refused.reason, refused.body()) == (405, "method", b"")
        assert refused.headers() == [("allow", "GET, POST, DELETE")]


@pytest.mark.parametrize("era", ["legacy", "modern"])
def test_an_origin_is_refused(era: Era) -> None:
    for origin in ("https://evil.example", "null", ""):
        assert check(era, sent=headers(("origin", origin))) == Refusal(403, "origin")


@pytest.mark.parametrize("era", ["legacy", "modern"])
@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
def test_an_unauthenticated_request_is_refused_before_the_body(era: Era, method: str) -> None:
    """X13: the decision needs no body byte, and every identity failure looks the same."""
    sent_list = [
        headers(token=None),
        headers(token="wrong"),
        headers(("authorization", f"Bearer {TOKEN}")),
        [(b"authorization", f"Basic {TOKEN}".encode()), *headers(token=None)],
    ]
    for sent in sent_list:
        refused = check(era, method, sent=sent)
        assert refused == Refusal(403, "token")
        assert (refused.body(), refused.headers()) == (b"", [])
    origin = check(era, method, sent=headers(("origin", "https://a.example")))
    assert isinstance(origin, Refusal)
    assert (origin.status, origin.body(), origin.headers()) == (403, b"", [])


@pytest.mark.parametrize("era", ["legacy", "modern"])
def test_a_post_carries_json_of_a_known_length(era: Era) -> None:
    def sent(*pairs: tuple[str, str]) -> list[tuple[bytes, bytes]]:
        return headers(*pairs, post=False)

    length = ("content-length", "100")
    json_type = ("content-type", "application/json")
    assert check(era, sent=sent(length)) == Refusal(415, "content_type")
    assert check(era, sent=sent(("content-type", "text/plain"), length)) == Refusal(
        415, "content_type"
    )
    assert check(era, sent=sent(json_type, json_type, length)) == Refusal(415, "content_type")
    assert check(
        era, sent=sent(("content-type", "application/json; charset=latin-1"), length)
    ) == Refusal(415, "content_type")
    for good in (
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
        'application/json;charset="UTF-8"',
    ):
        assert isinstance(check(era, sent=sent(("content-type", good), length)), Head)
    assert check(era, sent=sent(json_type)) == Refusal(411, "length")
    assert check(era, sent=sent(json_type, length, length)) == Refusal(411, "length")
    for bad in ("", "-1", "1e3", " 10", "0x10", "1" * 21):
        assert check(era, sent=sent(json_type, ("content-length", bad))) == Refusal(411, "length")
    assert check(era, sent=sent(json_type, ("content-length", "101"))) == Refusal(413, "too_large")
    assert isinstance(check(era, sent=sent(json_type, ("content-length", "0"))), Head)
    assert isinstance(check(era, sent=sent(json_type, ("content-length", "0" * 20))), Head)
    assert isinstance(check(era, sent=sent(json_type, ("content-length", "100"))), Head)


@pytest.mark.parametrize("era", ["legacy", "modern"])
def test_get_and_delete_need_no_content_headers(era: Era) -> None:
    for method in ("GET", "DELETE"):
        found = check(era, method, sent=headers(("mcp-session-id", "known-session"), post=False))
        if era == "legacy":
            assert found == Head(method, "the session")
        else:
            assert found == Refusal(405, "era_method", allow="POST")


# --- row 6, legacy: the session and the version --------------------------------------------------


def test_a_legacy_session_is_looked_up() -> None:
    found = check("legacy", sent=headers(("mcp-session-id", "known-session")))
    assert isinstance(found, Head)
    assert found.session == "the session"
    unknown = check("legacy", sent=headers(("mcp-session-id", "ended-session")))
    assert isinstance(unknown, Refusal)
    assert answer(unknown) == (404, -32600, None)
    assert unknown.reason == "session_unknown"
    assert unknown.headers() == [("content-type", "application/json")]
    twice = check(
        "legacy",
        sent=headers(("mcp-session-id", "known-session"), ("mcp-session-id", "known-session")),
    )
    assert isinstance(twice, Refusal)
    assert (twice.status, twice.reason) == (400, "session_repeated")


def test_a_legacy_get_or_delete_needs_a_session() -> None:
    for method in ("GET", "DELETE"):
        refused = check("legacy", method, sent=headers(post=False))
        assert isinstance(refused, Refusal)
        assert answer(refused) == (400, -32600, None)
        assert refused.reason == "session_missing"
        assert (
            check("legacy", method, sent=headers(("mcp-session-id", "nope"), post=False))
            == admit.SESSION_UNKNOWN
        )


def test_a_legacy_post_without_a_session_waits_for_the_body() -> None:
    assert check("legacy") == Head("POST")


def test_a_legacy_bridge_answers_a_modern_version_header_with_400() -> None:
    """C.5: as a legacy server must, so the SDK's auto mode falls back to initialize."""
    for version in (MODERN, "2099-01-01", ""):
        refused = check("legacy", sent=headers(("mcp-protocol-version", version)))
        assert isinstance(refused, Refusal)
        assert (refused.status, refused.reason) == (400, "version")
        assert answer(refused) == (400, -32600, None)
    for version in ("2024-11-05", "2025-03-26", "2025-06-18", LEGACY):
        assert isinstance(check("legacy", sent=headers(("mcp-protocol-version", version))), Head)
    twice = headers(("mcp-protocol-version", LEGACY), ("mcp-protocol-version", LEGACY))
    assert check("legacy", sent=twice) == admit.VERSION
    # Before the session's lookup, so a modern probe gets the version's answer.
    probe = headers(("mcp-protocol-version", MODERN), ("mcp-session-id", "unknown"))
    assert check("legacy", sent=probe) == admit.VERSION


def test_a_modern_bridge_ignores_the_session_header() -> None:
    """SPEC-5: neither looked up nor refused, whatever it holds."""
    for value in ("known-session", "unknown", ""):
        found = check(
            "modern", sent=headers(("mcp-session-id", value), ("mcp-protocol-version", MODERN))
        )
        assert isinstance(found, Head)
        assert found.session is None
    assert isinstance(check("modern", sent=headers(("mcp-protocol-version", LEGACY))), Head)


def test_the_routing_headers_are_kept_as_sent() -> None:
    sent = headers(("Mcp-Method", "tools/call"), ("mcp-name", "a"), ("mcp-name", "b"))
    found = check("modern", sent=sent)
    assert isinstance(found, Head)
    assert found.routing == {
        "mcp-protocol-version": (),
        "mcp-method": ("tools/call",),
        "mcp-name": ("a", "b"),
    }


# --- rows 6 to 9: the body ----------------------------------------------------------------------


@pytest.mark.parametrize("era", ["legacy", "modern"])
def test_the_body_is_one_request_or_notification(era: Era) -> None:
    seen: Head[str] = Head("POST", "the session")
    for data in (
        b"",
        b"not json",
        b'[{"jsonrpc":"2.0","method":"m"}]',
        b'"x"',
        b'{"jsonrpc":"2.0","id":1,"result":{}}',
        b'{"id":1,"method":"m"}',
        b'{"jsonrpc":"2.0","id":null,"method":"m"}',
    ):
        refused = body(era, seen, data)
        assert isinstance(refused, Refusal)
        assert answer(refused) == (400, -32600, None)
        assert refused.reason == "invalid"
    note = request("notifications/initialized", rpc_id=None)
    assert body(era, seen, note, max_bytes=len(note) - 1) == body(era, seen, b"x")
    assert isinstance(body(era, seen, note, max_bytes=len(note)), Admitted)


def test_legacy_initialize_starts_a_session() -> None:
    data = request("initialize", {"protocolVersion": LEGACY})
    started = body("legacy", Head("POST"), data)
    assert isinstance(started, Admitted)
    assert (started.action, started.accepted) == ("start", False)
    assert started.message.raw == data
    refused = body("legacy", Head("POST", "the session"), data)
    assert isinstance(refused, Refusal)
    assert (refused.status, refused.reason, refused.rpc_id) == (400, "initialize_in_session", 7)
    # A notification named initialize is no start.
    note = body("legacy", Head("POST"), request("initialize", rpc_id=None))
    assert isinstance(note, Refusal)
    assert note.reason == "session_missing"


def test_legacy_needs_a_session_for_everything_else() -> None:
    """SPEC-4: a missing Mcp-Session-Id is 400 (and an unknown one 404, in head)."""
    for data in (BODY, request("notifications/initialized", rpc_id=None)):
        refused = body("legacy", Head("POST"), data)
        assert isinstance(refused, Refusal)
        assert answer(refused) == (400, -32600, None)
        assert refused.reason == "session_missing"
    assert json.loads(body("legacy", Head("POST"), BODY).body())["id"] == 1  # type: ignore[union-attr]
    relayed = body("legacy", Head("POST", "the session"), BODY)
    assert isinstance(relayed, Admitted)
    assert (relayed.action, relayed.accepted) == ("relay", False)


def test_a_notification_is_accepted_with_202_in_both_eras() -> None:
    """SPEC-4: only legacy's initialized and cancelled reach the child."""
    session: Head[str] = Head("POST", "the session")
    expected = {
        "notifications/initialized": ("notify", "accept"),
        "notifications/cancelled": ("cancel", "accept"),
        "notifications/roots/list_changed": ("accept", "accept"),
        "notifications/progress": ("accept", "accept"),
    }
    for method, (legacy, modern_action) in expected.items():
        data = request(method, rpc_id=None)
        for era, action in (("legacy", legacy), ("modern", modern_action)):
            admitted = body(era, session, data)  # type: ignore[arg-type]
            assert isinstance(admitted, Admitted)
            assert (admitted.action, admitted.accepted) == (action, True)
    # A modern notification needs no routing header.
    assert body(
        "modern", Head("POST"), request("notifications/cancelled", {"requestId": 1}, None)
    ) == Admitted(Message(request("notifications/cancelled", {"requestId": 1}, None), {}), "accept")


def test_a_modern_bridge_refuses_initialize() -> None:
    """C.5, SPEC-5: 400 with data.supported, so a client finds the versions it serves."""
    refused = body("modern", modern_head(), request("initialize", {"protocolVersion": LEGACY}))
    assert isinstance(refused, Refusal)
    assert answer(refused) == (400, -32022, {"supported": [MODERN], "requested": LEGACY})
    assert (refused.reason, json.loads(refused.body())["id"]) == ("initialize_modern", 7)
    assert json.loads(refused.body())["error"]["message"] == "Unsupported protocol version"
    bare = body("modern", modern_head(), request("initialize", {"protocolVersion": 5}))
    assert isinstance(bare, Refusal)
    assert answer(bare) == (400, -32022, {"supported": [MODERN], "requested": ""})
    assert answer(body("modern", modern_head(), request("initialize"))) == answer(bare)  # type: ignore[arg-type]


def test_a_modern_request_whose_headers_match_is_relayed() -> None:
    seen = modern_head(mcp_protocol_version=MODERN, mcp_method="tools/list")
    relayed = body("modern", seen, modern("tools/list"))
    assert isinstance(relayed, Admitted)
    assert (relayed.action, relayed.accepted) == ("relay", False)
    call = modern("tools/call", {"name": "get_time"})
    named = modern_head(mcp_protocol_version=MODERN, mcp_method="tools/call", mcp_name="get_time")
    assert isinstance(body("modern", named, call), Admitted)
    read = modern("resources/read", {"uri": "file:///a b"})
    by_uri = modern_head(
        mcp_protocol_version=MODERN, mcp_method="resources/read", mcp_name="file:///a b"
    )
    assert isinstance(body("modern", by_uri, read), Admitted)
    prompt = modern("prompts/get", {"name": "p"})
    by_name = modern_head(mcp_protocol_version=MODERN, mcp_method="prompts/get", mcp_name="p")
    assert isinstance(body("modern", by_name, prompt), Admitted)
    # Mcp-Param-* headers are the child's to check.
    assert body("modern", seen, modern("tools/list")) == relayed


def test_an_encoded_mcp_name() -> None:
    """SPEC-5: a name that isn't plain ASCII travels in the Base64 sentinel form."""
    name = "h\u00e9llo wor\u00efd "
    encoded = "=?base64?" + base64.b64encode(name.encode()).decode() + "?="
    call = modern("tools/call", {"name": name})
    seen = modern_head(mcp_protocol_version=MODERN, mcp_method="tools/call", mcp_name=encoded)
    assert isinstance(body("modern", seen, call), Admitted)
    # The same through head, from the header as received.
    sent = headers(
        ("mcp-protocol-version", MODERN), ("mcp-method", "tools/call"), ("mcp-name", encoded)
    )
    received = check("modern", sent=sent)
    assert isinstance(received, Head)
    assert isinstance(body("modern", received, call), Admitted)
    # Sent as it is, its UTF-8 bytes arrive as Latin-1 text and match nothing.
    raw = name.encode().decode("latin-1")
    wrong = modern_head(mcp_protocol_version=MODERN, mcp_method="tools/call", mcp_name=raw)
    refused = body("modern", wrong, call)
    assert isinstance(refused, Refusal)
    assert answer(refused) == (400, -32020, None)
    assert (
        json.loads(refused.body())["error"]["message"]
        == "mcp-name doesn't match the request's name"
    )


def test_decode_name() -> None:
    assert decode_name("plain") == "plain"
    assert decode_name("=?base64?aGk=?=") == "hi"
    assert decode_name("=?base64??=") == ""
    assert decode_name("=?base64?aGk?=") is None  # not padded
    assert decode_name("=?base64?aGl=?=") is None  # not canonical
    assert decode_name("=?base64?a*k=?=") is None
    assert decode_name("=?base64?/w==?=") is None  # not UTF-8
    assert decode_name("x=?base64?aGk=?=") == "x=?base64?aGk=?="
    assert decode_name("=?base64?aGk=?=x") == "=?base64?aGk=?=x"


@pytest.mark.parametrize(
    ("values", "message", "reason"),
    [
        ({"mcp_method": "tools/list"}, modern("tools/list"), "mcp-protocol-version"),
        (
            {"mcp_protocol_version": LEGACY, "mcp_method": "tools/list"},
            modern("tools/list"),
            "mcp-protocol-version",
        ),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": "tools/list"},
            request("tools/list"),
            "mcp-protocol-version",
        ),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": "tools/list"},
            request("tools/list", {"_meta": []}),
            "mcp-protocol-version",
        ),
        ({"mcp_protocol_version": MODERN}, modern("tools/list"), "mcp-method"),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": "tools/call"},
            modern("tools/list"),
            "mcp-method",
        ),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": "tools/call"},
            modern("tools/call", {"name": "a"}),
            "mcp-name",
        ),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": "tools/call", "mcp_name": "b"},
            modern("tools/call", {"name": "a"}),
            "mcp-name",
        ),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": "tools/call", "mcp_name": "a"},
            modern("tools/call"),
            "mcp-name",
        ),
        (
            {
                "mcp_protocol_version": MODERN,
                "mcp_method": "tools/call",
                "mcp_name": "=?base64?aGk?=",
            },
            modern("tools/call"),
            "mcp-name",
        ),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": "resources/read", "mcp_name": "a"},
            modern("resources/read", {"name": "a"}),
            "mcp-name",
        ),
        (
            {"mcp_protocol_version": (MODERN, MODERN), "mcp_method": "tools/list"},
            modern("tools/list"),
            "mcp-protocol-version",
        ),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": ("tools/list", "tools/list")},
            modern("tools/list"),
            "mcp-method",
        ),
        (
            {"mcp_protocol_version": MODERN, "mcp_method": "tools/list", "mcp_name": ("a", "a")},
            modern("tools/list"),
            "mcp-name",
        ),
    ],
)
def test_a_protocol_version_or_header_mismatch(
    values: dict[str, Any], message: bytes, reason: str
) -> None:
    """Row 7: each routing header present once and equal to the body, else -32020."""
    refused = body("modern", modern_head(**values), message)
    assert isinstance(refused, Refusal)
    assert answer(refused) == (400, -32020, None)
    assert (refused.reason, refused.rpc_id) == ("header_mismatch", 7)
    assert json.loads(refused.body())["error"]["message"].startswith(reason)


def test_mismatch_messages() -> None:
    assert mismatch({}, {"method": "tools/list"}) == (
        "mcp-protocol-version doesn't match the request's _meta protocol version"
    )
    version = {"mcp-protocol-version": (MODERN,)}
    meta = {"method": "tools/list", "params": {"_meta": {admit.PROTOCOL_VERSION_META: MODERN}}}
    assert mismatch(version, meta) == "mcp-method doesn't match the request's method"
    assert mismatch({**version, "mcp-method": ("tools/list",)}, meta) is None
    twice = {**version, "mcp-method": ("tools/list",), "mcp-name": ("a", "b")}
    assert mismatch(twice, meta) == "mcp-name appears more than once"
    read = {
        "method": "resources/read",
        "params": {"_meta": {admit.PROTOCOL_VERSION_META: MODERN}, "uri": "u"},
    }
    assert (
        mismatch({**version, "mcp-method": ("resources/read",)}, read)
        == "mcp-name doesn't match the request's uri"
    )


def test_a_modern_request_with_a_legacy_body_is_a_mismatch() -> None:
    seen = modern_head(mcp_protocol_version=MODERN, mcp_method="tools/list")
    refused = body("modern", seen, BODY)
    assert isinstance(refused, Refusal)
    assert (refused.reason, refused.rpc_id) == ("header_mismatch", 1)


# --- the answers --------------------------------------------------------------------------------


def test_the_bridges_own_answers() -> None:
    """M.3: 502 when the child died, 503 when busy, full or not ready; empty bodies."""
    assert [(r.status, r.reason) for r in (BUSY, SESSIONS_FULL, CHILD_EXITED, NOT_READY)] == [
        (503, "bridge_busy"),
        (503, "sessions_full"),
        (502, "child_exited"),
        (503, "not_ready"),
    ]
    assert {r.body() for r in (BUSY, SESSIONS_FULL, CHILD_EXITED, NOT_READY)} == {b""}


def test_a_refusals_body() -> None:
    refused = Refusal(400, "r", -32020, "m", {"k": [1]}, "id-1")
    assert (
        refused.body()
        == b'{"jsonrpc":"2.0","id":"id-1","error":{"code":-32020,"message":"m","data":{"k":[1]}}}'
    )
    assert (
        Refusal(400, "r", -32600, "m").body()
        == b'{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"m"}}'
    )
    assert (
        Refusal(400, "r", -32600, "m", rpc_id=2**63)
        .body()
        .startswith(b'{"jsonrpc":"2.0","id":9223372036854775808,')
    )
    assert Refusal(405, "r", allow="POST").headers() == [("allow", "POST")]
    assert Refusal(400, "r", 1, "m", allow="POST").headers() == [
        ("content-type", "application/json"),
        ("allow", "POST"),
    ]


# --- what each answer carries -------------------------------------------------------------------


def said(refused: Head[str] | Admitted | Refusal) -> tuple[int, int, str, Any]:
    """A refusal's status, and its JSON-RPC error's code, message and id, as the client sees it."""
    assert isinstance(refused, Refusal)
    sent = json.loads(refused.body())
    return refused.status, sent["error"]["code"], sent["error"]["message"], sent["id"]


def test_the_token_is_everything_after_the_first_space() -> None:
    spaced = BridgeTokenHash("sha256:" + hashlib.sha256(b"two words").hexdigest())
    assert spaced.admits(["Bearer two words"])
    assert not spaced.admits(["Bearer two"])
    assert not spaced.admits(["Bearer words"])
    assert not HASH.admits([f"Bearer two {TOKEN}"])


def test_a_modern_head_keeps_its_method() -> None:
    assert check("modern") == Head(
        "POST", routing={"mcp-protocol-version": (), "mcp-method": (), "mcp-name": ()}
    )


def test_an_admitted_message_is_the_one_sent() -> None:
    session: Head[str] = Head("POST", "the session")
    relayed = body("legacy", session, BODY)
    assert isinstance(relayed, Admitted)
    assert relayed.message.raw == BODY
    for method in ("notifications/initialized", "notifications/cancelled", "notifications/x"):
        note = request(method, rpc_id=None)
        accepted = body("legacy", session, note)
        assert isinstance(accepted, Admitted)
        assert accepted.message.raw == note
    seen = modern_head(mcp_protocol_version=MODERN, mcp_method="tools/list")
    listed = modern("tools/list")
    modern_relayed = body("modern", seen, listed)
    assert isinstance(modern_relayed, Admitted)
    assert modern_relayed.message.raw == listed


def test_the_body_refusals_say_why() -> None:
    session: Head[str] = Head("POST", "the session")
    assert said(body("legacy", session, b"x")) == (
        400,
        -32600,
        "the body isn't one JSON-RPC request or notification",
        None,
    )
    assert said(body("modern", Head("POST"), b"x")) == said(body("legacy", session, b"x"))
    initialize = request("initialize", {"protocolVersion": LEGACY})
    assert said(body("legacy", session, initialize)) == (
        400,
        -32600,
        "Bad Request: initialize is sent without a session",
        7,
    )
    assert said(body("legacy", Head("POST"), BODY)) == (
        400,
        -32600,
        "Bad Request: missing session ID",
        1,
    )
    # From head, before any body: no id to answer.
    assert said(check("legacy", "GET", sent=headers(post=False))) == (
        400,
        -32600,
        "Bad Request: missing session ID",
        None,
    )
