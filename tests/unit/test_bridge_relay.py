"""The relay's decisions (M7 design C.4, X14; SPEC-3, SPEC-4, TI-4, MISS-5, G10; O.2
``test_bridge_relay.py``).

Remapping (ids and progress tokens from one counter per child, rewritten in place so nothing else
is re-encoded), routing (answers, progress and listen notifications to their own exchange, the
rest to the GET stream or nowhere), local answers to the child's own requests, and the cancels:
two exchanges with the same id and the same progress token each get only their own progress, and
a cancel from one leaves the other untouched (O.4 X14).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from zoeymcp.bridge import relay
from zoeymcp.bridge.framing import Era, Message, parse
from zoeymcp.bridge.relay import (
    ID,
    IDS_MAX,
    PROGRESS_TOKEN,
    REQUEST_ID,
    SUBSCRIPTION,
    TOKEN,
    Broadcast,
    Deliver,
    Drop,
    Relay,
    Reply,
    cancelled,
    rewrite,
    span,
)


def message(data: bytes | str | dict[str, Any]) -> Message:
    if isinstance(data, dict):
        data = json.dumps(data)
    if isinstance(data, str):
        data = data.encode()
    parsed = parse(data)
    assert isinstance(parsed, Message)
    return parsed


def call(rpc_id: Any = 5, token: Any = None, method: str = "tools/call") -> Message:
    params: dict[str, Any] = {"name": "fetch"}
    if token is not None:
        params["_meta"] = {"progressToken": token}
    return message({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params})


def sent(line: bytes) -> dict[str, Any]:
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    value: dict[str, Any] = json.loads(line)
    return value


def answer(rpc_id: Any, result: Any = None) -> Message:
    return message({"jsonrpc": "2.0", "id": rpc_id, "result": result or {}})


def progress(token: Any, value: int = 1) -> Message:
    params = {"progressToken": token, "progress": value}
    return message({"jsonrpc": "2.0", "method": "notifications/progress", "params": params})


def outbound(relay_: Relay, request: Message, exchange: int) -> tuple[bytes, relay.Pending]:
    found = relay_.outbound(request, exchange)
    assert found is not None
    return found


# --- rewriting in place -------------------------------------------------------------------------


def test_span_finds_a_value_by_path() -> None:
    text = ' { "id" : 12 , "params": {"_meta": {"progressToken": "t\\"k"}, "x": [1, {"id": 3}]} } '
    assert text[slice(*span(text, ID))] == "12"  # type: ignore[misc]
    assert text[slice(*span(text, TOKEN))] == '"t\\"k"'  # type: ignore[misc]
    assert span(text, ("params", "x", "id")) is None
    assert span(text, ("nope",)) is None
    assert span(text, ("params", "nope")) is None
    assert span("{}", ID) is None
    assert span('{"params": {}}', TOKEN) is None
    # An escaped key is the same key.
    assert span('{"\\u0069d": 4}', ID) == (12, 13)
    # Only an object is descended into.
    assert span('{"params": "_meta"}', TOKEN) is None
    assert span('{"params": {"_meta": [1]}}', TOKEN) is None


def test_rewrite_keeps_every_other_byte() -> None:
    raw = b'{"result": {"t": "caf\\u00e9", "n": 1.0E5, "big": 18446744073709551616},\n "id": 4}'
    assert rewrite(raw, [(ID, '"original"')]) == raw.replace(b'"id": 4', b'"id": "original"')
    assert rewrite(raw, [(TOKEN, "1")]) == raw
    assert rewrite(raw, []) == raw
    two = b'{"id":1,"params":{"_meta":{"progressToken":"abc"}}}'
    assert (
        rewrite(two, [(TOKEN, "9"), (ID, "8")])
        == b'{"id":8,"params":{"_meta":{"progressToken":9}}}'
    )
    accented = '{"id":1,"x":"\u00e9\u4e2d"}'.encode()
    assert rewrite(accented, [(ID, "22")]) == '{"id":22,"x":"\u00e9\u4e2d"}'.encode()


# --- outbound -----------------------------------------------------------------------------------


def test_outbound_remaps_the_id_and_the_progress_token_from_one_counter() -> None:
    """MISS-5, SPEC-3."""
    child = Relay("legacy")
    line, pending = outbound(child, call(5, token="p-5"), exchange=10)
    assert sent(line)["id"] == 1
    assert sent(line)["params"]["_meta"]["progressToken"] == 2
    assert pending == relay.Pending(10, 5, "5", 1, '"p-5"', 2, False)
    line, pending = outbound(child, call("five"), exchange=11)
    assert sent(line)["id"] == 3
    assert pending == relay.Pending(11, "five", '"five"', 3)
    assert len(child) == 2


def test_outbound_sends_the_bytes_as_written() -> None:
    raw = (
        '{"jsonrpc": "2.0",\n  "id": "a\\u0062", "method": "tools/call", '
        '"params": {"arguments": {"n": 1.50, "s": "\\n"}}}'
    )
    line, pending = outbound(Relay("modern"), message(raw), 1)
    assert line == raw.replace('"a\\u0062"', "1").replace("\n", " ").encode() + b"\n"
    assert (pending.original_id, pending.id_text) == ("ab", '"a\\u0062"')


def test_every_progress_token_is_remapped() -> None:
    for token in (0, "", None, 1.5, [1], {"a": 1}):
        request = message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "m",
                "params": {"_meta": {"progressToken": token}},
            }
        )
        line, pending = outbound(Relay("modern"), request, 1)
        assert sent(line)["params"]["_meta"]["progressToken"] == 2
        assert pending.token_text == json.dumps(token)
    no_meta = message({"jsonrpc": "2.0", "id": 1, "method": "m", "params": {"_meta": "x"}})
    line, pending = outbound(Relay("modern"), no_meta, 1)
    assert (sent(line)["params"]["_meta"], pending.remapped_token) == ("x", None)


def test_a_listen_is_marked() -> None:
    _, pending = outbound(Relay("modern"), call(1, method=relay.LISTEN), 1)
    assert pending.listen
    _, pending = outbound(Relay("modern"), call(1, method="tools/list"), 1)
    assert not pending.listen


def test_at_most_ids_max_in_flight() -> None:
    assert IDS_MAX == 256
    child = Relay("modern", limit=2)
    outbound(child, call(1), 1)
    outbound(child, call(2), 2)
    assert child.outbound(call(3), 3) is None
    assert len(child) == 2
    assert isinstance(child.inbound(answer(1)), Deliver)
    assert child.outbound(call(3), 3) is not None
    assert Relay("legacy").limit == IDS_MAX


# --- inbound ------------------------------------------------------------------------------------


def test_an_answer_goes_to_its_exchange_with_its_id_restored() -> None:
    child = Relay("legacy")
    outbound(child, call('id "1"'), 7)
    raw = (
        b'{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"x"}],'
        b'"n":9007199254740993},"id":1}'
    )
    route = child.inbound(message(raw))
    assert route == Deliver(7, raw.replace(b'"id":1}', b'"id":"id \\"1\\""}'), True)
    assert len(child) == 0
    # Answered once only.
    assert child.inbound(message(raw)) == Drop("unmatched")
    assert child.unmatched == 1


def test_an_answer_to_an_id_never_sent_is_dropped_and_counted() -> None:
    child = Relay("legacy")
    outbound(child, call(5), 1)
    for rpc_id in (2, "1", True, 1.0, None):
        assert child.inbound(answer(rpc_id)) == Drop("unmatched")
    assert child.unmatched == 5
    error = message({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse"}})
    assert child.inbound(error) == Drop("unmatched")
    assert len(child) == 1


def test_two_exchanges_with_the_same_id_and_progress_token() -> None:
    """SPEC-3, TI-4: each gets only its own progress and its own answer."""
    child = Relay("modern")
    line_a, a = outbound(child, call(5, token=5), exchange=1)
    line_b, b = outbound(child, call(5, token=5), exchange=2)
    assert (sent(line_a)["id"], sent(line_a)["params"]["_meta"]["progressToken"]) == (1, 2)
    assert (sent(line_b)["id"], sent(line_b)["params"]["_meta"]["progressToken"]) == (3, 4)
    to_b = child.inbound(progress(4, 10))
    assert isinstance(to_b, Deliver)
    assert (to_b.exchange, to_b.final, json.loads(to_b.data)["params"]) == (
        2,
        False,
        {"progressToken": 5, "progress": 10},
    )
    to_a = child.inbound(progress(2, 20))
    assert isinstance(to_a, Deliver)
    assert (to_a.exchange, json.loads(to_a.data)["params"]["progress"]) == (1, 20)
    # A cancel from the first (its stream closed) leaves the second untouched.
    assert child.disconnect(1) == [cancelled(a.remapped)]
    assert child.inbound(progress(2)) == Drop("progress")
    later = child.inbound(progress(4, 30))
    assert isinstance(later, Deliver)
    assert later.exchange == 2
    done = child.inbound(answer(b.remapped))
    assert isinstance(done, Deliver)
    assert (done.exchange, done.final, json.loads(done.data)["id"]) == (2, True, 5)
    # Progress after the answer goes nowhere.
    assert child.inbound(progress(4)) == Drop("progress")


def test_progress_for_an_unknown_token_is_dropped() -> None:
    child = Relay("legacy")
    outbound(child, call(1, token="t"), 1)
    for token in (1, 3, "2", True, None, 2.0):
        assert child.inbound(progress(token)) == Drop("progress")
    assert isinstance(child.inbound(progress(2)), Deliver)
    # A request without a token has none to match.
    outbound(child, call(9), 2)
    assert child.inbound(progress(3)) == Drop("progress")
    assert child.unmatched == 0


def test_a_listen_notification_goes_to_its_stream() -> None:
    """C.4: the child echoes the remapped listen id as subscriptionId; it is restored."""
    child = Relay("modern")
    outbound(child, call(5), 1)
    outbound(child, call("sub", method=relay.LISTEN), 2)
    meta_key = relay.SUBSCRIPTION_META

    def changed(subscription: Any) -> Message:
        params = {"_meta": {meta_key: subscription}}
        return message(
            {"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": params}
        )

    route = child.inbound(changed(2))
    assert isinstance(route, Deliver)
    assert (route.exchange, route.final) == (2, False)
    assert json.loads(route.data)["params"]["_meta"][meta_key] == "sub"
    for other in (1, 3, "2", None, [2], {"a": 2}):
        assert child.inbound(changed(other)) == Drop("notification")
    no_meta = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"_meta": 2}}
    assert child.inbound(message(no_meta)) == Drop("notification")
    assert child.inbound(message({"jsonrpc": "2.0", "method": "notifications/message"})) == Drop(
        "notification"
    )
    # The listen's own answer ends its stream.
    end = child.inbound(answer(2))
    assert isinstance(end, Deliver)
    assert (end.exchange, end.final) == (2, True)
    assert child.inbound(changed(2)) == Drop("notification")


def test_a_legacy_notification_goes_to_the_get_stream() -> None:
    child = Relay("legacy")
    outbound(child, call(1, method=relay.LISTEN), 1)
    raw = (
        b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed",\r'
        b'"params":{"_meta":{"io.modelcontextprotocol/subscriptionId":1}}}'
    )
    assert child.inbound(message(raw)) == Broadcast(raw)
    assert child.inbound(
        message({"jsonrpc": "2.0", "method": "notifications/message"})
    ) == Broadcast(b'{"jsonrpc": "2.0", "method": "notifications/message"}')


def test_the_childs_requests_are_answered_never_relayed() -> None:
    """X14, G10: ping gets {}, anything else -32601, with the method to log."""
    child = Relay("legacy")
    ping = child.inbound(message('{"jsonrpc":"2.0","id":"p\\u0031","method":"ping"}'))
    assert ping == Reply(b'{"jsonrpc":"2.0","id":"p\\u0031","result":{}}\n')
    for method in ("sampling/createMessage", "elicitation/create", "roots/list"):
        route = child.inbound(message({"jsonrpc": "2.0", "id": 9, "method": method, "params": {}}))
        assert route == Reply(
            b'{"jsonrpc":"2.0","id":9,"error":'
            b'{"code":-32601,"message":"not supported by this bridge"}}\n',
            method,
        )
    hidden = "x\u202e" + "y" * 100
    route = child.inbound(message({"jsonrpc": "2.0", "id": 2**63, "method": hidden}))
    assert isinstance(route, Reply)
    assert route.refused == "x[U+202E]" + "y" * 62
    assert sent(route.line)["id"] == 2**63
    assert len(child) == 0


def test_an_invalid_message_is_dropped() -> None:
    child = Relay("legacy")
    assert child.inbound(message({"id": 1, "result": {}})) == Drop("invalid")
    assert child.inbound(message({"jsonrpc": "2.0", "id": None, "method": "m"})) == Drop("invalid")
    assert child.unmatched == 0


# --- cancels and endings ------------------------------------------------------------------------


def cancel(request_id: Any) -> Message:
    params = {"requestId": request_id, "reason": "user"}
    return message({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": params})


def test_a_legacy_cancel_is_resolved_within_its_session() -> None:
    """TI-4: each session has its own child, so its own relay; a cancel matches only there."""
    first, second = Relay("legacy"), Relay("legacy")
    outbound(first, call(5), 1)
    outbound(second, call(4), 2)
    _, other = outbound(second, call(5), 3)
    line = first.cancel(cancel(5))
    assert line is not None
    assert sent(line) == {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 1, "reason": "user"},
    }
    assert (
        second.cancel(cancel(5))
        == rewrite(cancel(5).raw, [(REQUEST_ID, str(other.remapped))]) + b"\n"
    )
    # Unknown ids, and ids of another type, are dropped.
    for request_id in (6, "5", True, None, 5.0):
        assert first.cancel(cancel(request_id)) is None
    assert first.cancel(message({"jsonrpc": "2.0", "method": "notifications/cancelled"})) is None
    # The request stays in flight until its answer or its exchange's end.
    assert len(first) == 1


def test_an_ambiguous_legacy_cancel_is_dropped() -> None:
    child = Relay("legacy")
    outbound(child, call(5), 1)
    outbound(child, call(5), 2)
    assert child.cancel(cancel(5)) is None


def test_a_modern_cancel_is_dropped() -> None:
    """MCP 2026-07-28: a client cancels by closing its stream, never by notification."""
    child = Relay("modern")
    outbound(child, call(5), 1)
    assert child.cancel(cancel(5)) is None


def test_a_legacy_disconnect_cancels_nothing() -> None:
    """SPEC-4: a disconnect isn't a cancel in 2025-11-25; the orphaned answer is dropped."""
    child = Relay("legacy")
    outbound(child, call(5, token=1), 1)
    outbound(child, call(6), 2)
    assert child.disconnect(1) == []
    assert len(child) == 1
    assert child.inbound(progress(2)) == Drop("progress")
    assert child.inbound(answer(1)) == Drop("orphaned")
    assert child.unmatched == 0
    # Dropped once: a second answer to it is unmatched.
    assert child.inbound(answer(1)) == Drop("unmatched")
    assert child.unmatched == 1
    assert child.disconnect(99) == []


def test_a_legacy_cancel_reaches_a_request_whose_exchange_ended() -> None:
    """FM-20: the gateway's ``call_timeout`` closes the stream, then cancels; the cancel still
    reaches the child, and the late answer is still dropped."""
    child = Relay("legacy")
    outbound(child, call(5), 1)
    child.disconnect(1)
    line = child.cancel(cancel(5))
    assert line is not None
    assert sent(line)["params"]["requestId"] == 1
    assert child.inbound(answer(1)) == Drop("orphaned")
    # Answered, it is forgotten.
    assert child.cancel(cancel(5)) is None
    # One in flight and one orphaned with the same id: ambiguous, dropped.
    outbound(child, call(6), 2)
    child.disconnect(2)
    outbound(child, call(6), 3)
    assert child.cancel(cancel(6)) is None
    # A modern relay keeps no orphan for a cancel.
    modern = Relay("modern")
    outbound(modern, call(5), 1)
    modern.disconnect(1)
    assert modern.cancel(cancel(5)) is None


def test_a_modern_disconnect_cancels_that_exchanges_requests() -> None:
    child = Relay("modern")
    outbound(child, call(1), 1)
    outbound(child, call(2, method=relay.LISTEN), 1)
    outbound(child, call(3), 2)
    assert child.disconnect(1) == [cancelled(1), cancelled(2)]
    assert (
        cancelled(7)
        == b'{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}\n'
    )
    assert len(child) == 1
    assert child.inbound(answer(1)) == Drop("orphaned")
    assert isinstance(child.inbound(answer(3)), Deliver)


def test_orphans_are_bounded() -> None:
    child = Relay("modern", limit=2)
    for exchange in range(1, 4):
        outbound(child, call(exchange), exchange)
        child.disconnect(exchange)
    # The oldest orphan was forgotten: its late answer counts as unmatched.
    assert child.inbound(answer(1)) == Drop("unmatched")
    assert child.inbound(answer(2)) == Drop("orphaned")
    assert child.inbound(answer(3)) == Drop("orphaned")
    assert child.unmatched == 1


def test_a_child_that_dies_fails_every_request_in_flight() -> None:
    child = Relay("legacy")
    _, first = outbound(child, call(1, token=9), 1)
    outbound(child, call(2), 2)
    child.disconnect(2)
    gone = child.fail()
    assert gone == [first]
    assert len(child) == 0
    assert child.inbound(progress(2)) == Drop("progress")
    assert child.inbound(answer(2)) == Drop("unmatched")
    assert child.fail() == []


def test_the_paths() -> None:
    assert (ID, TOKEN, PROGRESS_TOKEN, REQUEST_ID) == (
        ("id",),
        ("params", "_meta", "progressToken"),
        ("params", "progressToken"),
        ("params", "requestId"),
    )
    assert SUBSCRIPTION == ("params", "_meta", "io.modelcontextprotocol/subscriptionId")
    assert (relay.NOT_SUPPORTED, relay.METHOD_SHOWN_MAX) == (-32601, 64)


@pytest.mark.parametrize("era", ["legacy", "modern"])
def test_the_counter_is_the_childs(era: Era) -> None:
    first, second = Relay(era), Relay(era)
    assert sent(outbound(first, call(1), 1)[0])["id"] == 1
    assert sent(outbound(second, call(1), 1)[0])["id"] == 1
    assert sent(outbound(first, call(1), 2)[0])["id"] == 2


# The integers whose text is at most 20 characters: canonical's strict parser refuses longer.
LEAST, MOST = -(10**19) + 1, 10**19
INTS = st.integers(LEAST, MOST)

JSON = st.recursive(
    st.none()
    | st.booleans()
    | INTS
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=4), children, max_size=3)
    ),
    max_leaves=12,
)


@settings(max_examples=50, deadline=None)
@given(
    params=st.dictionaries(st.text(max_size=4), JSON, max_size=3),
    result=JSON,
    rpc_id=INTS | st.text(max_size=8),
    indent=st.sampled_from([None, 2]),
    ascii_only=st.booleans(),
)
@example(params={"n": MOST}, result=LEAST, rpc_id=LEAST, indent=None, ascii_only=False)
@example(params={"n": LEAST}, result=MOST, rpc_id=MOST, indent=None, ascii_only=False)
def test_only_the_id_changes_on_the_way_out_and_back(
    params: dict[str, Any], result: Any, rpc_id: Any, indent: int | None, ascii_only: bool
) -> None:
    """CR-6: every other byte of the request and of the answer passes as written."""

    def dumps(value: Any) -> bytes:
        return json.dumps(value, indent=indent, ensure_ascii=ascii_only).encode()

    head = b'{"jsonrpc": "2.0", "method": "tools/call", "params": ' + dumps(params)
    request = head + b', "id": ' + dumps(rpc_id) + b"}"
    child = Relay("modern")
    line, pending = outbound(child, message(request), 3)
    expected = (head + b', "id": 1}').replace(b"\r", b" ").replace(b"\n", b" ")
    assert line == expected + b"\n"
    body = b'{"jsonrpc": "2.0", "result": ' + dumps(result)
    route = child.inbound(message(body + b', "id": 1}'))
    assert route == Deliver(3, body + b', "id": ' + dumps(rpc_id) + b"}", True)
    assert pending.id_text == dumps(rpc_id).decode()
