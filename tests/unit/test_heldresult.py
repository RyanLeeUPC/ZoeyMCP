"""The stored answer's reader (M8 design F.5 step 5, B.8; O.3 ``test_heldresult.py``; CR-6, G-27).

JSON, and an event stream whose ``message`` events are read in order: notifications ignored, a
request from the server refusing ``upstream_input_required``, exactly one response to the held
request (its id, of its type), else ``unknown``; the event stream's own line and field rules;
an answer split at every byte boundary reads the same; and the forward's outcome (B.8), which
the vault's chain records, from the whole answer.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.unit.plainid import plain_id
from zoeymcp.common import heldresult, logs
from zoeymcp.common.heldresult import (
    Answered,
    EventReader,
    Unread,
    media_type,
    messages,
    outcome_of,
    read,
)

SSE = "text/event-stream"
JSON = "application/json"
RESULT: dict[str, Any] = {"content": [{"type": "text", "text": "done"}], "isError": False}


def response(id: Any = 1, **fields: Any) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": id, **(fields or {"result": RESULT})}).encode()


def event(data: bytes, kind: str | None = None) -> bytes:
    head = b"" if kind is None else b"event: " + kind.encode() + b"\n"
    return head + b"data: " + data + b"\n\n"


NOTIFICATION = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress"}).encode()
REQUEST = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "elicitation/create"}).encode()


def splits(body: bytes) -> list[list[bytes]]:
    """``body`` in two chunks at every boundary, and one byte at a time."""
    return [[body[:cut], body[cut:]] for cut in range(len(body) + 1)] + [
        [body[n : n + 1] for n in range(len(body))]
    ]


# --- the response -------------------------------------------------------------------------------


def test_a_json_answer_is_its_one_response() -> None:
    assert read(200, JSON, [response()], 1) == Answered(RESULT)
    assert read(201, "Application/JSON; charset=utf-8", [response()], 1) == Answered(RESULT)


def test_an_event_streams_message_events_are_read_in_order() -> None:
    body = event(NOTIFICATION, "message") + event(response(id="r-1"))
    assert read(200, SSE, [body], "r-1") == Answered(RESULT)


def test_an_error_response_is_answered_as_one() -> None:
    error = {"code": -32000, "message": "nope"}
    found = read(200, JSON, [response(error=error)], 1)
    assert found == Answered(None, error)
    assert isinstance(found, Answered)
    assert found.result is None


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        pytest.param(event(REQUEST) + event(response()), "upstream_input_required", id="request"),
        pytest.param(event(response()) + event(REQUEST), "upstream_input_required", id="late"),
        pytest.param(event(response()) + event(response()), "unknown", id="two-responses"),
        pytest.param(event(response(id=2)), "unknown", id="wrong-id"),
        pytest.param(event(response(id=2)) + event(response()), "unknown", id="another-id"),
        pytest.param(event(response(id="1")), "unknown", id="string-id"),
        pytest.param(event(response(id=1.0)), "unknown", id="float-id"),
        pytest.param(event(response(id=True)), "unknown", id="boolean-id"),
        pytest.param(event(NOTIFICATION), "unknown", id="no-response"),
        pytest.param(b"", "unknown", id="empty"),
        pytest.param(event(b"not json"), "unknown", id="not-json"),
        pytest.param(event(b"[1]"), "unknown", id="not-an-object"),
        pytest.param(event(response(result=[1])), "unknown", id="result-not-an-object"),
        pytest.param(event(response(other=1)), "unknown", id="neither"),
        pytest.param(event(b"[" * 100_000), "unknown", id="too-deep"),
    ],
)
def test_anything_but_one_response_is_unread(body: bytes, reason: str) -> None:
    assert read(200, SSE, [body], 1) == Unread(reason)  # type: ignore[arg-type]


def test_an_error_beside_a_result_is_the_error() -> None:
    assert read(200, JSON, [response(result=RESULT, error="x")], 1) == Answered(None, "x")


@pytest.mark.parametrize("status", [199, 300, 404, 500, 502])
def test_a_status_outside_2xx_is_unread(status: int) -> None:
    assert read(status, JSON, [response()], 1) == Unread("unknown")


@pytest.mark.parametrize("status", [200, 204, 299])
def test_any_2xx_is_read(status: int) -> None:
    assert read(status, JSON, [response()], 1) == Answered(RESULT)


@pytest.mark.parametrize("kind", ["text/plain", "application/x-ndjson", "", "application/jsonx"])
def test_another_content_type_has_no_message(kind: str) -> None:
    assert messages(kind, [response()]) is None
    assert read(200, kind, [response()], 1) == Unread("unknown")


def test_a_json_answer_in_chunks_is_joined() -> None:
    body = response()
    assert messages(JSON, [body[:5], body[5:]]) == [body]
    assert read(200, JSON, [body[:5], body[5:]], 1) == Answered(RESULT)


def test_the_media_type() -> None:
    assert media_type(" Text/Event-Stream ; charset=utf-8") == SSE
    assert media_type("application/json") == JSON
    assert heldresult.JSON_TYPE == JSON
    assert heldresult.SSE_TYPE == SSE


# --- the event stream's own rules ----------------------------------------------------------------


def events_of(body: bytes) -> list[bytes]:
    reader = EventReader()
    reader.feed(body)
    return reader.finish()


@pytest.mark.parametrize(
    ("body", "found"),
    [
        pytest.param(b"data: a\n\n", [b"a"], id="lf"),
        pytest.param(b"data: a\r\n\r\n", [b"a"], id="crlf"),
        pytest.param(b"data: a\r\r", [b"a"], id="cr"),
        pytest.param(b"data: a\ndata: b\n\n", [b"a\nb"], id="two-data-lines"),
        pytest.param(b"data:a\n\n", [b"a"], id="no-space"),
        pytest.param(b"data:  a\n\n", [b" a"], id="one-space-only"),
        pytest.param(b"data\n\n", [b""], id="no-colon"),
        pytest.param(b"data:\n\n", [b""], id="empty-data"),
        pytest.param(b": comment\ndata: a\n\n", [b"a"], id="comment"),
        pytest.param(b"id: 7\nretry: 5\nfoo: x\ndata: a\n\n", [b"a"], id="other-fields"),
        pytest.param(b"event: ping\ndata: a\n\ndata: b\n\n", [b"b"], id="another-event"),
        pytest.param(b"event: message\ndata: a\n\n", [b"a"], id="message-event"),
        pytest.param(b"event:\ndata: a\n\n", [b"a"], id="empty-event-type"),
        pytest.param(b"event: ping\n\ndata: a\n\n", [b"a"], id="event-type-resets"),
        pytest.param(b"\n\nevent: x\n\n", [], id="no-data-no-event"),
        pytest.param(b"data: a\n", [], id="left-open"),
        pytest.param(b"data: a", [], id="unterminated-line"),
        pytest.param(b"data: a\r", [], id="cr-at-the-end"),
        pytest.param(b"\xef\xbb\xbfdata: a\n\n", [b"a"], id="bom"),
        pytest.param(b"\xef\xbb\xbf\xef\xbb\xbfdata: a\n\n", [], id="second-bom-is-a-field"),
        pytest.param(b"\xef\xbbdata: a\n\n", [], id="half-a-bom"),
        pytest.param(b"data: a\n\ndata: b\n\n", [b"a", b"b"], id="two-events"),
        pytest.param(b"data: a\r\n\ndata: b\r\r\n", [b"a", b"b"], id="mixed-endings"),
    ],
)
def test_the_event_stream_rules(body: bytes, found: list[bytes]) -> None:
    assert events_of(body) == found


def test_a_bom_split_across_chunks_is_dropped() -> None:
    reader = EventReader()
    for chunk in (b"", b"\xef", b"\xbb", b"\xbf", b"data: a\n\n"):
        reader.feed(chunk)
    assert reader.finish() == [b"a"]


def test_a_crlf_split_across_chunks_is_one_line_end() -> None:
    reader = EventReader()
    reader.feed(b"data: a\r")
    reader.feed(b"\n")
    reader.feed(b"\r\n")
    assert reader.finish() == [b"a"]


def test_a_cr_then_more_is_a_line_end() -> None:
    reader = EventReader()
    reader.feed(b"data: a\r")
    reader.feed(b"\rdata: b\n\n")
    assert reader.finish() == [b"a", b"b"]


# --- G-27: an answer split at every byte boundary reads the same ---------------------------------

SPLIT_BODIES = [
    pytest.param(
        b"\xef\xbb\xbf: hi\r\nevent: message\r\ndata: "
        + NOTIFICATION
        + b"\r\n\r\ndata: "
        + response()[:20]
        + b"\r\ndata: "
        + response()[20:]
        + b"\r\r",
        id="crlf-cr-bom",
    ),
    pytest.param(event(NOTIFICATION) + event(response()) + b"data: x", id="left-open"),
    pytest.param(event(REQUEST), id="request"),
]


@pytest.mark.parametrize("body", SPLIT_BODIES)
def test_an_answer_split_at_every_byte_reads_the_same(body: bytes) -> None:
    whole = read(200, SSE, [body], 1)
    for chunks in splits(body):
        assert read(200, SSE, chunks, 1) == whole
    assert messages(SSE, [body]) == messages(SSE, splits(body)[-1])


PARTS = [b"data: ", b"data:", b"event: ping", b"event: message", b": c", b"x", b"\xef\xbb\xbf"]
PARTS += [b"\n", b"\r", b"\r\n", b"{}", b'{"a":1}', b"\xef", NOTIFICATION, response()]


@settings(max_examples=50, deadline=None)
@given(
    st.lists(st.sampled_from(PARTS), max_size=12),
    st.data(),
)
def test_any_stream_reads_the_same_in_any_chunks(parts: list[bytes], data: st.DataObject) -> None:
    body = b"".join(parts)
    cuts = sorted(data.draw(st.lists(st.integers(0, len(body)), max_size=4)))
    chunks = [body[a:b] for a, b in zip([0, *cuts], [*cuts, len(body)], strict=True)]
    assert messages(SSE, chunks) == messages(SSE, [body])


# --- B.8: the forward's outcome ---------------------------------------------------------------

OUTCOMES = [
    (200, JSON, b'{"jsonrpc":"2.0","id":1,"result":{"isError":false}}', "ok"),
    (200, JSON, b'{"jsonrpc":"2.0","id":1,"result":{}}', "ok"),
    (200, JSON, b'{"jsonrpc":"2.0","id":1,"result":{"isError":true}}', "tool_error"),
    (200, JSON, b'{"jsonrpc":"2.0","id":1,"result":{"isError":1}}', "ok"),
    (200, JSON, b'{"jsonrpc":"2.0","id":1,"error":{"code":-1}}', "upstream_error"),
    (200, JSON, b'{"jsonrpc":"2.0","id":2,"result":{}}', "upstream_error"),
    (500, JSON, b'{"jsonrpc":"2.0","id":1,"result":{}}', "upstream_error"),
    (200, "text/plain", b"ok", "upstream_error"),
    (
        200,
        SSE,
        b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n'
        b'data: {"jsonrpc":"2.0","id":1,\ndata: "result":{"isError":true}}\n\n',
        "tool_error",
    ),
    (200, SSE, b"data: not json\n\n", "upstream_error"),
    (200, SSE, event(REQUEST) + event(response()), "upstream_error"),
]


@pytest.mark.parametrize(("status", "content_type", "body", "outcome"), OUTCOMES, ids=plain_id)
def test_the_outcome_is_read_from_the_whole_answer(
    status: int, content_type: str, body: bytes, outcome: str
) -> None:
    assert outcome_of(status, content_type, body, 1) == outcome


def test_an_answer_hides_its_result_and_refuses_to_be_logged() -> None:
    """The result is what the tool returned: never in a log line (O.6)."""
    found = Answered({"secret": "result-sentinel-77"})
    assert repr(found) == "Answered(error=False)"
    assert repr(Answered(None, {"code": 1})) == "Answered(error=True)"
    log = logs.Log("gateway")
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        with pytest.raises(TypeError):
            log.event("probe", value=found)
    finally:
        logs.set_stream(None)
    assert stream.getvalue() == ""
