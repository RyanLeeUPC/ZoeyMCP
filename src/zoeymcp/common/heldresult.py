"""The stored answer's reader (M8 design F.5 step 5, B.8; CR-6, G-27). Pure, standard library only,
mutation-tested.

An approved held call's answer is read whole by the vault, which keeps it (B.6, B.8), and is read
again here: by the vault, to classify the forward's outcome for its chain, and by the gateway,
for the result ``check_approval`` hands over (vault code may not import the gateway's, so the one
reader is in ``common``). The answer is the upstream's own: its HTTP status, its content type
and its bytes.

- **Its messages.** ``application/json`` is one message; ``text/event-stream`` is read as the
  event stream it is (:class:`EventReader`: lines ended by CRLF, LF or CR, a leading BOM
  dropped, comments and fields other than ``event`` and ``data`` ignored), and its ``message``
  events are the messages, in order; an event left open at the end is dropped, as the stream's
  own rules drop it. Anything else has no message. The reader takes the bytes in any chunks, and
  an answer split at any byte boundary reads the same.
- **The response.** Notifications are ignored; a request from the server (it wants input the
  gateway doesn't relay, H13) refuses ``upstream_input_required``; and the answer must carry
  exactly one response, whose id is the held request's (the same type, a number never a
  boolean), else it is ``unknown``. So is a message that isn't a JSON object, and a status
  outside 2xx.
- **The outcome** (B.8): ``ok``, ``tool_error`` from the result's ``isError``, else
  ``upstream_error``: a JSON-RPC error, or an answer that isn't read as one response.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final, Literal

from .logs import refuse_type

Outcome = Literal["ok", "tool_error", "upstream_error"]
Reason = Literal["upstream_input_required", "unknown"]

JSON_TYPE: Final = "application/json"
SSE_TYPE: Final = "text/event-stream"
_BOM: Final = b"\xef\xbb\xbf"
_LINE_END: Final = re.compile(rb"\r\n?|\n")


@dataclass(frozen=True, repr=False)
class Answered:
    """The held request's one response: its ``result`` object, or its ``error``. Logging it
    raises: the result is what the tool returned."""

    result: dict[str, Any] | None
    error: object = None

    def __repr__(self) -> str:
        return f"Answered(error={self.error is not None})"


@dataclass(frozen=True)
class Unread:
    """Why the answer isn't one response to the held request."""

    reason: Reason


refuse_type(Answered)


def media_type(content_type: str) -> str:
    """A content type's media type, lowercased, without its parameters."""
    return content_type.lower().split(";", 1)[0].strip()


class EventReader:
    """An event stream's ``message`` events, as their data, from bytes in any chunks. A chunk
    costs time linear in the bytes buffered: each line is looked for from where the last one
    ended, and what was read is dropped once a chunk."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._started = False  # the leading BOM is behind
        self._kind = b""
        self._data: list[bytes] | None = None
        self._found: list[bytes] = []

    def feed(self, chunk: bytes) -> None:
        self._buffer += chunk
        if not self._started:
            if _BOM.startswith(self._buffer):
                return  # a BOM, or the start of one, so far
            self._started = True
            self._buffer = self._buffer.removeprefix(_BOM)
        self._lines(final=False)

    def finish(self) -> list[bytes]:
        """The data of every ``message`` event, in order. An event the stream left open (no
        blank line after it) is dropped."""
        self._lines(final=True)
        return self._found

    def _lines(self, *, final: bool) -> None:
        start = 0
        while True:
            cut = _line_end(self._buffer, start, final=final)
            if cut is None:
                break
            line, start = cut
            self._line(line)
        del self._buffer[:start]

    def _line(self, line: bytes) -> None:
        if not line:
            if self._data is not None and self._kind in (b"", b"message"):
                self._found.append(b"\n".join(self._data))
            self._kind, self._data = b"", None
            return
        if line.startswith(b":"):
            return  # a comment
        field, _, value = line.partition(b":")
        value = value.removeprefix(b" ")  # with no colon, there is no value
        if field == b"event":
            self._kind = value
        elif field == b"data":
            if self._data is None:
                self._data = []
            self._data.append(value)


def _line_end(buffer: bytearray, start: int, *, final: bool) -> tuple[bytes, int] | None:
    """The first whole line in ``buffer`` from ``start``, and where the next begins, or None.
    The search stops at the first line end, so no byte is searched twice. A CR at the end of
    the buffer may be the first half of a CRLF, so it ends a line only when the stream did."""
    found = _LINE_END.search(buffer, start)
    if found is None or (not final and found.group() == b"\r" and found.end() == len(buffer)):
        return None
    return bytes(buffer[start : found.start()]), found.end()


def messages(content_type: str, chunks: Iterable[bytes]) -> list[bytes] | None:
    """The answer's messages, each one JSON text: the whole body for JSON, an event stream's
    ``message`` events' data, or None for any other content type."""
    kind = media_type(content_type)
    if kind == JSON_TYPE:
        return [b"".join(chunks)]
    if kind != SSE_TYPE:
        return None
    reader = EventReader()
    for chunk in chunks:
        reader.feed(chunk)
    return reader.finish()


def read(
    status: int, content_type: str, chunks: Iterable[bytes], request_id: str | int
) -> Answered | Unread:
    """The response to the held request ``request_id`` in an answer, or why there is none."""
    if not 200 <= status <= 299:
        return Unread("unknown")
    found = messages(content_type, chunks)
    if found is None:
        return Unread("unknown")
    responses: list[dict[str, Any]] = []
    for text in found:
        message = _json(text)
        if not isinstance(message, dict):
            return Unread("unknown")
        if "method" in message:
            if "id" in message:
                return Unread("upstream_input_required")
            continue  # a notification
        if not _same_id(message.get("id"), request_id):
            return Unread("unknown")
        responses.append(message)
    if len(responses) != 1:
        return Unread("unknown")
    [response] = responses
    if "error" in response:
        return Answered(None, response["error"])
    result = response.get("result")
    if not isinstance(result, dict):
        return Unread("unknown")
    return Answered(result)


def outcome_of(status: int, content_type: str, body: bytes, request_id: str | int) -> Outcome:
    """The forward's outcome from its full answer (B.8)."""
    found = read(status, content_type, [body], request_id)
    if not isinstance(found, Answered) or found.result is None:
        return "upstream_error"
    return "tool_error" if found.result.get("isError") is True else "ok"


def _same_id(found: object, request_id: str | int) -> bool:
    """A response's id is the request's: equal and of the same type, so ``1.0`` and ``true``
    aren't ``1``, nor ``"1"``."""
    return type(found) is type(request_id) and found == request_id


def _json(text: bytes) -> Any:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None
