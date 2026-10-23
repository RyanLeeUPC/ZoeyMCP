"""The bridge's wire format (M7 design C.3, C.4, X14, TI-13, CR-6). Pure and mutation-tested;
:mod:`.child` and :mod:`.server` read and write around these decisions.

- **From the child** (stdout): :func:`next_line` reads one line of at most
  ``--max-message-bytes`` from an :class:`asyncio.StreamReader` whose ``limit`` is that cap
  (contract 47), and :func:`parse` makes it one strict JSON object with the bridge's caps: its
  own size cap, depth :data:`MAX_DEPTH` and integers of any size. ``loads_strict``'s defaults
  (1 MiB, depth 64, safe integers only) would end a child for a 2 MiB result or a 64-bit id that
  a remote server could send through the vault unharmed (CR-6). A longer line, a line that isn't
  JSON, a batch (the protocol floor refuses batching) or any other JSON value is a
  :class:`Violation`, which ends that child. Blank lines are skipped.
- **To the child** and **to the client**: :func:`to_line` and :func:`sse_event` carry a message's
  bytes as they are, so nothing is re-encoded; only JSON's insignificant CR and LF become spaces,
  so one message is one line, and one SSE event.
- **stderr**: counted by default, never shown (TI-13), because a child commonly prints its
  configuration, ``--env`` values and fetched content included. ``--stderr text`` is the
  operator's opt-in (:class:`StderrLog`), refused for a bridge that holds a secret.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ..common.canonical import JSONRejected, loads_strict
from ..common.textrules import reveal_hidden

# M7 design C.3, C.4 and M.6.
MESSAGE_MAX: Final = 8 * 1024 * 1024
MAX_DEPTH: Final = 128
KEEPALIVE_INTERVAL: Final = 15.0
KEEPALIVE: Final = b": keepalive\n\n"
STDERR_WINDOW: Final = 10.0
STDERR_LINE_MAX: Final = 2048
STDERR_LINES_MAX: Final = 50
STDERR_TEXT_REFUSED: Final = "a bridge that holds a secret logs stderr as counts only"

Era = Literal["legacy", "modern"]
# The protocol versions each era serves, restated: the bridge imports no MCP SDK (mcp_types'
# HANDSHAKE_PROTOCOL_VERSIONS and MODERN_PROTOCOL_VERSIONS).
LEGACY_VERSIONS: Final = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MODERN_VERSIONS: Final = ("2026-07-28",)

ViolationReason = Literal["too_long", "invalid_json", "batch", "not_object"]
Kind = Literal["request", "notification", "response", "invalid"]
StderrMode = Literal["counts", "text"]
# A log line: its event and fields.
LogLine = tuple[str, dict[str, Any]]

# JSON's whitespace; any CR or LF in a valid JSON text is one of these, never inside a string.
_BREAKS: Final = (b"\r", b"\n")
_SPACE: Final = b" \t\r\n"


@dataclass(frozen=True)
class Violation:
    """Why a line from the child ends it (logged ``bridge_child_violation``)."""

    reason: ViolationReason


@dataclass(frozen=True)
class Message:
    """One JSON object: its bytes as received, without surrounding whitespace, and its value."""

    raw: bytes
    value: dict[str, Any] = field(compare=False)

    @property
    def kind(self) -> Kind:
        return kind(self.value)


def is_id(value: object) -> bool:
    """A JSON-RPC id as MCP allows it: a string or an integer (never null or a boolean)."""
    return isinstance(value, str) or type(value) is int


def kind(message: Mapping[str, Any]) -> Kind:
    """What a JSON-RPC 2.0 message is. ``params``, when present, must be an object (MCP's
    params always are); a response carries exactly one of ``result`` and ``error``."""
    if message.get("jsonrpc") != "2.0":
        return "invalid"
    if "params" in message and not isinstance(message["params"], dict):
        return "invalid"
    if "method" in message:
        if not isinstance(message["method"], str) or "result" in message or "error" in message:
            return "invalid"
        if "id" not in message:
            return "notification"
        return "request" if is_id(message["id"]) else "invalid"
    if "params" in message or "id" not in message or ("result" in message) == ("error" in message):
        return "invalid"
    return "response"


def parse(data: bytes, max_bytes: int = MESSAGE_MAX) -> Message | Violation | None:
    """One message from a line (or a request body): None for a blank one."""
    raw = data.strip(_SPACE)
    if not raw:
        return None
    if len(raw) > max_bytes:
        return Violation("too_long")
    try:
        value = loads_strict(raw, max_bytes=max_bytes, max_depth=MAX_DEPTH, safe_integers=False)
    except JSONRejected:
        return Violation("invalid_json")
    if isinstance(value, list):
        return Violation("batch")
    if not isinstance(value, dict):
        return Violation("not_object")
    return Message(raw, value)


async def next_line(reader: asyncio.StreamReader) -> bytes | Literal["too_long", "eof"]:
    """The next line from the child's stdout, without its newline. A line longer than the
    reader's ``limit`` is ``too_long`` (the stream is then usable for nothing, contract 47); the
    end of the stream is ``eof``, and so is a last line the child never ended."""
    try:
        line = await reader.readline()
    except (asyncio.LimitOverrunError, ValueError):
        return "too_long"
    if not line.endswith(b"\n"):
        return "eof"
    return line[:-1]


def _one_line(raw: bytes) -> bytes:
    for byte in _BREAKS:
        raw = raw.replace(byte, b" ")
    return raw


def to_line(raw: bytes) -> bytes:
    """A message as one line for the child's stdin."""
    return _one_line(raw) + b"\n"


def sse_event(raw: bytes) -> bytes:
    """A message as one SSE event (one event per message, contract 49). A CR would end an SSE
    line, so none stays in the data."""
    return b"event: message\ndata: " + _one_line(raw) + b"\n\n"


def stderr_line(data: bytes) -> str:
    """One stderr line as ``--stderr text`` logs it: cut at :data:`STDERR_LINE_MAX` bytes, its
    line ending dropped, every hidden character shown."""
    text = data[:STDERR_LINE_MAX].decode("utf-8", "replace").rstrip("\r\n")
    return reveal_hidden(text)


def check_stderr_mode(mode: StderrMode, holds_secret: bool) -> None:
    """Refuse ``--stderr text`` with any ``--secret-env``: the secret could be printed."""
    if mode == "text" and holds_secret:
        raise ValueError(STDERR_TEXT_REFUSED)


class StderrLog:
    """One child's stderr, in windows of :data:`STDERR_WINDOW` seconds.

    ``counts`` (the default) logs only how many lines and bytes each window saw
    (``bridge_stderr`` with ``lines`` and ``bytes``), never text. ``text`` logs each line
    (``bridge_stderr`` with ``text``), at most :data:`STDERR_LINES_MAX` a window, then one
    ``bridge_stderr_suppressed`` with the count left out when the window ends. A window ends at
    the first line or :meth:`tick` at least :data:`STDERR_WINDOW` after it began.
    """

    def __init__(self, mode: StderrMode, now: float) -> None:
        self.mode = mode
        self._start = now
        self._lines = 0
        self._bytes = 0

    def line(self, data: bytes, now: float, size: int | None = None) -> list[LogLine]:
        """What to log for one line, as read (its length counts its newline). ``size`` is the
        whole line's length when ``data`` holds only its start (a reader keeps no more than a
        logged line shows)."""
        out = self.tick(now)
        self._lines += 1
        self._bytes += len(data) if size is None else size
        if self.mode == "text" and self._lines <= STDERR_LINES_MAX:
            out.append(("bridge_stderr", {"text": stderr_line(data)}))
        return out

    def tick(self, now: float) -> list[LogLine]:
        """End the window if it has run its time."""
        if now - self._start < STDERR_WINDOW:
            return []
        out = self.close()
        self._start = now
        return out

    def close(self) -> list[LogLine]:
        """End the window now (the child ended): what it saw that isn't logged yet."""
        out: list[LogLine] = []
        if self.mode == "counts" and self._lines:
            out.append(("bridge_stderr", {"lines": self._lines, "bytes": self._bytes}))
        if self.mode == "text" and self._lines > STDERR_LINES_MAX:
            out.append(("bridge_stderr_suppressed", {"count": self._lines - STDERR_LINES_MAX}))
        self._lines = 0
        self._bytes = 0
        return out
