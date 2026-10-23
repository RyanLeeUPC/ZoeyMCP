"""The bridge's wire format (M7 design C.3, C.4, X14, TI-13, CR-6; O.2 ``test_bridge_framing.py``).

Each rule both ways and both sides of every cap: a line from the child is one strict JSON object
under the bridge's own caps (a 2 MiB line and a 2^63 integer pass), anything else ends the child;
a message's bytes go to the child and the client as they are, one line and one event; stderr is
counted unless the operator opts in to text.
"""

from __future__ import annotations

import asyncio
import json

import anyio
import pytest

from zoeymcp.bridge import framing
from zoeymcp.bridge.framing import (
    KEEPALIVE,
    MAX_DEPTH,
    MESSAGE_MAX,
    STDERR_LINE_MAX,
    STDERR_LINES_MAX,
    STDERR_TEXT_REFUSED,
    STDERR_WINDOW,
    Message,
    StderrLog,
    Violation,
    check_stderr_mode,
    is_id,
    kind,
    next_line,
    parse,
    sse_event,
    stderr_line,
    to_line,
)

MIB = 1024 * 1024


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_the_constants() -> None:
    """M7 design C.3, C.4 and M.6."""
    assert (MESSAGE_MAX, MAX_DEPTH) == (8 * MIB, 128)
    assert framing.KEEPALIVE_INTERVAL == 15.0
    assert KEEPALIVE == b": keepalive\n\n"
    assert (STDERR_WINDOW, STDERR_LINE_MAX, STDERR_LINES_MAX) == (10.0, 2048, 50)
    assert framing.LEGACY_VERSIONS == ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
    assert framing.MODERN_VERSIONS == ("2026-07-28",)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, "request"),
        ({"jsonrpc": "2.0", "id": "a", "method": "m", "params": {}}, "request"),
        ({"jsonrpc": "2.0", "method": "notifications/initialized"}, "notification"),
        ({"jsonrpc": "2.0", "method": "m", "params": {"a": 1}}, "notification"),
        ({"jsonrpc": "2.0", "id": 1, "result": {}}, "response"),
        ({"jsonrpc": "2.0", "id": None, "error": {"code": 1, "message": "x"}}, "response"),
        ({"id": 1, "method": "m"}, "invalid"),
        ({"jsonrpc": "1.0", "id": 1, "method": "m"}, "invalid"),
        ({"jsonrpc": "2.0", "id": 1, "method": 5}, "invalid"),
        ({"jsonrpc": "2.0", "id": None, "method": "m"}, "invalid"),
        ({"jsonrpc": "2.0", "id": True, "method": "m"}, "invalid"),
        ({"jsonrpc": "2.0", "id": 1.0, "method": "m"}, "invalid"),
        ({"jsonrpc": "2.0", "id": 1, "method": "m", "params": [1]}, "invalid"),
        ({"jsonrpc": "2.0", "method": "m", "params": None}, "invalid"),
        ({"jsonrpc": "2.0", "id": 1, "method": "m", "result": {}}, "invalid"),
        ({"jsonrpc": "2.0", "method": "m", "error": {}}, "invalid"),
        ({"jsonrpc": "2.0", "id": 1}, "invalid"),
        ({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}}, "invalid"),
        ({"jsonrpc": "2.0", "result": {}}, "invalid"),
        ({"jsonrpc": "2.0", "id": 1, "result": {}, "params": {}}, "invalid"),
    ],
)
def test_kind(message: dict[str, object], expected: str) -> None:
    assert kind(message) == expected


def test_an_id_is_a_string_or_an_integer() -> None:
    assert is_id("x")
    assert is_id(0)
    assert is_id(2**63)
    assert not is_id(None)
    assert not is_id(True)
    assert not is_id(1.0)
    assert not is_id([1])


def test_a_line_is_one_strict_json_object() -> None:
    line = b'  {"jsonrpc":"2.0","id":1,"method":"ping"}\r'
    parsed = parse(line)
    assert parsed == Message(b'{"jsonrpc":"2.0","id":1,"method":"ping"}', {})
    assert isinstance(parsed, Message)
    assert parsed.value == {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert parsed.kind == "request"


@pytest.mark.parametrize("line", [b"", b"   ", b"\t\r", b"\r\n"])
def test_a_blank_line_is_skipped(line: bytes) -> None:
    assert parse(line) is None


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (b"not json", "invalid_json"),
        (b'{"a": 1,}', "invalid_json"),
        (b'{"a": 1, "a": 2}', "invalid_json"),
        (b'{"a": NaN}', "invalid_json"),
        (b'{"a": "\xff"}', "invalid_json"),
        (b'{"a": 1} {"b": 2}', "invalid_json"),
        (b'[{"jsonrpc": "2.0", "method": "m"}]', "batch"),
        (b"[]", "batch"),
        (b'"text"', "not_object"),
        (b"5", "not_object"),
        (b"null", "not_object"),
    ],
)
def test_anything_else_ends_the_child(line: bytes, reason: str) -> None:
    assert parse(line) == Violation(reason)  # type: ignore[arg-type]


def test_the_size_cap_is_the_bridges() -> None:
    body = b'{"a":"' + b"x" * 100 + b'"}'
    assert isinstance(parse(body, len(body)), Message)
    assert parse(body, len(body) - 1) == Violation("too_long")
    # Surrounding whitespace doesn't count.
    assert isinstance(parse(b"  " + body + b"\n", len(body)), Message)


def test_a_2_mib_line_and_a_2_63_integer_pass() -> None:
    """CR-6: the defaults of loads_strict (1 MiB, safe integers) would end the child."""
    big = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"t": "x" * (2 * MIB)}}).encode()
    assert len(big) > 2 * MIB
    parsed = parse(big)
    assert isinstance(parsed, Message)
    assert len(parsed.value["result"]["t"]) == 2 * MIB
    huge = parse(b'{"jsonrpc":"2.0","id":9223372036854775808,"result":{"n":-9223372036854775808}}')
    assert isinstance(huge, Message)
    assert huge.value["id"] == 2**63
    assert huge.value["result"]["n"] == -(2**63)
    # The default cap is the bridge's own.
    over = b'{"t":"' + b"x" * (MESSAGE_MAX - 7) + b'"}'
    assert len(over) == MESSAGE_MAX + 1
    assert parse(over) == Violation("too_long")
    assert isinstance(parse(over[:-3] + b'"}'), Message)


def test_nesting_to_the_bridges_depth_passes() -> None:
    def nested(levels: int) -> bytes:
        return b'{"a":' * (levels - 1) + b"{}" + b"}" * (levels - 1)

    assert isinstance(parse(nested(MAX_DEPTH)), Message)
    assert parse(nested(MAX_DEPTH + 1)) == Violation("invalid_json")


async def read(data: bytes, limit: int, *, eof: bool = True) -> list[bytes | str]:
    reader = asyncio.StreamReader(limit=limit)
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    found: list[bytes | str] = []
    with anyio.fail_after(5):
        while not found or found[-1] not in ("eof", "too_long"):
            found.append(await next_line(reader))
    return found


@pytest.mark.anyio
async def test_next_line_reads_lines_up_to_the_limit() -> None:
    assert await read(b"a\nbb\n\n", 4) == [b"a", b"bb", b"", "eof"]
    assert await read(b"abcd\n", 4) == [b"abcd", "eof"]
    assert await read(b"abcde\n", 4) == ["too_long"]
    # A longer line is too long before it ends.
    assert await read(b"abcdef", 4, eof=False) == ["too_long"]


@pytest.mark.anyio
async def test_next_line_at_the_end() -> None:
    assert await read(b"", 4) == ["eof"]
    # A last line the child never ended isn't a message.
    assert await read(b"a\nbc", 4) == [b"a", "eof"]


@pytest.mark.anyio
async def test_next_line_passes_a_2_mib_line_at_the_default_limit() -> None:
    line = b"x" * (2 * MIB)
    assert await read(line + b"\n", MESSAGE_MAX) == [line, "eof"]


def test_a_message_goes_to_the_child_as_one_line() -> None:
    raw = b'{"a":\r\n "b\\n",\n"c":1}'
    assert to_line(raw) == b'{"a":   "b\\n", "c":1}\n'
    assert json.loads(to_line(raw)) == json.loads(raw)
    assert to_line(b"{}") == b"{}\n"


def test_a_message_goes_to_the_client_as_one_event() -> None:
    assert sse_event(b'{"a":1}') == b'event: message\ndata: {"a":1}\n\n'
    # A CR would end the SSE line; JSON's own whitespace becomes a space.
    assert sse_event(b'{"a":\r1,\n"b":2}') == b'event: message\ndata: {"a": 1, "b":2}\n\n'


def test_stderr_text_is_cut_and_revealed() -> None:
    assert stderr_line(b"hello\r\n") == "hello"
    assert stderr_line(b"tab\there\n") == "tab\there"
    assert stderr_line("a\u202eb\x1b[31m\n".encode()) == "a[U+202E]b[U+001B][31m"
    assert stderr_line(b"\xff") == "\ufffd"
    long = b"y" * (STDERR_LINE_MAX + 10) + b"\n"
    assert stderr_line(long) == "y" * STDERR_LINE_MAX
    assert stderr_line(b"z" * (STDERR_LINE_MAX - 1) + b"\n") == "z" * (STDERR_LINE_MAX - 1)


def test_stderr_text_is_refused_with_a_secret() -> None:
    with pytest.raises(ValueError, match=f"^{STDERR_TEXT_REFUSED}$"):
        check_stderr_mode("text", True)
    check_stderr_mode("text", False)
    check_stderr_mode("counts", True)
    assert STDERR_TEXT_REFUSED == "a bridge that holds a secret logs stderr as counts only"


def test_stderr_counts_by_default_never_text() -> None:
    log = StderrLog("counts", 100.0)
    assert log.line(b"SECRET=1\n", 100.0) == []
    assert log.line(b"more\n", 105.0) == []
    assert log.tick(109.999) == []
    assert log.tick(110.0) == [("bridge_stderr", {"lines": 2, "bytes": 14})]
    # The next window starts at that tick and is empty until a line arrives.
    assert log.tick(125.0) == []
    assert log.line(b"x\n", 125.5) == []
    assert log.line(b"yy\n", 135.5) == [("bridge_stderr", {"lines": 1, "bytes": 2})]
    assert log.close() == [("bridge_stderr", {"lines": 1, "bytes": 3})]
    assert log.close() == []


def test_a_lines_size_counts_what_its_reader_kept_back() -> None:
    """``child.py`` keeps only a line's start; the count is the whole line's (FM-22)."""
    log = StderrLog("counts", 100.0)
    assert log.line(b"x" * 10, 100.0, 65537) == []
    assert log.line(b"y\n", 100.0, None) == []
    assert log.line(b"", 100.0, 0) == []
    assert log.close() == [("bridge_stderr", {"lines": 3, "bytes": 65539})]
    shown = StderrLog("text", 100.0)
    assert shown.line(b"abc\n", 100.0, 9999) == [("bridge_stderr", {"text": "abc"})]


def test_stderr_text_is_rate_limited() -> None:
    log = StderrLog("text", 0.0)
    shown = [log.line(f"line {n}\n".encode(), 1.0) for n in range(STDERR_LINES_MAX + 3)]
    assert shown[0] == [("bridge_stderr", {"text": "line 0"})]
    assert shown[STDERR_LINES_MAX - 1] == [
        ("bridge_stderr", {"text": f"line {STDERR_LINES_MAX - 1}"})
    ]
    assert shown[STDERR_LINES_MAX:] == [[], [], []]
    assert log.tick(9.0) == []
    first = log.line(b"next\n", 10.0)
    assert first == [
        ("bridge_stderr_suppressed", {"count": 3}),
        ("bridge_stderr", {"text": "next"}),
    ]
    # No counts in text mode, and no suppressed line for a window under the cap.
    assert log.close() == []


def test_stderr_text_at_the_cap_suppresses_nothing() -> None:
    log = StderrLog("text", 0.0)
    for _ in range(STDERR_LINES_MAX):
        assert log.line(b"x\n", 0.0) != []
    assert log.close() == []
    log.line(b"x\n", 0.0)
    assert log.close() == []
