"""The stream scrubbers in ``vault/request.py`` (M3 design J.2).

An SSE stream is scrubbed one event at a time and NDJSON one line at a time, so a secret split
across chunks is still caught, and nothing is held beyond the event or line it's in.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.vault import request
from zoeymcp.vault.request import (
    MAX_STREAM_EVENT_BYTES,
    NDJSONScrubber,
    SSEScrubber,
    StreamEventTooLarge,
    scrub,
    secret_variants,
)

SECRET = 'fake/key>?+01="x"'
VARIANTS = secret_variants(SECRET)


def run(scrubber: SSEScrubber | NDJSONScrubber, chunks: list[bytes]) -> list[bytes]:
    """What each feed released, then what finish released."""
    return [scrubber.feed(chunk) for chunk in chunks] + [scrubber.finish()]


class CountingSearch:
    """Stands in for a line-break pattern and adds up the bytes each search may look at."""

    def __init__(self, pattern: re.Pattern[bytes]) -> None:
        self.pattern = pattern
        self.looked_at = 0

    def search(self, held: bytearray, pos: int) -> re.Match[bytes] | None:
        self.looked_at += len(held) - pos
        return self.pattern.search(held, pos)


# A long line in small chunks: 1 MiB in 1 KiB pieces. Looking at the whole line again on every
# chunk would mean about 512 MiB.
LONG_LINE = [b"x" * 1024] * 1024


def test_the_limit() -> None:
    assert MAX_STREAM_EVENT_BYTES == 17 * 1024 * 1024
    assert str(StreamEventTooLarge(9)) == "a stream event of at least 9 bytes is over the limit"
    assert StreamEventTooLarge(9).size == 9


def test_every_variant_has_its_own_form() -> None:
    # Raw, percent-encoded both ways, JSON-escaped with "/" kept and as "\/", base64 and
    # base64url: all different.
    assert len(VARIANTS) == 7
    assert all(b"\n" not in v and b"\r" not in v for v in VARIANTS)


def test_json_escaped_variants_with_and_without_an_escaped_solidus() -> None:
    a_umlaut = chr(0xE4)
    secret = f"k/{a_umlaut}y-key"
    variants = secret_variants(secret)
    assert b"k/\\u00e4y-key" in variants
    assert b"k\\/\\u00e4y-key" in variants
    assert secret.encode() in variants
    assert f"k\\/{a_umlaut}y-key".encode() in variants
    assert len(variants) == 8


# --- SSE -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event",
    [
        b"data: a\n\n",
        b"data: a\r\n\r\n",
        b"data: a\r\r",
        b"data: a\n\r\n",
        b"data: a\r\n\n",
        b"data: a\n\r",
        b"data: a\r\n\r",
        b"id: 1\ndata: a\ndata: b\n\n",
        b"\n",
        b"\r\n",
        b"\r",
    ],
)
def test_an_event_is_released_when_it_ends(event: bytes) -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(event) == event
    assert scrubber.finish() == b""


@pytest.mark.parametrize(
    ("partial", "rest"),
    [
        (b"data: a", b"\n\n"),
        (b"data: a\n", b"\n"),
        (b"data: a\r\n", b"\r\n"),
        (b"data: a\r", b"\n\n"),
        (b"data: a\r", b"\r"),
    ],
)
def test_an_event_is_held_until_it_ends(partial: bytes, rest: bytes) -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(partial) == b""
    assert scrubber.feed(rest) == partial + rest


def test_a_secret_split_across_chunks_is_caught() -> None:
    event = b"data: " + SECRET.encode() + b"\n\n"
    for cut in range(1, len(event)):
        scrubber = SSEScrubber(VARIANTS)
        released = run(scrubber, [event[:cut], event[cut:]])
        assert b"".join(released) == b"data: [REDACTED]\n\n"
        assert scrubber.scrubbed == 1


@pytest.mark.parametrize("variant", VARIANTS)
def test_each_form_is_caught_split_in_half(variant: bytes) -> None:
    event = b'data: {"error": "bad key ' + variant + b'"}\n\n'
    middle = event.index(variant) + len(variant) // 2
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(event[:middle]) == b""
    assert scrubber.feed(event[middle:]) == b'data: {"error": "bad key [REDACTED]"}\n\n'
    assert scrubber.scrubbed == 1


def test_several_events_in_one_chunk() -> None:
    scrubber = SSEScrubber(VARIANTS)
    secret = SECRET.encode()
    released = scrubber.feed(b"data: 1\n\ndata: " + secret + b"\n\ndata: 3")
    assert released == b"data: 1\n\ndata: [REDACTED]\n\n"
    assert scrubber.feed(b"\n\n") == b"data: 3\n\n"
    assert scrubber.scrubbed == 1


def test_scrubbed_counts_every_replacement() -> None:
    scrubber = SSEScrubber(VARIANTS)
    secret = SECRET.encode()
    scrubber.feed(b"data: " + secret + b" " + secret + b"\n\n")
    scrubber.feed(b"data: " + VARIANTS[-1] + b"\n\n")
    assert scrubber.scrubbed == 3


def test_a_comment_first_in_an_event_passes_at_once() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b": ping\n") == b": ping\n"
    assert scrubber.feed(b":\r\n") == b":\r\n"
    assert scrubber.feed(b": ping\r") == b": ping\r"
    assert scrubber.feed(b"\n") == b"\n"
    assert scrubber.feed(b": partial") == b""
    assert scrubber.feed(b" line\n") == b": partial line\n"


def test_a_comment_is_scrubbed_too() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b": " + SECRET.encode() + b"\n") == b": [REDACTED]\n"


def test_a_comment_inside_an_event_waits_for_the_event() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"data: a\n: note\n") == b""
    assert scrubber.feed(b"\n") == b"data: a\n: note\n\n"


def test_a_colon_later_in_a_line_is_no_comment() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"data: :\n") == b""
    assert scrubber.feed(b"x:\n") == b""


def test_a_cr_lf_split_across_chunks_is_one_line_break() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"data: a\r") == b""
    # Were the \n a line break of its own, it would end the event here.
    assert scrubber.feed(b"\n") == b""
    assert scrubber.feed(b"data: b\r") == b""
    assert scrubber.feed(b"\n\r\n") == b"data: a\r\ndata: b\r\n\r\n"


def test_a_cr_ending_an_event_lets_it_go_at_once() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"data: a\r\r") == b"data: a\r\r"
    # The \n that may follow is let go alone; the reader gets the same bytes.
    assert scrubber.feed(b"\n") == b"\n"
    assert scrubber.feed(b"data: b\n") == b""
    assert scrubber.feed(b"\n") == b"data: b\n\n"


def test_a_cr_lf_inside_one_chunk_is_one_line_break() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"data: a\r\ndata: b\r\n") == b""
    assert scrubber.feed(b"\r\n") == b"data: a\r\ndata: b\r\n\r\n"


def test_a_cr_before_a_lf_elsewhere_doesnt_join_them() -> None:
    scrubber = SSEScrubber(VARIANTS)
    # The first \n is a blank line, though the buffer ends with a \r.
    assert scrubber.feed(b"\ndata\r") == b"\n"
    assert scrubber.feed(b"\r") == b"data\r\r"


def test_a_cr_lf_cr_ends_the_event() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"a\r\rb") == b"a\r\r"
    assert scrubber.feed(b"\n") == b""
    assert scrubber.feed(b"\n") == b"b\n\n"


def test_lines_already_seen_are_not_looked_at_again() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"data: a\n") == b""
    assert scrubber.feed(b"data: b\n") == b""
    assert scrubber.feed(b"data: c") == b""
    assert scrubber.feed(b"\n\n") == b"data: a\ndata: b\ndata: c\n\n"


def test_a_long_line_is_looked_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    counter = CountingSearch(request._LINE_BREAK)
    monkeypatch.setattr(request, "_LINE_BREAK", counter)
    scrubber = SSEScrubber(VARIANTS)
    out = [scrubber.feed(chunk) for chunk in [b"data: ", *LONG_LINE, b"\r", b"\n\r\n"]]
    assert b"".join(out) == b"data: " + b"".join(LONG_LINE) + b"\r\n\r\n"
    assert out[-1] == b"data: " + b"".join(LONG_LINE) + b"\r\n\r\n"
    assert counter.looked_at < 2 * 1024 * 1024


def test_after_a_release_the_search_starts_afresh() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"data: aaaa") == b""
    assert scrubber.feed(b"\n\nb\n\n") == b"data: aaaa\n\nb\n\n"
    assert scrubber.feed(b"data: c") == b""
    assert scrubber.feed(b"\n\n") == b"data: c\n\n"


def test_finish_releases_an_unended_event_scrubbed() -> None:
    scrubber = SSEScrubber(VARIANTS)
    assert scrubber.feed(b"data: " + SECRET.encode()) == b""
    assert scrubber.finish() == b"data: [REDACTED]"
    assert scrubber.finish() == b""
    assert scrubber.scrubbed == 1


def test_after_finish_the_scrubber_starts_afresh() -> None:
    scrubber = SSEScrubber(VARIANTS)
    scrubber.feed(b"data: a\n")
    scrubber.finish()
    assert scrubber.feed(b": c\n") == b": c\n"


def test_no_variants_pass_everything() -> None:
    scrubber = SSEScrubber([])
    assert run(scrubber, [b"data: " + SECRET.encode() + b"\n\n"]) == [
        b"data: " + SECRET.encode() + b"\n\n",
        b"",
    ]
    assert scrubber.scrubbed == 0


# --- SSE event size --------------------------------------------------------------------------


def test_an_event_at_the_limit_passes() -> None:
    event = b"data: ab\n\n"
    assert len(event) == 10
    assert SSEScrubber(VARIANTS, max_event_bytes=10).feed(event) == event


def test_a_held_event_at_the_limit_waits() -> None:
    scrubber = SSEScrubber(VARIANTS, max_event_bytes=10)
    assert scrubber.feed(b"data: abcd") == b""
    assert scrubber.finish() == b"data: abcd"


def test_a_held_event_over_the_limit_raises() -> None:
    scrubber = SSEScrubber(VARIANTS, max_event_bytes=10)
    with pytest.raises(StreamEventTooLarge) as raised:
        scrubber.feed(b"data: abcde")
    assert raised.value.size == 11


def test_an_ended_event_over_the_limit_raises() -> None:
    scrubber = SSEScrubber(VARIANTS, max_event_bytes=10)
    with pytest.raises(StreamEventTooLarge) as raised:
        scrubber.feed(b"data: abc\n\n")
    assert raised.value.size == 11


def test_the_limit_is_per_event() -> None:
    scrubber = SSEScrubber(VARIANTS, max_event_bytes=10)
    assert scrubber.feed(b"data: a\n\ndata: b\n\ndata: c") == b"data: a\n\ndata: b\n\n"
    assert scrubber.feed(b"\n\n") == b"data: c\n\n"


def test_the_default_limit() -> None:
    scrubber = SSEScrubber([])
    big = b"data: " + b"x" * (MAX_STREAM_EVENT_BYTES - 8) + b"\n\n"
    assert len(big) == MAX_STREAM_EVENT_BYTES
    assert scrubber.feed(big) == big
    with pytest.raises(StreamEventTooLarge):
        scrubber.feed(b"x" * (MAX_STREAM_EVENT_BYTES + 1))


# --- NDJSON ------------------------------------------------------------------------------------


def test_ndjson_lines_go_out_when_they_end() -> None:
    scrubber = NDJSONScrubber(VARIANTS)
    assert scrubber.feed(b'{"a": 1}\n{"b"') == b'{"a": 1}\n'
    assert scrubber.feed(b": 2}") == b""
    assert scrubber.feed(b"\r\n") == b'{"b": 2}\r\n'
    assert scrubber.finish() == b""


@pytest.mark.parametrize("variant", VARIANTS)
def test_ndjson_catches_each_form_split_in_half(variant: bytes) -> None:
    line = b'{"error": "bad key ' + variant + b'"}\n'
    middle = line.index(variant) + len(variant) // 2
    scrubber = NDJSONScrubber(VARIANTS)
    assert scrubber.feed(line[:middle]) == b""
    assert scrubber.feed(line[middle:]) == b'{"error": "bad key [REDACTED]"}\n'
    assert scrubber.scrubbed == 1


def test_ndjson_finish_releases_the_last_line_scrubbed() -> None:
    scrubber = NDJSONScrubber(VARIANTS)
    assert scrubber.feed(b'{"k": "' + SECRET.encode().replace(b'"', b'\\"')) == b""
    assert scrubber.finish() == b'{"k": "[REDACTED]'
    assert scrubber.finish() == b""
    assert scrubber.scrubbed == 1


def test_ndjson_lines_already_seen_are_not_looked_at_again() -> None:
    scrubber = NDJSONScrubber(VARIANTS)
    assert scrubber.feed(b"1\n2") == b"1\n"
    assert scrubber.feed(b"3") == b""
    assert scrubber.feed(b"\n4\n") == b"23\n4\n"
    assert scrubber.feed(b"5") == b""
    assert scrubber.feed(b"\n") == b"5\n"


def test_ndjson_a_long_line_is_looked_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    counter = CountingSearch(request._LF_BREAK)
    monkeypatch.setattr(request, "_LF_BREAK", counter)
    scrubber = NDJSONScrubber(VARIANTS)
    out = [scrubber.feed(chunk) for chunk in [*LONG_LINE, b"\n"]]
    assert out[-1] == b"".join(LONG_LINE) + b"\n"
    assert b"".join(out[:-1]) == b""
    assert counter.looked_at < 2 * 1024 * 1024


def test_ndjson_a_chunk_may_start_with_a_line_break() -> None:
    scrubber = NDJSONScrubber([])
    assert scrubber.feed(b"\n") == b"\n"
    assert scrubber.feed(b"\nx") == b"\n"
    assert scrubber.feed(b"\n") == b"x\n"


def test_ndjson_line_limit() -> None:
    assert NDJSONScrubber([], max_line_bytes=4).feed(b"abc\n") == b"abc\n"
    with pytest.raises(StreamEventTooLarge) as raised:
        NDJSONScrubber([], max_line_bytes=4).feed(b"abcd\n")
    assert raised.value.size == 5
    with pytest.raises(StreamEventTooLarge) as raised:
        NDJSONScrubber([], max_line_bytes=4).feed(b"ab\nabcde\n")
    assert raised.value.size == 6
    with pytest.raises(StreamEventTooLarge) as raised:
        NDJSONScrubber([], max_line_bytes=4).feed(b"ab\nabcde")
    assert raised.value.size == 5
    held = NDJSONScrubber([], max_line_bytes=4)
    assert held.feed(b"abcd") == b""
    with pytest.raises(StreamEventTooLarge) as raised:
        held.feed(b"e")
    assert raised.value.size == 5


def test_ndjson_limit_is_per_line() -> None:
    scrubber = NDJSONScrubber([], max_line_bytes=4)
    assert scrubber.feed(b"abc\ndef\ngh") == b"abc\ndef\n"
    assert scrubber.feed(b"i\nj") == b"ghi\n"
    assert scrubber.feed(b"klm") == b""
    with pytest.raises(StreamEventTooLarge) as raised:
        scrubber.feed(b"n")
    assert raised.value.size == 5


def test_ndjson_default_limit() -> None:
    line = b"x" * (MAX_STREAM_EVENT_BYTES - 1) + b"\n"
    assert NDJSONScrubber([]).feed(line) == line
    with pytest.raises(StreamEventTooLarge):
        NDJSONScrubber([]).feed(b"x" * MAX_STREAM_EVENT_BYTES + b"\n")


# --- properties --------------------------------------------------------------------------------

FRAGMENTS = [
    b"data: ",
    b"id: 7",
    b": ping",
    b":",
    b"x",
    b" ",
    b"\r",
    b"\n",
    b"\r\n",
    *VARIANTS,
]
_LINE = re.compile(rb"[^\r\n]*(?:\r\n|\r|\n)")


def event_ends(data: bytes) -> list[int]:
    """Where each event in ``data`` ends, by a plain reading of the SSE line rules."""
    ends = []
    for line in _LINE.finditer(data):
        if line.group() in (b"\n", b"\r", b"\r\n"):
            ends.append(line.end())
    return ends


def by_event(data: bytes) -> bytes:
    """Scrub each event of ``data`` on its own, as the reference."""
    out, start = [], 0
    for end in event_ends(data):
        out.append(scrub(data[start:end], VARIANTS)[0])
        start = end
    out.append(scrub(data[start:], VARIANTS)[0])
    return b"".join(out)


def chunked(data: bytes, cuts: list[int]) -> list[bytes]:
    points = sorted({c % (len(data) + 1) for c in cuts})
    return [data[a:b] for a, b in zip([0, *points], [*points, len(data)], strict=True)]


streams = st.lists(st.sampled_from(FRAGMENTS), max_size=40).map(b"".join)
cuts = st.lists(st.integers(min_value=0, max_value=10_000), max_size=12)


def test_the_reference_reads_lines_as_sse_does() -> None:
    assert event_ends(b"a\n\nb\r\rc\r\n\r\nd\n\r\n") == [3, 6, 11, 15]
    assert event_ends(b"a\nb\n") == []


@settings(max_examples=400)
@given(streams, cuts)
def test_property_sse_output_is_each_event_scrubbed(data: bytes, cut: list[int]) -> None:
    scrubber = SSEScrubber(VARIANTS)
    output = b"".join(run(scrubber, chunked(data, cut)))
    assert output == by_event(data)
    # No variant has a line break, so that's the whole stream scrubbed too.
    assert output == scrub(data, VARIANTS)[0]
    assert scrubber.scrubbed == scrub(data, VARIANTS)[1]


@settings(max_examples=400)
@given(streams, cuts)
def test_property_sse_holds_no_more_than_one_event(data: bytes, cut: list[int]) -> None:
    scrubber = SSEScrubber([])
    fed, released = b"", 0
    for chunk in chunked(data, cut):
        fed += chunk
        released += len(scrubber.feed(chunk))
        ends = event_ends(fed)
        assert released >= (ends[-1] if ends else 0)
        assert released <= len(fed)


@settings(max_examples=300)
@given(streams, cuts)
def test_property_ndjson_output_is_each_line_scrubbed(data: bytes, cut: list[int]) -> None:
    scrubber = NDJSONScrubber(VARIANTS)
    scrubbed, count = scrub(data, VARIANTS)
    assert b"".join(run(scrubber, chunked(data, cut))) == scrubbed
    assert scrubber.scrubbed == count


@settings(max_examples=300)
@given(streams, cuts)
def test_property_ndjson_holds_only_the_last_line(data: bytes, cut: list[int]) -> None:
    scrubber = NDJSONScrubber([])
    fed, released = b"", 0
    for chunk in chunked(data, cut):
        fed += chunk
        released += len(scrubber.feed(chunk))
        assert released == fed.rfind(b"\n") + 1
