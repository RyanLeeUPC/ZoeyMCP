"""The held answer is read in linear time (M8 design B.8; step 11 review F1).

The vault reads every approved forward's answer on its event loop, so a reader that rescans its
buffer at each line would stall the vault on a hostile upstream's answer. This test lives outside
``tests/unit`` on purpose: mutmut runs ``tests/unit`` against instrumented code, where a 4 MiB read
under a wall-clock bound would make the clean run fail.
"""

from __future__ import annotations

import time

from zoeymcp.common.heldresult import messages, outcome_of

SSE = "text/event-stream"


def test_a_long_answer_of_short_lines_is_read_in_linear_time() -> None:
    """An answer at its 4 MiB bound of short lines (one event of LF-less data lines, then
    comments, then blank lines) is read in about a second. A reader that searched the rest of the
    buffer, or copied it, at each line would take minutes."""
    body = b"data:x\r" * (2**21 // 7) + b":\n" * 2**19 + b"\r\n" * 2**19
    assert len(body) <= 4 * 2**20
    started = time.monotonic()
    assert outcome_of(200, SSE, body, 1) == "upstream_error"  # its one event isn't JSON
    assert time.monotonic() - started < 15
    [found] = messages(SSE, [body]) or []
    assert found == b"\n".join([b"x"] * (2**21 // 7))
