"""A legacy bridge's sessions (M7 design C.5, SPEC-4, G20; O.2 ``test_bridge_sessions.py``).

The cap counts sessions and starts alike, an id is 256 random bits compared in constant time and
logged only as its hash8, an ended or idle session is gone, and each notification goes to the
oldest open GET stream.
"""

from __future__ import annotations

import base64
import hashlib
import itertools

import pytest

from zoeymcp.bridge import sessions
from zoeymcp.bridge.sessions import IDLE_TIMEOUT, SESSIONS_MAX, Session, Sessions, hash8, new_id


def counting() -> Sessions[str]:
    ids = (f"session-{n}" for n in itertools.count(1))
    return Sessions(limit=2, idle_timeout=10.0, new_id=lambda: next(ids))


def test_the_constants() -> None:
    """M7 design C.5 and M.6."""
    assert (SESSIONS_MAX, IDLE_TIMEOUT, sessions.ID_BYTES) == (8, 600.0, 32)
    table: Sessions[str] = Sessions()
    assert (table.limit, table.idle_timeout) == (8, 600.0)


def test_a_new_id_is_256_random_bits_in_base64url() -> None:
    made = {new_id() for _ in range(50)}
    assert len(made) == 50
    for session_id in made:
        assert len(session_id) == 43
        assert len(base64.urlsafe_b64decode(session_id + "=")) == 32


def test_hash8() -> None:
    assert hash8("abc") == hashlib.sha256(b"abc").hexdigest()[:8]
    session = Session("abc", "child", 0.0)
    assert session.hash8 == hash8("abc")
    assert repr(session) == f"Session({hash8('abc')})"
    assert "abc" not in repr(session)


def test_a_session_is_established_in_a_reserved_place() -> None:
    table = counting()
    assert table.reserve()
    assert table.reserve()
    # Two starting fill the two places.
    assert not table.reserve()
    first = table.establish("child-1", 5.0)
    assert (first.session_id, first.child, first.last_used) == ("session-1", "child-1", 5.0)
    assert len(table) == 1
    assert not table.reserve()
    table.release()
    assert table.reserve()
    table.establish("child-2", 6.0)
    assert len(table) == 2
    assert not table.reserve()
    assert [s.child for s in table] == ["child-1", "child-2"]


def test_establish_needs_a_reservation() -> None:
    table = counting()
    with pytest.raises(ValueError, match=r"^no session is starting$"):
        table.establish("child", 0.0)
    table.release()
    table.release()
    assert table.reserve()
    assert table.reserve()
    assert not table.reserve()


def test_a_new_id_never_repeats_a_live_one() -> None:
    ids = iter(["same", "same", "other"])
    table: Sessions[str] = Sessions(new_id=lambda: next(ids))
    table.reserve()
    table.reserve()
    assert table.establish("a", 0.0).session_id == "same"
    assert table.establish("b", 0.0).session_id == "other"


def test_find_compares_ids_exactly() -> None:
    table = counting()
    table.reserve()
    session = table.establish("child", 0.0)
    assert table.find("session-1") is session
    for other in ("session-", "session-11", "SESSION-1", "", "session-1 ", "s\u00e9ssion-1"):
        assert table.find(other) is None
    assert session.matches("session-1")
    assert not session.matches("session-2")


def test_an_ended_session_is_gone() -> None:
    table = counting()
    table.reserve()
    session = table.establish("child", 0.0)
    assert table.end(session)
    assert not table.end(session)
    assert table.find("session-1") is None
    assert len(table) == 0
    assert table.reserve()


def test_a_session_idles_only_with_nothing_open() -> None:
    table = counting()
    table.reserve()
    table.reserve()
    busy = table.establish("busy", 0.0)
    quiet = table.establish("quiet", 1.0)
    busy.begin(1.0)
    assert table.idle(10.999) == []
    assert table.idle(11.0) == [quiet]
    assert list(table) == [busy]
    assert busy.requests == 1
    assert table.idle(100.0) == []
    busy.finish(100.0)
    assert busy.requests == 0
    assert table.idle(109.0) == []
    stream = busy.open_stream()
    assert table.idle(200.0) == []
    busy.close_stream(stream, 200.0)
    assert table.idle(209.0) == []
    assert table.idle(210.0) == [busy]
    assert len(table) == 0


def test_idle_counts_from_the_last_use() -> None:
    session = Session("s", "c", 0.0)
    assert not session.idle(9.0, 10.0)
    assert session.idle(10.0, 10.0)
    session.begin(5.0)
    session.finish(7.0)
    assert session.last_used == 7.0
    assert not session.idle(16.0, 10.0)
    assert session.idle(17.0, 10.0)


def test_each_get_has_its_own_stream_and_notifications_go_to_the_oldest() -> None:
    """SPEC-4: a second GET gets its own stream; each notification goes to exactly one."""
    session = Session("s", "c", 0.0)
    assert session.stream is None
    first = session.open_stream()
    second = session.open_stream()
    assert first != second
    assert session.stream == first
    session.close_stream(first, 3.0)
    assert (session.stream, session.last_used) == (second, 3.0)
    third = session.open_stream()
    assert third not in (first, second)
    session.close_stream(first, 4.0)
    assert session.stream == second
    session.close_stream(second, 5.0)
    assert session.stream == third
    session.close_stream(third, 6.0)
    assert session.stream is None
    assert session.idle(16.0, 10.0)
