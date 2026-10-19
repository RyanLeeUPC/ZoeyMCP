"""Sessions and ceremonies (M5 design F.1-F.3, O.2): expiry at the second, both halves, origin
binding, eviction, every way a session ends, planted cookies, the ceremony table's quotas, and a
stateful property over all of it."""

from __future__ import annotations

import base64
import hashlib
import itertools
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from zoeymcp.portal import sessions
from zoeymcp.portal.sessions import (
    CEREMONY_TTL,
    ENROL_TAG,
    LOGIN_TAG,
    MAX_LOGIN_CEREMONIES,
    MAX_LOGIN_CEREMONIES_PER_PEER,
    MAX_SESSION_COOKIES,
    MAX_SESSIONS,
    SESSION_IDLE,
    SESSION_MAX,
    SETUP_SESSION_MAX,
    Ceremonies,
    Ceremony,
    Full,
    Minted,
    Session,
    Sessions,
    SessionToken,
    challenge,
    new_token,
)
from zoeymcp.vault.oauth import pkce

ORIGIN = "http://localhost:8081"
OTHER = "https://zoeymcp.tailnet.example"
RP = "localhost"
T0 = 1_760_000_000.0


def counting() -> Callable[[int], bytes]:
    """Distinct bytes on every call, so every token and ID differs."""
    counter = itertools.count(1)
    return lambda n: next(counter).to_bytes(n, "big")


def scripted(*chunks: bytes) -> Callable[[int], bytes]:
    queue = list(chunks)

    def random(n: int) -> bytes:
        chunk = queue.pop(0)
        assert len(chunk) == n
        return chunk

    return random


def mint(
    table: Sessions,
    now: float = T0,
    *,
    origin: str = ORIGIN,
    scope: sessions.Scope = "full",
    credential: str | None = "c1",
    reset: bool = False,
) -> Minted:
    return table.mint(
        origin=origin, rp_id=RP, scope=scope, now=now, credential=credential, reset=reset
    )


def find(table: Sessions, minted: Minted, now: float, origin: str = ORIGIN) -> Session | None:
    return table.lookup([minted.cookie], minted.header, origin=origin, now=now)


def test_the_constants_are_the_designs() -> None:
    assert (SESSION_IDLE, SESSION_MAX, SETUP_SESSION_MAX) == (900.0, 14_400.0, 600.0)
    assert (MAX_SESSIONS, MAX_SESSION_COOKIES) == (8, 4)
    assert (CEREMONY_TTL, MAX_LOGIN_CEREMONIES, MAX_LOGIN_CEREMONIES_PER_PEER) == (300.0, 16, 4)
    assert (sessions.TOKEN_BYTES, sessions.ID_BYTES, sessions.NONCE_BYTES) == (32, 16, 32)
    assert LOGIN_TAG == b"zoeymcp/webauthn/login/v1\n"
    assert ENROL_TAG == b"zoeymcp/webauthn/enrol/v1\n"


# --- tokens --------------------------------------------------------------------------------------


def test_a_token_hides_itself() -> None:
    token = SessionToken("fake-session-half")
    assert token.reveal() == "fake-session-half"
    assert repr(token) == str(token) == "SessionToken(<hidden>)"
    assert token.sha256() == hashlib.sha256(b"fake-session-half").digest()
    assert SessionToken("café").sha256() == hashlib.sha256("café".encode()).digest()


def test_a_token_is_token_urlsafe_32() -> None:
    raw = bytes(range(32))
    token = new_token(scripted(raw))
    assert token.reveal() == base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    assert len(token.reveal()) == 43


def test_the_default_randomness_is_the_system_s() -> None:
    table = Sessions()
    first, second = mint(table), mint(table)
    halves = {m.cookie.reveal() for m in (first, second)} | {
        m.header.reveal() for m in (first, second)
    }
    assert len(halves) == 4
    assert all(len(h) == 43 for h in halves)
    assert first.session.id != second.session.id
    assert Ceremonies().begin_login(origin=ORIGIN, peer="p", now=T0) != Ceremonies().begin_login(
        origin=ORIGIN, peer="p", now=T0
    )


# --- minting -------------------------------------------------------------------------------------


def test_minting_records_both_hashes_and_nothing_else_secret() -> None:
    table = Sessions(scripted(b"\x01" * 32, b"\x02" * 32, b"\xab" * 16))
    minted = mint(table, scope="setup", credential=None, reset=True)
    session = minted.session
    assert minted.cookie.reveal() == base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
    assert minted.header.reveal() == base64.urlsafe_b64encode(b"\x02" * 32).rstrip(b"=").decode()
    assert session.cookie_hash == minted.cookie.sha256()
    assert session.header_hash == minted.header.sha256()
    assert session.id == "ab" * 16
    assert (session.origin, session.rp_id, session.scope) == (ORIGIN, RP, "setup")
    assert (session.reset, session.credential) == (True, None)
    assert (session.created, session.last_seen) == (T0, T0)
    assert minted.ended == ()
    assert minted.cookie.reveal() not in repr(minted)
    assert minted.header.reveal() not in repr(minted)
    assert "cookie_hash" not in repr(session)
    assert "header_hash" not in repr(session)
    assert len(table) == 1


def test_a_full_session_defaults() -> None:
    table = Sessions(counting())
    session = table.mint(origin=ORIGIN, rp_id=RP, scope="full", now=T0).session
    assert (session.reset, session.credential) == (False, None)


def test_the_owner_fits_the_flow_tables_form() -> None:
    session = mint(Sessions(counting())).session
    assert session.owner == "session:" + session.id
    assert pkce._SESSION_OWNER.fullmatch(session.owner)
    assert len(session.id) == 32


def test_the_fingerprint_is_not_the_id() -> None:
    session = mint(Sessions(scripted(b"\x01" * 32, b"\x02" * 32, b"\xab" * 16))).session
    expected = hashlib.sha256(b"zoeymcp/session/v1\n" + ("ab" * 16).encode()).hexdigest()[:16]
    assert session.fingerprint == expected
    assert session.id not in session.fingerprint


# --- lookup ---------------------------------------------------------------------------------------


def test_both_halves_are_needed() -> None:
    table = Sessions(counting())
    first, second = mint(table), mint(table)
    assert find(table, first, T0) == first.session
    assert find(table, second, T0) == second.session
    # One half alone, or halves of two sessions, or a half in the wrong place.
    assert table.lookup([first.cookie], second.header, origin=ORIGIN, now=T0) is None
    assert table.lookup([second.cookie], first.header, origin=ORIGIN, now=T0) is None
    assert table.lookup([first.header], first.cookie, origin=ORIGIN, now=T0) is None
    assert table.lookup([], first.header, origin=ORIGIN, now=T0) is None
    assert table.lookup([first.cookie], SessionToken("x"), origin=ORIGIN, now=T0) is None
    assert table.lookup([SessionToken("x")], first.header, origin=ORIGIN, now=T0) is None


def test_a_session_belongs_to_its_origin() -> None:
    table = Sessions(counting())
    minted = mint(table)
    assert find(table, minted, T0, origin=OTHER) is None
    other = mint(table, origin=OTHER)
    assert find(table, other, T0, origin=OTHER) == other.session
    assert find(table, other, T0) is None


def test_the_cookie_that_pairs_wins_among_planted_ones() -> None:
    # A neighbour sets a cookie of our name at Path=/api, which the browser sends first.
    table = Sessions(counting())
    minted = mint(table)
    planted = [SessionToken(f"planted-{i}") for i in range(4)]
    assert table.lookup([planted[0], minted.cookie], minted.header, origin=ORIGIN, now=T0)
    assert table.lookup([*planted[:3], minted.cookie], minted.header, origin=ORIGIN, now=T0)
    # A fifth isn't tried.
    assert table.lookup([*planted, minted.cookie], minted.header, origin=ORIGIN, now=T0) is None


def test_another_sessions_cookie_among_ours_changes_nothing() -> None:
    table = Sessions(counting())
    first, second = mint(table), mint(table)
    cookies = [second.cookie, first.cookie]
    assert table.lookup(cookies, first.header, origin=ORIGIN, now=T0) == first.session


def test_lookup_changes_nothing() -> None:
    table = Sessions(counting())
    minted = mint(table)
    assert find(table, minted, T0 + 100) == minted.session
    assert table.live(T0)[0].last_seen == T0
    # An expired session stays until it is swept, so its end can be logged.
    assert find(table, minted, T0 + SESSION_IDLE) is None
    assert len(table) == 1


# --- expiry ---------------------------------------------------------------------------------------


def test_the_idle_clock_ends_at_its_second() -> None:
    table = Sessions(counting())
    minted = mint(table)
    assert find(table, minted, T0 + SESSION_IDLE - 0.001) == minted.session
    assert minted.session.ended_by(T0 + SESSION_IDLE - 0.001) is None
    assert find(table, minted, T0 + SESSION_IDLE) is None
    assert minted.session.ended_by(T0 + SESSION_IDLE) == "idle"
    assert minted.session.idle_until == T0 + SESSION_IDLE


def test_touch_moves_the_idle_clock() -> None:
    table = Sessions(counting())
    minted = mint(table)
    touched = table.touch(minted.session.id, T0 + 600)
    assert touched is not None
    assert touched.last_seen == T0 + 600
    assert find(table, minted, T0 + 600 + SESSION_IDLE - 1) == touched
    assert find(table, minted, T0 + 600 + SESSION_IDLE) is None


def test_touch_never_moves_the_clock_back() -> None:
    table = Sessions(counting())
    minted = mint(table)
    table.touch(minted.session.id, T0 + 600)
    touched = table.touch(minted.session.id, T0 + 100)
    assert touched is not None
    assert touched.last_seen == T0 + 600


def test_touch_neither_revives_nor_invents() -> None:
    table = Sessions(counting())
    minted = mint(table)
    assert table.touch(minted.session.id, T0 + SESSION_IDLE) is None
    assert find(table, minted, T0 + SESSION_IDLE) is None
    assert table.live(T0)[0].last_seen == T0
    assert table.touch("ab" * 16, T0) is None
    assert len(table) == 1


def test_the_absolute_clock_ends_at_its_second() -> None:
    table = Sessions(counting())
    minted = mint(table)
    now = T0
    while now + 800 < T0 + SESSION_MAX:
        now += 800
        assert table.touch(minted.session.id, now) is not None
    assert minted.session.expires_at == T0 + SESSION_MAX
    assert find(table, minted, T0 + SESSION_MAX - 0.001) is not None
    assert find(table, minted, T0 + SESSION_MAX) is None
    assert table.live(T0 + SESSION_MAX - 1)[0].ended_by(T0 + SESSION_MAX) == "max"


def test_a_setup_session_lasts_ten_minutes_whatever_it_does() -> None:
    table = Sessions(counting())
    minted = mint(table, scope="setup", credential=None)
    assert minted.session.expires_at == T0 + SETUP_SESSION_MAX
    table.touch(minted.session.id, T0 + 300)
    assert find(table, minted, T0 + SETUP_SESSION_MAX - 0.001) is not None
    assert find(table, minted, T0 + SETUP_SESSION_MAX) is None
    assert minted.session.ended_by(T0 + SETUP_SESSION_MAX) == "max"


def test_the_absolute_end_wins_when_both_run_out() -> None:
    session = mint(Sessions(counting()), scope="setup", credential=None).session
    assert session.ended_by(T0 + SESSION_IDLE) == "max"


def test_sweep_ends_each_with_its_reason() -> None:
    table = Sessions(counting())
    idle = mint(table)
    kept = mint(table)
    setup = mint(table, scope="setup", credential=None)
    table.touch(kept.session.id, T0 + 500)
    ended = table.sweep(T0 + SESSION_IDLE)
    assert [(e.session.id, e.why) for e in ended] == [
        (idle.session.id, "idle"),
        (setup.session.id, "max"),
    ]
    assert [s.id for s in table.live(T0 + SESSION_IDLE)] == [kept.session.id]
    assert table.sweep(T0 + SESSION_IDLE) == []


def test_live_lists_only_what_would_authenticate() -> None:
    table = Sessions(counting())
    first = mint(table)
    second = mint(table, T0 + 10)
    assert [s.id for s in table.live(T0 + 10)] == [first.session.id, second.session.id]
    assert [s.id for s in table.live(T0 + SESSION_IDLE)] == [second.session.id]
    assert len(table) == 2


# --- eviction -------------------------------------------------------------------------------------


def test_a_full_table_evicts_the_least_recently_used() -> None:
    table = Sessions(counting())
    minted = [mint(table, T0 + i) for i in range(MAX_SESSIONS)]
    table.touch(minted[0].session.id, T0 + 20)
    newest = mint(table, T0 + 30)
    [ended] = newest.ended
    assert (ended.session.id, ended.why) == (minted[1].session.id, "evicted")
    assert len(table) == MAX_SESSIONS
    assert find(table, minted[1], T0 + 30) is None
    assert find(table, minted[0], T0 + 30) is not None
    assert find(table, newest, T0 + 30) is not None


def test_eviction_breaks_a_tie_by_age() -> None:
    table = Sessions(counting())
    minted = [mint(table) for _ in range(MAX_SESSIONS)]
    [ended] = mint(table).ended
    assert ended.session.id == minted[0].session.id


def test_below_the_cap_nothing_is_evicted() -> None:
    table = Sessions(counting())
    for _ in range(MAX_SESSIONS - 1):
        mint(table)
    assert mint(table).ended == ()
    assert len(table) == MAX_SESSIONS


def test_expired_sessions_go_before_any_eviction() -> None:
    table = Sessions(counting())
    old = mint(table)
    for i in range(MAX_SESSIONS - 1):
        mint(table, T0 + 100 + i)
    newest = mint(table, T0 + SESSION_IDLE)
    assert [(e.session.id, e.why) for e in newest.ended] == [(old.session.id, "idle")]
    assert len(table) == MAX_SESSIONS


# --- ending ---------------------------------------------------------------------------------------


def test_logout_ends_one_session_once() -> None:
    table = Sessions(counting())
    minted, other = mint(table), mint(table)
    ended = table.end(minted.session.id, "logout")
    assert ended is not None
    assert (ended.session, ended.why) == (minted.session, "logout")
    assert table.end(minted.session.id, "logout") is None
    assert find(table, minted, T0) is None
    assert find(table, other, T0) is not None


def test_end_others_keeps_only_this_one() -> None:
    table = Sessions(counting())
    keep, *others = [mint(table) for _ in range(3)]
    ended = table.end_others(keep.session.id)
    assert [(e.session.id, e.why) for e in ended] == [(m.session.id, "end_others") for m in others]
    assert [s.id for s in table.live(T0)] == [keep.session.id]


def test_removing_a_passkey_ends_the_sessions_it_made() -> None:
    table = Sessions(counting())
    first = mint(table, credential="c1")
    second = mint(table, credential="c2")
    setup = mint(table, scope="setup", credential=None)
    ended = table.end_credential("c1")
    assert [(e.session.id, e.why) for e in ended] == [(first.session.id, "passkey_removed")]
    assert {s.id for s in table.live(T0)} == {second.session.id, setup.session.id}


def test_a_reload_ends_the_sessions_of_a_dropped_origin() -> None:
    table = Sessions(counting())
    local = mint(table)
    remote = mint(table, origin=OTHER)
    ended = table.end_origins([ORIGIN])
    assert [(e.session.id, e.why) for e in ended] == [(remote.session.id, "origin_removed")]
    assert [s.id for s in table.live(T0)] == [local.session.id]


def test_a_reset_ends_every_session() -> None:
    table = Sessions(counting())
    minted = [mint(table) for _ in range(3)]
    ended = table.end_where(lambda s: True, "reset")
    assert [(e.session.id, e.why) for e in ended] == [(m.session.id, "reset") for m in minted]
    assert len(table) == 0
    assert table.end_where(lambda s: True, "end_all") == []


# --- the challenge --------------------------------------------------------------------------------


def test_the_challenge_is_tag_nonce_and_canonical_binding() -> None:
    nonce = b"\x22" * 32
    binding = {"origin": ORIGIN, "ceremony": "x"}
    expected = hashlib.sha256(
        LOGIN_TAG + nonce + b'{"ceremony":"x","origin":"http://localhost:8081"}'
    ).digest()
    assert challenge(LOGIN_TAG, nonce, binding) == expected


def test_a_login_ceremony_against_a_fixed_vector() -> None:
    table = Ceremonies(scripted(b"\x11" * 16, b"\x22" * 32))
    ceremony = table.begin_login(origin=ORIGIN, peer="127.0.0.1", now=T0)
    assert isinstance(ceremony, Ceremony)
    assert (ceremony.id, ceremony.kind, ceremony.origin) == ("11" * 16, "login", ORIGIN)
    assert (ceremony.peer, ceremony.session, ceremony.name) == ("127.0.0.1", None, None)
    assert (ceremony.nonce, ceremony.expires) == (b"\x22" * 32, T0 + CEREMONY_TTL)
    assert ceremony.binding() == {"ceremony": "11" * 16, "origin": ORIGIN}
    assert ceremony.challenge.hex() == (
        "d693c30b699eab2919ea55136acd8099e56937ba65508324f42faf5f8661cf65"
    )


def test_an_enrolment_ceremony_against_a_fixed_vector() -> None:
    table = Ceremonies(scripted(b"\x11" * 16, b"\x22" * 32))
    ceremony = table.begin_enrol(origin=ORIGIN, session="ab" * 16, name="Laptop", now=T0)
    assert (ceremony.kind, ceremony.session, ceremony.name, ceremony.peer) == (
        "enrol",
        "ab" * 16,
        "Laptop",
        None,
    )
    assert ceremony.expires == T0 + CEREMONY_TTL
    assert ceremony.binding() == {
        "ceremony": "11" * 16,
        "origin": ORIGIN,
        "session": "ab" * 16,
        "name": "Laptop",
    }
    assert ceremony.challenge.hex() == (
        "43b2db582f38475dcfe9beb57b6ec3ae134e9277d3ba25f0215aa822f5ced438"
    )


@pytest.mark.parametrize("field", ["id", "nonce", "origin", "session", "name", "kind"])
def test_any_change_to_a_ceremony_changes_its_challenge(field: str) -> None:
    table = Ceremonies(scripted(b"\x11" * 16, b"\x22" * 32))
    ceremony = table.begin_enrol(origin=ORIGIN, session="ab" * 16, name="Laptop", now=T0)
    other = {
        "id": "12" * 16,
        "nonce": b"\x23" * 32,
        "origin": OTHER,
        "session": "ac" * 16,
        "name": "Phone",
        "kind": "login",
    }[field]
    changed = Ceremony(**{**ceremony.__dict__, field: other})
    assert changed.challenge != ceremony.challenge


def test_a_ceremony_hides_its_nonce() -> None:
    ceremony = Ceremonies(scripted(b"\x11" * 16, b"\x22" * 32)).begin_login(
        origin=ORIGIN, peer="p", now=T0
    )
    assert isinstance(ceremony, Ceremony)
    assert repr(ceremony) == f"Ceremony(kind=login, expires={T0 + CEREMONY_TTL})"


# --- the ceremony table ---------------------------------------------------------------------------


def login(table: Ceremonies, peer: str = "p1", now: float = T0) -> Ceremony:
    ceremony = table.begin_login(origin=ORIGIN, peer=peer, now=now)
    assert isinstance(ceremony, Ceremony)
    return ceremony


def test_a_ceremony_is_single_use() -> None:
    table = Ceremonies(counting())
    ceremony = login(table)
    assert table.take(ceremony.id, kind="login", origin=ORIGIN, now=T0) == ceremony
    assert table.take(ceremony.id, kind="login", origin=ORIGIN, now=T0) is None
    assert len(table) == 0


def test_a_ceremony_expires_at_its_second() -> None:
    table = Ceremonies(counting())
    early, late = login(table), login(table)
    end = T0 + CEREMONY_TTL
    assert table.take(early.id, kind="login", origin=ORIGIN, now=end - 0.001) == early
    assert table.take(late.id, kind="login", origin=ORIGIN, now=end) is None
    # Taken out even so: it can't be tried again.
    assert len(table) == 0


@pytest.mark.parametrize(
    ("kind", "origin", "session"),
    [("enrol", ORIGIN, None), ("login", OTHER, None), ("login", ORIGIN, "ab" * 16)],
)
def test_a_foreign_login_ceremony_is_unknown_and_stays(
    kind: sessions.CeremonyKind, origin: str, session: str | None
) -> None:
    table = Ceremonies(counting())
    ceremony = login(table)
    assert table.take(ceremony.id, kind=kind, origin=origin, now=T0, session=session) is None
    assert table.take("ab" * 16, kind="login", origin=ORIGIN, now=T0) is None
    assert table.take(ceremony.id, kind="login", origin=ORIGIN, now=T0) == ceremony


@pytest.mark.parametrize(
    ("kind", "origin", "session"),
    [("login", ORIGIN, "ab" * 16), ("enrol", OTHER, "ab" * 16), ("enrol", ORIGIN, "ac" * 16)],
)
def test_a_foreign_enrolment_ceremony_is_unknown_and_stays(
    kind: sessions.CeremonyKind, origin: str, session: str | None
) -> None:
    table = Ceremonies(counting())
    ceremony = table.begin_enrol(origin=ORIGIN, session="ab" * 16, name="Laptop", now=T0)
    assert table.take(ceremony.id, kind=kind, origin=origin, now=T0, session=session) is None
    assert table.take(ceremony.id, kind="enrol", origin=ORIGIN, now=T0) is None
    taken = table.take(ceremony.id, kind="enrol", origin=ORIGIN, now=T0, session="ab" * 16)
    assert taken == ceremony


def test_a_session_holds_one_enrolment_ceremony() -> None:
    table = Ceremonies(counting())
    first = table.begin_enrol(origin=ORIGIN, session="ab" * 16, name="One", now=T0)
    other = table.begin_enrol(origin=ORIGIN, session="ac" * 16, name="Other", now=T0)
    second = table.begin_enrol(origin=ORIGIN, session="ab" * 16, name="Two", now=T0)
    assert len(table) == 2
    assert table.take(first.id, kind="enrol", origin=ORIGIN, now=T0, session="ab" * 16) is None
    table.drop_session("ac" * 16)
    assert table.take(other.id, kind="enrol", origin=ORIGIN, now=T0, session="ac" * 16) is None
    taken = table.take(second.id, kind="enrol", origin=ORIGIN, now=T0, session="ab" * 16)
    assert taken == second


def test_enrolment_ceremonies_dont_count_against_logins() -> None:
    table = Ceremonies(counting())
    table.begin_enrol(origin=ORIGIN, session="ab" * 16, name="One", now=T0)
    for peer in range(MAX_LOGIN_CEREMONIES // MAX_LOGIN_CEREMONIES_PER_PEER):
        for _ in range(MAX_LOGIN_CEREMONIES_PER_PEER):
            login(table, f"p{peer}")
    assert table.logins() == MAX_LOGIN_CEREMONIES
    assert len(table) == MAX_LOGIN_CEREMONIES + 1


def test_a_fifth_from_one_peer_evicts_its_own_oldest() -> None:
    table = Ceremonies(counting())
    mine = [login(table, "p1", T0 + i) for i in range(MAX_LOGIN_CEREMONIES_PER_PEER)]
    theirs = login(table, "p2")
    fifth = login(table, "p1", T0 + 10)
    assert table.logins("p1") == MAX_LOGIN_CEREMONIES_PER_PEER
    assert table.logins("p2") == 1
    assert table.logins() == MAX_LOGIN_CEREMONIES_PER_PEER + 1
    assert table.take(mine[0].id, kind="login", origin=ORIGIN, now=T0 + 10) is None
    for ceremony in [*mine[1:], theirs, fifth]:
        assert table.take(ceremony.id, kind="login", origin=ORIGIN, now=T0 + 10) == ceremony


def test_a_full_table_refuses_and_evicts_no_one_else() -> None:
    table = Ceremonies(counting())
    held = [
        login(table, f"p{peer}")
        for peer in range(MAX_LOGIN_CEREMONIES // MAX_LOGIN_CEREMONIES_PER_PEER)
        for _ in range(MAX_LOGIN_CEREMONIES_PER_PEER)
    ]
    assert table.begin_login(origin=ORIGIN, peer="newcomer", now=T0) == Full()
    assert table.logins() == MAX_LOGIN_CEREMONIES
    # A peer at its quota still begins one, in place of its own oldest.
    assert isinstance(table.begin_login(origin=ORIGIN, peer="p0", now=T0), Ceremony)
    assert table.take(held[0].id, kind="login", origin=ORIGIN, now=T0) is None
    assert table.take(held[1].id, kind="login", origin=ORIGIN, now=T0) == held[1]
    # One gone: the newcomer fits.
    assert isinstance(table.begin_login(origin=ORIGIN, peer="newcomer", now=T0), Ceremony)


def test_one_below_the_cap_a_newcomer_fits() -> None:
    table = Ceremonies(counting())
    for i in range(MAX_LOGIN_CEREMONIES - 1):
        login(table, f"p{i}")
    assert isinstance(table.begin_login(origin=ORIGIN, peer="newcomer", now=T0), Ceremony)
    assert table.logins() == MAX_LOGIN_CEREMONIES


def test_expired_ceremonies_free_their_places() -> None:
    table = Ceremonies(counting())
    for i in range(MAX_LOGIN_CEREMONIES):
        login(table, f"p{i}")
    enrol = table.begin_enrol(origin=ORIGIN, session="ab" * 16, name="One", now=T0 + 1)
    assert table.begin_login(origin=ORIGIN, peer="newcomer", now=T0 + CEREMONY_TTL - 1) == Full()
    assert isinstance(
        table.begin_login(origin=ORIGIN, peer="newcomer", now=T0 + CEREMONY_TTL), Ceremony
    )
    assert table.logins() == 1
    table.sweep(T0 + 1 + CEREMONY_TTL - 0.001)
    assert table.take(enrol.id, kind="enrol", origin=ORIGIN, now=T0, session="ab" * 16) == enrol


def test_a_peers_quota_counts_only_live_ceremonies() -> None:
    table = Ceremonies(counting())
    old = [login(table, "p1") for _ in range(MAX_LOGIN_CEREMONIES_PER_PEER - 1)]
    fresh = login(table, "p1", T0 + 10)
    login(table, "p1", T0 + CEREMONY_TTL)
    assert table.logins("p1") == 2
    assert all(table.take(c.id, kind="login", origin=ORIGIN, now=T0 + 10) is None for c in old)
    assert table.take(fresh.id, kind="login", origin=ORIGIN, now=T0 + 10) == fresh


def test_begin_enrol_sweeps_expired_ceremonies() -> None:
    table = Ceremonies(counting())
    login(table)
    table.begin_enrol(origin=ORIGIN, session="ab" * 16, name="One", now=T0 + CEREMONY_TTL)
    assert (len(table), table.logins()) == (1, 0)


# --- the stateful property ------------------------------------------------------------------------


@dataclass
class Held:
    minted: Minted
    created: float
    last_seen: float
    setup: bool

    def alive(self, now: float) -> bool:
        limit = SETUP_SESSION_MAX if self.setup else SESSION_MAX
        return now < self.created + limit and now < self.last_seen + SESSION_IDLE


class SessionMachine(RuleBasedStateMachine):
    """No sequence passes a cap; an expired or ended session never authenticates; tokens never
    repeat; eviction takes the least recently used."""

    def __init__(self) -> None:
        super().__init__()
        self.table = Sessions(counting())
        self.ceremonies = Ceremonies(counting())
        self.now = T0
        self.held: dict[str, Held] = {}
        self.ended: list[Minted] = []
        self.issued: set[str] = set()
        self.taken: set[str] = set()
        self.live_ceremonies: list[Ceremony] = []

    def _end(self, session_id: str) -> None:
        self.ended.append(self.held.pop(session_id).minted)

    @rule(origin=st.sampled_from([ORIGIN, OTHER]), setup=st.booleans(), cred=st.sampled_from("ab"))
    def mint(self, origin: str, setup: bool, cred: str) -> None:
        expired = {i for i, h in self.held.items() if not h.alive(self.now)}
        survivors = [h for i, h in self.held.items() if i not in expired]
        evicted = set()
        if len(survivors) >= MAX_SESSIONS:
            lru = min(survivors, key=lambda h: h.last_seen)
            evicted = {lru.minted.session.id}
        minted = self.table.mint(
            origin=origin,
            rp_id=RP,
            scope="setup" if setup else "full",
            now=self.now,
            credential=None if setup else cred,
        )
        assert {e.session.id for e in minted.ended if e.why != "evicted"} == expired
        assert {e.session.id for e in minted.ended if e.why == "evicted"} == evicted
        for session_id in expired | evicted:
            self._end(session_id)
        for half in (minted.cookie.reveal(), minted.header.reveal(), minted.session.id):
            assert half not in self.issued
            self.issued.add(half)
        self.held[minted.session.id] = Held(minted, self.now, self.now, setup)

    @precondition(lambda self: bool(self.held))
    @rule(data=st.data())
    def touch(self, data: st.DataObject) -> None:
        session_id = data.draw(st.sampled_from(sorted(self.held)))
        held = self.held[session_id]
        touched = self.table.touch(session_id, self.now)
        assert (touched is not None) == held.alive(self.now)
        if touched is not None:
            held.last_seen = self.now

    @precondition(lambda self: bool(self.held))
    @rule(data=st.data(), how=st.sampled_from(["logout", "others", "credential", "origin"]))
    def end(self, data: st.DataObject, how: str) -> None:
        session_id = data.draw(st.sampled_from(sorted(self.held)))
        session = self.held[session_id].minted.session
        if how == "logout":
            ended = [self.table.end(session_id, "logout")]
        elif how == "others":
            ended = list(self.table.end_others(session_id))
        elif how == "credential":
            ended = list(self.table.end_credential(session.credential or "none"))
        else:
            ended = list(self.table.end_origins([OTHER if session.origin == ORIGIN else ORIGIN]))
        for item in ended:
            assert item is not None
            self._end(item.session.id)

    @rule()
    def sweep(self) -> None:
        for item in self.table.sweep(self.now):
            assert not self.held[item.session.id].alive(self.now)
            self._end(item.session.id)
        assert all(h.alive(self.now) for h in self.held.values())

    @rule(step=st.sampled_from([0.001, 1.0, 299.0, 300.0, 600.0, 899.0, 900.0, 3600.0]))
    def wait(self, step: float) -> None:
        self.now += step

    @rule(peer=st.sampled_from(["p0", "p1", "p2", "p3", "p4"]))
    def begin_login(self, peer: str) -> None:
        result = self.ceremonies.begin_login(origin=ORIGIN, peer=peer, now=self.now)
        if isinstance(result, Ceremony):
            assert result.id not in self.taken
            self.live_ceremonies.append(result)

    @precondition(lambda self: bool(self.live_ceremonies))
    @rule(data=st.data())
    def take_login(self, data: st.DataObject) -> None:
        ceremony = data.draw(st.sampled_from(self.live_ceremonies))
        self.ceremonies.take(ceremony.id, kind="login", origin=ORIGIN, now=self.now)
        self.taken.add(ceremony.id)
        self.live_ceremonies.remove(ceremony)

    @invariant()
    def bounded(self) -> None:
        assert len(self.table) <= MAX_SESSIONS
        assert self.ceremonies.logins() <= MAX_LOGIN_CEREMONIES
        for peer in ("p0", "p1", "p2", "p3", "p4"):
            assert self.ceremonies.logins(peer) <= MAX_LOGIN_CEREMONIES_PER_PEER

    @invariant()
    def only_live_sessions_authenticate(self) -> None:
        for minted in self.ended:
            for origin in (ORIGIN, OTHER):
                assert find(self.table, minted, self.now, origin) is None
        for held in self.held.values():
            session = held.minted.session
            found = find(self.table, held.minted, self.now, session.origin)
            assert (found is not None) == held.alive(self.now)

    @invariant()
    def a_taken_ceremony_never_returns(self) -> None:
        for ceremony_id in self.taken:
            assert self.ceremonies.take(ceremony_id, kind="login", origin=ORIGIN, now=T0) is None


TestSessionMachine = SessionMachine.TestCase
TestSessionMachine.settings = hypothesis_settings(
    max_examples=50, stateful_step_count=20, deadline=None
)
