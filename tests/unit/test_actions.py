"""Pending actions (M5 design F.3, F.4, O.2): the challenge against a fixed vector, what changes
it, single use, the TTL, one per session, the registry, and a re-plan that differs."""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Callable
from typing import Any

import pytest

from zoeymcp.common.canonical import digest
from zoeymcp.portal import actions
from zoeymcp.portal.actions import (
    ACTION_TTL,
    KINDS,
    MAX_ACTIONS_BODY,
    MAX_ACTIONS_PER_SESSION,
    STEP_UP_TAG,
    Action,
    ActionRefusal,
    Actions,
    HeldData,
    Kind,
    Request,
    changed,
    parse_request,
)
from zoeymcp.vault.secretplan import PutPlan

ORIGIN = "http://localhost:8081"
OTHER = "https://zoeymcp.tailnet.example"
SESSION = "ab" * 16
T0 = 1_760_000_000.0
DATA = {"name": "notes-key", "value": "fake-value-0001"}


def counting() -> Callable[[int], bytes]:
    counter = itertools.count(1)
    return lambda n: next(counter).to_bytes(n, "big")


def scripted(*chunks: bytes) -> Callable[[int], bytes]:
    queue = list(chunks)
    return lambda n: queue.pop(0)


def prepare(
    table: Actions,
    *,
    kind: str = "secret.put",
    data: Any = DATA,
    plan: Any = "plan",
    session: str = SESSION,
    origin: str = ORIGIN,
    now: float = T0,
) -> Action:
    return table.prepare(kind=kind, data=data, plan=plan, session=session, origin=origin, now=now)


def test_the_constants_are_the_designs() -> None:
    assert (ACTION_TTL, MAX_ACTIONS_PER_SESSION, MAX_ACTIONS_BODY) == (300.0, 1, 128 * 1024)
    assert STEP_UP_TAG == b"zoeymcp/webauthn/step-up/v1\n"


# --- the registry ---------------------------------------------------------------------------------


def test_the_registry_holds_f4s_kinds() -> None:
    shapes = {
        name: (kind.cap, sorted(kind.required), sorted(kind.optional))
        for name, kind in KINDS.items()
    }
    assert shapes == {
        "secret.put": (131072, ["name", "value"], ["origins"]),
        "secret.delete": (4096, ["name"], []),
        "oauth.complete": (8192, ["credential", "flow"], ["redirect_url", "returned"]),
        "oauth.reset": (4096, ["credential"], []),
        "passkey.enrol": (4096, ["name"], []),
        "passkey.rename": (4096, ["credential", "name"], []),
        "passkey.remove": (4096, ["credential"], []),
        "ledger.restart": (4096, [], []),
    }
    assert all(name == kind.name for name, kind in KINDS.items())


def test_a_kinds_optional_keys_default_to_empty() -> None:
    assert Kind("x", 1, frozenset()).optional == frozenset()


@pytest.mark.parametrize("name", sorted(KINDS))
def test_each_kind_takes_a_body_up_to_its_cap(name: str) -> None:
    kind = KINDS[name]
    data = dict.fromkeys(kind.required, "x")
    assert parse_request({"kind": name, "data": data}, kind.cap) == Request(kind, data)
    assert parse_request({"kind": name, "data": data}, kind.cap + 1) == ActionRefusal(
        413, "too_large"
    )


@pytest.mark.parametrize("kind", ["secret.get", "", None, 1, ["secret.put"]])
def test_an_unknown_kind_is_a_bad_body(kind: object) -> None:
    assert parse_request({"kind": kind, "data": {}}, 2) == ActionRefusal(400, "bad_body")


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        "name",
        {"name": "x"},
        {"value": "x"},
        {"name": "x", "value": "y", "extra": 1},
        {"name": "x", "value": "y", "origins": [], "extra": 1},
    ],
)
def test_data_without_the_kinds_keys_is_a_bad_body(data: object) -> None:
    assert parse_request({"kind": "secret.put", "data": data}, 2) == ActionRefusal(400, "bad_body")


def test_optional_keys_may_be_given() -> None:
    data = {"name": "x", "value": "y", "origins": ["https://a.example"]}
    assert parse_request({"kind": "secret.put", "data": data}, 2) == Request(
        KINDS["secret.put"], data
    )
    assert parse_request({"kind": "ledger.restart", "data": {}}, 2) == Request(
        KINDS["ledger.restart"], {}
    )


def test_the_kind_is_checked_before_the_size() -> None:
    assert parse_request({"kind": "nope", "data": {}}, 10**9) == ActionRefusal(400, "bad_body")


def test_the_size_is_checked_before_the_data() -> None:
    assert parse_request({"kind": "oauth.reset", "data": []}, 4097) == ActionRefusal(
        413, "too_large"
    )


# --- held data and the challenge ------------------------------------------------------------------


def test_held_data_hides_itself() -> None:
    held = HeldData(DATA)
    assert held.reveal() is DATA
    assert repr(held) == str(held) == "HeldData(<hidden>)"
    assert held.digest() == digest(DATA)
    assert held.digest() == (
        "sha256:" + hashlib.sha256(b'{"name":"notes-key","value":"fake-value-0001"}').hexdigest()
    )


def test_the_challenge_against_a_fixed_vector() -> None:
    action = prepare(Actions(scripted(b"\x11" * 16, b"\x22" * 32)))
    assert (action.id, action.nonce) == ("11" * 16, b"\x22" * 32)
    assert action.binding() == {
        "action": "11" * 16,
        "kind": "secret.put",
        "origin": ORIGIN,
        "session": SESSION,
        "data": "sha256:062187ce40673f4228e1ace48211733de622291ed41aa5220e31dc569d890594",
    }
    assert action.challenge.hex() == (
        "036fdba58b35eef676d4a20aafb586d48eff50ee74c7a7b2c59f10415442a6b6"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "12" * 16),
        ("kind", "secret.delete"),
        ("data", HeldData({"name": "notes-key", "value": "fake-value-0002"})),
        ("session", "ac" * 16),
        ("origin", OTHER),
        ("nonce", b"\x23" * 32),
    ],
)
def test_any_change_changes_the_challenge(field: str, value: object) -> None:
    action = prepare(Actions(scripted(b"\x11" * 16, b"\x22" * 32)))
    other = Action(**{**action.__dict__, field: value})
    assert other.challenge != action.challenge


def test_the_plan_is_not_in_the_challenge() -> None:
    # The plan is the vault's own; confirm re-plans instead.
    action = prepare(Actions(scripted(b"\x11" * 16, b"\x22" * 32)))
    assert Action(**{**action.__dict__, "plan": "other"}).challenge == action.challenge


def test_an_action_hides_what_it_holds() -> None:
    action = prepare(Actions(counting()))
    assert repr(action) == f"Action(kind=secret.put, expires={T0 + ACTION_TTL})"
    assert "fake-value-0001" not in repr(action)


# --- the table ------------------------------------------------------------------------------------


def test_prepare_holds_the_action_for_its_ttl() -> None:
    table = Actions(counting())
    action = prepare(table, plan=("Store", "notes-key"))
    assert (action.kind, action.session, action.origin) == ("secret.put", SESSION, ORIGIN)
    assert action.data.reveal() == DATA
    assert action.plan == ("Store", "notes-key")
    assert action.expires == T0 + ACTION_TTL
    assert len(action.id) == 32
    assert len(action.nonce) == 32
    assert table.pending(SESSION, T0) == action
    assert len(table) == 1


def test_an_action_is_single_use() -> None:
    table = Actions(counting())
    action = prepare(table)
    assert table.take(action.id, session=SESSION, origin=ORIGIN, now=T0) == action
    assert table.take(action.id, session=SESSION, origin=ORIGIN, now=T0) is None
    assert table.pending(SESSION, T0) is None
    assert len(table) == 0


def test_an_action_expires_at_its_second() -> None:
    table = Actions(counting())
    action = prepare(table)
    end = T0 + ACTION_TTL
    assert table.pending(SESSION, end - 0.001) == action
    assert table.pending(SESSION, end) is None
    assert table.take(action.id, session=SESSION, origin=ORIGIN, now=end - 0.001) == action
    late = prepare(table)
    assert table.take(late.id, session=SESSION, origin=ORIGIN, now=end) is None
    # Taken out even so.
    assert len(table) == 0


@pytest.mark.parametrize(
    ("action_id", "session", "origin"),
    [("12" * 16, SESSION, ORIGIN), (None, "ac" * 16, ORIGIN), (None, SESSION, OTHER)],
)
def test_a_foreign_action_is_unknown_and_stays(
    action_id: str | None, session: str, origin: str
) -> None:
    table = Actions(counting())
    action = prepare(table)
    found = action_id or action.id
    assert table.take(found, session=session, origin=origin, now=T0) is None
    assert not table.cancel(found, session=session, origin=origin, now=T0)
    assert table.take(action.id, session=SESSION, origin=ORIGIN, now=T0) == action


def test_one_action_per_session() -> None:
    table = Actions(counting())
    first = prepare(table)
    other = prepare(table, session="ac" * 16)
    second = prepare(table, kind="secret.delete", data={"name": "notes-key"})
    assert len(table) == 2
    assert table.take(first.id, session=SESSION, origin=ORIGIN, now=T0) is None
    assert table.take(second.id, session=SESSION, origin=ORIGIN, now=T0) == second
    assert table.pending("ac" * 16, T0) == other


def test_cancel_drops_a_live_action() -> None:
    table = Actions(counting())
    action = prepare(table)
    assert table.cancel(action.id, session=SESSION, origin=ORIGIN, now=T0)
    assert not table.cancel(action.id, session=SESSION, origin=ORIGIN, now=T0)
    assert len(table) == 0
    late = prepare(table)
    assert not table.cancel(late.id, session=SESSION, origin=ORIGIN, now=T0 + ACTION_TTL)
    assert len(table) == 0


def test_an_ended_session_drops_its_action() -> None:
    table = Actions(counting())
    prepare(table)
    kept = prepare(table, session="ac" * 16)
    table.drop_session(SESSION)
    table.drop_session(SESSION)
    assert table.pending(SESSION, T0) is None
    assert table.pending("ac" * 16, T0) == kept


def test_sweep_drops_expired_actions() -> None:
    table = Actions(counting())
    old = prepare(table)
    young = prepare(table, session="ac" * 16, now=T0 + 1)
    table.sweep(T0 + ACTION_TTL)
    assert len(table) == 1
    assert table.pending("ac" * 16, T0 + 1) == young
    assert old.id != young.id


def test_the_default_randomness_is_the_system_s() -> None:
    table = Actions()
    first, second = prepare(table), prepare(table, session="ac" * 16)
    assert first.id != second.id
    assert first.nonce != second.nonce
    assert len(first.id) == 32
    assert len(first.nonce) == 32


# --- re-planning ----------------------------------------------------------------------------------


def test_a_replan_that_differs_is_changed() -> None:
    plan = PutPlan("notes-key", "fake-value-0001", {"origins": ["https://a.example"]}, False)
    action = prepare(Actions(counting()), plan=plan)
    same = PutPlan("notes-key", "fake-value-0001", {"origins": ["https://a.example"]}, False)
    assert not changed(action, same)
    assert changed(action, PutPlan("notes-key", "fake-value-0001", {"origins": []}, False))
    # The value is hidden from repr but not from the comparison (step 4b).
    assert changed(action, PutPlan("notes-key", "fake-value-0002", plan.binding, False))
    assert changed(action, None)


def test_changed_answers_a_bool() -> None:
    class Odd:
        def __ne__(self, other: object) -> Any:
            return "yes"

    action = prepare(Actions(counting()), plan=Odd())
    assert changed(action, 1) is True


def test_the_module_registers_its_refused_types() -> None:
    from zoeymcp.common import logs

    assert {actions.HeldData, actions.Action} <= set(logs.refused_types())
