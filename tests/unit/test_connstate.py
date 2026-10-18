"""Connection keys and the connection state machine (M3 design F.3, F.4)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.gateway import connstate
from zoeymcp.gateway.connstate import (
    Admit,
    ConnState,
    Phase,
    Refuse,
    Wait,
    admit,
    backoff,
    connection_key,
    era_of,
    on_change,
    on_closed,
    on_connecting,
    on_list_failed,
    on_listed,
    on_session_expired,
    on_timer_failed,
    should_connect,
    supported_upstream_version,
)
from zoeymcp.gateway.pins import Evaluation, ExposedTool

PIN_A = "sha256:" + "a" * 64
PIN_B = "sha256:" + "b" * 64


def server(shared: bool = False, era: str = "auto") -> ViewRemoteServer:
    raw: dict[str, Any] = {
        "kind": "remote",
        "vault_path": "/notes/mcp",
        "tools": {"include": [], "allow": [], "approve": []},
        "review": {},
        "on_drift": "hide",
        "shared_session": shared,
        "wrap_results": False,
        "enable": [],
        "era": era,
        "drift_check_interval": 300,
        "call_timeout": None,
    }
    return ViewRemoteServer.model_validate(raw)


def exposing(tools: dict[str, str], blocked: bool = False) -> Evaluation:
    exposed = {name: ExposedTool({"name": name}, pin) for name, pin in tools.items()}
    return Evaluation(exposed=exposed, reports=(), marks=frozenset(), blocked=blocked)


def evaluation(blocked: bool = False, **tools: str) -> Evaluation:
    return exposing(tools, blocked)


def ready(**tools: str) -> ConnState:
    return on_listed(ConnState(), exposing(tools), now=0)


# --- F.3 and F.2 -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("era", "shared", "key"),
    [
        (None, False, ("notes", "alpha")),
        (None, True, ("notes", "alpha")),
        ("modern", False, ("notes", "*")),
        ("modern", True, ("notes", "*")),
        ("legacy", False, ("notes", "alpha")),
        ("legacy", True, ("notes", "*")),
    ],
)
def test_connection_keys(era: Any, shared: bool, key: tuple[str, str]) -> None:
    assert connection_key("notes", server(shared), era, "alpha") == key


@pytest.mark.parametrize(
    ("asserted", "shared", "key"),
    [
        ("legacy", True, ("notes", "*")),
        ("legacy", False, ("notes", "alpha")),
        ("modern", False, ("notes", "*")),
        ("auto", True, ("notes", "alpha")),
    ],
)
def test_an_asserted_era_counts_before_one_is_seen(
    asserted: str, shared: bool, key: tuple[str, str]
) -> None:
    assert connection_key("notes", server(shared, asserted), None, "alpha") == key


def test_the_era_seen_wins_over_the_asserted_one() -> None:
    assert connection_key("notes", server(True, "legacy"), "modern", "alpha") == ("notes", "*")
    assert connection_key("notes", server(False, "modern"), "legacy", "alpha") == ("notes", "alpha")


@pytest.mark.parametrize("version", ["2026-07-28", "2025-11-25", "2025-06-18"])
def test_supported_upstream_versions(version: str) -> None:
    assert supported_upstream_version(version)


@pytest.mark.parametrize("version", ["2025-03-26", "2024-11-05", None, ""])
def test_unsupported_upstream_versions(version: str | None) -> None:
    assert not supported_upstream_version(version)


def test_era_of() -> None:
    assert era_of("2026-07-28") == "modern"
    assert era_of("2025-11-25") == "legacy"
    assert era_of("2025-06-18") == "legacy"


# --- transitions -----------------------------------------------------------------------------


def test_a_new_connection_is_connecting() -> None:
    state = ConnState()
    assert (state.phase, state.evaluation, state.version, state.verified_at) == (
        Phase.CONNECTING,
        None,
        0,
        None,
    )


def test_listed_ok_is_ready() -> None:
    state = ready(a=PIN_A)
    assert state.phase is Phase.READY
    assert state.verified_at == 0
    assert state.version == 1
    assert state.failures == 0
    assert state.retry_at is None


def test_the_version_moves_only_when_the_view_changes() -> None:
    state = ready(a=PIN_A)
    same = on_listed(on_change(state), evaluation(a=PIN_A), now=5)
    assert (same.phase, same.version, same.verified_at) == (Phase.READY, 1, 5)
    other_pin = on_listed(same, evaluation(a=PIN_B), now=6)
    assert other_pin.version == 2
    other_tool = on_listed(other_pin, evaluation(a=PIN_B, b=PIN_A), now=7)
    assert other_tool.version == 3
    blocked = on_listed(other_tool, evaluation(blocked=True), now=8)
    assert blocked.version == 4
    # Blocked with nothing exposed differs from not blocked with nothing exposed.
    assert on_listed(blocked, evaluation(), now=9).version == 5


def test_a_listing_resets_failures() -> None:
    state = on_list_failed(on_list_failed(ConnState(), now=0), now=1)
    assert state.failures == 2
    state = on_listed(on_connecting(state), evaluation(), now=10)
    assert (state.failures, state.retry_at) == (0, None)


def test_a_change_signal_makes_ready_stale() -> None:
    state = on_change(ready(a=PIN_A))
    assert state.phase is Phase.STALE
    assert state.evaluation == evaluation(a=PIN_A)  # kept, for comparing
    assert on_change(state).phase is Phase.STALE


@pytest.mark.parametrize(
    "phase", [Phase.CONNECTING, Phase.RECONNECTING, Phase.FAILED, Phase.CLOSED]
)
def test_a_change_signal_elsewhere_changes_nothing(phase: Phase) -> None:
    state = ConnState(phase=phase)
    assert on_change(state) == state


def test_a_failed_listing_is_failed_with_backoff() -> None:
    state = on_list_failed(ConnState(), now=100)
    assert (state.phase, state.failures, state.retry_at) == (Phase.FAILED, 1, 101)
    state = on_list_failed(on_connecting(state), now=200)
    assert (state.failures, state.retry_at) == (2, 202)


@pytest.mark.parametrize("phase", [Phase.STALE, Phase.CONNECTING, Phase.RECONNECTING])
def test_a_failed_listing_from_any_waiting_phase_fails(phase: Phase) -> None:
    assert on_list_failed(ConnState(phase=phase), now=0).phase is Phase.FAILED


def test_backoff() -> None:
    assert [backoff(n) for n in (0, 1, 2, 3, 4)] == [1, 1, 2, 4, 8]
    assert backoff(9) == 256
    assert backoff(10) == 300
    assert backoff(50) == 300
    assert (connstate.BACKOFF_START, connstate.BACKOFF_MAX) == (1.0, 300.0)


def test_a_timer_failure_keeps_ready_for_one_more_interval() -> None:
    state = ready(a=PIN_A)
    assert on_timer_failed(state, now=600, interval=300) == state
    failed = on_timer_failed(state, now=600.5, interval=300)
    assert failed.phase is Phase.FAILED
    assert failed.failures == 1


def test_a_timer_failure_without_a_verified_listing_fails() -> None:
    state = ConnState(phase=Phase.READY, evaluation=evaluation())
    assert on_timer_failed(state, now=0, interval=300).phase is Phase.FAILED


@pytest.mark.parametrize("phase", [Phase.STALE, Phase.CONNECTING, Phase.FAILED, Phase.CLOSED])
def test_a_timer_failure_matters_only_when_ready(phase: Phase) -> None:
    state = ConnState(phase=phase, verified_at=0)
    assert on_timer_failed(state, now=10_000, interval=300) == state


@pytest.mark.parametrize("phase", [Phase.READY, Phase.STALE])
def test_session_expiry_reconnects(phase: Phase) -> None:
    state = on_session_expired(ConnState(phase=phase, evaluation=evaluation(a=PIN_A)))
    assert state.phase is Phase.RECONNECTING


@pytest.mark.parametrize(
    "phase", [Phase.CONNECTING, Phase.FAILED, Phase.CLOSED, Phase.RECONNECTING]
)
def test_session_expiry_elsewhere_changes_nothing(phase: Phase) -> None:
    state = ConnState(phase=phase)
    assert on_session_expired(state) == state


def test_closed_is_final() -> None:
    state = on_closed(ready(a=PIN_A))
    assert state.phase is Phase.CLOSED
    assert on_listed(state, evaluation(a=PIN_A), now=1) == state
    assert on_list_failed(state, now=1) == state
    assert on_change(state) == state


def test_should_connect() -> None:
    failed = on_list_failed(ConnState(), now=100)
    assert not should_connect(failed, now=100.5)
    assert should_connect(failed, now=101)
    assert should_connect(ConnState(phase=Phase.FAILED), now=0)
    assert should_connect(ConnState(phase=Phase.CLOSED), now=0)
    for phase in (Phase.CONNECTING, Phase.READY, Phase.STALE, Phase.RECONNECTING):
        assert not should_connect(ConnState(phase=phase), now=10**6)


def test_connecting_again_keeps_failures_and_version() -> None:
    state = on_list_failed(ready(a=PIN_A), now=5)
    again = on_connecting(state)
    assert again == ConnState(phase=Phase.CONNECTING, version=1, failures=1)


# --- admit -----------------------------------------------------------------------------------


def test_admit_an_exposed_tool() -> None:
    assert admit(ready(a=PIN_A), set(), "a", now=1) == Admit(PIN_A)


def test_refuse_an_unexposed_tool() -> None:
    assert admit(ready(a=PIN_A), set(), "b", now=1) == Refuse("tool not exposed")


def test_refuse_a_marked_tool() -> None:
    assert admit(ready(a=PIN_A), {("a", PIN_A)}, "a", now=1) == Refuse("tool marked")
    # A mark for another pin, or another tool, doesn't apply.
    assert admit(ready(a=PIN_A), {("a", PIN_B), ("b", PIN_A)}, "a", now=1) == Admit(PIN_A)


def test_a_blocked_server_admits_nothing() -> None:
    state = on_listed(ConnState(), evaluation(blocked=True), now=0)
    assert admit(state, set(), "a", now=1) == Refuse("tool not exposed")


@pytest.mark.parametrize("phase", [Phase.STALE, Phase.CONNECTING, Phase.RECONNECTING])
def test_waiting_phases_wait_up_to_ten_seconds(phase: Phase) -> None:
    state = ConnState(phase=phase, evaluation=evaluation(a=PIN_A))
    assert admit(state, set(), "a", now=100) == Wait(until=110)
    assert admit(state, set(), "a", now=105, waiting_since=100) == Wait(until=110)
    assert admit(state, set(), "a", now=109.9, waiting_since=100) == Wait(until=110)
    assert admit(state, set(), "a", now=110, waiting_since=100) == Refuse(
        "upstream not ready in time"
    )
    assert connstate.ADMIT_WAIT == 10.0


@pytest.mark.parametrize("phase", [Phase.FAILED, Phase.CLOSED])
def test_failed_and_closed_refuse(phase: Phase) -> None:
    state = ConnState(phase=phase, evaluation=evaluation(a=PIN_A))
    assert admit(state, set(), "a", now=0) == Refuse(f"connection {phase.value}")


def test_ready_without_an_evaluation_refuses() -> None:
    assert admit(ConnState(phase=Phase.READY), set(), "a", now=0) == Refuse("connection ready")


# --- the G8 property -------------------------------------------------------------------------

EVENTS = st.lists(
    st.sampled_from(["listed", "failed", "change", "timer_failed", "expired", "closed", "connect"]),
    max_size=30,
)


def step(state: ConnState, event: str, now: float) -> ConnState:
    if event == "listed":
        return on_listed(state, evaluation(a=PIN_A), now)
    if event == "failed":
        return on_list_failed(state, now)
    if event == "change":
        return on_change(state)
    if event == "timer_failed":
        return on_timer_failed(state, now, interval=300)
    if event == "expired":
        return on_session_expired(state)
    if event == "closed":
        return on_closed(state)
    return on_connecting(state) if should_connect(state, now) else state


@given(before=EVENTS, after=EVENTS)
def test_property_after_a_change_signal_nothing_is_admitted_until_a_listing(
    before: list[str], after: list[str]
) -> None:
    state = ConnState()
    now = 0.0
    for event in before:
        now += 100
        state = step(state, event, now)
    state = on_change(state)
    for event in after:
        now += 100
        if event == "listed" and state.phase is not Phase.CLOSED:
            return  # a successful listing: admission may resume
        state = step(state, event, now)
        assert not isinstance(admit(state, set(), "a", now), Admit)
    assert not isinstance(admit(state, set(), "a", now), Admit)


@given(events=EVENTS)
def test_property_admit_only_when_ready(events: list[str]) -> None:
    state = ConnState()
    now = 0.0
    for event in events:
        now += 100
        state = step(state, event, now)
        if isinstance(admit(state, set(), "a", now), Admit):
            assert state.phase is Phase.READY
