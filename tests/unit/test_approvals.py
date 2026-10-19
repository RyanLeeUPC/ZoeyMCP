"""The approval core: table, locks, rate limits, handles and decisions (M4 design E, D.1, D.6)."""

from __future__ import annotations

import io
from typing import Any

import pytest
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from zoeymcp.common import logs
from zoeymcp.gateway import approvals
from zoeymcp.gateway.approvals import (
    HANDLE_PATTERN,
    MAX_RECORDS,
    MAX_TOMBSTONES,
    Buried,
    Busy,
    Closed,
    ConfirmCode,
    Cooldown,
    Foreign,
    Full,
    HourlyCap,
    Key,
    Live,
    Pending,
    PendingCap,
    Settings,
    Table,
    Tombstone,
    Unknown,
    can_ask,
    decide_answer,
    handle_sha256,
    may_reask,
    new_code,
    new_handle,
    retry,
)

SETTINGS = Settings(
    timeout=300, call_timeout=60, cooldown=15, max_pending_per_client=1, max_prompts_per_hour=30
)
KEY = Key("agent1", "mail", "send_note")
DIGEST = "sha256:" + "a" * 64
PIN = "sha256:" + "b" * 64


def begin(
    table: Table,
    key: Key = KEY,
    *,
    ref: str = "r1",
    now: float = 0.0,
    era: Any = "modern",
    handle: str | None = None,
    settings: Settings = SETTINGS,
    session: str | None = None,
) -> Pending | Any:
    return table.begin(
        key,
        settings=settings,
        now=now,
        ref=ref,
        era=era,
        args={"subject": "Hi"},
        args_digest=DIGEST,
        pin=PIN,
        text_sha256="t",
        session_sha256=session,
        handle_sha256=handle_sha256(handle) if handle else None,
    )


def a_handle() -> str:
    return new_handle().reveal()


# --- secrets -------------------------------------------------------------------------------------


def test_handles_are_unguessable_and_well_formed() -> None:
    values = {a_handle() for _ in range(200)}
    assert len(values) == 200
    assert all(HANDLE_PATTERN.match(v) for v in values)
    handle = new_handle()
    assert handle.sha256() == handle_sha256(handle.reveal())
    assert handle.reveal() not in repr(handle)


def test_codes() -> None:
    code = new_code()
    assert len(code.reveal()) == 4
    assert set(code.reveal()) <= set(approvals.CODE_ALPHABET)
    assert code.reveal() not in repr(code)
    fixed = ConfirmCode("K7QD")
    assert fixed.matches("K7QD")
    assert fixed.matches(" k7qd \n")
    assert not fixed.matches("K7Q")
    assert not fixed.matches("K7QDX")
    assert not fixed.matches(None)
    assert not fixed.matches(1234)


def test_secrets_refuse_to_be_logged() -> None:
    table = Table()
    record = begin(table)
    assert isinstance(record, Pending)
    assert "subject" not in repr(record)
    log = logs.Log("gateway")
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        for value in (new_handle(), new_code(), record):
            with pytest.raises(TypeError):
                log.event("probe", value=value)
    finally:
        logs.set_stream(None)
    assert stream.getvalue() == ""


# --- begin and its refusals ----------------------------------------------------------------------


def test_begin_records_the_prompt_and_its_deadlines() -> None:
    table = Table()
    handle = a_handle()
    record = begin(table, now=100.0, handle=handle)
    assert isinstance(record, Pending)
    assert (record.asks, record.asked_at, record.expires_at) == (1, 100.0, 400.0)
    assert record.hard_deadline == 400.0 + 60 + 30
    assert record.decision is None
    assert table.get("r1") == record
    assert table.lookup(handle_sha256(handle), 101.0) == record
    assert len(table) == 1


def test_one_call_per_tool_at_a_time() -> None:
    table = Table()
    begin(table, now=0.0)
    refusal = begin(table, ref="r2", now=10.0)
    assert refusal == Busy("r1", 380)  # frees by the hard deadline, 390 s after asking
    # Another client, or the same tool on another server, is another lock.
    assert isinstance(begin(table, Key("agent2", "mail", "send_note"), ref="r3"), Pending)
    assert isinstance(begin(table, Key("agent3", "other", "send_note"), ref="r4"), Pending)


def test_the_pending_cap_counts_undecided_prompts_per_client() -> None:
    table = Table()
    begin(table)
    other_tool = Key("agent1", "mail", "other")
    assert begin(table, other_tool, ref="r2") == PendingCap("r1")
    table.decide("r1", "accept", 1.0)  # decided: no longer waiting, though the lock is held
    assert isinstance(begin(table, other_tool, ref="r2"), Pending)
    wider = Settings(300, 60, 15, max_pending_per_client=2, max_prompts_per_hour=30)
    third = Key("agent1", "mail", "third")
    assert isinstance(begin(table, third, ref="r3", settings=wider), Pending)


def test_the_pending_cap_names_the_oldest_waiting_prompt() -> None:
    table = Table()
    wide = Settings(300, 60, 15, max_pending_per_client=2, max_prompts_per_hour=30)
    begin(table, Key("agent1", "s", "a"), ref="old", now=1.0, settings=wide)
    begin(table, Key("agent1", "s", "b"), ref="new", now=2.0, settings=wide)
    assert begin(table, Key("agent1", "s", "c"), ref="x", now=3.0, settings=wide) == PendingCap(
        "old"
    )


def test_the_hourly_cap_is_rolling() -> None:
    table = Table()
    capped = Settings(300, 60, 0, max_pending_per_client=1, max_prompts_per_hour=2)
    for index, now in enumerate((0.0, 100.0)):
        ref = f"r{index}"
        assert isinstance(begin(table, ref=ref, now=now, settings=capped), Pending)
        table.decide(ref, "accept", now)
        assert table.finish(KEY, ref, now, settings_cooldown=0)
    assert begin(table, ref="r2", now=3599.0, settings=capped) == HourlyCap()
    assert isinstance(begin(table, ref="r2", now=3600.0, settings=capped), Pending)
    # Refusals don't count against the cap.
    table.decide("r2", "accept", 3600.0)
    table.finish(KEY, "r2", 3600.0, settings_cooldown=0)
    assert begin(table, ref="r3", now=3600.5, settings=capped) == HourlyCap()


@pytest.mark.parametrize("decision", sorted(approvals.COOLDOWN_DECISIONS))
def test_a_decline_like_decision_starts_the_cooldown(decision: Any) -> None:
    table = Table()
    begin(table)
    table.decide("r1", decision, 10.0)
    assert table.finish(KEY, "r1", 10.0, settings_cooldown=15)
    assert begin(table, ref="r2", now=11.0) == Cooldown(14)
    assert begin(table, ref="r2", now=24.5) == Cooldown(1)
    assert isinstance(begin(table, ref="r2", now=25.0), Pending)
    # Only that tool: another tool of the client isn't cooling down.
    table2 = Table()
    begin(table2)
    table2.decide("r1", decision, 10.0)
    table2.finish(KEY, "r1", 10.0, settings_cooldown=15)
    assert isinstance(begin(table2, Key("agent1", "mail", "other"), ref="x", now=11.0), Pending)


@pytest.mark.parametrize(
    "decision",
    ["accept", "withdrawn", "stream_lost", "unavailable", "error", "changed", "shutdown"],
)
def test_other_decisions_start_no_cooldown(decision: Any) -> None:
    table = Table()
    begin(table)
    table.decide("r1", decision, 10.0)
    table.finish(KEY, "r1", 10.0, settings_cooldown=15)
    assert isinstance(begin(table, ref="r2", now=10.0), Pending)


def test_no_cooldown_when_it_is_zero() -> None:
    table = Table()
    begin(table)
    table.decide("r1", "decline", 0.0)
    table.finish(KEY, "r1", 0.0, settings_cooldown=0)
    assert isinstance(begin(table, ref="r2", now=0.0), Pending)


def test_the_table_is_bounded() -> None:
    table = Table()
    roomy = Settings(300, 60, 0, max_pending_per_client=16, max_prompts_per_hour=1000)
    for index in range(MAX_RECORDS):
        key = Key(f"c{index // 16}", "s", f"t{index % 16}")
        assert isinstance(begin(table, key, ref=f"r{index}", settings=roomy), Pending)
    assert begin(table, Key("late", "s", "t"), ref="x", settings=roomy) == Full()


# --- finish, withdraw, sweep ----------------------------------------------------------------------


def test_only_the_owner_frees_the_lock() -> None:
    table = Table()
    begin(table)
    assert not table.finish(KEY, "stranger", 1.0, settings_cooldown=15)
    assert table.get("r1") is not None
    assert not table.finish(Key("agent1", "mail", "x"), "r1", 1.0, settings_cooldown=15)
    assert table.finish(KEY, "r1", 1.0, settings_cooldown=15)
    assert not table.finish(KEY, "r1", 1.0, settings_cooldown=15)  # a late finally
    assert table.get("r1") is None


def test_finishing_an_undecided_record_decides_error() -> None:
    table = Table()
    begin(table)
    assert table.finish(KEY, "r1", 1.0, settings_cooldown=15)
    assert isinstance(begin(table, ref="r2", now=1.0), Pending)  # error starts no cooldown


def test_the_first_decision_stands() -> None:
    table = Table()
    begin(table)
    assert table.decide("r1", "withdrawn", 1.0).decision == "withdrawn"
    assert table.decide("r1", "accept", 2.0).decision == "withdrawn"


def test_withdraw_decides_the_matching_undecided_records() -> None:
    table = Table()
    begin(table, ref="a")
    begin(table, Key("agent2", "mail", "send_note"), ref="b")
    begin(table, Key("agent3", "mail", "send_note"), ref="c")
    table.decide("c", "accept", 1.0)
    found = table.withdraw(lambda p: p.key.server == "mail", "shutdown", 2.0)
    assert sorted(p.ref for p in found) == ["a", "b"]
    assert all(p.decision == "shutdown" for p in found)
    assert table.get("c").decision == "accept"  # type: ignore[union-attr]
    assert table.withdraw(lambda p: True, "shutdown", 3.0) == []


def test_sweep_expires_modern_prompts_and_frees_overdue_locks() -> None:
    table = Table()
    handle = a_handle()
    begin(table, ref="modern", handle=handle)
    begin(table, Key("agent2", "s", "t"), ref="legacy", era="legacy", session="s1")
    assert table.sweep(299.0).expired == []
    swept = table.sweep(300.0)
    assert [p.ref for p in swept.expired] == ["modern"]
    assert swept.expired[0].decision == "timeout"
    assert table.lookup(handle_sha256(handle), 301.0) == Tombstone("expired", 900.0)
    assert table.get("legacy").decision is None  # type: ignore[union-attr]
    assert table.sweep(300.0).expired == []  # once
    swept = table.sweep(390.0)
    assert sorted(p.ref for p in swept.freed) == ["legacy", "modern"]
    assert len(table) == 0


def test_a_record_mid_retry_isnt_expired_by_the_sweeper() -> None:
    table = Table()
    handle = a_handle()
    begin(table, handle=handle)
    result = retry(table, handle, key=KEY, args_digest=DIGEST, pin=PIN, now=10.0)
    assert isinstance(result, Live)
    assert table.sweep(300.0).expired == []  # its retry handler owns it now
    assert [p.ref for p in table.sweep(390.0).freed] == ["r1"]


def test_legacy_waiting() -> None:
    table = Table()
    begin(table, era="legacy", session="s1")
    assert table.legacy_waiting("s1")
    assert table.legacy_waiting_count("s1") == 1
    assert not table.legacy_waiting("s2")
    assert table.legacy_waiting_count("s2") == 0
    wide = Settings(300, 60, 15, max_pending_per_client=2, max_prompts_per_hour=30)
    begin(
        table, Key("agent1", "mail", "other"), ref="r2", era="legacy", session="s1", settings=wide
    )
    begin(table, Key("agent1", "mail", "third"), ref="r3", handle=a_handle(), settings=wide)
    assert table.legacy_waiting_count("s1") == 2  # a modern record has no session
    table.decide("r1", "accept", 1.0)
    assert table.legacy_waiting_count("s1") == 1
    table.decide("r2", "decline", 1.0)
    assert not table.legacy_waiting("s1")


# --- the modern retry ----------------------------------------------------------------------------


def test_a_valid_retry_consumes_the_handle_once() -> None:
    table = Table()
    handle = a_handle()
    begin(table, handle=handle)
    first = retry(table, handle, key=KEY, args_digest=DIGEST, pin=PIN, now=10.0)
    assert isinstance(first, Live)
    assert first.record.handle_sha256 is None
    assert retry(table, handle, key=KEY, args_digest=DIGEST, pin=PIN, now=11.0) == Buried("used")


@pytest.mark.parametrize(
    "state",
    [None, 1, "", "za1.short", "za2." + "a" * 43, "za1." + "!" * 43, "za1." + "a" * 43 + chr(10)],
)
def test_malformed_handles_are_unknown(state: object) -> None:
    table = Table()
    begin(table, handle=a_handle())
    assert retry(table, state, key=KEY, args_digest=DIGEST, pin=PIN, now=1.0) == Unknown()


def test_a_guessed_handle_is_unknown() -> None:
    table = Table()
    begin(table, handle=a_handle())
    assert retry(table, a_handle(), key=KEY, args_digest=DIGEST, pin=PIN, now=1.0) == Unknown()


@pytest.mark.parametrize(
    "other",
    [
        Key("agent2", "mail", "send_note"),
        Key("agent1", "other", "send_note"),
        Key("agent1", "mail", "x"),
    ],
)
def test_a_foreign_presentation_leaves_the_record_alone(other: Key) -> None:
    table = Table()
    handle = a_handle()
    begin(table, handle=handle)
    before = table.get("r1")
    assert retry(table, handle, key=other, args_digest=DIGEST, pin=PIN, now=1.0) == Foreign()
    assert table.get("r1") == before
    assert isinstance(retry(table, handle, key=KEY, args_digest=DIGEST, pin=PIN, now=2.0), Live)


def test_changed_arguments_or_pin_close_the_record() -> None:
    for digest, pin in (("sha256:" + "c" * 64, PIN), (DIGEST, "sha256:" + "d" * 64)):
        table = Table()
        handle = a_handle()
        begin(table, handle=handle)
        result = retry(table, handle, key=KEY, args_digest=digest, pin=pin, now=1.0)
        assert isinstance(result, Closed)
        assert result.record.decision == "mismatch"
        assert retry(table, handle, key=KEY, args_digest=DIGEST, pin=PIN, now=2.0) == Buried("used")


def test_a_late_retry_is_a_timeout() -> None:
    table = Table()
    handle = a_handle()
    begin(table, handle=handle)
    result = retry(table, handle, key=KEY, args_digest=DIGEST, pin=PIN, now=300.0)
    assert isinstance(result, Closed)
    assert result.record.decision == "timeout"


def test_a_reask_keeps_the_prompt_under_a_new_handle() -> None:
    table = Table()
    first = a_handle()
    begin(table, handle=first)
    live = retry(table, first, key=KEY, args_digest=DIGEST, pin=PIN, now=1.0)
    assert isinstance(live, Live)
    assert may_reask(live.record)
    second = a_handle()
    record = table.reask("r1", handle_sha256(second))
    assert (record.ref, record.asks, record.expires_at, record.text_sha256) == ("r1", 2, 300.0, "t")
    assert retry(table, first, key=KEY, args_digest=DIGEST, pin=PIN, now=2.0) == Buried("used")
    again = retry(table, second, key=KEY, args_digest=DIGEST, pin=PIN, now=3.0)
    assert isinstance(again, Live)
    table.reask("r1", handle_sha256(a_handle()))
    assert not may_reask(table.get("r1"))  # type: ignore[arg-type]


def test_tombstones_expire_and_are_bounded() -> None:
    table = Table()
    handle = a_handle()
    begin(table, handle=handle)
    retry(table, handle, key=KEY, args_digest=DIGEST, pin=PIN, now=1.0)
    assert table.lookup(handle_sha256(handle), 600.9) == Tombstone("used", 601.0)
    assert table.lookup(handle_sha256(handle), 601.0) is None
    for index in range(MAX_TOMBSTONES + 5):
        table._bury(f"h{index}", "used", 0.0)
    assert len(table._tombstones) == MAX_TOMBSTONES
    assert "h0" not in table._tombstones
    assert f"h{MAX_TOMBSTONES + 4}" in table._tombstones


# --- the gate and the answer ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("declared", "form", "url", "expected"),
    [
        (False, False, False, False),  # no elicitation at all
        (True, False, False, True),  # {}: form mode only (2025-11-25)
        (True, True, False, True),
        (True, False, True, False),  # URL only
        (True, True, True, True),
    ],
)
def test_can_ask(declared: bool, form: bool, url: bool, expected: bool) -> None:
    assert (
        can_ask("modern", declared=declared, form=form, url=url, can_send_request=False) is expected
    )
    assert (
        can_ask("legacy", declared=declared, form=form, url=url, can_send_request=True) is expected
    )
    # A stateless legacy request can't send the prompt at all.
    assert not can_ask("legacy", declared=declared, form=form, url=url, can_send_request=False)


@pytest.mark.parametrize(
    ("action", "content", "code", "expected"),
    [
        ("accept", None, None, "accept"),
        ("accept", {}, None, "accept"),
        ("accept", {"anything": 1}, None, "accept"),
        ("decline", None, None, "decline"),
        ("cancel", None, None, "dismiss"),
        ("ACCEPT", None, None, "error"),
        (None, None, None, "error"),
        ("accept", {"code": "k7qd"}, ConfirmCode("K7QD"), "accept"),
        ("accept", {"code": "K7QX"}, ConfirmCode("K7QD"), "code_mismatch"),
        ("accept", {}, ConfirmCode("K7QD"), "code_mismatch"),
        ("accept", None, ConfirmCode("K7QD"), "code_mismatch"),
        ("accept", {"code": ["K7QD"]}, ConfirmCode("K7QD"), "code_mismatch"),
        ("decline", {"code": "K7QD"}, ConfirmCode("K7QD"), "decline"),
    ],
)
def test_decide_answer(
    action: object, content: object, code: ConfirmCode | None, expected: str
) -> None:
    assert decide_answer(action, content, code) == expected


# --- properties (E.2) ----------------------------------------------------------------------------

CLIENTS = ["a", "b"]
TOOLS = [Key(c, "s", t) for c in CLIENTS for t in ("x", "y", "z")]
TIGHT = Settings(
    timeout=30, call_timeout=10, cooldown=5, max_pending_per_client=1, max_prompts_per_hour=4
)


class TableMachine(RuleBasedStateMachine):
    @initialize()
    def start(self) -> None:
        self.table = Table()
        self.now = 0.0
        self.count = 0
        self.handles: dict[str, str] = {}  # handle -> ref it was issued for
        self.consumed: set[str] = set()
        self.begins: list[tuple[float, str]] = []

    @rule(key=st.sampled_from(TOOLS), modern=st.booleans())
    def begin(self, key: Key, modern: bool) -> None:
        self.count += 1
        ref = f"r{self.count}"
        handle = a_handle() if modern else None
        result = begin(
            self.table,
            key,
            ref=ref,
            now=self.now,
            era="modern" if modern else "legacy",
            handle=handle,
            settings=TIGHT,
        )
        if isinstance(result, Pending):
            self.begins.append((self.now, key.client))
            if handle is not None:
                self.handles[handle] = ref

    @rule(data=st.data(), as_owner=st.booleans())
    def present(self, data: st.DataObject, as_owner: bool) -> None:
        if not self.handles:
            return
        handle = data.draw(st.sampled_from(sorted(self.handles)))
        ref = self.handles[handle]
        record = self.table.get(ref)
        owner = record.key if record is not None else TOOLS[0]
        key = owner if as_owner else Key("intruder", owner.server, owner.tool)
        before = self.table.get(ref)
        result = retry(self.table, handle, key=key, args_digest=DIGEST, pin=PIN, now=self.now)
        if isinstance(result, Foreign):
            assert self.table.get(ref) == before  # a foreign lookup never changes a record
        if isinstance(result, Live | Closed):
            assert handle not in self.consumed  # a handle is consumed at most once
            self.consumed.add(handle)

    @rule(data=st.data(), decision=st.sampled_from(["accept", "decline", "timeout", "withdrawn"]))
    def decide(self, data: st.DataObject, decision: Any) -> None:
        records = list(self.table.records())
        if records:
            record = data.draw(st.sampled_from(records))
            self.table.decide(record.ref, decision, self.now)

    @rule(data=st.data(), stranger=st.booleans())
    def finish(self, data: st.DataObject, stranger: bool) -> None:
        records = list(self.table.records())
        if not records:
            return
        record = data.draw(st.sampled_from(records))
        freed = self.table.finish(
            record.key,
            "stranger" if stranger else record.ref,
            self.now,
            settings_cooldown=TIGHT.cooldown,
        )
        assert freed is not stranger  # a stranger never frees a lock; the owner always does

    @rule(seconds=st.floats(min_value=0, max_value=40))
    def wait(self, seconds: float) -> None:
        self.now += seconds

    @rule()
    def sweep(self) -> None:
        self.table.sweep(self.now)
        for record in self.table.records():
            assert record.hard_deadline > self.now  # after the hard deadline, a sweep frees it
            if record.era == "modern" and record.handle_sha256 is not None:
                assert record.decision is not None or record.expires_at > self.now

    @rule(server=st.sampled_from(["s", "t"]))
    def withdraw(self, server: str) -> None:
        for record in self.table.withdraw(lambda p: p.key.server == server, "withdrawn", self.now):
            assert record.decision is not None

    @invariant()
    def caps_hold(self) -> None:
        if not hasattr(self, "table"):
            return
        records = list(self.table.records())
        assert len({r.key for r in records}) == len(records)  # one live record per key
        for client in CLIENTS:
            waiting = [r for r in records if r.key.client == client and r.decision is None]
            assert len(waiting) <= TIGHT.max_pending_per_client
            recent = [t for t, c in self.begins if c == client and t > self.now - approvals.HOUR]
            assert len(recent) <= TIGHT.max_prompts_per_hour


TestTableMachine = TableMachine.TestCase
TestTableMachine.settings = hypothesis_settings(
    max_examples=150, stateful_step_count=40, deadline=None
)
