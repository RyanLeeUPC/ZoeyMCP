"""The vault's approval chain on disk (M8 design J.1; Z19, G-10, G-22, OPS-8).

On ``tmp_path`` with the vault's chain key: records written as the vault (``via`` on its
decisions), keyed digests only, recovery closing every hold a kill left open and counting it for
the two start findings, the recent endings read back and handed to the hold table, ``verify``,
and no chain, no hold: an append that fails, a full retry queue and files over the cap with
nothing old enough to prune each make the chain unwritable until an append succeeds, and while it
is the vault holds nothing: a held call is refused ``held_ledger_down``, nobody is asked, and
health says ``vault_ledger_unavailable`` (FM-25); a record on disk is never written twice, and one
that isn't valid is never queued. The vault's start recovers the chain before any listener (J10's
chain half).
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import pytest

from tests.gateway.holdrig import HoldRig, call, headers, marker
from zoeymcp.common import canonical, ledgerformat, logs
from zoeymcp.vault import server, vaultledger
from zoeymcp.vault.admin import HealthReader
from zoeymcp.vault.holds import ENDINGS_SECONDS, HoldTable, Limits
from zoeymcp.vault.keys import CONTEXT_LEDGER_VAULT, KeySet, derive, generate_master_key
from zoeymcp.vault.vaultledger import (
    CHAIN_DIR,
    ChainUnavailable,
    RecentEnding,
    Start,
    VaultLedger,
)

pytestmark = pytest.mark.anyio

MASTER = bytes(range(32))
KEYS = KeySet.from_master(MASTER)
PIN = "sha256:" + "c" * 64
EXAMPLE_POLICY = Path(__file__).resolve().parents[2] / "examples" / "policy.yaml"
REF_A, REF_B, REF_C, REF_D, REF_E = (f"00000000000000a{n}" for n in "abcde")
DAY_MS = int(ENDINGS_SECONDS * 1000)
BOUND = 30  # seconds: every effect test's own bound


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        yield stream
    finally:
        logs.set_stream(None)


def events(stream: io.StringIO, kind: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line]
    return [line for line in lines if line["event"] == kind]


class Clock:
    """The vault's wall clock in milliseconds, one tick per read."""

    def __init__(self) -> None:
        self.now = 1_767_276_000_000

    def __call__(self) -> int:
        self.now += 1
        return self.now


def opened(state: Path, clock: Clock | None = None, **options: Any) -> VaultLedger:
    return VaultLedger.open_at(state, KEYS.chain_key, clock=clock or Clock(), **options)


def asked_fields(
    chain: VaultLedger, args: Any, *, where: str = "vault", client: str = "agent1"
) -> dict[str, Any]:
    return {
        "client": client,
        "server": "shop",
        "tool": "place_order",
        "where": where,
        "era": "modern",
        "args": chain.digest(args),
        "pin": PIN,
        "text": chain.text_digest("the approval text"),
        "chars": 17,
        "writes": 1,
        "expires": 1,
    }


async def hold(
    chain: VaultLedger,
    ref: str,
    *,
    decision: str | None = "accept",
    outcome: str | None = "ok",
    where: str = "vault",
    client: str = "agent1",
    args: Any = None,
) -> None:
    """One held (or, with ``where="gateway"``, relayed) call's records, up to where it stops."""
    fields = asked_fields(chain, args or {"n": ref}, where=where, client=client)
    await chain.write("asked", ref, critical=True, **fields)
    if decision is not None:
        via = "none" if decision in ("timeout", "abandoned") else "telegram"
        await chain.write(
            "decided",
            ref,
            critical=decision == "accept",
            decision=decision,
            waited_ms=5,
            via=via,
        )
    if outcome is not None:
        await chain.write(
            "outcome",
            ref,
            critical=False,
            outcome=outcome,
            detail="relayed" if where == "gateway" else None,
            writes_sent=1 if outcome == "ok" else 0,
            writes_unknown=0,
        )


def records(state: Path) -> list[ledgerformat.Record]:
    found: list[ledgerformat.Record] = []
    for path in sorted((state / CHAIN_DIR).glob("*.jsonl")):
        found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
    return found


def broken_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("zoeymcp.common.ledgerfile.os.open", refuse)


# --- writing ------------------------------------------------------------------------------------


async def test_a_fresh_chain(tmp_path: Path) -> None:
    chain = opened(tmp_path)
    directory = tmp_path / CHAIN_DIR
    assert directory.is_dir()
    if sys.platform != "win32":
        assert directory.stat().st_mode & 0o777 == 0o700
    assert list(directory.iterdir()) == []  # no key file: the key is derived, never written
    assert chain.start == Start(chain.start.recovery)
    assert chain.start.recovery.index_rebuilt
    assert chain.writable()
    assert (chain.file.writer, chain.file.max_bytes, chain.file.keep_ms) == (
        "vault",
        64 * 2**20,
        30 * 24 * 3600 * 1000,
    )


async def test_records_are_the_vaults_and_chain(tmp_path: Path) -> None:
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        first = await chain.write("asked", REF_A, critical=True, **asked_fields(chain, {"a": 1}))
        assert chain.open == {REF_A: ["asked"]}
        await chain.write(
            "decided", REF_A, critical=True, decision="accept", waited_ms=3, via="portal"
        )
        last = await chain.write(
            "outcome",
            REF_A,
            critical=False,
            outcome="ok",
            detail=None,
            writes_sent=1,
            writes_unknown=0,
        )
    assert first is not None
    assert last is not None
    assert (first.seq, last.seq) == (0, 2)
    assert chain.open == {}
    found = records(tmp_path)
    assert [(r.kind, r.writer) for r in found] == [
        ("asked", "vault"),
        ("decided", "vault"),
        ("outcome", "vault"),
    ]
    assert found[1].fields["via"] == "portal"
    assert (tmp_path / CHAIN_DIR / "000000000000.jsonl").exists()
    assert chain.verify() == {
        "records": 3,
        "head_seq": 2,
        "head_hash": last.hash,
        "broken_at": None,
        "ok": True,
    }
    assert [r["seq"] for r in chain.read(after=0)] == [1, 2]
    assert chain.writable()


async def test_a_vault_decision_needs_its_via(tmp_path: Path) -> None:
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        await chain.write("asked", REF_A, critical=True, **asked_fields(chain, {}))
        with pytest.raises(ChainUnavailable):
            await chain.write("decided", REF_A, critical=True, decision="accept", waited_ms=1)
    assert chain.writable()  # a record that isn't valid is a bug, not a disk that failed
    assert chain.queue == []


async def test_only_keyed_digests_reach_the_file(tmp_path: Path) -> None:
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        await hold(chain, REF_A, args={"item": "very-secret-item"})
    data = b"".join(p.read_bytes() for p in (tmp_path / CHAIN_DIR).iterdir())
    assert b"very-secret-item" not in data
    assert b"the approval text" not in data
    plain = canonical.digest({"item": "very-secret-item"}).removeprefix("sha256:")
    assert plain.encode() not in data  # not an unkeyed digest either
    assert derive(MASTER, CONTEXT_LEDGER_VAULT).hex().encode() not in data
    assert chain.digest({"item": "very-secret-item"}).encode() in data
    other = VaultLedger(tmp_path, KeySet.from_master(bytes(32)).chain_key)
    assert other.digest({"item": "very-secret-item"}).encode() not in data


# --- recovery and the recent endings (J10's chain half) -----------------------------------------


async def test_recovery_closes_every_open_hold_and_counts_it(
    tmp_path: Path, log: io.StringIO
) -> None:
    clock = Clock()
    chain = opened(tmp_path, clock)
    with anyio.fail_after(BOUND):
        await hold(chain, REF_E, decision="decline", outcome="not_sent")  # ended before the kill
        await hold(chain, REF_A, decision=None, outcome=None, client="agent2")  # still waiting
        await hold(chain, REF_B, outcome=None)  # approved: the forward may have run
        await hold(chain, REF_C, decision="decline", outcome=None)
        await hold(chain, REF_D, decision=None, outcome=None, where="gateway")  # a relay
    again = opened(tmp_path, clock)
    start = again.start
    assert start.recovery.closed == {"abandoned": 2, "not_sent": 3, "unknown": 1}
    # Only the two still waiting were withdrawn: REF_C was declined, and says so below.
    assert (start.withdrawn, start.outcome_unknown) == (2, (REF_B,))
    tail = records(tmp_path)[-7:]
    assert [(r.kind, r.ref, r.fields.get("outcome") or r.fields.get("decision")) for r in tail] == [
        ("decided", REF_A, "abandoned"),
        ("outcome", REF_A, "not_sent"),
        ("outcome", REF_B, "unknown"),
        ("outcome", REF_C, "not_sent"),
        ("decided", REF_D, "abandoned"),
        ("outcome", REF_D, "not_sent"),
        ("recovered", None, None),
    ]
    assert all(r.writer == "vault" for r in tail)
    assert [r.fields["via"] for r in tail if r.kind == "decided"] == ["none", "none"]
    assert again.open == {}
    assert again.verify()["ok"]
    [recovered] = events(log, "ledger_recovered")
    assert (recovered["role"], recovered["unknown"]) == ("vault", 1)
    ends = {e.ref: (e.client, e.state, e.detail) for e in start.endings}
    assert ends == {
        REF_E: ("agent1", "denied", None),
        REF_A: ("agent2", "withdrawn", "restart"),
        REF_B: ("agent1", "done", "restart"),
        REF_C: ("agent1", "denied", None),
        REF_D: ("agent1", "withdrawn", "restart"),
    }
    assert [e.ref for e in start.endings] == [REF_E, REF_A, REF_B, REF_C, REF_D]
    # A later start closes nothing more and counts nothing, but still knows how each ended.
    third = opened(tmp_path, clock)
    assert (third.start.recovery.closed, third.start.withdrawn) == ({}, 0)
    assert third.start.outcome_unknown == ()
    assert third.start.endings == start.endings


async def test_the_recent_endings_are_a_day_and_at_most_the_last_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    chain = opened(tmp_path, clock)
    with anyio.fail_after(BOUND):
        await hold(chain, REF_A)
        clock.now += DAY_MS  # REF_A's outcome is now a day and a little old
        await hold(chain, REF_B, decision="timeout", outcome="not_sent")
        await hold(chain, REF_C, outcome="tool_error")
        await hold(chain, REF_D, decision="withdrawn", outcome="not_sent")
    found = opened(tmp_path, clock).start.endings
    assert [(e.ref, e.state, e.detail) for e in found] == [
        (REF_B, "expired", None),
        (REF_C, "done", "tool_error"),
        (REF_D, "withdrawn", None),
    ]
    monkeypatch.setattr(vaultledger, "RECENT_ENDINGS", 2)
    assert [e.ref for e in opened(tmp_path, clock).start.endings] == [REF_C, REF_D]


async def test_an_ending_the_ledger_withdrew_says_so(tmp_path: Path) -> None:
    """A hold whose decided accept couldn't be written ended ``withdrawn``, detail ``ledger``
    (J.1), whatever decision reached the files; a relay's outcome, written by the gateway's chain,
    is ``unknown`` here."""
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        for ref, decision in ((REF_A, "withdrawn"), (REF_C, "accept"), (REF_D, None)):
            await hold(chain, ref, decision=decision, outcome=None)
            await chain.write(
                "outcome",
                ref,
                critical=False,
                outcome="not_sent",
                detail="ledger",
                writes_sent=0,
                writes_unknown=0,
            )
        await hold(chain, REF_B, outcome="unknown", where="gateway")
    ends = {e.ref: (e.state, e.detail) for e in opened(tmp_path).start.endings}
    assert ends == {
        REF_A: ("withdrawn", "ledger"),
        REF_C: ("withdrawn", "ledger"),
        REF_D: ("withdrawn", "ledger"),
        REF_B: ("done", "unknown"),
    }


async def test_every_ended_ref_stays_used(tmp_path: Path) -> None:
    """E19: a ref that ended with any other decision, or with none left in the files, is still a
    recent ending, so it can't be held again within the day."""
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        await hold(chain, REF_A, decision="changed", outcome="not_sent")
        await hold(chain, REF_B, decision="error", outcome="not_sent")
        await hold(chain, REF_C, decision=None, outcome="not_sent")
    ends = {e.ref: (e.state, e.detail) for e in opened(tmp_path).start.endings}
    assert ends == {
        REF_A: ("withdrawn", "changed"),
        REF_B: ("withdrawn", "error"),
        REF_C: ("withdrawn", None),
    }


async def test_the_hold_table_is_told_the_endings(tmp_path: Path) -> None:
    """Each ref stays used (E19) and its client is told how it ended (F.5 step 4), its time moved
    to the table's clock."""
    clock = Clock()
    chain = opened(tmp_path, clock)
    with anyio.fail_after(BOUND):
        await hold(chain, REF_A, decision=None, outcome=None, client="agent2")
    again = opened(tmp_path, clock)
    [ending] = again.start.endings
    table = HoldTable(Limits(timeout=3600, block_seconds=120, cooldown=60, max_prompts_per_hour=30))
    clock.now = ending.ended_ms + 4_999  # the remember reads it once more: 5 s after
    again.remember(table, 1000.0)
    found = table.ending(REF_A)
    assert found is not None
    assert (found.id, found.client, found.state, found.detail) == (
        None,
        "agent2",
        "withdrawn",
        "restart",
    )
    assert found.ended_at == pytest.approx(995.0)
    assert table.knows(REF_A)
    assert not table.knows(REF_B)


def test_an_ending_carries_no_text() -> None:
    assert set(RecentEnding.__dataclass_fields__) == {
        "ref",
        "client",
        "state",
        "detail",
        "ended_ms",
    }


async def test_an_edited_record_breaks_verify_and_is_noted(
    tmp_path: Path, log: io.StringIO
) -> None:
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        await hold(chain, REF_A)
    newest = tmp_path / CHAIN_DIR / "000000000000.jsonl"
    lines = newest.read_bytes().splitlines(keepends=True)
    lines[1] = lines[1].replace(b'"telegram"', b'"portal"')
    newest.write_bytes(b"".join(lines))
    assert chain.verify()["broken_at"] == 2  # the next record no longer chains from it
    again = opened(tmp_path)
    assert again.start.recovery.chain_broken_at == 2
    [broken] = events(log, "ledger_chain_broken")
    assert (broken["role"], broken["seq"], broken["level"]) == ("vault", 2, "critical")


# --- no chain, no hold (G-10, FM-25's chain half) -----------------------------------------------


async def test_no_chain_no_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log: io.StringIO
) -> None:
    """FM-25: an append that fails makes the chain unwritable until one succeeds; meanwhile a
    held call is refused 503 ``held_ledger_down``, nothing is asked or sent, and health raises
    ``vault_ledger_unavailable``, which goes once the disk is back."""
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        await chain.write("asked", REF_A, critical=True, **asked_fields(chain, {}))
        with monkeypatch.context() as patched:
            broken_disk(patched)
            with pytest.raises(ChainUnavailable):
                await chain.write(
                    "asked", REF_B, critical=True, **asked_fields(chain, {"x": "do-not-log"})
                )
            assert not chain.writable()
            # A hold already asked goes on: a record it needn't have on disk is queued.
            decided = {"decision": "decline", "waited_ms": 1, "via": "portal"}
            assert await chain.write("decided", REF_A, critical=False, **decided) is None
            assert await chain.flush_queue() == 1
            assert not chain.writable()
        # The disk is back: the queued record lands, and new holds may begin.
        assert await chain.flush_queue() == 0
    assert chain.writable()
    assert [(r.kind, r.ref) for r in records(tmp_path)] == [("asked", REF_A), ("decided", REF_A)]
    failed = events(log, "ledger_write_failed")
    assert [(f["role"], f["record_kind"], f["queued"], f["level"]) for f in failed] == [
        ("vault", "asked", 0, "critical"),
        ("vault", "decided", 1, "critical"),
    ]
    assert "do-not-log" not in log.getvalue()
    # The vault's half: a held call while the chain can't be written (the in-process link: the
    # links themselves are test_vault_hold.py's).
    rig = HoldRig(tmp_path / "hold", link="asgi")
    health = HealthReader(rig.store, lambda: rig.app.policy, chain=rig.chain)
    assert health.report()["approvals"]["findings"] == []
    async with rig.running() as http:
        with anyio.fail_after(BOUND), monkeypatch.context() as patched:
            broken_disk(patched)
            with pytest.raises(ChainUnavailable):
                await rig.chain.write("asked", REF_C, critical=True, **asked_fields(rig.chain, {}))
            answer = await http.post(
                "/shop/mcp", content=call(), headers=headers(held=marker(REF_D))
            )
            assert answer.status_code == 503
            assert answer.json()["code"] == "held_ledger_down"
            assert answer.headers["x-zoeymcp-vault"] == "refused"
            [finding] = health.report()["approvals"]["findings"]
            assert (finding["code"], finding["level"]) == ("vault_ledger_unavailable", "error")
        assert rig.surface.shown == []
        assert rig.upstream.received == []
        assert not rig.app.holds.knows(REF_D)  # nothing began: the ref is still unused
        assert await rig.chain.flush_queue() == 0
        await rig.chain.write("asked", REF_E, critical=True, **asked_fields(rig.chain, {}))
        assert health.report()["approvals"]["findings"] == []


async def test_a_record_that_isnt_valid_is_never_queued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log: io.StringIO
) -> None:
    """Not even behind records a failed disk queued, where it would stop every retry after it."""
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        await chain.write("asked", REF_A, critical=True, **asked_fields(chain, {}))
        decided = {"decision": "decline", "waited_ms": 1, "via": "portal"}
        with monkeypatch.context() as patched:
            broken_disk(patched)
            await chain.write("decided", REF_A, critical=False, **decided)
        assert len(chain.queue) == 1
        no_via = {"decision": "decline", "waited_ms": 1}
        assert await chain.write("decided", REF_B, critical=False, **no_via) is None
        assert len(chain.queue) == 1
        with pytest.raises(ChainUnavailable):
            await chain.write("decided", REF_B, critical=True, **no_via)
        assert await chain.flush_queue() == 0
    assert chain.writable()
    assert [(r.kind, r.ref) for r in records(tmp_path)] == [("asked", REF_A), ("decided", REF_A)]
    failed = events(log, "ledger_write_failed")
    assert [(f["record_kind"], f["error_type"], f["queued"]) for f in failed] == [
        ("decided", "OSError", 1),
        ("decided", "LedgerFormatError", 1),
        ("decided", "LedgerFormatError", 1),
    ]


async def test_a_record_on_disk_is_never_written_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The index's rewrite failing after the record was fsynced doesn't fail the append: a
    critical record isn't reported unwritten, nor a queued one written again. The stale index
    (REF_A still open) is rebuilt at the next start, which closes nothing twice."""
    chain = opened(tmp_path)

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise OSError(28, "No space left on device")

    with anyio.fail_after(BOUND):
        await chain.write("asked", REF_A, critical=True, **asked_fields(chain, {}))
        with monkeypatch.context() as patched:
            patched.setattr("zoeymcp.common.ledgerfile.files.write_atomic", refuse)
            decided = {"decision": "accept", "waited_ms": 1, "via": "portal"}
            anchor = await chain.write("decided", REF_A, critical=True, **decided)
            outcome = {"outcome": "ok", "detail": None, "writes_sent": 1, "writes_unknown": 0}
            assert await chain.write("outcome", REF_A, critical=False, **outcome) is not None
        assert chain.queue == []
    assert anchor is not None
    assert chain.writable()
    assert [r.kind for r in records(tmp_path)] == ["asked", "decided", "outcome"]
    again = opened(tmp_path)
    assert again.start.recovery.index_rebuilt
    assert (again.start.recovery.closed, again.start.outcome_unknown) == ({}, ())
    assert [r.kind for r in records(tmp_path)] == ["asked", "decided", "outcome"]
    assert again.verify()["ok"]


async def test_a_critical_append_that_succeeds_makes_it_writable_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        with monkeypatch.context() as patched:
            broken_disk(patched)
            with pytest.raises(ChainUnavailable):
                await chain.write("asked", REF_A, critical=True, **asked_fields(chain, {}))
        assert not chain.writable()
        await chain.write("asked", REF_B, critical=True, **asked_fields(chain, {}))
    assert chain.writable()


async def test_a_full_retry_queue_makes_it_unwritable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vaultledger, "MAX_QUEUED", 2)
    chain = opened(tmp_path)
    with anyio.fail_after(BOUND):
        await chain.write("asked", REF_A, critical=True, **asked_fields(chain, {}))
        await chain.write("asked", REF_B, critical=True, **asked_fields(chain, {}))
        with monkeypatch.context() as patched:
            broken_disk(patched)
            decided = {"decision": "timeout", "waited_ms": 1, "via": "none"}
            await chain.write("decided", REF_A, critical=False, **decided)
        chain.failed = False  # as if an unrelated append had just succeeded
        assert chain.writable()  # one queued
        # Queued behind it, in order, though the disk is back.
        assert await chain.write("decided", REF_B, critical=False, **decided) is None
        assert not chain.writable()  # two queued: the queue is full
        assert await chain.flush_queue() == 0
    assert chain.writable()
    assert [r.ref for r in records(tmp_path) if r.kind == "decided"] == [REF_A, REF_B]


async def test_over_the_cap_with_nothing_old_enough_to_prune(tmp_path: Path) -> None:
    """The copy's rule (M5 J.4): history younger than ``keep_ms`` stays, so new holds stop until
    the oldest file comes of age; the holds already asked still write."""
    clock = Clock()
    chain = opened(tmp_path, clock, max_bytes=3000, rotate_bytes=1200, keep_ms=60_000)
    with anyio.fail_after(BOUND):
        index = 0
        while chain.writable():
            await hold(chain, f"{index:016x}")
            index += 1
            assert index < 100
        assert chain.file.size > 3000
        await hold(chain, REF_A, outcome=None)  # an in-flight hold isn't stopped by the cap
        assert not chain.writable()
        prunable_at = chain.file.prunable_at
        assert prunable_at is not None
        clock.now = prunable_at + 1_000  # past every file written so far
        assert chain.writable()
        await chain.write(
            "outcome",
            REF_A,
            critical=False,
            outcome="ok",
            detail=None,
            writes_sent=1,
            writes_unknown=0,
        )
    assert chain.file.size <= 3000
    assert records(tmp_path)[0].seq > 0  # the oldest file went
    assert chain.writable()
    assert chain.verify()["ok"]


# --- the vault's start --------------------------------------------------------------------------


def test_the_vault_recovers_its_chain_before_any_listener(tmp_path: Path) -> None:
    environ = {"ZOEYMCP_MASTER_KEY": generate_master_key()}
    state = tmp_path / "state"
    chain = VaultLedger.open_at(state, KeySet.from_text(environ["ZOEYMCP_MASTER_KEY"]).chain_key)

    async def asked() -> None:
        with anyio.fail_after(BOUND):
            await hold(chain, REF_A, decision=None, outcome=None)
            await hold(chain, REF_B, outcome=None)

    asyncio.run(asked())
    vault = server.build(str(EXAMPLE_POLICY), ["127.0.0.1:8080"], state, environ, None)
    try:
        start = vault.chain.start
        assert (start.withdrawn, start.outcome_unknown) == (1, (REF_B,))
        assert vault.chain.open == {}
        assert vault.chain.writable()
        # Its digests are under the same key as the chain written before the restart.
        assert vault.chain.digest({"n": REF_A}) == chain.digest({"n": REF_A})
    finally:
        asyncio.run(vault.app.aclose())
    assert [r.kind for r in records(state)][-1] == "recovered"


def test_a_chain_that_cant_be_opened_refuses_the_start(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / CHAIN_DIR).write_bytes(b"not a directory")
    environ = {"ZOEYMCP_MASTER_KEY": generate_master_key()}
    with pytest.raises(server.StartupError, match="the vault's approval chain"):
        server.build(str(EXAMPLE_POLICY), ["127.0.0.1:8080"], state, environ, None)
