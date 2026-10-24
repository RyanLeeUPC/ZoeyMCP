"""The policy store's I/O (M6 design D.1, D.7-D.9, F.4, O.3, O.4; Y1, Y3, Y4, T-13), in process:
the commit's order and what each failed step leaves (FM-4, FM-30), the seed's anchor at 0 first
(FM-25), retention (D.8), the start's housekeeping (rows 5, 12-16: temporaries, quarantine moves,
strays, prune leftovers, a stale anchor), the master-key rotation's order, a rotation cut short
(FM-3) and the retired key (T-13), the park (F.4), the host's offline seed of a used volume and
its reseed (F.3: the old store set aside, the anchor first, a number never used before, Y4), the
history lookup behind the planner's
"removed in revision M", and a byte search of every file the store writes for the values a
revision encrypts (Y3).

Each write seam is replaced where a test needs it to fail or to be watched; the crash holds
themselves are tests/fakes/test_policyholds.py's.
"""

from __future__ import annotations

import errno
import io
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.common.policy.plan import WriteKind, WritePlan
from zoeymcp.common.policy.ratchet import initial
from zoeymcp.common.policy.schema import Policy
from zoeymcp.vault import logs, policystore
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.policyseal import (
    REVISION_MAX,
    Anchor,
    Head,
    body_digest,
    make_body,
    seal_anchor,
    seal_head,
    seal_revision,
    unseal_anchor,
    unseal_head,
    unseal_revision,
)
from zoeymcp.vault.policystart import Fresh, Ok, Quarantined, Refused, revision_file
from zoeymcp.vault.policystore import KEEP, Committed, PolicyStore, StoreRefused

KEYS = KeySet.from_master(bytes(range(32)))
OLD = KeySet.from_master(bytes(range(1, 33)))
POLICY = Policy.model_validate({"version": 1, "mode": "managed"})
SEED = "sha256:" + "5" * 64
FROM_ENV = "sha256:" + "6" * 64
PASSKEY = {"by": "passkey", "fingerprint": "0123456789abcdef"}
SOCKET = {"by": "host", "via": "socket"}
NOW = 1_792_900_000
SEAMS = ("write_revision", "write_head", "write_anchor", "move", "remove")
# Every value a revision encrypts (D.4), each a sentinel (Y3).
SENTINELS = {
    "token": "store-client-token-sentinel-0001",
    "placeholder": "store-placeholder-sentinel-0001",
    "token_header": "store-token-header-sentinel-01",
    "query": "store-query-sentinel-0001",
    "username": "store-username-sentinel-0001",
    "recipient": "store-recipient-sentinel@mail.example",
}


class Clock:
    def __init__(self, now: float = NOW) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def state(tmp_path: Path) -> Path:
    found = tmp_path / "state"
    found.mkdir(mode=0o700)
    return found


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def events(buffer: io.StringIO) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    for line in lines:
        del line["ts"]
        del line["role"]
    return lines


@pytest.fixture
def seams(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Every seam call from here on, as (seam, file name), in order."""
    calls: list[tuple[str, str]] = []
    for name in SEAMS:
        real: Callable[..., None] = getattr(policystore, name)

        def recorded(*args: Any, _name: str = name, _real: Callable[..., None] = real) -> None:
            calls.append((_name, Path(args[0]).name))
            _real(*args)

        monkeypatch.setattr(policystore, name, recorded)
    return calls


def broken(*args: Any) -> None:
    raise OSError(errno.ENOSPC, "No space left on device")


def fresh(state: Path, keys: KeySet = KEYS, previous: KeySet | None = None) -> PolicyStore:
    return PolicyStore.open(state, keys, previous, clock=Clock())


def seeded(state: Path, policy: Policy = POLICY, keys: KeySet = KEYS) -> PolicyStore:
    store = fresh(state, keys)
    store.seed(policy, ratchet=initial(policy), seed_digest=SEED)
    return store


def plan_on(
    store: PolicyStore, policy: Policy = POLICY, kind: WriteKind = "policy.save"
) -> WritePlan:
    """The planner's answer for ``policy`` on the store's head."""
    head = store.head
    assert head is not None
    return WritePlan(
        kind=kind,
        base=head.revision,
        base_digest=head.digest,
        changes=(),
        effects=(),
        breaks=(),
        kept=(),
        unused_slots=(),
        moves=(),
        kept_allow=(),
        ratchet=initial(policy),
        rows=(),
        policy=policy,
    )


def saved(store: PolicyStore, count: int, policy: Policy = POLICY) -> None:
    for _ in range(count):
        store.commit(plan_on(store, policy), author=PASSKEY)


def head_on_disk(state: Path) -> Head:
    return unseal_head((state / "policy" / "head.json").read_bytes(), KEYS, OLD)


def anchor_on_disk(state: Path) -> Anchor:
    return unseal_anchor((state / "policy-anchor.json").read_bytes(), KEYS, OLD)


def revision_on_disk(state: Path, number: int) -> Any:
    return unseal_revision((state / revision_file(number)).read_bytes(), KEYS, OLD, deployment=None)


def ok(store: PolicyStore) -> Ok:
    assert isinstance(store.verdict, Ok), store.verdict
    return store.verdict


def name(number: int) -> str:
    return f"{number:010d}.json"


# --- the seed and the commit (D.9) --------------------------------------------------------------


def test_the_seed_writes_the_anchor_at_zero_before_revision_one(
    state: Path, seams: list[tuple[str, str]], log_buffer: io.StringIO
) -> None:
    store = fresh(state)
    assert store.verdict == Fresh()
    committed = store.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    assert seams == [
        ("write_anchor", "policy-anchor.json"),
        ("write_revision", name(1)),
        ("write_head", "head.json"),
        ("write_anchor", "policy-anchor.json"),
    ]
    assert committed.revision == 1
    assert committed.anchor_written is True
    header = committed.header
    assert (header["origin"], header["kind"], header["author"]) == (
        "seed",
        "policy.seed",
        {"by": "seed"},
    )
    assert (header["parent"], header["base"], header["created"]) == (None, None, NOW)
    head = head_on_disk(state)
    assert (head.revision, head.digest, head.oldest, head.oldest_parent) == (
        1,
        committed.digest,
        1,
        None,
    )
    anchor = anchor_on_disk(state)
    assert (anchor.highest, anchor.parked, anchor.deployment) == (1, None, head.deployment)
    assert len(anchor.deployment) == 32
    assert revision_on_disk(state, 1).body.seed_digest == SEED
    assert events(log_buffer) == []
    reopened = fresh(state)
    assert ok(reopened).revision == 1
    assert reopened.seed_digest == SEED
    with pytest.raises(ValueError, match="only a store with nothing in it is seeded"):
        store.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    with pytest.raises(ValueError, match="only a store with nothing in it is seeded"):
        reopened.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)


def test_a_seed_that_never_committed_is_seeded_again_under_its_deployment(
    state: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    """FM-25 (D.6 row 5): the anchor at 0 stays, the half-written revision 1 goes to quarantine,
    and the next seed keeps the deployment."""
    store = fresh(state)
    real = policystore.write_head
    monkeypatch.setattr(policystore, "write_head", broken)
    with pytest.raises(StoreRefused) as refused:
        store.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    assert refused.value.reason == "policy_write_failed"
    deployment = anchor_on_disk(state).deployment
    assert anchor_on_disk(state).highest == 0
    monkeypatch.setattr(policystore, "write_head", real)
    again = fresh(state)
    assert again.verdict == Fresh(deployment, (1,))
    assert (state / "policy" / "quarantine" / "1.uncommitted.json").is_file()
    assert not (state / revision_file(1)).exists()
    again.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    assert head_on_disk(state).deployment == deployment
    assert events(log_buffer) == [
        {"event": "policy_save_uncommitted", "level": "warning", "revision": 1}
    ]


def test_a_commit_writes_the_revision_the_head_then_the_anchor(
    state: Path, seams: list[tuple[str, str]]
) -> None:
    store = seeded(state)
    head = store.head
    assert head is not None
    seams.clear()
    committed = store.commit(plan_on(store), author=PASSKEY)
    assert seams == [
        ("write_revision", name(2)),
        ("write_head", "head.json"),
        ("write_anchor", "policy-anchor.json"),
    ]
    assert committed.revision == 2
    assert committed.header["parent"] == head.digest
    moved = head_on_disk(state)
    assert store.head == moved
    assert (moved.revision, moved.digest) == (2, committed.digest)
    assert anchor_on_disk(state).highest == 2
    assert store.kept == (1, 2)
    assert store.header == committed.header


@pytest.mark.parametrize(
    ("kind", "origin"),
    [
        ("policy.save", "save"),
        ("tool.repin", "save"),
        ("tool.allow", "save"),
        ("client.servers", "save"),
        ("connector.limits", "save"),
        ("policy.import", "import"),
        ("policy.acknowledge", "acknowledge"),
        ("policy.resume", "resume"),
    ],
)
def test_a_commit_is_written_with_its_kinds_origin(
    state: Path, kind: WriteKind, origin: str
) -> None:
    store = seeded(state)
    author = PASSKEY if origin == "save" else SOCKET
    committed = store.commit(plan_on(store, kind=kind), author=author)
    assert (committed.header["origin"], committed.header["kind"]) == (origin, kind)
    assert revision_on_disk(state, 2).header == committed.header


def test_a_commit_records_its_header_and_carries_the_seed_digest(state: Path) -> None:
    clock = Clock()
    store = PolicyStore.open(state, KEYS, None, clock=clock)
    store.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    saved(store, 1)
    clock.now = NOW + 60
    rolled = store.commit(plan_on(store, kind="policy.rollback"), author=SOCKET, target=1)
    assert {name: rolled.header[name] for name in ("origin", "base", "target", "created")} == {
        "origin": "rollback",
        "base": 2,
        "target": 1,
        "created": NOW + 60,
    }
    assert revision_on_disk(state, 3).body.seed_digest == SEED
    imported = store.commit(
        plan_on(store, kind="policy.import"),
        author=SOCKET,
        reason="from the compose file",
        seed_digest=FROM_ENV,
    )
    body = revision_on_disk(state, imported.revision).body
    assert (body.seed_digest, body.reason) == (FROM_ENV, "from the compose file")
    assert store.seed_digest == FROM_ENV
    saved(store, 1)
    assert revision_on_disk(state, 5).body.seed_digest == FROM_ENV
    assert revision_on_disk(state, 5).body.policy == {"version": 1, "mode": "managed"}


def test_a_plan_on_another_head_or_a_seed_kind_isnt_committed(state: Path) -> None:
    store = seeded(state)
    stale = plan_on(store)
    saved(store, 1)
    with pytest.raises(ValueError, match="another head"):
        store.commit(stale, author=PASSKEY)
    kinds: tuple[WriteKind, ...] = ("policy.seed", "policy.reseed")
    for kind in kinds:
        with pytest.raises(ValueError, match="isn't written on the head"):
            store.commit(plan_on(store, kind=kind), author=SOCKET)
    assert head_on_disk(state).revision == 2


@pytest.mark.parametrize("seam", ["write_revision", "write_head"])
def test_write_fails(
    state: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO, seam: str
) -> None:
    """FM-4: a disk full at D.9 step 1 or 2 refuses ``policy_write_failed``; the head on disk and
    the store's are unchanged, and the anchor too. A revision written without its head is the
    next start's uncommitted file; a retry writes the same revision number again."""
    store = seeded(state)
    head, anchor = store.head, anchor_on_disk(state)
    real = getattr(policystore, seam)
    monkeypatch.setattr(policystore, seam, broken)
    with pytest.raises(StoreRefused) as refused:
        store.commit(plan_on(store), author=PASSKEY)
    assert refused.value.reason == "policy_write_failed"
    assert refused.value.detail == "revision 2 can't be written (OSError)"
    assert store.head == head
    assert head_on_disk(state) == head
    assert anchor_on_disk(state) == anchor
    assert store.kept == (1,)
    assert (state / revision_file(2)).exists() == (seam == "write_head")
    assert events(log_buffer) == []
    monkeypatch.setattr(policystore, seam, real)
    assert store.commit(plan_on(store), author=PASSKEY).revision == 2
    assert ok(fresh(state)).revision == 2


def test_anchor_write_fails(
    state: Path,
    monkeypatch: pytest.MonkeyPatch,
    seams: list[tuple[str, str]],
    log_buffer: io.StringIO,
) -> None:
    """FM-30: the save is committed with the anchor stale, ``policy_anchor_write_failed`` is
    logged, the next commit writes the anchor first or refuses with nothing written, and a
    start in between rewrites it (D.6 row 13)."""
    store = seeded(state)
    real = policystore.write_anchor
    monkeypatch.setattr(policystore, "write_anchor", broken)
    committed = store.commit(plan_on(store), author=PASSKEY)
    assert (committed.revision, committed.anchor_written) == (2, False)
    assert store.anchor_dirty is True
    assert head_on_disk(state).revision == 2
    assert events(log_buffer) == [
        {
            "event": "policy_anchor_write_failed",
            "level": "warning",
            "revision": 2,
            "error_type": "OSError",
        }
    ]
    with pytest.raises(StoreRefused) as refused:
        store.commit(plan_on(store), author=PASSKEY)
    assert refused.value.reason == "policy_write_failed"
    assert refused.value.detail == "the anchor of revision 2 still can't be written"
    assert not (state / revision_file(3)).exists()
    assert head_on_disk(state).revision == 2
    assert len(events(log_buffer)) == 1
    monkeypatch.setattr(policystore, "write_anchor", real)
    seams.clear()
    assert store.commit(plan_on(store), author=PASSKEY).revision == 3
    assert seams == [
        ("write_anchor", "policy-anchor.json"),
        ("write_revision", name(3)),
        ("write_head", "head.json"),
        ("write_anchor", "policy-anchor.json"),
    ]
    assert store.anchor_dirty is False
    assert anchor_on_disk(state).highest == 3


def test_a_start_after_a_failed_anchor_write_rewrites_it(
    state: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    store = seeded(state)
    real = policystore.write_anchor
    monkeypatch.setattr(policystore, "write_anchor", broken)
    store.commit(plan_on(store), author=PASSKEY)
    monkeypatch.setattr(policystore, "write_anchor", real)
    reopened = fresh(state)
    assert ok(reopened).anchor_stale is True
    assert reopened.anchor_dirty is False
    assert anchor_on_disk(state).highest == 2
    assert ok(fresh(state)).anchor_stale is False


def test_a_start_that_cant_rewrite_the_anchor_leaves_it_dirty(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = seeded(state)
    monkeypatch.setattr(policystore, "write_anchor", broken)
    store.commit(plan_on(store), author=PASSKEY)
    reopened = fresh(state)
    assert reopened.anchor_dirty is True
    assert reopened.anchor is not None
    assert reopened.anchor.highest == 2
    with pytest.raises(StoreRefused, match="still can't be written"):
        reopened.commit(plan_on(reopened), author=PASSKEY)


def test_a_revision_past_the_maximum_is_refused(state: Path, seams: list[tuple[str, str]]) -> None:
    """T-4: a head at 9,999,999,999 takes no further revision, and nothing is written."""
    deployment = "ab" * 16
    plaintext = make_body(
        salt=bytes(32),
        policy={"version": 1},
        ratchet=initial(POLICY).as_dict(),
        seed_digest=SEED,
        reason=None,
    )
    parent = "sha256:" + "1" * 64
    header = {
        "v": 1,
        "deployment": deployment,
        "revision": REVISION_MAX,
        "parent": parent,
        "created": NOW,
        "origin": "save",
        "kind": "policy.save",
        "author": PASSKEY,
        "base": REVISION_MAX - 1,
        "target": None,
        "jumped_from": None,
        "body_digest": body_digest(plaintext),
    }
    data = seal_revision(header, plaintext, keys=KEYS, nonce=bytes(12))
    top = unseal_revision(data, KEYS, None, deployment=None)
    (state / "policy" / "revisions").mkdir(mode=0o700, parents=True)
    (state / revision_file(REVISION_MAX)).write_bytes(data)
    head = Head(deployment, REVISION_MAX, top.digest, REVISION_MAX, parent, KEYS.key_id)
    (state / "policy" / "head.json").write_bytes(seal_head(head, KEYS))
    anchor = Anchor(deployment, REVISION_MAX, None, None, KEYS.key_id)
    (state / "policy-anchor.json").write_bytes(seal_anchor(anchor, KEYS))
    seams.clear()
    store = fresh(state)
    assert ok(store).revision == REVISION_MAX
    with pytest.raises(StoreRefused) as refused:
        store.commit(plan_on(store), author=PASSKEY)
    assert refused.value.reason == "revision_out_of_range"
    assert seams == []


# --- retention (D.8) ----------------------------------------------------------------------------


def test_the_newest_64_revisions_are_kept(state: Path, log_buffer: io.StringIO) -> None:
    store = seeded(state)
    saved(store, KEEP - 1)
    assert store.kept == tuple(range(1, KEEP + 1))
    assert events(log_buffer) == []
    second = revision_on_disk(state, 2)
    saved(store, 2)
    head = head_on_disk(state)
    assert (head.revision, head.oldest, head.oldest_parent) == (KEEP + 2, 3, second.digest)
    assert store.kept == tuple(range(3, KEEP + 3))
    assert sorted(path.name for path in (state / "policy" / "revisions").iterdir()) == [
        name(n) for n in range(3, KEEP + 3)
    ]
    assert events(log_buffer) == [
        {"event": "policy_pruned", "revisions": 1, "below": 2},
        {"event": "policy_pruned", "revisions": 1, "below": 3},
    ]
    reopened = ok(fresh(state))
    assert reopened.kept == tuple(range(3, KEEP + 3))
    assert (reopened.quarantined, reopened.pruned, reopened.missing) == ((), (), 0)


def test_a_prune_cut_short_is_finished_at_the_next_start(
    state: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    """D.9 step 4 failing is logged, the save stands, and the next start removes what is below
    the oldest kept (row 16, FM-27). Four revisions kept here, to stay quick."""
    keep = 4
    monkeypatch.setattr(policystore, "KEEP", keep)
    store = seeded(state)
    saved(store, keep - 1)
    real = policystore.remove
    monkeypatch.setattr(policystore, "remove", broken)
    assert store.commit(plan_on(store), author=PASSKEY).revision == keep + 1
    assert (state / revision_file(1)).exists()
    assert events(log_buffer) == [
        {
            "event": "policy_housekeeping_failed",
            "level": "warning",
            "action": "prune",
            "error_type": "OSError",
            "revision": 1,
        }
    ]
    monkeypatch.setattr(policystore, "remove", real)
    reopened = fresh(state)
    assert ok(reopened).pruned == (1,)
    assert not (state / revision_file(1)).exists()
    assert events(log_buffer)[1:] == [{"event": "policy_pruned", "revisions": 1, "below": 2}]
    assert reopened.kept == tuple(range(2, keep + 2))


# --- the start's housekeeping (D.6 rows 12-16, D.1) ---------------------------------------------


def test_leftover_temporary_files_are_removed(state: Path) -> None:
    """D.1: a write that never finished leaves a ``.policy-`` file; it is removed before the
    volume is judged, so it makes no volume used."""
    leftovers = [
        state / ".policy-anchor-tmp",
        state / "policy" / ".policy-head-tmp",
        state / "policy" / "revisions" / ".policy-revision-tmp",
    ]
    (state / "policy" / "revisions").mkdir(mode=0o700, parents=True)
    for path in leftovers:
        path.write_bytes(b"half")
    (state / "setup.json").write_bytes(b"{}\n")
    store = fresh(state)
    assert store.verdict == Fresh()
    assert not any(path.exists() for path in leftovers)
    (state / "store.json").write_bytes(b"{}\n")
    used = fresh(state).verdict
    assert isinstance(used, Refused)
    assert (used.reason, used.detail) == ("policy_seed_needs_host", "store.json")


def test_quarantine_moves(
    state: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    """Rows 12, 14 and 15: an uncommitted revision above the head and an older revision that
    fails go to quarantine under their own names; a stray name is logged once and left alone;
    quarantine/ is never read."""
    store = seeded(state)
    saved(store, 3)
    changed = json.loads((state / revision_file(2)).read_bytes())
    changed["created"] += 1
    tampered = json.dumps(changed).encode()
    (state / revision_file(2)).write_bytes(tampered)
    real = policystore.write_head
    monkeypatch.setattr(policystore, "write_head", broken)
    with pytest.raises(StoreRefused):
        store.commit(plan_on(store), author=PASSKEY)
    monkeypatch.setattr(policystore, "write_head", real)
    (state / "policy" / "notes.txt").write_bytes(b"stray\n")
    (state / "policy" / "quarantine").mkdir(mode=0o700)
    (state / "policy" / "quarantine" / "garbage").write_bytes(b"\x00")
    reopened = fresh(state)
    found = ok(reopened)
    assert (found.revision, found.uncommitted) == (4, 5)
    assert found.quarantined == (Quarantined(2, "tampered"),)
    assert found.stray == ("notes.txt",)
    quarantine = state / "policy" / "quarantine"
    assert sorted(path.name for path in quarantine.iterdir()) == [
        "2.unreadable.json",
        "5.uncommitted.json",
        "garbage",
    ]
    assert (quarantine / "2.unreadable.json").read_bytes() == tampered
    assert (state / "policy" / "notes.txt").read_bytes() == b"stray\n"
    assert events(log_buffer) == [
        {"event": "policy_save_uncommitted", "level": "warning", "revision": 5},
        {
            "event": "policy_revision_quarantined",
            "level": "warning",
            "revision": 2,
            "reason": "tampered",
        },
        {"event": "policy_stray_file", "name": "notes.txt"},
    ]
    assert reopened.kept == (1, 3, 4)
    again = ok(fresh(state))
    assert (again.uncommitted, again.quarantined, again.kept) == (None, (), (1, 3, 4))
    assert again.missing == 1
    assert reopened.commit(plan_on(reopened), author=PASSKEY).revision == 5


def test_a_move_that_fails_is_logged_and_tried_again(
    state: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    store = seeded(state)
    saved(store, 1)
    (state / revision_file(1)).write_bytes(b"{}")
    real = policystore.move
    monkeypatch.setattr(policystore, "move", broken)
    assert ok(fresh(state)).quarantined == (Quarantined(1, "not_a_revision"),)
    assert (state / revision_file(1)).exists()
    assert events(log_buffer) == [
        {
            "event": "policy_housekeeping_failed",
            "level": "warning",
            "action": "quarantine",
            "error_type": "OSError",
            "revision": 1,
        },
        {
            "event": "policy_revision_quarantined",
            "level": "warning",
            "revision": 1,
            "reason": "not_a_revision",
        },
    ]
    monkeypatch.setattr(policystore, "move", real)
    assert ok(fresh(state)).quarantined == (Quarantined(1, "not_a_revision"),)
    assert (state / "policy" / "quarantine" / "1.unreadable.json").read_bytes() == b"{}"


def test_a_second_file_of_the_same_name_is_quarantined_beside_the_first(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Quarantine is kept until the operator deletes it (D.8, N.5): two saves at the same number
    that never answered are both kept, and a move never replaces a file."""
    store = seeded(state)
    real = policystore.write_head
    written = []
    for _ in range(2):
        monkeypatch.setattr(policystore, "write_head", broken)
        with pytest.raises(StoreRefused):
            store.commit(plan_on(store), author=PASSKEY)
        monkeypatch.setattr(policystore, "write_head", real)
        written.append((state / revision_file(2)).read_bytes())
        store = fresh(state)
        assert ok(store).uncommitted == 2
    assert written[0] != written[1]
    quarantine = state / "policy" / "quarantine"
    assert (quarantine / "2.uncommitted.json").read_bytes() == written[0]
    assert (quarantine / "2.uncommitted.2.json").read_bytes() == written[1]
    (state / "spare.json").write_bytes(b"{}")
    with pytest.raises(FileExistsError):
        policystore.move(state / "spare.json", quarantine / "2.uncommitted.json")
    assert (quarantine / "2.uncommitted.json").read_bytes() == written[0]
    assert (state / "spare.json").exists()


def test_a_refused_store_is_left_as_it_is(state: Path, seams: list[tuple[str, str]]) -> None:
    store = seeded(state)
    saved(store, 1)
    (state / "policy-anchor.json").unlink()
    (state / "policy" / "revisions" / ".policy-tmp").write_bytes(b"half")
    seams.clear()
    refused = fresh(state)
    assert isinstance(refused.verdict, Refused)
    assert refused.verdict.reason == "policy_anchor_missing"
    assert seams == [("remove", ".policy-tmp")]
    assert (refused.head, refused.kept) == (None, ())
    with pytest.raises(ValueError, match="no head"):
        refused.commit(plan_on(store), author=PASSKEY)
    with pytest.raises(ValueError, match="no head"):
        refused.park()
    with pytest.raises(ValueError, match="only a store with nothing in it"):
        refused.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)


def test_a_head_that_cant_be_read_is_refused(state: Path) -> None:
    seeded(state)
    (state / "policy" / "head.json").unlink()
    (state / "policy" / "head.json").mkdir(mode=0o700)
    found = fresh(state).verdict
    assert isinstance(found, Refused)
    assert found.reason == "tampered"
    assert found.detail.startswith("can't be read (")


# --- the master-key rotation (D.7) --------------------------------------------------------------


def old_store(state: Path, revisions: int = 3) -> PolicyStore:
    """A store written under the previous master key."""
    store = seeded(state, keys=OLD)
    saved(store, revisions - 1)
    return store


def test_a_rotation_reseals_oldest_first_then_the_head_then_the_anchor(
    state: Path, seams: list[tuple[str, str]], log_buffer: io.StringIO
) -> None:
    before = old_store(state)
    digests = [revision_on_disk(state, n).digest for n in (1, 2, 3)]
    seams.clear()
    store = fresh(state, KEYS, OLD)
    assert seams == [
        ("write_revision", name(1)),
        ("write_revision", name(2)),
        ("write_revision", name(3)),
        ("write_head", "head.json"),
        ("write_anchor", "policy-anchor.json"),
    ]
    assert [revision_on_disk(state, n).digest for n in (1, 2, 3)] == digests
    assert {revision_on_disk(state, n).key_id for n in (1, 2, 3)} == {KEYS.key_id}
    head = unseal_head((state / "policy" / "head.json").read_bytes(), KEYS, None)
    assert before.head is not None
    assert (head.revision, head.digest, head.key_id) == (3, before.head.digest, KEYS.key_id)
    anchor = unseal_anchor((state / "policy-anchor.json").read_bytes(), KEYS, None)
    assert (anchor.highest, anchor.retired_key_id, anchor.key_id) == (3, OLD.key_id, KEYS.key_id)
    assert store.head == head
    assert events(log_buffer) == [
        {
            "event": "policy_rekeyed",
            "revisions": 3,
            "key_id": KEYS.key_id,
            "next": "remove ZOEYMCP_MASTER_KEY_PREVIOUS",
        }
    ]
    seams.clear()
    again = fresh(state, KEYS, OLD)
    assert ok(again).revision == 3
    assert seams == []
    assert ok(fresh(state)).revision == 3


def test_retired_key_refused(state: Path) -> None:
    """T-13: after a rotation, a head planted under the old key is refused ``key_retired`` even
    while ZOEYMCP_MASTER_KEY_PREVIOUS is still set, and an older revision under it is
    quarantined."""
    old_store(state)
    planted_head = (state / "policy" / "head.json").read_bytes()
    planted_second = (state / revision_file(2)).read_bytes()
    fresh(state, KEYS, OLD)
    (state / revision_file(2)).write_bytes(planted_second)
    found = ok(fresh(state, KEYS, OLD))
    assert found.quarantined == (Quarantined(2, "key_retired"),)
    (state / "policy" / "head.json").write_bytes(planted_head)
    refused = fresh(state, KEYS, OLD).verdict
    assert isinstance(refused, Refused)
    assert (refused.reason, refused.key_id) == ("key_retired", OLD.key_id)


def test_a_rotation_cut_short_is_finished_by_the_next_start(
    state: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    """FM-3 in process: the head's re-seal fails after the revisions', so files are under both
    keys, each verifying under its own; the anchor records no retired key, the next start with
    the previous key set finishes, and without it the start is refused naming the key."""
    old_store(state)
    real = policystore.write_head
    monkeypatch.setattr(policystore, "write_head", broken)
    cut = fresh(state, KEYS, OLD)
    assert ok(cut).revision == 3
    assert {revision_on_disk(state, n).key_id for n in (1, 2, 3)} == {KEYS.key_id}
    assert head_on_disk(state).key_id == OLD.key_id
    assert anchor_on_disk(state).key_id == OLD.key_id
    assert anchor_on_disk(state).retired_key_id is None
    assert events(log_buffer) == [
        {
            "event": "policy_housekeeping_failed",
            "level": "warning",
            "action": "rekey",
            "error_type": "OSError",
        }
    ]
    monkeypatch.setattr(policystore, "write_head", real)
    without = fresh(state).verdict
    assert isinstance(without, Refused)
    assert (without.reason, without.key_id) == ("key_unknown", OLD.key_id)
    finished = fresh(state, KEYS, OLD)
    assert ok(finished).revision == 3
    assert head_on_disk(state).key_id == KEYS.key_id
    assert anchor_on_disk(state).retired_key_id == OLD.key_id
    assert events(log_buffer)[-1]["event"] == "policy_rekeyed"


def test_a_rotation_waits_for_the_move_of_a_file_above_the_head(
    state: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    """A save under the previous key that never answered and can't be moved yet: the rotation
    waits, so the next start still finds it a row-12 file, moves it and finishes; retiring the
    key first would make that start ``files_above_head``."""
    store = old_store(state)
    real_head, real_move = policystore.write_head, policystore.move
    monkeypatch.setattr(policystore, "write_head", broken)
    with pytest.raises(StoreRefused):
        store.commit(plan_on(store), author=PASSKEY)
    monkeypatch.setattr(policystore, "write_head", real_head)
    monkeypatch.setattr(policystore, "move", broken)
    assert ok(fresh(state, KEYS, OLD)).uncommitted == 4
    assert revision_on_disk(state, 4).key_id == OLD.key_id
    assert head_on_disk(state).key_id == OLD.key_id
    assert anchor_on_disk(state).retired_key_id is None
    assert "policy_rekeyed" not in log_buffer.getvalue()
    monkeypatch.setattr(policystore, "move", real_move)
    assert ok(fresh(state, KEYS, OLD)).uncommitted == 4
    assert (state / "policy" / "quarantine" / "4.uncommitted.json").exists()
    assert head_on_disk(state).key_id == KEYS.key_id
    assert anchor_on_disk(state).retired_key_id == OLD.key_id
    assert ok(fresh(state)).revision == 3


def test_a_previous_key_equal_to_the_current_one_is_ignored(
    state: Path, seams: list[tuple[str, str]], log_buffer: io.StringIO
) -> None:
    """ZOEYMCP_MASTER_KEY_PREVIOUS set to the current key: nothing is re-sealed, and the vault's
    own key isn't recorded as retired, so the next start still runs."""
    seeded(state)
    seams.clear()
    assert ok(fresh(state, KEYS, KEYS)).revision == 1
    assert seams == []
    assert "policy_rekeyed" not in log_buffer.getvalue()
    assert anchor_on_disk(state).retired_key_id is None
    assert ok(fresh(state, KEYS, KEYS)).revision == 1
    assert ok(fresh(state)).revision == 1


def test_a_commit_after_a_rotation_keeps_the_retired_key(state: Path) -> None:
    old_store(state)
    store = fresh(state, KEYS, OLD)
    saved(store, 1)
    anchor = anchor_on_disk(state)
    assert (anchor.highest, anchor.retired_key_id) == (4, OLD.key_id)


# --- the park (F.4) -----------------------------------------------------------------------------


def test_the_park_writes_highest_and_parked_as_the_head(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F.4 with D.6 row 13: a park that finds the head one above the anchor writes ``highest``
    and ``parked`` both the head's revision, and the next start reads it parked."""
    store = seeded(state)
    real = policystore.write_anchor
    monkeypatch.setattr(policystore, "write_anchor", broken)
    store.commit(plan_on(store), author=PASSKEY)
    stale = fresh(state)
    assert (ok(stale).anchor_stale, anchor_on_disk(state).highest) == (True, 1)
    with pytest.raises(StoreRefused) as refused:
        stale.park()
    assert refused.value.reason == "policy_write_failed"
    monkeypatch.setattr(policystore, "write_anchor", real)
    stale.park()
    anchor = anchor_on_disk(state)
    assert (anchor.highest, anchor.parked) == (2, 2)
    assert stale.anchor == anchor
    assert stale.anchor_dirty is False
    parked = ok(fresh(state))
    assert (parked.parked, parked.anchor_stale) == (2, False)


# --- the host's offline seed and reseed (F.3) ---------------------------------------------------


def test_the_host_seeds_a_used_volume(state: Path) -> None:
    """F.3, Y18: a used volume with no store is the host's to seed (``policy seed --state``), as
    revision 1 by the host offline; the vault's own seed stays by the seed, and the store refuses
    it there too, writing nothing (D-130's backstop)."""
    (state / "store.json").write_bytes(b"{}")
    store = fresh(state)
    assert isinstance(store.verdict, Refused)
    assert store.verdict.reason == "policy_seed_needs_host"
    for author in ({}, {"author": policystore.SEED_AUTHOR}, {"author": SOCKET}):
        with pytest.raises(ValueError, match="only a store with nothing in it is seeded"):
            store.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED, **author)
    assert sorted(path.name for path in state.iterdir()) == ["store.json"]
    committed = store.seed(
        POLICY, ratchet=initial(POLICY), seed_digest=SEED, author=policystore.OFFLINE
    )
    assert (committed.revision, committed.header["origin"]) == (1, "seed")
    assert committed.header["author"] == {"by": "host", "via": "offline"}
    reopened = ok(fresh(state))
    assert reopened.top.header["author"] == {"by": "host", "via": "offline"}
    assert dict(policystore.SEED_AUTHOR) == {"by": "seed"}


def test_a_reseed_sets_the_old_store_aside(
    state: Path, seams: list[tuple[str, str]], log_buffer: io.StringIO
) -> None:
    """F.3: the old head and revisions move to quarantine, never deleted; the anchor is written
    first, under the same deployment, then D.9's steps write the revision one above the highest,
    with no parent, as its own oldest; the next start runs it."""
    store = seeded(state)
    saved(store, 2)
    deployment = anchor_on_disk(state).deployment
    reopened = fresh(state)
    assert reopened.reseed_revision == 4
    seams.clear()
    committed = reopened.reseed(POLICY, ratchet=initial(POLICY), seed_digest=FROM_ENV, base=3)
    assert seams == [
        ("move", "head.json"),
        ("move", name(1)),
        ("move", name(2)),
        ("move", name(3)),
        ("write_anchor", "policy-anchor.json"),
        ("write_revision", name(4)),
        ("write_head", "head.json"),
        ("write_anchor", "policy-anchor.json"),
    ]
    header = committed.header
    assert (committed.revision, header["origin"], header["kind"]) == (4, "reseed", "policy.reseed")
    assert (header["parent"], header["base"], header["author"]) == (
        None,
        3,
        {"by": "host", "via": "offline"},
    )
    head = head_on_disk(state)
    assert (head.revision, head.oldest, head.oldest_parent, head.deployment) == (
        4,
        4,
        None,
        deployment,
    )
    assert (anchor_on_disk(state).highest, reopened.kept) == (4, (4,))
    quarantine = sorted(path.name for path in (state / "policy" / "quarantine").iterdir())
    assert quarantine == [f"{n}.reseeded.json" for n in (1, 2, 3)] + ["head.reseeded.json"]
    again = ok(fresh(state))
    assert (again.revision, again.kept, again.seed_digest) == (4, (4,), FROM_ENV)
    assert events(log_buffer) == []
    # The next reseed counts what quarantine holds too (Y4): never 4 again.
    (state / "policy" / "quarantine" / "9.unreadable.json").write_bytes(b"{}")
    assert fresh(state).reseed_revision == 10


def test_a_reseed_without_a_trusted_anchor_is_a_new_deployment(state: Path) -> None:
    """F.3: an anchor that doesn't verify, or is under its own retired key, keeps nothing: the
    reseed makes a new deployment, numbered above every revision file still there (Y4)."""
    store = seeded(state)
    saved(store, 1)
    deployment = anchor_on_disk(state).deployment
    (state / "policy-anchor.json").write_bytes(b"x")
    refused = fresh(state)
    assert refused.trusted_anchor is None
    assert refused.reseed_revision == 3
    committed = refused.reseed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    assert committed.revision == 3
    assert committed.header["base"] is None
    assert anchor_on_disk(state).deployment not in (deployment, "")
    assert ok(fresh(state)).revision == 3
    anchor = anchor_on_disk(state)
    retired = Anchor(anchor.deployment, 3, None, KEYS.key_id, KEYS.key_id)
    (state / "policy-anchor.json").write_bytes(seal_anchor(retired, KEYS))
    assert fresh(state).trusted_anchor is None


def test_a_reseed_the_seal_refuses_touches_nothing(
    state: Path, seams: list[tuple[str, str]]
) -> None:
    """The revision is sealed before anything moves: a body ``policyseal`` refuses (here a seed
    digest that isn't one) leaves the store as it was."""
    store = seeded(state)
    saved(store, 1)
    reopened = fresh(state)
    seams.clear()
    with pytest.raises(StoreRefused) as refused:
        reopened.reseed(POLICY, ratchet=initial(POLICY), seed_digest="sha256:none")
    assert refused.value.reason == "policy_write_failed"
    assert seams == []
    assert ok(fresh(state)).revision == 2


# Each write a reseed makes before its head: the seam, the call of it that fails, and the detail.
FAILS = {
    "second-move": ("move", 2, "the old store can't be moved to quarantine (PermissionError)"),
    "anchor": ("write_anchor", 1, "the anchor can't be written (PermissionError)"),
    "revision": ("write_revision", 1, "revision 3 can't be written (PermissionError)"),
    "head": ("write_head", 1, "revision 3 can't be written (PermissionError)"),
}


def files_in(state: Path) -> dict[str, bytes]:
    return {
        path.relative_to(state).as_posix(): path.read_bytes()
        for path in state.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("step", sorted(FAILS))
def test_a_reseed_that_fails_before_its_head_puts_the_old_store_back(
    state: Path, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """A write that fails before the new head puts back every file moved and the anchor, and
    removes the new revision: the store is as it was ("nothing changed" holds), the old head
    verifies, and the reseed runs again on it."""
    store = seeded(state)
    saved(store, 1)
    before = files_in(state)
    seam, failing, detail = FAILS[step]
    real: Callable[..., None] = getattr(policystore, seam)
    calls: list[str] = []

    def fails(*args: Any) -> None:
        calls.append(Path(args[0]).name)
        if len(calls) == failing:
            raise OSError(errno.EACCES, "Permission denied")
        real(*args)

    monkeypatch.setattr(policystore, seam, fails)
    with pytest.raises(StoreRefused) as refused:
        fresh(state).reseed(POLICY, ratchet=initial(POLICY), seed_digest=SEED, base=2)
    assert (refused.value.reason, refused.value.detail) == ("policy_write_failed", detail)
    monkeypatch.setattr(policystore, seam, real)
    assert files_in(state) == before
    again = fresh(state)
    assert ok(again).revision == 2
    assert again.reseed(POLICY, ratchet=initial(POLICY), seed_digest=SEED, base=2).revision == 3
    assert ok(fresh(state)).revision == 3


def test_a_reseed_that_cant_put_the_old_store_back_names_what_is_left(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When even the way back fails, ``reseed_incomplete`` names each file still out of place
    and where it goes, and the anchor that couldn't be rewritten."""
    store = seeded(state)
    saved(store, 1)
    real_move, real_anchor = policystore.move, policystore.write_anchor
    anchors: list[str] = []

    def move_in_only(source: Path, target: Path) -> None:
        if source.parent.name == "quarantine":
            raise OSError(errno.EACCES, "Permission denied")
        real_move(source, target)

    def anchor_once(path: Path, data: bytes) -> None:
        anchors.append(path.name)
        if len(anchors) > 1:
            raise OSError(errno.EACCES, "Permission denied")
        real_anchor(path, data)

    monkeypatch.setattr(policystore, "move", move_in_only)
    monkeypatch.setattr(policystore, "write_anchor", anchor_once)
    monkeypatch.setattr(policystore, "write_head", broken)
    with pytest.raises(StoreRefused) as refused:
        fresh(state).reseed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    assert refused.value.reason == "reseed_incomplete"
    assert refused.value.detail == "; ".join(
        [
            "revision 3 can't be written (OSError)",
            "the old policy-anchor.json can't be put back",
            "policy/quarantine/2.reseeded.json goes back to policy/revisions/0000000002.json",
            "policy/quarantine/1.reseeded.json goes back to policy/revisions/0000000001.json",
            "policy/quarantine/head.reseeded.json goes back to policy/head.json",
        ]
    )
    assert not (state / revision_file(3)).exists()


def test_a_reseed_numbers_above_a_refused_head(state: Path) -> None:
    """Y4: a head that unsealed but is refused still counts. Here its revision file is gone and
    the anchor is restored from before it: the reseed's number is above the head's, never one a
    head committed."""
    store = seeded(state)
    saved(store, 6)
    deployment = anchor_on_disk(state).deployment
    stale = Anchor(deployment, 5, None, None, KEYS.key_id)
    (state / "policy-anchor.json").write_bytes(seal_anchor(stale, KEYS))
    (state / revision_file(7)).unlink()
    refused = fresh(state)
    assert isinstance(refused.verdict, Refused)
    assert (refused.verdict.reason, refused.verdict.revision) == ("head_dangling", 7)
    assert refused.reseed_revision == 8
    assert refused.reseed(POLICY, ratchet=initial(POLICY), seed_digest=SEED).revision == 8
    assert ok(fresh(state)).revision == 8


def test_a_reseed_past_the_counter_is_refused(state: Path) -> None:
    """T-4: a reseed above the ten-digit file names is refused before anything moves."""
    seeded(state)
    quarantine = state / "policy" / "quarantine"
    quarantine.mkdir(mode=0o700)
    (quarantine / f"{REVISION_MAX}.unreadable.json").write_bytes(b"{}")
    store = fresh(state)
    with pytest.raises(StoreRefused) as refused:
        store.reseed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    assert refused.value.reason == "revision_out_of_range"
    assert (state / "policy" / "head.json").is_file()


# --- the history lookup (PlanInput.removed_in) --------------------------------------------------


def with_clients(clients: dict[str, str], placeholders: tuple[str, ...] = ()) -> Policy:
    document: dict[str, Any] = {
        "version": 1,
        "mode": "managed",
        "gateway": {
            "clients": {
                client: {"token_sha256": "sha256:" + digit * 64}
                for client, digit in clients.items()
            }
        },
    }
    if placeholders:
        document["routes"] = [
            {
                "name": "api",
                "prefix": "/api",
                "upstream": "https://api.example",
                "callers": [{"placeholder": placeholder} for placeholder in placeholders],
                "rules": [{"methods": ["GET"], "paths": ["/items"]}],
            }
        ]
    return Policy.model_validate(document)


def test_the_lookup_finds_the_revision_that_retired_a_token_or_a_placeholder(state: Path) -> None:
    """The revision named is the one that retired the candidate's value, as the ratchet did: a
    rename with the token kept, a caller that only shifted index, and a later re-token of the
    same name aren't removals of it."""
    caller, other = "store-placeholder-one-0001", "store-placeholder-two-0001"
    store = seeded(state, with_clients({"a": "1", "b": "2"}, (caller, other)))
    for policy in (
        with_clients({"b": "2"}, (caller, other)),  # 2 removes a (token 1)
        with_clients({"b": "3"}, (caller, other)),  # 3 re-tokens b (2 retired)
        with_clients({"b": "4"}, (caller,)),  # 4 re-tokens b (3 retired), drops api/1 (other)
        with_clients({"b": "4", "c": "1"}, (other,)),  # 5 token 1 as c; api/0 caller -> other
        with_clients({"b": "4", "d": "1"}, (other,)),  # 6 renames c to d, the token kept
        with_clients({"b": "4"}, (other,)),  # 7 removes d (token 1 retired)
    ):
        store.commit(plan_on(store, policy), author=PASSKEY)
    candidate = with_clients({"a": "1", "b": "2", "e": "3", "f": "9"}, (caller, other))
    removed_in = store.removed_lookup(candidate)
    assert removed_in("client:a") == 7
    assert removed_in("client:b") == 3
    assert removed_in("client:e") == 4
    assert removed_in("caller:api/0") == 5
    assert removed_in("caller:api/1") == 4
    assert removed_in("client:f") is None
    assert removed_in("client:never") is None
    assert removed_in("caller:api/2") is None
    assert removed_in("pin:notes/tool/list") is None
    (state / revision_file(2)).write_bytes(b"{}")
    assert removed_in("client:b") == 3  # read once, at its first subject of the kind
    after = store.removed_lookup(candidate)
    assert (after("client:b"), after("client:a")) == (None, 7)
    reopened = fresh(state)
    assert ok(reopened).quarantined[0].revision == 2
    assert reopened.removed_lookup(candidate)("client:b") is None
    assert reopened.removed_lookup(candidate)("caller:api/1") == 4


# --- what the files hold (Y3) -------------------------------------------------------------------


def sentinel_policy() -> Policy:
    found = SENTINELS
    return Policy.model_validate(
        {
            "version": 1,
            "mode": "managed",
            "credentials": {
                "api": {
                    "kind": "oauth2",
                    "token_url": "https://auth.example/token",
                    "client_id": "store-client-id",
                    "refresh_token": "store:api-refresh",
                    "token_headers": {"X-Extra": found["token_header"]},
                }
            },
            "connectors": {
                "mail": {
                    "kind": "smtp",
                    "host": "smtp.example",
                    "port": 465,
                    "username": found["username"],
                    "password": "store:smtp",
                    "from": "Notes <notes@mail.example>",
                    "to": [found["recipient"]],
                }
            },
            "routes": [
                {
                    "name": "api",
                    "prefix": "/api",
                    "upstream": "https://api.example",
                    "credential": "api",
                    "callers": [{"placeholder": found["placeholder"]}],
                    "query": {"force": {"mode": found["query"]}},
                    "rules": [{"methods": ["GET"], "paths": ["/items"]}],
                },
                {
                    "name": "mail",
                    "prefix": "/mail",
                    "connector": "mail",
                    "callers": ["gateway"],
                    "rules": [{"methods": ["POST"], "paths": ["/send"]}],
                },
            ],
            "gateway": {"clients": {"agent": {"token": found["token"]}}},
        }
    )


def test_the_files_hold_no_policy_value_in_clear(state: Path, log_buffer: io.StringIO) -> None:
    """Y3, a byte search: no sentinel of a policy committed twice is in any file the store
    wrote, its log lines or its repr; the client's token is held only as its hash, and that
    only encrypted; and the two revisions' salted body digests differ."""
    policy = sentinel_policy()
    store = seeded(state, policy)
    saved(store, 1, policy)
    body = revision_on_disk(state, 2).body
    assert body.policy["gateway"]["clients"]["agent"] == {
        "token_sha256": policy.gateway.clients["agent"].token_hash  # type: ignore[union-attr]
    }
    token_hash = body.policy["gateway"]["clients"]["agent"]["token_sha256"]
    written = [path.read_bytes() for path in state.rglob("*") if path.is_file()]
    assert len(written) == 4
    for value in [*SENTINELS.values(), token_hash]:
        assert not any(value.encode() in data for data in written), value
        assert value not in log_buffer.getvalue()
        assert value not in repr(store)
    first, second = revision_on_disk(state, 1), revision_on_disk(state, 2)
    assert first.body.policy == second.body.policy
    assert first.header["body_digest"] != second.header["body_digest"]
    with pytest.raises(TypeError, match=r"refusing to log a secret"):
        logs.event("oops", store=store)


def test_the_store_can_be_shown(state: Path) -> None:
    store = seeded(state)
    assert repr(store) == "PolicyStore(revision=1, anchor_dirty=False)"
    assert isinstance(store.commit(plan_on(store), author=PASSKEY), Committed)
