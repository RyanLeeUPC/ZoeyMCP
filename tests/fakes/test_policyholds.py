"""Self-test of the policy store's crash holds (M6 design O.1): each hold lands between the D.9
steps it names, and what a kill there leaves is what the next start sorts out (FM-1, FM-2, FM-25,
in process). A ``wait`` that raises stands in for the kill."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes.policyholds import HOLDS, hold, install, save
from zoeymcp.common.policy.plan import WritePlan
from zoeymcp.common.policy.ratchet import initial
from zoeymcp.common.policy.schema import Policy
from zoeymcp.vault import policystore
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.policystart import Fresh, Ok, revision_file
from zoeymcp.vault.policystore import PolicyStore

KEYS = KeySet.from_master(bytes(range(32)))
POLICY = Policy.model_validate({"version": 1, "mode": "managed"})
SEED = "sha256:" + "5" * 64
AUTHOR = {"by": "passkey", "fingerprint": "0123456789abcdef"}


class Killed(BaseException):
    """The kill: no handler in the store catches it."""


def kill() -> None:
    raise Killed


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A state directory; every seam a hold wraps is put back after the test."""
    for seam in HOLDS.values():
        monkeypatch.setattr(policystore, seam, getattr(policystore, seam))
    found = tmp_path / "state"
    found.mkdir(mode=0o700)
    return found


def seeded(state: Path) -> PolicyStore:
    store = PolicyStore.open(state, KEYS, None)
    store.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    return store


def save_on(store: PolicyStore) -> WritePlan:
    """A portal save with no change on the head, as the planner would answer it."""
    head = store.head
    assert head is not None
    return WritePlan(
        kind="policy.save",
        base=head.revision,
        base_digest=head.digest,
        changes=(),
        effects=(),
        breaks=(),
        kept=(),
        unused_slots=(),
        moves=(),
        kept_allow=(),
        ratchet=initial(POLICY),
        rows=(),
        policy=POLICY,
    )


def test_pause_after_revision_holds_before_the_head(state: Path, tmp_path: Path) -> None:
    """FM-1: killed there, the revision file is written and the head isn't; the next start
    runs the old head and quarantines the file as uncommitted."""
    store = seeded(state)
    marker = tmp_path / "held"
    hold("pause_after_revision", marker, wait=kill)
    with pytest.raises(Killed):
        store.commit(save_on(store), author=AUTHOR)
    assert marker.read_bytes() == b"written\n"
    assert (state / revision_file(2)).is_file()
    found = PolicyStore.open(state, KEYS, None).verdict
    assert isinstance(found, Ok)
    assert (found.revision, found.uncommitted) == (1, 2)
    assert (state / "policy" / "quarantine" / "2.uncommitted.json").is_file()
    assert not (state / revision_file(2)).exists()


def test_pause_after_head_holds_before_the_anchor(state: Path, tmp_path: Path) -> None:
    """FM-2: killed there, the head names the new revision and the anchor the old; the next
    start runs the new head and rewrites the anchor (D.6 row 13)."""
    store = seeded(state)
    marker = tmp_path / "held"
    hold("pause_after_head", marker, wait=kill)
    with pytest.raises(Killed):
        store.commit(save_on(store), author=AUTHOR)
    assert marker.read_bytes() == b"written\n"
    reopened = PolicyStore.open(state, KEYS, None)
    assert isinstance(reopened.verdict, Ok)
    assert (reopened.verdict.revision, reopened.verdict.anchor_stale) == (2, True)
    again = PolicyStore.open(state, KEYS, None)
    assert isinstance(again.verdict, Ok)
    assert again.verdict.anchor_stale is False
    assert again.anchor is not None
    assert again.anchor.highest == 2


def test_pause_after_revision_holds_a_seed_after_its_anchor(state: Path, tmp_path: Path) -> None:
    """FM-25: a seed killed after the anchor at 0 and revision 1 starts fresh again, under the
    same deployment, its revision 1 quarantined."""
    store = PolicyStore.open(state, KEYS, None)
    marker = tmp_path / "held"
    hold("pause_after_revision", marker, wait=kill)
    with pytest.raises(Killed):
        store.seed(POLICY, ratchet=initial(POLICY), seed_digest=SEED)
    assert store.anchor is not None
    deployment = store.anchor.deployment
    found = PolicyStore.open(state, KEYS, None).verdict
    assert found == Fresh(deployment, (1,))
    assert (state / "policy" / "quarantine" / "1.uncommitted.json").is_file()


def test_the_holds_file_installs_each_hold_it_names(state: Path, tmp_path: Path) -> None:
    real = policystore.write_revision
    path = tmp_path / "holds.json"
    save(path, pause_after_head=tmp_path / "held")
    assert path.read_bytes() == (
        b'{\n  "pause_after_head": "'
        + str(tmp_path / "held").replace("\\", "\\\\").encode()
        + b'"\n}\n'
    )
    install(str(path))
    assert policystore.write_revision is real
    assert policystore.write_head.__name__ == "held"
    with pytest.raises(ValueError, match="no such hold"):
        save(path, pause_after_anchor=tmp_path / "held")
