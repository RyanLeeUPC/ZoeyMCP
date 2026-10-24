"""S17, Managed policy lifecycle (M6 design O.5; J4, J5, J9, J16 here, the rest in the steps that
build them): real vault processes on one state directory, with the host's ``zoeymcp policy``
commands run beside them as ``docker compose run`` runs them.

- J4: a fresh volume seeds revision 1 from ``ZOEYMCP_CONFIG`` by itself, then runs the head with
  the policy removed, and names a changed one ignored (F.5);
- J5: a declarative start is as before (J5a); a used volume switched to managed is refused with
  the seed's three commands, ``policy seed --state`` waits for the vault to stop, and seeds it,
  and the vault starts on it (J5b, Y18);
- J9: a master-key rotation re-seals every revision, the head and the anchor, and records the old
  key as retired, so a head put back under it is refused even with the old key set (T-13);
- J16: a start refused over the head, its reseed (planned on the old store when it verifies, with
  a new ratchet when it doesn't), and the start after it.

The state lock is ``flock``, which Windows lacks, so the seed's wait for the vault runs where there
is one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.policyseal import unseal_anchor
from zoeymcp.vault.policystart import Ok
from zoeymcp.vault.policystore import PolicyStore

from .procs import ManagedVault, managed_policy

HARDENED = "docker compose -f deploy/compose.hardened.yaml"
OFFLINE = {"by": "host", "via": "offline"}


def events(text: str, name: str) -> list[dict[str, Any]]:
    found = []
    for line in text.splitlines():
        if line.startswith("{"):
            record = json.loads(line)
            if record.get("event") == name:
                found.append(record)
    return found


def vault(tmp_path: Path) -> ManagedVault:
    made = ManagedVault(tmp_path, {"ZOEYMCP_MASTER_KEY": generate_master_key()})
    made.policy = managed_policy(made.portal)
    return made


def opened(made: ManagedVault, previous: str | None = None) -> Ok:
    keys = KeySet.from_text(made.env["ZOEYMCP_MASTER_KEY"])
    old = None if previous is None else KeySet.from_text(previous)
    found = PolicyStore.open(made.state, keys, old).verdict
    assert isinstance(found, Ok), found
    return found


def declarative(made: ManagedVault) -> dict[str, Any]:
    assert made.policy is not None
    return {**made.policy, "mode": "declarative"}


def test_fresh_seed(tmp_path: Path) -> None:
    """J4, F.3, F.5: on a fresh volume the vault seeds revision 1 from ZOEYMCP_CONFIG and starts;
    with the policy removed it runs the head; with it changed it runs the head and says the
    policy given is ignored."""
    made = vault(tmp_path)
    made.start()
    made.stop()
    found = opened(made)
    assert (found.revision, found.top.header["author"]) == (1, {"by": "seed"})
    [seeded] = events(made.output(), "policy_seeded")
    assert (seeded["revision"], seeded["tokens_hashed"], seeded["via"]) == (1, 1, "start")
    assert seeded["deployment"] == found.head.deployment[:8]
    kept = made.policy
    made.policy = None
    made.start()
    made.stop()
    assert unchanged(made, found)
    assert kept is not None
    made.policy = {**kept, "egress_key_generation": 2}
    made.start()
    made.stop()
    assert unchanged(made, found)
    [ignored] = events(made.output(), "policy_seed_ignored")
    assert (ignored["revision"], ignored["reason"]) == (1, "changed")
    assert [line["revision"] for line in events(made.output(), "policy_head")] == [1, 1, 1]


def unchanged(made: ManagedVault, before: Ok) -> bool:
    after = opened(made)
    return (after.revision, after.head.digest) == (before.revision, before.head.digest)


def test_declarative_unchanged(tmp_path: Path) -> None:
    """J5a: a declarative start writes nothing of the store and logs nothing of it."""
    made = vault(tmp_path)
    made.policy = declarative(made)
    made.start()
    made.stop()
    names = {path.name for path in made.state.iterdir()}
    assert not names & {"policy", "policy-anchor.json"}
    assert '"event":"policy_' not in made.output()


def test_upgrade_needs_seed(tmp_path: Path) -> None:
    """J5b, Y18, FM-9: a used volume switched to managed is refused with the three commands; the
    host's ``policy seed --state`` shows what it writes and seeds revision 1 as the host's; the
    vault then starts on it, from the head."""
    made = vault(tmp_path)
    managed = made.policy
    made.policy = declarative(made)
    made.start()
    made.stop()
    made.policy = managed
    refused = made.refused()
    state = made.state
    assert (
        "zoeymcp vault: refused to start: managed mode with no policy revisions, on a state "
        "volume that was used before ("
    ) in refused
    assert "gateway-key.json" in refused
    assert (
        f"  {HARDENED} stop vault\n"
        f"  {HARDENED} run --rm --no-deps vault policy seed --state {state.as_posix()}\n"
        f"  {HARDENED} up -d vault\n"
    ) in refused
    code, out, err = made.cli(["policy", "seed", "--state", str(state)], "y\n")
    assert code == 0, err
    assert err.startswith(
        "Seeding revision 1 of a new deployment from the policy given:\n"
        "  Clients: agent1\n"
        "  Routes: none\n"
        "  Servers: none\n"
        "  env: names it allows: none\n"
        "  Client tokens written as their hash: 1\n"
        "Write it? [y/N] Seeded revision 1 of deployment "
    )
    assert err.endswith(f"Start the vault:\n  {HARDENED} up -d vault\n")
    [seeded] = events(out, "policy_seeded")
    assert seeded["via"] == "offline"
    made.start()
    made.stop()
    found = opened(made)
    assert (found.revision, found.top.header["author"]) == (1, OFFLINE)
    assert events(made.output(), "policy_seed_ignored") == []


@pytest.mark.skipif(sys.platform == "win32", reason="the state lock is flock, which Windows lacks")
def test_the_seed_waits_for_the_vault_to_stop(tmp_path: Path) -> None:
    """OPS-6: while the vault runs it holds the state lock, and the seed refuses, naming the stop
    in the host's own commands; nothing is written."""
    made = vault(tmp_path)
    managed = made.policy
    made.policy = declarative(made)
    made.env["ZOEYMCP_COMPOSE_CMD"] = "docker compose -f deploy/compose.yaml"
    made.env["ZOEYMCP_EXEC_SERVICE"] = "zoeymcp"
    made.start()
    made.policy = managed
    try:
        code, _, err = made.cli(["policy", "seed", "--state", str(made.state), "--yes"])
    finally:
        made.stop()
    assert (code, err) == (
        2,
        "zoeymcp policy seed: The state directory is in use: stop the vault first (docker "
        "compose -f deploy/compose.yaml stop zoeymcp), then run this again.\n",
    )
    assert not (made.state / "policy-anchor.json").exists()


def test_master_key_rotation(tmp_path: Path) -> None:
    """J9, D.7, T-13: recreated with the new key and the old as the previous one, the vault
    re-seals every revision, the head and the anchor (no digest moves) and records the old key
    as retired; with the previous key removed it starts; a head put back under the old key is
    refused ``key_retired`` even with the old key set again."""
    made = vault(tmp_path)
    made.start()
    made.stop()
    old = made.env["ZOEYMCP_MASTER_KEY"]
    before = opened(made)
    old_head = (made.state / "policy" / "head.json").read_bytes()
    new = generate_master_key()
    made.env = {"ZOEYMCP_MASTER_KEY": new, "ZOEYMCP_MASTER_KEY_PREVIOUS": old}
    made.start()
    made.stop()
    [rekeyed] = events(made.output(), "policy_rekeyed")
    current = KeySet.from_text(new)
    assert (rekeyed["revisions"], rekeyed["key_id"]) == (1, current.key_id)
    assert rekeyed["next"] == "remove ZOEYMCP_MASTER_KEY_PREVIOUS"
    made.env = {"ZOEYMCP_MASTER_KEY": new}
    made.start()
    made.stop()
    after = opened(made)
    assert (after.revision, after.head.digest, after.head.key_id) == (
        1,
        before.head.digest,
        current.key_id,
    )
    anchor = unseal_anchor((made.state / "policy-anchor.json").read_bytes(), current, None)
    assert anchor.retired_key_id == KeySet.from_text(old).key_id
    rotated_head = (made.state / "policy" / "head.json").read_bytes()
    (made.state / "policy" / "head.json").write_bytes(old_head)
    made.env = {"ZOEYMCP_MASTER_KEY": new, "ZOEYMCP_MASTER_KEY_PREVIOUS": old}
    refused = made.refused()
    assert (
        f"/policy/head.json is sealed under master key ID {KeySet.from_text(old).key_id}, which "
        "a finished master-key rotation retired."
    ) in refused
    (made.state / "policy" / "head.json").write_bytes(rotated_head)
    made.env = {"ZOEYMCP_MASTER_KEY": new}
    made.start()
    made.stop()


def test_refused_start_and_the_reseed(tmp_path: Path) -> None:
    """J16's way out: a head that fails its MAC refuses the start; the reseed from the policy on
    standard input needs --new-ratchet (no ratchet to plan against), prints its plan and writes
    nothing without --yes; with it, revision 2 replaces the store, the old files in quarantine,
    and the vault starts on it. A later reseed against the verifying head is planned on it."""
    made = vault(tmp_path)
    made.start()
    made.stop()
    state = made.state
    head = state / "policy" / "head.json"
    data = head.read_bytes()
    at = data.index(b'"mac":"') + len(b'"mac":"')
    head.write_bytes(data[:at] + (b"1" if data[at : at + 1] == b"0" else b"0") + data[at + 1 :])
    assert "was tampered with, or written under another master key." in made.refused()
    source = json.dumps(made.policy)
    argv = ["policy", "import", "--state", str(state), "--reseed", "-"]
    code, _, err = made.cli(argv, source)
    assert code == 1
    assert "The old policy head doesn't verify (tampered)" in err
    code, _, err = made.cli([*argv, "--new-ratchet"], source)
    assert code == 1
    assert err.startswith(
        "Reseeding as revision 2, its deployment kept, with a new ratchet, the old store doesn't "
        "verify (tampered):\n"
    )
    assert err.endswith("Read the plan above, then run this again with --yes.\n")
    code, out, err = made.cli([*argv, "--new-ratchet", "--yes"], source)
    assert code == 0, err
    [imported] = events(out, "policy_imported")
    assert (imported["revision"], imported["write_kind"], imported["reseed"]) == (
        2,
        "policy.reseed",
        True,
    )
    quarantine = sorted(path.name for path in (state / "policy" / "quarantine").iterdir())
    assert quarantine == ["1.reseeded.json", "head.reseeded.json"]
    made.start()
    made.stop()
    found = opened(made)
    assert (found.revision, found.top.header["origin"]) == (2, "reseed")
    assert [line["write_kind"] for line in events(made.output(), "policy_head")][-1] == (
        "policy.reseed"
    )
    assert made.policy is not None
    edited = {**made.policy, "egress_key_generation": 2}
    code, _, err = made.cli([*argv, "--yes"], json.dumps(edited))
    assert code == 0, err
    assert err.startswith(
        "Reseeding as revision 3, its deployment kept, planned against revision 2 and what it "
        "retired:\n"
    )
    assert "  egress_key_generation: 2 (the store's floor 1)\n" in err
    assert opened(made).revision == 3
