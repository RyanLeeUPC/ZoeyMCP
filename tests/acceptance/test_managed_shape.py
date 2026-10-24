"""S17, Managed policy lifecycle (M6 design O.5; J4-J10 and J16 here, to the point the steps so
far reach, the rest in the steps that build them): real vault processes on one state directory,
with the host's ``zoeymcp policy`` commands run beside them as ``docker compose run`` runs them,
or as ``docker compose exec`` runs them over the vault's admin socket.

- J4: a fresh volume seeds revision 1 from ``ZOEYMCP_CONFIG`` by itself, then runs the head with
  the policy removed, and names a changed one ignored (F.5);
- J5: a declarative start is as before (J5a); a used volume switched to managed is refused with
  the seed's three commands, ``policy seed --state`` waits for the vault to stop, and seeds it,
  and the vault starts on it (J5b, Y18);
- J9: a master-key rotation re-seals every revision, the head and the anchor, and records the old
  key as retired, so a head put back under it is refused even with the old key set (T-13);
- J16: a start refused over the head, its reseed (planned on the old store when it verifies, with
  a new ratchet when it doesn't), and the start after it;
- J6-J8 and J10's export (step 14a): an export edited and imported over the socket, the compose
  policy recorded or imported with --from-env, a diff and a rollback, a broken admin rolled
  back, an import with the vault stopped, and a declarative export that starts the vault
  declaratively. The admin socket is a Unix socket, so its rows run where there is one.

The state lock is ``flock``, which Windows lacks, so the seed's wait for the vault runs where there
is one.
"""

from __future__ import annotations

import json
import sys
import textwrap
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.managed import head_policy
from zoeymcp.vault.policyseal import unseal_anchor
from zoeymcp.vault.policystart import Ok
from zoeymcp.vault.policystore import PolicyStore

from .procs import ManagedVault, free_port, managed_policy

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


# --- the host's commands (J6-J8, J10's export; M6 design H, I.1, step 14a) -----------------------

UNIX = pytest.mark.skipif(sys.platform == "win32", reason="the admin socket is a Unix socket")


def socket_vault(tmp_path: Path) -> ManagedVault:
    made = vault(tmp_path)
    made.admin_socket = True
    return made


def edited_export(
    made: ManagedVault, change: Callable[[dict[str, Any]], None], argv: Sequence[str] = ()
) -> str:
    """The head exported over the socket (or with ``argv``'s --state), edited as an operator
    would; the export's first line kept for the import's base."""
    code, out, err = made.cli(["policy", "export", *argv])
    assert code == 0, err
    first, _, rest = out.partition("\n")
    data = yaml.safe_load(rest)
    change(data)
    return first + "\n" + json.dumps(data) + "\n"


@UNIX
def test_export_edit_import(tmp_path: Path) -> None:
    """J7: export over the socket, add a client, import: the base from the export's header, the
    widening shown first and refused with --yes alone; with --accept-widening revision 2 is
    written and runs; the history names it."""
    made = socket_vault(tmp_path)
    made.start()
    try:
        code, out, err = made.cli(["policy", "export"])
        assert code == 0, err
        assert err.startswith("Exported revision 1 of deployment ")
        assert "managed-client-token-0001" not in out

        def add(data: dict[str, Any]) -> None:
            data["gateway"]["clients"]["reports"] = {"token_sha256": "sha256:" + "4" * 64}

        text = edited_export(made, add)
        code, _, err = made.cli(["policy", "import", "-", "--yes"], text)
        assert code == 1
        assert "This plan widens the policy (gateway.clients.reports)" in err
        code, _, err = made.cli(["policy", "import", "-", "--yes", "--accept-widening"], text)
        assert code == 0, err
        assert err.splitlines()[:3] == [
            "Planned on revision 1 (from the export's header):",
            "  Revision: 2, from 1",
            "  gateway.clients.reports: added (wider)",
        ]
        assert "Imported as revision 2." in err
        code, out, err = made.cli(["policy", "history"])
        assert code == 0, err
        assert out.splitlines()[0].startswith("2  policy.import  saved ")
    finally:
        made.stop()
    assert opened(made).revision == 2
    [imported] = events(made.output(), "policy_imported")
    assert (imported["revision"], imported["author"]) == (2, "host")


@UNIX
def test_import_from_env(tmp_path: Path) -> None:
    """J7's other half, F.5, OPS-7: a compose policy changed after the seed is ignored; recorded
    with --from-env --baseline-only (nothing applied), the next start says nothing; changed
    again and imported with --from-env, it is applied and recorded."""
    made = socket_vault(tmp_path)
    made.start()
    made.stop()
    assert made.policy is not None
    made.policy = {**made.policy, "egress_key_generation": 2}
    made.start()
    try:
        code, _, err = made.cli(["policy", "import", "--from-env", "--baseline-only", "--yes"])
        assert code == 0, err
        assert "Recorded the configured policy as the seed's baseline in revision 2." in err
    finally:
        made.stop()
    found = opened(made)
    assert (found.revision, found.top.header["kind"]) == (2, "policy.acknowledge")
    assert head_policy(found).egress_key_generation == 1
    before = len(events(made.output(), "policy_seed_ignored"))
    made.start()
    made.stop()
    assert len(events(made.output(), "policy_seed_ignored")) == before
    made.policy = {**made.policy, "egress_key_generation": 3}
    made.start()
    try:
        code, _, err = made.cli(["policy", "import", "--from-env", "--yes", "--accept-widening"])
        assert code == 0, err
        assert "Imported as revision 3." in err
    finally:
        made.stop()
    assert head_policy(opened(made)).egress_key_generation == 3


@UNIX
def test_history_diff_and_rollback(tmp_path: Path) -> None:
    """J6's socket half: an import that replaces agent1 with another client, a diff that hides
    the token hashes, a rollback to 1 refused for bringing back agent1's token, then granted."""
    made = socket_vault(tmp_path)
    made.start()
    try:

        def replace(data: dict[str, Any]) -> None:
            del data["gateway"]["clients"]["agent1"]
            data["gateway"]["clients"]["reports"] = {"token_sha256": "sha256:" + "4" * 64}

        argv = ["policy", "import", "-", "--yes", "--accept-widening"]
        code, _, err = made.cli(argv, edited_export(made, replace))
        assert code == 0, err
        code, out, err = made.cli(["policy", "diff", "2"])
        assert code == 0, err
        assert out.splitlines()[1].startswith("  gateway.clients.agent1: removed ")
        assert "sha256:" not in out
        code, _, err = made.cli(["policy", "rollback", "1", "--yes"])
        assert code == 1
        assert err.splitlines()[-1] == "  --allow-revive client:agent1"
        argv = ["policy", "rollback", "1", "--yes", "--accept-widening"]
        code, _, err = made.cli([*argv, "--allow-revive", "client:agent1"])
        assert code == 0, err
        assert "Rolled back as revision 3." in err
    finally:
        made.stop()
    found = opened(made)
    assert (found.revision, found.top.header["target"]) == (3, 1)
    [line] = events(made.output(), "policy_rolled_back")
    assert (line["revision"], line["base"], line["target"]) == (3, 2, 1)


@UNIX
def test_lockout_rollback_restores_admin(tmp_path: Path) -> None:
    """J8, T-6, Y17: an import that breaks admin.origins is written; a host rollback to the
    revision before takes that revision's admin block back, over the socket."""
    made = socket_vault(tmp_path)
    made.start()
    try:

        def broken(data: dict[str, Any]) -> None:
            data["admin"]["origins"] = ["http://localhost:1"]

        argv = ["policy", "import", "-", "--yes", "--accept-widening"]
        code, _, err = made.cli(argv, edited_export(made, broken))
        assert code == 0, err
        code, _, err = made.cli(["policy", "rollback", "1", "--yes", "--accept-widening"])
        assert code == 0, err
    finally:
        made.stop()
    found = opened(made)
    assert found.revision == 3
    admin = head_policy(found).admin
    assert admin is not None
    assert admin.origins == [f"http://localhost:{made.portal}"]


@UNIX
def test_export_back_to_declarative(tmp_path: Path) -> None:
    """J10's export, G-15: --mode declarative --for compose writes the YAML alone to stdout,
    indented for an inline block with every $ as $$, and the notes and the way back to stderr;
    that document, put back as the vault's policy, starts it declaratively, parking the store."""
    made = socket_vault(tmp_path)
    made.start()
    try:
        argv = ["policy", "export", "--mode", "declarative", "--for", "compose"]
        code, out, err = made.cli(argv)
    finally:
        made.stop()
    assert code == 0, err
    assert err.splitlines()[-3:] == [
        "Next: replace the policy under ZOEYMCP_CONFIG in your compose file with it, then:",
        f"  {HARDENED} run --rm --no-deps vault check",
        f"  {HARDENED} up -d vault",
    ]
    assert all(line.startswith("        ") for line in out.splitlines())
    made.policy = yaml.safe_load(textwrap.dedent(out).replace("$$", "$"))
    assert made.policy is not None
    assert made.policy["mode"] == "declarative"
    made.start()
    made.stop()
    [parked] = events(made.output(), "policy_store_parked")
    assert parked["revision"] == 1


def test_offline_import(tmp_path: Path) -> None:
    """J8 without a socket (OPS-14): the vault stopped, the policy exported with --state, its
    admin.listen moved, imported with --state (--lockout-ok: a lockout row), and the vault
    starts on it, its portal where the import put it."""
    made = vault(tmp_path)
    made.start()
    made.stop()
    state = ["--state", str(made.state)]
    moved = free_port()

    def listen(data: dict[str, Any]) -> None:
        data["admin"]["listen"] = f"127.0.0.1:{moved}"

    text = edited_export(made, listen, state)
    argv = ["policy", "import", "-", *state, "--yes", "--accept-widening"]
    code, _, err = made.cli(argv, text)
    assert code == 1
    assert "--lockout-ok" in err
    code, _, err = made.cli([*argv, "--lockout-ok"], text)
    assert code == 0, err
    assert err.splitlines()[-2:] == ["Start the vault:", f"  {HARDENED} up -d vault"]
    found = opened(made)
    assert (found.revision, found.top.header["author"]) == (2, OFFLINE)
    made.portal = moved
    made.start()
    made.stop()
