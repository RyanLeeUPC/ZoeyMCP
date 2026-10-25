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
- J11 (step 17): /state/policy put back alone is refused; the whole /state put back, or wiped
  and seeded again, while a real gateway process on its own volume witnessed the newer
  revisions, is flagged (``policy_behind_witness``, ``policy_deployment_changed``) and cleared
  by ``policy acknowledge-restore``, with the vault stopped or, where there is an admin socket,
  over it; a tool re-pinned in the portal since the copy is drifted again on the restored head
  until the portal's review saves it again (H.5), the gateway listing a real fake upstream;
- J6-J8 and J10's export (step 14a): an export edited and imported over the socket, the compose
  policy recorded or imported with --from-env, a diff and a rollback, a broken admin rolled
  back, an import with the vault stopped, and a declarative export that starts the vault
  declaratively. The admin socket is a Unix socket, so its rows run where there is one.

The state lock is ``flock``, which Windows lacks, so the seed's wait for the vault runs where there
is one.
"""

from __future__ import annotations

import json
import shutil
import sys
import textwrap
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Browser, Page
from tests.fakes.mcp_server import PATH, McpFake, base_tools
from tests.gateway.rig import pin_of_fake
from tests.portal.flows import enrol, login, redeem
from zoeymcp.gateway import witness
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.managed import head_policy
from zoeymcp.vault.policyseal import unseal_anchor, unseal_head
from zoeymcp.vault.policystart import Ok
from zoeymcp.vault.policystore import PolicyStore

from .conftest import serve_tls
from .procs import ManagedVault, Process, free_port, managed_policy, start, wait_port
from .test_portal_shapes import setup_code
from .tls import ProviderCA

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


# --- a restored volume and the gateway as witness (J11; M6 design D.6, K.3; T-5, Y24) ----------

WITNESS_WAIT = 150.0  # a vault restart, the gateway's backoff, and its status within the minute


def gateway_on(made: ManagedVault, state: Path, port: int | None = None) -> Process:
    """The gateway on the vault's TCP listener with the gateway key, as the hardened tier runs
    it, on its own volume ``state``: kept when the vault's is restored or wiped. Its agents'
    listener is on ``port`` (any free one by default)."""
    state.mkdir(mode=0o700, exist_ok=True)
    port = port or free_port()
    keys = KeySet.from_text(made.env["ZOEYMCP_MASTER_KEY"])
    argv = [
        "gateway", "--vault", f"http://127.0.0.1:{made.port}", "--listen", f"127.0.0.1:{port}",
        "--state", str(state), "--admin-socket", "none",
    ]  # fmt: skip
    process = start(
        argv, env={"ZOEYMCP_GATEWAY_KEY": keys.gateway_key(1)}, log=state.parent / "gateway.log"
    )
    wait_port(port, process)
    return process


def deployment_of(made: ManagedVault) -> str:
    """The deployment the vault's head names, read without opening the store under it."""
    keys = KeySet.from_text(made.env["ZOEYMCP_MASTER_KEY"])
    return unseal_head((made.state / "policy" / "head.json").read_bytes(), keys, None).deployment


def seen_by(state: Path) -> dict[str, int]:
    """What the gateway's witness holds: each deployment's highest revision."""
    path = state / witness.FILE
    return witness.loads(path.read_bytes()).report() if path.exists() else {}


def wait_for(check: Callable[[], bool], what: str, *processes: Process) -> None:
    """Until ``check`` holds; fails with the processes' output if one exits or time runs out."""
    deadline = time.monotonic() + WITNESS_WAIT
    while not check():
        for process in processes:
            if process.popen.poll() is not None:
                raise RuntimeError(f"a process exited before {what}:\n{process.output()}")
        if time.monotonic() > deadline:
            said = "\n".join(process.output() for process in processes)
            raise AssertionError(f"{what} never happened:\n{said}")
        time.sleep(0.2)


def add_client(made: ManagedVault, name: str, digit: str) -> int:
    """An offline import, the vault stopped, adding client ``name`` (a change to the gateway's
    view); the revision it wrote."""

    def change(data: dict[str, Any]) -> None:
        data["gateway"]["clients"][name] = {"token_sha256": "sha256:" + digit * 64}

    state = ["--state", str(made.state)]
    text = edited_export(made, change, state)
    code, _, err = made.cli(["policy", "import", "-", *state, "--yes", "--accept-widening"], text)
    assert code == 0, err
    return opened(made).revision


def put_back(made: ManagedVault, copy: Path, relative: str = "") -> None:
    """The vault's volume, or one directory in it, replaced by ``copy``, as a restore does."""
    target = made.state / relative if relative else made.state
    shutil.rmtree(target)
    shutil.copytree(copy, target)


def test_policy_dir_restored_alone(tmp_path: Path) -> None:
    """J11's first case, D.6 row 9: /state/policy put back from an older backup, the anchor
    beside it kept: the vault refuses to start, naming the recoveries."""
    made = vault(tmp_path)
    made.start()
    made.stop()
    backup = tmp_path / "policy-backup"
    shutil.copytree(made.state / "policy", backup)
    assert add_client(made, "agent2", "2") == 2
    put_back(made, backup, "policy")
    said = made.refused()
    assert "the policy head is revision 1, but revision 2 was committed" in said
    assert "restored from an older backup?" in said
    assert (
        f"Restore {made.state.as_posix()} from one backup, or start from your latest export:"
        in said
    )
    assert f"policy import --state {made.state.as_posix()} --reseed - < policy-export.yaml" in said


# How the host acknowledges: with the vault stopped (--state), or over its admin socket.
VIA = [pytest.param(False, id="offline"), pytest.param(True, id="socket", marks=UNIX)]
SOCKET_AUTHOR = {"by": "host", "via": "socket"}


# J11's re-review: notes, on a fake upstream through the vault's route, which the gateway lists,
# and the portal's review Save with a passkey, the only write that re-pins in managed mode (H.5).
SERVER = "notes"
AGENT_TOKEN = "managed-client-token-0001"
DRIFTED = "add"  # the tool the fake changes (its rounding enum, change_tool("enum"))


def notes_policy(portal: int, upstream: str, pins: dict[str, str]) -> dict[str, Any]:
    """The smallest managed policy with a remote server: notes on the fake at ``upstream`` (no
    credential; the loopback upstream listed in ``egress_private``), every tool in ``pins``
    included as approve at its pin, and agent1 given it."""
    tools = sorted(pins)
    route = {
        "name": SERVER,
        "prefix": f"/{SERVER}",
        "upstream": upstream,
        "callers": ["gateway"],
        "stream": True,
        "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": [PATH]}],
    }
    server = {
        "kind": "remote",
        "route": SERVER,
        "path": PATH,
        "era": "modern",
        "tools": {"include": tools, "allow": [], "approve": tools},
        "review": pins,
    }
    return managed_policy(
        portal,
        egress_private=[upstream.removeprefix("https://")],
        routes=[route],
        gateway={
            "clients": {"agent1": {"token": AGENT_TOKEN, "servers": [SERVER]}},
            "servers": {SERVER: server},
        },
    )


def served(port: int) -> list[str] | None:
    """The tools the gateway on ``port`` serves agent1 from notes, as an agent lists them; None
    while it can't answer (the vault restarting, the gateway's backoff)."""

    async def listing() -> list[str]:
        headers = {"authorization": f"Bearer {AGENT_TOKEN}"}
        async with httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0)) as http:
            url = f"http://127.0.0.1:{port}/s/{SERVER}/mcp"
            async with Client(streamable_http_client(url, http_client=http), cache=None) as agent:
                return sorted(tool.name for tool in (await agent.list_tools()).tools)

    try:
        return anyio.run(listing)
    except Exception:  # the SDK's errors arrive in exception groups
        return None


def shown(page: Page) -> tuple[set[str], list[tuple[str, str]]]:
    """What the portal shows: the codes on health's checklist, and Home's attention items (each
    its kind and the server its button reviews)."""
    health = page.fetch("GET", "/api/health")
    home = page.fetch("GET", "/api/attention")
    assert (health.status_code, home.status_code) == (200, 200), health.text + home.text
    codes = {finding["code"] for finding in health.json()["checklist"]}
    items = [(item["kind"], item["action"]["server"]) for item in home.json()["items"]]
    return codes, items


def review_saved(
    page: Page, passkey: SoftAuthenticator, tools: list[str], *processes: Process
) -> tuple[str, dict[str, Any]]:
    """**Review again** on notes in the portal, which the gateway runs against the upstream; the
    drifted tool re-pinned and every tool kept approve, saved with the passkey: the kind the
    draft named and the confirm's answer."""
    queued = page.fetch("POST", f"/api/review/{SERVER}", json={"fresh": True})
    assert queued.status_code == 200, queued.text
    path = f"/api/review/jobs/{queued.json()['job']}"
    read: dict[str, Any] = {}

    def done() -> bool:
        answer = page.fetch("GET", path)
        assert answer.status_code == 200, answer.text
        read.update(answer.json())
        return bool(read["state"] == "done")

    wait_for(done, "the review", *processes)
    assert {row["name"]: row["state"] for row in read["tools"]}[DRIFTED] == "drift"
    choices = {"include": tools, "allow": [], "approve": tools, "repin": [DRIFTED]}
    drafted = page.fetch("POST", f"{path}/diff", json={**choices, "decline_rest": False})
    assert drafted.status_code == 200, drafted.text
    draft = drafted.json()
    data = {"draft": draft["draft"], "base": draft["base"]}
    held = page.fetch("POST", "/api/actions", json={"kind": draft["kind"], "data": data})
    assert held.status_code == 200, held.text
    assertion = passkey.get(held.json()["options"], page.origin).body()
    confirm = f"/api/actions/{held.json()['action']}/confirm"
    saved = page.fetch("POST", confirm, json={"credential": assertion})
    assert saved.status_code == 200, saved.text
    answer: dict[str, Any] = saved.json()
    return str(draft["kind"]), answer


@pytest.mark.parametrize("over_socket", VIA)
def test_restored_volume_is_flagged(tmp_path: Path, ca: ProviderCA, over_socket: bool) -> None:
    """J11's second case, FM-8's witness half, Y24, OPS-10: the whole /state put back from a copy
    at revision 1 while the gateway, on its own volume, has applied revision 3 (an import, then
    the portal's re-pin of ``add``, which the fake changed): the vault starts, the gateway logs
    the regression and keeps 3, and the vault raises policy_behind_witness from its status
    report. The restored head pins ``add`` at its old definition, so the gateway hides it again
    and Home and health list notes as drifted, until the portal's review saves the re-pin again
    (revision 2, still behind the witness). Acknowledged, revision 4 jumps past the claim: with
    the vault stopped, the number given with --to; over the socket, the gateway's claim named
    and the number typed. The finding is not raised again, the gateway records 4, and ``add`` is
    served at the pin the review saved."""
    fake = McpFake(mode="modern")
    pins = {wire["name"]: pin_of_fake(fake, wire["name"]) for wire in base_tools()}
    tools = sorted(pins)
    hidden = [name for name in tools if name != DRIFTED]
    made = socket_vault(tmp_path) if over_socket else vault(tmp_path)
    made.ca = ca.ca_file
    gateway_state = tmp_path / "gateway-state"
    port = free_port()
    passkey = SoftAuthenticator()
    # A review queued in the vault's first 45 s waits for the gateway's first poll (OPS-20).
    with serve_tls(fake.app(), ca, lifespan=True) as upstream, Browser(timeout=60.0) as browser:
        made.policy = notes_policy(made.portal, upstream, pins)
        page = browser.page(f"http://localhost:{made.portal}")
        running = made.start()
        gateway = gateway_on(made, gateway_state, port)
        try:
            deployment = deployment_of(made)
            assert redeem(page, setup_code(made.state, made.env)).status_code == 200
            assert enrol(page, passkey).status_code == 200
            wait_for(lambda: seen_by(gateway_state) == {deployment: 1}, "revision 1 seen", gateway)
            made.stop()
            backup = tmp_path / "state-backup"
            shutil.copytree(made.state, backup)
            assert add_client(made, "agent2", "2") == 2
            running = made.start()
            assert login(page, passkey).status_code == 200
            fake.change_tool("enum")
            repinned = pin_of_fake(fake, DRIFTED)
            wait_for(lambda: served(port) == hidden, "add hidden", gateway, running)
            wait_for(lambda: shown(page)[1] == [("drifted", SERVER)], "drift", gateway, running)
            assert review_saved(page, passkey, tools, gateway, running)[0] == "tool.repin"
            wait_for(lambda: seen_by(gateway_state) == {deployment: 3}, "revision 3 seen", gateway)
            wait_for(lambda: served(port) == tools, "add served", gateway, running)
            made.stop()
            put_back(made, backup)
            before = len(made.output())
            running = made.start()

            def flagged() -> bool:
                return bool(events(made.output()[before:], "policy_behind_witness"))

            wait_for(flagged, "policy_behind_witness", gateway, running)
            [line] = events(made.output()[before:], "policy_behind_witness")
            assert (line["level"], line["head"], line["witness"]) == ("critical", 1, 3)

            def regressions() -> list[tuple[int, int]]:
                found = events(gateway.output(), "policy_revision_regressed")
                assert {r["deployment"] for r in found} <= {deployment[:8]}
                return [(r["seen"], r["now"]) for r in found]

            # The status push that raised the finding can come before the gateway's next fetch.
            wait_for(lambda: regressions() == [(3, 1)], "the regression to 1", gateway, running)
            assert seen_by(gateway_state) == {deployment: 3}
            # The restored head pins add as it was: drifted again, until it is reviewed again.
            assert login(page, passkey).status_code == 200
            wait_for(lambda: served(port) == hidden, "add hidden again", gateway, running)
            wait_for(lambda: shown(page)[1] == [("drifted", SERVER)], "drift", gateway, running)
            assert {"policy_behind_witness", "drift_marked"} <= shown(page)[0]
            kind, answer = review_saved(page, passkey, tools, gateway, running)
            assert (kind, answer["revision"]) == ("tool.repin", 2)
            wait_for(lambda: served(port) == tools, "add served again", gateway, running)
            wait_for(lambda: shown(page)[1] == [], "no drift", gateway, running)
            codes = shown(page)[0]
            assert "drift_marked" not in codes
            assert "policy_behind_witness" in codes  # 2 is still behind the witness's 3
            wait_for(
                lambda: regressions() == [(3, 1), (3, 2)], "the regression to 2", gateway, running
            )
            if over_socket:
                code, _, err = made.cli(["policy", "acknowledge-restore"], "4\n")
                assert code == 0, err
                assert err.splitlines()[:2] == [
                    "Revision 2 jumps to 4: one above the gateway's claim of 3; the number comes "
                    "from the gateway.",
                    "Type 4 to write it: Planned on revision 2 (the head):",
                ]
                after = len(made.output())
            else:
                made.stop()
                state = ["--state", str(made.state)]
                argv = ["policy", "acknowledge-restore", *state, "--to", "4", "--yes"]
                code, _, err = made.cli(argv)
                assert code == 0, err
                after = len(made.output())
                running = made.start()
                assert login(page, passkey).status_code == 200
            assert "Acknowledged the restore as revision 4." in err
            wait_for(lambda: seen_by(gateway_state) == {deployment: 4}, "revision 4 seen", gateway)
            wait_for(
                lambda: bool(events(made.output()[after:], "status_received")),
                "a status report after the acknowledgment",
                gateway,
            )
            assert events(made.output()[after:], "policy_behind_witness") == []
            wait_for(lambda: served(port) == tools, "add served at 4", gateway, running)

            def quiet() -> bool:
                codes, items = shown(page)
                return not items and not {"policy_behind_witness", "drift_marked"} & codes

            wait_for(quiet, "nothing left to review or acknowledge", gateway, running)
        finally:
            gateway.stop()
            made.stop()
    acknowledged = opened(made)
    header = acknowledged.top.header
    assert (acknowledged.revision, header["origin"], header["jumped_from"]) == (4, "acknowledge", 2)
    assert header["author"] == (SOCKET_AUTHOR if over_socket else OFFLINE)
    saved = head_policy(acknowledged).gateway
    assert saved is not None
    assert saved.servers[SERVER].review[DRIFTED] == repinned != pins[DRIFTED]


@pytest.mark.parametrize("over_socket", VIA)
def test_wiped_state_is_flagged(tmp_path: Path, over_socket: bool) -> None:
    """J11's third case, T-5: /state wiped whole while the gateway's volume is kept: the vault
    seeds revision 1 under a new deployment, the gateway records it beside the old one at 2
    (policy_deployment_seen, a warning), and the vault raises policy_deployment_changed from
    the status report. Acknowledged past the old one's revision (with --to and --yes, the vault
    stopped or over the socket, where the line names the other deployment), it isn't raised
    again."""
    made = socket_vault(tmp_path) if over_socket else vault(tmp_path)
    made.start()
    made.stop()
    assert add_client(made, "agent2", "2") == 2
    old = opened(made).head.deployment
    made.start()
    gateway_state = tmp_path / "gateway-state"
    gateway = gateway_on(made, gateway_state)
    try:
        wait_for(lambda: seen_by(gateway_state) == {old: 2}, "revision 2 seen", gateway)
        made.stop()
        shutil.rmtree(made.state)
        before = len(made.output())
        made.start()
        assert made.process is not None
        wait_for(lambda: (made.state / "policy" / "head.json").exists(), "the seed", gateway)
        new = deployment_of(made)
        assert new != old
        wait_for(lambda: seen_by(gateway_state) == {old: 2, new: 1}, "the new one", gateway)
        seen_lines = events(gateway.output(), "policy_deployment_seen")
        assert [(s["level"], s["deployment"]) for s in seen_lines] == [
            ("info", old[:8]),
            ("warning", new[:8]),
        ]

        def flagged() -> bool:
            return bool(events(made.output()[before:], "policy_deployment_changed"))

        wait_for(flagged, "policy_deployment_changed", gateway, made.process)
        [line] = events(made.output()[before:], "policy_deployment_changed")
        assert (line["deployment"], line["other"], line["revision"]) == (new[:8], old[:8], 2)
        if over_socket:
            code, _, err = made.cli(["policy", "acknowledge-restore", "--to", "3", "--yes"])
            assert code == 0, err
            assert err.splitlines()[0] == (
                "Revision 1 jumps to 3: one above the gateway's claim of 2 for another "
                f"deployment of this vault ({old[:8]}); the number comes from the gateway."
            )
            after = len(made.output())
        else:
            made.stop()
            state = ["--state", str(made.state)]
            argv = ["policy", "acknowledge-restore", *state, "--to", "3", "--yes"]
            code, _, err = made.cli(argv)
            assert code == 0, err
            after = len(made.output())
            made.start()
        assert "Acknowledged the restore as revision 3." in err
        wait_for(lambda: seen_by(gateway_state) == {old: 2, new: 3}, "revision 3 seen", gateway)
        wait_for(
            lambda: bool(events(made.output()[after:], "status_received")),
            "a status report after the acknowledgment",
            gateway,
        )
        assert events(made.output()[after:], "policy_deployment_changed") == []
    finally:
        gateway.stop()
        made.stop()
    acknowledged = opened(made)
    assert (acknowledged.revision, acknowledged.top.header["jumped_from"]) == (3, 1)
    assert acknowledged.top.header["author"] == (SOCKET_AUTHOR if over_socket else OFFLINE)
