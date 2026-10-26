"""S17, Managed policy lifecycle (M6 design O.5; J4-J11, J14-J16 here, J12 in
``test_prompts_resources_shape.py``, the crash during a save in ``test_policy_crash.py``): real
vault processes on one state directory, with the host's ``zoeymcp policy`` commands run beside
them as ``docker compose run`` runs them, or as ``docker compose exec`` runs them over the
vault's admin socket, and a real gateway process where a journey needs one, over the hardened
tier's TCP link with the gateway key or, on Linux, the standard tier's link socket.

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
  declaratively. The admin socket is a Unix socket, so its rows run where there is one;
- Y19 (step 22): F.1's rows as processes: the mode comes from the source, a source that doesn't
  load or fails check is ignored beside a head and refused beside a parked store, and a store
  that doesn't verify is left alone by a declarative start;
- J10 (step 22): back to declarative, parking the store, and back to managed, resuming it as the
  next revision; a stale declarative file that brings back a removed client is named at the
  park and at the resume (FM-26, T-16);
- J15 (step 22): an import that needs a vault restart, health's ``policy_restart_needed`` until
  it; the gateway key rotated by an import, not by the compose variable;
- Y12 (step 22): a removed client's token refused; the portal's rollback that would revive it
  refused, the host's with --allow-revive done, and the token works again;
- S17's saves (step 22): **Allow without asking**, a rollback from the Policy page and a
  connector's Pause, each with the test authenticator's passkey (the review saves, the clear
  and Give to clients are J11's, J12's, J14's and S12's);
- J14 (step 22): the quickstart in both tiers, prompt for prompt: J14s's seed, ``secret set``,
  ``setup-code`` and the review's Save over the link socket; J14h's five prompts for an OAuth
  server added by its URL (the fakes on their names through a resolver map, as S9's).

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
from zoeymcp.common.policy.schema import RemoteServer, hash_token
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


def gateway_on(
    made: ManagedVault, state: Path, port: int | None = None, *, generation: int = 1
) -> Process:
    """The gateway on the vault's TCP listener with the gateway key of ``generation``, as the
    hardened tier runs it, or on the vault's link socket when it has one, as the standard tier
    does; on its own volume ``state``: kept when the vault's is restored or wiped. Its agents'
    listener is on ``port`` (any free one by default)."""
    state.mkdir(mode=0o700, exist_ok=True)
    port = port or free_port()
    link, env = f"unix:{made.link}", {}
    if not made.link_socket:
        keys = KeySet.from_text(made.env["ZOEYMCP_MASTER_KEY"])
        link = f"http://127.0.0.1:{made.port}"
        env = {"ZOEYMCP_GATEWAY_KEY": keys.gateway_key(generation)}
    argv = [
        "gateway", "--vault", link, "--listen", f"127.0.0.1:{port}", "--state", str(state),
        "--admin-socket", "none",
    ]  # fmt: skip
    process = start(argv, env=env, log=state.parent / "gateway.log")
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


def served(port: int, token: str = AGENT_TOKEN) -> list[str] | None:
    """The tools the gateway on ``port`` serves the client of ``token`` (agent1's by default)
    from notes, as an agent lists them; None while it can't answer (the vault restarting, the
    gateway's backoff, a token it refuses)."""

    async def listing() -> list[str]:
        headers = {"authorization": f"Bearer {token}"}
        async with httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0)) as http:
            url = f"http://127.0.0.1:{port}/s/{SERVER}/mcp"
            async with Client(streamable_http_client(url, http_client=http), cache=None) as agent:
                return sorted(tool.name for tool in (await agent.list_tools()).tools)

    try:
        return anyio.run(listing)
    except Exception:  # the SDK's errors arrive in exception groups
        return None


def refused_with(port: int, token: str) -> int | None:
    """The status the gateway on ``port`` answers an agent's first request with ``token``, or
    None while it can't answer."""
    headers = {"authorization": f"Bearer {token}", "accept": "application/json, text/event-stream"}
    hello = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    try:
        answer = httpx2.post(
            f"http://127.0.0.1:{port}/s/{SERVER}/mcp", headers=headers, json=hello, timeout=30
        )
    except httpx2.HTTPError:
        return None
    return answer.status_code


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


# --- the source's mode, and back to declarative (J10, F.1, F.4; Y19, FM-26) --------------------


def test_mode_comes_from_the_source(tmp_path: Path) -> None:
    """Y19, F.1's rows as processes: on a managed store, a source that doesn't load, a managed
    one that fails check, and none at all each start the head, the first two saying the source
    is ignored; a declarative one that fails check refuses and parks nothing; a valid one runs
    declaratively and parks the store, and the next declarative start parks nothing again;
    parked, no source, one that doesn't load and a managed one that fails check are refused,
    naming the resume; a store that doesn't verify is left alone by a declarative start
    (``policy_store_unverified``), its files as they were; and on a fresh volume no source, one
    that doesn't load and a managed one that fails check are each refused, nothing seeded."""
    made = vault(tmp_path)
    made.start()
    made.stop()
    before = opened(made)
    kept = declarative(made)
    made.config = "version: 1\nmode: [\n"
    made.start()
    made.stop()
    made.config = None
    made.policy = {"version": 1, "mode": "managed"}  # no admin block: check refuses (A.2 row 2)
    made.start()
    made.stop()
    made.policy = None
    made.start()
    made.stop()
    assert unchanged(made, before)
    ignored = [line["reason"] for line in events(made.output(), "policy_seed_ignored")]
    assert ignored == ["unreadable", "fails_check"]
    made.policy = {**kept, "bogus": 1}
    assert "bogus" in made.refused()
    assert opened(made).parked is None
    made.policy = kept
    for _ in range(2):
        made.start()
        made.stop()
    assert [line["revision"] for line in events(made.output(), "policy_store_parked")] == [1]
    assert opened(made).parked == 1
    parked_text = (
        "refused to start: this store was parked by a declarative start at revision 1: give the "
        "policy to resume from, with mode: managed"
    )
    made.policy = None
    assert parked_text in made.refused()
    made.config = "version: 1\nmode: [\n"
    assert f"{parked_text}; the policy given is refused: " in made.refused()
    made.config = None
    made.policy = {"version": 1, "mode": "managed"}
    said = made.refused()
    assert f"{parked_text}; the policy given is refused: " in said
    assert FAILS_CHECK in said
    assert opened(made).parked == 1
    made.policy = kept
    head = made.state / "policy" / "head.json"
    good = head.read_bytes()
    at = good.index(b'"mac":"') + len(b'"mac":"')
    head.write_bytes(good[:at] + (b"1" if good[at : at + 1] == b"0" else b"0") + good[at + 1 :])
    tampered = store_bytes(made)
    made.start()
    made.stop()
    [unverified] = events(made.output(), "policy_store_unverified")
    assert unverified["reason"] == "tampered"
    assert store_bytes(made) == tampered
    head.write_bytes(good)
    fresh = ManagedVault(tmp_path / "fresh", dict(made.env))
    fresh.tmp.mkdir(mode=0o700)
    assert "no policy given: use --config or set ZOEYMCP_CONFIG" in fresh.refused()
    fresh.config = "version: 1\nmode: [\n"
    assert "invalid YAML" in fresh.refused()
    fresh.config = None
    fresh.policy = {"version": 1, "mode": "managed"}
    assert FAILS_CHECK in fresh.refused()
    assert not (fresh.state / "policy-anchor.json").exists()
    assert not (fresh.state / "policy").exists()
    assert '"event":"policy_seeded"' not in fresh.output()


# The gate's finding for a managed policy with no admin block (A.2 row 2).
FAILS_CHECK = "fails check (1 error(s)): mode: managed mode is edited in the portal"


def store_bytes(made: ManagedVault) -> dict[str, bytes]:
    """The anchor's and every policy/ file's bytes, by path."""
    found = {"policy-anchor.json": (made.state / "policy-anchor.json").read_bytes()}
    for path in sorted((made.state / "policy").rglob("*")):
        if path.is_file():
            found[path.relative_to(made.state).as_posix()] = path.read_bytes()
    return found


def test_back_to_declarative_and_resume(tmp_path: Path) -> None:
    """J10, FM-26, F.4, T-16: the head exported as a declarative policy runs declaratively,
    parking the store; back to managed, the vault resumes: the file it is given becomes the next
    revision, planned against the parked head, and nothing stale runs. A stale declarative file
    that brings back a client managed mode removed says so at the park (critical, naming it)
    and in health while it runs (``policy_declarative_revives``, beside the park's info), and
    the resume accepts it, the host having run it, and names it once."""
    made = vault(tmp_path)
    made.start()
    made.stop()
    state = ["--state", str(made.state)]
    assert add_client(made, "agent2", "2") == 2
    code, stale, err = made.cli(["policy", "export", "--mode", "declarative", *state])
    assert code == 0, err

    def remove(data: dict[str, Any]) -> None:
        del data["gateway"]["clients"]["agent2"]

    text = edited_export(made, remove, state)
    code, _, err = made.cli(["policy", "import", "-", *state, "--yes"], text)
    assert code == 0, err
    code, out, err = made.cli(["policy", "export", "--mode", "declarative", *state])
    assert code == 0, err
    current = yaml.safe_load(out)
    assert (current["mode"], sorted(current["gateway"]["clients"])) == ("declarative", ["agent1"])
    made.policy = current
    made.start()
    made.stop()
    [parked] = events(made.output(), "policy_store_parked")
    assert (parked["level"], parked["revision"]) == ("warning", 3)
    assert opened(made).parked == 3
    made.policy = {**current, "mode": "managed"}
    made.start()
    made.stop()
    found = opened(made)
    assert (found.revision, found.parked, found.top.header["origin"]) == (4, None, "resume")
    [resumed] = events(made.output(), "policy_resumed")
    assert (resumed["level"], resumed["revision"], resumed["parked_at"]) == ("info", 4, 3)
    assert resumed["revived"] == 0
    # A stale file, from before agent2 was removed, flipped to declarative by hand.
    made.policy = yaml.safe_load(stale)
    passkey = SoftAuthenticator()
    with Browser(timeout=60.0) as browser:
        page = browser.page(f"http://localhost:{made.portal}")
        made.start()
        try:
            assert redeem(page, setup_code(made.state, made.env)).status_code == 200
            assert enrol(page, passkey).status_code == 200
            assert login(page, passkey).status_code == 200
            health = page.fetch("GET", "/api/health")
        finally:
            made.stop()
    assert health.status_code == 200, health.text
    checklist = {finding["code"]: finding for finding in health.json()["checklist"]}
    assert checklist["policy_store_parked"]["level"] == "info"
    revives = checklist["policy_declarative_revives"]
    assert revives["level"] == "warning"
    assert "client:agent2" in revives["text_shown"]
    revived = events(made.output(), "policy_store_parked")[-1]
    assert (revived["level"], revived["revision"], revived["revived"]) == ("critical", 4, 1)
    assert revived["names"] == ["client:agent2"]
    made.policy = {**yaml.safe_load(stale), "mode": "managed"}
    made.start()
    made.stop()
    found = opened(made)
    assert found.revision == 5
    gateway = head_policy(found).gateway
    assert gateway is not None
    assert sorted(gateway.clients) == ["agent1", "agent2"]
    resumed = events(made.output(), "policy_resumed")[-1]
    assert (resumed["level"], resumed["revision"], resumed["parked_at"]) == ("warning", 5, 4)
    assert (resumed["revived"], resumed["names"]) == (1, ["client:agent2"])


# --- a save that needs a restart, and the gateway key in managed mode (J15; I.2, Y16) ----------

PROXY_TEXT = (
    "egress_proxy: the vault's HTTP clients keep the proxy they started with: restart the vault"
)


def restart_findings(made: ManagedVault) -> list[str]:
    """Health's ``policy_restart_needed`` texts, over the socket."""
    code, out, err = made.cli(["health", "--json"])
    assert code in (0, 1), err
    findings = json.loads(out)["policy"]["findings"]
    return [f["text"] for f in findings if f["code"] == "policy_restart_needed"]


@UNIX
def test_restart_needed(tmp_path: Path) -> None:
    """J15, Y16, I.2: an import over the socket that changes egress_proxy says a vault restart
    is needed, in its plan; health keeps ``policy_restart_needed`` naming the path until the
    vault restarts, and not after."""
    made = socket_vault(tmp_path)
    made.start()
    try:

        def proxied(data: dict[str, Any]) -> None:
            data["egress_proxy"] = "http://127.0.0.1:3128"

        argv = ["policy", "import", "-", "--yes", "--accept-widening"]
        code, _, err = made.cli(argv, edited_export(made, proxied))
        assert code == 0, err
        assert f"  Restart needed: {PROXY_TEXT}\n" in err
        assert restart_findings(made) == [PROXY_TEXT]
    finally:
        made.stop()
    made.start()
    try:
        assert restart_findings(made) == []
    finally:
        made.stop()
    assert head_policy(opened(made)).egress_proxy == "http://127.0.0.1:3128"


def test_gateway_key_rotation_managed(tmp_path: Path) -> None:
    """J15's rotation, F-46, OPS-7: in managed mode the compose policy's gateway_key_generation
    is read only at the seed, so raising it and recreating changes no generation (the source is
    ignored); an export with the generation raised, imported with the vault stopped, plans the
    key's delivery, and the gateway then reaches the vault with the new generation's key."""
    made = vault(tmp_path)
    assert made.policy is not None
    gateway_state = tmp_path / "gateway-state"
    running = made.start()
    deployment = deployment_of(made)
    gateway = gateway_on(made, gateway_state)
    try:
        wait_for(lambda: seen_by(gateway_state) == {deployment: 1}, "revision 1", gateway, running)
    finally:
        gateway.stop()
        made.stop()
    made.policy = {**made.policy, "gateway_key_generation": 2}
    made.start()
    made.stop()
    [ignored] = events(made.output(), "policy_seed_ignored")
    assert ignored["reason"] == "changed"
    assert head_policy(opened(made)).gateway_key_generation == 1

    def raised(data: dict[str, Any]) -> None:
        data["gateway_key_generation"] = 2

    state = ["--state", str(made.state)]
    text = edited_export(made, raised, state)
    code, _, err = made.cli(["policy", "import", "-", *state, "--yes", "--accept-widening"], text)
    assert code == 0, err
    assert "give the gateway key(2) within 5 minutes (zoeymcp gateway-key), or it is refused" in err
    assert head_policy(opened(made)).gateway_key_generation == 2
    running = made.start()
    gateway = gateway_on(made, gateway_state, generation=2)
    try:
        wait_for(lambda: seen_by(gateway_state) == {deployment: 2}, "revision 2", gateway, running)
    finally:
        gateway.stop()
        made.stop()


# --- a reviving rollback is the host's (Y5, Y12; J6) ------------------------------------------

OTHER_TOKEN = "managed-client-token-0002"


def opened_live(made: ManagedVault) -> int:
    """The head revision the running vault answers over its socket."""
    code, out, err = made.cli(["policy", "head", "--format", "json"])
    assert code == 0, err
    revision: int = json.loads(out)["revision"]
    return revision


@UNIX
def test_revive_needs_the_host(tmp_path: Path, ca: ProviderCA) -> None:
    """Y5, Y12, J6: agent2's token, removed by an import over the socket, is refused (401) while
    agent1's is served; a portal rollback to the revision before is refused
    ``rollback_revives``, before any prompt; the host's rollback with --allow-revive brings
    agent2 back, and its token works again."""
    fake = McpFake(mode="modern")
    pins = {wire["name"]: pin_of_fake(fake, wire["name"]) for wire in base_tools()}
    tools = sorted(pins)
    made = socket_vault(tmp_path)
    made.ca = ca.ca_file
    port = free_port()
    passkey = SoftAuthenticator()
    with serve_tls(fake.app(), ca, lifespan=True) as upstream, Browser(timeout=60.0) as browser:
        made.policy = notes_policy(made.portal, upstream, pins)
        made.policy["gateway"]["clients"]["agent2"] = {"token": OTHER_TOKEN, "servers": [SERVER]}
        page = browser.page(f"http://localhost:{made.portal}")
        running = made.start()
        gateway = gateway_on(made, tmp_path / "gateway-state", port)
        try:
            assert redeem(page, setup_code(made.state, made.env)).status_code == 200
            assert enrol(page, passkey).status_code == 200
            assert login(page, passkey).status_code == 200
            wait_for(lambda: served(port, OTHER_TOKEN) == tools, "agent2 served", gateway, running)

            def remove(data: dict[str, Any]) -> None:
                del data["gateway"]["clients"]["agent2"]

            code, _, err = made.cli(["policy", "import", "-", "--yes"], edited_export(made, remove))
            assert code == 0, err

            def agent2_refused() -> bool:
                return refused_with(port, OTHER_TOKEN) == 401 and served(port) == tools

            wait_for(agent2_refused, "agent2 refused, agent1 served", gateway, running)
            rollback = {"kind": "policy.rollback", "data": {"base": 2, "revision": 1}}
            refused = page.fetch("POST", "/api/actions", json=rollback)
            assert (refused.status_code, refused.json()["reason"]) == (409, "rollback_revives")
            assert refused.json()["subjects"] == ["client:agent2"]
            assert opened_live(made) == 2
            argv = ["policy", "rollback", "1", "--yes", "--accept-widening"]
            code, _, err = made.cli([*argv, "--allow-revive", "client:agent2"])
            assert code == 0, err
            wait_for(lambda: served(port, OTHER_TOKEN) == tools, "agent2 again", gateway, running)
        finally:
            gateway.stop()
            made.stop()
    found = opened(made)
    assert (found.revision, found.top.header["target"]) == (3, 1)
    assert events(made.output(), "step_up_confirmed") == []


# --- the quickstart, managed, prompt by prompt (J14; F.3, G.3, G.9) -------------------------

LINK = pytest.mark.skipif(
    sys.platform != "linux", reason="the standard tier's link socket and admin socket are Linux's"
)
API_KEY = "quickstart-notes-key-0001"
STANDARD = "docker compose -f deploy/compose.yaml"


def one_row(page: Page) -> dict[str, Any]:
    """The MCP servers page's one row."""
    answer = page.fetch("GET", "/api/servers")
    assert answer.status_code == 200, answer.text
    [found] = answer.json()["servers"]
    row: dict[str, Any] = found
    return row


def portal_review(
    page: Page, *processes: Process, fresh: bool = True
) -> tuple[str, dict[str, Any]]:
    """**Review** on notes in the portal, which the gateway runs: the job's path and its done
    answer."""
    queued = page.fetch("POST", f"/api/review/{SERVER}", json={"fresh": True} if fresh else {})
    assert queued.status_code == 200, queued.text
    path = f"/api/review/jobs/{queued.json()['job']}"
    read: dict[str, Any] = {}

    def done() -> bool:
        answer = page.fetch("GET", path)
        assert answer.status_code == 200, answer.text
        read.update(answer.json())
        return bool(read["state"] == "done")

    wait_for(done, "the review", *processes)
    return path, read


def stepped_up(
    page: Page, passkey: SoftAuthenticator, kind: str, data: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """An action prepared, its passkey prompt answered and confirmed, as the page's dialog does
    it: the plan the dialog showed and the confirm's answer."""
    held = page.fetch("POST", "/api/actions", json={"kind": kind, "data": data})
    assert held.status_code == 200, held.text
    assertion = passkey.get(held.json()["options"], page.origin).body()
    confirm = f"/api/actions/{held.json()['action']}/confirm"
    saved = page.fetch("POST", confirm, json={"credential": assertion})
    assert saved.status_code == 200, saved.text
    plan: dict[str, Any] = held.json()
    answer: dict[str, Any] = saved.json()
    return plan, answer


def quickstart_policy(portal: int, upstream: str) -> dict[str, Any]:
    """The standard compose file's policy with ``mode: managed``, edited as J14s says before the
    first ``up -d``: the server's URL (the fake's, listed in ``egress_private``) and agent1's
    ``token_sha256``."""
    route = {
        "name": "notes-mcp",
        "prefix": "/notes",
        "upstream": upstream,
        "credential": "notes-key",
        "callers": ["gateway"],
        "stream": True,
        "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": [PATH]}],
    }
    key = {"kind": "header", "header": "X-API-Key", "format": "{secret}"}
    server = {
        "kind": "remote",
        "route": "notes-mcp",
        "path": PATH,
        "tools": {"include": [], "allow": [], "approve": []},
        "review": {},
    }
    return managed_policy(
        portal,
        egress_private=[upstream.removeprefix("https://")],
        credentials={"notes-key": {**key, "secret": "store:notes-key"}},
        routes=[route],
        gateway={
            "clients": {"agent1": {"token_sha256": hash_token(AGENT_TOKEN), "servers": [SERVER]}},
            "servers": {SERVER: server},
        },
    )


def standard_walk(tmp_path: Path, ca: ProviderCA) -> None:
    """J14s, the README's quickstart in the standard tier: the seed from the compose policy, the
    key set and the setup code issued in the container, then one prompt: the review's Save."""
    fake = McpFake(mode="modern", key=API_KEY, key_header="x-api-key")
    made = vault(tmp_path)
    made.admin_socket = True
    made.link_socket = True
    made.ca = ca.ca_file
    made.env["ZOEYMCP_COMPOSE_CMD"] = STANDARD
    made.env["ZOEYMCP_EXEC_SERVICE"] = "zoeymcp"
    port = free_port()
    passkey = SoftAuthenticator()
    with serve_tls(fake.app(), ca, lifespan=True) as upstream, Browser(timeout=60.0) as browser:
        made.policy = quickstart_policy(made.portal, upstream)
        page = browser.page(f"http://localhost:{made.portal}")
        running = made.start()
        gateway = gateway_on(made, tmp_path / "gateway-state", port)
        try:
            [seeded] = events(made.output(), "policy_seeded")
            assert (seeded["revision"], seeded["tokens_hashed"], seeded["via"]) == (1, 0, "start")
            code, _, err = made.cli(["secret", "set", "notes-key"], API_KEY)
            assert code == 0, err
            code, out, err = made.cli(["setup-code"])
            assert code == 0, err
            assert err.splitlines()[0] == (
                "One-time code, valid for 15 minutes. "
                f"Open http://localhost:{made.portal} and choose Set up."
            )
            assert redeem(page, out.strip()).status_code == 200
            assert enrol(page, passkey).status_code == 200
            assert login(page, passkey).status_code == 200
            path, read = portal_review(page, gateway, running)
            rows = [row for row in read["tools"] if row["pinnable"]]
            allow = sorted(row["name"] for row in rows if row["suggested"] == "allow")
            approve = ["add"]
            assert allow
            assert "add" not in allow
            choices = {"include": [*allow, *approve], "allow": allow, "approve": approve}
            drafted = page.fetch("POST", f"{path}/diff", json={**choices, "decline_rest": True})
            assert drafted.status_code == 200, drafted.text
            draft = drafted.json()
            # The managed ending: a draft to save, no fragment and no commit or recreate.
            assert set(draft) == {"draft", "base", "kind", "summary"}
            assert (draft["kind"], draft["base"]) == ("policy.save", 1)
            data = {"draft": draft["draft"], "base": 1}
            plan, saved = stepped_up(page, passkey, "policy.save", data)
            assert plan["summary"][0][0] == "Revision"
            assert plan["summary"][0][1].startswith("2, from 1")
            assert plan["summary"][-1] == ["No restart needed", ""]
            # agent1 already reaches notes: no Give to clients, only the gateway's new view.
            wait = {"do": "wait_gateway", "label": "The gateway takes the new view within seconds"}
            assert (saved["revision"], saved["next"]) == (2, [wait])
            wanted = sorted([*allow, *approve])
            wait_for(lambda: served(port) == wanted, "notes served", gateway, running)
        finally:
            gateway.stop()
            made.stop()
    assert [line["action"] for line in events(made.output(), "step_up_confirmed")] == [
        "policy.save"
    ]
    notes = head_policy(opened(made)).gateway
    assert notes is not None
    server = notes.servers[SERVER]
    assert isinstance(server, RemoteServer)
    assert sorted(server.declined) == sorted(
        wire["name"] for wire in base_tools() if wire["name"] not in wanted
    )
    assert API_KEY not in made.output()


def hardened_walk(tmp_path: Path, ca: ProviderCA) -> None:
    """J14h, the hardened tier's portal walk for an OAuth server added by its URL: five prompts,
    each for one thing (register, the Save that adds the server, Connect, the review's Save,
    Give to clients), the vault and the gateway linked over TCP with the gateway key; then the
    agent lists the server's tools. No fragment is shown or committed."""
    # Imported here: test_onboard_shape imports test_mcp_shapes, which imports this module.
    from contextlib import ExitStack
    from urllib.parse import urlsplit

    import httpx

    from tests.fakes.browser import loopback
    from tests.fakes.harness import serve
    from tests.fakes.resolver import FakeResolver
    from tests.gateway.rig import token_for
    from tests.portal.flows import connect_by_callback

    from .conftest import Clock
    from .test_onboard_shape import (
        ALLOWED,
        APPROVED,
        AUTH,
        CLIENT,
        ISSUER,
        MCP,
        SERVER_URL,
        ByName,
        base_policy,
        fakes,
    )
    from .tls import issue_cert

    auth, mcp = fakes(Clock(), registration="open")
    certs = tmp_path / "certs"
    certs.mkdir(mode=0o700)
    resolver = FakeResolver()
    ports: dict[str, int] = {}
    made = vault(tmp_path)
    made.ca = ca.ca_file
    made.hooks = tmp_path / "hooks.json"
    made.policy = {**base_policy(portal_port=made.portal), "mode": "managed"}
    port = free_port()
    passkey = SoftAuthenticator()
    with ExitStack() as stack:
        for name, app, lifespan in ((MCP, mcp.app(), True), (AUTH, auth.app(), False)):
            url = stack.enter_context(
                serve(app, lifespan=lifespan, tls=issue_cert(ca, name, certs))
            )
            ports[name] = int(str(urlsplit(url).port))
            resolver.serve(name, ports[name])
        resolver.save(made.hooks)
        provider = httpx.Client(transport=ByName(ports, ca), base_url=ISSUER, trust_env=False)
        stack.callback(provider.close)
        browser = stack.enter_context(
            Browser(address=loopback, remote={ISSUER: provider}, timeout=60.0)
        )
        page = browser.page(f"http://localhost:{made.portal}")
        running = made.start()
        gateway = gateway_on(made, tmp_path / "gateway-state", port)
        try:
            [seeded] = events(made.output(), "policy_seeded")
            assert (seeded["revision"], seeded["tokens_hashed"], seeded["via"]) == (1, 0, "start")
            assert redeem(page, setup_code(made.state, made.env)).status_code == 200
            assert enrol(page, passkey).status_code == 200
            assert login(page, passkey).status_code == 200
            found = page.fetch("POST", "/api/onboard/discover", json={"url": SERVER_URL})
            assert found.status_code == 200, found.text
            plan = found.json()
            assert plan["next"] == [{"do": "register", "label": "Register its client"}]
            onboarding = plan["onboarding"]
            _, made_client = stepped_up(
                page, passkey, "onboard.register", {"onboarding": onboarding}
            )
            assert "diff" not in made_client
            assert made_client["next"][0]["do"] == "save"
            assert one_row(page)["state"] == "needs_save"
            drafted = page.fetch("POST", f"/api/onboard/{onboarding}/fragment", json={})
            assert drafted.status_code == 200, drafted.text
            draft = drafted.json()
            assert (draft["kind"], draft["base"]) == ("policy.save", 1)
            _, saved = stepped_up(
                page, passkey, "policy.save", {"draft": draft["draft"], "base": 1}
            )
            assert saved["revision"] == 2
            assert one_row(page)["state"] == "needs_connect"
            _, connected = connect_by_callback(page, passkey, SERVER)
            assert connected.status_code == 200, connected.text
            assert one_row(page)["state"] == "needs_review"
            path, _ = portal_review(page, gateway, running, fresh=False)
            choices = {"include": [ALLOWED, APPROVED], "allow": [ALLOWED], "approve": [APPROVED]}
            drafted = page.fetch("POST", f"{path}/diff", json={**choices, "decline_rest": True})
            assert drafted.status_code == 200, drafted.text
            draft = drafted.json()
            assert (draft["kind"], draft["base"]) == ("policy.save", 2)
            data = {"draft": draft["draft"], "base": 2}
            _, reviewed = stepped_up(page, passkey, "policy.save", data)
            assert reviewed["next"][-1]["do"] == "assign_clients"
            assert (one_row(page)["state"], one_row(page)["clients_shown"]) == ("reviewed", [])
            give = {"base": 3, "client": CLIENT, "servers": [SERVER]}
            _, given = stepped_up(page, passkey, "client.servers", give)
            assert given["revision"] == 4
            assert one_row(page)["clients_shown"] == [CLIENT]
            wanted = sorted([ALLOWED, APPROVED])
            token = token_for(CLIENT)
            wait_for(lambda: served(port, token) == wanted, "notes served", gateway, running)
        finally:
            gateway.stop()
            made.stop()
    assert [line["action"] for line in events(made.output(), "step_up_confirmed")] == [
        "onboard.register",
        "policy.save",
        "oauth.complete",
        "policy.save",
        "client.servers",
    ]
    assert opened(made).revision == 4
    assert len(auth.registrations) == 1


@pytest.mark.parametrize("tier", [pytest.param("standard", marks=LINK), "hardened"])
def test_quickstart_managed(tmp_path: Path, ca: ProviderCA, tier: str) -> None:
    """J14, both shipped tiers as processes, prompt for prompt: J14s (the standard tier, the
    vault and the gateway on the link socket) and J14h (the hardened tier, over TCP with the
    gateway key). Each starts from a fresh volume that seeds revision 1 from the compose
    policy."""
    if tier == "standard":
        standard_walk(tmp_path, ca)
    else:
        hardened_walk(tmp_path, ca)


# --- the portal's other saves, each with a passkey (S17; G.3, H.3, J.4) -----------------------

MAIL = {
    "kind": "smtp",
    "host": "smtp.mail.example",
    "port": 465,
    "username": "mail-account-user",
    "password": "store:mail-pass",
    "from": "zoeymcp@mail.example",
    "to": ["ops@mail.example"],
}


def test_saves_of_each_kind(tmp_path: Path, ca: ProviderCA) -> None:
    """S17's saves with a real assertion, as processes: **Allow without asking** on one approve
    tool (``tool.allow``, its definition from the review the vault holds, logged
    ``tool_allowed``), a rollback from the Policy page to the revision before it
    (``policy.rollback``: narrower, so the portal may), and a connector's Pause
    (``connector.limits``), each one passkey prompt and one revision the vault installs. The
    review saves (``policy.save``, ``tool.repin``), ``tool.clear`` and ``client.servers`` are
    walked by J11, J12, J14 and S12's portal rows."""
    fake = McpFake(mode="modern")
    pins = {wire["name"]: pin_of_fake(fake, wire["name"]) for wire in base_tools()}
    made = vault(tmp_path)
    made.ca = ca.ca_file
    port = free_port()
    passkey = SoftAuthenticator()
    with serve_tls(fake.app(), ca, lifespan=True) as upstream, Browser(timeout=60.0) as browser:
        made.policy = {**notes_policy(made.portal, upstream, pins), "connectors": {"mail": MAIL}}
        page = browser.page(f"http://localhost:{made.portal}")
        running = made.start()
        gateway = gateway_on(made, tmp_path / "gateway-state", port)
        try:
            assert redeem(page, setup_code(made.state, made.env)).status_code == 200
            assert enrol(page, passkey).status_code == 200
            assert login(page, passkey).status_code == 200
            portal_review(page, gateway, running)  # the definition the move shows
            moved = {"base": 1, "server": SERVER, "kind": "tool", "name": "echo"}
            plan, allowed = stepped_up(page, passkey, "tool.allow", {**moved, "pin": pins["echo"]})
            assert plan["summary"][0][1].startswith("2, from 1")
            assert allowed["revision"] == 2
            plan, rolled = stepped_up(page, passkey, "policy.rollback", {"base": 2, "revision": 1})
            assert plan["summary"][0][1].startswith("3, from 2: the content of revision 1")
            assert rolled["revision"] == 3
            paused = {"base": 3, "connector": "mail", "paused": True}
            plan, limited = stepped_up(page, passkey, "connector.limits", paused)
            assert ["connectors.mail.paused", "changed"] in plan["summary"]
            assert limited["revision"] == 4
            wait_for(lambda: served(port) == sorted(pins), "notes served", gateway, running)
        finally:
            gateway.stop()
            made.stop()
    assert [line["action"] for line in events(made.output(), "step_up_confirmed")] == [
        "tool.allow",
        "policy.rollback",
        "connector.limits",
    ]
    [line] = events(made.output(), "tool_allowed")
    assert (line["server"], line["name"], line["revision"]) == (SERVER, "echo", 2)
    found = opened(made)
    assert [found.top.header["kind"], found.revision] == ["connector.limits", 4]
    head = head_policy(found)
    assert head.connectors["mail"].paused is True
    notes = head.gateway.servers[SERVER] if head.gateway is not None else None
    assert isinstance(notes, RemoteServer)
    assert notes.tools.allow == []
