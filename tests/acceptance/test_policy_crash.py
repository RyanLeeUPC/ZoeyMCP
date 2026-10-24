"""The managed policy store across a kill, and the starts it refuses (M6 design D.6, D.7, D.9,
N.6; FM-1 to FM-3, FM-25, J16; Y1, Y3, Y4, Y18): real vault processes.

The vault runs in its own interpreter (``procs.py``), killed (SIGKILL) while a hold
(``tests/fakes/policyholds.py``) keeps it between two of a write's steps, then started again:

- a seed killed after its anchor at 0 and its revision 1, before the head, starts fresh again
  under the same deployment, the half-written revision in quarantine (FM-25);
- a write killed after its revision, before the head, leaves the old head running and the file
  in quarantine as uncommitted; its retry is a fresh write (FM-1). The write is the resume a
  managed start makes of a parked store (F.4): the one write a vault makes with no portal or
  socket in front of it;
- a write killed after its head, before the anchor, runs the new head, and the anchor is
  rewritten (FM-2);
- a master-key rotation killed after its first re-sealed revision is refused without the
  previous key, naming the key the files were written under, and finishes with it (FM-3).

Then J16's refusals, each naming its cause and the way out in the host's commands. The stores
are made in this process (``load_runtime``), the way a vault makes them. Linux only: these are
the process crash tests (P.2), and the CI runs them there.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.common.policy.schema import hash_token
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.policyseal import unseal_anchor, unseal_head, unseal_revision
from zoeymcp.vault.policystart import Ok, revision_file
from zoeymcp.vault.policystore import PolicyStore
from zoeymcp.vault.server import load_runtime

from .procs import ManagedVault, managed_policy, wait_file

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the process crash tests run on Linux (M6 design P.2)"
)
HARDENED = "docker compose -f deploy/compose.hardened.yaml"
TOKEN = "managed-client-token-0001"


def events(text: str, name: str) -> list[dict[str, Any]]:
    """The vault's log lines named ``name``, from a process's output."""
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


def keys(made: ManagedVault) -> KeySet:
    return KeySet.from_text(made.env["ZOEYMCP_MASTER_KEY"])


def in_process(made: ManagedVault, mode: str = "managed") -> None:
    """One start of the vault in this process, on its policy in ``mode``: a seed, a park or a
    resume, as F.1 decides."""
    assert made.policy is not None
    made.state.mkdir(mode=0o700, exist_ok=True)
    policy = {**made.policy, "mode": mode}
    load_runtime(None, made.state, {**made.env, "ZOEYMCP_CONFIG": json.dumps(policy)})


def parked(made: ManagedVault) -> None:
    """Revision 1 seeded, then parked by a declarative start: the next managed start resumes,
    writing revision 2."""
    in_process(made)
    in_process(made, "declarative")


def opened(made: ManagedVault) -> Ok:
    found = PolicyStore.open(made.state, keys(made), None).verdict
    assert isinstance(found, Ok), found
    return found


# --- kills (FM-1, FM-2, FM-3, FM-25) ------------------------------------------------------------


def test_kill_during_seed(tmp_path: Path) -> None:
    """FM-25: killed after the anchor at 0 and revision 1, before the head; the next start seeds
    again under the same deployment, the half-written revision 1 in quarantine."""
    made = vault(tmp_path)
    marker = tmp_path / "held"
    process = made.launch(holds={"pause_after_revision": marker})
    wait_file(marker, process)
    made.kill()
    anchor = unseal_anchor((made.state / "policy-anchor.json").read_bytes(), keys(made), None)
    assert (anchor.highest, anchor.parked) == (0, None)
    assert (made.state / revision_file(1)).is_file()
    assert not (made.state / "policy" / "head.json").exists()
    made.start()
    made.stop()
    found = opened(made)
    assert (found.revision, found.head.deployment) == (1, anchor.deployment)
    quarantine = made.state / "policy" / "quarantine"
    assert sorted(path.name for path in quarantine.iterdir()) == ["1.uncommitted.json"]
    output = made.output()
    assert [line["revision"] for line in events(output, "policy_save_uncommitted")] == [1]
    [seeded] = events(output, "policy_seeded")
    assert (seeded["deployment"], seeded["via"]) == (anchor.deployment[:8], "start")
    assert TOKEN not in output
    assert hash_token(TOKEN) not in output


def test_kill_before_head(tmp_path: Path) -> None:
    """FM-1, Y1: a resume killed after revision 2's file, before the head: the next start runs
    revision 1, moves the file to quarantine as uncommitted, and the resume is written again as
    a fresh revision 2."""
    made = vault(tmp_path)
    parked(made)
    marker = tmp_path / "held"
    process = made.launch(holds={"pause_after_revision": marker})
    wait_file(marker, process)
    made.kill()
    held = (made.state / revision_file(2)).read_bytes()
    head = unseal_head((made.state / "policy" / "head.json").read_bytes(), keys(made), None)
    assert head.revision == 1
    made.start()
    made.stop()
    found = opened(made)
    assert found.revision == 2
    assert found.top.header["origin"] == "resume"
    quarantine = made.state / "policy" / "quarantine"
    assert (quarantine / "2.uncommitted.json").read_bytes() == held
    # The retry is a fresh write: its own salt, so its own bytes.
    assert (made.state / revision_file(2)).read_bytes() != held
    output = made.output()
    assert [line["revision"] for line in events(output, "policy_save_uncommitted")] == [2]
    assert [line["revision"] for line in events(output, "policy_resumed")] == [2]


def test_kill_before_anchor(tmp_path: Path) -> None:
    """FM-2: a resume killed after its head, before the anchor: the next start runs revision 2,
    rewrites the anchor (D.6 row 13) and resumes nothing again."""
    made = vault(tmp_path)
    parked(made)
    marker = tmp_path / "held"
    process = made.launch(holds={"pause_after_head": marker})
    wait_file(marker, process)
    made.kill()
    anchor = unseal_anchor((made.state / "policy-anchor.json").read_bytes(), keys(made), None)
    assert (anchor.highest, anchor.parked) == (1, 1)
    made.start()
    made.stop()
    found = opened(made)
    assert (found.revision, found.anchor_stale, found.parked) == (2, False, None)
    anchor = unseal_anchor((made.state / "policy-anchor.json").read_bytes(), keys(made), None)
    assert (anchor.highest, anchor.parked) == (2, None)
    output = made.output()
    assert events(output, "policy_resumed") == []
    assert [line["revision"] for line in events(output, "policy_head")] == [2]


def test_kill_during_rekey(tmp_path: Path) -> None:
    """FM-3: a rotation killed after re-sealing revision 1 under the new key: without the
    previous key the start is refused naming the key the anchor was written under; with it, the
    start finishes the rotation (no digest moved) and records the old key as retired."""
    made = vault(tmp_path)
    parked(made)
    in_process(made)  # the resume: revision 2
    old = made.env["ZOEYMCP_MASTER_KEY"]
    before = opened(made)
    new = generate_master_key()
    made.env = {"ZOEYMCP_MASTER_KEY": new, "ZOEYMCP_MASTER_KEY_PREVIOUS": old}
    marker = tmp_path / "held"
    process = made.launch(holds={"pause_after_revision": marker})
    wait_file(marker, process)
    made.kill()
    current, previous = KeySet.from_text(new), KeySet.from_text(old)
    first = unseal_revision(
        (made.state / revision_file(1)).read_bytes(), current, previous, deployment=None
    )
    second = unseal_revision(
        (made.state / revision_file(2)).read_bytes(), current, previous, deployment=None
    )
    assert (first.key_id, second.key_id) == (current.key_id, previous.key_id)
    made.env = {"ZOEYMCP_MASTER_KEY": new}
    refused = made.refused()
    assert f"was written under master key ID {previous.key_id}" in refused
    assert "set ZOEYMCP_MASTER_KEY_PREVIOUS to the old one and recreate the vault" in refused
    assert [line["reason"] for line in events(refused, "policy_refused")] == ["key_unknown"]
    made.env = {"ZOEYMCP_MASTER_KEY": new, "ZOEYMCP_MASTER_KEY_PREVIOUS": old}
    made.start()
    made.stop()
    [rekeyed] = events(made.output(), "policy_rekeyed")
    assert (rekeyed["revisions"], rekeyed["key_id"]) == (1, current.key_id)
    made.env = {"ZOEYMCP_MASTER_KEY": new}
    after = opened(made)
    assert (after.revision, after.head.digest) == (2, before.head.digest)
    anchor = unseal_anchor((made.state / "policy-anchor.json").read_bytes(), current, None)
    assert (anchor.key_id, anchor.retired_key_id) == (current.key_id, previous.key_id)


# --- J16: the refusals and their way out ---------------------------------------------------------


def recoveries(where: str) -> list[str]:
    """The lines every store refusal ends with (D.6, J16), in the hardened tier's commands."""
    return [
        f"  Restore {where} from one backup, or start from your latest export:",
        f"  {HARDENED} stop vault",
        f"  {HARDENED} run --rm --no-deps -T vault policy import --state {where} --reseed - < "
        "policy-export.yaml",
        f"  {HARDENED} up -d vault",
        "  (Last resort: --reseed --from-env takes your compose policy as it is now, usually "
        "older than the head.)",
    ]


def test_refusals_name_recovery(tmp_path: Path) -> None:
    """J16, Q7 (a), Y3: a head that fails its MAC, an anchor gone beside a store, a store gone
    beside its anchor, and a head whose policy no longer passes check here each refuse the start
    (logged ``policy_refused``), naming the cause and the way out, never falling back to the
    seed; nothing is written."""
    made = vault(tmp_path)
    made.policy = managed_policy(
        made.portal,
        credentials={
            "k": {"kind": "header", "header": "X-Key", "format": "{secret}", "secret": "env:K2"}
        },
    )
    made.env["K2"] = "v"
    in_process(made)
    state = made.state
    where = state.as_posix()
    head = state / "policy" / "head.json"
    anchor = state / "policy-anchor.json"
    good_head, good_anchor = head.read_bytes(), anchor.read_bytes()
    at = good_head.index(b'"mac":"') + len(b'"mac":"')
    flipped = b"1" if good_head[at : at + 1] == b"0" else b"0"
    head.write_bytes(good_head[:at] + flipped + good_head[at + 1 :])
    refused = made.refused()
    assert (
        f"zoeymcp vault: refused to start: {where}/policy/head.json was tampered with, or written "
        "under another master key.\n"
        "  If you rotated the master key, set ZOEYMCP_MASTER_KEY_PREVIOUS to the old one and "
        "recreate the vault.\n"
        "  Otherwise the file was changed outside the vault.\n" + "\n".join(recoveries(where))
    ) in refused
    head.write_bytes(good_head)
    anchor.unlink()
    refused = made.refused()
    assert (
        f"refused to start: {where}/policy holds revisions, but the anchor beside it, "
        f"{where}/policy-anchor.json, is gone.\n" + "\n".join(recoveries(where))
    ) in refused
    anchor.write_bytes(good_anchor)
    (state / revision_file(1)).rename(tmp_path / "revision-1.json")
    head.rename(tmp_path / "head.json")
    refused = made.refused()
    assert (
        f"refused to start: {where}/policy is gone, but this volume held revisions up to 1 "
        f"({where}/policy-anchor.json).\n" + "\n".join(recoveries(where))
    ) in refused
    (tmp_path / "revision-1.json").rename(state / revision_file(1))
    (tmp_path / "head.json").rename(head)
    del made.env["K2"]
    refused = made.refused()
    assert "zoeymcp vault: policy revision 1 fails check (1 error(s)): credentials.k" in refused
    assert "K2" in refused
    reasons = [line["reason"] for line in events(made.output(), "policy_refused")]
    assert reasons == ["tampered", "policy_anchor_missing", "policy_store_missing", "fails_check"]
    assert events(made.output(), "policy_seeded") == []
    made.env["K2"] = "v"
    made.start()
    made.stop()
    assert opened(made).revision == 1
