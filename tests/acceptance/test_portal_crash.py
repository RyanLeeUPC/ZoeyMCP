"""The portal's state across kills and restarts (M5 design N, O.5, P22).

Real ``zoeymcp vault`` processes, killed with SIGKILL (TerminateProcess on Windows), so nothing
in them finishes the work; every wait is on the port, a log event or a file, never a sleep.

- killed after an enrolment's answer: after a restart that passkey signs in;
- killed after a code's redemption: after a restart the code is refused;
- killed with a session and a step-up action pending: after a restart the session is gone and
  the action ran nothing;
- killed while the gateway's reporter pushes 10,000 records, the copy's last file ending in
  half a line, as a kill in the middle of an append leaves it: the restart repairs it, the
  reporter resumes, and the copy holds every record once, chained, its head the gateway's own;
- an older ``passkeys.json`` restored while stopped: the passkey removed since signs in again,
  and ``passkeys_loaded`` shows the lower generation (D-62).
"""

from __future__ import annotations

import json
import shutil
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Browser, Page
from tests.portal.flows import enrol, redeem
from zoeymcp.common import ledgerformat, ledgerreport
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.gateway.ledger import LEDGER_DIR, ROTATE_BYTES, Ledger
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.reportstore import REPORTED_DIR

from .procs import Process, free_port, start, wait_port
from .test_portal_shapes import log_events, portal, setup_code, sign_in

RECORDS = 10_002  # 3,334 calls, each asked, decided and closed
WAIT = 90.0


def wait_until(condition: Callable[[], bool], what: str, timeout: float = WAIT) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, what
        time.sleep(0.05)


def first_visit(page: Page, passkey: SoftAuthenticator, state: Path, env: dict[str, str]) -> str:
    """A code issued offline, redeemed, a passkey enrolled; returns its fingerprint."""
    assert redeem(page, setup_code(state, env)).status_code == 200
    enrolled = enrol(page, passkey)
    assert enrolled.status_code == 200, enrolled.text
    fingerprint: str = enrolled.json()["passkey"]["fingerprint"]
    return fingerprint


# --- passkeys, setup codes, sessions and actions ------------------------------------------------


def test_a_kill_after_an_enrolment_answer_keeps_the_passkey(tmp_path: Path) -> None:
    """The passkey file is written before the enrolment answers (N.2): a kill right after the
    answer loses nothing."""
    passkey = SoftAuthenticator()
    with Browser() as browser, portal(tmp_path) as (origin, state, env, vault):
        fingerprint = first_visit(browser.page(origin), passkey, state, env)
        vault.kill()
    with Browser() as browser, portal(tmp_path) as (origin, _, _, vault):
        page = browser.page(origin)
        sign_in(page, passkey)
        assert page.fetch("GET", "/api/session").json()["credential"] == fingerprint
        [loaded] = log_events(vault, "passkeys_loaded")
        assert loaded["count"] == 1


def test_a_kill_after_a_redemption_spends_the_code(tmp_path: Path) -> None:
    """The record is deleted and its directory synced before the setup session is minted
    (N.2): a code redeemed once is never redeemed again, a kill in between or not."""
    with Browser() as browser, portal(tmp_path) as (origin, state, env, vault):
        code = setup_code(state, env)
        assert redeem(browser.page(origin), code).status_code == 200
        vault.kill()
    assert not (tmp_path / "state" / "setup.json").exists()
    with Browser() as browser, portal(tmp_path) as (origin, _, _, vault):
        again = redeem(browser.page(origin), code)
        assert (again.status_code, again.json()["reason"]) == (401, "setup_code_refused")
        assert [e["hint"] for e in log_events(vault, "setup_pending")]  # still no passkey


def test_a_kill_ends_every_session_and_runs_no_pending_action(tmp_path: Path) -> None:
    """Sessions, ceremonies and actions live in memory (N.1): after a kill and a restart the
    old session's halves are refused, and the action prepared before it, confirmed with a good
    assertion, runs nothing."""
    passkey = SoftAuthenticator()
    data: dict[str, Any] = {
        "name": "held-value",
        "value": "crash-held-value-0001",
        "origins": ["https://x.example"],
    }
    with Browser() as browser:  # one browser throughout: its cookie and header half stay
        with portal(tmp_path) as (origin, state, env, vault):
            page = browser.page(origin)
            first_visit(page, passkey, state, env)
            sign_in(page, passkey)
            held = page.fetch("POST", "/api/actions", json={"kind": "secret.put", "data": data})
            assert held.status_code == 200, held.text
            assertion = passkey.get(held.json()["options"], origin).body()
            vault.kill()
        with portal(tmp_path) as (_, _, _, vault):
            assert page.fetch("GET", "/api/session").status_code == 401
            sign_in(page, passkey)
            path = f"/api/actions/{held.json()['action']}/confirm"
            late = page.fetch("POST", path, json={"credential": assertion})
            assert (late.status_code, late.json()["reason"]) == (404, "action_unknown")
            assert page.fetch("GET", "/api/secrets").json()["secrets"] == []
            assert log_events(vault, "step_up_confirmed") == []
    assert data["value"] not in vault.output()


def test_an_older_passkey_file_brings_a_removed_passkey_back(tmp_path: Path) -> None:
    """D-62, pinned: restoring a backup of ``passkeys.json`` restores what it held, a passkey
    removed since included, and ``passkeys_loaded`` shows the generation going back."""
    laptop, phone = SoftAuthenticator(), SoftAuthenticator()
    passkeys = tmp_path / "state" / "portal" / "passkeys.json"
    backup = tmp_path / "passkeys.backup.json"
    with Browser() as browser, portal(tmp_path) as (origin, state, env, vault):
        first_visit(browser.page(origin), laptop, state, env)
        phone_fp = first_visit(browser.tab(origin), phone, state, env)  # a second code, enrolled
        shutil.copyfile(passkeys, backup)
        page = browser.page(origin)
        sign_in(page, laptop)
        held = page.fetch(
            "POST",
            "/api/actions",
            json={"kind": "passkey.remove", "data": {"credential": phone_fp}},
        )
        assert held.status_code == 200, held.text
        assertion = laptop.get(held.json()["options"], origin).body()
        path = f"/api/actions/{held.json()['action']}/confirm"
        assert page.fetch("POST", path, json={"credential": assertion}).status_code == 200
    with portal(tmp_path) as (_, _, _, vault):
        [removed] = log_events(vault, "passkeys_loaded")
    assert removed["count"] == 1
    shutil.copyfile(backup, passkeys)  # restored while the vault is stopped
    with Browser() as browser, portal(tmp_path) as (origin, _, _, vault):
        [restored] = log_events(vault, "passkeys_loaded")
        page = browser.page(origin)
        sign_in(page, phone)
        assert page.fetch("GET", "/api/session").json()["credential"] == phone_fp
    assert restored["count"] == 2
    newer, older = removed["generation"], restored["generation"]
    assert isinstance(newer, int)
    assert isinstance(older, int)
    assert older < newer


# --- the report path ----------------------------------------------------------------------------


def call_records(count: int, ts: int) -> list[bytes]:
    """``count`` records, complete calls (asked, decided, outcome), as one chain from seq 0."""
    lines: list[bytes] = []
    prev = GENESIS
    for seq in range(count):
        ref = f"{seq // 3:016x}"
        kind, fields = [
            ("asked", ASKED),
            ("decided", {"decision": "accept", "waited_ms": 812}),
            ("outcome", {"outcome": "ok", "detail": None, "writes_sent": 1, "writes_unknown": 0}),
        ][seq % 3]
        line = ledgerformat.encode(kind, seq=seq, prev=prev, ts=ts + seq, ref=ref, **fields)  # type: ignore[arg-type]
        lines.append(line)
        prev = line_hash(line)
    return lines


ASKED: dict[str, Any] = {
    "client": "agent1",
    "server": "mail",
    "tool": "send_note",
    "where": "gateway",
    "era": "modern",
    "args": "hmac-sha256:" + "1" * 64,
    "pin": "sha256:" + "2" * 64,
    "text": "hmac-sha256:" + "1" * 64,
    "chars": 10,
    "writes": 1,
    "expires": 1,
}


def write_ledger(state: Path, lines: list[bytes]) -> None:
    """The gateway's ledger as it writes it: files named by their first seq, rotated at
    ``ROTATE_BYTES``. Every call is closed, so its recovery appends nothing."""
    folder = state / LEDGER_DIR
    folder.mkdir(mode=0o700, parents=True)
    chunk: list[bytes] = []
    first = 0
    for seq, line in enumerate(lines):
        if chunk and sum(map(len, chunk)) + len(line) > ROTATE_BYTES:
            (folder / f"{first:012d}.jsonl").write_bytes(b"".join(chunk))
            chunk, first = [], seq
        chunk.append(line)
    (folder / f"{first:012d}.jsonl").write_bytes(b"".join(chunk))


def copy_head(port: int, keys: KeySet) -> int | None:
    """The copy's head seq, as the gateway asks for it; None while the vault is down."""
    try:
        answer = httpx.get(
            f"http://127.0.0.1:{port}{ledgerreport.PATH}",
            headers={"x-zoeymcp-gateway": keys.gateway_key(1)},
            timeout=10,
        )
    except httpx.HTTPError:
        return None
    seq: int | None = answer.json().get("head_seq") if answer.status_code == 200 else None
    return seq


def copied(state: Path) -> list[bytes]:
    folder = state / REPORTED_DIR
    return [
        line
        for path in sorted(folder.glob("*.jsonl"))
        for line in path.read_bytes().splitlines(keepends=True)
    ]


def test_a_kill_mid_report_is_repaired_and_the_copy_completes(tmp_path: Path) -> None:
    """J.4, N.1: the vault killed while the reporter pushes 10,000 records, the copy's last
    file then given half of the next record, as a kill in the middle of the next batch's append
    leaves it (the lines the copy answered for are fsynced first, N.2). The restart cuts the
    torn tail aside and rebuilds the head before listening; the reporter resumes; the copy ends
    with every record once, in order, chained, and its head is the one the gateway's ``zoeymcp
    ledger --verify`` reports (its admin route answers ``Ledger.verify()``)."""
    lines = call_records(RECORDS, int(time.time() * 1000) - 60_000)
    gateway_state = tmp_path / "gateway-state"
    gateway_state.mkdir(mode=0o700)
    write_ledger(gateway_state, lines)
    vault_state = tmp_path / "vault-state"
    vault_state.mkdir(mode=0o700)
    config = tmp_path / "policy.json"
    config.write_text(json.dumps({"version": 1, "mode": "declarative"}), encoding="utf-8")
    port, gateway_port = free_port(), free_port()
    argv = [
        "vault", "--config", str(config), "--listen", f"127.0.0.1:{port}",
        "--state", str(vault_state), "--admin-socket", "none",
    ]  # fmt: skip
    master = generate_master_key()
    keys = KeySet.from_text(master)
    env = {"ZOEYMCP_MASTER_KEY": master}
    log = tmp_path / "vault.log"
    vault: Process = start(argv, env=env, log=log)
    gateway: Process | None = None
    try:
        wait_port(port, vault)
        gateway_argv = [
            "gateway", "--vault", f"http://127.0.0.1:{port}", "--listen",
            f"127.0.0.1:{gateway_port}", "--state", str(gateway_state), "--admin-socket", "none",
        ]  # fmt: skip
        gateway_env = {"ZOEYMCP_GATEWAY_KEY": keys.gateway_key(1)}
        gateway = start(gateway_argv, env=gateway_env, log=tmp_path / "gateway.log")
        wait_until(lambda: bool(copied(vault_state)), "the first report")
        vault.kill()
        held = copied(vault_state)
        assert len(held) < RECORDS, "the stream finished before the kill"
        newest = sorted((vault_state / REPORTED_DIR).glob("*.jsonl"))[-1]
        torn = lines[len(held)][: len(lines[len(held)]) // 2]
        newest.write_bytes(newest.read_bytes() + torn)
        vault = start(argv, env=env, log=log)
        wait_port(port, vault)
        wait_until(lambda: copy_head(port, keys) == RECORDS - 1, "the copy's head at the gateway's")
    finally:
        if gateway is not None:
            gateway.stop()
        vault.stop()
    output = vault.output()
    assert '"event":"ledger_reported_repaired"' in output
    held = copied(vault_state)
    assert [ledgerformat.parse(line).seq for line in held] == list(range(RECORDS))
    verified = ledgerformat.verify(held, prev=GENESIS, seq=0)
    assert (verified.broken_at, verified.records) == (None, RECORDS)
    ledger, _ = Ledger.open_at(gateway_state, max_bytes=2**30)
    assert ledger.verify() == {
        "records": RECORDS,
        "head_seq": RECORDS - 1,
        "head_hash": verified.head_hash,
        "broken_at": None,
        "ok": True,
    }
    assert list(vault_state.joinpath(REPORTED_DIR).glob("torn-*.bin"))  # the cut, kept aside
    # No ledger line reached the vault's log (M.4).
    for line in (lines[0], lines[-1]):
        assert line.decode().strip() not in output
