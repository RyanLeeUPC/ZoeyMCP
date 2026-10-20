"""The portal's journey against a real ``zoeymcp vault`` process (M5 design O.5).

Begun in step 11: the first visit (a setup code issued with ``zoeymcp setup-code``, redeemed,
a passkey enrolled, the login with it), the session list and logout, and a restart, which ends
every session while the passkey still signs in. Later steps add a secret, a connect and the
ledger view, over both links.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import SESSION_KEY, Browser, Page
from zoeymcp.vault.keys import generate_master_key

from .procs import PASSED, Process, free_port, start, wait_port

STARTUP_TIMEOUT = 30.0


@contextmanager
def portal(tmp_path: Path) -> Iterator[tuple[str, Path, dict[str, str], Process]]:
    """A vault with an ``admin`` block and no admin socket, as on a host without one."""
    state = tmp_path / "state"
    if not state.exists():
        state.mkdir(mode=0o700)
    port_file = tmp_path / "ports.json"
    if port_file.exists():
        ports = json.loads(port_file.read_text(encoding="utf-8"))
    else:
        ports = {"portal": free_port(), "proxy": free_port()}
        port_file.write_text(json.dumps(ports), encoding="utf-8")
    origin = f"http://localhost:{ports['portal']}"
    policy = {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": f"127.0.0.1:{ports['portal']}", "origins": [origin]},
    }
    config = tmp_path / "policy.json"
    config.write_text(json.dumps(policy), encoding="utf-8")
    key_file = tmp_path / "master.key"
    if not key_file.exists():
        key_file.write_text(generate_master_key(), encoding="utf-8")
    env = {"ZOEYMCP_MASTER_KEY": key_file.read_text(encoding="utf-8")}
    argv = [
        "vault",
        "--config",
        str(config),
        "--listen",
        f"127.0.0.1:{ports['proxy']}",
        "--state",
        str(state),
        "--admin-socket",
        "none",
    ]
    log = tmp_path / f"vault-{len(list(tmp_path.glob('vault-*.log')))}.log"
    vault = start(argv, env=env, log=log)
    try:
        wait_port(ports["portal"], vault, STARTUP_TIMEOUT)
        yield origin, state, env, vault
    finally:
        vault.stop()


def setup_code(state: Path, env: dict[str, str]) -> str:
    """``zoeymcp setup-code --state DIR``, the offline form, in its own process."""
    environment = {name: os.environ[name] for name in PASSED if name in os.environ}
    environment.update(env)
    done = subprocess.run(  # noqa: S603 - our own interpreter and arguments
        [sys.executable, "-m", "zoeymcp.cli.main", "setup-code", "--state", str(state)],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return done.stdout.strip()


def keep(page: Page, answer: dict[str, object]) -> None:
    page.storage[SESSION_KEY] = str(answer["token"])


def log_events(vault: Process, event: str) -> list[dict[str, object]]:
    lines = [line for line in vault.output().splitlines() if line.startswith("{")]
    return [entry for entry in map(json.loads, lines) if entry.get("event") == event]


def sign_in(page: Page, authenticator: SoftAuthenticator) -> None:
    begun = page.fetch("POST", "/api/login/begin", json={}).json()
    assertion = authenticator.get(begun["options"], page.origin)
    body = {"ceremony": begun["ceremony"], "credential": assertion.body()}
    finished = page.fetch("POST", "/api/login/finish", json=body)
    assert finished.status_code == 200, finished.text
    keep(page, finished.json())


def test_the_first_visit_and_a_restart(tmp_path: Path) -> None:
    authenticator = SoftAuthenticator()
    with Browser() as browser, portal(tmp_path) as (origin, state, env, vault):
        assert browser.navigate(origin + "/").status_code == 200
        assert [e["hint"] for e in log_events(vault, "setup_pending")] == [
            "run zoeymcp setup-code in the vault's container"
        ]
        page = browser.page(origin)
        code = setup_code(state, env)
        redeemed = page.fetch("POST", "/api/setup/redeem", json={"code": code})
        assert redeemed.status_code == 200, redeemed.text
        keep(page, redeemed.json())
        begun = page.fetch("POST", "/api/passkeys/enrol/begin", json={"name": "laptop"}).json()
        attestation = authenticator.create(begun["options"], origin)
        body = {"ceremony": begun["ceremony"], "credential": attestation.body()}
        enrolled = page.fetch("POST", "/api/passkeys/enrol/finish", json=body)
        assert enrolled.status_code == 200, enrolled.text
        fingerprint = enrolled.json()["passkey"]["fingerprint"]
        sign_in(page, authenticator)
        assert page.fetch("GET", "/api/session").json()["credential"] == fingerprint
        assert [s["this"] for s in page.fetch("GET", "/api/sessions").json()["sessions"]] == [True]
        deadline = time.monotonic() + 10
        while not log_events(vault, "passkey_enrolled"):
            assert time.monotonic() < deadline
            time.sleep(0.05)
        assert code not in vault.output()
        old_token = page.storage[SESSION_KEY]
    # A restart ends every session; the passkey file keeps the passkey.
    with Browser() as browser, portal(tmp_path) as (origin, state, env, vault):
        page = browser.page(origin)
        page.storage[SESSION_KEY] = old_token
        assert page.fetch("GET", "/api/session").status_code == 401
        assert log_events(vault, "setup_pending") == []  # a passkey can sign in
        sign_in(page, authenticator)
        assert page.fetch("GET", "/api/session").json()["credential"] == fingerprint
        out = page.fetch("POST", "/api/logout", json={})
        assert out.headers["clear-site-data"] == '"storage"'
        assert page.fetch("GET", "/api/session").status_code == 401
