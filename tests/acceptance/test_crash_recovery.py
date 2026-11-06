"""H10's kills: real processes, killed at each observable point, then restarted (M4 design N.4).

- the vault, while the SMTP fake holds a send's final reply: after a restart the journal closes
  the send ``unknown``, and the key's replay says so without sending again;
- the gateway, while a prompt waits: after a restart the ledger closes the asked call, and
  ``zoeymcp ledger --verify`` over the restarted gateway's admin socket says the chain is whole
  (D-77's last row; the admin socket is a Unix socket, so that half runs where there is one);
- the gateway, while the upstream holds an approved call: the outcome is ``unknown``.

Every ``asked`` ends with exactly one ``outcome``, and the chain verifies.
"""

from __future__ import annotations

import concurrent.futures
import io
import json
import sys
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from tests.fakes.agent import ACCEPT, Answer, Script, agent
from tests.fakes.mcp_server import McpFake
from tests.fakes.smtp_server import PASSWORD, SmtpFake, Switch, serve_smtp
from tests.gateway.rig import KEYS, deployment, token_for
from tests.gateway.test_upstream import review
from zoeymcp.cli.main import main
from zoeymcp.common import ledgerformat
from zoeymcp.common.policy import Policy
from zoeymcp.gateway.ledger import LEDGER_DIR, Ledger
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.store import SecretStore

from .procs import Process, free_port, start, wait_port
from .tls import ProviderCA
from .toolkits import merged

pytestmark = pytest.mark.anyio
KEY = "crash-key-0001-abcdef"
TOOLS = ["echo", "add", "slow"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --- the vault ----------------------------------------------------------------------------------


def send(port: int, keys: KeySet) -> httpx.Response:
    request = {
        "expect_from": "Agent <agent@mail.example>",
        "expect_to": ["partner@mail.example"],
        "subject": "Crash test",
        "body": "Sent once at most.",
    }
    return httpx.post(
        f"http://127.0.0.1:{port}/mail/send",
        headers={
            "x-zoeymcp-gateway": keys.gateway_key(1),
            "idempotency-key": KEY,
            "content-type": "application/json",
        },
        content=json.dumps(request),
        timeout=120,
    )


def test_a_send_cut_by_a_kill_is_unknown_and_never_sent_again(
    tmp_path: Path, ca: ProviderCA
) -> None:
    fake = SmtpFake(ca, switches={Switch.HANG_AFTER_DOT})
    master = generate_master_key()
    keys = KeySet.from_text(master)
    state = tmp_path / "vault"
    with serve_smtp(fake, tmp_path) as (_, smtp_port):
        raw = merged("smtp-implicit-tls.yaml")
        raw["connectors"]["mail-out"].update(host="localhost", port=smtp_port)
        config = tmp_path / "policy.json"
        config.write_text(json.dumps(raw), encoding="utf-8")
        store = SecretStore(state, keys)
        store.load()
        store.put("mail-pass", PASSWORD, derive_binding(Policy.model_validate(raw), "mail-pass"))
        port = free_port()
        argv = [
            "vault", "--config", str(config), "--listen", f"127.0.0.1:{port}",
            "--state", str(state), "--admin-socket", "none",
        ]  # fmt: skip
        log = tmp_path / "vault.log"
        env = {"ZOEYMCP_MASTER_KEY": master}
        vault: Process = start(argv, env=env, log=log, ca=ca.ca_file)
        try:
            wait_port(port, vault)
            with concurrent.futures.ThreadPoolExecutor(1) as pool:
                pending = pool.submit(send, port, keys)
                deadline = time.monotonic() + 30
                while not fake.messages:  # the fake holds the final reply
                    assert time.monotonic() < deadline, vault.output()
                    time.sleep(0.05)
                vault.kill()
                with pytest.raises(httpx.HTTPError):
                    pending.result(30)
            vault = start(argv, env=env, log=log, ca=ca.ca_file)
            wait_port(port, vault)
            replay = send(port, keys)
        finally:
            vault.stop()
    assert (replay.status_code, replay.json()["code"]) == (502, "smtp_outcome_unknown")
    assert replay.headers["x-zoeymcp-replayed"] == "1"
    assert len(fake.messages) == 1  # sent once; never again
    journal = [
        json.loads(line)
        for path in sorted((state / "connectors" / "mail-out").glob("journal-*.jsonl"))
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert [(r["kind"], r.get("phase")) for r in journal] == [
        ("sending", None),
        ("unknown", "vault_restarted"),
    ]
    assert "connector_journal_recovered" in vault.output()


# --- the gateway --------------------------------------------------------------------------------


def start_gateway(
    vault_url: str, state: Path, port: int, log: Path, admin: Path | None = None
) -> Process:
    argv = [
        "gateway", "--vault", vault_url, "--listen", f"127.0.0.1:{port}",
        "--state", str(state), "--admin-socket", "none" if admin is None else str(admin),
    ]  # fmt: skip
    process = start(argv, env={"ZOEYMCP_GATEWAY_KEY": KEYS.gateway_key(1)}, log=log)
    wait_port(port, process)
    deadline = time.monotonic() + 30
    while httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=5).status_code != 200:
        assert time.monotonic() < deadline, process.output()
        time.sleep(0.1)
    return process


def closed_exactly_once(state: Path) -> dict[str, list[dict[str, Any]]]:
    """Every ref's records; asserts each ``asked`` has exactly one ``outcome`` and the chain is
    whole. Run with the gateway stopped."""
    ledger, _ = Ledger.open_at(state, max_bytes=2**20)
    assert ledger.verify()["ok"] is True
    records = [
        ledgerformat.parse(line)
        for path in sorted((state / LEDGER_DIR).glob("*.jsonl"))
        for line in path.read_bytes().splitlines()
    ]
    asked = Counter(r.ref for r in records if r.kind == "asked")
    outcomes = Counter(r.ref for r in records if r.kind == "outcome")
    assert asked
    assert all(outcomes[ref] == 1 for ref in asked), (asked, outcomes)
    by_ref: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if record.ref is not None:
            by_ref.setdefault(record.ref, []).append({"kind": record.kind, **record.fields})
    return by_ref


async def kill_while(
    tmp_path: Path,
    tool: str,
    arguments: dict[str, Any],
    script: Script,
    ready: Any,
    *,
    admin: Path | None = None,
    restarted: Callable[[], None] | None = None,
) -> tuple[McpFake, Path]:
    """The gateway killed once ``ready`` holds for the call in flight, then restarted on the same
    state, with its admin socket at ``admin`` (none by default); ``restarted`` runs while the
    restarted gateway does."""
    fake = McpFake()
    options = {
        "include": TOOLS,
        "review": review(fake),
        "approve": ["echo", "slow"],
        "approvals": {"agent1": {"attended": True}},
    }
    state = tmp_path / "gateway-state"
    port = free_port()
    log = tmp_path / "gateway.log"
    with deployment(tmp_path, fake, **options) as deployed:
        gateway = start_gateway(deployed.vault_url, state, port, log)
        try:

            async def call() -> None:
                url = f"http://127.0.0.1:{port}/s/notes/mcp"
                headers = {"authorization": f"Bearer {token_for('agent1')}"}
                try:
                    async with agent(
                        url, version="2025-11-25", script=script, headers=headers
                    ) as client:
                        await client.call_tool(tool, arguments)
                except Exception:  # the gateway died under the call
                    return

            async with anyio.create_task_group() as group:
                group.start_soon(call)
                with anyio.fail_after(30):
                    while not ready(fake):
                        await anyio.sleep(0.05)
                gateway.kill()
                group.cancel_scope.cancel()
            gateway = start_gateway(deployed.vault_url, state, port, log, admin)
            if restarted is not None:
                restarted()
        finally:
            gateway.stop()
    return fake, state


def ledger_cli(admin: Path, *argv: str) -> tuple[int, str, str]:
    """``zoeymcp ledger <argv>`` over the gateway's admin socket at ``admin``."""
    out, err = io.StringIO(), io.StringIO()
    code = main(["ledger", *argv, "--socket", str(admin)], stdin=io.StringIO(), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


async def test_a_kill_while_a_prompt_waits(tmp_path: Path) -> None:
    """The prompt's ``asked`` is closed ``not_sent`` by the restart's recovery. Where there is a
    Unix admin socket, the operator's ``ledger --verify`` over the restarted gateway's says the
    chain is whole, and ``ledger`` lists the call closed (D-77)."""
    script = Script([Answer(delay=3600)])
    admin = None
    said: list[tuple[int, str, str]] = []
    if sys.platform != "win32":
        admin = tmp_path / "admin" / "gateway.sock"
        admin.parent.mkdir(mode=0o700)

    def check() -> None:
        assert admin is not None
        deadline = time.monotonic() + 10
        while not admin.exists():  # served beside the agents' listener, which is up
            assert time.monotonic() < deadline, "the admin socket never appeared"
            time.sleep(0.05)
        said.append(ledger_cli(admin, "--verify"))
        said.append(ledger_cli(admin))

    fake, state = await kill_while(
        tmp_path,
        "echo",
        {"text": "hi"},
        script,
        lambda _fake: bool(script.prompts),
        admin=admin,
        restarted=check if admin is not None else None,
    )
    assert fake.calls == []  # nothing was ever sent
    [(ref, records)] = closed_exactly_once(state).items()
    assert records[-1]["outcome"] == "not_sent"
    if admin is not None:
        (code, verified, err), (listed_code, listed, _) = said
        assert (code, err) == (0, ""), verified
        # asked, then the recovery's decided abandoned, outcome not_sent and recovered
        assert verified.startswith("ok: 4 records chain; head seq 3, hash sha256:"), verified
        assert listed_code == 0
        [line, recovered] = listed.splitlines()
        assert line.endswith(f"{ref} agent1 notes/echo legacy abandoned not_sent (restart)"), line
        assert recovered.endswith("ledger recovered abandoned=1 not_sent=1 unknown=0")


async def test_a_kill_while_the_upstream_holds_an_approved_call(tmp_path: Path) -> None:
    _fake, state = await kill_while(
        tmp_path,
        "slow",
        {"steps": 200, "interval": 0.1},
        Script([ACCEPT]),
        lambda found: any(c.name == "slow" for c in found.calls),
    )
    [records] = closed_exactly_once(state).values()
    assert [r["kind"] for r in records] == ["asked", "decided", "outcome"]
    assert records[1]["decision"] == "accept"
    assert records[-1]["outcome"] == "unknown"
