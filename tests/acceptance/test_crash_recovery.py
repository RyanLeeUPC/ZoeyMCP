"""H10's kills: real processes, killed at each observable point, then restarted (M4 design N.4).

- the vault, while the SMTP fake holds a send's final reply: after a restart the journal closes
  the send ``unknown``, and the key's replay says so without sending again;
- the gateway, while a prompt waits: after a restart the ledger closes the asked call;
- the gateway, while the upstream holds an approved call: the outcome is ``unknown``.

Every ``asked`` ends with exactly one ``outcome``, and the chain verifies.
"""

from __future__ import annotations

import concurrent.futures
import json
import time
from collections import Counter
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


def start_gateway(vault_url: str, state: Path, port: int, log: Path) -> Process:
    argv = [
        "gateway", "--vault", vault_url, "--listen", f"127.0.0.1:{port}",
        "--state", str(state), "--admin-socket", "none",
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
    tmp_path: Path, tool: str, arguments: dict[str, Any], script: Script, ready: Any
) -> tuple[McpFake, Path]:
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
            gateway = start_gateway(deployed.vault_url, state, port, log)
        finally:
            gateway.stop()
    return fake, state


async def test_a_kill_while_a_prompt_waits(tmp_path: Path) -> None:
    script = Script([Answer(delay=3600)])
    fake, state = await kill_while(
        tmp_path, "echo", {"text": "hi"}, script, lambda _fake: bool(script.prompts)
    )
    assert fake.calls == []  # nothing was ever sent
    [records] = closed_exactly_once(state).values()
    assert records[-1]["outcome"] == "not_sent"


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
