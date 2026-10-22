"""The egress role as a process (M7 design I.4, X15, FM-25; O.4's X15 row, N.1's FM-25 row).

``zoeymcp egress`` runs in its own interpreter (``procs.start``), so a kill is a real kill. For
X15's rows it polls the allowlist fake (tests/fakes/allowlist.py) in the test's loop; for FM-25 it
polls a real vault whose SMTP connector sends through it (``egress_proxy_kind: role``, fold-in
R6). Names resolve through the system here, as in a deployment, so the destinations are loopback
servers, listed private where the role must reach them; a name that resolves to loopback and
isn't marked private stands for "a name that resolves private" (the in-process tests,
tests/unit/test_egress_role.py, change the answer between two lookups). Every test bounds itself
with ``anyio.fail_after``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from tests.fakes.allowlist import KEY, AllowlistFake, serve_allowlist
from tests.fakes.smtp_server import PASSWORD, SmtpFake, Switch, serve_smtp
from zoeymcp.common.policy import Policy
from zoeymcp.egress.allowlist import KEY_ENV
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.store import SecretStore

from .procs import Process, free_port, start
from .tls import ProviderCA
from .toolkits import merged

pytestmark = pytest.mark.anyio
# FM-25's two sends' idempotency keys: the one the restart cuts, and one after it.
FIRST, SECOND = "egress-role-key-0001", "egress-role-key-0002"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --- the rig --------------------------------------------------------------------------------------


def records(process: Process) -> list[dict[str, Any]]:
    """The JSON log lines ``process`` has written so far."""
    found = []
    for line in process.output().splitlines():
        if line.startswith("{"):
            found.append(json.loads(line))
    return found


def events(process: Process, kind: str) -> list[dict[str, Any]]:
    return [record for record in records(process) if record.get("event") == kind]


async def logged(process: Process, kind: str, count: int = 1) -> list[dict[str, Any]]:
    """Waits until ``process`` has logged ``kind`` ``count`` times; fails if it exits first."""
    while len(found := events(process, kind)) < count:
        assert process.popen.poll() is None, f"the process exited:\n{process.output()}"
        await asyncio.sleep(0.05)
    return found


async def listening(port: int, process: Process) -> None:
    """Waits until something takes a connection on ``port``."""
    while True:
        assert process.popen.poll() is None, f"the process exited:\n{process.output()}"
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        return


def start_role(log: Path, vault: str, listens: Sequence[str], key: str) -> Process:
    argv = ["egress", "--vault", vault]
    for spec in listens:
        argv += ["--listen", spec]
    return start(argv, env={KEY_ENV: key}, log=log)


def ports(started: dict[str, Any]) -> dict[str, int]:
    """Each source's port, from ``egress_started``'s listener map."""
    return {source: int(bound.rsplit(":", 1)[1]) for source, bound in started["listeners"].items()}


def head(target: str, *, method: str = "CONNECT") -> bytes:
    return f"{method} {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()


def parse_head(raw: bytes) -> tuple[int, dict[str, str]]:
    lines = raw.decode("latin-1").removesuffix("\r\n\r\n").split("\r\n")
    fields = (line.partition(":") for line in lines[1:])
    return int(lines[0].split(" ")[1]), {name.lower(): value.strip() for name, _, value in fields}


@asynccontextmanager
async def tunnel(
    port: int, request: bytes
) -> AsyncIterator[tuple[int, dict[str, str], asyncio.StreamReader, asyncio.StreamWriter]]:
    """``request`` to the role's listener on ``port``: the answer's status and headers, and the
    connection, a tunnel after a 200."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request)
        await writer.drain()
        status, headers = parse_head(await reader.readuntil(b"\r\n\r\n"))
        yield status, headers, reader, writer
    finally:
        writer.close()


async def ask(port: int, request: bytes) -> tuple[int, dict[str, str]]:
    async with tunnel(port, request) as (status, headers, _, _):
        return status, headers


@asynccontextmanager
async def echo_server() -> AsyncIterator[int]:
    """A loopback server that sends back what it receives; yields its port."""

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()


# --- X15 ------------------------------------------------------------------------------------------


async def test_the_role_holds_each_listener_to_its_sources_list(tmp_path: Path) -> None:
    """X15 as a process: no tunnel before the first list; then the listed private literal goes
    through, and a plain-HTTP request, an unlisted host, a listed name that resolves to loopback
    without the private mark, and another source's destination are refused."""
    fake = AllowlistFake()
    role: Process | None = None
    with anyio.fail_after(60):
        async with echo_server() as echo, echo_server() as other, serve_allowlist(fake) as url:
            role = start_role(
                tmp_path / "role.log", url, ("vault=127.0.0.1:0", "fetch=127.0.0.1:0"), KEY
            )
            try:
                [started] = await logged(role, "egress_started")
                port = ports(started)
                # The fake has published nothing: the role has no list, so every tunnel waits.
                assert (await ask(port["vault"], head(f"127.0.0.1:{echo}")))[0] == 503
                fake.publish(
                    {
                        "vault": [("127.0.0.1", echo, True), ("localhost", echo)],
                        "fetch": [("127.0.0.1", other, True)],
                    }
                )
                await logged(role, "egress_allowlist_applied")
                async with tunnel(port["vault"], head(f"127.0.0.1:{echo}")) as found:
                    status, _, reader, writer = found
                    assert status == 200
                    writer.write(b"through the role")
                    await writer.drain()
                    assert await reader.readexactly(16) == b"through the role"
                status, headers = await ask(
                    port["vault"], head(f"http://127.0.0.1:{echo}/", method="GET")
                )
                assert (status, headers["allow"], headers["content-length"]) == (
                    405,
                    "CONNECT",
                    "0",
                )
                assert "www-authenticate" not in headers
                assert "proxy-authenticate" not in headers
                assert (await ask(port["vault"], head("unlisted.example:443")))[0] == 403
                assert (await ask(port["vault"], head(f"localhost:{echo}")))[0] == 403
                # fetch's destination, on the vault's listener: refused; on its own, it goes.
                assert (await ask(port["vault"], head(f"127.0.0.1:{other}")))[0] == 403
                assert (await ask(port["fetch"], head(f"127.0.0.1:{other}")))[0] == 200
                # Both tunnels closed from this side, before the role stops.
                await logged(role, "egress_tunnel", 2)
            finally:
                role.stop()
    refused = [(r["source"], r["reason"]) for r in events(role, "egress_refused")]
    assert refused == [
        ("vault", "list_stale"),
        ("vault", "not_connect"),
        ("vault", "not_allowed"),
        ("vault", "address_refused"),
        ("vault", "not_allowed"),
    ]
    tunnels = [(r["source"], r["port"], r["result"]) for r in events(role, "egress_tunnel")]
    assert sorted(tunnels) == sorted([("vault", echo, "closed"), ("fetch", other, "closed")])
    assert KEY not in role.output()


# --- FM-25 ----------------------------------------------------------------------------------------


def send(port: int, keys: KeySet, idempotency_key: str) -> httpx.Response:
    request = {
        "expect_from": "Agent <agent@mail.example>",
        "expect_to": ["partner@mail.example"],
        "subject": "Through the egress role",
        "body": "Sent once at most.",
    }
    return httpx.post(
        f"http://127.0.0.1:{port}/mail/send",
        headers={
            "x-zoeymcp-gateway": keys.gateway_key(1),
            "idempotency-key": idempotency_key,
            "content-type": "application/json",
        },
        content=json.dumps(request),
        timeout=60,
    )


async def test_restart(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-25: the role restarts. Its open tunnels are cut, so the vault's send in flight fails
    502 and its journal keeps it from being sent again; the new role opens no tunnel before its
    first fetch, then carries the vault's sends again (H15: the SMTP connector through the role's
    vault listener)."""
    fake = SmtpFake(ca, switches={Switch.HANG_AFTER_DOT})
    master = generate_master_key()
    keys = KeySet.from_text(master)
    state = tmp_path / "vault"
    vault: Process | None = None
    role: Process | None = None
    with serve_smtp(fake, tmp_path) as (_, smtp_port):
        vault_port, role_port = free_port(), free_port()
        raw = merged("smtp-implicit-tls.yaml")
        raw["connectors"]["mail-out"].update(host="localhost", port=smtp_port)
        # The profile's commented lines, with the role's address in this test, and the fake's
        # loopback address listed private for the role's connect-time check.
        raw |= {
            "egress_proxy": f"http://127.0.0.1:{role_port}",
            "egress_proxy_kind": "role",
            "egress_private": [f"localhost:{smtp_port}"],
        }
        policy = Policy.model_validate(raw)
        config = tmp_path / "policy.json"
        config.write_bytes(json.dumps(raw).encode())
        store = SecretStore(state, keys)
        store.load()
        store.put("mail-pass", PASSWORD, derive_binding(policy, "mail-pass"))
        vault_argv = [
            "vault", "--config", str(config), "--listen", f"127.0.0.1:{vault_port}",
            "--state", str(state), "--admin-socket", "none",
        ]  # fmt: skip
        vault_env = {"ZOEYMCP_MASTER_KEY": master}
        role_args = (f"http://127.0.0.1:{vault_port}", (f"vault=127.0.0.1:{role_port}",))
        role_key = keys.egress_key(policy.egress_key_generation)
        try:
            with anyio.fail_after(150):
                vault = start(vault_argv, env=vault_env, log=tmp_path / "vault.log", ca=ca.ca_file)
                role = start_role(tmp_path / "role-1.log", *role_args, role_key)
                await listening(vault_port, vault)
                await logged(role, "egress_allowlist_applied")
                pending = asyncio.create_task(
                    anyio.to_thread.run_sync(send, vault_port, keys, FIRST)
                )
                while not fake.messages:  # the fake holds its reply to the final dot
                    assert not pending.done(), vault.output()
                    await asyncio.sleep(0.05)
                await anyio.to_thread.run_sync(role.kill)
                cut = await pending
                assert (cut.status_code, cut.json()["code"]) == (502, "smtp_outcome_unknown")

                # A new role while the vault is down: no list, so no tunnel.
                await anyio.to_thread.run_sync(vault.stop)
                first = role
                role = start_role(tmp_path / "role-2.log", *role_args, role_key)
                [started] = await logged(role, "egress_started")
                stale = head(f"localhost:{smtp_port}")
                assert (await ask(ports(started)["vault"], stale))[0] == 503
                vault = start(vault_argv, env=vault_env, log=tmp_path / "vault.log", ca=ca.ca_file)
                await listening(vault_port, vault)
                await logged(role, "egress_allowlist_applied")

                replay = await anyio.to_thread.run_sync(send, vault_port, keys, FIRST)
                assert (replay.status_code, replay.json()["code"]) == (502, "smtp_outcome_unknown")
                assert replay.headers["x-zoeymcp-replayed"] == "1"
                assert len(fake.messages) == 1  # sent once; never again
                fake.switches.discard(Switch.HANG_AFTER_DOT)
                fresh = await anyio.to_thread.run_sync(send, vault_port, keys, SECOND)
                assert fresh.status_code == 200, fresh.text
                assert len(fake.messages) == 2
                [through] = await logged(role, "egress_tunnel")
        finally:
            for process in (role, vault):
                if process is not None:
                    process.stop()
    assert (through["source"], through["host"], through["port"]) == (
        "vault",
        "localhost",
        smtp_port,
    )
    assert through["result"] == "closed"
    refused = [(r["source"], r["reason"]) for r in events(role, "egress_refused")]
    assert refused == [("vault", "list_stale")]
    journal = [
        json.loads(line)
        for path in sorted((state / "connectors" / "mail-out").glob("journal-*.jsonl"))
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert [(r["kind"], r.get("phase")) for r in journal] == [
        ("sending", None),
        ("unknown", "final_reply"),
        ("sending", None),
        ("sent", None),
    ]
    for process in (first, role, vault):  # the vault's two runs share vault.log
        assert role_key not in process.output()
