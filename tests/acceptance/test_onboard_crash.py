"""Onboarding by URL across a vault restart (M7 design N, FM-1, FM-2; PC-4): real processes.

The vault runs as its own process (``procs.py``), its guarded clients answering names from the
fake resolver's map, and the fakes serve over TLS on loopback. It is killed (SIGKILL) at each
point and started again:

- after discovery, before registration: the onboarding is gone, and the same command
  rediscovers (FM-1);
- after a given confidential client's secret was stored and fragment 1 shown: the onboarding is
  gone, the secret stays in the store under the predicted binding, which the fragment, merged
  into the policy, derives (FM-2); health reports the entry unreferenced until then, and the
  same command shows fragment 1 again without storing anything (D.7 step 6);
- before the register request is sent, the store holds nothing; once the secret's write has
  returned and before the answer (held there by the hooks file's ``pause_after_put``), the
  store holds that secret under the predicted binding, and nothing else.

The admin socket is a Unix socket, so these run where one exists.
"""

from __future__ import annotations

import concurrent.futures
import json
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from tests.fakes.oauth_server import FakeAuthServer
from tests.fakes.resolver import FakeResolver
from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.policy.merge import Merged, merge
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault.admin import socket_supported
from zoeymcp.vault.bindings import derive_binding, oauth_binding
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.store import SecretStore

from .procs import Process, free_port, start, wait_port
from .tls import ProviderCA, issue_cert

pytestmark = pytest.mark.skipif(not socket_supported(), reason="the admin socket is a Unix socket")

MCP = "mcp.notes.example"
AUTH = "auth.notes.example"
SERVER_URL = f"https://{MCP}/mcp"
ISSUER = f"https://{AUTH}"
CLIENT_ID = "notes-given-client"
SECRET = "onboard-crash-secret-0001"
SECRET_NAME = "notes-client-secret"
CONFIDENTIAL = {"url": SERVER_URL, "client_id": CLIENT_ID, "issuer": ISSUER, "secret_given": True}
PUBLIC = {"url": SERVER_URL, "client_id": CLIENT_ID, "name": "pub"}
POLICY: dict[str, Any] = {"version": 1, "mode": "declarative", "gateway": {}}


@dataclass
class Deployment:
    """A vault process and what it needs to start again."""

    argv: list[str]
    env: dict[str, str]
    log: Path
    ca: Path
    hooks: Path
    port: int
    socket: Path
    state: Path
    master: str
    process: Process | None = None

    def start(self) -> None:
        self.process = start(self.argv, env=self.env, log=self.log, ca=self.ca, hooks=self.hooks)
        wait_port(self.port, self.process)
        deadline = time.monotonic() + 30
        while not self.socket.exists():
            assert time.monotonic() < deadline, self.process.output()
            time.sleep(0.05)

    def kill(self) -> None:
        assert self.process is not None
        self.process.kill()

    def stop(self) -> None:
        if self.process is not None:
            self.process.stop()

    def call(self, method: str, path: str, body: Any = None) -> httpx.Response:
        transport = httpx.HTTPTransport(uds=str(self.socket))
        with httpx.Client(transport=transport, base_url="http://vault-admin", timeout=60) as client:
            return client.request(method, path, json=body)

    def store(self) -> SecretStore:
        held = SecretStore(self.state, KeySet.from_text(self.master))
        held.load()
        return held


@contextmanager
def deployed(tmp_path: Path, ca: ProviderCA) -> Iterator[Deployment]:
    """The fakes over TLS, their names in a hooks file, and a vault ready to start."""
    mcp = McpFake(key="fake-key-notes-0001", prm="path", authorization_servers=[ISSUER])
    mcp.scopes = ("notes.read",)
    auth = FakeAuthServer(
        client_id=CLIENT_ID, issuer=ISSUER, iss_supported=True, registration="none"
    )
    certs = tmp_path / "certs"
    certs.mkdir(mode=0o700)
    resolver = FakeResolver()
    with ExitStack() as stack:
        for name, app, lifespan in ((MCP, mcp.app(), True), (AUTH, auth.app(), False)):
            url = stack.enter_context(
                serve(app, lifespan=lifespan, tls=issue_cert(ca, name, certs))
            )
            resolver.serve(name, int(str(urlsplit(url).port)))
        hooks = tmp_path / "hooks.json"
        resolver.save(hooks)
        config = tmp_path / "policy.json"
        config.write_bytes(json.dumps(POLICY).encode() + b"\n")
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        port = free_port()
        socket = tmp_path / "admin" / "admin.sock"
        argv = ["vault", "--config", str(config), "--listen", f"127.0.0.1:{port}"]
        argv += ["--state", str(state), "--admin-socket", str(socket)]
        master = generate_master_key()
        deployment = Deployment(
            argv,
            {"ZOEYMCP_MASTER_KEY": master},
            tmp_path / "vault.log",
            ca.ca_file,
            hooks,
            port,
            socket,
            state,
            master,
        )
        try:
            yield deployment
        finally:
            deployment.stop()


def merged(fragment: str) -> Policy:
    """The policy with fragment 1 merged, as ``check --with`` merges it."""
    result = merge(POLICY, load_mapping(fragment))
    assert isinstance(result, Merged)
    return Policy.model_validate(result.data)


def predicted() -> dict[str, Any]:
    return oauth_binding(f"{ISSUER}/token", [f"https://{MCP}"])


def test_restart_before_register(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-1."""
    with deployed(tmp_path, ca) as vault:
        vault.start()
        plan = vault.call("POST", "/onboard/discover", CONFIDENTIAL)
        assert plan.status_code == 200, plan.text
        vault.kill()
        vault.start()
        gone = vault.call(
            "POST", f"/onboard/{plan.json()['onboarding']}/register", {"client_secret": SECRET}
        )
        again = vault.call("POST", "/onboard/discover", CONFIDENTIAL)
        vault.stop()
        assert (gone.status_code, gone.json()["reason"]) == (404, "onboarding_unknown")
        assert again.status_code == 200, again.text
        assert again.json()["onboarding"] != plan.json()["onboarding"]
        assert again.json()["plan"] == plan.json()["plan"]
        assert vault.store().names() == []


def test_restart_after_register(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-2: diff 1 was shown, and a confidential client's secret stays; a given public
    client's fragment holds only what the operator typed, so it keeps nothing."""
    with deployed(tmp_path, ca) as vault:
        vault.start()
        public = vault.call("POST", "/onboard/discover", PUBLIC).json()
        made_public = vault.call("POST", f"/onboard/{public['onboarding']}/fragment", {})
        assert made_public.status_code == 200, made_public.text
        plan = vault.call("POST", "/onboard/discover", CONFIDENTIAL).json()
        made = vault.call(
            "POST", f"/onboard/{plan['onboarding']}/register", {"client_secret": SECRET}
        )
        assert made.status_code == 200, made.text
        vault.kill()
        vault.start()
        gone = vault.call("POST", f"/onboard/{plan['onboarding']}/fragment", {})
        health = vault.call("GET", "/health").json()
        # The same command again: the entry found by its meta, its binding checked against a
        # fresh discovery, and fragment 1 again (D.7 step 6), with nothing stored.
        again = vault.call("POST", "/onboard/discover", CONFIDENTIAL)
        assert again.status_code == 200, again.text
        shown = vault.call("POST", f"/onboard/{again.json()['onboarding']}/fragment", {})
        vault.stop()
    assert (gone.status_code, gone.json()["reason"]) == (404, "onboarding_unknown")
    assert again.json()["stage"] == "registered"
    assert shown.status_code == 200, shown.text
    assert shown.json()["diff"]["yaml"] == made.json()["diff"]["yaml"]
    held = vault.store()
    assert held.names() == [SECRET_NAME]
    entry = held.entry(SECRET_NAME)
    assert entry is not None
    assert entry.binding == predicted()
    assert entry.meta == {
        "onboarded": AUTH,
        "resource": SERVER_URL,
        "client_id": CLIENT_ID,
        "client_secret_expires_at": None,
    }
    assert held.get_for_oauth(SECRET_NAME, token_url=f"{ISSUER}/token")[0].reveal() == SECRET
    # The fragment shown before the kill still works: merged, it checks and derives the binding.
    policy = merged(made.json()["diff"]["yaml"])
    assert not [f for f in check_policy(policy) if f.level == "error"]
    assert derive_binding(policy, SECRET_NAME) == entry.binding
    # Health reports the entry until the fragment is committed (X22).
    [finding] = health["store"]["findings"]
    assert (finding["code"], finding["action"]) == (
        "unreferenced",
        {"kind": "delete_secret", "secret": SECRET_NAME},
    )
    logged = vault.log.read_text(encoding="utf-8", errors="replace")
    assert SECRET not in json.dumps(health) + made.text + shown.text + logged


def test_a_kill_during_register(tmp_path: Path, ca: ProviderCA) -> None:
    """N's ordering rule: the secret is written before the answer carries diff 1. Killed before
    the request, the store holds nothing; killed once the write has returned and before the
    answer, it holds the secret under the predicted binding, and nothing else."""
    with deployed(tmp_path, ca) as vault:
        marker = tmp_path / "written"
        hooks = json.loads(vault.hooks.read_bytes())
        vault.hooks.write_bytes(json.dumps({**hooks, "pause_after_put": str(marker)}).encode())
        vault.start()
        assert vault.call("POST", "/onboard/discover", CONFIDENTIAL).status_code == 200
        vault.kill()
        before = vault.store().names()
        vault.start()
        plan = vault.call("POST", "/onboard/discover", CONFIDENTIAL).json()
        path = f"/onboard/{plan['onboarding']}/register"
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            pending = pool.submit(vault.call, "POST", path, {"client_secret": SECRET})
            deadline = time.monotonic() + 30
            while not marker.exists():
                assert vault.process is not None
                assert time.monotonic() < deadline, vault.process.output()
                time.sleep(0.05)
            vault.kill()
            with pytest.raises(httpx.HTTPError):  # killed before it answered
                pending.result(60)
    assert before == []
    held = vault.store()
    assert held.names() == [SECRET_NAME]
    entry = held.entry(SECRET_NAME)
    assert entry is not None
    assert entry.binding == predicted()
