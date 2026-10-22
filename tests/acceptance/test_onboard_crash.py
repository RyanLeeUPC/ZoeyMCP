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
- after a client the vault registered (step 11) was given a secret and fragment 1 shown: the
  secret stays under the predicted binding with the registration's meta, and the same command
  shows that fragment 1 again, registering nothing more (FM-2 for DCR);
- before the register request is sent, the store holds nothing; once the secret's write has
  returned and before the answer (held there by the hooks file's ``pause_after_put``), the
  store holds that secret under the predicted binding, and nothing else;
- through the CLI (step 8b), J1's given public client: fragment 1, the commit recreating the
  vault, and the second ``login --mcp``, which signs in with nothing lost (FM-3);
- J3's given confidential client, the vault killed while the operator is at the provider: the
  sign-in is lost and the stored client secret stays, and the same command signs in (FM-4).

The admin socket is a Unix socket, so these run where one exists.
"""

from __future__ import annotations

import concurrent.futures
import io
import json
import re
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from tests.fakes.oauth_server import FakeAuthServer
from tests.fakes.resolver import FakeResolver
from zoeymcp.cli.main import main
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
    config: Path
    ports: dict[str, int] = field(default_factory=dict)
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

    def commit(self, fragment: str) -> None:
        """Fragment 1 merged into the policy file as ``check --with`` merges it, then the vault
        recreated with it, as committing an inline ``ZOEYMCP_CONFIG`` does (F-13)."""
        result = merge(POLICY, load_mapping(fragment))
        assert isinstance(result, Merged)
        self.stop()
        self.config.write_bytes(json.dumps(result.data).encode() + b"\n")
        self.start()

    def cli(self, argv: list[str], stdin: io.StringIO | None = None) -> tuple[int, str, str]:
        """``zoeymcp <argv>`` in this process, on the vault's admin socket."""
        out, err = io.StringIO(), io.StringIO()
        given = stdin if stdin is not None else io.StringIO()
        if isinstance(given, Browser):
            given.shown = out
        code = main([*argv, "--socket", str(self.socket)], stdin=given, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def browse(self, url: str) -> str:
        """The operator's browser at the authorization URL, on the fake's own address: where
        the provider sends it back to."""
        parts = urlsplit(url)
        assert parts.hostname == AUTH
        local = f"https://127.0.0.1:{self.ports[AUTH]}{parts.path}?{parts.query}"
        answer = httpx.get(local, verify=False, timeout=30)  # noqa: S501 - the test's browser
        assert answer.status_code == 302, answer.text
        return answer.headers["location"]


class Browser(io.StringIO):
    """The paste: reading it opens the authorization URL the CLI printed and answers where the
    browser was sent to; ``meanwhile`` runs while the operator is at the provider."""

    def __init__(self, vault: Deployment, meanwhile: Any = None) -> None:
        super().__init__()
        self.vault = vault
        self.meanwhile = meanwhile
        self.shown = io.StringIO()

    def readline(self, size: int = -1, /) -> str:  # type: ignore[override]  # as typeshed
        [url] = re.findall(r"^  (https://\S+/authorize\?\S+)$", self.shown.getvalue(), re.M)
        location = self.vault.browse(url)
        if self.meanwhile is not None:
            self.meanwhile()
        return location + "\n"


@contextmanager
def deployed(tmp_path: Path, ca: ProviderCA, **auth_options: Any) -> Iterator[Deployment]:
    """The fakes over TLS, their names in a hooks file, and a vault ready to start."""
    mcp = McpFake(key="fake-key-notes-0001", prm="path", authorization_servers=[ISSUER])
    mcp.scopes = ("notes.read",)
    options = {"registration": "none", **auth_options}
    auth = FakeAuthServer(client_id=CLIENT_ID, issuer=ISSUER, iss_supported=True, **options)
    certs = tmp_path / "certs"
    certs.mkdir(mode=0o700)
    resolver = FakeResolver()
    ports: dict[str, int] = {}
    with ExitStack() as stack:
        for name, app, lifespan in ((MCP, mcp.app(), True), (AUTH, auth.app(), False)):
            url = stack.enter_context(
                serve(app, lifespan=lifespan, tls=issue_cert(ca, name, certs))
            )
            ports[name] = int(str(urlsplit(url).port))
            resolver.serve(name, ports[name])
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
            config,
            ports,
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


def test_restart_after_a_registration(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-2 for a confidential client the vault registered (D.4, D.7 step 6)."""
    with deployed(tmp_path, ca, registration="confidential_only") as vault:
        vault.start()
        body = {"url": SERVER_URL}
        plan = vault.call("POST", "/onboard/discover", body).json()
        assert plan["plan"]["registration"] == "dcr"
        made = vault.call("POST", f"/onboard/{plan['onboarding']}/register", {})
        assert made.status_code == 200, made.text
        vault.kill()
        vault.start()
        again = vault.call("POST", "/onboard/discover", body)
        assert again.status_code == 200, again.text
        shown = vault.call("POST", f"/onboard/{again.json()['onboarding']}/fragment", {})
        vault.stop()
    assert again.json()["stage"] == "registered"
    assert shown.status_code == 200, shown.text
    # The same client: nothing was registered again.
    assert shown.json()["client_id"] == made.json()["client_id"]
    assert shown.json()["diff"]["yaml"] == made.json()["diff"]["yaml"]
    held = vault.store()
    assert held.names() == [SECRET_NAME]
    entry = held.entry(SECRET_NAME)
    assert entry is not None
    assert entry.binding == predicted()
    assert entry.meta == {
        "onboarded": AUTH,
        "resource": SERVER_URL,
        "client_id": made.json()["client_id"],
        "client_secret_expires_at": 0,
        "client_auth": "basic",
        "redirect_uri": "http://127.0.0.1/callback/notes",
    }
    policy = merged(made.json()["diff"]["yaml"])
    assert not [f for f in check_policy(policy) if f.level == "error"]
    assert derive_binding(policy, SECRET_NAME) == entry.binding
    secret = held.get_for_oauth(SECRET_NAME, token_url=f"{ISSUER}/token")[0].reveal()
    logged = vault.log.read_text(encoding="utf-8", errors="replace")
    assert secret not in made.text + again.text + shown.text + logged


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


# --- through the CLI (step 8b; FM-3, FM-4) --------------------------------------------------------

J1 = ["login", "--mcp", SERVER_URL, "--name", "notes"]


def test_commit_recreates_the_vault(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-3, J1 through the CLI: fragment 1 from a given public client, the commit recreating
    the vault, and the second run, which finds the credential committed, signs in with nothing
    lost (F-13) and names the review next."""
    with deployed(tmp_path, ca, auth="none") as vault:
        vault.start()
        code, fragment, err = vault.cli([*J1, "--client-id", CLIENT_ID, "--yes"])
        assert code == 0, err
        assert vault.store().names() == []
        vault.commit(fragment)
        code, out, err = vault.cli(J1, Browser(vault))
        vault.stop()
    assert code == 0, err
    assert "Stored the refresh token for notes as notes-refresh.\n" in out
    assert "notes is in the policy and matches what the server publishes" in err
    assert err.endswith("exec gateway zoeymcp review notes\n")
    assert vault.store().names() == ["notes-refresh"]


def test_restart_during_login(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-4, J3 through the CLI: the vault killed while the operator is at the provider loses
    the sign-in (M2), and the client secret stored at register stays; the same command then
    signs in with it."""
    with deployed(tmp_path, ca, client_secret=SECRET) as vault:
        vault.start()
        argv = [*J1, "--issuer", ISSUER, "--client-id", CLIENT_ID, "--client-secret", "--yes"]
        code, fragment, err = vault.cli(argv, io.StringIO(SECRET + "\n"))
        assert code == 0, err
        vault.commit(fragment)

        def restarted() -> None:
            vault.kill()
            vault.start()

        code, out, err = vault.cli(J1, Browser(vault, restarted))
        assert code == 1, err
        assert vault.store().names() == [SECRET_NAME]
        again, out, err = vault.cli(J1, Browser(vault))
        vault.stop()
    assert again == 0, err
    assert "Stored the refresh token for notes as notes-refresh.\n" in out
    held = vault.store()
    assert held.names() == ["notes-client-secret", "notes-refresh"]
    entry = held.entry(SECRET_NAME)
    assert entry is not None
    assert entry.binding == predicted()
    logged = vault.log.read_text(encoding="utf-8", errors="replace")
    assert SECRET not in out + err + fragment + logged
