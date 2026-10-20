"""OAuth connect by paste against a real ``zoeymcp vault`` process (M5 design H.5, D-68).

The vault runs in its own interpreter (``procs.py``), its portal on loopback, its token client
trusting the test CA only, against ``FakeAuthServer`` over real TLS. The operator's side is the
fake browser: a setup code (the offline issuer, which works on every platform; on Linux the code
comes from the admin socket instead), a passkey enrolled with the software authenticator and
signed in with, Connect, the approval at the provider, the paste and its confirm. Then the grant
is in the store (on Linux, ``oauth status`` over the socket says so as well) and nothing secret
is in the process's output: no token or code the provider issued, no ``state``, verifier, flow
ID, pasted address or setup code.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Browser
from tests.fakes.oauth_server import FakeAuthServer
from tests.portal.flows import enrol, login, redeem
from zoeymcp.cli import admin_client
from zoeymcp.vault.admin import socket_supported
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.store import SecretStore

from .conftest import serve_tls
from .procs import free_port, start, wait_port
from .test_oauth_shapes import browse
from .test_portal_shapes import setup_code
from .tls import ProviderCA

STARTUP_TIMEOUT = 30.0
CLIENT_ID = "example-notes-client"
SCOPES = ("notes.read", "notes.write")
ISSUED = re.compile(r"fake-notes-(?:rt|at|code)-\d+")


def policy(auth_url: str, portal: int) -> dict[str, Any]:
    return {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": f"127.0.0.1:{portal}", "origins": [f"http://localhost:{portal}"]},
        "credentials": {
            "notes": {
                "kind": "oauth2",
                "token_url": f"{auth_url}/token",
                "authorize_url": f"{auth_url}/authorize",
                "client_id": CLIENT_ID,
                "client_auth": "none",
                "rotates": True,
                "refresh_token": "store:notes-refresh",
                "scope": " ".join(SCOPES),
            }
        },
        "routes": [
            {
                "name": "notes",
                "prefix": "/notes",
                "upstream": "https://api.notes.example",
                "credential": "notes",
                "callers": [{"placeholder": "ph-agent1-notes-0001"}],
                "rules": [{"methods": ["GET"], "paths": ["/**"]}],
            }
        ],
    }


def test_connect_by_paste_in_a_real_vault(tmp_path: Path, ca: ProviderCA) -> None:
    auth = FakeAuthServer(
        time.time, client_id=CLIENT_ID, auth="none", rotate=True, scopes=SCOPES, prefix="fake-notes"
    )
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    portal, proxy = free_port(), free_port()
    origin = f"http://localhost:{portal}"
    master = generate_master_key()
    env = {"ZOEYMCP_MASTER_KEY": master}
    socket = tmp_path / "admin" / "admin.sock" if socket_supported() else None
    with serve_tls(auth.app(), ca) as auth_url:
        config = tmp_path / "policy.json"
        config.write_text(json.dumps(policy(auth_url, portal)), encoding="utf-8")
        argv = ["vault", "--config", str(config), "--listen", f"127.0.0.1:{proxy}"]
        argv += ["--state", str(state), "--admin-socket", str(socket or "none")]
        vault = start(argv, env=env, log=tmp_path / "vault.log", ca=ca.ca_file)
        try:
            wait_port(portal, vault, STARTUP_TIMEOUT)
            if socket is not None:
                code = str(admin_client.setup_code(str(socket))["code"])
            else:
                code = setup_code(state, env)
            passkey = SoftAuthenticator()
            with Browser() as browser:
                page = browser.page(origin)
                assert redeem(page, code).status_code == 200
                assert enrol(page, passkey).status_code == 200
                assert login(page, passkey).status_code == 200
                started = page.fetch("POST", "/api/oauth/notes/start", json={})
                assert started.status_code == 200, started.text
                begun = started.json()
                pasted = browse(begun["authorize_url"], ca)
                data = {"credential": "notes", "flow": begun["flow"], "redirect_url": pasted}
                body = {"kind": "oauth.complete", "data": data}
                held = page.fetch("POST", "/api/actions", json=body)
                assert held.status_code == 200, held.text
                assert auth.calls == []  # nothing exchanged before the passkey
                assertion = passkey.get(held.json()["options"], origin).body()
                path = f"/api/actions/{held.json()['action']}/confirm"
                done = page.fetch("POST", path, json={"credential": assertion})
                assert done.status_code == 200, done.text
                assert (done.json()["slot"], done.json()["persisted"]) == ("notes-refresh", True)
                listed = page.fetch("GET", "/api/oauth").json()["credentials"]
                assert [(e["credential"], e["state"]) for e in listed] == [("notes", "ok")]
            if socket is not None:
                [status] = admin_client.oauth_status(str(socket))["credentials"]
                assert (status["credential"], status["state"]) == ("notes", "ok")
        finally:
            vault.stop()
    # The grant is the one the provider issued, and nothing secret reached the output.
    store = SecretStore(state, KeySet.from_text(master))
    store.load()
    stored, _ = store.get_for_oauth("notes-refresh", token_url=f"{auth_url}/token")
    assert stored.reveal() == auth.active_refresh_token()
    output = vault.output()
    assert '"event":"oauth_login_completed"' in output
    assert '"event":"step_up_confirmed"' in output
    leaked = ISSUED.search(output)
    assert leaked is None, leaked.group(0)
    [exchange] = auth.calls
    query = dict(parse_qsl(urlsplit(begun["authorize_url"]).query))
    for value in (
        query["state"],
        exchange.params["code_verifier"],
        begun["flow"],
        pasted,
        code,
        code.replace("-", ""),
    ):
        assert value not in output
