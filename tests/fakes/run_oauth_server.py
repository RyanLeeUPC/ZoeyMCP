"""Serves the fake OAuth provider for the manual check of the portal's callback (M5 design O.6
item 13, review finding R14).

From the repository root, in the development environment::

    python -m tests.fakes.run_oauth_server --dir DIR [--portal-port 8081] [--port 9443]
        [--credential notes]

It makes a throwaway certificate authority in ``DIR`` (``DIR/ca.pem``, a day long), serves
``FakeAuthServer`` over HTTPS at ``https://localhost:<port>`` with its registered redirect the
credential's callback address, ``http://localhost:<portal-port>/oauth/callback/<credential>``,
and writes a development policy beside it (``DIR/policy.json``) whose ``admin`` block lists that
origin and whose credential uses the provider with that ``redirect_uri``. Then it prints how to
start a vault with that policy, trusting the CA for the token exchange, and how to issue the
setup code. The browser must trust ``DIR/ca.pem`` too (a throwaway profile with it imported), or
accept the certificate warning for the provider once. Ctrl-C stops it; nothing it issues is real.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import uvicorn

from tests.acceptance.tls import make_ca
from tests.fakes.oauth_server import FakeAuthServer

CLIENT_ID = "example-notes-client"
SCOPES = ("notes.read", "notes.write")
PROXY_PORT = 8090
# The vault's token client trusts only certifi's bundle: for this check, the throwaway CA.
LAUNCHER = (
    "import sys, certifi; certifi.where = lambda: sys.argv[1]; "
    "from zoeymcp.cli.main import main; sys.exit(main(sys.argv[2:]))"
)


def policy(provider: str, portal_port: int, credential: str) -> dict[str, Any]:
    origin = f"http://localhost:{portal_port}"
    return {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": f"127.0.0.1:{portal_port}", "origins": [origin]},
        "credentials": {
            credential: {
                "kind": "oauth2",
                "token_url": f"{provider}/token",
                "authorize_url": f"{provider}/authorize",
                "client_id": CLIENT_ID,
                "client_auth": "none",
                "rotates": True,
                "refresh_token": f"store:{credential}-refresh",
                "scope": " ".join(SCOPES),
                "redirect_uri": f"{origin}/oauth/callback/{credential}",
            }
        },
        "routes": [
            {
                "name": credential,
                "prefix": f"/{credential}",
                "upstream": "https://api.notes.example",
                "credential": credential,
                "callers": [{"placeholder": f"ph-agent1-{credential}-0001"}],
                "rules": [{"methods": ["GET"], "paths": ["/**"]}],
            }
        ],
    }


def main(argv: Sequence[str]) -> None:
    parser = argparse.ArgumentParser(prog="python -m tests.fakes.run_oauth_server")
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--portal-port", type=int, default=8081)
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--credential", default="notes")
    args = parser.parse_args(argv)
    directory: Path = args.dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "state").mkdir(mode=0o700, exist_ok=True)
    ca = make_ca(directory)
    provider = f"https://localhost:{args.port}"
    document = policy(provider, args.portal_port, args.credential)
    config = directory / "policy.json"
    config.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    address = document["credentials"][args.credential]["redirect_uri"]
    fake = FakeAuthServer(
        time.time,
        client_id=CLIENT_ID,
        auth="none",
        rotate=True,
        scopes=SCOPES,
        registered_redirect=address,
        prefix="fake-notes",
    )
    state = directory / "state"
    print(f"The fake provider: {provider}, its registered redirect {address}")
    print(f"The policy: {config}; the CA: {ca.ca_file}")
    print("In another shell, with ZOEYMCP_MASTER_KEY set (zoeymcp keygen), start the vault:")
    print(
        f'  {sys.executable} -c "{LAUNCHER}" {ca.ca_file} vault --config {config} '
        f"--listen 127.0.0.1:{PROXY_PORT} --state {state} --admin-socket none"
    )
    print("and issue the setup code:")
    print(f"  {sys.executable} -m zoeymcp.cli.main setup-code --state {state}")
    print(f"Then open http://localhost:{args.portal_port}/ and Connect {args.credential}.")
    sys.stdout.flush()
    uvicorn.run(
        fake.app(),
        host="127.0.0.1",
        port=args.port,
        ssl_certfile=str(ca.cert_file),
        ssl_keyfile=str(ca.key_file),
        log_level="warning",
        proxy_headers=False,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
