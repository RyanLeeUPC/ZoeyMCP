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

``--consent`` (register D-183) puts an Approve page in front of the answer, as a real provider's
consent screen, and serves the provider at ``https://127.0.0.1:<port>`` (the certificate covers
it), a different site from the portal's ``localhost``, so the return navigation starts on another
site. For onboarding by URL (M7 design O.1), ``--metadata`` publishes the provider's metadata with
the provider (and ``--issuer-path``) as its issuer, ``--iss`` advertises RFC 9207's ``iss``,
``--registration`` picks how ``/register`` answers, and ``--switch`` (repeatable) turns on a
hostile or slow answer by its name in ``AuthSwitch``.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn

from tests.acceptance.tls import make_ca
from tests.fakes.oauth_server import AuthSwitch, FakeAuthServer, Registration

CLIENT_ID = "example-notes-client"
SCOPES = ("notes.read", "notes.write")
PROXY_PORT = 8090
REGISTRATIONS: tuple[Registration, ...] = (
    "open",
    "none",
    "confidential_only",
    "cimd_only",
    "needs_initial_token",
)
# A stalled answer is cut this long after Ctrl-C.
SHUTDOWN_GRACE = 1
# The vault's token client trusts only certifi's bundle: for this check, the throwaway CA.
LAUNCHER = (
    "import sys, certifi; certifi.where = lambda: sys.argv[1]; "
    "from zoeymcp.cli.main import main; sys.exit(main(sys.argv[2:]))"
)


def policy(
    provider: str, portal_port: int, credential: str, endpoints: str | None = None
) -> dict[str, Any]:
    """The vault's policy for this provider; ``endpoints`` is where its endpoints are, when not
    at its origin (``--endpoint-path``)."""
    origin = f"http://localhost:{portal_port}"
    base = endpoints or provider
    return {
        "version": 1,
        "mode": "declarative",
        # The provider is on loopback, which the vault's address guard refuses unless listed.
        "egress_private": [urlsplit(provider).netloc],
        "admin": {"listen": f"127.0.0.1:{portal_port}", "origins": [origin]},
        "credentials": {
            credential: {
                "kind": "oauth2",
                "token_url": f"{base}/token",
                "authorize_url": f"{base}/authorize",
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


def parse(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m tests.fakes.run_oauth_server")
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--portal-port", type=int, default=8081)
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--credential", default="notes")
    parser.add_argument("--consent", action="store_true")
    parser.add_argument("--metadata", action="store_true")
    parser.add_argument("--issuer-path", default="")
    parser.add_argument("--endpoint-path", default="")
    parser.add_argument("--iss", action="store_true")
    parser.add_argument("--registration", choices=REGISTRATIONS, default="open")
    parser.add_argument(
        "--switch", action="append", default=[], choices=[s.value for s in AuthSwitch]
    )
    return parser.parse_args(argv)


def provider_of(args: argparse.Namespace) -> str:
    """The provider's origin: on ``127.0.0.1`` with a consent page, another site (D-183)."""
    host = "127.0.0.1" if args.consent else "localhost"
    return f"https://{host}:{args.port}"


def fake_for(args: argparse.Namespace, address: str) -> FakeAuthServer:
    """The fake provider the arguments describe, its registered redirect ``address``."""
    fake = FakeAuthServer(
        time.time,
        client_id=CLIENT_ID,
        auth="none",
        rotate=True,
        scopes=SCOPES,
        registered_redirect=address,
        prefix="fake-notes",
        iss_supported=args.iss,
        registration=args.registration,
        consent=args.consent,
    )
    if args.metadata:
        fake.issuer = provider_of(args) + args.issuer_path
    if args.endpoint_path:
        fake.endpoint_base = provider_of(args) + args.endpoint_path
    fake.switches = {AuthSwitch(name) for name in args.switch}
    return fake


def main(argv: Sequence[str]) -> None:
    args = parse(argv)
    directory: Path = args.dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "state").mkdir(mode=0o700, exist_ok=True)
    ca = make_ca(directory)
    provider = provider_of(args)
    endpoints = provider + args.endpoint_path if args.endpoint_path else None
    document = policy(provider, args.portal_port, args.credential, endpoints)
    config = directory / "policy.json"
    config.write_bytes(json.dumps(document, indent=2).encode() + b"\n")
    address = document["credentials"][args.credential]["redirect_uri"]
    fake = fake_for(args, address)
    state = directory / "state"
    print(f"The fake provider: {provider}, its registered redirect {address}")
    if fake.consent:
        print("It shows an Approve page before it sends the tab back.")
    if fake.issuer is not None:
        print(f"Its metadata, for the issuer {fake.issuer}: {', '.join(fake.metadata_paths())}")
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
        timeout_graceful_shutdown=SHUTDOWN_GRACE,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
