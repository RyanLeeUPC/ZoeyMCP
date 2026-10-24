"""Serves the fake MCP server (``mcp_server.py``) on its own, for the image smoke test (D-80).

The smoke runs it in a container of the official image with the gateway's interpreter, the only
one there with the MCP SDK, and the repository's ``tests/`` on ``PYTHONPATH``::

    /opt/zoeymcp-gateway/bin/python -m tests.fakes.run_mcp_server CERT KEY

The fake is in its default state: dual era, no key, every tool well behaved. It serves HTTPS on
``0.0.0.0:9000`` at ``/mcp`` with the certificate and key in the files named, since the policy
check refuses MCP over plain http even with ``allow_insecure_upstream``. The ASGI lifespan is on:
it runs the SDK's session manager.

For out-of-process onboarding tests (M7 design O.1), options change that state: ``--port``,
``--mode``, ``--static-key`` (required as ``Authorization: Bearer``, so a request without it gets
the 401 and its challenge), ``--prm`` with ``--authorization-server`` and ``--scope`` (each
repeatable), ``--as-metadata`` (a JSON file served at the server URL as an issuer when ``--prm``
is ``none``), ``--switch`` (repeatable) with a switch's name from ``Switch``, and ``--drift``
with a drift member's name (``DriftMember``), listed changed from the start (the fake's
``change_tool``), for manual check 19's drift review (M6 design O.5).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import uvicorn

from tests.fakes.mcp_server import DRIFT_MEMBERS, McpFake, Switch

# Every interface: the smoke's vault reaches it by its service name on a compose network.
HOST = "0.0.0.0"  # noqa: S104
PORT = 9000


def parse(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m tests.fakes.run_mcp_server")
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--mode", choices=("dual", "legacy", "modern"), default="dual")
    parser.add_argument("--static-key")
    parser.add_argument("--prm", choices=("path", "root", "none"), default="none")
    parser.add_argument("--authorization-server", action="append", default=[])
    parser.add_argument("--scope", action="append", default=[])
    parser.add_argument("--as-metadata", type=Path)
    parser.add_argument("--switch", action="append", default=[], choices=[s.value for s in Switch])
    parser.add_argument("--drift", choices=DRIFT_MEMBERS)
    return parser.parse_args(argv)


def fake_for(args: argparse.Namespace) -> McpFake:
    """The fake the arguments describe."""
    fake = McpFake(
        mode=args.mode,
        switches={Switch(name) for name in args.switch},
        key=args.static_key,
        prm=args.prm,
        authorization_servers=list(args.authorization_server),
        scopes=tuple(args.scope),
    )
    if args.as_metadata is not None:
        document: dict[str, Any] = json.loads(args.as_metadata.read_bytes())
        fake.as_metadata = lambda: document
    fake.tool_change = args.drift
    return fake


def main(argv: Sequence[str]) -> None:
    args = parse(argv)
    uvicorn.run(
        fake_for(args).app(),
        host=HOST,
        port=args.port,
        ssl_certfile=args.cert,
        ssl_keyfile=args.key,
        lifespan="on",
        log_level="warning",
        # Nothing in front of it to trust.
        proxy_headers=False,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
