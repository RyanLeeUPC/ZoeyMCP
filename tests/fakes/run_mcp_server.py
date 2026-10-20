"""Serves the fake MCP server (``mcp_server.py``) on its own, for the image smoke test (D-80).

The smoke runs it in a container of the official image with the gateway's interpreter, the only
one there with the MCP SDK, and the repository's ``tests/`` on ``PYTHONPATH``::

    /opt/zoeymcp-gateway/bin/python -m tests.fakes.run_mcp_server CERT KEY

The fake is in its default state: dual era, no key, every tool well behaved. It serves HTTPS on
``0.0.0.0:9000`` at ``/mcp`` with the certificate and key in the files named, since the policy
check refuses MCP over plain http even with ``allow_insecure_upstream``. The ASGI lifespan is on:
it runs the SDK's session manager.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

import uvicorn

from tests.fakes.mcp_server import McpFake

# Every interface: the smoke's vault reaches it by its service name on a compose network.
HOST = "0.0.0.0"  # noqa: S104
PORT = 9000


def main(argv: Sequence[str]) -> None:
    if len(argv) != 2:
        raise SystemExit("usage: python -m tests.fakes.run_mcp_server CERT KEY")
    cert, key = argv
    uvicorn.run(
        McpFake().app(),
        host=HOST,
        port=PORT,
        ssl_certfile=cert,
        ssl_keyfile=key,
        lifespan="on",
        log_level="warning",
        # Nothing in front of it to trust.
        proxy_headers=False,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
