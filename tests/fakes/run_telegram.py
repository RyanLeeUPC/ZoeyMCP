"""Serves the fake Bot API (``telegram.py``) on its own, for process tests and the image smoke
(M8 design O.1, BP-9).

From the repository root, in the development environment::

    python -m tests.fakes.run_telegram CERT KEY --token TOKEN [--host 127.0.0.1] [--port 8443]
        [--switch NAME]...

It serves HTTPS on ``<host>:<port>`` with the certificate and key in the files named, as
``run_mcp_server.py`` does: a throwaway CA's certificate for ``api.telegram.org``
(``tests/acceptance/tls.py``'s ``make_ca`` and ``issue_cert``), which the vault trusts and reaches
through a fake name entry, so nothing ever reaches the real service. The host is loopback unless
``--host`` names another address, as the image smoke's ``fake-telegram`` service does (all of
its container's, so the vault reaches it as ``api.telegram.org`` on a compose network). The fake
checks ``TOKEN`` in every Bot API path and records what each send asked for. ``--switch``
(repeatable) turns on a fault or variant by its name in ``Switch``. The operator is driven from
outside through the fake's control routes: ``GET /_fake/messages``, ``POST /_fake/press`` with
``{"message_id", "label"}`` and ``POST /_fake/start`` with ``{"code"}``. Ctrl-C stops it.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

import uvicorn

from tests.fakes.telegram import BotApi, Switch

# Loopback by default: a test reaches it through the fake name entry for api.telegram.org.
HOST = "127.0.0.1"
PORT = 8443
# A long poll still open at Ctrl-C is cut this long after it.
SHUTDOWN_GRACE = 1


def parse(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m tests.fakes.run_telegram")
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("--token", required=True)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--switch", action="append", default=[], choices=[s.value for s in Switch])
    return parser.parse_args(argv)


def fake_for(args: argparse.Namespace) -> BotApi:
    """The fake the arguments describe."""
    return BotApi(args.token, switches={Switch(name) for name in args.switch})


def main(argv: Sequence[str]) -> None:
    args = parse(argv)
    uvicorn.run(
        fake_for(args).app(),
        host=args.host,
        port=args.port,
        ssl_certfile=args.cert,
        ssl_keyfile=args.key,
        log_level="warning",
        # Nothing in front of it to trust.
        proxy_headers=False,
        timeout_graceful_shutdown=SHUTDOWN_GRACE,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
