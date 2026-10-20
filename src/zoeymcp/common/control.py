"""The launcher's control pipe, read by the vault and the gateway (M3 design B.1, B.2).

In the standard tier the launcher can't signal its children's uids, so it writes ``HUP`` and
``TERM`` to a pipe each child reads instead.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from typing import Any

CONTROL_RELOAD = b"HUP"
CONTROL_STOP = b"TERM"
CONTROL_LINE_LIMIT = 1024

Event = Callable[..., Any]


async def open_control(fd: int) -> tuple[asyncio.StreamReader, asyncio.BaseTransport]:
    """Read the control pipe ``fd`` without blocking the loop. The transport owns ``fd``."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=CONTROL_LINE_LIMIT)
    transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(fd, "rb", buffering=0)
    )
    return reader, transport


async def read_control(
    reader: asyncio.StreamReader,
    *,
    reload: Callable[[], None],
    stop: Callable[[], None],
    event: Event,
) -> None:
    """Act on the launcher's commands: ``HUP`` reloads, ``TERM`` stops.

    The end of the pipe stops the process too: the launcher is gone, and nothing would stop it
    any more. So does an error reading it. Anything else is logged by size and ignored.

    A line over :data:`CONTROL_LINE_LIMIT` is dropped up to the limit, and what follows it is
    read as the next line. Only the launcher holds the pipe, and it writes short lines.
    """
    while True:
        try:
            line = await reader.readline()
        except ValueError:
            event("control_ignored", bytes=CONTROL_LINE_LIMIT)
            continue
        except OSError as exc:
            event("control_failed", error_type=type(exc).__name__)
            stop()
            return
        if not line:
            event("control_received", command="EOF")
            stop()
            return
        command = line.strip()
        if command == CONTROL_RELOAD:
            event("control_received", command="HUP")
            try:
                reload()
            except Exception as exc:  # a failed reload must not end the reader, or TERM is lost
                event("reload_failed", error_type=type(exc).__name__)
        elif command == CONTROL_STOP:
            event("control_received", command="TERM")
            stop()
        else:
            event("control_ignored", bytes=len(line))
