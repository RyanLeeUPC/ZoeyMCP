"""The rules :mod:`.approve` applies to a waiting prompt after a policy change (M8 design C.1).

Pure, so they can be tested exhaustively; :mod:`.approve` does the I/O around them.

- :func:`still_asked`: whether a view still lets a recorded call be asked, checked at the
  commit's re-check (M4 design B.5) and by ``withdraw_unallowed`` after a policy change (M6
  design Y28, Q32 (b): a tool moved to ``allow`` withdraws its prompt).
- :func:`withdraw_picks`: whether a withdrawal takes a record, and whether that record is mid-retry
  (a modern record whose handle was consumed has a handler running, which sees the decision).
"""

from __future__ import annotations

from collections.abc import Callable

from ..common.policy.view import ViewGateway
from .approvals import Key, Pending


def still_asked(gateway: ViewGateway, key: Key) -> bool:
    """The view still assigns the server to the client, the client is attended, and the tool is
    in the server's ``approve`` list."""
    client = gateway.clients.get(key.client)
    server = gateway.servers.get(key.server)
    if client is None or server is None or key.server not in client.servers:
        return False
    if client.approvals is None or not client.approvals.attended:
        return False
    return key.tool in server.tools.approve


def withdraw_picks(record: Pending, matches: Callable[[Pending], bool]) -> tuple[bool, bool]:
    """(picked, retrying): whether ``matches`` takes the record, and whether a taken record is
    mid-retry. Read before deciding: deciding clears the handle, so the record can't tell after."""
    if not matches(record):
        return False, False
    return True, record.handle_sha256 is None
