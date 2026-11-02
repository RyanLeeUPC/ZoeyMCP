"""The rules :mod:`.approve` applies to a waiting prompt after a policy change (M8 design C.1).

Pure, so they can be tested exhaustively; :mod:`.approve` does the I/O around them.

- :func:`still_asked`: whether a view still lets a recorded call be asked the way it was, on the
  agent's session or relayed out of band (step 12b's rewrite, G-24), checked at the commit's
  re-check (M4 design B.5) and by ``withdraw_unallowed`` after a policy change (M6 design Y28,
  Q32 (b): a tool moved to ``allow`` withdraws its prompt).
- :func:`withdraw_picks`: whether a withdrawal takes a record, and whether that record is mid-retry
  (a modern record whose handle was consumed has a handler running, which sees the decision).
- :func:`ending_records`: how the vault's ending of a held call closes the gateway's pending
  record of it (M8 design E.2, D.2; OPS-3), the records the decisions poller writes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final, Literal

from ..common.policy.view import ViewGateway
from .approvals import Key, Pending

# The gateway ledger's decision for an ending the vault reports.
Ended = Literal["approved_elsewhere", "decline", "timeout", "withdrawn"]
# An ending's status (E.2) to that decision, and whether it starts the cooldown: a decline or an
# expiry does (E.1), as for a call the gateway asked about itself.
ENDINGS: Final[Mapping[str, tuple[Ended, bool]]] = MappingProxyType(
    {
        "done": ("approved_elsewhere", False),
        "denied": ("decline", True),
        "expired": ("timeout", True),
        "withdrawn": ("withdrawn", False),
    }
)


def still_asked(gateway: ViewGateway, key: Key, how: Literal["elicitation", "relay"]) -> bool:
    """The view still assigns the server to the client, and the tool is in the server's
    ``approve`` list and not its ``vault_approval`` one (M6 Q32 (b)). An elicited record needs
    the client attended; a relayed one needs it ``out_of_band``, with an out-of-band approver
    configured (M8 design C.1, G-24). A record the client no longer qualifies for is withdrawn,
    and only that one: a relay survives a change that doesn't touch it."""
    client = gateway.clients.get(key.client)
    server = gateway.servers.get(key.server)
    if client is None or server is None or key.server not in client.servers:
        return False
    if key.tool not in server.tools.approve or key.tool in server.tools.vault_approval:
        return False
    own = client.approvals
    if own is None:
        return False
    if how == "relay":
        return own.out_of_band and gateway.approvals.out_of_band is not None
    return own.attended


def withdraw_picks(record: Pending, matches: Callable[[Pending], bool]) -> tuple[bool, bool]:
    """(picked, retrying): whether ``matches`` takes the record, and whether a taken record is
    mid-retry. Read before deciding: deciding clears the handle, so the record can't tell after."""
    if not matches(record):
        return False, False
    return True, record.handle_sha256 is None


def ending_records(status: object, outcome: str) -> tuple[Ended, str, bool] | None:
    """(decision, outcome, cooldown): the gateway's records for the vault's ending of a held call,
    and whether it starts the cooldown. A call the vault forwarded keeps the vault's ``outcome``
    (one the gateway's ledger knows: the poller reads it so); any other ending sent nothing. None
    for a status that isn't an ending (the call still waits, or runs)."""
    found = ENDINGS.get(status) if isinstance(status, str) else None
    if found is None:
        return None
    decision, cooldown = found
    return decision, outcome if decision == "approved_elsewhere" else "not_sent", cooldown
