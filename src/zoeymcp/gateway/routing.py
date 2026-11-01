"""The routing decision: what step 5 of the ``tools/call`` pipeline does with a call (M8 design
C.1; M4 design B.8's seam).

Pure: :func:`decide` reads the server's tool lists, the client's view entry, the agent's era and
whether the request carried MRTR input, and returns one closed :data:`Route`. The pipeline acts
on it; nothing here asks anyone or sends anything.

The rows are evaluated in order, the first that holds wins:

1. a legacy request with ``requestState`` or ``inputResponses``: Refuse ``unexpected_input``;
1b. a ``requestState`` on a tool the gateway issued no handle for (only an ``approve`` tool's
    prompt has one): Refuse ``unexpected_state``;
8. an ``approve`` tool, for an attended client or on a retry (its handle is checked where it was
   issued, :func:`zoeymcp.gateway.approvals.retry`): AskElicitation;
9. any other ``approve`` call: Refuse ``no_approvals``;
11. an ``allow`` tool: Allow;
12. anything else: Refuse ``unclassified``.

Rows 2-7 (``vault_approval`` and out-of-band approvers) read fields the policy doesn't have yet;
they arrive with them, and so do the routes only they return.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..common.policy.schema import Tools
from ..common.policy.view import ViewClient
from .approvals import Era

RefuseReason = Literal["unexpected_input", "unexpected_state", "unclassified", "no_approvals"]


@dataclass(frozen=True)
class Allow:
    """Forward the call as it is (pipeline steps 6 and 7)."""


@dataclass(frozen=True)
class AskElicitation:
    """Ask the agent's human on the call's own session (:mod:`.approve`)."""


@dataclass(frozen=True)
class Refuse:
    """Refuse the call; the pipeline words it and logs ``reason``."""

    reason: RefuseReason


Route = Allow | AskElicitation | Refuse


def decide(
    *,
    tool: str,
    tools: Tools,
    client: ViewClient | None,
    era: Era,
    request_state: bool,
    inputs: bool,
) -> Route:
    """The route for one call to ``tool``. ``client`` is the client's entry in the view the
    request started with (None without an approval context); ``request_state`` and ``inputs``
    say whether the request carried a ``requestState`` or any ``inputResponses``."""
    if era == "legacy" and (request_state or inputs):
        return Refuse("unexpected_input")
    if request_state and tool not in tools.approve:
        return Refuse("unexpected_state")
    if tool in tools.approve:
        if request_state or attended(client):
            return AskElicitation()
        return Refuse("no_approvals")
    if tool in tools.allow:
        return Allow()
    return Refuse("unclassified")


def attended(client: ViewClient | None) -> bool:
    """Whether someone answers this client's prompts: its ``approvals`` say ``attended``."""
    return client is not None and client.approvals is not None and client.approvals.attended
