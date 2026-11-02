"""The routing decision: what step 5 of the ``tools/call`` pipeline does with a call (M8 design
C.1; M4 design B.8's seam).

Pure: :func:`decide` reads the server's tool lists, the client's view entry, the agent's era and
whether the request carried MRTR input, and returns one closed :data:`Route`. The pipeline acts
on it; nothing here asks anyone or sends anything.

The rows are evaluated in order, the first that holds wins:

1. a legacy request with ``requestState`` or ``inputResponses``: Refuse ``unexpected_input``;
1b. a ``requestState`` on a tool the gateway issued no handle for (only an ``approve`` tool's
    elicited prompt has one; a ``vault_approval`` tool never does, so any MRTR input on it is
    stray): Refuse ``unexpected_state``;
2. a ``vault_approval`` tool, for a client neither ``attended`` nor ``out_of_band``: Refuse
   ``no_out_of_band``;
3. a ``vault_approval`` tool, with no out-of-band approver configured: Refuse ``no_approver``;
4. a ``vault_approval`` tool whose pinned schema mirrors parameters into headers
   (``x-mcp-header``; Q27): Refuse ``header_params``;
5. a ``vault_approval`` tool: Elsewhere, ``block`` for a toolkit's (B.7), else ``pending``;
6. an ``approve`` tool, for an ``out_of_band`` client with an approver configured, not a retry:
   AskOutOfBand;
7. the same with none configured: Refuse ``no_approver``;
8. an ``approve`` tool, for an attended client or on a retry (its handle is checked where it was
   issued, :func:`zoeymcp.gateway.approvals.retry`): AskElicitation;
9. any other ``approve`` call: Refuse ``no_approvals``;
11. an ``allow`` tool: Allow;
12. anything else: Refuse ``unclassified``.

Rows 2 and 5 are G-18: an ``attended`` client's call to a held tool goes to the vault, which asks
the operator's approvers, while its other ``approve`` tools keep elicitation (Z11). A retry on an
``approve`` tool is the elicitation's to answer before rows 6 and 7, since only an elicited prompt
issues a handle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..common.policy.schema import Tools
from ..common.policy.view import ViewClient
from .approvals import Era

RefuseReason = Literal[
    "unexpected_input",
    "unexpected_state",
    "unclassified",
    "no_approvals",
    "no_out_of_band",
    "no_approver",
    "header_params",
]


@dataclass(frozen=True)
class Allow:
    """Forward the call as it is (pipeline steps 6 and 7)."""


@dataclass(frozen=True)
class AskElicitation:
    """Ask the agent's human on the call's own session (:mod:`.approve`)."""


@dataclass(frozen=True)
class AskOutOfBand:
    """Relay the prompt to the vault's out-of-band approvers (Q6 (B); M8 step 12b)."""


@dataclass(frozen=True)
class Elsewhere:
    """Forward the call marked, for the vault to hold and ask its approvers (:mod:`.elsewhere`).
    ``wait`` is ``block`` for a toolkit's write, which can't be suspended (B.7)."""

    wait: Literal["block", "pending"]


@dataclass(frozen=True)
class Refuse:
    """Refuse the call; the pipeline words it and logs ``reason``."""

    reason: RefuseReason


Route = Allow | AskElicitation | AskOutOfBand | Elsewhere | Refuse


def decide(
    *,
    tool: str,
    tools: Tools,
    client: ViewClient | None,
    era: Era,
    request_state: bool,
    inputs: bool,
    out_of_band_configured: bool,
    header_params: bool,
    toolkit: bool,
) -> Route:
    """The route for one call to ``tool``. ``client`` is the client's entry in the view the
    request started with (None without an approval context); ``request_state`` and ``inputs``
    say whether the request carried a ``requestState`` or any ``inputResponses``;
    ``out_of_band_configured`` whether the view names an out-of-band approver; ``header_params``
    whether the tool's pinned schema declares ``x-mcp-header``; ``toolkit`` whether the server is
    a toolkit."""
    if era == "legacy" and (request_state or inputs):
        return Refuse("unexpected_input")
    held = tool in tools.vault_approval
    if (request_state and tool not in tools.approve) or (held and (request_state or inputs)):
        return Refuse("unexpected_state")
    if held:
        if not (attended(client) or out_of_band(client)):
            return Refuse("no_out_of_band")
        if not out_of_band_configured:
            return Refuse("no_approver")
        if header_params:
            return Refuse("header_params")
        return Elsewhere("block" if toolkit else "pending")
    if tool in tools.approve:
        if not request_state and out_of_band(client):
            return AskOutOfBand() if out_of_band_configured else Refuse("no_approver")
        if request_state or attended(client):
            return AskElicitation()
        return Refuse("no_approvals")
    if tool in tools.allow:
        return Allow()
    return Refuse("unclassified")


def attended(client: ViewClient | None) -> bool:
    """Whether someone answers this client's prompts: its ``approvals`` say ``attended``."""
    return client is not None and client.approvals is not None and client.approvals.attended


def out_of_band(client: ViewClient | None) -> bool:
    """Whether this client's prompts may be raised out of band: its ``approvals`` say
    ``out_of_band`` (M8 design E.1)."""
    return client is not None and client.approvals is not None and client.approvals.out_of_band
