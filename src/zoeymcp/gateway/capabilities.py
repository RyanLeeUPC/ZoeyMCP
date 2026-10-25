"""What a server path serves, and the listen acknowledgment it may give (M6 design K.4, L.5).

:func:`served` reads a path's kinds from the view: ``tools`` always; ``prompts`` and
``resources`` when the server enables the kind **and** includes at least one entry of it;
``completions`` when it enables them and the path serves a prompt or a template, since
completions have no entries of their own (SPEC-6). A toolkit server serves tools only.

:func:`advertised` is the capabilities a path states, in both eras, from those kinds alone and
never from the upstream's: ``tools``, ``prompts`` and ``resources`` with ``listChanged`` (never
``subscribe``), and ``completions``, each only as served. :func:`notified` is the lists a view
change may have changed for the agents on a path.

An agent's ``subscriptions/listen`` names the notifications it wants. The SDK's handler
acknowledges every kind it is asked for, and the acknowledgment is the server's promise of what
the stream carries (SDK contract 59), so the gateway filters the request first: ``honored``
keeps ``toolsListChanged``; ``promptsListChanged`` and ``resourcesListChanged`` only for a path
that serves that kind; and never ``resourceSubscriptions``, since the gateway relays no resource
updates (Q21). Unknown members, which the SDK would drop from the acknowledgment anyway, go too.

Pure; the gateway's ``_listen`` passes the filtered parameters to the SDK's handler.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Literal

from mcp.types import (
    CompletionsCapability,
    PromptsCapability,
    ResourcesCapability,
    ServerCapabilities,
    SubscriptionFilter,
    SubscriptionsListenRequestParams,
    ToolsCapability,
)

from ..common.pinhash import DefinitionKind
from ..common.policy.view import ViewRemoteServer, ViewToolkitServer

Kind = Literal["tools", "prompts", "resources", "completions"]
# The kinds one path serves; tools are always among them.
ServedKinds = frozenset[Kind]

TOOLS_ONLY: Final[ServedKinds] = frozenset({"tools"})
# The served kind whose list holds each definition kind (M6 design L.4).
LISTED_IN: Final[Mapping[DefinitionKind, Kind]] = {
    "tool": "tools",
    "prompt": "prompts",
    "resource_template": "resources",
    "resource": "resources",
}


def served(server: ViewRemoteServer | ViewToolkitServer) -> ServedKinds:
    """The kinds ``server``'s path serves (L.5)."""
    if not isinstance(server, ViewRemoteServer):
        return TOOLS_ONLY
    kinds: set[Kind] = {"tools"}
    templates = "resources" in server.enable and bool(server.resources.templates.include)
    if "prompts" in server.enable and server.prompts.include:
        kinds.add("prompts")
    if templates or ("resources" in server.enable and server.resources.fixed.include):
        kinds.add("resources")
    if "completions" in server.enable and ("prompts" in kinds or templates):
        kinds.add("completions")
    return frozenset(kinds)


def advertised(kinds: ServedKinds) -> ServerCapabilities:
    """The capabilities a path serving ``kinds`` states: every list it serves with
    ``listChanged``, which the gateway sends (SPEC-1), and never resource subscriptions."""
    return ServerCapabilities(
        tools=ToolsCapability(list_changed=True),
        prompts=PromptsCapability(list_changed=True) if "prompts" in kinds else None,
        resources=ResourcesCapability(list_changed=True) if "resources" in kinds else None,
        completions=CompletionsCapability() if "completions" in kinds else None,
    )


def notified(
    before: ViewRemoteServer | ViewToolkitServer | None,
    after: ViewRemoteServer | ViewToolkitServer | None,
) -> ServedKinds:
    """The lists to announce when a path's server changed from ``before`` to ``after`` (either
    None when it wasn't there): tools, as M3 always did, and each other list either side serves.
    Completions are no list."""
    kinds: set[Kind] = {"tools"}
    for server in (before, after):
        if server is not None:
            kinds |= served(server) & {"prompts", "resources"}
    return frozenset(kinds)


def honored(
    params: SubscriptionsListenRequestParams, served: ServedKinds
) -> SubscriptionsListenRequestParams:
    """``params`` with only the notifications the path will send: what the SDK then acknowledges
    and delivers. Everything else in ``params`` (its ``_meta``) is kept."""
    asked = params.notifications
    kept = SubscriptionFilter(
        tools_list_changed=asked.tools_list_changed,
        prompts_list_changed=asked.prompts_list_changed if "prompts" in served else None,
        resources_list_changed=asked.resources_list_changed if "resources" in served else None,
    )
    return params.model_copy(update={"notifications": kept})
