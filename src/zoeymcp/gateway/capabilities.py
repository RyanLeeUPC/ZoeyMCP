"""What a server path serves, and the listen acknowledgment it may give (M6 design K.4, L.5).

An agent's ``subscriptions/listen`` names the notifications it wants. The SDK's handler
acknowledges every kind it is asked for, and the acknowledgment is the server's promise of what
the stream carries (SDK contract 59), so the gateway filters the request first: ``honored``
keeps ``toolsListChanged``; ``promptsListChanged`` and ``resourcesListChanged`` only for a path
that serves that kind; and never ``resourceSubscriptions``, since the gateway relays no resource
updates (Q21). Unknown members, which the SDK would drop from the acknowledgment anyway, go too.

Until R31 is switched on every path serves tools only (:data:`TOOLS_ONLY`). Pure; the gateway's
``_listen`` passes the filtered parameters to the SDK's handler.
"""

from __future__ import annotations

from typing import Final, Literal

from mcp.types import SubscriptionFilter, SubscriptionsListenRequestParams

Kind = Literal["tools", "prompts", "resources", "completions"]
# The kinds one path serves; tools are always among them.
ServedKinds = frozenset[Kind]

TOOLS_ONLY: Final[ServedKinds] = frozenset({"tools"})


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
