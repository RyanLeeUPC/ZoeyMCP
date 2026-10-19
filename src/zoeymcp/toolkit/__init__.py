"""The toolkit SDK: tools that run inside the gateway and reach upstreams only through the vault
(M4 design G).

A toolkit holds no secret, address or HTTP client. It declares named slots; the policy maps each
to a vault route and lists the paths and methods it may use there. A consequential tool shows the
human a plan of exact writes, and after an accept may send only those, once each.

Gateway-side: this package imports ``zoeymcp.common`` and the standard library only. Its one
exception is :mod:`zoeymcp.toolkit.testing`, which also uses the gateway's schema checks.
"""

from __future__ import annotations

from ..common.approvaltext import LayoutError, Plan, Show, Write
from .context import (
    PrepareContext,
    PrepareSlot,
    ToolContext,
    Toolkit,
    ToolkitError,
    ToolSpec,
    VaultError,
    VaultSlot,
)
from .params import Batch, MessageId, Range, Text
from .results import BatchResult, ItemResult, batch

__all__ = [
    "Batch",
    "BatchResult",
    "ItemResult",
    "LayoutError",
    "MessageId",
    "Plan",
    "PrepareContext",
    "PrepareSlot",
    "Range",
    "Show",
    "Text",
    "ToolContext",
    "ToolSpec",
    "Toolkit",
    "ToolkitError",
    "VaultError",
    "VaultSlot",
    "Write",
    "batch",
]
