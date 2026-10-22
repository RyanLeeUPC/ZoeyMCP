"""A tool's pin: the canonical digest of its projection under a domain tag (M3 design G.1).

The gateway pins what it projects (:mod:`zoeymcp.gateway.pins`, which re-exports these), and the
vault recomputes every pin a review report gives from the definition beside it (M7 design F.4,
fold-in C25), so both sides take the one function from here. The tag means a later projection can
never produce a v1 pin.

This module is pure and imports only :mod:`.canonical`: the vault and the gateway both import it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from . import canonical

PIN_TAG: Final = "tool-pin/1"


class ProjectionError(ValueError):
    """A tool the gateway can't project or pin. The message names the member, never its value."""


def pin_of(projection: Mapping[str, Any]) -> str:
    """The pin of a projection: ``sha256:`` and the hex digest of it under the domain tag."""
    try:
        return canonical.digest({"zoeymcp": PIN_TAG, "tool": projection})
    except canonical.JSONRejected as exc:
        raise ProjectionError(
            "the definition has no canonical form (an unsafe integer, a lone surrogate or too deep)"
        ) from exc
