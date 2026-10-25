"""A definition's pin: the canonical digest of its projection under a domain tag (M3 design G.1,
M6 design L.2).

The gateway pins what it projects (:mod:`zoeymcp.gateway.pins`, which re-exports these), and the
vault recomputes every pin a review report gives from the definition beside it (M7 design F.4,
fold-in C25), so both sides take the one function from here. The tag means a later projection can
never produce a v1 pin. Each kind has its own tag and its own member beside it (``tool``,
``prompt``, ``resource_template``, ``resource``), so a prompt can never share a pin with a tool, a
template or a resource of the same name and members.

This module is pure and imports only :mod:`.canonical`: the vault and the gateway both import it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from . import canonical

PIN_TAG: Final = "tool-pin/1"
PROMPT_PIN_TAG: Final = "prompt-pin/1"
TEMPLATE_PIN_TAG: Final = "resource-template-pin/1"
RESOURCE_PIN_TAG: Final = "resource-pin/1"


class ProjectionError(ValueError):
    """A definition the gateway can't project or pin. The message names the member, never its
    value."""


def _pinned(tag: str, kind: str, projection: Mapping[str, Any]) -> str:
    try:
        return canonical.digest({"zoeymcp": tag, kind: projection})
    except canonical.JSONRejected as exc:
        raise ProjectionError(
            "the definition has no canonical form (an unsafe integer, a lone surrogate or too deep)"
        ) from exc


def pin_of(projection: Mapping[str, Any]) -> str:
    """The pin of a tool's projection: ``sha256:`` and the hex digest of it under the domain
    tag."""
    return _pinned(PIN_TAG, "tool", projection)


def prompt_pin_of(projection: Mapping[str, Any]) -> str:
    """The pin of a prompt's projection (L.2: ``name``, ``title``, ``description``,
    ``arguments``)."""
    return _pinned(PROMPT_PIN_TAG, "prompt", projection)


def template_pin_of(projection: Mapping[str, Any]) -> str:
    """The pin of a resource template's projection (L.2: ``uriTemplate`` and its metadata)."""
    return _pinned(TEMPLATE_PIN_TAG, "resource_template", projection)


def resource_pin_of(projection: Mapping[str, Any]) -> str:
    """The pin of a fixed resource's projection (L.2: ``uri`` and its metadata)."""
    return _pinned(RESOURCE_PIN_TAG, "resource", projection)
