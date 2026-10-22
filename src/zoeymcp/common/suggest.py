"""The classification a tool's own annotations suggest (M7 design F.6, CR-3; F-52). Pure.

One rule for every place that shows a suggestion: the gateway's review finding
(:mod:`zoeymcp.gateway.findings`), the CLI's choices file and the portal's review screen. ``allow``
only for a tool the server marks ``readOnlyHint: true`` without ``destructiveHint: true``,
``approve`` for any other hinted tool, and nothing for a tool with no hint. The hints are the
server's claims, not a judgement: a suggestion is shown labelled as the server's, pre-fills the
classification of a tool the operator includes, and never includes a tool itself (E-9, Q26).

The annotations may come from a report the vault didn't make, so anything but a mapping counts as
no hints, and ``readOnlyHint`` and ``destructiveHint`` count as set only when exactly ``true``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Literal

Suggestion = Literal["allow", "approve"]
# The annotation hints, by wire name, as gateway/pins.py pins and serves them.
HINTS: Final = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def suggestion(annotations: object) -> Suggestion | None:
    """The classification ``annotations`` suggest, or None when they hold no hint."""
    if not isinstance(annotations, Mapping) or not any(hint in annotations for hint in HINTS):
        return None
    read_only = annotations.get("readOnlyHint") is True
    destructive = annotations.get("destructiveHint") is True
    return "allow" if read_only and not destructive else "approve"
