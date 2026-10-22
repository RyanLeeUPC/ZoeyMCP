"""The shared suggestion rule (M7 design F.6, CR-3; F-52): what a tool's annotations suggest, the
same for the gateway's review finding, the CLI and the portal."""

from __future__ import annotations

import itertools
from types import MappingProxyType
from typing import Any

import pytest

from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.suggest import HINTS, suggestion
from zoeymcp.gateway import pins
from zoeymcp.gateway.findings import tool_findings


@pytest.mark.parametrize(
    ("annotations", "suggested"),
    [
        ({"readOnlyHint": True}, "allow"),
        ({"readOnlyHint": True, "destructiveHint": False}, "allow"),
        ({"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True}, "allow"),
        ({"readOnlyHint": False}, "approve"),
        ({"destructiveHint": True}, "approve"),
        ({"destructiveHint": False}, "approve"),
        ({"idempotentHint": True}, "approve"),
        ({"openWorldHint": False}, "approve"),
        # The contradictory tool: read-only and destructive. Never allow.
        ({"readOnlyHint": True, "destructiveHint": True}, "approve"),
        # Only an exact true counts, as a report the vault didn't make may hold anything.
        ({"readOnlyHint": "true"}, "approve"),
        ({"readOnlyHint": 1}, "approve"),
        ({"readOnlyHint": True, "destructiveHint": "yes"}, "allow"),
        ({"readOnlyHint": None}, "approve"),
        ({"title": "Notes", "readOnlyHint": True}, "allow"),
    ],
)
def test_a_hinted_tool(annotations: dict[str, Any], suggested: str) -> None:
    assert suggestion(annotations) == suggested
    assert suggestion(MappingProxyType(annotations)) == suggested


@pytest.mark.parametrize(
    "annotations",
    [{}, {"title": "Notes"}, {"readonlyhint": True}, None, [], ["readOnlyHint"], "readOnlyHint"],
)
def test_no_hint_no_suggestion(annotations: object) -> None:
    assert suggestion(annotations) is None


def test_the_hints_are_the_ones_pinned() -> None:
    assert tuple(member for member, _ in pins.HINTS) == HINTS


def test_the_gateways_finding_states_the_shared_suggestion() -> None:
    """Every combination of hints, absent, true or false: the review note names what the shared
    rule suggests, and there is a note exactly when there is a suggestion."""
    definition: dict[str, Any] = {"name": "t", "inputSchema": {"type": "object"}}
    for values in itertools.product((None, True, False), repeat=len(HINTS)):
        annotations = {
            hint: value for hint, value in zip(HINTS, values, strict=True) if value is not None
        }
        notes = [
            finding.message
            for finding in tool_findings(
                {**definition, "annotations": annotations}, GatewayLimits()
            )
            if finding.pointer == "/annotations"
        ]
        suggested = suggestion(annotations)
        if suggested is None:
            assert notes == [], annotations
        else:
            [note] = notes
            assert note.startswith(f"suggested by the server: {suggested} ("), annotations
