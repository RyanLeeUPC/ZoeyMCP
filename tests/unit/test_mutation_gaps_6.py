"""Killing tests for mutants that survived M7's review-path modules on ce44a02 (step 12a).

``gateway.pins`` (moved in part to ``common.pinhash``) and ``gateway.findings`` (its suggestion
now ``common.suggest``'s) get their floors in step 12a (M7 design O.6, D-153). Each test names what
it pins. The mutants left alive on purpose are in :data:`EQUIVALENT`, each with why no test can
tell it from the original; :func:`test_each_equivalent_names_a_function` keeps the list honest
when a function is renamed or removed. mutmut still counts them as survivors, so they stay in each
module's score.
"""

from __future__ import annotations

import importlib
from typing import Any, Final

import pytest
from mcp.types import Tool, ToolAnnotations

from zoeymcp.common import pinhash
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.gateway import pins
from zoeymcp.gateway.findings import has_nested_quantifier, tool_findings

LIMITS = GatewayLimits()
_FALSY: Final = (
    "None for False: the value is only ever tested for truth, and has_nested_quantifier returns "
    "its own literals, never it"
)

EQUIVALENT: Final[dict[str, str]] = {
    # --- gateway.pins
    "zoeymcp.gateway.pins.x_text_problems__mutmut_6": (
        "is_key=None makes a key take a value's limits, but a key reaches _text_limits' special "
        'paths only as the last part of its own path, so the key is "name", "title" or '
        '"description" itself, which no limit refuses'
    ),
    "zoeymcp.gateway.pins.x_text_problems__mutmut_22": (
        "allow_tabs=True dropped: it is find_violations' default"
    ),
    # --- gateway.findings
    "zoeymcp.gateway.findings.x_has_nested_quantifier__mutmut_2": _FALSY,
    "zoeymcp.gateway.findings.x_has_nested_quantifier__mutmut_4": _FALSY,
    "zoeymcp.gateway.findings.x_has_nested_quantifier__mutmut_6": _FALSY,
    "zoeymcp.gateway.findings.x_has_nested_quantifier__mutmut_21": (
        "a group opened as None, not False: groups[-1] is only tested for truth, and a quantifier "
        "sets it to True either way"
    ),
}


def _function(key: str) -> tuple[str, str]:
    """A mutant key's module and function."""
    path, _, _ = key.partition("__mutmut_")
    module, _, name = path.rpartition(".x_")
    return module, name


@pytest.mark.parametrize("key", sorted(EQUIVALENT))
def test_each_equivalent_names_a_function(key: str) -> None:
    module_name, name = _function(key)
    assert callable(getattr(importlib.import_module(module_name), name)), key


# --- gateway.pins and common.pinhash ---------------------------------------------------------

WIRE: dict[str, Any] = {"name": "t", "inputSchema": {"type": "object"}}


def test_the_projection_errors_say_what_they_refuse() -> None:
    base = Tool.model_validate(WIRE)
    cases = [
        (base.model_copy(update={"name": "a b"}), "name is not a valid tool name"),
        (base.model_copy(update={"output_schema": "x"}), "outputSchema is not an object"),
        (
            base.model_copy(
                update={"annotations": ToolAnnotations().model_copy(update={"title": 5})}
            ),
            "annotations.title is not a string",
        ),
    ]
    for tool, message in cases:
        with pytest.raises(pins.ProjectionError) as caught:
            pins.project(tool)
        assert str(caught.value) == message


def test_a_definition_with_no_canonical_form_says_so() -> None:
    with pytest.raises(pinhash.ProjectionError) as caught:
        pinhash.pin_of({"name": "t", "n": 2**53})
    assert str(caught.value) == (
        "the definition has no canonical form (an unsafe integer, a lone surrogate or too deep)"
    )


def test_a_later_hint_is_kept_when_an_earlier_one_is_absent() -> None:
    tool = Tool.model_validate({**WIRE, "annotations": {"destructiveHint": True}})
    assert pins.project(tool)["annotations"] == {"destructiveHint": True}


def test_a_name_has_its_own_limits() -> None:
    long = pins.text_problems({"name": "n" * 129})
    assert [str(problem) for problem in long] == ["/name: too long: 129 characters, limit 128"]
    assert [str(problem) for problem in pins.text_problems({"name": "a\nb"})] == [
        "/name: line break in a single-line field U+000A (unnamed) at position 1"
    ]


def test_an_input_schema_is_checked_as_one() -> None:
    reasons = pins.tool_problems({"name": "t", "inputSchema": {"type": "string"}}, LIMITS)
    assert reasons
    assert all(reason.startswith("/inputSchema") for reason in reasons)


def _server(include: list[str]) -> ViewRemoteServer:
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": include, "allow": include, "approve": []},
            "review": {},
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


def test_every_duplicated_name_is_reported() -> None:
    listing = [Tool.model_validate({**WIRE, "name": name}) for name in ("a", "a", "b", "b")]
    reports = pins.evaluate(listing, _server([]), frozenset(), LIMITS).reports
    assert [(report.kind, report.tool) for report in reports] == [
        ("duplicate", "a"),
        ("duplicate", "b"),
    ]


def test_a_tool_after_an_unprojectable_one_is_evaluated() -> None:
    bad = Tool.model_validate(WIRE).model_copy(update={"name": "a b"})
    listing = [bad, Tool.model_validate({**WIRE, "name": "good"})]
    reports = pins.evaluate(listing, _server([]), frozenset(), LIMITS).reports
    assert [(report.kind, report.tool) for report in reports] == [
        ("invalid", "a b"),
        ("unreviewed", "good"),
    ]


# --- gateway.findings ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "nested"),
    [
        ("([a+])+", False),  # a quantifier inside a class quantifies nothing
        ("[a](b+)+", True),  # a class ends at its "]"
        ("(a+)X", False),  # only *, + and { quantify
        (r"\.(a+)+", True),  # an escape covers one character
    ],
)
def test_classes_escapes_and_quantifiers(pattern: str, nested: bool) -> None:
    assert has_nested_quantifier(pattern) is nested


def test_an_output_schema_is_read_without_an_input_schema() -> None:
    definition = {
        "name": "t",
        "outputSchema": {"type": "object", "properties": {"v": {"pattern": "a"}}},
    }
    assert [(f.level, f.pointer) for f in tool_findings(definition, LIMITS)] == [
        ("note", "/outputSchema/properties/v/pattern")
    ]
