"""``zoeymcp review`` for a toolkit server (M4 design H.6): the report, the text, and a snippet
that ``check`` accepts once pasted over the server's entry."""

from __future__ import annotations

import copy
import importlib.metadata
from pathlib import Path
from typing import Any

import pytest
import yaml

from zoeymcp.cli import review as view
from zoeymcp.common.policy import Policy, check_policy, parse_policy
from zoeymcp.common.policy.view import ViewToolkitServer, build_view
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.review import toolkit_report
from zoeymcp.gateway.toolkits import Loaded, Toolkits
from zoeymcp.gateway.vaultlink import parse_link

ENTRY = importlib.metadata.EntryPoint("mail", "example_toolkits.mail:toolkit", "zoeymcp.toolkits")


def reviewed(tmp_path: Path, raw: dict[str, Any]) -> dict[str, Any]:
    """The gateway's review of the example's ``mail`` server under ``raw``."""
    gateway = build_view(Policy.model_validate(raw)).gateway
    toolkits = Toolkits(
        parse_link("http://vault:8080"),
        None,
        DriftMarks.load(tmp_path),
        entry_points=lambda: [ENTRY],
        allow_writable=True,
    )
    toolkits.apply(gateway)
    loaded = toolkits.get("mail")
    assert isinstance(loaded, Loaded)
    policy = gateway.servers["mail"]
    assert isinstance(policy, ViewToolkitServer)
    return toolkit_report("mail", loaded, policy, marks=frozenset(), limits=gateway.limits)


def pasted(raw: dict[str, Any], lines: list[str]) -> dict[str, Any]:
    """``raw`` with the snippet's entry merged over the server's, as an operator would."""
    entry = yaml.safe_load("\n".join(lines))["gateway"]["servers"]["mail"]
    merged = copy.deepcopy(raw)
    merged["gateway"]["servers"]["mail"].update(entry)
    return merged


def errors(raw: dict[str, Any]) -> list[str]:
    policy = parse_policy(yaml.safe_dump(raw, sort_keys=False), "test")
    return [f"{f.path}: {f.message}" for f in check_policy(policy) if f.level == "error"]


def test_the_example_reviews_clean(tmp_path: Path, example_raw: dict[str, Any]) -> None:
    answer = reviewed(tmp_path, example_raw)
    assert (answer["kind"], answer["module"], answer["clean"]) == (
        "toolkit",
        "example_toolkits.mail",
        True,
    )
    [tool] = answer["tools"]
    assert (tool["state"], tool["consequential"], tool["classification"]) == (
        "ok",
        True,
        "approve",
    )
    lines = view.render(answer, view.Choices())
    assert lines[0].startswith("server mail  (toolkit example_toolkits.mail, ")
    assert lines[0].endswith("pinning required)")
    assert any("consequential" in line for line in lines)
    assert errors(pasted(example_raw, view.snippet(answer, view.Choices()))) == []


def test_add_puts_a_consequential_tool_into_approve(
    tmp_path: Path, example_raw: dict[str, Any]
) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["mail"]["tools"] = {}
    raw["gateway"]["servers"]["mail"]["review"] = {}
    answer = reviewed(tmp_path, raw)
    [tool] = answer["tools"]
    assert (tool["state"], tool["included"]) == ("unreviewed", False)
    choices = view.Choices(add=("send_note",))
    view.check_choices(answer, choices)
    lines = view.snippet(answer, choices)
    assert "        approve: [send_note]" in lines
    assert "        # send_note: approve, declared by the toolkit" in lines
    assert errors(pasted(raw, lines)) == []
    assert (
        pasted(raw, lines)["gateway"]["servers"]["mail"]["review"]
        == example_raw["gateway"]["servers"]["mail"]["review"]
    )


def test_pinning_off_writes_no_pins_and_prints_definitions(
    tmp_path: Path, example_raw: dict[str, Any]
) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["mail"].update(pinning="off", review={})
    answer = reviewed(tmp_path, raw)
    assert answer["tools"][0]["state"] == "ok"
    lines = view.render(answer, view.Choices())
    assert any(line.startswith("definition send_note (sha256:") for line in lines)
    snippet = view.snippet(answer, view.Choices())
    assert not any(line.strip().startswith("send_note: sha256:") for line in snippet)
    assert errors(pasted(raw, snippet)) == []


@pytest.mark.parametrize("pinning", ["required", "off"])
def test_a_tool_the_policy_allows_against_the_code(
    tmp_path: Path, example_raw: dict[str, Any], pinning: str
) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["mail"]["tools"] = {"include": ["send_note"], "allow": ["send_note"]}
    if pinning == "off":
        raw["gateway"]["servers"]["mail"].update(pinning="off", review={})
    answer = reviewed(tmp_path, raw)
    [tool] = answer["tools"]
    assert tool["state"] == "invalid"
    assert {f["message"] for f in tool["findings"]} >= {
        "consequential in the toolkit's code, so it can't be in allow"
    }
    assert answer["clean"] is False
