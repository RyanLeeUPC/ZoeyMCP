"""The review report the vault accepts from the gateway (M7 design F.4): both shapes, straight
from the gateway's review code, the caps that follow the limits, and the pins recomputed; and
M6's additions (design J.1): a drift entry's reviewed definition, checked against the policy's
pin, the policy's pins and declines, ``offered``, and an M7 report, with none of them, still
read."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, get_args

import pytest
from mcp.types import Implementation, ServerCapabilities, Tool

from tests.unit.test_review import LIMITS, pin, policy, reviewed, tool
from tests.unit.test_review_toolkits import reviewed as toolkit_reviewed
from zoeymcp.cli import review as cli_review
from zoeymcp.common import canonical, pinhash
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.reviewreport import (
    DEFINITION_TEXT_BYTES,
    DISTRIBUTION_MAX,
    FINDINGS_MAX,
    INSTRUCTIONS_MAX,
    LISTED_NAME_MAX,
    MESSAGE_MAX,
    NAMES_MAX,
    POINTER_MAX,
    PROTOCOL_VERSIONS,
    REPORT_BYTES_MAX,
    REPORT_BYTES_MIN,
    TEXT_MAX,
    ProtocolVersion,
    RemoteReport,
    ReportRefused,
    ToolkitReport,
    check_length,
    definition_max,
    fit,
    read,
    report_max,
)
from zoeymcp.gateway import access, pins, review

PIN0 = "sha256:" + "0" * 64


def wired(answer: dict[str, Any]) -> dict[str, Any]:
    """``answer`` as the vault receives it: through JSON."""
    loaded: dict[str, Any] = json.loads(json.dumps(answer))
    return loaded


def unclassified(*names: str, **extra: Any) -> dict[str, Any]:
    """The report of a server listing ``names`` whose include list is empty."""
    return wired(reviewed([tool(name) for name in names], policy([], {}), **extra))


def refused(data: object, limits: GatewayLimits = LIMITS) -> ReportRefused:
    with pytest.raises(ReportRefused) as caught:
        read(data, limits)
    return caught.value


def invalid(data: object, limits: GatewayLimits = LIMITS) -> str:
    """The detail of a ``review_invalid`` refusal."""
    refusal = refused(data, limits)
    assert refusal.reason == "review_invalid", refusal
    assert refusal.tools == ()
    return refusal.detail


# --- the two shapes --------------------------------------------------------------------------


def test_a_report_straight_from_the_review_with_nothing_included() -> None:
    """CR-9, F-56: every tool unclassified, as JSON null."""
    data = unclassified("list_notes", "delete_note")
    assert [entry["classification"] for entry in data["tools"]] == [None, None]
    report = read(data, LIMITS)
    assert isinstance(report, RemoteReport)
    assert (report.server, report.kind, report.vault_path) == ("notes", "remote", "/notes/mcp")
    assert [(e.kind, e.name, e.state, e.classification) for e in report.tools] == [
        ("tool", "delete_note", "unreviewed", None),
        ("tool", "list_notes", "unreviewed", None),
    ]
    assert report.tools[1].pin == pin("list_notes")
    assert report.tools[1].definition == pins.project(tool("list_notes"))
    assert report.policy.include == []


def test_every_state_the_review_writes_reads_back() -> None:
    old = pins.project_and_pin(tool("drifts")).definition
    server = policy(
        ["fine", "drifts", "gone", "bad", "twice", "held"],
        {name: pin(name) for name in ("fine", "drifts", "gone", "bad", "twice", "held")},
    )
    tools = [
        tool("fine"),
        tool("drifts", "Does another thing."),
        tool("bad", "Hidden\u200b text."),
        tool("twice"),
        tool("twice", "Again."),
        tool("extra"),
        tool("held"),
    ]
    data = wired(
        reviewed(
            tools,
            server,
            marks=frozenset({("held", pin("held"))}),
            defs={pin("drifts"): old},
            server_info=None,
            instructions="Use the notes tools.",
        )
    )
    report = read(data, LIMITS)
    assert isinstance(report, RemoteReport)
    states = {entry.name: entry.state for entry in report.tools}
    assert states == {
        "fine": "ok",
        "drifts": "drift",
        "bad": "invalid",
        "twice": "duplicate",
        "extra": "unreviewed",
        "gone": "missing",
        "held": "marked",
    }
    drifts = next(entry for entry in report.tools if entry.name == "drifts")
    assert drifts.changed == ["description"]
    assert drifts.diff is not None
    assert drifts.diff[:2] == ["--- reviewed", "+++ listed"]
    assert report.instructions == "Use the notes tools."
    assert report.marked == ["drifts", "held"]
    assert drifts.reviewed == old
    assert [entry.name for entry in report.tools if entry.reviewed is not None] == ["drifts"]
    assert report.policy.review == {name: pin(name) for name in server.review}
    assert (report.policy.declined, report.offered) == ({}, None)


def test_a_blocked_server_and_server_info() -> None:
    server = policy(["fine"], {"fine": pin("fine", "Another.")}, on_drift="fail")
    data = wired(
        reviewed(
            [tool("fine")],
            server,
            server_info=Implementation(name="notes", version="1.2", title="Notes"),
            protocol_version="2025-06-18",
            era="legacy",
        )
    )
    report = read(data, LIMITS)
    assert isinstance(report, RemoteReport)
    assert report.blocked is True
    assert report.server_info is not None
    assert (report.server_info.name, report.server_info.title) == ("notes", "Notes")
    assert (report.era, report.protocol_version) == ("legacy", "2025-06-18")


def test_a_toolkit_report(tmp_path: Path, example_raw: dict[str, Any]) -> None:
    """COV-1: a toolkit's own shape, its entries carrying ``consequential``."""
    data = wired(toolkit_reviewed(tmp_path, example_raw))
    report = read(data, LIMITS)
    assert isinstance(report, ToolkitReport)
    assert (report.kind, report.module, report.pinning) == (
        "toolkit",
        "example_toolkits.mail",
        "required",
    )
    [entry] = report.tools
    assert (entry.kind, entry.name, entry.consequential, entry.classification) == (
        "tool",
        "send_note",
        True,
        "approve",
    )
    assert (report.slots, report.policy.include) == (["mail"], ["send_note"])


def test_a_toolkit_entry_needs_consequential_and_a_remote_one_has_none(
    tmp_path: Path, example_raw: dict[str, Any]
) -> None:
    data = wired(toolkit_reviewed(tmp_path, example_raw))
    del data["tools"][0]["consequential"]
    assert invalid(data) == "at toolkit.tools[0].consequential"
    remote = unclassified("a")
    remote["tools"][0]["consequential"] = False
    assert invalid(remote) == "at remote.tools[0].consequential"


def test_the_entry_kind_is_a_tool() -> None:
    data = unclassified("a")
    data["tools"][0]["kind"] = "tool"
    assert read(data, LIMITS).tools[0].kind == "tool"
    data["tools"][0]["kind"] = "resource"
    assert invalid(data) == "at remote.tools[0].kind"


@pytest.mark.parametrize(
    ("change", "location"),
    [
        ({"kind": "bridge"}, "(document)"),
        ({"server": "Notes"}, "remote.server"),
        ({"era": "auto"}, "remote.era"),
        ({"asserted_era": "new"}, "remote.asserted_era"),
        ({"protocol_version": "2024-11-05"}, "remote.protocol_version"),
        ({"vault_path": "notes/mcp"}, "remote.vault_path"),
        ({"blocked": 0}, "remote.blocked"),
        ({"clean": "true"}, "remote.clean"),
        ({"marked": ["a b"]}, "remote.marked[0]"),
        ({"instructions": 5}, "remote.instructions"),
        (
            {"policy": {"include": [], "allow": [], "approve": [], "on_drift": "x"}},
            "remote.policy.on_drift",
        ),
        ({"extra": 1}, "remote.extra"),
    ],
)
def test_a_report_field_out_of_shape(change: dict[str, Any], location: str) -> None:
    data = unclassified("a")
    data.update(change)
    assert invalid(data) == f"at {location}"


@pytest.mark.parametrize(
    ("change", "location"),
    [
        ({"classification": "deny"}, "remote.tools[0].classification"),
        ({"state": "hidden"}, "remote.tools[0].state"),
        ({"included": 1}, "remote.tools[0].included"),
        ({"name": "a b"}, "remote.tools[0]"),
        ({"name": "x" * (LISTED_NAME_MAX + 1)}, "remote.tools[0].name"),
        ({"pinned": "sha256:abc"}, "remote.tools[0].pinned"),
        ({"definition": []}, "remote.tools[0].definition"),
        (
            {"findings": [{"level": "fatal", "pointer": "", "message": "x"}]},
            "remote.tools[0].findings[0].level",
        ),
        ({"findings": [{"level": "note", "pointer": ""}]}, "remote.tools[0].findings[0].message"),
        ({"changed": "description"}, "remote.tools[0].changed"),
        ({"diff": [1]}, "remote.tools[0].diff[0]"),
    ],
)
def test_an_entry_field_out_of_shape(change: dict[str, Any], location: str) -> None:
    data = unclassified("a")
    data["tools"][0].update(change)
    assert invalid(data) == f"at {location}"


def test_not_a_report() -> None:
    assert invalid("report") == "at (document)"
    assert invalid({"kind": "remote"}).startswith("at remote.asserted_era, remote.blocked, ")


def test_a_refusal_names_locations_never_values() -> None:
    data = unclassified("a")
    data["\u202eevil"] = 1
    data["tools"][0]["x" * 129] = 1
    detail = invalid(data)
    assert detail == "at remote.?, remote.tools[0].?"
    assert "evil" not in detail


def test_at_most_five_locations_are_named() -> None:
    data = unclassified("a")
    for key in ("k1", "k2", "k3", "k4", "k5", "k6", "k7"):
        data[key] = 1
    assert invalid(data) == "at remote.k1, remote.k2, remote.k3, remote.k4, remote.k5 and 2 more"
    del data["k6"], data["k7"]
    assert invalid(data) == "at remote.k1, remote.k2, remote.k3, remote.k4, remote.k5"


# --- the names a server lists ----------------------------------------------------------------


def bare(name: str) -> Tool:
    return Tool(name=name, inputSchema={"type": "object"})


def test_names_that_arent_tool_names_read_as_the_review_reports_them() -> None:
    """review.py writes an entry under every name the server lists: one that isn't a tool name
    is the invalid tool, or the duplicate one, it reports, with no pin."""
    long = "x" * 129
    listing = [tool("a"), bare("get weather"), bare(long), bare("tw ice"), bare("tw ice")]
    report = read(wired(reviewed(listing, policy([], {}))), LIMITS)
    assert {(entry.name, entry.state, entry.pin) for entry in report.tools} == {
        ("a", "unreviewed", pin("a")),
        ("get weather", "invalid", None),
        (long, "invalid", None),
        ("tw ice", "duplicate", None),
    }


def test_only_an_unpinnable_entry_has_a_name_that_isnt_one() -> None:
    data = wired(reviewed([bare("get weather")], policy([], {})))
    for state in ("ok", "marked", "blocked", "drift", "unreviewed", "missing"):
        data["tools"][0]["state"] = state
        assert invalid(data) == "at remote.tools[0]"
    data["tools"][0]["state"] = "duplicate"
    read(data, LIMITS)
    data = unclassified("a")
    entry = data["tools"][0]
    entry["name"] = entry["definition"]["name"] = "a b"
    entry.update(state="invalid", pin=pinhash.pin_of(entry["definition"]))
    assert invalid(data) == "at remote.tools[0]"


def test_a_listed_name_is_capped() -> None:
    data = wired(reviewed([bare("x" * LISTED_NAME_MAX)], policy([], {})))
    read(data, LIMITS)
    data["tools"][0]["name"] += "x"
    assert invalid(data) == "at remote.tools[0].name"


# --- a pin and its definition --------------------------------------------------------------


def test_a_pin_comes_with_its_definition() -> None:
    data = unclassified("a")
    no_definition = copy.deepcopy(data)
    no_definition["tools"][0]["definition"] = None
    assert invalid(no_definition) == "at remote.tools[0]"
    no_pin = copy.deepcopy(data)
    no_pin["tools"][0]["pin"] = None
    assert invalid(no_pin) == "at remote.tools[0]"
    neither = copy.deepcopy(data)
    neither["tools"][0].update(pin=None, definition=None)
    assert read(neither, LIMITS).tools[0].pin is None


def test_a_definition_is_its_own_tools() -> None:
    data = unclassified("a", "b")
    data["tools"][0]["definition"], data["tools"][1]["definition"] = (
        data["tools"][1]["definition"],
        data["tools"][0]["definition"],
    )
    assert invalid(data) == "at remote.tools[0], remote.tools[1]"


def test_one_bad_pin_refuses_the_whole_report() -> None:
    """X11, fold-in C25: the vault recomputes every pin; each mismatch is named."""
    data = unclassified("a", "b", "c")
    data["tools"][0]["pin"] = PIN0
    data["tools"][2]["definition"]["description"] = "Does another thing."
    refusal = refused(data)
    assert refusal.reason == "pin_mismatch"
    assert refusal.tools == ("a", "c")
    assert refusal.detail == "a reported pin isn't the pin of its definition"
    assert str(refusal) == "pin_mismatch: a reported pin isn't the pin of its definition"


def test_a_definition_with_no_pin_form_is_a_mismatch() -> None:
    """Canonical JSON one level short of the pin's depth limit: the gateway couldn't have pinned
    it, so whatever pin it reports is wrong."""
    deep: dict[str, Any] = {}
    for _ in range(62):
        deep = {"a": deep}
    data = unclassified("a", "b")
    data["tools"][0]["definition"]["inputSchema"] = deep
    with pytest.raises(pinhash.ProjectionError):
        pinhash.pin_of(data["tools"][0]["definition"])
    data["tools"][1]["pin"] = PIN0
    assert refused(data).tools == ("a", "b")


def test_a_bad_pin_after_an_entry_with_no_definition() -> None:
    data = wired(reviewed([tool("a"), tool("a", "Again."), tool("b")], policy([], {})))
    assert [entry["definition"] is None for entry in data["tools"]] == [True, False]
    data["tools"][1]["pin"] = PIN0
    assert refused(data).tools == ("b",)


def test_a_definition_with_no_canonical_form_is_invalid() -> None:
    data = unclassified("a", "b")
    for entry in data["tools"]:
        entry["definition"]["inputSchema"]["maximum"] = 2**53
    assert invalid(data) == (
        "at tools[0].definition (no canonical form), tools[1].definition (no canonical form)"
    )


# --- caps from the limits (GR-30) ------------------------------------------------------------


@pytest.mark.parametrize(
    ("tools", "most"),
    [
        (1, REPORT_BYTES_MIN),
        (512, REPORT_BYTES_MIN),
        (513, 513 * 16 * 1024),
        (4096, REPORT_BYTES_MAX),
        (4097, REPORT_BYTES_MAX),
        (10_000, REPORT_BYTES_MAX),
    ],
)
def test_the_body_cap_follows_the_limits(tools: int, most: int) -> None:
    limits = GatewayLimits(max_tools_per_server=tools)
    assert report_max(limits) == most
    check_length(most, limits)
    with pytest.raises(ReportRefused) as caught:
        check_length(most + 1, limits)
    assert (caught.value.reason, caught.value.detail) == (
        "review_too_large",
        f"a report is at most {most} bytes (gateway.limits)",
    )


def test_the_body_cap_constants() -> None:
    assert (REPORT_BYTES_MIN, REPORT_BYTES_MAX) == (8 * 2**20, 64 * 2**20)


def test_at_most_max_tools_per_server_listed() -> None:
    limits = GatewayLimits(max_tools_per_server=2)
    read(unclassified("a", "b"), limits)
    assert invalid(unclassified("a", "b", "c"), limits) == (
        "at tools (more than gateway.limits.max_tools_per_server listed)"
    )


def test_missing_tools_beside_a_full_listing() -> None:
    """An included tool the server no longer lists is reported missing on top of the listing."""
    limits = GatewayLimits(max_tools_per_server=1)
    data = wired(reviewed([tool("a")], policy(["a", "b"], {"a": pin("a"), "b": PIN0})))
    assert [entry["state"] for entry in data["tools"]] == ["ok", "missing"]
    read(data, limits)
    data["policy"]["include"] = ["b"]
    read(data, limits)
    data["policy"]["include"] = []
    assert invalid(data, limits) == "at tools (more missing than the policy includes)"


def test_the_entry_list_is_capped_before_the_limits() -> None:
    """Twice the most tools a server may list, for the missing ones; any more isn't counted."""
    limits = GatewayLimits(max_tools_per_server=NAMES_MAX)
    data = unclassified("a")
    entry = {**data["tools"][0], "pin": None, "definition": None}
    data["tools"] = [{**entry, "name": f"t{index}"} for index in range(2 * NAMES_MAX)]
    assert invalid(data, limits) == (
        "at tools (more than gateway.limits.max_tools_per_server listed)"
    )
    data["tools"].append({**entry, "name": "t"})
    assert invalid(data, limits) == "at remote.tools"


@pytest.mark.parametrize("path", [("policy", "include"), ("policy", "allow"), ("marked",)])
def test_name_lists_are_capped(path: tuple[str, ...]) -> None:
    data = unclassified("a")
    *parents, member = path
    holder = data
    for parent in parents:
        holder = holder[parent]
    names = [f"t{index}" for index in range(NAMES_MAX)]
    holder[member] = names
    read(data, LIMITS)
    holder[member] = [*names, "t"]
    assert invalid(data) == "at remote." + ".".join(path)


def test_a_toolkits_lists_and_text_are_capped(tmp_path: Path, example_raw: dict[str, Any]) -> None:
    data = wired(toolkit_reviewed(tmp_path, example_raw))
    slots = [f"s{index}" for index in range(NAMES_MAX)]
    data.update(slots=slots, distribution="d" * DISTRIBUTION_MAX, version="v" * DISTRIBUTION_MAX)
    data["policy"]["approve"] = [f"t{index}" for index in range(NAMES_MAX)]
    read(data, LIMITS)
    for member, value in (
        ("slots", [*slots, "s"]),
        ("distribution", "d" * (DISTRIBUTION_MAX + 1)),
        ("version", "v" * (DISTRIBUTION_MAX + 1)),
    ):
        assert invalid({**data, member: value}) == f"at toolkit.{member}"
    data["policy"]["approve"].append("t")
    assert invalid(data) == "at toolkit.policy.approve"


def test_a_tool_reported_twice() -> None:
    data = unclassified("a")
    data["tools"].append(copy.deepcopy(data["tools"][0]))
    assert invalid(data) == "at tools (a tool twice)"


@pytest.mark.parametrize(
    ("schema_bytes", "most"),
    [(64 * 1024, 4 * 64 * 1024), (1024, 2 * 1024 + DEFINITION_TEXT_BYTES)],
)
def test_the_definition_cap(schema_bytes: int, most: int) -> None:
    limits = GatewayLimits(max_schema_bytes=schema_bytes)
    assert definition_max(limits) == most
    data = unclassified("a")
    definition = data["tools"][0]["definition"]
    size = len(canonical.dumps_canonical(definition))
    definition["description"] += "x" * (most - size)
    data["tools"][0]["pin"] = pinhash.pin_of(definition)
    read(data, limits)
    definition["description"] += "x"
    data["tools"][0]["pin"] = pinhash.pin_of(definition)
    assert invalid(data, limits) == f"at tools[0].definition (over {most} bytes)"


def test_a_valid_tools_text_fits_the_smallest_schema_limit() -> None:
    """Every text member at its length in 4-byte characters, beside two schemas at the limit."""
    limits = GatewayLimits(max_schema_bytes=1024)
    name = "n" * pins.MAX_NAME_CHARS
    data = unclassified(name)
    wide = "\U0001f600"
    schema: dict[str, Any] = {"type": "object", "description": ""}
    schema["description"] = "d" * (1024 - len(canonical.dumps_canonical(schema)))
    assert len(canonical.dumps_canonical(schema)) == 1024
    definition = {
        "name": name,
        "title": wide * pins.MAX_TITLE_CHARS,
        "description": wide * pins.MAX_DESCRIPTION_CHARS,
        "inputSchema": schema,
        "outputSchema": schema,
        "annotations": {"title": wide * pins.MAX_TITLE_CHARS, "readOnlyHint": True},
    }
    assert pins.tool_problems(definition, limits) == []
    data["tools"][0].update(definition=definition, pin=pinhash.pin_of(definition))
    assert len(canonical.dumps_canonical(definition)) > 4 * 1024
    read(data, limits)


def test_the_diff_cap() -> None:
    limits = GatewayLimits(max_schema_bytes=64 * 1024)
    most = 16 * definition_max(limits)
    data = unclassified("a")
    data["tools"][0]["diff"] = ["x" * (most - 1), "y"]
    read(data, limits)
    data["tools"][0]["diff"] = ["x" * most, "y"]
    assert invalid(data, limits) == f"at tools[0].diff (over {most} characters)"


def test_findings_are_capped() -> None:
    finding = {"level": "note", "pointer": "/" + "p" * 255, "message": "m" * 1000}
    data = unclassified("a")
    data["tools"][0]["findings"] = [finding] * 64
    read(data, LIMITS)
    data["tools"][0]["findings"] = [finding] * 65
    assert invalid(data) == "at remote.tools[0].findings"
    for member, value in (("pointer", "/" + "p" * 256), ("message", "m" * 1001)):
        data["tools"][0]["findings"] = [{**finding, member: value}]
        assert invalid(data) == f"at remote.tools[0].findings[0].{member}"


def test_changed_members_are_capped() -> None:
    data = unclassified("a")
    data["tools"][0]["changed"] = ["m" * 128] * 16
    read(data, LIMITS)
    data["tools"][0]["changed"] = ["m"] * 17
    assert invalid(data) == "at remote.tools[0].changed"
    data["tools"][0]["changed"] = ["m" * 129]
    assert invalid(data) == "at remote.tools[0].changed[0]"


def test_instructions_as_the_review_cuts_them() -> None:
    """review.report() keeps 16,384 characters and marks the cut with "..."."""
    data = unclassified("a", instructions="i" * (TEXT_MAX + 50))
    assert len(data["instructions"]) == INSTRUCTIONS_MAX == TEXT_MAX + 3
    read(data, LIMITS)
    data["instructions"] += "i"
    assert invalid(data) == "at remote.instructions"


def test_server_info_strings_are_capped() -> None:
    data = unclassified("a")
    data["server_info"] = {"name": "n" * TEXT_MAX, "version": "v" * TEXT_MAX, "title": None}
    read(data, LIMITS)
    for member in ("name", "version", "title"):
        data["server_info"] = {"name": "n", "version": "v", member: "x" * (TEXT_MAX + 1)}
        assert invalid(data) == f"at remote.server_info.{member}"


def test_the_protocol_versions_are_the_gateways() -> None:
    assert set(PROTOCOL_VERSIONS) == set(get_args(ProtocolVersion)) == access.SUPPORTED_VERSIONS


# --- fitting the gateway's answer to the caps ------------------------------------------------


def patterned(name: str, *properties: str) -> Tool:
    """A tool whose input schema has a string property with a pattern under each name."""
    schema = {
        "type": "object",
        "properties": {member: {"type": "string", "pattern": "^a$"} for member in properties},
    }
    return Tool(name=name, description="Does a thing.", inputSchema=schema)


def test_an_answer_that_fits_is_unchanged(tmp_path: Path, example_raw: dict[str, Any]) -> None:
    data = unclassified(
        "a",
        "b",
        server_info=Implementation(name="n" * TEXT_MAX, version="1.2", title="Notes"),
        instructions="i" * (TEXT_MAX + 50),
    )
    kept = copy.deepcopy(data)
    assert fit(data, LIMITS) == kept
    assert data == kept
    toolkit = wired(toolkit_reviewed(tmp_path, example_raw))
    toolkit.update(distribution="d" * DISTRIBUTION_MAX, version=None)
    assert fit(toolkit, LIMITS) == toolkit


def test_an_over_cap_definition_goes_for_an_error() -> None:
    """A description far over its limit: the tool is invalid, and its definition goes."""
    data = wired(reviewed([tool("a"), tool("big", "word " * 60_000)], policy([], {})))
    most = definition_max(LIMITS)
    assert invalid(data) == f"at tools[1].definition (over {most} bytes)"
    fitted = fit(data, LIMITS)
    assert fitted["tools"][0] == data["tools"][0]
    big = fitted["tools"][1]
    assert (big["state"], big["pin"], big["definition"]) == ("invalid", None, None)
    assert big["findings"] == [
        {
            "level": "error",
            "pointer": "",
            "message": f"the definition is over {most} bytes, more than a review report carries",
        },
        *data["tools"][1]["findings"],
    ]
    read(fitted, LIMITS)


def test_the_definition_cap_when_fitting() -> None:
    data = unclassified("a")
    entry = data["tools"][0]
    entry.update(state="drift", changed=["description"], diff=["--- reviewed"])
    most = definition_max(LIMITS)
    definition = entry["definition"]
    definition["description"] += "x" * (most - len(canonical.dumps_canonical(definition)))
    entry["pin"] = pinhash.pin_of(definition)
    assert fit(data, LIMITS) == data
    definition["description"] += "x"
    [fitted] = fit(data, LIMITS)["tools"]
    assert (fitted["pin"], fitted["definition"], fitted["diff"]) == (None, None, None)
    assert (fitted["pinned"], fitted["changed"]) == (entry["pinned"], ["description"])
    assert [finding["level"] for finding in fitted["findings"]] == ["error"]


def test_an_over_cap_diff_goes_for_a_note() -> None:
    most = 16 * definition_max(LIMITS)
    data = unclassified("a")
    data["tools"][0]["diff"] = ["x" * (most - 1), "y"]
    assert fit(data, LIMITS) == data
    data["tools"][0]["diff"] = ["x" * most, "y"]
    fitted = fit(data, LIMITS)
    [entry] = fitted["tools"]
    assert entry["diff"] is None
    assert entry["findings"] == [
        *data["tools"][0]["findings"],
        {
            "level": "note",
            "pointer": "",
            "message": f"the diff is over {most} characters, so not shown",
        },
    ]
    read(fitted, LIMITS)


def test_findings_past_the_cap_become_one() -> None:
    """A pattern note on each of 65 properties."""
    listing = [patterned("a", *(f"p{index}" for index in range(65)))]
    data = wired(reviewed(listing, policy([], {})))
    found = data["tools"][0]["findings"]
    assert len(found) > FINDINGS_MAX
    assert invalid(data) == "at remote.tools[0].findings"
    fitted = fit(data, LIMITS)
    assert fitted["tools"][0]["findings"] == [
        *found[: FINDINGS_MAX - 1],
        {
            "level": "note",
            "pointer": "",
            "message": f"and {len(found) - FINDINGS_MAX + 1} more findings, not shown",
        },
    ]
    read(fitted, LIMITS)


@pytest.mark.parametrize(
    ("levels", "level"),
    [(["note", "warning"], "warning"), (["warning", "error", "note"], "error"), (["note"], "")],
)
def test_the_findings_summary_takes_the_most_severe_level(levels: list[str], level: str) -> None:
    data = unclassified("a")
    note = {"level": "note", "pointer": "", "message": "m"}
    data["tools"][0]["findings"] = [note] * (FINDINGS_MAX - 1) + [
        {**note, "level": each} for each in levels
    ]
    findings = fit(data, LIMITS)["tools"][0]["findings"]
    if not level:  # at the cap: as it is
        assert findings == data["tools"][0]["findings"]
        return
    assert len(findings) == FINDINGS_MAX
    assert findings[-1] == {
        "level": level,
        "pointer": "",
        "message": f"and {len(levels)} more findings, not shown",
    }


def test_long_pointers_and_messages_are_cut() -> None:
    """A property name of 300 characters with a pattern."""
    data = wired(reviewed([patterned("a", "q" * 300)], policy([], {})))
    pointers = [finding["pointer"] for finding in data["tools"][0]["findings"]]
    assert all(len(pointer) > POINTER_MAX for pointer in pointers)
    assert invalid(data).startswith("at remote.tools[0].findings[0].pointer")
    fitted = fit(data, LIMITS)
    assert [finding["pointer"] for finding in fitted["tools"][0]["findings"]] == [
        pointer[: POINTER_MAX - 3] + "..." for pointer in pointers
    ]
    read(fitted, LIMITS)
    data = unclassified("a")
    finding = {"level": "note", "pointer": "/" + "p" * 255, "message": "m" * MESSAGE_MAX}
    data["tools"][0]["findings"] = [finding]
    assert fit(data, LIMITS) == data
    data["tools"][0]["findings"] = [{**finding, "message": "m" * (MESSAGE_MAX + 1)}]
    [cut] = fit(data, LIMITS)["tools"][0]["findings"]
    assert cut == {**finding, "message": "m" * (MESSAGE_MAX - 3) + "..."}


def test_server_info_and_instructions_are_cut() -> None:
    data = unclassified("a", server_info=Implementation(name="n", version="v" * 20_000))
    assert invalid(data) == "at remote.server_info.version"
    fitted = fit(data, LIMITS)
    assert fitted["server_info"] == {"name": "n", "version": "v" * (TEXT_MAX - 3) + "..."}
    read(fitted, LIMITS)
    data["server_info"] = {"name": "n" * (TEXT_MAX + 1), "version": "v", "title": None}
    assert fit(data, LIMITS)["server_info"] == {
        "name": "n" * (TEXT_MAX - 3) + "...",
        "version": "v",
        "title": None,
    }
    data["instructions"] = "i" * (INSTRUCTIONS_MAX + 1)
    assert fit(data, LIMITS)["instructions"] == "i" * (INSTRUCTIONS_MAX - 3) + "..."


def test_a_toolkits_distribution_and_version_are_cut(
    tmp_path: Path, example_raw: dict[str, Any]
) -> None:
    data = wired(toolkit_reviewed(tmp_path, example_raw))
    data.update(distribution="d" * (DISTRIBUTION_MAX + 1), version="v" * (DISTRIBUTION_MAX + 1))
    fitted = fit(data, LIMITS)
    assert (fitted["distribution"], fitted["version"]) == (
        "d" * (DISTRIBUTION_MAX - 3) + "...",
        "v" * (DISTRIBUTION_MAX - 3) + "...",
    )
    read(fitted, LIMITS)


def test_long_listed_names_are_cut_and_stay_apart() -> None:
    first, second = "x" * (LISTED_NAME_MAX + 1), "x" * LISTED_NAME_MAX + "y"
    data = wired(reviewed([bare(first), bare(second), bare(first)], policy([], {})))
    assert invalid(data) == "at remote.tools[0].name, remote.tools[1].name"
    fitted = fit(data, LIMITS)
    names = [entry["name"] for entry in fitted["tools"]]
    digests = ["sha256:" + hashlib.sha256(name.encode()).hexdigest() for name in (first, second)]
    prefix = "x" * (LISTED_NAME_MAX - 3 - len(digests[0]))
    assert names == [prefix + "..." + digest for digest in digests]
    assert all(len(name) == LISTED_NAME_MAX for name in names)
    assert [entry.state for entry in read(fitted, LIMITS).tools] == ["duplicate", "invalid"]


# --- the reviewed definition, the policy's pins, offered (M6 design J.1) --------------------


def drifted(description: str = "Does another thing.", **extra: Any) -> dict[str, Any]:
    """The report of a server whose one included tool, ``a``, drifted from the definition the
    gateway's store holds at the policy's pin."""
    old = pins.project_and_pin(tool("a")).definition
    server = policy(["a"], {"a": pin("a")})
    return wired(reviewed([tool("a", description)], server, defs={pin("a"): old}, **extra))


def test_a_drift_entry_carries_its_reviewed_definition() -> None:
    data = drifted(
        offered={"prompts": True, "resources": False, "completions": False, "logging": True}
    )
    [entry] = data["tools"]
    assert (entry["state"], entry["pinned"]) == ("drift", pin("a"))
    assert entry["reviewed"] == pins.project(tool("a"))
    report = read(data, LIMITS)
    assert isinstance(report, RemoteReport)
    assert report.tools[0].reviewed == pins.project(tool("a"))
    assert report.policy.review == {"a": pin("a")}
    assert report.offered is not None
    assert report.offered.model_dump() == {
        "prompts": True,
        "resources": False,
        "completions": False,
        "logging": True,
    }


def test_a_drift_the_store_has_no_copy_of_has_no_reviewed_definition() -> None:
    """F-41: the store was pruned; the entry reads without one, and without a diff."""
    server = policy(["a"], {"a": pin("a")})
    data = wired(reviewed([tool("a", "Does another thing.")], server))
    [entry] = data["tools"]
    assert entry["state"] == "drift"
    assert ("reviewed" in entry, entry["diff"]) == (False, None)
    assert read(data, LIMITS).tools[0].reviewed is None


def test_a_reviewed_definition_whose_pin_isnt_pinned_refuses_the_whole_report() -> None:
    """Y10: a gateway can leave the old definition out, never fake it. The vault recomputes its
    pin; one that isn't the entry's ``pinned`` refuses all of the report, naming the tool once
    even when its listed pin is wrong too."""
    data = drifted()
    data["tools"][0]["reviewed"]["description"] = "Does a third thing."
    refusal = refused(data)
    assert (refusal.reason, refusal.tools) == ("pin_mismatch", ("a",))
    assert refusal.detail == "a reported pin isn't the pin of its definition"
    data = drifted()
    data["tools"][0]["pinned"] = PIN0
    assert refused(data).tools == ("a",)
    data["tools"][0]["pin"] = PIN0
    assert refused(data).tools == ("a",)


def test_a_reviewed_definition_is_the_one_the_policys_pin_names() -> None:
    """Y10: a reviewed definition whose own ``pinned`` matches it, but isn't the policy's pin,
    refuses the whole report, as does one for a tool the policy has no pin for."""
    data = drifted()
    entry = data["tools"][0]
    entry["reviewed"]["description"] = "A forged old definition."
    entry["pinned"] = pinhash.pin_of(entry["reviewed"])
    assert data["policy"]["review"] == {"a": pin("a")}
    refusal = refused(data)
    assert (refusal.reason, refusal.tools) == ("pin_mismatch", ("a",))
    data["policy"]["review"] = {}
    assert refused(data).tools == ("a",)
    data["policy"]["review"] = {"a": entry["pinned"]}  # stale() compares this map (J.2)
    read(data, LIMITS)


def test_a_reviewed_definition_with_no_pin_form_is_a_mismatch() -> None:
    deep: dict[str, Any] = {}
    for _ in range(62):
        deep = {"a": deep}
    data = drifted()
    data["tools"][0]["reviewed"]["inputSchema"] = deep
    assert refused(data).tools == ("a",)


def test_a_reviewed_definition_comes_only_with_a_drift_entrys_pinned_pin() -> None:
    data = drifted()
    entry = data["tools"][0]
    for state in ("ok", "marked", "blocked", "unreviewed", "invalid"):
        entry["state"] = state
        assert invalid(data) == "at remote.tools[0]"
    entry["state"] = "drift"
    entry["pinned"] = None
    assert invalid(data) == "at remote.tools[0]"
    data = drifted()
    data["tools"][0]["reviewed"]["name"] = "b"
    assert invalid(data) == "at remote.tools[0]"
    data["tools"][0]["reviewed"] = []
    assert invalid(data) == "at remote.tools[0].reviewed"


def test_the_reviewed_definition_is_capped_like_the_listed_one() -> None:
    limits = GatewayLimits(max_schema_bytes=64 * 1024)
    most = definition_max(limits)
    data = drifted()
    entry = data["tools"][0]
    old = entry["reviewed"]
    old["description"] += "x" * (most - len(canonical.dumps_canonical(old)))
    entry["pinned"] = data["policy"]["review"]["a"] = pinhash.pin_of(old)
    read(data, limits)
    old["description"] += "x"
    entry["pinned"] = data["policy"]["review"]["a"] = pinhash.pin_of(old)
    assert invalid(data, limits) == f"at tools[0].reviewed (over {most} bytes)"
    old["inputSchema"]["maximum"] = 2**53
    entry["definition"]["inputSchema"]["maximum"] = 2**53
    assert invalid(data, limits) == (
        "at tools[0].definition (no canonical form), tools[0].reviewed (no canonical form)"
    )


def test_the_cap_drops_the_reviewed_definition_first() -> None:
    """An entry whose reviewed definition is over the cap loses that definition, for a note; its
    listed definition, pin, changed members and diff stay."""
    most = definition_max(LIMITS)
    data = drifted()
    entry = data["tools"][0]
    old = entry["reviewed"]
    old["description"] += "x" * (most - len(canonical.dumps_canonical(old)))
    entry["pinned"] = data["policy"]["review"]["a"] = pinhash.pin_of(old)
    assert fit(data, LIMITS) == data
    old["description"] += "x"
    entry["pinned"] = data["policy"]["review"]["a"] = pinhash.pin_of(old)
    [fitted] = fit(data, LIMITS)["tools"]
    assert fitted["reviewed"] is None
    assert fitted["findings"] == [
        *entry["findings"],
        {
            "level": "note",
            "pointer": "",
            "message": "the reviewed definition was too large to report",
        },
    ]
    kept = ("definition", "pin", "pinned", "changed", "diff")
    assert {key: fitted[key] for key in kept} == {key: entry[key] for key in kept}
    assert data["tools"][0]["reviewed"] is old  # the answer itself isn't changed
    read(fit(data, LIMITS), LIMITS)


def test_the_policys_pins_and_declines() -> None:
    """Shape and keys are checked; the maps aren't capped at NAMES_MAX, since a pin for a tool
    that isn't included is only a warning in the policy, so the gateway can write more."""
    data = unclassified("a")
    assert data["policy"]["review"] == {}
    data["policy"].update(review={"a": pin("a")}, declined={"b": PIN0})
    report = read(data, LIMITS)
    assert (report.policy.review, report.policy.declined) == ({"a": pin("a")}, {"b": PIN0})
    for member in ("review", "declined"):
        data["policy"][member] = {"a": "sha256:abc"}
        assert invalid(data) == f"at remote.policy.{member}.a"
        data["policy"][member] = {"a b": PIN0}
        assert invalid(data) == f"at remote.policy.{member}.?.?"  # the key, then "[key]"
        data["policy"][member] = {f"t{index}": PIN0 for index in range(NAMES_MAX + 1)}
        read(data, LIMITS)
        data["policy"][member] = {}


def test_a_toolkits_policy_carries_its_pins(tmp_path: Path, example_raw: dict[str, Any]) -> None:
    data = wired(toolkit_reviewed(tmp_path, example_raw))
    pins_ = example_raw["gateway"]["servers"]["mail"]["review"]
    assert data["policy"]["review"] == pins_
    report = read(data, LIMITS)
    assert report.policy.review == pins_
    assert all(entry.reviewed is None for entry in report.tools)
    assert invalid({**data, "offered": None}) == "at toolkit.offered"


@pytest.mark.parametrize(
    ("offered", "location"),
    [
        ({"prompts": True, "resources": True, "completions": True}, "remote.offered.logging"),
        (
            {"prompts": 1, "resources": True, "completions": True, "logging": True},
            "remote.offered.prompts",
        ),
        (
            {
                "prompts": True,
                "resources": True,
                "completions": True,
                "logging": True,
                "tools": True,
            },
            "remote.offered.tools",
        ),
        ([], "remote.offered"),
    ],
)
def test_offered_out_of_shape(offered: object, location: str) -> None:
    data = unclassified("a")
    data["offered"] = offered
    assert invalid(data) == f"at {location}"


@pytest.mark.parametrize(
    ("kind", "options"),
    [
        ("prompts", {"listChanged": True}),
        ("resources", {"subscribe": True}),
        ("completions", {}),
        ("logging", {}),
    ],
)
def test_offered_from_the_upstreams_capabilities(kind: str, options: dict[str, Any]) -> None:
    """Each kind the upstream advertises, whatever its options, and only that kind; tools
    aren't among them."""
    kinds = ("prompts", "resources", "completions", "logging")
    assert review.offered(ServerCapabilities()) == dict.fromkeys(kinds, False)
    assert review.offered(ServerCapabilities.model_validate({"tools": {}})) == dict.fromkeys(
        kinds, False
    )
    advertised = ServerCapabilities.model_validate({"tools": {}, kind: options})
    assert review.offered(advertised) == {other: other == kind for other in kinds}
    assert "offered" not in unclassified("a")


def test_an_m7_report_still_reads(tmp_path: Path, example_raw: dict[str, Any]) -> None:
    """CR-6: a report with none of M6's fields, as an M7 gateway writes it, reads with each
    field at its default."""
    data = drifted(
        offered={"prompts": True, "resources": True, "completions": True, "logging": True}
    )
    del data["offered"], data["policy"]["review"], data["tools"][0]["reviewed"]
    report = read(data, LIMITS)
    assert isinstance(report, RemoteReport)
    assert report.offered is None
    assert (report.policy.review, report.policy.declined) == ({}, {})
    assert report.tools[0].reviewed is None
    assert report.model_dump(mode="json", exclude_unset=True) == data
    toolkit = wired(toolkit_reviewed(tmp_path, example_raw))
    del toolkit["policy"]["review"]
    assert read(toolkit, LIMITS).policy.review == {}


def test_the_clis_review_text_reads_none_of_the_new_fields() -> None:
    """J.1's acceptance: the CLI prints the gateway's answer as before, so its text and snippet
    are byte-identical with and without M6's fields."""
    data = drifted(
        offered={"prompts": True, "resources": True, "completions": True, "logging": True}
    )
    m7 = copy.deepcopy(data)
    del m7["offered"], m7["policy"]["review"], m7["tools"][0]["reviewed"]
    for choices in (
        cli_review.Choices(),
        cli_review.Choices(show_all=True, repin=frozenset({"a"})),
    ):
        assert cli_review.render(data, choices) == cli_review.render(m7, choices)
        assert cli_review.snippet(data, choices) == cli_review.snippet(m7, choices)
