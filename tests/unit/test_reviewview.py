"""The portal's review data (M7 design F.6, K.1, K.5; O.2 ``test_reviewview.py``).

A done job's rows, from reports straight from the gateway's review code (the ``large`` fake's 96
tools, a toolkit's), read and dumped as the vault holds them; the definition in chunks with
nothing cut, a 16 KiB description shown whole (CR-2, TI-5); every server string shown, hostile
fixtures built from escapes in this source (S12 style, fold-in R23); the shared suggestion
(CR-3); and fragment 2 from the operator's choices, with each refusal: ``bad_body``,
``review_stale`` (GR-11) and every ``diff_invalid``.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from mcp.types import Tool

from tests.unit.test_onboarding import committed
from tests.unit.test_review import LIMITS, reviewed
from tests.unit.test_review import policy as reviewed_policy
from tests.unit.test_review_choices import LARGE, large, served
from tests.unit.test_review_choices import reviewed as choices_reviewed
from tests.unit.test_review_toolkits import reviewed as toolkit_reviewed
from zoeymcp.cli import review as cli_review
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.change import ChangeRefused
from zoeymcp.common.policy.emit import EmitRefused, emit
from zoeymcp.common.policy.schema import Tools
from zoeymcp.common.reviewreport import read
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.portal import reviewview
from zoeymcp.portal.refusals import CATALOGUE, Refusal
from zoeymcp.portal.reviewview import (
    CHUNK,
    ERROR_FINDING,
    GONE,
    NO_PIN,
    WHY_CONSEQUENTIAL,
    WHY_HINTED,
    WHY_READ_ONLY,
    WHY_UNANNOTATED,
    Choices,
    changes,
    choices,
    counts,
    definition_lines,
    diff,
    notes,
    rows,
    stale,
    suggested_for,
    unpinnable,
)
from zoeymcp.vault.onboarding import INLINE_SOURCE, Listed, listed_server, reviewed_next

# Hostile text, from escapes: a right-to-left override, a zero-width space, a line break.
RLO = "\u202e"
ZWSP = "\u200b"
NOTES = Listed("notes", "remote", Tools(), "hide")


def held(report: dict[str, Any]) -> dict[str, Any]:
    """``report`` as the vault holds a done job's: read under the limits, then dumped."""
    dumped: dict[str, Any] = read(json.loads(json.dumps(report)), LIMITS).model_dump(
        mode="json", exclude_unset=True
    )
    return dumped


def entry(report: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(e for e in report["tools"] if e["name"] == name)
    return found


def row(view: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(r for r in view["tools"] if r["name_shown"] == name)
    return found


def one_tool(definition: dict[str, Any]) -> dict[str, Any]:
    """The held report of a server listing one tool with this wire ``definition``."""
    wire = {"inputSchema": {"type": "object"}, **definition}
    return held(reviewed([Tool.model_validate(wire)], reviewed_policy([], {})))


def without_echo() -> dict[str, Any]:
    """The ``large`` fake's report for a server including ``echo`` and ``add``, the server no
    longer listing ``echo``."""
    wires = [copy.deepcopy(wire) for wire in LARGE if wire["name"] != "echo"]
    return held(choices_reviewed(wires, served(["echo", "add"], approve=["echo", "add"])))


def refused(found: object, reason: str) -> Refusal:
    assert isinstance(found, Refusal), found
    assert found.reason == reason
    assert found.status == CATALOGUE[reason].status
    return found


def detail(found: object, reason: str = "diff_invalid") -> str:
    """A refusal's detail: in the text for diff_invalid, beside it for bad_body."""
    answer = refused(found, reason)
    if reason == "bad_body":
        return str(dict(answer.more)["detail"])
    return answer.error


def chosen(include: list[str], allow: list[str] = [], approve: list[str] = []) -> Choices:  # noqa: B006
    made = choices({"include": include, "allow": allow, "approve": approve}, 512)
    assert isinstance(made, Choices)
    return made


# --- the rows (F.6, K.1) -------------------------------------------------------------------------


def test_the_constants() -> None:
    assert CHUNK == 200
    assert (WHY_READ_ONLY, WHY_HINTED, WHY_UNANNOTATED) == (
        "the server marks it read-only",
        "the server's hints don't mark it read-only",
        "the server doesn't annotate it",
    )
    assert WHY_CONSEQUENTIAL == "the toolkit declares it consequential: approve, never allow"
    assert (GONE, ERROR_FINDING, NO_PIN) == (
        "the server no longer lists it",
        "it has an error finding",
        "the server gave no definition the vault can pin",
    )


def test_the_large_fakes_96_tools() -> None:
    """K.1's sizing case: the rows once, the counts the page heads its list with."""
    view = rows(held(large()))
    assert (view["state"], view["server_shown"], view["kind"]) == ("done", "notes", "remote")
    assert (view["era"], view["protocol_version"]) == ("modern", "2026-07-28")
    assert (view["server_info_shown"], view["instructions_shown"], view["notes"]) == (
        None,
        None,
        [],
    )
    assert view["counts"] == {
        "tools": 96,
        "read_only": 64,
        "not_annotated": 32,
        "with_findings": 4,
        "with_errors": 1,
        "included": 0,
    }
    assert len(view["tools"]) == 96
    echo = row(view, "echo")
    assert {key: echo[key] for key in echo if key != "definition_lines"} == {
        "name": "echo",
        "name_shown": "echo",
        "state": "unreviewed",
        "included": False,
        "classification": None,
        "suggested": "allow",
        "suggested_why": WHY_READ_ONLY,
        "pinnable": True,
        "not_pinnable": None,
        "pin": entry(large(), "echo")["pin"],
        "title_shown": "Echo",
        "description_shown": "Returns the text it is given.",
        "findings": [
            {"level": "note", "message_shown": "suggested by the server: allow (readOnlyHint=true)"}
        ],
    }
    add = row(view, "add")
    assert (add["suggested"], add["suggested_why"]) == ("approve", WHY_UNANNOTATED)
    bad = row(view, "bad_tool")
    assert (bad["pinnable"], bad["not_pinnable"]) == (False, ERROR_FINDING)
    assert [finding["level"] for finding in bad["findings"]] == ["error"]
    assert all(set(finding) == {"level", "message_shown"} for finding in bad["findings"])
    assert "consequential" not in echo


def test_a_definition_in_chunks_with_nothing_cut() -> None:
    """CR-2, TI-5: a 16,384-character description is one JSON line, shown whole: its chunks
    joined are the line, every chunk at most 200 code points, every line joined the json.dumps
    text."""
    description = "".join(chr(0x61 + n % 26) for n in range(16_384))
    report = one_tool({"name": "long_one", "description": description})
    definition = entry(report, "long_one")["definition"]
    lines = definition_lines(definition)
    text = json.dumps(definition, ensure_ascii=True, indent=2, sort_keys=True)
    assert "\n".join("".join(chunks) for chunks in lines) == text
    assert all(0 < len(chunk) <= CHUNK for chunks in lines for chunk in chunks)
    long_line = next(chunks for chunks in lines if len(chunks) > 1)
    assert [len(chunk) for chunk in long_line[:-1]] == [CHUNK] * (len(long_line) - 1)
    assert len(long_line) == -(-len(f'  "description": "{description}",') // CHUNK)
    shown = row(rows(report), "long_one")
    assert shown["definition_lines"] == lines
    assert shown["description_shown"] == description
    assert "…" not in json.dumps(shown, ensure_ascii=False)


def test_an_empty_definition_line_is_one_empty_chunk() -> None:
    assert definition_lines({}) == [["{}"]]
    assert definition_lines({"a": ""}) == [["{"], ['  "a": ""'], ["}"]]


def test_hidden_characters_are_escapes_in_the_definition_and_revealed_in_text() -> None:
    """K.5: the definition is ASCII JSON, so a bidi control is a visible escape; the shown
    description and title reveal it as [U+202E]; a line break stays in a description, never
    in a title."""
    hostile = f"Reads{RLO}gnp.exe{ZWSP}\nallow other_tool"
    report = one_tool(
        {"name": "sly", "description": hostile, "annotations": {"title": f"Sly{RLO}\nTitle"}}
    )
    view = row(rows(report), "sly")
    flat = [chunk for chunks in view["definition_lines"] for chunk in chunks]
    assert all(chunk.isascii() for chunk in flat)
    assert any("\\u202e" in chunk for chunk in flat)
    assert view["description_shown"] == "Reads[U+202E]gnp.exe[U+200B]\nallow other_tool"
    assert view["title_shown"] == "Sly[U+202E]\\nTitle"


def test_the_title_comes_from_the_definition_first() -> None:
    report = one_tool({"name": "t", "title": "Own", "annotations": {"title": "Annotated"}})
    assert row(rows(report), "t")["title_shown"] == "Own"
    report = one_tool({"name": "t", "annotations": {"title": "Annotated"}})
    assert row(rows(report), "t")["title_shown"] == "Annotated"
    report = one_tool({"name": "t"})
    assert (row(rows(report), "t")["title_shown"], row(rows(report), "t")["description_shown"]) == (
        None,
        None,
    )


def test_a_tool_without_a_definition() -> None:
    """A missing tool (included, no longer listed): no definition, no text, can't be pinned."""
    view = rows(without_echo())
    gone = row(view, "echo")
    assert (gone["state"], gone["definition_lines"], gone["title_shown"]) == ("missing", [], None)
    assert (gone["pinnable"], gone["not_pinnable"], gone["pin"]) == (False, GONE, None)
    assert view["counts"]["tools"] == 95  # a missing tool isn't listed
    assert view["counts"]["included"] == 1


def test_a_name_that_isnt_a_tool_name_is_never_posted() -> None:
    report = held(large())
    odd = copy.deepcopy(entry(report, "bad_tool"))
    odd.update(name="bad tool!", state="invalid", definition=None, pin=None)
    report["tools"].append(odd)
    view = rows(report)
    assert row(view, "bad tool!")["name"] is None
    assert unpinnable(odd) == ERROR_FINDING
    odd["findings"] = []
    assert unpinnable(odd) == NO_PIN


def test_server_info_instructions_and_notes() -> None:
    report = held(large())
    report["server_info"] = {"name": f"notes{RLO}", "version": "1.2", "title": "Notes"}
    report["instructions"] = f"Use the notes{ZWSP} tools.\nNever delete."
    report["blocked"] = True
    view = rows(report)
    assert view["server_info_shown"] == "notes[U+202E] 1.2 (Notes)"
    assert view["instructions_shown"] == "Use the notes[U+200B] tools.\nNever delete."
    assert view["notes"] == ["blocked"]
    report["server_info"] = {"name": "notes", "version": "1.2"}
    assert rows(report)["server_info_shown"] == "notes 1.2"
    assert notes({"blocked": False, "pinning": "off"}) == ["pinning_off"]
    assert notes({"blocked": True, "pinning": "required"}) == ["blocked"]


def test_a_toolkits_report(tmp_path: Path, example_raw: dict[str, Any]) -> None:
    """COV-1: a toolkit's consequential tool is suggested approve, never allow, whatever its
    annotations; the row says it is declared."""
    report = held(toolkit_reviewed(tmp_path, example_raw))
    view = rows(report)
    assert view["kind"] == "toolkit"
    send = row(view, "send_note")
    assert (send["consequential"], send["suggested"], send["suggested_why"]) == (
        True,
        "approve",
        WHY_CONSEQUENTIAL,
    )
    assert (send["included"], send["classification"]) == (True, "approve")
    routine = {**entry(report, "send_note"), "consequential": False}
    assert suggested_for(routine)[1] != WHY_CONSEQUENTIAL


@pytest.mark.parametrize(
    ("annotations", "expected"),
    [
        (None, ("approve", WHY_UNANNOTATED)),
        ({}, ("approve", WHY_UNANNOTATED)),
        ({"title": "x"}, ("approve", WHY_UNANNOTATED)),
        ({"readOnlyHint": True}, ("allow", WHY_READ_ONLY)),
        ({"readOnlyHint": False}, ("approve", WHY_HINTED)),
        ({"openWorldHint": True}, ("approve", WHY_HINTED)),
        # The contradictory tool: read-only and destructive is approve, never bulk-allowed.
        ({"readOnlyHint": True, "destructiveHint": True}, ("approve", WHY_HINTED)),
    ],
)
def test_the_shared_suggestion(annotations: object, expected: tuple[str, str]) -> None:
    definition: dict[str, Any] = {"name": "t"}
    if annotations is not None:
        definition["annotations"] = annotations
    assert suggested_for({"definition": definition}) == expected
    assert suggested_for({"definition": None}) == ("approve", WHY_UNANNOTATED)
    assert suggested_for({"definition": {"annotations": "not a mapping"}}) == (
        "approve",
        WHY_UNANNOTATED,
    )


def test_counts_take_the_listed_tools_only() -> None:
    report = {
        "tools": [
            {
                "name": "a",
                "state": "ok",
                "included": True,
                "definition": {"annotations": {"readOnlyHint": True}},
                "findings": [{"level": "warning", "message": "m"}],
            },
            {
                "name": "n",
                "state": "unreviewed",
                "included": False,
                "definition": {},
                "findings": [{"level": "note", "message": "m"}, {"level": "error", "message": "e"}],
            },
            {
                "name": "b",
                "state": "unreviewed",
                "included": False,
                "definition": {"annotations": {"destructiveHint": True}},
                "findings": [],
            },
            {"name": "c", "state": "missing", "included": True, "definition": None, "findings": []},
        ]
    }
    assert counts(report) == {
        "tools": 3,
        "read_only": 1,
        "not_annotated": 1,
        "with_findings": 1,
        "with_errors": 1,
        "included": 1,
    }


# --- the choices (F.6) ---------------------------------------------------------------------------


def test_choices_of_the_right_shape() -> None:
    body = {"include": ["a", "b"], "allow": ["a"], "approve": ["b"]}
    assert choices(body, 2) == Choices(("a", "b"), frozenset({"a"}), frozenset({"b"}), 0, "plain")
    assert choices({**body, "indent": 16}, 2) == Choices(
        ("a", "b"), frozenset({"a"}), frozenset({"b"}), 16, "plain"
    )
    assert choices({**body, "indent": "compose"}, 2) == Choices(
        ("a", "b"), frozenset({"a"}), frozenset({"b"}), 8, "compose"
    )
    assert Choices(("a",), frozenset({"a"}), frozenset()).classified("a") == "allow"
    assert Choices(("a",), frozenset(), frozenset({"a"})).classified("a") == "approve"


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ({"include": "a"}, "include is a list of tool names"),
        ({"allow": ["a b"]}, "allow is a list of tool names"),
        ({"approve": [1]}, "approve is a list of tool names"),
        ({"include": ["a", "b", "c"]}, "include names at most 2 tools (max_tools_per_server)"),
        ({"approve": ["b", "b"]}, "approve names a tool twice"),
        ({"indent": 17}, "indent is 0 to 16, or compose"),
        ({"indent": -1}, "indent is 0 to 16, or compose"),
        ({"indent": True}, "indent is 0 to 16, or compose"),
        ({"indent": "4"}, "indent is 0 to 16, or compose"),
    ],
)
def test_choices_of_the_wrong_shape(change: dict[str, Any], said: str) -> None:
    body = {"include": ["a", "b"], "allow": ["a"], "approve": ["b"], **change}
    assert detail(choices(body, 2), "bad_body") == said


# --- stale (GR-11) -------------------------------------------------------------------------------


def test_a_report_is_stale_once_the_servers_tools_changed() -> None:
    report = held(large(["echo", "add"], allow=["echo"], approve=["add"]))
    tools = Tools(include=["add", "echo"], allow=["echo"], approve=["add"])
    same = Listed("notes", "remote", tools, "hide")
    assert not stale(report, same)  # the order of a list isn't a change
    assert stale(report, None)
    assert stale(report, replace(same, kind="toolkit"))
    assert stale(report, replace(same, on_drift="fail"))
    assert stale(report, replace(same, tools=Tools(include=["echo"], allow=["echo"])))
    moved = Tools(include=["add", "echo"], allow=["echo", "add"])
    assert stale(report, replace(same, tools=moved))
    swapped = Tools(include=["add", "echo"], allow=["add"], approve=["echo"])
    assert stale(report, replace(same, tools=swapped))
    other = Tools(include=["add", "echo"], allow=["echo"], approve=["add", "echo"])
    assert stale(report, replace(same, tools=other))


def test_a_report_is_stale_once_the_servers_declines_changed() -> None:
    """Fragment 2 writes the report's declined block whole (M6 design J.5): a report made before
    a decline would undo it (J.2's rule for declines)."""
    report = held(large())
    assert not stale(report, NOTES)
    later = replace(NOTES, declined={"read_01": entry(report, "read_01")["pin"]})
    assert stale(report, later)
    body: dict[str, Any] = {"include": [], "allow": [], "approve": []}
    assert detail(run_diff(report, body, server=later), "review_stale")
    declined = held(large(declined=["read_01"]))
    assert not stale(declined, later)
    assert stale(declined, NOTES)  # undeclined since
    moved = {"read_01": entry(report, "read_02")["pin"]}
    assert stale(declined, replace(later, declined=moved))
    m7 = copy.deepcopy(report)
    m7["policy"].pop("declined", None)  # an M7 gateway's report ran under no declines
    assert not stale(m7, NOTES)
    assert stale(m7, later)


# --- the changes (F.6) ---------------------------------------------------------------------------


def test_a_first_review_includes_what_was_chosen() -> None:
    report = held(large())
    made = changes(report, chosen(["read_01", "add", "echo"], ["read_01", "echo"], ["add"]))
    assert made == cli_review.Changes(
        added={
            "read_01": cli_review.Added("allow", "allow, chosen in the portal"),
            "add": cli_review.Added("approve", "approve, chosen in the portal"),
            "echo": cli_review.Added("allow", "allow, chosen in the portal"),
        }
    )


def test_a_review_again_moves_and_drops_and_keeps() -> None:
    report = held(large(["echo", "add", "slow"], allow=["echo"], approve=["add", "slow"]))
    made = changes(report, chosen(["echo", "add", "read_02"], ["add", "read_02"], ["echo"]))
    assert made == cli_review.Changes(
        added={"read_02": cli_review.Added("allow", "allow, chosen in the portal")},
        dropped=frozenset({"slow"}),
        moved={"echo": "approve", "add": "allow"},
    )
    kept = changes(report, chosen(["echo", "add", "slow"], ["echo"], ["add", "slow"]))
    assert kept == cli_review.Changes()


def test_an_included_tool_leaves_the_servers_declined_block() -> None:
    """M6 design J.5: the block is written whole once the server has one, so including a
    declined tool can't leave it in both; with none, the change is M7's."""
    report = held(large(declined=["read_01", "read_02"]))
    pins = {name: entry(report, name)["pin"] for name in ("read_01", "read_02")}
    made = changes(report, chosen(["read_01"], ["read_01"]))
    assert made == cli_review.Changes(
        added={"read_01": cli_review.Added("allow", "allow, chosen in the portal")},
        declined={"read_02": pins["read_02"]},
    )
    assert changes(report, chosen([])) == cli_review.Changes(declined=pins)
    body = {"include": ["read_01"], "allow": ["read_01"], "approve": []}
    answer = run_diff(report, body, server=replace(NOTES, declined=pins))
    assert isinstance(answer, dict)
    assert not [f for f in answer["diff"]["check"] if f["level"] == "error"]
    entry_ = load_mapping(answer["diff"]["yaml"])["gateway"]["servers"]["notes"]
    assert entry_["declined"] == {"read_02": pins["read_02"]}
    # Its title names the three blocks it replaces, as the CLI's choices file does.
    assert answer["diff"]["yaml"].startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools:, review: and declined: blocks "
        "of gateway.servers.notes,"
    )
    assert changes(held(large()), chosen([])) == cli_review.Changes()


def test_a_tool_the_server_no_longer_lists_may_stay_or_go() -> None:
    report = without_echo()
    assert changes(report, chosen(["echo", "add"], [], ["echo", "add"])) == cli_review.Changes()
    gone = changes(report, chosen(["add"], [], ["add"]))
    assert isinstance(gone, cli_review.Changes)
    assert gone.dropped == frozenset({"echo"})
    # It may be classified anew: its pin stays as the policy has it.
    moved = changes(report, chosen(["echo", "add"], ["echo"], ["add"]))
    assert isinstance(moved, cli_review.Changes)
    assert moved.moved == {"echo": "allow"}


@pytest.mark.parametrize(
    ("include", "allow", "approve", "said"),
    [
        (["nope", "echo"], [], ["nope", "echo"], "the server lists no tool nope"),
        (["echo"], ["ghost"], ["echo"], "the server lists no tool ghost"),
        (["echo"], ["echo"], ["echo"], "echo is in both allow and approve"),
        (["echo"], ["echo", "add"], [], "add is classified but not included"),
        (["echo", "add"], ["echo"], [], "add is included but neither allowed nor approved"),
        (["bad_tool"], [], ["bad_tool"], "bad_tool can't be pinned, so it can't be included"),
    ],
)
def test_what_cant_be_chosen(
    include: list[str], allow: list[str], approve: list[str], said: str
) -> None:
    text = detail(changes(held(large()), chosen(include, allow, approve)))
    assert said in text


def test_each_refusal_names_every_tool_once() -> None:
    text = detail(changes(held(large()), chosen(["echo", "add", "slow"], ["echo"])))
    assert "add, slow is included but neither allowed nor approved" in text


def test_a_toolkits_consequential_tool_is_never_in_allow(
    tmp_path: Path, example_raw: dict[str, Any]
) -> None:
    report = held(toolkit_reviewed(tmp_path, example_raw))
    text = detail(changes(report, chosen(["send_note"], ["send_note"])))
    assert "the toolkit declares send_note consequential, so it can't be in allow" in text
    assert changes(report, chosen(["send_note"], [], ["send_note"])) == cli_review.Changes()


# --- fragment 2 (F.6, E.4, H) --------------------------------------------------------------------


def run_diff(
    report: dict[str, Any],
    body: dict[str, Any],
    policy: Policy | None = None,
    server: Listed | None = NOTES,
) -> dict[str, Any] | Refusal:
    return diff(
        report,
        server,
        body,
        policy=policy or committed(),
        most=512,
        source=INLINE_SOURCE,
    )


def test_fragment_2_from_the_choices() -> None:
    """J2 step 6 and J4: the same change the CLI's choices file makes, checked merged into the
    running policy, written by the emitter, then what to do next."""
    report = held(large())
    body = {"include": ["read_01", "add"], "allow": ["read_01"], "approve": ["add"]}
    answer = run_diff(report, body)
    assert isinstance(answer, dict)
    made = cli_review.fragment(
        report,
        cli_review.Changes(
            added={
                "read_01": cli_review.Added("allow", "allow, chosen in the portal"),
                "add": cli_review.Added("approve", "approve, chosen in the portal"),
            }
        ),
        heading=cli_review.second_title("notes"),
    )
    assert answer["diff"]["yaml"] == emit(made)
    assert answer["diff"]["yaml"].startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools: and review: blocks of "
    )
    entry_ = load_mapping(answer["diff"]["yaml"])["gateway"]["servers"]["notes"]
    assert entry_["tools"] == {
        "include": ["read_01", "add"],
        "allow": ["read_01"],
        "approve": ["add"],
    }
    assert set(entry_["review"]) == {"read_01", "add"}
    assert not [f for f in answer["diff"]["check"] if f["level"] == "error"]
    assert answer["next"] == [step.answer() for step in reviewed_next("notes", INLINE_SOURCE)]
    assert set(answer) == {"diff", "next"}
    compose = run_diff(report, {**body, "indent": "compose"})
    assert isinstance(compose, dict)
    assert compose["diff"]["yaml"] == emit(made, indent=8, target="compose")


def test_the_server_as_the_running_policy_has_it() -> None:
    """The listed server from the policy is the one stale compares (committed() includes
    nothing of notes, as the report)."""
    report = held(large())
    found = listed_server(committed(), "notes")
    answer = run_diff(report, {"include": [], "allow": [], "approve": []}, server=found)
    assert isinstance(answer, dict)
    assert load_mapping(answer["diff"]["yaml"])["gateway"]["servers"]["notes"]["tools"] == {
        "include": [],
        "allow": [],
        "approve": [],
    }


def test_a_diff_refuses_in_order() -> None:
    report = held(large())
    bad = {"include": "x", "allow": [], "approve": []}
    assert detail(run_diff(report, bad, server=None), "bad_body") == (
        "include is a list of tool names"
    )
    good = {"include": ["echo"], "allow": ["echo"], "approve": []}
    refused(run_diff(report, good, server=None), "review_stale")
    unknown = {"include": ["nope"], "allow": [], "approve": ["nope"]}
    assert "the server lists no tool nope" in detail(run_diff(report, unknown))


def test_a_merged_policy_that_fails_check_is_diff_invalid() -> None:
    policy = committed()
    assert policy.gateway is not None
    client = policy.gateway.clients["agent1"].model_copy(update={"servers": ["notes", "ghost"]})
    gateway = policy.gateway.model_copy(update={"clients": {"agent1": client}})
    broken = policy.model_copy(update={"gateway": gateway})
    body = {"include": ["echo"], "allow": ["echo"], "approve": []}
    found = refused(run_diff(held(large()), body, broken), "diff_invalid")
    assert "gateway.clients.agent1.servers: unknown server 'ghost'" in found.error
    more = dict(found.more)
    assert [f["path"] for f in more["check"] if f["level"] == "error"] == [
        "gateway.clients.agent1.servers"
    ]


def test_at_most_five_findings_are_named(monkeypatch: pytest.MonkeyPatch) -> None:
    from zoeymcp.common.policy.findings import Finding

    found = [Finding(f"p{n}", "error", f"m{n}") for n in range(7)]
    monkeypatch.setattr(reviewview, "validate", lambda policy, change: found)
    answer = refused(
        run_diff(held(large()), {"include": [], "allow": [], "approve": []}), "diff_invalid"
    )
    assert "p4: m4" in answer.error
    assert "p5" not in answer.error
    assert len(dict(answer.more)["check"]) == 7


def test_a_change_or_fragment_the_policy_cant_take(monkeypatch: pytest.MonkeyPatch) -> None:
    body: dict[str, list[str]] = {"include": [], "allow": [], "approve": []}

    def refuse_change(policy: object, change: object) -> None:
        raise ChangeRefused("diff_invalid", "(document)", ("gateway: bad", "routes: worse"))

    monkeypatch.setattr(reviewview, "validate", refuse_change)
    assert "gateway: bad; routes: worse" in detail(run_diff(held(large()), body))

    def refuse_path(policy: object, change: object) -> None:
        raise ChangeRefused("diff_invalid", "gateway.servers.notes")

    monkeypatch.setattr(reviewview, "validate", refuse_path)
    assert "(gateway.servers.notes)" in detail(run_diff(held(large()), body))
    monkeypatch.undo()

    def too_big(change: object, **_: object) -> str:
        raise EmitRefused("(document)", "size")

    monkeypatch.setattr(reviewview, "emit", too_big)
    assert "(document): size" in detail(run_diff(held(large()), body))
