"""The portal's review data (M7 design F.6, K.1, K.5; O.2 ``test_reviewview.py``; M6 J.2, J.3).

A done job's rows, from reports straight from the gateway's review code (the ``large`` fake's 96
tools, a toolkit's), read and dumped as the vault holds them; the definition in chunks with
nothing cut, a 16 KiB description shown whole (CR-2, TI-5); every server string shown, hostile
fixtures built from escapes in this source (S12 style, fold-in R23); the shared suggestion
(CR-3); and fragment 2 from the operator's choices, with each refusal: ``bad_body``,
``review_stale`` (GR-11) and every ``diff_invalid``. M6: every row's ``prefill`` (so **Select
suggested** makes no move, Q27), the chips' flags (D-188), a finding's pointer (D-199), a drifted
tool's two definitions and the vault's diff, re-pin and decline in fragment 2, and a report made
before a re-pin is stale (J.2). M6 L.7: a server's prompts and resources as rows by kind under
their headings, each kind's choices, its refusals, its blocks in fragment 2 (which ``check``
accepts from step 21b, L.11) and in a managed save, and a report made before either block
changed is stale.
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
from tests.unit.test_pins import prompt_pin, resource
from tests.unit.test_review import LIMITS, pin, reviewed, tool
from tests.unit.test_review import policy as reviewed_policy
from tests.unit.test_review_choices import (
    INDEX,
    INDEX_PIN,
    LARGE,
    OTHER_URI,
    OTHER_URI_PIN,
    TEMPLATE,
    TEMPLATE_PIN,
    kinds,
    large,
    served,
)
from tests.unit.test_review_choices import OLD as PROMPT_OLD
from tests.unit.test_review_choices import reviewed as choices_reviewed
from tests.unit.test_review_toolkits import reviewed as toolkit_reviewed
from tests.unit.test_reviewreport import kinds_report
from zoeymcp.cli import review as cli_review
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.change import ChangeRefused, SetServerReview
from zoeymcp.common.policy.emit import EmitRefused, emit
from zoeymcp.common.policy.reviewchange import KindChanges
from zoeymcp.common.policy.schema import PromptsPolicy, ResourcesPolicy, Tools
from zoeymcp.common.reviewreport import read
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import pins
from zoeymcp.portal import reviewview
from zoeymcp.portal.refusals import CATALOGUE, Refusal
from zoeymcp.portal.reviewview import (
    CHUNK,
    ERROR_FINDING,
    GONE,
    HEADINGS,
    KIND_LISTS,
    NAME_LIMITS,
    NO_PIN,
    WHY_CONSEQUENTIAL,
    WHY_HINTED,
    WHY_READ_ONLY,
    WHY_UNANNOTATED,
    Choices,
    KindChoice,
    changes,
    choices,
    counts,
    definition_lines,
    diff,
    drift_diff,
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


def chosen(
    include: list[str],
    allow: list[str] = [],  # noqa: B006
    approve: list[str] = [],  # noqa: B006
    **more: Any,
) -> Choices:
    made = choices({"include": include, "allow": allow, "approve": approve, **more}, 512)
    assert isinstance(made, Choices)
    return made


OTHER_PIN = "sha256:" + "0" * 64
# Text that would be markup if a page parsed it: the review screen shows it as text.
MARKUP = '<img src=x onerror=alert(1)> & "quoted"'
OLD = f"Finds notes. {MARKUP}"
NEW = f"Finds notes, and sends them on. {MARKUP}"


def drifted(*, kept: bool = True) -> dict[str, Any]:
    """notes includes ``search`` (allow), which the server changed after the review, and lists
    ``other`` and ``third`` besides; the gateway holds the reviewed copy unless not ``kept``."""
    old = tool("search", OLD)
    defs = {pin("search", OLD): pins.project_and_pin(old).definition} if kept else {}
    server = reviewed_policy(["search"], {"search": pin("search", OLD)})
    listed = [tool("search", NEW), tool("other"), tool("third")]
    return held(reviewed(listed, server, defs=defs))


SEARCH = Listed(
    "notes",
    "remote",
    Tools(include=["search"], allow=["search"]),
    "hide",
    review={"search": pin("search", OLD)},
)


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
        "kind": "tool",
        "heading": None,
        "state": "unreviewed",
        "included": False,
        "classification": None,
        "suggested": "allow",
        "suggested_why": WHY_READ_ONLY,
        "prefill": "allow",
        "annotated": True,
        "read_only_hint": True,
        "pinnable": True,
        "not_pinnable": None,
        "pin": entry(large(), "echo")["pin"],
        "pinned": None,
        "title_shown": "Echo",
        "description_shown": "Returns the text it is given.",
        "reviewed_lines": [],
        "reviewed_missing": False,
        "proposed": False,
        "diff_lines": [],
        "findings": [
            {
                "level": "note",
                "pointer_shown": "/annotations",
                "message_shown": "suggested by the server: allow (readOnlyHint=true)",
            }
        ],
    }
    add = row(view, "add")
    assert (add["suggested"], add["suggested_why"]) == ("approve", WHY_UNANNOTATED)
    bad = row(view, "bad_tool")
    assert (bad["pinnable"], bad["not_pinnable"]) == (False, ERROR_FINDING)
    assert [finding["level"] for finding in bad["findings"]] == ["error"]
    assert all(
        set(finding) == {"level", "pointer_shown", "message_shown"} for finding in bad["findings"]
    )
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
        ({"repin": "a"}, "repin is a list of tool names"),
        ({"repin": ["a", "b", "c"]}, "repin names at most 2 tools (max_tools_per_server)"),
        ({"decline": ["b", "b"]}, "decline names a tool twice"),
        ({"decline": ["a b"]}, "decline is a list of tool names"),
        ({"decline_rest": 1}, "decline_rest is true or false"),
        ({"decline_rest": "true"}, "decline_rest is true or false"),
    ],
)
def test_choices_of_the_wrong_shape(change: dict[str, Any], said: str) -> None:
    body = {"include": ["a", "b"], "allow": ["a"], "approve": ["b"], **change}
    assert detail(choices(body, 2), "bad_body") == said


def test_choices_take_repins_declines_and_the_rest() -> None:
    """M6 J.2, J.3: the three optional keys, none of them needed."""
    body = {"include": ["a"], "allow": ["a"], "approve": [], "repin": ["a"], "decline": ["b"]}
    assert choices({**body, "decline_rest": True}, 2) == Choices(
        ("a",), frozenset({"a"}), frozenset(), 0, "plain", frozenset({"a"}), ("b",), True
    )
    assert choices({"include": [], "allow": [], "approve": []}, 2) == Choices(
        (), frozenset(), frozenset(), 0, "plain", frozenset(), (), False
    )


# --- stale (GR-11) -------------------------------------------------------------------------------


def test_a_report_is_stale_once_the_servers_tools_changed() -> None:
    report = held(large(["echo", "add"], allow=["echo"], approve=["add"]))
    tools = Tools(include=["add", "echo"], allow=["echo"], approve=["add"])
    same = Listed("notes", "remote", tools, "hide", review=report["policy"]["review"])
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


def test_a_report_is_stale_once_the_servers_pins_changed() -> None:
    """M6 J.2: fragment 2 writes the report's pins, which would undo a re-pin made since; an M7
    gateway's report, with no pins, ran under none."""
    report = drifted()
    assert not stale(report, SEARCH)
    assert stale(report, replace(SEARCH, review={"search": pin("search", NEW)}))
    assert stale(report, replace(SEARCH, review={}))
    assert stale(report, replace(SEARCH, review={**SEARCH.review, "other": OTHER_PIN}))
    m7 = copy.deepcopy(report)
    m7["policy"].pop("review")
    assert stale(m7, SEARCH)
    assert not stale(m7, replace(SEARCH, review={}))
    body = {"include": ["search"], "allow": ["search"], "approve": [], "repin": ["search"]}
    repinned = replace(SEARCH, review={"search": pin("search", NEW)})
    assert detail(run_diff(report, body, server=repinned), "review_stale")


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


def test_a_repin_takes_the_new_pin_and_keeps_the_classification() -> None:
    """M6 J.2, J.3, Q8 (a): Accept the new definition re-pins a drifted tool, its
    classification kept; an allow tool whose new definition isn't marked read-only stays allow,
    and fragment 2 says so."""
    report = drifted()
    made = changes(report, chosen(["search"], ["search"], repin=["search"]))
    assert made == cli_review.Changes(repin=frozenset({"search"}))
    body = {"include": ["search"], "allow": ["search"], "approve": [], "repin": ["search"]}
    answer = run_diff(report, body, server=SEARCH)
    assert isinstance(answer, dict)
    text = answer["diff"]["yaml"]
    entry_ = load_mapping(text)["gateway"]["servers"]["notes"]
    assert entry_["review"] == {"search": pin("search", NEW)}
    assert entry_["tools"] == {"include": ["search"], "allow": ["search"], "approve": []}
    assert f"# changed: search (was {pin('search', OLD)})" in text
    assert "# kept: search (allow: the new definition isn't marked read-only: proposed" in text
    kept = run_diff(report, {**body, "repin": []}, server=SEARCH)
    assert isinstance(kept, dict)
    assert load_mapping(kept["diff"]["yaml"])["gateway"]["servers"]["notes"]["review"] == {
        "search": pin("search", OLD)
    }


def test_declines_one_by_one_and_the_rest() -> None:
    """M6 J.3, J.5: Decline records a tool left out at the pin shown; Record the rest as
    declined, every listed tool not included; an included tool is never declined."""
    report = drifted()
    one = changes(report, chosen(["search"], ["search"], decline=["other"]))
    assert one == cli_review.Changes(declined={"other": pin("other")})
    rest = changes(report, chosen(["search"], ["search"], decline_rest=True))
    assert rest == cli_review.Changes(declined={"other": pin("other"), "third": pin("third")})
    dropped = changes(report, chosen([], decline_rest=True))
    assert isinstance(dropped, cli_review.Changes)
    assert dropped.declined == {
        "search": pin("search", NEW),
        "other": pin("other"),
        "third": pin("third"),
    }
    body = {"include": ["search"], "allow": ["search"], "approve": [], "decline_rest": True}
    answer = run_diff(report, body, server=SEARCH)
    assert isinstance(answer, dict)
    assert not [f for f in answer["diff"]["check"] if f["level"] == "error"]
    assert answer["diff"]["yaml"].startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools:, review: and declined: blocks "
    )
    entry_ = load_mapping(answer["diff"]["yaml"])["gateway"]["servers"]["notes"]
    assert entry_["declined"] == {"other": pin("other"), "third": pin("third")}


@pytest.mark.parametrize(
    ("more", "said"),
    [
        ({"repin": ["other"]}, "other hasn't drifted, so there is no new definition to accept"),
        ({"repin": ["ghost"]}, "ghost hasn't drifted, so there is no new definition to accept"),
        ({"decline": ["ghost"]}, "the server lists no tool ghost"),
        ({"decline": ["search"]}, "search is declined but included"),
    ],
)
def test_what_cant_be_repinned_or_declined(more: dict[str, Any], said: str) -> None:
    assert said in detail(changes(drifted(), chosen(["search"], ["search"], **more)))


def test_a_repin_of_a_tool_left_out_or_unpinnable_and_an_unpinnable_decline() -> None:
    report = drifted()
    left = detail(changes(report, chosen([], repin=["search"])))
    assert "search is re-pinned but not included" in left
    broken = copy.deepcopy(report)
    entry(broken, "search")["findings"].append({"level": "error", "pointer": "", "message": "m"})
    said = detail(changes(broken, chosen(["search"], ["search"], repin=["search"])))
    assert "search can't be pinned, so its new definition can't be accepted" in said
    bad = detail(changes(held(large()), chosen([], decline=["bad_tool"])))
    assert "bad_tool can't be pinned, so it can't be declined" in bad


# --- prefill, the chips' flags and a finding's pointer (M6 J.3, D-188, D-199) --------------------


def test_prefill_is_where_a_ticked_box_starts() -> None:
    """M6 J.3, Q27: an included tool's classification whatever its suggestion (read_01, which
    the server marks read-only, stays approve); a tool not included whose name is in the
    ratchet's approved set, approve; any other, its suggestion. With nothing approved passed
    (declarative mode), every row's prefill is its classification or its suggestion."""
    report = held(large(["read_01", "add"], approve=["read_01", "add"]))
    view = rows(report)
    assert (row(view, "read_01")["suggested"], row(view, "read_01")["prefill"]) == (
        "allow",
        "approve",
    )
    assert (row(view, "read_02")["prefill"], row(view, "write_01")["prefill"]) == (
        "allow",
        "approve",
    )
    assert all(r["prefill"] == (r["classification"] or r["suggested"]) for r in view["tools"])
    once = rows(report, approved=frozenset({"read_02", "read_01"}))
    assert [row(once, name)["prefill"] for name in ("read_01", "read_02", "read_03")] == [
        "approve",
        "approve",
        "allow",
    ]


def test_select_suggested_after_clear_makes_no_move() -> None:
    """M6 J.3, Q27: the choices Select suggested gives after Clear (every pinnable tool the
    server marks read-only, each at its row's prefill, as review.js sets them) move no included
    approve tool to allow."""
    report = held(large(["read_01", "add"], approve=["read_01", "add"]))
    picked = [r for r in rows(report)["tools"] if r["pinnable"] and r["suggested"] == "allow"]
    allow = [r["name"] for r in picked if r["prefill"] == "allow"]
    approve = [r["name"] for r in picked if r["prefill"] == "approve"]
    assert approve == ["read_01"]
    made = changes(report, chosen([r["name"] for r in picked], allow, approve))
    assert isinstance(made, cli_review.Changes)
    assert made.moved == {}
    assert "read_01" not in made.added


def test_the_chips_flags_count_what_the_counts_count(
    tmp_path: Path, example_raw: dict[str, Any]
) -> None:
    """D-188: the chips read annotated and read_only_hint, the counts' own rules, so a
    toolkit's consequential tool with no annotations is a not-annotated tool though it is
    suggested approve as consequential."""
    view = rows(held(large()))
    assert sum(not r["annotated"] for r in view["tools"]) == view["counts"]["not_annotated"]
    assert sum(r["read_only_hint"] for r in view["tools"]) == view["counts"]["read_only"]
    report = held(toolkit_reviewed(tmp_path, example_raw))
    send = entry(report, "send_note")
    send["definition"] = {k: v for k, v in send["definition"].items() if k != "annotations"}
    view = rows(report)
    found = row(view, "send_note")
    assert (found["suggested_why"], found["annotated"]) == (WHY_CONSEQUENTIAL, False)
    assert view["counts"]["not_annotated"] == 1
    send["definition"]["annotations"] = {"readOnlyHint": True}
    found = row(rows(report), "send_note")
    assert (found["suggested"], found["read_only_hint"], found["annotated"]) == (
        "approve",
        True,
        True,
    )


def test_a_findings_pointer_is_shown() -> None:
    """D-199: "(definition)" for the whole definition, the server's pointer revealed and
    capped like a message."""
    report = held(large())
    entry(report, "echo")["findings"] = [
        {"level": "warning", "pointer": "", "message": "m"},
        {"level": "warning", "pointer": f"/description{RLO}", "message": "m"},
        {"level": "warning", "pointer": "/" + "p" * 300, "message": "m"},
    ]
    shown_ = [f["pointer_shown"] for f in row(rows(report), "echo")["findings"]]
    assert shown_[:2] == ["(definition)", "/description[U+202E]"]
    assert shown_[2] == "/" + "p" * 255 + "…[+45]"


# --- a drifted tool's two definitions (M6 J.2) ---------------------------------------------------


def test_a_drifted_tool_shows_both_definitions_and_the_vaults_diff() -> None:
    report = drifted()
    found = row(rows(report), "search")
    assert (found["state"], found["pinned"], found["pin"]) == (
        "drift",
        pin("search", OLD),
        pin("search", NEW),
    )
    assert found["reviewed_lines"] == definition_lines(entry(report, "search")["reviewed"])
    assert found["definition_lines"] == definition_lines(entry(report, "search")["definition"])
    assert found["reviewed_missing"] is False
    # search is allow and its new definition isn't marked read-only: a re-pin proposes approve (Q8).
    assert found["proposed"] is True
    joined = ["".join(chunks) for chunks in found["diff_lines"]]
    assert joined[:2] == ["--- reviewed", "+++ now"]
    assert any(line.startswith("-") and "Finds notes. <img" in line for line in joined)
    assert any(line.startswith("+") and "and sends them on" in line for line in joined)
    # The markup is text on both sides and in the diff: the page shows it through textContent.
    assert any("<img src=x onerror=alert(1)>" in "".join(c) for c in found["reviewed_lines"])
    others = row(rows(report), "other")
    assert (others["reviewed_lines"], others["diff_lines"], others["reviewed_missing"]) == (
        [],
        [],
        False,
    )
    assert others["proposed"] is False


def test_hidden_characters_on_both_sides_are_escapes() -> None:
    """K.5 on both columns and the diff: a definition the server or the reviewed copy holds is
    ASCII JSON, so a bidi control is a visible escape everywhere, never the character."""
    report = drifted()
    search = entry(report, "search")
    search["reviewed"]["description"] += RLO
    search["definition"]["description"] += ZWSP
    found = row(rows(report), "search")
    assert RLO not in json.dumps(found, ensure_ascii=False)
    assert ZWSP not in json.dumps(found, ensure_ascii=False)
    for lines, escape in (
        (found["reviewed_lines"], "\\u202e"),
        (found["definition_lines"], "\\u200b"),
        (found["diff_lines"], "\\u202e"),
        (found["diff_lines"], "\\u200b"),
    ):
        assert any(escape in chunk for chunks in lines for chunk in chunks), escape


def test_without_the_reviewed_copy_the_new_definition_is_shown_whole() -> None:
    found = row(rows(drifted(kept=False)), "search")
    assert (found["reviewed_missing"], found["reviewed_lines"], found["diff_lines"]) == (
        True,
        [],
        [],
    )
    assert found["definition_lines"]


def test_the_diff_is_shown_in_chunks_with_nothing_cut() -> None:
    long = "y" * 450
    lines = drift_diff(definition_lines({"d": "x"}), definition_lines({"d": long}))
    assert f'+  "d": "{long}"' in ["".join(chunks) for chunks in lines]
    assert all(0 < len(chunk) <= CHUNK for chunks in lines for chunk in chunks)
    hidden = drift_diff([["a"]], [[f"b{RLO}"]])
    assert "+b[U+202E]" in ["".join(chunks) for chunks in hidden]


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


# --- a managed review save's change (M6 design G.4, J.3; step 15a) ----------------------------


def test_a_managed_save_is_the_change_fragment_2_would_write() -> None:
    """G.4: the same change as fragment 2, its title the snippet's, for the planner to plan;
    the indent, a fragment's, is ignored; nothing is checked here (the vault's gate checks the
    candidate)."""
    report = held(large())
    body = {"include": ["read_01", "add"], "allow": ["read_01"], "approve": ["add"]}
    made = reviewview.change_of(report, NOTES, {**body, "indent": 4}, most=512)
    assert not isinstance(made, Refusal)
    chosen_ = reviewview.choices(body, 512)
    assert not isinstance(chosen_, Refusal)
    changes_ = reviewview.changes(report, chosen_)
    assert not isinstance(changes_, Refusal)
    assert made == cli_review.fragment(report, changes_)
    assert made.title == cli_review.title("notes")


def test_a_managed_save_refuses_as_the_diff_does() -> None:
    report = held(large())
    bad = {"include": "x", "allow": [], "approve": []}
    assert detail(reviewview.change_of(report, None, bad, most=512), "bad_body") == (
        "include is a list of tool names"
    )
    tight = {"include": ["echo", "add"], "allow": ["echo"], "approve": ["add"]}
    assert detail(reviewview.change_of(report, NOTES, tight, most=1), "bad_body") == (
        "include names at most 1 tools (max_tools_per_server)"
    )
    good = {"include": ["echo"], "allow": ["echo"], "approve": []}
    refused(reviewview.change_of(report, None, good, most=512), "review_stale")
    unknown = {"include": ["nope"], "allow": [], "approve": ["nope"]}
    found = reviewview.change_of(report, NOTES, unknown, most=512)
    assert "the server lists no tool nope" in detail(found)
    # A server whose name the policy can't hold: the change itself refuses it.
    renamed = {**report, "server": "no such name"}
    named = listed_server(committed(), "notes")
    assert named is not None
    listed_ = replace(named, name="no such name")
    empty: dict[str, list[str]] = {"include": [], "allow": [], "approve": []}
    assert "isn't a policy name" in detail(reviewview.change_of(renamed, listed_, empty, most=512))


# --- prompts and resources (M6 design L.7) -------------------------------------------------------


def kinds_held(**options: Any) -> dict[str, Any]:
    return held(kinds(**options))


def kind_row(view: dict[str, Any], kind: str, name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(r for r in view["tools"] if (r["kind"], r["name"]) == (kind, name))
    return found


def as_listed(report: dict[str, Any]) -> Listed:
    """The running policy's entry for notes, as the kinds report ran under it."""
    ran = report["policy"]
    return Listed(
        "notes",
        "remote",
        Tools(include=ran["include"], allow=ran["allow"], approve=ran["approve"]),
        "hide",
        review=ran["review"],
        prompts=PromptsPolicy.model_validate(ran["prompts"]),
        resources=ResourcesPolicy.model_validate(ran["resources"]),
    )


TOOL_A = {"include": ["a"], "allow": ["a"], "approve": []}


def test_the_headings() -> None:
    assert HEADINGS == {
        "prompt": "Prompts",
        "resource_template": "Resource templates",
        "resource": "Resources",
    }
    assert KIND_LISTS == ("include", "repin", "decline")


def test_prompts_and_resources_are_rows_by_kind_under_a_heading_each() -> None:
    """The rows after the tools, grouped by kind whatever order the report lists them in, the
    first of each kind under its heading; each posts its name or URI; the counts stay the
    tools'."""
    report = kinds_held()
    view = rows(report)
    assert [(r["kind"], r["name"], r["heading"]) for r in view["tools"]] == [
        ("tool", "a", None),
        ("prompt", "bad", "Prompts"),
        ("prompt", "drifts", None),
        ("prompt", "fine", None),
        ("prompt", "new", None),
        ("prompt", "old", None),
        ("prompt", "gone", None),
        ("resource_template", TEMPLATE, "Resource templates"),
        ("resource", INDEX, "Resources"),
        ("resource", OTHER_URI, None),
    ]
    assert (view["counts"]["tools"], view["counts"]["included"]) == (1, 1)
    shuffled = {**report, "tools": list(reversed(report["tools"]))}
    assert [r["kind"] for r in rows(shuffled)["tools"]] == [r["kind"] for r in view["tools"]]
    assert [r["heading"] for r in rows(shuffled)["tools"]][1:3] == ["Prompts", None]
    drifts = kind_row(view, "prompt", "drifts")
    assert (drifts["state"], drifts["pinnable"], drifts["reviewed_missing"]) == (
        "drift",
        True,
        False,
    )
    assert drifts["pinned"] == prompt_pin("drifts", description=PROMPT_OLD)
    assert drifts["reviewed_lines"]
    assert any('"Old."' in "".join(line) for line in drifts["diff_lines"])
    gone = kind_row(view, "prompt", "gone")
    assert (gone["state"], gone["not_pinnable"]) == ("missing", GONE)
    index = kind_row(view, "resource", INDEX)
    assert (index["title_shown"], index["pin"], index["classification"]) == (
        "Index",
        INDEX_PIN,
        None,
    )
    tools_only = rows(held(large()))
    assert {r["kind"] for r in tools_only["tools"]} == {"tool"}
    assert {r["heading"] for r in tools_only["tools"]} == {None}


def test_a_uri_is_shown_whole_up_to_the_longest_the_policy_holds() -> None:
    """A name is cut at a name's cap, and a template's or a fixed resource's URI only past the
    longest its set holds (L.1): two resources whose URIs share their first 128 characters
    still look different in the rows they're included from."""
    assert NAME_LIMITS == {"resource_template": 1024, "resource": 2048}
    report = kinds_held()
    stem = "notes://" + "n" * 140
    index = entry(report, INDEX)
    index["name"] = stem + "/a"
    entry(report, OTHER_URI)["name"] = stem + "/b"
    entry(report, TEMPLATE)["name"] = "notes://{id}/" + "t" * 1100
    entry(report, "fine")["name"] = "p" * 130
    view = rows(report)
    fixed = [r["name_shown"] for r in view["tools"] if r["kind"] == "resource"]
    assert fixed == [stem + "/a", stem + "/b"]
    (templated,) = [r["name_shown"] for r in view["tools"] if r["kind"] == "resource_template"]
    assert templated == ("notes://{id}/" + "t" * 1100)[:1024] + "…[+89]"
    assert "p" * 128 + "…[+2]" in {r["name_shown"] for r in view["tools"]}
    index["name"] = "notes://" + "n" * 2050
    assert {r["name_shown"] for r in rows(report)["tools"] if r["kind"] == "resource"} >= {
        "notes://" + "n" * 2040 + "…[+10]"
    }


def test_a_resources_annotations_suggest_nothing() -> None:
    """A tool's annotations hint at its calls; a prompt's or a resource's never do, so a hint in
    one is no suggestion, and its title isn't taken from them."""
    report = kinds_held()
    hinted = copy.deepcopy(report)
    found = next(e for e in hinted["tools"] if e["name"] == INDEX)
    found["definition"]["annotations"] = {"readOnlyHint": True, "title": "Hinted"}
    del found["definition"]["title"]
    index = kind_row(rows(hinted), "resource", INDEX)
    assert (index["suggested"], index["suggested_why"]) == ("approve", WHY_UNANNOTATED)
    assert (index["annotated"], index["read_only_hint"], index["title_shown"]) == (
        False,
        False,
        None,
    )


def test_how_each_kinds_walk_went_is_a_note() -> None:
    """Why a kind's walk failed, shown, and the gateway's finding that a list was cut."""
    report = kinds_held(failure="entries " + RLO, cut=True)
    assert notes(report) == [
        "Prompts: the gateway couldn't list them (entries [U+202E]), so none is served.",
        "Resources: the server lists more than the review could take under gateway.limits: "
        "the first 2 are shown.",
    ]
    assert rows(report)["notes"] == notes(report)
    assert notes(kinds_held()) == []
    blocked = {**kinds_held(failure="pages"), "blocked": True}
    assert notes(blocked)[0] == "blocked"


def test_choices_take_each_kinds_lists() -> None:
    made = choices(
        {
            **TOOL_A,
            "kinds": {
                "prompt": {"include": ["fine"], "repin": ["fine"], "decline": ["new"]},
                "resource": {"include": [INDEX]},
                "resource_template": {},
            },
        },
        2,
    )
    assert isinstance(made, Choices)
    assert made.kinds == {
        "prompt": KindChoice(("fine",), frozenset({"fine"}), ("new",)),
        "resource": KindChoice((INDEX,)),
        "resource_template": KindChoice(),
    }
    assert chosen(["a"], ["a"]).kinds == {}


@pytest.mark.parametrize(
    ("kinds_", "said"),
    [
        ([], "kinds maps prompt, resource_template or resource to its lists"),
        ({"tool": {}}, "kinds maps prompt, resource_template or resource to its lists"),
        ({"prompt": []}, "kinds.prompt holds include, repin and decline"),
        ({"prompt": {"allow": []}}, "kinds.prompt holds include, repin and decline"),
        ({"prompt": {"include": "fine"}}, "kinds.prompt.include is a list of prompt names"),
        ({"prompt": {"include": [1]}}, "kinds.prompt.include is a list of prompt names"),
        ({"prompt": {"repin": ["a b"]}}, "kinds.prompt.repin is a list of prompt names"),
        (
            {"resource_template": {"decline": ["x"]}},
            "kinds.resource_template.decline is a list of resource template names",
        ),
        (
            {"resource": {"include": [TEMPLATE]}},
            "kinds.resource.include is a list of resource names",
        ),
        ({"prompt": {"include": ["f", "f"]}}, "kinds.prompt.include names a prompt twice"),
        (
            {"resource": {"include": [INDEX, OTHER_URI, "notes://third"]}},
            "kinds.resource.include names at most 2 resources (max_tools_per_server)",
        ),
    ],
    ids=[
        "not-a-mapping",
        "a-tool",
        "lists-not-a-mapping",
        "another-list",
        "not-a-list",
        "not-a-string",
        "not-a-prompt-name",
        "not-a-template",
        "not-a-fixed-uri",
        "twice",
        "too-many",
    ],
)
def test_choices_of_kinds_of_the_wrong_shape(kinds_: object, said: str) -> None:
    assert detail(choices({**TOOL_A, "kinds": kinds_}, 2), "bad_body") == said


def test_each_kinds_choices_change_its_block() -> None:
    """A kind named is changed as chosen; a kind not named stays as the policy has it, and
    with Record the rest as declined every kind's other listed entries are declined."""
    report = kinds_held()
    new = entry(report, "new")["pin"]
    named = {
        "prompt": {"include": ["fine", "drifts", "new"], "repin": ["drifts"], "decline": ["old"]},
        "resource": {"include": [INDEX], "decline": [OTHER_URI]},
    }
    made = changes(report, chosen(["a"], ["a"], kinds=named))
    assert not isinstance(made, Refusal)
    assert made.kinds == {
        "prompt": KindChanges(
            ("fine", "drifts", "new"), frozenset({"drifts"}), {"old": prompt_pin("old")}
        ),
        "resource": KindChanges((INDEX,), frozenset(), {OTHER_URI: OTHER_URI_PIN}),
    }
    rest = changes(report, chosen(["a"], ["a"], decline_rest=True))
    assert not isinstance(rest, Refusal)
    assert rest.kinds == {
        "prompt": KindChanges(
            ("fine", "drifts", "gone"), frozenset(), {"new": new, "old": prompt_pin("old")}
        ),
        "resource_template": KindChanges((TEMPLATE,), frozenset(), None),
        "resource": KindChanges((), frozenset(), {INDEX: INDEX_PIN, OTHER_URI: OTHER_URI_PIN}),
    }
    both = changes(report, chosen(["a"], ["a"], kinds={"prompt": {}}, decline_rest=True))
    assert not isinstance(both, Refusal)
    assert both.kinds["prompt"].include == ()
    assert set(both.kinds["prompt"].declined or {}) == {"drifts", "fine", "new", "old"}
    kept = changes(report, chosen(["a"], ["a"], kinds={"prompt": {"include": ["gone"]}}))
    assert not isinstance(kept, Refusal)
    assert kept.kinds["prompt"].include == ("gone",)  # included, not listed: it may stay


def test_a_block_member_the_report_leaves_out_is_its_default() -> None:
    """A report held with its templates block's ``include`` and the prompts block's
    ``declined`` and ``assistant`` unset: the choices read them as their defaults, and the
    fragment is made."""
    raw = kinds()
    prompts = raw["policy"]["prompts"]
    raw["policy"]["prompts"] = {"include": prompts["include"], "review": prompts["review"]}
    raw["policy"]["resources"] = {"templates": {"review": {}}}
    report = held(raw)
    rest = changes(report, chosen(["a"], ["a"], decline_rest=True))
    assert not isinstance(rest, Refusal)
    assert rest.kinds["resource_template"] == KindChanges((), frozenset(), {TEMPLATE: TEMPLATE_PIN})
    assert rest.kinds["prompt"].include == ("fine", "drifts", "gone")
    made = cli_review.fragment(report, rest)
    assert made.title.endswith("blocks of gateway.servers.notes.")


@pytest.mark.parametrize(
    ("named", "said"),
    [
        ({"prompt": {"include": ["nope"]}}, "the server lists no prompt nope"),
        ({"prompt": {"include": ["bad"]}}, "bad can't be pinned, so it can't be included"),
        (
            {"prompt": {"include": ["fine"], "repin": ["fine"]}},
            "fine hasn't drifted, so there is no new definition to accept",
        ),
        (
            {"prompt": {"include": ["fine"], "repin": ["drifts"]}},
            "drifts is re-pinned but not included",
        ),
        ({"prompt": {"decline": ["nope"]}}, "the server lists no prompt nope"),
        ({"prompt": {"include": ["new"], "decline": ["new"]}}, "new is declined but included"),
        ({"prompt": {"decline": ["bad"]}}, "bad can't be pinned, so it can't be declined"),
        ({"resource": {"include": ["notes://nope"]}}, "the server lists no resource notes://nope"),
        (
            {"resource_template": {"decline": ["notes://n/{x}"]}},
            "the server lists no resource template notes://n/{x}",
        ),
    ],
    ids=[
        "unknown",
        "unpinnable",
        "repin-not-drifted",
        "repin-left-out",
        "decline-unknown",
        "decline-included",
        "decline-unpinnable",
        "unknown-resource",
        "unknown-template",
    ],
)
def test_what_cant_be_chosen_of_a_kind(named: dict[str, Any], said: str) -> None:
    assert f"({said})" in detail(changes(kinds_held(), chosen(["a"], ["a"], kinds=named)))


def test_a_kind_the_server_doesnt_enable_cant_be_chosen() -> None:
    report = held(large())
    said = detail(changes(report, chosen([], kinds={"prompt": {}})))
    assert "(the server doesn't enable prompts)" in said
    both: dict[str, Any] = {"resource": {}, "resource_template": {}}
    said = detail(changes(report, chosen([], kinds=both)))
    assert "(the server doesn't enable resource templates, resources)" in said
    made = changes(report, chosen([], decline_rest=True))
    assert not isinstance(made, Refusal)
    assert made.kinds == {}


def test_a_report_is_stale_once_the_servers_prompts_or_resources_changed() -> None:
    """Fragment 2 writes a server's prompts and resources blocks whole (L.7): a report made
    before either changed would undo it; a report without a block ran under none."""
    report = kinds_held()
    same = as_listed(report)
    assert not stale(report, same)
    assert stale(report, replace(same, prompts=PromptsPolicy()))
    assert stale(report, replace(same, resources=ResourcesPolicy()))
    prompts_only = copy.deepcopy(report)
    del prompts_only["policy"]["resources"]
    assert not stale(prompts_only, replace(same, resources=ResourcesPolicy()))
    del prompts_only["policy"]["prompts"]
    assert not stale(prompts_only, replace(same, prompts=PromptsPolicy()))
    # The running policy's blocks are the listed server's.
    policy = committed()
    assert policy.gateway is not None
    notes_ = policy.gateway.servers["notes"].model_copy(
        update={"prompts": same.prompts, "resources": same.resources}
    )
    servers = {**policy.gateway.servers, "notes": notes_}
    found = listed_server(
        policy.model_copy(
            update={"gateway": policy.gateway.model_copy(update={"servers": servers})}
        ),
        "notes",
    )
    assert found is not None
    assert (found.prompts, found.resources) == (same.prompts, same.resources)


def kinds_policy(report: dict[str, Any]) -> Policy:
    """committed() with notes enabling prompts and resources, as the kinds report ran under."""
    policy = committed()
    assert policy.gateway is not None
    same = as_listed(report)
    notes_ = policy.gateway.servers["notes"].model_copy(
        update={
            "enable": ["prompts", "resources"],
            "prompts": same.prompts,
            "resources": same.resources,
        }
    )
    gateway = policy.gateway.model_copy(
        update={"servers": {**policy.gateway.servers, "notes": notes_}}
    )
    return policy.model_copy(update={"gateway": gateway})


def test_fragment_2_writes_the_kinds_blocks() -> None:
    """From step 21b (L.11) ``check`` accepts a server that enables prompts and resources, so
    fragment 2 for it passes the merged check; its title names both blocks."""
    report = kinds_held()
    body = {**TOOL_A, "kinds": {"prompt": {"include": ["fine", "new"]}}}
    policy = kinds_policy(report)
    answer = run_diff(report, body, policy, server=as_listed(report))
    assert isinstance(answer, dict)
    text = answer["diff"]["yaml"]
    assert text.startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools:, review:, prompts: and "
        "resources: blocks of gateway.servers.notes, then assign notes to its clients.\n"
    )
    written = load_mapping(text)["gateway"]["servers"]["notes"]
    assert written["prompts"]["include"] == ["fine", "new"]
    assert written["prompts"]["assistant"] == ["fine"]
    assert written["resources"]["templates"]["include"] == [TEMPLATE]


def test_a_managed_save_carries_the_kinds_blocks() -> None:
    report = kinds_held()
    body = {**TOOL_A, "kinds": {"resource": {"include": [INDEX]}}}
    made = reviewview.change_of(report, as_listed(report), body, most=512)
    assert not isinstance(made, Refusal)
    [op] = [op for op in made.ops if isinstance(op, SetServerReview)]
    assert op.resources is not None
    assert dict(op.resources.fixed.review) == {INDEX: INDEX_PIN}
    assert op.prompts is not None
    assert op.prompts.include == ["fine", "drifts", "gone"]
    assert made.title == cli_review.title("notes", kinds=("prompts", "resources"))
    stale_ = reviewview.change_of(
        report, replace(as_listed(report), prompts=PromptsPolicy()), body, most=512
    )
    refused(stale_, "review_stale")


def test_the_compose_form_doubles_a_dollar_in_a_resources_uri(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fixed resource's URI may hold "$" (one of RFC 3986's sub-delims), which compose's
    interpolation would read: fragment 2's compose form writes it "$$" (TI-1), the plain one as
    it is."""
    dollar = "notes://a$b"
    report = held(kinds_report([], resources=[resource(uri=dollar, name="d")]))
    monkeypatch.setattr(reviewview, "validate", lambda policy, change: [])
    body = {**TOOL_A, "kinds": {"resource": {"include": [dollar]}}, "indent": "compose"}
    policy, server = kinds_policy(report), as_listed(report)
    compose = run_diff(report, body, policy, server=server)
    assert isinstance(compose, dict)
    assert '"notes://a$$b": "sha256:' in compose["diff"]["yaml"]
    plain = run_diff(report, {**body, "indent": 8}, policy, server=server)
    assert isinstance(plain, dict)
    assert '"notes://a$b": "sha256:' in plain["diff"]["yaml"]
    assert "$$" not in plain["diff"]["yaml"]
