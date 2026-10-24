"""The choices file of ``review <server> --choose`` and ``--choices`` (M7 design F.5; GR-2, TI-6,
TI-12, OPS-12): rendered from a report, read back, and refused when it is wrong or stale."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from mcp.types import Tool

from tests.fakes.mcp_server import LARGE_INVALID, LARGE_READ, LARGE_WRITE, base_tools, large_tools
from zoeymcp.cli import choices
from zoeymcp.cli import review as view
from zoeymcp.common.policy.emit import emit
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.common.suggest import suggestion
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import pins
from zoeymcp.gateway.review import report

LIMITS = GatewayLimits()
JOB = "3f9cQx_-job"
OTHER_PIN = "sha256:" + "0" * 64
# A report line's two digests, for a header written by hand.
DIGESTS = f"{OTHER_PIN} policy {OTHER_PIN}"


def served(
    include: list[str] = [],  # noqa: B006
    declined: list[str] = [],  # noqa: B006
    **classes: list[str],
) -> ViewRemoteServer:
    review = {name: pins.project_and_pin(Tool.model_validate(wire)).pin for name, wire in WIRES}
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": include, "allow": [], "approve": [], **classes},
            "review": {name: review[name] for name in include},
            "declined": {name: review[name] for name in declined},
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


def reviewed(wires: list[dict[str, Any]], server: ViewRemoteServer) -> dict[str, Any]:
    tools = [Tool.model_validate(wire) for wire in wires]
    evaluation = pins.evaluate(tools, server, frozenset(), LIMITS)
    return report(
        "notes",
        server,
        tools,
        evaluation,
        marks=frozenset(),
        defs=lambda pin: None,
        limits=LIMITS,
        era="modern",
        protocol_version="2026-07-28",
        server_info=None,
        instructions=None,
    )


LARGE = [*base_tools(), *large_tools()]
WIRES = [(wire["name"], wire) for wire in LARGE]


def large(
    include: list[str] = [],  # noqa: B006
    declined: list[str] = [],  # noqa: B006
    **classes: list[str],
) -> dict[str, Any]:
    """The ``large`` fake's 96 tools, reviewed against a server including ``include`` and
    declining ``declined`` at the pins listed."""
    return reviewed(copy.deepcopy(LARGE), served(include, declined, **classes))


def by_name(answer: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["name"]: entry for entry in answer["tools"]}


def file_of(answer: dict[str, Any], *, suggest: bool = False, job: str = JOB) -> str:
    return "\n".join(choices.render(answer, job, suggest=suggest)) + "\n"


def fragment_of(answer: dict[str, Any], text: str, job: str = JOB) -> dict[str, Any]:
    """The fragment ``--choices`` prints for ``text``, loaded back."""
    changes = choices.decide(answer, job, choices.parse(text))
    change = view.fragment(answer, changes, heading=view.second_title("notes"))
    entry: dict[str, Any] = load_mapping(emit(change))["gateway"]["servers"]["notes"]
    return entry


def refused(answer: dict[str, Any], text: str, job: str = JOB) -> choices.ChoicesRefused:
    with pytest.raises(choices.ChoicesRefused) as caught:
        choices.decide(answer, job, choices.parse(text))
    return caught.value


def rows(text: str) -> list[list[str]]:
    return [line.split("#")[0].split() for line in text.splitlines() if not line.startswith("#")]


def edited(text: str, tool: str, word: str) -> str:
    """``text`` with ``tool``'s word replaced, as an operator edits it."""
    out = []
    for line in text.splitlines(keepends=True):
        parts = line.split()
        if parts[:1] != ["#"] and len(parts) > 1 and parts[1] == tool:
            line = word + line[len(parts[0]) :]
        out.append(line)
    return "".join(out)


# --- rendering -----------------------------------------------------------------------------------


def test_the_header_and_one_line_per_listed_tool() -> None:
    answer = large()
    text = file_of(answer)
    lines = text.splitlines()
    assert lines[:4] == [
        '# zoeymcp review notes: 96 tools. Keep "skip", or write "allow", "approve" or '
        '"decline", on each line.',
        f"# report {JOB} {choices.report_digest(answer)} policy {choices.policy_digest(answer)}",
        "# allow: agents call it with no prompt. approve: every call asks you first.",
        "# The suggestions are the server's own annotations, not a judgement by ZoeyMCP.",
    ]
    found = rows(text)
    # Every listed tool but the one with an error finding, each with its full pin (TI-6).
    assert len(found) == 95
    pinned = {entry["name"]: entry["pin"] for entry in answer["tools"]}
    assert all(row[0] == "skip" and row[2] == pinned[row[1]] for row in found)
    assert f"# {LARGE_INVALID} can't be included: error finding (" in text
    [bad] = [line for line in lines if line.startswith(f"# {LARGE_INVALID} ")]
    assert bad.endswith(f"; review notes --show {LARGE_INVALID}")
    [read] = [line for line in lines if line.startswith("skip     read_01 ")]
    assert "   # read-only (the server's suggestion); finding: a URL " in read
    assert "   # not annotated: approve suggested if you include it" in text


def test_suggest_allows_only_what_the_server_marks_read_only() -> None:
    answer = large()
    found = rows(file_of(answer, suggest=True))
    allowed = sorted(row[1] for row in found if row[0] == "allow")
    read_only = [
        e["name"]
        for e in answer["tools"]
        if suggestion(e["definition"].get("annotations")) == "allow"
    ]
    assert allowed == sorted(read_only)
    assert len(allowed) == LARGE_READ + 1  # the base tools' read-only one
    writes = [row[0] for row in found if row[1].startswith("write_")]
    assert writes == ["skip"] * LARGE_WRITE


def test_the_large_fakes_96_tools_round_trip() -> None:
    """An unedited --suggest file includes the 64 read-only tools as allow, and nothing else;
    the operator's edits come back as the fragment's include, allow and approve."""
    answer = large()
    text = file_of(answer, suggest=True)
    entry = fragment_of(answer, text)
    pinned = {e["name"]: e["pin"] for e in answer["tools"]}
    assert len(entry["tools"]["include"]) == 64
    assert entry["tools"]["allow"] == entry["tools"]["include"]
    assert entry["tools"]["approve"] == []
    assert entry["review"] == {name: pinned[name] for name in entry["tools"]["include"]}
    text = edited(edited(edited(text, "write_01", "approve"), "read_02", "skip"), "add", "allow")
    entry = fragment_of(answer, text)
    assert "write_01" in entry["tools"]["approve"]
    assert "read_02" not in entry["tools"]["include"]
    assert "add" in entry["tools"]["allow"]
    assert set(entry["review"]) == set(entry["tools"]["include"])
    assert len(entry["tools"]["include"]) == 65


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.fixed_dictionaries(
            {},
            optional={
                "readOnlyHint": st.booleans(),
                "destructiveHint": st.booleans(),
                "idempotentHint": st.booleans(),
                "openWorldHint": st.booleans(),
            },
        ),
        min_size=1,
        max_size=8,
    )
)
def test_an_unedited_suggest_file_never_includes_an_unannotated_or_destructive_tool(
    hints: list[dict[str, bool]],
) -> None:
    """OPS-12, PC-2: whatever the annotations, an unedited --suggest file includes exactly the
    tools marked read-only and not destructive, each as allow."""
    wires = [
        {
            "name": f"tool_{index}",
            "description": "Does a thing.",
            "inputSchema": {"type": "object"},
            **({"annotations": hint} if hint else {}),
        }
        for index, hint in enumerate(hints)
    ]
    answer = reviewed(wires, served())
    changes = choices.decide(answer, JOB, choices.parse(file_of(answer, suggest=True)))
    expected = [
        f"tool_{index}"
        for index, hint in enumerate(hints)
        if hint.get("readOnlyHint") is True and hint.get("destructiveHint") is not True
    ]
    assert sorted(changes.added) == sorted(expected)
    assert all(added.classification == "allow" for added in changes.added.values())
    assert changes.dropped == frozenset()
    assert changes.moved == {}


def test_an_unedited_file_without_suggest_changes_nothing() -> None:
    answer = large(["echo", "read_01"], allow=["read_01"], approve=["echo"])
    text = file_of(answer)
    found = {row[1]: row[0] for row in rows(text)}
    # An included tool's line says its classification, so the file keeps it.
    assert (found["echo"], found["read_01"], found["read_02"]) == ("approve", "allow", "skip")
    assert "# in the policy as approve; " in text
    entry = fragment_of(answer, text)
    assert entry["tools"] == {
        "include": ["echo", "read_01"],
        "allow": ["read_01"],
        "approve": ["echo"],
    }
    # skip takes an included tool out; another word classifies it anew.
    entry = fragment_of(answer, edited(edited(text, "echo", "skip"), "read_01", "approve"))
    assert entry["tools"] == {"include": ["read_01"], "allow": [], "approve": ["read_01"]}
    assert list(entry["review"]) == ["read_01"]


def test_a_drifted_tool_has_no_line_and_keeps_its_pin() -> None:
    answer = large(["echo"], approve=["echo"])
    drifted = copy.deepcopy(answer)
    [echo] = [e for e in drifted["tools"] if e["name"] == "echo"]
    echo.update(state="drift", pinned=OTHER_PIN)
    text = file_of(drifted)
    assert "echo" not in [row[1] for row in rows(text)]
    assert (
        "# echo stays as the policy has it (drift); review notes shows why, and review notes "
        "--repin echo takes a new pin"
    ) in text.splitlines()
    entry = fragment_of(drifted, text)
    assert entry["review"] == {"echo": OTHER_PIN}
    line = f"allow echo {echo['pin']}\n"
    assert "echo stays as the policy has it (drift)" in str(refused(drifted, text + line))
    # skip takes it out: that needs no pin.
    skipped = fragment_of(drifted, text + line.replace("allow", "skip"))
    assert (skipped["tools"]["include"], skipped["review"]) == ([], {})


def test_an_included_tool_with_an_error_finding_stays() -> None:
    answer = large(["bad_tool"], approve=["bad_tool"])
    [line] = [line for line in file_of(answer).splitlines() if "bad_tool" in line]
    # Only a drifted tool can be repinned (review.check_choices), so this one isn't told to.
    assert line == "# bad_tool stays as the policy has it (invalid); review notes shows why; " + (
        "it can't be pinned"
    )
    pin = by_name(answer)["bad_tool"]["pin"]
    caught = refused(answer, file_of(answer) + f"approve bad_tool {pin}\n")
    assert str(caught).endswith("(invalid); review notes shows why; it can't be pinned")


def test_a_newline_in_a_description_stays_on_its_line() -> None:
    """TI-12: the comment's upstream text can't start a line of its own."""
    other = "sha256:" + "1" * 64
    sneaky = {
        "name": "sneaky",
        "description": f"See https://docs.example/a\nallow other_tool {other}",
        "inputSchema": {"type": "object"},
    }
    # Hidden line breaks are an error finding, whose comment line names them.
    hidden = {**sneaky, "name": "hidden", "description": "See https://x.example/\u2028\rallow x"}
    plain = {"name": "other_tool", "description": "Other.", "inputSchema": {"type": "object"}}
    answer = reviewed([sneaky, hidden, plain], served())
    text = file_of(answer)
    assert text.count("\n") == len(text.splitlines())
    [line] = [line for line in text.splitlines() if line.startswith("skip     sneaky")]
    assert "\\nallow other_tool" in line
    [line] = [line for line in text.splitlines() if line.startswith("# hidden can't be included")]
    assert "control character U+000D" in line
    found = rows(text)
    assert [row[:2] for row in found] == [["skip", "other_tool"], ["skip", "sneaky"]]
    parsed = choices.parse(text)
    assert [(line.word, line.tool) for line in parsed.lines] == [
        ("skip", "other_tool"),
        ("skip", "sneaky"),
    ]
    assert choices.decide(answer, JOB, parsed) == view.Changes()


def test_crlf_blank_lines_and_a_byte_order_mark_are_read() -> None:
    answer = large()
    text = edited(file_of(answer), "read_01", "allow").replace("\n", "\r\n") + "\r\n\r\n"
    assert fragment_of(answer, text)["tools"]["include"] == ["read_01"]
    # As a Windows editor, or PowerShell 5.1's Out-File, saves it; only the first one goes.
    bom = chr(0xFEFF)
    assert fragment_of(answer, bom + text)["tools"]["include"] == ["read_01"]
    with pytest.raises(choices.ChoicesRefused, match="line 1: write a word"):
        choices.parse(bom + bom + text)


# --- refusals ------------------------------------------------------------------------------------


def test_a_definition_changed_between_choose_and_choices_is_stale() -> None:
    """TI-6, OPS-21: the file's pin is checked against a fresh listing, and every tool whose pin
    changed is named before anything is pinned."""
    answer = large()
    text = edited(file_of(answer), "read_01", "allow")
    text = edited(edited(text, "read_02", "approve"), "read_03", "allow")
    changed = copy.deepcopy(LARGE)
    for wire in changed:
        if wire["name"] in ("read_01", "read_02", "write_01"):
            wire["description"] += " Changed."
    later = reviewed(changed, served())
    stale = refused(later, text, job="another-job")
    assert stale.reason == "choices_stale"
    assert stale.tools == ("read_01", "read_02")  # write_01 says skip: nothing to pin
    assert "changed since review --choose wrote the file: read_01, read_02" in str(stale)
    # The same tools unchanged in a newer report pass: only the pins are compared.
    assert fragment_of(large(), text, job="another-job")["tools"]["include"] == [
        "read_01",
        "read_02",
        "read_03",
    ]


def test_a_tool_gone_from_a_newer_listing_is_stale_unless_skipped() -> None:
    answer = large()
    text = edited(file_of(answer), "read_01", "allow")
    fewer = reviewed([w for w in LARGE if w["name"] not in ("read_01", "read_02")], served())
    assert refused(fewer, text, job="another-job").tools == ("read_01",)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda t: edited(t, "read_01", "alow"), '"alow" isn\'t skip, allow, approve or decline'),
        (lambda t: edited(t, "read_01", "Allow"), '"Allow" isn\'t skip, allow, approve or decline'),
        (lambda t: t + f"skip read_01 {OTHER_PIN}\n", "read_01 is on line "),
        (lambda t: t + "allow read_99\n", "write a word, the tool's name and its pin"),
        (lambda t: t + "allow read_99 sha256:abc\n", "read_99's pin isn't sha256: and 64 hex"),
        (lambda t: t + f"allow read_99 {OTHER_PIN} extra\n", "write a word, the tool's name"),
        (lambda t: t + f"allow b@d {OTHER_PIN}\n", "b@d isn't a tool name"),
        (lambda t: t + f"allow read_99 {OTHER_PIN}\n", "the server lists no tool read_99"),
        (lambda t: t + f"# report {JOB} {DIGESTS}\n", "a second report line"),
    ],
)
def test_choices_invalid_names_the_line(change: Any, message: str) -> None:
    answer = large()
    caught = refused(answer, change(file_of(answer)))
    assert caught.reason == "choices_invalid"
    assert message in str(caught)
    assert str(caught).startswith("line ")


def test_a_pin_edited_in_the_same_report_is_invalid() -> None:
    answer = large()
    text = file_of(answer)
    pin = by_name(answer)["read_01"]["pin"]
    caught = refused(answer, text.replace(pin, OTHER_PIN))
    assert text.count(pin) == 1
    assert caught.reason == "choices_invalid"
    assert "read_01's pin isn't the one the server lists" in str(caught)


def test_a_tool_with_an_error_finding_cant_be_included() -> None:
    answer = large()
    bad = by_name(answer)[LARGE_INVALID]
    line = f"allow {LARGE_INVALID} {bad['pin']}\n"
    caught = refused(answer, file_of(answer) + line)
    assert f"{LARGE_INVALID} has an error finding, so it can't be pinned" in str(caught)
    # skip on it is no change.
    skipped = choices.parse(file_of(answer) + line.replace("allow", "skip"))
    assert choices.decide(answer, JOB, skipped) == view.Changes()


def test_a_consequential_tool_cant_be_allowed() -> None:
    answer = large()
    for entry in answer["tools"]:
        if entry["name"] == "read_01":
            entry["consequential"] = True
    text = file_of(answer, suggest=True)
    assert [row[0] for row in rows(text) if row[1] == "read_01"] == ["skip"]
    assert "declared consequential by the toolkit" in text
    caught = refused(answer, edited(text, "read_01", "allow"))
    assert "the toolkit declares read_01 consequential" in str(caught)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("allow read_01 " + OTHER_PIN + "\n", "no zoeymcp review header and report line"),
        ('# zoeymcp review notes: 1 tool. Keep "skip".\n', "no zoeymcp review header"),
        (f"# report {JOB} {DIGESTS}\n", "no zoeymcp review header"),
        # A report line without the policy's digest is only a comment.
        (f"# zoeymcp review notes: x\n# report {JOB} {OTHER_PIN}\n", "no zoeymcp review header"),
        (
            f"# zoeymcp review notes: x\n# report b@d {DIGESTS}\n",
            "line 2: the report line's job isn't a job ID",
        ),
    ],
)
def test_the_header_is_required(text: str, message: str) -> None:
    with pytest.raises(choices.ChoicesRefused, match=message):
        choices.parse(text)


def test_a_file_for_another_server_is_invalid() -> None:
    answer = large()
    text = file_of(answer).replace("# zoeymcp review notes:", "# zoeymcp review mail:")
    assert "the file is for mail, and this review is of notes" in str(refused(answer, text))


def test_a_file_too_large_isnt_read(monkeypatch: pytest.MonkeyPatch) -> None:
    assert choices.FILE_MAX == 16 * 2**20
    with pytest.raises(choices.ChoicesRefused, match="the file is over 16 MiB"):
        choices.parse("#" * (choices.FILE_MAX + 1))
    monkeypatch.setattr(choices, "FILE_MAX", 10)
    with pytest.raises(choices.ChoicesRefused, match="no zoeymcp review header"):
        choices.parse("#" * 10)


def test_the_digest_is_of_the_report_with_its_keys_sorted() -> None:
    answer = large()
    other = copy.deepcopy(answer)
    other["instructions"] = "x"
    assert choices.report_digest(answer) != choices.report_digest(other)
    reordered = dict(reversed(list(answer.items())))
    assert choices.report_digest(answer) == choices.report_digest(reordered)
    text = '{"a":"\\u00e9","b":[1,null]}'
    assert choices.report_digest({"b": [1, None], "a": "é"}) == (
        "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    )


def test_the_report_lines_job() -> None:
    answer = large()
    head = file_of(answer).splitlines()[0]
    policy = "sha256:" + "2" * 64
    for job in (choices.NO_JOB, "a" * 64, "A-z_0"):
        parsed = choices.parse(f"{head}\n# report {job} {OTHER_PIN} policy {policy}\n")
        found = (parsed.server, parsed.job, parsed.digest, parsed.policy)
        assert found == ("notes", job, OTHER_PIN, policy)
    for job in ("a" * 65, "b@d", "a.b"):
        with pytest.raises(choices.ChoicesRefused, match="line 2: the report line's job"):
            choices.parse(f"{head}\n# report {job} {DIGESTS}\n")
    assert choices.NO_JOB == "-"
    # Only the first header counts; a later one is a comment.
    parsed = choices.parse(file_of(answer) + "# zoeymcp review mail: 1 tool.\n")
    assert parsed.server == "notes"


def test_a_long_finding_is_cut_and_the_rest_counted() -> None:
    """A report's finding is the gateway's text, shown cut to 100 characters (F.5)."""
    answer = reviewed([LARGE[0]], served())
    [entry] = answer["tools"]
    entry["findings"] = [
        {"level": "warning", "pointer": "/description", "message": "m" * 150},
        {"level": "note", "pointer": "/annotations", "message": "suggested by the server: allow"},
        {"level": "note", "pointer": "/inputSchema", "message": "a pattern"},
        {"level": "note", "pointer": "/inputSchema", "message": "another"},
    ]
    [line] = rows_text(file_of(answer))
    # The gateway's own suggestion finding isn't repeated: the rule beside it says the same.
    assert line.endswith(f"; finding: {'m' * 100}... (and 2 more)")
    assert choices.COMMENT_CHARS == 100
    entry["findings"] = entry["findings"][:1]
    [line] = rows_text(file_of(answer))
    assert line.endswith(f"; finding: {'m' * 100}...")
    # Only the suggestion, at /annotations, is left out: not another finding there, nor a
    # message elsewhere that starts the same way.
    entry["findings"] = [
        {"level": "note", "pointer": "/annotations", "message": "suggested by the server: allow"},
        {"level": "warning", "pointer": "/annotations", "message": "contradictory hints"},
        {"level": "note", "pointer": "/description", "message": "suggested wording"},
    ]
    [line] = rows_text(file_of(answer))
    assert line.endswith("; finding: contradictory hints (and 1 more)")


def test_a_row_in_full() -> None:
    """Names of different lengths line up; a tool without a line doesn't set the width."""
    wires = [
        {**LARGE[0], "name": "a", "annotations": {"readOnlyHint": True}},
        {"name": "longer_name", "description": "Does a thing.", "inputSchema": {"type": "object"}},
        {**next(w for w in LARGE if w["name"] == LARGE_INVALID), "name": "the_longest_name_of_all"},
    ]
    answer = reviewed(wires, served())
    pinned = {e["name"]: e["pin"] for e in answer["tools"]}
    assert choices.render(answer, JOB, suggest=True)[4:6] == [
        f"allow    a            {pinned['a']}   # read-only (the server's suggestion)",
        f"skip     longer_name  {pinned['longer_name']}   # not annotated: approve suggested if "
        "you include it",
    ]


def rows_text(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.startswith("#")]


def test_one_tool_and_a_name_the_policy_cant_hold() -> None:
    answer = reviewed([LARGE[0]], served())
    assert file_of(answer).startswith("# zoeymcp review notes: 1 tool. Keep")
    named = copy.deepcopy(answer)
    named["tools"][0]["name"] = "b@d"
    lines = choices.render(named, JOB, suggest=True)
    assert lines[4:] == ["# b@d can't be included: it can't be pinned; review notes --show b@d"]


def test_skip_on_a_changed_included_tool_takes_it_out() -> None:
    """Taking a tool out needs no pin, so a newer listing doesn't hold it up."""
    answer = large(["write_01", "read_01"], approve=["write_01"], allow=["read_01"])
    text = edited(file_of(answer), "write_01", "skip")
    changed = copy.deepcopy(LARGE)
    for wire in changed:
        if wire["name"] == "write_01":
            wire["description"] += " Changed."
    later = reviewed(
        changed, served(["write_01", "read_01"], approve=["write_01"], allow=["read_01"])
    )
    changes = choices.decide(later, "another-job", choices.parse(text))
    assert changes == view.Changes(dropped=frozenset({"write_01"}))
    entry = fragment_of(later, text, job="another-job")
    assert entry["tools"] == {"include": ["read_01"], "allow": ["read_01"], "approve": []}


def test_a_file_written_against_other_tools_in_the_policy_is_stale() -> None:
    """An unedited file says skip on a tool the policy didn't include then, and allow on one it
    did: applied after the operator changed that, it would take out, or put back, what they
    changed. The policy's digest on the report line refuses it."""
    before = large()
    text = file_of(before)  # read_01 says skip
    after = large(["read_01"], allow=["read_01"])
    caught = refused(after, text, job="another-job")
    assert caught.reason == "choices_stale"
    assert str(caught) == (
        "the policy's tools for notes changed since review --choose wrote the file; write it "
        "again (review notes --choose)"
    )
    # The other way: read_01 says allow, and the operator has since taken it out.
    assert refused(before, file_of(after), job="another-job").reason == "choices_stale"
    # Reclassified since is a change too.
    moved = large(["read_01"], approve=["read_01"])
    assert refused(moved, file_of(after), job="another-job").reason == "choices_stale"


def test_the_policys_digest_is_of_its_tools_alone() -> None:
    answer = large(["read_01", "echo"], allow=["read_01"], approve=["echo"])
    digest = choices.policy_digest(answer)
    reordered = copy.deepcopy(answer)
    reordered["policy"]["include"].reverse()
    reordered["policy"]["on_drift"] = "block"
    assert choices.policy_digest(reordered) == digest
    text = '{"allow":["read_01"],"approve":["echo"],"include":["echo","read_01"]}'
    assert digest == "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    # So a newer report at the same policy reads the file as before.
    assert fragment_of(reordered, file_of(answer), job="another-job")["tools"] == {
        "include": ["echo", "read_01"],
        "allow": ["read_01"],
        "approve": ["echo"],
    }


def head_of(answer: dict[str, Any]) -> str:
    """The four header lines ``--choose`` writes for ``answer``, so the next line is line 5."""
    return "\n".join(file_of(answer).splitlines()[:4]) + "\n"


def test_a_line_read_keeps_its_number_past_a_blank_line_and_a_hash_in_its_comment() -> None:
    """A blank line is skipped, not the end of the file; a comment is everything after the first
    #, whatever it holds."""
    answer = large()
    pin = by_name(answer)["read_01"]["pin"]
    text = head_of(answer) + f"\nallow read_01 {pin}   # see #2, and #3\n\n"
    parsed = choices.parse(text)
    assert parsed.lines == (choices.Line(6, "allow", "read_01", pin),)
    added = choices.decide(answer, JOB, parsed).added
    assert added == {"read_01": view.Added("allow", "allow, from the choices file")}
    # A whole file's lines keep theirs: the comment line in between counts too.
    text = file_of(answer)
    numbers = {line.tool: line.number for line in choices.parse(text).lines}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("#"):
            assert numbers[line.split()[1]] == number


def test_a_refusal_in_parsing_says_its_line_and_cuts_what_it_quotes() -> None:
    """A word is cut to 20 characters and a tool name to 128, as a comment's upstream text is."""
    answer = large()
    text = file_of(answer)
    end = len(text.splitlines()) + 1
    [first] = [n for n, line in enumerate(text.splitlines(), start=1) if " read_01 " in line]

    def message(line: str) -> str:
        with pytest.raises(choices.ChoicesRefused) as caught:
            choices.parse(text + line + "\n")
        assert caught.value.reason == "choices_invalid"
        return str(caught.value)

    word, cut_word = "w" * 21, "w" * 20 + "..."
    assert message(f"{word} read_01 {OTHER_PIN}") == (
        f'line {end}: "{cut_word}" isn\'t skip, allow, approve or decline'
    )
    tool, cut_tool = "t" * 129, "t" * 128 + "..."
    assert message(f"allow {tool} {OTHER_PIN}") == f"line {end}: {cut_tool} isn't a tool name"
    assert message(f"skip read_01 {OTHER_PIN}") == f"line {end}: read_01 is on line {first} too"
    assert message("allow read_99 sha256:abc") == (
        f"line {end}: read_99's pin isn't sha256: and 64 hex digits"
    )
    assert message(f"# report {JOB} {DIGESTS}") == f"line {end}: a second report line"


def test_a_refusal_in_deciding_says_its_line() -> None:
    answer = large()
    head = head_of(answer)
    caught = refused(answer, head + f"allow read_01 {OTHER_PIN}\n")
    assert str(caught) == "line 5: read_01's pin isn't the one the server lists"
    bad = by_name(answer)[LARGE_INVALID]["pin"]
    caught = refused(answer, head + f"allow {LARGE_INVALID} {bad}\n")
    assert str(caught) == f"line 5: {LARGE_INVALID} has an error finding, so it can't be pinned"
    included = large(["bad_tool"], approve=["bad_tool"])
    pin = by_name(included)["bad_tool"]["pin"]
    caught = refused(included, head_of(included) + f"approve bad_tool {pin}\n")
    assert str(caught) == (
        "line 5: bad_tool stays as the policy has it (invalid); review notes shows why; it can't "
        "be pinned"
    )
    for entry in answer["tools"]:
        if entry["name"] == "read_01":
            entry["consequential"] = True
    pin = by_name(answer)["read_01"]["pin"]
    caught = refused(answer, head_of(answer) + f"allow read_01 {pin}\n")
    assert str(caught) == (
        "line 5: the toolkit declares read_01 consequential, so it can't be in allow"
    )


def test_the_whole_file_refusals_are_choices_invalid() -> None:
    answer = large()
    text = file_of(answer).replace("# zoeymcp review notes:", "# zoeymcp review mail:")
    assert refused(answer, text).reason == "choices_invalid"
    with pytest.raises(choices.ChoicesRefused) as caught:
        choices.parse("#" * (choices.FILE_MAX + 1))
    assert caught.value.reason == "choices_invalid"
    with pytest.raises(choices.ChoicesRefused) as caught:
        choices.parse("")
    assert (caught.value.reason, str(caught.value)) == (
        "choices_invalid",
        "the file has no zoeymcp review header and report line; write it with review <server> "
        "--choose",
    )


def test_a_long_name_is_cut_in_a_comment_line() -> None:
    """A name the policy can't hold, included or not, is shown cut to 128 characters, and an
    error finding to 100; an included one that can't be pinned isn't told to repin, drifted or
    not."""
    answer = reviewed([LARGE[0], LARGE[1]], served())
    kept, unpinned = answer["tools"]
    kept.update(name="a" * 129, included=True, state="drift", classification="approve")
    unpinned["name"] = "b" * 129
    unpinned["findings"] = [{"level": "error", "pointer": "/description", "message": "m" * 150}]
    lines = choices.render(answer, JOB, suggest=False)
    kept_name, unpinned_name = "a" * 128 + "...", "b" * 128 + "..."
    assert lines[4:] == [
        f"# {kept_name} stays as the policy has it (drift); review notes shows why; it can't be "
        "pinned",
        f"# {unpinned_name} can't be included: error finding ({'m' * 100}...); review notes "
        f"--show {unpinned_name}",
    ]


# --- decline (M6 design J.3, J.5) ----------------------------------------------------------------


def test_decline_records_a_tool_at_its_pin() -> None:
    answer = large()
    text = file_of(answer)
    pin = by_name(answer)["read_01"]["pin"]
    changes = choices.decide(answer, JOB, choices.parse(edited(text, "read_01", "decline")))
    assert changes == view.Changes(declined={"read_01": pin})
    change = view.fragment(answer, changes, heading=view.second_title("notes", declined=True))
    emitted = emit(change)
    assert emitted.startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools:, review: and declined: blocks of "
        "gateway.servers.notes, then assign notes to its clients.\n"
    )
    assert f"# declined: read_01 ({pin})" in emitted.splitlines()
    assert f"# not included: read_01 ({pin}; " not in emitted
    entry = load_mapping(emitted)["gateway"]["servers"]["notes"]
    assert (entry["tools"]["include"], entry["review"]) == ([], {})
    assert entry["declined"] == {"read_01": pin}


def test_a_file_that_declines_nothing_writes_m7s_fragment() -> None:
    answer = large()
    changes = choices.decide(answer, JOB, choices.parse(file_of(answer)))
    assert changes == view.Changes()
    assert "declined" not in fragment_of(answer, file_of(answer))
    assert "declined" not in emit(view.fragment(answer, changes))


def test_a_declined_tools_line_says_decline_so_an_unedited_file_keeps_it() -> None:
    answer = large(declined=["read_01", "write_01"])
    text = file_of(answer, suggest=True)
    found = {row[1]: row[0] for row in rows(text)}
    assert (found["read_01"], found["write_01"], found["read_02"]) == (
        "decline",
        "decline",
        "allow",
    )
    [line] = [line for line in text.splitlines() if line.split()[1:2] == ["write_01"]]
    assert "# declined in the policy; " in line
    pins_ = {name: by_name(answer)[name]["pin"] for name in ("read_01", "write_01")}
    assert fragment_of(answer, edited(text, "read_02", "skip"))["declined"] == pins_
    # skip takes a tool out of declined; including it does too.
    entry = fragment_of(answer, edited(edited(text, "read_01", "skip"), "write_01", "approve"))
    assert entry["declined"] == {}
    assert entry["tools"]["approve"] == ["write_01"]
    assert "read_01" not in entry["tools"]["include"]


def test_decline_on_an_included_tool_takes_it_out() -> None:
    answer = large(["read_01", "echo"], allow=["read_01"], approve=["echo"])
    text = edited(file_of(answer), "echo", "decline")
    changes = choices.decide(answer, JOB, choices.parse(text))
    pin = by_name(answer)["echo"]["pin"]
    assert (changes.dropped, changes.declined) == (frozenset({"echo"}), {"echo": pin})
    entry = fragment_of(answer, text)
    assert entry["tools"] == {"include": ["read_01"], "allow": ["read_01"], "approve": []}
    assert entry["declined"] == {"echo": pin}


def test_a_declined_tool_that_changed_is_unreviewed_and_says_skip() -> None:
    """Its pin moved, so the policy's decline no longer holds: the file offers it again."""
    answer = large(declined=["read_01"])
    changed = copy.deepcopy(LARGE)
    for wire in changed:
        if wire["name"] == "read_01":
            wire["description"] += " Changed."
    later = reviewed(changed, served(declined=["read_01"]))
    assert by_name(later)["read_01"]["state"] == "unreviewed"
    text = file_of(later)
    assert {row[1]: row[0] for row in rows(text)}["read_01"] == "skip"
    # Declined again at the new pin, the old one replaced.
    new = by_name(later)["read_01"]["pin"]
    assert new != by_name(answer)["read_01"]["pin"]
    assert fragment_of(later, edited(text, "read_01", "decline"))["declined"] == {"read_01": new}


def test_a_tool_with_an_error_finding_cant_be_declined() -> None:
    answer = large()
    bad = by_name(answer)[LARGE_INVALID]["pin"]
    caught = refused(answer, head_of(answer) + f"decline {LARGE_INVALID} {bad}\n")
    assert str(caught) == f"line 5: {LARGE_INVALID} has an error finding, so it can't be pinned"
    caught = refused(answer, head_of(answer) + f"decline read_01 {OTHER_PIN}\n")
    assert str(caught) == "line 5: read_01's pin isn't the one the server lists"


def test_the_policys_digest_holds_declined_once_it_has_one() -> None:
    """A file written before a decline would undo it (skip), so it is stale after one."""
    before = large()
    assert choices.policy_digest(before) == choices.policy_digest(
        {**before, "policy": {**before["policy"], "declined": {}}}
    )
    after = large(declined=["read_01"])
    pin = by_name(after)["read_01"]["pin"]
    text = '{"allow":[],"approve":[],"declined":{"read_01":"' + pin + '"},"include":[]}'
    assert choices.policy_digest(after) == "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    assert refused(after, file_of(before), job="another-job").reason == "choices_stale"
