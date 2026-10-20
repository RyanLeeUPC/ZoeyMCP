"""The Ledger page, over the real API (M5 design J.4, J.5, J.6, K.1, Q2, Q3, Q12, D-25).

``GET /api/ledger`` pages the vault's copy of the gateway's ledger newest first, each call one row
with its sends from the SMTP connectors' journals, and the sends whose call the copy doesn't hold
as orphans; no keyed digest or pin is in any answer. A name the current policy lacks is marked,
every row says the gateway reported it (or, from M8, which record the vault wrote), and every
string from the gateway, a journal or ``head.json`` is shown with its hidden characters
revealed. While the copy refuses reports, every page has its banner, and ``ledger.restart``,
planned with every epoch it deletes and confirmed with a passkey, archives the chain, which the
page still reads. Hidden characters are written with ``chr()`` (the hygiene test).
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page
from tests.unit.test_ledgerjoin import RECORDS, REF_D, T, record
from zoeymcp.common import canonical, ledgerformat, ledgerreport
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.portal.app import LEDGER_BANNERS, ORPHAN_FLAGS, _ledger_view, _row_view
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.vault import ledgerview
from zoeymcp.vault.connectors import sendjournal
from zoeymcp.vault.reports import Held, LiveFile
from zoeymcp.vault.reportstore import REPORTED_DIR, ReportStore

from .flows import set_up, status_reason
from .rig import PortalRig, running
from .test_stepup import confirm, prepare, prepared, step_up

DIGEST = "hmac-sha256:" + "1" * 64
PIN = "sha256:" + "2" * 64
REFS = [f"{n:016x}" for n in range(0xA0, 0xA8)]
BIDI = chr(0x202E)


def policy() -> dict[str, Any]:
    """An SMTP connector the gateway's toolkit sends through, a remote server, one client."""
    return {
        "connectors": {
            "mail-out": {
                "kind": "smtp",
                "host": "smtp.mail.example",
                "port": 465,
                "username": "store:mail-user",
                "password": "store:mail-pass",
                "from": "agent@mail.example",
                "to": ["partner@mail.example"],
            }
        },
        "routes": [
            {
                "name": "mail-send",
                "prefix": "/mail",
                "connector": "mail-out",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/send"]}],
            },
            {
                "name": "notes",
                "prefix": "/notes",
                "upstream": "https://api.notes.example",
                "callers": ["gateway"],
                "stream": True,
                "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
            },
        ],
        "gateway": {
            "clients": {"agent1": {"token_sha256": "sha256:" + "3" * 64, "servers": ["mail"]}},
            "servers": {"mail": {"kind": "remote", "route": "notes"}},
        },
    }


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with running(tmp_path, policy=policy()) as portal:
        yield portal


@pytest.fixture
def signed_in(rig: PortalRig) -> tuple[Page, SoftAuthenticator]:
    authenticator = SoftAuthenticator()
    page = rig.browser().page(rig.origin)
    set_up(rig, page, authenticator)
    return page, authenticator


# --- the gateway's records, reported -------------------------------------------------------------


def now_ms() -> int:
    return int(time.time() * 1000)


def asked(ref: str, *, client: str = "agent1", tool: str = "send_note") -> dict[str, Any]:
    return {
        "kind": "asked",
        "ref": ref,
        "client": client,
        "server": "mail",
        "tool": tool,
        "where": "gateway",
        "era": "modern",
        "args": DIGEST,
        "pin": PIN,
        "text": DIGEST,
        "chars": 10,
        "writes": 1,
        "expires": 1,
    }


def decided(ref: str, decision: str = "accept") -> dict[str, Any]:
    return {"kind": "decided", "ref": ref, "decision": decision, "waited_ms": 812}


def outcome(ref: str) -> dict[str, Any]:
    fields = {"outcome": "ok", "detail": "sent", "writes_sent": 1, "writes_unknown": 0}
    return {"kind": "outcome", "ref": ref, **fields}


def chain(records: list[dict[str, Any]], *, ts: int) -> list[bytes]:
    """The records as one chain from seq 0, a millisecond apart from ``ts``."""
    lines: list[bytes] = []
    prev = GENESIS
    for seq, fields in enumerate(records):
        line = ledgerformat.encode(seq=seq, prev=prev, ts=ts + seq, **fields)[:-1]
        lines.append(line)
        prev = line_hash(line)
    return lines


def copy_of(rig: PortalRig) -> ReportStore:
    assert rig.app.ledger is not None
    return rig.app.ledger.copy


def report(rig: PortalRig, lines: list[bytes]) -> Any:
    """A report as the endpoint applies it, on the vault's loop."""
    body = canonical.loads_strict(ledgerreport.encode(lines))
    return rig.call(lambda: copy_of(rig).report(body))


def journal(rig: PortalRig, *records: tuple[str, dict[str, Any]]) -> None:
    """The mail connector's send journal, as its sends wrote it."""
    folder = rig.state / "connectors" / "mail-out"
    folder.mkdir(parents=True, exist_ok=True)
    lines = [sendjournal.encode(kind, **fields) for kind, fields in records]  # type: ignore[arg-type]
    (folder / "journal-0000000000001.jsonl").write_bytes(b"".join(lines))


def sending(key: str, ts: int) -> tuple[str, dict[str, Any]]:
    fields = {
        "ts": ts,
        "key": key,
        "req_hmac": "hmac-sha256:" + "9" * 64,
        "key_id": "0" * 16,
        "subject_chars": 5,
        "body_chars": 9,
    }
    return "sending", fields


def sent(key: str, ts: int) -> tuple[str, dict[str, Any]]:
    return "sent", {"ts": ts, "key": key, "message_id": "<m1@mail.example>", "smtp_code": 250}


def ledger(page: Page, query: str = "") -> dict[str, Any]:
    answer = page.fetch("GET", "/api/ledger" + query)
    assert answer.status_code == 200, answer.text
    value: dict[str, Any] = answer.json()
    return value


# --- the page ------------------------------------------------------------------------------------


def test_a_page_of_the_copy(rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]) -> None:
    """J.5: one row per call, newest first, paged; the state line; no keyed digest or pin."""
    page, _ = signed_in
    empty = ledger(page)
    assert empty["state_shown"] == "The copy is ok: nothing reported yet."
    assert (empty["rows"], empty["orphans"], empty["archives"], empty["next"]) == ([], [], [], None)
    assert (empty["restartable"], empty["archive"]) == (False, None)
    ts = now_ms()
    lines = chain(
        [
            {"kind": "repaired", "ref": None, "torn_bytes": 7},
            asked(REFS[0]),
            decided(REFS[0]),
            outcome(REFS[0]),
            asked(REFS[1], tool="list_notes"),
        ],
        ts=ts,
    )
    report(rig, lines)
    answer = ledger(page)
    state = answer["state"]
    assert (state["state"], state["head_seq"], state["start_seq"]) == ("ok", 4, 0)
    assert answer["state_shown"] == (
        f"The copy is ok: head seq 4 ({line_hash(lines[4])}), the chain from seq 0; the head "
        f"last moved {state['reported_ago']} s ago."
    )
    assert [(row["kind"], row["seq"]) for row in answer["rows"]] == [
        ("call", 4),
        ("call", 1),
        ("repaired", 0),
    ]
    at = ledgerview.when(ts + 1)
    first = answer["rows"][1]
    assert first["text_shown"] == (
        f"{at} call {REFS[0]} (seq 1): agent1 asked for mail/send_note (modern); decision "
        "accept; outcome ok (sent); 1 write(s) asked, 1 sent, 0 unknown; reported by the "
        "gateway."
    )
    assert (first["client_shown"], first["server_shown"], first["tool_shown"]) == (
        "agent1",
        "mail",
        "send_note",
    )
    assert "client" not in first
    assert first["lines_shown"] == []
    assert answer["rows"][0]["text_shown"].endswith(
        "decision none yet; outcome none yet; 1 write(s) asked; reported by the gateway."
    )
    assert answer["rows"][2]["text_shown"] == (
        f"{ledgerview.when(ts)} ledger record repaired (seq 0): torn_bytes 7; reported by the "
        "gateway."
    )
    # Q12: never a keyed digest or a pin, in any answer about the copy.
    assert "hmac-sha256" not in json.dumps(answer)
    assert PIN not in json.dumps(answer)
    # Paged: the rows below a seq, then none.
    older = ledger(page, "?limit=1")
    assert ([row["seq"] for row in older["rows"]], older["next"]) == ([4], 4)
    rest = ledger(page, "?before=4&limit=200")
    assert ([row["seq"] for row in rest["rows"]], rest["next"]) == ([1, 0], None)


def test_a_name_the_policy_lacks_is_marked(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, _ = signed_in
    lines = chain([asked(REFS[0], client="agent9")], ts=now_ms())
    report(rig, lines)
    [row] = ledger(page)["rows"]
    assert row["not_in_policy"] == ["client"]
    assert row["lines_shown"] == ["Not in the current policy: client agent9."]


def test_the_sends_are_joined_and_an_orphan_is_flagged(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    """D-25: a call shows its sends (state, SMTP code, time, never the Message-ID or the
    request's HMAC); a send whose call the copy doesn't hold is an orphan, flagged
    ``no_ledger_record`` once a report reached the copy after it began, else
    ``not_yet_reported``; orphans are on the live chain's first page only."""
    page, _ = signed_in
    ts = now_ms()
    joined, orphan, later = f"{REFS[0]}.1", f"{REFS[5]}.1", f"{REFS[6]}.1"
    journal(
        rig,
        sending(joined, ts - 2000),
        sent(joined, ts - 1000),
        sending(orphan, ts - 60_000),  # a send no call explains, in the copy's span
        sent(orphan, ts - 59_000),
        sending(later, ts + 3_600_000),  # after the copy's latest report
    )
    report(rig, chain([asked(REFS[0]), decided(REFS[0]), outcome(REFS[0])], ts=ts - 120_000))
    answer = ledger(page)
    [row] = answer["rows"]
    assert row["journal"] == [
        {"state": "sent", "smtp_code": 250, "at": ledgerview.when(ts - 1000), "key_shown": joined}
    ]
    assert row["lines_shown"] == [
        f"Send {joined}: sent, SMTP 250, at {ledgerview.when(ts - 1000)}."
    ]
    text = json.dumps(answer)
    assert "m1@mail.example" not in text
    assert "hmac-sha256" not in text
    assert [(o["key_shown"], o["flag"]) for o in answer["orphans"]] == [
        (later, "not_yet_reported"),
        (orphan, "no_ledger_record"),
    ]
    flagged = answer["orphans"][1]
    assert flagged["connector_shown"] == "mail-out"
    assert flagged["text_shown"] == (
        f"{ledgerview.when(ts - 59_000)} send {orphan} on mail-out: sent; "
        f"{ORPHAN_FLAGS['no_ledger_record']}."
    )
    assert ledger(page, "?before=1")["orphans"] == []


@pytest.mark.parametrize(
    "query",
    ["?before=x", "?limit=-1", "?other=1", "?limit=1&limit=2", "?before=" + "9" * 16, "?before"],
)
def test_a_bad_query_is_refused(signed_in: tuple[Page, SoftAuthenticator], query: str) -> None:
    page, _ = signed_in
    assert status_reason(page.fetch("GET", "/api/ledger" + query)) == (400, "bad_body")


def test_an_archive_the_copy_doesnt_list_is_404(signed_in: tuple[Page, SoftAuthenticator]) -> None:
    page, _ = signed_in
    for name in ("archive-0000000000001", "000000000000.jsonl", "..", ""):
        answer = page.fetch("GET", "/api/ledger?archive=" + name)
        assert status_reason(answer) == (404, "not_found"), name


def test_an_unreadable_copy_is_a_page_that_says_so(tmp_path: Path) -> None:
    """J.4: the copy is unavailable, the page says so, and nothing can restart it."""

    def unreadable(state: Path) -> None:
        (state / REPORTED_DIR).write_bytes(b"not a directory")

    with running(tmp_path, policy=policy(), before_start=unreadable) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        answer = ledger(page)
        assert answer["state"]["state"] == "unavailable"
        assert answer["state_shown"] == CATALOGUE["copy_unavailable"].text
        assert (answer["rows"], answer["restartable"]) == ([], False)
        refused = prepare(page, "ledger.restart", {})
        assert status_reason(refused) == (503, "copy_unavailable")


# --- what the renderer shows (J.6, K.1) -----------------------------------------------------------


HELD = Held("ok", 0, 12, "sha256:" + "f" * 64, (LiveFile("000000000000.jsonl", 900, T),))


def test_records_the_vault_wrote_are_rendered() -> None:
    """J.6: M8's vault-written records arrive through their own chain, never the report path
    (which refuses them), so the renderer is shown its fixtures: ``approved_elsewhere`` and
    ``pending``, each labelled as the vault's."""
    fields = {k: v for k, v in asked(REFS[7]).items() if k not in ("kind", "ref")}
    records = [
        *RECORDS,
        record(12, T + 90_000_000, REFS[7], "asked", **fields),
        record(13, T + 90_000_001, REFS[7], "decided", writer="vault", decision="pending"),
    ]
    page = ledgerview.page(records, held=HELD, journals={}, now=T + 90_000_002)
    answer = _ledger_view(page, None, [], None)
    by_ref = {row.get("ref"): row for row in answer["rows"]}
    elsewhere = by_ref[REF_D]
    assert elsewhere["decision"] == "approved_elsewhere"
    assert elsewhere["text_shown"].endswith(
        "decision approved_elsewhere; outcome none yet; 1 write(s) asked; asked reported by the "
        "gateway, decided written by the vault."
    )
    pending = by_ref[REFS[7]]
    assert "decision pending;" in pending["text_shown"]
    assert pending["text_shown"].endswith(
        "asked reported by the gateway, decided written by the vault."
    )
    assert "hmac-sha256" not in json.dumps(answer)


def test_hidden_characters_are_revealed() -> None:
    """K.1: a name that reached a row some other way than the report path's format check (M8's
    own chain, an edited file) is capped and its hidden characters shown."""
    row = {
        "kind": "call",
        "seq": 3,
        "ref": REFS[0],
        "at": "2026-01-01T14:00:00Z",
        "client": f"agent{BIDI}1",
        "server": "x" * 130,
        "tool": f"send{chr(0x200B)}",
        "era": "modern",
        "decision": None,
        "waited_ms": None,
        "outcome": None,
        "detail": None,
        "writes": 0,
        "writes_sent": None,
        "writes_unknown": None,
        "writers": {"asked": "gateway"},
        "not_in_policy": ["client"],
        "journal": [{"key": f"k{BIDI}.1", "state": "sent", "smtp_code": None, "at": "t"}],
    }
    view = _row_view(row)
    assert view["client_shown"] == "agent[U+202E]1"
    assert view["server_shown"] == "x" * 128 + chr(0x2026) + "[+2]"
    assert view["tool_shown"] == "send[U+200B]"
    assert "agent[U+202E]1 asked for" in view["text_shown"]
    assert view["lines_shown"] == [
        "Not in the current policy: client agent[U+202E]1.",
        "Send k[U+202E].1: sent, at t.",
    ]
    assert BIDI not in json.dumps(view)


def test_an_edited_head_json_is_shown_revealed(tmp_path: Path) -> None:
    """``head.json``'s refusal is checked only as an object: what it says is shown as text."""

    def edited(state: Path) -> None:
        folder = state / REPORTED_DIR
        folder.mkdir(mode=0o700)
        head = {
            "v": 1,
            "state": "fork",
            "start_seq": None,
            "start_prev": None,
            "head_seq": None,
            "head_hash": None,
            "refused": {"reason": f"fork{BIDI}", "held_seq": 3, "offered_seq": "x", "at": "?"},
            "files": {},
            "archives": [],
        }
        (folder / "head.json").write_bytes(canonical.dumps_canonical(head))

    with running(tmp_path, policy=policy(), before_start=edited) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        answer = ledger(page)
        assert answer["restartable"] is True
        assert (
            "fork[U+202E] at seq x, the copy holding seq 3, at an unknown time"
            in (answer["state_shown"])
        )
        assert BIDI not in json.dumps(answer)
        summary = prepared(page, "ledger.restart", {})["summary"]
        assert summary[0] == [
            "Restart the chain of",
            "the vault's copy, now fork: fork[U+202E] at seq x, the copy holding seq 3, at an "
            "unknown time",
        ]


# --- the restart (J.4, Q3) -----------------------------------------------------------------------


def forked(rig: PortalRig) -> tuple[list[bytes], int]:
    """A copy that took a chain, then refused another history from the same start."""
    ts = now_ms()
    lines = chain([asked(REFS[0]), decided(REFS[0]), outcome(REFS[0])], ts=ts)
    report(rig, lines)
    other = chain([asked(REFS[1]), decided(REFS[1])], ts=ts + 500)
    refused = report(rig, other)
    assert refused.reason == "fork"
    return lines, ts


def banners(page: Page) -> list[str]:
    """The copy's banners on the page (health's errors have their own)."""
    answer = page.fetch("GET", "/api/session")
    assert answer.status_code == 200, answer.text
    codes = [banner["code"] for banner in answer.json()["banners"]]
    return [code for code in codes if code.startswith("ledger_")]


def test_a_copy_that_takes_reports_isnt_restarted(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, _ = signed_in
    assert status_reason(prepare(page, "ledger.restart", {})) == (409, "not_restartable")
    assert len(rig.app.actions) == 0  # refused before any prompt


def test_the_chain_restarts_with_a_passkey(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    """Q2, Q3: a fork refuses every report, with a banner on every page, until a stepped-up
    restart; the plan names what it archives, and the archive stays readable."""
    page, authenticator = signed_in
    lines, ts = forked(rig)
    assert banners(page) == ["ledger_fork"]
    session = page.fetch("GET", "/api/session").json()
    assert {"code": "ledger_fork", "text": LEDGER_BANNERS["fork"]} in session["banners"]
    before = ledger(page)
    assert before["restartable"] is True
    assert (
        "Every report is refused until the chain is restarted: fork at seq 0"
        in (before["state_shown"])
    )
    held = prepared(page, "ledger.restart", {})
    epoch = (
        f"seq 0 to 2 (head {line_hash(lines[2])}), last received "
        f"{ledgerview.when(copy_of(rig).held.received_ms or 0)}, {sum(len(x) + 1 for x in lines)} "
        "bytes"
    )
    assert held["summary"] == [
        [
            "Restart the chain of",
            "the vault's copy, now fork: fork at seq 0, the copy holding seq 2, at "
            f"{ledgerview.when(copy_of(rig).refused['at'])}",  # type: ignore[index]
        ],
        ["Archive", f"the live chain, {epoch}"],
        ["Then", "the next report from the gateway starts a new chain, on trust"],
    ]
    # The plan names no archive, so time passing before the confirm changes nothing.
    time.sleep(0.01)
    assertion = authenticator.get(held["options"], page.origin).body()
    done = confirm(page, held["action"], assertion)
    assert done.status_code == 200, done.text
    restarted = done.json()
    name = restarted["restarted"]["archive"]["name"]
    assert name.startswith("archive-")
    assert restarted["head"] == {"head_seq": None, "head_hash": None, "state": "ok"}
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "ledger.restart")
    [line] = rig.logged("ledger_reported_restarted", lambda line: True)
    assert (line["lifted"], line["archived"]["name"]) == ("fork", name)
    assert banners(page) == []
    after = ledger(page)
    assert (after["state"]["state"], after["rows"], after["restartable"]) == ("ok", [], False)
    [archived] = after["archives"]
    assert (archived["name"], archived["dropped"]) == (name, False)
    assert archived["text_shown"] == f"{name}: {epoch}."
    # Still readable: the archive's rows, with no orphans (they are judged on the live chain).
    rows = ledger(page, "?archive=" + name)
    assert rows["archive"] == name
    assert [row["seq"] for row in rows["rows"]] == [0]
    assert rows["orphans"] == []
    # The next report starts a new chain, on trust: the forked history is taken.
    assert report(rig, chain([asked(REFS[1]), decided(REFS[1])], ts=ts + 500)).head.seq == 1


def test_orphans_are_judged_against_the_kept_archives_too(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator], monkeypatch: pytest.MonkeyPatch
) -> None:
    """J.4, J.5: after a restart, a send whose call is in the archived epoch isn't an orphan; one
    begun before the earliest record the copy keeps can't be checked (``older_than_copy``); a
    send no call explains inside that span is still ``no_ledger_record``, however old. Once a
    restart deletes the epoch, its sends are older than the copy. The archives are read for the
    first page only, and an archive that can't be read is a copy that can't be."""
    page, _ = signed_in
    copy = copy_of(rig)
    ts = now_ms() - 3_600_000
    report(rig, chain([asked(REFS[0]), decided(REFS[0]), outcome(REFS[0])], ts=ts))
    assert report(rig, chain([asked(REFS[1])], ts=ts + 500)).reason == "fork"
    rig.call(lambda: copy.restart())
    report(rig, chain([asked(REFS[1]), decided(REFS[1])], ts=ts + 500))  # a new chain
    archived, live, older, inside, later = (f"{REFS[n]}.1" for n in (0, 1, 5, 6, 7))
    journal(
        rig,
        sending(older, ts - 1),  # a millisecond before the earliest record kept
        sending(inside, ts),  # exactly at it: inside the span, and no call explains it
        sending(archived, ts + 1),
        sent(archived, ts + 2),
        sending(live, ts + 600),
        sending(later, ts + 700),
    )
    reads: list[str] = []
    real = copy.archived_coverage

    def counted() -> ledgerview.Coverage:
        reads.append("archives")
        return real()

    monkeypatch.setattr(copy, "archived_coverage", counted)
    answer = ledger(page)
    assert [(o["key_shown"], o["flag"]) for o in answer["orphans"]] == [
        (later, "no_ledger_record"),
        (inside, "no_ledger_record"),
        (older, "older_than_copy"),
    ]
    assert answer["orphans"][2]["text_shown"] == (
        f"{ledgerview.when(ts - 1)} send {older} on mail-out: sending; "
        f"{ORPHAN_FLAGS['older_than_copy']}."
    )
    assert ORPHAN_FLAGS["older_than_copy"].startswith(
        "older than the ledger copy: can't be checked"
    )
    assert reads == ["archives"]
    [epoch] = answer["archives"]
    assert ledger(page, "?archive=" + epoch["name"])["orphans"] == []
    assert ledger(page, "?before=1")["orphans"] == []
    assert reads == ["archives"]  # only the live chain's first page reads them

    # A restart that deletes the archived epoch: its sends are older than the copy now.
    copy.archive_max_bytes = 1
    assert report(rig, chain([asked(REFS[2])], ts=ts + 900)).reason == "fork"
    rig.call(lambda: copy.restart())
    report(rig, chain([asked(REFS[3])], ts=ts + 650))
    flags = [(o["key_shown"], o["flag"]) for o in ledger(page)["orphans"]]
    assert flags == [
        (later, "no_ledger_record"),
        (live, "older_than_copy"),
        (archived, "older_than_copy"),
        (inside, "older_than_copy"),
        (older, "older_than_copy"),
    ]

    def unreadable() -> ledgerview.Coverage:
        raise PermissionError(13, "denied")

    monkeypatch.setattr(copy, "archived_coverage", unreadable)
    assert ledger(page)["state"]["state"] == "unavailable"
    assert [row["seq"] for row in ledger(page, "?before=1")["rows"]] == [0]


def test_a_restart_that_deletes_lists_each_epoch(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    """Q3: archives past their bound go, the live chain too when it can't be kept; each is in
    the summary, and its head stays as an anchor, no longer readable."""
    page, authenticator = signed_in
    copy_of(rig).archive_max_bytes = 1
    forked(rig)
    held = prepared(page, "ledger.restart", {})
    deleted = [value for label, value in held["summary"] if label == "Delete"]
    assert len(deleted) == 1
    assert deleted[0].startswith("the live chain, once archived: seq 0 to 2 (head sha256:")
    assert deleted[0].endswith("; its head stays as an anchor")
    assertion = authenticator.get(held["options"], page.origin).body()
    assert confirm(page, held["action"], assertion).status_code == 200
    [archived] = ledger(page)["archives"]
    assert archived["dropped"] is True
    assert archived["text_shown"].endswith(
        "; its files were deleted, and its head is kept as an anchor."
    )
    gone = page.fetch("GET", "/api/ledger?archive=" + archived["name"])
    assert status_reason(gone) == (404, "not_found")


def test_a_copy_that_moved_since_the_plan_isnt_restarted(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    """F.4: a restart from the host between the plan and the confirm leaves nothing to restart
    (that refusal); one that then forked again is another plan (``409 changed``, both shown)."""
    page, authenticator = signed_in
    forked(rig)
    held = prepared(page, "ledger.restart", {})
    rig.call(lambda: copy_of(rig).restart())
    assertion = authenticator.get(held["options"], page.origin).body()
    assert status_reason(confirm(page, held["action"], assertion)) == (409, "not_restartable")
    forked(rig)
    held = prepared(page, "ledger.restart", {})
    rig.call(lambda: copy_of(rig).restart())
    report(rig, chain([asked(REFS[2])], ts=now_ms()))
    report(rig, chain([asked(REFS[3]), decided(REFS[3])], ts=now_ms() + 900))
    assertion = authenticator.get(held["options"], page.origin).body()
    moved = confirm(page, held["action"], assertion)
    assert status_reason(moved) == (409, "changed")
    assert moved.json()["was"] != moved.json()["now"]
    assert copy_of(rig).state == "fork"
    done = step_up(page, authenticator, "ledger.restart", {})
    assert done.status_code == 200, done.text


def test_a_gap_and_a_full_copy_have_their_banners(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    """K.3: every page shows the copy's state through the session answer, for each sticky
    refusal (J.2 rows 8-10)."""
    page, _ = signed_in
    report(rig, chain([asked(REFS[0])], ts=now_ms()))
    gapped = [ledgerformat.encode(seq=5, prev=GENESIS, ts=now_ms(), **asked(REFS[1]))[:-1]]
    assert report(rig, gapped).reason == "gap"
    assert banners(page) == ["ledger_gap"]
    rig.call(lambda: copy_of(rig).restart())
    assert banners(page) == []
    copy_of(rig).max_bytes = 1
    assert report(rig, chain([asked(REFS[2])], ts=now_ms())).reason == "full"
    assert banners(page) == ["ledger_full"]
    assert ledger(page)["restartable"] is True
    assert set(LEDGER_BANNERS) == {"fork", "gap", "full"}
    for state, text in LEDGER_BANNERS.items():
        assert text.endswith("Decide why, then restart the chain on the Ledger page."), state
