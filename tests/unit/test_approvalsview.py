"""The portal's Approvals queue, as data (M8 design H.1-H.3, A.4; O.3 ``test_approvalsview.py``;
Z16, G-11): the queue's rows, a hold opened, Decided recently's words, every refusal of a portal
decision in ``HoldTable.decide``'s order, ``decide_plan``'s summary, and the turn-on lines."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

import pytest

from tests.unit.plainid import plain_id
from zoeymcp.common.approvaltext import ApprovalText
from zoeymcp.common.policy.schema import Policy
from zoeymcp.portal import approvalsview
from zoeymcp.portal.approvalsview import (
    APPROVE_SENTENCE,
    CHUNK,
    DECIDED_SHOWN,
    HOST_WHERE,
    Planned,
    Refused,
    check,
    clock,
    decide_plan,
    decided,
    detail,
    gone,
    outcome,
    queue,
    row,
    text_lines,
    turn_on_lines,
    utc,
    waiting,
)
from zoeymcp.vault.holds import Ending, Hold, Kind, State, Via

# 2026-11-01 16:00:00 UTC, the wall clock at the hold table's 0.
BASE = 1_793_548_800.0
TEXT = 'Approval request 3f9c0a17b2d4e681\nTool: shop -> place_order\n\n{\n  "qty": 2\n}'
DIGEST = "a" * 64


def wall(at: float) -> float:
    return at + BASE


def hold(number: int = 1, **fields: Any) -> Hold:
    made = Hold(
        id=f"{number:016x}".replace("0", "A"),
        ref=f"{number:016x}",
        kind="held",
        epoch="0123456789ab",
        legacy_session=False,
        route="shop",
        server="shop",
        tool="place_order",
        client="desk",
        args_digest="sha256:" + "c" * 64,
        text=ApprovalText(TEXT, frozenset(), ((0, None),)),
        text_sha256=DIGEST,
        surfaces=frozenset({"portal"}),
        wait="pending",
        asked_at=0.0,
        block_until=120.0,
        deadline=3600.0,
        held_bytes=100,
    )
    return replace(made, **fields)


@dataclass(frozen=True)
class Closed:
    """A hold the portal surface closed (``vault/approvers.py``'s)."""

    id: str
    ref: str
    kind: Kind
    server: str
    tool: str
    client: str | None
    state: State
    via: Via | None
    decided_at: float | None
    detail: str | None


def closed(number: int, state: State, via: Via | None, detail: str | None = None) -> Closed:
    handle = f"{number:016x}"
    return Closed(handle, handle, "held", "shop", "place_order", None, state, via, 1.0, detail)


def delivered(_: str) -> bool:
    return True


def undelivered(_: str) -> bool:
    return False


# --- times and lines ----------------------------------------------------------------------------


def test_times_are_absolute_utc() -> None:
    assert utc(BASE + 2399.0) == "2026-11-01 16:39 UTC"
    assert clock(BASE + 2399.0) == "16:39"
    assert utc(BASE + 86_400.0) == "2026-11-02 16:00 UTC"


def test_a_texts_lines_are_chunked_and_nothing_is_cut() -> None:
    long = "x" * (2 * CHUNK + 50)
    text = f"first\n\n{long}\nlast"
    lines = text_lines(text)
    assert lines == [["first"], [""], ["x" * CHUNK, "x" * CHUNK, "x" * 50], ["last"]]
    assert "\n".join("".join(line) for line in lines) == text
    assert text_lines("x" * CHUNK) == [["x" * CHUNK]]
    assert text_lines("") == [[""]]
    # A hidden character can't reach the page as itself, though the vault's rules refuse one.
    assert text_lines("a\u200bb") == [["a[U+200B]b"]]


# --- the lists (H.1) ----------------------------------------------------------------------------


def test_waiting_is_the_undecided_holds_shown_here_oldest_first() -> None:
    young = hold(1, asked_at=50.0)
    old = hold(2, asked_at=10.0)
    elsewhere = hold(3, surfaces=frozenset({"telegram"}))
    approved = hold(4, state="approved")
    assert waiting([young, approved, elsewhere, old]) == [old, young]
    assert waiting([]) == []


def test_a_waiting_row() -> None:
    found = row(hold(), wall, delivered)
    assert found == {
        "approval": hold().id,
        "ref": "0000000000000001",
        "kind": "held",
        "how_shown": "Held by the vault",
        "server_shown": "shop",
        "tool_shown": "place_order",
        "client_shown": "desk",
        "asked": int(BASE),
        "asked_shown": "2026-11-01 16:00 UTC",
        "deadline": int(BASE + 3600),
        "deadline_shown": "2026-11-01 17:00 UTC",
        "surfaces": ["portal"],
        "telegram_shown": None,
    }
    relayed = row(hold(kind="relay", client=None), wall, delivered)
    assert (relayed["how_shown"], relayed["client_shown"]) == ("Relayed from the gateway", None)
    # A blocking-only hold must be answered by its block (B.6).
    blocking = row(hold(wait="block"), wall, delivered)
    assert blocking["deadline_shown"] == "2026-11-01 16:02 UTC"


def test_a_row_says_when_telegram_has_not_taken_its_prompt() -> None:
    both = hold(surfaces=frozenset({"telegram", "portal"}))
    assert row(both, wall, undelivered)["telegram_shown"] == "not delivered to Telegram"
    assert row(both, wall, delivered)["telegram_shown"] is None
    assert row(both, wall, delivered)["surfaces"] == ["portal", "telegram"]
    assert row(hold(), wall, undelivered)["telegram_shown"] is None  # not a Telegram hold
    asked: list[str] = []

    def told(hold_id: str) -> bool:
        asked.append(hold_id)
        return True

    row(both, wall, told)
    assert asked == [both.id]


def test_names_from_outside_are_shown() -> None:
    found = row(hold(client="desk\u202e", tool="t" * 200), wall, delivered)
    assert found["client_shown"] == "desk[U+202E]"
    assert found["tool_shown"] == "t" * 128 + "\u2026[+72]"


def test_the_queue_lists_waiting_then_decided() -> None:
    held = hold(1, asked_at=5.0)
    running = hold(2, state="forwarding", via="telegram", decided_at=30.0)
    newer = hold(3, state="approved", via="portal", decided_at=40.0)
    unshown = hold(4, state="approved", decided_at=50.0, surfaces=frozenset({"telegram"}))
    ended = [closed(9, "done", "portal", "ok"), closed(8, "denied", "telegram")]
    answer = queue(
        [held, running, newer, unshown], ended, wall, delivered, enabled=True, notice="Full."
    )
    assert (answer["enabled"], answer["notice"]) == (True, "Full.")
    assert [r["approval"] for r in answer["waiting"]] == [held.id]
    order = [newer.id, running.id, ended[0].id, ended[1].id]
    assert [r["approval"] for r in answer["decided"]] == order
    assert answer["decided"][0] == {
        "approval": newer.id,
        "ref": newer.ref,
        "kind": "held",
        "how_shown": "Held by the vault",
        "server_shown": "shop",
        "tool_shown": "place_order",
        "client_shown": "desk",
        "state": "approved",
        "outcome_shown": "approved here 16:00 UTC; sending",
    }
    assert answer["decided"][2]["outcome_shown"] == "approved here 16:00 UTC; sent: ok"
    assert answer["decided"][3]["client_shown"] is None
    quiet = queue([], [], wall, delivered, enabled=False, notice=None)
    assert quiet == {"enabled": False, "notice": None, "waiting": [], "decided": []}
    # A running hold with no decision time sorts as the oldest.
    timeless = hold(5, state="approved", decided_at=None)
    early = hold(6, state="approved", decided_at=0.5)
    found = queue([timeless, early], [], wall, delivered, enabled=True, notice=None)["decided"]
    assert [r["approval"] for r in found] == [early.id, timeless.id]


def test_decided_recently_shows_at_most_twenty() -> None:
    running = hold(1, state="approved", decided_at=1.0)
    ended = [closed(number, "denied", "portal") for number in range(30, 0, -1)]
    decided = queue([running], ended, wall, delivered, enabled=True, notice=None)["decided"]
    assert len(decided) == DECIDED_SHOWN == 20
    assert decided[0]["approval"] == running.id
    assert decided[-1]["ref"] == ended[18].ref


def test_a_hold_opened() -> None:
    shown = detail(hold(), wall, delivered)
    assert shown == {
        **row(hold(), wall, delivered),
        "state": "waiting",
        "text": TEXT,
        "text_sha256": DIGEST,
        "text_lines": text_lines(TEXT),
    }
    assert detail(hold(state="forwarding"), wall, delivered)["state"] == "forwarding"


NOTHING = "; nothing was sent"
ERROR = "; sent: the server answered an error"
UNKNOWN = "; the outcome is unknown: see the Ledger"
OUTCOMES: list[tuple[State, Via | None, str | None, str]] = [
    ("approved", "portal", None, "approved here 16:39 UTC; sending"),
    ("forwarding", "telegram", None, "approved in Telegram 16:39 UTC; sending"),
    ("done", "portal", "ok", "approved here 16:39 UTC; sent: ok"),
    ("done", "telegram", "tool_error", "approved in Telegram 16:39 UTC" + ERROR),
    ("done", "portal", "upstream_error", "approved here 16:39 UTC" + ERROR),
    ("done", "portal", "relayed", "approved here 16:39 UTC; the gateway runs it: see the Ledger"),
    ("done", "portal", "refused", "approved here 16:39 UTC" + NOTHING),
    ("done", "portal", "not_sent", "approved here 16:39 UTC" + NOTHING),
    ("done", "portal", "unknown", "approved here 16:39 UTC" + UNKNOWN),
    ("done", "portal", None, "approved here 16:39 UTC" + UNKNOWN),
    ("denied", "portal", None, "denied here 16:39 UTC" + NOTHING),
    ("denied", "telegram", None, "denied in Telegram 16:39 UTC" + NOTHING),
    ("expired", "none", None, "expired 16:39 UTC" + NOTHING),
    ("withdrawn", "host", "operator", "withdrawn by the operator 16:39 UTC" + NOTHING),
    ("withdrawn", "none", "changed", "withdrawn 16:39 UTC: the policy changed" + NOTHING),
    ("withdrawn", "none", "shutdown", "withdrawn 16:39 UTC: the vault stopped" + NOTHING),
    ("withdrawn", "none", "stream_lost", "withdrawn 16:39 UTC: the agent cancelled" + NOTHING),
    ("withdrawn", "none", "caller_cancelled", "withdrawn 16:39 UTC: the agent cancelled" + NOTHING),
    (
        "withdrawn",
        "none",
        "gateway_restarted",
        "withdrawn 16:39 UTC: the gateway restarted" + NOTHING,
    ),
    ("withdrawn", "none", "gateway_stopped", "withdrawn 16:39 UTC: the gateway stopped" + NOTHING),
    ("withdrawn", "none", "ledger", "withdrawn 16:39 UTC: the vault couldn't record it" + NOTHING),
    ("withdrawn", "none", "not_shown", "withdrawn 16:39 UTC: no approver could show it" + NOTHING),
    (
        "withdrawn",
        "none",
        "busy",
        "withdrawn 16:39 UTC: the vault had no room for its result" + NOTHING,
    ),
    ("withdrawn", "none", "other", "withdrawn 16:39 UTC" + NOTHING),
    ("withdrawn", None, None, "withdrawn 16:39 UTC" + NOTHING),
]


@pytest.mark.parametrize(("state", "via", "detail_", "words"), OUTCOMES, ids=plain_id)
def test_how_a_decided_hold_went(
    state: State, via: Via | None, detail_: str | None, words: str
) -> None:
    assert outcome(state, via, detail_, "16:39") == words


def test_the_hosts_list_names_where_each_was_decided() -> None:
    """K.3 (step 16): the host's list has no "here"; it names the portal as Telegram is named,
    and the queue's own words keep "here"."""
    assert HOST_WHERE == {"portal": " in the portal", "telegram": " in Telegram"}
    words = outcome("denied", "portal", None, "16:39", HOST_WHERE)
    assert words == "denied in the portal 16:39 UTC; nothing was sent"
    words = outcome("done", "telegram", "ok", "16:39", HOST_WHERE)
    assert words == "approved in Telegram 16:39 UTC; sent: ok"
    ended = closed(1, "denied", "portal")
    assert decided(ended, wall, HOST_WHERE) == {
        "approval": "0000000000000001",
        "ref": "0000000000000001",
        "kind": "held",
        "how_shown": "Held by the vault",
        "server_shown": "shop",
        "tool_shown": "place_order",
        "client_shown": None,
        "state": "denied",
        "outcome_shown": "denied in the portal 16:00 UTC; nothing was sent",
    }
    assert decided(ended, wall)["outcome_shown"] == "denied here 16:00 UTC; nothing was sent"


def test_a_decided_hold_with_no_time() -> None:
    timeless = replace(closed(1, "expired", "none"), decided_at=None)
    found = queue([], [timeless], wall, delivered, enabled=True, notice=None)
    assert found["decided"][0]["outcome_shown"] == "expired  UTC; nothing was sent"


# --- a decision (H.3) ---------------------------------------------------------------------------


def ending(state: State, via: Via | None = "telegram", decided_at: float | None = 2399.0) -> Ending:
    return Ending("0000000000000001", "A" * 16, "desk", state, via, decided_at, None, 2400.0)


def already(where: str, at: str, decision: str) -> Refused:
    return Refused("already_decided", (("where", where), ("at", at), ("decision", decision)))


def test_a_hold_that_is_gone_is_told_how_it_ended() -> None:
    assert gone(None, wall) == Refused("approval_unknown")
    assert gone(ending("expired"), wall) == Refused("expired")
    assert gone(ending("withdrawn"), wall) == Refused("withdrawn")
    assert gone(ending("done"), wall) == already("in Telegram", "16:39 UTC", "approved")
    assert gone(ending("denied", "portal"), wall) == already("in the portal", "16:39 UTC", "denied")
    assert gone(ending("done", None, None), wall) == already(
        "elsewhere", "an unknown time", "approved"
    )
    assert gone(ending("done", "host"), wall) == already("elsewhere", "16:39 UTC", "approved")


def test_the_checks_go_in_decides_order() -> None:
    now = 10.0
    assert check(hold(), None, DIGEST, now=now, wall=wall) is None
    assert check(None, None, DIGEST, now=now, wall=wall) == Refused("approval_unknown")
    assert check(None, ending("expired"), DIGEST, now=now, wall=wall) == Refused("expired")
    decided = hold(state="approved", via="telegram", decided_at=2399.0)
    # Decided first, even with another digest and past its end.
    assert check(decided, None, "x", now=5000.0, wall=wall) == already(
        "in Telegram", "16:39 UTC", "approved"
    )
    elsewhere = hold(surfaces=frozenset({"telegram"}))
    assert check(elsewhere, None, "x", now=5000.0, wall=wall) == Refused("approval_unknown")
    assert check(hold(), None, "x", now=3600.0, wall=wall) == Refused("expired")
    assert check(hold(), None, DIGEST, now=3599.9, wall=wall) is None
    assert check(hold(wait="block"), None, DIGEST, now=120.0, wall=wall) == Refused("expired")
    assert check(hold(), None, "b" * 64, now=now, wall=wall) == Refused("digest_changed")


def data(**fields: Any) -> dict[str, Any]:
    return {"approval": hold().id, "text_sha256": DIGEST, "decision": "approve", **fields}


def test_the_plan_is_the_whole_text_and_one_sentence() -> None:
    planned = decide_plan(data(), hold(), None, now=10.0, wall=wall)
    assert planned == Planned(
        (
            ("Approval request", "0000000000000001"),
            ("How", "Held by the vault"),
            ("Server", "shop"),
            ("Tool", "place_order"),
            ("Client, as the gateway reports it", "desk"),
            ("Asked", "2026-11-01 16:00 UTC"),
            ("Answer by", "2026-11-01 17:00 UTC"),
            ("The request, whole", TEXT),
            ("Approve", APPROVE_SENTENCE),
        ),
        (hold().id, DIGEST),
    )
    assert APPROVE_SENTENCE == "Approve runs this one call, exactly as shown."
    # No relative time: a re-plan later in the wait is the same plan (M5 9a).
    assert decide_plan(data(), hold(), None, now=3000.0, wall=wall) == planned
    relayed = decide_plan(data(), hold(kind="relay", client=None), None, now=10.0, wall=wall)
    assert isinstance(relayed, Planned)
    assert dict(relayed.summary)["How"] == "Relayed from the gateway"
    assert dict(relayed.summary)["Client, as the gateway reports it"] == "not reported"
    odd = decide_plan(data(), hold(client="desk\u202e"), None, now=10.0, wall=wall)
    assert isinstance(odd, Planned)
    assert dict(odd.summary)["Client, as the gateway reports it"] == "desk[U+202E]"


@pytest.mark.parametrize(
    "fields",
    [
        {"approval": 7},
        {"approval": None},
        {"text_sha256": 7},
        {"text_sha256": ["a"]},
        {"decision": "deny"},
        {"decision": "Approve"},
        {"decision": True},
    ],
    ids=plain_id,
)
def test_a_plan_of_the_wrong_shape_is_a_bad_body(fields: dict[str, Any]) -> None:
    assert decide_plan(data(**fields), hold(), None, now=10.0, wall=wall) == Refused("bad_body")


def test_a_plan_refuses_by_what_happened() -> None:
    assert decide_plan(data(), None, ending("withdrawn"), now=10.0, wall=wall) == Refused(
        "withdrawn"
    )
    assert decide_plan(data(), None, None, now=10.0, wall=wall) == Refused("approval_unknown")
    assert decide_plan(data(), hold(), None, now=4000.0, wall=wall) == Refused("expired")
    assert decide_plan(data(text_sha256="b" * 64), hold(), None, now=1.0, wall=wall) == Refused(
        "digest_changed"
    )


# --- the turn-on lines (A.4, J2) ----------------------------------------------------------------


def policy(**more: Any) -> Policy:
    clients = {
        "desk": {"token": "t" * 32, "servers": ["broker"], "approvals": {"attended": True}},
        "nightly": {
            "token": "u" * 32,
            "servers": ["broker"],
            "approvals": {"attended": False, "out_of_band": True},
        },
        "batch": {"token": "v" * 32, "servers": ["broker"]},
        "watched": {
            "token": "w" * 32,
            "servers": ["broker"],
            "approvals": {"attended": True, "out_of_band": True},
        },
        "other": {"token": "x" * 32, "servers": [], "approvals": {"attended": True}},
    }
    servers: dict[str, Any] = {
        "broker": {
            "kind": "remote",
            "route": "broker-api",
            "tools": {"include": ["place_order"], "approve": ["place_order"]},
        },
        "mailer": {
            "kind": "toolkit",
            "module": "tests.toolkits.mailer",
            "tools": {"include": ["send_mail"], "approve": ["send_mail"]},
            "slots": {
                "out": {
                    "route": "mail",
                    "rules": [{"methods": ["POST"], "paths": ["/send"], "approved": True}],
                },
                "read": {"route": "broker-api", "rules": [{"methods": ["GET"], "paths": ["/x"]}]},
            },
        },
    }
    route = {
        "name": "broker-api",
        "prefix": "/broker",
        "upstream": "https://broker.example",
        "credential": "broker-key",
        "callers": ["gateway"],
        "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
    }
    mail = {
        "name": "mail",
        "prefix": "/mail",
        "connector": "mail-out",
        "callers": ["gateway"],
        "rules": [{"methods": ["POST"], "paths": ["/send"]}],
    }
    document: dict[str, Any] = {
        "version": 1,
        "mode": "managed",
        "credentials": {"broker-key": {"kind": "header", "secret": "store:broker-key"}},
        "routes": [{**route, **more.pop("route", {})}, mail],
        "approvers": more.pop("approvers", {"portal": {}}),
        "gateway": {"clients": clients, "servers": servers},
        **more,
    }
    return Policy.model_validate(document)


def lines_of(found: Policy, server: str, tool: str) -> list[str]:
    """The turn-on lines as the vault side asks for them: the policy's server and its clients."""
    gateway = found.gateway
    served = None if gateway is None else gateway.servers.get(server)
    clients = {} if gateway is None else gateway.clients
    return turn_on_lines(found, server, tool, served=served, clients=clients)


def test_the_turn_on_lines_say_who_is_asked_where() -> None:
    lines = lines_of(policy(), "broker", "place_order")
    assert lines == [
        "broker.place_order: vault_approval on.",
        "  The vault will hold every call to place_order and ask you in the Approvals queue. The "
        "gateway will no longer ask in the agent's own client.",
        '  batch (neither): refused, as before ("nobody answers for this client").',
        "  desk (attended): asked on your approvers instead of in its client.",
        "  nightly (out of band): asked on your approvers, as before.",
        "  watched (out of band): asked on your approvers, as before.",
        "  Route broker-api holds a credential: a compromised gateway can't call the server "
        "directly.",
    ]


@pytest.mark.parametrize(
    ("approvers", "where"),
    [
        ({"portal": {}}, "in the Approvals queue"),
        ({"telegram": {"bot_token": "store:bot", "user_id": 5, "chat_id": 5}}, "on Telegram"),
        (
            {"portal": {}, "telegram": {"bot_token": "store:bot", "user_id": 5, "chat_id": 5}},
            "on Telegram or in the Approvals queue",
        ),
        ({}, "on your approvers, once one is set up"),
        (None, "on your approvers, once one is set up"),
    ],
    ids=plain_id,
)
def test_the_turn_on_lines_name_the_approvers(approvers: dict[str, Any] | None, where: str) -> None:
    lines = lines_of(policy(approvers=approvers), "broker", "place_order")
    assert lines[1].startswith(
        f"  The vault will hold every call to place_order and ask you {where}."
    )


def test_the_turn_on_lines_say_what_the_route_holds() -> None:
    bare = policy(route={"credential": None})
    assert lines_of(bare, "broker", "place_order")[-1] == (
        "  Route broker-api holds no credential: in the standard tier the gateway shares the "
        "vault's network and can reach this upstream itself; vault_approval holds here only in "
        "the hardened tier."
    )
    bridged = policy(route={"credential": None, "upstream": "unix:/run/zoeymcp-bridge-b/mcp.sock"})
    assert lines_of(bridged, "broker", "place_order")[-1] == (
        "  Route broker-api reaches a bridge's socket: a compromised gateway can't call the "
        "server directly."
    )
    # A toolkit's: the routes its approved writes go through, a connector's among them.
    toolkit = lines_of(policy(), "mailer", "send_mail")
    assert toolkit[0] == "mailer.send_mail: vault_approval on."
    assert toolkit[-1] == (
        "  Route mail is connector mail-out's: a compromised gateway can't send through it "
        "directly."
    )
    assert not any("broker-api" in line for line in toolkit)


def test_no_turn_on_lines_for_a_server_the_policy_lacks() -> None:
    assert lines_of(policy(), "nothing", "place_order") == []
    plain = Policy.model_validate({"version": 1, "mode": "managed"})
    assert lines_of(plain, "broker", "place_order") == []
    assert turn_on_lines(policy(), "broker", "x", served=None, clients={}) == []
    # A server no client is given: who is asked is nobody, the route's line all the same.
    found = policy()
    assert found.gateway is not None
    served = found.gateway.servers["broker"]
    alone = turn_on_lines(found, "broker", "place_order", served=served, clients={})
    assert len(alone) == 3
    assert alone[2].startswith("  Route broker-api holds a credential")


def test_the_module_names_every_kind_and_reason() -> None:
    """Every hold kind has its words, and the refusals are the catalogue's (test_refusals)."""
    assert set(approvalsview.HOW) == {"held", "relay"}
