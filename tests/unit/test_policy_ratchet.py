"""The ratchet (M6 design E, O.3; D-58 part 2.10, D-198, D-194; Y5, Y11, Y12, Y14): ``initial``,
``advance`` field by field, every violation with and without its grant, ``reach`` for every kind
of credential and a connector, the cap both sides, and the plain form a revision's body carries
(a golden, the round trip, and every form ``loaded`` refuses)."""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Callable
from typing import Any

import pytest

from zoeymcp.common.canonical import dumps_canonical
from zoeymcp.common.policy.ratchet import (
    PLACEHOLDER_CONTEXT,
    RATCHET_MAX,
    Grants,
    Ratchet,
    Violation,
    advance,
    caller_digest,
    entries,
    full,
    initial,
    loaded,
    reach,
    violations,
)
from zoeymcp.common.policy.schema import Policy

PIN_READ = "sha256:" + "a" * 64
PIN_WRITE = "sha256:" + "b" * 64
PIN_NEW = "sha256:" + "c" * 64
TOKEN_CI = "sha256:" + "1" * 64
TOKEN_NEW = "sha256:" + "2" * 64
PLACEHOLDER = "ph-script-0001"
READ = ("notes", "tool", "read")
WRITE = ("notes", "tool", "write")
NONE: frozenset[tuple[tuple[str, str, str], str]] = frozenset()

Edit = Callable[[dict[str, Any]], None]


def document() -> dict[str, Any]:
    """A managed policy: a header credential on the notes route, a placeholder caller on the
    files route, one client, and a server with an allow and an approve tool."""
    return {
        "version": 1,
        "mode": "managed",
        "credentials": {"notes-key": {"kind": "header", "secret": "store:notes-key"}},
        "routes": [
            {
                "name": "notes-mcp",
                "prefix": "/notes",
                "upstream": "https://mcp.notes.example",
                "credential": "notes-key",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
            },
            {
                "name": "files",
                "prefix": "/files",
                "upstream": "https://api.files.example",
                "callers": ["gateway", {"placeholder": PLACEHOLDER}],
                "rules": [{"methods": ["GET"], "paths": ["/**"]}],
            },
        ],
        "gateway": {
            "clients": {"ci": {"token_sha256": TOKEN_CI}},
            "servers": {
                "notes": {
                    "kind": "remote",
                    "route": "notes-mcp",
                    "tools": {
                        "include": ["read", "write"],
                        "allow": ["read"],
                        "approve": ["write"],
                    },
                    "review": {"read": PIN_READ, "write": PIN_WRITE},
                }
            },
        },
    }


def make(*edits: Edit) -> Policy:
    raw = document()
    for edit in edits:
        edit(raw)
    return Policy.model_validate(raw)


def notes(raw: dict[str, Any]) -> dict[str, Any]:
    server: dict[str, Any] = raw["gateway"]["servers"]["notes"]
    return server


def repin(name: str, pin: str) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        notes(raw)["review"][name] = pin

    return edit


def drop(name: str) -> Edit:
    """The tool left out: not included, classified or pinned."""

    def edit(raw: dict[str, Any]) -> None:
        tools = notes(raw)["tools"]
        for block in ("include", "allow", "approve"):
            tools[block] = [t for t in tools[block] if t != name]
        notes(raw)["review"].pop(name)

    return edit


def generations(gateway: int, egress: int) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        raw["gateway_key_generation"] = gateway
        raw["egress_key_generation"] = egress

    return edit


def no_client(raw: dict[str, Any]) -> None:
    raw["gateway"]["clients"] = {}


def client_token(token: str) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        raw["gateway"]["clients"]["ci"] = {"token_sha256": token}

    return edit


def no_placeholder(raw: dict[str, Any]) -> None:
    raw["routes"][1]["callers"] = ["gateway"]


def env_secret(name: str) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        raw["credentials"]["notes-key"]["secret"] = f"env:{name}"

    return edit


def upstream(url: str) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        raw["routes"][0]["upstream"] = url

    return edit


def no_gateway(raw: dict[str, Any]) -> None:
    del raw["gateway"]


BASE = make()
START = initial(BASE)
NO_GRANTS = Grants()  # the portal's


# --- initial -----------------------------------------------------------------------------------


def test_initial_takes_the_generations_the_approve_tools_and_the_reach() -> None:
    policy = make(generations(3, 2), env_secret("NOTES_KEY"))
    found = initial(policy)
    assert (found.gateway_key_floor, found.egress_key_floor) == (3, 2)
    assert found.approved == {WRITE}
    assert found.env == {"NOTES_KEY": {"https://mcp.notes.example:443"}}
    assert found.retired_pins == {}
    assert found.retired_clients == found.retired_callers == frozenset()


def test_initial_of_a_policy_without_a_gateway_holds_no_definition() -> None:
    found = initial(make(no_gateway))
    assert found.approved == frozenset()
    assert entries(found) == 0


# --- advance -----------------------------------------------------------------------------------


def test_advance_keeps_each_floors_maximum() -> None:
    raised = advance(START, BASE, make(generations(4, 3)), verified=NONE)
    assert (raised.gateway_key_floor, raised.egress_key_floor) == (4, 3)
    # A later write below the floors (one violations refused, or a host's) moves no floor down.
    kept = advance(raised, make(generations(4, 3)), make(generations(2, 2)), verified=NONE)
    assert (kept.gateway_key_floor, kept.egress_key_floor) == (4, 3)
    each = advance(START, BASE, make(generations(1, 5)), verified=NONE)
    assert (each.gateway_key_floor, each.egress_key_floor) == (1, 5)


def test_advance_retires_a_replaced_pin_and_a_removed_one() -> None:
    repinned = advance(START, BASE, make(repin("read", PIN_NEW)), verified=NONE)
    assert repinned.retired_pins == {READ: {PIN_READ}}
    dropped = advance(START, BASE, make(drop("write")), verified=NONE)
    assert dropped.retired_pins == {WRITE: {PIN_WRITE}}
    # A pin kept is not retired, and an earlier retirement stays.
    later = advance(
        repinned,
        make(repin("read", PIN_NEW)),
        make(drop("write"), repin("read", PIN_NEW)),
        verified=NONE,
    )
    assert later.retired_pins == {READ: {PIN_READ}, WRITE: {PIN_WRITE}}


def test_a_verified_pin_leaves_the_retired_set() -> None:
    retired = advance(START, BASE, make(repin("read", PIN_NEW)), verified=NONE)
    # Re-pinned back to a definition the fresh review verified again: the operator read it.
    back = advance(
        retired, make(repin("read", PIN_NEW)), BASE, verified=frozenset({(READ, PIN_READ)})
    )
    assert back.retired_pins == {READ: {PIN_NEW}}
    # A verification of another pin or another definition takes nothing out.
    other = advance(
        retired,
        make(repin("read", PIN_NEW)),
        make(repin("read", PIN_NEW)),
        verified=frozenset({(READ, PIN_WRITE), (WRITE, PIN_READ)}),
    )
    assert other.retired_pins == {READ: {PIN_READ}}
    # A pin verified by the same write that would retire it isn't retired; an emptied entry goes.
    same = advance(START, BASE, make(drop("read")), verified=frozenset({(READ, PIN_READ)}))
    assert same.retired_pins == {}
    assert READ not in same.retired_pins


def test_advance_retires_removed_and_retokened_clients() -> None:
    removed = advance(START, BASE, make(no_client), verified=NONE)
    assert removed.retired_clients == {TOKEN_CI}
    retokened = advance(START, BASE, make(client_token(TOKEN_NEW)), verified=NONE)
    assert retokened.retired_clients == {TOKEN_CI}
    kept = advance(
        retokened, make(client_token(TOKEN_NEW)), make(client_token(TOKEN_NEW)), verified=NONE
    )
    assert kept.retired_clients == {TOKEN_CI}
    assert advance(START, BASE, BASE, verified=NONE).retired_clients == frozenset()


def test_advance_to_a_policy_without_a_gateway_retires_its_client_and_every_pin() -> None:
    found = advance(START, BASE, make(no_gateway), verified=NONE)
    assert found.retired_clients == {TOKEN_CI}
    assert found.retired_pins == {READ: {PIN_READ}, WRITE: {PIN_WRITE}}


def test_advance_keeps_the_pin_of_a_tool_no_longer_included() -> None:
    """Every pin in ``review`` counts, included or not: one still there isn't replaced or
    removed."""

    def unincluded(raw: dict[str, Any]) -> None:
        notes(raw)["tools"].update(include=["write"], allow=[])

    assert advance(START, BASE, make(unincluded), verified=NONE).retired_pins == {}


def test_advance_retires_a_removed_placeholder_as_a_digest() -> None:
    removed = advance(START, BASE, make(no_placeholder), verified=NONE)
    expected = (
        "sha256:" + hashlib.sha256(f"{PLACEHOLDER_CONTEXT}{PLACEHOLDER}".encode()).hexdigest()
    )
    assert PLACEHOLDER_CONTEXT == "zoeymcp/placeholder/v1\n"
    assert removed.retired_callers == {expected} == {caller_digest(PLACEHOLDER)}
    assert PLACEHOLDER.encode() not in dumps_canonical(removed.as_dict())
    kept = advance(removed, make(no_placeholder), make(no_placeholder), verified=NONE)
    assert kept.retired_callers == {expected}
    assert advance(START, BASE, BASE, verified=NONE).retired_callers == frozenset()


def test_approved_only_grows() -> None:
    empty = Ratchet(1, 1, {}, frozenset(), frozenset(), frozenset(), {})
    # The old policy's approve tools join, and the new one's.
    assert advance(empty, BASE, make(drop("write")), verified=NONE).approved == {WRITE}

    def approve_read(raw: dict[str, Any]) -> None:
        notes(raw)["tools"].update(allow=[], approve=["read", "write"])

    assert advance(empty, make(drop("write")), make(approve_read), verified=NONE).approved == {
        READ,
        WRITE,
    }
    # Dropped, or moved to allow: nothing leaves.
    moved = make(lambda raw: notes(raw)["tools"].update(allow=["read", "write"], approve=[]))
    once = advance(START, BASE, make(drop("write")), verified=NONE)
    assert advance(once, make(drop("write")), moved, verified=NONE).approved == {WRITE}


def test_advance_widens_env_by_the_new_reach() -> None:
    first = initial(make(env_secret("NOTES_KEY")))
    moved = make(env_secret("NOTES_KEY"), upstream("https://other.notes.example:8443"))
    found = advance(first, make(env_secret("NOTES_KEY")), moved, verified=NONE)
    assert found.env == {
        "NOTES_KEY": {"https://mcp.notes.example:443", "https://other.notes.example:8443"}
    }
    # A name the new policy no longer uses is kept, and a new one joins.
    renamed = advance(found, moved, make(env_secret("OTHER_KEY")), verified=NONE)
    assert set(renamed.env) == {"NOTES_KEY", "OTHER_KEY"}
    assert renamed.env["NOTES_KEY"] == found.env["NOTES_KEY"]


# --- violations --------------------------------------------------------------------------------


def check(
    candidate: Policy,
    ratchet: Ratchet = START,
    head: Policy = BASE,
    verified: frozenset[tuple[tuple[str, str, str], str]] = NONE,
    grants: Grants = NO_GRANTS,
) -> tuple[Violation, ...]:
    return violations(ratchet, head, candidate, verified=verified, grants=grants)


def test_nothing_moved_back_is_no_violation() -> None:
    assert check(BASE) == ()


@pytest.mark.parametrize(
    ("gateway", "egress", "expected"),
    [
        (2, 3, ()),
        (3, 3, ()),
        (1, 3, (Violation("generation_lowered", "gateway_key_generation", floor=2),)),
        (2, 2, (Violation("generation_lowered", "egress_key_generation", floor=3),)),
        (
            1,
            1,
            (
                Violation("generation_lowered", "gateway_key_generation", floor=2),
                Violation("generation_lowered", "egress_key_generation", floor=3),
            ),
        ),
    ],
)
def test_e1_a_generation_below_its_floor(
    gateway: int, egress: int, expected: tuple[Violation, ...]
) -> None:
    ratchet = initial(make(generations(2, 3)))
    head = make(generations(2, 3))
    assert check(make(generations(gateway, egress)), ratchet, head) == expected
    # No grant allows it: a lower key is a retired key.
    grants = Grants(revive=frozenset({"gateway_key_generation", "egress_key_generation"}))
    assert check(make(generations(gateway, egress)), ratchet, head, grants=grants) == expected


def test_e2_a_retired_pin_brought_back() -> None:
    head = make(repin("read", PIN_NEW))
    ratchet = advance(START, BASE, head, verified=NONE)
    refused = (Violation("pin_retired", "pin:notes/tool/read"),)
    assert check(BASE, ratchet, head) == refused
    # Verified again by this write's review, or granted by the host: allowed.
    assert check(BASE, ratchet, head, verified=frozenset({(READ, PIN_READ)})) == ()
    assert (
        check(BASE, ratchet, head, grants=Grants(revive=frozenset({"pin:notes/tool/read"}))) == ()
    )
    # Another grant or verification doesn't count.
    assert check(BASE, ratchet, head, verified=frozenset({(READ, PIN_NEW)})) == refused
    assert check(BASE, ratchet, head, grants=Grants(revive=frozenset({"client:ci"}))) == refused


def test_e2_only_an_included_pin_that_differs_from_the_heads() -> None:
    head = make(repin("read", PIN_NEW))
    ratchet = advance(START, BASE, head, verified=NONE)
    # The head's own pin, even if retired (a host revived it), isn't refused again.
    revived = Ratchet(
        1, 1, {READ: frozenset({PIN_NEW, PIN_READ})}, frozenset(), frozenset(), frozenset(), {}
    )
    assert check(head, revived, head) == ()

    # A retired pin on a tool that isn't included isn't a definition anyone is served.
    def unincluded(raw: dict[str, Any]) -> None:
        notes(raw)["tools"].update(include=["write"], allow=[])

    assert check(make(unincluded), ratchet, head) == ()
    # A pin that was never retired is no violation.
    assert check(make(repin("read", PIN_NEW), repin("write", PIN_NEW)), ratchet, head) == ()


def test_e3_a_retired_client_brought_back() -> None:
    head = make(no_client)
    ratchet = advance(START, BASE, head, verified=NONE)
    assert check(BASE, ratchet, head) == (Violation("revives_client", "client:ci"),)
    assert check(BASE, ratchet, head, grants=Grants(revive=frozenset({"client:ci"}))) == ()
    assert check(BASE, ratchet, head, grants=Grants(revive=frozenset({"client:other"}))) != ()

    # Under another name, the token is still the retired one.
    def renamed(raw: dict[str, Any]) -> None:
        raw["gateway"]["clients"] = {"other": {"token_sha256": TOKEN_CI}}

    assert check(make(renamed), ratchet, head) == (Violation("revives_client", "client:other"),)
    # A client the head holds (revived by a host grant) isn't refused by later writes.
    assert check(BASE, ratchet, BASE) == ()
    assert check(make(client_token(TOKEN_NEW)), ratchet, head) == ()


def test_e4_a_retired_caller_brought_back() -> None:
    head = make(no_placeholder)
    ratchet = advance(START, BASE, head, verified=NONE)
    assert check(BASE, ratchet, head) == (Violation("revives_caller", "caller:files/1"),)
    assert check(BASE, ratchet, head, grants=Grants(revive=frozenset({"caller:files/1"}))) == ()
    assert check(BASE, ratchet, head, grants=Grants(revive=frozenset({"caller:files/0"}))) != ()
    assert check(BASE, ratchet, BASE) == ()

    def other_placeholder(raw: dict[str, Any]) -> None:
        raw["routes"][1]["callers"] = [{"placeholder": "ph-script-0002"}]

    assert check(make(other_placeholder), ratchet, head) == ()


def test_e5_a_new_env_name() -> None:
    candidate = make(env_secret("NOTES_KEY"))
    assert check(candidate) == (Violation("env_name_new", "NOTES_KEY"),)
    assert check(candidate, grants=Grants(env=frozenset({"NOTES_KEY"}))) == ()
    assert check(candidate, grants=Grants(env=frozenset({"OTHER_KEY"}))) != ()

    # The name alone is new even when no route sends it anywhere.
    def unused(raw: dict[str, Any]) -> None:
        raw["credentials"]["spare"] = {"kind": "header", "secret": "env:SPARE_KEY"}

    assert check(make(unused)) == (Violation("env_name_new", "SPARE_KEY"),)
    # A granted name is passed over, not the end of the check: the other name still counts.
    both = make(env_secret("NOTES_KEY"), unused)
    assert check(both, grants=Grants(env=frozenset({"NOTES_KEY"}))) == (
        Violation("env_name_new", "SPARE_KEY"),
    )
    assert check(both, grants=Grants(env=frozenset({"SPARE_KEY"}))) == (
        Violation("env_name_new", "NOTES_KEY"),
    )


def test_e6_an_env_name_sent_further() -> None:
    ratchet = initial(make(env_secret("NOTES_KEY")))
    head = make(env_secret("NOTES_KEY"))
    moved = make(env_secret("NOTES_KEY"), upstream("https://evil.example"))
    assert check(moved, ratchet, head) == (
        Violation("env_reach_grows", "NOTES_KEY", origins=("https://evil.example:443",)),
    )
    assert check(moved, ratchet, head, grants=Grants(env=frozenset({"NOTES_KEY"}))) == ()

    # Sent to fewer origins, or the same ones: no violation.
    def unused(raw: dict[str, Any]) -> None:
        raw["routes"][0]["credential"] = None

    assert check(make(env_secret("NOTES_KEY"), unused), ratchet, head) == ()
    assert check(head, ratchet, head) == ()


def test_violations_come_in_order_e1_to_e6() -> None:
    head = make(generations(2, 1), no_client, no_placeholder, repin("read", PIN_NEW))
    ratchet = advance(initial(BASE), BASE, head, verified=NONE)
    found = check(make(env_secret("NOTES_KEY")), ratchet, head)
    assert [v.reason for v in found] == [
        "generation_lowered",
        "pin_retired",
        "revives_client",
        "revives_caller",
        "env_name_new",
    ]


# --- reach -------------------------------------------------------------------------------------


def credential(spec: dict[str, Any]) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        raw["credentials"]["notes-key"] = spec

    return edit


@pytest.mark.parametrize(
    "spec",
    [
        {"kind": "header", "secret": "env:NOTES_KEY"},
        {"kind": "query", "param": "key", "secret": "env:NOTES_KEY"},
        {"kind": "path", "template": "/k/{secret}", "secret": "env:NOTES_KEY"},
        {"kind": "basic", "username": "agent", "secret": "env:NOTES_KEY"},
        {"kind": "basic", "username": "env:NOTES_KEY", "secret": "store:notes-key"},
    ],
)
def test_a_route_credentials_secret_reaches_its_routes_upstreams(spec: dict[str, Any]) -> None:
    def second_route(raw: dict[str, Any]) -> None:
        raw["routes"][1].update(credential="notes-key", upstream="https://API.files.example:8443")

    assert reach(make(credential(spec))) == {"NOTES_KEY": {"https://mcp.notes.example:443"}}
    assert reach(make(credential(spec), second_route)) == {
        "NOTES_KEY": {"https://mcp.notes.example:443", "https://api.files.example:8443"}
    }


def test_an_http_and_a_bridge_upstream() -> None:
    bridge = "unix:/run/zoeymcp-bridge-notes/mcp.sock"
    assert reach(make(env_secret("NOTES_KEY"), upstream("http://notes.local"))) == {
        "NOTES_KEY": {"http://notes.local:80"}
    }
    assert reach(make(env_secret("NOTES_KEY"), upstream(bridge))) == {"NOTES_KEY": {bridge}}


def test_an_oauth_credentials_secrets_reach_its_token_and_revocation_endpoints() -> None:
    spec = {
        "kind": "oauth2",
        "token_url": "https://Auth.notes.example/token?tenant=a",
        "client_id": "env:NOTES_ID",
        "client_secret": "env:NOTES_SECRET",
        "refresh_token": "env:NOTES_REFRESH",
    }
    endpoints = {"https://auth.notes.example:443"}
    found = reach(make(credential(spec)))
    assert found == dict.fromkeys(("NOTES_ID", "NOTES_REFRESH", "NOTES_SECRET"), endpoints)
    revoked = reach(
        make(credential({**spec, "revocation_url": "https://revoke.notes.example:9443/r"}))
    )
    assert revoked["NOTES_ID"] == {
        "https://auth.notes.example:443",
        "https://revoke.notes.example:9443",
    }
    # Never the route's upstream: the access token goes there, not these.
    assert "https://mcp.notes.example:443" not in revoked["NOTES_SECRET"]


def test_a_connectors_username_reaches_its_smtp_server() -> None:
    def connector(raw: dict[str, Any]) -> None:
        raw["connectors"] = {
            "mail-out": {
                "kind": "smtp",
                "host": "SMTP.mail.example",
                "port": 465,
                "username": "env:MAIL_USER",
                "password": "store:mail-pass",
                "from": "agent@mail.example",
                "to": ["partner@mail.example"],
            }
        }

    def second(raw: dict[str, Any]) -> None:  # each connector's references, not only the first's
        raw["connectors"]["mail-relay"] = {
            **raw["connectors"]["mail-out"],
            "host": "relay.mail.example",
            "port": 587,
            "username": "env:RELAY_USER",
        }

    assert reach(make(connector)) == {"MAIL_USER": {"smtp://smtp.mail.example:465"}}
    assert reach(make(connector, second)) == {
        "MAIL_USER": {"smtp://smtp.mail.example:465"},
        "RELAY_USER": {"smtp://relay.mail.example:587"},
    }


def test_store_references_have_no_reach_and_one_name_used_twice_is_one_union() -> None:
    assert reach(BASE) == {}

    def twice(raw: dict[str, Any]) -> None:
        raw["credentials"]["files-key"] = {"kind": "header", "secret": "env:NOTES_KEY"}
        raw["routes"][1]["credential"] = "files-key"

    assert reach(make(env_secret("NOTES_KEY"), twice)) == {
        "NOTES_KEY": {"https://mcp.notes.example:443", "https://api.files.example:443"}
    }


# --- the cap -----------------------------------------------------------------------------------


def sized(count: int) -> Ratchet:
    """A ratchet whose four sets hold ``count`` entries between them."""
    pins = frozenset(f"sha256:{i:064x}" for i in range(count - 3))
    return Ratchet(
        1,
        1,
        {READ: pins},
        frozenset({TOKEN_CI}),
        frozenset({caller_digest(PLACEHOLDER)}),
        frozenset({WRITE}),
        {"NOTES_KEY": frozenset({"https://a.example:443", "https://b.example:443"})},
    )


def test_the_cap_counts_the_retired_sets_and_approved_not_env() -> None:
    assert RATCHET_MAX == 10_000
    assert entries(sized(7)) == 7
    assert not full(sized(RATCHET_MAX))
    assert full(sized(RATCHET_MAX + 1))


# --- the plain form ----------------------------------------------------------------------------


def test_the_plain_form_is_canonical_and_sorted() -> None:
    ratchet = Ratchet(
        3,
        2,
        {WRITE: frozenset({PIN_NEW, PIN_WRITE}), READ: frozenset({PIN_READ})},
        frozenset({TOKEN_NEW, TOKEN_CI}),
        frozenset({caller_digest(PLACEHOLDER)}),
        frozenset({WRITE, READ}),
        {"B_KEY": frozenset({"https://b.example:443"}), "A_KEY": frozenset({"z", "a"})},
    )
    assert ratchet.as_dict() == {
        "gateway_key_floor": 3,
        "egress_key_floor": 2,
        "retired_pins": [
            {"server": "notes", "kind": "tool", "name": "read", "pins": [PIN_READ]},
            {"server": "notes", "kind": "tool", "name": "write", "pins": [PIN_WRITE, PIN_NEW]},
        ],
        "retired_clients": [TOKEN_CI, TOKEN_NEW],
        "retired_callers": [caller_digest(PLACEHOLDER)],
        "approved": [list(READ), list(WRITE)],
        "env": {"A_KEY": ["a", "z"], "B_KEY": ["https://b.example:443"]},
    }
    assert loaded(ratchet.as_dict()) == ratchet
    assert loaded(START.as_dict()) == START
    # It goes into the sealed body as canonical JSON.
    dumps_canonical(ratchet.as_dict())


FIELDS_REFUSED = (
    "a ratchet has exactly the fields approved, egress_key_floor, env, gateway_key_floor, "
    "retired_callers, retired_clients, retired_pins"
)
WHOLE_NUMBER = " is a generation, a whole number from 1"
ENTRY_FORM = "a retired_pins entry is a server, kind, name and pins"
ENTRY_NEW = "a retired_pins entry names a new definition and one pin or more"


def plain(**changes: Any) -> dict[str, Any]:
    found = copy.deepcopy(sized(4).as_dict())
    found.update(changes)
    return found


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({**plain(), "extra": 1}, FIELDS_REFUSED),
        ({k: v for k, v in plain().items() if k != "env"}, FIELDS_REFUSED),
        (plain(gateway_key_floor=0), "gateway_key_floor" + WHOLE_NUMBER),
        (plain(egress_key_floor=True), "egress_key_floor" + WHOLE_NUMBER),
        (plain(egress_key_floor="1"), "egress_key_floor" + WHOLE_NUMBER),
        (plain(retired_pins={}), "retired_pins is a list"),
        (plain(retired_pins=[["notes", "tool", "read", [PIN_READ]]]), ENTRY_FORM),
        (plain(retired_pins=[{"server": "notes", "kind": "tool", "name": "read"}]), ENTRY_FORM),
        (
            plain(retired_pins=[{"server": "notes", "kind": "tool", "name": "read", "pins": []}]),
            ENTRY_NEW,
        ),
        (
            plain(
                retired_pins=[
                    {"server": "notes", "kind": "tool", "name": "read", "pins": [PIN_READ]},
                    {"server": "notes", "kind": "tool", "name": "read", "pins": [PIN_NEW]},
                ]
            ),
            ENTRY_NEW,
        ),
        (
            plain(
                retired_pins=[{"server": "notes", "kind": "tool", "name": "read", "pins": ["x"]}]
            ),
            "retired_pins holds sha256 digests only",
        ),
        (
            plain(
                retired_pins=[{"server": "notes", "kind": "skill", "name": "r", "pins": [PIN_READ]}]
            ),
            "retired_pins names a definition by server, kind and name",
        ),
        (
            plain(retired_clients=["sha256:" + "A" * 64]),
            "retired_clients holds sha256 digests only",
        ),
        (plain(retired_clients=[1]), "retired_clients holds text only"),
        (
            plain(retired_callers=["sha256:" + "B" * 64]),
            "retired_callers holds sha256 digests only",
        ),
        (plain(retired_callers=[""]), "retired_callers holds text only"),
        (plain(retired_callers="sha256:" + "1" * 64), "retired_callers is a list"),
        (plain(approved={}), "approved is a list"),
        (plain(approved=["notes/tool/read"]), "approved is a list"),
        (
            plain(approved=[["notes", "tool"]]),
            "approved names a definition by server, kind and name",
        ),
        (plain(approved=[["notes", "tool", 3]]), "approved holds text only"),
        (plain(approved=[[None, "tool", "read"]]), "approved holds text only"),
        (plain(env=[]), "env maps each name to its origins"),
        (plain(env={"": ["a"]}), "env holds text only"),
        (plain(env={"A": "https://a.example:443"}), "env is a list"),
    ],
)
def test_loaded_refuses_anything_but_the_plain_form(data: dict[str, Any], message: str) -> None:
    # The whole message: it names the field, and each entry is the first one it reaches.
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        loaded(data)


def test_loaded_takes_any_text_as_an_origin() -> None:
    found = loaded(plain(env={"A": ["unix:/run/zoeymcp-bridge-a/mcp.sock"]}))
    assert found.env == {"A": {"unix:/run/zoeymcp-bridge-a/mcp.sock"}}
