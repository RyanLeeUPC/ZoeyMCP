"""A diff between two revisions, as the portal and the socket show it (M6 design H.2, O.3; DD-10,
Y13).

Every op and every policy-view field kind: a shown value as the policy view shows it, a whole
entry as its model with its own hidden fields only as set, a hidden field and one name of a
names map only as set, changed or removed, the recipients as a count; every row's direction is
the diff's; the path's names shown. No hidden value reaches any row: a sentinel in every hidden
field, added, removed and changed. A model or field the policy view's table doesn't name raises,
so a field a later milestone adds never reaches a diff before someone decides how it shows.
Hidden characters are written as escapes so this file holds none.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest

from zoeymcp.common.policy.diff import Change, direction, structured
from zoeymcp.common.policy.schema import Policy
from zoeymcp.portal import policydiffview
from zoeymcp.portal.policydiffview import CHANGED, REMOVED, SET, rows
from zoeymcp.portal.policyview import FIELDS

TOKEN_HASH = "sha256:" + "4" * 64
PIN = "sha256:" + "a" * 64
PIN_NEW = "sha256:" + "b" * 64
# One sentinel per hidden value (policyview's table: L, and the two names maps).
SENTINELS = {
    "token": "sentinel-literal-token-0001",
    "token_sha256": "sha256:" + "7" * 64,
    "placeholder": "sentinel-placeholder-0001",
    "basic": "sentinel-basic-user",
    "smtp_user": "sentinel-smtp-user",
    "from": "sentinel-from@mail.example",
    "to": "sentinel-to@mail.example",
    "token_header": "sentinel-token-header-value",
    "forced": "sentinel-forced-value",
}

Edit = Callable[[dict[str, Any]], None]


def document() -> dict[str, Any]:
    """A managed policy with every hidden field set to a sentinel."""
    found = SENTINELS
    return {
        "version": 1,
        "mode": "managed",
        "admin": {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]},
        "credentials": {
            "basic-cred": {"kind": "basic", "username": found["basic"], "secret": "store:b"},
            "oauth-cred": {
                "kind": "oauth2",
                "token_url": "https://auth.example/token",
                "client_id": "example-client",
                "refresh_token": "store:oauth-refresh",
                "token_headers": {"X-Extra": found["token_header"]},
            },
        },
        "connectors": {
            "mail-out": {
                "kind": "smtp",
                "host": "smtp.mail.example",
                "port": 465,
                "username": found["smtp_user"],
                "password": "store:mail-pass",
                "from": found["from"],
                "to": [found["to"]],
            }
        },
        "routes": [
            {
                "name": "api",
                "prefix": "/api",
                "upstream": "https://api.example",
                "credential": "basic-cred",
                "callers": ["gateway", {"placeholder": found["placeholder"], "header": "X-A"}],
                "query": {"force": {"mode": found["forced"]}},
                "rules": [{"methods": ["GET"], "paths": ["/items/{id}"], "params": {"id": ["1"]}}],
            }
        ],
        "gateway": {
            "clients": {
                "literal": {"token": found["token"], "servers": ["notes"]},
                "hashed": {"token_sha256": found["token_sha256"]},
            },
            "servers": {
                "notes": {
                    "kind": "remote",
                    "route": "api",
                    "tools": {"include": ["read"], "allow": ["read"]},
                    "review": {"read": PIN},
                }
            },
        },
    }


def make(*edits: Edit) -> Policy:
    raw = document()
    for edit in edits:
        edit(raw)
    return Policy.model_validate(raw)


BASE = make()
EMPTY = Policy.model_validate({"version": 1, "mode": "managed"})


def diff_rows(old: Policy, new: Policy) -> list[dict[str, Any]]:
    return rows(structured(old, new))


def one(*edits: Edit) -> dict[str, Any]:
    """The one row ``edits`` make against :data:`BASE`."""
    [row] = diff_rows(BASE, make(*edits))
    return row


def notes(raw: dict[str, Any]) -> dict[str, Any]:
    server: dict[str, Any] = raw["gateway"]["servers"]["notes"]
    return server


def route(raw: dict[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = raw["routes"][0]
    return found


# --- the row -------------------------------------------------------------------------------------


def test_a_row_names_the_path_the_op_the_direction_and_both_values() -> None:
    row = one(lambda raw: notes(raw).update(on_drift="fail"))
    assert row == {
        "path_shown": ["gateway", "servers", "notes", "on_drift"],
        "op": "changed",
        "direction": "narrower",
        "old": "hide",
        "new": "fail",
        "hidden": False,
    }
    back = diff_rows(make(lambda raw: notes(raw).update(on_drift="fail")), BASE)
    assert [(r["direction"], r["old"], r["new"]) for r in back] == [("wider", "fail", "hide")]


def test_every_rows_direction_is_the_diffs() -> None:
    for old, new in ((EMPTY, BASE), (BASE, EMPTY)):
        changes = structured(old, new)
        assert len(changes) > 5
        assert [r["direction"] for r in rows(changes)] == [direction(c) for c in changes]
        assert [r["op"] for r in rows(changes)] == [c.op for c in changes]
    assert {r["direction"] for r in diff_rows(EMPTY, BASE)} == {"wider"}
    assert "narrower" in {r["direction"] for r in diff_rows(BASE, EMPTY)}


def test_the_rows_keep_the_diffs_order() -> None:
    changes = structured(EMPTY, BASE)
    assert [r["path_shown"] for r in rows(changes)] == [list(c.path) for c in changes]
    assert rows(()) == []
    assert rows(iter(changes)) == rows(changes)


# --- shown values --------------------------------------------------------------------------------


def test_a_map_entry_a_name_and_a_list_whole() -> None:
    added = one(lambda raw: notes(raw)["review"].update(write=PIN_NEW))
    assert (added["path_shown"], added["op"], added["old"], added["new"]) == (
        ["gateway", "servers", "notes", "review", "write"],
        "added",
        None,
        PIN_NEW,
    )
    changed = one(lambda raw: notes(raw)["review"].update(read=PIN_NEW))
    assert (changed["op"], changed["old"], changed["new"]) == ("changed", PIN, PIN_NEW)
    named = diff_rows(BASE, make(lambda raw: notes(raw)["tools"].update(allow=[])))
    assert [(r["path_shown"], r["op"], r["old"], r["new"]) for r in named] == [
        (["gateway", "servers", "notes", "tools", "allow"], "removed", "read", None)
    ]
    whole = one(lambda raw: raw.update(egress_private=["api.example:443"]))
    assert (whole["old"], whole["new"]) == ([], ["api.example:443"])


def test_a_whole_entry_is_its_model_with_its_hidden_fields_only_set() -> None:
    def add(raw: dict[str, Any]) -> None:
        raw["gateway"]["clients"]["reports"] = {
            "token_sha256": TOKEN_HASH,
            "servers": ["notes"],
            "approvals": {"attended": True},
        }

    row = one(add)
    assert row["path_shown"] == ["gateway", "clients", "reports"]
    assert (row["op"], row["direction"], row["old"], row["hidden"]) == (
        "added",
        "wider",
        None,
        False,
    )
    assert row["new"] == {
        "token": None,
        "token_sha256": SET,
        "servers": ["notes"],
        "sources": [],
        "approvals": {
            "attended": True,
            "timeout": None,
            "budget_chars": None,
            "confirm_code": False,
            "renders": "markdown",
        },
    }
    gone = diff_rows(make(add), BASE)
    assert [(r["op"], r["old"]["token_sha256"], r["new"]) for r in gone] == [("removed", SET, None)]


def test_a_route_a_caller_and_a_rule_are_their_models() -> None:
    def add(raw: dict[str, Any]) -> None:
        raw["routes"].append({**copy.deepcopy(route(raw)), "name": "api2", "prefix": "/api2"})

    row = one(add)
    assert row["path_shown"] == ["routes", "api2"]
    callers = row["new"]["callers"]
    assert callers == [
        "gateway",
        {"placeholder": SET, "header": "X-A", "query": None, "sources": []},
    ]
    assert row["new"]["query"] == {"force": {"mode": SET}, "strip": [], "allow": None}
    caller = one(lambda raw: route(raw)["callers"].append({"placeholder": "p" * 20, "query": "q"}))
    assert (caller["path_shown"], caller["old"]) == (["routes", "api", "callers", 2], None)
    assert caller["new"] == {"placeholder": SET, "header": None, "query": "q", "sources": []}
    gateway = one(lambda raw: route(raw)["callers"].append("gateway"))
    assert (gateway["path_shown"][-1], gateway["new"]) == (2, "gateway")
    rule = one(lambda raw: route(raw)["rules"].append({"methods": ["POST"], "paths": ["/x"]}))
    assert rule["new"] == {"methods": ["POST"], "paths": ["/x"], "params": {}}


def test_a_params_entry_changed_from_values_to_a_regex() -> None:
    row = one(lambda raw: route(raw)["rules"][0].update(params={"id": {"regex": "^a"}}))
    assert row["path_shown"] == ["routes", "api", "rules", 0, "params", "id"]
    assert (row["old"], row["new"]) == (["1"], {"regex": "^a"})


def test_an_entry_replaced_by_another_kind() -> None:
    def swap(raw: dict[str, Any]) -> None:
        raw["credentials"]["basic-cred"] = {"kind": "header", "secret": "store:b"}

    row = one(swap)
    assert (row["path_shown"], row["op"]) == (["credentials", "basic-cred"], "changed")
    assert row["old"] == {"kind": "basic", "username": SET, "secret": "store:b"}
    assert row["new"] == {
        "kind": "header",
        "secret": "store:b",
        "header": "Authorization",
        "format": "Bearer {secret}",
    }

    def toolkit(raw: dict[str, Any]) -> None:
        raw["gateway"]["servers"]["notes"] = {"kind": "toolkit", "module": "kits.notes"}

    server = one(toolkit)
    assert (server["old"]["kind"], server["new"]["kind"]) == ("remote", "toolkit")
    assert server["new"]["module"] == "kits.notes"


def test_a_block_added_and_removed() -> None:
    row = one(lambda raw: raw.pop("admin"))
    assert (row["path_shown"], row["direction"], row["new"]) == (["admin"], "narrower", None)
    assert row["old"] == {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]}
    [back] = diff_rows(make(lambda raw: raw.pop("admin")), BASE)
    assert (back["old"], back["new"]) == (None, row["old"])


def test_every_string_is_shown() -> None:
    """Revealed and capped, values as the policy view caps them, names at the name cap."""
    long_url = "https://api.example/" + "p" * 3000
    row = one(lambda raw: route(raw).update(upstream=long_url))
    assert row["new"] == long_url[:2048] + "\u2026[+" + str(len(long_url) - 2048) + "]"
    client = one(lambda raw: raw["credentials"]["oauth-cred"].update(client_id="a\u202eb\u200bc"))
    assert client["new"] == "a[U+202E]b[U+200B]c"
    hostile = Change(
        ("gateway", "servers", "a\u202eb" + "x" * 200), "removed", None, None, "Gateway", "servers"
    )
    [shown] = rows([hostile])
    assert shown["path_shown"][:2] == ["gateway", "servers"]
    assert shown["path_shown"][2] == "a[U+202E]b" + "x" * 125 + "\u2026[+75]"


# --- hidden values -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "edit", "path", "marker"),
    [
        pytest.param(
            "token_sha256",
            lambda raw: raw["gateway"]["clients"]["hashed"].update(token_sha256=TOKEN_HASH),
            ["gateway", "clients", "hashed", "token_sha256"],
            CHANGED,
            id="token_sha256",
        ),
        pytest.param(
            "token_set",
            lambda raw: raw["gateway"]["clients"]["hashed"].update(
                token="another-literal-token", token_sha256=None
            ),
            ["gateway", "clients", "hashed", "token"],
            SET,
            id="token_set",
        ),
        pytest.param(
            "placeholder",
            lambda raw: route(raw)["callers"][1].update(placeholder="another-placeholder"),
            ["routes", "api", "callers", 1, "placeholder"],
            CHANGED,
            id="placeholder",
        ),
        pytest.param(
            "basic_username",
            lambda raw: raw["credentials"]["basic-cred"].update(username="another-user"),
            ["credentials", "basic-cred", "username"],
            CHANGED,
            id="basic_username",
        ),
        pytest.param(
            "smtp_username",
            lambda raw: raw["connectors"]["mail-out"].update(username="another-user"),
            ["connectors", "mail-out", "username"],
            CHANGED,
            id="smtp_username",
        ),
        pytest.param(
            "smtp_from",
            lambda raw: raw["connectors"]["mail-out"].update({"from": "x@mail.example"}),
            ["connectors", "mail-out", "from"],
            CHANGED,
            id="smtp_from",
        ),
        pytest.param(
            "token_header_changed",
            lambda raw: raw["credentials"]["oauth-cred"].update(token_headers={"X-Extra": "y"}),
            ["credentials", "oauth-cred", "token_headers", "X-Extra"],
            CHANGED,
            id="token_header_changed",
        ),
        pytest.param(
            "token_header_removed",
            lambda raw: raw["credentials"]["oauth-cred"].update(token_headers={}),
            ["credentials", "oauth-cred", "token_headers", "X-Extra"],
            REMOVED,
            id="token_header_removed",
        ),
        pytest.param(
            "forced_added",
            lambda raw: route(raw)["query"]["force"].update(page="2"),
            ["routes", "api", "query", "force", "page"],
            SET,
            id="forced_added",
        ),
    ],
)
def test_a_hidden_field_shows_only_that_it_changed(
    name: str, edit: Edit, path: list[str | int], marker: str
) -> None:
    changes = [c for c in structured(BASE, make(edit)) if list(c.path) == path]
    assert len(changes) == 1, name
    [row] = rows(changes)
    assert row == {
        "path_shown": path,
        "op": changes[0].op,
        "direction": direction(changes[0]),
        "old": None,
        "new": marker,
        "hidden": True,
    }


def test_a_hidden_value_removed() -> None:
    def literal(raw: dict[str, Any]) -> None:
        raw["gateway"]["clients"]["hashed"].update(token="another-literal-token", token_sha256=None)

    [token, removed] = diff_rows(BASE, make(literal))
    assert (token["new"], removed["path_shown"][-1], removed["new"]) == (
        SET,
        "token_sha256",
        REMOVED,
    )


def test_the_recipients_are_a_count() -> None:
    def two(raw: dict[str, Any]) -> None:
        raw["connectors"]["mail-out"]["to"] = ["a@mail.example", "b@mail.example"]

    row = one(two)
    assert row == {
        "path_shown": ["connectors", "mail-out", "to"],
        "op": "changed",
        "direction": "wider",
        "old": "(1 address)",
        "new": "(2 addresses)",
        "hidden": True,
    }


def test_no_hidden_value_reaches_any_row() -> None:
    """Y13: added, removed, and every hidden value changed at once."""

    def every(raw: dict[str, Any]) -> None:
        raw["gateway"]["clients"]["literal"]["token"] = "another-literal-token"
        raw["gateway"]["clients"]["hashed"]["token_sha256"] = TOKEN_HASH
        route(raw)["callers"][1]["placeholder"] = "another-placeholder"
        raw["credentials"]["basic-cred"]["username"] = "another-basic"
        mail = raw["connectors"]["mail-out"]
        mail.update(username="another-smtp", to=["a@mail.example", "b@mail.example"])
        mail["from"] = "another@mail.example"
        raw["credentials"]["oauth-cred"]["token_headers"] = {"X-Extra": "another-header"}
        route(raw)["query"]["force"] = {"mode": "another-forced"}

    pairs = ((EMPTY, BASE), (BASE, EMPTY), (BASE, make(every)), (make(every), BASE))
    for old, new in pairs:
        changes = structured(old, new)
        held = repr(changes)
        assert all(value in held for value in SENTINELS.values())  # the test isn't vacuous
        text = json.dumps(rows(changes))
        for where, value in SENTINELS.items():
            assert value not in text, where
        assert "sha256:" + "7" not in text
        assert TOKEN_HASH not in text
    assert len(diff_rows(BASE, make(every))) == 9


# --- fail closed ---------------------------------------------------------------------------------


def test_a_model_or_field_the_view_doesnt_name_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    tables = dict(FIELDS)
    del tables["Admin"]
    monkeypatch.setattr(policydiffview, "FIELDS", tables)
    admin = Change(("admin", "listen"), "changed", "a:1", "b:2", "Admin", "listen")
    with pytest.raises(KeyError, match="Admin"):
        rows([admin])
    tables["Admin"] = {"origins": "shown"}
    with pytest.raises(KeyError, match="listen"):
        rows([admin])
