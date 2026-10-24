"""The planner (M6 design G.5, G.7, H.4, D.5, O.3; Y5-Y9, Y11, Y16; G-11, G-12, Q27).

Every refusal, and the rules' order wherever two adjacent ones apply; ``required_kind`` for
every op mix, prepared both ways; a rollback as its target's carry-forward; rule 1b; the move
rules (a move, a re-include of a
definition in ``approved``, a kept ``allow`` derived from ``suggested``) with
``allow_needs_review``, ``allow_marked`` and ``consequential_allow`` per move; the direction
rule's portal cases; the summary's rows in G.7's order, every chunk of every definition, nothing
cut; the cap both ways; ``pinning: off``'s row; the carry-forward (H.4); ``normalize`` (D.5);
and determinism.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any, Literal

import pytest

import zoeymcp.common.policy.plan as planner
from zoeymcp.common.canonical import digest
from zoeymcp.common.policy.check import secret_references
from zoeymcp.common.policy.diff import structured
from zoeymcp.common.policy.plan import (
    BREAK_TEXT,
    HOST_NEXT,
    NO_RESTART,
    SUMMARY_ROWS_MAX,
    BindingState,
    PlanInput,
    PlanRefused,
    WriteKind,
    WritePlan,
    carry_forward,
    document,
    normalize,
    normalized_digest,
    plan,
    required_kind,
)
from zoeymcp.common.policy.ratchet import RATCHET_MAX, Grants, Violation, caller_digest, initial
from zoeymcp.common.policy.restart import Started
from zoeymcp.common.policy.reviewchange import Lines, definition_lines
from zoeymcp.common.policy.schema import Policy, hash_token

PIN_READ = "sha256:" + "a" * 64
PIN_WRITE = "sha256:" + "b" * 64
PIN_LIST = "sha256:" + "c" * 64
PIN_NEW = "sha256:" + "d" * 64
PIN_OLD = "sha256:" + "e" * 64
TOKEN_CI = "sha256:" + "1" * 64
TOKEN_OLD = "sha256:" + "2" * 64
HEAD_DIGEST = "sha256:" + "f" * 64
READ = ("notes", "tool", "read")
WRITE = ("notes", "tool", "write")
LIST = ("notes", "tool", "list")
STARTED = Started(
    egress_proxy=None, egress_proxy_kind="own", admin_listen="127.0.0.1:8081", bridges=frozenset()
)

Edit = Callable[[dict[str, Any]], None]


def raw() -> dict[str, Any]:
    """A managed policy: the portal, a header credential on the notes route, a placeholder caller
    on the files route, a mail connector, one client, a server with an allow tool and two approve
    tools, and a toolkit with pinning off."""
    return {
        "version": 1,
        "mode": "managed",
        "admin": {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]},
        "credentials": {"notes-key": {"kind": "header", "secret": "store:notes-key"}},
        "connectors": {
            "mail": {
                "kind": "smtp",
                "host": "smtp.mail.example",
                "port": 465,
                "username": "bot",
                "password": "store:mail-password",
                "from": "bot@mail.example",
                "to": ["ops@mail.example"],
            }
        },
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
                "callers": ["gateway", {"placeholder": "ph-script-0001"}],
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
                        "include": ["read", "write", "list"],
                        "allow": ["read"],
                        "approve": ["write", "list"],
                    },
                    "review": {"read": PIN_READ, "write": PIN_WRITE, "list": PIN_LIST},
                },
                "kit": {
                    "kind": "toolkit",
                    "module": "kits.notes",
                    "pinning": "off",
                    "tools": {"include": ["send"], "approve": ["send"]},
                },
            },
        },
    }


def make(*edits: Edit) -> Policy:
    data = raw()
    for edit in edits:
        edit(data)
    return Policy.model_validate(data)


def notes(data: dict[str, Any]) -> dict[str, Any]:
    server: dict[str, Any] = data["gateway"]["servers"]["notes"]
    return server


def move(name: str, server: str = "notes") -> Edit:
    """``name`` from approve to allow."""

    def edit(data: dict[str, Any]) -> None:
        tools = data["gateway"]["servers"][server]["tools"]
        tools["approve"].remove(name)
        tools["allow"] = [*tools.get("allow", []), name]

    return edit


def repin(name: str, pin: str) -> Edit:
    def edit(data: dict[str, Any]) -> None:
        notes(data)["review"][name] = pin

    return edit


def drop(name: str) -> Edit:
    def edit(data: dict[str, Any]) -> None:
        tools = notes(data)["tools"]
        for block in ("include", "allow", "approve"):
            tools[block] = [t for t in tools[block] if t != name]
        notes(data)["review"].pop(name, None)

    return edit


def include(name: str, classification: str, pin: str) -> Edit:
    def edit(data: dict[str, Any]) -> None:
        tools = notes(data)["tools"]
        tools["include"].append(name)
        tools[classification].append(name)
        notes(data)["review"][name] = pin

    return edit


def setting(*path: str, value: Any) -> Edit:
    def edit(data: dict[str, Any]) -> None:
        here = data
        for key in path[:-1]:
            here = here.setdefault(key, {})
        here[path[-1]] = value

    return edit


def stored(policy: Policy) -> dict[str, BindingState]:
    """Every store entry the policy uses, each bound as it needs (a fake of the vault's)."""
    names = [ref.removeprefix("store:") for _, ref, _ in secret_references(policy)]
    return {name: "ok" for name in names if not name.startswith("env:")}


HEAD = make()


def planned(candidate: Policy, **fields: Any) -> WritePlan | PlanRefused:
    given: dict[str, Any] = {
        "kind": "policy.save",
        "surface": "portal",
        "head": HEAD,
        "head_revision": 17,
        "head_digest": HEAD_DIGEST,
        "ratchet": initial(HEAD),
        "candidate": candidate,
        "started": STARTED,
        "bindings": stored,
    }
    given.update(fields)
    return plan(PlanInput(**given))


def ok(candidate: Policy, **fields: Any) -> WritePlan:
    found = planned(candidate, **fields)
    assert isinstance(found, WritePlan), found
    return found


def refused(candidate: Policy, **fields: Any) -> PlanRefused:
    found = planned(candidate, **fields)
    assert isinstance(found, PlanRefused), found
    return found


def lines(definition: Mapping[str, Any]) -> Lines:
    return tuple(tuple(chunks) for chunks in definition_lines(definition))


def shown(name: str, pin: str | None, definition: Mapping[str, Any]) -> list[tuple[str, str]]:
    """A one-chunk-per-line definition's rows, the first naming its pin (G.7 row 2, J3)."""
    text = json.dumps(definition, ensure_ascii=True, indent=2, sort_keys=True).split("\n")
    rows = [(f"{name}, as pinned", line) for line in text]
    if pin is not None:
        rows[0] = (f"{name}, as pinned ({pin})", text[0])
    return rows


def tool(name: str, description: str = "Reads.") -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": True},
    }


# --- normalize and the revision's form (D.5) ----------------------------------------------------


def test_normalize_hashes_a_literal_token_and_keeps_the_rest() -> None:
    token = "t" * 40
    policy = make(setting("gateway", "clients", "ci", value={"token": token}))
    held = normalize(policy)
    assert held.gateway is not None
    client = held.gateway.clients["ci"]
    assert (client.token, client.token_sha256) == (None, hash_token(token))
    assert normalize(held) == held
    assert document(policy)["gateway"]["clients"]["ci"] == {"token_sha256": hash_token(token)}
    assert document(policy)["routes"][1]["callers"][1] == {"placeholder": "ph-script-0001"}
    assert normalize(HEAD) == HEAD
    assert "gateway_key_generation" not in document(HEAD)  # defaults left out


def test_the_normalized_digest_is_the_documents() -> None:
    token = "t" * 40
    policy = make(setting("gateway", "clients", "ci", value={"token": token}))
    hashed = make(setting("gateway", "clients", "ci", value={"token_sha256": hash_token(token)}))
    assert normalized_digest(policy) == digest(document(policy)) == normalized_digest(hashed)
    assert normalized_digest(policy) != normalized_digest(HEAD)


def test_normalize_leaves_a_default_unset_and_takes_a_policy_with_no_gateway() -> None:
    """The round trip through the document form (D.5, F-17): a default the policy leaves out stays
    unset, as ``change.apply`` loads its merge."""
    held = normalize(HEAD)
    assert held.model_fields_set == HEAD.model_fields_set
    assert held.model_dump(mode="json", by_alias=True, exclude_unset=True) == document(HEAD)
    bare = Policy.model_validate({"version": 1, "mode": "managed"})
    assert normalize(bare) == bare
    assert normalize(bare).model_fields_set == {"version", "mode"}


# --- rule 1: the kind is its diff ---------------------------------------------------------------


def kind_of(candidate: Policy, **fields: Any) -> WriteKind:
    changes = structured(HEAD, normalize(candidate))
    ratchet = fields.pop("ratchet", initial(HEAD))
    return required_kind(changes, HEAD, ratchet, **fields)


def test_required_kind_for_each_op() -> None:
    assert kind_of(make(move("write"))) == "tool.allow"
    assert kind_of(make(move("write"), move("list"))) == "policy.save"
    assert kind_of(make(move("write"), repin("read", PIN_NEW))) == "policy.save"
    verified = frozenset({(READ, PIN_NEW), (WRITE, PIN_OLD)})
    drifted = frozenset({READ, WRITE})
    repinned = make(repin("read", PIN_NEW), repin("write", PIN_OLD))
    assert kind_of(repinned, drifted=drifted, verified=verified) == "tool.repin"
    assert kind_of(repinned, drifted=frozenset({READ}), verified=verified) == "policy.save"
    assert kind_of(repinned, drifted=drifted, verified=frozenset({(READ, PIN_NEW)})) == (
        "policy.save"
    )
    assert kind_of(make(repin("read", PIN_NEW))) == "policy.save"  # nothing drifted
    limits = setting("connectors", "mail", "max_per_day", value=40)
    paused = setting("connectors", "mail", "paused", value=True)
    assert kind_of(make(limits, paused)) == "connector.limits"
    assert kind_of(make(setting("connectors", "mail", "to", value=["a@mail.example"]))) == (
        "policy.save"
    )
    servers = setting("gateway", "clients", "ci", "servers", value=["notes", "kit"])
    assert kind_of(make(servers)) == "client.servers"
    assert kind_of(make(servers, limits)) == "policy.save"
    other = setting(
        "gateway", "clients", "cd", value={"token_sha256": TOKEN_OLD, "servers": ["kit"]}
    )
    assert kind_of(make(servers, other)) == "policy.save"  # two clients
    assert kind_of(HEAD) == "policy.save"  # nothing: rule 6 answers it
    assert kind_of(make(drop("read"))) == "policy.save"
    # Two existing clients each given servers: two clients, so a save.
    two = make(other)
    both = make(other, servers, setting("gateway", "clients", "cd", "servers", value=["notes"]))
    assert required_kind(structured(two, normalize(both)), two, initial(two)) == "policy.save"


def test_a_move_of_a_tool_not_included_is_no_tool_allow() -> None:
    """``tool.allow`` is one included ``approve`` tool (Y7)."""
    loose = setting("gateway", "servers", "notes", "tools", "approve", value=["write", "list", "x"])
    head = make(loose)
    changes = structured(
        head,
        make(
            setting("gateway", "servers", "notes", "tools", "approve", value=["write", "list"]),
            setting("gateway", "servers", "notes", "tools", "allow", value=["read", "x"]),
        ),
    )
    assert required_kind(changes, head, initial(head)) == "policy.save"


def test_a_lone_reinclude_as_allow_is_a_policy_save() -> None:
    """A once-approved tool dropped and then included as allow is a move (T-2), and a save
    (Q27-4): it also adds an include and a pin. Its row names no revision (Q27-5)."""
    head = make(drop("write"))
    ratchet = replace(initial(head), approved=frozenset({WRITE}))
    candidate = make(drop("write"), include("write", "allow", PIN_WRITE))
    changes = structured(head, candidate)
    assert required_kind(changes, head, ratchet) == "policy.save"
    definitions = {WRITE: lines(tool("write"))}
    found = ok(
        candidate,
        head=head,
        ratchet=ratchet,
        verified=frozenset({(WRITE, PIN_WRITE)}),
        definitions=definitions,
    )
    assert found.moves == (WRITE,)
    assert found.rows[1] == (
        "notes.write",
        "write was approve in an earlier revision: calls will run with no prompt",
    )
    assert found.rows[2] == (f"write, as pinned ({PIN_WRITE})", "{")
    # Without the ratchet's approved entry it is a fresh include as allow: no move.
    fresh = ok(
        candidate, head=head, ratchet=initial(head), verified=frozenset({(WRITE, PIN_WRITE)})
    )
    assert fresh.moves == ()
    assert ("gateway.servers.notes.tools.allow", "write will run with no prompt") in fresh.rows


@pytest.mark.parametrize(
    ("prepared", "required", "edits"),
    [
        ("policy.save", "tool.allow", (move("write"),)),
        ("tool.allow", "policy.save", (move("write"), move("list"))),
        ("tool.repin", "policy.save", (repin("read", PIN_NEW),)),
        (
            "connector.limits",
            "client.servers",
            (setting("gateway", "clients", "ci", "servers", value=["kit"]),),
        ),
        (
            "client.servers",
            "connector.limits",
            (setting("connectors", "mail", "paused", value=True),),
        ),
        ("policy.import", "policy.save", (drop("read"),)),
    ],
    ids=["under", "over", "repin", "client", "limits", "import"],
)
def test_a_prepared_kind_that_differs_is_kind_mismatch(
    prepared: WriteKind, required: str, edits: tuple[Edit, ...]
) -> None:
    found = refused(make(*edits), kind=prepared)
    assert found.reason == "kind_mismatch"
    assert found.subjects == (required, prepared)
    changes = structured(HEAD, normalize(make(*edits)))
    paths = ", ".join(".".join(str(part) for part in c.path) for c in changes)
    assert found.detail == f"{required}, not {prepared}: {paths}"
    assert paths


def test_kind_mismatch_names_nothing_for_an_empty_diff() -> None:
    assert refused(HEAD, kind="tool.allow").detail == "policy.save, not tool.allow: nothing"


def test_a_surfaces_own_command_is_its_kind() -> None:
    """A rollback, an import, an acknowledge: the command is the kind (G.2); each surface has
    its own, and the portal's only one is the rollback."""
    candidate = make(drop("read"))
    assert ok(candidate, kind="policy.rollback", target=candidate).kind == "policy.rollback"
    socket = ok(candidate, kind="policy.rollback", surface="socket", target=candidate)
    assert socket.kind == "policy.rollback"
    for kind in ("policy.import", "policy.acknowledge"):
        assert ok(candidate, kind=kind, surface="socket").kind == kind
    for kind in ("policy.import", "policy.seed", "policy.reseed"):
        assert ok(candidate, kind=kind, surface="offline").kind == kind
    assert ok(candidate, kind="policy.resume", surface="host").kind == "policy.resume"
    for surface, kind in (
        ("portal", "policy.import"),
        ("socket", "policy.seed"),
        ("host", "policy.import"),
        ("offline", "policy.resume"),
    ):
        assert refused(candidate, kind=kind, surface=surface).reason == "kind_mismatch"
    # A host surface can still make a portal kind, by its diff.
    assert ok(make(move("write")), kind="tool.allow", surface="socket").kind == "tool.allow"


def test_a_rollback_is_its_targets_carry_forward() -> None:
    """Y11 in the planner (G.5 rule 1, H.4): a rollback with no target, or whose candidate isn't
    its target's carry-forward, is the kind its diff says; from the portal, a target makes a
    rollback whatever the page prepared."""
    stale = make(drop("list"), repin("write", PIN_OLD))
    found = refused(stale, kind="policy.rollback")
    assert found.subjects == ("policy.save", "policy.rollback")
    paths = "gateway.servers.notes.tools.include, gateway.servers.notes.tools.approve, "
    paths += "gateway.servers.notes.review.list, gateway.servers.notes.review.write"
    assert found == PlanRefused(
        "kind_mismatch",
        f"policy.save, not policy.rollback: {paths}",
        ("policy.save", "policy.rollback"),
    )
    # The carry-forward keeps the head's pin of write: a candidate that re-pins it isn't one.
    found = refused(stale, kind="policy.rollback", target=stale, target_revision=3)
    assert found.reason == "kind_mismatch"
    carried = carry_forward(HEAD, stale)
    rolled = ok(carried, kind="policy.rollback", target=stale, target_revision=3)
    assert rolled.policy.gateway is not None
    assert rolled.policy.gateway.servers["notes"].review["write"] == PIN_WRITE
    assert refused(carried, kind="policy.rollback").reason == "kind_mismatch"  # no target
    # A host's rollback takes the target's admin, the portal's the head's (H.4).
    origins = make(setting("admin", "origins", value=["http://localhost:9000"]))
    host = carry_forward(HEAD, origins, host=True)
    socket = ok(host, kind="policy.rollback", surface="socket", target=origins)
    assert socket.kind == "policy.rollback"
    assert refused(host, kind="policy.rollback", target=origins).reason == "kind_mismatch"
    portal = carry_forward(HEAD, origins)
    found = refused(portal, kind="policy.rollback", surface="socket", target=origins)
    assert found.reason == "kind_mismatch"
    # From the portal a candidate carried from a target is a rollback; the host's import may
    # name its document as the target.
    found = refused(carried, target=stale)
    assert found.subjects == ("policy.rollback", "policy.save")
    assert ok(carried, kind="policy.import", surface="socket", target=stale)


def test_a_rollback_that_isnt_a_carry_forward_names_its_diffs_kind() -> None:
    """With no target, a rollback's kind is read from its diff, with the head, the ratchet and
    the review's drifted and verified pins as any write's (G.5 rule 1)."""
    found = refused(make(move("write")), kind="policy.rollback")
    assert found == PlanRefused(
        "kind_mismatch",
        "tool.allow, not policy.rollback: gateway.servers.notes.tools.allow, "
        "gateway.servers.notes.tools.approve",
        ("tool.allow", "policy.rollback"),
    )
    repinned = refused(
        make(repin("read", PIN_NEW)),
        kind="policy.rollback",
        drifted=frozenset({READ}),
        verified=frozenset({(READ, PIN_NEW)}),
    )
    assert repinned.subjects == ("tool.repin", "policy.rollback")
    # A fresh include as allow asks the ratchet whether it is a re-include.
    fresh = refused(make(include("fresh", "allow", PIN_NEW)), kind="policy.rollback")
    assert fresh.subjects == ("policy.save", "policy.rollback")


# --- rule 1: the moves -------------------------------------------------------------------------


def test_n_moves_give_n_rows_each_with_its_definition_first_among_the_weakenings() -> None:
    lowered = setting("connectors", "mail", "max_per_day", value=10)
    candidate = make(move("write"), move("list"), lowered)
    definitions = {WRITE: lines(tool("write")), LIST: lines(tool("list"))}
    found = ok(candidate, definitions=definitions)
    assert found.kind == "policy.save"
    assert found.moves == (LIST, WRITE)  # the diff's order: names sorted
    assert found.kept_allow == ()
    rows = list(found.rows)
    assert rows[0] == ("Revision", "18, from 17")
    body = shown("list", PIN_LIST, tool("list"))
    assert rows[1] == ("notes.list", "approve -> allow. Calls to list will run with no prompt.")
    assert rows[2 : 2 + len(body)] == body
    assert rows[2] == (f"list, as pinned ({PIN_LIST})", "{")
    at = 2 + len(body)
    assert rows[at] == ("notes.write", "approve -> allow. Calls to write will run with no prompt.")
    assert rows[at + 1 : at + 1 + len(body)] == shown("write", PIN_WRITE, tool("write"))
    # Every other change after them; the allow additions are the move rows themselves; no
    # effect, so no restart (J3).
    assert rows[at + 1 + len(body) :] == [
        ("connectors.mail.max_per_day", "changed"),
        ("gateway.servers.notes.tools.approve", "list removed"),
        ("gateway.servers.notes.tools.approve", "write removed"),
        ("No restart needed", ""),
    ]


def test_a_move_with_no_definition_is_allow_needs_review() -> None:
    found = refused(make(move("write"), move("list")), definitions={WRITE: lines(tool("write"))})
    assert found == PlanRefused("allow_needs_review", "notes.list", ("notes/tool/list",))
    # The host shows what it has: no definition, no refusal (H.5's plan prints the rows).
    host = ok(make(move("write")), kind="policy.import", surface="socket")
    assert host.moves == (WRITE,)
    assert host.rows[1:3] == (
        ("notes.write", "approve -> allow. Calls to write will run with no prompt."),
        ("gateway.servers.notes.tools.approve", "write removed"),
    )


@pytest.mark.parametrize("reason", ["allow_marked", "consequential_allow"])
def test_a_marked_or_consequential_move_kept_allow_or_new_include_is_refused(
    reason: Literal["allow_marked", "consequential_allow"],
) -> None:
    given = "marked" if reason == "allow_marked" else "consequential"
    definitions = {WRITE: lines(tool("write")), READ: lines(tool("read"))}
    candidate = make(move("write"))
    found = refused(
        candidate, kind="tool.allow", definitions=definitions, **{given: frozenset({WRITE})}
    )
    assert found == PlanRefused(reason, "notes.write", ("notes/tool/write",))
    kept = make(repin("read", PIN_NEW))
    found = refused(
        kept,
        verified=frozenset({(READ, PIN_NEW)}),
        definitions=definitions,
        **{given: frozenset({READ})},
    )
    assert (found.reason, found.subjects) == (reason, ("notes/tool/read",))
    new = make(include("fresh", "allow", PIN_NEW))
    key = ("notes", "tool", "fresh")
    found = refused(new, verified=frozenset({(key, PIN_NEW)}), **{given: frozenset({key})})
    assert (found.reason, found.subjects) == (reason, ("notes/tool/fresh",))
    # An approve include of a marked tool is no allow.
    approve = make(include("fresh", "approve", PIN_NEW))
    assert ok(approve, verified=frozenset({(key, PIN_NEW)}), **{given: frozenset({key})})


def test_the_move_checks_in_order() -> None:
    """``allow_needs_review`` before ``allow_marked`` before ``consequential_allow``, each naming
    every tool it applies to."""
    candidate = make(move("write"), move("list"))
    both = frozenset({WRITE, LIST})
    assert refused(candidate, marked=both, consequential=both).reason == "allow_needs_review"
    definitions = {WRITE: lines(tool("write")), LIST: lines(tool("list"))}
    found = refused(candidate, definitions=definitions, marked=both, consequential=both)
    assert found == PlanRefused(
        "allow_marked", "notes.list, notes.write", ("notes/tool/list", "notes/tool/write")
    )
    found = refused(candidate, definitions=definitions, consequential=frozenset({LIST}))
    assert found == PlanRefused("consequential_allow", "notes.list", ("notes/tool/list",))
    # The kind comes first.
    assert refused(candidate, kind="tool.allow", marked=both).reason == "kind_mismatch"


def test_the_kept_allow_is_derived_from_suggested() -> None:
    """A re-pinned allow tool whose new definition isn't suggested allow stays allow as its own
    row (Q8, Q27); suggested allow gives none; a re-pinned approve tool none."""
    candidate = make(repin("read", PIN_NEW), repin("write", PIN_OLD))
    verified = frozenset({(READ, PIN_NEW), (WRITE, PIN_OLD)})
    drifted = frozenset({READ, WRITE})
    definitions = {READ: lines(tool("read", "Now writes."))}
    for suggested in ({}, {READ: None}, {READ: "approve"}):
        found = ok(
            candidate,
            kind="tool.repin",
            verified=verified,
            drifted=drifted,
            definitions=definitions,
            suggested=suggested,
        )
        assert found.kept_allow == (READ,)
        assert found.moves == ()
        assert found.rows[1] == (
            "notes.read",
            "read's new definition isn't marked read-only and stays allow: calls will run with "
            "no prompt",
        )
        assert found.rows[2] == (f"read, as pinned ({PIN_NEW})", "{")
    found = ok(
        candidate,
        kind="tool.repin",
        verified=verified,
        drifted=drifted,
        suggested={READ: "allow"},
    )
    assert found.kept_allow == ()
    assert found.rows[1:] == (
        (
            "gateway.servers.notes.review.read",
            f"{PIN_READ} -> {PIN_NEW} (re-pinned: you read both definitions)",
        ),
        (
            "gateway.servers.notes.review.write",
            f"{PIN_WRITE} -> {PIN_OLD} (re-pinned: you read both definitions)",
        ),
        NO_RESTART,
    )
    # An approve tool re-pinned is no kept allow, whatever its suggestion.
    approve = ok(
        make(repin("write", PIN_OLD)),
        kind="tool.repin",
        verified=verified,
        drifted=drifted,
        suggested={WRITE: "approve"},
    )
    assert approve.kept_allow == ()
    # From the portal a kept allow needs its definition.
    found2 = refused(candidate, kind="tool.repin", verified=verified, drifted=drifted)
    assert found2 == PlanRefused("allow_needs_review", "notes.read", ("notes/tool/read",))


def test_a_definition_is_every_chunk_nothing_cut() -> None:
    """A 16,384-character description with a U+202E past code point 200: the rows' chunks,
    joined line by line, are the ``json.dumps`` text, the escape among them, every chunk a row
    counted toward the cap (G.7, Y9)."""
    description = "a" * 300 + "\u202e" + "b" * (16_384 - 301)
    definition = tool("write", description)
    found = ok(make(move("write")), kind="tool.allow", definitions={WRITE: lines(definition)})
    labels = (f"write, as pinned ({PIN_WRITE})", "write, as pinned", "write, continued")
    rows = [row for row in found.rows if row[0] in labels]
    assert rows[0][0] == labels[0]
    text = json.dumps(definition, ensure_ascii=True, indent=2, sort_keys=True)
    joined: list[str] = []
    for label, chunk in rows:
        assert len(chunk) <= 200
        if label != "write, continued":
            joined.append(chunk)
        else:
            joined[-1] += chunk
    assert "\n".join(joined) == text
    assert any("\\u202e" in chunk for _, chunk in rows)
    assert len(rows) == sum(len(chunks) for chunks in definition_lines(definition))
    assert len(rows) > 80


def test_pinning_off_shows_its_row_after_the_definition() -> None:
    kit = ("kit", "tool", "send")
    found = ok(make(move("send", "kit")), kind="tool.allow", definitions={kit: lines(tool("send"))})
    assert found.moves == (kit,)
    body = len(definition_lines(tool("send")))
    assert found.rows[1] == ("kit.send", "approve -> allow. Calls to send will run with no prompt.")
    assert found.rows[2] == ("send, as pinned", "{")  # no pin is written
    assert found.rows[2 + body] == (
        "kit",
        "pinning is off for kit: the image can change this definition with no review",
    )
    plain = ok(make(move("write")), kind="tool.allow", definitions={WRITE: lines(tool("write"))})
    assert not any(label == "notes" for label, _ in plain.rows)


# --- rules 1b and 1c ---------------------------------------------------------------------------


def test_a_pin_the_review_didnt_verify_is_review_stale() -> None:
    key = ("notes", "tool", "fresh")
    candidate = make(include("fresh", "approve", PIN_NEW), repin("write", PIN_OLD))
    found = refused(candidate, verified=frozenset({(key, PIN_NEW)}))
    assert found == PlanRefused("review_stale", "notes.write", ("notes/tool/write",))
    found = refused(candidate, verified=frozenset({(WRITE, PIN_OLD)}))
    assert found.subjects == ("notes/tool/fresh",)
    assert ok(candidate, verified=frozenset({(key, PIN_NEW), (WRITE, PIN_OLD)}))
    # A server added whole brings its pins: each is checked too.
    other = {
        "kind": "remote",
        "route": "files",
        "tools": {"include": ["x"], "approve": ["x"]},
        "review": {"x": PIN_NEW},
    }
    added = setting("gateway", "servers", "other", value=other)
    found = refused(make(added))
    assert found == PlanRefused("review_stale", "other.x", ("other/tool/x",))
    # Beside a re-pin, both are checked.
    found = refused(
        make(added, repin("write", PIN_OLD)),
        verified=frozenset({(("other", "tool", "x"), PIN_NEW)}),
    )
    assert found == PlanRefused("review_stale", "notes.write", ("notes/tool/write",))
    # The host isn't held to it; a portal rollback carries the head's pins (H.4), and one that
    # doesn't is no rollback.
    assert ok(candidate, kind="policy.import", surface="socket")
    stale = make(repin("write", PIN_OLD))
    assert refused(stale, kind="policy.rollback", target=stale).reason == "kind_mismatch"


def test_rule_1c_comes_before_rule_2() -> None:
    """A portal rollback that revives a client and widens a route is ``rollback_revives``, with
    the revision that removed it (verifier C1, N.2)."""
    ratchet = replace(initial(HEAD), retired_clients=frozenset({TOKEN_OLD}))
    target = make(
        setting("gateway", "clients", "old", value={"token_sha256": TOKEN_OLD}),
        setting(
            "routes",
            value=[
                {**raw()["routes"][0], "rules": [{"methods": ["POST", "GET"], "paths": ["/mcp"]}]},
                raw()["routes"][1],
            ],
        ),
    )
    candidate = carry_forward(HEAD, target)
    removed = {"client:old": 21}
    found = refused(
        candidate,
        kind="policy.rollback",
        ratchet=ratchet,
        target=target,
        target_revision=20,
        removed_in=removed.get,
    )
    assert found == PlanRefused(
        "rollback_revives",
        "revision 20 brings back client old, removed in revision 21",
        ("client:old",),
    )
    # Without the client the route's widening is rule 2's.
    plain = make(
        setting(
            "routes",
            value=[
                {**raw()["routes"][0], "rules": [{"methods": ["POST", "GET"], "paths": ["/mcp"]}]},
                raw()["routes"][1],
            ],
        )
    )
    found = refused(plain, kind="policy.rollback", target=plain, target_revision=20)
    assert found.reason == "portal_widens"
    assert found.detail == "widen routes.notes-mcp.rules.0.methods through a rollback"
    # The socket names the client and its grant; with the grant it plans, with a row for it.
    found = refused(
        candidate, kind="policy.rollback", surface="socket", ratchet=ratchet, target=target
    )
    assert found == PlanRefused("revives_client", "client old", ("client:old",))
    granted = ok(
        candidate,
        kind="policy.rollback",
        surface="socket",
        ratchet=ratchet,
        target=target,
        grants=Grants(revive=frozenset({"client:old"})),
    )
    assert ("Granted by the host", "revives_client: client:old") in granted.rows
    # The portal never uses a grant.
    found = refused(
        candidate,
        kind="policy.rollback",
        ratchet=ratchet,
        target=target,
        grants=Grants(revive=frozenset({"client:old"})),
    )
    assert (found.reason, found.detail) == ("rollback_revives", "the target brings back client old")


def test_a_revived_caller() -> None:
    from zoeymcp.common.policy.ratchet import caller_digest

    ratchet = replace(initial(HEAD), retired_callers=frozenset({caller_digest("ph-old-00001")}))
    files = {**raw()["routes"][1], "callers": ["gateway", {"placeholder": "ph-old-00001"}]}
    candidate = make(setting("routes", value=[raw()["routes"][0], files]))
    found = refused(candidate, kind="policy.rollback", ratchet=ratchet, target=candidate)
    assert found == PlanRefused(
        "rollback_revives", "the target brings back caller files/1", ("caller:files/1",)
    )
    found = refused(
        candidate,
        kind="policy.import",
        surface="socket",
        ratchet=ratchet,
        removed_in={"caller:files/1": 9}.get,
    )
    assert found == PlanRefused(
        "revives_caller", "caller files/1, removed in revision 9", ("caller:files/1",)
    )


def test_the_other_violations_keep_their_names() -> None:
    ratchet = replace(initial(HEAD), gateway_key_floor=3, egress_key_floor=2)
    found = refused(HEAD, kind="policy.import", surface="socket", ratchet=ratchet)
    assert found == PlanRefused(
        "generation_lowered",
        "gateway_key_generation can't go below 3",
        ("gateway_key_generation", "egress_key_generation"),
    )
    retired = replace(initial(HEAD), retired_pins={WRITE: frozenset({PIN_OLD})})
    back = make(repin("write", PIN_OLD))
    found = refused(back, kind="policy.import", surface="socket", ratchet=retired)
    assert found == PlanRefused("pin_retired", "notes's tool write", ("pin:notes/tool/write",))
    # A rollback keeps the head's pins: only a definition the head lacks keeps the target's.
    dropped = make(drop("write"))
    found = refused(
        carry_forward(dropped, back),
        kind="policy.rollback",
        head=dropped,
        ratchet=replace(initial(dropped), retired_pins={WRITE: frozenset({PIN_OLD})}),
        target=back,
    )
    assert found == PlanRefused("pin_retired", "notes's tool write", ("pin:notes/tool/write",))
    env = setting("credentials", "notes-key", value={"kind": "header", "secret": "env:NOTES_KEY"})
    found = refused(make(env), kind="policy.import", surface="socket")
    assert found == PlanRefused("env_name_new", "NOTES_KEY is new", ("NOTES_KEY",))
    head = make(env)
    wider = setting(
        "routes",
        value=[{**raw()["routes"][0], "upstream": "https://other.example"}, raw()["routes"][1]],
    )
    found = refused(
        make(env, wider), head=head, ratchet=initial(head), kind="policy.import", surface="socket"
    )
    assert found == PlanRefused(
        "env_reach_grows",
        "NOTES_KEY would also be sent to https://other.example:443",
        ("NOTES_KEY",),
    )
    granted = ok(
        make(env, wider),
        head=head,
        ratchet=initial(head),
        kind="policy.import",
        surface="socket",
        grants=Grants(env=frozenset({"NOTES_KEY"})),
    )
    assert ("Granted by the host", "env_reach_grows: NOTES_KEY") in granted.rows
    # The portal's grants are always empty: the same write is refused there.
    found = refused(
        make(env, wider),
        head=head,
        ratchet=initial(head),
        kind="policy.rollback",
        target=make(env, wider),
        grants=Grants(env=frozenset({"NOTES_KEY"})),
    )
    assert found.reason == "env_reach_grows"


def test_a_refusal_names_each_violation_of_its_reason() -> None:
    """Two retired pins, two new env names, two new origins, a client and a caller revived:
    each refusal's detail joins them all (N.2)."""
    retired = replace(
        initial(HEAD), retired_pins={WRITE: frozenset({PIN_OLD}), LIST: frozenset({PIN_NEW})}
    )
    back = make(repin("write", PIN_OLD), repin("list", PIN_NEW))
    found = refused(back, kind="policy.import", surface="socket", ratchet=retired)
    assert found == PlanRefused(
        "pin_retired",
        "notes's tool write, notes's tool list",
        ("pin:notes/tool/write", "pin:notes/tool/list"),
    )
    env = setting("credentials", "notes-key", value={"kind": "header", "secret": "env:NOTES_KEY"})
    files = setting("credentials", "files-key", value={"kind": "header", "secret": "env:FILES_KEY"})
    used = setting(
        "routes", value=[raw()["routes"][0], {**raw()["routes"][1], "credential": "files-key"}]
    )
    found = refused(make(env, files, used), kind="policy.import", surface="socket")
    assert found == PlanRefused(
        "env_name_new", "NOTES_KEY is new; env:FILES_KEY is new", ("NOTES_KEY", "FILES_KEY")
    )
    head = make(env)
    extra = {**ROUTE, "name": "extra", "prefix": "/extra", "upstream": "https://b.example"}
    wider = setting(
        "routes",
        value=[
            {**raw()["routes"][0], "upstream": "https://a.example"},
            raw()["routes"][1],
            {**extra, "credential": "notes-key"},
        ],
    )
    found = refused(
        make(env, wider), head=head, ratchet=initial(head), kind="policy.import", surface="socket"
    )
    assert found == PlanRefused(
        "env_reach_grows",
        "NOTES_KEY would also be sent to https://a.example:443, https://b.example:443",
        ("NOTES_KEY",),
    )
    ratchet = replace(
        initial(HEAD),
        retired_clients=frozenset({TOKEN_OLD}),
        retired_callers=frozenset({caller_digest("ph-old-00001")}),
    )
    caller = {**raw()["routes"][1], "callers": ["gateway", {"placeholder": "ph-old-00001"}]}
    target = make(
        setting("gateway", "clients", "old", value={"token_sha256": TOKEN_OLD}),
        setting("routes", value=[raw()["routes"][0], caller]),
    )
    candidate = carry_forward(HEAD, target)
    removed = {"client:old": 21}.get
    found = refused(
        candidate,
        kind="policy.rollback",
        ratchet=ratchet,
        target=target,
        target_revision=20,
        removed_in=removed,
    )
    assert found == PlanRefused(
        "rollback_revives",
        "revision 20 brings back client old, removed in revision 21; caller files/1",
        ("client:old", "caller:files/1"),
    )
    found = refused(
        candidate, kind="policy.import", surface="socket", ratchet=ratchet, removed_in=removed
    )
    assert found == PlanRefused(
        "revives_client",
        "client old, removed in revision 21; caller files/1",
        ("client:old", "caller:files/1"),
    )


def test_a_host_write_back_to_a_retired_pin_it_verified_needs_no_grant() -> None:
    """A retired pin the review verified again isn't a violation (E.2), so the host's plan has no
    "Granted by the host" row for it."""
    retired = replace(initial(HEAD), retired_pins={WRITE: frozenset({PIN_OLD})})
    found = ok(
        make(repin("write", PIN_OLD)),
        kind="policy.import",
        surface="socket",
        ratchet=retired,
        verified=frozenset({(WRITE, PIN_OLD)}),
    )
    assert found.rows == (
        ("Revision", "18, from 17"),
        (
            "gateway.servers.notes.review.write",
            f"{PIN_WRITE} -> {PIN_OLD} (re-pinned: you read both definitions)",
        ),
        NO_RESTART,
    )


def test_a_retired_pins_name_may_hold_a_slash(monkeypatch: pytest.MonkeyPatch) -> None:
    """A resource's name is a URI (L.2): only the server and the kind end at a "/"."""
    subject = "pin:files/resource/https://files.example/a/b"
    monkeypatch.setattr(planner, "violations", lambda *a, **k: (Violation("pin_retired", subject),))
    found = refused(make(drop("read")), kind="policy.import", surface="socket")
    assert found == PlanRefused(
        "pin_retired", "files's resource https://files.example/a/b", (subject,)
    )


def test_a_ratchet_past_its_bound_is_ratchet_full() -> None:
    from zoeymcp.common.policy.ratchet import RATCHET_MAX

    # The head's three approve definitions join approved and the write retires client ci: with
    # RATCHET_MAX - 4 retired before it, the ratchet after holds exactly RATCHET_MAX entries.
    before = frozenset(f"sha256:{n:064x}" for n in range(3, RATCHET_MAX - 1))
    ratchet = replace(initial(HEAD), retired_clients=before)
    assert len(before) + 1 + len(ratchet.approved) == RATCHET_MAX
    gone = make(setting("gateway", "clients", value={}))
    assert ok(gone, kind="policy.import", surface="socket").ratchet.approved == ratchet.approved
    assert ok(gone, ratchet=ratchet)
    over = replace(ratchet, approved=ratchet.approved | {("x", "tool", "y")})
    assert refused(gone, ratchet=over) == PlanRefused("ratchet_full")
    assert refused(gone, ratchet=over, kind="policy.import", surface="socket").reason == (
        "ratchet_full"
    )


def order_case(name: str) -> tuple[Policy, dict[str, Any]]:
    """A write that breaks two adjacent rules (G.5's order: 1, 1b, 1c, ratchet_full, 2, 4, 5)."""
    over = replace(
        initial(HEAD),
        retired_clients=frozenset(f"sha256:{n:064x}" for n in range(3, RATCHET_MAX + 3)),
    )
    origins = setting("admin", "origins", value=["http://localhost:9000"])
    raised = setting("gateway_key_generation", value=2)
    wide = {"type": "object", "properties": {f"p{n}": {"type": "string"} for n in range(130)}}
    cases: dict[str, tuple[Policy, dict[str, Any]]] = {
        # 1 (kind_mismatch) before the per-move checks
        "kind-moves": (make(move("write"), move("list")), {"kind": "tool.allow"}),
        # the per-move checks before 1b
        "moves-1b": (make(move("write"), repin("list", PIN_NEW)), {}),
        # 1b before 1c: an unverified re-pin to a retired pin
        "1b-1c": (
            make(repin("write", PIN_OLD)),
            {"ratchet": replace(initial(HEAD), retired_pins={WRITE: frozenset({PIN_OLD})})},
        ),
        # 1c before ratchet_full
        "1c-full": (
            make(drop("write")),
            {"ratchet": replace(over, gateway_key_floor=3), "kind": "policy.import"},
        ),
        # ratchet_full before 2
        "full-2": (make(origins), {"ratchet": over}),
        # 2 before 4
        "2-4": (make(raised, origins), {}),
        # 4 before 5: a key rotation beside a move whose definition passes the cap
        "4-5": (
            make(raised, move("write")),
            {"definitions": {WRITE: lines({**tool("write"), "inputSchema": wide})}},
        ),
    }
    return cases[name]


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("kind-moves", "kind_mismatch"),
        ("moves-1b", "allow_needs_review"),
        ("1b-1c", "review_stale"),
        ("1c-full", "generation_lowered"),
        ("full-2", "ratchet_full"),
        ("2-4", "portal_widens"),
        ("4-5", "generation_raise_from_portal"),
    ],
    ids=["kind-moves", "moves-1b", "1b-1c", "1c-full", "full-2", "2-4", "4-5"],
)
def test_every_refusal_in_order(name: str, reason: str) -> None:
    """Where a write breaks two adjacent rules, the earlier one answers (G.5, O.3); the later
    one answers alone once the earlier is mended (each case's own test)."""
    candidate, fields = order_case(name)
    surface = "socket" if fields.get("kind") == "policy.import" else "portal"
    assert refused(candidate, surface=surface, **fields).reason == reason


# --- rule 2: the portal's bound ----------------------------------------------------------------

ROUTE = {
    "name": "new",
    "prefix": "/new",
    "upstream": "https://mcp.new.example",
    "credential": "new-key",
    "callers": ["gateway"],
    "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
}


@pytest.mark.parametrize(
    ("edits", "detail"),
    [
        ((setting("admin", "origins", value=["http://localhost:9000"]),), "change admin.origins"),
        ((setting("admin", value=None),), "change admin"),
        ((setting("egress_proxy", value="http://proxy.example:3128"),), "change egress_proxy"),
        (
            (setting("egress_proxy_acls", value={"vault": "acl_vault"}),),
            "change egress_proxy_acls.vault",
        ),
        (
            (setting("gateway", "limits", value={"call_timeout": 10}),),
            "change gateway.limits.call_timeout",
        ),
        (
            (setting("gateway", "approvals", value={"timeout": 10}),),
            "change gateway.approvals.timeout",
        ),
        ((setting("gateway", "hosts", value=["localhost"]),), "change gateway.hosts"),
        ((setting("gateway", "origins", value=["https://app.example"]),), "change gateway.origins"),
        (
            (setting("connectors", "mail", "to", value=["x@mail.example"]),),
            "change connectors.mail.to",
        ),
        ((setting("connectors", "mail", "port", value=587),), "change connectors.mail.port"),
        (
            (setting("gateway", "clients", "cd", value={"token_sha256": TOKEN_OLD}),),
            "add a client (gateway.clients.cd)",
        ),
        (
            (setting("gateway", "clients", "ci", "token_sha256", value=TOKEN_OLD),),
            "change the token of client ci",
        ),
        (
            (
                setting(
                    "routes",
                    value=[
                        {
                            **raw()["routes"][0],
                            "callers": ["gateway", {"placeholder": "ph-new-000001"}],
                        },
                        raw()["routes"][1],
                    ],
                ),
            ),
            "add a caller to route notes-mcp",
        ),
        (
            (
                setting(
                    "credentials", "new-key", value={"kind": "header", "secret": "store:new-key"}
                ),
                setting(
                    "routes",
                    value=[
                        *raw()["routes"],
                        {**ROUTE, "callers": [{"placeholder": "ph-new-000001"}]},
                    ],
                ),
            ),
            "add a caller to route new",
        ),
        (
            (
                setting("gateway", "servers", "notes", "on_drift", value="fail"),
                setting("gateway", "servers", "notes", "shared_session", value=True),
            ),
            "widen gateway.servers.notes.shared_session",
        ),
        (
            (
                setting("gateway", "clients", "ci", "sources", value=["10.0.0.0/8"]),
                setting("gateway", "clients", "ci", "servers", value=["notes"]),
            ),
            "widen gateway.clients.ci.servers",
        ),
        (
            (
                setting(
                    "routes",
                    value=[
                        {**raw()["routes"][0], "upstream": "https://x.example"},
                        raw()["routes"][1],
                    ],
                ),
            ),
            "widen routes.notes-mcp.upstream",
        ),
    ],
    ids=[
        "admin-origins",
        "admin-removed",
        "egress-proxy",
        "egress-acls",
        "limits",
        "approvals",
        "hosts",
        "origins",
        "connector-to",
        "connector-port",
        "client-added",
        "client-token",
        "caller-added",
        "new-route-caller",
        "server-widened",
        "client-servers-in-a-save",
        "route-repointed",
    ],
)
def test_the_portal_cant_widen(edits: tuple[Edit, ...], detail: str) -> None:
    found = refused(
        make(*edits),
        kind=required_kind(structured(HEAD, normalize(make(*edits))), HEAD, initial(HEAD)),
    )
    assert (found.reason, found.detail, found.next) == ("portal_widens", detail, HOST_NEXT)
    # The host may (its plan shows the widening rows).
    assert ok(make(*edits), kind="policy.import", surface="socket")


def test_portal_widens_names_every_path() -> None:
    candidate = make(
        setting("admin", "origins", value=["http://localhost:9000"]),
        setting("gateway", "servers", "notes", "shared_session", value=True),
    )
    found = refused(candidate)
    assert found.subjects == ("admin.origins", "gateway.servers.notes.shared_session")


def test_the_portal_may_remove_a_connector_and_a_caller() -> None:
    """A removal is narrower: neither a connector's whole entry nor a caller taken away is a
    bound field or an added caller (G.5 rule 2)."""
    gone = ok(make(setting("connectors", value={})))
    assert gone.rows == (
        ("Revision", "18, from 17"),
        ("connectors.mail", "removed"),
        NO_RESTART,
        ("Left unused", "mail-password"),
    )
    files = {**raw()["routes"][1], "callers": ["gateway"]}
    found = ok(make(setting("routes", value=[raw()["routes"][0], files])))
    assert found.rows[1] == ("routes.files.callers.1", "removed")


def test_a_routes_query_allow_is_no_tools_allow() -> None:
    """A save permits a tool's ``allow`` addition, not a route's wider ``query.allow``."""
    query = {**raw()["routes"][0], "query": {"allow": ["a"]}}
    head = make(setting("routes", value=[query, raw()["routes"][1]]))
    wider = {**raw()["routes"][0], "query": {"allow": ["a", "b"]}}
    found = refused(
        make(setting("routes", value=[wider, raw()["routes"][1]])), head=head, ratchet=initial(head)
    )
    assert (found.reason, found.detail) == ("portal_widens", "widen routes.notes-mcp.query.allow")


def test_onboarding_and_each_kinds_widening_are_permitted() -> None:
    """``policy.save``: onboarding's credential, route (callers gateway), server and private
    entry, a re-registration's credential and a review's include, declines and era;
    ``connector.limits`` an unpause and a raise; ``client.servers`` a server given."""
    onboard = make(
        setting("credentials", "new-key", value={"kind": "header", "secret": "store:new-key"}),
        setting("routes", value=[*raw()["routes"], ROUTE]),
        setting("gateway", "servers", "new", value={"kind": "remote", "route": "new"}),
        setting("egress_private", value=["mcp.lan.example:443"]),
    )
    assert ok(onboard).kind == "policy.save"
    reregister = setting("credentials", "notes-key", "header", value="X-Key")
    assert ok(make(reregister)).kind == "policy.save"
    era = setting("gateway", "servers", "notes", "era", value="modern")
    assert ok(make(era)).kind == "policy.save"
    paused = make(setting("connectors", "mail", "paused", value=True))
    unpause = ok(make(), head=paused, ratchet=initial(paused), kind="connector.limits")
    assert unpause.rows[1] == ("connectors.mail.paused", "sends can go out again")
    raised = ok(
        make(setting("connectors", "mail", "max_body_chars", value=9000)), kind="connector.limits"
    )
    assert raised.rows[1] == ("connectors.mail.max_body_chars", "2200 -> 9000: raised")
    given = ok(
        make(setting("gateway", "clients", "ci", "servers", value=["notes"])), kind="client.servers"
    )
    assert given.rows[1] == (
        "gateway.clients.ci.servers",
        "agents holding client ci's token can call notes's 3 included tools",
    )


def test_a_decline_taken_back_is_a_weakening_a_save_permits() -> None:
    """A review's declines (G.5 rule 2): a declined tool included again says so, with the
    revision it was declined in; a decline dropped for a tool left out is wider too; an include
    is a weakening of its own, no allow (G.7 row 2)."""
    fresh = ("notes", "tool", "fresh")
    declined = {"fresh": PIN_NEW, "gone": PIN_OLD}
    head = make(setting("gateway", "servers", "notes", "declined", value=declined))
    found = ok(
        make(include("fresh", "approve", PIN_NEW)),
        head=head,
        ratchet=initial(head),
        verified=frozenset({(fresh, PIN_NEW)}),
    )
    assert found.rows == (
        ("Revision", "18, from 17"),
        ("gateway.servers.notes.tools.include", "fresh added (wider)"),
        ("gateway.servers.notes.declined.fresh", "fresh: declined in revision 17, included again"),
        ("gateway.servers.notes.declined.gone", "removed (wider)"),
        ("gateway.servers.notes.tools.approve", "fresh added"),
        ("gateway.servers.notes.review.fresh", "added"),
        NO_RESTART,
    )


def test_a_connectors_wider_recipients_are_no_raised_limit() -> None:
    """Only a connector's limits read "raised"; its other wider fields are plain weakenings."""
    grown = setting("connectors", "mail", "to", value=["ops@mail.example", "x@mail.example"])
    found = ok(make(grown), kind="policy.import", surface="socket")
    assert found.rows[1] == ("connectors.mail.to", "changed (wider)")


def test_a_portal_rollback_narrows_and_removes_but_never_widens() -> None:
    """Undoing an onboarding (the server, route and credential removed) and a move: narrower,
    so the portal may (G-11, E-4); the unused store entry is listed (Q13)."""
    head = make(
        setting("credentials", "new-key", value={"kind": "header", "secret": "store:new-key"}),
        setting("routes", value=[*raw()["routes"], ROUTE]),
        setting("gateway", "servers", "new", value={"kind": "remote", "route": "new"}),
        move("write"),
    )
    target = HEAD
    candidate = carry_forward(head, target)
    found = ok(
        candidate,
        head=head,
        ratchet=initial(head),
        kind="policy.rollback",
        target=target,
        target_revision=12,
    )
    assert found.unused_slots == ("new-key",)
    assert found.rows[0] == ("Revision", "18, from 17: the content of revision 12")
    assert found.rows[-1] == ("Left unused", "new-key")
    widened = make(setting("gateway", "servers", "notes", "on_drift", value="hide"))
    strict = make(setting("gateway", "servers", "notes", "on_drift", value="fail"))
    wider = refused(
        widened, head=strict, ratchet=initial(strict), kind="policy.rollback", target=widened
    )
    assert wider.detail == "widen gateway.servers.notes.on_drift through a rollback"
    # A move to allow by a rollback is wider too.
    moved = refused(make(move("write")), kind="policy.rollback", target=make(move("write")))
    assert moved.detail == "widen gateway.servers.notes.tools.allow through a rollback"


def test_a_key_rotation_from_the_portal_is_refused() -> None:
    raised = make(setting("gateway_key_generation", value=2))
    assert refused(raised) == PlanRefused(
        "generation_raise_from_portal", "gateway_key_generation", ("gateway_key_generation",)
    )
    egress = make(setting("egress_key_generation", value=2))
    assert refused(egress).detail == "egress_key_generation"
    host = ok(raised, kind="policy.import", surface="socket")
    assert host.rows[-1] == (
        "Redeploy needed",
        "gateway_key_generation: give the gateway key(2) within 5 minutes (zoeymcp gateway-key), "
        "or it is refused",
    )


# --- rules 5 and 6 -----------------------------------------------------------------------------


def test_a_single_move_over_the_cap_goes_to_the_host() -> None:
    """A definition whose rows alone pass 400 can't be moved from the portal at all (Q27-8)."""
    wide = {"type": "object", "properties": {f"p{n}": {"type": "string"} for n in range(130)}}
    definition = {**tool("write"), "inputSchema": wide}
    rows = lines(definition)
    assert sum(len(chunks) for chunks in rows) > SUMMARY_ROWS_MAX
    found = refused(make(move("write")), kind="tool.allow", definitions={WRITE: rows})
    assert found == PlanRefused(
        "summary_too_large",
        "write's definition has more than 400 lines: make this move on the host",
        ("notes/tool/write",),
        HOST_NEXT,
    )
    assert HOST_NEXT == "zoeymcp policy export, edit, zoeymcp policy import"
    assert ok(
        make(move("write")), kind="policy.import", surface="socket", definitions={WRITE: rows}
    )
    # A definition of exactly 400 rows isn't over on its own: the whole plan is.
    at = {WRITE: (("x",),) * SUMMARY_ROWS_MAX}
    found = refused(make(move("write")), kind="tool.allow", definitions=at)
    assert (found.detail, found.subjects) == (
        "it has more than 400 lines: save fewer moves to allow at once, or make it on the host",
        (),
    )


def test_a_plan_over_the_cap_is_summary_too_large_and_one_at_it_passes() -> None:
    """Every chunk row counts (G.5 rule 5): a plan of exactly 400 rows passes, 401 doesn't."""
    candidate = make(move("write"), move("list"))
    fixed = len(ok(candidate, definitions={WRITE: (), LIST: ()}).rows)
    half = SUMMARY_ROWS_MAX - fixed
    at = {WRITE: (("x",),) * (half // 2), LIST: (("x",),) * (half - half // 2)}
    assert len(ok(candidate, definitions=at).rows) == SUMMARY_ROWS_MAX
    over = {**at, LIST: (*at[LIST], ("x",))}
    assert refused(candidate, definitions=over) == PlanRefused(
        "summary_too_large",
        "it has more than 400 lines: save fewer moves to allow at once, or make it on the host",
        (),
        HOST_NEXT,
    )
    assert ok(candidate, kind="policy.import", surface="socket", definitions=over)


def test_an_empty_diff_is_no_change_except_an_acknowledge() -> None:
    assert refused(HEAD) == PlanRefused("no_change")
    assert refused(HEAD, kind="policy.import", surface="socket") == PlanRefused("no_change")
    acknowledged = ok(HEAD, kind="policy.acknowledge", surface="socket")
    assert (acknowledged.changes, acknowledged.rows) == ((), (("Revision", "18, from 17"),))


@pytest.mark.parametrize(
    ("kind", "surface"),
    [("policy.resume", "host"), ("policy.reseed", "offline")],
    ids=["resume", "reseed"],
)
def test_an_unchanged_resume_or_reseed_is_still_a_revision(kind: WriteKind, surface: str) -> None:
    """A resume writes parked + 1 and clears the park (F.4, J10: the exported file run again is
    the next revision); a reseed writes highest + 1 (F.3): each is its own revision (Y4)."""
    found = ok(HEAD, kind=kind, surface=surface)
    assert (found.kind, found.changes, found.rows) == (kind, (), (("Revision", "18, from 17"),))


# --- the plan's parts --------------------------------------------------------------------------


def test_the_rows_in_g7s_order() -> None:
    """The revision; the moves and the kept allows with their definitions; the other weakenings;
    every other change; restarts; bindings that stop matching; fields kept; unused entries."""
    head = make(include("ext", "approve", PIN_OLD))
    key = ("notes", "tool", "ext")

    def bindings(policy: Policy) -> dict[str, BindingState]:
        found = stored(policy)
        if policy.routes[0].upstream != "https://mcp.notes.example":
            found["notes-key"] = "changed"
        return found

    edits = (
        include("ext", "approve", PIN_OLD),
        move("ext"),
        repin("read", PIN_NEW),
        drop("list"),
        setting("routes", value=[{**raw()["routes"][0], "upstream": "https://mcp2.notes.example"}]),
        setting("gateway", "servers", "notes", "declined", value={"list": PIN_LIST}),
        setting("admin", "listen", value="127.0.0.1:9090"),
        setting("connectors", value={}),
    )
    candidate = make(*edits)
    found = ok(
        candidate,
        head=head,
        ratchet=initial(head),
        kind="policy.import",
        surface="socket",
        definitions={key: (("{",), ("}",))},
        target=make(*edits, repin("read", PIN_OLD)),
        target_revision=15,
        bindings=bindings,
    )
    assert found.moves == (key,)
    assert found.kept_allow == (READ,)
    assert found.breaks == ("notes-key",)
    assert found.unused_slots == ("mail-password",)
    assert found.rows == (
        ("Revision", "18, from 17: the content of revision 15"),
        ("notes.ext", "approve -> allow. Calls to ext will run with no prompt."),
        (f"ext, as pinned ({PIN_OLD})", "{"),
        ("ext, as pinned", "}"),
        (
            "notes.read",
            "read's new definition isn't marked read-only and stays allow: calls will run with "
            "no prompt",
        ),
        ("admin.listen", "changed (wider)"),
        ("routes.notes-mcp.upstream", "changed (wider)"),
        ("connectors.mail", "removed"),
        ("routes.files", "removed"),
        ("gateway.servers.notes.tools.include", "list removed"),
        ("gateway.servers.notes.tools.approve", "ext removed"),
        ("gateway.servers.notes.tools.approve", "list removed"),
        ("gateway.servers.notes.review.list", "removed"),
        ("gateway.servers.notes.review.read", f"{PIN_READ} -> {PIN_NEW}"),
        ("gateway.servers.notes.declined.list", "added"),
        (
            "Restart needed",
            "admin.listen: the portal keeps listening where it started: restart the vault",
        ),
        ("Stops matching", BREAK_TEXT.format(name="notes-key")),
        ("Kept from revision 17", "gateway.servers.notes.review.read"),
        ("Left unused", "mail-password"),
    )


def test_kept_rows_name_what_the_head_carried() -> None:
    """A rollback's "Kept from revision N" rows list each field the candidate took from the
    head, not the target (H.4, G.7 row 6)."""
    target = make(
        setting("admin", "origins", value=["http://localhost:9000"]),
        setting("gateway_key_generation", value=1),
        repin("read", PIN_OLD),
        drop("list"),
    )
    head = make(setting("gateway_key_generation", value=4))
    candidate = carry_forward(head, target)
    found = ok(
        candidate,
        head=head,
        ratchet=initial(head),
        kind="policy.rollback",
        target=target,
        target_revision=3,
    )
    assert found.kept == (
        "gateway_key_generation",
        "admin.origins",
        "gateway.servers.notes.review.read",
    )
    assert found.rows[-3:] == tuple(("Kept from revision 17", path) for path in found.kept)
    assert [".".join(map(str, c.path)) for c in found.changes] == [
        "gateway.servers.notes.tools.include",
        "gateway.servers.notes.tools.approve",
        "gateway.servers.notes.review.list",
    ]


def test_the_plan_carries_the_head_and_the_advanced_ratchet() -> None:
    candidate = make(drop("write"))
    found = ok(candidate, head_revision=41, head_digest=HEAD_DIGEST)
    assert (found.base, found.base_digest) == (41, HEAD_DIGEST)
    assert found.policy == normalize(candidate)
    assert found.ratchet.retired_pins == {WRITE: frozenset({PIN_WRITE})}
    assert found.ratchet.approved == frozenset({WRITE, LIST, ("kit", "tool", "send")})
    assert found.effects == ()
    assert "policy=" not in repr(found)
    assert "ratchet=" not in repr(found)


def test_the_plan_is_deterministic() -> None:
    candidate = make(move("write"), move("list"), repin("read", PIN_NEW))
    fields: dict[str, Any] = {
        "verified": frozenset({(READ, PIN_NEW)}),
        "definitions": {
            WRITE: lines(tool("write")),
            LIST: lines(tool("list")),
            READ: lines(tool("read")),
        },
    }
    assert ok(candidate, **fields) == ok(copy.deepcopy(candidate), **fields)


# --- the carry-forward (H.4) -------------------------------------------------------------------


def test_the_carry_forward() -> None:
    """The head's generations, admin (a portal rollback) and pins of the definitions it pins;
    the host's rollback takes the target's admin; declined is both less what is included."""
    head = make(
        setting("gateway_key_generation", value=5),
        setting("egress_key_generation", value=3),
        setting("admin", "origins", value=["http://localhost:9000"]),
        repin("read", PIN_NEW),
        drop("list"),
        setting("gateway", "servers", "notes", "declined", value={"list": PIN_LIST, "a": PIN_OLD}),
    )
    target = make(
        include("extra", "approve", PIN_OLD),
        setting("gateway", "servers", "notes", "declined", value={"b": PIN_OLD, "extra": PIN_NEW}),
    )
    portal = carry_forward(head, target)
    assert (portal.gateway_key_generation, portal.egress_key_generation) == (5, 3)
    assert portal.admin == head.admin
    assert portal.gateway is not None
    server = portal.gateway.servers["notes"]
    assert server.review == {
        "read": PIN_NEW,
        "write": PIN_WRITE,
        "list": PIN_LIST,
        "extra": PIN_OLD,
    }
    assert server.declined == {"a": PIN_OLD, "b": PIN_OLD}  # list and extra are included
    assert target.gateway is not None
    assert portal.gateway.servers["kit"] == target.gateway.servers["kit"]
    host = carry_forward(head, target, host=True)
    assert host.admin == target.admin
    assert (host.gateway_key_generation, host.egress_key_generation) == (5, 3)
    no_admin = make(setting("admin", value=None))
    assert carry_forward(no_admin, target).admin is None
    assert carry_forward(head, no_admin, host=True).admin is None


def test_the_carry_forward_normalizes_and_keeps_a_server_only_the_target_has() -> None:
    token = "t" * 40
    target = make(
        setting("gateway", "clients", "ci", value={"token": token}),
        setting(
            "gateway",
            "servers",
            "solo",
            value={
                "kind": "remote",
                "route": "files",
                "tools": {"include": ["x"], "approve": ["x"]},
                "review": {"x": PIN_OLD},
                "declined": {"x": PIN_OLD, "y": PIN_NEW},
            },
        ),
    )
    found = carry_forward(HEAD, target)
    assert found.gateway is not None
    assert found.gateway.clients["ci"].token_sha256 == hash_token(token)
    solo = found.gateway.servers["solo"]
    assert (solo.review, solo.declined) == ({"x": PIN_OLD}, {"y": PIN_NEW})
    assert found == normalize(found)


def test_the_carry_forward_of_policies_missing_a_block() -> None:
    """A head or a target with no gateway, a target whose gateway has no servers, a server with
    no tools (every tool declined) and a target with no admin: each block absent is empty."""
    bare = Policy.model_validate({"version": 1, "mode": "managed"})
    assert carry_forward(HEAD, bare).gateway is None
    assert carry_forward(HEAD, bare).admin == HEAD.admin
    from_bare = carry_forward(bare, HEAD)
    assert (from_bare.gateway, from_bare.admin) == (HEAD.gateway, None)
    serverless = carry_forward(HEAD, make(setting("gateway", "servers", value={})))
    assert serverless.gateway is not None
    assert serverless.gateway.servers == {}
    all_declined = {"kind": "remote", "route": "notes-mcp", "declined": {"read": PIN_READ}}
    found = carry_forward(HEAD, make(setting("gateway", "servers", "notes", value=all_declined)))
    assert found.gateway is not None
    notes = found.gateway.servers["notes"]
    assert (notes.tools.include, notes.review, notes.declined) == ([], {}, {"read": PIN_READ})
    assert carry_forward(HEAD, make(setting("admin", value=None))).admin == HEAD.admin


def test_the_plans_effects_breaks_and_unused_entries() -> None:
    def bindings(policy: Policy) -> dict[str, BindingState]:
        found: dict[str, BindingState] = {"mail-password": "ok"}
        if policy.credentials:
            found["notes-key"] = "wider"
        return found

    gone = make(
        setting("credentials", value={}),
        setting("routes", value=[raw()["routes"][1]]),
        setting("gateway", "servers", value={"kit": raw()["gateway"]["servers"]["kit"]}),
    )
    found = ok(gone, kind="policy.import", surface="socket", bindings=bindings)
    assert (found.breaks, found.unused_slots) == ((), ("notes-key",))

    # A binding already changed at the head isn't a break; a new one going changed is none.
    def broken(policy: Policy) -> dict[str, BindingState]:
        return {
            "a": "changed",
            "b": "changed",
            "c": "ok" if policy == HEAD else "changed",
            "d": "wider" if policy == HEAD else "changed",
            **({} if policy == HEAD else {"e": "changed"}),
        }

    found = ok(make(drop("read")), bindings=broken)
    assert found.breaks == ("c", "d")
    assert found.unused_slots == ()


def test_inputs_carry_their_defaults() -> None:
    i = PlanInput(
        kind="policy.save",
        surface="portal",
        head=HEAD,
        head_revision=1,
        head_digest=HEAD_DIGEST,
        ratchet=initial(HEAD),
        candidate=HEAD,
        started=STARTED,
        bindings=stored,
    )
    assert (i.verified, i.drifted, i.marked, i.consequential) == ((frozenset(),) * 4)
    assert (dict(i.definitions), dict(i.suggested), i.grants) == ({}, {}, Grants())
    assert (i.target, i.target_revision, i.removed_in("client:x")) == (None, None, None)


def test_a_server_the_policy_lacks_has_no_tools_pin_or_pinning() -> None:
    """The planner's readers of one server, given one the policy lacks or a policy with no
    gateway: no tools, no pin, pinning not off."""
    bare = Policy.model_validate({"version": 1, "mode": "managed"})
    absent = ("absent", "tool", "x")
    assert planner._tools(bare, "notes") == planner._tools(HEAD, "absent") == ([], [])
    assert planner._tools(HEAD, "notes") == (["read", "write", "list"], ["read"])
    assert planner._pin(bare, READ) is None
    assert planner._pin(HEAD, absent) is None
    assert planner._pin(HEAD, READ) == PIN_READ
    assert planner._pinning_off(bare, "kit") is False
    assert planner._pinning_off(HEAD, "absent") is False
    assert planner._pinning_off(HEAD, "kit") is True
