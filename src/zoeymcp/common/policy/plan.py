"""The planner: what a managed write changes, whether its surface may make it, and the summary
the operator confirms (M6 design G.5, G.7, H.4, D.5; Y2, Y5-Y9, Y11, Y16; G-11, G-12, Q27). Pure,
mutation-tested.

Every managed write, from any surface, is planned here against the head and its ratchet (G.1):
:func:`plan` takes the candidate the gate admitted (C) and answers the :class:`WritePlan` the
operator confirms and the commit writes, or the first :class:`PlanRefused` of G.5's rules:

1. **The kind is its diff** (Y7, G-12): :func:`required_kind` reads the structured diff (H.2) of
   the two policies as :func:`normalize` writes them; a surface's own command (an import, F's
   host writes) is its kind (:data:`COMMANDS`), and a rollback is the carry-forward of its
   ``target`` (:func:`carry_forward`, H.4) or no rollback at all; a portal write carried from a
   target is a rollback. A prepared kind that differs is ``kind_mismatch``, whichever way. A
   **move to allow** is a tool's ``approve`` removal with its ``allow`` addition, or a re-include
   as ``allow`` of a definition the ratchet's ``approved`` set holds (E.1, T-2); a **kept allow**
   is a tool both policies classify ``allow`` whose pin the write changes and whose new
   definition ``suggested`` doesn't give as ``allow`` (Q8). From the portal (but a rollback,
   which rule 2 holds to no move at all), each move and kept allow needs its definition
   (``allow_needs_review``), and none of them, nor a new include as ``allow``, may be marked
   (``allow_marked``) or a toolkit's consequential tool (``consequential_allow``), so every
   per-move check runs again at confirm (Y8). 1b, from the portal: every pin the candidate
   adds or changes is one the review verified (``review_stale``, Y11, T-10), except a
   rollback's, which 1c checks. 1c: the ratchet's violations (E.2), before the direction rule, so
   a portal rollback that brings back a client or a caller is ``rollback_revives`` (verifier
   C1); then a ratchet past ``RATCHET_MAX`` is ``ratchet_full`` (E.1).
2. ``portal_widens`` (Y6, G-11): a portal write that changes a host field at all, adds a client,
   a token or a caller, or makes a change :func:`.diff.direction` calls wider that its kind doesn't
   permit (a rollback permits none).
4. ``generation_raise_from_portal``: a key rotation is the host's (I.2).
5. ``summary_too_large`` (Y9): a portal plan of more than :data:`SUMMARY_ROWS_MAX` rows, or one
   move or kept allow whose definition alone passes it.
6. ``no_change``: an empty diff, except the host's ``policy.acknowledge``, ``policy.resume``
   and ``policy.reseed``, whose revision is the point (F.3, F.4, J10, Y4).

The rows keep ``Plan.summary``'s label/value shape (MISS-6) in G.7's order: the revision; the
weakenings, the moves and kept allows first, each followed by its definition, one row per chunk of
every line (``reviewchange.definition_lines``), nothing cut, the first naming the pin it allows
(J3); every other change; the restarts (I.2), or that none is needed; the secrets whose binding
stops matching (D-10); the fields kept from the head (H.4) and the host's grants; the store
entries left unused (Q13). A value names policy names, pins, limits and definition chunks only,
never a hidden field's value (Y13); the portal passes each through ``display.shown`` as
``Plan.summary`` requires, which cuts no chunk (G.7). The plan is deterministic over its input,
so a re-plan at confirm compares equal unless something it read moved (Y8).

:func:`normalize` is what a revision holds (D.5): every literal client token as its
``token_sha256``, the round trip ``change.apply`` relies on. :func:`carry_forward` builds a
rollback's candidate from its target (H.4).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Literal

from ..canonical import digest
from ..suggest import Suggestion
from . import diff
from .change import CONNECTOR_LIMITS
from .diff import Change
from .ratchet import DefKey, Grants, Ratchet, Violation, advance, full, violations
from .restart import Effect, Started, classify
from .reviewchange import Lines
from .schema import Policy, ToolkitServer

WriteKind = Literal[
    "policy.save",
    "tool.repin",
    "tool.allow",
    "client.servers",
    "connector.limits",
    "policy.rollback",
    "policy.import",
    "policy.seed",
    "policy.resume",
    "policy.reseed",
    "policy.acknowledge",
]
# host: the vault's own start acting on the host's source (a resume, F.4).
Surface = Literal["portal", "socket", "offline", "host"]
# health.judge's verdict on a stored secret's binding where the policy uses it (D-10).
BindingState = Literal["ok", "changed", "wider"]
Reason = Literal[
    "kind_mismatch",
    "allow_needs_review",
    "allow_marked",
    "consequential_allow",
    "review_stale",
    "generation_lowered",
    "pin_retired",
    "rollback_revives",
    "revives_client",
    "revives_caller",
    "env_name_new",
    "env_reach_grows",
    "ratchet_full",
    "portal_widens",
    "generation_raise_from_portal",
    "summary_too_large",
    "no_change",
]
# The socket's names for what the portal answers as rollback_revives (N.2, verifier C1).
HOST_ONLY: Final = frozenset({"revives_client", "revives_caller"})
# The most rows a portal plan shows, every chunk row of every definition counted (N.4, Y9).
SUMMARY_ROWS_MAX: Final = 400
# The kinds a surface's own command writes, which no diff decides (G.2).
COMMANDS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "portal": frozenset({"policy.rollback"}),
        "socket": frozenset({"policy.rollback", "policy.import", "policy.acknowledge"}),
        "offline": frozenset(
            {
                "policy.rollback",
                "policy.import",
                "policy.seed",
                "policy.reseed",
                "policy.acknowledge",
            }
        ),
        "host": frozenset({"policy.resume", "policy.seed"}),
    }
)
# The host's way for what the portal can't do (G.5 rules 2 and 5).
HOST_NEXT: Final = "zoeymcp policy export, edit, zoeymcp policy import"
# Fields no portal write changes at all (G.5 rule 2 (a), I.1), at the top and under gateway.
_HOST_FIELDS: Final = frozenset({"admin", "egress_proxy", "egress_proxy_kind", "egress_proxy_acls"})
_HOST_GATEWAY: Final = frozenset({"approvals", "limits", "hosts", "origins"})
_SERVER_MODELS: Final = frozenset({"RemoteServer", "ToolkitServer"})
# A server's prompts and its resource sets, each pinned and declined as its tools are (L.1); the
# kind of definition a change under each block is about, a tool's elsewhere.
_KIND_MODELS: Final = frozenset({"PromptsPolicy", "ResourceSet"})
_BLOCK_KINDS: Final[Mapping[str, str]] = MappingProxyType(
    {"prompts": "prompt", "templates": "resource_template", "fixed": "resource"}
)
_GENERATIONS: Final = ("gateway_key_generation", "egress_key_generation")
# G.7's fixed sentences.
MOVE_TEXT: Final = "approve -> allow. Calls to {name} will run with no prompt."
REINCLUDE_TEXT: Final = "{name} was approve in an earlier revision: calls will run with no prompt"
KEPT_ALLOW_TEXT: Final = (
    "{name}'s new definition isn't marked read-only and stays allow: calls will run with no prompt"
)
NEW_ALLOW_TEXT: Final = "{name} will run with no prompt"
CLIENT_TEXT: Final = (
    "agents holding client {client}'s token can call {server}'s {count} included tools"
)
UNPAUSED_TEXT: Final = "sends can go out again"
PINNING_OFF_TEXT: Final = (
    "pinning is off for {server}: the image can change this definition with no review"
)
DECLINED_TEXT: Final = "{name}: declined in revision {revision}, included again"
REPINNED_TEXT: Final = "{old} -> {new} (re-pinned: you read both definitions)"
BREAK_TEXT: Final = (
    "{name}: its stored secret is bound to what the policy used before; set it again after the "
    "save (binding_changed)"
)
# The effects a restart takes; the rest take a redeploy (I.2, G.7 row 4).
_RESTARTS: Final = frozenset({"vault_restart", "gateway_restart"})
# G.7 row 4 when a change takes no effect (J3, J7).
NO_RESTART: Final = ("No restart needed", "")
# The host's kinds whose revision is the point, a change or none (rule 6; F.3, F.4, K.3).
ALWAYS_WRITTEN: Final = frozenset({"policy.acknowledge", "policy.resume", "policy.reseed"})


def _unknown(subject: str) -> int | None:
    return None


@dataclass(frozen=True)
class PlanInput:
    kind: WriteKind  # as prepared; must equal the required kind (rule 1)
    surface: Surface
    head: Policy
    head_revision: int
    head_digest: str
    ratchet: Ratchet
    candidate: Policy  # admitted by the gate
    started: Started  # the vault's startup egress pair, admin.listen and bridges (I.2)
    # Every stored secret the policy uses, and its binding's verdict (D-10's preview, from the
    # vault's bindings and health.judge).
    bindings: Callable[[Policy], Mapping[str, BindingState]]
    verified: frozenset[tuple[DefKey, str]] = frozenset()  # pins the write's review verified
    drifted: frozenset[DefKey] = frozenset()  # tools that review showed drifted (tool.repin)
    # For every DefKey the candidate classifies allow at a (classification, pin) the head doesn't
    # hold: the lines of the definition at the pin the write sets (the listed one with pinning
    # off), from the verified report (J.3, J.4); the moves and kept allows use theirs.
    definitions: Mapping[DefKey, Lines] = field(default_factory=dict)
    # The shared rule's suggestion for each re-pinned DefKey's new definition (Q8).
    suggested: Mapping[DefKey, Suggestion | None] = field(default_factory=dict)
    marked: frozenset[DefKey] = frozenset()  # marked in the gateway's status or the report
    consequential: frozenset[DefKey] = frozenset()  # a toolkit's consequential tools
    grants: Grants = field(default_factory=Grants)  # always empty from the portal
    # The policy the candidate was carried forward from (a rollback's target, which it needs,
    # H.4; on the host also an import's document, H.5), and its revision when it has one: the
    # plan's "Kept" rows and its refusals name them.
    target: Policy | None = None
    target_revision: int | None = None
    # The revision that removed a retired client, caller or pin, by its grant subject
    # ("client:<name>"), from the store's history (the ratchet keeps no revision number, E.1).
    removed_in: Callable[[str], int | None] = _unknown


@dataclass(frozen=True)
class WritePlan:
    kind: WriteKind  # the required kind
    base: int
    base_digest: str
    changes: tuple[Change, ...]  # structured, by field path (H.2)
    effects: tuple[Effect, ...]  # I.2
    breaks: tuple[str, ...]  # stored secrets that go from fine to binding_changed (D-10)
    kept: tuple[str, ...]  # fields carried from the head (H.4), by path
    unused_slots: tuple[str, ...]  # stored secrets the candidate no longer uses (Q13)
    moves: tuple[DefKey, ...]  # moves to allow (rule 1), each logged tool_allowed (G.6)
    kept_allow: tuple[DefKey, ...]  # kept allows (Q8), each logged tool_allowed kept=true
    ratchet: Ratchet = field(repr=False)  # after this write
    rows: tuple[tuple[str, str], ...]  # the summary the operator confirms (G.7)
    policy: Policy = field(repr=False)  # the candidate as the revision holds it (D.5)


@dataclass(frozen=True)
class PlanRefused:
    """The first rule a write breaks. ``detail`` is what the refusal's sentence names
    (``portal/refusals.py``'s ``{detail}``); ``subjects`` the paths, definitions, kinds or grant
    subjects it is about; ``next`` the host's way, where there is one."""

    reason: Reason
    detail: str = ""
    subjects: tuple[str, ...] = ()
    next: str | None = None


# --- what a revision holds (D.5) ---------------------------------------------------------------


def normalize(policy: Policy) -> Policy:
    """The policy as a revision holds it: every client's literal ``token`` as its
    ``token_sha256`` (the literal leaves the vault for good), then the round trip through the
    document form ``change.apply`` relies on (F-17). Placeholders, ``token_headers`` and forced
    query values stay as written: they have no hash form (D.4 is their protection)."""
    data = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    clients = {} if policy.gateway is None else policy.gateway.clients
    for name, client in clients.items():
        if client.token is not None:
            entry = data["gateway"]["clients"][name]
            del entry["token"]
            entry["token_sha256"] = client.token_hash
    return Policy.model_validate(data)


def document(policy: Policy) -> dict[str, Any]:
    """The plain form of :func:`normalize`'s policy: what a revision's body holds."""
    held: dict[str, Any] = normalize(policy).model_dump(
        mode="json", by_alias=True, exclude_defaults=True
    )
    return held


def normalized_digest(policy: Policy) -> str:
    """The digest of :func:`document`: what the start compares a source with (F.5,
    ``policystart.read_source``) and a retry with the head (G.6 step 2)."""
    return digest(document(policy))


# --- the carry-forward (H.4) -------------------------------------------------------------------


def carry_forward(head: Policy, target: Policy, *, host: bool = False) -> Policy:
    """A rollback's candidate: ``target``'s policy with, from ``head``, the two key generations
    (never lower, Y5), ``admin`` unless the rollback is the ``host``'s (Y17, T-6), and the pin of
    every definition the head pins (Y11, G-24); each server's ``declined`` is the head's and the
    target's less the tools the candidate includes (T-9, CR-17). The ratchet checks the result
    (G.5 rule 1c): a pin only the target holds may be a retired one (``pin_retired``)."""
    data = document(target)
    for name in _GENERATIONS:
        data[name] = getattr(head, name)
    if not host:
        data.pop("admin", None)
        if head.admin is not None:
            data["admin"] = head.admin.model_dump(mode="json", by_alias=True)
    held = {} if head.gateway is None else head.gateway.servers
    for name, entry in data.get("gateway", {}).get("servers", {}).items():
        before = held.get(name)
        review = entry.get("review", {})
        if before is not None:
            for tool in review:
                review[tool] = before.review.get(tool, review[tool])
        declined = {**entry.get("declined", {}), **({} if before is None else before.declined)}
        include = entry.get("tools", {}).get("include", [])
        entry["declined"] = {t: pin for t, pin in sorted(declined.items()) if t not in include}
    return normalize(Policy.model_validate(data))


# --- the kind (rule 1) -------------------------------------------------------------------------


def _key(change: Change) -> DefKey:
    """The definition a server's ``tools``, ``review`` or ``declined`` change is about, or one
    under its ``prompts`` or a ``resources.<set>`` (L.1): the name a list of names gains or
    loses, or the map's key."""
    path = change.path
    block = path[4] if path[3] == "resources" else path[3]
    named = (change.model, change.field) in diff.NAME_SETS
    name = _item(change) if named else path[-1]
    return (str(path[2]), _BLOCK_KINDS.get(str(block), "tool"), str(name))


def _item(change: Change) -> Any:
    """The name a change to a list of names adds or removes."""
    return change.new if change.op == "added" else change.old


def _named(changes: tuple[Change, ...], field_name: str, op: str) -> list[DefKey]:
    """The tools a ``tools.<field_name>`` change of ``op`` names, in the diff's order."""
    return [_key(c) for c in changes if c.model == "Tools" and c.field == field_name and c.op == op]


def _tools(policy: Policy, server: str) -> tuple[list[str], list[str]]:
    """A server's included and ``allow`` tools (none for a server the policy hasn't)."""
    entry = None if policy.gateway is None else policy.gateway.servers.get(server)
    return ([], []) if entry is None else (entry.tools.include, entry.tools.allow)


def _moves(changes: tuple[Change, ...], ratchet: Ratchet) -> tuple[list[DefKey], list[DefKey]]:
    """The moves to allow (rule 1), and which of them are re-includes: an ``allow`` addition
    whose ``approve`` removal is in the diff, or one of a definition in ``approved``."""
    removed = _named(changes, "approve", "removed")
    moves = [key for key in _named(changes, "allow", "added") if key in removed]
    reincludes = [
        key
        for key in _named(changes, "allow", "added")
        if key not in removed and key in ratchet.approved
    ]
    return moves + reincludes, reincludes


def _repin(change: Change, drifted: frozenset[DefKey], verified: frozenset[Any]) -> bool:
    """A drifted tool's pin changed to one the review verified (``tool.repin``)."""
    if change.model not in _SERVER_MODELS or change.field != "review" or change.op != "changed":
        return False
    key = _key(change)
    return key in drifted and (key, change.new) in verified


def _one(changes: tuple[Change, ...], model: str, fields: tuple[str, ...], at: int) -> bool:
    """Every change is to one of ``model``'s ``fields``, all under one name at ``path[at]``."""
    if any(c.model != model or c.field not in fields for c in changes):
        return False
    return len({c.path[at] for c in changes}) == 1


def required_kind(
    changes: tuple[Change, ...],
    head: Policy,
    ratchet: Ratchet,
    *,
    drifted: frozenset[DefKey] = frozenset(),
    verified: frozenset[tuple[DefKey, str]] = frozenset(),
) -> WriteKind:
    """The kind G.3's ops make, read from the diff (Y7, G-12): ``tool.allow`` for exactly one
    move of an included ``approve`` tool at the head's pin and nothing else; ``tool.repin`` for
    only re-pins of ``drifted`` tools, each to a ``verified`` pin; ``connector.limits`` for only
    one connector's pause and limits; ``client.servers`` for only one client's servers;
    ``policy.save`` for anything else, a lone re-include as ``allow`` included."""
    if not changes:
        return "policy.save"
    moves, reincludes = _moves(changes, ratchet)
    if len(changes) == 2 and len(moves) == 1 and not reincludes:
        server, _, name = moves[0]
        if name in _tools(head, server)[0]:
            return "tool.allow"
    if all(_repin(c, drifted, verified) for c in changes):
        return "tool.repin"
    if _one(changes, "SMTPConnector", CONNECTOR_LIMITS, 1):
        return "connector.limits"
    if _one(changes, "Client", ("servers",), 2):
        return "client.servers"
    return "policy.save"


# --- the portal's bound (rule 2) ---------------------------------------------------------------


def _dotted(path: tuple[str | int, ...]) -> str:
    return ".".join(str(part) for part in path)


def _permits(kind: str, change: Change) -> bool:
    """Whether ``kind`` permits a wider ``change`` (G.5 rule 2 (c)): a save, a review's includes
    (at verified pins, rule 1b), moves, declines, its learned era, and onboarding's credential,
    route, server and ``egress_private`` entry (a re-registration and a scope step-up change a
    credential, G.3); the others their one change; a rollback nothing."""
    path = change.path
    if kind == "policy.save":
        return (
            (change.model == "Tools" and change.field in ("include", "allow"))
            or (change.model in _SERVER_MODELS and change.field in ("declined", "era"))
            or (change.model in _KIND_MODELS and change.field in ("include", "declined"))
            or path[0] in ("credentials", "egress_private")
            or (path[0] == "routes" and len(path) == 2 and change.op == "added")
            or (path[:2] == ("gateway", "servers") and len(path) == 3 and change.op == "added")
        )
    if kind == "tool.allow":
        return change.model == "Tools" and change.field == "allow"
    if kind == "connector.limits":
        return change.model == "SMTPConnector" and change.field in CONNECTOR_LIMITS
    if kind == "client.servers":
        return change.model == "Client" and change.field == "servers"
    return False


def _widening(kind: str, change: Change) -> str | None:
    """What a portal write of ``kind`` may not do in ``change`` (G.5 rule 2), as its refusal
    says it, or None."""
    path, where = change.path, _dotted(change.path)
    if path[0] in _HOST_FIELDS or (path[0] == "gateway" and path[1:2] and path[1] in _HOST_GATEWAY):
        return f"change {where}"
    if path[0] == "connectors" and len(path) > 2 and path[2] not in CONNECTOR_LIMITS:
        return f"change {where}"  # a bound constraint (F-15, COV-1)
    if path[:2] == ("gateway", "clients") and len(path) == 3 and change.op == "added":
        return f"add a client ({where})"
    if change.model == "Client" and change.field in ("token", "token_sha256"):
        return f"change the token of client {path[2]}"
    route = change.model == "Route" and change.field == "callers" and change.op != "removed"
    if route or (
        path[0] == "routes"
        and len(path) == 2
        and change.op == "added"
        and change.new["callers"] != ["gateway"]
    ):
        return f"add a caller to route {path[1]}"
    if diff.direction(change) == "wider" and not _permits(kind, change):
        return f"widen {where}" + (" through a rollback" if kind == "policy.rollback" else "")
    return None


# --- the plan ----------------------------------------------------------------------------------


def _names(keys: list[DefKey]) -> str:
    return ", ".join(f"{server}.{name}" for server, _, name in keys)


def _subjects(keys: list[DefKey]) -> tuple[str, ...]:
    return tuple("/".join(key) for key in keys)


def _pins_added(changes: tuple[Change, ...]) -> list[tuple[DefKey, str]]:
    """Every pin the candidate adds or changes, of every kind (a tool's, a prompt's, a
    template's or a fixed resource's, G.5 rule 1b): a ``review`` entry, or one of a server
    added."""
    found = [
        (_key(c), c.new)
        for c in changes
        if c.model in _SERVER_MODELS | _KIND_MODELS and c.field == "review" and c.op != "removed"
    ]
    for c in changes:
        if c.path[:2] == ("gateway", "servers") and len(c.path) == 3 and c.op == "added":
            server = str(c.path[2])
            resources = c.new.get("resources", {})
            for kind, block in (
                ("tool", c.new),
                ("prompt", c.new.get("prompts", {})),
                ("resource_template", resources.get("templates", {})),
                ("resource", resources.get("fixed", {})),
            ):
                pins = block.get("review", {})
                found += [((server, kind, name), pin) for name, pin in sorted(pins.items())]
    return found


def _refused(violation: list[Violation], i: PlanInput) -> PlanRefused:
    """Rule 1c's refusal for the violations of the first one's reason (E.2, N.2)."""
    first = violation[0]
    same = [v for v in violation if v.reason == first.reason]
    subjects = tuple(v.subject for v in same)
    if first.reason == "generation_lowered":
        return PlanRefused(
            "generation_lowered", f"{first.subject} can't go below {first.floor}", subjects
        )
    if first.reason == "pin_retired":
        # A server's name and a kind hold no "/"; a resource's name (a URI, L.2) may.
        found = [subject.removeprefix("pin:").split("/", 2) for subject in subjects]
        detail = ", ".join(f"{server}'s {kind} {name}" for server, kind, name in found)
        return PlanRefused("pin_retired", detail, subjects)
    if first.reason in ("env_name_new", "env_reach_grows"):
        said = [
            f"{v.subject} is new"
            if v.reason == "env_name_new"
            else f"{v.subject} would also be sent to {', '.join(v.origins)}"
            for v in same
        ]
        return PlanRefused(first.reason, "; env:".join(said), subjects)
    # revives_client, revives_caller: the portal answers both as rollback_revives (rule 1c).
    revived = [v for v in violation if v.reason in HOST_ONLY]
    items = []
    for v in revived:
        what, name = v.subject.split(":", 1)
        removed = i.removed_in(v.subject)
        items.append(
            f"{what} {name}" + ("" if removed is None else f", removed in revision {removed}")
        )
    grants = tuple(v.subject for v in revived)
    if i.surface != "portal":
        return PlanRefused(first.reason, "; ".join(items), grants)
    target = "the target" if i.target_revision is None else f"revision {i.target_revision}"
    return PlanRefused("rollback_revives", f"{target} brings back {'; '.join(items)}", grants)


def _definition(name: str, pin: str | None, lines: Lines) -> list[tuple[str, str]]:
    """A definition's rows: one per chunk of every line, nothing cut, the first naming the pin
    (none with pinning off) the write allows (G.7 row 2, J3)."""
    rows = [
        (f"{name}, as pinned" if index == 0 else f"{name}, continued", chunk)
        for chunks in lines
        for index, chunk in enumerate(chunks)
    ]
    if rows and pin is not None:
        rows[0] = (f"{name}, as pinned ({pin})", rows[0][1])
    return rows


def _pin(policy: Policy, key: DefKey) -> str | None:
    """The pin ``policy`` holds for ``key``, if any."""
    server, _, name = key
    entry = None if policy.gateway is None else policy.gateway.servers.get(server)
    return None if entry is None else entry.review.get(name)


def _pinning_off(policy: Policy, server: str) -> bool:
    entry = None if policy.gateway is None else policy.gateway.servers.get(server)
    return isinstance(entry, ToolkitServer) and entry.pinning == "off"


def _said(change: Change) -> str:
    """A change's op, naming the name a list of names gains or loses."""
    if (change.model, change.field) in diff.NAME_SETS:
        return f"{_item(change)} {change.op}"
    return change.op


def _weakening(change: Change, i: PlanInput, candidate: Policy) -> str:
    """A wider change's sentence (G.7 row 2)."""
    if change.model == "Tools" and change.field == "allow":
        return NEW_ALLOW_TEXT.format(name=change.new)
    if change.model == "Client" and change.field == "servers":
        include = _tools(candidate, change.new)[0]
        client = change.path[2]
        return CLIENT_TEXT.format(client=client, server=change.new, count=len(include))
    if change.model == "SMTPConnector" and change.field == "paused":
        return UNPAUSED_TEXT
    if change.model == "SMTPConnector" and change.field in CONNECTOR_LIMITS:
        return f"{change.old} -> {change.new}: raised"
    if change.model in _SERVER_MODELS and change.field == "declined":
        server, _, name = _key(change)
        if name in _tools(candidate, server)[0]:
            return DECLINED_TEXT.format(name=name, revision=i.head_revision)
    return f"{_said(change)} (wider)"


def _other(change: Change, i: PlanInput) -> str:
    """Any other change's value (G.7 row 3): a re-pin, of any kind, shows both pins."""
    pinned = change.model in _SERVER_MODELS | _KIND_MODELS
    if pinned and change.field == "review" and change.op == "changed":
        if (_key(change), change.new) in i.verified:
            return REPINNED_TEXT.format(old=change.old, new=change.new)
        return f"{change.old} -> {change.new}"
    return _said(change)


def _rows(
    i: PlanInput,
    parts: dict[str, Any],
    candidate: Policy,
    reincludes: list[DefKey],
    granted: list[Violation],
) -> list[tuple[str, str]]:
    """G.7's rows, in order."""
    head = i.head_revision
    revision = f"{head + 1}, from {head}"
    if i.target_revision is not None:
        revision += f": the content of revision {i.target_revision}"
    rows = [("Revision", revision)]
    for key in (*parts["moves"], *parts["kept_allow"]):
        server, _, name = key
        if key in reincludes:
            sentence = REINCLUDE_TEXT.format(name=name)
        elif key in parts["moves"]:
            sentence = MOVE_TEXT.format(name=name)
        else:
            sentence = KEPT_ALLOW_TEXT.format(name=name)
        rows.append((f"{server}.{name}", sentence))
        rows += _definition(name, _pin(candidate, key), i.definitions.get(key, ()))
        if _pinning_off(candidate, server):
            rows.append((server, PINNING_OFF_TEXT.format(server=server)))
    moved = [
        c
        for c in parts["changes"]
        if c.model == "Tools" and c.field == "allow" and _key(c) in parts["moves"]
    ]
    wider = [c for c in parts["changes"] if diff.direction(c) == "wider" and c not in moved]
    rows += [(_dotted(c.path), _weakening(c, i, candidate)) for c in wider]
    rows += [
        (_dotted(c.path), _other(c, i))
        for c in parts["changes"]
        if c not in wider and c not in moved
    ]
    for effect in parts["effects"]:
        label = "Restart needed" if effect.kind in _RESTARTS else "Redeploy needed"
        rows.append((label, f"{effect.path}: {effect.text}"))
    if parts["changes"] and not parts["effects"]:
        rows.append(NO_RESTART)
    rows += [("Stops matching", BREAK_TEXT.format(name=name)) for name in parts["breaks"]]
    rows += [(f"Kept from revision {head}", path) for path in parts["kept"]]
    rows += [("Granted by the host", f"{v.reason}: {v.subject}") for v in granted]
    rows += [("Left unused", name) for name in parts["unused_slots"]]
    return rows


def _carried(i: PlanInput, candidate: Policy) -> bool:
    """Whether ``candidate`` is the carry-forward of the write's target, a host's rollback
    taking the target's ``admin`` (H.4)."""
    if i.target is None:
        return False
    carried = carry_forward(i.head, i.target, host=i.surface != "portal")
    return document(carried) == document(candidate)


def plan(i: PlanInput) -> WritePlan | PlanRefused:
    """The write ``i`` describes, planned against the head and its ratchet, or the first rule it
    breaks (the module docstring's order)."""
    head, candidate = normalize(i.head), normalize(i.candidate)
    portal = i.surface == "portal"
    changes = diff.structured(head, candidate)
    paths = [_dotted(c.path) for c in changes]
    # Rule 1: the kind is its diff; a rollback's, its target's carry-forward (H.4, Y11).
    required: WriteKind = i.kind
    if i.kind == "policy.rollback" and not _carried(i, candidate):
        required = required_kind(changes, head, i.ratchet, drifted=i.drifted, verified=i.verified)
    elif portal and i.target is not None:
        required = "policy.rollback"
    elif i.kind not in COMMANDS[i.surface]:
        required = required_kind(changes, head, i.ratchet, drifted=i.drifted, verified=i.verified)
    if required != i.kind:
        said = ", ".join(paths) or "nothing"
        return PlanRefused("kind_mismatch", f"{required}, not {i.kind}: {said}", (required, i.kind))
    moves, reincludes = _moves(changes, i.ratchet)
    kept_allow = [
        _key(c)
        for c in changes
        if c.model in _SERVER_MODELS
        and c.field == "review"
        and c.op == "changed"
        and c.path[4] in _tools(head, str(c.path[2]))[1]
        and c.path[4] in _tools(candidate, str(c.path[2]))[1]
        and i.suggested.get(_key(c)) != "allow"
    ]
    # A portal rollback permits no move (rule 2 says so); every other portal write shows each.
    if portal and required != "policy.rollback":
        shown = moves + kept_allow
        allows = shown + [key for key in _named(changes, "allow", "added") if key not in moves]
        checks: tuple[tuple[Reason, list[DefKey]], ...] = (
            ("allow_needs_review", [key for key in shown if key not in i.definitions]),
            ("allow_marked", [key for key in allows if key in i.marked]),
            ("consequential_allow", [key for key in allows if key in i.consequential]),
        )
        for reason, keys in checks:
            if keys:
                return PlanRefused(reason, _names(keys), _subjects(keys))
    # Rule 1b: every pin the portal adds or changes is one the review verified.
    if portal and required != "policy.rollback":
        stale = [key for key, pin in _pins_added(changes) if (key, pin) not in i.verified]
        if stale:
            return PlanRefused("review_stale", _names(stale), _subjects(stale))
    # Rule 1c: the ratchet's violations, then its bound.
    grants = Grants() if portal else i.grants
    found = violations(i.ratchet, head, candidate, verified=i.verified, grants=grants)
    if found:
        return _refused(list(found), i)
    ratchet = advance(i.ratchet, head, candidate, verified=i.verified)
    if full(ratchet):
        return PlanRefused("ratchet_full")
    # Rule 2: what the portal may widen.
    if portal:
        widens = [(c, _widening(required, c)) for c in changes]
        refused = [(c, said) for c, said in widens if said is not None]
        if refused:
            subjects = tuple(_dotted(c.path) for c, _ in refused)
            return PlanRefused("portal_widens", refused[0][1], subjects, HOST_NEXT)
    # Rule 4: a key rotation is the host's.
    if portal:
        raised = [name for name in _GENERATIONS if getattr(candidate, name) > getattr(head, name)]
        if raised:
            return PlanRefused("generation_raise_from_portal", raised[0], tuple(raised))
    before, after = i.bindings(head), i.bindings(candidate)
    kept: tuple[str, ...] = ()
    if i.target is not None:
        kept = tuple(_dotted(c.path) for c in diff.structured(normalize(i.target), candidate))
    # What the host's grants let through (the portal has none): each its own row (G.7 row 6).
    granted = (
        ()
        if portal
        else violations(i.ratchet, head, candidate, verified=i.verified, grants=Grants())
    )
    parts: dict[str, Any] = {
        "changes": changes,
        "effects": classify(head, candidate, i.started),
        "breaks": tuple(
            sorted(
                n
                for n, s in after.items()
                if s == "changed" and before.get(n, "changed") != "changed"
            )
        ),
        "kept": kept,
        "unused_slots": tuple(sorted(set(before) - set(after))),
        "moves": tuple(moves),
        "kept_allow": tuple(kept_allow),
    }
    rows = _rows(i, parts, candidate, reincludes, list(granted))
    # Rule 5: what one portal dialog can show.
    if portal:
        long = [
            key
            for key in moves + kept_allow
            if _count(i.definitions.get(key, ())) > SUMMARY_ROWS_MAX
        ]
        if long:
            name = long[0][2]
            detail = (
                f"{name}'s definition has more than {SUMMARY_ROWS_MAX} lines: make this move on "
                "the host"
            )
            return PlanRefused("summary_too_large", detail, _subjects(long), HOST_NEXT)
        if len(rows) > SUMMARY_ROWS_MAX:
            detail = (
                f"it has more than {SUMMARY_ROWS_MAX} lines: save fewer moves to allow at once, "
                "or make it on the host"
            )
            return PlanRefused("summary_too_large", detail, (), HOST_NEXT)
    # Rule 6: no revision for nothing.
    if not changes and required not in ALWAYS_WRITTEN:
        return PlanRefused("no_change")
    return WritePlan(
        kind=required,
        base=i.head_revision,
        base_digest=i.head_digest,
        ratchet=ratchet,
        rows=tuple(rows),
        policy=candidate,
        **parts,
    )


def _count(lines: Lines) -> int:
    return sum(len(chunks) for chunks in lines)
