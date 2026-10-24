"""The structured diff between two policies, and the direction of each change (M6 design H.2;
DD-10, G-11; T-1, T-2, CR-4). Pure, mutation-tested.

:func:`structured` walks two policies (as ``normalize`` writes them, D.5) field by field, with
every default filled in, and names each difference as a :class:`Change` by its path: a mapping by
key, ``routes`` by name, the lists of models a route or a toolkit slot holds (callers, rules) by
position, a list of names (:data:`NAME_SETS`) as a set, one change per name added or removed, and
any other list whole. A change carries plain JSON values and the schema model and field it is
under, as ``portal/policyview.py``'s ``FIELDS`` names them. Diffs are recomputed from adjacent
revisions, never stored.

:func:`direction` says whether a change makes the policy **wider**, **narrower** or **neutral**:
the classifier of the planner's rule 2 and of the summary's weakenings-first order (G.5, G.7). It
is exhaustive and default-aware: :data:`DIRECTIONS` names every field of every schema model (a
test walks the schema), each value compared is the field's with its default filled in, so a
removal is the change to the default, and a change the table can't classify is wider, so an
unclassified field fails closed. "Every removal is narrower" is not a rule: where an empty or
absent value means "any" (a client's or a caller's ``sources``, ``query.allow``), going back to
it is wider. A tool moved from ``approve`` to ``allow`` is wider by its ``allow`` addition, and so
is a re-include as ``allow`` of a definition the ratchet's ``approved`` set holds (T-2); the
planner, which holds the ratchet, also names it a move.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from pydantic import BaseModel

from .schema import Policy

Op = Literal["added", "removed", "changed"]
Direction = Literal["wider", "narrower", "neutral"]
Rule = Callable[[Op, Any, Any], Direction]

# Lists of names, compared as sets: one change per name added or removed.
NAME_SETS: Final = frozenset(
    {
        ("Tools", "include"),
        ("Tools", "allow"),
        ("Tools", "approve"),
        ("Client", "servers"),
        ("RemoteServer", "enable"),
    }
)
# Lists of models, compared by position (``routes`` is compared by name).
BY_INDEX: Final = frozenset({("Route", "callers"), ("Route", "rules"), ("ToolkitSlot", "rules")})


@dataclass(frozen=True)
class Change:
    path: tuple[str | int, ...]  # field names as the document writes them, keys, route names
    op: Op
    old: Any  # plain JSON values; None for an addition
    new: Any  # None for a removal
    model: str  # the schema model and field the change is under, as policyview.FIELDS names them
    field: str


def structured(old: Policy, new: Policy) -> tuple[Change, ...]:
    """Every difference from ``old`` to ``new``, in the schema's field order, keys sorted."""
    found: list[Change] = []
    _model(old, new, (), found)
    return tuple(found)


def direction(change: Change) -> Direction:
    """The change's direction by :data:`DIRECTIONS`; one the table doesn't name is wider."""
    rule = DIRECTIONS.get(change.model, {}).get(change.field, _wider)
    return rule(change.op, change.old, change.new)


def _model(
    old: BaseModel, new: BaseModel, path: tuple[str | int, ...], found: list[Change]
) -> None:
    owner = type(old).__name__
    for name, info in type(old).model_fields.items():
        where = (*path, info.alias or name)
        _value(owner, name, where, getattr(old, name), getattr(new, name), found)


def _value(
    owner: str, name: str, path: tuple[str | int, ...], old: Any, new: Any, found: list[Change]
) -> None:
    if old == new:
        return
    if isinstance(old, BaseModel) and type(new) is type(old):
        _model(old, new, path, found)
        return
    if (owner, name) in NAME_SETS:
        removed, added = sorted(set(old) - set(new)), sorted(set(new) - set(old))
        found.extend(Change(path, "removed", item, None, owner, name) for item in removed)
        found.extend(Change(path, "added", None, item, owner, name) for item in added)
        return
    if isinstance(old, list):  # the list itself, not one of its items
        if (owner, name) == ("Policy", "routes"):
            old, new = {route.name: route for route in old}, {route.name: route for route in new}
        elif (owner, name) in BY_INDEX:
            old, new = dict(enumerate(old)), dict(enumerate(new))
    if isinstance(old, Mapping):
        for key in sorted(old.keys() | new.keys()):
            where = (*path, key)
            if key not in new:
                found.append(Change(where, "removed", _plain(old[key]), None, owner, name))
            elif key not in old:
                found.append(Change(where, "added", None, _plain(new[key]), owner, name))
            else:
                _value(owner, name, where, old[key], new[key], found)
        return
    found.append(Change(path, "changed", _plain(old), _plain(new), owner, name))


def _plain(value: Any) -> Any:
    """A model as the document writes it, defaults filled in; any other value is plain already
    (a mapping or a list of models is walked, never carried whole)."""
    return value.model_dump(mode="json", by_alias=True) if isinstance(value, BaseModel) else value


# --- the rules ---------------------------------------------------------------------------------


def _wider(op: Op, old: Any, new: Any) -> Direction:
    """Any change: one the table can't call narrower (a credential's or an egress field's)."""
    return "wider"


# A model the diff walks into, field by field: it never changes as a whole.
_into: Final[Rule] = _wider


def _neutral(op: Op, old: Any, new: Any) -> Direction:
    return "neutral"


def _entry(op: Op, old: Any, new: Any) -> Direction:
    """A whole entry: one added (or replaced by another kind) is wider, one removed narrower,
    since nothing then reaches it."""
    return "narrower" if op == "removed" else "wider"


def _name(op: Op, old: Any, new: Any) -> Direction:
    """A name in a set: added is wider, removed narrower."""
    return "wider" if op == "added" else "narrower"


def _optional(op: Op, old: Any, new: Any) -> Direction:
    """A block whose absence turns its feature off (``admin``, ``gateway``, a client's
    ``approvals``)."""
    return "narrower" if new is None else "wider"


def _raised(op: Op, old: Any, new: Any) -> Direction:
    """A limit: higher is wider, and none (``None``) is the highest."""
    if new is None or (old is not None and new > old):
        return "wider"
    return "narrower"


def _lowered(op: Op, old: Any, new: Any) -> Direction:
    """A limit whose lower value is wider (a cooldown)."""
    return "wider" if new < old else "narrower"


def _generation(op: Op, old: Any, new: Any) -> Direction:
    """A key generation: a raise retires a key; a lower one would bring one back (refused)."""
    return "narrower" if new > old else "wider"


def _to_true(op: Op, old: Any, new: Any) -> Direction:
    return "wider" if new else "narrower"


def _to_false(op: Op, old: Any, new: Any) -> Direction:
    return "narrower" if new else "wider"


def _to_hide(op: Op, old: Any, new: Any) -> Direction:
    """``on_drift``: ``hide`` is the wider (a drifted tool goes on being listed, unmarked)."""
    return "wider" if new == "hide" else "narrower"


def _to_off(op: Op, old: Any, new: Any) -> Direction:
    """``pinning``: ``off`` is the wider."""
    return "wider" if new == "off" else "narrower"


def _grows(op: Op, old: Any, new: Any) -> Direction:
    """A list read as what is allowed: an entry added is wider, only removals narrower, and a
    reordering neutral."""
    if set(new) - set(old):
        return "wider"
    return "narrower" if set(old) - set(new) else "neutral"


def _shrinks(op: Op, old: Any, new: Any) -> Direction:
    """A list read as what is taken away (``query.strip``): an entry removed is wider."""
    if set(old) - set(new):
        return "wider"
    return "narrower" if set(new) - set(old) else "neutral"


def _any_when_empty(op: Op, old: Any, new: Any) -> Direction:
    """An allowlist where ``[]`` means any (a client's or a caller's ``sources``)."""
    if not new:
        return "wider"
    return "narrower" if not old else _grows(op, old, new)


def _any_when_none(op: Op, old: Any, new: Any) -> Direction:
    """An allowlist where ``None`` means any (``query.allow``)."""
    if new is None:
        return "wider"
    return "narrower" if old is None else _grows(op, old, new)


def _declined(op: Op, old: Any, new: Any) -> Direction:
    """A decline: removed is wider (the tool counts as unreviewed again); added or moved to the
    pin listed now is neutral."""
    return "wider" if op == "removed" else "neutral"


def _params(op: Op, old: Any, new: Any) -> Direction:
    """A ``Rule.params`` constraint: added is narrower, removed wider; a list of values loosened
    by a value added; a regex changed can't be compared."""
    if op != "changed":
        return "narrower" if op == "added" else "wider"
    if isinstance(old, list) and isinstance(new, list):
        return _grows(op, old, new)
    return "wider"


_UPSTREAM: Final[Mapping[str, Rule]] = MappingProxyType(
    {
        "tools": _into,
        "review": _neutral,  # a re-pin: Y11 governs it
        "declined": _declined,
        "on_drift": _to_hide,
        "shared_session": _to_true,
        "wrap_results": _to_false,
        "enable": _name,
        "era": _wider,
        "drift_check_interval": _neutral,
        "call_timeout": _raised,
    }
)
# Every field of every model in common/policy/schema.py, by the model's class name: the field's
# rule over its plain values with defaults filled in (H.2's table). Built from plain statements:
# no rule is made at import time, so every rule's mutants run under the tests (mutmut).
_RULES: Final[dict[str, Mapping[str, Rule]]] = {
    "HeaderCredential": dict.fromkeys(("kind", "secret", "header", "format"), _wider),
    "QueryCredential": dict.fromkeys(("kind", "param", "secret"), _wider),
    "PathCredential": dict.fromkeys(("kind", "template", "secret"), _wider),
    "BasicCredential": dict.fromkeys(("kind", "username", "secret"), _wider),
    "OAuth2Credential": dict.fromkeys(
        (
            "kind",
            "token_url",
            "grant",
            "client_id",
            "client_secret",
            "client_auth",
            "refresh_token",
            "rotates",
            "reseed",
            "extra_params",
            "token_body",
            "token_headers",
            "scope_separator",
            "scope",
            "expected_scopes",
            "refresh_skew",
            "default_expires_in",
            "grant_lifetime_days",
            "idle_expiry_days",
            "authorize_url",
            "authorize_params",
            "redirect_uri",
            "issuer",
            "require_iss",
            "revocation_url",
            "resource_metadata",
        ),
        _wider,
    ),
    "SMTPConnector": {
        **dict.fromkeys(("kind", "host", "port", "tls", "username", "password", "from_"), _wider),
        "to": _grows,
        "max_per_day": _raised,
        "max_subject_chars": _raised,
        "max_body_chars": _raised,
        "paused": _to_false,
    },
    "PlaceholderCaller": {
        **dict.fromkeys(("placeholder", "header", "query"), _wider),
        "sources": _any_when_empty,
    },
    "RegexParam": {"regex": _wider},
    "Rule": {"methods": _grows, "paths": _grows, "params": _params},
    "QueryPolicy": {
        "force": _wider,
        "strip": _shrinks,
        "allow": _any_when_none,
    },
    "Route": {
        **dict.fromkeys(
            ("name", "prefix", "upstream", "credential", "connector", "stream", "program"),
            _wider,
        ),
        "callers": _entry,
        "query": _into,
        "rules": _entry,
        "allow_insecure_upstream": _to_true,
    },
    "RouteProgram": {
        "holds_secret": _wider,
        "egress": _grows,
        "egress_private": _grows,
    },
    "ClientApprovals": {
        "renders": _wider,
        "attended": _to_true,
        "timeout": _raised,
        "budget_chars": _raised,
        "confirm_code": _to_false,
    },
    "Client": {
        **dict.fromkeys(("token", "token_sha256"), _wider),
        "servers": _name,
        "sources": _any_when_empty,
        "approvals": _optional,
    },
    "Approvals": {
        "approver": _wider,
        "timeout": _raised,
        "budget_chars": _raised,
        "cooldown": _lowered,
        "max_pending_per_client": _raised,
        "max_prompts_per_hour": _raised,
    },
    "Tools": {"include": _name, "allow": _name, "approve": _neutral},
    "_UpstreamServer": _UPSTREAM,
    "RemoteServer": {**dict.fromkeys(("kind", "route", "path"), _wider), **_UPSTREAM},
    "ToolkitRule": {"methods": _grows, "paths": _grows, "approved": _to_true},
    "ToolkitSlot": {"route": _wider, "rules": _entry},
    "ToolkitServer": {
        **dict.fromkeys(("kind", "module"), _wider),
        "tools": _into,
        "pinning": _to_off,
        "review": _neutral,
        "declined": _declined,
        "on_drift": _to_hide,
        "slots": _entry,
        "wrap_results": _to_false,
        "call_timeout": _raised,
    },
    "GatewayLimits": {
        "max_request_bytes": _raised,
        "max_argument_bytes": _raised,
        "max_result_bytes": _raised,
        "max_upstream_message_bytes": _raised,
        "max_concurrent_per_client": _raised,
        "max_streams_per_client": _raised,
        "max_sessions_per_client": _raised,
        "max_upstream_sessions": _raised,
        "session_idle_timeout": _raised,
        "upstream_idle_timeout": _raised,
        "call_timeout": _raised,
        "list_timeout": _raised,
        "max_list_pages": _raised,
        "max_tools_per_server": _raised,
        "max_list_bytes": _raised,
        "max_schema_bytes": _raised,
        "max_schema_depth": _raised,
        "max_subschemas": _raised,
        "policy_max_stale": _raised,
        "ledger_max_bytes": _raised,
    },
    "Gateway": {
        "clients": _entry,
        "approvals": _into,
        "servers": _entry,
        "hosts": _grows,
        "origins": _grows,
        "limits": _into,
    },
    "Admin": dict.fromkeys(("listen", "origins"), _wider),
    "Policy": {
        **dict.fromkeys(
            ("version", "mode", "egress_proxy", "egress_proxy_kind", "egress_proxy_acls"),
            _wider,
        ),
        "egress_private": _grows,
        "egress_key_generation": _generation,
        "gateway_key_generation": _generation,
        "admin": _optional,
        "credentials": _entry,
        "connectors": _entry,
        "routes": _entry,
        "gateway": _optional,
    },
}
DIRECTIONS: Final[Mapping[str, Mapping[str, Rule]]] = MappingProxyType(
    {model: MappingProxyType(dict(rules)) for model, rules in _RULES.items()}
)
