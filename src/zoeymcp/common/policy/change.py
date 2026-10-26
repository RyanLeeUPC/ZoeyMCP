"""A change to the policy, as data (M7 design H.1; D-150; M6 design G.3). Pure.

Onboarding's fragment 1, a review's fragment 2 and a re-registration are each a
:class:`PolicyChange`: a title and a tuple of ops. Each op holds the schema's own models
(``OAuth2Credential``, ``Route``, ``RemoteServer``, ``Tools``) or values checked against the
schema's own types when the op is made, so a value that reaches the emitter (``emit.py``) has
already passed its validator. There is no op that adds a client, a token, a caller or a secret
value, so a change can't hold one (H.3). Three ops are managed mode's portal edits and nothing
else's (M6 G.3): :class:`MoveToAllow` (one included ``approve`` tool to ``allow``),
:class:`SetClientServers` (the servers one existing client reaches) and
:class:`SetConnectorLimits` (a connector's pause and limits, outside its secret's binding, F-15).

- :meth:`PolicyChange.data` is the change's plain form: what the fragment's YAML loads back to. A
  :class:`MoveToAllow` has none: it moves a name between two lists a merge replaces whole, so only
  :func:`apply`, which holds the policy, makes it.
- :meth:`PolicyChange.replace` names the blocks it replaces whole (H.4, CR-14).
- :func:`apply` merges the plain form into the running policy with ``merge.merge``, the function
  ``zoeymcp check --with`` runs, and validates the result as a :class:`Policy`; :func:`validate`
  runs ``check`` on it too. A managed write applies it with ``managed=True``: every
  :class:`SetServerReview` then writes its server's ``declined`` block whole, an empty one
  included, less the tools it includes (M6 J.3, H.4; CR-17), so a candidate never holds a tool
  both included and declined. A declarative fragment stays M7's (M6 step 6). A refusal is
  :class:`ChangeRefused`, whose ``reason`` is M.2's.
- A review of a server that enables prompts or resources (M6 design L.7) writes those blocks
  whole too (:class:`SetServerReview`'s ``prompts`` and ``resources``), and a comment may name a
  prompt or a resource by its URI.
- :func:`from_portal` holds the portal's bounds on the ops themselves (M6 G.3, I.3): a credential
  the portal adds or changes takes no ``env:`` reference (``portal_env_ref``, CR-16), and a route
  it adds calls as the gateway with a credential the same change adds
  (``route_reuses_credential``, MISS-1).
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Final, Literal

from pydantic import TypeAdapter, ValidationError

from . import fields
from .check import check_policy
from .findings import Finding, format_location
from .merge import REVIEW_BLOCKS, Merged, Path, describe, merge
from .schema import (
    _SCOPE_TOKEN,
    MAX_SCOPES,
    NAME_PATTERN,
    HeaderCredential,
    OAuth2Credential,
    Pin,
    Policy,
    PrivateHostPort,
    PromptsPolicy,
    RemoteServer,
    ResourcesPolicy,
    Route,
    SMTPConnector,
    ToolkitServer,
    ToolName,
    Tools,
    is_secret_ref,
)

Reason = Literal["name_taken", "diff_invalid", "portal_env_ref", "route_reuses_credential"]
CommentKind = Literal[
    "added",
    "changed_was",
    "kept",
    "not_included",
    "declined",
    "error_finding",
    "suggested",
    "merge_hint",
]
Era = Literal["auto", "modern", "legacy"]
ScopeSeparator = Literal[" ", ","]

_NAME = re.compile(NAME_PATTERN)
_REVIEW: Final = TypeAdapter(dict[ToolName, Pin])
_TOOL_NAME: Final = TypeAdapter(ToolName)
_PIN: Final = TypeAdapter(Pin)
_ENTRY: Final = TypeAdapter(PrivateHostPort)
_ERA: Final[TypeAdapter[Era]] = TypeAdapter(Era)
_SEPARATOR: Final[TypeAdapter[ScopeSeparator]] = TypeAdapter(ScopeSeparator)
# A connector's fields outside its secret's binding (F-15): the only ones the portal changes.
CONNECTOR_LIMITS: Final = ("paused", "max_per_day", "max_subject_chars", "max_body_chars")
# The fields of a credential the portal adds or changes that may hold a secret reference.
_SECRET_FIELDS: Final = ("secret", "client_id", "client_secret", "refresh_token")


class ChangeRefused(ValueError):
    """A change the running policy can't take: ``name_taken`` (an op adds a name the policy has)
    or ``diff_invalid`` (the merged policy doesn't load, or the op changes what isn't there).
    ``messages`` are the schema's or the merge's own."""

    def __init__(self, reason: Reason, path: str, messages: tuple[str, ...] = ()) -> None:
        self.reason: Reason = reason
        self.path = path
        self.messages = messages
        super().__init__(f"{reason}: {path}" + "".join(f"; {m}" for m in messages))


def _name(value: str) -> str:
    if not _NAME.fullmatch(value):
        raise ValueError(f"{value!r} isn't a policy name")
    return value


@dataclass(frozen=True)
class AddCredential:
    name: str
    credential: OAuth2Credential | HeaderCredential

    def __post_init__(self) -> None:
        _name(self.name)


@dataclass(frozen=True)
class AddRoute:
    route: Route


@dataclass(frozen=True)
class AddServer:
    name: str
    server: RemoteServer  # a bridge's server is one (no bridge kind)

    def __post_init__(self) -> None:
        _name(self.name)


@dataclass(frozen=True)
class AddEgressPrivate:
    entry: str

    def __post_init__(self) -> None:
        _ENTRY.validate_python(self.entry, strict=True)


@dataclass(frozen=True)
class SetServerReview:
    """A review's result for one server: its ``tools`` and ``review`` replaced whole, its
    ``declined``, ``prompts`` and ``resources`` too unless each is ``None`` (left as it is; M6
    design J.3, L.7), and its ``era`` when the review learned it."""

    name: str
    tools: Tools
    review: Mapping[str, str]
    era: str | None = None
    declined: Mapping[str, str] | None = None
    prompts: PromptsPolicy | None = None
    resources: ResourcesPolicy | None = None

    def __post_init__(self) -> None:
        _name(self.name)
        # A copy no caller holds, checked as the schema checks a server's review.
        pins = _REVIEW.validate_python(dict(self.review), strict=True)
        object.__setattr__(self, "review", MappingProxyType(pins))
        if self.declined is not None:  # the same map of names to pins
            declined = _REVIEW.validate_python(dict(self.declined), strict=True)
            object.__setattr__(self, "declined", MappingProxyType(declined))
        if self.era is not None:
            _ERA.validate_python(self.era)  # a Literal takes only its own strings

    def blocks(self) -> tuple[str, ...]:
        """The server's blocks the op replaces whole (``merge.REVIEW_BLOCKS``): ``tools`` and
        ``review``, and each of the others it holds."""
        return tuple(block for block in REVIEW_BLOCKS if getattr(self, block) is not None)


@dataclass(frozen=True)
class SetCredential:
    """A re-registration (D.12, OPS-3): the credential replaced whole."""

    name: str
    credential: OAuth2Credential

    def __post_init__(self) -> None:
        _name(self.name)


@dataclass(frozen=True)
class SetScope:
    """A step-up (D.5, SPEC-11): an oauth2 credential's ``scope`` set to ``scopes`` joined by
    its ``separator``, the rest of the credential kept, so the fragment merges into one written
    by hand too. Each token is the schema's, and none holds the separator, so the scope splits
    back into exactly these tokens; the merged policy checks its length."""

    name: str
    scopes: tuple[str, ...]
    separator: ScopeSeparator = " "

    def __post_init__(self) -> None:
        _name(self.name)
        _SEPARATOR.validate_python(self.separator)
        if not 0 < len(self.scopes) <= MAX_SCOPES:
            raise ValueError(f"1 to {MAX_SCOPES} scopes")
        for scope in self.scopes:
            if not _SCOPE_TOKEN.fullmatch(scope) or self.separator in scope:
                raise ValueError(f"{scope!r} isn't a scope token")

    @property
    def scope(self) -> str:
        return self.separator.join(self.scopes)


@dataclass(frozen=True)
class MoveToAllow:
    """One included ``approve`` tool moved to ``allow`` from a server's page (M6 design G.3,
    J.4): ``pin`` is the one the operator was shown, which the policy must still hold (on a
    ``pinning: off`` toolkit, which holds none, the reported pin of the listed definition)."""

    server: str
    kind: str
    name: str
    pin: str

    def __post_init__(self) -> None:
        _name(self.server)
        if self.kind != "tool":  # only a tool is classified (E.1's other kinds come with R31)
            raise ValueError(f"{self.kind!r} isn't a kind a move takes")
        _TOOL_NAME.validate_python(self.name, strict=True)
        _PIN.validate_python(self.pin, strict=True)


@dataclass(frozen=True)
class SetClientServers:
    """The servers one existing client reaches, replaced whole (M6 design G.3, G-13)."""

    client: str
    servers: tuple[str, ...]

    def __post_init__(self) -> None:
        _name(self.client)
        servers = tuple(_name(server) for server in self.servers)
        if len(set(servers)) != len(servers):
            raise ValueError("a client's servers name each server once")
        object.__setattr__(self, "servers", servers)


@dataclass(frozen=True)
class SetConnectorLimits:
    """A connector's pause and limits (M6 design G.3): only the fields outside its secret's
    binding (F-15), each checked as the schema checks it; ``None`` leaves one as it is, and at
    least one is set."""

    name: str
    paused: bool | None = None
    max_per_day: int | None = None
    max_subject_chars: int | None = None
    max_body_chars: int | None = None

    def __post_init__(self) -> None:
        _name(self.name)
        if not self.limits():
            raise ValueError("a connector's limits change sets one field or more")
        for field_name, value in self.limits().items():
            info = SMTPConnector.model_fields[field_name]
            TypeAdapter(info.rebuild_annotation()).validate_python(value, strict=True)

    def limits(self) -> dict[str, bool | int]:
        """The fields this change sets, by name."""
        found = {name: getattr(self, name) for name in CONNECTOR_LIMITS}
        return {name: value for name, value in found.items() if value is not None}


@dataclass(frozen=True)
class Comment:
    """A comment line of a fixed kind about a tool or a policy name; the emitter words it."""

    kind: CommentKind
    subject: str
    detail: str | None = None

    def __post_init__(self) -> None:
        _subject(self.subject)


def _subject(value: str) -> None:
    """A comment's subject: a tool's name (a policy's and a prompt's are one too), or a resource
    template's or a fixed resource's URI (M6 design L.1), each printable ASCII on one line."""
    if isinstance(value, str):
        for rule in (fields.uri_template, fields.resource_uri):
            with contextlib.suppress(ValueError):
                rule(value)
                return
    _TOOL_NAME.validate_python(value, strict=True)


Op = (
    AddCredential
    | AddRoute
    | AddServer
    | AddEgressPrivate
    | SetServerReview
    | SetCredential
    | SetScope
    | MoveToAllow
    | SetClientServers
    | SetConnectorLimits
    | Comment
)


@dataclass(frozen=True)
class PolicyChange:
    title: str  # fixed text and a policy name; the emitter checks its characters
    ops: tuple[Op, ...] = ()

    def __post_init__(self) -> None:
        targets = [_target(op) for op in self.ops if not isinstance(op, Comment)]
        for index, target in enumerate(targets):
            if target in targets[:index]:
                raise ValueError(f"the change names {describe(target)} twice")

    def data(self) -> dict[str, Any]:
        """The change's plain form: each model as the policy document writes it (JSON types),
        with only the fields its maker set, and no ``None``. A change holding a
        :class:`MoveToAllow` has none (only :func:`apply` makes the move)."""
        if any(isinstance(op, MoveToAllow) for op in self.ops):
            raise ValueError("a move to allow has no fragment: only a managed write makes it")
        return self._data()

    def _data(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for op in self.ops:
            if isinstance(op, AddCredential | SetCredential):
                out.setdefault("credentials", {})[op.name] = _plain(op.credential)
            elif isinstance(op, SetScope):
                # The kind the emitter needs to know the model; the merge keeps every other field.
                out.setdefault("credentials", {})[op.name] = {"kind": "oauth2", "scope": op.scope}
            elif isinstance(op, AddRoute):
                out.setdefault("routes", []).append(_plain(op.route))
            elif isinstance(op, AddServer):
                _servers(out)[op.name] = _plain(op.server)
            elif isinstance(op, AddEgressPrivate):
                out.setdefault("egress_private", []).append(op.entry)
            elif isinstance(op, SetServerReview):
                block: dict[str, Any] = {"tools": _plain(op.tools), "review": dict(op.review)}
                if op.declined is not None:
                    block["declined"] = dict(op.declined)
                for name in ("prompts", "resources"):
                    held: PromptsPolicy | ResourcesPolicy | None = getattr(op, name)
                    if held is not None:  # every field written: the block is replaced whole
                        block[name] = held.model_dump(mode="json")
                if op.era is not None:
                    block["era"] = op.era
                _servers(out)[op.name] = block
            elif isinstance(op, SetClientServers):
                clients = out.setdefault("gateway", {}).setdefault("clients", {})
                clients[op.client] = {"servers": list(op.servers)}  # a list: merged whole
            elif isinstance(op, SetConnectorLimits):
                # The kind the emitter needs to know the model; the merge keeps every other field.
                out.setdefault("connectors", {})[op.name] = {"kind": "smtp", **op.limits()}
        return out

    def replace(self) -> tuple[Path, ...]:
        """The paths the fragment's value replaces whole when it merges (H.4)."""
        paths: list[Path] = []
        for op in self.ops:
            if isinstance(op, SetServerReview):
                paths += [("gateway", "servers", op.name, block) for block in op.blocks()]
            elif isinstance(op, SetCredential):
                paths.append(("credentials", op.name))
        return tuple(paths)

    def comments(self) -> tuple[Comment, ...]:
        return tuple(op for op in self.ops if isinstance(op, Comment))


def _target(op: Op) -> Path:
    """What an op adds or changes, so a change can't name it twice."""
    if isinstance(op, AddCredential | SetCredential | SetScope):
        return ("credentials", op.name)
    if isinstance(op, AddRoute):
        return ("routes", op.route.name)
    if isinstance(op, AddServer | SetServerReview):
        return ("gateway", "servers", op.name)
    if isinstance(op, MoveToAllow):
        return ("gateway", "servers", op.server)
    if isinstance(op, SetClientServers):
        return ("gateway", "clients", op.client)
    if isinstance(op, SetConnectorLimits):
        return ("connectors", op.name)
    assert isinstance(op, AddEgressPrivate)  # noqa: S101 - Comment ops have no target
    return ("egress_private", op.entry)


def _plain(model: Any) -> dict[str, Any]:
    # No op's model has a field whose document name differs, so no by_alias here.
    plain: dict[str, Any] = model.model_dump(mode="json", exclude_unset=True, exclude_none=True)
    return plain


def _servers(out: dict[str, Any]) -> dict[str, Any]:
    servers: dict[str, Any] = out.setdefault("gateway", {}).setdefault("servers", {})
    return servers


def apply(policy: Policy, change: PolicyChange, *, managed: bool = False) -> Policy:
    """The running policy with ``change`` merged, validated as a :class:`Policy`. With
    ``managed`` (a managed write's candidate, M6 G.6 step 3), every :class:`SetServerReview`
    writes its server's ``declined`` block: its own, or the server's when it holds none, less
    the tools it includes (J.3, H.4)."""
    _check_names(policy, change)
    if managed:
        change = _declined_written(policy, change)
    base = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    data, paths = change._data(), change.replace()
    for op in change.ops:
        if isinstance(op, MoveToAllow):
            _servers(data)[op.server] = {"tools": _moved(_server(policy, op.server).tools, op)}
            paths += (("gateway", "servers", op.server, "tools"),)
    merged = merge(base, data, replace=paths)
    # A route by a taken name, the only conflict, is name_taken above.
    assert isinstance(merged, Merged), merged  # noqa: S101
    try:
        return Policy.model_validate(merged.data)
    except ValidationError as exc:
        messages = tuple(
            f"{format_location(error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False)
        )
        raise ChangeRefused("diff_invalid", "(document)", messages) from None


def _server(policy: Policy, name: str) -> RemoteServer | ToolkitServer:
    assert policy.gateway is not None  # noqa: S101 - _check_names found the server
    return policy.gateway.servers[name]


def _moved(tools: Tools, op: MoveToAllow) -> dict[str, list[str]]:
    """A server's ``tools`` with ``op``'s tool moved from ``approve`` to ``allow``."""
    return {
        "include": list(tools.include),
        "allow": [*tools.allow, op.name],
        "approve": [name for name in tools.approve if name != op.name],
    }


def _declined_written(policy: Policy, change: PolicyChange) -> PolicyChange:
    """``change`` with each :class:`SetServerReview` holding the ``declined`` block it leaves:
    its own, or the server's when it holds none, less the tools it includes."""
    ops: list[Op] = []
    for op in change.ops:
        if isinstance(op, SetServerReview):
            held = _server(policy, op.name).declined if op.declined is None else op.declined
            kept = {name: pin for name, pin in held.items() if name not in op.tools.include}
            op = replace(op, declined=kept)
        ops.append(op)
    return PolicyChange(change.title, tuple(ops))


def from_portal(change: PolicyChange) -> None:
    """Raises :class:`ChangeRefused` for an op the portal may not make (M6 design G.3, I.3): a
    credential added or changed whose secret field is an ``env:`` reference
    (``portal_env_ref``, CR-16; the store holds the portal's secrets), or a route added whose
    callers aren't the gateway alone or whose credential isn't one the same change adds
    (``route_reuses_credential``: an existing secret is never sent to a new origin, MISS-1)."""
    added = {op.name for op in change.ops if isinstance(op, AddCredential)}
    for op in change.ops:
        if isinstance(op, AddCredential | SetCredential):
            for field_name in _SECRET_FIELDS:
                value = getattr(op.credential, field_name, None)
                if isinstance(value, str) and is_secret_ref(value) and value.startswith("env:"):
                    raise ChangeRefused("portal_env_ref", f"credentials.{op.name}.{field_name}")
        elif isinstance(op, AddRoute):
            route = op.route
            reused = route.credential is not None and route.credential not in added
            if route.callers != ["gateway"] or reused:
                raise ChangeRefused("route_reuses_credential", f"routes {route.name}")


def validate(policy: Policy, change: PolicyChange) -> list[Finding]:
    """``check``'s findings on the running policy with ``change`` merged."""
    return check_policy(apply(policy, change))


def _check_names(policy: Policy, change: PolicyChange) -> None:
    """An ``Add*`` op may not name what the policy has; a ``Set*`` op must."""
    servers = {} if policy.gateway is None else policy.gateway.servers
    routes = {route.name for route in policy.routes}
    for op in change.ops:
        if isinstance(op, AddCredential) and op.name in policy.credentials:
            raise ChangeRefused("name_taken", f"credentials.{op.name}")
        if isinstance(op, AddRoute) and op.route.name in routes:
            raise ChangeRefused("name_taken", f"routes {op.route.name}")
        if isinstance(op, AddServer) and op.name in servers:
            raise ChangeRefused("name_taken", f"gateway.servers.{op.name}")
        if isinstance(op, SetServerReview) and op.name not in servers:
            raise ChangeRefused(
                "diff_invalid", f"gateway.servers.{op.name}", ("the policy has no such server",)
            )
        if isinstance(op, SetCredential) and op.name not in policy.credentials:
            raise ChangeRefused(
                "diff_invalid", f"credentials.{op.name}", ("the policy has no such credential",)
            )
        if isinstance(op, SetScope) and not isinstance(
            policy.credentials.get(op.name), OAuth2Credential
        ):
            raise ChangeRefused(
                "diff_invalid",
                f"credentials.{op.name}",
                ("the policy has no such oauth2 credential",),
            )
        if isinstance(op, MoveToAllow):
            _check_move(servers, op)
        if isinstance(op, SetClientServers):
            _check_client(policy, op)
        if isinstance(op, SetConnectorLimits) and op.name not in policy.connectors:
            raise ChangeRefused(
                "diff_invalid", f"connectors.{op.name}", ("the policy has no such connector",)
            )


def _check_move(servers: Mapping[str, RemoteServer | ToolkitServer], op: MoveToAllow) -> None:
    """A move needs the tool included in ``approve`` at the pin the operator was shown (J.4)."""
    where = f"gateway.servers.{op.server}"
    entry = servers.get(op.server)
    if entry is None:
        raise ChangeRefused("diff_invalid", where, ("the policy has no such server",))
    if op.name not in entry.tools.include or op.name not in entry.tools.approve:
        raise ChangeRefused(
            "diff_invalid", f"{where}.tools", (f"{op.name} isn't an included approve tool",)
        )
    off = isinstance(entry, ToolkitServer) and entry.pinning == "off"
    if not off and entry.review.get(op.name) != op.pin:
        raise ChangeRefused(
            "diff_invalid", f"{where}.review.{op.name}", ("the policy pins another definition",)
        )


def _check_client(policy: Policy, op: SetClientServers) -> None:
    """An existing client, given servers the policy has (G.3: no client is added)."""
    gateway = policy.gateway
    if gateway is None or op.client not in gateway.clients:
        where = f"gateway.clients.{op.client}"
        raise ChangeRefused("diff_invalid", where, ("the policy has no such client",))
    for server in op.servers:
        if server not in gateway.servers:
            where = f"gateway.servers.{server}"
            raise ChangeRefused("diff_invalid", where, ("the policy has no such server",))
