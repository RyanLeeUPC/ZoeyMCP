"""A change to the policy, as data (M7 design H.1; D-150). Pure.

Onboarding's fragment 1, a review's fragment 2 and a re-registration are each a
:class:`PolicyChange`: a title and a tuple of ops. Each op holds the schema's own models
(``OAuth2Credential``, ``Route``, ``RemoteServer``, ``Tools``) or values checked against the
schema's own types when the op is made, so a value that reaches the emitter (``emit.py``) has
already passed its validator. There is no op for a client, a limit or a secret value, so a change
can't hold one (H.3).

- :meth:`PolicyChange.data` is the change's plain form: what the fragment's YAML loads back to.
- :meth:`PolicyChange.replace` names the blocks it replaces whole (H.4, CR-14).
- :func:`apply` merges the plain form into the running policy with ``merge.merge``, the function
  ``zoeymcp check --with`` runs, and validates the result as a :class:`Policy`; :func:`validate`
  runs ``check`` on it too. A refusal is :class:`ChangeRefused`, whose ``reason`` is M.2's.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from pydantic import TypeAdapter, ValidationError

from .check import check_policy
from .findings import Finding, format_location
from .merge import REVIEW_BLOCKS, Merged, Path, describe, merge
from .schema import (
    NAME_PATTERN,
    HeaderCredential,
    OAuth2Credential,
    Pin,
    Policy,
    PrivateHostPort,
    RemoteServer,
    Route,
    ToolName,
    Tools,
)

Reason = Literal["name_taken", "diff_invalid"]
CommentKind = Literal[
    "added", "changed_was", "not_included", "error_finding", "suggested", "merge_hint"
]
Era = Literal["auto", "modern", "legacy"]

_NAME = re.compile(NAME_PATTERN)
_REVIEW: Final = TypeAdapter(dict[ToolName, Pin])
_TOOL_NAME: Final = TypeAdapter(ToolName)
_ENTRY: Final = TypeAdapter(PrivateHostPort)
_ERA: Final[TypeAdapter[Era]] = TypeAdapter(Era)


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
    """A review's result for one server: its ``tools`` and ``review`` replaced whole, and its
    ``era`` when the review learned it."""

    name: str
    tools: Tools
    review: Mapping[str, str]
    era: str | None = None

    def __post_init__(self) -> None:
        _name(self.name)
        # A copy no caller holds, checked as the schema checks a server's review.
        pins = _REVIEW.validate_python(dict(self.review), strict=True)
        object.__setattr__(self, "review", MappingProxyType(pins))
        if self.era is not None:
            _ERA.validate_python(self.era)  # a Literal takes only its own strings


@dataclass(frozen=True)
class SetCredential:
    """A re-registration (D.12, OPS-3): the credential replaced whole."""

    name: str
    credential: OAuth2Credential

    def __post_init__(self) -> None:
        _name(self.name)


@dataclass(frozen=True)
class Comment:
    """A comment line of a fixed kind about a tool or a policy name; the emitter words it."""

    kind: CommentKind
    subject: str
    detail: str | None = None

    def __post_init__(self) -> None:
        _TOOL_NAME.validate_python(self.subject, strict=True)  # a policy name is one too


Op = (
    AddCredential
    | AddRoute
    | AddServer
    | AddEgressPrivate
    | SetServerReview
    | SetCredential
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
        with only the fields its maker set, and no ``None``."""
        out: dict[str, Any] = {}
        for op in self.ops:
            if isinstance(op, AddCredential | SetCredential):
                out.setdefault("credentials", {})[op.name] = _plain(op.credential)
            elif isinstance(op, AddRoute):
                out.setdefault("routes", []).append(_plain(op.route))
            elif isinstance(op, AddServer):
                _servers(out)[op.name] = _plain(op.server)
            elif isinstance(op, AddEgressPrivate):
                out.setdefault("egress_private", []).append(op.entry)
            elif isinstance(op, SetServerReview):
                block: dict[str, Any] = {"tools": _plain(op.tools), "review": dict(op.review)}
                if op.era is not None:
                    block["era"] = op.era
                _servers(out)[op.name] = block
        return out

    def replace(self) -> tuple[Path, ...]:
        """The paths the fragment's value replaces whole when it merges (H.4)."""
        paths: list[Path] = []
        for op in self.ops:
            if isinstance(op, SetServerReview):
                paths += [("gateway", "servers", op.name, block) for block in REVIEW_BLOCKS]
            elif isinstance(op, SetCredential):
                paths.append(("credentials", op.name))
        return tuple(paths)

    def comments(self) -> tuple[Comment, ...]:
        return tuple(op for op in self.ops if isinstance(op, Comment))


def _target(op: Op) -> Path:
    """What an op adds or changes, so a change can't name it twice."""
    if isinstance(op, AddCredential | SetCredential):
        return ("credentials", op.name)
    if isinstance(op, AddRoute):
        return ("routes", op.route.name)
    if isinstance(op, AddServer | SetServerReview):
        return ("gateway", "servers", op.name)
    assert isinstance(op, AddEgressPrivate)  # noqa: S101 - Comment ops have no target
    return ("egress_private", op.entry)


def _plain(model: Any) -> dict[str, Any]:
    # No op's model has a field whose document name differs, so no by_alias here.
    plain: dict[str, Any] = model.model_dump(mode="json", exclude_unset=True, exclude_none=True)
    return plain


def _servers(out: dict[str, Any]) -> dict[str, Any]:
    servers: dict[str, Any] = out.setdefault("gateway", {}).setdefault("servers", {})
    return servers


def apply(policy: Policy, change: PolicyChange) -> Policy:
    """The running policy with ``change`` merged, validated as a :class:`Policy`."""
    _check_names(policy, change)
    base = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    merged = merge(base, change.data(), replace=change.replace())
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
