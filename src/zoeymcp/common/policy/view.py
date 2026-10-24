"""The gateway's view of the policy (M3 design D.1, invariant G1).

The vault serves it to the gateway on ``/_zoeymcp/gateway/v1/view``. It holds what the gateway
needs and nothing secret: no routes, credentials, connectors, secret references, placeholders,
upstream URLs or admin settings. Client tokens appear only as their ``token_sha256`` hashes. A
remote server carries ``vault_path``, the vault path that reaches it (its route's prefix plus its
path). A toolkit server carries its module, which the gateway imports, and its slots: each slot's
route prefix, the connector's kind (never its name) and the toolkit's rules as full vault paths.

``digest`` is the canonical digest of everything else, so it changes exactly when the view does.
A field M6 added (``declined``, M6 design A.3) is left out of both the digest and the served bytes
while it is empty, so a policy that doesn't use it keeps the view an M7 vault served, digest and
all, and an older gateway meets the field only once the operator uses it (CR-6, CR-7).
The module is pure and needs only pydantic, so the vault builds the view without the gateway's
dependencies, and the gateway parses it with the same models.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Annotated, Any, Final, Literal

from pydantic import Field, StringConstraints, ValidationError, field_validator

from .. import canonical
from .findings import format_location
from .schema import (
    Approvals,
    Capability,
    ClientApprovals,
    Gateway,
    GatewayLimits,
    ModulePath,
    Name,
    Network,
    Origin,
    Pin,
    Policy,
    Server,
    SlotName,
    TokenHash,
    ToolkitMethod,
    ToolkitServer,
    ToolName,
    Tools,
    _check_gateway_host,
    _check_network,
    _check_origin,
    _Model,
)

VIEW_VERSION: Literal[1] = 1
MAX_VIEW_BYTES = 8 * 2**20
# A route prefix and a server path, as the schema and check allow them.
VaultPath = Annotated[
    str, StringConstraints(pattern=r"^/[a-z0-9][a-z0-9_-]{0,62}/[A-Za-z0-9._~/-]{0,1023}$")
]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
# A location part named in a ViewError: a field, tag or short plain key. Anything else is "?".
_LOCATION_PART = re.compile(r"[A-Za-z0-9_.-]{1,128}|\[key\]")


class ViewError(ValueError):
    """A view the gateway refuses. The message names locations only, never values."""


class ViewClient(_Model):
    token_sha256: TokenHash
    servers: list[Name]
    sources: list[Network]
    approvals: ClientApprovals | None

    @field_validator("sources")
    @classmethod
    def _valid_sources(cls, value: list[str]) -> list[str]:
        for source in value:
            _check_network(source)
        return value


class ViewRemoteServer(_Model):
    kind: Literal["remote"]
    vault_path: VaultPath
    tools: Tools
    review: dict[ToolName, Pin]
    # M6 A.3: left out of the digest and the served bytes while empty (_OMITTED_WHEN_EMPTY).
    declined: dict[ToolName, Pin] = Field(default_factory=dict)
    on_drift: Literal["hide", "fail"]
    shared_session: bool
    wrap_results: bool
    enable: list[Capability]
    era: Literal["auto", "modern", "legacy"]
    drift_check_interval: Annotated[int, Field(ge=60, le=86400)]
    call_timeout: Annotated[int, Field(ge=1, le=3600)] | None


class ViewToolkitRule(_Model):
    methods: list[ToolkitMethod]
    paths: list[str]  # the route's prefix and the rule's path, as the vault sees them: /mail/send
    approved: bool


class ViewSlot(_Model):
    prefix: Annotated[str, StringConstraints(pattern=r"^/[a-z0-9][a-z0-9_-]{0,62}$")]
    connector: Literal["smtp"] | None  # the connector's kind, never its name
    rules: list[ViewToolkitRule]


class ViewToolkitServer(_Model):
    kind: Literal["toolkit"]
    module: ModulePath
    tools: Tools
    pinning: Literal["required", "off"]
    review: dict[ToolName, Pin]
    declined: dict[ToolName, Pin] = Field(default_factory=dict)  # as a remote server's
    on_drift: Literal["hide", "fail"]
    slots: dict[SlotName, ViewSlot]
    wrap_results: bool
    call_timeout: Annotated[int, Field(ge=1, le=3600)] | None


ViewServer = Annotated[ViewRemoteServer | ViewToolkitServer, Field(discriminator="kind")]


class ViewGateway(_Model):
    hosts: Annotated[list[str], Field(min_length=1)]
    origins: list[Origin]
    limits: GatewayLimits
    approvals: Approvals
    clients: dict[Name, ViewClient]
    servers: dict[Name, ViewServer]

    @field_validator("hosts")
    @classmethod
    def _valid_hosts(cls, value: list[str]) -> list[str]:
        for host in value:
            _check_gateway_host(host)
        return value

    @field_validator("origins")
    @classmethod
    def _valid_origins(cls, value: list[str]) -> list[str]:
        for origin in value:
            _check_origin(origin)
        return value


class GatewayView(_Model):
    v: Literal[1]
    digest: Digest
    gateway: ViewGateway


# A server's fields M6 added, which the digest and the served bytes leave out while empty (A.3).
_OMITTED_WHEN_EMPTY: Final = ("declined",)


def _dumped(gateway: ViewGateway) -> dict[str, Any]:
    """The view's content as plain data, with each of a server's new fields left out while empty."""
    data = gateway.model_dump()
    for server in data["servers"].values():
        for member in _OMITTED_WHEN_EMPTY:
            if not server[member]:
                del server[member]
    return data


def view_digest(gateway: ViewGateway) -> str:
    """The digest of a view with this content."""
    return canonical.digest({"v": VIEW_VERSION, "gateway": _dumped(gateway)})


def _toolkit(name: str, server: ToolkitServer, policy: Policy) -> ViewToolkitServer:
    routes = {route.name: route for route in policy.routes}
    slots = {}
    for slot, binding in server.slots.items():
        route = routes.get(binding.route)
        if route is None:
            raise ValueError(f"gateway server {name!r} names an unknown route")
        connector = policy.connectors.get(route.connector) if route.connector else None
        slots[slot] = ViewSlot(
            prefix=route.prefix,
            connector=connector.kind if connector is not None else None,
            rules=[
                ViewToolkitRule(
                    methods=list(rule.methods),
                    paths=[route.prefix + path for path in rule.paths],
                    approved=rule.approved,
                )
                for rule in binding.rules
            ],
        )
    return ViewToolkitServer(
        kind="toolkit",
        module=server.module,
        tools=server.tools,
        pinning=server.pinning,
        review=dict(server.review),
        declined=dict(server.declined),
        on_drift=server.on_drift,
        slots=slots,
        wrap_results=server.wrap_results,
        call_timeout=server.call_timeout,
    )


def _server(name: str, server: Server, policy: Policy, prefixes: dict[str, str]) -> ViewServer:
    if isinstance(server, ToolkitServer):
        return _toolkit(name, server, policy)
    prefix = prefixes.get(server.route)
    if prefix is None:
        raise ValueError(f"gateway server {name!r} names an unknown route")
    return ViewRemoteServer(
        kind="remote",
        vault_path=prefix + server.path,
        tools=server.tools,
        review=dict(server.review),
        declined=dict(server.declined),
        on_drift=server.on_drift,
        shared_session=server.shared_session,
        wrap_results=server.wrap_results,
        enable=list(server.enable),
        era=server.era,
        drift_check_interval=server.drift_check_interval,
        call_timeout=server.call_timeout,
    )


def build_view(policy: Policy) -> GatewayView:
    """The gateway's view of ``policy``. A policy without a gateway section gives the defaults.

    The policy must pass ``check``: a server whose route is missing raises ValueError.
    """
    gateway = policy.gateway or Gateway()
    prefixes = {route.name: route.prefix for route in policy.routes}
    body = ViewGateway(
        hosts=list(gateway.hosts),
        origins=list(gateway.origins),
        limits=gateway.limits,
        approvals=gateway.approvals,
        clients={
            name: ViewClient(
                token_sha256=client.token_hash,
                servers=list(client.servers),
                sources=list(client.sources),
                approvals=client.approvals,
            )
            for name, client in gateway.clients.items()
        },
        servers={
            name: _server(name, server, policy, prefixes)
            for name, server in gateway.servers.items()
        },
    )
    return GatewayView(v=VIEW_VERSION, digest=view_digest(body), gateway=body)


def dump_view(view: GatewayView) -> bytes:
    """The view as canonical JSON, as the vault serves it."""
    return canonical.dumps_canonical(
        {"v": view.v, "digest": view.digest, "gateway": _dumped(view.gateway)}
    )


def _location(location: Sequence[int | str]) -> str:
    """A pydantic location, with any key that isn't a short plain name replaced by "?"."""
    return format_location(
        [
            part if isinstance(part, int) or _LOCATION_PART.fullmatch(part) else "?"
            for part in location
        ]
    )


def parse_view(data: bytes) -> GatewayView:
    """Parse a served view, refusing one that isn't valid or whose digest doesn't match."""
    if len(data) > MAX_VIEW_BYTES:
        raise ViewError(f"the view is larger than {MAX_VIEW_BYTES} bytes")
    try:
        raw = canonical.loads_strict(data, max_bytes=MAX_VIEW_BYTES)
    except canonical.JSONRejected as exc:
        raise ViewError("the view is not valid JSON") from exc
    try:
        view = GatewayView.model_validate(raw)
    except ValidationError as exc:
        locations = sorted({_location(error["loc"]) for error in exc.errors()})
        raise ViewError("invalid view at " + ", ".join(locations)) from exc
    if view_digest(view.gateway) != view.digest:
        raise ViewError("the view's digest doesn't match its content")
    return view
