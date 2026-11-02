"""Which tools the vault holds (M8 design A.3; MISS-1, T-1, T-2, Z7, Z20). Pure, mutation-tested.

The vault holds by route, not by path (T-1): a route is held when a gateway server on it lists
``tools.vault_approval``, and the vault then reads every request on it. :func:`held_map` is the
map the vault builds once per installed policy, never per request: for a held MCP route, each
server path the route carries with that server's held and listed tools and the held tools' pins;
for a held connector route, the toolkit servers that send through it (its writers), each with its
effective ``call_timeout`` (B.7). A path is keyed as :func:`path_key` writes it, under the route's
prefix, so ``/mcp`` and ``/mcp/`` stay two paths. A path two servers share on a held route is left
out of the map, so the vault refuses every request on it (``check`` refuses the policy, A.2 row 3).

:func:`held_pairs` is the (server, tool) set the managed planner compares, and
:func:`unheld_reach` the held pairs another route or server of the same policy reaches without
the hold: the same upstream (:func:`target`) with the same credential (:func:`same_credential`),
on a route that holds nothing or by a server that lists the tool unheld (A.4). ``check`` uses the
same helpers for A.2 rows 3, 4 and 21-23. The module takes the pydantic ``Policy``, so it is "no
``zoeymcp.gateway``, no I/O", not standard library only (J.1).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final
from urllib.parse import urlsplit

from .fields import UNIX_PREFIX, client_host
from .match import NormalizedPath
from .schema import (
    BasicCredential,
    OAuth2Credential,
    Policy,
    RemoteServer,
    Route,
    Server,
    ToolkitServer,
    is_secret_ref,
)
from .serverpaths import request_path

_DEFAULT_PORTS: Final[Mapping[str, int]] = MappingProxyType({"https": 443, "http": 80})


@dataclass(frozen=True)
class HeldPath:
    route: str
    path: tuple[str, ...]  # the server's path under the route, as path_key writes it
    server: str
    tools: frozenset[str]  # the server's vault_approval list
    listed: frozenset[str]  # the server's allow | approve: any other name is refused (B.2 E18)
    pins: Mapping[str, str]  # each held tool's pin from the server's review (the frame shows it)


@dataclass(frozen=True)
class HeldRoute:
    route: str
    paths: Mapping[tuple[str, ...], HeldPath]  # every server path the route carries
    names: frozenset[str]  # the union of the held names of every server on the route


@dataclass(frozen=True)
class HeldConnector:
    route: str
    writers: Mapping[str, int]  # toolkit server -> its effective call_timeout (F-50)
    names: frozenset[str]  # the writers' held tools, one of which a held write's marker names


Held = HeldRoute | HeldConnector
HeldMap = Mapping[str, Held]  # keyed by route name
# A hold's place: its route and the path key it came on; a connector's path is ().
HoldKey = tuple[str, tuple[str, ...]]


def path_key(path: NormalizedPath) -> tuple[str, ...]:
    """A normalized path as the map keys it: its segments, and a trailing slash as a last empty
    segment, which no segment of a normalized path is."""
    return (*path.segments, "") if path.trailing_slash else path.segments


def held_map(policy: Policy) -> HeldMap:
    """The routes the vault holds, by name (the module docstring)."""
    found: dict[str, Held] = {}
    if policy.gateway is None:
        return MappingProxyType(found)
    servers, limit = policy.gateway.servers, policy.gateway.limits.call_timeout
    for route, on_paths in server_paths(policy).items():
        names = frozenset(
            tool
            for names_on in on_paths.values()
            for name in names_on
            for tool in servers[name].tools.vault_approval
        )
        if not names:
            continue
        paths = {
            key: _held_path(route, key, names_on[0], servers[names_on[0]])
            for key, names_on in on_paths.items()
            if len(names_on) == 1
        }
        found[route] = HeldRoute(route, MappingProxyType(paths), names)
    for route, writers in connector_writers(policy).items():
        names = frozenset(tool for name in writers for tool in servers[name].tools.vault_approval)
        if names:
            timeouts = {name: servers[name].call_timeout or limit for name in writers}
            found[route] = HeldConnector(route, MappingProxyType(timeouts), names)
    return MappingProxyType(found)


def lookup(held: HeldMap, route: str) -> Held | None:
    """The hold on ``route``, or None for a route that holds nothing (B.1 step 2)."""
    return held.get(route)


def same_hold(old: HeldMap, new: HeldMap, key: HoldKey, tool: str) -> bool:
    """Whether a hold on ``tool`` at ``key`` stays as it is from ``old`` to ``new`` (Z7): the same
    server on the same path of the route holds the tool at the same pin; for a connector, the
    route still holds the tool for the same writers at the same deadlines. Any other change
    withdraws the hold (a change to ``approvers`` too, which the map doesn't hold)."""
    route, path = key
    before, after = old.get(route), new.get(route)
    if isinstance(before, HeldConnector) and isinstance(after, HeldConnector):
        return tool in before.names and tool in after.names and before.writers == after.writers
    if not isinstance(before, HeldRoute) or not isinstance(after, HeldRoute):
        return False
    was, now = before.paths.get(path), after.paths.get(path)
    if was is None or now is None:
        return False
    return (
        was.server == now.server
        and tool in was.tools
        and tool in now.tools
        and was.pins.get(tool) == now.pins.get(tool)
    )


def held_pairs(policy: Policy) -> frozenset[tuple[str, str]]:
    """Every (server, tool) the vault holds (Z20's set): a ``vault_approval`` tool the server
    also includes and approves. One it leaves out of either isn't called as held, so a candidate
    that drops it there drops the pair."""
    return frozenset(
        (name, tool)
        for name, server in _servers(policy).items()
        for tool in server.tools.vault_approval
        if tool in server.tools.approve and tool in server.tools.include
    )


def unheld_reach(policy: Policy) -> frozenset[tuple[str, str]]:
    """The held pairs ``policy`` also reaches unheld (T-2): through a route to the same upstream
    with the same credential that holds nothing, or one whose hold lets the tool through unheld
    (another server on it lists the tool without holding it; the held route itself included)."""
    held = held_map(policy)
    servers = _servers(policy)
    writes = connector_writers(policy)
    found: set[tuple[str, str]] = set()
    for name, tool in held_pairs(policy):
        server = servers[name]
        if isinstance(server, RemoteServer):
            homes = [server.route]
        else:
            homes = [route for route, writers in writes.items() if name in writers]
        for home in homes:
            if _reached(policy, held, home, tool):
                found.add((name, tool))
    return frozenset(found)


def server_paths(policy: Policy) -> dict[str, dict[tuple[str, ...], list[str]]]:
    """Per route, each path key its remote servers use and the servers on it, by name. A server
    path the vault refuses (``check``'s error) has none."""
    found: dict[str, dict[tuple[str, ...], list[str]]] = defaultdict(lambda: defaultdict(list))
    for name, server in sorted(_servers(policy).items()):
        if isinstance(server, RemoteServer):
            path = request_path(server.path)
            if path is not None:
                found[server.route][path_key(path)].append(name)
    return {route: dict(paths) for route, paths in found.items()}


def connector_writers(policy: Policy) -> dict[str, list[str]]:
    """Per connector route, the toolkit servers whose slots on it carry an ``approved: true``
    rule, by name: the writers a held connector holds all or none of (A.2 row 4; F-50)."""
    connectors = {route.name for route in policy.routes if route.connector is not None}
    found: dict[str, list[str]] = defaultdict(list)
    for name, server in sorted(_servers(policy).items()):
        if not isinstance(server, ToolkitServer):
            continue
        for binding in server.slots.values():
            approved = any(rule.approved for rule in binding.rules)
            if binding.route in connectors and approved and name not in found[binding.route]:
                found[binding.route].append(name)
    return dict(found)


def target(route: Route) -> str | None:
    """What ``route`` reaches, as routes are compared (A.2 rows 22-23): a connector by its name,
    a ``unix:`` socket as written, an http(s) upstream as ``scheme://host:port`` with the host as
    the vault's client connects to it (``fields.client_host``, no trailing dot); None for an
    upstream with no port the vault could use."""
    if route.connector is not None:
        return f"connector:{route.connector}"
    upstream = route.upstream or ""
    if upstream.startswith(UNIX_PREFIX):
        return upstream
    parts = urlsplit(upstream)  # lowercases the scheme and the host
    try:
        port = parts.port or _DEFAULT_PORTS[parts.scheme]
    except (KeyError, ValueError):
        return None
    host = client_host(parts.hostname or "").removesuffix(".")
    return f"{parts.scheme}://{host}:{port}"


def same_credential(policy: Policy, one: Route, other: Route) -> bool:
    """Whether two routes send the same credential (A.2 row 22): none on both, the same one, or
    two that share a secret reference (a store name, or an ``env:`` variable)."""
    if one.credential == other.credential:
        return True
    return bool(_references(policy, one.credential) & _references(policy, other.credential))


def _servers(policy: Policy) -> Mapping[str, Server]:
    return policy.gateway.servers if policy.gateway is not None else {}


def _held_path(route: str, key: tuple[str, ...], name: str, server: Server) -> HeldPath:
    tools = frozenset(server.tools.vault_approval)
    return HeldPath(
        route=route,
        path=key,
        server=name,
        tools=tools,
        listed=frozenset(server.tools.allow) | frozenset(server.tools.approve),
        pins=MappingProxyType(
            {tool: server.review[tool] for tool in tools if tool in server.review}
        ),
    )


def _reached(policy: Policy, held: HeldMap, home: str, tool: str) -> bool:
    """Whether a route to what route ``home`` reaches, with its credential, lets ``tool`` through
    unheld."""
    origin = next((route for route in policy.routes if route.name == home), None)
    where = None if origin is None else target(origin)
    if origin is None or where is None:  # a route check refuses: nothing reaches it
        return False
    for route in policy.routes:
        if target(route) != where or not same_credential(policy, route, origin):
            continue
        hold = held.get(route.name)
        if hold is None:
            return True
        if isinstance(hold, HeldConnector):
            if tool not in hold.names:
                return True
        elif any(tool in path.listed and tool not in path.tools for path in hold.paths.values()):
            return True
    return False


def _references(policy: Policy, credential: str | None) -> set[str]:
    """The secret references credential ``credential`` sends or mints with; none for no
    credential or an unknown one."""
    cred = policy.credentials.get(credential or "")
    if cred is None:
        return set()
    if isinstance(cred, OAuth2Credential):
        refs = (cred.client_id, cred.client_secret, cred.refresh_token)
        return {ref for ref in refs if ref is not None and is_secret_ref(ref)}
    found = {cred.secret}
    if isinstance(cred, BasicCredential) and is_secret_ref(cred.username):
        found.add(cred.username)
    return found
