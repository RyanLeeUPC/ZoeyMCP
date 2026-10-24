"""The ratchet: everything about a managed policy that only moves forward (M6 design E; D-58
part 2.10, D-198, D-194; Y5, Y11, Y12, Y14). Pure, mutation-tested.

Each revision carries one sealed :class:`Ratchet` (``vault/policyseal.py`` holds its plain form,
:meth:`Ratchet.as_dict`), and every write's candidate is checked against it by
:func:`violations` before anything else decides (G.5 rule 1c):

- the two key-generation **floors**, the highest each generation any revision ran (E1: a lower one
  would bring back a retired key; no grant);
- the **retired pins**: a definition's pin a write replaced or removed, unless a fresh review
  verified it again (E2: an included definition going back to one, ``pin:<server>/<kind>/<name>``);
- the **retired clients** (the ``token_sha256`` of every client a write removed or re-tokened, E3,
  ``client:<name>``) and **retired callers** (each removed placeholder as a digest under
  :data:`PLACEHOLDER_CONTEXT`, so even the encrypted body holds no removed placeholder; E4,
  ``caller:<route>/<index>``);
- **approved**: every definition ever classified ``approve`` (T-2), which nothing leaves; the
  planner reads it to find a re-include as ``allow`` (a move) and the review screen's ``prefill``;
- **env**: each ``env:`` name and the origins the host accepted it may be sent to (:func:`reach`;
  E5 a new name, E6 a wider reach, each ``--allow-env <name>``).

E2 to E4 compare with the head: a client, caller or pin the head already holds (a host write
revived it with a grant) is not refused again by every later write. :func:`initial` is the
ratchet of a seed, which the host accepted whole; :func:`advance` the one after a write the
checks passed. The retired sets and ``approved`` together hold at most :data:`RATCHET_MAX`
entries: a write whose ratchet would pass it (:func:`full`) is refused ``ratchet_full``, whose way
on is a reseed with ``--new-ratchet`` (F.3).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from . import fields
from .check import secret_references
from .schema import OAuth2Credential, PlaceholderCaller, Policy, RemoteServer, ToolkitServer

# A definition by (server, kind, name); kind: tool, and from step 19 prompt or resource (E.1).
DefKey = tuple[str, str, str]
DEF_KINDS: Final = ("tool", "prompt", "resource_template", "resource")
# The retired sets and approved together (N.4).
RATCHET_MAX: Final = 10_000
# A removed placeholder is kept as sha256 of this line and the placeholder.
PLACEHOLDER_CONTEXT: Final = "zoeymcp/placeholder/v1\n"
GENERATIONS: Final = (
    ("gateway_key_generation", "gateway_key_floor"),
    ("egress_key_generation", "egress_key_floor"),
)
_DEFAULT_PORTS: Final = MappingProxyType({"https": 443, "http": 80})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_FIELDS: Final = frozenset(
    {
        "gateway_key_floor",
        "egress_key_floor",
        "retired_pins",
        "retired_clients",
        "retired_callers",
        "approved",
        "env",
    }
)

ViolationReason = Literal[
    "generation_lowered",
    "pin_retired",
    "revives_client",
    "revives_caller",
    "env_name_new",
    "env_reach_grows",
]


@dataclass(frozen=True)
class Ratchet:
    gateway_key_floor: int  # the highest gateway_key_generation any revision ran
    egress_key_floor: int  # the same for egress_key_generation (D-198)
    retired_pins: Mapping[DefKey, frozenset[str]]  # pins a write replaced or removed
    retired_clients: frozenset[str]  # token_sha256 of every client a write removed or re-tokened
    retired_callers: frozenset[str]  # placeholder digests a write removed
    approved: frozenset[DefKey]  # every definition ever classified approve (T-2)
    env: Mapping[str, frozenset[str]]  # each env: name, and the origins it may be sent to

    def as_dict(self) -> dict[str, Any]:
        """The plain form a revision's body carries: canonical JSON, every list sorted."""
        return {
            "gateway_key_floor": self.gateway_key_floor,
            "egress_key_floor": self.egress_key_floor,
            "retired_pins": [
                {"server": key[0], "kind": key[1], "name": key[2], "pins": sorted(pins)}
                for key, pins in sorted(self.retired_pins.items())
            ],
            "retired_clients": sorted(self.retired_clients),
            "retired_callers": sorted(self.retired_callers),
            "approved": [list(key) for key in sorted(self.approved)],
            "env": {name: sorted(origins) for name, origins in sorted(self.env.items())},
        }


@dataclass(frozen=True)
class Grants:
    """What the host names on a write (socket, offline); the portal always passes ``Grants()``."""

    # "client:<name>", "caller:<route>/<index>", "pin:<server>/<kind>/<name>"
    revive: frozenset[str] = frozenset()
    # env: names whose new name or new reach the host accepts
    env: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Violation:
    """One thing a candidate would move back. ``subject`` is what a grant names (the generation's
    field for ``generation_lowered``, which no grant allows; the bare name for the env reasons)."""

    reason: ViolationReason
    subject: str
    floor: int = 0  # generation_lowered: the floor it went below
    origins: tuple[str, ...] = ()  # env_reach_grows: the origins the candidate adds, sorted


def initial(policy: Policy) -> Ratchet:
    """The ratchet of a seed: its generations as the floors, its ``approve`` definitions and its
    ``env:`` reach, which the host accepted with the document; nothing retired yet."""
    return Ratchet(
        gateway_key_floor=policy.gateway_key_generation,
        egress_key_floor=policy.egress_key_generation,
        retired_pins=MappingProxyType({}),
        retired_clients=frozenset(),
        retired_callers=frozenset(),
        approved=_approved(policy),
        env=reach(policy),
    )


def advance(
    ratchet: Ratchet, old: Policy, new: Policy, *, verified: frozenset[tuple[DefKey, str]]
) -> Ratchet:
    """The ratchet after a write from ``old`` (the head) to ``new``: the floors' maxima; every
    pin ``old`` held that ``new`` doesn't hold for that definition, less each pin ``verified``
    (the write's fresh review read it again); the clients and placeholders ``old`` had and
    ``new`` hasn't; ``old``'s and ``new``'s ``approve`` definitions; ``new``'s reach."""
    retired: dict[DefKey, set[str]] = {key: set(pins) for key, pins in ratchet.retired_pins.items()}
    now = _pins(new)
    for key, pin in _pins(old).items():
        if now.get(key) != pin:
            retired.setdefault(key, set()).add(pin)
    for key, pin in verified:
        retired.get(key, set()).discard(pin)
    env = {name: set(origins) for name, origins in ratchet.env.items()}
    for name, origins in reach(new).items():
        env.setdefault(name, set()).update(origins)
    return Ratchet(
        gateway_key_floor=max(ratchet.gateway_key_floor, new.gateway_key_generation),
        egress_key_floor=max(ratchet.egress_key_floor, new.egress_key_generation),
        retired_pins=MappingProxyType(
            {key: frozenset(pins) for key, pins in retired.items() if pins}
        ),
        retired_clients=ratchet.retired_clients
        | (set(_clients(old).values()) - set(_clients(new).values())),
        retired_callers=ratchet.retired_callers
        | (set(_callers(old).values()) - set(_callers(new).values())),
        approved=ratchet.approved | _approved(old) | _approved(new),
        env=MappingProxyType({name: frozenset(origins) for name, origins in env.items()}),
    )


def violations(
    ratchet: Ratchet,
    head: Policy,
    candidate: Policy,
    *,
    verified: frozenset[tuple[DefKey, str]],
    grants: Grants,
) -> tuple[Violation, ...]:
    """What ``candidate`` would move back (E.2): E1 to E6 in order, each in the candidate's own
    order; an entry the host granted isn't one, and nothing grants E1."""
    found = [
        Violation("generation_lowered", name, floor=getattr(ratchet, floor))
        for name, floor in GENERATIONS
        if getattr(candidate, name) < getattr(ratchet, floor)
    ]
    held = _pins(head)
    for key, pin in _pins(candidate, included=True).items():
        subject = "pin:" + "/".join(key)
        if (
            pin != held.get(key)
            and pin in ratchet.retired_pins.get(key, ())
            and (key, pin) not in verified
            and subject not in grants.revive
        ):
            found.append(Violation("pin_retired", subject))
    tokens = set(_clients(head).values())
    for name, token in _clients(candidate).items():
        subject = f"client:{name}"
        retired = token in ratchet.retired_clients and token not in tokens
        if retired and subject not in grants.revive:
            found.append(Violation("revives_client", subject))
    placeholders = set(_callers(head).values())
    for (route, index), placeholder in _callers(candidate).items():
        subject = f"caller:{route}/{index}"
        retired = placeholder in ratchet.retired_callers and placeholder not in placeholders
        if retired and subject not in grants.revive:
            found.append(Violation("revives_caller", subject))
    for name, origins in reach(candidate).items():
        if name in grants.env:
            continue
        if name not in ratchet.env:
            found.append(Violation("env_name_new", name))
        elif grown := origins - ratchet.env[name]:
            found.append(Violation("env_reach_grows", name, origins=tuple(sorted(grown))))
    return tuple(found)


def reach(policy: Policy) -> Mapping[str, frozenset[str]]:
    """Each ``env:`` name the policy uses (``check.secret_references``) and the origins it can be
    sent to: a header, query, path or basic credential's to the upstream of every route using the
    credential; an OAuth client ID, secret or refresh-token seed to ``token_url``'s and
    ``revocation_url``'s; a connector's to ``smtp://<host>:<port>``."""
    found: dict[str, set[str]] = {}
    for path, ref, _ in secret_references(policy):
        if not ref.startswith("env:"):
            continue
        section, owner = path.split(".")[:2]
        origins = found.setdefault(ref.removeprefix("env:"), set())
        if section == "connectors":
            conn = policy.connectors[owner]
            origins.add(f"smtp://{conn.host.lower()}:{conn.port}")
            continue
        cred = policy.credentials[owner]
        if isinstance(cred, OAuth2Credential):
            origins.add(_origin(cred.token_url))
            if cred.revocation_url is not None:
                origins.add(_origin(cred.revocation_url))
            continue
        origins.update(
            _origin(route.upstream)
            for route in policy.routes
            if route.credential == owner and route.upstream is not None
        )
    return MappingProxyType({name: frozenset(origins) for name, origins in found.items()})


def entries(ratchet: Ratchet) -> int:
    """The entries :data:`RATCHET_MAX` counts: every retired pin, client and caller, and every
    definition in ``approved``."""
    return (
        sum(len(pins) for pins in ratchet.retired_pins.values())
        + len(ratchet.retired_clients)
        + len(ratchet.retired_callers)
        + len(ratchet.approved)
    )


def full(ratchet: Ratchet) -> bool:
    """Whether ``ratchet`` holds more than :data:`RATCHET_MAX` entries (``ratchet_full``)."""
    return entries(ratchet) > RATCHET_MAX


def caller_digest(placeholder: str) -> str:
    """How :attr:`Ratchet.retired_callers` holds a removed placeholder."""
    text = PLACEHOLDER_CONTEXT + placeholder
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def loaded(data: Mapping[str, Any]) -> Ratchet:
    """A :class:`Ratchet` from its plain form (:meth:`Ratchet.as_dict`); ``ValueError`` names the
    first field that isn't in that form."""
    if set(data) != _FIELDS:
        raise ValueError("a ratchet has exactly the fields " + ", ".join(sorted(_FIELDS)))
    floors = [data[floor] for _, floor in GENERATIONS]
    for (_, floor), value in zip(GENERATIONS, floors, strict=True):
        if type(value) is not int or value < 1:
            raise ValueError(f"{floor} is a generation, a whole number from 1")
    pins: dict[DefKey, frozenset[str]] = {}
    for entry in _list(data["retired_pins"], "retired_pins"):
        if not isinstance(entry, Mapping) or set(entry) != {"server", "kind", "name", "pins"}:
            raise ValueError("a retired_pins entry is a server, kind, name and pins")
        key = _key([entry["server"], entry["kind"], entry["name"]], "retired_pins")
        found = _strings(entry["pins"], "retired_pins", _DIGEST)
        if not found or key in pins:
            raise ValueError("a retired_pins entry names a new definition and one pin or more")
        pins[key] = found
    env: dict[str, frozenset[str]] = {}
    raw = data["env"]
    if not isinstance(raw, Mapping):
        raise ValueError("env maps each name to its origins")
    for name, origins in raw.items():
        env[_string(name, "env")] = _strings(origins, "env", None)
    return Ratchet(
        gateway_key_floor=floors[0],
        egress_key_floor=floors[1],
        retired_pins=MappingProxyType(pins),
        retired_clients=_strings(data["retired_clients"], "retired_clients", _DIGEST),
        retired_callers=_strings(data["retired_callers"], "retired_callers", _DIGEST),
        approved=frozenset(_key(key, "approved") for key in _list(data["approved"], "approved")),
        env=MappingProxyType(env),
    )


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{name} is a list")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} holds text only")
    return value


def _strings(value: Any, name: str, form: re.Pattern[str] | None) -> frozenset[str]:
    found = frozenset(_string(item, name) for item in _list(value, name))
    if form is not None and any(form.fullmatch(item) is None for item in found):
        raise ValueError(f"{name} holds sha256 digests only")
    return found


def _key(value: Any, name: str) -> DefKey:
    items = _list(value, name)
    if len(items) != 3 or items[1] not in DEF_KINDS:
        raise ValueError(f"{name} names a definition by server, kind and name")
    return (_string(items[0], name), items[1], _string(items[2], name))


def _origin(url: str) -> str:
    """``scheme://host:port`` for an http(s) URL, as ``check`` compares origins; a ``unix:``
    upstream is its own."""
    if url.startswith(fields.UNIX_PREFIX):
        return url
    parts = urlsplit(url)  # lowercases the scheme and the host
    return f"{parts.scheme}://{parts.hostname}:{parts.port or _DEFAULT_PORTS[parts.scheme]}"


def _servers(policy: Policy) -> Iterable[tuple[str, RemoteServer | ToolkitServer]]:
    return () if policy.gateway is None else policy.gateway.servers.items()


def _pins(policy: Policy, *, included: bool = False) -> dict[DefKey, str]:
    """Every definition's pin in the policy's ``review`` maps, or only the included ones'."""
    return {
        (server, "tool", tool): pin
        for server, entry in _servers(policy)
        for tool, pin in entry.review.items()
        if not included or tool in entry.tools.include
    }


def _approved(policy: Policy) -> frozenset[DefKey]:
    return frozenset(
        (server, "tool", tool) for server, entry in _servers(policy) for tool in entry.tools.approve
    )


def _clients(policy: Policy) -> dict[str, str]:
    """Each client's ``token_sha256``, by name."""
    clients = {} if policy.gateway is None else policy.gateway.clients
    return {name: client.token_hash for name, client in clients.items()}


def _callers(policy: Policy) -> dict[tuple[str, int], str]:
    """Each placeholder caller's :func:`caller_digest`, by route and index."""
    return {
        (route.name, index): caller_digest(caller.placeholder)
        for route in policy.routes
        for index, caller in enumerate(route.callers)
        if isinstance(caller, PlaceholderCaller)
    }
