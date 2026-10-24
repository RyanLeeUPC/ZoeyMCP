"""Onboardings in progress (M7 design D.8, D.11, D.12, I.3, M.7). Pure and mutation-tested.

An onboarding is phase 1 of onboarding by URL, from the first probe to fragment 1: what the
vault learned, what it may contact, and what the operator chose. :class:`OnboardingTable` holds
them in the vault's memory, like ``pkce.FlowTable``: each has an owner, the CLI or one portal
session, and another owner's answers as an unknown one; at most :data:`ONBOARDINGS_MAX` in all
and one per owner, each for :data:`ONBOARDING_TTL` seconds from its start, on a monotonic clock.

- **Stages**: ``discovering``, ``blocked`` (an operator's own proxy refused a host, D.11),
  ``discovered`` (the plan, immutable, and the draft change's ``check`` result) and
  ``registered`` (fragment 1's validated change, never a secret, so it can be rendered again at
  any indent, OPS-2, and the :class:`Client` a registration made, D.4). A registered onboarding
  ends when the running policy names its credential.
- **Resuming**: a start by the same owner for the same URL and names carries on with a blocked
  one (D.11), unless its options differ (``onboarding_options_changed``, OPS-8), and with a
  discovered (``--plan-only``, D.10) or registered one started with the same options; any other
  start replaces the owner's own.
- **Names** (OPS-15): :func:`default_name` from the server's host, never one the policy, the
  store or another onboarding has; :func:`name_taken` for the names given.
- **Allowances** (I.3): the ``host:port`` pairs an onboarding contacts, for the egress role's
  list until it registers: the hosts discovery fetched from, and the registration endpoint's
  once the plan says the vault registers the client. Never private: ``private_target`` is the
  one typed server's exception, carried per request (B.2, TI-10).
- **The second run** (D.12): :func:`committed_for` finds the running oauth2 credential an
  onboarded URL has, :func:`mismatches` where it, its route and its server differ from a fresh
  discovery, by field name only, and :func:`token_state` whether it already holds a refresh
  token; :func:`served_at` finds a server reaching the URL with another kind of credential
  (``already_configured``, OPS-14).
- **A re-registration** (``--reregister``, OPS-3) keeps the committed names and replaces the
  credential: its onboarding ends once the running policy holds the credential its fragment
  sets, not merely one by that name.
- :func:`next_for` (M.7): what the operator does next, each command an argument list shown
  shell-quoted and without a container prefix, which the CLI adds.
- :func:`widen_scope` (D.5's step-up, SPEC-11): health's fragment for a scope an upstream asked
  for, the union of the committed scope and the challenged one.
- :func:`listed_servers` (K.1, GR-21): the running policy's servers as the portal's rows list
  them, each with its state and, from :func:`listed_next`, what to do next; and
  :func:`reviewed_next`, the steps after fragment 2 (E.4), on every surface.

Nothing here does I/O; the clock and the ID source are injected. An onboarding's ID is never
logged and is compared in constant time.
"""

from __future__ import annotations

import hmac
import ipaddress
import re
import secrets
import shlex
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from ..common import egresslist, netguard
from ..common.egresslist import Allowance, Destination
from ..common.logs import refuse_type
from ..common.policy.change import PolicyChange, SetCredential, SetScope, apply
from ..common.policy.emit import emit
from ..common.policy.findings import Finding
from ..common.policy.restart import Effect
from ..common.policy.schema import (
    NAME_PATTERN,
    ClientAuth,
    GatewayLimits,
    OAuth2Credential,
    Policy,
    RemoteServer,
    Route,
    ToolkitServer,
    Tools,
    split_scope,
)
from .bindings import live_slot
from .oauth.discovery import Plan, origin_of
from .oauth.pkce import CLI_OWNER

ONBOARDING_TTL: Final = 1800.0
ONBOARDINGS_MAX: Final = 4
# 256 bits: token_urlsafe(32) gives 43 characters.
ID_BYTES: Final = 32
# Host labels that say nothing about the server, so never its default name (OPS-15).
GENERIC_LABELS: Final = frozenset({"mcp", "api", "www", "app", "server"})
# The default for a server named by an address, whose labels are numbers.
ADDRESS_NAME: Final = "server"
# The Squid source an onboarding's lines are written for, so their ACLs read zoeymcp_onboard_<n>.
ONBOARD_SOURCE: Final = "onboard"

Stage = Literal["discovering", "blocked", "discovered", "registered"]
Ending = Literal["registered", "cancelled", "expired", "owner_gone"]
Reason = Literal[
    "onboarding_unknown", "onboarding_busy", "onboarding_options_changed", "name_taken"
]
NameSource = Literal["given", "label", "second_label", "address"]
Do = Literal[
    "register",
    "make_fragment",
    "check_fragment",
    "check_policy",
    "commit_fragment",
    "reload",
    "sign_in",
    "connect",
    "review",
    "choose",
    "assign_clients",
    "allow_hosts",
    "update_proxy_allowlist",
    "retry",
    "fix_policy",
    "widen_scope",
    "check_egress_role",
    "onboard_again",
    "clear",
    "restart",
    "deliver_key",
    "wait_gateway",
    "save",
    "export_policy",
    "import_policy",
]
# Where the CLI runs a command (M.7): ``exec`` in the running service; ``run``, a one-off
# container that reads the inline policy from the service's environment; ``run_mount``, the same
# with the working directory mounted at /w, for a fragment file; ``up``, the service recreated;
# ``restart``, the service restarted (M6 design J15: a managed save the vault applies only at its
# restart). None: as written, where the policy file is.
Via = Literal["exec", "run", "run_mount", "up", "restart"]
# Whether a committed credential holds a refresh token (D.12, OPS-13): ``stored`` in its store
# slot (by login, a seeding secret set, or an env seed promoted), ``seeded`` from an env: seed
# not used yet, or ``none``.
TokenState = Literal["stored", "seeded", "none"]

NAME_SOURCES: Final[Mapping[NameSource, str]] = {
    "given": "the name you gave",
    "label": "from the server's host name",
    "second_label": "from the server's host name, whose other labels say nothing about it",
    "address": "a default: the server is named by its address",
}
# The policy sources ``zoeymcp check`` reads (load.read_source's labels), as E.5 names them.
STDIN_SOURCE: Final = "<stdin>"
INLINE_SOURCE: Final = "$ZOEYMCP_CONFIG"

_NAME = re.compile(NAME_PATTERN)
_SESSION_OWNER = re.compile(r"session:[0-9a-f]+")


class OnboardingRefused(Exception):
    """A start or a step the table refuses. ``reason`` is M.2's; ``values`` are what the
    refusal names (the taken name and where the other onboarding was started)."""

    def __init__(self, reason: Reason, message: str, values: tuple[str, ...] = ()) -> None:
        self.reason: Reason = reason
        self.values = values
        super().__init__(message)


@dataclass(frozen=True)
class Options:
    """What an onboarding was started with (D.8), never a secret: resuming a blocked one with
    other options refuses (OPS-8). ``secret_given`` says only that a given client came with a
    secret, which ``client_auth`` then defaults to ``basic`` for (D.10); without one, a client
    authenticates with nothing. ``reregister`` is a re-registration of a committed credential
    under its own names (D.12, OPS-3). Without a ``client_id`` the vault registers the client
    (D.4), at the portal origin ``callback_origin``'s callback when one is named."""

    client_id: str | None = None
    client_auth: ClientAuth | None = None
    redirect_uri: str | None = None
    issuer: str | None = None
    scope: str | None = None
    client_name: str | None = None
    allow_private: bool = False
    secret_given: bool = False
    reregister: bool = False
    callback_origin: str | None = None

    def __post_init__(self) -> None:
        if self.secret_given:
            if self.client_id is None:
                raise ValueError("a client secret needs its client ID")
            if self.client_auth == "none":
                raise ValueError("a client with a secret authenticates with basic or post")
            if self.client_auth is None:
                object.__setattr__(self, "client_auth", "basic")
        elif self.client_auth in ("basic", "post"):
            raise ValueError(f"client authentication {self.client_auth} needs a client secret")


@dataclass(frozen=True)
class Names:
    """The credential, route and server an onboarding adds, and where they came from."""

    credential: str
    route: str
    server: str
    source: NameSource = "given"

    def __post_init__(self) -> None:
        for value in (self.credential, self.route, self.server):
            if not _NAME.fullmatch(value):
                raise ValueError(f"{value!r} isn't a policy name")

    def same(self, other: Names) -> bool:
        """The same three names, wherever they came from."""
        return (self.credential, self.route, self.server) == (
            other.credential,
            other.route,
            other.server,
        )


@dataclass(frozen=True)
class Client:
    """The client a registration made (D.4): its ID, how it authenticates at the token endpoint,
    its secret's ``client_secret_expires_at`` (0 or None: never), and what its answer leaves to
    note (``dcr.NOTES``). Never the secret."""

    client_id: str
    client_auth: ClientAuth
    expires_at: int | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, repr=False)
class OnboardingRecord:
    """One onboarding. ``needed_hosts`` are the ``(host, port)`` pairs a blocked one's proxy must
    allow (D.11); ``allowance`` the pairs it contacts (I.3). ``plan`` is set once, at
    ``discovered``; ``change`` at ``registered``, with ``client`` when the vault registered it."""

    id: str
    owner: str
    server_url: str
    names: Names
    options: Options
    expires_at: float
    stage: Stage = "discovering"
    blocked_on: tuple[str, int] | None = None
    needed_hosts: tuple[tuple[str, int], ...] = ()
    plan: Plan | None = None
    draft_check: tuple[Finding, ...] = ()
    change: PolicyChange | None = None
    client: Client | None = None
    allowance: frozenset[tuple[str, int]] = field(default_factory=frozenset)

    @property
    def private_target(self) -> str | None:
        """The typed server's ``host:port`` when the operator ticked ``allow_private``: the one
        destination its probe and metadata fetches may find private (B.2)."""
        if not self.options.allow_private:
            return None
        return netguard.entry_key(*server_host_port(self.server_url))

    def __repr__(self) -> str:
        return f"OnboardingRecord(server={self.names.server!r}, stage={self.stage!r})"


# It holds its ID, which is never logged (M.4, M.5).
refuse_type(OnboardingRecord)


@dataclass(frozen=True)
class Started:
    """A start's onboarding, and whether it carries on with one the owner already had."""

    record: OnboardingRecord
    resumed: bool


@dataclass(frozen=True)
class Ended:
    """An onboarding gone from the table, and why (M.4's ``onboard_ended``)."""

    record: OnboardingRecord
    why: Ending


TokenFunction = Callable[[int], str]


def server_host_port(server_url: str) -> tuple[str, int]:
    """The ``(host, port)`` of an https URL discovery accepted, the host in lower case."""
    parts = urlsplit(server_url)
    return str(parts.hostname), parts.port or 443


def client_options(record: OnboardingRecord, client: Client | None = None) -> Options:
    """The options fragment 1 is made with: the onboarding's, with the client a registration
    made (``client``, else the record's) in the given client's place (D.4): its ID, and its
    authentication, a secret for any but ``none``."""
    made = client or record.client
    if made is None:
        return record.options
    return replace(
        record.options,
        client_id=made.client_id,
        client_auth=made.client_auth,
        secret_given=made.client_auth != "none",
    )


def server_path(server_url: str) -> str:
    """The server's ``path`` in the policy: the URL's path, or ``/`` when it has none (B.4)."""
    return urlsplit(server_url).path or "/"


def surface(owner: str) -> str:
    """Where an onboarding's owner works: ``cli`` or ``portal``."""
    return "cli" if owner == CLI_OWNER else "portal"


class OnboardingTable:
    """Onboardings in progress: ``ONBOARDINGS_MAX`` in all, one per owner, each for
    ``ONBOARDING_TTL`` seconds. What ends is kept for :meth:`sweep`, so each end is logged."""

    def __init__(
        self, clock: Callable[[], float], *, token: TokenFunction = secrets.token_urlsafe
    ) -> None:
        self._clock = clock
        self._token = token
        self._records: dict[str, OnboardingRecord] = {}
        self._ended: list[Ended] = []

    def __len__(self) -> int:
        self._expire()
        return len(self._records)

    def start(self, owner: str, server_url: str, names: Names, options: Options) -> Started:
        """The owner's onboarding of ``server_url`` under ``names``. A blocked one the owner
        already has for the same URL and names carries on from the blocked fetch, back to
        ``discovering`` and with its expiry, unless its options differ (OPS-8); a discovered or
        registered one carries on as it is when its options are the same, and is replaced when
        they aren't; one still discovering is replaced like any other. Names another owner's
        onboarding uses are ``name_taken``."""
        if owner != CLI_OWNER and not _SESSION_OWNER.fullmatch(owner):
            raise ValueError("an onboarding's owner is cli or session:<hex id>")
        own = self.owned(owner)
        if own is not None and own.server_url == server_url and own.names.same(names):
            if own.stage == "blocked":
                if own.options != options:
                    raise OnboardingRefused(
                        "onboarding_options_changed",
                        "the onboarding in progress for this URL was started with other options",
                    )
                own = replace(own, stage="discovering", blocked_on=None, needed_hosts=())
                self._records[own.id] = own
                return Started(own, resumed=True)
            if own.stage != "discovering" and own.options == options:
                return Started(own, resumed=True)
        for other in self._records.values():
            if other.owner == owner:
                continue
            taken = _shared_name(names, other.names)
            if taken is not None:
                where = surface(other.owner)
                raise OnboardingRefused(
                    "name_taken",
                    f"{taken} is taken by another onboarding, started from the {where}",
                    (taken, where),
                )
        if own is not None:
            del self._records[own.id]
            self._ended.append(Ended(own, "cancelled"))
        if len(self._records) >= ONBOARDINGS_MAX:
            raise OnboardingRefused(
                "onboarding_busy", f"at most {ONBOARDINGS_MAX} onboardings can be in progress"
            )
        record = OnboardingRecord(
            id=self._token(ID_BYTES),
            owner=owner,
            server_url=server_url,
            names=names,
            options=options,
            expires_at=self._clock() + ONBOARDING_TTL,
            allowance=frozenset({server_host_port(server_url)}),
        )
        self._records[record.id] = record
        return Started(record, resumed=False)

    def owned(self, owner: str) -> OnboardingRecord | None:
        """The owner's onboarding in progress, if it has one: a run that names none resumes
        it under its names (D.10)."""
        self._expire()
        return next((r for r in self._records.values() if r.owner == owner), None)

    def get(self, onboarding: str, owner: str) -> OnboardingRecord:
        """The owner's onboarding, unless it is unknown, expired or another owner's: all three
        answer ``onboarding_unknown``."""
        record = self._find(onboarding)
        if record is None or record.owner != owner or self._clock() >= record.expires_at:
            raise OnboardingRefused("onboarding_unknown", "no such onboarding is in progress")
        return record

    def widen(
        self, onboarding: str, owner: str, hosts: Iterable[tuple[str, int]]
    ) -> OnboardingRecord:
        """The allowance with ``hosts`` added, as discovery learns them (I.3)."""
        record = self.get(onboarding, owner)
        if record.stage == "registered":
            raise ValueError("a registered onboarding contacts nothing more")
        added = frozenset((host.lower(), port) for host, port in hosts)
        return self._put(replace(record, allowance=record.allowance | added))

    def block(
        self, onboarding: str, owner: str, target: tuple[str, int], policy: Policy
    ) -> OnboardingRecord:
        """A discovering onboarding stopped by a proxy refusing ``target`` (D.11). Its needed
        hosts are the target and every host in its allowance that the running policy's own
        destinations don't already cover, sorted."""
        record = self._in_stage(onboarding, owner, "discovering")
        host, port = target[0].lower(), target[1]
        known = {(d.host, d.port) for d in egresslist.derive(policy)[egresslist.VAULT]}
        # The refused target stays needed even when the policy names it: the proxy's list is
        # behind the policy.
        needed = sorted((record.allowance - known) | {(host, port)})
        return self._put(
            replace(
                record,
                stage="blocked",
                blocked_on=(host, port),
                needed_hosts=tuple(needed),
                allowance=record.allowance | {(host, port)},
            )
        )

    def discovered(
        self, onboarding: str, owner: str, plan: Plan, draft_check: Iterable[Finding]
    ) -> OnboardingRecord:
        """A discovering onboarding's plan, and its draft change's ``check`` findings (OPS-5).
        One with no client ID registers its client next, so the registration endpoint's host
        joins its allowance (D.8, I.3)."""
        record = self._in_stage(onboarding, owner, "discovering")
        allowance = record.allowance
        endpoint = plan.metadata.registration_endpoint
        if record.options.client_id is None and endpoint is not None:
            allowance |= {server_host_port(endpoint)}
        return self._put(
            replace(
                record,
                stage="discovered",
                plan=plan,
                draft_check=tuple(draft_check),
                allowance=allowance,
            )
        )

    def registered(
        self, onboarding: str, owner: str, change: PolicyChange, client: Client | None = None
    ) -> OnboardingRecord:
        """A discovered onboarding's fragment 1, and the ``client`` its registration made. It
        contacts nothing more, so its allowance goes (I.3)."""
        record = self._in_stage(onboarding, owner, "discovered")
        return self._put(
            replace(record, stage="registered", change=change, client=client, allowance=frozenset())
        )

    def cancel(self, onboarding: str, owner: str) -> Ended | None:
        """Drop the onboarding. Another owner's stays, and answers as an unknown one; an expired
        one is :meth:`sweep`'s to report."""
        self._expire()
        record = self._find(onboarding)
        if record is None or record.owner != owner:
            return None
        del self._records[record.id]
        return Ended(record, "cancelled")

    def cancel_owner(self, owner: str) -> tuple[Ended, ...]:
        """Drop the owner's onboarding: its portal session ended."""
        self._expire()
        gone = [r for r in self._records.values() if r.owner == owner]
        for record in gone:
            del self._records[record.id]
        return tuple(Ended(record, "owner_gone") for record in gone)

    def sweep(self, committed: Collection[str] | Mapping[str, object] = ()) -> tuple[Ended, ...]:
        """Every onboarding that ended since the last sweep: replaced by its owner's next start,
        expired, or registered with its credential now in the running policy (``committed``,
        the policy's credentials by name). A re-registration's credential was there all along,
        so it ends once the policy's is the one its fragment sets."""
        self._expire()
        for record in list(self._records.values()):
            if record.stage == "registered" and _in_force(record, committed):
                del self._records[record.id]
                self._ended.append(Ended(record, "registered"))
        ended, self._ended = tuple(self._ended), []
        return ended

    def allowances(self) -> tuple[Allowance, ...]:
        """The live onboardings' allowances, for the vault's egress list (I.2, I.3)."""
        now = self._clock()
        return tuple(
            Allowance(record.allowance)
            for record in self._records.values()
            if now < record.expires_at and record.allowance
        )

    def allowances_expire_in(self) -> float | None:
        """Seconds until the next live allowance expires, or None when none is live: an expiry
        changes the egress list with no event (I.3)."""
        now = self._clock()
        live = [
            record.expires_at - now
            for record in self._records.values()
            if now < record.expires_at and record.allowance
        ]
        return min(live, default=None)

    def names_in_use(self, owner: str) -> frozenset[str]:
        """Every name another owner's live onboarding uses, for :func:`default_name`."""
        now = self._clock()
        return frozenset(
            name
            for record in self._records.values()
            if record.owner != owner and now < record.expires_at
            for name in (record.names.credential, record.names.route, record.names.server)
        )

    def _find(self, onboarding: str) -> OnboardingRecord | None:
        """The onboarding with this ID, every ID compared in constant time, with no early
        exit."""
        wanted = onboarding.encode("utf-8", "surrogatepass")
        found = None
        for record in self._records.values():
            if hmac.compare_digest(record.id.encode("ascii"), wanted):
                found = record
        return found

    def _in_stage(self, onboarding: str, owner: str, stage: Stage) -> OnboardingRecord:
        record = self.get(onboarding, owner)
        if record.stage != stage:
            raise ValueError(f"the onboarding is {record.stage}, not {stage}")
        return record

    def _put(self, record: OnboardingRecord) -> OnboardingRecord:
        self._records[record.id] = record
        return record

    def _expire(self) -> None:
        now = self._clock()
        for record in list(self._records.values()):
            if now >= record.expires_at:
                del self._records[record.id]
                self._ended.append(Ended(record, "expired"))


def _in_force(record: OnboardingRecord, committed: Collection[str] | Mapping[str, object]) -> bool:
    """Whether the running policy holds a registered onboarding's credential: by name, or for a
    re-registration, the very credential its fragment sets."""
    name = record.names.credential
    if name not in committed:
        return False
    if not record.options.reregister:
        return True
    assert record.change is not None  # noqa: S101 - a registered record holds its change
    wanted = [op.credential for op in record.change.ops if isinstance(op, SetCredential)]
    found = committed.get(name) if isinstance(committed, Mapping) else None
    return isinstance(found, OAuth2Credential) and [found] == wanted


def _shared_name(mine: Names, theirs: Names) -> str | None:
    """A name both onboardings would add as the same kind of thing, or None."""
    for own, other in (
        (mine.credential, theirs.credential),
        (mine.route, theirs.route),
        (mine.server, theirs.server),
    ):
        if own == other:
            return own
    return None


# --- names (D.8, OPS-15) -----------------------------------------------------------------------


def secret_names(credential: str) -> tuple[str, ...]:
    """The store entries an onboarding of ``credential`` writes or names: its client secret
    (D.7), a public client's ID (D.8) and the refresh-token slot login fills (E.2)."""
    return (f"{credential}-client-secret", f"{credential}-client-id", f"{credential}-refresh")


def _servers(policy: Policy) -> Mapping[str, RemoteServer | ToolkitServer]:
    return {} if policy.gateway is None else policy.gateway.servers


def name_taken(names: Names, policy: Policy, store_names: Collection[str]) -> str | None:
    """The first of ``names`` the running policy or the store already has, or None: a
    credential (or an entry it would write), a route (or its prefix, ``/<route>``), a server."""
    if names.credential in policy.credentials or any(
        entry in store_names for entry in secret_names(names.credential)
    ):
        return names.credential
    routes = {route.name for route in policy.routes} | {
        route.prefix.removeprefix("/") for route in policy.routes
    }
    if names.route in routes:
        return names.route
    if names.server in _servers(policy):
        return names.server
    return None


def in_use(
    policy: Policy, store_names: Collection[str], others: Collection[str] = ()
) -> Callable[[str], bool]:
    """Whether a default name is taken: as any credential, route, route prefix or server of the
    running policy, by an entry an onboarding under it would write, or by another onboarding."""
    taken = set(policy.credentials) | set(_servers(policy)) | set(others)
    for route in policy.routes:
        taken |= {route.name, route.prefix.removeprefix("/")}

    def check(name: str) -> bool:
        return name in taken or any(entry in store_names for entry in secret_names(name))

    return check


def _base_name(host: str) -> tuple[str, NameSource]:
    """A name from the host's labels: the first one before the last that isn't generic, else
    the second-to-last; a single label is its own. An address has none worth using."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return ADDRESS_NAME, "address"
    labels = [label for label in host.lower().split(".") if _NAME.fullmatch(label)]
    if not labels:
        return ADDRESS_NAME, "address"
    if len(labels) == 1:
        return labels[0], "label"
    for label in labels[:-1]:
        if label not in GENERIC_LABELS:
            return label, "label"
    return labels[-2], "second_label"


def default_name(server_url: str, taken: Callable[[str], bool]) -> tuple[str, NameSource]:
    """The default name for the server at ``server_url`` (OPS-15), with ``-2``, ``-3`` and on
    added until ``taken`` says it is free, the base shortened so the name still fits."""
    base, source = _base_name(server_host_port(server_url)[0])
    name, number = base, 1
    while taken(name):
        number += 1
        suffix = f"-{number}"
        name = base[: 63 - len(suffix)] + suffix
    return name, source


def choose_names(
    server_url: str,
    taken: Callable[[str], bool],
    *,
    name: str | None = None,
    credential: str | None = None,
    route: str | None = None,
    server: str | None = None,
) -> Names:
    """The names an onboarding adds: each one given, else ``name``, else the default."""
    source: NameSource = "given"
    if name is None:
        if credential is not None and route is not None and server is not None:
            return Names(credential, route, server)
        name, source = default_name(server_url, taken)
    return Names(credential or name, route or name, server or name, source)


# --- the second run's comparison (D.12, GR-26) -------------------------------------------------


@dataclass(frozen=True)
class Committed:
    """The running policy's credential, route and remote server for an onboarded URL."""

    credential: str
    route: str
    server: str


def committed_for(policy: Policy, server_url: str) -> Committed | None:
    """The remote server whose route's oauth2 credential names ``server_url`` as its resource,
    or whose route's upstream origin and own ``path`` are the URL's: a credential written by
    hand may have no resource, and a root-published one is the origin (D.3). The first by
    server name; None when no running credential names it."""
    routes = {route.name: route for route in policy.routes}
    for name, server in sorted(_servers(policy).items()):
        if not isinstance(server, RemoteServer) or server.route not in routes:
            continue
        route = routes[server.route]
        cred = None if route.credential is None else policy.credentials.get(route.credential)
        if not isinstance(cred, OAuth2Credential) or route.upstream is None:
            continue
        if cred.extra_params.get("resource") == server_url or (
            origin_of(route.upstream) == origin_of(server_url)
            and server.path == server_path(server_url)
        ):
            return Committed(str(route.credential), route.name, name)
    return None


@dataclass(frozen=True)
class Served:
    """A remote server reaching an onboarded URL through a route whose credential isn't
    oauth2: ``kind`` is that credential's kind, or ``none``."""

    server: str
    route: str
    credential: str | None
    kind: str


def served_at(policy: Policy, server_url: str) -> Served | None:
    """The first remote server by name whose route's upstream origin and own ``path`` are
    ``server_url``'s, whatever its route's credential: after :func:`committed_for` finds none,
    one with a static key (J1's shipped ``notes``) or no credential, which D.12 refuses
    ``already_configured`` rather than onboarding the URL a second time (OPS-14)."""
    routes = {route.name: route for route in policy.routes}
    for name, server in sorted(_servers(policy).items()):
        if not isinstance(server, RemoteServer) or server.route not in routes:
            continue
        route = routes[server.route]
        if route.upstream is None or origin_of(route.upstream) != origin_of(server_url):
            continue
        if server.path != server_path(server_url):
            continue
        cred = None if route.credential is None else policy.credentials.get(route.credential)
        return Served(name, route.name, route.credential, "none" if cred is None else cred.kind)
    return None


def token_state(
    credential: str, cred: OAuth2Credential, store_names: Collection[str]
) -> TokenState:
    """Whether a committed credential already holds a refresh token, so the second run doesn't
    sign in again (D.12 step 3, OPS-13): its ``store:`` slot, or an env seed's live slot, is in
    the store (``stored``), or an env seed waits for its first use (``seeded``)."""
    ref = cred.refresh_token or ""
    if ref.startswith("store:"):
        return "stored" if ref.removeprefix("store:") in store_names else "none"
    if ref.startswith("env:"):
        return "stored" if live_slot(credential) in store_names else "seeded"
    return "none"


def _auth_method(cred: OAuth2Credential) -> str:
    """The RFC 8414 name of how the credential authenticates at the token endpoint."""
    if cred.client_auth == "post":
        return "client_secret_post"
    if cred.client_auth == "none" or (cred.client_auth is None and cred.client_secret is None):
        return "none"
    return "client_secret_basic"


def mismatches(policy: Policy, plan: Plan) -> list[str]:
    """Every field of the committed credential, route and server that differs from what a fresh
    discovery found (D.12), by name, never by value: the endpoints as written (a query
    included, Q41), the issuer, the client authentication against the authorization server's
    methods, both ``resource`` values, the route's upstream origin and the server's path, and
    ``require_iss``, which may be stricter than the server's, never looser."""
    found = committed_for(policy, plan.server_url)
    if found is None:
        raise ValueError("no running credential names this URL")
    cred = policy.credentials[found.credential]
    assert isinstance(cred, OAuth2Credential)  # noqa: S101 - committed_for found an oauth2 one
    route: Route = next(r for r in policy.routes if r.name == found.route)
    server = _servers(policy)[found.server]
    assert isinstance(server, RemoteServer)  # noqa: S101 - committed_for found a remote one
    meta = plan.metadata
    at = f"credentials.{found.credential}"
    checks = [
        (f"{at}.token_url", cred.token_url == meta.token_endpoint),
        (f"{at}.authorize_url", cred.authorize_url == meta.authorization_endpoint),
        (f"{at}.issuer", cred.issuer == plan.issuer),
        (f"{at}.revocation_url", cred.revocation_url == meta.revocation_endpoint),
        (f"{at}.client_auth", _auth_method(cred) in meta.token_auth_methods),
        (f"{at}.extra_params.resource", cred.extra_params.get("resource") == plan.resource),
        (
            f"{at}.authorize_params.resource",
            cred.authorize_params.get("resource") == plan.resource,
        ),
        (f"{at}.require_iss", cred.require_iss or not meta.require_iss),
        (f"routes.{found.route}.upstream", route.upstream == origin_of(plan.server_url)),
        (
            f"gateway.servers.{found.server}.path",
            server.path == server_path(plan.server_url),
        ),
    ]
    return [path for path, same in checks if not same]


# --- next (M.7) --------------------------------------------------------------------------------


@dataclass(frozen=True)
class NextStep:
    """One thing for the operator to do next. ``command`` is an argument list, shown
    shell-quoted, every argument (TI-14); ``via`` says where the CLI runs it, and it adds the
    prefix. ``piped`` says stdin is redirected into it, and ``redirect`` is the fixed text after
    it (J1's files), as the CLI's own ``retry`` carries them. ``hosts`` and ``squid`` are an
    ``allow_hosts`` entry's (D.11)."""

    do: Do
    label: str
    command: tuple[str, ...] = ()
    via: Via | None = None
    hosts: tuple[str, ...] = ()
    squid: tuple[str, ...] = ()
    piped: bool = False
    redirect: str = ""

    def shell(self) -> str:
        return " ".join(shlex.quote(argument) for argument in self.command)

    def answer(self) -> dict[str, Any]:
        """The entry as the socket and the portal answer it: ``command`` already quoted."""
        out: dict[str, Any] = {"do": self.do, "label": self.label}
        if self.command:
            out["command"] = self.shell()
        if self.via is not None:
            out["via"] = self.via
        if self.hosts:
            out["hosts"] = list(self.hosts)
        if self.squid:
            out["squid"] = list(self.squid)
        if self.piped:
            out["piped"] = True
        if self.redirect:
            out["redirect"] = self.redirect
        return out


def fragment_file(server: str, number: int) -> str:
    """The file a fragment is written to in the documented commands (J1)."""
    return f"onboard-{server}-{number}.yaml"


def choices_file(server: str) -> str:
    """The choices file of ``review --choose`` in the documented commands (J1)."""
    return f"{server}.choices"


def _check(source: str, *more: str) -> tuple[tuple[str, ...], Via | None]:
    """``zoeymcp check`` against the policy's source (E.5): a one-off container for the inline
    ``ZOEYMCP_CONFIG``, else ``--config`` with the file, or ``-`` for stdin, where it is."""
    if source == INLINE_SOURCE:
        return ("check", *more), "run"
    return ("zoeymcp", "check", "--config", "-" if source == STDIN_SOURCE else source, *more), None


def allow_hosts(
    hosts: Iterable[tuple[str, int]],
    acl_names: Mapping[str, str],
    emitted_ports: Collection[int] = (),
) -> NextStep:
    """D.11's entry: the hosts an operator's proxy must allow for the vault, and the Squid
    lines for them, from ``egresslist.render`` with the vault's source ACL (``acl_names``, the
    policy's ``egress_proxy_acls`` or ``--squid-src``). The lines reuse the emitted file's
    private-destination ACL and its ``zoeymcp_port_<n>`` ACLs, one per port in
    ``emitted_ports``: a port the emitted file lacks gets its ACL line here, or Squid would
    refuse a rule naming it."""
    pairs = tuple(dict.fromkeys((host.lower(), port) for host, port in hosts))
    lists = {
        ONBOARD_SOURCE: tuple(
            Destination(host, port, False, frozenset({"onboarding"})) for host, port in pairs
        )
    }
    src = acl_names.get(egresslist.VAULT, f"zoeymcp_src_{egresslist.VAULT}")
    text = egresslist.render(lists, "squid", acl_names={ONBOARD_SOURCE: src})
    emitted = {f"acl zoeymcp_port_{port} port {port}" for port in emitted_ports}
    squid = tuple(
        line
        for line in text.splitlines()
        if line.startswith((f"acl zoeymcp_{ONBOARD_SOURCE}_", "http_access "))
        or (line.startswith("acl zoeymcp_port_") and line not in emitted)
    )
    return NextStep(
        "allow_hosts",
        "Allow these hosts in your proxy for the vault",
        hosts=tuple(netguard.entry_key(host, port) for host, port in pairs),
        squid=squid,
    )


def remove_first(served: Served) -> NextStep:
    """``already_configured``'s entry (OPS-14): what to take out of the policy before the URL
    can be onboarded."""
    parts = [f"gateway.servers.{served.server}", f"routes {served.route}"]
    if served.credential is not None:
        parts.append(f"credentials.{served.credential}")
    return NextStep(
        "fix_policy",
        f"Remove {', '.join(parts[:-1])} and {parts[-1]} from the policy, reload, then run this "
        "command again",
    )


def committed_next(found: Committed, held: TokenState) -> tuple[NextStep, ...]:
    """The second run's steps after its comparison (D.12 steps 3 and 4): sign in, unless the
    credential holds a refresh token, then choose the server's tools (J1, F.5): the choices file
    and, once edited, fragment 2 from it, both through the vault's job path, which reads the
    review the second run queued once it is done (OPS-11)."""
    steps = []
    if held == "none":
        steps.append(NextStep("connect", "Sign in", ("zoeymcp", "login", found.credential), "exec"))
    return (*steps, *choose_next(found.server))


def choose_next(server: str) -> tuple[NextStep, ...]:
    """Choosing a reviewed server's tools (J1, F.5): the choices file and, once edited, fragment
    2 from it, both through the vault's job path, which reads the review queued last once it is
    done (OPS-11)."""
    review = ("zoeymcp", "review", server, "--via", "vault")
    choices = choices_file(server)
    return (
        NextStep(
            "choose",
            "Choose its tools",
            (*review, "--choose", "--suggest"),
            "exec",
            redirect=f" > {choices}",
        ),
        NextStep(
            "make_fragment",
            # Declining the rest ends the review quiet (M6 design J.5).
            f"Edit {choices} (skip, allow, approve or decline on each line; decline the tools "
            "you leave out), then make fragment 2",
            (*review, "--choices", "-"),
            "exec",
            piped=True,
            redirect=f" < {choices} > {fragment_file(server, 2)}",
        ),
    )


# The review job refusals whose way on is a fresh review (M6 design M.7, D-200): a server busy
# or a queue full once the other review ends, a job its clock, the gateway or its report ended,
# and a clear that found an included tool not matching its pin, which the review shows.
REVIEW_AGAIN: Final = frozenset(
    {
        "review_busy",
        "review_jobs_full",
        "review_stale",
        "review_timeout",
        "review_failed",
        "review_invalid",
        "review_too_large",
        "pin_mismatch",
        "clear_not_clean",
    }
)


def review_again(server: str) -> NextStep:
    """A fresh review of ``server`` through the vault's job path, never the finished one."""
    review = ("zoeymcp", "review", server, "--via", "vault", "--fresh")
    return NextStep("review", "Review again", review, "exec")


# The host's copy of the policy in managed_next's commands (M6 design H.5, H.6).
EXPORT_FILE: Final = "policy.yaml"


def managed_next(via: Via | None = "exec") -> tuple[NextStep, ...]:
    """In managed mode, the way to change the policy that a fragment is in declarative mode (M6
    design G.9, Y25): a save in the portal, or the host's export, edit and import. ``via`` is
    where the two commands run: ``exec`` in the vault's service, or None where the CLI can't name
    that service (the gateway's container), saying where in the label instead. Both take ``-T``:
    the export's stdout and the import's stdin are files. Without ``--yes`` the import shows its
    plan and writes nothing."""
    where = "" if via is not None else " (in the vault's container)"
    export = ("zoeymcp", "policy", "export")
    imported = ("zoeymcp", "policy", "import", "-")
    return (
        NextStep("save", "Save the change in the portal"),
        NextStep(
            "export_policy",
            f"Or export the policy{where}",
            export,
            via,
            piped=True,
            redirect=f" > {EXPORT_FILE}",
        ),
        NextStep(
            "import_policy",
            f"Edit {EXPORT_FILE}, then import it{where}; it shows the plan, and the same with "
            "--yes writes it",
            imported,
            via,
            piped=True,
            redirect=f" < {EXPORT_FILE}",
        ),
    )


def job_next(server: str, *, clear: bool, managed: bool = False) -> tuple[NextStep, ...]:
    """A finished job's way on (D-200): after a review, choosing the server's tools, or in
    managed mode saving them (:func:`managed_next`, Y25); after a clear, nothing."""
    if clear:
        return ()
    return managed_next() if managed else choose_next(server)


def refusal_next(server: str | None, reason: str) -> tuple[NextStep, ...]:
    """A review job refusal's way on (D-200): a fresh review for :data:`REVIEW_AGAIN`'s; the
    clear in the gateway's own container, as before, while the gateway runs no clear jobs
    (``clear_unsupported``); else nothing the CLI can do (a name the policy doesn't have, a
    gateway that isn't polling, an unknown job). None when no server is known."""
    if server is None:
        return ()
    if reason == "clear_unsupported":
        clear = ("zoeymcp", "review", server, "--clear")
        return (NextStep("clear", "Clear the marks in the gateway's container", clear),)
    return (review_again(server),) if reason in REVIEW_AGAIN else ()


# A managed write's effects as the operator's steps (M6 design I.2, M.7): the kinds a step
# names by its own words; the rest say it in the effect's text.
_DELIVER: Final[Mapping[str, NextStep]] = {
    "redeliver_gateway_key": NextStep(
        "deliver_key",
        "Give the gateway its new key within 5 minutes",
        ("zoeymcp", "gateway-key"),
        "exec",
    ),
    "redeliver_egress_key": NextStep(
        "deliver_key",
        "Write the egress role's new key, then restart the role",
        ("zoeymcp", "egress-key"),
        "exec",
    ),
}
# The vault's own restart, by the host's compose command (J15's line, M.7).
RESTART_VAULT: Final = NextStep(
    "restart", "Restart the vault: the change waits for it", via="restart"
)
WAIT_GATEWAY: Final = NextStep("wait_gateway", "The gateway takes the new view within seconds")


def saved_next(effects: Iterable[Effect], *, applied: bool = False) -> tuple[NextStep, ...]:
    """A managed write's way on (M6 design M.7, I.2, Y16): the vault's restart first, once,
    when any effect needs it; then a step per other effect that asks something of the operator,
    in order (a key to give, the gateway or a bridge to restart, a proxy's allowlist); and, until
    the gateway has applied the revision, that it takes the new view within seconds. A ``live``
    effect asks nothing."""
    steps: list[NextStep] = []
    for effect in effects:
        if effect.kind == "vault_restart":
            if RESTART_VAULT not in steps:
                steps.insert(0, RESTART_VAULT)
        elif effect.kind in _DELIVER:
            steps.append(_DELIVER[effect.kind])
        elif effect.kind == "reemit_proxy_allowlist":
            steps.append(NextStep("update_proxy_allowlist", effect.text))
        elif effect.kind != "live":
            steps.append(NextStep("restart", effect.text))
    if not applied:
        steps.append(WAIT_GATEWAY)
    return tuple(steps)


def onboard_again(server_url: str) -> NextStep:
    """Every ``onboard_again`` entry: register a new client under the same names (OPS-3)."""
    return NextStep(
        "onboard_again",
        "Register a new client",
        ("zoeymcp", "login", "--mcp", server_url, "--reregister"),
        "exec",
    )


# --- the portal's server rows (K.1, GR-21) ------------------------------------------------------

ServerKind = Literal["remote", "toolkit"]
RowState = Literal["needs_connect", "needs_review", "reviewed"]


@dataclass(frozen=True)
class Listed:
    """A server of the running policy as the portal lists it (K.1): its kind, its tools and
    ``on_drift`` as the policy has them, the clients it is assigned to, and for a remote server
    whose route has an oauth2 credential, that credential, the resource it names (D.12) and,
    for a ``refresh_token`` grant, whether it holds a refresh token (OPS-13): a
    ``client_credentials`` grant never holds one, and needs no sign-in. ``review`` and
    ``declined`` are the policy's pins and declined block, which a review report made before a
    re-pin or a decline no longer matches (M6 design J.2, J.5)."""

    name: str
    kind: ServerKind
    tools: Tools
    on_drift: str
    clients: tuple[str, ...] = ()
    credential: str | None = None
    resource: str | None = None
    held: TokenState | None = None
    declined: Mapping[str, str] = field(default_factory=dict)
    review: Mapping[str, str] = field(default_factory=dict)

    @property
    def state(self) -> RowState:
        """``needs_connect`` until its credential holds a refresh token, then ``needs_review``
        while it includes no tool, then ``reviewed``."""
        if self.held == "none":
            return "needs_connect"
        return "reviewed" if self.tools.include else "needs_review"


def listed_servers(policy: Policy, store_names: Collection[str]) -> tuple[Listed, ...]:
    """Every server a review job can be queued for (F.2), remote or toolkit, by name."""
    routes = {route.name: route for route in policy.routes}
    clients = {} if policy.gateway is None else policy.gateway.clients
    found = []
    for name, server in sorted(_servers(policy).items()):
        assigned = tuple(sorted(c for c, client in clients.items() if name in client.servers))
        listed = Listed(
            name,
            "toolkit" if isinstance(server, ToolkitServer) else "remote",
            server.tools,
            server.on_drift,
            assigned,
            declined=dict(server.declined),
            review=dict(server.review),
        )
        if isinstance(server, ToolkitServer):
            found.append(listed)
            continue
        route = routes.get(server.route)
        credential = None if route is None else route.credential
        cred = None if credential is None else policy.credentials.get(credential)
        if credential is not None and isinstance(cred, OAuth2Credential):
            held = None
            if cred.grant == "refresh_token":
                held = token_state(credential, cred, store_names)
            found_resource = cred.extra_params.get("resource")
            resource = found_resource if isinstance(found_resource, str) else None
            listed = replace(listed, credential=credential, resource=resource, held=held)
        found.append(listed)
    return tuple(found)


def listed_server(policy: Policy, name: str, store_names: Collection[str] = ()) -> Listed | None:
    """The server ``name`` as :func:`listed_servers` lists it, or None."""
    return next((s for s in listed_servers(policy, store_names) if s.name == name), None)


def tools_max(policy: Policy) -> int:
    """``gateway.limits.max_tools_per_server``: the most tools a list of a server's may name."""
    limits = GatewayLimits() if policy.gateway is None else policy.gateway.limits
    return limits.max_tools_per_server


def listed_next(listed: Listed) -> tuple[NextStep, ...]:
    """A row's steps (K.1): connect, else review its tools, else review them again, and for an
    onboarded credential register a new client (OPS-3). The page's button does the first; each
    command is the CLI's way to the same."""
    review = ("zoeymcp", "review", listed.name, "--via", "vault")
    if listed.state == "needs_connect" and listed.credential is not None:
        login = ("zoeymcp", "login", listed.credential)
        return (NextStep("connect", "Connect", login, "exec"),)
    if listed.state == "needs_review":
        return (NextStep("review", "Review tools", review, "exec"),)
    steps = [NextStep("review", "Review again", review, "exec")]
    if listed.resource is not None:
        steps.append(onboard_again(listed.resource))
    return tuple(steps)


@dataclass(frozen=True)
class Widened:
    """A credential's scope widened: the union as the fragment writes it, and the fragment."""

    scope: str
    fragment: str


def widen_scope(policy: Policy, credential: str, challenged: Collection[str]) -> Widened | None:
    """An ``upstream_insufficient_scope`` finding's fix (D.5's step-up, SPEC-11): a fragment
    setting the running credential's ``scope`` to the union of its own and the scope an
    upstream's challenge asked for, its own tokens first, merged into the credential (the rest of
    it kept). None when the challenge adds no token, or when the union is no scope the credential
    can hold (a token holding its separator, too many, too long): the finding then says to sign
    in again, as before. The vault never widens a scope itself: the operator commits and
    connects."""
    cred = policy.credentials.get(credential)
    if not isinstance(cred, OAuth2Credential):
        return None
    held = split_scope(cred.scope, cred.scope_separator)
    # The schema lets a scope repeat a token, so new ones are looked for, not counted.
    if set(challenged) <= set(held):
        return None
    union = tuple(dict.fromkeys([*held, *challenged]))
    try:
        op = SetScope(credential, union, cred.scope_separator)
        change = PolicyChange(f"widen the scope of {credential}", (op,))
        apply(policy, change)
        return Widened(op.scope, emit(change))
    except ValueError:  # ChangeRefused and EmitRefused are ones
        return None


def _login_again(record: OnboardingRecord) -> tuple[str, ...]:
    """The second ``login --mcp``, with the names and the discovery options of the first."""
    names = record.names
    command = ["zoeymcp", "login", "--mcp", record.server_url]
    if names.credential == names.route == names.server:
        command += ["--name", names.credential]
    else:
        command += [
            "--credential",
            names.credential,
            "--route",
            names.route,
            "--server",
            names.server,
        ]
    if record.options.issuer is not None:
        command += ["--issuer", record.options.issuer]
    if record.options.allow_private:
        command.append("--allow-private")
    return tuple(command)


def _make(record: OnboardingRecord) -> tuple[NextStep, ...]:
    errors = sum(1 for finding in record.draft_check if finding.level == "error")
    if errors:
        return (
            NextStep(
                "fix_policy",
                f"Fix the policy first: check finds {errors} error(s) with this server merged",
            ),
        )
    options = record.options
    if options.client_id is None:
        return (NextStep("register", "Register and make the YAML"),)
    if options.secret_given:
        return (NextStep("register", "Store the secret and make the YAML"),)
    return (NextStep("make_fragment", "Make the YAML"),)


def _applied(server: str, number: int, source: str, merge: str) -> list[NextStep]:
    """How fragment ``number`` of ``server`` is applied for the policy's source (E.5): checked
    with the policy, merged as ``merge`` says, the edited policy checked, then the vault
    reloaded, or recreated for an inline policy."""
    fragment = fragment_file(server, number)
    if source == INLINE_SOURCE:
        check_fragment = NextStep(
            "check_fragment",
            f"Check fragment {number} with the running policy",
            ("check", "--with", f"/w/{fragment}"),
            "run_mount",
        )
        reload = NextStep("reload", "Commit, then recreate the vault", via="up")
    else:
        command, via = _check(source, "--with", fragment)
        check_fragment = NextStep(
            "check_fragment", f"Check fragment {number} with the policy", command, via
        )
        restart = (
            "send the vault SIGHUP (docker kill -s HUP)"
            if source != STDIN_SOURCE
            else "restart the vault with the new policy"
        )
        reload = NextStep("reload", f"Commit, then {restart}")
    command, via = _check(source)
    return [
        check_fragment,
        NextStep("commit_fragment", merge),
        NextStep("check_policy", "Then check the edited policy", command, via),
        reload,
    ]


def _commit(record: OnboardingRecord, source: str, own_proxy: bool) -> tuple[NextStep, ...]:
    if source == INLINE_SOURCE:
        merge = (
            "Merge it into the policy under ZOEYMCP_CONFIG in the compose form (--for compose), "
            "or print the whole merged block with --print-merged --for compose and replace it"
        )
    else:
        merge = (
            "Merge it into the policy, or print the whole merged policy with --print-merged and "
            "replace it"
        )
    steps = _applied(record.names.server, 1, source, merge)
    if own_proxy:
        command, via = _check(source, "--emit-egress-allowlist", "--allowlist-format", "squid")
        steps.append(
            NextStep(
                "update_proxy_allowlist",
                "Update your proxy's allowlist from the committed policy, reload your proxy, "
                "then remove the onboarding lines",
                command,
                via,
            )
        )
    if record.options.reregister:
        # The committed credential keeps its old grant until a sign-in with the new client,
        # which discards it on purpose: --rebind, since a token endpoint that moved changes the
        # old grant's binding.
        login = ("zoeymcp", "login", record.names.credential, "--rebind")
        steps.append(NextStep("connect", "Then sign in with the new client", login, "exec"))
    else:
        steps.append(NextStep("connect", "Then sign in and review", _login_again(record), "exec"))
    return tuple(steps)


def reviewed_next(server: str, source: str) -> tuple[NextStep, ...]:
    """What the operator does after fragment 2 of ``server`` (E.4, M.7), the same words on every
    surface: apply it as fragment 1 was, its two blocks replacing the server's, then assign the
    server to its clients, which fragment 2 never does (GR-D2, Q33)."""
    blocks = f"the tools: and review: blocks of gateway.servers.{server}"
    if source == INLINE_SOURCE:
        merge = (
            f"Replace {blocks} under ZOEYMCP_CONFIG with it, in the compose form (--for compose)"
        )
    else:
        merge = f"Replace {blocks} with it"
    assign = NextStep(
        "assign_clients",
        f"Then add {server} to gateway.clients.<client>.servers for each client that should "
        "reach it",
    )
    return (*_applied(server, 2, source, merge), assign)


def next_for(
    record: OnboardingRecord,
    source: str,
    *,
    own_proxy: bool = False,
    acl_names: Mapping[str, str] | None = None,
    emitted_ports: Collection[int] = (),
) -> tuple[NextStep, ...]:
    """What the operator does next for ``record`` (M.7), the same words on every surface.
    ``source`` is the running policy's (``load.read_source``'s label: a file path,
    ``<stdin>`` or ``$ZOEYMCP_CONFIG``); ``own_proxy`` is an ``egress_proxy`` that isn't the
    built-in role; ``acl_names`` its Squid source ACLs; ``emitted_ports`` the ports whose ACLs
    the policy's emitted Squid file defines. A blocked onboarding's ``retry`` is the CLI's own,
    from its argv (D.11)."""
    if record.stage == "blocked":
        return (allow_hosts(record.needed_hosts, acl_names or {}, emitted_ports),)
    if record.stage == "discovered":
        return _make(record)
    if record.stage == "registered":
        return _commit(record, source, own_proxy)
    return ()
