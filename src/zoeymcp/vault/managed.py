"""Managed mode's running policy (M6 design F.2-F.6, G.6, K.1, M.5; Q31, Q37, Q39; Y1, Y16; G-3,
G-5, MISS-9). I/O.

The start (``vault/server.py``) opens the policy store and decides (``policystart.decide``);
from then on a managed vault's policy belongs to :class:`ManagedPolicy`: the store, the head that
runs, its ratchet, whether a saved revision isn't running (``_not_running``), and the map from
each revision this process installed to the view digest the install built (K.1), which starts
with the head's.

:meth:`ManagedPolicy.write` is the one write path (G.1, G.6). It is synchronous from its first
line to its return (G-3): there is no ``await`` in it, so on the vault's one event loop no other
request runs between its check of the head and its install, and two writes can't interleave
(T29, FM-15). The lock covers code that runs in a thread. In order: a saved revision that isn't
running refuses every write (``policy_not_running``); a write planned on another revision is a
retry whose answer was lost (``already_saved``, MISS-9, FM-16) or ``policy_moved``; the candidate
built on the head passes the gate (C) and the planner (G.5), whose plan must be the one the
caller confirmed (``changed`` for the portal's, ``plan_changed`` for the socket's digest,
:func:`plan_digest`); ``gatewaykeys.check`` refuses a lower gateway key generation before any
file is written (G-4); then the commit (D.9) and the install. An install that can't write the
gateway-key state leaves the revision committed and the old head running: the write answers
``saved_not_running``, the vault logs ``policy_not_installed`` and health says
``policy_not_running`` until a ``SIGHUP`` installs the head (:meth:`ManagedPolicy.reverify`,
F.6, G-5, FM-5).

:meth:`ManagedPolicy.reverify` is a managed ``SIGHUP``: the store read again (with its
housekeeping, as at a start), the head's policy through the gate with this vault's environment,
the head installed when it isn't the one running, and the configured source compared with the
seed and the head (F.5). It never applies the source (DD-7, Y19).

The vault states its running head beside every view answer, and the gateway's status report
carries what the gateway has seen of it (the restore witness, K.3): :meth:`ManagedPolicy.witness`
compares the two (``statusreport.witnessed``); health raises ``policy_behind_witness`` or
``policy_deployment_changed`` from it, and the vault logs either (critical) when a report first
shows it. :func:`acknowledge_shaped` is ``zoeymcp policy acknowledge-restore``'s write: the
head's content, numbered one above the gateway's claim (:func:`jumped`), so the counter passes
it and the finding clears.

The portal's saves (G.3, G.4, J.4) plan and write here too: :meth:`ManagedPolicy.marked` gives
the planner the tools the gateway's latest status marks, :attr:`ManagedPolicy.ratchet` the head
ratchet whose ``approved`` set the review rows' ``prefill`` reads, and :func:`allow_pin` the pin
a move from a server's page shows a definition at. Health's ``gateway_view_behind`` is a gateway
still on another view than the head's :data:`GATEWAY_APPLY_GRACE` after the install (K.1).

:class:`DeclarativeStore` is a declarative start's view of a store it found (F.4): the head it
parked, what the running policy brings back that the parked ratchet retired (T-16), or why the
store wasn't read. :func:`commands` builds the host's commands a start refusal names from
``ZOEYMCP_COMPOSE_CMD`` and the tier (``policystart.Commands``).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from string import Formatter
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from ..common.canonical import digest
from ..common.logs import refuse_type
from ..common.policy import diff, gate, restart
from ..common.policy.emit import Target
from ..common.policy.export import Mode, export, notes
from ..common.policy.gate import GateRefused
from ..common.policy.plan import (
    BindingState,
    PlanInput,
    PlanRefused,
    Surface,
    WriteKind,
    WritePlan,
    carry_forward,
    direction,
    document,
    normalize,
    normalized_digest,
    plan,
)
from ..common.policy.ratchet import DefKey, Grants, Ratchet, violations
from ..common.policy.restart import Effect
from ..common.policy.reviewchange import Lines
from ..common.policy.schema import Policy, ToolkitServer
from ..common.suggest import Suggestion
from ..portal import policydiffview
from ..portal.policyview import saved
from ..portal.refusals import CATALOGUE, Refusal, refusal
from . import gatewaykeys, health, logs
from .app import VaultApp
from .gatewaykeys import GatewayKeyError
from .onboarding import NextStep, saved_next
from .policyseal import Head, Unsealed
from .policystart import Commands, Ok, Refused, SeedIgnored, Source, before
from .policystore import HISTORY_PAGE_MAX, KEEP, Committed, PolicyStore, StoreRefused
from .statusreport import Report, Witnessed, witnessed
from .store import SecretStore

# The refusals a write itself gives; the planner's and the store's pass through by their own
# reasons. portal/refusals.py catalogues every one (N.2).
Reason = Literal[
    "policy_not_running",
    "policy_moved",
    "changed",
    "plan_changed",
    "import_refused",
    "generation_lowered",
    "saved_not_running",
]

# How the host runs the vault's service (the onboarding's M.7 names, cli/onboard.py): the compose
# command and the service, by default the shipped hardened file's; the standard tier runs a
# one-off container as the vault's uid (OPS-5).
COMPOSE_CMD_ENV: Final = "ZOEYMCP_COMPOSE_CMD"
EXEC_SERVICE_ENV: Final = "ZOEYMCP_EXEC_SERVICE"
DEFAULT_COMPOSE_CMD: Final = "docker compose -f deploy/compose.hardened.yaml"
DEFAULT_SERVICE: Final = "vault"
STANDARD_USER: Final = "10001:10001"
# What a declarative policy can bring back that a parked ratchet retired (F.4, T-16).
REVIVALS: Final = frozenset({"revives_client", "revives_caller", "pin_retired"})
# The effects health keeps as policy_restart_needed until a restart (I.2).
_RESTARTS: Final = frozenset({"vault_restart", "gateway_restart"})
# The event each host command's revision is logged as; every other kind is policy_saved (N.3).
_SAVED_EVENTS: Final = {
    "policy.rollback": "policy_rolled_back",
    "policy.import": "policy_imported",
    "policy.acknowledge": "policy_acknowledged",
}
_SERVER_MODELS: Final = frozenset({"RemoteServer", "ToolkitServer"})
# How long the gateway may take a new view before health says it is behind (K.1, M.5, N.4).
GATEWAY_APPLY_GRACE: Final = 30.0


def commands(environ: Mapping[str, str], state: str, *, standard: bool) -> Commands:
    """The host's commands for a start refusal's recoveries (J5b, J11, J16): the compose command
    and service the container's environment names, ``--user 10001:10001`` in the standard tier
    (``standard``: the vault has the gateway link socket), and the state directory."""
    return Commands(
        environ.get(COMPOSE_CMD_ENV) or DEFAULT_COMPOSE_CMD,
        environ.get(EXEC_SERVICE_ENV) or DEFAULT_SERVICE,
        STANDARD_USER if standard else None,
        state,
    )


def acknowledge_command(environ: Mapping[str, str]) -> str:
    """``acknowledge-restore`` as the host runs it in the vault's service (J11, OPS-10): the
    compose command and service from the container's environment."""
    compose = environ.get(COMPOSE_CMD_ENV) or DEFAULT_COMPOSE_CMD
    service = environ.get(EXEC_SERVICE_ENV) or DEFAULT_SERVICE
    return f"{compose} exec {service} zoeymcp policy acknowledge-restore"


def head_policy(found: Ok) -> Policy:
    """The policy the head's revision holds. Raises ``ValueError`` when the schema refuses it."""
    return Policy.model_validate(dict(found.top.body.policy))


def revived(ratchet: Ratchet, head: Policy, policy: Policy) -> tuple[str, ...]:
    """What ``policy`` brings back that ``ratchet`` retired, against ``head`` (F.4, T-16): each
    client, caller or pin, by its grant subject (``client:<name>``), in ``policy``'s order."""
    found = violations(ratchet, head, policy, verified=frozenset(), grants=Grants())
    return tuple(v.subject for v in found if v.reason in REVIVALS)


def seed_ignored(source: Source | None, found: Ok) -> SeedIgnored | None:
    """F.5: why the configured ``source`` is ignored, or None when there is none or it is the
    head's seed or the head itself."""
    if source is None:
        return None
    if isinstance(source.admitted, GateRefused):
        return "unreadable" if source.admitted.reason == "unreadable" else "fails_check"
    return None if source.digest in (found.seed_digest, found.policy_digest) else "changed"


def bindings(secrets: SecretStore) -> Callable[[Policy], Mapping[str, BindingState]]:
    """``PlanInput.bindings``: every stored secret a policy uses, and health's verdict on its
    binding there (D-10's preview); a secret the store doesn't hold has none."""

    def judged(policy: Policy) -> Mapping[str, BindingState]:
        report = health.assess(health.Inputs(policy, secrets.metadata(), frozenset()))
        found: dict[str, BindingState] = {}
        for section in (*report["credentials"], *report["connectors"]):
            for row in section["refs"]:
                verdict = row["binding"]
                if row["ref"].startswith("store:") and verdict in ("ok", "changed", "wider"):
                    found[row["ref"].removeprefix("store:")] = verdict
        return found

    return judged


def plan_digest(planned: WritePlan) -> str:
    """The digest a socket write names in ``X-ZoeyMCP-Plan`` (G.6 step 4): the kind, the base, the
    rows the operator read and the policy the revision would hold."""
    return digest(
        {
            "kind": planned.kind,
            "base": planned.base,
            "base_digest": planned.base_digest,
            "rows": [list(row) for row in planned.rows],
            "policy": normalized_digest(planned.policy),
        }
    )


def _digest8(value: str) -> str:
    return value.removeprefix("sha256:")[:8]


def _author(author: Mapping[str, str]) -> str:
    """The author as a log line names it: a passkey's fingerprint's first 8, or ``host``."""
    return author["fingerprint"][:8] if author["by"] == "passkey" else author["by"]


@dataclass(frozen=True)
class Evidence:
    """What a write's surface read besides the policy, for the planner (G.5): the pins its review
    verified and the tools it showed drifted, the definitions it shows for each allow, the shared
    rule's suggestions, the marked and consequential tools, and a rollback's target."""

    verified: frozenset[tuple[DefKey, str]] = frozenset()
    drifted: frozenset[DefKey] = frozenset()
    definitions: Mapping[DefKey, Lines] = field(default_factory=dict)
    suggested: Mapping[DefKey, Suggestion | None] = field(default_factory=dict)
    marked: frozenset[DefKey] = frozenset()
    consequential: frozenset[DefKey] = frozenset()
    target: Policy | None = field(default=None, repr=False)
    target_revision: int | None = None


@dataclass(frozen=True)
class Written:
    """A committed write: its revision and digest, the plan's effects (I.2), the gateway's
    state, ``pending`` until its status shows the new view (K.1), and what the operator does
    next (M.7). ``already_saved`` answers a retry of the write that made the head (G.6 step 2).
    ``captured`` is what the write's ``capture`` took inside the section (G.8)."""

    revision: int
    digest: str
    effects: tuple[Effect, ...] = ()
    already_saved: bool = False
    gateway: str = "pending"
    next: tuple[NextStep, ...] = ()
    captured: Any = field(default=None, repr=False)


@dataclass(frozen=True)
class WriteRefused:
    """A write that took no effect, or (``saved_not_running``) one committed and not running.
    ``reason`` is one of :data:`Reason`, the planner's or the store's; ``detail`` what its
    sentence names; ``subjects`` and ``next`` the planner's; ``revision`` the head's (or the one
    saved but not running); ``plan`` the re-plan a ``changed`` or ``plan_changed`` compared."""

    reason: str
    detail: str = ""
    subjects: tuple[str, ...] = ()
    next: str | None = None
    revision: int | None = None
    plan: WritePlan | None = field(default=None, repr=False)


def refused_answer(refused: WriteRefused) -> Refusal:
    """A write's refusal as the catalogue words it (N.2): its text filled with the fields it
    names, of the refusal's ``detail`` and ``revision``."""
    text = CATALOGUE[refused.reason].text
    wanted = {name for _, name, _, _ in Formatter().parse(text) if name is not None}
    offered = {"detail": refused.detail, "revision": str(refused.revision)}
    return refusal(refused.reason, **{k: v for k, v in offered.items() if k in wanted})


@dataclass(frozen=True)
class Lockout:
    """A host write's lockout row (I.1, G-17): what it does, and what the operator types to
    confirm it (the origin it removes, or where the portal will listen)."""

    text: str
    confirm: str


def _host(origin: str) -> str:
    return (urlsplit(origin).hostname or "").lower()


def lockout_rows(
    head: Policy, candidate: Policy, rp_ids: Iterable[str] | None
) -> tuple[Lockout, ...]:
    """The rows of a host write that can lock the portal out (I.1, G-17, Y17): each ``admin``
    origin it removes whose host is the RP ID of an enrolled passkey (``rp_ids``, every
    passkey's) and no origin it keeps has, and a changed ``admin.listen``. ``rp_ids`` None means
    the passkey file can't be read: every such removed origin is a row then (fail closed)."""
    before, after = head.admin, candidate.admin
    if before is None:
        return ()
    kept = [] if after is None else after.origins
    hosts = {_host(origin) for origin in kept}
    enrolled = None if rp_ids is None else [rp_id.lower() for rp_id in rp_ids]
    rows: list[Lockout] = []
    for origin in before.origins:
        if origin in kept or _host(origin) in hosts:
            continue
        if enrolled is None:
            text = (
                f"removes {origin}: the passkey file can't be read, so passkeys enrolled "
                "through it may stop working"
            )
            rows.append(Lockout(text, origin))
            continue
        count = enrolled.count(_host(origin))
        if count == 1:
            text = f"removes {origin}, where 1 passkey was enrolled: it stops working"
            rows.append(Lockout(text, origin))
        elif count:
            text = f"removes {origin}, where {count} passkeys were enrolled: they stop working"
            rows.append(Lockout(text, origin))
    if after is not None and after.listen != before.listen:
        text = (
            f"moves the portal from {before.listen} to {after.listen}: after the vault's "
            "restart it listens there"
        )
        rows.append(Lockout(text, str(after.listen)))
    return tuple(rows)


def widenings(planned: WritePlan) -> list[str]:
    """A plan's widening rows by path (G.7 row 2, Q41): each move to allow, and each change the
    planner's direction calls wider (a new client, caller or origin among them)."""
    moved = [f"{server}.{name}" for server, _, name in planned.moves]
    wider = [
        ".".join(str(part) for part in change.path)
        for change in planned.changes
        if direction(change, planned.policy) == "wider"
    ]
    return moved + [path for path in wider if path not in moved]


def widens(planned: WritePlan) -> bool:
    """Whether a plan holds a widening row (:func:`widenings`)."""
    return bool(widenings(planned))


def imported(head: Policy, given: Policy) -> Policy:
    """An import's candidate (H.5 step 4): the document with, from the head, the pin of every
    definition both hold (an import can't re-pin: that is a review) and ``declined`` the union
    less what the document includes (T-9), as a host rollback's carry-forward takes them, with
    ``admin`` and the key generations as the document gives them: an import is how the host
    changes ``admin`` (I.1) and rotates a key (J15), and the ratchet refuses a lower
    generation (E1)."""
    data = document(carry_forward(head, given, host=True))
    for name in ("gateway_key_generation", "egress_key_generation"):
        data[name] = getattr(given, name)
    return Policy.model_validate(data)


def plan_on(
    store: PolicyStore,
    head: Policy,
    ratchet: Ratchet,
    kind: WriteKind,
    surface: Surface,
    candidate_of: Callable[[Policy], Policy],
    *,
    environ: Mapping[str, str],
    started: restart.Started,
    bindings: Callable[[Policy], Mapping[str, BindingState]],
    grants: Grants,
    evidence: Evidence,
) -> WritePlan | WriteRefused:
    """G.6 steps 3 and 4 on the store's head (``head``, with its ``ratchet``): the candidate
    ``candidate_of`` builds from it, through the gate with ``environ`` (C), then the planner
    (G.5), with the history lookup for its refusal texts. The running vault's write and the
    host's offline forms (``cli/policy.py``) both plan here. ``candidate_of``'s own errors
    (``ValueError``) pass through."""
    top = store.head
    if top is None:
        raise ValueError("a write needs a store with a head")
    try:
        candidate = gate.admit(candidate_of(head), f"revision {top.revision + 1}", environ=environ)
    except GateRefused as exc:
        return WriteRefused("import_refused", str(exc))
    planned = plan(
        PlanInput(
            kind=kind,
            surface=surface,
            head=head,
            head_revision=top.revision,
            head_digest=top.digest,
            ratchet=ratchet,
            candidate=candidate.policy,
            started=started,
            bindings=bindings,
            verified=evidence.verified,
            drifted=evidence.drifted,
            definitions=evidence.definitions,
            suggested=evidence.suggested,
            marked=evidence.marked,
            consequential=evidence.consequential,
            grants=grants,
            target=evidence.target,
            target_revision=evidence.target_revision,
            removed_in=store.removed_lookup(candidate.policy),
        )
    )
    if isinstance(planned, PlanRefused):
        return WriteRefused(planned.reason, planned.detail, planned.subjects, planned.next)
    return planned


def lowered(state: gatewaykeys.State | None, planned: WritePlan) -> WriteRefused | None:
    """G.6 step 5 (G-4): a gateway key generation below the gateway-key state, refused before
    any file is written; None without a state to compare."""
    if state is None:
        return None
    found = gatewaykeys.check(state, planned.policy.gateway_key_generation)
    return None if found is None else WriteRefused("generation_lowered", found.reason)


def moved(header: Mapping[str, Any] | None, revision: int) -> str:
    """``policy_moved``'s detail (G.6 step 2, N.2): the head ``revision`` with when and by whom
    it was written, as the policy view names it (A.4), from its ``header``."""
    said = f"revision {revision}" if header is None else saved(header)
    return f"the policy moved to {said} since you started"


def allow_pin(policy: Policy, server: str, name: str) -> tuple[str | None, bool]:
    """What a move to allow from a server's page shows a definition at (J.4, T-11): ``policy``'s
    pin for the tool, if any, and whether the server is a ``pinning: off`` toolkit, which holds
    none (the dialog's pin is then the one to show)."""
    entry = None if policy.gateway is None else policy.gateway.servers.get(server)
    off = isinstance(entry, ToolkitServer) and entry.pinning == "off"
    return (None if entry is None else entry.review.get(name)), off


def author_shown(author: Mapping[str, str]) -> str:
    """The author as a log line names it: a passkey's fingerprint's first 8, or ``host``."""
    return _author(author)


class ManagedPolicy:
    """A managed vault's policy, from a store whose head ``policy`` (with its ``ratchet``) the
    ``app`` runs. ``secrets`` is the store whose bindings a plan previews; ``environ`` the vault's
    environment, which every candidate is checked with; ``started`` what the vault started with
    (the restart classifier's, I.2, with the launcher's bridges); ``reopen`` opens the store
    again for a ``SIGHUP``; ``seed_ignored`` the start's F.5 answer; ``installed`` is told every
    policy installed after the start (the portal's origins); ``wall`` dates the installs."""

    def __init__(
        self,
        store: PolicyStore,
        app: VaultApp,
        *,
        policy: Policy,
        ratchet: Ratchet,
        secrets: SecretStore,
        environ: Mapping[str, str],
        started: restart.Started,
        reopen: Callable[[], PolicyStore],
        seed_ignored: SeedIgnored | None = None,
        installed: Callable[[Policy], None] | None = None,
        wall: Callable[[], float] = time.time,
    ) -> None:
        head = store.head
        if head is None:
            raise ValueError("a managed policy needs a store with a head")
        self._store = store
        self._app = app
        self._policy = policy
        self._ratchet = ratchet
        self._bindings = bindings(secrets)
        self._environ = environ
        self._started = started
        self._reopen = reopen
        self._seed_ignored = seed_ignored
        self._installed = installed
        self._wall = wall
        self._lock = threading.Lock()
        # The revision committed whose install failed (G.6 step 8), until one succeeds.
        self._not_running: int | None = None
        # The running head's digest and header (the policy view names the revision it shows,
        # G.10), and what the vault started with, for the restart notes.
        self._running = head.digest
        self._running_header = store.header
        self._startup = app.policy
        self._effects: tuple[Effect, ...] = ()
        # Each gateway restart note's path, and when the install that last raised it ran: the
        # note is done once the gateway started after that, whatever was installed since.
        self._raised_at: dict[str, float] = {}
        # Each revision this process installed, and the view digest the install built (K.1).
        self._digests: dict[int, str] = {head.revision: app.view_digest}
        # When the running head was installed, for gateway_view_behind's grace (K.1, M.5).
        self._installed_at = wall()
        # What the restore witness last showed of the head, once logged (K.3, N.3).
        self._witness_logged: tuple[int | None, tuple[str, int] | None] = (None, None)
        # The view answers state the running head; each status report is compared with it.
        app.state_head(head.deployment, head.revision)
        app.watch_status(self._witness_seen)

    def __repr__(self) -> str:
        return f"ManagedPolicy(revision={self.revision}, not_running={self._not_running})"

    @property
    def revision(self) -> int:
        """The head's revision."""
        return self._head().revision

    @property
    def not_running(self) -> int | None:
        """The revision saved and not running, if its install failed."""
        return self._not_running

    @property
    def header(self) -> Mapping[str, Any] | None:
        """The running revision's header, which the portal's policy view names (A.4, G.10): the
        head's, or while a saved revision isn't running (G.6 step 8), the one still running."""
        return self._running_header

    @property
    def store(self) -> PolicyStore:
        """The store whose head this vault runs (history, diffs and exports read it, H)."""
        return self._store

    @property
    def policy(self) -> Policy:
        """The head's policy (while a saved revision isn't running, that one's)."""
        return self._policy

    @property
    def environ(self) -> Mapping[str, str]:
        """The vault's environment, which every candidate is checked with (C)."""
        return self._environ

    @property
    def ratchet(self) -> Ratchet:
        """The head's ratchet: the portal's review rows read its ``approved`` set (J.3)."""
        return self._ratchet

    def marked(self) -> frozenset[DefKey]:
        """The tools the gateway's latest status report says a drift mark hides (K.1), for the
        planner's ``allow_marked`` (G.5 rule 1, J.4); none before the first report."""
        report = self._app.gateway_status().report
        if report is None:
            return frozenset()
        return frozenset(
            (server, "tool", name)
            for server, entry in report.servers.items()
            for name in entry.marked
        )

    def gateway(self) -> dict[str, Any]:
        """Which revision the gateway runs (G-23, K.1), from its latest status report's view
        digest and the revision-to-view-digest map: ``applied`` when it is the head's,
        ``pending`` when it is another's or none this process installed, ``unknown`` before any
        report; with the newest revision whose view it is, when there is one."""
        report = self._app.gateway_status().report
        if report is None:
            return {"state": "unknown", "revision": None}
        found = [n for n, view in self._digests.items() if view == report.view]
        applied = self._digests.get(self.revision) == report.view
        return {"state": "applied" if applied else "pending", "revision": max(found, default=None)}

    def witness(self) -> Witnessed | None:
        """What the gateway's latest status report says it has seen, against the head (K.3):
        None before any report."""
        report = self._app.gateway_status().report
        if report is None:
            return None
        head = self._head()
        return witnessed(report.witness, head.deployment, head.revision)

    def _witness_seen(self, report: Report) -> None:
        """A status report kept: ``policy_behind_witness`` and ``policy_deployment_changed``
        (critical) logged when it first shows either, or shows it at another revision (N.3)."""
        head = self._head()
        found = witnessed(report.witness, head.deployment, head.revision)
        shown = (found.claim if found.behind else None, found.other)
        if shown == self._witness_logged:
            return
        self._witness_logged = shown
        if found.behind:
            logs.event(
                "policy_behind_witness", level="critical", head=head.revision, witness=found.claim
            )
        if found.other is not None:
            other, revision = found.other
            logs.event(
                "policy_deployment_changed",
                level="critical",
                deployment=head.deployment[:8],
                other=other[:8],
                revision=revision,
            )

    @property
    def view_digests(self) -> Mapping[int, str]:
        """Each revision this process installed, newest :data:`~.policystore.KEEP`, and the
        view digest its install built (K.1's map)."""
        return dict(self._digests)

    def state(self) -> health.PolicyState:
        """Health's ``policy`` section's input (M.5)."""
        head = self._head()
        report = self._app.gateway_status().report
        started = None if report is None else report.started

        def waiting(effect: Effect) -> bool:
            # A raised limit's restart is the gateway's: done once it started after the raise.
            if effect.kind == "vault_restart" or started is None:
                return True
            return started < self._raised_at[effect.path]

        # The gateway still on another view than the head's, past the grace (K.1, FM-18).
        gateway = self.gateway()
        found = self.witness() or Witnessed()
        behind = (
            gateway["state"] == "pending"
            and self._not_running is None
            and self._wall() - self._installed_at > GATEWAY_APPLY_GRACE
        )
        return health.PolicyState(
            "managed",
            revision=head.revision,
            oldest=head.oldest,
            not_running=self._not_running,
            seed_ignored=self._seed_ignored,
            restart_needed=tuple(
                (effect.path, effect.text) for effect in self._effects if waiting(effect)
            ),
            unreadable=self._store.unreadable(),
            quarantine=self._store.quarantined(),
            gateway_behind=behind,
            gateway_revision=gateway["revision"] if behind else None,
            witness_behind=found.claim if found.behind else None,
            witness_other=None if found.other is None else found.other[1],
            acknowledge=acknowledge_command(self._environ),
        )

    # --- the write (G.6) ---------------------------------------------------------------------

    def write(
        self,
        kind: WriteKind,
        surface: Surface,
        base: int,
        candidate_of: Callable[[Policy], Policy],
        *,
        author: Mapping[str, str],
        expected: WritePlan | str | None,
        grants: Grants | None = None,
        reason: str | None = None,
        evidence: Evidence | None = None,
        seed_digest: str | None = None,
        jumped_from: int | None = None,
        capture: Callable[[WritePlan], Any] | None = None,
        logged: Mapping[str, Any] | None = None,
        revision: int | None = None,
    ) -> Written | WriteRefused:
        """One write, planned on revision ``base``: ``candidate_of`` builds the candidate from a
        policy (the head's, or for a retry its parent's; G.6 step 3), ``author`` is the header's
        (D.2), ``expected`` the plan the portal's action holds or the socket's plan digest
        (None: none to compare). ``grants`` are the host's (the portal passes none),
        ``evidence`` what the surface read for the planner, ``seed_digest`` a new seed digest
        (F.5) and ``jumped_from`` an acknowledged restore's (K.3). ``capture`` runs on the final
        plan inside the section, before the commit, from the policy still running (a host
        write's revocation material, G.8, CR-5); what it returns is the answer's ``captured``.
        ``logged`` adds fields to the write's log line (an import's ``from_env``, N.3).
        ``revision`` numbers an acknowledged restore's revision past the gateway's claim (K.3,
        :func:`jumped`), the head in ``jumped_from``. Synchronous, with no await: nothing else
        on the event loop runs until it returns. ``candidate_of``'s own errors (``ValueError``)
        pass through, with nothing written."""
        with self._lock:
            return self._write(
                kind,
                surface,
                base,
                candidate_of,
                author=author,
                expected=expected,
                grants=grants or Grants(),
                reason=reason,
                evidence=evidence or Evidence(),
                seed_digest=seed_digest,
                jumped_from=jumped_from,
                capture=capture,
                logged=logged or {},
                revision=revision,
            )

    def plan(
        self,
        kind: WriteKind,
        surface: Surface,
        base: int,
        candidate_of: Callable[[Policy], Policy],
        *,
        author: Mapping[str, str] | None = None,
        grants: Grants | None = None,
        evidence: Evidence | None = None,
        revision: int | None = None,
    ) -> WritePlan | WriteRefused | Written:
        """What :meth:`write` would commit, and nothing written (the socket's ``?plan=1``, H.5):
        G.6 steps 1 to 5, a write on another head ``policy_moved``, unless it is the write by
        ``author`` that made the head, whose answer was lost: that is ``already_saved``, as
        :meth:`write` answers it (MISS-9, FM-16; the CLI plans before it commits, so its rerun
        meets it here). ``revision`` is an acknowledged restore's number (:func:`jumped`).
        Synchronous."""
        with self._lock:
            head = self._head()
            if (
                author is not None
                and self._not_running is None
                and base != head.revision
                and self._retried(kind, base, candidate_of, author)
            ):
                return Written(head.revision, head.digest, already_saved=True)
            refused = self._refused_first(head, base)
            if refused is not None:
                return refused
            planned = self._planned(kind, surface, candidate_of, grants or Grants(), evidence)
            if isinstance(planned, WriteRefused):
                return planned
            if revision is not None:
                planned = jumped(planned, revision)
            return lowered(self._app.gateway_keys.state, planned) or planned

    def _write(
        self,
        kind: WriteKind,
        surface: Surface,
        base: int,
        candidate_of: Callable[[Policy], Policy],
        *,
        author: Mapping[str, str],
        expected: WritePlan | str | None,
        grants: Grants,
        reason: str | None,
        evidence: Evidence,
        seed_digest: str | None,
        jumped_from: int | None,
        capture: Callable[[WritePlan], Any] | None,
        logged: Mapping[str, Any],
        revision: int | None,
    ) -> Written | WriteRefused:
        head = self._head()
        # Step 2: a retry whose answer was lost (step 1 refuses it too while not running).
        if (
            self._not_running is None
            and base != head.revision
            and self._retried(kind, base, candidate_of, author)
        ):
            return Written(head.revision, head.digest, already_saved=True)
        # Steps 1 and 2: a revision saved and not running, or a head that moved.
        refused = self._refused_first(head, base)
        if refused is not None:
            return refused
        # Steps 3 and 4: the candidate through the gate (C) and the planner, and the plan the
        # caller confirmed.
        planned = self._planned(kind, surface, candidate_of, grants, evidence)
        if isinstance(planned, WriteRefused):
            return planned
        if revision is not None:
            planned = jumped(planned, revision)
        if isinstance(expected, WritePlan) and expected != planned:
            return WriteRefused("changed", "the plan changed", plan=planned)
        if isinstance(expected, str) and expected != plan_digest(planned):
            return WriteRefused("plan_changed", "the plan changed", plan=planned)
        # Step 5: the gateway key generation, before any file is written (G-4).
        refused = lowered(self._app.gateway_keys.state, planned)
        if refused is not None:
            return refused
        # What the write takes from the policy still running, before it changes (G.8, CR-5).
        captured = None if capture is None else capture(planned)
        # Steps 6 and 7: the commit (D.9), the anchor first when it is dirty.
        target = evidence.target_revision if planned.kind == "policy.rollback" else None
        try:
            committed = self._store.commit(
                planned,
                author=author,
                reason=reason,
                target=target,
                jumped_from=jumped_from,
                seed_digest=seed_digest,
                revision=revision,
            )
        except StoreRefused as exc:
            return WriteRefused(exc.reason, exc.detail)
        self._policy, self._ratchet = planned.policy, planned.ratchet
        # Step 8: the install.
        failed = self._install(committed.revision, committed.digest, planned.policy)
        # Step 9: the log lines.
        log_saved(planned, committed, author, jumped_from=jumped_from, logged=logged)
        if failed is not None:
            detail = (
                f"saved as revision {committed.revision}, but the vault couldn't apply it: send "
                "SIGHUP to the vault or restart it"
            )
            return WriteRefused("saved_not_running", detail, revision=committed.revision)
        return Written(
            committed.revision,
            committed.digest,
            planned.effects,
            next=saved_next(planned.effects),
            captured=captured,
        )

    def _refused_first(self, head: Head, base: int) -> WriteRefused | None:
        """G.6 steps 1 and 2's refusals: a revision saved and not running refuses every write
        until it runs; a write planned on another revision is ``policy_moved``, naming when and
        by whom the head was written (:func:`moved`)."""
        if self._not_running is not None:
            number = self._not_running
            detail = (
                f"revision {number} is saved but not running: send SIGHUP to the vault or "
                "restart it"
            )
            return WriteRefused("policy_not_running", detail, revision=number)
        if base != head.revision:
            detail = moved(self._store.header, head.revision)
            return WriteRefused("policy_moved", detail, revision=head.revision)
        return None

    def _planned(
        self,
        kind: WriteKind,
        surface: Surface,
        candidate_of: Callable[[Policy], Policy],
        grants: Grants,
        evidence: Evidence | None,
    ) -> WritePlan | WriteRefused:
        """G.6 steps 3 and 4 on the head (:func:`plan_on`)."""
        return plan_on(
            self._store,
            self._policy,
            self._ratchet,
            kind,
            surface,
            candidate_of,
            environ=self._environ,
            started=self._started,
            bindings=self._bindings,
            grants=grants,
            evidence=evidence or Evidence(),
        )

    def _retried(
        self,
        kind: WriteKind,
        base: int,
        candidate_of: Callable[[Policy], Policy],
        author: Mapping[str, str],
    ) -> bool:
        """Whether this write made the head (G.6 step 2, MISS-9): the head names ``base`` as its
        base, its author and kind are this write's, and the candidate built on revision ``base``
        (the head's parent, which is kept) is the head's policy."""
        header = self._store.header
        if header is None or (header["base"], header["kind"]) != (base, kind):
            return False
        if header["author"] != dict(author):
            return False
        before = self._store.policy(base)
        if before is None:
            return False
        try:
            rebuilt = candidate_of(before)
        except ValueError:
            return False
        return normalized_digest(rebuilt) == normalized_digest(self._policy)

    # --- SIGHUP (F.6) ------------------------------------------------------------------------

    def reverify(self, source: Source | None, *, recheck: bool = True) -> bool | None:
        """A managed ``SIGHUP``: the store read and verified again, the head's policy through the
        gate, and the head installed when it isn't the one running or a saved revision isn't
        running (G-5). F.5 runs on ``source``, the configured source read again (None: none
        given), unless ``recheck`` is false (standard input, read once at start); the source is
        never applied. Returns whether it installed the head, or None when it refused (logged
        ``reload_refused``; the running policy stays)."""
        with self._lock:
            try:
                store = self._reopen()
            except OSError as exc:
                reason = f"the policy store can't be read ({type(exc).__name__})"
                logs.event("reload_refused", reason=reason)
                return None
            found = store.verdict
            if not isinstance(found, Ok) or found.parked is not None:
                if isinstance(found, Refused):
                    reason = found.reason
                elif isinstance(found, Ok):
                    reason = "policy_store_parked"
                else:
                    reason = "policy_store_missing"
                logs.event("reload_refused", reason=reason)
                return None
            try:
                policy = head_policy(found)
                gate.admit(policy, f"revision {found.revision}", environ=self._environ)
            except GateRefused as exc:
                logs.event("reload_refused", reason=str(exc))
                return None
            except ValueError:
                logs.event("reload_refused", reason="tampered")
                return None
            self._store, self._policy, self._ratchet = store, policy, found.ratchet
            if recheck:
                self._seed_ignored = seed_ignored(source, found)
            if self._seed_ignored is not None:
                logs.event(
                    "policy_seed_ignored",
                    level="warning",
                    revision=found.revision,
                    reason=self._seed_ignored,
                )
            if found.head.digest == self._running and self._not_running is None:
                return False
            failed = self._install(found.revision, found.head.digest, policy)
            if failed is not None:
                logs.event("reload_refused", reason=failed)
                return None
            return True

    # --- internals ---------------------------------------------------------------------------

    def _head(self) -> Head:
        head = self._store.head
        assert head is not None  # noqa: S101 - a managed store always has one
        return head

    def _install(self, revision: int, head_digest: str, policy: Policy) -> str | None:
        """G.6 step 8: ``policy`` installed, the gateway key ratchet first (F-3). Returns None,
        or why it failed: the revision stays committed and the old head runs (Y1)."""
        before = self._app.policy
        try:
            self._app.reload(policy)
        except GatewayKeyError as exc:
            self._not_running = revision
            logs.event("policy_not_installed", level="critical", revision=revision, reason=str(exc))
            return str(exc)
        self._not_running = None
        self._running = head_digest
        self._running_header = self._store.header
        self._app.state_head(self._head().deployment, revision)
        self._installed_at = self._wall()
        self._digests[revision] = self._app.view_digest
        for number in sorted(self._digests)[:-KEEP]:
            del self._digests[number]
        effects = restart.classify(self._startup, policy, self._started)
        self._effects = tuple(effect for effect in effects if effect.kind in _RESTARTS)
        # Against the startup policy a limit raised once stays a note; it waits for a gateway
        # start after the install that raised it, not after every install since.
        now = self._wall()
        raised = {e.path for e in restart.classify(before, policy, self._started)}
        self._raised_at = {
            effect.path: now if effect.path in raised else self._raised_at.get(effect.path, now)
            for effect in self._effects
            if effect.kind == "gateway_restart"
        }
        if self._installed is not None:
            self._installed(policy)
        return None


refuse_type(ManagedPolicy)


def log_saved(
    planned: WritePlan,
    committed: Committed,
    author: Mapping[str, str],
    *,
    jumped_from: int | None = None,
    logged: Mapping[str, Any] | None = None,
) -> None:
    """G.6 step 9's lines (N.3): the revision's event, by its kind, with a rollback's target and
    an acknowledged restore's jump, and ``logged``'s fields; then one line per tool moved to
    allow, kept allow or re-pinned. The running vault's writes and the host's offline ones log
    alike."""
    target = committed.header["target"]
    logs.event(
        _SAVED_EVENTS.get(planned.kind, "policy_saved"),
        revision=committed.revision,
        write_kind=planned.kind,  # "kind" is the logger's own argument
        origin=committed.header["origin"],
        author=_author(author),
        base=planned.base,
        digest=_digest8(committed.digest),
        effects=[effect.kind for effect in planned.effects],
        **({"target": target} if target is not None else {}),
        **({"jumped_from": jumped_from} if jumped_from is not None else {}),
        **(logged or {}),
    )
    _log_tools(planned, committed.revision)


def _log_tools(planned: WritePlan, revision: int) -> None:
    """``tool_allowed`` per move to allow and, with ``kept``, per kept allow; ``tool_repinned``
    per re-pin, whatever the write's kind (G.6 step 9, N.3, Q27). The definition's kind is
    ``def_kind``: ``kind`` is the logger's own argument."""
    for server, kind, name in planned.moves:
        logs.event("tool_allowed", server=server, def_kind=kind, name=name, revision=revision)
    for server, kind, name in planned.kept_allow:
        logs.event(
            "tool_allowed", server=server, def_kind=kind, name=name, revision=revision, kept=True
        )
    for change in planned.changes:
        if change.model in _SERVER_MODELS and change.field == "review" and change.op == "changed":
            server, name = str(change.path[2]), str(change.path[4])
            logs.event(
                "tool_repinned", server=server, def_kind="tool", name=name, revision=revision
            )


# --- what the host reads and is answered (H.1-H.6, N.1) --------------------------------------
#
# The admin socket's policy routes and the host's offline forms (``cli/policy.py``) answer in
# these shapes, from the same store, so the two read alike.


def history_page(
    store: PolicyStore, before: int | None = None, limit: int = HISTORY_PAGE_MAX
) -> dict[str, Any]:
    """A page of history (H.1): the entries, newest first, and ``next``, the ``before`` of the
    next page, or None at the oldest kept revision."""
    entries = store.history(before, limit)
    head = store.head
    last = entries[-1]["revision"] if entries else None
    more = last is not None and head is not None and last > head.oldest
    return {"revisions": entries, "next": last if more else None}


def read_revision(store: PolicyStore, number: int) -> tuple[Unsealed, Policy] | Refusal:
    """Kept revision ``number`` and its policy, or why it can't be read (H.3:
    ``revision_unreadable`` in quarantine or no longer verifying, ``revision_unknown`` pruned
    or never written)."""
    found = store.revision(number)
    policy = store.policy(number) if found is not None else None
    if found is None or policy is None:
        why = store.missing(number) or "revision_unreadable"
        return refusal(why, revision=str(number))
    return found, policy


def diff_answer(
    store: PolicyStore, number: int, against: int | None = None
) -> dict[str, Any] | Refusal:
    """Revision ``number``'s diff from ``against``, by default its parent (H.2): every row
    through the policy view's renderer (``portal/policydiffview.py``), hidden fields hidden
    (Y13). A revision with no parent (the seed, a reseed) is diffed from an empty policy."""
    read = read_revision(store, number)
    if isinstance(read, Refusal):
        return read
    entry, new = read
    if against is None and entry.header["parent"] is not None:
        against = before(entry)
    if against is None:
        old = Policy.model_validate({"version": 1, "mode": "managed"})
    else:
        other = read_revision(store, against)
        if isinstance(other, Refusal):
            return other
        old = other[1]
    changes = diff.structured(normalize(old), normalize(new))
    return {"revision": number, "against": against, "rows": policydiffview.rows(changes)}


def export_answer(
    store: PolicyStore, number: int, *, mode: Mode = "managed", target: Target = "plain"
) -> dict[str, Any] | Refusal:
    """Revision ``number`` exported (H.6, R61's fourth exception): the document and the notes
    the CLI writes beside it."""
    read = read_revision(store, number)
    if isinstance(read, Refusal):
        return read
    entry, policy = read
    deployment = str(entry.header["deployment"])
    return {
        "revision": number,
        "deployment": deployment[:8],
        "export": export(
            policy,
            revision=number,
            deployment=deployment,
            created=entry.header["created"],
            mode=mode,
            target=target,
        ),
        "notes": notes(policy, revision=number, deployment=deployment, mode=mode, target=target),
    }


def policy_status(managed: ManagedPolicy) -> dict[str, Any]:
    """What the portal's Policy page says beside the view (M.1, K.1): the head's revision, which
    one the gateway runs (:meth:`ManagedPolicy.gateway`) and a revision saved and not running.
    Built here, vault-side, as health's sections are: the portal's code names nothing of the
    gateway's (D-115's check, ``tests/unit/test_no_secret_answers.py``)."""
    return {
        "revision": managed.revision,
        "gateway": managed.gateway(),
        "not_running": managed.not_running,
    }


def plan_answer(
    planned: WritePlan, lockout: Iterable[Lockout], revision: int | None = None
) -> dict[str, Any]:
    """A host write's plan (H.5 step 5): its rows in G.7's order, widenings first, its
    effects, whether it widens (``import_widens``, Q41), its lockout rows (I.1), the store
    entries it leaves unused (G.8) and the digest the commit names in ``X-ZoeyMCP-Plan``.
    ``revision`` is an acknowledged restore's number, else the head's next."""
    return {
        "kind": planned.kind,
        "base": planned.base,
        "revision": planned.base + 1 if revision is None else revision,
        "rows": [list(row) for row in planned.rows],
        "effects": [
            {"kind": effect.kind, "path": effect.path, "text": effect.text}
            for effect in planned.effects
        ],
        "widens": widens(planned),
        "widenings": widenings(planned),
        "lockout": [{"text": row.text, "confirm": row.confirm} for row in lockout],
        "unused": list(planned.unused_slots),
        "digest": plan_digest(planned),
    }


@dataclass(frozen=True)
class Shaped:
    """A host write as the write path takes it: its kind, the candidate it builds on a head,
    what the planner reads besides, a new seed digest (F.5) and the log line's extra fields."""

    kind: WriteKind
    candidate_of: Callable[[Policy], Policy] = field(repr=False)
    evidence: Evidence = field(default_factory=Evidence, repr=False)
    seed_digest: str | None = field(default=None, repr=False)
    logged: Mapping[str, Any] = field(default_factory=dict)


def import_shaped(
    seed_digest: str | None,
    basis: Policy,
    given: Policy,
    *,
    from_env: bool = False,
    baseline_only: bool = False,
) -> Shaped | Refusal:
    """An import of ``given``, admitted by the gate (H.5): ``import_declarative`` unless it is
    managed; else planned as :func:`imported` builds it, the document its target (the plan's
    "Kept" rows). ``from_env`` (G-14): ``given`` is the configured policy, whose normalized
    digest becomes the seed digest, and one equal to ``basis`` is the baseline write rather
    than ``no_change``, or ``nothing_to_acknowledge`` when it is already the seed's; with
    ``baseline_only`` it changes nothing and records that digest (``policy.acknowledge``, F.5,
    OPS-7), ``nothing_to_acknowledge`` when it is already the seed's or ``basis``'s. ``basis``
    and ``seed_digest`` are the revision the import is planned on, its policy and seed digest:
    a retry whose answer was lost is shaped as its first try was, so the write can tell it
    (``already_saved``, G.6 step 2)."""
    if given.mode != "managed":
        return refusal("import_declarative")
    digest_of = normalized_digest(given)
    logged = {"from_env": from_env, "baseline_only": baseline_only}
    seed = digest_of if from_env else None
    if baseline_only:
        if digest_of in (seed_digest, normalized_digest(basis)):
            detail = "the configured policy already matches the one seeded, or the head"
            return refusal("nothing_to_acknowledge", detail=detail)
        return Shaped("policy.acknowledge", _same, seed_digest=seed, logged=logged)
    if from_env and normalized_digest(imported(basis, given)) == normalized_digest(basis):
        if digest_of == seed_digest:
            detail = "the configured policy is the head's, and already its seed's"
            return refusal("nothing_to_acknowledge", detail=detail)
        return Shaped("policy.acknowledge", _same, seed_digest=seed, logged=logged)

    def candidate_of(policy: Policy) -> Policy:
        return imported(policy, given)

    return Shaped(
        "policy.import", candidate_of, Evidence(target=given), seed_digest=seed, logged=logged
    )


def rollback_shaped(store: PolicyStore, number: int) -> Shaped | Refusal:
    """A host rollback to kept revision ``number`` (H.3): its policy carried forward on the head
    as a host's (H.4: the target's ``admin``, the head's key generations and pins), or why the
    target can't be read."""
    read = read_revision(store, number)
    if isinstance(read, Refusal):
        return read
    target = read[1]

    def candidate_of(policy: Policy) -> Policy:
        return carry_forward(policy, target, host=True)

    return Shaped("policy.rollback", candidate_of, Evidence(target=target, target_revision=number))


def acknowledge_shaped() -> Shaped:
    """``acknowledge-restore``'s write (K.3): the head's content again, ``policy.acknowledge``,
    which the planner writes with no change (G.5 rule 6); its number is :func:`jumped`'s."""
    return Shaped("policy.acknowledge", _same)


def jumped(planned: WritePlan, revision: int) -> WritePlan:
    """``planned`` numbered ``revision``, an acknowledged restore's jump past the gateway's claim
    (K.3, Y4): its first row says so, so the plan's digest names the number too."""
    said = f"{revision}, from {planned.base}"
    if revision == planned.base + 2:
        said += f", past {planned.base + 1}, which is never written"
    elif revision > planned.base + 2:
        said += f", past {planned.base + 1}-{revision - 1}, which are never written"
    return replace(planned, rows=(("Revision", said), *planned.rows[1:]))


def witness_answer(found: Witnessed | None) -> dict[str, Any] | None:
    """``GET /policy``'s ``witness`` (N.1, K.3): the revision of this deployment the gateway has
    seen, whether the head is behind it, another deployment's claim that raises
    ``policy_deployment_changed`` (8 characters and its revision), and the revision an
    acknowledgment would write; None before any status report."""
    if found is None:
        return None
    other = found.other
    return {
        "revision": found.claim,
        "behind": found.behind,
        "other": None if other is None else {"deployment8": other[0][:8], "revision": other[1]},
        "target": found.target,
    }


def _same(policy: Policy) -> Policy:
    return policy


def written_answer(written: Written, removed: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """A committed host write (N.1): the revision, a retry's ``already_saved``, its effects,
    the gateway's state, ``next`` (M.7), and the store entries ``--revoke-removed`` deleted,
    each ``{name, revoked}``: whether its provider was asked to revoke it (G.8)."""
    return {
        "revision": written.revision,
        "already_saved": written.already_saved,
        "effects": [
            {"kind": effect.kind, "path": effect.path, "text": effect.text}
            for effect in written.effects
        ],
        "gateway": written.gateway,
        "next": [step.answer() for step in written.next],
        "removed": [dict(entry) for entry in removed],
    }


def refused_body(refused: WriteRefused) -> tuple[int, dict[str, Any]]:
    """A write's refusal as an answer: its status and body, with the planner's ``subjects``
    (each grant a ``--allow-revive`` or ``--allow-env`` names) and the head's revision. A head
    that moved is 412 on the socket (N.1)."""
    answer = refused_answer(refused)
    status = 412 if refused.reason == "policy_moved" else answer.status
    body = {**answer.body(), "subjects": list(refused.subjects), "revision": refused.revision}
    return status, body


class DeclarativeStore:
    """What a declarative start found of the policy store (F.1, F.4), for health: the head it
    parked, with what the running ``policy`` brings back that the parked ratchet retired (T-16,
    judged at every read, so a reload is judged too), or the refusal it didn't meet
    (``policy_store_unverified``). None when there is no store to speak of."""

    def __init__(self, store: PolicyStore, policy: Callable[[], Policy]) -> None:
        self._store = store
        self._policy = policy
        found = store.verdict
        self._parked: tuple[Ok, Policy | None] | None = None
        if isinstance(found, Ok):
            try:
                self._parked = (found, head_policy(found))
            except ValueError:
                self._parked = (found, None)

    def __repr__(self) -> str:
        parked = None if self._parked is None else self._parked[0].revision
        return f"DeclarativeStore(parked={parked})"

    def state(self) -> health.PolicyState | None:
        found = self._store.verdict
        if self._parked is not None:
            ok, head = self._parked
            return health.PolicyState(
                "declarative",
                revision=ok.revision,
                oldest=ok.head.oldest,
                revived=() if head is None else revived(ok.ratchet, head, self._policy()),
                quarantine=self._store.quarantined(),
            )
        if isinstance(found, Refused) and found.reason != "policy_seed_needs_host":
            return health.PolicyState(
                "declarative", unverified=found.reason, quarantine=self._store.quarantined()
            )
        return None


refuse_type(DeclarativeStore)
