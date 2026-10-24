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

:class:`DeclarativeStore` is a declarative start's view of a store it found (F.4): the head it
parked, what the running policy brings back that the parked ratchet retired (T-16), or why the
store wasn't read. :func:`commands` builds the host's commands a start refusal names from
``ZOEYMCP_COMPOSE_CMD`` and the tier (``policystart.Commands``).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ..common.canonical import digest
from ..common.logs import refuse_type
from ..common.policy import gate, restart
from ..common.policy.gate import GateRefused
from ..common.policy.plan import (
    BindingState,
    PlanInput,
    PlanRefused,
    Surface,
    WriteKind,
    WritePlan,
    normalized_digest,
    plan,
)
from ..common.policy.ratchet import DefKey, Grants, Ratchet, violations
from ..common.policy.restart import Effect
from ..common.policy.reviewchange import Lines
from ..common.policy.schema import Policy
from ..common.suggest import Suggestion
from ..portal.policyview import saved
from . import gatewaykeys, health, logs
from .app import VaultApp
from .gatewaykeys import GatewayKeyError
from .policyseal import Head
from .policystart import Commands, Ok, Refused, SeedIgnored, Source
from .policystore import KEEP, PolicyStore, StoreRefused
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
    """A committed write: its revision and digest, the plan's effects (I.2), and the gateway's
    state, ``pending`` until its status shows the new view (K.1). ``already_saved`` answers a
    retry of the write that made the head (G.6 step 2)."""

    revision: int
    digest: str
    effects: tuple[Effect, ...] = ()
    already_saved: bool = False
    gateway: str = "pending"


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
    def view_digests(self) -> Mapping[int, str]:
        """Each revision this process installed, newest :data:`~.policystore.KEEP`, and the
        view digest its install built (K.1's map)."""
        return dict(self._digests)

    def state(self) -> health.PolicyState:
        """Health's ``policy`` section's input (M.5)."""
        head = self._head()
        kept = set(self._store.kept)
        report = self._app.gateway_status().report
        started = None if report is None else report.started

        def waiting(effect: Effect) -> bool:
            # A raised limit's restart is the gateway's: done once it started after the raise.
            if effect.kind == "vault_restart" or started is None:
                return True
            return started < self._raised_at[effect.path]

        return health.PolicyState(
            "managed",
            revision=head.revision,
            oldest=head.oldest,
            not_running=self._not_running,
            seed_ignored=self._seed_ignored,
            restart_needed=tuple(
                (effect.path, effect.text) for effect in self._effects if waiting(effect)
            ),
            unreadable=tuple(n for n in range(head.oldest, head.revision) if n not in kept),
            quarantine=self._store.quarantined(),
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
    ) -> Written | WriteRefused:
        """One write, planned on revision ``base``: ``candidate_of`` builds the candidate from a
        policy (the head's, or for a retry its parent's; G.6 step 3), ``author`` is the header's
        (D.2), ``expected`` the plan the portal's action holds or the socket's plan digest
        (None: none to compare). ``grants`` are the host's (the portal passes none),
        ``evidence`` what the surface read for the planner, ``seed_digest`` a new seed digest
        (F.5) and ``jumped_from`` an acknowledged restore's (K.3). Synchronous, with no await:
        nothing else on the event loop runs until it returns. ``candidate_of``'s own errors
        (``ValueError``) pass through, with nothing written."""
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
            )

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
    ) -> Written | WriteRefused:
        head = self._head()
        # Step 1: a revision saved and not running refuses every write until it runs.
        if self._not_running is not None:
            number = self._not_running
            detail = (
                f"revision {number} is saved but not running: send SIGHUP to the vault or "
                "restart it"
            )
            return WriteRefused("policy_not_running", detail, revision=number)
        # Step 2: a retry whose answer was lost, or a write on a head that moved.
        if base != head.revision:
            if self._retried(kind, base, candidate_of, author):
                return Written(head.revision, head.digest, already_saved=True)
            header = self._store.header
            said = f"revision {head.revision}" if header is None else saved(header)
            detail = f"the policy moved to {said} since you started"
            return WriteRefused("policy_moved", detail, revision=head.revision)
        # Step 3: the candidate, built on the head, through the gate (C).
        try:
            label = f"revision {head.revision + 1}"
            candidate = gate.admit(candidate_of(self._policy), label, environ=self._environ)
        except GateRefused as exc:
            return WriteRefused("import_refused", str(exc))
        # Step 4: the plan, and the one the caller confirmed.
        planned = plan(
            PlanInput(
                kind=kind,
                surface=surface,
                head=self._policy,
                head_revision=head.revision,
                head_digest=head.digest,
                ratchet=self._ratchet,
                candidate=candidate.policy,
                started=self._started,
                bindings=self._bindings,
                verified=evidence.verified,
                drifted=evidence.drifted,
                definitions=evidence.definitions,
                suggested=evidence.suggested,
                marked=evidence.marked,
                consequential=evidence.consequential,
                grants=grants,
                target=evidence.target,
                target_revision=evidence.target_revision,
                removed_in=self._store.removed_lookup(candidate.policy),
            )
        )
        if isinstance(planned, PlanRefused):
            return WriteRefused(planned.reason, planned.detail, planned.subjects, planned.next)
        if isinstance(expected, WritePlan) and expected != planned:
            return WriteRefused("changed", "the plan changed", plan=planned)
        if isinstance(expected, str) and expected != plan_digest(planned):
            return WriteRefused("plan_changed", "the plan changed", plan=planned)
        # Step 5: the gateway key generation, before any file is written (G-4).
        lowered = gatewaykeys.check(
            self._app.gateway_keys.state, planned.policy.gateway_key_generation
        )
        if lowered is not None:
            return WriteRefused("generation_lowered", lowered.reason)
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
            )
        except StoreRefused as exc:
            return WriteRefused(exc.reason, exc.detail)
        self._policy, self._ratchet = planned.policy, planned.ratchet
        # Step 8: the install.
        failed = self._install(committed.revision, committed.digest, planned.policy)
        # Step 9: the log lines.
        event = _SAVED_EVENTS.get(planned.kind, "policy_saved")
        logs.event(
            event,
            revision=committed.revision,
            write_kind=planned.kind,  # "kind" is the logger's own argument
            origin=committed.header["origin"],
            author=_author(author),
            base=planned.base,
            digest=_digest8(committed.digest),
            effects=[effect.kind for effect in planned.effects],
            **({"target": target} if target is not None else {}),
            **({"jumped_from": jumped_from} if jumped_from is not None else {}),
        )
        _log_tools(planned, committed.revision)
        if failed is not None:
            detail = (
                f"saved as revision {committed.revision}, but the vault couldn't apply it: send "
                "SIGHUP to the vault or restart it"
            )
            return WriteRefused("saved_not_running", detail, revision=committed.revision)
        return Written(committed.revision, committed.digest, planned.effects)

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
