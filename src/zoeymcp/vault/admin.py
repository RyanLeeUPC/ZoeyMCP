"""The vault's local admin interface (design §4.5, §7.5).

Served on a Unix socket inside the vault container. Access control is the filesystem: the
socket's directory must be owned by the vault's uid and closed to everyone else, so only that
uid (or root, which already has the host) can connect. The CLI reaches it with
``docker exec <vault> zoeymcp secret ...``.

There is deliberately no endpoint that returns a secret value. Three answers carry a credential,
as recorded exceptions to R61 (M5 design D16, M7 design DD-14): ``POST /setup-code`` the new
setup code, ``GET /gateway-key`` the gateway key, and ``GET /egress-key`` the egress role's key.

``zoeymcp setup-code [--reset] [--wait]`` uses ``POST /setup-code`` and ``GET /setup-code/status``;
``zoeymcp passkeys`` and ``sessions`` list and remove the portal's passkeys and sessions, with no
step-up: host access is the recovery path (M5 design E).

``PUT/DELETE /secrets/{name}`` decide with :mod:`.secretplan` and write with :mod:`.secretops`,
which the portal shares (M5 design G). ``PUT`` with ``{"generate": true}`` in place of a value
(``zoeymcp secret set NAME --generate``, M7 design C.2, GR-27) stores 32 random bytes in
base64url through the same put, for a secret the policy binds to origins (a bridge's token, as
any header credential's), and answers only the token's ``sha256:`` form: the token never leaves
the vault. An OAuth slot or a connector's secret is refused (``generate_refused``). Secrets an
oauth2 credential uses are written and deleted through the token manager, which first waits for
any refresh of that slot (design D.12). If the store can't write its file, the change is kept
in memory and the answer is a 500 that says so (B.4).

``zoeymcp gateway-key`` prints the gateway key and any rotation pending; ``--retire-previous``
retires the previous key at once (M3 design C.2). ``zoeymcp egress-key`` prints the egress role's
key for the running ``egress_key_generation`` (M7 design G.3): it reads the allowlists alone,
and a new generation retires it at once.

``zoeymcp login`` and ``oauth status|reset`` use the ``/oauth`` endpoints (design E.1). Their
errors are ``{"error", "reason"}`` with a stable reason. No answer holds a token, code, verifier
or secret; the authorization URL holds ``state`` and the PKCE challenge, which are useless
without the verifier the vault keeps.

``POST /onboard/discover``, ``POST /onboard/{onboarding}/register``, ``POST
/onboard/{onboarding}/fragment`` and ``DELETE /onboard/{onboarding}`` are onboarding by URL's
phase 1 (M7 design M.1), owned by the CLI: :class:`.onboard.OnboardService`, which the portal
shares, answers them, and a refusal is the catalogue's ``{"error", "reason"}`` with its own
status (M.2). A given client secret comes in the register body, and no answer carries it.

``POST /review/{server}``, ``POST /review/{server}/clear``, ``GET /review/jobs/{job}?wait=N``
and ``POST /review/jobs/{job}/diff`` are the review job path's (M7 design F.2, F.6, M.1), owned by
the CLI: the first queues a review of a server in the running view for the gateway's poll, or
answers the CLI's ``done`` job at the current view digest unless the body says ``{"fresh":
true}`` (OPS-11); the second queues a clear of its drift marks, which the gateway runs only if
every included tool matches its pin (M6 design J.4); the third answers the job's state, and its
report once it is done, or a failed job's refusal; the fourth makes fragment 2 from ``{include,
allow, approve, indent?}`` as the portal does (``portal/reviewview.py``), saving nothing. A
refusal is the catalogue's ``{"error", "reason"}`` (M.2), with ``next``, its way on, as a done
job's answer has (M6 design M.7, D-200).

``zoeymcp health`` uses ``GET /health``: :mod:`.health`'s findings, from metadata only (M5
design I), gathered by :class:`HealthReader`, which the portal's ``GET /api/health`` shares.

``zoeymcp ledger --vault`` uses ``GET /ledger/reported``: the vault's copy of the gateway's
ledger, a page of :mod:`.ledgerview` rows with the send journals joined in, and the archived
epochs. ``--restart-chain`` uses ``POST /ledger/reported/restart``: ``{"dry_run": true}`` answers
the plan, and ``{"plan": ...}`` runs it if the copy hasn't changed since (M5 design J.4).

``zoeymcp policy`` uses the ``/policy`` routes (M6 design H, M.6, N.1), the host's managed
policy: ``GET /policy`` the mode and the head (in declarative mode, the mode alone);
``GET /policy/revisions`` a page of history, ``GET /policy/revisions/{revision}`` one header and
``.../diff?against=M`` a diff through the policy view's renderer (no exception: hidden fields stay
hidden); ``GET /policy/export`` the export, **R61's fourth scoped exception** (DD-4: it holds
placeholders and client token hashes), ``cache-control: no-store``, logged ``policy_exported``;
``POST /policy/import`` (a YAML body of at most :data:`IMPORT_MAX`, or ``from_env=1`` for the
vault's own configured policy, with ``baseline_only=1`` to record its digest and apply nothing)
and ``POST /policy/rollback/{revision}``, each first with ``plan=1`` (the plan, its lockout rows
and its digest), then committed with ``If-Match: "<base>"`` (428 ``base_required`` without it,
412 ``policy_moved`` on a head that moved) and ``X-ZoeyMCP-Plan`` (``plan_changed`` on a
re-plan that differs); a retry of a write whose answer was lost is ``already_saved``, at its
plan as at its commit, the import shaped on the revision ``If-Match`` names. A plan
that widens commits only with ``accept_widening=1`` (``import_widens``, Q41), one with a lockout
row only with ``lockout_ok=1`` (``lockout_unconfirmed``, I.1); ``revoke_removed=1`` deletes the
store entries the write leaves unused and revokes their grants after the commit, with what the
write took from the policy still running (G.8, CR-5). Every write is the host's, through
``ManagedPolicy.write`` (G.6); in declarative mode each answers ``policy_not_managed``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import math
import os
import re
import secrets
import stat
import sys
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, Protocol

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..common import files

# The CLI reads these from common, so the gateway's entry path loads no vault code.
from ..common.adminsocket import DEFAULT_SOCKET as DEFAULT_SOCKET
from ..common.adminsocket import SOCKET_ENV as SOCKET_ENV
from ..common.policy import PolicyError, gate
from ..common.policy.gate import GateRefused
from ..common.policy.plan import WritePlan
from ..common.policy.ratchet import Grants
from ..common.policy.schema import Policy, hash_token
from ..common.reviewreport import RemoteReport, ToolkitReport
from ..portal import passkeys as passkey_file
from ..portal import reviewview, setupcode
from ..portal.passkeys import PasskeyError, Passkeys
from ..portal.refusals import Refusal, refusal
from ..portal.routes import BODY_CHOICES
from ..portal.sessions import SETUP_SESSION_MAX
from ..portal.setupcode import Record, Redeemed, Refused, SetupCode
from . import health, ledgerview, logs, secretops, secretplan
from .connectors.smtp import SmtpConnectors
from .gatewaykeys import GatewayKeyError, GatewayKeys
from .keys import KeySet, PortalKey
from .managed import (
    ManagedPolicy,
    Shaped,
    WriteRefused,
    Written,
    diff_answer,
    export_answer,
    history_page,
    import_shaped,
    lockout_rows,
    plan_answer,
    read_revision,
    refused_body,
    rollback_shaped,
    widenings,
    written_answer,
)
from .oauth.login import LoginError, LoginService
from .oauth.protocol import RevocationMaterial
from .oauth.tokens import TokenManager
from .onboard import (
    DISCOVER_BODY_MAX,
    FRAGMENT_BODY_MAX,
    REGISTER_BODY_MAX,
    OnboardError,
    OnboardService,
)
from .onboarding import INLINE_SOURCE, job_next, listed_server, refusal_next, tools_max
from .policyseal import REASON_MAX
from .policystore import HISTORY_PAGE_MAX
from .reportstore import CopyUnavailable, NotRestartable, PlanChanged, ReportStore
from .reviewjobs import Job, Owner, ReviewRefused
from .secretplan import NOT_WRITTEN as NOT_WRITTEN
from .secretplan import SecretRefusal
from .statusreport import GatewayStatus
from .store import SecretStore

MAX_BODY = 128 * 1024
MAX_COMPLETE_BODY = 8 * 1024
NO_TOKENS = "OAuth needs the vault's token manager"
NO_ONBOARDING: Final = "this vault runs no onboarding service"
NO_GATEWAY_KEYS = "the vault keeps no gateway key state"
NO_REVIEWS: Final = "this vault queues no review jobs"
# POST /review/{server} takes {fresh?}; GET /review/jobs/{job}?wait=N waits at most this long;
# POST /review/jobs/{job}/diff takes the portal's choices, under the portal's cap (M7 K.2).
REVIEW_BODY_MAX: Final = 1024
REVIEW_WAIT_MAX: Final = 30
REVIEW_DIFF_BODY_MAX: Final = BODY_CHOICES
REVIEW_DIFF_KEYS: Final = frozenset({"include", "allow", "approve"})
# The socket's review jobs are the CLI's (M.1).
_REVIEW_OWNER: Final[Owner] = "cli"
# POST /setup-code takes {reset?}.
MAX_SETUP_BODY: Final = 4 * 1024
# The longest GET /setup-code/status?wait=N waits, in seconds.
MAX_STATUS_WAIT: Final = 60
NO_PASSKEYS: Final = "the vault keeps no passkey state"
PASSKEYS_UNAVAILABLE: Final = (
    "the passkey file can't be verified (edited, or written under another master key); "
    "run zoeymcp setup-code --reset"
)
_FINGERPRINT: Final = re.compile(r"[0-9a-f]{16}")
# The socket's own refusals of the host's policy commands (M6 design N.2); portal/refusals.py
# catalogues each, and the managed write's, the store's and the planner's pass through by their
# own reasons, as do an import's and a rollback's (vault/managed.py's shapes).
PolicyReason = Literal[
    "policy_not_managed",
    "base_required",
    "import_refused",
    "import_widens",
    "lockout_unconfirmed",
    "plan_changed",
]
# An import's body: the loader's own cap (M6 design N.4).
IMPORT_MAX: Final = 1_048_576
IMPORT_TYPE: Final = "application/yaml"
# The host's author over the socket (D.2).
SOCKET_AUTHOR: Final = MappingProxyType({"by": "host", "via": "socket"})
# What the policy routes' queries may hold (N.1): flags are "1"; the grants repeat.
_FLAGS: Final = frozenset(
    {"plan", "from_env", "baseline_only", "lockout_ok", "revoke_removed", "accept_widening"}
)
_GRANTS: Final = frozenset({"allow_revive", "allow_env"})
_IMPORT_QUERY: Final = _FLAGS | _GRANTS | {"reason"}
_ROLLBACK_QUERY: Final = _IMPORT_QUERY - {"from_env", "baseline_only"}
_IF_MATCH: Final = re.compile(r'"([1-9][0-9]{0,9})"')
_EXPORT_MODES: Final = frozenset({"managed", "declarative"})
# A generated token (M7 design C.2): this many random bytes, in unpadded base64url.
GENERATED_BYTES: Final = 32
GENERATE_REFUSED: Final = SecretRefusal(
    409,
    "generate_refused",
    "--generate makes a token for a header, query, path or basic credential; an OAuth or "
    "connector secret is entered as it was given",
)
# Passkey refusals over the socket: status and text.
_PASSKEY_REFUSALS: Final = {
    "unavailable": (503, PASSKEYS_UNAVAILABLE),
    "not_found": (404, "no passkey has that fingerprint"),
    "ambiguous_fingerprint": (409, "more than one passkey has that fingerprint; nothing removed"),
    "not_written": (500, "not written to disk; nothing changed; check the state volume"),
}
# Login reasons answered with something other than 400.
_LOGIN_STATUS = {
    "not_oauth": 404,
    "flow_unknown": 404,
    "no_authorize_url": 409,
    "no_route": 409,
    "authorize_misconfigured": 409,
    "binding_changed": 409,
    "client_id_unavailable": 409,
    "client_secret_unavailable": 409,
    "client_secret_binding_changed": 409,
    "too_many_flows": 429,
}


class PortalSessions(Protocol):
    """The portal's sessions as the socket reaches them (``portal.app.PortalApp``), on the loop
    both serve from."""

    def session_list(self) -> list[dict[str, Any]]: ...

    def end_all(self) -> int: ...

    def end_credential(self, fingerprint: str) -> int: ...


class ReviewQueue(Protocol):
    """The review jobs as the socket reaches them (``app.VaultApp``), on the loop both serve
    from (M7 design F.2)."""

    async def queue_review(self, server: str, owner: Owner, *, fresh: bool = False) -> Job: ...

    async def queue_clear(self, server: str, owner: Owner) -> Job: ...

    async def review_job(self, job_id: str, owner: Owner, *, wait: float = 0) -> Job: ...

    def held_reports(self, server: str) -> tuple[RemoteReport | ToolkitReport, ...]: ...


class AdminSocketError(Exception):
    """The admin socket's directory isn't safe to use."""


def check_socket_dir(path: Path) -> None:
    """Create the socket's directory if needed, and refuse one others can reach (POSIX)."""
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise AdminSocketError(f"{directory} must be owned by the vault's uid {os.getuid()}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise AdminSocketError(f"{directory} must not be accessible to group or others (0700)")
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


@dataclass
class _Tracked:
    """The code this vault last issued or redeemed, as ``GET /setup-code/status`` tells it."""

    record: Record
    state: Literal["pending", "redeemed", "enrolled", "expired"] = "pending"
    # When it was redeemed, and on which origin.
    redeemed_at: float | None = None
    origin: str | None = None
    # The passkey its setup session enrolled (passkeys.describe), once it has.
    passkey: dict[str, Any] | None = None


class SetupCodes:
    """One-time setup codes for the portal (M5 design E), kept in ``<state>/setup.json`` as a
    record MAC'd under ``key`` (:mod:`..portal.setupcode`). The socket issues them, and so does
    ``zoeymcp setup-code --state DIR`` with the vault stopped or without a socket; the portal
    redeems them, one at a time.

    What happened to the code this vault last issued or redeemed is kept in memory for
    ``zoeymcp setup-code --wait``: never the code itself.
    """

    def __init__(
        self,
        state_dir: Path,
        key: PortalKey,
        clock: Callable[[], float] = time.time,
        *,
        random: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._path = state_dir / setupcode.FILE
        self._key = key
        self._clock = clock
        self._random = random
        self._lock = asyncio.Lock()
        self._tracked: _Tracked | None = None
        # Set, and replaced, on every change, to wake the status's long polls.
        self._changed = asyncio.Event()

    @property
    def path(self) -> Path:
        return self._path

    def issue(self, *, reset: bool = False) -> tuple[SetupCode, Record]:
        """A new code, replacing any earlier one. Raises :class:`OSError` if the record can't be
        written, and the earlier code then still works."""
        code = setupcode.new_code(self._random)
        record = setupcode.new_record(code, now=self._clock(), reset=reset)
        files.write_atomic(self._path, setupcode.seal(record, self._key), prefix=".setup-")
        self._track(_Tracked(record))
        return code, record

    def record(self) -> Record | None:
        """The pending code's record; None when there is none, or it doesn't verify."""
        try:
            with self._path.open("rb") as handle:
                data = handle.read(setupcode.MAX_FILE_BYTES + 1)
        except OSError:
            return None
        return setupcode.unseal(data, self._key)

    async def redeem(self, typed: object, *, origin: str) -> Redeemed | Refused:
        """Spend the code ``typed`` is, typed on ``origin``. The record is removed, and its
        directory synced, before :class:`Redeemed` is returned, so a code works once even across
        a crash. Raises :class:`OSError` if it can't be removed: the code then isn't spent and
        no setup session may open."""
        async with self._lock:
            record = self.record()
            decision = setupcode.decide(record, typed, self._clock())
            if record is None or isinstance(decision, Refused):
                return decision
            _remove_synced(self._path)
            self._track(_Tracked(record, "redeemed", self._clock(), origin))
            return decision

    def enrolled(self, passkey: dict[str, Any]) -> None:
        """The setup session the last redeemed code opened enrolled ``passkey``."""
        tracked = self._tracked
        if tracked is not None and tracked.state == "redeemed":
            self._track(replace(tracked, state="enrolled", passkey=passkey))

    def discard(self) -> None:
        """Remove any pending code: the first passkey was enrolled, by whatever path (E.1)."""
        with contextlib.suppress(FileNotFoundError):
            _remove_synced(self._path)
        tracked = self._tracked
        if tracked is not None and tracked.state == "pending":
            self._track(replace(tracked, state="expired"))

    def status(self) -> dict[str, Any]:
        """``{state, expires, reset, origin, passkey}`` of the code this vault last issued or
        redeemed, never the code. ``state`` is ``none`` (none since the vault started),
        ``pending``, ``redeemed``, ``enrolled``, or ``expired``: unused in time, discarded, or
        redeemed by a setup session that ended without an enrolment."""
        tracked = self._tracked
        if tracked is None:
            return {
                "state": "none",
                "expires": None,
                "reset": None,
                "origin": None,
                "passkey": None,
            }
        state = tracked.state
        if self._until_change(tracked) <= 0:
            state = "expired"
        return {
            "state": state,
            "expires": tracked.record.expires,
            "reset": tracked.record.reset,
            "origin": tracked.origin,
            "passkey": tracked.passkey,
        }

    async def wait_status(self, seconds: float) -> dict[str, Any]:
        """:meth:`status`, once it changes or ``seconds`` pass, whichever is first; at once when
        nothing can change it any more (``none``, ``enrolled``, ``expired``)."""
        tracked, changed = self._tracked, self._changed
        if tracked is not None and self.status()["state"] in ("pending", "redeemed"):
            timeout = min(seconds, self._until_change(tracked))
            if timeout > 0:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(changed.wait(), timeout)
        return self.status()

    def _until_change(self, tracked: _Tracked) -> float:
        """Seconds until time alone changes the state: a pending code expires, a redeemed one's
        setup session ends. Infinite for the other states."""
        now = self._clock()
        if tracked.state == "pending":
            return tracked.record.expires - now
        if tracked.state == "redeemed" and tracked.redeemed_at is not None:
            return tracked.redeemed_at + SETUP_SESSION_MAX - now
        return math.inf

    def _track(self, tracked: _Tracked) -> None:
        self._tracked = tracked
        self._changed.set()
        self._changed = asyncio.Event()


def _remove_synced(path: Path) -> None:
    """Remove ``path`` and, on POSIX, sync its directory, so the removal survives a crash."""
    path.unlink()
    if hasattr(os, "O_DIRECTORY"):
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _connector_secret(policy: Policy, name: str) -> bool:
    """Whether a connector uses ``store:<name>`` (as ``bindings.derive_binding`` finds it)."""
    ref = f"store:{name}"
    return any(ref in (c.password, c.username) for c in policy.connectors.values())


def generated_token(random: Callable[[int], bytes]) -> str:
    """A new token: :data:`GENERATED_BYTES` random bytes in unpadded base64url (C.2)."""
    return base64.urlsafe_b64encode(random(GENERATED_BYTES)).rstrip(b"=").decode("ascii")


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _refused(refusal: SecretRefusal) -> JSONResponse:
    return _error(refusal.status, refusal.message)


def _login_error(exc: LoginError) -> JSONResponse:
    body = {"error": str(exc), "reason": exc.reason, **exc.details}
    return JSONResponse(body, status_code=_LOGIN_STATUS.get(exc.reason, 400))


async def _json_object(request: Request, limit: int) -> dict[str, Any] | Response:
    """The body as a JSON object (empty means ``{}``), or the error answer."""
    body = await request.body()
    if len(body) > limit:
        return _error(413, "body too large")
    if not body:
        return {}
    try:
        data: Any = json.loads(body)
    except ValueError:
        return _error(400, "body must be JSON")
    if not isinstance(data, dict):
        return _error(400, "body must be a JSON object")
    return data


def json_safe(value: Any) -> Any:
    """``value`` with every NaN or infinity replaced by ``None``.

    A store entry's ``meta`` is clear text anyone with the state file can edit, and JSON answers
    can't carry those numbers.
    """
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


@dataclass(frozen=True)
class HealthReader:
    """What credential health is read from (M5 design I.1), for the socket's ``GET /health``
    and the portal's ``GET /api/health``, which share one reader per vault: the store's clear
    entries, the running policy, the logins' status, the connectors' send journals, the ``env:``
    variables found set, the reported copy and the passkey file. Without ``connectors`` it shows
    no sends; without ``env_names`` every ``env:`` reference is unset; without ``reports`` or
    ``passkeys`` the report has no ``ledger_copy`` or ``passkeys`` section. ``wall`` is the
    wall clock a registered client's secret expiry is judged on (M7 design J, FM-28). The
    address guard's refusals come from the logins' token manager (J), and the egress role's last
    fetch from ``egress_fetched_ago`` (``VaultApp``'s; without it, no
    ``egress_allowlist_stale``). ``bridges`` is the tier and the bridges the vault was started
    with (M7 design C.10, J; by default the hardened tier's: no link socket, no bridge).
    ``gateway_status`` is the gateway's latest status report (``VaultApp``'s, M6 design K.1);
    without it, the report has no ``gateway`` section. ``policy_state`` is the policy store's
    (``vault/managed.py``, M6 design M.5); without it, or while it answers None (no store), the
    report has no ``policy`` section."""

    store: SecretStore
    policy: Callable[[], Policy]
    login: LoginService | None = None
    connectors: SmtpConnectors | None = None
    env_names: Callable[[], Collection[str]] | None = None
    reports: ReportStore | None = None
    passkeys: Passkeys | None = None
    wall: Callable[[], float] = time.time
    egress_fetched_ago: Callable[[], float | None] | None = None
    bridges: health.Bridges = field(default_factory=health.Bridges)
    gateway_status: Callable[[], GatewayStatus] | None = None
    policy_state: Callable[[], health.PolicyState | None] | None = None

    def report(self) -> dict[str, Any]:
        """:func:`.health.assess` now, with no number JSON can't carry."""
        policy = self.policy()
        inputs = health.Inputs(
            policy,
            self.store.metadata(),
            frozenset(() if self.env_names is None else self.env_names()),
            oauth=None if self.login is None else self.login.status(),
            sends=self._sends(policy),
            persisted=not self.store.dirty,
            passkeys=self._passkey_state(policy),
            ledger_copy=self._ledger_copy(policy),
            wall=self.wall(),
            refused=() if self.login is None else self.login.refused(),
            egress_fetched_ago=None
            if self.egress_fetched_ago is None
            else self.egress_fetched_ago(),
            bridges=self.bridges,
            gateway_status=None if self.gateway_status is None else self.gateway_status(),
            policy_state=None if self.policy_state is None else self.policy_state(),
        )
        report: dict[str, Any] = json_safe(health.assess(inputs))
        return report

    def _passkey_state(self, policy: Policy) -> health.PasskeyState | None:
        """The passkey file for health; None without one, or without a portal to use it."""
        holder = self.passkeys
        if holder is None or policy.admin is None:
            return None
        document = holder.document
        last = document.last_regressed
        return health.PasskeyState(
            count=len(document.credentials),
            unavailable=holder.unavailable,
            regressed_ago=None if last is None else holder.clock() - last,
        )

    def _ledger_copy(self, policy: Policy) -> health.LedgerCopy | None:
        """The reported copy for health; None without a copy or a gateway to report to it."""
        copy = self.reports
        if copy is None or policy.gateway is None:
            return None
        now = copy.clock()
        contact = copy.contact_ms
        return health.LedgerCopy(
            state=copy.state,
            head_seq=copy.held.head_seq,
            reported_ago=None if contact is None else max(0, now - contact) // 1000,
            uptime=max(0, now - copy.started_ms) // 1000,
            broken_at=copy.broken_at,
        )

    def _sends(self, policy: Policy) -> dict[str, health.Sends]:
        """Each connector's send journal, summed up. One that can't be read is left out."""
        found: dict[str, health.Sends] = {}
        if self.connectors is None:
            return found
        now = self.connectors.clock_ms()
        for name in policy.connectors:
            try:
                found[name] = health.sends(self.connectors.journal(name), now)
            except OSError:
                continue
        return found


class AdminApp:
    def __init__(
        self,
        store: SecretStore,
        keys: KeySet,
        policy: Callable[[], Policy],
        setup: SetupCodes,
        tokens: TokenManager | None = None,
        login: LoginService | None = None,
        *,
        gateway_keys: GatewayKeys | None = None,
        connectors: SmtpConnectors | None = None,
        env_names: Callable[[], Collection[str]] | None = None,
        reports: ReportStore | None = None,
        passkeys: Passkeys | None = None,
        portal: PortalSessions | None = None,
        onboard: OnboardService | None = None,
        revoker: secretops.Revoker | None = None,
        reviews: ReviewQueue | None = None,
        egress_fetched_ago: Callable[[], float | None] | None = None,
        bridges: health.Bridges | None = None,
        gateway_status: Callable[[], GatewayStatus] | None = None,
        policy_state: Callable[[], health.PolicyState | None] | None = None,
        managed: ManagedPolicy | None = None,
        source: Callable[[], tuple[str, str]] | None = None,
        random: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        """``gateway_keys`` is the proxy's ratchet. Without it, ``GET /gateway-key`` answers from
        the policy and the previous key can't be retired here.

        ``connectors`` and ``env_names`` (the ``env:`` variables the vault found set) are for
        ``GET /health``. Without them it shows no sends, and every ``env:`` reference unset.

        ``reports`` is the reported copy of the gateway's ledger, for ``/ledger/reported`` and
        health. Without it, those routes answer 503 and health has no ``ledger_copy``.

        ``passkeys`` is the portal's passkey file, shared with the portal. Without it,
        ``/passkeys`` answers 503 and health has no ``passkeys``.

        ``portal`` holds the portal's sessions: ``/sessions`` lists and ends them, and removing
        a passkey ends the sessions it made. Without a portal there are none.

        ``onboard`` is onboarding by URL's service, shared with the portal. Without it, the
        ``/onboard`` routes answer 503.

        ``revoker`` revokes a deleted refresh token whose credential names a ``revocation_url``
        (M7 design D.9), shared with the portal. Without it, nothing is revoked.

        ``reviews`` holds the review jobs the gateway polls for (M7 design F.2). Without it,
        the ``/review`` routes answer 503.

        ``egress_fetched_ago`` says how long ago the egress role last fetched its lists, for
        health (M7 design J). Without it, health has no ``egress_allowlist_stale``.

        ``bridges`` is the tier and the bridges the vault was started with, for health's route
        findings (M7 design C.10, J). Without it, health judges routes as the hardened tier's.

        ``gateway_status`` is the gateway's latest status report, for health's ``gateway``
        section (M6 design K.1, M.5). Without it, health has none. ``policy_state`` is the
        policy store's, for health's ``policy`` section (M.5); without it, health has none.

        ``managed`` is a managed vault's policy (``vault/managed.py``), which the ``/policy``
        routes read and write (M6 design H, N.1); without it the policy is declarative and they
        answer ``policy_not_managed``. ``source`` reads the policy the vault was configured with
        (its text and label), for ``import?from_env=1`` (H.5, G-14); without it (the policy came
        on standard input, read once) that import is refused.

        ``random`` makes a generated token's bytes (``secrets.token_bytes``; tests)."""
        self._store = store
        self._random = random
        self._managed = managed
        self._source = source
        self._reviews = reviews
        self._revoker = revoker
        self._onboard = onboard
        self._portal = portal
        self._passkeys = passkeys
        self._reports = reports
        self._connectors = connectors
        self._keys = keys
        self._gateway_keys = gateway_keys
        self._policy = policy
        self._setup = setup
        self._tokens = tokens
        if login is None and tokens is not None:
            login = LoginService(tokens)
        self._login = login
        self._health_reader = HealthReader(
            store,
            policy,
            login,
            connectors=connectors,
            env_names=env_names,
            reports=reports,
            passkeys=passkeys,
            egress_fetched_ago=egress_fetched_ago,
            bridges=bridges or health.Bridges(),
            gateway_status=gateway_status,
            policy_state=policy_state,
        )
        self.app = Starlette(
            routes=[
                Route("/secrets", self._list, methods=["GET"]),
                Route("/secrets/{name}", self._put, methods=["PUT"]),
                Route("/secrets/{name}", self._delete, methods=["DELETE"]),
                Route("/setup-code", self._setup_code, methods=["POST"]),
                Route("/setup-code/status", self._setup_code_status, methods=["GET"]),
                Route("/passkeys", self._passkey_list, methods=["GET"]),
                Route("/passkeys/{fingerprint}", self._passkey_remove, methods=["DELETE"]),
                Route("/sessions", self._session_list, methods=["GET"]),
                Route("/sessions", self._session_end_all, methods=["DELETE"]),
                Route("/gateway-key", self._gateway_key, methods=["GET"]),
                Route("/gateway-key/retire-previous", self._retire_previous, methods=["POST"]),
                Route("/egress-key", self._egress_key, methods=["GET"]),
                Route("/oauth", self._oauth_status, methods=["GET"]),
                Route("/oauth/flows/{flow}", self._oauth_cancel, methods=["DELETE"]),
                Route("/oauth/{credential}/login", self._oauth_login, methods=["POST"]),
                Route("/oauth/{credential}/complete", self._oauth_complete, methods=["POST"]),
                Route("/oauth/{credential}/reset", self._oauth_reset, methods=["POST"]),
                Route("/onboard/discover", self._onboard_discover, methods=["POST"]),
                Route("/onboard/{onboarding}/register", self._onboard_register, methods=["POST"]),
                Route("/onboard/{onboarding}/fragment", self._onboard_fragment, methods=["POST"]),
                Route("/onboard/{onboarding}", self._onboard_cancel, methods=["DELETE"]),
                Route("/review/jobs/{job}", self._review_read, methods=["GET"]),
                Route("/review/jobs/{job}/diff", self._review_diff, methods=["POST"]),
                Route("/review/{server}", self._review_queue, methods=["POST"]),
                Route("/review/{server}/clear", self._review_clear, methods=["POST"]),
                Route("/health", self._health, methods=["GET"]),
                Route("/ledger/reported", self._ledger_reported, methods=["GET"]),
                Route("/ledger/reported/restart", self._ledger_restart, methods=["POST"]),
                Route("/policy", self._policy_head, methods=["GET"]),
                Route("/policy/revisions", self._policy_history, methods=["GET"]),
                Route("/policy/revisions/{revision}", self._policy_revision, methods=["GET"]),
                Route("/policy/revisions/{revision}/diff", self._policy_diff, methods=["GET"]),
                Route("/policy/export", self._policy_export, methods=["GET"]),
                Route("/policy/import", self._policy_import, methods=["POST"]),
                Route("/policy/rollback/{revision}", self._policy_rollback, methods=["POST"]),
            ]
        )

    async def _list(self, request: Request) -> Response:
        return JSONResponse({"secrets": [json_safe(m.as_dict()) for m in self._store.metadata()]})

    async def _put(self, request: Request) -> Response:
        name = request.path_params["name"]
        # The name first: a bad one is refused whatever the body.
        refusal = secretplan.check_name(name)
        if refusal is not None:
            return _refused(refusal)
        body = await request.body()
        if len(body) > MAX_BODY:
            return _error(413, "body too large")
        try:
            data: Any = json.loads(body)
        except ValueError:
            return _error(400, "body must be JSON")
        token = None
        if isinstance(data, dict) and "generate" in data:
            if data["generate"] is not True or not set(data) <= {"generate", "origins"}:
                return _error(400, "expected {generate: true, origins?}")
            token = generated_token(self._random)
            data = {key: value for key, value in data.items() if key != "generate"}
            data["value"] = token
        policy = self._policy()
        plan = secretplan.plan_put(name, data, policy)
        if isinstance(plan, SecretRefusal):
            return _refused(plan)
        # A connector's secret is refused with or without --origin, which would bind it there.
        if token is not None and (
            plan.oauth or "origins" not in plan.binding or _connector_secret(policy, name)
        ):
            return _refused(GENERATE_REFUSED)
        binding = await secretops.put(self._store, self._tokens, plan, via="socket")
        if isinstance(binding, SecretRefusal):
            return _refused(binding)
        if token is not None:
            # Only the hash: the bridge holds it as ZOEYMCP_BRIDGE_TOKEN_SHA256 (X14).
            return JSONResponse({"name": name, "binding": binding, "sha256": hash_token(token)})
        return JSONResponse({"name": name, "binding": binding})

    async def _delete(self, request: Request) -> Response:
        plan = secretplan.plan_delete(request.path_params["name"], self._policy())
        done = await secretops.delete(
            self._store, self._tokens, plan, via="socket", revoker=self._revoker
        )
        if isinstance(done, SecretRefusal):
            return _refused(done)
        # The revocation, if any, runs on: the answer never waits for it (D.9).
        return JSONResponse({"name": plan.name, "deleted": True, "revocation": done})

    # --- setup codes, passkeys and sessions (M5 design E, D.5, F.2) ----------------------------

    async def _setup_code(self, request: Request) -> Response:
        """``{reset?}``: a new code, which only this answer carries (R61's recorded exception,
        D16), with how many passkeys are enrolled (null when the file can't be verified) and
        the origins to redeem it on."""
        data = await _json_object(request, MAX_SETUP_BODY)
        if isinstance(data, Response):
            return data
        reset = data.get("reset", False)
        if not set(data) <= {"reset"} or not isinstance(reset, bool):
            return _error(400, "expected {reset?: bool}")
        try:
            code, record = self._setup.issue(reset=reset)
        except OSError:
            message = (
                "the setup code couldn't be written, so none was issued; check the state volume"
            )
            return _reason(500, message, "not_written")
        logs.event("setup_code_issued", expires=record.expires, reset=record.reset)
        admin = self._policy().admin
        answer = {
            "code": code.reveal(),
            "expires": record.expires,
            "reset": record.reset,
            "passkeys": self._passkey_count(),
            "origins": [] if admin is None else list(admin.origins),
        }
        return JSONResponse(answer)

    async def _setup_code_status(self, request: Request) -> Response:
        """``?wait=N``: what became of the code this vault last issued or redeemed, once it
        changes or N seconds (at most 60) pass. Never the code (E.4)."""
        query = dict(request.query_params)
        if set(query) - {"wait"} or len(request.query_params.multi_items()) != len(query):
            return _reason(400, "expected ?wait=N", "bad_query")
        try:
            wait = _number(query.get("wait"))
        except _BadNumber:
            return _reason(400, "wait is a number of seconds", "bad_query")
        seconds = min(wait or 0, MAX_STATUS_WAIT)
        return JSONResponse(await self._setup.wait_status(seconds))

    def _passkey_count(self) -> int | None:
        """How many passkeys are enrolled: None when the file can't be verified, 0 without a
        passkey holder."""
        holder = self._passkeys
        if holder is None:
            return 0
        return None if holder.unavailable else len(holder.document.credentials)

    def _holder(self) -> Passkeys | Response:
        holder = self._passkeys
        if holder is None:
            return _reason(503, NO_PASSKEYS, "unavailable")
        if holder.unavailable:
            return _reason(503, PASSKEYS_UNAVAILABLE, "unavailable")
        return holder

    async def _passkey_list(self, request: Request) -> Response:
        """Every passkey as D.5 shows it: never a key, a full ID or the user handle."""
        holder = self._holder()
        if isinstance(holder, Response):
            return holder
        listed = [
            passkey_file.describe(passkey, holder.fingerprint(passkey.id))
            for passkey in holder.document.credentials
        ]
        return JSONResponse({"passkeys": listed})

    async def _passkey_remove(self, request: Request) -> Response:
        """Remove a passkey by its fingerprint, the last one too: host access is the recovery
        path (Q26). Written before it takes effect."""
        holder = self._holder()
        if isinstance(holder, Response):
            return holder
        wanted = request.path_params["fingerprint"]
        if not _FINGERPRINT.fullmatch(wanted):
            message = "a fingerprint is 16 hex digits, as zoeymcp passkeys lists them"
            return _reason(400, message, "bad_fingerprint")
        try:
            removed = holder.remove(wanted, allow_last=True)
        except PasskeyError as exc:
            status, message = _PASSKEY_REFUSALS[exc.reason]
            return _reason(status, message, exc.reason)
        ended = 0 if self._portal is None else self._portal.end_credential(wanted)
        remaining = len(holder.document.credentials)
        logs.event(
            "passkey_removed",
            credential=wanted,
            rp_id=removed.rp_id,
            origin=removed.origin,
            sessions_ended=ended,
            remaining=remaining,
        )
        answer = {
            "removed": passkey_file.describe(removed, wanted),
            "sessions_ended": ended,
            "remaining": remaining,
        }
        return JSONResponse(answer)

    async def _session_list(self, request: Request) -> Response:
        """Every live portal session (F.2): fingerprints, never an ID or either half."""
        listed = [] if self._portal is None else self._portal.session_list()
        return JSONResponse({"sessions": listed})

    async def _session_end_all(self, request: Request) -> Response:
        """End every portal session, with no step-up: host access is the recovery path."""
        ended = 0 if self._portal is None else self._portal.end_all()
        return JSONResponse({"ended": ended})

    async def _gateway_key(self, request: Request) -> Response:
        if self._gateway_keys is None:
            generation = self._policy().gateway_key_generation
            key = self._keys.gateway_key(generation)
            return JSONResponse({"generation": generation, "key": key, "previous": None})
        return JSONResponse(self._gateway_keys.info())

    async def _egress_key(self, request: Request) -> Response:
        """The egress role's key for the running ``egress_key_generation``: R61's third scoped
        exception (M7 design G.3, DD-14). No previous key is accepted, so none is shown."""
        generation = self._policy().egress_key_generation
        return JSONResponse({"key": self._keys.egress_key(generation), "generation": generation})

    async def _retire_previous(self, request: Request) -> Response:
        if self._gateway_keys is None:
            return _error(503, NO_GATEWAY_KEYS)
        try:
            retired = self._gateway_keys.retire_previous()
        except GatewayKeyError:
            # The retirement took effect; only the file is behind (M3 design C.2).
            return _error(500, NOT_WRITTEN)
        return JSONResponse({"retired": retired, **self._gateway_keys.info()})

    # --- OAuth (design E.1) --------------------------------------------------------------------

    async def _oauth_status(self, request: Request) -> Response:
        if self._login is None:
            return _error(503, NO_TOKENS)
        return JSONResponse({"credentials": json_safe(self._login.status())})

    async def _oauth_login(self, request: Request) -> Response:
        if self._login is None:
            return _error(503, NO_TOKENS)
        data = await _json_object(request, MAX_BODY)
        if isinstance(data, Response):
            return data
        if not set(data) <= {"rebind"} or not isinstance(data.get("rebind", False), bool):
            return _error(400, "expected {rebind?: bool}")
        try:
            answer = await self._login.start(
                request.path_params["credential"], rebind=data.get("rebind", False)
            )
        except LoginError as exc:
            return _login_error(exc)
        return JSONResponse(answer)

    async def _oauth_complete(self, request: Request) -> Response:
        if self._login is None:
            return _error(503, NO_TOKENS)
        data = await _json_object(request, MAX_COMPLETE_BODY)
        if isinstance(data, Response):
            return data
        flow, redirect_url = data.get("flow"), data.get("redirect_url")
        if set(data) != {"flow", "redirect_url"} or not (
            isinstance(flow, str) and isinstance(redirect_url, str)
        ):
            return _error(400, "expected {flow, redirect_url}")
        try:
            answer = await self._login.complete(
                request.path_params["credential"], flow, redirect_url
            )
        except LoginError as exc:
            return _login_error(exc)
        return JSONResponse(answer)

    async def _oauth_cancel(self, request: Request) -> Response:
        if self._login is None:
            return _error(503, NO_TOKENS)
        return JSONResponse({"cancelled": self._login.cancel(request.path_params["flow"])})

    async def _oauth_reset(self, request: Request) -> Response:
        if self._tokens is None:
            return _error(503, NO_TOKENS)
        name = request.path_params["credential"]
        if not self._tokens.reset(name):
            return _login_error(LoginError("not_oauth", f"no oauth2 credential named {name!r}"))
        return JSONResponse({"credential": name, "reset": True})

    # --- onboarding by URL (M7 design M.1) -----------------------------------------------------

    async def _onboard_discover(self, request: Request) -> Response:
        """The plan, or the onboarding of the same URL and names carried on (D.8, D.11)."""
        if self._onboard is None:
            return _reason(503, NO_ONBOARDING, "unavailable")
        data = await _json_object(request, DISCOVER_BODY_MAX)
        if isinstance(data, Response):
            return data
        try:
            answer = await self._onboard.discover(data)
        except OnboardError as exc:
            return _onboard_refused(exc)
        return JSONResponse(answer)

    async def _onboard_register(self, request: Request) -> Response:
        """``{client_secret?}``: the secret stored and fragment 1 (D.7). Never echoed."""
        if self._onboard is None:
            return _reason(503, NO_ONBOARDING, "unavailable")
        data = await _json_object(request, REGISTER_BODY_MAX)
        if isinstance(data, Response):
            return data
        try:
            answer = await self._onboard.register(request.path_params["onboarding"], data)
        except OnboardError as exc:
            return _onboard_refused(exc)
        return JSONResponse(answer)

    async def _onboard_fragment(self, request: Request) -> Response:
        """``{indent?}``: fragment 1, made or again (OPS-2)."""
        if self._onboard is None:
            return _reason(503, NO_ONBOARDING, "unavailable")
        data = await _json_object(request, FRAGMENT_BODY_MAX)
        if isinstance(data, Response):
            return data
        try:
            answer = await self._onboard.fragment(request.path_params["onboarding"], data)
        except OnboardError as exc:
            return _onboard_refused(exc)
        return JSONResponse(answer)

    async def _onboard_cancel(self, request: Request) -> Response:
        if self._onboard is None:
            return _reason(503, NO_ONBOARDING, "unavailable")
        try:
            await self._onboard.cancel(request.path_params["onboarding"])
        except OnboardError as exc:
            return _onboard_refused(exc)
        return Response(status_code=204)

    # --- review jobs (M7 design F.2, M.1) ------------------------------------------------------

    async def _review_queue(self, request: Request) -> Response:
        """``{fresh?}``: ``{job, server, state, reused}``, the job queued for the gateway's
        poll or the CLI's ``done`` one at the current view digest (OPS-11)."""
        if self._reviews is None:
            return _reason(503, NO_REVIEWS, "unavailable")
        data = await _json_object(request, REVIEW_BODY_MAX)
        if isinstance(data, Response):
            return data
        fresh = data.get("fresh", False)
        if not set(data) <= {"fresh"} or not isinstance(fresh, bool):
            return _review_refused("bad_body", {})
        server = request.path_params["server"]
        try:
            job = await self._reviews.queue_review(server, _REVIEW_OWNER, fresh=fresh)
        except ReviewRefused as exc:
            return _review_refused(exc.reason, exc.fields, server=server)
        answer = _job_answer(job, managed=self._managed is not None)
        answer["reused"] = job.state == "done"
        return JSONResponse(answer)

    async def _review_clear(self, request: Request) -> Response:
        """``{}``: ``{job, server, state}``, a clear of the server's drift marks queued for the
        gateway's poll (M6 design J.4), always a new job; ``clear_unsupported`` while the
        polling gateway runs no clear jobs. It reads as a review job does: a clear the gateway
        refused, since an included tool doesn't match its pin, fails ``clear_not_clean``."""
        if self._reviews is None:
            return _reason(503, NO_REVIEWS, "unavailable")
        data = await _json_object(request, REVIEW_BODY_MAX)
        if isinstance(data, Response):
            return data
        if data:
            return _review_refused("bad_body", {})
        server = request.path_params["server"]
        try:
            job = await self._reviews.queue_clear(server, _REVIEW_OWNER)
        except ReviewRefused as exc:
            return _review_refused(exc.reason, exc.fields, server=server)
        return JSONResponse(_job_answer(job, managed=self._managed is not None))

    async def _review_read(self, request: Request) -> Response:
        """``?wait=N``: the CLI's job once it is done or failed, or after N seconds (at most
        30): its state, and its report once done; a failed job answers its refusal."""
        if self._reviews is None:
            return _reason(503, NO_REVIEWS, "unavailable")
        query = dict(request.query_params)
        if set(query) - {"wait"} or len(request.query_params.multi_items()) != len(query):
            return _reason(400, "expected ?wait=N", "bad_query")
        try:
            wait = _number(query.get("wait"))
        except _BadNumber:
            return _reason(400, "wait is a number of seconds", "bad_query")
        try:
            job = await self._reviews.review_job(
                request.path_params["job"], _REVIEW_OWNER, wait=min(wait or 0, REVIEW_WAIT_MAX)
            )
        except ReviewRefused as exc:
            return _review_refused(exc.reason, exc.fields)
        if job.state == "failed":
            return _failed(job)
        return JSONResponse(_job_answer(job, managed=self._managed is not None))

    async def _review_diff(self, request: Request) -> Response:
        """``{include, allow, approve, indent?}``: fragment 2 for the CLI's done job, against
        the running policy (F.6, E.4), as the portal's ``POST /api/review/jobs/{job}/diff``
        makes it; ``review_stale`` after a reload that changed the server's tools (GR-11)."""
        if self._reviews is None:
            return _reason(503, NO_REVIEWS, "unavailable")
        data = await _json_object(request, REVIEW_DIFF_BODY_MAX)
        if isinstance(data, Response):
            return data
        if not REVIEW_DIFF_KEYS <= set(data) <= REVIEW_DIFF_KEYS | {"indent"}:
            return _review_refused("bad_body", {})
        try:
            job = await self._reviews.review_job(request.path_params["job"], _REVIEW_OWNER)
        except ReviewRefused as exc:
            return _review_refused(exc.reason, exc.fields)
        if job.state == "failed":
            return _failed(job)
        if job.report is None:
            return _reason(400, "the review isn't done yet", "bad_body")
        policy = self._policy()
        answer = reviewview.diff(
            job.report.model_dump(mode="json", exclude_unset=True),
            listed_server(policy, job.server),
            data,
            policy=policy,
            most=tools_max(policy),
            source=INLINE_SOURCE if self._onboard is None else self._onboard.source,
        )
        if isinstance(answer, Refusal):
            return JSONResponse(answer.body(), status_code=answer.status)
        return JSONResponse(answer)

    # --- health (M5 design I) ------------------------------------------------------------------

    async def _health(self, request: Request) -> Response:
        return JSONResponse(self._health_reader.report())

    # --- the reported ledger (M5 design J.4, J.5) -----------------------------------------------

    async def _ledger_reported(self, request: Request) -> Response:
        """A page of the copy, newest first: ``?before=SEQ&limit=N`` (1 to 200). The first
        page's orphans are judged against the live chain and every kept archived epoch."""
        copy = self._reports
        if copy is None:
            return _reason(503, "the vault keeps no reported copy", "unavailable")
        query = dict(request.query_params)
        if set(query) - {"before", "limit"} or len(request.query_params.multi_items()) != len(
            query
        ):
            return _reason(400, "expected ?before=SEQ&limit=N", "bad_query")
        try:
            before, limit = _number(query.get("before")), _number(query.get("limit"))
        except _BadNumber:
            return _reason(400, "before and limit are numbers", "bad_query")
        policy = self._policy()
        journals = self._journals(policy)

        def read() -> tuple[list[dict[str, Any]], ledgerview.Coverage | None]:
            return copy.records(), None if before is not None else copy.archived_coverage()

        try:
            records, archived = await asyncio.to_thread(read)
        except (CopyUnavailable, OSError):
            view = ledgerview.state(copy.held, now=copy.clock())
            view["state"] = "unavailable"
            answer: dict[str, Any] = {"state": view, "rows": [], "orphans": [], "next": None}
            answer |= {"refused": None, "archives": []}
            return JSONResponse(answer)
        page = ledgerview.page(
            records,
            held=copy.held,
            journals=journals,
            now=copy.clock(),
            before=before,
            limit=ledgerview.MAX_LIMIT if limit is None else limit,
            broken_at=copy.broken_at,
            archived=archived,
        )
        return JSONResponse({**page, "refused": copy.refused, "archives": copy.archives()})

    def _journals(self, policy: Policy) -> dict[str, list[dict[str, Any]]]:
        """Each connector's journal records; one that can't be read is left out."""
        found: dict[str, list[dict[str, Any]]] = {}
        if self._connectors is None:
            return found
        for name in policy.connectors:
            with contextlib.suppress(OSError):
                found[name] = self._connectors.records(name)
        return found

    async def _ledger_restart(self, request: Request) -> Response:
        """``{"dry_run": true}``: the restart's plan. ``{"plan": P}``: run it, unless the
        plan is no longer ``P`` (409 ``changed``, with the plan now)."""
        copy = self._reports
        if copy is None:
            return _reason(503, "the vault keeps no reported copy", "unavailable")
        data = await _json_object(request, MAX_BODY)
        if isinstance(data, Response):
            return data
        dry_run = data == {"dry_run": True}
        if not dry_run and (set(data) != {"plan"} or not isinstance(data["plan"], dict)):
            return _error(400, 'expected {"dry_run": true} or {"plan": ...}')
        async with copy.lock:
            try:
                plan = copy.plan_restart()
                if dry_run:
                    return JSONResponse({"plan": plan.to_json()})
                if plan.to_json() != data["plan"]:
                    raise PlanChanged(plan)
                done = await asyncio.to_thread(copy.restart, plan)
            except NotRestartable:
                message = "the copy takes reports; only a fork, gap or full is restarted"
                return _reason(409, message, "not_restartable")
            except CopyUnavailable:
                return _reason(503, "the reported copy can't be read", "unavailable")
            except PlanChanged as exc:
                body = {
                    "error": "the copy changed since the restart was planned",
                    "reason": "changed",
                    "plan": exc.plan.to_json(),
                }
                return JSONResponse(body, status_code=409)
            except OSError:
                return _reason(500, NOT_WRITTEN, "not_written")
        return JSONResponse({"restarted": done.to_json(), "head": copy.head().to_json()})

    # --- the managed policy (M6 design H, M.6, N.1) -------------------------------------------

    async def _policy_head(self, request: Request) -> Response:
        """The mode and, in managed mode, the head (N.1): its revision, digest and deployment
        (8 characters each), when, how and by whom it was written, the revision the gateway
        runs (K.1), and a saved revision that isn't running. No hidden field (Y13). The
        witness is step 17's."""
        managed = self._managed
        if managed is None:
            return JSONResponse({"mode": self._policy().mode, "revision": None})
        store = managed.store
        head, header = store.head, store.header
        assert head is not None  # noqa: S101 - a managed store has one
        assert header is not None  # noqa: S101
        answer = {
            "mode": "managed",
            "revision": head.revision,
            "digest8": head.digest.removeprefix("sha256:")[:8],
            "deployment8": head.deployment[:8],
            "created": header["created"],
            "origin": header["origin"],
            "kind": header["kind"],
            "author": dict(header["author"]),
            "witness": None,
            "gateway": managed.gateway(),
            "not_running": managed.not_running,
        }
        return JSONResponse(answer)

    async def _policy_history(self, request: Request) -> Response:
        """``?before=N&limit=N``: a page of history, newest first (H.1), and the next page's
        ``before``; a revision in quarantine is a gap."""
        managed = self._managed
        if managed is None:
            return _not_managed()
        query = dict(request.query_params)
        if set(query) - {"before", "limit"} or len(request.query_params.multi_items()) != len(
            query
        ):
            return _reason(400, "expected ?before=N&limit=N", "bad_query")
        try:
            before, limit = _number(query.get("before")), _number(query.get("limit"))
        except _BadNumber:
            return _reason(400, "before and limit are numbers", "bad_query")
        if limit is not None and not 1 <= limit <= HISTORY_PAGE_MAX:
            return _reason(400, f"limit is 1 to {HISTORY_PAGE_MAX}", "bad_query")
        page = history_page(managed.store, before, limit or HISTORY_PAGE_MAX)
        return JSONResponse(page)

    async def _policy_revision(self, request: Request) -> Response:
        """One revision's header, as history shows it (H.1)."""
        managed = self._managed
        if managed is None:
            return _not_managed()
        number = _revision(request.path_params["revision"])
        if isinstance(number, Response):
            return number
        if request.query_params:
            return _reason(400, "this route takes no query", "bad_query")
        found = managed.store.history(number + 1, 1)
        if not found or found[0]["revision"] != number or found[0].get("gap"):
            why = managed.store.missing(number) or "revision_unreadable"
            return _answer(refusal(why, revision=str(number)))
        return JSONResponse(found[0])

    async def _policy_diff(self, request: Request) -> Response:
        """``?against=M``: revision N's diff from M, by default its parent (H.2), through the
        policy view's renderer: no hidden value, as in the portal (Y13)."""
        managed = self._managed
        if managed is None:
            return _not_managed()
        number = _revision(request.path_params["revision"])
        if isinstance(number, Response):
            return number
        query = dict(request.query_params)
        if set(query) - {"against"} or len(request.query_params.multi_items()) != len(query):
            return _reason(400, "expected ?against=M", "bad_query")
        try:
            against = _number(query.get("against"))
        except _BadNumber:
            return _reason(400, "against is a revision number", "bad_query")
        answer = diff_answer(managed.store, number, against)
        if isinstance(answer, Refusal):
            return _answer(answer)
        return JSONResponse(answer)

    async def _policy_export(self, request: Request) -> Response:
        """``?revision=N&mode=managed|declarative&for=compose``: the head's policy, or a kept
        revision's, as ``zoeymcp policy import`` takes it back (H.6). R61's fourth scoped
        exception: it holds placeholders and client token hashes (DD-4); never stored by a
        cache, and logged."""
        managed = self._managed
        if managed is None:
            return _not_managed()
        query = dict(request.query_params)
        if set(query) - {"revision", "mode", "for"} or len(
            request.query_params.multi_items()
        ) != len(query):
            return _reason(400, "expected ?revision=N&mode=M&for=compose", "bad_query")
        try:
            number = _number(query.get("revision"))
        except _BadNumber:
            return _reason(400, "revision is a number", "bad_query")
        mode = query.get("mode", "managed")
        target = query.get("for")
        if mode not in _EXPORT_MODES or target not in (None, "compose"):
            return _reason(400, "mode is managed or declarative; for is compose", "bad_query")
        revision = managed.revision if number is None else number
        answer = export_answer(
            managed.store,
            revision,
            mode="declarative" if mode == "declarative" else "managed",
            target="compose" if target == "compose" else "plain",
        )
        if isinstance(answer, Refusal):
            return _answer(answer)
        logs.event("policy_exported", revision=revision, via="socket")
        return JSONResponse(answer, headers={"cache-control": "no-store"})

    async def _policy_import(self, request: Request) -> Response:
        """``POST /policy/import``: a YAML body, or ``from_env=1`` with none (H.5), planned
        with ``plan=1``, else committed (the module docstring)."""
        managed = self._managed
        if managed is None:
            return _not_managed()
        query = _write_query(request, _IMPORT_QUERY)
        if isinstance(query, Response):
            return query
        if query.baseline_only and not query.from_env:
            return _reason(400, "baseline_only=1 goes with from_env=1", "bad_query")
        body = await request.body()
        if query.from_env:
            if body:
                return _reason(400, "from_env=1 takes no body", "bad_body")
            if self._source is None:
                detail = "the vault's policy came on standard input, which it read once at start"
                return _answer(refusal("import_refused", detail=detail))
            try:
                text, label = self._source()
            except PolicyError as exc:
                found = gate.refused_text(exc.source, exc.findings)
                return _answer(refusal("import_refused", detail=found))
        else:
            kind = request.headers.get("content-type", "").partition(";")[0].strip().lower()
            if kind != IMPORT_TYPE:
                return _reason(415, f"send the policy as {IMPORT_TYPE}", "content_type")
            if len(body) > IMPORT_MAX:
                return _reason(413, "an import is at most 1 MiB", "too_large")
            try:
                text, label = body.decode("utf-8"), "the import"
            except UnicodeDecodeError:
                return _answer(refusal("import_refused", detail="the import isn't UTF-8"))
        try:
            given = gate.admit_text(text, label, environ=managed.environ).policy
        except GateRefused as exc:
            return _answer(refusal("import_refused", detail=str(exc)))
        base = _if_match(request)
        if isinstance(base, Response):
            return base
        # Shaped on the revision it is planned on, so a retry whose answer was lost is shaped
        # as its first try was (already_saved, G.6 step 2); a base no longer readable leaves
        # the head's, and the write answers policy_moved.
        basis, seed = managed.policy, managed.store.seed_digest
        if base is not None and base != managed.revision:
            read = read_revision(managed.store, base)
            if not isinstance(read, Refusal):
                basis, seed = read[1], read[0].body.seed_digest
        shaped = import_shaped(
            seed,
            basis,
            given,
            from_env=query.from_env,
            baseline_only=query.baseline_only,
        )
        if isinstance(shaped, Refusal):
            return _answer(shaped)
        return await self._policy_write(request, query, shaped)

    async def _policy_rollback(self, request: Request) -> Response:
        """``POST /policy/rollback/{revision}``: the target's policy carried forward (H.4: the
        key generations and every pin the head has kept from the head, ``admin`` the target's,
        since this is the host's), planned with ``plan=1``, else committed (H.3)."""
        managed = self._managed
        if managed is None:
            return _not_managed()
        number = _revision(request.path_params["revision"])
        if isinstance(number, Response):
            return number
        query = _write_query(request, _ROLLBACK_QUERY)
        if isinstance(query, Response):
            return query
        if await request.body():
            return _reason(400, "a rollback takes no body", "bad_body")
        shaped = rollback_shaped(managed.store, number)
        if isinstance(shaped, Refusal):
            return _answer(shaped)
        return await self._policy_write(request, query, shaped)

    async def _policy_write(self, request: Request, query: _WriteQuery, shaped: Shaped) -> Response:
        """A host write over the socket (H.5 step 5, G.6): the plan on ``If-Match``'s base (the
        head without one) answered for ``plan=1``; else, with ``If-Match`` and the plan's
        digest, the plan's confirmations checked and the write committed, then the entries it
        left unused removed when asked (G.8). A commit on a base the head has moved past is the
        write's to answer: a retry of the write that made the head is ``already_saved``."""
        managed = self._managed
        assert managed is not None  # noqa: S101 - the routes check it
        match = _if_match(request)
        if isinstance(match, Response):
            return match
        if match is None and not query.plan:
            return _answer(refusal("base_required"))
        base = managed.revision if match is None else match
        grants = Grants(revive=frozenset(query.revive), env=frozenset(query.env))
        digest = request.headers.get("x-zoeymcp-plan")
        if query.plan or base == managed.revision:
            # The plan of a retry whose answer was lost is already_saved, as its commit is:
            # the CLI plans before it commits (MISS-9, FM-16).
            planned = managed.plan(
                shaped.kind,
                "socket",
                base,
                shaped.candidate_of,
                author=SOCKET_AUTHOR,
                grants=grants,
                evidence=shaped.evidence,
            )
            if isinstance(planned, WriteRefused):
                return _write_refused(planned)
            if isinstance(planned, Written):
                return JSONResponse(written_answer(planned))
            lockout = lockout_rows(managed.policy, planned.policy, self._rp_ids())
            if query.plan:
                return JSONResponse(plan_answer(planned, lockout))
            if digest is None:
                return _answer(refusal("plan_changed"))
            wider = widenings(planned)
            if wider and not query.accept_widening:
                return _answer(refusal("import_widens", detail=", ".join(wider)))
            if lockout and not query.lockout_ok:
                detail = "; ".join(row.text for row in lockout)
                return _answer(refusal("lockout_unconfirmed", detail=detail))
        elif digest is None:
            return _answer(refusal("plan_changed"))
        # On another base the write answers a retry whose answer was lost (already_saved, its
        # confirmations given the first time) or policy_moved (G.6 step 2).
        capture = self._capture if query.revoke_removed else None
        written = managed.write(
            shaped.kind,
            "socket",
            base,
            shaped.candidate_of,
            author=SOCKET_AUTHOR,
            expected=digest,
            grants=grants,
            reason=query.reason,
            evidence=shaped.evidence,
            seed_digest=shaped.seed_digest,
            capture=capture,
            logged=shaped.logged,
        )
        if isinstance(written, WriteRefused):
            return _write_refused(written)
        removed: list[dict[str, Any]] = []
        for name, material in sorted((written.captured or {}).items()):
            done = await secretops.remove_unused(
                self._store, self._tokens, name, material, via="socket", revoker=self._revoker
            )
            if done is not None:
                removed.append({"name": name, "revoked": done == "requested"})
        return JSONResponse(written_answer(written, removed))

    def _capture(self, planned: WritePlan) -> dict[str, RevocationMaterial | None]:
        """Inside the write's section, from the policy still running: what revoking each
        store entry the write leaves unused needs (G.8, CR-5)."""
        tokens = self._tokens
        return {
            name: None if tokens is None else tokens.revocation(name)
            for name in planned.unused_slots
        }

    def _rp_ids(self) -> list[str] | None:
        """Every enrolled passkey's RP ID, for the lockout rows (I.1): none without a passkey
        file, None when it can't be verified."""
        holder = self._passkeys
        if holder is None:
            return []
        if holder.unavailable:
            return None
        return [passkey.rp_id for passkey in holder.document.credentials]


@dataclass(frozen=True)
class _WriteQuery:
    """A host write's query (N.1)."""

    plan: bool = False
    from_env: bool = False
    baseline_only: bool = False
    lockout_ok: bool = False
    revoke_removed: bool = False
    accept_widening: bool = False
    revive: tuple[str, ...] = ()
    env: tuple[str, ...] = ()
    reason: str | None = None


def _write_query(request: Request, allowed: frozenset[str]) -> _WriteQuery | Response:
    """The query of an import or a rollback: each flag at most once and ``1``, the grants
    repeated, the reason 1 to 200 printable characters."""
    flags: set[str] = set()
    grants: dict[str, list[str]] = {"allow_revive": [], "allow_env": []}
    reason = None
    for key, value in request.query_params.multi_items():
        if key not in allowed:
            return _reason(400, f"{key} isn't a query this route takes", "bad_query")
        if key in _GRANTS:
            grants[key].append(value)
        elif key == "reason":
            if reason is not None or not (1 <= len(value) <= REASON_MAX and value.isprintable()):
                return _reason(
                    400, f"reason is 1 to {REASON_MAX} printable characters", "bad_query"
                )
            reason = value
        elif key in flags or value != "1":
            return _reason(400, f"{key} is 1, once", "bad_query")
        else:
            flags.add(key)
    return _WriteQuery(
        plan="plan" in flags,
        from_env="from_env" in flags,
        baseline_only="baseline_only" in flags,
        lockout_ok="lockout_ok" in flags,
        revoke_removed="revoke_removed" in flags,
        accept_widening="accept_widening" in flags,
        revive=tuple(grants["allow_revive"]),
        env=tuple(grants["allow_env"]),
        reason=reason,
    )


def _if_match(request: Request) -> int | Response | None:
    """The revision a host write names in ``If-Match`` (N.1), None without one."""
    match = request.headers.get("if-match")
    if match is None:
        return None
    found = _IF_MATCH.fullmatch(match.strip())
    if found is None:
        return _reason(400, 'If-Match is "N", the revision planned on', "bad_query")
    return int(found[1])


def _revision(value: str) -> int | Response:
    """A revision number from a path."""
    try:
        number = _number(value)
    except _BadNumber:
        return _reason(400, "a revision is a number", "bad_query")
    assert number is not None  # noqa: S101 - a path segment is never empty
    return number


def _answer(refused: Refusal) -> JSONResponse:
    return JSONResponse(refused.body(), status_code=refused.status)


def _not_managed() -> JSONResponse:
    return _answer(refusal("policy_not_managed"))


def _write_refused(refused: WriteRefused) -> JSONResponse:
    status, body = refused_body(refused)
    return JSONResponse(body, status_code=status)


def _onboard_refused(exc: OnboardError) -> JSONResponse:
    return JSONResponse(exc.answer.body(), status_code=exc.answer.status)


def _job_answer(job: Job, *, managed: bool = False) -> dict[str, Any]:
    """A job as the socket answers it: never its digest or times; its report once ``done``, as
    the gateway posted it (or the review a clear the gateway refused rests on), and once done
    its way on (M6 design M.7, D-200), a save rather than a fragment when ``managed`` (Y25)."""
    answer: dict[str, Any] = {"job": job.id, "server": job.server, "state": job.state}
    if job.report is not None:
        answer["report"] = job.report.model_dump(mode="json", exclude_unset=True)
    if job.state == "done":
        steps = job_next(job.server, clear=job.work == "clear", managed=managed)
        answer["next"] = [step.answer() for step in steps]
    return answer


def _failed(job: Job) -> JSONResponse:
    """A failed job's refusal, beside the job's answer, with its way on."""
    assert job.failure is not None  # noqa: S101 - every failed job has one
    return _review_refused(job.failure, dict(job.fields), _job_answer(job), server=job.server)


def _review_refused(
    reason: str,
    fields: Mapping[str, str],
    more: Mapping[str, Any] | None = None,
    *,
    server: str | None = None,
) -> JSONResponse:
    """The catalogue's refusal (M.2), its text filled with ``fields``, beside ``more``, with its
    way on (``next``) when it is about ``server`` (D-200)."""
    answer = refusal(reason, **fields)
    steps = [step.answer() for step in refusal_next(server, reason)]
    body = {**(more or {}), **answer.body(), "next": steps}
    return JSONResponse(body, status_code=answer.status)


def _reason(status: int, message: str, reason: str) -> JSONResponse:
    return JSONResponse({"error": message, "reason": reason}, status_code=status)


class _BadNumber(ValueError):
    pass


def _number(value: str | None) -> int | None:
    """A query number, None when absent. Raises :class:`_BadNumber` unless plain digits."""
    if value is None:
        return None
    if not (value.isascii() and value.isdigit()) or len(value) > 15:
        raise _BadNumber(value)
    return int(value)


def socket_supported() -> bool:
    return sys.platform != "win32"
