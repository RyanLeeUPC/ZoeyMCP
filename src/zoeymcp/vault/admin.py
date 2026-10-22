"""The vault's local admin interface (design §4.5, §7.5).

Served on a Unix socket inside the vault container. Access control is the filesystem: the
socket's directory must be owned by the vault's uid and closed to everyone else, so only that
uid (or root, which already has the host) can connect. The CLI reaches it with
``docker exec <vault> zoeymcp secret ...``.

There is deliberately no endpoint that returns a secret value. Two answers carry a credential, as
recorded exceptions to R61 (M5 design D16): ``POST /setup-code`` the new setup code, and
``GET /gateway-key`` the gateway key.

``zoeymcp setup-code [--reset] [--wait]`` uses ``POST /setup-code`` and ``GET /setup-code/status``;
``zoeymcp passkeys`` and ``sessions`` list and remove the portal's passkeys and sessions, with no
step-up: host access is the recovery path (M5 design E).

``PUT/DELETE /secrets/{name}`` decide with :mod:`.secretplan` and write with :mod:`.secretops`,
which the portal shares (M5 design G). Secrets an oauth2 credential uses are written and deleted
through the token manager, which first waits for any refresh of that slot (design D.12). If the
store can't write its file, the change is kept in memory and the answer is a 500 that says so
(B.4).

``zoeymcp gateway-key`` prints the gateway key and any rotation pending; ``--retire-previous``
retires the previous key at once (M3 design C.2).

``zoeymcp login`` and ``oauth status|reset`` use the ``/oauth`` endpoints (design E.1). Their
errors are ``{"error", "reason"}`` with a stable reason. No answer holds a token, code, verifier
or secret; the authorization URL holds ``state`` and the PKCE challenge, which are useless
without the verifier the vault keeps.

``POST /onboard/discover``, ``POST /onboard/{onboarding}/register``, ``POST
/onboard/{onboarding}/fragment`` and ``DELETE /onboard/{onboarding}`` are onboarding by URL's
phase 1 (M7 design M.1), owned by the CLI: :class:`.onboard.OnboardService`, which the portal
shares, answers them, and a refusal is the catalogue's ``{"error", "reason"}`` with its own
status (M.2). A given client secret comes in the register body, and no answer carries it.

``POST /review/{server}``, ``GET /review/jobs/{job}?wait=N`` and ``POST
/review/jobs/{job}/diff`` are the review job path's (M7 design F.2, F.6, M.1), owned by the CLI:
the first queues a review of a server in the running view for the gateway's poll, or answers the
CLI's ``done`` job at the current view digest unless the body says ``{"fresh": true}`` (OPS-11);
the second answers the job's state, and its report once it is done, or a failed job's refusal;
the third makes fragment 2 from ``{include, allow, approve, indent?}`` as the portal does
(``portal/reviewview.py``), saving nothing. A refusal is the catalogue's ``{"error", "reason"}``
(M.2).

``zoeymcp health`` uses ``GET /health``: :mod:`.health`'s findings, from metadata only (M5
design I), gathered by :class:`HealthReader`, which the portal's ``GET /api/health`` shares.

``zoeymcp ledger --vault`` uses ``GET /ledger/reported``: the vault's copy of the gateway's
ledger, a page of :mod:`.ledgerview` rows with the send journals joined in, and the archived
epochs. ``--restart-chain`` uses ``POST /ledger/reported/restart``: ``{"dry_run": true}`` answers
the plan, and ``{"plan": ...}`` runs it if the copy hasn't changed since (M5 design J.4).
"""

from __future__ import annotations

import asyncio
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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..common import files

# The CLI reads these from common, so the gateway's entry path loads no vault code.
from ..common.adminsocket import DEFAULT_SOCKET as DEFAULT_SOCKET
from ..common.adminsocket import SOCKET_ENV as SOCKET_ENV
from ..common.policy.schema import Policy
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
from .oauth.login import LoginError, LoginService
from .oauth.tokens import TokenManager
from .onboard import (
    DISCOVER_BODY_MAX,
    FRAGMENT_BODY_MAX,
    REGISTER_BODY_MAX,
    OnboardError,
    OnboardService,
)
from .onboarding import INLINE_SOURCE, listed_server, tools_max
from .reportstore import CopyUnavailable, NotRestartable, PlanChanged, ReportStore
from .reviewjobs import Job, Owner, ReviewRefused
from .secretplan import NOT_WRITTEN as NOT_WRITTEN
from .secretplan import SecretRefusal
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

    async def review_job(self, job_id: str, owner: Owner, *, wait: float = 0) -> Job: ...


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
    wall clock a registered client's secret expiry is judged on (M7 design J, FM-28)."""

    store: SecretStore
    policy: Callable[[], Policy]
    login: LoginService | None = None
    connectors: SmtpConnectors | None = None
    env_names: Callable[[], Collection[str]] | None = None
    reports: ReportStore | None = None
    passkeys: Passkeys | None = None
    wall: Callable[[], float] = time.time

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
        the ``/review`` routes answer 503."""
        self._store = store
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
                Route("/health", self._health, methods=["GET"]),
                Route("/ledger/reported", self._ledger_reported, methods=["GET"]),
                Route("/ledger/reported/restart", self._ledger_restart, methods=["POST"]),
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
        plan = secretplan.plan_put(name, data, self._policy())
        if isinstance(plan, SecretRefusal):
            return _refused(plan)
        binding = await secretops.put(self._store, self._tokens, plan, via="socket")
        if isinstance(binding, SecretRefusal):
            return _refused(binding)
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
        try:
            job = await self._reviews.queue_review(
                request.path_params["server"], _REVIEW_OWNER, fresh=fresh
            )
        except ReviewRefused as exc:
            return _review_refused(exc.reason, exc.fields)
        answer = _job_answer(job)
        answer["reused"] = job.state == "done"
        return JSONResponse(answer)

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
            assert job.failure is not None  # noqa: S101 - every failed job has one
            return _review_refused(job.failure, dict(job.fields), _job_answer(job))
        return JSONResponse(_job_answer(job))

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
            assert job.failure is not None  # noqa: S101 - every failed job has one
            return _review_refused(job.failure, dict(job.fields), _job_answer(job))
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


def _onboard_refused(exc: OnboardError) -> JSONResponse:
    return JSONResponse(exc.answer.body(), status_code=exc.answer.status)


def _job_answer(job: Job) -> dict[str, Any]:
    """A job as the socket answers it: never its digest or times; its report once ``done``, as
    the gateway posted it."""
    answer: dict[str, Any] = {"job": job.id, "server": job.server, "state": job.state}
    if job.report is not None:
        answer["report"] = job.report.model_dump(mode="json", exclude_unset=True)
    return answer


def _review_refused(
    reason: str, fields: Mapping[str, str], more: Mapping[str, Any] | None = None
) -> JSONResponse:
    """The catalogue's refusal (M.2), its text filled with ``fields``, beside ``more``."""
    answer = refusal(reason, **fields)
    return JSONResponse({**(more or {}), **answer.body()}, status_code=answer.status)


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
