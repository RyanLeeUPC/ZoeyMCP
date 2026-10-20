"""``zoeymcp login``: the authorization code flow with PKCE, completed by pasting (design E).

The operator opens the authorization URL in a browser and approves. The browser is then sent to
the loopback ``redirect_uri``, which fails to load, and the operator pastes that address back.
The vault checks it against the pending flow, exchanges the code once, and stores the refresh
token through the token manager, which also caches the access token.

The client_credentials grant has nothing to consent to: its login is a test fetch.

Flows are owned (M5 design H.2): the admin socket's are the CLI's, the default, and the portal's
belong to one session. The portal checks a paste with :meth:`LoginService.check_paste` before it
asks for the passkey, and completes with :meth:`LoginService.complete` after.

A portal session's flow for a credential whose ``redirect_uri`` is its portal callback address
(``common/policy/callback.py``) can take the provider's redirect instead (H.6): the start mints
the flow's binder, which the portal sets as the binding cookie; the callback route's
:meth:`LoginService.receive_callback` consumes the flow's ``state`` and holds the code, and only
the owner's stepped-up :meth:`LoginService.complete_returned` exchanges it. Two different answers
for one flow, by callback or paste, fail it. A CLI flow never takes a callback.

Nothing here logs or returns a token, code, verifier, ``state`` or client secret. A provider's
``error_description`` from the redirect goes back to the CLI only, and is never logged.
"""

from __future__ import annotations

import hmac
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

import httpx

from ...common.policy.callback import callback_address, callback_origin
from ...common.policy.schema import OAuth2Credential, split_scope
from .. import logs
from ..bindings import BindingError, derive_binding, derive_oauth_binding, live_slot
from ..health import idle, last_failure, parse_time
from ..store import Secret
from . import pkce
from .pkce import (
    CLI_OWNER,
    FLOW_TTL,
    CallbackBinder,
    Flow,
    FlowTable,
    Redirect,
    RedirectError,
    Returned,
    TokenFunction,
    TooManyFlows,
    surface,
)
from .protocol import (
    CREDENTIAL_UNAVAILABLE,
    EXCHANGE_DEADLINE,
    GRANT_WARN_DAYS,
    OAUTH_CLIENT_REJECTED,
    OAUTH_MISCONFIGURED,
    OAUTH_RECONSENT_NEEDED,
    OAUTH_ROTATION_LOST,
    OAUTH_UNAVAILABLE,
    OAUTH_UNSUPPORTED,
    Client,
    Failure,
    GrantKind,
    Minted,
    Outcome,
    ScopeCheck,
    TokenRequest,
    build_client_credentials,
    build_exchange,
    check_login_scopes,
    classify,
    transport_failure,
)
from .tokens import BindingChanged, TokenManager, Trigger, slot_key

DAY: Final = 86400
CODE_HINT: Final = "the code expired or was already used; run login again"
NO_REFRESH_HINT: Final = (
    "for Google keep access_type: offline and prompt: consent; "
    "some providers need an offline_access scope"
)
# A paste's refusals after its state matched: an answer for the flow, so for a flow holding a
# returned code, a different answer (H.6's conflict rule). The others aren't answers for it.
_ANSWERS: Final = frozenset({"provider_error", "iss_mismatch", "no_code"})
# The failure reasons of a client ref, and what the ref holds.
_CLIENT_REFS: Final = {
    "client_id_unavailable": "client ID",
    "client_secret_unavailable": "client secret",
}

Clock = Callable[[], float]
# What the operator can do about a failure, for the portal's button (M5 design H.4).
Action = dict[str, str]


class LoginError(Exception):
    """A login step refused. ``reason`` is a stable code; ``details`` go into the answer."""

    def __init__(
        self, reason: str, message: str, *, details: Mapping[str, Any] | None = None
    ) -> None:
        self.reason = reason
        self.details = dict(details or {})
        super().__init__(message)


class LoginService:
    """Pending logins and their completion, for the admin socket and the portal, which share one
    service (M5 design H.2). Flows live in memory only."""

    def __init__(
        self,
        tokens: TokenManager,
        *,
        clock: Clock = time.monotonic,
        wall: Clock = time.time,
        token: TokenFunction = secrets.token_urlsafe,
    ) -> None:
        self._tokens = tokens
        self._clock = clock
        self._wall = wall
        self._token = token
        self._flows = FlowTable(clock, token=token)

    # --- start ---------------------------------------------------------------------------------

    async def start(
        self,
        credential: str,
        *,
        rebind: bool = False,
        owner: str = CLI_OWNER,
        origin: str | None = None,
    ) -> dict[str, Any]:
        """Start a login: the authorization URL for a refresh grant, or a client_credentials
        test fetch, whose answer has the shape of :meth:`complete`'s.

        A credential has one pending login, whoever started it: the answer's ``replaced`` says
        where the one this start replaced was started (``cli`` or ``portal``), or is None.

        ``callback_address`` says whether the credential's ``redirect_uri`` is its callback
        address on a listed portal origin, whoever starts; ``callback`` is that origin when this
        flow can take the callback (H.6): only a portal session's can, and only when the address
        is on ``origin``, the origin the session is on, since the binding cookie the start sets
        reaches that origin alone. Such a start mints the flow's binder: the answer then carries
        it as ``binder``, a :class:`CallbackBinder` that is never JSON, for the portal to set as
        the binding cookie and take out.
        """
        try:
            cred = self._credential(credential)
            if cred.grant == "client_credentials":
                logs.event("oauth_login_started", credential=credential)
                return await self._test_fetch(credential, cred)
            answer = self._start(credential, cred, rebind, owner, origin)
        except LoginError as exc:
            self._failed(credential, exc)
            raise
        logs.event("oauth_login_started", credential=credential)
        return answer

    def _start(
        self,
        credential: str,
        cred: OAuth2Credential,
        rebind: bool,
        owner: str,
        portal_origin: str | None,
    ) -> dict[str, Any]:
        if cred.authorize_url is None:
            raise LoginError(
                "no_authorize_url",
                f"{credential!r} has no authorize_url; {refresh_token_hint(credential, cred)}",
            )
        binding = self._binding(credential, cred)
        self._client(credential, cred)
        change = None
        existing = self._tokens.store.entry(slot_key(credential, cred))
        if existing is not None and existing.binding != binding:
            if not rebind:
                raise LoginError(
                    "binding_changed",
                    "the policy binds this grant differently; pass --rebind to accept",
                    details={"old": existing.binding, "new": binding},
                )
            change = {"old": existing.binding, "new": binding}
        replaced = self._flows.owner_of(credential)
        origin = callback_origin(cred.redirect_uri, credential, self._origins())
        binder = None
        if origin is not None and owner != CLI_OWNER and origin == portal_origin:
            binder = CallbackBinder.new(self._token)
        try:
            flow = self._flows.start(
                credential,
                cred.redirect_uri,
                rebind=rebind,
                owner=owner,
                callback=None if binder is None else origin,
                binder_hash=None if binder is None else binder.sha256(),
            )
        except TooManyFlows as exc:
            raise LoginError("too_many_flows", str(exc)) from None
        if replaced is not None:
            logs.event("oauth_flow_replaced", credential=credential, by=surface(owner))
        try:
            url = pkce.authorize_url(cred, state=flow.state, challenge=flow.challenge)
        except ValueError as exc:
            # A client_id ref or a reserved authorize_params name: check refuses both.
            self._flows.cancel(flow.id, owner)
            raise LoginError("authorize_misconfigured", str(exc)) from None
        answer: dict[str, Any] = {
            "flow": flow.id,
            "authorize_url": url,
            "redirect_uri": flow.redirect_uri,
            "expires": int(self._wall() + FLOW_TTL),
            "requested_scopes": split_scope(cred.scope, cred.scope_separator),
            "expected_scopes": cred.effective_expected_scopes,
            "client_auth": cred.effective_client_auth,
            "rotates": cred.rotates,
            "binding": binding,
            "binding_change": change,
            "replaced": None if replaced is None else surface(replaced),
            "callback": flow.callback,
            "callback_address": origin is not None,
        }
        if binder is not None:
            answer["binder"] = binder
        return answer

    # --- complete ------------------------------------------------------------------------------

    async def complete(
        self, credential: str, flow_id: str, redirect_url: str, owner: str = CLI_OWNER
    ) -> dict[str, Any]:
        """Check the pasted address, exchange its code and store the grant (design E.2, E.3).

        The flow is taken first, so any failure needs a new login.
        """
        try:
            return await self._complete(credential, flow_id, redirect_url, owner)
        except LoginError as exc:
            self._failed(credential, exc)
            raise

    async def _complete(
        self, credential: str, flow_id: str, redirect_url: str, owner: str
    ) -> dict[str, Any]:
        flow = self._flows.take(flow_id, credential, owner)
        if flow is None:
            raise _flow_unknown()
        cred, redirect = self._parse(credential, flow, redirect_url)
        return await self._redeem(credential, cred, flow, redirect.code)

    async def _redeem(
        self, credential: str, cred: OAuth2Credential, flow: Flow, code: Secret
    ) -> dict[str, Any]:
        """The one exchange of a taken flow's code, then the commit (design E.2, E.3): the same
        for a pasted code and one a callback returned."""
        client = self._client(credential, cred)
        try:
            request = build_exchange(
                cred,
                client,
                code=code,
                verifier=flow.verifier,
                redirect_uri=flow.redirect_uri,
            )
        except ValueError:
            raise _unbuildable() from None
        sent_at = self._clock()
        minted, new_refresh_token = await self._exchange(
            credential, cred, request, "authorization_code"
        )
        if new_refresh_token is None:
            raise LoginError(
                "no_refresh_token", f"the token endpoint issued no refresh token; {NO_REFRESH_HINT}"
            )
        try:
            commit = await self._tokens.commit_login(
                credential,
                refresh_token=new_refresh_token,
                minted=minted,
                sent_at=sent_at,
                rebind=flow.rebind,
            )
        except BindingChanged as exc:
            raise LoginError(
                "binding_changed", str(exc), details={"old": exc.old, "new": exc.new}
            ) from None
        except BindingError as exc:
            raise LoginError("no_route", str(exc)) from None
        except ValueError as exc:
            raise LoginError("not_oauth", str(exc)) from None
        scopes = self._flag_scopes(credential, cred, commit.granted_scopes)
        logs.event(
            "oauth_login_completed",
            credential=credential,
            slot=commit.slot,
            binding=commit.binding,
            granted=list(commit.granted_scopes),
            unexpected=list(scopes.unexpected),
            missing=list(scopes.missing),
            persisted=commit.persisted,
        )
        return {
            "slot": commit.slot,
            "binding": commit.binding,
            "granted_scopes": list(commit.granted_scopes),
            "unexpected_scopes": list(scopes.unexpected),
            "missing_scopes": list(scopes.missing),
            "access_expires_in": minted.lifetime,
            "refresh_expires_at": commit.refresh_expires_at,
            "consented_at": commit.consented_at,
            "grant_expires_at": commit.grant_expires_at,
            "persisted": commit.persisted,
            "seed_note": seed_note(cred, commit.seed_present),
        }

    def check_paste(
        self, credential: str, flow_id: str, redirect_url: str, owner: str = CLI_OWNER
    ) -> dict[str, Any]:
        """Check a pasted address against the flow without taking it (M5 design H.1), so a
        mistyped paste can be fixed before the portal asks for a passkey. A provider's error
        ends the flow: its answer is final.

        Then what completing would store: the binding the grant gets, the change from the stored
        one (refused as ``binding_changed`` unless the login was started with ``rebind``, as
        the commit would refuse it after spending the code), and the scopes asked for.

        For a flow whose callback returned a code (H.6), a paste that isn't an answer for it
        (another address, ``state`` or a duplicate parameter) is refused as for a pending flow
        and changes nothing; the same code again is ``flow_returned`` (confirm the returned
        one); any other answer fails the flow, ``flow_conflict``. A failed flow is unknown."""
        flow = self._flows.peek(flow_id, credential, owner)
        if flow is None or flow.stage == "failed":
            raise _flow_unknown()
        try:
            cred, redirect = self._parse(credential, flow, redirect_url)
        except LoginError as exc:
            if flow.stage == "returned" and exc.reason in _ANSWERS:
                raise self._conflict(credential, flow) from None
            if exc.reason == "provider_error":
                self._flows.cancel(flow_id, owner)
                self._failed(credential, exc)
            raise
        if flow.returned is not None:
            if _same_code(redirect.code, flow.returned.code):
                raise LoginError(
                    "flow_returned",
                    "the provider already sent this sign-in back to the portal; confirm it there",
                )
            raise self._conflict(credential, flow)
        return self._plan(credential, cred, flow)

    def check_returned(self, credential: str, flow_id: str, owner: str) -> dict[str, Any]:
        """What completing a flow whose callback returned a code would store, as
        :meth:`check_paste` answers it, with where and when the code came back (F.4). Any other
        flow, a pending one included, is ``flow_unknown``."""
        flow = self._flows.peek(flow_id, credential, owner)
        if flow is None or flow.returned is None:
            raise _flow_unknown()
        cred = self._refresh_credential(credential)
        return {
            **self._plan(credential, cred, flow),
            "origin": flow.callback,
            "returned_at": int(flow.returned.at),
        }

    def _plan(self, credential: str, cred: OAuth2Credential, flow: Flow) -> dict[str, Any]:
        """The facts a completion's plan shows: the flow's stage, its rebind, the binding the
        grant gets and any change from the stored one, and the scopes."""
        binding = self._binding(credential, cred)
        change = None
        existing = self._tokens.store.entry(slot_key(credential, cred))
        if existing is not None and existing.binding != binding:
            if not flow.rebind:
                raise LoginError(
                    "binding_changed",
                    "the policy binds this grant differently; start again with rebind",
                    details={"old": existing.binding, "new": binding},
                )
            change = {"old": existing.binding, "new": binding}
        return {
            "stage": flow.stage,
            "rebind": flow.rebind,
            "binding": binding,
            "binding_change": change,
            "requested_scopes": split_scope(cred.scope, cred.scope_separator),
            "expected_scopes": cred.effective_expected_scopes,
        }

    def _conflict(self, credential: str, flow: Flow) -> LoginError:
        """Two different answers for one flow: it fails, its held code dropped (H.6)."""
        self._flows.settle(flow.id, pkce.Failure("conflict"))
        exc = LoginError(
            "flow_conflict", "two different answers came back for this sign-in; connect again"
        )
        self._failed(credential, exc)
        return exc

    async def complete_returned(self, credential: str, flow_id: str, owner: str) -> dict[str, Any]:
        """Exchange the code a callback returned and store the grant, as :meth:`complete` does
        after its parse (H.6). The flow is taken first, in stage ``returned`` only; any other is
        ``flow_unknown``."""
        try:
            flow = self._flows.take(flow_id, credential, owner, stage="returned")
            if flow is None or flow.returned is None:
                raise _flow_unknown()
            cred = self._refresh_credential(credential)
            return await self._redeem(credential, cred, flow, flow.returned.code)
        except LoginError as exc:
            self._failed(credential, exc)
            raise

    def receive_callback(
        self, origin: str, credential: str, raw_query: str, binders: Sequence[CallbackBinder]
    ) -> str:
        """The callback route's one effect (H.6), after admission (C.7): find the flow the
        ``state`` and a binding cookie name, consume its ``state``, run the paste's own checks
        on the address rebuilt from its ``redirect_uri`` and the raw query, and hold the code
        (``returned``) or fail the flow (``failed``); a different second answer for a returned
        flow fails it (``conflict``). Answers which of the three. Nothing is exchanged or
        stored, and there is no ``await``, so two callbacks are ordered.

        Raises :class:`LoginError` ``duplicate_param``, or ``callback_not_taken`` for every
        other cause (no such flow, expired, failed, the CLI's, no or a wrong binding cookie,
        the address no longer this credential's callback, the same answer again), with no flow
        touched."""
        try:
            state = pkce.callback_state(raw_query)
        except RedirectError as exc:
            raise LoginError(exc.reason, str(exc)) from None
        address = callback_address(origin, credential)
        flow = self._flows.match_callback(credential, state, binders, address)
        cred = self._tokens.policy.credentials.get(credential)
        if (
            flow is None
            or not isinstance(cred, OAuth2Credential)
            or cred.grant != "refresh_token"
            # The policy now in force must still make this the credential's callback address
            # on this origin (A.5): a reload that moves either ends the callback, not the paste.
            or cred.redirect_uri != flow.redirect_uri
            or callback_origin(cred.redirect_uri, credential, self._origins()) != origin
        ):
            raise _not_taken()
        try:
            redirect: Redirect | None = pkce.parse_redirect(
                flow.redirect_uri + "?" + raw_query,
                redirect_uri=flow.redirect_uri,
                state=flow.state,
                issuer=cred.issuer,
            )
            refused = None
        except RedirectError as exc:
            redirect, refused = None, exc
        if flow.returned is not None:
            if redirect is not None and _same_code(redirect.code, flow.returned.code):
                raise _not_taken()  # the same answer again: nothing changes
            outcome = "conflict"
            self._flows.settle(flow.id, pkce.Failure("conflict"))
            logs.event(
                "oauth_callback_failed", credential=credential, reason="conflict", error=None
            )
        elif refused is not None:
            outcome = "failed"
            failure = pkce.Failure(refused.reason, refused.error, refused.description)
            self._flows.settle(flow.id, failure)
            logs.event(
                "oauth_callback_failed",
                credential=credential,
                reason=refused.reason,
                error=refused.error,
            )
        else:
            assert redirect is not None  # noqa: S101 - parse_redirect returns or raises
            outcome = "returned"
            self._flows.settle(flow.id, Returned(redirect.code, redirect.iss, self._wall()))
            logs.event("oauth_callback_returned", credential=credential)
        return outcome

    def flow_status(self, flow_id: str, owner: str) -> dict[str, Any]:
        """A flow as its owner's poll reads it (H.6): its credential, stage, when it expires,
        the origin whose callback it can take, when a code came back, and why it failed (the
        provider's cleaned, capped description included, for the owner alone). Never the code,
        ``state``, binder or verifier. Another owner's, an expired or an unknown flow is
        ``flow_unknown``."""
        flow = self._flows.owned(flow_id, owner)
        if flow is None:
            raise _flow_unknown()
        failure = flow.failure
        return {
            "credential": flow.credential,
            "stage": flow.stage,
            "expires": int(self._wall() + flow.expires_at - self._clock()),
            "origin": flow.callback,
            "returned_at": None if flow.returned is None else int(flow.returned.at),
            "failure": None
            if failure is None
            else {
                "reason": failure.reason,
                "error": failure.error,
                "description": failure.description,
            },
        }

    def cancel(self, flow_id: str, owner: str = CLI_OWNER) -> bool:
        """Drop a flow (the CLI does on Ctrl-C), in whatever stage."""
        return self._flows.cancel(flow_id, owner)

    def cancel_owner(self, owner: str) -> int:
        """Drop every flow a portal session started, when it ends (M5 design H.2)."""
        return self._flows.cancel_owner(owner)

    def _parse(
        self, credential: str, flow: Flow, redirect_url: str
    ) -> tuple[OAuth2Credential, Redirect]:
        """The credential, and the code the pasted address carries for the flow."""
        cred = self._refresh_credential(credential)
        try:
            redirect = pkce.parse_redirect(
                redirect_url, redirect_uri=flow.redirect_uri, state=flow.state, issuer=cred.issuer
            )
        except RedirectError as exc:
            details = {}
            if exc.reason == "provider_error":
                details = {"provider_error": exc.error, "description": exc.description}
            raise LoginError(exc.reason, str(exc), details=details) from None
        return cred, redirect

    # --- client_credentials --------------------------------------------------------------------

    async def _test_fetch(self, credential: str, cred: OAuth2Credential) -> dict[str, Any]:
        """Fetch one access token and drop it. Success clears the failure state."""
        binding = self._binding(credential, cred)
        client = self._client(credential, cred)
        ref = cred.client_secret or ""
        if ref.startswith("store:"):
            # The client secret is the grant's anchor: its binding bounds the access tokens.
            entry = self._tokens.store.entry(ref.removeprefix("store:"))
            binding = entry.binding if entry is not None else binding
        try:
            request = build_client_credentials(cred, client)
        except ValueError:
            raise _unbuildable() from None
        minted, _ = await self._exchange(credential, cred, request, "client_credentials")
        granted = minted.scope
        if granted is None:
            granted = tuple(split_scope(cred.scope, cred.scope_separator))
        scopes = self._flag_scopes(credential, cred, granted)
        self._tokens.reset(credential, reason="login")
        slot = slot_key(credential, cred)
        logs.event(
            "oauth_login_completed",
            credential=credential,
            slot=slot,
            binding=binding,
            granted=list(granted),
            unexpected=list(scopes.unexpected),
            missing=list(scopes.missing),
            persisted=True,
        )
        return {
            "slot": slot,
            "binding": binding,
            "granted_scopes": list(granted),
            "unexpected_scopes": list(scopes.unexpected),
            "missing_scopes": list(scopes.missing),
            "access_expires_in": minted.lifetime,
            "refresh_expires_at": None,
            "consented_at": None,
            "grant_expires_at": None,
            # Nothing to store: the client secret is already in place.
            "persisted": True,
            "seed_note": None,
        }

    # --- health --------------------------------------------------------------------------------

    def status(self) -> list[dict[str, Any]]:
        """The token manager's status, with a hint and its action, the time since the last
        success, a re-consent warning, the scopes outside the expected set, and the last failure
        and idleness health reads from ``meta`` (M5 design I). Never a value.

        ``meta`` is clear text anyone with the state file can edit: it is shown, never trusted.
        """
        policy = self._tokens.policy
        wall = self._wall()
        result = []
        for item in self._tokens.status():
            name = item["credential"]
            cred = policy.credentials.get(name)
            # The manager lists only the oauth2 credentials of this policy.
            assert isinstance(cred, OAuth2Credential)  # noqa: S101
            meta = item["meta"] or {}
            last_ok = parse_time(meta.get("last_ok"))
            result.append(
                {
                    **item,
                    "hint": hint(name, cred, item["code"], item["reason"]),
                    "action": hint_action(name, cred, item["code"], item["reason"]),
                    "last_ok_ago": None if last_ok is None else max(0, round(wall - last_ok)),
                    "reconsent_due": reconsent_due(cred, meta, wall),
                    "scopes": scope_health(cred, meta),
                    "last_failure": last_failure(item["state"], meta),
                    "idle": idle(cred, meta, wall),
                }
            )
        return result

    # --- helpers -------------------------------------------------------------------------------

    def _credential(self, name: str) -> OAuth2Credential:
        cred = self._tokens.policy.credentials.get(name)
        if not isinstance(cred, OAuth2Credential):
            raise LoginError("not_oauth", f"no oauth2 credential named {name!r}")
        return cred

    def _refresh_credential(self, name: str) -> OAuth2Credential:
        cred = self._credential(name)
        if cred.grant != "refresh_token":
            raise LoginError("not_oauth", f"{name!r} no longer uses the refresh grant")
        return cred

    def _origins(self) -> list[str]:
        """The portal origins of the policy in force, none without an ``admin`` block."""
        admin = self._tokens.policy.admin
        return [] if admin is None else admin.origins

    def _binding(self, credential: str, cred: OAuth2Credential) -> dict[str, Any]:
        """The binding the grant gets: the same one commit_login derives."""
        policy = self._tokens.policy
        try:
            if cred.grant == "client_credentials":
                return derive_oauth_binding(policy, credential)
            return derive_binding(policy, slot_key(credential, cred))
        except BindingError as exc:
            raise LoginError("no_route", str(exc)) from None

    def _client(self, credential: str, cred: OAuth2Credential) -> Client:
        client = self._tokens.client_for(credential)
        if isinstance(client, Failure):
            what = _CLIENT_REFS.get(client.reason)
            if what is None:
                raise LoginError(client.reason, "the client can't be identified")
            ref = cred.client_id if what == "client ID" else cred.client_secret
            raise LoginError(
                client.reason,
                f"the {what} isn't set or isn't bound to the token endpoint; "
                f"{set_ref_hint(ref or '', what)}",
            )
        return client

    async def _exchange(
        self, credential: str, cred: OAuth2Credential, request: TokenRequest, grant: GrantKind
    ) -> tuple[Minted, Secret | None]:
        """One token call, never replayed: a code is single use (design E.2)."""
        started = self._clock()
        try:
            response = await self._tokens.post(request, deadline=EXCHANGE_DEADLINE)
        except (httpx.HTTPError, TimeoutError, OSError):
            self._log_call(credential, cred, grant, transport_failure("no_response"), started)
            raise LoginError(
                f"exchange_failed:{OAUTH_UNAVAILABLE}",
                "no answer from the token endpoint; run login again",
            ) from None
        outcome = classify(
            response, cred=cred, grant=grant, presented=None, replayed=False, now=self._wall()
        )
        self._log_call(credential, cred, grant, outcome, started)
        if outcome.failure is not None:
            raise _exchange_failed(outcome.failure, response.status, grant)
        # An outcome has exactly one of minted and failure.
        assert outcome.minted is not None  # noqa: S101
        return outcome.minted, outcome.new_refresh_token

    def _log_call(
        self,
        credential: str,
        cred: OAuth2Credential,
        grant: GrantKind,
        outcome: Outcome,
        started: float,
    ) -> None:
        """The token call, logged as a refresh with trigger ``login`` (design H). Never a token,
        a code or an ``error_description``."""
        minted, failure = outcome.minted, outcome.failure
        trigger: Trigger = "login"
        logs.event(
            "oauth_refresh",
            credential=credential,
            slot=slot_key(credential, cred),
            grant=grant,
            trigger=trigger,
            attempt=1,
            replayed=False,
            http_status=outcome.status,
            outcome="ok" if minted is not None else (failure.kind if failure else None),
            code=failure.code if failure is not None else None,
            error=failure.error if failure is not None else None,
            error_subtype=failure.subtype if failure is not None else None,
            failure_reason=failure.reason if failure is not None else None,
            refresh_token_issued=outcome.new_refresh_token is not None,
            expires_in=minted.expires_in if minted is not None else None,
            lifetime=minted.lifetime if minted is not None else None,
            duration_ms=round((self._clock() - started) * 1000, 1),
        )

    @staticmethod
    def _flag_scopes(
        credential: str, cred: OAuth2Credential, granted: tuple[str, ...]
    ) -> ScopeCheck:
        """Scopes are flagged, never refused (design E.3, owner decision K1)."""
        check = check_login_scopes(granted, cred.effective_expected_scopes)
        if check.unexpected:
            logs.event(
                "oauth_scope_unexpected",
                credential=credential,
                scopes=list(check.unexpected),
                at="login",
            )
        if check.missing:
            logs.event(
                "oauth_scope_narrowed",
                credential=credential,
                scopes=list(check.missing),
                at="login",
            )
        return check

    @staticmethod
    def _failed(credential: str, exc: LoginError) -> None:
        logs.event("oauth_login_failed", credential=credential, reason=exc.reason)


def _flow_unknown() -> LoginError:
    return LoginError(
        "flow_unknown", "no such login is pending (it expired or was used); run login again"
    )


def _not_taken() -> LoginError:
    return LoginError("callback_not_taken", "no pending login takes this callback")


def _same_code(one: Secret, other: Secret) -> bool:
    return hmac.compare_digest(one.reveal().encode("utf-8"), other.reveal().encode("utf-8"))


def _unbuildable() -> LoginError:
    return LoginError(
        f"exchange_failed:{OAUTH_MISCONFIGURED}", "the token request can't be built from the policy"
    )


def _exchange_failed(failure: Failure, status: int, grant: GrantKind) -> LoginError:
    """``error`` is already filtered; ``error_description`` never gets this far."""
    message = f"the token endpoint refused: {failure.error or failure.reason} (HTTP {status})"
    if failure.error == "invalid_grant" and grant == "authorization_code":
        message += f"; {CODE_HINT}"
    return LoginError(
        f"exchange_failed:{failure.code}", message, details={"provider_error": failure.error}
    )


def seed_note(cred: OAuth2Credential, seed_present: bool) -> str | None:
    """What a login means for the credential's env seed, when there is one."""
    ref = cred.refresh_token or ""
    if not ref.startswith("env:") or not seed_present:
        return None
    var = ref.removeprefix("env:")
    if cred.reseed == "never":
        return f"The env seed {var} is now ignored (reseed: never). You may remove it."
    return (
        f"The env seed {var} is now ignored until its value changes (reseed: on-change). "
        "You may remove it."
    )


def hint(
    name: str, cred: OAuth2Credential, code: str | None, reason: str | None = None
) -> str | None:
    """What the operator can do about a failure code and its reason."""
    advice = _advice(name, cred, code, reason)
    return None if advice is None else advice[0]


def hint_action(
    name: str, cred: OAuth2Credential, code: str | None, reason: str | None = None
) -> Action | None:
    """:func:`hint` as an action the portal offers (M5 design H.4): its ``kind`` is
    ``connect``, ``reset``, ``set_secret`` or ``restart`` (both with the ``ref``),
    ``fix_policy`` or ``wait``. None when there is nothing to do, or nothing the vault can."""
    advice = _advice(name, cred, code, reason)
    return None if advice is None else advice[1]


def _advice(
    name: str, cred: OAuth2Credential, code: str | None, reason: str | None
) -> tuple[str, Action | None] | None:
    """The hint and its action, decided once so the two always agree."""
    if code is None:
        return None
    what = _CLIENT_REFS.get(reason or "")
    if what is not None:
        ref = (cred.client_id if what == "client ID" else cred.client_secret) or ""
        return (
            f"{set_ref_hint(ref, what)}, then run: zoeymcp oauth reset {name}",
            _ref_action(name, ref),
        )
    if reason == "no_route":
        return f"no route uses {name}; fix the policy", _action("fix_policy", name)
    reset = f"check the client ID and secret, then run: zoeymcp oauth reset {name}"
    if code in (OAUTH_RECONSENT_NEEDED, OAUTH_ROTATION_LOST, CREDENTIAL_UNAVAILABLE):
        if cred.grant == "client_credentials":
            return reset, _action("reset", name)
        if cred.authorize_url is not None:
            return f"run: zoeymcp login {name}", _action("connect", name)
        return refresh_token_hint(name, cred), _ref_action(name, cred.refresh_token or "")
    if code == OAUTH_CLIENT_REJECTED:
        return reset, _action("reset", name)
    if code == OAUTH_MISCONFIGURED:
        return f"fix the policy, then run: zoeymcp oauth reset {name}", _action("fix_policy", name)
    if code == OAUTH_UNSUPPORTED:
        return "the provider's tokens aren't Bearer tokens the vault can use", None
    if code == OAUTH_UNAVAILABLE:
        return (
            "the token endpoint is unavailable; a request after the backoff tries again",
            _action("wait", name),
        )
    return None


def _action(kind: str, name: str) -> Action:
    return {"kind": kind, "credential": name}


def _ref_action(name: str, ref: str) -> Action:
    """A secret ref given a value: an env var by a restart, a store entry by setting it."""
    kind = "restart" if ref.startswith("env:") else "set_secret"
    return {**_action(kind, name), "ref": ref}


def set_ref_hint(ref: str, what: str) -> str:
    """How to give a secret ref a value: an env var needs a restart, a store entry doesn't."""
    if ref.startswith("env:"):
        return f"set the {what} in env {ref.removeprefix('env:')} and restart the vault"
    return f"enter the {what} with zoeymcp secret set {ref.removeprefix('store:')}"


def refresh_token_hint(name: str, cred: OAuth2Credential) -> str:
    """How to give a credential without an authorize_url a new refresh token."""
    ref = cred.refresh_token or ""
    if not ref.startswith("env:"):
        return set_ref_hint(ref, "refresh token")
    var = ref.removeprefix("env:")
    if cred.reseed == "on-change":
        return f"put a new refresh token in env {var} and restart the vault (reseed: on-change)"
    return (
        f"put a new refresh token in env {var}, delete {live_slot(name)} with zoeymcp secret "
        "delete (reseed: never keeps it), and restart the vault"
    )


def reconsent_due(cred: OAuth2Credential, meta: Mapping[str, Any], wall: float) -> str | None:
    """When the grant ends, if that is less than ``GRANT_WARN_DAYS`` away."""
    candidates = []
    consented = parse_time(meta.get("consented_at"))
    if consented is not None and cred.grant_lifetime_days is not None:
        candidates.append(consented + cred.grant_lifetime_days * DAY)
    refresh_expires = parse_time(meta.get("refresh_expires_at"))
    if refresh_expires is not None:
        candidates.append(refresh_expires)
    if not candidates:
        return None
    due = min(candidates)
    if due - wall >= GRANT_WARN_DAYS * DAY:
        return None
    return _iso(due)


def scope_health(cred: OAuth2Credential, meta: Mapping[str, Any]) -> dict[str, list[str]] | None:
    """The last granted scopes compared with the expected ones, or None when unknown."""
    granted = meta.get("granted_scope")
    if not isinstance(granted, str):
        return None
    check = check_login_scopes(
        [s for s in granted.split(cred.scope_separator) if s], cred.effective_expected_scopes
    )
    return {"unexpected": list(check.unexpected), "missing": list(check.missing)}


def _iso(wall: float) -> str:
    return (
        datetime.fromtimestamp(wall, UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
