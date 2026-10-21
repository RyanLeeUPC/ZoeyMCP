"""PKCE and the authorization request, as pure functions (RFC 7636, RFC 6749 section 4.1).

The verifier, ``state`` and flow IDs come from an injected token function, and the flow table
from an injected monotonic clock. Only ``S256`` exists: there is no ``plain`` here.

Flows live in the vault's memory only. A flow is removed when it's taken, so any failure while
completing a login needs a new login. Each flow has an owner, the CLI or one portal session (M5
design H.2): another owner's flow answers as an unknown one.

A flow a portal session started for a credential whose ``redirect_uri`` is its portal callback
address can also take the provider's redirect at the callback route (H.6). Such a flow has a
``callback`` origin and the SHA-256 of its binder, the binding cookie the start set in that
browser. Its ``stage`` is ``pending`` until a callback consumes its ``state``; then it is
``returned``, holding the code until its owner confirms, or ``failed``, with the reason kept for
its owner. A held code is never replaced: a different second answer fails the flow
(``conflict``). :func:`callback_state`, :meth:`FlowTable.match_callback` and
:meth:`FlowTable.settle` are the callback's part.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Final, Literal
from urllib.parse import parse_qsl, urlsplit

from ...common.logs import refuse_type
from ...common.policy.schema import OAuth2Credential, is_secret_ref, param_values
from ...common.textrules import find_violations
from ..store import Secret, canonical_origin
from .protocol import safe_error_code, with_query

FLOW_TTL: Final = 600.0
MAX_FLOWS: Final = 8
MAX_REDIRECT_QUERY: Final = 4096
MAX_DESCRIPTION: Final = 200
# token_urlsafe(32) gives 43 characters: the shortest verifier RFC 7636 allows.
SECRET_BYTES: Final = 32
FLOW_ID_BYTES: Final = 16

# The owner of a flow the admin socket starts; a portal session's flows are "session:<hex id>".
CLI_OWNER: Final = "cli"

_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_SESSION_OWNER = re.compile(r"session:[0-9a-f]+")
_CODE = re.compile(r"[\x21-\x7E]{1,2048}")
# Parameters that must appear at most once in the redirect.
_SINGLE = ("code", "state", "error", "iss")
# Parameters that mean the response was put in the fragment.
_FRAGMENT_RESPONSE = frozenset({"code", "state", "error", "iss", "access_token", "id_token"})
# A state a callback can carry: URL-safe ASCII only, so a compare never meets other text (the
# vault's own are 43 characters).
_STATE = re.compile(r"[A-Za-z0-9_-]{1,128}")

TokenFunction = Callable[[int], str]
Stage = Literal["pending", "returned", "failed"]


def new_verifier(token: TokenFunction = secrets.token_urlsafe) -> Secret:
    verifier = token(SECRET_BYTES)
    if not _VERIFIER.fullmatch(verifier):
        raise ValueError("a PKCE verifier is 43 to 128 unreserved characters")
    return Secret(verifier)


def code_challenge(verifier: str) -> str:
    """The S256 challenge: base64url without padding of the verifier's SHA-256."""
    if not _VERIFIER.fullmatch(verifier):
        raise ValueError("a PKCE verifier is 43 to 128 unreserved characters")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authorize_url(cred: OAuth2Credential, *, state: Secret, challenge: str) -> str:
    """The URL the operator opens to approve. It never holds a secret: ``check`` refuses a
    ``client_id`` ref when ``authorize_url`` is set, and this refuses one again."""
    if cred.authorize_url is None:
        raise ValueError("this credential has no authorize_url")
    if is_secret_ref(cred.client_id):
        raise ValueError("a client_id ref can't go in an authorization URL")
    params = [
        ("response_type", "code"),
        ("client_id", cred.client_id),
        ("redirect_uri", cred.redirect_uri),
        ("state", state.reveal()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
    if cred.scope is not None:
        params.append(("scope", cred.scope))
    names = {name for name, _ in params}
    for name, value in cred.authorize_params.items():
        if name in names:
            raise ValueError(f"authorize_params can't set {name!r}; the vault sets it")
        params.extend((name, one) for one in param_values(value))
    return with_query(cred.authorize_url, params)


# --- the redirect ------------------------------------------------------------------------------


class RedirectError(ValueError):
    """The pasted redirect can't complete the login. ``reason`` is a stable code.

    For ``provider_error``, ``error`` is the filtered code and ``description`` the provider's
    text, cleaned and capped. The description goes back to the CLI only and is never logged, so
    the message leaves it out.
    """

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        error: str | None = None,
        description: str | None = None,
    ) -> None:
        self.reason = reason
        self.error = error
        self.description = description
        super().__init__(message)


@dataclass(frozen=True)
class Redirect:
    code: Secret
    iss: str | None


def parse_redirect(
    pasted: str, *, redirect_uri: str, state: Secret, issuer: str | None
) -> Redirect:
    """Check the address the browser was sent to and take the code from it."""
    text = pasted.strip()
    try:
        # A lone surrogate (from JSON, or undecodable stdin) can't be compared or answered.
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise RedirectError("redirect_mismatch", "the address can't be read") from None
    expected = urlsplit(redirect_uri)
    try:
        parts = urlsplit(text)
        # A browser shows an empty path as "/".
        matches = canonical_origin(text) == canonical_origin(redirect_uri) and (
            parts.path or "/"
        ) == (expected.path or "/")
    except ValueError:
        matches = False
    if not matches:
        raise RedirectError(
            "redirect_mismatch", f"that isn't an address under {redirect_uri}; paste the full URL"
        )
    if len(parts.query) > MAX_REDIRECT_QUERY:
        raise RedirectError("redirect_mismatch", "the address's query is too long")
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True, errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise RedirectError("redirect_mismatch", "the address's query can't be read") from None
    for name in _SINGLE:
        if sum(1 for key, _ in pairs if key == name) > 1:
            raise RedirectError("duplicate_param", f"the address has more than one {name!r}")
    fragment = {key for key, _ in parse_qsl(parts.fragment, keep_blank_values=True)}
    if fragment & _FRAGMENT_RESPONSE:
        raise RedirectError(
            "redirect_mismatch", "the response is in the address's fragment; expected the query"
        )
    values = dict(pairs)
    got_state = values.get("state")
    if got_state is None or not hmac.compare_digest(
        got_state.encode("utf-8"), state.reveal().encode("utf-8")
    ):
        raise RedirectError("state_mismatch", "the address is for a different login")
    if "error" in values:
        error = safe_error_code(values["error"])
        raise RedirectError(
            "provider_error",
            f"the provider refused the authorization: {error}",
            error=error,
            description=_description(values.get("error_description")),
        )
    iss = values.get("iss")
    if issuer is not None and iss is not None and iss != issuer:
        raise RedirectError("iss_mismatch", "the response came from a different issuer")
    code = values.get("code")
    if code is None or not _CODE.fullmatch(code):
        raise RedirectError("no_code", "the address has no usable authorization code")
    return Redirect(Secret(code), iss)


def _description(value: str | None) -> str | None:
    """The provider's ``error_description``, capped, or None when it breaks the text rules."""
    if value is None:
        return None
    text = value[:MAX_DESCRIPTION]
    if find_violations(text, max_chars=MAX_DESCRIPTION, single_line=True):
        return None
    return text


# --- the callback (M5 design H.6) --------------------------------------------------------------


class CallbackBinder:
    """A callback flow's binding cookie (C.7): 32 random bytes the start sets in the browser that
    started the flow, of which the flow keeps only the SHA-256. Its ``repr`` hides it; logging it
    raises."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    @classmethod
    def new(cls, token: TokenFunction = secrets.token_urlsafe) -> CallbackBinder:
        return cls(token(SECRET_BYTES))

    def reveal(self) -> str:
        return self._value

    def sha256(self) -> bytes:
        return hashlib.sha256(self._value.encode("utf-8")).digest()

    def __repr__(self) -> str:
        return "CallbackBinder(<hidden>)"

    __str__ = __repr__


refuse_type(CallbackBinder)


@dataclass(frozen=True, repr=False)
class Returned:
    """The code a callback brought back, held for the flow's owner to confirm; ``at`` is the wall
    time it arrived."""

    code: Secret
    iss: str | None
    at: float


@dataclass(frozen=True)
class Failure:
    """Why a callback flow failed: a :class:`RedirectError` reason, or ``conflict`` (two
    different answers). ``error`` is the provider's filtered code and ``description`` its
    cleaned, capped text, kept for the owner and never logged."""

    reason: str
    error: str | None = None
    description: str | None = field(default=None, repr=False)


def callback_state(raw_query: str) -> Secret:
    """The ``state`` a callback's query carries, before any flow is looked at (H.6 step 1): a
    second ``code``, ``state``, ``error`` or ``iss`` is ``duplicate_param``; anything but exactly
    one ``state`` of 1 to 128 URL-safe ASCII characters is ``callback_not_taken``, so a decoded
    ``%C3%A9`` never reaches a compare."""
    try:
        pairs = parse_qsl(raw_query, keep_blank_values=True, errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise _not_taken() from None
    for name in _SINGLE:
        if sum(1 for key, _ in pairs if key == name) > 1:
            raise RedirectError("duplicate_param", f"the address has more than one {name!r}")
    states = [value for key, value in pairs if key == "state"]
    if len(states) != 1 or not _STATE.fullmatch(states[0]):
        raise _not_taken()
    return Secret(states[0])


def _not_taken() -> RedirectError:
    return RedirectError("callback_not_taken", "no pending login takes this callback")


# --- flows -------------------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class Flow:
    """A login. The flow ID, ``state``, verifier, binder hash and any returned code are never
    logged. ``callback`` is the portal origin whose callback this flow can take, or None."""

    id: str
    credential: str
    state: Secret
    verifier: Secret
    redirect_uri: str
    expires_at: float
    rebind: bool = False
    owner: str = CLI_OWNER
    callback: str | None = None
    binder_hash: bytes | None = None
    stage: Stage = "pending"
    returned: Returned | None = None
    failure: Failure | None = None

    @property
    def challenge(self) -> str:
        return code_challenge(self.verifier.reveal())

    def __repr__(self) -> str:
        return f"Flow(credential={self.credential!r})"


def surface(owner: str) -> str:
    """Where a flow's owner works: ``cli`` or ``portal``."""
    return "cli" if owner == CLI_OWNER else "portal"


class TooManyFlows(Exception):
    reason = "too_many_flows"


class FlowTable:
    """Pending logins: one per credential, ``MAX_FLOWS`` in all, each for ``FLOW_TTL`` seconds."""

    def __init__(
        self, clock: Callable[[], float], *, token: TokenFunction = secrets.token_urlsafe
    ) -> None:
        self._clock = clock
        self._token = token
        self._flows: dict[str, Flow] = {}

    def __len__(self) -> int:
        self._purge(self._clock())
        return len(self._flows)

    def start(
        self,
        credential: str,
        redirect_uri: str,
        *,
        rebind: bool = False,
        owner: str = CLI_OWNER,
        callback: str | None = None,
        binder_hash: bytes | None = None,
    ) -> Flow:
        """A new flow. It replaces the credential's flow, in whatever stage and whoever owns it.
        A flow that can take the callback has both ``callback`` and ``binder_hash``, and a
        portal session for its owner."""
        if owner != CLI_OWNER and not _SESSION_OWNER.fullmatch(owner):
            raise ValueError("a flow's owner is cli or session:<hex id>")
        if (callback is None) != (binder_hash is None) or (
            callback is not None and owner == CLI_OWNER
        ):
            raise ValueError("a callback flow has an origin and a binder, and a portal owner")
        now = self._clock()
        self._purge(now)
        for flow_id, flow in list(self._flows.items()):
            if flow.credential == credential:
                del self._flows[flow_id]
        if len(self._flows) >= MAX_FLOWS:
            raise TooManyFlows(f"at most {MAX_FLOWS} logins can be pending")
        flow = Flow(
            id=self._token(FLOW_ID_BYTES),
            credential=credential,
            state=Secret(self._token(SECRET_BYTES)),
            verifier=new_verifier(self._token),
            redirect_uri=redirect_uri,
            expires_at=now + FLOW_TTL,
            rebind=rebind,
            owner=owner,
            callback=callback,
            binder_hash=binder_hash,
        )
        self._flows[flow.id] = flow
        return flow

    def owner_of(self, credential: str) -> str | None:
        """The owner of the credential's pending flow, the one a start would replace."""
        self._purge(self._clock())
        for flow in self._flows.values():
            if flow.credential == credential:
                return flow.owner
        return None

    def take(
        self, flow_id: str, credential: str, owner: str = CLI_OWNER, stage: Stage = "pending"
    ) -> Flow | None:
        """Remove the flow and return it, unless it's unknown, expired, another credential's or
        another owner's. All four get the same answer; another owner's flow stays. A flow in
        another ``stage`` than the caller needs answers None too and stays: a paste never takes a
        code a callback returned, nor the returned confirm a flow still pending."""
        flow = self._flows.get(flow_id)
        if flow is None or flow.owner != owner or flow.stage != stage:
            return None
        del self._flows[flow_id]
        return flow if self._usable(flow, credential) else None

    def peek(self, flow_id: str, credential: str, owner: str = CLI_OWNER) -> Flow | None:
        """The flow in whatever stage, left in place, unless it's unknown, expired, another
        credential's or another owner's."""
        flow = self._flows.get(flow_id)
        if flow is None or flow.owner != owner or not self._usable(flow, credential):
            return None
        return flow

    def owned(self, flow_id: str, owner: str) -> Flow | None:
        """The flow in whatever stage, for its owner only, unless it expired: what its owner's
        poll reads (H.6)."""
        flow = self._flows.get(flow_id)
        if flow is None or flow.owner != owner or self._clock() >= flow.expires_at:
            return None
        return flow

    def match_callback(
        self, credential: str, state: Secret, binders: Sequence[CallbackBinder], address: str
    ) -> Flow | None:
        """The flow a callback at ``address`` with ``state`` and these binding-cookie values is
        for (H.6 step 2): the credential's one flow, unexpired, able to take the callback,
        pending or returned, with exactly that ``redirect_uri``, its ``state`` equal, and one of
        the binders hashing to its binder hash. The ``state`` is compared in constant time on
        UTF-8 bytes, and every binder is compared, with no early exit. None for every cause."""
        flow = next((f for f in self._flows.values() if f.credential == credential), None)
        if (
            flow is None
            or self._clock() >= flow.expires_at
            or flow.callback is None
            or flow.binder_hash is None
            or flow.stage == "failed"
            or flow.redirect_uri != address
        ):
            return None
        same_state = hmac.compare_digest(
            state.reveal().encode("utf-8"), flow.state.reveal().encode("utf-8")
        )
        bound = False
        for binder in binders:
            bound = hmac.compare_digest(binder.sha256(), flow.binder_hash) or bound
        return flow if same_state and bound else None

    def settle(self, flow_id: str, outcome: Returned | Failure) -> Flow | None:
        """The flow moved on by its callback, or by a paste that conflicts with a held code:
        ``returned`` with the code, or ``failed`` with why, any held code dropped. Its
        ``expires_at`` stays, so a returned code lives no longer than the flow would have."""
        flow = self._flows.get(flow_id)
        if flow is None:
            return None
        if isinstance(outcome, Returned):
            settled = replace(flow, stage="returned", returned=outcome, failure=None)
        else:
            settled = replace(flow, stage="failed", returned=None, failure=outcome)
        self._flows[flow_id] = settled
        return settled

    def cancel(self, flow_id: str, owner: str = CLI_OWNER) -> bool:
        """Drop the flow. Another owner's flow stays, and answers as an unknown one."""
        flow = self._flows.get(flow_id)
        if flow is None or flow.owner != owner:
            return False
        del self._flows[flow_id]
        return True

    def cancel_owner(self, owner: str) -> int:
        """Drop every flow ``owner`` has: its portal session ended (H.2). How many went."""
        owned = [flow_id for flow_id, flow in self._flows.items() if flow.owner == owner]
        for flow_id in owned:
            del self._flows[flow_id]
        return len(owned)

    def _usable(self, flow: Flow, credential: str) -> bool:
        return self._clock() < flow.expires_at and flow.credential == credential

    def _purge(self, now: float) -> None:
        for flow_id, flow in list(self._flows.items()):
            if now >= flow.expires_at:
                del self._flows[flow_id]
