"""PKCE and the authorization request, as pure functions (RFC 7636, RFC 6749 section 4.1).

The verifier, ``state`` and flow IDs come from an injected token function, and the flow table
from an injected monotonic clock. Only ``S256`` exists: there is no ``plain`` here.

Flows live in the vault's memory only. A flow is removed when it's taken, so any failure while
completing a login needs a new login. Each flow has an owner, the CLI or one portal session (M5
design H.2): another owner's flow answers as an unknown one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final
from urllib.parse import parse_qsl, urlsplit

from ...common.policy.schema import OAuth2Credential, is_secret_ref, param_values
from ...common.textrules import find_violations
from ..request import encode_query
from ..store import Secret, canonical_origin
from .protocol import safe_error_code

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

TokenFunction = Callable[[int], str]


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
    return f"{cred.authorize_url}?{encode_query(params)}"


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


# --- flows -------------------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class Flow:
    """A pending login. The flow ID, ``state`` and verifier are never logged."""

    id: str
    credential: str
    state: Secret
    verifier: Secret
    redirect_uri: str
    expires_at: float
    rebind: bool = False
    owner: str = CLI_OWNER

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
    ) -> Flow:
        """A new flow. It replaces the credential's pending one, whoever owns that."""
        if owner != CLI_OWNER and not _SESSION_OWNER.fullmatch(owner):
            raise ValueError("a flow's owner is cli or session:<hex id>")
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

    def take(self, flow_id: str, credential: str, owner: str = CLI_OWNER) -> Flow | None:
        """Remove the flow and return it, unless it's unknown, expired, another credential's or
        another owner's. All four get the same answer; another owner's flow stays."""
        flow = self._flows.get(flow_id)
        if flow is None or flow.owner != owner:
            return None
        del self._flows[flow_id]
        return flow if self._usable(flow, credential) else None

    def peek(self, flow_id: str, credential: str, owner: str = CLI_OWNER) -> Flow | None:
        """The flow, left in place, unless ``take`` would refuse it."""
        flow = self._flows.get(flow_id)
        if flow is None or flow.owner != owner or not self._usable(flow, credential):
            return None
        return flow

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
