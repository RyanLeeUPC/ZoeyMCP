"""Dynamic client registration's decisions, as pure functions (M7 design D.4, D.6's backstop, X7).

Phase 1 of onboarding (``vault/onboard.py``) sends the one registration request when the
operator gave no client ID and the authorization server publishes a ``registration_endpoint``;
what it sends and what its answer means are decided here:

- :func:`redirect_for`: the redirect address a credential registers (D.4). The operator's own
  wins; a given client uses the shared ``http://127.0.0.1/callback``; a registration the vault
  makes uses the credential's own address, the paste one or a listed portal origin's callback,
  so an answer meant for another credential's sign-in is refused by its address (D.6's
  backstop).
- :func:`application_type`: ``native`` when the redirect's host is a loopback address or
  ``localhost``, whatever the scheme (SPEC-6), else ``web``.
- :func:`request_auth` and :func:`registration_request`: a public client when the authorization
  server allows one, else a secret by basic, else by post; and the request's exact members,
  public metadata only (RFC 7591 6, D-19).
- :func:`check_registration`: the answer checked, not trusted (X7). Its :class:`Registration`
  holds the client ID, how it authenticates, its secret and the secret's expiry, and nothing
  else: ``registration_access_token`` and ``registration_client_uri`` are never read out of
  the answer (D-148, D-155).

Nothing here does I/O or reads a clock. A refusal is a :class:`Refusal` value, never an
exception: its ``reason`` is M.2's, and the portal's catalogue (``portal/refusals.py``) words it.
Every pattern is used with ``fullmatch``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeGuard, cast
from urllib.parse import urlsplit

from ...common.logs import refuse_type
from ...common.policy.callback import callback_address
from ...common.policy.schema import ClientAuth, OAuth2Credential
from ...common.textrules import reveal_hidden
from ..store import Secret
from .discovery import Plan
from .protocol import safe_error_code

Reason = Literal[
    "dcr_refused",
    "dcr_failed",
    "dcr_redirect_changed",
    "dcr_auth_unsupported",
    "dcr_bad_client_id",
    "dcr_bad_secret",
    "dcr_grant_missing",
    "dcr_answer_invalid",
]
# RFC 7591's names for the client authentication the vault speaks, in the order it asks for one
# (D.4): a public client first (Q24), the preferred case, since nothing is stored.
AuthMethod = Literal["none", "client_secret_basic", "client_secret_post"]
METHODS: Final[Mapping[AuthMethod, ClientAuth]] = {
    "none": "none",
    "client_secret_basic": "basic",
    "client_secret_post": "post",
}
GRANT_TYPES: Final = ("authorization_code", "refresh_token")
RESPONSE_TYPES: Final = ("code",)
# The address an operator-registered client uses (D-15), and the paste address of a credential
# the vault registers: its own path segment (schema.py's redirect rule takes a path).
SHARED_REDIRECT: Final = str(OAuth2Credential.model_fields["redirect_uri"].default)
PASTE_REDIRECT: Final = "http://127.0.0.1/callback/"
CLIENT_ID_MAX: Final = 255
CLIENT_SECRET_MAX: Final = 512
CLIENT_NAME_MAX: Final = 64
DESCRIPTION_MAX: Final = 200

# X7: a client ID a policy can hold, inline included: printable ASCII without a space, a quote, a
# backslash or a $ (compose would interpolate it, TI-1).
_CLIENT_ID = re.compile(rf"[\x21\x23\x25-\x5b\x5d-\x7e]{{1,{CLIENT_ID_MAX}}}")
# What makes a policy value a reference to a secret (schema.SECRET_REF_PATTERN's prefixes).
SECRET_PREFIXES: Final = ("store:", "env:")
# A client secret the store takes on one line, sent only as the authentication.
_CLIENT_SECRET = re.compile(rf"[\x20-\x7e]{{1,{CLIENT_SECRET_MAX}}}")

NOTES: Final[Mapping[str, str]] = {
    "grant_types_absent": "The authorization server didn't say which grants it registered, so "
    "the RFC's default, the authorization code alone, is assumed; sign-in refuses an answer with "
    "no refresh token.",
}


@dataclass(frozen=True)
class Refusal:
    """Why a registration isn't used. ``reason`` is M.2's; ``field`` names the answer's member it
    is about; ``values`` are what the refusal shows: a ``dcr_refused``'s filtered error code and
    its cleaned description, a ``dcr_failed``'s status."""

    reason: Reason
    field: str = ""
    values: tuple[str, ...] = ()


@dataclass(frozen=True, repr=False)
class Registration:
    """A checked registration (D.4): the client ID, how it authenticates at the token endpoint
    (the policy's ``client_auth``), its secret when it has one, and the secret's
    ``client_secret_expires_at`` (0 for never; None when the answer gave none). Its ``repr``
    hides the secret, and logging it raises (M.5)."""

    client_id: str
    auth: ClientAuth
    client_secret: Secret | None
    expires_at: int | None

    def __repr__(self) -> str:
        return f"Registration(client_id={self.client_id!r}, auth={self.auth!r})"


# It holds the client secret, which is never logged (M.4, M.5).
refuse_type(Registration)


@dataclass(frozen=True)
class Choices:
    """What a registration asks for beyond the plan: the server's name (the default client name
    says it), the operator's client name, the redirect address and the authentication."""

    server: str
    redirect_uri: str
    auth_method: AuthMethod
    client_name: str | None = None


def redirect_for(credential: str, origin: str | None, override: str | None, *, given: bool) -> str:
    """The redirect address ``credential`` registers or uses (D.4, DD-16): the operator's
    ``override``; else, for a ``given`` client, the shared one operator-registered clients use;
    else, for a registration with no portal ``origin``, the credential's own paste address;
    else that portal origin's callback for it."""
    if override is not None:
        return override
    if given:
        return SHARED_REDIRECT
    if origin is None:
        return PASTE_REDIRECT + credential
    return callback_address(origin, credential)


def application_type(redirect_uri: str) -> str:
    """Where the client runs, by the redirect's host whatever the scheme (D.4, SPEC-6):
    ``native`` for a loopback address or ``localhost``, else ``web`` (OIDC Registration forbids
    ``localhost`` for a web client)."""
    host = urlsplit(redirect_uri).hostname or ""
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    return "native" if loopback else "web"


def request_auth(supported: Sequence[str]) -> AuthMethod | Refusal:
    """The authentication a registration asks for: ``none`` when the authorization server lists
    it, else ``client_secret_basic``, else ``client_secret_post`` (D.4)."""
    for method in METHODS:
        if method in supported:
            return method
    return Refusal("dcr_auth_unsupported", field="token_endpoint_auth_methods_supported")


def client_name(server: str, given: str | None) -> str:
    """The name the provider may show for the client: the operator's, else ``ZoeyMCP
    (<server>)``."""
    return given or f"ZoeyMCP ({server})"


def registration_request(plan: Plan, choices: Choices) -> dict[str, Any]:
    """The registration's JSON object, with exactly D.4's members: public metadata, and the
    plan's scopes when it has any. No contact, logo, URI, key, statement or DPoP member is
    sent, and no initial access token (D-179)."""
    request: dict[str, Any] = {
        "client_name": client_name(choices.server, choices.client_name),
        "redirect_uris": [choices.redirect_uri],
        "grant_types": list(GRANT_TYPES),
        "response_types": list(RESPONSE_TYPES),
        "token_endpoint_auth_method": choices.auth_method,
        "application_type": application_type(choices.redirect_uri),
    }
    if plan.scopes.scopes:
        request["scope"] = " ".join(plan.scopes.scopes)
    return request


def request_body(request: Mapping[str, Any]) -> bytes:
    """The request as it is sent: compact ASCII JSON."""
    return json.dumps(request, separators=(",", ":")).encode("ascii")


def literal_client_id(value: object) -> TypeGuard[str]:
    """Whether a client ID from the network can go into fragment 1 as itself (X7): its class,
    and no ``store:`` or ``env:`` prefix, which a policy reads as a reference to a secret the
    vault would then send as the client ID."""
    return (
        isinstance(value, str)
        and _CLIENT_ID.fullmatch(value) is not None
        and not value.startswith(SECRET_PREFIXES)
    )


def description(value: object) -> str | None:
    """A refusal's ``error_description``, for the operator alone (never logged): hidden
    characters made visible, on one line, and capped (M2 I7's treatment)."""
    if not isinstance(value, str):
        return None
    text = " ".join(reveal_hidden(value).split())
    return text[:DESCRIPTION_MAX] or None


def check_registration(
    status: int, answer: Mapping[str, Any] | None, request: Mapping[str, Any]
) -> Registration | Refusal:
    """The registration answer, checked in D.4's order against the ``request`` sent (X7). A 400
    is the server's refusal, with its error code filtered and its description cleaned; any other
    status but 200 and 201, or no JSON object, is ``dcr_failed`` with the status alone."""
    if status == 400:
        found = answer or {}
        code = safe_error_code(found.get("error")) or "no error code"
        said = description(found.get("error_description"))
        return Refusal("dcr_refused", values=(code,) if said is None else (code, said))
    if status not in (200, 201) or answer is None:
        return Refusal("dcr_failed", values=(str(status),))
    client_id = answer.get("client_id")
    if not literal_client_id(client_id):
        return Refusal("dcr_bad_client_id", field="client_id")
    if "redirect_uris" in answer and answer["redirect_uris"] != request["redirect_uris"]:
        return Refusal("dcr_redirect_changed", field="redirect_uris")
    method = answer.get("token_endpoint_auth_method", request["token_endpoint_auth_method"])
    # A list or an object isn't hashable, so the type is checked before the lookup.
    if not isinstance(method, str) or method not in METHODS:
        return Refusal("dcr_auth_unsupported", field="token_endpoint_auth_method")
    auth = METHODS[cast(AuthMethod, method)]
    secret = answer.get("client_secret")
    if (secret is not None) != (auth != "none"):
        return Refusal("dcr_bad_secret", field="client_secret")
    if secret is not None and not (isinstance(secret, str) and _CLIENT_SECRET.fullmatch(secret)):
        return Refusal("dcr_bad_secret", field="client_secret")
    if "grant_types" in answer:
        grants = answer["grant_types"]
        if not isinstance(grants, list) or not all(isinstance(g, str) for g in grants):
            return Refusal("dcr_answer_invalid", field="grant_types")
        if not set(GRANT_TYPES) <= set(grants):
            return Refusal("dcr_grant_missing", field="grant_types")
    expires = answer.get("client_secret_expires_at")
    if expires is not None and (
        isinstance(expires, bool) or not isinstance(expires, int) or expires < 0
    ):
        return Refusal("dcr_answer_invalid", field="client_secret_expires_at")
    return Registration(client_id, auth, None if secret is None else Secret(secret), expires)


def notes(answer: Mapping[str, Any]) -> tuple[str, ...]:
    """What a used registration's answer leaves to note: ``grant_types`` absent, so the RFC's
    default, which login's ``no_refresh_token`` refusal then decides on (MISS-9)."""
    return () if "grant_types" in answer else ("grant_types_absent",)
