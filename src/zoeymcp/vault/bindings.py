"""Deriving a secret's binding from the policy when it's written (design §4.5).

A binding says what a stored secret may be used for. It's derived from how the policy uses the
secret at the moment it is written, so a later policy change that sends it somewhere new can't
use it until it's entered again.

OAuth secrets (a client ID ref, a client secret, a refresh token) get their own shape, with no
``origins`` key, so they can never be injected as a static secret:

    {"oauth": {"token": "https://accounts.example:443",
               "resources": ["https://api.example:443"]}}

``token`` is the only origin the secret itself may go to. ``resources`` are the origins the access
tokens minted with it may go to.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Final

from ..common.policy.schema import (
    BasicCredential,
    HeaderCredential,
    OAuth2Credential,
    PathCredential,
    Policy,
    QueryCredential,
)
from .store import canonical_origin, origin_binding, smtp_binding

# Store entries whose names start with this are managed by the vault, never set by hand.
VAULT_PREFIX: Final = "oauth."


class BindingError(ValueError):
    """The policy doesn't say how a secret is used, or says two incompatible things."""


def live_slot(credential: str) -> str:
    """The entry holding the live refresh token of a credential seeded from ``env:``."""
    return f"{VAULT_PREFIX}{credential}.live"


def oauth_binding(token_url: str, resources: Iterable[str]) -> dict[str, Any]:
    """The binding for an OAuth secret: its token endpoint and its access tokens' origins."""
    origins = sorted({canonical_origin(r) for r in resources})
    if not origins:
        raise ValueError("an OAuth binding needs at least one resource origin")
    return {"oauth": {"token": canonical_origin(token_url), "resources": origins}}


def oauth_secret_names(policy: Policy) -> set[str]:
    """Every store entry the policy uses as an OAuth secret, live slots included."""
    names: set[str] = set()
    for cred_name, cred in policy.credentials.items():
        if not isinstance(cred, OAuth2Credential):
            continue
        for ref in (cred.client_id, cred.client_secret, cred.refresh_token):
            if ref is not None and ref.startswith("store:"):
                names.add(ref.removeprefix("store:"))
        if _is_seeded(cred):
            names.add(live_slot(cred_name))
    return names


def derive_oauth_binding(policy: Policy, credential: str) -> dict[str, Any]:
    """The binding of an oauth2 credential's grant: its token endpoint and its routes."""
    cred = policy.credentials.get(credential)
    if not isinstance(cred, OAuth2Credential):
        raise BindingError(f"{credential!r} is not an oauth2 credential")
    resources = _route_origins(policy, credential)
    if not resources:
        raise BindingError(
            f"no route uses credential {credential!r}; there is nothing to bind its access "
            "tokens to"
        )
    return oauth_binding(cred.token_url, resources)


def derive_binding(policy: Policy, name: str) -> dict[str, Any]:
    if name.startswith(VAULT_PREFIX):
        return derive_oauth_binding(policy, _live_slot_owner(policy, name))
    ref = f"store:{name}"
    origins: set[str] = set()
    smtp: list[dict[str, Any]] = []
    oauth: dict[str, OAuth2Credential] = {}
    # Set by any static use, routed or not: an OAuth secret may have none at all.
    static = False

    for cred_name, cred in policy.credentials.items():
        if isinstance(cred, OAuth2Credential):
            if ref in (cred.client_id, cred.client_secret, cred.refresh_token):
                oauth[cred_name] = cred
        elif isinstance(cred, HeaderCredential | QueryCredential | PathCredential):
            if cred.secret == ref:
                static = True
                origins.update(_route_origins(policy, cred_name))
        elif isinstance(cred, BasicCredential) and ref in (cred.secret, cred.username):
            static = True
            origins.update(_route_origins(policy, cred_name))

    for connector in policy.connectors.values():
        if ref in (connector.password, connector.username):
            smtp.append(smtp_binding(connector.host, connector.port, connector.from_, connector.to))

    if oauth:
        if smtp or static:
            raise BindingError(
                f"{name!r} is an OAuth secret of {', '.join(oauth)} and is also used by another "
                "credential or a connector; an OAuth secret must never be injectable as a "
                "static secret"
            )
        return _shared_oauth_binding(policy, name, oauth)
    if smtp and origins:
        raise BindingError(f"{name!r} is used both by a connector and by HTTP credentials")
    if smtp:
        if any(b != smtp[0] for b in smtp):
            raise BindingError(f"{name!r} is used by connectors with different constraints")
        return smtp[0]
    if origins:
        return origin_binding(sorted(origins))
    raise BindingError(
        f"the policy doesn't use store:{name} on any route or connector; "
        "pass --origin to bind it explicitly"
    )


def _shared_oauth_binding(
    policy: Policy, name: str, oauth: dict[str, OAuth2Credential]
) -> dict[str, Any]:
    """One binding for every oauth2 credential that uses ``name``: one token origin, all routes."""
    tokens = {canonical_origin(cred.token_url) for cred in oauth.values()}
    if len(tokens) > 1:
        raise BindingError(
            f"{name!r} would be sent to the token endpoints {', '.join(sorted(tokens))}; "
            "an OAuth secret is bound to one"
        )
    resources: set[str] = set()
    for cred_name in oauth:
        resources.update(_route_origins(policy, cred_name))
    if not resources:
        raise BindingError(
            f"no route uses {', '.join(oauth)}; there is nothing to bind the access tokens "
            f"minted with {name!r} to"
        )
    return oauth_binding(next(iter(oauth.values())).token_url, resources)


def _live_slot_owner(policy: Policy, name: str) -> str:
    for cred_name, cred in policy.credentials.items():
        if isinstance(cred, OAuth2Credential) and _is_seeded(cred) and live_slot(cred_name) == name:
            return cred_name
    raise BindingError(
        f"{name!r} is managed by the vault, and no credential keeps its live refresh token there"
    )


def _is_seeded(cred: OAuth2Credential) -> bool:
    return cred.refresh_token is not None and cred.refresh_token.startswith("env:")


def _route_origins(policy: Policy, credential: str) -> set[str]:
    return {
        canonical_origin(r.upstream)
        for r in policy.routes
        if r.credential == credential and r.upstream is not None
    }
