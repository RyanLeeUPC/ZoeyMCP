"""Deriving a secret's binding from the policy when it's written (design §4.5).

A binding says what a stored secret may be used for. It's derived from how the policy uses the
secret at the moment it is written, so a later policy change that sends it somewhere new can't
use it until it's entered again.
"""

from __future__ import annotations

from typing import Any

from ..common.policy.schema import (
    BasicCredential,
    HeaderCredential,
    OAuth2Credential,
    PathCredential,
    Policy,
    QueryCredential,
)
from .store import canonical_origin, origin_binding, smtp_binding


class BindingError(ValueError):
    """The policy doesn't say how a secret is used, or says two incompatible things."""


def derive_binding(policy: Policy, name: str) -> dict[str, Any]:
    ref = f"store:{name}"
    origins: set[str] = set()
    smtp: list[dict[str, Any]] = []

    for cred_name, cred in policy.credentials.items():
        routes = [r for r in policy.routes if r.credential == cred_name and r.upstream]
        route_origins = {canonical_origin(r.upstream) for r in routes if r.upstream}
        if isinstance(cred, OAuth2Credential):
            # Client secrets and refresh tokens only ever go to the token endpoint.
            if ref in (cred.client_id, cred.client_secret, cred.refresh_token):
                origins.add(canonical_origin(cred.token_url))
        elif isinstance(cred, HeaderCredential | QueryCredential | PathCredential):
            if cred.secret == ref:
                origins.update(route_origins)
        elif isinstance(cred, BasicCredential) and ref in (cred.secret, cred.username):
            origins.update(route_origins)

    for connector in policy.connectors.values():
        if ref in (connector.password, connector.username):
            smtp.append(smtp_binding(connector.host, connector.port, connector.from_, connector.to))

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
