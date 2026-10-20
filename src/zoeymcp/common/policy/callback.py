"""The portal's OAuth callback address (M5 design A.5, D-129). Pure, so ``check``, the logins'
start and the callback route decide alike.

A credential takes the portal's callback only when its ``redirect_uri`` **is** its own callback
address on a listed portal origin: the origin, then :data:`CALLBACK_PREFIX`, then the credential's
name as the policy keys it. One address per credential means a provider's answer can only reach
the flow of the credential it was registered for, the distinct-redirect-URI mix-up defence of
RFC 9700 section 4.4.2, whether or not the provider sends ``iss``. Credential names match
``NAME_PATTERN``, so a name needs no escaping in a path.

The match is on strings: ``admin.origins`` are already in browser form (lower case, no default
port, no path), so the callback address has one spelling. Anything that only resembles it (a
trailing slash, a query, a default port written out, another credential's name) is paste only,
and ``check`` names the exact form. Every other address, the default portless
``http://127.0.0.1/callback`` included, is paste only.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

CALLBACK_PREFIX: Final = "/oauth/callback/"


def callback_address(origin: str, credential: str) -> str:
    """The credential's callback address on the portal origin ``origin``."""
    return origin + CALLBACK_PREFIX + credential


def callback_origin(redirect_uri: str, credential: str, origins: Iterable[str]) -> str | None:
    """The listed origin on which ``redirect_uri`` is this credential's callback address, else
    None (paste only)."""
    for origin in origins:
        if redirect_uri == callback_address(origin, credential):
            return origin
    return None
