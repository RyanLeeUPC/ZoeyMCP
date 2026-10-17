"""Optional live smoke tests against the real Google and Spotify (design J.8, K3).

Skipped unless their environment variables are set; CI never sets them. Use your own client
registrations. Nothing here prints, logs or keeps a token: the store lives in a temporary
directory, and the assertions only look at status codes and error names.

- ``ZOEYMCP_LIVE_GOOGLE_CLIENT_ID`` (a Desktop client): Google accepts the authorization request
  with the default redirect URI ``http://127.0.0.1/callback``, which has no port (K3).
- ``ZOEYMCP_LIVE_GOOGLE_CLIENT_SECRET`` and ``ZOEYMCP_LIVE_GOOGLE_REFRESH_TOKEN`` as well: a
  refresh through the vault, then the calendar list. Google doesn't rotate refresh tokens, so
  the one given stays valid.
- ``ZOEYMCP_LIVE_SPOTIFY_CLIENT_ID``: Spotify accepts the authorization request with the same
  redirect URI, registered without a port. No refresh: Spotify rotates refresh tokens, and the
  successor would be left behind in the temporary store.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.oauth.pkce import authorize_url, code_challenge, new_verifier
from zoeymcp.vault.store import Secret, SecretStore

from .conftest import BASE, PROFILES

GOOGLE_CLIENT_ID = "ZOEYMCP_LIVE_GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "ZOEYMCP_LIVE_GOOGLE_CLIENT_SECRET"
GOOGLE_REFRESH_TOKEN = "ZOEYMCP_LIVE_GOOGLE_REFRESH_TOKEN"
SPOTIFY_CLIENT_ID = "ZOEYMCP_LIVE_SPOTIFY_CLIENT_ID"
DEFAULT_REDIRECT = "http://127.0.0.1/callback"


def live(*names: str) -> pytest.MarkDecorator:
    missing = [name for name in names if not os.environ.get(name)]
    return pytest.mark.skipif(bool(missing), reason=f"live test: set {', '.join(missing)}")


def profile_policy(profile: str, client_id: str) -> tuple[Policy, OAuth2Credential]:
    """The shipped profile with the operator's client ID, and nothing else changed."""
    fragment = load_mapping((PROFILES / profile).read_text(encoding="utf-8"))
    [cred_raw] = fragment["credentials"].values()
    cred_raw["client_id"] = client_id
    policy = Policy.model_validate({**BASE, **fragment})
    assert [f for f in check_policy(policy) if f.level == "error"] == []
    [cred] = policy.credentials.values()
    assert isinstance(cred, OAuth2Credential)
    return policy, cred


def authorization_page(cred: OAuth2Credential) -> httpx.Response:
    """Open the authorization URL as a browser would, up to the sign-in page."""
    assert cred.redirect_uri == DEFAULT_REDIRECT
    challenge = code_challenge(new_verifier().reveal())
    url = authorize_url(cred, state=Secret("live-smoke-state"), challenge=challenge)
    with httpx.Client(follow_redirects=True, timeout=30) as browser:
        return browser.get(url)


@live(GOOGLE_CLIENT_ID)
def test_google_accepts_the_portless_loopback_redirect() -> None:
    _, cred = profile_policy("google-oauth.yaml", os.environ[GOOGLE_CLIENT_ID])
    page = authorization_page(cred)
    assert page.status_code == 200
    assert "redirect_uri_mismatch" not in page.text
    assert "invalid_request" not in page.text


@live(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN)
def test_google_refresh_and_calendar_list(tmp_path: Path) -> None:
    policy, _ = profile_policy("google-oauth.yaml", os.environ[GOOGLE_CLIENT_ID])
    keys = KeySet.from_text(generate_master_key())
    store = SecretStore(tmp_path, keys)
    store.load()
    for name, var in (
        ("google-client-secret", GOOGLE_CLIENT_SECRET),
        ("google-refresh", GOOGLE_REFRESH_TOKEN),
    ):
        store.put(name, os.environ[var], derive_binding(policy, name))
    placeholder = next(c.placeholder for c in policy.routes[0].callers if not isinstance(c, str))

    async def calendar_list() -> tuple[int, dict[str, Any]]:
        # The vault's own clients: the system trust store, no proxy from the environment.
        vault = VaultApp(policy, store, keys, environ={})
        transport = httpx.ASGITransport(app=vault)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://vault") as agent:
                response = await agent.get(
                    "/gcal/calendar/v3/users/me/calendarList",
                    headers={"Authorization": f"Bearer {placeholder}"},
                )
            [status] = vault.tokens.status()
        finally:
            await vault.aclose()
        return response.status_code, status

    code, status = asyncio.run(calendar_list())
    assert code == 200
    assert (status["state"], status["code"]) == ("ok", None)


@live(SPOTIFY_CLIENT_ID)
def test_spotify_accepts_the_portless_loopback_redirect() -> None:
    _, cred = profile_policy("spotify-pkce.yaml", os.environ[SPOTIFY_CLIENT_ID])
    page = authorization_page(cred)
    assert page.status_code == 200
    assert "INVALID_CLIENT" not in page.text
    assert "Invalid redirect URI" not in page.text
