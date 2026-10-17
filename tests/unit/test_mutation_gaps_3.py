"""Third round of mutation-testing gaps: the M2 OAuth modules (see test_mutation_gaps.py)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.vault.bindings import oauth_binding
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.oauth.protocol import (
    OAUTH_CLIENT_REJECTED,
    OAUTH_RECONSENT_NEEDED,
    OAUTH_ROTATION_LOST,
    OAUTH_UNAVAILABLE,
    GrantKind,
    TokenResponse,
    classify,
    parse_token_body,
)
from zoeymcp.vault.store import SecretStore, SecretUnavailable

TOKEN_URL = "https://accounts.example/token"
API = "https://api.example/v1"
NOW = datetime(2026, 10, 17, 9, 0, tzinfo=UTC).timestamp()
# 90 seconds after NOW, as an HTTP date.
RETRY_DATE = "Sat, 17 Oct 2026 09:01:30 GMT"
KEYS = KeySet.from_master(bytes(range(32)))


def cred(**fields: Any) -> OAuth2Credential:
    raw: dict[str, Any] = {"kind": "oauth2", "token_url": TOKEN_URL, "client_id": "app-1"}
    raw.update(fields)
    return OAuth2Credential.model_validate(raw)


def classified(
    response: TokenResponse, *, grant: GrantKind = "refresh_token", replayed: bool = False
) -> Any:
    return classify(
        response, cred=cred(grant=grant), grant=grant, presented=None, replayed=replayed, now=NOW
    )


# --- a form body is recognized by its media type, whatever parameters follow ------------------


def test_a_form_body_with_two_media_type_parameters() -> None:
    body = b"access_token=fake-at&token_type=Bearer"
    content_type = "application/x-www-form-urlencoded; charset=utf-8; foo=bar"
    assert parse_token_body(body, content_type) == {
        "access_token": "fake-at",
        "token_type": "Bearer",
    }


# --- a Retry-After date counts from the wall clock on every backoff path -----------------------


def test_a_retry_date_on_an_error_status() -> None:
    outcome = classified(TokenResponse(503, b"", retry_after=RETRY_DATE))
    assert outcome.failure.code == OAUTH_UNAVAILABLE
    assert outcome.failure.retry_after == 90.0


def test_a_retry_date_on_a_success_status_that_is_an_error() -> None:
    body = b'{"error": "temporarily_unavailable"}'
    outcome = classified(TokenResponse(200, body, "application/json", RETRY_DATE))
    assert outcome.failure.code == OAUTH_UNAVAILABLE
    assert outcome.failure.retry_after == 90.0


# --- an error inside a 2xx is classified with the grant and the replay flag --------------------


@pytest.mark.parametrize(
    ("grant", "replayed", "code"),
    [
        ("refresh_token", False, OAUTH_RECONSENT_NEEDED),
        ("refresh_token", True, OAUTH_ROTATION_LOST),
        ("client_credentials", False, OAUTH_CLIENT_REJECTED),
    ],
)
def test_an_invalid_grant_inside_a_success_status(
    grant: GrantKind, replayed: bool, code: str
) -> None:
    body = b'{"error": "invalid_grant"}'
    outcome = classified(
        TokenResponse(200, body, "application/json"), grant=grant, replayed=replayed
    )
    assert (outcome.failure.kind, outcome.failure.code) == ("terminal", code)


# --- a refused OAuth secret names itself ------------------------------------------------------


def test_refused_oauth_secrets_say_which_and_why(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, KEYS)
    store.load()
    store.put("music-refresh", "fake-rt", oauth_binding(TOKEN_URL, [API]))
    with pytest.raises(SecretUnavailable) as caught:
        store.get_for_oauth("music-refresh", token_url="https://elsewhere.example/token")
    assert caught.value.name == "music-refresh"
    assert str(caught.value) == (
        "secret 'music-refresh': not bound to token endpoint https://elsewhere.example:443; "
        "enter it again to authorize it"
    )
    with pytest.raises(SecretUnavailable) as caught:
        store.get_for_oauth(
            "music-refresh", token_url=TOKEN_URL, resource_url="https://other.example/v2"
        )
    assert caught.value.name == "music-refresh"
    assert str(caught.value) == (
        "secret 'music-refresh': not bound to https://other.example:443; "
        "run login again to authorize it"
    )
    with pytest.raises(SecretUnavailable) as caught:
        store.get_for_oauth("missing", token_url=TOKEN_URL)
    assert caught.value.name == "missing"
    assert caught.value.reason == "not in the store"
