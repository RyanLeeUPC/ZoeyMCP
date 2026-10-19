from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.vault.bindings import (
    VAULT_PREFIX,
    BindingError,
    derive_binding,
    derive_oauth_binding,
    live_slot,
    oauth_binding,
    oauth_secret_names,
)
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore, SecretUnavailable

from .conftest import EXAMPLE_POLICY

Raw = dict[str, Any]
TOKEN = "https://accounts.example:443"
BROKER = {
    "oauth": {
        "token": "https://auth.broker.example:443",
        "resources": ["https://mcp.broker.example:443"],
    }
}


def example_policy() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


def oauth(**fields: Any) -> Raw:
    return {
        "kind": "oauth2",
        "token_url": "https://accounts.example/oauth/token",
        "client_id": "client-1",
        "refresh_token": "store:music-refresh",
        **fields,
    }


def header(secret: str) -> Raw:
    return {"kind": "header", "header": "X-Api-Key", "secret": secret}


def smtp(password: str, *, to: str = "b@mail.example", username: str = "u") -> Raw:
    return {
        "kind": "smtp",
        "host": "smtp.mail.example",
        "port": 465,
        "username": username,
        "password": password,
        "from": "a@mail.example",
        "to": [to],
    }


def policy(
    credentials: dict[str, Raw],
    routes: list[tuple[str, str]],
    connectors: dict[str, Raw] | None = None,
) -> Policy:
    """A policy with one route per ``(credential, upstream)`` pair."""
    return Policy.model_validate(
        {
            "version": 1,
            "mode": "declarative",
            "credentials": {
                n: {k: v for k, v in c.items() if v is not None} for n, c in credentials.items()
            },
            "connectors": connectors or {},
            "routes": [
                {
                    "name": f"r{i}",
                    "prefix": f"/r{i}",
                    "upstream": upstream,
                    "credential": cred,
                    "callers": [{"placeholder": f"ph-route-{i}-0123456789"}],
                    "rules": [{"methods": ["GET"], "paths": ["/x"]}],
                }
                for i, (cred, upstream) in enumerate(routes)
            ],
        }
    )


def binding_error(p: Policy, name: str, reason: str) -> str:
    with pytest.raises(BindingError) as info:
        derive_binding(p, name)
    assert info.value.reason == reason
    return str(info.value)


# --- static secrets and connectors -------------------------------------------------------------


def test_route_credential_binds_to_its_upstream() -> None:
    assert derive_binding(example_policy(), "music-stats") == {
        "origins": ["https://api.stats.example:443"]
    }


@pytest.mark.parametrize(
    "cred",
    [
        header("store:key"),
        {"kind": "query", "param": "api_key", "secret": "store:key"},
        {"kind": "path", "template": "/bot{secret}", "secret": "store:key"},
        {"kind": "basic", "username": "alice", "secret": "store:key"},
        {"kind": "basic", "username": "store:key", "secret": "store:other"},
    ],
    ids=["header", "query", "path", "basic-secret", "basic-username"],
)
def test_static_secrets_bind_to_every_upstream_that_uses_them(cred: Raw) -> None:
    p = policy(
        {
            "a": cred,
            "b": header("store:key"),
            "c": header("store:unrelated"),
            "d": {"kind": "basic", "username": "bob", "secret": "store:other"},
        },
        [
            ("c", "https://c.example"),
            ("b", "https://b.example"),
            ("a", "https://A.example:443"),
            ("d", "https://d.example"),
        ],
    )
    assert derive_binding(p, "key") == {
        "origins": ["https://a.example:443", "https://b.example:443"]
    }


def test_smtp_password_binds_to_the_connector() -> None:
    assert derive_binding(example_policy(), "mail-pass") == {
        "smtp": {
            "host": "smtp.mail.example",
            "port": 465,
            "from": "Agent <agent@mail.example>",
            "to": ["partner@mail.example"],
        }
    }


def test_connectors_with_the_same_constraints_share_a_secret() -> None:
    p = policy({}, [], {"one": smtp("store:pass"), "two": smtp("env:X", username="store:pass")})
    assert derive_binding(p, "pass") == {
        "smtp": {
            "host": "smtp.mail.example",
            "port": 465,
            "from": "a@mail.example",
            "to": ["b@mail.example"],
        }
    }


def test_connectors_with_different_constraints_are_refused() -> None:
    p = policy({}, [], {"one": smtp("store:pass"), "two": smtp("store:pass", to="c@mail.example")})
    assert (
        binding_error(p, "pass", "conflict")
        == "'pass' is used by connectors with different constraints"
    )


def test_unreferenced_secret_needs_an_explicit_origin() -> None:
    assert binding_error(example_policy(), "nobody-uses-this", "unbound") == (
        "the policy doesn't use store:nobody-uses-this on any route or connector; "
        "pass --origin to bind it explicitly"
    )


def test_conflicting_uses_are_refused() -> None:
    raw = example_policy().model_dump(by_alias=True)
    raw["credentials"]["music-stats"]["secret"] = "store:mail-pass"
    assert binding_error(Policy.model_validate(raw), "mail-pass", "conflict") == (
        "'mail-pass' is used both by a connector and by HTTP credentials"
    )


# --- OAuth secrets -----------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["broker-refresh", "broker-client-id"])
def test_oauth_secrets_bind_to_the_token_endpoint_and_the_routes(name: str) -> None:
    assert derive_binding(example_policy(), name) == BROKER


@pytest.mark.parametrize(
    "cred",
    [
        oauth(refresh_token="store:s"),
        oauth(client_id="store:s"),
        oauth(client_secret="store:s"),
        oauth(grant="client_credentials", refresh_token=None, client_secret="store:s"),
    ],
    ids=["refresh-token", "client-id", "client-secret", "client-credentials"],
)
def test_every_oauth_ref_gets_the_oauth_shape(cred: Raw) -> None:
    p = policy({"other": header("store:x"), "music": cred}, [("music", "https://api.example")])
    assert derive_binding(p, "s") == {
        "oauth": {"token": TOKEN, "resources": ["https://api.example:443"]}
    }


def test_resources_are_the_union_of_every_route() -> None:
    p = policy(
        {
            "music": oauth(client_secret="store:client"),
            "files": oauth(
                token_url="https://ACCOUNTS.example:443/other/path",
                refresh_token="store:files-refresh",
                client_secret="store:client",
            ),
            "stats": header("store:key"),
        },
        [
            ("music", "https://media.example"),
            ("files", "https://files.example:8443"),
            ("music", "https://api.example"),
            ("files", "https://API.example:443/v2"),
            ("stats", "https://stats.example"),
        ],
    )
    assert derive_binding(p, "client") == {
        "oauth": {
            "token": TOKEN,
            "resources": [
                "https://api.example:443",
                "https://files.example:8443",
                "https://media.example:443",
            ],
        }
    }
    # A refresh token is bound to its own credential's routes only.
    assert derive_binding(p, "files-refresh") == {
        "oauth": {
            "token": TOKEN,
            "resources": ["https://api.example:443", "https://files.example:8443"],
        }
    }


def test_a_shared_client_secret_binds_to_the_routes_there_are() -> None:
    p = policy(
        {
            "music": oauth(client_secret="store:client"),
            "unused": oauth(refresh_token="store:unused-refresh", client_secret="store:client"),
        },
        [("music", "https://api.example")],
    )
    assert derive_binding(p, "client") == {
        "oauth": {"token": TOKEN, "resources": ["https://api.example:443"]}
    }


@pytest.mark.parametrize(
    ("other_url", "other"),
    [
        ("https://other.example/oauth/token", "https://other.example:443"),
        ("https://accounts.example:8443/oauth/token", "https://accounts.example:8443"),
    ],
)
def test_different_token_origins_are_refused(other_url: str, other: str) -> None:
    p = policy(
        {
            "music": oauth(client_secret="store:client"),
            "files": oauth(
                token_url=other_url,
                refresh_token="store:files-refresh",
                client_secret="store:client",
            ),
        },
        [("music", "https://api.example"), ("files", "https://api.example")],
    )
    assert binding_error(p, "client", "conflict") == (
        f"'client' would be sent to the token endpoints {TOKEN}, {other}; "
        "an OAuth secret is bound to one"
    )


@pytest.mark.parametrize("routed", [True, False], ids=["routed", "unrouted"])
@pytest.mark.parametrize(
    ("credentials", "connectors"),
    [
        ({"stats": header("store:s")}, {}),
        ({"stats": {"kind": "query", "param": "key", "secret": "store:s"}}, {}),
        ({"stats": {"kind": "path", "template": "/k{secret}", "secret": "store:s"}}, {}),
        ({"stats": {"kind": "basic", "username": "alice", "secret": "store:s"}}, {}),
        ({"stats": {"kind": "basic", "username": "store:s", "secret": "store:x"}}, {}),
        ({}, {"mail": smtp("store:s")}),
        ({"stats": header("store:s")}, {"mail": smtp("store:s")}),
    ],
    ids=["header", "query", "path", "basic-secret", "basic-username", "connector", "both"],
)
def test_an_oauth_secret_is_never_also_a_static_secret(
    credentials: dict[str, Raw], connectors: dict[str, Raw], routed: bool
) -> None:
    # A static use with no route still counts: the policy says the secret is a static one.
    static_routes = [(n, "https://stats.example") for n in credentials] if routed else []
    p = policy(
        {"music": oauth(client_secret="store:s"), **credentials},
        [("music", "https://api.example"), *static_routes],
        connectors,
    )
    assert binding_error(p, "s", "conflict") == (
        "'s' is an OAuth secret of music and is also used by another credential or a "
        "connector; an OAuth secret must never be injectable as a static secret"
    )


def test_a_mixed_use_names_every_oauth_user() -> None:
    p = policy(
        {
            "music": oauth(client_secret="store:s"),
            "files": oauth(refresh_token="store:files-refresh", client_secret="store:s"),
            "stats": header("store:s"),
        },
        [("music", "https://api.example"), ("files", "https://files.example")],
    )
    assert binding_error(p, "s", "conflict") == (
        "'s' is an OAuth secret of music, files and is also used by another credential or a "
        "connector; an OAuth secret must never be injectable as a static secret"
    )


def test_an_oauth_secret_with_no_route_is_refused() -> None:
    p = policy(
        {
            "music": oauth(client_secret="store:client"),
            "files": oauth(refresh_token="store:files-refresh", client_secret="store:client"),
            "stats": header("store:key"),
        },
        [("stats", "https://stats.example")],
    )
    assert binding_error(p, "client", "no_route") == (
        "no route uses music, files; there is nothing to bind the access tokens minted with "
        "'client' to"
    )
    assert binding_error(p, "music-refresh", "no_route") == (
        "no route uses music; there is nothing to bind the access tokens minted with "
        "'music-refresh' to"
    )


# --- live slots and derive_oauth_binding -------------------------------------------------------


def seeded_policy() -> Policy:
    return policy(
        {
            "stats": header("store:key"),
            "plain": oauth(refresh_token="store:plain-refresh"),
            "machine": oauth(
                grant="client_credentials", refresh_token=None, client_secret="store:machine"
            ),
            "music": oauth(refresh_token="env:MUSIC_REFRESH"),
            "unrouted": oauth(refresh_token="env:UNROUTED_REFRESH"),
        },
        [
            ("stats", "https://stats.example"),
            ("plain", "https://plain.example"),
            ("machine", "https://machine.example"),
            ("music", "https://api.example"),
            ("music", "https://media.example"),
        ],
    )


def test_live_slot_names() -> None:
    assert VAULT_PREFIX == "oauth."
    assert live_slot("music") == "oauth.music.live"


def test_a_live_slot_binds_like_its_credential() -> None:
    p = seeded_policy()
    expected = {
        "oauth": {
            "token": TOKEN,
            "resources": ["https://api.example:443", "https://media.example:443"],
        }
    }
    assert derive_binding(p, "oauth.music.live") == expected
    assert derive_oauth_binding(p, "music") == expected


@pytest.mark.parametrize(
    "name",
    [
        "oauth.stats.live",
        "oauth.plain.live",
        "oauth.machine.live",
        "oauth.nobody.live",
        "oauth.music",
        "oauth.music.live.x",
        "oauth.plain-refresh",
    ],
)
def test_other_vault_managed_names_are_refused(name: str) -> None:
    assert binding_error(seeded_policy(), name, "orphan_slot") == (
        f"{name!r} is managed by the vault, and no credential keeps its live refresh token there"
    )


def test_a_live_slot_with_no_route_is_refused() -> None:
    assert binding_error(seeded_policy(), "oauth.unrouted.live", "no_route") == (
        "no route uses credential 'unrouted'; there is nothing to bind its access tokens to"
    )


def test_derive_oauth_binding_per_credential() -> None:
    p = seeded_policy()
    assert derive_oauth_binding(p, "machine") == {
        "oauth": {"token": TOKEN, "resources": ["https://machine.example:443"]}
    }
    assert derive_oauth_binding(p, "plain") == {
        "oauth": {"token": TOKEN, "resources": ["https://plain.example:443"]}
    }
    for name in ("stats", "absent"):
        with pytest.raises(BindingError) as info:
            derive_oauth_binding(p, name)
        assert str(info.value) == f"{name!r} is not an oauth2 credential"
        assert info.value.reason == "not_oauth"


def test_oauth_binding_is_canonical() -> None:
    resources = ["https://B.example/x", "https://a.example:443", "https://b.example:443"]
    assert oauth_binding("HTTPS://Accounts.example/token", resources) == {
        "oauth": {"token": TOKEN, "resources": ["https://a.example:443", "https://b.example:443"]}
    }
    with pytest.raises(ValueError, match=r"^an OAuth binding needs at least one resource origin$"):
        oauth_binding("https://accounts.example/token", [])


def test_oauth_secret_names() -> None:
    assert oauth_secret_names(example_policy()) == {"broker-refresh", "broker-client-id"}
    p = policy(
        {
            "stats": header("store:key"),
            "music": oauth(
                client_id="store:music-id",
                client_secret="env:MUSIC_SECRET",
                refresh_token="env:MUSIC_REFRESH",
            ),
            "plain": oauth(refresh_token="store:plain-refresh", client_secret="store:plain-secret"),
            "machine": oauth(
                grant="client_credentials", refresh_token=None, client_secret="store:machine"
            ),
        },
        [],
    )
    assert oauth_secret_names(p) == {
        "music-id",
        "oauth.music.live",
        "plain-refresh",
        "plain-secret",
        "machine",
    }


# --- what the binding allows -------------------------------------------------------------------


def test_an_oauth_binding_is_never_an_origin_binding(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, KeySet.from_master(bytes(range(32))))
    store.load()
    store.put("broker-refresh", "rt-123456", derive_binding(example_policy(), "broker-refresh"))
    with pytest.raises(SecretUnavailable):
        store.get_for_origin("broker-refresh", "https://auth.broker.example/oauth/token")
    with pytest.raises(SecretUnavailable):
        store.get_for_origin("broker-refresh", "https://mcp.broker.example/mcp")
    secret, _ = store.get_for_oauth(
        "broker-refresh",
        token_url="https://auth.broker.example/oauth/token",
        resource_url="https://mcp.broker.example/mcp",
    )
    assert secret.reveal() == "rt-123456"
    with pytest.raises(SecretUnavailable):
        store.get_for_oauth(
            "broker-refresh",
            token_url="https://auth.broker.example/oauth/token",
            resource_url="https://api.stats.example/2.0/",
        )
