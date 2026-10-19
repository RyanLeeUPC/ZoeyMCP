"""Second round of mutation-testing gaps (see test_mutation_gaps.py)."""

from __future__ import annotations

import json

import pytest

from zoeymcp.common.canonical import JSONRejected, loads_strict, render_for_approval
from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.policy.match import NormalizedPath, rule_matches
from zoeymcp.common.policy.schema import Rule
from zoeymcp.common.textrules import TextRuleError, check_text
from zoeymcp.vault.request import (
    filter_response_headers,
    normalize_path,
    scrub,
    secret_variants,
)
from zoeymcp.vault.store import canonical_origin

NL, TAB = chr(10), chr(9)


# --- a rule's later paths are still tried after an earlier one doesn't match ------------------


def test_a_rule_matches_on_its_second_path() -> None:
    rule = Rule(methods=["GET"], paths=["/first", "/second/{id}"], params={"id": ["7"]})
    assert rule_matches(rule, "GET", normalize_path(b"/second/7"))
    assert not rule_matches(rule, "GET", normalize_path(b"/second/8"))


# --- an upstream can't send internal headers through to the caller ---------------------------


def test_internal_headers_from_an_upstream_are_dropped() -> None:
    kept = filter_response_headers(
        [("X-ZoeyMCP-Gateway", "zgw1-forged"), ("x-zoeymcp-anything", "1"), ("X-Ok", "y")]
    )
    assert kept == [("X-Ok", "y")]


# --- encoding and scrubbing details ----------------------------------------------------------


def test_sub_delimiters_stay_literal_upstream() -> None:
    path = NormalizedPath(("user@host", "a:b", "x+y", "k=v;w", "it's(1)"))
    assert path.encoded() == "/user@host/a:b/x+y/k=v;w/it's(1)"


def test_json_variant_of_a_secret_needing_escapes() -> None:
    secret = "k" + chr(0xE4) + 'y"with-quote'
    variants = secret_variants(secret)
    assert json.dumps(secret, ensure_ascii=False)[1:-1].encode() in variants
    assert json.dumps(secret)[1:-1].encode() in variants


def test_scrub_counts_every_hit() -> None:
    secret = "sk-live-0123456789"
    data = f"{secret} and %s".encode() % secret.replace("-", "%2D").encode()
    _, count = scrub(data + b" " + secret.encode(), secret_variants(secret))
    assert count == 2


def test_canonical_origin_needs_a_host() -> None:
    for url in ("https://", "https:///path", "//host-only"):
        with pytest.raises(ValueError, match="not an absolute URL"):
            canonical_origin(url)


# --- canonical JSON rendering and integer limits ---------------------------------------------


def test_rendering_nested_lists() -> None:
    assert render_for_approval({"a": [[1, 2], []]}) == (
        "{"
        + NL
        + '  "a": ['
        + NL
        + "    ["
        + NL
        + "      1,"
        + NL
        + "      2"
        + NL
        + "    ],"
        + NL
        + "    []"
        + NL
        + "  ]"
        + NL
        + "}"
    )


def test_rendering_refuses_unsafe_integers() -> None:
    with pytest.raises(JSONRejected, match="safe range"):
        render_for_approval({"amount": 2**60})


def test_integer_length_limit() -> None:
    assert loads_strict("9" * 20, safe_integers=False) == int("9" * 20)
    with pytest.raises(JSONRejected, match="too long"):
        loads_strict("9" * 21, safe_integers=False)


# --- check_text passes its options through ---------------------------------------------------


def test_check_text_options() -> None:
    assert check_text("", max_chars=5) == ""
    with pytest.raises(TextRuleError, match="too short"):
        check_text("", max_chars=5, min_chars=1)
    with pytest.raises(TextRuleError, match="single-line"):
        check_text("a" + NL + "b", max_chars=5, single_line=True)
    with pytest.raises(TextRuleError, match="tab"):
        check_text("a" + TAB + "b", max_chars=5, allow_tabs=False)


# --- check: seeds vs secrets, client_credentials, no gateway section --------------------------

BASE = {
    "version": 1,
    "mode": "declarative",
}


def _check(credentials: dict[str, object], **extra: object) -> list[str]:
    routes = [
        {
            "name": f"r{i}",
            "prefix": f"/r{i}",
            "upstream": "https://api.example",
            "credential": name,
            "callers": [{"placeholder": f"ph-route-{i}-0123456789"}],
            "rules": [{"methods": ["GET"], "paths": ["/x"]}],
        }
        for i, name in enumerate(credentials)
    ]
    policy = Policy.model_validate({**BASE, "credentials": credentials, "routes": routes, **extra})
    return [f"{f.level} {f.path}: {f.message}" for f in check_policy(policy)]


def test_env_secrets_are_called_secrets_not_seeds() -> None:
    found = _check(
        {
            "o": {
                "kind": "oauth2",
                "token_url": "https://auth.example/token",
                "grant": "client_credentials",
                "client_id": "env:CLIENT_ID",
                "client_secret": "env:CLIENT_SECRET",
            },
            "b": {"kind": "basic", "username": "env:BASIC_USER", "secret": "store:b"},
        }
    )
    for var in ("CLIENT_ID", "CLIENT_SECRET", "BASIC_USER"):
        assert any(f"secret read from env var {var}" in f for f in found), (var, found)
    assert not any("seeded" in f for f in found)


def test_client_credentials_take_no_refresh_token() -> None:
    found = _check(
        {
            "o": {
                "kind": "oauth2",
                "token_url": "https://auth.example/token",
                "grant": "client_credentials",
                "client_id": "c",
                "client_secret": "store:o-secret",
                "refresh_token": "store:o-refresh",
            }
        }
    )
    assert "error credentials.o.refresh_token: not used by the client_credentials grant" in found


def test_reseed_on_change_is_fine_for_an_env_seed() -> None:
    found = _check(
        {
            "o": {
                "kind": "oauth2",
                "token_url": "https://auth.example/token",
                "client_id": "c",
                "refresh_token": "env:SEED",
                "reseed": "on-change",
            }
        }
    )
    assert not any(".reseed:" in f for f in found), found
    assert any(
        "a changed env value replaces the live token (reseed: on-change)" in f for f in found
    )


def test_check_without_a_gateway_section() -> None:
    found = _check({"k": {"kind": "header", "secret": "store:k"}})
    assert not any(f.startswith("error") for f in found), found
