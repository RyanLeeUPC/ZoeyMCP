from __future__ import annotations

import base64
import hashlib
import hmac
import io

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zoeymcp.common import logs
from zoeymcp.egress.allowlist import KEY_PATTERN, EgressKey
from zoeymcp.vault.keys import (
    CONTEXT_AUDIT,
    CONTEXT_CONFIG,
    CONTEXT_EGRESS,
    CONTEXT_GATEWAY,
    CONTEXT_KEY_ID,
    CONTEXT_POLICY,
    CONTEXT_PORTAL,
    CONTEXT_STORE,
    POLICY_NONCE_BYTES,
    ConfigMac,
    KeySet,
    MasterKeyError,
    PolicyKey,
    PortalKey,
    derive,
    generate_master_key,
    parse_master_key,
)

MASTER = bytes(range(32))
MASTER_TEXT = base64.urlsafe_b64encode(MASTER).rstrip(b"=").decode()


def test_generated_keys_parse_and_differ() -> None:
    first, second = generate_master_key(), generate_master_key()
    assert first != second
    assert len(parse_master_key(first)) == 32
    assert len(first) == 43


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "empty"),
        (" " + MASTER_TEXT, "whitespace"),
        (MASTER_TEXT + "\n", "whitespace"),
        (MASTER_TEXT + "=", "without padding"),
        (base64.b64encode(MASTER).decode(), "without padding"),
        (base64.urlsafe_b64encode(bytes(16)).rstrip(b"=").decode(), "must be 32 bytes"),
        ("!" * 43, "isn't valid base64url"),
        (MASTER_TEXT[:-1] + "B", "canonical"),
    ],
)
def test_bad_master_keys(text: str, message: str) -> None:
    with pytest.raises(MasterKeyError, match=message):
        parse_master_key(text)


def test_contexts_give_independent_keys() -> None:
    keys = KeySet.from_text(MASTER_TEXT)
    derived = {
        keys.store_key,
        keys.config_key,
        bytes.fromhex(keys.key_id),
        keys.gateway_key(1).encode(),
        keys.gateway_key(2).encode(),
        derive(MASTER, CONTEXT_AUDIT),
        derive(MASTER, CONTEXT_PORTAL),
        derive(MASTER, CONTEXT_POLICY),
        keys.egress_key(1).encode(),
        keys.egress_key(2).encode(),
    }
    assert len(derived) == 10
    assert MASTER not in derived
    assert keys.store_key == derive(MASTER, CONTEXT_STORE)
    assert keys.config_key == derive(MASTER, CONTEXT_CONFIG)
    assert keys.key_id == derive(MASTER, CONTEXT_KEY_ID, 8).hex()


def test_derivation_is_deterministic_and_key_specific() -> None:
    assert KeySet.from_master(MASTER).gateway_key(1) == KeySet.from_master(MASTER).gateway_key(1)
    other = KeySet.from_master(bytes(32))
    assert other.key_id != KeySet.from_master(MASTER).key_id
    assert other.gateway_key(1) != KeySet.from_master(MASTER).gateway_key(1)


def test_gateway_key_format() -> None:
    key = KeySet.from_master(MASTER).gateway_key(3)
    assert key.startswith("zgw1-")
    assert len(base64.urlsafe_b64decode(key[5:] + "=")) == 32
    with pytest.raises(ValueError, match="start at 1"):
        KeySet.from_master(MASTER).gateway_key(0)


def test_repr_hides_key_material() -> None:
    text = repr(KeySet.from_master(MASTER))
    assert MASTER.hex() not in text
    assert "store_key" not in text
    assert "key_id=" in text


def test_the_portal_key_is_its_own_and_pinned() -> None:
    assert CONTEXT_PORTAL == "zoeymcp/portal/v1"
    keys = KeySet.from_master(MASTER)
    portal = keys.portal_key
    assert isinstance(portal, PortalKey)
    assert portal.key_id == keys.key_id
    expected = hmac.new(derive(MASTER, CONTEXT_PORTAL), b"data", hashlib.sha256).digest()
    assert portal.mac(b"data") == expected
    assert derive(MASTER, CONTEXT_PORTAL).hex() == (
        "54215fd5f0dc5b31cf630c373824d823c570331864074db90c0258742ca4d63f"
    )
    other = KeySet.from_master(bytes(32)).portal_key
    assert other.mac(b"data") != expected
    assert other.key_id != portal.key_id


def test_the_portal_key_never_shows() -> None:
    portal = KeySet.from_master(MASTER).portal_key
    text = repr(portal)
    assert text == f"PortalKey(key_id={portal.key_id}, <hidden>)"
    assert derive(MASTER, CONTEXT_PORTAL).hex() not in text
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        for value in (portal, [portal], {"k": (portal,)}):
            with pytest.raises(TypeError, match=r"refusing to log a secret \(PortalKey\)"):
                logs.Log("vault").event("probe", key=value)
    finally:
        logs.set_stream(None)
    assert buffer.getvalue() == ""
    assert PortalKey in logs.refused_types()


# --- the egress key (M7 design G.3) -------------------------------------------------------------


def test_the_egress_context_is_its_own_and_pinned() -> None:
    """A context of its own, beside the gateway's: neither key can be turned into the other."""
    assert CONTEXT_EGRESS == "zoeymcp/egress/v1/gen-{generation}"
    assert CONTEXT_GATEWAY == "zoeymcp/gateway/v1/gen-{generation}"
    assert derive(MASTER, "zoeymcp/egress/v1/gen-1").hex() == (
        "19140e620432121bc680b380358854275866101c093d1638b28f718af7f8f3c3"
    )
    keys = KeySet.from_master(MASTER)
    assert keys.egress_key(1) == "zeg1-GRQOYgQyEhvGgLOANYhUJ1hmEBwJPRY4so9xivf488M"
    assert keys.egress_key(1)[5:] != keys.gateway_key(1)[5:]
    assert len({keys.egress_key(n) for n in range(1, 6)}) == 5


def test_the_egress_key_is_what_the_role_takes() -> None:
    """``zeg1-`` and 43 base64url characters: the role's own pattern accepts it (G.3)."""
    keys = KeySet.from_master(MASTER)
    for generation in (1, 2, 1000):
        key = keys.egress_key(generation)
        assert key.startswith("zeg1-")
        assert len(base64.urlsafe_b64decode(key[5:] + "=")) == 32
        assert KEY_PATTERN.fullmatch(key)
        assert EgressKey(key).reveal() == key
    assert KeySet.from_master(bytes(32)).egress_key(1) != keys.egress_key(1)
    with pytest.raises(ValueError, match="start at 1"):
        keys.egress_key(0)


# --- the managed policy's keys (M6 design D.2, D.3) ----------------------------------------------

NONCE = bytes(range(12))


def test_the_policy_key_is_its_own_and_pinned() -> None:
    assert CONTEXT_POLICY == "zoeymcp/policy/v1"
    assert POLICY_NONCE_BYTES == 12
    keys = KeySet.from_master(MASTER)
    policy = keys.policy_key
    assert isinstance(policy, PolicyKey)
    assert policy.key_id == keys.key_id
    assert derive(MASTER, CONTEXT_POLICY).hex() == (
        "b3c1355c83e95091bb870d0fe31143353799ad0183a4a7c1a39c2aac1e8e73f9"
    )
    sealed = policy.encrypt(NONCE, b"body", b"bound")
    assert sealed == AESGCM(derive(MASTER, CONTEXT_POLICY)).encrypt(NONCE, b"body", b"bound")
    assert policy.decrypt(NONCE, sealed, b"bound") == b"body"
    other = KeySet.from_master(bytes(32)).policy_key
    assert other.key_id != policy.key_id
    for key, nonce, associated in ((policy, NONCE, b"other"), (policy, bytes(12), b"bound")):
        with pytest.raises(InvalidTag):
            key.decrypt(nonce, sealed, associated)
    with pytest.raises(InvalidTag):
        other.decrypt(NONCE, sealed, b"bound")


def test_the_policy_key_takes_only_twelve_byte_nonces() -> None:
    """``AESGCM`` takes 8 to 128 bytes (contract 61); the policy key holds to D.2's 12."""
    policy = KeySet.from_master(MASTER).policy_key
    sealed = policy.encrypt(NONCE, b"body", b"")
    for size in (8, 11, 13, 16):
        with pytest.raises(ValueError, match=rf"^a policy nonce is 12 bytes, not {size}$"):
            policy.encrypt(bytes(size), b"body", b"")
        with pytest.raises(ValueError, match=rf"^a policy nonce is 12 bytes, not {size}$"):
            policy.decrypt(bytes(size), sealed, b"")


def test_the_config_mac_is_k_config_under_a_context_line() -> None:
    keys = KeySet.from_master(MASTER)
    config = keys.config_mac
    assert isinstance(config, ConfigMac)
    assert config.key_id == keys.key_id
    context = b"zoeymcp/policy-head/v1\n"
    expected = hmac.new(keys.config_key, context + b"data", hashlib.sha256).digest()
    assert config.mac(context, b"data") == expected
    assert config.mac(b"\n", b"data") == hmac.new(keys.config_key, b"\ndata", "sha256").digest()
    assert KeySet.from_master(bytes(32)).config_mac.mac(context, b"data") != expected
    for bad in (b"", b"zoeymcp/policy-head/v1", b"two\nlines\n", b"\n\n"):
        with pytest.raises(ValueError, match=r"^a MAC context is one line, ending in a newline$"):
            config.mac(bad, b"data")


@pytest.mark.parametrize("name", ["policy_key", "config_mac"])
def test_the_policy_keys_never_show(name: str) -> None:
    key = getattr(KeySet.from_master(MASTER), name)
    kind = type(key).__name__
    assert repr(key) == f"{kind}(key_id={key.key_id}, <hidden>)"
    for material in (derive(MASTER, CONTEXT_POLICY), derive(MASTER, CONTEXT_CONFIG)):
        assert material.hex() not in repr(key)
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        for value in (key, [key], {"k": (key,)}):
            with pytest.raises(TypeError, match=rf"refusing to log a secret \({kind}\)"):
                logs.Log("vault").event("probe", key=value)
    finally:
        logs.set_stream(None)
    assert buffer.getvalue() == ""
    assert {PolicyKey, ConfigMac} <= set(logs.refused_types())
