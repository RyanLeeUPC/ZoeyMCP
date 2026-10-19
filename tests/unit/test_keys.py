from __future__ import annotations

import base64
import hashlib
import hmac
import io

import pytest

from zoeymcp.common import logs
from zoeymcp.vault.keys import (
    CONTEXT_AUDIT,
    CONTEXT_CONFIG,
    CONTEXT_KEY_ID,
    CONTEXT_PORTAL,
    CONTEXT_STORE,
    KeySet,
    MasterKeyError,
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
    }
    assert len(derived) == 7
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
