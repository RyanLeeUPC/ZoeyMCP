"""Pinned formats: a change here breaks every existing deployment, so it must be deliberate.

The golden store was written by the store code with a fixed master key. If these tests fail,
the on-disk store format, the key derivation or the authenticated data changed, and existing
stores would no longer decrypt.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore, _aad, smtp_binding

GOLDEN = Path(__file__).parent / "data" / "golden-store"
MASTER = bytes(range(100, 132))


def test_key_derivation_is_pinned() -> None:
    keys = KeySet.from_master(MASTER)
    assert keys.key_id == "94229fc20fd18d94"
    assert keys.gateway_key(1) == "zgw1-FS0e74ioM9Z0FkwBv2vf7079tRI1XO84IhfzKt4rlYw"


def test_authenticated_data_is_pinned() -> None:
    aad = _aad("0123456789abcdef", "api-key", {"origins": ["https://api.example:443"]})
    assert aad == (
        b'{"binding":{"origins":["https://api.example:443"]},"format":1,'
        b'"kid":"0123456789abcdef","name":"api-key"}'
    )


def test_the_golden_store_still_decrypts(tmp_path: Path) -> None:
    shutil.copy(GOLDEN / "store.json", tmp_path / "store.json")
    store = SecretStore(tmp_path, KeySet.from_master(MASTER))
    assert store.load() == 0
    assert store.get_for_origin("api-key", "https://api.example/x").reveal() == (
        "golden-api-value-1"
    )
    binding = smtp_binding("smtp.mail.example", 465, "A <a@mail.example>", ["p@mail.example"])
    assert store.get_for_binding("mail-pass", binding).reveal() == "golden-mail-value-2"
