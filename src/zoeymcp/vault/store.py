"""The encrypted secret store (design §4.5).

One JSON file on the vault's state volume. Each entry is encrypted with AES-256-GCM under the
store key, with a fresh nonce per write. The authenticated data binds:

- the format version and key ID;
- the secret's **name**, so a ciphertext can't be moved to another entry;
- its **binding**: what the secret may be used for (the origins it may be sent to, or a
  connector's fixed constraints). The binding is set when the secret is written.

So editing the file, moving ciphertexts, or changing a binding makes the entry undecryptable,
and a policy change that sends a secret somewhere new can't use it until it's entered again.

Metadata (name, binding, times, key ID) is kept in the clear, so health can be shown without
decrypting anything. There is deliberately no way to list secret values.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..common.canonical import dumps_canonical
from .keys import KeySet

STORE_FORMAT = 1
STORE_FILE = "store.json"
NONCE_BYTES = 12
MAX_SECRET_BYTES = 64 * 1024
_DEFAULT_PORTS = {"https": 443, "http": 80}


class StoreError(Exception):
    """The store file can't be used as it is (wrong key, corrupt, unknown format)."""


class SecretUnavailable(Exception):
    """A secret can't be used for this request. ``reason`` is safe to log."""

    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self.reason = reason
        super().__init__(f"secret {name!r}: {reason}")


class Secret:
    """A secret value. ``repr`` and ``str`` never show it; use :meth:`reveal`."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    __str__ = __repr__


def canonical_origin(url: str) -> str:
    """``scheme://host:port`` with a lowercase host and an explicit port."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ValueError(f"not an absolute URL: {url!r}")
    port = parts.port or _DEFAULT_PORTS.get(parts.scheme)
    if port is None:
        raise ValueError(f"no default port for scheme {parts.scheme!r}")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme.lower()}://{host}:{port}"


def origin_binding(origins: list[str]) -> dict[str, Any]:
    """The binding for an HTTP credential: the origins it may be sent to."""
    if not origins:
        raise ValueError("a binding needs at least one origin")
    return {"origins": sorted({canonical_origin(o) for o in origins})}


def smtp_binding(host: str, port: int, sender: str, recipients: list[str]) -> dict[str, Any]:
    """The binding for an SMTP connector's password: its host, port, sender and recipients."""
    return {
        "smtp": {
            "host": host.lower(),
            "port": port,
            "from": sender,
            "to": sorted(r.lower() for r in recipients),
        }
    }


@dataclass(frozen=True)
class EntryMeta:
    name: str
    binding: dict[str, Any]
    key_id: str
    created: str
    updated: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "binding": self.binding,
            "key_id": self.key_id,
            "created": self.created,
            "updated": self.updated,
        }


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _aad(key_id: str, name: str, binding: Mapping[str, Any]) -> bytes:
    return dumps_canonical(
        {"format": STORE_FORMAT, "kid": key_id, "name": name, "binding": dict(binding)}
    )


class SecretStore:
    """The vault's store. Safe to share between threads; writes are atomic."""

    def __init__(self, state_dir: Path, keys: KeySet, previous: KeySet | None = None) -> None:
        self._path = state_dir / STORE_FILE
        self._keys = keys
        self._previous = previous
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}

    @property
    def path(self) -> Path:
        return self._path

    # --- loading and rotation ------------------------------------------------------------------

    def load(self) -> int:
        """Read the store file. Returns how many entries were re-encrypted under the current key.

        Refuses to start (``StoreError``) if any entry was written under a key that is neither
        the current master key nor ``ZOEYMCP_MASTER_KEY_PREVIOUS``: that is almost always a
        mistyped key, and starting anyway would mix entries from two keys.
        """
        with self._lock:
            if not self._path.exists():
                self._entries = {}
                return 0
            try:
                document = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise StoreError(f"can't read {self._path}: {exc}") from exc
            if not isinstance(document, dict) or document.get("format") != STORE_FORMAT:
                raise StoreError(f"{self._path} isn't a format-{STORE_FORMAT} store")
            entries = document.get("entries")
            if not isinstance(entries, dict):
                raise StoreError(f"{self._path} has no entries table")
            known = {self._keys.key_id}
            if self._previous is not None:
                known.add(self._previous.key_id)
            for name, entry in entries.items():
                kid = entry.get("kid") if isinstance(entry, dict) else None
                if kid not in known:
                    raise StoreError(
                        f"entry {name!r} was written with key ID {kid}, but the master key's ID "
                        f"is {self._keys.key_id}. If you are rotating the master key, set "
                        "ZOEYMCP_MASTER_KEY_PREVIOUS to the old key."
                    )
            self._entries = entries
            rotated = 0
            if self._previous is not None and self._previous.key_id != self._keys.key_id:
                for name, entry in list(entries.items()):
                    if entry["kid"] == self._previous.key_id:
                        value = self._decrypt(name, entry, self._previous)
                        self._entries[name] = self._encrypt(
                            name, value, entry["binding"], created=entry["created"]
                        )
                        rotated += 1
                if rotated:
                    self._write()
            return rotated

    # --- reading -------------------------------------------------------------------------------

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._entries)

    def metadata(self) -> list[EntryMeta]:
        with self._lock:
            return [
                EntryMeta(name, e["binding"], e["kid"], e["created"], e["updated"])
                for name, e in sorted(self._entries.items())
            ]

    def get_for_origin(self, name: str, url: str) -> Secret:
        """The secret, if its binding allows sending it to ``url``'s origin."""
        origin = canonical_origin(url)
        entry = self._entry(name)
        allowed = entry["binding"].get("origins")
        if not isinstance(allowed, list) or origin not in allowed:
            raise SecretUnavailable(
                name, f"not bound to {origin}; enter it again to authorize that origin"
            )
        return self._decrypt(name, entry, self._keys)

    def get_for_binding(self, name: str, binding: Mapping[str, Any]) -> Secret:
        """The secret, if it was stored with exactly this binding (connectors)."""
        entry = self._entry(name)
        if dumps_canonical(entry["binding"]) != dumps_canonical(dict(binding)):
            raise SecretUnavailable(
                name, "its connector constraints changed; enter it again to authorize them"
            )
        return self._decrypt(name, entry, self._keys)

    def _entry(self, name: str) -> dict[str, Any]:
        with self._lock:
            entry = self._entries.get(name)
        if entry is None:
            raise SecretUnavailable(name, "not in the store")
        return entry

    # --- writing -------------------------------------------------------------------------------

    def put(self, name: str, value: str, binding: Mapping[str, Any]) -> None:
        """Store or replace a secret with its binding."""
        if not value:
            raise ValueError("a secret can't be empty")
        if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
            raise ValueError(f"a secret can't be larger than {MAX_SECRET_BYTES} bytes")
        if not binding:
            raise ValueError("a secret needs a binding")
        with self._lock:
            existing = self._entries.get(name)
            created = existing["created"] if existing else None
            self._entries[name] = self._encrypt(name, Secret(value), dict(binding), created=created)
            self._write()

    def delete(self, name: str) -> bool:
        with self._lock:
            if self._entries.pop(name, None) is None:
                return False
            self._write()
            return True

    # --- internals -----------------------------------------------------------------------------

    def _encrypt(
        self, name: str, value: Secret, binding: dict[str, Any], *, created: str | None
    ) -> dict[str, Any]:
        nonce = os.urandom(NONCE_BYTES)
        aad = _aad(self._keys.key_id, name, binding)
        ciphertext = AESGCM(self._keys.store_key).encrypt(
            nonce, value.reveal().encode("utf-8"), aad
        )
        now = _now()
        return {
            "kid": self._keys.key_id,
            "binding": binding,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "created": created or now,
            "updated": now,
        }

    def _decrypt(self, name: str, entry: Mapping[str, Any], keys: KeySet) -> Secret:
        try:
            nonce = base64.b64decode(entry["nonce"], validate=True)
            ciphertext = base64.b64decode(entry["ciphertext"], validate=True)
            aad = _aad(entry["kid"], name, entry["binding"])
            plain = AESGCM(keys.store_key).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, KeyError, ValueError, TypeError) as exc:
            raise SecretUnavailable(
                name, "entry failed authentication (tampered or corrupt)"
            ) from exc
        return Secret(plain.decode("utf-8"))

    def _write(self) -> None:
        document = {"format": STORE_FORMAT, "kid": self._keys.key_id, "entries": self._entries}
        data = json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # mkstemp creates the file with mode 0600, readable by the vault's uid only.
        fd, tmp = tempfile.mkstemp(prefix=".store-", dir=self._path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
