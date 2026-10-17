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
decrypting anything. There is deliberately no way to list secret values. Bindings and ``meta`` are
copied on the way in and out: a caller changing its copy would otherwise break the entry's AAD.

An entry may also carry a clear ``meta`` object (OAuth health). It is outside the authenticated
data and is for display only: no decision reads it.

Write failures: ``put``, ``delete`` and ``update_meta`` change memory first. If the file can't be
written they set ``dirty`` and raise :class:`StoreWriteError`. Memory keeps the new value, and
the next successful write or :meth:`SecretStore.flush` saves everything. A crash before that
loses the change.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import enum
import json
import os
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
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


class StoreWriteError(OSError):
    """The store file couldn't be written. Memory holds the change, and ``dirty`` is set."""


class _Keep(enum.Enum):
    KEEP = enum.auto()


KEEP: Final = _Keep.KEEP
"""Passed as ``meta`` to :meth:`SecretStore.put`: keep the entry's current ``meta``."""


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
    meta: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "binding": self.binding,
            "key_id": self.key_id,
            "created": self.created,
            "updated": self.updated,
            "meta": self.meta,
        }


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _clean_meta(meta: Mapping[str, Any]) -> dict[str, Any]:
    """A private copy of ``meta``. Refused unless it is plain JSON."""
    try:
        text = json.dumps(dict(meta), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"meta must be plain JSON: {exc}") from exc
    clean: dict[str, Any] = json.loads(text)
    return clean


def _entry_meta(name: str, entry: Mapping[str, Any]) -> EntryMeta:
    meta = entry.get("meta")
    return EntryMeta(
        name,
        copy.deepcopy(entry["binding"]),
        entry["kid"],
        entry["created"],
        entry["updated"],
        copy.deepcopy(meta) if isinstance(meta, dict) else None,
    )


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
        self._dirty = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def dirty(self) -> bool:
        """Memory holds changes the file doesn't, because a write failed."""
        return self._dirty

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
                        fresh = self._encrypt(
                            name, value, entry["binding"], created=entry["created"]
                        )
                        if "meta" in entry:
                            fresh["meta"] = entry["meta"]
                        self._entries[name] = fresh
                        rotated += 1
                if rotated:
                    try:
                        self._persist()
                    except StoreWriteError as exc:
                        raise StoreError(f"can't save the re-encrypted store: {exc}") from exc
            return rotated

    # --- reading -------------------------------------------------------------------------------

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._entries)

    def metadata(self) -> list[EntryMeta]:
        with self._lock:
            return [_entry_meta(name, e) for name, e in sorted(self._entries.items())]

    def entry(self, name: str) -> EntryMeta | None:
        """One entry's clear metadata, or ``None`` if there is no such entry."""
        with self._lock:
            entry = self._entries.get(name)
            return None if entry is None else _entry_meta(name, entry)

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

    def get_for_oauth(
        self, name: str, *, token_url: str, resource_url: str | None = None
    ) -> tuple[Secret, dict[str, Any]]:
        """An OAuth secret and a copy of its binding, if it is bound to ``token_url``'s origin.

        With ``resource_url``, that origin must also be one of the binding's resources.
        """
        token_origin = canonical_origin(token_url)
        resource_origin = canonical_origin(resource_url) if resource_url is not None else None
        entry = self._entry(name)
        oauth = entry["binding"].get("oauth")
        if not isinstance(oauth, dict) or oauth.get("token") != token_origin:
            raise SecretUnavailable(
                name, f"not bound to token endpoint {token_origin}; enter it again to authorize it"
            )
        if resource_origin is not None:
            resources = oauth.get("resources")
            if not isinstance(resources, list) or resource_origin not in resources:
                raise SecretUnavailable(
                    name, f"not bound to {resource_origin}; run login again to authorize it"
                )
        return self._decrypt(name, entry, self._keys), copy.deepcopy(entry["binding"])

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

    def put(
        self,
        name: str,
        value: str,
        binding: Mapping[str, Any],
        *,
        meta: Mapping[str, Any] | _Keep | None = KEEP,
    ) -> None:
        """Store or replace a secret with its binding.

        ``meta`` replaces the entry's clear metadata. ``None`` removes it; ``KEEP`` keeps it.
        Raises :class:`StoreWriteError` if the file can't be written; memory has the new value.
        """
        if not value:
            raise ValueError("a secret can't be empty")
        if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
            raise ValueError(f"a secret can't be larger than {MAX_SECRET_BYTES} bytes")
        if not binding:
            raise ValueError("a secret needs a binding")
        new_meta = None if meta is None or meta is KEEP else _clean_meta(meta)
        with self._lock:
            existing = self._entries.get(name)
            created = existing["created"] if existing else None
            entry = self._encrypt(
                name, Secret(value), copy.deepcopy(dict(binding)), created=created
            )
            if meta is KEEP:
                if existing is not None and "meta" in existing:
                    entry["meta"] = existing["meta"]
            elif new_meta is not None:
                entry["meta"] = new_meta
            self._entries[name] = entry
            self._persist()

    def update_meta(self, name: str, meta: Mapping[str, Any] | None) -> bool:
        """Replace an entry's clear metadata without re-encrypting it. ``None`` removes it.

        Returns ``False`` if there is no such entry. Raises :class:`StoreWriteError` like
        :meth:`put`.
        """
        new_meta = None if meta is None else _clean_meta(meta)
        with self._lock:
            entry = self._entries.get(name)
            if entry is None:
                return False
            if new_meta is None:
                entry.pop("meta", None)
            else:
                entry["meta"] = new_meta
            self._persist()
            return True

    def delete(self, name: str) -> bool:
        """Remove a secret. Raises :class:`StoreWriteError` like :meth:`put`."""
        with self._lock:
            if self._entries.pop(name, None) is None:
                return False
            self._persist()
            return True

    def flush(self) -> None:
        """Write the file if an earlier write failed. Raises :class:`StoreWriteError`."""
        with self._lock:
            if self._dirty:
                self._persist()

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

    def _persist(self) -> None:
        """Write the file, or mark the store dirty and raise. Call with the lock held."""
        try:
            self._write()
        except OSError as exc:
            self._dirty = True
            raise StoreWriteError(f"can't write {self._path}: {exc}") from exc
        self._dirty = False

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
