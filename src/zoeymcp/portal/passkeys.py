"""The passkey file (M5 design D.4): its format, its MAC, the transitions, and the holder.

``<state>/portal/passkeys.json`` holds the operator's user handle and every enrolled credential,
as canonical JSON MAC'd under ``K_portal``, so a writer of ``/state`` without the master key can't
add a passkey or change a counter (T16). It can still restore an older file that verifies, which
brings back removed passkeys; ``generation`` rises on every write and is logged at start, so a
restore shows as a lower number (D-62).

The transitions are pure functions of a :class:`PasskeyFile`: each returns a new one, the same one
when nothing changes, or a :class:`Refusal`. :class:`Passkeys` holds the file in a running vault and
writes before each change takes effect: enrolment, rename, removal and reset write the new file
first, and only then change memory, so a failed write changes nothing. After a login or step-up,
:meth:`Passkeys.touch` keeps the counter even if its write fails, because the login stands.

A file that can't be read, parsed or verified makes the holder *unavailable*: the portal refuses
logins, enrolments and actions (503 ``unavailable``) until an enrolment with a ``--reset`` setup
code moves the file aside and writes a fresh one. The proxy doesn't read this file (P21).
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final, Literal

from ..common import files
from ..common.canonical import JSONRejected, dumps_canonical, loads_strict
from ..common.textrules import find_violations
from ..vault import logs
from ..vault.keys import PortalKey
from .webauthn import (
    ALGORITHMS,
    MAX_CREDENTIAL_ID,
    MAX_PASSKEYS,
    MAX_PUBLIC_KEY,
    TRANSPORTS,
    Asserted,
    NewCredential,
    b64url,
    b64url_decode,
)

DIRECTORY: Final = "portal"
FILE: Final = "passkeys.json"
VERSION: Final = 1
# A larger file is refused unread.
MAX_FILE_BYTES: Final = 128 * 1024
MAX_NAME: Final = 64
USER_HANDLE_BYTES: Final = 32
FINGERPRINT_HEX: Final = 16
# last_used and last_regressed are kept to the day.
DAY: Final = 86400
MAX_SIGN_COUNT: Final = 2**32 - 1
# Each keeps its MAC apart from anything else K_portal authenticates.
_MAC_CONTEXT: Final = b"zoeymcp/passkeys/v1\n"
_FINGERPRINT_CONTEXT: Final = b"zoeymcp/passkey-fp/v1\n"
_KEY_ID: Final = re.compile(r"[0-9a-f]{16}")
_FIELDS: Final = frozenset({"v", "key_id", "generation", "user_handle", "credentials", "mac"})
_RECORD_FIELDS: Final = frozenset(
    {
        "id",
        "rp_id",
        "alg",
        "public_key",
        "sign_count",
        "backup_eligible",
        "backup_state",
        "transports",
        "name",
        "via",
        "origin",
        "created",
        "last_used",
        "last_regressed",
    }
)

# How a passkey was enrolled: with a setup code, a --reset one, or from a full session.
Via = Literal["setup_code", "setup_code_reset", "portal"]
VIAS: Final[tuple[Via, ...]] = ("setup_code", "setup_code_reset", "portal")
Reason = Literal[
    "unavailable",
    "bad_name",
    "duplicate_credential",
    "too_many_passkeys",
    "not_found",
    "ambiguous_fingerprint",
    "last_passkey",
    "not_written",
]


class PasskeyFileError(Exception):
    """The file can't be used. ``reason`` is logged; the message is safe to print."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class PasskeyError(Exception):
    """A change the holder refused or couldn't write, with a stable ``reason`` (M.2)."""

    def __init__(self, reason: Reason) -> None:
        super().__init__(reason)
        self.reason: Reason = reason


@dataclass(frozen=True)
class Refusal:
    reason: Reason


@dataclass(frozen=True)
class Passkey:
    """One enrolled credential (D.4). It is a :class:`~.webauthn.CredentialRecord`: ``spki`` is
    the file's ``public_key``. Times are Unix seconds; ``last_used`` and ``last_regressed`` (the
    last day its counter didn't rise) are kept to the day, and None until it happens."""

    id: bytes = field(repr=False)
    rp_id: str
    alg: int
    spki: bytes = field(repr=False)
    sign_count: int
    backup_eligible: bool
    backup_state: bool
    transports: tuple[str, ...]
    name: str = field(repr=False)
    via: Via
    origin: str
    created: int
    last_used: int | None = None
    last_regressed: int | None = None


@dataclass(frozen=True)
class PasskeyFile:
    """The file's content: its generation, the operator's user handle, and the credentials in the
    order they were enrolled. Generation 0 is a file never written."""

    generation: int
    user_handle: bytes = field(repr=False)
    credentials: tuple[Passkey, ...] = ()

    def get(self, credential_id: bytes) -> Passkey | None:
        return next((c for c in self.credentials if c.id == credential_id), None)

    @property
    def last_regressed(self) -> int | None:
        """The latest day any counter went back (I.1's ``passkey_counter``), or None."""
        days = [c.last_regressed for c in self.credentials if c.last_regressed is not None]
        return max(days, default=None)


# --- names and fingerprints ---------------------------------------------------------------------


def check_name(name: object) -> bool:
    """1 to 64 code points on one line, with no hidden characters and no tabs (D.4): a single
    line refuses tabs too."""
    return isinstance(name, str) and not find_violations(
        name, max_chars=MAX_NAME, min_chars=1, single_line=True
    )


def fingerprint(key: PortalKey, credential_id: bytes) -> str:
    """The first 16 hex of a keyed hash of the credential ID. Registration is unattested, so an
    enroller chooses its ID; without the master key it can't make one that shows as another's."""
    return key.mac(_FINGERPRINT_CONTEXT + credential_id).hex()[:FINGERPRINT_HEX]


def find(document: PasskeyFile, key: PortalKey, wanted: str) -> Passkey | Refusal:
    """The one credential with this fingerprint. Two with the same one are refused, so a removal
    never takes a credential other than the one shown."""
    found = [c for c in document.credentials if fingerprint(key, c.id) == wanted]
    if not found:
        return Refusal("not_found")
    if len(found) > 1:
        return Refusal("ambiguous_fingerprint")
    return found[0]


# --- the transitions ----------------------------------------------------------------------------


def new_file(user_handle: bytes) -> PasskeyFile:
    """No passkeys yet. The user handle is made before the first enrolment, whose options carry
    it, and written with it."""
    return PasskeyFile(generation=0, user_handle=user_handle)


def _day(now: float) -> int:
    return int(now) // DAY * DAY


def _next(document: PasskeyFile, credentials: tuple[Passkey, ...]) -> PasskeyFile:
    return replace(document, generation=document.generation + 1, credentials=credentials)


def _record(new: NewCredential, name: str, via: Via, origin: str, now: float) -> Passkey:
    return Passkey(
        id=new.id,
        rp_id=new.rp_id,
        alg=new.alg,
        spki=new.spki,
        sign_count=new.sign_count,
        backup_eligible=new.backup_eligible,
        backup_state=new.backup_state,
        transports=new.transports,
        name=name,
        via=via,
        origin=origin,
        created=int(now),
    )


def add(
    document: PasskeyFile,
    new: NewCredential,
    *,
    name: str,
    via: Literal["setup_code", "portal"],
    origin: str,
    now: float,
) -> PasskeyFile | Refusal:
    """Enrol ``new``, verified on ``origin``. The verifier checked the last two refusals when the
    ceremony finished; they are checked again here, against the file as it is now."""
    if not check_name(name):
        return Refusal("bad_name")
    if document.get(new.id) is not None:
        return Refusal("duplicate_credential")
    if len(document.credentials) >= MAX_PASSKEYS:
        return Refusal("too_many_passkeys")
    record = _record(new, name, via, origin, now)
    return _next(document, (*document.credentials, record))


def reset_with(
    document: PasskeyFile, new: NewCredential, *, name: str, origin: str, now: float
) -> PasskeyFile | Refusal:
    """Remove every credential and enrol ``new`` (a ``--reset`` setup code). The user handle is
    kept, so the new credential replaces an old one on the same authenticator."""
    if not check_name(name):
        return Refusal("bad_name")
    return _next(document, (_record(new, name, "setup_code_reset", origin, now),))


def rename(document: PasskeyFile, credential_id: bytes, name: str) -> PasskeyFile | Refusal:
    """Give a credential a new name. Names needn't be unique: the list shows fingerprints."""
    if not check_name(name):
        return Refusal("bad_name")
    current = document.get(credential_id)
    if current is None:
        return Refusal("not_found")
    if current.name == name:
        return document
    renamed = replace(current, name=name)
    return _next(document, tuple(renamed if c is current else c for c in document.credentials))


def remove(
    document: PasskeyFile, credential_id: bytes, *, allow_last: bool = False
) -> PasskeyFile | Refusal:
    """Remove a credential. The portal can't remove the last one (``allow_last`` False): that
    would lock the operator out. The admin socket may, since host access is the recovery path."""
    if document.get(credential_id) is None:
        return Refusal("not_found")
    if len(document.credentials) == 1 and not allow_last:
        return Refusal("last_passkey")
    return _next(document, tuple(c for c in document.credentials if c.id != credential_id))


def touch(document: PasskeyFile, asserted: Asserted, now: float) -> PasskeyFile:
    """Apply a login or step-up that passed every check: the counter (never lower than stored),
    the backup state, the day it was used and, for a counter that didn't rise, the day of that.
    The same file when nothing changes, so a synced passkey's logins write once a day at most."""
    current = document.get(asserted.credential_id)
    if current is None:
        return document  # removed since the ceremony began
    day = _day(now)
    updated = replace(
        current,
        sign_count=max(current.sign_count, asserted.sign_count),
        backup_state=asserted.backup_state and current.backup_eligible,
        last_used=day,
        last_regressed=day if asserted.regressed else current.last_regressed,
    )
    if updated == current:
        return document
    return _next(document, tuple(updated if c is current else c for c in document.credentials))


# --- the file -----------------------------------------------------------------------------------


def _record_json(passkey: Passkey) -> dict[str, Any]:
    return {
        "id": b64url(passkey.id),
        "rp_id": passkey.rp_id,
        "alg": passkey.alg,
        "public_key": b64url(passkey.spki),
        "sign_count": passkey.sign_count,
        "backup_eligible": passkey.backup_eligible,
        "backup_state": passkey.backup_state,
        "transports": list(passkey.transports),
        "name": passkey.name,
        "via": passkey.via,
        "origin": passkey.origin,
        "created": passkey.created,
        "last_used": passkey.last_used,
        "last_regressed": passkey.last_regressed,
    }


def _mac(document: dict[str, Any], key: PortalKey) -> str:
    return key.mac(_MAC_CONTEXT + dumps_canonical(document)).hex()


def seal(document: PasskeyFile, key: PortalKey) -> bytes:
    """The file's bytes: the content and its MAC under ``key``."""
    content: dict[str, Any] = {
        "v": VERSION,
        "key_id": key.key_id,
        "generation": document.generation,
        "user_handle": b64url(document.user_handle),
        "credentials": [_record_json(c) for c in document.credentials],
    }
    content["mac"] = _mac(content, key)
    return dumps_canonical(content) + b"\n"


def _is_int(value: object, low: int = 0, high: int | None = None) -> bool:
    return type(value) is int and value >= low and (high is None or value <= high)


def _is_bool(value: object) -> bool:
    return type(value) is bool


def _is_text(value: object) -> bool:
    return isinstance(value, str) and value != ""


def _bytes(value: object, low: int, high: int) -> bytes | None:
    """Strict base64url of ``low`` to ``high`` bytes, or None."""
    if not isinstance(value, str):
        return None
    try:
        data = b64url_decode(value)
    except ValueError:
        return None
    return data if low <= len(data) <= high else None


def _parse_record(value: object) -> Passkey | None:
    """A credential a MAC-verified file holds, or None if it isn't consistent."""
    if not isinstance(value, dict) or value.keys() != _RECORD_FIELDS:
        return None
    credential_id = _bytes(value["id"], 1, MAX_CREDENTIAL_ID)
    spki = _bytes(value["public_key"], 1, MAX_PUBLIC_KEY)
    transports = value["transports"]
    if not (
        credential_id is not None
        and spki is not None
        and _is_text(value["rp_id"])
        and type(value["alg"]) is int
        and value["alg"] in ALGORITHMS
        and _is_int(value["sign_count"], high=MAX_SIGN_COUNT)
        and _is_bool(value["backup_eligible"])
        and _is_bool(value["backup_state"])
        and (value["backup_eligible"] or not value["backup_state"])
        and isinstance(transports, list)
        and all(isinstance(t, str) and t in TRANSPORTS for t in transports)
        and transports == sorted(set(transports))
        and check_name(value["name"])
        and value["via"] in VIAS
        and _is_text(value["origin"])
        and _is_int(value["created"])
        and (value["last_used"] is None or _is_int(value["last_used"]))
        and (value["last_regressed"] is None or _is_int(value["last_regressed"]))
    ):
        return None
    return Passkey(
        id=credential_id,
        rp_id=value["rp_id"],
        alg=value["alg"],
        spki=spki,
        sign_count=value["sign_count"],
        backup_eligible=value["backup_eligible"],
        backup_state=value["backup_state"],
        transports=tuple(transports),
        name=value["name"],
        via=value["via"],
        origin=value["origin"],
        created=value["created"],
        last_used=value["last_used"],
        last_regressed=value["last_regressed"],
    )


def _parse(content: dict[str, Any]) -> PasskeyFile | None:
    """The content of a MAC-verified file, or None if it isn't consistent."""
    user_handle = _bytes(content["user_handle"], USER_HANDLE_BYTES, USER_HANDLE_BYTES)
    records = content["credentials"]
    if not (
        content["v"] == VERSION
        and type(content["v"]) is int
        and _is_int(content["generation"], low=1)
        and user_handle is not None
        and isinstance(records, list)
        and len(records) <= MAX_PASSKEYS
    ):
        return None
    credentials = [_parse_record(record) for record in records]
    parsed = [c for c in credentials if c is not None]
    if len(parsed) != len(credentials) or len({c.id for c in parsed}) != len(parsed):
        return None
    return PasskeyFile(content["generation"], user_handle, tuple(parsed))


def unseal(
    data: bytes, key: PortalKey, previous: PortalKey | None = None
) -> tuple[PasskeyFile, bool]:
    """Read the file's bytes, verifying the MAC under the master key that wrote them: ``key``,
    or ``previous`` during a master-key rotation. Returns the content and whether it was
    ``previous``, so the file is sealed again under ``key``.

    Raises :class:`PasskeyFileError`.
    """
    if len(data) > MAX_FILE_BYTES:
        raise PasskeyFileError("too_large", f"is larger than {MAX_FILE_BYTES} bytes")
    try:
        content = loads_strict(data)  # within its default limit, checked above
    except JSONRejected as exc:
        raise PasskeyFileError("not_json", f"isn't a passkey file: {exc}") from exc
    if not isinstance(content, dict) or content.keys() != _FIELDS:
        raise PasskeyFileError("shape", f"isn't a version-{VERSION} passkey file")
    key_id, mac = content["key_id"], content["mac"]
    if not (isinstance(key_id, str) and _KEY_ID.fullmatch(key_id) and isinstance(mac, str)):
        raise PasskeyFileError("shape", f"isn't a version-{VERSION} passkey file")
    if key_id == key.key_id:
        signer = key
    elif previous is not None and key_id == previous.key_id:
        signer = previous
    else:
        raise PasskeyFileError(
            "master_key",
            f"was written under master key ID {key_id}, but the master key's ID is "
            f"{key.key_id}. If you are rotating the master key, set ZOEYMCP_MASTER_KEY_PREVIOUS "
            "to the old key; otherwise run zoeymcp setup-code --reset.",
        )
    rest = {name: value for name, value in content.items() if name != "mac"}
    if not secrets.compare_digest(mac.encode(), _mac(rest, signer).encode()):
        raise PasskeyFileError(
            "mac", "was changed, or written under another master key: it can't be verified"
        )
    document = _parse(rest)
    if document is None:
        raise PasskeyFileError("inconsistent", f"isn't a consistent version-{VERSION} passkey file")
    return document, signer is not key


def write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` with ``data`` (mode 0600), so a crash leaves the old file or the new."""
    files.write_atomic(path, data, prefix=".passkeys-")


def rejected_name(now: float) -> str:
    """Where a file that failed to verify goes when a ``--reset`` enrolment replaces it."""
    return f"passkeys.rejected-{int(now * 1000)}.json"


# --- the file in a running vault ----------------------------------------------------------------


def _applied(result: PasskeyFile | Refusal) -> PasskeyFile:
    if isinstance(result, Refusal):
        raise PasskeyError(result.reason)
    return result


class Passkeys:
    """The vault's passkeys, kept in ``<state>/portal/passkeys.json``.

    Every change but :meth:`touch` is written before it takes effect and raises
    :class:`PasskeyError` (``not_written``) if it can't be, leaving memory as it was. The caller
    then ends the sessions a removal or reset ends, logs, and answers (N.2). Writes take a lock.
    """

    def __init__(
        self,
        document: PasskeyFile,
        key: PortalKey,
        path: Path,
        *,
        unavailable: bool = False,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._document = document
        self._key = key
        self._path = path
        self._unavailable = unavailable
        self._clock = clock
        self._lock = threading.Lock()
        self._dirty = False

    @classmethod
    def load(
        cls,
        state_dir: Path,
        key: PortalKey,
        previous: PortalKey | None = None,
        *,
        clock: Callable[[], float] = time.time,
        random: Callable[[int], bytes] = secrets.token_bytes,
    ) -> Passkeys:
        """Read the file at startup. Never raises: a missing file is no passkeys, and one that
        can't be read or verified makes the holder unavailable (``passkey_store_tampered``). A
        file verified under the previous master key is sealed again under the current one."""
        path = state_dir / DIRECTORY / FILE
        fresh = new_file(random(USER_HANDLE_BYTES))
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
            document, reseal = unseal(data, key, previous)
        except FileNotFoundError:
            holder = cls(fresh, key, path, clock=clock)
        except (OSError, PasskeyFileError) as exc:
            reason = exc.reason if isinstance(exc, PasskeyFileError) else "unreadable"
            logs.event("passkey_store_tampered", level="critical", reason=reason)
            return cls(fresh, key, path, unavailable=True, clock=clock)
        else:
            holder = cls(document, key, path, clock=clock)
            if reseal:
                holder._document = _next(document, document.credentials)
                holder._save()
        document = holder._document
        logs.event(
            "passkeys_loaded", count=len(document.credentials), generation=document.generation
        )
        return holder

    @property
    def document(self) -> PasskeyFile:
        return self._document

    @property
    def unavailable(self) -> bool:
        """The file failed to read or verify: nothing but a reset enrolment is allowed."""
        return self._unavailable

    @property
    def dirty(self) -> bool:
        """Memory holds a counter the file doesn't, because a write failed."""
        return self._dirty

    @property
    def user_handle(self) -> bytes:
        return self._document.user_handle

    def fingerprint(self, credential_id: bytes) -> str:
        return fingerprint(self._key, credential_id)

    def find(self, wanted: str) -> Passkey:
        """The credential with this fingerprint. Raises ``not_found`` or
        ``ambiguous_fingerprint``."""
        self._usable()
        result = find(self._document, self._key, wanted)
        if isinstance(result, Refusal):
            raise PasskeyError(result.reason)
        return result

    def add(
        self,
        new: NewCredential,
        *,
        name: str,
        via: Literal["setup_code", "portal"],
        origin: str,
    ) -> Passkey:
        """Enrol ``new``. Returns its record."""
        with self._lock:
            self._usable()
            document = _applied(
                add(self._document, new, name=name, via=via, origin=origin, now=self._clock())
            )
            self._commit(document)
            return document.credentials[-1]

    def reset_with(self, new: NewCredential, *, name: str, origin: str) -> tuple[Passkey, ...]:
        """Replace every credential with ``new`` (a ``--reset`` setup code); the one way out of
        an unavailable file, which is first moved aside to :func:`rejected_name`, never
        overwritten. Returns the credentials removed."""
        with self._lock:
            removed = self._document.credentials  # none when the file was unavailable
            document = _applied(
                reset_with(self._document, new, name=name, origin=origin, now=self._clock())
            )
            if self._unavailable:
                try:
                    self._path.rename(self._path.with_name(rejected_name(self._clock())))
                except FileNotFoundError:
                    pass  # moved aside by an earlier reset whose write failed
                except OSError:
                    raise PasskeyError("not_written") from None
            self._commit(document)
            self._unavailable = False
            return removed

    def rename(self, wanted: str, name: str) -> Passkey:
        """Rename the credential with this fingerprint. Returns its new record."""
        with self._lock:
            target = self.find(wanted)
            document = _applied(rename(self._document, target.id, name))
            if document is not self._document:
                self._commit(document)
            return replace(target, name=name)

    def remove(self, wanted: str, *, allow_last: bool = False) -> Passkey:
        """Remove the credential with this fingerprint. Returns its record, so the caller ends
        the sessions it made."""
        with self._lock:
            target = self.find(wanted)
            self._commit(_applied(remove(self._document, target.id, allow_last=allow_last)))
            return target

    def touch(self, asserted: Asserted) -> None:
        """Keep what a login or step-up that passed every check changed. The login stands even if
        this can't be written: memory keeps it, ``portal_state_not_written`` is logged, and the
        next write saves it."""
        with self._lock:
            if self._unavailable:
                return
            if asserted.regressed:
                logs.event(
                    "passkey_counter_regressed",
                    level="critical",
                    credential=self.fingerprint(asserted.credential_id),
                )
            document = touch(self._document, asserted, self._clock())
            if document is self._document and not self._dirty:
                return
            self._document = document
            self._save()

    # --- internals (call with the lock held) -----------------------------------------------------

    def _usable(self) -> None:
        if self._unavailable:
            raise PasskeyError("unavailable")

    def _commit(self, document: PasskeyFile) -> None:
        """Write ``document``, then make it current."""
        try:
            write_atomic(self._path, seal(document, self._key))
        except OSError as exc:
            _not_written(exc, kept=False)
            raise PasskeyError("not_written") from None
        self._document, self._dirty = document, False

    def _save(self) -> None:
        """Write the current document; on failure keep it in memory, marked dirty."""
        try:
            write_atomic(self._path, seal(self._document, self._key))
        except OSError as exc:
            self._dirty = True
            _not_written(exc, kept=True)
        else:
            self._dirty = False


def _not_written(exc: OSError, *, kept: bool) -> None:
    logs.event(
        "portal_state_not_written",
        level="critical",
        state="passkeys",
        kept_in_memory=kept,
        error_type=type(exc).__name__,
    )
