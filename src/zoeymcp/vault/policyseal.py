"""The managed policy's revisions, its head and its anchor, sealed (M6 design D.2; Q6 (b), Q40).
Pure: the caller gives the nonce and the salt, so each seal is a function of its inputs.

A **revision** file is canonical JSON: a clear header (the deployment, the revision number, its
parent's digest, when, the write's origin and kind, its author, the revision it was planned on, a
rollback's target, an acknowledgment's jump, and ``body_digest``), the **body** encrypted with
AES-256-GCM under ``K_policy`` with a 12-byte nonce, the master key's ID, and an HMAC-SHA256 under
``K_config`` of every other field, ciphertext and key ID included. The plaintext body
(:func:`make_body`) holds a random 32-byte salt, the policy as ``normalize`` writes it (D.5), the
ratchet after the write (an object this module doesn't read), the seed's digest and the host's
optional reason. The salt makes ``body_digest`` useless for confirming a guessed policy (E-10), and
since it is fixed for the revision's life the digest survives a re-seal.

A revision's **digest** (:func:`revision_digest`) is ``canonical.digest`` of its header alone: it
names the content and the chain position, and a re-seal under a new master key (D.7), which
changes only the nonce, the ciphertext, the key ID and the MAC, leaves it, every ``parent`` and the
head's ``digest`` as they were. The body's associated data is ``zoeymcp/policy-body/v1`` and that
digest, which binds the ciphertext to its header.

The **head** names the newest committed revision with its digest, and the oldest revision kept with
its parent's digest (D.8). The **anchor**, beside the store, names the highest revision ever
committed (0 while a seed hasn't committed), a head a declarative start parked (F.4) and the master
key a finished rotation retired (D.7, T-13). Each is MAC'd under ``K_config`` with its own context
line, as the gateway-key state is.

Unsealing checks, in order, the size and the strict JSON (``unreadable``), the exact field set and
the key ID's and MAC's form (``not_a_revision``), the master key (``key_unknown``: neither the
current one nor ``ZOEYMCP_MASTER_KEY_PREVIOUS``), the MAC, compared with ``hmac.compare_digest``
(``tampered``), every field's form (``not_a_revision``), and for a revision the deployment it
should belong to (``deployment``) and the body: its decryption, its digest and its form
(``body``). What a verified file means for the start is ``policystart``'s (D.6), which reads the
master key each file names to refuse a retired one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidTag

from ..common.canonical import JSONRejected, digest, dumps_canonical, loads_strict
from ..common.logs import refuse_type
from .keys import POLICY_NONCE_BYTES, KeySet

Reason = Literal["unreadable", "not_a_revision", "key_unknown", "tampered", "deployment", "body"]

VERSION: Final = 1
# The highest revision number: the ten-digit file names and the portal's PARAMS hold it (T-4).
# vault/statusreport.py bounds a witness's claims by it too.
REVISION_MAX: Final = 9_999_999_999
# The canonical plaintext body, and a whole revision file (N.4).
REVISION_BODY_MAX: Final = 1_048_576
REVISION_FILE_MAX: Final = 2_097_152
HEAD_MAX: Final = 4096
ANCHOR_MAX: Final = 4096
SALT_BYTES: Final = 32
# The host's optional --reason, in printable characters.
REASON_MAX: Final = 200

# Each keeps its MAC or its associated data apart from anything else the same key covers.
BODY_CONTEXT: Final = b"zoeymcp/policy-body/v1\n"
REVISION_CONTEXT: Final = b"zoeymcp/policy-revision/v1\n"
HEAD_CONTEXT: Final = b"zoeymcp/policy-head/v1\n"
ANCHOR_CONTEXT: Final = b"zoeymcp/policy-anchor/v1\n"

ORIGINS: Final = frozenset(
    {"seed", "save", "rollback", "import", "resume", "reseed", "acknowledge"}
)
# The portal's action kinds, then the host's commands.
KINDS: Final = frozenset(
    {
        "policy.save",
        "tool.repin",
        "tool.allow",
        "client.servers",
        "policy.rollback",
        "connector.limits",
        "policy.import",
        "policy.seed",
        "policy.resume",
        "policy.reseed",
        "policy.acknowledge",
    }
)
# The kinds each origin writes: a save is one of the portal's changes, and every other origin is
# its one command (D.2).
ORIGIN_KINDS: Final[Mapping[str, frozenset[str]]] = {
    "save": frozenset(
        {"policy.save", "tool.repin", "tool.allow", "client.servers", "connector.limits"}
    ),
    **{origin: frozenset({f"policy.{origin}"}) for origin in ORIGINS - {"save"}},
}
# How a host write came: over the admin socket, offline with --state, or a resume's source (F.4).
VIAS: Final = frozenset({"socket", "offline", "source"})

HEADER_FIELDS: Final = frozenset(
    {
        "v",
        "deployment",
        "revision",
        "parent",
        "created",
        "origin",
        "kind",
        "author",
        "base",
        "target",
        "jumped_from",
        "body_digest",
    }
)
REVISION_FIELDS: Final = HEADER_FIELDS | {"body", "key_id", "mac"}
SEALED_FIELDS: Final = frozenset({"nonce", "ciphertext"})
BODY_FIELDS: Final = frozenset({"salt", "policy", "ratchet", "seed", "reason"})
HEAD_FIELDS: Final = frozenset(
    {"v", "deployment", "revision", "digest", "oldest", "oldest_parent", "key_id", "mac"}
)
ANCHOR_FIELDS: Final = frozenset(
    {"v", "deployment", "highest", "parked", "retired_key_id", "key_id", "mac"}
)

_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
_DEPLOYMENT: Final = re.compile(r"[0-9a-f]{32}")
# A master key's ID, and a passkey's fingerprint.
_ID: Final = re.compile(r"[0-9a-f]{16}")
_MAC: Final = re.compile(r"[0-9a-f]{64}")


class SealRefused(ValueError):
    """A file that can't be used. ``reason`` is one of :data:`Reason`; ``key_id`` names the master
    key of a ``key_unknown`` file, for the recoveries the start names."""

    def __init__(self, reason: Reason, detail: str, key_id: str | None = None) -> None:
        super().__init__(detail)
        self.reason: Reason = reason
        self.detail = detail
        self.key_id = key_id


@dataclass(frozen=True)
class Body:
    """A revision's plaintext body, parsed. Its ``repr`` shows nothing: even the seed's digest,
    unsalted, would confirm a guessed policy (E-10)."""

    salt: bytes = field(repr=False)
    policy: Mapping[str, Any] = field(repr=False)
    ratchet: Mapping[str, Any] = field(repr=False)
    seed_digest: str = field(repr=False)
    reason: str | None = field(repr=False)


@dataclass(frozen=True)
class Unsealed:
    """A verified revision: its header (``body_digest`` included), its digest, the ID of the master
    key that verified it, its body parsed, and the plaintext, which a re-seal encrypts again."""

    header: Mapping[str, Any]
    digest: str
    key_id: str
    body: Body
    plaintext: bytes = field(repr=False)

    @property
    def revision(self) -> int:
        number: int = self.header["revision"]
        return number


@dataclass(frozen=True)
class Head:
    """``head.json``: the newest committed revision and its digest, the oldest kept and its
    parent's digest (D.8), and the master key it is sealed under."""

    deployment: str
    revision: int
    digest: str
    oldest: int
    oldest_parent: str | None
    key_id: str


@dataclass(frozen=True)
class Anchor:
    """``policy-anchor.json``: the highest revision ever committed, a parked head (F.4), the master
    key a finished rotation retired (T-13), and the master key it is sealed under."""

    deployment: str
    highest: int
    parked: int | None
    retired_key_id: str | None
    key_id: str


refuse_type(Body)
refuse_type(Unsealed)
refuse_type(Anchor)


# --- forms -----------------------------------------------------------------------------------


def _integer(value: Any) -> bool:
    return type(value) is int


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _number(value: Any, low: int, high: int) -> bool:
    return _integer(value) and low <= value <= high


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: Any) -> bytes | None:
    """Standard base64 with padding, in its one canonical spelling, or ``None``."""
    if not isinstance(value, str):
        return None
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return data if _b64(data) == value else None


def _author(value: Any) -> bool:
    """``{"by": "passkey", "fingerprint"}``, ``{"by": "host", "via"}`` or ``{"by": "seed"}``."""
    if not isinstance(value, dict):
        return False
    by = value.get("by")
    if by == "passkey":
        return set(value) == {"by", "fingerprint"} and _matches(_ID, value["fingerprint"])
    if by == "host":
        via = value.get("via")
        return set(value) == {"by", "via"} and isinstance(via, str) and via in VIAS
    return value == {"by": "seed"}


def _header(header: Mapping[str, Any]) -> bool:
    if set(header) != HEADER_FIELDS:
        return False
    revision, parent = header["revision"], header["parent"]
    origin, kind = header["origin"], header["kind"]
    if not (_number(header["v"], VERSION, VERSION) and _number(revision, 1, REVISION_MAX)):
        return False
    if not (isinstance(origin, str) and origin in ORIGINS):
        return False
    # Each revision names its parent's digest (Y4), but revision 1 and a reseed (F.3) have none.
    if (revision == 1 or origin == "reseed") != (parent is None):
        return False
    if parent is not None and not _matches(_DIGEST, parent):
        return False
    # target is a rollback's source, which every rollback names; jumped_from only
    # acknowledge-restore's (K.3) jump, which --baseline-only leaves out (F.5).
    if (header["target"] is not None) != (origin == "rollback"):
        return False
    if header["jumped_from"] is not None and origin != "acknowledge":
        return False
    if not (isinstance(kind, str) and kind in ORIGIN_KINDS[origin]):
        return False
    # The vault writes the seed itself, as revision 1 on a fresh volume, and nothing else (F.3).
    seed = origin == "seed"
    if (header["author"] == {"by": "seed"}) != seed or (seed and revision != 1):
        return False
    # base, target and jumped_from each name an earlier revision.
    earlier = (header[name] for name in ("base", "target", "jumped_from"))
    return (
        _matches(_DEPLOYMENT, header["deployment"])
        # The canonical form bounds it above.
        and _integer(header["created"])
        and header["created"] >= 0
        and _author(header["author"])
        and all(value is None or _number(value, 1, revision - 1) for value in earlier)
        and _matches(_DIGEST, header["body_digest"])
    )


def _body(data: bytes) -> Body | None:
    """The body ``data`` holds, or ``None`` unless it is one, canonical, in at most 1 MiB."""
    try:
        document = loads_strict(data, max_bytes=REVISION_BODY_MAX)
    except JSONRejected:
        return None
    if not isinstance(document, dict) or set(document) != BODY_FIELDS:
        return None
    salt, policy, ratchet = _unb64(document["salt"]), document["policy"], document["ratchet"]
    seed, reason = document["seed"], document["reason"]
    if salt is None or len(salt) != SALT_BYTES:
        return None
    if not (isinstance(policy, dict) and isinstance(ratchet, dict) and isinstance(seed, dict)):
        return None
    if set(seed) != {"digest"} or not _matches(_DIGEST, seed["digest"]):
        return None
    if reason is not None and not (
        isinstance(reason, str) and 1 <= len(reason) <= REASON_MAX and reason.isprintable()
    ):
        return None
    # One spelling per body, so its digest names its content.
    if dumps_canonical(document) != data:
        return None
    return Body(salt, policy, ratchet, seed["digest"], reason)


def _head(document: Mapping[str, Any]) -> bool:
    revision, oldest, parent = document["revision"], document["oldest"], document["oldest_parent"]
    return (
        _number(document["v"], VERSION, VERSION)
        and _matches(_DEPLOYMENT, document["deployment"])
        and _number(revision, 1, REVISION_MAX)
        and _matches(_DIGEST, document["digest"])
        and _number(oldest, 1, revision)
        # Revision 1 has no parent; a later oldest has one, unless it is a reseed's (F.3).
        and (parent is None or (oldest > 1 and _matches(_DIGEST, parent)))
    )


def _anchor(document: Mapping[str, Any]) -> bool:
    highest, parked, retired = document["highest"], document["parked"], document["retired_key_id"]
    return (
        _number(document["v"], VERSION, VERSION)
        and _matches(_DEPLOYMENT, document["deployment"])
        and _number(highest, 0, REVISION_MAX)
        and (parked is None or _number(parked, 1, highest))
        and (retired is None or _matches(_ID, retired))
    )


# --- the MAC -----------------------------------------------------------------------------------


def _mac(context: bytes, document: Mapping[str, Any], keys: KeySet) -> str:
    return keys.config_mac.mac(context, dumps_canonical(dict(document))).hex()


def _sealed(context: bytes, document: dict[str, Any], keys: KeySet) -> bytes:
    document["key_id"] = keys.key_id
    document["mac"] = _mac(context, document, keys)
    return dumps_canonical(document) + b"\n"


def _verified(
    data: bytes,
    what: str,
    sizes: tuple[int, frozenset[str], bytes],
    keys: KeySet,
    previous: KeySet | None,
) -> tuple[dict[str, Any], KeySet]:
    """The document ``data`` holds and the master key whose MAC it carries. ``sizes`` is the
    file's size cap, its field set and its MAC context."""
    max_bytes, fields, context = sizes
    try:
        document = loads_strict(data, max_bytes=max_bytes)
    except JSONRejected as exc:
        raise SealRefused("unreadable", f"isn't {what}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != fields:
        raise SealRefused("not_a_revision", f"isn't {what}")
    key_id, mac = document["key_id"], document["mac"]
    if not (_matches(_ID, key_id) and _matches(_MAC, mac)):
        raise SealRefused("not_a_revision", f"isn't {what}")
    if key_id == keys.key_id:
        signer = keys
    elif previous is not None and key_id == previous.key_id:
        signer = previous
    else:
        raise SealRefused(
            "key_unknown",
            f"was written under master key ID {key_id}, which is neither ZOEYMCP_MASTER_KEY "
            "nor ZOEYMCP_MASTER_KEY_PREVIOUS",
            key_id,
        )
    rest = {name: value for name, value in document.items() if name != "mac"}
    if not hmac.compare_digest(mac, _mac(context, rest, signer)):
        raise SealRefused("tampered", "was tampered with, or written under another master key")
    return document, signer


# --- revisions ---------------------------------------------------------------------------------


def body_digest(body: bytes) -> str:
    """``sha256:<hex>`` of a plaintext body, as a revision's ``body_digest`` names it."""
    return "sha256:" + hashlib.sha256(body).hexdigest()


def make_body(
    *,
    salt: bytes,
    policy: Mapping[str, Any],
    ratchet: Mapping[str, Any],
    seed_digest: str,
    reason: str | None,
) -> bytes:
    """A revision's canonical plaintext body. ``salt`` is 32 fresh random bytes, made once per
    revision. Raises ``ValueError`` for anything :func:`unseal_revision` would refuse."""
    document = {
        "salt": _b64(salt),
        "policy": dict(policy),
        "ratchet": dict(ratchet),
        "seed": {"digest": seed_digest},
        "reason": reason,
    }
    data = dumps_canonical(document)
    if _body(data) is None:
        raise ValueError(
            "a revision body is a 32-byte salt, a policy, a ratchet, a seed digest and a reason "
            f"of 1 to {REASON_MAX} printable characters or none, in at most 1 MiB"
        )
    return data


def revision_digest(header: Mapping[str, Any]) -> str:
    """The digest of a revision: ``canonical.digest`` of its header fields alone, so a re-seal
    keeps it. ``header`` may hold the other fields too. Raises ``ValueError`` without them all."""
    if not set(header) >= HEADER_FIELDS:
        raise ValueError("a revision header needs every field of HEADER_FIELDS")
    return digest({name: header[name] for name in HEADER_FIELDS})


def seal_revision(header: Mapping[str, Any], body: bytes, *, keys: KeySet, nonce: bytes) -> bytes:
    """A revision file's bytes: ``body`` (from :func:`make_body`) encrypted under ``keys`` with
    ``nonce`` (12 fresh random bytes), and the header, whose ``body_digest`` must be the body's.

    Raises ``ValueError`` for a revision above :data:`REVISION_MAX` (T-4), a header or a body
    :func:`unseal_revision` would refuse, or a nonce that isn't 12 bytes.
    """
    revision = header.get("revision")
    if type(revision) is int and revision > REVISION_MAX:
        raise ValueError("a revision can't go above 9,999,999,999")
    if not _header(header):
        raise ValueError("isn't a revision header")
    if _body(body) is None:
        raise ValueError("isn't a revision body")
    if header["body_digest"] != body_digest(body):
        raise ValueError("body_digest isn't the body's digest")
    document = dict(header)
    associated = BODY_CONTEXT + revision_digest(header).encode("ascii")
    ciphertext = keys.policy_key.encrypt(nonce, body, associated)
    document["body"] = {"nonce": _b64(nonce), "ciphertext": _b64(ciphertext)}
    return _sealed(REVISION_CONTEXT, document, keys)


def unseal_revision(
    data: bytes, keys: KeySet, previous: KeySet | None, *, deployment: str | None
) -> Unsealed:
    """Read a revision file, verified under the master key it names (``keys``, or ``previous``
    during a rotation), from ``deployment`` unless that is ``None``. Raises :class:`SealRefused`."""
    sizes = (REVISION_FILE_MAX, REVISION_FIELDS, REVISION_CONTEXT)
    document, signer = _verified(data, "a policy revision", sizes, keys, previous)
    header = {name: document[name] for name in HEADER_FIELDS}
    sealed = document["body"]
    if not (_header(header) and isinstance(sealed, dict) and set(sealed) == SEALED_FIELDS):
        raise SealRefused("not_a_revision", "isn't a policy revision")
    nonce, ciphertext = _unb64(sealed["nonce"]), _unb64(sealed["ciphertext"])
    if nonce is None or len(nonce) != POLICY_NONCE_BYTES or ciphertext is None:
        raise SealRefused("not_a_revision", "isn't a policy revision")
    if deployment is not None and header["deployment"] != deployment:
        raise SealRefused(
            "deployment", f"belongs to deployment {header['deployment'][:8]}, not {deployment[:8]}"
        )
    name = revision_digest(header)
    try:
        plaintext = signer.policy_key.decrypt(nonce, ciphertext, BODY_CONTEXT + name.encode())
    except InvalidTag as exc:
        raise SealRefused("body", "its body doesn't decrypt") from exc
    body = _body(plaintext)
    if not hmac.compare_digest(body_digest(plaintext), header["body_digest"]) or body is None:
        raise SealRefused("body", "its body isn't the one its header names")
    return Unsealed(header, name, signer.key_id, body, plaintext)


# --- the head and the anchor -------------------------------------------------------------------


def seal_head(head: Head, keys: KeySet) -> bytes:
    """``head.json``'s bytes. ``keys`` must be the head's master key. Raises ``ValueError`` for a
    head :func:`unseal_head` would refuse."""
    if keys.key_id != head.key_id:
        raise ValueError("the head must be sealed under its own master key")
    document: dict[str, Any] = {
        "v": VERSION,
        "deployment": head.deployment,
        "revision": head.revision,
        "digest": head.digest,
        "oldest": head.oldest,
        "oldest_parent": head.oldest_parent,
    }
    if not _head(document):
        raise ValueError("isn't a policy head")
    return _sealed(HEAD_CONTEXT, document, keys)


def unseal_head(data: bytes, keys: KeySet, previous: KeySet | None) -> Head:
    """Read ``head.json``, verified under the master key it names. Raises :class:`SealRefused`."""
    sizes = (HEAD_MAX, HEAD_FIELDS, HEAD_CONTEXT)
    document, signer = _verified(data, "a policy head", sizes, keys, previous)
    if not _head(document):
        raise SealRefused("not_a_revision", "isn't a policy head")
    return Head(
        deployment=document["deployment"],
        revision=document["revision"],
        digest=document["digest"],
        oldest=document["oldest"],
        oldest_parent=document["oldest_parent"],
        key_id=signer.key_id,
    )


def seal_anchor(anchor: Anchor, keys: KeySet) -> bytes:
    """``policy-anchor.json``'s bytes. ``keys`` must be the anchor's master key. Raises
    ``ValueError`` for an anchor :func:`unseal_anchor` would refuse.

    ``parked`` is at most ``highest``: a park (F.4) that finds the head at ``highest + 1`` (a crash
    between D.9's steps 2 and 3) writes ``highest = max(highest, parked)``, D.6 row 13's repair.
    """
    if keys.key_id != anchor.key_id:
        raise ValueError("the anchor must be sealed under its own master key")
    document: dict[str, Any] = {
        "v": VERSION,
        "deployment": anchor.deployment,
        "highest": anchor.highest,
        "parked": anchor.parked,
        "retired_key_id": anchor.retired_key_id,
    }
    if not _anchor(document):
        raise ValueError("isn't a policy anchor")
    return _sealed(ANCHOR_CONTEXT, document, keys)


def unseal_anchor(data: bytes, keys: KeySet, previous: KeySet | None) -> Anchor:
    """Read ``policy-anchor.json``, verified under the master key it names. Raises
    :class:`SealRefused`."""
    sizes = (ANCHOR_MAX, ANCHOR_FIELDS, ANCHOR_CONTEXT)
    document, signer = _verified(data, "a policy anchor", sizes, keys, previous)
    if not _anchor(document):
        raise SealRefused("not_a_revision", "isn't a policy anchor")
    return Anchor(
        deployment=document["deployment"],
        highest=document["highest"],
        parked=document["parked"],
        retired_key_id=document["retired_key_id"],
        key_id=signer.key_id,
    )
