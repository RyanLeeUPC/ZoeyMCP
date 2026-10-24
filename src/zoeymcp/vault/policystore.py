"""The managed policy's store on disk (M6 design D.1, D.7-D.9, F.4; Q6 (b), Q25, Q33-Q35; Y1, Y3,
Y4, T-13). I/O: the files' forms are ``policyseal``'s, and what a start makes of them is
``policystart.verdict``'s.

``<state>/policy/`` holds ``head.json``, the commit point, one sealed file per revision in
``revisions/`` (the newest :data:`KEEP`), and ``quarantine/``, where the files a start won't use
are moved and never read again. ``<state>/policy-anchor.json`` sits beside the directory, so
restoring or deleting the directory alone is seen (D.6). Only this module reads or writes them,
every write through ``common/files.write_atomic`` with the prefix ``.policy-``.

:meth:`PolicyStore.open`, at every start, removes leftover temporary files, reads the anchor, the
head and every revision, and takes the verdict. On a store that verifies (``Ok``) it does the
housekeeping whatever the start then decides: the uncommitted file above the head and each older
revision that fails or doesn't chain go to ``quarantine/`` (rows 12 and 14), a stray name is
logged and left alone (row 15), files below the oldest kept are removed (row 16), a master-key
rotation re-seals every kept revision still under ``ZOEYMCP_MASTER_KEY_PREVIOUS``, oldest first,
then the head, then the anchor, which records the retired key (D.7, T-13), and a stale anchor is
rewritten with ``highest`` the head's (row 13). A ``Fresh`` store's half-written seed goes to
quarantine (row 5). A refused store is left as it is.

:meth:`PolicyStore.commit` is D.9: revision ``head + 1``, then the head (the commit), then the
anchor, then the prune (D.8). A failure before the head's rename leaves nothing in effect
(``policy_write_failed``); an anchor that can't be written leaves the save committed and the anchor
dirty, so the next commit writes it first or refuses (FM-30). :meth:`PolicyStore.seed` writes the
anchor at 0 before revision 1 (FM-25); :meth:`PolicyStore.park` records the head a declarative
start parked, with ``highest`` the head's too (F.4). :meth:`PolicyStore.removed_lookup` finds in
the kept history the revision that retired a client's token or a caller's placeholder, which the
ratchet doesn't keep (E.1), for the planner's refusal texts.

Every write goes through a module-level seam (:func:`write_revision`, :func:`write_head`,
:func:`write_anchor`, :func:`move`, :func:`remove`): unit tests make them fail, and
``tests/fakes/policyholds.py`` holds a test vault right after one, for the crash tests (FM-1 to
FM-3, FM-25).
"""

from __future__ import annotations

import errno
import os
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final, Literal

from ..common import files
from ..common.logs import refuse_type
from ..common.policy.plan import WritePlan, document
from ..common.policy.ratchet import Ratchet, caller_digest
from ..common.policy.schema import PlaceholderCaller, Policy
from . import logs
from .keys import POLICY_NONCE_BYTES, KeySet
from .policyseal import (
    ANCHOR_MAX,
    HEAD_MAX,
    REVISION_FILE_MAX,
    REVISION_MAX,
    SALT_BYTES,
    VERSION,
    Anchor,
    Head,
    SealRefused,
    Unsealed,
    body_digest,
    make_body,
    revision_digest,
    seal_anchor,
    seal_head,
    seal_revision,
    unseal_anchor,
    unseal_head,
    unseal_revision,
)
from .policystart import (
    ANCHOR_FILE,
    HEAD_FILE,
    POLICY_DIR,
    QUARANTINE,
    REVISIONS,
    TEMPORARY_PREFIX,
    Fresh,
    Ok,
    StoreVerdict,
    revision_file,
    revision_number,
    verdict,
    volume_used,
)

# portal/refusals.py catalogues both (N.2).
Reason = Literal["policy_write_failed", "revision_out_of_range"]

# The revisions kept, the head's included (D.8, Q25).
KEEP: Final = 64
# The store's directories are the vault's alone (D.1).
DIRECTORY_MODE: Final = 0o700


class StoreRefused(Exception):
    """A write the store didn't make: nothing of it took effect. ``reason`` is one of
    :data:`Reason`; ``detail`` says why, without a policy value."""

    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(detail)
        self.reason: Reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Committed:
    """A committed revision: its number, its digest, and its header, which says when, how and by
    whom (G.7's first row, History). ``anchor_written`` is false when the anchor is left dirty
    (FM-30): the save stands, and the next commit writes the anchor first."""

    revision: int
    digest: str
    header: Mapping[str, Any]
    anchor_written: bool = True


# --- the seams ---------------------------------------------------------------------------------


def write_revision(path: Path, data: bytes) -> None:
    """Write a revision file: D.9 step 1, and a rotation's re-seal (D.7)."""
    files.write_atomic(path, data, prefix=TEMPORARY_PREFIX)


def write_head(path: Path, data: bytes) -> None:
    """Write ``head.json``: D.9 step 2, whose rename is the commit."""
    files.write_atomic(path, data, prefix=TEMPORARY_PREFIX)


def write_anchor(path: Path, data: bytes) -> None:
    """Write ``policy-anchor.json``: D.9 step 3, a seed's anchor at 0, a park, a rotation's end."""
    files.write_atomic(path, data, prefix=TEMPORARY_PREFIX)


def move(source: Path, target: Path) -> None:
    """Move a file into quarantine. A file already there is never replaced (``FileExistsError``):
    quarantine is kept until the operator deletes it (D.8, N.5). One process holds the state."""
    target.parent.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(errno.EEXIST, "already in quarantine", target.name)
    os.replace(source, target)


def remove(path: Path) -> None:
    """Remove a pruned revision or a leftover temporary file."""
    path.unlink(missing_ok=True)


# --- reading -----------------------------------------------------------------------------------


def _read(path: Path, cap: int) -> bytes | None:
    """At most ``cap + 1`` bytes of ``path``, so the seal refuses a larger file without it being
    read whole, or ``None`` when there is no file."""
    try:
        with path.open("rb") as handle:
            return handle.read(cap + 1)
    except FileNotFoundError:
        return None


def _unsealed(path: Path, cap: int, read: Callable[[bytes], Any]) -> Any:
    """What ``read`` makes of ``path``: its answer, its :class:`SealRefused`, or ``None`` when
    there is no file. A file that can't be read is ``unreadable``."""
    try:
        data = _read(path, cap)
    except OSError as exc:
        return SealRefused("unreadable", f"can't be read ({type(exc).__name__})")
    if data is None:
        return None
    try:
        return read(data)
    except SealRefused as exc:
        return exc


def _entries(directory: Path) -> list[Path]:
    return sorted(directory.iterdir()) if directory.is_dir() else []


def _failed(action: str, exc: OSError, **where: Any) -> None:
    """A housekeeping step that didn't happen; the next start tries it again."""
    logs.event(
        "policy_housekeeping_failed",
        level="warning",
        action=action,
        error_type=type(exc).__name__,
        **where,
    )


def _origin(kind: str) -> str:
    """The origin a kind is written with (``policyseal.ORIGIN_KINDS``): a portal change is a save,
    a host command its own name."""
    if kind.startswith("policy.") and kind != "policy.save":
        return kind.removeprefix("policy.")
    return "save"


def _clients(policy: Policy) -> dict[str, str]:
    clients = {} if policy.gateway is None else policy.gateway.clients
    return {name: client.token_hash for name, client in clients.items()}


def _callers(policy: Policy) -> dict[str, str]:
    return {
        f"{route.name}/{index}": caller_digest(caller.placeholder)
        for route in policy.routes
        for index, caller in enumerate(route.callers)
        if isinstance(caller, PlaceholderCaller)
    }


# What each revived grant subject's name (E.3, E.4) is held by in a policy.
_HELD: Final[Mapping[str, Callable[[Policy], dict[str, str]]]] = {
    "client": _clients,
    "caller": _callers,
}


# --- the store ---------------------------------------------------------------------------------


class PolicyStore:
    """The store in ``state``, as :meth:`open` found and housekept it. ``verdict`` is what the
    start found (D.6); ``head`` and ``anchor`` are what is on disk now, or what the anchor should
    say while ``anchor_dirty``."""

    def __init__(
        self,
        state: Path,
        keys: KeySet,
        previous: KeySet | None,
        found: StoreVerdict,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.verdict: StoreVerdict = found
        self.anchor_dirty = False
        self._state = state
        self._keys = keys
        self._previous = previous
        self._clock = clock
        self._head: Head | None = None
        self._anchor: Anchor | None = None
        self._header: Mapping[str, Any] | None = None
        self._seed_digest: str | None = None
        # Each kept revision's parent digest, by number: the head names its oldest's (D.8).
        self._parents: dict[int, str | None] = {}

    def __repr__(self) -> str:
        revision = None if self._head is None else self._head.revision
        return f"PolicyStore(revision={revision}, anchor_dirty={self.anchor_dirty})"

    @classmethod
    def open(
        cls,
        state: Path,
        keys: KeySet,
        previous: KeySet | None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> PolicyStore:
        """Read the store in ``state`` at start, take D.6's verdict and do its housekeeping.
        Never raises for what the files hold: a store that can't be used is a ``Refused``
        verdict, for the start to refuse with."""
        if previous is not None and previous.key_id == keys.key_id:
            # The current key set again as the previous one: there is nothing to re-seal, and a
            # rotation would record the vault's own key as retired (D.7).
            previous = None
        _remove_temporaries(state)
        directory = state / POLICY_DIR
        anchor = _unsealed(
            state / ANCHOR_FILE, ANCHOR_MAX, lambda data: unseal_anchor(data, keys, previous)
        )
        head = _unsealed(
            state / HEAD_FILE, HEAD_MAX, lambda data: unseal_head(data, keys, previous)
        )
        listed: list[str] = []
        read: dict[int, Unsealed | SealRefused] = {}
        for entry in _entries(directory):
            listed.append(entry.name)
            if entry.name != REVISIONS or not entry.is_dir():
                continue
            for child in _entries(entry):
                listed.append(f"{REVISIONS}/{child.name}")
                number = revision_number(child.name)
                if number is None or not child.is_file():
                    continue
                found = _unsealed(
                    child,
                    REVISION_FILE_MAX,
                    lambda data: unseal_revision(data, keys, previous, deployment=None),
                )
                if found is not None:
                    read[number] = found
        # A policy directory holding no file at all, its empty revisions/ (a seed whose anchor
        # wasn't written) included, doesn't make the volume used (F.1).
        empty = not any(path.is_file() for path in directory.rglob("*"))
        names = [entry.name for entry in _entries(state)]
        used = volume_used(names, policy_empty=empty)
        store = cls(state, keys, previous, verdict(anchor, head, read, listed, used), clock=clock)
        if isinstance(anchor, Anchor):
            store._anchor = anchor
        if isinstance(store.verdict, Ok):
            chained = set(store.verdict.kept)
            kept = {n: e for n, e in read.items() if n in chained and isinstance(e, Unsealed)}
            store._housekeep(store.verdict, kept)
        elif isinstance(store.verdict, Fresh):
            # Row 5: a seed that never committed.
            for number in store.verdict.uncommitted:
                store._quarantine(number, "uncommitted")
                logs.event("policy_save_uncommitted", level="warning", revision=number)
        return store

    # --- what is on disk ---------------------------------------------------------------------

    @property
    def head(self) -> Head | None:
        return self._head

    @property
    def anchor(self) -> Anchor | None:
        return self._anchor

    @property
    def header(self) -> Mapping[str, Any] | None:
        """The head revision's header: when, how and by whom (G.7's first row)."""
        return self._header

    @property
    def seed_digest(self) -> str | None:
        """The head body's seed digest, which a write carries forward (D.2, F.5)."""
        return self._seed_digest

    @property
    def kept(self) -> tuple[int, ...]:
        """The revisions whose files are kept, oldest first, the head's included."""
        return tuple(sorted(self._parents))

    # --- writes ------------------------------------------------------------------------------

    def commit(
        self,
        plan: WritePlan,
        *,
        author: Mapping[str, str],
        reason: str | None = None,
        target: int | None = None,
        jumped_from: int | None = None,
        seed_digest: str | None = None,
    ) -> Committed:
        """Commit ``plan`` as revision ``head + 1`` (D.9), inside G.6's section. ``author``,
        ``reason``, ``target`` and ``jumped_from`` go to the header as D.2 says; ``seed_digest``
        replaces the head's (an ``import --from-env``, a resume, F.5). Raises
        :class:`StoreRefused`, with nothing in effect, and ``ValueError`` for a plan made on
        another head or a header ``policyseal`` refuses."""
        head = self._running()
        if (plan.base, plan.base_digest) != (head.revision, head.digest):
            raise ValueError("the plan was made on another head")
        if plan.kind in ("policy.seed", "policy.reseed"):
            raise ValueError(f"{plan.kind} isn't written on the head")
        if self.anchor_dirty and not self._save_anchor(logged=False):
            raise StoreRefused(
                "policy_write_failed",
                f"the anchor of revision {head.revision} still can't be written",
            )
        return self._write(
            {
                "origin": _origin(plan.kind),
                "kind": plan.kind,
                "author": dict(author),
                "base": plan.base,
                "target": target,
                "jumped_from": jumped_from,
                "parent": head.digest,
            },
            document(plan.policy),
            plan.ratchet,
            seed_digest or self._seed_digest or "",  # an Ok store's head names one
            reason,
        )

    def seed(self, policy: Policy, *, ratchet: Ratchet, seed_digest: str) -> Committed:
        """Revision 1 on a fresh store, written by the vault itself (F.3): the anchor at 0 under
        the deployment a seed that never committed made, or a new one, then D.9's steps
        (FM-25). Raises :class:`StoreRefused`, and ``ValueError`` on a store that isn't fresh."""
        if not isinstance(self.verdict, Fresh) or self._head is not None:
            raise ValueError("only a fresh store is seeded")
        deployment = self.verdict.deployment or secrets.token_hex(16)
        retired = None if self._anchor is None else self._anchor.retired_key_id
        self._anchor = Anchor(deployment, 0, None, retired, self._keys.key_id)
        try:
            write_anchor(self._state / ANCHOR_FILE, seal_anchor(self._anchor, self._keys))
        except OSError as exc:
            raise StoreRefused(
                "policy_write_failed", f"the anchor can't be written ({type(exc).__name__})"
            ) from exc
        self.anchor_dirty = False
        return self._write(
            {
                "origin": "seed",
                "kind": "policy.seed",
                "author": {"by": "seed"},
                "base": None,
                "target": None,
                "jumped_from": None,
                "parent": None,
            },
            document(policy),
            ratchet,
            seed_digest,
            None,
        )

    def park(self) -> None:
        """Record that a declarative start parked the head (F.4): the anchor says ``parked`` and
        ``highest`` both the head's revision, whatever it said before (a park that finds the
        head one above ``highest`` repairs row 13 too). Raises :class:`StoreRefused`."""
        head = self._running()
        assert self._anchor is not None  # noqa: S101 - an Ok store has one
        wanted = replace(
            self._anchor, highest=head.revision, parked=head.revision, key_id=self._keys.key_id
        )
        try:
            write_anchor(self._state / ANCHOR_FILE, seal_anchor(wanted, self._keys))
        except OSError as exc:
            raise StoreRefused(
                "policy_write_failed", f"the anchor can't be written ({type(exc).__name__})"
            ) from exc
        self._anchor, self.anchor_dirty = wanted, False

    def reseal(self, kept: Mapping[int, Unsealed]) -> int | None:
        """D.7's rotation, at start: every kept revision still under the previous master key
        re-sealed under the current one (a new nonce, the same plaintext, so no digest moves),
        oldest first, then the head. Returns how many revisions it re-sealed, after which the
        anchor records the previous key as retired; ``None`` when nothing was under it, or when
        a write failed (the next start, with the previous key still set, finishes; FM-3)."""
        previous, head, anchor = self._previous, self._head, self._anchor
        if previous is None or head is None or anchor is None:
            return None
        stale = [number for number in sorted(kept) if kept[number].key_id == previous.key_id]
        if not stale and previous.key_id not in (head.key_id, anchor.key_id):
            return None
        try:
            for number in stale:
                entry = kept[number]
                sealed = seal_revision(
                    entry.header, entry.plaintext, keys=self._keys, nonce=_nonce()
                )
                write_revision(self._path(number), sealed)
            if head.key_id == previous.key_id:
                moved = replace(head, key_id=self._keys.key_id)
                write_head(self._state / HEAD_FILE, seal_head(moved, self._keys))
                self._head = moved
        except OSError as exc:
            _failed("rekey", exc)
            return None
        return len(stale)

    def removed_lookup(self, candidate: Policy) -> Callable[[str], int | None]:
        """``PlanInput.removed_in`` for a plan whose candidate is ``candidate`` (E.1 keeps no
        revision number; N.2's "removed in revision M"). For a grant subject
        (``client:<name>``, ``caller:<route>/<index>``) it answers the newest kept revision that
        retired the value ``candidate`` holds under that subject, as ``ratchet.advance`` did:
        ``n + 1`` when revision ``n`` held the token hash or placeholder digest anywhere and
        ``n + 1`` held it nowhere, so a rename or a shifted index isn't a removal. ``None`` when
        the kept history doesn't show it (a gap, a pruned revision, a pin). Each kept revision is
        read once per kind of subject."""
        found: dict[str, dict[int, frozenset[str] | None]] = {}

        def removed_in(subject: str) -> int | None:
            what, _, name = subject.partition(":")
            held = _HELD.get(what)
            if held is None:
                return None
            value = held(candidate).get(name)
            if value is None:
                return None
            if what not in found:
                found[what] = {number: self._held(number, held) for number in self._parents}
            values = found[what]
            for number in sorted(values, reverse=True):
                older, newer = values[number], values.get(number + 1)
                if older is not None and newer is not None and value in older - newer:
                    return number + 1
            return None

        return removed_in

    # --- internals ---------------------------------------------------------------------------

    def _path(self, number: int) -> Path:
        return self._state / revision_file(number)

    def _running(self) -> Head:
        if self._head is None:
            raise ValueError("the store has no head")
        return self._head

    def _directories(self) -> None:
        for directory in (self._state / POLICY_DIR, self._state / POLICY_DIR / REVISIONS):
            directory.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)

    def _housekeep(self, ok: Ok, kept: Mapping[int, Unsealed]) -> None:
        """An ``Ok`` store's rows 12-16, the rotation, and the anchor last."""
        self._head, self._header, self._seed_digest = ok.head, ok.top.header, ok.seed_digest
        self._parents = {number: entry.header["parent"] for number, entry in kept.items()}
        moved = True
        if ok.uncommitted is not None:
            moved = self._quarantine(ok.uncommitted, "uncommitted")
            logs.event("policy_save_uncommitted", level="warning", revision=ok.uncommitted)
        for found in ok.quarantined:
            self._quarantine(found.revision, "unreadable")
            logs.event(
                "policy_revision_quarantined",
                level="warning",
                revision=found.revision,
                reason=found.reason,
            )
        for name in ok.stray:
            logs.event("policy_stray_file", name=name)
        self._prune(ok.pruned, below=ok.head.oldest)
        # A file left above the head may be under the previous key: retiring that key now would
        # make it files_above_head at the next start, so the rotation waits for the move.
        resealed = self.reseal(kept) if moved else None
        if resealed is None and not ok.anchor_stale:
            return
        assert self._anchor is not None  # noqa: S101 - an Ok store has one
        retired = None if resealed is None or self._previous is None else self._previous.key_id
        self._anchor = replace(
            self._anchor,
            highest=ok.head.revision,
            parked=ok.parked,
            retired_key_id=retired or self._anchor.retired_key_id,
            key_id=self._keys.key_id,
        )
        if self._save_anchor() and resealed is not None:
            logs.event(
                "policy_rekeyed",
                revisions=resealed,
                key_id=self._keys.key_id,
                next="remove ZOEYMCP_MASTER_KEY_PREVIOUS",
            )

    def _quarantine(self, number: int, why: str) -> bool:
        """Move revision ``number`` to ``quarantine/<n>.<why>.json``, or ``<n>.<why>.<k>.json``
        with the first free ``k`` from 2 when an earlier one has that name. Returns whether it
        moved; when it didn't, the next start tries again."""
        directory = self._state / POLICY_DIR / QUARANTINE
        target, copy = directory / f"{number}.{why}.json", 1
        while target.exists():
            copy += 1
            target = directory / f"{number}.{why}.{copy}.json"
        try:
            move(self._path(number), target)
        except OSError as exc:
            _failed("quarantine", exc, revision=number)
            return False
        return True

    def _prune(self, numbers: Iterable[int], *, below: int) -> None:
        """D.8: remove revisions below ``below``, oldest first; one that can't be removed stops
        the prune, which the next start finishes (row 16)."""
        removed = 0
        for number in sorted(numbers):
            try:
                remove(self._path(number))
            except OSError as exc:
                _failed("prune", exc, revision=number)
                break
            self._parents.pop(number, None)
            removed += 1
        if removed:
            logs.event("policy_pruned", revisions=removed, below=below)

    def _save_anchor(self, *, logged: bool = True) -> bool:
        """Write the anchor the store holds. Returns whether it was written; when it wasn't,
        the anchor is dirty, and ``policy_anchor_write_failed`` is logged unless ``logged`` is
        false (a commit that then refuses)."""
        assert self._anchor is not None  # noqa: S101 - callers set it
        try:
            write_anchor(self._state / ANCHOR_FILE, seal_anchor(self._anchor, self._keys))
        except OSError as exc:
            self.anchor_dirty = True
            if logged:
                logs.event(
                    "policy_anchor_write_failed",
                    level="warning",
                    revision=self._anchor.highest,
                    error_type=type(exc).__name__,
                )
            return False
        self.anchor_dirty = False
        return True

    def _write(
        self,
        fields: Mapping[str, Any],
        policy: Mapping[str, Any],
        ratchet: Ratchet,
        seed_digest: str,
        reason: str | None,
    ) -> Committed:
        """D.9's steps 1-4 for revision ``head + 1`` (1 for a seed), ``fields`` its header's
        origin, kind, author, base, target, jumped_from and parent."""
        head, anchor = self._head, self._anchor
        assert anchor is not None  # noqa: S101 - a seed writes it first
        number = 1 if head is None else head.revision + 1
        if number > REVISION_MAX:
            raise StoreRefused("revision_out_of_range", "a revision can't go above 9,999,999,999")
        try:
            body = make_body(
                salt=secrets.token_bytes(SALT_BYTES),
                policy=policy,
                ratchet=ratchet.as_dict(),
                seed_digest=seed_digest,
                reason=reason,
            )
        except ValueError as exc:
            raise StoreRefused("policy_write_failed", str(exc)) from exc
        header = {
            "v": VERSION,
            "deployment": anchor.deployment,
            "revision": number,
            "created": int(self._clock()),
            **fields,
            "body_digest": body_digest(body),
        }
        data = seal_revision(header, body, keys=self._keys, nonce=_nonce())
        digest = revision_digest(header)
        parent = fields["parent"]
        oldest = 1 if head is None else max(head.oldest, number - KEEP + 1)
        if head is not None and oldest == head.oldest:
            oldest_parent = head.oldest_parent
        else:
            oldest_parent = parent if oldest == number else self._parents.get(oldest)
        new = Head(anchor.deployment, number, digest, oldest, oldest_parent, self._keys.key_id)
        try:
            self._directories()
            write_revision(self._path(number), data)
            write_head(self._state / HEAD_FILE, seal_head(new, self._keys))
        except OSError as exc:
            raise StoreRefused(
                "policy_write_failed",
                f"revision {number} can't be written ({type(exc).__name__})",
            ) from exc
        self._head, self._header, self._seed_digest = new, header, seed_digest
        self._parents[number] = parent
        self._anchor = replace(anchor, highest=number, parked=None, key_id=self._keys.key_id)
        written = self._save_anchor()
        self._prune([n for n in self._parents if n < oldest], below=oldest)
        return Committed(number, digest, header, written)

    def _held(self, number: int, held: Callable[[Policy], dict[str, str]]) -> frozenset[str] | None:
        """The values ``held`` finds in revision ``number``'s policy, or ``None`` when it can't be
        read now."""
        head = self._running()
        found = _unsealed(
            self._path(number),
            REVISION_FILE_MAX,
            lambda data: unseal_revision(
                data, self._keys, self._previous, deployment=head.deployment
            ),
        )
        if not isinstance(found, Unsealed):
            return None
        try:
            return frozenset(held(Policy.model_validate(dict(found.body.policy))).values())
        except ValueError:
            return None


refuse_type(PolicyStore)


def _nonce() -> bytes:
    return secrets.token_bytes(POLICY_NONCE_BYTES)


def _remove_temporaries(state: Path) -> None:
    """Remove what a write that never finished left: ``.policy-*`` files beside the anchor, in
    ``policy/`` and in ``revisions/`` (D.1)."""
    policy = state / POLICY_DIR
    for directory in (state, policy, policy / REVISIONS):
        for entry in _entries(directory):
            if entry.name.startswith(TEMPORARY_PREFIX) and entry.is_file():
                try:
                    remove(entry)
                except OSError as exc:
                    _failed("remove", exc)
