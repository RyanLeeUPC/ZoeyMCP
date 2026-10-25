"""The gateway as the restore witness (M6 design K.3; Q11 narrow (b), Y24, T-4, T-5). Pure,
mutation-tested.

In managed mode the vault states its head beside every view answer, outside the view and its
digest, in :data:`~zoeymcp.common.policy.view.REVISION_HEADER`: ``<deployment>.<revision>``, the
deployment's 32 hex digits and a revision from 1 to :data:`REVISION_MAX`. The gateway keeps the
highest revision it has seen of each deployment, with when it first saw the deployment, in
``/state-gateway/policy-seen.json`` (:data:`FILE`), and its status report carries them (K.1). So
a vault whose whole ``/state`` was put back from an older backup, while the gateway's volume
wasn't, is seen behind them (``policy_behind_witness``), and a ``/state`` wiped and seeded again
under a new deployment is seen beside the old one (``policy_deployment_changed``): the cases the
vault's own volume can't see (D.6).

:func:`stated` reads the header; anything else is no statement (a declarative vault, an older
one). :func:`seen` decides what the gateway records: the same revision changes nothing; a higher
one is recorded; a lower one of a deployment it knows is :class:`Regressed`, and the higher record
stays (the gateway logs ``policy_revision_regressed``); a new deployment is recorded beside the
others with the time it was first seen, and counted (``deployments_seen``, T-5). At most
:data:`WITNESS_DEPLOYMENTS_MAX` are kept: past it, the one at the lowest revision goes, the
earliest seen on a tie, never the one just seen, so deployments seeded again and again can't push
out the one that reached a high revision. The gateway applies the view either way: it is a
witness, not an authority.

The file is canonical JSON with no MAC (:func:`dumps`, :func:`loads`): the gateway holds no key,
and a compromised gateway can lie anyway (0.5). Its deployments are listed in the order first
seen, which the status report keeps.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from ..common import canonical

FILE: Final = "policy-seen.json"
VERSION: Final = 1
# The vault's own bound on a revision (vault/policyseal.py's REVISION_MAX, D.2, T-4): a stated
# revision above it is no statement.
REVISION_MAX: Final = 9_999_999_999
# How many deployments the file keeps (K.3, N.4).
WITNESS_DEPLOYMENTS_MAX: Final = 8
# A file holds at most this many bytes.
MAX_BYTES: Final = 64 * 1024
_STATED: Final = re.compile(r"([0-9a-f]{32})\.([1-9][0-9]{0,9})")
_DEPLOYMENT: Final = re.compile(r"[0-9a-f]{32}")
_ENTRY: Final = frozenset({"deployment", "revision", "first_seen"})


class WitnessError(ValueError):
    """The file exists but isn't one this version reads."""


@dataclass(frozen=True)
class Stated:
    """The head a view answer states (K.3)."""

    deployment: str
    revision: int


@dataclass(frozen=True)
class Entry:
    """A deployment as the gateway recorded it: the highest revision seen, and when it was first
    seen (Unix seconds)."""

    revision: int
    first_seen: int


@dataclass(frozen=True)
class Seen:
    """What the gateway has witnessed: each deployment, in the order first seen, and how many it
    has recorded in all (those let go past :data:`WITNESS_DEPLOYMENTS_MAX` included)."""

    deployments: Mapping[str, Entry] = field(default_factory=lambda: MappingProxyType({}))
    counted: int = 0

    def report(self) -> dict[str, int]:
        """The status report's ``witness`` (K.1): each deployment's revision, first seen first."""
        return {deployment: entry.revision for deployment, entry in self.deployments.items()}


@dataclass(frozen=True)
class Regressed:
    """A view answer that states a revision below the one recorded for its deployment."""

    deployment: str
    seen: int
    now: int


def stated(header: str | None) -> Stated | None:
    """The head a view answer's revision header states, or None when it states none."""
    if header is None:
        return None
    found = _STATED.fullmatch(header)
    if found is None:
        return None
    revision = int(found[2])
    if revision > REVISION_MAX:
        return None
    return Stated(found[1], revision)


def seen(old: Seen, header: Stated, at: int) -> Seen | Regressed:
    """What the gateway records after a view answer stated ``header`` at ``at`` (Unix seconds):
    ``old`` itself when nothing changes, a new record, or :class:`Regressed`."""
    known = old.deployments.get(header.deployment)
    if known is not None:
        if header.revision < known.revision:
            return Regressed(header.deployment, known.revision, header.revision)
        if header.revision == known.revision:
            return old
        moved = {**old.deployments, header.deployment: Entry(header.revision, known.first_seen)}
        return Seen(MappingProxyType(moved), old.counted)
    kept = dict(old.deployments)
    while len(kept) >= WITNESS_DEPLOYMENTS_MAX:
        order = list(kept)
        del kept[min(order, key=lambda name: (kept[name].revision, order.index(name)))]
    kept[header.deployment] = Entry(header.revision, at)
    return Seen(MappingProxyType(kept), old.counted + 1)


def dumps(found: Seen) -> bytes:
    """The file's bytes: canonical JSON, the deployments first seen first."""
    return canonical.dumps_canonical(
        {
            "v": VERSION,
            "deployments": [
                {"deployment": name, "revision": entry.revision, "first_seen": entry.first_seen}
                for name, entry in found.deployments.items()
            ],
            "counted": found.counted,
        }
    )


def loads(data: bytes) -> Seen:
    """The file :func:`dumps` wrote. Raises :class:`WitnessError` for anything else."""
    try:
        document = canonical.loads_strict(data, max_bytes=MAX_BYTES)
    except canonical.JSONRejected as exc:
        raise WitnessError("not strict JSON") from exc
    if not isinstance(document, dict) or set(document) != {"v", "deployments", "counted"}:
        raise WitnessError("not a witness document")
    if document["v"] != VERSION or isinstance(document["v"], bool):
        raise WitnessError(f"version {document['v']!r} is not {VERSION}")
    entries, counted = document["deployments"], document["counted"]
    if not isinstance(entries, list) or len(entries) > WITNESS_DEPLOYMENTS_MAX:
        raise WitnessError("deployments is not a list of at most 8")
    found: dict[str, Entry] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _ENTRY:
            raise WitnessError("a deployment entry is malformed")
        name, revision, first = entry["deployment"], entry["revision"], entry["first_seen"]
        if not isinstance(name, str) or _DEPLOYMENT.fullmatch(name) is None or name in found:
            raise WitnessError("a deployment entry is malformed")
        if not _integer(revision) or not 1 <= revision <= REVISION_MAX:
            raise WitnessError("a deployment entry is malformed")
        if not _integer(first) or first < 0:
            raise WitnessError("a deployment entry is malformed")
        found[name] = Entry(revision, first)
    if not _integer(counted) or counted < len(found):
        raise WitnessError("counted is not a count of the deployments seen")
    return Seen(MappingProxyType(found), counted)


def _integer(value: object) -> bool:
    """A JSON integer: an ``int`` that isn't a ``bool``."""
    return isinstance(value, int) and not isinstance(value, bool)
