"""Merging a fragment into a policy (M7 design H.4; GR-1, CR-14, PC-3, OPS-16). Pure.

One function, :func:`merge`, is what the vault runs before it shows a fragment
(``change.apply``) and what ``zoeymcp check --with`` runs before the operator commits it, so both
see the same merged policy:

- two mappings merge key by key;
- a ``replace`` path takes the fragment's value whole (a review's ``tools``, ``review`` and
  ``declined``, a re-registered credential), so a re-review that drops a tool leaves no stale pin;
- the top-level ``routes`` list merges by ``name``: a new name is appended, an existing name
  must be equal, else :class:`MergeConflict` names it;
- the top-level ``egress_private`` list merges as a set, the base's order first, so "nothing here
  replaces a key you have" holds for it too;
- every other list, and every scalar, is replaced.

A fragment carries its ``replace`` paths in a fixed header line (:data:`REPLACE_HEADER`), which
:func:`replace_line` writes and :func:`replace_paths` reads. Only the paths a change can replace are
accepted there, so a fragment can't replace a whole ``routes`` list or another server's block.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Final

from pydantic import ValidationError

from .schema import NAME_PATTERN, Route

Path = tuple[str, ...]

# The header line that lists a fragment's replace paths, each dotted (names hold no dot).
REPLACE_HEADER: Final = "# zoeymcp replace: "
ROUTES: Final[Path] = ("routes",)
EGRESS_PRIVATE: Final[Path] = ("egress_private",)
# Mappings of names a fragment adds into: a new key under one of these is a new name, so a policy
# without the container still reports ``credentials.notes`` as added, not ``credentials``.
CONTAINERS: Final[frozenset[Path]] = frozenset(
    {
        ("credentials",),
        ("connectors",),
        ("gateway",),
        ("gateway", "servers"),
        ("gateway", "clients"),
    }
)
_NAME = re.compile(NAME_PATTERN)
# The blocks a server's review replaces whole (E.4).
REVIEW_BLOCKS: Final = ("tools", "review", "declined")


@dataclass(frozen=True)
class Merged:
    """The merged document, and the paths the fragment added and replaced, in order."""

    data: dict[str, Any]
    added: tuple[Path, ...]
    replaced: tuple[Path, ...]


@dataclass(frozen=True)
class MergeConflict:
    """A fragment that can't merge: a route by an existing name that differs from it."""

    path: Path
    message: str


class _Conflict(Exception):
    def __init__(self, conflict: MergeConflict) -> None:
        self.conflict = conflict


def merge(
    base: Mapping[str, Any], fragment: Mapping[str, Any], *, replace: Collection[Path] = ()
) -> Merged | MergeConflict:
    """``fragment`` merged into a copy of ``base``; neither is changed."""
    out = copy.deepcopy(dict(base))
    added: list[Path] = []
    replaced: list[Path] = []
    try:
        _mapping(out, fragment, (), frozenset(replace), added, replaced)
    except _Conflict as exc:
        return exc.conflict
    return Merged(out, tuple(added), tuple(replaced))


def _mapping(
    out: dict[str, Any],
    fragment: Mapping[str, Any],
    path: Path,
    replace: frozenset[Path],
    added: list[Path],
    replaced: list[Path],
) -> None:
    for key, value in fragment.items():
        where = (*path, key)
        current = out.get(key)
        if where in replace:
            out[key] = copy.deepcopy(value)
            replaced.append(where)
        elif where == ROUTES and isinstance(value, list) and isinstance(current, list | None):
            out[key] = _routes(current or [], value, added)
        elif (
            where == EGRESS_PRIVATE and isinstance(value, list) and isinstance(current, list | None)
        ):
            out[key] = _union(current or [], value, added)
        elif key not in out:
            if isinstance(value, Mapping) and where in CONTAINERS:
                out[key] = {}
                _mapping(out[key], value, where, replace, added, replaced)
            else:
                out[key] = copy.deepcopy(value)
                added.append(where)
        elif isinstance(current, dict) and isinstance(value, Mapping):
            _mapping(current, value, where, replace, added, replaced)
        elif current != value:
            out[key] = copy.deepcopy(value)
            replaced.append(where)


def _routes(current: list[Any], routes: list[Any], added: list[Path]) -> list[Any]:
    out = list(current)
    for route in routes:
        name = route.get("name") if isinstance(route, Mapping) else None
        if not isinstance(name, str):
            raise _Conflict(MergeConflict(ROUTES, "a route in the fragment has no name"))
        existing = [r for r in out if isinstance(r, Mapping) and r.get("name") == name]
        if not existing:
            out.append(copy.deepcopy(route))
            added.append((*ROUTES, name))
        elif not _same_route(existing[0], route):
            raise _Conflict(
                MergeConflict(
                    (*ROUTES, name),
                    f"route {name} is in the policy already and differs from the fragment's; "
                    "remove one, or give the fragment's route another name",
                )
            )
    return out


def _same_route(one: Mapping[str, Any], other: Mapping[str, Any]) -> bool:
    """Equal as written, or equal once each takes its defaults (``stream: false`` written out)."""
    if one == other:
        return True
    try:
        return Route.model_validate(one) == Route.model_validate(other)
    except ValidationError:
        return False


def _union(current: list[Any], entries: list[Any], added: list[Path]) -> list[Any]:
    out = list(current)
    for entry in entries:
        if entry not in out:
            out.append(entry)
            added.append((*EGRESS_PRIVATE, str(entry)))
    return out


# --- the header line ---------------------------------------------------------------------------


def replaceable(path: Path) -> bool:
    """Whether a fragment may replace ``path``: a credential, or a server's review blocks."""
    if len(path) == 2:
        return path[0] == "credentials" and _NAME.fullmatch(path[1]) is not None
    return (
        len(path) == 4
        and path[:2] == ("gateway", "servers")
        and _NAME.fullmatch(path[2]) is not None
        and path[3] in REVIEW_BLOCKS
    )


def replace_line(paths: Collection[Path]) -> str:
    """The header line naming ``paths``."""
    for path in paths:
        if not replaceable(path):
            raise ValueError(f"a fragment can't replace {'.'.join(path)}")
    return REPLACE_HEADER + " ".join(".".join(path) for path in paths)


def replace_paths(text: str) -> tuple[Path, ...]:
    """The replace paths a fragment's header names: every :data:`REPLACE_HEADER` line among the
    comment lines before the first line of YAML. A ``ValueError`` names a path no fragment may
    replace."""
    found: list[Path] = []
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            break
        if not line.lstrip().startswith(REPLACE_HEADER):
            continue
        for item in line.lstrip()[len(REPLACE_HEADER) :].split():
            path = tuple(item.split("."))
            if not replaceable(path):
                raise ValueError(f"the header names {item}, which a fragment can't replace")
            found.append(path)
    return tuple(found)


def describe(path: Path) -> str:
    """A path as the CLI says it: ``credentials.notes``, ``routes notes``,
    ``egress_private host:port``."""
    if path[:1] in (ROUTES, EGRESS_PRIVATE) and len(path) == 2:
        return f"{path[0]} {path[1]}"
    return ".".join(path)
