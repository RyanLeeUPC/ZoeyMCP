"""Drift marks, persisted in the gateway's state (M3 design G.4).

When any connection sees an included tool listed with a pin other than the policy's, the tool is
marked, and the mark hides it for every client of that server. The mark stays when the upstream
flips back to the reviewed definition: a server that changes a tool and changes it back has shown
that it can. A mark clears only when the policy's pin for the tool changes, or when ``review
--clear`` lists fresh and finds every included tool matching.

Marks are keyed by definition kind (M6 design L.4): a prompt, a resource template or a fixed
resource is marked as a tool is, under its name, URI template or URI. Each method takes the kind,
``tool`` when none is given.

Marks are written atomically to ``drift.json``, so a restart doesn't clear them. A file that
can't be read stops the gateway rather than silently forgetting them. Version 2 holds ``(kind,
name, pin)``; a version 1 file, an M7 gateway's, holds ``(tool, pin)`` and loads as tool marks,
and the first change writes it as version 2. An older gateway refuses a version 2 file as it
refuses any version it doesn't know, so a downgrade fails closed. A compromised gateway could
edit the file, but it could also skip the pins, so the file adds no risk.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Set
from pathlib import Path
from typing import Final, cast

from ..common import canonical, files
from ..common.policy import fields
from . import logs
from .pins import DefinitionKind, Mark

MARKS_FILE = "drift.json"
VERSION = 2
LEGACY_VERSION: Final = 1  # tool marks only, as M7 wrote them
MAX_BYTES = 4 * 2**20
_PIN = re.compile(r"sha256:[0-9a-f]{64}")
_TOOL = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_SERVER = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")

# (kind, name, the policy pin it drifted from).
KindMark = tuple[DefinitionKind, str, str]


class MarksError(RuntimeError):
    """The marks file exists but can't be used."""


def _form(rule: Callable[[str], str]) -> Callable[[str], bool]:
    def holds(value: str) -> bool:
        try:
            rule(value)
        except ValueError:
            return False
        return True

    return holds


# What each kind's mark may name: an included entry's key, in the form the policy holds it.
_NAMES: Final[dict[str, Callable[[str], bool]]] = {
    "tool": lambda name: _TOOL.fullmatch(name) is not None,
    "prompt": lambda name: _TOOL.fullmatch(name) is not None,
    "resource_template": _form(fields.uri_template),
    "resource": _form(fields.resource_uri),
}


def _mark(entry: object, legacy: bool) -> KindMark:
    """One entry of a server's list: ``[tool, pin]`` in version 1, ``[kind, name, pin]`` in 2."""
    if not isinstance(entry, list) or not all(isinstance(part, str) for part in entry):
        raise MarksError("a mark is malformed")
    parts: list[str] = ["tool", *entry] if legacy else list(entry)
    if len(parts) != 3 or parts[0] not in _NAMES:
        raise MarksError("a mark is malformed")
    kind, name, pin = parts
    if not _NAMES[kind](name) or not _PIN.fullmatch(pin):
        raise MarksError("a mark is malformed")
    return cast(DefinitionKind, kind), name, pin


def _parse(data: bytes) -> dict[str, frozenset[KindMark]]:
    try:
        document = canonical.loads_strict(data, max_bytes=MAX_BYTES)
    except canonical.JSONRejected as exc:
        raise MarksError("not strict JSON") from exc
    if not isinstance(document, dict) or set(document) != {"v", "marks"}:
        raise MarksError("not a marks document")
    if document["v"] not in (VERSION, LEGACY_VERSION):
        raise MarksError(f"version {document['v']!r} is not {LEGACY_VERSION} or {VERSION}")
    legacy = document["v"] == LEGACY_VERSION
    raw = document["marks"]
    if not isinstance(raw, dict):
        raise MarksError("marks is not an object")
    marks: dict[str, frozenset[KindMark]] = {}
    for server, entries in raw.items():
        if not _SERVER.fullmatch(server) or not isinstance(entries, list):
            raise MarksError("a server entry is malformed")
        found = frozenset(_mark(entry, legacy) for entry in entries)
        if found:
            marks[server] = found
    return marks


def _dump(marks: dict[str, frozenset[KindMark]]) -> bytes:
    body = {server: sorted(list(mark) for mark in held) for server, held in marks.items() if held}
    return canonical.dumps_canonical({"v": VERSION, "marks": body})


class DriftMarks:
    """Every server's drift marks, of every kind, in memory and on disk."""

    def __init__(self, path: Path, marks: dict[str, frozenset[KindMark]] | None = None) -> None:
        self._path = path
        self._marks: dict[str, frozenset[KindMark]] = dict(marks or {})

    @classmethod
    def load(cls, state_dir: Path) -> DriftMarks:
        path = state_dir / MARKS_FILE
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return cls(path)
        except OSError as exc:
            raise MarksError(f"can't read {path.name}: {exc.strerror}") from exc
        return cls(path, _parse(data))

    def for_server(self, server: str, kind: DefinitionKind = "tool") -> frozenset[Mark]:
        """The server's marks of ``kind``, as ``(name, pin)``."""
        return frozenset(
            (name, pin) for held, name, pin in self._marks.get(server, ()) if held == kind
        )

    def servers(self) -> frozenset[str]:
        return frozenset(self._marks)

    def pins(self) -> frozenset[str]:
        """Every pin a mark of any server and kind holds (the definitions kept at a start)."""
        return frozenset(pin for held in self._marks.values() for _, _, pin in held)

    def replace(
        self, server: str, marks: Set[Mark], kind: DefinitionKind = "tool"
    ) -> tuple[frozenset[Mark], frozenset[Mark]]:
        """Make ``marks`` the server's marks of ``kind``. Returns ``(added, removed)``; writes if
        either."""
        old = self.for_server(server, kind)
        new = frozenset(marks)
        added, removed = new - old, old - new
        if added or removed:
            others = {mark for mark in self._marks.get(server, ()) if mark[0] != kind}
            held = frozenset(others | {(kind, name, pin) for name, pin in new})
            if held:
                self._marks[server] = held
            else:
                self._marks.pop(server, None)
            self._save()
        return added, removed

    def clear(self, server: str, tools: Set[str]) -> frozenset[Mark]:
        """Remove the marks for ``tools`` (``review --clear``). Returns what was removed."""
        keep = {mark for mark in self.for_server(server) if mark[0] not in tools}
        return self.replace(server, keep)[1]

    def _save(self) -> None:
        try:
            files.write_atomic(self._path, _dump(self._marks), prefix=".drift-")
        except OSError as exc:
            # The marks still hold in memory, and the next change writes them all again.
            logs.event("drift_marks_not_written", level="critical", error=exc.strerror or "error")
