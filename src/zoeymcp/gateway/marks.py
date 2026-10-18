"""Drift marks, persisted in the gateway's state (M3 design G.4).

When any connection sees an included tool listed with a pin other than the policy's, the tool is
marked, and the mark hides it for every client of that server. The mark stays when the upstream
flips back to the reviewed definition: a server that changes a tool and changes it back has shown
that it can. A mark clears only when the policy's pin for the tool changes, or when ``review
--clear`` lists fresh and finds every included tool matching.

Marks are written atomically to ``drift.json``, so a restart doesn't clear them. A file that
can't be read stops the gateway rather than silently forgetting them. A compromised gateway could
edit the file, but it could also skip the pins, so the file adds no risk.
"""

from __future__ import annotations

import re
from collections.abc import Set
from pathlib import Path

from ..common import canonical, files
from . import logs
from .pins import Mark

MARKS_FILE = "drift.json"
VERSION = 1
MAX_BYTES = 4 * 2**20
_PIN = re.compile(r"sha256:[0-9a-f]{64}")
_TOOL = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_SERVER = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")


class MarksError(RuntimeError):
    """The marks file exists but can't be used."""


def _parse(data: bytes) -> dict[str, frozenset[Mark]]:
    try:
        document = canonical.loads_strict(data, max_bytes=MAX_BYTES)
    except canonical.JSONRejected as exc:
        raise MarksError("not strict JSON") from exc
    if not isinstance(document, dict) or set(document) != {"v", "marks"}:
        raise MarksError("not a marks document")
    if document["v"] != VERSION:
        raise MarksError(f"version {document['v']!r} is not {VERSION}")
    raw = document["marks"]
    if not isinstance(raw, dict):
        raise MarksError("marks is not an object")
    marks: dict[str, frozenset[Mark]] = {}
    for server, entries in raw.items():
        if not _SERVER.fullmatch(server) or not isinstance(entries, list):
            raise MarksError("a server entry is malformed")
        found: set[Mark] = set()
        for entry in entries:
            if (
                not isinstance(entry, list)
                or len(entry) != 2
                or not all(isinstance(part, str) for part in entry)
                or not _TOOL.fullmatch(entry[0])
                or not _PIN.fullmatch(entry[1])
            ):
                raise MarksError("a mark is malformed")
            found.add((entry[0], entry[1]))
        if found:
            marks[server] = frozenset(found)
    return marks


def _dump(marks: dict[str, frozenset[Mark]]) -> bytes:
    body = {
        server: sorted([tool, pin] for tool, pin in held) for server, held in marks.items() if held
    }
    return canonical.dumps_canonical({"v": VERSION, "marks": body})


class DriftMarks:
    """Every server's drift marks, in memory and on disk."""

    def __init__(self, path: Path, marks: dict[str, frozenset[Mark]] | None = None) -> None:
        self._path = path
        self._marks: dict[str, frozenset[Mark]] = dict(marks or {})

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

    def for_server(self, server: str) -> frozenset[Mark]:
        return self._marks.get(server, frozenset())

    def servers(self) -> frozenset[str]:
        return frozenset(self._marks)

    def replace(self, server: str, marks: Set[Mark]) -> tuple[frozenset[Mark], frozenset[Mark]]:
        """Make ``marks`` the server's marks. Returns ``(added, removed)``; writes if either."""
        old = self.for_server(server)
        new = frozenset(marks)
        added, removed = new - old, old - new
        if added or removed:
            if new:
                self._marks[server] = new
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
