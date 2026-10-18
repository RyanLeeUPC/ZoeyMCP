"""The definition store: reviewed tool definitions by pin (M3 design G.5).

When a listed tool matches its pin, its canonical projection is written to ``defs/<hex>.json``
if it isn't there yet. The store is content-addressed: a file whose content doesn't hash to its
name is ignored, so it checks itself even after a gateway compromise. It lets ``review`` and the
``tool_drift`` line say which members changed, with a diff. **No decision reads it.**
"""

from __future__ import annotations

import contextlib
import difflib
import re
from collections.abc import Mapping, Set
from pathlib import Path
from typing import Any

from ..common import canonical, files, textrules
from . import logs
from .pins import ProjectionError, pin_of

DEFS_DIR = "defs"
MAX_FILES = 4096
MAX_BYTES = 4 * 2**20
_NAME = re.compile(r"[0-9a-f]{64}\.json")


def _file_name(pin: str) -> str:
    return pin.removeprefix("sha256:") + ".json"


class DefinitionStore:
    def __init__(self, state_dir: Path) -> None:
        self._dir = state_dir / DEFS_DIR

    def put(self, pin: str, definition: Mapping[str, Any]) -> None:
        """Keep ``definition``, which must hash to ``pin``. A failed write is logged, not raised."""
        path = self._dir / _file_name(pin)
        if path.exists():
            return
        try:
            if pin_of(definition) != pin:
                return
        except ProjectionError:
            return
        try:
            files.write_atomic(path, canonical.dumps_canonical(dict(definition)), prefix=".def-")
        except OSError as exc:
            logs.event("defstore_write_failed", error=exc.strerror or "error")

    def get(self, pin: str) -> dict[str, Any] | None:
        """The definition for ``pin``, or None if it's missing, unreadable, or doesn't match."""
        try:
            data = (self._dir / _file_name(pin)).read_bytes()
        except OSError:
            return None
        try:
            definition = canonical.loads_strict(data, max_bytes=MAX_BYTES)
        except canonical.JSONRejected:
            return None
        if not isinstance(definition, dict):
            return None
        try:
            return definition if pin_of(definition) == pin else None
        except ProjectionError:
            return None

    def prune(self, keep: Set[str]) -> int:
        """At start: remove every definition whose pin isn't in ``keep``, then the oldest beyond
        :data:`MAX_FILES`. Returns how many were removed. Other files are left alone."""
        try:
            entries = [entry for entry in self._dir.iterdir() if _NAME.fullmatch(entry.name)]
        except OSError:
            return 0
        kept_names = {_file_name(pin) for pin in keep}
        removed = 0
        survivors: list[tuple[float, Path]] = []
        for entry in entries:
            if entry.name in kept_names:
                with contextlib.suppress(OSError):
                    survivors.append((entry.stat().st_mtime, entry))
                continue
            with contextlib.suppress(OSError):
                entry.unlink()
                removed += 1
        survivors.sort()
        for _, entry in survivors[: max(0, len(survivors) - MAX_FILES)]:
            with contextlib.suppress(OSError):
                entry.unlink()
                removed += 1
        return removed


def changed_members(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    """The top-level members that differ between two definitions, sorted."""
    return sorted(key for key in set(old) | set(new) if old.get(key, ...) != new.get(key, ...))


def diff(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    """A unified diff of two definitions as indented canonical JSON, with nothing hidden."""
    before = canonical.render_for_approval(dict(old)).splitlines()
    after = canonical.render_for_approval(dict(new)).splitlines()
    lines = difflib.unified_diff(before, after, "reviewed", "listed", lineterm="", n=2)
    return [textrules.reveal_hidden(line) for line in lines]
