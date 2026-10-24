"""The managed policy store's crash holds (M6 design O.1, N.6): test builds only, as M7's
``pause_after_put`` (tests/fakes/resolver.py).

A hold wraps one of ``vault/policystore.py``'s module-level write seams: once that write returns,
it says so in a marker file and waits to be killed, so a crash test's kill falls between two of
D.9's steps. ``pause_after_revision`` holds after a revision file is written, before its head:
FM-1 in a save, FM-25 in a seed (after the anchor at 0), FM-3 in a master-key rotation (after the
first re-sealed revision). ``pause_after_head`` holds after the head, before the anchor: FM-2.

:func:`save` writes a holds file and :func:`install` reads it in a vault's own process, before the
store is opened (tests/acceptance/procs.py's launcher, step 13c). A hold waits with a blocking
sleep: the commit runs synchronously on the vault's event loop (G.6), so nothing else runs there
either, as in a real crash.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final

from zoeymcp.vault import policystore

# Each hold and the seam it wraps.
HOLDS: Final = {"pause_after_revision": "write_revision", "pause_after_head": "write_head"}


def forever() -> None:
    """Wait to be killed."""
    time.sleep(3600)


def hold(name: str, marker: Path, *, wait: Callable[[], None] = forever) -> None:
    """From now on, once the seam ``name`` holds at returns, write ``written`` to ``marker`` and
    ``wait``. A self-test passes a ``wait`` that raises, standing in for the kill."""
    seam = HOLDS[name]
    real: Callable[[Path, bytes], None] = getattr(policystore, seam)

    def held(path: Path, data: bytes) -> None:
        real(path, data)
        marker.write_bytes(b"written\n")
        wait()

    setattr(policystore, seam, held)


def save(path: Path, **markers: Path) -> None:
    """A holds file naming each hold's marker, for :func:`install`."""
    unknown = set(markers) - set(HOLDS)
    if unknown:
        raise ValueError(f"no such hold: {sorted(unknown)}")
    document = {name: str(marker) for name, marker in markers.items()}
    path.write_bytes(json.dumps(document, indent=2).encode() + b"\n")


def install(path: str) -> None:
    """In a vault's own process, before it opens the store: install every hold ``path`` names."""
    for name, marker in json.loads(Path(path).read_bytes()).items():
        hold(name, Path(marker))
