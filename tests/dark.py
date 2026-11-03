"""The switch for M8's dark-built policy fields (M8 design A.2 row 0, G-2, BP-2), now lit.

Until step 18, ``check`` refused every new M8 field while ``check._DARK`` listed it, and
:func:`lit` emptied that table for one test, so steps 5-17 tested the fields and their rows. Step
18 turned them on: the table is gone, and :func:`lit` does nothing, so the tests written through
it read as before. A process test's ``lit=True`` (``tests/acceptance/procs.py``'s launcher) does
nothing too.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def lit() -> Iterator[None]:
    """Nothing: every M8 policy field is served (step 18)."""
    yield
