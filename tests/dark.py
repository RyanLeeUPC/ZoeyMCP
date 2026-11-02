"""The switch for M8's dark-built policy fields (M8 design A.2 row 0, G-2, BP-2).

``check`` refuses every new M8 field while ``check._DARK`` lists it, so a cut anywhere before
step 18 leaves M8 shippable. :func:`lit` empties the table for one test, so steps 5-17 test the
fields and their rows; it lives here, not in a conftest, because a conftest applies only to its
own directory and ``tests/unit``, ``tests/gateway``, ``tests/portal`` and ``tests/acceptance`` all
need it. A process test passes ``lit=True`` to ``tests/acceptance/procs.py``'s launcher instead,
which empties the table in the fresh interpreter. Step 18 deletes the table; this then does
nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from types import MappingProxyType

import pytest

from zoeymcp.common.policy import check


@contextmanager
def lit() -> Iterator[None]:
    """``check`` with no field dark, until the block ends."""
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(check, "_DARK", MappingProxyType({}))
        yield
