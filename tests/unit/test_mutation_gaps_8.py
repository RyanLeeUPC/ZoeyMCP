"""The mutants left alive on purpose in M8's modules (M8 design O.7; BP-15): from step 5, those of
the frame and the ledger format (``common.approvaltext``, ``common.ledgerformat``), which M8
changes for security reasons and step 5 gives their first floor, and of the modules each later
step floors.

The killing tests are in each module's own test file (``test_approvaltext.py``,
``test_ledgerformat.py``, ...). The mutants no test can tell from the original are in
:data:`EQUIVALENT`, each with why; :func:`test_each_equivalent_names_a_function` keeps the list
honest when a function is renamed or removed. mutmut still counts them as survivors, so they stay
in each module's score.
"""

from __future__ import annotations

import importlib
from typing import Final

EQUIVALENT: Final[dict[str, str]] = {}


def _function(key: str) -> tuple[str, str, str | None]:
    """A mutant key's module, function and class (None for a module-level function)."""
    path, _, _ = key.partition("__mutmut_")
    if "x\u01c1" in path:
        module, _, rest = path.partition(".x\u01c1")
        cls, _, name = rest.partition("\u01c1")
        return module, name, cls
    module, _, name = path.rpartition(".x_")
    return module, name, None


def test_each_equivalent_names_a_function() -> None:
    """One test over the whole list, so a key holding mutmut's class marker makes no node ID."""
    for key in sorted(EQUIVALENT):
        module_name, name, cls = _function(key)
        owner: object = importlib.import_module(module_name)
        if cls is not None:
            owner = getattr(owner, cls)
        assert callable(getattr(owner, name)), key


def test_a_key_is_read_as_mutmut_writes_it() -> None:
    """The reader above, on a module function's key and a method's."""
    assert _function("zoeymcp.common.ledgerformat.x_via__mutmut_3") == (
        "zoeymcp.common.ledgerformat",
        "via",
        None,
    )
    method = "zoeymcp.common.approvaltext.x\u01c1Header\u01c1render__mutmut_1"
    assert _function(method) == ("zoeymcp.common.approvaltext", "render", "Header")
