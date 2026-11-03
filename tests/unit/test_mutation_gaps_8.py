"""The mutants left alive on purpose in M8's modules (M8 design O.7; BP-15): from step 5, those of
the frame and the ledger format (``common.approvaltext``, ``common.ledgerformat``), which M8
changes for security reasons and step 5 gives their first floor, and of the modules each later
step floors; from step 22, those on the lines M8 added to the earlier modules it grew, which hold
their floors (``vault.internal``, ``common.policy.check``, ``common.policy.plan``,
``vault.ledgerview``).

The killing tests are in each module's own test file (``test_approvaltext.py``,
``test_ledgerformat.py``, ``test_internal.py``, ``test_policy.py``, ``test_policy_plan.py``,
``test_ledgerview.py``, ...). The mutants no test can tell from the original are in
:data:`EQUIVALENT`, each with why; :func:`test_each_equivalent_names_a_function` keeps the list
honest when a function is renamed or removed. mutmut still counts them as survivors, so they stay
in each module's score.
"""

from __future__ import annotations

import importlib
from typing import Final

EQUIVALENT: Final[dict[str, str]] = {
    # --- common.policy.check (step 22)
    "zoeymcp.common.policy.check.x__check_vault_approval__mutmut_30": (
        '`route.upstream or "XXXX"`: a route without a connector always has an upstream (the '
        "schema refuses one with neither), so the fallback is never read"
    ),
    # --- common.policy.plan (step 22)
    "zoeymcp.common.policy.plan.x_closed_set__mutmut_13": (
        "`servers = ...` for `servers |= ...`: routes only grows, so the writers of every route "
        "so far already hold the ones gathered before"
    ),
    # --- vault.ledgerview (step 22)
    "zoeymcp.vault.ledgerview.x__row__mutmut_101": (
        "verdict(..., None) for the vault's decision: verdict tells writers apart only by "
        '`writer == "gateway"`, and None is no more the gateway than "vault" is'
    ),
    "zoeymcp.vault.ledgerview.x__row__mutmut_106": (
        'verdict(..., "XXvaultXX")'
        " for the vault's decision: verdict tells writers apart only by "
        '`writer == "gateway"`'
    ),
    "zoeymcp.vault.ledgerview.x__row__mutmut_107": (
        'verdict(..., "VAULT")'
        " for the vault's decision: verdict tells writers apart only by "
        '`writer == "gateway"`'
    ),
    "zoeymcp.vault.ledgerview.x_coverage__mutmut_2": (
        '`first = ""` for None: first is set on the first record, and with none coverage returns '
        "Coverage() without reading it"
    ),
    "zoeymcp.vault.ledgerview.x_coverage__mutmut_3": (
        "`held = None` for `held = False`: held is only ever read as `not held`, and both are falsy"
    ),
    "zoeymcp.vault.ledgerview.x_page__mutmut_97": (
        '`began = ""` for None: began stays unset only when held lists no file, and then the live '
        "chain has no record, so coverage never reads it"
    ),
}


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
