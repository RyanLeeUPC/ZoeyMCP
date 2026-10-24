"""The mutants left alive on purpose in M6's modules: the strict YAML loader (step 1,
``common.yamlload``), the change a review makes (step 8, ``common.policy.reviewchange``, whose
``definition_lines`` moved from ``portal.reviewview`` with its two equivalents), and the
ratchet's plain form (step 11b, ``common.policy.ratchet``).

The loader's killing tests are in ``test_yamlload.py``. The mutants no test can tell from the
original are in :data:`EQUIVALENT`, each with why; :func:`test_each_equivalent_names_a_function`
keeps the list honest when a function is renamed or removed. mutmut still counts them as
survivors, so they stay in each module's score.
"""

from __future__ import annotations

import importlib
from typing import Final

import pytest

EQUIVALENT: Final[dict[str, str]] = {
    # --- common.yamlload
    "zoeymcp.common.yamlload.x_load_mapping__mutmut_8": (
        '`text.count("\\n", None, found.start())`: str.count takes None for its start as a '
        "slice does, the same as 0"
    ),
    # --- common.policy.reviewchange (moved from portal.reviewview's in step 8)
    "zoeymcp.common.policy.reviewchange.x_definition_lines__mutmut_7": (
        "ensure_ascii=True dropped: it is json.dumps' default"
    ),
    "zoeymcp.common.policy.reviewchange.x_definition_lines__mutmut_22": (
        '`or ["XXXX"]` for an empty line: json.dumps with an indent writes no empty line'
    ),
    # --- common.policy.ratchet
    "zoeymcp.common.policy.ratchet.x_loaded__mutmut_13": (
        "`zip(GENERATIONS, floors, strict=None)`: floors is built from GENERATIONS, one per "
        "generation, so the two are never of different lengths"
    ),
    "zoeymcp.common.policy.ratchet.x_loaded__mutmut_16": (
        "strict=True dropped from the floors' zip: floors is built from GENERATIONS, so the "
        "two are never of different lengths"
    ),
    "zoeymcp.common.policy.ratchet.x_loaded__mutmut_17": (
        "strict=False in the floors' zip: floors is built from GENERATIONS, so the two are "
        "never of different lengths"
    ),
}


def _function(key: str) -> tuple[str, str, str | None]:
    """A mutant key's module, function and class (None for a module-level function)."""
    path, _, _ = key.partition("__mutmut_")
    if "xǁ" in path:
        module, _, rest = path.partition(".xǁ")
        cls, _, name = rest.partition("ǁ")
        return module, name, cls
    module, _, name = path.rpartition(".x_")
    return module, name, None


@pytest.mark.parametrize("key", sorted(EQUIVALENT))
def test_each_equivalent_names_a_function(key: str) -> None:
    module_name, name, cls = _function(key)
    owner: object = importlib.import_module(module_name)
    if cls is not None:
        owner = getattr(owner, cls)
    assert callable(getattr(owner, name)), key


def test_count_takes_none_as_its_start() -> None:
    # The reason the one equivalent above gives, checked.
    text = "a\nb\nc"
    assert text.count("\n", None, 4) == text.count("\n", 0, 4) == 2
