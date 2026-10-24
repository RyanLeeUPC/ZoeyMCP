"""The mutants left alive on purpose in M6's modules: the strict YAML loader (step 1,
``common.yamlload``), the change a review makes (step 8, ``common.policy.reviewchange``, whose
``definition_lines`` moved from ``portal.reviewview`` with its two equivalents), the ratchet's
plain form (step 11b, ``common.policy.ratchet``), the planner and the change's managed ops
(step 12a, ``common.policy.plan`` and ``common.policy.change``, whose earlier equivalents stay in
``test_mutation_gaps_6.py``), and the host's export (step 12b, ``common.policy.export``).

The loader's killing tests are in ``test_yamlload.py``, the export's in ``test_policy_export.py``.
The mutants no test can tell from the original are in :data:`EQUIVALENT`, each with why;
:func:`test_each_equivalent_names_a_function` keeps the list honest when a function is renamed or
removed. mutmut still counts them as survivors, so they stay in each module's score.
"""

from __future__ import annotations

import importlib
from typing import Final

import pytest

_MODE: Final = (
    "model_dump in python mode (any mode but json is python mode) for json mode: the policy's "
    "models hold only strings, numbers, booleans, None, lists and mappings, which both modes "
    "dump alike"
)
_ADMIN: Final = (
    "the head's admin dumped in python mode or without by_alias: Admin holds only listen and "
    "origins, strings and a list of strings with no alias, which every such dump writes alike"
)
_MOVE_TOOLS: Final = (
    "the move's tools block left out of the replaced paths: _moved writes all three of Tools' "
    "fields, each a list the merge replaces whole when it differs, so merging the block leaves "
    "what replacing it does"
)
_ONE_COLON: Final = (
    'a revive\'s subject is "client:<name>" or "caller:<route>/<index>", and a client\'s or a '
    "route's name is a policy name, which holds no colon, so every split of it is the same"
)
_HAS_DEFINITION: Final = (
    "the definition looked up with no () default at rule 5: from the portal every move and kept "
    "allow counted there has one (allow_needs_review held each to it, and a portal rollback has "
    "none: rule 2 refused its moves, and its carried pins re-pin no allow tool)"
)
_PLAIN: Final = (
    'a target default other than "plain": the target is only ever compared with "compose", in '
    "export and in emit's document, so any other default writes the plain form"
)
_MANAGED: Final = (
    'a mode default other than "managed": notes only compares the mode with "declarative", so '
    "any other default writes the managed notes"
)

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
    # --- common.policy.change
    "zoeymcp.common.policy.change.x__declined_written__mutmut_18": (
        "the rewritten change's title None: apply, its only caller, reads the change's ops, "
        "never its title"
    ),
    "zoeymcp.common.policy.change.x_apply__mutmut_37": _MOVE_TOOLS,
    "zoeymcp.common.policy.change.x_apply__mutmut_38": _MOVE_TOOLS,
    "zoeymcp.common.policy.change.x_apply__mutmut_39": _MOVE_TOOLS,
    "zoeymcp.common.policy.change.x_apply__mutmut_40": _MOVE_TOOLS,
    "zoeymcp.common.policy.change.x_apply__mutmut_41": _MOVE_TOOLS,
    "zoeymcp.common.policy.change.x_apply__mutmut_42": _MOVE_TOOLS,
    # --- common.policy.plan
    "zoeymcp.common.policy.plan.x__permits__mutmut_59": (
        "`or` for `and` in tool.allow's permit: required_kind makes a write tool.allow only when "
        "its diff is one move, two Tools changes, and of those only the allow addition is wider, "
        "the one change asked about, for which both are true"
    ),
    "zoeymcp.common.policy.plan.x__permits__mutmut_70": (
        "`or` for `and` in connector.limits' permit: required_kind makes a write connector.limits "
        "only when every change is to one SMTPConnector's CONNECTOR_LIMITS fields, so both halves "
        "are true for every change asked about"
    ),
    "zoeymcp.common.policy.plan.x__permits__mutmut_79": (
        "`or` for `and` in client.servers' permit: every change of a client.servers write is a "
        "Client's servers (required_kind), as mutant 70"
    ),
    "zoeymcp.common.policy.plan.x__pins_added__mutmut_27": (
        "an added server's review read with no {} default: the change's value is the server's "
        "model dumped with every default filled in (diff._plain), so it always holds review"
    ),
    "zoeymcp.common.policy.plan.x__pins_added__mutmut_29": "no default: as mutant 27",
    "zoeymcp.common.policy.plan.x__refused__mutmut_73": _ONE_COLON,
    "zoeymcp.common.policy.plan.x__refused__mutmut_74": _ONE_COLON,
    "zoeymcp.common.policy.plan.x__refused__mutmut_76": _ONE_COLON,
    "zoeymcp.common.policy.plan.x__widening__mutmut_13": (
        "`path[1:3]` for `path[1:2]`: each is empty exactly when the path has no second part, "
        "all the test asks"
    ),
    "zoeymcp.common.policy.plan.x__widening__mutmut_45": (
        "a client's token field misspelled: plan diffs normalized policies, and normalize writes "
        "every literal token as its token_sha256, so no change is to a client's token"
    ),
    "zoeymcp.common.policy.plan.x__widening__mutmut_46": "as mutant 45",
    "zoeymcp.common.policy.plan.x_carry_forward__mutmut_19": _ADMIN,
    "zoeymcp.common.policy.plan.x_carry_forward__mutmut_20": _ADMIN,
    "zoeymcp.common.policy.plan.x_carry_forward__mutmut_21": _ADMIN,
    "zoeymcp.common.policy.plan.x_carry_forward__mutmut_22": _ADMIN,
    "zoeymcp.common.policy.plan.x_carry_forward__mutmut_23": _ADMIN,
    "zoeymcp.common.policy.plan.x_carry_forward__mutmut_24": _ADMIN,
    "zoeymcp.common.policy.plan.x_carry_forward__mutmut_25": _ADMIN,
    "zoeymcp.common.policy.plan.x_document__mutmut_2": _MODE,
    "zoeymcp.common.policy.plan.x_document__mutmut_5": _MODE,
    "zoeymcp.common.policy.plan.x_document__mutmut_9": _MODE,
    "zoeymcp.common.policy.plan.x_document__mutmut_10": _MODE,
    "zoeymcp.common.policy.plan.x_normalize__mutmut_2": _MODE,
    "zoeymcp.common.policy.plan.x_normalize__mutmut_5": _MODE,
    "zoeymcp.common.policy.plan.x_normalize__mutmut_8": _MODE,
    "zoeymcp.common.policy.plan.x_normalize__mutmut_9": _MODE,
    "zoeymcp.common.policy.plan.x_plan__mutmut_252": (
        "the host's grants check run from the portal too: there it repeats rule 1c's own call "
        "(the portal's grants are already empty), which found nothing, or the plan had stopped"
    ),
    "zoeymcp.common.policy.plan.x_plan__mutmut_323": _HAS_DEFINITION,
    "zoeymcp.common.policy.plan.x_plan__mutmut_325": _HAS_DEFINITION,
    # --- common.policy.export
    "zoeymcp.common.policy.export.x_export__mutmut_3": _PLAIN,
    "zoeymcp.common.policy.export.x_export__mutmut_4": _PLAIN,
    "zoeymcp.common.policy.export.x_notes__mutmut_1": _MANAGED,
    "zoeymcp.common.policy.export.x_notes__mutmut_2": _MANAGED,
    "zoeymcp.common.policy.export.x_notes__mutmut_3": _PLAIN,
    "zoeymcp.common.policy.export.x_notes__mutmut_4": _PLAIN,
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
