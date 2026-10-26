"""The mutants left alive on purpose in M6's modules: the strict YAML loader (step 1,
``common.yamlload``), the change a review makes (step 8, ``common.policy.reviewchange``, whose
``definition_lines`` moved from ``portal.reviewview`` with its two equivalents), the ratchet's
plain form (step 11b, ``common.policy.ratchet``), the planner and the change's managed ops
(step 12a, ``common.policy.plan`` and ``common.policy.change``, whose earlier equivalents stay in
``test_mutation_gaps_6.py``), the host's export (step 12b, ``common.policy.export``), and the
gateway modules prompts and resources touched (step 25: ``gateway.sanitize``, which gets its
first floor, ``gateway.access`` and ``gateway.connstate``).

The loader's killing tests are in ``test_yamlload.py``, the export's in ``test_policy_export.py``,
the gateway's in ``test_sanitize.py``, ``test_access.py`` and ``test_connstate.py``.
The mutants no test can tell from the original are in :data:`EQUIVALENT`, each with why;
:func:`test_each_equivalent_names_a_function` keeps the list honest when a function is renamed or
removed. mutmut still counts them as survivors, so they stay in each module's score.
"""

from __future__ import annotations

import base64
import importlib
from typing import Final

import pytest
from hypothesis import given
from hypothesis import strategies as st
from mcp.types import (
    AudioContent,
    EmbeddedResource,
    ImageContent,
    ResourceLink,
    TextContent,
    TextResourceContents,
)
from pydantic import BaseModel

from zoeymcp.common import canonical
from zoeymcp.gateway import access, sanitize

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
_TYPE: Final = (
    "a content block built without its type: each block model's type is a one-value Literal "
    "defaulting to that value, and the SDK's runner dumps a handler's result model with "
    "exclude_none, not exclude_unset (runner._dump_result), before the envelope is written, so "
    "the block on the wire is the same"
)
_DECODES: Final = (
    "valid_base64's decode with validate None, False or left out, or its except returning True: "
    "_BASE64 has already matched whole padded quads of the base64 alphabet, which b64decode "
    "decodes alike in every mode and never refuses, so the except never runs"
)
_ONE_LESS: Final = "a missing count read as 1, not 0: one less is 0, and max(0, -1) is 0 too"

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
    # A set server's prompts and resources blocks (M6 step 21a), dumped as the rest of the change.
    "zoeymcp.common.policy.change.xǁPolicyChangeǁ_data__mutmut_64": _MODE,
    "zoeymcp.common.policy.change.xǁPolicyChangeǁ_data__mutmut_65": _MODE,
    "zoeymcp.common.policy.change.xǁPolicyChangeǁ_data__mutmut_66": _MODE,
    # --- common.policy.plan
    # Renumbered in M6 step 21a (a save's prompt and resource includes and declines came first):
    # _permits 59, 70 and 79. _pins_added's 27 and 29 (an added server's review with no default)
    # went: a toolkit added whole has no prompts or resources block, which the default reads, so
    # test_policy_plan.py's added-whole test kills them.
    "zoeymcp.common.policy.plan.x__permits__mutmut_67": (
        "`or` for `and` in tool.allow's permit: required_kind makes a write tool.allow only when "
        "its diff is one move, two Tools changes, and of those only the allow addition is wider, "
        "the one change asked about, for which both are true"
    ),
    "zoeymcp.common.policy.plan.x__permits__mutmut_78": (
        "`or` for `and` in connector.limits' permit: required_kind makes a write connector.limits "
        "only when every change is to one SMTPConnector's CONNECTOR_LIMITS fields, so both halves "
        "are true for every change asked about"
    ),
    "zoeymcp.common.policy.plan.x__permits__mutmut_87": (
        "`or` for `and` in client.servers' permit: every change of a client.servers write is a "
        "Client's servers (required_kind), as mutant 78"
    ),
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
    # --- gateway.sanitize (judged in M6 step 25, on fdd4100's run)
    "zoeymcp.gateway.sanitize.x__link__mutmut_35": _TYPE,
    "zoeymcp.gateway.sanitize.x__media__mutmut_20": _TYPE,
    "zoeymcp.gateway.sanitize.x__media__mutmut_28": _TYPE,
    "zoeymcp.gateway.sanitize.x__media__mutmut_35": _TYPE,
    "zoeymcp.gateway.sanitize.x_map_upstream__mutmut_7": _TYPE,
    "zoeymcp.gateway.sanitize.x_sanitize_prompt__mutmut_18": (
        "`revealed = ...` for `+=` on the description: it is counted first, while revealed is "
        "still 0"
    ),
    "zoeymcp.gateway.sanitize.x_sanitize_prompt__mutmut_43": _TYPE,
    "zoeymcp.gateway.sanitize.x_sanitize_prompt__mutmut_68": _TYPE,
    "zoeymcp.gateway.sanitize.x_sanitize_result__mutmut_41": _TYPE,
    "zoeymcp.gateway.sanitize.x_sanitize_result__mutmut_60": _TYPE,
    "zoeymcp.gateway.sanitize.x_valid_base64__mutmut_5": _DECODES,
    "zoeymcp.gateway.sanitize.x_valid_base64__mutmut_7": _DECODES,
    "zoeymcp.gateway.sanitize.x_valid_base64__mutmut_8": _DECODES,
    "zoeymcp.gateway.sanitize.x_valid_base64__mutmut_9": _DECODES,
    # --- gateway.access (judged in M6 step 25)
    "zoeymcp.gateway.access.x_bearer_token__mutmut_5": (
        "rpartition for partition: a token holds no space (_TOKEN), so with one space both "
        "split alike, and with more the token or the scheme holds a space and is refused"
    ),
    "zoeymcp.gateway.access.x_host_name__mutmut_8": (
        '`end <= 0` for `end < 0`: the header starts with "[", so its "]" is never at 0'
    ),
    "zoeymcp.gateway.access.x_host_name__mutmut_9": "`end < 1`: as mutant 8",
    "zoeymcp.gateway.access.x_host_name__mutmut_20": (
        "the bracketless IPv6 check weakened: a port holding a colon then fails _PORT, which "
        "holds no colon, so the header is refused either way"
    ),
    "zoeymcp.gateway.access.x_parse_message__mutmut_15": (
        "loads_strict's max_depth left to its default: DEFAULT_MAX_DEPTH and MAX_BODY_DEPTH are "
        "both 64"
    ),
    "zoeymcp.gateway.access.x_source_allowed__mutmut_14": (
        "strict=None for strict=False: ip_network only tests strict for truth"
    ),
    "zoeymcp.gateway.access.xǁClientCountersǁrelease__mutmut_12": _ONE_LESS,
    "zoeymcp.gateway.access.xǁClientCountersǁrelease__mutmut_25": _ONE_LESS,
    "zoeymcp.gateway.access.xǁClientCountersǁrelease_reply__mutmut_7": (
        "a missing slot count read as 1: left is 0 rather than -1, and both pop the slot"
    ),
    "zoeymcp.gateway.access.xǁSessionBindingsǁbegin__mutmut_10": (
        "begin's last_seen None: the idle clock is read only with nothing in flight, and the end "
        "that brings the count back to 0 sets last_seen"
    ),
    "zoeymcp.gateway.access.xǁSessionBindingsǁbind__mutmut_22": (
        "return for break: nothing follows the eviction loop"
    ),
    # --- gateway.connstate (judged in M6 step 25)
    "zoeymcp.gateway.connstate.x_connection_key__mutmut_4": (
        'the asserted era copied even when it is "auto": an era of "auto" is neither modern nor '
        "legacy, so the client gets its own connection, as with no era"
    ),
    "zoeymcp.gateway.connstate.x_connection_key__mutmut_5": "as mutant 4",
    "zoeymcp.gateway.connstate.x_on_connecting__mutmut_4": (
        "the phase left to its default, which is Phase.CONNECTING"
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


_DATA: Final = base64.b64encode(b"data").decode()


@pytest.mark.parametrize(
    ("block", "kind"),
    [
        (TextContent(text="a"), "text"),
        (ImageContent(data=_DATA, mime_type="image/png"), "image"),
        (AudioContent(data=_DATA, mime_type="audio/wav"), "audio"),
        (EmbeddedResource(resource=TextResourceContents(uri="a://b", text="x")), "resource"),
        (ResourceLink(name="n", uri="a://b"), "resource_link"),
    ],
    ids=["text", "image", "audio", "resource", "resource_link"],
)
def test_a_blocks_type_defaults_to_its_one_value(block: BaseModel, kind: str) -> None:
    # _TYPE's reason, checked: a block built without its type is dumped as the SDK's runner
    # dumps a result, with its type, the same as the block built with it.
    model = type(block)
    assert "type" not in block.model_fields_set
    assert model.model_fields["type"].default == kind
    dumped = block.model_dump(by_alias=True, mode="json", exclude_none=True)
    assert dumped["type"] == kind
    typed = model.model_validate(dumped)
    assert "type" in typed.model_fields_set
    assert typed.model_dump(by_alias=True, mode="json", exclude_none=True) == dumped


@given(st.from_regex(sanitize._BASE64, fullmatch=True))
def test_what_the_base64_pattern_takes_decodes_in_every_mode(data: str) -> None:
    # _DECODES's reason, checked.
    assert base64.b64decode(data, validate=True) == base64.b64decode(data, validate=False)
    assert sanitize.valid_base64(data)


def test_the_body_depth_is_the_parsers_default() -> None:
    # The reason access's parse_message mutant 15 gives, checked.
    assert access.MAX_BODY_DEPTH == canonical.DEFAULT_MAX_DEPTH == 64
