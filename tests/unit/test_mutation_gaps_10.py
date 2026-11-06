"""Killing tests for the unread survivors of M6's modules above their floors (register D-221).

From run 42159911619 (71b27bd), the security-relevant ones first: ``common.policy.check`` (the
checks a policy must pass), ``common.policy.reviewchange`` (what a review writes, and which
``allow`` needs its definition recorded), ``cli.choices`` (the operator's choices file) and
``gateway.pins``. Each test names what it pins. The mutants left alive on purpose are in
:data:`EQUIVALENT`, each with why no test can tell it from the original (reviewchange's
``definition_lines`` 7 and 22 and check's ``_check_vault_approval`` 30 are in
``test_mutation_gaps_7.py`` and ``test_mutation_gaps_8.py``);
:func:`test_each_equivalent_names_a_function` keeps the list honest when a function is renamed or
removed. mutmut still counts them as survivors, so they stay in each module's score.

The last part is register D-86's re-check of the earlier lists under today's names: the M2 list
(commit 52ae364: tokens and login) and ``.git/m4-left.txt``; what still survives is killed below
or recorded in :data:`EQUIVALENT` with its reason. Of ``test_mutation_gaps_4.py``'s docstring, the
import-time tables are no longer left alive: ``test_mutation_gaps_9.py`` calls them directly.
"""

from __future__ import annotations

import copy
import importlib
from dataclasses import replace
from datetime import UTC, datetime
from email.message import EmailMessage
from email.policy import SMTP
from typing import Any, Final, Literal, TypedDict, get_args

import pytest
import yaml

from tests.unit.test_approvaltext import HEADER, MAIL_HEADER, MAIL_REQUEST, MAIL_SHOW
from tests.unit.test_policy import callback_findings, run, warnings
from tests.unit.test_review import reviewed
from tests.unit.test_review_choices import INDEX, INDEX_PIN, JOB, file_of, kind_edited, kinds
from tests.unit.test_reviewchange import (
    NEW_B,
    OLD_B,
    READ_ONLY,
    definition,
    drifting,
    entry,
    hinted,
    key,
    kind_entry,
    kinds_held,
    lines_of,
    op_of,
    pin_of,
    server,
)
from tests.unit.test_reviewview import held
from zoeymcp.cli import choices
from zoeymcp.common import canonical
from zoeymcp.common.approvaltext import (
    ApprovalText,
    Plan,
    Show,
    Write,
    problems,
    received,
    relayed,
    render_call,
    render_plan,
)
from zoeymcp.common.policy import check, parse_policy
from zoeymcp.common.policy.change import PolicyChange
from zoeymcp.common.policy.emit import emit
from zoeymcp.common.policy.match import RequestRejected
from zoeymcp.common.policy.reviewchange import (
    PROPOSED,
    Added,
    AllowRefused,
    Changes,
    Choices,
    KindChanges,
    definitions,
    fragment,
    kind_of,
    planned,
    suggested,
    verified,
)
from zoeymcp.common.policy.schema import SMTPConnector
from zoeymcp.common.textrules import find_violations
from zoeymcp.gateway import pins
from zoeymcp.toolkit import params, rules
from zoeymcp.vault.connectors import mailmsg

Raw = dict[str, Any]

_STORE_SCHEMA_HOST: Final = (
    "a route's upstream always has a host (the schema refuses one without: 'missing host'), so "
    "the fallback for a missing hostname is never read"
)
_NAME_PATTERN: Final = (
    'credentials.get(route.credential or "XXXX") for or "": a credential\'s name matches '
    "NAME_PATTERN, lower case only, so neither key names one"
)
_BRACKETS: Final = (
    "an egress entry with brackets is an IPv6 literal (the schema's _check_host_port), which "
    "untrusted_host refuses as ip_literal; what the mutant leaves (a bracket kept, or the part "
    "before the first colon) is refused as syntax, and without brackets rpartition and partition "
    "agree on host:port"
)
_DISTINCT: Final = (
    "the count is of distinct entries either way: two valid entries never share a host once "
    "the brackets are stripped (ASCII hosts are kept as written, already in lower case), and "
    "the mutant's hosts are as distinct, as is a private mark flipped for every entry"
)
_RESEED: Final = (
    "getattr(cred, 'reseed', ...)'s default: is_seed is true only for an OAuth2Credential's "
    "refresh_token, and that model always has reseed"
)
_UNUSED_WIDTH: Final = (
    "the column width's default when no row has a line: the width is read only for a row with "
    "a line"
)
_CAST: Final = "cast(None, word): typing.cast returns its value unchanged at run time"
_SPLIT: Final = "split('#') with no or another maxsplit: only the part before the first # is read"

_CLIENT_GRANT: Final = (
    "a client-credentials grant's binding or envelope changed: both are read only by _save, "
    "which runs only for a refresh grant (entry set)"
)
_UNIQUE_NAMES: Final = (
    "the fields sorted as whole tuples: a function's parameter names are unique, so the first "
    "item decides every comparison"
)
_CLEANDOC: Final = (
    "description's allow_tabs: inspect.cleandoc expands tabs first, so the text holds none"
)
_PARAM_NAME: Final = (
    "params' pointer escape: a field or parameter name is a lower-case identifier, with no ~ or /"
)
_ANY_VIOLATION: Final = (
    "max_reported dropped or 2: _text_problem reads only whether any violation is found"
)
_RENDERER_BUG: Final = (
    "the message of the renderer-bug assertion (marked no cover): _json_parts mirrors "
    "render_for_approval, so it never fires"
)
_SUBJECT_TAB: Final = (
    "the subject's allow_tabs None, dropped or True: single_line refuses a tab whatever "
    "allow_tabs says (checked below)"
)
_HANDLE_MAP: Final = (
    "pop(handle) with no default: a record's handle_sha256 is set exactly while _by_handle maps "
    "it (create, consume, reask, decide and sweep change both together), so it is there"
)
_FINISH: Final = (
    "finish deciding an undecided record as something other than error: the record is deleted "
    "next, and only COOLDOWN_DECISIONS (none of these) and timeout (a tombstone's reason) are "
    "read of it"
)
_CONSUMED: Final = (
    "decide(..., None) for now after consume: consume has cleared the handle, so decide buries "
    "none and never reads now"
)

EQUIVALENT: Final[dict[str, str]] = {
    # --- common.policy.check
    "zoeymcp.common.policy.check.x__check_callback__mutmut_30": (
        'ip_address("XXXX") for ip_address(""): both raise ValueError, and the check returns'
    ),
    "zoeymcp.common.policy.check.x__check_connector_use__mutmut_15": (
        "`break` for `continue` when there is no gateway: with no gateway no connector has a "
        "slot, so the loop has already continued at the no-slot warning"
    ),
    "zoeymcp.common.policy.check.x__check_oauth_refs__mutmut_60": (
        "other.get(ref, None): None and [] are both falsy, and the next line continues on either"
    ),
    "zoeymcp.common.policy.check.x__check_oauth_refs__mutmut_62": (
        "other.get(ref) with no default: None and [] are both falsy, and the next line "
        "continues on either"
    ),
    "zoeymcp.common.policy.check.x__check_program__mutmut_23": _BRACKETS,
    "zoeymcp.common.policy.check.x__check_program__mutmut_25": _BRACKETS,
    "zoeymcp.common.policy.check.x__check_program__mutmut_27": _BRACKETS,
    "zoeymcp.common.policy.check.x__check_program__mutmut_30": _BRACKETS,
    "zoeymcp.common.policy.check.x__check_program__mutmut_31": _BRACKETS,
    "zoeymcp.common.policy.check.x__check_route_query__mutmut_14": _NAME_PATTERN,
    "zoeymcp.common.policy.check.x__token_problems__mutmut_4": _NAME_PATTERN,
    "zoeymcp.common.policy.check.x__check_secret_refs__mutmut_49": _RESEED,
    "zoeymcp.common.policy.check.x__check_secret_refs__mutmut_52": _RESEED,
    "zoeymcp.common.policy.check.x__check_secret_refs__mutmut_55": _RESEED,
    "zoeymcp.common.policy.check.x__check_secret_refs__mutmut_56": _RESEED,
    "zoeymcp.common.policy.check.x__check_squid_names__mutmut_7": (
        'the skip for a route named "vault" lost (_check_program refuses that name): the Squid '
        "names of vault are short and neither src nor port, so the checks find nothing for it"
    ),
    "zoeymcp.common.policy.check.x__check_squid_names__mutmut_8": (
        'the skip for a route named "vault" lost (_check_program refuses that name): the Squid '
        "names of vault are short and neither src nor port, so the checks find nothing for it"
    ),
    "zoeymcp.common.policy.check.x__confined__mutmut_6": _STORE_SCHEMA_HOST,
    "zoeymcp.common.policy.check.x__local_mcp_problems__mutmut_10": _STORE_SCHEMA_HOST,
    "zoeymcp.common.policy.check.x__local_upstream__mutmut_12": _STORE_SCHEMA_HOST,
    "zoeymcp.common.policy.check.x__env_seeded__mutmut_3": (
        '"XXXX" for "" when there is no refresh token: neither starts with env:'
    ),
    "zoeymcp.common.policy.check.x__program_destinations__mutmut_11": _DISTINCT,
    "zoeymcp.common.policy.check.x__program_destinations__mutmut_13": _DISTINCT,
    "zoeymcp.common.policy.check.x__program_destinations__mutmut_14": _DISTINCT,
    "zoeymcp.common.policy.check.x__program_destinations__mutmut_15": _DISTINCT,
    "zoeymcp.common.policy.check.x__program_destinations__mutmut_18": _DISTINCT,
    # --- common.policy.reviewchange
    "zoeymcp.common.policy.reviewchange.x_kind_block__mutmut_95": (
        "_kept_why(None, ...) for a prompt or a resource: the server is named only in a tool's "
        "drift line, and kind_block holds no tool"
    ),
    "zoeymcp.common.policy.reviewchange.x_kind_block__mutmut_96": (
        "_kept_why(server, None, ...) for a prompt or a resource: the name is used only in a "
        "tool's drift line, and kind_block holds no tool"
    ),
    # --- cli.choices
    "zoeymcp.cli.choices.x__kind_line__mutmut_77": _CAST,
    "zoeymcp.cli.choices.x__line__mutmut_69": _CAST,
    "zoeymcp.cli.choices.x__kind_lines__mutmut_17": _UNUSED_WIDTH,
    "zoeymcp.cli.choices.x__kind_lines__mutmut_21": _UNUSED_WIDTH,
    "zoeymcp.cli.choices.x_render__mutmut_28": _UNUSED_WIDTH,
    "zoeymcp.cli.choices.x_render__mutmut_31": _UNUSED_WIDTH,
    "zoeymcp.cli.choices.x__line__mutmut_5": _SPLIT,
    "zoeymcp.cli.choices.x__line__mutmut_8": _SPLIT,
    "zoeymcp.cli.choices.x_parse__mutmut_20": (
        '"\\uFEFF" for "\\ufeff": the same one-character string'
    ),
    "zoeymcp.cli.choices.x_report_digest__mutmut_9": (
        "ensure_ascii=True dropped: it is json.dumps' default"
    ),
    "zoeymcp.cli.choices.x_report_digest__mutmut_20": (
        'the codec named "ASCII": Python looks codec names up case-blind'
    ),
    # --- gateway.pins
    "zoeymcp.gateway.pins.x_evaluate_server__mutmut_20": (
        "limits None for the kinds beyond tools: listings holds only those kinds, and "
        "definition_problems reads limits only for a tool's schemas"
    ),
    "zoeymcp.gateway.pins.x_text_problems__mutmut_22": (
        "allow_tabs=True dropped: it is find_violations' default"
    ),
    "zoeymcp.gateway.pins.x_text_problems__mutmut_6": (
        "_text_limits(path, None) for a key: the paths given a tighter limit end in name, "
        "title, mimeType or description, and a key there is that word, short and on one line"
    ),
    # --- D-86: the M2 list (commit 52ae364), read again under today's names; _read_slot 12 and
    # 13, __init__ 18 and login's _complete 35 are gone
    "zoeymcp.vault.oauth.tokens.xǁTokenManagerǁ__init____mutmut_8": (
        "`self._env = None` at first: every reader of _env takes a credential's config, which "
        "only configure makes, and configure sets _env first"
    ),
    "zoeymcp.vault.oauth.tokens.xǁTokenManagerǁ_meta_entry__mutmut_8": (
        "a client secret that isn't store: named as the meta entry anyway: its env:... or "
        "empty name is no store entry (store names hold no colon), so entry() is None and "
        "update_meta writes nothing"
    ),
    "zoeymcp.vault.oauth.tokens.xǁTokenManagerǁ_prepare__mutmut_29": (
        'live_hash "" at first for None: it keeps its first value only when the credential '
        "isn't seeded (its seed_hash is never written) or the slot is empty (the source is then "
        "the seed, whose hash replaces it, or none); decide_source compares it only after "
        "`is not None`, and no digest is empty"
    ),
    "zoeymcp.vault.oauth.tokens.xǁTokenManagerǁ_prepare_client_credentials__mutmut_58": (
        _CLIENT_GRANT
    ),
    "zoeymcp.vault.oauth.tokens.xǁTokenManagerǁ_prepare_client_credentials__mutmut_59": (
        _CLIENT_GRANT
    ),
    "zoeymcp.vault.oauth.tokens.xǁTokenManagerǁ_prepare_client_credentials__mutmut_74": (
        _CLIENT_GRANT
    ),
    "zoeymcp.vault.oauth.tokens.xǁTokenManagerǁ_start__mutmut_14": (
        '`slot.trigger = ""` for None: trigger is read only as `slot.trigger or ...`'
    ),
    "zoeymcp.vault.oauth.tokens.xǁTokenManagerǁpost__mutmut_25": (
        "follow_redirects=None for False: httpx takes the client's default only for "
        "USE_CLIENT_DEFAULT and reads any other value for its truth"
    ),
    "zoeymcp.vault.oauth.login.xǁLoginServiceǁ_test_fetch__mutmut_25": (
        "entry.binding read with no None check: _client has just resolved the store: client "
        "secret, refusing a missing one, with no await in between, so the entry is there"
    ),
    # --- D-86: .git/m4-left.txt, read again under today's names (the ledgerformat, sendjournal
    # and tunnel entries are test_mutation_gaps_9.py's; recovery_plan 16, 18 and 24 and
    # approvaltext's _frame_imitations 7 and 27 are gone)
    "zoeymcp.toolkit.params.x__node__mutmut_50": (
        "the message of a Literal listing a value twice: typing.Literal drops a repeated value, "
        "so the branch never runs"
    ),
    "zoeymcp.toolkit.params.x_parameters__mutmut_59": _UNIQUE_NAMES,
    "zoeymcp.toolkit.params.x_parameters__mutmut_61": _UNIQUE_NAMES,
    "zoeymcp.toolkit.params.x_description__mutmut_8": _CLEANDOC,
    "zoeymcp.toolkit.params.x_description__mutmut_12": _CLEANDOC,
    "zoeymcp.toolkit.params.x_description__mutmut_14": _CLEANDOC,
    "zoeymcp.toolkit.params.x__escape__mutmut_9": _PARAM_NAME,
    "zoeymcp.toolkit.params.x__escape__mutmut_10": _PARAM_NAME,
    "zoeymcp.toolkit.params.x__escape__mutmut_11": _PARAM_NAME,
    "zoeymcp.toolkit.params.x__escape__mutmut_12": _PARAM_NAME,
    "zoeymcp.toolkit.params.x__text_problem__mutmut_12": _ANY_VIOLATION,
    "zoeymcp.toolkit.params.x__text_problem__mutmut_13": _ANY_VIOLATION,
    "zoeymcp.toolkit.rules.x_join__mutmut_14": (
        'the codec named "ASCII": Python looks codec names up case-blind'
    ),
    "zoeymcp.common.approvaltext.xǁApprovalTextǁpointer_at__mutmut_1": (
        'found "" at first for None: the first run starts at offset 0 and problems asks only '
        "for offsets into the text, so the loop always sets it"
    ),
    "zoeymcp.common.approvaltext.xǁ_Builderǁjson__mutmut_16": _RENDERER_BUG,
    "zoeymcp.common.approvaltext.xǁ_Builderǁjson__mutmut_17": _RENDERER_BUG,
    "zoeymcp.common.approvaltext.xǁ_Builderǁjson__mutmut_18": _RENDERER_BUG,
    "zoeymcp.common.approvaltext.xǁ_Builderǁjson__mutmut_19": _RENDERER_BUG,
    "zoeymcp.common.approvaltext.xǁWriteǁ_build__mutmut_39": (
        "max_bytes len + 2 for len + 1: the frozen body is len bytes, under both"
    ),
    "zoeymcp.common.approvaltext.x__render_write__mutmut_51": (
        "`first = None` for False: it is read only for its truth"
    ),
    "zoeymcp.common.approvaltext.x_problems__mutmut_6": (
        "over_budget sorted at -2 for -1: both come before every offset in the text"
    ),
    "zoeymcp.common.approvaltext.x_problems__mutmut_19": (
        "allow_tabs=True dropped: it is find_violations' default"
    ),
    "zoeymcp.common.approvaltext.x__frame_imitations__mutmut_6": (
        "a frame imitation sorted one offset on: a line that imitates the frame starts with "
        "whitespace and a prefix of one run, so the pointer is the same, and no other rule can "
        "start a problem at the second character of that whitespace and prefix"
    ),
    "zoeymcp.vault.connectors.mailmsg.x_parse_send__mutmut_11": (
        "loads_strict with its default max_bytes: parse_send has already refused a body over "
        "MAX_BODY_BYTES (64 KiB), under the default"
    ),
    "zoeymcp.vault.connectors.mailmsg.x_parse_send__mutmut_60": _SUBJECT_TAB,
    "zoeymcp.vault.connectors.mailmsg.x_parse_send__mutmut_65": _SUBJECT_TAB,
    "zoeymcp.vault.connectors.mailmsg.x_parse_send__mutmut_68": _SUBJECT_TAB,
    "zoeymcp.vault.connectors.mailmsg.x_parse_send__mutmut_103": (
        "allow_tabs=True dropped: it is find_violations' default"
    ),
    "zoeymcp.vault.connectors.mailmsg.x_domain_of__mutmut_2": (
        "partition for rpartition on @: the schema's address pattern holds exactly one @"
    ),
    "zoeymcp.vault.connectors.mailmsg.x_build_message__mutmut_2": (
        "EmailMessage(policy=None), the default policy: data_bytes serializes with SMTP, and "
        "the bytes are the same (test_the_message_policy_doesnt_change_the_bytes)"
    ),
    "zoeymcp.vault.connectors.mailmsg.x_build_message__mutmut_46": (
        'set_content without subtype: "plain" is its default for a str'
    ),
    "zoeymcp.vault.connectors.mailmsg.x_build_message__mutmut_47": (
        'set_content without charset: "utf-8" is its default for a str'
    ),
    "zoeymcp.vault.connectors.mailmsg.x_data_bytes__mutmut_2": (
        "as_bytes(policy=None): the message's own policy, SMTP, which build_message gave it"
    ),
    "zoeymcp.vault.connectors.mailmsg.x_data_bytes__mutmut_6": (
        "`lines or` for `lines and`: split always returns a list, and the message always ends "
        "with CRLF, so its last part is empty either way"
    ),
    "zoeymcp.gateway.approvals.x_new_handle__mutmut_5": (
        "secrets.token_bytes(None): 32 bytes, its default"
    ),
    "zoeymcp.gateway.approvals.x_new_handle__mutmut_7": (
        "rstrip of X as well as =: the last character of 32 bytes in base64 carries two zero "
        "bits, and X's index (23) doesn't end in two"
    ),
    "zoeymcp.gateway.approvals.xǁTableǁget__mutmut_4": (
        "_by_key.get(None): no key is None, so it is None as the original's"
    ),
    "zoeymcp.gateway.approvals.xǁTableǁreask__mutmut_6": _HANDLE_MAP,
    "zoeymcp.gateway.approvals.xǁTableǁdecide__mutmut_7": _HANDLE_MAP,
    "zoeymcp.gateway.approvals.xǁTableǁsweep__mutmut_8": _HANDLE_MAP,
    "zoeymcp.gateway.approvals.xǁTableǁfinish__mutmut_10": _FINISH,
    "zoeymcp.gateway.approvals.xǁTableǁfinish__mutmut_15": _FINISH,
    "zoeymcp.gateway.approvals.xǁTableǁfinish__mutmut_16": _FINISH,
    "zoeymcp.gateway.approvals.x_retry__mutmut_26": _CONSUMED,
    "zoeymcp.gateway.approvals.x_retry__mutmut_36": _CONSUMED,
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


def test_each_equivalent_names_a_function() -> None:
    """One test over the whole list, so a key holding mutmut's class marker makes no node ID."""
    for key_ in sorted(EQUIVALENT):
        module_name, name, cls = _function(key_)
        owner: object = importlib.import_module(module_name)
        if cls is not None:
            owner = getattr(owner, cls)
        assert callable(getattr(owner, name)), key_


# --- common.policy.check ------------------------------------------------------------------------


def findings(raw: Raw, environ: dict[str, str] | None = None) -> list[str]:
    return [f"{f.level} {f.path}: {f.message}" for f in run(raw, environ)]


def test_the_longest_prompt_timeout_is_allowed(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["approvals"]["timeout"] = check.MAX_ELICITATION_TIMEOUT
    assert [f for f in findings(raw) if "gateway.approvals.timeout" in f] == [
        "warning gateway.approvals.timeout: some clients end a tool call sooner; see the client "
        "notes"
    ]


def test_a_portless_callback_isnt_matched_to_a_portless_origin() -> None:
    # The 127.0.0.1 hint is only for a callback with a port, on an origin with that port.
    assert callback_findings("http://127.0.0.1/callback", ("http://localhost",)) == []


def test_a_connector_rule_names_every_endpoint_it_cant_answer(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["routes"][2]["rules"] = [{"methods": ["GET", "PUT"], "paths": ["/config", "/x"]}]
    assert (
        "error routes[2].rules[0]: a connector answers only GET /config and POST /send, not "
        "GET /x, PUT /config, PUT /x"
    ) in findings(raw)


def _spare(raw: Raw) -> Raw:
    spare: Raw = copy.deepcopy(raw["connectors"]["mail-out"])
    spare["password"] = "store:spare-pass"
    return spare


def test_an_unused_connector_says_so(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["connectors"]["spare"] = _spare(raw)
    assert "warning connectors.spare: not used by any route" in findings(raw)


def _prompt_size(raw: Raw) -> int:
    """check's estimate for agent1's prompt for mail's send_note on the mail-out connector."""
    policy = parse_policy(yaml.safe_dump(raw, sort_keys=False), "test")
    conn = policy.connectors["mail-out"]
    values = (
        conn.max_subject_chars
        + conn.max_body_chars
        + len(conn.from_)
        + len(canonical.dumps_canonical(list(conn.to)))
    )
    names = len("agent1") + len("mail") + len("send_note")
    return check.PROMPT_FRAME_CHARS + names + check.PROMPT_REPLY_LINE_CHARS + values


def size_warnings(raw: Raw) -> list[str]:
    return [w for w in warnings(run(raw)) if "can't be approved" in w]


def test_a_prompt_exactly_at_the_budget_fits(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["approvals"]["budget_chars"] = _prompt_size(raw)
    assert size_warnings(raw) == []


def _one_over(raw: Raw) -> list[str]:
    size = _prompt_size(raw)
    raw["gateway"]["approvals"]["budget_chars"] = size - 1
    return [
        f"connectors.mail-out: a message near these limits can't be approved by 'agent1' "
        f"(about {size} characters, budget {size - 1}); lower max_body_chars"
    ]


def test_a_prompt_one_over_the_budget_warns_with_its_size(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    expected = _one_over(raw)
    assert size_warnings(raw) == expected


def test_the_estimate_goes_on_past_a_client_with_no_prompts(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    expected = _one_over(raw)
    raw["gateway"]["clients"] = {
        "a0": {"token_sha256": "sha256:" + "1" * 64, "servers": ["broker-read"]},
        **raw["gateway"]["clients"],
    }
    assert size_warnings(raw) == expected


def test_the_estimate_goes_on_past_a_server_the_client_lacks(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    expected = _one_over(raw)
    servers = raw["gateway"]["servers"]
    raw["gateway"]["servers"] = {"a-mail": copy.deepcopy(servers["mail"]), **servers}
    assert size_warnings(raw) == expected


def test_the_estimate_goes_on_past_a_connector_with_no_slot(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    expected = _one_over(raw)
    raw["connectors"] = {"a-spare": _spare(raw), **raw["connectors"]}
    assert size_warnings(raw) == expected


def test_a_secret_holding_program_names_every_private_entry(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    private = ["a.example:443", "b.example:443"]
    raw["routes"][0]["program"] = {
        "egress": private,
        "egress_private": list(private),  # a list of its own: the loader refuses YAML aliases
        "holds_secret": True,
    }
    assert (
        "error routes[0].program.holds_secret: a program holding a real secret may reach no "
        "private address: a.example:443, b.example:443 is in egress_private"
    ) in findings(raw)


def test_the_gateway_only_callers_error_says_why(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["routes"][1]["callers"] = [{"placeholder": "ph-sandbox-broker-0001"}]
    assert (
        "error routes[1].callers: a route used by a gateway server must accept only the gateway, "
        "so the tool filter can't be bypassed"
    ) in findings(raw)


def test_every_env_connector_password_is_refused_in_full(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["connectors"]["mail-out"]["password"] = "env:MAIL_PASS"
    raw["connectors"]["spare"] = {**_spare(raw), "password": "env:SPARE_PASS"}
    said = (
        "a connector password must come from the store, where it is bound to the connector's "
        "host, port, from and to; enter it with zoeymcp secret set"
    )
    found = findings(raw)
    assert f"error connectors.mail-out.password: {said}" in found
    assert f"error connectors.spare.password: {said}" in found


def test_an_on_change_seed_says_what_a_change_does(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["credentials"]["broker-mcp"].update(refresh_token="env:BROKER_SEED", reseed="on-change")
    assert (
        "warning credentials.broker-mcp.refresh_token: refresh token seeded from env var "
        "BROKER_SEED: the live token is kept in the store as oauth.broker-mcp.live, and a changed "
        "env value replaces the live token (reseed: on-change); zoeymcp secret delete "
        "oauth.broker-mcp.live forces a re-seed"
    ) in findings(raw)


def test_the_slot_checks_go_on_past_an_unknown_route(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["mail"]["slots"] = {
        name: {"route": route, "rules": [{"methods": ["GET"], "paths": ["/mcp"]}]}
        for name, route in (("a", "nope"), ("z", "broker-mcp"))
    }
    found = findings(raw)
    assert "error gateway.servers.mail.slots.a.route: unknown route 'nope'" in found
    assert (
        "error gateway.servers.mail.slots.z.route: a toolkit must not speak raw MCP to a "
        "reviewed server"
    ) in found


def test_a_line_break_matters_only_in_an_injected_secret(example_raw: Raw) -> None:
    # A connector's username is sent in SMTP AUTH, never injected into an upstream's request.
    raw = copy.deepcopy(example_raw)
    raw["connectors"]["mail-out"]["username"] = "env:SMTP_USER"
    found = findings(raw, {"SMTP_USER": "a\nb"})
    assert [f for f in found if "SMTP_USER" in f] == [
        "warning connectors.mail-out.username: secret read from env var SMTP_USER: it isn't "
        "encrypted at rest or bound to its origins; prefer store:<name>"
    ]


def test_a_shared_adapter_token_names_every_other_route(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["credentials"]["tok"] = {"kind": "header", "header": "Authorization", "secret": "store:tok"}
    raw["routes"][1].update(
        upstream="http://adapter:8080", allow_insecure_upstream=True, credential="tok"
    )
    for i in (1, 2):
        raw["routes"].append(
            {
                "name": f"r{i}",
                "prefix": f"/r{i}",
                "upstream": "https://api.example",
                "credential": "tok",
                "callers": [{"placeholder": f"ph-route-{i}-0123456789"}],
                "rules": [{"methods": ["GET"], "paths": ["/x"]}],
            }
        )
    assert (
        f"error routes[1].upstream: tok is also route r1, r2's credential: {check._LOCAL_ONLY}"
    ) in findings(raw)


def test_a_connector_password_is_no_seed(example_raw: Raw) -> None:
    policy = parse_policy(yaml.safe_dump(example_raw, sort_keys=False), "test")
    assert check.secret_references(policy)[-1] == (
        "connectors.mail-out.password",
        "store:mail-pass",
        False,
    )


# --- common.policy.reviewchange -----------------------------------------------------------------

_ELSEWHERE = "sha256:" + "f" * 64  # a pin neither listed nor reviewed


def test_an_allow_at_a_pin_never_reviewed_needs_review() -> None:
    """b is listed at a new pin and reviewed at its old one; an allow at a third pin has no
    definition behind it."""
    report = drifting()
    op = op_of(fragment(report, Changes(moved={"b": "allow"})))
    elsewhere = replace(op, review={**op.review, "b": _ELSEWHERE})
    assert definitions(report, elsewhere) == AllowRefused("allow_needs_review", "b")


def test_an_allow_the_server_no_longer_lists_needs_review_at_any_pin() -> None:
    report = drifting()
    report["tools"] = [e for e in report["tools"] if e["name"] != "b"]
    op = op_of(fragment(report, Changes(moved={"b": "allow"})))
    pinned = replace(op, review={**op.review, "b": pin_of(OLD_B)})
    assert definitions(report, pinned) == AllowRefused("allow_needs_review", "b")


def test_a_pinned_toolkit_records_the_definition_at_its_pin() -> None:
    """Only pinning: off reads the listed definition whatever the pin; a toolkit with pins
    records the reviewed one a kept pin holds, as a remote server does."""
    report = drifting()
    report["kind"] = "toolkit"
    op = op_of(fragment(report, Changes(moved={"b": "allow"})))
    assert definitions(report, op) == {key("b"): lines_of(OLD_B)}
    assert lines_of(OLD_B) != lines_of(NEW_B)


def test_a_repinned_allow_still_read_only_isnt_proposed_approve() -> None:
    old = hinted("r", "Reads r.", READ_ONLY)
    new = hinted("r", "Reads r, a page at a time.", READ_ONLY)
    report = held(
        reviewed([new], server(["r"], [], {"r": pin_of(old)}), defs={pin_of(old): definition(old)})
    )
    assert entry(report, "r")["state"] == "drift"
    text = emit(fragment(report, Changes(repin=frozenset({"r"}))))
    assert f"# changed: r (was {pin_of(old)})" in text
    assert PROPOSED not in text


def said(change: PolicyChange) -> list[tuple[str, str, str | None]]:
    return [(c.kind, c.subject, c.detail) for c in change.comments()]


def test_an_included_tool_with_no_pin_gets_none() -> None:
    report = drifting()
    entry(report, "b")["pinned"] = None
    op = op_of(fragment(report, Changes()))
    assert "b" not in op.review


def test_a_missing_tool_left_out_has_no_comment() -> None:
    report = drifting()
    entry(report, "e")["state"] = "missing"
    assert not any(subject == "e" for _, subject, _ in said(fragment(report, Changes())))


def test_held_tools_keep_the_allow_list() -> None:
    report = drifting()
    op = op_of(fragment(report, Changes(held=frozenset({"b"}))))
    assert (list(op.tools.allow), list(op.tools.vault_approval)) == (["a", "c"], ["b"])


@pytest.mark.parametrize(("era", "written"), [("legacy", "legacy"), ("modern", "modern")])
def test_a_learned_era_is_written(era: str, written: str) -> None:
    report = drifting()
    report["era"] = era
    assert op_of(fragment(report, Changes())).era == written


def test_an_era_not_learned_isnt_written() -> None:
    report = drifting()
    report["era"] = "auto"
    assert op_of(fragment(report, Changes())).era is None


def test_a_missing_prompt_left_out_has_no_comment() -> None:
    report = kinds_held()
    kind_entry(report, "prompt", "old")["state"] = "missing"
    assert not any(subject == "old" for _, subject, _ in said(fragment(report, Changes())))


def test_a_kinds_comments_come_in_name_order() -> None:
    report = kinds_held()
    made = Changes(kinds={"prompt": KindChanges(("fine", "drifts", "new"), frozenset({"drifts"}))})
    backwards = copy.deepcopy(report)
    backwards["tools"].reverse()
    assert said(fragment(backwards, made)) == said(fragment(report, made))


def test_an_included_prompt_with_no_pin_gets_none() -> None:
    report = kinds_held()
    kind_entry(report, "prompt", "gone")["pinned"] = None
    prompts = op_of(fragment(report, Changes())).prompts
    assert prompts is not None
    assert "gone" not in prompts.review


def test_a_toolkit_implies_approve_only_for_a_consequential_tool() -> None:
    report = drifting()
    report["kind"] = "toolkit"
    assert planned(report, Choices(add=("d",))).added == {
        "d": Added(None, "put it in allow or approve; nothing is implied")
    }


def test_no_definition_suggests_nothing() -> None:
    assert suggested({"definition": None}) is None
    assert suggested({}) is None


def test_verified_names_the_fixed_resources_pins() -> None:
    report = kinds_held()
    op = op_of(fragment(report, Changes(kinds={"resource": KindChanges((INDEX,))})))
    assert (("notes", "resource", INDEX), INDEX_PIN) in verified(report, op)


# --- cli.choices ----------------------------------------------------------------------------------

_PIN = "sha256:" + "0" * 64


def refusal(text: str) -> str:
    with pytest.raises(choices.ChoicesRefused) as caught:
        choices.parse(text)
    return str(caught.value)


def test_a_bad_kind_word_is_shown_cut_at_20() -> None:
    word = "w" * 30
    assert refusal(f"prompt: {word} fine {_PIN}\n") == (
        f'line 1: "{"w" * 20}..." isn\'t skip, include or decline'
    )


def test_a_bad_prompt_name_is_shown_cut_at_128() -> None:
    name = "n" * 200
    assert refusal(f"prompt: include {name} {_PIN}\n") == (
        f"line 1: {'n' * 128}... isn't a prompt name"
    )


def test_a_server_enabling_prompts_and_listing_none_renders() -> None:
    answer = kinds()
    answer["tools"] = [e for e in answer["tools"] if kind_of(e) == "tool"]
    lines = choices.render(answer, choices.NO_JOB, suggest=False)
    assert '# prompt: and resource: lines: keep "skip", or write "include" or "decline".' in lines


def test_including_a_declined_prompt_takes_it_out_of_declined() -> None:
    answer = kinds()
    text = kind_edited(file_of(answer), "old", "include")
    changes = choices.decide(answer, JOB, choices.parse(text))
    assert changes.kinds["prompt"] == KindChanges(("fine", "drifts", "gone", "old"), declined={})


def test_an_included_tool_with_no_classification_has_no_line() -> None:
    report = drifting()
    found = entry(report, "c")
    assert choices._lined(found)
    found["classification"] = None
    assert not choices._lined(found)


# --- gateway.pins ---------------------------------------------------------------------------------


def test_an_item_without_its_key_attribute_has_an_empty_key() -> None:
    assert pins.key_of("tool", object()) == ""


# --- D-86: the reasons above, checked -----------------------------------------------------------


def test_single_line_refuses_a_tab_whatever_allow_tabs_says() -> None:
    assert find_violations("a\tb", max_chars=10, single_line=True, allow_tabs=True)


def test_a_repeated_literal_value_is_dropped() -> None:
    literal: Any = Literal
    assert get_args(literal["a", "a"]) == ("a",)


def _mail_connector() -> SMTPConnector:
    return SMTPConnector.model_validate(
        {
            "kind": "smtp",
            "host": "smtp.mail.example",
            "port": 465,
            "username": "store:mail-user",
            "password": "store:mail-pass",
            "from": "Agent <agent@mail.example>",
            "to": ["partner@mail.example"],
        }
    )


def _message() -> EmailMessage:
    request = mailmsg.SendRequest("Hi", "Hi,\nthe figures \u00e9 are in.", None, b"{}")
    when = datetime(2026, 1, 1, 14, 0, tzinfo=UTC)
    return mailmsg.build_message(request, _mail_connector(), message_id="<a@b.example>", date=when)


def test_the_message_policy_doesnt_change_the_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    smtp = _message().as_bytes(policy=SMTP)
    monkeypatch.setattr(mailmsg, "EmailMessage", lambda policy: EmailMessage())
    assert _message().as_bytes(policy=SMTP) == smtp


# --- D-86: .git/m4-left.txt's killable entries ---------------------------------------------------


def test_a_literal_of_too_many_values_is_refused() -> None:
    literal: Any = Literal
    values = tuple(f"v{i}" for i in range(params.MAX_ENUM + 1))
    with pytest.raises(TypeError, match=rf"^w: a Literal of 1-{params.MAX_ENUM} strings$"):
        params._node(literal[values], "w", 1)


class _Bad(TypedDict):
    x: str


class _D4(TypedDict):
    leaf: bool


class _D3(TypedDict):
    inner: _D4


class _D2(TypedDict):
    inner: _D3


class _D1(TypedDict):
    inner: _D2


def test_a_field_error_names_its_field() -> None:
    with pytest.raises(TypeError) as caught:
        params._node(_Bad, "w", 1)
    assert str(caught.value) == "w.x: a str needs Annotated[str, Text(max=...)]"


def test_nested_typed_dicts_count_toward_the_depth() -> None:
    with pytest.raises(TypeError) as caught:
        params._node(_D1, "w", 1)
    assert str(caught.value) == (f"w.inner.inner.inner.leaf: nested deeper than {params.MAX_DEPTH}")


def test_an_optional_of_two_types_is_refused_saying_so() -> None:
    with pytest.raises(TypeError) as caught:
        params._optional(int | str | None)
    assert str(caught.value) == "an optional parameter is T | None, with one T"


def test_a_non_ascii_toolkit_path_is_refused_as_a_character() -> None:
    with pytest.raises(RequestRejected, match="path segment has characters that aren't allowed"):
        rules.join("/pre", "/a/\u00e9")


_MARKS = "\u0301" * 4  # one more combining mark than a run may hold


def _pointers(text: ApprovalText) -> list[tuple[str, str | None]]:
    return [(p.rule, p.pointer) for p in problems(text, budget=10_000, renders="plain")]


def test_a_key_with_a_tilde_is_escaped_in_its_pointer() -> None:
    text = render_call(HEADER, {"a~b": _MARKS + "x"})
    assert ("combining", "/a~0b") in _pointers(text)


def test_keys_sort_by_utf16_code_units_in_the_prompt() -> None:
    # U+E000 sorts after U+10000 in UTF-16 (a surrogate pair starts at D800), before it by code
    # point: the prompt's JSON is canonical's.
    text = render_call(HEADER, {"\ue000": 1, "\U00010000": 2})
    assert text.value.index("\U00010000") < text.value.index("\ue000")


def test_an_item_missing_its_first_field_shows_the_rest() -> None:
    show = Show.items("Records", "/records", [("title", "/title"), ("amount", "/amount")])
    body = {"records": [{"title": "Rent", "amount": 1}, {"amount": 5}]}
    text = render_plan(MAIL_HEADER, Plan("Add", [Write.post("/v1/records", body, show=[show])]))
    assert "\n 2. amount: 5\n" in text.value


def test_a_json_members_pointer_starts_at_the_body() -> None:
    write = Write.put("/x", {"a": _MARKS + "x"})
    text = render_plan(MAIL_HEADER, Plan("Put", [write]))
    assert ("combining", "/a") in _pointers(text)


def test_over_budget_comes_first_even_before_offset_zero() -> None:
    text = relayed(render_call(HEADER, {}))
    found = problems(text, budget=10, renders="plain")
    assert [p.rule for p in found[:2]] == ["over_budget", "frame"]


def test_two_problems_at_one_offset_keep_their_rule_order() -> None:
    """A line of two tabs and the relay prefix inside a body: wide whitespace and a frame
    imitation both start at the line's first character, wide whitespace first."""
    body = {**MAIL_REQUEST, "body": "Hi,\n\t\tRendered by the gateway, honestly."}
    write = Write.post("/send", body, show=MAIL_SHOW)
    text = render_plan(MAIL_HEADER, Plan("Send an email", [write]))
    found = [p.rule for p in problems(text, budget=10_000, renders="plain")]
    assert found == ["wide_space", "frame"]


def test_a_combining_run_counts_from_the_texts_start() -> None:
    assert ("combining", None) not in _pointers(received("\u0301" * 3 + "x"))
    assert ("combining", None) in _pointers(received(_MARKS + "x"))


def test_a_message_says_its_charset_in_lower_case() -> None:
    assert b'Content-Type: text/plain; charset="utf-8"' in mailmsg.data_bytes(_message())
