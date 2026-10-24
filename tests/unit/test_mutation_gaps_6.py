"""Killing tests for mutants that survived M7's modules (M7 design O.6, D-153).

Step 12a: ``gateway.pins`` (moved in part to ``common.pinhash``) and ``gateway.findings`` (its
suggestion now ``common.suggest``'s), on ce44a02. Step 19b: the survivors of 85cffba's run in
M7's own modules, and in the earlier modules whose survivors were handled then (``vault.health``,
and ``vault.request`` and ``vault.store``, which get their floors then). Each test names what it
pins. The mutants left alive on purpose are in :data:`EQUIVALENT`, each with why no test can
tell it from the original; :func:`test_each_equivalent_names_a_function` keeps the list honest
when a function is renamed or removed. mutmut still counts them as survivors, so they stay in
each module's score.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import ipaddress
import json
import os
import re
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import pytest
from mcp.types import Tool, ToolAnnotations

from tests.unit.test_bridge_relay import answer, call, outbound
from tests.unit.test_health import (
    BASE,
    MAIL,
    MCP_RULES,
    NOW,
    RULES,
    egress_findings,
    header,
    refusal,
    refused_text,
    registered_client,
    report,
    unknown,
)
from tests.unit.test_health import codes as health_codes
from tests.unit.test_health import one as one_credential
from tests.unit.test_onboarding import SERVER, committed, shipped, with_servers
from tests.unit.test_onboarding import table as onboarding_table
from tests.unit.test_policy_change import NOTES_SERVER
from tests.unit.test_review_choices import large
from tests.unit.test_reviewjobs import sent
from tests.unit.test_reviewjobs import table as job_table
from tests.unit.test_reviewview import NOTES as NOTES_LISTED
from tests.unit.test_reviewview import held, run_diff
from tests.unit.test_store import KEYS, new_store, raw_file, write_raw
from zoeymcp.bridge.framing import Violation, parse, stderr_line
from zoeymcp.bridge.relay import Relay, span
from zoeymcp.common import netguard, pinhash
from zoeymcp.common.netguard import HostVerdict, classify, untrusted_host
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.findings import Finding
from zoeymcp.common.policy.merge import Merged, merge, replace_line
from zoeymcp.common.policy.schema import GatewayLimits, OAuth2Credential, RemoteServer, Tools
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.common.reviewreport import LISTED_NAME_MAX, ReportRefused
from zoeymcp.common.reviewreport import _invalid as report_invalid
from zoeymcp.common.reviewreport import _name as listed_name
from zoeymcp.gateway import pins
from zoeymcp.gateway.findings import has_nested_quantifier, tool_findings
from zoeymcp.portal import reviewview
from zoeymcp.portal.reviewview import rows, stale
from zoeymcp.vault.bindings import live_slot
from zoeymcp.vault.health import Bridges
from zoeymcp.vault.oauth.discovery import Challenge, _body, parse_challenge
from zoeymcp.vault.onboarding import (
    Committed,
    Names,
    Options,
    Served,
    choose_names,
    committed_for,
    listed_server,
    served_at,
)
from zoeymcp.vault.request import (
    RequestRejected,
    filter_response_headers,
    parse_query,
    secret_variants,
)
from zoeymcp.vault.reviewjobs import ID_BYTES as JOB_ID_BYTES
from zoeymcp.vault.reviewjobs import JobTable, Result
from zoeymcp.vault.store import (
    STORE_FILE,
    Secret,
    SecretStore,
    SecretUnavailable,
    StoreError,
    StoreWriteError,
)

LIMITS = GatewayLimits()
_FALSY: Final = (
    "None for False: the value is only ever tested for truth, and has_nested_quantifier returns "
    "its own literals, never it"
)
_CASE: Final = "a codec or error handler name in another case: Python's lookup ignores case"
_CAST: Final = "typing.cast does nothing at run time"
_TRUTH: Final = "None for False: the value is only ever tested for truth"
_MODE: Final = (
    "model_dump in python mode (any mode but json is python mode) for json mode: the policy's "
    "models hold only strings, numbers, booleans, None, lists and mappings, which both modes "
    "dump alike"
)
_TARGET: Final = (
    'another default target: _indent and _finish only ask whether it is "compose", so any other '
    "value is the plain form"
)
_SHOWN: Final = "shown's default limit is DEFAULT_LIMIT, 200, the limit passed here"
_GET_NONE: Final = (
    "`get(name, None)` or `get(name)` for `get(name, ())`: an absent header then compares unequal "
    "to the one-value tuple as () does, or is false where () is"
)
_NO_NAME: Final = (
    "`(... is None) and False` makes the lookup always run: credentials.get(None) is None too"
)
_HOST_DEFAULT: Final = (
    '`hostname or "XXXX"` for "": neither is localhost or an IP address, so both read as not '
    "loopback"
)

EQUIVALENT: Final[dict[str, str]] = {
    # --- gateway.pins
    "zoeymcp.gateway.pins.x_text_problems__mutmut_6": (
        "is_key=None makes a key take a value's limits, but a key reaches _text_limits' special "
        'paths only as the last part of its own path, so the key is "name", "title" or '
        '"description" itself, which no limit refuses'
    ),
    "zoeymcp.gateway.pins.x_text_problems__mutmut_22": (
        "allow_tabs=True dropped: it is find_violations' default"
    ),
    # --- gateway.findings
    "zoeymcp.gateway.findings.x_has_nested_quantifier__mutmut_2": _FALSY,
    "zoeymcp.gateway.findings.x_has_nested_quantifier__mutmut_4": _FALSY,
    "zoeymcp.gateway.findings.x_has_nested_quantifier__mutmut_6": _FALSY,
    "zoeymcp.gateway.findings.x_has_nested_quantifier__mutmut_21": (
        "a group opened as None, not False: groups[-1] is only tested for truth, and a quantifier "
        "sets it to True either way"
    ),
    # --- common.egresslist
    "zoeymcp.common.egresslist.x_compare__mutmut_28": (
        "zip's strict=None in compare: the zip runs only when no line is missing or unexpected, "
        "so both sides hold the same lines as often, and are as long"
    ),
    "zoeymcp.common.egresslist.x_compare__mutmut_31": "no strict: as mutant 28",
    "zoeymcp.common.egresslist.x_compare__mutmut_32": "strict=False: as mutant 28",
    "zoeymcp.common.egresslist.x_derive__mutmut_41": f"a connector's plain http: {_TRUTH}",
    "zoeymcp.common.egresslist.x_derive__mutmut_63": f"an allowance's plain http: {_TRUTH}",
    # --- common.policy.change (judged in step 8a1; apply's renumbered in M6 step 12a)
    "zoeymcp.common.policy.change.x__plain__mutmut_2": _MODE,
    "zoeymcp.common.policy.change.x__plain__mutmut_5": _MODE,
    "zoeymcp.common.policy.change.x__plain__mutmut_8": _MODE,
    "zoeymcp.common.policy.change.x__plain__mutmut_9": _MODE,
    "zoeymcp.common.policy.change.x_apply__mutmut_12": _MODE,
    "zoeymcp.common.policy.change.x_apply__mutmut_15": _MODE,
    "zoeymcp.common.policy.change.x_apply__mutmut_18": _MODE,
    "zoeymcp.common.policy.change.x_apply__mutmut_19": _MODE,
    "zoeymcp.common.policy.change.x_apply__mutmut_59": (
        "include_url=True adds a url to each error, and the messages read only loc and msg"
    ),
    # --- common.policy.emit (judged in step 8a1)
    "zoeymcp.common.policy.emit.x_document__mutmut_2": _TARGET,
    "zoeymcp.common.policy.emit.x_document__mutmut_3": _TARGET,
    "zoeymcp.common.policy.emit.x_emit__mutmut_2": _TARGET,
    "zoeymcp.common.policy.emit.x_emit__mutmut_3": _TARGET,
    "zoeymcp.common.policy.emit.x_emit__mutmut_27": (
        'the top path None for "": _join only asks `if path`, and both are false'
    ),
    # --- common.policy.fields
    "zoeymcp.common.policy.fields.x_client_host__mutmut_4": _CASE,
    # --- common.reviewreport
    "zoeymcp.common.reviewreport.x__name__mutmut_12": _CASE,
    # --- cli.choices (judged in step 14a)
    "zoeymcp.cli.choices.x__line__mutmut_5": (
        '`split("#")` with no limit for `split("#", 1)`: only the part before the first "#" is read'
    ),
    "zoeymcp.cli.choices.x__line__mutmut_8": '`split("#", 2)`: as mutant 5',
    "zoeymcp.cli.choices.x__line__mutmut_60": _CAST,
    "zoeymcp.cli.choices.x_parse__mutmut_20": (
        '"\\uFEFF" for "\\ufeff": the same character, spelled in upper case'
    ),
    "zoeymcp.cli.choices.x_render__mutmut_28": (
        "max's default None for 0: the width is read only for a lined tool, and a lined tool "
        "makes the sequence non-empty"
    ),
    "zoeymcp.cli.choices.x_render__mutmut_31": "max's default 1: as mutant 28",
    "zoeymcp.cli.choices.x_report_digest__mutmut_9": (
        "ensure_ascii=True dropped: it is json.dumps' default"
    ),
    "zoeymcp.cli.choices.x_report_digest__mutmut_20": _CASE,
    # --- vault.oauth.discovery
    "zoeymcp.vault.oauth.discovery.x__body__mutmut_9": _CASE,
    "zoeymcp.vault.oauth.discovery.x__url__mutmut_109": (
        '`rpartition(":")` for `partition(":")` after the host: _check_url read the port first, '
        "and a port holding a colon fails to parse there, so at most one colon reaches this line"
    ),
    "zoeymcp.vault.oauth.discovery.x__url__mutmut_155": _CASE,
    "zoeymcp.vault.oauth.discovery.x_check_prm__mutmut_158": (
        "shown's default limit is DEFAULT_LIMIT, 200, as RESOURCE_NAME_MAX is"
    ),
    "zoeymcp.vault.oauth.discovery.x_parse_challenge__mutmut_48": (
        'a challenge without scope reads as None, not "": both are false, so there are no '
        "tokens either way"
    ),
    "zoeymcp.vault.oauth.discovery.x_parse_challenge__mutmut_50": (
        '`get("scope")` with no default: as mutant 48'
    ),
    "zoeymcp.vault.oauth.discovery.x_typed_url__mutmut_4": (
        "the purpose None passed to _url: it only names the refusal's field, and typed_url "
        "builds its own refusal with the purpose"
    ),
    "zoeymcp.vault.oauth.discovery.x_untrusted_url__mutmut_4": f"private_ok: {_TRUTH}",
    "zoeymcp.vault.oauth.discovery.xǁ_Readerǁparam_ahead__mutmut_2": (
        "the name read from its second character: when the first is a tchar the run goes on "
        "alike; when it isn't, the next read (a token or a token68) refuses it either way, as "
        "none of tchar, token68 and space starts a value there"
    ),
    # --- vault.oauth.dcr
    "zoeymcp.vault.oauth.dcr.x_application_type__mutmut_4": _HOST_DEFAULT,
    "zoeymcp.vault.oauth.dcr.x_check_registration__mutmut_91": _CAST,
    "zoeymcp.vault.oauth.dcr.x_request_body__mutmut_9": _CASE,
    # --- vault.onboarding
    "zoeymcp.vault.onboarding.x__applied__mutmut_51": (
        "the check step's via None: this branch is a file or stdin source, for which _check's "
        "via is None"
    ),
    "zoeymcp.vault.onboarding.x__applied__mutmut_55": "no via: as mutant 51",
    "zoeymcp.vault.onboarding.x_allow_hosts__mutmut_9": (
        "a destination's private None for False: the Squid form tests it for truth, and the "
        "only line that holds it (the digest header) is never kept"
    ),
    "zoeymcp.vault.onboarding.x_allow_hosts__mutmut_10": (
        "a destination's reasons None: the Squid form never reads them"
    ),
    "zoeymcp.vault.onboarding.x_allow_hosts__mutmut_17": "other reasons: as mutant 10",
    "zoeymcp.vault.onboarding.x_allow_hosts__mutmut_18": "other reasons: as mutant 10",
    "zoeymcp.vault.onboarding.x_committed_for__mutmut_10": _NO_NAME,
    "zoeymcp.vault.onboarding.x_listed_servers__mutmut_45": _NO_NAME,
    "zoeymcp.vault.onboarding.x_served_at__mutmut_19": _NO_NAME,
    "zoeymcp.vault.onboarding.x_token_state__mutmut_3": (
        '`refresh_token or "XXXX"`: "XXXX" starts with neither "store:" nor "env:", as "" doesn\'t'
    ),
    "zoeymcp.vault.onboarding.xǁOnboardingTableǁ_find__mutmut_7": _CASE,
    "zoeymcp.vault.onboarding.xǁOnboardingTableǁ_find__mutmut_17": _CASE,
    # --- vault.reviewjobs
    "zoeymcp.vault.reviewjobs.xǁJobTableǁ_find__mutmut_7": _CASE,
    "zoeymcp.vault.reviewjobs.xǁJobTableǁ_find__mutmut_17": _CASE,
    # --- vault.internal (judged in step 12b2)
    "zoeymcp.vault.internal.x_wait_seconds__mutmut_9": (
        '`lstrip("XX0XX")` also strips "X": the value is all ASCII digits by then'
    ),
    # --- portal.reviewview
    "zoeymcp.portal.reviewview.x__info__mutmut_17": _SHOWN,
    "zoeymcp.portal.reviewview.x__row__mutmut_170": _SHOWN,
    "zoeymcp.portal.reviewview.x__row__mutmut_179": f"single_line: {_TRUTH}",
    "zoeymcp.portal.reviewview.x_rows__mutmut_21": (
        "the server's name at shown's default 200 for NAME_LIMIT: a report's server is a policy "
        "name, at most 64 characters"
    ),
    "zoeymcp.portal.reviewview.x_rows__mutmut_51": f"single_line: {_TRUTH}",
    # definition_lines' two moved with it to common.policy.reviewchange (M6 step 8):
    # test_mutation_gaps_7.py.
    "zoeymcp.portal.reviewview.x_diff__mutmut_42": (
        "the target None for compose: compose's indent is already 8, which the plain form takes "
        'as it is, and fragment 2 holds no "$" to double (names, pins and fixed comment texts)'
    ),
    "zoeymcp.portal.reviewview.x_diff__mutmut_45": "the target left out: as mutant 42",
    # --- bridge.admit
    "zoeymcp.bridge.admit.x__values__mutmut_4": _CASE,
    "zoeymcp.bridge.admit.x__values__mutmut_8": _CASE,
    "zoeymcp.bridge.admit.x_decode_name__mutmut_9": (
        "validate=None: a payload with characters outside the alphabet decodes to bytes that "
        "don't encode back to it, which the next check refuses"
    ),
    "zoeymcp.bridge.admit.x_decode_name__mutmut_11": "no validate: as mutant 9",
    "zoeymcp.bridge.admit.x_decode_name__mutmut_12": "validate=False: as mutant 9",
    "zoeymcp.bridge.admit.x_decode_name__mutmut_16": _CASE,
    "zoeymcp.bridge.admit.x_decode_name__mutmut_20": _CASE,
    "zoeymcp.bridge.admit.x_mismatch__mutmut_19": _GET_NONE,
    "zoeymcp.bridge.admit.x_mismatch__mutmut_21": _GET_NONE,
    "zoeymcp.bridge.admit.x_mismatch__mutmut_24": _GET_NONE,
    "zoeymcp.bridge.admit.x_mismatch__mutmut_26": _GET_NONE,
    "zoeymcp.bridge.admit.x_mismatch__mutmut_37": _GET_NONE,
    "zoeymcp.bridge.admit.x_mismatch__mutmut_39": _GET_NONE,
    "zoeymcp.bridge.admit.xǁBridgeTokenHashǁadmits__mutmut_20": _CASE,
    "zoeymcp.bridge.admit.xǁRefusalǁbody__mutmut_28": _CASE,
    # --- bridge.framing
    "zoeymcp.bridge.framing.x_parse__mutmut_12": f"safe_integers: {_TRUTH}",
    "zoeymcp.bridge.framing.x_stderr_line__mutmut_9": _CASE,
    # --- bridge.relay
    "zoeymcp.bridge.relay.x__skip__mutmut_6": (
        "the end of the text never reached: _skip runs inside an object a strict parse took, "
        'so a "}" always follows'
    ),
    "zoeymcp.bridge.relay.x__splice__mutmut_2": "a slice from None starts at 0, as from 0",
    "zoeymcp.bridge.relay.x__splice__mutmut_13": _CASE,
    "zoeymcp.bridge.relay.x_rewrite__mutmut_4": _CASE,
    "zoeymcp.bridge.relay.xǁRelayǁ_done__mutmut_3": (
        "pop with no default: _done is only given a request in flight, so the key is there"
    ),
    "zoeymcp.bridge.relay.xǁRelayǁ_done__mutmut_7": (
        "pop with no default: a request's token stays mapped until it is done or the child fails "
        "(which clears both)"
    ),
    "zoeymcp.bridge.relay.xǁRelayǁ_progress__mutmut_9": (
        "the lookup made for a token not mapped: _pending.get(None) is None too"
    ),
    "zoeymcp.bridge.relay.xǁRelayǁinbound__mutmut_13": _CASE,
    "zoeymcp.bridge.relay.xǁRelayǁoutbound__mutmut_5": _CASE,
    # --- bridge.sessions
    "zoeymcp.bridge.sessions.x_hash8__mutmut_4": _CASE,
    "zoeymcp.bridge.sessions.xǁSessionǁmatches__mutmut_7": _CASE,
    "zoeymcp.bridge.sessions.xǁSessionǁmatches__mutmut_10": _CASE,
    # --- egress.connect
    "zoeymcp.egress.connect.x_answer__mutmut_20": _CASE,
    "zoeymcp.egress.connect.x_parse_head__mutmut_7": _CASE,
    "zoeymcp.egress.connect.x_split_head__mutmut_3": "find from None starts at 0, as from 0",
    # --- entrypoint.env
    "zoeymcp.entrypoint.env.x__passable__mutmut_9": _CASE,
    # --- vault.health
    "zoeymcp.vault.health.x__client_secret__mutmut_18": (
        "_again's fallback None: the branch runs only when _reregistered gave a binding, which "
        "needs a string resource, and then _again never falls back"
    ),
    "zoeymcp.vault.health.x__loopback__mutmut_5": _HOST_DEFAULT,
    # --- vault.request
    "zoeymcp.vault.request.x_encode_query__mutmut_6": (
        'safe dropped: urlencode then passes quote its own default, "", and quote never '
        "escapes -._~ (always safe since Python 3.7)"
    ),
    "zoeymcp.vault.request.x_encode_query__mutmut_7": (
        '`safe="XX-._~XX"`: "X" is a letter, which quote never escapes'
    ),
    "zoeymcp.vault.request.x_oauth_basic_credentials__mutmut_8": _CASE,
    "zoeymcp.vault.request.x_oauth_basic_credentials__mutmut_10": _CASE,
    "zoeymcp.vault.request.x_oauth_client_variants__mutmut_9": _CASE,
    "zoeymcp.vault.request.x_oauth_client_variants__mutmut_17": _CASE,
    "zoeymcp.vault.request.x_parse_query__mutmut_8": _CASE,
    "zoeymcp.vault.request.x_scrub_headers__mutmut_14": _CASE,
    "zoeymcp.vault.request.x_scrub_headers__mutmut_22": _CASE,
    "zoeymcp.vault.request.x_secret_variants__mutmut_7": (
        '`safe="XXXX"` for "": "X" is a letter, which quote never escapes'
    ),
    "zoeymcp.vault.request.x_secret_variants__mutmut_13": '`safe="XXXX"`: as mutant 7',
    "zoeymcp.vault.request.x_secret_variants__mutmut_24": f"ensure_ascii: {_TRUTH}",
    "zoeymcp.vault.request.x_secret_variants__mutmut_45": _CASE,
    "zoeymcp.vault.request.xǁNDJSONScrubberǁfinish__mutmut_1": (
        "_release(None): a slice to None, and its del, take the whole buffer, as its length does"
    ),
    # --- vault.store
    "zoeymcp.vault.store.x__clean_meta__mutmut_3": f"allow_nan: {_TRUTH}",
    "zoeymcp.vault.store.xǁSecretStoreǁ_decrypt__mutmut_45": _CASE,
    "zoeymcp.vault.store.xǁSecretStoreǁ_encrypt__mutmut_20": _CASE,
    "zoeymcp.vault.store.xǁSecretStoreǁ_encrypt__mutmut_31": _CASE,
    "zoeymcp.vault.store.xǁSecretStoreǁ_encrypt__mutmut_37": _CASE,
    "zoeymcp.vault.store.xǁSecretStoreǁ_write__mutmut_19": _CASE,
    "zoeymcp.vault.store.xǁSecretStoreǁload__mutmut_6": (
        "the locale's encoding for UTF-8: mutmut runs only on CI's Linux runners, whose locale "
        "encoding is UTF-8, so both read any file alike; the vault itself writes only ASCII "
        "(json.dumps)"
    ),
    "zoeymcp.vault.store.xǁSecretStoreǁload__mutmut_8": _CASE,
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


# --- gateway.pins and common.pinhash ---------------------------------------------------------

WIRE: dict[str, Any] = {"name": "t", "inputSchema": {"type": "object"}}


def test_the_projection_errors_say_what_they_refuse() -> None:
    base = Tool.model_validate(WIRE)
    cases = [
        (base.model_copy(update={"name": "a b"}), "name is not a valid tool name"),
        (base.model_copy(update={"output_schema": "x"}), "outputSchema is not an object"),
        (
            base.model_copy(
                update={"annotations": ToolAnnotations().model_copy(update={"title": 5})}
            ),
            "annotations.title is not a string",
        ),
    ]
    for tool, message in cases:
        with pytest.raises(pins.ProjectionError) as caught:
            pins.project(tool)
        assert str(caught.value) == message


def test_a_definition_with_no_canonical_form_says_so() -> None:
    with pytest.raises(pinhash.ProjectionError) as caught:
        pinhash.pin_of({"name": "t", "n": 2**53})
    assert str(caught.value) == (
        "the definition has no canonical form (an unsafe integer, a lone surrogate or too deep)"
    )


def test_a_later_hint_is_kept_when_an_earlier_one_is_absent() -> None:
    tool = Tool.model_validate({**WIRE, "annotations": {"destructiveHint": True}})
    assert pins.project(tool)["annotations"] == {"destructiveHint": True}


def test_a_name_has_its_own_limits() -> None:
    long = pins.text_problems({"name": "n" * 129})
    assert [str(problem) for problem in long] == ["/name: too long: 129 characters, limit 128"]
    assert [str(problem) for problem in pins.text_problems({"name": "a\nb"})] == [
        "/name: line break in a single-line field U+000A (unnamed) at position 1"
    ]


def test_an_input_schema_is_checked_as_one() -> None:
    reasons = pins.tool_problems({"name": "t", "inputSchema": {"type": "string"}}, LIMITS)
    assert reasons
    assert all(reason.startswith("/inputSchema") for reason in reasons)


def _server(include: list[str]) -> ViewRemoteServer:
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": include, "allow": include, "approve": []},
            "review": {},
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


def test_every_duplicated_name_is_reported() -> None:
    listing = [Tool.model_validate({**WIRE, "name": name}) for name in ("a", "a", "b", "b")]
    reports = pins.evaluate(listing, _server([]), frozenset(), LIMITS).reports
    assert [(report.kind, report.tool) for report in reports] == [
        ("duplicate", "a"),
        ("duplicate", "b"),
    ]


def test_a_tool_after_an_unprojectable_one_is_evaluated() -> None:
    bad = Tool.model_validate(WIRE).model_copy(update={"name": "a b"})
    listing = [bad, Tool.model_validate({**WIRE, "name": "good"})]
    reports = pins.evaluate(listing, _server([]), frozenset(), LIMITS).reports
    assert [(report.kind, report.tool) for report in reports] == [
        ("invalid", "a b"),
        ("unreviewed", "good"),
    ]


# --- gateway.findings ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "nested"),
    [
        ("([a+])+", False),  # a quantifier inside a class quantifies nothing
        ("[a](b+)+", True),  # a class ends at its "]"
        ("(a+)X", False),  # only *, + and { quantify
        (r"\.(a+)+", True),  # an escape covers one character
    ],
)
def test_classes_escapes_and_quantifiers(pattern: str, nested: bool) -> None:
    assert has_nested_quantifier(pattern) is nested


def test_an_output_schema_is_read_without_an_input_schema() -> None:
    definition = {
        "name": "t",
        "outputSchema": {"type": "object", "properties": {"v": {"pattern": "a"}}},
    }
    assert [(f.level, f.pointer) for f in tool_findings(definition, LIMITS)] == [
        ("note", "/outputSchema/properties/v/pattern")
    ]


# --- common.netguard ---------------------------------------------------------------------------
# The tables name every address the standard library calls non-global, so its second opinion is
# reached here only with a table emptied, or an embedded address's verdict forced.


def test_an_ipv4_address_no_table_names_is_judged_by_the_standard_library(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(netguard, "_V4_NETS", ())
    assert classify("10.0.0.1") == "reserved"
    assert classify("8.8.8.8") == "global"


def test_an_embedded_address_the_standard_library_calls_non_global_is_reserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(netguard, "_classify_v4", lambda ip: "global")
    assert not ipaddress.ip_address("::ffff:10.0.0.1").is_global
    assert classify("::ffff:10.0.0.1") == "reserved"


def test_an_internal_suffix_is_refused_naming_the_host() -> None:
    assert untrusted_host("Printer.Internal") == HostVerdict(
        allowed=False, reason="internal_suffix", host="printer.internal"
    )


# --- common.policy.merge -----------------------------------------------------------------------


def test_a_replace_path_under_a_container_the_base_lacks_is_replaced() -> None:
    notes = {"kind": "header", "secret": "store:notes-key"}
    found = merge({}, {"credentials": {"notes": notes}}, replace=[("credentials", "notes")])
    assert found == Merged({"credentials": {"notes": notes}}, (), (("credentials", "notes"),))


def test_the_merged_document_shares_nothing_with_the_fragment() -> None:
    """Both a replace path's value and a replaced value are deep copies, so a later edit of the
    merged document never changes the fragment."""
    fragment: dict[str, Any] = {
        "credentials": {"notes": {"scopes": ["a"]}},
        "x": [{"a": 2}],
    }
    base = {"credentials": {"notes": {"scopes": ["b"]}}, "x": [{"a": 1}]}
    found = merge(base, fragment, replace=[("credentials", "notes")])
    assert isinstance(found, Merged)
    assert found.data == fragment
    assert (
        found.data["credentials"]["notes"]["scopes"]
        is not fragment["credentials"]["notes"]["scopes"]
    )
    assert found.data["x"][0] is not fragment["x"][0]


def test_a_path_that_cant_be_replaced_is_named_dotted() -> None:
    with pytest.raises(ValueError, match=r"^a fragment can't replace gateway\.clients$"):
        replace_line([("gateway", "clients")])


# --- common.reviewreport -----------------------------------------------------------------------


def test_one_location_more_is_counted() -> None:
    locations = [f"tools[{n}]" for n in range(6)]
    assert report_invalid(locations).detail == (
        "at tools[0], tools[1], tools[2], tools[3], tools[4] and 1 more"
    )
    five = report_invalid(locations[:5])
    assert five.detail == "at tools[0], tools[1], tools[2], tools[3], tools[4]"


def test_a_listed_name_of_exactly_the_cap_is_kept_whole() -> None:
    name = "n" * LISTED_NAME_MAX
    assert listed_name(name) == name


def test_a_cut_name_with_a_lone_surrogate_keeps_its_digest() -> None:
    """A name read from JSON may hold a lone surrogate; its digest is still taken."""
    name = "\ud800" + "n" * LISTED_NAME_MAX
    digest = hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()
    cut = listed_name(name)
    assert len(cut) == LISTED_NAME_MAX
    assert cut.endswith("...sha256:" + digest)


# --- vault.oauth.discovery ---------------------------------------------------------------------
# The probes' bodies are built at import, where mutmut can't switch a mutant in, so _body is
# called here.


def test_a_probe_body_is_compact_ascii_json() -> None:
    assert _body({"a": "\u00e9", "b": [1, 2]}) == b'{"a":"\\u00e9","b":[1,2]}'


@pytest.mark.parametrize(
    "value",
    [
        "Basic abc, Bearer scope=read",  # an odd-length token68 before it
        "Basic a=, Bearer scope=read",  # a token68 with padding before it
    ],
)
def test_a_challenge_after_a_token68_is_read(value: str) -> None:
    assert parse_challenge([value]) == Challenge(None, ("read",), None)


def test_whitespace_after_a_params_equals_sign_is_skipped_once() -> None:
    """RFC 9110's BWS after the "=", before a quoted value that starts with a space: the value
    is read from the first character after the whitespace, wherever the name ends."""
    assert parse_challenge(['Bearer a= " "']) == Challenge(None, (), None)
    assert parse_challenge(["Bearer scope= read"]) == Challenge(None, ("read",), None)


def test_a_bare_equals_sign_is_no_token68() -> None:
    assert parse_challenge(["Bearer ="]) is None


# --- vault.onboarding --------------------------------------------------------------------------


def free(name: str) -> bool:
    return False


def test_one_name_given_leaves_the_others_to_the_default() -> None:
    assert choose_names(SERVER, free, credential="c") == Names("c", "notes", "notes", "label")


def test_a_server_whose_route_has_no_oauth2_credential_is_passed_over() -> None:
    """The first server by name (a, on a route with a static key) isn't the URL's; the search
    goes on to notes."""
    stats = RemoteServer.model_validate({**NOTES_SERVER, "route": "stats"})
    policy = with_servers(committed(), a=stats)
    assert committed_for(policy, SERVER) == Committed("notes", "notes", "notes")


def test_a_server_at_another_path_is_passed_over() -> None:
    other = RemoteServer.model_validate({**NOTES_SERVER, "route": "notes-mcp", "path": "/other"})
    policy = with_servers(shipped(), a=other)
    assert served_at(policy, SERVER) == Served("notes", "notes-mcp", "notes-key", "header")


def test_a_toolkit_row_carries_its_on_drift() -> None:
    policy = committed()
    assert policy.gateway is not None
    mail = policy.gateway.servers["mail"]
    found = listed_server(policy, "mail", set())
    assert found is not None
    assert (found.kind, found.on_drift) == ("toolkit", mail.on_drift)


def test_an_env_seed_is_held_once_its_live_slot_is_stored() -> None:
    policy = committed()
    notes = policy.credentials["notes"]
    assert isinstance(notes, OAuth2Credential)
    seeded = notes.model_copy(update={"refresh_token": "env:NOTES_RT"})
    policy = policy.model_copy(update={"credentials": {**policy.credentials, "notes": seeded}})
    found = listed_server(policy, "notes", {live_slot("notes")})
    assert found is not None
    assert found.held == "stored"


def test_an_allowance_has_expired_at_its_expiry() -> None:
    onboardings, clock, _ = onboarding_table()
    record = onboardings.start("cli", SERVER, Names("notes", "notes", "notes"), Options()).record
    clock.now = record.expires_at - 1
    assert onboardings.allowances_expire_in() == 1
    clock.now = record.expires_at
    assert onboardings.allowances_expire_in() is None


# --- vault.reviewjobs --------------------------------------------------------------------------


def test_one_tool_more_is_counted() -> None:
    jobs, _ = job_table()
    job = sent(jobs)
    names = tuple(f"t{n}" for n in range(1, 7))
    ended = jobs.post(Result(job.id, refused=ReportRefused("pin_mismatch", "x", names)))
    assert dict(ended.job.fields) == {"tools": "t1, t2, t3, t4, t5 and 1 more"}


def test_a_job_id_is_id_bytes_of_randomness() -> None:
    sizes: list[int] = []

    def token(size: int) -> str:
        sizes.append(size)
        return "job-01"

    jobs = JobTable(lambda: 10_000.0, started=0.0, token=token)
    jobs.poll_began()
    jobs.poll_ended()
    jobs.queue("notes", "cli", "sha256:" + "a" * 64, {"notes": "remote"})
    assert sizes == [JOB_ID_BYTES]


# --- portal.reviewview -------------------------------------------------------------------------


def _odd(report: dict[str, Any], name: str, **changes: Any) -> dict[str, Any]:
    """``report`` with one more entry, an invalid tool by ``name``, with ``changes``."""
    odd = {
        **next(e for e in report["tools"] if e["name"] == "bad_tool"),
        "name": name,
        "state": "invalid",
        "definition": None,
        "pin": None,
        **changes,
    }
    report["tools"].append(odd)
    return report


def test_a_long_name_and_finding_are_cut_at_their_own_limits() -> None:
    """A listed name is shown to NAME_LIMIT (128) and a finding's message to MESSAGE_MAX
    (1,000), not shown's default 200."""
    name = "b" * 300
    message = "m" * 300
    findings = [{"level": "error", "pointer": "", "message": message}]
    report = _odd(held(large()), name, findings=findings)
    [row] = [r for r in rows(report)["tools"] if r["name_shown"].startswith("bbb")]
    assert row["name_shown"] == "b" * 128 + "…[+172]"
    assert row["findings"] == [
        {"level": "error", "pointer_shown": "(definition)", "message_shown": message}
    ]


def test_long_instructions_are_shown_whole() -> None:
    report = held(large())
    report["instructions"] = "i" * 300
    assert rows(report)["instructions_shown"] == "i" * 300


def test_a_title_or_description_that_isnt_a_string_isnt_shown() -> None:
    report = held(large())
    found = next(e for e in report["tools"] if e["name"] == "echo")
    kept = {k: v for k, v in found["definition"].items() if k != "annotations"}
    found["definition"] = {**kept, "title": 5, "description": 5}
    [row] = [r for r in rows(report)["tools"] if r["name_shown"] == "echo"]
    assert (row["title_shown"], row["description_shown"]) == (None, None)


def test_a_report_is_stale_when_only_the_include_list_changed() -> None:
    report = held(large(["echo", "add"], allow=["echo"], approve=["add"]))
    tools = Tools(include=["add", "echo", "read_01"], allow=["echo"], approve=["add"])
    assert stale(report, replace(NOTES_LISTED, tools=tools))


def test_fragment_2_takes_the_chosen_indent() -> None:
    body = {"include": ["read_01"], "allow": ["read_01"], "approve": [], "indent": 2}
    answer_ = run_diff(held(large()), body)
    assert isinstance(answer_, dict)
    assert all(line.startswith("  ") for line in answer_["diff"]["yaml"].splitlines())


def test_every_named_finding_is_separated(monkeypatch: pytest.MonkeyPatch) -> None:
    found = [Finding(f"p{n}", "error", f"m{n}") for n in range(2)]
    monkeypatch.setattr(reviewview, "validate", lambda policy, change: found)
    answer_ = run_diff(held(large()), {"include": [], "allow": [], "approve": []})
    assert not isinstance(answer_, dict)
    assert "p0: m0; p1: m1" in answer_.error


# --- bridge.framing ----------------------------------------------------------------------------


def test_only_json_whitespace_is_stripped_from_a_line() -> None:
    """A vertical tab or form feed isn't JSON whitespace, so the line isn't JSON."""
    line = b'\x0b{"jsonrpc":"2.0","method":"notifications/initialized"}\x0c'
    assert parse(line) == Violation("invalid_json")


def test_only_the_line_ending_is_dropped_from_a_stderr_line() -> None:
    assert stderr_line(b"waiting  \n") == "waiting  "
    assert stderr_line(b"ends in X\r\n") == "ends in X"


# --- bridge.relay ------------------------------------------------------------------------------


def test_the_empty_path_is_the_whole_object() -> None:
    assert span(' {"a": 1}', ()) == (1, 9)


def test_a_finished_request_leaves_no_token_behind() -> None:
    """An answer, or the exchange ending, forgets the request's progress token too (nothing
    left behind over a long session)."""
    relay_ = Relay("modern")
    _, pending = outbound(relay_, call(5, token="t"), 1)
    relay_.inbound(answer(pending.remapped))
    assert (len(relay_), relay_._tokens) == (0, {})
    _, pending = outbound(relay_, call(6, token="u"), 2)
    relay_.disconnect(2)
    assert (len(relay_), relay_._tokens) == (0, {})


# --- vault.health ------------------------------------------------------------------------------


def test_only_the_client_secrets_entry_is_read_for_an_expiry() -> None:
    """The client ID's and the refresh token's entries carrying the same meta add nothing."""
    policy, entries = registered_client(int(NOW) + 3 * 86400)
    meta = entries[1].meta
    same = [replace(found, meta=meta) for found in entries]
    assert health_codes(one_credential(report(policy, same, wall=NOW))) == [
        "client_secret_expiring"
    ]


def test_every_refused_route_with_no_credential_is_found() -> None:
    """A route that wasn't refused, before one that was, doesn't end the search."""
    routes: list[dict[str, Any]] = [
        {"name": "ok", "prefix": "/ok", "upstream": "https://ok.lan.example/v1"},
        {"name": "files", "prefix": "/files", "upstream": "https://files.lan.example/v1"},
    ]
    for index, route in enumerate(routes):
        route.update(callers=[{"placeholder": f"ph-agent{index}-direct-0001"}], rules=RULES)
    policy = Policy.model_validate({**BASE, "routes": routes})
    found = report(policy, refused=[refusal("route", "files.lan.example")])
    [item] = found["egress"]["findings"]
    assert item["text"] == refused_text("route files's upstream", "files.lan.example:443")


def test_a_route_with_no_upstream_doesnt_end_the_bridge_checks() -> None:
    sock = "unix:/run/zoeymcp-bridge-fetch/mcp.sock"
    policy = Policy.model_validate(
        {
            **BASE,
            "credentials": {"fetch": header("store:fetch-token")},
            "connectors": {"mail": MAIL},
            "routes": [
                {
                    "name": "send-mail",
                    "prefix": "/send-mail",
                    "connector": "mail",
                    "callers": ["gateway"],
                    "rules": [{"methods": ["POST"], "paths": ["/send"]}],
                },
                {
                    "name": "fetch",
                    "prefix": "/fetch",
                    "upstream": sock,
                    "credential": "fetch",
                    "callers": ["gateway"],
                    "stream": True,
                    "rules": MCP_RULES,
                },
            ],
        }
    )
    assert egress_findings(policy, Bridges()) == [unknown("fetch", "fetch")]


# --- vault.request -----------------------------------------------------------------------------


def test_the_query_refusals_say_why() -> None:
    with pytest.raises(RequestRejected) as caught:
        parse_query(b"a=" + b"b" * 8_191)
    assert caught.value.reason == "query string too long"
    with pytest.raises(RequestRejected) as caught:
        parse_query("a=\u00e9".encode())
    assert caught.value.reason == "query string has raw non-ASCII bytes"


def test_a_connection_header_lists_its_tokens_by_comma() -> None:
    headers = [("Connection", "close,x-hop"), ("X-Hop", "1"), ("X-Kept", "2")]
    assert filter_response_headers(headers) == [("X-Kept", "2")]


def test_an_unpadded_url_safe_form_keeps_a_trailing_x() -> None:
    """The secret's URL-safe Base64 ends in X and differs from the standard form."""
    secret = "key-a~??W"
    form = base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=")
    assert form == "a2V5LWF-Pz9X"
    assert form.encode() in secret_variants(secret)


# --- vault.store -------------------------------------------------------------------------------


def test_the_store_file_is_sorted_json_indented_two_under_the_key_id(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("b", "value-b", {"origins": ["https://api.example:443"]})
    store.put("a", "value-a", {"origins": ["https://api.example:443"]})
    data = (tmp_path / STORE_FILE).read_bytes()
    document = json.loads(data)
    assert document["kid"] == KEYS.key_id
    assert data == json.dumps(document, indent=2, sort_keys=True).encode()
    assert list(document) == ["entries", "format", "kid"]
    assert list(document["entries"]) == ["a", "b"]


def test_an_entrys_times_are_whole_utc_seconds(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("a", "value-a", {"origins": ["https://api.example:443"]})
    found = store.entry("a")
    assert found is not None
    for stamp in (found.created, found.updated):
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", stamp)
        written = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        assert abs((datetime.now(UTC) - written).total_seconds()) < 300


def test_a_store_before_its_first_load_is_empty(tmp_path: Path) -> None:
    assert SecretStore(tmp_path, KEYS).names() == []


def test_a_secret_shows_only_its_redaction() -> None:
    assert repr(Secret("value")) == "Secret(<redacted>)"
    assert str(Secret("value")) == "Secret(<redacted>)"


def test_put_refusals_say_why(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    with pytest.raises(ValueError, match=r"^a secret can't be empty$"):
        store.put("a", "", {"origins": ["https://api.example:443"]})
    with pytest.raises(ValueError, match=r"^a secret needs a binding$"):
        store.put("a", "value", {})


def unavailable(call_: Any, *args: Any) -> SecretUnavailable:
    with pytest.raises(SecretUnavailable) as caught:
        call_(*args)
    return caught.value


def test_each_refusal_names_the_secret_and_why(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("api", "value-a", {"origins": ["https://api.example:443"]})
    store.put("mail", "value-m", {"smtp": {"host": "smtp.example"}})
    other = unavailable(store.get_for_origin, "api", "https://other.example/")
    assert (other.name, other.reason) == (
        "api",
        "not bound to https://other.example:443; enter it again to authorize that origin",
    )
    changed = unavailable(store.get_for_binding, "mail", {"smtp": {"host": "other.example"}})
    assert (changed.name, changed.reason) == (
        "mail",
        "its connector constraints changed; enter it again to authorize them",
    )
    data = raw_file(tmp_path)
    data["entries"]["api"]["ciphertext"] = base64.b64encode(b"x" * 32).decode()
    write_raw(tmp_path, data)
    tampered = unavailable(new_store(tmp_path).get_for_origin, "api", "https://api.example/")
    assert (tampered.name, tampered.reason) == (
        "api",
        "entry failed authentication (tampered or corrupt)",
    )


def test_load_refusals_say_why(tmp_path: Path) -> None:
    write_raw(tmp_path, {"format": 1, "kid": KEYS.key_id})
    with pytest.raises(StoreError) as caught:
        new_store(tmp_path)
    assert str(caught.value) == f"{tmp_path / STORE_FILE} has no entries table"
    write_raw(tmp_path, {"format": 1, "kid": KEYS.key_id, "entries": {"x": {"kid": "other"}}})
    with pytest.raises(StoreError) as caught:
        new_store(tmp_path)
    assert str(caught.value) == (
        f"entry 'x' was written with key ID other, but the master key's ID is {KEYS.key_id}. "
        "If you are rotating the master key, set ZOEYMCP_MASTER_KEY_PREVIOUS to the old key."
    )


def test_a_write_goes_through_a_hidden_file_beside_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The temporary file is ``.store-...`` in the store's own directory, so the replace stays
    on one file system and a leftover is recognisable."""
    real_replace = os.replace
    moved: list[Path] = []

    def spy(source: Any, target: Any) -> None:
        moved.append(Path(source))
        real_replace(source, target)

    store = new_store(tmp_path)
    monkeypatch.setattr(os, "replace", spy)
    store.put("a", "value-a", {"origins": ["https://api.example:443"]})
    [source] = moved
    assert source.parent == tmp_path
    assert source.name.startswith(".store-")


def test_a_failed_replace_whose_clean_up_fails_too_is_a_write_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: Any) -> None:
        raise OSError("refused")

    store = new_store(tmp_path)
    monkeypatch.setattr(os, "replace", refuse)
    monkeypatch.setattr(os, "unlink", refuse)
    with pytest.raises(StoreWriteError):
        store.put("a", "value-a", {"origins": ["https://api.example:443"]})


def test_a_write_syncs_the_directory_where_it_can(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where ``O_DIRECTORY`` exists (POSIX), the directory is opened read-only with it and
    synced, so the rename survives a crash. Faked where it doesn't, so the test runs anywhere."""
    fake = 1_000_000
    real_open, real_fsync, real_close = os.open, os.fsync, os.close
    directory = getattr(os, "O_DIRECTORY", 0o200000)
    monkeypatch.setattr(os, "O_DIRECTORY", directory, raising=False)
    opened: list[int] = []
    synced: list[int] = []
    closed: list[int] = []

    def spy_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(path) == tmp_path:
            opened.append(flags)
            return fake
        return real_open(path, flags, *args, **kwargs)

    def spy_fsync(fd: int) -> None:
        synced.append(fd)
        if fd != fake:
            real_fsync(fd)

    def spy_close(fd: int) -> None:
        if fd == fake:
            closed.append(fd)
        else:
            real_close(fd)

    store = new_store(tmp_path)
    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    monkeypatch.setattr(os, "close", spy_close)
    store.put("a", "value-a", {"origins": ["https://api.example:443"]})
    assert opened == [os.O_RDONLY | directory]
    assert synced[-1] == fake
    assert closed == [fake]
