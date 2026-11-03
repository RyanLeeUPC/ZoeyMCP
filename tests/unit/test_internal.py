"""The vault's own endpoints (M7 design G.1; O.2 ``test_internal.py``): one table, decided before
any body byte is read, the review jobs poll's query (F.2, CR-8), (step 17b) the egress role's
allowlists: its key there alone, never on the gateway's link (G.2, G.3, X21), (M6 step 7)
the gateway's status path, one report at a time and at most one accepted per 5 s (K.1, T-12,
FM-19), (M8 step 11) the collect path and its body (E.2, F.5, Q46), and (M8 step 12a) the
decisions poll's query, the withdraw's and the detach's bodies, the epoch rule and the endings
the poll answers (E.2, G-15, G-16, OPS-3), and (M8 step 12b) the ask's body and the relay
decisions the poll answers beside the endings (E.2, E.4; G-23)."""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

import pytest

from zoeymcp.common import ledgerreport
from zoeymcp.common.policy.match import NormalizedPath, RequestRejected
from zoeymcp.vault import app, internal
from zoeymcp.vault.internal import (
    ALLOWLISTS,
    ASK,
    COLLECT,
    DECISIONS,
    DETACH,
    ENDPOINTS,
    LEDGER,
    REVIEW_JOBS,
    REVIEW_REPORT,
    STATUS,
    VIEW,
    WITHDRAW,
    Ask,
    Collect,
    Detach,
    Ended,
    Endpoint,
    Epochs,
    Feed,
    Refusal,
    Relayed,
    StatusGate,
    Withdraw,
    _egress_path,
    _path,
    allowlist_wait,
    ask_body,
    collect_body,
    decide,
    decisions_query,
    detach_body,
    find,
    jobs_query,
    wait_seconds,
    withdraw_body,
)
from zoeymcp.vault.reviewjobs import OLDER

DIGEST = "sha256:" + "ab" * 32
TAKES = "the review jobs path takes wait, view and kinds, once each"
KINDS = "kinds is review, or review,clear"
GATEWAY_ENDPOINTS = (
    VIEW,
    LEDGER,
    REVIEW_JOBS,
    REVIEW_REPORT,
    STATUS,
    COLLECT,
    DECISIONS,
    WITHDRAW,
    DETACH,
    ASK,
)


def path(text: str) -> NormalizedPath:
    return NormalizedPath(tuple(text.strip("/").split("/")))


# --- the table ------------------------------------------------------------------------------------


def test_the_table_is_g1s() -> None:
    """Path, methods, identity, body cap and waiters, as G.1 lists them, M6 K.1's status path
    after the gateway's other rows, M8 E.2's collect after it and then its other paths (step
    12a), the ask after them (step 12b), the egress row last (step 17b)."""
    rows = [
        (e.path.text, e.methods, e.identity, e.body_cap, e.waiters, e.name, e.label)
        for e in ENDPOINTS
    ]
    assert rows == [
        ("/_zoeymcp/gateway/v1/view", ("GET",), "gateway", 0, 4, "gateway_view", "the view"),
        (
            "/_zoeymcp/gateway/v1/report/ledger",
            ("GET", "POST"),
            "gateway",
            2**20,
            None,
            "gateway_report",
            "the report path",
        ),
        (
            "/_zoeymcp/gateway/v1/review/jobs",
            ("GET",),
            "gateway",
            0,
            1,
            "review_jobs",
            "the review jobs path",
        ),
        (
            "/_zoeymcp/gateway/v1/report/review",
            ("POST",),
            "gateway",
            None,
            None,
            "review_report",
            "the review report path",
        ),
        (
            "/_zoeymcp/gateway/v1/report/status",
            ("POST",),
            "gateway",
            256 * 1024,
            None,
            "gateway_status",
            "the status path",
        ),
        (
            "/_zoeymcp/gateway/v1/approvals/collect",
            ("POST",),
            "gateway",
            1024,
            None,
            "approvals_collect",
            "the collect path",
        ),
        (
            "/_zoeymcp/gateway/v1/approvals/decisions",
            ("GET",),
            "gateway",
            0,
            1,
            "approvals_decisions",
            "the decisions path",
        ),
        (
            "/_zoeymcp/gateway/v1/approvals/withdraw",
            ("POST",),
            "gateway",
            1024,
            None,
            "approvals_withdraw",
            "the withdraw path",
        ),
        (
            "/_zoeymcp/gateway/v1/approvals/detach",
            ("POST",),
            "gateway",
            16 * 1024,
            None,
            "approvals_detach",
            "the detach path",
        ),
        (
            "/_zoeymcp/gateway/v1/approvals/ask",
            ("POST",),
            "gateway",
            96 * 1024,
            None,
            "approvals_ask",
            "the ask path",
        ),
        (
            "/_zoeymcp/egress/v1/allowlists",
            ("GET",),
            "egress",
            0,
            2,
            "egress_allowlists",
            "the allowlist path",
        ),
    ]
    assert LEDGER.body_cap == ledgerreport.MAX_BODY_BYTES
    assert REVIEW_JOBS.waiters == internal.REVIEW_WAITERS
    assert ALLOWLISTS.waiters == internal.ALLOWLIST_WAITERS
    assert STATUS.body_cap == internal.STATUS_MAX_BYTES
    assert COLLECT.body_cap == internal.COLLECT_MAX_BYTES == 1024
    assert DECISIONS.waiters == internal.DECISIONS_WAITERS == 1
    assert WITHDRAW.body_cap == internal.WITHDRAW_MAX_BYTES == 1024
    assert DETACH.body_cap == internal.DETACH_MAX_BYTES == 16 * 1024
    assert ASK.body_cap == internal.ASK_MAX_BYTES == 96 * 1024
    assert (*GATEWAY_ENDPOINTS, ALLOWLISTS) == ENDPOINTS


def test_path_is_under_the_gateways_version() -> None:
    """Called directly, since the table is built at import, before a mutant is switched on."""
    assert _path("review", "jobs") == NormalizedPath(
        ("_zoeymcp", "gateway", "v1", "review", "jobs")
    )
    assert _path() == NormalizedPath(("_zoeymcp", "gateway", "v1"))
    assert _egress_path("allowlists") == NormalizedPath(("_zoeymcp", "egress", "v1", "allowlists"))
    assert _egress_path() == NormalizedPath(("_zoeymcp", "egress", "v1"))


def test_the_constants() -> None:
    """M.6's, and the view's from M3 D.2, which the app re-exports for the gateway's contract."""
    assert (internal.REVIEW_WAIT, internal.REVIEW_WAITERS) == (25, 1)
    assert internal.REVIEW_READ_DEADLINE == 30.0
    assert (internal.VIEW_MAX_WAIT, internal.VIEW_MAX_WAITERS) == (25, 4)
    assert (internal.ALLOWLIST_WAIT, internal.ALLOWLIST_WAITERS) == (25, 2)
    assert internal.ALLOWLIST_MAX_STALE == 300
    assert (internal.DECISIONS_WAIT, internal.DETACH_MAX_CALLS) == (25, 64)
    assert (internal.ENDINGS_KEPT, internal.EPOCHS_KEPT) == (1024, 64)
    assert frozenset({"caller_cancelled"}) == internal.WITHDRAW_REASONS
    assert app.ALLOWLIST_PATH is ALLOWLISTS.path
    assert app.ALLOWLIST_PATH.text == "/_zoeymcp/egress/v1/allowlists"
    assert (app.VIEW_MAX_WAIT, app.VIEW_MAX_WAITERS) == (25, 4)
    assert app.VIEW_PATH is VIEW.path
    assert app.REPORT_PATH is LEDGER.path
    assert app.REVIEW_JOBS_PATH.text == "/_zoeymcp/gateway/v1/review/jobs"
    assert app.REVIEW_REPORT_PATH.text == "/_zoeymcp/gateway/v1/report/review"
    assert app.STATUS_PATH is STATUS.path
    assert (internal.STATUS_MAX_BYTES, internal.STATUS_MIN_INTERVAL) == (256 * 1024, 5.0)
    assert app.INTERNAL_SEGMENT == internal.SEGMENT == "_zoeymcp"


def test_rows_cannot_be_changed() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        VIEW.methods = ("POST",)  # type: ignore[misc]


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=lambda e: e.name)
def test_each_path_finds_its_row(endpoint: Endpoint) -> None:
    assert find(endpoint.path) is endpoint
    assert find(path(endpoint.path.text)) is endpoint


@pytest.mark.parametrize(
    "text",
    [
        "/_zoeymcp",
        "/_zoeymcp/gateway/v1",
        "/_zoeymcp/gateway/v1/review",
        "/_zoeymcp/gateway/v1/review/jobs/x",
        "/_zoeymcp/gateway/v1/report",
        "/_zoeymcp/gateway/v1/report/Review",
        "/_zoeymcp/gateway/v2/review/jobs",
        "/_zoeymcp/egress/v1",
        "/_zoeymcp/egress/v1/allowlist",
        "/_zoeymcp/egress/v2/allowlists",
        "/_zoeymcp/egress/v1/allowlists/vault",
        "/_zoeymcp/gateway/v1/allowlists",
        "/_zoeymcp/egress/v1/view",
        "/_zoeymcp/gateway/v1/approvals",
        "/_zoeymcp/gateway/v1/approvals/Collect",
        "/_zoeymcp/gateway/v1/collect",
        "/_zoeymcp/gateway/v1/approvals/collect/x",
        "/_zoeymcp/gateway/v1/approvals/Ask",
        "/_zoeymcp/gateway/v1/approvals/decision",
        "/_zoeymcp/gateway/v1/approvals/Withdraw",
        "/_zoeymcp/gateway/v1/approvals/detach/x",
    ],
)
def test_anything_else_is_404(text: str) -> None:
    assert find(path(text)) is None
    assert decide(path(text), "GET", "gateway", "gateway") == Refusal(404, "no such vault endpoint")
    assert decide(path(text), "GET", "tcp", "egress") == Refusal(404, "no such vault endpoint")


def test_the_status_path_is_its_own() -> None:
    for text in ("/_zoeymcp/gateway/v1/report/Status", "/_zoeymcp/gateway/v1/status"):
        assert find(path(text)) is None
    assert find(path("/_zoeymcp/gateway/v1/report/status")) is STATUS


def test_a_trailing_slash_is_another_path() -> None:
    slashed = NormalizedPath(REVIEW_JOBS.path.segments, trailing_slash=True)
    assert find(slashed) is None


# --- deciding -------------------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", GATEWAY_ENDPOINTS, ids=lambda e: e.name)
@pytest.mark.parametrize("listener", ["gateway", "tcp"])
def test_the_gateway_reaches_each_method(endpoint: Endpoint, listener: internal.Listener) -> None:
    for method in endpoint.methods:
        assert decide(endpoint.path, method, listener, "gateway") is endpoint


@pytest.mark.parametrize(
    ("endpoint", "reason"),
    [
        (VIEW, "the view is for the gateway only"),
        (LEDGER, "the report path is for the gateway only"),
        (REVIEW_JOBS, "the review jobs path is for the gateway only"),
        (REVIEW_REPORT, "the review report path is for the gateway only"),
        (STATUS, "the status path is for the gateway only"),
        (COLLECT, "the collect path is for the gateway only"),
        (DECISIONS, "the decisions path is for the gateway only"),
        (WITHDRAW, "the withdraw path is for the gateway only"),
        (DETACH, "the detach path is for the gateway only"),
    ],
)
@pytest.mark.parametrize("listener", ["gateway", "tcp"])
def test_no_identity_is_the_bare_403_before_the_method(
    endpoint: Endpoint, reason: str, listener: internal.Listener
) -> None:
    for method in ("GET", "POST", "DELETE"):
        assert decide(endpoint.path, method, listener, None) == Refusal(403, reason)


@pytest.mark.parametrize(
    ("endpoint", "method", "reason", "allow"),
    [
        (VIEW, "POST", "the view takes GET only", "GET"),
        (VIEW, "HEAD", "the view takes GET only", "GET"),
        (LEDGER, "PUT", "the report path takes GET or POST", "GET, POST"),
        (REVIEW_JOBS, "POST", "the review jobs path takes GET only", "GET"),
        (REVIEW_REPORT, "GET", "the review report path takes POST only", "POST"),
        (REVIEW_REPORT, "post", "the review report path takes POST only", "POST"),
        (STATUS, "GET", "the status path takes POST only", "POST"),
        (STATUS, "PUT", "the status path takes POST only", "POST"),
        (COLLECT, "GET", "the collect path takes POST only", "POST"),
        (DECISIONS, "POST", "the decisions path takes GET only", "GET"),
        (WITHDRAW, "GET", "the withdraw path takes POST only", "POST"),
        (DETACH, "PUT", "the detach path takes POST only", "POST"),
    ],
)
def test_another_method_is_405_with_allow(
    endpoint: Endpoint, method: str, reason: str, allow: str
) -> None:
    assert decide(endpoint.path, method, "gateway", "gateway") == Refusal(405, reason, allow)


def test_a_refusal_has_no_allow_by_default() -> None:
    assert Refusal(403, "x").allow is None


# --- the egress role (G.2, G.3, X21) --------------------------------------------------------------


def test_the_egress_role_reaches_the_allowlists_over_tcp() -> None:
    assert decide(ALLOWLISTS.path, "GET", "tcp", "egress") is ALLOWLISTS
    assert decide(path("/_zoeymcp/egress/v1/allowlists"), "GET", "tcp", "egress") is ALLOWLISTS


@pytest.mark.parametrize("identity", ["egress", "gateway", None])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_the_allowlists_are_never_served_on_the_link(
    identity: internal.Identity | None, method: str
) -> None:
    """X21: before the identity and the method, whoever the link's caller says it is."""
    refused = Refusal(403, "the allowlist path isn't served on the gateway's link")
    assert decide(ALLOWLISTS.path, method, "gateway", identity) == refused


@pytest.mark.parametrize("identity", ["gateway", None])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_only_the_egress_key_reaches_the_allowlists(
    identity: internal.Identity | None, method: str
) -> None:
    refused = Refusal(403, "the allowlist path is for the egress role only")
    assert decide(ALLOWLISTS.path, method, "tcp", identity) == refused


@pytest.mark.parametrize("endpoint", GATEWAY_ENDPOINTS, ids=lambda e: e.name)
@pytest.mark.parametrize("listener", ["gateway", "tcp"])
def test_the_egress_key_reaches_no_gateway_path(
    endpoint: Endpoint, listener: internal.Listener
) -> None:
    for method in endpoint.methods:
        refused = decide(endpoint.path, method, listener, "egress")
        assert refused == Refusal(403, f"{endpoint.label} is for the gateway only")


@pytest.mark.parametrize("method", ["POST", "HEAD", "get", "DELETE"])
def test_the_allowlists_take_get_only(method: str) -> None:
    refused = Refusal(405, "the allowlist path takes GET only", "GET")
    assert decide(ALLOWLISTS.path, method, "tcp", "egress") == refused


@pytest.mark.parametrize(
    ("params", "seconds"),
    [
        ([], 0),
        ([("wait", "0")], 0),
        ([("wait", "25")], 25),
        ([("wait", "24")], 24),
        ([("wait", "26")], 25),
        ([("wait", "9" * 400)], 25),
        ([("wait", "007")], 7),
    ],
)
def test_the_allowlist_wait(params: list[tuple[str, str]], seconds: int) -> None:
    assert allowlist_wait(params) == seconds


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ([("other", "1")], "the allowlist path takes one parameter, wait"),
        ([("wait", "1"), ("wait", "1")], "the allowlist path takes one parameter, wait"),
        ([("wait", "1"), ("view", DIGEST)], "the allowlist path takes one parameter, wait"),
        ([("Wait", "1")], "the allowlist path takes one parameter, wait"),
        ([("wait", "x")], "wait must be a number of seconds"),
        ([("wait", "")], "wait must be a number of seconds"),
        ([("wait", "-1")], "wait must be a number of seconds"),
    ],
)
def test_a_bad_allowlist_query_is_refused(params: list[tuple[str, str]], reason: str) -> None:
    with pytest.raises(RequestRejected) as caught:
        allowlist_wait(params)
    assert caught.value.reason == reason


# --- the review jobs poll's query ---------------------------------------------------------------


def test_the_view_digest_and_a_wait() -> None:
    assert jobs_query([("wait", "25"), ("view", DIGEST)]) == (25, DIGEST, OLDER)
    assert jobs_query([("view", DIGEST), ("wait", "3")]) == (3, DIGEST, OLDER)


def test_without_a_wait_the_poll_answers_at_once() -> None:
    assert jobs_query([("view", DIGEST)]) == (0, DIGEST, OLDER)


@pytest.mark.parametrize(("value", "seconds"), [("26", 25), ("0" * 40 + "7", 7), ("9" * 400, 25)])
def test_the_wait_is_capped(value: str, seconds: int) -> None:
    assert jobs_query([("wait", value), ("view", DIGEST)]) == (seconds, DIGEST, OLDER)


def test_the_kinds_a_poll_advertises() -> None:
    """M6 J.4 (G-8): a poll that advertises no kinds is an older gateway's, which runs reviews
    only; a new one runs reviews and clears; review alone is the same as none."""
    both = frozenset({"review", "clear"})
    assert frozenset({"review"}) == OLDER
    assert jobs_query([("view", DIGEST), ("kinds", "review,clear")]) == (0, DIGEST, both)
    query = [("wait", "5"), ("kinds", "review"), ("view", DIGEST)]
    assert jobs_query(query) == (5, DIGEST, OLDER)


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ([], "the review jobs path needs the view's digest"),
        ([("wait", "1")], "the review jobs path needs the view's digest"),
        ([("view", DIGEST), ("view", DIGEST)], TAKES),
        ([("wait", "1"), ("wait", "1"), ("view", DIGEST)], TAKES),
        ([("view", DIGEST), ("other", "1")], TAKES),
        ([("view", DIGEST), ("kinds", "review"), ("kinds", "review")], TAKES),
        ([("view", DIGEST), ("kinds", "clear")], KINDS),
        ([("view", DIGEST), ("kinds", "clear,review")], KINDS),
        ([("view", DIGEST), ("kinds", "review,clear,")], KINDS),
        ([("view", DIGEST), ("kinds", "review,review")], KINDS),
        ([("view", DIGEST), ("kinds", "review,clear,other")], KINDS),
        ([("view", DIGEST), ("kinds", "")], KINDS),
        ([("view", DIGEST), ("kinds", "Review")], KINDS),
        ([("view", DIGEST), ("wait", "x")], "wait must be a number of seconds"),
        ([("view", DIGEST), ("wait", "-1")], "wait must be a number of seconds"),
        ([("view", DIGEST), ("wait", "")], "wait must be a number of seconds"),
    ],
)
def test_a_bad_query_is_refused(params: list[tuple[str, str]], reason: str) -> None:
    with pytest.raises(RequestRejected) as caught:
        jobs_query(params)
    assert caught.value.reason == reason


@pytest.mark.parametrize(
    "digest",
    [
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "sha256:" + "A" * 64,
        "SHA256:" + "a" * 64,
        "a" * 64,
        "sha256:" + "a" * 64 + "\n",
        "",
    ],
)
def test_the_view_is_a_digest(digest: str) -> None:
    """CR-8: ``view.Digest``'s pattern, by full match."""
    with pytest.raises(RequestRejected) as caught:
        jobs_query([("view", digest)])
    assert caught.value.reason == "view must be sha256: and 64 hex digits"


@pytest.mark.parametrize(
    ("value", "most", "seconds"),
    [
        ("0", 25, 0),
        ("", 25, None),
        ("25", 25, 25),
        ("100", 25, 25),
        ("99", 100, 99),
        ("10", 25, 10),
        ("100", 100, 100),
    ],
)
def test_wait_seconds(value: str, most: int, seconds: int | None) -> None:
    if seconds is None:
        with pytest.raises(RequestRejected):
            wait_seconds(value, most)
    else:
        assert wait_seconds(value, most) == seconds


def test_a_wait_of_non_ascii_digits_is_refused() -> None:
    with pytest.raises(RequestRejected):
        wait_seconds("٣", 25)  # ARABIC-INDIC DIGIT THREE: a digit, not ASCII


# --- the status path's admission (K.1, T-12, FM-19) ----------------------------------------------


def test_the_first_status_report_is_read() -> None:
    gate = StatusGate()
    assert gate.reading is False
    assert gate.accepted_at is None
    assert gate.begin(100.0) is None
    assert gate.reading is True


def test_one_status_report_at_a_time() -> None:
    gate = StatusGate()
    assert gate.begin(100.0) is None
    assert gate.begin(100.0) == Refusal(429, "a status report is being read")
    gate.end(100.0, accepted=False)
    assert gate.reading is False
    assert gate.begin(100.0) is None


def test_at_most_one_accepted_per_interval() -> None:
    """T-12: enforced by the vault, whatever the gateway's debounce: a report 5 s after the last
    accepted one is read, one a moment sooner is 429."""
    gate = StatusGate()
    assert gate.begin(100.0) is None
    gate.end(100.0, accepted=True)
    assert gate.accepted_at == 100.0
    too_soon = Refusal(429, "a status report came too soon after the last")
    assert gate.begin(104.99) == too_soon
    assert gate.begin(100.0) == too_soon
    assert gate.reading is False
    assert gate.begin(105.0) is None
    gate.end(105.5, accepted=True)
    assert gate.accepted_at == 105.5
    assert gate.begin(110.4) == too_soon


def test_a_refused_report_doesnt_start_the_interval() -> None:
    gate = StatusGate()
    assert gate.begin(100.0) is None
    gate.end(100.0, accepted=True)
    assert gate.begin(106.0) is None
    gate.end(106.5, accepted=False)  # refused: invalid, say
    assert gate.accepted_at == 100.0
    assert gate.begin(106.5) is None


# --- the collect path's body (M8 design E.2, F.5, Q46) --------------------------------------------

EPOCH = "0123456789ab"
REF = "0123456789abcdef"
ONE = {"epoch": EPOCH, "client": "agent1", "server": "shop", "ref": REF}


def test_a_collect_names_one_call() -> None:
    assert collect_body(ONE) == Collect(EPOCH, "agent1", "shop", REF)


def test_a_collect_with_no_ref_lists_the_clients_calls() -> None:
    listed = {key: value for key, value in ONE.items() if key != "ref"}
    assert collect_body(listed) == Collect(EPOCH, "agent1", "shop", None)


@pytest.mark.parametrize(
    "document",
    [
        [ONE],
        "x",
        None,
        {},
        {**ONE, "extra": "1"},
        {key: value for key, value in ONE.items() if key != "epoch"},
        {key: value for key, value in ONE.items() if key != "client"},
        {key: value for key, value in ONE.items() if key != "server"},
        {"ref": REF, "epoch": EPOCH},
    ],
    ids=["array", "string", "null", "empty", "extra", "no-epoch", "no-client", "no-server", "two"],
)
def test_a_collect_names_its_fields_exactly(document: object) -> None:
    with pytest.raises(RequestRejected):
        collect_body(document)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("epoch", "0123456789a"),
        ("epoch", "0123456789abc"),
        ("epoch", "0123456789AB"),
        ("epoch", 123456789012),
        ("ref", "0123456789abcde"),
        ("ref", "0123456789abcdef0"),
        ("ref", "0123456789ABCDEF"),
        ("ref", "0123456789abcdeg"),
        ("ref", None),
        ("client", "Agent1"),
        ("client", "-agent"),
        ("client", ""),
        ("client", "a" * 64),
        ("client", ["agent1"]),
        ("server", "shop/x"),
        ("server", "shop\n"),
    ],
    ids=[
        "epoch-short",
        "epoch-long",
        "epoch-upper",
        "epoch-number",
        "ref-short",
        "ref-long",
        "ref-upper",
        "ref-not-hex",
        "ref-null",
        "client-upper",
        "client-dash-first",
        "client-empty",
        "client-too-long",
        "client-list",
        "server-slash",
        "server-line-break",
    ],
)
def test_each_field_has_its_form(key: str, value: object) -> None:
    with pytest.raises(RequestRejected, match=f"a collect's {key} isn't of its form"):
        collect_body({**ONE, key: value})


def test_the_longest_names_are_taken() -> None:
    name = "a" + "b" * 62
    assert collect_body({**ONE, "client": name, "server": name}).client == name


def test_the_refusals_name_what_is_wrong() -> None:
    with pytest.raises(RequestRejected) as caught:
        collect_body([])
    assert caught.value.reason == "a collect is a JSON object"
    with pytest.raises(RequestRejected) as caught:
        collect_body({"epoch": EPOCH})
    assert caught.value.reason == "a collect names epoch, client, server and, for one call, ref"


# --- the withdraw's body (M8 design E.2, B.6) -----------------------------------------------------

WITHDRAWN = {"epoch": EPOCH, "ref": REF, "client": "agent1", "reason": "caller_cancelled"}


def test_a_withdraw_names_one_call_and_why() -> None:
    assert withdraw_body(WITHDRAWN) == Withdraw(EPOCH, REF, "agent1", "caller_cancelled")


@pytest.mark.parametrize(
    "document",
    [
        [WITHDRAWN],
        "x",
        None,
        {},
        {**WITHDRAWN, "extra": "1"},
        {key: value for key, value in WITHDRAWN.items() if key != "reason"},
        {key: value for key, value in WITHDRAWN.items() if key != "epoch"},
    ],
    ids=["array", "string", "null", "empty", "extra", "no-reason", "no-epoch"],
)
def test_a_withdraw_names_its_fields_exactly(document: object) -> None:
    with pytest.raises(RequestRejected):
        withdraw_body(document)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("epoch", "0123456789a"),
        ("epoch", "0123456789AB"),
        ("epoch", None),
        ("ref", "0123456789abcde"),
        ("ref", "0123456789ABCDEF"),
        ("ref", 1),
        ("client", "Agent1"),
        ("client", ""),
        ("client", ["agent1"]),
    ],
    ids=[
        "epoch-short",
        "epoch-upper",
        "epoch-null",
        "ref-short",
        "ref-upper",
        "ref-number",
        "client-upper",
        "client-empty",
        "client-list",
    ],
)
def test_each_withdraw_field_has_its_form(key: str, value: object) -> None:
    with pytest.raises(RequestRejected) as caught:
        withdraw_body({**WITHDRAWN, key: value})
    assert caught.value.reason == f"a withdraw's {key} isn't of its form"


@pytest.mark.parametrize(
    "reason",
    ["changed", "Caller_cancelled", "", None, ["caller_cancelled"]],
    ids=["changed", "case", "empty", "null", "list"],
)
def test_a_withdraw_gives_a_known_reason(reason: object) -> None:
    with pytest.raises(RequestRejected) as caught:
        withdraw_body({**WITHDRAWN, "reason": reason})
    assert caught.value.reason == "a withdraw's reason is caller_cancelled"


def test_the_withdraw_refusals_name_what_is_wrong() -> None:
    with pytest.raises(RequestRejected) as caught:
        withdraw_body([])
    assert caught.value.reason == "a withdraw is a JSON object"
    with pytest.raises(RequestRejected) as caught:
        withdraw_body({"epoch": EPOCH})
    assert caught.value.reason == "a withdraw names epoch, ref, client and reason"


# --- the detach's body (E.2, I.2, G-16) ----------------------------------------------------------


def calls(count: int) -> list[dict[str, str]]:
    return [{"ref": f"{n:016x}", "client": "agent1"} for n in range(count)]


def test_a_detach_names_its_calls_in_order() -> None:
    other = {"ref": "fedcba9876543210", "client": "agent2"}
    found = detach_body({"epoch": EPOCH, "calls": [{"ref": REF, "client": "agent1"}, other]})
    assert found == Detach(EPOCH, ((REF, "agent1"), ("fedcba9876543210", "agent2")))


def test_a_detach_names_one_to_sixty_four_calls() -> None:
    assert len(detach_body({"epoch": EPOCH, "calls": calls(1)}).calls) == 1
    assert len(detach_body({"epoch": EPOCH, "calls": calls(64)}).calls) == 64
    for count in (0, 65):
        with pytest.raises(RequestRejected) as caught:
            detach_body({"epoch": EPOCH, "calls": calls(count)})
        assert caught.value.reason == "a detach names 1 to 64 calls"


ONE_CALL = {"ref": REF, "client": "agent1"}


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        ([], "a detach is a JSON object"),
        ({"epoch": EPOCH}, "a detach names epoch and calls"),
        ({"epoch": EPOCH, "calls": calls(1), "x": 1}, "a detach names epoch and calls"),
        ({"epoch": "x", "calls": calls(1)}, "a detach's epoch isn't of its form"),
        ({"epoch": EPOCH, "calls": ONE_CALL}, "a detach names 1 to 64 calls"),
        ({"epoch": EPOCH, "calls": [REF]}, "a detach's call names ref and client"),
        ({"epoch": EPOCH, "calls": [{"ref": REF}]}, "a detach's call names ref and client"),
        (
            {"epoch": EPOCH, "calls": [{**ONE_CALL, "wait": "pending"}]},
            "a detach's call names ref and client",
        ),
        (
            {"epoch": EPOCH, "calls": [{"ref": "x", "client": "agent1"}]},
            "a detach's ref isn't of its form",
        ),
        (
            {"epoch": EPOCH, "calls": [{"ref": REF, "client": "A"}]},
            "a detach's client isn't of its form",
        ),
        ({"epoch": EPOCH, "calls": [ONE_CALL, ONE_CALL]}, "a detach names each call once"),
        (
            {"epoch": EPOCH, "calls": [ONE_CALL, {**ONE_CALL, "client": "agent2"}]},
            "a detach names each call once",
        ),
    ],
    ids=[
        "array",
        "no-calls",
        "extra",
        "epoch",
        "calls-object",
        "call-string",
        "no-client",
        "call-extra",
        "ref",
        "client",
        "twice",
        "ref-twice",
    ],
)
def test_a_detach_refuses_what_it_cant_read(document: object, reason: str) -> None:
    with pytest.raises(RequestRejected) as caught:
        detach_body(document)
    assert caught.value.reason == reason


# --- the decisions poll's query (E.2) ------------------------------------------------------------


def test_the_poll_names_its_epoch_where_it_is_and_how_long_it_waits() -> None:
    query = [("epoch", EPOCH), ("after", "17"), ("wait", "25")]
    assert decisions_query(query) == (EPOCH, 17, 25)
    assert decisions_query([("wait", "3"), ("epoch", EPOCH), ("after", "0")]) == (EPOCH, 0, 3)


def test_after_and_wait_default_to_the_start_and_at_once() -> None:
    assert decisions_query([("epoch", EPOCH)]) == (EPOCH, 0, 0)
    assert decisions_query([("epoch", EPOCH), ("wait", "99")]) == (EPOCH, 0, 25)
    assert decisions_query([("epoch", EPOCH), ("after", "9" * 18)]) == (EPOCH, 10**18 - 1, 0)
    assert decisions_query([("epoch", EPOCH), ("after", "007")]) == (EPOCH, 7, 0)


POLL = "the decisions path takes epoch, after and wait, once each"


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ([], "the decisions path needs the gateway's epoch"),
        ([("after", "1")], "the decisions path needs the gateway's epoch"),
        ([("epoch", EPOCH), ("epoch", EPOCH)], POLL),
        ([("epoch", EPOCH), ("after", "1"), ("after", "1")], POLL),
        ([("epoch", EPOCH), ("ref", REF)], POLL),
        ([("Epoch", EPOCH)], POLL),
        ([("epoch", "0123456789a")], "epoch must be 12 lowercase hex digits"),
        ([("epoch", "0123456789AB")], "epoch must be 12 lowercase hex digits"),
        ([("epoch", "")], "epoch must be 12 lowercase hex digits"),
        ([("epoch", EPOCH), ("after", "")], "after must be a sequence number"),
        ([("epoch", EPOCH), ("after", "-1")], "after must be a sequence number"),
        ([("epoch", EPOCH), ("after", "1.0")], "after must be a sequence number"),
        ([("epoch", EPOCH), ("after", "9" * 19)], "after must be a sequence number"),
        ([("epoch", EPOCH), ("wait", "x")], "wait must be a number of seconds"),
    ],
    ids=[
        "none",
        "no-epoch",
        "epoch-twice",
        "after-twice",
        "other",
        "epoch-case",
        "epoch-short",
        "epoch-upper",
        "epoch-empty",
        "after-empty",
        "after-negative",
        "after-decimal",
        "after-too-long",
        "wait",
    ],
)
def test_a_bad_poll_is_refused(params: list[tuple[str, str]], reason: str) -> None:
    with pytest.raises(RequestRejected) as caught:
        decisions_query(params)
    assert caught.value.reason == reason


# --- the epoch rule (E.2, G-15) and the endings the poll answers (OPS-3) --------------------------

LATER = "ba9876543210"


def test_the_first_epoch_seen_is_the_current_one() -> None:
    epochs = Epochs()
    assert epochs.current is None
    assert epochs.arrive(EPOCH) is True
    assert epochs.current == EPOCH
    assert epochs.arrive(EPOCH) is False  # seen: nothing to withdraw again


def test_a_new_epoch_replaces_it_and_a_late_one_changes_nothing() -> None:
    epochs = Epochs()
    assert epochs.arrive(EPOCH)
    assert epochs.arrive(LATER)
    assert epochs.current == LATER
    assert epochs.arrive(EPOCH) is False  # a late request from the earlier gateway
    assert epochs.current == LATER


def test_the_last_sixty_four_epochs_are_remembered() -> None:
    epochs = Epochs()
    seen = [f"{n:012x}" for n in range(internal.EPOCHS_KEPT + 1)]
    for epoch in seen:
        assert epochs.arrive(epoch)
    assert not epochs.arrive(seen[1])  # still remembered
    assert epochs.current == seen[-1]
    assert epochs.arrive(seen[0])  # forgotten: new again
    assert epochs.current == seen[0]


def test_the_feed_numbers_each_ending_from_one() -> None:
    feed = Feed()
    assert feed.last == 0
    first = feed.add(EPOCH, REF, "done", "ok")
    second = feed.add(EPOCH, "fedcba9876543210", "denied", "not_sent")
    assert (first.seq, second.seq, feed.last) == (1, 2, 2)
    assert first == Ended(1, EPOCH, REF, "done", "ok")
    assert first.wire() == {"seq": 1, "ref": REF, "status": "done", "outcome": "ok"}
    assert feed.since(EPOCH, 0) == [first, second]
    assert feed.since(EPOCH, 1) == [second]
    assert feed.since(EPOCH, 2) == []


def test_the_feed_answers_a_gateway_its_own_calls_only() -> None:
    feed = Feed()
    mine = feed.add(EPOCH, REF, "expired", "not_sent")
    feed.add(LATER, "fedcba9876543210", "withdrawn", "not_sent")
    assert feed.since(EPOCH, 0) == [mine]
    assert [ended.seq for ended in feed.since(LATER, 0)] == [2]


def test_the_feed_keeps_the_last_endings() -> None:
    feed = Feed(kept=2)
    for n in range(3):
        feed.add(EPOCH, f"{n:016x}", "done", "ok")
    assert [ended.seq for ended in feed.since(EPOCH, 0)] == [2, 3]
    assert feed.last == 3
    default = Feed()
    for n in range(internal.ENDINGS_KEPT + 1):
        default.add(EPOCH, f"{n:016x}", "done", "ok")
    kept = default.since(EPOCH, 0)
    assert (len(kept), kept[0].seq) == (internal.ENDINGS_KEPT, 2)


def test_an_ending_cannot_be_changed() -> None:
    ended: Any = Feed().add(EPOCH, REF, "done", "ok")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ended.seq = 2


# --- the ask's body (M8 design E.2, E.4) ----------------------------------------------------------

TEXT = "Approval request 0123456789abcdef\nTool: shop \u2192 cancel_order"
DIGEST_OF_TEXT = hashlib.sha256(TEXT.encode()).hexdigest()
ASKED: dict[str, Any] = {
    "v": 1,
    "epoch": EPOCH,
    "ref": REF,
    "client": "agent1",
    "server": "shop",
    "tool": "cancel_order",
    "text": TEXT,
    "text_sha256": DIGEST_OF_TEXT,
    "deadline_ms": 1_800_000_000_000,
    "wait": "pending",
}


def test_an_ask_names_the_call_its_text_and_its_wait() -> None:
    assert ask_body(ASKED) == Ask(
        EPOCH,
        REF,
        "agent1",
        "shop",
        "cancel_order",
        TEXT,
        DIGEST_OF_TEXT,
        1_800_000_000_000,
        "pending",
    )
    assert ask_body({**ASKED, "wait": "block"}) == Ask(
        EPOCH,
        REF,
        "agent1",
        "shop",
        "cancel_order",
        TEXT,
        DIGEST_OF_TEXT,
        1_800_000_000_000,
        "block",
    )


def test_an_ask_hides_its_text() -> None:
    asked = ask_body(ASKED)
    assert repr(asked) == f"Ask(ref={REF}, tool=cancel_order)"
    assert TEXT not in repr(asked)


def test_an_asks_tool_is_the_policys_tool_name() -> None:
    longest = "T." * 64
    assert ask_body({**ASKED, "tool": longest}).tool == longest
    assert ask_body({**ASKED, "tool": "a"}).tool == "a"


def test_an_asks_deadline_is_a_positive_safe_integer() -> None:
    assert ask_body({**ASKED, "deadline_ms": 1}).deadline_ms == 1
    assert ask_body({**ASKED, "deadline_ms": 2**53 - 1}).deadline_ms == 2**53 - 1


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        ([ASKED], "an ask is a JSON object"),
        (None, "an ask is a JSON object"),
        (
            {**ASKED, "extra": 1},
            "an ask names v, epoch, ref, client, server, tool, text, text_sha256, deadline_ms "
            "and wait",
        ),
        (
            {key: value for key, value in ASKED.items() if key != "wait"},
            "an ask names v, epoch, ref, client, server, tool, text, text_sha256, deadline_ms "
            "and wait",
        ),
        ({**ASKED, "v": 2}, "an ask's v is 1"),
        ({**ASKED, "v": True}, "an ask's v is 1"),
        ({**ASKED, "v": "1"}, "an ask's v is 1"),
        ({**ASKED, "v": 1.0}, "an ask's v is 1"),
        ({**ASKED, "epoch": "0123456789AB"}, "an ask's epoch isn't of its form"),
        ({**ASKED, "ref": "0123456789abcde"}, "an ask's ref isn't of its form"),
        ({**ASKED, "client": "Agent1"}, "an ask's client isn't of its form"),
        ({**ASKED, "server": ""}, "an ask's server isn't of its form"),
        ({**ASKED, "tool": "cancel order"}, "an ask's tool isn't of its form"),
        ({**ASKED, "tool": "t" * 129}, "an ask's tool isn't of its form"),
        ({**ASKED, "tool": ""}, "an ask's tool isn't of its form"),
        (
            {**ASKED, "text_sha256": DIGEST_OF_TEXT.upper()},
            "an ask's text_sha256 isn't of its form",
        ),
        ({**ASKED, "text_sha256": DIGEST_OF_TEXT[:63]}, "an ask's text_sha256 isn't of its form"),
        ({**ASKED, "text_sha256": None}, "an ask's text_sha256 isn't of its form"),
        (
            {**ASKED, "text": "", "text_sha256": hashlib.sha256(b"").hexdigest()},
            "an ask's text isn't of its form",
        ),
        ({**ASKED, "text": ["x"]}, "an ask's text isn't of its form"),
        ({**ASKED, "text": "\ud800"}, "an ask's text isn't of its form"),
        ({**ASKED, "text": TEXT + " "}, "an ask's text_sha256 isn't its text's"),
        ({**ASKED, "deadline_ms": 0}, "an ask's deadline_ms isn't of its form"),
        ({**ASKED, "deadline_ms": -1}, "an ask's deadline_ms isn't of its form"),
        ({**ASKED, "deadline_ms": 2**53}, "an ask's deadline_ms isn't of its form"),
        ({**ASKED, "deadline_ms": 1.5}, "an ask's deadline_ms isn't of its form"),
        ({**ASKED, "deadline_ms": True}, "an ask's deadline_ms isn't of its form"),
        ({**ASKED, "deadline_ms": "1"}, "an ask's deadline_ms isn't of its form"),
        ({**ASKED, "wait": "Pending"}, "an ask's wait is block or pending"),
        ({**ASKED, "wait": ""}, "an ask's wait is block or pending"),
        ({**ASKED, "wait": ["block"]}, "an ask's wait is block or pending"),
    ],
    ids=[
        "array",
        "null",
        "extra",
        "no-wait",
        "v-two",
        "v-true",
        "v-string",
        "v-float",
        "epoch",
        "ref",
        "client",
        "server",
        "tool-space",
        "tool-long",
        "tool-empty",
        "digest-upper",
        "digest-short",
        "digest-null",
        "text-empty",
        "text-list",
        "text-surrogate",
        "digest-other",
        "deadline-zero",
        "deadline-negative",
        "deadline-unsafe",
        "deadline-float",
        "deadline-true",
        "deadline-string",
        "wait-case",
        "wait-empty",
        "wait-list",
    ],
)
def test_an_ask_refuses_what_it_cant_read(document: object, reason: str) -> None:
    with pytest.raises(RequestRejected) as caught:
        ask_body(document)
    assert caught.value.reason == reason


# --- the relay decisions the poll answers (E.2, G-23) ---------------------------------------------


def test_a_relays_decision_is_numbered_with_the_endings() -> None:
    feed = Feed()
    ended = feed.add(EPOCH, REF, "done", "ok")
    relayed = feed.relay(EPOCH, "fedcba9876543210", "accept", "portal", 1234, "e" * 64)
    assert (ended.seq, relayed.seq, feed.last) == (1, 2, 2)
    assert relayed == Relayed(2, EPOCH, "fedcba9876543210", "accept", "portal", 1234, "e" * 64)
    assert relayed.wire() == {
        "seq": 2,
        "ref": "fedcba9876543210",
        "decision": "accept",
        "via": "portal",
        "decided_ms": 1234,
        "text_sha256": "e" * 64,
    }
    assert feed.since(EPOCH, 0) == [ended, relayed]
    assert feed.since(EPOCH, 1) == [relayed]
    assert feed.since(LATER, 0) == []  # another gateway's relays aren't its own


def test_the_feed_keeps_relays_with_the_endings() -> None:
    feed = Feed(kept=2)
    feed.add(EPOCH, REF, "done", "ok")
    feed.relay(EPOCH, "fedcba9876543210", "decline", "telegram", 1, "e" * 64)
    feed.relay(EPOCH, "fedcba9876543211", "timeout", "none", 2, "f" * 64)
    assert [item.seq for item in feed.since(EPOCH, 0)] == [2, 3]


def test_a_relays_decision_cannot_be_changed() -> None:
    relayed: Any = Feed().relay(EPOCH, REF, "withdrawn", "none", 0, "e" * 64)
    with pytest.raises(dataclasses.FrozenInstanceError):
        relayed.decision = "accept"
