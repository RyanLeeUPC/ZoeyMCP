"""The vault's own endpoints (M7 design G.1; O.2 ``test_internal.py``): one table, decided before
any body byte is read, the review jobs poll's query (F.2, CR-8), (step 17b) the egress role's
allowlists: its key there alone, never on the gateway's link (G.2, G.3, X21), and (M6 step 7)
the gateway's status path, one report at a time and at most one accepted per 5 s (K.1, T-12,
FM-19)."""

from __future__ import annotations

import dataclasses

import pytest

from zoeymcp.common import ledgerreport
from zoeymcp.common.policy.match import NormalizedPath, RequestRejected
from zoeymcp.vault import app, internal
from zoeymcp.vault.internal import (
    ALLOWLISTS,
    ENDPOINTS,
    LEDGER,
    REVIEW_JOBS,
    REVIEW_REPORT,
    STATUS,
    VIEW,
    Endpoint,
    Refusal,
    StatusGate,
    _egress_path,
    _path,
    allowlist_wait,
    decide,
    find,
    jobs_query,
    wait_seconds,
)
from zoeymcp.vault.reviewjobs import OLDER

DIGEST = "sha256:" + "ab" * 32
TAKES = "the review jobs path takes wait, view and kinds, once each"
KINDS = "kinds is review, or review,clear"
GATEWAY_ENDPOINTS = (VIEW, LEDGER, REVIEW_JOBS, REVIEW_REPORT, STATUS)


def path(text: str) -> NormalizedPath:
    return NormalizedPath(tuple(text.strip("/").split("/")))


# --- the table ------------------------------------------------------------------------------------


def test_the_table_is_g1s() -> None:
    """Path, methods, identity, body cap and waiters, as G.1 lists them, M6 K.1's status path
    after the gateway's other rows, the egress row last (step 17b)."""
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
