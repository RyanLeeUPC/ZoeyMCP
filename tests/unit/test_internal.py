"""The vault's own endpoints (M7 design G.1; O.2 ``test_internal.py``): one table, decided before
any body byte is read, and the review jobs poll's query (F.2, CR-8)."""

from __future__ import annotations

import dataclasses

import pytest

from zoeymcp.common import ledgerreport
from zoeymcp.common.policy.match import NormalizedPath, RequestRejected
from zoeymcp.vault import app, internal
from zoeymcp.vault.internal import (
    ENDPOINTS,
    LEDGER,
    REVIEW_JOBS,
    REVIEW_REPORT,
    VIEW,
    Endpoint,
    Refusal,
    decide,
    find,
    jobs_query,
    wait_seconds,
)

DIGEST = "sha256:" + "ab" * 32


def path(text: str) -> NormalizedPath:
    return NormalizedPath(tuple(text.strip("/").split("/")))


# --- the table ------------------------------------------------------------------------------------


def test_the_table_is_g1s() -> None:
    """Path, methods, identity, body cap and waiters, as G.1 lists them, without the egress row
    (step 17)."""
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
    ]
    assert LEDGER.body_cap == ledgerreport.MAX_BODY_BYTES
    assert REVIEW_JOBS.waiters == internal.REVIEW_WAITERS


def test_the_constants() -> None:
    """M.6's, and the view's from M3 D.2, which the app re-exports for the gateway's contract."""
    assert (internal.REVIEW_WAIT, internal.REVIEW_WAITERS) == (25, 1)
    assert internal.REVIEW_READ_DEADLINE == 30.0
    assert (internal.VIEW_MAX_WAIT, internal.VIEW_MAX_WAITERS) == (25, 4)
    assert (app.VIEW_MAX_WAIT, app.VIEW_MAX_WAITERS) == (25, 4)
    assert app.VIEW_PATH is VIEW.path
    assert app.REPORT_PATH is LEDGER.path
    assert app.REVIEW_JOBS_PATH.text == "/_zoeymcp/gateway/v1/review/jobs"
    assert app.REVIEW_REPORT_PATH.text == "/_zoeymcp/gateway/v1/report/review"
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
        "/_zoeymcp/egress/v1/allowlists",
    ],
)
def test_anything_else_is_404(text: str) -> None:
    assert find(path(text)) is None
    assert decide(path(text), "GET", "gateway", "gateway") == Refusal(404, "no such vault endpoint")


def test_a_trailing_slash_is_another_path() -> None:
    slashed = NormalizedPath(REVIEW_JOBS.path.segments, trailing_slash=True)
    assert find(slashed) is None


# --- deciding -------------------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=lambda e: e.name)
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
    ],
)
def test_another_method_is_405_with_allow(
    endpoint: Endpoint, method: str, reason: str, allow: str
) -> None:
    assert decide(endpoint.path, method, "gateway", "gateway") == Refusal(405, reason, allow)


def test_a_refusal_has_no_allow_by_default() -> None:
    assert Refusal(403, "x").allow is None


# --- the review jobs poll's query ---------------------------------------------------------------


def test_the_view_digest_and_a_wait() -> None:
    assert jobs_query([("wait", "25"), ("view", DIGEST)]) == (25, DIGEST)
    assert jobs_query([("view", DIGEST), ("wait", "3")]) == (3, DIGEST)


def test_without_a_wait_the_poll_answers_at_once() -> None:
    assert jobs_query([("view", DIGEST)]) == (0, DIGEST)


@pytest.mark.parametrize(("value", "seconds"), [("26", 25), ("0" * 40 + "7", 7), ("9" * 400, 25)])
def test_the_wait_is_capped(value: str, seconds: int) -> None:
    assert jobs_query([("wait", value), ("view", DIGEST)]) == (seconds, DIGEST)


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ([], "the review jobs path needs the view's digest"),
        ([("wait", "1")], "the review jobs path needs the view's digest"),
        (
            [("view", DIGEST), ("view", DIGEST)],
            "the review jobs path takes wait and view, once each",
        ),
        (
            [("wait", "1"), ("wait", "1"), ("view", DIGEST)],
            "the review jobs path takes wait and view, once each",
        ),
        ([("view", DIGEST), ("other", "1")], "the review jobs path takes wait and view, once each"),
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
