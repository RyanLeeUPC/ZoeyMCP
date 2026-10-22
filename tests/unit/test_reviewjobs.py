"""Review jobs (M7 design F.1, F.2, F.4; O.2 ``test_reviewjobs.py``).

The table on an injected monotonic clock: queueing at the view digest, the active-job caps and
``done``-job reuse by surface (OPS-11), the poller counted as seen while it waits or for 15 s
after (CR-15) with a queue call 20 s into a waiting poll, the start grace (OPS-20, FM-16b), the
claim at a digest and ``review_stale`` after 60 s (FM-12, FM-15), ``review_timeout`` after 120 s,
no poller (FM-16), results kept 30 minutes, and a post's result read whole (X11). Then the
vault's two endpoints and the admin socket's routes, in process, over the real ``VaultApp``.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import anyio
import httpx
import pytest

from tests.unit.test_reviewreport import unclassified
from tests.unit.test_vault_view import KEYS, key, raw_policy
from zoeymcp.common import logs as common_logs
from zoeymcp.common import reviewreport
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import GatewayLimits, Tools
from zoeymcp.common.reviewreport import REPORT_BYTES_MIN, ReportRefused
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault import logs, reviewjobs
from zoeymcp.vault.admin import AdminApp, SetupCodes
from zoeymcp.vault.app import (
    LISTENER_SCOPE_KEY,
    REFUSAL_HEADER,
    REFUSAL_MARKER,
    Listener,
    VaultApp,
)
from zoeymcp.vault.reviewjobs import (
    CLAIM_DEADLINE,
    ID_BYTES,
    QUEUE_TTL,
    RESULT_TTL,
    REVIEW_JOBS_MAX,
    REVIEW_SEEN,
    REVIEW_START_GRACE,
    Ended,
    Job,
    JobTable,
    Result,
    ReviewRefused,
    Wait,
    named_job,
    read_result,
)
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

LIMITS = GatewayLimits()
A = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64
SERVERS: dict[str, reviewjobs.ServerKind] = {
    "notes": "remote",
    "mail": "toolkit",
    "files": "remote",
}
# Long past the vault's start, so no test waits out the grace by accident.
LATER = 10_000.0

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Clock:
    def __init__(self, now: float = LATER) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def ids() -> Iterator[str]:
    n = 0
    while True:
        n += 1
        yield f"job-{n:02d}"


def table(clock: Clock | None = None, *, started: float = 0.0) -> tuple[JobTable, Clock]:
    """A table whose IDs are job-01, job-02, ...; with a poll that just finished."""
    clock = clock or Clock()
    made = ids()
    jobs = JobTable(clock, started=started, token=lambda size: next(made))
    jobs.poll_began()
    jobs.poll_ended()
    return jobs, clock


def queued(jobs: JobTable, server: str = "notes", **kwargs: Any) -> Job:
    owner = kwargs.pop("owner", "cli")
    digest = kwargs.pop("digest", A)
    job = jobs.queue(server, owner, digest, SERVERS, **kwargs)
    assert isinstance(job, Job), job
    return job


def refused(call: Any, *args: Any, **kwargs: Any) -> ReviewRefused:
    with pytest.raises(ReviewRefused) as caught:
        call(*args, **kwargs)
    return caught.value


def report(server: str = "notes", *names: str) -> dict[str, Any]:
    data = unclassified(*(names or ("list_notes", "delete_note")))
    data["server"] = server
    return data


def posted(job: Job, data: dict[str, Any] | None = None, **envelope: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"v": 1, "job": job.id, "server": job.server}
    body["report"] = report(job.server) if data is None else data
    body.update(envelope)
    return body


def sent(jobs: JobTable, server: str = "notes", digest: str = A) -> Job:
    queued(jobs, server, digest=digest)
    [job] = [j for j in jobs.claim(digest) if j.server == server]
    return job


def post(jobs: JobTable, data: object) -> reviewjobs.Posted:
    return jobs.post(read_result(data, LIMITS))


# --- the constants --------------------------------------------------------------------------------


def test_the_constants_are_m6s() -> None:
    assert REVIEW_JOBS_MAX == 2
    assert (REVIEW_SEEN, REVIEW_START_GRACE) == (15.0, 45.0)
    assert (QUEUE_TTL, CLAIM_DEADLINE, RESULT_TTL) == (60.0, 120.0, 1800.0)
    assert ID_BYTES == 32
    assert reviewjobs.JOB_ID_MAX == 64
    assert reviewjobs.TOOLS_SHOWN == 5


def test_ids_are_256_random_bits() -> None:
    jobs = JobTable(Clock(), started=0.0)
    jobs.poll_began()
    job = queued(jobs)
    assert len(job.id) == 43
    assert job.hash8 == hashlib.sha256(job.id.encode()).hexdigest()[:8]


def test_the_table_starts_on_its_clock() -> None:
    """Without ``started``, the grace runs from the table's making."""
    clock = Clock(500.0)
    jobs = JobTable(clock)
    assert jobs.queue("notes", "cli", A, SERVERS) == Wait(500.0 + REVIEW_START_GRACE)


# --- queueing -------------------------------------------------------------------------------------


def test_a_job_is_queued_at_the_view_digest() -> None:
    jobs, _ = table()
    job = queued(jobs, "mail", owner="portal", digest=B)
    assert (job.id, job.server, job.kind, job.owner, job.digest) == (
        "job-01",
        "mail",
        "toolkit",
        "portal",
        B,
    )
    assert (job.state, job.queued_at, job.sent_at, job.ended_at) == ("queued", LATER, None, None)
    assert (job.report, job.failure, job.fields) == (None, None, ())
    assert jobs.get("job-01", "portal") == job
    assert len(jobs) == 1


def test_an_unknown_server_is_refused_and_nothing_queued() -> None:
    jobs, _ = table()
    refusal = refused(jobs.queue, "bridge-x", "cli", A, SERVERS)
    assert refusal.reason == "review_unknown_server"
    assert refusal.fields == {"server": "bridge-x"}
    assert len(jobs) == 0


def test_one_active_job_per_server_whoever_asks() -> None:
    jobs, _ = table()
    queued(jobs)
    for owner in ("cli", "portal"):
        refusal = refused(jobs.queue, "notes", owner, A, SERVERS)
        assert (refusal.reason, refusal.fields) == ("review_busy", {"server": "notes"})
    jobs.claim(A)
    assert refused(jobs.queue, "notes", "cli", A, SERVERS).reason == "review_busy"
    assert len(jobs) == 1


def test_at_most_two_active_jobs() -> None:
    jobs, _ = table()
    queued(jobs, "notes")
    queued(jobs, "mail")
    refusal = refused(jobs.queue, "files", "cli", A, SERVERS)
    assert (refusal.reason, refusal.fields) == ("review_jobs_full", {})
    assert "at most 2 reviews" in str(refusal)
    assert len(jobs) == 2


def test_busy_comes_before_full() -> None:
    jobs, _ = table()
    queued(jobs, "notes")
    queued(jobs, "mail")
    assert refused(jobs.queue, "notes", "cli", A, SERVERS).reason == "review_busy"


def test_finished_jobs_count_toward_neither_limit() -> None:
    """OPS-11: a done or failed job blocks nothing."""
    jobs, _ = table()
    post(jobs, posted(sent(jobs, "notes")))
    failing = sent(jobs, "mail")
    post(jobs, {"v": 1, "job": failing.id, "error": {"status": 502, "code": "x", "message": ""}})
    assert jobs.get(failing.id, "cli").state == "failed"
    queued(jobs, "files")
    queued(jobs, "mail")
    assert refused(jobs.queue, "notes", "portal", A, SERVERS).reason == "review_jobs_full"


def test_a_done_job_is_reused_by_its_surface_at_the_same_digest() -> None:
    """OPS-11: login --mcp, then --choose, then --choices read one report."""
    jobs, _ = table()
    first = sent(jobs)
    done = post(jobs, posted(first)).job
    assert queued(jobs) == done
    assert len(jobs) == 1


def test_a_done_job_is_not_another_surfaces() -> None:
    jobs, _ = table()
    done = post(jobs, posted(sent(jobs))).job
    other = queued(jobs, owner="portal")
    assert other.id != done.id
    assert other.state == "queued"
    # The CLI's stays, and is still handed back.
    assert jobs.get(done.id, "cli") == done


def test_a_done_job_at_another_digest_is_not_reused() -> None:
    """After a reload the view digest differs: the report may be for another policy."""
    jobs, _ = table()
    done = post(jobs, posted(sent(jobs))).job
    fresh = queued(jobs, digest=B)
    assert (fresh.id, fresh.digest) == ("job-02", B)
    assert refused(jobs.get, done.id, "cli").reason == "job_unknown"


def test_fresh_queues_a_new_job_and_replaces_the_done_one() -> None:
    jobs, _ = table()
    done = post(jobs, posted(sent(jobs))).job
    fresh = queued(jobs, fresh=True)
    assert fresh.id != done.id
    assert refused(jobs.get, done.id, "cli").reason == "job_unknown"
    assert len(jobs) == 1


def test_a_failed_job_is_not_reused() -> None:
    jobs, clock = table()
    job = queued(jobs)
    jobs.poll_began()
    clock.now += QUEUE_TTL
    again = queued(jobs)
    assert again.id != job.id
    assert refused(jobs.get, job.id, "cli").reason == "job_unknown"


def test_a_new_job_keeps_another_servers_finished_ones() -> None:
    jobs, _ = table()
    done = post(jobs, posted(sent(jobs, "notes"))).job
    queued(jobs, "files", fresh=True)
    assert jobs.get(done.id, "cli").state == "done"


def test_nothing_is_queued_on_a_refusal() -> None:
    """GR-9: no poller means no job."""
    jobs, clock = table()
    clock.now += REVIEW_SEEN
    assert refused(jobs.queue, "notes", "cli", A, SERVERS).reason == "review_unavailable"
    assert len(jobs) == 0


# --- the poller ----------------------------------------------------------------------------------


def test_a_queue_call_twenty_seconds_into_a_waiting_poll() -> None:
    """CR-15: a poll waits up to 25 s; while it does, the poller is seen."""
    clock = Clock()
    jobs = JobTable(clock, started=0.0, token=lambda size: "job-01")
    jobs.poll_began()
    clock.now += 20
    assert jobs.waiting == 1
    assert queued(jobs).state == "queued"


def test_a_poll_counts_for_fifteen_seconds_after_it_ends() -> None:
    jobs, clock = table()
    clock.now += REVIEW_SEEN - 0.5
    assert jobs.availability() is None
    clock.now += 0.5
    refusal = refused(jobs.availability)
    assert refusal.reason == "review_unavailable"
    assert refusal.fields == {"detail": "no review poll in the last 15 s"}


def test_no_poller() -> None:
    """FM-16: no poll waiting and none finished in 15 s."""
    jobs, clock = table()
    clock.now += 300
    refusal = refused(jobs.queue, "notes", "cli", A, SERVERS)
    assert (refusal.reason, refusal.fields) == (
        "review_unavailable",
        {"detail": "no review poll in the last 15 s"},
    )


def test_the_waiting_count() -> None:
    jobs, _ = table()
    assert jobs.waiting == 0
    jobs.poll_began()
    jobs.poll_began()
    assert jobs.waiting == 2
    jobs.poll_ended()
    assert jobs.waiting == 1


def test_first_poll_after_start() -> None:
    """FM-16b, OPS-20: in the first 45 s with no poll seen, wait for the first one; past them,
    the refusal says the gateway reconnects within 30 s."""
    clock = Clock(1000.0)
    jobs = JobTable(clock, started=1000.0, token=lambda size: "job-01")
    clock.now = 1010.0
    assert jobs.queue("notes", "cli", A, SERVERS) == Wait(1045.0)
    assert len(jobs) == 0
    clock.now = 1044.9
    assert jobs.availability() == Wait(1045.0)
    clock.now = 1045.0
    refusal = refused(jobs.queue, "notes", "cli", A, SERVERS)
    assert refusal.reason == "review_unavailable"
    assert refusal.fields == {
        "detail": "no review poll since the vault started 45 s ago; the gateway reconnects "
        "within 30 s, try again"
    }
    clock.now = 1100.7
    assert "started 100 s ago" in refused(jobs.availability).fields["detail"]


def test_the_first_poll_ends_the_wait() -> None:
    clock = Clock(1000.0)
    jobs = JobTable(clock, started=1000.0, token=lambda size: "job-01")
    jobs.poll_began()
    assert queued(jobs).state == "queued"


def test_a_poll_seen_in_the_grace_is_judged_as_any() -> None:
    """Once a poll finished, the 15 s rule applies, grace or not."""
    clock = Clock(1000.0)
    jobs = JobTable(clock, started=1000.0, token=lambda size: "job-01")
    jobs.poll_began()
    jobs.poll_ended()
    clock.now = 1020.0
    assert refused(jobs.availability).fields == {"detail": "no review poll in the last 15 s"}


def test_a_claimed_job_being_run_counts_as_seen() -> None:
    """The gateway runs a claimed job before it polls again, and a listing alone can take 30 s:
    a queue call for another server 20 s into that review is queued."""
    jobs, clock = table()
    sent(jobs, "notes")
    clock.now += 20
    assert queued(jobs, "files").state == "queued"


def test_a_claimed_job_counts_until_its_deadline() -> None:
    jobs, clock = table()
    sent(jobs)
    clock.now += CLAIM_DEADLINE - 0.5
    assert jobs.availability() is None
    clock.now += 0.5
    assert refused(jobs.availability).reason == "review_unavailable"


def test_a_queued_job_is_no_sign_of_the_poller() -> None:
    jobs, clock = table()
    queued(jobs, "notes")
    clock.now += REVIEW_SEEN
    assert refused(jobs.queue, "files", "cli", A, SERVERS).reason == "review_unavailable"


def test_a_post_counts_as_the_pollers_last_sign() -> None:
    """Between a post and the next poll the poller is seen, however long the review took."""
    jobs, clock = table()
    job = sent(jobs)
    clock.now += 100
    assert post(jobs, posted(job)).job.state == "done"
    clock.now += REVIEW_SEEN - 0.5
    assert jobs.availability() is None
    clock.now += 0.5
    assert refused(jobs.availability).reason == "review_unavailable"
    # A post for no sent job is no sign of it.
    refused(post, jobs, posted(job))
    assert refused(jobs.availability).reason == "review_unavailable"


# --- claiming, and the clock ----------------------------------------------------------------------


def test_a_poll_claims_the_jobs_queued_at_its_digest() -> None:
    jobs, clock = table()
    first = queued(jobs, "notes", digest=A)
    queued(jobs, "mail", digest=B)
    assert jobs.offered(A)
    assert jobs.offered(B)
    assert not jobs.offered("sha256:" + "c" * 64)
    clock.now += 5
    [claimed] = jobs.claim(A)
    assert claimed.id == first.id
    assert (claimed.state, claimed.sent_at) == ("sent", LATER + 5)
    assert not jobs.offered(A)
    assert jobs.claim(A) == ()
    assert [job.server for job in jobs.claim(B)] == ["mail"]


def test_two_jobs_at_one_digest_are_claimed_together_in_order() -> None:
    jobs, _ = table()
    queued(jobs, "notes")
    queued(jobs, "mail")
    assert [job.server for job in jobs.claim(A)] == ["notes", "mail"]


def test_stale_view_gets_no_job() -> None:
    """FM-12, FM-15: a gateway on another view claims nothing; the job fails review_stale once
    60 s pass, and the clock's end is swept for the log."""
    jobs, clock = table()
    job = queued(jobs, digest=A)
    clock.now += QUEUE_TTL - 1
    assert jobs.claim(B) == ()
    assert jobs.get(job.id, "cli").state == "queued"
    assert jobs.sweep() == ()
    clock.now += 1
    assert not jobs.offered(A)
    failed = jobs.get(job.id, "cli")
    assert (failed.state, failed.failure, failed.ended_at) == ("failed", "review_stale", clock.now)
    assert jobs.sweep() == (Ended(failed, "review_stale"),)
    assert jobs.sweep() == ()
    assert jobs.claim(A) == ()


def test_a_claimed_job_with_no_result_times_out() -> None:
    """FM-13: review_timeout 120 s after the claim."""
    jobs, clock = table()
    clock.now += 10
    job = sent(jobs)
    clock.now += CLAIM_DEADLINE - 1
    assert jobs.get(job.id, "cli").state == "sent"
    clock.now += 1
    failed = jobs.get(job.id, "cli")
    assert (failed.state, failed.failure) == ("failed", "review_timeout")
    [ended] = jobs.sweep()
    assert ended.why == "review_timeout"
    assert refused(jobs.sent, job.id).reason == "job_unknown"


def test_the_deadlines() -> None:
    jobs, clock = table()
    job = queued(jobs)
    assert jobs.deadline(job) == LATER + QUEUE_TTL
    clock.now += 10
    [claimed] = jobs.claim(A)
    assert jobs.deadline(claimed) == LATER + 10 + CLAIM_DEADLINE
    done = post(jobs, posted(claimed)).job
    assert jobs.deadline(done) is None


def test_a_finished_job_is_kept_thirty_minutes() -> None:
    jobs, clock = table()
    job = sent(jobs)
    clock.now += 7
    done = post(jobs, posted(job)).job
    assert done.ended_at == LATER + 7
    clock.now += RESULT_TTL - 0.5
    assert jobs.get(job.id, "cli").state == "done"
    clock.now += 0.5
    assert refused(jobs.get, job.id, "cli").reason == "job_unknown"
    assert len(jobs) == 0


def test_a_failed_job_is_kept_as_long() -> None:
    jobs, clock = table()
    job = queued(jobs)
    clock.now += QUEUE_TTL
    assert jobs.get(job.id, "cli").failure == "review_stale"
    clock.now += RESULT_TTL - 1
    assert jobs.get(job.id, "cli").failure == "review_stale"
    clock.now += 1
    assert refused(jobs.get, job.id, "cli").reason == "job_unknown"


@pytest.mark.parametrize(
    ("job_id", "owner"),
    [("job-01", "portal"), ("job-02", "cli"), ("job-0", "cli"), ("", "cli"), ("\udcff", "cli")],
)
def test_another_surfaces_or_an_unknown_job_is_unknown(job_id: str, owner: Any) -> None:
    jobs, _ = table()
    queued(jobs)
    refusal = refused(jobs.get, job_id, owner)
    assert (refusal.reason, refusal.fields) == ("job_unknown", {})


# --- results ------------------------------------------------------------------------------------


def test_a_report_ends_its_job_done() -> None:
    jobs, clock = table()
    job = sent(jobs)
    clock.now += 3
    result = read_result(posted(job), LIMITS)
    assert (result.job, result.server, result.code, result.refused) == (job.id, "notes", None, None)
    done = jobs.post(result)
    assert done.refused is None
    assert done.job.state == "done"
    assert done.job.report is not None
    assert [entry.name for entry in done.job.report.tools] == ["delete_note", "list_notes"]
    assert done.job.ended_at == LATER + 3
    assert jobs.get(job.id, "cli") == done.job


def test_a_second_result_is_job_unknown() -> None:
    """FM-14: a result for a job that isn't sent (here, already reported) is refused."""
    jobs, _ = table()
    job = sent(jobs)
    post(jobs, posted(job))
    assert refused(post, jobs, posted(job)).reason == "job_unknown"
    assert jobs.get(job.id, "cli").state == "done"


def test_a_result_for_an_unclaimed_job_is_job_unknown() -> None:
    jobs, _ = table()
    job = queued(jobs)
    refusal = refused(jobs.sent, job.id)
    assert (refusal.reason, refusal.fields) == ("job_unknown", {})
    assert refused(post, jobs, posted(job)).reason == "job_unknown"
    assert jobs.get(job.id, "cli").state == "queued"


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        "job-01",
        {},
        {"v": 1},
        {"v": 1, "job": 1},
        {"v": 1, "job": None},
        {"v": 1, "job": "j" * 65},
    ],
)
def test_a_post_naming_no_job_is_job_unknown(data: object) -> None:
    assert refused(named_job, data).reason == "job_unknown"
    assert refused(read_result, data, LIMITS).reason == "job_unknown"


def test_a_long_named_job_up_to_the_cap() -> None:
    assert named_job({"job": "j" * 64}) == "j" * 64


def test_a_gateway_error_ends_its_job_failed() -> None:
    """PC-22: reading the job answers review_failed with the gateway's code."""
    jobs, _ = table()
    job = sent(jobs)
    error = {"status": 502, "code": "upstream", "message": "the upstream refused the listing"}
    result = read_result({"v": 1, "job": job.id, "error": error}, LIMITS)
    assert result == Result(job.id, code="upstream")
    ended = jobs.post(result)
    assert ended.refused is None
    assert (ended.job.state, ended.job.failure, ended.job.fields) == (
        "failed",
        "review_failed",
        (("code", "upstream"),),
    )


@pytest.mark.parametrize(
    "error",
    [
        None,
        {"status": 502, "code": "upstream"},
        {"status": 502, "code": "upstream", "message": "", "data": 1},
        {"status": 399, "code": "upstream", "message": ""},
        {"status": 600, "code": "upstream", "message": ""},
        {"status": 502.0, "code": "upstream", "message": ""},
        {"status": True, "code": "upstream", "message": ""},
        {"status": "502", "code": "upstream", "message": ""},
        {"status": 502, "code": "Upstream", "message": ""},
        {"status": 502, "code": "", "message": ""},
        {"status": 502, "code": "a" * 65, "message": ""},
        {"status": 502, "code": "up stream", "message": ""},
        {"status": 502, "code": "1x", "message": ""},
        {"status": 502, "code": None, "message": ""},
        {"status": 502, "code": "upstream", "message": None},
        {"status": 502, "code": "upstream", "message": "m" * 1001},
    ],
)
def test_a_malformed_error_is_review_invalid(error: object) -> None:
    jobs, _ = table()
    job = sent(jobs)
    ended = post(jobs, {"v": 1, "job": job.id, "error": error})
    assert ended.refused is not None
    assert (ended.refused.reason, ended.refused.detail) == ("review_invalid", "at error")
    assert (ended.job.failure, ended.job.fields) == ("review_invalid", (("detail", "at error"),))


@pytest.mark.parametrize(
    ("error", "code"),
    [
        ({"status": 400, "code": "a", "message": ""}, "a"),
        ({"status": 599, "code": "a" * 64, "message": "m" * 1000}, "a" * 64),
        ({"status": 503, "code": "no_view_2", "message": "x"}, "no_view_2"),
    ],
)
def test_the_error_bounds(error: dict[str, Any], code: str) -> None:
    assert read_result({"v": 1, "job": "j", "error": error}, LIMITS) == Result("j", code=code)


@pytest.mark.parametrize("tools", [512, 1000])
def test_the_gateways_too_large_fails_its_job_with_the_cap(tools: int) -> None:
    """F.4: a report over the cap is refused 413 before a byte is read, naming no job; the
    gateway posts that back as its error, and the job fails review_too_large with the vault's cap,
    as check_length words it."""
    limits = GatewayLimits(max_tools_per_server=tools)
    jobs, _ = table()
    job = sent(jobs)
    error = {"status": 413, "code": "review_too_large", "message": "m"}
    result = read_result({"v": 1, "job": job.id, "error": error}, limits)
    with pytest.raises(ReportRefused) as caught:
        reviewreport.check_length(reviewreport.report_max(limits) + 1, limits)
    assert result == Result(job.id, code="review_too_large", too_large=caught.value.detail)
    ended = jobs.post(result)
    assert ended.refused is None
    assert (ended.job.state, ended.job.failure, ended.job.fields) == (
        "failed",
        "review_too_large",
        (("detail", caught.value.detail),),
    )


@pytest.mark.parametrize(
    ("change", "detail"),
    [
        ({"v": 2}, "at v"),
        ({"v": True}, "at v"),
        ({"extra": 1}, "at the result's members"),
        ({"server": 1}, "at the result's members"),
    ],
)
def test_a_result_out_of_shape_is_review_invalid(change: dict[str, Any], detail: str) -> None:
    jobs, _ = table()
    job = sent(jobs)
    ended = post(jobs, posted(job, **change))
    assert ended.refused is not None
    assert (ended.refused.reason, ended.refused.detail) == ("review_invalid", detail)
    assert ended.job.state == "failed"


def test_an_error_and_a_report_together_are_out_of_shape() -> None:
    jobs, _ = table()
    job = sent(jobs)
    data = posted(job, error={"status": 502, "code": "x", "message": ""})
    ended = post(jobs, data)
    assert ended.refused is not None
    assert ended.refused.detail == "at the result's members"


def test_a_result_without_its_report_is_out_of_shape() -> None:
    jobs, _ = table()
    job = sent(jobs)
    ended = post(jobs, {"v": 1, "job": job.id, "server": "notes"})
    assert ended.refused is not None
    assert ended.refused.detail == "at the result's members"


@pytest.mark.parametrize(
    ("server", "envelope", "inner"),
    [
        ("notes", "files", "notes"),
        ("notes", "notes", "files"),
        # A remote server's report for a toolkit's job.
        ("mail", "mail", "mail"),
    ],
)
def test_another_servers_report_is_review_invalid(server: str, envelope: str, inner: str) -> None:
    """The envelope's server, the report's, and its kind, against the job's."""
    jobs, _ = table()
    job = sent(jobs, server)
    data = posted(job, report(inner), server=envelope)
    ended = post(jobs, data)
    assert ended.refused is not None
    assert ended.refused.reason == "review_invalid"
    assert ended.job.failure == "review_invalid"


def test_a_report_the_model_refuses_fails_its_job() -> None:
    jobs, _ = table()
    job = sent(jobs)
    data = report()
    data["blocked"] = "no"
    ended = post(jobs, posted(job, data))
    assert ended.refused is not None
    assert (ended.refused.reason, ended.refused.detail) == ("review_invalid", "at remote.blocked")
    assert dict(ended.job.fields) == {"detail": "at remote.blocked"}


def test_a_report_is_read_under_the_running_limits() -> None:
    jobs, _ = table()
    job = sent(jobs)
    small = GatewayLimits(max_tools_per_server=1)
    ended = jobs.post(read_result(posted(job), small))
    assert ended.refused is not None
    assert ended.refused.reason == "review_invalid"
    assert "max_tools_per_server" in ended.refused.detail


def test_one_lying_pin_refuses_the_whole_report() -> None:
    """X11: the vault recomputes every pin; one wrong one fails the job pin_mismatch."""
    jobs, _ = table()
    job = sent(jobs)
    data = report()
    data["tools"][0]["pin"] = "sha256:" + "0" * 64
    ended = post(jobs, posted(job, data))
    assert ended.refused is not None
    assert (ended.refused.reason, ended.refused.tools) == ("pin_mismatch", ("delete_note",))
    assert (ended.job.state, ended.job.failure, ended.job.report) == (
        "failed",
        "pin_mismatch",
        None,
    )
    assert dict(ended.job.fields) == {"tools": "delete_note"}


@pytest.mark.parametrize(
    ("count", "tools"), [(5, "t1, t2, t3, t4, t5"), (7, "t1, t2, t3, t4, t5 and 2 more")]
)
def test_a_mismatch_names_five_tools(count: int, tools: str) -> None:
    jobs, _ = table()
    job = sent(jobs)
    names = tuple(f"t{n}" for n in range(1, count + 1))
    ended = jobs.post(Result(job.id, refused=ReportRefused("pin_mismatch", "x", names)))
    assert dict(ended.job.fields) == {"tools": tools}
    assert ended.refused is not None
    assert ended.refused.tools == names


def test_a_job_that_timed_out_while_its_report_was_read_is_unknown() -> None:
    jobs, clock = table()
    job = sent(jobs)
    result = read_result(posted(job), LIMITS)
    clock.now += CLAIM_DEADLINE
    assert refused(jobs.post, result).reason == "job_unknown"
    assert jobs.get(job.id, "cli").failure == "review_timeout"


def test_a_job_is_never_logged_and_its_repr_holds_no_id() -> None:
    jobs, _ = table()
    job = queued(jobs)
    assert repr(job) == "Job(server='notes', state='queued')"
    assert job.id not in repr(job)
    with pytest.raises(TypeError, match="refusing to log"):
        logs.event("x", job=job)
    with pytest.raises(TypeError, match="refusing to log"):
        common_logs.Log("vault").event("x", jobs=[job])


def test_each_refusal_says_why() -> None:
    """The messages beside M.2's reasons, for a traceback or a test, never an answer."""
    jobs, clock = table()
    job = queued(jobs)
    said = {
        str(refused(jobs.queue, "x", "cli", A, SERVERS)),
        str(refused(jobs.queue, "notes", "cli", A, SERVERS)),
        str(refused(jobs.get, "x", "cli")),
        str(refused(jobs.sent, job.id)),
        str(refused(named_job, {})),
    }
    clock.now += REVIEW_SEEN
    said.add(str(refused(jobs.queue, "mail", "cli", A, SERVERS)))
    fresh = JobTable(Clock(), started=0.0)
    said.add(str(refused(fresh.availability)))
    assert said == {
        "review_unknown_server: no remote or toolkit server by that name",
        "review_busy: a review of that server is active",
        "job_unknown: no such review job",
        "job_unknown: the post names no review job that was sent",
        "job_unknown: the post names no review job",
        "review_unavailable: no review poll is waiting or finished recently",
        "review_unavailable: no review poll since the vault started",
    }


def test_another_servers_report_says_so() -> None:
    jobs, _ = table()
    job = sent(jobs)
    ended = post(jobs, posted(job, server="files"))
    assert ended.refused is not None
    assert ended.refused.detail == "at server (another server's report, or another kind's)"


def test_the_reason_types() -> None:
    assert ReviewRefused("job_unknown", "m", a="b").fields == {"a": "b"}
    assert str(ReviewRefused("job_unknown", "m")) == "job_unknown: m"


# --- the vault's endpoints, in process ------------------------------------------------------------


def review_policy(*, max_tools: int | None = None) -> Policy:
    raw = raw_policy()
    servers = raw["gateway"]["servers"]
    servers["notes"] = servers.pop("notes-read")
    raw["gateway"]["clients"]["agent1"]["servers"] = ["notes"]
    if max_tools is not None:
        raw["gateway"]["limits"] = {"max_tools_per_server": max_tools}
    return Policy.model_validate(raw)


@pytest.fixture
def captured() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def lines(buffer: io.StringIO, kind: str | None = None) -> list[dict[str, Any]]:
    parsed = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in parsed if kind is None or line["event"] == kind]


class Rig:
    """A vault on the review policy, its job table on a test clock, and an admin socket app on
    the same vault, as server.py wires them."""

    def __init__(self, tmp_path: Path, *, started: float = 0.0, policy: Policy | None = None):
        self.clock = Clock()
        self.jobs = JobTable(self.clock, started=started)
        store = SecretStore(tmp_path, KEYS)
        store.load()
        client = httpx.AsyncClient(transport=httpx.MockTransport(self.unreachable))
        self.app = VaultApp(
            policy or review_policy(), store, KEYS, client=client, environ={}, review_jobs=self.jobs
        )
        setup = SetupCodes(tmp_path, KEYS.portal_key)
        self.admin = AdminApp(store, KEYS, lambda: self.app.policy, setup, reviews=self.app)

    @staticmethod
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise AssertionError("a review never reaches an upstream")

    async def call(
        self,
        path: str,
        *,
        method: str = "GET",
        listener: str | None = "gateway",
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        app: Any = self.app if listener is None else ListenerTag(self.app, cast(Listener, listener))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(method, path, headers=headers, content=content)

    async def poll(self, wait: int = 0, digest: str | None = None) -> httpx.Response:
        view = digest or self.app.view_digest
        return await self.call(f"/_zoeymcp/gateway/v1/review/jobs?wait={wait}&view={view}")

    async def post(self, body: object, **headers: str) -> httpx.Response:
        content = json.dumps(body).encode()
        sent_headers = {"content-type": "application/json", **headers}
        return await self.call(
            "/_zoeymcp/gateway/v1/report/review",
            method="POST",
            headers=sent_headers,
            content=content,
        )

    async def socket(self, method: str, path: str, body: Any = None) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.admin.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.request(method, path, json=body)

    def seen(self) -> None:
        """A poll that just finished: the poller counts as seen."""
        self.jobs.poll_began()
        self.jobs.poll_ended()


@pytest.fixture
async def rig(tmp_path: Path) -> Any:
    r = Rig(tmp_path)
    r.seen()
    yield r
    await r.app.aclose()


async def test_a_poll_takes_the_job_queued_at_its_view(rig: Rig, captured: io.StringIO) -> None:
    job = await rig.app.queue_review("notes", "cli")
    response = await rig.poll()
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"v": 1, "jobs": [{"id": job.id, "server": "notes"}]}
    assert rig.jobs.get(job.id, "cli").state == "sent"
    assert (await rig.poll()).json() == {"v": 1, "jobs": []}
    [line] = lines(captured, "review_requested")
    assert line == {
        **line,
        "server": "notes",
        "job": job.hash8,
        "owner": "cli",
        "reused": False,
    }
    request = lines(captured, "request")[0]
    assert (request["endpoint"], request["caller"], request["jobs"]) == (
        "review_jobs",
        "gateway",
        1,
    )


async def test_a_poll_at_another_view_takes_nothing(rig: Rig) -> None:
    await rig.app.queue_review("notes", "cli")
    assert (await rig.poll(digest=B)).json() == {"v": 1, "jobs": []}


async def test_a_waiting_poll_is_woken_by_the_queue(rig: Rig) -> None:
    with anyio.fail_after(5):
        polling = asyncio.ensure_future(rig.poll(wait=25))
        while rig.jobs.waiting == 0:
            await asyncio.sleep(0)
        job = await rig.app.queue_review("notes", "cli")
        response = await polling
    assert response.json()["jobs"] == [{"id": job.id, "server": "notes"}]
    assert rig.jobs.waiting == 0


async def test_one_poll_waits_at_a_time(rig: Rig) -> None:
    rig.jobs.poll_began()
    response = await rig.poll()
    assert response.status_code == 429
    assert response.headers["retry-after"] == "1"
    rig.jobs.poll_ended()
    assert (await rig.poll()).status_code == 200


async def test_shutdown_answers_a_waiting_poll(rig: Rig) -> None:
    with anyio.fail_after(5):
        polling = asyncio.ensure_future(rig.poll(wait=25))
        while rig.jobs.waiting == 0:
            await asyncio.sleep(0)
        rig.app.stop_view_waits()
        assert (await polling).json() == {"v": 1, "jobs": []}


async def test_the_poll_is_for_the_gateway_only(rig: Rig, captured: io.StringIO) -> None:
    for listener, headers in (("tcp", {}), (None, {}), ("tcp", {"x-zoeymcp-gateway": "zgw1-x"})):
        response = await rig.call(
            f"/_zoeymcp/gateway/v1/review/jobs?view={A}", listener=listener, headers=headers
        )
        assert response.status_code == 403
        assert response.json() == {"error": "forbidden"}
        assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    reasons = [line["reason"] for line in lines(captured, "request")]
    assert reasons == [
        "the review jobs path is for the gateway only",
        "the review jobs path is for the gateway only",
        "gateway key refused",
    ]
    # A gateway key on TCP is the gateway (no link socket here).
    response = await rig.call(
        f"/_zoeymcp/gateway/v1/review/jobs?view={A}", listener="tcp", headers=key()
    )
    assert response.status_code == 200


async def test_the_poll_takes_get_only_and_a_good_query(rig: Rig) -> None:
    response = await rig.call(f"/_zoeymcp/gateway/v1/review/jobs?view={A}", method="POST")
    assert (response.status_code, response.headers["allow"]) == (405, "GET")
    for query in ("", "?wait=1", f"?view={A}&x=1", "?view=sha256:x"):
        response = await rig.call("/_zoeymcp/gateway/v1/review/jobs" + query)
        assert response.status_code == 400, query


async def test_a_queue_call_waits_for_the_first_poll_after_start(tmp_path: Path) -> None:
    """FM-16b's vault half: in the start grace the queue call waits; the first poll lets it go
    on, and that poll takes its job."""
    rig = Rig(tmp_path, started=LATER)
    with anyio.fail_after(5):
        queueing = asyncio.ensure_future(rig.app.queue_review("notes", "cli"))
        for _ in range(5):
            await asyncio.sleep(0)
        assert not queueing.done()
        assert len(rig.jobs) == 0
        polling = asyncio.ensure_future(rig.poll(wait=25))
        job = await queueing
        response = await polling
    assert response.json()["jobs"] == [{"id": job.id, "server": "notes"}]
    await rig.app.aclose()


async def test_shutdown_ends_a_queue_call_waiting_out_the_grace(
    tmp_path: Path, captured: io.StringIO
) -> None:
    """No poll comes once the vault is stopping, so the call is refused at once, not held for
    up to 45 s while the servers wait for requests in flight."""
    rig = Rig(tmp_path, started=LATER)
    with anyio.fail_after(5):
        queueing = asyncio.ensure_future(rig.app.queue_review("notes", "cli"))
        for _ in range(5):
            await asyncio.sleep(0)
        assert not queueing.done()
        rig.app.stop_view_waits()
        with pytest.raises(ReviewRefused) as caught:
            await queueing
    assert (caught.value.reason, caught.value.fields) == (
        "review_unavailable",
        {"detail": "the vault is stopping"},
    )
    [line] = lines(captured, "review_unavailable")
    assert line["server"] == "notes"
    assert len(rig.jobs) == 0
    await rig.app.aclose()


async def test_past_the_grace_the_queue_call_is_refused(
    tmp_path: Path, captured: io.StringIO
) -> None:
    rig = Rig(tmp_path, started=LATER - REVIEW_START_GRACE)
    with pytest.raises(ReviewRefused) as caught:
        await rig.app.queue_review("notes", "cli")
    assert caught.value.reason == "review_unavailable"
    [line] = lines(captured, "review_unavailable")
    assert line["server"] == "notes"
    assert len(rig.jobs) == 0
    await rig.app.aclose()


async def test_a_report_through_the_vault(rig: Rig, captured: io.StringIO) -> None:
    job = await rig.app.queue_review("notes", "cli")
    await rig.poll()
    response = await rig.post(posted(rig.jobs.get(job.id, "cli")))
    assert response.status_code == 200, response.text
    assert response.json() == {"v": 1, "job": job.id, "state": "done"}
    assert rig.jobs.get(job.id, "cli").state == "done"
    [line] = lines(captured, "review_reported")
    assert (line["server"], line["job"], line["tools"]) == ("notes", job.hash8, 2)
    # A second result for it is job_unknown, logged.
    again = await rig.post(posted(rig.jobs.get(job.id, "cli")))
    assert again.status_code == 409
    assert again.json() == {"error": "error", "code": "job_unknown"}
    assert lines(captured, "review_refused")[-1]["reason"] == "job_unknown"
    assert job.id not in captured.getvalue()


async def test_a_lying_report_is_refused_whole_and_logged_critical(
    rig: Rig, captured: io.StringIO
) -> None:
    job = await rig.app.queue_review("notes", "cli")
    await rig.poll()
    data = report()
    data["tools"][1]["pin"] = "sha256:" + "0" * 64
    response = await rig.post(posted(rig.jobs.get(job.id, "cli"), data))
    assert response.status_code == 502
    assert response.json()["code"] == "pin_mismatch"
    [line] = lines(captured, "review_refused")
    assert (line["reason"], line["level"], line["tools"], line["job"]) == (
        "pin_mismatch",
        "critical",
        1,
        job.hash8,
    )
    assert "list_notes" not in captured.getvalue()
    assert rig.jobs.get(job.id, "cli").failure == "pin_mismatch"


async def test_a_gateway_error_through_the_vault(rig: Rig, captured: io.StringIO) -> None:
    job = await rig.app.queue_review("notes", "cli")
    await rig.poll()
    error = {"status": 503, "code": "no_view", "message": "the gateway has no fresh view"}
    response = await rig.post({"v": 1, "job": job.id, "error": error})
    assert response.json() == {"v": 1, "job": job.id, "state": "failed"}
    [line] = lines(captured, "review_reported")
    assert (line["reason"], line["code"]) == ("review_failed", "no_view")
    assert "fresh view" not in captured.getvalue()


async def test_a_report_too_large_reads_as_review_too_large(
    rig: Rig, captured: io.StringIO
) -> None:
    """F.4 end to end: the 413 names no job, the gateway's error post does, and the socket
    reads the job as review_too_large naming the cap."""
    job = await rig.app.queue_review("notes", "cli")
    await rig.poll()
    too_long = {"content-type": "application/json", "content-length": str(REPORT_BYTES_MIN + 1)}
    path = "/_zoeymcp/gateway/v1/report/review"
    response = await rig.call(path, method="POST", content=b"{}", headers=too_long)
    assert (response.status_code, response.json()["code"]) == (413, "review_too_large")
    error = {"status": 413, "code": "review_too_large", "message": "the vault refused it"}
    response = await rig.post({"v": 1, "job": job.id, "error": error})
    assert response.json() == {"v": 1, "job": job.id, "state": "failed"}
    [line] = lines(captured, "review_reported")
    assert (line["reason"], line["code"]) == ("review_too_large", "review_too_large")
    read = await rig.socket("GET", f"/review/jobs/{job.id}")
    assert (read.status_code, read.json()["reason"]) == (413, "review_too_large")
    assert f"at most {REPORT_BYTES_MIN} bytes" in read.json()["error"]


async def test_the_report_path_checks_before_reading(rig: Rig) -> None:
    path = "/_zoeymcp/gateway/v1/report/review"
    body = b"{}"
    assert (await rig.call(path, method="GET")).status_code == 405
    assert (await rig.call(path, method="POST", content=body, listener="tcp")).status_code == 403
    response = await rig.call(path + "?x=1", method="POST", content=body)
    assert response.status_code == 400
    response = await rig.call(
        path, method="POST", content=body, headers={"content-type": "text/plain"}
    )
    assert (response.status_code, response.json()["code"]) == (415, "content_type")
    too_long = {"content-type": "application/json", "content-length": str(REPORT_BYTES_MIN + 1)}
    response = await rig.call(path, method="POST", content=body, headers=too_long)
    assert (response.status_code, response.json()["code"]) == (413, "review_too_large")
    response = await rig.call(
        path, method="POST", content=b"{", headers={"content-type": "application/json"}
    )
    assert (response.status_code, response.json()["code"]) == (400, "bad_body")
    response = await rig.call(
        path, method="POST", content=b"{}", headers={"content-type": "application/json"}
    )
    assert (response.status_code, response.json()["code"]) == (409, "job_unknown")


async def test_the_report_cap_follows_the_limits(tmp_path: Path) -> None:
    """GR-30: max_tools_per_server x 16 KiB, at least 8 MiB."""
    rig = Rig(tmp_path, policy=review_policy(max_tools=1000))
    rig.seen()
    headers = {"content-type": "application/json", "content-length": str(1000 * 16 * 1024)}
    path = "/_zoeymcp/gateway/v1/report/review"
    response = await rig.call(path, method="POST", content=b"", headers=headers)
    # Within the cap: the body is read and found short.
    assert (response.status_code, response.json()["code"]) == (400, "bad_body")
    headers["content-length"] = str(1000 * 16 * 1024 + 1)
    response = await rig.call(path, method="POST", content=b"", headers=headers)
    assert (response.status_code, response.json()["code"]) == (413, "review_too_large")
    await rig.app.aclose()


async def test_one_report_is_read_at_a_time(rig: Rig) -> None:
    async with rig.app._review_lock:
        response = await rig.post({"v": 1, "job": "x"})
    assert (response.status_code, response.json()["code"]) == (429, "busy")


async def test_a_deep_definition_still_parses(rig: Rig) -> None:
    """The result nests a definition four levels down, so the parse allows canonical's depth
    plus those."""
    job = await rig.app.queue_review("notes", "cli")
    await rig.poll()
    data = report()
    deep: dict[str, Any] = {"type": "string"}
    for _ in range(30):
        deep = {"type": "object", "properties": {"x": deep}}
    entry = data["tools"][0]
    entry["definition"] = copy.deepcopy({**entry["definition"], "inputSchema": deep})
    response = await rig.post(posted(rig.jobs.get(job.id, "cli"), data))
    # Parsed (not bad_body): its pin no longer matches, so the report is refused for that.
    assert response.json()["code"] == "pin_mismatch"


# --- the admin socket's routes (M.1) --------------------------------------------------------------


async def test_the_socket_queues_reads_and_reuses(rig: Rig) -> None:
    queued_answer = await rig.socket("POST", "/review/notes")
    assert queued_answer.status_code == 200, queued_answer.text
    job = queued_answer.json()["job"]
    assert queued_answer.json() == {
        "job": job,
        "server": "notes",
        "state": "queued",
        "reused": False,
    }
    read = await rig.socket("GET", f"/review/jobs/{job}")
    assert read.json() == {"job": job, "server": "notes", "state": "queued"}
    await rig.poll()
    assert (await rig.socket("GET", f"/review/jobs/{job}")).json()["state"] == "sent"
    assert (await rig.post(posted(rig.jobs.get(job, "cli")))).status_code == 200
    with anyio.fail_after(5):
        done = (await rig.socket("GET", f"/review/jobs/{job}?wait=30")).json()
    assert done["state"] == "done"
    assert done["report"] == report()
    again = (await rig.socket("POST", "/review/notes")).json()
    assert (again["job"], again["reused"]) == (job, True)
    fresh = (await rig.socket("POST", "/review/notes", {"fresh": True})).json()
    assert (fresh["state"], fresh["reused"]) == ("queued", False)
    assert fresh["job"] != job


async def test_a_socket_read_waits_for_the_result(rig: Rig) -> None:
    job = await rig.app.queue_review("notes", "cli")
    await rig.poll()
    with anyio.fail_after(5):
        reading = asyncio.ensure_future(rig.socket("GET", f"/review/jobs/{job.id}?wait=30"))
        for _ in range(5):
            await asyncio.sleep(0)
        assert not reading.done()
        await rig.post(posted(rig.jobs.get(job.id, "cli")))
        assert (await reading).json()["state"] == "done"


async def test_a_failed_job_reads_as_its_refusal(rig: Rig) -> None:
    job = await rig.app.queue_review("notes", "cli")
    await rig.poll()
    error = {"status": 502, "code": "upstream", "message": "m"}
    await rig.post({"v": 1, "job": job.id, "error": error})
    read = await rig.socket("GET", f"/review/jobs/{job.id}")
    assert read.status_code == 502
    body = read.json()
    assert (body["reason"], body["state"], body["job"], body["server"]) == (
        "review_failed",
        "failed",
        job.id,
        "notes",
    )
    assert "(upstream)" in body["error"]


async def test_a_stale_job_reads_as_review_stale(rig: Rig, captured: io.StringIO) -> None:
    """FM-12 over the socket, and its log line."""
    job = await rig.app.queue_review("notes", "cli")
    rig.clock.now += QUEUE_TTL
    read = await rig.socket("GET", f"/review/jobs/{job.id}")
    assert (read.status_code, read.json()["reason"]) == (409, "review_stale")
    [line] = lines(captured, "review_stale")
    assert (line["server"], line["job"]) == ("notes", job.hash8)


@pytest.mark.parametrize(
    ("path", "body", "status", "reason"),
    [
        ("/review/other", None, 404, "review_unknown_server"),
        ("/review/notes", {"fresh": 1}, 400, "bad_body"),
        ("/review/notes", {"again": True}, 400, "bad_body"),
    ],
)
async def test_socket_refusals_are_the_catalogues(
    rig: Rig, path: str, body: Any, status: int, reason: str
) -> None:
    response = await rig.socket("POST", path, body)
    assert (response.status_code, response.json()["reason"]) == (status, reason)


async def test_the_socket_refuses_busy_and_no_poller(rig: Rig) -> None:
    await rig.socket("POST", "/review/notes")
    busy = await rig.socket("POST", "/review/notes")
    assert (busy.status_code, busy.json()["reason"]) == (409, "review_busy")
    assert "notes" in busy.json()["error"]
    # The job goes stale, and no poll came for 300 s: FM-16 over the socket.
    rig.clock.now += 300
    gone = await rig.socket("POST", "/review/notes", {"fresh": True})
    assert (gone.status_code, gone.json()["reason"]) == (503, "review_unavailable")
    assert "no review poll in the last 15 s" in gone.json()["error"]


async def test_a_socket_read_of_an_unknown_job(rig: Rig) -> None:
    response = await rig.socket("GET", "/review/jobs/nope")
    assert (response.status_code, response.json()["reason"]) == (409, "job_unknown")
    response = await rig.socket("GET", "/review/jobs/nope?wait=x")
    assert (response.status_code, response.json()["reason"]) == (400, "bad_query")
    response = await rig.socket("GET", "/review/jobs/nope?other=1")
    assert (response.status_code, response.json()["reason"]) == (400, "bad_query")


async def test_a_portal_job_is_unknown_to_the_socket(rig: Rig) -> None:
    job = await rig.app.queue_review("notes", "portal")
    response = await rig.socket("GET", f"/review/jobs/{job.id}")
    assert response.json()["reason"] == "job_unknown"


async def test_without_reviews_the_routes_answer_503(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, KEYS)
    store.load()
    setup = SetupCodes(tmp_path, KEYS.portal_key)
    admin = AdminApp(store, KEYS, review_policy, setup)
    transport = httpx.ASGITransport(app=admin.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
        for method, path in (
            ("POST", "/review/notes"),
            ("GET", "/review/jobs/x"),
            ("POST", "/review/jobs/x/diff"),
        ):
            response = await client.request(method, path)
            assert (response.status_code, response.json()["reason"]) == (503, "unavailable")


# --- fragment 2 over the socket (M7 design F.6, M.1; step 14a) ---------------------------------


def unreviewed_policy() -> Policy:
    """The review policy, its notes server including no tool yet (the report's policy block)
    and its route the gateway's alone, so the policy passes check."""
    policy = review_policy()
    assert policy.gateway is not None
    server = policy.gateway.servers["notes"].model_copy(update={"tools": Tools(), "review": {}})
    servers = {**policy.gateway.servers, "notes": server}
    gateway = policy.gateway.model_copy(update={"servers": servers})
    route = policy.routes[0].model_copy(update={"callers": ["gateway"]})
    return policy.model_copy(update={"gateway": gateway, "routes": [route, *policy.routes[1:]]})


async def done_job(rig: Rig, owner: reviewjobs.Owner = "cli") -> Job:
    job = await rig.app.queue_review("notes", owner)
    await rig.poll()
    assert (await rig.post(posted(rig.jobs.get(job.id, owner)))).status_code == 200
    return rig.jobs.get(job.id, owner)


CHOSEN = {"include": ["list_notes"], "allow": ["list_notes"], "approve": []}


async def test_the_socket_makes_fragment_2(tmp_path: Path) -> None:
    """J1's choices, as the portal posts them: fragment 2 for the CLI's done job, checked
    against the running policy, and the steps after it; nothing is saved."""
    rig = Rig(tmp_path, policy=unreviewed_policy())
    rig.seen()
    job = await done_job(rig)
    made = await rig.socket("POST", f"/review/jobs/{job.id}/diff", CHOSEN)
    assert made.status_code == 200, made.text
    answer = made.json()
    assert set(answer) == {"diff", "next"}
    entry = load_mapping(answer["diff"]["yaml"])["gateway"]["servers"]["notes"]
    assert entry["tools"] == {"include": ["list_notes"], "allow": ["list_notes"], "approve": []}
    [listed] = [e for e in report()["tools"] if e["name"] == "list_notes"]
    assert entry["review"] == {"list_notes": listed["pin"]}
    # Without an onboarding service the socket names the inline policy's commands.
    assert answer["next"][0] == {
        "do": "check_fragment",
        "label": "Check fragment 2 with the running policy",
        "command": "check --with /w/onboard-notes-2.yaml",
        "via": "run_mount",
    }
    compose = await rig.socket(
        "POST", f"/review/jobs/{job.id}/diff", {**CHOSEN, "indent": "compose"}
    )
    assert compose.json()["diff"]["yaml"].startswith("        # zoeymcp: review of notes")
    assert rig.app.policy == unreviewed_policy()
    await rig.app.aclose()


async def test_the_socket_refuses_fragment_2(tmp_path: Path) -> None:
    rig = Rig(tmp_path, policy=unreviewed_policy())
    rig.seen()
    queued = await rig.app.queue_review("notes", "cli")
    path = f"/review/jobs/{queued.id}/diff"
    waiting = await rig.socket("POST", path, CHOSEN)
    assert (waiting.status_code, waiting.json()["reason"]) == (400, "bad_body")
    await rig.poll()
    await rig.post(posted(rig.jobs.get(queued.id, "cli")))
    bodies: list[dict[str, Any]] = [{"include": [], "allow": []}, {**CHOSEN, "extra": 1}]
    for body in bodies:
        refused = await rig.socket("POST", path, body)
        assert (refused.status_code, refused.json()["reason"]) == (400, "bad_body")
    shaped = await rig.socket("POST", path, {**CHOSEN, "indent": 99})
    assert (shaped.status_code, shaped.json()["detail"]) == (400, "indent is 0 to 16, or compose")
    unknown = await rig.socket("POST", path, {**CHOSEN, "include": ["nope"], "allow": ["nope"]})
    assert (unknown.status_code, unknown.json()["reason"]) == (422, "diff_invalid")
    gone = await rig.socket("POST", "/review/jobs/nope/diff", CHOSEN)
    assert (gone.status_code, gone.json()["reason"]) == (409, "job_unknown")
    portal = await done_job(rig, "portal")
    theirs = await rig.socket("POST", f"/review/jobs/{portal.id}/diff", CHOSEN)
    assert theirs.json()["reason"] == "job_unknown"
    # GR-11: a reload that changes the server's tools since the review.
    rig.app.reload(review_policy())
    stale = await rig.socket("POST", path, CHOSEN)
    assert (stale.status_code, stale.json()["reason"]) == (409, "review_stale")
    await rig.app.aclose()


async def test_a_failed_job_has_no_fragment_2(rig: Rig) -> None:
    job = await rig.app.queue_review("notes", "cli")
    await rig.poll()
    error = {"status": 502, "code": "upstream", "message": "m"}
    await rig.post({"v": 1, "job": job.id, "error": error})
    refused = await rig.socket("POST", f"/review/jobs/{job.id}/diff", CHOSEN)
    assert (refused.status_code, refused.json()["reason"]) == (502, "review_failed")
    assert refused.json()["state"] == "failed"


def test_the_listener_scope_key_is_the_apps() -> None:
    assert LISTENER_SCOPE_KEY == "zoeymcp.listener"
