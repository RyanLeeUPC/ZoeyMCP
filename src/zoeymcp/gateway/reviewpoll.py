"""The gateway's side of the review job path (M7 design F.1, F.3; D-29). I/O, not mutated.

The listing needs the SDK, which only the gateway runs, and the vault never connects to the
gateway (X12), so the gateway asks for work. One task, beside the policy client and the reporter,
long-polls the jobs path with the digest of the view its policy client holds; the vault answers
as soon as a job queued at that digest exists, or with none after 25 s, or at once when its view
changes (D-189). The policy client may not hold the new view yet when that answer comes, and a
poll at a view the vault no longer serves waits its whole 25 s, so after a poll the vault ended
early with nothing the poller waits up to :data:`VIEW_CATCH_UP` for another view first. For
each job the poller checks that the server is a policy name in that view, runs the same review as
``zoeymcp review`` (:func:`.review.review`, any server kind) under ``app.reviewing``, the lock the
admin socket's review takes, so one review runs at a time, and posts the result to the report
path:

- ``{"v": 1, "job", "server", "report"}``: the review's answer through
  :func:`~zoeymcp.common.reviewreport.fit` under the view's limits, so one odd tool can't make
  the vault refuse its server's whole report;
- ``{"v": 1, "job", "error": {"status", "code", "message"}}``: the review's
  :class:`~.review.ReviewError`. A report over the vault's cap
  (:func:`~zoeymcp.common.reviewreport.report_max`, which both sides compute from the same
  limits) isn't sent: its error is ``review_too_large``, as it is after a 413 from the vault,
  which names no job, so the job fails with the vault's cap instead of timing out.

A post that fails is tried twice more within the vault's claim deadline, then dropped
(``review_job_post_failed``); one the vault answers 409 ``job_unknown`` (it restarted, or the job
timed out) is dropped at once (FM-14). A poll that fails backs off from 1 s up to 30 s, logged at
most once a minute (``review_poll_failed``). Every error ends only its round, and the log names a
job by the first 8 hex digits of its ID's SHA-256, never by its ID.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final

import anyio
import httpx2

from ..common import canonical, reviewreport
from ..common.logs import refuse_type
from ..common.policy.schema import NAME_PATTERN, GatewayLimits
from . import logs, review
from .policyclient import Snapshot, backoff
from .vaultlink import (
    REVIEW_JOBS_PATH,
    REVIEW_MAX_ANSWER_BYTES,
    REVIEW_REPORT_PATH,
    vault_refusal_code,
)

WAIT: Final = 25  # the vault's REVIEW_WAIT
LOG_EVERY: Final = 60.0  # review_poll_failed at most this often
POST_TRIES: Final = 3  # a post, and two retries
# The vault fails a claimed job with no result after this many seconds (vault/reviewjobs.py's
# CLAIM_DEADLINE, which the gateway can't import): retries stop there.
CLAIM_DEADLINE: Final = 120.0
NO_VIEW_WAIT: Final = 1.0  # before the first view, a poll would have no digest to name
# After a poll the vault ended early with nothing: how long, and how often, to look for a new view.
VIEW_CATCH_UP: Final = 1.0
VIEW_CATCH_UP_STEP: Final = 0.05
TOO_LARGE: Final = "review_too_large"
# A job ID the vault issued (43 URL-safe characters) and its post may name (at most 64).
_JOB_ID: Final = re.compile(r"[A-Za-z0-9_-]{1,64}")
_NAME: Final = re.compile(NAME_PATTERN)
# What the vault answers a post with, once it has ended the job.
_ENDED: Final = ("done", "failed")
# The reasons a report the vault read and refused fails its job with (common/reviewreport.py).
_REFUSED: Final = ("review_invalid", "pin_mismatch")

Review = Callable[[Any, str], Awaitable[dict[str, Any]]]


@dataclass(frozen=True, repr=False)
class Job:
    """One job a poll answered: its ID, which is never logged, and the server it names."""

    id: str
    server: str

    @property
    def hash8(self) -> str:
        """What the log names the job by (M.4), as the vault does."""
        return hashlib.sha256(self.id.encode("ascii", "replace")).hexdigest()[:8]

    def __repr__(self) -> str:
        return f"Job(server={self.server!r})"


# It holds its ID, which is never logged (M.4).
refuse_type(Job)


class _Failed(Exception):
    """A poll that failed for ``reason``: a stable code, never text from the vault."""


def _error(job: Job, status: int, code: str, message: str) -> dict[str, Any]:
    """A job's error result, its message bounded as the vault reads it."""
    if len(message) > reviewreport.MESSAGE_MAX:
        message = message[: reviewreport.MESSAGE_MAX - len(reviewreport.CUT)] + reviewreport.CUT
    error = {"status": status, "code": code, "message": message}
    return {"v": 1, "job": job.id, "error": error}


def _crashed(job: Job, exc: Exception) -> dict[str, Any]:
    """A review that raised something other than its own error: named by type, never text."""
    return _error(job, 500, "review_crashed", f"the review failed ({type(exc).__name__})")


def _too_large(job: Job, limits: GatewayLimits) -> dict[str, Any]:
    most = reviewreport.report_max(limits)
    return _error(job, 413, TOO_LARGE, f"the review report is over the vault's cap ({most} bytes)")


def _encoded(document: dict[str, Any]) -> bytes:
    # ASCII: a lone surrogate in an upstream's text can't make the body unencodable.
    return json.dumps(document, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()


def _jobs(body: bytes) -> tuple[Job, ...]:
    """The jobs in a poll's answer, ``{"v": 1, "jobs": [{"id", "server"}, ...]}``."""
    try:
        value = canonical.loads_strict(body, max_bytes=REVIEW_MAX_ANSWER_BYTES)
    except canonical.JSONRejected as exc:
        raise _Failed("bad_answer") from exc
    if not isinstance(value, dict) or set(value) != {"v", "jobs"} or value["v"] != 1:
        raise _Failed("bad_answer")
    listed = value["jobs"]
    if not isinstance(listed, list):
        raise _Failed("bad_answer")
    jobs = []
    for item in listed:
        if not isinstance(item, dict) or set(item) != {"id", "server"}:
            raise _Failed("bad_answer")
        job_id, server = item["id"], item["server"]
        if not isinstance(job_id, str) or not isinstance(server, str):
            raise _Failed("bad_answer")
        jobs.append(Job(job_id, server))
    return tuple(jobs)


def _ended(body: bytes) -> str:
    """The state an accepted post answers, ``done`` or ``failed``; ``accepted`` otherwise."""
    try:
        value = canonical.loads_strict(body, max_bytes=REVIEW_MAX_ANSWER_BYTES)
    except canonical.JSONRejected:
        return "accepted"
    state = value.get("state") if isinstance(value, dict) else None
    return state if isinstance(state, str) and state in _ENDED else "accepted"


class ReviewPoller:
    """Polls for review jobs, runs each, and posts its result. ``run_review`` is the review
    (:func:`.review.review`; tests replace it); ``clock``, ``jitter`` and ``sleep`` are the
    loop's."""

    def __init__(
        self,
        app: Any,
        http: httpx2.AsyncClient,
        *,
        wait: int = WAIT,
        run_review: Review | None = None,
        clock: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = random.random,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    ) -> None:
        self._app = app
        self._http = http
        self._wait = wait
        self._review = run_review if run_review is not None else review.review
        self._clock = clock
        self._jitter = jitter
        self._sleep = sleep
        self._failures = 0
        self._logged: float | None = None

    async def run(self) -> None:
        """Poll for ever: a review for each job, backoff while the jobs path fails."""
        while True:
            snapshot: Snapshot | None = self._app.policy.snapshot
            if snapshot is None:
                await self._sleep(NO_VIEW_WAIT)
                continue
            began = self._clock()
            try:
                jobs = await self.poll_once(snapshot)
            except _Failed as failed:
                reason = str(failed)
            except Exception as exc:  # every failure is the same to the loop
                reason = type(exc).__name__
            else:
                self._failures = 0
                claimed = self._clock()
                for job in jobs:
                    await self.run_job(job, snapshot, claimed)
                if not jobs and claimed - began < self._wait:
                    await self._catch_up(snapshot)
                continue
            self._failures += 1
            self._poll_failed(reason)
            await self._sleep(backoff(self._failures, 0.5 + self._jitter()))

    async def _catch_up(self, polled: Snapshot) -> None:
        """Wait up to :data:`VIEW_CATCH_UP` for the policy client to hold a view other than
        ``polled``'s, so the next poll names the vault's view (D-189, M6 design K.5)."""
        deadline = self._clock() + VIEW_CATCH_UP
        while self._clock() < deadline:
            snapshot: Snapshot | None = self._app.policy.snapshot
            if snapshot is None or snapshot.view.digest != polled.view.digest:
                return
            await self._sleep(VIEW_CATCH_UP_STEP)

    async def poll_once(self, snapshot: Snapshot) -> tuple[Job, ...]:
        """One poll at ``snapshot``'s digest: the jobs it claimed, or :class:`_Failed`."""
        params = {"wait": str(self._wait), "view": snapshot.view.digest}
        response = await self._http.get(REVIEW_JOBS_PATH, params=params)
        body = await response.aread()
        if response.status_code != 200:
            raise _Failed(vault_refusal_code(body) or f"status_{response.status_code}")
        return _jobs(body)

    async def run_job(self, job: Job, snapshot: Snapshot, claimed: float) -> None:
        """Review ``job``'s server and post the result; never raises."""
        if _JOB_ID.fullmatch(job.id) is None:
            self._poll_failed("bad_job")  # a post couldn't name it back
            return
        gateway = snapshot.view.gateway
        try:
            if _NAME.fullmatch(job.server) is None or job.server not in gateway.servers:
                document = _error(job, 404, "unknown_server", "no gateway server by that name")
                await self._post(job, None, document, claimed, gateway.limits)
                return
            logs.event("review_job_started", server=job.server, job=job.hash8)
            document = await self._reviewed(job, gateway.limits)
            await self._post(job, job.server, document, claimed, gateway.limits)
        except Exception as exc:  # one job's failure ends only that job
            logs.event(
                "review_job_post_failed",
                server=job.server if _NAME.fullmatch(job.server) else None,
                job=job.hash8,
                outcome=type(exc).__name__,
                level="warning",
            )

    async def _reviewed(self, job: Job, limits: GatewayLimits) -> dict[str, Any]:
        """The job's result: the fitted report, or the review's error."""
        async with self._app.reviewing:
            try:
                answer = await self._review(self._app, job.server)
            except review.ReviewError as exc:
                return _error(job, exc.status, exc.reason, str(exc))
            except Exception as exc:  # the job fails, not the poller
                return _crashed(job, exc)
        try:
            report = reviewreport.fit(answer, limits)
        except Exception as exc:  # an answer the review code never writes
            return _crashed(job, exc)
        return {"v": 1, "job": job.id, "server": job.server, "report": report}

    async def _post(
        self,
        job: Job,
        server: str | None,
        document: dict[str, Any],
        claimed: float,
        limits: GatewayLimits,
    ) -> None:
        """Post ``document`` for ``job``: at most :data:`POST_TRIES` times, within the claim
        deadline. A report the vault won't take for its size becomes ``review_too_large``."""
        body = _encoded(document)
        if "report" in document and len(body) > reviewreport.report_max(limits):
            document = _too_large(job, limits)
            body = _encoded(document)
        deadline = claimed + CLAIM_DEADLINE
        tries = 0
        while True:
            tries += 1
            try:
                response = await self._http.post(
                    REVIEW_REPORT_PATH, content=body, headers={"content-type": "application/json"}
                )
                answer = await response.aread()
            except Exception as exc:  # every failure is the same to the loop
                outcome = type(exc).__name__
            else:
                status, code = response.status_code, vault_refusal_code(answer)
                if status == 200:
                    logs.event(
                        "review_job_done", server=server, job=job.hash8, outcome=_ended(answer)
                    )
                    return
                if status == 413 and code == TOO_LARGE and "report" in document:
                    # The 413 names no job: say which one it was, with the vault's cap (F.4).
                    document = _too_large(job, limits)
                    body = _encoded(document)
                    tries -= 1
                    continue
                if status == 502 and code in _REFUSED:
                    # The vault read the report, refused it whole, and failed the job (X11).
                    logs.event(
                        "review_job_done", server=server, job=job.hash8, outcome=code, level="error"
                    )
                    return
                if status == 409:
                    # The vault restarted, or the job ended: nobody waits for this result.
                    self._post_failed(job, server, code or "job_unknown")
                    return
                outcome = code or f"status_{status}"
            left = deadline - self._clock()
            if tries >= POST_TRIES or left <= 0:
                self._post_failed(job, server, outcome)
                return
            await self._sleep(min(backoff(tries, 0.5 + self._jitter()), left))

    def _post_failed(self, job: Job, server: str | None, outcome: str) -> None:
        logs.event(
            "review_job_post_failed", server=server, job=job.hash8, outcome=outcome, level="warning"
        )

    def _poll_failed(self, reason: str) -> None:
        now = self._clock()
        if self._logged is None or now - self._logged >= LOG_EVERY:
            self._logged = now
            logs.event("review_poll_failed", reason=reason, level="warning")
