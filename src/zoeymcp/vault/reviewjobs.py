"""Review jobs (M7 design F.1, F.2, F.4; D-29, GR-11, OPS-11). Pure and mutation-tested.

The listing needs the gateway's SDK, and the vault never connects to the gateway (X12), so the
gateway asks for work: it long-polls the jobs path with the digest of the view its policy client
holds, runs the review a job names, and posts the result to the report path. :class:`JobTable`
holds the jobs in the vault's memory, on a monotonic clock:

- **Queueing** (:meth:`JobTable.queue`): the socket (``cli``) and the portal (``portal``) queue a
  job for a server in the running view, remote (bridges included) or toolkit, recording the view
  digest it was queued at. A ``done`` job for the server at the current digest is handed to any
  owner of the same surface instead (OPS-11), unless a fresh review is asked for. At most
  :data:`REVIEW_JOBS_MAX` jobs are **active** (``queued`` or ``sent``), one per server; ``done``
  and ``failed`` ones count toward neither limit, and a new job replaces the server's finished
  ones of its surface. Nothing is queued on a refusal (GR-9).
- **The poller** (CR-15, OPS-20): a poll that is waiting counts as seen, and so does a claimed
  job within its :data:`CLAIM_DEADLINE`, since the gateway is running it; otherwise the poller's
  last sign of life (a poll's end, or a post for a ``sent`` job) must be within the last
  :data:`REVIEW_SEEN` seconds, or the queue call is ``review_unavailable``.
  In the first :data:`REVIEW_START_GRACE` seconds after the vault started, with no poll seen
  yet, the call is told to wait for the first poll instead (:class:`Wait`).
- **Claiming** (:meth:`JobTable.claim`): a poll at a digest takes the jobs queued at that digest,
  which become ``sent``. A job no poll at its digest claims within :data:`QUEUE_TTL` fails
  ``review_stale`` (FM-12, FM-15); a claimed one with no result within :data:`CLAIM_DEADLINE`
  fails ``review_timeout`` (FM-13).
- **Clear jobs** (M6 design J.4, G-8): a job is a review or a ``clear``, which asks the gateway to
  list the server again and clear its drift marks only if every included tool matches its pin.
  A poll advertises the kinds it runs (``kinds=review,clear``), and a clear job is offered only to
  one that advertised ``clear``; an older gateway advertises nothing and gets review jobs only,
  so a clear asked while only it polls is refused ``clear_unsupported`` (FM-29). A clear is never
  handed back done, and leaves the server's finished reviews alone.
- **The result**: :func:`read_result` reads a post, its report with
  :func:`.reviewreport.read`, which refuses the whole of it ``review_invalid`` or
  ``pin_mismatch`` (X11); then :meth:`JobTable.post` ends the job it names, which must be
  ``sent``, once (``job_unknown`` otherwise, FM-14). A refused report, and a gateway's
  ``error``, end the job ``failed``; so does a clear the gateway refused, its ``not_clean``
  mapped to the portal's ``clear_not_clean`` here and nowhere else (CR-8). A finished job stays
  readable for :data:`RESULT_TTL` seconds, so a hundred tools can be classified before it goes.

A job's ID is 256 random bits, compared in constant time, never logged (only :attr:`Job.hash8`,
M.4) and refused by the logger. Nothing here does I/O; the clock and the ID source are injected.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Final, Literal

from ..common import reviewreport
from ..common.logs import refuse_type
from ..common.policy.schema import GatewayLimits
from ..common.reviewreport import RemoteReport, ReportRefused, ToolkitReport

REVIEW_JOBS_MAX: Final = 2
# A poll must have finished (or a sent job's result come) within this many seconds, unless one
# is waiting or a claimed job is being run (CR-15).
REVIEW_SEEN: Final = 15.0
# How long after the vault starts a queue call waits for the first poll (OPS-20): the gateway's
# poller backs off up to 30 s after the vault is recreated.
REVIEW_START_GRACE: Final = 45.0
QUEUE_TTL: Final = 60.0
CLAIM_DEADLINE: Final = 120.0
RESULT_TTL: Final = 1800.0
# 256 bits: token_urlsafe(32) gives 43 characters.
ID_BYTES: Final = 32
# The longest job ID a post may name: an ID is 43 characters.
JOB_ID_MAX: Final = 64
# How many of a pin_mismatch's tools the refusal names.
TOOLS_SHOWN: Final = 5
# The gateway's own refusal of a job (gateway/review.py's ReviewError): its status, its reason as
# ``code``, and its message, bounded like a finding's.
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ERROR_STATUS: Final = range(400, 600)

# What a queue call, a read or a post is refused with.
Reason = Literal[
    "review_busy",
    "review_unknown_server",
    "job_unknown",
    "review_jobs_full",
    "review_unavailable",
    "clear_unsupported",
]
Owner = Literal["cli", "portal"]
State = Literal["queued", "sent", "done", "failed"]
# Why a job failed: on the clock, by the gateway, a report the vault refused, or a clear the
# gateway refused because an included tool doesn't match its pin.
Failure = (
    Literal["review_stale", "review_timeout", "review_failed", "clear_not_clean"]
    | reviewreport.Reason
)
ServerKind = Literal["remote", "toolkit"]
# What a job asks the gateway to run (M6 design J.4): a review, or a clear of the server's marks.
Work = Literal["review", "clear"]
WORKS: Final[tuple[Work, ...]] = ("review", "clear")
# What a poll that advertises no kinds runs: an older gateway's, reviews only (G-8).
OLDER: Final[frozenset[Work]] = frozenset({"review"})
# The portal's name for the gateway's ``not_clean`` (a clear it refused: gateway/review.py, whose
# admin socket and ``zoeymcp review --clear`` keep the word), mapped in _cleared() only (CR-8).
CLEAR_NOT_CLEAN: Final[Failure] = "clear_not_clean"
_ACTIVE: Final = ("queued", "sent")
_FINISHED: Final = ("done", "failed")


class ReviewRefused(Exception):
    """A queue call, a read or a post the table refuses. ``reason`` is M.2's; ``fields`` are
    what its text names (the server, or why no poller counts as seen)."""

    def __init__(self, reason: Reason, message: str, **fields: str) -> None:
        self.reason: Reason = reason
        self.fields = fields
        super().__init__(f"{reason}: {message}")


@dataclass(frozen=True, repr=False)
class Job:
    """One review job. ``digest`` is the view digest it was queued at; ``report`` is set when it
    is ``done`` (and when a clear failed ``clear_not_clean``: the review that found it),
    ``failure`` (with the ``fields`` its refusal names) when it ``failed``. ``work`` is what the
    gateway runs for it, a review or a clear."""

    id: str
    server: str
    kind: ServerKind
    owner: Owner
    digest: str
    queued_at: float
    state: State = "queued"
    sent_at: float | None = None
    ended_at: float | None = None
    report: RemoteReport | ToolkitReport | None = None
    failure: Failure | None = None
    fields: tuple[tuple[str, str], ...] = ()
    work: Work = "review"

    @property
    def hash8(self) -> str:
        """What the log names the job by (M.4): the first 8 hex digits of its ID's SHA-256."""
        return hashlib.sha256(self.id.encode("ascii")).hexdigest()[:8]

    def __repr__(self) -> str:
        return f"Job(server={self.server!r}, state={self.state!r})"


# It holds its ID, which is never logged (M.4, M.5).
refuse_type(Job)


@dataclass(frozen=True)
class Wait:
    """No poll was seen since the vault started, within the start grace: wait for the first
    one until ``until`` on the table's clock, then ask again (OPS-20, FM-16b)."""

    until: float


@dataclass(frozen=True)
class Ended:
    """A job the clock ended (M.4's ``review_stale``; a timeout)."""

    job: Job
    why: Literal["review_stale", "review_timeout"]


@dataclass(frozen=True)
class Posted:
    """A post's job, ended: ``done``, or ``failed`` with ``refused`` when the vault refused the
    report (``None`` for a gateway's own ``error``)."""

    job: Job
    refused: ReportRefused | None = None


TokenFunction = Callable[[int], str]


class JobTable:
    """Review jobs, the poller's last sign of life, and what the clock ended since the last
    :meth:`sweep`. ``started`` is when the vault started, on ``clock`` (now, by default)."""

    def __init__(
        self,
        clock: Callable[[], float],
        *,
        started: float | None = None,
        token: TokenFunction = secrets.token_urlsafe,
    ) -> None:
        self._clock = clock
        self._token = token
        self._started = clock() if started is None else started
        self._jobs: dict[str, Job] = {}
        self._ended: list[Ended] = []
        self._waiting = 0
        self._last_poll: float | None = None
        self._kinds = OLDER

    def now(self) -> float:
        return self._clock()

    # --- the poller ---------------------------------------------------------------------------

    @property
    def waiting(self) -> int:
        """How many polls are waiting now."""
        return self._waiting

    @property
    def kinds(self) -> frozenset[Work]:
        """What the latest poll advertised it runs: reviews only before any poll."""
        return self._kinds

    def poll_began(self, kinds: frozenset[Work] = OLDER) -> None:
        """A poll began, advertising ``kinds`` (an older gateway advertises none: reviews)."""
        self._waiting += 1
        self._kinds = kinds

    def poll_ended(self) -> None:
        self._waiting -= 1
        self._last_poll = self._clock()

    def availability(self) -> Wait | None:
        """None while a poll waits, while a claimed job is within its deadline (the gateway runs
        one review at a time before it polls again), or within :data:`REVIEW_SEEN` of the last
        poll's end or ``sent`` job's post; :class:`Wait` in the start grace with no poll seen
        yet; else raises ``review_unavailable``."""
        now = self._clock()
        if self._waiting > 0 or self._running(now):
            return None
        if self._last_poll is not None:
            if now - self._last_poll < REVIEW_SEEN:
                return None
            raise ReviewRefused(
                "review_unavailable",
                "no review poll is waiting or finished recently",
                detail=f"no review poll in the last {REVIEW_SEEN:.0f} s",
            )
        if now < self._started + REVIEW_START_GRACE:
            return Wait(self._started + REVIEW_START_GRACE)
        since = int(now - self._started)
        raise ReviewRefused(
            "review_unavailable",
            "no review poll since the vault started",
            detail=(
                f"no review poll since the vault started {since} s ago; the gateway "
                "reconnects within 30 s, try again"
            ),
        )

    # --- jobs ---------------------------------------------------------------------------------

    def queue(
        self,
        server: str,
        owner: Owner,
        digest: str,
        servers: Mapping[str, ServerKind],
        *,
        fresh: bool = False,
        work: Work = "review",
    ) -> Job | Wait:
        """A job for ``server``, one of the running view's ``servers`` (name to kind), queued at
        ``digest``, or the owner's surface's ``done`` review at that digest unless ``fresh``; a
        ``clear`` is always queued anew. Raises ``review_unknown_server``, ``review_busy``,
        ``review_jobs_full``, ``review_unavailable`` or, for a clear the polling gateway doesn't
        run, ``clear_unsupported``; :class:`Wait` means ask again once the first poll came or the
        grace ended. Nothing is queued on a refusal or a wait."""
        self._expire()
        kind = servers.get(server)
        if kind is None:
            raise ReviewRefused(
                "review_unknown_server", "no remote or toolkit server by that name", server=server
            )
        jobs = list(self._jobs.values())
        if not fresh and work == "review":
            for job in jobs:
                if (job.server, job.owner, job.digest, job.state, job.work) == (
                    server,
                    owner,
                    digest,
                    "done",
                    "review",
                ):
                    return job
        active = [job for job in jobs if job.state in _ACTIVE]
        if any(job.server == server for job in active):
            raise ReviewRefused("review_busy", "a review of that server is active", server=server)
        if len(active) >= REVIEW_JOBS_MAX:
            raise ReviewRefused(
                "review_jobs_full", f"at most {REVIEW_JOBS_MAX} reviews can be active"
            )
        wait = self.availability()
        if wait is not None:
            return wait
        if work not in self._kinds:
            raise ReviewRefused(
                "clear_unsupported", "the polling gateway runs no clear jobs", server=server
            )
        for job in jobs:
            if (job.server, job.owner, job.work) == (server, owner, work) and (
                job.state in _FINISHED
            ):
                del self._jobs[job.id]
        job = Job(
            id=self._token(ID_BYTES),
            server=server,
            kind=kind,
            owner=owner,
            digest=digest,
            queued_at=self._clock(),
            work=work,
        )
        self._jobs[job.id] = job
        return job

    def offered(self, digest: str, kinds: frozenset[Work] = OLDER) -> bool:
        """Whether a job of ``kinds`` is queued at ``digest``, for a poll there to claim."""
        self._expire()
        return any(_takes(job, digest, kinds) for job in self._jobs.values())

    def claim(self, digest: str, kinds: frozenset[Work] = OLDER) -> tuple[Job, ...]:
        """Every job of ``kinds`` queued at ``digest``, now ``sent``, in the order they were
        queued: a poll that advertised no ``clear`` never takes a clear job."""
        self._expire()
        now = self._clock()
        claimed = []
        for job in list(self._jobs.values()):
            if _takes(job, digest, kinds):
                claimed.append(self._put(replace(job, state="sent", sent_at=now)))
        return tuple(claimed)

    def get(self, job_id: str, owner: Owner) -> Job:
        """The job, unless it is unknown, gone or another surface's: all three answer
        ``job_unknown``."""
        self._expire()
        job = self._find(job_id)
        if job is None or job.owner != owner:
            raise ReviewRefused("job_unknown", "no such review job")
        return job

    def deadline(self, job: Job) -> float | None:
        """When the clock ends an active job, on the table's clock; None for a finished one."""
        if job.state == "queued":
            return job.queued_at + QUEUE_TTL
        if job.state == "sent" and job.sent_at is not None:
            return job.sent_at + CLAIM_DEADLINE
        return None

    def sent(self, job_id: str) -> Job:
        """The ``sent`` job a post names; ``job_unknown`` for one unknown, gone, never claimed
        or already reported (FM-14)."""
        self._expire()
        job = self._find(job_id)
        if job is None or job.state != "sent":
            raise ReviewRefused("job_unknown", "the post names no review job that was sent")
        return job

    def post(self, result: Result) -> Posted:
        """End the ``sent`` job ``result`` is for (:meth:`sent` refuses any other): ``done``
        with its report, or ``failed`` with the gateway's error or the report's refusal. A
        report of another server, or of another kind, is ``review_invalid``; the gateway's
        ``review_too_large`` fails the job so, with the vault's cap. A clear job's report is
        read by :meth:`_cleared`, and a review job's that clears anything is ``review_invalid``.
        The post is the poller's last sign of life."""
        job = self.sent(result.job)
        self._last_poll = self._clock()
        if result.refused is not None:
            return self._refused(job, result.refused)
        if result.too_large is not None:
            return Posted(self._fail(job, "review_too_large", detail=result.too_large))
        if result.code is not None:
            return Posted(self._fail(job, "review_failed", code=result.code))
        report = result.report
        assert report is not None  # noqa: S101 - a Result holds one of the three
        if result.server != job.server or report.server != job.server or report.kind != job.kind:
            detail = "at server (another server's report, or another kind's)"
            return self._refused(job, ReportRefused("review_invalid", detail))
        if job.work == "clear":
            return self._cleared(job, report)
        if report.cleared is not None or report.not_clean is not None:
            detail = "at cleared (a review job's report clears nothing)"
            return self._refused(job, ReportRefused("review_invalid", detail))
        done = replace(job, state="done", ended_at=self._clock(), report=report)
        return Posted(self._put(done))

    def _cleared(self, job: Job, report: RemoteReport | ToolkitReport) -> Posted:
        """A clear job's report (J.4): it ends ``done`` with the tools whose marks the gateway
        ``cleared``; the gateway's ``not_clean``, its refusal to clear while an included tool
        doesn't match its pin, fails it ``clear_not_clean``, the portal's name for it (CR-8),
        naming the tools and keeping the review that found them. A report with neither, or
        both, is ``review_invalid``."""
        if (report.cleared is None) == (report.not_clean is None):
            detail = "at cleared (a clear job's report says what it cleared, or what didn't match)"
            return self._refused(job, ReportRefused("review_invalid", detail))
        if report.not_clean is not None:
            tools = _named(tuple(report.not_clean))
            return Posted(self._fail(job, CLEAR_NOT_CLEAN, report=report, tools=tools))
        done = replace(job, state="done", ended_at=self._clock(), report=report)
        return Posted(self._put(done))

    def sweep(self) -> tuple[Ended, ...]:
        """Every job the clock ended since the last sweep."""
        self._expire()
        ended, self._ended = tuple(self._ended), []
        return ended

    def __len__(self) -> int:
        self._expire()
        return len(self._jobs)

    def _running(self, now: float) -> bool:
        """Whether a claimed job is within its deadline, on the gateway's one review lock."""
        return any(
            job.state == "sent" and job.sent_at is not None and now < job.sent_at + CLAIM_DEADLINE
            for job in self._jobs.values()
        )

    def _refused(self, job: Job, refusal: ReportRefused) -> Posted:
        if refusal.reason == "pin_mismatch":
            return Posted(self._fail(job, "pin_mismatch", tools=_named(refusal.tools)), refusal)
        return Posted(self._fail(job, refusal.reason, detail=refusal.detail), refusal)

    def _fail(
        self,
        job: Job,
        failure: Failure,
        *,
        report: RemoteReport | ToolkitReport | None = None,
        **fields: str,
    ) -> Job:
        failed = replace(
            job,
            state="failed",
            ended_at=self._clock(),
            failure=failure,
            fields=tuple(fields.items()),
            report=report,
        )
        return self._put(failed)

    def _find(self, job_id: str) -> Job | None:
        """The job with this ID, every ID compared in constant time, with no early exit."""
        wanted = job_id.encode("utf-8", "surrogatepass")
        found = None
        for job in self._jobs.values():
            if hmac.compare_digest(job.id.encode("ascii"), wanted):
                found = job
        return found

    def _put(self, job: Job) -> Job:
        self._jobs[job.id] = job
        return job

    def _expire(self) -> None:
        now = self._clock()
        for job in list(self._jobs.values()):
            deadline = self.deadline(job)
            if deadline is not None and now >= deadline:
                why: Literal["review_stale", "review_timeout"] = (
                    "review_stale" if job.state == "queued" else "review_timeout"
                )
                self._ended.append(Ended(self._fail(job, why), why))
            elif job.ended_at is not None and now >= job.ended_at + RESULT_TTL:
                del self._jobs[job.id]


@dataclass(frozen=True)
class Result:
    """A post's result, read: for ``job``, the ``report`` the ``server`` reported, the
    gateway's error ``code``, or the vault's refusal of the post (``refused``). ``too_large`` is
    the vault's cap, named for the gateway's ``review_too_large``: the vault refused its report
    413 before reading a byte of it, so only this error can say which job that was."""

    job: str
    server: str | None = None
    report: RemoteReport | ToolkitReport | None = None
    code: str | None = None
    refused: ReportRefused | None = None
    too_large: str | None = None


def _takes(job: Job, digest: str, kinds: frozenset[Work]) -> bool:
    """Whether a poll at ``digest`` that runs ``kinds`` claims ``job``."""
    return job.state == "queued" and job.digest == digest and job.work in kinds


def _named(tools: tuple[str, ...]) -> str:
    """Tools as a refusal names them: the first :data:`TOOLS_SHOWN`, and how many more."""
    shown = tools[:TOOLS_SHOWN]
    more = len(tools) - len(shown)
    return ", ".join(shown) + (f" and {more} more" if more > 0 else "")


def named_job(data: object) -> str:
    """The job a post's parsed JSON names; ``job_unknown`` when it names none."""
    named = data.get("job") if isinstance(data, dict) else None
    if not isinstance(named, str) or len(named) > JOB_ID_MAX:
        raise ReviewRefused("job_unknown", "the post names no review job")
    return named


def read_result(data: object, limits: GatewayLimits) -> Result:
    """A post's parsed JSON, ``{"v": 1, "job", "server", "report"}`` or ``{"v": 1, "job",
    "error": {"status", "code", "message"}}``, read: the report with
    :func:`.reviewreport.read` under ``limits``, so one bad pin refuses all of it (X11). Raises
    ``job_unknown`` when it names no job; anything else out of shape is ``review_invalid``. An
    error coded ``review_too_large`` carries the cap the limits give. Needs no table, so the
    vault reads a large report off its event loop."""
    job = named_job(data)
    assert isinstance(data, dict)  # noqa: S101 - named_job read a member of it
    version = data.get("v")
    if type(version) is not int or version != 1:
        return Result(job, refused=ReportRefused("review_invalid", "at v"))
    if set(data) == {"v", "job", "error"}:
        code = _gateway_code(data["error"])
        if code is None:
            return Result(job, refused=ReportRefused("review_invalid", "at error"))
        if code == "review_too_large":
            most = reviewreport.report_max(limits)
            return Result(
                job, code=code, too_large=f"a report is at most {most} bytes (gateway.limits)"
            )
        return Result(job, code=code)
    if set(data) != {"v", "job", "server", "report"} or not isinstance(data["server"], str):
        return Result(job, refused=ReportRefused("review_invalid", "at the result's members"))
    try:
        report = reviewreport.read(data["report"], limits)
    except ReportRefused as exc:
        return Result(job, refused=exc)
    return Result(job, server=data["server"], report=report)


def _gateway_code(error: object) -> str | None:
    """The code of a gateway's ``error``, if it is ``{"status", "code", "message"}`` with a
    4xx or 5xx status, a plain code and a bounded message."""
    if not isinstance(error, dict) or set(error) != {"status", "code", "message"}:
        return None
    status, code, message = error["status"], error["code"], error["message"]
    if type(status) is not int or status not in _ERROR_STATUS:
        return None
    if not isinstance(code, str) or _ERROR_CODE.fullmatch(code) is None:
        return None
    if not isinstance(message, str) or len(message) > reviewreport.MESSAGE_MAX:
        return None
    return code
