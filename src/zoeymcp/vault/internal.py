"""The vault's own endpoints under ``/_zoeymcp/`` (M7 design G.1). Pure and mutation-tested.

One table, decided before any body byte is read: each endpoint's path, its methods, the identity
it is for, its body cap and how many of its long polls may wait.

| Path | Methods | Identity | Body cap | Waiters |
| --- | --- | --- | --- | --- |
| ``/_zoeymcp/gateway/v1/view`` | GET | gateway | 0 | 4 |
| ``/_zoeymcp/gateway/v1/report/ledger`` | GET, POST | gateway | 1 MiB | (one report at a time) |
| ``/_zoeymcp/gateway/v1/review/jobs`` | GET | gateway | 0 | 1 |
| ``/_zoeymcp/gateway/v1/report/review`` | POST | gateway | from the limits | (one at a time) |
| ``/_zoeymcp/gateway/v1/report/status`` | POST | gateway | 256 KiB | (one at a time) |
| ``/_zoeymcp/egress/v1/allowlists`` | GET | egress | 0 | 2 |

Anything else under ``/_zoeymcp/`` is 404. :func:`decide` takes the identity the listener and the
headers prove (the gateway, the egress role, or none) and answers the endpoint or the refusal:
one bare 403 for every identity failure (design.md 4.1 step 2), whose reason goes to the log
only. The egress role's key reaches the allowlists alone, the gateway's never does, and the
allowlists are never served on the gateway's link socket (X21). The review report's cap follows
the running limits (:func:`.reviewreport.report_max`, GR-30).

The gateway's status report (M6 design K.1, D-29) is read one at a time, and at most one is
accepted per :data:`STATUS_MIN_INTERVAL`, whatever the gateway's own debounce: a report sooner
is a 429 (:class:`StatusGate`, T-12).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from pydantic import TypeAdapter, ValidationError

from ..common import ledgerreport
from ..common.policy.match import NormalizedPath, RequestRejected
from ..common.policy.view import Digest
from .reviewjobs import OLDER, WORKS, Work

Identity = Literal["gateway", "egress"]
Listener = Literal["gateway", "tcp"]

SEGMENT: Final = "_zoeymcp"
# The longest ``?wait=`` of a view poll, and how many may wait at once (M3 design D.2).
VIEW_MAX_WAIT: Final = 25
VIEW_MAX_WAITERS: Final = 4
# The review jobs poll (M.6): the longest ``?wait=``, and how many may wait at once.
REVIEW_WAIT: Final = 25
REVIEW_WAITERS: Final = 1
# A review report's body is read within this many seconds (F.2).
REVIEW_READ_DEADLINE: Final = 30.0
# The egress role's allowlist poll (M.6): the longest ``?wait=``, how many may wait at once, and
# how long after its last fetch the role's lists go stale (I.4; health's
# ``egress_allowlist_stale``, J).
ALLOWLIST_WAIT: Final = 25
ALLOWLIST_WAITERS: Final = 2
ALLOWLIST_MAX_STALE: Final = 300
# The gateway's status report (M6 design K.1, N.4): its body cap, and the seconds between two
# accepted reports.
STATUS_MAX_BYTES: Final = 256 * 1024
STATUS_MIN_INTERVAL: Final = 5.0

_DIGEST: Final[TypeAdapter[str]] = TypeAdapter(Digest)
# How a refusal names who an endpoint is for.
_WHO: Final[dict[Identity, str]] = {"gateway": "the gateway", "egress": "the egress role"}


@dataclass(frozen=True)
class Endpoint:
    """One row of the table. ``name`` is what the request log calls it, ``label`` how its
    refusals name it. ``body_cap`` is None where the limits set it; ``waiters`` None where
    nothing waits."""

    name: str
    label: str
    path: NormalizedPath
    methods: tuple[str, ...]
    identity: Identity
    body_cap: int | None
    waiters: int | None


@dataclass(frozen=True)
class Refusal:
    """The vault's answer instead of an endpoint: a status, the log's reason and, for a 405,
    the ``Allow`` header."""

    status: int
    reason: str
    allow: str | None = None


def _path(*segments: str) -> NormalizedPath:
    return NormalizedPath((SEGMENT, "gateway", "v1", *segments))


def _egress_path(*segments: str) -> NormalizedPath:
    return NormalizedPath((SEGMENT, "egress", "v1", *segments))


VIEW: Final = Endpoint(
    "gateway_view", "the view", _path("view"), ("GET",), "gateway", 0, VIEW_MAX_WAITERS
)
LEDGER: Final = Endpoint(
    "gateway_report",
    "the report path",
    _path("report", "ledger"),
    ("GET", "POST"),
    "gateway",
    ledgerreport.MAX_BODY_BYTES,
    None,
)
REVIEW_JOBS: Final = Endpoint(
    "review_jobs",
    "the review jobs path",
    _path("review", "jobs"),
    ("GET",),
    "gateway",
    0,
    REVIEW_WAITERS,
)
REVIEW_REPORT: Final = Endpoint(
    "review_report",
    "the review report path",
    _path("report", "review"),
    ("POST",),
    "gateway",
    None,
    None,
)
STATUS: Final = Endpoint(
    "gateway_status",
    "the status path",
    _path("report", "status"),
    ("POST",),
    "gateway",
    STATUS_MAX_BYTES,
    None,
)
ALLOWLISTS: Final = Endpoint(
    "egress_allowlists",
    "the allowlist path",
    _egress_path("allowlists"),
    ("GET",),
    "egress",
    0,
    ALLOWLIST_WAITERS,
)
ENDPOINTS: Final = (VIEW, LEDGER, REVIEW_JOBS, REVIEW_REPORT, STATUS, ALLOWLISTS)


def find(path: NormalizedPath) -> Endpoint | None:
    """The endpoint at ``path``, a normalized path under ``/_zoeymcp/``; None for any other."""
    return next((endpoint for endpoint in ENDPOINTS if endpoint.path == path), None)


def decide(
    path: NormalizedPath, method: str, listener: Listener, identity: Identity | None
) -> Endpoint | Refusal:
    """The endpoint a request may reach, or why not: 404 for no endpoint, 403 for the egress
    role's endpoint on the gateway's link (X21) or for an identity it isn't for, then 405 for a
    method it doesn't take. ``listener`` is where the request arrived; every gateway endpoint
    takes the gateway on either."""
    endpoint = find(path)
    if endpoint is None:
        return Refusal(404, "no such vault endpoint")
    if endpoint.identity == "egress" and listener == "gateway":
        return Refusal(403, f"{endpoint.label} isn't served on the gateway's link")
    if identity != endpoint.identity:
        return Refusal(403, f"{endpoint.label} is for {_WHO[endpoint.identity]} only")
    if method not in endpoint.methods:
        methods = endpoint.methods
        reason = f"{endpoint.label} takes " + " or ".join(methods)
        if len(methods) == 1:
            reason += " only"
        return Refusal(405, reason, allow=", ".join(methods))
    return endpoint


def wait_seconds(value: str, most: int) -> int:
    """A ``wait`` query value: plain digits, at most ``most`` seconds. Raises
    :class:`RequestRejected`."""
    if not (value.isascii() and value.isdigit()):
        raise RequestRejected("wait must be a number of seconds")
    # Capped before int(), which refuses a string of thousands of digits.
    seconds = value.lstrip("0")
    if len(seconds) > len(str(most)):
        return most
    return min(int(seconds or "0"), most)


def jobs_query(params: list[tuple[str, str]]) -> tuple[int, str, frozenset[Work]]:
    """A review jobs poll's ``(wait, view, kinds)``: ``view`` is required, the digest of the view
    the gateway's policy client holds (``sha256:`` and 64 hex, CR-8); ``wait`` at most
    :data:`REVIEW_WAIT`, or 0; ``kinds`` the job kinds the gateway runs, ``review`` and then
    ``clear`` if it runs clear jobs (M6 design J.4, G-8), or reviews only when it advertises
    none, as an older gateway does. Any other parameter, or one given twice, is refused."""
    names = [name for name, _ in params]
    if len(set(names)) != len(names) or not set(names) <= {"wait", "view", "kinds"}:
        raise RequestRejected("the review jobs path takes wait, view and kinds, once each")
    given = dict(params)
    if "view" not in given:
        raise RequestRejected("the review jobs path needs the view's digest")
    try:
        digest = _DIGEST.validate_python(given["view"])
    except ValidationError as exc:
        raise RequestRejected("view must be sha256: and 64 hex digits") from exc
    wait = wait_seconds(given["wait"], REVIEW_WAIT) if "wait" in given else 0
    kinds = OLDER
    if "kinds" in given:
        listed = given["kinds"].split(",")
        if listed not in (["review"], ["review", "clear"]):
            raise RequestRejected("kinds is review, or review,clear")
        kinds = frozenset(work for work in WORKS if work in listed)
    return wait, digest, kinds


def allowlist_wait(params: list[tuple[str, str]]) -> int:
    """The seconds an allowlist poll may wait: ``?wait=N``, at most :data:`ALLOWLIST_WAIT`, or
    0. Any other parameter, or ``wait`` twice, is refused (:class:`RequestRejected`)."""
    if not params:
        return 0
    if len(params) > 1 or params[0][0] != "wait":
        raise RequestRejected("the allowlist path takes one parameter, wait")
    return wait_seconds(params[0][1], ALLOWLIST_WAIT)


class StatusGate:
    """The status path's admission (K.1, T-12): one report read at a time, and at most one
    accepted per :data:`STATUS_MIN_INTERVAL`. :meth:`begin` admits a report or answers the 429;
    :meth:`end` lets the next one in, and starts the interval again when this one was accepted.
    A refused report doesn't count toward the interval. ``now`` is monotonic seconds."""

    def __init__(self) -> None:
        self.reading = False
        self.accepted_at: float | None = None

    def begin(self, now: float) -> Refusal | None:
        """None, with the report now being read; or the refusal, for one being read already or
        an accepted one too recently."""
        if self.reading:
            return Refusal(429, "a status report is being read")
        if self.accepted_at is not None and now - self.accepted_at < STATUS_MIN_INTERVAL:
            return Refusal(429, "a status report came too soon after the last")
        self.reading = True
        return None

    def end(self, now: float, *, accepted: bool) -> None:
        self.reading = False
        if accepted:
            self.accepted_at = now
