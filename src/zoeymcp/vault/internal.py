"""The vault's own endpoints under ``/_zoeymcp/`` (M7 design G.1). Pure and mutation-tested.

One table, decided before any body byte is read: each endpoint's path, its methods, the identity
it is for, its body cap and how many of its long polls may wait.

| Path | Methods | Identity | Body cap | Waiters |
| --- | --- | --- | --- | --- |
| ``/_zoeymcp/gateway/v1/view`` | GET | gateway | 0 | 4 |
| ``/_zoeymcp/gateway/v1/report/ledger`` | GET, POST | gateway | 1 MiB | (one report at a time) |
| ``/_zoeymcp/gateway/v1/review/jobs`` | GET | gateway | 0 | 1 |
| ``/_zoeymcp/gateway/v1/report/review`` | POST | gateway | from the limits | (one at a time) |

Anything else under ``/_zoeymcp/`` is 404. :func:`decide` takes the identity the listener and the
headers prove (the gateway, or none) and answers the endpoint or the refusal: one bare 403 for
every identity failure (design.md 4.1 step 2), whose reason goes to the log only. The review
report's cap follows the running limits (:func:`.reviewreport.report_max`, GR-30).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from pydantic import TypeAdapter, ValidationError

from ..common import ledgerreport
from ..common.policy.match import NormalizedPath, RequestRejected
from ..common.policy.view import Digest

Identity = Literal["gateway"]
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

_DIGEST: Final[TypeAdapter[str]] = TypeAdapter(Digest)


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
ENDPOINTS: Final = (VIEW, LEDGER, REVIEW_JOBS, REVIEW_REPORT)


def find(path: NormalizedPath) -> Endpoint | None:
    """The endpoint at ``path``, a normalized path under ``/_zoeymcp/``; None for any other."""
    return next((endpoint for endpoint in ENDPOINTS if endpoint.path == path), None)


def decide(
    path: NormalizedPath, method: str, listener: Listener, identity: Identity | None
) -> Endpoint | Refusal:
    """The endpoint a request may reach, or why not: 404 for no endpoint, 403 for an identity
    it isn't for, then 405 for a method it doesn't take. ``listener`` is where the request
    arrived; every endpoint here takes the gateway on either."""
    endpoint = find(path)
    if endpoint is None:
        return Refusal(404, "no such vault endpoint")
    if identity != endpoint.identity:
        return Refusal(403, f"{endpoint.label} is for the {endpoint.identity} only")
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


def jobs_query(params: list[tuple[str, str]]) -> tuple[int, str]:
    """A review jobs poll's ``(wait, view)``: ``view`` is required, the digest of the view the
    gateway's policy client holds (``sha256:`` and 64 hex, CR-8); ``wait`` at most
    :data:`REVIEW_WAIT`, or 0. Any other parameter, or one given twice, is refused."""
    names = [name for name, _ in params]
    if len(set(names)) != len(names) or not set(names) <= {"wait", "view"}:
        raise RequestRejected("the review jobs path takes wait and view, once each")
    given = dict(params)
    if "view" not in given:
        raise RequestRejected("the review jobs path needs the view's digest")
    try:
        digest = _DIGEST.validate_python(given["view"])
    except ValidationError as exc:
        raise RequestRejected("view must be sha256: and 64 hex digits") from exc
    wait = wait_seconds(given["wait"], REVIEW_WAIT) if "wait" in given else 0
    return wait, digest
