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
| ``/_zoeymcp/gateway/v1/approvals/collect`` | POST | gateway | 1 KiB | - |
| ``/_zoeymcp/gateway/v1/approvals/decisions`` | GET | gateway | 0 | 1 |
| ``/_zoeymcp/gateway/v1/approvals/withdraw`` | POST | gateway | 1 KiB | - |
| ``/_zoeymcp/gateway/v1/approvals/detach`` | POST | gateway | 16 KiB | - |
| ``/_zoeymcp/gateway/v1/approvals/ask`` | POST | gateway | 96 KiB | - |
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

The gateway collects a held call's result, or its status, by its ref and the client it reported
(M8 design E.2, F.5): :func:`collect_body` reads the request, and a body that names no ref asks
for the client's own calls on that server instead (Q46). The vault answers only for the client
and the server the call was held for, so another client's ref reads as an unknown one (T34).

The gateway's other approvals paths (E.2): :func:`withdraw_body` reads the gateway's word that it
abandoned a call, :func:`detach_body` its stop's list of blocking calls to answer pending, and
:func:`decisions_query` its long poll of the endings of held calls (:class:`Feed`, OPS-3). Each
carries the gateway process's epoch, and :class:`Epochs` keeps the epoch rule (G-15): the first
request with a new one makes it the current gateway's, so the vault withdraws what only an
earlier gateway could have used.

A gateway-held prompt goes out of band through the ask (E.2, E.4; Q6 (B)): :func:`ask_body` reads
the gateway's rendered text, its digest (recomputed here, and refused unless it matches) and the
call it is for, and the vault relays the text to its approvers below its own relay line (E.5).
The decisions poll answers each relay's decision beside the held calls' endings, in one
numbering (:class:`Feed`), so the gateway that asked forwards the call, or doesn't.
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass
from typing import Any, Final, Literal

from pydantic import TypeAdapter, ValidationError

from ..common import ledgerreport
from ..common.logs import refuse_type
from ..common.policy.match import NormalizedPath, RequestRejected
from ..common.policy.schema import NAME_PATTERN
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
# A collect's body cap (M8 design E.2), and what its fields are: the gateway process's epoch (12
# hex), the call's ref (16 hex), and a client's and a server's policy names.
COLLECT_MAX_BYTES: Final = 1024
_EPOCH: Final = re.compile(r"[0-9a-f]{12}")
_REF: Final = re.compile(r"[0-9a-f]{16}")
_NAME: Final = re.compile(NAME_PATTERN.removeprefix("^").removesuffix("$"))
# A withdraw's and a detach's body caps, how many calls one detach names, and the reasons a
# withdraw gives: the gateway abandoned the call, in any era (E.2, B.6).
WITHDRAW_MAX_BYTES: Final = 1024
DETACH_MAX_BYTES: Final = 16 * 1024
DETACH_MAX_CALLS: Final = 64
WITHDRAW_REASONS: Final = frozenset({"caller_cancelled"})
# The decisions poll (E.2): the longest ``?wait=``, how many may wait at once, how many endings
# the vault keeps for it, and how many gateway epochs it remembers (G-15). An ending's ``seq``
# has at most 18 digits, below 2**63.
DECISIONS_WAIT: Final = 25
DECISIONS_WAITERS: Final = 1
ENDINGS_KEPT: Final = 1024
EPOCHS_KEPT: Final = 64
_SEQ: Final = re.compile(r"[0-9]{1,18}")
# The ask (E.2): its body cap (a text within the largest budget, with its JSON escapes), the
# policy's tool names, a text's SHA-256 (64 lowercase hex), and the latest deadline (the largest
# integer JSON carries exactly).
ASK_MAX_BYTES: Final = 96 * 1024
_TOOL: Final = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_SAFE_INTEGER: Final = 2**53 - 1
_ASK_KEYS: Final = frozenset(
    {"v", "epoch", "ref", "client", "server", "tool", "text", "text_sha256", "deadline_ms", "wait"}
)

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
COLLECT: Final = Endpoint(
    "approvals_collect",
    "the collect path",
    _path("approvals", "collect"),
    ("POST",),
    "gateway",
    COLLECT_MAX_BYTES,
    None,
)
DECISIONS: Final = Endpoint(
    "approvals_decisions",
    "the decisions path",
    _path("approvals", "decisions"),
    ("GET",),
    "gateway",
    0,
    DECISIONS_WAITERS,
)
WITHDRAW: Final = Endpoint(
    "approvals_withdraw",
    "the withdraw path",
    _path("approvals", "withdraw"),
    ("POST",),
    "gateway",
    WITHDRAW_MAX_BYTES,
    None,
)
DETACH: Final = Endpoint(
    "approvals_detach",
    "the detach path",
    _path("approvals", "detach"),
    ("POST",),
    "gateway",
    DETACH_MAX_BYTES,
    None,
)
ASK: Final = Endpoint(
    "approvals_ask",
    "the ask path",
    _path("approvals", "ask"),
    ("POST",),
    "gateway",
    ASK_MAX_BYTES,
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
ENDPOINTS: Final = (
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
    ALLOWLISTS,
)


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


@dataclass(frozen=True)
class Collect:
    """A collect's request: the gateway's ``epoch``, the ``client`` it reported, the ``server``
    the call was for, and the call's ``ref``; None asks for the client's own calls there."""

    epoch: str
    client: str
    server: str
    ref: str | None


def collect_body(document: object) -> Collect:
    """A collect's strict-JSON body: an object of exactly ``epoch``, ``client``, ``server`` and,
    for one call, ``ref``, each a string of its form. Raises :class:`RequestRejected`."""
    if not isinstance(document, dict):
        raise RequestRejected("a collect is a JSON object")
    keys = set(document)
    if keys not in ({"epoch", "client", "server", "ref"}, {"epoch", "client", "server"}):
        raise RequestRejected("a collect names epoch, client, server and, for one call, ref")
    fields = {"epoch": _EPOCH, "client": _NAME, "server": _NAME, "ref": _REF}
    for key in sorted(keys):
        value = document[key]
        if not isinstance(value, str) or fields[key].fullmatch(value) is None:
            raise RequestRejected(f"a collect's {key} isn't of its form")
    return Collect(document["epoch"], document["client"], document["server"], document.get("ref"))


def _form(kind: str, key: str, value: object, form: re.Pattern[str]) -> str:
    """``value``, a string of ``form``; else :class:`RequestRejected`, naming ``kind``'s
    ``key`` (``kind`` with its article: "a withdraw")."""
    if not isinstance(value, str) or form.fullmatch(value) is None:
        raise RequestRejected(f"{kind}'s {key} isn't of its form")
    return value


@dataclass(frozen=True)
class Withdraw:
    """A withdraw's request (E.2): the gateway abandoned the call ``ref`` that it reported for
    ``client``, for ``reason``."""

    epoch: str
    ref: str
    client: str
    reason: str


def withdraw_body(document: object) -> Withdraw:
    """A withdraw's strict-JSON body: an object of exactly ``epoch``, ``ref``, ``client`` and
    ``reason``, each of its form, the reason one of :data:`WITHDRAW_REASONS`. Raises
    :class:`RequestRejected`."""
    if not isinstance(document, dict):
        raise RequestRejected("a withdraw is a JSON object")
    if set(document) != {"epoch", "ref", "client", "reason"}:
        raise RequestRejected("a withdraw names epoch, ref, client and reason")
    epoch = _form("a withdraw", "epoch", document["epoch"], _EPOCH)
    ref = _form("a withdraw", "ref", document["ref"], _REF)
    client = _form("a withdraw", "client", document["client"], _NAME)
    reason = document["reason"]
    if not isinstance(reason, str) or reason not in WITHDRAW_REASONS:
        raise RequestRejected("a withdraw's reason is caller_cancelled")
    return Withdraw(epoch, ref, client, reason)


@dataclass(frozen=True)
class Detach:
    """A detach's request (E.2, I.2): the gateway stops, and names its blocking held calls, each
    as ``(ref, client)``, each ref once."""

    epoch: str
    calls: tuple[tuple[str, str], ...]


def detach_body(document: object) -> Detach:
    """A detach's strict-JSON body: an object of exactly ``epoch`` and ``calls``, a list of 1 to
    :data:`DETACH_MAX_CALLS` objects of exactly ``ref`` and ``client``, no ref twice. Raises
    :class:`RequestRejected`."""
    if not isinstance(document, dict):
        raise RequestRejected("a detach is a JSON object")
    if set(document) != {"epoch", "calls"}:
        raise RequestRejected("a detach names epoch and calls")
    epoch = _form("a detach", "epoch", document["epoch"], _EPOCH)
    listed = document["calls"]
    if not isinstance(listed, list) or not 1 <= len(listed) <= DETACH_MAX_CALLS:
        raise RequestRejected(f"a detach names 1 to {DETACH_MAX_CALLS} calls")
    calls: list[tuple[str, str]] = []
    for call in listed:
        if not isinstance(call, dict) or set(call) != {"ref", "client"}:
            raise RequestRejected("a detach's call names ref and client")
        ref = _form("a detach", "ref", call["ref"], _REF)
        calls.append((ref, _form("a detach", "client", call["client"], _NAME)))
    if len({ref for ref, _ in calls}) != len(calls):
        raise RequestRejected("a detach names each call once")
    return Detach(epoch, tuple(calls))


@dataclass(frozen=True, repr=False)
class Ask:
    """An ask's request (E.2): the gateway's rendered prompt ``text`` for the call ``ref`` that
    ``client`` made to ``server``'s ``tool``, the gateway's own deadline for it (wall
    milliseconds) and the wait it keeps. Logging it raises: it holds the text."""

    epoch: str
    ref: str
    client: str
    server: str
    tool: str
    text: str
    text_sha256: str
    deadline_ms: int
    wait: Literal["block", "pending"]

    def __repr__(self) -> str:
        return f"Ask(ref={self.ref}, tool={self.tool})"


refuse_type(Ask)


def ask_body(document: object) -> Ask:
    """An ask's strict-JSON body: an object of exactly ``v`` (1), ``epoch``, ``ref``, ``client``,
    ``server``, ``tool``, ``text``, ``text_sha256``, ``deadline_ms`` and ``wait``, each of its
    form, the text not empty and its SHA-256 (of its UTF-8) the one named: the vault recomputes
    it. Raises :class:`RequestRejected`."""
    if not isinstance(document, dict):
        raise RequestRejected("an ask is a JSON object")
    if set(document) != _ASK_KEYS:
        raise RequestRejected(
            "an ask names v, epoch, ref, client, server, tool, text, text_sha256, deadline_ms "
            "and wait"
        )
    version = document["v"]
    if type(version) is not int or version != 1:
        raise RequestRejected("an ask's v is 1")
    epoch = _form("an ask", "epoch", document["epoch"], _EPOCH)
    ref = _form("an ask", "ref", document["ref"], _REF)
    client = _form("an ask", "client", document["client"], _NAME)
    server = _form("an ask", "server", document["server"], _NAME)
    tool = _form("an ask", "tool", document["tool"], _TOOL)
    digest = _form("an ask", "text_sha256", document["text_sha256"], _SHA256)
    text = document["text"]
    if not isinstance(text, str) or not text:
        raise RequestRejected("an ask's text isn't of its form")
    try:
        encoded = text.encode()
    except UnicodeEncodeError as exc:  # a lone surrogate: no UTF-8, so no digest to compare
        raise RequestRejected("an ask's text isn't of its form") from exc
    if hashlib.sha256(encoded).hexdigest() != digest:
        raise RequestRejected("an ask's text_sha256 isn't its text's")
    deadline = document["deadline_ms"]
    if type(deadline) is not int or not 0 < deadline <= _SAFE_INTEGER:
        raise RequestRejected("an ask's deadline_ms isn't of its form")
    wait = document["wait"]
    if wait == "block":
        return Ask(epoch, ref, client, server, tool, text, digest, deadline, "block")
    if wait == "pending":
        return Ask(epoch, ref, client, server, tool, text, digest, deadline, "pending")
    raise RequestRejected("an ask's wait is block or pending")


def decisions_query(params: list[tuple[str, str]]) -> tuple[str, int, int]:
    """A decisions poll's ``(epoch, after, wait)`` (E.2): ``epoch`` is required, the gateway
    process's (12 lowercase hex); ``after`` the seq of the last ending the gateway has, or 0;
    ``wait`` at most :data:`DECISIONS_WAIT`, or 0. Any other parameter, or one given twice, is
    refused (:class:`RequestRejected`)."""
    names = [name for name, _ in params]
    if len(set(names)) != len(names) or not set(names) <= {"epoch", "after", "wait"}:
        raise RequestRejected("the decisions path takes epoch, after and wait, once each")
    given = dict(params)
    if "epoch" not in given:
        raise RequestRejected("the decisions path needs the gateway's epoch")
    if _EPOCH.fullmatch(given["epoch"]) is None:
        raise RequestRejected("epoch must be 12 lowercase hex digits")
    after = given.get("after", "0")
    if _SEQ.fullmatch(after) is None:
        raise RequestRejected("after must be a sequence number")
    wait = wait_seconds(given["wait"], DECISIONS_WAIT) if "wait" in given else 0
    return given["epoch"], int(after), wait


class Epochs:
    """The gateway epochs the vault has seen (E.2's epoch rule, G-15). The first request with one
    it hasn't seen makes that the :attr:`current` epoch; the last :data:`EPOCHS_KEPT` are
    remembered, so a late request from an earlier gateway changes nothing."""

    def __init__(self) -> None:
        self.current: str | None = None
        self._seen: deque[str] = deque(maxlen=EPOCHS_KEPT)

    def arrive(self, epoch: str) -> bool:
        """Whether ``epoch`` is new: it is then the current one, and the vault withdraws the
        relays and the legacy-session holds of every other (:func:`.holds.from_earlier_epoch`)."""
        if epoch in self._seen:
            return False
        self._seen.append(epoch)
        self.current = epoch
        return True


EndedStatus = Literal["done", "denied", "expired", "withdrawn"]
# A relay's decision, in the words of the gateway's ledger (E.2): approved, denied, nobody
# answered by its deadline, or withdrawn (a change, a stop, the gateway's own withdraw).
RelayDecision = Literal["accept", "decline", "timeout", "withdrawn"]


@dataclass(frozen=True)
class Ended:
    """A held call's ending, as a decisions poll answers it (E.2): never its result, which stays
    for collect, nor its text. ``epoch`` is the gateway epoch its marker carried."""

    seq: int
    epoch: str
    ref: str
    status: EndedStatus
    outcome: str

    def wire(self) -> dict[str, Any]:
        return {"seq": self.seq, "ref": self.ref, "status": self.status, "outcome": self.outcome}


@dataclass(frozen=True)
class Relayed:
    """A relay's decision, as a decisions poll answers it (E.2): never its text, only the digest
    of the text the surface decided on, which the gateway checks is the one it asked with
    (G-23). ``epoch`` is the gateway epoch its ask carried, ``decided_ms`` the wall time."""

    seq: int
    epoch: str
    ref: str
    decision: RelayDecision
    via: str
    decided_ms: int
    text_sha256: str

    def wire(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ref": self.ref,
            "decision": self.decision,
            "via": self.via,
            "decided_ms": self.decided_ms,
            "text_sha256": self.text_sha256,
        }


class Feed:
    """The endings and the relay decisions a decisions poll answers (E.2, OPS-3), numbered
    together from 1 in the order they came; the last :data:`ENDINGS_KEPT` are kept.
    :attr:`last` is the latest ``seq``."""

    def __init__(self, kept: int = ENDINGS_KEPT) -> None:
        self.last = 0
        self._endings: deque[Ended | Relayed] = deque(maxlen=kept)

    def add(self, epoch: str, ref: str, status: EndedStatus, outcome: str) -> Ended:
        self.last += 1
        ended = Ended(self.last, epoch, ref, status, outcome)
        self._endings.append(ended)
        return ended

    def relay(
        self,
        epoch: str,
        ref: str,
        decision: RelayDecision,
        via: str,
        decided_ms: int,
        text_sha256: str,
    ) -> Relayed:
        self.last += 1
        relayed = Relayed(self.last, epoch, ref, decision, via, decided_ms, text_sha256)
        self._endings.append(relayed)
        return relayed

    def since(self, epoch: str, after: int) -> list[Ended | Relayed]:
        """What is kept after seq ``after`` for the gateway of ``epoch``: the endings of the calls
        its markers named, and the decisions on the relays it asked."""
        return [ended for ended in self._endings if ended.seq > after and ended.epoch == epoch]
