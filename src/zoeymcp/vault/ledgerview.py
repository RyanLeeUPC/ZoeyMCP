"""The ledger view: the vault's copy and its own chain, one row per call, with the send journal
(M5 design J.5, J.6; M8 design J.2, J.3).

Pure, so each flag can be tested. The records are joined by :mod:`zoeymcp.common.ledgerjoin`, the
code ``zoeymcp ledger`` prints with, and flattened into rows, newest first, a page at a time:

- **No keyed digests and no pin.** An ``asked`` record's ``args``, ``text`` and ``pin`` never
  reach a row; ``zoeymcp ledger check`` in the gateway's container checks arguments (Q12).
- **Two chains, joined by ref (J.2).** The rows are the copy's calls, as the gateway reported
  them. The vault's own chain (its holds and relays) joins each by ref, never by digest: each
  chain is joined alone, so one chain asking a ref again never hides the other's call, and a
  call's latest records from each are merged. A row shows the vault's decision when it wrote
  one (``decided accept`` with ``via``; ``approved_elsewhere`` and ``pending`` are the gateway's
  own records of a vault decision, M8 design C.4), the vault's outcome for a call it held and
  the gateway's for a relay (whose vault outcome is ``unknown``, ``relayed``), who wrote each
  record it shows (``writers``), and the records it doesn't show (``others``). Where one chain's
  decision approves the call and the other's refuses it, the row is flagged ``disagree``. A
  record the gateway wrote is a claim it made, and the page says so. A call only the vault's
  chain holds is no row, since the rows page by the copy's seqs: the first page lists it in
  ``vault_only``, its seq the vault chain's, flagged as an orphan is, by when the vault asked it.
- **The journal join (D-25, J.3).** A send's ``Idempotency-Key`` up to its last dot is the call's
  ref. A row shows its sends' state, SMTP code and time, never the Message-ID or ``req_hmac``. A
  send whose ref the copy doesn't hold, and the vault's chain doesn't hold as ``decided accept``,
  is an orphan, flagged ``not_yet_reported`` until the copy (its live chain or a kept archived
  epoch, J.4) receives a report after that send began. One that began before the span the copy
  can check is ``older_than_copy``. The span is on the vault's clock, never the gateway's ``ts``
  (C-9): a chain held from the gateway's first record spans everything; any other starts when
  the vault received the first line of the earliest file of it kept, and no span starts before
  an archived epoch a restart deleted was last received. Any other orphan is
  ``no_ledger_record``: a send whose call the gateway didn't record, or whose record was lost,
  or one the vault's chain holds but didn't accept. A compromised gateway can cover its own
  sends with records it makes up (threat T4); only the vault's own record of a held call, under
  ``vault_approval``, is beyond its reach, and a call the copy lacks still shows in
  ``vault_only``.
- **Names the current policy lacks** are listed in a row's ``not_in_policy``.

Every string here is the gateway's or the journal's: the portal shows each through
``display.shown``.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

from ..common import ledgerjoin
from ..common.ledgerformat import GENESIS
from ..common.policy.schema import Policy
from .reports import Held

MAX_LIMIT: Final = 200
NAMED: Final = ("client", "server", "tool")  # the asked record's names a policy can lack
_COMMON: Final = frozenset({"v", "seq", "prev", "ts", "ref", "kind", "writer"})
# A decision's verdict on its call, for J.2's disagreement flag: these approve it; these say
# neither (a wait the vault answered pending, an error or a refusal before anyone was asked);
# any other refuses it. The gateway's ``abandoned`` says neither too: its restart closed a call
# whose vault decision it never heard (C.4), while the vault's own means it never forwarded.
APPROVING: Final = frozenset({"accept", "approved_elsewhere"})
NEITHER: Final = frozenset({"pending", "error", "unavailable"})

Flag = Literal["no_ledger_record", "not_yet_reported", "older_than_copy"]


def when(ts: int) -> str:
    """Epoch milliseconds as ``2026-10-19T09:12:03Z``."""
    return datetime.fromtimestamp(ts // 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _least(left: int | None, right: int | None) -> int | None:
    return min((ms for ms in (left, right) if ms is not None), default=None)


def _most(left: int | None, right: int | None) -> int | None:
    return max((ms for ms in (left, right) if ms is not None), default=None)


@dataclass(frozen=True)
class Coverage:
    """What the copy holds, for the orphan check (J.3), its times on the vault's clock: the refs
    of its records; ``first_ms``, the start of the span it can check (0 for a chain held from the
    gateway's first record, None when it holds none); ``received_ms``, when it last received a
    report (None before any); and ``deleted_ms``, when it last received a line of an archived
    epoch a restart deleted (None when none was)."""

    refs: frozenset[str] = frozenset()
    first_ms: int | None = None
    received_ms: int | None = None
    deleted_ms: int | None = None

    def __or__(self, other: Coverage) -> Coverage:
        return Coverage(
            self.refs | other.refs,
            _least(self.first_ms, other.first_ms),
            _most(self.received_ms, other.received_ms),
            _most(self.deleted_ms, other.deleted_ms),
        )

    @property
    def start_ms(self) -> int | None:
        """The start of the span: ``first_ms``, but never before ``deleted_ms``, since what a
        restart deleted can't be checked any more."""
        if self.deleted_ms is None:
            return self.first_ms
        return max(self.first_ms or 0, self.deleted_ms)


def coverage(
    records: Iterable[Mapping[str, Any]],
    *,
    received_ms: int | None = None,
    first_received_ms: int | None = None,
) -> Coverage:
    """What one chain of the copy holds, oldest first, in one pass, so an archived epoch can be
    read a record at a time: its refs; the start of its span, 0 when its first record is the
    gateway's first (``prev`` the genesis hash: nothing came before it), else
    ``first_received_ms``, when the vault received the first line of the earliest file holding it;
    and ``received_ms``, when the vault last received a line of it. Holding no record, it holds
    nothing."""
    refs: set[str] = set()
    first: int | None = None
    held = False
    for record in records:
        if not held:
            held = True
            first = 0 if record["prev"] == GENESIS else first_received_ms
        ref = record.get("ref")
        if ref is not None:
            refs.add(ref)
    if not held:
        return Coverage()
    return Coverage(frozenset(refs), first, received_ms)


@dataclass
class Send:
    """One ``Idempotency-Key``'s journal records: its latest state, and when it began and ended."""

    connector: str
    key: str
    state: str
    smtp_code: int | None
    started_ms: int
    at_ms: int

    @property
    def ref(self) -> str:
        return self.key.rpartition(".")[0]


def sends(journals: Mapping[str, Iterable[Mapping[str, Any]]]) -> list[Send]:
    """Each connector's journal records (as parsed, in order) by key, in the order each began.

    A ``sending`` record starts a send; the first ``sent``, ``failed`` or ``unknown`` after it
    ends it, as the connector's own journal reads them. An ending whose ``sending`` is gone is
    shown as it is.
    """
    found: dict[tuple[str, str], Send] = {}
    for connector, records in journals.items():
        for record in records:
            kind, key, ts = record["kind"], record["key"], record["ts"]
            send = found.get((connector, key))
            if kind == "sending":
                found[(connector, key)] = Send(connector, key, kind, None, ts, ts)
            elif send is None:
                found[(connector, key)] = Send(
                    connector, key, kind, record.get("smtp_code"), ts, ts
                )
            elif send.state == "sending":
                send.state, send.smtp_code, send.at_ms = kind, record.get("smtp_code"), ts
    return list(found.values())


def known(policy: Policy) -> dict[str, frozenset[str]]:
    """The names a row's client and server have in ``policy``, for :func:`page`'s ``known``.
    Tools aren't checked: a server's tools needn't be listed. Without a gateway section no name
    is in the policy."""
    section = policy.gateway
    if section is None:
        return {"client": frozenset(), "server": frozenset()}
    return {"client": frozenset(section.clients), "server": frozenset(section.servers)}


def state(held: Held, *, now: int, broken_at: int | None = None) -> dict[str, Any]:
    """The copy's state line: ``reported_ago`` is how many seconds since the head last moved.
    ``broken_at``: the seq where the copy's files stop chaining, if recovery found one (J.4)."""
    received = held.received_ms
    return {
        "state": held.state,
        "head_seq": held.head_seq,
        "head_hash": held.head_hash,
        "start_seq": held.start_seq,
        "reported_ago": None if received is None else max(0, now - received) // 1000,
        "broken_at": broken_at,
    }


def page(
    records: Iterable[Mapping[str, Any]],
    *,
    held: Held,
    journals: Mapping[str, Iterable[Mapping[str, Any]]],
    now: int,
    chain: Iterable[Mapping[str, Any]] = (),
    before: int | None = None,
    limit: int = MAX_LIMIT,
    known: Mapping[str, Collection[str]] | None = None,
    broken_at: int | None = None,
    archived: Coverage | None = None,
    vault_calls: bool = False,
) -> dict[str, Any]:
    """One page of the view: the rows whose seq is below ``before``, newest first, at most
    ``limit`` (1 to :data:`MAX_LIMIT`), and ``next``, the ``before`` of the page after it (None at
    the end). ``chain``: the vault's own chain's records, joined to the copy's calls by ref (J.2);
    its ledger-level records aren't rows. ``vault_calls`` keeps only the rows of the calls that
    chain holds (``ledger --vault --chain vault``, M8 design K.3): still joined against the whole
    copy, so a call the copy holds is never one only the vault's chain holds. Orphans and
    ``vault_only``, the newest
    :data:`MAX_LIMIT` calls only the vault's chain holds (``vault_only_more`` counts the rest),
    are on the first page, judged against ``records`` (the live chain, whose files ``held``
    lists), ``archived``, what the kept archived epochs hold, and for orphans the vault chain's
    accepted refs (J.3). ``known``: the current policy's names by field (``client``, ``server``,
    ``tool``); a field it doesn't list isn't checked.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    records = list(records)
    vault = [record for record in chain if record.get("ref") is not None]
    by_ref: dict[str, list[Send]] = {}
    found = sends(journals)
    for send in found:
        by_ref.setdefault(send.ref, []).append(send)
    # The vault chain's latest records of each ref, its own asked starting them again (F-53),
    # merged into the copy's calls: each chain read alone, so neither asking a ref again hides
    # the other's call.
    theirs: dict[str, dict[tuple[str, str], Mapping[str, Any]]] = {}
    for record in vault:
        if record["kind"] == "asked":
            theirs[record["ref"]] = {}
        theirs.setdefault(record["ref"], {})[(record["kind"], record["writer"])] = record
    rows: list[dict[str, Any]] = []
    calls: set[int] = set()
    for entry in ledgerjoin.join(records):
        if isinstance(entry, ledgerjoin.Call) and entry.ref in theirs:
            entry = ledgerjoin.Call(entry.ref, {**entry.records, **theirs[entry.ref]})
        row = _row(entry, by_ref, known or {})
        if row["kind"] == "call":
            # A ref asked twice is two entries holding the same, latest, records: one row.
            if row["seq"] in calls:
                continue
            calls.add(row["seq"])
        rows.append(row)
    rows.sort(key=lambda row: row["seq"], reverse=True)
    if vault_calls:
        rows = [row for row in rows if row.get("ref") in theirs]
    if before is not None:
        rows = [row for row in rows if row["seq"] < before]
    shown = rows[:limit]
    began: int | None = None  # when the vault received the earliest kept file's first line
    if held.files:
        began = held.files[0].first_received_ms
        began = held.files[0].received_ms if began is None else began
    live = coverage(records, received_ms=held.received_ms, first_received_ms=began)
    copied = live | (Coverage() if archived is None else archived)
    accepted = frozenset(
        record["ref"]
        for record in vault
        if record["kind"] == "decided" and record.get("decision") == "accept"
    )
    alone = [
        {
            **_row(ledgerjoin.Call(ref, own), by_ref, known or {}),
            "flag": flag(own[("asked", "vault")]["ts"], copied),
        }
        for ref, own in theirs.items()
        if ("asked", "vault") in own and ref not in copied.refs
    ]
    alone.sort(key=lambda row: row["seq"], reverse=True)
    first = before is None
    return {
        "state": state(held, now=now, broken_at=broken_at),
        "rows": shown,
        "orphans": orphans(found, copied | Coverage(accepted)) if first else [],
        "vault_only": alone[:MAX_LIMIT] if first else [],
        "vault_only_more": max(0, len(alone) - MAX_LIMIT) if first else 0,
        "next": shown[-1]["seq"] if len(rows) > limit else None,
    }


def flag(started_ms: int, covered: Coverage) -> Flag:
    """What something the copy doesn't hold, begun at ``started_ms`` on the vault's clock, is
    flagged (J.3): ``not_yet_reported`` unless the copy received a report after it began, then
    ``older_than_copy`` if it began before the copy's span (:attr:`Coverage.start_ms`), else
    ``no_ledger_record``."""
    start, received = covered.start_ms, covered.received_ms
    if received is None or received <= started_ms:
        return "not_yet_reported"
    if start is not None and started_ms < start:
        return "older_than_copy"
    return "no_ledger_record"


def orphans(found: Iterable[Send], covered: Coverage) -> list[dict[str, Any]]:
    """The sends whose ref ``covered`` doesn't hold, newest first, each flagged by when it
    began (:func:`flag`)."""
    out = []
    for send in sorted(found, key=lambda s: s.started_ms, reverse=True):
        if send.ref in covered.refs:
            continue
        out.append(
            {
                "connector": send.connector,
                "key": send.key,
                "state": send.state,
                "at": when(send.at_ms),
                "flag": flag(send.started_ms, covered),
            }
        )
    return out


def verdict(decision: str | None, writer: str) -> bool | None:
    """Whether ``writer``'s ``decision`` approves its call (True), refuses it (False) or says
    neither (None, also when there is none)."""
    if decision is None or decision in NEITHER:
        return None
    if decision == "abandoned" and writer == "gateway":
        return None
    return decision in APPROVING


def _row(
    entry: ledgerjoin.Call | Mapping[str, Any],
    by_ref: Mapping[str, list[Send]],
    known: Mapping[str, Collection[str]],
) -> dict[str, Any]:
    if not isinstance(entry, ledgerjoin.Call):
        return {
            "kind": entry["kind"],
            "seq": entry["seq"],
            "at": when(entry["ts"]),
            "writer": entry["writer"],
            "fields": {k: v for k, v in entry.items() if k not in _COMMON},
        }
    # The gateway's asked, as reported; the vault's for a call only its chain holds.
    asked = entry.get("asked", "gateway") or entry.records[("asked", "vault")]
    where = (entry.get("asked", "vault") or asked)["where"]
    by_vault, by_gateway = entry.get("decided", "vault"), entry.get("decided", "gateway")
    decided = by_vault or by_gateway or {}
    # The vault's outcome for a call the vault held, the gateway's for a relay; else either's.
    order = ("vault", "gateway") if where == "vault" else ("gateway", "vault")
    outcome = entry.get("outcome", *order) or {}
    shown = {"asked": asked, "decided": decided, "outcome": outcome}
    vault_says = None if by_vault is None else verdict(by_vault["decision"], "vault")
    gateway_says = None if by_gateway is None else verdict(by_gateway["decision"], "gateway")
    return {
        "kind": "call",
        "seq": asked["seq"],
        "ref": entry.ref,
        "at": when(asked["ts"]),
        "client": asked["client"],
        "server": asked["server"],
        "tool": asked["tool"],
        "era": asked["era"],
        "where": where,
        "decision": decided.get("decision"),
        "via": decided.get("via"),
        "waited_ms": decided.get("waited_ms"),
        "outcome": outcome.get("outcome"),
        "detail": outcome.get("detail"),
        "writes": asked["writes"],
        "writes_sent": outcome.get("writes_sent"),
        "writes_unknown": outcome.get("writes_unknown"),
        "writers": {kind: record["writer"] for kind, record in shown.items() if record},
        "others": [
            _other(record)
            for (kind, _), record in entry.records.items()
            if kind in ("decided", "outcome") and record is not shown[kind]
        ],
        "disagree": None not in (vault_says, gateway_says) and vault_says != gateway_says,
        "not_in_policy": [
            name for name in NAMED if name in known and asked[name] not in known[name]
        ],
        "journal": [
            {
                "key": send.key,
                "state": send.state,
                "smtp_code": send.smtp_code,
                "at": when(send.at_ms),
            }
            for send in by_ref.get(entry.ref, [])
        ],
    }


def _other(record: Mapping[str, Any]) -> dict[str, Any]:
    """A record of the call that its row doesn't show, by its writer (J.2): a decision is
    always the gateway's, since the vault's is the one shown."""
    if record["kind"] == "decided":
        return {"kind": "decided", "writer": record["writer"], "decision": record["decision"]}
    return {
        "kind": "outcome",
        "writer": record["writer"],
        "outcome": record["outcome"],
        "detail": record.get("detail"),
    }
