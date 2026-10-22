"""Credential health (M5 design I): what needs the operator, per credential and connector.

Pure, and from metadata only: the policy, the store's clear entries (never a value: nothing here
can decrypt), the names of the ``env:`` variables the vault found set, the token manager's
status (:meth:`~.oauth.login.LoginService.status`) and each connector's send journal, summed up
by :func:`sends`. The admin socket's ``GET /health`` gathers them; ``zoeymcp health`` and the
portal show what :func:`assess` finds.

A finding is ``{code, level, advisory, text, action}``, with ``level`` ``error``, ``warning`` or
``info``. ``advisory`` marks a finding drawn from an entry's clear ``meta``, which anyone with the
state file can edit: it is shown, and no decision reads it. ``action`` is what to do, as a
``kind`` and the name it applies to, so the portal can offer a button and the CLI words its own
command. The kinds are :func:`~.oauth.login.hint_action`'s (``connect``, ``reset``,
``set_secret`` and ``restart`` with the ``ref``, ``fix_policy``, ``wait``), plus
``delete_secret``, ``check_volume`` and ``check_mailbox``, and for the passkeys ``add_passkey``,
``review_passkeys`` and ``reset_passkeys``, and for the reported ledger ``check_gateway`` and
``read_ledger``; from M7, ``onboard_again`` with the ``command`` (``login --mcp URL
--reregister``, OPS-3) and ``widen_scope`` with the union ``scope`` and the ``fragment`` that
sets it (D.5's step-up, SPEC-11), which ``connect`` follows.

Stored bindings are judged by effect, not by equality (verifier V9), because the socket may store
an explicit ``origins`` binding for any name: ``binding_changed`` means a use the policy makes now
would be refused, ``binding_wider`` that every use is covered, and more.

``insufficient_scope`` and ``resource_metadata_changed`` are the token manager's memory of an
upstream's answers, so they cover the time since the vault started (D-16, M7 design J).
:func:`last_failure` (D-23) and :func:`idle` (D-20) read ``meta``; ``oauth status`` shows them
too.

A ``store:`` client secret of a credential that logs in is held to M7 design D.7 step 5 as
login holds it, by :func:`~.bindings.client_secret_rebound`: bound exactly as the policy derives
its binding now, or ``client_secret_binding_changed`` (D-185).

A ``store:`` client secret whose entry's meta has a registration's ``client_secret_expires_at``
(M7 design J, D.7 step 7) is ``client_secret_expiring`` within :data:`GRANT_WARN_DAYS` of it and
``client_secret_expired`` after it, judged on the wall clock (``Inputs.wall``; FM-28), each
advisory: the one decision-free read of clear meta that D.7 step 4 allows.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal

from ..common.policy.check import secret_references
from ..common.policy.schema import Credential, OAuth2Credential, Policy, SMTPConnector
from .bindings import (
    VAULT_PREFIX,
    BindingError,
    client_secret_rebound,
    derive_binding,
    live_slot,
    oauth_binding,
)
from .connectors.sendjournal import DAY_MS, Journal
from .oauth.protocol import GRANT_WARN_DAYS
from .onboarding import onboard_again, widen_scope
from .secretplan import binding_refusal
from .store import EntryMeta, canonical_origin

Level = Literal["error", "warning", "info"]
LEVELS: Final[tuple[Level, ...]] = ("error", "warning", "info")
DAY: Final = 86400
# A connector is near its limit at this share of max_per_day (percent).
NEAR_LIMIT: Final = 80
# A failure code as the vault writes one. Any other value in meta is shown as no code.
_CODE: Final = re.compile(r"[a-z_]{1,64}")
# The token manager's states with a failure in memory.
_FAILING: Final = frozenset({"backoff", "terminal"})
# The status fields drawn from an entry's clear meta.
DISPLAY_ONLY: Final = ("source", "consented_at", "rotations", "last_ok_ago")
# A passkey counter that went back within this many days is a warning.
REGRESSION_DAYS: Final = 30
# The gateway asks for the copy's head at least every 60 s while it takes reports (J.3).
STALE_SECONDS: Final = 300
# The entries an onboarding stores before its fragment is committed: a confidential client's
# secret (M7 design D.7) and a public client's ID (D.8), each named after the credential.
ONBOARDING_SUFFIXES: Final = ("-client-secret", "-client-id")

Action = dict[str, str]
Finding = dict[str, Any]


@dataclass(frozen=True)
class Sends:
    """A connector's send journal, summed up: counts, codes and times, never a message."""

    sent_24h: int
    unknown_24h: int
    # The latest attempt: {state, at, smtp_code}, or None before the first.
    last: dict[str, Any] | None


@dataclass(frozen=True)
class PasskeyState:
    """The portal's passkey file, summed up (D.4): never a key, an ID or a name."""

    count: int
    # The file failed to read, parse or verify: portal login is off.
    unavailable: bool = False
    # Seconds since the latest day a counter went back, or None.
    regressed_ago: float | None = None


@dataclass(frozen=True)
class Inputs:
    policy: Policy
    entries: Sequence[EntryMeta]
    # The env: variables the vault found set when it loaded the policy.
    env_names: Collection[str]
    # LoginService.status(), or None without a token manager.
    oauth: Sequence[Mapping[str, Any]] | None = None
    # Per connector; one whose journal couldn't be read is missing.
    sends: Mapping[str, Sends] = field(default_factory=dict)
    # False when the store holds changes its file doesn't (a failed write).
    persisted: bool = True
    # The passkeys, or None without a portal: the report then has no passkeys section.
    passkeys: PasskeyState | None = None
    # The reported copy, or None without a gateway: the report then has no ledger_copy section.
    ledger_copy: LedgerCopy | None = None
    # The wall clock now (seconds since the epoch), or None: no client secret's expiry is judged.
    wall: float | None = None


@dataclass(frozen=True)
class LedgerCopy:
    """The vault's copy of the gateway's ledger, summed up (M5 design J.4): never a line."""

    # ok, fork, gap, full, or unavailable (the directory can't be read).
    state: str
    head_seq: int | None
    # Seconds since the gateway last asked for the head or reported, None if it hasn't since
    # the vault started; and seconds since the vault started.
    reported_ago: int | None
    uptime: int
    # Where the copy's files stop chaining, as recovery found it.
    broken_at: int | None = None


@dataclass(frozen=True)
class _Use:
    """A secret reference in the policy, and what the vault checks when it uses the secret."""

    owner: Literal["credential", "connector"]
    name: str
    ref: str
    # The origins the stored binding must allow, or None when the vault checks none (an OAuth
    # client ID or secret of a refresh grant: only its token endpoint is checked).
    needs: frozenset[str] | None
    # What gives it a value, or binds it again.
    fix: Action


def assess(inputs: Inputs) -> dict[str, Any]:
    """The health of every credential, connector and store entry, and a count per level."""
    policy = inputs.policy
    stored = {entry.name: entry for entry in inputs.entries}
    status = {item["credential"]: item for item in inputs.oauth or ()}
    refs: dict[str, list[tuple[str, str]]] = {}
    for path, ref, _ in secret_references(policy):
        owner, _, field_name = path.rpartition(".")
        refs.setdefault(owner, []).append((field_name, ref))
    credentials = [
        _credential(inputs, stored, name, cred, refs.get(f"credentials.{name}", []), status)
        for name, cred in policy.credentials.items()
    ]
    connectors = [
        _connector(inputs, stored, name, connector, refs.get(f"connectors.{name}", []))
        for name, connector in policy.connectors.items()
    ]
    store = _store(inputs)
    sections = [*credentials, *connectors, store]
    report: dict[str, Any] = {
        "credentials": credentials,
        "connectors": connectors,
        "store": store,
    }
    if inputs.passkeys is not None:
        report["passkeys"] = _passkeys(inputs.passkeys)
        sections.append(report["passkeys"])
    if inputs.ledger_copy is not None:
        report["ledger_copy"] = _ledger_copy(inputs.ledger_copy)
        sections.append(report["ledger_copy"])
    summary = {
        level: sum(f["level"] == level for s in sections for f in s["findings"]) for level in LEVELS
    }
    return {"summary": summary, **report}


# --- credentials -------------------------------------------------------------------------------


def _credential(
    inputs: Inputs,
    stored: Mapping[str, EntryMeta],
    name: str,
    cred: Credential,
    refs: list[tuple[str, str]],
    status: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    policy = inputs.policy
    origins = _route_origins(policy, name)
    rows: list[dict[str, Any]] = []
    findings: list[Finding] = []
    oauth = cred if isinstance(cred, OAuth2Credential) else None
    for field_name, ref in refs:
        if oauth is not None and field_name == "refresh_token" and ref.startswith("env:"):
            found_rows, found = _seed(inputs, stored, name, oauth, ref)
            rows += found_rows
            findings += found
            continue
        fix = _set("credential", name, ref)
        needs: frozenset[str] | None = origins
        if oauth is not None and field_name == "refresh_token":
            fix = _renew(name, oauth)
        elif oauth is not None:
            # A client ID or secret is checked against the token endpoint only; a
            # client_credentials secret bounds the access tokens too.
            bounds = oauth.grant == "client_credentials" and field_name == "client_secret"
            needs = origins if bounds else None
        row, found = _ref(inputs, stored, _Use("credential", name, ref, needs, fix))
        if oauth is not None and field_name == "client_secret" and _logs_in(oauth):
            row, found = _client_secret(policy, stored, name, oauth, (row, found), fix)
        if oauth is not None and field_name == "client_secret" and ref.startswith("store:"):
            found += _expiry(inputs.wall, stored.get(ref.removeprefix("store:")), name, oauth)
        rows.append(row)
        findings += found
    extra: dict[str, Any] = {}
    current = status.get(name)
    if oauth is not None and current is not None:
        extra["oauth"] = _oauth(current)
        findings += _oauth_findings(policy, name, oauth, current)
    return {
        "name": name,
        "kind": cred.kind,
        "level": _level(findings),
        "routes": [r.name for r in policy.routes if r.credential == name],
        "refs": rows,
        **extra,
        "findings": findings,
    }


def _client_secret(
    policy: Policy,
    stored: Mapping[str, EntryMeta],
    name: str,
    cred: OAuth2Credential,
    judged: tuple[dict[str, Any], list[Finding]],
    fix: Action,
) -> tuple[dict[str, Any], list[Finding]]:
    """A ``store:`` client secret held to D.7 step 5 as login holds it (D-185): bound otherwise
    than the policy now derives, login refuses it ``client_secret_binding_changed``, whatever
    :func:`judge` says of its token endpoint alone. ``judged`` is :func:`_ref`'s row and
    findings, kept when the secret passes or the policy can't bind it (which they report)."""
    try:
        rebound = client_secret_rebound(policy, cred, stored.get)
    except BindingError:
        return judged
    if rebound is None:
        return judged
    row, _ = judged
    text = (
        f"store:{rebound.name} was stored for another token endpoint or other server origins "
        "than the policy has now; login refuses it"
    )
    # Onboarding again only when its store would clear this; ``secret set`` stores the binding
    # the policy derives, whatever the cause.
    action = _again(name, cred, fix) if _reregistered(cred) == rebound.new else fix
    return {**row, "binding": "changed"}, [
        _finding("client_secret_binding_changed", "error", text, action)
    ]


def _expiry(
    wall: float | None, entry: EntryMeta | None, name: str, cred: OAuth2Credential
) -> list[Finding]:
    """A registered client's secret near or past its ``client_secret_expires_at`` (M7 design
    J, D.7 step 7): a warning within :data:`GRANT_WARN_DAYS` of it, an error once it is past;
    nothing for 0 (never), for no such meta, or with no wall clock. Read from clear meta, so
    advisory. Onboarding again registers a new client; without the server's URL as its
    ``resource``, enter the new secret with ``secret set``."""
    if wall is None or entry is None:
        return []
    expires = (entry.meta or {}).get("client_secret_expires_at")
    if isinstance(expires, bool) or not isinstance(expires, int) or expires <= 0:
        return []
    if expires - wall > GRANT_WARN_DAYS * DAY:
        return []
    action = _again(name, cred, _set("credential", name, f"store:{entry.name}"))
    when = _iso(float(expires))
    if expires <= wall:
        text = f"store:{entry.name} expired at {when}: the provider refuses this client now"
        return [_finding("client_secret_expired", "error", text, action, advisory=True)]
    text = f"store:{entry.name} expires at {when}: register a new client before then"
    return [_finding("client_secret_expiring", "warning", text, action, advisory=True)]


def _seed(
    inputs: Inputs, stored: Mapping[str, EntryMeta], name: str, cred: OAuth2Credential, ref: str
) -> tuple[list[dict[str, Any]], list[Finding]]:
    """A refresh token seeded from ``env:``: the live slot holds it once it has been used."""
    var = ref.removeprefix("env:")
    seed_set = var in inputs.env_names
    slot = f"store:{live_slot(name)}"
    renew = _renew(name, cred)
    if live_slot(name) not in stored:
        rows = [_row(ref, seed_set, None), _row(slot, False, None)]
        if seed_set:
            return rows, []
        text = f"env {var} isn't set, and there is no live refresh token"
        return rows, [_finding("env_unset", "error", text, renew)]
    use = _Use("credential", name, slot, _route_origins(inputs.policy, name), renew)
    row, findings = _ref(inputs, stored, use)
    if seed_set:
        if cred.reseed == "never":
            text = f"env {var} is ignored: the live refresh token is used (reseed: never)"
        else:
            text = f"env {var} is ignored until its value changes (reseed: on-change)"
        findings.append(_finding("seed_ignored", "info", text, None))
    return [_row(ref, seed_set, None), row], findings


def _oauth(status: Mapping[str, Any]) -> dict[str, Any]:
    """The token manager's view of a credential. The meta fields are shown, never trusted."""
    meta = status["meta"] or {}
    source, consented, rotations = (meta.get(k) for k in ("source", "consented_at", "rotations"))
    return {
        "state": status["state"],
        "code": status["code"],
        "source": source if isinstance(source, str) else None,
        "consented_at": consented if isinstance(consented, str) else None,
        "rotations": rotations if type(rotations) is int else None,
        "last_ok_ago": status["last_ok_ago"],
        "display_only": list(DISPLAY_ONLY),
    }


def _oauth_findings(
    policy: Policy, name: str, cred: OAuth2Credential, status: Mapping[str, Any]
) -> list[Finding]:
    """The token manager's states, as ``oauth status`` shows them, and what upstreams said."""
    renew = _renew(name, cred)
    found: list[Finding] = []
    code = status["code"]
    if status["state"] == "terminal":
        text = f"no token calls until you act ({code})"
        found.append(_finding("terminal", "error", text, status["action"]))
    elif status["state"] == "backoff":
        text = f"a failure ({code}); a request after the backoff tries again"
        found.append(_finding("backoff", "warning", text, status["action"]))
    if status["reconsent_due"]:
        text = f"re-consent due by {status['reconsent_due']}"
        found.append(_finding("reconsent_due", "warning", text, renew, advisory=True))
    scopes = status["scopes"] or {}
    if scopes.get("unexpected"):
        text = f"unexpected scopes granted: {' '.join(scopes['unexpected'])}"
        found.append(_finding("unexpected_scopes", "warning", text, renew, advisory=True))
    if scopes.get("missing"):
        text = f"expected scopes not granted: {' '.join(scopes['missing'])}"
        found.append(_finding("missing_scopes", "warning", text, renew, advisory=True))
    upstream = status["upstream"]
    if upstream:
        text = (
            f"an upstream said the token lacks a scope at {upstream['at']} "
            "(since the vault started)"
        )
        action = renew
        asked = upstream.get("scopes") or []
        if asked:
            text += f"; it asked for {' '.join(asked)}"
            widened = widen_scope(policy, name, asked)
            if widened is not None:
                action = {
                    **_act("widen_scope", "credential", name),
                    "scope": widened.scope,
                    "fragment": widened.fragment,
                }
        found.append(_finding("insufficient_scope", "warning", text, action))
    moved = status["resource_metadata"]
    if moved and cred.resource_metadata is not None and moved["url"] != cred.resource_metadata:
        text = (
            "a 401 on its route named other protected-resource metadata than its "
            f"resource_metadata at {moved['at']} (since the vault started): the server may have "
            "moved its authorization; the vault never registers again by itself"
        )
        action = _again(name, cred, _act("fix_policy", "credential", name))
        found.append(_finding("resource_metadata_changed", "warning", text, action))
    failure = status["last_failure"]
    if failure:
        reset = {"kind": "reset", "credential": name}
        found.append(
            _finding("last_failure", "warning", failure_text(failure), reset, advisory=True)
        )
    unused = status["idle"]
    if unused:
        found.append(_finding("idle", "warning", idle_text(unused), renew, advisory=True))
    return found


# --- connectors and the store ------------------------------------------------------------------


def _connector(
    inputs: Inputs,
    stored: Mapping[str, EntryMeta],
    name: str,
    connector: SMTPConnector,
    refs: list[tuple[str, str]],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for _, ref in refs:
        use = _Use("connector", name, ref, frozenset(), _set("connector", name, ref))
        row, found = _ref(inputs, stored, use)
        rows.append(row)
        findings += found
    if connector.paused:
        text = "paused in the policy: every send is refused"
        findings.append(_finding("paused", "info", text, _act("fix_policy", "connector", name)))
    summed = inputs.sends.get(name)
    if summed is not None:
        if summed.sent_24h * 100 >= connector.max_per_day * NEAR_LIMIT:
            text = f"{summed.sent_24h} of {connector.max_per_day} sends in the last 24 hours"
            findings.append(
                _finding("near_limit", "warning", text, _act("wait", "connector", name))
            )
        if summed.unknown_24h:
            text = f"{summed.unknown_24h} send(s) in the last 24 hours with an unknown outcome"
            action = _act("check_mailbox", "connector", name)
            findings.append(_finding("unknown_sends", "warning", text, action))
    return {
        "name": name,
        "level": _level(findings),
        "paused": connector.paused,
        "sent_24h": None if summed is None else summed.sent_24h,
        "max_per_day": connector.max_per_day,
        "last": None if summed is None else summed.last,
        "refs": rows,
        "findings": findings,
    }


def _store(inputs: Inputs) -> dict[str, Any]:
    """Entries nothing uses, and a store that can't be written."""
    policy = inputs.policy
    used = {ref.removeprefix("store:") for _, ref, _ in secret_references(policy)}
    used |= {live_slot(name) for name, cred in policy.credentials.items() if _seeded(cred)}
    findings: list[Finding] = []
    for entry in inputs.entries:
        if entry.name in used:
            continue
        action = {"kind": "delete_secret", "secret": entry.name}
        waiting = _onboarded(entry)
        if entry.name.startswith(VAULT_PREFIX):
            text = f"{entry.name}: no credential keeps its live refresh token here"
            findings.append(_finding("orphan_slot", "info", text, action))
        elif waiting is not None:
            text = (
                f"store:{entry.name} is waiting for its credential: commit onboarding fragment 1 "
                f"for {waiting}, or delete it"
            )
            findings.append(_finding("unreferenced", "info", text, action, advisory=True))
        else:
            text = f"nothing in the policy uses store:{entry.name}"
            findings.append(_finding("unreferenced", "info", text, action))
    if not inputs.persisted:
        text = "degraded (not persisted): the store can't be written"
        findings.append(_finding("degraded", "error", text, {"kind": "check_volume"}))
    return {"entries": len(inputs.entries), "level": _level(findings), "findings": findings}


def _passkeys(state: PasskeyState) -> dict[str, Any]:
    """A file that can't be verified, a single passkey, a counter that went back (I.1)."""
    findings: list[Finding] = []
    if state.unavailable:
        text = (
            "the passkey file can't be verified (edited, or written under another master key); "
            "portal login is off"
        )
        findings.append(_finding("passkeys_unavailable", "error", text, {"kind": "reset_passkeys"}))
        return {"count": None, "level": _level(findings), "findings": findings}
    if state.regressed_ago is not None and state.regressed_ago < REGRESSION_DAYS * DAY:
        text = (
            f"a passkey's signature counter went back in the last {REGRESSION_DAYS} days: "
            "the authenticator may have been copied"
        )
        findings.append(_finding("passkey_counter", "warning", text, {"kind": "review_passkeys"}))
    if state.count == 1:
        text = "only one passkey is enrolled: add a second, so losing one doesn't lock you out"
        findings.append(_finding("passkey_single", "info", text, {"kind": "add_passkey"}))
    return {"count": state.count, "level": _level(findings), "findings": findings}


_REFUSED_TEXT: Final = {
    "fork": "the gateway's ledger no longer extends the copy (a fork)",
    "gap": "the gateway's report skipped records the copy doesn't hold (a gap)",
    "full": "the copy is full and holds nothing received long enough ago to prune",
}


def _ledger_copy(copy: LedgerCopy) -> dict[str, Any]:
    """The reported copy (J.2, J.4): one that can't be read, a sticky refusal, a break in its
    files, a gateway that stopped reporting, or none yet."""
    findings: list[Finding] = []
    read = {"kind": "read_ledger"}
    gateway = {"kind": "check_gateway"}
    quiet = copy.uptime if copy.reported_ago is None else copy.reported_ago
    if copy.state == "unavailable":
        text = "the vault can't read its copy of the gateway's ledger; reports are refused"
        findings.append(
            _finding("ledger_copy_unavailable", "error", text, {"kind": "check_volume"})
        )
    elif copy.state in _REFUSED_TEXT:
        text = f"{_REFUSED_TEXT[copy.state]}: reports are refused until the chain is restarted"
        findings.append(_finding("ledger_copy_refused", "error", text, read))
    elif quiet > STALE_SECONDS:
        text = f"no report from the gateway for {quiet // 60} min"
        findings.append(_finding("ledger_copy_stale", "warning", text, gateway))
    elif copy.head_seq is None:
        findings.append(
            _finding("ledger_copy_none", "info", "no report from the gateway yet", gateway)
        )
    if copy.broken_at is not None and copy.state != "unavailable":
        text = f"the copy's files stop chaining at seq {copy.broken_at} (damaged or edited)"
        findings.append(_finding("ledger_copy_broken", "error", text, read))
    return {
        "state": copy.state,
        "head_seq": copy.head_seq,
        "reported_ago": copy.reported_ago,
        "broken_at": copy.broken_at,
        "level": _level(findings),
        "findings": findings,
    }


def sends(journal: Journal, now_ms: int) -> Sends:
    """A connector's journal summed up for :class:`Inputs`."""
    attempts = list(journal.attempts.values())
    unknown = sum(
        1
        for a in attempts
        if a.terminal is not None
        and a.terminal["kind"] == "unknown"
        and a.terminal["ts"] > now_ms - DAY_MS
    )
    latest = max(attempts, key=lambda a: a.ts, default=None)
    last = None
    if latest is not None:
        end = latest.terminal
        last = {
            "state": "sending" if end is None else end["kind"],
            "at": _iso((latest.ts if end is None else end["ts"]) / 1000),
            "smtp_code": None if end is None else end.get("smtp_code"),
        }
    return Sends(journal.sent_24h(now_ms), unknown, last)


# --- references and bindings -------------------------------------------------------------------


def _ref(
    inputs: Inputs, stored: Mapping[str, EntryMeta], use: _Use
) -> tuple[dict[str, Any], list[Finding]]:
    """A reference's row and findings: set or not and, for the store, its binding's verdict."""
    if use.ref.startswith("env:"):
        var = use.ref.removeprefix("env:")
        if var in inputs.env_names:
            return _row(use.ref, True, None), []
        return _row(use.ref, False, None), [
            _finding("env_unset", "error", f"env {var} isn't set", use.fix)
        ]
    entry = stored.get(use.ref.removeprefix("store:"))
    if entry is None:
        return _row(use.ref, False, None), [
            _finding("missing", "error", f"{use.ref} has no entry", use.fix)
        ]
    try:
        verdict = judge(inputs.policy, entry, use.needs)
    except BindingError as exc:
        # The policy can't bind the name: the secret write would refuse it the same way (G).
        reason = binding_refusal(exc).reason
        action = _act("fix_policy", use.owner, use.name)
        return _row(use.ref, True, reason), [_finding(reason, "error", str(exc), action)]
    row = _row(use.ref, True, verdict)
    if verdict == "changed":
        text = f"{use.ref} isn't bound to a use the policy makes now; the vault refuses that use"
        return row, [_finding("binding_changed", "error", text, use.fix)]
    if verdict == "wider":
        text = f"{use.ref} is bound to more than the policy uses; it works"
        return row, [_finding("binding_wider", "info", text, use.fix)]
    return row, []


def judge(policy: Policy, entry: EntryMeta, needs: frozenset[str] | None) -> str:
    """A stored binding against what the policy does with the secret now: ``ok``, ``changed``
    (the vault refuses a use) or ``wider`` (it allows every use, and more).

    ``needs`` is the origins this use sends the secret, or its tokens, to (None: the vault
    checks only an OAuth secret's token endpoint). Raises :class:`BindingError` when the policy
    can't bind the name (``no_route``, ``conflict``).
    """
    try:
        expected = derive_binding(policy, entry.name)
    except BindingError as exc:
        if exc.reason != "unbound":
            raise
        # No route sends it anywhere: every binding covers that.
        expected = {"origins": []}
    held = entry.binding
    if "smtp" in expected:
        # A connector's secret is used only with exactly its binding.
        return "ok" if held == expected else "changed"
    if "oauth" in expected:
        oauth = held.get("oauth")
        if not isinstance(oauth, dict) or oauth.get("token") != expected["oauth"]["token"]:
            return "changed"
        if needs is None:
            return "ok"
        return _cover(oauth.get("resources"), needs, expected["oauth"]["resources"])
    return _cover(held.get("origins"), needs or frozenset(), expected["origins"])


def _cover(held: object, needs: frozenset[str], every: Sequence[str]) -> str:
    """``held`` (a stored list of origins) against the origins this use ``needs`` and those
    ``every`` use of the name needs."""
    allowed = frozenset(o for o in held if isinstance(o, str)) if isinstance(held, list) else None
    if not needs <= (allowed or frozenset()):
        return "changed"
    return "wider" if allowed is not None and allowed > frozenset(every) else "ok"


def _route_origins(policy: Policy, credential: str) -> frozenset[str]:
    return frozenset(
        canonical_origin(r.upstream)
        for r in policy.routes
        if r.credential == credential and r.upstream is not None
    )


def _onboarded(entry: EntryMeta) -> str | None:
    """The credential an onboarding stored ``entry`` for, before its fragment 1 was committed
    (M7 design D.7 step 6): a name :data:`ONBOARDING_SUFFIXES` ends, and the ``onboarded`` meta
    the register run writes. Meta is clear text, so this only words the finding."""
    meta = entry.meta or {}
    if not isinstance(meta.get("onboarded"), str):
        return None
    for suffix in ONBOARDING_SUFFIXES:
        credential = entry.name.removesuffix(suffix)
        if credential and credential != entry.name:
            return credential
    return None


def _logs_in(cred: OAuth2Credential) -> bool:
    """Whether ``zoeymcp login`` runs for the credential, and so D.7 step 5's check."""
    return cred.grant != "client_credentials" and cred.authorize_url is not None


def _seeded(cred: Credential) -> bool:
    return isinstance(cred, OAuth2Credential) and (cred.refresh_token or "").startswith("env:")


def _row(ref: str, present: bool, binding: str | None) -> dict[str, Any]:
    return {"ref": ref, "present": present, "binding": binding}


# --- actions and findings ----------------------------------------------------------------------


def _finding(
    code: str, level: Level, text: str, action: Action | None, *, advisory: bool = False
) -> Finding:
    return {"code": code, "level": level, "advisory": advisory, "text": text, "action": action}


def _level(findings: Sequence[Finding]) -> str:
    """The worst level among the findings, or ``ok``."""
    for level in LEVELS:
        if any(f["level"] == level for f in findings):
            return level
    return "ok"


def _act(kind: str, owner: str, name: str) -> Action:
    return {"kind": kind, owner: name}


def _set(owner: str, name: str, ref: str) -> Action:
    """A reference given a value: an env var by a restart, a store entry by setting it."""
    return {**_act("restart" if ref.startswith("env:") else "set_secret", owner, name), "ref": ref}


def _again(name: str, cred: OAuth2Credential, fallback: Action) -> Action:
    """Onboarding again (D.12, OPS-3), for a credential that names its server's URL as its
    ``resource``, as onboarding writes it; ``fallback`` for one written without."""
    resource = cred.extra_params.get("resource")
    if not isinstance(resource, str):
        return fallback
    return {**_act("onboard_again", "credential", name), "command": onboard_again(resource).shell()}


def _reregistered(cred: OAuth2Credential) -> dict[str, Any] | None:
    """The binding a re-registration stores the client secret under (D.7 step 2, as
    ``onboard._binding`` makes it): the token endpoint, and the origin of the server the
    credential names as its ``resource``. A route added, or a second credential naming the
    secret, derives another. None without a resource."""
    resource = cred.extra_params.get("resource")
    if not isinstance(resource, str):
        return None
    try:
        return oauth_binding(cred.token_url, [resource])
    except ValueError:
        return None


def _renew(name: str, cred: OAuth2Credential) -> Action:
    """What gets a credential a new grant, as :func:`~.oauth.login.hint_action` says for a
    refused refresh token."""
    if cred.grant == "client_credentials":
        return _act("reset", "credential", name)
    if cred.authorize_url is not None:
        return _act("connect", "credential", name)
    return _set("credential", name, cred.refresh_token or "")


# --- from the clear meta (oauth status shows these too) ----------------------------------------


def last_failure(state: str, meta: Mapping[str, Any]) -> dict[str, str | None] | None:
    """The last attempt failed and nothing has worked since, when no failure is in memory: a
    restart forgets failures, and ``meta.last_error`` remembers (D-23). Display only."""
    if state in _FAILING:
        return None
    error = meta.get("last_error")
    if not isinstance(error, dict):
        return None
    failed = parse_time(error.get("at"))
    if failed is None:
        return None
    worked = parse_time(meta.get("last_ok"))
    if worked is not None and worked >= failed:
        return None
    code = error.get("code")
    shown = code if isinstance(code, str) and _CODE.fullmatch(code) else None
    return {"code": shown, "at": _iso(failed)}


def idle(cred: OAuth2Credential, meta: Mapping[str, Any], wall: float) -> dict[str, int] | None:
    """Unused long enough that the provider may soon drop the grant (D-20): ``last_ok`` older
    than ``idle_expiry_days`` less :data:`GRANT_WARN_DAYS`. Display only."""
    limit = cred.idle_expiry_days
    worked = parse_time(meta.get("last_ok"))
    if limit is None or worked is None:
        return None
    unused = wall - worked
    if unused <= max(0, limit - GRANT_WARN_DAYS) * DAY:
        return None
    return {"days": int(unused) // DAY, "limit": limit}


def failure_text(failure: Mapping[str, Any]) -> str:
    return f"last attempt failed: {failure['code'] or 'no code'} at {failure['at']}"


def idle_text(unused: Mapping[str, Any]) -> str:
    return (
        f"unused for {unused['days']} days; "
        f"the provider drops unused grants after {unused['limit']}"
    )


def parse_time(value: object) -> float | None:
    """A timestamp from ``meta``, or None for anything that isn't an aware ISO time."""
    if not isinstance(value, str):
        return None
    try:
        when = datetime.fromisoformat(value)
    except ValueError:
        return None
    if when.tzinfo is None:
        return None
    stamp = when.timestamp()
    # The vault writes none before 1970, and some platforms can't format one.
    return stamp if stamp >= 0 else None


def _iso(wall: float) -> str:
    return (
        datetime.fromtimestamp(wall, UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
