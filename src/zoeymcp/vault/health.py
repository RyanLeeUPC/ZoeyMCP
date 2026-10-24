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
--reregister``, OPS-3), ``widen_scope`` with the union ``scope`` and the ``fragment`` that
sets it (D.5's step-up, SPEC-11), which ``connect`` follows, and ``check_egress_role``; from
M6, ``review`` with the ``server`` (M6 design M.5).

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

``address_refused`` is the token manager's memory of the address guard's refusals since start
(M7 design B.2, J): a credential's token or revocation endpoint, or a route of its, whose name
resolved where the running policy doesn't allow. A route with no credential has no credential
section, so its refusals are the ``egress`` section's, one finding per route. Each is judged
against the running policy, keyed as the guard sees the destination (:func:`.netclient.guard_key`),
so a reload that lists it in ``egress_private``, or moves the endpoint, ends it.

``egress_allowlist_stale`` (M7 design J, COV-7) is the ``egress`` section's too: the egress role
hasn't fetched its lists for more than :data:`.internal.ALLOWLIST_MAX_STALE` seconds, so it
refuses every new tunnel (I.4). A role that has asked since the vault started but was never
admitted (a wrong or old key) counts from its first request. A vault no role has asked since it
started counts from its start when its startup policy's ``egress_proxy`` is the role
(``egress_proxy_kind: role``), which is expected then, and has no such finding otherwise.

The ``egress`` section also judges each route against the bridges the vault was started with
(:class:`Bridges`; M7 design C.10, J, Q46). In the standard tier (the vault runs with the gateway
link socket), a route with a ``program`` block, a ``unix:`` upstream, or a local MCP route to a
loopback address (a literal, ``localhost`` or a name under it) is ``program_unconfined`` (info:
nothing there confines the program); that local MCP route over TCP is also
``loopback_bridge_route`` (error: any process in the container could listen there first and
receive the route's token); and a route to the socket of a bridge whose ARGS hold
``--secret-env`` without ``program.holds_secret`` is ``program_secret_unflagged`` (warning). In
either tier, a ``unix:`` upstream naming a bridge the launcher didn't start is
``bridge_socket_unknown`` (error: the route answers 502).

The ``gateway`` section (M6 design M.5, K.1) reads the gateway's latest status report
(:class:`~.statusreport.GatewayStatus`), labelled as the gateway's: nothing in it drives a
decision (Y21). Per server the running policy names, the gateway's attention decision (J.5,
read back with :meth:`~.statusreport.ServerStatus.attention`, never decided here) gives
``tools_unreviewed`` for the tools nobody reviewed and ``drift_marked`` for the included tools
that drifted, are hidden by a drift mark or are no longer listed, each a warning whose action is
``review`` with the ``server``, so ``zoeymcp review``'s exit code, these findings and Home's list
agree (Y29); a tool nobody reviewed is counted, not named, since its upstream chose the name.
``server_blocked`` is a server the gateway says ``on_drift: fail`` blocked;
``server_listing_invalid`` a server the gateway lists tools for that it can't name, or that it
reports invalid and no drift finding names already (counted), or whose status the vault refused
(T-7).
A gateway that hasn't reported for :data:`STATUS_STALE` seconds is ``gateway_status_stale``
(info): its findings are then as old.

The ``policy`` section (M6 design M.5, F.4-F.6, G.6) reads the policy store's state
(:class:`PolicyState`), only while there is a store: a declarative deployment that never ran
managed has none, and its report is as before. In managed mode: ``policy_not_running`` (error), a
revision saved but not running since its install failed, until a ``SIGHUP`` or a restart installs
it; ``policy_seed_ignored`` (warning), a configured source that differs from the seed and the head
(F.5; the OAuth seed's ``seed_ignored`` keeps its name); ``policy_restart_needed`` (warning), each
change installed since the start that needs a restart (I.2); ``revisions_unreadable`` (warning),
kept revisions that failed to verify. In declarative mode: ``policy_store_parked`` (info),
``policy_declarative_revives`` (warning) for what the running policy brings back that the parked
ratchet retired (T-16), and ``policy_store_unverified`` (warning), a store the start couldn't read.
In both, ``policy_quarantine_kept`` (info) counts the quarantine's files. Every text holds revision
numbers, grant subjects (policy names) and fixed words only (Y13).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from ..common import egresslist
from ..common.policy import fields as policy_fields
from ..common.policy.check import local_mcp_routes, secret_references
from ..common.policy.schema import (
    Credential,
    OAuth2Credential,
    Policy,
    RemoteServer,
    Route,
    SMTPConnector,
)
from .bindings import (
    VAULT_PREFIX,
    BindingError,
    client_secret_rebound,
    derive_binding,
    live_slot,
    oauth_binding,
)
from .connectors.sendjournal import DAY_MS, Journal
from .internal import ALLOWLIST_MAX_STALE
from .netclient import destination_key, guard_key, private_hint
from .oauth.protocol import GRANT_WARN_DAYS
from .onboarding import onboard_again, widen_scope
from .secretplan import binding_refusal
from .statusreport import GatewayStatus
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
# The gateway's status report is stale after this many seconds (M6 design K.1, N.4); it comes
# at least every 60 s.
STATUS_STALE: Final = 180
# A finding names at most this many tools, then says how many more.
NAMED_MAX: Final = 10
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
class Bridges:
    """What the vault was started with for the standard tier's bridges (M7 design C.10, J):
    fixed at start, so a reload changes none of it."""

    # The vault runs with the gateway link socket: the standard tier.
    link: bool = False
    # The bridges the launcher started (--bridge NAME=UID), by name.
    named: frozenset[str] = frozenset()
    # Those whose ZOEYMCP_BRIDGE_<NAME>_ARGS, in the vault's environment, hold --secret-env.
    secret_env: frozenset[str] = frozenset()


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
    # The address guard's refusals since start: LoginService.refused().
    refused: Sequence[Mapping[str, Any]] = ()
    # Seconds since the egress role last fetched its lists, or since its first refused request,
    # or since the vault started when egress_proxy is the role and none has asked; None if no
    # role has asked and none is expected (VaultApp.allowlist_fetched_ago).
    egress_fetched_ago: float | None = None
    # The tier and the bridges, for the routes' findings in the egress section.
    bridges: Bridges = Bridges()
    # The gateway's latest status report and its age (M6 design K.1), or None without one to
    # report: the report then has no gateway section (VaultApp.gateway_status).
    gateway_status: GatewayStatus | None = None
    # The policy store's state (M6 design M.5), or None without a store: the report then has no
    # policy section (vault/managed.py).
    policy_state: PolicyState | None = None


@dataclass(frozen=True)
class PolicyState:
    """The policy store, summed up for health (M6 design M.5): revision numbers, a reason code
    and grant subjects (policy names), never a policy value."""

    mode: Literal["declarative", "managed"]
    # The head running (managed) or parked (declarative), and the oldest revision kept.
    revision: int | None = None
    oldest: int = 1
    # A revision saved but not running: its install failed (G.6 step 8).
    not_running: int | None = None
    # Why the configured source is ignored (F.5): changed, unreadable or fails_check.
    seed_ignored: str | None = None
    # Each change installed since the start that needs a restart: its path and I.2's text.
    restart_needed: tuple[tuple[str, str], ...] = ()
    # Kept revisions below the head that failed to verify (D.6 row 14).
    unreadable: tuple[int, ...] = ()
    # What the declarative policy brings back that the parked ratchet retired, by grant subject.
    revived: tuple[str, ...] = ()
    # The store's refusal a declarative start didn't meet (policy_store_unverified).
    unverified: str | None = None
    # Files in /state/policy/quarantine.
    quarantine: int = 0


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
    """The health of every credential, connector and store entry, of the routes with no
    credential the guard refused and the egress role (``egress``), of the policy store
    (``policy``) and of what the gateway reports (``gateway``, M6 design M.5), and a count per
    level."""
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
    egress = _egress(policy, inputs.refused, inputs.egress_fetched_ago, inputs.bridges)
    sections = [*credentials, *connectors, store, egress]
    report: dict[str, Any] = {
        "credentials": credentials,
        "connectors": connectors,
        "store": store,
        "egress": egress,
    }
    if inputs.passkeys is not None:
        report["passkeys"] = _passkeys(inputs.passkeys)
        sections.append(report["passkeys"])
    if inputs.ledger_copy is not None:
        report["ledger_copy"] = _ledger_copy(inputs.ledger_copy)
        sections.append(report["ledger_copy"])
    if inputs.policy_state is not None:
        report["policy"] = _policy(inputs.policy_state)
        sections.append(report["policy"])
    if inputs.gateway_status is not None and policy.gateway is not None:
        report["gateway"] = _gateway(policy, inputs.gateway_status)
        sections.append(report["gateway"])
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
    findings += _address_refused(policy, name, cred, inputs.refused)
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


# What each purpose's refusals were calls to (M7 design J).
_REFUSED_CALLS: Final = {
    "route": "a route's upstream",
    "token": "the token endpoint",
    "revocation": "the revocation endpoint",
}


def _address_refused(
    policy: Policy, name: str, cred: Credential, refused: Sequence[Mapping[str, Any]]
) -> list[Finding]:
    """The guard's refusals of the credential's destinations since start (M7 design B.2, J):
    its token or revocation endpoint, or the upstream of a route that uses it, each as the
    running policy has it now and not listed in its ``egress_private``."""
    destinations = {
        "route": {
            destination_key(r.upstream)
            for r in policy.routes
            if r.credential == name and r.upstream is not None
        },
        "token": set(),
        "revocation": set(),
    }
    if isinstance(cred, OAuth2Credential):
        destinations["token"].add(destination_key(cred.token_url))
        if cred.revocation_url is not None:
            destinations["revocation"].add(destination_key(cred.revocation_url))
    listed = egresslist.private_exceptions(policy)
    found: list[Finding] = []
    for item in refused:
        purpose = item["purpose"]
        key = guard_key(item["host"], item["port"])
        if key not in destinations.get(purpose, ()) or key in listed:
            continue
        text = _refused_text(_REFUSED_CALLS[purpose], key, item)
        action = _act("fix_policy", "credential", name)
        found.append(_finding("address_refused", "error", text, action))
    return found


def _egress(
    policy: Policy,
    refused: Sequence[Mapping[str, Any]],
    fetched_ago: float | None,
    bridges: Bridges,
) -> dict[str, Any]:
    """The guard's refusals of a route with no credential, which no credential's section holds
    (M7 design J): one finding per such route whose upstream, as the running policy has it now,
    was refused and isn't listed in its ``egress_private``; then each route's program and
    bridge (:func:`_programs`); then an egress role whose last fetch of its lists is older than
    they stay fresh (COV-7)."""
    listed = egresslist.private_exceptions(policy)
    seen = {guard_key(i["host"], i["port"]): i for i in refused if i["purpose"] == "route"}
    findings: list[Finding] = []
    for route in policy.routes:
        if route.credential is not None or route.upstream is None:
            continue
        key = destination_key(route.upstream)
        if key not in seen or key in listed:
            continue
        text = _refused_text(f"route {route.name}'s upstream", key, seen[key])
        action = _act("fix_policy", "route", route.name)
        findings.append(_finding("address_refused", "error", text, action))
    findings += _programs(policy, bridges)
    if fetched_ago is not None and fetched_ago > ALLOWLIST_MAX_STALE:
        text = (
            f"the egress role hasn't fetched its allowlists for {int(fetched_ago) // 60} min: "
            f"its lists go stale after {ALLOWLIST_MAX_STALE} s, and then it refuses every new "
            "tunnel"
        )
        action = {"kind": "check_egress_role"}
        findings.append(_finding("egress_allowlist_stale", "warning", text, action))
    return {"level": _level(findings), "findings": findings}


UNCONFINED: Final = (
    "nothing in the standard tier confines this program: it can reach every listener in the "
    "container, the host's network and the internet"
)


def _programs(policy: Policy, bridges: Bridges) -> list[Finding]:
    """Each route's program and bridge against the tier and the bridges the launcher started
    (M7 design C.10, J, Q46), in the policy's order."""
    local = local_mcp_routes(policy)
    findings: list[Finding] = []
    for route in policy.routes:
        if route.upstream is None:
            continue
        bridge = _bridge_of(route.upstream)
        loopback = route.name in local and bridge is None and _loopback(route.upstream)
        fix = _act("fix_policy", "route", route.name)
        if bridges.link and (route.program is not None or bridge is not None or loopback):
            text = f"route {route.name}: {UNCONFINED}"
            findings.append(_finding("program_unconfined", "info", text, None))
        if bridges.link and loopback:
            text = (
                f"route {route.name}: any process in this container can listen on "
                f"{destination_key(route.upstream)} first and receive this route's token; a "
                "bridge under the launcher listens on unix:/run/zoeymcp-bridge-<name>/mcp.sock"
            )
            findings.append(_finding("loopback_bridge_route", "error", text, fix))
        if bridge is not None and bridge not in bridges.named:
            text = (
                f"route {route.name}: the route answers 502: no bridge {bridge} runs in this "
                "container"
            )
            findings.append(_finding("bridge_socket_unknown", "error", text, fix))
        secret = bridge is not None and bridge in bridges.secret_env
        if bridges.link and secret and not _holds_secret(route):
            text = (
                f"route {route.name}: this route's program holds a real secret, and check "
                "can't warn about it until program.holds_secret is set"
            )
            findings.append(_finding("program_secret_unflagged", "warning", text, fix))
    return findings


def _bridge_of(upstream: str) -> str | None:
    """The bridge a ``unix:`` upstream names (the schema allows only its one form), else None."""
    if not upstream.startswith(policy_fields.UNIX_PREFIX):
        return None
    return policy_fields.bridge_name(upstream)


def _loopback(upstream: str) -> bool:
    """A loopback host (CR-B8): a literal, an IPv4-mapped one included, ``localhost`` or a name
    under it."""
    host = (urlsplit(upstream).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def _holds_secret(route: Route) -> bool:
    return route.program is not None and route.program.holds_secret


def _refused_text(call: str, key: str, item: Mapping[str, Any]) -> str:
    return (
        f"{call} at {key} was refused at {item['at']} (since the vault started): its name "
        f"resolved to an address the guard refuses ({item['verdict']}); {private_hint(key)}"
    )


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


# --- the policy store (M6 design M.5) ----------------------------------------------------------

# F.5's ways on, after the sentence that says why the source is ignored.
SEED_IGNORED_NEXT: Final = (
    "Remove ZOEYMCP_CONFIG; or accept it as it is, without applying it: zoeymcp policy import "
    "--from-env --baseline-only; or apply it: zoeymcp policy import --from-env (the plan shows "
    "what it undoes)"
)
_SEED_IGNORED: Final = {
    "changed": "has changed since the policy was seeded from it",
    "unreadable": "doesn't load",
    "fails_check": "fails check",
}


def _policy(state: PolicyState) -> dict[str, Any]:
    """What the policy store's state needs of the operator (M.5's ``policy`` rows)."""
    findings: list[Finding] = []
    revision = state.revision
    declarative = state.mode == "declarative"
    if state.not_running is not None:
        text = (
            f"revision {state.not_running} is saved but not running: send SIGHUP to the vault "
            "or restart it"
        )
        findings.append(_finding("policy_not_running", "error", text, {"kind": "reload_vault"}))
    if state.seed_ignored is not None:
        said = _SEED_IGNORED[state.seed_ignored]
        text = (
            f"ZOEYMCP_CONFIG {said} and is ignored: the policy is revision {revision}. "
            f"{SEED_IGNORED_NEXT}"
        )
        action = {"kind": "import_from_env"}
        findings.append(_finding("policy_seed_ignored", "warning", text, action))
    for path, said in state.restart_needed:
        findings.append(_finding("policy_restart_needed", "warning", f"{path}: {said}", None))
    if state.unreadable:
        numbers = ", ".join(str(number) for number in state.unreadable)
        text = (
            f"revisions {numbers} failed to verify and are in quarantine: rollback to them is "
            "refused"
        )
        findings.append(_finding("revisions_unreadable", "warning", text, None))
    if declarative and revision is not None:
        text = (
            f"revisions {state.oldest}-{revision} are kept and unused while the mode is "
            "declarative; to return, set mode: managed: the policy you run then becomes "
            f"revision {revision + 1}"
        )
        findings.append(_finding("policy_store_parked", "info", text, None))
    if declarative and state.revived:
        text = (
            f"the declarative policy brings back {_some(state.revived)}, which managed mode had "
            "removed"
        )
        action = {"kind": "fix_policy"}
        findings.append(_finding("policy_declarative_revives", "warning", text, action))
    if declarative and state.unverified is not None:
        text = (
            f"the policy store doesn't verify ({state.unverified}): a return to managed will refuse"
        )
        findings.append(_finding("policy_store_unverified", "warning", text, None))
    if state.quarantine:
        text = (
            f"{state.quarantine} file(s) in /state/policy/quarantine: delete them once you don't "
            "need them"
        )
        findings.append(_finding("policy_quarantine_kept", "info", text, None))
    return {
        "mode": state.mode,
        "revision": revision,
        "level": _level(findings),
        "findings": findings,
    }


# --- the gateway's status (M6 design K.1, M.5) ------------------------------------------------


def _gateway(policy: Policy, status: GatewayStatus) -> dict[str, Any]:
    """What the gateway's latest status says needs the operator, per server the running policy
    names: each row with the attention decision as the gateway made it, and the findings."""
    findings: list[Finding] = []
    servers: list[dict[str, Any]] = []
    if status.age > STATUS_STALE:
        text = f"the gateway hasn't reported its status for {int(status.age) // 60} minutes"
        findings.append(_finding("gateway_status_stale", "info", text, {"kind": "check_gateway"}))
    report = status.report
    gateway = policy.gateway
    if report is not None and gateway is not None:
        upstreams = {route.name: route.upstream for route in policy.routes}
        for name, server in sorted(gateway.servers.items()):
            review = _act("review", "server", name)
            if name in report.refused_servers:
                text = f"{name}: the gateway's status for it isn't one the vault reads"
                findings.append(_finding("server_listing_invalid", "warning", text, review))
                continue
            entry = report.servers.get(name)
            if entry is None:
                continue
            found = entry.attention()
            unreviewed = found.unreviewed()
            if unreviewed:
                # Counted, not named: the upstream chose the names (M.5, Y13); review names them.
                text = f"{name} lists {_tools(len(unreviewed))} nobody reviewed"
                findings.append(_finding("tools_unreviewed", "warning", text, review))
            parts = [
                f"{len(names)} {words} ({_some(names)})"
                for names, words in (
                    (found.drifted, "changed since the review"),
                    (found.marked, "hidden by a drift mark"),
                    (found.missing, "no longer listed"),
                )
                if names
            ]
            if parts:
                text = f"{name}: included tools {'; '.join(parts)}"
                findings.append(_finding("drift_marked", "warning", text, review))
            # The gateway's own word (pins.evaluate): a held mark on a tool no longer listed, or an
            # included tool listed invalid, blocks it too.
            if entry.blocked:
                text = f"{name} is blocked (on_drift: fail): none of its tools are served"
                findings.append(_finding("server_blocked", "warning", text, review))
            # An included tool the gateway lists invalid is drifted already: counted once, there.
            invalid = sorted(set(entry.invalid) - set(found.drifted))
            if entry.unnamed or invalid:
                text = f"{name} lists tools whose names aren't valid; they are counted, not named"
                if invalid:
                    text = f"{name} lists {_tools(len(invalid))} the gateway can't serve" + (
                        "; others' names aren't valid, so they are counted, not named"
                        if entry.unnamed
                        else ""
                    )
                findings.append(_finding("server_listing_invalid", "warning", text, review))
            upstream = upstreams.get(server.route) if isinstance(server, RemoteServer) else None
            servers.append(
                {
                    "name": name,
                    "kind": entry.kind,
                    "bridge": upstream is not None and _bridge_of(upstream) is not None,
                    "state": list(entry.state),
                    "era": entry.era,
                    "attention": found.as_dict(),
                    "blocked": entry.blocked,
                    "invalid": invalid,
                    "unnamed": entry.unnamed,
                }
            )
        if report.unnamed_servers:
            text = (
                f"the gateway's status names {report.unnamed_servers} server(s) by names that "
                "aren't policy names; they are left out"
            )
            action = {"kind": "check_gateway"}
            findings.append(_finding("server_listing_invalid", "warning", text, action))
    return {
        "reported_ago": None if report is None else int(status.age),
        "view": None if report is None else report.view,
        "servers": servers,
        "level": _level(findings),
        "findings": findings,
    }


def _tools(count: int) -> str:
    return f"{count} tool{'' if count == 1 else 's'}"


def _some(names: Sequence[str]) -> str:
    """Up to :data:`NAMED_MAX` names, then how many more."""
    named = ", ".join(names[:NAMED_MAX])
    more = len(names) - NAMED_MAX
    return named if more <= 0 else f"{named} and {more} more"


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
