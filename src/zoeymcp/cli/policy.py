"""``zoeymcp policy``: the host's commands on a managed policy (M6 design H, M.6, F.3). I/O.

Over the vault's admin socket (``docker compose exec vault zoeymcp policy ...``), or, with
``--state DIR``, on the state directory with the vault stopped (I.1's recovery where there is no
socket, COV-5):

- ``policy`` / ``policy head`` (socket): the mode and the head, the revision the gateway runs;
- ``policy history [--before N] [--limit N]`` and ``policy diff N [--against M]``: H.1 and H.2,
  each row of a diff through the policy view's renderer, hidden fields hidden; both and ``head``
  take ``--format text|json`` (D-171);
- ``policy export [--revision N] [--mode managed|declarative] [--for compose]``: H.6, R61's
  fourth scoped exception. The YAML alone goes to stdout and the notes (what was exported, the
  compose form's interpolated fields, and for a declarative compose export the way back, J10)
  to stderr; a terminal stdout is refused without ``--force-tty``, so a placeholder doesn't
  scroll by;
- ``policy import FILE|-`` (or ``--from-env``, the vault's own configured policy, G-14, with
  ``--baseline-only`` to record its digest and apply nothing, F.5) and ``policy rollback N``
  (H.3, the target's ``admin`` with it, H.4): a host write. The plan goes to stderr, widenings
  first; each store entry it leaves unused is named with its ``secret delete`` line unless
  ``--revoke-removed`` (G.8); ``[y/N]`` unless ``--yes``, and a lockout row (I.1, G-17) asks
  its second, typed confirmation. With ``--yes`` a plan that widens needs ``--accept-widening``
  (``import_widens``, Q41) and one with a lockout row ``--lockout-ok``
  (``lockout_unconfirmed``). An import's base is ``--base N``, else the revision and deployment
  of the export's first line (OPS-8): a header from another deployment is refused
  (``export_other_deployment``), no header and no ``--base`` is ``base_required``; a rollback's
  and ``--from-env``'s base is the head as the plan read it. The write then names its base and
  the plan's digest, so a head that moved meanwhile is ``policy_moved`` and a plan that changed
  is ``plan_changed``; a retry whose answer was lost is ``already_saved``.

The offline forms that make a policy store or replace one, run with the vault stopped (F.3):

- ``policy seed --state DIR [--config FILE|-] [--yes]`` seeds revision 1 on a used volume with
  no store (``policy_seed_needs_host``, J5b), from the policy the vault is given; it prints what it
  will write (the clients, routes and servers, the ``env:`` names it allows, how many literal
  client tokens it writes as their hash) and records the host as the seed's author. With a store
  or an anchor it refuses and names the reseed. A volume with nothing in it may be seeded here
  too, as the vault's own start would.
- ``policy import --state DIR --reseed FILE|-`` (or ``--reseed --from-env``, the configured
  source) replaces a store that refuses to start, or one the host wants to replace (G-25). When
  the old head verifies, the reseed is planned against it and its ratchet as a host write (T-8,
  OPS-20): the plan names the revisions it undoes, the key generations against their floors and
  every change, and each thing the ratchet retired that it brings back needs its grant
  (``--allow-revive``, ``--allow-env``); the new ratchet is the old one advanced.
  ``--new-ratchet`` starts from the document's own ratchet instead, and lists what it forgets;
  it is the one way out of ``ratchet_full``, and the only way when the old head doesn't verify.
  Against a head that verifies, a planned reseed that widens needs ``--accept-widening`` with
  ``--yes``, and any reseed that drops a passkey's origin or moves ``admin.listen`` asks the
  typed confirmation, or ``--lockout-ok`` with ``--yes`` (I.1, Q41). The old head and revisions
  go to ``quarantine/`` (``vault/policystore.py``).

Every ``--state`` form refuses to run as root, since the vault's uid couldn't read what it wrote
(``state_as_root``, OPS-5), and takes the state lock a running vault holds (``state_locked``:
stop the vault first, in the host's own commands, OPS-6). It needs the vault's master key in its
environment, which is the vault's compose service's, so ``env:`` names resolve as the vault's
will; checks the document through the gate (C); and refuses a gateway key generation below the
gateway-key state before anything is written (``gatewaykeys.check``, G-4). An offline import or
rollback is planned and written as the running vault's is (``vault/managed.py``'s
``plan_on``), by the host offline, on a store a declarative start hasn't parked; it takes no
``--revoke-removed``, since revoking needs the running vault's token manager. What it will write
goes to stderr, with ``[y/N]`` unless ``--yes``; a policy read from standard input leaves no
answer to read, so without ``--yes`` the plan is printed and nothing is written. Every refusal is
the catalogue's sentence (``portal/refusals.py``, N.2), so operations.md's table names each.

``policy acknowledge-restore [--to N] [--yes]`` (K.3, J11), over the socket or with ``--state``,
records that the host saw a restore the gateway's witness shows (``policy_behind_witness``,
``policy_deployment_changed``): a revision with the head's content, numbered one above the
gateway's claim, so the counter passes it and the finding clears. The number is the gateway's
claim (T-4), so the command says where it comes from and takes it only typed at the terminal or
as ``--to N``, which must be the number the vault plans (with ``--yes``, ``--to`` is required).
With the vault stopped there is no claim to read: the number is the host's, typed or ``--to``,
from what health showed.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, Protocol, TextIO

from ..common.logs import off_stdout
from ..common.policy import PolicyError, gate, read_source, restart
from ..common.policy.export import header as export_header
from ..common.policy.gate import GateRefused
from ..common.policy.plan import (
    PlanInput,
    PlanRefused,
    WritePlan,
    normalize,
    normalized_digest,
    plan,
)
from ..common.policy.ratchet import Grants, Ratchet, initial, reach, violations
from ..common.policy.schema import Policy
from ..common.textrules import reveal_hidden
from ..portal import passkeys as passkey_file
from ..portal.refusals import Refusal, refusal
from ..vault import gatewaykeys, logs
from ..vault.keys import KeySet
from ..vault.managed import (
    Shaped,
    WriteRefused,
    Written,
    acknowledge_shaped,
    bindings,
    commands,
    diff_answer,
    export_answer,
    head_policy,
    history_page,
    import_shaped,
    jumped,
    lockout_rows,
    log_saved,
    lowered,
    moved,
    plan_answer,
    plan_digest,
    plan_on,
    refused_answer,
    rollback_shaped,
    widenings,
    written_answer,
)
from ..vault.onboarding import RESTART_VAULT, saved_next
from ..vault.policyseal import REASON_MAX, REVISION_MAX
from ..vault.policystart import POLICY_DIR, QUARANTINE, Commands, Fresh, Ok, Refused
from ..vault.policystore import HISTORY_PAGE_MAX, OFFLINE, PolicyStore, StoreRefused
from ..vault.server import (
    StartupError,
    StateLocked,
    acquire_state_lock,
    gateway_key_state,
    load_keys,
)
from ..vault.store import SecretStore, StoreError
from . import admin_client
from .onboard import Prefix, next_lines
from .review import write_json

# The refusals only these commands give; portal/refusals.py catalogues each (N.2).
Reason = Literal[
    "state_as_root",
    "state_locked",
    "seed_declarative",
    "import_declarative",
    "policy_store_present",
    "reseed_needs_new_ratchet",
    "policy_not_managed",
    "base_required",
    "export_other_deployment",
    "import_widens",
    "lockout_unconfirmed",
    "plan_changed",
    "nothing_to_acknowledge",
    "revision_out_of_range",
]

EXIT_OK: Final = 0
# Refused, or not confirmed: nothing was written.
EXIT_REFUSED: Final = 1
# It can't run: root, the lock, the master key, a policy that can't be read or is refused, a
# vault that can't be reached.
EXIT_UNREADABLE: Final = 2
# The planner's refusals whose subjects are grants, and the flag that grants each (H.5).
GRANT_FLAGS: Final = {
    "revives_client": "--allow-revive",
    "revives_caller": "--allow-revive",
    "pin_retired": "--allow-revive",
    "env_name_new": "--allow-env",
    "env_reach_grows": "--allow-env",
}
# The socket's route for acknowledge-restore (N.1, K.3).
ACKNOWLEDGE_PATH: Final = "/policy/acknowledge-restore"
# The actions whose stdout is their answer, kept free of log lines.
_READS: Final = frozenset({"head", "history", "diff", "export"})
# What the export's notes add for a declarative compose export: the way back (J10).
COMPOSE_NEXT: Final = (
    "Next: replace the policy under ZOEYMCP_CONFIG in your compose file with it, then:"
)


class OfflineRefused(Exception):
    """A refusal from the catalogue: its ``reason`` and the fields its sentence names, or the
    sentence ``said`` as the vault filled it in."""

    def __init__(
        self, reason: str, *, unreadable: bool = False, said: str | None = None, **fields: str
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.fields = fields
        self.unreadable = unreadable
        self.said = said
        self.flags: list[str] = []

    def text(self) -> str:
        return self.said if self.said is not None else refusal(self.reason, **self.fields).error

    @classmethod
    def answered(cls, reason: str, said: str, subjects: Sequence[str] = ()) -> OfflineRefused:
        """A refusal the vault (or the write path offline) answered: its sentence, and the flag
        each grant subject needs (H.5)."""
        refused = cls(reason, said=said)
        flag = GRANT_FLAGS.get(reason)
        if flag is not None:
            refused.flags = [f"{flag} {subject}" for subject in subjects]
        return refused

    @classmethod
    def of(cls, answer: Refusal | WriteRefused) -> OfflineRefused:
        if isinstance(answer, WriteRefused):
            filled = refused_answer(answer)
            return cls.answered(filled.reason, filled.error, answer.subjects)
        return cls(answer.reason, said=answer.error)


def _shown(value: str) -> str:
    """A name or a value as one line of the terminal: hidden characters revealed."""
    return reveal_hidden(value).replace("\n", "\\n").replace("\t", "\\t")


def run(
    args: argparse.Namespace,
    environ: Mapping[str, str],
    stdin: TextIO,
    out: TextIO,
    err: TextIO,
    *,
    as_root: bool,
) -> int:
    """``zoeymcp policy [<action>]``: over the admin socket, or with ``--state`` offline."""
    action = getattr(args, "action", None) or "head"
    name = f"zoeymcp policy {action}"
    usage = _usage(action, args, out)
    if usage is not None:
        err.write(f"{name}: {usage}\n")
        return EXIT_UNREADABLE
    # A read's stdout is its answer alone (the export's YAML, a JSON document): the store's log
    # lines (an offline form's housekeeping, the export's own) go to stderr meanwhile.
    quiet = off_stdout(err) if action in _READS else contextlib.nullcontext()
    try:
        with quiet:
            if getattr(args, "state", None) is None:
                socket = admin_client.socket_path(getattr(args, "socket", None))
                return _act(action, args, _Socket(socket), environ, stdin, out, err)
            return _offline(action, args, environ, stdin, out, err, as_root=as_root)
    except OfflineRefused as exc:
        err.write(f"{name}: {exc.text()}\n")
        for flag in exc.flags:
            err.write(f"  {flag}\n")
        return EXIT_UNREADABLE if exc.unreadable else EXIT_REFUSED
    except StartupError as exc:
        err.write(f"{name}: {exc}\n")
        return EXIT_UNREADABLE
    except admin_client.AdminUnavailable as exc:
        if exc.reason is None:
            err.write(f"{name}: {exc}\n")
            return EXIT_UNREADABLE
        refused = OfflineRefused.answered(exc.reason, str(exc), exc.data.get("subjects") or ())
        err.write(f"{name}: {refused.text()}\n")
        for flag in refused.flags:
            err.write(f"  {flag}\n")
        return EXIT_REFUSED


def _offline(
    action: str,
    args: argparse.Namespace,
    environ: Mapping[str, str],
    stdin: TextIO,
    out: TextIO,
    err: TextIO,
    *,
    as_root: bool,
) -> int:
    """A ``--state`` form, with the vault stopped: as the vault's uid, under the state lock."""
    state = Path(args.state)
    hosted = commands(environ, args.state, standard=False)
    if as_root:
        raise OfflineRefused("state_as_root", unreadable=True)
    keys, previous = load_keys(environ)
    try:
        fd = acquire_state_lock(state)
    except StateLocked as exc:
        raise OfflineRefused("state_locked", unreadable=True, command=hosted.stop()) from exc
    try:
        if action == "seed":
            return _seed(args, state, environ, stdin, err, keys, previous, hosted)
        if action == "import" and args.reseed:
            return _reseed(args, state, environ, stdin, err, keys, previous, hosted)
        vault = _Offline(state, environ, keys, previous, hosted)
        return _act(action, args, vault, environ, stdin, out, err)
    finally:
        if fd is not None:
            os.close(fd)


def _usage(action: str, args: argparse.Namespace, out: TextIO) -> str | None:
    """What is wrong with the arguments, if anything."""
    state = getattr(args, "state", None)
    reason = getattr(args, "reason", None)
    if reason is not None and not (1 <= len(reason) <= REASON_MAX and reason.isprintable()):
        return f"--reason is 1 to {REASON_MAX} printable characters"
    limit = getattr(args, "limit", None)
    if limit is not None and not 1 <= limit <= HISTORY_PAGE_MAX:
        return f"--limit is 1 to {HISTORY_PAGE_MAX}"
    if action == "acknowledge-restore":
        # One above REVISION_MAX is refused, revision_out_of_range, as the vault refuses it (K.3).
        if args.to is not None and args.to < 1:
            return f"--to is a revision, 1 to {REVISION_MAX:,}"
        if args.yes and args.to is None:
            return "with --yes, give the revision with --to N: the number is never taken unseen"
        return None
    if action == "export" and out.isatty() and not args.force_tty:
        return (
            "the export holds placeholders and client token hashes: redirect it to a file "
            "(> policy.yaml), or pass --force-tty to print it here"
        )
    if action != "import":
        if action == "rollback" and args.revoke_removed and state is not None:
            return "--revoke-removed needs the running vault: run it over the socket"
        return None
    if args.reseed:
        if state is None:
            return "--reseed replaces the store with the vault stopped: add --state DIR"
        for flag, given in (
            ("--baseline-only", args.baseline_only),
            ("--base", args.base is not None),
            ("--revoke-removed", args.revoke_removed),
        ):
            if given:
                return f"{flag} isn't a reseed's: a reseed replaces the store whole"
    elif args.new_ratchet:
        return "--new-ratchet goes with --reseed"
    if (args.source is None) == (not args.from_env):
        return "give the policy as FILE (- for standard input) or --from-env, one of them"
    if args.baseline_only and not args.from_env:
        return "--baseline-only goes with --from-env"
    if args.from_env and args.base is not None:
        return "--from-env is planned on the head: drop --base"
    if args.revoke_removed and state is not None:
        return "--revoke-removed needs the running vault: run it over the socket"
    return None


# --- what both forms share ---------------------------------------------------------------------


def _source(config: str | None, environ: Mapping[str, str], stdin: TextIO) -> tuple[str, Policy]:
    """The policy given, through the gate with this container's environment (C), and its text."""
    try:
        text, label = read_source(config, environ, stdin)
    except PolicyError as exc:
        found = gate.refused_text(exc.source, exc.findings)
        raise OfflineRefused("import_refused", unreadable=True, detail=found) from exc
    try:
        admitted = gate.admit_text(text, label, environ=environ)
    except GateRefused as exc:
        raise OfflineRefused("import_refused", unreadable=True, detail=str(exc)) from exc
    return text, admitted.policy


def _open(state: Path, keys: KeySet, previous: KeySet | None) -> PolicyStore:
    try:
        return PolicyStore.open(state, keys, previous)
    except OSError as exc:
        raise StartupError(f"can't read the policy store in {state}: {exc}") from exc


def _admitted(policy: Policy, revision: int, environ: Mapping[str, str]) -> None:
    """The policy as the revision will hold it, through the gate again (C.2)."""
    try:
        gate.admit(policy, f"revision {revision}", environ=environ)
    except GateRefused as exc:
        raise OfflineRefused("import_refused", detail=str(exc)) from exc


def _key_state(
    state: Path, keys: KeySet, previous: KeySet | None, policy: Policy
) -> gatewaykeys.State | None:
    """The gateway-key state, after refusing a policy whose gateway key generation is below it,
    before anything is written (F.3, G-4): a used volume has one."""
    found = gateway_key_state(state, keys, previous)
    if found is not None and gatewaykeys.check(found, policy.gateway_key_generation) is not None:
        detail = (
            f"gateway_key_generation can't go below {found.current}, the generation "
            f"{gatewaykeys.STATE_FILE} holds"
        )
        raise OfflineRefused("generation_lowered", detail=detail)
    return found


def _summary(given: Policy, policy: Policy) -> list[tuple[str, str]]:
    """What a policy written whole holds (F.3): its clients, routes and servers by name, the
    ``env:`` names it allows and where each may be sent, and how many literal client tokens it
    writes as their hash. Names only, never a value (Y13)."""
    gateway = policy.gateway
    clients = [] if gateway is None else sorted(gateway.clients)
    servers = [] if gateway is None else sorted(gateway.servers)
    given_clients = {} if given.gateway is None else given.gateway.clients
    hashed = sum(client.token is not None for client in given_clients.values())
    allowed = [
        name + (f" (sent to {', '.join(sorted(origins))})" if origins else "")
        for name, origins in sorted(reach(policy).items())
    ]
    return [
        ("Clients", ", ".join(clients) or "none"),
        ("Routes", ", ".join(route.name for route in policy.routes) or "none"),
        ("Servers", ", ".join(servers) or "none"),
        ("env: names it allows", "; ".join(allowed) or "none"),
        ("Client tokens written as their hash", str(hashed)),
    ]


def _rows(rows: Sequence[tuple[str, str]]) -> str:
    return "".join(
        f"  {_shown(label)}: {_shown(value)}\n" if value else f"  {_shown(label)}\n"
        for label, value in rows
    )


def _confirmed(
    yes: bool, piped: bool, stdin: TextIO, err: TextIO, question: str = "Write it?"
) -> bool:
    """``[y/N]`` unless ``--yes``. A policy read from standard input leaves no answer to read:
    the plan was printed, and nothing is written."""
    if yes:
        return True
    if piped:
        err.write(
            "Nothing written: the policy came on standard input, so there is no answer to read. "
            "Read the plan above, then run this again with --yes.\n"
        )
        return False
    err.write(f"{question} [y/N] ")
    err.flush()
    if stdin.readline().strip().lower() in ("y", "yes"):
        return True
    err.write("Nothing written.\n")
    return False


# --- policy seed -------------------------------------------------------------------------------


def _seed(
    args: argparse.Namespace,
    state: Path,
    environ: Mapping[str, str],
    stdin: TextIO,
    err: TextIO,
    keys: KeySet,
    previous: KeySet | None,
    hosted: Commands,
) -> int:
    """F.3's ``policy seed --state``: revision 1 on a volume with no store and no anchor."""
    _, given = _source(args.config, environ, stdin)
    if given.mode != "managed":
        raise OfflineRefused("seed_declarative", unreadable=True)
    store = _open(state, keys, previous)
    found = store.verdict
    if not (isinstance(found, Fresh) or _guarded(found)):
        raise OfflineRefused("policy_store_present", state=args.state)
    policy = normalize(given)
    _admitted(policy, 1, environ)
    _key_state(state, keys, previous, policy)
    err.write("Seeding revision 1 of a new deployment from the policy given:\n")
    err.write(_rows(_summary(given, policy)))
    if not _confirmed(args.yes, args.config == "-", stdin, err):
        return EXIT_REFUSED
    try:
        committed = store.seed(
            policy,
            ratchet=initial(policy),
            seed_digest=normalized_digest(given),
            author=OFFLINE,
        )
    except StoreRefused as exc:
        raise OfflineRefused(exc.reason) from exc
    head = store.head
    assert head is not None  # noqa: S101 - just seeded
    clients = {} if given.gateway is None else given.gateway.clients
    logs.event(
        "policy_seeded",
        revision=committed.revision,
        deployment=head.deployment[:8],
        tokens_hashed=sum(client.token is not None for client in clients.values()),
        via="offline",
    )
    err.write(
        f"Seeded revision 1 of deployment {head.deployment[:8]}. Start the vault:\n"
        f"  {hosted.up()}\n"
    )
    return EXIT_OK


def _guarded(found: object) -> bool:
    """A used volume with no store and no anchor: the one the vault won't seed (Y18)."""
    return isinstance(found, Refused) and found.reason == "policy_seed_needs_host"


# --- policy import --state --reseed ------------------------------------------------------------


def _reseed(
    args: argparse.Namespace,
    state: Path,
    environ: Mapping[str, str],
    stdin: TextIO,
    err: TextIO,
    keys: KeySet,
    previous: KeySet | None,
    hosted: Commands,
) -> int:
    """F.3's reseed: the document planned against the old head and its ratchet when that head
    verifies, else (or with ``--new-ratchet``) taken whole with its own ratchet; then written as
    the revision one above every number the volume shows, the old files in quarantine."""
    text, given = _source(None if args.from_env else args.source, environ, stdin)
    if given.mode != "managed":
        raise OfflineRefused("import_declarative", unreadable=True)
    store = _open(state, keys, previous)
    found = store.verdict
    number = store.reseed_revision
    candidate = normalize(given)
    _admitted(candidate, number, environ)
    floor = _key_state(state, keys, previous, candidate)
    old, why = _old_head(found)
    anchor = store.trusted_anchor
    kept = "its deployment kept" if anchor is not None else "a new deployment"
    wider: list[str] = []
    if old is not None and not args.new_ratchet:
        head = head_policy(old)
        ratchet, rows, wider = _planned(args, store, old, head, candidate, text, floor)
        err.write(
            f"Reseeding as revision {number}, {kept}, planned against revision {old.revision} "
            "and what it retired:\n"
        )
    else:
        if old is None and not args.new_ratchet:
            raise OfflineRefused("reseed_needs_new_ratchet", detail=why)
        ratchet = initial(candidate)
        rows = _summary(given, candidate)
        if old is not None:
            _floors(old, head_policy(old), candidate)
            rows += _forgotten(old.ratchet, ratchet)
            said = f"replacing revision {old.revision}"
        else:
            said = f"the old store doesn't verify ({why})"
        err.write(f"Reseeding as revision {number}, {kept}, with a new ratchet, {said}:\n")
    err.write(_rows(rows))
    # What can lock the portal out, against the old head when it verifies (I.1, G-17).
    lockout = (
        ()
        if old is None
        else lockout_rows(head_policy(old), candidate, _passkey_rp_ids(state, keys, previous))
    )
    for row in lockout:
        err.write(f"  Lockout: this {_shown(row.text)}\n")
    err.write(
        f"The old head and its revisions go to {args.state}/{POLICY_DIR}/{QUARANTINE}/, never "
        "deleted.\n"
    )
    asked = {
        "revision": number,
        "widens": bool(wider),
        "widenings": wider,
        "lockout": [{"text": row.text, "confirm": row.confirm} for row in lockout],
    }
    if _confirm_write(args, asked, args.source == "-", stdin, err, question="Write it?") is None:
        return EXIT_REFUSED
    try:
        committed = store.reseed(
            candidate,
            ratchet=ratchet,
            seed_digest=normalized_digest(given),
            base=None if old is None else old.revision,
            reason=args.reason,
        )
    except StoreRefused as exc:
        # The one store refusal whose sentence names what is still out of place.
        if exc.reason == "reseed_incomplete":
            raise OfflineRefused(exc.reason, detail=exc.detail) from exc
        raise OfflineRefused(exc.reason) from exc
    head_now = store.head
    assert head_now is not None  # noqa: S101 - just written
    logs.event(
        "policy_imported",
        revision=committed.revision,
        write_kind="policy.reseed",  # "kind" is the logger's own argument
        origin="reseed",
        author="host",
        base=None if old is None else old.revision,
        digest=committed.digest.removeprefix("sha256:")[:8],
        effects=[],
        deployment=head_now.deployment[:8],
        reseed=True,
        new_ratchet=old is None or args.new_ratchet,
        from_env=args.from_env,
    )
    err.write(f"Reseeded as revision {committed.revision}. Start the vault:\n  {hosted.up()}\n")
    return EXIT_OK


def _old_head(found: object) -> tuple[Ok | None, str]:
    """The old head when it verifies and its policy reads, else why not."""
    if isinstance(found, Ok):
        try:
            head_policy(found)
        except ValueError:
            return None, "its policy isn't one this version reads"
        return found, ""
    if isinstance(found, Refused):
        return None, found.reason
    return None, "there is no store"


def _planned(
    args: argparse.Namespace,
    store: PolicyStore,
    old: Ok,
    head: Policy,
    candidate: Policy,
    text: str,
    floor: gatewaykeys.State | None,
) -> tuple[Ratchet, list[tuple[str, str]], list[str]]:
    """The reseed planned as a host write against the old head (T-8): the planner's refusal, or
    the ratchet after it, the rows to show (the revisions it undoes and the key generations
    against their floors first) and its widening rows (``import_widens``, Q41)."""
    admin = candidate.admin
    planned = plan(
        PlanInput(
            kind="policy.reseed",
            surface="offline",
            head=head,
            head_revision=old.revision,
            head_digest=old.head.digest,
            ratchet=old.ratchet,
            candidate=candidate,
            # The vault starts with the candidate's own values: nothing in it waits for a restart.
            started=restart.Started(
                candidate.egress_proxy,
                candidate.egress_proxy_kind,
                None if admin is None else admin.listen,
                frozenset(),
            ),
            bindings=lambda policy: {},
            grants=Grants(revive=frozenset(args.allow_revive), env=frozenset(args.allow_env)),
            removed_in=store.removed_lookup(candidate),
        )
    )
    if isinstance(planned, PlanRefused):
        refused = OfflineRefused(planned.reason)
        refused.fields = _detail(planned)
        flag = GRANT_FLAGS.get(planned.reason)
        if flag is not None:
            refused.flags = [f"{flag} {subject}" for subject in planned.subjects]
        raise refused
    rows: list[tuple[str, str]] = []
    undone = _undone(store, old, candidate, text)
    if undone is not None:
        rows.append(("Undoes", undone))
    gateway = f"the store's floor {old.ratchet.gateway_key_floor}"
    if floor is not None:
        gateway += f", {gatewaykeys.STATE_FILE} {floor.current}"
    rows += [
        ("gateway_key_generation", f"{candidate.gateway_key_generation} ({gateway})"),
        (
            "egress_key_generation",
            f"{candidate.egress_key_generation} (the store's floor {old.ratchet.egress_key_floor})",
        ),
    ]
    # The planner's first row names head + 1; the reseed's number is above every one shown.
    rows += list(planned.rows[1:])
    return planned.ratchet, rows, widenings(planned)


def _detail(planned: PlanRefused) -> dict[str, str]:
    """The fields the refusal's sentence names: ``detail``, unless it names none."""
    return {} if planned.reason in ("ratchet_full", "no_change") else {"detail": planned.detail}


def _undone(store: PolicyStore, old: Ok, candidate: Policy, text: str) -> str | None:
    """The revisions the reseed undoes (F.3): those after the one the document came from, an
    export's header of this deployment, else the newest kept revision whose policy it is."""
    source = None
    found = export_header(text)
    if found is not None and found.deployment == old.head.deployment[:8]:
        source = found.revision
    else:
        wanted = normalized_digest(candidate)
        for number in sorted(store.kept, reverse=True):
            policy = store.policy(number)
            if policy is not None and normalized_digest(policy) == wanted:
                source = number
                break
    if source is None or source >= old.revision:
        return None
    if source + 1 == old.revision:
        return f"revision {old.revision}"
    return f"revisions {source + 1}..{old.revision}"


def _floors(old: Ok, head: Policy, candidate: Policy) -> None:
    """A new ratchet forgets what was retired, never a key generation's floor (E1, Y5)."""
    for found in violations(old.ratchet, head, candidate, verified=frozenset(), grants=Grants()):
        if found.reason == "generation_lowered":
            detail = f"{found.subject} can't go below {found.floor}"
            raise OfflineRefused("generation_lowered", detail=detail)


def _forgotten(before: Ratchet, after: Ratchet) -> list[tuple[str, str]]:
    """Every entry the old ratchet holds that the new one doesn't (F.3), by name where the
    ratchet keeps one: a retired client or caller is a hash, so only counted."""
    rows = [
        ("Forgets", f"pin:{server}/{kind}/{name}: {len(pins)} retired pin(s)")
        for (server, kind, name), pins in sorted(before.retired_pins.items())
    ]
    if before.retired_clients:
        rows.append(("Forgets", f"{len(before.retired_clients)} retired client token(s)"))
    if before.retired_callers:
        rows.append(("Forgets", f"{len(before.retired_callers)} retired caller placeholder(s)"))
    rows += [
        ("Forgets", f"approve: {server}/{kind}/{name}")
        for server, kind, name in sorted(before.approved - after.approved)
    ]
    for name, origins in sorted(before.env.items()):
        gone = sorted(origins - after.env.get(name, frozenset()))
        if name not in after.env:
            rows.append(("Forgets", f"env:{name}"))
        elif gone:
            rows.append(("Forgets", f"env:{name} sent to {', '.join(gone)}"))
    return rows or [("Forgets", "nothing: the old ratchet retired nothing")]


# --- the host's commands on the head and its history (H, M.6) ------------------------------------


@dataclass(frozen=True)
class _Write:
    """An import or a rollback, as the host asked for it."""

    action: Literal["import", "rollback"]
    target: int | None = None  # a rollback's
    text: str | None = None  # an import's document; None with --from-env
    from_env: bool = False
    baseline_only: bool = False
    revive: tuple[str, ...] = ()
    env: tuple[str, ...] = ()
    reason: str | None = None
    revoke_removed: bool = False

    def query(
        self, *, plan: bool, accept: bool = False, lockout: bool = False
    ) -> list[tuple[str, str]]:
        """The socket's query (N.1)."""
        flags = (
            ("plan", plan),
            ("from_env", self.from_env),
            ("baseline_only", self.baseline_only),
            ("revoke_removed", self.revoke_removed),
            ("accept_widening", accept),
            ("lockout_ok", lockout),
        )
        found = [(name, "1") for name, given in flags if given]
        found += [("allow_revive", value) for value in self.revive]
        found += [("allow_env", value) for value in self.env]
        if self.reason is not None:
            found.append(("reason", self.reason))
        return found


class _Vault(Protocol):
    """Where the commands read and write: the running vault over its socket, or the store with
    the vault stopped. Each answers in the socket's shapes (N.1)."""

    via: str

    def head(self) -> dict[str, Any]: ...

    def history(self, before: int | None, limit: int | None) -> dict[str, Any]: ...

    def diff(self, revision: int, against: int | None) -> dict[str, Any]: ...

    def export(self, revision: int | None, mode: str, target: str | None) -> dict[str, Any]: ...

    def plan(self, write: _Write, base: int) -> dict[str, Any]: ...

    def commit(
        self, write: _Write, base: int, digest: str, *, accept: bool, lockout: bool
    ) -> dict[str, Any]: ...

    def acknowledge(self, base: int, to: int | None, digest: str | None) -> dict[str, Any]:
        """``acknowledge-restore`` (K.3): its plan without ``digest``, numbered ``to`` (over the
        socket, the vault's own from the witness), else its commit."""
        ...


class _Socket:
    """The running vault, over its admin socket."""

    via = "socket"

    def __init__(self, socket: str) -> None:
        self._socket = socket

    def head(self) -> dict[str, Any]:
        return admin_client.policy_head(self._socket)

    def history(self, before: int | None, limit: int | None) -> dict[str, Any]:
        return admin_client.policy_history(self._socket, before=before, limit=limit)

    def diff(self, revision: int, against: int | None) -> dict[str, Any]:
        return admin_client.policy_diff(self._socket, revision, against=against)

    def export(self, revision: int | None, mode: str, target: str | None) -> dict[str, Any]:
        return admin_client.policy_export(self._socket, revision=revision, mode=mode, target=target)

    def plan(self, write: _Write, base: int) -> dict[str, Any]:
        return admin_client.policy_write(
            self._socket, _path(write), write.query(plan=True), body=_body(write), base=base
        )

    def commit(
        self, write: _Write, base: int, digest: str, *, accept: bool, lockout: bool
    ) -> dict[str, Any]:
        return admin_client.policy_write(
            self._socket,
            _path(write),
            write.query(plan=False, accept=accept, lockout=lockout),
            body=_body(write),
            base=base,
            plan_digest=digest,
        )

    def acknowledge(self, base: int, to: int | None, digest: str | None) -> dict[str, Any]:
        query = [("plan", "1")] if digest is None else [("to", str(to))]
        return admin_client.policy_write(
            self._socket, ACKNOWLEDGE_PATH, query, base=base, plan_digest=digest
        )


def _path(write: _Write) -> str:
    if write.action == "rollback":
        return f"/policy/rollback/{write.target}"
    return "/policy/import"


def _body(write: _Write) -> bytes:
    return b"" if write.text is None else write.text.encode("utf-8")


class _Offline:
    """The store in a state directory, with the vault stopped: read, planned and written as the
    running vault would (``vault/managed.py``), by the host offline. A store that refuses to
    start refuses here too, with its recoveries; one a declarative start parked is read, and
    refuses every write (``policy_not_managed``)."""

    via = "offline"

    def __init__(
        self,
        state: Path,
        environ: Mapping[str, str],
        keys: KeySet,
        previous: KeySet | None,
        hosted: Commands,
    ) -> None:
        self._state = state
        self._environ = environ
        self._keys = keys
        self._previous = previous
        self._hosted = hosted
        self._store = _open(state, keys, previous)
        found = self._store.verdict
        if isinstance(found, Refused):
            raise StartupError(found.text(hosted))
        if not isinstance(found, Ok):
            raise StartupError(
                f"there is no policy store in {state}: seed it with zoeymcp policy seed --state "
                f"{state}"
            )
        try:
            self._head = head_policy(found)
        except ValueError as exc:
            raise StartupError(
                f"the head's policy, revision {found.revision}, isn't one this version reads"
            ) from exc
        self._ratchet = found.ratchet
        self._parked = found.parked is not None

    def head(self) -> dict[str, Any]:
        top = self._store.head
        assert top is not None  # noqa: S101 - an Ok store has one
        return {"mode": "managed", "revision": top.revision, "deployment8": top.deployment[:8]}

    def history(self, before: int | None, limit: int | None) -> dict[str, Any]:
        return history_page(self._store, before, limit or HISTORY_PAGE_MAX)

    def diff(self, revision: int, against: int | None) -> dict[str, Any]:
        return _or_refused(diff_answer(self._store, revision, against))

    def export(self, revision: int | None, mode: str, target: str | None) -> dict[str, Any]:
        top = self._store.head
        assert top is not None  # noqa: S101 - an Ok store has one
        number = top.revision if revision is None else revision
        answer = _or_refused(
            export_answer(
                self._store,
                number,
                mode="declarative" if mode == "declarative" else "managed",
                target="compose" if target == "compose" else "plain",
            )
        )
        logs.event("policy_exported", revision=number, via="offline")
        return answer

    def plan(self, write: _Write, base: int) -> dict[str, Any]:
        planned, _ = self._planned(write, base)
        return plan_answer(planned, self._lockout(planned))

    def commit(
        self, write: _Write, base: int, digest: str, *, accept: bool, lockout: bool
    ) -> dict[str, Any]:
        planned, shaped = self._planned(write, base)
        if plan_digest(planned) != digest:
            raise OfflineRefused("plan_changed")
        wider = widenings(planned)
        if wider and not accept:
            raise OfflineRefused("import_widens", detail=", ".join(wider))
        rows = self._lockout(planned)
        if rows and not lockout:
            raise OfflineRefused("lockout_unconfirmed", detail="; ".join(r.text for r in rows))
        refused = lowered(gateway_key_state(self._state, self._keys, self._previous), planned)
        if refused is not None:
            raise OfflineRefused.of(refused)
        target = shaped.evidence.target_revision if planned.kind == "policy.rollback" else None
        try:
            committed = self._store.commit(
                planned,
                author=OFFLINE,
                reason=write.reason,
                target=target,
                seed_digest=shaped.seed_digest,
            )
        except StoreRefused as exc:
            raise OfflineRefused(exc.reason) from exc
        log_saved(planned, committed, OFFLINE, logged=shaped.logged)
        # The vault isn't running: its own restart is the start the host makes next.
        steps = tuple(s for s in saved_next(planned.effects, applied=True) if s != RESTART_VAULT)
        written = Written(committed.revision, committed.digest, planned.effects, next=steps)
        return written_answer(written)

    def acknowledge(self, base: int, to: int | None, digest: str | None) -> dict[str, Any]:
        """``acknowledge-restore`` with the vault stopped (K.3): no witness to read, so the
        number is the host's, ``to``, above the head and at most ``REVISION_MAX``."""
        assert to is not None  # noqa: S101 - the command asks for it first offline
        top = self._store.head
        assert top is not None  # noqa: S101 - an Ok store has one
        if to <= top.revision:
            detail = f"revision {to} isn't above the head, revision {top.revision}"
            raise OfflineRefused("nothing_to_acknowledge", detail=detail)
        if to > REVISION_MAX:
            raise OfflineRefused("revision_out_of_range")
        shaped = acknowledge_shaped()
        planned, _ = self._planned(_Write("import"), base, shaped)
        planned = jumped(planned, to)
        if digest is None:
            return plan_answer(planned, (), to) | {"witness": None}
        if plan_digest(planned) != digest:
            raise OfflineRefused("plan_changed")
        try:
            committed = self._store.commit(planned, author=OFFLINE, jumped_from=base, revision=to)
        except StoreRefused as exc:
            raise OfflineRefused(exc.reason) from exc
        log_saved(planned, committed, OFFLINE, jumped_from=base)
        return written_answer(Written(committed.revision, committed.digest))

    def _planned(
        self, write: _Write, base: int, shaped: Shaped | None = None
    ) -> tuple[WritePlan, Shaped]:
        """The write planned on the head (G.6 steps 2-5), as the running vault plans it;
        ``shaped`` when the command shaped it itself (an acknowledgment)."""
        if self._parked:
            raise OfflineRefused("policy_not_managed")
        top = self._store.head
        assert top is not None  # noqa: S101 - an Ok store has one
        if base != top.revision:
            detail = moved(self._store.header, top.revision)
            raise OfflineRefused.of(WriteRefused("policy_moved", detail, revision=top.revision))
        if shaped is None:
            shaped = self._shaped(write)
        try:
            started = _started(shaped.candidate_of(self._head))
        except ValueError as exc:
            raise OfflineRefused("import_refused", detail=str(exc)) from exc
        planned = plan_on(
            self._store,
            self._head,
            self._ratchet,
            shaped.kind,
            "offline",
            shaped.candidate_of,
            environ=self._environ,
            started=started,
            bindings=self._bindings(),
            grants=Grants(revive=frozenset(write.revive), env=frozenset(write.env)),
            evidence=shaped.evidence,
        )
        if isinstance(planned, WriteRefused):
            raise OfflineRefused.of(planned)
        refused = lowered(gateway_key_state(self._state, self._keys, self._previous), planned)
        if refused is not None:
            raise OfflineRefused.of(refused)
        return planned, shaped

    def _shaped(self, write: _Write) -> Shaped:
        if write.action == "rollback":
            assert write.target is not None  # noqa: S101 - the parser requires it
            found = rollback_shaped(self._store, write.target)
        else:
            text, label = (
                _configured(self._environ) if write.text is None else (write.text, "the import")
            )
            try:
                given = gate.admit_text(text, label, environ=self._environ).policy
            except GateRefused as exc:
                raise OfflineRefused("import_refused", detail=str(exc)) from exc
            found = import_shaped(
                self._store.seed_digest,
                self._head,
                given,
                from_env=write.from_env,
                baseline_only=write.baseline_only,
            )
        if isinstance(found, Refusal):
            raise OfflineRefused.of(found)
        return found

    def _bindings(self) -> Callable[[Policy], Mapping[str, Any]]:
        """``PlanInput.bindings`` from the secret store in the state directory (D-10's preview,
        the entries a write leaves unused, G.8); none when it can't be read."""
        secrets = SecretStore(self._state, self._keys, self._previous)
        try:
            secrets.load()
        except StoreError:
            return lambda policy: {}
        return bindings(secrets)

    def _lockout(self, planned: WritePlan) -> list[Any]:
        return list(lockout_rows(self._head, planned.policy, self._rp_ids()))

    def _rp_ids(self) -> list[str] | None:
        return _passkey_rp_ids(self._state, self._keys, self._previous)


def _passkey_rp_ids(state: Path, keys: KeySet, previous: KeySet | None) -> list[str] | None:
    """Every enrolled passkey's RP ID, read from the passkey file without writing it; None when
    it can't be verified (I.1's rows then fail closed)."""
    path = state / passkey_file.DIRECTORY / passkey_file.FILE
    try:
        with path.open("rb") as handle:
            data = handle.read(passkey_file.MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return []
    except OSError:
        return None
    portal = None if previous is None else previous.portal_key
    try:
        document, _ = passkey_file.unseal(data, keys.portal_key, portal)
    except passkey_file.PasskeyFileError:
        return None
    return [passkey.rp_id for passkey in document.credentials]


def _or_refused(answer: dict[str, Any] | Refusal) -> dict[str, Any]:
    if isinstance(answer, Refusal):
        raise OfflineRefused.of(answer)
    return answer


def _configured(environ: Mapping[str, str]) -> tuple[str, str]:
    """The policy the vault's service is configured with (``ZOEYMCP_CONFIG``, G-14)."""
    try:
        return read_source(None, environ)
    except PolicyError as exc:
        found = gate.refused_text(exc.source, exc.findings)
        raise OfflineRefused("import_refused", detail=found) from exc


def _started(candidate: Policy) -> restart.Started:
    """What the vault, stopped, will start with: the candidate's own values (I.2), so nothing
    in it waits for the vault's restart; the bridges are the launcher's, unknown here."""
    admin = candidate.admin
    bridges = frozenset(
        route.upstream.removeprefix("unix:/run/zoeymcp-bridge-").split("/", 1)[0]
        for route in candidate.routes
        if route.upstream is not None and route.upstream.startswith("unix:/run/zoeymcp-bridge-")
    )
    return restart.Started(
        candidate.egress_proxy,
        candidate.egress_proxy_kind,
        None if admin is None else admin.listen,
        bridges,
    )


def _act(
    action: str,
    args: argparse.Namespace,
    vault: _Vault,
    environ: Mapping[str, str],
    stdin: TextIO,
    out: TextIO,
    err: TextIO,
) -> int:
    if action == "head":
        return _head(args, vault, out)
    if action == "history":
        return _history(args, vault, out)
    if action == "diff":
        return _diff(args, vault, out)
    if action == "export":
        return _export(args, vault, environ, out, err)
    if action == "acknowledge-restore":
        return _acknowledge(args, vault, environ, stdin, err)
    return _write(action, args, vault, environ, stdin, err)


def _head(args: argparse.Namespace, vault: _Vault, out: TextIO) -> int:
    """The mode and the head (M.6's first row)."""
    answer = vault.head()
    if args.format == "json":
        write_json(answer, out)
        return EXIT_OK
    if answer["mode"] != "managed" or answer.get("revision") is None:
        out.write(
            "Mode: declarative: the policy is the file or ZOEYMCP_CONFIG the vault was given.\n"
        )
        return EXIT_OK
    out.write("Mode: managed\n")
    out.write(f"Revision {answer['revision']}, {_who(answer)}, {_shown(answer['kind'])}\n")
    out.write(f"Deployment {answer['deployment8']}, digest {answer['digest8']}\n")
    gateway = answer["gateway"]
    if gateway["state"] == "unknown":
        out.write("Gateway: unknown (no status report yet)\n")
    elif gateway["revision"] is None:
        out.write(f"Gateway: {gateway['state']} (on a view this vault didn't install)\n")
    else:
        out.write(f"Gateway: {gateway['state']} (on revision {gateway['revision']})\n")
    witness = answer["witness"]
    if witness is None:
        out.write("Witness: unknown (no status report yet)\n")
    elif witness["revision"] is None:
        out.write("Witness: the gateway has seen no revision of this deployment yet\n")
    else:
        out.write(f"Witness: the gateway has seen revision {witness['revision']}\n")
    if witness is not None and witness["target"] is not None:
        out.write(
            f"The gateway's witness shows a restore: see zoeymcp health, then zoeymcp policy "
            f"acknowledge-restore (revision {witness['target']}).\n"
        )
    if answer["not_running"] is not None:
        out.write(
            f"Revision {answer['not_running']} is saved but not running: send SIGHUP to the vault "
            "or restart it.\n"
        )
    return EXIT_OK


def _when(created: int) -> str:
    return datetime.fromtimestamp(created, UTC).strftime("%Y-%m-%d %H:%M UTC")


def _who(entry: Mapping[str, Any]) -> str:
    """When and by whom, as the portal's policy view says it (A.4)."""
    author = entry["author"]
    if author["by"] == "passkey":
        who = f"passkey {_shown(author['fingerprint'][:8])}"
    elif author["by"] == "host":
        who = f"the host ({_shown(author['via'])})"
    else:
        who = "the seed"
    return f"saved {_when(entry['created'])} by {who}"


def _history(args: argparse.Namespace, vault: _Vault, out: TextIO) -> int:
    """H.1: one line per revision, newest first; a revision in quarantine is a gap."""
    page = vault.history(args.before, args.limit)
    if args.format == "json":
        write_json(page, out)
        return EXIT_OK
    for entry in page["revisions"]:
        if entry.get("gap"):
            out.write(f"{entry['revision']}  (in quarantine, or no longer readable)\n")
            continue
        line = f"{entry['revision']}  {_shown(entry['kind'])}  {_who(entry)}"
        if entry["base"] is not None:
            line += f"  base {entry['base']}"
        if entry["target"] is not None:
            line += f"  target {entry['target']}"
        if entry["jumped_from"] is not None:
            line += f"  jumped from {entry['jumped_from']}"
        if entry["reason"] is not None:
            line += f": {_shown(entry['reason'])}"
        out.write(line + "\n")
    if page["next"] is not None:
        out.write(f"More: zoeymcp policy history --before {page['next']}\n")
    return EXIT_OK


def _value(value: Any) -> str:
    if isinstance(value, str):
        return _shown(value)
    return _shown(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(", ", ": ")))


def _diff(args: argparse.Namespace, vault: _Vault, out: TextIO) -> int:
    """H.2's rows, hidden fields hidden, each with its direction."""
    answer = vault.diff(args.revision, args.against)
    if args.format == "json":
        write_json(answer, out)
        return EXIT_OK
    against = answer["against"]
    said = "an empty policy" if against is None else f"revision {against}"
    out.write(f"Revision {answer['revision']} against {said}:\n")
    for row in answer["rows"]:
        path = ".".join(_shown(str(part)) for part in row["path_shown"])
        if row["hidden"]:
            change = _value(row["new"])
        elif row["op"] == "added":
            change = f"added {_value(row['new'])}"
        elif row["op"] == "removed":
            change = f"removed {_value(row['old'])}"
        else:
            change = f"{_value(row['old'])} -> {_value(row['new'])}"
        out.write(f"  {path}: {change} ({row['direction']})\n")
    if not answer["rows"]:
        out.write("  no change\n")
    return EXIT_OK


def _export(
    args: argparse.Namespace, vault: _Vault, environ: Mapping[str, str], out: TextIO, err: TextIO
) -> int:
    """H.6: the YAML alone on stdout, the notes on stderr; for a declarative compose export,
    the way back in the host's own commands (J10)."""
    answer = vault.export(args.revision, args.mode, args.target)
    out.write(answer["export"])
    for note in answer["notes"]:
        err.write(f"{_shown(note)}\n")
    if args.mode == "declarative" and args.target == "compose":
        hosted = commands(environ, "/state", standard=False)
        err.write(f"{COMPOSE_NEXT}\n  {hosted.run('check')}\n  {hosted.up()}\n")
    return EXIT_OK


def _write(
    action: str,
    args: argparse.Namespace,
    vault: _Vault,
    environ: Mapping[str, str],
    stdin: TextIO,
    err: TextIO,
) -> int:
    """An import or a rollback (H.3, H.5): the base, the plan on stderr, the confirmations,
    then the write, which names the base and the plan's digest."""
    head = vault.head()
    if head["mode"] != "managed" or head.get("revision") is None:
        raise OfflineRefused("policy_not_managed")
    text = None
    if action == "import" and not args.from_env:
        text = _document(args.source, environ, stdin)
    write = _Write(
        "rollback" if action == "rollback" else "import",
        target=getattr(args, "revision", None),
        text=text,
        from_env=action == "import" and args.from_env,
        baseline_only=action == "import" and args.baseline_only,
        revive=tuple(args.allow_revive),
        env=tuple(args.allow_env),
        reason=args.reason,
        revoke_removed=args.revoke_removed,
    )
    base, said = _base(args, head, text)
    answer = vault.plan(write, base)
    if answer.get("already_saved"):
        # The same write made the head, and its answer was lost (MISS-9, FM-16).
        err.write(f"This was already written as revision {answer['revision']}.\n")
        return EXIT_OK
    err.write(f"Planned on revision {base} ({said}):\n")
    err.write(_rows([(str(label), str(value)) for label, value in answer["rows"]]))
    for row in answer["lockout"]:
        err.write(f"  Lockout: this {_shown(row['text'])}\n")
    if answer["unused"] and not write.revoke_removed:
        err.write(
            "Each store entry it leaves unused can't be revoked at its provider after it: run "
            "these first, or add --revoke-removed:\n"
        )
        for name in answer["unused"]:
            err.write(f"  zoeymcp secret delete {_shown(name)}\n")
    piped = write.text is not None and args.source == "-"
    confirmed = _confirm_write(args, answer, piped, stdin, err)
    if confirmed is None:
        return EXIT_REFUSED
    accept, lockout = confirmed
    done = vault.commit(write, base, answer["digest"], accept=accept, lockout=lockout)
    revision = done["revision"]
    if done["already_saved"]:
        err.write(f"This was already written as revision {revision}.\n")
    else:
        err.write(f"{_written(answer['kind'])} revision {revision}.\n")
    for entry in done["removed"]:
        if entry["revoked"]:
            err.write(f"Deleted {_shown(entry['name'])}, and asked its provider to revoke it.\n")
        else:
            err.write(f"Deleted {_shown(entry['name'])}.\n")
    lines = next_lines(done["next"], Prefix.from_environ(environ))
    if vault.via == "offline":
        hosted = commands(environ, args.state, standard=False)
        lines = [*lines, "Start the vault:", f"  {hosted.up()}"]
    err.write("".join(f"{line}\n" for line in lines))
    return EXIT_OK


def _acknowledge(
    args: argparse.Namespace,
    vault: _Vault,
    environ: Mapping[str, str],
    stdin: TextIO,
    err: TextIO,
) -> int:
    """K.3's acknowledge-restore: the number, where it comes from, the plan, then the write,
    which names the head as its base and the plan's digest. A number above ``REVISION_MAX``,
    given or typed, is refused (``revision_out_of_range``)."""
    if args.to is not None and args.to > REVISION_MAX:
        raise OfflineRefused("revision_out_of_range")
    head = vault.head()
    if head["mode"] != "managed" or head.get("revision") is None:
        raise OfflineRefused("policy_not_managed")
    base = int(head["revision"])
    to: int | None = args.to
    if vault.via == "offline":
        if to is None:
            to = _typed(
                stdin,
                err,
                "The vault is stopped, so its witness can't be read here. "
                "Type the revision to jump to, the one zoeymcp health named: ",
            )
            if to is None:
                return EXIT_REFUSED
        answer = vault.acknowledge(base, to, None)
        err.write(f"Revision {base} jumps to {to}: the number you gave.\n")
    else:
        answer = vault.acknowledge(base, None, None)
        target = int(answer["revision"])
        err.write(_jump(base, target, answer["witness"]) + "\n")
        if to is None:
            typed = _typed(stdin, err, f"Type {target} to write it: ")
            if typed != target:
                err.write("Nothing written.\n")
                return EXIT_REFUSED
            to = typed
        elif to != target:
            err.write(f"Nothing written: the vault plans revision {target}, not {to}.\n")
            return EXIT_REFUSED
    err.write(f"Planned on revision {base} (the head):\n")
    err.write(_rows([(str(label), str(value)) for label, value in answer["rows"]]))
    if args.to is not None and not _confirmed(args.yes, False, stdin, err, f"Write revision {to}?"):
        return EXIT_REFUSED
    done = vault.acknowledge(base, to, answer["digest"])
    err.write(f"Acknowledged the restore as revision {done['revision']}.\n")
    lines = next_lines(done["next"], Prefix.from_environ(environ))
    if vault.via == "offline":
        hosted = commands(environ, args.state, standard=False)
        lines = [*lines, "Start the vault:", f"  {hosted.up()}"]
    err.write("".join(f"{line}\n" for line in lines))
    return EXIT_OK


def _jump(base: int, target: int, witness: Mapping[str, Any]) -> str:
    """Where an acknowledgment's number comes from (K.3, T-4): the gateway's claim."""
    claim = target - 1
    whose = ""
    other = witness.get("other")
    if not (witness.get("behind") and witness.get("revision") == claim) and other is not None:
        whose = f" for another deployment of this vault ({_shown(str(other['deployment8']))})"
    return (
        f"Revision {base} jumps to {target}: one above the gateway's claim of {claim}{whose}; "
        "the number comes from the gateway."
    )


def _typed(stdin: TextIO, err: TextIO, question: str) -> int | None:
    """A revision number typed at the terminal, or None (nothing written); one above
    ``REVISION_MAX`` is refused (``revision_out_of_range``)."""
    err.write(question)
    err.flush()
    answer = stdin.readline().strip()
    if not (answer.isascii() and answer.isdigit()):
        err.write("Nothing written.\n")
        return None
    if len(answer.lstrip("0")) > len(str(REVISION_MAX)):
        raise OfflineRefused("revision_out_of_range")
    return int(answer)


def _written(kind: str) -> str:
    if kind == "policy.rollback":
        return "Rolled back as"
    if kind == "policy.acknowledge":
        return "Recorded the configured policy as the seed's baseline in"
    return "Imported as"


def _document(source: str, environ: Mapping[str, str], stdin: TextIO) -> str:
    """The document an import names (FILE, or - for standard input)."""
    try:
        text, _ = read_source(source, environ, stdin)
    except PolicyError as exc:
        found = gate.refused_text(exc.source, exc.findings)
        raise OfflineRefused("import_refused", unreadable=True, detail=found) from exc
    return text


def _base(args: argparse.Namespace, head: Mapping[str, Any], text: str | None) -> tuple[int, str]:
    """The revision a write is planned on (H.5, OPS-8), and how it was found: ``--base``; for an
    import of a document, its export header's, of this deployment; else the head's."""
    if getattr(args, "base", None) is not None:
        return int(args.base), "--base"
    if text is None:
        return int(head["revision"]), "the head"
    found = export_header(text)
    if found is None:
        raise OfflineRefused("base_required")
    if found.deployment != head["deployment8"]:
        raise OfflineRefused("export_other_deployment", detail=found.deployment)
    return found.revision, "from the export's header"


def _confirm_write(
    args: argparse.Namespace,
    answer: Mapping[str, Any],
    piped: bool,
    stdin: TextIO,
    err: TextIO,
    *,
    question: str | None = None,
) -> tuple[bool, bool] | None:
    """The confirmations a write needs (H.5, I.1): with ``--yes``, ``--accept-widening`` for a
    plan that widens and ``--lockout-ok`` for a lockout row; else ``[y/N]``, then each lockout
    row typed. Returns what to send (``accept_widening``, ``lockout_ok``), or None when not
    confirmed (nothing written)."""
    lockout = answer["lockout"]
    if args.yes:
        if answer["widens"] and not args.accept_widening:
            raise OfflineRefused("import_widens", detail=_widened(answer))
        if lockout and not args.lockout_ok:
            detail = "; ".join(row["text"] for row in lockout)
            raise OfflineRefused("lockout_unconfirmed", detail=detail)
        return True, bool(lockout)
    asked = question or f"Write revision {answer['revision']}?"
    if not _confirmed(False, piped, stdin, err, asked):
        return None
    for row in lockout:
        what = "the address" if row["text"].startswith("moves") else "the origin"
        err.write(f"This {_shown(row['text'])}. Type {what} to continue: ")
        err.flush()
        if stdin.readline().strip() != row["confirm"]:
            err.write("Nothing written.\n")
            return None
    return True, bool(lockout)


def _widened(answer: Mapping[str, Any]) -> str:
    """The widening rows' paths, as the refusal names them."""
    return ", ".join(str(path) for path in answer["widenings"])
