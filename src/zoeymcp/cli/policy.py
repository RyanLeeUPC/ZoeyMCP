"""``zoeymcp policy``: the host's commands on a managed policy (M6 design M.6). I/O.

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
  The old head and revisions go to ``quarantine/`` (``vault/policystore.py``).

Every form refuses to run as root, since the vault's uid couldn't read what it wrote
(``state_as_root``, OPS-5), and takes the state lock a running vault holds (``state_locked``:
stop the vault first, in the host's own commands, OPS-6). It needs the vault's master key in its
environment, which is the vault's compose service's, so ``env:`` names resolve as the vault's
will; checks the document through the gate (C); and refuses a gateway key generation below the
gateway-key state before anything is written (``gatewaykeys.check``, G-4). What it will write goes
to stderr, with ``[y/N]`` unless ``--yes``; a policy read from standard input leaves no answer to
read, so without ``--yes`` the plan is printed and nothing is written. Every refusal is the
portal's catalogued sentence (``portal/refusals.py``, N.2), so operations.md's table names each.
The other ``policy`` commands, and the import over the admin socket, are step 14a's.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Literal, TextIO

from ..common.policy import PolicyError, gate, read_source, restart
from ..common.policy.export import header as export_header
from ..common.policy.gate import GateRefused
from ..common.policy.plan import PlanInput, PlanRefused, normalize, normalized_digest, plan
from ..common.policy.ratchet import Grants, Ratchet, initial, reach, violations
from ..common.policy.schema import Policy
from ..common.textrules import reveal_hidden
from ..portal.refusals import refusal
from ..vault import gatewaykeys, logs
from ..vault.keys import KeySet
from ..vault.managed import commands, head_policy
from ..vault.policyseal import REASON_MAX
from ..vault.policystart import POLICY_DIR, QUARANTINE, Commands, Fresh, Ok, Refused
from ..vault.policystore import OFFLINE, PolicyStore, StoreRefused
from ..vault.server import (
    StartupError,
    StateLocked,
    acquire_state_lock,
    gateway_key_state,
    load_keys,
)

# The refusals only these commands give; portal/refusals.py catalogues each (N.2).
Reason = Literal[
    "state_as_root",
    "state_locked",
    "seed_declarative",
    "import_declarative",
    "policy_store_present",
    "reseed_needs_new_ratchet",
]

EXIT_OK: Final = 0
# Refused, or not confirmed: nothing was written.
EXIT_REFUSED: Final = 1
# It can't run: root, the lock, the master key, a policy that can't be read or is refused.
EXIT_UNREADABLE: Final = 2
# The planner's refusals whose subjects are grants, and the flag that grants each (H.5).
GRANT_FLAGS: Final = {
    "revives_client": "--allow-revive",
    "revives_caller": "--allow-revive",
    "pin_retired": "--allow-revive",
    "env_name_new": "--allow-env",
    "env_reach_grows": "--allow-env",
}


class OfflineRefused(Exception):
    """A refusal from the catalogue: its ``reason`` and the fields its sentence names."""

    def __init__(self, reason: str, *, unreadable: bool = False, **fields: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.fields = fields
        self.unreadable = unreadable
        self.flags: list[str] = []

    def text(self) -> str:
        return refusal(self.reason, **self.fields).error


def _shown(value: str) -> str:
    """A name or a value as one line of the terminal: hidden characters revealed."""
    return reveal_hidden(value).replace("\n", "\\n").replace("\t", "\\t")


def run(
    args: argparse.Namespace,
    environ: Mapping[str, str],
    stdin: TextIO,
    err: TextIO,
    *,
    as_root: bool,
) -> int:
    """``zoeymcp policy <action>``: ``seed``, or ``import`` with ``--state`` and ``--reseed``."""
    name = f"zoeymcp policy {args.action}"
    if args.action == "import":
        usage = _import_usage(args)
        if usage is not None:
            err.write(f"{name}: {usage}\n")
            return EXIT_UNREADABLE
    state = Path(args.state)
    hosted = commands(environ, args.state, standard=False)
    try:
        if as_root:
            raise OfflineRefused("state_as_root", unreadable=True)
        keys, previous = load_keys(environ)
        try:
            fd = acquire_state_lock(state)
        except StateLocked as exc:
            raise OfflineRefused("state_locked", unreadable=True, command=hosted.stop()) from exc
        try:
            if args.action == "seed":
                return _seed(args, state, environ, stdin, err, keys, previous, hosted)
            return _reseed(args, state, environ, stdin, err, keys, previous, hosted)
        finally:
            if fd is not None:
                os.close(fd)
    except OfflineRefused as exc:
        err.write(f"{name}: {exc.text()}\n")
        for flag in exc.flags:
            err.write(f"  {flag}\n")
        return EXIT_UNREADABLE if exc.unreadable else EXIT_REFUSED
    except StartupError as exc:
        err.write(f"{name}: {exc}\n")
        return EXIT_UNREADABLE


def _import_usage(args: argparse.Namespace) -> str | None:
    """What is wrong with ``import``'s arguments, if anything."""
    if args.state is None or not args.reseed:
        return "this version imports only offline, with the vault stopped: --state DIR --reseed"
    if (args.source is None) == (not args.from_env):
        return "give the policy as FILE (- for standard input) or --from-env, one of them"
    if args.reason is not None and not (
        1 <= len(args.reason) <= REASON_MAX and args.reason.isprintable()
    ):
        return f"--reason is 1 to {REASON_MAX} printable characters"
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


def _confirmed(yes: bool, piped: bool, stdin: TextIO, err: TextIO) -> bool:
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
    err.write("Write it? [y/N] ")
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
    if old is not None and not args.new_ratchet:
        head = head_policy(old)
        ratchet, rows = _planned(args, store, old, head, candidate, text, floor)
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
    err.write(
        f"The old head and its revisions go to {args.state}/{POLICY_DIR}/{QUARANTINE}/, never "
        "deleted.\n"
    )
    if not _confirmed(args.yes, args.source == "-", stdin, err):
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
) -> tuple[Ratchet, list[tuple[str, str]]]:
    """The reseed planned as a host write against the old head (T-8): the planner's refusal, or
    the ratchet after it and the rows to show, the revisions it undoes and the key generations
    against their floors first."""
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
    return planned.ratchet, rows


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
