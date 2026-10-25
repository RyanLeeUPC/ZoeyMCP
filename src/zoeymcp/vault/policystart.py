"""What the vault makes of its policy store and its configured source at start (M6 design D.6,
F.1; Q7 (a), Q28, Q29, Q33-Q35; Y3, Y4, Y18, Y19, T-13, T-14). Pure, mutation-tested.

``policystore`` reads ``/state/policy-anchor.json``, ``head.json`` and every ``revisions/`` file
through ``policyseal`` (each revision with ``deployment=None``, so the deployment is judged here)
and lists the store's names; :func:`verdict` decides, in D.6's order, the first row that applies:

- **Refused** (rows 1 and 3-11): the anchor or the head fails, is under an unknown master key or
  the one a finished rotation retired, or names another deployment; the revision the head names is
  missing or isn't the one it names; the head is behind the anchor or more than one above it;
  files above the head that a crash can't explain; and the guard of D-130: no anchor beside a
  store, no store beside an anchor that counted revisions, and nothing on a volume that was used
  (:func:`volume_used`), which only the host seeds (Y18). :meth:`Refused.text` is the start's
  message, naming the file and the recoveries (J5b, J11, J16).
- **Fresh** (rows 2 and 5): nothing yet, or a seed that never committed (FM-25), whose anchor's
  deployment the next seed keeps.
- **Ok** (rows 12-17): the head runs, with the ratchet and the seed digest from its body. Its
  housekeeping is the store's to do, whatever the start decides: a file one above the head that
  chains is a save that never answered (``uncommitted``); a head one above the anchor is a crash
  between the head's write and the anchor's, so the anchor is rewritten with ``highest`` the
  head's (``anchor_stale``, row 13); an older revision that fails or doesn't chain is quarantined,
  the rest are ``kept`` (History shows the gap, Q34); a name the store doesn't write is
  ``stray``, never read (Q35); files below ``oldest`` are a prune cut short (``pruned``).

The chain below the head is walked from the head down, each revision the parent its successor
names; past the first that isn't, from ``oldest`` up, from the parent the head names for it, up to
that one. So one bad file costs that revision alone; with two, the revisions between them can't be
shown to chain either way and are quarantined too.

An acknowledged restore (K.3) numbers its revision one above the gateway's claim, not one above
the head, and names the head in ``jumped_from``: the numbers between are never written. Its
revision follows the one it jumped from (:func:`before`), in the chain, as the one file above the
head a save that never answered leaves, and as the head one above the anchor's ``highest``.

:func:`decide` then takes F.1's table: the configured source's mode, read from the text even when
the gate refuses it (:func:`source_mode`; T-14), the gate's answer, and the verdict, and gives one
:data:`StartDecision`: refuse, run declaratively (parking an ``Ok`` store, F.4), run the head,
resume a parked store from the source, or seed. Nothing here writes, logs or reads the clock.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final, Literal

from ..common.canonical import digest
from ..common.logs import refuse_type
from ..common.policy import gate
from ..common.policy.findings import Finding
from ..common.policy.gate import Admitted, GateRefused
from ..common.policy.load import CONFIG_ENV
from ..common.policy.ratchet import Ratchet, loaded
from ..common.policy.schema import Policy
from ..common.textrules import reveal_hidden
from ..common.yamlload import YAMLRejected, load_mapping
from .policyseal import Anchor, Head, SealRefused, Unsealed

StoreReason = Literal[
    "policy_anchor_tampered",
    "key_unknown",
    "key_retired",
    "policy_seed_needs_host",
    "policy_anchor_missing",
    "policy_store_missing",
    "tampered",
    "policy_deployment_mismatch",
    "head_dangling",
    "policy_head_behind",
    "policy_anchor_behind",
    "files_above_head",
]
# Why an older revision is quarantined: a seal's own reason, or one of the start's.
Fault = Literal[
    "unreadable",
    "not_a_revision",
    "key_unknown",
    "tampered",
    "deployment",
    "body",
    "key_retired",
    "misplaced",
    "chain",
]
SourceMode = Literal["declarative", "managed", "unreadable"]
# policy_seed_ignored's reasons (F.5); fails_check is F.1's "the source fails check".
SeedIgnored = Literal["changed", "unreadable", "fails_check"]

# The store's names, relative to the state directory (D.1).
POLICY_DIR: Final = "policy"
HEAD_FILE: Final = "policy/head.json"
ANCHOR_FILE: Final = "policy-anchor.json"
REVISIONS: Final = "revisions"
QUARANTINE: Final = "quarantine"
# A quarantined file's revision, from its name (<n>.<why>.json, <n>.<why>.<k>.json).
_QUARANTINED: Final = re.compile(r"([0-9]{1,10})\.[a-z]+(?:\.[0-9]+)?\.json")
# What write_atomic names its temporary files in the store (D.1).
TEMPORARY_PREFIX: Final = ".policy-"
# What a vault writes in /state that doesn't make a volume used (F.1, CR-12): its lock
# (``vault/server.py`` LOCK_FILE), a setup code made before the first start
# (``portal/setupcode.py`` FILE), and an empty policy directory.
UNUSED: Final = frozenset({"vault.lock", "setup.json"})
# How many names a message lists before "and N more".
NAMES_SHOWN: Final = 5
# The start's text when no source is given: today's, byte for byte.
NO_POLICY: Final = gate.refused_text(
    "(none)",
    [Finding("(document)", "error", f"no policy given: use --config or set {CONFIG_ENV}")],
)

_REVISION_NAME: Final = re.compile(r"([0-9]{10})\.json")


def revision_file(number: int) -> str:
    """Revision ``number``'s file, relative to the state directory."""
    return f"{POLICY_DIR}/{REVISIONS}/{number:010d}.json"


def revision_number(name: str) -> int | None:
    """The revision a ``revisions/`` file name holds, or ``None`` unless it is one (1 and up)."""
    found = _REVISION_NAME.fullmatch(name)
    number = int(found.group(1)) if found else 0
    return number or None


def volume_used(names: Iterable[str], *, policy_empty: bool) -> tuple[str, ...]:
    """The names in the state directory that make it a used volume, sorted (F.1): anything but
    :data:`UNUSED` and an empty ``policy`` directory, a name the vault doesn't know included
    (refuse rather than guess)."""
    return tuple(
        sorted(
            name
            for name in names
            if name not in UNUSED and not (name == POLICY_DIR and policy_empty)
        )
    )


def _shown(name: str) -> str:
    """A file name revealed, its line breaks and tabs too: a name is one line of a message."""
    return reveal_hidden(name).replace("\n", "[U+000A]").replace("\t", "[U+0009]")


def _names(names: Collection[str]) -> str:
    shown = ", ".join(_shown(name) for name in list(names)[:NAMES_SHOWN])
    more = len(names) - NAMES_SHOWN
    return f"{shown} and {more} more" if more > 0 else shown


# --- the verdict -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Commands:
    """How the operator runs the vault's service from the host, for the recoveries a refusal names:
    the compose command (``ZOEYMCP_COMPOSE_CMD``), the service, ``10001:10001`` where a one-off
    container would otherwise run as root (the standard tier, OPS-5), and the state directory."""

    compose: str
    service: str
    user: str | None = None
    state: str = "/state"

    def stop(self) -> str:
        return f"{self.compose} stop {shlex.quote(self.service)}"

    def run(self, command: str, *, piped: bool = False) -> str:
        flags = (" -T" if piped else "") + (f" --user {self.user}" if self.user else "")
        return f"{self.compose} run --rm --no-deps{flags} {shlex.quote(self.service)} {command}"

    def up(self) -> str:
        return f"{self.compose} up -d {shlex.quote(self.service)}"


@dataclass(frozen=True)
class Fresh:
    """Rows 2 and 5: the seed may run. ``deployment`` is the anchor's of a seed that never
    committed (FM-25), else ``None`` (the seed makes one); ``uncommitted`` are that seed's files,
    for quarantine."""

    deployment: str | None = None
    uncommitted: tuple[int, ...] = ()


@dataclass(frozen=True)
class Refused:
    """Rows 1 and 3-11: the start refuses. ``file`` is relative to the state directory; ``detail``
    is a seal's own words, or the names that made the volume used; ``revision`` the head's;
    ``highest`` the anchor's; ``key_id`` the master key a key refusal names."""

    reason: StoreReason
    file: str
    detail: str = ""
    revision: int | None = None
    highest: int | None = None
    key_id: str | None = None

    def text(self, commands: Commands) -> str:
        """The start's message: the cause, then the recoveries (Q7 (a); J5b, J11, J16)."""
        state = commands.state
        if self.reason == "policy_seed_needs_host":
            return "\n".join(
                [
                    "refused to start: managed mode with no policy revisions, on a state volume "
                    f"that was used before ({self.detail}). If you are switching this deployment "
                    f"to managed mode, seed revision 1 from {CONFIG_ENV} once:",
                    f"  {commands.stop()}",
                    f"  {commands.run(f'policy seed --state {state}')}",
                    f"  {commands.up()}",
                    f"If you didn't, {state}/{POLICY_DIR} and {state}/{ANCHOR_FILE} may have been "
                    f"deleted: restore {state} from one backup.",
                ]
            )
        lines = [f"refused to start: {self._cause(state)}"]
        if self.reason in ("policy_anchor_tampered", "key_unknown", "tampered"):
            lines += [
                "  If you rotated the master key, set ZOEYMCP_MASTER_KEY_PREVIOUS to the old one "
                "and recreate the vault.",
                "  Otherwise the file was changed outside the vault.",
            ]
        reseed = f"policy import --state {state} --reseed - < policy-export.yaml"
        return "\n".join(
            [
                *lines,
                f"  Restore {state} from one backup, or start from your latest export:",
                f"  {commands.stop()}",
                f"  {commands.run(reseed, piped=True)}",
                f"  {commands.up()}",
                "  (Last resort: --reseed --from-env takes your compose policy as it is now, "
                "usually older than the head.)",
            ]
        )

    def _cause(self, state: str) -> str:
        path, anchor = f"{state}/{self.file}", f"{state}/{ANCHOR_FILE}"
        causes: dict[str, str] = {
            "policy_anchor_tampered": f"{path} {self.detail}.",
            "key_unknown": f"{path} {self.detail}.",
            "tampered": f"{path} {self.detail}.",
            "key_retired": f"{path} is sealed under master key ID {self.key_id}, which a "
            "finished master-key rotation retired.",
            "policy_anchor_missing": f"{state}/{POLICY_DIR} holds revisions, but the anchor "
            f"beside it, {path}, is gone.",
            "policy_store_missing": f"{state}/{POLICY_DIR} is gone, but this volume held "
            f"revisions up to {self.highest} ({path}).",
            "policy_deployment_mismatch": f"{path} belongs to deployment {self.detail}.",
            "head_dangling": f"the policy head names revision {self.revision}, but {path} is "
            "missing.",
            "policy_head_behind": f"the policy head is revision {self.revision}, but revision "
            f"{self.highest} was committed ({anchor}). Was {state}/{POLICY_DIR} restored from an "
            "older backup?",
            "policy_anchor_behind": f"the policy head is revision {self.revision}, but {anchor} "
            f"says revision {self.highest} is the highest committed. Was {anchor} restored from "
            "an older backup?",
            "files_above_head": f"{path} holds {self.detail} above the head, revision "
            f"{self.revision}, that don't follow it. Was an older head.json put back over newer "
            "revisions?",
        }
        return causes[self.reason]


@dataclass(frozen=True)
class Quarantined:
    """An older revision's file, moved to ``quarantine/<n>.unreadable.json`` (row 14)."""

    revision: int
    reason: Fault


@dataclass(frozen=True)
class Ok:
    """Rows 12-17: ``head`` runs; ``top`` is its revision, with ``ratchet`` and the policy's
    digest read from its body (D.6: so the ratchet comes with the head).

    Rows 9 and 10 leave the head at the anchor's ``highest`` or one above it (row 13), so the
    anchor's ``highest`` must now be the head's revision: ``anchor_stale`` when it isn't, and every
    anchor written from here on (a park, F.4, included) says ``highest = max(highest, head)``, the
    head's, so it never says ``parked`` above ``highest`` (``policyseal`` refuses that). ``parked``
    is the anchor's mark while it names this head; a mark below the head is a resume whose anchor
    never got written, so it is dropped and the anchor is stale too.
    """

    head: Head
    top: Unsealed
    # Neither shows in the repr: the policy's digest, unsalted, would confirm a guessed policy
    # (E-10), and the ratchet holds retired token hashes and env names (Y13).
    ratchet: Ratchet = field(repr=False)
    policy_digest: str = field(repr=False)
    anchor_stale: bool = False
    parked: int | None = None
    uncommitted: int | None = None  # row 12: quarantine/<n>.uncommitted.json
    quarantined: tuple[Quarantined, ...] = ()  # row 14
    kept: tuple[int, ...] = ()  # the revisions History shows, the head's included
    absent: tuple[int, ...] = ()  # row 14: below the head, named and with no file at all
    stray: tuple[str, ...] = ()  # row 15, revealed
    pruned: tuple[int, ...] = ()  # row 16

    @property
    def revision(self) -> int:
        return self.head.revision

    @property
    def seed_digest(self) -> str:
        return self.top.body.seed_digest

    @property
    def missing(self) -> int:
        """How many kept revisions below the head have no file at all (:func:`_absent`)."""
        return len(self.absent)


StoreVerdict = Fresh | Refused | Ok
refuse_type(Ok)


def _checked(
    entry: Unsealed | SealRefused, number: int, anchor: Anchor
) -> Unsealed | tuple[Fault, str]:
    """``entry``, read from revision ``number``'s file, if it is a revision of this store; else
    why not, and in what words."""
    if isinstance(entry, SealRefused):
        return entry.reason, entry.detail
    if entry.key_id == anchor.retired_key_id:
        return "key_retired", f"is sealed under master key ID {entry.key_id}, which is retired"
    deployment = entry.header["deployment"]
    if deployment != anchor.deployment:
        return "deployment", f"belongs to deployment {deployment[:8]}, not {anchor.deployment[:8]}"
    if entry.revision != number:
        return "misplaced", f"holds revision {entry.revision}"
    return entry


def _stray(listed: Iterable[str]) -> tuple[str, ...]:
    found = []
    for name in listed:
        top, _, rest = name.partition("/")
        if top == QUARANTINE or top.startswith(TEMPORARY_PREFIX):
            continue
        if top == REVISIONS and rest:
            if revision_number(rest) is not None or rest.startswith(TEMPORARY_PREFIX):
                continue
        elif not rest and top in ("head.json", REVISIONS):
            continue
        found.append(_shown(name))
    return tuple(sorted(found))


GONE_MAX: Final = 64
"""The longest run of files gone that :func:`_absent` counts below one named: ``policystore``
keeps its newest 64 written, so a longer run holds numbers a lost jump passed over."""


def set_aside(names: Iterable[str]) -> frozenset[int]:
    """The revision each ``quarantine/`` file in ``names`` was, by its name."""
    found = set()
    for name in names:
        number = _QUARANTINED.fullmatch(name)
        if number is not None:
            found.add(int(number.group(1)))
    return frozenset(found)


def before(entry: Unsealed) -> int:
    """The revision ``entry`` follows: the one an acknowledged restore jumped from (K.3), else
    the one below it. The numbers between a jump's two are never written."""
    jumped: int | None = entry.header["jumped_from"]
    return entry.revision - 1 if jumped is None else jumped


def _chain(
    head: Head, top: Unsealed, files: Mapping[int, Unsealed | SealRefused], anchor: Anchor
) -> tuple[tuple[int, ...], tuple[Quarantined, ...]]:
    """The revisions that chain to the head, the head's included, and the older files that don't
    (row 14), each with its fault, or ``chain``. Each revision follows the one :func:`before`
    names."""
    kept = [head.revision]
    expected = top.header["parent"]
    number = before(top)
    while number >= head.oldest and number in files:
        entry = _checked(files[number], number, anchor)
        if not isinstance(entry, Unsealed) or entry.digest != expected:
            break
        kept.append(number)
        expected = entry.header["parent"]
        number = before(entry)
    # Below the first that doesn't chain down, up from the parent the head names for oldest,
    # past each jump to the revision that names its start.
    jumps = {
        entry.header["jumped_from"]: n
        for n, entry in files.items()
        if isinstance(entry, Unsealed) and entry.header["jumped_from"] is not None
    }
    expected = head.oldest_parent
    low = head.oldest
    while low < number and low in files:
        entry = _checked(files[low], low, anchor)
        if not isinstance(entry, Unsealed) or entry.header["parent"] != expected:
            break
        kept.append(low)
        expected = entry.digest
        low = jumps.get(low, low + 1)
    quarantined = []
    for n in sorted(files):
        if head.oldest <= n < head.revision and n not in kept:
            entry = _checked(files[n], n, anchor)
            fault: Fault = "chain" if isinstance(entry, Unsealed) else entry[0]
            quarantined.append(Quarantined(n, fault))
    return tuple(sorted(kept)), tuple(quarantined)


def _absent(
    head: Head,
    files: Mapping[int, Unsealed | SealRefused],
    anchor: Anchor,
    aside: Collection[int],
) -> tuple[int, ...]:
    """The revisions below the head that have no file at all (row 14): each one something read
    names (the oldest the head names, and the one each revision of this store follows,
    :func:`before`), and the run of files gone below it, down to the next file, one in
    quarantine (``aside``) or the oldest, at most :data:`GONE_MAX` of it. A number nothing names
    or reaches isn't counted: one a jump passed over was never written, and a jump whose own file
    is unreadable names nothing (K.3)."""
    named = {head.oldest}
    for number, found in files.items():
        entry = _checked(found, number, anchor)
        if isinstance(entry, Unsealed):
            named.add(before(entry))
    gone: set[int] = set()
    for top in named:
        number = top
        while number >= head.oldest and number not in files and top - number < GONE_MAX:
            gone.add(number)
            if number in aside:
                break
            number -= 1
    return tuple(sorted(gone))


def verdict(
    anchor: Anchor | SealRefused | None,
    head: Head | SealRefused | None,
    files: Mapping[int, Unsealed | SealRefused],
    listed: Collection[str],
    used: Collection[str],
) -> StoreVerdict:
    """D.6's verdict on what ``policystore`` read: the anchor and the head (``None`` when absent),
    every ``revisions/`` file by the number its name holds, every name in ``/state/policy``
    relative to it (``revisions/<name>`` and ``quarantine/<name>`` for the files there), and
    :func:`volume_used`'s names."""
    # Row 1.
    if isinstance(anchor, SealRefused):
        reason: StoreReason = (
            "key_unknown" if anchor.reason == "key_unknown" else "policy_anchor_tampered"
        )
        return Refused(reason, ANCHOR_FILE, anchor.detail, key_id=anchor.key_id)
    if anchor is not None and anchor.key_id == anchor.retired_key_id:
        return Refused("key_retired", ANCHOR_FILE, key_id=anchor.key_id)
    # Rows 2-6: nothing, a store without its anchor, an anchor without its store.
    if anchor is None:
        if head is not None or files:
            return Refused("policy_anchor_missing", ANCHOR_FILE)
        if used:
            return Refused("policy_seed_needs_host", POLICY_DIR, _names(used))
        return Fresh()
    if head is None:
        if anchor.highest == 0:
            return Fresh(anchor.deployment, tuple(sorted(files)))
        return Refused("policy_store_missing", ANCHOR_FILE, highest=anchor.highest)
    # Row 7: the head.
    if isinstance(head, SealRefused):
        reason = "key_unknown" if head.reason == "key_unknown" else "tampered"
        return Refused(reason, HEAD_FILE, head.detail, key_id=head.key_id)
    if head.key_id == anchor.retired_key_id:
        return Refused("key_retired", HEAD_FILE, key_id=head.key_id)
    if head.deployment != anchor.deployment:
        detail = f"{head.deployment[:8]}, not {anchor.deployment[:8]}, the anchor's"
        return Refused("policy_deployment_mismatch", HEAD_FILE, detail)
    # Row 8: the revision it names, its digest, and the ratchet in its body.
    named = revision_file(head.revision)
    read = files.get(head.revision)
    if read is None:
        return Refused("head_dangling", named, revision=head.revision)
    entry = _checked(read, head.revision, anchor)
    if not isinstance(entry, Unsealed):
        return Refused("tampered", named, entry[1], revision=head.revision)
    if entry.digest != head.digest:
        detail = "isn't the revision the head names: its digest differs"
        return Refused("tampered", named, detail, revision=head.revision)
    try:
        ratchet = loaded(entry.body.ratchet)
    except ValueError as exc:
        return Refused("tampered", named, f"holds no ratchet: {exc}", revision=head.revision)
    # Rows 9 and 10: the head against the highest revision ever committed.
    if head.revision < anchor.highest:
        return Refused(
            "policy_head_behind", HEAD_FILE, revision=head.revision, highest=anchor.highest
        )
    # A head an acknowledged restore jumped to follows the anchor's highest as head + 1 does.
    if head.revision > anchor.highest + 1 and before(entry) != anchor.highest:
        return Refused(
            "policy_anchor_behind", ANCHOR_FILE, revision=head.revision, highest=anchor.highest
        )
    # Rows 11 and 12: above the head, at most the one file a save that never answered leaves:
    # head + 1, or the revision an acknowledged restore jumped to from the head.
    above = sorted(n for n in files if n > head.revision)
    found = files.get(above[0]) if len(above) == 1 else None
    following = None if found is None else _checked(found, above[0], anchor)
    if above and not (
        isinstance(following, Unsealed)
        and following.header["parent"] == head.digest
        and before(following) == head.revision
    ):
        shown = _names([str(n) for n in above])
        detail = f"revision {shown}" if len(above) == 1 else f"revisions {shown}"
        return Refused(
            "files_above_head", f"{POLICY_DIR}/{REVISIONS}", detail, revision=head.revision
        )
    kept, quarantined = _chain(head, entry, files, anchor)
    parked = anchor.parked if anchor.parked == head.revision else None
    return Ok(
        head=head,
        top=entry,
        ratchet=ratchet,
        policy_digest=digest(dict(entry.body.policy)),
        anchor_stale=head.revision > anchor.highest or parked != anchor.parked,
        parked=parked,
        uncommitted=above[0] if above else None,
        quarantined=quarantined,
        kept=kept,
        absent=_absent(
            head,
            files,
            anchor,
            set_aside(
                name.partition("/")[2] for name in listed if name.partition("/")[0] == QUARANTINE
            ),
        ),
        stray=_stray(listed),
        pruned=tuple(sorted(n for n in files if n < head.oldest)),
    )


# --- the decision ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """The configured source, read: its mode (:func:`source_mode`), the gate's answer, and the
    digest of the admitted policy as ``normalize`` writes it (D.5), for F.5's comparison."""

    mode: SourceMode
    admitted: Admitted | GateRefused
    digest: str | None = None


def source_mode(text: str) -> SourceMode:
    """The source's mode, from the strictly loaded mapping's ``mode`` even when the schema or
    ``check`` refuses the text (T-14): ``unreadable`` only for text the loader refuses. A mode
    that isn't ``managed`` reads as ``declarative``, which the gate then refuses, so the start
    does too (F.1's first row) and never runs a store the operator didn't ask for."""
    try:
        document = load_mapping(text)
    except YAMLRejected:
        return "unreadable"
    return "managed" if document.get("mode") == "managed" else "declarative"


def read_source(
    text: str,
    label: str,
    *,
    environ: Mapping[str, str],
    normalized: Callable[[Policy], str],
) -> Source:
    """The source ``text`` (named ``label``) through :func:`source_mode` and the gate;
    ``normalized`` is the digest of a policy as a revision would hold it."""
    mode = source_mode(text)
    try:
        admitted = gate.admit_text(text, label, environ=environ)
    except GateRefused as exc:
        return Source(mode, exc)
    return Source(mode, admitted, normalized(admitted.policy))


@dataclass(frozen=True)
class StartFacts:
    """What the vault read at start: the source (``None``: none given, or none it could read,
    with ``unread`` the text to refuse with), the store's verdict, and the host's commands."""

    source: Source | None
    store: StoreVerdict
    commands: Commands
    unread: str = NO_POLICY


@dataclass(frozen=True)
class Refuse:
    reason: str  # a StoreReason, a gate's, "no_policy" or "policy_resume_needs_source"
    message: str


@dataclass(frozen=True)
class Declarative:
    """Run the source declaratively. ``parked`` is the head parked, by this start or an earlier
    one; ``park`` says this start parks it (F.4): the anchor it writes says ``parked`` and
    ``highest`` both the head's revision (:class:`Ok`), whatever the anchor said before.
    ``unverified`` is a store refusal the start doesn't meet (``policy_store_unverified``)."""

    parked: int | None = None
    park: bool = False
    unverified: StoreReason | None = None


@dataclass(frozen=True)
class Managed:
    """Run the head; ``seed_ignored`` when the source differs from it (F.5)."""

    seed_ignored: SeedIgnored | None = None


@dataclass(frozen=True)
class Resume:
    """Plan the source as revision ``parked + 1`` against the parked head (F.4)."""

    parked: int


@dataclass(frozen=True)
class Seed:
    """Seed revision 1 from the source (F.3), under ``deployment`` when the anchor names one."""

    deployment: str | None = None


StartDecision = Refuse | Declarative | Managed | Resume | Seed


def _parked_text(revision: int) -> str:
    return (
        f"refused to start: this store was parked by a declarative start at revision {revision}: "
        "give the policy to resume from, with mode: managed"
    )


def decide(facts: StartFacts) -> StartDecision:
    """F.1's table, row by row."""
    source, store = facts.source, facts.store
    refused = source.admitted if source is not None else None
    if source is not None and source.mode == "declarative":
        if isinstance(refused, GateRefused):
            return Refuse(refused.reason, str(refused))
        if isinstance(store, Ok):
            if store.parked is not None:
                return Declarative(parked=store.parked)
            return Declarative(store.revision, park=True)
        if isinstance(store, Refused) and store.reason != "policy_seed_needs_host":
            return Declarative(unverified=store.reason)
        return Declarative()
    if isinstance(store, Refused) and store.reason != "policy_seed_needs_host":
        return Refuse(store.reason, store.text(facts.commands))
    if not isinstance(store, Ok):
        # No store and no anchor (Fresh, or a used volume's guard).
        if source is None:
            return Refuse("no_policy", facts.unread)
        if isinstance(refused, GateRefused):
            return Refuse(refused.reason, str(refused))
        if isinstance(store, Refused):
            return Refuse(store.reason, store.text(facts.commands))
        return Seed(store.deployment)
    if store.parked is not None:
        if source is None:
            return Refuse("policy_resume_needs_source", _parked_text(store.parked))
        if isinstance(refused, GateRefused):
            text = f"{_parked_text(store.parked)}; the policy given is refused: {refused}"
            return Refuse("policy_resume_needs_source", text)
        return Resume(store.parked)
    if source is None:
        return Managed()
    if isinstance(refused, GateRefused):
        return Managed("unreadable" if refused.reason == "unreadable" else "fails_check")
    same = source.digest in (store.seed_digest, store.policy_digest)
    return Managed(None if same else "changed")
