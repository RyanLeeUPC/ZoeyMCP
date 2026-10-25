"""The store's verdict and the start decision (M6 design D.6, F.1, O.3; Q7 (a), Q28, Q29, Q33-Q35;
Y3, Y4, Y18, Y19, T-13, T-14): every row of D.6 in its order, FM-6 to FM-13, FM-25 and FM-27 as
verdicts, the start's messages and their recoveries (J5b, J11, J16), what makes a volume used, the
source's mode, and every row of F.1's table.

Revisions, heads and anchors are sealed and unsealed here with ``policyseal``, so the verdict sees
what ``policystore`` will hand it; a file that fails is the seal's own refusal.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from zoeymcp.common.canonical import digest
from zoeymcp.common.policy import Finding, parse_policy
from zoeymcp.common.policy.gate import Admitted, GateRefused
from zoeymcp.common.policy.ratchet import loaded
from zoeymcp.portal import setupcode
from zoeymcp.vault import server
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.policyseal import (
    Anchor,
    Head,
    SealRefused,
    Unsealed,
    body_digest,
    make_body,
    seal_anchor,
    seal_head,
    seal_revision,
    unseal_anchor,
    unseal_head,
    unseal_revision,
)
from zoeymcp.vault.policystart import (
    ANCHOR_FILE,
    GONE_MAX,
    HEAD_FILE,
    NAMES_SHOWN,
    NO_POLICY,
    UNUSED,
    Commands,
    Declarative,
    Fault,
    Fresh,
    Managed,
    Ok,
    Quarantined,
    Refuse,
    Refused,
    Resume,
    Seed,
    Source,
    StartFacts,
    before,
    decide,
    read_source,
    revision_file,
    revision_number,
    set_aside,
    source_mode,
    verdict,
    volume_used,
)
from zoeymcp.vault.policystore import KEEP

KEYS = KeySet.from_master(bytes(range(32)))
OLD = KeySet.from_master(bytes(range(1, 33)))
OTHER = KeySet.from_master(bytes(range(2, 34)))
DEPLOYMENT = "0123456789abcdef" * 2
ELSEWHERE = "fedcba9876543210" * 2
SEED = "sha256:" + "5" * 64
POLICY: dict[str, Any] = {"version": 1, "mode": "managed"}
RATCHET: dict[str, Any] = {
    "gateway_key_floor": 1,
    "egress_key_floor": 1,
    "retired_pins": [],
    "retired_clients": [],
    "retired_callers": [],
    "approved": [],
    "env": {},
}
HARDENED = Commands("docker compose -f deploy/compose.hardened.yaml", "vault")
STANDARD = Commands("docker compose -f deploy/compose.yaml", "zoeymcp", "10001:10001")
RESTORE = (
    "  Restore /state from one backup, or start from your latest export:\n"
    "  docker compose -f deploy/compose.hardened.yaml stop vault\n"
    "  docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -T vault policy import "
    "--state /state --reseed - < policy-export.yaml\n"
    "  docker compose -f deploy/compose.hardened.yaml up -d vault\n"
    "  (Last resort: --reseed --from-env takes your compose policy as it is now, usually older "
    "than the head.)"
)
KEY_HINT = (
    "  If you rotated the master key, set ZOEYMCP_MASTER_KEY_PREVIOUS to the old one and recreate "
    "the vault.\n"
    "  Otherwise the file was changed outside the vault.\n"
)


def sealed(
    number: int,
    parent: str | None,
    *,
    deployment: str = DEPLOYMENT,
    keys: KeySet = KEYS,
    ratchet: dict[str, Any] = RATCHET,
    salt: int = 1,
    origin: str = "save",
) -> bytes:
    """Revision ``number``'s file: the seed for 1, else a portal save on the revision below, or
    a reseed (with no parent)."""
    plaintext = make_body(
        salt=bytes([salt]) * 32, policy=POLICY, ratchet=ratchet, seed_digest=SEED, reason=None
    )
    header: dict[str, Any] = {
        "v": 1,
        "deployment": deployment,
        "revision": number,
        "parent": parent,
        "created": 1_792_900_000 + number,
        "origin": "save",
        "kind": "policy.save",
        "author": {"by": "passkey", "fingerprint": "0123456789abcdef"},
        "base": number - 1,
        "target": None,
        "jumped_from": None,
        "body_digest": body_digest(plaintext),
    }
    if number == 1:
        header |= {"origin": "seed", "kind": "policy.seed", "author": {"by": "seed"}, "base": None}
    if origin == "reseed":
        header |= {"origin": "reseed", "kind": "policy.reseed", "base": None}
        header["author"] = {"by": "host", "via": "offline"}
    return seal_revision(header, plaintext, keys=keys, nonce=bytes(12))


def unsealed(data: bytes) -> Unsealed:
    return unseal_revision(data, KEYS, OLD, deployment=None)


def refusal(data: bytes, read: Any = unseal_revision, **more: Any) -> SealRefused:
    with pytest.raises(SealRefused) as refused:
        read(data, KEYS, OLD, **more)
    return refused.value


def chain(top: int) -> dict[int, Unsealed]:
    """Revisions 1 to ``top``, each naming the one below as its parent."""
    files: dict[int, Unsealed] = {}
    parent = None
    for number in range(1, top + 1):
        files[number] = unsealed(sealed(number, parent))
        parent = files[number].digest
    return files


def head_of(files: dict[int, Unsealed], top: int, oldest: int = 1, **changes: Any) -> Head:
    parent = files[oldest].header["parent"] if oldest in files else None
    head = Head(DEPLOYMENT, top, files[top].digest, oldest, parent, KEYS.key_id)
    return replace(head, **changes)


def anchor_of(highest: int, **changes: Any) -> Anchor:
    return replace(Anchor(DEPLOYMENT, highest, None, None, KEYS.key_id), **changes)


def listed(files: dict[int, Any]) -> list[str]:
    return ["head.json", "revisions", *(f"revisions/{n:010d}.json" for n in files)]


def store(
    anchor: Anchor | SealRefused | None,
    head: Head | SealRefused | None,
    files: dict[int, Any],
    *,
    names: list[str] | None = None,
    used: tuple[str, ...] = ("gateway-key.json",),
) -> Any:
    return verdict(anchor, head, files, listed(files) if names is None else names, used)


def ok(found: Any) -> Ok:
    assert isinstance(found, Ok), found
    return found


def refused(found: Any) -> Refused:
    assert isinstance(found, Refused), found
    return found


FILES = chain(5)
HEAD = head_of(FILES, 5)
ANCHOR = anchor_of(5)


# --- names and the volume ------------------------------------------------------------------


def test_revision_files_have_ten_digit_names() -> None:
    assert revision_file(17) == "policy/revisions/0000000017.json"
    assert revision_file(9_999_999_999) == "policy/revisions/9999999999.json"
    assert revision_number("0000000017.json") == 17
    assert revision_number("9999999999.json") == 9_999_999_999


@pytest.mark.parametrize(
    "name",
    [
        "0000000000.json",
        "17.json",
        "00000000017.json",
        "0000000017.json.tmp",
        "x0000000017.json",
        "0000000017.jso",
        "000000001a.json",
        "0000000017_json",
    ],
)
def test_other_names_are_not_revision_files(name: str) -> None:
    assert revision_number(name) is None


def test_the_unused_names_are_the_lock_and_the_setup_code() -> None:
    assert frozenset({server.LOCK_FILE, setupcode.FILE}) == UNUSED


@pytest.mark.parametrize(
    ("names", "policy_empty", "used"),
    [
        ([], True, ()),
        (["vault.lock"], True, ()),
        # CR-12: a setup code made before the first start (J8) doesn't send the operator to seed.
        (["setup.json"], True, ()),
        (["vault.lock", "setup.json", "policy"], True, ()),
        (["policy"], False, ("policy",)),
        (["store.json", "vault.lock"], True, ("store.json",)),
        (["store.json", "gateway-key.json"], True, ("gateway-key.json", "store.json")),
        (["portal"], True, ("portal",)),
        (["ledger-reported"], True, ("ledger-reported",)),
        (["connectors"], True, ("connectors",)),
        # A name the vault doesn't know counts: refuse rather than guess.
        (["lost+found"], True, ("lost+found",)),
        (["vault.lock.old"], True, ("vault.lock.old",)),
    ],
    ids=[
        "empty",
        "lock",
        "setup-code",
        "lock-setup-empty-policy",
        "policy-not-empty",
        "store",
        "sorted",
        "portal",
        "ledger",
        "connectors",
        "unknown",
        "near-lock",
    ],
)
def test_what_makes_a_volume_used(
    names: list[str], policy_empty: bool, used: tuple[str, ...]
) -> None:
    assert volume_used(names, policy_empty=policy_empty) == used


# --- D.6 row 1: the anchor -----------------------------------------------------------------


def test_an_anchor_that_fails_its_mac_is_refused() -> None:
    data = bytearray(seal_anchor(ANCHOR, KEYS))
    data[data.index(b'"highest":5') + 10] = ord("6")
    found = refused(store(refusal(bytes(data), unseal_anchor), HEAD, FILES))
    assert found == Refused(
        "policy_anchor_tampered",
        ANCHOR_FILE,
        "was tampered with, or written under another master key",
    )
    assert found.text(HARDENED) == (
        "refused to start: /state/policy-anchor.json was tampered with, or written under another "
        f"master key.\n{KEY_HINT}{RESTORE}"
    )


def test_an_anchor_that_isnt_one_is_refused_as_tampered() -> None:
    found = refused(store(refusal(b"{}", unseal_anchor), HEAD, FILES))
    assert found.reason == "policy_anchor_tampered"
    assert found.detail == "isn't a policy anchor"


def test_an_anchor_under_an_unknown_key_names_it() -> None:
    data = seal_anchor(replace(ANCHOR, key_id=OTHER.key_id), OTHER)
    found = refused(store(refusal(data, unseal_anchor), HEAD, FILES))
    assert found.reason == "key_unknown"
    assert found.key_id == OTHER.key_id
    assert found.file == ANCHOR_FILE
    assert found.text(HARDENED) == (
        f"refused to start: /state/policy-anchor.json was written under master key ID "
        f"{OTHER.key_id}, which is neither ZOEYMCP_MASTER_KEY nor ZOEYMCP_MASTER_KEY_PREVIOUS.\n"
        f"{KEY_HINT}{RESTORE}"
    )


def test_an_anchor_under_the_key_it_retired_is_refused() -> None:
    """policyseal reads it (its own key verifies it); the start refuses it (T-13)."""
    anchor = unseal_anchor(seal_anchor(anchor_of(5, retired_key_id=KEYS.key_id), KEYS), KEYS, None)
    found = refused(store(anchor, HEAD, FILES))
    assert found == Refused("key_retired", ANCHOR_FILE, key_id=KEYS.key_id)
    assert found.text(HARDENED) == (
        f"refused to start: /state/policy-anchor.json is sealed under master key ID "
        f"{KEYS.key_id}, which a finished master-key rotation retired.\n{RESTORE}"
    )


def test_an_anchor_that_retired_another_key_is_read() -> None:
    assert ok(store(anchor_of(5, retired_key_id=OLD.key_id), HEAD, FILES)).revision == 5


def test_the_anchor_refusal_comes_before_every_other() -> None:
    """Row 1 first: even with no head and no files, a bad anchor is the refusal."""
    bad = SealRefused("tampered", "was tampered with, or written under another master key")
    assert refused(store(bad, None, {})).reason == "policy_anchor_tampered"


# --- rows 2-6: nothing, the guard, and one of the two gone ---------------------------------


def test_a_fresh_volume_may_seed() -> None:
    assert store(None, None, {}, names=[], used=()) == Fresh()


def test_both_deleted_on_a_used_volume() -> None:
    """FM-9, row 3: refused policy_seed_needs_host, J5b's message (Y18)."""
    found = refused(store(None, None, {}, names=[], used=("gateway-key.json", "store.json")))
    assert found == Refused("policy_seed_needs_host", "policy", "gateway-key.json, store.json")
    assert found.text(HARDENED) == (
        "refused to start: managed mode with no policy revisions, on a state volume that was used "
        "before (gateway-key.json, store.json). If you are switching this deployment to managed "
        "mode, seed revision 1 from ZOEYMCP_CONFIG once:\n"
        "  docker compose -f deploy/compose.hardened.yaml stop vault\n"
        "  docker compose -f deploy/compose.hardened.yaml run --rm --no-deps vault policy seed "
        "--state /state\n"
        "  docker compose -f deploy/compose.hardened.yaml up -d vault\n"
        "If you didn't, /state/policy and /state/policy-anchor.json may have been deleted: "
        "restore /state from one backup."
    )


def test_the_standard_tier_seeds_as_the_vaults_uid() -> None:
    """OPS-5: a one-off container there would run as root."""
    text = Refused("policy_seed_needs_host", "policy", "store.json").text(STANDARD)
    assert (
        "  docker compose -f deploy/compose.yaml run --rm --no-deps --user 10001:10001 zoeymcp "
        "policy seed --state /state\n"
    ) in text
    assert "  docker compose -f deploy/compose.yaml stop zoeymcp\n" in text
    assert "  docker compose -f deploy/compose.yaml up -d zoeymcp\n" in text


def test_the_used_names_are_capped_and_revealed() -> None:
    names = [f"name{n}" for n in range(NAMES_SHOWN + 2)]
    assert refused(store(None, None, {}, names=[], used=tuple(names))).detail == (
        "name0, name1, name2, name3, name4 and 2 more"
    )
    exactly = tuple(names[:NAMES_SHOWN])
    assert refused(store(None, None, {}, names=[], used=exactly)).detail == ", ".join(exactly)
    assert refused(store(None, None, {}, names=[], used=("a\u202eb",))).detail == "a[U+202E]b"
    assert refused(store(None, None, {}, names=[], used=("a\nb\tc",))).detail == (
        "a[U+000A]b[U+0009]c"
    )


def test_anchor_deleted() -> None:
    """FM-11, row 4: a head or revisions without their anchor."""
    found = refused(store(None, HEAD, FILES))
    assert found == Refused("policy_anchor_missing", ANCHOR_FILE)
    assert found.text(HARDENED) == (
        "refused to start: /state/policy holds revisions, but the anchor beside it, "
        f"/state/policy-anchor.json, is gone.\n{RESTORE}"
    )
    assert refused(store(None, None, FILES)).reason == "policy_anchor_missing"
    assert refused(store(None, HEAD, {})).reason == "policy_anchor_missing"


def test_a_store_without_its_anchor_is_refused_even_on_a_fresh_volume() -> None:
    assert refused(store(None, HEAD, FILES, used=())).reason == "policy_anchor_missing"


def test_fresh_again_after_a_seed_killed_after_its_anchor() -> None:
    """FM-25, row 5: the anchor at 0 and no head seeds again under the anchor's deployment; a
    revision 1 written before the kill is the seed's, for quarantine."""
    assert store(anchor_of(0), None, {}) == Fresh(DEPLOYMENT)
    assert store(anchor_of(0), None, {1: FILES[1]}) == Fresh(DEPLOYMENT, (1,))
    assert store(anchor_of(0), None, {2: FILES[2], 1: FILES[1]}) == Fresh(DEPLOYMENT, (1, 2))


def test_store_deleted() -> None:
    """FM-10, row 6: the anchor counted revisions and the head is gone."""
    found = refused(store(anchor_of(31), None, {}))
    assert found == Refused("policy_store_missing", ANCHOR_FILE, highest=31)
    assert found.text(HARDENED) == (
        "refused to start: /state/policy is gone, but this volume held revisions up to 31 "
        f"(/state/policy-anchor.json).\n{RESTORE}"
    )
    assert refused(store(anchor_of(1), None, FILES)).reason == "policy_store_missing"


# --- row 7: the head ------------------------------------------------------------------------


def test_a_head_that_fails_its_mac_is_refused() -> None:
    """J16's refusal, in its shape: a head that fails its MAC names no revision (unverified) and
    no key (the seal's refusal carries none)."""
    data = bytearray(seal_head(HEAD, KEYS))
    data[data.index(b'"oldest":1') + 9] = ord("2")
    found = refused(store(ANCHOR, refusal(bytes(data), unseal_head), FILES))
    assert found == Refused(
        "tampered", HEAD_FILE, "was tampered with, or written under another master key"
    )
    assert found.text(HARDENED) == (
        "refused to start: /state/policy/head.json was tampered with, or written under another "
        f"master key.\n{KEY_HINT}{RESTORE}"
    )


def test_a_head_under_an_unknown_key_names_it() -> None:
    data = seal_head(replace(HEAD, key_id=OTHER.key_id), OTHER)
    found = refused(store(ANCHOR, refusal(data, unseal_head), FILES))
    assert found.reason == "key_unknown"
    assert found.key_id == OTHER.key_id
    assert found.file == HEAD_FILE
    assert KEY_HINT in found.text(HARDENED)


def test_a_head_under_the_retired_key_is_refused() -> None:
    """T-13: even with ZOEYMCP_MASTER_KEY_PREVIOUS still set, which verifies it."""
    head = unseal_head(seal_head(replace(HEAD, key_id=OLD.key_id), OLD), KEYS, OLD)
    found = refused(store(anchor_of(5, retired_key_id=OLD.key_id), head, FILES))
    assert found == Refused("key_retired", HEAD_FILE, key_id=OLD.key_id)
    assert found.text(HARDENED).endswith(RESTORE)
    assert "If you rotated" not in found.text(HARDENED)


def test_a_head_under_the_previous_key_runs_mid_rotation() -> None:
    head = unseal_head(seal_head(replace(HEAD, key_id=OLD.key_id), OLD), KEYS, OLD)
    assert ok(store(ANCHOR, head, FILES)).head.key_id == OLD.key_id


def test_other_deployment() -> None:
    """FM-12: a head from another deployment is refused; an older revision is quarantined."""
    found = refused(store(ANCHOR, replace(HEAD, deployment=ELSEWHERE), FILES))
    assert found == Refused(
        "policy_deployment_mismatch", HEAD_FILE, "fedcba98, not 01234567, the anchor's"
    )
    assert found.text(HARDENED) == (
        "refused to start: /state/policy/head.json belongs to deployment fedcba98, not 01234567, "
        f"the anchor's.\n{RESTORE}"
    )
    files = {**FILES, 3: unsealed(sealed(3, FILES[2].digest, deployment=ELSEWHERE))}
    found_ok = ok(store(ANCHOR, HEAD, files))
    assert found_ok.quarantined == (Quarantined(3, "deployment"),)


# --- row 8: the revision the head names ------------------------------------------------------


def test_a_head_naming_a_missing_revision_dangles() -> None:
    files = {n: FILES[n] for n in range(1, 5)}
    found = refused(store(ANCHOR, HEAD, files))
    assert found == Refused("head_dangling", "policy/revisions/0000000005.json", revision=5)
    assert found.text(HARDENED) == (
        "refused to start: the policy head names revision 5, but "
        f"/state/policy/revisions/0000000005.json is missing.\n{RESTORE}"
    )


@pytest.mark.parametrize(
    ("entry", "detail"),
    [
        (
            SealRefused("tampered", "was tampered with, or written under another master key"),
            "was tampered with, or written under another master key",
        ),
        (SealRefused("body", "its body doesn't decrypt"), "its body doesn't decrypt"),
        (
            unsealed(sealed(5, FILES[4].digest, keys=OLD)),
            f"is sealed under master key ID {OLD.key_id}, which is retired",
        ),
        (
            unsealed(sealed(5, FILES[4].digest, deployment=ELSEWHERE)),
            "belongs to deployment fedcba98, not 01234567",
        ),
        (FILES[4], "holds revision 4"),
        (
            unsealed(sealed(5, FILES[4].digest, salt=2)),
            "isn't the revision the head names: its digest differs",
        ),
    ],
    ids=["tampered", "body", "retired-key", "other-deployment", "misplaced", "other-digest"],
)
def test_a_head_naming_a_revision_that_fails_is_tampered(entry: Any, detail: str) -> None:
    files: dict[int, Any] = {**FILES, 5: entry}
    found = refused(store(anchor_of(5, retired_key_id=OLD.key_id), HEAD, files))
    assert found == Refused("tampered", "policy/revisions/0000000005.json", detail, revision=5)
    assert found.text(HARDENED) == (
        f"refused to start: /state/policy/revisions/0000000005.json {detail}.\n{KEY_HINT}{RESTORE}"
    )


def test_a_head_revision_under_the_previous_key_runs_mid_rotation() -> None:
    files = {**FILES, 5: unsealed(sealed(5, FILES[4].digest, keys=OLD))}
    assert files[5].digest == HEAD.digest
    assert ok(store(ANCHOR, HEAD, files)).top.key_id == OLD.key_id


def test_a_head_revision_whose_ratchet_doesnt_load_is_tampered() -> None:
    top = unsealed(sealed(5, FILES[4].digest, ratchet={"gateway_key_floor": 1}))
    found = refused(store(ANCHOR, replace(HEAD, digest=top.digest), {**FILES, 5: top}))
    assert found.reason == "tampered"
    assert found.revision == 5
    assert found.detail.startswith("holds no ratchet: a ratchet has exactly the fields ")


# --- rows 9 and 10: the head against the anchor ----------------------------------------------


def test_head_behind_anchor() -> None:
    """FM-7, row 9: an older valid head put back; the anchor names the newer one (J11)."""
    head = head_of(FILES, 4)
    found = refused(store(ANCHOR, head, {n: FILES[n] for n in range(1, 5)}))
    assert found == Refused("policy_head_behind", HEAD_FILE, revision=4, highest=5)
    assert found.text(HARDENED) == (
        "refused to start: the policy head is revision 4, but revision 5 was committed "
        "(/state/policy-anchor.json). Was /state/policy restored from an older backup?\n"
        f"{RESTORE}"
    )


def test_the_head_behind_comes_before_files_above_it() -> None:
    """A head put back over a newer revision file: row 9, not row 11 or 12."""
    assert refused(store(ANCHOR, head_of(FILES, 4), FILES)).reason == "policy_head_behind"


def test_head_more_than_one_above_the_anchor() -> None:
    """Row 10: two commits never pass with a stale anchor (D.9), so no crash leaves this."""
    found = refused(store(anchor_of(3), HEAD, FILES))
    assert found == Refused("policy_anchor_behind", ANCHOR_FILE, revision=5, highest=3)
    assert found.text(HARDENED) == (
        "refused to start: the policy head is revision 5, but /state/policy-anchor.json says "
        "revision 3 is the highest committed. Was /state/policy-anchor.json restored from an "
        f"older backup?\n{RESTORE}"
    )


def test_head_one_above_the_anchor_runs_and_the_anchor_is_rewritten() -> None:
    """FM-2's verdict, row 13: a crash between the head's write and the anchor's."""
    found = ok(store(anchor_of(4), HEAD, FILES))
    assert found.anchor_stale
    assert found.revision == 5


def test_a_seed_killed_after_its_head_runs_with_the_anchor_rewritten() -> None:
    found = ok(store(anchor_of(0), head_of(FILES, 1), {1: FILES[1]}))
    assert (found.revision, found.anchor_stale) == (1, True)


def test_head_at_the_anchor_needs_no_rewrite() -> None:
    assert not ok(store(ANCHOR, HEAD, FILES)).anchor_stale


# --- rows 11 and 12: files above the head ----------------------------------------------------


NEXT = unsealed(sealed(6, FILES[5].digest))


def test_head_and_anchor_behind_one() -> None:
    """FM-8 and FM-1's verdict, row 12: the newest revision is above the head and chains: it is
    uncommitted, and the older head runs."""
    found = ok(store(ANCHOR, HEAD, {**FILES, 6: NEXT}))
    assert found.uncommitted == 6
    assert found.revision == 5
    assert found.kept == (1, 2, 3, 4, 5)
    assert found.quarantined == ()


def test_nothing_above_the_head_is_nothing_uncommitted() -> None:
    assert ok(store(ANCHOR, HEAD, FILES)).uncommitted is None


@pytest.mark.parametrize(
    ("above", "detail"),
    [
        ({6: NEXT, 7: unsealed(sealed(7, NEXT.digest))}, "revisions 6, 7"),
        ({7: unsealed(sealed(7, NEXT.digest))}, "revision 7"),
        ({6: unsealed(sealed(6, FILES[4].digest))}, "revision 6"),
        ({6: SealRefused("tampered", "was tampered with")}, "revision 6"),
        ({6: unsealed(sealed(6, FILES[5].digest, keys=OLD))}, "revision 6"),
        ({6: unsealed(sealed(6, FILES[5].digest, deployment=ELSEWHERE))}, "revision 6"),
        ({6: unsealed(sealed(7, FILES[5].digest))}, "revision 6"),
    ],
    ids=["two", "a-gap", "not-the-heads-child", "fails", "retired-key", "elsewhere", "misplaced"],
)
def test_files_above_the_head_that_dont_follow_it(above: dict[int, Any], detail: str) -> None:
    """Row 11: an older head put back over newer revisions."""
    files: dict[int, Any] = {**FILES, **above}
    found = refused(store(anchor_of(5, retired_key_id=OLD.key_id), HEAD, files))
    assert found == Refused("files_above_head", "policy/revisions", detail, revision=5)
    assert found.text(HARDENED) == (
        f"refused to start: /state/policy/revisions holds {detail} above the head, revision 5, "
        f"that don't follow it. Was an older head.json put back over newer revisions?\n{RESTORE}"
    )


def test_many_files_above_the_head_are_capped() -> None:
    files: dict[int, Any] = {**FILES, **dict.fromkeys(range(6, 13), NEXT)}
    assert refused(store(ANCHOR, HEAD, files)).detail == "revisions 6, 7, 8, 9, 10 and 2 more"


# --- row 14: older revisions ------------------------------------------------------------------


def test_replayed_old_revision() -> None:
    """FM-6: a kept revision replaced by an older valid one is quarantined, and only it; the
    head runs and History shows the gap."""
    found = ok(store(ANCHOR, HEAD, {**FILES, 3: FILES[2]}))
    assert found.quarantined == (Quarantined(3, "misplaced"),)
    assert found.kept == (1, 2, 4, 5)
    assert found.missing == 0
    assert found.revision == 5


def test_a_replayed_uncommitted_revision_doesnt_chain() -> None:
    """A save that never answered, put back in place of the one committed after it: it names
    the right parent and verifies, but the revision above doesn't name it."""
    uncommitted = unsealed(sealed(3, FILES[2].digest, salt=9))
    found = ok(store(ANCHOR, HEAD, {**FILES, 3: uncommitted}))
    assert found.quarantined == (Quarantined(3, "chain"),)
    assert found.kept == (1, 2, 4, 5)


@pytest.mark.parametrize(
    ("entry", "fault"),
    [
        (SealRefused("unreadable", "isn't a policy revision"), "unreadable"),
        (SealRefused("not_a_revision", "isn't a policy revision"), "not_a_revision"),
        (SealRefused("key_unknown", "was written under ...", "f" * 16), "key_unknown"),
        (SealRefused("tampered", "was tampered with"), "tampered"),
        (SealRefused("body", "its body doesn't decrypt"), "body"),
        (unsealed(sealed(3, FILES[2].digest, keys=OLD)), "key_retired"),
        (unsealed(sealed(3, FILES[2].digest, deployment=ELSEWHERE)), "deployment"),
    ],
    ids=["unreadable", "not-a-revision", "key-unknown", "tampered", "body", "retired", "elsewhere"],
)
def test_an_older_revision_that_fails_is_quarantined(entry: Any, fault: Fault) -> None:
    found = ok(store(anchor_of(5, retired_key_id=OLD.key_id), HEAD, {**FILES, 3: entry}))
    assert found.quarantined == (Quarantined(3, fault),)
    assert found.kept == (1, 2, 4, 5)


def test_an_older_revision_under_the_previous_key_is_kept_mid_rotation() -> None:
    """Re-sealed oldest first (D.7): a crash leaves files under both keys, each verifying."""
    files = {**FILES, 1: unsealed(sealed(1, None, keys=OLD))}
    found = ok(store(ANCHOR, HEAD, files))
    assert found.kept == (1, 2, 3, 4, 5)
    assert found.quarantined == ()


def test_a_missing_older_revision_is_a_gap() -> None:
    files = {n: FILES[n] for n in (1, 2, 4, 5)}
    found = ok(store(ANCHOR, HEAD, files))
    assert found.kept == (1, 2, 4, 5)
    assert found.quarantined == ()
    assert found.missing == 1


def test_two_gaps_keep_what_chains_from_either_end() -> None:
    files = {n: FILES[n] for n in (1, 3, 5)}
    found = ok(store(ANCHOR, HEAD, files))
    # 3 chains to neither 5 (4 is gone) nor 1 (2 is gone), so it can't be shown as history.
    assert found.kept == (1, 5)
    assert found.quarantined == (Quarantined(3, "chain"),)
    assert found.missing == 2


def test_the_walk_up_keeps_what_chains_from_the_oldest() -> None:
    files = {n: FILES[n] for n in (5, 3, 2, 1)}
    found = ok(store(ANCHOR, head_of(FILES, 5, oldest=2), files))
    assert found.kept == (2, 3, 5)
    assert found.pruned == (1,)
    assert found.missing == 1


def test_the_walk_up_starts_from_the_parent_the_head_names() -> None:
    """Below a break, the oldest kept must have the parent the head names for it."""
    files = {n: FILES[n] for n in (5, 3, 2, 1)}
    head = replace(HEAD, oldest=2, oldest_parent="sha256:" + "0" * 64)
    found = ok(store(ANCHOR, head, files))
    assert found.kept == (5,)
    assert found.quarantined == (Quarantined(2, "chain"), Quarantined(3, "chain"))
    assert found.pruned == (1,)
    assert found.missing == 1


def test_the_walk_up_stops_at_the_first_that_doesnt_chain() -> None:
    files = {**{n: FILES[n] for n in (1, 3, 5)}, 2: unsealed(sealed(2, FILES[1].digest, salt=3))}
    found = ok(store(ANCHOR, HEAD, files))
    # 2 is a sibling of the real one: 1 names nothing above it, so 2 chains from 1, and 3 doesn't.
    assert found.kept == (1, 2, 5)
    assert found.quarantined == (Quarantined(3, "chain"),)


def test_the_walk_up_stops_at_a_fault() -> None:
    bad = SealRefused("tampered", "was tampered with")
    files: dict[int, Any] = {**{n: FILES[n] for n in (1, 3, 5)}, 2: bad}
    found = ok(store(ANCHOR, HEAD, files))
    assert found.kept == (1, 5)
    assert found.quarantined == (Quarantined(2, "tampered"), Quarantined(3, "chain"))


def test_a_reseeds_oldest_has_no_parent() -> None:
    """After a reseed (F.3) the oldest kept has no parent, and the head names none: the walk up
    starts from no parent."""
    reseed = unsealed(sealed(3, None, origin="reseed"))
    four = unsealed(sealed(4, reseed.digest))
    files = {3: reseed, 5: unsealed(sealed(5, four.digest))}
    found = ok(store(ANCHOR, head_of(files, 5, oldest=3), files))
    assert found.kept == (3, 5)
    assert found.missing == 1
    files[4] = four
    assert ok(store(ANCHOR, head_of(files, 5, oldest=3), files)).kept == (3, 4, 5)


def test_a_chain_down_to_the_oldest_kept() -> None:
    """After pruning, the chain verifies from the oldest kept (D.8)."""
    files = {n: FILES[n] for n in (3, 4, 5)}
    found = ok(store(ANCHOR, head_of(FILES, 5, oldest=3), files))
    assert found.kept == (3, 4, 5)
    assert found.quarantined == ()
    assert found.missing == 0


# --- rows 15 and 16: stray names and a prune cut short -------------------------------------


def test_stray_file() -> None:
    """FM-13, row 15: names the store doesn't write are listed, revealed, and never read."""
    names = [
        *listed(FILES),
        "quarantine",
        "quarantine/0000000003.unreadable.json",
        ".policy-abc123",
        "revisions/.policy-def456",
        "notes.txt",
        "revisions/0000000000.json",
        "revisions/17.json",
        "revisions/0000000017.json.bak",
        "revisions/deeper/0000000001.json",
        "head.json/x",
        "head.json.bak",
        "Revisions",
        "a\u202eb",
        "a\nb",
    ]
    found = ok(store(ANCHOR, HEAD, FILES, names=names))
    assert found.stray == (
        "Revisions",
        "a[U+000A]b",
        "a[U+202E]b",
        "head.json.bak",
        "head.json/x",
        "notes.txt",
        "revisions/0000000000.json",
        "revisions/0000000017.json.bak",
        "revisions/17.json",
        "revisions/deeper/0000000001.json",
    )
    assert found.revision == 5


def test_a_store_with_only_its_own_names_has_no_stray() -> None:
    assert ok(store(ANCHOR, HEAD, FILES)).stray == ()


def test_prune_leftovers() -> None:
    """FM-27, row 16: a crash between the anchor and the prune leaves files below oldest,
    listed for removal and not verified."""
    files: dict[int, Any] = {n: FILES[n] for n in (5, 4, 3, 2)}
    files[1] = SealRefused("tampered", "was tampered with")
    found = ok(store(ANCHOR, head_of(FILES, 5, oldest=3), files))
    assert found.pruned == (1, 2)
    assert found.kept == (3, 4, 5)
    assert found.quarantined == ()


# --- row 17 -------------------------------------------------------------------------------


def test_ok_carries_the_head_its_ratchet_and_its_seed() -> None:
    found = ok(store(ANCHOR, HEAD, FILES))
    assert found.head == HEAD
    assert found.top == FILES[5]
    assert found.ratchet == loaded(RATCHET)
    assert found.seed_digest == SEED
    assert found.policy_digest == digest(POLICY)
    assert found.parked is None
    assert found.kept == (1, 2, 3, 4, 5)
    assert (found.uncommitted, found.quarantined, found.stray, found.pruned) == (None, (), (), ())
    assert found.missing == 0


def test_a_parked_store_says_so() -> None:
    found = ok(store(anchor_of(5, parked=5), HEAD, FILES))
    assert found.parked == 5
    assert not found.anchor_stale


def test_a_park_below_the_head_is_a_resume_whose_anchor_wasnt_written() -> None:
    """Parked at 5, resumed as 6, killed before the anchor: 6 runs, the mark is dropped."""
    files = {**FILES, 6: NEXT}
    found = ok(store(anchor_of(5, parked=5), head_of(files, 6), files))
    assert (found.parked, found.revision, found.anchor_stale) == (None, 6, True)


def test_a_stale_park_alone_makes_the_anchor_stale() -> None:
    found = ok(store(anchor_of(5, parked=4), HEAD, FILES))
    assert (found.parked, found.anchor_stale) == (None, True)


# --- the source -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "mode"),
    [
        ("version: 1\nmode: managed\n", "managed"),
        ("version: 1\nmode: declarative\n", "declarative"),
        # Each fails the gate; its mode is still read (T-14).
        ("version: 1\nmode: managed\nnot_a_field: 1\n", "managed"),
        ("version: 1\nmode: declarative\nnot_a_field: 1\n", "declarative"),
        # Neither: the gate refuses it, and so does the start.
        ("version: 1\n", "declarative"),
        ("version: 1\nmode: Managed\n", "declarative"),
        ("version: 1\nmode: [managed]\n", "declarative"),
        # The loader refuses these.
        ("version: 1\nmode: !!str managed\n", "unreadable"),
        ("- managed\n", "unreadable"),
        ("mode: managed\nmode: managed\n", "unreadable"),
    ],
    ids=[
        "managed",
        "declarative",
        "managed-failing",
        "declarative-failing",
        "no-mode",
        "capitalized",
        "a-list",
        "a-tag",
        "a-sequence",
        "duplicate-key",
    ],
)
def test_the_sources_mode(text: str, mode: str) -> None:
    assert source_mode(text) == mode


def test_a_source_the_gate_admits_carries_its_digest() -> None:
    text = "version: 1\nmode: declarative\n"
    found = read_source(text, "policy.yaml", environ={}, normalized=lambda p: "sha256:" + p.mode)
    assert found.mode == "declarative"
    assert found.admitted == Admitted(parse_policy(text, "policy.yaml"), ())
    assert found.digest == "sha256:declarative"


def test_a_source_the_gate_refuses_keeps_its_mode() -> None:
    found = read_source(
        "version: 1\nmode: managed\nnot_a_field: 1\n",
        "policy.yaml",
        environ={},
        normalized=lambda p: pytest.fail("no digest for a refused source"),
    )
    assert found.mode == "managed"
    assert isinstance(found.admitted, GateRefused)
    assert found.admitted.reason == "invalid"
    assert found.digest is None


def test_the_environment_reaches_the_gate() -> None:
    text = (
        "version: 1\nmode: declarative\ncredentials:\n"
        '  k: {kind: header, header: X-Key, format: "{secret}", secret: "env:NOTES_KEY"}\n'
    )
    refused_source = read_source(text, "p", environ={}, normalized=lambda p: "d")
    assert isinstance(refused_source.admitted, GateRefused)
    assert refused_source.admitted.reason == "fails_check"
    admitted = read_source(text, "p", environ={"NOTES_KEY": "v"}, normalized=lambda p: "d")
    assert isinstance(admitted.admitted, Admitted)


def test_no_policy_is_todays_text() -> None:
    with pytest.raises(server.StartupError) as refused_start:
        server.load_policy(None, {})
    assert str(refused_start.value) == NO_POLICY


# --- F.1's table ------------------------------------------------------------------------------


POLICY_OBJECT = parse_policy("version: 1\nmode: declarative\n", "policy.yaml")
FINDINGS = [Finding("routes", "error", "a route needs a name")]
GATE_REFUSED = GateRefused("fails_check", "policy.yaml", FINDINGS)
DECLARATIVE = Source("declarative", Admitted(POLICY_OBJECT, ()))
DECLARATIVE_FAILING = Source("declarative", GATE_REFUSED)
MANAGED = Source("managed", Admitted(POLICY_OBJECT, ()), SEED)
MANAGED_CHANGED = Source("managed", Admitted(POLICY_OBJECT, ()), "sha256:" + "9" * 64)
MANAGED_AS_HEAD = Source("managed", Admitted(POLICY_OBJECT, ()), digest(POLICY))
MANAGED_NO_DIGEST = Source("managed", Admitted(POLICY_OBJECT, ()))
MANAGED_FAILING = Source("managed", GateRefused("invalid", "policy.yaml", FINDINGS))
UNREADABLE = Source(
    "unreadable",
    GateRefused("unreadable", "policy.yaml", [Finding("(document)", "error", "tags")]),
)

OK = ok(store(ANCHOR, HEAD, FILES))
OK_STALE = ok(store(anchor_of(4), HEAD, FILES))
PARKED = ok(store(anchor_of(5, parked=5), HEAD, FILES))
FRESH = Fresh()
FRESH_AGAIN = Fresh(DEPLOYMENT, (1,))
GUARD = Refused("policy_seed_needs_host", "policy", "store.json")
BROKEN = Refused("tampered", HEAD_FILE, "was tampered with, or written under another master key")
BEHIND = Refused("policy_head_behind", HEAD_FILE, revision=4, highest=5)

PARKED_TEXT = (
    "refused to start: this store was parked by a declarative start at revision 5: give the "
    "policy to resume from, with mode: managed"
)
UNREAD = "policy missing.yaml refused: (document): can't read: gone"


def facts(source: Source | None, verdict_: Any, unread: str = NO_POLICY) -> StartFacts:
    return StartFacts(source, verdict_, HARDENED, unread)


@pytest.mark.parametrize(
    ("source", "found", "decision"),
    [
        # declarative, failing the gate: refused whatever the store (T-14).
        (DECLARATIVE_FAILING, OK, Refuse("fails_check", str(GATE_REFUSED))),
        (DECLARATIVE_FAILING, PARKED, Refuse("fails_check", str(GATE_REFUSED))),
        (DECLARATIVE_FAILING, FRESH, Refuse("fails_check", str(GATE_REFUSED))),
        (DECLARATIVE_FAILING, BROKEN, Refuse("fails_check", str(GATE_REFUSED))),
        # declarative with no store and no anchor: today's start, nothing written.
        (DECLARATIVE, FRESH, Declarative()),
        (DECLARATIVE, FRESH_AGAIN, Declarative()),
        (DECLARATIVE, GUARD, Declarative()),
        # declarative over a store: parked once (its anchor then says highest = parked = 5).
        (DECLARATIVE, OK, Declarative(5, park=True)),
        (DECLARATIVE, OK_STALE, Declarative(5, park=True)),
        (DECLARATIVE, PARKED, Declarative(parked=5)),
        (DECLARATIVE, BROKEN, Declarative(unverified="tampered")),
        (DECLARATIVE, BEHIND, Declarative(unverified="policy_head_behind")),
        # managed.
        (MANAGED, OK, Managed()),
        (MANAGED_AS_HEAD, OK, Managed()),
        (MANAGED_CHANGED, OK, Managed("changed")),
        (MANAGED_NO_DIGEST, OK, Managed("changed")),
        (MANAGED, PARKED, Resume(5)),
        (MANAGED_CHANGED, PARKED, Resume(5)),
        (MANAGED, FRESH, Seed()),
        (MANAGED, FRESH_AGAIN, Seed(DEPLOYMENT)),
        (MANAGED, GUARD, Refuse("policy_seed_needs_host", GUARD.text(HARDENED))),
        (MANAGED, BROKEN, Refuse("tampered", BROKEN.text(HARDENED))),
        (MANAGED, BEHIND, Refuse("policy_head_behind", BEHIND.text(HARDENED))),
        # unreadable, or managed failing the gate.
        (UNREADABLE, OK, Managed("unreadable")),
        (MANAGED_FAILING, OK, Managed("fails_check")),
        (
            UNREADABLE,
            PARKED,
            Refuse(
                "policy_resume_needs_source",
                f"{PARKED_TEXT}; the policy given is refused: {UNREADABLE.admitted}",
            ),
        ),
        (
            MANAGED_FAILING,
            PARKED,
            Refuse(
                "policy_resume_needs_source",
                f"{PARKED_TEXT}; the policy given is refused: {MANAGED_FAILING.admitted}",
            ),
        ),
        (UNREADABLE, FRESH, Refuse("unreadable", str(UNREADABLE.admitted))),
        (MANAGED_FAILING, FRESH, Refuse("invalid", str(MANAGED_FAILING.admitted))),
        (MANAGED_FAILING, GUARD, Refuse("invalid", str(MANAGED_FAILING.admitted))),
        (UNREADABLE, BROKEN, Refuse("tampered", BROKEN.text(HARDENED))),
        # none.
        (None, OK, Managed()),
        (None, OK_STALE, Managed()),
        (None, PARKED, Refuse("policy_resume_needs_source", PARKED_TEXT)),
        (None, FRESH, Refuse("no_policy", NO_POLICY)),
        (None, FRESH_AGAIN, Refuse("no_policy", NO_POLICY)),
        (None, GUARD, Refuse("no_policy", NO_POLICY)),
        (None, BROKEN, Refuse("tampered", BROKEN.text(HARDENED))),
    ],
    ids=[
        "declarative-failing-ok",
        "declarative-failing-parked",
        "declarative-failing-fresh",
        "declarative-failing-broken",
        "declarative-fresh",
        "declarative-fresh-again",
        "declarative-guard",
        "declarative-parks",
        "declarative-parks-stale-anchor",
        "declarative-parked",
        "declarative-unverified",
        "declarative-unverified-behind",
        "managed-head",
        "managed-head-equal-to-source",
        "managed-seed-ignored",
        "managed-no-digest",
        "managed-resume",
        "managed-resume-changed",
        "managed-seed",
        "managed-seed-again",
        "managed-guard",
        "managed-broken",
        "managed-behind",
        "unreadable-head",
        "managed-failing-head",
        "unreadable-parked",
        "managed-failing-parked",
        "unreadable-fresh",
        "managed-failing-fresh",
        "managed-failing-guard",
        "unreadable-broken",
        "none-head",
        "none-head-stale-anchor",
        "none-parked",
        "none-fresh",
        "none-fresh-again",
        "none-guard",
        "none-broken",
    ],
)
def test_the_start_decision(source: Source | None, found: Any, decision: Any) -> None:
    assert decide(facts(source, found)) == decision


def test_a_source_that_cant_be_read_refuses_with_its_own_text() -> None:
    assert decide(facts(None, FRESH, UNREAD)) == Refuse("no_policy", UNREAD)
    assert decide(facts(None, OK, UNREAD)) == Managed()


def test_a_refusal_names_the_hosts_commands() -> None:
    found = decide(StartFacts(MANAGED, GUARD, STANDARD))
    assert isinstance(found, Refuse)
    assert found.message == GUARD.text(STANDARD)
    assert "--user 10001:10001 zoeymcp policy seed" in found.message


# --- an acknowledged restore's jump (K.3, Y4) --------------------------------------------------


def acknowledged(number: int, parent: str, start: int) -> Unsealed:
    """Revision ``number``, an acknowledged restore that jumped from ``start``: the numbers
    between are never written."""
    plaintext = make_body(
        salt=bytes([7]) * 32, policy=POLICY, ratchet=RATCHET, seed_digest=SEED, reason=None
    )
    header: dict[str, Any] = {
        "v": 1,
        "deployment": DEPLOYMENT,
        "revision": number,
        "parent": parent,
        "created": 1_792_900_000 + number,
        "origin": "acknowledge",
        "kind": "policy.acknowledge",
        "author": {"by": "host", "via": "socket"},
        "base": start,
        "target": None,
        "jumped_from": start,
        "body_digest": body_digest(plaintext),
    }
    return unsealed(seal_revision(header, plaintext, keys=KEYS, nonce=bytes(12)))


JUMPED = acknowledged(9, FILES[5].digest, 5)
AFTER = unsealed(sealed(10, JUMPED.digest))


def test_a_revision_follows_its_jump_or_the_one_below() -> None:
    assert before(FILES[5]) == 4
    assert before(FILES[1]) == 0
    assert before(JUMPED) == 5
    assert before(acknowledged(6, FILES[5].digest, 5)) == 5


def test_a_jump_chains_to_the_revision_it_jumped_from() -> None:
    files: dict[int, Any] = {**FILES, 9: JUMPED, 10: AFTER}
    found = ok(store(anchor_of(10), head_of(files, 10), files))
    assert found.kept == (1, 2, 3, 4, 5, 9, 10)
    assert (found.quarantined, found.uncommitted, found.anchor_stale) == ((), None, False)
    # 6-8 were never written: none is missing.
    assert (found.absent, found.missing) == ((), 0)


def test_what_is_missing_is_what_a_revision_names() -> None:
    """Row 14 after a jump: a file gone is counted where the oldest the head names, or a revision
    of this store, names it, with the run of files gone below it; a number only an unreadable
    jump passed over isn't."""
    files: dict[int, Any] = {n: FILES[n] for n in (3, 5)}
    found = ok(store(ANCHOR, head_of(FILES, 5, oldest=2), files))
    assert (found.absent, found.missing) == ((2, 4), 2)
    files = {**{n: FILES[n] for n in (1, 2, 5)}, 9: JUMPED, 10: AFTER}
    found = ok(store(anchor_of(10), head_of(files, 10), files))
    assert (found.absent, found.missing) == ((3, 4), 2)
    files = {n: FILES[n] for n in (1, 5)}
    found = ok(store(ANCHOR, HEAD, files))
    assert (found.absent, found.missing) == ((2, 3, 4), 3)
    files = {**FILES, 9: SealRefused("tampered", "was tampered with"), 10: AFTER}
    found = ok(store(anchor_of(10), head_of(files, 10), files))
    assert (found.kept, found.quarantined) == ((1, 2, 3, 4, 5, 10), (Quarantined(9, "tampered"),))
    assert (found.absent, found.missing) == ((), 0)


def test_a_run_of_files_gone_is_counted_at_most_gone_max() -> None:
    """Past :data:`GONE_MAX` below the one named, a run of numbers is a lost jump's."""
    files: dict[int, Any] = {1: FILES[1], 100: unsealed(sealed(100, FILES[5].digest))}
    found = ok(store(anchor_of(100), head_of(files, 100), files))
    assert GONE_MAX == KEEP
    assert found.absent == tuple(range(100 - GONE_MAX, 100))
    files = {1: FILES[1], 66: unsealed(sealed(66, FILES[5].digest))}
    found = ok(store(anchor_of(66), head_of(files, 66), files))
    assert found.absent == tuple(range(2, 66))


def test_a_run_of_files_gone_stops_at_one_in_quarantine() -> None:
    files: dict[int, Any] = {n: FILES[n] for n in (1, 5)}
    names = [*listed(files), "quarantine/3.unreadable.json", "revisions/2.unreadable.json"]
    assert ok(store(ANCHOR, HEAD, files, names=names)).absent == (3, 4)


def test_set_aside_reads_the_revision_from_a_quarantined_name() -> None:
    names = [
        "3.unreadable.json",
        "0000000007.uncommitted.2.json",
        "9999999999.unreadable.json",
        "12345678901.unreadable.json",
        "4.json",
        "x.unreadable.json",
        "5.Unreadable.json",
        "6.unreadable.json.tmp",
    ]
    assert set_aside(names) == {3, 7, 9_999_999_999}


def test_the_walk_up_steps_over_a_jump() -> None:
    """Below a break above the jump, the walk up from the oldest crosses it to the revision that
    names its start."""
    eleven = unsealed(sealed(11, AFTER.digest))
    files: dict[int, Any] = {
        **FILES,
        9: JUMPED,
        10: SealRefused("tampered", "was tampered with"),
        11: eleven,
    }
    found = ok(store(anchor_of(11), head_of(files, 11), files))
    assert found.kept == (1, 2, 3, 4, 5, 9, 11)
    assert found.quarantined == (Quarantined(10, "tampered"),)


def test_a_jumped_head_one_step_above_the_anchor_rewrites_it() -> None:
    """FM-2 for an acknowledgment, row 13: killed after the jumped head, before the anchor."""
    files: dict[int, Any] = {**FILES, 9: JUMPED}
    found = ok(store(ANCHOR, head_of(files, 9), files))
    assert (found.revision, found.anchor_stale, found.kept) == (9, True, (1, 2, 3, 4, 5, 9))
    behind = refused(store(anchor_of(4), head_of(files, 9), files))
    assert behind == Refused("policy_anchor_behind", ANCHOR_FILE, revision=9, highest=4)


def test_a_jumped_save_that_never_answered_is_uncommitted() -> None:
    """FM-1 for an acknowledgment, row 12: the one file above the head is the jump from it."""
    found = ok(store(ANCHOR, HEAD, {**FILES, 9: JUMPED}))
    assert (found.uncommitted, found.revision, found.kept) == (9, 5, (1, 2, 3, 4, 5))


@pytest.mark.parametrize(
    ("above", "detail"),
    [
        ({9: acknowledged(9, FILES[5].digest, 4)}, "revision 9"),
        ({9: unsealed(sealed(9, FILES[5].digest))}, "revision 9"),
        ({9: acknowledged(9, FILES[4].digest, 5)}, "revision 9"),
        ({9: JUMPED, 10: AFTER}, "revisions 9, 10"),
    ],
    ids=["jumped-from-another", "no-jump", "not-the-heads-child", "two"],
)
def test_a_jump_above_the_head_that_doesnt_follow_it(above: dict[int, Any], detail: str) -> None:
    found = refused(store(ANCHOR, HEAD, {**FILES, **above}))
    assert found == Refused("files_above_head", "policy/revisions", detail, revision=5)
