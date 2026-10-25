"""The gateway's status report as the vault reads it (M6 design K.1; D-29, Y21, T-4, T-7).

The model: the frame refused whole, each server judged on its own, every cap both sides, a
definition or a token hash in a report refused, a bad tool name dropping only its own entry
(``test_bad_name_drops_only_its_entry``), a witness revision above ``REVISION_MAX`` refusing the
report, and the attention decision read back as the gateway made it.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from zoeymcp.common.policy.attention import Attention, attention, quiet
from zoeymcp.common.policy.schema import Tools, hash_token
from zoeymcp.common.reviewreport import NAMES_MAX
from zoeymcp.gateway import statuspush
from zoeymcp.vault import statusreport
from zoeymcp.vault.statusreport import (
    REVISION_MAX,
    GatewayStatus,
    Report,
    ServerStatus,
    StatusRefused,
    read,
)

VIEW = "sha256:" + "ab" * 32
A, B, C = ("sha256:" + digit * 64 for digit in "abc")
DEPLOYMENT = "0123456789abcdef" * 2
MAX_TOOLS = 4


def server(**changes: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "kind": "remote",
        "state": ["ready"],
        "blocked": False,
        "era": "modern",
        "included": 2,
        "exposed": 1,
        "marked": [],
        "unreviewed": [],
        "declined_changed": [],
        "drift": [],
        "missing": [],
        "invalid": [],
        "invalid_unnamed": 0,
        "duplicate_unnamed": 0,
        "offered": None,
    }
    return {**entry, **changes}


def report(**changes: Any) -> dict[str, Any]:
    frame: dict[str, Any] = {
        "v": 1,
        "view": VIEW,
        "started": 1_700_000_000,
        "servers": {"notes": server()},
        "witness": {},
        "deployments_seen": 0,
        "policy_mode": "unknown",
    }
    return {**frame, **changes}


def refused(data: Any) -> StatusRefused:
    with pytest.raises(StatusRefused) as caught:
        read(data, MAX_TOOLS)
    return caught.value


# --- the frame ---------------------------------------------------------------------------------


def test_a_report_reads() -> None:
    found = read(report(), MAX_TOOLS)
    assert found == Report(
        view=VIEW,
        started=1_700_000_000,
        servers={"notes": ServerStatus("remote", ("ready",), "modern", 2, 1)},
        policy_mode="unknown",
    )
    assert found.servers["notes"].attention() == Attention()
    assert (found.witness, found.deployments_seen, found.refused_servers) == ({}, 0, ())


def test_the_constants() -> None:
    assert REVISION_MAX == 9_999_999_999
    assert statusreport.WITNESS_DEPLOYMENTS_MAX == 8
    assert statusreport.VERSION == 1


@pytest.mark.parametrize(
    "data",
    [
        [],
        "report",
        None,
        {k: v for k, v in report().items() if k != "witness"},
        report(extra=1),
        report(v=2),
        report(v=True),
        report(v="1"),
        report(view="sha256:" + "A" * 64),
        report(view=None),
        report(started=-1),
        report(started=1.5),
        report(started=True),
        report(deployments_seen=-1),
        report(deployments_seen=2**31),
        report(deployments_seen=False),
        report(policy_mode="other"),
        report(policy_mode=None),
        report(servers=[]),
        report(witness=[]),
        report(witness={"x" * 32: 1}),
        report(witness={DEPLOYMENT.upper(): 1}),
        report(witness={DEPLOYMENT: 0}),
        report(witness={DEPLOYMENT: "1"}),
        report(witness={DEPLOYMENT: True}),
        report(witness={f"{n:032x}": 1 for n in range(9)}),
    ],
)
def test_a_bad_frame_is_refused_whole(data: Any) -> None:
    assert refused(data).reason == "invalid"


def test_the_frame_takes_each_edge() -> None:
    edges = report(
        started=0,
        deployments_seen=2**31 - 1,
        policy_mode="managed",
        witness={f"{n:032x}": REVISION_MAX for n in range(8)},
    )
    found = read(edges, MAX_TOOLS)
    assert (found.started, found.deployments_seen, found.policy_mode) == (0, 2**31 - 1, "managed")
    assert set(found.witness.values()) == {REVISION_MAX}
    assert read(report(policy_mode="declarative", witness={DEPLOYMENT: 1}), MAX_TOOLS).witness == {
        DEPLOYMENT: 1
    }


def test_a_witness_above_revision_max_is_refused_whole() -> None:
    """T-4: a claimed witness of 10^10 is refused at the status reader, so no claim reaches the
    vault's revision counter."""
    caught = refused(report(witness={DEPLOYMENT: 10**10}))
    assert caught.reason == "witness_range"
    assert refused(report(witness={DEPLOYMENT: REVISION_MAX + 1})).reason == "witness_range"
    assert "9,999,999,999" in caught.detail


@pytest.mark.parametrize(
    ("data", "reason", "detail"),
    [
        (
            report(extra=1),
            "invalid",
            "a status report has exactly deployments_seen, policy_mode, servers, started, v, "
            "view, witness",
        ),
        (report(v=2), "invalid", "the status report's version isn't 1"),
        (report(view=None), "invalid", "view must be sha256: and 64 hex digits"),
        (report(started=-1), "invalid", "started must be a whole number of seconds"),
        (report(witness=[]), "invalid", "witness must be an object of at most 8 deployments"),
        (report(witness={DEPLOYMENT: 0}), "invalid", "a witness maps a deployment to a revision"),
        (
            report(witness={DEPLOYMENT: REVISION_MAX + 1}),
            "witness_range",
            "a witness revision is above 9,999,999,999",
        ),
        (report(deployments_seen=-1), "invalid", "deployments_seen must be a count"),
        (
            report(policy_mode="other"),
            "invalid",
            "policy_mode must be managed, declarative or unknown",
        ),
        (report(servers=[]), "invalid", "servers must be an object"),
    ],
)
def test_each_refusal_says_why(data: Any, reason: str, detail: str) -> None:
    """The detail is the vault's 400 answer to the gateway, so each refusal's is its own."""
    caught = refused(data)
    assert (caught.reason, caught.detail, str(caught)) == (reason, detail, detail)


# --- a server on its own (T-7) ------------------------------------------------------------------


def test_bad_name_drops_only_its_entry() -> None:
    """A server listing a tool named "a b" drops only that entry, counted, while another
    server's drift still reads (T-7)."""
    data = report(
        servers={
            "notes": server(drift=["list_notes", "a b"], invalid=["x y", "ok.tool"]),
            "mail": server(drift=["send"], unreviewed=[["new_one", A]]),
        }
    )
    found = read(data, MAX_TOOLS)
    notes, mail = found.servers["notes"], found.servers["mail"]
    assert (notes.drift, notes.invalid, notes.dropped) == (("list_notes",), ("ok.tool",), 2)
    assert notes.unnamed == 2
    assert mail.attention() == Attention(drifted=("send",), new=("new_one",))
    assert mail.dropped == 0


@pytest.mark.parametrize(
    "bad",
    [
        "a b",
        "",
        "x" * 129,
        "sha256:" + "a" * 64,  # a token hash isn't a tool name
        hash_token("zgc1-agent1-token"),
        "é",
        3,
        None,
        ["a"],
    ],
)
def test_each_bad_name_is_dropped_and_counted(bad: Any) -> None:
    for key in statusreport.NAME_LISTS:
        found = read(report(servers={"notes": server(**{key: ["good", bad]})}), MAX_TOOLS)
        entry = found.servers["notes"]
        assert getattr(entry, key) == ("good",), key
        assert entry.dropped == 1, key


def test_a_128_character_name_is_a_name() -> None:
    name = "a" * 128
    assert read(report(servers={"notes": server(drift=[name])}), MAX_TOOLS).servers[
        "notes"
    ].drift == (name,)


@pytest.mark.parametrize(
    "pair",
    [
        ["a b", A],
        ["tool", "sha256:" + "A" * 64],
        ["tool", "sha256:abc"],
        ["tool"],
        ["tool", A, "x"],
        "tool",
        ["tool", None],
        [None, A],
    ],
)
def test_a_bad_unreviewed_pair_is_dropped_and_counted(pair: Any) -> None:
    entry = read(
        report(servers={"notes": server(unreviewed=[["ok", B], pair])}), MAX_TOOLS
    ).servers["notes"]
    assert (entry.unreviewed, entry.dropped) == ((("ok", B),), 1)


def test_every_bad_pair_and_name_is_counted() -> None:
    """Each bad unreviewed pair counts, and adds to the bad names the lists dropped."""
    entry = read(
        report(servers={"notes": server(unreviewed=[["a b", A], "tool"], drift=["x y"])}),
        MAX_TOOLS,
    ).servers["notes"]
    assert (entry.unreviewed, entry.dropped) == ((), 3)


def test_the_unnamed_counts_are_each_their_own() -> None:
    entry = read(
        report(servers={"notes": server(invalid_unnamed=1, duplicate_unnamed=3)}), MAX_TOOLS
    ).servers["notes"]
    assert (entry.invalid_unnamed, entry.duplicate_unnamed, entry.unnamed) == (1, 3, 4)


def test_names_are_sorted_once() -> None:
    entry = read(
        report(servers={"notes": server(marked=["b", "a", "b"], unreviewed=[["z", A], ["y", B]])}),
        MAX_TOOLS,
    ).servers["notes"]
    assert entry.marked == ("a", "b")
    assert entry.unreviewed == (("y", B), ("z", A))


@pytest.mark.parametrize(
    "entry",
    [
        server(definition={"name": "x"}),  # never a definition
        server(token_sha256=hash_token("zgc1-agent1-token")),  # never a token hash
        {k: v for k, v in server().items() if k != "offered"},
        server(kind="bridge"),
        server(kind=[]),  # an unhashable kind or era is a bad server, not a crash
        server(kind={}),
        server(kind=None),
        server(era="auto"),
        server(era=[]),
        server(era={}),
        server(era=1),
        server(blocked=None),
        server(blocked=0),
        server(blocked="false"),
        server(state=[]),
        server(state="ready"),
        server(state=["running"]),
        server(state=[1]),
        server(state=["ready"] * 10),
        server(included=-1),
        server(included=NAMES_MAX + 1),
        server(exposed=NAMES_MAX + 1),
        server(exposed=True),
        server(invalid_unnamed=MAX_TOOLS + 1),
        server(duplicate_unnamed=1.0),
        server(duplicate_unnamed=MAX_TOOLS + 1),
        server(drift="list_notes"),
        server(drift=["t"] * (MAX_TOOLS + 1)),
        server(unreviewed=[["t", A]] * (MAX_TOOLS + 1)),
        server(unreviewed={"t": A}),
        server(offered={"prompts": True}),
        server(offered={"prompts": 1, "resources": False, "completions": False, "logging": False}),
        server(offered=[]),
        [],
    ],
)
def test_a_bad_server_is_refused_alone(entry: Any) -> None:
    found = read(report(servers={"notes": entry, "mail": server()}), MAX_TOOLS)
    assert found.refused_servers == ("notes",)
    assert list(found.servers) == ["mail"]


def test_each_cap_takes_its_edge() -> None:
    full = ["t" + str(n) for n in range(MAX_TOOLS)]
    entry = read(
        report(
            servers={
                "notes": server(
                    drift=full,
                    unreviewed=[[name, A] for name in full],
                    included=MAX_TOOLS,
                    exposed=0,
                    invalid_unnamed=MAX_TOOLS,
                    duplicate_unnamed=MAX_TOOLS,
                    era=None,
                    kind="toolkit",
                    state=sorted(statusreport.STATES),
                    offered={
                        "prompts": True,
                        "resources": False,
                        "completions": True,
                        "logging": False,
                    },
                )
            }
        ),
        MAX_TOOLS,
    ).servers["notes"]
    assert len(entry.drift) == len(entry.unreviewed) == MAX_TOOLS
    assert entry.unnamed == 2 * MAX_TOOLS
    assert (entry.kind, entry.era, entry.state) == (
        "toolkit",
        None,
        tuple(sorted(statusreport.STATES)),
    )
    assert entry.offered == {
        "completions": True,
        "logging": False,
        "prompts": True,
        "resources": False,
    }


def test_the_tool_counts_are_held_to_the_schemas_ceiling() -> None:
    """An include list longer than the running max_tools_per_server (an operator lowered it)
    still reads, so the server's drift and new-tool signal reach health and Home (T-7)."""
    entry = read(
        report(
            servers={
                "notes": server(included=MAX_TOOLS + 1, exposed=NAMES_MAX, drift=["list_notes"])
            }
        ),
        MAX_TOOLS,
    ).servers["notes"]
    assert (entry.included, entry.exposed, entry.drift) == (
        MAX_TOOLS + 1,
        NAMES_MAX,
        ("list_notes",),
    )
    full = read(report(servers={"notes": server(included=NAMES_MAX)}), MAX_TOOLS)
    assert full.servers["notes"].included == NAMES_MAX


def test_blocked_is_the_gateways_word() -> None:
    entry = read(report(servers={"notes": server(blocked=True)}), MAX_TOOLS).servers["notes"]
    assert entry.blocked is True
    assert read(report(), MAX_TOOLS).servers["notes"].blocked is False


def test_a_server_without_a_policy_name_is_counted_not_named() -> None:
    found = read(
        report(servers={"Not A Name": server(), "notes": server(), "-x": server()}), MAX_TOOLS
    )
    assert (list(found.servers), found.unnamed_servers, found.refused_servers) == (
        ["notes"],
        2,
        (),
    )


# --- the attention decision, as the gateway made it (J.5, Y29) ----------------------------------


class Reviewed:
    def __init__(self, include: list[str], review: dict[str, str], declined: dict[str, str]):
        self.tools = Tools(include=include, allow=include)
        self.review = review
        self.declined = declined


def test_the_decision_reads_back_as_the_gateway_made_it() -> None:
    """For a listing in every attention state, the gateway's status report carries the decision
    and the vault's reading of it is the same decision."""
    listed = {"drifted": B, "marked": A, "new": C, "changed": B, "kept": A, "declined": A}
    policy = Reviewed(
        ["drifted", "marked", "kept", "gone"],
        {"drifted": A, "marked": A, "kept": A, "gone": A},
        {"changed": A, "declined": A},
    )
    decided = attention(listed, policy, frozenset({("marked", A)}))
    assert decided == Attention(
        drifted=("drifted",),
        marked=("marked",),
        new=("new",),
        changed_declined=("changed",),
        missing=("gone",),
    )
    status = {
        "view": VIEW,
        "servers": {
            "notes": {
                "kind": "remote",
                "state": ["ready"],
                "era": "modern",
                "included": 4,
                "exposed": 1,
                "reports": {},
                "attention": decided.as_dict(),
                "unreviewed_pins": {"new": C, "changed": B},
                "offered": None,
            }
        },
    }
    document = statuspush.content(status, started=5, max_tools=MAX_TOOLS)
    assert document is not None
    entry = read(copy.deepcopy(document), MAX_TOOLS).servers["notes"]
    assert entry.attention() == decided
    assert entry.unreviewed == (("changed", B), ("new", C))
    assert not quiet(entry.attention())


def test_a_quiet_server_reads_quiet() -> None:
    assert quiet(read(report(), MAX_TOOLS).servers["notes"].attention())


def test_the_gateway_status_holds_the_report_and_its_age() -> None:
    held = GatewayStatus(read(report(), MAX_TOOLS), 3.5)
    assert held.age == 3.5
    assert GatewayStatus(None, 0.0).report is None


# --- the restore witness (K.3; T-4, T-5, Y24) --------------------------------------------------

OLD = "fedcba9876543210" * 2
THIRD = "00112233445566778899aabbccddeeff"


def test_the_witness_keeps_the_order_the_gateway_first_saw() -> None:
    """The gateway sends its deployments first seen first (gateway/witness.py); the vault keeps
    that order, which ``policy_deployment_changed`` reads."""
    given = {OLD: 31, DEPLOYMENT: 1, THIRD: 2}
    found = read(report(witness=given), MAX_TOOLS)
    assert list(found.witness) == [OLD, DEPLOYMENT, THIRD]
    assert list(read(report(witness={THIRD: 2, OLD: 31}), MAX_TOOLS).witness) == [THIRD, OLD]


@pytest.mark.parametrize(
    ("witness", "head", "claim", "behind", "target"),
    [
        ({}, 27, None, False, None),
        ({DEPLOYMENT: 26}, 27, 26, False, None),
        ({DEPLOYMENT: 27}, 27, 27, False, None),
        ({DEPLOYMENT: 28}, 27, 28, True, 29),
        ({DEPLOYMENT: 31}, 27, 31, True, 32),
        ({DEPLOYMENT: REVISION_MAX}, 1, REVISION_MAX, True, REVISION_MAX + 1),
    ],
)
def test_the_head_behind_the_witness(
    witness: dict[str, int], head: int, claim: int | None, behind: bool, target: int | None
) -> None:
    """J11: the gateway has applied a revision of this deployment above the head (the whole
    ``/state`` put back); the acknowledgment's number is one above the claim (T-4: up to one
    above REVISION_MAX, which the write refuses)."""
    found = statusreport.witnessed(witness, DEPLOYMENT, head)
    assert (found.claim, found.behind, found.other, found.target) == (claim, behind, None, target)


@pytest.mark.parametrize(
    ("witness", "head", "other"),
    [
        # /state wiped whole: a new deployment at 1 after the old one at 31 (T-5).
        ({OLD: 31, DEPLOYMENT: 1}, 1, (OLD, 31)),
        # Not seen yet by the gateway: still raised at revision 1, and after a later one.
        ({OLD: 31}, 1, (OLD, 31)),
        ({OLD: 31}, 5, (OLD, 31)),
        # Seen after it, the head grown since, still not past it.
        ({OLD: 31, DEPLOYMENT: 5}, 5, (OLD, 31)),
        ({OLD: 31, DEPLOYMENT: 31}, 31, (OLD, 31)),
        # Past it: an acknowledged restore jumped to 32.
        ({OLD: 31, DEPLOYMENT: 32}, 32, None),
        # The other deployment never got past revision 1: a seed alone, nothing undone.
        ({OLD: 1, DEPLOYMENT: 1}, 1, None),
        ({OLD: 2, DEPLOYMENT: 1}, 1, (OLD, 2)),
        # Seen before the other one, and past revision 1: the gateway moved, not this vault.
        ({DEPLOYMENT: 5, OLD: 31}, 5, None),
        ({DEPLOYMENT: 2, OLD: 31}, 2, None),
        # ... but at revision 1 it is raised whichever came first.
        ({DEPLOYMENT: 1, OLD: 31}, 1, (OLD, 31)),
        ({DEPLOYMENT: 1, OLD: 2}, 1, (OLD, 2)),
        # Of several, the highest claim; one this deployment came before doesn't count.
        ({OLD: 31, THIRD: 40, DEPLOYMENT: 3}, 3, (THIRD, 40)),
        ({OLD: 31, DEPLOYMENT: 3, THIRD: 40}, 3, (OLD, 31)),
        ({OLD: 40, THIRD: 40, DEPLOYMENT: 3}, 3, (OLD, 40)),
    ],
)
def test_another_deployment_seen_before_this_one(
    witness: dict[str, int], head: int, other: tuple[str, int] | None
) -> None:
    """T-5: another deployment at revision 2 or more, not passed by this one's head, which was
    first seen after it (or is at revision 1): ``policy_deployment_changed``."""
    found = statusreport.witnessed(witness, DEPLOYMENT, head)
    assert found.other == other
    assert found.target == (None if other is None else other[1] + 1)


def test_the_target_passes_every_claim_that_raises_a_finding() -> None:
    both = statusreport.witnessed({OLD: 31, DEPLOYMENT: 40}, DEPLOYMENT, 20)
    assert (both.behind, both.other, both.target) == (True, (OLD, 31), 41)
    higher = statusreport.witnessed({OLD: 50, DEPLOYMENT: 40}, DEPLOYMENT, 20)
    assert higher.target == 51
    assert statusreport.Witnessed().target is None
    assert statusreport.Witnessed(claim=9, behind=False).target is None
