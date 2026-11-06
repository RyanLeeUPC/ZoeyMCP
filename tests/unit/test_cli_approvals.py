"""``zoeymcp approvals`` and ``zoeymcp approver telegram`` over the admin socket (M8 design K.3,
G.8, J1, J15; step 16).

A real vault app holds calls as ``tests/gateway/holdrig.py`` builds it, with the fake Bot API
(``tests/fakes/telegram.py``) on an ASGI transport, and its admin socket is served to the CLI in
process on a portal's loop (``test_admin_policy.serve``). Holds are begun in its hold table, as a
held call begins one:

- ``approvals list``: waiting, oldest first, and decided recently, each by both identifiers (the
  ref and the approval id), the deciding surface named, never a text;
- ``approvals show``: by either identifier, the same hold and its whole text; a hold that ended
  or never was, refused by the catalogue's sentence;
- ``approvals withdraw``: by either identifier, as the host's (via ``host`` on the chain, detail
  ``operator``); a withdrawn or approved hold refused by how it ended; ``--all`` (J15's
  emergency stop) withdraws every one, in J15's words;
- ``approver telegram enrol``: J1's transcript, the operator pressing Start and the host typing
  the code the phone shows; an enrolment a CLI lost, offered to the host to stop; ``approver
  telegram test``: the probe;
- ``--format json`` on every command (D-171, K.3).
"""

from __future__ import annotations

import io
import json
import re
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, TextIO

import httpx
import pytest
from anyio.from_thread import BlockingPortal, start_blocking_portal

from tests.fakes.telegram import BotApi, Person
from tests.gateway.holdrig import BOT_TOKEN, KEYS, OPERATOR_ID, HoldRig
from tests.gateway.rig import until
from zoeymcp.cli import admin_client
from zoeymcp.cli import approver as approver_cli
from zoeymcp.cli import main as main_module
from zoeymcp.cli.main import main
from zoeymcp.common.approvaltext import ApprovalText
from zoeymcp.portal.approvalsview import utc
from zoeymcp.vault.admin import AdminApp, SetupCodes
from zoeymcp.vault.app import START_FINDINGS_SECONDS
from zoeymcp.vault.approvers import SurfaceName
from zoeymcp.vault.holds import Hold, HoldRequest
from zoeymcp.vault.telegram import PROBE, Timings
from zoeymcp.vault.vaultledger import Start

from .test_admin_policy import PolicyRig, serve

BOUND = 30
TEXT = 'Approval request 3f9c0a17b2d4e681\nTool: shop -> place_order\n\n{\n  "qty": 2\n}'
DIGEST = "a" * 64
REFS = ("3f9c0a17b2d4e681", "9a01c4e2d7b35f60", "77e1b0c93a5d2f48")
OPERATOR = Person(OPERATOR_ID, "Operator", "operator_example")
TIMINGS = Timings(send_spacing=0.05, contested_backoff=0.3, backoff_max=0.2, poll_timeout=1)
CODE = re.compile(r"\?start=([A-Za-z0-9_-]{22})")
WITHDRAWN = "zoeymcp approvals: This approval was withdrawn, so nothing was sent.\n"


@pytest.fixture
def portal() -> Iterator[BlockingPortal]:
    with start_blocking_portal() as found:
        yield found


class Rig:
    """The vault app and its socket, served to the CLI on ``portal``'s loop."""

    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        portal: BlockingPortal,
        *,
        surfaces: tuple[SurfaceName, ...] = ("portal",),
    ) -> None:
        self.api = BotApi(BOT_TOKEN, second=0.05, flood_interval=None, operator_account=OPERATOR)
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.api.app()))
        self.hold = HoldRig(
            tmp_path,
            link="asgi",
            surfaces=surfaces,
            telegram=TIMINGS,
            approver_client=client,
        )
        self.portal = portal
        self.vault = self.hold.app
        admin = AdminApp(
            self.hold.store,
            KEYS,
            lambda: self.vault.policy,
            SetupCodes(tmp_path, KEYS.portal_key),
            chain=self.hold.chain,
            holds=self.vault,
            approvals=self.vault,
        )
        serve(monkeypatch, lambda: admin.app, portal)
        portal.call(self.vault.start_approvers)

    def begin(self, ref: str, **fields: Any) -> Hold:
        """A hold begun as a held call begins one, shown on the portal's queue."""
        found = self.portal.call(
            lambda: self.vault.holds.begin(self.hold.clock(), request(ref, **fields))
        )
        assert isinstance(found, Hold), found
        return found

    def settle(self) -> None:
        """Every ending begun so far written and told."""
        self.portal.call(self.vault.settle)

    def close(self) -> None:
        self.portal.call(self.vault.stop_approvers)


def request(
    ref: str,
    *,
    client: str = "agent1",
    tool: str = "place_order",
    surfaces: frozenset[Any] = frozenset({"portal"}),
) -> HoldRequest:
    return HoldRequest(
        ref=ref,
        kind="held",
        epoch="0123456789ab",
        legacy_session=False,
        route="shop",
        server="shop",
        tool=tool,
        client=client,
        args_digest="sha256:" + "c" * 64,
        text=ApprovalText(TEXT, frozenset(), ((0, None),)),
        text_sha256=DIGEST,
        surfaces=surfaces,
        wait="pending",
        held_bytes=100,
    )


def run_cli(argv: list[str], stdin: io.StringIO | None = None) -> tuple[int, str, str]:
    """``zoeymcp <argv>``: its exit code, stdout and stderr."""
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=stdin or io.StringIO(), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def at(rig: Rig, when: float) -> str:
    return utc(rig.vault.hold_wall(when))


# --- approvals list, show, withdraw ---------------------------------------------------------------


def test_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal) -> None:
    """K.3: waiting, oldest first, each by its ref and its approval id with its call, client and
    times, and "not delivered to Telegram" for a prompt Telegram didn't take; then decided
    recently, the deciding surface named (no "here" on the host); never a text."""
    rig = Rig(tmp_path, monkeypatch, portal)
    first = rig.begin(REFS[0])
    both = frozenset({"portal", "telegram"})
    second = rig.begin(REFS[1], client="agent2", surfaces=both)
    denied = rig.begin(REFS[2], tool="cancel_order")
    portal.call(rig.vault.decide, denied.id, "deny", "portal", DIGEST)
    rig.settle()
    code, out, err = run_cli(["approvals"])
    assert (code, err) == (0, "")
    when = rig.vault.holds.ending(REFS[2])
    assert when is not None
    assert when.decided_at is not None
    hhmm = at(rig, when.decided_at)[11:16]
    assert out.splitlines() == [
        "Waiting (2):",
        f"  {REFS[0]}  {first.id}  shop.place_order  client agent1  asked "
        f"{at(rig, first.asked_at)}  answer by {at(rig, first.deadline)}",
        f"  {REFS[1]}  {second.id}  shop.place_order  client agent2  asked "
        f"{at(rig, second.asked_at)}  answer by {at(rig, second.deadline)}  "
        "(not delivered to Telegram)",
        "Decided recently (1):",
        f"  {REFS[2]}  {denied.id}  shop.cancel_order  client agent1  denied in the portal "
        f"{hhmm} UTC; nothing was sent",
    ]
    code, out, _ = run_cli(["approvals", "list", "--format", "json"])
    listed = json.loads(out)
    # D14: list is the default, and the command takes --format and --socket for it.
    assert run_cli(["approvals", "--format", "json"]) == (0, out, "")
    assert run_cli(["approvals", "--format", "json", "list"]) == (0, out, "")
    assert [(r["ref"], r["approval"]) for r in listed["waiting"]] == [
        (REFS[0], first.id),
        (REFS[1], second.id),
    ]
    assert [(r["ref"], r["state"]) for r in listed["decided"]] == [(REFS[2], "denied")]
    assert "Approval request" not in out
    rig.close()


def test_list_clears_what_the_start_withdrew(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """K.1, J10 (step 16's deviation 9): health shows ``approvals_withdrawn_at_start`` until
    the host lists the approvals, and ``approvals_outcome_unknown`` on; 24 hours after the start,
    neither."""
    rig = Rig(tmp_path, monkeypatch, portal)
    rig.hold.chain.start = Start(withdrawn=2, outcome_unknown=(REFS[0],))

    def found() -> dict[str, str]:
        code, out, _ = run_cli(["health", "--json"])
        assert code in (0, 1)
        report = json.loads(out)["approvals"]
        return {
            f["code"]: f["text"] for f in report["findings"] if f["code"].startswith("approvals_")
        }

    before = found()
    assert list(before) == ["approvals_withdrawn_at_start", "approvals_outcome_unknown"]
    assert "withdrew 2 approval(s)" in before["approvals_withdrawn_at_start"]
    assert f"(refs {REFS[0]})" in before["approvals_outcome_unknown"]
    assert run_cli(["approvals", "list"])[0] == 0
    assert list(found()) == ["approvals_outcome_unknown"]
    rig.hold.clock.ahead += START_FINDINGS_SECONDS
    assert found() == {}
    rig.close()


def test_show_by_either_identifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """K.3, OPS-12, Z14: 16 lowercase hex digits is a ref, anything else an approval id; either
    shows the same hold, its whole text last, line by line. One that ended is told how; one that
    never was, unknown."""
    rig = Rig(tmp_path, monkeypatch, portal)
    hold = rig.begin(REFS[0])
    by_ref, by_id = run_cli(["approvals", "show", REFS[0]]), run_cli(["approvals", "show", hold.id])
    assert by_ref == by_id
    code, out, err = by_ref
    assert (code, err) == (0, "")
    assert out.splitlines() == [
        f"ref {REFS[0]}  approval {hold.id}",
        "shop.place_order  client agent1  Held by the vault  state waiting",
        f"asked {at(rig, hold.asked_at)}  answer by {at(rig, hold.deadline)}",
        "surfaces: portal",
        "",
        *TEXT.split("\n"),
    ]
    code, out, _ = run_cli(["approvals", "show", REFS[0], "--format", "json"])
    shown = json.loads(out)
    assert (shown["text"], shown["text_sha256"], shown["approval"]) == (TEXT, DIGEST, hold.id)
    code, out, err = run_cli(["approvals", "show", "ffffffffffffffff"])
    assert (code, out) == (1, "")
    assert err.startswith("zoeymcp approvals: No approval by that ID waits")
    run_cli(["approvals", "withdraw", hold.id])
    rig.settle()
    code, _, err = run_cli(["approvals", "show", REFS[0]])
    assert (code, err) == (1, WITHDRAWN)
    rig.close()


def test_withdraw_by_either_identifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """K.3, B.5: a hold withdrawn by its ref or its approval id, as the host's: its chain records
    ``decided withdrawn`` via host, its ending says the operator; nothing is sent. Withdrawn
    again, or already approved, it is refused by how it ended."""
    rig = Rig(tmp_path, monkeypatch, portal)
    first = rig.begin(REFS[0])
    second = rig.begin(REFS[1], client="agent2")
    approved = rig.begin(REFS[2], tool="cancel_order")
    code, out, err = run_cli(["approvals", "withdraw", REFS[0]])
    assert (code, err) == (0, "")
    # The whole ref, to paste into approvals show (D20), in a sentence (D8).
    said = f"Withdrew 1 approval ({REFS[0]}): nothing was sent; its message was edited.\n"
    assert out == said
    code, out, _ = run_cli(["approvals", "withdraw", second.id, "--format", "json"])
    assert json.loads(out) == {
        "withdrawn": [
            {"approval": second.id, "ref": REFS[1], "server": "shop", "tool": "place_order"}
        ]
    }
    rig.settle()
    ending = rig.vault.holds.ending(REFS[0])
    assert ending is not None
    assert (ending.state, ending.via, ending.detail) == ("withdrawn", "host", "operator")
    decided = [r.fields for r in rig.hold.records() if r.kind == "decided" and r.ref == REFS[0]]
    assert [(f["decision"], f["via"]) for f in decided] == [("withdrawn", "host")]
    # Recorded as every withdrawal is (B.5): not sent, the detail changed.
    ended = [r.fields for r in rig.hold.records() if r.kind == "outcome" and r.ref == REFS[0]]
    assert [(f["outcome"], f["detail"]) for f in ended] == [("not_sent", "changed")]
    code, _, err = run_cli(["approvals", "withdraw", first.id])
    assert (code, err) == (1, WITHDRAWN)
    now = rig.hold.clock()
    portal.call(lambda: rig.vault.holds.decide(now, approved.id, "approve", "portal", DIGEST))
    code, _, err = run_cli(["approvals", "withdraw", REFS[2]])
    assert code == 1
    assert re.fullmatch(
        r"zoeymcp approvals: Already decided in the portal at \d\d:\d\d UTC: approved\.\n", err
    )
    assert rig.hold.upstream.received == []
    rig.close()


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (["approvals", "withdraw"], "give a ref or an approval id, or --all"),
        (
            ["approvals", "withdraw", REFS[0], "--all"],
            "give a ref or an approval id, or --all, not both",
        ),
    ],
    ids=["neither", "both"],
)
def test_withdraw_takes_one_identifier_or_all(argv: list[str], said: str) -> None:
    # A usage error exits 2, as every command's does (D2).
    assert run_cli(argv) == (2, "", f"zoeymcp approvals withdraw: {said}\n")


def test_withdraw_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """J15: ``withdraw --all`` withdraws every hold waiting, in J15's words; the list is then
    empty of waiting holds and shows each withdrawn by the operator; again, nothing waits."""
    rig = Rig(tmp_path, monkeypatch, portal)
    rig.begin(REFS[0])
    rig.begin(REFS[1], client="agent2")
    rig.begin(REFS[2], tool="cancel_order")
    code, out, err = run_cli(["approvals", "withdraw", "--all"])
    assert (code, err) == (0, "")
    assert out == (
        f"Withdrew 3 approvals ({', '.join(REFS)}): nothing was sent; their messages were edited.\n"
    )
    rig.settle()
    _, out, _ = run_cli(["approvals", "list", "--format", "json"])
    listed = json.loads(out)
    assert listed["waiting"] == []
    assert all("withdrawn by the operator" in r["outcome_shown"] for r in listed["decided"])
    assert len(listed["decided"]) == 3
    assert run_cli(["approvals", "withdraw", "--all"]) == (
        0,
        "Nothing was waiting: no approval withdrawn.\n",
        "",
    )
    rig.close()


# --- approver telegram enrol and test (G.8, J1) ---------------------------------------------------


async def press_start(api: BotApi, said: list[io.StringIO]) -> None:
    """The operator opens the link the CLI printed and presses Start, once the enrolment polls
    for messages."""
    await until(lambda: any(CODE.search(stream.getvalue()) for stream in said), BOUND)
    await until(lambda: any(poll.allowed_updates == ["message"] for poll in api.polls), BOUND)
    [found] = [m for stream in said if (m := CODE.search(stream.getvalue()))]
    api.operator.start(found.group(1))


def enrol(
    rig: Rig, argv: list[str], stdin: str = "", answers: Sequence[str | None] = (None,)
) -> tuple[int, str, str]:
    """``zoeymcp <argv>`` as ``main`` parses it, the host typing ``answers`` in turn at the code's
    prompt (``None``: the code the operator's phone shows; not a terminal), and ``stdin`` for
    anything else it asks."""
    out, err = io.StringIO(), io.StringIO()
    rig.portal.start_task_soon(press_start, rig.api, [out, err])
    args = main_module._build_parser().parse_args(argv)
    phone = rig.api.operator
    left = list(answers)

    def typed(_stdin: TextIO) -> str:
        answer = left.pop(0)
        return phone.confirmation_code() if answer is None else answer

    code = approver_cli.run(args, io.StringIO(stdin), out, err, typed=typed)
    return code, out.getvalue(), err.getvalue()


def test_enrol(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal) -> None:
    """J1 step 3 (declarative, without --apply): the allowance, the bot, the one-time link,
    who pressed Start, the confirmation code typed, then the policy lines and the reload
    step. The code is in the link alone."""
    rig = Rig(tmp_path, monkeypatch, portal)
    code, out, err = enrol(rig, ["approver", "telegram", "enrol", "--secret", "approver-bot"])
    assert code == 0
    found = CODE.search(err)
    assert found is not None
    # The transcript and its prompts on stderr; the lines to add, the answer, on stdout (D10).
    assert out.splitlines() == [
        "approvers:",
        f"  telegram: {{bot_token: store:approver-bot, user_id: {OPERATOR_ID}, "
        f"chat_id: {OPERATOR_ID}}}",
        "  timeout: 3600",
        "  block_seconds: 120",
    ]
    assert err.splitlines() == [
        "Opened a temporary egress allowance: api.telegram.org:443 (approver, 10 minutes).",
        "The bot is @example_bot. On the phone you'll approve from, open this link and press Start",
        f"(it works once, for 10 minutes): https://t.me/example_bot?start={found.group(1)}",
        "Waiting for /start ... (Ctrl-C to stop)",
        f'Seen: user {OPERATOR_ID} ("Operator", @operator_example) in its private chat '
        f"{OPERATOR_ID}.",
        "The bot sent that chat a confirmation code. Type it here: ",
        "Confirmed.",
        *approver_cli.reload_lines(admin_client.Prefix.for_role("vault")),
    ]
    assert (out + err).count(found.group(1)) == 1
    rig.close()


def test_enrol_apply_in_declarative_mode_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """D17: --apply in declarative mode isn't ignored in silence: one line says it applies only
    in managed mode, then the lines and the reload step as without it."""
    rig = Rig(tmp_path, monkeypatch, portal)
    argv = ["approver", "telegram", "enrol", "--secret", "approver-bot", "--apply"]
    code, out, err = enrol(rig, argv)
    assert (code, out.startswith("approvers:\n")) == (0, True)
    assert err.splitlines()[-3:] == [
        "Confirmed.",
        "--apply only applies in managed mode; this deployment is declarative.",
        *approver_cli.reload_lines(admin_client.Prefix.for_role("vault")),
    ]
    rig.close()


def test_the_reload_step_names_the_reload() -> None:
    """D4: the reload as typed on the host, not prose."""
    assert approver_cli.reload_lines(admin_client.Prefix()) == [
        "Add these lines to the policy, then check it and reload the vault: docker compose -f "
        "deploy/compose.hardened.yaml kill -s HUP vault (managed: run this again with --apply, "
        "or export, edit and import). The reload starts the approver."
    ]


def test_what_cant_be_a_code_is_asked_again_unsent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """D-252: what isn't six digits (a paste that reached the hidden prompt as one character,
    the code with a space in it) is asked for again and never sent, so it doesn't end the
    enrolment; the code then typed enrols."""
    rig = Rig(tmp_path, monkeypatch, portal)
    argv = ["approver", "telegram", "enrol", "--secret", "approver-bot"]
    code, _, err = enrol(rig, argv, answers=["t", "123 456", None])
    assert code == 0
    lines = err.splitlines()
    prompt = lines.index("The bot sent that chat a confirmation code. Type it here: ")
    assert lines[prompt + 1 : prompt + 4] == [approver_cli.NOT_A_CODE] * 2 + ["Confirmed."]
    rig.close()


def test_after_five_reads_the_last_is_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """D-252's bound: the code is read at most five times, and the fifth is sent whatever it is,
    so a closed standard input ends the enrolment as a wrong code (``enrolment_unconfirmed``)."""
    rig = Rig(tmp_path, monkeypatch, portal)
    argv = ["approver", "telegram", "enrol", "--secret", "approver-bot"]
    code, out, err = enrol(rig, argv, answers=[""] * approver_cli.ASKS)
    assert (code, out) == (1, "")
    assert err.count(approver_cli.NOT_A_CODE) == approver_cli.ASKS - 1
    assert "wasn't the one the bot sent" in err
    rig.close()


def test_a_lost_enrolment_can_be_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """An enrolment a CLI lost (a Ctrl-C while it opened, a closed session) leaves another one
    open: ``enrolment_busy`` names it and when it ends by itself, and the CLI offers to stop it.
    Declined, nothing changes; accepted, it is stopped and the new one opens."""
    rig = Rig(tmp_path, monkeypatch, portal)
    lost, _ = portal.call(rig.vault.enrol, "approver-bot")
    argv = ["approver", "telegram", "enrol", "--secret", "approver-bot"]
    asked = (
        "Another enrolment is open: finish it, or stop it first. It ends by itself at "
        f"{utc(lost.expires)}. Stop it now? [y/N] "
    )
    args = main_module._build_parser().parse_args(argv)
    said, why = io.StringIO(), io.StringIO()
    code = approver_cli.run(args, io.StringIO("n\n"), said, why)
    assert (code, said.getvalue()) == (1, "")
    assert why.getvalue() == asked + "\n" + (
        "zoeymcp approver telegram enrol: Another enrolment is open: finish it, or stop it first.\n"
    )
    assert lost.open
    code, out, err = enrol(rig, argv, stdin="y\n")
    assert (code, out.startswith("approvers:\n")) == (0, True)
    assert err.startswith(asked + "\nStopped it.\nOpened a temporary egress allowance")
    assert (lost.state, lost.reason) == ("ended", "enrolment_expired")
    assert (
        err.splitlines()[-1] == approver_cli.reload_lines(admin_client.Prefix.for_role("vault"))[-1]
    )
    rig.close()


def test_the_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal) -> None:
    """G.8: ``approver telegram test`` exits 0 once Telegram took the probe; with no Telegram
    approver it is refused, exit 1."""
    rig = Rig(tmp_path / "on", monkeypatch, portal, surfaces=("portal", "telegram"))
    portal.call(until, lambda: len(rig.api.polls) >= 3, BOUND)
    assert run_cli(["approver", "telegram", "test"]) == (
        0,
        "Sent: the test message reached the chat.\n",
        "",
    )
    assert [m.text for m in rig.api.operator.messages()] == [PROBE]
    rig.close()
    rig = Rig(tmp_path / "off", monkeypatch, portal)
    code, out, err = run_cli(["approver", "telegram", "test"])
    assert (code, out) == (1, "")
    assert err.startswith("zoeymcp approver telegram test: The policy names no Telegram approver")
    rig.close()


def test_with_telegram_keeps_the_rest_of_the_export() -> None:
    """G.8 step 5's import: the head's export with ``approvers.telegram`` the enrolment's, the
    rest of the approvers block and the document kept."""
    document = {"version": 1, "mode": "managed", "approvers": {"portal": {}, "timeout": 600}}
    confirmed = {"secret": "approver-bot", "seen": {"user_id": 5, "chat_id": 5}}
    assert approver_cli.with_telegram(document, confirmed) == {
        "version": 1,
        "mode": "managed",
        "approvers": {
            "portal": {},
            "timeout": 600,
            "telegram": {"bot_token": "store:approver-bot", "user_id": 5, "chat_id": 5},
        },
    }
    assert "telegram" not in str(document)  # the export itself is unchanged


# --- enrol --apply in managed mode (G.8 step 5; step 16's deviation 4, tested in step 18) ---------

SEEN = {"user_id": OPERATOR_ID, "chat_id": OPERATOR_ID, "name": "Operator", "username": None}
LINES = [
    "approvers:",
    f"  telegram: {{bot_token: store:approver-bot, user_id: {OPERATOR_ID}, "
    f"chat_id: {OPERATOR_ID}}}",
    "  timeout: 3600",
    "  block_seconds: 120",
]


@pytest.mark.parametrize("answer", ["y", "n"], ids=["yes", "no"])
def test_enrol_apply_in_managed_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal, answer: str
) -> None:
    """G.8 step 5, J1 managed: after "Confirmed." the lines, then a host import of the head's
    export with ``approvers.telegram`` the enrolment's, planned over the socket and shown, then
    ``[y/N]``: yes imports it (a widening the host confirmed, so accepted), no writes nothing.
    The managed vault and its socket are real (``check`` admits ``approvers``, which until step
    18 it refused); the enrolment's own answers are the vault's, stood in for (``test_enrol``
    walks them against the fake Bot API)."""
    rig = PolicyRig(tmp_path)
    serve(monkeypatch, lambda: rig.admin.app, portal)
    opened = {
        "enrolment": "e" * 22,
        "state": "seen",
        "allowance": "api.telegram.org:443",
        "bot": "example_bot",
        "link": "https://t.me/example_bot?start=" + "c" * 22,
        "seen": SEEN,
    }
    confirmed = {"state": "confirmed", "secret": "approver-bot", "seen": SEEN, "lines": LINES}
    monkeypatch.setattr(admin_client, "telegram_enrol", lambda socket, secret: opened)
    monkeypatch.setattr(admin_client, "telegram_confirm", lambda socket, enrolment, code: confirmed)
    argv = ["approver", "telegram", "enrol", "--secret", "approver-bot", "--apply"]
    args = main_module._build_parser().parse_args(argv)
    out, err = io.StringIO(), io.StringIO()
    code = approver_cli.run(args, io.StringIO(f"{answer}\n"), out, err, typed=lambda _: "123456")
    # The plan and its question are the transcript, on stderr (D10); stdout stays empty.
    assert out.getvalue() == ""
    said = err.getvalue().splitlines()
    assert said[said.index("Confirmed.") + 1 :][: len(LINES) + 1] == [
        *LINES,
        "Planned on revision 1:",
    ]
    assert "  Revision: 2, from 1" in said
    assert any(line.startswith("  approvers") for line in said)
    asked = "Apply as a host import? [y/N] "
    managed = rig.vault.managed
    if answer == "y":
        assert code == 0
        assert said[-1] == asked + "Imported revision 2: the approver starts now."
        assert managed.revision == 2
        approvers = managed.policy.approvers
        assert approvers is not None
        assert approvers.telegram is not None
        assert (approvers.telegram.bot_token, approvers.telegram.user_id) == (
            "store:approver-bot",
            OPERATOR_ID,
        )
    else:
        assert code == 1
        assert said[-1] == asked + "Nothing written."
        assert managed.revision == 1
        assert managed.policy.approvers is None


# --- --format on every command (D-171, K.3) -------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "key"),
    [
        (["approvals", "list"], "waiting"),
        (["approvals", "show", REFS[0]], "text"),
        (["approvals", "withdraw", REFS[0]], "withdrawn"),
        (["approvals", "withdraw", "--all"], "withdrawn"),
        (["approver", "telegram", "test"], "sent"),
        (["approver", "telegram", "enrol", "--secret", "approver-bot"], "lines"),
    ],
    ids=["list", "show", "withdraw", "withdraw-all", "test", "enrol"],
)
def test_every_command_takes_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    portal: BlockingPortal,
    argv: list[str],
    key: str,
) -> None:
    """Each new command takes ``--format json``: its answer as JSON on stdout (an enrolment's
    transcript on stderr), and ``text`` by default."""
    rig = Rig(tmp_path, monkeypatch, portal, surfaces=("portal", "telegram"))
    rig.begin(REFS[0])
    portal.call(until, lambda: len(rig.api.polls) >= 3, BOUND)
    command = [*argv, "--format", "json"]
    if argv[1] == "telegram" and argv[2] == "enrol":
        code, out, _ = enrol(rig, command)
    else:
        code, out, _ = run_cli(command)
    assert code == 0
    assert key in json.loads(out)
    rig.close()
