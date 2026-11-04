"""``zoeymcp approver telegram``: enrol the Telegram approver, and probe it (M8 design G.8). I/O.

Over the vault's admin socket, as the host (no step-up kind: host authority, like every
``approvers`` change):

- ``approver telegram enrol --secret NAME [--apply]``: the vault opens the enrolment's own Bot API
  session with the store secret ``NAME`` and a temporary egress allowance, and the CLI prints the
  ``t.me`` link with the one-time code (10 minutes, once). It waits for ``/start``, prints who
  pressed Start, and asks for the confirmation code the bot sent that chat (T-12): a mismatch or a
  timeout stops the enrolment and nothing is printed or applied. Then it prints the policy lines.
  With ``--apply`` in managed mode it plans a host import of the head's export with
  ``approvers.telegram`` set, shows the plan and asks ``[y/N]``; without ``--apply``, or in
  declarative mode, it prints the lines and the reload step. Nothing is saved before the host
  confirms. Ctrl-C stops the enrolment. Another enrolment open (``enrolment_busy``: perhaps
  one a Ctrl-C or a closed session left behind) is offered to the host to stop, by the id its
  refusal names; else it ends by itself within 10 minutes.
- ``approver telegram test``: the probe, a message with no buttons; exit 0 when Telegram took it,
  1 with the finding that says why not (G.7), so a verify script can run it unattended.

Both take ``--format text|json`` (D-171): with ``json`` the transcript goes to stderr and the
answer to stdout. Every string from the vault or Telegram (a display name) goes out through
``review.write_lines``, which shows control characters as text.
"""

from __future__ import annotations

import argparse
import getpass
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final, TextIO

import yaml

from ..common.yamlload import load_mapping
from ..portal.approvalsview import utc
from ..portal.refusals import refusal
from . import admin_client
from . import review as review_view

EXIT_OK: Final = 0
EXIT_REFUSED: Final = 1
# One long poll of the enrolment's state, in seconds (the vault's cap is 60).
WAIT: Final = 50
# The bot's confirmation code is six ASCII digits (the vault's CONFIRM_DIGITS). Anything else
# can't be it, so it is asked for again, unsent, up to ASKS reads in all (D-252): a paste that
# never reached the hidden prompt would otherwise end the enrolment as a wrong code does.
CONFIRM_SHAPE: Final = re.compile(r"[0-9]{6}")
ASKS: Final = 5
NOT_A_CODE: Final = (
    "That isn't six digits, so it wasn't sent. Type the code the bot sent (a paste may not reach "
    "this hidden prompt): "
)
ALLOWANCE: Final = "Opened a temporary egress allowance: {allowance} (approver, 10 minutes)."
FINDINGS: Final[Mapping[str, str]] = {
    "approver_token_missing": "the bot's token isn't in the store",
    "approver_token_shared": "another secret holds the bot's token or the same bot",
    "approver_chat_unreachable": "Telegram refused the message: start the chat with the bot",
    "approver_unreachable": "Telegram didn't take the message: check the egress allowlist",
    "approver_rate_limited": "Telegram's flood control is slowing the bot: try again later",
}


def run(
    args: argparse.Namespace,
    stdin: TextIO,
    out: TextIO,
    err: TextIO,
    *,
    typed: Callable[[TextIO], str] | None = None,
) -> int:
    """``zoeymcp approver telegram enrol|test``. ``typed`` reads the confirmation code (a hidden
    prompt at a terminal; tests pass their own)."""
    socket = admin_client.socket_path(args.socket)
    try:
        if args.action == "test":
            return _test(args, socket, out)
        return _enrol(args, socket, stdin, out, err, typed or read_code)
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp approver telegram {args.action}: {exc}\n")
        return EXIT_REFUSED


def read_code(stdin: TextIO) -> str:
    """The confirmation code: hidden at a terminal, else a line of standard input."""
    if stdin.isatty():
        return getpass.getpass("")
    return stdin.readline().strip()


def _ask_code(stdin: TextIO, said: TextIO, typed: Callable[[TextIO], str]) -> str:
    """The confirmation code, after its prompt: read again, unsent, while it isn't six digits,
    at most :data:`ASKS` reads; the last is sent whatever it is, for the vault to judge."""
    asked = 0
    while True:
        said.flush()
        code = typed(stdin).strip()
        asked += 1
        if not stdin.isatty():
            said.write("\n")  # at a terminal, the line ends with the code typed
        if CONFIRM_SHAPE.fullmatch(code) or asked >= ASKS:
            return code
        said.write(NOT_A_CODE)


def _test(args: argparse.Namespace, socket: str, out: TextIO) -> int:
    answer = admin_client.telegram_test(socket)
    if args.format == "json":
        review_view.write_json(answer, out)
    elif answer["sent"]:
        out.write("sent: the test message reached the chat\n")
    else:
        finding = str(answer["finding"])
        why = FINDINGS.get(finding, finding)
        review_view.write_lines([f"not sent ({finding}): {why}"], out)
    return EXIT_OK if answer["sent"] else EXIT_REFUSED


def _enrol(
    args: argparse.Namespace,
    socket: str,
    stdin: TextIO,
    out: TextIO,
    err: TextIO,
    typed: Callable[[TextIO], str],
) -> int:
    said = err if args.format == "json" else out  # the transcript
    opened: Mapping[str, Any] | None = None
    try:
        try:
            opened = admin_client.telegram_enrol(socket, args.secret)
        except admin_client.AdminUnavailable as exc:
            if exc.reason != "enrolment_busy" or not _stop_busy(exc, socket, stdin, said):
                raise
            opened = admin_client.telegram_enrol(socket, args.secret)
        enrolment = str(opened["enrolment"])
        review_view.write_lines(opening_lines(opened), said)
        said.flush()
        state = opened
        while state["state"] == "waiting":
            state = admin_client.telegram_enrolment(socket, enrolment, wait=WAIT)
        if state["state"] != "seen":
            err.write(f"zoeymcp approver telegram enrol: {_refused(state)}\n")
            return EXIT_REFUSED
        review_view.write_lines(seen_lines(state["seen"]), said)
        said.write("The bot sent that chat a confirmation code. Type it here: ")
        code = _ask_code(stdin, said, typed)
        confirmed = admin_client.telegram_confirm(socket, enrolment, code)
    except KeyboardInterrupt:
        if opened is None:
            # Stopped while it opened: the vault may have opened it all the same.
            err.write(f"zoeymcp approver telegram enrol: {STOPPED_OPENING}\n")
            return EXIT_REFUSED
        admin_client.telegram_enrol_stop(socket, str(opened["enrolment"]))
        err.write("zoeymcp approver telegram enrol: stopped; nothing was enrolled\n")
        return EXIT_REFUSED
    said.write("Confirmed.\n")
    lines = [str(line) for line in confirmed["lines"]]
    applied = None
    if args.apply and admin_client.policy_head(socket)["mode"] == "managed":
        applied = _apply(socket, confirmed, lines, stdin, said)
        if applied is None:
            return EXIT_REFUSED
    else:
        review_view.write_lines([*lines, *RELOAD], said)
    if args.format == "json":
        review_view.write_json({**confirmed, "revision": applied}, out)
    return EXIT_OK


STOPPED_OPENING: Final = (
    "stopped while the enrolment opened; nothing was enrolled. If the vault opened it, run this "
    "again to stop it, or it ends by itself within 10 minutes"
)


def _stop_busy(
    exc: admin_client.AdminUnavailable, socket: str, stdin: TextIO, said: TextIO
) -> bool:
    """Another enrolment is open (``enrolment_busy``), perhaps one this command lost: offered
    to the host to stop, by the id its refusal names. True once it is stopped."""
    busy, expires = exc.data.get("enrolment"), exc.data.get("expires")
    if not isinstance(busy, str) or not isinstance(expires, int):
        return False
    said.write(f"{exc} It ends by itself at {utc(expires)}. Stop it now? [y/N] ")
    said.flush()
    answer = stdin.readline()
    if not stdin.isatty():
        said.write("\n")  # at a terminal, the line ends with the answer typed
    if answer.strip().lower() not in ("y", "yes"):
        return False
    admin_client.telegram_enrol_stop(socket, busy)
    said.write("Stopped it.\n")
    return True


# The step after the lines, in declarative mode or without --apply.
RELOAD: Final = (
    "Add these lines to the policy, then check it and reload the vault (managed: run this "
    "again with --apply, or export, edit and import). The reload starts the approver.",
)


def opening_lines(opened: Mapping[str, Any]) -> list[str]:
    """J1's first lines: the allowance, the bot and its link."""
    return [
        ALLOWANCE.format(allowance=opened["allowance"]),
        f"The bot is @{opened['bot']}. On the phone you'll approve from, open this link and "
        "press Start",
        f"(it works once, for 10 minutes): {opened['link']}",
        "Waiting for /start ... (Ctrl-C to stop)",
    ]


def seen_lines(seen: Mapping[str, Any]) -> list[str]:
    """Who pressed Start (G.8 step 3), before the confirmation code: a display name and a
    username are easy to mimic, which is why the code follows."""
    username = seen["username"]
    named = f'"{seen["name"]}"' + ("" if username is None else f", @{username}")
    return [f"Seen: user {seen['user_id']} ({named}) in its private chat {seen['chat_id']}."]


def with_telegram(document: Mapping[str, Any], confirmed: Mapping[str, Any]) -> dict[str, Any]:
    """``document`` (an export) with ``approvers.telegram`` the enrolment's, every other part
    of it kept."""
    seen = confirmed["seen"]
    telegram = {
        "bot_token": f"store:{confirmed['secret']}",
        "user_id": seen["user_id"],
        "chat_id": seen["chat_id"],
    }
    approvers = dict(document.get("approvers") or {})
    approvers["telegram"] = telegram
    return {**document, "approvers": approvers}


def _apply(
    socket: str,
    confirmed: Mapping[str, Any],
    lines: Sequence[str],
    stdin: TextIO,
    said: TextIO,
) -> int | None:
    """G.8 step 5 in managed mode: a host import of the head with the lines, planned, shown and
    asked; the revision written, or None when the host said no (nothing saved)."""
    exported = admin_client.policy_export(socket)
    base = int(exported["revision"])
    document = with_telegram(load_mapping(str(exported["export"])), confirmed)
    body = yaml.safe_dump(document, sort_keys=False, allow_unicode=False).encode("utf-8")
    path = "/policy/import"
    plan = admin_client.policy_write(socket, path, [("plan", "1")], body=body, base=base)
    review_view.write_lines([*lines, f"Planned on revision {base}:"], said)
    rows = [f"  {label}: {value}" for label, value in plan["rows"]]
    review_view.write_lines(rows, said)
    if plan["lockout"]:
        said.write("This plan has a lockout row: import it with zoeymcp policy import.\n")
        return None
    said.write("Apply as a host import? [y/N] ")
    said.flush()
    if stdin.readline().strip().lower() not in ("y", "yes"):
        said.write("Nothing written.\n")
        return None
    query = [("accept_widening", "1")] if plan["widens"] else []
    done = admin_client.policy_write(
        socket, path, query, body=body, base=base, plan_digest=plan["digest"]
    )
    revision = int(done["revision"])
    said.write(f"Imported revision {revision}: the approver starts now.\n")
    return revision


def _refused(state: Mapping[str, Any]) -> str:
    """The reason an enrolment ended, as the catalogue says it."""
    reason = state.get("reason") or "enrolment_expired"
    return refusal(str(reason)).error
