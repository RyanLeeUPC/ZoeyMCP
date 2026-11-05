"""``zoeymcp approvals``: the host's list, show and withdraw (M8 design K.3, Q13 (a), J15). I/O.

Over the vault's admin socket (``docker compose exec vault zoeymcp approvals ...``):

- ``approvals list`` (the default): the holds waiting, oldest first, and those decided recently,
  each by both identifiers, the ref (what Telegram's header, the queue row, the agent's texts and
  J15's output show) and the approval id (what the portal's URL and a press carry); never a text;
- ``approvals show <ref-or-id>``: one hold, its composed text whole, the one output of the CLI
  that prints one (Z14);
- ``approvals withdraw <ref-or-id>`` or ``--all`` (J15's emergency stop): undecided holds
  withdrawn as the host's; nothing is sent, each message is edited and each agent told. A call
  already approved runs on.

Each takes ``--format text|json`` (D-171). ``<ref-or-id>`` is either identifier (OPS-12): 16
lowercase hex digits is a ref, anything else an approval id; the vault tells them apart. No command
decides: approving takes the portal's passkey or the operator's Telegram (Q13). Every string from
the vault goes out through ``review.write_lines``, which shows control characters as text.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from typing import Any, Final, TextIO

from . import admin_client
from . import review as review_view

EXIT_OK: Final = 0
EXIT_REFUSED: Final = 1
EXIT_USAGE: Final = 2


def run(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    """``zoeymcp approvals [list|show|withdraw]``."""
    socket = admin_client.socket_path(args.socket)
    action = args.action or "list"
    try:
        if action == "show":
            answer = admin_client.approval(socket, args.key)
            _write(args, answer, show_lines(answer), out)
        elif action == "withdraw":
            usage = withdraw_usage(args.key, args.all)
            if usage is not None:
                err.write(f"zoeymcp approvals withdraw: {usage}\n")
                return EXIT_USAGE
            if args.all:
                answer = admin_client.approvals_withdraw_all(socket)
            else:
                answer = admin_client.approval_withdraw(socket, args.key)
            _write(args, answer, withdrawn_lines(answer["withdrawn"]), out)
        else:
            answer = admin_client.approvals(socket)
            _write(args, answer, list_lines(answer), out)
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp approvals: {exc}\n")
        return admin_client.exit_code(exc)
    return EXIT_OK


def withdraw_usage(key: str | None, every: bool) -> str | None:
    """What is wrong with ``withdraw``'s arguments: one identifier, or ``--all``, never both."""
    if every and key is not None:
        return "give a ref or an approval id, or --all, not both"
    if not every and key is None:
        return "give a ref or an approval id, or --all"
    return None


def list_lines(answer: Mapping[str, Any]) -> list[str]:
    """``approvals list``: Waiting, then Decided recently, one hold a line."""
    waiting, decided = answer["waiting"], answer["decided"]
    lines = [f"Waiting ({len(waiting)}):"]
    lines += [f"  {_waiting(row)}" for row in waiting] or ["  none"]
    lines.append(f"Decided recently ({len(decided)}):")
    lines += [f"  {_decided(row)}" for row in decided] or ["  none"]
    return lines


def show_lines(answer: Mapping[str, Any]) -> list[str]:
    """``approvals show``: the hold's facts, then its composed text whole, line by line."""
    lines = [
        f"ref {answer['ref']}  approval {answer['approval']}",
        f"{_call(answer)}  {answer['how_shown']}  state {answer['state']}",
        f"asked {answer['asked_shown']}  answer by {answer['deadline_shown']}",
        f"surfaces: {', '.join(answer['surfaces'])}",
    ]
    if answer.get("telegram_shown"):
        lines.append(str(answer["telegram_shown"]))
    return [*lines, "", *str(answer["text"]).split("\n")]


def withdrawn_lines(withdrawn: Sequence[Mapping[str, Any]]) -> list[str]:
    """J15's line: how many, their refs (whole, to paste into ``approvals show``), and that
    nothing was sent."""
    if not withdrawn:
        return ["Nothing was waiting: no approval withdrawn."]
    refs = ", ".join(str(row["ref"]) for row in withdrawn)
    if len(withdrawn) == 1:
        return [f"Withdrew 1 approval ({refs}): nothing was sent; its message was edited."]
    count = len(withdrawn)
    return [f"Withdrew {count} approvals ({refs}): nothing was sent; their messages were edited."]


def _write(
    args: argparse.Namespace, answer: Mapping[str, Any], lines: Sequence[str], out: TextIO
) -> None:
    if args.format == "json":
        review_view.write_json(answer, out)
    else:
        review_view.write_lines(lines, out)


def _call(row: Mapping[str, Any]) -> str:
    client = row["client_shown"]
    who = "client not reported" if client is None else f"client {client}"
    return f"{row['server_shown']}.{row['tool_shown']}  {who}"


def _waiting(row: Mapping[str, Any]) -> str:
    line = (
        f"{row['ref']}  {row['approval']}  {_call(row)}  asked {row['asked_shown']}  "
        f"answer by {row['deadline_shown']}"
    )
    shown = row.get("telegram_shown")
    return line if not shown else f"{line}  ({shown})"


def _decided(row: Mapping[str, Any]) -> str:
    return f"{row['ref']}  {row['approval']}  {_call(row)}  {row['outcome_shown']}"
