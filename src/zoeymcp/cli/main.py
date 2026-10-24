"""``zoeymcp`` entry point."""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from .. import __version__
from ..common import egresslist
from ..common.adminsocket import DEFAULT_SOCKET, SOCKET_ENV
from ..common.policy import (
    CONFIG_ENV,
    Finding,
    Policy,
    PolicyError,
    check_policy,
    fields,
    parse_policy,
    read_source,
)
from ..common.policy import emit as policy_emit
from ..common.policy import merge as policy_merge
from ..common.policy.load import validate_policy
from ..common.policy.schema import hash_token
from ..common.yamlload import load_mapping

# The vault's code is imported in the handlers that use it: ``python -m zoeymcp gateway`` runs
# this module in the gateway's process, which loads none of it.
from . import admin_client
from . import choices as review_choices
from . import ledger as ledger_view
from . import review as review_view

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_UNREADABLE = 2

CLIENT_TOKEN_PREFIX = "zgc1-"  # noqa: S105 - a format marker, not a secret
PASTE_PROMPT = "> "
NOT_PERSISTED = (
    "kept in memory, not on disk; fix the state volume; zoeymcp oauth status shows when it is saved"
)
# After a line drawn from a store entry's clear meta, which anyone with the file can edit.
FROM_META = "(from stored metadata)"
# How the CLI words each health action (M5 design I.1).
HEALTH_ACTIONS = {
    "connect": "run: zoeymcp login {credential}",
    "reset": "run: zoeymcp oauth reset {credential}",
    "set_secret": "run: zoeymcp secret set {secret}",
    "restart": "set env {var} and restart the vault",
    "delete_secret": "run: zoeymcp secret delete {secret}",
    "fix_policy": "fix the policy",
    "wait": "wait: it clears with time",
    "check_volume": "check the state volume",
    "check_mailbox": "check the mailbox for the sends with an unknown outcome",
    "check_gateway": "check that the gateway runs and reaches the vault",
    "read_ledger": "run: zoeymcp ledger --vault",
    "add_passkey": "run: zoeymcp setup-code, and enrol a second passkey with it",
    "review_passkeys": "run: zoeymcp passkeys, and remove any you don't recognize",
    "reset_passkeys": "run: zoeymcp setup-code --reset",
    "onboard_again": "run: {command}",
    "widen_scope": (
        'merge credentials.{credential}.scope: "{scope}" (the fragment is in health --json), '
        "check and reload the policy, then run: zoeymcp login {credential}"
    ),
    "check_egress_role": (
        "check that the egress role runs, reaches the vault, and has the key zoeymcp egress-key "
        "prints"
    ),
    "review": "run: zoeymcp review {server}",
    "reload_vault": "send SIGHUP to the vault, or restart it",
    "import_from_env": "remove ZOEYMCP_CONFIG, or run: zoeymcp policy import --from-env",
}

# The image's second virtual environment, the only one with the gateway's dependencies.
GATEWAY_ENVIRONMENT = Path("/opt/zoeymcp-gateway")
# The bridge's options the launcher sets first, each refused a second time (M7 design C.8, C.10).
BRIDGE_ONCE = ("--listen", "--peer-uid", "--work-dir", "--control-fd")


class _Once(argparse.Action):
    """An option that may be given once: a later ``--listen`` (or ``--listen=``) among the
    operator's arguments can't override the one the launcher put first (C.8)."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} is given once")
        setattr(namespace, self.dest, values)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zoeymcp", description="Credential vault and MCP gateway for AI agents."
    )
    parser.add_argument("--version", action="version", version=f"zoeymcp {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    check = commands.add_parser(
        "check",
        help="validate a policy document",
        description=(
            "Validate a policy document: its schema, cross-references and security rules. "
            f"Reads --config <file>, --config - (stdin) or ${CONFIG_ENV}. With "
            "--emit-egress-allowlist, print the destinations an egress proxy must allow for it "
            "instead, and the findings on stderr. With --with, check the policy with each "
            "fragment merged as the vault merges it."
        ),
    )
    check.add_argument("--config", metavar="FILE", help="policy file, or - for stdin")
    check.add_argument("--format", choices=("text", "json"), default="text")
    check.add_argument(
        "--resolve-env",
        action="store_true",
        help="also fail if an env: secret reference names a variable that isn't set",
    )
    check.add_argument(
        "--emit-egress-allowlist",
        action="store_true",
        help="print the egress allowlists the policy implies, sorted (nothing if it has errors)",
    )
    check.add_argument(
        "--allowlist-format",
        choices=("text", "json", "squid"),
        help="with --emit-egress-allowlist: text (the default), json, or a Squid snippet",
    )
    check.add_argument(
        "--squid-src",
        action="append",
        default=[],
        metavar="SOURCE=ACL",
        help="the Squid src ACL naming SOURCE's network, over the policy's egress_proxy_acls",
    )
    check.add_argument(
        "--check",
        dest="compare",
        metavar="FILE",
        help="with --emit-egress-allowlist: compare FILE with the output; exit 1 if it differs",
    )
    check.add_argument(
        "--with",
        dest="fragments",
        action="append",
        default=[],
        metavar="FRAGMENT",
        help="merge this fragment file into the policy first (repeatable)",
    )
    check.add_argument(
        "--print-merged",
        action="store_true",
        help="with --with: print the merged policy as YAML (comments dropped), findings on stderr",
    )
    layout = check.add_mutually_exclusive_group()
    layout.add_argument(
        "--indent",
        type=int,
        metavar="N",
        help=f"with --print-merged: indent every line N spaces (0 to {policy_emit.INDENT_MAX})",
    )
    layout.add_argument(
        "--for",
        dest="target",
        choices=("compose",),
        help="with --print-merged: the compose form, indented 8 with every $ written $$",
    )

    commands.add_parser(
        "keygen",
        help="print a new master key and its generation-1 gateway key",
        description=(
            "Print a new ZOEYMCP_MASTER_KEY and the matching generation-1 ZOEYMCP_GATEWAY_KEY. "
            "Set them as deployment secrets; nothing is written to disk."
        ),
    )

    commands.add_parser(
        "client-token",
        help="print a new gateway client token and its token_sha256 for the policy",
        description=(
            "Print a new client token for an agent, and the token_sha256 line to put under "
            "gateway.clients.<name> in the policy. The agent sends the token as "
            "Authorization: Bearer; the policy holds only its hash. Nothing is written to disk."
        ),
    )

    vault = commands.add_parser(
        "vault",
        help="run the vault",
        description=(
            "Run the vault: the only role that holds secrets. Needs ZOEYMCP_MASTER_KEY, and a "
            f"policy from --config <file>, --config - or ${CONFIG_ENV}."
        ),
    )
    vault.add_argument("--config", metavar="FILE", help="policy file, or - for stdin")
    vault.add_argument(
        "--listen",
        action="append",
        metavar="HOST:PORT",
        help=(
            "address to listen on (repeatable; default 0.0.0.0:8080); 'none' for no TCP "
            "listener, with --gateway-socket"
        ),
    )
    vault.add_argument("--state", default="/state", metavar="DIR", help="state directory")
    vault.add_argument(
        "--admin-socket",
        metavar="PATH",
        help=f"admin Unix socket (default ${SOCKET_ENV} or {DEFAULT_SOCKET}); 'none' disables it",
    )
    vault.add_argument(
        "--gateway-socket",
        metavar="PATH",
        help=(
            "the gateway's link socket (Linux; with --gateway-uid). Only that uid may connect, "
            "and TCP listeners then refuse gateway keys"
        ),
    )
    vault.add_argument(
        "--gateway-uid", type=int, metavar="UID", help="the gateway's uid on the link socket"
    )
    vault.add_argument(
        "--control-fd",
        type=int,
        metavar="FD",
        help="read HUP and TERM lines from this pipe; its end stops the vault (the launcher's)",
    )
    vault.add_argument(
        "--bridge",
        action="append",
        default=[],
        metavar="NAME=UID",
        help=(
            "a bridge the launcher started (repeatable; Linux): a unix: route to it is reached "
            "on its socket, only when that uid listens there"
        ),
    )

    gateway = commands.add_parser(
        "gateway",
        help="run the gateway",
        description=(
            "Run the gateway: the MCP server agents connect to. It holds no secret: everything "
            "upstream goes through the vault, which serves it its view of the policy."
        ),
    )
    gateway.add_argument(
        "--vault",
        required=True,
        metavar="LINK",
        help=(
            "unix:<socket> (the standard tier's link) or http://host:port (the hardened tier's, "
            "with ZOEYMCP_GATEWAY_KEY or ZOEYMCP_GATEWAY_KEY_FILE)"
        ),
    )
    gateway.add_argument(
        "--listen", default="0.0.0.0:8090", metavar="HOST:PORT", help="default 0.0.0.0:8090"
    )
    gateway.add_argument("--state", default="/state-gateway", metavar="DIR", help="state directory")
    gateway.add_argument(
        "--admin-socket",
        default="/run/zoeymcp-gateway/admin.sock",
        metavar="PATH",
        help="admin Unix socket (GET /status); 'none' disables it",
    )
    gateway.add_argument(
        "--allow-root", action="store_true", help="run as root anyway (development only)"
    )
    gateway.add_argument(
        "--allow-writable-toolkits",
        action="store_true",
        help="load toolkits from paths the gateway could write (development only; logged)",
    )
    gateway.add_argument(
        "--control-fd",
        type=int,
        metavar="FD",
        help="read HUP and TERM lines from this pipe; its end stops the gateway (the launcher's)",
    )

    egress = commands.add_parser(
        "egress",
        help="run the egress role: a CONNECT proxy held to the vault's allowlists (hardened tier)",
        description=(
            "Run the egress role: a CONNECT-only proxy with one listener per egress source, each "
            "allowing only that source's host:port list, which it long-polls from the vault "
            "with the egress key (ZOEYMCP_EGRESS_KEY or ZOEYMCP_EGRESS_KEY_FILE). It refuses "
            "every tunnel until it has a list, and again once its list is 300 s old."
        ),
    )
    egress.add_argument(
        "--vault", required=True, metavar="URL", help="the vault's listener, http://host:port"
    )
    egress.add_argument(
        "--listen",
        action="append",
        required=True,
        metavar="SOURCE=NAME:PORT",
        help=(
            "a source's listener (repeatable): vault, or a route's name, and the role's address "
            "on that source's network, as a name that resolves to exactly one address"
        ),
    )
    egress.add_argument(
        "--max-tunnels",
        type=int,
        default=256,
        metavar="N",
        help="open tunnels per listener (default 256; 1,024 in all)",
    )
    egress.add_argument(
        "--idle-timeout",
        type=float,
        default=900.0,
        metavar="SECONDS",
        help="close a tunnel that carried nothing for this long (default 900)",
    )
    egress.add_argument(
        "--max-tunnel-seconds",
        type=float,
        default=86400.0,
        metavar="SECONDS",
        help="close a tunnel open for this long (default 86400)",
    )

    bridge = commands.add_parser(
        "bridge",
        allow_abbrev=False,
        help="run a bridge: one stdio MCP program served as a Streamable HTTP upstream",
        description=(
            "Run a bridge: the program after -- is started with a built environment and served "
            "as one MCP endpoint, /mcp, which only a caller with the route's token (its "
            "sha256 in ZOEYMCP_BRIDGE_TOKEN_SHA256) reaches. With --ready-check, exit 0 once "
            "the bridge's readiness probe passed, 1 before."
        ),
    )
    bridge.add_argument(
        "--listen",
        action=_Once,
        metavar="ADDRESS",
        help="a network alias NAME:PORT, a loopback HOST:PORT, or unix:<path> (with --peer-uid)",
    )
    bridge.add_argument(
        "--peer-uid",
        action=_Once,
        type=int,
        metavar="UID",
        help="with --listen unix:, the only uid that may connect (the vault's)",
    )
    bridge.add_argument("--era", choices=["legacy", "modern"], help="the MCP era it serves")
    bridge.add_argument(
        "--egress-proxy",
        metavar="URL",
        help="http://host:port: the child's proxy variables (confine only in the hardened tier)",
    )
    bridge.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME",
        help="copy this variable to the child (repeatable)",
    )
    bridge.add_argument(
        "--secret-env",
        action="append",
        default=[],
        metavar="NAME",
        help="copy this secret to the child (repeatable; must be set; stderr then counts only)",
    )
    bridge.add_argument(
        "--stderr",
        choices=["counts", "text"],
        default="counts",
        help="log the child's stderr as counts (default) or as text, which may show --env values",
    )
    for option, kind, default, metavar, what in (
        ("--max-sessions", int, 8, "N", "legacy sessions at once"),
        ("--max-message-bytes", int, 8388608, "BYTES", "the longest message, either way"),
        ("--idle-timeout", float, 600.0, "SECONDS", "stop a legacy session idle this long"),
        ("--start-timeout", float, 60.0, "SECONDS", "how long the readiness probe waits"),
        ("--keepalive", float, 15.0, "SECONDS", "an SSE comment this often on a silent answer"),
        ("--max-procs", int, 64, "N", "RLIMIT_NPROC for the bridge and its children"),
    ):
        bridge.add_argument(
            option, type=kind, default=default, metavar=metavar, help=f"{what} (default {default})"
        )
    bridge.add_argument(
        "--work-dir",
        action=_Once,
        metavar="DIR",
        help="its own 0700 directory for the child (default /tmp/zoeymcp-bridge)",
    )
    bridge.add_argument(
        "--control-fd",
        action=_Once,
        type=int,
        metavar="FD",
        help="stop on a TERM line from this pipe, or its end (the launcher's)",
    )
    bridge.add_argument(
        "--ready-check", action="store_true", help="exit 0 if the readiness probe passed"
    )
    bridge.add_argument(
        "program", nargs="*", metavar="command", help="after --: the program and its arguments"
    )

    standard = commands.add_parser(
        "standard",
        help="run the standard tier: the vault and the gateway in one container, as two uids",
        description=(
            "The standard tier's entrypoint, PID 1 of a container started as root with "
            "cap_drop: [ALL], cap_add: [SETUID, SETGID] and no-new-privileges. It starts the "
            "vault as uid 10001 and the gateway as uid 10002, linked by a Unix socket, and each "
            "--bridge as uid 10100 and up, then drops to uid 10003 with an empty environment "
            "and supervises them."
        ),
    )
    standard.add_argument(
        "--gateway-listen",
        default="0.0.0.0:8090",
        metavar="HOST:PORT",
        help="the gateway's address (default 0.0.0.0:8090)",
    )
    standard.add_argument(
        "--vault-listen",
        action="append",
        default=[],
        metavar="HOST:PORT",
        help="also a vault TCP listener, for direct routes (repeatable; default none)",
    )
    standard.add_argument(
        "--unsafe-skip-checks",
        action="store_true",
        help="skip the NoNewPrivs and capability checks (development only)",
    )
    standard.add_argument(
        "--bridge",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "also run bridge NAME, unconfined, from ZOEYMCP_BRIDGE_<NAME>_ARGS, _TOKEN_SHA256 "
            "and _ENV_*, on unix:/run/zoeymcp-bridge-NAME/mcp.sock (repeatable; at most 8)"
        ),
    )
    standard.add_argument("--supervise", action="append", default=[], help=argparse.SUPPRESS)

    secret = commands.add_parser(
        "secret",
        help="set, list or delete secrets in a running vault (run inside the vault container)",
    )
    secret_commands = secret.add_subparsers(dest="action", required=True, metavar="action")
    secret_set = secret_commands.add_parser(
        "set",
        help="store or replace a secret; the value is read from stdin or a hidden prompt",
        description=(
            "Store or replace a secret. The value is read from stdin, or from a hidden prompt on "
            "a terminal, never from the command line. Its binding is derived from the policy "
            "unless --origin is given. OAuth secrets always take the policy's binding."
        ),
    )
    secret_set.add_argument("name")
    secret_set.add_argument(
        "--origin", action="append", metavar="URL", help="bind to this origin (repeatable)"
    )
    secret_set.add_argument(
        "--generate",
        action="store_true",
        help=(
            "store 32 random bytes instead, for a header credential (a bridge's token), and "
            "print only their sha256: line; the token never leaves the vault"
        ),
    )
    secret_commands.add_parser("list", help="list secret names and bindings (never values)")
    secret_delete = secret_commands.add_parser("delete", help="delete a secret")
    secret_delete.add_argument("name")

    selftest = commands.add_parser(
        "selftest",
        help="test a policy's routes against an echo upstream",
        description=(
            "Run the vault with this policy, every upstream replaced by an echo server and every "
            "secret by a dummy value, and check each case in --cases. With --mutate, also break "
            "the policy one rule at a time and report weakenings no case notices."
        ),
    )
    selftest.add_argument("--config", metavar="FILE", help="policy file, or - for stdin")
    selftest.add_argument("--cases", metavar="FILE", required=True, help="cases file (YAML)")
    selftest.add_argument("--mutate", action="store_true", help="also mutation-test the cases")

    setup_code = commands.add_parser(
        "setup-code",
        help="issue a one-time portal setup code, valid for 15 minutes (inside the vault)",
        description=(
            "Print a one-time code that enrols a passkey in the portal: it works once, for 15 "
            "minutes, and replaces any earlier one. Enrolling with it adds a passkey; with "
            "--reset, it removes every other passkey and ends every session. --state writes "
            "the code into a state directory instead, for hosts without the admin socket: it "
            "needs ZOEYMCP_MASTER_KEY and refuses to run as root."
        ),
    )
    setup_code.add_argument(
        "--reset",
        action="store_true",
        help="enrolling with this code removes every other passkey and ends every session",
    )
    setup_code.add_argument(
        "--wait",
        action="store_true",
        help="wait until a passkey is enrolled with the code, or it expires, and show which",
    )
    setup_code.add_argument(
        "--state",
        metavar="DIR",
        help="write the code into this state directory, without the admin socket",
    )
    passkeys = commands.add_parser(
        "passkeys",
        help="list the portal's passkeys, or remove one (inside the vault)",
        description=(
            "List each passkey with its fingerprint, how and where it was enrolled, and when it "
            "was last used, or remove one by its fingerprint. The last passkey may be removed "
            "here: the portal then waits for a setup code."
        ),
    )
    passkeys.add_argument("--remove", metavar="FINGERPRINT", help="remove this passkey")
    sessions = commands.add_parser(
        "sessions", help="list the portal's sessions, or end them all (inside the vault)"
    )
    sessions.add_argument("--end-all", action="store_true", help="end every portal session")
    gateway_key = commands.add_parser(
        "gateway-key",
        help="print the gateway key for the current generation",
        description=(
            "Print the gateway key for the current gateway_key_generation. After a bump, the "
            "previous key stays accepted until the gateway first uses the new one, for at most 5 "
            "minutes; while it is, a 'rotation pending' line goes to stderr."
        ),
    )
    gateway_key.add_argument(
        "--retire-previous",
        action="store_true",
        help="stop accepting the previous key now, for a suspected leak",
    )
    commands.add_parser(
        "egress-key",
        help="print the egress role's key for the current generation (inside the vault)",
        description=(
            "Print the egress role's key for the current egress_key_generation, as "
            "ZOEYMCP_EGRESS_KEY. It reads the vault's allowlists and nothing else. After a bump "
            "the old key is refused at once, and the role refuses new tunnels within 300 s "
            "until it has the new one."
        ),
    )

    review = commands.add_parser(
        "review",
        help="review a gateway server's tools and print pins to commit (in either container)",
        description=(
            "Ask the running gateway to list a server's tools on a fresh connection and show, per "
            "tool, its state, pin and findings, a diff for drifted tools, and a YAML snippet for "
            "the policy. With no server, one line per server and no upstream call. Inside the "
            "vault, --via vault asks the gateway through the vault's review jobs, and reads the "
            "last finished review again unless --fresh. --choose prints a choices file, one line "
            "per tool (skip, allow, approve or decline), and --choices FILE reads the edited file "
            "back into the snippet. Exit 0 when every included tool matches, nothing is marked "
            "and every listed tool is included or declined, 1 when something needs you (a tool "
            "nobody reviewed among them), 2 when the review couldn't run."
        ),
    )
    review.add_argument("server", nargs="?")
    review.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="TOOL",
        help="show only this tool (repeatable; the snippet still covers the whole server)",
    )
    review.add_argument(
        "--show", action="append", default=[], metavar="TOOL", help="print TOOL's definition"
    )
    review.add_argument("--all", action="store_true", help="print every definition")
    review.add_argument(
        "--add",
        action="append",
        default=[],
        metavar="TOOL",
        help="include TOOL in the snippet; you still classify it as allow or approve",
    )
    review.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="TOOL",
        help="include TOOL in the snippet as allow: agents call it with no prompt",
    )
    review.add_argument(
        "--approve",
        action="append",
        default=[],
        metavar="TOOL",
        help="include TOOL in the snippet as approve: every call asks you first",
    )
    review.add_argument(
        "--allow-read-only",
        action="store_true",
        help=(
            "include as allow every tool the server marks read-only and not destructive (its "
            "own annotations, not a judgement by ZoeyMCP); never an unannotated tool"
        ),
    )
    review.add_argument(
        "--decline",
        action="append",
        default=[],
        metavar="TOOL",
        help="record TOOL as declined at its pin: left out, and quiet until it changes",
    )
    review.add_argument(
        "--decline-rest",
        action="store_true",
        help="record every listed tool the snippet doesn't include as declined at its pin",
    )
    review.add_argument(
        "--choose",
        action="store_true",
        help="print a choices file: one line per tool, to edit and read back with --choices",
    )
    review.add_argument(
        "--suggest",
        action="store_true",
        help="with --choose: write allow on each tool the server marks read-only, skip elsewhere",
    )
    review.add_argument(
        "--choices",
        metavar="FILE",
        help="read an edited choices file (- for stdin) and print the snippet it makes",
    )
    review.add_argument(
        "--repin",
        action="append",
        default=[],
        metavar="TOOL",
        help="take a drifted tool's new pin in the snippet",
    )
    review.add_argument(
        "--clear",
        action="store_true",
        help="clear the server's drift marks, if every included tool matches its pin again",
    )
    review.add_argument(
        "--via",
        choices=("auto", "gateway", "vault"),
        default="auto",
        help=(
            "where the review runs: the gateway's admin socket, or the vault's and its review "
            "jobs (default: the gateway's socket when this container has it)"
        ),
    )
    review.add_argument(
        "--fresh",
        action="store_true",
        help="with --via vault: review again, not the last finished review at this policy",
    )
    review.add_argument("--format", choices=("text", "json"), default="text")
    gateway_status = commands.add_parser(
        "gateway-status",
        help="the gateway's view and each server's state (inside the gateway)",
        description=(
            "Print the gateway's view digest and, per server, its connections, era, exposed and "
            "included tools, reports and drift marks. Never definitions or token hashes."
        ),
    )
    gateway_status.add_argument("server", nargs="?")
    gateway_status.add_argument("--format", choices=("text", "json"), default="text")
    ledger = commands.add_parser(
        "ledger",
        help="the approval ledger: list, verify, or check a call's arguments (inside the gateway)",
        description=(
            "List approval ledger records, one line per call (when, ref, client, server/tool, "
            "era, decision, outcome). --verify walks the hash chain and prints its head, to "
            "compare with the last anchor in the logs. 'ledger check REF FILE' proves whether "
            "FILE (JSON) holds the arguments that call was made with, without the key leaving "
            "the gateway. Never argument values or prompt text. --vault reads the vault's "
            "copy of the ledger instead (inside the vault), which the gateway reports to it; "
            "--restart-chain archives that copy's chain after a fork, gap or full, once you "
            "have decided why, and asks first."
        ),
    )
    ledger.add_argument("action", nargs="?", metavar="check")
    ledger.add_argument("ref", nargs="?")
    ledger.add_argument("file", nargs="?")
    ledger.add_argument(
        "--since", metavar="AGE", help="only calls asked within AGE, like 7d, 12h or 30m"
    )
    ledger.add_argument("--client", metavar="CLIENT")
    ledger.add_argument("--server", metavar="SERVER")
    ledger.add_argument("--tool", metavar="TOOL")
    ledger.add_argument("--verify", action="store_true", help="check the hash chain")
    ledger.add_argument("--format", choices=("text", "json"), default="text")
    ledger.add_argument(
        "--vault", action="store_true", help="the vault's reported copy (inside the vault)"
    )
    ledger.add_argument(
        "--restart-chain",
        action="store_true",
        help="with --vault: archive the copy's chain after a fork, gap or full (asks first)",
    )
    ledger.add_argument(
        "--before", type=int, metavar="SEQ", help="with --vault: the rows before this seq"
    )
    for sub in (review, gateway_status, ledger):
        sub.add_argument(
            "--socket",
            metavar="PATH",
            help=(
                f"the gateway's admin socket (default ${admin_client.GATEWAY_SOCKET_ENV} or "
                f"{admin_client.GATEWAY_SOCKET}); with ledger --vault or review --via vault, "
                "the vault's"
            ),
        )

    login = commands.add_parser(
        "login",
        help="consent to an OAuth credential, or onboard an MCP server by URL (inside the vault)",
        description=(
            "Open the printed URL in a browser and approve. The browser is then sent to the "
            "credential's redirect_uri, which fails to load: paste that address back. It is read "
            "from a hidden prompt, or one line of stdin, never from the command line. For the "
            "client_credentials grant, login is a test fetch. With --mcp URL instead of a "
            "credential, onboard the MCP server at URL: the vault discovers its authorization "
            "server and shows the plan (stderr); confirmed, fragment 1 for the policy goes to "
            "stdout. Run it again once the fragment is committed to compare and sign in."
        ),
    )
    target = login.add_mutually_exclusive_group(required=True)
    target.add_argument("credential", nargs="?")
    target.add_argument("--mcp", metavar="URL", help="onboard the MCP server at URL")
    login.add_argument(
        "--rebind", action="store_true", help="accept a binding the policy has changed"
    )
    mode = login.add_mutually_exclusive_group()
    mode.add_argument(
        "--start", action="store_true", help="print the URL and the flow ID, then exit"
    )
    mode.add_argument(
        "--flow", metavar="ID", help="complete a flow from --start; reads the address from stdin"
    )
    onboard = login.add_argument_group("onboarding by URL (with --mcp)")
    onboard.add_argument(
        "--name", metavar="NAME", help="the credential, route and server name (default: the host's)"
    )
    onboard.add_argument("--credential", dest="credential_name", metavar="C")
    onboard.add_argument("--route", metavar="R")
    onboard.add_argument("--server", metavar="S")
    onboard.add_argument(
        "--issuer",
        metavar="ISSUER",
        help="the authorization server to use; needed with --client-secret",
    )
    onboard.add_argument(
        "--scope", metavar='"TOKEN ..."', help="the scopes to request, instead of the server's"
    )
    onboard.add_argument("--client-name", metavar="TEXT", help="the client's name at the provider")
    onboard.add_argument(
        "--client-id", metavar="ID", help="a client registered at the provider already"
    )
    # It takes no value, but parses one (--client-secret=VALUE included) so that login --mcp
    # refuses it without echoing it, as argparse's own error would (D.10, OPS-4).
    onboard.add_argument(
        "--client-secret",
        nargs="?",
        const=True,
        default=False,
        metavar="",
        help="the client has a secret: read from a hidden prompt, or with --yes from stdin, "
        "never from the command line",
    )
    onboard.add_argument(
        "--client-auth",
        choices=("basic", "post"),
        help="how the client sends its secret (default basic)",
    )
    onboard.add_argument(
        "--redirect-uri", metavar="URL", help="the redirect address the provider has on record"
    )
    onboard.add_argument(
        "--callback-origin",
        metavar="ORIGIN",
        help="register the client with this admin.origins portal's callback, not the paste one",
    )
    onboard.add_argument(
        "--allow-private",
        action="store_true",
        help="the server is on your network: its own host:port may resolve privately",
    )
    onboard.add_argument(
        "--plan-only", action="store_true", help="show the plan, then stop; nothing is stored"
    )
    onboard.add_argument(
        "--yes", action="store_true", help="don't ask; needed when a client secret is piped in"
    )
    onboard.add_argument(
        "--reregister",
        action="store_true",
        help="register a new client for the committed credential, under its names",
    )
    onboard.add_argument(
        "--no-connect",
        action="store_true",
        help="after the commit: compare only, don't sign in (an adopted grant)",
    )
    onboard.add_argument(
        "--squid-src",
        action="append",
        default=[],
        metavar="vault=ACL",
        help="the Squid src ACL for the vault in the lines a proxy refusal prints",
    )
    layout = onboard.add_mutually_exclusive_group()
    layout.add_argument(
        "--indent",
        type=int,
        metavar="N",
        help=f"indent fragment 1's lines N spaces (0 to {policy_emit.INDENT_MAX})",
    )
    layout.add_argument(
        "--for",
        dest="target",
        choices=("compose",),
        help="fragment 1 in the compose form, indented 8 with every $ written $$",
    )
    onboard.add_argument("--format", choices=("text", "json"))

    oauth = commands.add_parser("oauth", help="OAuth health: status and reset (inside the vault)")
    oauth_commands = oauth.add_subparsers(dest="action", required=True, metavar="action")
    oauth_status = oauth_commands.add_parser(
        "status", help="state, failures and warnings of each oauth2 credential (never values)"
    )
    oauth_status.add_argument("credential", nargs="?")
    oauth_reset = oauth_commands.add_parser(
        "reset", help="clear a credential's failure state, so the next request tries once"
    )
    oauth_reset.add_argument("credential")

    health = commands.add_parser(
        "health",
        help="what needs you, per credential, connector and store entry (inside the vault)",
        description=(
            "Print what needs you, per credential, connector and store entry, with what to do "
            "about it. From metadata only: nothing is decrypted and no request is sent. Exit 0 "
            "with no error (with --strict, no warning either), 1 otherwise, 2 when the vault "
            "can't be asked."
        ),
    )
    health.add_argument("--json", action="store_true", help="print the whole report as JSON")
    health.add_argument("--strict", action="store_true", help="also exit 1 for a warning")

    for sub in [*secret_commands.choices.values(), *oauth_commands.choices.values()]:
        sub.add_argument("--socket", metavar="PATH", help="admin socket path")
    for name in (
        "setup-code",
        "passkeys",
        "sessions",
        "gateway-key",
        "egress-key",
        "login",
        "health",
    ):
        commands.choices[name].add_argument("--socket", metavar="PATH", help="admin socket path")
    return parser


def _cmd_vault(args: argparse.Namespace, out: TextIO) -> int:
    from ..vault.server import StartupError, run

    admin_socket = None
    if args.admin_socket != "none":
        admin_socket = Path(admin_client.socket_path(args.admin_socket))
    listens: list[str] = args.listen or ["0.0.0.0:8080"]
    if "none" in listens:
        if len(listens) > 1:
            out.write("zoeymcp vault: --listen none can't be combined with other addresses\n")
            return EXIT_UNREADABLE
        listens = []
    try:
        run(
            args.config,
            listens,
            Path(args.state),
            os.environ,
            admin_socket,
            gateway_socket=Path(args.gateway_socket) if args.gateway_socket else None,
            gateway_uid=args.gateway_uid,
            control_fd=args.control_fd,
            bridges=args.bridge,
        )
    except StartupError as exc:
        out.write(f"zoeymcp vault: {exc}\n")
        return EXIT_UNREADABLE
    return EXIT_OK


def _cmd_gateway(args: argparse.Namespace, out: TextIO) -> int:
    # Imported here: only the gateway's environment has its packages.
    from ..gateway.server import Options, StartupError, run

    admin_socket = None if args.admin_socket == "none" else Path(args.admin_socket)
    options = Options(
        vault=args.vault,
        listen=args.listen,
        state=Path(args.state),
        admin_socket=admin_socket,
        allow_root=args.allow_root,
        control_fd=args.control_fd,
        allow_writable_toolkits=args.allow_writable_toolkits,
    )
    try:
        run(options, os.environ)
    except StartupError as exc:
        out.write(f"zoeymcp gateway: {exc}\n")
        return EXIT_UNREADABLE
    return EXIT_OK


def _cmd_egress(args: argparse.Namespace, err: TextIO) -> int:
    from ..egress.main import Options, StartupError, run

    options = Options(
        vault=args.vault,
        listens=tuple(args.listen),
        max_tunnels=args.max_tunnels,
        idle_timeout=args.idle_timeout,
        max_tunnel_seconds=args.max_tunnel_seconds,
    )
    try:
        run(options, os.environ)
    except StartupError as exc:
        err.write(f"zoeymcp egress: {exc}\n")
        return EXIT_UNREADABLE
    return EXIT_OK


def _cmd_bridge(args: argparse.Namespace, err: TextIO) -> int:
    from ..bridge.main import Options, StartupError, ready_check, run

    work_dir = args.work_dir or "/tmp/zoeymcp-bridge"  # noqa: S108 - the bridge's own tmpfs
    if args.ready_check:
        return EXIT_OK if ready_check(work_dir) else EXIT_FINDINGS
    if args.listen is None or args.era is None:
        err.write("zoeymcp bridge: --listen and --era are required\n")
        return EXIT_UNREADABLE
    options = Options(
        listen=args.listen,
        era=args.era,
        command=tuple(args.program),
        peer_uid=args.peer_uid,
        egress_proxy=args.egress_proxy,
        env=tuple(args.env),
        secret_env=tuple(args.secret_env),
        stderr=args.stderr,
        max_sessions=args.max_sessions,
        max_message_bytes=args.max_message_bytes,
        idle_timeout=args.idle_timeout,
        start_timeout=args.start_timeout,
        keepalive=args.keepalive,
        max_procs=args.max_procs,
        work_dir=work_dir,
        control_fd=args.control_fd,
    )
    try:
        run(options, os.environ)
    except StartupError as exc:
        err.write(f"zoeymcp bridge: {exc}\n")
        return EXIT_UNREADABLE
    return EXIT_OK


def _cmd_standard(args: argparse.Namespace, err: TextIO) -> int:
    from ..entrypoint import launcher

    try:
        if args.supervise:
            return launcher.Supervisor(launcher.parse_supervised(args.supervise)).run()
        launcher.launch(
            launcher.Options(
                gateway_listen=args.gateway_listen,
                vault_listens=tuple(args.vault_listen),
                unsafe_skip_checks=args.unsafe_skip_checks,
                bridges=tuple(args.bridge),
            ),
            os.environ,
        )
    except launcher.LaunchError as exc:
        err.write(f"zoeymcp standard: {exc}\n")
        return EXIT_UNREADABLE


def _cmd_keygen(out: TextIO) -> int:
    from ..vault.keys import MASTER_KEY_ENV, KeySet, generate_master_key

    master = generate_master_key()
    keys = KeySet.from_text(master)
    out.write(f"{MASTER_KEY_ENV}={master}\n")
    out.write(f"ZOEYMCP_GATEWAY_KEY={keys.gateway_key(1)}\n")
    return EXIT_OK


def new_client_token() -> str:
    """A new client token: the prefix and 32 random bytes in unpadded base64url (48 characters)."""
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    return CLIENT_TOKEN_PREFIX + raw


def _cmd_client_token(out: TextIO, err: TextIO) -> int:
    token = new_client_token()
    out.write(f"client_token: {token}\n")
    out.write(f"token_sha256: {hash_token(token)}\n")
    err.write(
        "Give the agent the client token (Authorization: Bearer). Put only the token_sha256 "
        "line in the policy, under gateway.clients.<name>.\n"
    )
    return EXIT_OK


def _cmd_admin(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    socket = admin_client.socket_path(getattr(args, "socket", None))
    try:
        if args.command == "gateway-key":
            _gateway_key(socket, args.retire_previous, out, err)
        elif args.command == "egress-key":
            result = admin_client.egress_key(socket)
            out.write(f"ZOEYMCP_EGRESS_KEY={result['key']}\n")
            err.write(f"Generation {result['generation']}.\n")
        elif args.action == "set" and args.generate:
            # Only the hash is printed: the token itself never leaves the vault (C.2).
            result = admin_client.secret_generate(socket, args.name, args.origin)
            out.write(f"{result['sha256']}\n")
            err.write(
                f"Stored a new token as {result['name']}, bound to "
                f"{admin_client.describe_binding(result['binding'])}. Set the line above as the "
                "bridge's ZOEYMCP_BRIDGE_TOKEN_SHA256.\n"
            )
        elif args.action == "set":
            value = admin_client.read_secret_value(stdin)
            result = admin_client.secret_set(socket, args.name, value, args.origin)
            out.write(
                f"stored {result['name']}, bound to "
                f"{admin_client.describe_binding(result['binding'])}\n"
            )
        elif args.action == "list":
            for entry in admin_client.secret_list(socket)["secrets"]:
                out.write(
                    f"{entry['name']}  updated {entry['updated']}  "
                    f"{admin_client.describe_binding(entry['binding'])}\n"
                )
        elif args.action == "delete":
            admin_client.secret_delete(socket, args.name)
            out.write(f"deleted {args.name}\n")
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp {args.command}: {exc}\n")
        return EXIT_FINDINGS
    return EXIT_OK


def _gateway_key(socket: str, retire_previous: bool, out: TextIO, err: TextIO) -> None:
    from ..vault.gatewaykeys import utc

    if retire_previous:
        result = admin_client.gateway_key_retire_previous(socket)
    else:
        result = admin_client.gateway_key(socket)
    out.write(f"ZOEYMCP_GATEWAY_KEY={result['key']}\n")
    err.write(f"Generation {result['generation']}.\n")
    if retire_previous:
        retired = result["retired"]
        if retired is None:
            err.write("No previous key was accepted.\n")
        else:
            err.write(f"Retired generation {retired}: only this key is accepted now.\n")
    previous = result["previous"]
    if previous is not None:
        generations, master = f"generation {previous['generation']}", ""
        if previous["master_key"] == "previous":
            # The previous master's key(current) is accepted too.
            master = " (previous master key)"
            if previous["generation"] != result["generation"]:
                generations = f"generations {previous['generation']} and {result['generation']}"
        err.write(
            f"rotation pending: {generations}{master} accepted until {utc(previous['until'])}\n"
        )


# --- setup codes, passkeys and sessions (M5 design E) ------------------------------------------


def _cmd_setup_code(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    if args.state is not None:
        if args.wait:
            err.write("zoeymcp setup-code: --wait asks the vault, so it can't go with --state\n")
            return EXIT_UNREADABLE
        return _offline_setup_code(Path(args.state), args.reset, out, err)
    socket = admin_client.socket_path(args.socket)
    try:
        result = admin_client.setup_code(socket, reset=args.reset)
        out.write(f"{result['code']}\n")
        out.flush()
        err.write("".join(f"{line}\n" for line in setup_code_lines(result)))
        if args.wait:
            return _wait_for_enrolment(socket, result, out, err)
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp setup-code: {exc}\n")
        return EXIT_FINDINGS
    return EXIT_OK


def running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _offline_setup_code(state: Path, reset: bool, out: TextIO, err: TextIO) -> int:
    """``setup-code --state DIR``: write the MAC'd record with the master key from the
    environment, for hosts without the admin socket (M5 design E.2)."""
    from ..portal.setupcode import FILE
    from ..vault.admin import SetupCodes
    from ..vault.keys import MASTER_KEY_ENV, PREVIOUS_MASTER_KEY_ENV, KeySet, MasterKeyError

    if running_as_root():
        err.write(
            "zoeymcp setup-code: --state won't run as root: the vault's uid couldn't read the "
            "file. Run it as the vault's user.\n"
        )
        return EXIT_UNREADABLE
    text = os.environ.get(MASTER_KEY_ENV)
    if not text:
        err.write(f"zoeymcp setup-code: --state needs the vault's master key in {MASTER_KEY_ENV}\n")
        return EXIT_UNREADABLE
    try:
        keys = KeySet.from_text(text)
        previous_text = os.environ.get(PREVIOUS_MASTER_KEY_ENV)
        previous = KeySet.from_text(previous_text) if previous_text else None
    except MasterKeyError as exc:
        err.write(f"zoeymcp setup-code: {exc}\n")
        return EXIT_UNREADABLE
    try:
        code, record = SetupCodes(state, keys.portal_key).issue(reset=reset)
    except OSError as exc:
        err.write(f"zoeymcp setup-code: can't write {state / FILE}: {exc}\n")
        return EXIT_FINDINGS
    out.write(f"{code.reveal()}\n")
    result = {
        "expires": record.expires,
        "reset": record.reset,
        "passkeys": _passkey_count(state, keys, previous),
        "origins": None,
    }
    err.write("".join(f"{line}\n" for line in setup_code_lines(result)))
    return EXIT_OK


def _passkey_count(state: Path, keys: Any, previous: Any) -> int | None:
    """How many passkeys the state directory holds; None when the file can't be verified."""
    from ..portal import passkeys

    path = state / passkeys.DIRECTORY / passkeys.FILE
    try:
        with path.open("rb") as handle:
            data = handle.read(passkeys.MAX_FILE_BYTES + 1)
        document, _ = passkeys.unseal(
            data, keys.portal_key, None if previous is None else previous.portal_key
        )
    except FileNotFoundError:
        return 0
    except (OSError, passkeys.PasskeyFileError):
        return None
    return len(document.credentials)


def setup_code_lines(result: dict[str, Any]) -> list[str]:
    """What ``setup-code`` tells the operator on stderr: where to use the code, what enrolling
    with it does, and what a refusal of an unused code means (E.1, E.4). ``origins`` is None
    when the code was written offline, without the policy."""
    from ..portal.setupcode import TTL

    origins = result["origins"]
    if origins is None:
        where = "Open the portal and choose Set up."
    elif origins:
        where = f"Open {' or '.join(origins)} and choose Set up."
    else:
        where = "The policy has no admin block, so no portal takes it yet."
    lines = [f"One-time code, valid for {TTL // 60} minutes. {where}"]
    count, reset = result["passkeys"], result["reset"]
    if count is None and reset:
        lines.append(
            "The passkey file can't be verified: enrolling with this code moves it aside, "
            "removes every passkey and ends every session."
        )
    elif count is None:
        lines.append(
            "The passkey file can't be verified: only a code issued with --reset can enrol; "
            "run zoeymcp setup-code --reset."
        )
    elif count:
        enrolled = "1 passkey is enrolled" if count == 1 else f"{count} passkeys are enrolled"
        effect = "removes all of them and ends every session" if reset else "adds one"
        lines.append(f"{enrolled}; enrolling with this code {effect}.")
    lines.append(
        "If the portal refuses this code before you have used it, someone else has: run "
        "zoeymcp setup-code --reset."
    )
    return lines


# Each status request of setup-code --wait waits up to this many seconds for a change.
SETUP_WAIT_POLL = 30


def _wait_for_enrolment(socket: str, issued: dict[str, Any], out: TextIO, err: TextIO) -> int:
    """Ask until a passkey is enrolled with the code, or it can't be any more (E.4)."""
    err.write("Waiting until a passkey is enrolled with this code (Ctrl-C stops waiting).\n")
    err.flush()
    announced = False
    while True:
        try:
            status = admin_client.setup_code_status(socket, wait=SETUP_WAIT_POLL)
        except KeyboardInterrupt:
            err.write(
                "zoeymcp setup-code: stopped waiting; the code still works until it expires\n"
            )
            return EXIT_FINDINGS
        state = status["state"]
        if state == "none" or status["expires"] != issued["expires"]:
            err.write(
                "zoeymcp setup-code: the vault has a newer code, or restarted: nothing to wait "
                "for\n"
            )
            return EXIT_FINDINGS
        if state == "enrolled":
            out.write(f"{enrolled_line(status['passkey'])}\n")
            return EXIT_OK
        if state == "expired":
            if status["origin"] is None:
                text = "the code expired, or was withdrawn, unused"
            else:
                text = f"redeemed on {status['origin']}, but no passkey was enrolled in time"
            err.write(f"zoeymcp setup-code: {text}; issue a new code\n")
            return EXIT_FINDINGS
        if state == "redeemed" and not announced:
            announced = True
            err.write(f"Redeemed on {status['origin']}; waiting for the enrolment.\n")
            err.flush()


def enrolled_line(passkey: dict[str, Any]) -> str:
    """The passkey a setup code enrolled, to compare with what the portal showed (E.4)."""
    from ..vault.gatewaykeys import utc

    at = utc(passkey["created"]).partition("T")[2].removesuffix("Z")
    return (
        f"enrolled: {passkey['fingerprint']} on {passkey['origin']} as {passkey['name']} "
        f"at {at} UTC"
    )


def passkey_lines(passkey: dict[str, Any]) -> list[str]:
    """Two lines per passkey: its fingerprint and name, then how and where it was enrolled."""
    from ..vault.gatewaykeys import utc

    kind = "synced" if passkey["synced"] else "device-bound"
    used = passkey["last_used"]
    last = "never used" if used is None else f"last used {utc(used).partition('T')[0]}"
    return [
        f"{passkey['fingerprint']}  {passkey['name']}",
        f"  {passkey['alg']}, {kind}, for {passkey['rp_id']}; enrolled {utc(passkey['created'])} "
        f"via {passkey['via']} on {passkey['origin']}; {last}",
    ]


def _cmd_passkeys(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    socket = admin_client.socket_path(args.socket)
    try:
        if args.remove is not None:
            result = admin_client.passkey_remove(socket, args.remove)
            lines = passkey_lines(result["removed"])
            out.write(f"removed {lines[0]}\n{lines[1]}\n")
            remaining = result["remaining"]
            out.write(f"{result['sessions_ended']} session(s) ended; {remaining} passkey(s) left\n")
            if remaining == 0:
                err.write(
                    "No passkey is left: the portal waits for a setup code (zoeymcp setup-code).\n"
                )
            return EXIT_OK
        listed = admin_client.passkeys(socket)["passkeys"]
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp passkeys: {exc}\n")
        return EXIT_FINDINGS
    if not listed:
        out.write("no passkeys\n")
    for passkey in listed:
        out.write("".join(f"{line}\n" for line in passkey_lines(passkey)))
    return EXIT_OK


def _cmd_sessions(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    socket = admin_client.socket_path(args.socket)
    try:
        if args.end_all:
            ended = admin_client.sessions_end_all(socket)["ended"]
            out.write(f"ended {ended} portal session(s)\n")
            return EXIT_OK
        listed = admin_client.sessions(socket)["sessions"]
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp sessions: {exc}\n")
        return EXIT_FINDINGS
    if not listed:
        out.write("no portal sessions\n")
    for session in listed:
        out.write(f"{json.dumps(session, sort_keys=True)}\n")
    return EXIT_OK


# --- review and gateway-status ----------------------------------------------------------------


def _cmd_review(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    usage = _review_usage(args)
    if usage is not None:
        err.write(f"zoeymcp review: {usage}\n")
        return review_view.EXIT_COULD_NOT_RUN
    parsed: review_choices.Parsed | None = None
    if args.choices is not None:
        # Read before the review runs, so a file that can't be read costs no listing.
        try:
            text = stdin.read() if args.choices == "-" else Path(args.choices).read_text("utf-8")
            parsed = review_choices.parse(text)
        except (OSError, UnicodeDecodeError) as exc:
            err.write(f"zoeymcp review: can't read {args.choices}: {exc}\n")
            return review_view.EXIT_COULD_NOT_RUN
        except review_choices.ChoicesRefused as exc:
            err.write(f"zoeymcp review: {exc.reason}: {review_view.untrusted(exc)}\n")
            return review_view.EXIT_COULD_NOT_RUN
    if review_view.pick_via(args.via, args.socket) == "vault":
        return _review_through_vault(args, parsed, out, err)
    if args.fresh:  # --via gateway, or auto on the gateway's socket
        err.write(
            "zoeymcp review: --fresh goes with --via vault; this review runs over the gateway's "
            "socket, which always lists anew\n"
        )
        return review_view.EXIT_COULD_NOT_RUN
    socket = admin_client.gateway_socket_path(args.socket)
    if args.server is None:
        try:
            status = admin_client.gateway_status(socket)
        except admin_client.AdminUnavailable as exc:
            err.write(f"zoeymcp review: {exc}\n")
            return review_view.EXIT_COULD_NOT_RUN
        lines, code = review_view.summary(status)
        if args.format == "json":
            review_view.write_json(status, out)
        else:
            review_view.write_lines(lines, out)
        return code
    choices = _review_choices(args)
    try:
        result = admin_client.gateway_review(socket, args.server, clear=args.clear)
    except admin_client.AdminUnavailable as exc:
        if exc.reason == "not_clean" and isinstance(exc.data.get("review"), dict):
            # --clear refused: show what doesn't match, and why.
            err.write(f"zoeymcp review: --clear refused: {review_view.untrusted(exc)}\n")
            code = _review_output(exc.data["review"], choices, args, out, err)
            return max(code, review_view.EXIT_NEEDS_OPERATOR)
        err.write(f"zoeymcp review: {review_view.untrusted(exc)}\n")
        return review_view.EXIT_COULD_NOT_RUN
    # The gateway's own socket keeps no job: the choices file names none.
    return _review_output(result, choices, args, out, err, job=review_choices.NO_JOB, read=parsed)


def _review_usage(args: argparse.Namespace) -> str | None:
    """What's wrong with ``review``'s options as given, before anything is asked."""
    picked = (
        args.add
        or args.allow
        or args.approve
        or args.allow_read_only
        or args.repin
        or args.decline
        or args.decline_rest
    )
    shown = args.tool or args.show or args.all
    if args.server is None and (picked or shown or args.clear or args.choose or args.choices):
        return "these options need a server"
    if args.suggest and not args.choose:
        return "--suggest goes with --choose"
    if args.choose and args.choices is not None:
        return "--choose writes a choices file and --choices reads one: give one of them"
    if (args.choose or args.choices is not None) and (
        picked or shown or args.clear or args.format == "json"
    ):
        return (
            "--choose and --choices print text and take no other choices: give them in the "
            "file, or leave --choose out"
        )
    return None


def _review_through_vault(
    args: argparse.Namespace,
    parsed: review_choices.Parsed | None,
    out: TextIO,
    err: TextIO,
) -> int:
    """``review <server> --via vault`` (M7 design F.5): the gateway's review, as a job the vault
    queued and the gateway ran, printed as the gateway's own answer is; with ``--clear``, a
    clear job (M6 design J.4), refused as the gateway's own ``--clear`` is when an included
    tool doesn't match its pin."""
    if args.server is None:
        # The summary is the gateway's status, which only its own socket answers.
        err.write("zoeymcp review: through the vault, name the server to review\n")
        return review_view.EXIT_COULD_NOT_RUN
    choices = _review_choices(args)
    try:
        job = review_view.vault_review(
            admin_client.socket_path(args.socket), args.server, fresh=args.fresh, clear=args.clear
        )
    except admin_client.AdminUnavailable as exc:
        if exc.reason == "clear_not_clean" and isinstance(exc.data.get("report"), dict):
            # The gateway refused the clear: show what doesn't match, as --via gateway does.
            err.write(f"zoeymcp review: --clear refused: {review_view.untrusted(exc)}\n")
            code = _review_output(exc.data["report"], choices, args, out, err)
            return max(code, review_view.EXIT_NEEDS_OPERATOR)
        err.write(f"zoeymcp review: {review_view.untrusted(exc)}\n")
        return review_view.EXIT_COULD_NOT_RUN
    except review_view.StillRunning:
        err.write(
            "zoeymcp review: the review is still running in the gateway; run this again in a "
            "minute to read it\n"
        )
        return review_view.EXIT_COULD_NOT_RUN
    return _review_output(job["report"], choices, args, out, err, job=job["job"], read=parsed)


def _review_choices(args: argparse.Namespace) -> review_view.Choices:
    return review_view.Choices(
        tools=frozenset(args.tool),
        show=frozenset(args.show),
        show_all=args.all,
        add=tuple(dict.fromkeys(args.add)),
        repin=frozenset(args.repin),
        allow=tuple(dict.fromkeys(args.allow)),
        approve=tuple(dict.fromkeys(args.approve)),
        allow_read_only=args.allow_read_only,
        decline=tuple(dict.fromkeys(args.decline)),
        decline_rest=args.decline_rest,
    )


def _review_output(
    result: dict[str, Any],
    choices: review_view.Choices,
    args: argparse.Namespace,
    out: TextIO,
    err: TextIO,
    *,
    job: str = review_choices.NO_JOB,
    read: review_choices.Parsed | None = None,
) -> int:
    """Print the review as asked: the text and snippet (or JSON), the choices file
    (``--choose``), or the snippet a choices file makes (``--choices``)."""
    if args.choose:
        lines = review_choices.render(result, job, suggest=args.suggest)
        review_view.write_lines(lines, out)
        return review_view.exit_code(result)
    try:
        if read is not None:
            changes = review_choices.decide(result, job, read)
            heading = review_view.second_title(
                result["server"], declined=changes.declined is not None
            )
            out.write(policy_emit.emit(review_view.fragment(result, changes, heading=heading)))
            err.write(
                f"zoeymcp review: {_classified(changes)}. Prove it with check --with, commit it "
                "and reload, then assign the server to its clients.\n"
            )
            return review_view.exit_code(result)
        review_view.check_choices(result, choices)
        if args.format == "json":
            snippet = review_view.snippet(result, choices)
            review_view.write_json({**result, "snippet": snippet}, out)
        else:
            review_view.write_lines(review_view.render(result, choices), out)
    except review_choices.ChoicesRefused as exc:
        err.write(f"zoeymcp review: {exc.reason}: {review_view.untrusted(exc)}\n")
        return review_view.EXIT_COULD_NOT_RUN
    except ValueError as exc:  # a UsageError, or a name the policy can't hold
        err.write(f"zoeymcp review: {review_view.untrusted(exc)}\n")
        return review_view.EXIT_COULD_NOT_RUN
    return review_view.exit_code(result)


def _classified(changes: review_view.Changes) -> str:
    """``the file includes 3 tools (2 allow, 1 approve) and takes out 1``, for stderr."""
    kinds = [added.classification for added in changes.added.values()]
    count = len(kinds)
    said = (
        f"the file includes {count} tool{'' if count == 1 else 's'} ({kinds.count('allow')} "
        f"allow, {kinds.count('approve')} approve)"
    )
    if changes.dropped:
        said += f", takes out {len(changes.dropped)}"
    if changes.moved:
        said += f", classifies {len(changes.moved)} anew"
    if changes.declined is not None:
        said += f", and leaves {len(changes.declined)} declined"
    return said


def _cmd_gateway_status(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    try:
        status = admin_client.gateway_status(admin_client.gateway_socket_path(args.socket))
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp gateway-status: {exc}\n")
        return EXIT_UNREADABLE
    if args.server is not None and args.server not in status["servers"]:
        err.write(f"zoeymcp gateway-status: no gateway server named {args.server!r}\n")
        return EXIT_UNREADABLE
    if args.format == "json":
        if args.server is not None:
            status = {**status, "servers": {args.server: status["servers"][args.server]}}
        review_view.write_json(status, out)
    else:
        review_view.write_lines(review_view.status_lines(status, args.server), out)
    return EXIT_OK


def _cmd_ledger(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    if args.vault:
        return _cmd_vault_ledger(args, stdin, out, err)
    if args.restart_chain or args.before is not None:
        err.write("zoeymcp ledger: --restart-chain and --before go with --vault\n")
        return EXIT_UNREADABLE
    socket = admin_client.gateway_socket_path(args.socket)
    if args.action not in (None, "check"):
        err.write("zoeymcp ledger: the only action is 'check REF FILE'\n")
        return EXIT_UNREADABLE
    try:
        if args.action == "check":
            if args.ref is None or args.file is None:
                err.write("zoeymcp ledger: check takes REF FILE\n")
                return EXIT_UNREADABLE
            try:
                arguments = json.loads(Path(args.file).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                err.write(f"zoeymcp ledger: can't read {args.file}: {exc}\n")
                return EXIT_UNREADABLE
            result = admin_client.gateway_ledger_check(socket, args.ref, arguments)
            ledger_view.write(out, ledger_view.check_lines(result))
            return EXIT_OK if result["matches"] else EXIT_FINDINGS
        if args.ref is not None:
            err.write("zoeymcp ledger: a REF goes with check\n")
            return EXIT_UNREADABLE
        if args.verify:
            verified = admin_client.gateway_ledger_verify(socket)
            if args.format == "json":
                ledger_view.write_json(out, [verified])
            else:
                ledger_view.write(out, ledger_view.verify_lines(verified))
            return EXIT_OK if verified["ok"] else EXIT_FINDINGS
        since = ledger_view.since_ms(args.since)
        records = admin_client.gateway_ledger(
            socket, client=args.client, server=args.server, tool=args.tool
        )
    except ledger_view.UsageError as exc:
        err.write(f"zoeymcp ledger: {exc}\n")
        return EXIT_UNREADABLE
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp ledger: {exc}\n")
        return EXIT_UNREADABLE
    if args.format == "json":
        kept = [r for r in records if since is None or r["ts"] >= since]
        ledger_view.write_json(out, kept)
    else:
        ledger_view.write(out, ledger_view.lines(records, since=since))
    return EXIT_OK


def _cmd_vault_ledger(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    """``ledger --vault [--restart-chain] [--before SEQ]``: the vault's reported copy."""
    gateway_only = (args.action, args.ref, args.since, args.client, args.server, args.tool)
    if any(value is not None for value in gateway_only) or args.verify:
        err.write("zoeymcp ledger: --vault takes only --restart-chain, --before and --format\n")
        return EXIT_UNREADABLE
    socket = admin_client.socket_path(args.socket)
    try:
        if args.restart_chain:
            return _restart_chain(socket, stdin, out, err)
        page = admin_client.vault_ledger(socket, before=args.before)
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp ledger: {exc}\n")
        return EXIT_UNREADABLE
    if args.format == "json":
        review_view.write_json(page, out)
    else:
        review_view.write_lines(ledger_view.vault_lines(page), out)
    state = page["state"]
    return EXIT_OK if state["state"] == "ok" and state["broken_at"] is None else EXIT_FINDINGS


def _restart_chain(socket: str, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    """Show the restart's plan, ask, then run exactly that plan."""
    plan = admin_client.vault_ledger_restart(socket, {"dry_run": True})["plan"]
    review_view.write_lines(ledger_view.restart_lines(plan), out)
    out.write("Restart the chain? [y/N] ")
    out.flush()
    if stdin.readline().strip().lower() not in ("y", "yes"):
        err.write("zoeymcp ledger: not restarted\n")
        return EXIT_FINDINGS
    try:
        done = admin_client.vault_ledger_restart(socket, {"plan": plan})["restarted"]
    except admin_client.AdminUnavailable as exc:
        if exc.reason != "changed":
            raise
        err.write("zoeymcp ledger: the copy changed since this plan; nothing was done; run again\n")
        return EXIT_FINDINGS
    archive = done["archive"]
    where = "nothing to archive" if archive is None else f"archived as {archive['name']}"
    out.write(f"restarted: {where}; the next report starts a new chain\n")
    return EXIT_OK


# --- login and oauth ---------------------------------------------------------------------------


def _cmd_login(
    args: argparse.Namespace, argv: Sequence[str], stdin: TextIO, out: TextIO, err: TextIO
) -> int:
    from . import onboard as onboard_cli

    socket = admin_client.socket_path(args.socket)
    if args.mcp is not None:

        def connect(credential: str, shown: TextIO) -> int:
            # D.12 step 3: the login a named credential gets, with --rebind passed through.
            return _login(socket, credential, args.rebind, None, False, stdin, shown, err)

        return onboard_cli.login_mcp(
            args, argv, stdin, out, err, connect=connect, environ=os.environ
        )
    problem = onboard_cli.without_mcp(args)
    if problem is not None:
        err.write(f"zoeymcp login: {problem}\n")
        return EXIT_UNREADABLE
    return _login(socket, args.credential, args.rebind, args.flow, args.start, stdin, out, err)


def _login(
    socket: str,
    credential: str,
    rebind: bool,
    flow: str | None,
    start: bool,
    stdin: TextIO,
    out: TextIO,
    err: TextIO,
) -> int:
    from ..vault.oauth.pkce import FLOW_TTL

    try:
        if flow is not None:
            url = _read_paste(socket, flow, stdin, err)
            if url is None:
                return EXIT_FINDINGS
            result = admin_client.oauth_complete(socket, credential, flow, url)
            return _report_login(credential, result, out, err)
        started = admin_client.oauth_login(socket, credential, rebind=rebind)
        if "flow" not in started:
            return _report_test_fetch(credential, started, out, err)
        _describe_login(credential, started, out)
        minutes = round(FLOW_TTL / 60)
        if start:
            out.write(
                f"\nThen, within {minutes} minutes, run: zoeymcp login {credential} "
                f"--flow={started['flow']}\nand give it the address your browser was sent to.\n"
            )
            return EXIT_OK
        how = "input hidden" if stdin.isatty() else "one line on stdin"
        if started.get("callback_address"):
            # The redirect_uri is the portal's callback address (M5 design H.6), which takes
            # only a login started in the portal, so the tab lands on its refused page.
            out.write(
                "\nYour browser will land on the portal's callback, which doesn't take a "
                "command-line login:\ncopy the full address from that tab's address bar and "
                f"paste it here ({how}, {minutes} minutes):\n"
            )
        else:
            out.write(
                f"\nYour browser will then try to open {started['redirect_uri']}?... and fail to "
                "load. That is\nexpected. Copy the full address from the address bar and paste "
                f"it here ({how}, {minutes} minutes):\n"
            )
        out.flush()
        url = _read_paste(socket, started["flow"], stdin, err)
        if url is None:
            return EXIT_FINDINGS
        result = admin_client.oauth_complete(socket, credential, started["flow"], url)
        return _report_login(credential, result, out, err)
    except admin_client.AdminUnavailable as exc:
        _report_login_error(exc, err)
        return EXIT_FINDINGS


def _read_paste(socket: str, flow: str, stdin: TextIO, err: TextIO) -> str | None:
    """The pasted address. Without one (Ctrl-C, end of input, an empty line) the flow is
    cancelled, and the result is None after an interruption."""
    try:
        return admin_client.read_redirect_url(stdin, PASTE_PROMPT)
    except (KeyboardInterrupt, EOFError, admin_client.AdminUnavailable) as exc:
        with contextlib.suppress(admin_client.AdminUnavailable):
            admin_client.oauth_cancel(socket, flow)
        if isinstance(exc, admin_client.AdminUnavailable):
            raise
        err.write("zoeymcp login: cancelled\n")
        return None


def _describe_login(credential: str, started: dict[str, Any], out: TextIO) -> None:
    # An older vault's answer has no "replaced". A login started here replaces any pending one
    # silently, as before; only the portal's is worth a line.
    if started.get("replaced") == "portal":
        out.write("Replaced a login pending in the portal.\n")
    client = "public client" if started["client_auth"] == "none" else "confidential client"
    rotation = "rotating" if started["rotates"] else "non-rotating"
    oauth = started["binding"]["oauth"]
    scopes = " ".join(started["requested_scopes"]) or "(none requested)"
    out.write(f"Credential   {credential} ({client}, PKCE S256, {rotation} refresh tokens)\n")
    out.write(f"Binding      token endpoint {oauth['token']}\n")
    out.write(f"             access tokens to {', '.join(oauth['resources'])}\n")
    change = started["binding_change"]
    if change is not None:
        out.write(f"Rebinding    was {admin_client.describe_binding(change['old'])}\n")
    out.write(f"Scopes       {scopes}\n")
    out.write(f"\nOpen this URL in a browser and approve:\n  {started['authorize_url']}\n")


def _report_scopes(result: dict[str, Any], out: TextIO, err: TextIO) -> None:
    out.write(f"Granted: {' '.join(result['granted_scopes']) or '(no scopes)'}\n")
    if result["unexpected_scopes"]:
        err.write(f"UNEXPECTED: {' '.join(result['unexpected_scopes'])}\n")
    if result["missing_scopes"]:
        err.write(f"missing: {' '.join(result['missing_scopes'])}\n")


def _report_login(credential: str, result: dict[str, Any], out: TextIO, err: TextIO) -> int:
    out.write(f"Stored the refresh token for {credential} as {result['slot']}.\n")
    _report_scopes(result, out, err)
    for key, text in (
        ("grant_expires_at", "The grant ends at"),
        ("refresh_expires_at", "The refresh token expires at"),
    ):
        if result[key] is not None:
            out.write(f"{text} {result[key]}; run login again before then.\n")
    if result["seed_note"] is not None:
        out.write(f"{result['seed_note']}\n")
    if not result["persisted"]:
        err.write(f"zoeymcp login: {NOT_PERSISTED}\n")
        return EXIT_FINDINGS
    return EXIT_OK


def _report_test_fetch(credential: str, result: dict[str, Any], out: TextIO, err: TextIO) -> int:
    out.write(
        f"The client credentials of {credential} work: the token endpoint issued an access "
        f"token for {result['access_expires_in']} s. Nothing was stored.\n"
    )
    _report_scopes(result, out, err)
    return EXIT_OK


def _report_login_error(exc: admin_client.AdminUnavailable, err: TextIO) -> None:
    err.write(f"zoeymcp login: {exc}\n")
    data = exc.data
    if exc.reason == "binding_changed":
        err.write(f"  old: {admin_client.describe_binding(data['old'])}\n")
        err.write(f"  new: {admin_client.describe_binding(data['new'])}\n")
    elif exc.reason == "provider_error" and data.get("description"):
        err.write(f"  the provider says: {data['description']}\n")


def _cmd_oauth(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    socket = admin_client.socket_path(args.socket)
    try:
        if args.action == "reset":
            admin_client.oauth_reset(socket, args.credential)
            out.write(f"reset {args.credential}: the next request that needs a token tries once\n")
            return EXIT_OK
        entries = admin_client.oauth_status(socket)["credentials"]
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp oauth {args.action}: {exc}\n")
        return EXIT_FINDINGS
    if args.credential is not None:
        entries = [e for e in entries if e["credential"] == args.credential]
        if not entries:
            err.write(f"zoeymcp oauth status: no oauth2 credential named {args.credential!r}\n")
            return EXIT_FINDINGS
    if not entries:
        out.write("no oauth2 credentials\n")
    for entry in entries:
        out.write("".join(f"{line}\n" for line in format_status(entry)))
    return EXIT_OK


def format_status(entry: dict[str, Any]) -> list[str]:
    """The lines ``oauth status`` prints for one credential."""
    head = f"{entry['credential']}: {entry['state']}"
    if entry["code"]:
        head += f" {entry['code']}"
    if entry["refreshing"]:
        head += " (refreshing)"
    lines = [head]
    if entry.get("hint"):
        lines.append(f"  hint: {entry['hint']}")
    if entry["retry_in"] is not None:
        lines.append(f"  retry in {duration(entry['retry_in'])}")
    if entry["access_expires_in"] is not None:
        lines.append(f"  access token expires in {duration(entry['access_expires_in'])}")
    if entry.get("last_ok_ago") is not None:
        lines.append(f"  last success {duration(entry['last_ok_ago'])} ago")
    if entry.get("reconsent_due"):
        lines.append(f"  WARNING re-consent due by {entry['reconsent_due']}")
    scopes = entry.get("scopes") or {}
    if scopes.get("unexpected"):
        lines.append(f"  UNEXPECTED scopes: {' '.join(scopes['unexpected'])}")
    if scopes.get("missing"):
        lines.append(f"  missing scopes: {' '.join(scopes['missing'])}")
    upstream = entry.get("upstream")
    if upstream:
        lines.append(f"  WARNING an upstream said {upstream['code']} at {upstream['at']}")
    if entry.get("last_failure") or entry.get("idle"):
        from ..vault.health import failure_text, idle_text

        if entry.get("last_failure"):
            text = failure_text(entry["last_failure"])
            lines.append(f"  WARNING {text} {FROM_META}")
        if entry.get("idle"):
            lines.append(f"  WARNING {idle_text(entry['idle'])} {FROM_META}")
    if not entry["persisted"]:
        lines.append(
            "  degraded (not persisted): the store can't be written; check the state volume"
        )
    return lines


# --- health ------------------------------------------------------------------------------------


def _cmd_health(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    try:
        report = admin_client.health(admin_client.socket_path(args.socket))
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp health: {exc}\n")
        return EXIT_UNREADABLE
    summary = report["summary"]
    failed = summary["error"] or (args.strict and summary["warning"])
    code = EXIT_FINDINGS if failed else EXIT_OK
    if args.json:
        review_view.write_json(report, out)
    else:
        review_view.write_lines(health_lines(report, ok=code == EXIT_OK), out)
    return code


def health_lines(report: dict[str, Any], *, ok: bool) -> list[str]:
    """The lines ``health`` prints: per credential, connector and the store, its findings, each
    with what to do, then the routes with no credential the guard refused (``egress``, only when
    there are some), the passkeys, the ledger copy and what the gateway reports (``gateway``, M6
    design M.5), then the counts."""
    lines: list[str] = []
    for item in report["credentials"]:
        lines.append(f"{item['name']} ({item['kind']}): {item['level']}")
        lines += _finding_lines(item["findings"])
    for item in report["connectors"]:
        head = f"connector {item['name']}: {item['level']}"
        if item["sent_24h"] is not None:
            head += f" ({item['sent_24h']} of {item['max_per_day']} sends in 24 h)"
        lines.append(head)
        lines += _finding_lines(item["findings"])
    store = report["store"]
    lines.append(f"store: {store['level']} ({store['entries']} entries)")
    lines += _finding_lines(store["findings"])
    egress = report.get("egress")
    if egress is not None and egress["findings"]:
        lines.append(f"egress: {egress['level']}")
        lines += _finding_lines(egress["findings"])
    passkeys = report.get("passkeys")
    if passkeys is not None:
        count = (
            "can't be verified" if passkeys["count"] is None else f"{passkeys['count']} enrolled"
        )
        lines.append(f"passkeys: {passkeys['level']} ({count})")
        lines += _finding_lines(passkeys["findings"])
    copy = report.get("ledger_copy")
    if copy is not None:
        head = "nothing reported" if copy["head_seq"] is None else f"head seq {copy['head_seq']}"
        lines.append(f"ledger copy: {copy['level']} ({copy['state']}, {head})")
        lines += _finding_lines(copy["findings"])
    policy = report.get("policy")
    if policy is not None:
        revision = policy["revision"]
        said = policy["mode"] if revision is None else f"{policy['mode']}, revision {revision}"
        lines.append(f"policy: {policy['level']} ({said})")
        lines += _finding_lines(policy["findings"])
    gateway = report.get("gateway")
    if gateway is not None:
        ago = gateway["reported_ago"]
        said = "no status yet" if ago is None else f"the gateway reported {duration(ago)} ago"
        lines.append(f"gateway: {gateway['level']} ({said})")
        lines += _finding_lines(gateway["findings"])
    counts = report["summary"]
    lines.append(
        f"health: {'ok' if ok else 'FAILED'} ({counts['error']} error(s), "
        f"{counts['warning']} warning(s), {counts['info']} info)"
    )
    return lines


def _finding_lines(findings: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for finding in findings:
        line = f"  {finding['level']:<8}{finding['code']}: {finding['text']}"
        if finding["advisory"]:
            line += f" {FROM_META}"
        lines.append(line)
        action = health_action(finding["action"])
        if action is not None:
            lines.append(f"          {action}")
    return lines


def health_action(action: dict[str, str] | None) -> str | None:
    """An action in the CLI's words: its own command, or what to do."""
    if action is None:
        return None
    ref = action.get("ref", "")
    fields = {
        "secret": ref.removeprefix("store:"),
        "var": ref.removeprefix("env:"),
        **action,
    }
    template = HEALTH_ACTIONS.get(action["kind"])
    # An action this CLI doesn't know (a newer vault's): its kind.
    return action["kind"] if template is None else template.format_map(fields)


def duration(seconds: float) -> str:
    """A rough, readable length of time."""
    value = int(seconds)
    if value < 120:
        return f"{value} s"
    if value < 2 * 3600:
        return f"{value // 60} min"
    if value < 2 * 86400:
        return f"{value // 3600} h"
    return f"{value // 86400} days"


def _cmd_selftest(args: argparse.Namespace, stdin: TextIO, out: TextIO) -> int:
    import asyncio

    from pydantic import ValidationError

    from ..common.yamlload import YAMLRejected
    from ..selftest import runner
    from ..selftest.cases import parse_cases

    try:
        text, source = read_source(args.config, os.environ, stdin)
        policy = parse_policy(text, source)
    except PolicyError as exc:
        _report(exc.source, exc.findings, "text", out, readable=exc.readable)
        return EXIT_UNREADABLE
    errors = [f for f in check_policy(policy) if f.level == "error"]
    if errors:
        _report(source, errors, "text", out)
        return EXIT_UNREADABLE
    try:
        cases = parse_cases(Path(args.cases).read_text(encoding="utf-8"))
    except (OSError, YAMLRejected, ValidationError) as exc:
        print(f"zoeymcp selftest: can't use {args.cases}: {exc}", file=out)
        return EXIT_UNREADABLE

    with runner.temporary_state() as state:
        rig = runner.Rig(policy, Path(state))
        results = asyncio.run(rig.run(policy, cases))
        for result in results:
            print(f"{'PASS' if result.ok else 'FAIL'}  {result.name}", file=out)
            for problem in result.problems:
                print(f"        {problem}", file=out)
        failed = sum(not r.ok for r in results)
        print(f"{len(results) - failed}/{len(results)} cases passed", file=out)
        if failed:
            return EXIT_FINDINGS
        if args.mutate:
            report = asyncio.run(runner.mutate(policy, cases, rig))
            total = len(report.killed) + len(report.survived)
            print(f"mutants: {len(report.killed)}/{total} killed", file=out)
            for description in report.survived:
                print(f"SURVIVED  {description}", file=out)
            if report.survived:
                return EXIT_FINDINGS
    return EXIT_OK


def _report(
    source: str, findings: list[Finding], fmt: str, out: TextIO, *, readable: bool = True
) -> None:
    errors = sum(1 for f in findings if f.level == "error")
    warnings = len(findings) - errors
    if fmt == "json":
        json.dump(
            {
                "source": source,
                "readable": readable,
                "ok": readable and errors == 0,
                "errors": errors,
                "warnings": warnings,
                "findings": [f.as_dict() for f in findings],
            },
            out,
            indent=2,
        )
        out.write("\n")
        return
    for finding in findings:
        out.write(f"{finding.level:<8}{finding.path}: {finding.message}\n")
    verdict = "ok" if readable and errors == 0 else "FAILED"
    out.write(f"{source}: {verdict} ({errors} error(s), {warnings} warning(s))\n")


def _cmd_check(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    emit = args.emit_egress_allowlist
    if not emit and (args.allowlist_format or args.squid_src or args.compare):
        err.write(
            "zoeymcp check: --allowlist-format, --squid-src and --check go with "
            "--emit-egress-allowlist\n"
        )
        return EXIT_UNREADABLE
    if args.squid_src and (args.allowlist_format or "text") != "squid":
        err.write("zoeymcp check: --squid-src goes with --allowlist-format squid\n")
        return EXIT_UNREADABLE
    if (args.indent is not None or args.target) and not args.print_merged:
        err.write("zoeymcp check: --indent and --for go with --print-merged\n")
        return EXIT_UNREADABLE
    if args.print_merged and not args.fragments:
        err.write("zoeymcp check: --print-merged goes with --with\n")
        return EXIT_UNREADABLE
    if args.fragments and emit:
        err.write("zoeymcp check: --with and --emit-egress-allowlist are separate runs\n")
        return EXIT_UNREADABLE
    if args.indent is not None and not 0 <= args.indent <= policy_emit.INDENT_MAX:
        err.write(f"zoeymcp check: --indent is 0 to {policy_emit.INDENT_MAX}\n")
        return EXIT_UNREADABLE
    if args.fragments:
        return _check_with(args, stdin, out, err)
    # A value's shape is a usage error whatever the policy holds, so it is checked before the
    # policy is read; whether SOURCE is one of the policy's sources waits for derive's lists.
    for item in args.squid_src:
        source, equals, acl = item.partition("=")
        if not equals or not source or not fields.is_squid_acl_name(acl):
            err.write(
                f"zoeymcp check: --squid-src {item}: write SOURCE=ACL, ACL 1 to 64 letters, "
                "digits or underscores\n"
            )
            return EXIT_UNREADABLE
    # The allowlist goes to stdout, so the findings go to stderr (I.6).
    findings_out = err if emit else out
    try:
        text, source = read_source(args.config, os.environ, stdin)
        policy = parse_policy(text, source)
    except PolicyError as exc:
        _report(exc.source, exc.findings, args.format, findings_out, readable=exc.readable)
        return EXIT_FINDINGS if exc.readable else EXIT_UNREADABLE
    findings = check_policy(policy, environ=os.environ if args.resolve_env else None)
    _report(source, findings, args.format, findings_out)
    if any(f.level == "error" for f in findings):
        return EXIT_FINDINGS
    return _emit_egress_allowlist(args, policy, out, err) if emit else EXIT_OK


def _check_with(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    """``check --with`` (M7 design H.4, GR-1): the policy with each fragment merged by the
    function the vault runs, then checked; with ``--print-merged``, the merged policy."""
    # stdout holds the merged policy with --print-merged, and one JSON document with --format
    # json; the findings, and the lines about the source and the merge, go to stderr then.
    findings_out = err if args.print_merged else out
    notes = err if args.print_merged or args.format == "json" else out
    try:
        text, source = read_source(args.config, os.environ, stdin)
    except PolicyError as exc:
        _report(exc.source, exc.findings, args.format, findings_out, readable=exc.readable)
        return EXIT_UNREADABLE
    # Which policy was read, so a check against the wrong base shows (OPS-17).
    notes.write(f"policy from {source.removeprefix('$')}, {len(text.encode()):,} bytes\n")
    try:
        data = load_mapping(text)
    except ValueError as exc:
        _report(source, [Finding("(document)", "error", str(exc))], args.format, findings_out)
        return EXIT_FINDINGS
    flags: list[Finding] = []
    added: list[policy_merge.Path] = []
    replaced: list[policy_merge.Path] = []
    for name in args.fragments:
        try:
            fragment_text = Path(name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            err.write(f"zoeymcp check: can't read {name}: {exc}\n")
            return EXIT_UNREADABLE
        flags += dollar_flags(name, fragment_text)
        try:
            fragment = load_mapping(fragment_text)
            replace = policy_merge.replace_paths(fragment_text)
        except ValueError as exc:
            _report(name, [Finding("(document)", "error", str(exc))], args.format, findings_out)
            return EXIT_FINDINGS
        merged = policy_merge.merge(data, fragment, replace=replace)
        if isinstance(merged, policy_merge.MergeConflict):
            found = Finding(policy_merge.describe(merged.path), "error", merged.message)
            _report(name, [found], args.format, findings_out)
            return EXIT_FINDINGS
        data = merged.data
        added += merged.added
        replaced += merged.replaced
    names = listed([Path(name).name for name in args.fragments])
    label = f"{source} with {names} merged"
    try:
        policy = validate_policy(data, label)
    except PolicyError as exc:
        # What the fragments added or replaced helps most when the result doesn't load.
        findings = flags + exc.findings
        notes.write(merge_line(names, findings, added, replaced))
        _report(exc.source, findings, args.format, findings_out)
        return EXIT_FINDINGS
    findings = flags + check_policy(policy, environ=os.environ if args.resolve_env else None)
    notes.write(merge_line(names, findings, added, replaced))
    _report(label, findings, args.format, findings_out)
    if any(f.level == "error" for f in findings):
        return EXIT_FINDINGS
    if args.print_merged:
        err.write(
            "zoeymcp check: the merged policy is printed whole, so the comments of the policy "
            "and the fragments are dropped\n"
        )
        if args.config is None:
            # Compose substituted the inline policy's variables before the vault read it.
            err.write(
                f"zoeymcp check: {CONFIG_ENV} is read as compose substituted it, so a value it "
                "took from a variable (gateway_key_generation, the portal's origin port) is "
                "printed as its current value; restore each ${...} reference before replacing "
                "the block\n"
            )
        target: policy_emit.Target = args.target or "plain"
        out.write(policy_emit.document(data, indent=args.indent or 0, target=target))
    return EXIT_OK


def dollar_flags(name: str, text: str) -> list[Finding]:
    """A warning for each line of a fragment holding a ``$``, which compose would read as a
    variable in an inline ``ZOEYMCP_CONFIG`` (TI-1)."""
    return [
        Finding(
            f"{name} line {number}",
            "warning",
            "holds a $, which compose reads as a variable in an inline ZOEYMCP_CONFIG; merge "
            "the compose form (--for compose) there",
        )
        for number, line in enumerate(text.splitlines(), start=1)
        if "$" in line
    ]


def merge_line(
    names: str,
    findings: Sequence[Finding],
    added: Sequence[policy_merge.Path],
    replaced: Sequence[policy_merge.Path],
) -> str:
    """``check --with``'s line before the findings: their counts, and what the fragments did."""
    errors = sum(1 for f in findings if f.level == "error")
    return (
        f"with {names} merged: {counted(errors, 'error')}, "
        f"{counted(len(findings) - errors, 'warning')}; {merge_summary(added, replaced)}\n"
    )


def merge_summary(added: Sequence[policy_merge.Path], replaced: Sequence[policy_merge.Path]) -> str:
    """What the fragments add and replace, as ``check --with`` says it."""
    adds = listed([policy_merge.describe(path) for path in added]) or "nothing"
    if not replaced:
        return f"it adds {adds} and changes nothing that exists"
    return f"it adds {adds} and replaces {listed([policy_merge.describe(p) for p in replaced])}"


def listed(items: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``; nothing for no items."""
    if len(items) < 2:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def counted(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _emit_egress_allowlist(
    args: argparse.Namespace, policy: Policy, out: TextIO, err: TextIO
) -> int:
    """``check --emit-egress-allowlist`` (M7 design I.6): the lists ``egresslist.derive`` gives
    the egress role, in one form, or with ``--check FILE`` how FILE differs from that form."""
    fmt: egresslist.Format = args.allowlist_format or "text"
    lists = egresslist.derive(policy)
    acl_names = dict(policy.egress_proxy_acls)
    for item in args.squid_src:
        source, _, acl = item.partition("=")
        if source not in lists:
            err.write(
                f"zoeymcp check: --squid-src {item}: SOURCE is one of {', '.join(sorted(lists))}\n"
            )
            return EXIT_UNREADABLE
        acl_names[source] = acl
    if args.compare is None:
        out.write(egresslist.render(lists, fmt, acl_names=acl_names))
        return EXIT_OK
    try:
        found = Path(args.compare).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        err.write(f"zoeymcp check: can't read {args.compare}: {exc}\n")
        return EXIT_UNREADABLE
    differences = egresslist.compare(lists, found, fmt, acl_names=acl_names)
    for line in differences:
        out.write(line + "\n")
    if differences:
        out.write(
            f"{args.compare}: out of date ({len(differences)} difference(s)); regenerate it "
            "with check --emit-egress-allowlist\n"
        )
        return EXIT_FINDINGS
    out.write(f"{args.compare}: matches the policy's egress allowlist\n")
    return EXIT_OK


def gateway_command(
    argv: Sequence[str], *, environment: Path = GATEWAY_ENVIRONMENT, prefix: str | None = None
) -> list[str] | None:
    """The command that runs ``zoeymcp <argv>`` in the gateway's environment, or None to run it
    in this process: when this is that environment, or it doesn't exist (a development checkout)."""
    python = environment / "bin" / "python"
    if not python.is_file():
        return None
    if Path(sys.prefix if prefix is None else prefix).resolve() == environment.resolve():
        return None
    # -I: no PYTHON* variables, no user site-packages, no current directory on the path.
    return [str(python), "-I", "-m", "zoeymcp", *argv]


def exec_gateway_environment(argv: Sequence[str]) -> None:
    """Replace this process with ``zoeymcp <argv>`` in the gateway's environment, if there is one
    to move to. Returns only when the command should run here."""
    command = gateway_command(argv)
    if command is not None:
        os.execv(command[0], command)  # noqa: S606 - a fixed interpreter, no shell


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["gateway"]:
        exec_gateway_environment(argv)
    args = _build_parser().parse_args(argv)
    stdin, out, err = stdin or sys.stdin, out or sys.stdout, err or sys.stderr
    if args.command == "check":
        return _cmd_check(args, stdin, out, err)
    if args.command == "keygen":
        return _cmd_keygen(out)
    if args.command == "client-token":
        return _cmd_client_token(out, err)
    if args.command == "vault":
        return _cmd_vault(args, err)
    if args.command == "gateway":
        return _cmd_gateway(args, err)
    if args.command == "egress":
        return _cmd_egress(args, err)
    if args.command == "bridge":
        return _cmd_bridge(args, err)
    if args.command == "standard":
        return _cmd_standard(args, err)
    if args.command == "selftest":
        return _cmd_selftest(args, stdin, out)
    if args.command in ("secret", "gateway-key", "egress-key"):
        return _cmd_admin(args, stdin, out, err)
    if args.command == "setup-code":
        return _cmd_setup_code(args, out, err)
    if args.command == "passkeys":
        return _cmd_passkeys(args, out, err)
    if args.command == "sessions":
        return _cmd_sessions(args, out, err)
    if args.command == "review":
        return _cmd_review(args, stdin, out, err)
    if args.command == "gateway-status":
        return _cmd_gateway_status(args, out, err)
    if args.command == "ledger":
        return _cmd_ledger(args, stdin, out, err)
    if args.command == "login":
        return _cmd_login(args, argv, stdin, out, err)
    if args.command == "oauth":
        return _cmd_oauth(args, out, err)
    if args.command == "health":
        return _cmd_health(args, out, err)
    raise AssertionError(f"unhandled command {args.command}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
