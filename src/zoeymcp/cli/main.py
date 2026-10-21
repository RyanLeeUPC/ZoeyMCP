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
from ..common.policy.schema import hash_token

# The vault's code is imported in the handlers that use it: ``python -m zoeymcp gateway`` runs
# this module in the gateway's process, which loads none of it.
from . import admin_client
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
}

# The image's second virtual environment, the only one with the gateway's dependencies.
GATEWAY_ENVIRONMENT = Path("/opt/zoeymcp-gateway")


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
            "instead, and the findings on stderr."
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

    standard = commands.add_parser(
        "standard",
        help="run the standard tier: the vault and the gateway in one container, as two uids",
        description=(
            "The standard tier's entrypoint, PID 1 of a container started as root with "
            "cap_drop: [ALL], cap_add: [SETUID, SETGID] and no-new-privileges. It starts the "
            "vault as uid 10001 and the gateway as uid 10002, linked by a Unix socket, then "
            "drops to uid 10003 with an empty environment and supervises them."
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

    review = commands.add_parser(
        "review",
        help="review a gateway server's tools and print pins to commit (inside the gateway)",
        description=(
            "Ask the running gateway to list a server's tools on a fresh connection and show, per "
            "tool, its state, pin and findings, a diff for drifted tools, and a YAML snippet for "
            "the policy. With no server, one line per server and no upstream call. Exit 0 when "
            "every included tool matches and nothing is marked, 1 when something needs you, 2 "
            "when the review couldn't run."
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
                f"{admin_client.GATEWAY_SOCKET}); with ledger --vault, the vault's"
            ),
        )

    login = commands.add_parser(
        "login",
        help="consent to an OAuth credential and store its refresh token (inside the vault)",
        description=(
            "Open the printed URL in a browser and approve. The browser is then sent to the "
            "credential's redirect_uri, which fails to load: paste that address back. It is read "
            "from a hidden prompt, or one line of stdin, never from the command line. For the "
            "client_credentials grant, login is a test fetch."
        ),
    )
    login.add_argument("credential")
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
    for name in ("setup-code", "passkeys", "sessions", "gateway-key", "login", "health"):
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


def _cmd_review(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    socket = admin_client.gateway_socket_path(args.socket)
    if args.server is None:
        if args.tool or args.show or args.all or args.add or args.repin or args.clear:
            err.write("zoeymcp review: these options need a server\n")
            return review_view.EXIT_COULD_NOT_RUN
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
    choices = review_view.Choices(
        tools=frozenset(args.tool),
        show=frozenset(args.show),
        show_all=args.all,
        add=tuple(dict.fromkeys(args.add)),
        repin=frozenset(args.repin),
    )
    try:
        result = admin_client.gateway_review(socket, args.server, clear=args.clear)
    except admin_client.AdminUnavailable as exc:
        if exc.reason == "not_clean" and isinstance(exc.data.get("review"), dict):
            # --clear refused: show what doesn't match, and why.
            err.write(f"zoeymcp review: --clear refused: {review_view.untrusted(exc)}\n")
            _print_review(exc.data["review"], choices, args.format, out)
            return review_view.EXIT_NEEDS_OPERATOR
        err.write(f"zoeymcp review: {review_view.untrusted(exc)}\n")
        return review_view.EXIT_COULD_NOT_RUN
    try:
        review_view.check_choices(result, choices)
    except review_view.UsageError as exc:
        err.write(f"zoeymcp review: {review_view.untrusted(exc)}\n")
        return review_view.EXIT_COULD_NOT_RUN
    _print_review(result, choices, args.format, out)
    return review_view.exit_code(result)


def _print_review(
    result: dict[str, Any], choices: review_view.Choices, fmt: str, out: TextIO
) -> None:
    if fmt == "json":
        review_view.write_json({**result, "snippet": review_view.snippet(result, choices)}, out)
    else:
        review_view.write_lines(review_view.render(result, choices), out)


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


def _cmd_login(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    from ..vault.oauth.pkce import FLOW_TTL

    socket = admin_client.socket_path(args.socket)
    try:
        if args.flow is not None:
            url = _read_paste(socket, args.flow, stdin, err)
            if url is None:
                return EXIT_FINDINGS
            result = admin_client.oauth_complete(socket, args.credential, args.flow, url)
            return _report_login(args.credential, result, out, err)
        started = admin_client.oauth_login(socket, args.credential, rebind=args.rebind)
        if "flow" not in started:
            return _report_test_fetch(args.credential, started, out, err)
        _describe_login(args.credential, started, out)
        minutes = round(FLOW_TTL / 60)
        if args.start:
            out.write(
                f"\nThen, within {minutes} minutes, run: zoeymcp login {args.credential} "
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
        result = admin_client.oauth_complete(socket, args.credential, started["flow"], url)
        return _report_login(args.credential, result, out, err)
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
    with what to do, then the counts."""
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
    if args.command == "standard":
        return _cmd_standard(args, err)
    if args.command == "selftest":
        return _cmd_selftest(args, stdin, out)
    if args.command in ("secret", "gateway-key"):
        return _cmd_admin(args, stdin, out, err)
    if args.command == "setup-code":
        return _cmd_setup_code(args, out, err)
    if args.command == "passkeys":
        return _cmd_passkeys(args, out, err)
    if args.command == "sessions":
        return _cmd_sessions(args, out, err)
    if args.command == "review":
        return _cmd_review(args, out, err)
    if args.command == "gateway-status":
        return _cmd_gateway_status(args, out, err)
    if args.command == "ledger":
        return _cmd_ledger(args, stdin, out, err)
    if args.command == "login":
        return _cmd_login(args, stdin, out, err)
    if args.command == "oauth":
        return _cmd_oauth(args, out, err)
    if args.command == "health":
        return _cmd_health(args, out, err)
    raise AssertionError(f"unhandled command {args.command}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
