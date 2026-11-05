"""``zoeymcp`` entry point."""

from __future__ import annotations

import argparse
import base64
import contextlib
import difflib
import json
import os
import secrets
import sys
from collections.abc import Iterable, Mapping, Sequence
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
# The portal's sign-in screen's button that takes a setup code (portal/static/index.html).
SETUP_BUTTON = "I have a setup code"
# keygen's one line on stderr: where each key goes, and that nothing was written.
KEYGEN_NOTE = (
    "Set ZOEYMCP_MASTER_KEY in the vault's environment and keep a copy; the hardened tier's "
    "gateway takes ZOEYMCP_GATEWAY_KEY, which the standard tier doesn't need. Nothing was written."
)
NO_SECRETS = "No secrets stored. Store one with: zoeymcp secret set NAME"
NO_PASSKEYS = "No passkeys: the portal waits for a setup code. Issue one with: zoeymcp setup-code"
NO_OAUTH = "No oauth2 credentials in the policy."
# The source read_source names when no policy was given.
NO_SOURCE = "(none)"
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
    "list_approvals": "run: zoeymcp approvals list",
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
    "acknowledge_restore": "re-apply and review as it says, then run: zoeymcp policy "
    "acknowledge-restore",
}

# check and selftest of a managed document, on stderr (M6 design M.6): they run in a throwaway
# container with no socket, so what they read is the document they are given, never the head.
NOT_THE_HEAD = (
    "checking this document, not the running revision: to check what runs, pipe zoeymcp policy "
    "export into this command with --config -"
)

# The image's second virtual environment, the only one with the gateway's dependencies.
GATEWAY_ENVIRONMENT = Path("/opt/zoeymcp-gateway")
# The bridge's options the launcher sets first, each refused a second time (M7 design C.8, C.10).
BRIDGE_ONCE = ("--listen", "--peer-uid", "--work-dir", "--control-fd")


class _Formatter(argparse.RawDescriptionHelpFormatter):
    """Descriptions and epilogs as written (two short lines, then examples), and a flag that
    parses a value only to refuse it (:class:`_NoValue`) shown bare."""

    def _format_args(self, action: argparse.Action, default_metavar: str) -> str:
        if isinstance(action, _NoValue):
            return ""
        return super()._format_args(action, default_metavar)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if isinstance(action, _NoValue):
            return ", ".join(action.option_strings)
        return super()._format_action_invocation(action)

    def _format_usage(self, *args: Any, **kwargs: Any) -> str:
        return (
            super()._format_usage(*args, **kwargs).replace("--client-secret ]", "--client-secret]")
        )


class _NoValue(argparse.Action):
    """``--client-secret``: a flag, which parses a value (``--client-secret=VALUE`` included) only
    so that ``login --mcp`` refuses it without echoing it, as argparse's own error would (D.10,
    OPS-4)."""

    def __init__(self, option_strings: Sequence[str], dest: str, **kwargs: Any) -> None:
        super().__init__(option_strings, dest, nargs="?", const=True, default=False, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        setattr(namespace, self.dest, values)


# ``zoeymcp --help``'s commands, by when an operator reaches for them, and where each runs
# (M8 UX pass, D3). Every command is in exactly one group (tests/unit/test_cli.py).
COMMAND_GROUPS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    (
        "First run (any container, e.g. docker run --rm; nothing is written):",
        (
            ("keygen", "print a new master key and its gateway key"),
            ("client-token", "print an agent's client token, and its hash for the policy"),
            ("check", "validate a policy document"),
            ("selftest", "test a policy's routes against echo upstreams"),
        ),
    ),
    (
        "Then, in the vault's container:",
        (
            ("setup-code", "issue a one-time code that enrols a portal passkey"),
            ("secret", "store, list or delete the secrets the policy names"),
            ("login", "sign in to an OAuth credential, or onboard an MCP server by URL"),
            ("egress-key", "print the egress role's key (hardened tier)"),
        ),
    ),
    (
        "Every day (in the vault's container, unless it says otherwise):",
        (
            ("health", "what needs you, and what to do about it"),
            ("approvals", "the calls held for approval: list, show, withdraw"),
            ("review", "a server's tools, pins and drift (either container)"),
            (
                "gateway-status",
                "the gateway's view, each server's state (in the gateway's container)",
            ),
            ("ledger", "the approval ledger (in the gateway's container; --vault in the vault's)"),
            ("oauth", "the OAuth credentials' state, and a reset after a failure"),
            ("passkeys", "list the portal's passkeys, or remove one"),
            ("sessions", "list the portal's sessions, or end them all"),
            ("approver", "enrol the Telegram approver, or test it"),
            ("gateway-key", "print the gateway key, for a rotation"),
        ),
    ),
    (
        "The policy (managed mode, in the vault's container):",
        (("policy", "head, history, diff, export, import, rollback, seed, acknowledge-restore"),),
    ),
)
# The roles the image's entrypoint starts; nobody types them.
ROLE_COMMANDS = ("vault", "gateway", "egress", "bridge", "standard")
EXIT_CODES = (
    "Exit codes, for every command: 0 done; 1 findings, refused, declined or nothing to do;\n"
    "2 a usage error, or it can't run (the admin socket can't be reached, the vault isn't running)."
)


def _epilog() -> str:
    """``zoeymcp --help``'s guide: where the commands run, the commands by group, the exit
    codes and where the how-to is."""
    lines = [
        "Where they run: a vault command in the vault's container, a gateway command in the",
        "gateway's, from the host as",
        f"  {admin_client.STANDARD_COMPOSE_CMD} exec {admin_client.STANDARD_SERVICE} zoeymcp "
        "COMMAND          (standard tier)",
        f"  {admin_client.DEFAULT_COMPOSE_CMD} exec vault zoeymcp COMMAND   (hardened tier)",
        "In the hardened tier, a gateway command takes exec gateway.",
    ]
    for title, members in COMMAND_GROUPS:
        lines += ["", title, *(f"  {name:<16}{summary}" for name, summary in members)]
    lines += [
        "",
        "Roles (the image's entrypoint runs them): " + ", ".join(ROLE_COMMANDS),
        "",
        EXIT_CODES,
        "",
        "docs/operations.md is the how-to; zoeymcp COMMAND --help gives a command's options.",
    ]
    return "\n".join(lines)


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


FORMAT_HELP = "text (the default), or json: one JSON document on stdout"
VAULT_SOCKET_HELP = f"the vault's admin socket (default ${SOCKET_ENV} or {DEFAULT_SOCKET})"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zoeymcp",
        description="Credential vault and MCP gateway for AI agents.",
        epilog=_epilog(),
        formatter_class=_Formatter,
    )
    parser.add_argument("--version", action="version", version=f"zoeymcp {__version__}")
    # No command has a help line: the epilog lists them by group instead.
    commands = parser.add_subparsers(
        dest="command", required=True, metavar="command", help="one of the commands below"
    )

    def command(name: str, description: str, epilog: str | None = None) -> argparse.ArgumentParser:
        return commands.add_parser(
            name, description=description, epilog=epilog, formatter_class=_Formatter
        )

    check = command(
        "check",
        "Validate a policy document: its schema, cross-references and security rules (any\n"
        f"container). It reads --config FILE, --config - (stdin) or ${CONFIG_ENV}.",
        "With --emit-egress-allowlist it prints the destinations an egress proxy must allow, and\n"
        "the findings on stderr. With --with it checks the policy with each fragment merged as\n"
        "the vault merges it.\n\n"
        "Examples:\n"
        "  zoeymcp check --config policy.yaml\n"
        "  zoeymcp check --config policy.yaml --with onboard-notes-1.yaml --print-merged\n"
        "  zoeymcp check --config - --emit-egress-allowlist --allowlist-format squid < policy.yaml",
    )
    check.add_argument("--config", metavar="FILE", help="policy file, or - for stdin")
    check.add_argument("--format", choices=("text", "json"), default="text", help=FORMAT_HELP)
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

    command(
        "keygen",
        "Print a new ZOEYMCP_MASTER_KEY and its generation-1 ZOEYMCP_GATEWAY_KEY (any container).\n"
        "Set them as deployment secrets: nothing is written to disk.",
        "Example:\n  docker run --rm zoeymcp:local keygen",
    )

    command(
        "client-token",
        "Print a new client token for an agent, and its token_sha256 for the policy (any\n"
        "container). The agent sends the token as Authorization: Bearer; the policy holds a hash.",
        "The token_sha256 line goes under gateway.clients.<name> in the policy. Nothing is\n"
        "written to disk.\n\n"
        "Example:\n  docker run --rm zoeymcp:local client-token",
    )

    vault = command(
        "vault",
        "Run the vault, the only role that holds secrets (the image's entrypoint runs it).\n"
        f"It needs ZOEYMCP_MASTER_KEY and a policy: --config FILE, --config - or ${CONFIG_ENV}.",
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

    gateway = command(
        "gateway",
        "Run the gateway, the MCP server agents connect to (the image's entrypoint runs it).\n"
        "It holds no secret: everything upstream goes through the vault, which serves its view.",
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

    egress = command(
        "egress",
        "Run the egress role, a CONNECT-only proxy held to the vault's allowlists (hardened tier;\n"
        "the image's entrypoint runs it). Each listener allows only its source's host:port list.",
        "It long-polls the lists from the vault with the egress key (ZOEYMCP_EGRESS_KEY or\n"
        "ZOEYMCP_EGRESS_KEY_FILE). It refuses every tunnel until it has a list, and again once\n"
        "its list is 300 s old.",
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
        formatter_class=_Formatter,
        description=(
            "Run a bridge: one stdio MCP program, after --, served as a Streamable HTTP upstream\n"
            "(the image's entrypoint or a compose command: line runs it)."
        ),
        epilog=(
            "The program starts with a built environment, and /mcp answers only a caller with\n"
            "the route's token (its sha256 in ZOEYMCP_BRIDGE_TOKEN_SHA256). With --ready-check,\n"
            "exit 0 once the bridge's readiness probe passed, 1 before."
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

    standard = command(
        "standard",
        "Run the standard tier: the vault and the gateway in one container, as two uids (the\n"
        "image's entrypoint, PID 1 of a container started as root).",
        "The container runs with cap_drop: [ALL], cap_add: [SETUID, SETGID] and\n"
        "no-new-privileges. It starts the vault as uid 10001 and the gateway as uid 10002, linked\n"
        "by a Unix socket, and each --bridge as uid 10100 and up, then drops to uid 10003 with an\n"
        "empty environment and supervises them.",
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

    secret = command(
        "secret",
        "Store, list or delete the secrets the policy names (in the vault's container).\n"
        "A value is never printed, and never read from the command line.",
        "Examples:\n"
        "  printf '%s' \"$API_KEY\" | zoeymcp secret set notes-key\n"
        "  zoeymcp secret list",
    )
    secret_commands = secret.add_subparsers(dest="action", required=True, metavar="action")
    secret_set = secret_commands.add_parser(
        "set",
        help="store or replace a secret; the value is read from stdin or a hidden prompt",
        formatter_class=_Formatter,
        description=(
            "Store or replace a secret (in the vault's container). The value is read from stdin,\n"
            "or a hidden prompt on a terminal, never from the command line."
        ),
        epilog=(
            "Its binding comes from the policy unless --origin is given; an OAuth secret always\n"
            "takes the policy's binding.\n\n"
            "Example:\n  printf '%s' \"$API_KEY\" | zoeymcp secret set notes-key"
        ),
    )
    secret_set.add_argument("name", help="the secret's name, as the policy's store:NAME says it")
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
    secret_commands.add_parser(
        "list",
        help="list secret names and bindings (never values)",
        description="Each secret's name, when it was updated and its binding; never a value.",
    )
    secret_delete = secret_commands.add_parser(
        "delete",
        help="delete a secret",
        description="Delete a secret from the store (in the vault's container). It doesn't ask.",
    )
    secret_delete.add_argument("name", help="the secret to delete")

    selftest = command(
        "selftest",
        "Test a policy's routes against echo upstreams, with dummy secrets (any container),\n"
        "checking each case in --cases. --mutate also reports weakenings no case notices.",
        "With --mutate it breaks the policy one rule at a time and reports each break no case\n"
        "catches.\n\n"
        "Example:\n  zoeymcp selftest --config policy.yaml --cases cases.yaml --mutate",
    )
    selftest.add_argument("--config", metavar="FILE", help="policy file, or - for stdin")
    selftest.add_argument("--cases", metavar="FILE", required=True, help="cases file (YAML)")
    selftest.add_argument("--mutate", action="store_true", help="also mutation-test the cases")

    setup_code = command(
        "setup-code",
        "Print a one-time code that enrols a portal passkey (in the vault's container). It works\n"
        f"once, for 15 minutes: open the portal, choose {SETUP_BUTTON}, and type it.",
        "It replaces any earlier code. Enrolling with it adds a passkey; with --reset, it removes\n"
        "every other passkey and ends every session. --state writes the code into a state\n"
        "directory instead, with the vault stopped: it needs ZOEYMCP_MASTER_KEY, and not root.\n\n"
        "Example:\n  zoeymcp setup-code --wait",
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
    passkeys = command(
        "passkeys",
        "List the portal's passkeys: fingerprint, how and where each was enrolled, when last used\n"
        "(in the vault's container). --remove takes one out, the last one too; it doesn't ask.",
        "With no passkey left, the portal waits for a setup code (zoeymcp setup-code).",
    )
    passkeys.add_argument(
        "--remove", metavar="FINGERPRINT", help="remove this passkey and end its sessions"
    )
    sessions = command(
        "sessions",
        "List the portal's sessions, one a line, or end them all (in the vault's container).\n"
        "--end-all ends every session, including any you are signed in with; it doesn't ask.",
    )
    sessions.add_argument(
        "--end-all",
        action="store_true",
        help="end every portal session, including any you are signed in with",
    )
    sessions.add_argument("--format", choices=("text", "json"), default="text", help=FORMAT_HELP)
    gateway_key = command(
        "gateway-key",
        "Print the gateway key for the current gateway_key_generation (in the vault's container).\n"
        "After a bump, a 'rotation pending' line on stderr says how long the previous key works.",
        "The previous key stays accepted until the gateway first uses the new one, for at most 5\n"
        "minutes. --retire-previous stops accepting it at once.",
    )
    gateway_key.add_argument(
        "--retire-previous",
        action="store_true",
        help="stop accepting the previous key now, for a suspected leak",
    )
    command(
        "egress-key",
        "Print the egress role's key for the current egress_key_generation, as ZOEYMCP_EGRESS_KEY\n"
        "(in the vault's container). It reads the vault's allowlists and nothing else.",
        "After a bump the old key is refused at once, and the role refuses new tunnels within\n"
        "300 s until it has the new one.",
    )

    review = command(
        "review",
        "Review a server's tools on a fresh connection: per tool its state, pin, findings and any\n"
        "drift (either container). With no server, one line per server and no upstream call.",
        "In declarative mode it also prints a YAML snippet to commit; --add, --allow, --approve,\n"
        "--decline, --repin, --choose and --choices shape it. In managed mode it shows the review\n"
        "and the way to save it: the portal, or export, edit and import.\n"
        "In the vault's container, --via vault asks the gateway through the vault's review jobs\n"
        "and reads the last finished review again unless --fresh.\n\n"
        "Exit 0 when every included tool matches, nothing is marked and every listed tool is\n"
        "included or declined; 1 when something needs you; 2 when the review couldn't run.\n\n"
        "Examples:\n"
        "  zoeymcp review\n"
        "  zoeymcp review notes --show search_notes\n"
        "  zoeymcp review notes --choose --suggest > notes.choices    (declarative mode)",
    )
    review.add_argument(
        "server", nargs="?", help="the gateway server to review; none for one line per server"
    )
    review.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="TOOL",
        help="show only this tool (repeatable; a snippet still covers the whole server)",
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
        help="include TOOL in the snippet; you classify it as allow or approve (declarative mode)",
    )
    review.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="TOOL",
        help="include TOOL in the snippet as allow: agents call it with no prompt (declarative)",
    )
    review.add_argument(
        "--approve",
        action="append",
        default=[],
        metavar="TOOL",
        help="include TOOL in the snippet as approve: every call asks you first (declarative)",
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
        help="record TOOL as declined at its pin: left out, quiet until it changes (declarative)",
    )
    review.add_argument(
        "--decline-rest",
        action="store_true",
        help="record every listed tool the snippet doesn't include as declined at its pin",
    )
    review.add_argument(
        "--choose",
        action="store_true",
        help="print a choices file, one line per tool, to edit and read back (declarative mode)",
    )
    review.add_argument(
        "--suggest",
        action="store_true",
        help="with --choose: write allow on each tool the server marks read-only, skip elsewhere",
    )
    review.add_argument(
        "--choices",
        metavar="FILE",
        help="read an edited choices file (- for stdin) and print its snippet (declarative mode)",
    )
    review.add_argument(
        "--repin",
        action="append",
        default=[],
        metavar="TOOL",
        help="take a drifted tool's new pin in the snippet (the portal's Accept the new "
        "definition; declarative mode)",
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
    review.add_argument("--format", choices=("text", "json"), default="text", help=FORMAT_HELP)
    gateway_status = command(
        "gateway-status",
        "Print the gateway's view digest and, per server, its connections, era, tools, reports\n"
        "and drift marks (in the gateway's container). Never definitions or token hashes.",
    )
    gateway_status.add_argument("server", nargs="?", help="only this server")
    gateway_status.add_argument(
        "--format", choices=("text", "json"), default="text", help=FORMAT_HELP
    )
    ledger = command(
        "ledger",
        "List the approval ledger, one line per call: when, ref, client, server/tool, era,\n"
        "decision, outcome (in the gateway's container). Never argument values or prompt text.",
        "--verify walks the hash chain and prints its head, to compare with the last anchor in\n"
        "the logs. 'ledger check REF FILE' proves whether FILE (JSON) holds the arguments that\n"
        "call was made with, without the key leaving the gateway.\n"
        "--vault reads the vault's copy instead (in the vault's container), which the gateway\n"
        "reports to it, joined with the vault's own approval chain. --restart-chain archives that\n"
        "copy's chain after a fork, gap or full, once you have decided why; it asks first.\n\n"
        "Examples:\n"
        "  zoeymcp ledger --since 7d --server notes\n"
        "  zoeymcp ledger check 3f9c0a17b2d4e681 args.json\n"
        "  zoeymcp ledger --vault --chain both",
    )
    ledger.add_argument(
        "action", nargs="?", metavar="check", help="check: prove a call's arguments"
    )
    ledger.add_argument("ref", nargs="?", help="with check: the call's ref")
    ledger.add_argument("file", nargs="?", help="with check: a JSON file of the arguments")
    ledger.add_argument(
        "--since", metavar="AGE", help="only calls asked within AGE, like 7d, 12h or 30m"
    )
    ledger.add_argument("--client", metavar="CLIENT", help="only this client's calls")
    ledger.add_argument("--server", metavar="SERVER", help="only calls to this server")
    ledger.add_argument("--tool", metavar="TOOL", help="only calls of this tool")
    ledger.add_argument(
        "--verify", action="store_true", help="walk the hash chain (with --vault, the vault's)"
    )
    ledger.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text (the default), or json: one record a line (with --vault, one document)",
    )
    ledger.add_argument(
        "--vault", action="store_true", help="the vault's reported copy (in the vault's container)"
    )
    ledger.add_argument(
        "--restart-chain",
        action="store_true",
        help="with --vault: archive the copy's chain after a fork, gap or full (asks first)",
    )
    ledger.add_argument(
        "--before", type=int, metavar="SEQ", help="with --vault: the rows before this seq"
    )
    ledger.add_argument(
        "--chain",
        choices=("vault", "copy", "both"),
        help="with --vault: the vault's own approval chain, the reported copy, or both joined "
        "(the default)",
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

    approvals = command(
        "approvals",
        "The calls held for approval, as the host sees them: list, show, withdraw (in the vault's\n"
        "container). No command here approves: that takes a passkey in the portal, or Telegram.",
        "list (the default) shows those waiting and decided recently, by ref and approval id,\n"
        "never a text; show prints one's whole text; withdraw stops one, or every one with --all:\n"
        "nothing is sent, the messages are edited and the agents told.\n\n"
        "Examples:\n"
        "  zoeymcp approvals\n"
        "  zoeymcp approvals show 3f9c0a17b2d4e681\n"
        "  zoeymcp approvals withdraw --all",
    )
    approvals.set_defaults(action=None, key=None, all=False, format="text", socket=None)
    approvals_commands = approvals.add_subparsers(dest="action", metavar="action")
    approvals_list = approvals_commands.add_parser(
        "list",
        help="waiting and decided recently (the default)",
        description="The calls waiting, oldest first, and those decided recently; never a text.",
    )
    approvals_show = approvals_commands.add_parser(
        "show", help="one call's whole text", description="One held call, its text whole."
    )
    approvals_show.add_argument(
        "key", metavar="REF-OR-ID", help="the call's ref (16 hex digits) or its approval id"
    )
    approvals_withdraw = approvals_commands.add_parser(
        "withdraw",
        help="withdraw a waiting call, or every one with --all",
        description="Withdraw a waiting call, or every one with --all. Nothing is sent; it "
        "doesn't ask.",
    )
    approvals_withdraw.add_argument(
        "key",
        nargs="?",
        metavar="REF-OR-ID",
        help="the call's ref (16 hex digits) or its approval id",
    )
    approvals_withdraw.add_argument(
        "--all", action="store_true", help="withdraw every waiting call (emergency stop)"
    )
    approver = command(
        "approver",
        "Enrol the Telegram approver, or test it (in the vault's container).",
        "enrol finds the operator's Telegram ids: open the link it prints on the phone you will\n"
        "approve from, press Start, and type the confirmation code the bot sends. It prints the\n"
        "policy lines; with --apply in managed mode it plans a host import and asks first.\n"
        "test sends a message with no buttons: exit 0 when Telegram took it, 1 otherwise.\n\n"
        "Examples:\n"
        "  zoeymcp approver telegram enrol --secret telegram-bot --apply\n"
        "  zoeymcp approver telegram test",
    )
    approver_kinds = approver.add_subparsers(dest="kind", required=True, help="the approver")
    telegram = approver_kinds.add_parser(
        "telegram", help="the Telegram approver", description="The Telegram approver."
    )
    telegram_commands = telegram.add_subparsers(dest="action", required=True, metavar="action")
    telegram_enrol = telegram_commands.add_parser(
        "enrol",
        help="find the operator's ids with a one-time link and a confirmation code",
        description="Find the operator's Telegram ids with a one-time link and the confirmation "
        "code the bot sends, then print the policy lines.",
    )
    telegram_enrol.add_argument(
        "--secret", required=True, metavar="NAME", help="the store secret holding the bot's token"
    )
    telegram_enrol.add_argument(
        "--apply", action="store_true", help="in managed mode, plan a host import and ask"
    )
    telegram_test = telegram_commands.add_parser(
        "test",
        help="send a message with no buttons to the operator's chat",
        description="Send a message with no buttons to the operator's chat: exit 0 when Telegram "
        "took it, 1 otherwise.",
    )
    for sub in (approvals_list, approvals_show, approvals_withdraw, telegram_enrol, telegram_test):
        sub.add_argument("--format", choices=("text", "json"), default="text", help=FORMAT_HELP)
        sub.add_argument("--socket", metavar="PATH", help=VAULT_SOCKET_HELP)

    login = command(
        "login",
        "Sign in to an OAuth credential: open the printed URL, approve, and paste back the\n"
        "address the browser was sent to (in the vault's container).",
        "The paste is read from a hidden prompt, or one line of stdin. For the client_credentials\n"
        "grant, login is a test fetch.\n"
        "With --mcp URL instead of a credential (declarative mode), it onboards the MCP server at\n"
        "URL: the plan goes to stderr and, confirmed, fragment 1 for the policy to stdout. Run it\n"
        "again once the fragment is committed, to compare and sign in. In managed mode, add the\n"
        "server in the portal instead.\n\n"
        "Examples:\n"
        "  zoeymcp login calendar\n"
        "  zoeymcp login --mcp https://mcp.notes.example/mcp > onboard-notes-1.yaml",
    )
    target = login.add_mutually_exclusive_group(required=True)
    target.add_argument("credential", nargs="?", help="the oauth2 credential to sign in to")
    target.add_argument(
        "--mcp", metavar="URL", help="onboard the MCP server at URL (declarative mode)"
    )
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
    onboard.add_argument(
        "--credential",
        dest="credential_name",
        metavar="C",
        help="the name of the credential it creates (default: --name)",
    )
    onboard.add_argument(
        "--route", metavar="R", help="the name of the route it creates (default: --name)"
    )
    onboard.add_argument(
        "--server", metavar="S", help="the name of the gateway server it creates (default: --name)"
    )
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
    onboard.add_argument(
        "--client-secret",
        action=_NoValue,
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
    onboard.add_argument("--format", choices=("text", "json"), help=FORMAT_HELP)

    oauth = command(
        "oauth",
        "The OAuth credentials' state, and a reset after a failure (in the vault's container).\n"
        "Never a token or a secret.",
    )
    oauth_commands = oauth.add_subparsers(dest="action", required=True, metavar="action")
    oauth_status = oauth_commands.add_parser(
        "status",
        help="state, failures and warnings of each oauth2 credential (never values)",
        description="The state, failures and warnings of each oauth2 credential; never a value.",
    )
    oauth_status.add_argument("credential", nargs="?", help="only this credential")
    oauth_reset = oauth_commands.add_parser(
        "reset",
        help="clear a credential's failure state, so the next request tries once",
        description="Clear a credential's failure state, so the next request that needs a "
        "token tries once.",
    )
    oauth_reset.add_argument("credential", help="the oauth2 credential to reset")

    health = command(
        "health",
        "Print what needs you, per credential, connector and store entry, and what to do about\n"
        "it (in the vault's container). From metadata only: nothing is decrypted or sent.",
        "Exit 0 with no error (with --strict, no warning either), 1 otherwise, 2 when the vault\n"
        "can't be asked.\n\n"
        "Example:\n  zoeymcp health --strict --format json > /dev/null",
    )
    health.add_argument("--format", choices=("text", "json"), default="text", help=FORMAT_HELP)
    health.add_argument(
        "--json",
        action="store_const",
        const="json",
        dest="format",
        help="the same as --format json",
    )
    health.add_argument("--strict", action="store_true", help="also exit 1 for a warning")

    policy = command(
        "policy",
        "A managed policy's revisions, changed as the host (in the vault's container). With no\n"
        "action, the mode and the head. A write prints its plan and asks first, unless --yes.",
        "Over the vault's admin socket, or with --state DIR on its state directory with the vault\n"
        "stopped (as the vault's uid, with ZOEYMCP_MASTER_KEY).\n\n"
        "Examples:\n"
        "  zoeymcp policy history\n"
        "  zoeymcp policy export > policy.yaml\n"
        "  zoeymcp policy import - < policy.yaml",
    )
    policy.set_defaults(action=None, format="text", socket=None, state=None)
    policy_commands = policy.add_subparsers(dest="action", metavar="action")

    def policy_reader(parser: argparse.ArgumentParser, *, offline: bool = True) -> None:
        parser.add_argument("--socket", metavar="PATH", help=VAULT_SOCKET_HELP)
        if offline:
            parser.add_argument(
                "--state",
                metavar="DIR",
                help="offline: the vault's state directory, with the vault stopped",
            )

    policy_head = policy_commands.add_parser(
        "head",
        help="the mode, the head and the revision the gateway runs (the default)",
        description="The mode and, in managed mode, the head: when, how and by whom it was "
        "written, its deployment, and the revision the gateway runs.",
    )
    policy_head.add_argument("--format", choices=("text", "json"), default="text", help=FORMAT_HELP)
    policy_reader(policy_head, offline=False)
    policy_history = policy_commands.add_parser(
        "history",
        help="the kept revisions, newest first",
        description="The kept revisions, newest first: when, what made each and by whom, its "
        "base and the host's reason. A revision in quarantine shows as a gap.",
    )
    policy_history.add_argument("--before", type=int, metavar="N", help="older than revision N")
    policy_history.add_argument(
        "--limit", type=int, metavar="N", help="at most N revisions (1 to 50, 50 by default)"
    )
    policy_history.add_argument(
        "--format", choices=("text", "json"), default="text", help=FORMAT_HELP
    )
    policy_reader(policy_history)
    policy_diff = policy_commands.add_parser(
        "diff",
        help="what a revision changed, hidden fields hidden",
        description="What revision N changed from its parent (or from --against M), as the "
        "portal shows it: a hidden field only as set, changed or removed.",
    )
    policy_diff.add_argument("revision", type=int, metavar="N", help="the revision to show")
    policy_diff.add_argument("--against", type=int, metavar="M", help="another kept revision")
    policy_diff.add_argument("--format", choices=("text", "json"), default="text", help=FORMAT_HELP)
    policy_reader(policy_diff)
    policy_export = policy_commands.add_parser(
        "export",
        help="the policy as YAML to stdout, to edit and import (keep it like a secret)",
        formatter_class=_Formatter,
        description=(
            "The head's policy, or --revision N's, as YAML on stdout for policy import (notes on\n"
            "stderr). It holds placeholders and client token hashes: keep it like a secret."
        ),
        epilog=(
            "--mode declarative writes it to run declaratively; --for compose indents it for an\n"
            "inline ZOEYMCP_CONFIG with every $ as $$.\n\n"
            "Example:\n  zoeymcp policy export > policy.yaml"
        ),
    )
    policy_export.add_argument("--revision", type=int, metavar="N", help="a kept revision")
    policy_export.add_argument(
        "--mode", choices=("managed", "declarative"), default="managed", help="the mode it says"
    )
    policy_export.add_argument(
        "--for", dest="target", choices=("compose",), help="indented for an inline compose block"
    )
    policy_export.add_argument(
        "--force-tty", action="store_true", help="print it to a terminal anyway"
    )
    policy_reader(policy_export)
    policy_seed = policy_commands.add_parser(
        "seed",
        help="seed revision 1 on a state volume used before, from the policy given",
        description=(
            "Seed revision 1 of a managed policy on a state volume a vault used before, which "
            "the vault won't seed by itself: from --config, or ZOEYMCP_CONFIG."
        ),
    )
    policy_seed.add_argument(
        "--state", metavar="DIR", required=True, help="the vault's state directory"
    )
    policy_seed.add_argument("--config", metavar="FILE", help="policy file, or - for stdin")
    policy_seed.add_argument("--yes", action="store_true", help="write it without asking")

    def policy_writer(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--base", type=int, metavar="N", help="the revision it is planned on")
        parser.add_argument("--yes", action="store_true", help="write it without asking")
        parser.add_argument(
            "--accept-widening",
            action="store_true",
            help="with --yes, write a plan that widens the policy",
        )
        parser.add_argument("--reason", metavar="TEXT", help="kept with the revision")
        parser.add_argument(
            "--allow-revive",
            action="append",
            default=[],
            metavar="X",
            help="bring back client:NAME, caller:ROUTE/INDEX or pin:SERVER/KIND/NAME (repeatable)",
        )
        parser.add_argument(
            "--allow-env",
            action="append",
            default=[],
            metavar="NAME",
            help="allow env:NAME, new or sent somewhere new (repeatable)",
        )
        parser.add_argument(
            "--lockout-ok",
            action="store_true",
            help="with --yes, write a change that can lock the portal out",
        )
        parser.add_argument(
            "--revoke-removed",
            action="store_true",
            help="delete the store entries it leaves unused, and revoke their grants",
        )
        policy_reader(parser)

    policy_import = policy_commands.add_parser(
        "import",
        help="write the policy given as the next revision (or replace the store: --reseed)",
        formatter_class=_Formatter,
        description=(
            "Write the policy given (an edited export) as the next revision, planned on the\n"
            "revision its export header names, or --base N. It prints the plan and asks first."
        ),
        epilog=(
            "--from-env takes the vault's own ZOEYMCP_CONFIG; --baseline-only records it without\n"
            "applying it. With --state DIR --reseed, it replaces the store with the policy given,\n"
            "planned against the old head and what it retired when that head verifies (each\n"
            "revival needs its --allow-revive or --allow-env), or with --new-ratchet from the\n"
            "policy's own. The old files go to quarantine.\n\n"
            "Example:\n  zoeymcp policy import - < policy.yaml"
        ),
    )
    policy_import.add_argument(
        "source", nargs="?", metavar="FILE", help="policy file, or - for stdin"
    )
    policy_import.add_argument(
        "--from-env", action="store_true", help="the policy in ZOEYMCP_CONFIG instead"
    )
    policy_import.add_argument(
        "--baseline-only",
        action="store_true",
        help="with --from-env: record it as the seed's baseline, and apply nothing",
    )
    policy_import.add_argument(
        "--reseed", action="store_true", help="replace the store in --state, with the vault stopped"
    )
    policy_import.add_argument(
        "--new-ratchet",
        action="store_true",
        help="forget what the old store retired (listed), and start from the policy's own",
    )
    policy_writer(policy_import)
    policy_rollback = policy_commands.add_parser(
        "rollback",
        help="write a kept revision's content as the next revision",
        formatter_class=_Formatter,
        description=(
            "Write revision N's content as the next revision, with the head's key generations\n"
            "and pins and N's admin block (a lockout's way back). It prints the plan and asks."
        ),
        epilog=(
            "Each thing the store retired that it brings back needs its --allow-revive or\n"
            "--allow-env."
        ),
    )
    policy_rollback.add_argument(
        "revision", type=int, metavar="N", help="the kept revision whose content to write"
    )
    policy_writer(policy_rollback)
    policy_acknowledge = policy_commands.add_parser(
        "acknowledge-restore",
        help="record that you saw the restore the gateway's witness shows",
        formatter_class=_Formatter,
        description=(
            "Record that you saw a restore the gateway's witness shows (health's\n"
            "policy_behind_witness or policy_deployment_changed), so the finding clears."
        ),
        epilog=(
            "It writes a revision with the head's content, numbered one above the gateway's\n"
            "claim. The number is the gateway's: type it when asked, or give it with --to N."
        ),
    )
    policy_acknowledge.add_argument(
        "--to", type=int, metavar="N", help="the revision to jump to (required with --yes)"
    )
    policy_acknowledge.add_argument("--yes", action="store_true", help="write it without asking")
    policy_reader(policy_acknowledge)

    for sub in [*secret_commands.choices.values(), *oauth_commands.choices.values()]:
        sub.add_argument("--socket", metavar="PATH", help=VAULT_SOCKET_HELP)
    for name in (
        "setup-code",
        "passkeys",
        "sessions",
        "gateway-key",
        "egress-key",
        "login",
        "health",
    ):
        commands.choices[name].add_argument("--socket", metavar="PATH", help=VAULT_SOCKET_HELP)
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


def _cmd_keygen(out: TextIO, err: TextIO) -> int:
    from ..vault.keys import MASTER_KEY_ENV, KeySet, generate_master_key

    master = generate_master_key()
    keys = KeySet.from_text(master)
    out.write(f"{MASTER_KEY_ENV}={master}\n")
    out.write(f"ZOEYMCP_GATEWAY_KEY={keys.gateway_key(1)}\n")
    err.write(KEYGEN_NOTE + "\n")
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
                f"Stored {result['name']}, bound to "
                f"{admin_client.describe_binding(result['binding'])}.\n"
            )
        elif args.action == "list":
            entries = admin_client.secret_list(socket)["secrets"]
            if not entries:
                err.write(f"{NO_SECRETS}\n")
            for entry in entries:
                out.write(
                    f"{entry['name']}  updated {entry['updated']}  "
                    f"{admin_client.describe_binding(entry['binding'])}\n"
                )
        elif args.action == "delete":
            admin_client.secret_delete(socket, args.name)
            out.write(f"Deleted {args.name}.\n")
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp {args.command}: {exc}\n")
        return admin_client.exit_code(exc)
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


# --- the managed policy on the host (M6 design M.6) --------------------------------------------


def _cmd_policy(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    from . import policy as policy_cli

    return policy_cli.run(args, os.environ, stdin, out, err, as_root=running_as_root())


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
        return admin_client.exit_code(exc)
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
        where = f"Open the portal, choose {SETUP_BUTTON}, and type the code."
    elif origins:
        where = f"Open {' or '.join(origins)}, choose {SETUP_BUTTON}, and type the code."
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
        f"Enrolled {passkey['fingerprint']} on {passkey['origin']} as {passkey['name']} "
        f"at {at} UTC."
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
            out.write(f"Removed {lines[0]}\n{lines[1]}\n")
            remaining = result["remaining"]
            ended = counted(result["sessions_ended"], "session")
            out.write(f"{ended} ended; {counted(remaining, 'passkey')} left.\n")
            if remaining == 0:
                err.write(
                    "No passkey is left: the portal waits for a setup code (zoeymcp setup-code).\n"
                )
            return EXIT_OK
        listed = admin_client.passkeys(socket)["passkeys"]
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp passkeys: {exc}\n")
        return admin_client.exit_code(exc)
    if not listed:
        err.write(f"{NO_PASSKEYS}\n")
    for passkey in listed:
        out.write("".join(f"{line}\n" for line in passkey_lines(passkey)))
    return EXIT_OK


def _cmd_sessions(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    socket = admin_client.socket_path(args.socket)
    try:
        if args.end_all:
            answer = admin_client.sessions_end_all(socket)
            if args.format == "json":
                review_view.write_json(answer, out)
            else:
                out.write(f"Ended {counted(answer['ended'], 'portal session')}.\n")
            return EXIT_OK
        answer = admin_client.sessions(socket)
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp sessions: {exc}\n")
        return admin_client.exit_code(exc)
    if args.format == "json":
        review_view.write_json(answer, out)
        return EXIT_OK
    listed = answer["sessions"]
    if not listed:
        err.write("No portal sessions.\n")
    review_view.write_lines([session_line(session) for session in listed], out)
    return EXIT_OK


def session_line(session: Mapping[str, Any]) -> str:
    """One portal session, as ``passkeys`` shows a passkey: its fingerprint and scope, where and
    with which passkey it signed in, and when it began, was last seen and ends."""
    from ..vault.gatewaykeys import utc

    def when(key: str) -> str:
        value = session.get(key)
        return "unknown" if value is None else utc(value)

    return (
        f"{session.get('fingerprint', '?')}  {session.get('scope', '?')}  on "
        f"{session.get('origin', '?')}, passkey {session.get('credential', '?')}; signed in "
        f"{when('created')}, last seen {when('last_seen')}, ends {when('expires_at')}"
    )


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
            return admin_client.exit_code(exc)
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
            mode = review_view.answered_mode(exc.data)
            code = _review_output(exc.data["review"], choices, args, out, err, mode=mode)
            return max(code, review_view.EXIT_NEEDS_OPERATOR)
        err.write(f"zoeymcp review: {review_view.untrusted(exc)}\n")
        # The gateway's refusals are reviews that couldn't run, but for a name it doesn't know.
        if exc.reason == "unknown_server":
            return review_view.EXIT_NEEDS_OPERATOR
        return review_view.EXIT_COULD_NOT_RUN
    # The gateway's own socket keeps no job: the choices file names none. Its answer names the
    # mode the vault last stated (M6 design G.9), which is no part of the review: it is printed
    # alike through the vault, and the choices file's digest doesn't move with the mode.
    mode = review_view.answered_mode(result)
    report = {key: value for key, value in result.items() if key != "policy_mode"}
    return _review_output(
        report, choices, args, out, err, job=review_choices.NO_JOB, read=parsed, mode=mode
    )


def _picked(args: argparse.Namespace) -> bool:
    """Whether ``review``'s options include, classify, re-pin or decline a tool."""
    return bool(
        args.add
        or args.allow
        or args.approve
        or args.allow_read_only
        or args.repin
        or args.decline
        or args.decline_rest
    )


def _fragment_refused(
    mode: str, args: argparse.Namespace, err: TextIO, *, in_vault: bool = True
) -> int | None:
    """In managed mode, or with the mode ``unknown``, the options that make a fragment refuse
    (M6 design G.9, Y25): exit 1, naming the portal and the host's export and import, whose
    commands run in the vault's service when this container is the vault's (``in_vault``). None
    when the options make no fragment, or the mode is declarative."""
    if not _picked(args) and args.choices is None:
        return None
    from . import onboard as onboard_cli

    prefix = onboard_cli.Prefix.from_environ(os.environ)
    lines = onboard_cli.refused_lines("review", mode, prefix, in_vault=in_vault)
    if lines is None:
        return None
    review_view.write_lines(lines, err)
    return review_view.EXIT_NEEDS_OPERATOR


def _review_usage(args: argparse.Namespace) -> str | None:
    """What's wrong with ``review``'s options as given, before anything is asked."""
    picked = _picked(args)
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
    tool doesn't match its pin. Options that make a fragment first ask the vault's mode, and
    refuse in managed mode (G.9). The way on is the vault's ``next`` (M.7, D-200), on stderr:
    a refusal's, and a finished review's after its text (in its JSON, as ``next``), unless the
    options already made fragment 2, which is where a review's way on leads. A ``next`` that
    names a save is a managed vault's (Y25): the review prints no snippet to commit."""
    if args.server is None:
        # The summary is the gateway's status, which only its own socket answers.
        err.write("zoeymcp review: through the vault, name the server to review\n")
        return review_view.EXIT_COULD_NOT_RUN
    from . import onboard as onboard_cli

    socket = admin_client.socket_path(args.socket)
    prefix = onboard_cli.Prefix.from_environ(os.environ)
    if _picked(args) or args.choices is not None:
        try:
            mode = admin_client.policy_head(socket)["mode"]
        except admin_client.AdminUnavailable as exc:
            err.write(f"zoeymcp review: {review_view.untrusted(exc)}\n")
            return admin_client.exit_code(exc)
        refused = _fragment_refused(mode, args, err)
        if refused is not None:
            return refused
    choices = _review_choices(args)
    try:
        job = review_view.vault_review(socket, args.server, fresh=args.fresh, clear=args.clear)
    except admin_client.AdminUnavailable as exc:
        steps = exc.data.get("next") or []
        if exc.reason == "clear_not_clean" and isinstance(exc.data.get("report"), dict):
            # The gateway refused the clear: show what doesn't match, as --via gateway does, with
            # no snippet to commit in managed mode (Y25): the refusal names no mode, so ask. In
            # managed mode the vault's way on stands in the snippet's place; in declarative mode
            # it follows on stderr, as it always has.
            err.write(f"zoeymcp review: --clear refused: {review_view.untrusted(exc)}\n")
            try:
                mode = str(admin_client.policy_head(socket)["mode"])
            except admin_client.AdminUnavailable:
                mode = "declarative"  # as before the vault said: the review is read-only
            managed = mode == "managed"
            code = _review_output(
                exc.data["report"],
                choices,
                args,
                out,
                err,
                mode=mode,
                steps=steps if managed else None,
            )
            if not managed:
                review_view.write_lines(onboard_cli.next_lines(steps, prefix), err)
            return max(code, review_view.EXIT_NEEDS_OPERATOR)
        err.write(f"zoeymcp review: {review_view.untrusted(exc)}\n")
        review_view.write_lines(onboard_cli.next_lines(steps, prefix), err)
        if exc.data.get("state") == "failed":
            return review_view.EXIT_COULD_NOT_RUN  # the job ran and the review failed
        return admin_client.exit_code(exc)
    except review_view.StillRunning:
        err.write(
            "zoeymcp review: the review is still running in the gateway; run this again in a "
            "minute to read it\n"
        )
        return review_view.EXIT_COULD_NOT_RUN
    # Fragment 2, made here, is where a review's way on leads; a way on that saves is managed.
    steps = None if _picked(args) or parsed is not None else job.get("next")
    saved = any(step.get("do") == "save" for step in steps or ())
    return _review_output(
        job["report"],
        choices,
        args,
        out,
        err,
        job=job["job"],
        read=parsed,
        mode="managed" if saved else "declarative",
        steps=steps,
    )


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
    mode: str = "declarative",
    steps: Sequence[Mapping[str, Any]] | None = None,
) -> int:
    """Print the review as asked: the text and snippet, then the vault's ``steps`` on stderr (or
    JSON, with them as ``next`` when it gave them), the choices file (``--choose``), or the
    snippet a choices file makes (``--choices``); or, with options that make a fragment and
    ``mode`` not declarative, the refusal (M6 design G.9). In managed mode there is no snippet:
    the way on stands in its place, the vault's or, without it, the save, export and import
    (Y25, M.7)."""
    from . import onboard as onboard_cli

    in_vault = os.path.exists(admin_client.socket_path(None))
    refused = _fragment_refused(mode, args, err, in_vault=in_vault)
    if refused is not None:
        return refused
    managed = mode == "managed"
    if managed and steps is None:
        steps = onboard_cli.managed_steps(mode, in_vault=in_vault)
    if args.choose:
        lines = review_choices.render(result, job, suggest=args.suggest)
        review_view.write_lines(lines, out)
        return review_view.exit_code(result)
    try:
        if read is not None:
            changes = review_choices.decide(result, job, read)
            heading = review_view.second_title(
                result["server"],
                declined=changes.declined is not None,
                kinds=review_view.kind_blocks(result),
            )
            out.write(policy_emit.emit(review_view.fragment(result, changes, heading=heading)))
            err.write(
                f"zoeymcp review: {_classified(changes)}. Prove it with check --with, commit it "
                "and reload, then assign the server to its clients.\n"
            )
            return review_view.exit_code(result)
        review_view.check_choices(result, choices)
        if args.format == "json":
            document = dict(result)
            if not managed:
                document["snippet"] = review_view.snippet(result, choices)
            if steps is not None:
                document["next"] = list(steps)
            review_view.write_json(document, out)
        else:
            review_view.write_lines(review_view.render(result, choices, managed=managed), out)
            prefix = onboard_cli.Prefix.from_environ(os.environ)
            review_view.write_lines(onboard_cli.next_lines(steps or (), prefix), err)
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
        return admin_client.exit_code(exc)
    if args.server is not None and args.server not in status["servers"]:
        known = known_names(status["servers"])
        err.write(f"zoeymcp gateway-status: no gateway server named {args.server!r}; {known}\n")
        return EXIT_FINDINGS
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
    if args.restart_chain or args.before is not None or args.chain is not None:
        err.write("zoeymcp ledger: --restart-chain, --before and --chain go with --vault\n")
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
        return admin_client.exit_code(exc)
    if args.format == "json":
        kept = [r for r in records if since is None or r["ts"] >= since]
        ledger_view.write_json(out, kept)
    else:
        ledger_view.write(out, ledger_view.lines(records, since=since))
    return EXIT_OK


def _cmd_vault_ledger(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    """``ledger --vault [--restart-chain] [--before SEQ] [--chain C] [--verify]``: the vault's
    reported copy, joined with its own approval chain (M8 design K.3), or that chain's walk."""
    gateway_only = (args.action, args.ref, args.since, args.client, args.server, args.tool)
    if any(value is not None for value in gateway_only):
        err.write(
            "zoeymcp ledger: --vault takes only --restart-chain, --before, --chain, --verify and "
            "--format\n"
        )
        return EXIT_UNREADABLE
    if args.verify and (args.restart_chain or args.before is not None or args.chain is not None):
        err.write("zoeymcp ledger: --verify with --vault walks the vault chain, alone\n")
        return EXIT_UNREADABLE
    socket = admin_client.socket_path(args.socket)
    try:
        if args.verify:
            verified = admin_client.vault_ledger_verify(socket)
            if args.format == "json":
                ledger_view.write_json(out, [verified])
            else:
                ledger_view.write(out, ledger_view.verify_lines(verified))
            return EXIT_OK if verified["ok"] else EXIT_FINDINGS
        if args.restart_chain:
            return _restart_chain(socket, stdin, out, err)
        page = admin_client.vault_ledger(socket, before=args.before, chain=args.chain)
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp ledger: {exc}\n")
        return admin_client.exit_code(exc)
    if args.format == "json":
        review_view.write_json(page, out)
    else:
        review_view.write_lines(ledger_view.vault_lines(page), out)
    state = page["state"]
    return EXIT_OK if state["state"] == "ok" and state["broken_at"] is None else EXIT_FINDINGS


def _restart_chain(socket: str, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    """Show the restart's plan and ask, on stderr, then run exactly that plan."""
    plan = admin_client.vault_ledger_restart(socket, {"dry_run": True})["plan"]
    review_view.write_lines(ledger_view.restart_lines(plan), err)
    err.write("Restart the chain? [y/N] ")
    err.flush()
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
    out.write(f"Restarted: {where}; the next report starts a new chain.\n")
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
        # With --start the URL and the flow are the answer; else they lead to the prompt.
        said = out if start else err
        _describe_login(credential, started, said)
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
            err.write(
                "\nYour browser will land on the portal's callback, which doesn't take a "
                "command-line login:\ncopy the full address from that tab's address bar and "
                f"paste it here ({how}, {minutes} minutes):\n"
            )
        else:
            err.write(
                f"\nYour browser will then try to open {started['redirect_uri']}?... and fail to "
                "load. That is\nexpected. Copy the full address from the address bar and paste "
                f"it here ({how}, {minutes} minutes):\n"
            )
        err.flush()
        url = _read_paste(socket, started["flow"], stdin, err)
        if url is None:
            return EXIT_FINDINGS
        result = admin_client.oauth_complete(socket, credential, started["flow"], url)
        return _report_login(credential, result, out, err)
    except admin_client.AdminUnavailable as exc:
        _report_login_error(exc, err)
        return admin_client.exit_code(exc)


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
            out.write(f"Reset {args.credential}: the next request that needs a token tries once.\n")
            return EXIT_OK
        entries = admin_client.oauth_status(socket)["credentials"]
    except admin_client.AdminUnavailable as exc:
        err.write(f"zoeymcp oauth {args.action}: {exc}\n")
        return admin_client.exit_code(exc)
    if args.credential is not None:
        known = known_names(entry["credential"] for entry in entries)
        entries = [e for e in entries if e["credential"] == args.credential]
        if not entries:
            err.write(
                f"zoeymcp oauth status: no oauth2 credential named {args.credential!r}; {known}\n"
            )
            return EXIT_FINDINGS
    if not entries:
        err.write(f"{NO_OAUTH}\n")
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
        return admin_client.exit_code(exc)
    summary = report["summary"]
    failed = summary["error"] or (args.strict and summary["warning"])
    code = EXIT_FINDINGS if failed else EXIT_OK
    if args.format == "json":
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
    held = report.get("approvals")
    if held is not None:
        said = "the chain takes holds" if held["chain_writable"] else "the chain can't be written"
        if held["saturated"]:
            said += f", {held['saturated']} refused lately"
        lines.append(f"approvals: {held['level']} ({said})")
        telegram = held.get("telegram")
        if telegram is not None:
            lines.append(telegram_line(telegram, held["findings"]))
        lines += _finding_lines(held["findings"])
    counts = report["summary"]
    lines.append(
        f"health: {'ok' if ok else 'FAILED'} ({counted(counts['error'], 'error')}, "
        f"{counted(counts['warning'], 'warning')}, {counts['info']} info)"
    )
    return lines


def telegram_line(telegram: Mapping[str, Any], findings: list[dict[str, Any]]) -> str:
    """The Telegram approver's line (M8 design G.7, J1): its findings' level, its bot and its
    last good poll, as ``approver telegram: ok (@bot, last poll 3 s ago)``."""
    own = [finding for finding in findings if str(finding["code"]).startswith("approver_")]
    level = next(
        (lv for lv in ("error", "warning", "info") if any(f["level"] == lv for f in own)), "ok"
    )
    ago = telegram["last_poll_ago"]
    polled = "no poll yet" if ago is None else f"last poll {duration(ago)} ago"
    bot = telegram["username"]
    return f"approver telegram: {level} ({polled if bot is None else f'@{bot}, {polled}'})"


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


def _cmd_selftest(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    import asyncio

    from pydantic import ValidationError

    from ..common.yamlload import YAMLRejected
    from ..selftest import runner
    from ..selftest.cases import parse_cases

    try:
        text, source = read_source(args.config, os.environ, stdin)
        policy = parse_policy(text, source)
    except PolicyError as exc:
        _report(exc.source, exc.findings, "text", err, readable=exc.readable)
        return EXIT_UNREADABLE
    if policy.mode == "managed":
        err.write(f"zoeymcp selftest: {NOT_THE_HEAD}\n")
    errors = [f for f in check_policy(policy) if f.level == "error"]
    if errors:
        _report(source, errors, "text", err)
        return EXIT_UNREADABLE
    try:
        cases = parse_cases(Path(args.cases).read_text(encoding="utf-8"))
    except (OSError, YAMLRejected, ValidationError) as exc:
        err.write(f"zoeymcp selftest: can't use {args.cases}: {exc}\n")
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
    named = "no policy" if source == NO_SOURCE else source
    out.write(f"{named}: {verdict} ({counted(errors, 'error')}, {counted(warnings, 'warning')})\n")


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
    if policy.mode == "managed":
        err.write(f"zoeymcp check: {NOT_THE_HEAD}\n")
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
    if data.get("mode") == "managed":
        err.write(f"zoeymcp check: {NOT_THE_HEAD}\n")
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


counted = review_view.counted


def known_names(names: Iterable[str]) -> str:
    """The names there are, for a refusal of one that isn't: ``known: a, b`` or ``none known``."""
    found = sorted(names)
    return f"known: {', '.join(found)}" if found else "none known"


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
            f"{args.compare}: out of date ({counted(len(differences), 'difference')}); "
            "regenerate it with check --emit-egress-allowlist\n"
        )
        return EXIT_FINDINGS
    out.write(f"{args.compare}: matches the policy's egress allowlist\n")
    return EXIT_OK


def unknown_command(parser: argparse.ArgumentParser, argv: Sequence[str]) -> str | None:
    """What to say for a first word that is no command: the closest commands, if any are close,
    and where the list is. None when it is a command, or an option."""
    if not argv or argv[0].startswith("-"):
        return None
    names = next(
        action.choices
        for action in parser._actions  # argparse keeps its subparsers there
        if isinstance(action, argparse._SubParsersAction)
    )
    if argv[0] in names:
        return None
    close = difflib.get_close_matches(argv[0], list(names), n=3)
    guess = f"; did you mean {' or '.join(close)}?" if close else ";"
    return f"no command {argv[0]!r}{guess} zoeymcp --help lists every command"


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
    parser = _build_parser()
    unknown = unknown_command(parser, argv)
    if unknown is not None:
        parser.error(unknown)
    admin_client.INVOKED[:] = argv
    args = parser.parse_args(argv)
    stdin, out, err = stdin or sys.stdin, out or sys.stdout, err or sys.stderr
    if args.command == "check":
        return _cmd_check(args, stdin, out, err)
    if args.command == "keygen":
        return _cmd_keygen(out, err)
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
        return _cmd_selftest(args, stdin, out, err)
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
    if args.command == "policy":
        return _cmd_policy(args, stdin, out, err)
    if args.command == "approvals":
        from . import approvals as approvals_cli

        return approvals_cli.run(args, out, err)
    if args.command == "approver":
        from . import approver as approver_cli

        return approver_cli.run(args, stdin, out, err)
    raise AssertionError(f"unhandled command {args.command}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
