"""``zoeymcp`` entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from .. import __version__
from ..common.policy import (
    CONFIG_ENV,
    Finding,
    PolicyError,
    check_policy,
    parse_policy,
    read_source,
)
from ..vault.admin import DEFAULT_SOCKET, SOCKET_ENV
from ..vault.keys import MASTER_KEY_ENV, KeySet, generate_master_key
from . import admin_client

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_UNREADABLE = 2


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
            f"Reads --config <file>, --config - (stdin) or ${CONFIG_ENV}."
        ),
    )
    check.add_argument("--config", metavar="FILE", help="policy file, or - for stdin")
    check.add_argument("--format", choices=("text", "json"), default="text")
    check.add_argument(
        "--resolve-env",
        action="store_true",
        help="also fail if an env: secret reference names a variable that isn't set",
    )

    commands.add_parser(
        "keygen",
        help="print a new master key and its generation-1 gateway key",
        description=(
            "Print a new ZOEYMCP_MASTER_KEY and the matching generation-1 ZOEYMCP_GATEWAY_KEY. "
            "Set them as deployment secrets; nothing is written to disk."
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
        help="address to listen on (repeatable; default 0.0.0.0:8080)",
    )
    vault.add_argument("--state", default="/state", metavar="DIR", help="state directory")
    vault.add_argument(
        "--admin-socket",
        metavar="PATH",
        help=f"admin Unix socket (default ${SOCKET_ENV} or {DEFAULT_SOCKET}); 'none' disables it",
    )

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
            "unless --origin is given."
        ),
    )
    secret_set.add_argument("name")
    secret_set.add_argument(
        "--origin", action="append", metavar="URL", help="bind to this origin (repeatable)"
    )
    secret_commands.add_parser("list", help="list secret names and bindings (never values)")
    secret_delete = secret_commands.add_parser("delete", help="delete a secret")
    secret_delete.add_argument("name")

    commands.add_parser("setup-code", help="issue a one-time portal setup code (15 minutes)")
    commands.add_parser("gateway-key", help="print the gateway key for the current generation")

    for sub in secret_commands.choices.values():
        sub.add_argument("--socket", metavar="PATH", help="admin socket path")
    for name in ("setup-code", "gateway-key"):
        commands.choices[name].add_argument("--socket", metavar="PATH", help="admin socket path")
    return parser


def _cmd_vault(args: argparse.Namespace, out: TextIO) -> int:
    from ..vault.server import StartupError, run

    admin_socket = None
    if args.admin_socket != "none":
        admin_socket = Path(admin_client.socket_path(args.admin_socket))
    try:
        run(
            args.config, args.listen or ["0.0.0.0:8080"], Path(args.state), os.environ, admin_socket
        )
    except StartupError as exc:
        out.write(f"zoeymcp vault: {exc}\n")
        return EXIT_UNREADABLE
    return EXIT_OK


def _cmd_keygen(out: TextIO) -> int:
    master = generate_master_key()
    keys = KeySet.from_text(master)
    out.write(f"{MASTER_KEY_ENV}={master}\n")
    out.write(f"ZOEYMCP_GATEWAY_KEY={keys.gateway_key(1)}\n")
    return EXIT_OK


def _cmd_admin(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
    socket = admin_client.socket_path(getattr(args, "socket", None))
    try:
        if args.command == "setup-code":
            result = admin_client.setup_code(socket)
            out.write(f"{result['code']}\n")
            err.write("One-time code, valid for 15 minutes.\n")
        elif args.command == "gateway-key":
            result = admin_client.gateway_key(socket)
            out.write(f"ZOEYMCP_GATEWAY_KEY={result['key']}\n")
            err.write(f"Generation {result['generation']}.\n")
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


def _cmd_check(args: argparse.Namespace, stdin: TextIO, out: TextIO) -> int:
    try:
        text, source = read_source(args.config, os.environ, stdin)
        policy = parse_policy(text, source)
    except PolicyError as exc:
        _report(exc.source, exc.findings, args.format, out, readable=exc.readable)
        return EXIT_FINDINGS if exc.readable else EXIT_UNREADABLE
    findings = check_policy(policy, environ=os.environ if args.resolve_env else None)
    _report(source, findings, args.format, out)
    return EXIT_FINDINGS if any(f.level == "error" for f in findings) else EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    args = _build_parser().parse_args(argv)
    stdin, out, err = stdin or sys.stdin, out or sys.stdout, err or sys.stderr
    if args.command == "check":
        return _cmd_check(args, stdin, out)
    if args.command == "keygen":
        return _cmd_keygen(out)
    if args.command == "vault":
        return _cmd_vault(args, err)
    if args.command in ("secret", "setup-code", "gateway-key"):
        return _cmd_admin(args, stdin, out, err)
    raise AssertionError(f"unhandled command {args.command}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
