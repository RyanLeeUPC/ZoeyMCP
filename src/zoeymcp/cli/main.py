"""``zoeymcp`` entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
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
from ..vault.keys import MASTER_KEY_ENV, KeySet, generate_master_key

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
    return parser


def _cmd_keygen(out: TextIO) -> int:
    master = generate_master_key()
    keys = KeySet.from_text(master)
    out.write(f"{MASTER_KEY_ENV}={master}\n")
    out.write(f"ZOEYMCP_GATEWAY_KEY={keys.gateway_key(1)}\n")
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
    argv: Sequence[str] | None = None, *, stdin: TextIO | None = None, out: TextIO | None = None
) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "check":
        return _cmd_check(args, stdin or sys.stdin, out or sys.stdout)
    if args.command == "keygen":
        return _cmd_keygen(out or sys.stdout)
    raise AssertionError(f"unhandled command {args.command}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
