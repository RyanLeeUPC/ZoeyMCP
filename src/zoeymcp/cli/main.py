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
from ..common.policy import (
    CONFIG_ENV,
    Finding,
    PolicyError,
    check_policy,
    parse_policy,
    read_source,
)
from ..common.policy.schema import hash_token
from ..vault.admin import DEFAULT_SOCKET, SOCKET_ENV
from ..vault.gatewaykeys import utc
from ..vault.keys import MASTER_KEY_ENV, KeySet, generate_master_key
from ..vault.oauth.pkce import FLOW_TTL
from . import admin_client

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_UNREADABLE = 2

CLIENT_TOKEN_PREFIX = "zgc1-"  # noqa: S105 - a format marker, not a secret
PASTE_PROMPT = "> "
NOT_PERSISTED = (
    "kept in memory, not on disk; fix the state volume; zoeymcp oauth status shows when it is saved"
)

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
        "--control-fd",
        type=int,
        metavar="FD",
        help="read HUP and TERM lines from this pipe; its end stops the gateway (the launcher's)",
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

    commands.add_parser("setup-code", help="issue a one-time portal setup code (15 minutes)")
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

    for sub in [*secret_commands.choices.values(), *oauth_commands.choices.values()]:
        sub.add_argument("--socket", metavar="PATH", help="admin socket path")
    for name in ("setup-code", "gateway-key", "login"):
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
    )
    try:
        run(options, os.environ)
    except StartupError as exc:
        out.write(f"zoeymcp gateway: {exc}\n")
        return EXIT_UNREADABLE
    return EXIT_OK


def _cmd_keygen(out: TextIO) -> int:
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
        if args.command == "setup-code":
            result = admin_client.setup_code(socket)
            out.write(f"{result['code']}\n")
            err.write("One-time code, valid for 15 minutes.\n")
        elif args.command == "gateway-key":
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


# --- login and oauth ---------------------------------------------------------------------------


def _cmd_login(args: argparse.Namespace, stdin: TextIO, out: TextIO, err: TextIO) -> int:
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
        out.write(
            f"\nYour browser will then try to open {started['redirect_uri']}?... and fail to "
            "load. That is\nexpected. Copy the full address from the address bar and paste it "
            f"here ({how}, {minutes} minutes):\n"
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
    if not entry["persisted"]:
        lines.append(
            "  degraded (not persisted): the store can't be written; check the state volume"
        )
    return lines


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
        return _cmd_check(args, stdin, out)
    if args.command == "keygen":
        return _cmd_keygen(out)
    if args.command == "client-token":
        return _cmd_client_token(out, err)
    if args.command == "vault":
        return _cmd_vault(args, err)
    if args.command == "gateway":
        return _cmd_gateway(args, err)
    if args.command == "selftest":
        return _cmd_selftest(args, stdin, out)
    if args.command in ("secret", "setup-code", "gateway-key"):
        return _cmd_admin(args, stdin, out, err)
    if args.command == "login":
        return _cmd_login(args, stdin, out, err)
    if args.command == "oauth":
        return _cmd_oauth(args, out, err)
    raise AssertionError(f"unhandled command {args.command}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
