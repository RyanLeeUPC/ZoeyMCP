"""``zoeymcp login --mcp URL``: onboarding by URL from the vault's container (M7 design D.10-D.12,
M.7). The vault does the work over its admin socket; this module asks, prompts and prints.

- **The first run** discovers (``POST /onboard/discover``) and prints the plan on stderr, every
  string from the network through :func:`.review.untrusted`; asks, unless ``--yes``, whether to
  use the client at that authorization server; reads a given client secret from a hidden prompt
  on a terminal, or with ``--yes`` from a piped stdin (never from argv, and never from the stdin
  a confirmation is read from: OPS-4); then ``register`` (with a secret, or with no client ID,
  when the vault registers one, D.4) or ``fragment`` (a given public client, PC-13) writes
  fragment 1 to stdout and the ``next`` list to stderr.
  ``--plan-only`` stops after the plan, which the next run with the same URL and names resumes.
- **The second run** (D.12): for a URL the running policy has onboarded, the vault compares what
  it finds with what is committed, and the CLI signs in with ``login``'s own paste flow, unless
  ``--no-connect`` or the credential already holds a refresh token (OPS-13), then prints what is
  next: until the vault queues reviews, ``review`` in the gateway's container.
- **Commands** in a ``next`` list are the vault's argument lists, shell-quoted (TI-14), printed
  after the prefix ``ZOEYMCP_COMPOSE_CMD`` names and the service ``ZOEYMCP_EXEC_SERVICE`` (or,
  for ``review``, ``ZOEYMCP_REVIEW_SERVICE``) names, as the entry's ``via`` says (OPS-17). A
  refusal by the operator's own proxy gets a ``retry`` command rebuilt from this run's argv
  (D.11), with ``--squid-src`` naming the vault's source ACL in its Squid lines (OPS-7).

``--format json`` prints the vault's answers as one ASCII JSON document on stdout instead
(D-171): ``discover``, then ``fragment`` or ``refused``.
"""

from __future__ import annotations

import argparse
import contextlib
import shlex
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, TextIO
from urllib.parse import urlsplit

from ..common.policy import fields
from ..common.policy.emit import INDENT_MAX
from ..vault.oauth import dcr
from ..vault.onboarding import ONBOARDING_TTL, fragment_file
from . import admin_client
from .review import untrusted, write_json

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

COMPOSE_CMD_ENV: Final = "ZOEYMCP_COMPOSE_CMD"
EXEC_SERVICE_ENV: Final = "ZOEYMCP_EXEC_SERVICE"
REVIEW_SERVICE_ENV: Final = "ZOEYMCP_REVIEW_SERVICE"
# The shipped hardened file's, when the container's environment names nothing (M.7).
DEFAULT_COMPOSE_CMD: Final = "docker compose -f deploy/compose.hardened.yaml"
DEFAULT_EXEC_SERVICE: Final = "vault"
DEFAULT_REVIEW_SERVICE: Final = "gateway"
# The onboarding's flags, which a login of a named credential doesn't take: (dest, flag).
ONBOARD_FLAGS: Final = (
    ("name", "--name"),
    ("credential_name", "--credential"),
    ("route", "--route"),
    ("server", "--server"),
    ("issuer", "--issuer"),
    ("scope", "--scope"),
    ("client_name", "--client-name"),
    ("client_id", "--client-id"),
    ("client_secret", "--client-secret"),
    ("client_auth", "--client-auth"),
    ("redirect_uri", "--redirect-uri"),
    ("callback_origin", "--callback-origin"),
    ("allow_private", "--allow-private"),
    ("plan_only", "--plan-only"),
    ("yes", "--yes"),
    ("reregister", "--reregister"),
    ("no_connect", "--no-connect"),
    ("squid_src", "--squid-src"),
    ("indent", "--indent"),
    ("target", "--for"),
    ("format", "--format"),
)
# The discovery body's string keys, from the flags of the same meaning (K.2, M.1).
BODY_KEYS: Final = (
    ("name", "name"),
    ("credential", "credential_name"),
    ("route", "route"),
    ("server", "server"),
    ("issuer", "issuer"),
    ("scope", "scope"),
    ("client_id", "client_id"),
    ("client_auth", "client_auth"),
    ("redirect_uri", "redirect_uri"),
    ("client_name", "client_name"),
    ("callback_origin", "callback_origin"),
)
# The Squid source an onboarding's lines are for: the vault's (D.11).
SQUID_SOURCE: Final = "vault"
# A sign-in the second run makes: the credential, and where its lines go. Its exit code.
Connect = Callable[[str, TextIO], int]


@dataclass(frozen=True)
class Prefix:
    """How a ``next`` command is run from the host (M.7): the compose command, the service this
    CLI runs in, and the gateway's, for ``review``."""

    compose: str = DEFAULT_COMPOSE_CMD
    service: str = DEFAULT_EXEC_SERVICE
    review: str = DEFAULT_REVIEW_SERVICE

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> Prefix:
        return cls(
            environ.get(COMPOSE_CMD_ENV) or DEFAULT_COMPOSE_CMD,
            environ.get(EXEC_SERVICE_ENV) or DEFAULT_EXEC_SERVICE,
            environ.get(REVIEW_SERVICE_ENV) or DEFAULT_REVIEW_SERVICE,
        )

    def line(self, command: str, via: str | None, *, piped: bool = False) -> str:
        """``command`` (already shell-quoted) as typed on the host, by its ``via``: in the
        running service (``-T`` when stdin is piped), the gateway's, a one-off container (with
        the working directory at /w), or the service recreated; with no ``via``, as it is."""
        service = shlex.quote(self.service)
        if via == "exec":
            return f"{self.compose} exec{' -T' if piped else ''} {service} {command}"
        if via == "exec_gateway":
            return f"{self.compose} exec {shlex.quote(self.review)} {command}"
        if via == "run":
            return f"{self.compose} run --rm --no-deps {service} {command}"
        if via == "run_mount":
            return f'{self.compose} run --rm --no-deps -v "$PWD:/w:ro" {service} {command}'
        if via == "up":
            return f"{self.compose} up -d {service}"
        return command


def step_lines(step: Mapping[str, Any], prefix: Prefix) -> list[str]:
    """One ``next`` entry: its label, and its command as typed on the host; an ``allow_hosts``
    entry's hosts and Squid lines under it."""
    label = untrusted(step.get("label") or step.get("do", ""))
    command, via = step.get("command"), step.get("via")
    if command is None and via is None:
        lines = [f"  {label}"]
    else:
        line = prefix.line(command or "", via, piped=bool(step.get("piped")))
        lines = [f"  {label}:", f"    {untrusted(line + step.get('redirect', ''))}"]
    lines += [f"    {untrusted(host)}" for host in step.get("hosts", [])]
    lines += [f"    {untrusted(squid)}" for squid in step.get("squid", [])]
    return lines


def next_lines(steps: Sequence[Mapping[str, Any]], prefix: Prefix) -> list[str]:
    if not steps:
        return []
    lines = ["Next:"]
    for step in steps:
        lines += step_lines(step, prefix)
    return lines


def plan_lines(answer: Mapping[str, Any]) -> list[str]:
    """The plan (D.8) as rows, and the draft check's findings (OPS-5)."""
    lines = [f"Discovering {untrusted(answer['plan']['server_url'])}"]
    for label, value in answer["rows"]:
        lines.append(f"  {untrusted(label):<23} {untrusted(value)}")
    findings = answer.get("draft_check") or []
    if findings:
        lines.append("check, with this server merged:")
        lines += finding_lines(findings)
    return lines


def finding_lines(findings: Sequence[Mapping[str, str]]) -> list[str]:
    return [f"  {f['level']:<8}{untrusted(f['path'])}: {untrusted(f['message'])}" for f in findings]


def with_source(lines: Sequence[str], acl: str) -> list[str]:
    """D.11's Squid lines with ``acl`` as the vault's source ACL (``--squid-src``, OPS-7): the
    third word of each ``http_access allow`` line, where ``egresslist.render`` writes it."""
    out = []
    for line in lines:
        words = line.split(" ")
        if words[:2] == ["http_access", "allow"] and len(words) > 2:
            words[2] = acl
        out.append(" ".join(words))
    return out


def discover_body(args: argparse.Namespace) -> dict[str, Any]:
    """The discovery's body (K.2, M.1): the URL, the names and options given, and whether a
    secret follows at register (D.7). Never the secret."""
    body: dict[str, Any] = {"url": args.mcp}
    for key, dest in BODY_KEYS:
        value = getattr(args, dest)
        if value is not None:
            body[key] = value
    for key, given in (
        ("allow_private", args.allow_private),
        ("secret_given", args.client_secret),
        ("reregister", args.reregister),
    ):
        if given:
            body[key] = True
    return body


def without_mcp(args: argparse.Namespace) -> str | None:
    """A login of a named credential given an onboarding's flags: what to say."""
    used = [flag for dest, flag in ONBOARD_FLAGS if getattr(args, dest) not in (None, False, [])]
    if not used:
        return None
    return f"{', '.join(used)} {'goes' if len(used) == 1 else 'go'} with --mcp"


def usage(
    args: argparse.Namespace, argv: Sequence[str], stdin: TextIO, prefix: Prefix
) -> str | None:
    """What doesn't fit together in a ``login --mcp`` run, or None (D.10)."""
    if args.client_secret not in (True, False):
        # Never echoed, and before anything that shows argv (OPS-4).
        return (
            "a client secret is never an argument: give --client-secret alone, and pipe the "
            "secret in with --yes or type it at the hidden prompt"
        )
    if args.start or args.flow is not None:
        return "--start and --flow go with a credential, not --mcp"
    if args.client_secret and args.client_id is None:
        return "--client-secret goes with --client-id"
    if args.client_secret and args.issuer is None:
        return (
            "--client-secret needs --issuer, the authorization server that issued the client: "
            "a discovered one that differs is refused"
        )
    if args.client_auth is not None and not args.client_secret:
        return "--client-auth goes with --client-secret"
    if args.reregister and args.no_connect:
        return "--no-connect goes with the run after the commit, not with --reregister"
    if args.indent is not None and not 0 <= args.indent <= INDENT_MAX:
        return f"--indent is 0 to {INDENT_MAX}"
    for item in args.squid_src:
        source, equals, acl = item.partition("=")
        if source != SQUID_SOURCE or not equals or not fields.is_squid_acl_name(acl):
            return (
                f"--squid-src {item}: write vault=ACL, ACL 1 to 64 letters, digits or underscores"
            )
    if args.client_secret and not stdin.isatty() and not args.yes:
        # OPS-4: a secret piped in leaves no stdin for the confirmation.
        command = shlex.join(["zoeymcp", *argv, "--yes"])
        piped = prefix.line(command, "exec", piped=True)
        return (
            "a client secret read from a pipe needs --yes, since the confirmation can't come "
            f"from the same stdin: printf '%s' \"$CLIENT_SECRET\" | {piped}"
        )
    return None


def login_mcp(
    args: argparse.Namespace,
    argv: Sequence[str],
    stdin: TextIO,
    out: TextIO,
    err: TextIO,
    *,
    connect: Connect,
    environ: Mapping[str, str],
) -> int:
    """``login --mcp``: exit 0 once fragment 1 is written or the second run is done, 1 when
    the vault refused or the operator declined, 2 for a usage error."""
    prefix = Prefix.from_environ(environ)
    problem = usage(args, argv, stdin, prefix)
    if problem is not None:
        err.write(f"zoeymcp login: {problem}\n")
        return EXIT_USAGE
    return _Run(args, argv, stdin, out, err, prefix, connect).start()


class _Run:
    """One ``login --mcp`` run and the answers it collected, for ``--format json``."""

    def __init__(
        self,
        args: argparse.Namespace,
        argv: Sequence[str],
        stdin: TextIO,
        out: TextIO,
        err: TextIO,
        prefix: Prefix,
        connect: Connect,
    ) -> None:
        self.args = args
        self.argv = list(argv)
        self.stdin = stdin
        self.out = out
        self.err = err
        self.prefix = prefix
        self.connect = connect
        self.socket = admin_client.socket_path(args.socket)
        self.json = args.format == "json"
        self.answers: dict[str, Any] = {}

    def say(self, *lines: str) -> None:
        self.err.write("".join(f"{line}\n" for line in lines))
        self.err.flush()

    def finish(self, code: int) -> int:
        if self.json:
            write_json(self.answers, self.out)
        return code

    def start(self) -> int:
        try:
            plan = admin_client.onboard_discover(self.socket, discover_body(self.args))
        except admin_client.AdminUnavailable as exc:
            return self.refused(exc)
        self.answers["discover"] = plan
        if plan["stage"] == "committed":
            return self.second_run(plan)
        return self.first_run(plan)

    # --- the first run (D.10) --------------------------------------------------------------------

    def first_run(self, plan: dict[str, Any]) -> int:
        self.say(*plan_lines(plan))
        if any(finding["level"] == "error" for finding in plan["draft_check"]):
            self.say(*next_lines(plan["next"], self.prefix))
            return self.finish(EXIT_FINDINGS)
        if self.args.plan_only:
            minutes = round(ONBOARDING_TTL / 60)
            self.say(
                "Plan only: nothing was registered or stored. The same command without "
                f"--plan-only carries on from this plan within {minutes} minutes."
            )
            return self.finish(EXIT_OK)
        onboarding = plan["onboarding"]
        secret = None
        # A registered onboarding (one carried on, or a secret kept across a restart, D.7 step
        # 6) sends and stores nothing more: its fragment 1 is shown again.
        if plan["stage"] != "registered":
            if not self.confirmed(plan):
                self.cancel(onboarding)
                self.say("zoeymcp login: nothing was registered or stored")
                return self.finish(EXIT_FINDINGS)
            if self.args.client_secret:
                try:
                    secret = admin_client.read_secret_value(self.stdin)
                except admin_client.AdminUnavailable as exc:
                    self.cancel(onboarding)
                    self.say(f"zoeymcp login: {exc}")
                    return self.finish(EXIT_FINDINGS)
        indent: int | str = "compose" if self.args.target == "compose" else self.args.indent or 0
        registers = plan["stage"] != "registered" and plan["plan"].get("registration") == "dcr"
        stored_as = None
        try:
            if secret is not None or registers:
                first = made = admin_client.onboard_register(self.socket, onboarding, secret)
                stored_as = made["secret_name"] if made["secret_stored"] else None
                if indent != 0:
                    made = admin_client.onboard_fragment(self.socket, onboarding, indent)
            else:
                first = made = admin_client.onboard_fragment(self.socket, onboarding, indent)
        except admin_client.AdminUnavailable as exc:
            return self.refused(exc)
        self.answers["fragment"] = made
        if not self.json:
            self.out.write(made["diff"]["yaml"])
            self.out.flush()
        lines = []
        if registers:
            host = urlsplit(plan["plan"]["registration_endpoint"]).hostname
            client = untrusted(first["client_id"])
            lines.append(f"Registered client {client} at {untrusted(host)}.")
            lines += [f"  {untrusted(dcr.NOTES.get(note, note))}" for note in first["notes"]]
        if stored_as is not None:
            lines.append(
                f"Stored the client secret as {untrusted(stored_as)}, bound to the token "
                "endpoint and the server's origin fragment 1 names."
            )
        expires = first.get("client_secret_expires_at")
        if isinstance(expires, int) and expires > 0:
            try:
                when = datetime.fromtimestamp(expires, UTC).strftime("%Y-%m-%d %H:%M UTC")
            except (OverflowError, OSError, ValueError):  # past what a datetime holds
                when = f"epoch second {expires}"
            lines.append(
                f"The provider expires that secret at {when}; zoeymcp health warns 14 days before."
            )
        lines.append("Wrote fragment 1 of 2 to stdout.")
        if made["diff"]["check"]:
            lines.append("check, with fragment 1 merged:")
            lines += finding_lines(made["diff"]["check"])
        self.say(*lines, *next_lines(made["next"], self.prefix))
        return self.finish(EXIT_OK)

    def confirmed(self, plan: Mapping[str, Any]) -> bool:
        """The operator's yes, read from stdin (D.10 step 2), unless ``--yes``. It is never read
        from a piped secret's stdin: that takes ``--yes``."""
        if self.args.yes:
            return True
        shown = plan["plan"]
        host = urlsplit(shown["issuer"]).hostname
        client = shown["client_id"]
        if client is None:
            question = f"Register a client at {host}? [y/N] "
        else:
            question = f"Use client {client} at {host}? [y/N] "
        self.err.write(untrusted(question))
        self.err.flush()
        return self.stdin.readline().strip().lower() in ("y", "yes")

    def cancel(self, onboarding: str) -> None:
        # A cancel that fails leaves the onboarding to expire.
        with contextlib.suppress(admin_client.AdminUnavailable):
            admin_client.onboard_cancel(self.socket, onboarding)

    # --- the second run (D.12) -------------------------------------------------------------------

    def second_run(self, answer: dict[str, Any]) -> int:
        names = answer["names"]
        server, credential, held = names["server"], names["credential"], answer["token"]
        self.say(
            f"{untrusted(server)} is in the policy and matches what the server publishes "
            f"({untrusted(answer['plan']['server_url'])})."
        )
        steps = list(answer["next"])
        signing_in = [step for step in steps if step["do"] == "connect"]
        if self.args.plan_only:
            self.say(*next_lines(steps, self.prefix))
            return self.finish(EXIT_OK)
        if held != "none":
            self.say(
                f"{untrusted(credential)} already holds a refresh token ({held}), so this run "
                f"doesn't sign in again; zoeymcp login {untrusted(credential)} does."
            )
        elif self.args.no_connect:
            self.say("Not signing in (--no-connect).")
        else:
            self.say("Connecting:")
            code = self.connect(credential, self.err if self.json else self.out)
            self.answers["connected"] = code == EXIT_OK
            if code != EXIT_OK:
                return self.finish(code)
            steps = [step for step in steps if step not in signing_in]
        self.say(*next_lines(steps, self.prefix))
        return self.finish(EXIT_OK)

    # --- refusals ------------------------------------------------------------------------------

    def refused(self, exc: admin_client.AdminUnavailable) -> int:
        data = dict(exc.data) or {"error": str(exc)}
        steps = [dict(step) for step in data.get("next", [])]
        if data.get("reason") == "proxy_refused":
            for step in steps:
                if self.args.squid_src and step.get("squid"):
                    acl = self.args.squid_src[-1].partition("=")[2]
                    step["squid"] = with_source(step["squid"], acl)
            steps.append(self.retry())
        if self.json:
            self.answers["refused"] = {**data, "next": steps} if steps else data
            return self.finish(EXIT_FINDINGS)
        lines = [f"zoeymcp login: {untrusted(exc)}"]
        reason = data.get("reason")
        if reason == "bad_body" and data.get("detail"):
            lines.append(f"  {untrusted(data['detail'])}")
        if reason == "dcr_refused" and data.get("description"):
            # The provider's own words, for the operator alone (D.4): never logged.
            lines.append(f"  the provider says: {untrusted(data['description'])}")
        if data.get("issuers"):
            lines.append(f"  issuers: {untrusted(', '.join(data['issuers']))}")
            if reason == "as_choice_needed":
                lines.append("  name one with --issuer")
        lines += [f"  tried: {untrusted(url)}" for url in data.get("tried", [])]
        lines += [f"  differs: {untrusted(path)}" for path in data.get("fields", [])]
        lines += finding_lines(data.get("check", []))
        if data.get("secret_deleted"):
            lines.append("  The client secret this run stored was deleted again.")
        if data.get("secret_restored"):
            lines.append("  The client secret it replaced was put back; the policy still uses it.")
        self.say(*lines, *next_lines(steps, self.prefix))
        return self.finish(EXIT_FINDINGS)

    def retry(self) -> dict[str, Any]:
        """D.11's ``retry``: this run's own argv again, shell-quoted (TI-14), in the vault's
        container, with ``-T`` when stdin was piped and the fragment's redirect when stdout
        wasn't a terminal. A secret was read from stdin, so argv holds none."""
        label = "Then run the same command again"
        if self.args.client_secret:
            label += ", piping the client secret in again"
        step: dict[str, Any] = {
            "do": "retry",
            "label": label,
            "command": shlex.join(["zoeymcp", *self.argv]),
            "via": "exec",
        }
        if not self.stdin.isatty():
            step["piped"] = True
        server = self.args.server or self.args.name
        if server is not None and not self.out.isatty():
            step["redirect"] = f" > {fragment_file(server, 1)}"
        return step
