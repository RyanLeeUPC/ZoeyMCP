"""Running self-test cases, and mutation-testing them (design R54).

The vault runs with the operator's **real** policy. Every upstream is replaced by the echo
server, and every secret by a generated dummy value, so a case can assert exactly what would
have been sent (and that a refused request sent nothing). Token endpoints are played by
:class:`TokenEcho`, through the same in-process transport: there is no network transport at all,
so a self-test can never refresh a real token. SMTP connectors send to :class:`SendRecorder`,
which opens no socket: a self-test never sends mail (M4 design J.8). Each run starts with an
empty send journal, so the cases see the same keys and limits every time.

``--mutate`` then breaks the policy one rule at a time (wider methods, wider paths, a dropped
constraint, pin or forced parameter, a deleted rule) and reruns the cases. A mutant no case
notices *survives*: the cases don't really test that rule.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import secrets
import ssl
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError
from starlette.types import Receive, Scope, Send

from ..common.policy.check import secret_references
from ..common.policy.schema import (
    BasicCredential,
    HeaderCredential,
    OAuth2Credential,
    PathCredential,
    PlaceholderCaller,
    Policy,
    QueryCredential,
    Route,
    SMTPConnector,
    is_secret_ref,
)
from ..vault import logs
from ..vault.app import GATEWAY_HEADER, REPLAYED_HEADER, VaultApp
from ..vault.bindings import BindingError, derive_binding
from ..vault.connectors.smtp import SendResult, SmtpConnectors
from ..vault.keys import KeySet, generate_master_key
from ..vault.store import SecretStore
from .cases import Case, CaseFile, PlaceholderPresent
from .echo import EchoUpstream, Received, TokenClient, TokenEcho

ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


@dataclass
class SendRecorder:
    """The SMTP transport of a self-test: it records the send and answers 250."""

    sends: list[tuple[str, list[str], bytes]] = field(default_factory=list)

    def __call__(
        self,
        connector: SMTPConnector,
        *,
        proxy: str | None,
        username: str,
        password: str,
        sender: str,
        recipients: list[str],
        data: bytes,
        tls: ssl.SSLContext,
    ) -> SendResult:
        self.sends.append((sender, recipients, data))
        return SendResult("final_reply", final_dot_written=True, reply_code=250)

    def message_id(self, connector: SMTPConnector) -> str:
        return f"<selftest-{len(self.sends) + 1}@selftest.invalid>"


@dataclass
class CaseResult:
    name: str
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


@dataclass(frozen=True)
class Mutant:
    description: str
    policy: Policy


@dataclass
class MutationReport:
    killed: list[str]
    survived: list[str]


class Rig:
    """Dummy secrets for every reference in the policy, in a throwaway store."""

    def __init__(self, policy: Policy, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.keys = KeySet.from_text(generate_master_key())
        self.store = SecretStore(state_dir, self.keys)
        self.store.load()
        self.values: dict[str, str] = {}
        self.environ: dict[str, str] = {}
        for _, ref, _ in secret_references(policy):
            if ref in self.values:
                continue
            digest = hashlib.sha256(ref.encode()).hexdigest()[:8]
            value = f"selftest-{digest}-{secrets.token_hex(6)}"
            self.values[ref] = value
            if ref.startswith("store:"):
                name = ref.removeprefix("store:")
                try:
                    self.store.put(name, value, derive_binding(policy, name))
                except BindingError:
                    continue
            else:
                self.environ[ref.removeprefix("env:")] = value

    async def run(self, policy: Policy, cases: CaseFile) -> list[CaseResult]:
        echo = EchoUpstream()
        tokens = TokenEcho(self.token_clients(policy))

        async def dispatch(scope: Scope, receive: Receive, send: Send) -> None:
            # Token calls never show in echo.received, so "1 upstream request" still holds.
            if scope["type"] == "http" and tokens.handles(scope):
                await tokens(scope, receive, send)
            else:
                await echo(scope, receive, send)

        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=dispatch))
        recorder = SendRecorder()
        journals = tempfile.TemporaryDirectory(prefix="journals-", dir=self.state_dir)
        connectors = SmtpConnectors(
            Path(journals.name), self.keys, transport=recorder, message_id=recorder.message_id
        )
        app = VaultApp(
            policy,
            self.store,
            self.keys,
            client=client,
            token_client=client,
            environ=self.environ,
            connectors=connectors,
        )
        results = []
        with logs.quiet(), journals:
            try:
                for case in cases.cases:
                    before, sends_before = len(echo.received), len(recorder.sends)
                    response = await self._send(app, policy, case)
                    received = echo.received[before:]
                    if _is_connector(policy, case.request.path):
                        sends = len(recorder.sends) - sends_before
                        results.append(_evaluate_connector(case, response, received, sends))
                    else:
                        results.append(self._evaluate(policy, case, response, received, tokens))
            finally:
                await app.aclose()
        return results

    def token_clients(self, policy: Policy) -> list[TokenClient]:
        """What each oauth2 credential must send to its token endpoint, with the dummies."""
        clients = []
        for name, cred in sorted(policy.credentials.items()):
            if not isinstance(cred, OAuth2Credential):
                continue
            client_id = cred.client_id
            if is_secret_ref(client_id):
                client_id = self.values.get(client_id, "")
            clients.append(
                TokenClient(
                    credential=name,
                    token_url=cred.token_url,
                    grant=cred.grant,
                    auth=cred.effective_client_auth,
                    body=cred.token_body,
                    client_id=client_id,
                    client_secret=self.values.get(cred.client_secret or ""),
                    refresh_token=self.values.get(cred.refresh_token or ""),
                )
            )
        return clients

    async def _send(self, app: VaultApp, policy: Policy, case: Case) -> httpx.Response:
        request = case.request
        headers = dict(request.headers)
        path = request.path
        if request.caller == "gateway":
            headers[GATEWAY_HEADER] = self.keys.gateway_key(policy.gateway_key_generation)
        elif isinstance(request.caller, PlaceholderPresent):
            value = request.caller.placeholder
            caller = _find_caller(policy, path, value)
            if caller is not None and caller.query is not None:
                separator = "&" if "?" in path else "?"
                path = f"{path}{separator}{caller.query}={value}"
            elif caller is not None and caller.header is not None:
                headers[caller.header] = value
            else:
                headers["Authorization"] = f"Bearer {value}"
        transport = httpx.ASGITransport(app=app, client=(request.source, 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(
                request.method, path, headers=headers, content=request.body.encode()
            )

    def _evaluate(
        self,
        policy: Policy,
        case: Case,
        response: httpx.Response,
        received: list[Received],
        tokens: TokenEcho,
    ) -> CaseResult:
        result = CaseResult(case.name)
        expect = case.expect
        if response.status_code != expect.status:
            result.problems.append(f"status {response.status_code}, expected {expect.status}")
        if expect.status >= 400 and received:
            result.problems.append("a refused request reached the upstream")
        if expect.status < 400 and len(received) != 1:
            result.problems.append(f"{len(received)} upstream request(s), expected 1")
        if expect.upstream is None or len(received) != 1:
            return result
        got = received[0]
        want = expect.upstream
        if want.method is not None and got.method != want.method:
            result.problems.append(f"upstream method {got.method}, expected {want.method}")
        if want.path is not None and got.path != want.path:
            result.problems.append(f"upstream path {got.path!r}, expected {want.path!r}")
        query = dict(got.query)
        for name, value in want.query.items():
            if value is None and name in query:
                result.problems.append(f"query {name!r} should be absent")
            elif value is not None and query.get(name) != value:
                result.problems.append(f"query {name!r} is {query.get(name)!r}, expected {value!r}")
        for name, value in want.headers.items():
            actual = got.header(name)
            if value is None and actual is not None:
                result.problems.append(f"header {name!r} should be absent")
            elif value is not None and actual != value:
                result.problems.append(f"header {name!r} is {actual!r}, expected {value!r}")
        if want.credential is not None:
            route = _route_for(policy, case.request.path)
            injected = route is not None and self._credential_injected(policy, route, got, tokens)
            if want.credential and not injected:
                result.problems.append("the route's credential wasn't injected")
            if not want.credential and self._any_secret_in(got, tokens):
                result.problems.append("a secret reached the upstream")
        return result

    def _credential_injected(
        self, policy: Policy, route: Route, got: Received, tokens: TokenEcho
    ) -> bool:
        name = route.credential or ""
        cred = policy.credentials.get(name)
        if isinstance(cred, OAuth2Credential):
            issued = tokens.last_issued.get(name)
            return issued is not None and got.header("authorization") == f"Bearer {issued}"
        if cred is None or not hasattr(cred, "secret"):
            return False
        value = self.values.get(cred.secret)
        if value is None:
            return False
        if isinstance(cred, HeaderCredential):
            return got.header(cred.header) == cred.format.replace("{secret}", value)
        if isinstance(cred, QueryCredential):
            return (cred.param, value) in got.query
        if isinstance(cred, PathCredential):
            return cred.template.replace("{secret}", value) in got.path
        if isinstance(cred, BasicCredential):
            user = self.values.get(cred.username) if is_secret_ref(cred.username) else cred.username
            if user is None:
                return False
            token = base64.b64encode(f"{user}:{value}".encode()).decode()
            return got.header("authorization") == f"Basic {token}"
        return False

    def _any_secret_in(self, got: Received, tokens: TokenEcho) -> bool:
        haystack = got.path + repr(got.query) + repr(got.headers) + got.body.decode("latin-1")
        return any(value in haystack for value in [*self.values.values(), *tokens.issued])


def _is_connector(policy: Policy, path: str) -> bool:
    route = _route_for(policy, path)
    return route is not None and route.connector is not None


def _evaluate_connector(
    case: Case, response: httpx.Response, received: list[Received], sends: int
) -> CaseResult:
    """A connector has no upstream: a ``200`` to ``POST /send`` is exactly one recorded send,
    and anything else is none."""
    result = CaseResult(case.name)
    expect = case.expect
    if response.status_code != expect.status:
        result.problems.append(f"status {response.status_code}, expected {expect.status}")
    if received:
        result.problems.append("a connector request reached an upstream")
    sending = case.request.method == "POST" and case.request.path.split("?")[0].endswith("/send")
    replayed = response.headers.get(REPLAYED_HEADER) == "1"
    wanted = 1 if sending and response.status_code == 200 and not replayed else 0
    if sends != wanted:
        result.problems.append(f"{sends} message(s) sent, expected {wanted}")
    if expect.upstream is not None:
        result.problems.append("a connector route has no upstream to expect")
    return result


def _route_for(policy: Policy, path: str) -> Route | None:
    first = path.split("?", 1)[0].lstrip("/").split("/", 1)[0]
    return next((r for r in policy.routes if r.prefix == f"/{first}"), None)


def _find_caller(policy: Policy, path: str, value: str) -> PlaceholderCaller | None:
    route = _route_for(policy, path)
    if route is None:
        return None
    for caller in route.callers:
        if isinstance(caller, PlaceholderCaller) and caller.placeholder == value:
            return caller
    return None


# --- mutants -----------------------------------------------------------------------------------


def generate_mutants(policy: Policy) -> list[Mutant]:
    """One policy per single-rule weakening. Mutants that can't change behavior are skipped."""
    base = policy.model_dump(by_alias=True)
    mutants: list[Mutant] = []

    def add(description: str, raw: dict[str, Any]) -> None:
        # A weakening the schema itself refuses can't happen in a real policy.
        with contextlib.suppress(ValidationError):
            mutants.append(Mutant(description, Policy.model_validate(raw)))

    for r_index, route in enumerate(policy.routes):
        where = f"routes[{r_index}] ({route.name})"
        always_removed = {
            c.query for c in route.callers if isinstance(c, PlaceholderCaller) and c.query
        }
        cred = policy.credentials.get(route.credential or "")
        if isinstance(cred, QueryCredential):
            always_removed.add(cred.param)

        for rule_index, rule in enumerate(route.rules):
            rule_where = f"{where}.rules[{rule_index}]"
            if set(rule.methods) != set(ALL_METHODS):
                raw = copy.deepcopy(base)
                raw["routes"][r_index]["rules"][rule_index]["methods"] = list(ALL_METHODS)
                add(f"{rule_where}: allow every method", raw)
            for p_index, pattern in enumerate(rule.paths):
                if pattern != "/**":
                    raw = copy.deepcopy(base)
                    raw["routes"][r_index]["rules"][rule_index]["paths"][p_index] = "/**"
                    add(f"{rule_where}.paths[{p_index}]: {pattern} widened to /**", raw)
            for name in rule.params:
                raw = copy.deepcopy(base)
                del raw["routes"][r_index]["rules"][rule_index]["params"][name]
                add(f"{rule_where}.params.{name}: constraint removed", raw)
            if len(route.rules) > 1:
                raw = copy.deepcopy(base)
                del raw["routes"][r_index]["rules"][rule_index]
                add(f"{rule_where}: rule deleted", raw)

        for c_index, caller in enumerate(route.callers):
            if isinstance(caller, PlaceholderCaller) and caller.sources:
                raw = copy.deepcopy(base)
                raw["routes"][r_index]["callers"][c_index]["sources"] = []
                add(f"{where}.callers[{c_index}]: source pins removed", raw)

        for name in route.query.force:
            raw = copy.deepcopy(base)
            del raw["routes"][r_index]["query"]["force"][name]
            add(f"{where}.query.force.{name}: no longer forced", raw)
        for name in route.query.strip:
            if name in always_removed:
                continue
            raw = copy.deepcopy(base)
            raw["routes"][r_index]["query"]["strip"].remove(name)
            add(f"{where}.query.strip: {name} no longer stripped", raw)
        if route.query.allow is not None:
            raw = copy.deepcopy(base)
            raw["routes"][r_index]["query"]["allow"] = None
            add(f"{where}.query.allow: removed", raw)
    return mutants


async def mutate(policy: Policy, cases: CaseFile, rig: Rig) -> MutationReport:
    report = MutationReport([], [])
    for mutant in generate_mutants(policy):
        results = await rig.run(mutant.policy, cases)
        (report.killed if any(not r.ok for r in results) else report.survived).append(
            mutant.description
        )
    return report


def temporary_state() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix="zoeymcp-selftest-")
