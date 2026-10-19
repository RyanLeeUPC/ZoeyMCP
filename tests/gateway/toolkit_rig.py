"""A real vault with a records API route and a mail connector, and the gateway serving the example
toolkits on it (M4 design H). The toolkits aren't installed: entry points are handed to the
loader, and the origin check is skipped (``allow_writable``), as in development.
"""

from __future__ import annotations

import copy
import importlib.metadata
import io
import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from mcp.types import Tool

from tests.acceptance.tls import ProviderCA
from tests.fakes.harness import serve
from tests.fakes.records_api import SECRET as RECORDS_SECRET
from tests.fakes.records_api import RecordsApi
from tests.fakes.smtp_server import PASSWORD, USERNAME, SmtpFake, serve_smtp
from tests.gateway.rig import KEYS, Reloadable, Running, WithAdmin, token_for
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import GatewayView, build_view
from zoeymcp.gateway import logs
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.pins import project_and_pin
from zoeymcp.gateway.toolkits import Toolkits
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client
from zoeymcp.toolkit import Toolkit
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.connectors.smtp import SmtpConnectors
from zoeymcp.vault.store import SecretStore

SENDER = "Agent <agent@mail.example>"
TO = ["partner@mail.example"]
GROUP = "zoeymcp.toolkits"
ENTRY_POINTS = [
    importlib.metadata.EntryPoint("mail", "example_toolkits.mail:toolkit", GROUP),
    importlib.metadata.EntryPoint("records", "example_toolkits.records:toolkit", GROUP),
    importlib.metadata.EntryPoint("fixtures", "tests.gateway.toolkit_fixtures:toolkit", GROUP),
]


def pins_of(toolkit: Toolkit) -> dict[str, str]:
    """Each tool's pin, as the gateway computes it from the code."""
    return {
        name: project_and_pin(Tool.model_validate(spec.definition())).pin
        for name, spec in sorted(toolkit.tools.items())
    }


def mail_server(**changes: Any) -> dict[str, Any]:
    from example_toolkits.mail import toolkit

    server: dict[str, Any] = {
        "kind": "toolkit",
        "module": "example_toolkits.mail",
        "tools": {"include": ["send_note"], "approve": ["send_note"]},
        "review": pins_of(toolkit),
        "slots": {
            "mail": {
                "route": "mail-send",
                "rules": [
                    {"methods": ["GET"], "paths": ["/config"]},
                    {"methods": ["POST"], "paths": ["/send"], "approved": True},
                ],
            }
        },
    }
    server.update(changes)
    return server


def records_server(**changes: Any) -> dict[str, Any]:
    from example_toolkits.records import toolkit

    server: dict[str, Any] = {
        "kind": "toolkit",
        "module": "example_toolkits.records",
        "tools": {
            "include": ["get_records", "add_records", "archive_records"],
            "allow": ["get_records"],
            "approve": ["add_records", "archive_records"],
        },
        "review": pins_of(toolkit),
        "slots": {
            "db": {
                "route": "records",
                "rules": [
                    {"methods": ["GET"], "paths": ["/v1/records/{id}"]},
                    {"methods": ["POST"], "paths": ["/v1/records/batch"], "approved": True},
                    {"methods": ["POST"], "paths": ["/v1/records/archive"], "approved": True},
                ],
            }
        },
    }
    server.update(changes)
    return server


def fixtures_server(**changes: Any) -> dict[str, Any]:
    from tests.gateway.toolkit_fixtures import toolkit

    server: dict[str, Any] = {
        "kind": "toolkit",
        "module": "tests.gateway.toolkit_fixtures",
        "tools": {
            "include": sorted(toolkit.tools),
            "allow": sorted(n for n, t in toolkit.tools.items() if not t.consequential),
            "approve": sorted(n for n, t in toolkit.tools.items() if t.consequential),
        },
        "review": pins_of(toolkit),
        "slots": {
            "mail": {
                "route": "mail-send",
                "rules": [
                    {"methods": ["GET"], "paths": ["/config"]},
                    {"methods": ["POST"], "paths": ["/send"], "approved": True},
                ],
            },
            "db": {
                "route": "records",
                "rules": [
                    {"methods": ["GET"], "paths": ["/v1/records/{id}"]},
                    {"methods": ["POST"], "paths": ["/v1/records/batch"], "approved": True},
                ],
            },
        },
    }
    server.update(changes)
    return server


def toolkit_policy(
    records_url: str,
    smtp_port: int,
    *,
    servers: dict[str, Any] | None = None,
    approvals: dict[str, Any] | None = None,
) -> dict[str, Any]:
    servers = (
        servers
        if servers is not None
        else {"mail": mail_server(), "records": records_server(), "fixtures": fixtures_server()}
    )
    return {
        "version": 1,
        "mode": "declarative",
        "gateway_key_generation": 1,
        "credentials": {
            "records-key": {"kind": "header", "secret": "store:records-key"},
        },
        "connectors": {
            "mail-out": {
                "kind": "smtp",
                "host": "localhost",
                "port": smtp_port,
                "username": USERNAME,
                "password": "store:mail-pass",
                "from": SENDER,
                "to": TO,
            }
        },
        "routes": [
            {
                "name": "records",
                "prefix": "/records",
                "upstream": records_url,
                "allow_insecure_upstream": True,
                "credential": "records-key",
                "callers": ["gateway"],
                "rules": [
                    {
                        "methods": ["GET"],
                        "paths": ["/v1/records/{id}"],
                        "params": {"id": {"regex": "[A-Za-z0-9_-]{1,64}"}},
                    },
                    {"methods": ["POST"], "paths": ["/v1/records/batch", "/v1/records/archive"]},
                ],
            },
            {
                "name": "mail-send",
                "prefix": "/mail",
                "connector": "mail-out",
                "callers": ["gateway"],
                "rules": [
                    {"methods": ["GET"], "paths": ["/config"]},
                    {"methods": ["POST"], "paths": ["/send"]},
                ],
            },
        ],
        "gateway": {
            "clients": {
                "agent1": {
                    "token_sha256": hash_token(token_for("agent1")),
                    "servers": sorted(servers),
                    "approvals": approvals if approvals is not None else {"attended": True},
                },
            },
            "servers": servers,
        },
    }


@dataclass
class Kit:
    """The deployment: the fakes, the vault and its policy."""

    records: RecordsApi
    smtp: SmtpFake
    vault_url: str
    vault: VaultApp
    records_url: str
    smtp_port: int
    state: Path
    log: io.StringIO
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def view(self) -> GatewayView:
        return build_view(Policy.model_validate(self.raw))

    def events(self, kind: str | None = None) -> list[dict[str, Any]]:
        parsed = [json.loads(line) for line in self.log.getvalue().splitlines()]
        return [line for line in parsed if kind is None or line["event"] == kind]

    def reload(self, **options: Any) -> None:
        self.raw = toolkit_policy(self.records_url, self.smtp_port, **options)
        answer = httpx.post(self.vault_url + "/_test_reload", json=self.raw, timeout=10)
        assert answer.status_code == 204, answer.text


@contextmanager
def kit(tmp_path: Path, ca: ProviderCA, **options: Any) -> Iterator[Kit]:
    log = io.StringIO()
    logs.set_stream(log)
    records = RecordsApi()
    smtp = SmtpFake(ca)
    try:
        with serve(records) as records_url, serve_smtp(smtp, tmp_path) as (_, smtp_port):
            raw = toolkit_policy(records_url, smtp_port, **options)
            policy = Policy.model_validate(raw)
            store = SecretStore(tmp_path / "vault", KEYS)
            store.load()
            store.put("records-key", RECORDS_SECRET, derive_binding(policy, "records-key"))
            store.put("mail-pass", PASSWORD, derive_binding(policy, "mail-pass"))
            connectors = SmtpConnectors(tmp_path / "vault", KEYS, tls=ca.client_context())
            vault = VaultApp(
                policy, store, KEYS, client=httpx.AsyncClient(), environ={}, connectors=connectors
            )
            with serve(Reloadable(vault)) as vault_url:
                yield Kit(
                    records,
                    smtp,
                    vault_url,
                    vault,
                    records_url,
                    smtp_port,
                    tmp_path / "gateway",
                    log,
                    raw=copy.deepcopy(raw),
                )
    finally:
        logs.set_stream(None)


@contextmanager
def toolkit_gateway(
    deployed: Kit, *, entry_points: list[importlib.metadata.EntryPoint] | None = None
) -> Iterator[Running]:
    link = parse_link(deployed.vault_url)
    keys = KeySource(KEYS.gateway_key(1))
    marks = DriftMarks.load(deployed.state)
    pool = UpstreamPool(link, keys, marks, DefinitionStore(deployed.state))
    found = ENTRY_POINTS if entry_points is None else entry_points
    toolkits = Toolkits(link, keys, marks, entry_points=lambda: found, allow_writable=True)
    app = GatewayApp(pool, view_client(link, keys), policy_wait=1, toolkits=toolkits)
    app.ledger, _ = Ledger.open_at(deployed.state, max_bytes=2**20)
    with serve(WithAdmin(app), lifespan=True, proxy_headers=False) as url:
        deadline = time.monotonic() + 10
        while httpx.get(f"{url}/healthz", timeout=5).status_code != 200:
            if time.monotonic() > deadline:
                raise RuntimeError("the gateway didn't become ready")
            time.sleep(0.05)
        yield Running(app, url)
