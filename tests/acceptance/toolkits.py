"""The toolkit acceptance rig: the shipped SMTP and toolkit profiles, the real vault and the real
gateway (M4 design N.5).

Agent (SDK client) -> gateway (real socket) -> vault (real socket) -> the records API fake (real
TLS, verified against the test CA) and the SMTP fake (implicit TLS or STARTTLS, through the
CONNECT proxy fake). The profiles are used as shipped, with only the upstream, the mail server's
address, the egress proxy and the client token swapped. The example toolkits aren't installed:
their entry points go to the loader, which skips the origin check (``--allow-writable-toolkits``).

Every log line, CLI output and agent answer is recorded in :class:`Seen`, for the H14 sweep.
"""

from __future__ import annotations

import asyncio
import io
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal

import httpx
import uvicorn

from tests.fakes.connect_proxy import ConnectProxy, serve_proxy
from tests.fakes.records_api import SECRET as RECORDS_SECRET
from tests.fakes.records_api import RecordsApi
from tests.fakes.smtp_server import PASSWORD, SmtpFake, serve_smtp
from tests.gateway.rig import Running, WithAdmin, token_for
from tests.gateway.toolkit_rig import ENTRY_POINTS
from zoeymcp.cli.main import main
from zoeymcp.common import logs
from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.toolkits import Toolkits
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.connectors.smtp import SmtpConnectors
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

from .conftest import BASE, PROFILES, _Server, _wait_started, serve_tls, tls_client
from .gateway import GatewayAdminTransport, wait_healthy
from .helpers import Seen
from .tls import ProviderCA

AGENT = "agent1"
Mode = Literal["implicit", "starttls"]


def merged(*names: str) -> dict[str, Any]:
    """The profiles' fragments merged into one policy, as an operator would paste them."""
    document: dict[str, Any] = dict(BASE)
    for name in names:
        document = _merge(document, load_mapping((PROFILES / name).read_text(encoding="utf-8")))
    return document


def _merge(into: dict[str, Any], fragment: dict[str, Any]) -> dict[str, Any]:
    """Mappings merge key by key, at any depth; lists are joined; anything else is replaced."""
    merged_: dict[str, Any] = dict(into)
    for key, value in fragment.items():
        if isinstance(value, dict) and isinstance(merged_.get(key), dict):
            merged_[key] = _merge(merged_[key], value)
        elif isinstance(value, list) and isinstance(merged_.get(key), list):
            merged_[key] = [*merged_[key], *value]
        else:
            merged_[key] = value
    return merged_


class ToolkitDeployment:
    """The mail and records toolkits, from their profiles, on fakes behind a real vault."""

    def __init__(self, tmp_path: Path, ca: ProviderCA, *, mode: Mode = "implicit") -> None:
        self.tmp_path, self.ca, self.mode = tmp_path, ca, mode
        self.records = RecordsApi()
        self.smtp = SmtpFake(ca, mode=mode)
        self.proxy = ConnectProxy()
        self.seen = Seen()
        self.keys = KeySet.from_text(generate_master_key())
        self.state = tmp_path / "gateway"
        self.policy: Policy | None = None

    def build(self, records_url: str, smtp_port: int, proxy_url: str) -> Policy:
        smtp_profile = "smtp-implicit-tls.yaml" if self.mode == "implicit" else "smtp-starttls.yaml"
        raw = merged(smtp_profile, "toolkit-mail.yaml", "toolkit-records.yaml")
        raw["connectors"]["mail-out"].update(host="localhost", port=smtp_port)
        raw["egress_proxy"] = proxy_url
        for route in raw["routes"]:
            if route["name"] == "records":
                route["upstream"] = records_url
        client = raw["gateway"]["clients"][AGENT]
        client.update(
            token_sha256=hash_token(token_for(AGENT)), sources=[], servers=["mail", "records"]
        )
        policy = Policy.model_validate(raw)
        errors = [f for f in check_policy(policy) if f.level == "error"]
        assert errors == [], errors
        return policy

    @contextmanager
    def running(self) -> Iterator[Running]:
        logs.set_stream(self.seen.log)
        try:
            with (
                serve_tls(self.records, self.ca) as records_url,
                serve_smtp(self.smtp, self.tmp_path) as (_, smtp_port),
                serve_proxy(self.proxy) as proxy_url,
            ):
                self.policy = policy = self.build(records_url, smtp_port, proxy_url)
                store = SecretStore(self.tmp_path / "vault", self.keys)
                store.load()
                store.put("records-key", RECORDS_SECRET, derive_binding(policy, "records-key"))
                store.put("mail-pass", PASSWORD, derive_binding(policy, "mail-pass"))
                connectors = SmtpConnectors(
                    self.tmp_path / "vault", self.keys, tls=self.ca.client_context()
                )
                vault = VaultApp(
                    policy,
                    store,
                    self.keys,
                    client=tls_client(self.ca),
                    environ={},
                    connectors=connectors,
                )
                with _serve_vault(vault) as vault_url, self._gateway(vault_url) as running:
                    yield running
        finally:
            logs.set_stream(None)

    @contextmanager
    def _gateway(self, vault_url: str) -> Iterator[Running]:
        from tests.fakes.harness import serve

        link = parse_link(vault_url)
        keys = KeySource(self.keys.gateway_key(1))
        marks = DriftMarks.load(self.state)
        pool = UpstreamPool(link, keys, marks, DefinitionStore(self.state))
        toolkits = Toolkits(
            link, keys, marks, entry_points=lambda: ENTRY_POINTS, allow_writable=True
        )
        app = GatewayApp(pool, view_client(link, keys), policy_wait=1, toolkits=toolkits)
        app.ledger, _ = Ledger.open_at(self.state, max_bytes=2**20)
        with serve(WithAdmin(app), lifespan=True, proxy_headers=False) as url:
            running = Running(app, url)
            wait_healthy(running)
            yield running

    def cli(self, running: Running, *argv: str) -> tuple[int, str, str]:
        """``zoeymcp <argv>`` against the running gateway's admin app; output is recorded."""
        original = httpx.HTTPTransport
        httpx.HTTPTransport = lambda **_: GatewayAdminTransport(running.admin_url)  # type: ignore[assignment,misc]
        try:
            out, err = io.StringIO(), io.StringIO()
            code = main(list(argv), stdin=io.StringIO(), out=out, err=err)
        finally:
            httpx.HTTPTransport = original  # type: ignore[misc]
        self.seen.outputs += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()


@contextmanager
def _serve_vault(vault: VaultApp) -> Iterator[str]:
    """The vault's proxy app on its own loop and thread, over TCP, as ``zoeymcp vault``."""
    server = _Server(
        uvicorn.Config(
            ListenerTag(vault, "tcp"), host="127.0.0.1", port=0, log_level="warning", lifespan="off"
        )
    )
    loop = asyncio.new_event_loop()

    async def run() -> None:
        try:
            await server.serve()
        finally:
            await vault.aclose()

    thread = threading.Thread(target=loop.run_until_complete, args=(run(),), daemon=True)
    thread.start()
    [port] = _wait_started([server], thread)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(30)
        if not thread.is_alive():
            loop.close()
        time.sleep(0)
