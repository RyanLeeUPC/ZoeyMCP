"""The acceptance rig: real HTTPS fakes, the real vault on a real socket, shipped profiles."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from starlette.types import ASGIApp

from tests.fakes.harness import serve
from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.store import SecretStore

from .tls import ProviderCA, make_ca

PROFILES = Path(__file__).resolve().parents[2] / "profiles"
BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
}


@pytest.fixture(scope="session")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("tls"))


class _Server(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        pass


@contextmanager
def serve_tls(app: ASGIApp, ca: ProviderCA) -> Iterator[str]:
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        ssl_certfile=str(ca.cert_file),
        ssl_keyfile=str(ca.key_file),
        log_level="warning",
        lifespan="off",
    )
    server = _Server(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("TLS fake failed to start")
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"https://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(10)


class Deployment:
    """A shipped profile, with its upstream pointed at a fake, behind a real vault."""

    def __init__(
        self,
        tmp_path: Path,
        profile: str,
        upstream: str,
        ca: ProviderCA,
        *,
        secrets: dict[str, str],
        replace: dict[str, str] | None = None,
    ) -> None:
        text = (PROFILES / profile).read_text(encoding="utf-8")
        for old, new in (replace or {}).items():
            assert old in text, f"{old!r} not in {profile}"
            text = text.replace(old, new)
        fragment = load_mapping(text)
        for route in fragment["routes"]:
            route["upstream"] = upstream
        self.policy = Policy.model_validate({**BASE, **fragment})
        errors = [f for f in check_policy(self.policy) if f.level == "error"]
        assert errors == [], errors

        keys = KeySet.from_text(generate_master_key())
        store = SecretStore(tmp_path, keys)
        store.load()
        for name, value in secrets.items():
            store.put(name, value, derive_binding(self.policy, name))
        # No keep-alive: the vault runs on a server thread whose loop stops before the fakes do,
        # and an idle TLS connection left behind would stall the fake's shutdown.
        client = httpx.AsyncClient(
            verify=ca.client_context(),
            trust_env=False,
            follow_redirects=False,
            limits=httpx.Limits(max_keepalive_connections=0),
        )
        self.app = VaultApp(self.policy, store, keys, client=client, environ={})
        self.placeholder = next(
            c.placeholder for c in self.policy.routes[0].callers if not isinstance(c, str)
        )
        self.prefix = self.policy.routes[0].prefix

    @contextmanager
    def running(self) -> Iterator[httpx.Client]:
        with serve(self.app) as base, httpx.Client(base_url=base, timeout=10) as client:
            yield client
