"""The vault's local admin interface (design §4.5, §7.5).

Served on a Unix socket inside the vault container. Access control is the filesystem: the
socket's directory must be owned by the vault's uid and closed to everyone else, so only that
uid (or root, which already has the host) can connect. The CLI reaches it with
``docker exec <vault> zoeymcp secret ...``.

There is deliberately no endpoint that returns a secret value.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from base64 import b32encode
from collections.abc import Callable
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..common.policy.schema import Policy
from ..common.textrules import find_violations
from . import logs
from .bindings import BindingError, derive_binding
from .keys import KeySet
from .store import SecretStore, origin_binding

DEFAULT_SOCKET = "/run/zoeymcp/admin.sock"
SOCKET_ENV = "ZOEYMCP_ADMIN_SOCKET"
SETUP_FILE = "setup.json"
SETUP_CODE_TTL = 15 * 60
MAX_BODY = 128 * 1024

# The same shape as the name in a store: reference.
_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")


class AdminSocketError(Exception):
    """The admin socket's directory isn't safe to use."""


def check_socket_dir(path: Path) -> None:
    """Create the socket's directory if needed, and refuse one others can reach (POSIX)."""
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise AdminSocketError(f"{directory} must be owned by the vault's uid {os.getuid()}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise AdminSocketError(f"{directory} must not be accessible to group or others (0700)")
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


class SetupCodes:
    """One-time setup codes for the portal (consumed in M5). Only a hash is kept."""

    def __init__(self, state_dir: Path, clock: Callable[[], float] = time.time) -> None:
        self._path = state_dir / SETUP_FILE
        self._clock = clock

    def issue(self) -> tuple[str, int]:
        raw = b32encode(secrets.token_bytes(15)).decode("ascii")
        code = "-".join(raw[i : i + 6] for i in range(0, 24, 6))
        expires = int(self._clock()) + SETUP_CODE_TTL
        record = {"sha256": hashlib.sha256(code.encode()).hexdigest(), "expires": expires}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".setup-", dir=self._path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle)
        os.replace(tmp, self._path)
        return code, expires

    def consume(self, code: str) -> bool:
        """True once for a valid, unexpired code; the code is then gone."""
        try:
            record = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        valid = (
            isinstance(record, dict)
            and self._clock() < record.get("expires", 0)
            and hmac.compare_digest(
                hashlib.sha256(code.encode()).hexdigest(), str(record.get("sha256", ""))
            )
        )
        if valid:
            self._path.unlink(missing_ok=True)
        return bool(valid)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


class AdminApp:
    def __init__(
        self,
        store: SecretStore,
        keys: KeySet,
        policy: Callable[[], Policy],
        setup: SetupCodes,
    ) -> None:
        self._store = store
        self._keys = keys
        self._policy = policy
        self._setup = setup
        self.app = Starlette(
            routes=[
                Route("/secrets", self._list, methods=["GET"]),
                Route("/secrets/{name}", self._put, methods=["PUT"]),
                Route("/secrets/{name}", self._delete, methods=["DELETE"]),
                Route("/setup-code", self._setup_code, methods=["POST"]),
                Route("/gateway-key", self._gateway_key, methods=["GET"]),
            ]
        )

    async def _list(self, request: Request) -> Response:
        return JSONResponse({"secrets": [m.as_dict() for m in self._store.metadata()]})

    async def _put(self, request: Request) -> Response:
        name = request.path_params["name"]
        if not _NAME.match(name):
            return _error(400, "invalid secret name")
        body = await request.body()
        if len(body) > MAX_BODY:
            return _error(413, "body too large")
        try:
            data: Any = json.loads(body)
        except ValueError:
            return _error(400, "body must be JSON")
        if not isinstance(data, dict) or not set(data) <= {"value", "origins"}:
            return _error(400, "expected {value, origins?}")
        value = data.get("value")
        if not isinstance(value, str) or not value:
            return _error(400, "value must be a non-empty string")
        if find_violations(value, max_chars=65536, single_line=True, allow_tabs=False):
            return _error(400, "value has line breaks, control or invisible characters")
        origins = data.get("origins")
        try:
            if origins is not None:
                if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
                    return _error(400, "origins must be a list of URLs")
                binding = origin_binding(origins)
            else:
                binding = derive_binding(self._policy(), name)
            self._store.put(name, value, binding)
        except (BindingError, ValueError) as exc:
            return _error(409, str(exc))
        logs.event("secret_set", name=name, binding=binding)
        return JSONResponse({"name": name, "binding": binding})

    async def _delete(self, request: Request) -> Response:
        name = request.path_params["name"]
        if not self._store.delete(name):
            return _error(404, "no such secret")
        logs.event("secret_deleted", name=name)
        return JSONResponse({"name": name, "deleted": True})

    async def _setup_code(self, request: Request) -> Response:
        code, expires = self._setup.issue()
        logs.event("setup_code_issued", expires=expires)
        return JSONResponse({"code": code, "expires": expires})

    async def _gateway_key(self, request: Request) -> Response:
        generation = self._policy().gateway_key_generation
        return JSONResponse({"generation": generation, "key": self._keys.gateway_key(generation)})


def socket_supported() -> bool:
    return sys.platform != "win32"
