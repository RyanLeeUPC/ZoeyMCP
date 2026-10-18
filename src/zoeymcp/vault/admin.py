"""The vault's local admin interface (design §4.5, §7.5).

Served on a Unix socket inside the vault container. Access control is the filesystem: the
socket's directory must be owned by the vault's uid and closed to everyone else, so only that
uid (or root, which already has the host) can connect. The CLI reaches it with
``docker exec <vault> zoeymcp secret ...``.

There is deliberately no endpoint that returns a secret value.

Secrets an oauth2 credential uses are written and deleted through the token manager, which first
waits for any refresh of that slot (design D.12). If the store can't write its file, the change
is kept in memory and the answer is a 500 that says so (B.4).

``zoeymcp gateway-key`` prints the gateway key and any rotation pending; ``--retire-previous``
retires the previous key at once (M3 design C.2).

``zoeymcp login`` and ``oauth status|reset`` use the ``/oauth`` endpoints (design E.1). Their
errors are ``{"error", "reason"}`` with a stable reason. No answer holds a token, code, verifier
or secret; the authorization URL holds ``state`` and the PKCE challenge, which are useless
without the verifier the vault keeps.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
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
from .bindings import VAULT_PREFIX, BindingError, derive_binding, oauth_secret_names
from .gatewaykeys import GatewayKeyError, GatewayKeys
from .keys import KeySet
from .oauth.login import LoginError, LoginService
from .oauth.tokens import TokenManager
from .store import SecretStore, StoreWriteError, origin_binding

DEFAULT_SOCKET = "/run/zoeymcp/admin.sock"
SOCKET_ENV = "ZOEYMCP_ADMIN_SOCKET"
SETUP_FILE = "setup.json"
SETUP_CODE_TTL = 15 * 60
MAX_BODY = 128 * 1024
MAX_COMPLETE_BODY = 8 * 1024

# The same shape as the name in a store: reference.
_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
NOT_WRITTEN = "kept in memory, not written to disk; check the state volume"
NO_TOKENS = "OAuth needs the vault's token manager"
NO_GATEWAY_KEYS = "the vault keeps no gateway key state"
# Login reasons answered with something other than 400.
_LOGIN_STATUS = {
    "not_oauth": 404,
    "flow_unknown": 404,
    "no_authorize_url": 409,
    "no_route": 409,
    "authorize_misconfigured": 409,
    "binding_changed": 409,
    "client_id_unavailable": 409,
    "client_secret_unavailable": 409,
    "too_many_flows": 429,
}


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


def _login_error(exc: LoginError) -> JSONResponse:
    body = {"error": str(exc), "reason": exc.reason, **exc.details}
    return JSONResponse(body, status_code=_LOGIN_STATUS.get(exc.reason, 400))


async def _json_object(request: Request, limit: int) -> dict[str, Any] | Response:
    """The body as a JSON object (empty means ``{}``), or the error answer."""
    body = await request.body()
    if len(body) > limit:
        return _error(413, "body too large")
    if not body:
        return {}
    try:
        data: Any = json.loads(body)
    except ValueError:
        return _error(400, "body must be JSON")
    if not isinstance(data, dict):
        return _error(400, "body must be a JSON object")
    return data


def json_safe(value: Any) -> Any:
    """``value`` with every NaN or infinity replaced by ``None``.

    A store entry's ``meta`` is clear text anyone with the state file can edit, and JSON answers
    can't carry those numbers.
    """
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


class AdminApp:
    def __init__(
        self,
        store: SecretStore,
        keys: KeySet,
        policy: Callable[[], Policy],
        setup: SetupCodes,
        tokens: TokenManager | None = None,
        login: LoginService | None = None,
        *,
        gateway_keys: GatewayKeys | None = None,
    ) -> None:
        """``gateway_keys`` is the proxy's ratchet. Without it, ``GET /gateway-key`` answers from
        the policy and the previous key can't be retired here."""
        self._store = store
        self._keys = keys
        self._gateway_keys = gateway_keys
        self._policy = policy
        self._setup = setup
        self._tokens = tokens
        if login is None and tokens is not None:
            login = LoginService(tokens)
        self._login = login
        self.app = Starlette(
            routes=[
                Route("/secrets", self._list, methods=["GET"]),
                Route("/secrets/{name}", self._put, methods=["PUT"]),
                Route("/secrets/{name}", self._delete, methods=["DELETE"]),
                Route("/setup-code", self._setup_code, methods=["POST"]),
                Route("/gateway-key", self._gateway_key, methods=["GET"]),
                Route("/gateway-key/retire-previous", self._retire_previous, methods=["POST"]),
                Route("/oauth", self._oauth_status, methods=["GET"]),
                Route("/oauth/flows/{flow}", self._oauth_cancel, methods=["DELETE"]),
                Route("/oauth/{credential}/login", self._oauth_login, methods=["POST"]),
                Route("/oauth/{credential}/complete", self._oauth_complete, methods=["POST"]),
                Route("/oauth/{credential}/reset", self._oauth_reset, methods=["POST"]),
            ]
        )

    async def _list(self, request: Request) -> Response:
        return JSONResponse({"secrets": [json_safe(m.as_dict()) for m in self._store.metadata()]})

    async def _put(self, request: Request) -> Response:
        name = request.path_params["name"]
        if not _NAME.match(name):
            return _error(400, "invalid secret name")
        if name.startswith(VAULT_PREFIX):
            return _error(409, "managed by the vault; use zoeymcp login")
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
        oauth = name in oauth_secret_names(self._policy())
        try:
            if origins is not None:
                if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
                    return _error(400, "origins must be a list of URLs")
                if oauth:
                    return _error(409, "OAuth secrets are bound by the policy; drop --origin")
                binding = origin_binding(origins)
                self._store.put(name, value, binding)
            elif oauth and self._tokens is not None:
                binding = await self._tokens.replace_secret(name, value)
            else:
                binding = derive_binding(self._policy(), name)
                self._store.put(name, value, binding)
        except StoreWriteError as exc:
            logs.event("secret_set", name=name, persisted=False, error_type=type(exc).__name__)
            return _error(500, NOT_WRITTEN)
        except (BindingError, ValueError) as exc:
            return _error(409, str(exc))
        logs.event("secret_set", name=name, binding=binding)
        return JSONResponse({"name": name, "binding": binding})

    async def _delete(self, request: Request) -> Response:
        name = request.path_params["name"]
        try:
            if name in oauth_secret_names(self._policy()) and self._tokens is not None:
                existed = await self._tokens.forget(name)
            else:
                existed = self._store.delete(name)
        except StoreWriteError as exc:
            logs.event("secret_deleted", name=name, persisted=False, error_type=type(exc).__name__)
            return _error(500, NOT_WRITTEN)
        if not existed:
            return _error(404, "no such secret")
        logs.event("secret_deleted", name=name)
        return JSONResponse({"name": name, "deleted": True})

    async def _setup_code(self, request: Request) -> Response:
        code, expires = self._setup.issue()
        logs.event("setup_code_issued", expires=expires)
        return JSONResponse({"code": code, "expires": expires})

    async def _gateway_key(self, request: Request) -> Response:
        if self._gateway_keys is None:
            generation = self._policy().gateway_key_generation
            key = self._keys.gateway_key(generation)
            return JSONResponse({"generation": generation, "key": key, "previous": None})
        return JSONResponse(self._gateway_keys.info())

    async def _retire_previous(self, request: Request) -> Response:
        if self._gateway_keys is None:
            return _error(503, NO_GATEWAY_KEYS)
        try:
            retired = self._gateway_keys.retire_previous()
        except GatewayKeyError:
            # The retirement took effect; only the file is behind (M3 design C.2).
            return _error(500, NOT_WRITTEN)
        return JSONResponse({"retired": retired, **self._gateway_keys.info()})

    # --- OAuth (design E.1) --------------------------------------------------------------------

    async def _oauth_status(self, request: Request) -> Response:
        if self._login is None:
            return _error(503, NO_TOKENS)
        return JSONResponse({"credentials": json_safe(self._login.status())})

    async def _oauth_login(self, request: Request) -> Response:
        if self._login is None:
            return _error(503, NO_TOKENS)
        data = await _json_object(request, MAX_BODY)
        if isinstance(data, Response):
            return data
        if not set(data) <= {"rebind"} or not isinstance(data.get("rebind", False), bool):
            return _error(400, "expected {rebind?: bool}")
        try:
            answer = await self._login.start(
                request.path_params["credential"], rebind=data.get("rebind", False)
            )
        except LoginError as exc:
            return _login_error(exc)
        return JSONResponse(answer)

    async def _oauth_complete(self, request: Request) -> Response:
        if self._login is None:
            return _error(503, NO_TOKENS)
        data = await _json_object(request, MAX_COMPLETE_BODY)
        if isinstance(data, Response):
            return data
        flow, redirect_url = data.get("flow"), data.get("redirect_url")
        if set(data) != {"flow", "redirect_url"} or not (
            isinstance(flow, str) and isinstance(redirect_url, str)
        ):
            return _error(400, "expected {flow, redirect_url}")
        try:
            answer = await self._login.complete(
                request.path_params["credential"], flow, redirect_url
            )
        except LoginError as exc:
            return _login_error(exc)
        return JSONResponse(answer)

    async def _oauth_cancel(self, request: Request) -> Response:
        if self._login is None:
            return _error(503, NO_TOKENS)
        return JSONResponse({"cancelled": self._login.cancel(request.path_params["flow"])})

    async def _oauth_reset(self, request: Request) -> Response:
        if self._tokens is None:
            return _error(503, NO_TOKENS)
        name = request.path_params["credential"]
        if not self._tokens.reset(name):
            return _login_error(LoginError("not_oauth", f"no oauth2 credential named {name!r}"))
        return JSONResponse({"credential": name, "reset": True})


def socket_supported() -> bool:
    return sys.platform != "win32"
