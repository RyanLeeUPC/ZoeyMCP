"""The policy document schema (design §4.6, §9).

One document holds the policy for every role: the vault's credentials, connectors and routes,
and the gateway's clients, servers and approvals. Secrets never appear in it, only references:
``store:<name>`` (the vault's encrypted store) or ``env:<VAR>``.

The schema checks shape and syntax. Cross-references and security rules (every send connector
bound to the gateway, every included tool classified, ...) are in :mod:`.check`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from email.utils import parseaddr
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

NAME_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,62}$"
# A reference to a secret, never a secret itself.
SECRET_REF_PATTERN = r"^(?:store:[a-z0-9][a-z0-9_.-]{0,127}|env:[A-Za-z_][A-Za-z0-9_]{0,127})$"  # noqa: S105
_SECRET_REF = re.compile(SECRET_REF_PATTERN)
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_ADDRESS = re.compile(r"^[^@\s<>\"]{1,64}@[A-Za-z0-9.-]{1,253}$")
# One scope token: RFC 6749 NQCHAR (printable ASCII without space, double quote or backslash).
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]{1,256}$")
MAX_SCOPES = 64

Name = Annotated[str, StringConstraints(pattern=NAME_PATTERN)]
SecretRef = Annotated[str, StringConstraints(pattern=SECRET_REF_PATTERN)]
Token = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._~-]{1,256}$")]
ToolName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]
Pin = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
TokenHash = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
HeaderName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9-]{1,64}$")]
QueryParam = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._~-]{1,128}$")]
CaptureName = Annotated[str, StringConstraints(pattern=r"^[a-z_][a-z0-9_]{0,31}$")]
ModulePath = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
]
ParamText = Annotated[str, Field(max_length=2048)]
ParamValue = ParamText | Annotated[list[ParamText], Field(min_length=1, max_length=10)]
ClientAuth = Literal["basic", "post", "none"]
Method = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
Capability = Literal["resources", "prompts", "completions", "sampling", "elicitation", "roots"]
_DEFAULT_PORTS = {"https": 443, "http": 80}


def is_secret_ref(value: str) -> bool:
    return bool(_SECRET_REF.match(value))


def hash_token(token: str) -> str:
    """The ``token_sha256`` form of a client token: ``sha256:`` and the hex SHA-256 of its UTF-8
    bytes. Tokens are long and random, so no slow hash is needed."""
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()


def _no_line_breaks(value: str) -> str:
    if any(c in value for c in "\r\n\x00"):
        raise ValueError("line breaks and NUL are not allowed")
    return value


def _check_url(value: str, *, schemes: tuple[str, ...], allow_path: bool) -> str:
    _no_line_breaks(value)
    parts = urlsplit(value)
    if parts.scheme not in schemes:
        raise ValueError(f"scheme must be one of: {', '.join(schemes)}")
    if not parts.hostname:
        raise ValueError("missing host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("credentials in URLs are not allowed; use a credential reference")
    if parts.query or parts.fragment:
        raise ValueError("query strings and fragments are not allowed")
    if not allow_path and parts.path not in ("", "/"):
        raise ValueError("a path is not allowed here")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid port: {exc}") from exc
    return value


def _check_redirect_uri(value: str) -> str:
    _check_url(value, schemes=("https", "http"), allow_path=True)
    parts = urlsplit(value)
    host = parts.hostname or ""
    name = host.rstrip(".")  # a trailing dot names the same host
    if name == "localhost" or name.endswith(".localhost"):
        raise ValueError("use 127.0.0.1; RFC 8252 section 8.3 and some providers refuse localhost")
    if parts.scheme == "http":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ValueError("http is only allowed with a loopback IP address like 127.0.0.1")
    return value


def split_scope(scope: str | None, separator: str) -> list[str]:
    """The scopes in a ``scope`` string; none when it isn't set."""
    return [] if scope is None else scope.split(separator)


def param_values(value: str | list[str]) -> list[str]:
    """A parameter's values: one, or several when it's repeated."""
    return [value] if isinstance(value, str) else value


def _check_params(value: dict[str, str | list[str]]) -> dict[str, str | list[str]]:
    for item in value.values():
        for text in param_values(item):
            _no_line_breaks(text)
    return value


def _check_host_port(value: str) -> str:
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        if not rest.startswith(":"):
            raise ValueError("expected [ipv6]:port")
        port = rest[1:]
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise ValueError(f"invalid IPv6 address {host!r}") from exc
    else:
        host, sep, port = value.rpartition(":")
        if not sep or not host:
            raise ValueError("expected host:port")
        if not _HOSTNAME.match(host):
            try:
                ipaddress.IPv4Address(host)
            except ValueError as exc:
                raise ValueError(f"invalid host {host!r}") from exc
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"invalid port {port!r}")
    return value


def _check_network(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid address or network {value!r}") from exc
    return value


def _check_hostname(value: str) -> str:
    if not _HOSTNAME.match(value):
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"invalid host name {value!r}") from exc
    return value


def _check_gateway_host(value: str) -> str:
    if value.startswith("["):
        raise ValueError(f"write IPv6 addresses without brackets: {value!r}")
    return _check_hostname(value)


def _check_origin(value: str) -> str:
    """An origin as browsers send it: ``scheme://host[:port]``, in lower case, with no path and
    no default port."""
    _check_url(value, schemes=("http", "https"), allow_path=False)
    if value != value.lower():
        raise ValueError("write origins in lower case, as browsers send them")
    parts = urlsplit(value)
    host = parts.hostname or ""
    _check_hostname(host)
    expected = f"{parts.scheme}://{f'[{host}]' if ':' in host else host}"
    if parts.port is not None:
        expected += f":{parts.port}"
    if value != expected:
        raise ValueError("an origin is scheme://host[:port], with no path, not even '/'")
    if parts.port == _DEFAULT_PORTS[parts.scheme]:
        raise ValueError(f"leave out the default port {parts.port}; browsers do")
    return value


def _check_mailbox(value: str, *, allow_display_name: bool) -> str:
    _no_line_breaks(value)
    name, address = parseaddr(value)
    if not address or not _ADDRESS.match(address):
        raise ValueError(f"invalid email address {value!r}")
    if not allow_display_name and (name or value.strip() != address):
        raise ValueError("a bare address is required here, without a display name")
    return value


HostPort = Annotated[str, Field(min_length=3, max_length=300)]
Network = Annotated[str, Field(min_length=1, max_length=64)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


# --- credentials -------------------------------------------------------------------------------


class HeaderCredential(_Model):
    kind: Literal["header"]
    secret: SecretRef
    header: HeaderName = "Authorization"
    format: Annotated[str, Field(min_length=8, max_length=256)] = "Bearer {secret}"

    @field_validator("format")
    @classmethod
    def _one_placeholder(cls, value: str) -> str:
        _no_line_breaks(value)
        if value.count("{secret}") != 1:
            raise ValueError("must contain {secret} exactly once")
        return value


class QueryCredential(_Model):
    kind: Literal["query"]
    param: QueryParam
    secret: SecretRef


class PathCredential(_Model):
    kind: Literal["path"]
    template: Annotated[str, Field(min_length=9, max_length=256)]
    secret: SecretRef

    @field_validator("template")
    @classmethod
    def _valid_template(cls, value: str) -> str:
        _no_line_breaks(value)
        if not value.startswith("/"):
            raise ValueError("must start with '/'")
        if value.count("{secret}") != 1:
            raise ValueError("must contain {secret} exactly once")
        rest = value.replace("{secret}", "")
        if any(c in rest for c in "{}?#%"):
            raise ValueError("only the {secret} placeholder is allowed; no query, fragment or %")
        return value


class BasicCredential(_Model):
    kind: Literal["basic"]
    username: Annotated[str, Field(min_length=1, max_length=256)]
    secret: SecretRef

    @field_validator("username")
    @classmethod
    def _valid_username(cls, value: str) -> str:
        _no_line_breaks(value)
        if ":" in value and not is_secret_ref(value):
            raise ValueError("a basic-auth username can't contain ':'")
        return value


class OAuth2Credential(_Model):
    kind: Literal["oauth2"]
    token_url: str
    grant: Literal["refresh_token", "client_credentials"] = "refresh_token"
    client_id: Annotated[str, Field(min_length=1, max_length=512)]
    client_secret: SecretRef | None = None
    # None means basic with a client secret, none without.
    client_auth: ClientAuth | None = None
    refresh_token: SecretRef | None = None
    rotates: bool = False
    reseed: Literal["never", "on-change"] = "never"
    # Token requests. A list value is sent as a repeated parameter (several resources).
    extra_params: dict[QueryParam, ParamValue] = {}
    token_body: Literal["form", "json"] = "form"  # noqa: S105
    token_headers: dict[HeaderName, Annotated[str, Field(min_length=1, max_length=256)]] = {}
    # Scopes and lifetimes. The separator comes first so the scope validator can see it.
    scope_separator: Literal[" ", ","] = " "
    scope: Annotated[str, Field(max_length=2048)] | None = None
    expected_scopes: list[Annotated[str, Field(min_length=1, max_length=256)]] = []
    refresh_skew: Annotated[int, Field(ge=0, le=3600)] = 120
    default_expires_in: Annotated[int, Field(ge=60, le=86400)] = 3600
    grant_lifetime_days: Annotated[int, Field(ge=1, le=3650)] | None = None
    # Interactive consent: zoeymcp login.
    authorize_url: str | None = None
    authorize_params: dict[QueryParam, ParamValue] = {}
    redirect_uri: str = "http://127.0.0.1/callback"
    issuer: str | None = None

    @field_validator("token_url")
    @classmethod
    def _valid_token_url(cls, value: str) -> str:
        return _check_url(value, schemes=("https", "http"), allow_path=True)

    @field_validator("authorize_url", "issuer")
    @classmethod
    def _valid_optional_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_url(value, schemes=("https", "http"), allow_path=True)

    @field_validator("redirect_uri")
    @classmethod
    def _valid_redirect_uri(cls, value: str) -> str:
        return _check_redirect_uri(value)

    @field_validator("client_id")
    @classmethod
    def _valid_client_id(cls, value: str) -> str:
        return _no_line_breaks(value)

    @field_validator("extra_params", "authorize_params")
    @classmethod
    def _valid_params(cls, value: dict[str, str | list[str]]) -> dict[str, str | list[str]]:
        return _check_params(value)

    @field_validator("token_headers")
    @classmethod
    def _valid_token_headers(cls, value: dict[str, str]) -> dict[str, str]:
        for text in value.values():
            _no_line_breaks(text)
        return value

    @field_validator("scope")
    @classmethod
    def _valid_scope(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        separator = info.data.get("scope_separator", " ")
        scopes = split_scope(value, separator)
        if len(scopes) > MAX_SCOPES:
            raise ValueError(f"at most {MAX_SCOPES} scopes")
        for scope in scopes:
            if not _SCOPE_TOKEN.match(scope):
                raise ValueError(
                    f"invalid scope {scope!r}: 1 to 256 printable ASCII characters, without "
                    "spaces, quotes or backslashes, separated by one scope_separator"
                )
        return value

    @model_validator(mode="after")
    def _client_auth_matches_secret(self) -> OAuth2Credential:
        if self.client_auth in ("basic", "post") and self.client_secret is None:
            raise ValueError(f"client_auth {self.client_auth} needs a client_secret")
        if self.client_auth == "none" and self.client_secret is not None:
            raise ValueError("client_auth none takes no client_secret")
        return self

    @property
    def effective_client_auth(self) -> ClientAuth:
        if self.client_auth is not None:
            return self.client_auth
        return "basic" if self.client_secret is not None else "none"

    @property
    def effective_expected_scopes(self) -> list[str]:
        return self.expected_scopes or split_scope(self.scope, self.scope_separator)


Credential = Annotated[
    HeaderCredential | QueryCredential | PathCredential | BasicCredential | OAuth2Credential,
    Field(discriminator="kind"),
]


# --- connectors --------------------------------------------------------------------------------


class SMTPConnector(_Model):
    kind: Literal["smtp"]
    host: str
    port: Annotated[int, Field(ge=1, le=65535)]
    tls: Literal["implicit", "starttls"] = "implicit"
    username: Annotated[str, Field(min_length=1, max_length=256)]
    password: SecretRef
    from_: Annotated[str, Field(alias="from", max_length=320)]
    to: Annotated[list[Annotated[str, Field(max_length=320)]], Field(min_length=1, max_length=20)]
    max_per_day: Annotated[int, Field(ge=1, le=10000)] = 20
    max_subject_chars: Annotated[int, Field(ge=1, le=998)] = 150
    # 2,200 lets a full-length reply fit the default 3,000-character approval budget.
    max_body_chars: Annotated[int, Field(ge=1, le=100_000)] = 2200
    paused: bool = False  # refuses every send; outside the secret's binding

    @field_validator("host")
    @classmethod
    def _valid_host(cls, value: str) -> str:
        return _check_hostname(value)

    @field_validator("username")
    @classmethod
    def _valid_username(cls, value: str) -> str:
        return _no_line_breaks(value)

    @field_validator("from_")
    @classmethod
    def _valid_from(cls, value: str) -> str:
        return _check_mailbox(value, allow_display_name=True)

    @field_validator("to")
    @classmethod
    def _valid_to(cls, value: list[str]) -> list[str]:
        for address in value:
            _check_mailbox(address, allow_display_name=False)
        if len({a.lower() for a in value}) != len(value):
            raise ValueError("duplicate recipient")
        return value


# --- routes ------------------------------------------------------------------------------------


class PlaceholderCaller(_Model):
    """A caller identified by a placeholder: in ``Authorization: Bearer`` by default, or in a
    named header or query parameter (``header:`` / ``query:``)."""

    placeholder: Token
    header: HeaderName | None = None
    query: QueryParam | None = None
    sources: list[Network] = []

    @model_validator(mode="after")
    def _one_location(self) -> PlaceholderCaller:
        if self.header is not None and self.query is not None:
            raise ValueError("a placeholder is read from a header or a query parameter, not both")
        return self

    @field_validator("sources")
    @classmethod
    def _valid_sources(cls, value: list[str]) -> list[str]:
        for source in value:
            _check_network(source)
        return value


Caller = Literal["gateway"] | PlaceholderCaller


class RegexParam(_Model):
    regex: Annotated[str, Field(min_length=1, max_length=256)]

    @field_validator("regex")
    @classmethod
    def _compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        return value


class Rule(_Model):
    methods: Annotated[list[Method], Field(min_length=1)]
    paths: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=1024)]], Field(min_length=1)
    ]
    params: dict[
        CaptureName,
        Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1)] | RegexParam,
    ] = {}


class QueryPolicy(_Model):
    force: dict[QueryParam, Annotated[str, Field(max_length=2048)]] = {}
    strip: list[QueryParam] = []
    allow: list[QueryParam] | None = None


class Route(_Model):
    name: Name
    prefix: Annotated[str, StringConstraints(pattern=r"^/[a-z0-9][a-z0-9_-]{0,62}$")]
    upstream: str | None = None
    credential: Name | None = None
    connector: Name | None = None
    callers: Annotated[list[Caller], Field(min_length=1)]
    query: QueryPolicy = QueryPolicy()
    rules: Annotated[list[Rule], Field(min_length=1)]
    stream: bool = False
    allow_insecure_upstream: bool = False

    @field_validator("upstream")
    @classmethod
    def _valid_upstream(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_url(value, schemes=("https", "http"), allow_path=True)

    @model_validator(mode="after")
    def _one_target(self) -> Route:
        if self.connector is not None:
            if self.upstream is not None or self.credential is not None:
                raise ValueError("a connector route takes no upstream or credential")
        elif self.upstream is None:
            raise ValueError("a route needs an upstream or a connector")
        return self


# --- gateway -----------------------------------------------------------------------------------


class ClientApprovals(_Model):
    """Whether, and how, this client may be asked to approve a call."""

    attended: bool  # the operator says a human watches this client
    timeout: Annotated[int, Field(ge=1, le=600)] | None = None  # may only lower the gateway's
    budget_chars: Annotated[int, Field(ge=200, le=20000)] | None = None  # likewise
    confirm_code: bool = False
    # How the client shows a prompt; plain text needs fewer markup rules.
    renders: Literal["markdown", "plain"] = "markdown"


class Client(_Model):
    """An agent. Its token is written as a hash (``zoeymcp client-token``), or literally, which
    ``check`` warns about. Source pins see the direct peer only, never ``X-Forwarded-For``."""

    token: Token | None = None
    token_sha256: TokenHash | None = None
    servers: list[Name] = []
    sources: list[Network] = []
    approvals: ClientApprovals | None = None  # None: this client is never asked

    @field_validator("sources")
    @classmethod
    def _valid_sources(cls, value: list[str]) -> list[str]:
        for source in value:
            _check_network(source)
        return value

    @model_validator(mode="after")
    def _one_token(self) -> Client:
        if (self.token is None) == (self.token_sha256 is None):
            raise ValueError("set exactly one of token and token_sha256")
        return self

    @property
    def token_hash(self) -> str:
        """The token's ``token_sha256`` form, however it was written."""
        if self.token is not None:
            return hash_token(self.token)
        assert self.token_sha256 is not None  # noqa: S101 - guaranteed by _one_token
        return self.token_sha256


class Approvals(_Model):
    approver: Literal["elicitation", "telegram", "portal"] = "elicitation"
    timeout: Annotated[int, Field(ge=1, le=86400)] = 300
    budget_chars: Annotated[int, Field(ge=200, le=20000)] = 3000
    cooldown: Annotated[int, Field(ge=0, le=3600)] = 15  # seconds after a decline-like decision
    max_pending_per_client: Annotated[int, Field(ge=1, le=16)] = 1
    max_prompts_per_hour: Annotated[int, Field(ge=1, le=1000)] = 30  # per client, rolling


class Tools(_Model):
    include: list[ToolName] = []
    allow: list[ToolName] = []
    approve: list[ToolName] = []


class _UpstreamServer(_Model):
    tools: Tools = Tools()
    # "sha256:<hex>" is pin projection v1.
    review: dict[ToolName, Pin] = {}
    on_drift: Literal["hide", "fail"] = "hide"
    shared_session: bool = False  # legacy upstreams only
    wrap_results: bool = False
    enable: list[Capability] = []  # check refuses a non-empty list: tools only for now
    # An assertion about the protocol era the upstream speaks, not a transport mode.
    era: Literal["auto", "modern", "legacy"] = "auto"
    drift_check_interval: Annotated[int, Field(ge=60, le=86400)] = 300
    call_timeout: Annotated[int, Field(ge=1, le=3600)] | None = None  # overrides limits


class RemoteServer(_UpstreamServer):
    kind: Literal["remote"]
    route: Name
    path: Annotated[str, Field(min_length=1, max_length=1024)] = "/mcp"


class BridgeServer(_UpstreamServer):
    kind: Literal["bridge"]
    url: str
    egress: list[HostPort] = []

    @field_validator("url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        return _check_url(value, schemes=("http", "https"), allow_path=True)

    @field_validator("egress")
    @classmethod
    def _valid_egress(cls, value: list[str]) -> list[str]:
        for entry in value:
            _check_host_port(entry)
        return value


class ToolkitServer(_Model):
    kind: Literal["toolkit"]
    module: ModulePath
    tools: Tools = Tools()


Server = Annotated[RemoteServer | BridgeServer | ToolkitServer, Field(discriminator="kind")]


class GatewayLimits(_Model):
    """Sizes in bytes, times in seconds."""

    max_request_bytes: Annotated[int, Field(ge=4096, le=16 * 2**20)] = 2**20
    max_argument_bytes: Annotated[int, Field(ge=1024, le=4 * 2**20)] = 256 * 1024
    max_result_bytes: Annotated[int, Field(ge=65536, le=16 * 2**20)] = 4 * 2**20
    max_upstream_message_bytes: Annotated[int, Field(ge=65536, le=16 * 2**20)] = 8 * 2**20
    max_concurrent_per_client: Annotated[int, Field(ge=1, le=64)] = 8
    max_streams_per_client: Annotated[int, Field(ge=1, le=64)] = 4
    max_sessions_per_client: Annotated[int, Field(ge=1, le=256)] = 16
    max_upstream_sessions: Annotated[int, Field(ge=1, le=1024)] = 64
    session_idle_timeout: Annotated[int, Field(ge=60, le=86400)] = 1800
    upstream_idle_timeout: Annotated[int, Field(ge=30, le=86400)] = 600
    call_timeout: Annotated[int, Field(ge=1, le=3600)] = 300
    list_timeout: Annotated[int, Field(ge=1, le=300)] = 30
    max_list_pages: Annotated[int, Field(ge=1, le=1000)] = 32
    max_tools_per_server: Annotated[int, Field(ge=1, le=10000)] = 512
    max_list_bytes: Annotated[int, Field(ge=65536, le=64 * 2**20)] = 4 * 2**20
    max_schema_bytes: Annotated[int, Field(ge=1024, le=2**20)] = 64 * 1024
    max_schema_depth: Annotated[int, Field(ge=4, le=128)] = 32
    max_subschemas: Annotated[int, Field(ge=16, le=10000)] = 512
    policy_max_stale: Annotated[int, Field(ge=30, le=3600)] = 300
    ledger_max_bytes: Annotated[int, Field(ge=2**20, le=2**30)] = 64 * 2**20


Origin = Annotated[str, Field(min_length=8, max_length=300)]


class Gateway(_Model):
    clients: dict[Name, Client] = {}
    approvals: Approvals = Approvals()
    servers: dict[Name, Server] = {}
    # Host header values the gateway answers to, without the port.
    hosts: Annotated[list[str], Field(min_length=1)] = ["localhost", "127.0.0.1", "::1"]
    # A request without Origin is fine; one with an Origin must name one of these.
    origins: list[Origin] = []
    limits: GatewayLimits = GatewayLimits()

    @field_validator("hosts")
    @classmethod
    def _valid_hosts(cls, value: list[str]) -> list[str]:
        for host in value:
            _check_gateway_host(host)
        return value

    @field_validator("origins")
    @classmethod
    def _valid_origins(cls, value: list[str]) -> list[str]:
        for origin in value:
            _check_origin(origin)
        return value


# --- document ----------------------------------------------------------------------------------


class Admin(_Model):
    listen: HostPort
    hosts: Annotated[list[str], Field(min_length=1)]

    @field_validator("listen")
    @classmethod
    def _valid_listen(cls, value: str) -> str:
        return _check_host_port(value)

    @field_validator("hosts")
    @classmethod
    def _valid_hosts(cls, value: list[str]) -> list[str]:
        for host in value:
            _check_hostname(host)
        return value


class Policy(_Model):
    version: Literal[1]
    mode: Literal["managed", "declarative"]
    egress_proxy: str | None = None
    gateway_key_generation: Annotated[int, Field(ge=1)] = 1
    admin: Admin
    credentials: dict[Name, Credential] = {}
    connectors: dict[Name, SMTPConnector] = {}
    routes: list[Route] = []
    gateway: Gateway | None = None

    @field_validator("egress_proxy")
    @classmethod
    def _valid_egress_proxy(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_url(value, schemes=("http",), allow_path=False)
