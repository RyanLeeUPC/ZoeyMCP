"""The policy document schema (design §4.6, §9).

One document holds the policy for every role: the vault's credentials, connectors and routes,
and the gateway's clients, servers and approvals. Secrets never appear in it, only references:
``store:<name>`` (the vault's encrypted store) or ``env:<VAR>``.

The schema checks shape and syntax. Cross-references and security rules (every send connector
bound to the gateway, every included tool classified, ...) are in :mod:`.check`.
"""

from __future__ import annotations

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

Name = Annotated[str, StringConstraints(pattern=NAME_PATTERN)]
SecretRef = Annotated[str, StringConstraints(pattern=SECRET_REF_PATTERN)]
Token = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._~-]{1,256}$")]
ToolName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]
Pin = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
HeaderName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9-]{1,64}$")]
QueryParam = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._~-]{1,128}$")]
CaptureName = Annotated[str, StringConstraints(pattern=r"^[a-z_][a-z0-9_]{0,31}$")]
ModulePath = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
]
Method = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
Capability = Literal["resources", "prompts", "sampling", "elicitation", "roots"]


def is_secret_ref(value: str) -> bool:
    return bool(_SECRET_REF.match(value))


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
    refresh_token: SecretRef | None = None
    rotates: bool = False
    reseed: Literal["never", "on-change"] = "never"
    extra_params: dict[QueryParam, Annotated[str, Field(max_length=2048)]] = {}
    scope: Annotated[str, Field(max_length=2048)] | None = None
    expected_scopes: list[Annotated[str, Field(min_length=1, max_length=256)]] = []
    refresh_skew: Annotated[int, Field(ge=0, le=3600)] = 120

    @field_validator("token_url")
    @classmethod
    def _valid_token_url(cls, value: str) -> str:
        return _check_url(value, schemes=("https", "http"), allow_path=True)

    @field_validator("client_id")
    @classmethod
    def _valid_client_id(cls, value: str) -> str:
        return _no_line_breaks(value)


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
    placeholder: Token
    sources: list[Network] = []

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


class Client(_Model):
    token: Token
    servers: list[Name] = []
    sources: list[Network] = []

    @field_validator("sources")
    @classmethod
    def _valid_sources(cls, value: list[str]) -> list[str]:
        for source in value:
            _check_network(source)
        return value


class Approvals(_Model):
    approver: Literal["elicitation", "telegram", "portal"] = "elicitation"
    timeout: Annotated[int, Field(ge=1, le=86400)] = 300
    budget_chars: Annotated[int, Field(ge=200, le=20000)] = 3000


class Tools(_Model):
    include: list[ToolName] = []
    allow: list[ToolName] = []
    approve: list[ToolName] = []


class _UpstreamServer(_Model):
    tools: Tools = Tools()
    review: dict[ToolName, Pin] = {}
    on_drift: Literal["hide", "fail"] = "hide"
    shared_session: bool = False
    wrap_results: bool = False
    enable: list[Capability] = []


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


class Gateway(_Model):
    clients: dict[Name, Client] = {}
    approvals: Approvals = Approvals()
    servers: dict[Name, Server] = {}


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
