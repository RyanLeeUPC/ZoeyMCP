"""The declarative policy, read-only (M5 design L, D-09). Pure, so completeness and redaction can
be tested.

``GET /api/policy`` shows the running policy, built from an **allowlist** of the schema's fields,
never by dumping the model: :data:`FIELDS` names every field of every model in
``common/policy/schema.py`` as shown or hidden, and :func:`view` walks the model by that table. A
model or field the table doesn't name raises ``KeyError``, so a field a later milestone adds stays
out of every answer until someone decides how it shows (a test walks the schema and fails first).

Hidden fields show only that they are set, never their value:

- a client's ``token`` and ``token_sha256``: a client token is the approval credential;
- every placeholder: placeholders are credentials;
- a connector's ``username`` and ``from``, and its ``to`` as a count: recipients aren't shown,
  and usernames are account details; a basic credential's ``username`` likewise;
- an OAuth credential's ``token_headers`` and a route's forced query values, by name only: both
  are free text sent upstream, where a literal credential could sit.

Secret references (``store:x``, ``env:X``) show as written: they name a secret, never hold one.
Every string, dictionary keys included, goes through :func:`~.display.shown`. The answer lists
the path of each value it hid, in the policy's own path form (``routes[0].callers[1].placeholder``).

In managed mode the policy is the store's head (M6 design A.4), and the page says which revision
it is, when it was saved and by whom (:func:`saved`), from the head revision's header.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final, Literal

from pydantic import BaseModel

from ..common.policy.schema import Policy
from .display import NAME_LIMIT, shown

Source = Literal["env", "file", "stdin", "managed"]
# How a field shows: as it is (every string shown), "(set)", a count of addresses, or the names
# of a mapping with each value "(set)".
Treatment = Literal["shown", "hidden", "addresses", "names"]
SET: Final = "(set)"
HIDDEN: Final = "hidden"
ADDRESSES: Final = "addresses"
NAMES: Final = "names"
# The longest string a valid policy holds (a scope, a forced value, a parameter); URLs have no cap
# of their own, so this one keeps any answer bounded.
VALUE_LIMIT: Final = 2048
# Where the policy came from, as the page says it (B.3: read at start and on SIGHUP).
SOURCES: Final[Mapping[Source, str]] = MappingProxyType(
    {
        "env": "the ZOEYMCP_CONFIG environment variable",
        "file": "the file given with --config",
        "stdin": "standard input, read once at start",
        "managed": "the vault's policy store (managed mode)",
    }
)


def _fields(*shown_names: str, **special: Treatment) -> Mapping[str, Treatment]:
    found: dict[str, Treatment] = dict.fromkeys(shown_names, "shown")
    return MappingProxyType({**found, **special})


# The fields of the schema's _UpstreamServer, a remote server's base.
_UPSTREAM: Final = (
    "tools",
    "review",
    "declined",
    "on_drift",
    "shared_session",
    "wrap_results",
    "enable",
    "prompts",
    "resources",
    "era",
    "drift_check_interval",
    "call_timeout",
)
# Every field of every model in common/policy/schema.py, by the model's class name.
FIELDS: Final[Mapping[str, Mapping[str, Treatment]]] = MappingProxyType(
    {
        "HeaderCredential": _fields("kind", "secret", "header", "format"),
        "QueryCredential": _fields("kind", "param", "secret"),
        "PathCredential": _fields("kind", "template", "secret"),
        "BasicCredential": _fields("kind", "secret", username=HIDDEN),
        "OAuth2Credential": _fields(
            "kind",
            "token_url",
            "grant",
            "client_id",
            "client_secret",
            "client_auth",
            "refresh_token",
            "rotates",
            "reseed",
            "extra_params",
            "token_body",
            "scope_separator",
            "scope",
            "expected_scopes",
            "refresh_skew",
            "default_expires_in",
            "grant_lifetime_days",
            "idle_expiry_days",
            "authorize_url",
            "authorize_params",
            "redirect_uri",
            "issuer",
            "require_iss",
            "revocation_url",
            "resource_metadata",
            token_headers=NAMES,
        ),
        "SMTPConnector": _fields(
            "kind",
            "host",
            "port",
            "tls",
            "password",
            "max_per_day",
            "max_subject_chars",
            "max_body_chars",
            "paused",
            username=HIDDEN,
            from_=HIDDEN,
            to=ADDRESSES,
        ),
        "PlaceholderCaller": _fields("header", "query", "sources", placeholder=HIDDEN),
        "RegexParam": _fields("regex"),
        "Rule": _fields("methods", "paths", "params"),
        "QueryPolicy": _fields("strip", "allow", force=NAMES),
        "Route": _fields(
            "name",
            "prefix",
            "upstream",
            "credential",
            "connector",
            "callers",
            "query",
            "rules",
            "stream",
            "allow_insecure_upstream",
            "program",
        ),
        # A route's program (M7 design A.1): configuration, no secret. A unix: upstream shows as
        # written above, as any upstream does.
        "RouteProgram": _fields("egress", "egress_private", "holds_secret"),
        "ClientApprovals": _fields(
            "attended", "timeout", "budget_chars", "confirm_code", "renders"
        ),
        "Client": _fields("servers", "sources", "approvals", token=HIDDEN, token_sha256=HIDDEN),
        "Approvals": _fields(
            "approver",
            "timeout",
            "budget_chars",
            "cooldown",
            "max_pending_per_client",
            "max_prompts_per_hour",
        ),
        "Tools": _fields("include", "allow", "approve"),
        # A server's prompts and resources (M6 design A.4): names, URIs and pins, as tools are.
        "PromptsPolicy": _fields("include", "review", "declined", "assistant"),
        "ResourceSet": _fields("include", "review", "declined"),
        "ResourcesPolicy": _fields("templates", "fixed"),
        "_UpstreamServer": _fields(*_UPSTREAM),
        "RemoteServer": _fields(*_UPSTREAM, "kind", "route", "path"),
        "ToolkitRule": _fields("methods", "paths", "approved"),
        "ToolkitSlot": _fields("route", "rules"),
        "ToolkitServer": _fields(
            "kind",
            "module",
            "tools",
            "pinning",
            "review",
            "declined",
            "on_drift",
            "slots",
            "wrap_results",
            "call_timeout",
        ),
        "GatewayLimits": _fields(
            "max_request_bytes",
            "max_argument_bytes",
            "max_result_bytes",
            "max_upstream_message_bytes",
            "max_concurrent_per_client",
            "max_streams_per_client",
            "max_sessions_per_client",
            "max_upstream_sessions",
            "session_idle_timeout",
            "upstream_idle_timeout",
            "call_timeout",
            "list_timeout",
            "max_list_pages",
            "max_tools_per_server",
            "max_list_bytes",
            "max_schema_bytes",
            "max_schema_depth",
            "max_subschemas",
            "policy_max_stale",
            "ledger_max_bytes",
        ),
        "Gateway": _fields("clients", "approvals", "servers", "hosts", "origins", "limits"),
        "Admin": _fields("listen", "origins"),
        "Policy": _fields(
            "version",
            "mode",
            "egress_proxy",
            "egress_proxy_kind",
            "egress_private",
            "egress_key_generation",
            "egress_proxy_acls",
            "gateway_key_generation",
            "admin",
            "credentials",
            "connectors",
            "routes",
            "gateway",
        ),
    }
)


def view(
    policy: Policy, source: Source, *, header: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """``GET /api/policy``'s answer: the mode, where the policy came from (and the page's
    sentence about it: in managed mode, :func:`saved` of the head's ``header``), the policy by
    :data:`FIELDS`, and the paths of the values hidden."""
    hidden: list[str] = []
    said = SOURCES[source] if source != "managed" or header is None else saved(header)
    return {
        "mode": policy.mode,
        "source": source,
        "source_shown": said,
        "policy": _model(policy, "", hidden),
        "hidden": hidden,
    }


def saved(header: Mapping[str, Any]) -> str:
    """A revision as the page names it (M6 design A.4): ``revision N, saved <when> by <who>``,
    the time in UTC to the minute, and the author a passkey by its fingerprint's first 8, the
    host and how it came (``socket``, ``offline``, ``source``), or the seed (D.2)."""
    when = datetime.fromtimestamp(header["created"], UTC).strftime("%Y-%m-%d %H:%M UTC")
    author = header["author"]
    if author["by"] == "passkey":
        who = f"passkey {author['fingerprint'][:8]}"
    elif author["by"] == "host":
        who = f"the host ({author['via']})"
    else:
        who = "the seed"
    return f"revision {header['revision']}, saved {when} by {who}"


def rendered(value: Any, treatment: Treatment = "shown") -> Any:
    """One field's value as :func:`view` shows a field of ``treatment``: a model by
    :data:`FIELDS`, any other value shown, a hidden one only as set (M6 design H.2: the diff's
    renderer, ``portal/policydiffview.py``)."""
    return _value(value, "", []) if treatment == "shown" else _hidden(treatment, value)


def _model(model: BaseModel, path: str, hidden: list[str]) -> dict[str, Any]:
    """One model's fields in the schema's order, each as :data:`FIELDS` says, under its name in
    the document (``from``, not ``from_``)."""
    table = FIELDS[type(model).__name__]
    out: dict[str, Any] = {}
    for name, info in type(model).model_fields.items():
        treatment = table[name]
        key = info.alias or name
        where = f"{path}.{key}" if path else key
        value = getattr(model, name)
        if treatment == "shown":
            out[key] = _value(value, where, hidden)
            continue
        out[key] = _hidden(treatment, value)
        if value:  # an unset token, or no headers, hides nothing
            hidden.append(where)
    return out


def _value(value: Any, path: str, hidden: list[str]) -> Any:
    if isinstance(value, BaseModel):
        return _model(value, path, hidden)
    if isinstance(value, Mapping):
        return {
            _key(key): _value(item, f"{path}.{_key(key)}", hidden) for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [_value(item, f"{path}[{index}]", hidden) for index, item in enumerate(value)]
    if isinstance(value, str):
        return shown(value, VALUE_LIMIT)
    if value is None or isinstance(value, bool | int):
        return value
    raise TypeError(f"{path}: a {type(value).__name__} has no rendering")


def _hidden(treatment: Treatment, value: Any) -> Any:
    if treatment == "addresses":
        count = len(value)
        return f"({count} address)" if count == 1 else f"({count} addresses)"
    if treatment == "names":
        return {_key(key): SET for key in value}
    return None if value is None else SET


def _key(key: Any) -> str:
    return shown(str(key), NAME_LIMIT)
