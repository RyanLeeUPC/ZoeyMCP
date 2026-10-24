"""The host's export of a managed policy (M6 design H.6; Q5, Q30, DD-4, G-15, OPS-8, OPS-17). Pure,
mutation-tested.

``zoeymcp policy export`` and the admin socket's ``GET /policy/export`` write the head's policy, or
a kept revision's, as a document ``zoeymcp policy import`` takes back: R61's fourth scoped
exception, since it holds placeholders, ``token_headers`` and forced query values, which count as
credentials, and the client token hashes. No portal route reaches it. :func:`export` writes:

- fixed comment lines first: the revision, the deployment (its first 8 characters) and when the
  revision was made, on the first line, which :func:`header` reads back for the import's base
  (H.5, OPS-8); that it is kept like a secret; and how it goes back (an import), or for
  ``mode="declarative"`` that the vault runs it as written (J10);
- the policy as :func:`.plan.document` holds it (D.5: every literal client token as its
  ``token_sha256``, defaults left out), field by field in :data:`EXPORT_FIELDS`' order, with
  ``mode`` as asked and ``gateway_key_generation`` always written, so the generation never falls
  back to its default by omission;
- every string double-quoted and escaped as :func:`.emit.document` escapes it (F-18), so any text
  the policy holds comes back the same.

:data:`EXPORT_FIELDS` names every field of every schema model (a test walks the schema, as
``portal/policyview.py``'s ``FIELDS``' does): a model or field it doesn't name is a ``KeyError``,
never a document that silently drops what a later milestone adds. It is kept apart from the
emitter's fragment table on purpose: that one must stay a subset of the policy view's shown
fields, and this one can't.

``target="compose"`` indents the document 8 for an inline ``ZOEYMCP_CONFIG`` block and writes every
``$`` as ``$$`` (emit's compose form, TI-1). :func:`notes` are the lines the CLI writes to stderr
beside it: what was exported and, for the compose form, one line per field the shipped compose
files interpolate (``gateway_key_generation``, the port of an ``http://localhost`` origin), now a
literal (OPS-17).
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from pydantic import BaseModel

from .emit import COMPOSE_INDENT, Target
from .emit import document as emitted
from .plan import document
from .schema import Policy

Mode = Literal["managed", "declarative"]
# The first line, as written and as the import reads it (revision, deployment, when).
FIRST_LINE: Final = (
    "# zoeymcp policy export: revision {revision} of deployment {deployment}, {when}."
)
KEEP_LINE: Final = "# It holds placeholders and client token hashes: keep it like a secret."
IMPORT_LINE: Final = "# Import with zoeymcp policy import."
DECLARATIVE_LINE: Final = (
    "# mode: declarative: the vault runs it as written and keeps its revisions parked; "
    "mode: managed resumes them."
)
# A revision is 1 to 9,999,999,999 (REVISION_MAX in vault/policyseal.py, which common can't
# import): at most 10 digits.
_FIRST: Final = re.compile(
    r"# zoeymcp policy export: revision ([1-9][0-9]{0,9}) of deployment ([0-9a-f]{8}), .*"
)
# The admin origin the shipped compose files write with ${ZOEYMCP_ADMIN_PORT:-8081}.
_LOCALHOST: Final = re.compile(r"http://localhost:([0-9]+)")
GENERATION_NOTE: Final = (
    "gateway_key_generation is now a literal {n}: put ${{ZOEYMCP_GATEWAY_KEY_GENERATION:-{n}}} "
    "back if you rotate by the variable."
)
ORIGIN_NOTE: Final = (
    "admin.origins is now the literal {origin}: put ${{ZOEYMCP_ADMIN_PORT:-{port}}} back if you "
    "move the port by the variable."
)

# The UpstreamServer fields a remote server shares, in the schema's order.
_UPSTREAM: Final = (
    "tools",
    "review",
    "declined",
    "on_drift",
    "shared_session",
    "wrap_results",
    "enable",
    "era",
    "drift_check_interval",
    "call_timeout",
)
# Every field of every model in common/policy/schema.py, by the model's class name, in the order
# the export writes them (the schema's).
EXPORT_FIELDS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "HeaderCredential": ("kind", "secret", "header", "format"),
        "QueryCredential": ("kind", "param", "secret"),
        "PathCredential": ("kind", "template", "secret"),
        "BasicCredential": ("kind", "username", "secret"),
        "OAuth2Credential": (
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
            "token_headers",
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
        ),
        "SMTPConnector": (
            "kind",
            "host",
            "port",
            "tls",
            "username",
            "password",
            "from_",
            "to",
            "max_per_day",
            "max_subject_chars",
            "max_body_chars",
            "paused",
        ),
        "PlaceholderCaller": ("placeholder", "header", "query", "sources"),
        "RegexParam": ("regex",),
        "Rule": ("methods", "paths", "params"),
        "QueryPolicy": ("force", "strip", "allow"),
        "RouteProgram": ("egress", "egress_private", "holds_secret"),
        "Route": (
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
        "ClientApprovals": ("attended", "timeout", "budget_chars", "confirm_code", "renders"),
        "Client": ("token", "token_sha256", "servers", "sources", "approvals"),
        "Approvals": (
            "approver",
            "timeout",
            "budget_chars",
            "cooldown",
            "max_pending_per_client",
            "max_prompts_per_hour",
        ),
        "Tools": ("include", "allow", "approve"),
        "_UpstreamServer": _UPSTREAM,
        "RemoteServer": (*_UPSTREAM, "kind", "route", "path"),
        "ToolkitRule": ("methods", "paths", "approved"),
        "ToolkitSlot": ("route", "rules"),
        "ToolkitServer": (
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
        "GatewayLimits": (
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
        "Gateway": ("clients", "approvals", "servers", "hosts", "origins", "limits"),
        "Admin": ("listen", "origins"),
        "Policy": (
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


@dataclass(frozen=True)
class Header:
    """What an export's first line names: the import's base (H.5, OPS-8)."""

    revision: int
    deployment: str  # its first 8 characters


def export(
    policy: Policy,
    *,
    revision: int,
    deployment: str,
    created: int,
    mode: Mode = "managed",
    target: Target = "plain",
) -> str:
    """Revision ``revision``'s ``policy`` as the document the host exports: the fixed comment
    lines, then the policy (the module docstring)."""
    data = document(policy)
    data["mode"] = mode
    data["gateway_key_generation"] = policy.gateway_key_generation
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created))
    lines = [
        FIRST_LINE.format(revision=revision, deployment=deployment[:8], when=when),
        KEEP_LINE,
        DECLARATIVE_LINE if mode == "declarative" else IMPORT_LINE,
    ]
    spaces = " " * COMPOSE_INDENT if target == "compose" else ""
    comments = "".join(spaces + line + "\n" for line in lines)
    return comments + emitted(_model(policy, data), target=target)


def header(text: str) -> Header | None:
    """The revision and deployment an export's first line names, or None for a document with no
    such line."""
    found = _FIRST.fullmatch(text.partition("\n")[0])
    return None if found is None else Header(int(found[1]), found[2])


def notes(
    policy: Policy,
    *,
    revision: int,
    deployment: str,
    mode: Mode = "managed",
    target: Target = "plain",
) -> list[str]:
    """What the CLI writes to stderr beside :func:`export`'s document (H.6, J7, J10)."""
    said = f"Exported revision {revision} of deployment {deployment[:8]}"
    if mode == "declarative":
        said += " as a declarative policy (mode: declarative)"
    if target == "compose":
        said += ", indented for compose, every $ written as $$"
    lines = [said + ". It holds placeholders and client token hashes: keep it like a secret."]
    if target != "compose":
        return lines
    lines.append(GENERATION_NOTE.format(n=policy.gateway_key_generation))
    origins = [] if policy.admin is None else policy.admin.origins
    for origin in origins:
        found = _LOCALHOST.fullmatch(origin)
        if found is not None:
            lines.append(ORIGIN_NOTE.format(origin=origin, port=found[1]))
    return lines


def _model(model: BaseModel, data: Mapping[str, Any]) -> dict[str, Any]:
    """``model``'s fields that ``data`` (its plain form) holds, in :data:`EXPORT_FIELDS`' order;
    a field the table doesn't name raises ``KeyError``."""
    name = type(model).__name__
    table = EXPORT_FIELDS[name]
    fields = type(model).model_fields
    for field in fields:
        if field not in table:
            raise KeyError(f"{name}.{field}")
    out: dict[str, Any] = {}
    for field in table:
        key = fields[field].alias or field
        if key in data:
            out[key] = _value(getattr(model, field), data[key])
    return out


def _value(value: Any, plain: Any) -> Any:
    if isinstance(value, BaseModel):
        return _model(value, plain)
    if isinstance(value, Mapping):
        return {key: _value(value[key], item) for key, item in plain.items()}
    if isinstance(value, list):
        return [_value(item, plain[index]) for index, item in enumerate(value)]
    return plain
