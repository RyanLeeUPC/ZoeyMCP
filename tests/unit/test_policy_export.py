"""The host's export (M6 design H.6, O.3; Q5, Q30, DD-4, G-15, OPS-8, OPS-17).

The field table walks the schema, so a field a later milestone adds fails here until the export
names it, and a model or field the table doesn't name is a ``KeyError``, never a document that
drops it. The round trip: the gate admits the export as the normalized policy, every hidden field
included, and exporting that gives the same bytes; a literal client token is exported as its
hash; any text a policy holds, and any generated policy, comes back the same. The header: the
fixed comment lines, the first one read back for the import's base, the declarative form. The
compose form, with ``$$`` read back as ``$``, is the same document; and the notes, the
interpolated fields' lines among them. Hidden characters are written as escapes so this file holds
none.
"""

from __future__ import annotations

import copy
import re
from typing import Any
from urllib.parse import urlsplit

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from zoeymcp.common.policy import export as export_module
from zoeymcp.common.policy import schema
from zoeymcp.common.policy.emit import COMPOSE_INDENT
from zoeymcp.common.policy.export import (
    DECLARATIVE_LINE,
    EXPORT_FIELDS,
    IMPORT_LINE,
    KEEP_LINE,
    Header,
    export,
    header,
    notes,
)
from zoeymcp.common.policy.gate import admit_text
from zoeymcp.common.policy.plan import normalize
from zoeymcp.common.policy.schema import OAuth2Credential, Policy, hash_token
from zoeymcp.common.yamlload import load_mapping

from .test_policy_emit import (
    dedented,
    header_credentials,
    hosts,
    interpolate,
    names,
    scope_tokens,
    urls,
)

DEPLOYMENT = "6f2e1c0a" + "9" * 24
# 2026-10-24T10:00:00Z, a whole second.
CREATED = 1_792_836_000
LITERAL_TOKEN = "export-literal-token-0001"
PIN = "sha256:" + "d" * 64
ENVIRON = {"HOME": "/root"}


def raw_policy(example_raw: dict[str, Any]) -> dict[str, Any]:
    """The example policy, managed, with what only an export carries: a literal client token, a
    token header, a declined tool, a raised key generation, and text compose and YAML read
    specially."""
    raw = copy.deepcopy(example_raw)
    raw["mode"] = "managed"
    raw["gateway_key_generation"] = 2
    oauth = raw["credentials"]["broker-mcp"]
    oauth["token_headers"] = {"X-Tenant": 'tenant $HOME ${X:-y} "q" \\ #'}
    oauth["client_id"] = "zc-caf\u00e9-\u202e-\U0001f600"
    raw["gateway"]["clients"]["literal"] = {"token": LITERAL_TOKEN, "servers": ["mail"]}
    raw["gateway"]["servers"]["broker-read"]["declined"] = {"close_account": PIN}
    return raw


def made(raw: dict[str, Any]) -> Policy:
    return Policy.model_validate(raw)


def exported(policy: Policy, **options: Any) -> str:
    return export(policy, revision=24, deployment=DEPLOYMENT, created=CREATED, **options)


def admitted(text: str) -> Policy:
    return admit_text(text, "(export)", environ=ENVIRON).policy


def models() -> dict[str, type[BaseModel]]:
    return {
        name: value
        for name, value in vars(schema).items()
        if isinstance(value, type)
        and issubclass(value, BaseModel)
        and value.__module__ == schema.__name__
    }


# --- the field table -----------------------------------------------------------------------------


def test_the_table_names_every_field_of_every_schema_model_in_the_schemas_order() -> None:
    found = models()
    assert {"Policy", "Client", "PlaceholderCaller", "SMTPConnector"} <= set(found)
    for name, model in found.items():
        if not model.model_fields:
            assert name not in EXPORT_FIELDS, name
            continue
        assert name in EXPORT_FIELDS, f"{name} isn't in EXPORT_FIELDS: decide how it exports"
        assert list(EXPORT_FIELDS[name]) == list(model.model_fields), name
    assert set(EXPORT_FIELDS) <= set(found)


def test_a_model_or_field_the_table_doesnt_name_is_never_exported(
    monkeypatch: pytest.MonkeyPatch, example_raw: dict[str, Any]
) -> None:
    """Fail closed: a missing entry raises, so no export silently drops a field."""
    policy = made(raw_policy(example_raw))
    tables = dict(EXPORT_FIELDS)
    del tables["Admin"]
    monkeypatch.setattr(export_module, "EXPORT_FIELDS", tables)
    with pytest.raises(KeyError, match="Admin"):
        exported(policy)
    tables["Admin"] = ("listen",)
    with pytest.raises(KeyError, match=r"Admin\.origins"):
        exported(policy)


def test_the_document_follows_the_tables_order(
    monkeypatch: pytest.MonkeyPatch, example_raw: dict[str, Any]
) -> None:
    policy = made(raw_policy(example_raw))
    tables = dict(EXPORT_FIELDS)
    tables["Admin"] = ("origins", "listen")
    monkeypatch.setattr(export_module, "EXPORT_FIELDS", tables)
    text = exported(policy)
    assert '\nadmin:\n  origins: ["http://localhost:8081", ' in text
    assert text.index("  origins:") < text.index("  listen:")


# --- the round trip ------------------------------------------------------------------------------


def test_the_export_is_admitted_as_the_normalized_policy(example_raw: dict[str, Any]) -> None:
    policy = made(raw_policy(example_raw))
    text = exported(policy)
    back = admitted(text)
    assert back == normalize(policy)
    assert exported(back) == text
    assert load_mapping(text) == load_mapping(exported(back))


def test_every_hidden_field_is_exported(example_raw: dict[str, Any]) -> None:
    """The host's export holds what the portal hides: R61's fourth exception (DD-4)."""
    text = exported(made(raw_policy(example_raw)))
    for value in (
        "ph-agent1-stats-4c1f9b27",  # a placeholder
        '"user": "alice"',  # a forced query value
        '"X-Tenant": "tenant $HOME ${X:-y} \\"q\\" \\\\ #"',  # a token header
        'username: "store:mail-user"',
        'from: "Agent <agent@mail.example>"',
        'to: ["partner@mail.example"]',
        "sha256:8ca973db011281c88e678afeb86d1955579aed24fd7deeae43155fe7aabb0f43",
    ):
        assert value in text, value


def test_a_literal_token_is_exported_as_its_hash(example_raw: dict[str, Any]) -> None:
    text = exported(made(raw_policy(example_raw)))
    assert LITERAL_TOKEN not in text
    assert f'    "literal":\n      token_sha256: "{hash_token(LITERAL_TOKEN)}"\n' in text
    literal = load_mapping(text)["gateway"]["clients"]["literal"]
    assert literal == {"token_sha256": hash_token(LITERAL_TOKEN), "servers": ["mail"]}


def test_text_outside_ascii_is_escaped_and_comes_back(example_raw: dict[str, Any]) -> None:
    policy = made(raw_policy(example_raw))
    text = exported(policy)
    assert text.isascii()
    assert 'client_id: "zc-caf\\xe9-\\u202e-\\U0001f600"' in text
    oauth = admitted(text).credentials["broker-mcp"]
    assert isinstance(oauth, OAuth2Credential)
    assert oauth.client_id == "zc-caf\u00e9-\u202e-\U0001f600"


def test_defaults_are_left_out_but_the_gateway_key_generation_is_always_written(
    example_raw: dict[str, Any],
) -> None:
    raw = raw_policy(example_raw)
    del raw["gateway_key_generation"]
    text = exported(made(raw))
    assert "\ngateway_key_generation: 1\n" in text
    assert "egress_key_generation" not in text
    assert "max_per_day" not in text  # 20, its default
    assert "egress_proxy_kind" not in text
    assert admitted(text).gateway_key_generation == 1


def test_the_documents_order_is_the_schemas(example_raw: dict[str, Any]) -> None:
    text = exported(made(raw_policy(example_raw)))
    top = [line.split(":")[0] for line in text.splitlines() if re.match(r"[a-z_]+:", line)]
    assert top == [
        "version",
        "mode",
        "gateway_key_generation",
        "admin",
        "credentials",
        "connectors",
        "routes",
        "gateway",
    ]
    assert text.count("\n") == len(text.splitlines())


# --- the header ----------------------------------------------------------------------------------


def test_the_fixed_comment_lines(example_raw: dict[str, Any]) -> None:
    text = exported(made(raw_policy(example_raw)))
    assert text.splitlines()[:4] == [
        "# zoeymcp policy export: revision 24 of deployment 6f2e1c0a, 2026-10-24T10:00:00Z.",
        "# It holds placeholders and client token hashes: keep it like a secret.",
        "# Import with zoeymcp policy import.",
        "version: 1",
    ]
    assert (text.splitlines()[1], text.splitlines()[2]) == (KEEP_LINE, IMPORT_LINE)
    assert '\nmode: "managed"\n' in text


def test_the_time_is_utc_to_the_second(example_raw: dict[str, Any]) -> None:
    policy = made(raw_policy(example_raw))
    text = export(policy, revision=1, deployment=DEPLOYMENT, created=CREATED + 3_599 + 86_400)
    assert text.startswith(
        "# zoeymcp policy export: revision 1 of deployment 6f2e1c0a, 2026-10-25T10:59:59Z.\n"
    )
    text = export(policy, revision=1, deployment=DEPLOYMENT, created=0)
    assert ", 1970-01-01T00:00:00Z.\n" in text.splitlines(keepends=True)[0]


def test_the_declarative_form(example_raw: dict[str, Any]) -> None:
    policy = made(raw_policy(example_raw))
    text = exported(policy, mode="declarative")
    assert text.splitlines()[2] == DECLARATIVE_LINE
    assert DECLARATIVE_LINE == (
        "# mode: declarative: the vault runs it as written and keeps its revisions parked; "
        "mode: managed resumes them."
    )
    assert IMPORT_LINE not in text
    assert '\nmode: "declarative"\n' in text
    back = admitted(text)
    assert back.mode == "declarative"
    assert back.model_copy(update={"mode": "managed"}) == normalize(policy)


def test_the_import_reads_the_first_line(example_raw: dict[str, Any]) -> None:
    text = exported(made(raw_policy(example_raw)))
    assert header(text) == Header(24, "6f2e1c0a")
    assert header(exported(made(raw_policy(example_raw)), mode="declarative")) == Header(
        24, "6f2e1c0a"
    )
    most = "# zoeymcp policy export: revision 9999999999 of deployment 0123abcd, x."
    assert header(most) == Header(9_999_999_999, "0123abcd")  # REVISION_MAX


@pytest.mark.parametrize(
    "text",
    [
        "",
        "version: 1\n",
        "\n# zoeymcp policy export: revision 24 of deployment 6f2e1c0a, x.",
        " # zoeymcp policy export: revision 24 of deployment 6f2e1c0a, x.",
        "# zoeymcp policy export: revision 0 of deployment 6f2e1c0a, x.",
        "# zoeymcp policy export: revision 024 of deployment 6f2e1c0a, x.",
        "# zoeymcp policy export: revision 10000000000 of deployment 6f2e1c0a, x.",
        "# zoeymcp policy export: revision -1 of deployment 6f2e1c0a, x.",
        "# zoeymcp policy export: revision 24 of deployment 6F2E1C0A, x.",
        "# zoeymcp policy export: revision 24 of deployment 6f2e1c0, x.",
        "# zoeymcp policy export: revision 24 of deployment 6f2e1c0ab, x.",
        "# zoeymcp policy export: revision 24 of deployment 6f2e1c0a.",
        "# zoeymcp policy export: revision 24 of deployment 6f2e1c0g, x.",
    ],
    ids=[
        "empty",
        "no_comment",
        "second_line",
        "indented",
        "revision_0",
        "leading_zero",
        "11_digits",
        "negative",
        "upper_case",
        "7_characters",
        "9_characters",
        "no_comma",
        "not_hex",
    ],
)
def test_a_document_without_the_line_has_no_header(text: str) -> None:
    assert header(text) is None


# --- the compose form and the notes --------------------------------------------------------------


def test_the_compose_form_is_the_same_document(example_raw: dict[str, Any]) -> None:
    policy = made(raw_policy(example_raw))
    text = exported(policy, target="compose")
    plain = exported(policy)
    assert text == "".join(" " * 8 + line for line in plain.replace("$", "$$").splitlines(True))
    assert " $${X:-y} " in text
    assert dedented(interpolate(text, {"X": "leaked", "HOME": "/root"}), COMPOSE_INDENT) == plain


def test_the_notes_for_an_export_to_import(example_raw: dict[str, Any]) -> None:
    policy = made(raw_policy(example_raw))
    assert notes(policy, revision=24, deployment=DEPLOYMENT) == [
        "Exported revision 24 of deployment 6f2e1c0a. It holds placeholders and client token "
        "hashes: keep it like a secret."
    ]


def test_the_notes_for_the_way_back_to_declarative(example_raw: dict[str, Any]) -> None:
    """J10: the fields the shipped compose files interpolate are now literals."""
    raw = raw_policy(example_raw)
    raw["admin"]["origins"] = [
        "https://zoeymcp.tailnet.example",
        "http://localhost:8081",
        "http://localhost:9443",
    ]
    said = notes(made(raw), revision=9, deployment=DEPLOYMENT, mode="declarative", target="compose")
    assert said == [
        "Exported revision 9 of deployment 6f2e1c0a as a declarative policy (mode: declarative), "
        "indented for compose, every $ written as $$. It holds placeholders and client token "
        "hashes: keep it like a secret.",
        "gateway_key_generation is now a literal 2: put ${ZOEYMCP_GATEWAY_KEY_GENERATION:-2} "
        "back if you rotate by the variable.",
        "admin.origins is now the literal http://localhost:8081: put ${ZOEYMCP_ADMIN_PORT:-8081} "
        "back if you move the port by the variable.",
        "admin.origins is now the literal http://localhost:9443: put ${ZOEYMCP_ADMIN_PORT:-9443} "
        "back if you move the port by the variable.",
    ]


def test_the_notes_name_only_what_is_there(example_raw: dict[str, Any]) -> None:
    raw = raw_policy(example_raw)
    raw["admin"]["origins"] = ["https://zoeymcp.tailnet.example", "https://localhost:8081"]
    said = notes(made(raw), revision=9, deployment=DEPLOYMENT, target="compose")
    assert said == [
        "Exported revision 9 of deployment 6f2e1c0a, indented for compose, every $ written as "
        "$$. It holds placeholders and client token hashes: keep it like a secret.",
        "gateway_key_generation is now a literal 2: put ${ZOEYMCP_GATEWAY_KEY_GENERATION:-2} "
        "back if you rotate by the variable.",
    ]
    no_portal = made({"version": 1, "mode": "declarative"})
    assert notes(no_portal, revision=1, deployment=DEPLOYMENT, mode="declarative") == [
        "Exported revision 1 of deployment 6f2e1c0a as a declarative policy (mode: "
        "declarative). It holds placeholders and client token hashes: keep it like a secret."
    ]
    assert len(notes(no_portal, revision=1, deployment=DEPLOYMENT, target="compose")) == 2


# --- generated -----------------------------------------------------------------------------------

# Any text but surrogates, the line and paragraph separators (B2; M7 lesson 9), and the line breaks
# and NUL the schema refuses in every string.
texts = st.text(
    st.characters(blacklist_categories=("Cs", "Zl", "Zp"), blacklist_characters="\n\r\x00"),
    min_size=1,
    max_size=24,
)
tool_names = st.from_regex(r"[A-Za-z0-9_.-]{1,24}", fullmatch=True)
pins = st.from_regex(r"sha256:[0-9a-f]{64}", fullmatch=True)
tokens = st.from_regex(r"[A-Za-z0-9._~-]{16,40}", fullmatch=True)


@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],  # copied before each use
)
@given(
    client_id=texts,
    header_value=texts,
    forced=texts,
    prefix=texts,
    token=tokens,
    declined=st.dictionaries(tool_names, pins, max_size=3),
    generation=st.integers(1, 2**40),
    target=st.sampled_from(["plain", "compose"]),
)
def test_any_text_comes_back_the_same(
    example_raw: dict[str, Any],
    client_id: str,
    header_value: str,
    forced: str,
    prefix: str,
    token: str,
    declined: dict[str, str],
    generation: int,
    target: Any,
) -> None:
    raw = raw_policy(example_raw)
    oauth = raw["credentials"]["broker-mcp"]
    oauth["client_id"] = client_id
    oauth["token_headers"] = {"X-Tenant": header_value}
    raw["routes"][0]["query"]["force"] = {"user": forced}
    raw["credentials"]["spare"] = {
        "kind": "header",
        "format": prefix + " {secret}",
        "secret": "store:s",
    }
    raw["gateway"]["clients"]["literal"]["token"] = "zq-" + token  # no pin or name holds it
    raw["gateway"]["servers"]["broker-trade"]["declined"] = {
        name: pin for name, pin in declined.items() if name not in ("place_order", "cancel_order")
    }
    raw["gateway_key_generation"] = generation
    policy = made(raw)
    text = exported(policy, target=target)
    plain = exported(policy)
    if target == "compose":
        assert dedented(text, COMPOSE_INDENT).replace("$$", "$") == plain
    back = admitted(plain)
    assert back == normalize(policy)
    assert exported(back) == plain
    assert "zq-" + token not in plain


# Generated policies (H.6, O.3): every credential kind, connector, route, rule (params as lists
# and regexes), program and remote server, built so check admits them; references are made from
# the credential's own name so no two credentials share one.
captures = st.from_regex(r"[a-z_][a-z0-9_]{0,7}", fullmatch=True)
segments = st.from_regex(r"[A-Za-z0-9._~!$&'()+,;=:@-]{1,8}", fullmatch=True).filter(
    lambda segment: segment not in (".", "..")
)
query_params = st.from_regex(r"q[a-z0-9_]{0,6}", fullmatch=True)
header_names = st.from_regex(r"X-[A-Za-z0-9-]{1,12}", fullmatch=True)
route_names = names.filter(lambda n: n not in ("mcp", "mail", "port", "vault"))
methods = st.lists(st.sampled_from(["GET", "POST", "DELETE", "PUT"]), min_size=1, unique=True)
ORIGINS = ["http://localhost:8081", "http://localhost:9443", "https://zoeymcp.tailnet.example"]


def compiles(text: str) -> bool:
    try:
        re.compile(text)
    except re.error:
        return False
    return True


@st.composite
def oauth_credentials(draw: st.DrawFn, name: str) -> dict[str, Any]:
    data: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": draw(urls(query=True)),
        "client_id": draw(texts),
        "refresh_token": f"store:{name}-refresh",
    }
    if draw(st.booleans()):
        data["client_secret"] = f"store:{name}-secret"
        data["client_auth"] = draw(st.sampled_from(["basic", "post"]))
    optional: dict[str, st.SearchStrategy[Any]] = {
        "rotates": st.booleans(),
        "token_body": st.sampled_from(["form", "json"]),
        "token_headers": st.dictionaries(header_names, texts, min_size=1, max_size=2),
        "scope": st.lists(scope_tokens, min_size=1, max_size=3).map(" ".join),
        "expected_scopes": st.lists(scope_tokens, max_size=3),
        "refresh_skew": st.integers(0, 3600),
        "idle_expiry_days": st.integers(1, 3650),
        "authorize_params": st.dictionaries(st.just("prompt"), texts, max_size=1),
    }
    for key, strategy in optional.items():
        if draw(st.booleans()):
            data[key] = draw(strategy)
    return data


@st.composite
def credentials(draw: st.DrawFn, name: str) -> Any:
    secret = f"store:{name}-key"
    kind = draw(st.sampled_from(["oauth2", "header", "basic", "path", "query"]))
    if kind == "oauth2":
        return draw(oauth_credentials(name))
    if kind == "header":
        return draw(header_credentials()).model_copy(update={"secret": secret})
    if kind == "basic":
        username = draw(texts.filter(lambda t: ":" not in t))
        return {"kind": "basic", "username": username, "secret": secret}
    if kind == "path":
        return {"kind": "path", "template": f"/{draw(segments)}/{{secret}}", "secret": secret}
    return {"kind": "query", "param": draw(query_params), "secret": secret}


@st.composite
def rules(draw: st.DrawFn) -> dict[str, Any]:
    taken = draw(st.lists(captures, max_size=2, unique=True))
    path = "/" + "/".join([*draw(st.lists(segments, max_size=2)), *(f"{{{n}}}" for n in taken)])
    if draw(st.booleans()):
        path = path.rstrip("/") + "/**"
    rule: dict[str, Any] = {"methods": draw(methods), "paths": [path]}
    values = st.lists(texts, min_size=1, max_size=2) | texts.filter(compiles).map(
        lambda regex: {"regex": regex}
    )
    if taken:
        rule["params"] = {name: draw(values) for name in taken}
    return rule


@st.composite
def programs(draw: st.DrawFn) -> dict[str, Any]:
    egress = draw(st.lists(hosts.map(lambda host: host + ":443"), max_size=2, unique=True))
    return {"egress": egress, "egress_private": egress[: draw(st.integers(0, len(egress)))]}


@st.composite
def routes(draw: st.DrawFn, index: int, name: str, named: list[str]) -> dict[str, Any]:
    route: dict[str, Any] = {
        "name": name,
        "prefix": "/" + name,
        "upstream": draw(urls()),
        "callers": [{"placeholder": f"ph-{index}-" + draw(tokens)}],
        "rules": draw(st.lists(rules(), min_size=1, max_size=2)),
    }
    if draw(st.booleans()) and named:
        route["credential"] = draw(st.sampled_from(named))
    if draw(st.booleans()):
        route["query"] = {"force": draw(st.dictionaries(query_params, texts, max_size=2))}
    if draw(st.booleans()):
        route["program"] = draw(programs())
    return route


@st.composite
def remote_servers(draw: st.DrawFn) -> dict[str, Any]:
    include = draw(st.lists(tool_names, max_size=3, unique=True))
    cut = draw(st.integers(0, len(include)))
    declined = draw(st.dictionaries(tool_names, pins, max_size=2))
    return {
        "kind": "remote",
        "route": "mcp",
        "path": "/mcp",
        "tools": {"include": include, "allow": include[:cut], "approve": include[cut:]},
        "review": {tool: draw(pins) for tool in include},
        "declined": {tool: pin for tool, pin in declined.items() if tool not in include},
    }


@st.composite
def policies(draw: st.DrawFn) -> Policy:
    """A managed policy check admits."""
    named = draw(st.lists(names, max_size=4, unique=True))
    rest = [
        draw(routes(index, name, named))
        for index, name in enumerate(draw(st.lists(route_names, max_size=3, unique=True)))
    ]
    mcp = {
        "name": "mcp",
        "prefix": "/mcp",
        "upstream": draw(urls()),
        "callers": ["gateway"],
        "stream": True,
        "rules": [{"methods": ["GET", "POST", "DELETE"], "paths": ["/mcp"]}],
    }
    servers = {name: draw(remote_servers()) for name in draw(st.lists(names, max_size=2))}
    raw: dict[str, Any] = {
        "version": 1,
        "mode": "managed",
        "gateway_key_generation": draw(st.integers(1, 2**40)),
        "admin": {
            "listen": "127.0.0.1:8081",
            "origins": draw(st.lists(st.sampled_from(ORIGINS), min_size=1, unique=True)),
        },
        "credentials": {name: draw(credentials(name)) for name in named},
        "routes": [*rest, mcp],
        "gateway": {
            "servers": servers,
            "clients": {"agent": {"token": "zq-" + draw(tokens), "servers": sorted(servers)}},
        },
    }
    for route in rest:
        # check refuses a forced query value named as the route's query credential's param.
        cred = raw["credentials"].get(route.get("credential", ""))
        if isinstance(cred, dict) and cred["kind"] == "query" and "query" in route:
            route["query"]["force"].pop(cred["param"], None)
    if draw(st.booleans()):
        raw["connectors"] = {
            "mail": {
                "kind": "smtp",
                "host": draw(hosts),
                "port": draw(st.integers(1, 65535)),
                "username": draw(texts),
                "password": "store:mail-pass",
                "from": "Agent <agent@mail.example>",
                "to": draw(
                    st.lists(
                        st.sampled_from(["a@mail.example", "b@mail.example"]),
                        min_size=1,
                        unique=True,
                    )
                ),
                "paused": draw(st.booleans()),
            }
        }
        raw["routes"].append(
            {
                "name": "mail",
                "prefix": "/mail",
                "connector": "mail",
                "callers": ["gateway"],
                "rules": [
                    {"methods": ["GET"], "paths": ["/config"]},
                    {"methods": ["POST"], "paths": ["/send"]},
                ],
            }
        )
    sources = [
        "vault",
        *(route["name"] for route in rest if route.get("program", {}).get("egress")),
    ]
    acl = st.from_regex(r"[A-Za-z0-9_]{1,20}", fullmatch=True)
    raw["egress_proxy_acls"] = draw(st.dictionaries(st.sampled_from(sources), acl, max_size=2))
    upstreams = sorted({f"{urlsplit(r['upstream']).hostname}:443" for r in [*rest, mcp]})
    raw["egress_private"] = draw(st.lists(st.sampled_from(upstreams), max_size=2, unique=True))
    return made(raw)


@settings(max_examples=50, deadline=None)
@given(policies())
def test_a_generated_policy_comes_back_the_same(policy: Policy) -> None:
    plain = exported(policy)
    back = admitted(plain)
    assert back == normalize(policy)
    assert exported(back) == plain
    compose = exported(policy, target="compose")
    assert dedented(compose, COMPOSE_INDENT).replace("$$", "$") == plain
    assert exported(back, target="compose") == compose


# --- a model inside a mapping or a list ----------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "last"),
    [
        ("Client", "approvals"),  # gateway.clients, a mapping of models
        ("Route", "program"),  # routes, a list of models
    ],
)
def test_a_model_inside_a_mapping_or_a_list_is_written_by_the_table(
    monkeypatch: pytest.MonkeyPatch, example_raw: dict[str, Any], model: str, last: str
) -> None:
    """The table governs a model reached through a mapping's values or a list's items as it does a
    field's model: one it doesn't name, or one of whose fields it doesn't name, raises."""
    policy = made(raw_policy(example_raw))
    tables = dict(EXPORT_FIELDS)
    monkeypatch.setattr(export_module, "EXPORT_FIELDS", tables)
    del tables[model]
    with pytest.raises(KeyError, match=f"^'{model}'$"):
        exported(policy)
    tables[model] = tuple(field for field in EXPORT_FIELDS[model] if field != last)
    with pytest.raises(KeyError, match=re.escape(f"{model}.{last}")):
        exported(policy)
