"""The YAML emitter (M7 design H.2, H.3, O.2 ``test_policy_emit.py``; TI-1, X10).

A fragment is written from a fixed field table, a subset of what the policy view shows; every
string is a double-quoted string of printable ASCII, every name a quoted key; the output loads
with the strict loader to exactly the change's plain form, and its compose form survives compose's
interpolation with the master key in the environment. ``document`` writes ``check --with
--print-merged``'s whole policy, escaping what the emitter would refuse.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, get_args

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.common.policy import Policy, schema
from zoeymcp.common.policy.change import (
    AddCredential,
    AddEgressPrivate,
    AddRoute,
    AddServer,
    Comment,
    CommentKind,
    PolicyChange,
    SetCredential,
    SetServerReview,
    apply,
)
from zoeymcp.common.policy.emit import (
    BOOLEAN,
    COMMENTS,
    COMPOSE_INDENT,
    CREDENTIALS,
    EMIT_MAX,
    FIELD_NAMES,
    FIELDS,
    INDENT_MAX,
    INTEGER,
    STRING,
    STRING_MAP,
    STRINGS,
    EmitRefused,
    _field_names,
    _table,
    document,
    emit,
)
from zoeymcp.common.policy.merge import Merged, merge, replace_paths
from zoeymcp.common.policy.schema import (
    HeaderCredential,
    OAuth2Credential,
    QueryCredential,
    RemoteServer,
    Route,
    Tools,
)
from zoeymcp.common.yamlload import YAMLRejected, load_mapping
from zoeymcp.portal import policyview

from .test_policy_change import (
    NOTES_CREDENTIAL,
    NOTES_ROUTE,
    NOTES_SERVER,
    PIN_A,
    example,
    notes_change,
    review_change,
)

MASTER_KEY = "zoeymcp-master-key-must-never-reach-a-policy"
PRINTABLE = "".join(chr(c) for c in range(0x20, 0x7F))

FRAGMENT_1 = """\
# zoeymcp: onboarding notes (1 of 2). Merge into your policy; nothing here replaces a key you have.
credentials:
  "notes":
    kind: "oauth2"
    token_url: "https://auth.notes.example/oauth/token?tenant=notes"
    authorize_url: "https://auth.notes.example/oauth/authorize"
    issuer: "https://auth.notes.example"
    require_iss: true
    revocation_url: "https://auth.notes.example/oauth/revoke"
    resource_metadata: "https://mcp.notes.example/.well-known/oauth-protected-resource/mcp"
    client_id: "zc_4f1c9a"
    client_auth: "none"
    refresh_token: "store:notes-refresh"
    rotates: true
    redirect_uri: "http://127.0.0.1/callback/notes"
    scope: "notes.read notes.write offline_access"
    extra_params:
      "resource": "https://mcp.notes.example/mcp"
    authorize_params:
      "resource": "https://mcp.notes.example/mcp"
routes:
  - name: "notes"
    prefix: "/notes"
    upstream: "https://mcp.notes.example"
    credential: "notes"
    callers: ["gateway"]
    stream: true
    rules:
      - methods: ["POST", "GET", "DELETE"]
        paths: ["/mcp"]
gateway:
  servers:
    "notes":
      kind: "remote"
      route: "notes"
      path: "/mcp"
      tools:
        include: []
egress_private: ["mcp.lan.example:443"]
"""
FRAGMENT_2 = f"""\
# zoeymcp: review of broker-read (2 of 2)
# zoeymcp replace: gateway.servers.broker-read.tools gateway.servers.broker-read.review
gateway:
  servers:
    "broker-read":
      era: "modern"
      tools:
        include: ["get_quote"]
        allow: ["get_quote"]
      review:
        "get_quote": "{PIN_A}"
"""


def fragment_applied(policy: Policy, text: str) -> Policy:
    """What ``check --with`` makes of a fragment's text: the strict loader, its header's replace
    paths, the merge, the schema."""
    base = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    result = merge(base, load_mapping(text), replace=replace_paths(text))
    assert isinstance(result, Merged), result
    return Policy.model_validate(result.data)


def interpolate(text: str, environ: Mapping[str, str]) -> str:
    """Compose's interpolation: ``$$`` is ``$``; ``${VAR}``, ``${VAR:-default}``, ``${VAR-x}``,
    ``${VAR:?err}`` and ``$VAR`` are the variable's value."""

    def value(match: re.Match[str]) -> str:
        if match.group(0) == "$$":
            return "$"
        name = match.group(1) or match.group(3)
        default = match.group(2) or ""
        return environ.get(name, default.lstrip(":-?"))

    pattern = r"\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)((?::?[-?])[^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
    return re.sub(pattern, value, text)


def dedented(text: str, spaces: int) -> str:
    lines = text.splitlines(keepends=True)
    assert all(line.startswith(" " * spaces) for line in lines)
    return "".join(line[spaces:] for line in lines)


# --- the field table -----------------------------------------------------------------------------


def test_the_table_is_a_subset_of_what_the_view_shows() -> None:
    """H.2: never a field the policy view hides, so a new hidden field can't leak into a
    fragment (H.3)."""
    for model, table in FIELDS.items():
        shown = policyview.FIELDS[model]
        for name in table:
            assert name in shown, (model, name)
            assert shown[name] in ("shown", "names", "addresses"), (model, name)


def test_every_table_field_is_a_schema_field_and_typed_as_one() -> None:
    simple = {STRING: str, BOOLEAN: bool, INTEGER: int}
    for model, table in FIELDS.items():
        fields = getattr(schema, model).model_fields
        for name, kind in table.items():
            assert name in fields, (model, name)
            annotation = repr(fields[name].annotation)
            if kind in simple:
                assert simple[kind].__name__ in annotation or "Literal" in annotation, (model, name)
            elif kind == STRINGS:
                assert annotation.startswith("list["), (model, name)
            elif kind == STRING_MAP:
                assert annotation.startswith("dict["), (model, name)
            else:
                target = kind.strip("[]{}")
                assert target == "Credential" or target in FIELDS, (model, name)
    assert set(CREDENTIALS.values()) <= set(FIELDS)


def test_the_table_holds_no_secret_value_client_limit_or_connector() -> None:
    """H.3: refs only, no token_headers, client tokens, limits, admin or connectors."""
    assert set(FIELDS["Policy"]) == {"credentials", "routes", "gateway", "egress_private"}
    assert set(FIELDS["Gateway"]) == {"servers"}
    assert "token_headers" not in FIELDS["OAuth2Credential"]
    assert {"connector", "query"}.isdisjoint(FIELDS["Route"])
    assert "Client" not in FIELDS
    assert "PlaceholderCaller" not in FIELDS
    assert set(CREDENTIALS) == {"oauth2", "header"}


def test_a_table_is_read_only() -> None:
    table = _table(kind=STRING, rotates=BOOLEAN)
    assert list(table.items()) == [("kind", STRING), ("rotates", BOOLEAN)]
    with pytest.raises(TypeError):
        table["kind"] = BOOLEAN  # type: ignore[index]


def test_every_comment_kind_has_its_words() -> None:
    assert set(COMMENTS) == set(get_args(CommentKind))


def test_the_limits() -> None:
    assert (EMIT_MAX, INDENT_MAX, COMPOSE_INDENT) == (2 * 1024 * 1024, 16, 8)


# --- the two fragments ---------------------------------------------------------------------------


def test_fragment_1_byte_for_byte() -> None:
    text = emit(notes_change())
    assert text == FRAGMENT_1
    assert load_mapping(text) == notes_change().data()


def test_fragment_2_byte_for_byte() -> None:
    text = emit(review_change())
    assert text == FRAGMENT_2
    assert load_mapping(text) == review_change().data()
    assert fragment_applied(example(), text) == apply(example(), review_change())


def test_a_re_registration_keeps_every_setting_it_carries() -> None:
    """D.12, OPS-3: a SetCredential replaces the credential whole, so its fragment writes every
    setting, expected_scopes and the lifetimes included, and check --with merges it as the vault
    applies it."""
    old = example().credentials["broker-mcp"]
    assert isinstance(old, OAuth2Credential)
    new = old.model_copy(
        update={
            "client_id": "zc_new",
            "grant": "client_credentials",
            "reseed": "on-change",
            "token_body": "json",
            "scope_separator": ",",
            "scope": "read,trade",
            "refresh_skew": 60,
            "default_expires_in": 600,
            "grant_lifetime_days": 90,
            "idle_expiry_days": 180,
        }
    )
    change = PolicyChange(
        "re-registration of broker-mcp",
        (Comment("changed_was", "broker-mcp", "client_id"), SetCredential("broker-mcp", new)),
    )
    text = emit(change)
    assert text == (
        "# zoeymcp: re-registration of broker-mcp\n"
        "# zoeymcp replace: credentials.broker-mcp\n"
        "# changed: broker-mcp (client_id)\n"
        "credentials:\n"
        '  "broker-mcp":\n'
        '    kind: "oauth2"\n'
        '    token_url: "https://auth.broker.example/oauth/token"\n'
        '    grant: "client_credentials"\n'
        '    client_id: "zc_new"\n'
        '    refresh_token: "store:broker-refresh"\n'
        "    rotates: true\n"
        '    reseed: "on-change"\n'
        '    scope_separator: ","\n'
        '    scope: "read,trade"\n'
        '    expected_scopes: ["read", "trade"]\n'
        "    refresh_skew: 60\n"
        "    default_expires_in: 600\n"
        "    grant_lifetime_days: 90\n"
        "    idle_expiry_days: 180\n"
        "    extra_params:\n"
        '      "resource": "https://mcp.broker.example/"\n'
        '    token_body: "json"\n'
    )
    assert replace_paths(text) == (("credentials", "broker-mcp"),)
    assert load_mapping(text) == change.data()
    merged = fragment_applied(example(), text)
    assert merged == apply(example(), change)
    assert merged.credentials["broker-mcp"] == new
    assert new.expected_scopes == ["read", "trade"]


def test_a_re_registration_with_token_headers_is_refused() -> None:
    """H.3: token_headers values never reach a fragment, so a credential holding them can't be
    written whole; the refusal names the field rather than dropping it."""
    old = OAuth2Credential.model_validate(
        {**NOTES_CREDENTIAL, "token_headers": {"X-Tenant": "notes"}}
    )
    error = refused(PolicyChange("t", (SetCredential("notes", old),)))
    assert (error.path, error.reason) == ("credentials.notes.token_headers", "field")


def test_a_header_credential_and_comments() -> None:
    header = HeaderCredential(kind="header", secret="store:fetch", format='Token "{secret}" \\x')
    change = PolicyChange(
        "t",
        (
            Comment("added", "fetch"),
            AddCredential("fetch", header),
            Comment("changed_was", "notes", "client_id"),
            Comment("error_finding", "bad_tool", "inputSchema isn't valid JSON Schema"),
        ),
    )
    assert emit(change) == (
        "# zoeymcp: t\n"
        "# added: fetch\n"
        "# changed: notes (client_id)\n"
        "# can't be included, error finding: bad_tool (inputSchema isn't valid JSON Schema)\n"
        "credentials:\n"
        '  "fetch":\n'
        '    kind: "header"\n'
        '    secret: "store:fetch"\n'
        '    format: "Token \\"{secret}\\" \\\\x"\n'
    )
    assert load_mapping(emit(change)) == change.data()


def test_an_empty_change_is_an_empty_mapping() -> None:
    assert emit(PolicyChange("nothing")) == "# zoeymcp: nothing\n{}\n"
    assert load_mapping(emit(PolicyChange("nothing"))) == {}


def test_empty_blocks_and_every_scalar_kind() -> None:
    server = RemoteServer.model_validate(
        {
            "kind": "remote",
            "route": "r",
            "era": "legacy",
            "on_drift": "fail",
            "wrap_results": False,
            "call_timeout": 30,
            "tools": {},
            "review": {},
        }
    )
    route = Route.model_validate({**NOTES_ROUTE, "allow_insecure_upstream": False})
    credential = OAuth2Credential.model_validate({**NOTES_CREDENTIAL, "extra_params": {}})
    change = PolicyChange(
        "t", (AddServer("s", server), AddRoute(route), AddCredential("c", credential))
    )
    text = emit(change)
    assert "      tools: {}\n      review: {}\n" in text
    assert "      wrap_results: false\n      call_timeout: 30\n" in text
    assert "    allow_insecure_upstream: false\n" in text
    assert "    extra_params: {}\n" in text
    assert load_mapping(text) == change.data()


def test_a_servers_declined_block_is_written_after_its_pins() -> None:
    """M6 design A.4: ``declined`` is a review block, a map of tool names to pins like
    ``review``; a server without one writes none."""
    pin_b = "sha256:" + "b" * 64
    server = RemoteServer.model_validate(
        {
            "kind": "remote",
            "route": "r",
            "tools": {"include": ["read"], "allow": ["read"]},
            "review": {"read": PIN_A},
            "declined": {"write": pin_b, "yes": pin_b},
        }
    )
    change = PolicyChange("t", (AddServer("s", server),))
    text = emit(change)
    assert (
        f'      review:\n        "read": "{PIN_A}"\n'
        f'      declined:\n        "write": "{pin_b}"\n        "yes": "{pin_b}"\n'
    ) in text
    assert load_mapping(text) == change.data()
    assert yaml.safe_load(text)["gateway"]["servers"]["s"]["declined"] == {
        "write": pin_b,
        "yes": pin_b,
    }
    plain = RemoteServer.model_validate({"kind": "remote", "route": "r"})
    assert "declined" not in emit(PolicyChange("t", (AddServer("s", plain),)))


def test_a_declined_entry_outside_the_rule_is_refused() -> None:
    assert stub_refused({"gateway": {"servers": {"x": {"declined": {"a": 1}}}}}) == (
        "gateway.servers.x.declined.a",
        "type",
    )
    server = {"gateway": {"servers": {"x": {"declined": {"\u00e9": PIN_A}}}}}
    assert stub_refused(server) == ("gateway.servers.x.declined.\u00e9", "characters")


def test_names_that_read_as_other_types_stay_strings() -> None:
    """``yes``, ``on``, ``1e3``, ``0x10``, ``.inf`` and ``null`` stay strings even to a YAML 1.1
    loader, as keys and as values (``~``, ``<<`` and ``12:30`` aren't tool names)."""
    names = ["yes", "on", "1e3", "0x10", ".inf", "null", "0755", "-", "true", "Off", ".NaN"]
    tools = Tools(include=names)
    change = PolicyChange("t", (SetServerReview("x", tools, dict.fromkeys(names, PIN_A)),))
    text = emit(change)
    for loaded in (load_mapping(text), yaml.safe_load(text)):
        server = loaded["gateway"]["servers"]["x"]
        assert server["tools"]["include"] == names
        assert list(server["review"]) == names


def test_a_hostile_scope_or_path_is_one_string() -> None:
    credential = OAuth2Credential.model_validate(
        {**NOTES_CREDENTIAL, "scope": "a:b #c {d} [e]", "client_id": '"} x: "y\\'}
    )
    route = Route.model_validate(
        {**NOTES_ROUTE, "rules": [{"methods": ["GET"], "paths": ['/a" # b\\', "*", "&x"]}]}
    )
    change = PolicyChange("t", (AddCredential("c", credential), AddRoute(route)))
    loaded = load_mapping(emit(change))
    assert loaded == change.data()
    assert set(loaded["credentials"]["c"]) == set(change.data()["credentials"]["c"])


# --- refusals ------------------------------------------------------------------------------------


def refused(change: PolicyChange) -> EmitRefused:
    with pytest.raises(EmitRefused) as caught:
        emit(change)
    return caught.value


@pytest.mark.parametrize(
    "text", ["caf\u00e9", "a\tb", "a\x7fb", "\u202eevil", "a\u200bb", "\x00", "\U0001f600"]
)
def test_a_string_outside_printable_ascii_is_refused(text: str) -> None:
    credential = OAuth2Credential.model_validate(NOTES_CREDENTIAL).model_copy(
        update={"client_id": text}
    )
    error = refused(PolicyChange("t", (AddCredential("notes", credential),)))
    assert (error.path, error.reason, error.value) == (
        "credentials.notes.client_id",
        "characters",
        text,
    )
    assert str(error) == "credentials.notes.client_id: characters"


def test_a_list_item_or_a_title_or_a_comment_outside_the_rule_is_refused() -> None:
    route = Route.model_validate(NOTES_ROUTE)
    rule = route.rules[0].model_copy(update={"paths": ["/mcp", "/m\u00e9"]})
    change = PolicyChange("t", (AddRoute(route.model_copy(update={"rules": [rule]})),))
    error = refused(change)
    assert (error.path, error.reason, error.value) == (
        "routes[0].rules[0].paths[1]",
        "characters",
        "/m\u00e9",
    )
    error = refused(PolicyChange("title\nsecond line"))
    assert (error.path, error.reason) == ("(title)", "characters")
    error = refused(PolicyChange("t", (Comment("added", "x", "\u00e9"),)))
    assert (error.path, error.reason) == ("(comment)", "characters")


def test_a_field_outside_the_table_is_refused() -> None:
    credential = OAuth2Credential.model_validate(
        {**NOTES_CREDENTIAL, "token_headers": {"X-Key": "literal-secret"}}
    )
    error = refused(PolicyChange("t", (AddCredential("notes", credential),)))
    assert (error.path, error.reason, error.value) == (
        "credentials.notes.token_headers",
        "field",
        "",
    )
    route = Route.model_validate({**NOTES_ROUTE, "query": {"force": {"user": "alice"}}})
    error = refused(PolicyChange("t", (AddRoute(route),)))
    assert (error.path, error.reason) == ("routes[0].query", "field")


def test_a_value_of_another_type_is_refused() -> None:
    credential = OAuth2Credential.model_validate(
        {**NOTES_CREDENTIAL, "extra_params": {"resource": ["https://a.example/", "https://b/"]}}
    )
    error = refused(PolicyChange("t", (AddCredential("notes", credential),)))
    assert (error.path, error.reason) == ("credentials.notes.extra_params.resource", "type")
    route = Route.model_validate({**NOTES_ROUTE, "callers": [{"placeholder": "ph-0123456789"}]})
    error = refused(PolicyChange("t", (AddRoute(route),)))
    assert (error.path, error.reason) == ("routes[0].callers", "type")


def test_a_credential_kind_no_fragment_holds_is_refused() -> None:
    query = QueryCredential(kind="query", param="k", secret="store:k")
    error = refused(PolicyChange("t", (AddCredential("q", query),)))  # type: ignore[arg-type]
    assert (error.path, error.reason) == ("credentials.q.kind", "kind")


def test_a_fragment_over_2_mib_is_refused() -> None:
    paths = ["/" + "p" * 1023] * 2100
    route = Route.model_validate({**NOTES_ROUTE, "rules": [{"methods": ["GET"], "paths": paths}]})
    error = refused(PolicyChange("t", (AddRoute(route),)))
    assert (error.path, error.reason) == ("(document)", "size")
    fits = Route.model_validate(
        {**NOTES_ROUTE, "rules": [{"methods": ["GET"], "paths": paths[:2000]}]}
    )
    assert len(emit(PolicyChange("t", (AddRoute(fits),))).encode()) <= EMIT_MAX


def test_a_fragment_of_exactly_2_mib_is_written() -> None:
    def sized(last: int) -> PolicyChange:
        paths = ["/" + "p" * 1023] * 2039 + ["/" + "q" * (last - 1)]
        rule = {"methods": ["GET"], "paths": paths}
        return PolicyChange(
            "t", (AddRoute(Route.model_validate({**NOTES_ROUTE, "rules": [rule]})),)
        )

    gap = EMIT_MAX - len(emit(sized(1)).encode())
    assert 0 < gap < 1024
    assert len(emit(sized(1 + gap)).encode()) == EMIT_MAX
    error = refused(sized(2 + gap))
    assert (error.path, error.reason) == ("(document)", "size")


@dataclass(frozen=True)
class Stub:
    """A change whose plain form is given, to reach what no op makes."""

    data_: dict[str, Any]
    title: str = "t"

    def data(self) -> dict[str, Any]:
        return self.data_

    def replace(self) -> tuple[tuple[str, ...], ...]:
        return ()

    def comments(self) -> tuple[Comment, ...]:
        return ()


def stub(data: dict[str, Any]) -> str:
    return emit(Stub(data))  # type: ignore[arg-type]


def stub_refused(data: dict[str, Any]) -> tuple[str, str]:
    with pytest.raises(EmitRefused) as caught:
        stub(data)
    return caught.value.path, caught.value.reason


def test_empty_blocks_no_op_makes() -> None:
    assert stub({"credentials": {}, "routes": []}) == "# zoeymcp: t\ncredentials: {}\nroutes: []\n"
    text = stub({"gateway": {"servers": {"x": {}}}, "routes": [{}]})
    assert text == '# zoeymcp: t\nroutes:\n  - {}\ngateway:\n  servers:\n    "x": {}\n'
    assert load_mapping(text) == {"gateway": {"servers": {"x": {}}}, "routes": [{}]}
    assert stub({"gateway": {}}) == "# zoeymcp: t\ngateway: {}\n"


@pytest.mark.parametrize(
    ("data", "path"),
    [
        ({"routes": [{"name": 3}]}, "routes[0].name"),
        ({"routes": [{"stream": "yes"}]}, "routes[0].stream"),
        ({"routes": [{"stream": 1}]}, "routes[0].stream"),
        ({"gateway": {"servers": {"x": {"call_timeout": True}}}}, "gateway.servers.x.call_timeout"),
        ({"gateway": {"servers": {"x": {"call_timeout": "30"}}}}, "gateway.servers.x.call_timeout"),
        ({"egress_private": "a.lan.example:443"}, "egress_private"),
        ({"egress_private": ["a", 1]}, "egress_private"),
        ({"credentials": {"c": {"kind": "header", "secret": None}}}, "credentials.c.secret"),
        ({"credentials": ["c"]}, "credentials"),
        ({"credentials": {"c": "store:x"}}, "credentials.c"),
        ({"gateway": {"servers": {"x": {"review": ["a"]}}}}, "gateway.servers.x.review"),
        ({"gateway": {"servers": {"x": {"review": {"a": 1}}}}}, "gateway.servers.x.review.a"),
        ({"routes": {"name": "x"}}, "routes"),
        ({"routes": ["x"]}, "routes[0]"),
        ({"gateway": []}, "gateway"),
        ({"gateway": {"servers": {"x": {"tools": ["a"]}}}}, "gateway.servers.x.tools"),
    ],
)
def test_a_value_unlike_its_table_entry_is_refused(data: dict[str, Any], path: str) -> None:
    assert stub_refused(data) == (path, "type")


@pytest.mark.parametrize("kind", [None, 3, "basic", "OAUTH2"])
def test_a_credential_without_a_fragment_kind_is_refused(kind: Any) -> None:
    data = {"credentials": {"c": {} if kind is None else {"kind": kind}}}
    assert stub_refused(data) == ("credentials.c.kind", "kind")


def test_a_name_outside_the_rule_is_refused() -> None:
    assert stub_refused({"credentials": {"c\u00e9": {"kind": "header"}}}) == (
        "credentials.c\u00e9",
        "characters",
    )
    assert stub_refused({"gateway": {"servers": {"x": {"review": {"\u00e9": PIN_A}}}}}) == (
        "gateway.servers.x.review.\u00e9",
        "characters",
    )
    assert stub_refused({"x": 1}) == ("x", "field")


# --- indent and the compose form -----------------------------------------------------------------


@pytest.mark.parametrize("indent", [0, 1, 8, 16])
def test_indent_prefixes_every_line(indent: int) -> None:
    text = emit(notes_change(), indent=indent)
    assert text == "".join(" " * indent + line for line in FRAGMENT_1.splitlines(keepends=True))
    assert replace_paths(emit(review_change(), indent=indent))


@pytest.mark.parametrize("indent", [-1, 17])
def test_indent_is_0_to_16(indent: int) -> None:
    with pytest.raises(ValueError, match="indent is 0 to 16 spaces"):
        emit(notes_change(), indent=indent)


def test_the_compose_form_is_indented_8_with_every_dollar_doubled() -> None:
    credential = OAuth2Credential.model_validate(
        {**NOTES_CREDENTIAL, "scope": "${ZOEYMCP_MASTER_KEY} $ZOEYMCP_MASTER_KEY $$"}
    )
    change = PolicyChange("t $HOME", (AddCredential("notes", credential),))
    text = emit(change, target="compose")
    assert text == emit(change, target="compose", indent=COMPOSE_INDENT)
    plain = emit(change)
    assert text == "".join(" " * 8 + line for line in plain.replace("$", "$$").splitlines(True))
    assert '"$${ZOEYMCP_MASTER_KEY} $$ZOEYMCP_MASTER_KEY $$$$"' in text
    environ = {"ZOEYMCP_MASTER_KEY": MASTER_KEY, "HOME": "/root"}
    assert load_mapping(dedented(interpolate(text, environ), 8)) == change.data()
    # Without the compose form, compose would write the master key into the policy.
    assert MASTER_KEY in interpolate(plain, environ)


def test_the_compose_form_takes_no_other_indent() -> None:
    with pytest.raises(ValueError, match=r"^the compose form is indented 8; give no other indent$"):
        emit(notes_change(), target="compose", indent=4)


# --- properties ----------------------------------------------------------------------------------

names = st.from_regex(r"[a-z0-9][a-z0-9_-]{0,20}", fullmatch=True)
tool_names = st.from_regex(r"[A-Za-z0-9_.-]{1,24}", fullmatch=True)
pins = st.from_regex(r"sha256:[0-9a-f]{64}", fullmatch=True)
refs = st.from_regex(r"store:[a-z0-9][a-z0-9_.-]{0,20}", fullmatch=True)
# Printable ASCII, with what compose and YAML read specially made likely.
texts = st.text(
    alphabet=st.sampled_from(PRINTABLE) | st.sampled_from(['"', "\\", "$", "{", "}", "#", ":"]),
    max_size=24,
)
hosts = st.from_regex(r"[a-z](?:[a-z0-9-]{0,9}[a-z0-9])?\.example", fullmatch=True)
url_paths = st.text(alphabet=PRINTABLE.replace("?", "").replace("#", ""), max_size=20)
# A.1's endpoint-query rule, with names no credential reserves.
query_values = st.from_regex(r"[A-Za-z0-9._~!()*+,=:@/?-]{0,8}|%2[0-9A-F]", fullmatch=True)
queries = st.dictionaries(
    st.from_regex(r"q[a-z]{0,6}", fullmatch=True), query_values, min_size=1, max_size=3
).map(lambda pairs: "&".join(f"{name}={value}" for name, value in pairs.items()))
# A.1's scope tokens without ",", so no token holds either separator.
scope_tokens = st.from_regex(r"[\x21\x23-\x2b\x2d-\x5b\x5d-\x7e]{1,12}", fullmatch=True)


@st.composite
def urls(draw: st.DrawFn, *, query: bool = False) -> str:
    url = f"https://{draw(hosts)}/{draw(url_paths)}"
    if query and draw(st.booleans()):
        url += "?" + draw(queries)
    return url


@st.composite
def oauth_credentials(draw: st.DrawFn) -> OAuth2Credential:
    data: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": draw(urls(query=True)),
        "client_id": draw(texts.filter(bool)),
    }
    optional: dict[str, st.SearchStrategy[Any]] = {
        "authorize_url": urls(query=True),
        "issuer": urls(),
        "require_iss": st.booleans(),
        "revocation_url": urls(),
        "resource_metadata": urls(),
        "refresh_token": refs,
        "rotates": st.booleans(),
        "redirect_uri": st.just("http://127.0.0.1/callback/x"),
        "grant": st.sampled_from(["refresh_token", "client_credentials"]),
        "reseed": st.sampled_from(["never", "on-change"]),
        "token_body": st.sampled_from(["form", "json"]),
        "scope_separator": st.sampled_from([" ", ","]),
        "scope": st.lists(scope_tokens, min_size=1, max_size=3),
        "expected_scopes": st.lists(scope_tokens, max_size=3),
        "refresh_skew": st.integers(0, 3600),
        "default_expires_in": st.integers(60, 86400),
        "grant_lifetime_days": st.integers(1, 3650),
        "idle_expiry_days": st.integers(1, 3650),
        "extra_params": st.dictionaries(st.sampled_from(["resource", "audience"]), urls()),
        "authorize_params": st.dictionaries(st.sampled_from(["resource", "prompt"]), texts),
    }
    for key, strategy in optional.items():
        if draw(st.booleans()):
            data[key] = draw(strategy)
    if "scope" in data:
        data["scope"] = data.get("scope_separator", " ").join(data["scope"])
    if draw(st.booleans()):
        data["client_secret"] = draw(refs)
        data["client_auth"] = draw(st.sampled_from(["basic", "post"]))
    elif draw(st.booleans()):
        data["client_auth"] = "none"
    return OAuth2Credential.model_validate(data)


@st.composite
def header_credentials(draw: st.DrawFn) -> HeaderCredential:
    data: dict[str, Any] = {"kind": "header", "secret": draw(refs)}
    if draw(st.booleans()):
        data["header"] = draw(st.from_regex(r"[A-Za-z0-9-]{1,20}", fullmatch=True))
    if draw(st.booleans()):
        prefix = draw(texts.filter(lambda t: "{secret}" not in t and "{" not in t[-1:]))
        data["format"] = prefix + "{secret}"
    return HeaderCredential.model_validate(data)


@st.composite
def routes(draw: st.DrawFn, name: str) -> Route:
    rules = st.fixed_dictionaries(
        {
            "methods": st.lists(
                st.sampled_from(["GET", "POST", "DELETE", "PUT"]), min_size=1, max_size=3
            ),
            "paths": st.lists(texts.filter(bool), min_size=1, max_size=3),
        }
    )
    data: dict[str, Any] = {
        "name": name,
        "prefix": "/" + name,
        "upstream": draw(urls()),
        "callers": ["gateway"],
        "rules": draw(st.lists(rules, min_size=1, max_size=2)),
    }
    for key, strategy in {
        "credential": names,
        "stream": st.booleans(),
        "allow_insecure_upstream": st.booleans(),
    }.items():
        if draw(st.booleans()):
            data[key] = draw(strategy)
    return Route.model_validate(data)


@st.composite
def servers(draw: st.DrawFn) -> RemoteServer:
    data: dict[str, Any] = {"kind": "remote", "route": draw(names)}
    for key, strategy in {
        "path": texts.filter(bool),
        "era": st.sampled_from(["auto", "modern", "legacy"]),
        "on_drift": st.sampled_from(["hide", "fail"]),
        "wrap_results": st.booleans(),
        "call_timeout": st.integers(1, 3600),
        "tools": st.fixed_dictionaries({"include": st.lists(tool_names, max_size=3)}),
        "review": st.dictionaries(tool_names, pins, max_size=3),
        "declined": st.dictionaries(tool_names, pins, max_size=2),
    }.items():
        if draw(st.booleans()):
            data[key] = draw(strategy)
    return RemoteServer.model_validate(data)


@st.composite
def changes(draw: st.DrawFn) -> PolicyChange:
    """A fragment 1, a fragment 2 or a re-registration against :func:`property_base`, with
    comments."""
    ops: list[Any] = []
    if draw(st.booleans()):
        credential = draw(oauth_credentials() | header_credentials())
        ops.append(AddCredential(draw(names.filter(lambda n: n != "kept")), credential))
    if draw(st.booleans()):
        ops.append(SetCredential("kept", draw(oauth_credentials())))
    if draw(st.booleans()):
        ops.append(AddRoute(draw(routes(draw(names)))))
    if draw(st.booleans()):
        ops.append(AddServer(draw(names.filter(lambda n: n != "existing")), draw(servers())))
    for entry in draw(st.lists(hosts, max_size=2, unique=True)):
        ops.append(AddEgressPrivate(f"{entry}:{draw(st.integers(1, 65535))}"))
    if draw(st.booleans()):
        include = draw(st.lists(tool_names, max_size=4, unique=True))
        review = {tool: draw(pins) for tool in include}
        era = draw(st.none() | st.sampled_from(["auto", "modern", "legacy"]))
        ops.append(SetServerReview("existing", Tools(include=include), review, era=era))
    for kind in draw(st.lists(st.sampled_from(sorted(COMMENTS)), max_size=2)):
        ops.append(Comment(kind, draw(tool_names), draw(st.none() | texts)))
    return PolicyChange(draw(texts), tuple(ops))


def property_base() -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "mode": "declarative",
            "egress_private": ["kept.lan.example:443"],
            # A SetCredential replaces it whole: none of these settings survives one.
            "credentials": {
                "kept": {
                    "kind": "oauth2",
                    "token_url": "https://auth.kept.example/token",
                    "client_id": "zc_kept",
                    "expected_scopes": ["kept.read"],
                    "idle_expiry_days": 180,
                    "token_headers": {"X-Tenant": "kept"},
                }
            },
            "gateway": {
                "servers": {
                    "existing": {
                        "kind": "remote",
                        "route": "r",
                        "tools": {"include": ["old"], "allow": ["old"]},
                        "review": {"old": PIN_A},
                    }
                }
            },
        }
    )


@settings(max_examples=150, deadline=None)
@given(changes())
def test_every_change_round_trips_and_applies_alike(change: PolicyChange) -> None:
    text = emit(change)
    assert load_mapping(text) == change.data()
    assert fragment_applied(property_base(), text) == apply(property_base(), change)


@settings(max_examples=100, deadline=None)
@given(changes())
def test_the_compose_form_survives_compose_interpolation(change: PolicyChange) -> None:
    """TI-1: a hostile environment (the master key set) gives back exactly the change."""
    text = emit(change, target="compose")
    environ = {"ZOEYMCP_MASTER_KEY": MASTER_KEY, "HOME": "/root", "q": "x"}
    restored = dedented(interpolate(text, environ), COMPOSE_INDENT)
    assert restored == emit(change)
    assert load_mapping(restored) == change.data()
    assert MASTER_KEY not in restored


# Where arbitrary text can sit in a change once its models are copied without validation.
SLOTS = ["title", "detail", "client_id", "scope", "format", "path", "rule_path", "tool"]


def with_text(slot: str, text: str) -> PolicyChange:
    oauth = OAuth2Credential.model_validate(NOTES_CREDENTIAL)
    header = HeaderCredential(kind="header", secret="store:h")
    route = Route.model_validate(NOTES_ROUTE)
    server = RemoteServer.model_validate(NOTES_SERVER)
    title, detail = "t", None
    if slot == "title":
        title = text
    elif slot == "detail":
        detail = text
    elif slot in ("client_id", "scope"):
        oauth = oauth.model_copy(update={slot: text})
    elif slot == "format":
        header = header.model_copy(update={"format": text})
    elif slot == "path":
        server = server.model_copy(update={"path": text})
    elif slot == "rule_path":
        route = route.model_copy(
            update={"rules": [route.rules[0].model_copy(update={"paths": [text]})]}
        )
    else:
        server = server.model_copy(update={"tools": Tools.model_construct(include=[text])})
    ops = (
        AddCredential("notes", oauth),
        AddCredential("header", header),
        AddRoute(route),
        AddServer("notes", server),
        Comment("suggested", "x", detail),
    )
    return PolicyChange(title, ops)


@settings(max_examples=200, deadline=None)
@given(st.sampled_from(SLOTS), st.text())
def test_any_unicode_is_refused_or_round_trips(slot: str, text: str) -> None:
    change = with_text(slot, text)
    if re.fullmatch(r"[\x20-\x7e]*", text):
        # A title or a comment is a comment line, so it never changes what the fragment says.
        assert load_mapping(emit(change)) == change.data()
        return
    with pytest.raises(EmitRefused) as caught:
        emit(change)
    assert (caught.value.reason, caught.value.value) == ("characters", text)


# --- a whole document ----------------------------------------------------------------------------


def test_a_whole_policy_round_trips(example_raw: dict[str, Any]) -> None:
    text = document(example_raw)
    assert load_mapping(text) == example_raw
    assert text.startswith('version: 1\nmode: "declarative"\n')
    assert '\n  "music-stats":\n' in text  # a name is quoted
    assert "\n    from: " in text  # a field name, aliases included, is bare


def test_document_escapes_what_emit_refuses() -> None:
    data: dict[str, Any] = {
        "routes": [
            {
                "name": 'a\nb\u00e9\U0001f600\x01"\\\u200b',
                "callers": ["gateway", {"placeholder": "ph", "sources": []}],
                "query": {"force": {}},
                "rules": [{"methods": ["GET"], "paths": ["/x"], "params": {"n": [["a"], [{}]]}}],
            }
        ],
        "gateway": {"limits": {"call_timeout": 30}, "hosts": []},
        "yes": True,
        "no": False,
        "admin": None,
        "numbers": {"m": 1.5, "n": -2},
        "nested": [[{"a": 1}], [[1, 2]]],
    }
    text = document(data)
    assert '"a\\x0ab\\xe9\\U0001f600\\x01\\"\\\\\\u200b"' in text
    assert all(re.fullmatch(r"[\x20-\x7e]*", line) for line in text.splitlines())
    assert load_mapping(text) == data
    assert '\n"yes": true\n"no": false\nadmin: null\n' in text
    assert '\n  "m": 1.5\n  "n": -2\n' in text
    # A key that isn't a string is written as its value would be, and the strict loader refuses
    # it there as anywhere (M6 design B3).
    numbered = document({"numbers": {3: 1.5}})
    assert numbered == '"numbers":\n  3: 1.5\n'
    with pytest.raises(YAMLRejected, match=r"^key 3 at /numbers is not a string$"):
        load_mapping(numbered)


def test_document_indents_and_takes_the_compose_form() -> None:
    data = {"credentials": {"c": {"kind": "query", "param": "k", "secret": "env:$X"}}}
    assert document(data, indent=2) == (
        '  credentials:\n    "c":\n      kind: "query"\n      param: "k"\n      secret: "env:$X"\n'
    )
    compose = document(data, target="compose")
    assert compose.startswith("        credentials:\n")
    assert '"env:$$X"' in compose
    assert document({}) == "{}\n"
    with pytest.raises(ValueError, match="indent is 0 to 16"):
        document(data, indent=17)


def test_document_escapes_at_each_boundary() -> None:
    text = document({"scope": "\x1f ~\x7f\xff\u0100\uffff\U00010000"})
    assert text == 'scope: "\\x1f ~\\x7f\\xff\\u0100\\uffff\\U00010000"\n'
    assert load_mapping(text) == {"scope": "\x1f ~\x7f\xff\u0100\uffff\U00010000"}


def test_document_refuses_a_value_with_no_yaml_form() -> None:
    with pytest.raises(TypeError, match="a set has no YAML form here"):
        document({"x": {1, 2}})


def test_field_names_are_the_documents() -> None:
    names = _field_names(Policy)
    assert names == FIELD_NAMES
    assert {"from", "token_url", "servers", "include", "placeholder"} <= names
    assert "from_" not in names
    assert all(re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in names)
