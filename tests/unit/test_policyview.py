"""The declarative policy, read-only (M5 design L, O.2 ``policyview``): completeness and redaction.

The view is built from an allowlist. The completeness test walks every pydantic model in
``common/policy/schema.py`` and fails unless each field is listed, so a field a later milestone
adds stays out of the answer until someone decides how it shows. The redaction tests put a
distinctive value in every hidden field, by hand and generated, and find none of them in the
answer. Hidden characters are written with ``chr()`` so this file holds none (the hygiene test).
"""

from __future__ import annotations

import json
from typing import Any, get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from zoeymcp.common.policy import schema
from zoeymcp.common.policy.schema import Policy
from zoeymcp.portal import policyview
from zoeymcp.portal.policyview import FIELDS, SET, SOURCES, VALUE_LIMIT, Source, Treatment, view

ELLIPSIS = chr(0x2026)
LITERAL_TOKEN = "hidden-literal-client-token-0001"
TOKEN_HASH = "sha256:" + "4" * 64
PLACEHOLDERS = ("hidden-placeholder-0001", "hidden-placeholder-0002")
BASIC_USER = "hidden-basic-user"
SMTP_USER = "hidden-smtp-user"
SMTP_FROM = "Hidden Sender <hidden-from@mail.example>"
SMTP_TO = ("hidden-to-1@mail.example", "hidden-to-2@mail.example")
TOKEN_HEADER = "hidden-token-header-value"
FORCED = "hidden-forced-value"
HIDDEN_VALUES = (
    LITERAL_TOKEN,
    TOKEN_HASH,
    *PLACEHOLDERS,
    BASIC_USER,
    SMTP_USER,
    "hidden-from",
    "Hidden Sender",
    *SMTP_TO,
    TOKEN_HEADER,
    FORCED,
)


def models() -> dict[str, type[BaseModel]]:
    """Every pydantic model the schema module defines, by class name."""
    return {
        name: value
        for name, value in vars(schema).items()
        if isinstance(value, type)
        and issubclass(value, BaseModel)
        and value.__module__ == schema.__name__
    }


def document() -> dict[str, Any]:
    """A policy with every hidden field set, and every kind of credential, caller and server."""
    return {
        "version": 1,
        "mode": "declarative",
        "egress_proxy": "http://proxy.example:3128",
        "egress_proxy_kind": "role",
        "egress_private": ["api.example:443"],
        "egress_key_generation": 2,
        "egress_proxy_acls": {"vault": "stack_vault_net"},
        "admin": {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]},
        "credentials": {
            "header-cred": {
                "kind": "header",
                "header": "X-Api-Key",
                "format": "Token {secret}",
                "secret": "store:header-key",
            },
            "query-cred": {"kind": "query", "param": "api_key", "secret": "env:QUERY_KEY"},
            "path-cred": {"kind": "path", "template": "/k/{secret}", "secret": "store:path-key"},
            "basic-cred": {"kind": "basic", "username": BASIC_USER, "secret": "store:basic-pass"},
            "oauth-cred": {
                "kind": "oauth2",
                "token_url": "https://auth.example/token",
                "client_id": "example-client",
                "client_secret": "store:oauth-secret",
                "refresh_token": "store:oauth-refresh",
                "extra_params": {"resource": "https://api.example/"},
                "token_headers": {"X-Extra": TOKEN_HEADER},
                "scope": "read write",
                "issuer": "https://auth.example",
                "require_iss": True,
                "revocation_url": "https://auth.example/revoke",
                "resource_metadata": "https://api.example/.well-known/oauth-protected-resource",
            },
        },
        "connectors": {
            "mail-out": {
                "kind": "smtp",
                "host": "smtp.mail.example",
                "port": 465,
                "username": SMTP_USER,
                "password": "store:mail-pass",
                "from": SMTP_FROM,
                "to": list(SMTP_TO),
            }
        },
        "routes": [
            {
                "name": "api",
                "prefix": "/api",
                "upstream": "https://api.example",
                "credential": "header-cred",
                "callers": [
                    "gateway",
                    {"placeholder": PLACEHOLDERS[0], "header": "X-Agent"},
                    {"placeholder": PLACEHOLDERS[1], "query": "agent", "sources": ["10.0.0.0/8"]},
                ],
                "query": {"force": {"mode": FORCED}, "strip": ["debug"]},
                "rules": [
                    {"methods": ["GET"], "paths": ["/items/{id}"], "params": {"id": ["1", "2"]}},
                    {"methods": ["POST"], "paths": ["/search"], "params": {"q": {"regex": "^a"}}},
                ],
            },
            {
                "name": "mail",
                "prefix": "/mail",
                "connector": "mail-out",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/send"]}],
            },
        ],
        "gateway": {
            "clients": {
                "literal": {"token": LITERAL_TOKEN, "servers": ["remote"]},
                "hashed": {
                    "token_sha256": TOKEN_HASH,
                    "servers": ["remote", "bridge", "kit"],
                    "approvals": {"attended": True},
                },
            },
            "servers": {
                "remote": {"kind": "remote", "route": "api", "review": {"t": "sha256:" + "5" * 64}},
                "bridge": {
                    "kind": "bridge",
                    "url": "http://bridge.example:9000/mcp",
                    "egress": ["api.example:443"],
                },
                "kit": {
                    "kind": "toolkit",
                    "module": "zoeymcp.toolkits.example",
                    "slots": {
                        "mail": {
                            "route": "mail",
                            "rules": [{"methods": ["POST"], "paths": ["/send"]}],
                        }
                    },
                },
            },
        },
    }


def rendered(raw: dict[str, Any] | None = None, source: Source = "file") -> dict[str, Any]:
    return view(Policy.model_validate(raw or document()), source)


# --- completeness -------------------------------------------------------------------------------


def test_every_field_of_every_schema_model_is_listed() -> None:
    found = models()
    assert {"Policy", "Client", "PlaceholderCaller", "SMTPConnector"} <= set(found)
    for name, model in found.items():
        if not model.model_fields:
            assert name not in FIELDS, name  # a base without fields (_Model)
            continue
        assert name in FIELDS, f"{name} isn't in policyview.FIELDS: decide how it shows"
        assert set(FIELDS[name]) == set(model.model_fields), name
    assert set(FIELDS) <= set(found)  # nothing listed that the schema doesn't have
    for name, fields in FIELDS.items():
        assert set(fields.values()) <= set(get_args(Treatment)), name


def test_only_the_decided_fields_are_hidden() -> None:
    """L's table, and the two free-text maps sent upstream, shown by name only."""
    hidden = {
        (model, field): treatment
        for model, fields in FIELDS.items()
        for field, treatment in fields.items()
        if treatment != "shown"
    }
    assert hidden == {
        ("BasicCredential", "username"): "hidden",
        ("OAuth2Credential", "token_headers"): "names",
        ("SMTPConnector", "username"): "hidden",
        ("SMTPConnector", "from_"): "hidden",
        ("SMTPConnector", "to"): "addresses",
        ("PlaceholderCaller", "placeholder"): "hidden",
        ("QueryPolicy", "force"): "names",
        ("Client", "token"): "hidden",
        ("Client", "token_sha256"): "hidden",
    }


def test_a_model_or_field_the_table_doesnt_list_is_never_shown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed: a missing entry raises, so the answer is a 500, never the value."""
    policy = Policy.model_validate(document())
    tables = dict(FIELDS)
    del tables["Admin"]
    monkeypatch.setattr(policyview, "FIELDS", tables)
    with pytest.raises(KeyError, match="Admin"):
        view(policy, "file")
    tables["Admin"] = {"listen": "shown"}
    with pytest.raises(KeyError, match="origins"):
        view(policy, "file")


def test_a_value_of_no_known_kind_raises() -> None:
    with pytest.raises(TypeError, match=r"^x\.y: a float has no rendering$"):
        policyview._value(1.5, "x.y", [])


# --- redaction ----------------------------------------------------------------------------------


def test_no_hidden_value_appears() -> None:
    raw = document()
    assert all(value in json.dumps(raw) for value in HIDDEN_VALUES)
    text = json.dumps(rendered(raw))
    for value in HIDDEN_VALUES:
        assert value not in text, value
    assert "sha256:" + "4" not in text  # no token hash, however written


def test_each_hidden_value_shows_only_that_it_is_set() -> None:
    answer = rendered()
    policy = answer["policy"]
    assert policy["credentials"]["basic-cred"] == {
        "kind": "basic",
        "username": SET,
        "secret": "store:basic-pass",
    }
    assert policy["credentials"]["oauth-cred"]["token_headers"] == {"X-Extra": SET}
    connector = policy["connectors"]["mail-out"]
    assert (connector["username"], connector["from"], connector["to"]) == (
        SET,
        SET,
        "(2 addresses)",
    )
    assert "from_" not in connector  # the document's name, not the model's
    callers = policy["routes"][0]["callers"]
    assert callers == [
        "gateway",
        {"placeholder": SET, "header": "X-Agent", "query": None, "sources": []},
        {"placeholder": SET, "header": None, "query": "agent", "sources": ["10.0.0.0/8"]},
    ]
    assert policy["routes"][0]["query"] == {
        "force": {"mode": SET},
        "strip": ["debug"],
        "allow": None,
    }
    clients = policy["gateway"]["clients"]
    assert (clients["literal"]["token"], clients["literal"]["token_sha256"]) == (SET, None)
    assert (clients["hashed"]["token"], clients["hashed"]["token_sha256"]) == (None, SET)
    assert answer["hidden"] == [
        "credentials.basic-cred.username",
        "credentials.oauth-cred.token_headers",
        "connectors.mail-out.username",
        "connectors.mail-out.from",
        "connectors.mail-out.to",
        "routes[0].callers[1].placeholder",
        "routes[0].callers[2].placeholder",
        "routes[0].query.force",
        "gateway.clients.literal.token",
        "gateway.clients.hashed.token_sha256",
    ]


def test_one_address_and_nothing_to_hide() -> None:
    raw = document()
    raw["connectors"]["mail-out"]["to"] = [SMTP_TO[0]]
    del raw["credentials"]["oauth-cred"]["token_headers"]
    del raw["routes"][0]["query"]
    answer = rendered(raw)
    assert answer["policy"]["connectors"]["mail-out"]["to"] == "(1 address)"
    assert answer["policy"]["credentials"]["oauth-cred"]["token_headers"] == {}
    assert answer["policy"]["routes"][0]["query"]["force"] == {}
    assert "credentials.oauth-cred.token_headers" not in answer["hidden"]
    assert "routes[0].query.force" not in answer["hidden"]


_TOKEN = st.from_regex(r"[A-Za-z0-9]{16,40}", fullmatch=True)
_LOCAL = st.from_regex(r"[a-z0-9]{12,30}", fullmatch=True)


@settings(max_examples=50, deadline=None)
@given(
    token=_TOKEN,
    placeholder=_TOKEN,
    basic=_LOCAL,
    smtp_user=_LOCAL,
    sender=_LOCAL,
    recipients=st.lists(_LOCAL, min_size=1, max_size=4, unique=True),
    header_value=_LOCAL,
    forced=_LOCAL,
    hashed=st.booleans(),
    digest=st.from_regex(r"[0-9a-f]{64}", fullmatch=True),
)
def test_for_any_policy_no_hidden_value_appears(
    token: str,
    placeholder: str,
    basic: str,
    smtp_user: str,
    sender: str,
    recipients: list[str],
    header_value: str,
    forced: str,
    hashed: bool,
    digest: str,
) -> None:
    raw = document()
    secrets = {
        "token": "zq" + token,
        "placeholder": "zq" + placeholder,
        "basic": "zq" + basic,
        "smtp_user": "zq" + smtp_user,
        "sender": "zq" + sender,
        "header": "zq" + header_value,
        "forced": "zq" + forced,
        **{f"to{n}": "zq" + local for n, local in enumerate(recipients)},
    }
    client = raw["gateway"]["clients"]["literal"]
    if hashed:
        del client["token"]
        secrets["token"] = digest  # the hex alone: no form of it may show
        client["token_sha256"] = "sha256:" + digest
    else:
        client["token"] = secrets["token"]
    raw["routes"][0]["callers"][1]["placeholder"] = secrets["placeholder"]
    raw["credentials"]["basic-cred"]["username"] = secrets["basic"]
    connector = raw["connectors"]["mail-out"]
    connector["username"] = secrets["smtp_user"]
    connector["from"] = secrets["sender"] + "@mail.example"
    connector["to"] = [secrets[f"to{n}"] + "@mail.example" for n in range(len(recipients))]
    raw["credentials"]["oauth-cred"]["token_headers"] = {"X-Extra": secrets["header"]}
    raw["routes"][0]["query"]["force"] = {"mode": secrets["forced"]}
    text = json.dumps(rendered(raw))
    for where, value in secrets.items():
        assert value not in text, where
    assert f"({len(recipients)} address" in text


# --- what is shown ------------------------------------------------------------------------------


def test_the_answer_shape_and_the_source() -> None:
    answer = rendered(source="env")
    assert list(answer) == ["mode", "source", "source_shown", "policy", "hidden"]
    assert (answer["mode"], answer["source"]) == ("declarative", "env")
    assert answer["source_shown"] == "the ZOEYMCP_CONFIG environment variable"
    assert dict(SOURCES) == {
        "env": "the ZOEYMCP_CONFIG environment variable",
        "file": "the file given with --config",
        "stdin": "standard input, read once at start",
    }
    for source in get_args(Source):
        assert rendered(source=source)["source_shown"] == SOURCES[source]


def test_everything_else_is_shown_as_written_in_the_schemas_order() -> None:
    policy = rendered()["policy"]
    assert list(policy) == list(Policy.model_fields)
    assert policy["admin"] == {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]}
    assert policy["credentials"]["header-cred"] == {
        "kind": "header",
        "secret": "store:header-key",
        "header": "X-Api-Key",
        "format": "Token {secret}",
    }
    assert policy["credentials"]["query-cred"]["secret"] == "env:QUERY_KEY"
    oauth = policy["credentials"]["oauth-cred"]
    assert (oauth["client_secret"], oauth["refresh_token"]) == (
        "store:oauth-secret",
        "store:oauth-refresh",
    )
    assert oauth["extra_params"] == {"resource": "https://api.example/"}
    assert oauth["scope"] == "read write"
    assert policy["routes"][0]["rules"] == [
        {"methods": ["GET"], "paths": ["/items/{id}"], "params": {"id": ["1", "2"]}},
        {"methods": ["POST"], "paths": ["/search"], "params": {"q": {"regex": "^a"}}},
    ]
    servers = policy["gateway"]["servers"]
    assert servers["remote"]["review"] == {"t": "sha256:" + "5" * 64}
    assert servers["bridge"]["egress"] == ["api.example:443"]
    assert servers["kit"]["slots"]["mail"]["rules"] == [
        {"methods": ["POST"], "paths": ["/send"], "approved": False}
    ]
    assert policy["gateway"]["clients"]["hashed"]["approvals"]["attended"] is True
    assert policy["gateway"]["limits"]["call_timeout"] == 300
    assert policy["egress_proxy"] == "http://proxy.example:3128"
    # M7's fields show as written (M7 design A.1): none holds a secret.
    assert (oauth["issuer"], oauth["require_iss"]) == ("https://auth.example", True)
    assert oauth["revocation_url"] == "https://auth.example/revoke"
    assert oauth["resource_metadata"] == "https://api.example/.well-known/oauth-protected-resource"
    assert policy["egress_private"] == ["api.example:443"]
    assert policy["egress_key_generation"] == 2
    assert policy["egress_proxy_acls"] == {"vault": "stack_vault_net"}
    assert policy["egress_proxy_kind"] == "role"


def test_every_string_is_shown() -> None:
    """K.1: a rule's text (which the schema doesn't restrict) is capped and its hidden
    characters revealed; so are the keys."""
    raw = document()
    bidi, long = chr(0x202E), "x" * (VALUE_LIMIT + 5)
    raw["routes"][0]["rules"][0]["params"] = {"id": [f"a{bidi}b", long]}
    policy = rendered(raw)["policy"]
    assert policy["routes"][0]["rules"][0]["params"]["id"] == [
        "a[U+202E]b",
        "x" * VALUE_LIMIT + f"{ELLIPSIS}[+5]",
    ]
    assert VALUE_LIMIT == 2048
    assert policyview._key(f"k{bidi}") == "k[U+202E]"
    assert policyview._key("k" * 130) == "k" * 128 + f"{ELLIPSIS}[+2]"
    assert policyview._value({7: (True, None, 3)}, "p", []) == {"7": [True, None, 3]}


def test_hidden_paths_name_dictionary_keys_as_shown() -> None:
    hidden: list[str] = []
    policyview._value({f"a{chr(0x202E)}": {"b": [Policy.model_validate(document())]}}, "x", hidden)
    assert hidden[0] == "x.a[U+202E].b[0].credentials.basic-cred.username"
