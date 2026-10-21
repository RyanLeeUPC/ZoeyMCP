"""The egress allowlists, derived once (M7 design I.2, I.6, O.2 ``test_egresslist.py``).

Every source and reason, sorting and merging, private exceptions, the onboarding allowances, the
digest over the lists alone, the three output forms (the Squid form's ``zoeymcp_private_dst``
equal to netguard's tables, TI-8) and compare mode.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
import yaml

from zoeymcp.common import canonical, netguard
from zoeymcp.common.egresslist import (
    PLAIN_HTTP_NOTE,
    Allowance,
    Destination,
    Lists,
    Reason,
    compare,
    derive,
    digest,
    document,
    private_exceptions,
    render,
)
from zoeymcp.common.policy import Policy, parse_policy

Raw = dict[str, Any]
RULES = [{"methods": ["GET"], "paths": ["/**"]}]


def route(name: str, upstream: str, **fields: Any) -> Raw:
    callers = [{"placeholder": f"ph-{name}-0123456789abcdef"}]
    return {
        "name": name,
        "prefix": f"/{name}",
        "upstream": upstream,
        "callers": callers,
        "rules": copy.deepcopy(RULES),
        **fields,
    }


def smtp(host: str, port: int) -> Raw:
    return {
        "kind": "smtp",
        "host": host,
        "port": port,
        "username": "store:mail-user",
        "password": "store:mail-pass",
        "from": "agent@mail.example",
        "to": ["partner@mail.example"],
    }


def oauth(token_url: str, **fields: Any) -> Raw:
    return {
        "kind": "oauth2",
        "token_url": token_url,
        "client_id": "client-1",
        "refresh_token": "store:o-seed",
        **fields,
    }


def policy_raw() -> Raw:
    return {
        "version": 1,
        "mode": "declarative",
        "egress_private": ["10.0.0.9:587", "lan.example:80", "unused.example:443"],
        "credentials": {
            "o1": oauth("https://auth.example/token", revocation_url="https://auth.example/rev"),
            "o2": oauth("http://127.0.0.1:9000/token"),
            "key": {"kind": "header", "secret": "store:key"},
        },
        "connectors": {"mail": smtp("SMTP.Mail.Example", 465), "lan-mail": smtp("10.0.0.9", 587)},
        "routes": [
            route("plain", "http://lan.example", allow_insecure_upstream=True),
            route("api", "https://API.Example"),
            route("port", "https://api.example:8443/v1"),
            route("six", "https://[2001:db8::5]"),
            route("auth", "https://auth.example/api", credential="key"),
            {
                "name": "send",
                "prefix": "/send",
                "connector": "mail",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/send"]}],
            },
        ],
    }


def parse(raw: Raw) -> Policy:
    return parse_policy(yaml.safe_dump(raw, sort_keys=False), "test")


def dest(
    host: str, port: int, *reasons: Reason, private: bool = False, http: bool = False
) -> Destination:
    return Destination(host, port, private, frozenset(reasons), plain_http=http)


EXPECTED = (
    dest("10.0.0.9", 587, "connector", private=True),
    dest("127.0.0.1", 9000, "token", http=True),
    dest("2001:db8::5", 443, "route"),
    dest("api.example", 443, "route"),
    dest("api.example", 8443, "route"),
    dest("auth.example", 443, "route", "token", "revocation"),
    dest("lan.example", 80, "route", private=True, http=True),
    dest("smtp.mail.example", 465, "connector"),
)


def test_every_vault_source_and_reason() -> None:
    assert derive(parse(policy_raw())) == {"vault": EXPECTED}


def test_the_order_of_the_policy_does_not_matter() -> None:
    raw = policy_raw()
    raw["routes"].reverse()
    raw["credentials"] = dict(reversed(list(raw["credentials"].items())))
    raw["connectors"] = dict(reversed(list(raw["connectors"].items())))
    assert derive(parse(raw)) == {"vault": EXPECTED}


def test_an_empty_policy_still_has_the_vault_source() -> None:
    lists = derive(parse({"version": 1, "mode": "declarative"}))
    assert lists == {"vault": ()}
    assert document(lists)["sources"] == {"vault": []}


def test_private_exceptions_are_egress_private() -> None:
    policy = parse(policy_raw())
    assert private_exceptions(policy) == frozenset(
        {"10.0.0.9:587", "lan.example:80", "unused.example:443"}
    )
    assert private_exceptions(parse({"version": 1, "mode": "declarative"})) == frozenset()


def test_an_ipv6_entry_in_egress_private_marks_its_destination() -> None:
    raw = policy_raw()
    raw["egress_private"] = ["[2001:db8::5]:443"]
    lists = derive(parse(raw))
    assert [d.host for d in lists["vault"] if d.private] == ["2001:db8::5"]


# --- onboarding allowances ---------------------------------------------------------------------


def test_an_allowance_adds_destinations_that_are_never_private() -> None:
    allowances = [
        Allowance(frozenset({("MCP.Notes.Example", 443), ("auth.example", 443)})),
        Allowance(frozenset({("unused.example", 443)})),
        Allowance(frozenset()),
    ]
    found = derive(parse(policy_raw()), allowances)["vault"]
    by_key = {(d.host, d.port): d for d in found}
    assert by_key[("mcp.notes.example", 443)] == dest("mcp.notes.example", 443, "onboarding")
    assert by_key[("auth.example", 443)].reasons == {"route", "token", "revocation", "onboarding"}
    # In egress_private, but only an allowance reaches it: the shared vault list would give every
    # vault connection to it the exception (TI-10).
    assert by_key[("unused.example", 443)] == dest("unused.example", 443, "onboarding")
    assert [(d.host, d.port) for d in found] == sorted(by_key)
    assert len(found) == len(EXPECTED) + 2


def test_an_allowance_keeps_a_policy_destinations_private_mark() -> None:
    found = derive(parse(policy_raw()), [Allowance(frozenset({("lan.example", 80)}))])["vault"]
    assert dest("lan.example", 80, "route", "onboarding", private=True, http=True) in found


# --- the digest and the document ---------------------------------------------------------------


def test_the_document() -> None:
    lists = derive(parse(policy_raw()))
    sources = {"vault": [{"host": d.host, "port": d.port, "private": d.private} for d in EXPECTED]}
    assert document(lists) == {"v": 1, "digest": canonical.digest(sources), "sources": sources}
    assert digest(lists) == canonical.digest(sources)


def test_sources_are_sorted_by_name() -> None:
    one = (dest("a.example", 443, "program"),)
    lists: Lists = {"vault": (), "bridge-fetch": one}
    assert list(document(lists)["sources"]) == ["bridge-fetch", "vault"]
    assert render(lists, "text").splitlines()[1:] == ["bridge-fetch a.example:443"]


@pytest.mark.parametrize(
    "edit",
    [
        lambda r: r["routes"][1].update(rules=[{"methods": ["POST"], "paths": ["/x"]}]),
        lambda r: r["credentials"]["o1"].update(client_id="client-2"),
        lambda r: r["connectors"]["mail"].update(max_per_day=5),
        lambda r: r.update(gateway_key_generation=3, egress_key_generation=2),
        # A new reason for an existing destination: the lists don't hold reasons.
        lambda r: r["routes"].append(route("auth2", "https://auth.example/other")),
    ],
)
def test_an_unrelated_edit_keeps_the_digest(edit: Any) -> None:
    raw = policy_raw()
    before = digest(derive(parse(raw)))
    edit(raw)
    assert digest(derive(parse(raw))) == before


def test_the_plain_http_mark_is_the_text_forms_alone() -> None:
    marked: Lists = {"vault": (dest("api.example", 80, "route", http=True),)}
    unmarked: Lists = {"vault": (dest("api.example", 80, "route"),)}
    assert digest(marked) == digest(unmarked)
    assert render(marked, "json") == render(unmarked, "json")
    assert render(marked, "text") != render(unmarked, "text")


@pytest.mark.parametrize(
    "edit",
    [
        lambda r: r.update(egress_private=["10.0.0.9:587"]),
        lambda r: r["routes"][1].update(upstream="https://api.example:444"),
        lambda r: r["routes"][1].update(upstream="https://api2.example"),
        lambda r: r["routes"].pop(1),
    ],
)
def test_a_list_edit_changes_the_digest(edit: Any) -> None:
    raw = policy_raw()
    before = digest(derive(parse(raw)))
    edit(raw)
    assert digest(derive(parse(raw))) != before


# --- the forms -----------------------------------------------------------------------------------

SMALL: Lists = {
    "vault": (
        dest("10.0.0.9", 587, "connector", private=True),
        dest("2001:db8::5", 443, "route"),
        dest("auth.notes.example", 443, "token"),
        dest("lan.example", 80, "route", private=True, http=True),
    )
}


def test_the_text_form() -> None:
    assert render(SMALL, "text") == (
        f"# zoeymcp egress allowlist, lists {digest(SMALL)}\n"
        "vault 10.0.0.9:587\n"
        "vault [2001:db8::5]:443\n"
        "vault auth.notes.example:443\n"
        f"vault lan.example:80  # {PLAIN_HTTP_NOTE}\n"
    )
    assert PLAIN_HTTP_NOTE == "plain http: refused by a CONNECT-only proxy"


def test_the_json_form_is_the_document() -> None:
    text = render(SMALL, "json")
    assert text.endswith("}\n")
    assert json.loads(text) == document(SMALL)


def squid_head(lists: Lists, acls: str) -> list[str]:
    return [
        f"# zoeymcp egress allowlist, lists {digest(lists)}; regenerate with zoeymcp check "
        "--emit-egress-allowlist; keep your own final deny",
        f"# expects your squid.conf to define: acl CONNECT method CONNECT, and {acls}",
        "acl zoeymcp_private_dst dst " + " ".join(netguard.squid_private_dst()),
    ]


def test_the_squid_form() -> None:
    assert render(SMALL, "squid").splitlines() == [
        *squid_head(SMALL, "acl zoeymcp_src_vault src <the vault's network>"),
        "acl zoeymcp_port_80 port 80",
        "acl zoeymcp_port_443 port 443",
        "acl zoeymcp_port_587 port 587",
        "acl zoeymcp_vault_1 dst -n 10.0.0.9",
        "http_access allow zoeymcp_src_vault CONNECT zoeymcp_vault_1 zoeymcp_port_587",
        "acl zoeymcp_vault_2 dst -n 2001:db8::5",
        "http_access allow zoeymcp_src_vault CONNECT zoeymcp_vault_2 zoeymcp_port_443 "
        "!zoeymcp_private_dst",
        "acl zoeymcp_vault_3 dstdomain -n auth.notes.example",
        "http_access allow zoeymcp_src_vault CONNECT zoeymcp_vault_3 zoeymcp_port_443 "
        "!zoeymcp_private_dst",
        "acl zoeymcp_vault_4 dstdomain -n lan.example",
        "http_access allow zoeymcp_src_vault CONNECT zoeymcp_vault_4 zoeymcp_port_80",
    ]
    assert render(SMALL, "squid").endswith("zoeymcp_port_80\n")


def test_the_squid_private_rule_is_netguards_tables() -> None:
    # TI-8: the emitted rule is the guard's own tables, never a hand-written subset.
    line = next(x for x in render(SMALL, "squid").splitlines() if "zoeymcp_private_dst dst" in x)
    entries = line.removeprefix("acl zoeymcp_private_dst dst ").split(" ")
    assert tuple(entries) == netguard.squid_private_dst()
    assert set(entries) <= set(netguard.DENIED_V4) | set(netguard.DENIED_V6)
    # Squid holds IPv4 as IPv4-mapped: this row would refuse every IPv4 destination.
    assert "::ffff:0:0/96" not in entries


def test_the_squid_form_names_the_operators_acls() -> None:
    lists: Lists = {
        "vault": (dest("auth.notes.example", 443, "token"),),
        "bridge-fetch": (dest("docs.example.org", 443, "program"),),
    }
    lines = render(lists, "squid", acl_names={"vault": "stack_vault_net"}).splitlines()
    assert lines[:3] == squid_head(
        lists,
        "acl zoeymcp_src_bridge-fetch src <the bridge-fetch's network>, and "
        "acl stack_vault_net src <the vault's network>",
    )
    assert lines[3:] == [
        "acl zoeymcp_port_443 port 443",
        "acl zoeymcp_bridge-fetch_1 dstdomain -n docs.example.org",
        "http_access allow zoeymcp_src_bridge-fetch CONNECT zoeymcp_bridge-fetch_1 "
        "zoeymcp_port_443 !zoeymcp_private_dst",
        "acl zoeymcp_vault_1 dstdomain -n auth.notes.example",
        "http_access allow stack_vault_net CONNECT zoeymcp_vault_1 zoeymcp_port_443 "
        "!zoeymcp_private_dst",
    ]


def test_the_squid_form_never_defines_the_operators_acls_or_a_final_deny() -> None:
    text = render(derive(parse(policy_raw())), "squid")
    rules = [line for line in text.splitlines() if not line.startswith("#")]
    assert rules
    assert not [line for line in rules if line.startswith(("acl CONNECT ", "acl zoeymcp_src_"))]
    assert not [line for line in rules if "deny" in line]


def test_an_empty_list_renders_only_the_header() -> None:
    lists: Lists = {"vault": ()}
    assert render(lists, "text") == f"# zoeymcp egress allowlist, lists {digest(lists)}\n"
    expected = squid_head(lists, "acl zoeymcp_src_vault src <the vault's network>")
    assert render(lists, "squid").splitlines() == expected


# --- compare -------------------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["text", "json", "squid"])
def test_compare_finds_nothing_in_the_emitted_text(fmt: Any) -> None:
    lists = derive(parse(policy_raw()))
    text = render(lists, fmt, acl_names={"vault": "net_v"})
    assert compare(lists, text, fmt, acl_names={"vault": "net_v"}) == []
    assert compare(lists, text.replace("\n", "\r\n"), fmt, acl_names={"vault": "net_v"}) == []


def test_compare_lists_the_differences_sorted() -> None:
    lists = derive(parse(policy_raw()))
    text = render(lists, "text")
    edited = text.replace("vault smtp.mail.example:465\n", "vault smtp.mail.example:25\n")
    old_head = f"# zoeymcp egress allowlist, lists {digest(lists)}"
    edited = edited.replace(old_head, "# zoeymcp egress allowlist, lists sha256:0")
    assert compare(lists, edited, "text") == [
        f"missing: {old_head}",
        "missing: vault smtp.mail.example:465",
        "unexpected: # zoeymcp egress allowlist, lists sha256:0",
        "unexpected: vault smtp.mail.example:25",
    ]


def test_compare_counts_a_repeated_line() -> None:
    lists: Lists = {"vault": (dest("a.example", 443, "route"), dest("b.example", 443, "route"))}
    text = render(lists, "json")
    port = '\n        "port": 443,\n'
    line = port.strip("\n")
    assert text.count(port) == 2
    assert compare(lists, text.replace(port, "\n", 1), "json") == [f"missing: {line}"]
    assert compare(lists, text.replace(port, port + line + "\n", 1), "json") == [
        f"unexpected: {line}"
    ]
    doubled = render(lists, "text") * 2
    assert compare(lists, doubled, "text") == [
        f"unexpected: {line}" for line in sorted(render(lists, "text").splitlines())
    ]


def test_compare_finds_lines_out_of_order() -> None:
    lists = derive(parse(policy_raw()))
    lines = render(lists, "squid").splitlines()
    # The ACL definitions moved after the rules that use them: Squid can't parse that.
    moved = "\n".join(lines[3:] + lines[:3]) + "\n"
    assert compare(lists, moved, "squid") == [f"order: line 1 should be: {lines[0]}"]
    text = render(lists, "text").splitlines()
    swapped = "\n".join([text[0], text[2], text[1], *text[3:]]) + "\n"
    assert compare(lists, swapped, "text") == [f"order: line 2 should be: {text[1]}"]


def test_compare_uses_the_acl_names() -> None:
    lists = derive(parse(policy_raw()))
    text = render(lists, "squid")
    differences = compare(lists, text, "squid", acl_names={"vault": "net_v"})
    assert differences
    assert all("zoeymcp_src_vault" in d or "net_v" in d for d in differences)
