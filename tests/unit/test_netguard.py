"""The address and host guard (M7 design B.1, O.2 ``test_netguard.py``).

Every row of both tables, both sides of each boundary, every mapped, compatible, 6to4, Teredo and
NAT64 form of three private addresses, the host-name rules, the egress-list key, the Squid
entries (against a model of how Squid holds addresses: IPv4 as IPv4-mapped), and two properties:
no address the standard library calls non-global is ever allowed, and the Squid rule refuses an
IPv4 address, or its mapped form, exactly when the guard does. From step 18b, a local MCP
route's rules (``local_target``, ``local_only``) on both sides of each ``LOCAL_*`` boundary, with
a property that ``local_only`` never allows a global address, and a bridge socket's peer rule
(``unix_peer``).
"""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.common import netguard
from zoeymcp.common.netguard import (
    DENIED_V4,
    DENIED_V6,
    INTERNAL_SUFFIXES,
    LOCAL_V4,
    LOCAL_V6,
    AddressVerdict,
    HostVerdict,
    addresses_allowed,
    classify,
    entry_key,
    listed,
    local_only,
    local_target,
    squid_private_dst,
    unix_peer,
    untrusted_host,
)
from zoeymcp.common.policy import fields, schema

# The two IPv6 rows whose addresses are judged by the IPv4 address they carry.
BY_IPV4 = ("::ffff:0:0/96", "::/96")


def test_the_tables_are_pinned() -> None:
    assert DENIED_V4 == (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
    assert DENIED_V6 == (
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
    assert INTERNAL_SUFFIXES == (
        "localhost",
        "local",
        "internal",
        "lan",
        "home.arpa",
        "corp",
        "intranet",
        "invalid",
        "test",
    )


def test_the_copied_patterns_equal_the_schemas() -> None:
    # netguard may import only the standard library, so it keeps copies.
    assert netguard._HOSTNAME.pattern == schema._HOSTNAME.pattern
    assert netguard._NUMERIC_LABEL.pattern == fields._NUMERIC_LABEL.pattern


# --- classify ----------------------------------------------------------------------------------


@pytest.mark.parametrize(("net", "kind"), netguard._V4_CLASSES + netguard._V6_CLASSES)
def test_every_row_is_refused_at_both_ends(net: str, kind: str) -> None:
    network = ipaddress.ip_network(net)
    for address in (network.network_address, network.broadcast_address):
        found = classify(str(address))
        assert found != "global"
        if net not in BY_IPV4:
            assert found == kind
        assert not addresses_allowed([str(address)], private_ok=False).allowed


@pytest.mark.parametrize(
    ("address", "kind"),
    [
        ("0.255.255.255", "unspecified"),
        ("1.0.0.0", "global"),
        ("9.255.255.255", "global"),
        ("10.0.0.0", "private"),
        ("10.255.255.255", "private"),
        ("11.0.0.0", "global"),
        ("100.63.255.255", "global"),
        ("100.64.0.0", "cgnat"),
        ("100.127.255.255", "cgnat"),
        ("100.128.0.0", "global"),
        ("126.255.255.255", "global"),
        ("127.0.0.0", "loopback"),
        ("128.0.0.0", "global"),
        ("169.253.255.255", "global"),
        ("169.254.169.254", "link_local"),
        ("169.255.0.0", "global"),
        ("172.15.255.255", "global"),
        ("172.16.0.0", "private"),
        ("172.31.255.255", "private"),
        ("172.32.0.0", "global"),
        ("191.255.255.255", "global"),
        ("192.0.0.0", "reserved"),
        ("192.0.2.0", "documentation"),
        ("192.0.3.0", "global"),
        ("192.88.98.255", "global"),
        ("192.88.99.0", "reserved"),
        ("192.88.100.0", "global"),
        ("192.167.255.255", "global"),
        ("192.168.0.0", "private"),
        ("192.169.0.0", "global"),
        ("198.17.255.255", "global"),
        ("198.18.0.0", "benchmark"),
        ("198.19.255.255", "benchmark"),
        ("198.20.0.0", "global"),
        ("198.51.99.255", "global"),
        ("198.51.100.0", "documentation"),
        ("198.51.101.0", "global"),
        ("203.0.112.255", "global"),
        ("203.0.113.0", "documentation"),
        ("203.0.114.0", "global"),
        ("223.255.255.255", "global"),
        ("224.0.0.0", "multicast"),
        ("239.255.255.255", "multicast"),
        ("240.0.0.0", "reserved"),
        ("255.255.255.254", "reserved"),
        ("255.255.255.255", "reserved"),
        ("8.8.8.8", "global"),
        ("::", "unspecified"),
        ("::1", "loopback"),
        ("::2", "unspecified"),
        ("64:ff9b:0:ffff:ffff:ffff:ffff:ffff", "global"),
        ("64:ff9b:1::", "embedded"),
        ("64:ff9b:1:ffff:ffff:ffff:ffff:ffff", "embedded"),
        ("64:ff9b:2::", "global"),
        ("100::", "reserved"),
        ("100::ffff:ffff:ffff:ffff", "reserved"),
        ("2001:db8::1", "documentation"),
        ("2001:db9::1", "global"),
        ("2001:4860:4860::8888", "global"),
        ("2002::", "embedded"),
        ("2003::1", "global"),
        ("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "global"),
        ("fc00::", "private"),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "private"),
        ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "global"),
        ("fe7f::", "global"),
        ("fe80::", "link_local"),
        ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "link_local"),
        ("fec0::", "private"),
        ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "private"),
        ("ff00::", "multicast"),
        # Not in a table, but the standard library calls it non-global: the second opinion.
        ("2001:2::1", "reserved"),
    ],
)
def test_both_sides_of_each_boundary(address: str, kind: str) -> None:
    assert classify(address) == kind
    assert addresses_allowed([address], private_ok=False).allowed is (kind == "global")


def _v4(address: str) -> int:
    return int(ipaddress.IPv4Address(address))


def _teredo(address: str) -> str:
    # 2001:0:<server>:<flags>:<port, inverted>:<client, inverted> (RFC 4380).
    server = _v4("65.54.227.120")
    value = (0x2001_0000 << 96) | (server << 64) | (0x8000 << 48) | (0x63BF << 32)
    return str(ipaddress.IPv6Address(value | (_v4(address) ^ 0xFFFF_FFFF)))


def _forms(address: str) -> dict[str, str]:
    ip = _v4(address)
    return {
        "mapped": str(ipaddress.IPv6Address((0xFFFF << 32) | ip)),
        "compatible": str(ipaddress.IPv6Address(ip)),
        "6to4": str(ipaddress.IPv6Address((0x2002 << 112) | (ip << 80) | 1)),
        "teredo": _teredo(address),
        "nat64": str(ipaddress.IPv6Address((0x64_FF9B << 96) | ip)),
        "nat64_local": str(ipaddress.IPv6Address((0x64_FF9B_0001 << 80) | ip)),
    }


@pytest.mark.parametrize(
    ("address", "kind"),
    [("127.0.0.1", "loopback"), ("10.0.0.1", "private"), ("169.254.169.254", "link_local")],
)
@pytest.mark.parametrize("form", ["mapped", "compatible", "6to4", "teredo", "nat64", "nat64_local"])
def test_every_embedded_form_of_a_private_address_is_refused(
    address: str, kind: str, form: str
) -> None:
    text = _forms(address)[form]
    found = classify(text)
    # Mapped, compatible and NAT64 forms are judged by their IPv4 address; the tunnels whole.
    assert found == (kind if form in ("mapped", "compatible", "nat64") else "embedded")
    verdict = addresses_allowed([text], private_ok=False)
    assert verdict == AddressVerdict(allowed=False, reason=found, address=text)


@pytest.mark.parametrize(
    ("form", "kind"),
    [
        ("mapped", "global"),
        ("compatible", "global"),
        ("nat64", "global"),  # so a NAT64 network still reaches global hosts
        ("6to4", "embedded"),
        ("teredo", "embedded"),
        ("nat64_local", "embedded"),
    ],
)
def test_the_embedded_forms_of_a_global_address(form: str, kind: str) -> None:
    assert classify(_forms("8.8.8.8")[form]) == kind


def test_a_mapped_address_is_written_either_way() -> None:
    assert classify("::ffff:127.0.0.1") == "loopback"
    assert classify("::ffff:7f00:1") == "loopback"
    assert classify("::ffff:8.8.8.8") == "global"


@pytest.mark.parametrize(
    "text", ["", "localhost", "2130706433", "0177.0.0.1", "0x7f.1", "1.2.3", "[::1]", " 8.8.8.8"]
)
def test_text_that_is_not_an_address_raises(text: str) -> None:
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 address"):
        classify(text)


def test_a_scoped_address_raises() -> None:
    with pytest.raises(ValueError, match=r"^a scoped address: 'fe80::1%eth0'$"):
        classify("fe80::1%eth0")
    with pytest.raises(ValueError, match="scoped"):
        classify("2001:4860:4860::8888%1")


# --- addresses_allowed ---------------------------------------------------------------------------


def test_global_addresses_are_allowed_and_the_first_is_named() -> None:
    verdict = addresses_allowed(["8.8.8.8", "2001:4860:4860::8888"], private_ok=False)
    assert verdict == AddressVerdict(allowed=True, reason="global", address="8.8.8.8")


def test_one_private_answer_refuses_the_whole_name() -> None:
    for answers in (["8.8.8.8", "10.0.0.1"], ["10.0.0.1", "8.8.8.8"]):
        verdict = addresses_allowed(answers, private_ok=False)
        assert verdict == AddressVerdict(allowed=False, reason="private", address="10.0.0.1")


def test_an_empty_answer_is_refused() -> None:
    for private_ok in (False, True):
        verdict = addresses_allowed([], private_ok=private_ok)
        assert verdict == AddressVerdict(allowed=False, reason="no_address", address=None)


@pytest.mark.parametrize("private_ok", [False, True])
def test_an_unparsable_answer_is_refused(private_ok: bool) -> None:
    for answers in (["8.8.8.8", "2130706433"], ["not-an-address"], ["fe80::1%eth0"]):
        verdict = addresses_allowed(answers, private_ok=private_ok)
        assert verdict == AddressVerdict(allowed=False, reason="unparsable", address=answers[-1])


def test_private_ok_allows_any_address() -> None:
    answers = ["10.0.0.1", "8.8.8.8", "127.0.0.1", "fe80::1"]
    verdict = addresses_allowed(answers, private_ok=True)
    assert verdict == AddressVerdict(allowed=True, reason="private_ok", address="10.0.0.1")
    verdict = addresses_allowed(["8.8.8.8"], private_ok=True)
    assert verdict == AddressVerdict(allowed=True, reason="global", address="8.8.8.8")


def _embedded(v4: ipaddress.IPv4Address, form: str) -> str:
    return _forms(str(v4))[form]


ADDRESSES = st.one_of(
    st.ip_addresses().map(str),
    st.builds(
        _embedded,
        st.ip_addresses(v=4),
        st.sampled_from(["mapped", "compatible", "6to4", "teredo", "nat64", "nat64_local"]),
    ),
)


@settings(max_examples=50, deadline=None)
@given(st.lists(ADDRESSES, min_size=1, max_size=4))
def test_no_address_the_standard_library_calls_non_global_is_allowed(answers: list[str]) -> None:
    verdict = addresses_allowed(answers, private_ok=False)
    if any(not ipaddress.ip_address(a).is_global for a in answers):
        assert not verdict.allowed
    if verdict.allowed:
        assert all(classify(a) == "global" for a in answers)
        assert verdict.address == answers[0]


# --- untrusted_host ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("bücher.example", "not_ascii"),
        ("127.0.0.1", "ip_literal"),
        ("8.8.8.8", "ip_literal"),
        ("::1", "ip_literal"),
        ("[::1]", "ip_literal"),
        ("[2001:db8::1]", "ip_literal"),
        ("", "syntax"),
        ("exa_mple.com", "syntax"),
        ("example.com.", "syntax"),
        (".example.com", "syntax"),
        ("-a.example", "syntax"),
        ("a-.example", "syntax"),
        ("a..example", "syntax"),
        ("example.com\n", "syntax"),
        ("a" * 64 + ".example", "syntax"),
        ("a." * 125 + "abcd", "syntax"),  # 254 characters
        # Browsers read these as IPv4 addresses (decimal, octal and hex spellings).
        ("2130706433", "numeric_label"),
        ("0177.0.0.1", "numeric_label"),
        ("0x7f.1", "numeric_label"),
        ("1.2.3", "numeric_label"),
        ("vault.example.42", "numeric_label"),
        ("vault.0x7f", "numeric_label"),
        ("vault.0x", "numeric_label"),
        ("localhost", "single_label"),
        ("vault", "single_label"),
        ("Vault", "single_label"),
    ],
)
def test_untrusted_hosts_refused(host: str, reason: str) -> None:
    assert untrusted_host(host) == HostVerdict(allowed=False, reason=reason, host=host.lower())


@pytest.mark.parametrize("suffix", INTERNAL_SUFFIXES)
def test_every_internal_suffix_is_refused(suffix: str) -> None:
    for host in (suffix, f"mcp.{suffix}", f"a.b.{suffix}", f"MCP.{suffix.upper()}"):
        verdict = untrusted_host(host)
        assert not verdict.allowed
        single = host == suffix and "." not in suffix
        assert verdict.reason == ("single_label" if single else "internal_suffix")
    for host in (f"mcp.{suffix}x", f"mcp.x{suffix}", f"{suffix}.example"):
        assert untrusted_host(host).allowed, host


@pytest.mark.parametrize(
    "host",
    [
        "mcp.notes.example",
        "a.b",
        "x.io",
        "vault.example.4a",
        "0x7g.example",
        "a" * 63 + ".example",
        "a." * 125 + "abc",  # 253 characters
        "xn--bcher-kva.example",
    ],
)
def test_untrusted_hosts_allowed(host: str) -> None:
    assert untrusted_host(host) == HostVerdict(allowed=True, reason="allowed", host=host)


def test_a_host_is_lowered() -> None:
    expected = HostVerdict(allowed=True, reason="allowed", host="mcp.notes.example")
    assert untrusted_host("MCP.Notes.Example") == expected


# --- entry_key and listed ----------------------------------------------------------------------


def test_entry_key() -> None:
    assert entry_key("MCP.Notes.Example", 443) == "mcp.notes.example:443"
    assert entry_key("10.0.0.5", 8443) == "10.0.0.5:8443"
    assert entry_key("FD00::1", 443) == "[fd00::1]:443"


def test_listed_compares_as_written() -> None:
    entries = frozenset({"mcp.lan.example:443", "10.0.0.5:8443", "[fd00::1]:443"})
    assert listed(entries, "MCP.lan.example", 443)
    assert listed(entries, "10.0.0.5", 8443)
    assert listed(entries, "fd00::1", 443)
    assert not listed(entries, "mcp.lan.example", 8443)
    assert not listed(entries, "lan.example", 443)
    assert not listed(entries, "x.mcp.lan.example", 443)
    # An IP literal is listed only literally, never by another spelling or a name.
    assert not listed(entries, "fd00:0::1", 443)
    assert not listed(entries, "10.0.0.5.nip.example", 8443)
    assert not listed(frozenset(), "mcp.lan.example", 443)


# --- squid_private_dst -------------------------------------------------------------------------


# Squid holds every address as IPv6, an IPv4 one in its IPv4-mapped form (Ip::Address), and a dst
# entry likewise: an IPv4 row a.b.c.d/n is ::ffff:a.b.c.d/(n + 96). These model that.
MAPPED_PREFIX = 0xFFFF << 32


def squid_holds(address: str) -> ipaddress.IPv6Address:
    ip = ipaddress.ip_address(address)
    return ipaddress.IPv6Address(MAPPED_PREFIX | int(ip)) if ip.version == 4 else ip


def squid_entry(entry: str) -> ipaddress.IPv6Network:
    net = ipaddress.ip_network(entry)
    if isinstance(net, ipaddress.IPv4Network):
        return ipaddress.IPv6Network((MAPPED_PREFIX | int(net.network_address), net.prefixlen + 96))
    return net


def squid_refuses(address: str, entries: tuple[str, ...] | None = None) -> bool:
    """Whether a Squid ``dst`` ACL of ``entries`` (the emitted rule's) matches ``address``."""
    held = squid_holds(address)
    return any(held in squid_entry(e) for e in entries or squid_private_dst())


def test_squid_private_dst_is_the_tables_less_the_mapped_row_and_covered_rows() -> None:
    assert squid_private_dst() == (
        *DENIED_V4[:-1],  # 255.255.255.255/32 is inside 240.0.0.0/4
        # ::/128 and ::1/128 are inside ::/96; ::ffff:0:0/96 is Squid's form of all of IPv4.
        "::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
    entries = squid_private_dst()
    for row in DENIED_V4 + DENIED_V6:
        if row in entries or row == "::ffff:0:0/96":
            continue
        # Every other row left out is inside one kept, so Squid still refuses all of it.
        assert any(squid_entry(row).subnet_of(squid_entry(e)) for e in entries), row
    # As Squid holds them, no two entries overlap: it would warn and merge or drop one.
    held = [squid_entry(e) for e in entries]
    assert not [(a, b) for a in held for b in held if a != b and a.overlaps(b)]


def test_the_mapped_row_would_refuse_every_ipv4_destination_in_squid() -> None:
    # Why ::ffff:0:0/96 is left out: Squid would hold 1.1.1.1 inside it.
    assert squid_refuses("1.1.1.1", ("::ffff:0:0/96",))
    assert squid_refuses("1.1.1.1", DENIED_V6)


@pytest.mark.parametrize(
    "address", ["1.1.1.1", "8.8.8.8", "93.184.216.34", "::ffff:1.1.1.1", "2606:4700:4700::1111"]
)
def test_squid_lets_a_public_address_through(address: str) -> None:
    assert classify(address) == "global"
    assert not squid_refuses(address)


def test_squid_refuses_both_ends_of_every_row_it_keeps_or_covers() -> None:
    for row in DENIED_V4 + DENIED_V6:
        if row == "::ffff:0:0/96":
            continue
        net = ipaddress.ip_network(row)
        for address in (net[0], net[-1]):
            assert squid_refuses(str(address)), (row, address)


@pytest.mark.parametrize(
    "address",
    [
        "::ffff:127.0.0.1",  # an AAAA answer Squid holds as 127.0.0.1 (contract 51)
        "::ffff:10.0.0.9",
        "::ffff:169.254.169.254",
        "::a00:9",  # compatible: inside ::/96
        "::7f00:1",
    ],
)
def test_squid_refuses_a_mapped_or_compatible_private_address(address: str) -> None:
    assert classify(address) != "global"
    assert squid_refuses(address)


def test_squid_lets_a_nat64_private_address_through() -> None:
    # The recorded limit (M7 design 0.5): only the guard sees the IPv4 address in 64:ff9b::/96.
    assert classify("64:ff9b::a00:9") == "private"
    assert not squid_refuses("64:ff9b::a00:9")


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_squid_and_the_guard_agree_on_every_ipv4_address(value: int) -> None:
    v4 = str(ipaddress.IPv4Address(value))
    mapped = f"::ffff:{v4}"
    refused = classify(v4) != "global"
    assert squid_refuses(v4) == refused
    assert squid_refuses(mapped) == refused == (classify(mapped) != "global")


def test_squid_entries_are_networks_as_written() -> None:
    for entry in squid_private_dst():
        assert str(ipaddress.ip_network(entry)) == entry  # host bits clear, the short form


# --- local MCP routes: local_target and local_only (M7 design B.1, step 18b) ---------------------


def test_the_local_tables_are_pinned() -> None:
    assert LOCAL_V4 == ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    assert LOCAL_V6 == ("::1/128", "fc00::/7")
    # Each is a row of the denied tables: a local address is never a global one.
    assert set(LOCAL_V4) <= set(DENIED_V4)
    assert set(LOCAL_V6) <= set(DENIED_V6)


# Both sides of each LOCAL_* boundary, and the denied addresses next to them.
LOCAL = [
    "127.0.0.0",
    "127.0.0.1",
    "127.255.255.255",
    "10.0.0.0",
    "10.255.255.255",
    "172.16.0.0",
    "172.31.255.255",
    "192.168.0.0",
    "192.168.255.255",
    "::1",
    "fc00::",
    "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "::ffff:10.0.0.1",  # mapped: by its IPv4 address
    "::ffff:127.0.0.1",
]
# The reason is the address's class (None: whatever classify says, which for these rows leans on
# the standard library's is_global), or not_local for a loopback or private one.
NOT_LOCAL: list[tuple[str, str | None]] = [
    ("126.255.255.255", "global"),
    ("128.0.0.0", "global"),
    ("9.255.255.255", "global"),
    ("11.0.0.0", "global"),
    ("172.15.255.255", "global"),
    ("172.32.0.0", "global"),
    ("192.167.255.255", "global"),
    ("192.169.0.0", "global"),
    ("8.8.8.8", "global"),
    ("169.254.169.254", "link_local"),  # cloud metadata
    ("100.64.0.1", "cgnat"),
    ("0.0.0.1", "unspecified"),
    ("224.0.0.1", "multicast"),
    ("192.0.2.1", "documentation"),
    ("::ffff:8.8.8.8", None),
    ("::ffff:169.254.169.254", "link_local"),
    ("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", None),
    ("fe00::", None),
    ("::", "unspecified"),
    ("::2", None),
    ("fe80::1", "link_local"),
    ("fec0::1", "not_local"),  # private to the denied table, never a local route's
    ("::10.0.0.1", "not_local"),  # IPv4-compatible: only the mapped form counts
    ("::127.0.0.1", "not_local"),  # likewise, for loopback
    ("64:ff9b::a00:1", "not_local"),  # NAT64 of 10.0.0.1
    ("2002:a00:1::", "embedded"),  # 6to4 of 10.0.0.1
    ("2001::1", "embedded"),  # Teredo
    ("2001:4860:4860::8888", None),
]


@pytest.mark.parametrize("address", LOCAL)
def test_a_local_address(address: str) -> None:
    assert local_only([address]) == AddressVerdict(allowed=True, reason="local", address=address)
    assert local_target(address)
    host = f"[{address}]" if ":" in address else address
    assert local_target(host)


@pytest.mark.parametrize(("address", "reason"), NOT_LOCAL)
def test_an_address_outside_the_local_tables(address: str, reason: str | None) -> None:
    expected = reason or classify(address)
    assert expected not in ("loopback", "private")
    assert local_only([address]) == AddressVerdict(allowed=False, reason=expected, address=address)
    assert not local_target(address)


def test_local_only_refuses_the_whole_name() -> None:
    """Every address must be local: one global, link-local or CGNAT answer refuses them all,
    wherever it comes, and the verdict names it; the first address is the one to dial."""
    assert local_only(["10.0.0.1", "8.8.8.8"]) == AddressVerdict(False, "global", "8.8.8.8")
    assert local_only(["169.254.169.254", "10.0.0.1"]) == AddressVerdict(
        False, "link_local", "169.254.169.254"
    )
    assert local_only(["10.0.0.1", "127.0.0.1", "::1"]) == AddressVerdict(True, "local", "10.0.0.1")
    assert local_only([]) == AddressVerdict(False, "no_address", None)
    for bad in ("not-an-address", "fe80::1%eth0", "::1%lo", "10.0.0.1/8", ""):
        assert local_only(["10.0.0.1", bad]) == AddressVerdict(False, "unparsable", bad)


@pytest.mark.parametrize(
    "host",
    ["localhost", "LOCALHOST", "bridge", "bridge-fetch-mcp", "fetch", "b2", "a" * 63],
)
def test_a_single_label_name_is_a_local_target(host: str) -> None:
    assert local_target(host)


@pytest.mark.parametrize(
    "host",
    [
        "bridge.fetch.example",  # two labels, whatever they resolve to
        "x.localhost",
        "localhost.",  # a trailing dot is a name of its own
        "bridge.",
        "a" * 64,  # longer than a label
        "-bridge",
        "bridge-",
        "bri_dge",
        "",
        "2130706433",  # 127.0.0.1, spelled as a number
        "0x7f000001",
        "0177",
        "0x",
        "[localhost]",
        "fe80::1%eth0",
        "::1%lo",
        "bücher",
    ],
)
def test_anything_else_is_not_a_local_target(host: str) -> None:
    assert not local_target(host)


@settings(max_examples=50, deadline=None)
@given(st.lists(ADDRESSES, min_size=1, max_size=4))
def test_local_only_is_false_whenever_any_address_is_global(answers: list[str]) -> None:
    verdict = local_only(answers)
    if any(ipaddress.ip_address(a).is_global for a in answers):
        assert not verdict.allowed
    if verdict.allowed:
        assert all(classify(a) in ("loopback", "private") for a in answers)
        assert verdict.address == answers[0]


# --- a bridge's socket: unix_peer (M7 design B.1, Q46) -------------------------------------------


@pytest.mark.parametrize(
    ("peer", "expected", "verdict"),
    [
        (10100, 10100, AddressVerdict(True, "bridge_uid", None)),
        (10107, 10107, AddressVerdict(True, "bridge_uid", None)),
        (1, 1, AddressVerdict(True, "bridge_uid", None)),
        (10101, 10100, AddressVerdict(False, "peer_uid", None)),  # another bridge's uid
        (10001, 10100, AddressVerdict(False, "peer_uid", None)),  # the vault's own
        (0, 10100, AddressVerdict(False, "peer_uid", None)),
        (0, 0, AddressVerdict(False, "peer_uid", None)),  # root never, even if named
        (None, 10100, AddressVerdict(False, "peer_uid", None)),  # the kernel didn't say
        (10100, None, AddressVerdict(False, "unknown_socket", None)),  # a name not started
        (None, None, AddressVerdict(False, "unknown_socket", None)),
    ],
)
def test_unix_peer(peer: int | None, expected: int | None, verdict: AddressVerdict) -> None:
    assert unix_peer(peer, expected) == verdict
