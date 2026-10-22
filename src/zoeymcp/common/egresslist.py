"""The egress allowlists, derived once (M7 design I.2, D-149, X16). Pure and mutation-tested.

:func:`derive` is the one derivation: the egress role's lists (from the vault's allowlist
endpoint), ``check --emit-egress-allowlist``'s output and the self-test's expectations all come
from it, so they can't disagree. Each source is a place connections start from; the vault's is
``vault``:

- ``route``: every route upstream's ``host:port`` (an ``http`` upstream on port 80 unless it
  names one, and marked in the text form: a CONNECT-only proxy refuses plain http);
- ``token`` and ``revocation``: every oauth2 ``token_url`` and ``revocation_url``;
- ``connector``: every connector's ``host:port``;
- ``onboarding``: each live onboarding's allowance (I.3), which only the vault's memory holds.
  An allowance is never private: the role can't tell which vault request a tunnel carries, so it
  would give every vault connection to that ``host:port`` the exception (TI-10).

A URL's host is keyed as the vault's client sends it, an internationalized name in its ``xn--``
form (``fields.client_host``, D-190). A destination is private when the policy lists it in
``egress_private`` (:func:`private_exceptions`, the set the vault's guarded transport reads
too), compared as the guard compares it: a trailing dot (``lan.example.``) names the entry
without it. Lists are sorted by source, then host, then
port, with a destination's reasons merged. The digest covers the lists alone (host, port and
private), so an edit the lists don't see changes no output (GR-20).
"""

from __future__ import annotations

import ipaddress
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from . import canonical, netguard
from .policy import fields
from .policy.schema import OAuth2Credential, Policy

SourceName = str  # "vault", or (from M7 step 18b) the name of a route with a program
Reason = Literal["route", "token", "revocation", "connector", "program", "onboarding"]
Format = Literal["text", "json", "squid"]
VAULT: Final = "vault"
_DEFAULT_PORTS: Final = {"https": 443, "http": 80}
PLAIN_HTTP_NOTE: Final = "plain http: refused by a CONNECT-only proxy"


@dataclass(frozen=True)
class Destination:
    host: str  # lower case, as netguard.entry_key writes it (an IPv6 address without brackets)
    port: int
    private: bool  # in egress_private
    reasons: frozenset[Reason]
    plain_http: bool = False  # reached over http: only the text form says so


@dataclass(frozen=True)
class Allowance:
    """One onboarding's allowance: the ``(host, port)`` pairs its phase 1 contacts (I.3)."""

    destinations: frozenset[tuple[str, int]]


Lists = Mapping[SourceName, tuple[Destination, ...]]


def private_exceptions(policy: Policy) -> frozenset[str]:
    """The vault's destinations allowed to resolve to non-global addresses, as ``host:port``
    (B.2). The schema keeps each entry in lower case, as :func:`.netguard.entry_key` writes it."""
    return frozenset(policy.egress_private)


def _url_destination(url: str) -> tuple[str, int, bool]:
    """``(host, port, plain_http)`` for an http(s) URL the schema has checked, the host as the
    vault's client sends it (an ``xn--`` name for an internationalized one)."""
    parts = urlsplit(url)  # lowercases the scheme and the host
    port = parts.port or _DEFAULT_PORTS[parts.scheme]
    return fields.client_host(str(parts.hostname)), port, parts.scheme == "http"


def derive(policy: Policy, allowances: Iterable[Allowance] = ()) -> Lists:
    """Every source's destinations. The vault's list is always present, even empty."""
    reasons: dict[tuple[str, int], set[Reason]] = {}
    plain_http: set[tuple[str, int]] = set()

    def add(host: str, port: int, http: bool, reason: Reason) -> None:
        key = (host.lower(), port)
        reasons.setdefault(key, set()).add(reason)
        if http:
            plain_http.add(key)

    for route in policy.routes:
        if route.upstream is not None:
            add(*_url_destination(route.upstream), "route")
    for cred in policy.credentials.values():
        if isinstance(cred, OAuth2Credential):
            add(*_url_destination(cred.token_url), "token")
            if cred.revocation_url is not None:
                add(*_url_destination(cred.revocation_url), "revocation")
    for conn in policy.connectors.values():
        add(conn.host, conn.port, False, "connector")
    # Only the policy's own destinations can be private; an allowance never is (TI-10).
    exceptions = private_exceptions(policy)
    private = {
        (host, port)
        for host, port in reasons
        if netguard.entry_key(host.removesuffix("."), port) in exceptions
    }
    for allowance in allowances:
        for host, port in allowance.destinations:
            add(host, port, False, "onboarding")
    vault = tuple(
        Destination(
            host=host,
            port=port,
            private=(host, port) in private,
            reasons=frozenset(found),
            plain_http=(host, port) in plain_http,
        )
        for (host, port), found in sorted(reasons.items())
    )
    return {VAULT: vault}


def _sources(lists: Lists) -> dict[str, list[dict[str, Any]]]:
    return {
        source: [{"host": d.host, "port": d.port, "private": d.private} for d in lists[source]]
        for source in sorted(lists)
    }


def digest(lists: Lists) -> str:
    """``sha256:<hex>`` over the lists alone: host, port and private, never the reasons."""
    return canonical.digest(_sources(lists))


def document(lists: Lists) -> dict[str, Any]:
    """The allowlist endpoint's answer (G.2): host names and ports only, with the digest."""
    sources = _sources(lists)
    return {"v": 1, "digest": canonical.digest(sources), "sources": sources}


def _acl_name(source: str, acl_names: Mapping[str, str]) -> str:
    return acl_names.get(source, f"zoeymcp_src_{source}")


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _render_text(lists: Lists) -> list[str]:
    lines = [f"# zoeymcp egress allowlist, lists {digest(lists)}"]
    for source in sorted(lists):
        for dest in lists[source]:
            line = f"{source} {netguard.entry_key(dest.host, dest.port)}"
            lines.append(f"{line}  # {PLAIN_HTTP_NOTE}" if dest.plain_http else line)
    return lines


def _render_squid(lists: Lists, acl_names: Mapping[str, str]) -> list[str]:
    sources = sorted(lists)
    expects = ", and ".join(
        ["acl CONNECT method CONNECT"]
        + [f"acl {_acl_name(s, acl_names)} src <the {s}'s network>" for s in sources]
    )
    lines = [
        f"# zoeymcp egress allowlist, lists {digest(lists)}; regenerate with zoeymcp check "
        "--emit-egress-allowlist; keep your own final deny",
        f"# expects your squid.conf to define: {expects}",
        "acl zoeymcp_private_dst dst " + " ".join(netguard.squid_private_dst()),
    ]
    ports = sorted({d.port for s in sources for d in lists[s]})
    lines.extend(f"acl zoeymcp_port_{port} port {port}" for port in ports)
    for source in sources:
        src = _acl_name(source, acl_names)
        for index, dest in enumerate(lists[source], start=1):
            name = f"zoeymcp_{source}_{index}"
            # -n: no lookup. Without it a dstdomain ACL matches an IP's PTR name, and a dst ACL
            # resolves a name, both before the final deny; zoeymcp_private_dst resolves, after.
            kind = "dst" if _is_literal(dest.host) else "dstdomain"
            lines.append(f"acl {name} {kind} -n {dest.host}")
            rule = f"http_access allow {src} CONNECT {name} zoeymcp_port_{dest.port}"
            lines.append(rule if dest.private else rule + " !zoeymcp_private_dst")
    return lines


def render(lists: Lists, fmt: Format, *, acl_names: Mapping[str, str] | None = None) -> str:
    """The lists in one of ``check --emit-egress-allowlist``'s forms (I.6). ``acl_names`` maps a
    source to the operator's own Squid ``src`` ACL; a source it doesn't name gets
    ``zoeymcp_src_<source>``. The Squid form never defines those ACLs, ``CONNECT`` or a final
    deny: the operator's file does, and the header says which it must define."""
    if fmt == "json":
        return json.dumps(document(lists), indent=2) + "\n"
    if fmt == "squid":
        return "\n".join(_render_squid(lists, acl_names or {})) + "\n"
    return "\n".join(_render_text(lists)) + "\n"


def compare(
    lists: Lists, text: str, fmt: Format, *, acl_names: Mapping[str, str] | None = None
) -> list[str]:
    """How ``text`` differs from what :func:`render` emits, line by line and sorted: ``missing:``
    for each line it lacks, ``unexpected:`` for each it shouldn't have, counted, so a repeated
    line (the JSON form's ``"port": 443,``) is missed once per copy. When the lines agree but
    their order doesn't (a Squid ACL after the rule that uses it), ``order:`` names the first
    line out of place. Empty only when the lines equal the emitted ones; line endings aside."""
    expected = render(lists, fmt, acl_names=acl_names).splitlines()
    actual = text.splitlines()
    missing = Counter(expected) - Counter(actual)
    unexpected = Counter(actual) - Counter(expected)
    differences = [f"missing: {line}" for line in missing.elements()]
    differences += [f"unexpected: {line}" for line in unexpected.elements()]
    if not differences and actual != expected:
        line = next(n for n, (a, e) in enumerate(zip(actual, expected, strict=True)) if a != e)
        differences.append(f"order: line {line + 1} should be: {expected[line]}")
    return sorted(differences)
