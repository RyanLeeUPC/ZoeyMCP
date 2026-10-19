"""Is a received message really from its sender? An offline check (M4 design K.1).

A mail reader shows an agent mail that strangers wrote. Before trusting who a message is from,
check the receiving provider's verdict: the provider adds an ``Authentication-Results`` header
at the top, and anything below it may be forged by the sender. :func:`verify_sender` says
``verified`` only if all of these hold:

- exactly one ``From`` header, with one address, equal (ignoring case) to the one expected. The
  address is parsed, so a display name that looks like an address doesn't count;
- no ``Sender`` header with another address;
- the **first** ``Authentication-Results`` header names the provider's authserv-id;
- it shows ``dkim=pass`` for ``header.d`` equal to the From domain or a parent of it.

DMARC and SPF are recorded, not required. A verdict never carries the body. Pure: no network,
no DNS. The provider did the DKIM check; this only reads its answer in the one header it owns.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.utils import getaddresses

_COMMENT = re.compile(r"\([^()]*\)")
_PROPERTY = re.compile(r"([A-Za-z0-9.-]+)\s*=\s*\"?([^\s;\"]+)\"?")


@dataclass(frozen=True)
class Verdict:
    """``verified``, or why not. ``headers`` holds the headers it read, never the body."""

    verified: bool
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    dkim: str | None = None
    dmarc: str | None = None
    spf: str | None = None


def _strip_comments(text: str) -> str:
    previous = None
    while previous != text:  # nested comments, from the inside out
        previous, text = text, _COMMENT.sub(" ", text)
    return text


def _results(header: str) -> tuple[str, list[dict[str, str]]]:
    """The authserv-id and each result of an ``Authentication-Results`` header (RFC 8601)."""
    parts = [p.strip() for p in _strip_comments(" ".join(header.split())).split(";")]
    authserv = parts[0].split()[0] if parts and parts[0] else ""
    found = []
    for part in parts[1:]:
        values = {k.lower(): v for k, v in _PROPERTY.findall(part)}
        if values:
            found.append(values)
    return authserv, found


def _domain(address: str) -> str:
    return address.rpartition("@")[2].lower()


def _aligned(signer: str, domain: str) -> bool:
    signer = signer.lower().rstrip(".")
    return domain == signer or domain.endswith("." + signer)


def verify_sender(raw: bytes, *, expected: str, authserv_id: str) -> Verdict:
    """Whether ``raw`` (a whole message) is from ``expected``, by ``authserv_id``'s verdict."""
    message = email.message_from_bytes(raw, policy=email.policy.compat32)
    froms = message.get_all("From") or []
    all_results = message.get_all("Authentication-Results") or []
    first_results = all_results[0] if all_results else None
    headers = {"From": " | ".join(str(f) for f in froms)}
    if message.get("Sender") is not None:
        headers["Sender"] = str(message["Sender"])
    if first_results is not None:
        headers["Authentication-Results"] = " ".join(str(first_results).split())

    def refuse(reason: str, **found: str | None) -> Verdict:
        return Verdict(False, reason, headers, **found)

    if len(froms) != 1:
        return refuse("not exactly one From header")
    addresses = [a for _, a in getaddresses([str(froms[0])]) if a]
    if len(addresses) != 1 or "@" not in addresses[0]:
        return refuse("the From header doesn't hold exactly one address")
    sender = addresses[0]
    if sender.casefold() != expected.casefold():
        return refuse("from another address")
    if message.get("Sender") is not None:
        others = [a for _, a in getaddresses([str(message["Sender"])]) if a]
        if [a.casefold() for a in others] != [sender.casefold()]:
            return refuse("a Sender header names another address")
    if first_results is None:
        return refuse("no Authentication-Results header")
    authserv, results = _results(str(first_results))
    if authserv.lower() != authserv_id.lower():
        return refuse("the first Authentication-Results header isn't the provider's")
    by_method: dict[str, str] = {}
    for result in results:
        for method in ("dkim", "dmarc", "spf"):
            if method in result:
                by_method.setdefault(method, result[method].lower())
    recorded = {m: by_method.get(m) for m in ("dkim", "dmarc", "spf")}
    domain = _domain(sender)
    signed = any(
        r.get("dkim", "").lower() == "pass" and _aligned(r.get("header.d", ""), domain)
        for r in results
    )
    if not signed:
        return refuse("no passing DKIM signature for the From domain", **recorded)
    return Verdict(True, None, headers, **recorded)
