"""The browsers the harness drives, and how each is launched (M8 design step 27a; D-222).

``ZOEYMCP_BROWSER`` names one: ``chromium`` (Playwright's bundled headless shell, CI's Linux
job), ``chrome`` (the installed Chrome, a development host: nothing downloaded) or ``msedge``
(the installed Edge, CI's Windows job). All three are Chromium, so the passkeys come from the
browser's own WebAuthn stack through CDP (``passkeys.py``). Firefox and WebKit would need
Playwright's ``credentials`` shim, which isn't built.

The browser resolves names itself, by ``--host-resolver-rules``: each test name to loopback and
every other name to nothing, so a page can't reach the network, without ``context.route``
(Playwright 1.63 mishandles a preflighted cross-origin redirect under any route on Chromium 155
and later). Loopback IP literals are left alone (``EXCLUDE``), or a ``MAP *`` rule would take
them too. ``MAP localhost`` goes to 127.0.0.1, where the rigs listen, never to ``::1`` first
(verifier V49's two-second fallback on Windows).

Two more names are served over https on loopback, each with a certificate the browser trusts by
its key alone (``--ignore-certificate-errors-spki-list``, which Chromium honours beside the
profile directory Playwright gives it): :data:`FRONT`, a second origin of the portal (manual item
7), through an in-process TLS front (``stacks.Forwarder``), so the page there is a secure context
with no certificate error and its passkeys are the browser's own for that name (Chromium refuses
WebAuthn on a page with a certificate error); and :data:`PROVIDER`, the fake OAuth provider's
site (items 13, 14, 18 and 23), a different site from the portal's, so its redirect back is a
real cross-site navigation (a route's answer isn't: Chromium counts no hop for it). Each key is
made once a session, with a throwaway CA, and never leaves the run.
"""

from __future__ import annotations

import base64
import hashlib
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives import serialization

ENGINES: Final = ("chromium", "chrome", "msedge")
# The https name of item 7's second origin, as the manual item's example name reads.
FRONT: Final = "zoeymcp.tailnet.example"
# The fake OAuth provider's https name, as the portal's tests name it.
PROVIDER: Final = "auth.notes.example"
# The names a test page may open, each served on loopback; every other name resolves to nothing.
NAMES: Final = ("localhost", FRONT, PROVIDER)
LOOPBACK: Final = ("127.0.0.1",)
# Web-first assertions retry until this many milliseconds; Windows runners are slower.
TIMEOUT: Final = 10_000 if sys.platform == "win32" else 5_000


def resolver_rules(names: tuple[str, ...] = NAMES) -> str:
    """Chromium's rules: the test names to loopback, loopback literals as they are, the rest
    unresolvable. The first matching ``MAP`` wins; an ``EXCLUDE`` beats every ``MAP``."""
    rules = [f"MAP {name} 127.0.0.1" for name in names]
    rules.append("MAP * ~NOTFOUND")
    rules.extend(f"EXCLUDE {address}" for address in LOOPBACK)
    return ", ".join(rules)


def spki(certificate: Path) -> str:
    """The certificate's public key as Chromium's trust flag names it: the base64 SHA-256 of its
    DER ``SubjectPublicKeyInfo``."""
    key = x509.load_pem_x509_certificate(certificate.read_bytes()).public_key()
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


def launch_options(engine: str, *, trusted: tuple[str, ...] = ()) -> Mapping[str, Any]:
    """``BrowserType.launch``'s arguments for ``engine``, always headless; ``trusted`` are the
    keys (:func:`spki`) of the certificates the browser then trusts."""
    if engine not in ENGINES:
        raise ValueError(
            f"ZOEYMCP_BROWSER={engine!r}: the harness drives {', '.join(ENGINES)} "
            "(Firefox and WebKit need the credentials shim, not built)"
        )
    options: dict[str, Any] = {
        "headless": True,
        "args": [f"--host-resolver-rules={resolver_rules()}"],
    }
    if trusted:
        options["args"].append(f"--ignore-certificate-errors-spki-list={','.join(trusted)}")
    if engine != "chromium":
        options["channel"] = engine
    return options
