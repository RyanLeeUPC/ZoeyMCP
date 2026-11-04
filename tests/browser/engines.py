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
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any, Final

ENGINES: Final = ("chromium", "chrome", "msedge")
# The names a test page may open, each served on loopback; every other name resolves to nothing.
NAMES: Final = ("localhost",)
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


def launch_options(engine: str) -> Mapping[str, Any]:
    """``BrowserType.launch``'s arguments for ``engine``, always headless."""
    if engine not in ENGINES:
        raise ValueError(
            f"ZOEYMCP_BROWSER={engine!r}: the harness drives {', '.join(ENGINES)} "
            "(Firefox and WebKit need the credentials shim, not built)"
        )
    options: dict[str, Any] = {
        "headless": True,
        "args": [f"--host-resolver-rules={resolver_rules()}"],
    }
    if engine != "chromium":
        options["channel"] = engine
    return options
