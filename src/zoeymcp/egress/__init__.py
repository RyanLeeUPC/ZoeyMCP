"""The egress role, ``zoeymcp egress`` (M7 design I.4, X15): a CONNECT-only proxy whose
listeners each serve one egress source, limited to that source's ``host:port`` list from the
vault.

- :mod:`.connect`: what one connection may do (pure, mutation-tested);
- :mod:`.listen`: where each source's listener binds;
- :mod:`.tunnel`: the connections and their tunnels;
- :mod:`.allowlist`: the lists, long-polled from the vault with the egress key;
- :mod:`.main`: the role itself.

The role imports the standard library and :mod:`zoeymcp.common.netguard` and
:mod:`zoeymcp.common.logs` only (test_import_guards.py's ``EGRESS_SIDE``). It holds no policy
and no secret but its read-only key, inspects no TLS and caches nothing. Its log lines carry
``role: egress``; the key's wrapper refuses to be logged.
"""

from __future__ import annotations

from ..common.logs import Log

event = Log("egress").event
