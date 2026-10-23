"""The bridge, ``zoeymcp bridge`` (M7 design C, X13, X14): one stdio MCP program served as a
Streamable HTTP endpoint, which to everything else in ZoeyMCP is one more upstream behind a vault
route.

- :mod:`.framing`: the wire format: lines from and to the child, SSE events, stderr (pure,
  mutation-tested);
- :mod:`.admit`: admission to ``/mcp``, before and after the body (pure, mutation-tested);
- :mod:`.relay`: ids and progress tokens remapped per exchange, and the child's messages routed
  (pure, mutation-tested);
- :mod:`.sessions`: a legacy bridge's sessions (pure, mutation-tested);
- :mod:`.childenv`: the child's environment and work directory (pure, mutation-tested);
- :mod:`.listen`: where the bridge listens, and the peer check on its Unix socket;
- :mod:`.child`: one child process, its lines and its stop;
- :mod:`.server`: the endpoint, its sessions and streams, and readiness;
- :mod:`.main`: the bridge itself: its start-up checks, limits and stop.

The bridge is a relay of JSON-RPC envelopes: it reads the fields it routes by and otherwise
passes the bytes through. It imports no MCP SDK; its code uses the standard library, Starlette,
uvicorn and :mod:`zoeymcp.common` only (test_import_guards.py's ``BRIDGE_SIDE``). Its log lines
carry ``role: bridge``; the token's hash refuses to be logged.
"""

from __future__ import annotations

from ..common.logs import Log

event = Log("bridge").event
