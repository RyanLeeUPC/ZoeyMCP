"""The gateway's log lines (M3 design M): :mod:`zoeymcp.common.logs` with ``role: gateway``.

Never logged (G20): client tokens or their hashes, the gateway key, session ids, argument values,
result content, upstream error text, ``instructions``, ``Mcp-Param-*`` values and request headers.
The gateway key's wrapper registers itself as a refused type, so logging it raises.
"""

from __future__ import annotations

from ..common.logs import Log, quiet, set_stream

__all__ = ["event", "quiet", "set_stream"]

event = Log("gateway").event
