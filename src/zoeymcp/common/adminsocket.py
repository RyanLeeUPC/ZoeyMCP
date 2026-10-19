"""The vault's admin socket and the waits behind it, as the CLI needs them.

The CLI talks to the vault's admin socket from either environment, and ``python -m zoeymcp
gateway`` goes through the CLI, so it takes these from here rather than from the vault's code.
``vault.admin`` and ``vault.oauth.protocol`` re-export them.
"""

from __future__ import annotations

from typing import Final

DEFAULT_SOCKET: Final = "/run/zoeymcp/admin.sock"
SOCKET_ENV: Final = "ZOEYMCP_ADMIN_SOCKET"
# What bounds a refresh of one slot, and a login's code exchange (M2 design D.3): the CLI's
# admin timeouts are derived from them.
REFRESH_BUDGET: Final = 41.0
EXCHANGE_DEADLINE: Final = 20.0
