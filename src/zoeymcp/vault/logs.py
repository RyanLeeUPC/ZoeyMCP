"""The vault's log lines (design R56): :mod:`zoeymcp.common.logs` with ``role: vault``.

Log fields are chosen by the caller and must never include secrets, placeholders, query values
or raw paths. Importing this module registers :class:`~zoeymcp.vault.store.Secret` as a refused
type, so :func:`event` raises rather than log one, in any role.
"""

from __future__ import annotations

from ..common.logs import Log, quiet, refuse_type, set_stream
from .store import Secret

__all__ = ["event", "quiet", "set_stream"]

refuse_type(Secret)

event = Log("vault").event
