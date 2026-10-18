"""Telling agents their tool list changed (M3 design E.7).

A registry per (client, server) of downstream listeners: legacy sessions (by session id,
registered on their requests, dropped on DELETE, at most :data:`MAX_SESSIONS` per pair) and
modern ``subscriptions/listen`` streams that asked for ``toolsListChanged``. The SDK's session
object for a request doesn't outlive the request otherwise, so the registry holds it.

When a client's view of a server changes, only that client's listeners are told. Nothing about
the change is sent: the agent lists again and sees the new view.
"""

from __future__ import annotations

import contextlib
from collections import OrderedDict
from collections.abc import Iterable

import anyio
from anyio.abc import TaskGroup
from mcp.server.session import ServerSession
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler, ToolsListChanged

from . import logs

SEND_TIMEOUT = 5.0
MAX_SESSIONS = 256  # per (client, server): the most max_sessions_per_client allows

Key = tuple[str, str]  # (client, server)


class Notifier:
    def __init__(self) -> None:
        self._sessions: dict[Key, OrderedDict[str, ServerSession]] = {}
        self._buses: dict[Key, InMemorySubscriptionBus] = {}
        self._handlers: dict[Key, ListenHandler] = {}
        self._group: TaskGroup | None = None

    async def run(
        self, *, task_status: anyio.abc.TaskStatus[None] = anyio.TASK_STATUS_IGNORED
    ) -> None:
        """Hosts the sends until cancelled."""
        try:
            async with anyio.create_task_group() as group:
                self._group = group
                task_status.started()
                await anyio.sleep_forever()
        finally:
            self._group = None

    def register_session(
        self, client: str, server: str, session_id: str, session: ServerSession
    ) -> None:
        sessions = self._sessions.setdefault((client, server), OrderedDict())
        sessions[session_id] = session
        sessions.move_to_end(session_id)
        while len(sessions) > MAX_SESSIONS:
            sessions.popitem(last=False)

    def drop_session(self, client: str, server: str, session_id: str) -> None:
        sessions = self._sessions.get((client, server))
        if sessions is not None:
            sessions.pop(session_id, None)

    def listen_handler(self, client: str, server: str) -> ListenHandler:
        """The ``subscriptions/listen`` handler for one client's streams on one server."""
        key = (client, server)
        handler = self._handlers.get(key)
        if handler is None:
            bus = InMemorySubscriptionBus()
            self._buses[key] = bus
            handler = self._handlers[key] = ListenHandler(bus)
        return handler

    def changed(self, client: str, server: str) -> None:
        """The client's view of the server changed: tell its listeners."""
        if self._group is None:
            return
        key = (client, server)
        sessions = list(self._sessions.get(key, {}).values())
        bus = self._buses.get(key)
        if not sessions and bus is None:
            return
        logs.event("tools_changed_sent", client=client, server=server, sessions=len(sessions))
        for session in sessions:
            self._group.start_soon(self._send, session)
        if bus is not None:
            self._group.start_soon(bus.publish, ToolsListChanged())

    def changed_for(self, clients: Iterable[str], server: str) -> None:
        for client in clients:
            self.changed(client, server)

    async def _send(self, session: ServerSession) -> None:
        # A session that has gone neither hangs nor raises here (SDK contract test 11).
        with anyio.move_on_after(SEND_TIMEOUT), contextlib.suppress(Exception):
            await session.send_tool_list_changed()

    def forget(self, client: str, server: str | None = None) -> None:
        """Drop a client's listeners: it was removed or unassigned."""
        for key in [key for key in self._sessions if key[0] == client and server in (None, key[1])]:
            del self._sessions[key]
        for key in [key for key in self._handlers if key[0] == client and server in (None, key[1])]:
            del self._handlers[key]
            self._buses.pop(key, None)
