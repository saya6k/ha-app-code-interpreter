"""Session registry: create/lookup/touch/close, idle reaper, max_sessions eviction."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable

log = logging.getLogger("mcp-server")


class SessionNotFound(KeyError):
    pass


@dataclass(eq=False)
class Session:
    id: str
    sandbox: Any
    created: float
    last_used: float
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class SessionManager:
    def __init__(
        self,
        sandbox_factory: Callable[[str], Awaitable[Any]],
        *,
        idle_timeout_s: float,
        max_sessions: int,
        clock: Callable[[], float] = time.time,
        on_destroy: Callable[[Session, str], None] | None = None,
    ) -> None:
        self._factory = sandbox_factory
        self._idle = idle_timeout_s
        self._max = max_sessions
        self._clock = clock
        self._on_destroy = on_destroy
        self._sessions: dict[str, Session] = {}
        self._create_lock = asyncio.Lock()

    def list(self) -> list[Session]:
        return list(self._sessions.values())

    def expires_in(self, session: Session) -> float:
        return max(0.0, session.last_used + self._idle - self._clock())

    @contextlib.asynccontextmanager
    async def acquire(self, session_id: str | None) -> AsyncIterator[Session]:
        """Get (or create, if session_id is None) a session and hold its lock."""
        if session_id is None:
            session = await self._create()
        else:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFound(session_id)
        async with session.lock:
            if self._sessions.get(session.id) is not session:
                raise SessionNotFound(session.id)  # closed while we waited
            session.last_used = self._clock()
            try:
                yield session
            finally:
                session.last_used = self._clock()

    async def close(self, session_id: str, reason: str = "close") -> None:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFound(session_id)
        await self._destroy(session, reason)

    async def close_all(self, reason: str) -> None:
        for session in list(self._sessions.values()):
            await self._destroy(session, reason)

    async def reap(self) -> None:
        now = self._clock()
        for session in list(self._sessions.values()):
            if not session.lock.locked() and now - session.last_used > self._idle:
                await self._destroy(session, "idle")

    async def run_reaper(self, interval_s: float = 60.0) -> None:
        while True:
            await asyncio.sleep(interval_s)
            try:
                await self.reap()
            except Exception:  # keep the reaper alive
                log.exception("[mcp-server] reaper failed")

    async def _create(self) -> Session:
        async with self._create_lock:
            while len(self._sessions) >= self._max:
                idle = [s for s in self._sessions.values() if not s.lock.locked()]
                if not idle:
                    raise RuntimeError("max_sessions reached and all sessions are busy")
                await self._destroy(min(idle, key=lambda s: s.last_used), "evicted")
            sid = secrets.token_hex(8)
            sandbox = await self._factory(sid)
            now = self._clock()
            session = Session(sid, sandbox, created=now, last_used=now)
            self._sessions[sid] = session
            return session

    async def _destroy(self, session: Session, reason: str) -> None:
        if self._sessions.pop(session.id, None) is None:
            return
        try:
            await session.sandbox.destroy()
        except Exception:  # reconcile on next start reclaims leftovers
            log.exception("[mcp-server] destroy failed sid=%s", session.id)
        if self._on_destroy:
            self._on_destroy(session, reason)
