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

# Each live session runs its sandbox under its own uid (UID_BASE + slot), so
# sessions cannot signal each other and RLIMIT_NPROC is counted per session.
UID_BASE = 60000


class SessionNotFound(KeyError):
    pass


@dataclass(eq=False)
class Session:
    id: str
    uid: int
    sandbox: Any
    created: float
    last_used: float
    # Home Assistant user the session belongs to (None: no user, e.g. a
    # satellite's pipeline or a client outside HA). Others never see it.
    owner: str | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class SessionManager:
    def __init__(
        self,
        sandbox_factory: Callable[[str, int], Awaitable[Any]],
        *,
        idle_timeout_s: float,
        max_sessions: int,
        clock: Callable[[], float] = time.time,
        on_destroy: Callable[[Session, str], None] | None = None,
        uid_base: int = UID_BASE,
    ) -> None:
        self._factory = sandbox_factory
        self._idle = idle_timeout_s
        self._max = max_sessions
        self._clock = clock
        self._on_destroy = on_destroy
        self._sessions: dict[str, Session] = {}
        self._uids = range(uid_base, uid_base + max_sessions)
        self._retired: set[int] = set()  # sandbox may outlive a failed destroy
        self._create_lock = asyncio.Lock()

    def list(self) -> list[Session]:
        return list(self._sessions.values())

    def expires_in(self, session: Session) -> float:
        return max(0.0, session.last_used + self._idle - self._clock())

    @contextlib.asynccontextmanager
    async def acquire(self, session_id: str | None, owner: str | None = None) -> AsyncIterator[Session]:
        """Get (or create, if session_id is None) `owner`'s session and hold its lock.
        Another owner's session is reported as not found, not as forbidden."""
        if session_id is None:
            session = await self._create(owner)
        else:
            session = self._sessions.get(session_id)
            if session is None or session.owner != owner:
                raise SessionNotFound(session_id)
        async with session.lock:
            if self._sessions.get(session.id) is not session:
                raise SessionNotFound(session.id)  # closed while we waited
            session.last_used = self._clock()
            try:
                yield session
            finally:
                session.last_used = self._clock()

    def latest(self, owner: str) -> str | None:
        """The owner's most recently used session, if any."""
        mine = [s for s in self._sessions.values() if s.owner == owner]
        return max(mine, key=lambda s: s.last_used).id if mine else None

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

    async def _create(self, owner: str | None = None) -> Session:
        async with self._create_lock:
            while len(self._sessions) >= self._max:
                idle = [s for s in self._sessions.values() if not s.lock.locked()]
                if not idle:
                    raise RuntimeError("max_sessions reached and all sessions are busy")
                await self._destroy(min(idle, key=lambda s: s.last_used), "evicted")
            uid = self._free_uid()
            sid = secrets.token_hex(8)
            try:
                sandbox = await self._factory(sid, uid)
            except Exception as e:
                # A failed create may leave processes behind, as a failed
                # destroy does: keep the uid out of use then too.
                if getattr(e, "uid_in_use", False):
                    self._retired.add(uid)
                    log.warning("[mcp-server] create failed sid=%s uid=%d retired", sid, uid)
                raise
            now = self._clock()
            session = Session(sid, uid, sandbox, created=now, last_used=now, owner=owner)
            self._sessions[sid] = session
            return session

    def _free_uid(self) -> int:
        used = {s.uid for s in self._sessions.values()} | self._retired
        for uid in self._uids:
            if uid not in used:
                return uid
        raise RuntimeError("no sandbox uid available (retired after failed destroys)")

    async def _destroy(self, session: Session, reason: str) -> None:
        if self._sessions.pop(session.id, None) is None:
            return
        try:
            await session.sandbox.destroy()
        except Exception:  # the app restart reclaims it; until then keep the uid out of use
            self._retired.add(session.uid)
            log.exception("[mcp-server] destroy failed sid=%s uid=%d retired", session.id, session.uid)
        if self._on_destroy:
            self._on_destroy(session, reason)
