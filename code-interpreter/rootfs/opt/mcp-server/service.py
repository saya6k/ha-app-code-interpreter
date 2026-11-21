"""Tool logic behind server.py, free of MCP (SPEC §3.1, §3.3).

Turns failures into tool results: an unknown session or a sandbox that will
not start is something the model should read and react to, not a crash.
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import egress
from policy import SandboxPolicy
from sandbox import BASE_DIR, Sandbox, SandboxError
from sessions import UID_BASE, Session, SessionManager, SessionNotFound

log = logging.getLogger("mcp-server")

OPTIONS_PATH = Path("/data/options.json")
MAX_TIMEOUT_S = 600
SELF_CHECK_UID = UID_BASE - 1  # outside the session slots
NOT_FOUND_HINT = (
    "This session expired or was closed; its variables and files are gone. "
    "Call again without session_id to start a new session."
)


@dataclass(frozen=True)
class Options:
    idle_timeout_minutes: int = 20
    max_sessions: int = 3
    policy: SandboxPolicy = field(default_factory=SandboxPolicy)


def load_options(path: Path = OPTIONS_PATH) -> Options:
    """App options; absent or unreadable file -> defaults (bare docker runs)."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError):
        raw = {}
    allow = []
    for entry in raw.get("network_allowlist") or []:
        if not entry or not entry.strip():
            continue
        try:
            egress.parse_rule(entry)
        except ValueError as e:  # dropping only narrows egress: fail-closed
            log.error("[mcp-server] %s — ignored", e)
            continue
        allow.append(entry.strip())
    return Options(
        idle_timeout_minutes=int(raw.get("idle_timeout_minutes", 20)),
        max_sessions=int(raw.get("max_sessions", 3)),
        policy=SandboxPolicy(memory_mb=int(raw.get("memory_limit_mb", 1024)), allowlist=tuple(allow)),
    )


def _clamp(timeout_s: float) -> float:
    return max(1, min(float(timeout_s), MAX_TIMEOUT_S))


class Service:
    def __init__(
        self,
        options: Options,
        *,
        create_sandbox: Callable[..., Awaitable] = Sandbox.create,
        base_dir: Path = BASE_DIR,
        on_net_event: Callable[[dict], None] | None = None,
    ) -> None:
        self.options = options
        self.base_dir = base_dir
        self._create = create_sandbox
        self._on_net_event = on_net_event
        self.manager = SessionManager(
            self._factory,
            idle_timeout_s=options.idle_timeout_minutes * 60,
            max_sessions=options.max_sessions,
            on_destroy=self._destroyed,
        )

    async def _factory(self, sid: str, uid: int):
        return await self._create(
            sid, uid, self.options.policy, base_dir=self.base_dir, on_net_event=self._on_net_event
        )

    @staticmethod
    def _destroyed(session: Session, reason: str) -> None:
        log.info("[mcp-server] session %s closed (%s)", session.id, reason)

    async def _call(self, session_id: str | None, fn) -> dict:
        try:
            async with self.manager.acquire(session_id) as session:
                try:
                    out = await fn(session.sandbox)
                except SandboxError as e:
                    await self.manager.close(session.id, "sandbox_failed")
                    return {"error": "sandbox_unavailable", "detail": str(e)}
                return {"session_id": session.id, **out}
        except SessionNotFound:
            return {"error": "session_not_found", "hint": NOT_FOUND_HINT}
        except SandboxError as e:  # could not create one
            return {"error": "sandbox_unavailable", "detail": str(e)}
        except RuntimeError as e:  # all sessions busy / no free uid
            return {"error": "busy", "detail": str(e)}

    async def run_code(
        self, code: str, session_id: str | None = None, timeout_s: float = 60, reset: bool = False
    ) -> dict:
        return await self._call(session_id, lambda s: s.run_code(code, _clamp(timeout_s), reset))

    async def run_command(self, command: str, session_id: str | None = None, timeout_s: float = 60) -> dict:
        return await self._call(session_id, lambda s: s.run_command(command, _clamp(timeout_s)))

    def list_sessions(self) -> dict:
        return {
            "sessions": [
                {
                    "session_id": s.id,
                    "created": s.created,
                    "last_used": s.last_used,
                    "expires_in_s": round(self.manager.expires_in(s)),
                }
                for s in self.manager.list()
            ]
        }

    async def close_session(self, session_id: str) -> dict:
        try:
            await self.manager.close(session_id)
        except SessionNotFound:
            return {"error": "session_not_found", "hint": NOT_FOUND_HINT}
        return {"closed": session_id}

    def clear_leftovers(self) -> None:
        """Session dirs from a previous run (crash, kill) are useless now."""
        shutil.rmtree(self.base_dir, ignore_errors=True)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    async def self_check(self) -> str | None:
        """Start one throwaway sandbox. None if fine, else why it failed."""
        try:
            sbx = await self._create("selfcheck", SELF_CHECK_UID, self.options.policy, base_dir=self.base_dir)
        except SandboxError as e:
            return str(e)
        try:
            r = await sbx.run_code("1 + 1", 30)
            return None if r.get("result") == "2" else f"unexpected result: {r}"
        finally:
            await sbx.destroy()

    async def run_reaper(self) -> None:
        await self.manager.run_reaper()

    async def shutdown(self) -> None:
        await self.manager.close_all("shutdown")
