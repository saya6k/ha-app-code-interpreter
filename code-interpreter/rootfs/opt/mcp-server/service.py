"""Tool logic behind server.py, free of MCP (SPEC §3.1, §3.3).

Turns failures into tool results: an unknown session or a sandbox that will
not start is something the model should read and react to, not a crash.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import mimetypes
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import egress
import sharefs
from audit import Audit, code_detail, sha256
from policy import SandboxPolicy
from sandbox import BASE_DIR, FileOpError, Sandbox, SandboxError
from sharefs import ShareError
from sessions import UID_BASE, Session, SessionManager, SessionNotFound

log = logging.getLogger("mcp-server")

OPTIONS_PATH = Path("/data/options.json")
MAX_TIMEOUT_S = 600
# Home Assistant's MCP integration ends a tool call after 30 s
# (asyncio.timeout(30)): stopping at 25 s ourselves lets the cell be
# interrupted cleanly, variables kept, instead of the call being cut off.
DEFAULT_TIMEOUT_S = 25
MIB = 1 << 20
DEFAULT_EXPORT_DIR = "/share/code-interpreter"
TEXT_LIMIT = 16000  # chars returned by read_file
NEW_FILES_CAP = 20
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
    max_file_mb: int = 20
    export_dir: Path = Path(DEFAULT_EXPORT_DIR)
    audit_retention_days: int = 30


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
    export_dir = Path(raw.get("export_dir") or DEFAULT_EXPORT_DIR)
    if not export_dir.is_absolute() or ".." in export_dir.parts or not (
        export_dir == sharefs.SHARE or sharefs.SHARE in export_dir.parents
    ):
        log.error("[mcp-server] export_dir %s is not under /share — using %s", export_dir, DEFAULT_EXPORT_DIR)
        export_dir = Path(DEFAULT_EXPORT_DIR)
    return Options(
        idle_timeout_minutes=int(raw.get("idle_timeout_minutes", 20)),
        max_sessions=int(raw.get("max_sessions", 3)),
        policy=SandboxPolicy(memory_mb=int(raw.get("memory_limit_mb", 2048)), allowlist=tuple(allow)),
        max_file_mb=int(raw.get("max_file_mb", 20)),
        export_dir=export_dir,
        audit_retention_days=int(raw.get("audit_retention_days", 30)),
    )


EGRESS_VIOLATIONS = {"not-allowlisted", "ip-literal", "non-public-address", "method-not-allowed"}


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


def _snapshot(listing: dict) -> dict[str, tuple]:
    """Files worth reporting: no dot paths (HOME lives in /sandbox)."""
    return {
        e["path"]: (e["size"], e["mtime"])
        for e in listing["entries"]
        if e["type"] == "file" and not any(part.startswith(".") for part in e["path"].split("/"))
    }


def _text_or_binary(path: str, data: bytes, size: int) -> dict:
    """Text if it decodes as UTF-8 (a multi-byte char cut at the limit is fine)."""
    cut = len(data) < size
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        if cut and e.start >= len(data) - 3:
            text = data[: e.start].decode("utf-8", errors="strict")
        else:
            text = None
    if text is None or "\x00" in text:
        return {"path": path, "size": size, "binary": True,
                "mime": mimetypes.guess_type(path)[0] or "application/octet-stream"}
    truncated = cut or len(text) > TEXT_LIMIT
    return {"path": path, "size": size, "content": text[:TEXT_LIMIT], "truncated": truncated}


def _clamp(timeout_s: float) -> float:
    return max(1, min(float(timeout_s), MAX_TIMEOUT_S))


class Service:
    def __init__(
        self,
        options: Options,
        *,
        create_sandbox: Callable[..., Awaitable] = Sandbox.create,
        base_dir: Path = BASE_DIR,
        share_root: Path = sharefs.SHARE,
        audit: Audit | None = None,
    ) -> None:
        self.options = options
        self.share_root = share_root
        self.base_dir = base_dir
        self._create = create_sandbox
        self.audit = audit or Audit(retention_days=options.audit_retention_days)
        self.manager = SessionManager(
            self._factory,
            idle_timeout_s=options.idle_timeout_minutes * 60,
            max_sessions=options.max_sessions,
            on_destroy=self._destroyed,
        )

    async def _factory(self, sid: str, uid: int):
        try:
            sbx = await self._create(
                sid, uid, self.options.policy, base_dir=self.base_dir, on_net_event=self._net_event
            )
        except SandboxError as e:
            self.audit.record("session.create", sid, "error", uid=uid, error=str(e))
            raise
        self.audit.record("session.create", sid, uid=uid, allowlist=list(self.options.policy.allowlist))
        return sbx

    def _destroyed(self, session: Session, reason: str) -> None:
        self.audit.record("session.destroy", session.id, reason=reason,
                          lifetime_s=round(time.time() - session.created))

    def _net_event(self, entry: dict) -> None:
        sid = entry.get("session_id")
        detail = {k: v for k, v in entry.items() if k != "session_id"}
        self.audit.record("net.connect", sid, "allowed" if entry.get("allowed") else "denied", **detail)
        if entry.get("reason") in EGRESS_VIOLATIONS:
            self.audit.record("policy.violation", sid, "denied", kind="egress",
                              host=entry.get("host"), port=entry.get("port"), reason=entry["reason"])

    async def _call(self, session_id: str | None, fn, event: str, **detail) -> dict:
        """Run fn(sandbox) in a session; on failure audit `event` as an error."""
        def failed(sid, error: str, message: str, kind: str | None = None) -> None:
            self.audit.record(event, sid, "error", **detail, error=error, message=message)
            if kind:
                self.audit.record("policy.violation", sid, "denied", kind=kind, during=event, message=message)

        try:
            async with self.manager.acquire(session_id) as session:
                try:
                    out = await fn(session.sandbox)
                except SandboxError as e:
                    failed(session.id, "sandbox_unavailable", str(e))
                    # Closed meanwhile (Ingress, close_session, eviction): the real error still stands.
                    with contextlib.suppress(SessionNotFound):
                        await self.manager.close(session.id, "sandbox_failed")
                    return {"error": "sandbox_unavailable", "detail": str(e)}
                except FileOpError as e:
                    failed(session.id, "file_error", str(e), e.violation)
                    return {"session_id": session.id, "error": "file_error", "detail": str(e)}
                except ShareError as e:
                    failed(session.id, "share_error", str(e), e.violation)
                    return {"session_id": session.id, "error": "share_error", "detail": str(e)}
                return {"session_id": session.id, **out}
        except SessionNotFound:
            return {"error": "session_not_found", "hint": NOT_FOUND_HINT}
        except SandboxError as e:  # could not create one
            return {"error": "sandbox_unavailable", "detail": str(e)}
        except RuntimeError as e:  # all sessions busy / no free uid
            return {"error": "busy", "detail": str(e)}

    @property
    def max_bytes(self) -> int:
        return self.options.max_file_mb * MIB

    async def run_code(
        self, code: str, session_id: str | None = None, timeout_s: float = DEFAULT_TIMEOUT_S, reset: bool = False
    ) -> dict:
        async def snapshot(s) -> dict:
            # new_files is a convenience: a listing problem must never cost
            # the call itself (or its result, once the code has run).
            try:
                return _snapshot(await s.list_files("/sandbox", recursive=True, skip_dot=True))
            except (FileOpError, SandboxError):
                return {}

        async def run(s):
            t0 = time.monotonic()
            before = await snapshot(s)
            r = await s.run_code(code, _clamp(timeout_s), reset)
            after = await snapshot(s)
            changed = sorted(p for p, meta in after.items() if before.get(p) != meta)
            r["new_files"] = changed[:NEW_FILES_CAP]
            self.audit.record(
                "code.exec", s.sid, "error" if r["error"] else "ok", **code_detail(code), ms=_ms(t0),
                error=r["error"], timeout=r["error"] == "TimeoutError", kernel_restarted=r["kernel_restarted"],
                reset=reset, stdout_chars=len(r["stdout"]), stderr_chars=len(r["stderr"]),
                new_files=len(changed),
            )
            return r

        return await self._call(session_id, run, "code.exec", **code_detail(code))

    async def list_files(self, session_id: str, path: str = "/sandbox") -> dict:
        return await self._call(session_id, lambda s: s.list_files(path), "file.list", path=path)

    async def read_file(self, session_id: str, path: str) -> dict:
        async def read(s):
            data, size = await s.read_file(path, TEXT_LIMIT * 4)  # UTF-8: up to 4 bytes per char
            return _text_or_binary(path, data, size)

        return await self._call(session_id, read, "file.read", path=path)

    async def write_file(self, session_id: str, path: str, content: str) -> dict:
        data = content.encode()

        async def write(s):
            if len(data) > self.max_bytes:
                raise FileOpError(f"content is larger than max_file_mb ({self.options.max_file_mb} MB)", "size")
            out = await s.write_file(path, data, self.max_bytes)
            self.audit.record("file.write", s.sid, path=out["path"], size=out["size"], sha256=sha256(data))
            return out

        return await self._call(session_id, write, "file.write", path=path, size=len(data))

    async def import_from_share(self, share_path: str, session_id: str | None = None, dest: str | None = None) -> dict:
        async def imp(s):
            # Off the event loop: up to max_file_mb of disk I/O would stall every call.
            data = await asyncio.to_thread(sharefs.read_share, share_path, self.max_bytes, root=self.share_root)
            target = dest or Path(share_path).name
            out = await s.write_file(target, data, self.max_bytes)
            self.audit.record("file.import", s.sid, share_path=share_path, path=out["path"],
                              size=out["size"], sha256=sha256(data))
            return out

        return await self._call(session_id, imp, "file.import", share_path=share_path)

    async def export_to_share(self, session_id: str, path: str) -> dict:
        async def exp(s):
            data, size = await s.read_file(path, self.max_bytes + 1)
            if size > self.max_bytes:
                raise FileOpError(f"{path} is larger than max_file_mb ({self.options.max_file_mb} MB)", "size")
            dest = await asyncio.to_thread(sharefs.export, data, path, self.options.export_dir, s.sid, root=self.share_root)
            self.audit.record("file.export", s.sid, path=path, share_path=str(dest), size=size, sha256=sha256(data))
            return {"share_path": str(dest), "size": size}

        return await self._call(session_id, exp, "file.export", path=path)

    async def run_command(self, command: str, session_id: str | None = None, timeout_s: float = DEFAULT_TIMEOUT_S) -> dict:
        async def cmd(s):
            t0 = time.monotonic()
            r = await s.run_command(command, _clamp(timeout_s))
            self.audit.record("command.exec", s.sid, "error" if r["error"] else "ok", **code_detail(command, "command"),
                              ms=_ms(t0), exit_code=r["exit_code"], error=r["error"],
                              stdout_chars=len(r["stdout"]), stderr_chars=len(r["stderr"]))
            return r

        return await self._call(session_id, cmd, "command.exec", **code_detail(command, "command"))

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
            problem = None if r.get("result") == "2" else f"unexpected result: {r}"
        except SandboxError as e:
            problem = str(e)
        finally:
            try:
                await sbx.destroy()
            except SandboxError as e:  # fail closed, never crash the app over it
                problem = f"self-check sandbox was not cleaned up: {e}"
        return problem

    async def run_reaper(self) -> None:
        await self.manager.run_reaper()

    async def shutdown(self) -> None:
        await self.manager.close_all("shutdown")
