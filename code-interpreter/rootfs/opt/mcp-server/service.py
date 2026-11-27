"""Tool logic behind server.py, free of MCP (SPEC §3.1, §3.3).

Turns failures into tool results: an unknown session or a sandbox that will
not start is something the model should read and react to, not a crash.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import egress
import sharefs
from hab import Hab, HabRefused, Rules
from hamcp import ADMIN, APIS, ASSIST, HaToolError, HaUnavailable, HomeAssistant
from audit import Audit, code_detail, sha256
from policy import SandboxPolicy
from replclient import RpcError
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
NEW_FILES_CAP = 20
HA_CALLS_PER_CELL = 50  # a runaway loop must not flip every light in the house
ARGS_AUDIT_CAP = 4096
SELF_CHECK_UID = UID_BASE - 1  # outside the session slots
NOT_FOUND_HINT = (
    "This session expired or was closed; its variables and files are gone. "
    "Call again without session_id: you continue your latest open session if there is one "
    "(check which variables it has), otherwise a new one starts."
)


@dataclass(frozen=True)
class Options:
    idle_timeout_minutes: int = 20
    max_sessions: int = 3
    policy: SandboxPolicy = field(default_factory=SandboxPolicy)
    max_file_mb: int = 20
    export_dir: Path = Path(DEFAULT_EXPORT_DIR)
    audit_retention_days: int = 30
    hab_rules: Rules = field(default_factory=Rules)


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
        hab_rules=Rules(
            allow=tuple(r.strip() for r in raw.get("hab_allow") or [] if r and r.strip()),
            deny=tuple(r.strip() for r in raw.get("hab_deny") or [] if r and r.strip()),
        ),
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


def _clamp(timeout_s: float) -> float:
    return max(1, min(float(timeout_s), MAX_TIMEOUT_S))


class _CellCalls:
    """What a running cell may ask the app for, on its session's behalf (SPEC
    §3.4). Every argument comes from sandbox code: paths are checked by
    sharefs and the agent, exactly as for the MCP tools."""

    def __init__(self, service: "Service", sandbox, user_id: str | None = None, deadline: float = 0.0) -> None:
        self.service = service
        self.sandbox = sandbox
        self.user_id = user_id
        self.deadline = deadline
        self.ha_calls = 0
        self.pool = service.ha.pool()  # Home Assistant connections for this run

    def _fail(self, event: str, e: Exception, **detail) -> RpcError:
        audit = self.service.audit
        audit.record(event, self.sandbox.sid, "error", **detail, error=type(e).__name__, message=str(e))
        if getattr(e, "violation", None):
            audit.record("policy.violation", self.sandbox.sid, "denied", kind=e.violation, during=event, message=str(e))
        return RpcError(type(e).__name__, str(e))

    def rejected(self, reason: str) -> None:
        self.service.audit.record("policy.violation", self.sandbox.sid, "denied", kind="rpc", message=reason)

    async def call(self, op: str, args: dict):
        svc, s = self.service, self.sandbox
        if op == "share.list":
            path = str(args.get("path", ""))
            try:
                out = await asyncio.to_thread(sharefs.list_share, path, root=svc.share_root)
            except ShareError as e:
                raise self._fail("share.list", e, path=path) from None
            svc.audit.record("share.list", s.sid, path=out["path"], entries=len(out["entries"]))
            return out
        if op == "share.import":
            share_path, dest = str(args.get("share_path", "")), args.get("dest")
            try:
                return await svc._import(s, share_path, None if dest is None else str(dest))
            except (ShareError, FileOpError) as e:
                raise self._fail("file.import", e, share_path=share_path) from None
        if op == "share.export":
            path = str(args.get("path", ""))
            try:
                return await svc._export(s, path)
            except (ShareError, FileOpError) as e:
                raise self._fail("file.export", e, path=path) from None
        if op in ("ha.list", "ha.call"):
            return await self._ha(op, args)
        if op == "ha.hab":
            return await self._hab(args)
        self.rejected(f"unknown call {op!r}")
        raise RpcError("RpcRejected", f"unknown call {op!r}")

    def _deny(self, kind: str, name: str, message: str) -> RpcError:
        self.service.audit.record("policy.violation", self.sandbox.sid, "denied", kind=kind, message=message,
                                  user_id=self.user_id)
        return RpcError(name, message)

    async def _hab(self, args: dict):
        svc, s = self.service, self.sandbox
        if not await svc.ha.is_admin(self.user_id):
            raise self._deny("admin", "AdminOnly", "ha.admin is only for Home Assistant administrators")
        argv, stdin = args.get("argv"), args.get("stdin")
        if stdin is not None and not isinstance(stdin, str):
            raise RpcError("TypeError", "stdin must be a string")
        try:
            path, effect = await svc.hab.check(argv if isinstance(argv, list) else [])
        except HabRefused as e:
            raise self._deny(e.kind, "NotAllowed", str(e)) from None
        except (OSError, ValueError, KeyError) as e:  # hab missing or its index unreadable
            raise RpcError("HabUnavailable", f"{type(e).__name__}: {e}") from None
        self.ha_calls += 1
        if self.ha_calls > HA_CALLS_PER_CELL:
            raise self._deny("rate", "RateLimited", f"more than {HA_CALLS_PER_CELL} Home Assistant calls in one run")
        raw = json.dumps(argv)
        detail = dict(command=path, side_effect=effect, argv=raw[:ARGS_AUDIT_CAP], argv_sha256=sha256(raw.encode()),
                      stdin_chars=len(stdin or ""), user_id=self.user_id)
        t0 = time.monotonic()
        svc._ha_inflight[self.user_id] = svc._ha_inflight.get(self.user_id, 0) + 1
        try:
            out = await svc.hab.call(argv, stdin, max(1.0, self.deadline - time.monotonic()))
        except (OSError, TimeoutError) as e:
            svc.audit.record("ha.hab", s.sid, "error", **detail, ms=_ms(t0), error=type(e).__name__)
            raise RpcError("HabUnavailable", f"{type(e).__name__}: {e}") from None
        finally:
            svc._ha_inflight[self.user_id] -= 1
        ok = out.get("success") is not False
        svc.audit.record("ha.hab", s.sid, "ok" if ok else "error", **detail, ms=_ms(t0),
                         exit_code=out.get("exit_code"), output_chars=len(json.dumps(out, default=str)))
        return out

    async def _allowed_tools(self, api: str) -> list[dict]:
        """What this caller may see of `api`, asked again on every call: admin
        rights can change mid-session."""
        svc = self.service
        if api not in APIS:
            raise self._deny("rpc", "RpcRejected", f"unknown API {api!r}")
        if api == ADMIN and not await svc.ha.is_admin(self.user_id):
            raise self._deny("admin", "AdminOnly", "ha.admin is only for Home Assistant administrators")
        try:
            tools = await svc.ha.tools(api)
        except HaUnavailable as e:
            raise RpcError("HaUnavailable", str(e)) from None
        # The Home Assistant API is not bounded by exposure: admins get its
        # read-only tools only (call_action and every config change stay out).
        return [t for t in tools if t["read_only"]] if api == ADMIN else tools

    async def _ha(self, op: str, args: dict):
        svc, s = self.service, self.sandbox
        api = str(args.get("api", ASSIST))
        tools = await self._allowed_tools(api)
        if op == "ha.list":
            return tools
        name = str(args.get("name", ""))
        tool_args = args.get("args") or {}
        if not isinstance(tool_args, dict):
            raise RpcError("TypeError", "tool arguments must be an object")
        tool = next((t for t in tools if t["name"] == name), None)
        if tool is None:
            if api == ADMIN:
                raise self._deny("admin", "NotAllowed", f"{name!r} is not one of the read-only tools ha.admin offers")
            raise RpcError("UnknownTool", f"Home Assistant has no tool {name!r} (see await ha.tools())")
        self.ha_calls += 1
        if self.ha_calls > HA_CALLS_PER_CELL:
            raise self._deny("rate", "RateLimited", f"more than {HA_CALLS_PER_CELL} Home Assistant calls in one run")
        raw = json.dumps(tool_args, sort_keys=True)
        detail = dict(api=api, tool=name, args=raw[:ARGS_AUDIT_CAP], args_sha256=sha256(raw.encode()),
                      read_only=tool["read_only"], destructive=tool["destructive"], user_id=self.user_id)
        t0 = time.monotonic()
        svc._ha_inflight[self.user_id] = svc._ha_inflight.get(self.user_id, 0) + 1
        try:
            value = await self.pool.call(api, name, tool_args, max(1.0, self.deadline - time.monotonic()))
        except (HaToolError, HaUnavailable) as e:
            svc.audit.record("ha.call", s.sid, "error", **detail, ms=_ms(t0), error=type(e).__name__, message=str(e))
            raise RpcError(type(e).__name__, str(e)) from None
        finally:
            svc._ha_inflight[self.user_id] -= 1
        svc.audit.record("ha.call", s.sid, **detail, ms=_ms(t0), result_chars=len(json.dumps(value, default=str)))
        return value


class Service:
    def __init__(
        self,
        options: Options,
        *,
        create_sandbox: Callable[..., Awaitable] = Sandbox.create,
        base_dir: Path = BASE_DIR,
        share_root: Path = sharefs.SHARE,
        audit: Audit | None = None,
        ha: HomeAssistant | None = None,
    ) -> None:
        self.options = options
        self.ha = ha or HomeAssistant()
        self.hab = Hab(options.hab_rules)
        # Home Assistant calls in flight per user: a run_code arriving while
        # one waits is that call coming back to us (a tool or script that asks
        # the conversation agent again). Refused, so it cannot recurse.
        self._ha_inflight: dict[str | None, int] = {}
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

    async def _call(self, session_id: str | None, fn, event: str, *, owner: str | None = None, **detail) -> dict:
        """Run fn(sandbox) in a session; on failure audit `event` as an error."""
        def failed(sid, error: str, message: str, kind: str | None = None) -> None:
            self.audit.record(event, sid, "error", **detail, error=error, message=message)
            if kind:
                self.audit.record("policy.violation", sid, "denied", kind=kind, during=event, message=message)

        try:
            async with self.manager.acquire(session_id, owner) as session:
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
        self, code: str, session_id: str | None = None, timeout_s: float = DEFAULT_TIMEOUT_S, reset: bool = False,
        user_id: str | None = None,
    ) -> dict:
        if user_id and self._ha_inflight.get(user_id):
            self.audit.record("policy.violation", session_id, "denied", kind="nested", user_id=user_id,
                              message="run_code while this user's Home Assistant call is in flight")
            return {"error": "nested_call", "detail": (
                "A Home Assistant tool called during your run_code asked the conversation agent again; "
                "the nested run_code is refused so it cannot recurse.")}

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
            limit = _clamp(timeout_s)
            calls = _CellCalls(self, s, user_id, deadline=time.monotonic() + limit)
            admin = await self.ha.is_admin(user_id)  # ha.admin exists in the cell only for admins
            try:
                r = await s.run_code(code, limit, reset, rpc=calls, ctx={"admin": admin})
            finally:
                await calls.pool.close()
            after = await snapshot(s)
            changed = sorted(p for p, meta in after.items() if before.get(p) != meta)
            r["new_files"] = changed[:NEW_FILES_CAP]
            self.audit.record(
                "code.exec", s.sid, "error" if r["error"] else "ok", **code_detail(code), ms=_ms(t0),
                error=r["error"], timeout=r["error"] == "TimeoutError", kernel_restarted=r["kernel_restarted"],
                reset=reset, logs_chars=len(r["logs"]),
                new_files=len(changed), user_id=user_id, admin=admin, ha_calls=calls.ha_calls,
            )
            return r

        # Without session_id, a known user continues their latest session, as
        # Claude Code keeps one REPL per conversation: agents rarely pass the
        # id back. Callers with no user (a satellite) always get a new one,
        # so anonymous conversations never share variables.
        resumed = session_id is None and user_id is not None and (latest := self.manager.latest(user_id)) is not None
        if resumed:
            out = await self._call(latest, run, "code.exec", owner=user_id, **code_detail(code))
            if out.get("error") != "session_not_found":  # closed in between: start a new one below
                return {**out, "resumed": True}
        return await self._call(session_id, run, "code.exec", owner=user_id, **code_detail(code))

    async def _import(self, s, share_path: str, dest: str | None) -> dict:
        # Off the event loop: up to max_file_mb of disk I/O would stall every call.
        data = await asyncio.to_thread(sharefs.read_share, share_path, self.max_bytes, root=self.share_root)
        target = dest or Path(share_path).name
        out = await s.write_file(target, data, self.max_bytes)
        digest = await asyncio.to_thread(sha256, data)
        self.audit.record("file.import", s.sid, share_path=share_path, path=out["path"],
                          size=out["size"], sha256=digest)
        return out

    async def _export(self, s, path: str) -> dict:
        data, size = await s.read_file(path, self.max_bytes + 1)
        if size > self.max_bytes:
            raise FileOpError(f"{path} is larger than max_file_mb ({self.options.max_file_mb} MB)", "size")
        dest = await asyncio.to_thread(sharefs.export, data, path, self.options.export_dir, s.sid, root=self.share_root)
        digest = await asyncio.to_thread(sha256, data)
        self.audit.record("file.export", s.sid, path=path, share_path=str(dest), size=size, sha256=digest)
        return {"share_path": str(dest), "size": size}

    def list_sessions(self, user_id: str | None = None, everyone: bool = False) -> dict:
        """The caller's own sessions; everyone=True for the Ingress panel."""
        return {
            "sessions": [
                {
                    "session_id": s.id,
                    "created": s.created,
                    "last_used": s.last_used,
                    "expires_in_s": round(self.manager.expires_in(s)),
                }
                for s in self.manager.list()
                if everyone or s.owner == user_id
            ]
        }

    async def close_session(self, session_id: str, user_id: str | None = None, everyone: bool = False) -> dict:
        session = next((s for s in self.manager.list() if s.id == session_id), None)
        if session is None or not (everyone or session.owner == user_id):
            return {"error": "session_not_found", "hint": NOT_FOUND_HINT}
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
