"""Ingress web UI: live sessions and the audit log (read-only, plus closing a session).

Served on its own port for Home Assistant's Ingress proxy only; the MCP
endpoint stays on 8099. Requests from anywhere but the Ingress proxy (or
loopback) are refused.
"""

from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

import auditview
from skills import SkillError, calls_in

INGRESS_PORT = 8098
INGRESS_PROXY = "172.30.32.2"  # Supervisor's Ingress gateway on the hassio network
ALLOWED_CLIENTS = frozenset({INGRESS_PROXY, "127.0.0.1", "::1"})
UI_FILE = Path(__file__).with_name("ui") / "index.html"
CSRF_HEADER = "x-requested-with"


class OnlyFrom:
    """Pure ASGI middleware: refuse HTTP requests from any other client host.
    (Starlette 1.x dropped the @app.middleware decorator.)"""

    def __init__(self, app, allowed):
        self.app = app
        self.allowed = allowed

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            client = (scope.get("client") or (None,))[0]
            if client not in self.allowed:
                response = Response("Forbidden: open this page through Home Assistant", status_code=403)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def build_app(svc, audit_dir: Path, allowed_clients=ALLOWED_CLIENTS) -> Starlette:
    async def index(request: Request) -> Response:
        return FileResponse(UI_FILE, media_type="text/html; charset=utf-8",
                            headers={"Cache-Control": "no-store"})

    async def live_sessions(request: Request) -> Response:
        policy = svc.options.policy
        return JSONResponse({
            **svc.list_sessions(everyone=True),  # the panel is admin-only
            "settings": {
                "idle_timeout_minutes": svc.options.idle_timeout_minutes,
                "max_sessions": svc.options.max_sessions,
                "memory_limit_mb": policy.memory_mb,
                "network_allowlist": list(policy.allowlist),
            },
        })

    async def close_session(request: Request) -> Response:
        # A cross-site form cannot set this header; fetch() from the UI does.
        if request.headers.get(CSRF_HEADER) != "code-interpreter-ui":
            return JSONResponse({"error": "missing X-Requested-With"}, status_code=403)
        sid = request.path_params["sid"]
        result = await svc.close_session(sid, everyone=True)
        user = request.headers.get("x-remote-user-name") or request.headers.get("x-remote-user-id")
        svc.audit.record("ui.close_session", sid, "error" if "error" in result else "ok",
                         user=user, result=result.get("error", "closed"))
        return JSONResponse(result, status_code=404 if "error" in result else 200)

    async def list_skills(request: Request) -> Response:
        names = await svc.ha.user_names()
        out = []
        for user in svc.skills.users():
            for s in svc.skills.list(user):
                # What the guide's code visibly calls, for whoever reads it here.
                out.append({"user_id": user, "user": names.get(user), **s, "calls": calls_in(s["guide"])})
        return JSONResponse({"skills": out, "workflow": svc.options.skill_workflow})

    async def skill_action(request: Request) -> Response:
        if request.headers.get(CSRF_HEADER) != "code-interpreter-ui":
            return JSONResponse({"error": "missing X-Requested-With"}, status_code=403)
        user, name, action = (request.path_params[k] for k in ("user", "name", "action"))
        by = request.headers.get("x-remote-user-name") or request.headers.get("x-remote-user-id")
        if action != "delete":
            return JSONResponse({"error": "unknown action"}, status_code=404)
        try:
            svc.skills.delete(user, name)
        except SkillError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        svc.audit.record("skill.deleted", None, user_id=user, name=name, by=by)
        svc.reviewer.deleted(user, name)
        return JSONResponse({"ok": True})

    async def audit_days(request: Request) -> Response:
        return JSONResponse({"days": auditview.days(audit_dir)})

    def day_param(request: Request) -> str:
        return request.query_params.get("day") or ""

    async def audit_sessions(request: Request) -> Response:
        try:
            return JSONResponse({"sessions": auditview.sessions(audit_dir, day_param(request))})
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    async def audit_events(request: Request) -> Response:
        q = request.query_params
        try:
            limit = max(1, min(int(q.get("limit", auditview.DEFAULT_LIMIT)), 5000))
            return JSONResponse(auditview.events(
                audit_dir, day_param(request),
                session_id=q.get("session_id") or None, event=q.get("event") or None, limit=limit,
            ))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    return Starlette(middleware=[Middleware(OnlyFrom, allowed=allowed_clients)], routes=[
        Route("/", index),
        Route("/api/sessions", live_sessions),
        Route("/api/sessions/{sid}/close", close_session, methods=["POST"]),
        Route("/api/skills", list_skills),
        Route("/api/skills/{user}/{name}/{action}", skill_action, methods=["POST"]),
        Route("/api/audit/days", audit_days),
        Route("/api/audit/sessions", audit_sessions),
        Route("/api/audit/events", audit_events),
    ])
