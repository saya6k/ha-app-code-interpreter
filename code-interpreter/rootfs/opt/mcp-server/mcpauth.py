"""The MCP endpoint answers only Home Assistant (SPEC-code-mode §3.13).

The app announces a secret with its Supervisor discovery
({"url": ..., "token": ...}, Home Assistant 2026.12+), and Home Assistant's
MCP client sends it as `Authorization: Bearer <token>` on every request.
Requests without it are refused: any container on the hassio network can
reach port 8099, and the user id in `_meta` is only worth trusting when the
request comes from Home Assistant.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

from starlette.responses import JSONResponse

TOKEN_PATH = Path("/data/mcp_token")


def load_or_create(path: Path = TOKEN_PATH) -> str:
    """The app's token, created once and kept across restarts (so Home
    Assistant's entry keeps working while the app restarts)."""
    try:
        token = path.read_text().strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    return token


class RequireToken:
    """Pure ASGI middleware: HTTP requests need the bearer token."""

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            sent = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(sent, self.expected):
                response = JSONResponse({"error": "unauthorized: only Home Assistant may call this server"},
                                        status_code=401)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
