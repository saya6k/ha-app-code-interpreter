"""Home Assistant's MCP Server, on behalf of the person in the conversation
(SPEC-code-mode §3.5).

The app's SUPERVISOR_TOKEN is an admin token: it would reach every API. So
the app decides what a caller gets: everyone the Assist API ("assist",
bounded by the entities exposed to Assist), admins also the read-only tools
of the Home Assistant API ("homeassistant"). Only these two APIs are used:
the MCP client integration registers an API for each MCP server it reaches,
this app included, so "all APIs" would call back into ourselves.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from datetime import timedelta
from typing import Any

log = logging.getLogger("mcp-server")

BASE = "http://supervisor/core"
ASSIST, ADMIN = "assist", "homeassistant"
APIS = (ASSIST, ADMIN)
CACHE_S = 60.0
ADMIN_GROUP = "system-admin"


class HaUnavailable(RuntimeError):
    """Home Assistant could not be asked (no token, no MCP Server integration, …)."""


class HaToolError(RuntimeError):
    """The tool ran and reported an error."""


def unwrap(result) -> Any:
    """A tool result as a value: structured content, else JSON text, else text."""
    if result.isError:
        text = " ".join(c.text for c in result.content if getattr(c, "type", "") == "text")
        raise HaToolError(text or "the tool reported an error")
    if result.structuredContent is not None:
        return result.structuredContent
    texts = [c.text for c in result.content if getattr(c, "type", "") == "text"]
    if texts and len(texts) == len(result.content):
        joined = "\n".join(texts)
        try:
            return json.loads(joined)
        except ValueError:
            return joined
    return [c.model_dump(mode="json") for c in result.content]


def describe(tool) -> dict:
    a = tool.annotations
    return {
        "name": tool.name,
        "description": tool.description or "",
        "input_schema": tool.inputSchema,
        # Undeclared counts as the least safe case, as in Home Assistant itself.
        "read_only": bool(a and a.readOnlyHint),
        "destructive": not (a and a.destructiveHint is False),
    }


class HomeAssistant:
    def __init__(self, token: str | None = None, base: str = BASE, clock=time.monotonic) -> None:
        self.token = token if token is not None else os.environ.get("SUPERVISOR_TOKEN", "")
        self.base = base
        self.clock = clock
        self._tools: dict[str, tuple[float, list[dict]]] = {}
        self._users: tuple[float, dict[str, dict]] | None = None

    @contextlib.asynccontextmanager
    async def _session(self, api: str, timeout_s: float):
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        if not self.token:
            raise HaUnavailable("no Supervisor token: the app runs outside Home Assistant")
        url = f"{self.base}/api/mcp/{api}"
        # The SDK turns a 404 into "Session terminated": keep the HTTP status to say why.
        statuses: list[int] = []

        async def seen(response: httpx.Response) -> None:
            statuses.append(response.status_code)

        http = httpx.AsyncClient(headers={"Authorization": f"Bearer {self.token}"}, timeout=timeout_s,
                                 event_hooks={"response": [seen]})
        try:
            async with http, streamable_http_client(url=url, http_client=http) as (r, w, _):
                async with ClientSession(r, w, read_timeout_seconds=timedelta(seconds=timeout_s)) as s:
                    await s.initialize()
                    yield s
        except Exception as e:  # httpx errors, anyio groups: one message the cell can act on
            inner = self._first(e)
            if isinstance(inner, HaToolError):  # raised by unwrap() inside the session's task group
                raise inner from None
            failed = next((s for s in reversed(statuses) if s >= 400), None)
            raise HaUnavailable(self._why(inner, failed)) from None

    @staticmethod
    def _first(e: BaseException) -> BaseException:
        while isinstance(e, BaseExceptionGroup) and e.exceptions:
            e = e.exceptions[0]
        return e

    @staticmethod
    def _why(e: BaseException, status: int | None = None) -> str:
        e = HomeAssistant._first(e)
        status = getattr(getattr(e, "response", None), "status_code", None) or status
        if status == 404:
            return "Home Assistant has no MCP Server: add the Model Context Protocol Server integration"
        if status in (401, 403):
            return f"Home Assistant refused the app's token ({status})"
        return f"Home Assistant MCP Server unreachable: {type(e).__name__}: {e}"

    async def tools(self, api: str) -> list[dict]:
        if api not in APIS:
            raise ValueError(f"unknown API {api!r}")
        hit = self._tools.get(api)
        if hit and self.clock() - hit[0] < CACHE_S:
            return hit[1]
        async with self._session(api, 15) as s:
            listed = [describe(t) for t in (await s.list_tools()).tools]
        self._tools[api] = (self.clock(), listed)
        return listed

    async def call(self, api: str, name: str, args: dict, timeout_s: float) -> Any:
        if api not in APIS:
            raise ValueError(f"unknown API {api!r}")
        async with self._session(api, timeout_s) as s:
            return unwrap(await s.call_tool(name, args, read_timeout_seconds=timedelta(seconds=timeout_s)))

    async def _fetch_users(self) -> list[dict]:
        import websockets

        if not self.token:
            raise HaUnavailable("no Supervisor token")
        url = self.base.replace("http", "ws", 1) + "/websocket"
        async with websockets.connect(url, max_size=None, open_timeout=10) as ws:
            json.loads(await ws.recv())
            await ws.send(json.dumps({"type": "auth", "access_token": self.token}))
            if json.loads(await ws.recv()).get("type") != "auth_ok":
                raise HaUnavailable("Home Assistant refused the app's token")
            await ws.send(json.dumps({"id": 1, "type": "config/auth/list"}))
            reply = json.loads(await asyncio.wait_for(ws.recv(), 10))
        if not reply.get("success"):
            raise HaUnavailable(f"config/auth/list failed: {reply.get('error')}")
        return reply["result"]

    async def is_admin(self, user_id: str | None) -> bool:
        """An active, human administrator. System users (Supervisor, apps) are
        not: another app's token in a conversation's context is not the
        person speaking. Any failure counts as not an admin (fail-closed)."""
        if not user_id:
            return False
        if self._users is None or self.clock() - self._users[0] >= CACHE_S:
            try:
                users = await self._fetch_users()
            except Exception as e:  # noqa: BLE001
                log.warning("[hamcp] user lookup failed: %s", e)
                return False
            self._users = (self.clock(), {u.get("id"): u for u in users})
        u = self._users[1].get(user_id)
        return bool(u and u.get("is_active") and not u.get("system_generated")
                    and ADMIN_GROUP in (u.get("group_ids") or []))

    async def self_check(self) -> str:
        parts = []
        for api in APIS:
            try:
                parts.append(f"{api}: {len(await self.tools(api))} tools")
            except HaUnavailable as e:
                parts.append(f"{api}: {e}")
        return ", ".join(parts)
