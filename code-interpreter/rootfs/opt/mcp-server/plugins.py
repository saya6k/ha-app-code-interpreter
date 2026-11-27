"""Plugins: MCP servers Home Assistant already reaches, offered to cells as
plugins.<server>.<tool>() (SPEC-code-mode §3.12).

The MCP client integration registers an API for each server it connects to
("mcp-" + config entry id), and Home Assistant's MCP Server serves it like
"assist". So the app calls those servers through Home Assistant: their
credentials stay there. An administrator lists the ones cells may use, each
for everyone with a Home Assistant user ("all") or administrators only.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from hamcp import APIS, API_ID, CACHE_S, HaUnavailable

log = logging.getLogger("mcp-server")

ACCESS = ("all", "admin")
# This app's own tool: a plugin that offers it is this app, reached through
# Home Assistant. Calling it would recurse.
SELF_TOOL = "__run_code"


@dataclass(frozen=True)
class Plugin:
    name: str  # the MCP client config entry's title, or a label when api is set
    access: str = "admin"
    api: str | None = None  # an LLM API id Home Assistant's MCP Server serves, e.g. wardrowbe__<entry id>


def valid_api(api: str) -> bool:
    """A plugin may name any LLM API but the two ha.* and ha.admin use (they
    have their own rules)."""
    return bool(API_ID.match(api)) and api not in APIS


class Plugins:
    def __init__(self, ha, configured: tuple[Plugin, ...], clock=time.monotonic) -> None:
        self.ha = ha
        self.configured = configured
        self.clock = clock
        self._resolved: tuple[float, list[tuple[Plugin, str]]] | None = None
        self.problems: list[str] = []

    async def resolve(self) -> list[tuple[Plugin, str]]:
        """(plugin, API id) for each configured plugin Home Assistant has
        loaded. Missing ones, and this app itself, are left out."""
        if not self.configured:
            return []
        if self._resolved and self.clock() - self._resolved[0] < CACHE_S:
            return self._resolved[1]
        entries = await self.ha.mcp_servers() if any(not p.api for p in self.configured) else []
        out, problems = [], []
        for p in self.configured:
            if p.api:
                api = p.api
            else:
                match = [e for e in entries if e["title"].casefold() == p.name.casefold()]
                if len(match) != 1:
                    problems.append(f"{p.name}: {'several' if match else 'no'} MCP client entries with that title")
                    continue
                entry = match[0]
                if entry["state"] != "loaded":
                    problems.append(f"{p.name}: not loaded ({entry['state']})")
                    continue
                api = f"mcp-{entry['entry_id']}"
            try:
                names = [t["name"] for t in await self.ha.tools(api)]
            except (HaUnavailable, ValueError) as e:
                problems.append(f"{p.name}: {e}")
                continue
            # An API that offers this app's own tool is this app (or an API
            # that bundles it): calling it would recurse.
            if any(n.endswith(SELF_TOOL) for n in names):
                problems.append(f"{p.name}: this app itself, never a plugin")
                continue
            out.append((p, api))
        if problems != self.problems:
            for problem in problems:
                log.warning("[plugins] %s", problem)
        self.problems = problems
        self._resolved = (self.clock(), out)
        return out

    async def tools(self, admin: bool) -> list[dict]:
        """The tools of the plugins this caller may use, each tagged with its
        plugin and API. Callers with no user get none (the caller checks)."""
        out = []
        for p, api in await self.resolve():
            if p.access == "admin" and not admin:
                continue
            for t in await self.ha.tools(api):
                out.append({**t, "plugin": p.name, "api": api})
        return out

    async def describe(self) -> str:
        if not self.configured:
            return "none configured"
        try:
            ready = await self.resolve()
        except HaUnavailable as e:
            return f"unavailable: {e}"
        return ", ".join(f"{p.name} ({p.access})" for p, _ in ready) or "none available"
