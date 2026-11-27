import asyncio

import pytest

import hamcp
from plugins import Plugin, Plugins

ENTRIES = [
    {"entry_id": "M1", "title": "Memory", "state": "loaded"},
    {"entry_id": "W1", "title": "Weather", "state": "setup_error"},
    {"entry_id": "D1", "title": "Twin", "state": "loaded"},
    {"entry_id": "D2", "title": "twin", "state": "loaded"},
    {"entry_id": "C1", "title": "My interpreter", "state": "loaded"},
]
TOOLS = {
    "mcp-M1": [{"name": "memory__search", "read_only": True}, {"name": "memory__save", "read_only": False}],
    "mcp-C1": [{"name": "code_interpreter__run_code", "read_only": False}],
}


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


class FakeHA:
    def __init__(self, down=False):
        self.down = down
        self.listed = 0

    async def mcp_servers(self):
        self.listed += 1
        if self.down:
            raise hamcp.HaUnavailable("down")
        return ENTRIES

    async def tools(self, api):
        return TOOLS[api]


def plugins(*configured, ha=None):
    return Plugins(ha or FakeHA(), tuple(configured), clock=Clock())


def test_titles_resolve_case_insensitively_to_their_api():
    p = plugins(Plugin("memory", "all"))
    assert asyncio.run(p.resolve()) == [(Plugin("memory", "all"), "mcp-M1")]


@pytest.mark.parametrize("name,problem", [("Weather", "not loaded"), ("Twin", "several"), ("Nope", "no MCP client"),
                                          ("My interpreter", "this app itself")])
def test_unusable_entries_are_left_out_with_a_reason(name, problem):
    p = plugins(Plugin(name, "all"))
    assert asyncio.run(p.resolve()) == []
    (msg,) = p.problems
    assert problem in msg


def test_admin_plugins_are_only_for_administrators_and_tools_are_tagged():
    p = plugins(Plugin("Memory", "admin"))
    assert asyncio.run(p.tools(admin=False)) == []
    tools = asyncio.run(p.tools(admin=True))
    assert [(t["name"], t["plugin"], t["api"]) for t in tools] == [
        ("memory__search", "Memory", "mcp-M1"), ("memory__save", "Memory", "mcp-M1")]


def test_resolution_is_cached_and_nothing_configured_asks_nothing():
    ha = FakeHA()
    p = plugins(Plugin("Memory", "all"), ha=ha)

    async def go():
        await p.resolve()
        await p.resolve()
        p.clock.t = hamcp.CACHE_S + 1
        await p.resolve()

    asyncio.run(go())
    assert ha.listed == 2
    none = plugins(ha=ha)
    assert asyncio.run(none.resolve()) == [] and ha.listed == 2
    assert asyncio.run(none.describe()) == "none configured"


def test_describe_reports_unavailable_home_assistant():
    p = plugins(Plugin("Memory", "all"), ha=FakeHA(down=True))
    assert asyncio.run(p.describe()).startswith("unavailable")
