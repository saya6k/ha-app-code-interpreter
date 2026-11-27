import asyncio
import json
import contextlib

import httpx
import pytest
from mcp import types

import hamcp
from hamcp import HaToolError, HaUnavailable, HomeAssistant


def text(*parts):
    return [types.TextContent(type="text", text=p) for p in parts]


def test_unwrap_prefers_structured_then_json_then_text():
    assert hamcp.unwrap(types.CallToolResult(content=text("{}"), structuredContent={"a": 1})) == {"a": 1}
    assert hamcp.unwrap(types.CallToolResult(content=text('{"b": [1]}'))) == {"b": [1]}
    assert hamcp.unwrap(types.CallToolResult(content=text("plain words"))) == "plain words"
    with pytest.raises(HaToolError, match="no device"):
        hamcp.unwrap(types.CallToolResult(content=text("no device"), isError=True))


def test_describe_treats_undeclared_as_writing_and_destructive():
    bare = types.Tool(name="x__y", inputSchema={"type": "object"})
    ro = types.Tool(name="a__b", inputSchema={}, annotations=types.ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    assert hamcp.describe(bare)["read_only"] is False and hamcp.describe(bare)["destructive"] is True
    assert hamcp.describe(ro)["read_only"] is True and hamcp.describe(ro)["destructive"] is False


USERS = [
    {"id": "owner", "is_active": True, "system_generated": False, "group_ids": ["system-admin"]},
    {"id": "supervisor", "is_active": True, "system_generated": True, "group_ids": ["system-admin"]},
    {"id": "kid", "is_active": True, "system_generated": False, "group_ids": ["system-users"]},
    {"id": "gone", "is_active": False, "system_generated": False, "group_ids": ["system-admin"]},
]


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def ha_with(users=USERS, fail=False):
    ha = HomeAssistant(token="t", clock=Clock())
    ha.fetches = 0

    async def fetch():
        ha.fetches += 1
        if fail:
            raise HaUnavailable("down")
        return users

    ha._fetch_users = fetch
    return ha


@pytest.mark.parametrize("user,admin", [("owner", True), ("supervisor", False), ("kid", False),
                                        ("gone", False), ("stranger", False), (None, False)])
def test_only_active_human_admins_are_admins(user, admin):
    assert asyncio.run(ha_with().is_admin(user)) is admin


def test_user_lookup_is_cached_and_failure_means_not_admin():
    ha = ha_with()

    async def go():
        await ha.is_admin("owner")
        await ha.is_admin("kid")
        ha.clock.t = hamcp.CACHE_S + 1
        await ha.is_admin("owner")

    asyncio.run(go())
    assert ha.fetches == 2
    assert asyncio.run(ha_with(fail=True).is_admin("owner")) is False


def test_tools_are_cached_per_api_and_unknown_apis_refused():
    ha = HomeAssistant(token="t", clock=Clock())
    opened = []

    class Session:
        async def list_tools(self):
            return types.ListToolsResult(tools=[types.Tool(name="intent__HassTurnOn", inputSchema={})])

    @contextlib.asynccontextmanager
    async def session(api, timeout_s):
        opened.append(api)
        yield Session()

    ha._session = session

    async def go():
        a = await ha.tools("assist")
        await ha.tools("assist")
        ha.clock.t = hamcp.CACHE_S + 1
        await ha.tools("assist")
        return a

    assert asyncio.run(go())[0]["name"] == "intent__HassTurnOn"
    assert opened == ["assist", "assist"]
    with pytest.raises(ValueError):
        asyncio.run(ha.tools("mcp_client_for_this_app"))


def test_why_names_the_missing_integration_and_token_problems():
    def status(code):
        req = httpx.Request("POST", "http://supervisor/core/api/mcp/assist")
        return httpx.HTTPStatusError("x", request=req, response=httpx.Response(code, request=req))

    assert "Model Context Protocol Server integration" in HomeAssistant._why(status(404))
    assert "refused the app's token (401)" in HomeAssistant._why(ExceptionGroup("g", [status(401)]))
    assert "unreachable" in HomeAssistant._why(OSError("no route"))


def test_no_token_is_unavailable_not_a_crash():
    with pytest.raises(HaUnavailable, match="outside Home Assistant"):
        asyncio.run(HomeAssistant(token="").tools("assist"))


def test_generate_data_posts_to_ai_task_and_returns_the_data(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers["authorization"]
        return httpx.Response(200, json={"service_response": {"conversation_id": "c", "data": {"save": False}}})

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    ha = HomeAssistant(token="t", base="http://supervisor/core")
    out = asyncio.run(ha.generate_data("task", "do it", {"save": {"selector": {"boolean": {}}}}))
    assert out == {"save": False}
    assert seen["url"] == "http://supervisor/core/api/services/ai_task/generate_data?return_response"
    assert "entity_id" not in seen["body"] and seen["auth"] == "Bearer t"
    asyncio.run(ha.generate_data("task", "do it", {}, entity_id="ai_task.claude_ai_task"))
    assert seen["body"]["entity_id"] == "ai_task.claude_ai_task"
