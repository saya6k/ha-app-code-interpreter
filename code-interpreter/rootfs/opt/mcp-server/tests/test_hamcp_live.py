"""hamcp against a real MCP server over streamable HTTP (FastMCP on loopback),
standing in for Home Assistant's /api/mcp/assist."""

import asyncio
import socket
import threading
import time
from types import SimpleNamespace

import pytest
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.types import RequestParams, ToolAnnotations

import hamcp
from hamcp import HaToolError, HaUnavailable, HomeAssistant


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def base():
    fake = FastMCP("fake-ha", stateless_http=True, streamable_http_path="/api/mcp/assist")

    @fake.tool(name="intent__HassTurnOff", annotations=ToolAnnotations(readOnlyHint=False))
    def turn_off(name: str) -> str:
        if name == "boom":
            raise ValueError("no device named boom")
        return '{"success": true, "name": "%s"}' % name

    @fake.tool(name="homeassistant__GetLiveContext", annotations=ToolAnnotations(readOnlyHint=True))
    def live() -> str:
        return "Live Context: lights are on"

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(fake.streamable_http_app(), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(5)


def test_lists_and_calls_tools(base):
    ha = HomeAssistant(token="t", base=base)

    async def go():
        tools = {t["name"]: t for t in await ha.tools("assist")}
        on = await ha.call("assist", "intent__HassTurnOff", {"name": "Kitchen"}, 10)
        text = await ha.call("assist", "homeassistant__GetLiveContext", {}, 10)
        return tools, on, text

    tools, on, text = asyncio.run(go())
    assert tools["homeassistant__GetLiveContext"]["read_only"] is True
    assert tools["intent__HassTurnOff"]["read_only"] is False
    assert on == {"success": True, "name": "Kitchen"} or on == {"result": '{"success": true, "name": "Kitchen"}'}
    assert "lights are on" in str(text)


def test_tool_errors_and_missing_api(base):
    ha = HomeAssistant(token="t", base=base)
    with pytest.raises(HaToolError, match="boom"):
        asyncio.run(ha.call("assist", "intent__HassTurnOff", {"name": "boom"}, 10))
    with pytest.raises(HaUnavailable, match="Model Context Protocol Server integration"):
        asyncio.run(ha.tools("homeassistant"))  # not served here: 404, like HA without the integration


def test_caller_reads_the_user_from_request_meta():
    import server  # noqa: PLC0415 - builds the app; fine without /data

    meta = RequestParams.Meta.model_validate({"io.home-assistant/user_id": "abc123"})
    assert server.caller(SimpleNamespace(request_context=SimpleNamespace(meta=meta))) == "abc123"
    assert server.caller(SimpleNamespace(request_context=SimpleNamespace(meta=None))) is None
    odd = RequestParams.Meta.model_validate({"io.home-assistant/user_id": 5})
    assert server.caller(SimpleNamespace(request_context=SimpleNamespace(meta=odd))) is None
