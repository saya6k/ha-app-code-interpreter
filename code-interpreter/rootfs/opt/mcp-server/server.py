"""Code Interpreter MCP server — streamable HTTP for Home Assistant's MCP client.

Tool signatures and descriptions only; the logic lives in service.py.
"""

import asyncio
import contextlib
import logging
import signal

from mcp.server.fastmcp import FastMCP

from service import Service, load_options

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("mcp-server")

mcp = FastMCP("Code Interpreter", host="0.0.0.0", port=8099, stateless_http=True)
svc = Service(load_options())


@mcp.tool()
async def run_code(code: str, session_id: str | None = None, timeout_s: int = 60, reset: bool = False) -> dict:
    """Run Python code in a sandbox. Variables persist across calls with the same session_id.

    Omit session_id to start a new session and pass the returned session_id on
    follow-up calls. If a call returns session_not_found, the old variables and
    files are gone: start again without session_id. The last expression's value
    is returned as `result`. Files live under /sandbox; /tmp is scratch.

    Preinstalled: numpy, pandas, scipy, statsmodels, scikit-learn, sympy,
    networkx, matplotlib (Agg; Korean font NanumGothic), seaborn, openpyxl,
    xlsxwriter, pyarrow, pillow, lxml, beautifulsoup4, python-docx, fpdf2,
    pyyaml, tabulate. There is no /proc (psutil does not work) and no network
    unless the app's allowlist permits a host. timeout_s is capped at 600.
    """
    return await svc.run_code(code, session_id, timeout_s, reset)


@mcp.tool()
async def run_command(command: str, session_id: str | None = None, timeout_s: int = 60) -> dict:
    """Run a shell command (sh -c) in a session's sandbox, in /sandbox.

    Shares files with run_code in the same session, but not variables.
    Returns stdout, stderr and exit_code.
    """
    return await svc.run_command(command, session_id, timeout_s)


@mcp.tool()
async def list_sessions() -> dict:
    """List active sandbox sessions and how long until each expires when idle."""
    return svc.list_sessions()


@mcp.tool()
async def close_session(session_id: str) -> dict:
    """Close a sandbox session now, discarding its variables and files."""
    return await svc.close_session(session_id)


async def main() -> None:
    svc.clear_leftovers()
    problem = await svc.self_check()
    if problem:
        # Fail-closed: tools keep returning sandbox_unavailable; say why up front.
        log.error("[mcp-server] sandbox self-check FAILED: %s", problem)
    else:
        log.info("[mcp-server] sandbox self-check ok")
    reaper = asyncio.create_task(svc.run_reaper())
    # uvicorn handles SIGTERM itself, then restores the previous handler and
    # re-raises the signal. With the default handler that kills the process
    # before the cleanup below; a no-op handler lets serve() return instead.
    signal.signal(signal.SIGTERM, lambda *_: None)
    try:
        await mcp.run_streamable_http_async()
    finally:
        reaper.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await reaper
        await svc.shutdown()
        log.info("[mcp-server] all sessions closed")


if __name__ == "__main__":
    asyncio.run(main())
