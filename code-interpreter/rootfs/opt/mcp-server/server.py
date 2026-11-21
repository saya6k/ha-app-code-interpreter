"""Code Interpreter MCP server — streamable HTTP for Home Assistant's MCP client.

Tool signatures and descriptions only; the logic lives in service.py.
"""

import asyncio
import contextlib
import logging
import signal

import uvicorn
from mcp.server.fastmcp import Context, FastMCP

import web
from audit import AUDIT_DIR, Audit
from service import DEFAULT_TIMEOUT_S, Service, load_options

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("mcp-server")

mcp = FastMCP("Code Interpreter", host="0.0.0.0", port=8099, stateless_http=True)
HEARTBEAT_S = 2.0


async def with_heartbeat(ctx: Context, coro):
    """Run a tool body while sending a log notification every HEARTBEAT_S on
    the request's SSE stream. Home Assistant's MCP client reads with httpx's
    default 5 s timeout: a quiet stream is dropped ("SSE stream ended without
    a response"). Clients ignore these notifications unless they log them."""
    task = asyncio.ensure_future(coro)
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=HEARTBEAT_S)
            if done:
                return task.result()
            with contextlib.suppress(Exception):  # a heartbeat must never fail the call
                await ctx.debug("still running")
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
options = load_options()
svc = Service(options, audit=Audit(retention_days=options.audit_retention_days))


@mcp.tool()
async def run_code(
    code: str, ctx: Context, session_id: str | None = None, timeout_s: int = DEFAULT_TIMEOUT_S, reset: bool = False
) -> dict:
    """Run Python code in a sandbox. Variables persist across calls with the same session_id.

    Omit session_id to start a new session and pass the returned session_id on
    follow-up calls. If a call returns session_not_found, the old variables and
    files are gone: start again without session_id. The last expression's value
    is returned as `result`, and files the call created or changed under
    /sandbox as `new_files`. Files live under /sandbox (256 MB); /tmp is
    scratch (64 MB). Use import_from_share / export_to_share to move files
    between /sandbox and Home Assistant's /share.

    Preinstalled: numpy, pandas, scipy, statsmodels, scikit-learn, sympy,
    networkx, matplotlib (Agg; Korean labels work by default), seaborn, openpyxl,
    xlsxwriter, pyarrow, pillow, lxml, beautifulsoup4, python-docx, fpdf2,
    pyyaml, tabulate. There is no /proc (psutil does not work) and no network
    unless the app's allowlist permits a host.

    Home Assistant ends any tool call after 30 s, so keep timeout_s at its
    default (25) or lower there: work that needs more than ~25 s (large pip
    installs, long training) cannot finish in one call. Split it into
    shorter steps; variables survive between calls. A timed-out cell is
    interrupted with its variables kept. Other clients may allow up to 600.
    """
    return await with_heartbeat(ctx, svc.run_code(code, session_id, timeout_s, reset))


@mcp.tool()
async def run_command(
    command: str, ctx: Context, session_id: str | None = None, timeout_s: int = DEFAULT_TIMEOUT_S
) -> dict:
    """Run a shell command (sh -c) in a session's sandbox, in /sandbox.

    Shares files with run_code in the same session, but not variables.
    Returns stdout, stderr and exit_code. Same time limit as run_code: keep
    timeout_s at 25 or lower under Home Assistant (it ends calls at 30 s).
    """
    return await with_heartbeat(ctx, svc.run_command(command, session_id, timeout_s))


@mcp.tool()
async def list_files(session_id: str, path: str = "/sandbox") -> dict:
    """List files in a session's /sandbox (name, type, size)."""
    return await svc.list_files(session_id, path)


@mcp.tool()
async def read_file(session_id: str, path: str) -> dict:
    """Read a text file from /sandbox (up to 16000 characters).

    For binary files only the size and MIME type are returned; use
    export_to_share to hand them to the user.
    """
    return await svc.read_file(session_id, path)


@mcp.tool()
async def write_file(session_id: str, path: str, content: str) -> dict:
    """Write a text file into /sandbox (parent directories are created)."""
    return await svc.write_file(session_id, path, content)


@mcp.tool()
async def import_from_share(
    share_path: str, ctx: Context, session_id: str | None = None, dest: str | None = None
) -> dict:
    """Copy a file from Home Assistant's /share into the session's /sandbox.

    share_path is relative to /share (e.g. "energy.csv"). Omit session_id to
    start a new session. dest defaults to the file name in /sandbox.
    """
    return await with_heartbeat(ctx, svc.import_from_share(share_path, session_id, dest))


@mcp.tool()
async def export_to_share(session_id: str, path: str, ctx: Context) -> dict:
    """Copy a /sandbox file (e.g. a plot) to /share so the user can open it.

    Returns share_path, under /share/code-interpreter/<session_id>/. Tell the
    user that path.
    """
    return await with_heartbeat(ctx, svc.export_to_share(session_id, path))


@mcp.tool()
async def list_sessions() -> dict:
    """List active sandbox sessions and how long until each expires when idle."""
    return svc.list_sessions()


@mcp.tool()
async def close_session(session_id: str) -> dict:
    """Close a sandbox session now, discarding its variables and files."""
    return await svc.close_session(session_id)


async def prune_audit() -> None:
    while True:
        svc.audit.prune()
        await asyncio.sleep(3600)


class _EmbeddedServer(uvicorn.Server):
    """The Ingress UI server: leaves signals to the MCP server, whose
    shutdown then stops this one too."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


async def main() -> None:
    svc.clear_leftovers()
    problem = await svc.self_check()
    if problem:
        # Fail-closed: tools keep returning sandbox_unavailable; say why up front.
        log.error("[mcp-server] sandbox self-check FAILED: %s", problem)
    else:
        log.info("[mcp-server] sandbox self-check ok")
    reaper = asyncio.create_task(svc.run_reaper())
    pruner = asyncio.create_task(prune_audit())
    ui = _EmbeddedServer(uvicorn.Config(
        web.build_app(svc, AUDIT_DIR), host="0.0.0.0", port=web.INGRESS_PORT, log_level="warning",
    ))
    ui_task = asyncio.create_task(ui.serve())
    # uvicorn handles SIGTERM itself, then restores the previous handler and
    # re-raises the signal. With the default handler that kills the process
    # before the cleanup below; a no-op handler lets serve() return instead.
    signal.signal(signal.SIGTERM, lambda *_: None)
    try:
        await mcp.run_streamable_http_async()
    finally:
        ui.should_exit = True
        with contextlib.suppress(Exception):
            await asyncio.wait_for(ui_task, 5)
        for task in (reaper, pruner):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await svc.shutdown()
        log.info("[mcp-server] all sessions closed")


if __name__ == "__main__":
    asyncio.run(main())
