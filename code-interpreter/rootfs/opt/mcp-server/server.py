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


META_USER_ID = "io.home-assistant/user_id"


def caller(ctx: Context) -> str | None:
    """The Home Assistant user in the conversation. Home Assistant's MCP client
    sends it only to servers it found through Supervisor discovery (this app);
    any other client, or a pipeline with no user, is anonymous."""
    meta = ctx.request_context.meta
    user = (getattr(meta, "model_extra", None) or {}).get(META_USER_ID) if meta else None
    return user if isinstance(user, str) and user else None


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
    """Run JavaScript (Node 26) in a sandbox that can also reach Home Assistant.

    One call runs a whole script: read state, filter it in code, act, and
    return only what is needed. Top-level await works; const/let/function/
    class declared at the top level stay defined for later calls with the
    same session_id (omit it to start a new session; session_not_found means
    the old variables and files are gone). The last expression is returned as
    `result` (promises inside a returned object are awaited); console.log and
    log() output comes back as `logs`; a thrown error as `error` + `message`.

    Globals:
      ha.tools(): Promise<Tool[]>              Home Assistant tools for entities exposed to Assist
      ha.<domain>.<tool>(args): Promise<any>   e.g. ha.intent.HassTurnOff({name: "Kitchen light"}),
                                               ha.homeassistant.GetLiveContext()
      ha.call(name, args)                      the same by full name, e.g. "light__HassLightSet"
      ha.admin?                                administrators only: read-only tools (logs, history,
                                               traces, configuration); undefined for everyone else
      $`cmd ${x}`                              sh -c in /sandbox, values quoted; .text() .lines()
                                               .json() .nothrow() .timeout(ms); non-zero exit throws
      file(p).text()/json()/lines()/exists(), write(p, s), sleep(ms), log(...), require(builtin)
      share.list(dir?), share.import(sharePath, dest?), share.export(path)   Home Assistant's /share

    Example, one call:
      const ctx = await ha.homeassistant.GetLiveContext();
      const on = /* parse ctx */ [];
      await Promise.all(on.map((name) => ha.intent.HassTurnOff({ name })));
      ({ turnedOff: on })
    Example, analysis with Python (numpy, pandas, scipy, statsmodels,
    scikit-learn, sympy, networkx, matplotlib with Korean labels, seaborn,
    openpyxl, pyarrow, pillow, python-docx, fpdf2, pypdf, pdfplumber, …):
      await share.import("energy.csv");
      await write("plot.py", "import pandas as pd ...; plt.savefig('plot.png')");
      await $`python3 plot.py`; (await share.export("plot.png")).share_path

    Limits: Home Assistant ends a call after 30 s, so keep timeout_s at 25 and
    split longer work across calls (variables survive; a timed-out run is
    interrupted, a loop after an await restarts the REPL but keeps files).
    At most 50 Home Assistant calls per run. Name rooms and devices ("here" is
    not known). Files: /sandbox (256 MB), /tmp (64 MB). No npm, no /proc, one
    worker thread, no network unless the app's allowlist permits a host.
    """
    return await with_heartbeat(ctx, svc.run_code(code, session_id, timeout_s, reset, user_id=caller(ctx)))


@mcp.tool()
async def list_sessions(ctx: Context) -> dict:
    """List your active sandbox sessions and how long until each expires when idle."""
    return svc.list_sessions(user_id=caller(ctx))


@mcp.tool()
async def close_session(session_id: str, ctx: Context) -> dict:
    """Close a sandbox session now, discarding its variables and files."""
    return await svc.close_session(session_id, user_id=caller(ctx))


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
    log.info("[hamcp] %s", await svc.ha.self_check())
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
