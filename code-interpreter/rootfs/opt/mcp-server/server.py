"""Code Interpreter MCP server — streamable HTTP for Home Assistant's MCP client.

The one tool's signature and description only; the logic lives in service.py.
Sessions need no tools of their own: run_code continues the speaker's latest
one, idle ones expire, and administrators list and close them in the panel.
"""

import asyncio
import contextlib
import logging
import signal

import uvicorn
from mcp.server.fastmcp import Context, FastMCP

import mcpauth
import stdin
import web
from audit import AUDIT_DIR, Audit
from hamcp import HaUnavailable
from service import DEFAULT_TIMEOUT_S, Service, load_options

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("mcp-server")

mcp = FastMCP("Code Interpreter", host="0.0.0.0", port=8099, stateless_http=True)
HEARTBEAT_S = 2.0


META_USER_ID = "io.home-assistant/user_id"


def caller(ctx: Context) -> str | None:
    """The Home Assistant user in the conversation. Home Assistant's MCP client
    sends it only to servers it found through Supervisor discovery (this app),
    and only Home Assistant holds the token every request needs (mcpauth), so
    the id is not something another client can claim. A pipeline with no user
    (a satellite) is anonymous."""
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

    What a call costs: each run_code is a full model round-trip, while the
    work inside a script is cheap and runs concurrently with Promise.all. So
    put everything one step needs in one script (read state, filter it in
    code, act, return only what is needed), and call again only when the next
    step depends on what this one returned. Top-level await works;
    const/let/function/class declared at the top level stay defined for later
    calls. Omit session_id to continue your latest session (`resumed: true`;
    reset: true for a clean one); session_not_found means that session's
    variables and files are gone. The last expression is returned as
    `result` (promises inside a returned object are awaited); console.log and
    log() output comes back as `logs`; a thrown error as `error` + `message`.

    Skills are this user's guides: instructions for a task they repeat (the
    steps, the tools, code to adapt), kept for you to follow. A new
    conversation's first result lists them in `skills` with one-line
    descriptions. When the task at hand is one a listed skill covers, read it
    first and follow it in place of your default approach: skills.<name>()
    returns {guide}. If no `skills` listing is in this conversation,
    skills.find(request) searches them. When the user wants a way of doing
    something kept, or says how you should do it from now on, save it:
    skills.save(name, {description, guide}), in force at once. Write the guide
    for your next self (steps, tools with their arguments, a run_code snippet)
    and the description as what it does and when to use it, in the user's
    words.

    Tools: ha.tools(), ha.admin.tools() and plugins.tools() list names and
    one-line descriptions only. ha.find(text), ha.admin.find(text) and
    plugins.find(text) return the few that match a task with their full input
    schema; find("select:a,b") fetches named ones. Look a tool up before
    calling it with arguments you have not seen.

    Globals:
      ha.<domain>.<tool>(args): Promise<any>   e.g. ha.intent.HassTurnOff({name: "Kitchen light"}),
                                               ha.homeassistant.GetLiveContext() -> {result: text,
                                               entities: [{names, domain, state, areas, attributes}]}:
                                               filter entities, do not parse the text
      ha.call(name, args)                      the same by full name, e.g. "light__HassLightSet"
      ha.admin?                                administrators only: read-only tools (logs, history,
                                               traces, configuration); undefined for everyone else
      ha.admin.hab(argv, {stdin?})             administrators: Home Assistant Builder CLI, e.g.
                                               ["automation", "get", "id"]; returns hab's JSON envelope.
                                               Reads run; changes only if the app's hab_allow rules
                                               allow them (see hab schema --index for commands)
      plugins?.<server>.<tool>(args)           MCP servers Home Assistant reaches that the app allows
                                               you; undefined if none
      skills.list(), skills.find(text)         all of this user's skills, or the few that match
      skills.<name>()                          read one: {guide}
      skills.save(name, {description, guide})  save or replace one
      skills.delete(name)                      remove one the user no longer wants
      skills.request(text)                     have a background writer draft one instead (about a
                                               minute)
      $`cmd ${x}`                              sh -c in /sandbox, values quoted; .text() .lines()
                                               .json() .nothrow() .timeout(ms); non-zero exit throws
      file(p).text()/json()/lines()/exists(), write(p, s), sleep(ms), log(...), require(builtin)
      share.list(dir?), share.import(sharePath, dest?), share.export(path)   Home Assistant's /share

    Example, one call:
      const { entities } = await ha.homeassistant.GetLiveContext();
      const on = entities.filter((e) => e.domain === "light" && e.state === "on").map((e) => e.names);
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


async def reload_when_listening(api: uvicorn.Server) -> None:
    """Have Home Assistant read this version's tools (see reload_own_entries),
    once the MCP endpoint answers: the reload connects to it."""
    for _ in range(120):
        if api.started:
            break
        await asyncio.sleep(0.5)
    else:
        return  # not listening: a reload would only make Home Assistant fail to connect
    try:
        log.info("[hamcp] reloaded MCP entries: %s", await svc.ha.reload_own_entries() or "none yet")
    except HaUnavailable as e:
        log.warning("[hamcp] could not reload this app's MCP entry: %s", e)


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
    try:
        n = len(await svc.hab.index())
        rules = svc.options.hab_rules
        log.info("[hab] %d commands; %d allow and %d deny rules", n, len(rules.allow), len(rules.deny))
    except Exception as e:  # noqa: BLE001 - ha.admin.hab() then answers HabUnavailable
        log.error("[hab] unavailable: %s", e)
    log.info("[plugins] %s", await svc.plugins.describe())
    requests = await stdin.serve(svc.handle_stdin)
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
    token = mcpauth.load_or_create()
    api = uvicorn.Server(uvicorn.Config(
        mcpauth.RequireToken(mcp.streamable_http_app(), token), host=mcp.settings.host, port=mcp.settings.port,
        log_level=mcp.settings.log_level.lower(),
    ))
    reloader = asyncio.create_task(reload_when_listening(api))
    try:
        await api.serve()
    finally:
        reloader.cancel()
        requests.close()
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
