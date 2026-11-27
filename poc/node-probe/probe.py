"""P0 probe for SPEC-code-mode.

A. Node under the real sandbox (policy.py, seccomp.py, sbxexec.py, Sandbox):
   starts without /proc under RLIMIT_AS, heap/Buffer/wasm limits, fetch()
   through the egress proxy, child processes, SIGINT out of a sync loop,
   dynamic import from vm code, an inherited socketpair fd, worker threads.
B. With a real SUPERVISOR_TOKEN (HA app, homeassistant_api: true): the MCP
   Server endpoints /api/mcp/assist and /api/mcp/homeassistant, and the
   fields of config/auth/list. Prints counts and flags, not names or states.

Prints a PASS/FAIL table and exits 1 if anything failed. Copy the whole log back.
"""

import asyncio
import json
import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, "/opt/mcp-server")

from policy import SandboxPolicy  # noqa: E402
from sandbox import Sandbox, SandboxError  # noqa: E402

BASE = Path("/tmp/node-probe")
NODE = "/opt/node/bin/node"
JS = "/opt/probe"
TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
results = []


def report(name, ok, detail=""):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'} | {name:<46} | {str(detail)[:160]}", flush=True)


async def step(name, coro):
    try:
        await coro
    except Exception as e:
        report(name, False, f"{type(e).__name__}: {e}")


async def node(s, script, *args, env="", timeout_s=60):
    """Run a probe script in the sandbox; its last stdout line is JSON."""
    cmd = f"{env} {NODE} {JS}/{script} {' '.join(args)}".strip()
    r = await s.run_command(cmd, timeout_s=timeout_s)
    lines = r["stdout"].strip().splitlines()
    if not lines:
        raise RuntimeError(f"exit {r['exit_code']} {r['error']}: {r['stderr'].strip()[-200:]}")
    return json.loads(lines[-1])


FD_TEST = r"""
import os, socket, subprocess
a, b = socket.socketpair()
p = subprocess.Popen(["NODE", "JS/fd.mjs", str(b.fileno())], pass_fds=(b.fileno(),), stdout=subprocess.PIPE, text=True)
b.close()
got = a.recv(4).decode()
a.sendall(b"pong")
print(got, p.communicate(timeout=10)[0].strip())
""".replace("NODE", NODE).replace("JS", JS)


async def sandboxed():
    print("== A. Node in the sandbox (RLIMIT_AS 2048 MB, no /proc) ==", flush=True)
    try:
        s = await Sandbox.create("node1", 60000, SandboxPolicy(), base_dir=BASE)
    except SandboxError as e:
        report("sandbox starts", False, e)
        return
    report("sandbox starts", True)
    try:
        async def env():
            v = await node(s, "env.mjs")
            report("node starts, no /proc", v["procStatus"] != "readable", v)

        async def startup():
            r = await s.run_command(f"a=$(date +%s%N) && {NODE} -e 0 && b=$(date +%s%N) && echo $(((b-a)/1000000))", 30)
            report("startup time (ms)", r["exit_code"] == 0, r["stdout"].strip() or r["stderr"])

        async def heap():
            v = await node(s, "heap.mjs", "768", env="NODE_OPTIONS=--max-old-space-size=1024")
            report("V8 heap 768 MB (max-old-space 1024)", v["ok"], v)

        async def buffer():
            v = await node(s, "buffer.mjs")
            report("Buffer 512 MB ok, 1536 MB refused cleanly", v["512"] == "ok" and v["1536"] != "ok", v)

        async def wasm():
            v = await node(s, "wasm.mjs")
            report("wasm instantiate + memories", all(x == "ok" or x.endswith("MB") for x in v.values()), v)

        async def offline_fetch():
            v = await node(s, "fetch.mjs", "https://example.com")
            report("fetch() without allowlist fails", "status" not in v, v)

        async def spawn():
            v = await node(s, "spawn.mjs")
            report("child_process: sh and python3", v == {"sh": "hi", "python": "42"}, v)

        async def sigint():
            v = await node(s, "sigint.mjs")
            report("self-SIGINT breaks sync loop", v["outcome"] == "ERR_SCRIPT_EXECUTION_INTERRUPTED", v)

        async def dynimport():
            v = await node(s, "dynimport.mjs")
            report("vm: dynamic import + globals persist", v.get("platform") == "linux" and v.get("kept") == 42, v)

        async def fd():
            r = await s.run_command(f"python3 -c '{FD_TEST}'", 30)
            out = r["stdout"].strip()
            report("socketpair fd 3 as net.Socket", out.startswith("ping") and '"got":"pong"' in out, out or r["stderr"][-200:])

        async def workers():
            # Each isolate reserves address space up front (CodeRange): under
            # RLIMIT_AS 2048 one Worker fits beside the main thread, two do not.
            one = await node(s, "workers.mjs", "1")
            report("1 worker thread under RLIMIT_AS 2048", one.get("results") == [0], one)
            r = await s.run_command(f"{NODE} {JS}/workers.mjs 2", 30)
            report("2 worker threads exceed RLIMIT_AS 2048 (expected)", r["exit_code"] != 0,
                   f"exit {r['exit_code']}: " + next((x for x in r["stderr"].splitlines() if "Fatal" in x), ""))

        for name, check in [("env", env), ("startup", startup), ("heap", heap), ("buffer", buffer),
                            ("wasm", wasm), ("offline fetch", offline_fetch), ("spawn", spawn),
                            ("sigint", sigint), ("dynamic import", dynimport), ("fd", fd), ("workers", workers)]:
            await step(name, check())
    finally:
        await s.destroy()

    print("\n== A2. fetch() through the egress proxy (allowlist example.com) ==", flush=True)
    events = []
    try:
        s = await Sandbox.create("node2", 60001, SandboxPolicy(allowlist=("example.com",)),
                                 base_dir=BASE, on_net_event=events.append)
    except SandboxError as e:
        report("sandbox with proxy starts", False, e)
        return
    try:
        async def proxied():
            plain = await node(s, "fetch.mjs", "https://example.com")
            report("fetch() ignores HTTPS_PROXY by default", "status" not in plain, plain)
            v = await node(s, "fetch.mjs", "https://example.com", env="NODE_USE_ENV_PROXY=1")
            report("NODE_USE_ENV_PROXY=1: allowlisted host", v.get("status") == 200, v)
            v = await node(s, "fetch.mjs", "https://example.org", env="NODE_USE_ENV_PROXY=1")
            report("NODE_USE_ENV_PROXY=1: other host refused", "status" not in v, v)

        await step("proxied fetch", proxied())
    finally:
        await s.destroy()


async def ha():
    print("\n== B. Home Assistant MCP Server and users ==", flush=True)
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    import websockets

    headers = {"Authorization": f"Bearer {TOKEN}"}
    for api in ("assist", "homeassistant"):
        async def tools(api=api):
            url = f"http://supervisor/core/api/mcp/{api}"
            async with streamablehttp_client(url, headers=headers) as (r, w, _):
                async with ClientSession(r, w) as cs:
                    await cs.initialize()
                    listed = (await cs.list_tools()).tools
            ro = [t.name for t in listed if t.annotations and t.annotations.readOnlyHint]
            report(f"/api/mcp/{api}: tools/list", bool(listed), f"{len(listed)} tools, {len(ro)} read-only")
            print(f"       names: {sorted(t.name for t in listed)}")
            print(f"       read-only: {sorted(ro)}", flush=True)

        await step(f"/api/mcp/{api}", tools())

    async def users():
        async with websockets.connect("ws://supervisor/core/websocket", max_size=None) as ws:
            json.loads(await ws.recv())
            await ws.send(json.dumps({"type": "auth", "access_token": TOKEN}))
            auth = json.loads(await ws.recv())
            if auth.get("type") != "auth_ok":
                raise RuntimeError(auth)
            await ws.send(json.dumps({"id": 1, "type": "config/auth/list"}))
            reply = json.loads(await ws.recv())
        if not reply.get("success"):
            raise RuntimeError(reply.get("error"))
        listed = reply["result"]
        report("config/auth/list", bool(listed), f"{len(listed)} users; fields {sorted(listed[0])}")
        for u in listed:  # no names: flags only
            flags = {k: u.get(k) for k in ("is_owner", "is_active", "system_generated", "group_ids", "local_only")}
            print(f"       {u.get('id', '')[:6]}… {flags}", flush=True)

    await step("config/auth/list", users())


async def main() -> int:
    print(f"kernel {platform.release()} {platform.machine()}\n", flush=True)
    await step("section A", sandboxed())
    if TOKEN and TOKEN != "local-test-token":
        await step("section B", ha())
    else:
        print("\n== B. skipped (no Supervisor token) ==")
    failed = results.count(False)
    print(f"\n== {len(results) - failed} passed, {failed} failed ==", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
