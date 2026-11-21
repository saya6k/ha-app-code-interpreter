"""MCP smoke client, run inside the app container by scripts/smoke.sh."""

import asyncio
import json
import os
import sys
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = "http://127.0.0.1:8099/mcp"
fails = 0


def check(name, ok, detail=""):
    global fails
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'} | {name:<40} | {str(detail)[:140]}", flush=True)


def payload(r):
    if r.structuredContent is not None:
        sc = r.structuredContent
        return sc.get("result", sc) if set(sc) == {"result"} else sc
    return json.loads(r.content[0].text)


def procs_of(uid):
    n = 0
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            status = open(f"/proc/{pid}/status").read()
        except OSError:
            continue
        line = next(x for x in status.splitlines() if x.startswith("Uid:"))
        n += int(line.split()[1]) == uid
    return n


async def main(idle_wait_s: int) -> int:
    async with streamablehttp_client(URL) as (read, write, _):
        async with ClientSession(read, write) as s:
            await s.initialize()
            call = lambda name, **args: s.call_tool(name, args)  # noqa: E731

            names = sorted(t.name for t in (await s.list_tools()).tools)
            check("tools/list", names == ["close_session", "list_sessions", "run_code", "run_command"], names)

            r1 = payload(await call("run_code", code="x = 20"))
            sid = r1.get("session_id")
            r2 = payload(await call("run_code", code="x + 1", session_id=sid))
            check("run_code keeps variables", r2.get("result") == "21" and r2.get("session_id") == sid, r2)

            r = payload(await call("run_code", code="import pandas as pd; pd.DataFrame({'a': [1, 2]}).a.sum()", session_id=sid))
            check("analysis stack", r.get("result") in ("3", "np.int64(3)"), r)

            r = payload(await call("run_command", command="echo hi; exit 2", session_id=sid))
            check("run_command", (r.get("stdout"), r.get("exit_code")) == ("hi\n", 2), r)

            r = payload(await call("run_code", code="1", session_id="deadbeefdeadbeef"))
            check("unknown session -> session_not_found", r.get("error") == "session_not_found", r)

            r = payload(await call("list_sessions"))
            check("list_sessions", [x["session_id"] for x in r["sessions"]] == [sid], r)

            if idle_wait_s:
                deadline = time.time() + idle_wait_s
                while time.time() < deadline and payload(await call("list_sessions"))["sessions"]:
                    await asyncio.sleep(5)
                left = payload(await call("list_sessions"))["sessions"]
                await asyncio.sleep(1)
                check(f"idle expiry within {idle_wait_s}s", not left and procs_of(60000) == 0
                      and not os.listdir("/var/cache/code-interpreter"), left)
                r = payload(await call("run_code", code="x", session_id=sid))
                check("expired session -> session_not_found", r.get("error") == "session_not_found", r)

            r = payload(await call("run_code", code="y = 1"))
            check("session open for shutdown test", "session_id" in r, r)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 0)))
