"""MCP smoke client, run inside the app container by scripts/smoke.sh."""

import asyncio
import json
import os
import sys
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = "http://127.0.0.1:8099/mcp"
# What Home Assistant gets through discovery (mcpauth): every request needs it.
AUTH = {"Authorization": "Bearer " + open("/data/mcp_token").read().strip()}
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


def audit_events():
    out = []
    for name in sorted(os.listdir("/data/audit")):
        with open(os.path.join("/data/audit", name)) as f:
            out += [json.loads(x) for x in f]
    return out


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


async def allowlist_mode(call) -> None:
    """App started with network_allowlist [pypi.org, *.pythonhosted.org]."""
    r = payload(await call("run_code", timeout_s=180,
                           code="await $`pip download -q --no-deps -d /tmp/dl requests && ls /tmp/dl`.text()"))
    check("pip download via proxy", (r.get("result") or "").startswith("requests-"), r)
    sid = r.get("session_id")
    probe = (
        "python3 - <<'EOF'\n"
        "import urllib.request, urllib.error, socket\n"
        "def get(u):\n"
        "    try: return urllib.request.urlopen(u, timeout=20).status\n"
        "    except urllib.error.URLError as e: return str(e.reason)\n"
        "def tcp(h, p):\n"
        "    try: socket.create_connection((h, p), timeout=3).close(); return 'open'\n"
        "    except OSError as e: return type(e).__name__\n"
        "print(repr((get('https://example.com/'), tcp('1.1.1.1', 443))))\n"
        "EOF")
    r = payload(await call("run_code", session_id=sid, code=f"(await $({json.dumps(probe)}).text()).trim()"))
    example, ip = eval(r["result"]) if r.get("result") else (None, None)
    check("example.com refused, direct IP blocked", "403" in str(example) and ip != "open", r.get("result"))
    r = payload(await call("run_code", session_id=sid, code="(await fetch('https://pypi.org/simple/requests/')).status"))
    check("fetch() in the REPL goes through the proxy", r.get("result") == "200", r)
    for _ in range(100):  # entries land when each tunnel closes
        ev = [e for e in audit_events() if e["event"] == "net.connect"]
        if {"pypi.org", "example.com"} <= {e["detail"]["host"] for e in ev}:
            break
        await asyncio.sleep(0.1)
    hosts = {(e["detail"]["host"], e["outcome"], e["session_id"] == sid) for e in ev}
    check("net.connect audited per session", ("pypi.org", "allowed", True) in hosts
          and ("example.com", "denied", True) in hosts, sorted(hosts))
    viol = [e for e in audit_events() if e["event"] == "policy.violation" and e["detail"].get("kind") == "egress"]
    check("egress denial audited as policy.violation", bool(viol), viol[:1])


SIDS = "/data/smoke-sids.json"  # survives the container restart (volume)


async def open_two(call) -> None:
    sids = []
    for _ in range(2):
        r = payload(await call("run_code", code="require('child_process').spawn('sleep', ['600'], {stdio: 'ignore'}).unref(); x = 1"))
        sids.append(r.get("session_id"))
    check("two sessions with background processes", all(sids) and procs_of(60000) + procs_of(60001) > 0, sids)
    with open(SIDS, "w") as f:
        json.dump(sids, f)


async def after_kill(call) -> None:
    with open(SIDS) as f:
        old = json.load(f)
    r = payload(await call("list_sessions"))
    check("after kill+restart: no sessions", r["sessions"] == [], r)
    left = sum(procs_of(u) for u in range(59999, 60010))
    check("after kill+restart: no sandbox processes", left == 0, left)
    check("after kill+restart: no session dirs", os.listdir("/var/cache/code-interpreter") == [],
          os.listdir("/var/cache/code-interpreter"))
    r = payload(await call("run_code", code="x", session_id=old[0]))
    check("old session id -> session_not_found", r.get("error") == "session_not_found", r)


async def ha_like_long_call() -> None:
    """Home Assistant's MCP client uses httpx's default 5 s read timeout and a
    30 s cap per call: a call quiet for 5 s used to fail with "SSE stream
    ended without a response"."""
    import httpx
    from mcp.client.streamable_http import streamable_http_client

    async with httpx.AsyncClient(headers=AUTH) as http, streamable_http_client(url=URL, http_client=http) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            try:
                async with asyncio.timeout(30):  # HA's per-call cap
                    res = payload(await s.call_tool("run_code", {"code": "await new Promise((r) => setTimeout(r, 8000)); 'slept'"}))
            except Exception as e:  # noqa: BLE001
                res = {"error": f"{type(e).__name__}: {e}"}
            check("8 s call through a 5 s read timeout (HA client)", res.get("result") == "slept", res)
            if res.get("session_id"):
                await s.call_tool("close_session", {"session_id": res["session_id"]})


def ingress_ui(sid: str) -> None:
    """Ingress UI on :8098 (loopback is allowed; so is HA's Ingress proxy)."""
    import socket
    import urllib.error
    import urllib.request

    def req(url, method="GET", headers=None):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, method=method, headers=headers or {}), timeout=10) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    base = "http://127.0.0.1:8098"
    status, page = req(f"{base}/")
    check("ingress UI page", status == 200 and "<title>Code Interpreter</title>" in page, status)
    status, body = req(f"{base}/api/sessions")
    live = json.loads(body).get("sessions", []) if status == 200 else []
    check("ingress UI lists live sessions", sid in [s["session_id"] for s in live], body[:120])
    status, body = req(f"{base}/api/audit/days")
    days = json.loads(body).get("days", []) if status == 200 else []
    status, body = req(f"{base}/api/audit/sessions?day={days[0] if days else ''}")
    check("ingress UI audit summary", status == 200 and sid in body, body[:120])
    status, _ = req(f"{base}/api/sessions/{sid}/close", "POST")
    check("ingress UI close without header refused", status == 403, status)
    status, body = req(f"{base}/api/sessions/{sid}/close", "POST",
                       {"X-Requested-With": "code-interpreter-ui", "X-Remote-User-Name": "smoke"})
    check("ingress UI closes a session", status == 200, body)
    ui_events = [e for e in audit_events() if e["event"] == "ui.close_session"]
    check("UI close is audited with the user", ui_events and ui_events[-1]["detail"].get("user") == "smoke", ui_events[-1:])
    own_ip = socket.gethostbyname(socket.gethostname())
    status, _ = req(f"http://{own_ip}:8098/api/sessions")
    check(f"ingress UI refuses a non-Ingress client ({own_ip})", status == 403, status)


def refuses_without_token() -> None:
    import urllib.error
    import urllib.request

    for headers in ({}, {"Authorization": "Bearer wrong"}):
        try:
            urllib.request.urlopen(urllib.request.Request(URL, method="POST", headers=headers, data=b"{}"), timeout=10)
            status = 200
        except urllib.error.HTTPError as e:
            status = e.code
        check(f"MCP refuses {'a wrong' if headers else 'no'} token", status == 401, status)


async def main(idle_wait_s: int, mode: str) -> int:
    if mode == "default":
        refuses_without_token()
        await ha_like_long_call()
    async with streamablehttp_client(URL, headers=AUTH) as (read, write, _):
        async with ClientSession(read, write) as s:
            await s.initialize()
            call = lambda name, **args: s.call_tool(name, args)  # noqa: E731
            if mode != "default":
                await {"allowlist": allowlist_mode, "open2": open_two, "after_kill": after_kill}[mode](call)
                return 1 if fails else 0

            import subprocess  # noqa: PLC0415

            p = subprocess.run(["/usr/local/bin/hab", "--json", "--skip-update-check", "--config", "/tmp/hab-smoke",
                                "schema", "--index", "--search", "automation update", "--limit", "5"],
                               capture_output=True, text=True, timeout=30)
            found = {c["path"]: c["side_effect"] for c in json.loads(p.stdout or "{}").get("data", {}).get("commands", [])}
            check("hab binary runs and lists its commands", found.get("hab automation update") == "write", found or p.stdout[-200:])

            names = sorted(t.name for t in (await s.list_tools()).tools)
            check("tools/list", names == ["close_session", "list_sessions", "run_code"], names)

            r1 = payload(await call("run_code", code="x = 20"))
            sid = r1.get("session_id")
            r2 = payload(await call("run_code", code="x + 1", session_id=sid))
            check("run_code keeps variables", r2.get("result") == "21" and r2.get("session_id") == sid, r2)

            pandas = "python3 -c \"import pandas as pd; print(pd.DataFrame({'a': [1, 2]}).a.sum())\""
            r = payload(await call("run_code", session_id=sid, code=f"(await $({json.dumps(pandas)}).text()).trim()"))
            check("analysis stack (python3 through $)", r.get("result") == "3", r)

            r = payload(await call("run_code", session_id=sid, code="(await $`echo hi; exit 2`.nothrow()).exitCode"))
            check("$ hands back a failing exit with nothrow", r.get("result") == "2", r)

            r = payload(await call("run_code", code="1", session_id="deadbeefdeadbeef"))
            check("unknown session -> session_not_found", r.get("error") == "session_not_found", r)

            r = payload(await call("list_sessions"))
            check("list_sessions", [x["session_id"] for x in r["sessions"]] == [sid], r)
            ui_sid = payload(await call("run_code", code="1"))["session_id"]
            await asyncio.to_thread(ingress_ui, ui_sid)

            # /share round trip (T7): smoke.sh puts energy.csv into /share.
            r = payload(await call("run_code", session_id=sid, code="(await share.import('energy.csv')).path"))
            check("share.import", r.get("result") == "/sandbox/energy.csv", r)
            r = payload(await call("run_code", session_id=sid, code=(
                "const PY = `import pandas as pd, matplotlib.pyplot as plt\n"
                "df = pd.read_csv('energy.csv'); df.kwh.plot(); plt.title('전력'); plt.savefig('plot.png')\n"
                "print(df.kwh.mean())`;\n"
                "const p = require('child_process').spawnSync('python3', ['-c', PY], {encoding: 'utf8'});\n"
                "console.error(p.stderr); p.stdout.trim()")))
            check("run_code runs python3 on it and reports new_files",
                  r.get("result") == "2.0" and r.get("new_files") == ["/sandbox/plot.png"], r)
            check("Korean title renders (no missing-glyph warning)", "Glyph" not in r.get("logs", "x"), r.get("logs"))
            r = payload(await call("run_code", session_id=sid, code="(await share.export('plot.png')).share_path"))
            out = r.get("result") or ""
            check("share.export", out == f"/share/code-interpreter/{sid}/plot.png" and os.path.getsize(out) > 0, r)
            r = payload(await call("run_code", session_id=sid, code=(
                "const listed = await share.list();\n"
                "const got = await share.import('energy.csv', 'via-cell.csv');\n"
                "const out = await share.export('via-cell.csv');\n"
                "({listed: listed.entries.some((e) => e.name === 'energy.csv'), got: got.path, out: out.share_path,\n"
                "  refused: await share.import('../etc/passwd').catch((e) => e.name)})")))
            res = json.loads(r["result"]) if r.get("result") else {}
            check("cell share.list/import/export", res.get("listed") is True and res.get("got") == "/sandbox/via-cell.csv"
                  and res.get("out") == f"/share/code-interpreter/{sid}/via-cell.csv" and res.get("refused") == "ShareError", r)
            r = payload(await call("run_code", session_id=sid, code=(
                "[await ha.tools().catch((e) => e.name), typeof ha.admin]")))
            check("ha.* without Home Assistant: HaUnavailable, no ha.admin", r.get("result") == '["HaUnavailable","undefined"]', r)

            # Audit (T9): events recorded, execution output never stored.
            r = payload(await call("run_code", session_id=sid, code="console.log('OUT' + 'PUT-MARKER-7')"))
            check("marker printed", r.get("logs") == "OUTPUT-MARKER-7\n", r)
            ev = audit_events()
            names = {e["event"] for e in ev}
            want = {"session.create", "code.exec", "share.list", "file.import", "file.export", "policy.violation"}
            check("audit log has the expected events", want <= names, sorted(names))
            raw = "".join(open(os.path.join("/data/audit", n)).read() for n in os.listdir("/data/audit"))
            check("audit log holds no execution output", "OUTPUT-MARKER-7" not in raw and "np.float64" not in raw)

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
    sys.exit(asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 0,
                              sys.argv[2] if len(sys.argv) > 2 else "default")))
