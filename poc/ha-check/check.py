"""Checkpoint A' on HAOS: the real Sandbox code under the real AppArmor profile.

Prints environment facts and a PASS/FAIL table, and exits 1 if anything
failed. Copy the whole log back.
"""

import asyncio
import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, "/opt/mcp-server")

from policy import SandboxPolicy  # noqa: E402
from sandbox import Sandbox, SandboxError  # noqa: E402

BASE = Path("/tmp/ci-check")
results = []


def report(name, ok, detail=""):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'} | {name:<44} | {str(detail)[:150]}", flush=True)


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError as e:
        return f"<{e.strerror}>"


def status(key):
    return next((x.split(":", 1)[1].strip() for x in read("/proc/self/status").splitlines() if x.startswith(key + ":")), "?")


def procs_of(uid):
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        s = read(f"/proc/{pid}/status")
        uid_line = next((x for x in s.splitlines() if x.startswith("Uid:")), None)
        if uid_line and int(uid_line.split()[1]) == uid:
            out.append(pid)
    return out


def gateway():
    for line in read("/proc/net/route").splitlines()[1:]:
        f = line.split()
        if f[1] == "00000000":
            return ".".join(str(int(f[2][i : i + 2], 16)) for i in (6, 4, 2, 0))
    return "172.30.32.1"


async def step(name, coro):
    """Run one check; an unexpected error fails it without stopping the rest."""
    try:
        await coro
    except Exception as e:
        report(name, False, f"{type(e).__name__}: {e}")


async def result_of(s, src, timeout_s=60):
    r = await s.run_code(src, timeout_s=timeout_s)
    if r["error"]:
        raise RuntimeError(f"{r['error']}: {r['stderr'].strip().splitlines()[-1:] or ''}")
    return eval(r["result"])


# The REPL is multithreaded, where the kernel refuses unshare(CLONE_NEWUSER)
# with EINVAL regardless of seccomp. Ask a single-threaded child instead, so
# 'allowed' really means allowed and EPERM can only come from the filter.
USERNS = """
import subprocess, sys
p = subprocess.run([sys.executable, '-c', 'import os; os.unshare(os.CLONE_NEWUSER)'],
                   capture_output=True, text=True)
'allowed' if p.returncode == 0 else ('blocked' if 'PermissionError' in p.stderr
                                     else p.stderr.strip().splitlines()[-1])
"""

IDENTITY = """
import ctypes, os, socket
class H(ctypes.Structure): _fields_=[('v',ctypes.c_uint32),('pid',ctypes.c_int)]
class D(ctypes.Structure): _fields_=[('e',ctypes.c_uint32),('p',ctypes.c_uint32),('i',ctypes.c_uint32)]
h=H(0x20080522,0); d=(D*2)(); ctypes.CDLL(None).capget(ctypes.byref(h),d)
(os.getuid(), [x.e|x.p for x in d], [n for _, n in socket.if_nameindex()])
"""

# What the app container has and the sandbox must not: env names, the app's
# own options file, /share (mapped like the real app), the MCP server code.
LEAKS = """
import os
seen = [k for k in os.environ if 'TOKEN' in k or 'SUPERVISOR' in k or 'HASSIO' in k]
seen += [p for p in ('/data/options.json', '/data', '/share', '/opt/mcp-server') if os.path.exists(p)]
seen
"""

NETWORK = """
import socket
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close(); return 'open'
    except OSError as e:
        return type(e).__name__
try:
    socket.getaddrinfo('example.com', 443); dns='resolved'
except OSError:
    dns='failed'
(tcp('1.1.1.1', 443), tcp('{gw}', 80), tcp('{gw}', 8123), dns)
"""

FETCH = """
import urllib.request, urllib.error
def get(url):
    try:
        return urllib.request.urlopen(url, timeout=20).status
    except urllib.error.URLError as e:
        return str(e.reason)
(get('https://pypi.org/simple/requests/'), get('https://example.com/'))
"""


async def check_destroyed(s, uid):
    await s.destroy()
    await asyncio.sleep(0.5)  # let init reap the inner bwrap
    left = procs_of(uid)
    report(f"destroy leaves nothing behind (uid {uid})", not left and not s.dir.exists(),
           {"procs": left, "dir": s.dir.exists()})


async def isolated():
    print("== sandbox, no allowlist ==", flush=True)
    report("precondition: app itself sees /share and /data/options.json",
           Path("/share").is_dir() and Path("/data/options.json").exists())
    try:
        s = await Sandbox.create("check1", 60000, SandboxPolicy(), base_dir=BASE)
    except SandboxError as e:
        report("sandbox starts (bwrap + AppArmor + seccomp)", False, e)
        return
    report("sandbox starts (bwrap + AppArmor + seccomp)", True)
    try:
        async def persist():
            await s.run_code("x = 20", timeout_s=30)
            r = await s.run_code("x + 1", timeout_s=30)
            report("variables persist", r["result"] == "21", r["result"] or r["stderr"])

        async def identity():
            uid, caps, ifaces = await result_of(s, IDENTITY)
            report("runs as 65534 with no capabilities", uid == 65534 and caps == [0, 0], (uid, caps))
            report("only loopback interface", ifaces == ["lo"], ifaces)

        async def userns():
            v = await result_of(s, USERNS)
            report("nested user namespace blocked (seccomp)", v == "blocked", v)

        async def leaks():
            seen = await result_of(s, LEAKS)
            report("no token env, /data, /share, app code", seen == [], seen)

        async def network():
            v = await result_of(s, NETWORK.replace("{gw}", gateway()))
            report("no IP egress, HA host, or DNS", "open" not in v[:3] and v[3] == "failed", v)

        async def memory():
            r = await s.run_code("b = bytearray(2 * 1024**3)", timeout_s=30)
            report("2 GB allocation -> MemoryError", r["error"] == "MemoryError", r["error"])

        async def interrupt():
            r = await s.run_code("while True: pass", timeout_s=1)
            kept = (await s.run_code("x", timeout_s=10))["result"]
            report("timeout interrupts, variables kept",
                   r["error"] == "TimeoutError" and not r["kernel_restarted"] and kept == "20", (r["error"], kept))

        async def crash():
            r = await s.run_code("import os; os._exit(1)", timeout_s=10)
            after = (await s.run_code("1", timeout_s=30))["result"]
            report("crash restarts kernel", r["kernel_restarted"] and after == "1", (r["error"], after))

        async def command():
            r = await s.run_command("echo hi; exit 3", timeout_s=30)
            report("run_command", (r["stdout"], r["exit_code"]) == ("hi\n", 3), r)

        for name, fn in [("variables persist", persist), ("identity probe", identity),
                         ("userns probe", userns), ("leak probe", leaks), ("network probe", network),
                         ("memory probe", memory), ("interrupt probe", interrupt),
                         ("crash probe", crash), ("run_command probe", command)]:
            await step(name, fn())
    finally:
        await step("destroy", check_destroyed(s, 60000))


async def allowlisted():
    print("== sandbox, allowlist pypi.org ==", flush=True)
    events = []
    try:
        s = await Sandbox.create("check2", 60001, SandboxPolicy(allowlist=("pypi.org",)),
                                 base_dir=BASE, on_net_event=events.append)
    except SandboxError as e:
        report("sandbox with proxy starts", False, e)
        return
    try:
        async def fetch():
            pypi, example = await result_of(s, FETCH)
            report("pypi.org reachable through proxy", pypi == 200, pypi)
            report("example.com refused", "403" in str(example), example)
            for _ in range(100):  # entries land when each tunnel closes (<= 5 s drain)
                if {"pypi.org", "example.com"} <= {e["host"] for e in events}:
                    break
                await asyncio.sleep(0.1)
            hosts = {(e["host"], e["allowed"], e["session_id"]) for e in events}
            report("connections logged per session",
                   {("pypi.org", True, "check2"), ("example.com", False, "check2")} <= hosts, sorted(hosts))

        await step("fetch probe", fetch())
    finally:
        sock = s.proxy_dir / "proxy.sock"
        await step("destroy", check_destroyed(s, 60001))
        report("proxy socket removed", not sock.exists())


async def main() -> int:
    print("== environment ==")
    print(f"kernel     {platform.release()} {platform.machine()}")
    print(f"apparmor   {read('/proc/self/attr/current')}")
    print(f"CapEff     {status('CapEff')}   Seccomp {status('Seccomp')}   NoNewPrivs {status('NoNewPrivs')}")
    print(flush=True)
    await step("no-allowlist section", isolated())
    await step("allowlist section", allowlisted())
    failed = results.count(False)
    print(f"\n== {len(results) - failed} passed, {failed} failed ==", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
