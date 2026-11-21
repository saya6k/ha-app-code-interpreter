"""Checkpoint A' on HAOS: the real Sandbox code under the real AppArmor profile.

Prints environment facts and a PASS/FAIL table. Copy the whole log back.
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


IDENTITY = """
import ctypes, os, socket
class H(ctypes.Structure): _fields_=[('v',ctypes.c_uint32),('pid',ctypes.c_int)]
class D(ctypes.Structure): _fields_=[('e',ctypes.c_uint32),('p',ctypes.c_uint32),('i',ctypes.c_uint32)]
h=H(0x20080522,0); d=(D*2)(); ctypes.CDLL(None).capget(ctypes.byref(h),d)
try:
    os.unshare(os.CLONE_NEWUSER); userns='allowed'
except PermissionError:
    userns='blocked'
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close(); return 'open'
    except OSError as e:
        return type(e).__name__
try:
    socket.getaddrinfo('example.com', 443); dns='resolved'
except OSError:
    dns='failed'
(os.getuid(), [x.e|x.p for x in d], userns, 'SUPERVISOR_TOKEN' in os.environ,
 os.path.exists('/data') or os.path.exists('/share'),
 [n for _, n in socket.if_nameindex()], tcp('1.1.1.1', 443), tcp('{gw}', 80), tcp('{gw}', 8123), dns)
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


async def isolated():
    print("== sandbox, no allowlist ==", flush=True)
    try:
        s = await Sandbox.create("check1", 60000, SandboxPolicy(), base_dir=BASE)
    except SandboxError as e:
        report("sandbox starts (bwrap + AppArmor + seccomp)", False, e)
        return
    report("sandbox starts (bwrap + AppArmor + seccomp)", True)
    try:
        await s.run_code("x = 20", timeout_s=30)
        r = await s.run_code("x + 1", timeout_s=30)
        report("variables persist", r["result"] == "21", r["result"] or r["stderr"])

        r = await s.run_code(IDENTITY.replace("{gw}", gateway()), timeout_s=60)
        if r["error"]:
            report("identity probe runs", False, r["stderr"])
        else:
            uid, caps, userns, token, data, ifaces, ip, gw80, gw8123, dns = eval(r["result"])
            report("runs as 65534 with no capabilities", uid == 65534 and caps == [0, 0], (uid, caps))
            report("nested user namespace blocked (seccomp)", userns == "blocked", userns)
            report("SUPERVISOR_TOKEN, /data, /share hidden", not token and not data)
            report("only loopback interface", ifaces == ["lo"], ifaces)
            report("no IP egress, HA host, or DNS", "open" not in (ip, gw80, gw8123) and dns == "failed",
                   (ip, gw80, gw8123, dns))

        r = await s.run_code("b = bytearray(2 * 1024**3)", timeout_s=30)
        report("2 GB allocation -> MemoryError", r["error"] == "MemoryError", r["error"])
        r = await s.run_code("while True: pass", timeout_s=1)
        report("timeout interrupts, variables kept", r["error"] == "TimeoutError" and not r["kernel_restarted"]
               and (await s.run_code("x", timeout_s=10))["result"] == "20", r)
        r = await s.run_code("import os; os._exit(1)", timeout_s=10)
        report("crash restarts kernel", r["kernel_restarted"] and (await s.run_code("1", timeout_s=30))["result"] == "1")
        r = await s.run_command("echo hi; exit 3", timeout_s=30)
        report("run_command", (r["stdout"], r["exit_code"]) == ("hi\n", 3), r)
    finally:
        await s.destroy()
    await asyncio.sleep(0.5)  # let init reap the inner bwrap
    report("destroy leaves no process or directory", not procs_of(60000) and not s.dir.exists(), procs_of(60000))


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
        r = await s.run_code(FETCH, timeout_s=60)
        if r["error"]:
            report("fetch probe runs", False, r["stderr"])
            return
        pypi, example = eval(r["result"])
        report("pypi.org reachable through proxy", pypi == 200, pypi)
        report("example.com refused", "403" in str(example), example)
        await asyncio.sleep(0.5)
        hosts = {(e["host"], e["allowed"], e["session_id"]) for e in events}
        report("connections logged per session", {("pypi.org", True, "check2"), ("example.com", False, "check2")} <= hosts,
               sorted(hosts))
    finally:
        await s.destroy()


async def main():
    print("== environment ==")
    print(f"kernel     {platform.release()} {platform.machine()}")
    print(f"apparmor   {read('/proc/self/attr/current')}")
    print(f"CapEff     {status('CapEff')}   Seccomp {status('Seccomp')}   NoNewPrivs {status('NoNewPrivs')}")
    print(flush=True)
    await isolated()
    await allowlisted()
    failed = results.count(False)
    print(f"\n== {len(results) - failed} passed, {failed} failed ==", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
