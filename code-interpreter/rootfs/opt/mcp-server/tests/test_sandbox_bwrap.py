"""Sandbox against real bubblewrap. Runs inside the app image only:

    scripts/test-sandbox.sh   (linux-test / CI; container runs seccomp=unconfined)
"""

import asyncio
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from policy import SANDBOX_ROOT, SandboxPolicy
from sandbox import Sandbox, SandboxError

pytestmark = pytest.mark.skipif(
    not (SANDBOX_ROOT.is_dir() and shutil.which("bwrap") and os.geteuid() == 0),
    reason="needs the app image (bwrap, /opt/sandbox-root, root)",
)

UID = 60000


def procs_of(uid: int, states: bool = False) -> list:
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            status = Path(f"/proc/{pid}/status").read_text()
        except OSError:
            continue
        fields = dict(x.split(":", 1) for x in status.splitlines() if ":" in x)
        if int(fields["Uid"].split()[0]) == uid:
            out.append((int(pid), fields["Name"].strip(), fields["State"].split()[0]) if states else int(pid))
    return out


class Harness:
    def __init__(self, policy=SandboxPolicy(), **kw) -> None:
        self.loop = asyncio.new_event_loop()
        self.base = Path(tempfile.mkdtemp(prefix="sbx-"))
        self.policy = policy
        self.kw = kw

    def do(self, coro):
        return self.loop.run_until_complete(coro)

    def create(self, sid="t1", uid=UID) -> Sandbox:
        return self.do(Sandbox.create(sid, uid, self.policy, base_dir=self.base, **self.kw))

    def close(self) -> None:
        self.loop.close()
        shutil.rmtree(self.base, ignore_errors=True)


@pytest.fixture
def h():
    os.environ["SUPERVISOR_TOKEN"] = "must-not-leak"
    harness = Harness()
    yield harness
    harness.close()


@pytest.fixture
def sbx(h):
    s = h.create()
    yield s
    h.do(s.destroy())


def code(h, s, src, timeout=60):
    return h.do(s.run_code(src, timeout_s=timeout))


def test_variables_persist_and_last_expression_is_returned(h, sbx):
    assert code(h, sbx, "x = 21")["error"] is None
    r = code(h, sbx, "x * 2")
    assert r["result"] == "42" and r["kernel_restarted"] is False


def test_identity_capabilities_env_and_network(h, sbx):
    r = code(h, sbx, """
import ctypes, os, socket
class H(ctypes.Structure): _fields_=[('v',ctypes.c_uint32),('pid',ctypes.c_int)]
class D(ctypes.Structure): _fields_=[('e',ctypes.c_uint32),('p',ctypes.c_uint32),('i',ctypes.c_uint32)]
h=H(0x20080522,0); d=(D*2)(); assert ctypes.CDLL(None).capget(ctypes.byref(h),d)==0
(os.getuid(), os.getgid(), [x.e|x.p for x in d], sorted(os.environ),
 [n for _, n in socket.if_nameindex()], os.path.exists('/proc/self'),
 os.path.exists('/data') or os.path.exists('/share') or os.path.exists('/opt/mcp-server'))
""")
    assert r["error"] is None, r["stderr"]
    uid, gid, caps, env, ifaces, has_proc, sees_app = eval(r["result"])
    assert (uid, gid) == (65534, 65534)
    assert caps == [0, 0]
    assert "SUPERVISOR_TOKEN" not in env and "REPL_FD" in env
    assert ifaces == ["lo"]
    assert has_proc is False and sees_app is False


def test_filesystem_rw_only_in_sandbox_and_tmp(h, sbx):
    r = code(h, sbx, """
import os
ok = []
for p in ('/sandbox/a.txt', '/tmp/b.txt', '/usr/c.txt', '/opt/ci/d.txt', '/run/ci/e.txt'):
    try:
        open(p, 'w').write('x'); ok.append(p)
    except OSError:
        pass
ok
""")
    assert eval(r["result"]) == ["/sandbox/a.txt", "/tmp/b.txt"]
    assert (sbx.work / "a.txt").read_text() == "x"


def test_seccomp_blocks_nested_userns_but_threads_and_processes_work(h, sbx):
    r = code(h, sbx, """
import os, ctypes, errno, threading, subprocess, sys, multiprocessing as m
# The REPL is multithreaded, where unshare(CLONE_NEWUSER) fails with EINVAL
# regardless of seccomp; only a single-threaded child shows the filter.
p = subprocess.run([sys.executable, '-c', 'import os; os.unshare(os.CLONE_NEWUSER)'],
                   capture_output=True, text=True)
userns = 'allowed' if p.returncode == 0 else ('blocked' if 'PermissionError' in p.stderr else p.stderr)
libc = ctypes.CDLL(None, use_errno=True)
keyctl_nr = {'x86_64': 250, 'aarch64': 219}[os.uname().machine]
libc.syscall(keyctl_nr, 0, 0, 0, 0, 0)
t = threading.Thread(target=lambda: None); t.start(); t.join()
with m.Pool(2) as p: pool = p.map(abs, [-1, -2])
(userns, errno.errorcode[ctypes.get_errno()], pool)
""")
    assert r["error"] is None, r["stderr"]
    assert eval(r["result"]) == ("blocked", "EPERM", [1, 2])


def test_memory_limit_raises_memoryerror(h, sbx):
    r = code(h, sbx, "b = bytearray(2 * 1024**3)")
    assert r["error"] == "MemoryError"
    assert code(h, sbx, "1")["result"] == "1"


def test_fork_flood_is_stopped(h, sbx):
    r = code(h, sbx, """
import subprocess
ps = []
try:
    for _ in range(300): ps.append(subprocess.Popen(['sleep', '30']))
except OSError:
    pass
n = len(ps)
for p in ps: p.kill(); p.wait()
n
""")
    assert int(r["result"]) < 130


def test_analysis_stack_with_threads_under_nproc_limit(h, sbx):
    r = code(h, sbx, """
from sklearn.ensemble import RandomForestClassifier as R
from sklearn.datasets import make_classification as m
import numpy as np, matplotlib.pyplot as plt
X, y = m(300); R(20, n_jobs=2).fit(X, y)
np.linalg.inv(np.eye(300) * 2)
plt.plot([1, 2]); plt.title('한글'); plt.savefig('/sandbox/p.png')
'ok'
""", timeout=120)
    assert r["result"] == "'ok'", r["stderr"]
    assert (sbx.work / "p.png").stat().st_size > 0


def test_timeout_interrupt_keeps_variables(h, sbx):
    code(h, sbx, "keep = 7")
    r = code(h, sbx, "while True: pass", timeout=1)
    assert r["error"] == "TimeoutError" and r["kernel_restarted"] is False
    assert code(h, sbx, "keep")["result"] == "7"


def test_stuck_kernel_is_restarted_keeping_files(h, sbx):
    code(h, sbx, "lost = 1; open('/sandbox/kept.txt', 'w').write('y')")
    r = code(h, sbx, "import signal\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\nwhile True: pass", timeout=1)
    assert r["error"] == "TimeoutError" and r["kernel_restarted"] is True
    assert code(h, sbx, "lost")["error"] == "NameError"
    assert code(h, sbx, "open('/sandbox/kept.txt').read()")["result"] == "'y'"


def test_crash_restarts_kernel(h, sbx):
    r = code(h, sbx, "import os; os._exit(3)")
    assert r["error"] == "KernelDied" and r["kernel_restarted"] is True
    assert code(h, sbx, "2")["result"] == "2"


def test_reset_clears_variables(h, sbx):
    code(h, sbx, "gone = 1")
    h.do(sbx.run_code("", timeout_s=10, reset=True))
    assert code(h, sbx, "gone")["error"] == "NameError"


def test_run_command_shares_files_and_reports_exit(h, sbx):
    code(h, sbx, "open('/sandbox/f.txt', 'w').write('hi')")
    r = h.do(sbx.run_command("cat f.txt; echo err >&2; exit 3", timeout_s=30))
    assert (r["stdout"], r["stderr"], r["exit_code"], r["error"]) == ("hi", "err\n", 3, None)


def test_run_command_timeout_and_output_cap(h, sbx):
    r = h.do(sbx.run_command("yes | head -c 100000; sleep 30", timeout_s=2))
    assert r["error"] == "TimeoutError"
    assert len(r["stdout"]) == 16000 and r["truncated"] is True


def test_destroy_leaves_no_process_or_directory(h):
    s = h.create()
    code(h, s, "import subprocess; subprocess.Popen(['sleep', '300'])")
    assert procs_of(UID)
    h.do(s.destroy())
    assert procs_of(UID) == [], procs_of(UID, states=True)
    assert not s.dir.exists()


def test_fail_closed_when_sandbox_cannot_start(h):
    broken = Harness(root=Path(tempfile.mkdtemp(prefix="empty-root-")))
    try:
        with pytest.raises(SandboxError):
            broken.create(sid="bad")
        assert procs_of(UID) == []
        assert not (broken.base / "bad").exists()
    finally:
        broken.close()


# ---- network (SPEC Success Criteria 2, 3) ---------------------------------

def gateway() -> str:
    """Default gateway of the app container: the HA host (172.30.32.1) on HAOS."""
    for line in Path("/proc/net/route").read_text().splitlines()[1:]:
        f = line.split()
        if f[1] == "00000000":
            return ".".join(str(int(f[2][i : i + 2], 16)) for i in (6, 4, 2, 0))
    raise RuntimeError("no default route")


PROBE = """
import os, socket
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close(); return 'open'
    except OSError as e:
        return type(e).__name__
try:
    socket.getaddrinfo('example.com', 443); dns = 'resolved'
except OSError:
    dns = 'failed'
(tcp('1.1.1.1', 443), tcp('{gw}', 80), tcp('{gw}', 8099), dns,
 os.path.exists('/run/ci/proxy.sock'), 'HTTPS_PROXY' in os.environ)
"""


def test_no_allowlist_means_no_network_at_all(h, sbx):
    r = code(h, sbx, PROBE.format(gw=gateway()))
    assert r["error"] is None, r["stderr"]
    ip, gw80, gw8099, dns, has_sock, has_env = eval(r["result"])
    assert "open" not in (ip, gw80, gw8099)
    assert dns == "failed" and has_sock is False and has_env is False
    r = code(h, sbx, "import socket\ntry:\n socket.create_connection(('127.0.0.1', 3128), 2); e = None\nexcept OSError as x: e = type(x).__name__\ne")
    assert r["result"] == "'ConnectionRefusedError'"


@pytest.fixture
def net():
    events = []
    harness = Harness(
        SandboxPolicy(allowlist=("pypi.org", "*.pythonhosted.org")),
        on_net_event=events.append,
    )
    s = harness.create(sid="net1")
    yield harness, s, events
    harness.do(s.destroy())
    harness.close()


def test_allowlist_reaches_only_listed_hosts_through_the_proxy(net):
    h, s, events = net
    r = code(h, s, PROBE.format(gw=gateway()))
    ip, gw80, gw8099, dns, has_sock, has_env = eval(r["result"])
    assert "open" not in (ip, gw80, gw8099)
    assert dns == "failed" and has_sock is True and has_env is True

    r = code(h, s, """
import urllib.request, urllib.error
def get(url):
    try:
        return urllib.request.urlopen(url, timeout=20).status
    except urllib.error.URLError as e:
        return str(e.reason)
(get('https://pypi.org/simple/requests/'), get('https://example.com/'))
""")
    assert r["error"] is None, r["stderr"]
    pypi, example = eval(r["result"])
    assert pypi == 200
    assert "403" in example

    # A keep-alive upstream holds the tunnel for up to DRAIN_AFTER_CLIENT_EOF_S
    # after the client is done; the log entry is written when it closes.
    for _ in range(100):
        if {"pypi.org", "example.com"} <= {e["host"] for e in events}:
            break
        h.do(asyncio.sleep(0.1))
    by_host = {e["host"]: e for e in events}
    assert by_host["pypi.org"]["allowed"] is True and by_host["pypi.org"]["bytes_down"] > 0
    assert by_host["example.com"]["allowed"] is False
    assert by_host["example.com"]["reason"] == "not-allowlisted"
    assert all(e["session_id"] == "net1" for e in events)


def test_pip_download_through_the_proxy(net):
    h, s, _ = net
    r = h.do(s.run_command("pip download -q --no-deps -d /tmp/dl requests && ls /tmp/dl", timeout_s=120))
    assert r["exit_code"] == 0, r["stderr"]
    assert r["stdout"].startswith("requests-")


def test_proxy_socket_belongs_to_the_session_uid(net):
    _, s, _ = net
    st = (s.proxy_dir / "proxy.sock").stat()
    assert (st.st_uid, oct(st.st_mode & 0o777)) == (UID, "0o600")


def test_destroy_closes_the_proxy(net):
    h, s, _ = net
    h.do(s.destroy())
    assert not (s.proxy_dir / "proxy.sock").exists()


# ---- teardown races (code review) ------------------------------------------

def test_destroy_during_running_cell_leaves_nothing(h):
    """destroy() must win over the restart that the dying cell triggers."""
    s = h.create()

    async def race():
        cell = asyncio.ensure_future(s.run_code("import time; time.sleep(60)", timeout_s=60))
        await asyncio.sleep(1)
        await s.destroy()
        return await cell

    r = h.do(race())
    assert r["error"] == "KernelDied"
    h.do(asyncio.sleep(0.5))
    assert procs_of(UID) == [], procs_of(UID, states=True)
    assert not s.dir.exists()


def test_cancelled_run_command_is_killed(h, sbx):
    async def go():
        task = asyncio.ensure_future(sbx.run_command("sleep 300", timeout_s=600))
        await asyncio.sleep(1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.5)

    h.do(go())
    names = [n for _, n, _ in procs_of(UID, states=True)]
    assert "sleep" not in names, names
    assert code(h, sbx, "1")["result"] == "1"  # the session itself is fine
