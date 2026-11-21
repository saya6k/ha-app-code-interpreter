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
import os, ctypes, errno, threading, multiprocessing as m
try:
    os.unshare(os.CLONE_NEWUSER); userns = 'allowed'
except PermissionError:
    userns = 'blocked'
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
