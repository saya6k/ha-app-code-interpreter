"""Sandbox against real bubblewrap. Runs inside the app image only:

    scripts/test-sandbox.sh   (local docker / CI; container runs seccomp=unconfined)
"""

import asyncio
import contextlib
import os
import shlex
import shutil
import tempfile
from pathlib import Path

import pytest

from policy import SANDBOX_ROOT, SandboxPolicy
from sandbox import FileOpError, Sandbox, SandboxError

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


PY_RUNNER = """import ast, sys
t = ast.parse(sys.stdin.read())
last = t.body.pop() if t.body and isinstance(t.body[-1], ast.Expr) else None
g = {"__name__": "__main__"}
exec(compile(t, "<py>", "exec"), g)
if last is not None:
    print(repr(eval(compile(ast.Expression(last.value), "<py>", "eval"), g)))
"""


def py(h, s, src, timeout=60):
    """Python through run_command, as the sandbox runs its analysis stack:
    the repr of the last expression as result, the exception's name as error."""
    r = h.do(s.run_command(f"python3 -c {shlex.quote(PY_RUNNER)} <<'__PY__'\n{src}\n__PY__", timeout_s=timeout))
    out = r["stdout"].strip().splitlines()
    err = r["stderr"].strip().splitlines()
    error = None if r["exit_code"] == 0 else (err[-1].split(":")[0] if err else str(r["error"]))
    return {"result": out[-1] if out else None, "error": error, "stderr": r["stderr"]}


def test_variables_persist_and_last_expression_is_returned(h, sbx):
    assert code(h, sbx, "x = 21")["error"] is None
    r = code(h, sbx, "x * 2")
    assert r["result"] == "42" and r["kernel_restarted"] is False


def test_identity_capabilities_env_and_network(h, sbx):
    r = py(h, sbx, """
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
    r = py(h, sbx, """
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


def test_seccomp_blocks_nested_userns_but_threads_and_processes_work(h, sbx):
    r = py(h, sbx, """
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
    r = py(h, sbx, "b = bytearray(3 * 1024**3)")
    assert r["error"] == "MemoryError"
    r = code(h, sbx, "Buffer.alloc(3 * 1024 ** 3).length")
    assert r["error"] == "RangeError" and r["kernel_restarted"] is False
    assert code(h, sbx, "1")["result"] == "1"


def test_fork_flood_is_stopped(h, sbx):
    r = py(h, sbx, """
import subprocess
ps = []
try:
    for _ in range(300): ps.append(subprocess.Popen(['sleep', '30']))
except OSError:
    pass
n = len(ps)
n
""")
    assert int(r["result"]) < 130
    # The flood is still alive: destroy() must not hand the uid on before
    # every one of them is gone (they would eat the next session's NPROC).
    h.do(sbx.destroy())
    assert procs_of(UID) == []


def test_analysis_stack_with_threads_under_nproc_limit(h, sbx):
    r = py(h, sbx, """
from sklearn.ensemble import RandomForestClassifier as R
from sklearn.datasets import make_classification as m
import numpy as np, matplotlib.pyplot as plt
X, y = m(300); R(20, n_jobs=2).fit(X, y)
np.linalg.inv(np.eye(300) * 2)
plt.plot([1, 2]); plt.title('한글'); plt.savefig('/sandbox/p.png')
'ok'
""", timeout=120)
    assert r["result"] == "'ok'", r
    assert int(py(h, sbx, "import os; os.path.getsize('/sandbox/p.png')")["result"]) > 0


def test_every_preinstalled_package_imports(h, sbx):
    # The image deletes the packages' tests/ directories; nothing may need them.
    r = py(h, sbx, """
import importlib
mods = ('numpy pandas scipy.stats statsmodels.api sklearn.linear_model sympy networkx '
        'matplotlib.pyplot seaborn openpyxl xlsxwriter pyarrow.parquet PIL.Image lxml.etree '
        'bs4 docx fpdf pypdf pdfplumber yaml tabulate').split()
[m for m in mods if not importlib.import_module(m)]
""", timeout=120)
    assert r["error"] is None and r["result"] == "[]", r


def test_pdf_text_and_tables(h, sbx):
    r = py(h, sbx, """
from fpdf import FPDF
pdf = FPDF(); pdf.add_page(); pdf.set_font('helvetica', size=12)
pdf.cell(text='Error codes'); pdf.ln(10)
with pdf.table() as t:
    for row in (('Code', 'Meaning'), ('E3', 'Door open'), ('E4', 'No water')):
        t.row(row)
pdf.output('/sandbox/m.pdf')
import pypdf, pdfplumber
text = pypdf.PdfReader('/sandbox/m.pdf').pages[0].extract_text()
with pdfplumber.open('/sandbox/m.pdf') as p:
    table = p.pages[0].extract_table()
('Error codes' in text, table)
""", timeout=60)
    assert r["error"] is None, r["stderr"]
    assert eval(r["result"]) == (True, [["Code", "Meaning"], ["E3", "Door open"], ["E4", "No water"]])


def test_timeout_interrupt_keeps_variables(h, sbx):
    code(h, sbx, "keep = 7")
    r = code(h, sbx, "while (true) {}", timeout=1)
    assert r["error"] == "TimeoutError" and r["kernel_restarted"] is False
    assert code(h, sbx, "keep")["result"] == "7"


# A loop after an await runs outside the interruptible script: only a restart ends it.
STUCK = "await null; while (true) {}"
READ_KEPT = "require('fs').readFileSync('/sandbox/kept.txt', 'utf8')"


def test_stuck_kernel_is_restarted_keeping_files(h, sbx):
    code(h, sbx, "lost = 1; require('fs').writeFileSync('/sandbox/kept.txt', 'y')")
    r = code(h, sbx, STUCK, timeout=1)
    assert r["error"] == "TimeoutError" and r["kernel_restarted"] is True
    assert code(h, sbx, "lost")["error"] == "ReferenceError"
    assert code(h, sbx, READ_KEPT)["result"] == "y"


def test_restart_survives_a_cancelled_caller(h, sbx):
    """HA cuts the call (cancel) while the stuck kernel's restart is running:
    the restart must still finish, so the next call finds a working REPL."""
    code(h, sbx, "require('fs').writeFileSync('/sandbox/kept.txt', 'y')")

    async def go():
        task = None
        run_locked = sbx._run_locked

        async def cancel_inside(work):  # the restart's agent call: cancel lands mid-call
            task.cancel()
            return await run_locked(work)

        sbx._run_locked = cancel_inside
        task = asyncio.ensure_future(sbx.run_code(STUCK, timeout_s=1))
        with pytest.raises(asyncio.CancelledError):
            await task
        sbx._run_locked = run_locked
        return await sbx.run_code(READ_KEPT, timeout_s=30)

    r = h.do(go())
    assert r["result"] == "y" and r["kernel_restarted"] is False


KILL_REPL = "process.kill(process.pid, 'SIGKILL')"


def test_crash_restarts_kernel(h, sbx):
    r = code(h, sbx, KILL_REPL)
    assert r["error"] == "KernelDied" and r["kernel_restarted"] is True
    assert code(h, sbx, "2")["result"] == "2"


def test_reset_clears_variables(h, sbx):
    code(h, sbx, "gone = 1")
    h.do(sbx.run_code("", timeout_s=10, reset=True))
    assert code(h, sbx, "gone")["error"] == "ReferenceError"


def test_run_command_shares_files_and_reports_exit(h, sbx):
    code(h, sbx, "require('fs').writeFileSync('/sandbox/f.txt', 'hi')")
    r = h.do(sbx.run_command("cat f.txt; echo err >&2; exit 3", timeout_s=30))
    assert (r["stdout"], r["stderr"], r["exit_code"], r["error"]) == ("hi", "err\n", 3, None)


def test_run_command_timeout_and_output_cap(h, sbx):
    r = h.do(sbx.run_command("yes | head -c 100000; sleep 30", timeout_s=2))
    assert r["error"] == "TimeoutError"
    assert len(r["stdout"]) == 16000 and r["truncated"] is True


SLEEPER = "require('child_process').spawn('sleep', ['300'], {stdio: 'ignore'}).unref()"


def test_destroy_leaves_no_process_or_directory(h):
    s = h.create()
    code(h, s, SLEEPER)
    assert "sleep" in [n for _, n, _ in procs_of(UID, states=True)]
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
    r = py(h, sbx, PROBE.format(gw=gateway()))
    assert r["error"] is None, r["stderr"]
    ip, gw80, gw8099, dns, has_sock, has_env = eval(r["result"])
    assert "open" not in (ip, gw80, gw8099)
    assert dns == "failed" and has_sock is False and has_env is False
    r = py(h, sbx, "import socket\ntry:\n socket.create_connection(('127.0.0.1', 3128), 2); e = None\nexcept OSError as x: e = type(x).__name__\ne")
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
    r = py(h, s, PROBE.format(gw=gateway()))
    ip, gw80, gw8099, dns, has_sock, has_env = eval(r["result"])
    assert "open" not in (ip, gw80, gw8099)
    assert dns == "failed" and has_sock is True and has_env is True

    r = py(h, s, """
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
    # fetch() in the REPL goes through the same proxy (NODE_USE_ENV_PROXY).
    r = code(h, s, "(await fetch('https://pypi.org/simple/requests/')).status")
    assert r["result"] == "200", r
    r = code(h, s, "await fetch('https://example.com/')")
    assert r["error"] == "TypeError"

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
        cell = asyncio.ensure_future(s.run_code("await new Promise((r) => setTimeout(r, 60000))", timeout_s=60))
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



# ---- one sandbox per session (review findings 4, 5) -------------------------

def test_sandbox_dir_is_capped_and_never_touches_the_app_disk(h, sbx):
    r = py(h, sbx, """
import errno
written, err = 0, None
try:
    for i in range(10):  # 10 x 40 MB: each file under RLIMIT_FSIZE, together over the cap
        with open(f'/sandbox/big{i}', 'wb') as f:
            for _ in range(40):
                f.write(b'0' * 1024 * 1024); written += 1
except OSError as e:
    err = errno.errorcode[e.errno]
(written, err)
""")
    written, err = eval(r["result"])
    assert err == "ENOSPC" and written <= 256
    assert sorted(p.name for p in sbx.dir.iterdir()) == ["proxy"]  # nothing else on disk
    py(h, sbx, "import glob, os; [os.remove(p) for p in glob.glob('/sandbox/big*')]")
    assert py(h, sbx, "open('/sandbox/ok', 'w').write('fine')")["error"] is None


def test_commands_and_code_share_tmp_home_and_sandbox(h, sbx):
    r = h.do(sbx.run_command("echo cmd > /tmp/t; echo home > $HOME/h; pwd", timeout_s=30))
    assert r["stdout"] == "/sandbox\n"
    r = code(h, sbx, "const fs = require('fs'); [fs.readFileSync('/tmp/t', 'utf8'), fs.readFileSync(require('os').homedir() + '/h', 'utf8')]")
    assert r["result"] == '["cmd\\n","home\\n"]'


def test_restart_keeps_files_and_ends_stray_processes(h, sbx):
    code(h, sbx, "require('fs').writeFileSync('/sandbox/f', 'kept'); " + SLEEPER)
    assert "sleep" in [n for _, n, _ in procs_of(UID, states=True)]
    r = code(h, sbx, KILL_REPL)
    assert r["kernel_restarted"] is True
    h.do(asyncio.sleep(0.3))
    assert "sleep" not in [n for _, n, _ in procs_of(UID, states=True)]
    assert code(h, sbx, "require('fs').readFileSync('/sandbox/f', 'utf8')")["result"] == "kept"


def test_sandbox_killed_from_inside_is_reported_and_files_are_gone(h, sbx):
    """kill(-1) from user code takes the agent down, so bwrap and the whole
    sandbox end. The app must say so instead of pretending a restart worked."""
    code(h, sbx, "process.kill(-1, 'SIGKILL')")  # its reply may still get out
    h.do(asyncio.sleep(0.5))  # bwrap tears the sandbox down once the agent is gone
    assert procs_of(UID) == []
    with pytest.raises(SandboxError, match="files are lost"):
        code(h, sbx, "1")


# ---- file ops through the agent (T7) ---------------------------------------

def test_large_binary_round_trip_through_the_agent(h, sbx):
    data = os.urandom(20 * 1024 * 1024)
    assert h.do(sbx.write_file("/sandbox/d/blob.bin", data, 20 << 20)) == {"path": "/sandbox/d/blob.bin", "size": len(data)}
    got, size = h.do(sbx.read_file("d/blob.bin", 21 << 20))
    assert size == len(data) and got == data
    r = code(h, sbx, "require('crypto').createHash('sha256').update(require('fs').readFileSync('/sandbox/d/blob.bin')).digest('hex')")
    import hashlib
    assert r["result"] == hashlib.sha256(data).hexdigest()


def test_file_ops_stay_inside_sandbox(h, sbx):
    code(h, sbx, "const fs = require('fs'); fs.symlinkSync('/etc/passwd', '/sandbox/pw'); fs.symlinkSync('/tmp', '/sandbox/t')")
    for path in ("/etc/passwd", "/sandbox/../etc/passwd", "pw", "t/x"):
        with pytest.raises(FileOpError, match="outside /sandbox"):
            h.do(sbx.read_file(path, 100))
    with pytest.raises(FileOpError):
        h.do(sbx.write_file("t/evil", b"x", 100))
    with pytest.raises(FileOpError, match="exceeds"):
        h.do(sbx.write_file("big", b"x" * 2000, 1000))


def test_listing_sees_code_output_and_survives_restart(h, sbx):
    code(h, sbx, "require('fs').writeFileSync('/sandbox/out.csv', 'a\\n1\\n')")
    names = [e["path"] for e in h.do(sbx.list_files())["entries"]]
    assert "/sandbox/out.csv" in names
    code(h, sbx, KILL_REPL)
    names = [e["path"] for e in h.do(sbx.list_files())["entries"]]
    assert "/sandbox/out.csv" in names


# ---- review fixes (00fd254^..HEAD) -----------------------------------------

def test_fifo_in_sandbox_is_refused_without_hanging(h, sbx):
    h.do(sbx.run_command("mkfifo /sandbox/p", timeout_s=10))

    async def go():
        return await asyncio.wait_for(sbx.read_file("/sandbox/p", 100), 10)

    with pytest.raises(FileOpError, match="regular file"):
        h.do(go())
    assert code(h, sbx, "1")["result"] == "1"


def test_huge_listing_does_not_kill_the_agent(h, sbx):
    py(h, sbx, """
import os
d = '/sandbox/' + 'd' * 100
os.makedirs(d)
for i in range(3000):
    open(f"{d}/{i:05d}-{'x' * 120}", 'w').close()
""", timeout=120)
    listing = h.do(sbx.list_files("/sandbox", recursive=True))
    assert listing["truncated"] is True and listing["entries"]
    assert code(h, sbx, "'alive'")["result"] == "alive"  # agent and files survived


def test_cancelled_file_op_does_not_leak_its_reply(h, sbx):
    data = os.urandom(20 * 1024 * 1024)
    h.do(sbx.write_file("big.bin", data, 20 << 20))

    async def go():
        task = asyncio.ensure_future(sbx.read_file("big.bin", 21 << 20))
        await asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return await sbx.list_files()

    listing = h.do(go())
    assert "entries" in listing and any(e["path"] == "/sandbox/big.bin" for e in listing["entries"])


def test_destroy_during_file_op_raises_cleanly(h):
    s = h.create()
    h.do(s.write_file("big.bin", os.urandom(20 * 1024 * 1024), 20 << 20))

    async def go():
        task = asyncio.ensure_future(s.read_file("big.bin", 21 << 20))
        await asyncio.sleep(0.05)
        await s.destroy()
        return await asyncio.gather(task, return_exceptions=True)

    (result,) = h.do(go())
    assert not isinstance(result, AttributeError), result
    assert isinstance(result, (SandboxError, tuple)), result
    assert procs_of(UID) == []


def test_kernel_death_reports_the_sandbox_stderr(h, sbx):
    r = code(h, sbx, "require('fs').writeSync(2, 'native lib: fatal error\\n'); process.abort()")
    assert r["error"] == "KernelDied" and r["kernel_restarted"] is True
    assert "native lib: fatal error" in r["stderr"]


def test_blas_threads_are_capped_so_the_memory_limit_holds_on_many_cores(h, sbx):
    """OpenBLAS reserves buffers per thread, and RLIMIT_AS counts reservations:
    on hosts with many cores (a 1 GB limit, an arm64 CI runner) an uncapped
    pool aborts the REPL. The sandbox caps it, whatever the core count."""
    r = py(h, sbx, "import os; (os.environ.get('OPENBLAS_NUM_THREADS'), os.environ.get('OMP_NUM_THREADS'))")
    assert r["result"] == "('2', '2')"
    r = py(h, sbx, "import numpy as np; from threadpoolctl import threadpool_info; "
                     "max(i['num_threads'] for i in threadpool_info())")
    assert r["result"] == "2", r

