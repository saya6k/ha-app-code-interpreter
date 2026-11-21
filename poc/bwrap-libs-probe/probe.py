"""bwrap libs probe: analysis stack without /proc, and memory/process limits.

Prints environment facts, then PASS/FAIL tables. Copy the whole log back.
"""

import json
import os
import platform
import resource
import statistics
import subprocess
import time

NOBODY = 65534
PY = "/opt/venv/bin/python3"
MB = 1024 * 1024
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} | {name:<44} | {detail}", flush=True)


def info(name, detail):
    print(f"INFO | {name:<44} | {detail}", flush=True)


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as e:
        return f"<{e.strerror}>"


def meminfo(key):
    for line in read("/proc/meminfo").splitlines():
        if line.startswith(key + ":"):
            return f"{int(line.split()[1]) // 1024} MB"
    return "?"


def options():
    try:
        with open("/data/options.json") as f:
            return json.load(f)
    except OSError:
        return {}


def bwrap_cmd(argv):
    cmd = ["bwrap", "--die-with-parent", "--new-session", "--unshare-all", "--unshare-user",
           "--uid", str(NOBODY), "--gid", str(NOBODY), "--hostname", "sandbox",
           "--clearenv",
           "--setenv", "PATH", "/opt/venv/bin:/usr/bin:/bin",
           "--setenv", "HOME", "/tmp", "--setenv", "MPLBACKEND", "Agg",
           "--setenv", "MPLCONFIGDIR", "/tmp/mpl",
           "--dev", "/dev", "--tmpfs", "/tmp"]
    for d in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt"):
        if os.path.islink(d):
            cmd += ["--symlink", os.readlink(d), d]
        elif os.path.isdir(d):
            cmd += ["--ro-bind", d, d]
    return cmd + argv


def preexec(as_mb=None, nproc=None, oom_adj=1000):
    def fn():
        with open("/proc/self/oom_score_adj", "w") as f:
            f.write(str(oom_adj))
        if as_mb:
            resource.setrlimit(resource.RLIMIT_AS, (as_mb * MB, as_mb * MB))
        if nproc:
            resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
        os.setgroups([])
        os.setgid(NOBODY)
        os.setuid(NOBODY)
    return fn


def sandbox(code, timeout=180, sandboxed=True, **limits):
    argv = [PY, "-c", code]
    cmd = bwrap_cmd(argv) if sandboxed else argv
    env = {"PATH": "/opt/venv/bin:/usr/bin:/bin", "HOME": "/tmp", "MPLBACKEND": "Agg",
           "MPLCONFIGDIR": "/tmp/mpl-baseline"}
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              preexec_fn=preexec(**limits), env=env)
    except subprocess.TimeoutExpired:
        return None


def tail(p):
    if p is None:
        return "timeout"
    lines = (p.stderr or p.stdout).strip().splitlines()
    return lines[-1][:160] if lines else f"exit {p.returncode}"


IMPORT_ALL = ("import numpy, pandas, scipy, statsmodels.api, sklearn, sympy, networkx, "
              "matplotlib.pyplot, seaborn, openpyxl, xlsxwriter, pyarrow, PIL, lxml, bs4, "
              "docx, fpdf, yaml, tabulate; print('ok')")

COMPAT = {
    "import full stack": IMPORT_ALL,
    "os.cpu_count / affinity": "import os; print(os.cpu_count(), len(os.sched_getaffinity(0)))",
    "numpy linalg (BLAS)":
        "import numpy as np; a=np.random.rand(400,400); np.linalg.inv(a@a.T+np.eye(400)); print('ok')",
    "pandas groupby + parquet + excel":
        "import pandas as pd; df=pd.DataFrame({'a':range(1000),'b':[i%7 for i in range(1000)]}); "
        "df.groupby('b').sum(); df.to_parquet('/tmp/x.parquet'); pd.read_parquet('/tmp/x.parquet'); "
        "df.to_excel('/tmp/x.xlsx'); print('ok')",
    "matplotlib png, Korean font":
        "import matplotlib.pyplot as plt; plt.rcParams['font.family']='NanumGothic'; "
        "plt.plot([1,2,3]); plt.title('한글'); plt.savefig('/tmp/x.png'); print('ok')",
    "scipy optimize + statsmodels OLS":
        "import numpy as np, scipy.optimize as o, statsmodels.api as sm; o.minimize(lambda x:(x-3)**2,[0]); "
        "x=np.random.rand(100); sm.OLS(2*x+1, sm.add_constant(x)).fit(); print('ok')",
    "sklearn n_jobs=2 (joblib/loky)":
        "from sklearn.ensemble import RandomForestClassifier as R; from sklearn.datasets import make_classification as m; "
        "X,y=m(300); R(20,n_jobs=2).fit(X,y); print('ok')",
    "multiprocessing.Pool":
        "import multiprocessing as m\nif __name__=='__main__':\n with m.Pool(2) as p: print(p.map(abs,[-1,-2]))",
    "ProcessPoolExecutor":
        "from concurrent.futures import ProcessPoolExecutor as P\nif __name__=='__main__':\n"
        " with P(2) as p: print(list(p.map(abs,[-1,-2])))",
    "subprocess + shell": "import subprocess; subprocess.run(['sh','-c','echo hi; ls / >/dev/null'],check=True); print('ok')",
    "pillow + python-docx + fpdf2":
        "from PIL import Image; Image.new('RGB',(9,9)).save('/tmp/a.png'); import docx; d=docx.Document(); "
        "d.add_paragraph('x'); d.save('/tmp/a.docx'); from fpdf import FPDF; p=FPDF(); p.add_page(); "
        "p.output('/tmp/a.pdf'); print('ok')",
    "no capabilities (capget)":
        "import ctypes\nclass H(ctypes.Structure): _fields_=[('v',ctypes.c_uint32),('pid',ctypes.c_int)]\n"
        "class D(ctypes.Structure): _fields_=[('e',ctypes.c_uint32),('p',ctypes.c_uint32),('i',ctypes.c_uint32)]\n"
        "h=H(0x20080522,0); d=(D*2)(); assert ctypes.CDLL(None).capget(ctypes.byref(h),d)==0\n"
        "assert not any(x.e or x.p for x in d), [(x.e,x.p) for x in d]; print('ok')",
}


def environment():
    print("== environment ==")
    print(f"kernel        {platform.release()} {platform.machine()}")
    print(f"apparmor      {read('/proc/self/attr/current')}")
    print(f"cpus          {os.cpu_count()}")
    print(f"MemTotal      {meminfo('MemTotal')}  MemAvailable {meminfo('MemAvailable')}  SwapTotal {meminfo('SwapTotal')}")
    print(f"app mem.max   {read('/sys/fs/cgroup/memory.max')}")
    print(f"bwrap         {subprocess.run(['bwrap', '--version'], capture_output=True, text=True).stdout.strip()}")
    print(flush=True)


def compat():
    print("== A. analysis stack inside bwrap, no /proc ==")
    for name, code in COMPAT.items():
        p = sandbox(code)
        ok = p is not None and p.returncode == 0
        detail = "" if ok else tail(p)
        if not ok:  # does it also fail outside the sandbox (same uid, no bwrap)?
            b = sandbox(code, sandboxed=False)
            detail += " [baseline outside: " + ("ok]" if b and b.returncode == 0 else "fails too]")
        report(name, ok, detail)
    print(flush=True)


def descendants(root):
    kids = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        stat = read(f"/proc/{pid}/stat")
        if stat.startswith("<"):
            continue
        ppid = int(stat.rsplit(")", 1)[1].split()[1])
        kids.setdefault(ppid, []).append(int(pid))
    out, todo = [], [root]
    while todo:
        p = todo.pop()
        out.append(p)
        todo += kids.get(p, [])
    return out


def limits():
    print("== B. limits ==")
    for mb in (512, 1024):
        p = sandbox(IMPORT_ALL, as_mb=mb)
        report(f"full stack imports under RLIMIT_AS={mb}MB", p is not None and p.returncode == 0,
               "" if p and p.returncode == 0 else tail(p))

    code = ("import numpy as np\ntry:\n np.ones(10**9)\nexcept MemoryError: print('MemoryError')\n"
            "try:\n b=bytearray(1024**3)\nexcept MemoryError: print('MemoryError')")
    p = sandbox(code, as_mb=1024)
    out = p.stdout.split() if p else []
    report("over-limit alloc -> MemoryError (AS=1024MB)", out == ["MemoryError", "MemoryError"],
           " ".join(out) or tail(p))

    proc = subprocess.Popen(bwrap_cmd([PY, "-c", "import time; time.sleep(4)"]),
                            preexec_fn=preexec(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    adj = {pid: read(f"/proc/{pid}/oom_score_adj") for pid in descendants(proc.pid)}
    proc.wait()
    report("oom_score_adj=1000 inherited by sandbox", len(adj) > 1 and set(adj.values()) == {"1000"},
           f"{len(adj)} procs: {sorted(set(adj.values()))}")
    info("app's own oom_score_adj", read("/proc/self/oom_score_adj"))

    code = ("import subprocess\nps=[]\ntry:\n for _ in range(200): ps.append(subprocess.Popen(['sleep','5']))\n"
            "except OSError as e: print(len(ps), e.errno)\nelse: print(len(ps), 0)\n"
            "for p in ps: p.kill()")
    p = sandbox(code, nproc=32)
    n = int(p.stdout.split()[0]) if p and p.stdout.strip() else -1
    report("RLIMIT_NPROC=32 stops a fork flood", 0 <= n < 40, f"spawned {n} before refusal" if p else "timeout")

    runs = []
    for _ in range(5):
        t = time.monotonic()
        subprocess.run(bwrap_cmd(["true"]), preexec_fn=preexec(), check=False)
        runs.append((time.monotonic() - t) * 1000)
    info("bwrap start latency (median of 5)", f"{statistics.median(runs):.0f} ms")
    t = time.monotonic()
    sandbox("import numpy, pandas")
    info("sandbox start + import numpy, pandas", f"{(time.monotonic() - t) * 1000:.0f} ms")
    print(flush=True)


def oom():
    print("== C. host OOM (oom_test: true) ==")
    print(f"MemAvailable before: {meminfo('MemAvailable')}", flush=True)
    code = ("import sys\nheld=[]\nwhile True:\n held.append(b'\\x01'*(64*1024*1024))\n"
            " print(len(held)*64, flush=True)")
    p = sandbox(code, timeout=300)
    if p is None:
        report("sandbox killed by OOM, app survives", False, "timeout after 300 s")
        return
    last = p.stdout.split()[-1] if p.stdout.split() else "0"
    report("sandbox killed by OOM, app survives", p.returncode in (-9, 137),
           f"exit {p.returncode} after ~{last} MB")
    print(f"MemAvailable after: {meminfo('MemAvailable')}", flush=True)


def main():
    environment()
    compat()
    limits()
    if options().get("oom_test"):
        oom()
    else:
        print("== C. host OOM: skipped (set oom_test: true to run) ==")
    failed = results.count(False)
    print(f"\n== {len(results) - failed} passed, {failed} failed ==", flush=True)


if __name__ == "__main__":
    main()
