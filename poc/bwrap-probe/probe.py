"""bwrap probe: can this app container sandbox code with bubblewrap?

Prints environment facts, then a PASS/FAIL table. Copy the whole log back.
"""

import ctypes
import gzip
import json
import os
import platform
import socket
import subprocess
import threading

NOBODY = 65534
SOCK_DIR = "/run/probe-sock"
SOCK = f"{SOCK_DIR}/proxy.sock"
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} | {name:<48} | {detail}", flush=True)


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as e:
        return f"<{e.strerror}>"


def status_field(key):
    for line in read("/proc/self/status").splitlines():
        if line.startswith(key + ":"):
            return line.split(":", 1)[1].strip()
    return "?"


def landlock_abi():
    # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION); nr 444 on x86_64 and arm64.
    libc = ctypes.CDLL(None, use_errno=True)
    r = libc.syscall(444, None, 0, 1)
    return str(r) if r >= 0 else f"unavailable ({os.strerror(ctypes.get_errno())})"


def kernel_config():
    try:
        with gzip.open("/proc/config.gz", "rt") as f:
            keys = ("CONFIG_USER_NS=", "CONFIG_SECURITY_LANDLOCK", "CONFIG_LSM=", "CONFIG_SECURITY_APPARMOR=")
            return [line.strip() for line in f if line.startswith(keys)] or ["(keys not found)"]
    except OSError as e:
        return [f"/proc/config.gz: {e.strerror}"]


def environment():
    print("== environment ==")
    print(f"kernel        {platform.release()} {platform.machine()}")
    print(f"apparmor      {read('/proc/self/attr/current')}")
    print(f"CapEff        {status_field('CapEff')}")
    print(f"Seccomp       {status_field('Seccomp')} (0=off 2=filter)")
    print(f"NoNewPrivs    {status_field('NoNewPrivs')}")
    print(f"max_userns    {read('/proc/sys/user/max_user_namespaces')}")
    print(f"userns ns     {os.path.exists('/proc/self/ns/user')}")
    print(f"landlock ABI  {landlock_abi()}")
    print(f"cgroup ctrls  {read('/sys/fs/cgroup/cgroup.controllers')}")
    print(f"cgroup write  {os.access('/sys/fs/cgroup', os.W_OK)}")
    print(f"bwrap         {subprocess.run(['bwrap', '--version'], capture_output=True, text=True).stdout.strip()}")
    for line in kernel_config():
        print(f"kconfig       {line}")
    print(flush=True)


def pong_server():
    os.makedirs(SOCK_DIR, mode=0o755, exist_ok=True)
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o777)
    srv.listen()

    def loop():
        while True:
            conn, _ = srv.accept()
            conn.sendall(b"pong")
            conn.close()

    threading.Thread(target=loop, daemon=True).start()


# Runs inside the sandbox; prints one JSON object.
INNER = r"""
import json, os, socket, threading
r = {}
r["uid"] = f"{os.getuid()}:{os.getgid()}"
caps = [l for l in open("/proc/self/status") if l.startswith("CapEff")] if os.path.exists("/proc/self/status") else []
r["capeff"] = caps[0].split()[1] if caps else "n/a"
r["no_token"] = "SUPERVISOR_TOKEN" not in os.environ
r["no_data"] = not os.path.exists("/data") and not os.path.exists("/share")
try:
    open("/usr/probe-write", "w"); r["ro_usr"] = False
except OSError:
    r["ro_usr"] = True
try:
    open("/tmp/x", "w").write("x"); r["tmp_rw"] = True
except OSError:
    r["tmp_rw"] = False
r["ifaces"] = [n for _, n in socket.if_nameindex()]
def blocked(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close(); return False
    except OSError:
        return True
r["block_ip"] = blocked("1.1.1.1", 443)
r["block_host"] = blocked("172.30.32.1", 80)
try:
    socket.getaddrinfo("example.com", 443); r["block_dns"] = False
except OSError:
    r["block_dns"] = True
r["pids"] = len([p for p in os.listdir("/proc") if p.isdigit()]) if os.path.isdir("/proc/1") else "n/a"
# loopback TCP listener forwarding to the bound unix socket (HTTP_PROXY shape)
lst = socket.socket(); lst.bind(("127.0.0.1", 3128)); lst.listen()
def fwd():
    c, _ = lst.accept()
    u = socket.socket(socket.AF_UNIX); u.connect("/run/proxy/proxy.sock")
    c.sendall(u.recv(16)); c.close(); u.close()
threading.Thread(target=fwd, daemon=True).start()
try:
    s = socket.create_connection(("127.0.0.1", 3128), timeout=3); r["proxy_path"] = s.recv(16).decode(); s.close()
except OSError as e:
    r["proxy_path"] = f"error: {e}"
print(json.dumps(r))
"""


def bwrap_cmd(with_proc):
    cmd = ["bwrap", "--die-with-parent", "--new-session", "--unshare-all", "--unshare-user",
           "--uid", str(NOBODY), "--gid", str(NOBODY), "--hostname", "sandbox",
           "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
           "--dev", "/dev", "--tmpfs", "/tmp", "--bind", SOCK_DIR, "/run/proxy"]
    for d in ("/usr", "/bin", "/sbin", "/lib", "/etc"):
        if os.path.islink(d):
            cmd += ["--symlink", os.readlink(d), d]
        elif os.path.isdir(d):
            cmd += ["--ro-bind", d, d]
    if with_proc:
        cmd += ["--proc", "/proc"]
    return cmd + ["python3", "-c", INNER]


def drop_to_nobody():
    os.setgroups([])
    os.setgid(NOBODY)
    os.setuid(NOBODY)


def run_sandbox(label, with_proc, as_nobody):
    try:
        p = subprocess.run(bwrap_cmd(with_proc), capture_output=True, text=True, timeout=30,
                           preexec_fn=drop_to_nobody if as_nobody else None)
    except subprocess.TimeoutExpired:
        report(f"[{label}] bwrap starts", False, "timeout")
        return None
    if p.returncode != 0:
        report(f"[{label}] bwrap starts", False, (p.stderr or p.stdout).strip()[:200])
        return None
    report(f"[{label}] bwrap starts", True)
    return json.loads(p.stdout.strip().splitlines()[-1])


def check_inner(label, r):
    report(f"[{label}] runs as nobody", r["uid"] == f"{NOBODY}:{NOBODY}", r["uid"])
    report(f"[{label}] no effective capabilities", r["capeff"] in ("0000000000000000", "n/a"), r["capeff"])
    report(f"[{label}] SUPERVISOR_TOKEN not visible", r["no_token"])
    report(f"[{label}] /data and /share not visible", r["no_data"])
    report(f"[{label}] /usr read-only", r["ro_usr"])
    report(f"[{label}] /tmp writable", r["tmp_rw"])
    report(f"[{label}] only loopback interface", r["ifaces"] == ["lo"], ",".join(r["ifaces"]))
    report(f"[{label}] direct IP egress blocked", r["block_ip"], "1.1.1.1:443")
    report(f"[{label}] HA host blocked", r["block_host"], "172.30.32.1:80")
    report(f"[{label}] DNS resolution blocked", r["block_dns"], "example.com")
    report(f"[{label}] proxy via unix socket", r["proxy_path"] == "pong", r["proxy_path"])
    report(f"[{label}] process list isolated", r["pids"] == "n/a" or r["pids"] <= 3, f"pids={r['pids']}")


def main():
    environment()
    print("== checks ==")
    p = subprocess.run(["unshare", "--user", "--map-root-user", "true"], capture_output=True, text=True)
    report("create user namespace (unshare -U)", p.returncode == 0, p.stderr.strip()[:200])

    pong_server()
    for label, with_proc, as_nobody in (
        ("nobody+proc", True, True),   # target setup: unprivileged caller, private /proc
        ("nobody", False, True),       # fallback if a fresh /proc mount is refused
        ("root+proc", True, False),    # caller is container root (for comparison)
    ):
        r = run_sandbox(label, with_proc, as_nobody)
        if r:
            check_inner(label, r)

    failed = results.count(False)
    print(f"\n== {len(results) - failed} passed, {failed} failed ==", flush=True)


if __name__ == "__main__":
    main()
