import json
from pathlib import Path

from policy import INNER_ID, MIB, SandboxPolicy, bwrap_argv, exec_prefix, sandbox_env


def argv(policy=SandboxPolicy()):
    return bwrap_argv(
        policy,
        work=Path("/w"),
        proxy_dir=Path("/p"),
        seccomp_fd=9,
        env=sandbox_env(policy),
    )


def pairs(a, flag):
    return [a[i + 1] for i, x in enumerate(a) if x == flag]


def test_namespaces_privileges_and_lifetime():
    a = argv()
    for flag in ("--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", "--clearenv"):
        assert flag in a
    assert pairs(a, "--cap-drop") == ["ALL"]
    assert pairs(a, "--uid") == pairs(a, "--gid") == [INNER_ID]
    assert pairs(a, "--seccomp") == ["9"]
    assert a[-1] == "--"


def test_filesystem_layout():
    a = argv()
    i = a.index("--ro-bind")
    assert a[i : i + 3] == ["--ro-bind", "/opt/sandbox-root", "/"]
    i = a.index("--bind")
    assert a[i : i + 3] == ["--bind", "/w", "/sandbox"]
    assert ["--ro-bind", "/p", "/run/ci"] == a[a.index("/p") - 1 : a.index("/p") + 2]
    assert a[a.index("--tmpfs") - 2 : a.index("--tmpfs") + 2] == ["--size", str(64 * MIB), "--tmpfs", "/tmp"]
    assert pairs(a, "--chdir") == ["/sandbox"]
    assert "--proc" not in a  # Docker refuses a fresh procfs (SPEC §0)
    assert "--disable-userns" not in a  # needs writable /proc/sys; seccomp covers it


def test_env_without_allowlist_has_no_proxy():
    env = sandbox_env(SandboxPolicy())
    assert env["HOME"] == "/tmp" and env["MPLBACKEND"] == "Agg"
    assert not any("PROXY" in k.upper() for k in env)


def test_env_with_allowlist_points_at_loopback_forwarder():
    env = sandbox_env(SandboxPolicy(allowlist=("pypi.org",)))
    assert env["HTTPS_PROXY"] == env["https_proxy"] == "http://127.0.0.1:3128"
    assert env["NO_PROXY"] == ""


def test_exec_prefix_carries_limits_and_uid():
    p = exec_prefix(SandboxPolicy(memory_mb=1024, nproc=128), 60001)
    assert p[1:3] == ["-I", "-S"] and p[3].endswith("sbxexec.py")
    spec = json.loads(p[4])
    assert spec["uid"] == 60001
    assert spec["oom_score_adj"] == 1000 and spec["nice"] == 10
    assert spec["rlimits"] == {
        "AS": 1024 * MIB,
        "NPROC": 128,
        "FSIZE": 256 * MIB,
        "NOFILE": 1024,
        "CORE": 0,
    }
