"""SandboxPolicy -> bubblewrap argv and process limits (SPEC §3.4)."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

MIB = 1 << 20
SANDBOX_ROOT = Path("/opt/sandbox-root")
INNER_ID = "65534"  # what the sandbox sees; outside it is the session uid
PROXY_PORT = 3128
SBXEXEC = Path(__file__).with_name("sbxexec.py")


@dataclass(frozen=True)
class SandboxPolicy:
    memory_mb: int = 1024  # RLIMIT_AS: address space, not RSS
    nproc: int = 128  # RLIMIT_NPROC: counts threads too
    fsize_mb: int = 256
    nofile: int = 1024
    tmp_mb: int = 64
    nice: int = 10
    oom_score_adj: int = 1000
    allowlist: tuple[str, ...] = ()


def exec_prefix(policy: SandboxPolicy, uid: int) -> list[str]:
    """Helper that applies limits, drops to `uid` and execs the rest of argv."""
    spec = {
        "uid": uid,
        "oom_score_adj": policy.oom_score_adj,
        "nice": policy.nice,
        "rlimits": {
            "AS": policy.memory_mb * MIB,
            "NPROC": policy.nproc,
            "FSIZE": policy.fsize_mb * MIB,
            "NOFILE": policy.nofile,
            "CORE": 0,
        },
    }
    return [sys.executable, "-I", "-S", str(SBXEXEC), json.dumps(spec)]


def sandbox_env(policy: SandboxPolicy) -> dict[str, str]:
    env = {
        "PATH": "/opt/venv/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "MPLBACKEND": "Agg",
        "MPLCONFIGDIR": "/tmp/mpl",
    }
    if policy.allowlist:
        url = f"http://127.0.0.1:{PROXY_PORT}"
        env.update(HTTP_PROXY=url, HTTPS_PROXY=url, http_proxy=url, https_proxy=url, NO_PROXY="")
    return env


def bwrap_argv(
    policy: SandboxPolicy,
    *,
    work: Path,
    proxy_dir: Path,
    seccomp_fd: int,
    env: dict[str, str],
    root: Path = SANDBOX_ROOT,
    bwrap: str = "bwrap",
) -> list[str]:
    argv = [
        bwrap,
        "--unshare-all", "--unshare-user",
        "--die-with-parent", "--new-session",
        "--cap-drop", "ALL",
        "--uid", INNER_ID, "--gid", INNER_ID,
        "--hostname", "sandbox",
        "--clearenv",
    ]
    for k, v in env.items():
        argv += ["--setenv", k, v]
    argv += [
        "--ro-bind", str(root), "/",
        "--dev", "/dev",
        "--size", str(policy.tmp_mb * MIB), "--tmpfs", "/tmp",
        "--bind", str(work), "/sandbox",
        "--ro-bind", str(proxy_dir), "/run/ci",
        "--chdir", "/sandbox",
        "--seccomp", str(seccomp_fd),
        "--",
    ]
    return argv
