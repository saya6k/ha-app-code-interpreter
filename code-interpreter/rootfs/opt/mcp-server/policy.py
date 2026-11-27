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
BLAS_THREADS = 2
SBXEXEC = Path(__file__).with_name("sbxexec.py")


@dataclass(frozen=True)
class SandboxPolicy:
    # RLIMIT_AS: address space, not RSS. 1024 left ~10% headroom for the
    # analysis stack with a few threads (stacks and buffers are reserved up
    # front) and failed intermittently on CI; 896 always failed.
    memory_mb: int = 2048
    nproc: int = 128  # RLIMIT_NPROC: counts threads too
    fsize_mb: int = 256
    nofile: int = 1024
    sandbox_mb: int = 256  # tmpfs /sandbox: RAM, a hard cap the disk cannot give
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
        "PATH": "/opt/node/bin:/opt/venv/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": "/sandbox",  # pip --user and dotfiles persist for the session
        "PIP_NO_CACHE_DIR": "1",  # a wheel cache would eat the /sandbox quota
        "CI_IN_SANDBOX": "1",  # lets launch.py use kill(-1) safely
        "LANG": "C.UTF-8",
        "MPLBACKEND": "Agg",
        "MPLCONFIGDIR": "/tmp/mpl",
        "MATPLOTLIBRC": "/opt/ci/matplotlibrc",  # Korean font by default
        # OpenBLAS reserves buffers per thread and RLIMIT_AS counts the
        # reservations: one thread per core made it abort under 1 GB on a
        # many-core arm64 host. A fixed pool also keeps CPU use modest
        # without cgroups.
        "OPENBLAS_NUM_THREADS": str(BLAS_THREADS),
        "OMP_NUM_THREADS": str(BLAS_THREADS),
        # V8 sizes its heap from the machine, not RLIMIT_AS: past the limit
        # it would abort instead of throwing. Half leaves room for buffers.
        "NODE_OPTIONS": f"--max-old-space-size={policy.memory_mb // 2}",
    }
    if policy.allowlist:
        url = f"http://127.0.0.1:{PROXY_PORT}"
        env.update(HTTP_PROXY=url, HTTPS_PROXY=url, http_proxy=url, https_proxy=url, NO_PROXY="")
        env["NODE_USE_ENV_PROXY"] = "1"  # fetch() ignores HTTP(S)_PROXY without it
    return env


def bwrap_argv(
    policy: SandboxPolicy,
    *,
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
        "--size", str(policy.sandbox_mb * MIB), "--tmpfs", "/sandbox",
        "--ro-bind", str(proxy_dir), "/run/ci",
        "--chdir", "/sandbox",
        "--seccomp", str(seccomp_fd),
        "--",
    ]
    return argv
