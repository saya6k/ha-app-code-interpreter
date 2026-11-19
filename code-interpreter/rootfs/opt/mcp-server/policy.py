"""SandboxPolicy (structure borrowed from OpenShell) → Docker create arguments."""

from __future__ import annotations

from dataclasses import dataclass, field

SANDBOX_UID = 65534

# Wait for the REPL to be injected (put_archive after start), then hand PID 1
# to the restart loop. `.ready` is written last so init.sh is never partial.
ENTRYPOINT = [
    "sh",
    "-c",
    "while [ ! -f /opt/repl/.ready ]; do sleep 0.1; done; exec sh /opt/repl/init.sh",
]


@dataclass(frozen=True)
class FilesystemPolicy:
    read_only: bool = True
    sandbox_mb: int = 256
    tmp_mb: int = 64
    repl_mb: int = 4


@dataclass(frozen=True)
class ProcessPolicy:
    user: str = f"{SANDBOX_UID}:{SANDBOX_UID}"
    pids_limit: int = 128
    memory_mb: int = 512
    nano_cpus: int = 1_000_000_000


@dataclass(frozen=True)
class NetworkPolicy:
    endpoints: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class SandboxPolicy:
    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    process: ProcessPolicy = field(default_factory=ProcessPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)

    @classmethod
    def from_options(cls, options: dict) -> SandboxPolicy:
        return cls(process=ProcessPolicy(memory_mb=int(options["memory_limit_mb"])))


def sandbox_volume(sid: str) -> str:
    return f"ci-sbx-{sid}"


def repl_volume(sid: str) -> str:
    return f"ci-repl-{sid}"


def volume_specs(policy: SandboxPolicy, sid: str, labels: dict) -> list[dict]:
    """tmpfs-backed named volumes: the only tmpfs form the archive API can reach."""
    fs = policy.filesystem

    def spec(name: str, opts: str) -> dict:
        return {
            "name": name,
            "driver": "local",
            "driver_opts": {"type": "tmpfs", "device": "tmpfs", "o": opts},
            "labels": labels,
        }

    return [
        spec(
            sandbox_volume(sid),
            f"size={fs.sandbox_mb}m,uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0700,nosuid,nodev",
        ),
        spec(repl_volume(sid), f"size={fs.repl_mb}m,mode=0755,nosuid,nodev,noexec"),
    ]


def container_kwargs(
    policy: SandboxPolicy, *, image_id: str, name: str, sid: str, labels: dict
) -> dict:
    """Keyword arguments for docker-py `containers.create`."""
    fs, proc = policy.filesystem, policy.process
    return {
        "image": image_id,
        "name": name,
        "labels": labels,
        "entrypoint": ENTRYPOINT,
        "user": proc.user,
        "working_dir": "/sandbox",
        "environment": {"HOME": "/sandbox"},
        "read_only": fs.read_only,
        "tmpfs": {"/tmp": f"size={fs.tmp_mb}m"},
        "volumes": {
            sandbox_volume(sid): {"bind": "/sandbox", "mode": "rw"},
            repl_volume(sid): {"bind": "/opt/repl", "mode": "rw"},
        },
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"],
        "pids_limit": proc.pids_limit,
        "mem_limit": f"{proc.memory_mb}m",
        "nano_cpus": proc.nano_cpus,
        "network_mode": "none",
    }
