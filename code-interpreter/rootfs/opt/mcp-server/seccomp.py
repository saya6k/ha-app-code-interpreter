"""Seccomp filter for bubblewrap's --seccomp FD (stdlib only, SPEC §3.4).

bwrap --disable-userns cannot work under Docker (/proc/sys is read-only), so
nested user namespaces are refused here instead, together with a few other
syscalls that only widen the kernel attack surface for analysis code.

The program is classic BPF over struct seccomp_data:
    nr @0 (u32), arch @4 (u32), instruction_pointer @8, args[6] @16 (u64 each)
"""

from __future__ import annotations

import errno
import platform
import struct

# BPF opcodes
LD_ABS = 0x20  # BPF_LD | BPF_W | BPF_ABS
JEQ = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
JGE = 0x35  # BPF_JMP | BPF_JGE | BPF_K
JSET = 0x45  # BPF_JMP | BPF_JSET | BPF_K
RET = 0x06  # BPF_RET | BPF_K

RET_ALLOW = 0x7FFF0000
RET_ERRNO = 0x00050000
RET_KILL_PROCESS = 0x80000000

OFF_NR, OFF_ARCH, OFF_ARG0_LO = 0, 4, 16

# CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET.
# Only NEWUSER works without privilege, but none has a use in the sandbox.
CLONE_NS_FLAGS = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000

ARCHES = {
    "x86_64": {
        "audit": 0xC000003E,
        "x32_bit": 0x40000000,
        "clone": 56, "unshare": 272, "clone3": 435,
        "deny": {
            "setns": 308, "mount": 165, "umount2": 166, "pivot_root": 155,
            "keyctl": 250, "add_key": 248, "request_key": 249,
            "bpf": 321, "perf_event_open": 298, "userfaultfd": 323, "ptrace": 101,
            "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
            "open_by_handle_at": 304, "kexec_load": 246,
        },
    },
    "aarch64": {
        "audit": 0xC00000B7,
        "x32_bit": None,
        "clone": 220, "unshare": 97, "clone3": 435,
        "deny": {
            "setns": 268, "mount": 40, "umount2": 39, "pivot_root": 41,
            "keyctl": 219, "add_key": 217, "request_key": 218,
            "bpf": 280, "perf_event_open": 241, "userfaultfd": 282, "ptrace": 117,
            "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
            "open_by_handle_at": 265, "kexec_load": 104,
        },
    },
}


def _assemble(prog: list[tuple]) -> list[tuple[int, int, int, int]]:
    """Resolve ("label", name) markers and jump targets given as label names."""
    labels, insns = {}, []
    for op in prog:
        if op[0] == "label":
            labels[op[1]] = len(insns)
        else:
            insns.append(op)
    out = []
    for i, (code, k, jt, jf) in enumerate(insns):
        jt = labels[jt] - i - 1 if isinstance(jt, str) else jt
        jf = labels[jf] - i - 1 if isinstance(jf, str) else jf
        assert 0 <= jt < 256 and 0 <= jf < 256
        out.append((code, jt, jf, k))
    return out


def program(arch: str | None = None) -> list[tuple[int, int, int, int]]:
    """Filter as (code, jt, jf, k) instructions for `arch` (default: this host)."""
    a = ARCHES[arch or platform.machine()]
    p: list[tuple] = [
        (LD_ABS, OFF_ARCH, 0, 0),
        (JEQ, a["audit"], 0, "kill"),  # foreign ABI (e.g. i386 on x86_64)
        (LD_ABS, OFF_NR, 0, 0),
    ]
    if a["x32_bit"]:
        p.append((JGE, a["x32_bit"], "eperm", 0))
    p += [
        (JEQ, a["clone3"], "enosys", 0),  # flags live in a struct; glibc falls back to clone
        (JEQ, a["unshare"], "check_ns", 0),
        (JEQ, a["clone"], "check_ns", 0),
    ]
    for nr in a["deny"].values():
        p.append((JEQ, nr, "eperm", 0))
    p += [
        (RET, RET_ALLOW, 0, 0),
        ("label", "check_ns"),
        (LD_ABS, OFF_ARG0_LO, 0, 0),
        (JSET, CLONE_NS_FLAGS, "eperm", 0),
        (RET, RET_ALLOW, 0, 0),
        ("label", "eperm"),
        (RET, RET_ERRNO | errno.EPERM, 0, 0),
        ("label", "enosys"),
        (RET, RET_ERRNO | errno.ENOSYS, 0, 0),
        ("label", "kill"),
        (RET, RET_KILL_PROCESS, 0, 0),
    ]
    return _assemble(p)


def compile_filter(arch: str | None = None) -> bytes:
    """struct sock_filter[] in native byte order, as bwrap --seccomp reads it."""
    return b"".join(struct.pack("=HBBI", *insn) for insn in program(arch))
