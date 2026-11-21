"""Seccomp filter logic, checked with a small classic-BPF interpreter."""

import errno
import struct

import pytest

import seccomp
from seccomp import ARCHES, RET_ALLOW, RET_ERRNO, RET_KILL_PROCESS

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
CLONE_THREAD_FLAGS = 0x003D0F00  # what glibc passes for pthread_create
SIGCHLD = 17


def run(prog, nr, arch, args=(0,) * 6):
    data = struct.pack("<iI Q 6Q", nr, arch, 0, *args)
    acc, pc = 0, 0
    while True:
        code, jt, jf, k = prog[pc]
        pc += 1
        if code == seccomp.LD_ABS:
            acc = struct.unpack_from("<I", data, k)[0]
        elif code == seccomp.JEQ:
            pc += jt if acc == k else jf
        elif code == seccomp.JGE:
            pc += jt if acc >= k else jf
        elif code == seccomp.JSET:
            pc += jt if acc & k else jf
        elif code == seccomp.RET:
            return k
        else:
            raise AssertionError(f"unknown opcode {code:#x}")


@pytest.fixture(params=sorted(ARCHES))
def arch(request):
    a = ARCHES[request.param]
    return request.param, a, seccomp.program(request.param)


def test_ordinary_syscalls_are_allowed(arch):
    _, a, prog = arch
    for nr in (0, 1, 63, 64, 200):  # read/write/... on either arch
        if nr not in a["deny"].values() and nr not in (a["clone"], a["unshare"]):
            assert run(prog, nr, a["audit"]) == RET_ALLOW


def test_unshare_newuser_is_refused(arch):
    _, a, prog = arch
    assert run(prog, a["unshare"], a["audit"], (CLONE_NEWUSER, 0, 0, 0, 0, 0)) == RET_ERRNO | errno.EPERM
    assert run(prog, a["unshare"], a["audit"], (CLONE_NEWNET, 0, 0, 0, 0, 0)) == RET_ERRNO | errno.EPERM


def test_clone_with_namespace_flag_is_refused_but_threads_and_fork_pass(arch):
    _, a, prog = arch
    assert run(prog, a["clone"], a["audit"], (CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0, 0)) == RET_ERRNO | errno.EPERM
    assert run(prog, a["clone"], a["audit"], (CLONE_THREAD_FLAGS, 0, 0, 0, 0, 0)) == RET_ALLOW
    assert run(prog, a["clone"], a["audit"], (SIGCHLD, 0, 0, 0, 0, 0)) == RET_ALLOW


def test_clone3_reports_enosys_so_libc_falls_back(arch):
    _, a, prog = arch
    assert run(prog, a["clone3"], a["audit"]) == RET_ERRNO | errno.ENOSYS


def test_denied_syscalls_get_eperm(arch):
    _, a, prog = arch
    for name, nr in a["deny"].items():
        assert run(prog, nr, a["audit"]) == RET_ERRNO | errno.EPERM, name


def test_foreign_arch_is_killed(arch):
    name, a, prog = arch
    other = next(v["audit"] for k, v in ARCHES.items() if k != name)
    assert run(prog, 0, other) == RET_KILL_PROCESS
    assert run(prog, 0, 0x40000003) == RET_KILL_PROCESS  # i386


def test_x32_syscalls_are_refused_on_x86_64():
    a = ARCHES["x86_64"]
    prog = seccomp.program("x86_64")
    assert run(prog, 0x40000000 | 1, a["audit"]) == RET_ERRNO | errno.EPERM


def test_compiled_size_matches_instruction_count(arch):
    name, _, prog = arch
    assert len(seccomp.compile_filter(name)) == 8 * len(prog)
