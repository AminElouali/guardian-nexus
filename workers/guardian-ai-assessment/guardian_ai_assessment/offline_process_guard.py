"""Fail-closed, process-local network denial for offline Qwen evaluation.

This is not a replacement for Docker, a broker, or a host security boundary.
It is intended only for the standalone, synthetic, no-API offline runner.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import resource
import socket
from typing import Any

_ACTIVE_GUARD: object | None = None

_PR_SET_SECCOMP = 22
_PR_GET_SECCOMP = 21
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06
_EPERM_RETURN = _SECCOMP_RET_ERRNO | errno.EPERM

# Audit architecture and syscall numbers are deliberately allowlisted. Unknown
# architectures or kernel-call layouts must not silently fall back to a weaker
# Python-only socket patch.
_ARCHITECTURES: dict[str, tuple[int, dict[str, int]]] = {
    "x86_64": (
        0xC000003E,
        {
            "socket": 41,
            "connect": 42,
            "accept": 43,
            "sendto": 44,
            "recvfrom": 45,
            "sendmsg": 46,
            "recvmsg": 47,
            "bind": 49,
            "listen": 50,
            "socketpair": 53,
            "fork": 57,
            "vfork": 58,
            "execve": 59,
            "accept4": 288,
            "recvmmsg": 299,
            "execveat": 322,
            "sendmmsg": 307,
            "io_uring_setup": 425,
            "io_uring_enter": 426,
            "io_uring_register": 427,
            "clone3": 435,
        },
    ),
}

_DENIED_CALLS = (
    "socket",
    "socketpair",
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "execve",
    "execveat",
    "fork",
    "vfork",
    "clone3",
)


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def _assert_no_inherited_sockets() -> int:
    fd_directory = "/proc/self/fd"
    if not os.path.isdir(fd_directory):
        raise RuntimeError("offline_inherited_fd_check_unavailable")
    socket_count = 0
    for name in os.listdir(fd_directory):
        try:
            target = os.readlink(os.path.join(fd_directory, name))
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            socket_count += 1
    if socket_count:
        raise RuntimeError("offline_inherited_socket_fd_present")
    return socket_count


def _lower_limit(limit_id: int, desired: int) -> tuple[int, int]:
    soft, hard = resource.getrlimit(limit_id)
    infinity = resource.RLIM_INFINITY
    target_hard = desired if hard == infinity else min(hard, desired)
    target_soft = desired if soft == infinity else min(soft, desired)
    target_soft = min(target_soft, target_hard)
    resource.setrlimit(limit_id, (target_soft, target_hard))
    actual = resource.getrlimit(limit_id)
    return int(actual[0]), int(actual[1])


def _set_process_limits() -> dict[str, Any]:
    if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
        raise RuntimeError("offline_cpu_affinity_unavailable")
    allowed_cpus = sorted(os.sched_getaffinity(0))
    if not allowed_cpus:
        raise RuntimeError("offline_cpu_affinity_empty")
    os.sched_setaffinity(0, {allowed_cpus[0]})
    if len(os.sched_getaffinity(0)) != 1:
        raise RuntimeError("offline_single_cpu_affinity_unverified")

    _lower_limit(resource.RLIMIT_CPU, 900)
    cpu_soft, cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
    cpu_soft = min(cpu_soft, 840)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))
    cpu_soft, cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
    as_soft, as_hard = _lower_limit(resource.RLIMIT_AS, 1536 * 1024 * 1024)
    file_soft, file_hard = _lower_limit(resource.RLIMIT_FSIZE, 4 * 1024 * 1024)
    open_soft, open_hard = _lower_limit(resource.RLIMIT_NOFILE, 64)
    core_soft, core_hard = _lower_limit(resource.RLIMIT_CORE, 0)
    return {
        "cpuAffinityCount": 1,
        "cpuTimeLimitSeconds": cpu_soft,
        "cpuTimeHardLimitSeconds": cpu_hard,
        "addressSpaceLimitBytes": as_soft,
        "addressSpaceHardLimitBytes": as_hard,
        "fileSizeLimitBytes": file_soft,
        "openFilesLimit": open_soft,
        "coreDumpLimit": core_soft,
        "concurrency": 1,
        "subprocessExecution": "seccomp_denied",
        "pidsCgroupLimit": "not_available_in_host_process_mode",
        "limitsVerified": True,
    }


def _install_filter(architecture_id: int, syscall_numbers: dict[str, int]) -> None:
    instructions = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 4),  # seccomp_data.arch
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, architecture_id),
        _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),  # seccomp_data.nr
    ]
    for name in _DENIED_CALLS:
        syscall_number = syscall_numbers.get(name)
        if syscall_number is None:
            raise RuntimeError("offline_seccomp_syscall_table_incomplete")
        instructions.extend(
            (
                _SockFilter(_BPF_JMP_JEQ_K, 0, 1, syscall_number),
                _SockFilter(_BPF_RET_K, 0, 0, _EPERM_RETURN),
            )
        )
    instructions.append(_SockFilter(_BPF_RET_K, 0, 0, 0x7FFF0000))  # ALLOW

    filters = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), ctypes.cast(filters, ctypes.POINTER(_SockFilter)))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "offline_no_new_privs_failed")
    if (
        libc.prctl(
            _PR_SET_SECCOMP,
            _SECCOMP_MODE_FILTER,
            ctypes.addressof(program),
            0,
            0,
        )
        != 0
    ):
        raise OSError(ctypes.get_errno(), "offline_seccomp_install_failed")
    seccomp_mode = libc.prctl(_PR_GET_SECCOMP, 0, 0, 0, 0)
    no_new_privs = libc.prctl(_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
    if seccomp_mode != _SECCOMP_MODE_FILTER or no_new_privs != 1:
        raise RuntimeError("offline_seccomp_state_unverified")


def install_offline_process_guard() -> object:
    """Deny socket and process-exec syscalls, returning a process-local proof."""
    global _ACTIVE_GUARD
    if _ACTIVE_GUARD is not None:
        raise RuntimeError("offline_guard_already_installed")
    if platform.system() != "Linux":
        raise RuntimeError("offline_linux_seccomp_required")
    architecture = platform.machine().lower()
    if architecture not in _ARCHITECTURES:
        raise RuntimeError("offline_seccomp_architecture_unsupported")
    inherited_socket_count = _assert_no_inherited_sockets()
    limits = _set_process_limits()
    architecture_id, syscall_numbers = _ARCHITECTURES[architecture]
    _install_filter(architecture_id, syscall_numbers)

    # These are local syscall checks only. They do not connect to or probe any
    # destination and intentionally also deny loopback sockets.
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise RuntimeError("offline_socket_syscall_denial_unverified") from exc
        else:
            raise RuntimeError("offline_socket_syscall_not_denied")
    try:
        socket.socketpair()
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise RuntimeError("offline_socketpair_denial_unverified") from exc
    else:
        raise RuntimeError("offline_socketpair_not_denied")

    _ACTIVE_GUARD = object()
    _ACTIVE_GUARD_LIMITS = limits
    _ACTIVE_GUARD_INHERITED_SOCKETS = inherited_socket_count
    return _ACTIVE_GUARD


_ACTIVE_GUARD_LIMITS: dict[str, Any] | None = None
_ACTIVE_GUARD_INHERITED_SOCKETS: int | None = None


def is_active_offline_guard(proof: object | None) -> bool:
    return _ACTIVE_GUARD is not None and proof is _ACTIVE_GUARD


def offline_network_evidence(proof: object) -> dict[str, Any]:
    if not is_active_offline_guard(proof):
        raise RuntimeError("offline_guard_proof_invalid")
    return {
        "networkMode": "standalone_seccomp_no_socket_syscalls",
        "seccompMode": 2,
        "noNewPrivileges": True,
        "socketSyscalls": "denied_and_self_tested_with_eperm",
        "subprocessExecution": "execve_denied",
        "inheritedSocketFileDescriptors": _ACTIVE_GUARD_INHERITED_SOCKETS,
        "destinationReachabilityProbes": "not_performed",
        "ipv4Egress": "socket_syscalls_denied_not_destination_probed",
        "ipv6Egress": "socket_syscalls_denied_not_destination_probed",
        "ipv6Capability": "not_verified",
        "dnsEgress": "socket_syscalls_denied_not_destination_probed",
        "loopback": "denied",
        "externalCalls": 0,
    }


def offline_limit_evidence(proof: object) -> dict[str, Any]:
    if not is_active_offline_guard(proof) or _ACTIVE_GUARD_LIMITS is None:
        raise RuntimeError("offline_guard_proof_invalid")
    return dict(_ACTIVE_GUARD_LIMITS)
