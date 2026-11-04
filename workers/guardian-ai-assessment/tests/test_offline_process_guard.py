import json
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

WORKER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER_ROOT))

from guardian_ai_assessment import offline_process_guard


class OfflineProcessGuardTests(unittest.TestCase):
    def test_invalid_guard_proof_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "offline_guard_proof_invalid"):
            offline_process_guard.offline_network_evidence(object())
        with self.assertRaisesRegex(RuntimeError, "offline_guard_proof_invalid"):
            offline_process_guard.offline_limit_evidence(object())

    def test_unsupported_architecture_fails_closed_before_installation(self):
        with patch.object(offline_process_guard.platform, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(
                RuntimeError, "offline_seccomp_architecture_unsupported"
            ):
                offline_process_guard.install_offline_process_guard()

    def test_seccomp_guard_persists_limits_and_denies_sockets_and_exec(self):
        child = textwrap.dedent(
            """
            import errno
            import json
            import os
            import socket
            import sys
            import threading
            from pathlib import Path
            import ctypes

            sys.path.insert(0, str(Path(sys.argv[1])))
            from guardian_ai_assessment.offline_process_guard import (
                install_offline_process_guard,
                offline_limit_evidence,
                offline_network_evidence,
            )

            proof = install_offline_process_guard()
            network = offline_network_evidence(proof)
            limits = offline_limit_evidence(proof)
            socket_denials = []
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    socket.socket(family, socket.SOCK_STREAM)
                except OSError as exc:
                    socket_denials.append(exc.errno == errno.EPERM)
                else:
                    socket_denials.append(False)
            try:
                os.execve("/bin/true", ["true"], {})
            except OSError as exc:
                exec_denied = exc.errno == errno.EPERM
            else:
                exec_denied = False

            thread_result = []
            thread = threading.Thread(target=lambda: thread_result.append("thread-ok"))
            thread.start()
            thread.join(timeout=2)
            thread_created = not thread.is_alive() and thread_result == ["thread-ok"]

            try:
                os.fork()
            except OSError as exc:
                fork_denied = exc.errno == errno.EPERM
            else:
                fork_denied = False
                os.wait()

            libc = ctypes.CDLL(None, use_errno=True)
            syscall = libc.syscall
            syscall.restype = ctypes.c_long
            syscall.argtypes = [
                ctypes.c_long, ctypes.c_ulong, ctypes.c_ulong,
                ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
            ]
            clone3_result = syscall(435, 0, 0, 0, 0, 0)
            clone3_errno = ctypes.get_errno()
            # Missing CLONE_THREAD and a namespace/process flag are denied
            # before the kernel can create a process.
            clone_missing_thread = syscall(56, 0, 0, 0, 0, 0)
            clone_missing_thread_errno = ctypes.get_errno()
            clone_namespace = syscall(56, 0x00010100 | 0x02000000, 0, 0, 0, 0)
            clone_namespace_errno = ctypes.get_errno()
            print(json.dumps({
                "network": network,
                "limits": limits,
                "socketDenials": socket_denials,
                "execDenied": exec_denied,
                "threadCreated": thread_created,
                "forkDenied": fork_denied,
                "clone3Errno": clone3_errno,
                "clone3Result": clone3_result,
                "cloneMissingThreadErrno": clone_missing_thread_errno,
                "cloneMissingThreadResult": clone_missing_thread,
                "cloneNamespaceErrno": clone_namespace_errno,
                "cloneNamespaceResult": clone_namespace,
            }, sort_keys=True))
            """
        )
        completed = subprocess.run(
            [sys.executable, "-c", child, str(WORKER_ROOT)],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        evidence = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(evidence["network"]["seccompMode"], 2)
        self.assertTrue(evidence["network"]["noNewPrivileges"])
        self.assertEqual(evidence["network"]["externalCalls"], 0)
        self.assertEqual(evidence["network"]["ipv6Capability"], "not_verified")
        self.assertEqual(evidence["network"]["destinationReachabilityProbes"], "not_performed")
        self.assertEqual(evidence["socketDenials"], [True, True])
        self.assertTrue(evidence["execDenied"])
        self.assertTrue(evidence["threadCreated"])
        self.assertTrue(evidence["forkDenied"])
        self.assertEqual(evidence["clone3Result"], -1)
        self.assertEqual(evidence["clone3Errno"], 38)  # ENOSYS
        self.assertEqual(evidence["cloneMissingThreadResult"], -1)
        self.assertEqual(evidence["cloneMissingThreadErrno"], 1)  # EPERM
        self.assertEqual(evidence["cloneNamespaceResult"], -1)
        self.assertEqual(evidence["cloneNamespaceErrno"], 1)  # EPERM
        self.assertEqual(evidence["limits"]["cpuAffinityCount"], 1)
        self.assertEqual(evidence["limits"]["concurrency"], 1)
        self.assertTrue(evidence["limits"]["limitsVerified"])


if __name__ == "__main__":
    unittest.main()
