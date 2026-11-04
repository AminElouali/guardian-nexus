import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from typing import Iterator, Mapping
from unittest.mock import patch

WORKER_ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(WORKER_ROOT))

from guardian_ai_assessment.offline_isolation_preflight import (  # noqa: E402
    collect_offline_isolation_preflight,
    require_offline_qwen_process_ready,
)
from guardian_ai_assessment import offline_qwen_runner  # noqa: E402


class KeyOnlyEnvironment(Mapping[str, str]):
    """Environment test double that rejects every read of a value."""

    def __init__(self, names: set[str]):
        self._names = names

    def __getitem__(self, key: str) -> str:
        raise AssertionError(f"environment value must not be read: {key}")

    def __iter__(self) -> Iterator[str]:
        return iter(self._names)

    def __len__(self) -> int:
        return len(self._names)

    def __contains__(self, key: object) -> bool:
        return key in self._names


class OfflineIsolationPreflightTests(unittest.TestCase):
    identity = {"uid": 1000, "gid": 1000, "groups": [1000]}

    def test_absent_socket_and_no_sensitive_environment_allow_process_only_mode(self):
        report = collect_offline_isolation_preflight(
            environment=KeyOnlyEnvironment(set()),
            socket_paths=[Path("/path/that/does/not/exist/docker.sock")],
            identity=self.identity,
            inherited_socket_fds={"status": "clear", "count": 0},
        )
        self.assertTrue(report["offlineQwenProcessReady"])
        self.assertFalse(report["apiWorkerBoundaryReady"])
        self.assertFalse(report["integratedAssessmentReady"])
        self.assertEqual(report["brokerIdentity"]["status"], "unverified")
        self.assertEqual(
            report["apiWorkerDatabaseIdentity"]["status"], "unverified"
        )
        self.assertEqual(report["externalConnectionsMade"], 0)

    def test_effective_socket_access_blocks_without_connecting(self):
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("Unix sockets are unavailable")
        with tempfile.TemporaryDirectory(prefix="guardian-preflight-") as root:
            path = Path(root) / "docker.sock"
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                endpoint.bind(str(path))
            finally:
                endpoint.close()
            report = collect_offline_isolation_preflight(
                environment=KeyOnlyEnvironment(set()),
                socket_paths=[path],
                inherited_socket_fds={"status": "clear", "count": 0},
            )
        self.assertFalse(report["offlineQwenProcessReady"])
        self.assertIn("offline_docker_socket_accessible", report["reasonCodes"])
        self.assertTrue(report["dockerSocketChecks"][0]["connected"] is False)

    def test_configured_docker_endpoint_blocks_without_reading_or_echoing_value(self):
        secretish_value = "tcp://private-docker.invalid:2375"
        environment = KeyOnlyEnvironment({"DOCKER_HOST"})
        report = collect_offline_isolation_preflight(
            environment=environment,
            socket_paths=[Path("/missing/docker.sock")],
            identity=self.identity,
            inherited_socket_fds={"status": "clear", "count": 0},
        )
        encoded = json.dumps(report)
        self.assertFalse(report["offlineQwenProcessReady"])
        self.assertIn("offline_docker_endpoint_configured", report["reasonCodes"])
        self.assertNotIn(secretish_value, encoded)

    def test_database_credential_names_block_and_values_are_never_read(self):
        environment = KeyOnlyEnvironment({"DATABASE_URL", "APP_RUNTIME_DB_PASSWORD"})
        report = collect_offline_isolation_preflight(
            environment=environment,
            socket_paths=[Path("/missing/docker.sock")],
            identity=self.identity,
            inherited_socket_fds={"status": "clear", "count": 0},
        )
        self.assertFalse(report["offlineQwenProcessReady"])
        self.assertTrue(report["databaseCredentialEnvironmentPresent"])
        self.assertEqual(report["databaseCredentialVariableCount"], 2)
        self.assertFalse(report["credentialValuesRead"])
        self.assertFalse(
            report["apiWorkerDatabaseIdentity"]["credentialValuesRead"]
        )
        self.assertIn("offline_sensitive_environment_present", report["reasonCodes"])

    def test_unverified_socket_metadata_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="guardian-preflight-file-") as root:
            path = Path(root) / "docker.sock"
            path.write_text("not-a-socket", encoding="utf-8")
            report = collect_offline_isolation_preflight(
                environment=KeyOnlyEnvironment(set()),
                socket_paths=[path],
                identity=self.identity,
                inherited_socket_fds={"status": "clear", "count": 0},
            )
        self.assertFalse(report["offlineQwenProcessReady"])
        self.assertIn("offline_docker_socket_unverified", report["reasonCodes"])

    def test_root_and_inherited_socket_fd_fail_closed(self):
        for identity, fd_status, expected in (
            ({"uid": 0, "gid": 0, "groups": [0]}, {"status": "clear"}, "offline_runner_root_identity"),
            (self.identity, {"status": "present", "count": 1}, "offline_inherited_socket_fd_present"),
            (self.identity, {"status": "unverified", "count": None}, "offline_inherited_socket_fd_unverified"),
        ):
            with self.subTest(expected=expected):
                report = collect_offline_isolation_preflight(
                    environment=KeyOnlyEnvironment(set()),
                    socket_paths=[Path("/missing/docker.sock")],
                    identity=identity,
                    inherited_socket_fds=fd_status,
                )
                self.assertFalse(report["offlineQwenProcessReady"])
                self.assertIn(expected, report["reasonCodes"])

    def test_require_helper_returns_report_or_raises_a_safe_reason_code(self):
        with self.assertRaisesRegex(RuntimeError, "offline_docker_endpoint_configured"):
            require_offline_qwen_process_ready(
                environment=KeyOnlyEnvironment({"DOCKER_CONTEXT"}),
                socket_paths=[Path("/missing/docker.sock")],
            )

    def test_qwen_runner_stops_at_preflight_before_artifact_or_model_loading(self):
        with tempfile.TemporaryDirectory(prefix="guardian-qwen-preflight-order-") as root:
            workspace = Path(root)
            with (
                patch(
                    "guardian_ai_assessment.offline_isolation_preflight.require_offline_qwen_process_ready",
                    side_effect=RuntimeError("offline_docker_socket_accessible"),
                ) as preflight,
                patch.object(offline_qwen_runner, "_load_verified_manifests") as load_manifests,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "offline_docker_socket_accessible"
                ):
                    offline_qwen_runner.run_offline_evaluation(workspace)
            preflight.assert_called_once_with()
            load_manifests.assert_not_called()
            self.assertFalse(
                (workspace / "generated-artifacts/guardian-qwen-offline").exists()
            )


if __name__ == "__main__":
    unittest.main()
