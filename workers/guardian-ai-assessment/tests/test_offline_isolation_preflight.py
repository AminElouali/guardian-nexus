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
from guardian_ai_assessment import (  # noqa: E402
    offline_isolation_preflight,
    offline_qwen_runner,
)


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

    @staticmethod
    def _write_historical_artifact(root: Path) -> Path:
        adapted_ids = set(offline_qwen_runner._PROFILE_ORDER[:-1])
        profiles = []
        for profile_id in offline_qwen_runner._PROFILE_ORDER:
            origin = (
                "guardian_qwen_native_markup_adapter"
                if profile_id in adapted_ids
                else "no_tool_call"
            )
            native = 0
            adapted = int(origin == "guardian_qwen_native_markup_adapter")
            no_proposal = int(origin == "no_tool_call")
            case = {
                "toolChoice": "auto",
                "toolCallOrigin": origin,
                "rawPromptStored": False,
                "rawResponseStored": False,
                "rawArgumentsStored": False,
                # Must never be copied into the read-only summary.
                "promptText": "synthetic-secret-sentinel",
            }
            profiles.append(
                {
                    "profileId": profile_id,
                    "cases": [case],
                    "summary": {
                        "modelCalls": 1,
                        "runtimeMessageToolCalls": native,
                        "adaptedQwenMarkupCalls": adapted,
                        "noToolCalls": no_proposal,
                    },
                }
            )
        artifact = {
            "schemaVersion": 1,
            "status": "completed",
            "executionMode": "real_local_qwen_inference_offline_process_guard",
            "sourceCodeSha256": {
                name: "b" * 64
                for name in (
                    "offlineRunner",
                    "offlineProcessGuard",
                    "qwenPolicyLab",
                )
            },
            "scope": {
                "profileCount": len(offline_qwen_runner._PROFILE_ORDER),
                "fixturesIncluded": False,
            },
            "profiles": profiles,
            "summary": {
                "modelCalls": 8,
                "runtimeMessageToolCalls": 0,
                "adaptedQwenMarkupCalls": 7,
                "noToolCalls": 1,
                "policyOffExecutions": 0,
                "externalCalls": 0,
                "unauthorizedExecutions": 0,
            },
        }
        artifact["bundleSha256"] = offline_qwen_runner._canonical_sha256(artifact)
        artifact_path = (
            root
            / "generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json"
        )
        artifact_path.parent.mkdir(parents=True)
        artifact_path.write_text(
            json.dumps(artifact, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        return artifact_path

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
        self.assertEqual(
            report["apiWorkerBoundaryReasonCodes"],
            [
                "assessment_broker_identity_unverified",
                "assessment_database_session_identity_unverified",
            ],
        )
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

    def test_process_only_preflight_never_authorizes_qwen_without_host_boundary(self):
        report = {
            "offlineQwenProcessReady": True,
            "reasonCodes": [],
            "apiWorkerBoundaryReady": False,
            "apiWorkerBoundaryReasonCodes": [
                "assessment_broker_identity_unverified",
                "assessment_database_session_identity_unverified",
            ],
            "integratedAssessmentReady": False,
        }
        with patch.object(
            offline_isolation_preflight,
            "collect_offline_isolation_preflight",
            return_value=report,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "assessment_broker_identity_unverified"
            ):
                require_offline_qwen_process_ready()

    def test_full_qwen_runner_stops_before_artifacts_when_boundary_is_unverified(self):
        report = {
            "offlineQwenProcessReady": True,
            "reasonCodes": [],
            "apiWorkerBoundaryReady": False,
            "apiWorkerBoundaryReasonCodes": [
                "assessment_broker_identity_unverified",
                "assessment_database_session_identity_unverified",
            ],
            "integratedAssessmentReady": False,
        }
        with tempfile.TemporaryDirectory(prefix="guardian-qwen-boundary-order-") as root:
            workspace = Path(root)
            with (
                patch.object(
                    offline_isolation_preflight,
                    "collect_offline_isolation_preflight",
                    return_value=report,
                ),
                patch.object(
                    offline_qwen_runner, "_load_verified_manifests"
                ) as load_manifests,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "assessment_broker_identity_unverified"
                ):
                    offline_qwen_runner.run_offline_evaluation(workspace)
            load_manifests.assert_not_called()
            self.assertFalse(
                (workspace / "generated-artifacts/guardian-qwen-offline").exists()
            )

    def test_profile_readiness_matrix_lists_eight_profiles_without_fake_counts(self):
        report = {
            "offlineQwenProcessReady": True,
            "reasonCodes": [],
            "apiWorkerBoundaryReady": False,
            "apiWorkerBoundaryReasonCodes": [
                "assessment_broker_identity_unverified"
            ],
            "integratedAssessmentReady": False,
        }
        matrix = offline_qwen_runner.offline_profile_readiness_matrix(report)
        self.assertEqual(
            [item["profileId"] for item in matrix],
            [
                "guardian-agent-qwen-lab-email-v1",
                "guardian-agent-qwen-lab-database-v1",
                "guardian-agent-qwen-lab-finance-v1",
                "guardian-agent-qwen-lab-programming-v1",
                "guardian-agent-qwen-lab-customer-service-v1",
                "guardian-agent-qwen-lab-browser-v1",
                "guardian-agent-qwen-lab-infrastructure-v1",
                "guardian-agent-qwen-lab-multiagent-v1",
            ],
        )
        self.assertTrue(all(len(item["selectedCaseIds"]) == 1 for item in matrix))
        self.assertTrue(
            all(item["suiteStatus"] == "blocked_host_boundary" for item in matrix)
        )
        self.assertTrue(all(item["qwenInferenceCount"] is None for item in matrix))
        self.assertTrue(all(item["nativeToolCalls"] is None for item in matrix))
        self.assertTrue(all(item["adaptedMarkerProposals"] is None for item in matrix))
        self.assertTrue(all(item["noProposal"] is None for item in matrix))
        self.assertTrue(
            all(
                item["fixtureBaseline"] == "separate_not_loaded"
                for item in matrix
            )
        )

    def test_historical_evidence_summary_keeps_adapted_native_and_no_proposal_separate(self):
        with tempfile.TemporaryDirectory(prefix="guardian-historical-evidence-") as root:
            self._write_historical_artifact(Path(root))
            report = offline_qwen_runner.inspect_historical_offline_evidence(
                Path(root),
                current_source_hashes={
                    name: "a" * 64
                    for name in (
                        "offlineRunner",
                        "offlineProcessGuard",
                        "qwenPolicyLab",
                    )
                },
            )
        encoded = json.dumps(report)
        self.assertEqual(report["status"], "historical_artifact_consistent")
        self.assertEqual(
            report["bundleIntegrity"], "self_hash_valid_not_authenticating"
        )
        self.assertEqual(report["sourceCurrentness"], "historical_source_hash_mismatch")
        self.assertEqual(report["profileCount"], 8)
        self.assertEqual(report["modelCalls"], 8)
        self.assertEqual(report["nativeMessageToolCalls"], 0)
        self.assertEqual(report["adaptedQwenMarkerProposals"], 7)
        self.assertEqual(report["noProposal"], 1)
        self.assertFalse(report["fixturesIncluded"])
        self.assertFalse(report["freshInferenceVerified"])
        self.assertFalse(report["rawPromptsResponsesArgumentsReturned"])
        self.assertNotIn("synthetic-secret-sentinel", encoded)
        self.assertNotIn("promptText", encoded)
        self.assertEqual(
            set(report["profileSummaries"][0]),
            {
                "profileId",
                "modelCalls",
                "nativeMessageToolCalls",
                "adaptedQwenMarkerProposals",
                "noProposal",
                "fixtureBaseline",
            },
        )

    def test_historical_evidence_missing_or_tampered_fails_closed_without_counts(self):
        with tempfile.TemporaryDirectory(prefix="guardian-historical-evidence-") as root:
            missing = offline_qwen_runner.inspect_historical_offline_evidence(Path(root))
            artifact_path = self._write_historical_artifact(Path(root))
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            artifact["profiles"][0]["cases"][0]["toolCallOrigin"] = "unknown_origin"
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            tampered = offline_qwen_runner.inspect_historical_offline_evidence(
                Path(root),
                current_source_hashes={
                    name: "a" * 64
                    for name in (
                        "offlineRunner",
                        "offlineProcessGuard",
                        "qwenPolicyLab",
                    )
                },
            )
        self.assertEqual(missing["status"], "not_available")
        self.assertIsNone(missing["modelCalls"])
        self.assertEqual(tampered["status"], "artifact_bundle_hash_mismatch")
        self.assertIsNone(tampered["modelCalls"])
        self.assertFalse(tampered["freshInferenceVerified"])

    def test_historical_evidence_rejects_unknown_origin_when_hash_is_recomputed(self):
        with tempfile.TemporaryDirectory(prefix="guardian-historical-origin-") as root:
            artifact_path = self._write_historical_artifact(Path(root))
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            artifact["profiles"][0]["cases"][0]["toolCallOrigin"] = "unknown_origin"
            artifact.pop("bundleSha256")
            artifact["bundleSha256"] = offline_qwen_runner._canonical_sha256(artifact)
            artifact_path.write_text(
                json.dumps(artifact, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            report = offline_qwen_runner.inspect_historical_offline_evidence(
                Path(root),
                current_source_hashes={
                    name: "a" * 64
                    for name in (
                        "offlineRunner",
                        "offlineProcessGuard",
                        "qwenPolicyLab",
                    )
                },
            )
        self.assertEqual(report["status"], "artifact_tool_origin_unrecognized")
        self.assertIsNone(report["nativeMessageToolCalls"])
        self.assertFalse(report["freshInferenceVerified"])

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
