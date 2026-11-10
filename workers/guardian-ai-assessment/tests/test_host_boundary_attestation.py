import base64
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

WORKER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER_ROOT))

from guardian_ai_assessment import autonomous_tool_selection  # noqa: E402
from guardian_ai_assessment import host_boundary_attestation  # noqa: E402
from guardian_ai_assessment import llm_lab, offline_qwen_runner  # noqa: E402
from guardian_ai_assessment.host_boundary_attestation import (  # noqa: E402
    HostBoundaryAttestationError,
    _validate_payload,
    verify_host_boundary_attestation,
)


NOW = datetime(2026, 11, 10, 15, 0, tzinfo=timezone.utc)
SOURCE_HASHES = {
    name: f"{index:064x}"
    for index, name in enumerate(host_boundary_attestation._SOURCE_FILES, 1)
}


def _valid_payload():
    roles = {"api": "guardian_api", "broker": "guardian_broker", "worker": "guardian_worker"}
    return {
        "schemaVersion": 1,
        "attestationId": "lab-attestation-2026-11-10-01",
        "issuer": "guardian-nexus-independent-host-verifier",
        "independentVerifierId": "security-review-opaque-id",
        "repository": "guardian-nexus-lab",
        "issuedAt": (NOW - timedelta(minutes=5)).isoformat(),
        "expiresAt": (NOW + timedelta(hours=1)).isoformat(),
        "hostBoundaryReady": True,
        "integratedAssessmentReady": True,
        "sensitiveEnvironmentNameCount": 0,
        "dockerSocketGroupGid": 1200,
        "serviceIdentities": {
            name: {
                "uid": uid,
                "gid": uid,
                "groups": [uid, 1200] if name == "broker" else [uid],
                "databaseRole": roles[name],
            }
            for name, uid in (("api", 1101), ("broker", 1103), ("worker", 1102))
        },
        "dockerSocketAccess": {
            "api": {"read": False, "write": False},
            "broker": {"read": True, "write": True},
            "worker": {"read": False, "write": False},
        },
        "databaseSessions": {
            name: {
                "databaseName": "guardian_lab_synthetic",
                "role": roles[name],
                "superuser": False,
                "bypassRls": False,
            }
            for name in ("api", "broker", "worker")
        },
        "qwenSandbox": {
            "networkNone": True,
            "readOnlyRoot": True,
            "capDropAll": True,
            "noNewPrivileges": True,
            "seccompVerified": True,
            "dockerSocketNotMounted": True,
            "imageIdPinned": True,
        },
        "sourceCodeSha256": dict(SOURCE_HASHES),
    }


class HostBoundaryAttestationTests(unittest.TestCase):
    def test_valid_contract_requires_distinct_identities_socket_and_database_roles(self):
        _validate_payload(
            _valid_payload(),
            now=NOW,
            expected_source_hashes=SOURCE_HASHES,
        )

    def test_stale_attestation_fails_closed(self):
        payload = _valid_payload()
        payload["expiresAt"] = (NOW - timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(
            HostBoundaryAttestationError,
            "assessment_host_attestation_expired_or_stale",
        ):
            _validate_payload(payload, now=NOW, expected_source_hashes=SOURCE_HASHES)

    def test_shared_service_uid_or_database_role_fails_closed(self):
        payload = _valid_payload()
        payload["serviceIdentities"]["worker"]["uid"] = payload[
            "serviceIdentities"
        ]["api"]["uid"]
        with self.assertRaisesRegex(
            HostBoundaryAttestationError,
            "assessment_host_identities_not_separate",
        ):
            _validate_payload(payload, now=NOW, expected_source_hashes=SOURCE_HASHES)

    def test_database_target_and_socket_group_are_part_of_the_signed_boundary(self):
        payload = _valid_payload()
        payload["databaseSessions"]["worker"]["databaseName"] = "production"
        with self.assertRaisesRegex(
            HostBoundaryAttestationError,
            "assessment_host_database_role_unverified",
        ):
            _validate_payload(payload, now=NOW, expected_source_hashes=SOURCE_HASHES)

        payload = _valid_payload()
        payload["serviceIdentities"]["api"]["groups"].append(1200)
        with self.assertRaisesRegex(
            HostBoundaryAttestationError,
            "assessment_host_socket_group_access_not_denied",
        ):
            _validate_payload(payload, now=NOW, expected_source_hashes=SOURCE_HASHES)

        payload = _valid_payload()
        payload["serviceIdentities"]["worker"]["databaseRole"] = "guardian_api"
        payload["databaseSessions"]["worker"]["role"] = "guardian_api"
        with self.assertRaisesRegex(
            HostBoundaryAttestationError,
            "assessment_host_identities_not_separate",
        ):
            _validate_payload(payload, now=NOW, expected_source_hashes=SOURCE_HASHES)

    def test_api_or_worker_socket_access_and_unverified_sandbox_fail_closed(self):
        payload = _valid_payload()
        payload["dockerSocketAccess"]["worker"]["read"] = True
        with self.assertRaisesRegex(
            HostBoundaryAttestationError,
            "assessment_host_socket_access_not_denied",
        ):
            _validate_payload(payload, now=NOW, expected_source_hashes=SOURCE_HASHES)

        payload = _valid_payload()
        payload["qwenSandbox"]["dockerSocketNotMounted"] = False
        with self.assertRaisesRegex(
            HostBoundaryAttestationError,
            "assessment_host_qwen_sandbox_unverified",
        ):
            _validate_payload(payload, now=NOW, expected_source_hashes=SOURCE_HASHES)

    def test_attestation_must_bind_the_exact_runner_and_policy_source_hashes(self):
        payload = _valid_payload()
        payload["sourceCodeSha256"]["qwenPolicyLab"] = "f" * 64
        with self.assertRaisesRegex(
            HostBoundaryAttestationError,
            "assessment_host_attestation_source_mismatch",
        ):
            _validate_payload(payload, now=NOW, expected_source_hashes=SOURCE_HASHES)

    def test_future_inference_bundle_hashes_all_gate_and_entrypoint_sources(self):
        hashes = offline_qwen_runner._source_code_hashes(WORKER_ROOT)
        expected = {
            "offlineRunner",
            "offlineProcessGuard",
            "hostBoundaryAttestation",
            "offlineIsolationPreflight",
            "llmLab",
            "autonomousToolSelection",
            "networkPreflight",
            "offlineQwenLauncher",
            "qwenPolicyLab",
        }
        self.assertEqual(set(hashes), expected)
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))

    def test_unavailable_attestation_blocks_without_launching_signature_tool(self):
        with tempfile.TemporaryDirectory(prefix="guardian-attestation-missing-") as root:
            root_path = Path(root)
            with (
                patch.object(host_boundary_attestation.os, "geteuid", return_value=1000),
                patch.object(
                    host_boundary_attestation,
                    "_verify_ed25519_signature",
                ) as verify_signature,
            ):
                with self.assertRaisesRegex(
                    HostBoundaryAttestationError,
                    "assessment_host_attestation_file_unavailable",
                ):
                    verify_host_boundary_attestation(
                        attestation_path=root_path / "missing.json",
                        public_key_path=root_path / "missing.pem",
                        now=NOW,
                        expected_source_hashes=SOURCE_HASHES,
                    )
            verify_signature.assert_not_called()

    def test_signed_attestation_is_parsed_and_verified_without_environment_overrides(self):
        payload = _valid_payload()
        envelope = {
            "payload": payload,
            "signatureAlgorithm": "Ed25519",
            "signatureBase64": base64.b64encode(b"s" * 64).decode("ascii"),
        }
        attestation_bytes = json.dumps(
            envelope, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        with (
            patch.object(host_boundary_attestation.os, "geteuid", return_value=1102),
            patch.object(host_boundary_attestation.os, "getegid", return_value=1102),
            patch.object(host_boundary_attestation.os, "getgroups", return_value=[1102]),
            patch.object(
                host_boundary_attestation,
                "_read_root_owned_file",
                side_effect=[attestation_bytes, b"root-installed-public-key"],
            ) as read_trusted_file,
            patch.object(
                host_boundary_attestation,
                "_verify_ed25519_signature",
            ) as verify_signature,
        ):
            result = verify_host_boundary_attestation(
                now=NOW,
                expected_source_hashes=SOURCE_HASHES,
            )

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["attestationId"], payload["attestationId"])
        self.assertEqual(
            result["independentVerifierId"], payload["independentVerifierId"]
        )
        self.assertEqual(read_trusted_file.call_count, 2)
        verify_signature.assert_called_once()

    def test_signed_attestation_must_match_the_current_worker_uid_gid_and_groups(self):
        payload = _valid_payload()
        envelope = {
            "payload": payload,
            "signatureAlgorithm": "Ed25519",
            "signatureBase64": base64.b64encode(b"s" * 64).decode("ascii"),
        }
        attestation_bytes = json.dumps(
            envelope, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        mismatched_identities = (
            (1101, 1101, [1101]),  # API UID instead of worker UID.
            (1102, 1101, [1102, 1101]),  # Unexpected effective GID.
            (1102, 1102, [1102, 1200]),  # Worker inherited broker socket group.
        )

        for uid, gid, groups in mismatched_identities:
            with self.subTest(uid=uid, gid=gid, groups=groups):
                with (
                    patch.object(host_boundary_attestation.os, "geteuid", return_value=uid),
                    patch.object(host_boundary_attestation.os, "getegid", return_value=gid),
                    patch.object(host_boundary_attestation.os, "getgroups", return_value=groups),
                    patch.object(
                        host_boundary_attestation,
                        "_read_root_owned_file",
                        side_effect=[attestation_bytes, b"root-installed-public-key"],
                    ),
                    patch.object(
                        host_boundary_attestation,
                        "_verify_ed25519_signature",
                    ) as verify_signature,
                ):
                    with self.assertRaisesRegex(
                        HostBoundaryAttestationError,
                        "assessment_host_runtime_identity_mismatch",
                    ):
                        verify_host_boundary_attestation(
                            now=NOW,
                            expected_source_hashes=SOURCE_HASHES,
                        )
                verify_signature.assert_called_once()

    def test_unreadable_current_worker_groups_fail_closed(self):
        payload = _valid_payload()
        envelope = {
            "payload": payload,
            "signatureAlgorithm": "Ed25519",
            "signatureBase64": base64.b64encode(b"s" * 64).decode("ascii"),
        }
        attestation_bytes = json.dumps(
            envelope, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        with (
            patch.object(host_boundary_attestation.os, "geteuid", return_value=1102),
            patch.object(host_boundary_attestation.os, "getegid", return_value=1102),
            patch.object(
                host_boundary_attestation.os,
                "getgroups",
                side_effect=OSError("synthetic unavailable"),
            ),
            patch.object(
                host_boundary_attestation,
                "_read_root_owned_file",
                side_effect=[attestation_bytes, b"root-installed-public-key"],
            ),
            patch.object(
                host_boundary_attestation,
                "_verify_ed25519_signature",
            ) as verify_signature,
        ):
            with self.assertRaisesRegex(
                HostBoundaryAttestationError,
                "assessment_host_runtime_identity_unavailable",
            ):
                verify_host_boundary_attestation(
                    now=NOW,
                    expected_source_hashes=SOURCE_HASHES,
                )
        verify_signature.assert_called_once()

    def test_offline_runner_fails_before_model_artifact_or_output_setup(self):
        with tempfile.TemporaryDirectory(prefix="guardian-runner-gate-") as root:
            workspace = Path(root)
            with (
                patch(
                    "guardian_ai_assessment.offline_isolation_preflight.collect_offline_isolation_preflight",
                    return_value={"offlineQwenProcessReady": True},
                ),
                patch(
                    "guardian_ai_assessment.host_boundary_attestation.require_host_boundary_attestation",
                    side_effect=HostBoundaryAttestationError(
                        "assessment_host_attestation_file_unavailable"
                    ),
                ),
                patch.object(
                    offline_qwen_runner, "_load_verified_manifests"
                ) as load_manifests,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "assessment_host_attestation_file_unavailable",
                ):
                    offline_qwen_runner.run_offline_evaluation(workspace)
            load_manifests.assert_not_called()
            self.assertFalse(
                (
                    workspace
                    / "generated-artifacts/guardian-qwen-offline"
                ).exists()
            )

    def test_all_live_model_paths_fail_before_model_or_runtime_setup(self):
        entrypoints = (
            llm_lab.run_real_evaluation,
            llm_lab.run_invoice_integration_job,
            llm_lab.run_native_tool_suite_job,
            autonomous_tool_selection.run_autonomous_tool_selection_job,
        )
        for entrypoint in entrypoints:
            with self.subTest(entrypoint=entrypoint.__name__):
                with (
                    patch(
                        "guardian_ai_assessment.offline_isolation_preflight.require_offline_qwen_process_ready",
                        side_effect=RuntimeError(
                            "assessment_host_attestation_file_unavailable"
                        ),
                    ) as gate,
                    patch.object(llm_lab, "_verify_model_artifact") as verify_model,
                    patch.object(llm_lab, "_read_cgroup_limits") as read_limits,
                    patch.object(llm_lab, "LocalQwenClient") as client,
                    patch("importlib.metadata.version") as runtime_version,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "assessment_host_attestation_file_unavailable",
                    ):
                        entrypoint()
                gate.assert_called_once_with()
                verify_model.assert_not_called()
                read_limits.assert_not_called()
                client.assert_not_called()
                runtime_version.assert_not_called()

    def test_model_client_constructor_checks_gate_before_loading_llama(self):
        with (
            patch(
                "guardian_ai_assessment.offline_isolation_preflight.require_offline_qwen_process_ready",
                side_effect=RuntimeError(
                    "assessment_host_attestation_file_unavailable"
                ),
            ) as gate,
            patch.object(llm_lab, "_assert_diskcache_runtime_absent") as cache_check,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "assessment_host_attestation_file_unavailable",
            ):
                llm_lab.LocalQwenClient(Path("/not-loaded/model.gguf"))
        gate.assert_called_once_with()
        cache_check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
