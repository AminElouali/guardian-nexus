import unittest

from guardian_ai_assessment.lab_host_preflight import evaluate_lab_host_observations


def _passing_observations():
    return {
        "host": {
            "osId": "ubuntu",
            "versionId": "24.04",
            "systemd": True,
            "container": False,
        },
        "identities": {
            "api": {"uid": 1101, "gid": 1101, "groups": [1101]},
            "worker": {"uid": 1102, "gid": 1102, "groups": [1102]},
            "broker": {"uid": 1103, "gid": 1103, "groups": [1103, 1200]},
        },
        "dockerSocket": {
            "status": "verified",
            "ownerUid": 0,
            "groupName": "guardian-docker-broker",
            "mode": 0o660,
            "aclChecked": True,
            "accessByRole": {
                "api": {"read": False, "write": False},
                "worker": {"read": False, "write": False},
                "broker": {"read": True, "write": True},
            },
        },
        "sensitiveEnvironmentNameCount": 0,
        "databaseSessions": {
            role: {
                "status": "verified",
                "sessionUser": f"guardian_{role}_login",
                "currentUser": f"guardian_{role}_login",
                "superuser": False,
                "bypassRls": False,
                "createRole": False,
                "createDatabase": False,
                "readOnly": True,
            }
            for role in ("api", "worker", "broker")
        },
        "qwenChildProbe": {
            "status": "verified",
            "probeType": "non_model_identity_probe",
            "uid": 1102,
            "dockerSocketAccessible": False,
            "inheritedSocketFdCount": 0,
            "sensitiveEnvironmentNameCount": 0,
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
    }


class LabHostPreflightTests(unittest.TestCase):
    def test_complete_mock_is_reported_as_synthetic_and_never_opens_execution_gate(self):
        result = evaluate_lab_host_observations(
            _passing_observations(),
            observation_origin="mocked_test_observation",
        )
        self.assertTrue(result["hostConditionsPassed"])
        self.assertFalse(result["hostBoundaryReady"])
        self.assertFalse(result["executionStarted"])
        self.assertFalse(result["qwenInferenceRun"])
        self.assertEqual(result["evidenceClass"], "synthetic_or_injected")
        self.assertTrue(result["databaseRoleSeparationVerified"])
        self.assertFalse(result["integratedAssessmentReady"])
        self.assertTrue(result["runtimeQwenGuardStillRequired"])

    def test_replit_like_shared_uid_socket_and_secret_presence_fail_closed(self):
        observations = _passing_observations()
        observations["host"] = {
            "osId": "nixos",
            "versionId": "unknown",
            "systemd": False,
            "container": True,
        }
        observations["identities"]["api"] = {
            "uid": 1000,
            "gid": 1000,
            "groups": [1000, 998],
        }
        observations["identities"]["worker"] = {
            "uid": 1000,
            "gid": 1000,
            "groups": [1000, 998],
        }
        observations["identities"]["broker"] = {
            "uid": 1000,
            "gid": 1000,
            "groups": [1000, 998],
        }
        observations["dockerSocket"] = {
            "status": "verified",
            "ownerUid": 0,
            "groupName": "runner",
            "mode": 0o660,
            "aclChecked": True,
            "accessByRole": {
                role: {"read": True, "write": True}
                for role in ("api", "worker", "broker")
            },
        }
        observations["sensitiveEnvironmentNameCount"] = 4
        observations["databaseSessions"] = None
        observations["qwenChildProbe"] = None
        observations["qwenSandbox"] = None
        result = evaluate_lab_host_observations(
            observations,
            observation_origin="mocked_replit_host_observation",
        )
        self.assertFalse(result["hostConditionsPassed"])
        self.assertFalse(result["hostBoundaryReady"])
        self.assertIn("lab_service_uids_not_distinct", result["reasonCodes"])
        self.assertIn("lab_docker_socket_access_not_denied_api", result["reasonCodes"])
        self.assertIn("lab_sensitive_environment_present", result["reasonCodes"])
        self.assertIn("lab_database_sessions_unverified", result["reasonCodes"])
        self.assertIn("lab_qwen_child_boundary_unverified", result["reasonCodes"])
        self.assertFalse(result["credentialValuesRead"])

    def test_worker_socket_access_and_privileged_database_role_are_rejected(self):
        observations = _passing_observations()
        observations["dockerSocket"]["accessByRole"]["worker"] = {
            "read": True,
            "write": True,
        }
        observations["databaseSessions"]["api"]["bypassRls"] = True
        result = evaluate_lab_host_observations(
            observations,
            observation_origin="mocked_test_observation",
        )
        self.assertIn("lab_docker_socket_access_not_denied_worker", result["reasonCodes"])
        self.assertIn("lab_api_database_privilege_excess", result["reasonCodes"])
        self.assertFalse(result["hostBoundaryReady"])

    def test_environment_output_contains_counts_not_secret_names_or_values(self):
        result = evaluate_lab_host_observations(
            _passing_observations(),
            observation_origin="mocked_test_observation",
        )
        encoded = str(result)
        self.assertNotIn("DATABASE_URL", encoded)
        self.assertNotIn("CLERK_SECRET_KEY", encoded)
        self.assertFalse(result["credentialValuesRead"])


if __name__ == "__main__":
    unittest.main()
