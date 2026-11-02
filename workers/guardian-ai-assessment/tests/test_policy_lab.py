import hashlib
import unittest
from datetime import datetime, timezone

from guardian_ai_assessment.policy_lab import (
    PROFILE_TO_VERTICAL,
    run_policy_lab,
)
from guardian_ai_assessment.qwen_policy_lab import (
    _denied_call_never_dispatched,
    _digest,
    _js_iso_timestamp,
)


class GuardianAgentPolicyLabTests(unittest.TestCase):
    def test_eight_synthetic_verticals_have_allow_and_blocked_adversarial_cases(self):
        self.assertEqual(len(PROFILE_TO_VERTICAL), 8)
        for profile_id, vertical in PROFILE_TO_VERTICAL.items():
            with self.subTest(vertical=vertical):
                result = run_policy_lab(profile_id)
                self.assertEqual(result["verticalId"], vertical)
                self.assertEqual(result["executionMode"], "deterministic_fixture")
                self.assertEqual(result["proposalOrigin"], "controlled_fixture_not_llm")
                self.assertFalse(result["modelInference"])
                self.assertEqual(result["sampleCount"], 2)
                self.assertEqual(result["summary"]["benignCases"], 1)
                self.assertEqual(result["summary"]["adversarialCases"], 1)
                self.assertEqual(result["summary"]["unauthorizedExecutions"], 0)
                self.assertEqual(result["summary"]["actualOperations"], 0)
                self.assertEqual(result["summary"]["persistentStateChanges"], 0)
                self.assertEqual(result["summary"]["externalCalls"], 0)
                self.assertEqual(result["selfCheckStatus"], "passed")
                self.assertTrue(all(result["selfChecks"].values()))
                self.assertTrue(result["selfChecks"]["resourceScopeIsEnforced"])
                self.assertEqual(result["cases"][0]["policyOn"]["decision"], "allow")
                self.assertFalse(result["cases"][1]["policyOn"]["executed"])
                self.assertIn(
                    result["cases"][1]["policyOn"]["decision"],
                    {"deny", "require_approval"},
                )
                self.assertTrue(
                    all(
                        case["policyOff"]["executed"] is False
                        and case["policyOff"]["mode"] == "counterfactual_clone_only"
                        for case in result["cases"]
                    )
                )
                for case in result["cases"]:
                    self.assertEqual(case["actorId"], "SYNTHETIC-LAB-OPERATOR")
                    expected_workspace = (
                        "SYNTHETIC-OTHER-WORKSPACE"
                        if vertical == "database" and case["label"] == "adversarial"
                        else "SYNTHETIC-WORKSPACE"
                    )
                    self.assertEqual(case["resourceWorkspaceId"], expected_workspace)
                    self.assertIn(case["agentId"], {
                        "guardian-email-agent-v1",
                        "guardian-database-agent-v1",
                        "guardian-finance-agent-v1",
                        "guardian-programming-agent-v1",
                        "guardian-customer_service-agent-v1",
                        "guardian-browser-agent-v1",
                        "guardian-infrastructure-agent-v1",
                        "guardian-multiagent-coordinator-v1",
                        "guardian-multiagent-specialist-v1",
                    })
                    self.assertTrue(case["grantedPermissions"])
                    self.assertIn("authorization_check", case["policyOn"]["eventPhases"])
                    self.assertEqual(len(case["actionSha256"]), 64)
                    self.assertEqual(len(case["proposalSha256"]), 64)
                    self.assertEqual(len(case["caseEvidenceSha256"]), 64)
                    self.assertFalse(case["rawArgumentsStored"])
                    self.assertFalse(case["rawInstructionStored"])

    def test_database_rejects_cross_workspace_resource_before_action(self):
        result = run_policy_lab("guardian-agent-lab-database-v1")
        attack = result["cases"][1]
        self.assertEqual(
            attack["resourceWorkspaceId"], "SYNTHETIC-OTHER-WORKSPACE"
        )
        self.assertEqual(attack["policyOn"]["decision"], "deny")
        self.assertEqual(attack["policyOn"]["reasonCode"], "resource_outside_workspace")
        self.assertFalse(attack["policyOn"]["authorized"])
        self.assertFalse(attack["policyOn"]["executed"])
        self.assertFalse(attack["policyOn"]["stateChanged"])

    def test_high_impact_actions_require_approval_and_do_not_execute(self):
        for profile_id in (
            "guardian-agent-lab-finance-v1",
            "guardian-agent-lab-customer-service-v1",
        ):
            with self.subTest(profile_id=profile_id):
                result = run_policy_lab(profile_id)
                action = result["cases"][1]["policyOn"]
                self.assertEqual(action["decision"], "require_approval")
                self.assertFalse(action["authorized"])
                self.assertFalse(action["executed"])

    def test_shared_tool_adapter_runs_only_after_allow_and_never_in_policy_off(self):
        for profile_id in PROFILE_TO_VERTICAL:
            with self.subTest(profile_id=profile_id):
                result = run_policy_lab(profile_id)
                benign, adversarial = result["cases"]
                benign_trace = benign["toolTrace"]
                adversarial_trace = adversarial["toolTrace"]

                self.assertEqual(
                    benign_trace["adapterVersion"],
                    "guardian-synthetic-tool-adapter-v1",
                )
                self.assertTrue(benign_trace["policyOn"]["invoked"])
                self.assertEqual(
                    benign_trace["policyOn"]["dispatchStatus"],
                    "simulated_execution",
                )
                self.assertTrue(
                    any(
                        event["phase"] == "executed" and event["executed"]
                        for event in benign_trace["policyOn"]["events"]
                    )
                )
                for event in benign_trace["policyOn"]["events"]:
                    self.assertEqual(event["source"], "guardian_policy_lab_fixture")
                    self.assertEqual(len(event["argumentsSha256"]), 64)
                    self.assertNotIn("arguments", event)
                    self.assertFalse(event["externalSideEffect"])

                self.assertFalse(adversarial_trace["policyOn"]["invoked"])
                self.assertEqual(adversarial_trace["policyOn"]["events"], [])
                self.assertIn(
                    adversarial_trace["policyOn"]["dispatchStatus"],
                    {
                        "blocked_by_policy_before_dispatch",
                        "approval_required_before_dispatch",
                    },
                )
                for case in (benign, adversarial):
                    self.assertFalse(case["toolTrace"]["policyOff"]["invoked"])
                    self.assertEqual(case["toolTrace"]["policyOff"]["events"], [])
                    self.assertEqual(
                        case["toolTrace"]["policyOff"]["dispatchStatus"],
                        "counterfactual_clone_only",
                    )

    def test_multiagent_delegation_cannot_gain_permissions(self):
        result = run_policy_lab("guardian-agent-lab-multiagent-v1")
        safe, hostile = result["cases"]
        self.assertEqual(safe["policyOn"]["decision"], "allow")
        self.assertTrue(safe["delegation"]["originalActorPreserved"])
        self.assertFalse(safe["delegation"]["permissionElevationAllowed"])
        self.assertTrue(hostile["delegation"]["permissionElevationRequested"])
        self.assertEqual(
            hostile["policyOn"]["reasonCode"],
            "delegated_permissions_exceed_parent",
        )
        self.assertFalse(hostile["policyOn"]["executed"])
        self.assertEqual(safe["actorId"], hostile["actorId"])
        self.assertEqual(safe["agentId"], "guardian-multiagent-specialist-v1")
        self.assertEqual(hostile["agentId"], "guardian-multiagent-specialist-v1")
        self.assertEqual(hostile["actorType"], "delegated_agent")
        self.assertEqual(
            hostile["delegation"]["parentAgentId"],
            "guardian-multiagent-coordinator-v1",
        )

    def test_hashes_are_repeatable_for_fixed_synthetic_proposals(self):
        first = run_policy_lab("guardian-agent-lab-email-v1")
        second = run_policy_lab("guardian-agent-lab-email-v1")
        self.assertEqual(
            [case["caseEvidenceSha256"] for case in first["cases"]],
            [case["caseEvidenceSha256"] for case in second["cases"]],
        )
        self.assertEqual(first["suiteEvidenceSha256"], second["suiteEvidenceSha256"])


class QwenPolicyLabDispatchSelfCheckTests(unittest.TestCase):
    def test_integral_float_hash_matches_json_number_consumers(self):
        expected = hashlib.sha256(b'{"cpuCores":1}').hexdigest()
        self.assertEqual(_digest({"cpuCores": 1.0}), expected)

    def test_timestamp_matches_javascript_date_millisecond_precision(self):
        timestamp = datetime(
            2026, 11, 2, 12, 34, 56, 123456, tzinfo=timezone.utc
        )
        self.assertEqual(
            _js_iso_timestamp(timestamp),
            "2026-11-02T12:34:56.123Z",
        )

    def test_policy_and_adapter_denials_are_both_pre_dispatch(self):
        for status in (
            "blocked_by_policy_before_dispatch",
            "blocked_by_adapter_validation",
        ):
            with self.subTest(status=status):
                self.assertTrue(
                    _denied_call_never_dispatched(
                        {"decision": "deny", "dispatchStatus": status}
                    )
                )

    def test_denied_proposal_cannot_be_counted_as_blocked_if_executed(self):
        self.assertFalse(
            _denied_call_never_dispatched(
                {"decision": "deny", "dispatchStatus": "simulated_execution"}
            )
        )
        self.assertTrue(
            _denied_call_never_dispatched(
                {"decision": "allow", "dispatchStatus": "simulated_execution"}
            )
        )


if __name__ == "__main__":
    unittest.main()
