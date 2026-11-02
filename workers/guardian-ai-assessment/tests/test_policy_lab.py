import unittest

from guardian_ai_assessment.policy_lab import (
    PROFILE_TO_VERTICAL,
    run_policy_lab,
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
                    self.assertEqual(len(case["actionSha256"]), 64)
                    self.assertEqual(len(case["proposalSha256"]), 64)
                    self.assertEqual(len(case["caseEvidenceSha256"]), 64)
                    self.assertFalse(case["rawArgumentsStored"])
                    self.assertFalse(case["rawInstructionStored"])

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

    def test_hashes_are_repeatable_for_fixed_synthetic_proposals(self):
        first = run_policy_lab("guardian-agent-lab-email-v1")
        second = run_policy_lab("guardian-agent-lab-email-v1")
        self.assertEqual(
            [case["caseEvidenceSha256"] for case in first["cases"]],
            [case["caseEvidenceSha256"] for case in second["cases"]],
        )
        self.assertEqual(first["suiteEvidenceSha256"], second["suiteEvidenceSha256"])


if __name__ == "__main__":
    unittest.main()
