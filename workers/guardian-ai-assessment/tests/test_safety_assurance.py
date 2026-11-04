import unittest

from guardian_ai_assessment.policy_lab import run_policy_lab
from guardian_ai_assessment.safety_assurance import (
    COMMON_PREVENTIVE_BARRIERS,
    COMMON_RECOVERY_BARRIERS,
    SAFETY_CASES,
    get_safety_case,
)


class SafetyAssuranceTests(unittest.TestCase):
    def test_catalog_covers_eight_distinct_fixture_profiles_and_four_lenses(self):
        self.assertEqual(len(SAFETY_CASES), 8)
        self.assertEqual(len({case.profile_id for case in SAFETY_CASES}), 8)
        self.assertEqual(len({case.vertical for case in SAFETY_CASES}), 8)
        self.assertTrue(COMMON_PREVENTIVE_BARRIERS)
        self.assertTrue(COMMON_RECOVERY_BARRIERS)

        for case in SAFETY_CASES:
            with self.subTest(profile=case.profile_id):
                self.assertTrue(case.stpa_hazard)
                self.assertTrue(case.safety_constraint)
                self.assertTrue(case.bow_tie_threat)
                self.assertTrue(case.top_event)
                self.assertTrue(case.consequence)
                self.assertTrue(case.fmea_failure_mode)
                self.assertTrue(case.fmea_detection)
                self.assertGreaterEqual(len(case.preventive_barriers), 3)
                self.assertGreaterEqual(len(case.recovery_barriers), 3)

    def test_explanatory_catalog_does_not_become_policy_authority(self):
        for case in SAFETY_CASES:
            with self.subTest(profile=case.profile_id):
                self.assertFalse(hasattr(case, "decision"))
                self.assertFalse(hasattr(case, "policy"))
                self.assertIs(get_safety_case(case.profile_id), case)
        self.assertIsNone(get_safety_case("caller-selected-profile"))

    def test_each_safety_case_matches_real_deterministic_fixture_control_flow(self):
        for safety_case in SAFETY_CASES:
            with self.subTest(profile=safety_case.profile_id):
                evidence = run_policy_lab(safety_case.profile_id)
                self.assertEqual(evidence["engine"], "guardian_policy_lab")
                self.assertEqual(evidence["executionMode"], "deterministic_fixture")
                self.assertIs(evidence["modelInference"], False)

                by_id = {item["caseId"]: item for item in evidence["cases"]}
                for expected in safety_case.expected_controls:
                    item = by_id[expected.case_id]
                    policy_on = item["policyOn"]
                    policy_trace = item["toolTrace"]["policyOn"]
                    self.assertEqual(policy_on["decision"], expected.decision)
                    self.assertEqual(
                        policy_trace["dispatchStatus"], expected.dispatch_status
                    )
                    self.assertIs(item["unauthorizedActionExecuted"], False)
                    if expected.decision in {"deny", "require_approval"}:
                        self.assertIs(policy_trace["invoked"], False)
                        self.assertEqual(policy_trace["events"], [])
                    if expected.decision == "deny":
                        self.assertIs(item["policyOff"]["executed"], False)
                        self.assertEqual(
                            item["policyOff"]["mode"], "counterfactual_clone_only"
                        )


if __name__ == "__main__":
    unittest.main()
