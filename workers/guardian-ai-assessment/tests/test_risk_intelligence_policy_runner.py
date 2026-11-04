import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian_ai_assessment import risk_intelligence_policy_runner as runner


class RiskIntelligencePolicyRunnerTests(unittest.TestCase):
    def test_all_32_catalog_cases_are_policy_decisions_only(self):
        result = runner.run_risk_intelligence_policy_scenarios()

        self.assertEqual(result["scenarioCount"], 32)
        self.assertEqual(result["summary"]["policyDecisionsEvaluated"], 32)
        self.assertEqual(result["summary"]["expectedDecisionsMatched"], 32)
        self.assertEqual(result["summary"]["expectedReasonsMatched"], 32)
        self.assertEqual(result["summary"]["toolDispatches"], 0)
        self.assertEqual(result["summary"]["simulatorInvocations"], 0)
        self.assertEqual(result["summary"]["qwenCalls"], 0)
        self.assertEqual(result["summary"]["dockerInvocations"], 0)
        self.assertTrue(all(result["selfChecks"].values()))
        self.assertFalse(result["limits"]["fullStpaControlObjectivesVerified"])
        self.assertEqual(result["nativeToolCalls"], 0)
        self.assertEqual(result["adaptedModelProposals"], 0)

    def test_runner_never_calls_synthetic_tool_dispatcher(self):
        with patch(
            "guardian_ai_assessment.tool_adapter.call_synthetic_tool",
            side_effect=AssertionError("tool_dispatch_must_not_be_called"),
        ):
            result = runner.run_risk_intelligence_policy_scenarios()
        self.assertEqual(result["selfCheckStatus"], "passed")

    def test_manifest_duplicate_or_extra_fields_fail_closed(self):
        manifest = json.loads(runner.MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["scenarios"][1]["scenarioId"] = manifest["scenarios"][0]["scenarioId"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "risk_manifest_scenario_value_invalid"):
                runner.run_risk_intelligence_policy_scenarios(manifest_path=path)

        manifest = json.loads(runner.MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["scenarios"][0]["untrustedField"] = "ignored-fields-are-not-accepted"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "risk_manifest_scenario_schema_invalid"):
                runner.run_risk_intelligence_policy_scenarios(manifest_path=path)


if __name__ == "__main__":
    unittest.main()
