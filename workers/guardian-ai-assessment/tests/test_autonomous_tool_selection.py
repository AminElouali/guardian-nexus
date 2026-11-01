import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian_ai_assessment import autonomous_tool_selection as autonomous  # noqa: E402
from guardian_ai_assessment import llm_lab  # noqa: E402
from guardian_ai_assessment.tool_adapter import (  # noqa: E402
    INVOICE_ID,
    SIMULATED_RECIPIENT,
    SYNTHETIC_ACCOUNT_ID,
    SYNTHETIC_IBAN,
)


def test_network():
    return {
        "networkMode": "docker-network-none",
        "interfaces": ["lo", "sit0"],
        "activeNonLoopbackInterfaces": [],
        "publicIpv4": "blocked",
        "publicIpv6": "unavailable",
        "ipv6Capability": "kernel_protocol_unavailable",
        "publicDns": "blocked",
        "loopbackOnly": True,
    }


def test_container_limits():
    return {
        "cpuCores": 1,
        "cpuLimitVerified": True,
        "memoryBytes": 1_610_612_736,
        "memoryLimitVerified": True,
        "pids": 64,
        "pidsLimitVerified": True,
        "concurrency": 1,
    }


class AutoToolProvider:
    """Test double: asserts auto selection and returns only structured tool calls."""

    def __init__(self, *, first_call_wrong=False, no_calls=False):
        self.calls = []
        self.first_call_wrong = first_call_wrong
        self.no_calls = no_calls

    def complete_native(
        self, *, messages, seed, tool_choice, max_tokens=96
    ):
        self.calls.append((tool_choice, max_tokens))
        if tool_choice != "auto":
            raise AssertionError("every task must use tool_choice=auto")
        if max_tokens != autonomous.MAX_COMPLETION_TOKENS:
            raise AssertionError("autonomous budget must be used on every case")
        if self.no_calls:
            return self._response(content="No tool was selected.")

        prompt = messages[-1]["content"]
        if INVOICE_ID in prompt:
            name = "consult_synthetic_invoice"
            arguments = {"invoice_id": INVOICE_ID}
        elif SIMULATED_RECIPIENT in prompt:
            name = "send_email_simulated"
            arguments = {
                "recipient": SIMULATED_RECIPIENT,
                "subject": "Synthetic review",
                "body": "The synthetic review is complete.",
            }
        else:
            name = "request_bank_account_change"
            arguments = {
                "account_id": SYNTHETIC_ACCOUNT_ID,
                "new_iban": SYNTHETIC_IBAN,
            }
        if self.first_call_wrong and len(self.calls) == 1:
            name = "send_email_simulated"
            arguments = {
                "recipient": SIMULATED_RECIPIENT,
                "subject": "Wrong tool",
                "body": "This must be denied.",
            }
        return self._response(
            tool_call={
                "id": f"auto-call-{len(self.calls)}",
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(arguments),
                },
            },
            finish_reason="tool_calls",
        )

    @staticmethod
    def _response(*, content="", tool_call=None, finish_reason="stop"):
        message = {"role": "assistant", "content": content}
        if tool_call:
            message["tool_calls"] = [tool_call]
        return {
            "choices": [{"message": message, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 64, "completion_tokens": 20},
        }


class AutonomousToolSelectionTests(unittest.TestCase):
    def _evaluate(self, provider):
        return autonomous.evaluate_autonomous_tool_selection(
            provider,
            network=test_network(),
            container_limits=test_container_limits(),
            runtime_version="0.3.36",
        )

    def test_all_six_tasks_use_auto_and_record_synthetic_success(self):
        provider = AutoToolProvider()
        evidence = self._evaluate(provider)
        suite = evidence["nativeToolSuite"]
        self.assertEqual(provider.calls, [("auto", 128)] * 6)
        self.assertEqual(evidence["source"], "test_double")
        self.assertEqual(evidence["profileId"], autonomous.PROFILE_ID)
        self.assertEqual(evidence["toolInvocationMode"], "native_tool_calls")
        self.assertEqual(suite["sampleCount"], 6)
        self.assertEqual(suite["languageCounts"], {"en": 3, "es": 3})
        self.assertEqual(suite["splitSampleCounts"], {"calibration": 3, "holdout": 3})
        self.assertTrue(
            all(item["toolChoiceMode"] == "auto" for item in suite["caseEvidence"])
        )
        self.assertTrue(all(item["taskSucceeded"] for item in suite["caseEvidence"]))
        self.assertTrue(all(item["argumentsValid"] for item in suite["caseEvidence"]))
        self.assertTrue(all(item["policyAllowed"] for item in suite["caseEvidence"]))
        self.assertTrue(all(item["simulatedExecution"] for item in suite["caseEvidence"]))
        self.assertEqual(suite["taskSuccess"]["numerator"], 6)
        self.assertEqual(suite["taskSuccess"]["denominator"], 6)
        self.assertEqual(suite["toolSummary"]["nativeCallsObserved"], 6)
        self.assertEqual(suite["toolSummary"]["authorizedExecutions"], 6)
        self.assertEqual(suite["toolSummary"]["deniedCalls"], 0)
        self.assertEqual(suite["toolSummary"]["externalCalls"], 0)
        self.assertEqual(suite["toolSummary"]["stateChanges"], 0)
        self.assertEqual(suite["nativeCapabilityProbe"]["toolChoice"], "auto")
        self.assertTrue(suite["nativeCapabilityProbe"]["toolCallObserved"])
        self.assertEqual(evidence["rawPromptsStored"], False)
        self.assertEqual(evidence["rawResponsesStored"], False)
        self.assertEqual(evidence["rawToolArgumentsStored"], False)

        serialized = json.dumps(evidence)
        self.assertNotIn(SIMULATED_RECIPIENT, serialized)
        self.assertNotIn(SYNTHETIC_IBAN, serialized)
        self.assertNotIn("The synthetic review is complete.", serialized)

    def test_wrong_native_tool_is_denied_by_external_policy(self):
        evidence = self._evaluate(AutoToolProvider(first_call_wrong=True))
        first = evidence["nativeToolSuite"]["caseEvidence"][0]
        self.assertEqual(first["toolChoiceMode"], "auto")
        self.assertTrue(first["unauthorizedProposal"])
        self.assertTrue(first["unauthorizedAttempt"])
        self.assertFalse(first["unauthorizedExecution"])
        self.assertFalse(first["argumentsValid"])
        self.assertFalse(first["policyAllowed"])
        self.assertFalse(first["simulatedExecution"])
        self.assertFalse(first["taskSucceeded"])
        self.assertEqual(first["deniedCount"], 1)
        self.assertEqual(evidence["nativeToolSuite"]["toolSummary"]["externalCalls"], 0)

    def test_no_autonomous_calls_are_reported_as_failures_without_forcing(self):
        provider = AutoToolProvider(no_calls=True)
        evidence = self._evaluate(provider)
        suite = evidence["nativeToolSuite"]
        self.assertEqual(provider.calls, [("auto", 128)] * 6)
        self.assertEqual(suite["toolSummary"]["nativeCallsObserved"], 0)
        self.assertEqual(suite["taskSuccess"]["numerator"], 0)
        self.assertEqual(suite["taskSuccess"]["denominator"], 6)
        self.assertTrue(all(not item["taskSucceeded"] for item in suite["caseEvidence"]))
        self.assertTrue(all(not item["argumentsValid"] for item in suite["caseEvidence"]))
        self.assertTrue(all(not item["policyAllowed"] for item in suite["caseEvidence"]))
        self.assertTrue(all(not item["simulatedExecution"] for item in suite["caseEvidence"]))
        self.assertFalse(suite["nativeCapabilityProbe"]["toolCallObserved"])


if __name__ == "__main__":
    unittest.main()
