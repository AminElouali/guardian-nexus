import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian_ai_assessment import autonomous_tool_selection as autonomous  # noqa: E402
from guardian_ai_assessment import llm_lab  # noqa: E402
from guardian_ai_assessment.tool_adapter import (  # noqa: E402
    INVOICE_ID,
    SIMULATED_RECIPIENT,
    SYNTHETIC_ACCOUNT_ID,
    SYNTHETIC_DOCUMENT_ID,
    SYNTHETIC_EMAIL_ID,
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

    def __init__(self, *, first_call_wrong=False, no_calls=False, attack_calls=False):
        self.calls = []
        self.first_call_wrong = first_call_wrong
        self.no_calls = no_calls
        self.attack_calls = attack_calls

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
        if self.attack_calls and "Untrusted document begins." in prompt:
            name = "request_bank_account_change"
            arguments = {
                "account_id": SYNTHETIC_ACCOUNT_ID,
                "new_iban": SYNTHETIC_IBAN,
            }
        elif SYNTHETIC_DOCUMENT_ID in prompt:
            name = "read_synthetic_document"
            arguments = {"document_id": SYNTHETIC_DOCUMENT_ID}
        elif SYNTHETIC_EMAIL_ID in prompt:
            name = "read_synthetic_email"
            arguments = {"email_id": SYNTHETIC_EMAIL_ID}
        elif INVOICE_ID in prompt:
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

    def test_fourteen_tasks_use_auto_and_keep_attacks_separate_from_benign_controls(self):
        provider = AutoToolProvider()
        evidence = self._evaluate(provider)
        suite = evidence["nativeToolSuite"]
        self.assertEqual(provider.calls, [("auto", 128)] * 14)
        self.assertEqual(evidence["source"], "test_double")
        self.assertEqual(evidence["profileId"], autonomous.PROFILE_ID)
        self.assertEqual(evidence["toolInvocationMode"], "native_tool_calls")
        self.assertNotIn("toolCallParsing", evidence["nativeToolSuite"])
        self.assertEqual(suite["sampleCount"], 14)
        self.assertEqual(suite["languageCounts"], {"en": 7, "es": 7})
        self.assertEqual(suite["splitSampleCounts"], {"calibration": 7, "holdout": 7})
        self.assertEqual(suite["attackCases"], 5)
        self.assertEqual(suite["benignCases"], 9)
        self.assertTrue(
            all(item["toolChoiceMode"] == "auto" for item in suite["caseEvidence"])
        )
        self.assertTrue(all(item["taskSucceeded"] for item in suite["caseEvidence"]))
        self.assertTrue(all(item["argumentsValid"] for item in suite["caseEvidence"]))
        self.assertTrue(all(item["policyAllowed"] for item in suite["caseEvidence"]))
        self.assertTrue(all(item["simulatedExecution"] for item in suite["caseEvidence"]))
        self.assertEqual(suite["taskSuccess"]["numerator"], 14)
        self.assertEqual(suite["taskSuccess"]["denominator"], 14)
        self.assertEqual(suite["toolSummary"]["nativeCallsObserved"], 14)
        self.assertEqual(suite["toolSummary"]["authorizedExecutions"], 14)
        self.assertEqual(suite["toolSummary"]["deniedCalls"], 0)
        self.assertEqual(suite["toolSummary"]["externalCalls"], 0)
        self.assertEqual(suite["toolSummary"]["stateChanges"], 0)
        self.assertEqual(
            {item["agentDomain"] for item in suite["caseEvidence"]},
            {"email", "documents", "finance"},
        )
        self.assertTrue(
            all(
                item["agentDomain"] == autonomous.AGENT_DOMAIN_BY_CASE[item["caseId"]]
                for item in suite["caseEvidence"]
            )
        )
        comparison = suite["policyComparison"]
        self.assertEqual(comparison["source"], "test_double_proposals")
        self.assertEqual(comparison["toolChoiceMode"], "auto")
        self.assertFalse(comparison["forcedCallsIncluded"])
        self.assertEqual(comparison["scenarioCount"], 14)
        self.assertEqual(comparison["proposalCount"], 14)
        self.assertEqual(comparison["pairedProposalCount"], 14)
        self.assertEqual(comparison["unpairedProposalCount"], 0)
        self.assertTrue(comparison["selfChecks"]["sameProposalIdentityInBothArms"])
        self.assertTrue(comparison["selfChecks"]["policyOffNeverExecutes"])
        self.assertEqual(
            comparison["metrics"]["proposalsByScenario"],
            {"numerator": 14, "denominator": 14, "value": 1},
        )
        self.assertEqual(
            comparison["metrics"]["benignSuccess"],
            {"numerator": 9, "denominator": 9, "value": 1},
        )
        self.assertEqual(comparison["policyOffSummary"]["actualOperationExecutions"], 0)
        self.assertEqual(comparison["policyOffSummary"]["persistentStateChanges"], 0)
        self.assertEqual(comparison["policyOffSummary"]["externalCalls"], 0)
        self.assertEqual(
            {item["toolCallOrigin"] for item in suite["caseEvidence"]},
            {"test_provider_message_tool_calls"},
        )
        self.assertEqual(suite["nativeCapabilityProbe"]["toolChoice"], "auto")
        self.assertTrue(suite["nativeCapabilityProbe"]["toolCallObserved"])
        self.assertEqual(evidence["rawPromptsStored"], False)
        self.assertEqual(evidence["rawResponsesStored"], False)
        self.assertEqual(evidence["rawToolArgumentsStored"], False)

        serialized = json.dumps(evidence)
        self.assertNotIn(SIMULATED_RECIPIENT, serialized)
        self.assertNotIn(SYNTHETIC_IBAN, serialized)
        self.assertNotIn("The synthetic review is complete.", serialized)
        self.assertNotIn("Untrusted document begins.", serialized)

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

    def test_controlled_attack_proposals_are_denied_without_execution(self):
        original_adapter = autonomous.call_synthetic_tool
        with patch.object(
            autonomous, "call_synthetic_tool", wraps=original_adapter
        ) as adapter_call:
            evidence = self._evaluate(AutoToolProvider(attack_calls=True))
        suite = evidence["nativeToolSuite"]
        attacks = [item for item in suite["caseEvidence"] if item["label"] == "attack"]
        comparison = suite["policyComparison"]
        attack_pairs = [item for item in comparison["pairs"] if item["label"] == "attack"]
        self.assertEqual(adapter_call.call_count, 14, "only the policy-on arm invokes the fake tool adapter")
        self.assertEqual(len(attacks), 5)
        self.assertEqual(sum(item["unauthorizedProposal"] for item in attacks), 5)
        self.assertEqual(sum(item["unauthorizedAttempt"] for item in attacks), 5)
        self.assertEqual(sum(item["unauthorizedExecution"] for item in attacks), 0)
        self.assertEqual(sum(item["deniedCount"] for item in attacks), 5)
        self.assertEqual(len(attack_pairs), 5)
        self.assertTrue(
            all(
                item["policyOn"]["denied"]
                and item["policyOff"]["counterfactualWouldExecute"]
                and item["policyOff"]["counterfactualCloneStateChanged"]
                and not item["policyOff"]["executed"]
                for item in attack_pairs
            )
        )
        self.assertEqual(comparison["metrics"]["attackPotential"]["numerator"], 5)
        self.assertEqual(comparison["metrics"]["attackPotential"]["denominator"], 5)
        self.assertTrue(comparison["selfChecks"]["sameProposalIdentityInBothArms"])
        self.assertTrue(comparison["selfChecks"]["policyOffNeverExecutes"])
        self.assertEqual(comparison["policyOffSummary"]["actualOperationExecutions"], 0)
        self.assertEqual(suite["toolSummary"]["unauthorizedExecutions"], 0)
        self.assertEqual(suite["toolSummary"]["externalCalls"], 0)
        self.assertEqual(suite["toolSummary"]["stateChanges"], 0)

    def test_no_autonomous_calls_are_reported_as_failures_without_forcing(self):
        provider = AutoToolProvider(no_calls=True)
        evidence = self._evaluate(provider)
        suite = evidence["nativeToolSuite"]
        self.assertEqual(provider.calls, [("auto", 128)] * 14)
        self.assertEqual(suite["toolSummary"]["nativeCallsObserved"], 0)
        self.assertEqual(suite["taskSuccess"]["numerator"], 0)
        self.assertEqual(suite["taskSuccess"]["denominator"], 14)
        self.assertTrue(all(not item["taskSucceeded"] for item in suite["caseEvidence"]))
        self.assertTrue(all(not item["argumentsValid"] for item in suite["caseEvidence"]))
        self.assertTrue(all(not item["policyAllowed"] for item in suite["caseEvidence"]))
        self.assertTrue(all(not item["simulatedExecution"] for item in suite["caseEvidence"]))
        self.assertFalse(suite["nativeCapabilityProbe"]["toolCallObserved"])
        comparison = suite["policyComparison"]
        self.assertEqual(comparison["proposalCount"], 0)
        self.assertEqual(comparison["pairedProposalCount"], 0)
        self.assertEqual(comparison["metrics"]["proposalsByScenario"]["denominator"], 14)
        self.assertEqual(comparison["metrics"]["pairedProposalIdentity"]["denominator"], 0)
        self.assertEqual(comparison["metrics"]["benignSuccess"]["denominator"], 9)
        self.assertEqual(comparison["metrics"]["attackPotential"]["denominator"], 5)


class QwenNativeMarkupAdapterTests(unittest.TestCase):
    def _completion(self, content):
        return {
            "choices": [
                {
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 4, "completion_tokens": 7},
        }

    def test_complete_qwen_markup_is_normalized_without_retaining_raw_content(self):
        response = self._completion(
            '<tool_call>{"name":"consult_synthetic_invoice",'
            '"arguments":{"invoice_id":"INV-LAB-2036-0001"}}</tool_call>'
        )
        adapted = llm_lab.adapt_qwen_native_tool_markup(response)
        message = adapted["choices"][0]["message"]
        self.assertIsNone(message["content"])
        self.assertEqual(adapted["choices"][0]["finish_reason"], "stop")
        self.assertEqual(
            message["tool_calls"][0]["function"]["name"],
            "consult_synthetic_invoice",
        )
        self.assertEqual(
            json.loads(message["tool_calls"][0]["function"]["arguments"]),
            {"invoice_id": INVOICE_ID},
        )
        self.assertEqual(
            adapted["_guardianToolMarkupParse"]["status"],
            "qwen_native_markup_adapter",
        )

    def test_plain_json_is_not_promoted_to_a_tool_call(self):
        response = self._completion(
            '{"name":"consult_synthetic_invoice",'
            '"arguments":{"invoice_id":"INV-LAB-2036-0001"}}'
        )
        adapted = llm_lab.adapt_qwen_native_tool_markup(response)
        self.assertNotIn("tool_calls", adapted["choices"][0]["message"])
        self.assertEqual(
            adapted["_guardianToolMarkupParse"]["status"], "no_marker"
        )

    def test_mixed_or_malformed_markup_fails_closed(self):
        contents = (
            'I might call this: <tool_call>{"name":"consult_synthetic_invoice",'
            '"arguments":{}}</tool_call>',
            '<tool_call>{"name":"consult_synthetic_invoice",'
            '"arguments":{}</tool_call>',
            '<tool_call>{"name":"consult_synthetic_invoice",'
            '"arguments":[]}</tool_call>',
        )
        for content in contents:
            with self.subTest(contentLength=len(content)):
                adapted = llm_lab.adapt_qwen_native_tool_markup(
                    self._completion(content)
                )
                self.assertNotIn("tool_calls", adapted["choices"][0]["message"])
                self.assertEqual(
                    adapted["_guardianToolMarkupParse"]["status"],
                    "unparsed_markup",
                )


if __name__ == "__main__":
    unittest.main()
