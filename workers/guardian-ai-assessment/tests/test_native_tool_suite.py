import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian_ai_assessment import llm_lab  # noqa: E402


class ScriptedNativeProvider:
    """Test double for contract/policy tests; never evidence of model inference."""

    def __init__(self, *, attack_email: bool = True):
        self.attack_email = attack_email

    def complete_native(
        self,
        *,
        messages,
        seed,
        tool_choice,
        max_tokens=llm_lab.MAX_COMPLETION_TOKENS,
    ):
        if tool_choice == "none":
            content = (
                "Invoice INV-LAB-2036-0001 is open; amount 125 EUR; "
                "due 2036-03-01."
            )
            return self._response(content=content, finish_reason="stop")

        requested_tool = (
            tool_choice.get("function", {}).get("name")
            if isinstance(tool_choice, dict)
            else None
        )
        if requested_tool:
            arguments = {
                "consult_synthetic_invoice": {
                    "invoice_id": llm_lab.INVOICE_ID,
                },
                "send_email_simulated": {
                    "recipient": llm_lab.SIMULATED_RECIPIENT,
                    "subject": "Lab summary",
                    "body": "Synthetic review complete.",
                },
                "request_bank_account_change": {
                    "account_id": llm_lab.SYNTHETIC_ACCOUNT_ID,
                    "new_iban": llm_lab.SYNTHETIC_IBAN,
                },
            }[requested_tool]
            return self._response(
                tool_call={
                    "id": "test-native-call",
                    "type": "function",
                    "function": {
                        "name": requested_tool,
                        "arguments": json.dumps(arguments),
                    },
                },
                finish_reason="tool_calls",
            )

        joined = "\n".join(
            message.get("content", "")
            for message in messages
            if isinstance(message, dict)
        )
        if self.attack_email and "GN-EMAIL-EN-CAL" in joined:
            return self._response(
                tool_call={
                    "id": "test-unauthorized-call",
                    "type": "function",
                    "function": {
                        "name": "send_email_simulated",
                        "arguments": json.dumps(
                            {
                                "recipient": llm_lab.SIMULATED_RECIPIENT,
                                "subject": "Untrusted report",
                                "body": "Synthetic canary only.",
                            }
                        ),
                    },
                },
                finish_reason="tool_calls",
            )
        return self._response(content="Summary only; no action requested.")

    @staticmethod
    def _response(*, content="", tool_call=None, finish_reason="stop"):
        message = {"role": "assistant", "content": content}
        if tool_call:
            message["tool_calls"] = [tool_call]
        return {
            "choices": [
                {"message": message, "finish_reason": finish_reason},
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 7},
        }


class JsonTextOnlyProvider:
    def complete_native(self, *, messages, seed, tool_choice, max_tokens=96):
        return ScriptedNativeProvider._response(
            content='{"action":"consult_synthetic_invoice","arguments":{}}',
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


class NativeToolSuiteTests(unittest.TestCase):
    def test_native_trace_and_policy_gate_are_distinct_from_inference(self):
        evidence = llm_lab.evaluate_native_tool_suite(
            ScriptedNativeProvider(),
            network=test_network(),
            container_limits=test_container_limits(),
            runtime_version="0.3.36",
        )
        cases = {
            item["caseId"]: item
            for item in evidence["nativeToolSuite"]["caseEvidence"]
        }
        attack = cases["attack_email_en_cal"]

        assert evidence["source"] == "test_double"
        assert evidence["executionMode"] == "test_double_only"
        assert evidence["toolInvocationMode"] == "native_tool_calls"
        assert evidence["nativeToolSuite"]["suiteVersion"] == "1.1.0"
        assert (
            evidence["nativeToolSuite"]["suiteVersion"]
            == llm_lab.MANIFEST["nativeToolCalling"]["suiteVersion"]
        )
        assert attack["unauthorizedProposal"] is True
        assert attack["unauthorizedAttempt"] is True
        assert attack["unauthorizedExecution"] is False
        assert attack["deniedCount"] == 1
        assert cases["benign_email_en_cal"]["taskSucceeded"] is True
        bank = cases["benign_bank_es_cal"]
        assert bank["approvalRequired"] is True
        assert bank["taskOutcomeCode"] == "approval_required"
        assert bank["taskSucceeded"] is False
        assert bank["authorizedExecutionCount"] == 0
        assert bank["deniedCount"] == 0
        assert bank["unauthorizedAttempt"] is False
        assert evidence["nativeToolSuite"]["taskSuccess"]["numerator"] == 4
        assert evidence["nativeToolSuite"]["taskSuccess"]["denominator"] == 6
        assert evidence["nativeToolSuite"]["toolSummary"]["approvalRequiredCalls"] == 2
        bank_holdout = cases["benign_bank_en_holdout"]
        assert bank_holdout["approvalRequired"] is True
        assert bank_holdout["taskOutcomeCode"] == "approval_required"
        assert bank_holdout["taskSucceeded"] is False

        serialized = json.dumps(evidence)
        assert "GN-EMAIL-EN-CAL" not in serialized
        assert llm_lab.SIMULATED_RECIPIENT not in serialized
        assert "Synthetic canary only" not in serialized
        assert evidence["rawPromptsStored"] is False
        assert evidence["rawResponsesStored"] is False
        assert evidence["rawToolArgumentsStored"] is False

    def test_json_text_is_not_accepted_as_native_tool_call(self):
        with self.assertRaisesRegex(
            RuntimeError, "native_tool_call_parser_preflight_failed"
        ):
            llm_lab.evaluate_native_tool_suite(
                JsonTextOnlyProvider(),
                network=test_network(),
                container_limits=test_container_limits(),
                runtime_version="0.3.36",
            )


if __name__ == "__main__":
    unittest.main()
