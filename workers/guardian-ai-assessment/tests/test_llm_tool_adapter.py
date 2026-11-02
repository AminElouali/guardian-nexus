import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian_ai_assessment import llm_lab  # noqa: E402
from guardian_ai_assessment.tool_adapter import (  # noqa: E402
    INVOICE_ID,
    SIMULATED_RECIPIENT,
    SYNTHETIC_ACCOUNT_ID,
    SYNTHETIC_DOCUMENT,
    SYNTHETIC_DOCUMENT_ID,
    SYNTHETIC_EMAIL,
    SYNTHETIC_EMAIL_ID,
    SYNTHETIC_IBAN,
    call_synthetic_tool,
)


class ScriptedProvider:
    def __init__(self, response: dict):
        self.response = json.dumps(response)

    def complete(self, *, system: str, user: str, seed: int):
        assert "INV-LAB-2036-0001" in user
        assert "function calling nativo" in system
        return self.response, 12, 8


class LocalLlmToolAdapterTests(unittest.TestCase):
    def test_invoice_integration_persists_only_sanitized_hashes(self):
        evidence = llm_lab.evaluate_invoice_integration(
            ScriptedProvider(
                {
                    "action": "final",
                    "arguments": {"text": "Synthetic invoice is open."},
                }
            ),
        )

        assert evidence["executionMode"] == "test_double_only"
        assert evidence["engine"] == "local_llm_lab"
        assert evidence["toolInvocationMode"] == "structured_json_emulation"
        assert evidence["toolSummary"]["harnessToolExecutions"] == 1
        assert evidence["toolSummary"]["modelActionProposals"] == 0
        assert evidence["externalCalls"] == 0
        assert evidence["rawPromptsStored"] is False
        assert evidence["rawResponsesStored"] is False
        assert evidence["rawToolArgumentsStored"] is False
        assert evidence["decision"]["responseSha256"]
        assert "Synthetic invoice is open." not in json.dumps(evidence)

    def test_fake_tool_schemas_are_exact_and_side_effect_free(self):
        invoice_events, invoice = call_synthetic_tool(
            tool="consult_synthetic_invoice",
            arguments={"invoice_id": INVOICE_ID},
            source="local_harness",
            tool_call_id="invoice-read-1",
        )
        assert invoice["invoice_id"] == INVOICE_ID
        assert invoice_events[-1]["phase"] == "executed"
        assert invoice_events[-1]["externalSideEffect"] is False

        document_events, document = call_synthetic_tool(
            tool="read_synthetic_document",
            arguments={"document_id": SYNTHETIC_DOCUMENT_ID},
            source="native_tool_call",
            tool_call_id="document-read-1",
        )
        assert document == SYNTHETIC_DOCUMENT
        assert document_events[-1]["phase"] == "executed"
        assert document_events[-1]["stateChanged"] is False
        assert document_events[-1]["externalSideEffect"] is False

        denied_document, _ = call_synthetic_tool(
            tool="read_synthetic_document",
            arguments={"document_id": SYNTHETIC_DOCUMENT_ID, "extra": "rejected"},
            source="native_tool_call",
            tool_call_id="document-read-2",
        )
        assert denied_document[-1]["phase"] == "denied"
        assert denied_document[-1]["executed"] is False

        email_read_events, email = call_synthetic_tool(
            tool="read_synthetic_email",
            arguments={"email_id": SYNTHETIC_EMAIL_ID},
            source="native_tool_call",
            tool_call_id="email-read-1",
        )
        assert email == SYNTHETIC_EMAIL
        assert email_read_events[-1]["phase"] == "executed"
        assert email_read_events[-1]["stateChanged"] is False
        assert email_read_events[-1]["externalSideEffect"] is False

        email_events, _ = call_synthetic_tool(
            tool="send_email_simulated",
            arguments={
                "recipient": SIMULATED_RECIPIENT,
                "subject": "Synthetic status",
                "body": "This remains inside the fake tool.",
            },
            source="model_json_emulation",
            tool_call_id="model-proposal-1",
        )
        assert email_events[-1]["resultCode"] == "simulated_email_prepared"
        assert email_events[-1]["executed"] is True
        assert email_events[-1]["stateChanged"] is False
        assert email_events[-1]["externalSideEffect"] is False

        denied_email, _ = call_synthetic_tool(
            tool="send_email_simulated",
            arguments={
                "recipient": "outside@example.org",
                "subject": "not allowed",
                "body": "must be denied",
                "extra": "unexpected",
            },
            source="model_json_emulation",
            tool_call_id="model-proposal-1",
        )
        assert denied_email[-1]["phase"] == "denied"
        assert denied_email[-1]["executed"] is False

        bank_events, _ = call_synthetic_tool(
            tool="request_bank_account_change",
            arguments={
                "account_id": SYNTHETIC_ACCOUNT_ID,
                "new_iban": SYNTHETIC_IBAN,
            },
            source="model_json_emulation",
            tool_call_id="model-proposal-1",
        )
        assert bank_events[-1]["resultCode"] == "simulated_change_request_pending"
        assert bank_events[-1]["executed"] is True
        assert bank_events[-1]["stateChanged"] is False
        assert bank_events[-1]["externalSideEffect"] is False

    def test_model_action_is_recorded_as_json_emulation_before_external_policy_gate(
        self,
    ):
        evidence = llm_lab.evaluate_invoice_integration(
            ScriptedProvider(
                {
                    "action": "send_email_simulated",
                    "arguments": {
                        "recipient": SIMULATED_RECIPIENT,
                        "subject": "Synthetic invoice status",
                        "body": "The invoice is open.",
                    },
                }
            ),
        )

        model_events = [
            event
            for event in evidence["toolTrace"]
            if event["source"] == "model_json_emulation"
        ]
        assert [event["phase"] for event in model_events] == [
            "proposal",
            "authorization_attempt",
            "executed",
        ]
        assert all(event["simulatedOnly"] for event in model_events)
        assert all(not event["externalSideEffect"] for event in model_events)
        assert evidence["toolSummary"]["modelActionProposals"] == 1
        assert evidence["toolSummary"]["simulatedExecutions"] == 1
        assert evidence["toolSummary"]["realMutations"] == 0


if __name__ == "__main__":
    unittest.main()
