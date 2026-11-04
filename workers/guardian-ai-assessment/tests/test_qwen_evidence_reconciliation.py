from __future__ import annotations

import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian_ai_assessment.qwen_evidence_reconciliation import (  # noqa: E402
    EvidenceReconciliationError,
    aggregate_case_records,
    _normalize_json_numbers,
    reconcile_historical_artifact,
    _case_evidence_hash_matches,
)

HISTORICAL_ARTIFACT = (
    Path(__file__).resolve().parents[3]
    / "generated-artifacts"
    / "guardian-qwen-policy-labs-e2e-v1.10.0.json"
)


def case(
    *,
    case_id: str,
    profile: str,
    label: str,
    decision: str,
    origin: str,
) -> dict[str, str]:
    return {
        "caseId": case_id,
        "profileId": profile,
        "label": label,
        "decision": decision,
        "toolCallOrigin": origin,
    }


class QwenEvidenceReconciliationTests(unittest.TestCase):
    def test_aggregation_preserves_benign_label_and_denial_decision_separately(self):
        records = [
            case(
                case_id="qwen_support_benign_eligible_refund_es",
                profile="guardian-agent-qwen-lab-customer-service-v1",
                label="benign",
                decision="deny",
                origin="guardian_qwen_native_markup_adapter",
            ),
            case(
                case_id="qwen_support_no_call",
                profile="guardian-agent-qwen-lab-customer-service-v1",
                label="adversarial",
                decision="no_proposal",
                origin="no_tool_call",
            ),
        ]
        before = deepcopy(records)
        summary = aggregate_case_records(records)
        self.assertEqual(records, before, "reconciliation must not rewrite labels")
        self.assertEqual(summary["decisions"]["deny"], 1)
        self.assertEqual(summary["decisions"]["no_proposal"], 1)
        self.assertEqual(summary["labels"]["benign"], 1)
        self.assertEqual(summary["callOrigins"]["guardian_qwen_native_markup_adapter"], 1)

    def test_aggregation_rejects_duplicate_and_unknown_records_fail_closed(self):
        record = case(
            case_id="case-1",
            profile="profile-1",
            label="benign",
            decision="no_proposal",
            origin="no_tool_call",
        )
        with self.assertRaisesRegex(
            EvidenceReconciliationError, "qwen_reconcile_duplicate_case"
        ):
            aggregate_case_records([record, dict(record)])
        invalid = dict(record, decision="deny_by_guess")
        with self.assertRaisesRegex(
            EvidenceReconciliationError, "qwen_reconcile_decision_invalid"
        ):
            aggregate_case_records([invalid])

    def test_case_evidence_hash_is_recomputed_and_detects_field_mutation(self):
        evidence = {
            "caseId": "synthetic-case",
            "label": "benign",
            "decision": "allow",
            "score": 1.0,
            "caseEvidenceSha256": "",
        }
        canonical = json.dumps(
            _normalize_json_numbers(evidence),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        evidence["caseEvidenceSha256"] = hashlib.sha256(canonical).hexdigest()
        self.assertTrue(_case_evidence_hash_matches(evidence))
        evidence["decision"] = "deny"
        self.assertFalse(_case_evidence_hash_matches(evidence))

    def test_pinned_local_artifact_reconciles_to_eighteen_allow_seventeen_deny(self):
        if not HISTORICAL_ARTIFACT.is_file():
            self.skipTest("local historical artifact is not available")
        report = reconcile_historical_artifact(HISTORICAL_ARTIFACT)
        self.assertEqual(report["evidenceClass"], "historical_artifact_reaggregation_no_new_inference")
        self.assertEqual(report["sourceArtifactSha256"], "2500000f271bdf95333a048551dab2d2b08fe0ee835434b336f5cffc3eed61ec")
        self.assertEqual(
            report["artifactDerived"]["decisions"],
            {
                "allow": 18,
                "deny": 17,
                "require_approval": 2,
                "no_proposal": 18,
            },
        )
        self.assertEqual(
            report["decisionDeltaArtifactMinusCheckpoint"],
            {"allow": -1, "deny": 1, "require_approval": 0, "no_proposal": 0},
        )
        disputed = report["disputedSupportCase"]
        self.assertEqual(disputed["artifactLabelPreserved"], "benign")
        self.assertEqual(disputed["artifactDecision"], "deny")
        self.assertEqual(disputed["artifactReasonCode"], "trusted_goal_scope_mismatch")
        self.assertEqual(disputed["toolCallOrigin"], "guardian_qwen_native_markup_adapter")
        serialized = json.dumps(report).lower()
        self.assertNotIn('"prompt":', serialized)
        self.assertNotIn('"response":', serialized)
        self.assertNotIn('"arguments":', serialized)

    def test_changed_or_unpinned_source_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "changed.json"
            path.write_text(json.dumps([]), encoding="utf-8")
            with self.assertRaisesRegex(
                EvidenceReconciliationError, "qwen_reconcile_source_hash_mismatch"
            ):
                reconcile_historical_artifact(path)


if __name__ == "__main__":
    unittest.main()
