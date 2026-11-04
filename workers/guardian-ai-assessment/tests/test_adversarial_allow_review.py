from __future__ import annotations

import json
import hashlib
import unittest
from copy import deepcopy
from pathlib import Path

from guardian_ai_assessment.adversarial_allow_review import (
    classify_historical_adversarial_allow,
    expected_historical_case_ids,
)

REVIEW_PATH = (
    Path(__file__).parents[1]
    / "reports"
    / "qwen-v1.10.0-adversarial-allow-review.json"
)


class HistoricalAdversarialAllowReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.review = json.loads(REVIEW_PATH.read_text(encoding="utf-8"))
        cls.cases = cls.review["cases"]

    def test_exact_nine_historical_allows_are_narrow_synthetic_reads(self) -> None:
        self.assertEqual(len(self.cases), 9)
        self.assertEqual(
            {case["caseId"] for case in self.cases},
            expected_historical_case_ids(),
        )
        self.assertEqual(
            self.review["sourceArtifactSha256"],
            "2500000f271bdf95333a048551dab2d2b08fe0ee835434b336f5cffc3eed61ec",
        )
        self.assertEqual(
            {
                profile: sum(case["profileId"] == profile for case in self.cases)
                for profile in {
                    "guardian-agent-qwen-lab-email-v1",
                    "guardian-agent-qwen-lab-database-v1",
                    "guardian-agent-qwen-lab-finance-v1",
                }
            },
            {
                "guardian-agent-qwen-lab-email-v1": 2,
                "guardian-agent-qwen-lab-database-v1": 4,
                "guardian-agent-qwen-lab-finance-v1": 3,
            },
        )
        for case in self.cases:
            self.assertEqual(
                classify_historical_adversarial_allow(case),
                self.review["classificationCode"],
            )

    def test_manifest_matches_local_historical_artifact_when_present(self) -> None:
        repo_root = REVIEW_PATH.parents[3]
        source_path = repo_root / self.review["sourceArtifact"]
        if not source_path.is_file():
            self.skipTest("generated historical source artifact is not present")
        source_bytes = source_path.read_bytes()
        self.assertEqual(
            hashlib.sha256(source_bytes).hexdigest(),
            self.review["sourceArtifactSha256"],
        )
        jobs = json.loads(source_bytes)
        source_cases = {}
        for job in jobs:
            result = job.get("result") or {}
            if result.get("engine") != "guardian_qwen_policy_lab":
                continue
            for case in result.get("cases", []):
                events = case.get("toolEvents", [])
                source_cases[case["caseId"]] = {
                    **case,
                    "profileId": result.get("profileId"),
                    "externalSideEffect": any(
                        event.get("externalSideEffect") is True for event in events
                    ),
                    "simulatedOnly": bool(events)
                    and all(event.get("simulatedOnly") is True for event in events),
                }
        for reviewed in self.cases:
            with self.subTest(caseId=reviewed["caseId"]):
                source = source_cases[reviewed["caseId"]]
                for field in (
                    "label",
                    "profileId",
                    "contentProvenance",
                    "instructionProvenance",
                    "trustedGoalScopeStatus",
                    "toolCallOrigin",
                    "proposedTool",
                    "decision",
                    "reasonCode",
                    "dispatchStatus",
                    "caseEvidenceSha256",
                    "proposalSha256",
                    "rawPromptStored",
                    "rawResponseStored",
                    "rawArgumentsStored",
                ):
                    self.assertEqual(reviewed.get(field), source.get(field), field)
                events = source["toolEvents"]
                self.assertTrue(events)
                self.assertTrue(all(event["simulatedOnly"] for event in events))
                self.assertTrue(
                    all(not event["externalSideEffect"] for event in events)
                )

    def test_review_does_not_mislabel_adapted_calls_as_native(self) -> None:
        self.assertEqual(
            {case["toolCallOrigin"] for case in self.cases},
            {"guardian_qwen_native_markup_adapter"},
        )
        self.assertEqual(self.review["sourceRunCounts"]["toolCallsNative"], 0)
        self.assertEqual(self.review["sourceRunCounts"]["markerAdaptedProposals"], 37)
        self.assertEqual(self.review["sourceRunCounts"]["noProposal"], 18)

    def test_rejects_untrusted_or_out_of_scope_evidence_mutations(self) -> None:
        mutations = (
            {"contentProvenance": "trusted_user_request"},
            {"trustedGoalScopeStatus": "mismatch"},
            {"instructionProvenance": "untrusted_synthetic_email"},
            {"proposedTool": "send_email"},
            {"dispatchStatus": "external_execution"},
            {"externalSideEffect": True},
            {"rawArgumentsStored": True},
            {"toolCallOrigin": "native_message_tool_calls"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = deepcopy(self.cases[0])
                changed.update(mutation)
                with self.assertRaises(ValueError):
                    classify_historical_adversarial_allow(changed)


if __name__ == "__main__":
    unittest.main()
