import assert from "node:assert/strict";
import { test } from "node:test";
import { computeApprovalProposalBindingV3 } from "./ai-assessment-approval-actions";

type ProposalBindingInput = Parameters<
  typeof computeApprovalProposalBindingV3
>[0];

const fixtureApproval: ProposalBindingInput = {
  workspaceId: "synthetic-workspace-finance",
  jobId: "synthetic-job-finance-1",
  caseId: "qwen_finance_benign_bank_change_request_es",
  proposalSha256: "a".repeat(64),
  actionSha256: "b".repeat(64),
  syntheticActionRef: "guardian.synthetic.finance.bank-change.v1",
  requestedByUserId: "synthetic-requester-a",
  requestedByRole: "owner",
  expiresAt: new Date("2026-11-12T12:00:00.000Z"),
  modelInference: false,
  executionMode: "deterministic_fixture",
  toolCallOrigin: "controlled_fixture_not_llm",
};

test("approval binding separates fixture provenance from Qwen claims and binds action identity", () => {
  // All inputs below are synthetic contract values. They do not represent a
  // live model run or an approval decision.
  const fixtureBinding = computeApprovalProposalBindingV3(fixtureApproval);
  const adaptedClaimBinding = computeApprovalProposalBindingV3({
    ...fixtureApproval,
    modelInference: true,
    executionMode: "real_local_qwen_inference",
    toolCallOrigin: "guardian_qwen_native_markup_adapter",
  });
  const nativeClaimBinding = computeApprovalProposalBindingV3({
    ...fixtureApproval,
    modelInference: true,
    executionMode: "real_local_qwen_inference",
    toolCallOrigin: "runtime_message_tool_calls",
  });
  const differentActionBinding = computeApprovalProposalBindingV3({
    ...fixtureApproval,
    syntheticActionRef: "guardian.synthetic.support.refund.v1",
  });

  assert.notEqual(fixtureBinding, adaptedClaimBinding);
  assert.notEqual(fixtureBinding, nativeClaimBinding);
  assert.notEqual(adaptedClaimBinding, nativeClaimBinding);
  assert.notEqual(fixtureBinding, differentActionBinding);
});
