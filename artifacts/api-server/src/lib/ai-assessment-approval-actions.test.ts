import assert from "node:assert/strict";
import { test } from "node:test";
import {
  computeApprovalProposalBindingV3,
  computeApprovalReplayBinding,
  isApprovalDecisionWindowOpen,
  type ApprovalEvidenceProvenance,
  type SyntheticApprovalActionRef,
} from "./ai-assessment-approval-actions";

type ProposalBindingInput = Parameters<
  typeof computeApprovalProposalBindingV3
>[0];

const financeApproval: ProposalBindingInput = {
  workspaceId: "synthetic-workspace-a",
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

function supportApproval(): ProposalBindingInput {
  return {
    ...financeApproval,
    jobId: "synthetic-job-support-1",
    caseId: "qwen_support_benign_refund_approval_es",
    proposalSha256: "c".repeat(64),
    actionSha256: "d".repeat(64),
    syntheticActionRef: "guardian.synthetic.support.refund.v1",
  };
}

test("approval v3 binding changes with tenant, context, proposal, actor, role, expiry, and provenance", () => {
  const expected = computeApprovalProposalBindingV3(financeApproval);
  const mutations: Array<[string, Partial<ProposalBindingInput>]> = [
    ["tenant", { workspaceId: "synthetic-workspace-b" }],
    ["job context", { jobId: "synthetic-job-finance-2" }],
    ["case context", { caseId: "qwen_finance_benign_quoted_instruction_en" }],
    ["exact proposal", { proposalSha256: "e".repeat(64) }],
    ["action arguments", { actionSha256: "f".repeat(64) }],
    [
      "allowlisted action",
      {
        syntheticActionRef:
          "guardian.synthetic.support.refund.v1" as SyntheticApprovalActionRef,
      },
    ],
    ["requesting actor", { requestedByUserId: "synthetic-requester-b" }],
    ["requesting role", { requestedByRole: "admin" }],
    ["expiry", { expiresAt: new Date("2026-11-13T12:00:00.000Z") }],
    ["model provenance", { modelInference: true }],
    ["execution provenance", { executionMode: "real_local_qwen_inference" }],
    [
      "call provenance",
      { toolCallOrigin: "guardian_qwen_native_markup_adapter" },
    ],
  ];

  for (const [context, mutation] of mutations) {
    assert.notEqual(
      computeApprovalProposalBindingV3({ ...financeApproval, ...mutation }),
      expected,
      `${context} must change the proposal binding`,
    );
  }
});

test("finance and support approvals use distinct proposal bindings", () => {
  const financeBinding = computeApprovalProposalBindingV3(financeApproval);
  const supportBinding = computeApprovalProposalBindingV3(supportApproval());

  assert.notEqual(financeBinding, supportBinding);
  assert.equal(financeBinding.length, 64);
  assert.equal(supportBinding.length, 64);
  assert.notEqual(
    computeApprovalProposalBindingV3({
      ...financeApproval,
      ...({
        modelInference: false,
        executionMode: "deterministic_fixture",
        toolCallOrigin: "controlled_fixture_not_llm",
      } satisfies ApprovalEvidenceProvenance),
    }),
    computeApprovalProposalBindingV3({
      ...supportApproval(),
      ...({
        modelInference: false,
        executionMode: "deterministic_fixture",
        toolCallOrigin: "controlled_fixture_not_llm",
      } satisfies ApprovalEvidenceProvenance),
    }),
  );
});

test("replay binding is stable for one decision and changes with approver or result context", () => {
  const decision = {
    proposalBindingSha256: computeApprovalProposalBindingV3(financeApproval),
    decision: "approved" as const,
    decidedByUserId: "synthetic-approver-a",
    decidedByRole: "admin",
    decidedAt: new Date("2026-11-11T12:30:00.000Z"),
    simulationResultCode: "synthetic_bank_change_approved_in_clone",
    simulationResultSha256: "1".repeat(64),
  };
  const expected = computeApprovalReplayBinding(decision);

  assert.equal(computeApprovalReplayBinding(decision), expected);
  const mutations = [
    { proposalBindingSha256: "2".repeat(64) },
    { decidedByUserId: "synthetic-approver-b" },
    { decidedByRole: "owner" },
    { decidedAt: new Date("2026-11-11T12:31:00.000Z") },
    { simulationResultCode: "different_synthetic_result" },
    { simulationResultSha256: "3".repeat(64) },
  ];
  for (const mutation of mutations) {
    assert.notEqual(
      computeApprovalReplayBinding({ ...decision, ...mutation }),
      expected,
    );
  }
});

test("only a pending, unexpired approval remains in its decision window", () => {
  const now = new Date("2026-11-11T12:00:00.000Z");

  assert.equal(
    isApprovalDecisionWindowOpen(
      "pending",
      new Date("2026-11-11T12:00:00.001Z"),
      now,
    ),
    true,
  );
  assert.equal(isApprovalDecisionWindowOpen("pending", now, now), false);
  assert.equal(
    isApprovalDecisionWindowOpen(
      "pending",
      new Date("2026-11-11T11:59:59.999Z"),
      now,
    ),
    false,
  );
  for (const state of ["approved", "rejected", "expired"]) {
    assert.equal(
      isApprovalDecisionWindowOpen(
        state,
        new Date("2026-11-13T12:00:00.000Z"),
        now,
      ),
      false,
    );
  }
});
