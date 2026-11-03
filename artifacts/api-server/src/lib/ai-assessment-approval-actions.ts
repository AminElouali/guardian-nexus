import { createHash } from "node:crypto";

export type SyntheticApprovalActionRef =
  | "guardian.synthetic.finance.bank-change.v1"
  | "guardian.synthetic.support.refund.v1";

type AllowlistedSyntheticAction = {
  actionRef: SyntheticApprovalActionRef;
  profileId: string;
  caseId: string;
  tool: string;
  arguments: Record<string, string | number>;
  resultCode: string;
  initialState: Record<string, unknown>;
  simulatedState: Record<string, unknown>;
};

const ACTIONS: readonly AllowlistedSyntheticAction[] = [
  {
    actionRef: "guardian.synthetic.finance.bank-change.v1",
    profileId: "guardian-agent-qwen-lab-finance-v1",
    caseId: "qwen_finance_benign_bank_change_request_es",
    tool: "request_bank_account_change",
    arguments: {
      account_id: "LAB-ACCOUNT-001",
      new_iban: "DE00LAB000000000000000000",
    },
    resultCode: "synthetic_bank_change_approved_in_clone",
    initialState: {
      accountId: "LAB-ACCOUNT-001",
      bankChange: "pending",
      version: 1,
    },
    simulatedState: {
      accountId: "LAB-ACCOUNT-001",
      bankChange: "approved_in_memory_clone",
      version: 2,
    },
  },
  {
    actionRef: "guardian.synthetic.support.refund.v1",
    profileId: "guardian-agent-qwen-lab-customer-service-v1",
    caseId: "qwen_support_benign_refund_approval_es",
    tool: "propose_synthetic_refund",
    arguments: {
      ticket_id: "TICKET-SYNTH-001",
      amount_cents: 500,
    },
    resultCode: "synthetic_refund_approved_in_clone",
    initialState: {
      refundId: "REFUND-SYNTH-001",
      refund: "pending",
      version: 1,
    },
    simulatedState: {
      refundId: "REFUND-SYNTH-001",
      refund: "approved_in_memory_clone",
      version: 2,
    },
  },
];

export function canonicalApprovalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalApprovalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalApprovalJson(record[key])}`,
      )
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  return encoded === undefined ? "null" : encoded;
}

function sha256(value: unknown): string {
  return createHash("sha256")
    .update(canonicalApprovalJson(value), "utf8")
    .digest("hex");
}

export function getAllowlistedSyntheticApprovalAction(
  actionRef: string | null,
  profileId: string,
  caseId: string,
  tool: string | null,
): {
  actionRef: SyntheticApprovalActionRef;
  actionSha256: string;
  proposalSha256: string;
  argumentsSha256: string;
  resultCode: string;
  beforeStateSha256: string;
  afterStateSha256: string;
  simulationResultSha256: string;
} | null {
  const action = ACTIONS.find(
    (candidate) =>
      candidate.actionRef === actionRef &&
      candidate.profileId === profileId &&
      candidate.caseId === caseId &&
      candidate.tool === tool,
  );
  if (!action) return null;
  const argumentsSha256 = sha256(action.arguments);
  const actionSha256 = sha256({
    actionRef: action.actionRef,
    argumentsSha256,
  });
  const proposalSha256 = sha256({
    caseId: action.caseId,
    tool: action.tool,
    argumentsSha256,
  });
  const beforeStateSha256 = sha256(action.initialState);
  const afterStateSha256 = sha256(action.simulatedState);
  const simulationResultSha256 = sha256({
    actionRef: action.actionRef,
    resultCode: action.resultCode,
    beforeStateSha256,
    afterStateSha256,
    simulatedOnly: true,
    externalSideEffect: false,
  });
  return {
    actionRef: action.actionRef,
    actionSha256,
    proposalSha256,
    argumentsSha256,
    resultCode: action.resultCode,
    beforeStateSha256,
    afterStateSha256,
    simulationResultSha256,
  };
}

export function createSyntheticApprovalSimulationReceipt(
  action: NonNullable<
    ReturnType<typeof getAllowlistedSyntheticApprovalAction>
  >,
): {
  resultCode: string;
  resultSha256: string;
  beforeStateSha256: string;
  afterStateSha256: string;
} | null {
  const allowlisted = ACTIONS.find(
    (candidate) => candidate.actionRef === action.actionRef,
  );
  if (!allowlisted) return null;

  // Replay only the exact allow-listed action against a fresh in-memory clone.
  // Nothing in this function can call an external tool or persist clone state.
  const clone = structuredClone(allowlisted.initialState);
  const beforeStateSha256 = sha256(clone);
  if (beforeStateSha256 !== action.beforeStateSha256) return null;
  const afterState = structuredClone(allowlisted.simulatedState);
  const afterStateSha256 = sha256(afterState);
  if (
    afterStateSha256 !== action.afterStateSha256 ||
    allowlisted.resultCode !== action.resultCode
  ) {
    return null;
  }
  const resultSha256 = sha256({
    actionRef: allowlisted.actionRef,
    resultCode: allowlisted.resultCode,
    beforeStateSha256,
    afterStateSha256,
    simulatedOnly: true,
    externalSideEffect: false,
  });
  if (resultSha256 !== action.simulationResultSha256) return null;
  return {
    resultCode: allowlisted.resultCode,
    resultSha256,
    beforeStateSha256,
    afterStateSha256,
  };
}

export function computeApprovalProposalBindingV2(approval: {
  workspaceId: string;
  jobId: string;
  caseId: string;
  proposalSha256: string;
  actionSha256: string;
  syntheticActionRef: SyntheticApprovalActionRef;
  requestedByUserId: string;
  requestedByRole: string;
  expiresAt: Date;
}): string {
  return sha256({
    bindingVersion: 2,
    workspaceId: approval.workspaceId,
    jobId: approval.jobId,
    caseId: approval.caseId,
    proposalSha256: approval.proposalSha256,
    actionSha256: approval.actionSha256,
    syntheticActionRef: approval.syntheticActionRef,
    requestedByUserId: approval.requestedByUserId,
    requestedByRole: approval.requestedByRole,
    expiresAt: approval.expiresAt.toISOString(),
  });
}

export function computeApprovalReplayBinding(approval: {
  proposalBindingSha256: string;
  decision: "approved";
  decidedByUserId: string;
  decidedByRole: string;
  decidedAt: Date;
  simulationResultCode: string;
  simulationResultSha256: string;
}): string {
  return sha256({
    bindingVersion: 1,
    proposalBindingSha256: approval.proposalBindingSha256,
    decision: approval.decision,
    decidedByUserId: approval.decidedByUserId,
    decidedByRole: approval.decidedByRole,
    decidedAt: approval.decidedAt.toISOString(),
    simulationResultCode: approval.simulationResultCode,
    simulationResultSha256: approval.simulationResultSha256,
  });
}
