import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createWorkspaceRuleActionEvidence,
  genericActionDisplay,
} from "./generic-action-evidence";
import {
  summarizeWorkspaceRuleHistoryImpact,
  type WorkspaceRuleHistoryProposalRow,
} from "./workspace-rule-history-impact";

const workspaceId = "11111111-1111-4111-8111-111111111111";
const requester = "user-history-impact-test";
const supportAction = "guardian.support.reply.send.v1";
const supportArgs = {
  ticket_id: "TICKET-SYNTH-HISTORY",
  recipient_email: "demo@example.test",
  recipient_type: "internal",
  compensation_cents: 0,
  template_id: "synthetic-support-reply-v1",
};
const activeDocument = {
  version: 1 as const,
  rules: [{ id: "review-support", decision: "require_approval" as const, when: {} }],
};
const draftDocument = {
  version: 1 as const,
  rules: [{ id: "block-support", decision: "deny" as const, when: {} }],
};

function validProposalRow(
  ruleEvaluationContext?: Parameters<
    typeof createWorkspaceRuleActionEvidence
  >[0]["ruleEvaluationContext"],
): WorkspaceRuleHistoryProposalRow {
  const display = genericActionDisplay(supportAction, supportArgs);
  assert.ok(display);
  const evidence = createWorkspaceRuleActionEvidence({
    workspaceId,
    requestedByUserId: requester,
    actionType: supportAction,
    args: supportArgs,
    ruleId: "review-support",
    ruleVersionId: "22222222-2222-4222-8222-222222222222",
    ruleDocument: activeDocument,
    ...(ruleEvaluationContext ? { ruleEvaluationContext } : {}),
    ...display,
  });
  assert.ok(evidence);
  return {
    approval: {
      caseId: supportAction,
      requestedByUserId: requester,
      actionSha256: evidence.actionSha256,
      proposalSha256: evidence.proposalSha256,
    },
    job: {
      profileId: evidence.profileId,
      status: "succeeded",
      result: evidence,
    },
  };
}

function summary(
  rows: WorkspaceRuleHistoryProposalRow[],
  totalProposalCount = rows.length,
  actionType = supportAction,
) {
  return summarizeWorkspaceRuleHistoryImpact({
    workspaceId,
    actionType,
    totalProposalCount,
    rows,
    activeVersionId: "33333333-3333-4333-8333-333333333333",
    activeDocument,
    draftVersionId: "44444444-4444-4444-8444-444444444444",
    draftDocument,
  });
}

test("history impact validates stored generic evidence and compares it with the real rule engine", () => {
  const missingArguments: WorkspaceRuleHistoryProposalRow = {
    approval: {
      caseId: supportAction,
      requestedByUserId: requester,
      actionSha256: "a".repeat(64),
      proposalSha256: "b".repeat(64),
    },
    job: {
      profileId: "guardian-agent-lab-customer-service-v1",
      status: "succeeded",
      result: {
        evidenceVersion: 2,
        argumentsSha256: "c".repeat(64),
        actionSha256: "a".repeat(64),
      },
    },
  };
  const result = summary([validProposalRow(), missingArguments]);

  assert.equal(result.totalProposalCount, 2);
  assert.equal(result.evaluatedCount, 1);
  assert.equal(result.notReevaluableCount, 1);
  assert.equal(result.notProcessedByLimitCount, 0);
  assert.deepEqual(result.activeCounts, { allow: 0, requireApproval: 1, deny: 0 });
  assert.deepEqual(result.draftCounts, { allow: 0, requireApproval: 0, deny: 1 });
  assert.deepEqual(result.changes, [{
    from: "require_approval",
    to: "deny",
    count: 1,
  }]);
  assert.equal(result.readOnly, true);
  assert.equal("arguments" in result, false);
  assert.equal("requestedByUserId" in result, false);
});

test("hashes and fixture action definitions never reconstruct missing or unsupported arguments", () => {
  const refundOnlyHashes: WorkspaceRuleHistoryProposalRow = {
    approval: {
      caseId: "guardian.synthetic.support.refund.v1",
      requestedByUserId: requester,
      actionSha256: "d".repeat(64),
      proposalSha256: "e".repeat(64),
    },
    job: {
      profileId: "guardian-agent-lab-customer-service-v1",
      status: "succeeded",
      result: {
        actionSha256: "d".repeat(64),
        argumentsSha256: "f".repeat(64),
      },
    },
  };
  const refundWithUntrustedFixtureLikeArguments: WorkspaceRuleHistoryProposalRow = {
    ...refundOnlyHashes,
    job: {
      ...refundOnlyHashes.job!,
      result: {
        actionSha256: "d".repeat(64),
        argumentsSha256: "f".repeat(64),
        arguments: { ticket_id: "DO-NOT-RECONSTRUCT", amount_cents: 500 },
      },
    },
  };

  const onlyHashes = summary([refundOnlyHashes], 1, refundOnlyHashes.approval.caseId);
  const fixtureLike = summary(
    [refundWithUntrustedFixtureLikeArguments],
    1,
    refundOnlyHashes.approval.caseId,
  );
  assert.equal(onlyHashes.evaluatedCount, 0);
  assert.equal(onlyHashes.notReevaluableCount, 1);
  assert.equal(fixtureLike.evaluatedCount, 0);
  assert.equal(fixtureLike.notReevaluableCount, 1);
  assert.equal(fixtureLike.activeCounts, null);
  assert.equal(fixtureLike.draftCounts, null);
});

test("empty history returns no misleading decision buckets", () => {
  const result = summary([], 0);
  assert.equal(result.totalProposalCount, 0);
  assert.equal(result.evaluatedCount, 0);
  assert.equal(result.notReevaluableCount, 0);
  assert.equal(result.activeCounts, null);
  assert.equal(result.draftCounts, null);
  assert.deepEqual(result.changes, []);
});

test("history does not reconstruct action-volume context for earlier time windows", () => {
  const result = summarizeWorkspaceRuleHistoryImpact({
    workspaceId,
    actionType: supportAction,
    totalProposalCount: 1,
    rows: [validProposalRow()],
    activeVersionId: "33333333-3333-4333-8333-333333333333",
    activeDocument: {
      version: 1,
      rules: [{
        id: "volume-review",
        decision: "require_approval",
        when: {
          all: [{
            field: "context.action_count",
            op: "gt",
            value: 10,
            windowSeconds: 3600,
          }],
        },
      }],
    },
    draftVersionId: "44444444-4444-4444-8444-444444444444",
    draftDocument: {
      version: 1,
      rules: [{ id: "fallback", decision: "deny", when: {} }],
    },
  });

  assert.equal(result.evaluatedCount, 0);
  assert.equal(result.notReevaluableCount, 1);
  assert.equal(result.activeCounts, null);
  assert.equal(result.draftCounts, null);
});

test("history reuses verified action-volume context stored with the proposal evidence", () => {
  const result = summarizeWorkspaceRuleHistoryImpact({
    workspaceId,
    actionType: supportAction,
    totalProposalCount: 1,
    rows: [validProposalRow({
      dataSensitivity: "normal",
      environment: "test",
      actionCountsByWindow: { 3600: 1 },
    })],
    activeVersionId: "33333333-3333-4333-8333-333333333333",
    activeDocument: {
      version: 1,
      rules: [{
        id: "volume-review",
        decision: "require_approval",
        when: {
          all: [{
            field: "context.action_count",
            op: "gt",
            value: 0,
            windowSeconds: 3600,
          }],
        },
      }],
    },
    draftVersionId: "44444444-4444-4444-8444-444444444444",
    draftDocument: {
      version: 1,
      rules: [{ id: "fallback", decision: "deny", when: {} }],
    },
  });

  assert.equal(result.evaluatedCount, 1);
  assert.equal(result.notReevaluableCount, 0);
  assert.deepEqual(result.activeCounts, { allow: 0, requireApproval: 1, deny: 0 });
  assert.deepEqual(result.draftCounts, { allow: 0, requireApproval: 0, deny: 1 });
});

test("history impact reports proposals not processed past the fixed cap as partial", () => {
  const result = summary([validProposalRow()], 501);
  assert.equal(result.maximumProposals, 500);
  assert.equal(result.evaluatedCount, 1);
  assert.equal(result.notProcessedByLimitCount, 500);
  assert.equal(result.isPartial, true);
});
