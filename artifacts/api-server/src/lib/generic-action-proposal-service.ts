import { and, count, eq, gt } from "drizzle-orm";
import {
  aiAssessmentApprovalRequestsTable,
  aiAssessmentJobsTable,
  type AiAssessmentJobEvidence,
  type Membership,
  workspaceAuditEventsTable,
} from "@workspace/db";
import {
  evaluateApprovalAction,
  getApprovalActionDefinition,
  evaluateWorkspaceActionRule,
} from "@workspace/db";
import { computeApprovalProposalBindingV3 } from "./ai-assessment-approval-actions";
import {
  createWorkspaceRuleActionEvidence,
  genericActionDisplay,
  hashGenericActionArguments,
  verifyGenericActionEvidence,
} from "./generic-action-evidence";
import {
  getActiveWorkspaceActionRule,
} from "./workspace-action-rules";
import type { TenantTransaction } from "./tenant-db";

const MAX_PENDING_PER_WORKSPACE = 3;
const PROFILE_BY_ACTION: Record<string, string> = {
  "guardian.synthetic.support.refund.v1": "guardian-agent-lab-customer-service-v1",
  "guardian.synthetic.finance.bank-change.v1": "guardian-agent-lab-customer-service-v1",
  "guardian.support.reply.send.v1": "guardian-agent-lab-customer-service-v1",
  "guardian.email.send.external.v1": "guardian-agent-lab-email-v1",
};

export type GenericActionProposalOutcome =
  | { kind: "invalid_action"; code: string; issues: string[] }
  | {
      kind: "terminal";
      decision: "allow" | "deny";
      reasonCode: string;
      actionType: string;
      actionSha256: string;
      ruleId: string | null;
      ruleVersionId: string | null;
    }
  | { kind: "forbidden" }
  | { kind: "idempotency_conflict" }
  | { kind: "pending_limit" }
  | { kind: "persistence_failed" }
  | {
      kind: "existing" | "created";
      approval: typeof aiAssessmentApprovalRequestsTable.$inferSelect;
      evidence: NonNullable<ReturnType<typeof createWorkspaceRuleActionEvidence>>;
    };

export async function createGenericActionProposalInTransaction(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    actorUserId: string;
    actorRole: Membership["role"];
    agentId: string;
    actionType: string;
    arguments: unknown;
    idempotencyKey: string;
  },
): Promise<GenericActionProposalOutcome> {
  const action = evaluateApprovalAction(input.actionType, input.arguments);
  const definition = getApprovalActionDefinition(input.actionType);
  if (!action.ok || !definition) {
    return {
      kind: "invalid_action",
      code: action.ok ? "unknown_action" : action.reasonCode,
      issues: action.ok ? ["unknown_action"] : action.issues,
    };
  }
  if (!definition.allowedApproverRoles.includes(input.actorRole as "owner" | "admin")) {
    return { kind: "forbidden" };
  }
  const hashes = hashGenericActionArguments(input.actionType, action.args);
  const rule = await getActiveWorkspaceActionRule(
    tx,
    input.workspaceId,
    input.actionType,
  );
  const decision = evaluateWorkspaceActionRule({
    actionType: input.actionType,
    arguments: action.args,
    document: rule?.document ?? null,
    ruleVersionId: rule?.activeVersionId ?? null,
  });

  if (decision.decision !== "require_approval") {
    await tx.insert(workspaceAuditEventsTable).values({
      workspaceId: input.workspaceId,
      actorUserId: input.actorUserId,
      action: "ai_assessment.generic_action_decision",
      resourceType: "generic_action",
      metadata: {
        actionType: input.actionType,
        actionSha256: hashes.actionSha256,
        decision: decision.decision,
        reasonCode: decision.reasonCode,
        ruleId: decision.ruleId,
        ruleVersionId: decision.ruleVersionId,
        agentId: input.agentId,
        synthetic: true,
        externalSideEffect: false,
      },
    });
    return {
      kind: "terminal",
      decision: decision.decision,
      reasonCode: decision.reasonCode,
      actionType: input.actionType,
      actionSha256: hashes.actionSha256,
      ruleId: decision.ruleId,
      ruleVersionId: decision.ruleVersionId,
    };
  }

  const display = genericActionDisplay(input.actionType, action.args);
  if (!display || !decision.ruleId || !rule?.document || !rule.activeVersionId) {
    return { kind: "persistence_failed" };
  }
  const evidence = createWorkspaceRuleActionEvidence({
    workspaceId: input.workspaceId,
    requestedByUserId: input.actorUserId,
    actionType: input.actionType,
    args: action.args,
    ruleId: decision.ruleId,
    ruleVersionId: rule.activeVersionId,
    ruleDocument: rule.document,
    summary: display.summary,
    messagePreview: display.messagePreview,
    agentId: input.agentId,
  });
  if (!evidence) return { kind: "persistence_failed" };
  const profileId = PROFILE_BY_ACTION[input.actionType];
  if (!profileId) return { kind: "invalid_action", code: "unknown_action", issues: [] };
  const now = new Date();

  const existingJob = await tx
    .select()
    .from(aiAssessmentJobsTable)
    .where(
      and(
        eq(aiAssessmentJobsTable.workspaceId, input.workspaceId),
        eq(aiAssessmentJobsTable.idempotencyKey, input.idempotencyKey),
      ),
    )
    .limit(1)
    .then((rows) => rows[0]);
  if (existingJob) {
    const verified = verifyGenericActionEvidence(existingJob.result, {
      workspaceId: input.workspaceId,
      requestedByUserId: input.actorUserId,
      actionType: input.actionType,
      actionSha256: evidence.actionSha256,
      proposalSha256: evidence.proposalSha256,
      profileId,
    });
    if (
      existingJob.requestedByUserId !== input.actorUserId ||
      existingJob.profileId !== profileId ||
      existingJob.status !== "succeeded" ||
      !verified ||
      verified.agentId !== input.agentId
    ) {
      return { kind: "idempotency_conflict" };
    }
    const [approval] = await tx
      .select()
      .from(aiAssessmentApprovalRequestsTable)
      .where(
        and(
          eq(aiAssessmentApprovalRequestsTable.workspaceId, input.workspaceId),
          eq(aiAssessmentApprovalRequestsTable.jobId, existingJob.id),
          eq(aiAssessmentApprovalRequestsTable.caseId, input.actionType),
        ),
      )
      .limit(1);
    return approval
      ? { kind: "existing", approval, evidence: verified }
      : { kind: "idempotency_conflict" };
  }

  const [pending] = await tx
    .select({ total: count() })
    .from(aiAssessmentApprovalRequestsTable)
    .where(
      and(
        eq(aiAssessmentApprovalRequestsTable.workspaceId, input.workspaceId),
        eq(aiAssessmentApprovalRequestsTable.status, "pending"),
        gt(aiAssessmentApprovalRequestsTable.expiresAt, now),
      ),
    );
  if ((pending?.total ?? 0) >= MAX_PENDING_PER_WORKSPACE) {
    return { kind: "pending_limit" };
  }

  const expiresAt = new Date(now.getTime() + definition.receiptExpirySeconds * 1000);
  const [job] = await tx
    .insert(aiAssessmentJobsTable)
    .values({
      workspaceId: input.workspaceId,
      requestedByUserId: input.actorUserId,
      idempotencyKey: input.idempotencyKey,
      profileId,
      status: "succeeded",
      workerVersion: "guardian-action-gateway-v2",
      engineVersion: "guardian-workspace-rules-v2",
      result: evidence as unknown as AiAssessmentJobEvidence,
      startedAt: now,
      completedAt: now,
    })
    .onConflictDoNothing({
      target: [
        aiAssessmentJobsTable.workspaceId,
        aiAssessmentJobsTable.idempotencyKey,
      ],
    })
    .returning();
  if (!job) return { kind: "idempotency_conflict" };

  const proposalBindingSha256 = computeApprovalProposalBindingV3({
    workspaceId: input.workspaceId,
    jobId: job.id,
    caseId: input.actionType,
    proposalSha256: evidence.proposalSha256,
    actionSha256: evidence.actionSha256,
    syntheticActionRef: input.actionType as
      | "guardian.synthetic.support.refund.v1"
      | "guardian.synthetic.finance.bank-change.v1"
      | "guardian.support.reply.send.v1"
      | "guardian.email.send.external.v1",
    requestedByUserId: input.actorUserId,
    requestedByRole: input.actorRole,
    expiresAt,
    modelInference: false,
    executionMode: "deterministic_fixture",
    toolCallOrigin: "controlled_fixture_not_llm",
  });
  const [approval] = await tx
    .insert(aiAssessmentApprovalRequestsTable)
    .values({
      workspaceId: input.workspaceId,
      jobId: job.id,
      caseId: input.actionType,
      proposalSha256: evidence.proposalSha256,
      actionSha256: evidence.actionSha256,
      proposalBindingSha256,
      requestedByUserId: input.actorUserId,
      requestedByRole: input.actorRole,
      bindingVersion: 3,
      syntheticActionRef: input.actionType,
      modelInference: false,
      executionMode: "deterministic_fixture",
      toolCallOrigin: "controlled_fixture_not_llm",
      status: "pending",
      expiresAt,
    })
    .returning();
  if (!approval) return { kind: "persistence_failed" };
  await tx.insert(workspaceAuditEventsTable).values({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "ai_assessment.generic_action_proposal_requested",
    resourceType: "ai_assessment_approval",
    resourceId: approval.id,
    metadata: {
      actionType: input.actionType,
      actionSha256: evidence.actionSha256,
      proposalSha256: evidence.proposalSha256,
      proposalBindingSha256,
      ruleId: evidence.ruleId,
      ruleVersionId: evidence.ruleVersionId ?? null,
      agentId: input.agentId,
      decision: "require_approval",
      synthetic: true,
      externalSideEffect: false,
    },
  });
  return { kind: "created", approval, evidence };
}
