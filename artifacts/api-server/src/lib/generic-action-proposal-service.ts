import { and, count, desc, eq, gte, gt, sql } from "drizzle-orm";
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
  isCatalogActionRef,
  evaluateWorkspaceActionRule,
} from "@workspace/db";
import { computeApprovalProposalBindingV3 } from "./ai-assessment-approval-actions";
import {
  createGenericActionEvidence,
  createWorkspaceRuleActionEvidence,
  genericActionDisplay,
  hashGenericActionArguments,
  verifyGenericActionEvidence,
} from "./generic-action-evidence";
import {
  getActiveWorkspaceActionRule,
  lockWorkspaceActionRule,
} from "./workspace-action-rules";
import type { TenantTransaction } from "./tenant-db";

const MAX_PENDING_PER_WORKSPACE = 3;
const AUTO_REFUND_ACTION = "guardian.synthetic.support.refund.v1";
const AUTO_REFUND_WINDOW_MS = 15 * 60 * 1_000;
const MAX_AUTO_REFUND_WINDOW_EVENTS = 500;

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
      replayed?: boolean;
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
    escalateAllowToApproval?: boolean;
    allowAutomaticRefund?: boolean;
    allowSyntheticNoEffectDecision?: boolean;
  },
): Promise<GenericActionProposalOutcome> {
  const action = evaluateApprovalAction(input.actionType, input.arguments);
  const definition = getApprovalActionDefinition(input.actionType);
  if (!action.ok || !definition || !isCatalogActionRef(input.actionType)) {
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
  if (input.actionType === AUTO_REFUND_ACTION) {
    await lockWorkspaceActionRule(tx, input.workspaceId, input.actionType);
  }
  const rule = await getActiveWorkspaceActionRule(
    tx,
    input.workspaceId,
    input.actionType,
  );
  const catalogDefaultRefundApproval =
    input.actionType === AUTO_REFUND_ACTION && !rule &&
    action.decision === "require_approval" && action.ruleId !== null;
  const ruleDecision = catalogDefaultRefundApproval
    ? {
        ...action,
        reasonCode: "catalog_default_requires_approval",
        ruleVersionId: null,
      }
    : evaluateWorkspaceActionRule({
        actionType: input.actionType,
        arguments: action.args,
        document: rule?.document ?? null,
        ruleVersionId: rule?.activeVersionId ?? null,
      });
  let automaticRefundAllowed = false;
  let refundApprovalReason: string | null = null;
  if (
    input.actionType === AUTO_REFUND_ACTION &&
    input.allowAutomaticRefund === true &&
    rule &&
    ruleDecision.decision === "allow"
  ) {
    const matchedRule = rule.document?.rules.find(
      (candidate) => candidate.id === ruleDecision.ruleId,
    );
    const amountLimits = matchedRule?.when.all?.filter(
      (condition) =>
        condition.field === "amount_cents" &&
        condition.op === "lte" &&
        typeof condition.value === "number",
    ) ?? [];
    const limitValue = amountLimits.length === 1
      ? amountLimits[0]!.value
      : null;
    const configuredLimit = matchedRule?.when.any?.length === undefined &&
        amountLimits.length === 1 &&
        typeof limitValue === "number" &&
        Number.isSafeInteger(limitValue) &&
        limitValue > 0
      ? limitValue
      : null;
    if (configuredLimit === null) {
      refundApprovalReason = "refund_auto_allow_limit_missing";
    } else {
      const recentRefunds = await tx
        .select({ metadata: workspaceAuditEventsTable.metadata })
        .from(workspaceAuditEventsTable)
        .where(
          and(
            eq(workspaceAuditEventsTable.workspaceId, input.workspaceId),
            eq(
              workspaceAuditEventsTable.action,
              "ai_assessment.generic_action_decision",
            ),
            gte(
              workspaceAuditEventsTable.createdAt,
              sql`now() - (${AUTO_REFUND_WINDOW_MS} * interval '1 millisecond')`,
            ),
            sql`${workspaceAuditEventsTable.metadata}->>'actionType' = ${AUTO_REFUND_ACTION}`,
            sql`${workspaceAuditEventsTable.metadata}->>'reasonCode' = 'automatic_refund_allowed'`,
          ),
        )
        .orderBy(desc(workspaceAuditEventsTable.createdAt))
        .limit(MAX_AUTO_REFUND_WINDOW_EVENTS + 1);
      const replayedDecision = recentRefunds.find(
        (row) => row.metadata.idempotencyKey === input.idempotencyKey,
      );
      if (replayedDecision) {
        if (
          replayedDecision.metadata.actionSha256 !== hashes.actionSha256 ||
          replayedDecision.metadata.ruleId !== ruleDecision.ruleId ||
          replayedDecision.metadata.ruleVersionId !== rule.activeVersionId ||
          replayedDecision.metadata.amountCents !== action.args.amount_cents
        ) {
          return { kind: "idempotency_conflict" };
        }
        return {
          kind: "terminal",
          decision: "allow",
          reasonCode: "automatic_refund_allowed",
          actionType: input.actionType,
          actionSha256: hashes.actionSha256,
          ruleId: ruleDecision.ruleId,
          ruleVersionId: rule.activeVersionId,
          replayed: true,
        };
      }
      let priorTotalCents = 0;
      let historyIsValid = recentRefunds.length <= MAX_AUTO_REFUND_WINDOW_EVENTS;
      for (const row of recentRefunds) {
        const amountCents = row.metadata.amountCents;
        if (
          typeof amountCents !== "number" ||
          !Number.isSafeInteger(amountCents) ||
          amountCents <= 0 ||
          !Number.isSafeInteger(priorTotalCents + amountCents)
        ) {
          historyIsValid = false;
          break;
        }
        priorTotalCents += amountCents;
      }
      if (!historyIsValid) {
        refundApprovalReason = "refund_window_history_requires_review";
      } else {
        const amountCents = action.args.amount_cents;
        if (
          typeof amountCents !== "number" ||
          priorTotalCents + amountCents > configuredLimit
        ) {
          refundApprovalReason = "refund_window_limit_requires_approval";
        } else {
          automaticRefundAllowed = true;
        }
      }
    }
  }
  const escalatedAllow =
    ruleDecision.decision === "allow" &&
    definition.requiresIndependentApprover &&
    (refundApprovalReason !== null ||
      (input.escalateAllowToApproval === true && !automaticRefundAllowed));
  const unsupportedAllow =
    ruleDecision.decision === "allow" &&
    input.escalateAllowToApproval === true &&
    !definition.requiresIndependentApprover &&
    !automaticRefundAllowed &&
    !(
      input.allowSyntheticNoEffectDecision === true &&
      definition.syntheticTemplateText !== undefined
    );
  const decision = automaticRefundAllowed
    ? { ...ruleDecision, reasonCode: "automatic_refund_allowed" }
    : refundApprovalReason
      ? {
          ...ruleDecision,
          decision: "require_approval" as const,
          reasonCode: refundApprovalReason,
        }
      : escalatedAllow
    ? {
        ...ruleDecision,
        decision: "require_approval" as const,
        reasonCode: "rule_allow_escalated_to_approval",
      }
    : unsupportedAllow
      ? {
          ...ruleDecision,
          decision: "deny" as const,
          reasonCode: "automatic_allow_not_supported",
        }
      : ruleDecision;

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
        ...(automaticRefundAllowed
          ? {
              idempotencyKey: input.idempotencyKey,
              amountCents: action.args.amount_cents,
              windowSeconds: AUTO_REFUND_WINDOW_MS / 1_000,
            }
          : {}),
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
  if (!display || !decision.ruleId) {
    return { kind: "persistence_failed" };
  }
  const evidence = catalogDefaultRefundApproval
    ? createGenericActionEvidence({
        workspaceId: input.workspaceId,
        requestedByUserId: input.actorUserId,
        actionType: input.actionType,
        args: action.args,
        ruleId: decision.ruleId,
        agentId: input.agentId,
        summary: display.summary,
        messagePreview: display.messagePreview,
      })
    : rule?.document && rule.activeVersionId
      ? createWorkspaceRuleActionEvidence({
          workspaceId: input.workspaceId,
          requestedByUserId: input.actorUserId,
          actionType: input.actionType,
          args: action.args,
          ruleId: decision.ruleId,
          ruleVersionId: rule.activeVersionId,
          ruleDocument: rule.document,
          allowEscalation: escalatedAllow,
          summary: display.summary,
          messagePreview: display.messagePreview,
          agentId: input.agentId,
        })
      : null;
  if (!evidence) return { kind: "persistence_failed" };
  const profileId = definition.profileId;
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
      agentId: input.agentId,
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
      engineVersion: evidence.engineVersion,
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
    syntheticActionRef: input.actionType,
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
      decisionReasonCode: decision.reasonCode,
      synthetic: true,
      externalSideEffect: false,
    },
  });
  return { kind: "created", approval, evidence };
}
