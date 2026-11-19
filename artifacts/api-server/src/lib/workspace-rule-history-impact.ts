import { and, count, desc, eq, gte } from "drizzle-orm";
import {
  aiAssessmentApprovalRequestsTable,
  aiAssessmentJobsTable,
  evaluateApprovalAction,
  evaluateWorkspaceActionRule,
  validateWorkspaceActionRuleDocument,
  workspaceActionRuleHeadsTable,
  workspaceActionRuleVersionsTable,
  type WorkspaceActionRuleDocument,
} from "@workspace/db";
import { verifyGenericActionEvidence } from "./generic-action-evidence";
import {
  getActiveWorkspaceActionRule,
} from "./workspace-action-rules";
import type { TenantTransaction } from "./tenant-db";

export const WORKSPACE_RULE_HISTORY_WINDOW_DAYS = 30;
export const MAX_WORKSPACE_RULE_HISTORY_PROPOSALS = 500;

const REEVALUABLE_ACTION_TYPES = new Set([
  "guardian.support.reply.send.v1",
  "guardian.email.send.external.v1",
]);

export type HistoryImpactDecision = "allow" | "require_approval" | "deny";

export type HistoryImpactDecisionCounts = {
  allow: number;
  requireApproval: number;
  deny: number;
};

export type WorkspaceRuleHistoryProposalRow = {
  approval: {
    caseId: string;
    requestedByUserId: string;
    actionSha256: string | null;
    proposalSha256: string;
  };
  job: {
    profileId: string;
    status: string;
    result: unknown;
  } | null;
};

function emptyCounts(): HistoryImpactDecisionCounts {
  return { allow: 0, requireApproval: 0, deny: 0 };
}

function incrementDecision(
  counts: HistoryImpactDecisionCounts,
  decision: HistoryImpactDecision,
): void {
  if (decision === "require_approval") counts.requireApproval += 1;
  else counts[decision] += 1;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasStoredArguments(value: unknown): boolean {
  return isRecord(value) && Object.hasOwn(value, "arguments");
}

export function summarizeWorkspaceRuleHistoryImpact(input: {
  workspaceId: string;
  actionType: string;
  totalProposalCount: number;
  rows: WorkspaceRuleHistoryProposalRow[];
  activeVersionId: string | null;
  activeDocument: WorkspaceActionRuleDocument | null;
  draftVersionId: string | null;
  draftDocument: WorkspaceActionRuleDocument | null;
}) {
  const activeCounts = emptyCounts();
  const draftCounts = input.draftVersionId ? emptyCounts() : null;
  const changes = new Map<string, { from: HistoryImpactDecision; to: HistoryImpactDecision; count: number }>();
  let evaluatedCount = 0;
  let notReevaluableCount = 0;

  for (const row of input.rows) {
    const actionType = row.approval.caseId;
    if (
      actionType !== input.actionType ||
      !REEVALUABLE_ACTION_TYPES.has(actionType) ||
      !row.job ||
      row.job.status !== "succeeded" ||
      !hasStoredArguments(row.job.result) ||
      typeof row.approval.actionSha256 !== "string"
    ) {
      notReevaluableCount += 1;
      continue;
    }

    let evidence: ReturnType<typeof verifyGenericActionEvidence>;
    try {
      evidence = verifyGenericActionEvidence(row.job.result, {
        workspaceId: input.workspaceId,
        requestedByUserId: row.approval.requestedByUserId,
        actionType,
        actionSha256: row.approval.actionSha256,
        proposalSha256: row.approval.proposalSha256,
        profileId: row.job.profileId,
      });
    } catch {
      evidence = null;
    }
    if (!evidence) {
      notReevaluableCount += 1;
      continue;
    }

    const action = evaluateApprovalAction(actionType, evidence.arguments);
    if (!action.ok) {
      notReevaluableCount += 1;
      continue;
    }

    const activeDecision = evaluateWorkspaceActionRule({
      actionType,
      arguments: action.args,
      document: input.activeDocument,
      ruleVersionId: input.activeVersionId,
    }).decision;
    incrementDecision(activeCounts, activeDecision);

    if (input.draftVersionId && draftCounts) {
      const draftDecision = evaluateWorkspaceActionRule({
        actionType,
        arguments: action.args,
        document: input.draftDocument,
        ruleVersionId: input.draftVersionId,
      }).decision;
      incrementDecision(draftCounts, draftDecision);
      if (activeDecision !== draftDecision) {
        const key = `${activeDecision}->${draftDecision}`;
        const existing = changes.get(key);
        if (existing) existing.count += 1;
        else changes.set(key, {
          from: activeDecision,
          to: draftDecision,
          count: 1,
        });
      }
    }
    evaluatedCount += 1;
  }

  const notProcessedByLimitCount = Math.max(
    0,
    input.totalProposalCount - input.rows.length,
  );
  return {
    actionType: input.actionType,
    windowDays: WORKSPACE_RULE_HISTORY_WINDOW_DAYS as 30,
    maximumProposals: MAX_WORKSPACE_RULE_HISTORY_PROPOSALS as 500,
    totalProposalCount: input.totalProposalCount,
    evaluatedCount,
    notReevaluableCount,
    notProcessedByLimitCount,
    isPartial: notProcessedByLimitCount > 0,
    activeVersionId: input.activeVersionId,
    draftVersionId: input.draftVersionId,
    activeCounts: evaluatedCount > 0 ? activeCounts : null,
    draftCounts: evaluatedCount > 0 && draftCounts ? draftCounts : null,
    changes: [...changes.values()].sort((left, right) =>
      left.from.localeCompare(right.from) || left.to.localeCompare(right.to),
    ),
    readOnly: true as const,
  };
}

export async function getWorkspaceRuleHistoryImpact(
  tx: TenantTransaction,
  workspaceId: string,
  actionType: string,
  now = new Date(),
) {
  const since = new Date(
    now.getTime() - WORKSPACE_RULE_HISTORY_WINDOW_DAYS * 24 * 60 * 60 * 1000,
  );
  const conditions = and(
    eq(aiAssessmentApprovalRequestsTable.workspaceId, workspaceId),
    eq(aiAssessmentApprovalRequestsTable.caseId, actionType),
    gte(aiAssessmentApprovalRequestsTable.createdAt, since),
  );
  const [totalRow] = await tx
    .select({ total: count() })
    .from(aiAssessmentApprovalRequestsTable)
    .where(conditions);
  const totalProposalCount = totalRow?.total ?? 0;

  const rows = await tx
    .select({
      approval: {
        caseId: aiAssessmentApprovalRequestsTable.caseId,
        requestedByUserId: aiAssessmentApprovalRequestsTable.requestedByUserId,
        actionSha256: aiAssessmentApprovalRequestsTable.actionSha256,
        proposalSha256: aiAssessmentApprovalRequestsTable.proposalSha256,
      },
      job: {
        profileId: aiAssessmentJobsTable.profileId,
        status: aiAssessmentJobsTable.status,
        result: aiAssessmentJobsTable.result,
      },
    })
    .from(aiAssessmentApprovalRequestsTable)
    .leftJoin(
      aiAssessmentJobsTable,
      and(
        eq(aiAssessmentJobsTable.id, aiAssessmentApprovalRequestsTable.jobId),
        eq(aiAssessmentJobsTable.workspaceId, workspaceId),
      ),
    )
    .where(conditions)
    .orderBy(
      desc(aiAssessmentApprovalRequestsTable.createdAt),
      desc(aiAssessmentApprovalRequestsTable.id),
    )
    .limit(MAX_WORKSPACE_RULE_HISTORY_PROPOSALS);

  const active = await getActiveWorkspaceActionRule(tx, workspaceId, actionType);
  const [head] = await tx
    .select()
    .from(workspaceActionRuleHeadsTable)
    .where(
      and(
        eq(workspaceActionRuleHeadsTable.workspaceId, workspaceId),
        eq(workspaceActionRuleHeadsTable.actionType, actionType),
      ),
    )
    .limit(1);
  const [draft] = head?.draftVersion
    ? await tx
        .select()
        .from(workspaceActionRuleVersionsTable)
        .where(
          and(
            eq(workspaceActionRuleVersionsTable.workspaceId, workspaceId),
            eq(workspaceActionRuleVersionsTable.actionType, actionType),
            eq(workspaceActionRuleVersionsTable.version, head.draftVersion),
          ),
        )
        .limit(1)
    : [];
  const draftValidation = draft
    ? validateWorkspaceActionRuleDocument(actionType, draft.ruleDocument)
    : null;
  const draftDocument = draftValidation?.ok ? draftValidation.document : null;
  const draftVersionId = draftValidation?.ok ? draft.id : null;

  return summarizeWorkspaceRuleHistoryImpact({
    workspaceId,
    actionType,
    totalProposalCount,
    rows,
    activeVersionId: active?.activeVersionId ?? null,
    activeDocument: active?.document ?? null,
    draftVersionId,
    draftDocument,
  });
}
