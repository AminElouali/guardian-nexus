import { createHash } from "node:crypto";
import { and, count, desc, eq, gte, inArray, max, sql } from "drizzle-orm";
import {
  APPROVAL_ACTION_CATALOG,
  evaluateWorkspaceActionRule,
  getApprovalActionDefinition,
  getWorkspaceRuleWarnings,
  validateWorkspaceActionRuleDocument,
  type WorkspaceActionRuleDocument,
  type WorkspaceRuleEvaluationContext,
} from "@workspace/db";
import {
  workspaceActionRuleHeadsTable,
  workspaceActionRuleVersionsTable,
  workspaceAuditEventsTable,
} from "@workspace/db";
import type { TenantTransaction } from "./tenant-db";
import { canonicalApprovalJson } from "./ai-assessment-approval-actions";

const VOLUME_AUDIT_ACTIONS = [
  "ai_assessment.generic_action_decision",
  "ai_assessment.generic_action_proposal_requested",
] as const;

export async function getWorkspaceActionRuleEvaluationContext(
  tx: TenantTransaction,
  workspaceId: string,
  actionType: string,
  document: WorkspaceActionRuleDocument | null,
): Promise<WorkspaceRuleEvaluationContext> {
  const definition = getApprovalActionDefinition(actionType);
  const windows = new Set<number>();
  for (const rule of document?.rules ?? []) {
    for (const condition of [...(rule.when.all ?? []), ...(rule.when.any ?? [])]) {
      if (
        condition.field === "context.action_count" &&
        typeof condition.windowSeconds === "number"
      ) {
        windows.add(condition.windowSeconds);
      }
    }
  }

  const actionCountsByWindow: Record<number, number | null> = {};
  for (const windowSeconds of windows) {
    const [row] = await tx
      .select({ total: count() })
      .from(workspaceAuditEventsTable)
      .where(
        and(
          eq(workspaceAuditEventsTable.workspaceId, workspaceId),
          inArray(workspaceAuditEventsTable.action, [...VOLUME_AUDIT_ACTIONS]),
          gte(
            workspaceAuditEventsTable.createdAt,
            sql`now() - (${windowSeconds} * interval '1 second')`,
          ),
          sql`${workspaceAuditEventsTable.metadata}->>'actionType' = ${actionType}`,
          sql`${workspaceAuditEventsTable.metadata}->>'actionSha256' ~ '^[a-f0-9]{64}$'`,
        ),
      );
    actionCountsByWindow[windowSeconds] = row?.total ?? 0;
  }

  return {
    dataSensitivity: definition
      ? definition.riskCategories.includes("customer_data")
        ? "sensitive"
        : "normal"
      : null,
    // Only the registered synthetic adapters exist today. A real environment
    // is unavailable until a real connector is deliberately registered.
    environment: definition?.syntheticTemplateText ? "test" : null,
    actionCountsByWindow,
  };
}

function sha256(value: unknown): string {
  return createHash("sha256")
    .update(canonicalApprovalJson(value), "utf8")
    .digest("hex");
}

export type WorkspaceActionRuleHead = {
  actionType: string;
  activeVersion: number | null;
  draftVersion: number | null;
  activeVersionId: string | null;
  draftVersionId: string | null;
  document: WorkspaceActionRuleDocument | null;
  documentSha256: string | null;
};

export async function lockWorkspaceActionRule(
  tx: TenantTransaction,
  workspaceId: string,
  actionType: string,
): Promise<void> {
  await tx.execute(
    // Serialize version allocation and head changes within this workspace/action.
    // A hash collision only serializes unrelated edits; it cannot grant access.
    sql`
      SELECT pg_advisory_xact_lock(
        hashtextextended(${`${workspaceId}:${actionType}`}, 0)
      )
    `,
  );
}

export async function getActiveWorkspaceActionRule(
  tx: TenantTransaction,
  workspaceId: string,
  actionType: string,
): Promise<WorkspaceActionRuleHead | null> {
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
  if (!head?.activeVersion) return null;
  const [version] = await tx
    .select()
    .from(workspaceActionRuleVersionsTable)
    .where(
      and(
        eq(workspaceActionRuleVersionsTable.workspaceId, workspaceId),
        eq(workspaceActionRuleVersionsTable.actionType, actionType),
        eq(workspaceActionRuleVersionsTable.version, head.activeVersion),
      ),
    )
    .limit(1);
  if (!version) return null;
  const validated = validateWorkspaceActionRuleDocument(
    actionType,
    version.ruleDocument,
  );
  if (!validated.ok) return null;
  return {
    actionType,
    activeVersion: head.activeVersion,
    draftVersion: head.draftVersion,
    activeVersionId: version.id,
    draftVersionId: null,
    document: validated.document,
    documentSha256: sha256(validated.document),
  };
}

export async function listWorkspaceActionRuleStates(
  tx: TenantTransaction,
  workspaceId: string,
) {
  const heads = await tx
    .select()
    .from(workspaceActionRuleHeadsTable)
    .where(eq(workspaceActionRuleHeadsTable.workspaceId, workspaceId));
  const versions = await tx
    .select()
    .from(workspaceActionRuleVersionsTable)
    .where(eq(workspaceActionRuleVersionsTable.workspaceId, workspaceId))
    .orderBy(desc(workspaceActionRuleVersionsTable.version));

  return APPROVAL_ACTION_CATALOG.map((definition) => {
    const head = heads.find((item) => item.actionType === definition.actionType);
    const actionVersionRows = versions
      .filter((item) => item.actionType === definition.actionType);
    const visibleVersionRows = actionVersionRows
      .slice(0, 50);
    for (const pinnedVersion of [head?.activeVersion, head?.draftVersion]) {
      if (
        pinnedVersion &&
        !visibleVersionRows.some((item) => item.version === pinnedVersion)
      ) {
        const pinned = actionVersionRows.find((item) => item.version === pinnedVersion);
        if (pinned) visibleVersionRows.push(pinned);
      }
    }
    const actionVersions = visibleVersionRows
      .map((item) => {
        const valid = validateWorkspaceActionRuleDocument(
          definition.actionType,
          item.ruleDocument,
        );
        return {
          id: item.id,
          version: item.version,
          rules: valid.ok ? valid.document.rules : [],
          approvalPolicy: valid.ok
            ? valid.document.approvalPolicy ?? null
            : null,
          createdByUserId: item.createdByUserId,
          createdAt: item.createdAt.toISOString(),
          isActive: item.version === head?.activeVersion,
          isDraft: item.version === head?.draftVersion,
        };
      });
    const activeVersion = actionVersions.find((item) => item.isActive);
    const draftVersion = actionVersions.find((item) => item.isDraft);
    const activeDoc = activeVersion
      ? {
          version: 1 as const,
          rules: activeVersion.rules,
          ...(activeVersion.approvalPolicy
            ? { approvalPolicy: activeVersion.approvalPolicy }
            : {}),
        }
      : null;
    const draftDoc = draftVersion
      ? {
          version: 1 as const,
          rules: draftVersion.rules,
          ...(draftVersion.approvalPolicy
            ? { approvalPolicy: draftVersion.approvalPolicy }
            : {}),
        }
      : null;
    const warningDetails = [
      ...(activeDoc
        ? getWorkspaceRuleWarnings(definition.actionType, activeDoc)
        : []),
      ...(draftDoc
        ? getWorkspaceRuleWarnings(definition.actionType, draftDoc)
        : []),
    ];
    return {
      actionType: definition.actionType,
      service: definition.service,
      label: definition.label,
      description: definition.description,
      riskClass: definition.riskClass,
      riskCategories: [...definition.riskCategories],
      requiresIndependentApprover: definition.requiresIndependentApprover,
      minimumApproverCount: definition.minimumApproverCount ?? 1,
      approvalAmountField: definition.approvalAmountField ?? null,
      activeApprovalPolicy: activeVersion?.approvalPolicy ?? null,
      draftApprovalPolicy: draftVersion?.approvalPolicy ?? null,
      argumentFields: Object.entries(definition.argumentSchema.properties).map(
        ([name, property]) => ({
          name,
          type: property.type === "integer"
            ? "number" as const
            : property.type === "boolean"
              ? "boolean" as const
              : "text" as const,
          required: property.required === true,
        }),
      ),
      activeVersionId: activeVersion?.id ?? null,
      draftVersionId: draftVersion?.id ?? null,
      activeRules: activeVersion?.rules ?? [],
      draftRules: draftVersion?.rules ?? [],
      history: actionVersions,
      warnings: warningDetails.map((warning) => warning.message),
      openRuleIds: [...new Set(
        warningDetails
          .filter((warning) =>
            warning.code === "unconditional_allow" ||
            warning.code === "unbounded_recipient",
          )
          .flatMap((warning) => warning.ruleIds),
      )],
    };
  });
}

export async function createWorkspaceActionRuleVersion(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    actionType: string;
    actorUserId: string;
    document: unknown;
    activate: boolean;
  },
) {
  const definition = getApprovalActionDefinition(input.actionType);
  const parsed = validateWorkspaceActionRuleDocument(
    input.actionType,
    input.document,
  );
  if (!definition || !parsed.ok) {
    return { kind: "invalid" as const, issues: parsed.ok ? [] : parsed.issues };
  }

  await lockWorkspaceActionRule(tx, input.workspaceId, input.actionType);
  const [head] = await tx
    .select()
    .from(workspaceActionRuleHeadsTable)
    .where(
      and(
        eq(workspaceActionRuleHeadsTable.workspaceId, input.workspaceId),
        eq(workspaceActionRuleHeadsTable.actionType, input.actionType),
      ),
    )
    .for("update")
    .limit(1);
  const [maxVersion] = await tx
    .select({ value: max(workspaceActionRuleVersionsTable.version) })
    .from(workspaceActionRuleVersionsTable)
    .where(
      and(
        eq(workspaceActionRuleVersionsTable.workspaceId, input.workspaceId),
        eq(workspaceActionRuleVersionsTable.actionType, input.actionType),
      ),
    );
  const versionNumber = (maxVersion?.value ?? 0) + 1;
  const [version] = await tx
    .insert(workspaceActionRuleVersionsTable)
    .values({
      workspaceId: input.workspaceId,
      actionType: input.actionType,
      version: versionNumber,
      ruleDocument: parsed.document,
      createdByUserId: input.actorUserId,
    })
    .returning();
  if (!version) return { kind: "failed" as const };

  const nextHead = {
    workspaceId: input.workspaceId,
    actionType: input.actionType,
    activeVersion: input.activate ? versionNumber : (head?.activeVersion ?? null),
    draftVersion: input.activate ? null : versionNumber,
    updatedByUserId: input.actorUserId,
    updatedAt: new Date(),
  };
  if (head) {
    await tx
      .update(workspaceActionRuleHeadsTable)
      .set(nextHead)
      .where(
        and(
          eq(workspaceActionRuleHeadsTable.workspaceId, input.workspaceId),
          eq(workspaceActionRuleHeadsTable.actionType, input.actionType),
        ),
      );
  } else {
    await tx.insert(workspaceActionRuleHeadsTable).values(nextHead);
  }
  await tx.insert(workspaceAuditEventsTable).values({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: input.activate
      ? "workspace.action_rule.created_and_activated"
      : "workspace.action_rule.draft_created",
    resourceType: "workspace_action_rule_version",
    resourceId: version.id,
    metadata: {
      actionType: input.actionType,
      version: versionNumber,
      activated: input.activate,
      ruleCount: parsed.document.rules.length,
    },
  });
  return {
    kind: "created" as const,
    version,
    active: input.activate,
  };
}

export async function activateWorkspaceActionRule(
  tx: TenantTransaction,
  input: { workspaceId: string; actionType: string; actorUserId: string },
) {
  await lockWorkspaceActionRule(tx, input.workspaceId, input.actionType);
  const [head] = await tx
    .select()
    .from(workspaceActionRuleHeadsTable)
    .where(
      and(
        eq(workspaceActionRuleHeadsTable.workspaceId, input.workspaceId),
        eq(workspaceActionRuleHeadsTable.actionType, input.actionType),
      ),
    )
    .for("update")
    .limit(1);
  if (!head?.draftVersion) return { kind: "no_draft" as const };
  const [version] = await tx
    .select()
    .from(workspaceActionRuleVersionsTable)
    .where(
      and(
        eq(workspaceActionRuleVersionsTable.workspaceId, input.workspaceId),
        eq(workspaceActionRuleVersionsTable.actionType, input.actionType),
        eq(workspaceActionRuleVersionsTable.version, head.draftVersion),
      ),
    )
    .limit(1);
  if (!version) return { kind: "no_draft" as const };
  await tx
    .update(workspaceActionRuleHeadsTable)
    .set({
      activeVersion: version.version,
      draftVersion: null,
      updatedByUserId: input.actorUserId,
      updatedAt: new Date(),
    })
    .where(
      and(
        eq(workspaceActionRuleHeadsTable.workspaceId, input.workspaceId),
        eq(workspaceActionRuleHeadsTable.actionType, input.actionType),
      ),
    );
  await tx.insert(workspaceAuditEventsTable).values({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "workspace.action_rule.activated",
    resourceType: "workspace_action_rule_version",
    resourceId: version.id,
    metadata: { actionType: input.actionType, version: version.version },
  });
  return { kind: "activated" as const, version };
}

export async function rollbackWorkspaceActionRule(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    actionType: string;
    actorUserId: string;
    sourceVersion: number;
  },
) {
  await lockWorkspaceActionRule(tx, input.workspaceId, input.actionType);
  const [source] = await tx
    .select()
    .from(workspaceActionRuleVersionsTable)
    .where(
      and(
        eq(workspaceActionRuleVersionsTable.workspaceId, input.workspaceId),
        eq(workspaceActionRuleVersionsTable.actionType, input.actionType),
        eq(workspaceActionRuleVersionsTable.version, input.sourceVersion),
      ),
    )
    .limit(1);
  if (!source) return { kind: "not_found" as const };
  const parsed = validateWorkspaceActionRuleDocument(
    input.actionType,
    source.ruleDocument,
  );
  if (!parsed.ok) return { kind: "not_found" as const };
  const created = await createWorkspaceActionRuleVersion(tx, {
    workspaceId: input.workspaceId,
    actionType: input.actionType,
    actorUserId: input.actorUserId,
    document: parsed.document,
    activate: false,
  });
  if (created.kind !== "created") return created;
  await tx.insert(workspaceAuditEventsTable).values({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "workspace.action_rule.rolled_back",
    resourceType: "workspace_action_rule_version",
    resourceId: created.version.id,
    metadata: {
      actionType: input.actionType,
      sourceVersion: input.sourceVersion,
      newVersion: created.version.version,
      activated: false,
    },
  });
  return { kind: "rolled_back" as const, version: created.version };
}

export function toWorkspaceActionRuleSimulation(input: {
  actionType: string;
  args: unknown;
  versionId: string | null;
  document: WorkspaceActionRuleDocument | null;
  context?: WorkspaceRuleEvaluationContext;
}) {
  const result = evaluateWorkspaceActionRule({
    actionType: input.actionType,
    arguments: input.args,
    document: input.document,
    ruleVersionId: input.versionId,
    context: input.context,
  });
  return {
    actionType: input.actionType,
    decision: result.decision,
    reasonCode: result.reasonCode,
    ruleId: result.ruleId,
    ruleVersionId: result.ruleVersionId,
    matched: result.ruleId !== null,
    persisted: false as const,
    dispatched: false as const,
    issues: result.issues,
  };
}

