import { and, eq, lte, sql } from "drizzle-orm";
import {
  monthlyUsageTable,
  workspacesTable,
} from "@workspace/db";
import { withWorkspaceUserTransaction } from "./tenant-db";
import { getPlan } from "./plans";

export type UsageDelta = {
  scans?: number;
  tokens?: number;
  apiRequests?: number;
};

export class UsageQuotaError extends Error {
  constructor() {
    super("Monthly workspace usage limit reached");
    this.name = "UsageQuotaError";
  }
}

export class WorkspaceAccessDeniedError extends Error {
  constructor() {
    super("Workspace access denied");
    this.name = "WorkspaceAccessDeniedError";
  }
}

function currentMonthStart(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}-01`;
}

/**
 * Atomically reserve usage before a trusted server-side scan, AI, or provider
 * request. Keep calls to this helper on the server; never accept usage claims
 * directly from a browser.
 */
export async function reserveWorkspaceUsage(
  userId: string,
  workspaceId: string,
  delta: UsageDelta,
) {
  const scans = delta.scans ?? 0;
  const tokens = delta.tokens ?? 0;
  const apiRequests = delta.apiRequests ?? 0;
  if (
    [scans, tokens, apiRequests].some(
      (value) => !Number.isSafeInteger(value) || value < 0,
    )
  ) {
    throw new Error("Usage must be a non-negative safe integer");
  }

  const monthStart = currentMonthStart();
  const result = await withWorkspaceUserTransaction(
    userId,
    workspaceId,
    async (tx) => {
      const [workspace] = await tx
        .select({ planId: workspacesTable.planId })
        .from(workspacesTable)
        .where(eq(workspacesTable.id, workspaceId))
        .limit(1);
      const plan = workspace ? getPlan(workspace.planId) : undefined;
      if (!plan) throw new Error("Workspace has an invalid plan");

      await tx
        .insert(monthlyUsageTable)
        .values({ workspaceId, monthStart })
        .onConflictDoNothing({
          target: [monthlyUsageTable.workspaceId, monthlyUsageTable.monthStart],
        });

      const [usage] = await tx
        .update(monthlyUsageTable)
        .set({
          scansUsed: sql`${monthlyUsageTable.scansUsed} + ${scans}`,
          tokensUsed: sql`${monthlyUsageTable.tokensUsed} + ${tokens}`,
          apiRequestsUsed: sql`${monthlyUsageTable.apiRequestsUsed} + ${apiRequests}`,
        })
        .where(
          and(
            eq(monthlyUsageTable.workspaceId, workspaceId),
            eq(monthlyUsageTable.monthStart, monthStart),
            lte(sql`${monthlyUsageTable.scansUsed} + ${scans}`, plan.scansPerMonth),
            lte(sql`${monthlyUsageTable.tokensUsed} + ${tokens}`, plan.tokensPerMonth),
            lte(
              sql`${monthlyUsageTable.apiRequestsUsed} + ${apiRequests}`,
              plan.apiRequestsPerMonth,
            ),
          ),
        )
        .returning();

      if (!usage) {
        throw new UsageQuotaError();
      }
      return usage;
    },
  );

  if (!result.authorized) throw new WorkspaceAccessDeniedError();
  return result.value;
}
