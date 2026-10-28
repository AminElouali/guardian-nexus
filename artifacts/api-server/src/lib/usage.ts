import { and, eq, lte, sql } from "drizzle-orm";
import { db, monthlyUsageTable } from "@workspace/db";
import type { Plan } from "./plans";

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
  workspaceId: string,
  plan: Plan,
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
  return db.transaction(async (tx) => {
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
  });
}
