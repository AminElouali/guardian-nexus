import { and, eq, sql } from "drizzle-orm";
import { db, membershipsTable, type Membership } from "@workspace/db";

type TenantTransaction = Parameters<Parameters<typeof db.transaction>[0]>[0];

async function setUserContext(tx: TenantTransaction, userId: string) {
  await tx.execute(sql`SET LOCAL ROLE app_runtime`);
  await tx.execute(sql`SELECT set_config('app.user_id', ${userId}, true)`);
  await tx.execute(sql`SELECT set_config('app.workspace_id', '', true)`);
}

/**
 * Run an authenticated database operation as the restricted RLS role.
 * Never pass caller-controlled workspace IDs directly to setWorkspaceContext:
 * workspace membership must be verified in this transaction first.
 */
export async function withUserTransaction<T>(
  userId: string,
  operation: (tx: TenantTransaction) => Promise<T>,
): Promise<T> {
  return db.transaction(async (tx) => {
    await setUserContext(tx, userId);
    return operation(tx);
  });
}

export async function setWorkspaceContext(
  tx: TenantTransaction,
  workspaceId: string,
): Promise<void> {
  await tx.execute(
    sql`SELECT set_config('app.workspace_id', ${workspaceId}, true)`,
  );
}

export async function withWorkspaceUserTransaction<T>(
  userId: string,
  workspaceId: string,
  operation: (tx: TenantTransaction, membership: Membership) => Promise<T>,
): Promise<
  | { authorized: false }
  | { authorized: true; membership: Membership; value: T }
> {
  return db.transaction(async (tx) => {
    await setUserContext(tx, userId);
    const [membership] = await tx
      .select()
      .from(membershipsTable)
      .where(
        and(
          eq(membershipsTable.workspaceId, workspaceId),
          eq(membershipsTable.userId, userId),
        ),
      )
      .limit(1);

    if (!membership) return { authorized: false };

    await setWorkspaceContext(tx, workspaceId);
    return {
      authorized: true,
      membership,
      value: await operation(tx, membership),
    };
  });
}

export function hasWorkspaceMembership(
  userId: string,
  workspaceId: string,
) {
  return withUserTransaction(userId, async (tx) => {
    const [membership] = await tx
      .select({ id: membershipsTable.id })
      .from(membershipsTable)
      .where(
        and(
          eq(membershipsTable.workspaceId, workspaceId),
          eq(membershipsTable.userId, userId),
        ),
      )
      .limit(1);
    return Boolean(membership);
  });
}
