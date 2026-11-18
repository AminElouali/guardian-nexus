import { and, eq, sql } from "drizzle-orm";
import {
  db,
  membershipsTable,
  workspaceAgentsTable,
  type Membership,
  type WorkspaceAgent,
} from "@workspace/db";

export type TenantTransaction = Parameters<Parameters<typeof db.transaction>[0]>[0];

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

/**
 * Authenticate a workspace-scoped agent using only its SHA-256 bearer-token
 * digest. The raw credential must never enter this helper, SQL parameters,
 * logs, or an error message.
 */
export async function withAgentWorkspaceTransaction<T>(
  workspaceId: string,
  credentialSha256: string,
  operation: (
    tx: TenantTransaction,
    agent: WorkspaceAgent,
    membership: Membership,
  ) => Promise<T>,
): Promise<
  | { authorized: false }
  | { authorized: true; agent: WorkspaceAgent; membership: Membership; value: T }
> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SET LOCAL ROLE app_runtime`);
    await setWorkspaceContext(tx, workspaceId);
    await tx.execute(sql`SELECT set_config('app.user_id', '', true)`);
    await tx.execute(
      sql`SELECT set_config('app.agent_credential_sha256', ${credentialSha256}, true)`,
    );
    await tx.execute(sql`SELECT set_config('app.agent_id', '', true)`);
    const [agent] = await tx
      .select()
      .from(workspaceAgentsTable)
      .where(
        and(
          eq(workspaceAgentsTable.workspaceId, workspaceId),
          eq(workspaceAgentsTable.credentialSha256, credentialSha256),
        ),
      )
      .limit(1);
    if (!agent || agent.revokedAt !== null) {
      return { authorized: false };
    }

    await tx.execute(
      sql`SELECT set_config('app.user_id', ${agent.principalUserId}, true)`,
    );
    await tx.execute(
      sql`SELECT set_config('app.agent_id', ${agent.id}, true)`,
    );
    const [membership] = await tx
      .select()
      .from(membershipsTable)
      .where(
        and(
          eq(membershipsTable.workspaceId, workspaceId),
          eq(membershipsTable.userId, agent.principalUserId),
        ),
      )
      .limit(1);
    if (!membership) return { authorized: false };
    return {
      authorized: true,
      agent,
      membership,
      value: await operation(tx, agent, membership),
    };
  });
}
