import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";

const runtimeLoginRole = "app_runtime_login";
const runtimeRole = "app_runtime";
const workspaceIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type SeedDemoMemberStatus = "inserted" | "already_member";

export type SeedDemoMemberOptions = {
  confirmDevWrite: boolean;
  expectedDatabase: string;
  workspaceId: string;
  ownerUserId: string;
  memberUserId: string;
};

export type SeedDemoMemberResult = {
  status: SeedDemoMemberStatus;
  workspaceIdSuffix: string;
  ownerUserIdSuffix: string;
  memberUserIdSuffix: string;
};

export type SeedDemoMemberErrorCode =
  | "development_only"
  | "deployment_forbidden"
  | "confirmation_required"
  | "arguments_invalid"
  | "actors_must_differ"
  | "database_mismatch"
  | "runtime_login_required"
  | "owner_not_verified"
  | "membership_write_failed";

export class SeedDemoMemberError extends Error {
  constructor(readonly code: SeedDemoMemberErrorCode) {
    super(code);
    this.name = "SeedDemoMemberError";
  }
}

const argumentNames = new Set([
  "--expected-database",
  "--workspace-id",
  "--owner-user-id",
  "--member-user-id",
]);

export function parseSeedDemoMemberArgs(
  suppliedArgs: string[],
): SeedDemoMemberOptions {
  const args = suppliedArgs[0] === "--" ? suppliedArgs.slice(1) : suppliedArgs;
  let confirmDevWrite = false;
  const values = new Map<string, string>();

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index] ?? "";
    if (argument === "--confirm-dev-write") {
      if (confirmDevWrite) {
        throw new SeedDemoMemberError("arguments_invalid");
      }
      confirmDevWrite = true;
      continue;
    }

    const equalsIndex = argument.indexOf("=");
    const name = equalsIndex < 0 ? argument : argument.slice(0, equalsIndex);
    if (!argumentNames.has(name) || values.has(name)) {
      throw new SeedDemoMemberError("arguments_invalid");
    }

    const value =
      equalsIndex < 0 ? args[++index] : argument.slice(equalsIndex + 1);
    if (!value || value.startsWith("--") || value.trim() !== value) {
      throw new SeedDemoMemberError("arguments_invalid");
    }
    values.set(name, value);
  }

  const expectedDatabase = values.get("--expected-database");
  const workspaceId = values.get("--workspace-id");
  const ownerUserId = values.get("--owner-user-id");
  const memberUserId = values.get("--member-user-id");
  if (!expectedDatabase || !workspaceId || !ownerUserId || !memberUserId) {
    throw new SeedDemoMemberError("arguments_invalid");
  }

  return {
    confirmDevWrite,
    expectedDatabase,
    workspaceId,
    ownerUserId,
    memberUserId,
  };
}

export function assertSeedDemoMemberPreconditions(
  options: SeedDemoMemberOptions,
  environment: NodeJS.ProcessEnv,
): void {
  if (environment.NODE_ENV !== "development") {
    throw new SeedDemoMemberError("development_only");
  }
  if (environment.REPLIT_DEPLOYMENT === "1") {
    throw new SeedDemoMemberError("deployment_forbidden");
  }
  if (!options.confirmDevWrite) {
    throw new SeedDemoMemberError("confirmation_required");
  }
  if (
    !options.expectedDatabase ||
    options.expectedDatabase.trim() !== options.expectedDatabase ||
    !workspaceIdPattern.test(options.workspaceId) ||
    !isSafeUserId(options.ownerUserId) ||
    !isSafeUserId(options.memberUserId)
  ) {
    throw new SeedDemoMemberError("arguments_invalid");
  }
  if (options.ownerUserId === options.memberUserId) {
    throw new SeedDemoMemberError("actors_must_differ");
  }
}

function isSafeUserId(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 256 &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function suffix(value: string): string {
  return value.slice(-4);
}

async function setUserContext(
  client: PoolClient,
  userId: string,
): Promise<void> {
  await client.query("SELECT set_config('app.user_id', $1, true)", [userId]);
}

async function setWorkspaceContext(
  client: PoolClient,
  workspaceId: string,
): Promise<void> {
  await client.query("SELECT set_config('app.workspace_id', $1, true)", [
    workspaceId,
  ]);
}

/**
 * Add a new workspace member with the least-privileged role allowed by the
 * current contract. The database has no literal "member" role; viewer is the
 * valid baseline that the workspace owner can later promote in the UI.
 */
export async function seedDemoMember(
  pool: Pick<Pool, "connect">,
  options: SeedDemoMemberOptions,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<SeedDemoMemberResult> {
  assertSeedDemoMemberPreconditions(options, environment);

  let client: PoolClient | undefined;
  let transactionStarted = false;
  try {
    client = await pool.connect();
    await client.query("BEGIN");
    transactionStarted = true;

    const identity = await client.query<{
      database_name: string;
      session_role: string;
      current_role: string;
    }>(
      `SELECT current_database() AS database_name,
              session_user::text AS session_role,
              current_user::text AS current_role`,
    );
    const connection = identity.rows[0];
    if (!connection || connection.database_name !== options.expectedDatabase) {
      throw new SeedDemoMemberError("database_mismatch");
    }
    if (
      connection.session_role !== runtimeLoginRole ||
      connection.current_role !== runtimeLoginRole
    ) {
      throw new SeedDemoMemberError("runtime_login_required");
    }

    await client.query(`SET LOCAL ROLE ${runtimeRole}`);
    await setUserContext(client, options.ownerUserId);
    await setWorkspaceContext(client, options.workspaceId);
    const ownerMembership = await client.query<{ role: string }>(
      `SELECT role
         FROM public.workspace_memberships
        WHERE workspace_id = $1
          AND user_id = $2
        LIMIT 1`,
      [options.workspaceId, options.ownerUserId],
    );
    if (ownerMembership.rows[0]?.role !== "owner") {
      throw new SeedDemoMemberError("owner_not_verified");
    }

    await setWorkspaceContext(client, options.workspaceId);
    await setUserContext(client, options.memberUserId);
    const inserted = await client.query(
      `INSERT INTO public.workspace_memberships
         (workspace_id, user_id, role)
       VALUES ($1, $2, 'viewer')
       ON CONFLICT (workspace_id, user_id) DO NOTHING`,
      [options.workspaceId, options.memberUserId],
    );
    if (inserted.rowCount !== 0 && inserted.rowCount !== 1) {
      throw new SeedDemoMemberError("membership_write_failed");
    }

    await client.query("COMMIT");
    transactionStarted = false;
    return {
      status: inserted.rowCount === 1 ? "inserted" : "already_member",
      workspaceIdSuffix: suffix(options.workspaceId),
      ownerUserIdSuffix: suffix(options.ownerUserId),
      memberUserIdSuffix: suffix(options.memberUserId),
    };
  } catch (error) {
    if (transactionStarted && client) {
      await client.query("ROLLBACK").catch(() => undefined);
    }
    if (error instanceof SeedDemoMemberError) {
      throw error;
    }
    throw new SeedDemoMemberError("membership_write_failed");
  } finally {
    client?.release();
  }
}

async function main(): Promise<void> {
  let runtimePool: Pool | undefined;
  try {
    const options = parseSeedDemoMemberArgs(process.argv.slice(2));
    assertSeedDemoMemberPreconditions(options, process.env);
    const { pool } = await import("@workspace/db");
    runtimePool = pool;
    const result = await seedDemoMember(runtimePool, options, process.env);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const code =
      error instanceof SeedDemoMemberError
        ? error.code
        : "membership_write_failed";
    process.stderr.write(`seed-demo-member: ${code}\n`);
    process.exitCode = 1;
  } finally {
    await runtimePool?.end().catch(() => undefined);
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  void main();
}
