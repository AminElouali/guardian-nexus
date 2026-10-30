import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import pg from "pg";
import { sql } from "drizzle-orm";
import {
  assertRlsRuntimeReady,
  assetsTable,
  db,
  pool,
} from "@workspace/db";
import { canManageMemberRoles, canWriteAssets } from "./lib/access-control";
import { UsageQuotaError, reserveWorkspaceUsage } from "./lib/usage";
import { withWorkspaceUserTransaction } from "./lib/tenant-db";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required for isolated security-test fixtures.");
}
const fixturePool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const userA = `rls-test-a-${randomUUID()}`;
const userB = `rls-test-b-${randomUUID()}`;
let workspaceA: string;
let workspaceB: string;
let assetA: string;
let assetB: string;

before(async () => {
  await assertRlsRuntimeReady();

  const [createdA, createdB] = await Promise.all([
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.workspaces (name, plan_id, created_by_user_id)
       VALUES ('RLS test tenant A', 'small', $1) RETURNING id`,
      [userA],
    ),
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.workspaces (name, plan_id, created_by_user_id)
       VALUES ('RLS test tenant B', 'small', $1) RETURNING id`,
      [userB],
    ),
  ]);
  workspaceA = createdA.rows[0].id;
  workspaceB = createdB.rows[0].id;

  await fixturePool.query(
    `INSERT INTO public.workspace_memberships (workspace_id, user_id, role)
     VALUES ($1, $2, 'owner'), ($3, $4, 'owner')`,
    [workspaceA, userA, workspaceB, userB],
  );
  const [createdAssetA, createdAssetB] = await Promise.all([
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.assets
         (workspace_id, name, type, environment, criticality)
       VALUES ($1, 'Tenant A test asset', 'application', 'test', 'low')
       RETURNING id`,
      [workspaceA],
    ),
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.assets
         (workspace_id, name, type, environment, criticality)
       VALUES ($1, 'Tenant B test asset', 'application', 'test', 'low')
       RETURNING id`,
      [workspaceB],
    ),
  ]);
  assetA = createdAssetA.rows[0].id;
  assetB = createdAssetB.rows[0].id;
});

after(async () => {
  if (workspaceA && workspaceB) {
    await fixturePool.query(
      `DELETE FROM public.workspaces WHERE id = ANY($1::uuid[])`,
      [[workspaceA, workspaceB]],
    );
  }
  await pool.end();
  await fixturePool.end();
});

test("API runtime login has no direct table access or elevated privileges", async () => {
  const result = await db.execute(sql`
    SELECT
      session_user::text AS session_role,
      current_user::text AS current_role,
      rolsuper,
      rolbypassrls,
      rolcanlogin,
      rolcreatedb,
      rolcreaterole,
      rolreplication,
      rolinherit,
      has_table_privilege(session_user, 'public.assets', 'SELECT') AS direct_read,
      has_table_privilege(session_user, 'public.assets', 'INSERT') AS direct_write
    FROM pg_roles
    WHERE rolname = session_user
  `);
  const role = result.rows[0];
  assert.equal(role?.session_role, "app_runtime_login");
  assert.equal(role?.current_role, "app_runtime_login");
  assert.equal(role?.rolsuper, false);
  assert.equal(role?.rolbypassrls, false);
  assert.equal(role?.rolcanlogin, true);
  assert.equal(role?.rolcreatedb, false);
  assert.equal(role?.rolcreaterole, false);
  assert.equal(role?.rolreplication, false);
  assert.equal(role?.rolinherit, false);
  assert.equal(role?.direct_read, false);
  assert.equal(role?.direct_write, false);
});

test("RLS scopes unfiltered asset reads to the verified tenant", async () => {
  const result = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) => tx.select().from(assetsTable),
  );

  assert.equal(result.authorized, true);
  if (!result.authorized) return;
  assert.deepEqual(
    result.value.map((asset) => asset.id),
    [assetA],
  );
  assert.equal(result.value.some((asset) => asset.id === assetB), false);
});

test("a member cannot enter another workspace context", async () => {
  const result = await withWorkspaceUserTransaction(
    userA,
    workspaceB,
    (tx) => tx.select().from(assetsTable),
  );
  assert.deepEqual(result, { authorized: false });
});

test("RLS rejects writes across workspace boundaries", async () => {
  await assert.rejects(
    withWorkspaceUserTransaction(userA, workspaceA, async (tx) => {
      await tx.insert(assetsTable).values({
        workspaceId: workspaceB,
        name: "Must be rejected",
        type: "application",
        environment: "test",
        criticality: "low",
      });
    }),
    (error: { cause?: { code?: string } }) => error.cause?.code === "42501",
  );
});

test("workspace usage limits are enforced atomically", async () => {
  await assert.rejects(
    reserveWorkspaceUsage(userA, workspaceA, { tokens: 100_001 }),
    UsageQuotaError,
  );
});

test("basic workspace role permissions are explicit", () => {
  assert.equal(canWriteAssets("owner"), true);
  assert.equal(canWriteAssets("admin"), true);
  assert.equal(canWriteAssets("analyst"), true);
  assert.equal(canWriteAssets("viewer"), false);
  assert.equal(canManageMemberRoles("owner"), true);
  assert.equal(canManageMemberRoles("admin"), false);
});
