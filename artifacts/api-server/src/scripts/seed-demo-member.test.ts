import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import pg from "pg";
import type { Pool as PgPool } from "pg";
import {
  assertSeedDemoMemberPreconditions,
  parseSeedDemoMemberArgs,
  SeedDemoMemberError,
  seedDemoMember,
  type SeedDemoMemberOptions,
} from "./seed-demo-member.js";

const { Pool } = pg;
const testWorkspaceId = "11111111-1111-4111-8111-111111111111";
const validOptions: SeedDemoMemberOptions = {
  confirmDevWrite: true,
  expectedDatabase: "guardian_demo_test",
  workspaceId: testWorkspaceId,
  ownerUserId: "user_demo_owner",
  memberUserId: "user_demo_member",
};

function assertSeedError(code: SeedDemoMemberError["code"]) {
  return (error: unknown) =>
    error instanceof SeedDemoMemberError && error.code === code;
}

test("CLI accepts the explicit development confirmation and required IDs", () => {
  assert.deepEqual(
    parseSeedDemoMemberArgs([
      "--confirm-dev-write",
      "--expected-database=guardian_demo_test",
      "--workspace-id",
      testWorkspaceId,
      "--owner-user-id",
      "user_demo_owner",
      "--member-user-id",
      "user_demo_member",
    ]),
    validOptions,
  );
});

test("CLI requires every identifier and rejects unsupported privilege roles", () => {
  const requiredPairs = [
    ["--expected-database", "guardian_demo_test"],
    ["--workspace-id", testWorkspaceId],
    ["--owner-user-id", "user_demo_owner"],
    ["--member-user-id", "user_demo_member"],
  ];
  assert.throws(
    () => parseSeedDemoMemberArgs(["--confirm-dev-write"]),
    assertSeedError("arguments_invalid"),
  );
  for (const [omittedFlag] of requiredPairs) {
    assert.throws(
      () =>
        parseSeedDemoMemberArgs([
          "--confirm-dev-write",
          ...requiredPairs
            .filter(([flag]) => flag !== omittedFlag)
            .flatMap(([flag, value]) => [flag, value]),
        ]),
      assertSeedError("arguments_invalid"),
    );
  }
  for (const role of ["owner", "admin", "member"]) {
    assert.throws(
      () =>
        parseSeedDemoMemberArgs([
          "--confirm-dev-write",
          "--expected-database",
          "guardian_demo_test",
          "--workspace-id",
          testWorkspaceId,
          "--owner-user-id",
          "user_demo_owner",
          "--member-user-id",
          "user_demo_member",
          "--role",
          role,
        ]),
      assertSeedError("arguments_invalid"),
    );
  }
});

test("write is refused without explicit confirmation or in production/deployment", () => {
  const noConfirmation = parseSeedDemoMemberArgs([
    "--expected-database=guardian_demo_test",
    "--workspace-id",
    testWorkspaceId,
    "--owner-user-id",
    "user_demo_owner",
    "--member-user-id",
    "user_demo_member",
  ]);
  assert.throws(
    () =>
      assertSeedDemoMemberPreconditions(noConfirmation, {
        NODE_ENV: "development",
      }),
    assertSeedError("confirmation_required"),
  );
  assert.throws(
    () =>
      assertSeedDemoMemberPreconditions(validOptions, {
        NODE_ENV: "production",
      }),
    assertSeedError("development_only"),
  );
  assert.throws(
    () =>
      assertSeedDemoMemberPreconditions(validOptions, {
        NODE_ENV: "development",
        REPLIT_DEPLOYMENT: "1",
      }),
    assertSeedError("deployment_forbidden"),
  );
  assert.throws(
    () =>
      assertSeedDemoMemberPreconditions(validOptions, {
        NODE_ENV: "test",
      }),
    assertSeedError("development_only"),
  );
});

test("database-backed seed runs only in the isolated disposable PostgreSQL lab", {
  skip:
    process.env.GUARDIAN_DEMO_MEMBER_TEST_REQUIRED === "1"
      ? false
      : "integration case is run by lab:local",
}, async (t) => {
  assert.equal(process.env.GUARDIAN_APPROVAL_E2E_DISPOSABLE, "1");
  const expectedDatabase = process.env.GUARDIAN_APPROVAL_E2E_DATABASE_NAME;
  const adminUrl = process.env.DATABASE_URL;
  assert.ok(expectedDatabase);
  assert.ok(adminUrl);
  assert.ok(process.env.APP_RUNTIME_DATABASE_URL);

  const adminPool = new Pool({
    connectionString: adminUrl,
    max: 1,
    connectionTimeoutMillis: 5000,
  });
  let runtimePool: PgPool | undefined;
  const workspaceId = randomUUID();
  const ownerUserId = `demo-owner-${randomUUID()}`;
  const memberUserId = `demo-member-${randomUUID()}`;
  const nonOwnerUserId = `demo-viewer-${randomUUID()}`;
  const notInsertedUserId = `demo-not-inserted-${randomUUID()}`;
  let workspaceCreated = false;

  try {
    const db = await import("@workspace/db");
    runtimePool = db.pool;
    const runtimeDbPool = runtimePool;
    const dbIdentity = await adminPool.query<{
      database_name: string;
      session_role: string;
    }>(
      "SELECT current_database() AS database_name, session_user::text AS session_role",
    );
    assert.equal(dbIdentity.rows[0]?.database_name, expectedDatabase);
    assert.equal(dbIdentity.rows[0]?.session_role, "postgres");

    await adminPool.query(
      `INSERT INTO public.workspaces
         (id, name, plan_id, created_by_user_id)
       VALUES ($1, 'Disposable seed-demo-member fixture', 'small', $2)`,
      [workspaceId, ownerUserId],
    );
    workspaceCreated = true;
    await adminPool.query(
      `INSERT INTO public.workspace_memberships
         (workspace_id, user_id, role)
       VALUES ($1, $2, 'owner'), ($1, $3, 'viewer')`,
      [workspaceId, ownerUserId, nonOwnerUserId],
    );

    const options: SeedDemoMemberOptions = {
      confirmDevWrite: true,
      expectedDatabase,
      workspaceId,
      ownerUserId,
      memberUserId,
    };
    const environment = {
      NODE_ENV: "development",
      GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    } as NodeJS.ProcessEnv;

    assert.ok(runtimeDbPool);
    const first = await seedDemoMember(runtimeDbPool, options, environment);
    assert.equal(first.status, "inserted");
    assert.equal(first.workspaceIdSuffix, workspaceId.slice(-4));
    assert.equal(first.ownerUserIdSuffix, ownerUserId.slice(-4));
    assert.equal(first.memberUserIdSuffix, memberUserId.slice(-4));
    const membership = await adminPool.query<{ role: string }>(
      `SELECT role
         FROM public.workspace_memberships
        WHERE workspace_id = $1 AND user_id = $2`,
      [workspaceId, memberUserId],
    );
    assert.deepEqual(membership.rows, [{ role: "viewer" }]);

    const second = await seedDemoMember(runtimeDbPool, options, environment);
    assert.equal(second.status, "already_member");

    await assert.rejects(
      () =>
        seedDemoMember(
          runtimeDbPool,
          {
            ...options,
            ownerUserId: nonOwnerUserId,
            memberUserId: notInsertedUserId,
          },
          environment,
        ),
      assertSeedError("owner_not_verified"),
    );
    const deniedMembership = await adminPool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM public.workspace_memberships
        WHERE workspace_id = $1 AND user_id = $2`,
      [workspaceId, notInsertedUserId],
    );
    assert.equal(deniedMembership.rows[0]?.count, "0");

    await assert.rejects(
      () =>
        seedDemoMember(
          runtimeDbPool,
          { ...options, expectedDatabase: `${expectedDatabase}-wrong` },
          environment,
        ),
      assertSeedError("database_mismatch"),
    );
  } finally {
    if (workspaceCreated) {
      await adminPool
        .query(
          "DELETE FROM public.workspace_memberships WHERE workspace_id = $1",
          [workspaceId],
        )
        .catch(() => undefined);
      await adminPool
        .query("DELETE FROM public.workspaces WHERE id = $1", [workspaceId])
        .catch(() => undefined);
    }
    await runtimePool?.end();
    await adminPool.end();
  }
});
