import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import pg from "pg";
import { eq, sql } from "drizzle-orm";
import {
  assertRlsRuntimeReady,
  assetsTable,
  connectorJobsTable,
  monthlyUsageTable,
  providerConnectionsTable,
  workspaceIntegrationsTable,
  db,
  pool,
} from "@workspace/db";
import { canManageMemberRoles, canWriteAssets } from "./lib/access-control";
import {
  microsoftGraphGetWithRetry,
  parseRetryAfterMs,
} from "./lib/microsoft-graph-throttle";
import { UsageQuotaError, reserveWorkspaceUsage } from "./lib/usage";
import { withWorkspaceUserTransaction } from "./lib/tenant-db";
import { prepareIntegration } from "./routes/workspace-integrations";
import {
  enqueueConnectorJob,
  rescheduleConnectorJob,
} from "./lib/connector-jobs";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required for isolated security-test fixtures.");
}
const fixturePool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const userA = `rls-test-a-${randomUUID()}`;
const userB = `rls-test-b-${randomUUID()}`;
const viewerA = `rls-test-viewer-${randomUUID()}`;
let workspaceA: string;
let workspaceB: string;
let assetA: string;
let assetB: string;
let providerConnectionA: string;
let providerConnectionB: string;
let integrationA: string;
let integrationB: string;

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
     VALUES ($1, $2, 'owner'), ($3, $4, 'owner'), ($1, $5, 'viewer')`,
    [workspaceA, userA, workspaceB, userB, viewerA],
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
  const [
    createdIntegrationA,
    createdIntegrationB,
    connectionA,
    connectionB,
  ] = await Promise.all([
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.workspace_integrations
         (workspace_id, provider, external_account_id, setup_key, status, created_by_user_id)
       VALUES ($1, 'microsoft', 'tenant-a', 'tenant-a', 'awaiting_app_registration', $2)
       RETURNING id`,
      [workspaceA, userA],
    ),
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.workspace_integrations
         (workspace_id, provider, external_account_id, setup_key, status, created_by_user_id)
       VALUES ($1, 'microsoft', 'tenant-b', 'tenant-b', 'awaiting_app_registration', $2)
       RETURNING id`,
      [workspaceB, userB],
    ),
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.provider_connections
         (workspace_id, provider, status, aws_account_id, aws_role_arn, aws_external_id)
       VALUES ($1, 'aws', 'active', '111122223333',
               'arn:aws:iam::111122223333:role/test-readonly', 'fixture-a')
       RETURNING id`,
      [workspaceA],
    ),
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.provider_connections
         (workspace_id, provider, status, aws_account_id, aws_role_arn, aws_external_id)
       VALUES ($1, 'aws', 'pending', '444455556666',
               'arn:aws:iam::444455556666:role/test-readonly', 'fixture-b')
       RETURNING id`,
      [workspaceB],
    ),
  ]);
  integrationA = createdIntegrationA.rows[0].id;
  integrationB = createdIntegrationB.rows[0].id;
  providerConnectionA = connectionA.rows[0].id;
  providerConnectionB = connectionB.rows[0].id;
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
      has_table_privilege(session_user, 'public.assets', 'INSERT') AS direct_write,
      has_table_privilege(session_user, 'public.workspace_integrations', 'SELECT') AS direct_integrations_read,
      has_table_privilege(session_user, 'public.workspace_integrations', 'INSERT') AS direct_integrations_write
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
  assert.equal(role?.direct_integrations_read, false);
  assert.equal(role?.direct_integrations_write, false);
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

test("RLS scopes unfiltered integration preparation reads to the verified tenant", async () => {
  const result = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) => tx.select().from(workspaceIntegrationsTable),
  );
  assert.equal(result.authorized, true);
  if (!result.authorized) return;
  assert.deepEqual(
    result.value.map((integration) => integration.id),
    [integrationA],
  );
  assert.equal(
    result.value.some((integration) => integration.id === integrationB),
    false,
  );
});

test("RLS rejects cross-tenant integration writes and hides foreign updates", async () => {
  await assert.rejects(
    withWorkspaceUserTransaction(userA, workspaceA, async (tx) => {
      await tx.insert(workspaceIntegrationsTable).values({
        workspaceId: workspaceB,
        provider: "aws",
        externalAccountId: "123456789012",
        setupKey: "123456789012",
        status: "awaiting_runtime_identity",
        createdByUserId: userA,
      });
    }),
    (error: { cause?: { code?: string } }) => error.cause?.code === "42501",
  );
  const update = await withWorkspaceUserTransaction(userA, workspaceA, (tx) =>
    tx
      .update(workspaceIntegrationsTable)
      .set({ status: "revoked" })
      .where(eq(workspaceIntegrationsTable.id, integrationB))
      .returning(),
  );
  assert.equal(update.authorized, true);
  if (update.authorized) assert.deepEqual(update.value, []);
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

test("provider connections are isolated between tenants", async () => {
  const result = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) => tx.select().from(providerConnectionsTable),
  );

  assert.equal(result.authorized, true);
  if (!result.authorized) return;
  assert.deepEqual(
    result.value.map((connection) => connection.id),
    [providerConnectionA],
  );
  assert.equal(
    result.value.some((connection) => connection.id === providerConnectionB),
    false,
  );
});

test("RLS rejects a provider connection write into another tenant", async () => {
  await assert.rejects(
    withWorkspaceUserTransaction(userA, workspaceA, async (tx) => {
      await tx.insert(providerConnectionsTable).values({
        workspaceId: workspaceB,
        provider: "aws",
        awsAccountId: "777788889999",
        awsRoleArn: "arn:aws:iam::777788889999:role/foreign",
        awsExternalId: "must-not-cross-tenants",
      });
    }),
    (error: { cause?: { code?: string } }) => error.cause?.code === "42501",
  );
});

test("connector jobs are tenant-scoped, idempotent, and reserve quota once", async () => {
  const input = {
    userId: userA,
    workspaceId: workspaceA,
    connectionId: providerConnectionA,
    kind: "inventory_sync",
    idempotencyKey: `job-${randomUUID()}`,
    metadata: { source: "security-test" },
  };
  const [first, second] = await Promise.all([
    enqueueConnectorJob(input),
    enqueueConnectorJob(input),
  ]);
  assert.equal(first.kind, "created");
  assert.equal(second.kind, "existing");
  if (first.kind !== "created" || second.kind !== "existing") return;
  assert.equal(first.job.id, second.job.id);

  const result = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    async (tx) => {
      const [usage] = await tx
        .select()
        .from(monthlyUsageTable)
        .where(eq(monthlyUsageTable.workspaceId, workspaceA))
        .limit(1);
      const jobs = await tx
        .select()
        .from(connectorJobsTable)
        .where(eq(connectorJobsTable.workspaceId, workspaceA));
      return { usage, jobs };
    },
  );
  assert.equal(result.authorized, true);
  if (!result.authorized) return;
  assert.equal(result.value.usage?.scansUsed, 1);
  assert.equal(result.value.jobs.length, 1);

  await withWorkspaceUserTransaction(userA, workspaceA, async (tx) => {
    await tx
      .update(connectorJobsTable)
      .set({
        status: "running",
        attempts: 1,
        leaseExpiresAt: new Date(Date.now() + 60_000),
      })
      .where(eq(connectorJobsTable.id, first.job.id));
  });
  const retryStartedAt = Date.now();
  const retried = await rescheduleConnectorJob({
    userId: userA,
    workspaceId: workspaceA,
    jobId: first.job.id,
    retryAfter: "30",
    errorCode: "provider_throttled",
  });
  assert.equal(retried?.status, "queued");
  assert.equal(retried?.attempts, 2);
  assert.equal(retried?.lastError, "provider_throttled");
  assert.ok((retried?.runAfter.getTime() ?? 0) >= retryStartedAt + 30_000);

  await withWorkspaceUserTransaction(userA, workspaceA, async (tx) => {
    await tx
      .update(connectorJobsTable)
      .set({ status: "running", leaseExpiresAt: new Date(Date.now() + 60_000) })
      .where(eq(connectorJobsTable.id, first.job.id));
    await tx
      .update(providerConnectionsTable)
      .set({ status: "revoked", revokedAt: new Date() })
      .where(eq(providerConnectionsTable.id, providerConnectionA));
  });
  const cancelled = await rescheduleConnectorJob({
    userId: userA,
    workspaceId: workspaceA,
    jobId: first.job.id,
    retryAfter: "30",
    errorCode: "provider_throttled",
  });
  assert.equal(cancelled?.status, "cancelled");
});

test("a tenant cannot enqueue jobs using another tenant's connector", async () => {
  await assert.rejects(
    enqueueConnectorJob({
      userId: userA,
      workspaceId: workspaceB,
      connectionId: providerConnectionB,
      kind: "inventory_sync",
      idempotencyKey: `cross-tenant-${randomUUID()}`,
    }),
    /Workspace access denied/,
  );
});

test("workspace usage limits are enforced atomically", async () => {
  await assert.rejects(
    reserveWorkspaceUsage(userA, workspaceA, { tokens: 100_001 }),
    UsageQuotaError,
  );
});

test("AWS setup preparation is idempotent without replacing its ExternalId", async () => {
  const first = await prepareIntegration(
    userA,
    workspaceA,
    "aws",
    "123456789012",
    [],
    "first-test-external-id",
  );
  const repeated = await prepareIntegration(
    userA,
    workspaceA,
    "aws",
    "123456789012",
    [],
    "second-test-external-id",
  );
  assert.equal(first.kind, "prepared");
  assert.equal(repeated.kind, "existing");
  if (first.kind === "prepared" && repeated.kind === "existing") {
    assert.equal(first.integration.id, repeated.integration.id);
    assert.equal(first.integration.externalId, "first-test-external-id");
    assert.equal(repeated.integration.externalId, "first-test-external-id");
  }
});

test("only workspace owners can prepare provider integrations", async () => {
  const result = await prepareIntegration(
    viewerA,
    workspaceA,
    "microsoft",
    randomUUID(),
    ["Organization.Read.All"],
    null,
  );
  assert.deepEqual(result, { kind: "forbidden" });
});

test("basic workspace role permissions are explicit", () => {
  assert.equal(canWriteAssets("owner"), true);
  assert.equal(canWriteAssets("admin"), true);
  assert.equal(canWriteAssets("analyst"), true);
  assert.equal(canWriteAssets("viewer"), false);
  assert.equal(canManageMemberRoles("owner"), true);
  assert.equal(canManageMemberRoles("admin"), false);
});

test("Microsoft Graph Retry-After values are parsed and respected", async () => {
  assert.equal(parseRetryAfterMs("2", 1_000), 2_000);
  assert.equal(
    parseRetryAfterMs("Thu, 01 Jan 1970 00:00:03 GMT", 1_000),
    2_000,
  );
  assert.equal(parseRetryAfterMs("not-a-date", 1_000), null);

  const delays: number[] = [];
  let calls = 0;
  const response = await microsoftGraphGetWithRetry(
    "https://graph.microsoft.com/v1.0/organization",
    "test-only-token",
    {
      now: () => 1_000,
      sleep: async (milliseconds) => {
        delays.push(milliseconds);
      },
      fetchImpl: async () => {
        calls += 1;
        return calls === 1
          ? new Response(null, {
              status: 429,
              headers: { "Retry-After": "2" },
            })
          : new Response("{}", { status: 200 });
      },
    },
  );
  assert.equal(response.status, 200);
  assert.equal(calls, 2);
  assert.deepEqual(delays, [2_000]);
});

test("Microsoft Graph reader rejects non-Graph or non-HTTPS targets", async () => {
  await assert.rejects(
    microsoftGraphGetWithRetry("https://example.com/v1.0/organization", "token"),
    /only permits HTTPS v1\.0 Graph URLs/,
  );
  await assert.rejects(
    microsoftGraphGetWithRetry("http://graph.microsoft.com/v1.0/organization", "token"),
    /only permits HTTPS v1\.0 Graph URLs/,
  );
});

test("long Microsoft Graph Retry-After values are returned to the queue", async () => {
  let calls = 0;
  const delays: number[] = [];
  const response = await microsoftGraphGetWithRetry(
    "https://graph.microsoft.com/v1.0/organization",
    "test-only-token",
    {
      maxInlineWaitMs: 1_000,
      sleep: async (milliseconds) => {
        delays.push(milliseconds);
      },
      fetchImpl: async () => {
        calls += 1;
        return new Response(null, {
          status: 429,
          headers: { "Retry-After": "120" },
        });
      },
    },
  );
  assert.equal(response.status, 429);
  assert.equal(calls, 1);
  assert.deepEqual(delays, []);
});
