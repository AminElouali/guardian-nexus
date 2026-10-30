import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import pg from "pg";
import { eq, sql } from "drizzle-orm";
import {
  assertRlsRuntimeReady,
  aiAssessmentJobsTable,
  withAiAssessmentQueueTransaction,
  assetsTable,
  connectorJobsTable,
  monthlyUsageTable,
  providerConnectionsTable,
  workspaceAuditEventsTable,
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
import {
  claimNextAssessmentJob,
  isAiAssessmentJobRetryable,
  renewAssessmentJobLease,
} from "./lib/ai-assessment-worker";

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
  await fixturePool.query(
    `INSERT INTO public.workspace_audit_events
       (workspace_id, actor_user_id, action, resource_type, resource_id, metadata)
     VALUES
       ($1, $2, 'ai_evaluation.mock.completed', 'ai_evaluation', $3,
        '{"checks":"[]","garakInvoked":false}'::jsonb),
       ($4, $5, 'ai_evaluation.mock.completed', 'ai_evaluation', $6,
        '{"checks":"[]","garakInvoked":false}'::jsonb)`,
    [workspaceA, userA, randomUUID(), workspaceB, userB, randomUUID()],
  );
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
      has_table_privilege(session_user, 'public.workspace_integrations', 'INSERT') AS direct_integrations_write,
      EXISTS (
        SELECT 1
        FROM unnest(ARRAY[
          'workspaces','workspace_memberships','assets','workspace_monthly_usage',
          'workspace_audit_events','workspace_integrations','provider_connections',
          'connector_oauth_states','connector_jobs'
        ]) AS protected(table_name)
        WHERE has_table_privilege(session_user, format('public.%I', protected.table_name), 'SELECT')
          OR has_table_privilege(session_user, format('public.%I', protected.table_name), 'INSERT')
          OR has_table_privilege(session_user, format('public.%I', protected.table_name), 'UPDATE')
          OR has_table_privilege(session_user, format('public.%I', protected.table_name), 'DELETE')
      ) AS direct_protected_access,
      EXISTS (
        SELECT 1 FROM pg_class AS protected
        JOIN pg_namespace AS protected_schema ON protected_schema.oid = protected.relnamespace
        WHERE protected_schema.nspname = 'public'
          AND protected.relname = ANY(ARRAY[
            'workspaces','workspace_memberships','assets','workspace_monthly_usage',
            'workspace_audit_events','workspace_integrations','provider_connections',
            'connector_oauth_states','connector_jobs'
          ])
          AND protected.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'app_runtime')
      ) AS runtime_owns_protected_table
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
  assert.equal(role?.direct_protected_access, false);
  assert.equal(role?.runtime_owns_protected_table, false);
});

test("AI evaluation audit reads are isolated to the verified workspace", async () => {
  const result = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) =>
      tx
        .select()
        .from(workspaceAuditEventsTable)
        .where(eq(workspaceAuditEventsTable.action, "ai_evaluation.mock.completed")),
  );
  assert.equal(result.authorized, true);
  if (!result.authorized) return;
  assert.equal(result.value.length, 1);
  assert.equal(result.value[0]?.workspaceId, workspaceA);
  assert.equal(result.value[0]?.metadata.garakInvoked, false);
});

test("RLS rejects cross-tenant AI evaluation evidence writes", async () => {
  await assert.rejects(
    withWorkspaceUserTransaction(userA, workspaceA, async (tx) => {
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId: workspaceB,
        actorUserId: userA,
        action: "ai_evaluation.mock.completed",
        resourceType: "ai_evaluation",
        resourceId: randomUUID(),
        metadata: { checks: "[]", garakInvoked: false },
      });
    }),
    (error: { cause?: { code?: string } }) => error.cause?.code === "42501",
  );
});

test("AI assessment jobs enforce tenant, role, and idempotency boundaries", async () => {
  const idempotencyKey = `lab-${randomUUID()}`;
  const inserted = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) =>
      tx
        .insert(aiAssessmentJobsTable)
        .values({
          workspaceId: workspaceA,
          requestedByUserId: userA,
          idempotencyKey,
        })
        .onConflictDoNothing()
        .returning(),
  );
  assert.equal(inserted.authorized, true);
  if (!inserted.authorized) return;
  assert.equal(inserted.value.length, 1);

  const duplicate = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) =>
      tx
        .insert(aiAssessmentJobsTable)
        .values({
          workspaceId: workspaceA,
          requestedByUserId: userA,
          idempotencyKey,
        })
        .onConflictDoNothing()
        .returning(),
  );
  assert.equal(duplicate.authorized, true);
  if (!duplicate.authorized) return;
  assert.equal(duplicate.value.length, 0);

  const [visibleToOwner, visibleToViewer, visibleToOtherTenant] =
    await Promise.all([
      withWorkspaceUserTransaction(userA, workspaceA, (tx) =>
        tx.select().from(aiAssessmentJobsTable),
      ),
      withWorkspaceUserTransaction(viewerA, workspaceA, (tx) =>
        tx.select().from(aiAssessmentJobsTable),
      ),
      withWorkspaceUserTransaction(userB, workspaceB, (tx) =>
        tx.select().from(aiAssessmentJobsTable),
      ),
    ]);
  assert.equal(visibleToOwner.authorized, true);
  assert.equal(visibleToViewer.authorized, true);
  assert.equal(visibleToOtherTenant.authorized, true);
  if (
    !visibleToOwner.authorized ||
    !visibleToViewer.authorized ||
    !visibleToOtherTenant.authorized
  ) return;
  assert.equal(visibleToOwner.value.length, 1);
  assert.equal(visibleToViewer.value.length, 1);
  assert.equal(visibleToOtherTenant.value.length, 0);
  assert.equal(visibleToOwner.value[0]?.workspaceId, workspaceA);

  await assert.rejects(
    withWorkspaceUserTransaction(userA, workspaceA, (tx) =>
      tx.insert(aiAssessmentJobsTable).values({
        workspaceId: workspaceB,
        requestedByUserId: userA,
        idempotencyKey: `cross-tenant-${randomUUID()}`,
      }),
    ),
    (error: { cause?: { code?: string } }) => error.cause?.code === "42501",
  );
  await assert.rejects(
    withWorkspaceUserTransaction(viewerA, workspaceA, (tx) =>
      tx.insert(aiAssessmentJobsTable).values({
        workspaceId: workspaceA,
        requestedByUserId: viewerA,
        idempotencyKey: `viewer-${randomUUID()}`,
      }),
    ),
    (error: { cause?: { code?: string } }) => error.cause?.code === "42501",
  );
  const viewerUpdate = await withWorkspaceUserTransaction(
    viewerA,
    workspaceA,
    (tx) =>
      tx
        .update(aiAssessmentJobsTable)
        .set({ status: "failed" })
        .where(eq(aiAssessmentJobsTable.id, inserted.value[0]!.id))
        .returning({ id: aiAssessmentJobsTable.id }),
  );
  assert.equal(viewerUpdate.authorized, true);
  if (!viewerUpdate.authorized) return;
  assert.equal(viewerUpdate.value.length, 0);
  const unchanged = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) =>
      tx
        .select({ status: aiAssessmentJobsTable.status })
        .from(aiAssessmentJobsTable)
        .where(eq(aiAssessmentJobsTable.id, inserted.value[0]!.id))
        .limit(1),
  );
  assert.equal(unchanged.authorized, true);
  if (!unchanged.authorized) return;
  assert.equal(unchanged.value[0]?.status, "queued");
  await withWorkspaceUserTransaction(userA, workspaceA, (tx) =>
    tx
      .update(aiAssessmentJobsTable)
      .set({ status: "failed", completedAt: new Date() })
      .where(eq(aiAssessmentJobsTable.id, inserted.value[0]!.id)),
  );
});

test("AI assessment retry policy stops at two attempts and only retries failures", () => {
  assert.equal(isAiAssessmentJobRetryable("failed", 1), true);
  assert.equal(isAiAssessmentJobRetryable("failed", 2), false);
  assert.equal(isAiAssessmentJobRetryable("queued", 1), false);
  assert.equal(isAiAssessmentJobRetryable("running", 1), false);
});

test("assessment queue role exposes metadata only and recovers expired leases once", async () => {
  const [jobA] = await withWorkspaceUserTransaction(userA, workspaceA, (tx) =>
    tx
      .insert(aiAssessmentJobsTable)
      .values({
        workspaceId: workspaceA,
        requestedByUserId: userA,
        idempotencyKey: `queue-recovery-a-${randomUUID()}`,
      })
      .returning(),
  ).then((result) => {
    assert.equal(result.authorized, true);
    if (!result.authorized) return [];
    return result.value;
  });
  const [jobB] = await withWorkspaceUserTransaction(userB, workspaceB, (tx) =>
    tx
      .insert(aiAssessmentJobsTable)
      .values({
        workspaceId: workspaceB,
        requestedByUserId: userB,
        idempotencyKey: `queue-recovery-b-${randomUUID()}`,
      })
      .returning(),
  ).then((result) => {
    assert.equal(result.authorized, true);
    if (!result.authorized) return [];
    return result.value;
  });
  assert.ok(jobA);
  assert.ok(jobB);

  const queueMetadata = await withAiAssessmentQueueTransaction(null, (tx) =>
    tx
      .select({
        id: aiAssessmentJobsTable.id,
        workspaceId: aiAssessmentJobsTable.workspaceId,
        requestedByUserId: aiAssessmentJobsTable.requestedByUserId,
        status: aiAssessmentJobsTable.status,
      })
      .from(aiAssessmentJobsTable),
  );
  assert.ok(queueMetadata.some((job) => job.id === jobA.id));
  assert.ok(queueMetadata.some((job) => job.id === jobB.id));
  assert.equal(
    queueMetadata.find((job) => job.id === jobB.id)?.workspaceId,
    workspaceB,
  );

  await assert.rejects(
    withAiAssessmentQueueTransaction(null, (tx) =>
      tx
        .select({ result: aiAssessmentJobsTable.result })
        .from(aiAssessmentJobsTable)
        .where(eq(aiAssessmentJobsTable.id, jobA.id)),
    ),
    (error: { code?: string; cause?: { code?: string } }) =>
      error.code === "42501" || error.cause?.code === "42501",
  );
  await assert.rejects(
    withAiAssessmentQueueTransaction(randomUUID(), (tx) =>
      tx
        .update(aiAssessmentJobsTable)
        .set({ workspaceId: workspaceB })
        .where(eq(aiAssessmentJobsTable.id, jobA.id)),
    ),
    (error: { code?: string; cause?: { code?: string } }) =>
      error.code === "42501" || error.cause?.code === "42501",
  );

  const markTenantBFailed = await withWorkspaceUserTransaction(
    userB,
    workspaceB,
    (tx) =>
      tx
        .update(aiAssessmentJobsTable)
        .set({ status: "failed", completedAt: new Date() })
        .where(eq(aiAssessmentJobsTable.id, jobB.id)),
  );
  assert.equal(markTenantBFailed.authorized, true);

  const raceClaims = await Promise.all([
    claimNextAssessmentJob(),
    claimNextAssessmentJob(),
  ]);
  const claimed = raceClaims.flatMap((claim) =>
    claim.job ? [claim.job] : [],
  );
  assert.equal(claimed.length, 1);
  const firstLease = claimed[0]!;
  assert.equal(firstLease.jobId, jobA.id);
  assert.equal(firstLease.attempts, 1);
  assert.equal(
    (await claimNextAssessmentJob()).job,
    null,
    "an active lease prevents a second claim",
  );
  assert.equal(await renewAssessmentJobLease(firstLease), true);

  await withAiAssessmentQueueTransaction(firstLease.leaseOwnerId, (tx) =>
    tx.execute(sql`
      UPDATE public.ai_assessment_jobs
      SET lease_expires_at = now() - interval '1 second'
      WHERE id = ${firstLease.jobId}::uuid
        AND lease_owner_id = ${firstLease.leaseOwnerId}::uuid
    `),
  );
  const recovered = await claimNextAssessmentJob();
  assert.equal(recovered.job?.jobId, firstLease.jobId);
  assert.equal(recovered.job?.attempts, 2);
  assert.ok(recovered.job);
  assert.equal(await renewAssessmentJobLease(firstLease), false);

  await withAiAssessmentQueueTransaction(recovered.job.leaseOwnerId, (tx) =>
    tx.execute(sql`
      UPDATE public.ai_assessment_jobs
      SET lease_expires_at = now() - interval '1 second'
      WHERE id = ${recovered.job!.jobId}::uuid
        AND lease_owner_id = ${recovered.job!.leaseOwnerId}::uuid
    `),
  );
  const exhausted = await claimNextAssessmentJob();
  assert.equal(exhausted.job, null);
  assert.equal(exhausted.exhausted.length, 1);
  assert.equal(exhausted.exhausted[0]?.jobId, jobA.id);
  const finalState = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) =>
      tx
        .select({
          status: aiAssessmentJobsTable.status,
          attempts: aiAssessmentJobsTable.attempts,
          leaseOwnerId: aiAssessmentJobsTable.leaseOwnerId,
          workerSlot: aiAssessmentJobsTable.workerSlot,
        })
        .from(aiAssessmentJobsTable)
        .where(eq(aiAssessmentJobsTable.id, jobA.id))
        .limit(1),
  );
  assert.equal(finalState.authorized, true);
  if (!finalState.authorized) return;
  assert.deepEqual(finalState.value[0], {
    status: "failed",
    attempts: 2,
    leaseOwnerId: null,
    workerSlot: null,
  });
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
  const results = await Promise.all([
    enqueueConnectorJob(input),
    enqueueConnectorJob(input),
  ]);
  const created = results.find((result) => result.kind === "created");
  const existing = results.find((result) => result.kind === "existing");
  assert.ok(created);
  assert.ok(existing);
  if (!created || !existing) return;
  assert.equal(created.job.id, existing.job.id);

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
        .where(eq(connectorJobsTable.id, created.job.id));
  });
  const retryStartedAt = Date.now();
  const retried = await rescheduleConnectorJob({
    userId: userA,
    workspaceId: workspaceA,
    jobId: created.job.id,
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
      .where(eq(connectorJobsTable.id, created.job.id));
    await tx
      .update(providerConnectionsTable)
      .set({ status: "revoked", revokedAt: new Date() })
      .where(eq(providerConnectionsTable.id, providerConnectionA));
  });
  const cancelled = await rescheduleConnectorJob({
    userId: userA,
    workspaceId: workspaceA,
    jobId: created.job.id,
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
