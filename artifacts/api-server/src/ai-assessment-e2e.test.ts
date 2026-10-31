import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import type { Server } from "node:http";
import express, { type RequestHandler } from "express";
import pg from "pg";
import { eq } from "drizzle-orm";
import { ListWorkspaceAiAssessmentLabJobsResponse } from "@workspace/api-zod";
import {
  aiAssessmentJobsTable,
  assertRlsRuntimeReady,
  pool,
} from "@workspace/db";
import { withWorkspaceUserTransaction } from "./lib/tenant-db";
import {
  getLocalWorkerAvailability,
  stopLocalAssessmentQueueWorker,
} from "./lib/ai-assessment-worker";
import { createAiAssessmentLabRouter } from "./routes/ai-assessment-lab";

const TIMEOUT_MS = 180_000;
const POLL_INTERVAL_MS = 500;
const userA = `assessment-e2e-owner-${randomUUID()}`;
const userB = `assessment-e2e-owner-${randomUUID()}`;
const viewerA = `assessment-e2e-viewer-${randomUUID()}`;
const authorizedTestUsers = new Set([userA, userB, viewerA]);
const testAuth: RequestHandler = (req, res, next) => {
  const userId = req.get("x-guardian-test-user");
  if (!userId || !authorizedTestUsers.has(userId)) {
    res.status(401).json({ error: "Test identity required" });
    return;
  }
  req.authUserId = userId;
  next();
};

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL_required_for_local_e2e");
}
const fixturePool = new pg.Pool({ connectionString: databaseUrl });
const app = express();
app.use(express.json());
app.use("/api", createAiAssessmentLabRouter(testAuth));

let workspaceA = "";
let workspaceB = "";
let jobId = "";
let server: Server | undefined;
let baseUrl = "";

if (
  process.env.NODE_ENV !== "development" ||
  process.env.REPLIT_DEPLOYMENT === "1"
) {
  throw new Error("ai_assessment_e2e_development_only");
}
before(async () => {
  await assertRlsRuntimeReady();
  assert.equal(getLocalWorkerAvailability().status, "ready");
  assert.notEqual(
    process.env.GUARDIAN_AI_ASSESSMENT_QUEUE_ENABLED,
    "false",
    "E2E refuses to enqueue when the local worker queue is disabled",
  );

  const pending = await fixturePool.query<{ count: string }>(
    `SELECT count(*)::text AS count
     FROM public.ai_assessment_jobs
     WHERE status IN ('queued', 'running')`,
  );
  assert.equal(
    Number(pending.rows[0]?.count ?? 0),
    0,
    "E2E refuses to run while any development assessment job is pending",
  );

  const [createdA, createdB] = await Promise.all([
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.workspaces (name, plan_id, created_by_user_id)
       VALUES ('Assessment E2E A', 'small', $1) RETURNING id`,
      [userA],
    ),
    fixturePool.query<{ id: string }>(
      `INSERT INTO public.workspaces (name, plan_id, created_by_user_id)
       VALUES ('Assessment E2E B', 'small', $1) RETURNING id`,
      [userB],
    ),
  ]);
  workspaceA = createdA.rows[0]!.id;
  workspaceB = createdB.rows[0]!.id;
  await fixturePool.query(
    `INSERT INTO public.workspace_memberships (workspace_id, user_id, role)
     VALUES ($1, $2, 'owner'), ($1, $3, 'viewer'), ($4, $5, 'owner')`,
    [workspaceA, userA, viewerA, workspaceB, userB],
  );

  server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  stopLocalAssessmentQueueWorker();
  if (jobId) {
    spawnSync("docker", ["rm", "--force", `guardian-ai-lab-${jobId}`], {
      stdio: "ignore",
      timeout: 5_000,
    });
  }
  if (server?.listening) {
    await new Promise<void>((resolveClose, rejectClose) => {
      server!.close((error) => {
        if (error) rejectClose(error);
        else resolveClose();
      });
    });
  }
  if (workspaceA && workspaceB) {
    await fixturePool.query(
      `DELETE FROM public.workspaces WHERE id = ANY($1::uuid[])`,
      [[workspaceA, workspaceB]],
    );
  }
  await pool.end();
  await fixturePool.end();
});

async function apiRequest(
  userId: string | null,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (userId) headers["x-guardian-test-user"] = userId;
  if (body !== undefined) headers["content-type"] = "application/json";
  return fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}

test(
  "authenticated request runs Garak and Guardian Verification through queue, tenant persistence, API, and UI contract",
  { timeout: TIMEOUT_MS },
  async () => {
    const pathA = `/api/workspaces/${workspaceA}/ai-security-assessments/lab/jobs`;
    const pathB = `/api/workspaces/${workspaceB}/ai-security-assessments/lab/jobs`;

    assert.equal((await apiRequest(null, pathA)).status, 401);
    assert.equal((await apiRequest(userB, pathA)).status, 403);
    assert.equal(
      (
        await apiRequest(viewerA, pathA, "POST", {
          idempotencyKey: `viewer-denied-${crypto.randomUUID()}`,
        })
      ).status,
      403,
      "viewer cannot start an evaluation",
    );

    const availability = await apiRequest(
      userA,
      `/api/workspaces/${workspaceA}/ai-security-assessments/lab/availability`,
    );
    assert.equal(availability.status, 200);
    const availabilityBody = (await availability.json()) as { status: string };
    assert.equal(availabilityBody.status, "ready");

    const idempotencyKey = `assessment-e2e-${randomUUID()}`;
    const created = await apiRequest(userA, pathA, "POST", { idempotencyKey });
    assert.equal(created.status, 202);
    const accepted = (await created.json()) as { id: string; status: string };
    jobId = accepted.id;
    assert.equal(accepted.status, "queued");

    const duplicate = await apiRequest(userA, pathA, "POST", {
      idempotencyKey,
    });
    assert.equal(duplicate.status, 202);
    const duplicateBody = (await duplicate.json()) as { id: string };
    assert.equal(duplicateBody.id, jobId);

    let completedRawJob: Record<string, unknown> | undefined;
    let observedLease = false;
    const deadline = Date.now() + TIMEOUT_MS - 10_000;
    while (Date.now() < deadline) {
      const response = await apiRequest(userA, pathA);
      assert.equal(response.status, 200);
      const rawJobs = (await response.json()) as unknown;
      const jobs = ListWorkspaceAiAssessmentLabJobsResponse.parse(rawJobs);
      const job = jobs.find((candidate) => candidate.id === jobId);
      const leaseSnapshot = await withWorkspaceUserTransaction(
        userA,
        workspaceA,
        (tx) =>
          tx
            .select({
              status: aiAssessmentJobsTable.status,
              leaseOwnerId: aiAssessmentJobsTable.leaseOwnerId,
            })
            .from(aiAssessmentJobsTable)
            .where(eq(aiAssessmentJobsTable.id, jobId)),
      );
      assert.equal(leaseSnapshot.authorized, true);
      if (
        leaseSnapshot.authorized &&
        leaseSnapshot.value[0]?.status === "running" &&
        leaseSnapshot.value[0]?.leaseOwnerId
      ) {
        observedLease = true;
      }
      if (job?.status === "succeeded" || job?.status === "failed") {
        completedRawJob = (rawJobs as Record<string, unknown>[]).find(
          (candidate) => candidate.id === jobId,
        );
        assert.equal(job.status, "succeeded", `worker failed: ${job.errorCode}`);
        assert.equal(job.attempts, 1);
        assert.equal(job.workerVersion, "guardian-ai-assessment-lab-0.3.0");
        assert.ok(job.result);
        assert.equal(job.result.engine, "garak");
        assert.equal(job.result.engineVersion, "0.17.1");
        assert.equal(job.result.probeRequests, 1);
        assert.ok(job.result.reportRecordTypes.attempt > 0);
        assert.ok(job.result.reportRecordTypes.eval > 0);
        assert.ok(Array.isArray(job.result.findings));
        assert.equal(job.result.guardianVerification?.sampleCount, 144);
        assert.equal(job.result.guardianVerification?.metrics.length, 42);
        assert.equal(job.result.guardianVerification?.externalCalls, 0);
        break;
      }
      await delay(POLL_INTERVAL_MS);
    }
    assert.ok(completedRawJob, "job did not reach a terminal state before timeout");
    assert.equal(observedLease, true, "worker claim lease was never observed");

    const persisted = await withWorkspaceUserTransaction(
      userA,
      workspaceA,
      (tx) =>
        tx
          .select({
            status: aiAssessmentJobsTable.status,
            attempts: aiAssessmentJobsTable.attempts,
            result: aiAssessmentJobsTable.result,
            leaseOwnerId: aiAssessmentJobsTable.leaseOwnerId,
            workerSlot: aiAssessmentJobsTable.workerSlot,
          })
          .from(aiAssessmentJobsTable)
          .where(eq(aiAssessmentJobsTable.id, jobId)),
    );
    assert.equal(persisted.authorized, true);
    if (!persisted.authorized) return;
    assert.equal(persisted.value[0]?.status, "succeeded");
    assert.equal(persisted.value[0]?.attempts, 1);
    assert.equal(persisted.value[0]?.leaseOwnerId, null);
    assert.equal(persisted.value[0]?.workerSlot, null);
    assert.equal(
      persisted.value[0]?.result?.guardianVerification?.suiteEvidenceSha256,
      (completedRawJob.result as { guardianVerification: { suiteEvidenceSha256: string } })
        .guardianVerification.suiteEvidenceSha256,
    );

    assert.equal((await apiRequest(userB, pathA)).status, 403);
    const tenantBJobs = await apiRequest(userB, pathB);
    assert.equal(tenantBJobs.status, 200);
    assert.deepEqual(await tenantBJobs.json(), []);

    const artifactPath = fileURLToPath(
      new URL("../../../generated-artifacts/ai-assessment-e2e-response.json", import.meta.url),
    );
    mkdirSync(dirname(artifactPath), { recursive: true });
    writeFileSync(artifactPath, JSON.stringify([completedRawJob], null, 2));
  },
);
