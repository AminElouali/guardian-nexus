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

const TIMEOUT_MS = 300_000;
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
let localLlmJobId = "";
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
  for (const candidateJobId of [jobId, localLlmJobId].filter(Boolean)) {
    spawnSync(
      "docker",
      ["rm", "--force", `guardian-ai-lab-${candidateJobId}`],
      {
      stdio: "ignore",
      timeout: 5_000,
      },
    );
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
          profileId: "guardian-local-llm-qwen3-0.6b-v1",
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
    const availabilityBody = (await availability.json()) as {
      status: string;
      profiles: Array<{ profileId: string; status: string }>;
    };
    assert.equal(availabilityBody.status, "ready");
    assert.equal(
      availabilityBody.profiles.find(
        (profile) => profile.profileId === "guardian-local-llm-qwen3-0.6b-v1",
      )?.status,
      "ready",
    );

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
        assert.equal(job.workerVersion, "guardian-ai-assessment-lab-0.4.0");
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

    const localIdempotencyKey = `local-llm-e2e-${randomUUID()}`;
    const localCreated = await apiRequest(userA, pathA, "POST", {
      idempotencyKey: localIdempotencyKey,
      profileId: "guardian-local-llm-qwen3-0.6b-v1",
    });
    assert.equal(localCreated.status, 202);
    const localAccepted = (await localCreated.json()) as {
      id: string;
      status: string;
      profileId: string;
    };
    localLlmJobId = localAccepted.id;
    assert.equal(localAccepted.status, "queued");
    assert.equal(localAccepted.profileId, "guardian-local-llm-qwen3-0.6b-v1");
    const localDuplicate = await apiRequest(userA, pathA, "POST", {
      idempotencyKey: localIdempotencyKey,
      profileId: "guardian-local-llm-qwen3-0.6b-v1",
    });
    assert.equal(localDuplicate.status, 202);
    assert.equal(
      ((await localDuplicate.json()) as { id: string }).id,
      localLlmJobId,
      "local LLM profile request remains idempotent",
    );
    assert.equal(
      (
        await apiRequest(userA, pathA, "POST", {
          idempotencyKey: localIdempotencyKey,
          profileId: "guardian-local-agent-v1",
        })
      ).status,
      409,
      "one idempotency key cannot silently switch execution profiles",
    );

    let completedLocalRawJob: Record<string, unknown> | undefined;
    const localDeadline = Date.now() + TIMEOUT_MS - 10_000;
    while (Date.now() < localDeadline) {
      const response = await apiRequest(userA, pathA);
      assert.equal(response.status, 200);
      const rawJobs = (await response.json()) as unknown;
      const jobs = ListWorkspaceAiAssessmentLabJobsResponse.parse(rawJobs);
      const localJob = jobs.find((candidate) => candidate.id === localLlmJobId);
      if (localJob?.status === "succeeded" || localJob?.status === "failed") {
        completedLocalRawJob = (rawJobs as Record<string, unknown>[]).find(
          (candidate) => candidate.id === localLlmJobId,
        );
        assert.equal(
          localJob.status,
          "succeeded",
          `local Qwen worker failed: ${localJob.errorCode}`,
        );
        assert.equal(localJob.attempts, 1);
        assert.equal(
          localJob.workerVersion,
          "guardian-ai-assessment-lab-0.4.0",
        );
        assert.equal(localJob.result?.engine, "local_llm_lab");
        if (localJob.result?.engine !== "local_llm_lab") {
          assert.fail("local result must retain its explicit engine discriminator");
        }
        assert.equal(
          localJob.result.profileId,
          "guardian-local-llm-qwen3-0.6b-v1",
        );
        assert.equal(
          localJob.result.executionMode,
          "real_local_llm_inference",
        );
        assert.equal(
          localJob.result.toolInvocationMode,
          "structured_json_emulation",
        );
        assert.equal(localJob.result.taskId, "synthetic_invoice_summary_v1");
        assert.equal(localJob.result.toolSummary.harnessToolExecutions, 1);
        assert.equal(localJob.result.toolSummary.externalCalls, 0);
        assert.equal(localJob.result.rawPromptsStored, false);
        assert.equal(localJob.result.rawResponsesStored, false);
        assert.equal(localJob.result.rawToolArgumentsStored, false);
        assert.equal(localJob.result.secretsMounted, false);
        assert.equal(localJob.result.network.networkMode, "docker-network-none");
        assert.ok(/^[a-f0-9]{64}$/.test(localJob.result.evidenceSha256));
        assert.equal(
          JSON.stringify(localJob.result).includes("Synthetic Vendor"),
          false,
          "raw synthetic invoice is not persisted",
        );
        assert.equal(
          JSON.stringify(localJob.result).includes("invoice is open"),
          false,
          "raw model response is not persisted",
        );
        break;
      }
      await delay(POLL_INTERVAL_MS);
    }
    assert.ok(
      completedLocalRawJob,
      "local Qwen job did not reach a terminal state before timeout",
    );
    const localPersisted = await withWorkspaceUserTransaction(
      userA,
      workspaceA,
      (tx) =>
        tx
          .select({
            status: aiAssessmentJobsTable.status,
            profileId: aiAssessmentJobsTable.profileId,
            result: aiAssessmentJobsTable.result,
          })
          .from(aiAssessmentJobsTable)
          .where(eq(aiAssessmentJobsTable.id, localLlmJobId)),
    );
    assert.equal(localPersisted.authorized, true);
    if (!localPersisted.authorized) return;
    assert.equal(localPersisted.value[0]?.status, "succeeded");
    assert.equal(
      localPersisted.value[0]?.profileId,
      "guardian-local-llm-qwen3-0.6b-v1",
    );
    assert.equal(localPersisted.value[0]?.result?.engine, "local_llm_lab");
    assert.equal((await apiRequest(userB, pathA)).status, 403);
    const tenantBAfterLocal = await apiRequest(userB, pathB);
    assert.equal(tenantBAfterLocal.status, 200);
    assert.deepEqual(await tenantBAfterLocal.json(), []);

    const artifactPath = fileURLToPath(
      new URL("../../../generated-artifacts/ai-assessment-e2e-response.json", import.meta.url),
    );
    mkdirSync(dirname(artifactPath), { recursive: true });
    writeFileSync(
      artifactPath,
      JSON.stringify([completedRawJob, completedLocalRawJob], null, 2),
    );
  },
);
