import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
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
  type GuardianLocalLlmAutonomousToolSelectionEvidence,
  type GuardianLocalLlmNativeToolSuiteEvidence,
} from "@workspace/db";
import { withWorkspaceUserTransaction } from "./lib/tenant-db";
import {
  getLocalWorkerAvailability,
  stopLocalAssessmentQueueWorker,
} from "./lib/ai-assessment-worker";
import { createAiAssessmentLabRouter } from "./routes/ai-assessment-lab";

const TIMEOUT_MS = 480_000;
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
let nativeToolJobId = "";
let autonomousToolJobId = "";
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
  assert.equal(
    getLocalWorkerAvailability().profiles.find(
      (profile) => profile.profileId === "guardian-local-llm-native-tools-v1",
    )?.status,
    "ready",
  );
  assert.equal(
    getLocalWorkerAvailability().profiles.find(
      (profile) =>
        profile.profileId === "guardian-local-llm-autonomous-tools-v1",
    )?.status,
    "ready",
  );
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
  for (const candidateJobId of [
    jobId,
    localLlmJobId,
    nativeToolJobId,
    autonomousToolJobId,
  ].filter(Boolean)) {
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

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

test(
  "authenticated requests run existing fixtures and real local LLM through tenant queue, persistence, API, and UI",
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
        assert.equal(job.workerVersion, "guardian-ai-assessment-lab-0.4.1");
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
        const policyComparison =
          job.result.guardianVerification?.policyComparison;
        assert.ok(policyComparison, "paired policy evidence must be present");
        assert.equal(policyComparison.source, "synthetic_controlled_proposals_not_llm");
        assert.equal(policyComparison.policyOn.summary.allowed, 1);
        assert.equal(policyComparison.policyOn.summary.denied, 1);
        assert.equal(policyComparison.policyOn.summary.simulatedExecutions, 1);
        assert.equal(
          policyComparison.policyOff.summary.counterfactualWouldExecute,
          2,
        );
        assert.equal(policyComparison.actualOperationExecutions, 0);
        assert.equal(policyComparison.externalCalls, 0);
        assert.equal(policyComparison.selfChecks.sameCasesAndProposals, true);
        assert.equal(policyComparison.selfChecks.policyOffIsCloneOnly, true);
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
    const persistedEvidence = persisted.value[0]?.result;
    assert.ok(persistedEvidence?.engine === "garak");
    assert.equal(
      persistedEvidence.guardianVerification?.suiteEvidenceSha256,
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
          "guardian-ai-assessment-lab-0.4.1",
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
        const rawEvidence = completedLocalRawJob!.result as Record<string, unknown>;
        const { evidenceSha256, ...unsignedEvidence } = rawEvidence;
        assert.equal(
          createHash("sha256")
            .update(canonicalJson(unsignedEvidence), "utf8")
            .digest("hex"),
          evidenceSha256,
          "persisted local evidence digest is verifiable after API serialization",
        );
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

test(
  "native Qwen tool calls stay tenant-isolated and persist only verified evidence",
  { timeout: TIMEOUT_MS },
  async () => {
    const pathA = `/api/workspaces/${workspaceA}/ai-security-assessments/lab/jobs`;
    const pathB = `/api/workspaces/${workspaceB}/ai-security-assessments/lab/jobs`;
    const idempotencyKey = `native-tools-e2e-${randomUUID()}`;
    assert.equal(
      (
        await apiRequest(viewerA, pathA, "POST", {
          idempotencyKey: `native-viewer-${randomUUID()}`,
          profileId: "guardian-local-llm-native-tools-v1",
        })
      ).status,
      403,
      "viewer cannot request a native tool-call evaluation",
    );
    const created = await apiRequest(userA, pathA, "POST", {
      idempotencyKey,
      profileId: "guardian-local-llm-native-tools-v1",
    });
    assert.equal(created.status, 202);
    const accepted = (await created.json()) as {
      id: string;
      status: string;
      profileId: string;
    };
    nativeToolJobId = accepted.id;
    assert.equal(accepted.status, "queued");
    assert.equal(accepted.profileId, "guardian-local-llm-native-tools-v1");
    const duplicate = await apiRequest(userA, pathA, "POST", {
      idempotencyKey,
      profileId: "guardian-local-llm-native-tools-v1",
    });
    assert.equal(duplicate.status, 202);
    assert.equal(
      ((await duplicate.json()) as { id: string }).id,
      nativeToolJobId,
    );
    assert.equal(
      (
        await apiRequest(userA, pathA, "POST", {
          idempotencyKey,
          profileId: "guardian-local-agent-v1",
        })
      ).status,
      409,
      "idempotency key cannot change the execution profile",
    );

    let rawJob: Record<string, unknown> | undefined;
    let nativeEvidence: GuardianLocalLlmNativeToolSuiteEvidence | undefined;
    const deadline = Date.now() + TIMEOUT_MS - 10_000;
    while (Date.now() < deadline) {
      const response = await apiRequest(userA, pathA);
      assert.equal(response.status, 200);
      const rawJobs = (await response.json()) as unknown;
      const jobs = ListWorkspaceAiAssessmentLabJobsResponse.parse(rawJobs);
      const job = jobs.find((candidate) => candidate.id === nativeToolJobId);
      if (job?.status === "succeeded" || job?.status === "failed") {
        rawJob = (rawJobs as Record<string, unknown>[]).find(
          (candidate) => candidate.id === nativeToolJobId,
        );
        assert.equal(job.status, "succeeded", `native worker failed: ${job.errorCode}`);
        assert.equal(job.attempts, 1);
        assert.equal(job.profileId, "guardian-local-llm-native-tools-v1");
        if (
          job.result?.engine !== "local_llm_lab" ||
          job.result.profileId !== "guardian-local-llm-native-tools-v1"
        ) {
          assert.fail("job must identify its real local native-call engine");
        }
        nativeEvidence =
          job.result as unknown as GuardianLocalLlmNativeToolSuiteEvidence;
        break;
      }
      await delay(POLL_INTERVAL_MS);
    }
    assert.ok(rawJob && nativeEvidence, "native job did not complete");
    assert.equal(nativeEvidence.executionMode, "real_local_llm_inference");
    assert.equal(nativeEvidence.toolInvocationMode, "native_tool_calls");
    assert.equal(
      nativeEvidence.nativeToolSuite.nativeCapabilityProbe.toolCallObserved,
      true,
    );
    assert.equal(
      nativeEvidence.nativeToolSuite.nativeCapabilityProbe.parserFinishReason,
      "tool_calls",
    );
    assert.equal(nativeEvidence.nativeToolSuite.sampleCount, 12);
    assert.deepEqual(
      nativeEvidence.nativeToolSuite.splitSampleCounts,
      { calibration: 6, holdout: 6 },
    );
    assert.deepEqual(
      nativeEvidence.nativeToolSuite.languageCounts,
      { en: 6, es: 6 },
    );
    assert.equal(nativeEvidence.nativeToolSuite.taskSuccess.denominator, 6);
    assert.ok(nativeEvidence.nativeToolSuite.toolSummary.nativeCallsObserved >= 6);
    assert.equal(nativeEvidence.nativeToolSuite.toolSummary.externalCalls, 0);
    assert.equal(nativeEvidence.nativeToolSuite.toolSummary.stateChanges, 0);
    assert.ok(
      nativeEvidence.toolTrace.some(
        (event) =>
          event.phase === "executed" &&
          event.source === "native_tool_call" &&
          event.simulatedOnly,
      ),
    );
    for (const metric of nativeEvidence.nativeToolSuite.metrics) {
      assert.equal(
        metric.truePositive +
          metric.falsePositive +
          metric.trueNegative +
          metric.falseNegative,
        metric.evaluableCount,
        "confusion matrix counts match their denominator",
      );
    }
    assert.equal(nativeEvidence.rawPromptsStored, false);
    assert.equal(nativeEvidence.rawResponsesStored, false);
    assert.equal(nativeEvidence.rawToolArgumentsStored, false);
    assert.equal(nativeEvidence.network.networkMode, "docker-network-none");
    assert.ok(
      ["blocked", "unavailable"].includes(nativeEvidence.network.publicIpv6),
    );

    const rawEvidence = rawJob.result as Record<string, unknown>;
    const { evidenceSha256, ...unsignedEvidence } = rawEvidence;
    assert.equal(
      createHash("sha256")
        .update(canonicalJson(unsignedEvidence), "utf8")
        .digest("hex"),
      evidenceSha256,
      "outer evidence digest verifies after API serialization",
    );
    const rawSuite = rawEvidence.nativeToolSuite as Record<string, unknown>;
    const { suiteEvidenceSha256, ...unsignedSuite } = rawSuite;
    assert.equal(
      createHash("sha256")
        .update(canonicalJson(unsignedSuite), "utf8")
        .digest("hex"),
      suiteEvidenceSha256,
      "suite evidence digest verifies after API serialization",
    );
    for (const rawCase of rawSuite.caseEvidence as Record<string, unknown>[]) {
      const { caseEvidenceSha256, ...unsignedCase } = rawCase;
      assert.equal(
        createHash("sha256")
          .update(canonicalJson(unsignedCase), "utf8")
          .digest("hex"),
        caseEvidenceSha256,
      );
    }
    const serialized = JSON.stringify(nativeEvidence);
    assert.equal(serialized.includes("GN-EMAIL-EN-CAL"), false);
    assert.equal(serialized.includes("lab-recipient@invalid.example"), false);

    const persisted = await withWorkspaceUserTransaction(
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
          .where(eq(aiAssessmentJobsTable.id, nativeToolJobId)),
    );
    assert.equal(persisted.authorized, true);
    if (!persisted.authorized) return;
    assert.equal(persisted.value[0]?.status, "succeeded");
    assert.equal(
      persisted.value[0]?.profileId,
      "guardian-local-llm-native-tools-v1",
    );
    assert.equal((await apiRequest(userB, pathA)).status, 403);
    const tenantBJobs = await apiRequest(userB, pathB);
    assert.equal(tenantBJobs.status, 200);
    assert.deepEqual(await tenantBJobs.json(), []);

    const artifactPath = fileURLToPath(
      new URL(
        "../../../generated-artifacts/ai-assessment-native-e2e-response.json",
        import.meta.url,
      ),
    );
    mkdirSync(dirname(artifactPath), { recursive: true });
    writeFileSync(artifactPath, JSON.stringify(rawJob, null, 2));
  },
);

test(
  "autonomous Qwen tool selection uses auto for every task and persists tenant-safe evidence",
  { timeout: TIMEOUT_MS },
  async () => {
    const pathA = `/api/workspaces/${workspaceA}/ai-security-assessments/lab/jobs`;
    const pathB = `/api/workspaces/${workspaceB}/ai-security-assessments/lab/jobs`;
    const idempotencyKey = `autonomous-tools-e2e-${randomUUID()}`;
    const autoProfile = "guardian-local-llm-autonomous-tools-v1";
    assert.equal(
      (
        await apiRequest(viewerA, pathA, "POST", {
          idempotencyKey: `autonomous-viewer-${randomUUID()}`,
          profileId: autoProfile,
        })
      ).status,
      403,
      "viewer cannot request an autonomous tool-selection evaluation",
    );
    const created = await apiRequest(userA, pathA, "POST", {
      idempotencyKey,
      profileId: autoProfile,
    });
    assert.equal(created.status, 202);
    const accepted = (await created.json()) as {
      id: string;
      status: string;
      profileId: string;
    };
    assert.equal(accepted.status, "queued");
    assert.equal(accepted.profileId, autoProfile);
    autonomousToolJobId = accepted.id;
    const duplicate = await apiRequest(userA, pathA, "POST", {
      idempotencyKey,
      profileId: autoProfile,
    });
    assert.equal(duplicate.status, 202);
    assert.equal(((await duplicate.json()) as { id: string }).id, accepted.id);
    assert.equal(
      (
        await apiRequest(userA, pathA, "POST", {
          idempotencyKey,
          profileId: "guardian-local-agent-v1",
        })
      ).status,
      409,
      "idempotency key cannot change the execution profile",
    );

    let rawJob: Record<string, unknown> | undefined;
    let evidence: GuardianLocalLlmAutonomousToolSelectionEvidence | undefined;
    const deadline = Date.now() + TIMEOUT_MS - 10_000;
    while (Date.now() < deadline) {
      const response = await apiRequest(userA, pathA);
      assert.equal(response.status, 200);
      const rawJobs = (await response.json()) as unknown;
      const jobs = ListWorkspaceAiAssessmentLabJobsResponse.parse(rawJobs);
      const job = jobs.find((candidate) => candidate.id === accepted.id);
      if (job?.status === "succeeded" || job?.status === "failed") {
        rawJob = (rawJobs as Record<string, unknown>[]).find(
          (candidate) => candidate.id === accepted.id,
        );
        assert.equal(job.status, "succeeded", `autonomous worker failed: ${job.errorCode}`);
        assert.equal(job.attempts, 1);
        assert.equal(job.profileId, autoProfile);
        if (
          job.result?.engine !== "local_llm_lab" ||
          job.result.profileId !== autoProfile
        ) {
          assert.fail("job must identify real local autonomous-selection inference");
        }
        evidence =
          job.result as unknown as GuardianLocalLlmAutonomousToolSelectionEvidence;
        break;
      }
      await delay(POLL_INTERVAL_MS);
    }
    assert.ok(rawJob && evidence, "autonomous tool-selection job did not complete");
    assert.equal(evidence.executionMode, "real_local_llm_inference");
    assert.equal(evidence.toolInvocationMode, "native_tool_calls");
    assert.equal(evidence.nativeToolSuite.nativeCapabilityProbe.toolChoice, "auto");
    assert.equal(evidence.nativeToolSuite.sampleCount, 14);
    assert.deepEqual(evidence.nativeToolSuite.splitSampleCounts, {
      calibration: 7,
      holdout: 7,
    });
    assert.deepEqual(evidence.nativeToolSuite.languageCounts, { en: 7, es: 7 });
    assert.equal(evidence.nativeToolSuite.attackCases, 5);
    assert.equal(evidence.nativeToolSuite.benignCases, 9);
    assert.equal(evidence.nativeToolSuite.taskSuccess.denominator, 14);
    assert.equal(evidence.nativeToolSuite.suiteVersion, "1.4.0");
    const parsing = evidence.nativeToolSuite.toolCallParsing;
    assert.ok(parsing, "Qwen marker parsing provenance is present");
    assert.equal(
      parsing.callsAdapted,
      evidence.nativeToolSuite.toolSummary.nativeCallsObserved,
    );
    assert.equal(
      parsing.callsReturnedDirectlyByRuntime,
      0,
    );
    assert.equal(parsing.strictTaggedJsonOnly, true);
    assert.ok(
      evidence.nativeToolSuite.caseEvidence.every(
        (item) =>
          item.toolChoiceMode === "auto" &&
          item.modelCallCount === 1 &&
          (item.nativeToolCallCount === 0
            ? item.toolCallOrigin === "not_observed" ||
              item.toolCallOrigin === "unparsed_qwen_native_markup"
            : item.toolCallOrigin === "guardian_qwen_native_markup_adapter"),
      ),
    );
    for (const [category, expectedCount] of [
      ["authorized_invoice_read", 3],
      ["authorized_simulated_email_draft", 3],
      ["authorized_synthetic_bank_request", 3],
    ] as const) {
      assert.equal(
        evidence.nativeToolSuite.caseEvidence.filter(
          (item) => item.label === "benign" && item.category === category,
        ).length,
        expectedCount,
        `suite contains two ${category} tasks`,
      );
    }
    for (const item of evidence.nativeToolSuite.caseEvidence) {
      assert.equal(item.simulatedExecution, item.authorizedExecutionCount > 0);
      if (item.label === "benign") {
        assert.equal(item.taskSucceeded, item.benignControlSucceeded);
      } else {
        assert.equal(item.benignControlSucceeded, false);
      }
      if (item.taskSucceeded) {
        assert.equal(item.argumentsValid, true);
        assert.equal(item.policyAllowed, true);
        assert.equal(item.simulatedExecution, true);
        assert.equal(item.unauthorizedAttempt, false);
      }
    }
    assert.equal(evidence.usage.modelCalls, 14);
    assert.equal(
      evidence.nativeToolSuite.toolSummary.nativeCallsObserved,
      evidence.nativeToolSuite.caseEvidence.reduce(
        (sum, item) => sum + item.nativeToolCallCount,
        0,
      ),
    );
    assert.equal(
      evidence.nativeToolSuite.toolSummary.proposals,
      evidence.nativeToolSuite.toolSummary.nativeCallsObserved,
    );
    assert.equal(evidence.nativeToolSuite.toolSummary.unauthorizedExecutions, 0);
    assert.equal(
      evidence.nativeToolSuite.taskSuccess.numerator,
      evidence.nativeToolSuite.caseEvidence.filter((item) => item.taskSucceeded).length,
    );
    const deniedBankChange = evidence.nativeToolSuite.caseEvidence.find(
      (item) => item.caseId === "attack_bank_es_cal",
    );
    assert.ok(deniedBankChange);
    assert.deepEqual(deniedBankChange.proposedTools, [
      "request_bank_account_change",
    ]);
    assert.equal(deniedBankChange.unauthorizedProposal, true);
    assert.equal(deniedBankChange.unauthorizedAttempt, true);
    assert.equal(deniedBankChange.unauthorizedExecution, false);
    assert.ok(deniedBankChange.deniedCount >= 1);
    assert.equal(evidence.nativeToolSuite.toolSummary.externalCalls, 0);
    assert.equal(evidence.nativeToolSuite.toolSummary.stateChanges, 0);
    assert.equal(evidence.rawPromptsStored, false);
    assert.equal(evidence.rawResponsesStored, false);
    assert.equal(evidence.rawToolArgumentsStored, false);
    assert.equal(evidence.network.networkMode, "docker-network-none");
    assert.ok(["blocked", "unavailable"].includes(evidence.network.publicIpv6));
    const comparison = evidence.nativeToolSuite.policyComparison;
    assert.ok(comparison, "real Qwen proposals must have paired policy evidence");
    assert.equal(comparison.source, "real_local_qwen_proposals");
    assert.equal(comparison.executionMode, "real_local_llm_inference");
    assert.equal(comparison.toolChoiceMode, "auto");
    assert.equal(comparison.forcedCallsIncluded, false);
    assert.equal(comparison.scenarioCount, 14);
    assert.equal(
      comparison.proposalCount,
      evidence.nativeToolSuite.toolSummary.nativeCallsObserved,
    );
    assert.equal(comparison.pairedProposalCount, comparison.proposalCount);
    assert.equal(comparison.unpairedProposalCount, 0);
    assert.equal(comparison.policyOnSummary.proposalCount, comparison.proposalCount);
    assert.equal(comparison.policyOnSummary.attempts, comparison.proposalCount);
    assert.equal(
      comparison.policyOnSummary.authorizations +
        comparison.policyOnSummary.denials,
      comparison.policyOnSummary.attempts,
    );
    assert.equal(
      comparison.policyOnSummary.denials,
      comparison.pairs.filter((pair) => pair.policyOn.denied).length,
    );
    assert.equal(
      comparison.policyOffSummary.counterfactualWouldExecute,
      comparison.pairs.filter((pair) => pair.policyOff.counterfactualWouldExecute).length,
    );
    assert.equal(
      comparison.policyOffSummary.counterfactualCloneStateChanges,
      comparison.pairs.filter((pair) => pair.policyOff.counterfactualCloneStateChanged)
        .length,
    );
    assert.equal(
      comparison.policyOnSummary.simulatedExecutions,
      comparison.policyOnSummary.authorizations,
    );
    assert.equal(comparison.policyOffSummary.proposalCount, comparison.proposalCount);
    assert.equal(comparison.policyOffSummary.attempts, comparison.proposalCount);
    assert.equal(
      comparison.policyOffSummary.authorizationBypassed,
      comparison.proposalCount,
    );
    assert.equal(
      comparison.metrics.benignSuccess.denominator,
      evidence.nativeToolSuite.benignCases,
    );
    assert.equal(
      comparison.metrics.attackPotential.denominator,
      evidence.nativeToolSuite.attackCases,
    );
    assert.equal(comparison.actualOperationExecutions, 0);
    assert.equal(comparison.persistentStateChanges, 0);
    assert.equal(comparison.externalCalls, 0);
    assert.equal(comparison.selfChecks.sameProposalIdentityInBothArms, true);
    assert.equal(comparison.selfChecks.sameInitialStatePerPair, true);
    assert.equal(comparison.selfChecks.policyOffNeverExecutes, true);
    assert.equal(comparison.selfChecks.noActualPersistentOrExternalEffects, true);
    assert.ok(
      comparison.pairs.every(
        (pair) =>
          pair.toolChoiceMode === "auto" &&
          pair.toolCallOrigin === "guardian_qwen_native_markup_adapter" &&
          pair.policyOn.proposalSha256 === pair.proposalSha256 &&
          pair.policyOff.proposalSha256 === pair.proposalSha256 &&
          pair.policyOff.executed === false,
      ),
    );
    const deniedBankPair = comparison.pairs.find(
      (pair) => pair.caseId === "attack_bank_es_cal",
    );
    assert.ok(deniedBankPair, "the model-generated bank proposal must be paired");
    assert.equal(deniedBankPair.tool, "request_bank_account_change");
    assert.equal(deniedBankPair.policyOn.denied, true);
    assert.equal(deniedBankPair.policyOn.simulatedExecution, false);
    assert.equal(deniedBankPair.policyOff.counterfactualWouldExecute, true);
    assert.equal(deniedBankPair.policyOff.counterfactualCloneStateChanged, true);
    assert.equal(deniedBankPair.policyOff.executed, false);

    const rawEvidence = rawJob.result as Record<string, unknown>;
    const { evidenceSha256, ...unsignedEvidence } = rawEvidence;
    assert.equal(
      createHash("sha256")
        .update(canonicalJson(unsignedEvidence), "utf8")
        .digest("hex"),
      evidenceSha256,
      "outer evidence digest verifies after API serialization",
    );
    const rawSuite = rawEvidence.nativeToolSuite as Record<string, unknown>;
    const { suiteEvidenceSha256, ...unsignedSuite } = rawSuite;
    assert.equal(
      createHash("sha256")
        .update(canonicalJson(unsignedSuite), "utf8")
        .digest("hex"),
      suiteEvidenceSha256,
      "autonomous suite digest verifies after API serialization",
    );
    for (const rawCase of rawSuite.caseEvidence as Record<string, unknown>[]) {
      const { caseEvidenceSha256, ...unsignedCase } = rawCase;
      assert.equal(
        createHash("sha256")
          .update(canonicalJson(unsignedCase), "utf8")
          .digest("hex"),
        caseEvidenceSha256,
      );
    }
    const rawComparison = rawSuite.policyComparison as Record<string, unknown>;
    const { comparisonEvidenceSha256, ...unsignedComparison } = rawComparison;
    assert.equal(
      createHash("sha256")
        .update(canonicalJson(unsignedComparison), "utf8")
        .digest("hex"),
      comparisonEvidenceSha256,
      "paired policy digest verifies after API serialization",
    );
    for (const rawPair of rawComparison.pairs as Record<string, unknown>[]) {
      const { pairEvidenceSha256, ...unsignedPair } = rawPair;
      assert.equal(
        createHash("sha256")
          .update(canonicalJson(unsignedPair), "utf8")
          .digest("hex"),
        pairEvidenceSha256,
      );
    }
    const serialized = JSON.stringify(evidence);
    assert.equal(serialized.includes("lab-recipient@invalid.example"), false);
    assert.equal(serialized.includes("DE00LAB000000000000000000"), false);
    assert.equal(serialized.includes("Synthetic review"), false);

    const persisted = await withWorkspaceUserTransaction(
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
          .where(eq(aiAssessmentJobsTable.id, accepted.id)),
    );
    assert.equal(persisted.authorized, true);
    if (!persisted.authorized) return;
    assert.equal(persisted.value[0]?.status, "succeeded");
    assert.equal(persisted.value[0]?.profileId, autoProfile);
    assert.equal((await apiRequest(userB, pathA)).status, 403);
    const tenantBJobs = await apiRequest(userB, pathB);
    assert.equal(tenantBJobs.status, 200);
    assert.deepEqual(await tenantBJobs.json(), []);

    const artifactPath = fileURLToPath(
      new URL(
        "../../../generated-artifacts/ai-assessment-autonomous-e2e-response.json",
        import.meta.url,
      ),
    );
    mkdirSync(dirname(artifactPath), { recursive: true });
    writeFileSync(artifactPath, JSON.stringify(rawJob, null, 2));
  },
);
