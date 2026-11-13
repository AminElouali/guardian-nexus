import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import express, { type RequestHandler } from "express";
import pg from "pg";
import {
  DecideWorkspaceAiAssessmentApprovalResponse,
  ListWorkspaceAiAssessmentApprovalsResponse,
  PreviewWorkspaceAiAssessmentPolicyLabResponse,
} from "@workspace/api-zod";
import {
  canonicalApprovalJson,
  computeApprovalProposalBindingV3,
  getAllowlistedSyntheticApprovalAction,
} from "./lib/ai-assessment-approval-actions";
import { verifyExplicitDisposableApprovalDatabase } from "./lib/approval-e2e-db-guard";
import { acquireGitHubActionsOidcToken } from "./lib/github-actions-oidc";
import {
  POLICY_LAB_PROFILE_IDS,
  QWEN_POLICY_LAB_PROFILE_IDS,
} from "./lib/ai-assessment-sandbox";

/*
 * This is an explicitly fixture-only integration harness. It executes the
 * deterministic Python policy worker locally, without Docker, then provisions
 * its redacted evidence as a completed fixture job so the real authenticated
 * approval API and RLS transaction path can be tested. It is not Qwen evidence,
 * a broker test, or a production job-queue consumer.
 */

const workerRoot = resolve(
  fileURLToPath(new URL("../../../workers/guardian-ai-assessment", import.meta.url)),
);
const workspaceAOwner = `synthetic-e2e-owner-${randomUUID()}`;
const workspaceAAdmin = `synthetic-e2e-admin-${randomUUID()}`;
const workspaceAAdmin2 = `synthetic-e2e-admin2-${randomUUID()}`;
const workspaceAViewer = `synthetic-e2e-viewer-${randomUUID()}`;
const workspaceBOwner = `synthetic-e2e-other-owner-${randomUUID()}`;
const authorizedUsers = new Set([
  workspaceAOwner,
  workspaceAAdmin,
  workspaceAAdmin2,
  workspaceAViewer,
  workspaceBOwner,
]);
const authForTest: RequestHandler = (req, res, next) => {
  const userId = req.get("x-guardian-test-user");
  if (!userId || !authorizedUsers.has(userId)) {
    res.status(401).json({ error: "Test identity required" });
    return;
  }
  req.authUserId = userId;
  next();
};

function sha256(value: unknown): string {
  return createHash("sha256")
    .update(canonicalApprovalJson(value), "utf8")
    .digest("hex");
}

function runPythonSdkApprovalClient(input: {
  apiBase: string;
  workspaceId: string;
  testUser: string;
  approvalId: string;
  binding: string;
}): Promise<string> {
  const sdkSource = resolve(
    workerRoot,
    "../../lib/guardian-agent-sdk-python/src",
  );
  const sdkClient = resolve(
    workerRoot,
    "tests/python_sdk_approval_api_client.py",
  );
  return new Promise((resolveSdk, rejectSdk) => {
    const child = spawn("python3", [sdkClient], {
      cwd: workerRoot,
      stdio: ["ignore", "pipe", "ignore"],
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        PYTHONPATH: sdkSource,
        PYTHONDONTWRITEBYTECODE: "1",
        GUARDIAN_API_BASE_URL: input.apiBase,
        GUARDIAN_WORKSPACE_ID: input.workspaceId,
        GUARDIAN_TEST_USER: input.testUser,
        GUARDIAN_APPROVAL_ID: input.approvalId,
        GUARDIAN_PROPOSAL_BINDING_SHA256: input.binding,
      },
    });
    let stdout = "";
    let settled = false;
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error("python_sdk_e2e_timeout"));
    }, 15_000);
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error) rejectSdk(error);
      else resolveSdk(stdout.trim());
    };
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      if (settled) return;
      if (Buffer.byteLength(stdout) + Buffer.byteLength(chunk) > 4_096) {
        child.kill("SIGKILL");
        finish(new Error("python_sdk_e2e_output_limit"));
        return;
      }
      stdout += chunk;
    });
    child.on("error", () => finish(new Error("python_sdk_e2e_spawn_failed")));
    child.on("close", (code) => {
      if (code !== 0) {
        finish(new Error(`python_sdk_e2e_failed:exit_${code ?? "unknown"}`));
      } else {
        finish();
      }
    });
  });
}

type SyntheticWorkerEvidence = {
  engine: "guardian_policy_lab";
  executionMode: "deterministic_fixture";
  modelInference: false;
  profileId: string;
  cases: Array<Record<string, unknown>>;
  evidenceSha256: string;
  summary: Record<string, unknown>;
};

const workerEvidenceCache = new Map<string, SyntheticWorkerEvidence>();
let fixtureWorkerProcessCount = 0;

function runDeterministicFixtureWorker(profileId: string): SyntheticWorkerEvidence {
  const cached = workerEvidenceCache.get(profileId);
  if (cached) return cached;
  const result = spawnSync(
    "python3",
    ["-m", "guardian_ai_assessment.policy_lab", "--profile-id", profileId],
    {
      cwd: workerRoot,
      encoding: "utf8",
      timeout: 15_000,
      maxBuffer: 1024 * 1024,
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        PYTHONPATH: workerRoot,
        PYTHONDONTWRITEBYTECODE: "1",
        PYTHONHASHSEED: "0",
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
      },
    },
  );
  fixtureWorkerProcessCount += 1;
  assert.equal(result.error, undefined, "fixture worker must finish locally");
  assert.equal(result.status, 0, result.stderr);
  const evidence = JSON.parse(result.stdout) as SyntheticWorkerEvidence;
  assert.equal(evidence.engine, "guardian_policy_lab");
  assert.equal(evidence.executionMode, "deterministic_fixture");
  assert.equal(evidence.modelInference, false);
  assert.equal(evidence.profileId, profileId);
  assert.equal(evidence.summary.externalCalls, 0);
  assert.equal(evidence.summary.actualOperations, 0);
  assert.equal(evidence.summary.persistentStateChanges, 0);
  workerEvidenceCache.set(profileId, evidence);
  return evidence;
}

async function createFixtureJob(
  fixturePool: pg.Pool,
  workspaceId: string,
  requesterId: string,
  profileId: string,
  idempotencyKey: string,
  evidence: SyntheticWorkerEvidence,
): Promise<string> {
  const inserted = await fixturePool.query<{ id: string }>(
    `INSERT INTO public.ai_assessment_jobs
       (workspace_id, requested_by_user_id, idempotency_key, profile_id,
        worker_version, engine_version, status, result, completed_at)
     VALUES ($1, $2, $3, $4, 'synthetic-fixture-no-broker-v1',
             'guardian-agent-policy-lab-v2', 'succeeded', $5::jsonb, now())
     ON CONFLICT (workspace_id, idempotency_key) DO NOTHING
     RETURNING id`,
    [workspaceId, requesterId, idempotencyKey, profileId, JSON.stringify(evidence)],
  );
  if (inserted.rows[0]?.id) return inserted.rows[0].id;
  const existing = await fixturePool.query<{
    id: string;
    profile_id: string;
    status: string;
    result: SyntheticWorkerEvidence;
  }>(
    `SELECT id, profile_id, status, result
       FROM public.ai_assessment_jobs
      WHERE workspace_id = $1 AND idempotency_key = $2`,
    [workspaceId, idempotencyKey],
  );
  const row = existing.rows[0];
  assert.ok(row);
  assert.equal(row.profile_id, profileId);
  assert.equal(row.status, "succeeded");
  assert.equal(row.result.evidenceSha256, evidence.evidenceSha256);
  return row.id;
}

async function seedApproval(
  fixturePool: pg.Pool,
  input: {
    workspaceId: string;
    requesterId: string;
    profileId: string;
    caseId: string;
    expiry: Date;
    idempotencyKey: string;
  },
): Promise<{ jobId: string; approvalId: string; binding: string }> {
  const evidence = runDeterministicFixtureWorker(input.profileId);
  const fixtureCase = evidence.cases.find((item) => item.caseId === input.caseId);
  assert.ok(fixtureCase, `fixture worker omitted ${input.caseId}`);
  const policyOn = fixtureCase.policyOn as Record<string, unknown>;
  const toolTrace = fixtureCase.toolTrace as {
    policyOn?: Record<string, unknown>;
  };
  assert.equal(policyOn?.decision, "require_approval");
  assert.equal(fixtureCase.instructionProvenance, "trusted_user_request");
  assert.equal(
    toolTrace?.policyOn?.dispatchStatus,
    "approval_required_before_dispatch",
  );
  assert.equal(fixtureCase.unauthorizedActionExecuted, false);
  assert.equal(fixtureCase.rawArgumentsStored, false);
  assert.equal(fixtureCase.rawInstructionStored, false);

  const jobId = await createFixtureJob(
    fixturePool,
    input.workspaceId,
    input.requesterId,
    input.profileId,
    input.idempotencyKey,
    evidence,
  );
  assert.equal(
    await createFixtureJob(
      fixturePool,
      input.workspaceId,
      input.requesterId,
      input.profileId,
      input.idempotencyKey,
      evidence,
    ),
    jobId,
    "repeating a fixture completion with the same key must reuse the same job",
  );
  const actionRef = String(fixtureCase.syntheticActionRef);
  const tool = String(fixtureCase.tool);
  const action = getAllowlistedSyntheticApprovalAction(
    actionRef,
    input.profileId,
    input.caseId,
    tool,
  );
  assert.ok(action, "fixture proposal must resolve to a fixed synthetic action");
  assert.equal(fixtureCase.actionSha256, action.actionSha256);
  assert.equal(fixtureCase.proposalSha256, action.proposalSha256);
  const approvalProvenance = {
    modelInference: false,
    executionMode: "deterministic_fixture" as const,
    toolCallOrigin: "controlled_fixture_not_llm" as const,
  };
  const proposalBindingSha256 = computeApprovalProposalBindingV3({
    workspaceId: input.workspaceId,
    jobId,
    caseId: input.caseId,
    proposalSha256: action.proposalSha256,
    actionSha256: action.actionSha256,
    syntheticActionRef: actionRef as
      | "guardian.synthetic.finance.bank-change.v1"
      | "guardian.synthetic.support.refund.v1",
    requestedByUserId: input.requesterId,
    requestedByRole: "owner",
    expiresAt: input.expiry,
    ...approvalProvenance,
  });
  const inserted = await fixturePool.query<{ id: string }>(
    `INSERT INTO public.ai_assessment_approval_requests
       (workspace_id, job_id, case_id, proposal_sha256, action_sha256,
        proposal_binding_sha256, requested_by_user_id, requested_by_role,
        binding_version, synthetic_action_ref, model_inference, execution_mode,
        tool_call_origin, status, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'owner', 3, $8, false,
             'deterministic_fixture', 'controlled_fixture_not_llm',
             'pending', $9)
     RETURNING id`,
    [
      input.workspaceId,
      jobId,
      input.caseId,
      action.proposalSha256,
      action.actionSha256,
      proposalBindingSha256,
      input.requesterId,
      actionRef,
      input.expiry,
    ],
  );
  const approvalId = inserted.rows[0]?.id;
  assert.ok(approvalId);
  return { jobId, approvalId, binding: proposalBindingSha256 };
}

test(
  "deterministic fixtures verify persistent approval state from a fresh database pool",
  { timeout: 60_000 },
  async (t) => {
    if (
      !(await verifyExplicitDisposableApprovalDatabase(
        process.env,
        acquireGitHubActionsOidcToken,
      ))
    ) {
      t.skip(
        "requires an authenticated GitHub Actions OIDC target or explicit local disposable opt-in",
      );
      return;
    }
    const { assertRlsRuntimeReady, pool: appPool } =
      await import("@workspace/db");
    const { createAiAssessmentLabRouter } =
      await import("./routes/ai-assessment-lab");
    const databaseUrl = process.env.DATABASE_URL;
    assert.ok(databaseUrl);
    await assertRlsRuntimeReady();
    const fixturePool = new pg.Pool({ connectionString: databaseUrl });
    const app = express();
    app.use(express.json({ limit: "8kb" }));
    app.use("/api", createAiAssessmentLabRouter(authForTest));

    let workspaceA = "";
    let workspaceB = "";
    let server: Server | undefined;
    t.after(async () => {
      if (server?.listening) {
        await new Promise<void>((resolveClose, reject) => {
          server!.close((error) => (error ? reject(error) : resolveClose()));
        });
      }
      if (workspaceA) {
        await fixturePool.query("DELETE FROM public.workspaces WHERE id = $1", [
          workspaceA,
        ]);
      }
      if (workspaceB) {
        await fixturePool.query("DELETE FROM public.workspaces WHERE id = $1", [
          workspaceB,
        ]);
      }
      await fixturePool.end();
    });

    const workspaces = await Promise.all([
      fixturePool.query<{ id: string }>(
        `INSERT INTO public.workspaces (name, plan_id, created_by_user_id)
         VALUES ('Synthetic approval harness A', 'small', $1) RETURNING id`,
        [workspaceAOwner],
      ),
      fixturePool.query<{ id: string }>(
        `INSERT INTO public.workspaces (name, plan_id, created_by_user_id)
         VALUES ('Synthetic approval harness B', 'small', $1) RETURNING id`,
        [workspaceBOwner],
      ),
    ]);
    workspaceA = workspaces[0].rows[0]!.id;
    workspaceB = workspaces[1].rows[0]!.id;
    await fixturePool.query(
      `INSERT INTO public.workspace_memberships (workspace_id, user_id, role)
       VALUES ($1, $2, 'owner'), ($1, $3, 'admin'), ($1, $4, 'admin'),
              ($1, $5, 'viewer'), ($6, $7, 'owner')`,
      [
        workspaceA,
        workspaceAOwner,
        workspaceAAdmin,
        workspaceAAdmin2,
        workspaceAViewer,
        workspaceB,
        workspaceBOwner,
      ],
    );

    server = createServer(app);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const apiBase = `http://127.0.0.1:${address.port}`;
    const request = async (
      userId: string | null,
      path: string,
      method = "GET",
      body?: unknown,
    ) =>
      fetch(`${apiBase}${path}`, {
        method,
        headers: {
          ...(userId ? { "x-guardian-test-user": userId } : {}),
          ...(body ? { "content-type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    const approvalPath = `/api/workspaces/${workspaceA}/ai-security-assessments/approvals`;
    const expireFuture = () => new Date(Date.now() + 60 * 60 * 1000);
    const queuePath = `/api/workspaces/${workspaceA}/ai-security-assessments/lab/jobs`;
    const previewPath = `/api/workspaces/${workspaceA}/ai-security-assessments/lab/policy-preview`;
    const previewEvidence: Array<{
      profileId: string;
      engineVersion: string;
      executionMode: "deterministic_fixture";
      proposalOrigin: "controlled_fixture_not_llm";
      modelInference: false;
      caseIds: string[];
      caseCount: number;
      decisionCounts: Record<string, number>;
      evidenceSha256: string;
    }> = [];
    assert.equal((await request(null, previewPath, "POST", {
      profileId: "guardian-agent-lab-email-v1",
    })).status, 401, "preview requires authentication");
    assert.equal((await request(workspaceBOwner, previewPath, "POST", {
      profileId: "guardian-agent-lab-email-v1",
    })).status, 403, "preview is workspace-scoped");
    assert.equal((await request(workspaceAViewer, previewPath, "POST", {
      profileId: "guardian-agent-lab-email-v1",
    })).status, 403, "viewer cannot run previews");
    assert.equal((await request(workspaceAOwner, previewPath, "POST", {
      profileId: "guardian-agent-lab-email-v1",
      engineVersion: "attacker-selected",
    })).status, 400, "unknown preview inputs are rejected");

    const jobsBeforePreview = await fixturePool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM public.ai_assessment_jobs
        WHERE workspace_id = $1`,
      [workspaceA],
    );
    for (const profileId of POLICY_LAB_PROFILE_IDS) {
      const previewResponse = await request(
        workspaceAAdmin,
        previewPath,
        "POST",
        { profileId },
      );
      assert.equal(previewResponse.status, 200, `${profileId} preview`);
      assert.equal(previewResponse.headers.get("cache-control"), "no-store");
      const preview = PreviewWorkspaceAiAssessmentPolicyLabResponse.parse(
        await previewResponse.json(),
      );
      const evidence = preview.evidence;
      assert.equal(preview.source, "fresh_deterministic_policy_preview");
      assert.equal(evidence.profileId, profileId);
      assert.equal(evidence.engineVersion, "guardian-agent-policy-lab-v3");
      assert.equal(evidence.executionContext, "api_policy_preview");
      assert.equal(evidence.executionMode, "deterministic_fixture");
      assert.equal(evidence.modelInference, false);
      assert.equal(evidence.proposalOrigin, "controlled_fixture_not_llm");
      assert.equal(evidence.limits.network, "host_network_unisolated");
      assert.equal(evidence.limits.processIsolation, "shared_api_identity");
      assert.equal(evidence.limits.dockerSocketAccess, "not_assessed");
      assert.equal(evidence.summary.externalCalls, 0);
      assert.equal(evidence.summary.actualOperations, 0);
      assert.equal(evidence.summary.persistentStateChanges, 0);
      assert.equal(evidence.summary.unauthorizedExecutions, 0);

      if (
        profileId === "guardian-agent-lab-email-v1" ||
        profileId === "guardian-agent-lab-database-v1"
      ) {
        const expectedAttack =
          profileId === "guardian-agent-lab-email-v1"
            ? {
                caseId: "email_adversarial_external_exfiltration",
                provenance: "untrusted_email",
                reasonCode: "permission_not_granted",
              }
            : {
                caseId: "database_adversarial_bulk_export",
                provenance: "untrusted_document",
                reasonCode: "resource_outside_workspace",
              };
        assert.equal(evidence.cases.length, 2);
        const benign = evidence.cases.find((item) => item.label === "benign");
        const adversarial = evidence.cases.find(
          (item) => item.caseId === expectedAttack.caseId,
        );
        assert.ok(benign, `${profileId} includes a benign fixture`);
        assert.ok(adversarial, `${profileId} includes the expected attack fixture`);
        assert.equal(benign.instructionProvenance, "trusted_user_request");
        assert.equal(adversarial.label, "adversarial");
        assert.equal(
          adversarial.instructionProvenance,
          expectedAttack.provenance,
        );
        assert.equal(
          adversarial.policyOn.reasonCode,
          expectedAttack.reasonCode,
        );
        assert.equal(adversarial.policyOn.decision, "deny");
        assert.equal(adversarial.policyOn.authorized, false);
        assert.equal(adversarial.policyOn.executed, false);
        assert.equal(
          adversarial.toolTrace?.policyOn.dispatchStatus,
          "blocked_by_policy_before_dispatch",
        );
        assert.equal(adversarial.toolTrace?.policyOn.invoked, false);
        assert.deepEqual(adversarial.toolTrace?.policyOn.events, []);
        if (profileId === "guardian-agent-lab-database-v1") {
          assert.equal(
            adversarial.resourceWorkspaceId,
            "SYNTHETIC-OTHER-WORKSPACE",
          );
        }
      }

      const decisionCounts: Record<string, number> = {};
      for (const scenario of evidence.cases) {
        const decision = scenario.policyOn.decision;
        decisionCounts[decision] = (decisionCounts[decision] ?? 0) + 1;
        const toolTrace = scenario.toolTrace;
        assert.ok(toolTrace, `${profileId} case must include tool trace`);
        const policyOn = toolTrace.policyOn;
        if (decision === "allow") {
          assert.equal(policyOn.dispatchStatus, "simulated_execution");
          assert.equal(policyOn.invoked, true);
          assert.equal(scenario.policyOn.executed, true);
          assert.ok(
            policyOn.events.some(
              (event) => event.phase === "executed" && event.executed,
            ),
          );
        } else if (decision === "require_approval") {
          assert.equal(
            policyOn.dispatchStatus,
            "approval_required_before_dispatch",
          );
          assert.equal(policyOn.invoked, false);
          assert.equal(policyOn.events.length, 0);
          assert.equal(scenario.policyOn.executed, false);
        } else {
          assert.equal(decision, "deny");
          assert.ok(
            policyOn.dispatchStatus === "blocked_by_policy_before_dispatch" ||
              policyOn.dispatchStatus === "adapter_validation_denied",
          );
          assert.equal(scenario.policyOn.executed, false);
          assert.ok(policyOn.events.every((event) => !event.executed));
        }
        assert.equal(
          scenario.policyOff.mode,
          "counterfactual_clone_only",
        );
        assert.equal(scenario.policyOff.executed, false);
        assert.equal(toolTrace.policyOff.invoked, false);
        assert.equal(toolTrace.policyOff.events.length, 0);
      }
      previewEvidence.push({
        profileId,
        engineVersion: evidence.engineVersion,
        executionMode: evidence.executionMode,
        proposalOrigin: evidence.proposalOrigin,
        modelInference: evidence.modelInference,
        caseIds: evidence.cases.map((item) => item.caseId),
        caseCount: evidence.cases.length,
        decisionCounts,
        evidenceSha256: evidence.evidenceSha256,
      });
    }
    const jobsAfterPreview = await fixturePool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM public.ai_assessment_jobs
        WHERE workspace_id = $1`,
      [workspaceA],
    );
    assert.equal(
      jobsAfterPreview.rows[0]?.count,
      jobsBeforePreview.rows[0]?.count,
      "preview is ephemeral and must not create a job or history record",
    );

    const beforeBlockedEnqueue = await fixturePool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM public.ai_assessment_jobs
        WHERE workspace_id = $1`,
      [workspaceA],
    );
    const queueProfiles = [
      ...POLICY_LAB_PROFILE_IDS,
      ...QWEN_POLICY_LAB_PROFILE_IDS,
    ];
    const queueAuthorizationChecks = {
      unauthenticatedRejected: 0,
      crossTenantRejected: 0,
      viewerRejected: 0,
    };
    const queueIdempotencyKeys = new Map(
      queueProfiles.map((profileId) => [
        profileId,
        `broker-disabled-${profileId}-${randomUUID()}`,
      ]),
    );
    for (const profileId of queueProfiles) {
      const body = {
        idempotencyKey: queueIdempotencyKeys.get(profileId)!,
        profileId,
      };
      assert.equal(
        (
          await request(
            null,
            queuePath,
            "POST",
            body,
          )
        ).status,
        401,
        `${profileId} unauthenticated queue request`,
      );
      queueAuthorizationChecks.unauthenticatedRejected += 1;
      assert.equal(
        (
          await request(
            workspaceBOwner,
            queuePath,
            "POST",
            body,
          )
        ).status,
        403,
        `${profileId} cross-tenant queue request`,
      );
      queueAuthorizationChecks.crossTenantRejected += 1;
      assert.equal(
        (
          await request(
            workspaceAViewer,
            queuePath,
            "POST",
            body,
          )
        ).status,
        403,
        `${profileId} viewer queue request`,
      );
      queueAuthorizationChecks.viewerRejected += 1;
    }
    for (const profileId of queueProfiles) {
      const blockedEnqueue = await request(workspaceAOwner, queuePath, "POST", {
        idempotencyKey: queueIdempotencyKeys.get(profileId)!,
        profileId,
      });
      assert.equal(
        blockedEnqueue.status,
        503,
        `${profileId} queue request must remain blocked without isolated broker`,
      );
    }
    for (const profileId of queueProfiles) {
      const body = {
        idempotencyKey: queueIdempotencyKeys.get(profileId)!,
        profileId,
      };
      assert.equal(
        (
          await request(workspaceAOwner, queuePath, "POST", body)
        ).status,
        503,
        `${profileId} owner retry remains blocked while the broker is unverified`,
      );
    }
    const afterBlockedEnqueue = await fixturePool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM public.ai_assessment_jobs
        WHERE workspace_id = $1`,
      [workspaceA],
    );
    assert.equal(
      afterBlockedEnqueue.rows[0]?.count,
      beforeBlockedEnqueue.rows[0]?.count,
      "disabled worker must reject every profile before creating a job",
    );

    const cases = [
      {
        profileId: "guardian-agent-lab-finance-v1",
        caseId: "finance_trusted_bank_change_requires_approval",
        idempotencyKey: `synthetic-finance-${randomUUID()}`,
        expectedResult: "synthetic_bank_change_approved_in_clone",
      },
      {
        profileId: "guardian-agent-lab-customer-service-v1",
        caseId: "support_trusted_refund_requires_approval",
        idempotencyKey: `synthetic-support-${randomUUID()}`,
        expectedResult: "synthetic_refund_approved_in_clone",
      },
    ] as const;

    const approvals = [];
    for (const fixture of cases) {
      const evidence = runDeterministicFixtureWorker(fixture.profileId);
      assert.equal(evidence.modelInference, false);
      assert.equal(evidence.executionMode, "deterministic_fixture");
      const seeded = await seedApproval(fixturePool, {
        workspaceId: workspaceA,
        requesterId: workspaceAOwner,
        profileId: fixture.profileId,
        caseId: fixture.caseId,
        expiry: expireFuture(),
        idempotencyKey: fixture.idempotencyKey,
      });
      approvals.push({ ...seeded, ...fixture });
    }

    assert.equal((await request(null, approvalPath)).status, 401);
    assert.equal((await request(workspaceBOwner, approvalPath)).status, 403);

    for (const approval of approvals) {
      const decisionPath = `${approvalPath}/${approval.approvalId}/decision`;
      assert.equal(
        (await request(workspaceAOwner, decisionPath, "POST", {
          decision: "approve",
          proposalBindingSha256: approval.binding,
        })).status,
        403,
        "requester cannot approve their own fixture proposal",
      );
      assert.equal(
        (await request(workspaceAViewer, decisionPath, "POST", {
          decision: "approve",
          proposalBindingSha256: approval.binding,
        })).status,
        403,
        "viewer cannot approve",
      );
      assert.equal(
        (await request(workspaceBOwner, decisionPath, "POST", {
          decision: "approve",
          proposalBindingSha256: approval.binding,
        })).status,
        403,
        "cross-tenant decision is denied",
      );
      assert.equal(
        (await request(workspaceAAdmin, decisionPath, "POST", {
          decision: "approve",
          proposalBindingSha256: "0".repeat(64),
        })).status,
        409,
        "tampered proposal binding is rejected",
      );
      const pending = ListWorkspaceAiAssessmentApprovalsResponse.parse(
        await (await request(workspaceAAdmin, approvalPath)).json(),
      );
      const pendingApproval = pending.approvals.find(
        (item) => item.id === approval.approvalId,
      );
      assert.equal(pendingApproval?.status, "pending");
      assert.equal(pendingApproval?.modelInference, false);
      assert.equal(pendingApproval?.executionMode, "deterministic_fixture");
      assert.equal(
        pendingApproval?.toolCallOrigin,
        "controlled_fixture_not_llm",
      );
      if (approval === approvals[0]) {
        const [persisted] = (
          await fixturePool.query<{
            workspace_id: string;
            job_id: string;
            case_id: string;
            proposal_sha256: string;
            action_sha256: string;
            synthetic_action_ref: string;
            requested_by_user_id: string;
            requested_by_role: string;
            expires_at: Date;
          }>(
            `SELECT workspace_id::text, job_id::text, case_id,
                    proposal_sha256, action_sha256, synthetic_action_ref,
                    requested_by_user_id, requested_by_role, expires_at
             FROM public.ai_assessment_approval_requests WHERE id = $1`,
            [approval.approvalId],
          )
        ).rows;
        assert.ok(persisted);
        const tamperedBinding = computeApprovalProposalBindingV3({
          workspaceId: persisted.workspace_id,
          jobId: persisted.job_id,
          caseId: persisted.case_id,
          proposalSha256: persisted.proposal_sha256,
          actionSha256: persisted.action_sha256,
          syntheticActionRef: persisted.synthetic_action_ref as
            | "guardian.synthetic.finance.bank-change.v1"
            | "guardian.synthetic.support.refund.v1",
          requestedByUserId: persisted.requested_by_user_id,
          requestedByRole: persisted.requested_by_role,
          expiresAt: persisted.expires_at,
          modelInference: true,
          executionMode: "real_local_qwen_inference",
          toolCallOrigin: "guardian_qwen_native_markup_adapter",
        });
        try {
          await fixturePool.query(
            `UPDATE public.ai_assessment_approval_requests
             SET model_inference = true,
                 execution_mode = 'real_local_qwen_inference',
                 tool_call_origin = 'guardian_qwen_native_markup_adapter',
                 proposal_binding_sha256 = $2
             WHERE id = $1`,
            [approval.approvalId, tamperedBinding],
          );
          const tamperedDecision = await request(
            workspaceAAdmin,
            decisionPath,
            "POST",
            {
              decision: "approve",
              proposalBindingSha256: tamperedBinding,
            },
          );
          assert.equal(
            tamperedDecision.status,
            409,
            "Qwen provenance cannot be substituted for linked fixture evidence",
          );
          const unchangedResult: {
            rows: Array<{ status: string; simulated_at: Date | null }>;
          } = await fixturePool.query(
            `SELECT status, simulated_at
             FROM public.ai_assessment_approval_requests WHERE id = $1`,
            [approval.approvalId],
          );
          const unchanged: { status: string; simulated_at: Date | null } | undefined =
            unchangedResult.rows[0];
          assert.equal(unchanged?.status, "pending");
          assert.equal(unchanged?.simulated_at, null);
        } finally {
          await fixturePool.query(
            `UPDATE public.ai_assessment_approval_requests
             SET model_inference = false,
                 execution_mode = 'deterministic_fixture',
                 tool_call_origin = 'controlled_fixture_not_llm',
                 proposal_binding_sha256 = $2
             WHERE id = $1`,
            [approval.approvalId, approval.binding],
          );
        }
      }
    }

    const finance = approvals[0]!;
    const financeDecisionPath = `${approvalPath}/${finance.approvalId}/decision`;
    const concurrent = await Promise.all([
      request(workspaceAAdmin, financeDecisionPath, "POST", {
        decision: "approve",
        proposalBindingSha256: finance.binding,
      }),
      request(workspaceAAdmin2, financeDecisionPath, "POST", {
        decision: "approve",
        proposalBindingSha256: finance.binding,
      }),
    ]);
    assert.deepEqual(
      concurrent.map((response) => response.status).sort(),
      [200, 409],
      "exactly one concurrent approval may consume the proposal",
    );
    const approvedResponse = DecideWorkspaceAiAssessmentApprovalResponse.parse(
      await concurrent.find((response) => response.status === 200)!.json(),
    );
    assert.equal(
      approvedResponse.execution,
      "synthetic_action_simulated_once",
    );
    assert.equal(
      approvedResponse.approval.simulationResultCode,
      finance.expectedResult,
    );
    assert.match(
      approvedResponse.approval.simulationResultSha256 ?? "",
      /^[a-f0-9]{64}$/,
    );
    assert.equal(
      (
        await request(workspaceAAdmin, financeDecisionPath, "POST", {
          decision: "approve",
          proposalBindingSha256: finance.binding,
        })
      ).status,
      409,
      "replay is rejected",
    );

    const support = approvals[1]!;
    const supportDecisionPath = `${approvalPath}/${support.approvalId}/decision`;
    const pythonSdkOutcome = await runPythonSdkApprovalClient({
      apiBase,
      workspaceId: workspaceA,
      testUser: workspaceAAdmin,
      approvalId: support.approvalId,
      binding: support.binding,
    });
    assert.equal(
      pythonSdkOutcome,
      "PYTHON_SDK_APPROVAL_E2E status=approved execution=synthetic_action_simulated_once",
    );
    assert.equal(
      (
        await request(workspaceAAdmin, supportDecisionPath, "POST", {
          decision: "approve",
          proposalBindingSha256: support.binding,
        })
      ).status,
      409,
      "support approval replay is rejected",
    );

    const supportDenied = await seedApproval(fixturePool, {
      workspaceId: workspaceA,
      requesterId: workspaceAOwner,
      profileId: support.profileId,
      caseId: support.caseId,
      expiry: expireFuture(),
      idempotencyKey: `synthetic-support-denied-${randomUUID()}`,
    });
    const denied = DecideWorkspaceAiAssessmentApprovalResponse.parse(
      await (
        await request(
          workspaceAAdmin,
          `${approvalPath}/${supportDenied.approvalId}/decision`,
          "POST",
          {
          decision: "deny",
            proposalBindingSha256: supportDenied.binding,
          },
        )
      ).json(),
    );
    assert.equal(denied.approval.status, "denied");
    assert.equal(denied.execution, "not_performed_denied");
    assert.equal(denied.approval.simulatedAt, null);

    const expired = await seedApproval(fixturePool, {
      workspaceId: workspaceA,
      requesterId: workspaceAOwner,
      profileId: finance.profileId,
      caseId: finance.caseId,
      expiry: new Date(Date.now() - 60_000),
      idempotencyKey: `synthetic-expired-${randomUUID()}`,
    });
    const expiredResponse = await request(
      workspaceAAdmin,
      `${approvalPath}/${expired.approvalId}/decision`,
      "POST",
      {
        decision: "approve",
        proposalBindingSha256: expired.binding,
      },
    );
    assert.equal(expiredResponse.status, 409);
    const expiredRows = await fixturePool.query<{
      status: string;
      simulated_at: Date | null;
    }>(
      `SELECT status, simulated_at
         FROM public.ai_assessment_approval_requests
        WHERE id = $1`,
      [expired.approvalId],
    );
    assert.equal(expiredRows.rows[0]?.status, "expired");
    assert.equal(expiredRows.rows[0]?.simulated_at, null);

    const roleRevoked = await seedApproval(fixturePool, {
      workspaceId: workspaceA,
      requesterId: workspaceAOwner,
      profileId: finance.profileId,
      caseId: finance.caseId,
      expiry: expireFuture(),
      idempotencyKey: `synthetic-role-revoked-${randomUUID()}`,
    });
    const revokedMembership = await fixturePool.query(
      `UPDATE public.workspace_memberships
          SET role = 'viewer'
        WHERE workspace_id = $1
          AND user_id = $2
          AND role = 'admin'`,
      [workspaceA, workspaceAAdmin2],
    );
    assert.equal(revokedMembership.rowCount, 1);
    const revokedRoleResponse = await request(
      workspaceAAdmin2,
      `${approvalPath}/${roleRevoked.approvalId}/decision`,
      "POST",
      {
        decision: "approve",
        proposalBindingSha256: roleRevoked.binding,
      },
    );
    assert.equal(
      revokedRoleResponse.status,
      403,
      "a previously authorized approver is denied after role revocation",
    );
    const roleRevokedRows = await fixturePool.query<{
      status: string;
      simulated_at: Date | null;
    }>(
      `SELECT status, simulated_at
         FROM public.ai_assessment_approval_requests
        WHERE id = $1`,
      [roleRevoked.approvalId],
    );
    assert.equal(roleRevokedRows.rows[0]?.status, "pending");
    assert.equal(
      roleRevokedRows.rows[0]?.simulated_at,
      null,
      "revoked role must not consume or simulate the pending proposal",
    );

    const expectedAuditEvents = [
      {
        approval: finance,
        action: "ai_assessment.approval_approved",
        simulated: true,
      },
      {
        approval: support,
        action: "ai_assessment.approval_approved",
        simulated: true,
      },
      {
        approval: supportDenied,
        action: "ai_assessment.approval_denied",
        simulated: false,
      },
      {
        approval: expired,
        action: "ai_assessment.approval_expired",
        simulated: false,
      },
    ] as const;
    for (const { approval, action, simulated } of expectedAuditEvents) {
      const audit = await fixturePool.query<{
        action: string;
        metadata: Record<string, unknown>;
      }>(
        `SELECT action, metadata
           FROM public.workspace_audit_events
          WHERE workspace_id = $1
            AND resource_id = $2
            AND action LIKE 'ai_assessment.approval_%'
          ORDER BY created_at`,
        [workspaceA, approval.approvalId],
      );
      assert.equal(
        audit.rows.length,
        1,
        "the successful transition is audited once; replay adds no audit event",
      );
      const event = audit.rows[0]!;
      assert.equal(event.action, action);
      if (simulated) {
        assert.equal(event.metadata.externalSideEffect, false);
        assert.equal(
          event.metadata.proposalBindingSha256,
          approval.binding,
        );
        assert.match(
          String(event.metadata.simulationResultSha256 ?? ""),
          /^[a-f0-9]{64}$/,
        );
        if (approval === finance) {
          assert.match(
            String(event.metadata.replayBindingSha256 ?? ""),
            /^[a-f0-9]{64}$/,
          );
        }
      }
    }

    for (const approval of [finance, support]) {
      const persisted = await fixturePool.query<{
        status: string;
        decided_by_role: string | null;
        simulated_at: Date | null;
        simulation_result_code: string | null;
        simulation_result_sha256: string | null;
        replay_binding_sha256: string | null;
      }>(
        `SELECT status, decided_by_role, simulated_at, simulation_result_code,
                simulation_result_sha256, replay_binding_sha256
           FROM public.ai_assessment_approval_requests
          WHERE id = $1 AND workspace_id = $2`,
        [approval.approvalId, workspaceA],
      );
      const row = persisted.rows[0];
      assert.ok(row, "approval decision must be persisted in its workspace");
      assert.equal(row.status, "approved");
      assert.equal(row.decided_by_role, "admin");
      assert.ok(row.simulated_at);
      assert.equal(row.simulation_result_code, approval.expectedResult);
      assert.match(row.simulation_result_sha256 ?? "", /^[a-f0-9]{64}$/);
      assert.match(row.replay_binding_sha256 ?? "", /^[a-f0-9]{64}$/);
    }

    // Reopen the database path through a fresh pool to verify that approval
    // states are durable beyond the fixture pool's existing connections.
    const reopenedPool = new pg.Pool({ connectionString: databaseUrl, max: 1 });
    try {
      for (const { approval, expectedStatus } of [
        { approval: finance, expectedStatus: "approved" },
        { approval: support, expectedStatus: "approved" },
        { approval: supportDenied, expectedStatus: "denied" },
        { approval: expired, expectedStatus: "expired" },
        { approval: roleRevoked, expectedStatus: "pending" },
      ]) {
        const reopened = await reopenedPool.query<{ status: string }>(
          `SELECT status
             FROM public.ai_assessment_approval_requests
            WHERE id = $1 AND workspace_id = $2`,
          [approval.approvalId, workspaceA],
        );
        assert.equal(
          reopened.rows[0]?.status,
          expectedStatus,
          `fresh database connections must observe durable ${expectedStatus} state`,
        );
      }
    } finally {
      await reopenedPool.end();
    }

    const revokedAudit = await fixturePool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM public.workspace_audit_events
        WHERE workspace_id = $1
          AND resource_id = $2
          AND action = 'ai_assessment.approval_approved'`,
      [workspaceA, roleRevoked.approvalId],
    );
    assert.equal(
      Number(revokedAudit.rows[0]?.count ?? 0),
      0,
      "a revoked approver cannot create an approval audit/simulation event",
    );

    const summary = {
      source: "deterministic_fixture_worker_harness",
      evidenceVersion: 1,
      generatedAt: new Date().toISOString(),
      modelInference: false,
      brokerUsed: false,
      dockerCommandRequestedByHarness: false,
      pythonSdkApprovalApiE2e: true,
      authenticationMode: "synthetic_test_header",
      fixtureWorkerProcesses: fixtureWorkerProcessCount,
      externalEffects: false,
      profiles: cases.map((item) => item.profileId),
      policyPreview: {
        status: "deterministic_fixture_only",
        executionMode: "deterministic_fixture",
        proposalOrigin: "controlled_fixture_not_llm",
        modelInference: false,
        invocationPath: "authenticated_api_to_deterministic_python_preview",
        profiles: previewEvidence,
        queueGate: {
          status: "disabled_without_isolated_broker",
          profileCount: queueProfiles.length,
          ownerRequestsRejectedBeforeJobInsert: queueProfiles.length * 2,
          firstOwnerRequestRejectedPerProfile: queueProfiles.length,
          sameKeyOwnerRetriesRejected: queueProfiles.length,
          queueConsumerInvoked: false,
          authorizationChecks: queueAuthorizationChecks,
        },
      },
      approvalRequests: approvals.length + 3,
      approvalDecisions: {
        approvedOnce: 2,
        deniedWithoutSimulation: 1,
        expiredWithoutSimulation: 1,
        concurrentSingleWinner: 1,
        revokedRoleRejected: true,
        revokedRoleNoSimulation: true,
        replayRejected: true,
        pythonSdkApprovalApiE2e: true,
        crossTenantRejected: true,
        roleAndSelfApprovalRejected: true,
        bindingMutationRejected: true,
      },
      evidenceSha256: cases.map(
        (item) => runDeterministicFixtureWorker(item.profileId).evidenceSha256,
      ),
    };
    assert.equal(summary.dockerCommandRequestedByHarness, false);
    assert.equal(summary.fixtureWorkerProcesses, 2);
    assert.equal(summary.externalEffects, false);
    assert.equal(summary.modelInference, false);
    assert.equal(previewEvidence.length, POLICY_LAB_PROFILE_IDS.length);
    assert.ok(
      previewEvidence.every(
        (item) =>
          item.executionMode === "deterministic_fixture" &&
          item.proposalOrigin === "controlled_fixture_not_llm" &&
          item.modelInference === false,
      ),
    );
    assert.deepEqual(
      queueAuthorizationChecks,
      {
        unauthenticatedRejected: queueProfiles.length,
        crossTenantRejected: queueProfiles.length,
        viewerRejected: queueProfiles.length,
      },
    );
    assert.equal(queueProfiles.length, 16);
    assert.equal(previewEvidence.length, POLICY_LAB_PROFILE_IDS.length);
    assert.equal(
      queueAuthorizationChecks.unauthenticatedRejected,
      queueProfiles.length,
    );
    assert.equal(
      queueAuthorizationChecks.crossTenantRejected,
      queueProfiles.length,
    );
    assert.equal(queueAuthorizationChecks.viewerRejected, queueProfiles.length);
    assert.equal((await appPool.query("SELECT 1")).rowCount, 1);
    const evidenceHash = sha256(summary);
    const artifactPath = fileURLToPath(
      new URL(
        "../../../generated-artifacts/guardian-synthetic-approval-e2e.json",
        import.meta.url,
      ),
    );
    mkdirSync(dirname(artifactPath), { recursive: true });
    writeFileSync(
      artifactPath,
      `${JSON.stringify({ ...summary, evidenceHash }, null, 2)}\n`,
      { mode: 0o600 },
    );
    console.info(
      `SYNTHETIC_APPROVAL_E2E_SHA256=${evidenceHash}; modelInference=false; dockerCommandRequestedByHarness=false`,
    );
  },
);
