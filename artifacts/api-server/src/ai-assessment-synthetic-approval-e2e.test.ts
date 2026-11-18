import assert from "node:assert/strict";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { createPrivateKey } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import {
  connect as connectTcp,
  createServer as createTcpServer,
  type Server as TcpServer,
} from "node:net";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import express, { type RequestHandler } from "express";
import pg from "pg";
import {
  ConsumeWorkspaceAiAssessmentApprovalReceiptResponse,
  DecideWorkspaceAiAssessmentApprovalResponse,
  ExportWorkspaceApprovalLedgerBundleResponse,
  ListWorkspaceApprovalLedgerEventsResponse,
  ListWorkspaceAiAssessmentApprovalsResponse,
  PreviewWorkspaceAiAssessmentPolicyLabResponse,
  CreateWorkspaceSyntheticRefundProposalResponse,
  CreateWorkspaceGenericActionProposalResponse,
  GetWorkspaceGenericActionCatalogResponse,
  PreviewWorkspaceGenericActionResponse,
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
import {
  signApprovalLedgerCheckpointV1,
  signApprovalReceiptV1,
  type ApprovalLedgerBundleV1,
  type SignedApprovalReceiptV1,
} from "./lib/approval-ledger-crypto";

/*
 * This is an explicitly fixture-only integration harness. It executes the
 * deterministic Python policy lab locally, without Docker, and exercises the
 * authenticated approval API, Python SDK proposal path, and RLS transaction
 * path. It is not Qwen evidence, a broker test, or a production queue consumer.
 */

const workerRoot = resolve(
  fileURLToPath(new URL("../../../workers/guardian-ai-assessment", import.meta.url)),
);
const workspaceAOwner = `synthetic-e2e-owner-${randomUUID()}`;
const workspaceAAdmin = `synthetic-e2e-admin-${randomUUID()}`;
const workspaceAAdmin2 = `synthetic-e2e-admin2-${randomUUID()}`;
const workspaceAViewer = `synthetic-e2e-viewer-${randomUUID()}`;
const workspaceBOwner = `synthetic-e2e-other-owner-${randomUUID()}`;
const workspaceBAdmin = `synthetic-e2e-other-admin-${randomUUID()}`;
const authorizedUsers = new Set([
  workspaceAOwner,
  workspaceAAdmin,
  workspaceAAdmin2,
  workspaceAViewer,
  workspaceBOwner,
  workspaceBAdmin,
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

async function startSyntheticSmtpCapture(guardCredential: string): Promise<{
  server: TcpServer;
  port: number;
  messages: string[];
}> {
  const messages: string[] = [];
  const expectedAuth = Buffer.from(
    `\0guardian-guard\0${guardCredential}`,
    "utf8",
  );
  const server = createTcpServer((socket) => {
    let buffer = "";
    let dataMode = false;
    let awaitingAuth = false;
    let authenticated = false;
    let message: string[] = [];
    socket.write("220 synthetic local capture ready\r\n");
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) break;
        const line = buffer.slice(0, newline).replace(/\r$/, "");
        buffer = buffer.slice(newline + 1);
        if (dataMode) {
          if (line === ".") {
            dataMode = false;
            messages.push(message.join("\r\n"));
            message = [];
            socket.write("250 captured in test process\r\n");
          } else {
            message.push(line.startsWith("..") ? line.slice(1) : line);
          }
          continue;
        }
        if (awaitingAuth) {
          awaitingAuth = false;
          const decoded = Buffer.from(line, "base64");
          const valid =
            decoded.toString("base64") === line &&
            decoded.length === expectedAuth.length &&
            timingSafeEqual(decoded, expectedAuth);
          if (!valid) {
            socket.write("535 invalid guard credential\r\n");
            continue;
          }
          authenticated = true;
          socket.write("235 guard authenticated\r\n");
          continue;
        }
        if (line.startsWith("EHLO ")) socket.write("250 local capture\r\n");
        else if (line === "AUTH PLAIN") {
          awaitingAuth = true;
          socket.write("334 provide guard credential\r\n");
        } else if (!authenticated) {
          socket.write("530 guard authentication required\r\n");
        } else if (line.startsWith("MAIL FROM:")) socket.write("250 sender accepted\r\n");
        else if (line.startsWith("RCPT TO:")) socket.write("250 recipient accepted\r\n");
        else if (line === "DATA") {
          dataMode = true;
          socket.write("354 end with dot\r\n");
        } else if (line === "QUIT") socket.write("221 bye\r\n");
        else socket.write("500 unsupported\r\n");
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return { server, port: address.port, messages };
}

async function attemptDirectSmtpWithoutGuardCredential(port: number): Promise<string> {
  const socket = connectTcp({ host: "127.0.0.1", port });
  let buffer = "";
  const nextLine = async (): Promise<string> => new Promise((resolveLine, reject) => {
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      const newline = buffer.indexOf("\n");
      if (newline < 0) return;
      const line = buffer.slice(0, newline).replace(/\r$/, "");
      buffer = buffer.slice(newline + 1);
      socket.off("data", onData);
      socket.off("error", onError);
      resolveLine(line);
    };
    const onError = (error: Error) => {
      socket.off("data", onData);
      reject(error);
    };
    socket.on("data", onData);
    socket.once("error", onError);
  });
  await once(socket, "connect");
  try {
    assert.match(await nextLine(), /^220\b/);
    socket.write("EHLO direct-agent.local\r\n");
    assert.match(await nextLine(), /^250\b/);
    socket.write("MAIL FROM:<agent@localhost.invalid>\r\n");
    return await nextLine();
  } finally {
    socket.end();
  }
}

function sha256(value: unknown): string {
  return createHash("sha256")
    .update(canonicalApprovalJson(value), "utf8")
    .digest("hex");
}

function verifyBundleWithOfflineCli(input: {
  bundle: unknown;
  keyId: string;
  publicKeyPem: string;
  verificationTime: string;
}): { status: number | null; stdout: string; stderr: string } {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-e2e-"));
  try {
    const bundle = input.bundle as ApprovalLedgerBundleV1;
    const head = bundle.events.at(-1);
    if (!head) {
      return { status: 1, stdout: '{"valid":false,"code":"invalid_bundle"}\n', stderr: "" };
    }
    const checkpointPair = generateKeyPairSync("ed25519");
    const checkpointKeyId = `e2e-checkpoint-${randomUUID()}`;
    const checkpoint = signApprovalLedgerCheckpointV1({
      version: 1,
      keyId: checkpointKeyId,
      workspaceId: head.event.workspaceId,
      sequence: head.event.sequence,
      headEventSha256: head.eventSha256,
      issuedAt: input.verificationTime,
    }, checkpointPair.privateKey);
    const bundlePath = resolve(directory, "bundle.json");
    const trustedKeysPath = resolve(directory, "trusted-public-keys.json");
    const checkpointPath = resolve(directory, "checkpoint.json");
    const checkpointTrustedKeysPath = resolve(
      directory,
      "checkpoint-trusted-public-keys.json",
    );
    writeFileSync(bundlePath, JSON.stringify(input.bundle), { mode: 0o600 });
    writeFileSync(
      trustedKeysPath,
      JSON.stringify({ [input.keyId]: input.publicKeyPem }),
      { mode: 0o600 },
    );
    writeFileSync(checkpointPath, JSON.stringify(checkpoint), { mode: 0o600 });
    writeFileSync(
      checkpointTrustedKeysPath,
      JSON.stringify({
        [checkpointKeyId]: checkpointPair.publicKey.export({
          format: "pem",
          type: "spki",
        }).toString(),
      }),
      { mode: 0o600 },
    );
    const cli = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "scripts/verify-approval-ledger-bundle.ts",
    );
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        cli,
        "--bundle",
        bundlePath,
        "--trusted-keys",
        trustedKeysPath,
        "--checkpoint",
        checkpointPath,
        "--checkpoint-trusted-keys",
        checkpointTrustedKeysPath,
        "--at",
        input.verificationTime,
      ],
      {
        cwd: resolve(dirname(fileURLToPath(import.meta.url)), ".."),
        encoding: "utf8",
        env: {
          PATH: process.env.PATH ?? "",
          HOME: directory,
          LANG: "C",
          LC_ALL: "C",
        },
      },
    );
    return {
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function runPythonSdkRefundProposalClient(input: {
  apiBase: string;
  workspaceId: string;
  testUser: string;
  idempotencyKey: string;
  proposalSource?: "fixture" | "qwen_provider";
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
        GUARDIAN_SDK_OPERATION: "propose_synthetic_refund",
        GUARDIAN_API_BASE_URL: input.apiBase,
        GUARDIAN_WORKSPACE_ID: input.workspaceId,
        GUARDIAN_TEST_USER: input.testUser,
        GUARDIAN_REFUND_IDEMPOTENCY_KEY: input.idempotencyKey,
        ...(input.proposalSource
          ? { GUARDIAN_PROPOSAL_SOURCE: input.proposalSource }
          : {}),
      },
    });
    let stdout = "";
    let settled = false;
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error("python_sdk_refund_proposal_timeout"));
    }, 20_000);
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
        finish(new Error("python_sdk_refund_proposal_output_limit"));
        return;
      }
      stdout += chunk;
    });
    child.on("error", () => finish(new Error("python_sdk_refund_proposal_spawn_failed")));
    child.on("close", (code) => {
      if (code !== 0) {
        finish(new Error(`python_sdk_refund_proposal_failed:exit_${code ?? "unknown"}`));
      } else {
        finish();
      }
    });
  });
}

async function withMockedQwenProvider<T>(
  apiBase: string,
  run: () => Promise<T>,
): Promise<T> {
  const syntheticKey = "synthetic-e2e-provider-key-never-valid";
  const baseUrl = "https://qwen-mock.invalid/v1";
  const endpoint = `${baseUrl}/chat/completions`;
  const savedEnvironment = {
    QWEN_PROVIDER_BASE_URL: process.env.QWEN_PROVIDER_BASE_URL,
    QWEN_PROVIDER_MODEL: process.env.QWEN_PROVIDER_MODEL,
    QWEN_PROVIDER_API_KEY: process.env.QWEN_PROVIDER_API_KEY,
  };
  const originalFetch = globalThis.fetch;
  process.env.QWEN_PROVIDER_BASE_URL = baseUrl;
  process.env.QWEN_PROVIDER_MODEL = "Qwen/Qwen3-Synthetic-Test";
  process.env.QWEN_PROVIDER_API_KEY = syntheticKey;
  globalThis.fetch = (async (input, init) => {
    const requestUrl =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    if (requestUrl === endpoint) {
      assert.equal(
        new Headers(init?.headers).get("authorization"),
        `Bearer ${syntheticKey}`,
      );
      return new Response(
        JSON.stringify({
          choices: [
            {
              message: {
                tool_calls: [
                  {
                    type: "function",
                    function: {
                      name: "propose_synthetic_refund",
                      arguments:
                        '{"ticket_id":"TICKET-SYNTH-001","amount_cents":500}',
                    },
                  },
                ],
              },
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (requestUrl.startsWith(apiBase)) return originalFetch(input, init);
    throw new Error("test-only provider network mock blocked an unexpected URL");
  }) as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
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

type RuntimeMembershipProbeOutcome = "allowed" | "denied";

async function runRuntimeMembershipProbe(input: {
  pool: pg.Pool;
  userId: string;
  workspaceId: string;
  statement: string;
  values: string[];
}): Promise<RuntimeMembershipProbeOutcome> {
  const client = await input.pool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;
    await client.query("SET LOCAL ROLE app_runtime");
    await client.query(
      `SELECT set_config('app.user_id', $1, true),
              set_config('app.workspace_id', $2, true)`,
      [input.userId, input.workspaceId],
    );
    try {
      const result = await client.query(input.statement, input.values);
      return result.rowCount === 1 ? "allowed" : "denied";
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? error.code
          : undefined;
      if (code === "42501") return "denied";
      throw new Error("runtime_membership_probe_database_error");
    }
  } finally {
    try {
      if (transactionStarted) await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  }
}

async function runWorkspaceCreatorMembershipProbe(input: {
  pool: pg.Pool;
  creatorUserId: string;
  role: "owner" | "admin";
}): Promise<RuntimeMembershipProbeOutcome> {
  const client = await input.pool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;
    await client.query("SET LOCAL ROLE app_runtime");
    await client.query(
      `SELECT set_config('app.user_id', $1, true),
              set_config('app.workspace_id', '', true)`,
      [input.creatorUserId],
    );
    try {
      const workspace = await client.query<{ id: string }>(
        `INSERT INTO public.workspaces
           (name, plan_id, created_by_user_id)
         VALUES ('Synthetic membership creator probe', 'small', $1)
         RETURNING id`,
        [input.creatorUserId],
      );
      const workspaceId = workspace.rows[0]?.id;
      if (!workspaceId) {
        throw new Error("workspace_creator_probe_workspace_missing");
      }
      await client.query(
        "SELECT set_config('app.workspace_id', $1, true)",
        [workspaceId],
      );
      const membership = await client.query(
        `INSERT INTO public.workspace_memberships
           (workspace_id, user_id, role)
         VALUES ($1, $2, $3)
         RETURNING id`,
        [workspaceId, input.creatorUserId, input.role],
      );
      return membership.rowCount === 1 ? "allowed" : "denied";
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? error.code
          : undefined;
      if (code === "42501") return "denied";
      throw new Error("workspace_creator_membership_probe_database_error");
    }
  } finally {
    try {
      if (transactionStarted) await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  }
}

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
  "deterministic approval E2E exports signed history and gates refund simulation",
  { timeout: 60_000 },
  async (t) => {
    if (
      !(await verifyExplicitDisposableApprovalDatabase(
        process.env,
        acquireGitHubActionsOidcToken,
      ))
    ) {
      if (process.env.GUARDIAN_APPROVAL_E2E_REQUIRED === "1") {
        throw new Error(
          "Required disposable approval database guard was not verified.",
        );
      }
      t.skip(
        "requires an authenticated GitHub Actions OIDC target or explicit local disposable opt-in",
      );
      return;
    }
    const ephemeralLedgerKey = generateKeyPairSync("ed25519").privateKey.export({
      format: "pem",
      type: "pkcs8",
    }).toString();
    process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY = ephemeralLedgerKey;
    const databaseUrl = process.env.DATABASE_URL;
    const runtimeDatabaseUrl = process.env.APP_RUNTIME_DATABASE_URL;
    assert.ok(databaseUrl);
    assert.ok(runtimeDatabaseUrl);
    const { assertRlsRuntimeReady, pool: appPool } =
      await import("@workspace/db");
    const { workspaceApprovalLedgerTable } = await import("@workspace/db");
    const { createAiAssessmentLabRouter } =
      await import("./routes/ai-assessment-lab");
    const { createWorkspaceGovernanceRouter } =
      await import("./routes/workspace-governance");
    const { withWorkspaceUserTransaction } =
      await import("./lib/tenant-db");
    const { updateApprovedRequestAndAppendReceipt } =
      await import("./lib/approval-ledger-service");
    await assertRlsRuntimeReady();
    const fixturePool = new pg.Pool({ connectionString: databaseUrl });
    const runtimePool = new pg.Pool({
      connectionString: runtimeDatabaseUrl,
      max: 1,
    });
    const app = express();
    app.use(express.json({ limit: "8kb" }));
    app.use("/api", createAiAssessmentLabRouter(authForTest));
    app.use("/api", createWorkspaceGovernanceRouter(authForTest));

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
        await fixturePool.query(
          "DELETE FROM public.workspace_approval_ledger WHERE workspace_id = $1",
          [workspaceA],
        );
        await fixturePool.query("DELETE FROM public.workspaces WHERE id = $1", [
          workspaceA,
        ]);
      }
      if (workspaceB) {
        await fixturePool.query(
          "DELETE FROM public.workspace_approval_ledger WHERE workspace_id = $1",
          [workspaceB],
        );
        await fixturePool.query("DELETE FROM public.workspaces WHERE id = $1", [
          workspaceB,
        ]);
      }
      await runtimePool.end();
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
              ($1, $5, 'viewer'), ($6, $7, 'owner'), ($6, $8, 'admin')`,
      [
        workspaceA,
        workspaceAOwner,
        workspaceAAdmin,
        workspaceAAdmin2,
        workspaceAViewer,
        workspaceB,
        workspaceBOwner,
        workspaceBAdmin,
      ],
    );

    const membershipProbeResults: Record<
      string,
      RuntimeMembershipProbeOutcome
    > = {};
    membershipProbeResults.selfPromotionUpdate =
      await runRuntimeMembershipProbe({
        pool: runtimePool,
        userId: workspaceAViewer,
        workspaceId: workspaceA,
        statement: `UPDATE public.workspace_memberships
                    SET role = 'owner'
                    WHERE workspace_id = $1
                      AND user_id = $2
                      AND role = 'viewer'
                    RETURNING id`,
        values: [workspaceA, workspaceAViewer],
      });
    membershipProbeResults.ownerMembershipInsert =
      await runRuntimeMembershipProbe({
        pool: runtimePool,
        userId: workspaceAViewer,
        workspaceId: workspaceB,
        statement: `INSERT INTO public.workspace_memberships
                      (workspace_id, user_id, role)
                    VALUES ($1, $2, 'owner')
                    RETURNING id`,
        values: [workspaceB, workspaceAViewer],
      });
    membershipProbeResults.adminMembershipInsert =
      await runWorkspaceCreatorMembershipProbe({
        pool: runtimePool,
        creatorUserId: workspaceAAdmin,
        role: "admin",
      });
    membershipProbeResults.creatorOwnerMembershipInsert =
      await runWorkspaceCreatorMembershipProbe({
        pool: runtimePool,
        creatorUserId: workspaceAAdmin,
        role: "owner",
      });
    membershipProbeResults.ownerRoleChange =
      await runRuntimeMembershipProbe({
        pool: runtimePool,
        userId: workspaceAOwner,
        workspaceId: workspaceA,
        statement: `UPDATE public.workspace_memberships
                    SET role = 'analyst'
                    WHERE workspace_id = $1
                      AND user_id = $2
                      AND role = 'viewer'
                    RETURNING id`,
        values: [workspaceA, workspaceAViewer],
      });
    for (const role of ["viewer", "analyst"] as const) {
      const roleLabel = role === "viewer" ? "Viewer" : "Analyst";
      membershipProbeResults[`crossWorkspace${roleLabel}Insert`] =
        await runRuntimeMembershipProbe({
          pool: runtimePool,
          userId: workspaceAViewer,
          workspaceId: workspaceB,
          statement: `INSERT INTO public.workspace_memberships
                        (workspace_id, user_id, role)
                      VALUES ($1, $2, $3)
                      RETURNING id`,
          values: [workspaceB, workspaceAViewer, role],
        });
    }
    const membershipProbePath = fileURLToPath(
      new URL(
        "../../../generated-artifacts/guardian-membership-role-probes.json",
        import.meta.url,
      ),
    );
    mkdirSync(dirname(membershipProbePath), { recursive: true });
    writeFileSync(
      membershipProbePath,
      `${JSON.stringify(
        {
          source: "app_runtime_disposable_database_probe",
          ...membershipProbeResults,
          eachMutationRolledBack: true,
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );
    const membershipProbeAssertions = Object.fromEntries(
      Object.entries(membershipProbeResults).filter(
        ([probeName]) =>
          probeName !== "crossWorkspaceViewerInsert" &&
          probeName !== "crossWorkspaceAnalystInsert",
      ),
    );
    assert.deepEqual(
      membershipProbeAssertions,
      {
        selfPromotionUpdate: "denied",
        ownerMembershipInsert: "denied",
        adminMembershipInsert: "denied",
        creatorOwnerMembershipInsert: "allowed",
        ownerRoleChange: "allowed",
      },
      "app_runtime must not allow member role escalation through direct database mutations",
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
      extraHeaders: Record<string, string> = {},
    ) =>
      fetch(`${apiBase}${path}`, {
        method,
        headers: {
          ...(userId ? { "x-guardian-test-user": userId } : {}),
          ...(body ? { "content-type": "application/json" } : {}),
          ...extraHeaders,
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    const approvalPath = `/api/workspaces/${workspaceA}/ai-security-assessments/approvals`;
    const expireFuture = () => new Date(Date.now() + 60 * 60 * 1000);
    const queuePath = `/api/workspaces/${workspaceA}/ai-security-assessments/lab/jobs`;
    const previewPath = `/api/workspaces/${workspaceA}/ai-security-assessments/lab/policy-preview`;
    let agentApprovalReceipt: SignedApprovalReceiptV1 | null = null;
    await t.test("saved rules are admin-managed, versioned, simulated and default-deny", async () => {
      const supportAction = "guardian.support.reply.send.v1";
      const rulePath =
        `/api/workspaces/${workspaceA}/action-rules/${supportAction}`;
      const supportArgs = {
        ticket_id: "TICKET-SYNTH-42",
        recipient_email: "demo@example.test",
        recipient_type: "internal",
        compensation_cents: 0,
        template_id: "synthetic-support-reply-v1",
      };
      const unconfigured = await request(
        workspaceAAdmin,
        `/api/workspaces/${workspaceA}/ai-security-assessments/action-proposals`,
        "POST",
        {
          actionType: supportAction,
          arguments: supportArgs,
          idempotencyKey: randomUUID(),
        },
      );
      assert.equal(unconfigured.status, 200);
      const defaultDeny = await unconfigured.json() as {
        decision: string;
        reasonCode: string;
        ruleVersionId: string | null;
        approval: unknown;
      };
      assert.equal(defaultDeny.decision, "deny");
      assert.equal(defaultDeny.reasonCode, "workspace_rule_not_configured");
      assert.equal(defaultDeny.ruleVersionId, null);
      assert.equal(defaultDeny.approval, null);

      const firstDocument = {
        version: 1,
        rules: [{
          id: "review-support-v1",
          decision: "require_approval",
          when: {},
        }],
      };
      assert.equal(
        (await request(workspaceAViewer, `${rulePath}/draft`, "PUT", firstDocument)).status,
        403,
        "viewers cannot save rule drafts",
      );
      const firstDraft = await request(
        workspaceAAdmin,
        `${rulePath}/draft`,
        "PUT",
        firstDocument,
      );
      assert.equal(firstDraft.status, 201);
      const firstVersion = await firstDraft.json() as { version: number };
      assert.equal(firstVersion.version, 1);
      const firstActivation = await request(
        workspaceAAdmin,
        `${rulePath}/activate`,
        "POST",
      );
      assert.equal(firstActivation.status, 200);

      const secondDraft = await request(
        workspaceAAdmin,
        `${rulePath}/draft`,
        "PUT",
        {
          version: 1,
          rules: [{
            id: "block-support-v2",
            decision: "deny",
            when: {},
          }],
        },
      );
      assert.equal(secondDraft.status, 201);
      const secondVersion = await secondDraft.json() as {
        version: number;
        versionId: string;
      };
      assert.equal(secondVersion.version, 2);
      const simulatedDraft = await request(
        workspaceAAdmin,
        `${rulePath}/simulate`,
        "POST",
        { versionId: secondVersion.versionId, arguments: supportArgs },
      );
      assert.equal(simulatedDraft.status, 200);
      const simulatedDraftData = await simulatedDraft.json() as {
        decision: string;
        ruleVersionId: string | null;
        persisted: boolean;
        dispatched: boolean;
      };
      assert.equal(simulatedDraftData.decision, "deny");
      assert.equal(simulatedDraftData.ruleVersionId, secondVersion.versionId);
      assert.equal(simulatedDraftData.persisted, false);
      assert.equal(simulatedDraftData.dispatched, false);
      assert.equal(
        (await request(workspaceAAdmin, `${rulePath}/activate`, "POST")).status,
        200,
      );
      const rollbackResponse = await request(
        workspaceAAdmin,
        `${rulePath}/rollback`,
        "POST",
        { version: 1 },
      );
      assert.equal(rollbackResponse.status, 201);
      const rollbackData = await rollbackResponse.json() as {
        version: number;
        versionId: string;
        active: boolean;
      };
      assert.equal(rollbackData.version, 3);
      assert.equal(rollbackData.active, false);
      const finalRules = await request(
        workspaceAAdmin,
        `/api/workspaces/${workspaceA}/action-rules`,
      );
      const finalRulesData = await finalRules.json() as {
        starterTemplates: Array<{
          id: string;
          actionType: string;
          document: { version: number; rules: unknown[] };
        }>;
        actions: Array<{
          actionType: string;
          activeVersionId: string | null;
          draftVersionId: string | null;
          history: Array<{ version: number }>;
        }>;
      };
      const finalSupportState = finalRulesData.actions.find(
        (action) => action.actionType === supportAction,
      );
      assert.equal(finalSupportState?.activeVersionId, secondVersion.versionId);
      assert.equal(finalSupportState?.draftVersionId, rollbackData.versionId);
      assert.deepEqual(
        finalSupportState?.history.map((version) => version.version).sort(),
        [1, 2, 3],
      );
      assert.equal(finalRulesData.starterTemplates.length, 4);
      assert.equal(
        finalRulesData.starterTemplates.find(
          (template) => template.actionType === supportAction,
        )?.id,
        "customer-support-v1",
      );
      const ruleAudit = await fixturePool.query<{ action: string }>(
        `SELECT action FROM public.workspace_audit_events
          WHERE workspace_id = $1
            AND resource_type = 'workspace_action_rule_version'`,
        [workspaceA],
      );
      assert.equal(
        ruleAudit.rows.length,
        6,
        "drafts, activations and rollback are recorded in the workspace audit history",
      );
      const simulatedActive = await request(
        workspaceAAdmin,
        `${rulePath}/simulate`,
        "POST",
        { arguments: supportArgs },
      );
      const simulatedActiveData = await simulatedActive.json() as {
        decision: string;
        ruleVersionId: string | null;
      };
      assert.equal(simulatedActiveData.decision, "deny");
      assert.equal(simulatedActiveData.ruleVersionId, secondVersion.versionId);
    });
    await t.test("starter profiles create bounded drafts and the server simulator uses their versions", async () => {
      const rulesPath = `/api/workspaces/${workspaceA}/action-rules`;
      const profilePath = (profileId: string) =>
        `/api/workspaces/${workspaceA}/action-rules/profiles/${profileId}/draft`;
      const listedBefore = await request(workspaceAViewer, rulesPath);
      assert.equal(listedBefore.status, 200);
      const beforeData = await listedBefore.json() as {
        ruleProfiles: Array<{ id: string; label: string; defaultRefundLimitCents: number }>;
        actions: Array<{ actionType: string; activeVersionId: string | null }>;
      };
      assert.deepEqual(
        beforeData.ruleProfiles.map(({ id, label, defaultRefundLimitCents }) => ({
          id,
          label,
          defaultRefundLimitCents,
        })),
        [
          { id: "prudent-v1", label: "Prudente", defaultRefundLimitCents: 5000 },
          { id: "balanced-v1", label: "Equilibrada", defaultRefundLimitCents: 5000 },
          { id: "read-only-v1", label: "Solo lectura", defaultRefundLimitCents: 5000 },
        ],
      );
      assert.equal(
        (await request(workspaceAViewer, profilePath("balanced-v1"), "POST", {
          refundLimitCents: 6500,
        })).status,
        403,
        "viewers can read rules but cannot create profile drafts",
      );
      assert.equal(
        (await request(workspaceAOwner, profilePath("balanced-v1"), "POST", {
          refundLimitCents: 0,
        })).status,
        400,
        "zero is not a valid refund threshold",
      );
      assert.equal(
        (await request(workspaceAOwner, profilePath("balanced-v1"), "POST", {
          refundLimitCents: 1_000_001,
        })).status,
        400,
        "the server rejects thresholds above 10,000 euros",
      );

      const createdResponse = await request(
        workspaceAOwner,
        profilePath("balanced-v1"),
        "POST",
        { refundLimitCents: 6500 },
      );
      assert.equal(createdResponse.status, 201);
      const createdProfile = await createdResponse.json() as {
        profileId: string;
        refundLimitCents: number;
        versions: Array<{
          actionType: string;
          versionId: string;
          version: number;
          active: boolean;
        }>;
      };
      assert.equal(createdProfile.profileId, "balanced-v1");
      assert.equal(createdProfile.refundLimitCents, 6500);
      assert.equal(createdProfile.versions.length, 4);
      assert.ok(createdProfile.versions.every((version) => version.active === false));

      const refundAction = "guardian.synthetic.support.refund.v1";
      const refundVersion = createdProfile.versions.find(
        (version) => version.actionType === refundAction,
      );
      assert.ok(refundVersion);
      const refundPath = `${rulesPath}/${refundAction}`;
      const simulateRefund = (amountCents: number) =>
        request(workspaceAViewer, `${refundPath}/simulate`, "POST", {
          versionId: refundVersion.versionId,
          arguments: {
            ticket_id: "TICKET-SYNTH-RULE-PROFILE",
            amount_cents: amountCents,
          },
        });
      const atLimit = await simulateRefund(6500);
      const atLimitResult = await atLimit.json() as {
        decision: string;
        ruleId: string | null;
        ruleVersionId: string | null;
        persisted: boolean;
        dispatched: boolean;
      };
      assert.equal(atLimitResult.decision, "allow");
      assert.equal(atLimitResult.ruleId, "refund-within-threshold");
      assert.equal(atLimitResult.ruleVersionId, refundVersion.versionId);
      assert.equal(atLimitResult.persisted, false);
      assert.equal(atLimitResult.dispatched, false);
      const overLimit = await simulateRefund(6501);
      const overLimitResult = await overLimit.json() as {
        decision: string;
        ruleId: string | null;
        ruleVersionId: string | null;
      };
      assert.equal(overLimitResult.decision, "require_approval");
      assert.equal(overLimitResult.ruleId, "refund-above-threshold");
      assert.equal(overLimitResult.ruleVersionId, refundVersion.versionId);

      const changedResponse = await request(
        workspaceAAdmin,
        profilePath("balanced-v1"),
        "POST",
        { refundLimitCents: 7500 },
      );
      assert.equal(changedResponse.status, 201);
      const changedProfile = await changedResponse.json() as {
        versions: Array<{
          actionType: string;
          versionId: string;
          version: number;
          active: boolean;
        }>;
      };
      const changedRefundVersion = changedProfile.versions.find(
        (version) => version.actionType === refundAction,
      );
      assert.ok(changedRefundVersion);
      assert.equal(changedRefundVersion.version, refundVersion.version + 1);
      assert.equal(changedRefundVersion.active, false);

      const listedAfter = await request(workspaceAAdmin, rulesPath);
      const afterData = await listedAfter.json() as {
        actions: Array<{
          actionType: string;
          activeVersionId: string | null;
          draftVersionId: string | null;
          history: Array<{
            rules: Array<{
              when: {
                all?: Array<{ field: string; value: string | number | boolean }>;
              };
            }>;
          }>;
        }>;
      };
      const refundState = afterData.actions.find(
        (action) => action.actionType === refundAction,
      );
      assert.ok(refundState);
      assert.equal(
        refundState.activeVersionId,
        beforeData.actions.find((action) => action.actionType === refundAction)
          ?.activeVersionId ?? null,
        "choosing a profile never activates its draft",
      );
      assert.equal(refundState.draftVersionId, changedRefundVersion.versionId);
      const savedThresholds = refundState.history.flatMap((version) =>
        version.rules.flatMap((rule) =>
          (rule.when.all ?? [])
            .filter((condition) => condition.field === "amount_cents")
            .map((condition) => condition.value),
        ),
      );
      assert.ok(savedThresholds.includes(6500));
      assert.ok(savedThresholds.includes(7500));

      const openRuleDraft = await request(
        workspaceAAdmin,
        `${rulesPath}/guardian.email.send.external.v1/draft`,
        "PUT",
        {
          version: 1,
          rules: [{ id: "unbounded-email-allow", decision: "allow", when: {} }],
        },
      );
      assert.equal(openRuleDraft.status, 201);
      const listedOpenRules = await request(workspaceAAdmin, rulesPath);
      const openRules = await listedOpenRules.json() as {
        actions: Array<{ actionType: string; openRuleIds: string[] }>;
      };
      assert.ok(
        openRules.actions.find(
          (action) => action.actionType === "guardian.email.send.external.v1",
        )?.openRuleIds.includes("unbounded-email-allow"),
        "the server identifies an unconditional external-email allow as open",
      );
    });
    await t.test("agent credentials are scoped, revocable, renewable and cannot self-approve", async () => {
      const agentsPath = `/api/workspaces/${workspaceA}/agents`;
      const supportRulePath =
        `/api/workspaces/${workspaceA}/action-rules/guardian.support.reply.send.v1`;
      const approvalRuleDraft = await request(
        workspaceAAdmin,
        `${supportRulePath}/draft`,
        "PUT",
        {
          version: 1,
          rules: [{
            id: "agent-proposal-requires-human-review",
            decision: "require_approval",
            when: {},
          }],
        },
      );
      assert.equal(
        approvalRuleDraft.status,
        201,
        "the agent test creates its own approval policy rather than relying on prior subtests",
      );
      const approvalRuleActivation = await request(
        workspaceAAdmin,
        `${supportRulePath}/activate`,
        "POST",
      );
      assert.equal(
        approvalRuleActivation.status,
        200,
        "the agent test activates the explicit human-review policy",
      );
      const viewerAgentCreate = await request(
        workspaceAViewer,
        agentsPath,
        "POST",
        { displayName: "Viewer must not register an agent" },
      );
      assert.equal(
        viewerAgentCreate.status,
        403,
        "only a workspace owner or administrator can register an agent",
      );
      assert.equal(
        (await viewerAgentCreate.text()).includes("gnx_agent_v1_"),
        false,
        "authorization errors never include a credential",
      );
      const createdResponse = await request(
        workspaceAAdmin,
        agentsPath,
        "POST",
        { displayName: "Synthetic API agent" },
      );
      assert.equal(createdResponse.status, 201);
      const created = await createdResponse.json() as {
        agent: { id: string; credentialVersion: number };
        credential: string;
        shownOnce: boolean;
      };
      assert.ok(
        typeof created.credential === "string" &&
          created.credential.startsWith("gnx_agent_v1_"),
        "the credential is returned only by the registration response",
      );
      assert.equal(created.shownOnce, true);
      assert.equal(created.agent.credentialVersion, 1);

      const stored = await fixturePool.query<{ credential_sha256: string }>(
        `SELECT credential_sha256 FROM public.workspace_agents
          WHERE workspace_id = $1 AND id = $2`,
        [workspaceA, created.agent.id],
      );
      const expectedCredentialHash = createHash("sha256")
        .update(created.credential, "utf8")
        .digest("hex");
      assert.ok(
        stored.rows[0]?.credential_sha256 === expectedCredentialHash,
        "only the SHA-256 digest is stored",
      );
      assert.ok(
        !stored.rows.some((row) => row.credential_sha256 === created.credential),
        "the raw credential is not stored",
      );
      const listedAgentsResponse = await request(workspaceAAdmin, agentsPath);
      assert.equal(listedAgentsResponse.status, 200);
      const listedAgentsText = await listedAgentsResponse.text();
      assert.equal(
        listedAgentsText.includes(created.credential),
        false,
        "the agent list never returns a credential",
      );
      assert.equal(
        listedAgentsText.includes(stored.rows[0]?.credential_sha256 ?? ""),
        false,
        "the agent list never returns the stored digest",
      );
      assert.equal(
        (await request(
          null,
          agentsPath,
          "GET",
          undefined,
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "an agent credential cannot use the people-authenticated agent registry",
      );
      assert.equal(
        (await request(
          null,
          `${agentsPath}/${created.agent.id}/rotate`,
          "POST",
          undefined,
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "an agent credential cannot rotate credentials",
      );
      assert.equal(
        (await request(
          null,
          agentsPath,
          "POST",
          { displayName: "Agent cannot create another agent" },
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "an agent credential cannot create or register agents",
      );
      assert.equal(
        (await request(
          null,
          `${agentsPath}/${created.agent.id}/revoke`,
          "POST",
          undefined,
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "an agent credential cannot revoke or manage agents",
      );
      assert.equal(
        (await request(
          null,
          `/api/workspaces/${workspaceA}/action-rules/guardian.email.send.external.v1/draft`,
          "PUT",
          { rules: [] },
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "an agent credential cannot use human rule-management endpoints",
      );
      assert.equal(
        (await request(
          null,
          `/api/workspaces/${workspaceA}/action-rules`,
          "GET",
          undefined,
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "an agent credential cannot read through person-only rule routes",
      );
      assert.equal(
        (await request(
          null,
          `/api/workspaces/${workspaceA}/members`,
          "GET",
          undefined,
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "agent credentials cannot access workspace people endpoints",
      );

      const agentProposalPath = `/api/agent/workspaces/${workspaceA}/action-proposals`;
      const proposalBody = {
        actionType: "guardian.support.reply.send.v1",
        arguments: {
          ticket_id: "TICKET-SYNTH-AGENT-1",
          recipient_email: "demo@example.test",
          recipient_type: "internal",
          compensation_cents: 0,
          template_id: "synthetic-support-reply-v1",
        },
        idempotencyKey: randomUUID(),
      };
      const wrongCredential = `gnx_agent_v1_${randomBytes(32).toString("base64url")}`;
      assert.equal(
        (await request(
          null,
          agentProposalPath,
          "POST",
          proposalBody,
          { authorization: `Bearer ${wrongCredential}` },
        )).status,
        401,
        "an unregistered credential is rejected",
      );
      const malformedCredentialResponse = await request(
        null,
        agentProposalPath,
        "POST",
        { ...proposalBody, idempotencyKey: randomUUID() },
        { authorization: "Bearer malformed" },
      );
      assert.equal(malformedCredentialResponse.status, 401);
      const malformedCredentialText = await malformedCredentialResponse.text();
      assert.equal(
        malformedCredentialText,
        '{"error":"Agent authentication failed"}',
        "invalid token formats use the same non-enumerating error",
      );
      assert.equal(
        (await request(
          null,
          `/api/agent/workspaces/${workspaceB}/action-proposals`,
          "POST",
          { ...proposalBody, idempotencyKey: randomUUID() },
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "an agent credential cannot be used in another workspace",
      );
      for (let attempt = 0; attempt < 7; attempt += 1) {
        const limitedAttempt = await request(
          null,
          `/api/agent/workspaces/${workspaceB}/action-proposals`,
          "POST",
          { ...proposalBody, idempotencyKey: randomUUID() },
          { authorization: "Bearer invalid-agent-token" },
        );
        assert.equal(
          limitedAttempt.status,
          401,
          "failed agent authentication attempts remain non-enumerating below the limit",
        );
      }
      const rateLimitedAttempt = await request(
        null,
        `/api/agent/workspaces/${workspaceB}/action-proposals`,
        "POST",
        { ...proposalBody, idempotencyKey: randomUUID() },
        { authorization: "Bearer invalid-agent-token" },
      );
      assert.equal(rateLimitedAttempt.status, 429);
      assert.ok(rateLimitedAttempt.headers.get("retry-after"));
      assert.equal(
        (await rateLimitedAttempt.text()).includes("invalid-agent-token"),
        false,
        "rate limit errors do not echo credentials",
      );

      const proposalResponse = await request(
        null,
        agentProposalPath,
        "POST",
        proposalBody,
        { authorization: `Bearer ${created.credential}` },
      );
      assert.equal(proposalResponse.status, 201);
      const proposalText = await proposalResponse.text();
      assert.equal(
        proposalText.includes(created.credential),
        false,
        "proposal responses never echo the bearer credential",
      );
      const proposal = CreateWorkspaceGenericActionProposalResponse.parse(
        JSON.parse(proposalText),
      );
      assert.equal(proposal.decision, "require_approval");
      assert.equal(proposal.approval?.proposalDetails?.agentId, created.agent.id);
      assert.ok(proposal.approval?.proposalDetails?.ruleVersionId);
      const afterProposalAgents = await request(workspaceAAdmin, agentsPath);
      const afterProposalAgentData = await afterProposalAgents.json() as {
        agents: Array<{ id: string; lastUsedAt: string | null }>;
      };
      assert.ok(
        afterProposalAgentData.agents.find((agent) => agent.id === created.agent.id)
          ?.lastUsedAt,
        "a successful proposal updates the agent's last activity",
      );
      assert.equal(
        (await request(
          workspaceAAdmin,
          `/api/workspaces/${workspaceA}/ai-security-assessments/approvals/${proposal.approval!.id}/decision`,
          "POST",
          {
            decision: "approve",
            proposalBindingSha256: proposal.approval!.proposalBindingSha256,
          },
        )).status,
        403,
        "the agent principal cannot approve its own proposal",
      );
      const agentCredentialSelfApproval = await request(
        null,
        `/api/workspaces/${workspaceA}/ai-security-assessments/approvals/${proposal.approval!.id}/decision`,
        "POST",
        {
          decision: "approve",
          proposalBindingSha256: proposal.approval!.proposalBindingSha256,
        },
        { authorization: `Bearer ${created.credential}` },
      );
      assert.equal(
        agentCredentialSelfApproval.status,
        401,
        "an agent bearer credential cannot use the human approval endpoint",
      );
      const secondAgentResponse = await request(
        workspaceAAdmin,
        agentsPath,
        "POST",
        { displayName: "Second synthetic agent" },
      );
      assert.equal(secondAgentResponse.status, 201);
      const secondAgent = await secondAgentResponse.json() as {
        agent: { id: string };
        credential: string;
      };
      const otherAgentApprovalAttempt = await request(
        null,
        `/api/workspaces/${workspaceA}/ai-security-assessments/approvals/${proposal.approval!.id}/decision`,
        "POST",
        {
          decision: "approve",
          proposalBindingSha256: proposal.approval!.proposalBindingSha256,
        },
        { authorization: `Bearer ${secondAgent.credential}` },
      );
      assert.equal(
        otherAgentApprovalAttempt.status,
        401,
        "a different agent cannot approve another agent's proposal",
      );
      const agentRejectAttempt = await request(
        null,
        `/api/workspaces/${workspaceA}/ai-security-assessments/approvals/${proposal.approval!.id}/decision`,
        "POST",
        {
          decision: "deny",
          proposalBindingSha256: proposal.approval!.proposalBindingSha256,
        },
        { authorization: `Bearer ${created.credential}` },
      );
      assert.equal(
        agentRejectAttempt.status,
        401,
        "agent credentials cannot reject proposals either",
      );
      assert.equal(
        (await otherAgentApprovalAttempt.text()).includes(secondAgent.credential),
        false,
        "human endpoint errors never echo another agent's credential",
      );
      const agentApprovalResponse = await request(
        workspaceAAdmin2,
        `/api/workspaces/${workspaceA}/ai-security-assessments/approvals/${proposal.approval!.id}/decision`,
        "POST",
        {
          decision: "approve",
          proposalBindingSha256: proposal.approval!.proposalBindingSha256,
        },
      );
      assert.equal(
        agentApprovalResponse.status,
        200,
        "a different workspace administrator can approve",
      );
      const agentDecision = DecideWorkspaceAiAssessmentApprovalResponse.parse(
        await agentApprovalResponse.json(),
      );
      assert.ok(agentDecision.receipt);
      agentApprovalReceipt = agentDecision.receipt;
      const agentApprovalLedger = await fixturePool.query<{
        approval_id: string;
        payload_canonical: string;
        result: Record<string, unknown>;
      }>(
        `SELECT ledger.approval_id, ledger.payload_canonical, job.result
           FROM public.workspace_approval_ledger AS ledger
           JOIN public.ai_assessment_approval_requests AS approval
             ON approval.id::text = ledger.approval_id
           JOIN public.ai_assessment_jobs AS job
             ON job.id = approval.job_id
          WHERE ledger.workspace_id = $1
            AND ledger.approval_id = $2
            AND ledger.event_type = 'approval.approved'`,
        [workspaceA, proposal.approval!.id],
      );
      assert.equal(agentApprovalLedger.rowCount, 1);
      assert.equal(
        agentApprovalLedger.rows[0]?.approval_id,
        proposal.approval!.id,
        "the v1 ledger event points to the approval that carries agent attribution",
      );
      assert.equal(
        (agentApprovalLedger.rows[0]?.result as { agentId?: string } | undefined)
          ?.agentId,
        created.agent.id,
        "the approved job evidence preserves the registered agent identity",
      );
      assert.equal(
        JSON.stringify(agentApprovalLedger.rows).includes(created.credential),
        false,
        "ledger history never contains the raw agent credential",
      );
      assert.equal(
        JSON.stringify(agentApprovalLedger.rows).includes(
          stored.rows[0]?.credential_sha256 ?? "",
        ),
        false,
        "ledger history never contains the credential digest",
      );

      const rotatedResponse = await request(
        workspaceAAdmin,
        `${agentsPath}/${created.agent.id}/rotate`,
        "POST",
      );
      assert.equal(rotatedResponse.status, 200);
      const rotated = await rotatedResponse.json() as {
        agent: { credentialVersion: number };
        credential: string;
        shownOnce: boolean;
      };
      assert.equal(rotated.agent.credentialVersion, 2);
      assert.equal(rotated.shownOnce, true);
      assert.equal(
        (await request(
          null,
          agentProposalPath,
          "POST",
          { ...proposalBody, idempotencyKey: randomUUID() },
          { authorization: `Bearer ${created.credential}` },
        )).status,
        401,
        "rotation invalidates the prior credential",
      );
      const oldCredentialAfterRotation = await request(
        null,
        agentProposalPath,
        "POST",
        { ...proposalBody, idempotencyKey: randomUUID() },
        { authorization: `Bearer ${created.credential}` },
      );
      assert.equal(
        (await oldCredentialAfterRotation.text()).includes(created.credential),
        false,
        "authentication errors do not echo a retired credential",
      );
      const rotatedProposalResponse = await request(
        null,
        agentProposalPath,
        "POST",
        { ...proposalBody, idempotencyKey: randomUUID() },
        { authorization: `Bearer ${rotated.credential}` },
      );
      assert.equal(
        rotatedProposalResponse.status,
        201,
        "the replacement credential is usable",
      );
      const rotatedProposal =
        CreateWorkspaceGenericActionProposalResponse.parse(
          await rotatedProposalResponse.json(),
        );
      assert.equal(rotatedProposal.decision, "require_approval");
      assert.ok(rotatedProposal.approval);
      assert.equal(
        (await request(
          workspaceAAdmin2,
          `/api/workspaces/${workspaceA}/ai-security-assessments/approvals/${rotatedProposal.approval!.id}/decision`,
          "POST",
          {
            decision: "deny",
            proposalBindingSha256:
              rotatedProposal.approval!.proposalBindingSha256,
          },
        )).status,
        200,
        "the replacement-credential proposal is resolved before the next scenario",
      );
      assert.equal(
        (await request(
          workspaceAAdmin,
          `${agentsPath}/${created.agent.id}/revoke`,
          "POST",
        )).status,
        200,
      );
      assert.equal(
        (await request(
          null,
          agentProposalPath,
          "POST",
          { ...proposalBody, idempotencyKey: randomUUID() },
          { authorization: `Bearer ${rotated.credential}` },
        )).status,
        401,
        "revocation blocks the current credential",
      );
      const renewedResponse = await request(
        workspaceAAdmin,
        `${agentsPath}/${created.agent.id}/rotate`,
        "POST",
      );
      assert.equal(renewedResponse.status, 200);
      const renewed = await renewedResponse.json() as {
        agent: { credentialVersion: number; revokedAt: string | null };
        credential: string;
        shownOnce: boolean;
      };
      assert.equal(renewed.agent.credentialVersion, 3);
      assert.equal(renewed.agent.revokedAt, null);
      assert.equal(renewed.shownOnce, true);
      const finalAgentList = await request(workspaceAAdmin, agentsPath);
      const finalAgentListText = await finalAgentList.text();
      assert.equal(finalAgentListText.includes(renewed.credential), false);
      assert.equal(finalAgentListText.includes(rotated.credential), false);
      const agentLifecycleAudit = await fixturePool.query<{
        action: string;
        metadata: Record<string, unknown>;
      }>(
        `SELECT action, metadata
           FROM public.workspace_audit_events
          WHERE workspace_id = $1
            AND resource_type = 'workspace_agent'
            AND resource_id = $2
          ORDER BY created_at`,
        [workspaceA, created.agent.id],
      );
      assert.deepEqual(
        agentLifecycleAudit.rows.map((event) => event.action),
        [
          "workspace.agent.created",
          "workspace.agent.credential_rotated",
          "workspace.agent.revoked",
          "workspace.agent.credential_rotated",
        ],
        "create, immediate rotation, revocation and reactivation are auditable",
      );
      const lifecycleText = JSON.stringify(agentLifecycleAudit.rows);
      for (const credential of [
        created.credential,
        rotated.credential,
        renewed.credential,
      ]) {
        assert.equal(
          lifecycleText.includes(credential),
          false,
          "agent credential values never enter audit metadata",
        );
      }
      for (const credentialHash of [
        stored.rows[0]!.credential_sha256,
        createHash("sha256").update(rotated.credential).digest("hex"),
        createHash("sha256").update(renewed.credential).digest("hex"),
      ]) {
        assert.equal(
          lifecycleText.includes(credentialHash),
          false,
          "audit events contain neither raw credentials nor credential digests",
        );
      }
    });
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
    ] as const;

    const approvals: Array<{
      jobId: string;
      approvalId: string;
      binding: string;
      profileId: string;
      caseId: string;
      idempotencyKey: string;
      expectedResult: string;
      modelInference?: boolean;
      executionMode?: string;
      toolCallOrigin?: string;
    }> = [];
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

    const refundPath =
      `/api/workspaces/${workspaceA}/ai-security-assessments/synthetic-refund-proposals`;
    const qwenProviderStatusPath =
      `/api/workspaces/${workspaceA}/ai-security-assessments/qwen-provider/status`;
    const savedQwenProviderEnvironment = {
      QWEN_PROVIDER_BASE_URL: process.env.QWEN_PROVIDER_BASE_URL,
      QWEN_PROVIDER_MODEL: process.env.QWEN_PROVIDER_MODEL,
      QWEN_PROVIDER_API_KEY: process.env.QWEN_PROVIDER_API_KEY,
    };
    delete process.env.QWEN_PROVIDER_BASE_URL;
    delete process.env.QWEN_PROVIDER_MODEL;
    delete process.env.QWEN_PROVIDER_API_KEY;
    try {
      const status = await request(workspaceAOwner, qwenProviderStatusPath);
      assert.equal(status.status, 200);
      assert.deepEqual(await status.json(), {
        status: "not_configured",
        provider: "openai_compatible_qwen",
        modelId: null,
        missing: ["base_url", "model", "api_key"],
      });
    } finally {
      if (savedQwenProviderEnvironment.QWEN_PROVIDER_BASE_URL !== undefined) {
        process.env.QWEN_PROVIDER_BASE_URL =
          savedQwenProviderEnvironment.QWEN_PROVIDER_BASE_URL;
      }
      if (savedQwenProviderEnvironment.QWEN_PROVIDER_MODEL !== undefined) {
        process.env.QWEN_PROVIDER_MODEL =
          savedQwenProviderEnvironment.QWEN_PROVIDER_MODEL;
      }
      if (savedQwenProviderEnvironment.QWEN_PROVIDER_API_KEY !== undefined) {
        process.env.QWEN_PROVIDER_API_KEY =
          savedQwenProviderEnvironment.QWEN_PROVIDER_API_KEY;
      }
    }
    assert.equal(
      (await request(null, refundPath, "POST", {
        scenarioId: "guardian.synthetic.support.refund.v1",
        idempotencyKey: `synthetic-refund-${randomUUID()}`,
      })).status,
      401,
      "refund proposal requires authentication",
    );
    assert.equal(
      (await request(workspaceBOwner, refundPath, "POST", {
        scenarioId: "guardian.synthetic.support.refund.v1",
        idempotencyKey: `synthetic-refund-${randomUUID()}`,
      })).status,
      403,
      "refund proposal is tenant-scoped",
    );
    assert.equal(
      (await request(workspaceAViewer, refundPath, "POST", {
        scenarioId: "guardian.synthetic.support.refund.v1",
        idempotencyKey: `synthetic-refund-${randomUUID()}`,
      })).status,
      403,
      "viewer cannot request a refund proposal",
    );
    assert.equal(
      (await request(workspaceAOwner, refundPath, "POST", {
        scenarioId: "guardian.synthetic.support.refund.v1",
        idempotencyKey: `synthetic-refund-${randomUUID()}`,
        tool: "untrusted_tool",
      })).status,
      400,
      "client cannot provide tools or action arguments",
    );
    const refundIdempotencyKey = `synthetic-refund-${randomUUID()}`;
    const refundProposalResponse = JSON.parse(
      await withMockedQwenProvider(apiBase, () =>
        runPythonSdkRefundProposalClient({
          apiBase,
          workspaceId: workspaceA,
          testUser: workspaceAOwner,
          idempotencyKey: refundIdempotencyKey,
          proposalSource: "qwen_provider",
        }),
      ),
    ) as {
      approvalId: string;
      jobId: string;
      proposalBindingSha256: string;
      modelInference: boolean;
      executionMode: string;
      toolCallOrigin: string;
      providerInferenceStatus: string;
      providerModelId: string;
      idempotentReplay: boolean;
    };
    assert.match(
      refundProposalResponse.approvalId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    assert.match(
      refundProposalResponse.jobId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    assert.match(refundProposalResponse.proposalBindingSha256, /^[a-f0-9]{64}$/);
    assert.equal(refundProposalResponse.modelInference, true);
    assert.equal(
      refundProposalResponse.executionMode,
      "real_openai_compatible_qwen_inference",
    );
    assert.equal(
      refundProposalResponse.toolCallOrigin,
      "openai_compatible_provider_tool_call",
    );
    assert.equal(
      refundProposalResponse.providerInferenceStatus,
      "real_inference_completed",
    );
    assert.equal(
      refundProposalResponse.providerModelId,
      "Qwen/Qwen3-Synthetic-Test",
    );
    assert.equal(refundProposalResponse.idempotentReplay, true);
    assert.equal(
      (
        await request(workspaceAAdmin, refundPath, "POST", {
          scenarioId: "guardian.synthetic.support.refund.v1",
          idempotencyKey: refundIdempotencyKey,
          proposalSource: "qwen_provider",
        })
      ).status,
      409,
      "another actor cannot reuse the requester's idempotency key",
    );
    approvals.push({
      approvalId: refundProposalResponse.approvalId,
      jobId: refundProposalResponse.jobId,
      binding: refundProposalResponse.proposalBindingSha256,
      profileId: "guardian-agent-lab-customer-service-v1",
      caseId: "support_trusted_refund_requires_approval",
      idempotencyKey: refundIdempotencyKey,
      expectedResult: "synthetic_refund_approved_in_clone",
      modelInference: refundProposalResponse.modelInference,
      executionMode: refundProposalResponse.executionMode as
        | "real_openai_compatible_qwen_inference"
        | "deterministic_fixture",
      toolCallOrigin: refundProposalResponse.toolCallOrigin as
        | "openai_compatible_provider_tool_call"
        | "controlled_fixture_not_llm",
    });

    const concurrentRefundKey = `synthetic-refund-${randomUUID()}`;
    const concurrentRefundResponses = await Promise.all([
      request(workspaceAOwner, refundPath, "POST", {
        scenarioId: "guardian.synthetic.support.refund.v1",
        idempotencyKey: concurrentRefundKey,
      }),
      request(workspaceAOwner, refundPath, "POST", {
        scenarioId: "guardian.synthetic.support.refund.v1",
        idempotencyKey: concurrentRefundKey,
      }),
    ]);
    assert.deepEqual(
      concurrentRefundResponses.map((response) => response.status).sort(),
      [200, 201],
      "concurrent identical requests create one pending approval",
    );
    const concurrentRefundBodies = await Promise.all(
      concurrentRefundResponses.map(async (response) =>
        CreateWorkspaceSyntheticRefundProposalResponse.parse(
          await response.json(),
        ),
      ),
    );
    assert.equal(
      concurrentRefundBodies[0]?.approval?.id,
      concurrentRefundBodies[1]?.approval?.id,
    );
    assert.equal(
      concurrentRefundBodies[0]?.execution,
      "not_performed",
    );
    assert.equal(
      concurrentRefundBodies[1]?.execution,
      "not_performed",
    );

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
      assert.equal(pendingApproval?.modelInference, approval.modelInference ?? false);
      assert.equal(
        pendingApproval?.executionMode,
        approval.executionMode ?? "deterministic_fixture",
      );
      assert.equal(
        pendingApproval?.toolCallOrigin,
        approval.toolCallOrigin ?? "controlled_fixture_not_llm",
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

    const signingFailure = await seedApproval(fixturePool, {
      workspaceId: workspaceA,
      requesterId: workspaceAOwner,
      profileId: "guardian-agent-lab-finance-v1",
      caseId: "finance_trusted_bank_change_requires_approval",
      expiry: expireFuture(),
      idempotencyKey: `synthetic-signing-failure-${randomUUID()}`,
    });
    const signingFailurePath =
      `${approvalPath}/${signingFailure.approvalId}/decision`;
    const ephemeralSigningKey =
      process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY;
    assert.ok(ephemeralSigningKey);
    process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY = "TEST ONLY malformed key";
    let signingFailureResponse: Response;
    try {
      signingFailureResponse = await request(
        workspaceAAdmin,
        signingFailurePath,
        "POST",
        {
          decision: "approve",
          proposalBindingSha256: signingFailure.binding,
        },
      );
    } finally {
      process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY = ephemeralSigningKey;
    }
    assert.equal(signingFailureResponse.status, 503);
    const signingFailureState = await fixturePool.query<{
      status: string;
      ledger_count: string;
    }>(
      `SELECT approval.status,
              (SELECT count(*)::text
                 FROM public.workspace_approval_ledger AS ledger
                WHERE ledger.workspace_id = approval.workspace_id
                  AND ledger.approval_id = approval.id::text) AS ledger_count
         FROM public.ai_assessment_approval_requests AS approval
        WHERE approval.id = $1`,
      [signingFailure.approvalId],
    );
    assert.equal(signingFailureState.rows[0]?.status, "pending");
    assert.equal(signingFailureState.rows[0]?.ledger_count, "0");

    const insertFailure = await seedApproval(fixturePool, {
      workspaceId: workspaceA,
      requesterId: workspaceAOwner,
      profileId: "guardian-agent-lab-finance-v1",
      caseId: "finance_trusted_bank_change_requires_approval",
      expiry: expireFuture(),
      idempotencyKey: `synthetic-insert-failure-${randomUUID()}`,
    });
    const insertFailureNow = new Date();
    await assert.rejects(
      withWorkspaceUserTransaction(
        workspaceAAdmin,
        workspaceA,
        async (tx) =>
          updateApprovedRequestAndAppendReceipt(
            tx,
            {
              workspaceId: workspaceA,
              approvalId: insertFailure.approvalId,
              expectedBindingSha256: insertFailure.binding,
              now: insertFailureNow,
              actorUserId: workspaceAAdmin,
              actorRole: "admin",
              update: {
                status: "approved",
                decidedByUserId: workspaceAAdmin,
                decidedByRole: "admin",
                decidedAt: insertFailureNow,
                simulatedAt: insertFailureNow,
                simulationResultCode:
                  "synthetic_bank_change_approved_in_clone",
                simulationResultSha256: "a".repeat(64),
                replayBindingSha256: "b".repeat(64),
                updatedAt: insertFailureNow,
              },
              approval: {
                actionSha256:
                  "a".repeat(64),
                requestedByUserId: workspaceAOwner,
              },
            },
            async (tx, row) => {
              await tx.insert(workspaceApprovalLedgerTable).values({
                ...row,
                signature: "invalid",
              });
            },
          ),
      ),
    );
    const insertFailureState = await fixturePool.query<{
      status: string;
      ledger_count: string;
    }>(
      `SELECT approval.status,
              (SELECT count(*)::text
                 FROM public.workspace_approval_ledger AS ledger
                WHERE ledger.workspace_id = approval.workspace_id
                  AND ledger.approval_id = approval.id::text) AS ledger_count
         FROM public.ai_assessment_approval_requests AS approval
        WHERE approval.id = $1`,
      [insertFailure.approvalId],
    );
    assert.equal(insertFailureState.rows[0]?.status, "pending");
    assert.equal(insertFailureState.rows[0]?.ledger_count, "0");

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
    assert.ok(approvedResponse.receipt, "approval returns one signed receipt");
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
    const financeReceipt = approvedResponse.receipt!;
    assert.equal(financeReceipt.payload.workspaceId, workspaceA);
    assert.equal(financeReceipt.payload.approvalId, finance.approvalId);
    assert.equal(
      financeReceipt.payload.proposalBindingSha256,
      finance.binding,
    );
    const financeApprovedLedger = await fixturePool.query<{
      payload_canonical: string;
      receipt_id: string;
      event_hash: string;
    }>(
      `SELECT payload_canonical, receipt_id, event_hash
         FROM public.workspace_approval_ledger
        WHERE workspace_id = $1 AND approval_id = $2
          AND event_type = 'approval.approved'`,
      [workspaceA, finance.approvalId],
    );
    assert.equal(financeApprovedLedger.rowCount, 1);
    assert.equal(
      financeApprovedLedger.rows[0]?.receipt_id,
      financeReceipt.payload.receiptId,
    );
    assert.match(financeApprovedLedger.rows[0]?.event_hash ?? "", /^[a-f0-9]{64}$/);
    const approvedEventEnvelope = JSON.parse(
      financeApprovedLedger.rows[0]!.payload_canonical,
    ) as {
      payload: Record<string, unknown>;
    };
    assert.deepEqual(
      Object.keys(approvedEventEnvelope.payload).sort(),
      ["receiptId", "receiptSha256"],
      "the ledger stores only the receipt reference and digest, not the receipt",
    );
    assert.equal(
      approvedEventEnvelope.payload.receiptSha256,
      financeReceipt.payloadSha256,
    );
    const consumePath =
      `/api/workspaces/${workspaceA}/ai-security-assessments/approvals/${finance.approvalId}/receipt/consume`;
    const expiredAt = Date.now() - 60_000;
    const expiredReceipt = signApprovalReceiptV1(
      {
        ...financeReceipt.payload,
        receiptId: randomUUID(),
        issuedAt: new Date(expiredAt - 60_000).toISOString(),
        expiresAt: new Date(expiredAt).toISOString(),
      },
      createPrivateKey(
        process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY!,
      ),
    );
    assert.equal(
      (
        await request(workspaceAAdmin, consumePath, "POST", {
          receipt: expiredReceipt,
        })
      ).status,
      409,
      "expired signed receipts are rejected before any ledger append",
    );
    const alteredReceipt = structuredClone(financeReceipt);
    alteredReceipt.signature = `${
      alteredReceipt.signature[0] === "A" ? "B" : "A"
    }${alteredReceipt.signature.slice(1)}`;
    assert.notEqual(alteredReceipt.signature, financeReceipt.signature);
    assert.equal(
      (
        await request(workspaceAAdmin, consumePath, "POST", {
          receipt: alteredReceipt,
        })
      ).status,
      409,
      "a tampered receipt signature is rejected",
    );
    const concurrentConsumption = await Promise.all([
      request(workspaceAAdmin, consumePath, "POST", {
        receipt: financeReceipt,
      }),
      request(workspaceAAdmin2, consumePath, "POST", {
        receipt: financeReceipt,
      }),
    ]);
    assert.deepEqual(
      concurrentConsumption.map((response) => response.status).sort(),
      [200, 409],
      "workspace lock and unique index permit exactly one receipt consumer",
    );
    const consumedResponse =
      ConsumeWorkspaceAiAssessmentApprovalReceiptResponse.parse(
        await concurrentConsumption
          .find((response) => response.status === 200)!
          .json(),
      );
    assert.equal(consumedResponse.consumed, true);
    const consumedLedger = await fixturePool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM public.workspace_approval_ledger
        WHERE workspace_id = $1 AND receipt_id = $2
          AND event_type = 'approval.receipt_consumed'`,
      [workspaceA, financeReceipt.payload.receiptId],
    );
    assert.equal(consumedLedger.rows[0]?.count, "1");
    assert.equal(
      (
        await request(workspaceAAdmin, consumePath, "POST", {
          receipt: financeReceipt,
        })
      ).status,
      409,
      "consumed receipts cannot be replayed",
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
    const concurrentRefundApprovals = await Promise.all([
      request(workspaceAAdmin, supportDecisionPath, "POST", {
        decision: "approve",
        proposalBindingSha256: support.binding,
      }),
      request(workspaceAAdmin2, supportDecisionPath, "POST", {
        decision: "approve",
        proposalBindingSha256: support.binding,
      }),
    ]);
    assert.deepEqual(
      concurrentRefundApprovals.map((response) => response.status).sort(),
      [200, 409],
      "concurrent refund approval requests produce one decision and one rejection",
    );
    const dashboardDecision =
      DecideWorkspaceAiAssessmentApprovalResponse.parse(
        await concurrentRefundApprovals
          .find((response) => response.status === 200)!
          .json(),
      );
    assert.equal(
      dashboardDecision.approval.status,
      "approved",
      "a different workspace admin can decide the externally generated proposal",
    );
    assert.equal(
      dashboardDecision.execution,
      "decision_only",
      "approval records authorization but does not run the refund simulator",
    );
    assert.ok(dashboardDecision.receipt);
    const supportReceipt = dashboardDecision.receipt!;
    assert.equal(dashboardDecision.approval.simulatedAt, null);
    assert.equal(dashboardDecision.approval.simulationResultCode, null);
    const visibleAfterApproval = ListWorkspaceAiAssessmentApprovalsResponse.parse(
      await (await request(workspaceAAdmin, approvalPath)).json(),
    );
    const recordedRefund = visibleAfterApproval.approvals.find(
      (approval) => approval.id === support.approvalId,
    );
    assert.equal(recordedRefund?.status, "approved");
    assert.equal(
      recordedRefund?.execution,
      "not_performed",
      "the dashboard does not claim a refund simulation before receipt consumption",
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
    const supportConsumePath =
      `/api/workspaces/${workspaceA}/ai-security-assessments/approvals/${support.approvalId}/receipt/consume`;
    assert.equal(
      (
        await request(workspaceAAdmin, supportConsumePath, "POST", {})
      ).status,
      400,
      "missing receipt is rejected before any operation",
    );
    const tamperedSupportReceipt = structuredClone(supportReceipt);
    tamperedSupportReceipt.signature =
      `${tamperedSupportReceipt.signature[0] === "A" ? "B" : "A"}${tamperedSupportReceipt.signature.slice(1)}`;
    assert.equal(
      (
        await request(workspaceAAdmin, supportConsumePath, "POST", {
          receipt: tamperedSupportReceipt,
        })
      ).status,
      409,
      "an altered signed receipt cannot reach the simulator",
    );

    const expiredSupportAt = Date.now() - 60_000;
    const expiredSupportReceipt = signApprovalReceiptV1(
      {
        ...supportReceipt.payload,
        receiptId: randomUUID(),
        issuedAt: new Date(expiredSupportAt - 60_000).toISOString(),
        expiresAt: new Date(expiredSupportAt).toISOString(),
      },
      createPrivateKey(process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY!),
    );
    assert.equal(
      (
        await request(workspaceAAdmin, supportConsumePath, "POST", {
          receipt: expiredSupportReceipt,
        })
      ).status,
      409,
      "an expired signed receipt cannot reach the simulator",
    );

    const actionMismatchReceipt = signApprovalReceiptV1(
      {
        ...supportReceipt.payload,
        actionSha256: "f".repeat(64),
      },
      createPrivateKey(process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY!),
    );
    assert.notEqual(
      actionMismatchReceipt.payload.actionSha256,
      supportReceipt.payload.actionSha256,
    );
    assert.equal(
      (
        await request(workspaceAAdmin, supportConsumePath, "POST", {
          receipt: actionMismatchReceipt,
        })
      ).status,
      409,
      "a validly signed receipt for a different action cannot reach the simulator",
    );

    const workspaceMismatchReceipt = signApprovalReceiptV1(
      {
        ...supportReceipt.payload,
        workspaceId: workspaceB,
      },
      createPrivateKey(process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY!),
    );
    assert.equal(
      (
        await request(workspaceAAdmin, supportConsumePath, "POST", {
          receipt: workspaceMismatchReceipt,
        })
      ).status,
      409,
      "a validly signed receipt for another workspace cannot reach the simulator",
    );

    const publicKeyPem = createPublicKey(
      createPrivateKey(process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY!),
    ).export({ format: "pem", type: "spki" }).toString();
    assert.ok(agentApprovalReceipt, "the agent approval produced a signed receipt");
    const eventsPath =
      `/api/workspaces/${workspaceA}/ai-security-assessments/approval-ledger/events`;
    const exportPath =
      `/api/workspaces/${workspaceA}/ai-security-assessments/approval-ledger/export`;
    assert.equal(
      (await request(workspaceAViewer, eventsPath)).status,
      403,
      "ledger event listing is limited to workspace owners and admins",
    );
    const eventsResponse = await request(workspaceAAdmin, eventsPath);
    assert.equal(eventsResponse.status, 200);
    const eventHistory = ListWorkspaceApprovalLedgerEventsResponse.parse(
      await eventsResponse.json(),
    );
    assert.ok(
      eventHistory.events.some((event) =>
        event.event.eventType === "approval.approved" &&
        event.event.approvalId === supportReceipt.payload.approvalId
      ),
      "the read-only ledger view includes the signed approval event",
    );
    assert.deepEqual(
      eventHistory.events.map((event) => event.event.sequence),
      [...eventHistory.events]
        .map((event) => event.event.sequence)
        .sort((left, right) => left - right),
      "the read-only ledger view preserves chain sequence order",
    );
    assert.equal(
      (
        await request(workspaceAViewer, exportPath, "POST", {
          receipts: [financeReceipt, supportReceipt, agentApprovalReceipt],
        })
      ).status,
      403,
      "ledger export is limited to workspace owners and admins",
    );
    assert.equal(
      (
        await request(workspaceAAdmin, exportPath, "POST", {
          receipts: [supportReceipt],
        })
      ).status,
      409,
      "export refuses to omit an earlier workspace receipt",
    );
    const exportResponse = await request(workspaceAAdmin, exportPath, "POST", {
      receipts: [financeReceipt, supportReceipt, agentApprovalReceipt],
    });
    assert.equal(exportResponse.status, 200);
    const portableBundle = ExportWorkspaceApprovalLedgerBundleResponse.parse(
      await exportResponse.json(),
    );
    const offlineVerification = verifyBundleWithOfflineCli({
      bundle: portableBundle,
      keyId: supportReceipt.payload.keyId,
      publicKeyPem,
      verificationTime: new Date().toISOString(),
    });
    assert.equal(offlineVerification.status, 0, offlineVerification.stderr);
    assert.equal(offlineVerification.stderr, "");
    assert.deepEqual(
      JSON.parse(offlineVerification.stdout),
      { valid: true, code: "ok" },
      "a separate process verifies the exported signed history before operation",
    );

    const supportApprovedEvent = await fixturePool.query<{
      signature: string;
    }>(
      `SELECT signature
         FROM public.workspace_approval_ledger
        WHERE workspace_id = $1 AND approval_id = $2
          AND event_type = 'approval.approved'`,
      [workspaceA, supportReceipt.payload.approvalId],
    );
    assert.equal(supportApprovedEvent.rowCount, 1);
    const originalSupportSignature = supportApprovedEvent.rows[0]!.signature;
    const invalidButWellFormedSignature = Buffer.alloc(64, 1).toString(
      "base64url",
    );
    const tamperedLedgerUpdate = await fixturePool.query(
      `UPDATE public.workspace_approval_ledger
          SET signature = $3
        WHERE workspace_id = $1 AND approval_id = $2
          AND event_type = 'approval.approved'
       RETURNING 1`,
      [
        workspaceA,
        supportReceipt.payload.approvalId,
        invalidButWellFormedSignature,
      ],
    );
    assert.equal(tamperedLedgerUpdate.rowCount, 1);
    const tamperedChainConsume = await request(
      workspaceAAdmin,
      supportConsumePath,
      "POST",
      { receipt: supportReceipt },
    );
    assert.equal(tamperedChainConsume.status, 503);
    assert.deepEqual(await tamperedChainConsume.json(), {
      error: "Approval ledger unavailable",
    });
    const tamperedChainConsumptionCount = await fixturePool.query<{
      count: string;
    }>(
      `SELECT count(*)::text AS count
         FROM public.workspace_approval_ledger
        WHERE workspace_id = $1 AND receipt_id = $2
          AND event_type = 'approval.receipt_consumed'`,
      [workspaceA, supportReceipt.payload.receiptId],
    );
    assert.equal(tamperedChainConsumptionCount.rows[0]?.count, "0");
    await fixturePool.query(
      `UPDATE public.workspace_approval_ledger
          SET signature = $3
        WHERE workspace_id = $1 AND approval_id = $2
          AND event_type = 'approval.approved'`,
      [
        workspaceA,
        supportReceipt.payload.approvalId,
        originalSupportSignature,
      ],
    );

    const supportConsumptions = await Promise.all([
      request(workspaceAAdmin, supportConsumePath, "POST", {
        receipt: supportReceipt,
      }),
      request(workspaceAAdmin2, supportConsumePath, "POST", {
        receipt: supportReceipt,
      }),
    ]);
    assert.deepEqual(
      supportConsumptions.map((response) => response.status).sort(),
      [200, 409],
      "one valid receipt consumption gates exactly one refund simulation",
    );
    const supportConsumed =
      ConsumeWorkspaceAiAssessmentApprovalReceiptResponse.parse(
        await supportConsumptions
          .find((response) => response.status === 200)!
          .json(),
      );
    assert.equal(supportConsumed.syntheticRefundOperation?.executed, true);
    assert.equal(
      supportConsumed.syntheticRefundOperation?.reasonCode,
      "valid_receipt_consumed",
    );
    assert.equal(
      supportConsumed.syntheticRefundOperation?.resultCode,
      "synthetic_refund_approved_in_clone",
    );
    assert.match(
      supportConsumed.syntheticRefundOperation?.resultSha256 ?? "",
      /^[a-f0-9]{64}$/,
    );
    const consumedBundleResponse = await request(
      workspaceAAdmin,
      exportPath,
      "POST",
      {
        receipts: [
          financeReceipt,
          supportReceipt,
          agentApprovalReceipt,
        ],
      },
    );
    assert.equal(consumedBundleResponse.status, 200);
    const consumedBundle = ExportWorkspaceApprovalLedgerBundleResponse.parse(
      await consumedBundleResponse.json(),
    );
    const consumedOfflineVerification = verifyBundleWithOfflineCli({
      bundle: consumedBundle,
      keyId: supportReceipt.payload.keyId,
      publicKeyPem,
      verificationTime: new Date().toISOString(),
    });
    assert.equal(consumedOfflineVerification.status, 0);
    assert.deepEqual(
      JSON.parse(consumedOfflineVerification.stdout),
      { valid: true, code: "ok" },
      "the independently verified export includes the consumed event",
    );
    assert.equal(
      (
        await request(workspaceAAdmin, supportConsumePath, "POST", {
          receipt: supportReceipt,
        })
      ).status,
      409,
      "a replay is rejected and cannot run the simulator again",
    );

    const concurrentWorkspaceAApprovals = await Promise.all([
      seedApproval(fixturePool, {
        workspaceId: workspaceA,
        requesterId: workspaceAOwner,
        profileId: "guardian-agent-lab-finance-v1",
        caseId: "finance_trusted_bank_change_requires_approval",
        expiry: expireFuture(),
        idempotencyKey: `synthetic-ledger-concurrent-a1-${randomUUID()}`,
      }),
      seedApproval(fixturePool, {
        workspaceId: workspaceA,
        requesterId: workspaceAOwner,
        profileId: "guardian-agent-lab-finance-v1",
        caseId: "finance_trusted_bank_change_requires_approval",
        expiry: expireFuture(),
        idempotencyKey: `synthetic-ledger-concurrent-a2-${randomUUID()}`,
      }),
    ]);
    const concurrentWorkspaceBApproval = await seedApproval(fixturePool, {
      workspaceId: workspaceB,
      requesterId: workspaceBOwner,
      profileId: "guardian-agent-lab-finance-v1",
      caseId: "finance_trusted_bank_change_requires_approval",
      expiry: expireFuture(),
      idempotencyKey: `synthetic-ledger-concurrent-b-${randomUUID()}`,
    });
    const crossWorkspaceDecisions = await Promise.all([
      request(
        workspaceAAdmin,
        `${approvalPath}/${concurrentWorkspaceAApprovals[0].approvalId}/decision`,
        "POST",
        {
          decision: "approve",
          proposalBindingSha256: concurrentWorkspaceAApprovals[0].binding,
        },
      ),
      request(
        workspaceAAdmin2,
        `${approvalPath}/${concurrentWorkspaceAApprovals[1].approvalId}/decision`,
        "POST",
        {
          decision: "approve",
          proposalBindingSha256: concurrentWorkspaceAApprovals[1].binding,
        },
      ),
      request(
        workspaceBAdmin,
        `/api/workspaces/${workspaceB}/ai-security-assessments/approvals/${concurrentWorkspaceBApproval.approvalId}/decision`,
        "POST",
        {
          decision: "approve",
          proposalBindingSha256: concurrentWorkspaceBApproval.binding,
        },
      ),
    ]);
    assert.deepEqual(
      crossWorkspaceDecisions.map((response) => response.status),
      [200, 200, 200],
      "independent workspaces and same-workspace approval writers can proceed concurrently",
    );
    for (const response of crossWorkspaceDecisions) {
      const parsed = DecideWorkspaceAiAssessmentApprovalResponse.parse(
        await response.json(),
      );
      assert.ok(parsed.receipt);
    }
    for (const [workspaceId, expectedCount] of [
      [workspaceA, 7],
      [workspaceB, 1],
    ] as const) {
      const chain = await fixturePool.query<{
        sequence: string;
        previous_hash: string;
        event_hash: string;
      }>(
        `SELECT sequence::text, previous_hash, event_hash
           FROM public.workspace_approval_ledger
          WHERE workspace_id = $1
          ORDER BY sequence`,
        [workspaceId],
      );
      assert.equal(chain.rowCount, expectedCount);
      let previousHash = "";
      chain.rows.forEach((event, index) => {
        assert.equal(event.sequence, String(index + 1));
        assert.equal(event.previous_hash, previousHash);
        previousHash = event.event_hash;
      });
    }

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
    assert.equal(denied.receipt, null, "denials never issue receipts");
    const deniedLedger = await fixturePool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM public.workspace_approval_ledger
        WHERE workspace_id = $1 AND approval_id = $2`,
      [workspaceA, supportDenied.approvalId],
    );
    assert.equal(deniedLedger.rows[0]?.count, "0");

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
        simulated: false,
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
      if (approval === support) {
        assert.equal(
          row.simulated_at,
          null,
          "refund execution is not represented as an approval-time simulation",
        );
        assert.equal(row.simulation_result_code, null);
        assert.equal(row.simulation_result_sha256, null);
        assert.equal(row.replay_binding_sha256, null);
      } else {
        assert.ok(row.simulated_at);
        assert.equal(row.simulation_result_code, approval.expectedResult);
        assert.match(row.simulation_result_sha256 ?? "", /^[a-f0-9]{64}$/);
        assert.match(row.replay_binding_sha256 ?? "", /^[a-f0-9]{64}$/);
      }
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

    const actionCatalogPath =
      `/api/workspaces/${workspaceA}/ai-security-assessments/action-catalog`;
    const actionCatalogResponse = await request(workspaceAOwner, actionCatalogPath);
    assert.equal(actionCatalogResponse.status, 200);
    const actionCatalog = GetWorkspaceGenericActionCatalogResponse.parse(
      await actionCatalogResponse.json(),
    );
    assert.equal(actionCatalog.catalogVersion, "guardian-action-catalog-v1");
    assert.ok(actionCatalog.actions.some(
      (item) => item.actionType === "guardian.support.reply.send.v1",
    ));
    assert.ok(actionCatalog.actions.some(
      (item) => item.actionType === "guardian.email.send.external.v1",
    ));
    assert.equal(
      (await request(
        workspaceAViewer,
        actionCatalogPath,
      )).status,
      200,
      "workspace members may read the versioned catalog",
    );

    const sandboxAction = {
      actionType: "guardian.email.send.external.v1",
      arguments: {
        to: "qa@example.test",
        template_id: "guardian-demo-email-v1",
      },
    };
    const emailRulePath =
      `/api/workspaces/${workspaceB}/action-rules/guardian.email.send.external.v1`;
    const emailRuleDraft = await request(
      workspaceBOwner,
      `${emailRulePath}/draft`,
      "PUT",
      {
        version: 1,
        rules: [{
          id: "review-synthetic-email",
          decision: "require_approval",
          when: {},
        }],
      },
    );
    assert.equal(emailRuleDraft.status, 201);
    assert.equal(
      (await request(
        workspaceBOwner,
        `${emailRulePath}/activate`,
        "POST",
      )).status,
      200,
    );
    const actionPreviewPath =
      `/api/workspaces/${workspaceB}/ai-security-assessments/action-preview`;
    const previewResponse = await request(
      workspaceBAdmin,
      actionPreviewPath,
      "POST",
      sandboxAction,
    );
    assert.equal(previewResponse.status, 200);
    const previewDecision = PreviewWorkspaceGenericActionResponse.parse(
      await previewResponse.json(),
    );
    assert.equal(previewDecision.decision, "require_approval");
    assert.equal(previewDecision.persisted, false);
    assert.equal(previewDecision.dispatched, false);
    assert.ok(previewDecision.ruleVersionId);
    const unknownPreview = await request(
      workspaceBAdmin,
      actionPreviewPath,
      "POST",
      { actionType: "guardian.unknown.v1", arguments: {} },
    );
    assert.equal(unknownPreview.status, 200);
    assert.equal(
      PreviewWorkspaceGenericActionResponse.parse(
        await unknownPreview.json(),
      ).reasonCode,
      "unknown_action",
    );

    const genericProposalPath =
      `/api/workspaces/${workspaceB}/ai-security-assessments/action-proposals`;
    const unknownProposal = await request(
      workspaceBOwner,
      genericProposalPath,
      "POST",
      {
        ...sandboxAction,
        actionType: "guardian.unlisted.action.v1",
        idempotencyKey: randomUUID(),
      },
    );
    assert.equal(unknownProposal.status, 400);
    assert.equal(
      (await unknownProposal.json() as { code?: unknown }).code,
      "unknown_action",
    );
    const malformedProposal = await request(
      workspaceBOwner,
      genericProposalPath,
      "POST",
      {
        ...sandboxAction,
        arguments: { ...sandboxAction.arguments, extra: "not allowed" },
        idempotencyKey: randomUUID(),
      },
    );
    assert.equal(malformedProposal.status, 400);
    assert.equal(
      (await malformedProposal.json() as { code?: unknown }).code,
      "arguments_invalid",
    );
    const externalRecipientProposal = await request(
      workspaceBOwner,
      genericProposalPath,
      "POST",
      {
        ...sandboxAction,
        arguments: { ...sandboxAction.arguments, to: "real@example.com" },
        idempotencyKey: randomUUID(),
      },
    );
    assert.equal(externalRecipientProposal.status, 400);
    assert.equal(
      (await externalRecipientProposal.json() as { code?: unknown }).code,
      "arguments_invalid",
    );

    const genericProposalResponse = await request(
      workspaceBOwner,
      genericProposalPath,
      "POST",
      {
        ...sandboxAction,
        idempotencyKey: randomUUID(),
      },
    );
    assert.equal(genericProposalResponse.status, 201);
    const genericProposal = CreateWorkspaceGenericActionProposalResponse.parse(
      await genericProposalResponse.json(),
    );
    assert.equal(genericProposal.decision, "require_approval");
    assert.equal(genericProposal.externalSideEffect, false);
    assert.equal(genericProposal.execution, "not_performed");
    assert.ok(genericProposal.approval);
    assert.equal(
      genericProposal.approval.proposalDetails?.agentId,
      "agent-fixture-email-demo-v1",
    );
    assert.equal(genericProposal.approval.proposalDetails?.synthetic, true);
    const genericApproval = genericProposal.approval;
    assert.equal(
      (await request(
        workspaceBOwner,
        `/api/workspaces/${workspaceB}/ai-security-assessments/approvals/${genericApproval.id}/decision`,
        "POST",
        {
          decision: "approve",
          proposalBindingSha256: genericApproval.proposalBindingSha256,
        },
      )).status,
      403,
      "the requester cannot approve the action they proposed",
    );
    const genericDecisionResponse = await request(
      workspaceBAdmin,
      `/api/workspaces/${workspaceB}/ai-security-assessments/approvals/${genericApproval.id}/decision`,
      "POST",
      {
        decision: "approve",
        proposalBindingSha256: genericApproval.proposalBindingSha256,
      },
    );
    assert.equal(genericDecisionResponse.status, 200);
    const genericDecision = DecideWorkspaceAiAssessmentApprovalResponse.parse(
      await genericDecisionResponse.json(),
    );
    assert.ok(genericDecision.receipt);
    assert.equal(genericDecision.execution, "decision_only");

    const guardCredential = randomBytes(32).toString("base64url");
    const smtpCapture = await startSyntheticSmtpCapture(guardCredential);
    t.after(async () => {
      if (smtpCapture.server.listening) {
        await new Promise<void>((resolveClose, reject) => {
          smtpCapture.server.close((error) =>
            error ? reject(error) : resolveClose(),
          );
        });
      }
    });
    const { executeGuardedSandboxAction } = await import(
      "../../../lib/guardian-guard/index.mjs"
    );
    const trustedLedgerPublicKey = createPublicKey(
      createPrivateKey(ephemeralLedgerKey),
    );
    const guardInput = {
      apiBaseUrl: apiBase,
      requestHeaders: { "x-guardian-test-user": workspaceBAdmin },
      receipt: genericDecision.receipt,
      trustedKeys: {
        "guardian-nexus-approval-ledger-v1": trustedLedgerPublicKey,
      },
      expected: {
        workspaceId: workspaceB,
        approvalId: genericApproval.id,
        proposalBindingSha256: genericApproval.proposalBindingSha256,
        actionSha256: genericApproval.actionSha256!,
        requestedBy: workspaceBOwner,
        approvedBy: workspaceBAdmin,
        approvedByRole: "admin",
      },
      action: {
        actionType: sandboxAction.actionType,
        args: sandboxAction.arguments,
      },
      sandboxSmtp: {
        port: smtpCapture.port,
        credential: guardCredential,
      },
    };
    const directToolReply = await attemptDirectSmtpWithoutGuardCredential(
      smtpCapture.port,
    );
    assert.match(directToolReply, /^530\b/);
    assert.equal(
      smtpCapture.messages.length,
      0,
      "direct agent access is rejected before any message is captured",
    );
    await assert.rejects(
      executeGuardedSandboxAction({
        ...guardInput,
        action: {
          actionType: sandboxAction.actionType,
          args: { ...sandboxAction.arguments, to: "other@example.test" },
        },
      }),
      (error: unknown) =>
        !!error &&
        typeof error === "object" &&
        "code" in error &&
        error.code === "receipt_reference_mismatch",
    );
    const guardedSend = await executeGuardedSandboxAction(guardInput);
    assert.equal(guardedSend.executed, true);
    assert.equal(guardedSend.mode, "local_smtp_capture_only");
    assert.equal(guardedSend.externalEffect, false);
    assert.match(smtpCapture.messages[0] ?? "", /To: qa@example\.test/);
    assert.match(smtpCapture.messages[0] ?? "", /\[SYNTHETIC\]/);
    await assert.rejects(
      executeGuardedSandboxAction(guardInput),
      (error: unknown) =>
        !!error &&
        typeof error === "object" &&
        "code" in error &&
        error.code === "receipt_rejected",
    );
    assert.equal(
      smtpCapture.messages.length,
      1,
      "one-use ledger consumption permits exactly one local SMTP capture",
    );

    const concurrentAction = {
      ...sandboxAction,
      idempotencyKey: randomUUID(),
    };
    const concurrentProposalResponse = await request(
      workspaceBOwner,
      genericProposalPath,
      "POST",
      concurrentAction,
    );
    assert.equal(concurrentProposalResponse.status, 201);
    const concurrentProposal =
      CreateWorkspaceGenericActionProposalResponse.parse(
        await concurrentProposalResponse.json(),
      );
    assert.ok(concurrentProposal.approval);
    const concurrentApproval = concurrentProposal.approval;
    const concurrentDecisionResponse = await request(
      workspaceBAdmin,
      `/api/workspaces/${workspaceB}/ai-security-assessments/approvals/${concurrentApproval.id}/decision`,
      "POST",
      {
        decision: "approve",
        proposalBindingSha256: concurrentApproval.proposalBindingSha256,
      },
    );
    assert.equal(concurrentDecisionResponse.status, 200);
    const concurrentDecision =
      DecideWorkspaceAiAssessmentApprovalResponse.parse(
        await concurrentDecisionResponse.json(),
      );
    assert.ok(concurrentDecision.receipt);
    const concurrentConsumeUrl =
      `/api/workspaces/${workspaceB}/ai-security-assessments/approvals/${concurrentApproval.id}/receipt/consume`;
    const concurrentConsumeResponses = await Promise.all([
      request(
        workspaceBAdmin,
        concurrentConsumeUrl,
        "POST",
        { receipt: concurrentDecision.receipt },
      ),
      request(
        workspaceBAdmin,
        concurrentConsumeUrl,
        "POST",
        { receipt: concurrentDecision.receipt },
      ),
    ]);
    assert.deepEqual(
      concurrentConsumeResponses.map((response) => response.status).sort(),
      [200, 409],
      "concurrent replay against disposable PostgreSQL has exactly one winner",
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
      approvalRequests: approvals.length + 5,
      approvalDecisions: {
        approvedOnce: 3,
        tamperedChainRejected: 1,
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
      receiptGatedRefund: {
        exportedBeforeConsumption: true,
        independentlyVerifiedBeforeConsumption: true,
        validReceiptAcceptedOnce: true,
        missingAlteredExpiredWorkspaceMismatchActionMismatchRejected: true,
        replayRejected: true,
        corruptedEventChainRejected: true,
        externalEffects: false,
      },
      genericActionGuard: {
        actionType: sandboxAction.actionType,
        catalogValidated: true,
        deniedUnknownActionAndArguments: true,
        approvedByDifferentAdmin: true,
        receiptVerifiedOffline: true,
        directToolCallRejected: true,
        consumedOnceBeforeToolExecution: true,
        localSmtpCaptureCount: smtpCapture.messages.length,
        replayRejected: true,
        concurrentConsumeOneWinner: true,
        externalDelivery: false,
      },
      membershipRoleProbes: {
        ...membershipProbeResults,
        eachMutationRolledBack: true,
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
