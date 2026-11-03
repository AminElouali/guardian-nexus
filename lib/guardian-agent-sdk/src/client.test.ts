import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GuardianNexusClient,
  GuardianNexusSdkError,
  createIdempotencyKey,
} from "./index.js";

const workspaceId = "123e4567-e89b-42d3-a456-426614174000";
const jobId = "123e4567-e89b-42d3-a456-426614174001";
const approvalId = "123e4567-e89b-42d3-a456-426614174002";
const binding = "a".repeat(64);

function clientWith(
  fetcher: typeof fetch,
  options: { token?: string | null; maxRetries?: number } = {},
) {
  return new GuardianNexusClient({
    baseUrl: "http://127.0.0.1:43121",
    workspaceId,
    getAccessToken: () => options.token === undefined ? "short-lived-test-token" : options.token,
    fetch: fetcher,
    maxRetries: options.maxRetries,
  });
}

test("SDK rejects non-loopback plain HTTP and malformed tenant IDs", () => {
  assert.throws(
    () =>
      new GuardianNexusClient({
        baseUrl: "http://example.com",
        workspaceId,
        getAccessToken: () => "unused",
      }),
    (error: unknown) =>
      error instanceof GuardianNexusSdkError &&
      error.code === "insecure_or_invalid_base_url",
  );
  assert.throws(
    () =>
      new GuardianNexusClient({
        baseUrl: "https://guardian.invalid",
        workspaceId: "not-a-uuid",
        getAccessToken: () => "unused",
      }),
    (error: unknown) =>
      error instanceof GuardianNexusSdkError &&
      error.code === "invalid_workspace_id",
  );
});

test("intent retries preserve the exact idempotency key and bearer auth", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  let attempt = 0;
  const fetcher: typeof fetch = async (input, init) => {
    attempt += 1;
    requests.push({ url: String(input), init });
    if (attempt === 1) return new Response("unavailable", { status: 503 });
    return Response.json({
      adapterVersion: "guardian-agent-intent-adapter-v1",
      source: "fixed_synthetic_scenario",
      decisionStatus: "pending_worker_evaluation",
      externalDispatch: false,
      actionIntent: {
        contractVersion: "guardian-action-intent-v1",
        agentId: "guardian-synthetic-external-agent-v1",
        actorUserId: "synthetic-user",
        actorRole: "owner",
        workspaceId,
        scenarioId: "email.allowed_draft",
        caseId: "email_benign_read_and_draft",
        toolId: "send_email_simulated",
        operation: "draft.create",
        resourceType: "mailbox",
        resourceId: "MAILBOX-SYNTH-001",
        sensitivity: "internal",
        instructionProvenance: "trusted_user_request",
        requiredPermissions: ["email.draft.create"],
        intentSha256: "b".repeat(64),
      },
      job: {
        id: jobId,
        status: "queued",
        profileId: "guardian-agent-lab-email-v1",
        workerVersion: "worker-test",
        createdAt: "2026-11-03T00:00:00.000Z",
      },
    });
  };
  const client = clientWith(fetcher, { maxRetries: 1 });
  const response = await client.submitIntent({
    scenarioId: "email.allowed_draft",
    idempotencyKey: "sdk-e2e-stable-key-001",
  });
  assert.equal(response.job.id, jobId);
  assert.equal(requests.length, 2);
  assert.equal(requests[0]?.url, `http://127.0.0.1:43121/api/workspaces/${workspaceId}/agent-action-adapter/intents`);
  for (const request of requests) {
    const headers = new Headers(request.init?.headers);
    assert.equal(headers.get("authorization"), "Bearer short-lived-test-token");
    assert.equal(request.init?.credentials, "omit");
    assert.equal(request.init?.redirect, "error");
    assert.equal(
      JSON.parse(String(request.init?.body)).idempotencyKey,
      "sdk-e2e-stable-key-001",
    );
  }
});

test("SDK performs bounded direct job lookup and rejects malformed responses", async () => {
  const client = clientWith(async (input) => {
    assert.match(String(input), new RegExp(`/lab/jobs/${jobId}$`));
    return Response.json({
      id: jobId,
      status: "succeeded",
      profileId: "guardian-agent-lab-finance-v1",
      workerVersion: "worker-test",
      attempts: 1,
      engineVersion: "guardian-agent-policy-lab-v2",
      result: { sampleCount: 3 },
      errorCode: null,
      createdAt: "2026-11-03T00:00:00.000Z",
      startedAt: null,
      completedAt: "2026-11-03T00:00:01.000Z",
    });
  });
  assert.equal((await client.getJob(jobId)).status, "succeeded");
  await assert.rejects(client.getJob("not-a-uuid"), {
    code: "invalid_job_id",
  });
});

test("approval list accepts the API envelope and validates each tenant record", async () => {
  const approval = {
    id: approvalId,
    jobId,
    caseId: "finance_trusted_bank_change_requires_approval",
    proposalSha256: binding,
    proposalBindingSha256: binding,
    requestedByUserId: "user-requester",
    status: "pending",
    expiresAt: "2026-11-03T00:05:00.000Z",
  };
  const client = clientWith(async () =>
    Response.json({ approvals: [approval] }),
  );
  assert.deepEqual(await client.listApprovals(), [approval]);
});

test("approval decisions are bound, typed and never automatically retried", async () => {
  let requests = 0;
  const client = clientWith(async (_input, init) => {
    requests += 1;
    assert.equal(init?.method, "POST");
    return Response.json(
      { error: "approval_already_decided" },
      { status: 409 },
    );
  });
  await assert.rejects(
    client.decideApproval({
      approvalId,
      decision: "approve",
      proposalBindingSha256: binding,
    }),
    (error: unknown) =>
      error instanceof GuardianNexusSdkError &&
      error.status === 409 &&
      error.code === "approval_already_decided",
  );
  assert.equal(requests, 1);
});

test("SDK maps approval evidence conflicts to a stable non-sensitive code", async () => {
  const client = clientWith(async () =>
    Response.json({ error: "Approval is evidence_invalid" }, { status: 409 }),
  );
  await assert.rejects(
    client.listApprovals(),
    (error: unknown) =>
      error instanceof GuardianNexusSdkError &&
      error.status === 409 &&
      error.code === "approval_evidence_invalid",
  );
});

test("SDK treats inherited property names as plain sanitized API error codes", async () => {
  const client = clientWith(async () =>
    Response.json({ error: "toString" }, { status: 409 }),
  );
  await assert.rejects(
    client.listApprovals(),
    (error: unknown) =>
      error instanceof GuardianNexusSdkError &&
      error.status === 409 &&
      typeof error.code === "string" &&
      error.code === "toString",
  );
});

test("idempotency key helper uses secure UUIDs", () => {
  assert.match(createIdempotencyKey(), /^[0-9a-f-]{36}$/i);
});
