import assert from "node:assert/strict";
import { test } from "node:test";
import {
  QWEN_AGENT_PROFILE_IDS,
  GuardianNexusClient,
  GuardianNexusSdkError,
  createIdempotencyKey,
  type QwenAgentProfileId,
} from "./index.js";

const workspaceId = "123e4567-e89b-42d3-a456-426614174000";
const jobId = "123e4567-e89b-42d3-a456-426614174001";
const approvalId = "123e4567-e89b-42d3-a456-426614174002";
const binding = "a".repeat(64);

function sampleQwenEvidence(
  profileId: QwenAgentProfileId = "guardian-agent-qwen-lab-email-v1",
) {
  const verticalId = profileId.replace(
    "guardian-agent-qwen-lab-",
    "",
  ).replace("-v1", "").replace("-", "_");
  const hash = "c".repeat(64);
  const sharedCase = {
    label: "benign",
    language: "en",
    promptSha256: hash,
    toolChoice: "auto",
    finishReason: "stop",
    proposedTool: null,
    proposalSha256: null,
    syntheticActionRef: null,
    actionSha256: null,
    policyOnStateBeforeSha256: hash,
    policyOnStateAfterSha256: hash,
    policyOff: {
      mode: "counterfactual_clone_only",
      wouldExecute: false,
      executed: false,
      stateBeforeSha256: hash,
      stateAfterSha256: hash,
    },
    unauthorizedActionExecuted: false,
    rawPromptStored: false,
    rawResponseStored: false,
    rawArgumentsStored: false,
    caseEvidenceSha256: hash,
  };
  const cases = [
    {
      ...sharedCase,
      caseId: "qwen_benign_adapted",
      toolCallOrigin: "guardian_qwen_native_markup_adapter",
      toolCallCount: 1,
      proposedTool: "read_synthetic_invoice",
      proposalSha256: hash,
      decision: "allow",
      reasonCode: "synthetic_read_allowed",
      dispatchStatus: "simulated_execution",
      toolEvents: [
        {
          phase: "executed",
          authorization: "allowed",
          executed: true,
          simulatedOnly: true,
          externalSideEffect: false,
          argumentsSha256: hash,
          resultCode: "synthetic_read_completed",
        },
      ],
    },
    {
      ...sharedCase,
      caseId: "qwen_attack_native_denied",
      label: "adversarial",
      toolCallOrigin: "runtime_message_tool_calls",
      toolCallCount: 1,
      proposedTool: "send_email_simulated",
      proposalSha256: hash,
      decision: "deny",
      reasonCode: "recipient_not_allowlisted",
      dispatchStatus: "blocked_by_policy_before_dispatch",
      toolEvents: [],
    },
    {
      ...sharedCase,
      caseId: "qwen_benign_no_proposal",
      toolCallOrigin: "no_tool_call",
      toolCallCount: 0,
      decision: "no_proposal",
      reasonCode: "no_tool_call",
      dispatchStatus: "not_invoked",
      toolEvents: [],
    },
  ];
  return {
    evidenceVersion: 1,
    source: "qwen_local_policy_lab",
    engine: "guardian_qwen_policy_lab",
    engineVersion: "guardian-agent-qwen-policy-lab-v1.6.0",
    profileId,
    verticalId,
    executionMode: "real_local_qwen_inference",
    proposalOriginScope: "qwen_marker_adapter_or_runtime_tool_calls_only",
    provider: { id: "local_qwen_gguf", toolChoice: "auto" },
    network: {
      networkMode: "docker-network-none",
      loopbackOnly: true,
      publicIpv4: "blocked",
      publicDns: "blocked",
      publicIpv6: "unavailable",
    },
    limits: {
      concurrency: 1,
      pids: 64,
      cpuCores: 1,
      memoryMiB: 1536,
      network: "docker-network-none",
      externalCalls: 0,
      actualOperations: 0,
      customerDataUsed: false,
      secretsMounted: false,
      rawPromptsStored: false,
      rawResponsesStored: false,
      rawToolArgumentsStored: false,
      maxCases: 3,
      maxToolCallsPerCase: 1,
      maxModelCallsPerCase: 1,
      maxCompletionTokensPerCall: 96,
      verifiedContainerLimits: {
        cpuLimitVerified: true,
        pidsLimitVerified: true,
        memoryLimitVerified: true,
      },
    },
    cases,
    summary: {
      modelCalls: 3,
      sampleCount: 3,
      benignCases: 2,
      adversarialCases: 1,
      noToolCalls: 1,
      runtimeMessageToolCalls: 1,
      adaptedQwenMarkupCalls: 1,
      simulatedExecutions: 1,
      externalCalls: 0,
      unauthorizedExecutions: 0,
      policyOffExecutions: 0,
    },
    selfChecks: {
      allCallsUsedAuto: true,
      noForcedToolSelection: true,
      onlyRealLocalQwenInference: true,
      policyBeforeDispatch: true,
      deniedCallsNeverDispatched: true,
      policyOffCloneOnly: true,
      noRawPromptsResponsesOrArguments: true,
    },
    evidenceSha256: hash,
  };
}

function qwenJobResponse(
  profileId: QwenAgentProfileId,
  result: unknown = null,
  status: "queued" | "succeeded" = "queued",
) {
  return {
    id: jobId,
    status,
    profileId,
    workerVersion: "worker-test",
    attempts: status === "succeeded" ? 1 : 0,
    engineVersion:
      status === "succeeded" ? "guardian-agent-qwen-policy-lab-v1.6.0" : null,
    result,
    errorCode: null,
    createdAt: "2026-11-03T00:00:00.000Z",
    startedAt: status === "succeeded" ? "2026-11-03T00:00:00.100Z" : null,
    completedAt: status === "succeeded" ? "2026-11-03T00:00:01.000Z" : null,
  };
}

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

test("Qwen SDK requests only allowlisted profiles with no caller-supplied actions", async () => {
  const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
  const client = clientWith(async (input, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    requests.push({ url: String(input), body });
    return Response.json(
      qwenJobResponse(body.profileId as QwenAgentProfileId),
      { status: 202 },
    );
  });

  for (const [index, profileId] of QWEN_AGENT_PROFILE_IDS.entries()) {
    const submitted = await client.submitQwenEvaluation({
      profileId,
      idempotencyKey: `sdk-qwen-profile-${index}-stable`,
    });
    assert.equal(submitted.source, "qwen_local_policy_lab_profile");
    assert.equal(submitted.executionMode, "not_yet_verified");
    assert.equal(submitted.externalDispatch, false);
    assert.equal(submitted.job.profileId, profileId);
  }
  assert.equal(requests.length, 8);
  assert.ok(
    requests.every(
      ({ url, body }) =>
        url.endsWith(
          `/workspaces/${workspaceId}/ai-security-assessments/lab/jobs`,
        ) &&
        Object.keys(body).sort().join(",") === "idempotencyKey,profileId" &&
        typeof body.idempotencyKey === "string" &&
        QWEN_AGENT_PROFILE_IDS.includes(
          body.profileId as QwenAgentProfileId,
        ),
    ),
  );

  let invalidProfileNetworkCalls = 0;
  const guardedClient = clientWith(async () => {
    invalidProfileNetworkCalls += 1;
    return Response.json({});
  });
  await assert.rejects(
    guardedClient.submitQwenEvaluation({
      profileId: "guardian-local-llm-autonomous-tools-v1" as QwenAgentProfileId,
      idempotencyKey: "sdk-qwen-invalid-profile-001",
    }),
    { code: "invalid_qwen_evaluation_request" },
  );
  assert.equal(invalidProfileNetworkCalls, 0);
});

test("Qwen evidence parser keeps native, adapted, and absent proposals distinct", async () => {
  // This is a parser fixture only; it is not model-inference evidence.
  const evidence = sampleQwenEvidence();
  const client = clientWith(async () =>
    Response.json(
      qwenJobResponse(
        "guardian-agent-qwen-lab-email-v1",
        evidence,
        "succeeded",
      ),
    ),
  );
  const completed = await client.waitForQwenEvaluation(
    jobId,
    "guardian-agent-qwen-lab-email-v1",
    { intervalMs: 50, maxAttempts: 1 },
  );
  assert.equal(completed.report.executionMode, "real_local_qwen_inference");
  assert.equal(completed.report.toolChoice, "auto");
  assert.deepEqual(completed.report.counts, {
    cases: 3,
    directRuntimeToolCallCases: 1,
    adaptedQwenMarkerCases: 1,
    unparsedMarkerCases: 0,
    noToolCallCases: 1,
    allow: 1,
    deny: 1,
    requireApproval: 0,
    noProposal: 1,
    simulatedExecutions: 1,
  });
  assert.deepEqual(
    completed.report.cases.map((item) => item.toolCallOrigin),
    [
      "guardian_qwen_native_markup_adapter",
      "runtime_message_tool_calls",
      "no_tool_call",
    ],
  );
});

test("Qwen SDK rejects false dispatch or mismatched evidence summaries", async () => {
  const invalidDispatch = structuredClone(sampleQwenEvidence());
  const invalidCase = invalidDispatch.cases[1] as Record<string, unknown>;
  const invalidPolicyOff = invalidCase.policyOff as Record<string, unknown>;
  invalidPolicyOff.executed = true;
  const invalidSummary = structuredClone(sampleQwenEvidence());
  invalidSummary.summary.adaptedQwenMarkupCalls = 0;
  for (const result of [invalidDispatch, invalidSummary]) {
    const client = clientWith(async () =>
      Response.json(
        qwenJobResponse(
          "guardian-agent-qwen-lab-email-v1",
          result,
          "succeeded",
        ),
      ),
    );
    await assert.rejects(
      client.waitForQwenEvaluation(
        jobId,
        "guardian-agent-qwen-lab-email-v1",
        { intervalMs: 50, maxAttempts: 1 },
      ),
      (error: unknown) =>
        error instanceof GuardianNexusSdkError &&
        [
          "invalid_qwen_policy_case",
          "inconsistent_qwen_policy_summary",
        ].includes(error.code),
    );
  }
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
