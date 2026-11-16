import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createExternalQwenApprovalEvidence,
  getQwenProviderStatus,
  parseQwenProviderConfig,
  providerProposalMatchesAllowlistedAction,
  QwenProviderError,
  requestQwenRefundProposal,
  validateExternalQwenApprovalEvidence,
  type QwenProviderConfig,
} from "./qwen-openai-provider";
import { resolveSyntheticRefundDecision } from "./synthetic-refund-gateway";

const TEST_KEY = "synthetic-test-key-never-valid";
const TEST_CONFIG: QwenProviderConfig = {
  baseUrl: "https://qwen-provider.invalid/v1",
  modelId: "Qwen/Qwen3-Test",
  apiKey: TEST_KEY,
};
const REFUND_ARGS_SHA256 = "a".repeat(64);

function toolResponse(
  name = "propose_synthetic_refund",
  args = '{"ticket_id":"TICKET-SYNTH-001","amount_cents":500}',
  calls?: unknown[],
): Response {
  return new Response(
    JSON.stringify({
      choices: [
        {
          message: {
            tool_calls:
              calls ??
              [
                {
                  type: "function",
                  function: { name, arguments: args },
                },
              ],
          },
        },
      ],
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

async function assertProviderError(
  operation: () => Promise<unknown>,
  code: QwenProviderError["code"],
): Promise<void> {
  await assert.rejects(operation, (error: unknown) => {
    assert.ok(error instanceof QwenProviderError);
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    assert.ok(!error.message.includes(TEST_KEY));
    assert.ok(!error.message.includes(TEST_CONFIG.baseUrl));
    return true;
  });
}

test("provider status distinguishes missing, invalid, and configured-not-tested", () => {
  assert.deepEqual(
    getQwenProviderStatus({
      QWEN_PROVIDER_BASE_URL: undefined,
      QWEN_PROVIDER_MODEL: undefined,
      QWEN_PROVIDER_API_KEY: undefined,
    }),
    {
      status: "not_configured",
      provider: "openai_compatible_qwen",
      modelId: null,
      missing: ["base_url", "model", "api_key"],
    },
  );
  assert.equal(
    getQwenProviderStatus({
      QWEN_PROVIDER_BASE_URL: "http://qwen.example/v1",
      QWEN_PROVIDER_MODEL: "Qwen/Qwen3-Test",
      QWEN_PROVIDER_API_KEY: TEST_KEY,
    }).status,
    "invalid_configuration",
  );
  assert.deepEqual(
    getQwenProviderStatus({
      QWEN_PROVIDER_BASE_URL: TEST_CONFIG.baseUrl,
      QWEN_PROVIDER_MODEL: TEST_CONFIG.modelId,
      QWEN_PROVIDER_API_KEY: TEST_KEY,
    }),
    {
      status: "configured_not_tested",
      provider: "openai_compatible_qwen",
      modelId: TEST_CONFIG.modelId,
      missing: [],
    },
  );
});

test("configuration rejects non-HTTPS, credentialed, loopback, and IP endpoints", async () => {
  for (const baseUrl of [
    "http://qwen.example/v1",
    "https://user:pass@qwen.example/v1",
    "https://localhost/v1",
    "https://127.0.0.1/v1",
  ]) {
    await assertProviderError(
      async () =>
        parseQwenProviderConfig({
          QWEN_PROVIDER_BASE_URL: baseUrl,
          QWEN_PROVIDER_MODEL: TEST_CONFIG.modelId,
          QWEN_PROVIDER_API_KEY: TEST_KEY,
        }),
      "provider_configuration_invalid",
    );
  }
});

test("valid OpenAI-compatible tool output becomes a hashed untrusted proposal", async () => {
  const captured: {
    requestUrl?: string;
    requestHeaders?: Headers;
    requestBody?: Record<string, unknown>;
  } = {};
  const proposal = await requestQwenRefundProposal(TEST_CONFIG, async (input, init) => {
    captured.requestUrl = String(input);
    captured.requestHeaders = new Headers(init?.headers);
    captured.requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return toolResponse();
  });

  assert.equal(
    captured.requestUrl,
    `${TEST_CONFIG.baseUrl}/chat/completions`,
  );
  assert.equal(
    captured.requestHeaders?.get("authorization"),
    `Bearer ${TEST_KEY}`,
  );
  assert.equal(captured.requestHeaders?.get("accept"), "application/json");
  assert.equal(captured.requestBody?.model, TEST_CONFIG.modelId);
  assert.equal(captured.requestBody?.tool_choice, "auto");
  assert.equal(proposal.toolName, "propose_synthetic_refund");
  assert.equal(proposal.arguments.ticket_id, "TICKET-SYNTH-001");
  assert.equal(proposal.arguments.amount_cents, 500);
  assert.match(proposal.argumentsSha256, /^[a-f0-9]{64}$/);
  assert.match(proposal.proposalSha256, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(proposal).includes(TEST_KEY));
  assert.ok(!JSON.stringify(proposal).includes(TEST_CONFIG.baseUrl));
  assert.equal("execute" in proposal, false);
});

test("missing credentials deny the provider call without fallback", async () => {
  await assertProviderError(
    async () =>
      parseQwenProviderConfig({
        QWEN_PROVIDER_BASE_URL: TEST_CONFIG.baseUrl,
        QWEN_PROVIDER_MODEL: TEST_CONFIG.modelId,
        QWEN_PROVIDER_API_KEY: undefined,
      }),
    "provider_not_configured",
  );
});

test("provider request failures return a fixed error without response details", async () => {
  const secretResponseMarker = "SYNTHETIC-RESPONSE-CANARY";
  await assertProviderError(
    () =>
      requestQwenRefundProposal(TEST_CONFIG, async () =>
        new Response(secretResponseMarker, { status: 500 }),
      ),
    "provider_request_failed",
  );
});

test("malformed, multiple, and adversarial tool calls are rejected", async () => {
  await assertProviderError(
    () =>
      requestQwenRefundProposal(TEST_CONFIG, async () =>
        toolResponse("execute_refund"),
      ),
    "provider_proposal_invalid",
  );
  await assertProviderError(
    () =>
      requestQwenRefundProposal(TEST_CONFIG, async () =>
        toolResponse("propose_synthetic_refund", "{malformed"),
      ),
    "provider_proposal_invalid",
  );
  await assertProviderError(
    () =>
      requestQwenRefundProposal(TEST_CONFIG, async () =>
        toolResponse(
          "propose_synthetic_refund",
          '{"ticket_id":"TICKET-SYNTH-001","amount_cents":500,"dispatch_url":"https://attacker.invalid"}',
        ),
      ),
    "provider_proposal_invalid",
  );
  await assertProviderError(
    () =>
      requestQwenRefundProposal(TEST_CONFIG, async () =>
        toolResponse("propose_synthetic_refund", undefined, [
          { type: "function", function: { name: "propose_synthetic_refund", arguments: "{}" } },
          { type: "function", function: { name: "execute_refund", arguments: "{}" } },
        ]),
      ),
    "provider_proposal_invalid",
  );
});

test("a shaped proposal is rejected unless its argument digest matches the fixed action", async () => {
  const matching = await requestQwenRefundProposal(TEST_CONFIG, async () =>
    toolResponse(),
  );
  assert.equal(
    providerProposalMatchesAllowlistedAction(matching, matching.argumentsSha256),
    true,
  );
  assert.equal(
    providerProposalMatchesAllowlistedAction(matching, REFUND_ARGS_SHA256),
    false,
  );
});

test("external approval evidence is hashed, strict, and contains no raw prompt or arguments", async () => {
  const proposal = await requestQwenRefundProposal(TEST_CONFIG, async () =>
    toolResponse(),
  );
  const evidence = createExternalQwenApprovalEvidence({
    proposal,
    actionSha256: "b".repeat(64),
    guardianPolicyEvidence: { engine: "guardian_policy_lab", decision: "require_approval" },
  });
  assert.equal(validateExternalQwenApprovalEvidence(evidence), true);
  assert.equal(evidence.rawPromptStored, false);
  assert.equal(evidence.rawResponseStored, false);
  assert.equal(evidence.rawToolArgumentsStored, false);
  assert.equal(evidence.externalOperations, 0);
  assert.equal(evidence.actualOperations, 0);
  assert.equal("arguments" in evidence, false);
  assert.equal("apiKey" in evidence, false);

  assert.equal(
    validateExternalQwenApprovalEvidence({
      ...evidence,
      proposalSha256: "c".repeat(64),
    }),
    false,
  );
  assert.equal(
    validateExternalQwenApprovalEvidence({
      ...evidence,
      executionMode: "deterministic_fixture",
    }),
    false,
  );
  assert.equal(
    validateExternalQwenApprovalEvidence({
      ...evidence,
      prompt: "untrusted raw prompt",
    }),
    false,
  );
});

test("Guardian decisions remain authoritative and the proposal never dispatches directly", async () => {
  const calls = { persist: 0, simulate: 0 };
  const callbacks = {
    persistPendingApproval: async () => {
      calls.persist += 1;
      return "pending-human-approval";
    },
    simulateAllowedAction: async () => {
      calls.simulate += 1;
      return "simulated";
    },
    requireReceiptForSimulation: true,
  };

  assert.deepEqual(
    await resolveSyntheticRefundDecision("require_approval", callbacks),
    { kind: "approval_required", approval: "pending-human-approval" },
  );
  assert.deepEqual(
    await resolveSyntheticRefundDecision("deny", callbacks),
    { kind: "denied" },
  );
  assert.deepEqual(
    await resolveSyntheticRefundDecision("allow", callbacks),
    { kind: "receipt_required" },
  );
  assert.deepEqual(calls, { persist: 1, simulate: 0 });
});
