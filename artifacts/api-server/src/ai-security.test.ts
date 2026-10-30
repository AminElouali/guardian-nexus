import assert from "node:assert/strict";
import { test } from "node:test";
import {
  acquireMockEvaluationSlot,
  evaluateMockFixtures,
  runLocalMockEvaluation,
} from "./lib/ai-evaluation";
import {
  getModelArmorReadiness,
  ModelArmorAdapter,
  type ModelArmorSanitizationRequest,
} from "./lib/model-armor";

test("local AI mock assessment is fixed, deterministic, and records no real agent output", () => {
  const first = runLocalMockEvaluation();
  const second = runLocalMockEvaluation();
  assert.deepEqual(first, second);
  assert.equal(first.execution, "simulated");
  assert.equal(first.engine, "guardian_mock");
  assert.equal(first.checks.length, 3);
  assert.equal(first.failedChecks, 0);
  assert.ok(
    first.checks.every(
      (check) =>
        !JSON.stringify(check).includes("SYNTHETIC_SECRET") &&
        !JSON.stringify(check).includes("prompt text"),
    ),
  );
});

test("mock assessment fixtures report controlled failures without exposing canaries", () => {
  const result = evaluateMockFixtures({
    promptInjectionRefused: false,
    syntheticCanaryLeaked: true,
    unauthorizedToolExecuted: true,
  });
  assert.equal(result.filter((check) => check.status === "failed").length, 3);
  assert.deepEqual(
    result.map((check) => check.reasonCode),
    [
      "mock_accepted_untrusted_instruction",
      "synthetic_canary_would_leak",
      "mock_executed_unapproved_tool",
    ],
  );
  assert.ok(!JSON.stringify(result).includes("SYNTHETIC_SECRET_VALUE"));
});

test("mock evaluation slot bounds concurrency and releases idempotently", () => {
  const release = acquireMockEvaluationSlot();
  assert.equal(typeof release, "function");
  assert.equal(acquireMockEvaluationSlot(), undefined);
  release?.();
  release?.();
  const nextRelease = acquireMockEvaluationSlot();
  assert.equal(typeof nextRelease, "function");
  nextRelease?.();
});

test("Model Armor remains disabled or blocked until both flag and tenant consent exist", async () => {
  const calls: ModelArmorSanitizationRequest[] = [];
  const readyDisabled = getModelArmorReadiness({
    featureFlag: false,
    tenantConsent: true,
    projectId: "demo-project",
    location: "europe-west1",
    promptTemplateId: "prompt-template",
    responseTemplateId: "response-template",
  });
  assert.deepEqual(readyDisabled, {
    state: "disabled",
    reason: "feature_flag_off",
  });

  const needsConsent = getModelArmorReadiness({
    featureFlag: true,
    tenantConsent: false,
    projectId: "demo-project",
    location: "europe-west1",
    promptTemplateId: "prompt-template",
    responseTemplateId: "response-template",
  });
  assert.deepEqual(needsConsent, {
    state: "needs_consent",
    reason: "tenant_consent_required",
  });

  const adapter = new ModelArmorAdapter(
    readyDisabled,
    "demo-project",
    "prompt-template",
    "response-template",
    { getAccessToken: async () => "ephemeral-test-token" },
    {
      sanitize: async (request) => {
        calls.push(request);
        return { sanitizedText: request.text, triggeredFilters: [] };
      },
    },
  );
  await assert.rejects(adapter.sanitize("user_prompt", "safe sample"));
  assert.equal(calls.length, 0);
});

test("Model Armor EU adapter routes input and output only to their configured templates", async () => {
  const calls: ModelArmorSanitizationRequest[] = [];
  let tokenSeen = "";
  const readiness = getModelArmorReadiness({
    featureFlag: true,
    tenantConsent: true,
    projectId: "demo-project",
    location: "europe-west9",
    promptTemplateId: "input-template",
    responseTemplateId: "output-template",
  });
  assert.equal(readiness.state, "prepared");
  if (readiness.state !== "prepared") return;

  const adapter = new ModelArmorAdapter(
    readiness,
    "demo-project",
    "input-template",
    "output-template",
    { getAccessToken: async () => "ephemeral-test-token" },
    {
      sanitize: async (request, token) => {
        calls.push(request);
        tokenSeen = token;
        return { sanitizedText: request.text, triggeredFilters: [] };
      },
    },
  );
  await adapter.sanitize("user_prompt", "synthetic prompt");
  await adapter.sanitize("model_response", "synthetic response");
  assert.deepEqual(
    calls.map(({ mode, location, templateId }) => ({
      mode,
      location,
      templateId,
    })),
    [
      {
        mode: "user_prompt",
        location: "europe-west9",
        templateId: "input-template",
      },
      {
        mode: "model_response",
        location: "europe-west9",
        templateId: "output-template",
      },
    ],
  );
  assert.equal(tokenSeen, "ephemeral-test-token");
  assert.equal(JSON.stringify(calls).includes("ephemeral-test-token"), false);
});

test("Model Armor readiness rejects missing config and non-EU regions", () => {
  assert.deepEqual(
    getModelArmorReadiness({
      featureFlag: true,
      tenantConsent: true,
      projectId: "project",
      location: "us-central1",
      promptTemplateId: "input",
      responseTemplateId: "output",
    }),
    { state: "blocked", reason: "non_eu_location" },
  );
  assert.deepEqual(
    getModelArmorReadiness({
      featureFlag: true,
      tenantConsent: true,
      projectId: "project",
      location: "europe-west1",
      promptTemplateId: "input",
    }),
    { state: "blocked", reason: "missing_configuration" },
  );
});
