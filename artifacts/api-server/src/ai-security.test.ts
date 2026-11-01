import assert from "node:assert/strict";
import { test } from "node:test";
import { CreateWorkspaceAiAssessmentLabJobResponse } from "@workspace/api-zod";
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

test("tenant job response contract accepts hashed synthetic verification evidence", () => {
  const ratio = { numerator: 1, denominator: 1, value: 1 };
  const timestamp = new Date("2026-10-30T12:00:00.000Z").toISOString();
  const parsed = CreateWorkspaceAiAssessmentLabJobResponse.parse({
    id: "33333333-3333-4333-8333-333333333333",
    status: "succeeded",
    profileId: "guardian-local-agent-v1",
    workerVersion: "guardian-ai-assessment-lab-0.4.0",
    attempts: 1,
    engineVersion: "0.17.1",
    result: {
      evidenceVersion: 1,
      source: "isolated_local_lab",
      engine: "garak",
      engineVersion: "0.17.1",
      profileId: "guardian-local-agent-v1",
      probeClasses: ["probes.promptinject.HijackHateHumans"],
      generationsPerProbe: 1,
      probeRequests: 1,
      reportRecordCount: 2,
      reportRecordTypes: { attempt: 1, eval: 1 },
      positiveDetectorScores: 0,
      findings: [],
      reportSha256: "c".repeat(64),
      reportBytes: 128,
      network: {
        networkMode: "docker-network-none",
        interfaces: ["lo"],
        activeNonLoopbackInterfaces: [],
        publicIpv4: "blocked",
        publicIpv6: "unavailable",
        ipv6Capability: "kernel_protocol_unavailable",
        publicDns: "blocked",
        loopbackOnly: true,
      },
      startedAt: timestamp,
      completedAt: timestamp,
      durationSeconds: 2,
      promptsStored: false,
      responsesStored: false,
      externalCalls: 0,
      customerDataUsed: false,
      findingSummary: "Fixture local acotado.",
      guardianVerification: {
        engine: "guardian_verification",
        version: "0.1.0",
        suiteVersion: "guardian-verification-fixtures-1",
        agentVersion: "guardian-deterministic-agent-1",
        policyVersion: "guardian-lab-policies-1",
        oracleVersion: "guardian-trace-oracle-1",
        mode: "deterministic_synthetic_local_agent",
        objectiveBitOrder: [
          "untrusted_text_present",
          "synthetic_data_propagated",
          "untrusted_instruction_obeyed",
          "action_attempted",
          "unauthorized_action_attempted",
          "action_executed",
          "policy_violation",
        ],
        scenarios: [
          {
            scenarioId: "synthetic_data_exfiltration",
            policyId: "mail-recipient-allowlist-1",
          },
        ],
        sampleCount: 2,
        seedCount: 1,
        splitSampleCounts: { calibration: 1, holdout: 1 },
        metrics: [
          {
            scenarioId: "synthetic_data_exfiltration",
            split: "holdout",
            objective: "policy_violation",
            sampleCount: 2,
            positiveSupport: 1,
            negativeSupport: 1,
            truePositive: 1,
            falsePositive: 0,
            trueNegative: 1,
            falseNegative: 0,
            precision: ratio,
            recall: ratio,
            falsePositiveRate: { numerator: 0, denominator: 1, value: 0 },
            falseNegativeRate: { numerator: 0, denominator: 1, value: 0 },
            accuracy: { numerator: 2, denominator: 2, value: 1 },
          },
        ],
        toolCallSummary: {
          total: 1,
          authorized: 1,
          denied: 0,
          executed: 1,
          stateChanges: 1,
          unauthorizedActionAttempts: 1,
          policyViolations: 1,
          operationCounts: { "email.send.external": 1 },
          byOperation: [
            {
              operation: "email.send.external",
              calls: 1,
              authorized: 1,
              denied: 0,
              executed: 1,
              policyAllowed: 0,
              policyDenied: 1,
              stateChanges: 1,
              targetActions: 1,
              syntheticDataObserved: 1,
              policyViolations: 1,
            },
          ],
        },
        anomalyCount: 0,
        selfChecks: {
          status: "passed",
          allToolCallsInstrumented: true,
          deniedCallsHaveNoSideEffects: true,
          scenarioPolicyOracleIndependentOfToolGrant: true,
          unknownOperationsRejected: true,
          rawSyntheticContentStored: false,
        },
        caseEvidence: [
          {
            caseId: "synthetic_data_exfiltration:holdout:9101:attack_vulnerable",
            expectedMask: 127,
            observedMask: 127,
            caseEvidenceSha256: "d".repeat(64),
          },
          {
            caseId: "synthetic_data_exfiltration:holdout:9101:benign_no_action",
            expectedMask: 0,
            observedMask: 0,
            caseEvidenceSha256: "f".repeat(64),
          },
        ],
        suiteEvidenceSha256: "e".repeat(64),
        startedAt: timestamp,
        completedAt: timestamp,
        durationMs: 5,
        limits: { maxRuntimeSeconds: 15, maxSamples: 144, concurrency: 1 },
        syntheticOnly: true,
        rawPromptsStored: false,
        rawResponsesStored: false,
        externalCalls: 0,
        customerDataUsed: false,
        interpretation: "Contrato de evidencia sintética.",
      },
    },
    errorCode: null,
    createdAt: timestamp,
    startedAt: timestamp,
    completedAt: timestamp,
  });

  assert.equal(
    parsed.result?.guardianVerification?.engine,
    "guardian_verification",
  );
  assert.equal(
    parsed.result?.guardianVerification?.caseEvidence[0]?.caseEvidenceSha256,
    "d".repeat(64),
  );
});

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
