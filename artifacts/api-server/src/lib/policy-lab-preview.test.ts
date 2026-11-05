import assert from "node:assert/strict";
import { test } from "node:test";
import { POLICY_LAB_PROFILE_IDS } from "./ai-assessment-sandbox";
import {
  buildPolicyLabPreviewCommand,
  PolicyLabPreviewError,
  validatePolicyLabPreviewEvidence,
  runPolicyLabPreview,
} from "./policy-lab-preview";

function assertEvidenceContainsNoRawPayloadKeys(value: unknown): void {
  const forbiddenKeys = new Set([
    "arguments",
    "prompt",
    "promptText",
    "rawArguments",
    "rawInstruction",
    "rawPrompt",
    "rawResponse",
    "response",
    "responseText",
  ]);
  const visit = (item: unknown): void => {
    if (Array.isArray(item)) {
      item.forEach(visit);
      return;
    }
    if (!item || typeof item !== "object") {
      return;
    }
    for (const [key, nested] of Object.entries(item)) {
      assert.equal(
        forbiddenKeys.has(key),
        false,
        `evidence must not contain raw payload field: ${key}`,
      );
      visit(nested);
    }
  };
  visit(value);
}

test("policy preview command is fixed, bounded, and receives only an allow-listed profile", () => {
  const command = buildPolicyLabPreviewCommand(POLICY_LAB_PROFILE_IDS[0]);
  assert.equal(command.executable, "python3");
  assert.deepEqual(command.args, [
    "-S",
    "-B",
    "-m",
    "guardian_ai_assessment.policy_lab",
    "--profile-id",
    POLICY_LAB_PROFILE_IDS[0],
    "--execution-context",
    "api_policy_preview",
  ]);
  assert.equal(command.timeout, 5_000);
  assert.equal(command.maxBuffer, 64 * 1024);
  assert.deepEqual(Object.keys(command.env).sort(), [
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "PYTHONNOUSERSITE",
    "PYTHONPATH",
  ]);
  assert.throws(
    () => buildPolicyLabPreviewCommand("guardian-local-llm-qwen3-0.6b-v1"),
    (error: unknown) =>
      error instanceof PolicyLabPreviewError &&
      error.code === "unsupported_policy_lab_profile",
  );
});

test("fresh deterministic previews validate all eight fixture profiles and never claim isolation", async () => {
  for (const profileId of POLICY_LAB_PROFILE_IDS) {
    const evidence = await runPolicyLabPreview(profileId);
    assert.equal(evidence.profileId, profileId);
    assert.equal(evidence.engine, "guardian_policy_lab");
    assert.equal(evidence.engineVersion, "guardian-agent-policy-lab-v3");
    assert.equal(evidence.executionContext, "api_policy_preview");
    assert.equal(evidence.executionMode, "deterministic_fixture");
    assert.equal(evidence.modelInference, false);
    assert.equal(evidence.proposalOrigin, "controlled_fixture_not_llm");
    assert.equal(evidence.selfCheckStatus, "passed");
    assert.equal(evidence.limits.network, "host_network_unisolated");
    assert.equal(evidence.limits.processIsolation, "shared_api_identity");
    assert.equal(evidence.limits.dockerSocketAccess, "not_assessed");
    assert.equal(evidence.summary.externalCalls, 0);
    assert.equal(evidence.summary.actualOperations, 0);
    assert.equal(evidence.summary.persistentStateChanges, 0);
    assert.equal(evidence.summary.unauthorizedExecutions, 0);
    assertEvidenceContainsNoRawPayloadKeys(evidence);
    for (const item of evidence.cases) {
      assert.equal(item.rawArgumentsStored, false);
      assert.equal(item.rawInstructionStored, false);
      assert.equal(item.policyOff.executed, false);
      assert.equal(item.toolTrace?.policyOff.invoked, false);
      assert.deepEqual(item.toolTrace?.policyOff.events, []);
      if (item.policyOn.decision === "deny") {
        assert.equal(item.policyOn.executed, false);
        assert.ok(
          item.toolTrace?.policyOn.events.every((event) => !event.executed),
        );
        if (
          item.toolTrace?.policyOn.dispatchStatus ===
          "blocked_by_policy_before_dispatch"
        ) {
          assert.equal(item.toolTrace.policyOn.invoked, false);
          assert.deepEqual(item.toolTrace.policyOn.events, []);
        }
      } else if (item.policyOn.decision === "require_approval") {
        assert.equal(item.policyOn.executed, false);
        assert.equal(item.toolTrace?.policyOn.invoked, false);
        assert.deepEqual(item.toolTrace?.policyOn.events, []);
      }
    }
    assert.ok(evidence.cases.every((item) => item.policyOff.executed === false));
    assert.ok(
      evidence.cases.every(
        (item) =>
          item.policyOff.mode === "counterfactual_clone_only" &&
          item.toolTrace?.policyOff.invoked === false &&
          item.toolTrace.policyOff.events.length === 0,
      ),
    );
  }
});

test("preview evidence hash binds the decision and fails closed on mutation", async () => {
  const evidence = await runPolicyLabPreview(POLICY_LAB_PROFILE_IDS[0]);
  const tampered = structuredClone(evidence);
  tampered.summary.allowed += 1;
  assert.throws(
    () =>
      validatePolicyLabPreviewEvidence(
        tampered,
        POLICY_LAB_PROFILE_IDS[0],
      ),
    (error: unknown) =>
      error instanceof PolicyLabPreviewError &&
      error.code === "policy_preview_evidence_invalid",
  );
});
