import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { canonicalApprovalJson } from "./ai-assessment-approval-actions";
import {
  AGENT_ACTION_ADAPTER_VERSION,
  AGENT_ACTION_INTENT_CONTRACT_VERSION,
  AGENT_ACTION_SCENARIO_IDS,
  SYNTHETIC_EXTERNAL_AGENT_ID,
  buildAgentActionIntent,
  deriveAgentActionIdempotencyKey,
  getAgentActionScenario,
} from "./guardian-agent-action-adapter";

const baseIdentity = {
  actorUserId: "test-owner",
  actorRole: "owner" as const,
  workspaceId: "10000000-0000-4000-8000-000000000001",
};

test("external agent adapter exposes only the four fixed synthetic scenarios", () => {
  assert.deepEqual(AGENT_ACTION_SCENARIO_IDS, [
    "email.allowed_draft",
    "email.untrusted_send",
    "finance.untrusted_transfer",
    "finance.trusted_bank_change_approval",
  ]);
  assert.equal(AGENT_ACTION_ADAPTER_VERSION, "guardian-agent-intent-adapter-v1");
  assert.equal(AGENT_ACTION_INTENT_CONTRACT_VERSION, "guardian-action-intent-v1");
  assert.equal(
    getAgentActionScenario("email.allowed_draft").profileId,
    "guardian-agent-lab-email-v1",
  );
  assert.equal(
    getAgentActionScenario("email.untrusted_send").caseId,
    "email_adversarial_external_exfiltration",
  );
  assert.equal(
    getAgentActionScenario("finance.untrusted_transfer").caseId,
    "finance_adversarial_transfer_request",
  );
});

test("intent hash binds server-derived actor, tenant, scenario and fixed tool metadata", () => {
  for (const scenarioId of AGENT_ACTION_SCENARIO_IDS) {
    const intent = buildAgentActionIntent(scenarioId, baseIdentity);
    const { intentSha256, ...unsignedIntent } = intent;
    const expected = createHash("sha256")
      .update(canonicalApprovalJson(unsignedIntent), "utf8")
      .digest("hex");
    assert.equal(intentSha256, expected);
    assert.match(intentSha256, /^[a-f0-9]{64}$/);
    assert.equal(intent.agentId, SYNTHETIC_EXTERNAL_AGENT_ID);
    assert.equal(intent.workspaceId, baseIdentity.workspaceId);
    assert.equal(intent.actorUserId, baseIdentity.actorUserId);
    assert.equal("arguments" in intent, false);
    assert.equal("policyMode" in intent, false);
    assert.equal("decision" in intent, false);
  }

  const otherWorkspace = buildAgentActionIntent("email.allowed_draft", {
    ...baseIdentity,
    workspaceId: "20000000-0000-4000-8000-000000000002",
  });
  const otherActor = buildAgentActionIntent("email.allowed_draft", {
    ...baseIdentity,
    actorUserId: "different-owner",
  });
  assert.notEqual(
    otherWorkspace.intentSha256,
    buildAgentActionIntent("email.allowed_draft", baseIdentity).intentSha256,
  );
  assert.notEqual(
    otherActor.intentSha256,
    buildAgentActionIntent("email.allowed_draft", baseIdentity).intentSha256,
  );
});

test("adapter idempotency is stable and bound to scenario, actor, and role", () => {
  const key = {
    scenarioId: "email.allowed_draft" as const,
    actorUserId: baseIdentity.actorUserId,
    actorRole: baseIdentity.actorRole,
    callerKey: "caller-key-with-more-than-16",
  };
  const first = deriveAgentActionIdempotencyKey(key);
  assert.equal(first, deriveAgentActionIdempotencyKey(key));
  assert.notEqual(
    first,
    deriveAgentActionIdempotencyKey({
      ...key,
      scenarioId: "email.untrusted_send",
    }),
  );
  assert.notEqual(
    first,
    deriveAgentActionIdempotencyKey({ ...key, actorUserId: "another-user" }),
  );
  assert.notEqual(
    first,
    deriveAgentActionIdempotencyKey({ ...key, actorRole: "admin" }),
  );
  assert.match(first, /^agent-intent-v1:[a-f0-9]{64}$/);
});
