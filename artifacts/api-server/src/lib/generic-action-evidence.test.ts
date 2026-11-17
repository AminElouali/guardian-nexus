import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createGenericActionEvidence,
  genericActionDisplay,
  genericActionProposalSha256,
  hashGenericActionArguments,
  verifyGenericActionEvidence,
} from "./generic-action-evidence";

const args = {
  to: "qa@example.test",
  template_id: "guardian-demo-email-v1",
};
const workspaceId = "11111111-1111-4111-8111-111111111111";
const requestedByUserId = "user-synthetic-agent";
const actionType = "guardian.email.send.external.v1";
const evaluatedRuleId =
  "external-email.sandbox.requires-independent-approval.v1";

function evidence() {
  const display = genericActionDisplay(actionType, args);
  assert.ok(display);
  return createGenericActionEvidence({
    workspaceId,
    requestedByUserId,
    actionType,
    args,
    ruleId: evaluatedRuleId,
    ...display,
  });
}

test("generic action evidence binds the exact action, arguments, workspace and requester", () => {
  const value = evidence();
  assert.ok(value);
  assert.equal(value.actionType, actionType);
  assert.equal(value.workspaceId, workspaceId);
  assert.equal(value.synthetic, true);
  assert.equal(value.modelInference, false);
  assert.equal(
    verifyGenericActionEvidence(value, {
      workspaceId,
      requestedByUserId,
      actionType,
      actionSha256: value.actionSha256,
      proposalSha256: value.proposalSha256,
      profileId: value.profileId,
    })?.evidenceSha256,
    value.evidenceSha256,
  );
});

test("generic evidence rejects changed arguments and mismatched action or workspace", () => {
  const value = evidence();
  assert.ok(value);
  const expected = {
    workspaceId,
    requestedByUserId,
    actionType,
    actionSha256: value.actionSha256,
    proposalSha256: value.proposalSha256,
    profileId: value.profileId,
  };
  assert.equal(
    verifyGenericActionEvidence(
      { ...value, arguments: { ...value.arguments, to: "other@example.test" } },
      expected,
    ),
    null,
  );
  assert.equal(
    verifyGenericActionEvidence(value, { ...expected, actionType: "guardian.support.reply.send.v1" }),
    null,
  );
  assert.equal(
    verifyGenericActionEvidence(value, { ...expected, workspaceId: "22222222-2222-4222-8222-222222222222" }),
    null,
  );
});

test("generic action and argument hashes use stable canonical input", () => {
  const first = hashGenericActionArguments(actionType, args);
  const reordered = hashGenericActionArguments(actionType, {
    template_id: "guardian-demo-email-v1",
    to: "qa@example.test",
  });
  assert.deepEqual(reordered, first);
  const proposalSha256 = genericActionProposalSha256({
    workspaceId,
    requestedByUserId,
    actionType,
    actionSha256: first.actionSha256,
    ruleId: evaluatedRuleId,
  });
  assert.match(proposalSha256, /^[a-f0-9]{64}$/);
});
