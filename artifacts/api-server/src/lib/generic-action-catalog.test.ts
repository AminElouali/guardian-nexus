import assert from "node:assert/strict";
import { test } from "node:test";
import {
  APPROVAL_ACTION_CATALOG,
  evaluateApprovalAction,
} from "@workspace/db/approval-action-catalog";

test("catalog includes the two existing synthetic actions and two versioned additions", () => {
  assert.deepEqual(
    APPROVAL_ACTION_CATALOG.map(({ actionType }) => actionType),
    [
      "guardian.synthetic.support.refund.v1",
      "guardian.synthetic.finance.bank-change.v1",
      "guardian.support.reply.send.v1",
      "guardian.email.send.external.v1",
    ],
  );
  assert.ok(APPROVAL_ACTION_CATALOG.every((action) =>
    action.defaultDecision === "deny" &&
    action.requiresIndependentApprover &&
    action.allowedApproverRoles.includes("owner") &&
    action.allowedApproverRoles.includes("admin"),
  ));
});

test("unknown action and out-of-schema arguments fail closed", () => {
  const unknown = evaluateApprovalAction("guardian.unlisted.action.v1", {});
  assert.equal(unknown.ok, false);
  if (!unknown.ok) assert.equal(unknown.reasonCode, "unknown_action");

  const extra = evaluateApprovalAction("guardian.email.send.external.v1", {
    to: "demo@example.test",
    subject: "Synthetic",
    body: "Fixture",
    dispatchNow: true,
  });
  assert.equal(extra.ok, false);
  if (!extra.ok) {
    assert.equal(extra.reasonCode, "arguments_invalid");
    assert.ok(extra.issues.includes("unknown_argument:dispatchNow"));
  }
});

test("email proposals are approval-gated and reject recipients outside the sandbox", () => {
  const accepted = evaluateApprovalAction("guardian.email.send.external.v1", {
    to: "qa@example.test",
    template_id: "guardian-demo-email-v1",
  });
  assert.equal(accepted.ok, true);
  if (accepted.ok) {
    assert.equal(accepted.decision, "require_approval");
    assert.equal(accepted.reasonCode, "human_approval_required");
  }

  const disallowed = evaluateApprovalAction("guardian.email.send.external.v1", {
    to: "customer@example.com",
    template_id: "guardian-demo-email-v1",
  });
  assert.equal(disallowed.ok, false);
  if (!disallowed.ok) assert.equal(disallowed.reasonCode, "arguments_invalid");
});

test("support rules allow internal zero-compensation, require approval externally, and deny over 50 EUR", () => {
  const common = {
    ticket_id: "TICKET-SYNTH-123",
    recipient_email: "agent@example.test",
    template_id: "synthetic-support-reply-v1",
  };
  const allowed = evaluateApprovalAction("guardian.support.reply.send.v1", {
    ...common,
    recipient_type: "internal",
    compensation_cents: 0,
  });
  assert.equal(allowed.ok, true);
  if (allowed.ok) assert.equal(allowed.decision, "allow");

  const approvalRequired = evaluateApprovalAction("guardian.support.reply.send.v1", {
    ...common,
    recipient_email: "customer@guardian.invalid",
    recipient_type: "external",
    compensation_cents: 2500,
  });
  assert.equal(approvalRequired.ok, true);
  if (approvalRequired.ok) assert.equal(approvalRequired.decision, "require_approval");

  const denied = evaluateApprovalAction("guardian.support.reply.send.v1", {
    ...common,
    recipient_type: "external",
    compensation_cents: 5001,
  });
  assert.equal(denied.ok, true);
  if (denied.ok) {
    assert.equal(denied.decision, "deny");
    assert.equal(denied.reasonCode, "blocked_by_template");
  }
});

test("recipient restrictions reject email-like values not on a test domain", () => {
  const result = evaluateApprovalAction("guardian.support.reply.send.v1", {
    ticket_id: "TICKET-SYNTH-123",
    recipient_email: "person@real.example",
    recipient_type: "external",
    compensation_cents: 0,
    template_id: "synthetic-support-reply-v1",
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.issues.includes("invalid_argument:recipient_email"));
});
