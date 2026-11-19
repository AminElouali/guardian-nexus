import assert from "node:assert/strict";
import test from "node:test";
import {
  APPROVAL_ACTION_CATALOG,
  evaluateApprovalAction,
  validateApprovalActionArguments,
} from "@workspace/db/approval-action-catalog";
import {
  buildWorkspaceActionRuleProfileDocuments,
  evaluateWorkspaceActionRule,
  MAX_REFUND_LIMIT_CENTS,
} from "@workspace/db";

const REFUND_ACTION = "guardian.synthetic.support.refund.v1";

test("synthetic refund accepts the 10,000 EUR catalog boundary and rejects one cent over", () => {
  const definition = APPROVAL_ACTION_CATALOG.find(
    (item) => item.actionType === REFUND_ACTION,
  );
  assert.ok(definition);

  const atMaximum = {
    ticket_id: "TICKET-SYNTH-BOUNDARY",
    amount_cents: 1_000_000,
  };
  const oneCentOver = {
    ...atMaximum,
    amount_cents: 1_000_001,
  };

  assert.equal(validateApprovalActionArguments(definition, atMaximum).ok, true);
  assert.equal(validateApprovalActionArguments(definition, oneCentOver).ok, false);

  const accepted = evaluateApprovalAction(REFUND_ACTION, atMaximum);
  assert.equal(accepted.ok, true);
  if (accepted.ok) assert.equal(accepted.decision, "require_approval");

  const rejected = evaluateApprovalAction(REFUND_ACTION, oneCentOver);
  assert.equal(rejected.ok, false);
  if (!rejected.ok) {
    assert.equal(rejected.decision, "deny");
    assert.equal(rejected.reasonCode, "arguments_invalid");
    assert.ok(rejected.issues.includes("invalid_argument:amount_cents"));
  }
});

test("configurable refund threshold accepts 10,000 EUR and rejects one cent over", () => {
  assert.equal(MAX_REFUND_LIMIT_CENTS, 1_000_000);

  const atMaximum = buildWorkspaceActionRuleProfileDocuments(
    "balanced-v1",
    1_000_000,
  );
  assert.equal(atMaximum.ok, true);
  if (!atMaximum.ok) return;

  const refundDocument = atMaximum.documents.find(
    (item) => item.actionType === REFUND_ACTION,
  );
  assert.ok(refundDocument);
  const evaluated = evaluateWorkspaceActionRule({
    actionType: REFUND_ACTION,
    arguments: {
      ticket_id: "TICKET-SYNTH-BOUNDARY",
      amount_cents: 1_000_000,
    },
    document: refundDocument.document,
    ruleVersionId: "synthetic-max-threshold-version",
  });
  assert.equal(evaluated.decision, "allow");
  assert.equal(evaluated.ruleId, "refund-within-threshold");

  const overMaximum = buildWorkspaceActionRuleProfileDocuments(
    "balanced-v1",
    1_000_001,
  );
  assert.equal(overMaximum.ok, false);
  if (!overMaximum.ok) {
    assert.ok(overMaximum.issues.includes("refund_limit_out_of_range"));
  }
});
