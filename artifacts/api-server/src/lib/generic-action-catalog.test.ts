import assert from "node:assert/strict";
import { test } from "node:test";
import {
  APPROVAL_ACTION_RISK_TYPES,
  APPROVAL_ACTION_CATALOG,
  evaluateApprovalAction,
} from "@workspace/db/approval-action-catalog";
import {
  buildWorkspaceActionRuleProfileDocuments,
  evaluateWorkspaceActionRule,
  type WorkspaceActionRuleDocument,
} from "@workspace/db/workspace-action-rule-engine";

test("catalog contains the four existing actions and the eight-service synthetic expansion", () => {
  assert.deepEqual(
    APPROVAL_ACTION_CATALOG.map(({ actionType }) => actionType),
    [
      "guardian.synthetic.support.refund.v1",
      "guardian.synthetic.finance.bank-change.v1",
      "guardian.support.reply.send.v1",
      "guardian.email.send.external.v1",
      "guardian.email.reply.internal.v1",
      "guardian.email.send.external_sensitive.v1",
      "guardian.email.forwarding_rule.create.v1",
      "guardian.support.customer_account.close.v1",
      "guardian.finance.balance_invoice.read.v1",
      "guardian.finance.vendor_payment.known.v1",
      "guardian.finance.vendor_payment.new.v1",
      "guardian.data.query.read.v1",
      "guardian.data.customer.export.v1",
      "guardian.data.bulk.modify.v1",
      "guardian.data.bulk.delete.v1",
      "guardian.code.pull_request.open.v1",
      "guardian.code.pull_request.merge_main.v1",
      "guardian.code.deploy.production.v1",
      "guardian.code.secret.access.v1",
      "guardian.web.navigate.read.v1",
      "guardian.web.personal_data.submit.v1",
      "guardian.web.purchase.v1",
      "guardian.web.unapproved_credentials.submit.v1",
      "guardian.cloud.resource.read.v1",
      "guardian.cloud.resource.create.v1",
      "guardian.cloud.iam.permission.change.v1",
      "guardian.cloud.production_destructive.v1",
      "guardian.multiagent.delegate_equal_or_lower.v1",
      "guardian.multiagent.delegate_higher_scope.v1",
      "guardian.multiagent.privilege_escalation.v1",
    ],
  );
  assert.ok(APPROVAL_ACTION_CATALOG.every((action) =>
    action.defaultDecision === "deny" &&
    action.allowedApproverRoles.includes("owner") &&
    action.allowedApproverRoles.includes("admin") &&
    action.argumentSchema.additionalProperties === false &&
    action.syntheticTemplateText?.startsWith("[SYNTHETIC]"),
  ));
  assert.equal(new Set(APPROVAL_ACTION_CATALOG.map((action) => action.actionType)).size, 30);
  assert.deepEqual(
    [...new Set(APPROVAL_ACTION_CATALOG.map((action) => action.service))].sort(),
    ["cloud", "code", "data", "email", "finance", "multiagent", "support", "web"],
  );
  const expectedProfileByService = {
    email: "guardian-agent-lab-email-v1",
    support: "guardian-agent-lab-customer-service-v1",
    finance: "guardian-agent-lab-finance-v1",
    data: "guardian-agent-lab-database-v1",
    code: "guardian-agent-lab-programming-v1",
    web: "guardian-agent-lab-browser-v1",
    cloud: "guardian-agent-lab-infrastructure-v1",
    multiagent: "guardian-agent-lab-multiagent-v1",
  } as const;
  for (const action of APPROVAL_ACTION_CATALOG) {
    assert.equal(action.profileId, expectedProfileByService[action.service]);
  }
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

test("the catalog exposes all risk types and keeps unknown actions denied", () => {
  assert.deepEqual(APPROVAL_ACTION_RISK_TYPES, [
    "read",
    "internal_write",
    "external_send",
    "money_movement",
    "permission_change",
    "delete_or_export",
    "execute_or_deploy",
    "corporate_commitment",
  ]);
  assert.equal(APPROVAL_ACTION_CATALOG.length, 30);
  for (const action of APPROVAL_ACTION_CATALOG) {
    assert.ok(action.riskTypes.length > 0, `${action.actionType} is classified`);
    assert.ok(
      action.riskTypes.every((risk) =>
        APPROVAL_ACTION_RISK_TYPES.includes(risk),
      ),
    );
  }
  const represented = new Set(
    APPROVAL_ACTION_CATALOG.flatMap((action) => action.riskTypes),
  );
  assert.ok(represented.has("money_movement"));
  assert.ok(represented.has("internal_write"));
  assert.ok(represented.has("external_send"));
  assert.equal(
    evaluateApprovalAction("guardian.unclassified.v1", {}).ok,
    false,
  );
});

test("balanced, prudent, and read-only templates define every catalog action", () => {
  const balanced = buildWorkspaceActionRuleProfileDocuments("balanced-v1", 5000);
  const prudent = buildWorkspaceActionRuleProfileDocuments("prudent-v1", 5000);
  const readOnly = buildWorkspaceActionRuleProfileDocuments("read-only-v1", 5000);
  assert.equal(balanced.ok, true);
  assert.equal(prudent.ok, true);
  assert.equal(readOnly.ok, true);
  if (balanced.ok !== true || prudent.ok !== true || readOnly.ok !== true) return;
  type ProfileDocument = {
    actionType: string;
    document: WorkspaceActionRuleDocument;
  };
  const findProfileDocument = (
    documents: ProfileDocument[],
    actionType: string,
  ): ProfileDocument | undefined => documents.find((item) => item.actionType === actionType);

  for (const action of APPROVAL_ACTION_CATALOG) {
    const balancedDoc = findProfileDocument(balanced.documents, action.actionType);
    const prudentDoc = findProfileDocument(prudent.documents, action.actionType);
    const readOnlyDoc = findProfileDocument(readOnly.documents, action.actionType);
    assert.ok(balancedDoc, `${action.actionType} has a balanced policy`);
    assert.ok(prudentDoc, `${action.actionType} has a prudent policy`);
    assert.ok(readOnlyDoc, `${action.actionType} has a read-only policy`);
    if (action.actionType === "guardian.synthetic.support.refund.v1") {
      assert.deepEqual(
        balancedDoc.document.rules.map(({ id, decision }) => ({ id, decision })),
        [
          { id: "refund-within-threshold", decision: "allow" },
          { id: "refund-above-threshold", decision: "require_approval" },
        ],
      );
      assert.ok(prudentDoc.document.rules.every((rule) => rule.decision === "require_approval"));
    } else if (action.actionType === "guardian.support.reply.send.v1") {
      assert.deepEqual(
        balancedDoc.document.rules.map(({ id, decision }) => ({ id, decision })),
        [
          { id: "support-sensitive-external-or-high-compensation", decision: "require_approval" },
          { id: "support-routine-internal", decision: "allow" },
        ],
      );
    } else {
      assert.deepEqual(
        balancedDoc.document.rules.map(({ id, decision }) => ({ id, decision })),
        action.rules.map(({ id, decision }) => ({ id, decision })),
      );
      assert.deepEqual(
        prudentDoc.document.rules.map((rule) => rule.decision),
        action.rules.map((rule) =>
          rule.decision === "allow" ? "require_approval" : rule.decision,
        ),
      );
    }
    assert.ok(
      readOnlyDoc.document.rules.every((rule) =>
        rule.decision === (action.readOnly ? "allow" : "deny"),
      ),
      `${action.actionType} has only its read-only status in the read-only template`,
    );
  }
});

test("balanced decisions cover routine actions and preserve approval or deny boundaries", () => {
  const balanced = buildWorkspaceActionRuleProfileDocuments("balanced-v1", 5000);
  const readOnly = buildWorkspaceActionRuleProfileDocuments("read-only-v1", 5000);
  assert.equal(balanced.ok, true);
  assert.equal(readOnly.ok, true);
  if (balanced.ok !== true || readOnly.ok !== true) return;
  type SuccessfulProfile = Extract<
    ReturnType<typeof buildWorkspaceActionRuleProfileDocuments>,
    { ok: true }
  >;
  const evaluateProfile = (
    profile: SuccessfulProfile,
    actionType: string,
    args: Record<string, string | number | boolean>,
  ) => {
    const document = profile.documents.find((item) => item.actionType === actionType);
    assert.ok(document, `${actionType} has a profile document`);
    return evaluateWorkspaceActionRule({
      actionType,
      arguments: args,
      document: document.document,
      ruleVersionId: "11111111-1111-4111-8111-111111111111",
    }).decision;
  };
  const internalEmailArgs = {
    thread_id: "THREAD-SYNTH-42",
    to: "agent@guardian.invalid",
    template_id: "guardian-internal-reply-v1",
  };
  assert.equal(
    evaluateProfile(balanced, "guardian.email.reply.internal.v1", internalEmailArgs),
    "allow",
  );
  assert.equal(
    evaluateProfile(balanced, "guardian.data.query.read.v1", {
      query_id: "demo.open-items.v1",
      scope_id: "DATA-SYNTH-42",
    }),
    "allow",
  );
  assert.equal(
    evaluateProfile(balanced, "guardian.finance.vendor_payment.known.v1", {
      vendor_id: "VENDOR-SYNTH-42",
      amount_cents: 10_000,
      invoice_id: "INVOICE-SYNTH-42",
    }),
    "require_approval",
  );
  assert.equal(
    evaluateProfile(balanced, "guardian.finance.vendor_payment.new.v1", {
      vendor_id: "VENDOR-SYNTH-43",
      amount_cents: 10_000,
      invoice_id: "INVOICE-SYNTH-42",
    }),
    "deny",
  );
  assert.equal(
    evaluateProfile(balanced, "guardian.email.forwarding_rule.create.v1", {
      mailbox_id: "MAILBOX-SYNTH-42",
      forward_to: "qa@example.test",
    }),
    "deny",
  );
  assert.equal(
    evaluateProfile(readOnly, "guardian.web.navigate.read.v1", {
      page_id: "PAGE-SYNTH-42",
      host: "example.test",
    }),
    "allow",
  );
  assert.equal(
    evaluateProfile(readOnly, "guardian.code.pull_request.open.v1", {
      repository_id: "REPO-SYNTH-42",
      title: "Demo change",
      source_branch: "feature/demo",
    }),
    "deny",
  );
});

test("external email accepts a syntactically valid address but remains approval-gated", () => {
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
  assert.equal(disallowed.ok, true);
  if (disallowed.ok) assert.equal(disallowed.decision, "require_approval");

  const malformed = evaluateApprovalAction("guardian.email.send.external.v1", {
    to: "customer@not-a-domain",
    template_id: "guardian-demo-email-v1",
  });
  assert.equal(malformed.ok, false);
  if (!malformed.ok) assert.equal(malformed.reasonCode, "arguments_invalid");
});

test("support rules allow routine internal replies and require approval for high compensation", () => {
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

  const approvalRequiredAboveLimit = evaluateApprovalAction("guardian.support.reply.send.v1", {
    ...common,
    recipient_type: "external",
    compensation_cents: 5001,
  });
  assert.equal(approvalRequiredAboveLimit.ok, true);
  if (approvalRequiredAboveLimit.ok) {
    assert.equal(approvalRequiredAboveLimit.decision, "require_approval");
    assert.equal(approvalRequiredAboveLimit.reasonCode, "human_approval_required");
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
