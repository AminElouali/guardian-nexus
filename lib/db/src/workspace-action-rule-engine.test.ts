import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateWorkspaceActionRule,
  buildWorkspaceActionRuleProfileDocuments,
  getWorkspaceActionRuleProfiles,
  getWorkspaceRuleWarnings,
  getStarterWorkspaceRuleTemplates,
  MAX_REFUND_LIMIT_CENTS,
  validateWorkspaceActionRuleDocument,
} from "./workspace-action-rule-engine";

test("workspace rule evaluator denies actions without saved configuration", () => {
  const result = evaluateWorkspaceActionRule({
    actionType: "guardian.support.reply.send.v1",
    arguments: {
      ticket_id: "TICKET-SYNTH-42",
      recipient_email: "demo@example.test",
      recipient_type: "internal",
      compensation_cents: 0,
      template_id: "synthetic-support-reply-v1",
    },
    document: null,
    ruleVersionId: null,
  });
  assert.equal(result.decision, "deny");
  assert.equal(result.reasonCode, "workspace_rule_not_configured");
});

test("workspace rule evaluator binds its decision to the selected immutable version", () => {
  const parsed = validateWorkspaceActionRuleDocument(
    "guardian.support.reply.send.v1",
    {
      version: 1,
      rules: [
        {
          id: "internal-no-compensation",
          decision: "allow",
          when: {
            all: [
              { field: "recipient_type", op: "eq", value: "internal" },
              { field: "compensation_cents", op: "eq", value: 0 },
            ],
          },
        },
      ],
    },
  );
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  const result = evaluateWorkspaceActionRule({
    actionType: "guardian.support.reply.send.v1",
    arguments: {
      ticket_id: "TICKET-SYNTH-42",
      recipient_email: "demo@example.test",
      recipient_type: "internal",
      compensation_cents: 0,
      template_id: "synthetic-support-reply-v1",
    },
    document: parsed.document,
    ruleVersionId: "version-uuid",
  });
  assert.equal(result.decision, "allow");
  assert.equal(result.ruleId, "internal-no-compensation");
  assert.equal(result.ruleVersionId, "version-uuid");
});

test("workspace rule validator rejects unknown actions, fields, operators, and extra keys", () => {
  assert.deepEqual(
    validateWorkspaceActionRuleDocument("not-a-catalog-action", { version: 1, rules: [] }),
    { ok: false, issues: ["unknown_action"] },
  );
  assert.equal(
    validateWorkspaceActionRuleDocument("guardian.email.send.external.v1", {
      version: 1,
      rules: [{ id: "open", decision: "allow", when: { all: [{ field: "unknown", op: "eq", value: true }] } }],
    }).ok,
    false,
  );
  assert.equal(
    validateWorkspaceActionRuleDocument("guardian.email.send.external.v1", {
      version: 1,
      rules: [{ id: "open", decision: "allow", when: {}, unexpected: true }],
    }).ok,
    false,
  );
});

test("starter templates include a customer support policy and all catalog actions", () => {
  const templates = getStarterWorkspaceRuleTemplates();
  assert.ok(templates.some((template) => template.id === "customer-support-v1"));
  assert.equal(templates.length, 4);
});

test("workspace profiles are versioned templates and validate a positive bounded refund limit", () => {
  const profiles = getWorkspaceActionRuleProfiles();
  assert.deepEqual(
    profiles.map(({ id, label, defaultRefundLimitCents }) => ({
      id,
      label,
      defaultRefundLimitCents,
    })),
    [
      { id: "prudent-v1", label: "Prudente", defaultRefundLimitCents: 5000 },
      { id: "balanced-v1", label: "Equilibrada", defaultRefundLimitCents: 5000 },
      { id: "read-only-v1", label: "Solo lectura", defaultRefundLimitCents: 5000 },
    ],
  );
  assert.equal(MAX_REFUND_LIMIT_CENTS, 1_000_000);
  assert.equal(
    buildWorkspaceActionRuleProfileDocuments("balanced-v1", 0).ok,
    false,
  );
  assert.equal(
    buildWorkspaceActionRuleProfileDocuments(
      "balanced-v1",
      MAX_REFUND_LIMIT_CENTS + 1,
    ).ok,
    false,
  );
  assert.equal(
    buildWorkspaceActionRuleProfileDocuments("unknown-profile", 5000).ok,
    false,
  );
});

test("balanced profile uses the server rule engine below and above its saved limit", () => {
  const built = buildWorkspaceActionRuleProfileDocuments("balanced-v1", 6500);
  assert.equal(built.ok, true);
  if (!built.ok) return;

  const refund = built.documents.find(
    (item) => item.actionType === "guardian.synthetic.support.refund.v1",
  );
  assert.ok(refund);
  const below = evaluateWorkspaceActionRule({
    actionType: refund.actionType,
    arguments: {
      ticket_id: "TICKET-SYNTH-42",
      amount_cents: 6500,
    },
    document: refund.document,
    ruleVersionId: "saved-version",
  });
  const above = evaluateWorkspaceActionRule({
    actionType: refund.actionType,
    arguments: {
      ticket_id: "TICKET-SYNTH-42",
      amount_cents: 6501,
    },
    document: refund.document,
    ruleVersionId: "saved-version",
  });
  assert.equal(below.decision, "allow");
  assert.equal(below.ruleId, "refund-within-threshold");
  assert.equal(below.ruleVersionId, "saved-version");
  assert.equal(above.decision, "require_approval");
  assert.equal(above.ruleId, "refund-above-threshold");
  assert.equal(above.ruleVersionId, "saved-version");
});

test("read-only profile denies every catalog action while prudent requires review for money and outbound actions", () => {
  const readOnly = buildWorkspaceActionRuleProfileDocuments(
    "read-only-v1",
    5000,
  );
  const prudent = buildWorkspaceActionRuleProfileDocuments("prudent-v1", 5000);
  assert.equal(readOnly.ok, true);
  assert.equal(prudent.ok, true);
  if (!readOnly.ok || !prudent.ok) return;
  assert.equal(readOnly.documents.length, 4);
  for (const item of readOnly.documents) {
    const args =
      item.actionType === "guardian.synthetic.support.refund.v1"
        ? { ticket_id: "TICKET-SYNTH-42", amount_cents: 2500 }
        : item.actionType === "guardian.synthetic.finance.bank-change.v1"
          ? { account_id: "LAB-ACCOUNT-42", new_iban: "DE00LAB0123456789ABCDEF" }
          : item.actionType === "guardian.email.send.external.v1"
            ? { to: "demo@example.test", template_id: "guardian-demo-email-v1" }
            : {
                ticket_id: "TICKET-SYNTH-42",
                recipient_email: "demo@example.test",
                recipient_type: "internal",
                compensation_cents: 0,
                template_id: "synthetic-support-reply-v1",
              };
    assert.equal(
      evaluateWorkspaceActionRule({
        actionType: item.actionType,
        arguments: args,
        document: item.document,
        ruleVersionId: "read-only-version",
      }).decision,
      "deny",
      `${item.actionType} must be blocked by the read-only profile`,
    );
  }
  assert.ok(
    prudent.documents.every((item) =>
      item.document.rules.every(
        (rule) => rule.decision === "require_approval",
      ),
    ),
  );
});

test("broad and contradictory rules produce visible warnings", () => {
  const parsed = validateWorkspaceActionRuleDocument(
    "guardian.email.send.external.v1",
    {
      version: 1,
      rules: [
        { id: "allow-any", decision: "allow", when: {} },
        { id: "deny-any", decision: "deny", when: {} },
      ],
    },
  );
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  const warnings = getWorkspaceRuleWarnings(
    "guardian.email.send.external.v1",
    parsed.document,
  );
  assert.deepEqual(
    warnings.map((warning) => warning.code).sort(),
    ["contradictory_rules", "unbounded_recipient", "unconditional_allow"],
  );
});

test("rule conditions cannot exceed the action argument schema", () => {
  const result = validateWorkspaceActionRuleDocument(
    "guardian.support.reply.send.v1",
    {
      version: 1,
      rules: [
        {
          id: "over-limit",
          decision: "allow",
          when: { all: [{ field: "compensation_cents", op: "gt", value: 1000001 }] },
        },
      ],
    },
  );
  assert.equal(result.ok, false);
});
