import assert from "node:assert/strict";
import test from "node:test";
import { APPROVAL_ACTION_CATALOG } from "./approval-action-catalog";
import {
  evaluateWorkspaceActionRule,
  buildWorkspaceActionRuleProfileDocuments,
  getWorkspaceActionRuleProfiles,
  getWorkspaceRuleWarnings,
  getStarterWorkspaceRuleTemplates,
  MAX_REFUND_LIMIT_CENTS,
  MAX_APPROVAL_TIER_THRESHOLD_CENTS,
  getWorkspaceActionApprovalRequirements,
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
  assert.equal(templates.length, 30);
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

test("read-only profile allows catalog reads and denies writes while prudent requires review", () => {
  const readOnly = buildWorkspaceActionRuleProfileDocuments(
    "read-only-v1",
    5000,
  );
  const prudent = buildWorkspaceActionRuleProfileDocuments("prudent-v1", 5000);
  assert.equal(readOnly.ok, true);
  assert.equal(prudent.ok, true);
  if (!readOnly.ok || !prudent.ok) return;
  assert.equal(readOnly.documents.length, 30);
  for (const item of readOnly.documents) {
    const definition = APPROVAL_ACTION_CATALOG.find(
      (candidate) => candidate.actionType === item.actionType,
    );
    assert.ok(definition, `${item.actionType} must exist in the catalogue`);
    assert.ok(item.document.rules.length > 0, `${item.actionType} must have a policy`);
    assert.ok(
      item.document.rules.every((rule) =>
        rule.decision === (definition.readOnly ? "allow" : "deny"),
      ),
      `${item.actionType} must follow its read-only classification`,
    );
  }
  assert.ok(
    prudent.documents.every((item) =>
      item.document.rules.every(
        (rule) => rule.decision !== "allow",
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

test("workspace rules evaluate trusted domains with an exact recipient match", () => {
  const parsed = validateWorkspaceActionRuleDocument(
    "guardian.email.send.external.v1",
    {
      version: 1,
      rules: [{
        id: "trusted-domain",
        decision: "allow",
        when: {
          all: [{
            field: "to",
            op: "domain_in",
            value: ["example.test"],
          }],
        },
      }],
    },
  );
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  const evaluate = (to: string) => evaluateWorkspaceActionRule({
    actionType: "guardian.email.send.external.v1",
    arguments: { to, template_id: "guardian-demo-email-v1" },
    document: parsed.document,
    ruleVersionId: "domain-version",
    context: {
      dataSensitivity: "normal",
      environment: "test",
      actionCountsByWindow: {},
    },
  });
  assert.equal(evaluate("demo@example.test").decision, "allow");
  assert.equal(evaluate("demo@sub.example.test").decision, "deny");
});

test("workspace rules reject malformed trusted domains and extra window fields", () => {
  for (const value of [["Example.test"], ["*.example.test"], ["example.test."]]) {
    assert.equal(
      validateWorkspaceActionRuleDocument("guardian.email.send.external.v1", {
        version: 1,
        rules: [{
          id: "invalid-domain",
          decision: "allow",
          when: { all: [{ field: "to", op: "domain_in", value }] },
        }],
      }).ok,
      false,
    );
  }
  assert.equal(
    validateWorkspaceActionRuleDocument("guardian.email.send.external.v1", {
      version: 1,
      rules: [{
        id: "unexpected-window",
        decision: "allow",
        when: {
          all: [{
            field: "to",
            op: "eq",
            value: "demo@example.test",
            windowSeconds: 3600,
          }],
        },
      }],
    }).ok,
    false,
  );
});

test("trusted sensitivity, environment, and action-volume conditions use server context", () => {
  const parsed = validateWorkspaceActionRuleDocument(
    "guardian.email.send.external_sensitive.v1",
    {
      version: 1,
      rules: [{
        id: "bounded-sensitive-test",
        decision: "require_approval",
        when: {
          all: [
            { field: "context.data_sensitivity", op: "eq", value: "sensitive" },
            { field: "context.environment", op: "eq", value: "test" },
            {
              field: "context.action_count",
              op: "gt",
              value: 4,
              windowSeconds: 3600,
            },
          ],
        },
      }],
    },
  );
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  const result = evaluateWorkspaceActionRule({
    actionType: "guardian.email.send.external_sensitive.v1",
    arguments: {
      to: "demo@example.test",
      template_id: "guardian-sensitive-email-v1",
      has_attachments: true,
      contains_customer_data: true,
    },
    document: parsed.document,
    ruleVersionId: "context-version",
    context: {
      dataSensitivity: "sensitive",
      environment: "test",
      actionCountsByWindow: { 3600: 5 },
    },
  });
  assert.equal(result.decision, "require_approval");
  assert.equal(result.ruleId, "bounded-sensitive-test");
  assert.equal(result.ruleVersionId, "context-version");
  assert.equal(
    validateWorkspaceActionRuleDocument("guardian.email.send.external.v1", {
      version: 1,
      rules: [{
        id: "bad-window",
        decision: "allow",
        when: {
          all: [{
            field: "context.action_count",
            op: "gt",
            value: 2,
            windowSeconds: 17,
          }],
        },
      }],
    }).ok,
    false,
  );
});

test("a rule condition with unavailable trusted context never allows", () => {
  const parsed = validateWorkspaceActionRuleDocument(
    "guardian.email.send.external.v1",
    {
      version: 1,
      rules: [{
        id: "only-in-test",
        decision: "allow",
        when: { all: [{ field: "context.environment", op: "eq", value: "test" }] },
      }],
    },
  );
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  const result = evaluateWorkspaceActionRule({
    actionType: "guardian.email.send.external.v1",
    arguments: { to: "demo@example.test", template_id: "guardian-demo-email-v1" },
    document: parsed.document,
    ruleVersionId: "missing-context-version",
  });
  assert.equal(result.decision, "require_approval");
  assert.equal(result.reasonCode, "workspace_rule_condition_unavailable");
});

test("approval tiers use the versioned threshold and stricter catalog requirements", () => {
  const parsed = validateWorkspaceActionRuleDocument(
    "guardian.synthetic.support.refund.v1",
    {
      version: 1,
      approvalPolicy: { amountThresholdCents: 5000 },
      rules: [],
    },
  );
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  assert.deepEqual(
    getWorkspaceActionApprovalRequirements(
      "guardian.synthetic.support.refund.v1",
      { amount_cents: 5000 },
      parsed.document,
    ),
    { requiredApprovers: 1, allowedApproverRoles: ["admin"] },
  );
  assert.deepEqual(
    getWorkspaceActionApprovalRequirements(
      "guardian.synthetic.support.refund.v1",
      { amount_cents: 5001 },
      parsed.document,
    ),
    { requiredApprovers: 1, allowedApproverRoles: ["owner"] },
  );
  assert.deepEqual(
    getWorkspaceActionApprovalRequirements(
      "guardian.synthetic.finance.bank-change.v1",
      {},
      null,
    ),
    { requiredApprovers: 2, allowedApproverRoles: ["owner", "admin"] },
  );
  assert.deepEqual(
    getWorkspaceActionApprovalRequirements(
      "guardian.synthetic.support.refund.v1",
      { amount_cents: 5001 },
      null,
    ),
    { requiredApprovers: 1, allowedApproverRoles: ["owner"] },
    "an older or unconfigured rule document still defaults the high tier to owner",
  );
});

test("approval tier documents reject missing, malformed, and excessive thresholds", () => {
  const action = "guardian.synthetic.support.refund.v1";
  assert.equal(
    validateWorkspaceActionRuleDocument(action, {
      version: 1,
      approvalPolicy: { amountThresholdCents: 0 },
      rules: [],
    }).ok,
    false,
  );
  assert.equal(
    validateWorkspaceActionRuleDocument(action, {
      version: 1,
      approvalPolicy: { amountThresholdCents: MAX_APPROVAL_TIER_THRESHOLD_CENTS + 1 },
      rules: [],
    }).ok,
    false,
  );
  assert.equal(
    validateWorkspaceActionRuleDocument("guardian.email.send.external.v1", {
      version: 1,
      approvalPolicy: { amountThresholdCents: 5000 },
      rules: [],
    }).ok,
    false,
  );
  assert.equal(
    getWorkspaceActionApprovalRequirements(action, {}, {
      version: 1,
      approvalPolicy: { amountThresholdCents: 5000 },
      rules: [],
    }),
    null,
  );
});
