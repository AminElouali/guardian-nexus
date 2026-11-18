import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateWorkspaceActionRule,
  getWorkspaceRuleWarnings,
  getStarterWorkspaceRuleTemplates,
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
