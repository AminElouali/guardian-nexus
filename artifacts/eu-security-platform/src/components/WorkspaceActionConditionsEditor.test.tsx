import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { WorkspaceActionRuleState } from "@workspace/api-client-react";
import {
  buildConditionalActionRule,
  buildConditionalActionRules,
  WorkspaceActionConditionsEditor,
} from "./WorkspaceActionConditionsEditor";

const action: WorkspaceActionRuleState = {
  actionType: "guardian.email.send.external.v1",
  service: "email",
  label: "Correo externo",
  description: "Envío sintético.",
  riskClass: "high",
  riskCategories: ["external_email"],
  requiresIndependentApprover: true,
  minimumApproverCount: 1,
  approvalAmountField: null,
  activeApprovalPolicy: null,
  draftApprovalPolicy: null,
  argumentFields: [
    { name: "to", type: "text", required: true },
    { name: "template_id", type: "text", required: true },
  ],
  activeVersionId: null,
  draftVersionId: null,
  activeRules: [],
  draftRules: [],
  history: [],
  warnings: [],
  openRuleIds: [],
};

test("condition builder creates strict trusted-domain, environment, and volume clauses", () => {
  const domain = buildConditionalActionRule("allow", [{
    field: "to",
    op: "domain_in",
    value: "Example.test, trusted.example",
    windowSeconds: "3600",
  }]);
  assert.deepEqual(domain?.when.all, [{
    field: "to",
    op: "domain_in",
    value: ["example.test", "trusted.example"],
  }]);

  const volume = buildConditionalActionRule("deny", [{
    field: "context.action_count",
    op: "gt",
    value: "8",
    windowSeconds: "3600",
  }]);
  assert.deepEqual(volume?.when.all, [{
    field: "context.action_count",
    op: "gt",
    value: 8,
    windowSeconds: 3600,
  }]);
});

test("condition builder rejects missing values and unsupported windows", () => {
  assert.equal(buildConditionalActionRule("allow", [{
    field: "to",
    op: "domain_in",
    value: "",
    windowSeconds: "3600",
  }]), null);
  assert.equal(buildConditionalActionRule("allow", [{
    field: "context.action_count",
    op: "gt",
    value: "10",
    windowSeconds: "17",
  }]), null);
});

test("approval tier controls show the saved euro threshold and critical actions require two people", () => {
  const refundAction: WorkspaceActionRuleState = {
    ...action,
    actionType: "guardian.synthetic.support.refund.v1",
    service: "support",
    label: "Reembolso sintético",
    approvalAmountField: "amount_cents",
    activeApprovalPolicy: { amountThresholdCents: 7500 },
    argumentFields: [
      { name: "ticket_id", type: "text", required: true },
      { name: "amount_cents", type: "number", required: true },
    ],
  };
  const refundHtml = renderToStaticMarkup(createElement(
    WorkspaceActionConditionsEditor,
    {
      actions: [refundAction],
      canManage: true,
      busy: false,
      onSave: async () => undefined,
    },
  ));
  assert.match(refundHtml, /Tramo de aprobación/);
  assert.match(refundHtml, /value="75"/);

  const bankHtml = renderToStaticMarkup(createElement(
    WorkspaceActionConditionsEditor,
    {
      actions: [{
        ...refundAction,
        actionType: "guardian.synthetic.finance.bank-change.v1",
        service: "finance",
        label: "Cambio de cuenta bancaria",
        approvalAmountField: null,
        minimumApproverCount: 2,
        activeApprovalPolicy: null,
      }],
      canManage: true,
      busy: false,
      onSave: async () => undefined,
    },
  ));
  assert.match(bankHtml, /requiere dos aprobaciones de personas distintas/);
});

test("condition builder creates an explicit fallback decision instead of allowing unmatched cases", () => {
  assert.deepEqual(
    buildConditionalActionRules("allow", "require_approval", [{
      field: "context.action_count",
      op: "lte",
      value: "20",
      windowSeconds: "3600",
    }]),
    [
      {
        id: "workspace-conditional-policy",
        decision: "allow",
        when: {
          all: [{
            field: "context.action_count",
            op: "lte",
            value: 20,
            windowSeconds: 3600,
          }],
        },
      },
      {
        id: "workspace-conditional-fallback",
        decision: "require_approval",
        when: {},
      },
    ],
  );
});

test("conditions editor explains versioning and restricts editing to administrators", () => {
  const html = renderToStaticMarkup(createElement(WorkspaceActionConditionsEditor, {
    actions: [action],
    canManage: false,
    busy: false,
    onSave: async () => undefined,
  }));
  assert.match(html, /Ajusta una acción/);
  assert.match(html, /Si un dato de contexto no se puede comprobar/);
  assert.match(html, /Solo owner o admin puede cambiar/);
  assert.doesNotMatch(html, /data-testid="condition-save"/);
});
