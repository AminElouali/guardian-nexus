import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  GuardianActionGatewayPanel,
  type GuardianActionGatewayPanelProps,
} from "./GuardianActionGatewayPanel";
import type {
  WorkspaceActionRuleState,
  WorkspaceAgent,
} from "@workspace/api-client-react";

const template: GuardianActionGatewayPanelProps["actionTemplates"][number] = {
  actionType: "support.refund.v1",
  version: "v1.2",
  label: "Solicitar reembolso ficticio",
  description: "Escenario de prueba, sin movimientos de fondos.",
  riskLabel: "Riesgo medio",
  defaultDecision: "deny",
  approverLabel: "Responsable de soporte",
  expiryMinutes: 12,
  requiresIndependentApprover: true,
  proposalEnabled: true,
  argumentFields: [
    { name: "caseId", label: "Identificador de caso", type: "text", required: true },
  ],
  rules: [],
};

function props(overrides: Partial<GuardianActionGatewayPanelProps> = {}): GuardianActionGatewayPanelProps {
  return {
    workspaceId: "ws-test",
    actionTemplates: [template],
    approvals: [{
      id: "approval-test",
      actionType: "support.refund.v1",
      agentIdentity: null,
      summary: null,
      appliedRule: null,
      status: "pending",
      expiresAt: null,
      canDecide: true,
      proposalBinding: null,
      receiptVerification: null,
    }],
    ledgerEvents: [{
      sequence: 4,
      eventType: "approval.proposed",
      approvalId: "approval-test",
      timestamp: "2025-02-10T12:30:00.000Z",
      hash: null,
      receiptState: null,
    }],
    accessState: "available",
    canPropose: true,
    onPropose: async () => ({
      decision: "require_approval",
      reasonCode: "human_approval_required",
      approvalId: "approval-test",
    }),
    onSimulate: async () => ({
      decision: "require_approval",
      reasonCode: "human_approval_required",
      ruleId: "rule-test",
      ruleVersionId: "rule-version-test",
      persisted: false,
      dispatched: false,
    }),
    onDecision: async () => true,
    onExport: () => undefined,
    ...overrides,
  };
}

function markup(overrides: Partial<GuardianActionGatewayPanelProps> = {}) {
  return renderToStaticMarkup(createElement(GuardianActionGatewayPanel, props(overrides)));
}

test("gateway exposes four accessible navigation sections and their content", () => {
  for (const [section, heading] of [
    ["rules", "Reglas por plantillas"],
    ["approvals", "Bandeja de aprobaciones"],
    ["activity", "Actividad"],
    ["connect", "Agentes"],
  ] as const) {
    const html = markup({ initialSection: section });
    assert.match(html, new RegExp(`data-testid="gateway-tab-${section}"`));
    assert.match(html, new RegExp(`aria-selected="true"[^>]*data-testid="gateway-tab-${section}"`));
    assert.match(html, new RegExp(`data-testid="gateway-panel-${section}"`));
    assert.match(html, new RegExp(heading));
  }
});

test("templates show versioned rule and simulator controls with default-block language", () => {
  const html = markup({ initialSection: "rules" });
  assert.match(html, /v1\.2/);
  assert.match(html, /Acciones no listadas: bloqueadas por defecto/);
  assert.match(html, /DEFAULT · DENY/);
  assert.match(html, /Sin regla específica/);
  assert.match(html, /Modo sombra · no intercepta herramientas/);
  assert.match(html, /La previsualización consulta la regla activa guardada/i);
  assert.match(html, /data-testid="gateway-simulator"/);
  assert.match(html, /guardian-template-customer-data-v1/);
  assert.match(html, /guardian-template-internal-email-v1/);
  assert.match(html, /guardian-template-infrastructure-v1/);
  assert.match(html, /data-testid="gateway-action-select"/);
  assert.match(html, /data-testid="gateway-argument-caseId"/);
  assert.match(html, /data-testid="gateway-button-propose"/);
  assert.match(html, /data-testid="gateway-button-simulate"/);
});

test("legacy synthetic actions keep their existing flow instead of using the generic proposal endpoint", () => {
  const html = markup({
    actionTemplates: [{
      ...template,
      actionType: "guardian.synthetic.support.refund.v1",
      proposalEnabled: false,
    }],
  });
  assert.match(html, /mantiene su flujo sintético existente/);
  assert.match(html, /disabled=""[^>]*data-testid="gateway-button-propose"/);
});

test("approval data has explicit unavailable labels and decision controls", () => {
  const html = markup({ initialSection: "approvals", approvalCount: 1 });
  assert.match(html, /data-testid="gateway-approval-agent-approval-test">No disponible/);
  assert.match(html, /<dt>Resumen<\/dt><dd>No disponible/);
  assert.match(html, /<dt>Regla aplicada<\/dt><dd>No disponible/);
  assert.match(html, /<dt>Caducidad<\/dt><dd>No disponible/);
  assert.match(html, /<dt>Vínculo de propuesta<\/dt><dd><code>No disponible/);
  assert.match(html, /data-testid="gateway-approve-approval-test"/);
  assert.match(html, /data-testid="gateway-reject-approval-test"/);
});

test("activity never invents counts and exposes supplied ledger and export controls", () => {
  const html = markup({
    initialSection: "activity",
    approvalCount: null,
    ledgerEventCount: undefined,
    verifiedReceiptCount: null,
    ledgerEvents: [],
  });
  assert.match(html, /data-testid="gateway-count-approvals">No disponible/);
  assert.match(html, /data-testid="gateway-count-events">No disponible/);
  assert.match(html, /data-testid="gateway-count-receipts">No disponible/);
  assert.match(html, /data-testid="gateway-empty-events"/);
  assert.match(html, /data-testid="gateway-button-export"/);
  assert.doesNotMatch(html, /0 registros|0 eventos|0 recibos/);
});

test("activity lists missing approval receipts and enables export only when every hash is present", () => {
  const event = {
    sequence: 1,
    eventType: "approval.approved",
    approvalId: "approval-1",
    timestamp: "2026-05-04T12:00:00.000Z",
    hash: "a".repeat(64),
    receiptId: "receipt-1",
    receiptSha256: "b".repeat(64),
  };
  const missing = markup({
    initialSection: "activity",
    ledgerEvents: [event],
    receipts: [],
  });
  assert.match(missing, /Faltan 1 recibos/);
  assert.match(missing, /approvalId <code>approval-1<\/code>/);
  assert.match(missing, /disabled=""[^>]*data-testid="gateway-button-export"/);

  const loaded = markup({
    initialSection: "activity",
    ledgerEvents: [event],
    receipts: [{ receiptId: "receipt-1", payloadSha256: "b".repeat(64) }],
  });
  assert.doesNotMatch(loaded, /gateway-missing-receipts/);
  assert.doesNotMatch(loaded, /disabled=""[^>]*data-testid="gateway-button-export"/);
});

test("agent connection offers safe setup guidance without generating credentials", () => {
  const html = markup({ initialSection: "connect" });
  assert.match(html, /data-testid="gateway-framework-select"/);
  assert.match(html, /data-testid="gateway-connection-guide"/);
  assert.match(html, /data-testid="gateway-button-safe-command"/);
  assert.match(html, /example\.v1/);
  assert.match(html, /ni genera credenciales/i);
  assert.doesNotMatch(html, /api[_ -]?key|token secreto|generar clave/i);
});

const persistedRuleState: WorkspaceActionRuleState = {
  actionType: "guardian.support.reply.send.v1",
  service: "support",
  label: "Responder a soporte",
  description: "Acción sintética de soporte.",
  riskClass: "medium",
  riskCategories: ["money", "customer_data", "external_email"],
  requiresIndependentApprover: true,
  minimumApproverCount: 1,
  approvalAmountField: "compensation_cents",
  activeApprovalPolicy: null,
  draftApprovalPolicy: null,
  argumentFields: [
    { name: "recipient_email", type: "text", required: true },
    { name: "recipient_type", type: "text", required: true },
    { name: "compensation_cents", type: "number", required: true },
  ],
  activeVersionId: "version-active",
  draftVersionId: "version-draft",
  activeRules: [{
    id: "review-under-50-eur",
    decision: "require_approval",
    when: { all: [{ field: "compensation_cents", op: "lte", value: 5000 }] },
  }],
  draftRules: [{
    id: "block-external",
    decision: "deny",
    when: { all: [{ field: "recipient_type", op: "eq", value: "external" }] },
  }],
  history: [
    {
      id: "version-draft",
      version: 2,
      rules: [{
        id: "block-external",
        decision: "deny",
        when: { all: [{ field: "recipient_type", op: "eq", value: "external" }] },
      }],
      approvalPolicy: null,
      createdByUserId: "user-admin",
      createdAt: "2026-11-17T12:00:00.000Z",
      isActive: false,
      isDraft: true,
    },
    {
      id: "version-active",
      version: 1,
      rules: [{
        id: "review-under-50-eur",
        decision: "require_approval",
        when: { all: [{ field: "compensation_cents", op: "lte", value: 5000 }] },
      }],
      approvalPolicy: null,
      createdByUserId: "user-owner",
      createdAt: "2026-11-16T12:00:00.000Z",
      isActive: true,
      isDraft: false,
    },
  ],
  warnings: ["La regla abierta ha sido bloqueada por defecto."],
  openRuleIds: [],
};

test("saved rule interface exposes immutable history and limits editing to administrators", () => {
  const readOnly = markup({
    initialSection: "rules",
    ruleActions: [persistedRuleState],
    canManage: false,
  });
  assert.match(readOnly, /data-testid="gateway-persisted-rules"/);
  assert.match(readOnly, /data-testid="gateway-rule-history"/);
  assert.match(readOnly, /data-testid="gateway-history-version-1"/);
  assert.match(readOnly, /data-testid="gateway-history-version-2"/);
  assert.match(readOnly, /Solo owner\/admin puede editar/);
  assert.match(readOnly, /textarea[^>]*disabled=""[^>]*data-testid="gateway-rule-editor"/);
  assert.doesNotMatch(readOnly, /data-testid="gateway-rollback-version-1"/);

  const administrator = markup({
    initialSection: "rules",
    ruleActions: [persistedRuleState],
    canManage: true,
  });
  assert.match(administrator, /data-testid="gateway-save-rule-draft"/);
  assert.match(administrator, /data-testid="gateway-activate-rule-draft"/);
  assert.match(administrator, /data-testid="gateway-rollback-version-1"/);
});

test("rule setup exposes versioned starter templates and synthetic pre-activation cases", () => {
  const html = markup({
    initialSection: "rules",
    canManage: true,
    ruleActions: [persistedRuleState],
    starterTemplates: [{
      id: "customer-support-v1",
      label: "Atención al cliente",
      actionType: "guardian.support.reply.send.v1",
      document: {
        version: 1,
        rules: [{
          id: "review-support-v1",
          decision: "require_approval",
          when: {},
        }],
      },
    }],
  });
  assert.match(html, /data-testid="gateway-load-rule-starter"/);
  assert.match(html, /Atención al cliente/);
  assert.match(html, /data-testid="gateway-rule-simulation-version"/);
  assert.match(html, /Borrador · v2/);
  assert.match(html, /data-testid="gateway-synthetic-rule-cases"/);
  assert.match(html, /Cliente interno, sin compensación/);
  assert.match(html, /Destinatario externo, compensación ficticia de 75 €/);
  assert.match(html, /Puedes simular un borrador antes de activarlo/);
});

test("agent management shows scoped identities and active revocation controls only to administrators", () => {
  const agents: WorkspaceAgent[] = [
    {
      id: "agent-1",
      displayName: "Agente sintético",
      principalUserId: "user-admin",
      credentialVersion: 2,
      createdAt: "2026-11-17T12:00:00.000Z",
      revokedAt: null,
      lastUsedAt: null,
    },
    {
      id: "agent-2",
      displayName: "Agente revocado",
      principalUserId: "user-admin",
      credentialVersion: 1,
      createdAt: "2026-11-16T12:00:00.000Z",
      revokedAt: "2026-11-17T12:30:00.000Z",
      lastUsedAt: null,
    },
  ];
  const administrator = markup({
    initialSection: "connect",
    canManage: true,
    agents,
  });
  assert.match(administrator, /data-testid="gateway-create-agent-form"/);
  assert.match(administrator, /data-testid="gateway-rotate-agent-agent-1"/);
  assert.match(administrator, /data-testid="gateway-revoke-agent-agent-1"/);
  assert.match(administrator, /data-testid="gateway-agent-status-agent-2">Revocado/);
  assert.match(administrator, /gateway-rotate-agent-agent-2/);
  assert.match(administrator, /Último uso/);
  assert.match(administrator, /solo permanece en memoria de esta pantalla/i);

  const member = markup({
    initialSection: "connect",
    canManage: false,
    agents,
  });
  assert.match(member, /Solo owner\/admin puede registrar agentes/);
  assert.doesNotMatch(member, /gateway-create-agent-form/);
  assert.doesNotMatch(member, /gateway-rotate-agent-agent-1/);
  assert.doesNotMatch(member, /gateway-rotate-agent-agent-2/);
});
