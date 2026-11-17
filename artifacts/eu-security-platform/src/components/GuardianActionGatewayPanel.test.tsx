import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  GuardianActionGatewayPanel,
  type GuardianActionGatewayPanelProps,
} from "./GuardianActionGatewayPanel";

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
    onPropose: () => undefined,
    onDecision: () => undefined,
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
    ["connect", "Conectar agente"],
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
  assert.match(html, /No hay regla específica/);
  assert.match(html, /Modo sombra · solo observación/);
  assert.match(html, /el modo sombra no bloquea la ejecución/i);
  assert.match(html, /data-testid="gateway-simulator"/);
  assert.match(html, /data-testid="gateway-action-select"/);
  assert.match(html, /data-testid="gateway-argument-caseId"/);
  assert.match(html, /data-testid="gateway-button-propose"/);
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

test("agent connection offers safe setup guidance without generating credentials", () => {
  const html = markup({ initialSection: "connect" });
  assert.match(html, /data-testid="gateway-framework-select"/);
  assert.match(html, /data-testid="gateway-connection-guide"/);
  assert.match(html, /data-testid="gateway-button-safe-command"/);
  assert.match(html, /printf %s/);
  assert.match(html, /no genera credenciales/i);
  assert.doesNotMatch(html, /api[_ -]?key|token secreto|generar clave/i);
});
