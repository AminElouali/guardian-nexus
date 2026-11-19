import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  WorkspaceActionRuleProfile,
  WorkspaceActionRuleHistoryImpactResponse,
  WorkspaceActionRuleSimulationResponse,
  WorkspaceActionRuleState,
} from "@workspace/api-client-react";
import {
  buildWorkspaceActionRuleDocument,
  buildWorkspaceActionRules,
  DEFAULT_REFUND_LIMIT_CENTS,
  defaultRuleDecisions,
  formatSimulationResult,
  formatHistoryImpactCoverage,
  historyImpactEmptyMessage,
  IMMUTABLE_DEFAULT_DENY,
  parseRefundLimitEuros,
  PROFILE_DRAFT_STATUS,
  SIMULATION_SAFETY_COPY,
  WorkspaceRulesEditor,
  type WorkspaceRulesEditorProps,
} from "./WorkspaceRulesEditor";

const actions: WorkspaceActionRuleState[] = [
  {
    actionType: "guardian.synthetic.support.refund.v1",
    label: "Reembolso sintético",
    description: "Reembolso de laboratorio.",
    riskClass: "high",
    riskCategories: ["money"],
    activeVersionId: "refund-v1",
    draftVersionId: null,
    activeRules: [],
    draftRules: [],
    history: [{
      id: "refund-v1",
      version: 1,
      rules: [],
      createdByUserId: "owner",
      createdAt: "2026-01-01T00:00:00.000Z",
      isActive: true,
      isDraft: false,
    }],
    warnings: [],
    openRuleIds: [],
  },
  {
    actionType: "guardian.synthetic.finance.bank-change.v1",
    label: "Cambio bancario sintético",
    description: "Cambio bancario de prueba.",
    riskClass: "high",
    riskCategories: ["money"],
    activeVersionId: null,
    draftVersionId: null,
    activeRules: [],
    draftRules: [],
    history: [],
    warnings: [],
    openRuleIds: [],
  },
  {
    actionType: "guardian.email.send.external.v1",
    label: "Correo externo",
    description: "Envío sintético.",
    riskClass: "high",
    riskCategories: ["external_email"],
    activeVersionId: null,
    draftVersionId: null,
    activeRules: [],
    draftRules: [],
    history: [],
    warnings: [],
    openRuleIds: [],
  },
  {
    actionType: "guardian.support.reply.send.v1",
    label: "Respuesta de soporte",
    description: "Respuesta sintética de soporte.",
    riskClass: "medium",
    riskCategories: ["customer_data"],
    activeVersionId: null,
    draftVersionId: null,
    activeRules: [],
    draftRules: [],
    history: [],
    warnings: [],
    openRuleIds: [],
  },
];

const profiles: WorkspaceActionRuleProfile[] = [
  { id: "prudent-v1", label: "Prudente", description: "Control estricto.", defaultRefundLimitCents: 5000 },
  { id: "balanced-v1", label: "Equilibrada", description: "Equilibrio revisable.", defaultRefundLimitCents: 5000 },
  { id: "read-only-v1", label: "Solo lectura", description: "Sin acciones de escritura.", defaultRefundLimitCents: 5000 },
];

function props(overrides: Partial<WorkspaceRulesEditorProps> = {}): WorkspaceRulesEditorProps {
  return {
    actions,
    profiles,
    canManage: true,
    loading: false,
    error: null,
    onRetry: () => undefined,
    onApplyProfile: async () => undefined,
    onSaveRuleDraft: async () => undefined,
    onActivateRuleDraft: async () => undefined,
    onRollbackRule: async () => undefined,
    onSimulateRule: async () => ({
      actionType: actions[0].actionType,
      decision: "require_approval",
      reasonCode: "human_review",
      ruleId: "refund-review",
      ruleVersionId: "version-7",
      matched: true,
      issues: [],
      persisted: false,
      dispatched: false,
    }),
    onCompareHistory: async (): Promise<WorkspaceActionRuleHistoryImpactResponse> => ({
      actionType: actions[0].actionType,
      windowDays: 30,
      maximumProposals: 500,
      totalProposalCount: 0,
      evaluatedCount: 0,
      notReevaluableCount: 0,
      notProcessedByLimitCount: 0,
      isPartial: false,
      activeVersionId: null,
      draftVersionId: null,
      activeCounts: null,
      draftCounts: null,
      changes: [],
      readOnly: true,
    }),
    ...overrides,
  };
}

function markup(overrides: Partial<WorkspaceRulesEditorProps> = {}) {
  return renderToStaticMarkup(createElement(WorkspaceRulesEditor, props(overrides)));
}

test("profile cards and all primary controls have Spanish accessible labels", () => {
  const html = markup();
  assert.match(html, /Prudente/);
  assert.match(html, /Equilibrada/);
  assert.match(html, /Solo lectura/);
  assert.match(html, /Límite de reembolso/);
  assert.match(html, /aria-label="Decisión para Reembolso sintético: Hasta el límite"/);
  assert.match(html, /data-testid="profile-card-balanced-v1"/);
});

test("actions are grouped by risk category and show the immutable default-deny sentence", () => {
  const riskClassDiffersFromCategory = actions.map((action, index) =>
    index === 0 ? { ...action, riskClass: "medium" as const } : action,
  );
  const html = markup({ actions: riskClassDiffersFromCategory });
  assert.match(html, /Dinero \(alto\)/);
  assert.match(html, /Sale de la empresa \(alto\)/);
  assert.match(html, /Hablar con clientes \(medio\)/);
  assert.match(html, /data-testid="action-row-guardian\.synthetic\.support\.refund\.v1"[\s\S]*?RIESGO ALTO/);
  assert.match(html, new RegExp(IMMUTABLE_DEFAULT_DENY));
  assert.equal((html.match(/data-testid="action-row-/g) ?? []).length, 4);
});

test("owner controls are editable while viewers receive a read-only view", () => {
  const editor = markup({ canManage: true });
  assert.match(editor, /data-testid="save-draft-guardian\.synthetic\.support\.refund\.v1"/);
  assert.match(editor, /data-testid="activate-draft-guardian\.synthetic\.support\.refund\.v1"/);
  assert.match(editor, /data-testid="rules-bottom-bar"/);
  assert.match(editor, /Volver a una versión anterior/);
  const viewer = markup({ canManage: false });
  assert.match(viewer, /Vista de solo lectura/);
  assert.doesNotMatch(viewer, /data-testid="save-draft-/);
  assert.doesNotMatch(viewer, /data-testid="apply-profile"/);
  assert.doesNotMatch(viewer, /data-testid="rules-bottom-bar"/);
  assert.match(viewer, /disabled=""[^>]*data-testid="decision-refundWithin-allow"/);
});

test("unconfigured action decisions remain deny by default", () => {
  const html = markup();
  assert.match(html, /aria-pressed="true"[^>]*data-testid="decision-refundWithin-deny"/);
  assert.match(html, /aria-pressed="true"[^>]*data-testid="decision-supportRoutine-deny"/);
  assert.doesNotMatch(html, /aria-pressed="true"[^>]*data-testid="decision-supportRoutine-allow"/);
});

test("open-rule warning links to the affected action and marks it Abierta", () => {
  const openActions = actions.map((action, index) => index === 1
    ? { ...action, openRuleIds: ["rule-open"], warnings: ["Regla abierta detectada."] }
    : action);
  const html = markup({ actions: openActions });
  assert.match(html, /data-testid="open-rule-warning"/);
  assert.match(html, /href="#action-guardian\.synthetic\.finance\.bank-change\.v1"/);
  assert.match(html, /Cambio bancario sintético <span>Abierta<\/span>/);
  assert.match(html, /class="wre-open-badge">Abierta/);
  assert.match(html, /Regla abierta detectada\./);
});

test("simulator result formatter includes server decision, rule, version, and safe-simulation copy", () => {
  const response: WorkspaceActionRuleSimulationResponse = {
    actionType: actions[0].actionType,
    decision: "require_approval",
    reasonCode: "human_review",
    ruleId: "refund-review",
    ruleVersionId: "version-7",
    matched: true,
    issues: [],
    persisted: false,
    dispatched: false,
  };
  const html = markup();
  assert.match(html, /data-testid="rules-simulator"/);
  assert.match(html, /Simulación en memoria: no crea aprobaciones ni recibos y no ejecuta acciones\./);
  assert.equal(formatSimulationResult(response), "Requerir aprobación · regla refund-review · versión version-7");
});

test("rule builder preserves the threshold in integer cents for both refund bands", () => {
  const rules = buildWorkspaceActionRules(defaultRuleDecisions, 7350);
  assert.equal(rules.find((rule) => rule.id === "refund-within-threshold")?.when.all?.[0].value, 7350);
  assert.equal(rules.find((rule) => rule.id === "refund-above-threshold")?.when.all?.[0].value, 7350);
  assert.equal(rules.find((rule) => rule.id === "refund-within-threshold")?.decision, "deny");
  assert.equal(rules.find((rule) => rule.id === "refund-above-threshold")?.decision, "deny");
  assert.equal(buildWorkspaceActionRuleDocument(defaultRuleDecisions, 7350).version, 1);
  assert.equal(DEFAULT_REFUND_LIMIT_CENTS, 5000);
});

test("refund threshold validation accepts positive euro decimals and rejects invalid or out-of-range values", () => {
  assert.deepEqual(parseRefundLimitEuros("73,50"), { cents: 7350, error: null });
  assert.equal(parseRefundLimitEuros("").error, "Introduce un límite mayor que 0 €.");
  assert.equal(parseRefundLimitEuros("0").error, "El límite debe ser mayor que 0 €.");
  assert.equal(parseRefundLimitEuros("10000.01").error, "El límite máximo es 10.000 €.");
  assert.equal(parseRefundLimitEuros("1.234").error, "Usa un importe válido con hasta dos decimales.");
});

test("profile application communicates draft-only status and invalid values have precise validation", () => {
  const html = markup();
  assert.match(html, /data-testid="profile-apply-form"/);
  assert.equal(PROFILE_DRAFT_STATUS, "Plantilla guardada como borradores. Nada se ha activado.");
  const invalid = parseRefundLimitEuros("10001");
  assert.equal(invalid.cents, null);
  assert.equal(invalid.error, "El límite máximo es 10.000 €.");
  assert.equal(SIMULATION_SAFETY_COPY.includes("no ejecuta acciones"), true);
});

test("bottom controls identify active and draft versions and history shows editor and timestamp", () => {
  const html = markup();
  assert.match(html, /Versión activa <b>v1<\/b> · Borrador <b>ninguno<\/b>/);
  assert.match(html, /por owner/);
  assert.match(html, /dateTime="2026-01-01T00:00:00.000Z"/);
  assert.match(html, /data-testid="rollback-version"/);
  assert.match(html, /data-testid="bottom-activate"/);
});

test("history comparison is visible to members and clearly requires a saved draft", () => {
  const html = markup({ canManage: false });
  assert.match(html, /Qué habría pasado/);
  assert.match(html, /data-testid="rule-history-impact"/);
  assert.match(html, />Ver qué cambia<\/button>/);
  assert.match(html, /data-testid="history-impact-no-draft"/);
  assert.match(html, /Solo se usan argumentos genéricos guardados y verificados/);
  assert.match(html, /no escribe en el ledger o la auditoría/);
});

test("history comparison coverage explains excluded and limit-skipped proposals", () => {
  const mixed = {
    actionType: actions[0].actionType,
    windowDays: 30 as const,
    maximumProposals: 500 as const,
    totalProposalCount: 52,
    evaluatedCount: 40,
    notReevaluableCount: 12,
    notProcessedByLimitCount: 0,
    isPartial: false,
    activeVersionId: "active-v1",
    draftVersionId: "draft-v2",
    activeCounts: { allow: 3, requireApproval: 30, deny: 7 },
    draftCounts: { allow: 1, requireApproval: 20, deny: 19 },
    changes: [],
    readOnly: true as const,
  };
  assert.equal(
    formatHistoryImpactCoverage(mixed),
    "Calculado con 40 de 52 acciones; 12 no se pueden re-evaluar porque no hay argumentos verificables guardados.",
  );
  assert.equal(historyImpactEmptyMessage(mixed), null);

  const partial = {
    ...mixed,
    notProcessedByLimitCount: 3,
    isPartial: true,
  };
  assert.match(formatHistoryImpactCoverage(partial), /3 quedaron sin revisar por el límite de 500/);
});

test("history comparison empty states distinguish no proposals from missing stored content", () => {
  const empty = {
    actionType: actions[0].actionType,
    windowDays: 30 as const,
    maximumProposals: 500 as const,
    totalProposalCount: 0,
    evaluatedCount: 0,
    notReevaluableCount: 0,
    notProcessedByLimitCount: 0,
    isPartial: false,
    activeVersionId: null,
    draftVersionId: "draft-v1",
    activeCounts: null,
    draftCounts: null,
    changes: [],
    readOnly: true as const,
  };
  assert.equal(
    historyImpactEmptyMessage(empty),
    "Todavía no hay acciones de tus agentes. Cuando las haya, verás qué habría cambiado con estas reglas.",
  );
  const noArguments = {
    ...empty,
    totalProposalCount: 3,
    notReevaluableCount: 3,
  };
  assert.match(historyImpactEmptyMessage(noArguments) ?? "", /no se guardó contenido verificable/);
});
