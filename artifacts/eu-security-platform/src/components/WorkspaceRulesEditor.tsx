import React, { useEffect, useMemo, useState, type FormEvent } from "react";
import type {
  WorkspaceActionRule,
  WorkspaceActionRuleProfile,
  WorkspaceActionRuleHistoryImpactResponse,
  WorkspaceActionRuleSimulationResponse,
  WorkspaceActionRuleState,
} from "@workspace/api-client-react";
import { WorkspaceActionConditionsEditor } from "./WorkspaceActionConditionsEditor";

export type WorkspaceRulesEditorProps = {
  actions: WorkspaceActionRuleState[];
  profiles: WorkspaceActionRuleProfile[];
  canManage: boolean;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
  onApplyProfile: (
    profileId: WorkspaceActionRuleProfile["id"],
    refundLimitCents: number,
  ) => Promise<unknown>;
  onSaveRuleDraft: (
    actionType: string,
    rules: WorkspaceActionRule[],
    approvalPolicy?: { amountThresholdCents: number },
  ) => Promise<unknown>;
  onActivateRuleDraft: (actionType: string) => Promise<unknown>;
  onRollbackRule: (actionType: string, version: number) => Promise<unknown>;
  onSimulateRule: (
    actionType: string,
    versionId: string | undefined,
    args: Record<string, string | number | boolean>,
  ) => Promise<WorkspaceActionRuleSimulationResponse>;
  onCompareHistory: (
    actionType: string,
  ) => Promise<WorkspaceActionRuleHistoryImpactResponse>;
};

export type RuleDecision = "allow" | "deny" | "require_approval";
export type RuleCase = "refundWithin" | "refundAbove" | "bank" | "email" | "supportRoutine" | "supportSensitive";
export type DecisionMap = Record<RuleCase, RuleDecision>;

export const DEFAULT_REFUND_LIMIT_CENTS = 5000;
export const IMMUTABLE_DEFAULT_DENY =
  "Cualquier otra acción queda bloqueada siempre. Esto no se puede cambiar.";
export const PROFILE_DRAFT_STATUS =
  "Plantilla guardada como borradores. Nada se ha activado.";
export const SIMULATION_SAFETY_COPY =
  "Simulación en memoria: no crea aprobaciones ni recibos y no ejecuta acciones.";

export const defaultRuleDecisions: DecisionMap = {
  refundWithin: "deny",
  refundAbove: "deny",
  bank: "deny",
  email: "deny",
  supportRoutine: "deny",
  supportSensitive: "deny",
};

const profileDecisions: Record<WorkspaceActionRuleProfile["id"], DecisionMap> = {
  "prudent-v1": {
    refundWithin: "require_approval",
    refundAbove: "require_approval",
    bank: "require_approval",
    email: "require_approval",
    supportRoutine: "require_approval",
    supportSensitive: "require_approval",
  },
  "balanced-v1": {
    refundWithin: "allow",
    refundAbove: "require_approval",
    bank: "require_approval",
    email: "require_approval",
    supportRoutine: "allow",
    supportSensitive: "require_approval",
  },
  "read-only-v1": {
    refundWithin: "deny",
    refundAbove: "deny",
    bank: "deny",
    email: "deny",
    supportRoutine: "deny",
    supportSensitive: "deny",
  },
};

export function parseRefundLimitEuros(value: string): { cents: number | null; error: string | null } {
  const normalized = value.trim().replace(",", ".");
  if (!normalized) return { cents: null, error: "Introduce un límite mayor que 0 €." };
  if (!/^\d+(?:\.\d{1,2})?$/.test(normalized)) {
    return { cents: null, error: "Usa un importe válido con hasta dos decimales." };
  }
  const euros = Number(normalized);
  if (!Number.isFinite(euros) || euros <= 0) {
    return { cents: null, error: "El límite debe ser mayor que 0 €." };
  }
  if (euros > 10_000) return { cents: null, error: "El límite máximo es 10.000 €." };
  return { cents: Math.round(euros * 100), error: null };
}

const condition = (field: string, op: "eq" | "gt" | "lte", value: string | number | boolean) => ({
  field,
  op,
  value,
});

export function buildWorkspaceActionRules(
  decisions: DecisionMap,
  refundLimitCents: number,
): WorkspaceActionRule[] {
  const limit = Math.round(refundLimitCents);
  return [
    {
      id: "refund-within-threshold",
      decision: decisions.refundWithin,
      when: { all: [condition("amount_cents", "lte", limit)] },
    },
    {
      id: "refund-above-threshold",
      decision: decisions.refundAbove,
      when: { all: [condition("amount_cents", "gt", limit)] },
    },
    { id: "bank-account-change", decision: decisions.bank, when: {} },
    { id: "external-email", decision: decisions.email, when: {} },
    {
      id: "support-routine-internal",
      decision: decisions.supportRoutine,
      when: {
        all: [
          condition("recipient_type", "eq", "internal"),
          condition("compensation_cents", "lte", limit),
        ],
      },
    },
    {
      id: "support-sensitive-external-or-high-compensation",
      decision: decisions.supportSensitive,
      when: {
        any: [
          condition("recipient_type", "eq", "external"),
          condition("compensation_cents", "gt", limit),
        ],
      },
    },
  ];
}

export function buildWorkspaceActionRuleDocument(decisions: DecisionMap, refundLimitCents: number) {
  return { version: 1 as const, rules: buildWorkspaceActionRules(decisions, refundLimitCents) };
}

export function formatSimulationResult(result: WorkspaceActionRuleSimulationResponse): string {
  const decision = result.decision === "allow"
    ? "Permitir"
    : result.decision === "deny" ? "Bloquear" : "Requerir aprobación";
  return `${decision} · regla ${result.ruleId ?? "predeterminada"} · versión ${result.ruleVersionId ?? "no disponible"}`;
}

const historyDecisionLabels: Record<string, string> = {
  allow: "Permitirían sin aprobación",
  require_approval: "Pedirían aprobación",
  deny: "Se bloquearían",
};

export function formatHistoryImpactCoverage(
  result: WorkspaceActionRuleHistoryImpactResponse,
): string {
  if (result.totalProposalCount === 0) {
    return "Cobertura: no se encontraron propuestas de esta acción en los últimos 30 días.";
  }
  const text = `Calculado con ${result.evaluatedCount} de ${result.totalProposalCount} acciones; ${result.notReevaluableCount} no se pueden re-evaluar porque faltan argumentos o contexto histórico verificable.`;
  return result.notProcessedByLimitCount > 0
    ? `${text} Otras ${result.notProcessedByLimitCount} quedaron sin revisar por el límite de ${result.maximumProposals}.`
    : text;
}

export function historyImpactEmptyMessage(
  result: WorkspaceActionRuleHistoryImpactResponse,
): string | null {
  if (result.evaluatedCount > 0) return null;
  return result.totalProposalCount === 0
    ? "Todavía no hay acciones de tus agentes. Cuando las haya, verás qué habría cambiado con estas reglas."
    : "No hay propuestas re-evaluables: falta contenido o contexto histórico verificable para esta acción. No se reconstruyen argumentos desde hashes ni ejemplos.";
}

type ActionKind = "refund" | "bank" | "email" | "support";
type ActionGroup = "Dinero (alto)" | "Sale de la empresa (alto)" | "Hablar con clientes (medio)";
type ActionConfig = {
  kind: ActionKind;
  group: ActionGroup;
  cases: { key: RuleCase; label: string; detail: string }[];
};

function configFor(action: WorkspaceActionRuleState): ActionConfig | null {
  const key = `${action.actionType} ${action.label}`.toLowerCase();
  if (key.includes("refund") || key.includes("reembolso")) return {
    kind: "refund", group: "Dinero (alto)", cases: [
      { key: "refundWithin", label: "Hasta el límite", detail: "Reembolso sintético · importe ≤ límite" },
      { key: "refundAbove", label: "Por encima del límite", detail: "Reembolso sintético · importe > límite" },
    ],
  };
  if (key.includes("bank-change") || key.includes("bank change") || key.includes("bancari")) return {
    kind: "bank", group: "Dinero (alto)", cases: [
      { key: "bank", label: "Cambio bancario", detail: "Cambio sintético de cuenta bancaria" },
    ],
  };
  if (key.includes("email") || key.includes("correo")) return {
    kind: "email", group: "Sale de la empresa (alto)", cases: [
      { key: "email", label: "Correo externo", detail: "Envío a un destinatario externo" },
    ],
  };
  if (key.includes("support.reply") || key.includes("support") || key.includes("respuesta") || key.includes("soporte")) return {
    kind: "support", group: "Hablar con clientes (medio)", cases: [
      { key: "supportRoutine", label: "Respuesta interna rutinaria", detail: "Destinatario interno, sin compensación superior al límite" },
      { key: "supportSensitive", label: "Caso externo o sensible", detail: "Destinatario externo o compensación superior al límite" },
    ],
  };
  return null;
}

function inferDecision(rules: WorkspaceActionRule[], id: string, fallback: RuleDecision): RuleDecision {
  const match = rules.find((rule) => rule.id === id);
  return match?.decision ?? fallback;
}

function initialDecisions(actions: WorkspaceActionRuleState[]): DecisionMap {
  const result = { ...defaultRuleDecisions };
  for (const action of actions) {
    const config = configFor(action);
    if (!config) continue;
    const rules = action.draftVersionId ? action.draftRules : action.activeRules;
    if (config.kind === "refund") {
      result.refundWithin = inferDecision(rules, "refund-within-threshold", result.refundWithin);
      result.refundAbove = inferDecision(rules, "refund-above-threshold", result.refundAbove);
    } else if (config.kind === "bank") result.bank = inferDecision(rules, "bank-account-change", result.bank);
    else if (config.kind === "email") result.email = inferDecision(rules, "external-email", result.email);
    else {
      result.supportRoutine = inferDecision(rules, "support-routine-internal", result.supportRoutine);
      result.supportSensitive = inferDecision(rules, "support-sensitive-external-or-high-compensation", result.supportSensitive);
    }
  }
  return result;
}

function refundLimitFromRules(rules: WorkspaceActionRule[]): number | null {
  for (const rule of rules) {
    const threshold = [...(rule.when.all ?? []), ...(rule.when.any ?? [])].find(
      (item) => item.field === "amount_cents" && item.op === "lte",
    );
    if (
      threshold &&
      typeof threshold.value === "number" &&
      Number.isSafeInteger(threshold.value) &&
      threshold.value > 0 &&
      threshold.value <= 1_000_000
    ) return threshold.value;
  }
  return null;
}

function currentRefundLimitCents(actions: WorkspaceActionRuleState[]): number {
  const refundAction = actions.find((action) =>
    action.actionType === "guardian.synthetic.support.refund.v1",
  );
  if (!refundAction) return DEFAULT_REFUND_LIMIT_CENTS;
  const rules = refundAction.draftVersionId
    ? refundAction.draftRules
    : refundAction.activeRules;
  const limit = refundLimitFromRules(rules);
  if (limit !== null) return limit;
  return DEFAULT_REFUND_LIMIT_CENTS;
}

const decisionLabels: Record<RuleDecision, string> = {
  allow: "Permitir",
  require_approval: "Aprobar",
  deny: "Bloquear",
};

const serverDecisionLabels: Record<WorkspaceActionRuleSimulationResponse["decision"], string> = {
  allow: "Permitir",
  require_approval: "Requiere aprobación",
  deny: "Bloquear",
};

export function WorkspaceRulesEditor({
  actions,
  profiles,
  canManage,
  loading,
  error,
  onRetry,
  onApplyProfile,
  onSaveRuleDraft,
  onActivateRuleDraft,
  onRollbackRule,
  onSimulateRule,
  onCompareHistory,
}: WorkspaceRulesEditorProps) {
  const [refundLimit, setRefundLimit] = useState(String(DEFAULT_REFUND_LIMIT_CENTS / 100));
  const [limitError, setLimitError] = useState("");
  const [selectedProfile, setSelectedProfile] = useState<WorkspaceActionRuleProfile["id"] | "">("");
  const [decisions, setDecisions] = useState<DecisionMap>(() => initialDecisions(actions));
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState("");
  const [simActionType, setSimActionType] = useState("");
  const [simVersionId, setSimVersionId] = useState("");
  const [simAmount, setSimAmount] = useState("25");
  const [simResult, setSimResult] = useState<WorkspaceActionRuleSimulationResponse | null>(null);
  const [simError, setSimError] = useState("");
  const [manageActionType, setManageActionType] = useState(actions[0]?.actionType ?? "");
  const [rollbackVersion, setRollbackVersion] = useState("");
  const [historyActionType, setHistoryActionType] = useState(actions[0]?.actionType ?? "");
  const [historyImpact, setHistoryImpact] = useState<WorkspaceActionRuleHistoryImpactResponse | null>(null);
  const [historyImpactError, setHistoryImpactError] = useState("");
  const [historyImpactBusy, setHistoryImpactBusy] = useState(false);

  useEffect(() => {
    setDecisions(initialDecisions(actions));
    setRefundLimit(String(currentRefundLimitCents(actions) / 100));
    setManageActionType((current) =>
      actions.some((action) => action.actionType === current)
        ? current
        : actions[0]?.actionType ?? "",
    );
  }, [actions]);

  const supportedActions = useMemo(
    () => actions.map((action) => ({ action, config: configFor(action) })).filter((item) => item.config),
    [actions],
  );
  const selectedAction = supportedActions.find((item) => item.action.actionType === simActionType)?.action
    ?? supportedActions[0]?.action;
  const manageAction = actions.find((action) => action.actionType === manageActionType)
    ?? actions[0];
  const historyAction = actions.find((action) => action.actionType === historyActionType)
    ?? actions[0];
  const manageDraft = manageAction?.history.find((item) => item.id === manageAction.draftVersionId);
  const manageActive = manageAction?.history.find((item) => item.id === manageAction.activeVersionId);
  const availableRollbackVersions = manageAction?.history.filter(
    (item) => !item.isActive && item.id !== manageAction.draftVersionId,
  ) ?? [];

  useEffect(() => {
    setHistoryActionType((current) =>
      actions.some((action) => action.actionType === current)
        ? current
        : actions[0]?.actionType ?? "",
    );
    setHistoryImpact(null);
    setHistoryImpactError("");
  }, [actions]);

  useEffect(() => {
    setHistoryImpact(null);
    setHistoryImpactError("");
  }, [historyAction?.actionType, historyAction?.activeVersionId, historyAction?.draftVersionId]);

  const compareHistory = async () => {
    if (!historyAction?.draftVersionId || historyImpactBusy) return;
    setHistoryImpactBusy(true);
    setHistoryImpact(null);
    setHistoryImpactError("");
    try {
      setHistoryImpact(await onCompareHistory(historyAction.actionType));
    } catch {
      setHistoryImpactError("No se pudo comparar el historial. No se modificó ninguna propuesta ni regla.");
    } finally {
      setHistoryImpactBusy(false);
    }
  };

  const validateLimit = () => {
    const parsed = parseRefundLimitEuros(refundLimit);
    setLimitError(parsed.error ?? "");
    return parsed.cents;
  };

  const applyProfileChoice = async (profileId: WorkspaceActionRuleProfile["id"]) => {
    if (!canManage) return;
    setSelectedProfile(profileId);
    const cents = validateLimit();
    if (cents === null) return;
    setBusy("profile");
    setMessage("");
    try {
      await onApplyProfile(profileId, cents);
      setDecisions({ ...profileDecisions[profileId] });
      setMessage(PROFILE_DRAFT_STATUS);
    } catch {
      setMessage("No se pudo guardar la plantilla. No se activó ninguna regla.");
    } finally {
      setBusy("");
    }
  };

  const updateDecision = (key: RuleCase, value: RuleDecision) => {
    setDecisions((current) => ({ ...current, [key]: value }));
  };

  const saveDraft = async (action: WorkspaceActionRuleState) => {
    if (!canManage) return;
    const cents = validateLimit();
    if (cents === null) return;
    const config = configFor(action);
    const keys = config?.cases.map((item) => item.key) ?? [];
    const scoped: DecisionMap = { ...decisions };
    // The shared rule builder receives every decision; only the action-specific subset is sent below.
    const allRules = buildWorkspaceActionRules(scoped, cents);
    const idsByKind: Record<ActionKind, string[]> = {
      refund: ["refund-within-threshold", "refund-above-threshold"],
      bank: ["bank-account-change"],
      email: ["external-email"],
      support: ["support-routine-internal", "support-sensitive-external-or-high-compensation"],
    };
    const chosen = new Set(keys.flatMap((key) => {
      if (key === "refundWithin" || key === "refundAbove") return idsByKind.refund;
      if (key === "bank") return idsByKind.bank;
      if (key === "email") return idsByKind.email;
      return idsByKind.support;
    }));
    setBusy(action.actionType);
    setMessage("");
    try {
      await onSaveRuleDraft(
        action.actionType,
        allRules.filter((rule) => chosen.has(rule.id)),
        action.draftApprovalPolicy ??
          action.activeApprovalPolicy ??
          (action.approvalAmountField
            ? { amountThresholdCents: DEFAULT_REFUND_LIMIT_CENTS }
            : undefined),
      );
      setMessage(`Borrador guardado para ${action.label}. La versión activa no cambia.`);
    } catch {
      setMessage(`No se pudo guardar el borrador de ${action.label}. La versión activa no ha cambiado.`);
    } finally {
      setBusy("");
    }
  };

  const activateDraft = async (action: WorkspaceActionRuleState) => {
    if (!canManage || !action.draftVersionId) return;
    setBusy(action.actionType);
    setMessage("");
    try {
      await onActivateRuleDraft(action.actionType);
      setMessage(`Se activó el borrador de ${action.label}.`);
    } catch {
      setMessage(`No se pudo activar el borrador de ${action.label}.`);
    } finally {
      setBusy("");
    }
  };

  const rollback = async (action: WorkspaceActionRuleState, version: number) => {
    if (!canManage) return;
    setBusy(action.actionType);
    setMessage("");
    try {
      await onRollbackRule(action.actionType, version);
      setMessage(`Se creó un nuevo borrador desde v${version}; no se ha activado.`);
    } catch {
      setMessage(`No se pudo crear un borrador desde v${version}.`);
    } finally {
      setBusy("");
    }
  };

  const simulate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedAction) return;
    setSimError("");
    setSimResult(null);
    setBusy("simulation");
    try {
      const config = configFor(selectedAction);
      const args: Record<string, string | number | boolean> = config?.kind === "refund"
        ? { ticket_id: "TICKET-SYNTH-SIMULACION", amount_cents: Math.round(Number(simAmount) * 100) }
        : config?.kind === "support"
          ? {
              ticket_id: "TICKET-SYNTH-SIMULACION",
              recipient_email: "simulacion@example.test",
              recipient_type: Number(simAmount) > 50 ? "external" : "internal",
              compensation_cents: Math.round(Number(simAmount) * 100),
              template_id: "synthetic-support-reply-v1",
            }
          : config?.kind === "email"
            ? { to: "simulacion@example.test", template_id: "guardian-demo-email-v1" }
            : { account_id: "LAB-ACCOUNT-SIM-1", new_iban: "DE00LAB1234567890ABCDEF" };
      const result = await onSimulateRule(selectedAction.actionType, simVersionId || undefined, args);
      setSimResult(result);
    } catch {
      setSimError("No se pudo completar la simulación. No se guardó ni ejecutó ninguna acción.");
    } finally {
      setBusy("");
    }
  };

  const groupOrder: ActionGroup[] = ["Dinero (alto)", "Sale de la empresa (alto)", "Hablar con clientes (medio)"];
  const groupedActions = groupOrder.map((group) => ({
    group,
    items: supportedActions.filter((item) => item.config?.group === group),
  }));

  return <section className="workspace-rules" aria-labelledby="workspace-rules-title" data-testid="workspace-rules-editor">
    <header className="wre-header">
      <div>
        <p className="wre-kicker">GUARDIAN NEXUS <span>/</span> CONTROL DE ACCIONES</p>
        <h1 id="workspace-rules-title">Reglas por plantillas</h1>
        <p className="wre-lede">Define qué puede proponer un agente y qué debe revisar una persona antes de actuar.</p>
      </div>
      <div className="wre-scope"><span className="wre-scope-dot" /> BORRADORES Y VERSIONES</div>
    </header>

    {loading ? <div className="wre-loading" role="status" data-testid="rules-loading" aria-label="Cargando reglas">
      <span /><span /><span />
    </div> : error ? <div className="wre-error" role="alert" data-testid="rules-error">
      <div><strong>No se pudieron cargar las reglas</strong><p>{error}</p></div>
      <button type="button" onClick={onRetry} data-testid="rules-retry">Reintentar</button>
    </div> : <>
      {actions.some((action) => action.openRuleIds.length > 0) && <aside className="wre-open-warning" role="alert" data-testid="open-rule-warning">
        <strong>Hay reglas abiertas</strong>
        <p>Una regla abierta puede ampliar el acceso. Revisa las acciones afectadas antes de guardar cambios.</p>
        <ul>{actions.flatMap((action) => action.openRuleIds.length
          ? [<li key={action.actionType}><a href={`#action-${encodeURIComponent(action.actionType)}`}>{action.label} <span>Abierta</span></a></li>]
          : [])}</ul>
      </aside>}

      <div className="wre-default-deny" role="note" data-testid="immutable-default-deny">
        <span className="wre-lock-mark" aria-hidden="true">!</span>
        <p>{IMMUTABLE_DEFAULT_DENY}</p>
        <span className="wre-fixed-tag">REGLA FIJA</span>
      </div>

      <section className="wre-profiles" aria-labelledby="profile-heading">
        <div className="wre-section-heading">
          <div><p className="wre-index">01 / PUNTO DE PARTIDA</p><h2 id="profile-heading">Perfiles globales</h2></div>
          <p>Una plantilla prepara borradores para las acciones listadas. La activación siempre es independiente.</p>
        </div>
        <div className="wre-profile-grid">
          {profiles.map((profile, index) => {
            const content = <>
              <span className="wre-profile-index">0{index + 1}</span>
              <span className="wre-profile-name">{profile.label}</span>
              <span className="wre-profile-description">{profile.description}</span>
              <span className="wre-profile-limit">Límite sugerido · {(profile.defaultRefundLimitCents / 100).toLocaleString("es-ES", { style: "currency", currency: "EUR" })}</span>
            </>;
            return canManage
              ? <button
                  type="button"
                  className={`wre-profile-card ${selectedProfile === profile.id ? "is-selected" : ""}`}
                  key={profile.id}
                  aria-pressed={selectedProfile === profile.id}
                  disabled={busy === "profile"}
                  onClick={() => { setMessage(""); void applyProfileChoice(profile.id); }}
                  data-testid={`profile-card-${profile.id}`}
                >{content}</button>
              : <article className="wre-profile-card wre-profile-card-static" key={profile.id} data-testid={`profile-card-${profile.id}`}>
                  {content}
                </article>;
          })}
        </div>
        {canManage ? <div className="wre-profile-form" data-testid="profile-apply-form">
          <div className="wre-profile-controls">
            <label htmlFor="refund-limit">Límite de reembolso (€)
              <span>El límite se aplica en céntimos; máximo 10.000 €.</span>
            </label>
            <input
              id="refund-limit"
              type="number"
              min="0.01"
              max="10000"
              step="0.01"
              inputMode="decimal"
              value={refundLimit}
              aria-invalid={!!limitError}
              aria-describedby={limitError ? "refund-limit-error" : "refund-limit-help"}
              onChange={(event) => { setRefundLimit(event.target.value); setLimitError(""); }}
              data-testid="refund-limit-input"
            />
            {limitError && <p className="wre-inline-error" id="refund-limit-error" role="alert" data-testid="refund-limit-error">{limitError}</p>}
            {!limitError && <span className="wre-sr-only" id="refund-limit-help">Introduce un importe positivo de hasta 10.000 euros.</span>}
          </div>
        </div> : <p className="wre-readonly-note">Vista de solo lectura. Solo owner o admin puede aplicar perfiles y editar reglas.</p>}
        {message && <p className="wre-status" role="status" data-testid="rules-action-status">{message}</p>}
      </section>

      <section className="wre-rules" aria-labelledby="actions-heading">
        <div className="wre-section-heading">
          <div><p className="wre-index">02 / DECISIONES EXPLÍCITAS</p><h2 id="actions-heading">Acciones cubiertas</h2></div>
          <p>Las decisiones se guardan como una versión nueva. Los casos no descritos siguen bloqueados.</p>
        </div>
        {!supportedActions.length ? <div className="wre-empty" data-testid="rules-empty">
          <strong>Aún no hay acciones disponibles</strong><p>Las acciones aparecerán aquí cuando el servicio proporcione sus reglas.</p>
        </div> : groupedActions.map(({ group, items }, groupIndex) => items.length > 0 && <section className="wre-group" key={group} aria-label={group}>
          <header className="wre-group-head"><span>0{groupIndex + 1}</span><h3>{group}</h3><i /></header>
          {items.map(({ action, config }) => {
            if (!config) return null;
            const active = action.history.find((entry) => entry.id === action.activeVersionId);
            const draft = action.history.find((entry) => entry.id === action.draftVersionId);
            const open = action.openRuleIds.length > 0;
            return <article id={`action-${encodeURIComponent(action.actionType)}`} className={`wre-action ${open ? "is-open" : ""}`} key={action.actionType} data-testid={`action-row-${action.actionType}`}>
              <div className="wre-action-copy">
                <div className="wre-action-title">{action.label} {open && <span className="wre-open-badge">Abierta</span>}</div>
                <p>{action.description}</p>
                <span className="wre-risk">RIESGO {config.group.endsWith("(alto)") ? "ALTO" : config.group.endsWith("(medio)") ? "MEDIO" : action.riskClass === "high" ? "ALTO" : action.riskClass === "medium" ? "MEDIO" : "BAJO"}</span>
                {action.warnings.length > 0 && <ul className="wre-action-warnings" aria-label={`Avisos de reglas para ${action.label}`}>
                  {action.warnings.map((warning, warningIndex) => <li key={`${action.actionType}-warning-${warningIndex}`}>{warning}</li>)}
                </ul>}
                <div className="wre-version-pair">
                  <span>Activa <b>{active ? `v${active.version}` : "Sin versión"}</b></span>
                  <span>Borrador <b>{draft ? `v${draft.version}` : "Sin borrador"}</b></span>
                </div>
              </div>
              <div className="wre-action-decisions">
                {config.cases.map((item) => <div className="wre-decision-case" key={item.key}>
                  <div className="wre-decision-label"><b>{item.label}</b><span>{item.detail}</span></div>
                  <div className="wre-decision-options" role="group" aria-label={`Decisión para ${action.label}: ${item.label}`}>
                    {(Object.keys(decisionLabels) as RuleDecision[]).map((decision) => <button
                      type="button"
                      key={decision}
                      className={decisions[item.key] === decision ? `is-${decision.replace("_", "-")}` : ""}
                      aria-pressed={decisions[item.key] === decision}
                      disabled={!canManage}
                      onClick={() => updateDecision(item.key, decision)}
                      data-testid={`decision-${item.key}-${decision}`}
                    >{decisionLabels[decision]}</button>)}
                  </div>
                </div>)}
                {canManage && <div className="wre-row-controls">
                  <button type="button" onClick={() => void saveDraft(action)} disabled={!!busy} data-testid={`save-draft-${action.actionType}`}>Guardar borrador</button>
                  <button type="button" className="wre-activate" onClick={() => void activateDraft(action)} disabled={!action.draftVersionId || !!busy} data-testid={`activate-draft-${action.actionType}`}>Activar borrador</button>
                </div>}
                {action.history.length > 0 && <details className="wre-history">
                  <summary>Versiones anteriores y reversión</summary>
                  <ul>{action.history.map((version) => {
                    const savedLimit = config.kind === "refund"
                      ? refundLimitFromRules(version.rules)
                      : null;
                    return <li key={version.id}>
                      <div className="wre-history-version">
                        <span>v{version.version} · {version.isActive ? "Activa" : version.isDraft ? "Borrador" : "Anterior"}</span>
                        <small><time dateTime={version.createdAt}>{new Date(version.createdAt).toLocaleString("es-ES")}</time> · por {version.createdByUserId}</small>
                        <small>{version.rules.length} reglas{config.kind === "refund" ? ` · límite ${
                          savedLimit === null
                            ? "no disponible"
                            : (savedLimit / 100).toLocaleString("es-ES", { style: "currency", currency: "EUR" })
                        }` : ""}</small>
                      </div>
                      {canManage && <button type="button" disabled={!!busy || version.isActive} onClick={() => void rollback(action, version.version)} data-testid={`rollback-${action.actionType}-${version.version}`}>Crear borrador desde v{version.version}</button>}
                    </li>;
                  })}</ul>
                </details>}
              </div>
            </article>;
          })}
        </section>)}
      </section>

      <WorkspaceActionConditionsEditor
        actions={actions}
        canManage={canManage}
        busy={!!busy}
        onSave={async (actionType, rules, approvalPolicy) => {
          setBusy(actionType);
          setMessage("");
          try {
            await onSaveRuleDraft(actionType, rules, approvalPolicy);
          } finally {
            setBusy("");
          }
        }}
      />

      <section className="wre-history-impact" aria-labelledby="history-impact-heading" data-testid="rule-history-impact">
        <div className="wre-history-impact-intro">
          <p className="wre-index">04 / COMPARACIÓN HISTÓRICA · SOLO LECTURA</p>
          <h2 id="history-impact-heading">Qué habría pasado</h2>
          <p>Compara las propuestas de los últimos 30 días con la versión activa y el borrador. Solo se usan argumentos genéricos guardados y verificados.</p>
          <p className="wre-history-impact-safety">No crea aprobaciones ni recibos, no escribe en el ledger o la auditoría y no ejecuta acciones.</p>
        </div>
        <div className="wre-history-impact-content">
          {historyAction ? <>
            <label htmlFor="history-impact-action">Acción
              <select
                id="history-impact-action"
                value={historyAction.actionType}
                onChange={(event) => {
                  setHistoryActionType(event.target.value);
                  setHistoryImpact(null);
                  setHistoryImpactError("");
                }}
                data-testid="history-impact-action"
              >
                {actions.map((action) => <option key={action.actionType} value={action.actionType}>{action.label}</option>)}
              </select>
            </label>
            {!historyAction.draftVersionId && <p className="wre-history-impact-empty" data-testid="history-impact-no-draft">No hay un borrador guardado para comparar con la versión activa.</p>}
            <button
              type="button"
              className="wre-history-impact-button"
              disabled={!historyAction.draftVersionId || historyImpactBusy}
              onClick={() => void compareHistory()}
              data-testid="history-impact-run"
            >{historyImpactBusy ? "Calculando…" : "Ver qué cambia"}</button>
          </> : <p className="wre-history-impact-empty">No hay acciones disponibles para comparar.</p>}
          {historyImpactError && <p className="wre-history-impact-error" role="alert" data-testid="history-impact-error">{historyImpactError}</p>}
          {historyImpact && <>
            <p className="wre-history-impact-coverage" role="status" data-testid="history-impact-coverage">
              {formatHistoryImpactCoverage(historyImpact)}
            </p>
            {historyImpactEmptyMessage(historyImpact) ? (
              <p className="wre-history-impact-empty" data-testid="history-impact-empty">
                {historyImpactEmptyMessage(historyImpact)}
              </p>
            ) : <>
              <div className="wre-history-impact-columns" data-testid="history-impact-counts">
                <HistoryImpactCounts
                  title={`Versión activa · ${historyImpact.activeVersionId ? "guardada" : "denegación predeterminada"}`}
                  counts={historyImpact.activeCounts}
                  testId="active"
                />
                <HistoryImpactCounts
                  title={`Borrador · ${historyImpact.draftVersionId ? "disponible" : "no disponible"}`}
                  counts={historyImpact.draftCounts}
                  testId="draft"
                />
              </div>
              <div className="wre-history-impact-changes" data-testid="history-impact-changes">
                <h3>Cambios de decisión</h3>
                {historyImpact.changes.length
                  ? <ul>{historyImpact.changes.map((change) => <li key={`${change.from}-${change.to}`}>
                      <b>{change.count}</b> {change.count === 1 ? "acción" : "acciones"} pasarían de {historyDecisionLabels[change.from]} a {historyDecisionLabels[change.to]}.
                    </li>)}</ul>
                  : <p>No cambiaría la decisión de las propuestas evaluables.</p>}
              </div>
            </>}
          </>}
        </div>
      </section>

      <section className="wre-simulator" aria-labelledby="simulator-heading" data-testid="rules-simulator">
        <div className="wre-simulator-intro">
          <p className="wre-index">03 / COMPROBACIÓN LOCAL</p>
          <h2 id="simulator-heading">Simulador de reglas</h2>
          <p>Consulta la respuesta del motor para un conjunto sintético de argumentos y una versión concreta.</p>
        </div>
        {selectedAction ? <form className="wre-sim-form" onSubmit={(event) => void simulate(event)}>
          <label htmlFor="sim-action">Acción
            <select id="sim-action" value={selectedAction.actionType} onChange={(event) => { setSimActionType(event.target.value); setSimVersionId(""); setSimResult(null); }} data-testid="simulator-action">
              {supportedActions.map(({ action }) => <option key={action.actionType} value={action.actionType}>{action.label}</option>)}
            </select>
          </label>
          <label htmlFor="sim-version">Versión
            <select id="sim-version" value={simVersionId} onChange={(event) => setSimVersionId(event.target.value)} data-testid="simulator-version">
              <option value="">Versión seleccionada por el servidor</option>
              {selectedAction.history.map((entry) => <option value={entry.id} key={entry.id}>{entry.isDraft ? "Borrador" : entry.isActive ? "Activa" : "Anterior"} · v{entry.version}</option>)}
            </select>
          </label>
          {["refund", "support"].includes(configFor(selectedAction)?.kind ?? "") && <label htmlFor="sim-amount">Importe sintético (€)
            <input id="sim-amount" type="number" min={configFor(selectedAction)?.kind === "refund" ? "0.01" : "0"} max="10000" step="0.01" required value={simAmount} onChange={(event) => setSimAmount(event.target.value)} data-testid="simulator-amount" />
          </label>}
          <button type="submit" disabled={busy === "simulation"} data-testid="run-simulation">{busy === "simulation" ? "Simulando…" : "Simular regla"}</button>
        </form> : <p className="wre-empty">No hay acciones que simular.</p>}
        <p className="wre-sim-safety">{SIMULATION_SAFETY_COPY}</p>
        {simError && <p role="alert" className="wre-inline-error">{simError}</p>}
        {simResult && <div className="wre-sim-result" role="status" data-testid="simulation-result">
          <div><span>DECISIÓN DEL SERVIDOR</span><strong>{serverDecisionLabels[simResult.decision]}</strong></div>
          <dl>
            <dt>Regla</dt><dd><code>{simResult.ruleId ?? "predeterminada"}</code></dd>
            <dt>Versión</dt><dd><code>{simResult.ruleVersionId ?? "no disponible"}</code></dd>
            <dt>Motivo</dt><dd><code>{simResult.reasonCode}</code></dd>
          </dl>
          <p>{SIMULATION_SAFETY_COPY}</p>
        </div>}
      </section>
      {canManage && manageAction && <footer className="wre-bottom-bar" data-testid="rules-bottom-bar">
        <div className="wre-bottom-selection">
          <label htmlFor="manage-action">Acción para activar o recuperar
            <select
              id="manage-action"
              value={manageAction.actionType}
              onChange={(event) => { setManageActionType(event.target.value); setRollbackVersion(""); }}
              data-testid="manage-action"
            >
              {actions.map((action) => <option value={action.actionType} key={action.actionType}>{action.label}</option>)}
            </select>
          </label>
          <p>Versión activa <b>{manageActive ? `v${manageActive.version}` : "ninguna"}</b> · Borrador <b>{manageDraft ? `v${manageDraft.version}` : "ninguno"}</b></p>
        </div>
        <label htmlFor="rollback-version">Volver a una versión anterior
          <select
            id="rollback-version"
            value={rollbackVersion}
            onChange={(event) => setRollbackVersion(event.target.value)}
            disabled={!availableRollbackVersions.length}
            data-testid="rollback-version"
          >
            <option value="">Elige una versión</option>
            {availableRollbackVersions.map((version) => <option value={String(version.version)} key={version.id}>Crear borrador desde v{version.version}</option>)}
          </select>
        </label>
        <button
          type="button"
          disabled={!rollbackVersion || !!busy}
          onClick={() => {
            const version = Number(rollbackVersion);
            if (Number.isSafeInteger(version) && version > 0) void rollback(manageAction, version);
          }}
          data-testid="bottom-rollback"
        >Volver a una versión anterior</button>
        <button
          type="button"
          className="wre-bottom-activate"
          disabled={!manageDraft || !!busy}
          onClick={() => void activateDraft(manageAction)}
          data-testid="bottom-activate"
        >{manageDraft ? `Activar versión ${manageDraft.version}` : "Sin borrador para activar"}</button>
      </footer>}
    </>}
  </section>;
}

function HistoryImpactCounts({
  title,
  counts,
  testId,
}: {
  title: string;
  counts: WorkspaceActionRuleHistoryImpactResponse["activeCounts"];
  testId: string;
}) {
  if (!counts) {
    return <div className="wre-history-impact-version" data-testid={`history-impact-${testId}-unavailable`}>
      <h3>{title}</h3>
      <p>No disponible para esta comparación.</p>
    </div>;
  }
  return <div className="wre-history-impact-version" data-testid={`history-impact-${testId}`}>
    <h3>{title}</h3>
    <dl>
      <div><dt>Pasarían solas</dt><dd data-testid={`history-impact-${testId}-allow`}>{counts.allow}</dd></div>
      <div><dt>Pedirían aprobación</dt><dd data-testid={`history-impact-${testId}-approval`}>{counts.requireApproval}</dd></div>
      <div><dt>Se bloquearían</dt><dd data-testid={`history-impact-${testId}-deny`}>{counts.deny}</dd></div>
    </dl>
  </div>;
}
