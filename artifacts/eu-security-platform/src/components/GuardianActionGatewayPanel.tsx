import React, { useMemo, useState, type FormEvent } from "react";
import { Activity, ArrowDownToLine, Check, ChevronRight, CircleAlert, Code2, GitBranch, LockKeyhole, Network, Shield, SlidersHorizontal } from "lucide-react";

export type GatewayArgumentField = {
  name: string;
  label: string;
  description?: string | null;
  type: "text" | "number" | "boolean";
  required?: boolean;
  placeholder?: string | null;
};

export type GatewayRuleRow = {
  condition: string;
  decision: string;
  approver: string;
};

export type GatewayActionTemplate = {
  actionType: string;
  version: string;
  businessArea?: string;
  label: string;
  description: string;
  riskLabel: string;
  defaultDecision: string;
  approverLabel: string;
  expiryMinutes: number;
  requiresIndependentApprover: boolean;
  proposalEnabled: boolean;
  argumentFields: GatewayArgumentField[];
  rules: GatewayRuleRow[];
};

export type GatewayApprovalRecord = {
  id: string;
  actionType: string;
  agentIdentity: string | null;
  summary: string | null;
  appliedRule: string | null;
  status: string;
  expiresAt: string | null;
  canDecide: boolean;
  proposalBinding: string | null;
  receiptVerification?: string | null;
};

export type GatewayLedgerEvent = {
  sequence: number;
  eventType: string;
  approvalId: string;
  timestamp: string;
  hash: string | null;
  receiptId?: string | null;
  receiptSha256?: string | null;
  receiptState?: string | null;
};

export type GatewayReceiptReference = {
  receiptId: string;
  payloadSha256: string;
};

export type GatewayPreviewResult = {
  decision: "allow" | "deny" | "require_approval";
  reasonCode: string;
  ruleId: string | null;
  persisted: false;
  dispatched: false;
};

export type GatewayAccessState = "available" | "restricted" | "unavailable";

export type GuardianActionGatewayPanelProps = {
  workspaceId: string;
  actionTemplates: GatewayActionTemplate[];
  approvals: GatewayApprovalRecord[];
  ledgerEvents: GatewayLedgerEvent[];
  accessState: GatewayAccessState;
  canPropose: boolean;
  loading?: boolean;
  error?: string | null;
  approvalCount?: number | null;
  ledgerEventCount?: number | null;
  verifiedReceiptCount?: number | null;
  receipts?: GatewayReceiptReference[];
  exporting?: boolean;
  initialSection?: "rules" | "approvals" | "activity" | "connect";
  onPropose: (actionType: string, args: Record<string, string | number | boolean>) => Promise<{
    decision: "allow" | "deny" | "require_approval";
    reasonCode: string;
    approvalId: string | null;
  }>;
  onSimulate: (actionType: string, args: Record<string, string | number | boolean>) => Promise<GatewayPreviewResult>;
  onDecision: (approvalId: string, decision: "approve" | "reject", proposalBinding: string | null) => Promise<boolean>;
  onExport: () => void;
};

type Section = "rules" | "approvals" | "activity" | "connect";
const sections: { id: Section; label: string; icon: typeof Shield }[] = [
  { id: "rules", label: "Reglas por plantillas", icon: SlidersHorizontal },
  { id: "approvals", label: "Bandeja de aprobaciones", icon: Check },
  { id: "activity", label: "Actividad", icon: Activity },
  { id: "connect", label: "Conectar agente", icon: Network },
];
const unconfiguredAreaTemplates = [
  { id: "guardian-template-customer-data-v1", label: "Datos de clientes" },
  { id: "guardian-template-infrastructure-v1", label: "Infraestructura" },
];
const unavailable = "No disponible";
const displayFact = (value: string | null | undefined) => value?.trim() || unavailable;
const textOrNumberInputValue = (
  value: string | number | boolean | undefined,
): string | number => typeof value === "string" || typeof value === "number"
  ? value
  : "";
const statusLabel = (status: string) => {
  const label = ({
    pending: "Pendiente",
    approved: "Aprobada",
    rejected: "Rechazada",
    denied: "Denegada",
    expired: "Caducada",
  } as Record<string, string>)[status];
  return label ?? (status || unavailable);
};

export function GuardianActionGatewayPanel({
  workspaceId,
  actionTemplates,
  approvals,
  ledgerEvents,
  accessState,
  canPropose,
  loading = false,
  error = null,
  approvalCount,
  ledgerEventCount,
  verifiedReceiptCount,
  receipts = [],
  exporting = false,
  initialSection = "rules",
  onPropose,
  onSimulate,
  onDecision,
  onExport,
}: GuardianActionGatewayPanelProps) {
  const [section, setSection] = useState<Section>(initialSection);
  const [selectedAction, setSelectedAction] = useState(actionTemplates[0]?.actionType ?? "");
  const [args, setArgs] = useState<Record<string, string | number | boolean>>({});
  const [simulationResult, setSimulationResult] = useState("");
  const [proposalResult, setProposalResult] = useState("");
  const [actionPending, setActionPending] = useState(false);
  const [decisionPendingId, setDecisionPendingId] = useState<string | null>(null);
  const [decisionResult, setDecisionResult] = useState("");
  const [framework, setFramework] = useState("gateway");
  const selectedTemplate = useMemo(
    () => actionTemplates.find((template) => template.actionType === selectedAction) ?? actionTemplates[0],
    [actionTemplates, selectedAction],
  );
  const receiptIndex = useMemo(
    () => new Map(receipts.map((receipt) => [
      receipt.receiptId,
      receipt.payloadSha256,
    ])),
    [receipts],
  );
  const missingApprovalIds = useMemo(
    () => [...new Set(ledgerEvents.filter((event) =>
      event.eventType === "approval.approved" &&
      (!event.receiptId ||
        receiptIndex.get(event.receiptId) !== event.receiptSha256),
    ).map((event) => event.approvalId))],
    [ledgerEvents, receiptIndex],
  );
  const approvalStatusCounts = useMemo(() => {
    if (typeof approvalCount !== "number") return null;
    return {
      approved: approvals.filter((item) => item.status === "approved").length,
      pending: approvals.filter((item) => item.status === "pending").length,
      rejected: approvals.filter((item) =>
        item.status === "rejected" || item.status === "denied" || item.status === "expired"
      ).length,
    };
  }, [approvalCount, approvals]);
  const submitProposal = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedTemplate || !selectedTemplate.proposalEnabled || !canPropose || actionPending) return;
    const valid = selectedTemplate.argumentFields.every((field) => !field.required || String(args[field.name] ?? "").trim().length > 0);
    if (!valid) {
      setSimulationResult("Completa los argumentos obligatorios para continuar.");
      return;
    }
    setActionPending(true);
    setProposalResult("");
    setSimulationResult("");
    try {
      const result = await onPropose(selectedTemplate.actionType, args);
      const resultLabel = result.decision === "require_approval"
        ? "requiere aprobación independiente"
        : result.decision === "allow" ? "permitida por la plantilla" : "bloqueada";
      setProposalResult(
        `Resultado: ${resultLabel} (${result.reasonCode}). ` +
          (result.approvalId
            ? `Se registró la aprobación ${result.approvalId}; no se despachó ninguna herramienta.`
            : "No se despachó ninguna herramienta."),
      );
    } catch {
      setProposalResult("No se pudo registrar la propuesta. No se ejecutó ninguna acción.");
    } finally {
      setActionPending(false);
    }
  };
  const simulateAction = async () => {
    if (!selectedTemplate) return;
    const valid = selectedTemplate.argumentFields.every((field) => !field.required || String(args[field.name] ?? "").trim().length > 0);
    if (!valid) {
      setSimulationResult("Completa los argumentos obligatorios para simular.");
      return;
    }
    setActionPending(true);
    setSimulationResult("");
    try {
      const result = await onSimulate(selectedTemplate.actionType, args);
      const label = result.decision === "require_approval"
        ? "Pedir aprobación"
        : result.decision === "allow" ? "Permitir" : "Bloquear";
      setSimulationResult(
        `${label} · ${result.reasonCode} · regla ${result.ruleId ?? "predeterminada"}. ` +
          "Simulación en memoria; no se guardó ni ejecutó nada.",
      );
    } catch {
      setSimulationResult("No se pudo simular la decisión; no se guardó ni ejecutó nada.");
    } finally {
      setActionPending(false);
    }
  };
  const submitDecision = async (
    approvalId: string,
    decision: "approve" | "reject",
    proposalBinding: string | null,
  ) => {
    if (!proposalBinding) {
      setDecisionResult("No se pudo validar el vínculo de la propuesta.");
      return;
    }
    setDecisionPendingId(approvalId);
    setDecisionResult("");
    try {
      const recorded = await onDecision(approvalId, decision, proposalBinding);
      setDecisionResult(recorded
        ? "Decisión registrada; no se despachó ninguna herramienta."
        : "No se pudo confirmar la decisión. No se despachó ninguna herramienta.");
    } catch {
      setDecisionResult("No se pudo registrar la decisión. No se despachó ninguna herramienta.");
    } finally {
      setDecisionPendingId(null);
    }
  };

  return <section className="guardian-gateway" data-testid="guardian-action-gateway" aria-label="Guardian Nexus · control de propuestas">
    <style>{`
      .guardian-gateway{--gw-ink:#203043;--gw-muted:#68777d;--gw-green:#28745b;--gw-paper:#f7f5ef;--gw-card:#fffdf8;--gw-line:#dedbd2;max-width:1180px;margin:0 auto;padding:clamp(18px,3vw,38px);color:var(--gw-ink);font-family:var(--font-sans,'DM Sans',sans-serif)}
      .guardian-gateway *{box-sizing:border-box}.gateway-header{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;padding:0 0 22px;border-bottom:1px solid var(--gw-line)}
      .gateway-kicker{display:flex;align-items:center;gap:7px;color:var(--gw-green);font:500 10px var(--font-mono,'DM Mono',monospace);letter-spacing:.09em}
      .gateway-heading h1{margin:11px 0 7px;font:700 clamp(27px,4vw,38px)/1.08 var(--font-display,'Manrope',sans-serif);letter-spacing:-.055em}
      .gateway-heading p{margin:0;color:var(--gw-muted);font-size:13px}.gateway-heading code,.gateway-facts code,.gateway-event-list code{font:11px var(--font-mono,'DM Mono',monospace);overflow-wrap:anywhere}
      .gateway-mode{display:flex;align-items:center;gap:8px;border:1px solid #d8dfd7;border-radius:999px;padding:9px 12px;color:#536c5f;background:#eef3ec;font:10px var(--font-mono,'DM Mono',monospace);white-space:nowrap}
      .gateway-mode span{width:7px;height:7px;border-radius:50%;background:#b98a3f}
      .gateway-disclosure{display:flex;gap:11px;margin:18px 0;padding:12px 15px;border:1px solid #e5d8bd;border-left:3px solid #b98a3f;border-radius:7px;background:#faf6eb;color:#675c47;font-size:12px;line-height:1.6}
      .gateway-disclosure svg{flex:none;margin-top:1px;color:#a47a38}.gateway-disclosure p{margin:0}
      .gateway-nav{display:flex;gap:6px;overflow-x:auto;border-bottom:1px solid var(--gw-line);padding-bottom:1px}
      .gateway-tab{display:flex;align-items:center;gap:8px;min-height:44px;padding:0 13px;border:0;border-bottom:2px solid transparent;color:#718078;background:transparent;font-size:12px;font-weight:600;white-space:nowrap}
      .gateway-tab-active{border-bottom-color:var(--gw-green);color:var(--gw-green)}.gateway-tab-arrow{opacity:.4}.gateway-tab:focus-visible,.guardian-gateway button:focus-visible,.guardian-gateway select:focus-visible,.guardian-gateway input:focus-visible{outline:2px solid var(--gw-green);outline-offset:2px}
      .gateway-panel{padding-top:24px}.gateway-section-title{display:flex;align-items:flex-end;justify-content:space-between;gap:15px;margin-bottom:18px}
      .gateway-section-title h2{margin:5px 0;font:700 clamp(21px,3vw,27px)/1.18 var(--font-display,'Manrope',sans-serif);letter-spacing:-.04em}
      .gateway-section-title p{margin:0;color:var(--gw-muted);font-size:12px;line-height:1.55}.gateway-count{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--gw-line);border-radius:6px;padding:7px 9px;color:#63736c;background:#fbfaf5;font:10px var(--font-mono,'DM Mono',monospace);white-space:nowrap}
      .gateway-default-block{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding:13px 15px;border:1px solid #d8e2d9;border-radius:8px;background:#edf3ec;color:#315846}
      .gateway-default-block>div{display:grid;gap:3px;flex:1}.gateway-default-block b{font-size:12px}.gateway-default-block span{color:#61756a;font-size:10px;line-height:1.4}.gateway-default-block code{font:10px var(--font-mono,'DM Mono',monospace)}
      .gateway-template-list,.gateway-approval-list{display:grid;gap:11px}.gateway-template,.gateway-approval,.gateway-simulator,.gateway-connect-card{border:1px solid var(--gw-line);border-radius:9px;background:var(--gw-card)}
      .gateway-template{padding:15px 17px}.gateway-template-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.gateway-version{color:var(--gw-green);font:10px var(--font-mono,'DM Mono',monospace)}
      .gateway-template h3,.gateway-connect-card h3{margin:5px 0;color:var(--gw-ink);font:700 15px var(--font-display,'Manrope',sans-serif)}.gateway-template-head p{margin:0;color:var(--gw-muted);font-size:11px;line-height:1.5}
      .gateway-risk{border-radius:4px;padding:5px 8px;background:#f2eee4;color:#77613c;font-size:10px;white-space:nowrap}
      .gateway-rule-head,.gateway-rule-row{display:grid;grid-template-columns:1.2fr .65fr .8fr;gap:12px;padding:9px 10px;font-size:10px}
      .gateway-rule-head{margin-top:14px;border-bottom:1px solid var(--gw-line);color:#89928b;font:9px var(--font-mono,'DM Mono',monospace);text-transform:uppercase;letter-spacing:.07em}
      .gateway-rule-row{border-bottom:1px solid #eeece5;color:#53645d;line-height:1.45}.gateway-rule-row b{color:var(--gw-green)}.gateway-template-meta{display:flex;flex-wrap:wrap;gap:8px 22px;padding:10px 1px 0;color:#78837c;font-size:10px}
      .gateway-simulator{margin-top:18px;padding:17px}.gateway-simulator-title{display:flex;justify-content:space-between;align-items:center;gap:12px}.gateway-simulator-title h3{margin:5px 0 14px;font:700 16px var(--font-display,'Manrope',sans-serif)}
      .gateway-sim-badge{color:#79877f;font:10px var(--font-mono,'DM Mono',monospace)}.gateway-simulator form{display:grid;gap:10px}.gateway-simulator label,.gateway-connect-label{color:#53645d;font-size:11px;font-weight:600}
      .gateway-gateway select,.guardian-gateway select,.guardian-gateway input:not([type=checkbox]){width:100%;min-height:39px;border:1px solid #d6d8ce;border-radius:6px;padding:8px 10px;color:var(--gw-ink);background:#fffefa;font-size:12px}
      .gateway-field{display:grid;gap:5px}.gateway-field small{color:var(--gw-muted);font-weight:400}.gateway-field input[type=checkbox]{margin:0;width:18px;height:18px;accent-color:var(--gw-green)}
      .gateway-simulator-note,.gateway-connect-caveat{color:#78837c;font-size:10px;line-height:1.55}.gateway-simulator-note{margin:2px 0}
      .guardian-gateway button:not(.gateway-tab){display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:38px;border:1px solid var(--gw-green);border-radius:6px;padding:0 12px;color:#fffdf8;background:var(--gw-green);font-size:11px;font-weight:700;transition:transform .16s ease,opacity .16s ease}
      .guardian-gateway button:not(.gateway-tab):hover:not(:disabled){transform:translateY(-1px)}.guardian-gateway button:disabled{cursor:not-allowed;opacity:.48}
      .gateway-result{margin:12px 0 0;padding:10px 12px;border-left:3px solid var(--gw-green);background:#edf3ec;color:#385e49;font-size:11px;line-height:1.5}
      .gateway-empty,.gateway-skeleton{padding:20px;border:1px dashed #cfd5cb;border-radius:8px;background:#fbfaf5;color:#77837c;font-size:12px;text-align:center}
      .gateway-skeleton{display:grid;gap:9px}.gateway-skeleton span{height:10px;border-radius:4px;background:#eae9e2}.gateway-skeleton span:nth-child(1){width:46%}.gateway-skeleton span:nth-child(2){width:88%}.gateway-skeleton span:nth-child(3){width:68%}
      .gateway-alert{margin-bottom:14px;padding:11px 13px;border:1px solid #e8c9c3;border-radius:6px;color:#914f45;background:#fbefec;font-size:11px}
      .gateway-approval{padding:15px 17px}.gateway-approval-head{display:flex;align-items:center;justify-content:space-between;gap:12px}
      .gateway-status{border-radius:999px;padding:5px 9px;background:#f1eee5;color:#766342;font-size:10px}.gateway-status-approved{background:#e7f1e8;color:#3d7452}.gateway-status-rejected,.gateway-status-denied{background:#f7e9e6;color:#9a4e43}
      .gateway-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 22px;margin:15px 0}.gateway-facts>div{min-width:0}.gateway-facts dt{color:#858f89;font:9px var(--font-mono,'DM Mono',monospace);text-transform:uppercase;letter-spacing:.06em}.gateway-facts dd{margin:4px 0 0;color:#41564c;font-size:11px;line-height:1.5;overflow-wrap:anywhere}
      .gateway-actions{display:flex;gap:8px}.guardian-gateway .gateway-actions .gateway-reject{border-color:#b75a4d;color:#a44e43;background:transparent}.gateway-muted{color:#78837c;font-size:11px}
      .gateway-metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:18px 0 24px}.gateway-metrics>div{display:grid;gap:7px;padding:14px;border:1px solid var(--gw-line);border-radius:8px;background:#fbfaf5}.gateway-metrics span{color:#78837c;font-size:10px}.gateway-metrics b{color:#2e5141;font:600 21px var(--font-mono,'DM Mono',monospace)}
      .gateway-ledger-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 10px}.gateway-ledger-head h3{margin:0;font:700 14px var(--font-display,'Manrope',sans-serif)}.gateway-ledger-head>span{color:#79847d;font-size:10px}
      .gateway-event-list{display:grid;gap:0;margin:0;padding:0;list-style:none}.gateway-event-list li{display:grid;grid-template-columns:44px 1fr auto;gap:12px;align-items:start;padding:13px 8px;border-bottom:1px solid var(--gw-line)}
      .gateway-event-sequence{color:var(--gw-green);font:11px var(--font-mono,'DM Mono',monospace)}.gateway-event-list li>div{display:grid;gap:4px;min-width:0}.gateway-event-list li>div b{color:#40584c;font-size:11px}.gateway-event-list li>div span,.gateway-event-list li code{color:#76827b;font-size:10px;overflow-wrap:anywhere}.gateway-receipt-state{color:#6e7d73;font-size:10px}
      .gateway-export{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:17px;padding:13px 14px;border:1px solid var(--gw-line);border-radius:8px;background:#fbfaf5}.gateway-export b{font-size:11px}.gateway-export p{margin:4px 0 0;color:var(--gw-muted);font-size:10px;line-height:1.5}
      .gateway-connect-label{display:block;margin-bottom:7px}.gateway-connect-card{position:relative;margin-top:14px;padding:20px}.gateway-connect-icon{display:grid;width:38px;height:38px;place-items:center;border-radius:8px;background:#e9f0e9;color:var(--gw-green)}
      .gateway-connect-card h3{margin-top:14px;font-size:17px}.gateway-connect-card ol{display:grid;gap:9px;padding-left:20px;color:#62716a;font-size:11px;line-height:1.55}
      .gateway-command{display:grid;gap:8px;margin-top:17px;padding:13px;border-radius:7px;background:#233549;color:#e4ece7}.gateway-command span{color:#a7b9b4;font:9px var(--font-mono,'DM Mono',monospace)}.gateway-command code{font:11px var(--font-mono,'DM Mono',monospace);overflow-wrap:anywhere}.gateway-command button{justify-self:start!important}
      .gateway-connect-caveat{display:flex;align-items:center;gap:7px;margin-top:13px}.gateway-connect-caveat svg{flex:none;color:var(--gw-green)}
      @media(max-width:700px){.guardian-gateway{padding:17px}.gateway-header{flex-direction:column}.gateway-mode{white-space:normal}.gateway-nav{margin-inline:-17px;padding-inline:17px}.gateway-tab{padding-inline:10px}.gateway-tab-arrow{display:none}.gateway-section-title{align-items:flex-start;flex-direction:column}.gateway-rule-head,.gateway-rule-row{grid-template-columns:1fr;gap:4px}.gateway-rule-head{display:none}.gateway-rule-row{padding:10px}.gateway-rule-row span:first-child:before{content:'Condición: ';color:#89928b}.gateway-rule-row b:before{content:'Decisión: ';font-weight:400;color:#89928b}.gateway-rule-row span:last-child:before{content:'Aprobador: ';color:#89928b}.gateway-facts{grid-template-columns:1fr}.gateway-metrics{grid-template-columns:1fr}.gateway-event-list li{grid-template-columns:38px 1fr}.gateway-receipt-state{grid-column:2}.gateway-export{align-items:flex-start;flex-direction:column}.gateway-template-head{flex-direction:column}.gateway-default-block{align-items:flex-start;flex-wrap:wrap}.gateway-default-block code{margin-left:29px}}
      @media(prefers-reduced-motion:reduce){.guardian-gateway *{scroll-behavior:auto!important;transition:none!important}}
    `}</style>
    <header className="gateway-header">
      <div className="gateway-heading">
        <span className="gateway-kicker"><Shield size={14} /> GUARDIAN NEXUS / CONTROL DE PROPUESTAS</span>
        <h1>Pasarela de acciones</h1>
        <p>Revisión de propuestas en el ámbito del espacio <code data-testid="gateway-workspace-id">{workspaceId || unavailable}</code>.</p>
      </div>
      <div className="gateway-mode" data-testid="gateway-shadow-mode"><span /> Modo sombra · no intercepta herramientas</div>
    </header>
    <div className="gateway-disclosure" role="note" data-testid="gateway-fictitious-notice">
      <CircleAlert size={17} /><p><b>Alcance honesto.</b> Los ejemplos y buzones son sintéticos. Las plantillas no se editan ni guardan; las propuestas de prueba sí se registran para aprobación, pero no se despachan aquí. No hay pagos ni efectos externos.</p>
    </div>

    <nav className="gateway-nav" role="tablist" aria-label="Secciones de la pasarela">
      {sections.map(({ id, label, icon: Icon }) => <button key={id} id={`gateway-tab-${id}`} type="button" role="tab" aria-selected={section === id} aria-controls={`gateway-panel-${id}`} className={section === id ? "gateway-tab gateway-tab-active" : "gateway-tab"} onClick={() => setSection(id)} data-testid={`gateway-tab-${id}`}>
        <Icon size={16} /><span>{label}</span><ChevronRight size={14} className="gateway-tab-arrow" />
      </button>)}
    </nav>

    <div className="gateway-panel" role="tabpanel" id={`gateway-panel-${section}`} aria-labelledby={`gateway-tab-${section}`} data-testid={`gateway-panel-${section}`}>
      {error && <div className="gateway-alert" role="alert" data-testid="gateway-error">{error}</div>}
      {loading && <div className="gateway-skeleton" role="status" data-testid="gateway-loading"><span /><span /><span />Cargando datos suministrados…</div>}

      {section === "rules" && !loading && <div className="gateway-section">
        <div className="gateway-section-title"><div><span className="gateway-kicker">01 / POLÍTICA DECLARATIVA</span><h2>Reglas por plantillas</h2><p>Las reglas describen decisiones; no se guardan ni se aplican desde esta vista.</p></div><span className="gateway-count">{actionTemplates.length} plantillas</span></div>
        <div className="gateway-default-block" data-testid="gateway-default-block"><LockKeyhole size={17} /><div><b>Acciones no listadas: bloqueadas por defecto</b><span>Es una regla de diseño para el futuro gateway; esta demostración no intercepta llamadas.</span></div><code>DEFAULT · DENY</code></div>
        {actionTemplates.length === 0 ? <div className="gateway-empty" data-testid="gateway-empty-templates">No hay plantillas suministradas. No se crean reglas de ejemplo.</div> : <div className="gateway-template-list">
          {actionTemplates.map((template) => <article className="gateway-template" key={`${template.actionType}-${template.version}`} data-testid={`gateway-template-${template.actionType}`}>
            <div className="gateway-template-head"><div><span className="gateway-version">{template.version}</span><h3>{template.label}</h3><p>{template.description || unavailable}</p>{template.businessArea && <small data-testid={`gateway-area-${template.actionType}`}>{template.businessArea}</small>}</div><span className="gateway-risk">{template.riskLabel || unavailable}</span></div>
            <div className="gateway-rule-head"><span>Condición</span><span>Decisión</span><span>Aprobador</span></div>
            {template.rules.length ? template.rules.map((rule, index) => <div className="gateway-rule-row" key={`${template.actionType}-rule-${index}`} data-testid={`gateway-rule-${template.actionType}-${index}`}><span>{rule.condition || unavailable}</span><b>{rule.decision || unavailable}</b><span>{rule.approver || unavailable}</span></div>) : <div className="gateway-rule-row" data-testid={`gateway-rule-default-${template.actionType}`}><span>Sin regla específica</span><b>{template.defaultDecision || unavailable}</b><span>{template.approverLabel || unavailable}</span></div>}
            <div className="gateway-template-meta"><span>Caducidad: {Number.isFinite(template.expiryMinutes) ? `${template.expiryMinutes} min` : unavailable}</span><span>Segundo aprobador independiente: {template.requiresIndependentApprover ? "Sí" : "No"}</span></div>
          </article>)}
          {unconfiguredAreaTemplates.map((area) => <article className="gateway-template" key={area.id} data-testid={area.id}>
            <div className="gateway-template-head"><div><span className="gateway-version">{area.id}</span><h3>{area.label}</h3><p>No hay una acción habilitada para esta categoría en el catálogo; no se evalúan ni registran propuestas.</p></div><span className="gateway-risk">No configurada</span></div>
            <div className="gateway-rule-row"><span>Acción no configurada</span><b>DENY · por defecto</b><span>No aplica</span></div>
          </article>)}
        </div>}
        <section className="gateway-simulator" aria-labelledby="gateway-simulator-title" data-testid="gateway-simulator">
          <div className="gateway-simulator-title"><div><span className="gateway-kicker">SIMULADOR EN MEMORIA</span><h3 id="gateway-simulator-title">Probar una propuesta</h3></div><span className="gateway-sim-badge">No persistente</span></div>
          <form onSubmit={submitProposal} data-testid="gateway-proposal-form">
            <label htmlFor="gateway-action-select">Acción permitida por plantilla</label>
            <select id="gateway-action-select" value={selectedTemplate?.actionType ?? ""} onChange={(event) => { setSelectedAction(event.target.value); setArgs({}); setSimulationResult(""); setProposalResult(""); }} disabled={!actionTemplates.length} data-testid="gateway-action-select">
              {actionTemplates.length ? actionTemplates.map((template) => <option key={template.actionType} value={template.actionType}>{template.label} · {template.version}</option>) : <option value="">Sin acciones disponibles</option>}
            </select>
            {selectedTemplate?.argumentFields.map((field) => <label className="gateway-field" key={field.name} htmlFor={`gateway-arg-${field.name}`}>{field.label}{field.required && <span aria-hidden="true"> · obligatorio</span>}{field.description && <small>{field.description}</small>}
              {field.type === "boolean" ? <input id={`gateway-arg-${field.name}`} type="checkbox" checked={Boolean(args[field.name])} onChange={(event) => setArgs((previous) => ({ ...previous, [field.name]: event.target.checked }))} data-testid={`gateway-argument-${field.name}`} /> : <input id={`gateway-arg-${field.name}`} type={field.type === "number" ? "number" : "text"} required={field.required} placeholder={field.placeholder ?? undefined} value={textOrNumberInputValue(args[field.name])} onChange={(event) => setArgs((previous) => ({ ...previous, [field.name]: field.type === "number" && event.target.value ? Number(event.target.value) : event.target.value }))} data-testid={`gateway-argument-${field.name}`} />}
            </label>)}
            <p className="gateway-simulator-note">La previsualización evalúa la misma plantilla sin guardar. Enviar propuesta sí registra la solicitud y, si procede, crea una aprobación; ninguna opción ejecuta una herramienta.</p>
            <div className="gateway-actions">
              <button type="button" disabled={!selectedTemplate || actionPending} onClick={() => void simulateAction()} data-testid="gateway-button-simulate">Simular decisión</button>
              <button type="submit" disabled={!selectedTemplate || !selectedTemplate.proposalEnabled || actionPending || !canPropose} data-testid="gateway-button-propose">{actionPending ? "Procesando…" : "Enviar propuesta"}</button>
            </div>
            {!canPropose && <small>Solo owner/admin puede registrar propuestas o decidir aprobaciones.</small>}
            {selectedTemplate && !selectedTemplate.proposalEnabled && <small>Esta acción mantiene su flujo sintético existente; el formulario genérico solo registra las acciones compatibles del catálogo.</small>}
          </form>
          {simulationResult && <p className="gateway-result" role="status" data-testid="gateway-proposal-result">{simulationResult}</p>}
          {proposalResult && <p className="gateway-result" role="status" data-testid="gateway-proposal-submit-result">{proposalResult}</p>}
        </section>
      </div>}

      {section === "approvals" && <div className="gateway-section">
        <div className="gateway-section-title"><div><span className="gateway-kicker">02 / DECISIÓN HUMANA</span><h2>Bandeja de aprobaciones</h2><p>Solo registros proporcionados por el integrador; el panel no genera propuestas.</p></div><span className="gateway-count">{approvalCount ?? unavailable} registros</span></div>
        {!loading && approvals.length === 0 ? <div className="gateway-empty" data-testid="gateway-empty-approvals">No hay registros de aprobación suministrados.</div> : <div className="gateway-approval-list">{approvals.map((record) => <article className="gateway-approval" key={record.id} data-testid={`gateway-approval-${record.id}`}>
          <div className="gateway-approval-head"><span className="gateway-kicker">APROBACIÓN · {record.id}</span><span className={`gateway-status gateway-status-${record.status}`}>{statusLabel(record.status)}</span></div>
          <dl className="gateway-facts">
            <div><dt>Agente</dt><dd data-testid={`gateway-approval-agent-${record.id}`}>{displayFact(record.agentIdentity)}</dd></div>
            <div><dt>Acción</dt><dd>{displayFact(record.actionType)}</dd></div>
            <div><dt>Resumen</dt><dd>{displayFact(record.summary)}</dd></div>
            <div><dt>Regla aplicada</dt><dd>{displayFact(record.appliedRule)}</dd></div>
            <div><dt>Caducidad</dt><dd>{record.expiresAt ? new Date(record.expiresAt).toLocaleString("es-ES") : unavailable}</dd></div>
            <div><dt>Vínculo de propuesta</dt><dd><code>{displayFact(record.proposalBinding)}</code></dd></div>
            <div><dt>Verificación del recibo</dt><dd>{displayFact(record.receiptVerification)}</dd></div>
          </dl>
          {record.status === "pending" && record.canDecide && <div className="gateway-actions"><button type="button" disabled={decisionPendingId !== null} onClick={() => void submitDecision(record.id, "approve", record.proposalBinding)} data-testid={`gateway-approve-${record.id}`}>Aprobar · solo registrar decisión</button><button className="gateway-reject" type="button" disabled={decisionPendingId !== null} onClick={() => void submitDecision(record.id, "reject", record.proposalBinding)} data-testid={`gateway-reject-${record.id}`}>Rechazar</button></div>}
          {record.status === "pending" && !record.canDecide && <p className="gateway-muted" data-testid={`gateway-cannot-decide-${record.id}`}>La capacidad para decidir no está disponible para esta sesión.</p>}
        </article>)}</div>}
        {decisionResult && <p role="status" className="gateway-result" data-testid="gateway-decision-result">{decisionResult}</p>}
      </div>}

      {section === "activity" && <div className="gateway-section">
        <div className="gateway-section-title"><div><span className="gateway-kicker">03 / TRAZABILIDAD</span><h2>Actividad</h2><p>Resumen basado únicamente en valores suministrados.</p></div><span className="gateway-count"><Activity size={14} /> Registro</span></div>
        <div className="gateway-metrics">
          <div><span>Aprobaciones cargadas</span><b data-testid="gateway-count-approvals">{approvalCount ?? unavailable}</b></div>
          <div><span>Eventos cargados</span><b data-testid="gateway-count-events">{ledgerEventCount ?? unavailable}</b></div>
          <div><span>Recibos verificados</span><b data-testid="gateway-count-receipts">{verifiedReceiptCount ?? unavailable}</b></div>
          <div><span>Aprobadas en la lista</span><b data-testid="gateway-count-approved">{approvalStatusCounts?.approved ?? unavailable}</b></div>
          <div><span>Pendientes en la lista</span><b data-testid="gateway-count-pending">{approvalStatusCounts?.pending ?? unavailable}</b></div>
          <div><span>Rechazadas o caducadas en la lista</span><b data-testid="gateway-count-rejected">{approvalStatusCounts?.rejected ?? unavailable}</b></div>
          <div><span>Evaluaciones ALLOW/DENY persistidas</span><b data-testid="gateway-count-policy-decisions">{unavailable}</b></div>
        </div>
        <div className="gateway-ledger-head"><h3>Eventos recientes suministrados</h3><span>{accessState === "available" ? "Acceso disponible" : accessState === "restricted" ? "Acceso restringido" : "Acceso no disponible"}</span></div>
        {!loading && ledgerEvents.length === 0 ? <div className="gateway-empty" data-testid="gateway-empty-events">No hay eventos suministrados.</div> : <ol className="gateway-event-list">{ledgerEvents.map((event) => <li key={`${event.sequence}-${event.approvalId}`} data-testid={`gateway-event-${event.sequence}`}>
          <span className="gateway-event-sequence">#{event.sequence}</span><div><b>{event.eventType || unavailable}</b><span>Aprobación {event.approvalId || unavailable} · {event.timestamp ? new Date(event.timestamp).toLocaleString("es-ES") : unavailable}</span><code>{displayFact(event.hash)}</code></div><span className="gateway-receipt-state">Recibo: {displayFact(event.receiptState)}</span>
        </li>)}</ol>}
        {missingApprovalIds.length > 0 && <div className="gateway-alert" data-testid="gateway-missing-receipts">
          <p>Faltan {missingApprovalIds.length} recibos que el servidor no conserva:</p>
          <ul>{missingApprovalIds.map((approvalId) => <li key={approvalId}>approvalId <code>{approvalId}</code></li>)}</ul>
          <p>Cárguelos en Aprobaciones durante esta sesión para habilitar la exportación.</p>
        </div>}
        <div className="gateway-export"><div><b>Exportar historial verificable</b><p>La exportación solo se habilita si se dispone de los recibos requeridos por los eventos; el servidor vuelve a validar su correspondencia.</p></div><button type="button" disabled={exporting || accessState !== "available" || missingApprovalIds.length > 0} onClick={onExport} data-testid="gateway-button-export"><ArrowDownToLine size={15} />{exporting ? "Preparando…" : "Descargar bundle JSON"}</button></div>
      </div>}

      {section === "connect" && <div className="gateway-section">
        <div className="gateway-section-title"><div><span className="gateway-kicker">04 / INTEGRACIÓN FUTURA</span><h2>Conectar agente</h2><p>Guía de preparación. No establece conexiones ni genera credenciales.</p></div><span className="gateway-count">Sin conexión activa</span></div>
        <label className="gateway-connect-label" htmlFor="gateway-framework">Punto de integración</label>
        <select id="gateway-framework" value={framework} onChange={(event) => setFramework(event.target.value)} data-testid="gateway-framework-select">
          <option value="gateway">Gateway HTTP propio</option><option value="framework">Framework de agentes</option><option value="library">Biblioteca cliente</option><option value="api">API directa</option>
        </select>
        <div className="gateway-connect-card" data-testid="gateway-connection-guide"><div className="gateway-connect-icon"><Code2 size={19} /></div>
          {framework === "gateway" && <><h3>Interponer un gateway controlado por tu equipo</h3><ol><li>Identifica cada llamada de herramienta antes de ejecutarla.</li><li>Envía una propuesta estructurada al integrador con el ámbito del espacio.</li><li>Verifica la respuesta y conserva el flujo normal hasta que exista enforcement real.</li></ol></>}
          {framework === "framework" && <><h3>Adaptar el ciclo de herramientas del framework</h3><ol><li>Localiza el punto de despacho de acciones, no el texto conversacional.</li><li>Construye una propuesta con tipo versionado y argumentos validados.</li><li>No consideres una decisión de este panel como autorización ejecutable.</li></ol></>}
          {framework === "library" && <><h3>Encapsular el cliente de herramientas</h3><ol><li>Define un adaptador local que describa argumentos y contexto.</li><li>Mantén el identificador del espacio explícito y validado.</li><li>Las respuestas de este panel no son una biblioteca ni un contrato de API.</li></ol></>}
          {framework === "api" && <><h3>Preparar una futura integración API</h3><ol><li>Espera el contrato publicado por el equipo integrador.</li><li>Valida versión, ámbito y vínculo de propuesta en el lado servidor.</li><li>No envíes secretos ni asumas que esta vista protege operaciones.</li></ol></>}
          <div className="gateway-command"><span>Comando de prueba seguro · local · no ejecuta acciones</span><code>{"printf '%s\\n' '{\"actionType\":\"example.v1\",\"args\":{}}'"}</code><button type="button" onClick={() => setSimulationResult("Comando local de ejemplo seleccionado; no se ha ejecutado.")} data-testid="gateway-button-safe-command">Ver confirmación del comando</button></div>
        </div>
        <p className="gateway-connect-caveat"><GitBranch size={15} /> Guía ilustrativa ficticia. El contrato, autenticación, validación de servidor y enforcement están fuera de este componente.</p>
      </div>}
    </div>
  </section>;
}

export default GuardianActionGatewayPanel;
