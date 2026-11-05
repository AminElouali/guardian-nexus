import React, { useState } from 'react';
import {
  CircleAlert,
  CircleCheck,
  Activity,
  ArrowRight,
  Clock3,
  CircleHelp,
  Cloud,
  Code2,
  Database,
  FlaskConical,
  Globe2,
  Mail,
  Network,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  WalletCards,
  type LucideIcon,
} from 'lucide-react';
import {
  type AiAssessmentLabJob,
  type AiAssessmentLabJobRequestProfileId,
  type GuardianPolicyLabPreviewResponse,
} from '@workspace/api-client-react';
import { Button } from '@/components/ui/button';

type PolicyLabEvidence = Extract<
  NonNullable<AiAssessmentLabJob['result']>,
  { engine: 'guardian_policy_lab' }
>;

type PolicyLabProfile = Extract<
  AiAssessmentLabJobRequestProfileId,
  `guardian-agent-lab-${string}-v1`
>;
type FreshPolicyPreview = {
  profileId: PolicyLabProfile;
  caseId: string;
  evidence: GuardianPolicyLabPreviewResponse['evidence'];
};

export const AGENT_POLICY_LABS: Array<{
  profileId: PolicyLabProfile;
  verticalId: string;
  title: string;
  selectorLabel: string;
  icon: LucideIcon;
  summary: string;
  testFocus: string;
  benignCaseId: string;
  adversarialCaseId: string;
}> = [
  {
    profileId: 'guardian-agent-lab-email-v1',
    verticalId: 'email',
    title: 'Correo',
    selectorLabel: 'Correo',
    icon: Mail,
    summary: 'Lectura y borradores locales; bloquea envíos externos y exfiltración.',
    testFocus: 'Inyección dentro de un correo sintético',
    benignCaseId: 'email_benign_read_and_draft',
    adversarialCaseId: 'email_adversarial_external_exfiltration',
  },
  {
    profileId: 'guardian-agent-lab-database-v1',
    verticalId: 'database',
    title: 'Bases de datos',
    selectorLabel: 'Datos',
    icon: Database,
    summary: 'Consulta una fila sintética; rechaza exportaciones entre espacios y borrados.',
    testFocus: 'Instrucción de exportación masiva en un documento',
    benignCaseId: 'database_benign_scoped_read',
    adversarialCaseId: 'database_adversarial_bulk_export',
  },
  {
    profileId: 'guardian-agent-lab-finance-v1',
    verticalId: 'finance',
    title: 'Finanzas',
    selectorLabel: 'Finanzas',
    icon: WalletCards,
    summary: 'Lectura de factura ficticia; transferencias requieren aprobación humana.',
    testFocus: 'Solicitud de transferencia desde contenido no confiable',
    benignCaseId: 'finance_benign_invoice_read',
    adversarialCaseId: 'finance_adversarial_transfer_request',
  },
  {
    profileId: 'guardian-agent-lab-programming-v1',
    verticalId: 'programming',
    title: 'Programación',
    selectorLabel: 'Código',
    icon: Code2,
    summary: 'Propone un cambio de ejemplo; no ejecuta comandos del host.',
    testFocus: 'Intento de comando y lectura de secretos',
    benignCaseId: 'programming_benign_diff_proposal',
    adversarialCaseId: 'programming_adversarial_host_command',
  },
  {
    profileId: 'guardian-agent-lab-customer-service-v1',
    verticalId: 'customer_service',
    title: 'Atención al cliente',
    selectorLabel: 'Soporte',
    icon: CircleHelp,
    summary: 'Prepara una respuesta ficticia; reembolsos quedan pendientes de aprobación.',
    testFocus: 'Petición de reembolso incrustada en un ticket',
    benignCaseId: 'support_benign_ticket_reply_draft',
    adversarialCaseId: 'support_adversarial_refund_request',
  },
  {
    profileId: 'guardian-agent-lab-browser-v1',
    verticalId: 'browser',
    title: 'Navegador',
    selectorLabel: 'Web',
    icon: Globe2,
    summary: 'Lee páginas de laboratorio; no visita ni envía formularios a terceros.',
    testFocus: 'Formulario externo solicitado por una página sintética',
    benignCaseId: 'browser_benign_local_page_read',
    adversarialCaseId: 'browser_adversarial_external_form_submit',
  },
  {
    profileId: 'guardian-agent-lab-infrastructure-v1',
    verticalId: 'infrastructure',
    title: 'Infraestructura',
    selectorLabel: 'Cloud',
    icon: Cloud,
    summary: 'Consulta configuración ficticia; deniega escaladas y borrados.',
    testFocus: 'Concesión de rol administrador no autorizada',
    benignCaseId: 'infrastructure_benign_config_read',
    adversarialCaseId: 'infrastructure_adversarial_admin_grant',
  },
  {
    profileId: 'guardian-agent-lab-multiagent-v1',
    verticalId: 'multiagent',
    title: 'Multiagente',
    selectorLabel: 'Multiagente',
    icon: Network,
    summary: 'Conserva actor y permisos originales al delegar.',
    testFocus: 'Intento de elevar privilegios mediante delegación',
    benignCaseId: 'multiagent_benign_read_only_delegation',
    adversarialCaseId: 'multiagent_adversarial_permission_escalation',
  },
];

const decisionLabel: Record<string, string> = {
  allow: 'Permitida en la simulación',
  deny: 'Denegada por política',
  require_approval: 'Requiere aprobación humana',
  bypassed_counterfactual: 'Contrafactual sin enforcement',
};

const adapterStatusLabel: Record<string, string> = {
  simulated_execution: 'Adaptador ficticio ejecutado solo en memoria.',
  adapter_validation_denied: 'El adaptador rechazó la propuesta; no se ejecutó.',
  approval_required_before_dispatch: 'Pendiente de aprobación; el adaptador no se invocó.',
  blocked_by_policy_before_dispatch: 'Bloqueada antes de invocar el adaptador.',
  counterfactual_clone_only: 'Contrafactual; no se invocó el adaptador.',
};

const reasonLabel: Record<string, string> = {
  synthetic_policy_allowlist: 'Operación de laboratorio dentro del permiso mínimo.',
  permission_not_granted: 'El actor no tiene el permiso solicitado.',
  resource_outside_workspace: 'El recurso pertenece a otro espacio y queda denegado.',
  delegated_permissions_exceed_parent: 'La delegación solicita más permisos que el agente original.',
  external_destination_not_allowed: 'El destino externo no está permitido en este laboratorio.',
  human_approval_required: 'La operación sensible no se ejecuta sin aprobación humana.',
  operation_outside_policy: 'La operación no pertenece a la lista permitida.',
  untrusted_content_cannot_authorize_action: 'El contenido no confiable no puede autorizar una acción.',
  synthetic_tool_adapter_validation_failed: 'El adaptador sintético rechazó la propuesta.',
};

const caseTitle: Record<string, string> = {
  email_benign_read_and_draft: 'Borrador de correo ficticio',
  email_adversarial_external_exfiltration: 'Intento de envío externo no autorizado',
  database_benign_scoped_read: 'Lectura de registro sintético',
  database_adversarial_bulk_export: 'Intento de exportación masiva',
  finance_benign_invoice_read: 'Consulta de factura ficticia',
  finance_adversarial_transfer_request: 'Solicitud de transferencia no ejecutada',
  programming_benign_diff_proposal: 'Propuesta local de cambio',
  programming_adversarial_host_command: 'Intento de comando del host denegado',
  support_benign_ticket_reply_draft: 'Borrador de respuesta a ticket',
  support_adversarial_refund_request: 'Solicitud de reembolso pendiente de aprobación',
  browser_benign_local_page_read: 'Lectura de página local sintética',
  browser_adversarial_external_form_submit: 'Intento de formulario externo bloqueado',
  infrastructure_benign_config_read: 'Consulta de configuración ficticia',
  infrastructure_adversarial_admin_grant: 'Intento de elevar privilegios denegado',
  multiagent_benign_read_only_delegation: 'Delegación de lectura acotada',
  multiagent_adversarial_permission_escalation: 'Escalada de permisos por delegación bloqueada',
};

export function AgentPolicyLabCatalog({
  profiles,
  canRun,
  pending,
  previewPending,
  onRequest,
  onPreview,
  onReset,
  onSelectionChange,
  onViewApprovals,
  recordedEvidence,
  recordedArtifactSha256,
  freshPreview,
}: {
  profiles: Array<{ profileId: string; status: string; reasonCode: string | null }>;
  canRun: boolean;
  pending: boolean;
  previewPending: boolean;
  onRequest: (profileId: AiAssessmentLabJobRequestProfileId, focusCaseId: string) => void;
  onPreview: (profileId: PolicyLabProfile, focusCaseId: string) => void;
  onReset: () => void;
  onSelectionChange: () => void;
  onViewApprovals: () => void;
  recordedEvidence: PolicyLabEvidence[];
  recordedArtifactSha256: string;
  freshPreview: FreshPolicyPreview | null;
}) {
  const [selectedProfileId, setSelectedProfileId] = useState<PolicyLabProfile | null>(
    'guardian-agent-lab-email-v1',
  );
  const [selectedCaseKind, setSelectedCaseKind] = useState<'benign' | 'adversarial' | null>(
    'adversarial',
  );
  const [showRecordedEvidence, setShowRecordedEvidence] = useState(false);
  const busy = pending || previewPending;
  const selectedLab = AGENT_POLICY_LABS.find((lab) => lab.profileId === selectedProfileId);
  const selectedCaseId = selectedLab
    ? selectedCaseKind === 'benign'
      ? selectedLab.benignCaseId
      : selectedCaseKind === 'adversarial'
        ? selectedLab.adversarialCaseId
        : null
    : null;
  const selectedReady = profiles.find((profile) => profile.profileId === selectedProfileId)?.status === 'ready';
  const selectedRecordedEvidence = recordedEvidence.find(
    (evidence) => evidence.profileId === selectedProfileId,
  );
  const selectedFreshPreview =
    freshPreview?.profileId === selectedProfileId &&
    freshPreview.caseId === selectedCaseId
      ? freshPreview
      : null;

  function resetGuide() {
    setSelectedProfileId('guardian-agent-lab-email-v1');
    setSelectedCaseKind('adversarial');
    setShowRecordedEvidence(false);
    onSelectionChange();
    onReset();
  }

  return (
    <section
      id="guardian-agent-policy-lab"
      className="agent-policy-lab-catalog agent-policy-workbench"
      aria-labelledby="agent-policy-lab-title"
      data-testid="agent-policy-lab-catalog"
    >
      <div className="agent-policy-workbench-heading">
        <div>
          <span className="panel-kicker">GUARDIAN NEXUS / LABORATORIO</span>
          <h3 id="agent-policy-lab-title">Comprueba la seguridad de tus agentes</h3>
        </div>
        <span className="agent-policy-demo-badge"><i />Demo ficticia</span>
      </div>
      <p className="agent-policy-workbench-intro">
        Selecciona un agente y un escenario para ver cómo el Policy Engine evalúa una propuesta sintética.
      </p>

      <section className="agent-policy-workbench-stage" aria-labelledby="agent-policy-profile-heading">
        <div className="agent-policy-stage-heading">
          <span>1</span>
          <h4 id="agent-policy-profile-heading">Selecciona un agente</h4>
        </div>
        <div className="agent-policy-profile-grid" role="group" aria-label="Perfiles de agente">
        {AGENT_POLICY_LABS.map((lab) => {
          const ProfileIcon = lab.icon;
          const selected = selectedProfileId === lab.profileId;
          return (
            <div
              key={lab.profileId}
              className="agent-policy-profile-option"
              data-testid={`agent-policy-lab-${lab.verticalId}`}
            >
              <Button
                type="button"
                variant="outline"
                className={`agent-policy-profile-button ${selected ? 'is-selected' : ''}`}
                onClick={() => {
                  setSelectedProfileId(lab.profileId);
                  setSelectedCaseKind('adversarial');
                  setShowRecordedEvidence(false);
                  onSelectionChange();
                }}
                disabled={busy}
                aria-pressed={selected}
                aria-label={lab.title}
                data-testid={`button-select-agent-lab-${lab.verticalId}`}
              >
                <ProfileIcon size={18} strokeWidth={1.9} aria-hidden="true" />
                <span>{lab.selectorLabel}</span>
              </Button>
            </div>
          );
        })}
        </div>
      </section>

      <fieldset className="agent-policy-scenario-fieldset" disabled={!selectedLab || busy}>
        <legend className="agent-policy-stage-heading">
          <span>2</span>
          <b>Elige qué comprobar</b>
        </legend>
        <div className="agent-policy-scenario-options" role="radiogroup" aria-label="Tipo de escenario">
          <label className={`agent-policy-scenario-option ${selectedCaseKind === 'benign' ? 'is-selected' : ''}`}>
            <input
              type="radio"
              name="agent-policy-scenario"
              value="benign"
              checked={selectedCaseKind === 'benign'}
              onChange={() => {
                setSelectedCaseKind('benign');
                setShowRecordedEvidence(false);
                onSelectionChange();
              }}
              data-testid="button-select-agent-case-benign"
            />
            <CircleCheck size={20} aria-hidden="true" />
            <span><b>Acción legítima</b><small>Comprobar una tarea autorizada.</small></span>
          </label>
          <label className={`agent-policy-scenario-option ${selectedCaseKind === 'adversarial' ? 'is-selected' : ''}`}>
            <input
              type="radio"
              name="agent-policy-scenario"
              value="adversarial"
              checked={selectedCaseKind === 'adversarial'}
              onChange={() => {
                setSelectedCaseKind('adversarial');
                setShowRecordedEvidence(false);
                onSelectionChange();
              }}
              data-testid="button-select-agent-case-adversarial"
            />
            <CircleAlert size={20} aria-hidden="true" />
            <span><b>Intento de ataque</b><small>Comprobar si se bloquea una acción peligrosa.</small></span>
          </label>
        </div>
      </fieldset>

      <div className="agent-policy-primary-action">
        <Button
          type="button"
          onClick={() => selectedLab && selectedCaseId && onPreview(selectedLab.profileId, selectedCaseId)}
          disabled={!canRun || !selectedLab || !selectedCaseId || busy}
          data-testid="button-preview-policy-lab"
        >
          {previewPending ? <Activity className="spin" size={17} /> : <FlaskConical size={17} />}
          {previewPending ? 'Preparando previsualización…' : 'Ejecutar demostración'}
          {!previewPending && <ArrowRight size={17} />}
        </Button>
        <p>
          El backend calcula la evidencia del perfil y destaca el caso elegido. No crea un job ni
          despacha herramientas externas. La selección solo enfoca una fixture: no modifica reglas,
          corpus ni permisos.
        </p>
        {!canRun && <small role="status">Solo owner/admin puede iniciar la previsualización.</small>}
      </div>

      {selectedFreshPreview && selectedCaseId ? (
        <div className="agent-policy-result-wrap" data-testid="agent-policy-fresh-preview">
          <AgentPolicyLabResult
            evidence={selectedFreshPreview.evidence}
            focusedCaseId={selectedCaseId}
            onViewApprovals={onViewApprovals}
          />
          <Button
            type="button"
            variant="outline"
            onClick={resetGuide}
            disabled={busy}
            data-testid="button-reset-agent-demo"
          >
            <RotateCcw size={15} /> Probar otro escenario
          </Button>
        </div>
      ) : showRecordedEvidence && selectedRecordedEvidence && selectedCaseId ? (
        <div className="agent-policy-result-wrap" data-testid="agent-policy-recorded-sample">
          <AgentPolicyLabResult
            evidence={selectedRecordedEvidence}
            focusedCaseId={selectedCaseId}
            recordedSnapshot
            recordedArtifactSha256={recordedArtifactSha256}
            onViewApprovals={onViewApprovals}
          />
        </div>
      ) : (
        <div className="agent-policy-result-placeholder" role="status" data-testid="agent-policy-empty-result">
          <ShieldCheck size={20} aria-hidden="true" />
          <div><b>El resultado aparecerá aquí</b><span>Ejecuta la demostración para consultar la decisión del Policy Engine.</span></div>
        </div>
      )}

      <details className="agent-policy-evidence-details">
        <summary>Detalles técnicos, evidencia histórica y estado del worker</summary>
        <div className="agent-policy-evidence-content">
          <p>
            Los perfiles de esta pantalla son fixtures deterministas. No es inferencia de Qwen ni
            una llamada nativa.
            <code> NO_PROPOSAL</code> solo aparece en la evidencia Qwen y no equivale a
            <code> DENY</code>. La previsualización se calcula en la API y no es una frontera de aislamiento.
          </p>
          {selectedLab && selectedCaseId && selectedRecordedEvidence && !showRecordedEvidence && (
            <Button
              type="button"
              variant="outline"
              onClick={() => setShowRecordedEvidence(true)}
              disabled={busy}
              data-testid="button-view-recorded-policy-evidence"
            >
              Ver evidencia histórica guardada
            </Button>
          )}
          <div className="agent-policy-worker-request">
            <div>
              <b>Trabajo aislado del perfil</b>
              <span>{selectedReady ? 'Disponible según el preflight actual.' : 'No disponible tras el preflight actual.'}</span>
            </div>
            <Button
              type="button"
              variant="outline"
              onClick={() => selectedLab && selectedCaseId && onRequest(selectedLab.profileId, selectedCaseId)}
              disabled={!canRun || !selectedLab || !selectedCaseId || !selectedReady || busy}
              data-testid="button-run-guided-agent-demo"
            >
              {pending ? <Activity className="spin" size={15} /> : <FlaskConical size={15} />}
              {pending ? 'Encolando recorrido…' : 'Solicitar trabajo aislado'}
            </Button>
          </div>
          {showRecordedEvidence && selectedRecordedEvidence && selectedCaseId && (
            <div className="agent-policy-recorded-sample" data-testid="agent-policy-recorded-detail">
              <p role="status">Evidencia histórica de solo lectura: no representa una ejecución nueva ni modifica la auditoría.</p>
              <AgentPolicyLabResult
                evidence={selectedRecordedEvidence}
                focusedCaseId={selectedCaseId}
                recordedSnapshot
                recordedArtifactSha256={recordedArtifactSha256}
                onViewApprovals={onViewApprovals}
              />
            </div>
          )}
        </div>
      </details>
    </section>
  );
}

export function AgentPolicyLabResult({
  evidence,
  focusedCaseId,
  recordedSnapshot = false,
  recordedArtifactSha256,
  onViewApprovals,
}: {
  evidence: PolicyLabEvidence;
  focusedCaseId?: string;
  recordedSnapshot?: boolean;
  recordedArtifactSha256?: string;
  onViewApprovals?: () => void;
}) {
  const focusedCase = evidence.cases.find((item) => item.caseId === focusedCaseId);
  const decision = focusedCase?.policyOn.decision;
  const focusedReason = focusedCase
    ? reasonLabel[focusedCase.policyOn.reasonCode] ?? focusedCase.policyOn.reasonCode
    : '';
  const focusedReasonSentence = focusedReason.endsWith('.')
    ? focusedReason
    : `${focusedReason}.`;
  const decisionHeading = decision === 'allow'
    ? 'Acción permitida en la simulación'
    : decision === 'deny'
      ? 'Acción bloqueada'
      : decision === 'require_approval'
        ? 'Requiere aprobación humana'
        : decision === 'bypassed_counterfactual'
          ? 'Solo contrafactual'
          : 'Resultado del laboratorio';
  const DecisionIcon = decision === 'allow'
    ? ShieldCheck
    : decision === 'require_approval'
      ? Clock3
      : ShieldAlert;
  const actionOutcome = !focusedCase
    ? 'Revisa el detalle de cada caso para consultar el resultado.'
    : focusedCase.policyOn.executed
      ? 'La acción solo cambió el estado sintético efímero del simulador; no hubo efectos externos.'
      : decision === 'require_approval'
        ? 'No se ejecutó. Esta previsualización no crea una solicitud persistente de aprobación.'
        : decision === 'deny'
          ? 'Se detuvo antes de invocar el adaptador; no se ejecutó.'
          : 'No se ejecutó ninguna acción externa.';
  return (
    <section className="agent-policy-lab-result" data-testid="agent-policy-lab-result">
      <div className="agent-policy-result-head">
        <div>
          <span className="panel-kicker">DECISIÓN DEL POLICY ENGINE · PROPUESTA DE FIXTURE DETERMINISTA</span>
          <h4>{focusedCase ? caseTitle[focusedCase.caseId] ?? focusedCase.caseId : `Laboratorio ${evidence.verticalLabel}`}</h4>
        </div>
        <span className={`agent-policy-result-decision agent-policy-result-${decision ?? 'unknown'}`}>
          <DecisionIcon size={18} aria-hidden="true" />
          {decisionLabel[decision ?? ''] ?? 'Resultado disponible'}
        </span>
      </div>
      <div className="agent-policy-result-summary">
        <div>
          <b>{decisionHeading}</b>
          <p>{evidence.interpretation}</p>
        </div>
        <span>{evidence.summary.sampleCount} casos en el perfil · simulación ficticia</span>
      </div>
      {focusedCase && (
        <div className="agent-policy-result-story">
          <article>
            <b>Qué intentó hacer</b>
            <span>{focusedCase.tool} · {focusedCase.operation} sobre un recurso sintético.</span>
          </article>
          <article>
            <b>Qué decidió Guardian Nexus</b>
            <span>{decisionLabel[focusedCase.policyOn.decision] ?? focusedCase.policyOn.decision}.</span>
          </article>
          <article>
            <b>Por qué</b>
            <span>{focusedReasonSentence}</span>
          </article>
          <article>
            <b>Qué ocurrió</b>
            <span>{actionOutcome}</span>
          </article>
        </div>
      )}
      {recordedSnapshot && (
        <div className="agent-policy-recorded-notice" role="note">
          Evidencia histórica guardada; no se ejecutó nada al abrir esta vista.
          {recordedArtifactSha256 && <span> SHA-256 del artefacto fuente: <code>{recordedArtifactSha256}</code></span>}
        </div>
      )}
      <details className="agent-policy-result-details">
        <summary>Detalles técnicos y evidencia</summary>
        <p>
          La evidencia de este Policy Lab procede de fixtures deterministas; no es inferencia de LLM
          ni una llamada nativa a herramientas.
        </p>
        {evidence.executionContext === 'api_policy_preview' && (
          <div className="agent-policy-recorded-notice" role="note" data-testid="policy-preview-runtime-limit">
            Previsualización fresca del Policy Engine; no se creó un job. El proceso comparte identidad con la API:
            red y acceso al socket Docker no aislados ni verificados.
          </div>
        )}
        {focusedCase && (
          <section className="agent-policy-guided-result" aria-labelledby="agent-policy-guided-result-title" data-testid="agent-policy-guided-result">
            <span className="panel-kicker">CASO SELECCIONADO · {focusedCase.caseId}</span>
            <h4 id="agent-policy-guided-result-title">{caseTitle[focusedCase.caseId] ?? focusedCase.caseId}</h4>
            <ol>
              <li><b>Propuesta y procedencia</b><span>Fixture determinista controlado, no es inferencia de LLM, Qwen ni llamada nativa: {focusedCase.tool} · {focusedCase.operation}.</span></li>
              <li><b>Policy ON</b><span>{decisionLabel[focusedCase.policyOn.decision] ?? focusedCase.policyOn.decision} · {focusedReasonSentence}</span></li>
              <li><b>Acción simulada</b><span>{focusedCase.policyOn.executed ? 'Solo en estado sintético efímero.' : 'No ejecutada.'} Policy OFF permanece contrafactual y no despacha herramientas.</span></li>
              <li><b>Aprobación ficticia</b><span>{focusedCase.policyOn.decision === 'require_approval'
                ? 'Esta previsualización registra el requisito, pero no crea una aprobación persistente.'
                : 'No aplica a este caso.'} La bandeja muestra solo solicitudes existentes.</span></li>
              <li><b>Evidencia redactada</b><span>Hash de caso: <code>{focusedCase.caseEvidenceSha256}</code></span></li>
            </ol>
            {focusedCase.policyOn.decision === 'require_approval' && (
              <button
                type="button"
                className="agent-policy-approval-link"
                onClick={onViewApprovals}
                data-testid="link-guided-approval-inbox"
              >
                Ir a la bandeja de aprobaciones <ArrowRight size={14} />
              </button>
            )}
          </section>
        )}
        <dl>
          <dt>Policy ON</dt>
          <dd>{evidence.summary.allowed} permitido · {evidence.summary.denied} denegado · {evidence.summary.requiresApproval} requiere aprobación · {evidence.summary.simulatedExecutions} ejecución simulada</dd>
          <dt>Policy OFF</dt>
          <dd>{evidence.summary.policyOffCounterfactualWouldExecute} hipotéticos en clones · {evidence.summary.policyOffCloneStateChanges} cambios solo en clones · 0 ejecución real</dd>
          <dt>Efectos reales</dt>
          <dd>0 operaciones externas · 0 llamadas externas · 0 cambios persistentes</dd>
          <dt>Identidad sintética</dt>
          <dd>{evidence.agentIdentity.agentId} · {evidence.agentIdentity.actorId}</dd>
        </dl>
        <div className="agent-policy-lab-cases">
          {evidence.cases.map((item) => (
            <details key={item.caseId} open={item.caseId === focusedCaseId} data-testid={`agent-policy-case-${item.caseId}`}>
              <summary>{caseTitle[item.caseId] ?? item.caseId} — {decisionLabel[item.policyOn.decision] ?? item.policyOn.decision}</summary>
              <dl>
                <dt>Propuesta</dt><dd>{item.tool} · {item.operation} · {item.resourceType} sintético</dd>
                <dt>Origen de instrucción</dt><dd>{item.instructionProvenance}</dd>
                <dt>Agente y actor</dt><dd>{item.agentId} · {item.actorId} ({item.actorType})</dd>
                <dt>Espacio del recurso</dt><dd>{item.resourceWorkspaceId}</dd>
                <dt>Permisos concedidos</dt><dd>{item.grantedPermissions.join(', ') || 'ninguno'}</dd>
                <dt>Permisos solicitados</dt><dd>{item.requestedPermissions.join(', ')}</dd>
                <dt>Motivo de política</dt><dd>{reasonLabel[item.policyOn.reasonCode] ?? item.policyOn.reasonCode}</dd>
                <dt>Intento</dt><dd>{item.policyOn.attempted ? 'Registrado' : 'No observado'}</dd>
                <dt>Autorización</dt><dd>{item.policyOn.authorized ? 'Sí, solo en el simulador' : 'No'}</dd>
                <dt>Acción</dt><dd>{item.policyOn.executed ? 'Ejecutada en estado sintético efímero' : 'No ejecutada'}</dd>
                <dt>Adaptador ficticio</dt><dd>{item.toolTrace ? `${adapterStatusLabel[item.toolTrace.policyOn.dispatchStatus] ?? item.toolTrace.policyOn.dispatchStatus} Eventos: ${item.toolTrace.policyOn.events.map((event) => event.phase).join(', ') || 'ninguno'}. Policy OFF: no invocado.` : 'No hay traza del adaptador en esta evidencia anterior.'}</dd>
                <dt>Contrafactual OFF</dt><dd>Habría sido propuesta en un clon; jamás ejecutada ni persistida.</dd>
                <dt>Delegación</dt><dd>{item.delegation.isDelegatedAction ? 'Agente delegado; identidad original preservada.' : 'No aplica.'} Elevación permitida: no.</dd>
                <dt>Hash de propuesta</dt><dd>{item.proposalSha256}</dd>
                <dt>Hash de evidencia</dt><dd>{item.caseEvidenceSha256}</dd>
              </dl>
            </details>
          ))}
        </div>
        <details>
          <summary>Procedencia, límites y hashes</summary>
          <dl>
            <dt>Motor</dt><dd>{evidence.engineVersion} · política {evidence.versions.policy}</dd>
            <dt>Corpus y oráculo</dt><dd>{evidence.versions.corpus} · {evidence.versions.oracle} · semilla {evidence.seed}</dd>
            <dt>Adaptador de herramientas</dt><dd>{evidence.versions.toolAdapter ?? 'No registrado en evidencia anterior'}</dd>
            <dt>Propuestas</dt><dd>Fixture controlado; no Qwen, no tool calls nativas.</dd>
            <dt>Red declarada</dt><dd>{evidence.limits.network}</dd>
            <dt>Entorno</dt><dd>{evidence.executionContext === 'api_policy_preview'
              ? 'Proceso API compartido; red y acceso al socket Docker no aislados ni verificados.'
              : 'Worker Docker network=none; sin secretos, pesos del modelo ni socket montado.'}</dd>
            <dt>Datos</dt><dd>No se guardan prompts, instrucciones ni argumentos en bruto; solo metadatos y hashes.</dd>
            <dt>Hash de suite</dt><dd>{evidence.suiteEvidenceSha256}</dd>
            <dt>Hash de evidencia</dt><dd>{evidence.evidenceSha256}</dd>
            {recordedSnapshot && recordedArtifactSha256 && <><dt>SHA-256 del artefacto fuente</dt><dd><code>{recordedArtifactSha256}</code></dd></>}
          </dl>
          <small>Dos o tres casos por vertical son una demostración acotada, no una medición de eficacia general.</small>
        </details>
      </details>
    </section>
  );
}
