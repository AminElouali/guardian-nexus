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
import {
  getPolicyOutcomePresentation,
  getPublicCaseLabel,
  getPublicDecisionLabel,
  getPublicDispatchStatusLabel,
  getPublicInstructionSourceLabel,
  getPublicReasonLabel,
  getPublicVerticalLabel,
} from './security-ui-copy';

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
        Selecciona un perfil y un escenario para comprobar si una solicitud respeta los permisos definidos.
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
          El servicio prepara el resultado del perfil y destaca el caso elegido. No inicia una
          evaluación en segundo plano ni una operación externa. La selección solo muestra un caso predefinido: no modifica
          las decisiones ni los permisos.
        </p>
        {!canRun && <small role="status">Solo las personas administradoras del espacio pueden iniciar esta prueba.</small>}
      </div>

      {selectedFreshPreview && selectedCaseId ? (
        <div className="agent-policy-result-wrap" data-testid="agent-policy-fresh-preview">
          <AgentPolicyLabResult
            evidence={selectedFreshPreview.evidence}
            focusedCaseId={selectedCaseId}
            showTechnicalDetails={canRun}
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
          <div><b>El resultado aparecerá aquí</b><span>Ejecuta la demostración para ver el resultado y su explicación.</span></div>
        </div>
      )}

      <details className="agent-policy-evidence-details">
        <summary>Límites de la demostración y evidencia</summary>
        <div className="agent-policy-evidence-content">
          <p>
            Esta pantalla usa escenarios sintéticos predefinidos, no una respuesta nueva de un agente.
            Si no hay una propuesta, se indica por separado y no se presenta como una denegación.
            Esta demostración no inicia un trabajo real ni confirma el aislamiento del entorno.
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
              <b>Prueba con el agente</b>
              <span>{selectedReady ? 'Disponible en este entorno.' : 'No disponible en este entorno. Los escenarios sintéticos siguen disponibles.'}</span>
            </div>
            <Button
              type="button"
              variant="outline"
              onClick={() => selectedLab && selectedCaseId && onRequest(selectedLab.profileId, selectedCaseId)}
              disabled={!canRun || !selectedLab || !selectedCaseId || !selectedReady || busy}
              data-testid="button-run-guided-agent-demo"
            >
              {pending ? <Activity className="spin" size={15} /> : <FlaskConical size={15} />}
              {pending ? 'Iniciando evaluación…' : 'Iniciar evaluación'}
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
                showTechnicalDetails={canRun}
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
  showTechnicalDetails = false,
  onViewApprovals,
}: {
  evidence: PolicyLabEvidence;
  focusedCaseId?: string;
  recordedSnapshot?: boolean;
  recordedArtifactSha256?: string;
  showTechnicalDetails?: boolean;
  onViewApprovals?: () => void;
}) {
  const focusedCase = evidence.cases.find((item) => item.caseId === focusedCaseId);
  const decision = focusedCase?.policyOn.decision;
  const presentation = focusedCase
    ? getPolicyOutcomePresentation(decision, focusedCase.policyOn.reasonCode, focusedCase.policyOn.executed)
    : null;
  const DecisionIcon = decision === 'allow'
    ? ShieldCheck
    : decision === 'require_approval'
      ? Clock3
      : ShieldAlert;
  const publicDecisionLabel = getPublicDecisionLabel(decision);
  return (
    <section
      className="agent-policy-lab-result agent-policy-incident-card"
      data-testid="agent-policy-lab-result"
      data-outcome={presentation?.tone ?? 'neutral'}
      aria-labelledby="agent-policy-result-title"
    >
      <div className="agent-policy-result-head agent-policy-incident-heading">
        <div>
          <span className="panel-kicker">SEGURIDAD · CONTROL DE ACCESO</span>
          <h4 id="agent-policy-result-title">
            {presentation?.title ?? `Resultado de la prueba · ${getPublicVerticalLabel(evidence.verticalLabel)}`}
          </h4>
        </div>
        <div className="agent-policy-incident-badges">
          <span className={`agent-policy-result-decision agent-policy-result-${presentation?.tone ?? 'neutral'}`}>
            <DecisionIcon size={18} aria-hidden="true" />
            {publicDecisionLabel}
          </span>
          <span className="agent-policy-simulation-badge">Simulación</span>
        </div>
      </div>
      <div className="agent-policy-result-summary">
        <div>
          <b>{focusedCase ? 'Resultado de la prueba' : 'Resultados del escenario'}</b>
          <p>
            {presentation?.summary ??
              'Selecciona un caso para consultar una explicación clara de la decisión y su alcance.'}
          </p>
        </div>
        <span>{evidence.summary.sampleCount} casos · datos sintéticos</span>
      </div>
      {focusedCase && (
        <div className="agent-policy-incident-body">
          <div className="agent-policy-incident-status" aria-label="Estado de la operación y de su ejecución">
            <div>
              <span>Operación</span>
              <strong>{presentation?.operationStatus}</strong>
            </div>
            <div>
              <span>Ejecución</span>
              <strong>{presentation?.executionStatus}</strong>
            </div>
          </div>
          <div className="agent-policy-incident-explanation">
            <section>
              <h5>¿Qué ha ocurrido?</h5>
              <p>{presentation?.whatHappened}</p>
            </section>
            <section>
              <h5>{decision === 'deny' ? '¿Por qué se ha bloqueado?' : decision === 'require_approval' ? '¿Por qué necesita aprobación?' : decision === 'allow' ? '¿Por qué se ha permitido?' : '¿Qué significa este resultado?'}</h5>
              <p>{presentation?.why}</p>
            </section>
            <section>
              <h5>¿Se ha realizado la operación?</h5>
              <p>{presentation?.execution}</p>
            </section>
            <section>
              <h5>¿Necesito hacer algo?</h5>
              <p>{presentation?.actionNeeded}</p>
            </section>
          </div>
          <div className="agent-policy-simulation-note" role="note">
            <FlaskConical size={17} aria-hidden="true" />
            <div>
              <strong>Prueba de seguridad</strong>
              <p>{presentation?.simulationNotice}</p>
            </div>
          </div>
        </div>
      )}
      {recordedSnapshot && (
        <div className="agent-policy-recorded-notice" role="note">
          Evidencia histórica de solo lectura. Abrir esta vista no realizó ninguna operación.
        </div>
      )}
      {showTechnicalDetails && <details className="agent-policy-result-details">
        <summary>Ver detalles de la prueba</summary>
        <p>
          La información técnica de la evaluación se conserva en los registros del espacio. Esta vista
          muestra un resumen redactado y no incluye instrucciones ni datos originales.
        </p>
        {evidence.executionContext === 'api_policy_preview' && (
          <div className="agent-policy-recorded-notice" role="note" data-testid="policy-preview-runtime-limit">
            Esta previsualización no demuestra el aislamiento del entorno ni acredita la seguridad de un sistema real.
          </div>
        )}
        {focusedCase && (
          <section className="agent-policy-guided-result" aria-labelledby="agent-policy-guided-result-title" data-testid="agent-policy-guided-result">
            <span className="panel-kicker">INFORMACIÓN DE LA PRUEBA</span>
            <h4 id="agent-policy-guided-result-title">{getPublicCaseLabel(focusedCase.caseId)}</h4>
            <ol>
              <li><b>Agente responsable</b><span>No identificado en esta prueba.</span></li>
              <li><b>Tipo de prueba</b><span>{getPublicVerticalLabel(evidence.verticalLabel)} · datos sintéticos.</span></li>
              <li><b>Motivo</b><span>{getPublicReasonLabel(focusedCase.policyOn.reasonCode)}</span></li>
              <li><b>Ejecución</b><span>{presentation?.execution}</span></li>
              <li><b>Acción necesaria</b><span>{presentation?.actionNeeded}</span></li>
              <li><b>Referencia verificable</b><span>SHA-256: <code>{focusedCase.caseEvidenceSha256}</code></span></li>
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
          <dt>Resultado de los controles</dt>
          <dd>{evidence.summary.allowed} permitidas · {evidence.summary.denied} bloqueadas · {evidence.summary.requiresApproval} requieren revisión</dd>
          <dt>Comparación hipotética</dt>
          <dd>{evidence.summary.policyOffCounterfactualWouldExecute} posibilidades calculadas en copias de prueba; no se ejecutaron.</dd>
          <dt>Operaciones externas</dt>
          <dd>Ninguna; esta prueba utiliza únicamente datos sintéticos.</dd>
        </dl>
        <div className="agent-policy-lab-cases">
          {evidence.cases.map((item, index) => (
            <details
              key={`${index}-${getPublicCaseLabel(item.caseId)}`}
              open={item.caseId === focusedCaseId}
              data-testid={`agent-policy-case-${index + 1}`}
            >
              <summary>{getPublicCaseLabel(item.caseId)} — {getPublicDecisionLabel(item.policyOn.decision)}</summary>
              <dl>
                <dt>Solicitud</dt><dd>{getPublicCaseLabel(item.caseId)}</dd>
                <dt>Origen</dt><dd>{getPublicInstructionSourceLabel(item.instructionProvenance)}</dd>
                <dt>Resultado</dt><dd>{getPublicDecisionLabel(item.policyOn.decision)}</dd>
                <dt>Motivo</dt><dd>{getPublicReasonLabel(item.policyOn.reasonCode)}</dd>
                <dt>Operación realizada</dt><dd>{item.policyOn.executed ? 'Solo dentro de la simulación.' : 'No realizada.'}</dd>
                <dt>Estado de la prueba</dt><dd>{getPublicDispatchStatusLabel(item.toolTrace?.policyOn.dispatchStatus)}</dd>
                <dt>Delegación</dt><dd>{item.delegation.isDelegatedAction ? 'Se conservaron los permisos del agente original.' : 'No aplica.'}</dd>
                <dt>Referencia verificable</dt><dd>SHA-256: {item.caseEvidenceSha256}</dd>
              </dl>
            </details>
          ))}
        </div>
        <details>
          <summary>Referencias y límites</summary>
          <dl>
            <dt>Tipo de resultado</dt><dd>Escenario sintético predefinido; no es una acción real.</dd>
            <dt>Alcance</dt><dd>Esta prueba no acredita la seguridad de un entorno de producción.</dd>
            <dt>Conexiones externas</dt><dd>Esta previsualización no inicia conexiones a servicios empresariales.</dd>
            <dt>Datos mostrados</dt><dd>Resumen redactado; no se incluyen instrucciones ni argumentos originales.</dd>
            <dt>Hash de suite</dt><dd>{evidence.suiteEvidenceSha256}</dd>
            <dt>Hash de evidencia</dt><dd>{evidence.evidenceSha256}</dd>
            {recordedSnapshot && recordedArtifactSha256 && <><dt>Referencia de evidencia histórica</dt><dd><code>{recordedArtifactSha256}</code></dd></>}
          </dl>
          <small>Los resultados corresponden a los escenarios incluidos; no son una medición de eficacia general.</small>
        </details>
      </details>}
    </section>
  );
}
