import React, { useState } from 'react';
import { Activity, ArrowRight, FlaskConical, RotateCcw } from 'lucide-react';
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
  summary: string;
  testFocus: string;
  benignCaseId: string;
  adversarialCaseId: string;
}> = [
  {
    profileId: 'guardian-agent-lab-email-v1',
    verticalId: 'email',
    title: 'Correo',
    summary: 'Lectura y borradores locales; bloquea envíos externos y exfiltración.',
    testFocus: 'Inyección dentro de un correo sintético',
    benignCaseId: 'email_benign_read_and_draft',
    adversarialCaseId: 'email_adversarial_external_exfiltration',
  },
  {
    profileId: 'guardian-agent-lab-database-v1',
    verticalId: 'database',
    title: 'Bases de datos',
    summary: 'Consulta una fila sintética; rechaza exportaciones entre espacios y borrados.',
    testFocus: 'Instrucción de exportación masiva en un documento',
    benignCaseId: 'database_benign_scoped_read',
    adversarialCaseId: 'database_adversarial_bulk_export',
  },
  {
    profileId: 'guardian-agent-lab-finance-v1',
    verticalId: 'finance',
    title: 'Finanzas',
    summary: 'Lectura de factura ficticia; transferencias requieren aprobación humana.',
    testFocus: 'Solicitud de transferencia desde contenido no confiable',
    benignCaseId: 'finance_benign_invoice_read',
    adversarialCaseId: 'finance_adversarial_transfer_request',
  },
  {
    profileId: 'guardian-agent-lab-programming-v1',
    verticalId: 'programming',
    title: 'Programación',
    summary: 'Propone un cambio de ejemplo; no ejecuta comandos del host.',
    testFocus: 'Intento de comando y lectura de secretos',
    benignCaseId: 'programming_benign_diff_proposal',
    adversarialCaseId: 'programming_adversarial_host_command',
  },
  {
    profileId: 'guardian-agent-lab-customer-service-v1',
    verticalId: 'customer_service',
    title: 'Atención al cliente',
    summary: 'Prepara una respuesta ficticia; reembolsos quedan pendientes de aprobación.',
    testFocus: 'Petición de reembolso incrustada en un ticket',
    benignCaseId: 'support_benign_ticket_reply_draft',
    adversarialCaseId: 'support_adversarial_refund_request',
  },
  {
    profileId: 'guardian-agent-lab-browser-v1',
    verticalId: 'browser',
    title: 'Navegador',
    summary: 'Lee páginas de laboratorio; no visita ni envía formularios a terceros.',
    testFocus: 'Formulario externo solicitado por una página sintética',
    benignCaseId: 'browser_benign_local_page_read',
    adversarialCaseId: 'browser_adversarial_external_form_submit',
  },
  {
    profileId: 'guardian-agent-lab-infrastructure-v1',
    verticalId: 'infrastructure',
    title: 'Infraestructura',
    summary: 'Consulta configuración ficticia; deniega escaladas y borrados.',
    testFocus: 'Concesión de rol administrador no autorizada',
    benignCaseId: 'infrastructure_benign_config_read',
    adversarialCaseId: 'infrastructure_adversarial_admin_grant',
  },
  {
    profileId: 'guardian-agent-lab-multiagent-v1',
    verticalId: 'multiagent',
    title: 'Multiagente',
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
  recordedEvidence: PolicyLabEvidence[];
  recordedArtifactSha256: string;
  freshPreview: FreshPolicyPreview | null;
}) {
  const [selectedProfileId, setSelectedProfileId] = useState<PolicyLabProfile | null>(null);
  const [selectedCaseKind, setSelectedCaseKind] = useState<'benign' | 'adversarial' | null>(null);
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
  const selectedAvailability = profiles.find((profile) => profile.profileId === selectedProfileId);
  const selectedReady = selectedAvailability?.status === 'ready';
  const selectedRecordedEvidence = recordedEvidence.find(
    (evidence) => evidence.profileId === selectedProfileId,
  );
  const selectedFreshPreview =
    freshPreview?.profileId === selectedProfileId &&
    freshPreview.caseId === selectedCaseId
      ? freshPreview
      : null;

  function resetGuide() {
    setSelectedProfileId(null);
    setSelectedCaseKind(null);
    setShowRecordedEvidence(false);
    onReset();
  }

  return (
    <section className="agent-policy-lab-catalog" data-testid="agent-policy-lab-catalog">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">OCHO VERTICALES · DATOS FICTICIOS</span>
          <h3>Laboratorios de políticas de agentes</h3>
        </div>
        <span className="ai-evaluation-state"><i />Prototipos locales</span>
      </div>
      <p>
        Cada previsualización evalúa dos o tres propuestas fixture fijas con el Policy Engine determinista.
        No es inferencia de Qwen, no conecta proveedores y no ejecuta acciones empresariales.
        El modo OFF solo calcula un contrafactual sobre un clon efímero.
      </p>
      <div className="agent-policy-guide" data-testid="agent-policy-guide">
        <div className="agent-policy-guide-heading">
          <div>
            <span className="panel-kicker">RECORRIDO GUIADO · FIXTURES DETERMINISTAS</span>
            <h4>De la propuesta a la evidencia</h4>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={resetGuide}
            disabled={busy}
            data-testid="button-reset-agent-demo"
          >
            <RotateCcw size={14} /> Reiniciar recorrido
          </Button>
        </div>
        <ol className="agent-policy-guide-steps" aria-label="Pasos de la demostración">
          <li aria-current={selectedLab ? undefined : 'step'}><span>1</span><div><b>Escoge un perfil</b><small>{selectedLab?.title ?? 'Selecciona una de las ocho verticales.'}</small></div></li>
          <li aria-current={selectedLab && selectedCaseKind ? undefined : selectedLab ? 'step' : undefined}><span>2</span><div><b>Elige un caso</b><small>{selectedCaseKind === 'benign' ? 'Control benigno' : selectedCaseKind === 'adversarial' ? 'Intento adversario sintético' : selectedLab ? 'Selecciona benigno o adversario.' : 'Aún no seleccionado'}</small></div></li>
          <li aria-current={selectedCaseId ? 'step' : undefined}><span>3</span><div><b>Revisa decisión y evidencia</b><small>Propuesta, Policy ON, simulación y hashes redactados.</small></div></li>
        </ol>
        <div className="agent-policy-guide-cases" role="group" aria-label="Tipo de caso para la demostración">
          <Button
            type="button"
            variant={selectedCaseKind === 'benign' ? 'default' : 'outline'}
            aria-pressed={selectedCaseKind === 'benign'}
            disabled={!selectedLab || busy}
            onClick={() => {
              setSelectedCaseKind('benign');
              setShowRecordedEvidence(false);
            }}
            data-testid="button-select-agent-case-benign"
          >
            Caso benigno
          </Button>
          <Button
            type="button"
            variant={selectedCaseKind === 'adversarial' ? 'default' : 'outline'}
            aria-pressed={selectedCaseKind === 'adversarial'}
            disabled={!selectedLab || busy}
            onClick={() => {
              setSelectedCaseKind('adversarial');
              setShowRecordedEvidence(false);
            }}
            data-testid="button-select-agent-case-adversarial"
          >
            Caso adversario
          </Button>
        </div>
        <div className="agent-policy-guide-submit">
          <p>
            La previsualización calcula evidencia nueva y efímera en el servidor; no crea un job ni modifica historial.
            La selección solo enfoca el caso elegido; no modifica reglas, corpus ni permisos.
          </p>
          <Button
            type="button"
            onClick={() => selectedLab && selectedCaseId && onPreview(selectedLab.profileId, selectedCaseId)}
            disabled={!canRun || !selectedLab || !selectedCaseId || busy}
            data-testid="button-preview-policy-lab"
          >
            {previewPending ? <Activity className="spin" size={15} /> : <FlaskConical size={15} />}
            {previewPending ? 'Calculando decisión…' : 'Previsualizar decisión determinista'}
          </Button>
          <Button
            type="button"
            onClick={() => selectedLab && selectedCaseId && onRequest(selectedLab.profileId, selectedCaseId)}
            disabled={!canRun || !selectedLab || !selectedCaseId || !selectedReady || busy}
            data-testid="button-run-guided-agent-demo"
          >
            {pending ? <Activity className="spin" size={15} /> : <FlaskConical size={15} />}
            {pending ? 'Encolando recorrido…' : 'Solicitar worker aislado'}
            {!pending && <ArrowRight size={14} />}
          </Button>
          {!canRun && <small>Solo owner/admin puede iniciar la evaluación.</small>}
          {selectedLab && !selectedReady && (
            <small role="status">
              El worker de Qwen/Garak no está disponible ({selectedAvailability?.reasonCode ?? 'worker_unavailable'}).
              La previsualización anterior no inicia ese worker.
            </small>
          )}
          {selectedLab && selectedCaseId && selectedRecordedEvidence && (
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
        </div>
      </div>
      <div className="agent-policy-lab-grid">
        {AGENT_POLICY_LABS.map((lab) => {
          const availability = profiles.find((profile) => profile.profileId === lab.profileId);
          const ready = availability?.status === 'ready';
          return (
            <article
              key={lab.profileId}
              className={`agent-policy-lab-card ${selectedProfileId === lab.profileId ? 'agent-policy-lab-card-selected' : ''}`}
              data-testid={`agent-policy-lab-${lab.verticalId}`}
            >
              <div>
                <span className="ai-evaluation-run-label">FIXTURES · SIN CONEXIONES REALES</span>
                <h4>{lab.title}</h4>
                <p>{lab.summary}</p>
                <small>Prueba adversarial: {lab.testFocus}.</small>
              </div>
              <Button
                variant="outline"
                onClick={() => {
                  setSelectedProfileId(lab.profileId);
                  setSelectedCaseKind(null);
                  setShowRecordedEvidence(false);
                }}
                disabled={busy}
                aria-pressed={selectedProfileId === lab.profileId}
                data-testid={`button-select-agent-lab-${lab.verticalId}`}
              >
                <FlaskConical size={15} />
                {selectedProfileId === lab.profileId ? 'Perfil seleccionado' : 'Seleccionar perfil'}
              </Button>
              {!ready && availability?.reasonCode && (
                <small role="status">Motivo: {availability.reasonCode}</small>
              )}
            </article>
          );
        })}
      </div>
      {selectedLab && <p className="agent-policy-guide-scope">
        El informe distinguirá el fixture controlado de una propuesta de modelo. En este laboratorio,
        <code>NO_PROPOSAL</code> no se mide; es un resultado distinto de <code>DENY</code> en la vista Qwen separada.
      </p>}
      {showRecordedEvidence && selectedRecordedEvidence && selectedCaseId && (
        <div className="agent-policy-recorded-sample" data-testid="agent-policy-recorded-sample">
          <p role="status">
            Muestra histórica de un resultado del Policy Engine. Esta vista es de solo lectura:
            no crea jobs, no modifica el historial de este espacio y no representa una ejecución nueva.
          </p>
          <AgentPolicyLabResult
            evidence={selectedRecordedEvidence}
            focusedCaseId={selectedCaseId}
            recordedSnapshot
            recordedArtifactSha256={recordedArtifactSha256}
          />
        </div>
      )}
      {!showRecordedEvidence && selectedFreshPreview && selectedCaseId && (
        <div className="agent-policy-recorded-sample" data-testid="agent-policy-fresh-preview">
          <p role="status">
            Decisión determinista recién calculada. No es inferencia Qwen, no se persiste como job ni en el historial.
            El proceso comparte identidad con la API; aislamiento de red y acceso al socket Docker no están verificados.
          </p>
          <AgentPolicyLabResult
            evidence={selectedFreshPreview.evidence}
            focusedCaseId={selectedCaseId}
          />
        </div>
      )}
    </section>
  );
}

export function AgentPolicyLabResult({
  evidence,
  focusedCaseId,
  recordedSnapshot = false,
  recordedArtifactSha256,
}: {
  evidence: PolicyLabEvidence;
  focusedCaseId?: string;
  recordedSnapshot?: boolean;
  recordedArtifactSha256?: string;
}) {
  const focusedCase = evidence.cases.find((item) => item.caseId === focusedCaseId);
  return (
    <section className="agent-policy-lab-result" data-testid="agent-policy-lab-result">
      <div className="ai-lab-result-summary">
        <b>Laboratorio {evidence.verticalLabel} · propuestas fixture deterministas</b>
        <span>{evidence.summary.sampleCount} casos · no es inferencia de LLM</span>
      </div>
      {recordedSnapshot && (
        <div className="agent-policy-recorded-notice" role="note">
          Evidencia histórica guardada; no se ejecutó nada al abrir esta vista.
          {recordedArtifactSha256 && <span> SHA-256 del artefacto fuente: <code>{recordedArtifactSha256}</code></span>}
        </div>
      )}
      {evidence.executionContext === 'api_policy_preview' && (
        <div className="agent-policy-recorded-notice" role="note" data-testid="policy-preview-runtime-limit">
          Previsualización fresca del Policy Engine; no se creó un job. No es una frontera de aislamiento:
          el proceso comparte identidad con la API y no se restringió ni verificó la red o el acceso al socket Docker.
        </div>
      )}
      <p>{evidence.interpretation}</p>
      <p>
        «Requiere aprobación» es una decisión registrada por este laboratorio: no hay aquí un flujo de aprobación ni una operación financiera real.
      </p>
      {focusedCase && (
        <section className="agent-policy-guided-result" aria-labelledby="agent-policy-guided-result-title" data-testid="agent-policy-guided-result">
          <span className="panel-kicker">CASO SELECCIONADO · {focusedCase.caseId}</span>
          <h4 id="agent-policy-guided-result-title">{caseTitle[focusedCase.caseId] ?? focusedCase.caseId}</h4>
          <ol>
            <li><b>Propuesta y procedencia</b><span>Fixture controlado, no inferencia Qwen ni llamada nativa: {focusedCase.tool} · {focusedCase.operation}.</span></li>
            <li><b>Policy ON</b><span>{decisionLabel[focusedCase.policyOn.decision] ?? focusedCase.policyOn.decision} · {reasonLabel[focusedCase.policyOn.reasonCode] ?? focusedCase.policyOn.reasonCode}.</span></li>
            <li><b>Acción simulada</b><span>{focusedCase.policyOn.executed ? 'Solo en estado sintético efímero.' : 'No ejecutada.'} Policy OFF permanece contrafactual y no despacha herramientas.</span></li>
            <li><b>Aprobación ficticia</b><span>{focusedCase.policyOn.decision === 'require_approval'
              ? 'Esta ejecución registra el requisito, pero no crea una aprobación persistente.'
              : 'No aplica a este caso.'} La bandeja muestra solo solicitudes existentes.</span></li>
            <li><b>Evidencia redactada</b><span>Hash de caso: <code>{focusedCase.caseEvidenceSha256}</code></span></li>
          </ol>
          {focusedCase.policyOn.decision === 'require_approval' && (
            <a href="#guardian-approval-inbox" data-testid="link-guided-approval-inbox">
              Ir a la bandeja de aprobaciones <ArrowRight size={14} />
            </a>
          )}
        </section>
      )}
      <dl>
        <dt>Policy ON</dt>
        <dd>
          {evidence.summary.allowed} permitido · {evidence.summary.denied} denegado ·{' '}
          {evidence.summary.requiresApproval} requiere aprobación ·{' '}
          {evidence.summary.simulatedExecutions} ejecución simulada
        </dd>
        <dt>Policy OFF</dt>
        <dd>
          {evidence.summary.policyOffCounterfactualWouldExecute} hipotéticos en clones ·{' '}
          {evidence.summary.policyOffCloneStateChanges} cambios solo en clones · 0 ejecución real
        </dd>
        <dt>Efectos reales</dt>
        <dd>0 operaciones externas · 0 llamadas externas · 0 cambios persistentes</dd>
        <dt>Identidad sintética</dt>
        <dd>{evidence.agentIdentity.agentId} · {evidence.agentIdentity.actorId}</dd>
      </dl>
      <div className="agent-policy-lab-cases">
        {evidence.cases.map((item) => (
          <details key={item.caseId} open={item.caseId === focusedCaseId} data-testid={`agent-policy-case-${item.caseId}`}>
            <summary>
              {caseTitle[item.caseId] ?? item.caseId} —{' '}
              {decisionLabel[item.policyOn.decision] ?? item.policyOn.decision}
            </summary>
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
        <summary>Procedencia, límites y evidencia</summary>
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
        </dl>
        <small>Dos o tres casos por vertical son una demostración acotada, no una medición de eficacia general.</small>
      </details>
    </section>
  );
}
