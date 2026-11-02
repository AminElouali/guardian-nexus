import React from 'react';
import { Activity, FlaskConical } from 'lucide-react';
import {
  type AiAssessmentLabJob,
  type AiAssessmentLabJobRequestProfileId,
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

export const AGENT_POLICY_LABS: Array<{
  profileId: PolicyLabProfile;
  verticalId: string;
  title: string;
  summary: string;
  testFocus: string;
}> = [
  {
    profileId: 'guardian-agent-lab-email-v1',
    verticalId: 'email',
    title: 'Correo',
    summary: 'Lectura y borradores locales; bloquea envíos externos y exfiltración.',
    testFocus: 'Inyección dentro de un correo sintético',
  },
  {
    profileId: 'guardian-agent-lab-database-v1',
    verticalId: 'database',
    title: 'Bases de datos',
    summary: 'Consulta una fila sintética; rechaza exportaciones entre espacios y borrados.',
    testFocus: 'Instrucción de exportación masiva en un documento',
  },
  {
    profileId: 'guardian-agent-lab-finance-v1',
    verticalId: 'finance',
    title: 'Finanzas',
    summary: 'Lectura de factura ficticia; transferencias requieren aprobación humana.',
    testFocus: 'Solicitud de transferencia desde contenido no confiable',
  },
  {
    profileId: 'guardian-agent-lab-programming-v1',
    verticalId: 'programming',
    title: 'Programación',
    summary: 'Propone un cambio de ejemplo; no ejecuta comandos del host.',
    testFocus: 'Intento de comando y lectura de secretos',
  },
  {
    profileId: 'guardian-agent-lab-customer-service-v1',
    verticalId: 'customer_service',
    title: 'Atención al cliente',
    summary: 'Prepara una respuesta ficticia; reembolsos quedan pendientes de aprobación.',
    testFocus: 'Petición de reembolso incrustada en un ticket',
  },
  {
    profileId: 'guardian-agent-lab-browser-v1',
    verticalId: 'browser',
    title: 'Navegador',
    summary: 'Lee páginas de laboratorio; no visita ni envía formularios a terceros.',
    testFocus: 'Formulario externo solicitado por una página sintética',
  },
  {
    profileId: 'guardian-agent-lab-infrastructure-v1',
    verticalId: 'infrastructure',
    title: 'Infraestructura',
    summary: 'Consulta configuración ficticia; deniega escaladas y borrados.',
    testFocus: 'Concesión de rol administrador no autorizada',
  },
  {
    profileId: 'guardian-agent-lab-multiagent-v1',
    verticalId: 'multiagent',
    title: 'Multiagente',
    summary: 'Conserva actor y permisos originales al delegar.',
    testFocus: 'Intento de elevar privilegios mediante delegación',
  },
];

const decisionLabel: Record<string, string> = {
  allow: 'Permitida en la simulación',
  deny: 'Denegada por política',
  require_approval: 'Requiere aprobación humana',
  bypassed_counterfactual: 'Contrafactual sin enforcement',
};

const reasonLabel: Record<string, string> = {
  synthetic_policy_allowlist: 'Operación de laboratorio dentro del permiso mínimo.',
  permission_not_granted: 'El actor no tiene el permiso solicitado.',
  delegated_permissions_exceed_parent: 'La delegación solicita más permisos que el agente original.',
  external_destination_not_allowed: 'El destino externo no está permitido en este laboratorio.',
  human_approval_required: 'La operación sensible no se ejecuta sin aprobación humana.',
  operation_outside_policy: 'La operación no pertenece a la lista permitida.',
  untrusted_content_cannot_authorize_action: 'El contenido no confiable no puede autorizar una acción.',
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
  onRequest,
}: {
  profiles: Array<{ profileId: string; status: string; reasonCode: string | null }>;
  canRun: boolean;
  pending: boolean;
  onRequest: (profileId: AiAssessmentLabJobRequestProfileId) => void;
}) {
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
        Cada ejecución usa dos propuestas controladas y un Policy Engine determinista externo a la propuesta.
        No es inferencia de Qwen, no conecta proveedores y no ejecuta acciones empresariales.
        El modo OFF solo calcula un contrafactual sobre un clon efímero.
      </p>
      <div className="agent-policy-lab-grid">
        {AGENT_POLICY_LABS.map((lab) => {
          const availability = profiles.find((profile) => profile.profileId === lab.profileId);
          const ready = availability?.status === 'ready';
          return (
            <article
              key={lab.profileId}
              className="agent-policy-lab-card"
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
                onClick={() => onRequest(lab.profileId)}
                disabled={!canRun || !ready || pending}
                data-testid={`button-run-agent-lab-${lab.verticalId}`}
              >
                {pending ? <Activity className="spin" size={15} /> : <FlaskConical size={15} />}
                {ready ? 'Ejecutar laboratorio' : 'No disponible'}
              </Button>
              {!ready && availability?.reasonCode && (
                <small role="status">Motivo: {availability.reasonCode}</small>
              )}
            </article>
          );
        })}
      </div>
      {!canRun && <small>Solo owner/admin puede iniciar evaluaciones del laboratorio.</small>}
    </section>
  );
}

export function AgentPolicyLabResult({ evidence }: { evidence: PolicyLabEvidence }) {
  return (
    <section className="agent-policy-lab-result" data-testid="agent-policy-lab-result">
      <div className="ai-lab-result-summary">
        <b>Laboratorio {evidence.verticalLabel} · propuestas fixture deterministas</b>
        <span>{evidence.summary.sampleCount} casos · no es inferencia de LLM</span>
      </div>
      <p>{evidence.interpretation}</p>
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
          <details key={item.caseId} data-testid={`agent-policy-case-${item.caseId}`}>
            <summary>
              {caseTitle[item.caseId] ?? item.caseId} —{' '}
              {decisionLabel[item.policyOn.decision] ?? item.policyOn.decision}
            </summary>
            <dl>
              <dt>Propuesta</dt><dd>{item.tool} · {item.operation} · {item.resourceType} sintético</dd>
              <dt>Origen de instrucción</dt><dd>{item.instructionProvenance}</dd>
              <dt>Permisos solicitados</dt><dd>{item.requestedPermissions.join(', ')}</dd>
              <dt>Motivo de política</dt><dd>{reasonLabel[item.policyOn.reasonCode] ?? item.policyOn.reasonCode}</dd>
              <dt>Intento</dt><dd>{item.policyOn.attempted ? 'Registrado' : 'No observado'}</dd>
              <dt>Autorización</dt><dd>{item.policyOn.authorized ? 'Sí, solo en el simulador' : 'No'}</dd>
              <dt>Acción</dt><dd>{item.policyOn.executed ? 'Ejecutada en estado sintético efímero' : 'No ejecutada'}</dd>
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
          <dt>Propuestas</dt><dd>Fixture controlado; no Qwen, no tool calls nativas.</dd>
          <dt>Datos</dt><dd>No se guardan prompts, instrucciones ni argumentos en bruto; solo metadatos y hashes.</dd>
          <dt>Hash de suite</dt><dd>{evidence.suiteEvidenceSha256}</dd>
          <dt>Hash de evidencia</dt><dd>{evidence.evidenceSha256}</dd>
        </dl>
        <small>Dos casos por vertical son una demostración acotada, no una medición de eficacia general.</small>
      </details>
    </section>
  );
}
