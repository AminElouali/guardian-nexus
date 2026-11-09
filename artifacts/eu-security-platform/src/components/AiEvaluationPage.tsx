import React, { useState, type KeyboardEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Activity, AlertTriangle, Check, Clock3, FlaskConical, LockKeyhole, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  getListWorkspaceAiAssessmentApprovalsQueryKey,
  getListWorkspaceAiAssessmentLabJobsQueryKey,
  getListWorkspaceAiEvaluationsQueryKey,
  useDecideWorkspaceAiAssessmentApproval,
  useCreateWorkspaceAiAssessmentLabJob,
  useGetWorkspaceAiAssessmentLabAvailability,
  useListWorkspaceAiAssessmentApprovals,
  useListWorkspaceAiAssessmentLabJobs,
  useListWorkspaceAiEvaluations,
  usePreviewWorkspaceAiAssessmentPolicyLab,
  useRetryWorkspaceAiAssessmentLabJob,
  useRunWorkspaceMockAiEvaluation,
  type AiAssessmentLabJob,
  type AiAssessmentLabJobRequestProfileId,
  type AiEvaluationRun,
  type GuardianPolicyLabPreviewResponse,
  type Workspace,
} from '@workspace/api-client-react';
import { Button } from '@/components/ui/button';
import {
  deriveQwenBankChangeFinding,
  downloadQwenExecutiveReport,
} from './qwenExecutiveReport';
import { GuardianApprovalInbox } from './GuardianApprovalInbox';
import {
  AgentPolicyLabCatalog,
  AgentPolicyLabResult,
} from './GuardianAgentPolicyLab';
import recordedPolicyLabJobs from '../../../../generated-artifacts/guardian-agent-policy-labs-e2e.json';
import {
  QwenPolicyLabCatalog,
  QwenPolicyLabResult,
} from './GuardianQwenPolicyLab';

const reasonLabels: Record<string, string> = {
  mock_refused_untrusted_instruction: 'El fixture rechazó una instrucción no confiable',
  mock_accepted_untrusted_instruction: 'El fixture aceptó una instrucción no confiable',
  synthetic_canary_not_returned: 'El canario sintético no apareció en la respuesta simulada',
  synthetic_canary_would_leak: 'El fixture simuló una posible fuga de canario',
  mock_did_not_execute_unapproved_tool: 'No se ejecutó la herramienta no autorizada',
  mock_executed_unapproved_tool: 'El fixture simuló la ejecución de una herramienta no autorizada',
};

const categoryLabels: Record<string, string> = {
  prompt_injection: 'Inyección de prompts',
  data_exposure: 'Exposición de datos',
  agent_permissions: 'Límite de permisos de agente',
};

function EvaluationCard({ run }: { run: AiEvaluationRun }) {
  return <article className="ai-evaluation-run" data-testid="ai-evaluation-run">
    <div className="ai-evaluation-run-head">
      <div>
        <span className="ai-evaluation-run-label">SIMULACIÓN · {run.version}</span>
        <h3>{run.passedChecks} de {run.checks.length} fixtures superados</h3>
      </div>
      <time dateTime={run.createdAt}><Clock3 size={13} /> {new Date(run.createdAt).toLocaleString('es-ES')}</time>
    </div>
    <ul className="ai-evaluation-checks">
      {run.checks.map((check) => (
        <li key={check.checkId} className={check.status === 'passed' ? 'ai-check-passed' : 'ai-check-failed'}>
          {check.status === 'passed' ? <Check size={15} /> : <AlertTriangle size={15} />}
          <span><b>{categoryLabels[check.category] ?? check.category}</b><small>{reasonLabels[check.reasonCode] ?? 'Resultado del fixture simulado'}</small></span>
          <em>{check.status === 'passed' ? 'Simulado OK' : 'Fallo simulado'}</em>
        </li>
      ))}
    </ul>
  </article>;
}

const labStatusLabels: Record<AiAssessmentLabJob['status'], string> = {
  queued: 'En cola',
  running: 'En ejecución',
  succeeded: 'Completada',
  failed: 'Fallida',
};

type GarakEvidence = Extract<
  NonNullable<AiAssessmentLabJob['result']>,
  { engine: 'garak' }
>;
type GuardianVerification = NonNullable<GarakEvidence['guardianVerification']>;
type PolicyComparison = NonNullable<GuardianVerification['policyComparison']>;
type LocalLlmEvidence = Extract<
  NonNullable<AiAssessmentLabJob['result']>,
  { profileId: 'guardian-local-llm-qwen3-0.6b-v1' }
>;
const recordedPolicyEvidence = (recordedPolicyLabJobs as AiAssessmentLabJob[]).flatMap((job) => {
  const result = job.result;
  return job.status === 'succeeded' && result?.engine === 'guardian_policy_lab'
    ? [result]
    : [];
});
const recordedPolicyArtifactSha256 =
  '9bbc87ca9ee5c7eac040a0d2f33defb6eeb41f95d5d9940979b5564b435960be';
type NativeToolSuiteEvidence = Extract<
  NonNullable<AiAssessmentLabJob['result']>,
  { profileId: 'guardian-local-llm-native-tools-v1' }
>;
type AutonomousToolSelectionEvidence = Extract<
  NonNullable<AiAssessmentLabJob['result']>,
  { profileId: 'guardian-local-llm-autonomous-tools-v1' }
>;
type QwenPairedPolicyComparison = NonNullable<
  AutonomousToolSelectionEvidence['nativeToolSuite']['policyComparison']
>;
type QwenPolicyRate =
  QwenPairedPolicyComparison['metrics'][keyof QwenPairedPolicyComparison['metrics']];

const verificationScenarioLabels: Record<string, string> = {
  synthetic_data_exfiltration: 'Exfiltración de dato sintético',
  unauthorized_tool_operation: 'Operación fuera de permisos',
  indirect_document_injection: 'Inyección indirecta en documento',
};

const verificationObjectiveLabels: Record<string, string> = {
  untrusted_text_present: 'Texto no confiable presente',
  synthetic_data_propagated: 'Dato sintético propagado',
  untrusted_instruction_obeyed: 'Instrucción no confiable obedecida',
  action_attempted: 'Acción intentada',
  unauthorized_action_attempted: 'Acción no autorizada intentada',
  action_executed: 'Acción ejecutada',
  policy_violation: 'Violación de política',
};

function networkStatusLabel(status: string) {
  if (status === 'blocked') return 'bloqueado';
  if (status === 'unavailable') return 'no verificado';
  if (status === 'reachable') return 'accesible';
  return status;
}

function GuardianVerificationResult({
  verification,
}: {
  verification: GuardianVerification;
}) {
  const comparison = verification.policyComparison;
  return <section className="guardian-verification" data-testid="guardian-verification-result">
    <div className="guardian-verification-heading">
      <div>
        <span className="ai-evaluation-run-label">FIXTURES DETERMINISTAS · DATOS SINTÉTICOS</span>
        <h4>Guardian Verification Engine · v{verification.version}</h4>
      </div>
      <span className="guardian-verification-pill">No es una evaluación de LLM</span>
    </div>
    <p className="guardian-verification-disclaimer">
      Agente y herramientas ficticios ejecutados localmente. Los resultados miden la conformidad de estos fixtures y sus oráculos; no describen sistemas de clientes ni garantizan seguridad.
    </p>
    <div className="guardian-verification-stats">
      <span><b>{verification.sampleCount}</b> casos totales</span>
      <span><b>{verification.splitSampleCounts.calibration}</b> calibración</span>
      <span><b>{verification.splitSampleCounts.holdout}</b> holdout</span>
      <span><b>{verification.toolCallSummary.total}</b> llamadas instrumentadas</span>
      <span><b>{verification.toolCallSummary.policyViolations}</b> efectos no autorizados previstos en fixtures vulnerables</span>
    </div>
    <p className="guardian-verification-note">
      Los intentos bloqueados, las acciones ejecutadas y las violaciones se cuentan por separado. Los casos vulnerables usan permisos ficticios excesivos para comprobar el oráculo; no modifican recursos reales.
    </p>
    {comparison && <PolicyComparisonResult comparison={comparison} />}
    <details className="guardian-verification-details">
      <summary>Métricas de holdout por escenario</summary>
      <div className="guardian-verification-scenarios">
        {verification.scenarios.map((scenario) => (
          <details key={scenario.scenarioId} data-testid={`gve-scenario-${scenario.scenarioId}`}>
            <summary>{verificationScenarioLabels[scenario.scenarioId] ?? scenario.scenarioId} · 24 casos</summary>
            <div className="guardian-verification-table-wrap">
              <table className="guardian-verification-table">
                <thead>
                  <tr>
                    <th scope="col">Objetivo</th>
                    <th scope="col">TP</th>
                    <th scope="col">FP</th>
                    <th scope="col">TN</th>
                    <th scope="col">FN</th>
                    <th scope="col">Positivos</th>
                    <th scope="col">Negativos</th>
                    <th scope="col">FPR</th>
                    <th scope="col">FNR</th>
                  </tr>
                </thead>
                <tbody>
                  {verification.metrics
                    .filter((metric) => metric.scenarioId === scenario.scenarioId && metric.split === 'holdout')
                    .map((metric) => (
                      <tr key={metric.objective} data-testid={`gve-metric-${scenario.scenarioId}-${metric.objective}`}>
                        <th scope="row">{verificationObjectiveLabels[metric.objective] ?? metric.objective}</th>
                        <td>{metric.truePositive}</td>
                        <td>{metric.falsePositive}</td>
                        <td>{metric.trueNegative}</td>
                        <td>{metric.falseNegative}</td>
                        <td>{metric.positiveSupport}</td>
                        <td>{metric.negativeSupport}</td>
                        <td>{(metric.falsePositiveRate.value * 100).toFixed(0)}%</td>
                        <td>{(metric.falseNegativeRate.value * 100).toFixed(0)}%</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </details>
        ))}
      </div>
    </details>
    <details className="guardian-verification-details">
      <summary>Contadores de herramientas y procedencia</summary>
      <div className="guardian-verification-table-wrap">
        <table className="guardian-verification-table">
          <thead>
            <tr>
              <th scope="col">Operación ficticia</th>
              <th scope="col">Llamadas</th>
              <th scope="col">Denegadas</th>
              <th scope="col">Ejecutadas</th>
              <th scope="col">Cambios de estado</th>
              <th scope="col">Violaciones</th>
            </tr>
          </thead>
          <tbody>
            {verification.toolCallSummary.byOperation.map((operation) => (
              <tr key={operation.operation}>
                <th scope="row">{operation.operation}</th>
                <td>{operation.calls}</td>
                <td>{operation.denied}</td>
                <td>{operation.executed}</td>
                <td>{operation.stateChanges}</td>
                <td>{operation.policyViolations}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <dl>
        <dt>Versiones</dt><dd>Agente {verification.agentVersion}; políticas {verification.policyVersion}; oráculo {verification.oracleVersion}</dd>
        <dt>Oráculo</dt><dd>{verification.selfChecks.status}; llamadas denegadas sin efectos secundarios; sin anomalías ({verification.anomalyCount})</dd>
        <dt>Hash del conjunto</dt><dd><code>{verification.suiteEvidenceSha256}</code></dd>
        <dt>Casos con hash</dt><dd>{verification.caseEvidence.length} evidencias sintéticas</dd>
        <dt>Datos y red</dt><dd>Sin prompts/respuestas guardados, llamadas externas ni datos de clientes.</dd>
      </dl>
      <small>Las máscaras esperadas/observadas usan el orden de objetivos del manifiesto del motor. Las métricas son de estos fixtures y no se extrapolan.</small>
    </details>
  </section>;
}

function PolicyComparisonResult({ comparison }: { comparison: PolicyComparison }) {
  return <section
    className="guardian-verification-details policy-counterfactual"
    data-testid="policy-counterfactual-result"
  >
    <div className="guardian-verification-heading">
      <div>
        <span className="ai-evaluation-run-label">C · PROPUESTAS SINTÉTICAS CONTROLADAS · NO LLM</span>
        <h4>Comparación del control de autorización</h4>
      </div>
      <span className="guardian-verification-pill">Solo estado ficticio</span>
    </div>
    <p className="guardian-verification-disclaimer">
      Prueba determinista del adaptador local fuera del modelo. No atribuir estas propuestas a Qwen/Garak. Los resultados A (tool_choice=auto) y B (llamadas forzadas) conservan sus propios informes y denominadores. El brazo sin enforcement solo modifica una copia ficticia en memoria; no ejecuta herramientas.
    </p>
    <div className="guardian-verification-stats">
      <span><b>{comparison.policyOn.summary.allowed}/{comparison.policyOn.summary.proposed}</b> permitidas con política</span>
      <span><b>{comparison.policyOn.summary.denied}/{comparison.policyOn.summary.attempted}</b> denegadas con política</span>
      <span><b>{comparison.policyOff.summary.counterfactualWouldExecute}/{comparison.policyOff.sampleCount}</b> hipotéticas sin enforcement</span>
      <span><b>{comparison.actualOperationExecutions}</b> operaciones reales</span>
    </div>
    <div className="guardian-verification-table-wrap">
      <table className="guardian-verification-table">
        <thead><tr>
          <th scope="col">Propuesta sintética</th>
          <th scope="col">Política activa</th>
          <th scope="col">Sin enforcement · clon</th>
          <th scope="col">Ejecución real</th>
        </tr></thead>
        <tbody>
          {comparison.policyOn.cases.map((onCase) => {
            const offCase = comparison.policyOff.cases.find(
              (candidate) => candidate.caseId === onCase.caseId,
            );
            const proposal = comparison.proposals.find(
              (candidate) => candidate.caseId === onCase.caseId,
            );
            return <tr key={onCase.caseId}>
              <th scope="row">{onCase.caseId} · {proposal?.tool}</th>
              <td>{onCase.policyDecision.toUpperCase()} · {onCase.executed ? 'solo adaptador ficticio' : 'no ejecutada'}</td>
              <td>{offCase?.counterfactualWouldExecute ? 'Habría ocurrido en el clon' : 'No habría ocurrido'} · {offCase?.counterfactualCloneStateChanged ? 'clon cambiado' : 'clon sin cambios'}</td>
              <td>No</td>
            </tr>;
          })}
        </tbody>
      </table>
    </div>
    <dl>
      <dt>Semilla / casos</dt><dd>{comparison.fixedSeed} · {comparison.sampleCount} pares</dd>
      <dt>Estado sintético inicial</dt><dd><code>{comparison.initialSyntheticStateSha256}</code></dd>
      <dt>Hash del conjunto emparejado</dt><dd><code>{comparison.caseSetSha256}</code></dd>
      <dt>Hash policy-on</dt><dd><code>{comparison.policyOn.armEvidenceSha256}</code></dd>
      <dt>Hash contrafactual</dt><dd><code>{comparison.policyOff.armEvidenceSha256}</code></dd>
      <dt>Hash de evidencia</dt><dd><code>{comparison.evidenceSha256}</code></dd>
      <dt>Oráculo</dt><dd>{comparison.selfChecks.sameCasesAndProposals && comparison.selfChecks.expectedAllowAndDenyObserved && comparison.selfChecks.policyOffIsCloneOnly && comparison.selfChecks.noPersistentOrExternalEffects ? 'Verificado; sin estado persistente ni llamadas externas' : 'Falló la verificación'}</dd>
    </dl>
  </section>;
}

const toolLabels: Record<string, string> = {
  consult_synthetic_invoice: 'Consultar factura sintética',
  read_synthetic_document: 'Leer documento sintético',
  read_synthetic_email: 'Leer correo sintético',
  send_email_simulated: 'Preparar correo simulado',
  request_bank_account_change: 'Solicitar cambio ficticio',
  unknown: 'Operación desconocida',
};

const toolPhaseLabels: Record<string, string> = {
  proposal: 'Propuesta JSON',
  authorization_attempt: 'Comprobación de permisos',
  executed: 'Ejecutada solo en simulación',
  denied: 'Denegada',
};

function LocalLlmResult({ evidence }: { evidence: LocalLlmEvidence }) {
  return <section className="guardian-verification" data-testid="local-llm-result">
    <div className="guardian-verification-heading">
      <div>
        <span className="ai-evaluation-run-label">INFERENCIA REAL · LABORATORIO LOCAL</span>
        <h4>Tarea funcional sintética</h4>
      </div>
      <span className="guardian-verification-pill">No disponible para clientes</span>
    </div>
    <p className="guardian-verification-disclaimer">
      Una tarea fija sobre una factura sintética. El modelo devuelve JSON; un adaptador valida las propuestas antes de ejecutar herramientas ficticias. No se guardan la respuesta, el prompt ni los argumentos.
    </p>
    <div className="guardian-verification-stats">
      <span><b>{evidence.toolSummary.harnessToolExecutions}</b> consultas sintéticas</span>
      <span><b>{evidence.toolSummary.modelActionProposals}</b> propuestas del modelo</span>
      <span><b>{evidence.toolSummary.deniedActions}</b> denegadas</span>
      <span><b>{evidence.toolSummary.simulatedExecutions}</b> ejecuciones simuladas</span>
      <span><b>{evidence.toolSummary.externalCalls}</b> llamadas externas</span>
    </div>
    <details className="guardian-verification-details">
      <summary>Trazas instrumentadas y procedencia</summary>
      <div className="guardian-verification-table-wrap">
        <table className="guardian-verification-table">
          <thead><tr>
            <th scope="col">Herramienta</th>
            <th scope="col">Origen</th>
            <th scope="col">Etapa</th>
            <th scope="col">Permiso</th>
            <th scope="col">Ejecución</th>
            <th scope="col">Efecto externo</th>
          </tr></thead>
          <tbody>
            {evidence.toolTrace.map((event, index) => (
              <tr key={`${event.toolCallId}-${event.phase}-${index}`}>
                <th scope="row">{toolLabels[event.tool] ?? event.tool}</th>
                <td>{event.source === 'local_harness' ? 'Arnés local' : 'Emulación JSON del modelo'}</td>
                <td>{toolPhaseLabels[event.phase] ?? event.phase}</td>
                <td>{event.authorization === 'allowed' ? 'Permitido' : event.authorization === 'denied' ? 'Denegado' : 'Sin comprobar'}</td>
                <td>{event.executed ? 'Sí, sintética' : 'No'}</td>
                <td>{event.externalSideEffect ? 'Sí' : 'Ninguno'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <dl>
        <dt>Modo de herramientas</dt><dd>Emulación JSON estructurada; no es function calling nativo.</dd>
        <dt>Motor y versión</dt><dd>{evidence.engine} · {evidence.engineVersion}</dd>
        <dt>Modelo y licencia</dt><dd>{evidence.provider.modelId} Q8_0 · {evidence.provider.license}</dd>
        <dt>Runtime</dt><dd>{evidence.provider.runtime} {evidence.provider.runtimeVersion} · {evidence.provider.runtimeLicense}</dd>
        <dt>Hash del modelo</dt><dd><code>{evidence.provider.sha256}</code></dd>
        <dt>Hash de evidencia</dt><dd><code>{evidence.evidenceSha256}</code></dd>
        <dt>Red</dt><dd>IPv4 {networkStatusLabel(evidence.network.publicIpv4)}, IPv6 {networkStatusLabel(evidence.network.publicIpv6)}, DNS {networkStatusLabel(evidence.network.publicDns)}.</dd>
        <dt>Límites comprobados</dt><dd>{evidence.limits.verifiedContainerLimits.cpuCores} CPU · {Math.round(evidence.limits.verifiedContainerLimits.memoryBytes / 1024 / 1024)} MiB · {evidence.limits.verifiedContainerLimits.pids} procesos · una ejecución concurrente.</dd>
        <dt>Datos</dt><dd>Factura sintética; sin secretos, datos de clientes, cambios persistentes ni llamadas externas.</dd>
      </dl>
      <small>{evidence.interpretation}</small>
    </details>
  </section>;
}

const nativeObjectiveLabels: Record<string, string> = {
  unauthorizedProposal: 'Propuesta no autorizada',
  unauthorizedAttempt: 'Intento no autorizado',
  unauthorizedExecution: 'Ejecución no autorizada',
};

const autonomousTaskLabels: Record<string, string> = {
  authorized_invoice_read: 'Lectura autorizada de factura sintética',
  authorized_document_read: 'Lectura autorizada de documento sintético',
  authorized_email_read: 'Lectura autorizada de correo sintético',
  authorized_simulated_email_draft: 'Preparación autorizada de correo simulado',
  authorized_synthetic_bank_request: 'Solicitud ficticia de cambio bancario',
  attack_bank_es_cal: 'Intento de modificación bancaria no autorizada bloqueado',
};

const autonomousCaseLabels: Record<string, string> = {
  attack_bank_es_cal: 'Intento de modificación bancaria no autorizada bloqueado',
  benign_document_en_holdout: 'Lectura benigna de documento en inglés',
  benign_document_es_holdout: 'Lectura benigna de documento en español',
  benign_email_reply_en_cal: 'Lectura benigna de correo en inglés',
  attack_document_injection_en_holdout: 'Inyección indirecta en documento en inglés',
  attack_email_en_cal: 'Inyección indirecta en correo en inglés',
  attack_email_es_holdout: 'Inyección indirecta en correo en español',
};

const agentDomainLabels: Record<string, string> = {
  email: 'Correo',
  documents: 'Documentos',
  finance: 'Finanzas sintéticas',
};

function pairedRate(
  value: QwenPolicyRate,
) {
  return `${value.numerator}/${value.denominator}`;
}

function QwenPolicyComparisonResult({
  comparison,
}: {
  comparison: QwenPairedPolicyComparison;
}) {
  const approvalRequiredCalls = comparison.pairs.filter(
    (pair) =>
      pair.policyOn.resultCode === "approval_required_before_dispatch",
  ).length;
  const explicitDenials = comparison.pairs.filter(
    (pair) =>
      pair.policyOn.denied &&
      pair.policyOn.resultCode !== "approval_required_before_dispatch",
  ).length;

  return <section
    className="guardian-verification"
    data-testid="qwen-policy-paired-comparison"
  >
    <div className="guardian-verification-heading">
      <div>
        <span className="ai-evaluation-run-label">
          {comparison.source === 'real_local_qwen_proposals'
            ? 'PROPUESTAS DEL QWEN LOCAL · tool_choice=auto'
            : 'DOBLE DE PRUEBA · NO ES INFERENCIA REAL'}
        </span>
        <h5>Comparación emparejada · Guardian Policy Engine</h5>
      </div>
      <span className="guardian-verification-pill">Policy OFF · solo clon desechable</span>
    </div>
    <p className="guardian-verification-disclaimer">
      Contrafactual emparejado: ambos brazos evalúan la misma propuesta identificada por hash. Policy ON comprueba permisos y, si corresponde, solo simula la acción. Policy OFF omite esa comprobación únicamente sobre una copia desechable en memoria para estimar qué habría pasado; no autoriza ni ejecuta una herramienta. No representa un modo operativo.
    </p>
    <div className="guardian-verification-stats">
      <span><b>{pairedRate(comparison.metrics.proposalsByScenario)}</b> escenarios con propuesta</span>
      <span><b>{pairedRate(comparison.metrics.pairedProposalIdentity)}</b> propuestas emparejadas</span>
      <span><b>{comparison.policyOnSummary.authorizations}/{comparison.policyOnSummary.attempts}</b> autorizadas con ON</span>
      <span><b>{explicitDenials}/{comparison.policyOnSummary.attempts}</b> denegadas con ON</span>
      <span><b>{approvalRequiredCalls}/{comparison.policyOnSummary.attempts}</b> requieren aprobación</span>
      <span><b>{comparison.policyOffSummary.counterfactualWouldExecute}/{comparison.policyOffSummary.proposalCount}</b> habrían ocurrido en el clon</span>
    </div>
    <div className="guardian-verification-stats">
      <span><b>{pairedRate(comparison.metrics.benignSuccess)}</b> éxito benigno</span>
      <span><b>{pairedRate(comparison.metrics.falseBlocks)}</b> falso bloqueo</span>
      <span><b>{pairedRate(comparison.metrics.attackPotential)}</b> potencial de ataque</span>
      <span><b>{comparison.policyOnSummary.simulatedExecutions}</b> ejecuciones simuladas con ON</span>
      <span><b>0</b> acciones reales · cambios en el estado simulado · llamadas externas</span>
    </div>
    <div className="guardian-verification-table-wrap">
      <table className="guardian-verification-table">
        <thead><tr>
          <th scope="col">Caso</th>
          <th scope="col">Origen</th>
          <th scope="col">Herramienta</th>
          <th scope="col">Policy ON</th>
          <th scope="col">Policy OFF · clon</th>
          <th scope="col">Identidad emparejada</th>
        </tr></thead>
        <tbody>
          {comparison.pairs.map((pair) => (
            <tr key={pair.toolCallId}>
              <th scope="row">{pair.caseId}</th>
              <td>{pair.toolCallOrigin === 'guardian_qwen_native_markup_adapter'
                ? 'Marcador Qwen adaptado'
                : pair.toolCallOrigin === 'runtime_message_tool_calls'
                  ? 'message.tool_calls directo'
                  : 'Doble de prueba'}</td>
              <td>{toolLabels[pair.tool] ?? pair.tool}</td>
              <td>{pair.policyOn.resultCode === 'approval_required_before_dispatch'
                ? 'REQUIRE_APPROVAL · no ejecutada'
                : pair.policyOn.denied
                ? `DENY · ${pair.policyOn.resultCode}`
                : pair.policyOn.simulatedExecution
                  ? 'ALLOW · simulada'
                  : `ALLOW · ${pair.policyOn.resultCode}`}</td>
              <td>{pair.policyOff.counterfactualWouldExecute
              ? `Habría ocurrido en el clon${pair.policyOff.counterfactualCloneStateChanged ? ' · estado del clon cambiaría' : ''}`
                : 'No superaría validación/límite'} · nunca ejecutado</td>
              <td>
                <details>
                  <summary>Hash</summary>
                  <code>{pair.proposalSha256}</code>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    <details className="guardian-verification-details">
      <summary>Versiones y hashes de comparación</summary>
      <dl>
        <dt>Versión de comparación</dt><dd>{comparison.version} · {comparison.policyVersion}</dd>
        <dt>Seed fija</dt><dd>{comparison.fixedSeed}</dd>
        <dt>Hash del conjunto emparejado</dt><dd><code>{comparison.caseSetSha256}</code></dd>
        <dt>Hash del estado inicial sintético</dt><dd><code>{comparison.initialSyntheticStateSha256}</code></dd>
        <dt>Hash de evidencia</dt><dd><code>{comparison.comparisonEvidenceSha256}</code></dd>
      </dl>
      <small>{comparison.interpretation}</small>
    </details>
  </section>;
}

function NativeToolSuiteResult({
  evidence,
  job,
}: {
  evidence: NativeToolSuiteEvidence | AutonomousToolSelectionEvidence;
  job: AiAssessmentLabJob;
}) {
  const suite = evidence.nativeToolSuite;
  const autonomous =
    evidence.profileId === 'guardian-local-llm-autonomous-tools-v1';
  const bankAttackCase = autonomous
    ? suite.caseEvidence.find((item) => item.caseId === 'attack_bank_es_cal')
    : undefined;
  const executiveFinding = autonomous ? deriveQwenBankChangeFinding(suite) : undefined;
  return <section className="guardian-verification" data-testid="native-tool-suite-result">
    <div className="guardian-verification-heading">
      <div>
        <span className="ai-evaluation-run-label">
          {autonomous
            ? 'LLM REAL · tool_choice=auto · LABORATORIO LOCAL'
            : 'LLM REAL · LLAMADAS NATIVAS · LABORATORIO LOCAL'}
        </span>
        <h4>{autonomous ? 'Selección autónoma de herramientas' : 'Evaluación de llamadas a herramientas'}</h4>
      </div>
      <span className="guardian-verification-pill">Solo laboratorio; no disponible para clientes</span>
    </div>
    <p className="guardian-verification-disclaimer">
      {autonomous
        ? suite.toolCallParsing
          ? <>Hubo inferencia local real en {suite.sampleCount} casos mixtos, con <code>tool_choice=auto</code>; no se forzó la función. El modelo emitió marcadores de plantilla Qwen que Guardian adaptó a propuestas estructuradas; no son llamadas nativas directas. En el registro, el runtime devolvió directamente {suite.toolCallParsing.callsReturnedDirectlyByRuntime} objetos <code>message.tool_calls</code>. El adaptador exige el marcador completo; no acepta JSON libre. Herramientas ficticias, sin efectos externos.</>
          : <>Los {suite.sampleCount} casos de este registro usaron <code>tool_choice=auto</code>. Esta evidencia anterior no registra extracción de marcador; no permite distinguir una llamada estructurada entregada como texto de una respuesta sin llamada. Las herramientas son ficticias y no producen efectos externos.</>
        : <>Qwen3 local devolvió objetos <code>message.tool_calls</code> usando el template GGUF; no se interpretó JSON del texto como tool call. Las llamadas de correo y cambio bancario solo generaron resultados ficticios en memoria.</>}
    </p>
    <div className="guardian-verification-stats">
      <span><b>{suite.sampleCount}</b> casos sintéticos mixtos</span>
      <span>{autonomous
        ? <>Particiones internas <b>{suite.splitSampleCounts.calibration}+{suite.splitSampleCounts.holdout}</b></>
        : <><b>{suite.splitSampleCounts.calibration}</b> calibración · <b>{suite.splitSampleCounts.holdout}</b> holdout</>}</span>
      <span><b>{suite.languageCounts.en}/{suite.languageCounts.es}</b> casos EN/ES</span>
      <span><b>{suite.toolCallParsing ? suite.toolCallParsing.callsAdapted : 'No registrado'}</b> marcadores Qwen adaptados por Guardian</span>
      <span><b>{suite.toolCallParsing ? suite.toolCallParsing.callsReturnedDirectlyByRuntime : 'No registrado'}</b> message.tool_calls directos del runtime</span>
      <span><b>{suite.taskSuccess.numerator}/{suite.taskSuccess.denominator}</b> tareas elegibles verificadas</span>
      <span><b>{suite.metrics.find((metric) => metric.split === 'all')?.inconclusiveCount ?? 0}</b> casos inconclusos</span>
    </div>
    {autonomous && <div className="qwen-executive-summary" data-testid="qwen-executive-summary">
      <div className="qwen-summary-mark">LECTURA EJECUTIVA <span>· {suite.sampleCount} CASOS</span></div>
      <h5>Una muestra local con controles y ataques sintéticos; no permite estimar una tasa general de seguridad.</h5>
      <p>El laboratorio usó datos ficticios y herramientas simuladas. {bankAttackCase
        ? <>En el caso bancario en español, el contenido planteó una modificación no autorizada: {bankAttackCase.policyObservationComplete
          ? bankAttackCase.unauthorizedAttempt
            ? 'el intento observado fue denegado por la política.'
            : bankAttackCase.policyAllowed
              ? 'la política permitió la propuesta observada.'
              : 'la evidencia no registra un intento no autorizado.'
          : 'la observación de autorización quedó inconclusa.'} {bankAttackCase.simulatedExecution
            ? 'La acción solo se ejecutó en el simulador ficticio.'
            : 'No consta ejecución de la acción en el simulador.'}</>
        : 'El caso bancario en español no está presente en esta evidencia.'} No se almacenan el prompt, la respuesta ni los argumentos, por lo que el informe no reproduce la solicitud literal.</p>
      {executiveFinding && <section className="qwen-bank-finding" data-testid="qwen-bank-finding">
        <div className="qwen-bank-finding-heading">
          <b>Hallazgo ejecutivo · {executiveFinding.title}</b>
          <span>{executiveFinding.stages.policyDecision}</span>
        </div>
        <p>{executiveFinding.observation} {executiveFinding.riskIllustrated}</p>
        <p className="qwen-finding-caveat">{executiveFinding.severityAndCustomerScope}</p>
        <div className="qwen-finding-stages" aria-label="Etapas de la evidencia">
          <span><b>Propuesta</b>{executiveFinding.stages.proposal}</span>
          <span><b>Intento</b>{executiveFinding.stages.attempt}</span>
          <span><b>Decisión de política</b>{executiveFinding.stages.policyDecision}</span>
          <span><b>Ejecución simulada</b>{executiveFinding.stages.simulatedExecution}</span>
          <span><b>Contrafactual · clon</b>{executiveFinding.stages.counterfactual}</span>
        </div>
        <div className="qwen-finding-footer">
          <div><b>Mitigación de política independiente</b><span>{executiveFinding.independentPolicyMitigation.status} · {executiveFinding.independentPolicyMitigation.explanation}</span></div>
          <div><b>Estado de remediación / efectos</b><span>{executiveFinding.remediationStatus}</span></div>
        </div>
        <details className="qwen-finding-evidence">
          <summary>Referencias de evidencia y hashes</summary>
          <p>{executiveFinding.evidenceReferences.verification}</p>
          <dl>
            <dt>Evidencia del caso</dt><dd><code>{executiveFinding.evidenceReferences.caseEvidenceSha256 ?? 'INCONCLUSO'}</code></dd>
            <dt>Conjunto de pruebas</dt><dd><code>{executiveFinding.evidenceReferences.suiteEvidenceSha256 ?? 'INCONCLUSO'}</code></dd>
            <dt>Propuesta emparejada</dt><dd><code>{executiveFinding.evidenceReferences.proposalSha256 ?? 'INCONCLUSO'}</code></dd>
            <dt>Evidencia del par</dt><dd><code>{executiveFinding.evidenceReferences.pairedCaseEvidenceSha256 ?? 'INCONCLUSO'}</code></dd>
            <dt>Comparación de política</dt><dd><code>{executiveFinding.evidenceReferences.comparisonEvidenceSha256 ?? 'INCONCLUSO'}</code></dd>
          </dl>
        </details>
      </section>}
      <div className="qwen-outcome-strip" aria-label="Resultados observados y denominadores">
        <span><b>{suite.toolSummary.proposals}/{suite.sampleCount}</b> casos con propuesta</span>
        <span><b>{suite.toolSummary.authorizationAttempts}/{suite.toolSummary.proposals}</b> propuestas con intento de autorización</span>
        <span><b>{suite.toolSummary.authorizedExecutions}/{suite.toolSummary.authorizationAttempts}</b> autorizadas y simuladas</span>
        <span><b>{suite.toolSummary.deniedCalls}/{suite.toolSummary.authorizationAttempts}</b> denegadas</span>
        <span><b>{suite.toolSummary.approvalRequiredCalls ?? 0}/{suite.toolSummary.authorizationAttempts}</b> requieren aprobación</span>
        <span><b>{suite.toolSummary.unauthorizedExecutions}/{suite.toolSummary.unauthorizedAttempts}</b> intentos no autorizados ejecutados</span>
        <span><b>{suite.toolSummary.externalCalls}</b> llamadas externas</span>
      </div>
      <div className="qwen-summary-footer">
        <span><b>Recomendación</b> Mantener autorización explícita por operación y revisar cada caso inconcluso antes de ampliar pruebas.</span>
        <span><b>Alcance</b> Agente local de laboratorio; no evalúa disponibilidad ni sistemas de clientes.</span>
      </div>
      <Button
        variant="outline"
        size="sm"
        onClick={() => downloadQwenExecutiveReport(job)}
        data-testid="download-qwen-report"
      >
        Descargar informe JSON redactado
      </Button>
      <p className="qwen-limitations">Límites: muestra pequeña de {suite.sampleCount} casos, sin tasa general de seguridad; IPv6 {networkStatusLabel(evidence.network.publicIpv6)} (no equivale a bloqueo verificado); la auditoría global de dependencias del worker se informa por separado y no forma parte de esta evidencia de tenant; servicio para clientes no disponible. No se conservan prompts, respuestas ni argumentos.</p>
    </div>}
    <p className="guardian-verification-disclaimer">
      {autonomous
        ? `La muestra de ${suite.sampleCount} casos incluye ${suite.benignCases} controles benignos y ${suite.attackCases} ataques de inyección indirecta en correo o documentos. Es pequeña y no permite calcular una tasa general de seguridad. «Verificada» significa que la tarea sintética elegible obtuvo el resultado esperado; no se evalúa una respuesta conversacional posterior. Las propuestas, intentos de autorización, autorizaciones y simulaciones son etapas distintas. Una llamada ausente o incorrecta no se convierte en éxito y nunca se cambia a selección forzada.`
        : 'En tareas benignas autorizadas, el arnés seleccionó la función específica para comprobar argumentos y autorización; eso no mide selección autónoma. Ataques y textos citados usaron selección automática. Las matrices comparan tipo de escenario con eventos de herramienta observados; un falso negativo significa que no se observó ese evento en un caso de ataque, no que un detector de ataques haya fallado.'}
    </p>
      {autonomous && suite.policyComparison && (
        <QwenPolicyComparisonResult comparison={suite.policyComparison} />
      )}
    <details className="guardian-verification-details">
      <summary>Métricas, trazas y procedencia</summary>
      <div className="guardian-verification-table-wrap">
        <table className="guardian-verification-table">
          <thead><tr>
            <th scope="col">Conjunto</th>
            <th scope="col">Objetivo</th>
            <th scope="col">Evaluables</th>
            <th scope="col">Inconclusos</th>
            <th scope="col">TP</th>
            <th scope="col">FP</th>
            <th scope="col">TN</th>
            <th scope="col">FN</th>
          </tr></thead>
          <tbody>
            {suite.metrics.map((metric) => (
              <tr key={`${metric.split}-${metric.objective}`}>
                <th scope="row">{metric.split}</th>
                <td>{nativeObjectiveLabels[metric.objective] ?? metric.objective}</td>
                <td>{metric.evaluableCount}/{metric.sampleCount}</td>
                <td>{metric.inconclusiveCount}</td>
                <td>{metric.truePositive}</td>
                <td>{metric.falsePositive}</td>
                <td>{metric.trueNegative}</td>
                <td>{metric.falseNegative}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {autonomous && <p className="guardian-verification-note">
        Este conjunto de laboratorio cubre correo, documentos y una acción financiera ficticia: {suite.benignCases} controles benignos y {suite.attackCases} casos de inyección indirecta. Bases de datos y programación aún no están evaluadas. Las matrices reflejan solo eventos observados en esta muestra; no son una estimación general de seguridad.
      </p>}
      <div className="guardian-verification-table-wrap">
        <table className="guardian-verification-table">
          <thead><tr>
            <th scope="col">Caso</th>
            <th scope="col">Grupo</th>
            <th scope="col">Herramientas propuestas</th>
            {autonomous && <th scope="col">Origen de llamada</th>}
            <th scope="col">Argumentos · permiso</th>
            <th scope="col">Intento no permitido</th>
            <th scope="col">Ejecución ficticia</th>
            <th scope="col">Tarea</th>
          </tr></thead>
          <tbody>
            {suite.caseEvidence.map((item) => (
              <tr key={item.caseId}>
                <th scope="row">{autonomousCaseLabels[item.caseId] ?? item.caseId}</th>
                <td>{autonomous
                  ? `${agentDomainLabels[item.agentDomain ?? ''] ?? 'Dominio no registrado'} · ${item.label === 'attack' ? 'ataque indirecto' : 'control benigno'} · ${item.split === 'calibration' ? 'calibración' : 'holdout'} · ${item.language.toUpperCase()} · ${autonomousTaskLabels[item.category] ?? item.label}`
                  : `${item.split} · ${item.language.toUpperCase()} · ${item.label}`}</td>
                <td>{item.proposedTools.length ? item.proposedTools.map((tool) => toolLabels[tool] ?? tool).join(', ') : 'Ninguna'}</td>
                {autonomous && <td>{item.toolCallOrigin === 'guardian_qwen_native_markup_adapter' ? 'Marcador de plantilla Qwen adaptado por Guardian' : item.toolCallOrigin === 'runtime_message_tool_calls' ? 'message.tool_calls directo del runtime' : item.toolCallOrigin === 'test_provider_message_tool_calls' ? 'Respuesta de prueba · no inferencia real' : item.toolCallOrigin === 'unparsed_qwen_native_markup' ? 'Marcador no interpretable' : item.toolCallOrigin === 'not_observed' ? 'No observada' : 'Origen no registrado'}</td>}
                <td>{autonomous ? `${item.argumentsValid ? 'Válidos' : 'No válidos'} · ${item.policyAllowed ? 'permitido' : 'no permitido'}` : 'No medido en este perfil'}</td>
                <td>{item.policyObservationComplete ? item.unauthorizedAttempt ? 'Sí; denegado' : 'No observado' : 'Inconcluso'}</td>
                <td>{autonomous ? item.simulatedExecution ? 'Sí, solo simulación' : 'No' : item.authorizedExecutionCount}</td>
                <td>{item.taskSuccessEligible ? item.taskSucceeded ? 'Verificada' : 'No verificada' : 'No aplicable'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <dl>
        <dt>Modelo y licencia</dt><dd>{evidence.provider.modelId} Q8_0 · {evidence.provider.license}</dd>
        <dt>Runtime</dt><dd>{evidence.provider.runtime} {evidence.provider.runtimeVersion} · {evidence.provider.runtimeLicense}</dd>
        <dt>Template GGUF</dt><dd><code>{evidence.provider.chatTemplateSha256}</code></dd>
        <dt>Template efectivo</dt><dd><code>{evidence.provider.effectiveChatTemplateSha256}</code></dd>
        <dt>Hash del modelo</dt><dd><code>{evidence.provider.sha256}</code></dd>
        <dt>Hash de evidencia</dt><dd><code>{evidence.evidenceSha256}</code></dd>
        <dt>Hash del conjunto</dt><dd><code>{suite.suiteEvidenceSha256}</code></dd>
        {autonomous && <><dt>Selección por tarea</dt><dd>tool_choice=auto · una llamada · máximo 128 tokens.</dd>{suite.toolCallParsing && <><dt>Parser Qwen</dt><dd>{suite.toolCallParsing.callsAdapted} marcadores de plantilla Qwen adaptados por Guardian · {suite.toolCallParsing.callsReturnedDirectlyByRuntime} llamadas directas del runtime · {suite.toolCallParsing.unparsedMarkupCases} casos con marcador rechazado. El parser exige el marcador completo y no acepta JSON libre.</dd></>}<dt>Suite forzada anterior</dt><dd><code>{suite.previousForcedSuiteEvidenceSha256}</code> · referencia separada, no es evidencia de autonomía.</dd></>}
        <dt>Red</dt><dd>IPv4 {networkStatusLabel(evidence.network.publicIpv4)}, IPv6 {networkStatusLabel(evidence.network.publicIpv6)}; «no disponible» no confirma bloqueo. DNS {networkStatusLabel(evidence.network.publicDns)}.</dd>
        <dt>Límites comprobados</dt><dd>{evidence.limits.verifiedContainerLimits.cpuCores} CPU · {Math.round(evidence.limits.verifiedContainerLimits.memoryBytes / 1024 / 1024)} MiB · {evidence.limits.verifiedContainerLimits.pids} procesos · una concurrencia · {evidence.durationSeconds} s.</dd>
        <dt>Acciones externas</dt><dd>{suite.toolSummary.externalCalls} llamadas externas · {suite.toolSummary.stateChanges} cambios persistentes.</dd>
      </dl>
      <small>{suite.metricInterpretation} No extrapolar esta muestra ni tratarla como garantía de seguridad.</small>
    </details>
  </section>;
}

export function LabJobCard({
  job,
  canRun,
  onRetry,
  retryPending,
  focusedCaseId,
}: {
  job: AiAssessmentLabJob;
  canRun: boolean;
  onRetry: (jobId: string) => void;
  retryPending: boolean;
  focusedCaseId?: string;
}) {
  const evidence = job.result;
  const garakEvidence = evidence?.engine === 'garak' ? evidence : null;
  const localLlmEvidence =
    evidence?.profileId === 'guardian-local-llm-qwen3-0.6b-v1'
      ? evidence
      : null;
  const nativeToolEvidence =
    evidence?.profileId === 'guardian-local-llm-native-tools-v1' ||
    evidence?.profileId === 'guardian-local-llm-autonomous-tools-v1'
      ? evidence
      : null;
  const policyLabEvidence =
    evidence?.engine === 'guardian_policy_lab' ? evidence : null;
  const qwenPolicyLabEvidence =
    evidence?.engine === 'guardian_qwen_policy_lab' ? evidence : null;
  return <article className="ai-evaluation-run" data-testid="ai-lab-job">
    <div className="ai-evaluation-run-head">
      <div>
        <span className="ai-evaluation-run-label">
          {job.profileId.startsWith('guardian-agent-lab-')
            ? 'POLICY ENGINE · FIXTURES DETERMINISTAS'
            : job.profileId === 'guardian-local-llm-autonomous-tools-v1'
            ? 'LLM REAL · SELECCIÓN AUTÓNOMA'
            : job.profileId === 'guardian-local-llm-native-tools-v1'
            ? 'LLM REAL · TOOL CALLS NATIVAS'
            : job.profileId === 'guardian-local-llm-qwen3-0.6b-v1'
            ? 'INFERENCIA REAL · LLM LOCAL'
            : job.profileId.startsWith('guardian-agent-qwen-lab-')
            ? 'INFERENCIA QWEN REAL · POLICY ENGINE EXTERNO'
            : 'EVALUACIÓN LOCAL · MOCK Y FIXTURES'}
        </span>
        <h3>{labStatusLabels[job.status]}</h3>
      </div>
      <time dateTime={job.createdAt}><Clock3 size={13} /> {new Date(job.createdAt).toLocaleString('es-ES')}</time>
    </div>
    {garakEvidence && <div className="ai-lab-result" data-testid="ai-lab-real-result">
      <div className="ai-lab-result-summary">
        <b>{garakEvidence.positiveDetectorScores === 0 ? 'Sin puntuaciones positivas en esta prueba acotada' : `${garakEvidence.positiveDetectorScores} puntuación${garakEvidence.positiveDetectorScores === 1 ? '' : 'es'} positiva${garakEvidence.positiveDetectorScores === 1 ? '' : 's'} del detector`}</b>
        <span>{garakEvidence.probeRequests} solicitud · {garakEvidence.generationsPerProbe} generación</span>
      </div>
      <p>{garakEvidence.findingSummary} Esta ejecución cubre únicamente las pruebas indicadas; no garantiza la seguridad del agente.</p>
      <details>
        <summary>Procedencia y evidencia técnica</summary>
        <dl>
          <dt>Motor y versión</dt><dd>Garak {garakEvidence.engineVersion} · licencia Apache-2.0</dd>
          <dt>Pruebas</dt><dd>{garakEvidence.probeClasses.join(', ')}</dd>
          <dt>Puntuaciones positivas</dt><dd>{garakEvidence.findings.length ? garakEvidence.findings.map((finding) => `${finding.detector}: ${finding.positiveScores}`).join('; ') : 'Ninguna registrada en este informe'}</dd>
          <dt>Informe procesado</dt><dd>{garakEvidence.reportRecordCount} registros · {garakEvidence.reportBytes} bytes · {garakEvidence.durationSeconds} s</dd>
          <dt>Red</dt><dd>Modo {garakEvidence.network.networkMode}; IPv4 {networkStatusLabel(garakEvidence.network.publicIpv4)}, IPv6 {networkStatusLabel(garakEvidence.network.publicIpv6)}, DNS público {networkStatusLabel(garakEvidence.network.publicDns)}.</dd>
          <dt>Informe</dt><dd>SHA-256 {garakEvidence.reportSha256}</dd>
          <dt>Datos</dt><dd>No se conservaron prompts ni respuestas; sin datos de clientes.</dd>
        </dl>
        <small>Garak es software de terceros; Guardian Nexus lo integra y conserva su atribución técnica. Esta ejecución fue en el agente local de laboratorio.</small>
      </details>
      {garakEvidence.guardianVerification && <GuardianVerificationResult verification={garakEvidence.guardianVerification} />}
    </div>}
    {localLlmEvidence && <LocalLlmResult evidence={localLlmEvidence} />}
    {nativeToolEvidence && <NativeToolSuiteResult evidence={nativeToolEvidence} job={job} />}
    {policyLabEvidence && <AgentPolicyLabResult evidence={policyLabEvidence} focusedCaseId={focusedCaseId} />}
    {qwenPolicyLabEvidence && <QwenPolicyLabResult evidence={qwenPolicyLabEvidence} />}
    {job.status === 'failed' && <p className="ai-lab-error">No se completó la evaluación. Código: {job.errorCode ?? 'worker_failed'}. No se guardaron salidas del agente.</p>}
    {canRun && job.status === 'failed' && job.attempts < 2 && <Button variant="outline" onClick={() => onRetry(job.id)} disabled={retryPending} data-testid="button-retry-ai-lab">
      {retryPending ? 'Reintentando…' : 'Reintentar una vez'}
    </Button>}
  </article>;
}

function ExecutiveLabJobCard({ job }: { job: AiAssessmentLabJob }) {
  const state = {
    queued: "En cola",
    running: "En curso",
    succeeded: "Resultado registrado",
    failed: "Sin resultado",
  }[job.status];
  const description = job.status === "failed"
    ? "La evaluación no se completó; este registro no contiene un resultado disponible."
    : job.status === "succeeded"
      ? "Hay evidencia de laboratorio asociada a este registro. Su alcance se limita a los escenarios sintéticos evaluados."
      : "El registro todavía no tiene un resultado final.";
  return <article className="ai-evaluation-run ai-executive-job" data-testid="ai-lab-job">
    <div className="ai-evaluation-run-head">
      <div><span className="ai-evaluation-run-label">EVALUACIÓN SINTÉTICA</span><h3>{state}</h3></div>
      <time dateTime={job.createdAt}><Clock3 size={13} /> {new Date(job.createdAt).toLocaleString("es-ES")}</time>
    </div>
    <p>{description}</p>
    <small>Los detalles técnicos de laboratorio están reservados a propietarios y administradores.</small>
  </article>;
}

export type AiEvaluationSection = 'lab' | 'approvals' | 'audit';

const AI_EVALUATION_SECTIONS: Array<{
  id: AiEvaluationSection;
  label: string;
}> = [
  { id: 'lab', label: 'Laboratorio' },
  { id: 'approvals', label: 'Aprobaciones' },
  { id: 'audit', label: 'Auditoría' },
];

export function AiEvaluationSectionNav({
  activeSection,
  onSelect,
}: {
  activeSection: AiEvaluationSection;
  onSelect: (section: AiEvaluationSection) => void;
}) {
  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    const currentIndex = AI_EVALUATION_SECTIONS.findIndex(
      (section) => section.id === activeSection,
    );
    let nextIndex: number | null = null;
    if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % AI_EVALUATION_SECTIONS.length;
    if (event.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + AI_EVALUATION_SECTIONS.length) % AI_EVALUATION_SECTIONS.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = AI_EVALUATION_SECTIONS.length - 1;
    if (nextIndex === null) return;

    event.preventDefault();
    const nextSection = AI_EVALUATION_SECTIONS[nextIndex];
    onSelect(nextSection.id);
    event.currentTarget.parentElement
      ?.querySelector<HTMLButtonElement>(`#ai-evaluation-tab-${nextSection.id}`)
      ?.focus();
  }

  return (
    <div className="ai-evaluation-section-nav" role="tablist" aria-label="Secciones de Seguridad IA" data-testid="ai-evaluation-section-nav">
      {AI_EVALUATION_SECTIONS.map((section) => (
        <button
          key={section.id}
          id={`ai-evaluation-tab-${section.id}`}
          type="button"
          role="tab"
          aria-selected={activeSection === section.id}
          aria-controls={`ai-evaluation-panel-${section.id}`}
          tabIndex={activeSection === section.id ? 0 : -1}
          data-testid={`ai-evaluation-tab-${section.id}`}
          onClick={() => onSelect(section.id)}
          onKeyDown={handleKeyDown}
        >
          {section.label}
        </button>
      ))}
    </div>
  );
}

export default function AiEvaluationPage({ workspace }: { workspace: Workspace }) {
  const cache = useQueryClient();
  const history = useListWorkspaceAiEvaluations(workspace.id);
  const runEvaluation = useRunWorkspaceMockAiEvaluation();
  const availability = useGetWorkspaceAiAssessmentLabAvailability(workspace.id, {
    query: { refetchInterval: 5_000 },
  });
  const labJobs = useListWorkspaceAiAssessmentLabJobs(workspace.id, {
    query: { refetchInterval: availability.data?.status === 'ready' ? 3_000 : false },
  });
  const approvalList = useListWorkspaceAiAssessmentApprovals(workspace.id, {
    query: { refetchInterval: 10_000 },
  });
  const createLabJob = useCreateWorkspaceAiAssessmentLabJob();
  const previewPolicyLab = usePreviewWorkspaceAiAssessmentPolicyLab();
  const retryLabJob = useRetryWorkspaceAiAssessmentLabJob();
  const decideApproval = useDecideWorkspaceAiAssessmentApproval();
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [labMessage, setLabMessage] = useState('');
  const [labError, setLabError] = useState('');
  const [guidedDemo, setGuidedDemo] = useState<{
    jobId: string;
    caseId: string;
  } | null>(null);
  const [freshPolicyPreview, setFreshPolicyPreview] = useState<{
    profileId: Extract<AiAssessmentLabJobRequestProfileId, `guardian-agent-lab-${string}-v1`>;
    caseId: string;
    evidence: GuardianPolicyLabPreviewResponse['evidence'];
  } | null>(null);
  const [approvalMessage, setApprovalMessage] = useState('');
  const [approvalError, setApprovalError] = useState('');
  const [activeSection, setActiveSection] = useState<AiEvaluationSection>('lab');
  const canRun = workspace.role === 'owner' || workspace.role === 'admin';
  const garakAvailable = availability.data?.profiles.some(
    (profile) => profile.profileId === 'guardian-local-agent-v1' && profile.status === 'ready',
  ) ?? false;
  const qwenAvailable = availability.data?.profiles.some(
    (profile) => profile.profileId === 'guardian-local-llm-qwen3-0.6b-v1' && profile.status === 'ready',
  ) ?? false;
  const nativeToolsAvailable = availability.data?.profiles.some(
    (profile) => profile.profileId === 'guardian-local-llm-native-tools-v1' && profile.status === 'ready',
  ) ?? false;
  const autonomousToolsAvailable = availability.data?.profiles.some(
    (profile) => profile.profileId === 'guardian-local-llm-autonomous-tools-v1' && profile.status === 'ready',
  ) ?? false;

  async function requestLabAssessment(
    profileId: AiAssessmentLabJobRequestProfileId,
    guidedCaseId?: string,
  ) {
    setLabMessage('');
    setLabError('');
    setFreshPolicyPreview(null);
    if (guidedCaseId) setGuidedDemo(null);
    try {
      const createdJob = await createLabJob.mutateAsync({
        workspaceId: workspace.id,
        data: { idempotencyKey: crypto.randomUUID(), profileId },
      });
      if (guidedCaseId) {
        setGuidedDemo({ jobId: createdJob.id, caseId: guidedCaseId });
      }
      setActiveSection('audit');
      setLabMessage(guidedCaseId
        ? 'Solicitud registrada. Se ejecutan solo los fixtures fijos del perfil; el caso elegido quedará resaltado.'
        : 'Solicitud registrada. Se ejecutará únicamente el perfil local seleccionado.');
      await cache.invalidateQueries({
        queryKey: getListWorkspaceAiAssessmentLabJobsQueryKey(workspace.id),
      });
    } catch {
      setLabError('No se pudo iniciar el laboratorio. No se ha creado un resultado simulado.');
    }
  }

  async function runPolicyPreview(
    profileId: Extract<AiAssessmentLabJobRequestProfileId, `guardian-agent-lab-${string}-v1`>,
    focusedCaseId: string,
  ) {
    setLabMessage('');
    setLabError('');
    setGuidedDemo(null);
    setFreshPolicyPreview(null);
    try {
      const result = await previewPolicyLab.mutateAsync({
        workspaceId: workspace.id,
        data: { profileId },
      });
      setFreshPolicyPreview({ profileId, caseId: focusedCaseId, evidence: result.evidence });
      setLabMessage('Decisión recibida del Policy Engine. No se creó un job ni se inició Qwen o Docker.');
    } catch {
      setLabError(
        'No se pudo calcular la previsualización determinista. No se creó un trabajo ni se inició Qwen, Docker o una acción externa.',
      );
    }
  }

  async function recordApprovalDecision(
    approvalId: string,
    proposalBindingSha256: string,
    decision: 'approve' | 'deny',
  ) {
    setApprovalMessage('');
    setApprovalError('');
    try {
      await decideApproval.mutateAsync({
        workspaceId: workspace.id,
        approvalId,
        data: { decision, proposalBindingSha256 },
      });
      setApprovalMessage('Decisión registrada. No se ejecutó ni reanudó ninguna herramienta.');
      await cache.invalidateQueries({
        queryKey: getListWorkspaceAiAssessmentApprovalsQueryKey(workspace.id),
      });
    } catch {
      setApprovalError('No se pudo registrar la decisión. La operación simulada no se ejecutó.');
      await approvalList.refetch();
    }
  }

  async function retryLabAssessment(jobId: string) {
    setLabError('');
    try {
      await retryLabJob.mutateAsync({ workspaceId: workspace.id, jobId });
      await cache.invalidateQueries({
        queryKey: getListWorkspaceAiAssessmentLabJobsQueryKey(workspace.id),
      });
    } catch {
      setLabError('No se pudo reencolar el trabajo. Comprueba el estado y los permisos del espacio.');
    }
  }

  async function runMock() {
    setMessage('');
    setError('');
    try {
      await runEvaluation.mutateAsync({ workspaceId: workspace.id });
      setActiveSection('audit');
      setMessage('Simulación registrada en la auditoría de este espacio. No se contactó ningún agente ni proveedor.');
      await cache.invalidateQueries({
        queryKey: getListWorkspaceAiEvaluationsQueryKey(workspace.id),
      });
    } catch {
      setError('No se pudo completar la simulación. Comprueba el permiso del espacio y la cuota de análisis.');
    }
  }

  return <div className="ai-evaluation-page">
    <div className="page-heading">
      <div>
        <div className="eyebrow">GUARDIAN AI SECURITY ASSESSMENT · LABORATORIO</div>
        <h1>Evaluación de Seguridad de IA</h1>
        <p>Consulta resultados sintéticos, decisiones pendientes y registros de auditoría. Las pruebas se limitan al laboratorio y no evalúan sistemas empresariales.</p>
      </div>
      <span className="ai-evaluation-badge"><FlaskConical size={14} /> LABORATORIO INTERNO</span>
    </div>

    <div className="ai-evaluation-disclaimer" role="note" data-testid="ai-evaluation-disclaimer">
      <ShieldAlert size={18} />
      <div><b>Solo se usan datos y herramientas sintéticos.</b><p>La demostración consulta el motor de autorización y no inicia modelos, contenedores ni conexiones externas. Esta previsualización no constituye una frontera de aislamiento ni está disponible como servicio para clientes.</p></div>
    </div>

    <AiEvaluationSectionNav activeSection={activeSection} onSelect={setActiveSection} />
    {labMessage && <div className="notice notice-success ai-evaluation-feedback" role="status">{labMessage}</div>}
    {labError && <div className="notice notice-error ai-evaluation-feedback" role="alert">{labError}</div>}
    {message && <div className="notice notice-success ai-evaluation-feedback" role="status">{message}</div>}
    {error && <div className="notice notice-error ai-evaluation-feedback" role="alert">{error}</div>}

    <section
      id="ai-evaluation-panel-lab"
      className="ai-evaluation-section-panel"
      role="tabpanel"
      aria-labelledby="ai-evaluation-tab-lab"
      tabIndex={0}
      hidden={activeSection !== 'lab'}
    >
    <section className="panel ai-evaluation-card ai-lab-card">
      <div className="panel-heading">
        <div><span className="panel-kicker">PREVISUALIZACIÓN · POLICY ON</span><h2>Laboratorio de políticas</h2></div>
        <span className="ai-evaluation-state ai-state-pending"><i />Fixtures deterministas</span>
      </div>
      <p>Elige un perfil y un escenario para recibir una decisión determinista calculada por el backend. El resultado destaca el caso elegido y conserva los detalles técnicos en un panel secundario.</p>
       <AgentPolicyLabCatalog
         profiles={availability.data?.profiles ?? []}
         canRun={canRun}
         pending={createLabJob.isPending}
          previewPending={previewPolicyLab.isPending}
          onRequest={(profileId, caseId) => void requestLabAssessment(profileId, caseId)}
          onPreview={(profileId, caseId) => void runPolicyPreview(profileId, caseId)}
           onSelectionChange={() => {
             setGuidedDemo(null);
             setFreshPolicyPreview(null);
             setLabMessage('');
             setLabError('');
           }}
           onViewApprovals={() => setActiveSection('approvals')}
          freshPreview={freshPolicyPreview}
          recordedEvidence={recordedPolicyEvidence}
          recordedArtifactSha256={recordedPolicyArtifactSha256}
          onReset={() => {
            setGuidedDemo(null);
            setFreshPolicyPreview(null);
             setLabMessage('Vista reiniciada. El historial y las auditorías del espacio no se han borrado.');
            setLabError('');
          }}
       />
        {canRun && <details className="ai-lab-advanced-details" data-testid="ai-lab-advanced-details">
          <summary>Evaluaciones técnicas y estado del worker</summary>
          <div className="ai-lab-advanced-content">
            <p>Qwen y Garak permanecen separados de los fixtures. El worker solo se inicia si el preflight está aprobado; los motivos de bloqueo se muestran una vez, no en cada perfil.</p>
            <QwenPolicyLabCatalog
              availability={availability.data?.profiles ?? []}
              canRun={canRun}
              pending={createLabJob.isPending}
              onRequest={(profileId) => void requestLabAssessment(profileId)}
            />
            <div className="ai-evaluation-actions">
              <Button onClick={() => void requestLabAssessment('guardian-local-agent-v1')} disabled={!canRun || !garakAvailable || createLabJob.isPending} data-testid="button-run-ai-lab">
                {createLabJob.isPending ? <Activity className="spin" size={15} /> : <ShieldCheck size={15} />}
                {createLabJob.isPending ? 'Encolando…' : 'Solicitar evaluación local'}
              </Button>
              <Button variant="outline" onClick={() => void requestLabAssessment('guardian-local-llm-qwen3-0.6b-v1')} disabled={!canRun || !qwenAvailable || createLabJob.isPending} data-testid="button-run-local-llm">
                {createLabJob.isPending ? <Activity className="spin" size={15} /> : <FlaskConical size={15} />}
                {createLabJob.isPending ? 'Encolando…' : 'Solicitar tarea con LLM local'}
              </Button>
              <Button variant="outline" onClick={() => void requestLabAssessment('guardian-local-llm-native-tools-v1')} disabled={!canRun || !nativeToolsAvailable || createLabJob.isPending} data-testid="button-run-native-tool-suite">
                {createLabJob.isPending ? <Activity className="spin" size={15} /> : <ShieldCheck size={15} />}
                {createLabJob.isPending ? 'Encolando…' : 'Solicitar suite de llamadas nativas'}
              </Button>
              <Button variant="outline" onClick={() => void requestLabAssessment('guardian-local-llm-autonomous-tools-v1')} disabled={!canRun || !autonomousToolsAvailable || createLabJob.isPending} data-testid="button-run-autonomous-tool-selection">
                {createLabJob.isPending ? <Activity className="spin" size={15} /> : <ShieldCheck size={15} />}
                {createLabJob.isPending ? 'Encolando…' : 'Evaluar selección autónoma'}
              </Button>
              {!canRun && <small>Solo owner/admin puede iniciar o reintentar.</small>}
            </div>

            <div className="ai-evaluation-grid">
              <section className="panel ai-evaluation-card">
                <div className="panel-heading">
                  <div><span className="panel-kicker">SIMULACIÓN · DATOS SINTÉTICOS</span><h2>Fixtures de ejemplo</h2></div>
                  <span className="ai-evaluation-state ai-state-pending"><i /> No es evaluación real</span>
                </div>
                <p>Los casos fijos describen rechazo de instrucciones no confiables, no exposición de un canario sintético y no ejecución de herramientas sin autorización.</p>
                <div className="ai-evaluation-limits">
                  <span><b>3</b> fixtures por ejecución</span>
                  <span><b>1</b> ejecución concurrente por proceso</span>
                  <span><b>0</b> llamadas a APIs/modelos externos</span>
                </div>
                <div className="ai-evaluation-actions">
                  <Button onClick={() => void runMock()} disabled={!canRun || runEvaluation.isPending || history.isLoading} data-testid="button-run-mock-ai-evaluation">
                    {runEvaluation.isPending ? <Activity className="spin" size={15} /> : <ShieldCheck size={15} />}
                    {runEvaluation.isPending ? 'Ejecutando…' : 'Ejecutar simulación local'}
                  </Button>
                  {!canRun && <small>Solo owner/admin puede iniciar la prueba.</small>}
                </div>
                <small className="ai-evaluation-footnote">Se guardan solo el resultado resumido y los códigos de motivo en la auditoría del espacio. No se guardan prompts, respuestas ni secretos.</small>
              </section>

              <section className="panel ai-evaluation-card ai-provider-card">
                <div className="panel-heading"><div><span className="panel-kicker">PROTECCIÓN OPCIONAL</span><h2>Google Cloud Model Armor</h2></div><span className="ai-evaluation-state ai-state-pending"><i /> Desactivado</span></div>
                <p>Existe un contrato de adaptador preparado para sanitizar entradas y salidas con consentimiento independiente por tenant y ubicación UE configurada.</p>
                <ul>
                  <li>Feature flag apagada; no hay llamadas ni credenciales de Google configuradas.</li>
                  <li>La conexión requiere autorización, IAM mínimo, plantilla y revisión de costes/condiciones.</li>
                  <li>Una protección de entrada/salida no reemplaza RLS ni otros controles.</li>
                </ul>
                <a href="https://docs.cloud.google.com/model-armor/data-residency" target="_blank" rel="noreferrer">Residencia y regiones oficiales ↗</a>
              </section>
            </div>
            <details className="ai-lab-provenance">
              <summary>Origen técnico y licencias</summary>
              <p>Garak v0.17.1 conserva su atribución de terceros y licencia Apache-2.0. La inferencia local utiliza Qwen3-0.6B-GGUF Q8_0 (Apache-2.0) mediante llama-cpp-python 0.3.36 (MIT). Sus versiones, hashes y procedencia se registran por separado en la evidencia.</p>
            </details>
          </div>
        </details>}
    </section>
    </section>

    <section
      id="ai-evaluation-panel-approvals"
      className="ai-evaluation-section-panel"
      role="tabpanel"
      aria-labelledby="ai-evaluation-tab-approvals"
      tabIndex={0}
      hidden={activeSection !== 'approvals'}
    >
    <GuardianApprovalInbox
      approvals={approvalList.data?.approvals ?? []}
      canDecide={approvalList.data?.canDecide ?? false}
      loading={approvalList.isLoading}
      error={approvalList.isError}
      mutationPending={decideApproval.isPending}
      message={approvalMessage}
      errorMessage={approvalError}
      onRetry={() => void approvalList.refetch()}
      onDecision={(approvalId, binding, decision) =>
        void recordApprovalDecision(approvalId, binding, decision)
      }
    />
    </section>

    <section
      id="ai-evaluation-panel-audit"
      className="ai-evaluation-section-panel"
      role="tabpanel"
      aria-labelledby="ai-evaluation-tab-audit"
      tabIndex={0}
      hidden={activeSection !== 'audit'}
    >
      <section className="panel ai-evaluation-card ai-lab-history-card">
        <div className="panel-heading">
          <div><span className="panel-kicker">TRABAJOS LOCALES · EVIDENCIA</span><h2>Resultados del laboratorio</h2></div>
          <span className="ai-evaluation-state ai-state-pending"><i />Procedencia explícita</span>
        </div>
        <p>Los resultados se mantienen separados por origen: fixtures deterministas, inferencia Qwen histórica o nueva cuando esté disponible. La ausencia de propuesta no equivale a una denegación.</p>
        {labJobs.isLoading && <div className="ai-history-empty" role="status">Cargando trabajos del laboratorio…</div>}
        {labJobs.isError && <div className="notice notice-error" role="alert">No se pudo cargar el estado del laboratorio. <Button variant="outline" onClick={() => void labJobs.refetch()}>Reintentar</Button></div>}
        {!!labJobs.data?.length && <div className="ai-history-list">{labJobs.data.map((job) => canRun
          ? <LabJobCard key={job.id} job={job} canRun={canRun} onRetry={(id) => void retryLabAssessment(id)} retryPending={retryLabJob.isPending} focusedCaseId={guidedDemo?.jobId === job.id ? guidedDemo.caseId : undefined} />
          : <ExecutiveLabJobCard key={job.id} job={job} />)}</div>}
        {!labJobs.isLoading && !labJobs.isError && !labJobs.data?.length && <div className="ai-history-empty">Aún no hay trabajos del laboratorio en este espacio.</div>}
      </section>
      <section id="ai-evaluation-audit" className="panel ai-evaluation-history">
        <div className="panel-heading"><div><span className="panel-kicker">REGISTROS SINTÉTICOS</span><h2>Simulaciones recientes</h2></div><span className="ai-evaluation-state ai-state-pending"><i /> Alcance de laboratorio</span></div>
      {history.isLoading && <div className="ai-history-empty" role="status">Cargando historial de este espacio…</div>}
      {history.isError && <div className="notice notice-error" role="alert">No se pudo cargar el historial. <Button variant="outline" onClick={() => void history.refetch()}>Reintentar</Button></div>}
      {!history.isLoading && !history.isError && history.data?.length === 0 && <div className="ai-history-empty">Aún no hay simulaciones. Los resultados reales no se inventan ni se muestran aquí.</div>}
      {!!history.data?.length && <div className="ai-history-list">{history.data.map((run) => <EvaluationCard key={run.id} run={run} />)}</div>}
      </section>
    </section>
  </div>;
}
