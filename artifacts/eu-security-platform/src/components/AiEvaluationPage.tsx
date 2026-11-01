import React, { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Activity, AlertTriangle, Check, Clock3, FlaskConical, LockKeyhole, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  getListWorkspaceAiAssessmentLabJobsQueryKey,
  getListWorkspaceAiEvaluationsQueryKey,
  useCreateWorkspaceAiAssessmentLabJob,
  useGetWorkspaceAiAssessmentLabAvailability,
  useListWorkspaceAiAssessmentLabJobs,
  useListWorkspaceAiEvaluations,
  useRetryWorkspaceAiAssessmentLabJob,
  useRunWorkspaceMockAiEvaluation,
  type AiAssessmentLabJob,
  type AiAssessmentLabJobRequestProfileId,
  type AiEvaluationRun,
  type Workspace,
} from '@workspace/api-client-react';
import { Button } from '@/components/ui/button';

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
type LocalLlmEvidence = Extract<
  NonNullable<AiAssessmentLabJob['result']>,
  { profileId: 'guardian-local-llm-qwen3-0.6b-v1' }
>;
type NativeToolSuiteEvidence = Extract<
  NonNullable<AiAssessmentLabJob['result']>,
  { profileId: 'guardian-local-llm-native-tools-v1' }
>;
type AutonomousToolSelectionEvidence = Extract<
  NonNullable<AiAssessmentLabJob['result']>,
  { profileId: 'guardian-local-llm-autonomous-tools-v1' }
>;

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

const toolLabels: Record<string, string> = {
  consult_synthetic_invoice: 'Consultar factura sintética',
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
  authorized_simulated_email_draft: 'Preparación autorizada de correo simulado',
  authorized_synthetic_bank_request: 'Solicitud ficticia de cambio bancario',
};

function NativeToolSuiteResult({
  evidence,
}: {
  evidence: NativeToolSuiteEvidence | AutonomousToolSelectionEvidence;
}) {
  const suite = evidence.nativeToolSuite;
  const autonomous =
    evidence.profileId === 'guardian-local-llm-autonomous-tools-v1';
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
        ? <>Cada una de las seis tareas usó <code>tool_choice=auto</code>; no se forzó la función. Solo se cuentan objetos nativos <code>message.tool_calls</code>, no JSON del texto. Las tres herramientas son ficticias y no producen efectos externos.</>
        : <>Qwen3 local devolvió objetos <code>message.tool_calls</code> usando el template GGUF; no se interpretó JSON del texto como tool call. Las llamadas de correo y cambio bancario solo generaron resultados ficticios en memoria.</>}
    </p>
    <div className="guardian-verification-stats">
      <span><b>{suite.sampleCount}</b> casos sintéticos</span>
      <span>{autonomous
        ? <>Particiones internas <b>{suite.splitSampleCounts.calibration}+{suite.splitSampleCounts.holdout}</b></>
        : <><b>{suite.splitSampleCounts.calibration}</b> calibración · <b>{suite.splitSampleCounts.holdout}</b> holdout</>}</span>
      <span><b>{suite.languageCounts.en}/{suite.languageCounts.es}</b> casos EN/ES</span>
      <span><b>{suite.toolSummary.nativeCallsObserved}</b> llamadas nativas observadas</span>
        <span><b>{suite.taskSuccess.numerator}/{suite.taskSuccess.denominator}</b> operaciones simuladas verificadas</span>
      <span><b>{suite.metrics.find((metric) => metric.split === 'all')?.inconclusiveCount ?? 0}</b> casos inconclusos</span>
    </div>
    <p className="guardian-verification-disclaimer">
      {autonomous
        ? 'Los seis ejemplos son tareas benignas autorizadas: no constituyen una prueba de detección de ataques ni una medida general de seguridad. «Resuelta» significa que la herramienta ficticia devolvió un resultado autorizado; no se evalúa una respuesta conversacional posterior. Una llamada ausente o incorrecta se cuenta como no resuelta; nunca se cambia a selección forzada.'
        : 'En tareas benignas autorizadas, el arnés seleccionó la función específica para comprobar argumentos y autorización; eso no mide selección autónoma. Ataques y textos citados usaron selección automática. Las matrices comparan tipo de escenario con eventos de herramienta observados; un falso negativo significa que no se observó ese evento en un caso de ataque, no que un detector de ataques haya fallado.'}
    </p>
    <details className="guardian-verification-details">
      <summary>Métricas, trazas y procedencia</summary>
      {!autonomous && <div className="guardian-verification-table-wrap">
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
      </div>}
      {autonomous && <p className="guardian-verification-note">
        Sin casos de ataque: TP/FP/TN/FN no se presentan como métricas de detección. La prueba informa únicamente selección de herramientas, autorización y resolución de estas seis tareas.
      </p>}
      <div className="guardian-verification-table-wrap">
        <table className="guardian-verification-table">
          <thead><tr>
            <th scope="col">Caso</th>
            <th scope="col">Grupo</th>
            <th scope="col">Herramientas propuestas</th>
            <th scope="col">Argumentos · permiso</th>
            <th scope="col">Intento no permitido</th>
            <th scope="col">Ejecución ficticia</th>
            <th scope="col">Tarea</th>
          </tr></thead>
          <tbody>
            {suite.caseEvidence.map((item) => (
              <tr key={item.caseId}>
                <th scope="row">{item.caseId}</th>
                <td>{autonomous
                  ? `${item.split === 'calibration' ? 'partición A' : 'partición B'} · ${item.language.toUpperCase()} · ${autonomousTaskLabels[item.category] ?? item.label}`
                  : `${item.split} · ${item.language.toUpperCase()} · ${item.label}`}</td>
                <td>{item.proposedTools.length ? item.proposedTools.map((tool) => toolLabels[tool] ?? tool).join(', ') : 'Ninguna'}</td>
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
        {autonomous && <><dt>Selección por tarea</dt><dd>tool_choice=auto · una llamada · máximo 128 tokens.</dd><dt>Suite forzada anterior</dt><dd><code>{suite.previousForcedSuiteEvidenceSha256}</code> · referencia separada, no es evidencia de autonomía.</dd></>}
        <dt>Red</dt><dd>IPv4 {networkStatusLabel(evidence.network.publicIpv4)}, IPv6 {networkStatusLabel(evidence.network.publicIpv6)}, DNS {networkStatusLabel(evidence.network.publicDns)}.</dd>
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
}: {
  job: AiAssessmentLabJob;
  canRun: boolean;
  onRetry: (jobId: string) => void;
  retryPending: boolean;
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
  return <article className="ai-evaluation-run" data-testid="ai-lab-job">
    <div className="ai-evaluation-run-head">
      <div>
        <span className="ai-evaluation-run-label">
          {job.profileId === 'guardian-local-llm-autonomous-tools-v1'
            ? 'LLM REAL · SELECCIÓN AUTÓNOMA'
            : job.profileId === 'guardian-local-llm-native-tools-v1'
            ? 'LLM REAL · TOOL CALLS NATIVAS'
            : job.profileId === 'guardian-local-llm-qwen3-0.6b-v1'
            ? 'INFERENCIA REAL · LLM LOCAL'
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
    {nativeToolEvidence && <NativeToolSuiteResult evidence={nativeToolEvidence} />}
    {job.status === 'failed' && <p className="ai-lab-error">No se completó la evaluación. Código: {job.errorCode ?? 'worker_failed'}. No se guardaron salidas del agente.</p>}
    {canRun && job.status === 'failed' && job.attempts < 2 && <Button variant="outline" onClick={() => onRetry(job.id)} disabled={retryPending} data-testid="button-retry-ai-lab">
      {retryPending ? 'Reintentando…' : 'Reintentar una vez'}
    </Button>}
  </article>;
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
  const createLabJob = useCreateWorkspaceAiAssessmentLabJob();
  const retryLabJob = useRetryWorkspaceAiAssessmentLabJob();
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [labMessage, setLabMessage] = useState('');
  const [labError, setLabError] = useState('');
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

  async function requestLabAssessment(profileId: AiAssessmentLabJobRequestProfileId) {
    setLabMessage('');
    setLabError('');
    try {
      await createLabJob.mutateAsync({
        workspaceId: workspace.id,
        data: { idempotencyKey: crypto.randomUUID(), profileId },
      });
      setLabMessage('Solicitud registrada. Se ejecutará únicamente el perfil local seleccionado.');
      await cache.invalidateQueries({
        queryKey: getListWorkspaceAiAssessmentLabJobsQueryKey(workspace.id),
      });
    } catch {
      setLabError('No se pudo iniciar el laboratorio. No se ha creado un resultado simulado.');
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
        <p>El perfil de pruebas ejecuta verificaciones deterministas con fixtures. Los perfiles de LLM ejecutan inferencia local real: una tarea sintética acotada y una suite experimental de llamadas nativas a herramientas. Ninguno está habilitado como servicio para clientes.</p>
      </div>
      <span className="ai-evaluation-badge"><FlaskConical size={14} /> LABORATORIO INTERNO</span>
    </div>

    <div className="ai-evaluation-disclaimer" role="note" data-testid="ai-evaluation-disclaimer">
      <ShieldAlert size={18} />
      <div><b>Solo se ejecutan perfiles locales fijos.</b><p>Los contenedores usan red deshabilitada y límites de recursos. No aceptan objetivos arbitrarios, cuentas de clientes, credenciales ni modelos de pago. IPv6 puede figurar como no verificado si el kernel no ofrece ese protocolo. La disponibilidad en desarrollo no habilita el servicio para clientes.</p></div>
    </div>

    {labMessage && <div className="notice notice-success ai-evaluation-feedback" role="status">{labMessage}</div>}
    {labError && <div className="notice notice-error ai-evaluation-feedback" role="alert">{labError}</div>}
    <section className="panel ai-evaluation-card ai-lab-card">
      <div className="panel-heading">
        <div><span className="panel-kicker">EJECUCIONES LOCALES · DESARROLLO</span><h2>Laboratorio aislado</h2></div>
        <span className={`ai-evaluation-state ${availability.data?.status === 'ready' ? '' : 'ai-state-pending'}`}><i />{availability.isLoading ? 'Comprobando' : availability.data?.status === 'ready' ? 'Disponible en desarrollo' : 'No disponible'}</span>
      </div>
       <p>Garak/GVE conserva el flujo local existente con fixtures. Qwen ejecuta una tarea sintética, la suite nativa anterior conserva sus 12 casos y el nuevo perfil prueba seis tareas benignas con selección automática de herramienta, sin forzar funciones. Los trabajos usan 1 CPU, 1.536 MiB, concurrencia global 1 y red deshabilitada. Ningún perfil está habilitado para clientes.</p>
      {availability.data?.status !== 'ready' && <div className="ai-lab-unavailable"><LockKeyhole size={15} />{availability.data?.reasonCode === 'development_only' ? 'Deshabilitado fuera del entorno de desarrollo.' : 'El worker local no está preparado. No se iniciará ni simulará una evaluación.'}</div>}
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
        {canRun && !qwenAvailable && <small>Qwen local no disponible: {availability.data?.profiles.find((profile) => profile.profileId === 'guardian-local-llm-qwen3-0.6b-v1')?.reasonCode ?? 'worker_unavailable'}.</small>}
        {canRun && !nativeToolsAvailable && <small>Suite de tool calls nativas no disponible: {availability.data?.profiles.find((profile) => profile.profileId === 'guardian-local-llm-native-tools-v1')?.reasonCode ?? 'worker_unavailable'}.</small>}
        {canRun && !autonomousToolsAvailable && <small>Selección autónoma no disponible: {availability.data?.profiles.find((profile) => profile.profileId === 'guardian-local-llm-autonomous-tools-v1')?.reasonCode ?? 'worker_unavailable'}.</small>}
      </div>
      {labJobs.isLoading && <div className="ai-history-empty" role="status">Cargando trabajos del laboratorio…</div>}
      {labJobs.isError && <div className="notice notice-error" role="alert">No se pudo cargar el estado del laboratorio. <Button variant="outline" onClick={() => void labJobs.refetch()}>Reintentar</Button></div>}
      {!!labJobs.data?.length && <div className="ai-history-list">{labJobs.data.map((job) => <LabJobCard key={job.id} job={job} canRun={canRun} onRetry={(id) => void retryLabAssessment(id)} retryPending={retryLabJob.isPending} />)}</div>}
      <details className="ai-lab-provenance">
        <summary>Origen técnico y licencia</summary>
        <p>Garak v0.17.1 conserva su atribución de terceros y licencia Apache-2.0. La inferencia local utiliza Qwen3-0.6B-GGUF Q8_0 (Apache-2.0) mediante llama-cpp-python 0.3.36 (MIT). Sus versiones, hashes y procedencia se registran por separado en la evidencia.</p>
      </details>
    </section>

    {message && <div className="notice notice-success ai-evaluation-feedback" role="status">{message}</div>}
    {error && <div className="notice notice-error ai-evaluation-feedback" role="alert">{error}</div>}

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

    <section className="panel ai-evaluation-history">
        <div className="panel-heading"><div><span className="panel-kicker">DATOS SINTÉTICOS</span><h2>Simulaciones recientes</h2></div><span className="ai-evaluation-state ai-state-pending"><i /> Separadas de evaluaciones reales</span></div>
      {history.isLoading && <div className="ai-history-empty" role="status">Cargando historial de este espacio…</div>}
      {history.isError && <div className="notice notice-error" role="alert">No se pudo cargar el historial. <Button variant="outline" onClick={() => void history.refetch()}>Reintentar</Button></div>}
      {!history.isLoading && !history.isError && history.data?.length === 0 && <div className="ai-history-empty">Aún no hay simulaciones. Los resultados reales no se inventan ni se muestran aquí.</div>}
      {!!history.data?.length && <div className="ai-history-list">{history.data.map((run) => <EvaluationCard key={run.id} run={run} />)}</div>}
    </section>
  </div>;
}
