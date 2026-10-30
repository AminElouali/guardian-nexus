import { useState } from 'react';
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

function LabJobCard({
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
  return <article className="ai-evaluation-run" data-testid="ai-lab-job">
    <div className="ai-evaluation-run-head">
      <div>
        <span className="ai-evaluation-run-label">LABORATORIO LOCAL · {job.profileId}</span>
        <h3>{labStatusLabels[job.status]}</h3>
      </div>
      <time dateTime={job.createdAt}><Clock3 size={13} /> {new Date(job.createdAt).toLocaleString('es-ES')}</time>
    </div>
    {evidence && <div className="ai-lab-result" data-testid="ai-lab-real-result">
      <div className="ai-lab-result-summary">
        <b>{evidence.positiveDetectorScores === 0 ? 'Sin puntuaciones positivas en esta prueba acotada' : `${evidence.positiveDetectorScores} puntuación${evidence.positiveDetectorScores === 1 ? '' : 'es'} positiva${evidence.positiveDetectorScores === 1 ? '' : 's'} del detector`}</b>
        <span>{evidence.probeRequests} solicitud · {evidence.generationsPerProbe} generación</span>
      </div>
      <p>{evidence.findingSummary} Esta ejecución cubre únicamente las pruebas indicadas; no garantiza la seguridad del agente.</p>
      <details>
        <summary>Procedencia y evidencia técnica</summary>
        <dl>
          <dt>Motor y versión</dt><dd>Garak {evidence.engineVersion} · licencia Apache-2.0</dd>
          <dt>Pruebas</dt><dd>{evidence.probeClasses.join(', ')}</dd>
          <dt>Puntuaciones positivas</dt><dd>{evidence.findings.length ? evidence.findings.map((finding) => `${finding.detector}: ${finding.positiveScores}`).join('; ') : 'Ninguna registrada en este informe'}</dd>
          <dt>Informe procesado</dt><dd>{evidence.reportRecordCount} registros · {evidence.reportBytes} bytes · {evidence.durationSeconds} s</dd>
          <dt>Red</dt><dd>Sin red externa; IPv4, IPv6 y DNS públicos bloqueados en el contenedor.</dd>
          <dt>Informe</dt><dd>SHA-256 {evidence.reportSha256}</dd>
          <dt>Datos</dt><dd>No se conservaron prompts ni respuestas; sin datos de clientes.</dd>
        </dl>
        <small>Garak es software de terceros; Guardian Nexus lo integra y conserva su atribución técnica. Esta ejecución fue en el agente local de laboratorio.</small>
      </details>
    </div>}
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

  async function requestLabAssessment() {
    setLabMessage('');
    setLabError('');
    try {
      await createLabJob.mutateAsync({
        workspaceId: workspace.id,
        data: { idempotencyKey: crypto.randomUUID() },
      });
      setLabMessage('Solicitud registrada. Se evaluará únicamente el agente local fijo del laboratorio.');
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
        <p>Una evaluación real, acotada y aislada del agente propio del laboratorio. El servicio para agentes y sistemas de clientes aún no está disponible.</p>
      </div>
      <span className="ai-evaluation-badge"><FlaskConical size={14} /> LABORATORIO INTERNO</span>
    </div>

    <div className="ai-evaluation-disclaimer" role="note" data-testid="ai-evaluation-disclaimer">
      <ShieldAlert size={18} />
      <div><b>Solo se evalúa un agente local autorizado.</b><p>El contenedor no tiene red externa y usa límites estrictos de recursos. No acepta objetivos arbitrarios, cuentas de clientes, credenciales ni modelos de pago. La disponibilidad de este laboratorio no implica que el servicio esté habilitado para clientes.</p></div>
    </div>

    {labMessage && <div className="notice notice-success ai-evaluation-feedback" role="status">{labMessage}</div>}
    {labError && <div className="notice notice-error ai-evaluation-feedback" role="alert">{labError}</div>}
    <section className="panel ai-evaluation-card ai-lab-card">
      <div className="panel-heading">
        <div><span className="panel-kicker">EVALUACIÓN REAL · AGENTE PROPIO</span><h2>Laboratorio aislado</h2></div>
        <span className={`ai-evaluation-state ${availability.data?.status === 'ready' ? '' : 'ai-state-pending'}`}><i />{availability.isLoading ? 'Comprobando' : availability.data?.status === 'ready' ? 'Disponible en desarrollo' : 'No disponible'}</span>
      </div>
      <p>El trabajo usa un perfil local fijo, un máximo de una solicitud de prueba y un intento de reejecución. El historial y la evidencia resumida quedan aislados en este espacio.</p>
      {availability.data?.status !== 'ready' && <div className="ai-lab-unavailable"><LockKeyhole size={15} />{availability.data?.reasonCode === 'development_only' ? 'Deshabilitado fuera del entorno de desarrollo.' : 'El worker local no está preparado. No se iniciará ni simulará una evaluación.'}</div>}
      <div className="ai-evaluation-actions">
        <Button onClick={() => void requestLabAssessment()} disabled={!canRun || availability.data?.status !== 'ready' || createLabJob.isPending} data-testid="button-run-ai-lab">
          {createLabJob.isPending ? <Activity className="spin" size={15} /> : <ShieldCheck size={15} />}
          {createLabJob.isPending ? 'Encolando…' : 'Solicitar evaluación local'}
        </Button>
        {!canRun && <small>Solo owner/admin puede iniciar o reintentar.</small>}
      </div>
      {labJobs.isLoading && <div className="ai-history-empty" role="status">Cargando trabajos del laboratorio…</div>}
      {labJobs.isError && <div className="notice notice-error" role="alert">No se pudo cargar el estado del laboratorio. <Button variant="outline" onClick={() => void labJobs.refetch()}>Reintentar</Button></div>}
      {!!labJobs.data?.length && <div className="ai-history-list">{labJobs.data.map((job) => <LabJobCard key={job.id} job={job} canRun={canRun} onRetry={(id) => void retryLabAssessment(id)} retryPending={retryLabJob.isPending} />)}</div>}
      <details className="ai-lab-provenance">
        <summary>Origen técnico y licencia</summary>
        <p>El motor de evaluación de código abierto utilizado internamente es NVIDIA Garak v0.17.1, licenciado bajo Apache-2.0. Guardian Nexus no reclama autoría del motor; su versión y procedencia se conservan en cada evidencia.</p>
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
