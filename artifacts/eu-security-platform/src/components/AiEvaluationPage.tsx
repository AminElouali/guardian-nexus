import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Activity, AlertTriangle, Check, Clock3, FlaskConical, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  getListWorkspaceAiEvaluationsQueryKey,
  useListWorkspaceAiEvaluations,
  useRunWorkspaceMockAiEvaluation,
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

export default function AiEvaluationPage({ workspace }: { workspace: Workspace }) {
  const cache = useQueryClient();
  const history = useListWorkspaceAiEvaluations(workspace.id);
  const runEvaluation = useRunWorkspaceMockAiEvaluation();
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const canRun = workspace.role === 'owner' || workspace.role === 'admin';

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
        <div className="eyebrow">SEGURIDAD DE IA · EXPERIMENTAL</div>
        <h1>Evaluación de agentes</h1>
        <p>Prueba determinista local con fixtures sintéticos. No evalúa un agente real ni mide cobertura de seguridad.</p>
      </div>
      <span className="ai-evaluation-badge"><FlaskConical size={14} /> SOLO SIMULACIÓN</span>
    </div>

    <div className="ai-evaluation-disclaimer" role="note" data-testid="ai-evaluation-disclaimer">
      <ShieldAlert size={18} />
      <div><b>Esto no es una ejecución de NVIDIA garak.</b><p>Garak no está instalado y aún no existe un worker aislado con salida de red bloqueada. La prueba disponible usa tres fixtures internos fijos; no envía prompts a modelos ni a endpoints públicos.</p></div>
    </div>

    {message && <div className="notice notice-success ai-evaluation-feedback" role="status">{message}</div>}
    {error && <div className="notice notice-error ai-evaluation-feedback" role="alert">{error}</div>}

    <div className="ai-evaluation-grid">
      <section className="panel ai-evaluation-card">
        <div className="panel-heading">
          <div><span className="panel-kicker">OBJETIVO INTERNO</span><h2>Agente de prueba local</h2></div>
          <span className="ai-evaluation-state"><i /> Mock disponible</span>
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
      <div className="panel-heading"><div><span className="panel-kicker">AUDITORÍA DEL ESPACIO</span><h2>Simulaciones recientes</h2></div><span className="ai-evaluation-state"><i /> Sin hallazgos reales</span></div>
      {history.isLoading && <div className="ai-history-empty" role="status">Cargando historial de este espacio…</div>}
      {history.isError && <div className="notice notice-error" role="alert">No se pudo cargar el historial. <Button variant="outline" onClick={() => void history.refetch()}>Reintentar</Button></div>}
      {!history.isLoading && !history.isError && history.data?.length === 0 && <div className="ai-history-empty">Aún no hay simulaciones. Los resultados reales no se inventan ni se muestran aquí.</div>}
      {!!history.data?.length && <div className="ai-history-list">{history.data.map((run) => <EvaluationCard key={run.id} run={run} />)}</div>}
    </section>
  </div>;
}
