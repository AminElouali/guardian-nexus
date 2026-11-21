import React, { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import {
  getListWorkspaceAgentsQueryKey,
  useCreateWorkspaceAgent,
  useListWorkspaceAgents,
  useRevokeWorkspaceAgent,
  useRotateWorkspaceAgentCredential,
  type Workspace,
  type WorkspaceAgentCredentialResponse,
} from '@workspace/api-client-react';
import {
  buildMcpUrl,
  hasConnectedSince,
  type AgentPlatformId,
  type AgentServiceId,
} from '@/lib/agent-connection';
import { AgentConnectWizard, AgentList, type ConnectionCheck } from './AgentConnect';
import './AgentConnect.css';

const POLL_INTERVAL_MS = 3_000;
const POLL_TIMEOUT_MS = 120_000;

function canManageAgents(role: string): boolean {
  return role === 'owner' || role === 'admin';
}

function initialWizardOpen(): boolean {
  if (typeof window === 'undefined') return false;
  return new URLSearchParams(window.location.search).get('connect') === '1';
}

export default function AgentsPage({ workspace }: { workspace: Workspace }) {
  const cache = useQueryClient();
  const canManage = canManageAgents(workspace.role);
  const agentsQueryKey = getListWorkspaceAgentsQueryKey(workspace.id);
  const agentsQuery = useListWorkspaceAgents(workspace.id, {
    query: { queryKey: agentsQueryKey, refetchOnWindowFocus: true },
  });
  const createAgent = useCreateWorkspaceAgent();
  const rotateAgent = useRotateWorkspaceAgentCredential();
  const revokeAgent = useRevokeWorkspaceAgent();

  const [wizardOpen, setWizardOpen] = useState(() => canManage && initialWizardOpen());
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [displayName, setDisplayName] = useState('');
  const [service, setService] = useState<AgentServiceId | null>(null);
  const [platform, setPlatform] = useState<AgentPlatformId>('claude');
  // The credential lives only in this state while step 2 is visible.
  const [credential, setCredential] = useState<string | null>(null);
  const [pendingAgent, setPendingAgent] = useState<{ id: string; issuedAt: Date } | null>(null);
  const [connection, setConnection] = useState<ConnectionCheck>('idle');
  const [wizardError, setWizardError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyAgentId, setBusyAgentId] = useState<string | null>(null);
  const [confirmingRevokeId, setConfirmingRevokeId] = useState<string | null>(null);
  const [listMessage, setListMessage] = useState<string | null>(null);
  const pollStartedAt = useRef<number>(0);

  let mcpUrl = '';
  try {
    if (typeof window !== 'undefined') mcpUrl = buildMcpUrl(window.location.origin, workspace.id);
  } catch {
    mcpUrl = '';
  }

  function resetWizard() {
    setCredential(null);
    setPendingAgent(null);
    setStep(1);
    setDisplayName('');
    setService(null);
    setPlatform('claude');
    setConnection('idle');
    setWizardError(null);
    setBusy(false);
  }

  function closeWizard() {
    resetWizard();
    setWizardOpen(false);
  }

  function showCredential(result: WorkspaceAgentCredentialResponse) {
    setCredential(result.credential);
    setPendingAgent({ id: result.agent.id, issuedAt: new Date() });
    setConnection('idle');
    setStep(2);
    setWizardOpen(true);
  }

  async function handleCreate() {
    const name = displayName.trim();
    if (!name || service === null) return;
    setBusy(true);
    setWizardError(null);
    try {
      const result = await createAgent.mutateAsync({
        workspaceId: workspace.id,
        data: { displayName: name },
      });
      createAgent.reset();
      await cache.invalidateQueries({ queryKey: agentsQueryKey });
      showCredential(result);
    } catch {
      createAgent.reset();
      setWizardError('No se pudo crear el agente. Comprueba que eres administrador del espacio e inténtalo de nuevo.');
    } finally {
      setBusy(false);
    }
  }

  function handleContinueToTest() {
    // Drop the credential from memory as soon as the user leaves step 2.
    setCredential(null);
    setStep(3);
  }

  function handleTestConnection() {
    if (!pendingAgent) return;
    pollStartedAt.current = Date.now();
    setConnection('waiting');
  }

  useEffect(() => {
    if (connection !== 'waiting' || !pendingAgent) return undefined;
    let cancelled = false;
    const tick = async () => {
      try {
        const result = await agentsQuery.refetch();
        if (cancelled) return;
        const agent = result.data?.agents.find((item) => item.id === pendingAgent.id);
        if (agent && hasConnectedSince(agent, pendingAgent.issuedAt)) {
          setConnection('connected');
          return;
        }
        if (Date.now() - pollStartedAt.current >= POLL_TIMEOUT_MS) {
          setConnection('timeout');
        }
      } catch {
        if (!cancelled) setConnection('error');
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
    // agentsQuery.refetch is stable for this query key.
  }, [connection, pendingAgent]);

  async function handleRotate(agentId: string) {
    const agent = agentsQuery.data?.agents.find((item) => item.id === agentId);
    setBusyAgentId(agentId);
    setListMessage(null);
    try {
      const result = await rotateAgent.mutateAsync({ workspaceId: workspace.id, agentId });
      rotateAgent.reset();
      await cache.invalidateQueries({ queryKey: agentsQueryKey });
      resetWizard();
      setDisplayName(agent?.displayName ?? result.agent.displayName);
      showCredential(result);
    } catch {
      rotateAgent.reset();
      setListMessage('No se pudo cambiar la clave. Inténtalo de nuevo.');
    } finally {
      setBusyAgentId(null);
    }
  }

  async function handleConfirmRevoke(agentId: string) {
    setBusyAgentId(agentId);
    setListMessage(null);
    try {
      await revokeAgent.mutateAsync({ workspaceId: workspace.id, agentId });
      revokeAgent.reset();
      await cache.invalidateQueries({ queryKey: agentsQueryKey });
      setListMessage('Agente dado de baja. Ya no puede conectarse.');
      if (pendingAgent?.id === agentId) closeWizard();
    } catch {
      revokeAgent.reset();
      setListMessage('No se pudo dar de baja el agente. Inténtalo de nuevo.');
    } finally {
      setBusyAgentId(null);
      setConfirmingRevokeId(null);
    }
  }

  const agents = agentsQuery.data?.agents ?? [];

  return <div className="agents-page" data-testid="page-agents">
    <div className="page-heading reveal">
      <div>
        <div className="eyebrow">AGENTES</div>
        <h1>Mis agentes</h1>
        <p>Conecta tus agentes de IA para que sus acciones delicadas pasen por Guardian Nexus.</p>
      </div>
      {canManage && !wizardOpen && <div className="heading-action">
        <button type="button" className="agc-primary" onClick={() => { resetWizard(); setWizardOpen(true); }} data-testid="button-connect-agent">
          <Plus size={15} style={{ verticalAlign: '-2px', marginRight: 6 }} />Conectar agente
        </button>
      </div>}
    </div>

    {!canManage && <p className="agc-note">Solo los administradores del espacio pueden conectar o gestionar agentes.</p>}

    {wizardOpen && canManage && <AgentConnectWizard
      step={step}
      displayName={displayName}
      service={service}
      mcpUrl={mcpUrl}
      credential={step === 2 ? credential : null}
      platform={platform}
      busy={busy}
      error={wizardError}
      connection={connection}
      onDisplayNameChange={setDisplayName}
      onServiceChange={setService}
      onPlatformChange={setPlatform}
      onCreate={() => void handleCreate()}
      onContinueToTest={handleContinueToTest}
      onTestConnection={handleTestConnection}
      onClose={closeWizard}
    />}

    <div className="agents-section-heading">
      <div><span className="agc-kicker">AGENTES DEL ESPACIO</span><h2>Estado de tus agentes</h2></div>
    </div>
    {listMessage && <p className="agc-note" role="status">{listMessage}</p>}
    {agentsQuery.isLoading
      ? <p className="agc-note" role="status">Cargando agentes…</p>
      : agentsQuery.isError
        ? <p className="agc-error" role="alert">No se pudieron cargar los agentes. Recarga la página.</p>
        : <AgentList
            agents={agents}
            now={new Date()}
            canManage={canManage}
            busyAgentId={busyAgentId}
            confirmingRevokeId={confirmingRevokeId}
            onRotate={(agentId) => void handleRotate(agentId)}
            onAskRevoke={setConfirmingRevokeId}
            onConfirmRevoke={(agentId) => void handleConfirmRevoke(agentId)}
            onCancelRevoke={() => setConfirmingRevokeId(null)}
          />}
  </div>;
}
