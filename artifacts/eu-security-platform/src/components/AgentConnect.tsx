import React, { useState } from 'react';
import {
  Bot, Check, Cloud, Code2, Copy, Database, Globe2, LifeBuoy, Mail, Network,
  RefreshCw, Trash2, Wallet, type LucideIcon,
} from 'lucide-react';
import type { WorkspaceAgent } from '@workspace/api-client-react';
import {
  AGENT_PLATFORMS,
  AGENT_SERVICES,
  agentActivityState,
  buildConnectionSnippet,
  formatLastActivity,
  type AgentPlatformId,
  type AgentServiceId,
} from '@/lib/agent-connection';

const SERVICE_ICONS: Record<AgentServiceId, LucideIcon> = {
  email: Mail,
  support: LifeBuoy,
  finance: Wallet,
  data: Database,
  code: Code2,
  web: Globe2,
  cloud: Cloud,
  multiagent: Network,
};

export type ConnectionCheck = 'idle' | 'waiting' | 'connected' | 'timeout' | 'error';

export type AgentConnectWizardProps = {
  step: 1 | 2 | 3;
  displayName: string;
  service: AgentServiceId | null;
  mcpUrl: string;
  /** Only present while step 2 is on screen. Never stored elsewhere. */
  credential: string | null;
  platform: AgentPlatformId;
  busy: boolean;
  error: string | null;
  connection: ConnectionCheck;
  onDisplayNameChange: (value: string) => void;
  onServiceChange: (value: AgentServiceId) => void;
  onPlatformChange: (value: AgentPlatformId) => void;
  onCreate: () => void;
  onContinueToTest: () => void;
  onTestConnection: () => void;
  onClose: () => void;
};

function StepMarker({ current }: { current: 1 | 2 | 3 }) {
  const labels = ['Tu agente', 'Copia la configuración', 'Prueba la conexión'];
  return <ol className="agc-steps" aria-label="Pasos para conectar un agente">
    {labels.map((label, index) => {
      const number = index + 1;
      const state = number < current ? 'done' : number === current ? 'current' : 'next';
      return <li key={label} className={`agc-step is-${state}`} aria-current={state === 'current' ? 'step' : undefined}>
        <span className="agc-step-number">{state === 'done' ? <Check size={13} /> : number}</span>
        <span>{label}</span>
      </li>;
    })}
  </ol>;
}

export function AgentConnectWizard(props: AgentConnectWizardProps) {
  const [copied, setCopied] = useState(false);
  const { step } = props;
  const snippet = props.credential
    ? buildConnectionSnippet(props.platform, { url: props.mcpUrl, credential: props.credential })
    : '';

  async function copySnippet() {
    if (!snippet) return;
    try {
      await navigator.clipboard.writeText(snippet);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  return <section className="agc-wizard" aria-labelledby="agc-wizard-title" data-testid="agent-connect-wizard">
    <div className="agc-wizard-head">
      <div>
        <span className="agc-kicker">CONECTAR AGENTE</span>
        <h2 id="agc-wizard-title">Conecta tu agente en 3 pasos</h2>
      </div>
      <button type="button" className="agc-link-button" onClick={props.onClose} data-testid="button-agent-wizard-close">Cerrar</button>
    </div>
    <StepMarker current={step} />

    {step === 1 && <div className="agc-body" data-testid="agent-wizard-step-1">
      <label className="agc-field">
        <span>Nombre del agente</span>
        <input
          value={props.displayName}
          maxLength={120}
          placeholder={AGENT_SERVICES.find((s) => s.id === props.service)?.example ?? 'Bot de soporte'}
          onChange={(event) => props.onDisplayNameChange(event.target.value)}
          data-testid="input-agent-name"
        />
      </label>
      <fieldset className="agc-services">
        <legend>¿Qué hace este agente?</legend>
        <div className="agc-service-grid">
          {AGENT_SERVICES.map((service) => {
            const Icon = SERVICE_ICONS[service.id];
            const selected = props.service === service.id;
            return <button
              key={service.id}
              type="button"
              className={`agc-service${selected ? ' is-selected' : ''}`}
              aria-pressed={selected}
              onClick={() => props.onServiceChange(service.id)}
              data-testid={`button-agent-service-${service.id}`}
            >
              <Icon size={18} />
              <span>{service.label}</span>
            </button>;
          })}
        </div>
      </fieldset>
      <p className="agc-note">Por ahora el agente ve todas las herramientas protegidas del espacio. Las reglas de cada acción deciden si pasa, si necesita aprobación o si se bloquea.</p>
      {props.error && <p className="agc-error" role="alert">{props.error}</p>}
      <div className="agc-actions">
        <button
          type="button"
          className="agc-primary"
          disabled={props.busy || !props.displayName.trim() || props.service === null}
          onClick={props.onCreate}
          data-testid="button-agent-create"
        >{props.busy ? 'Creando…' : 'Crear agente'}</button>
      </div>
    </div>}

    {step === 2 && <div className="agc-body" data-testid="agent-wizard-step-2">
      <div className="agc-once" role="note">
        <strong>Copia esto ahora.</strong> La clave del agente solo se muestra esta vez. Si la pierdes, podrás cambiarla por una nueva desde "Mis agentes".
      </div>
      <div className="agc-tabs" role="tablist" aria-label="Plataforma del agente">
        {AGENT_PLATFORMS.map((platform) => <button
          key={platform.id}
          type="button"
          role="tab"
          aria-selected={props.platform === platform.id}
          className={`agc-tab${props.platform === platform.id ? ' is-selected' : ''}`}
          onClick={() => props.onPlatformChange(platform.id)}
          data-testid={`tab-agent-platform-${platform.id}`}
        >{platform.label}</button>)}
      </div>
      <div className="agc-snippet" role="tabpanel">
        <pre data-testid="text-agent-snippet">{snippet}</pre>
        <button type="button" className="agc-copy" onClick={() => void copySnippet()} disabled={!snippet} data-testid="button-agent-copy">
          {copied ? <><Check size={14} /> Copiado</> : <><Copy size={14} /> Copiar</>}
        </button>
      </div>
      <p className="agc-note">Dirección del servidor: <code>{props.mcpUrl}</code></p>
      <div className="agc-actions">
        <button type="button" className="agc-primary" onClick={props.onContinueToTest} data-testid="button-agent-continue">Ya lo he copiado</button>
      </div>
    </div>}

    {step === 3 && <div className="agc-body" data-testid="agent-wizard-step-3">
      <p>Arranca tu agente con la configuración que has copiado y pulsa el botón. Comprobaremos que se ha conectado a Guardian Nexus.</p>
      {props.connection === 'connected' && <p className="agc-result is-ok" role="status" data-testid="status-agent-connected">✅ Conectado. Tu agente ya pasa por Guardian Nexus.</p>}
      {props.connection === 'waiting' && <p className="agc-result" role="status" data-testid="status-agent-waiting">Esperando a que tu agente se conecte…</p>}
      {props.connection === 'timeout' && <p className="agc-result is-bad" role="alert" data-testid="status-agent-timeout">❌ No hemos visto actividad. Revisa que copiaste la clave completa y la dirección de este espacio, y que el agente está en marcha.</p>}
      {props.connection === 'error' && <p className="agc-result is-bad" role="alert" data-testid="status-agent-error">❌ No se pudo comprobar ahora. Inténtalo de nuevo en unos segundos.</p>}
      <div className="agc-actions">
        {props.connection === 'connected'
          ? <button type="button" className="agc-primary" onClick={props.onClose} data-testid="button-agent-done">Terminar</button>
          : <button type="button" className="agc-primary" disabled={props.connection === 'waiting'} onClick={props.onTestConnection} data-testid="button-agent-test">{props.connection === 'waiting' ? 'Comprobando…' : 'Probar conexión'}</button>}
      </div>
    </div>}
  </section>;
}

export type AgentListProps = {
  agents: WorkspaceAgent[];
  now: Date;
  canManage: boolean;
  busyAgentId: string | null;
  confirmingRevokeId: string | null;
  onRotate: (agentId: string) => void;
  onAskRevoke: (agentId: string) => void;
  onConfirmRevoke: (agentId: string) => void;
  onCancelRevoke: () => void;
};

export function AgentList(props: AgentListProps) {
  const visible = props.agents;
  if (visible.length === 0) {
    return <div className="agc-empty" data-testid="state-agents-empty">
      <Bot size={22} />
      <h3>Aún no hay agentes conectados</h3>
      <p>Conecta tu primer agente para que sus acciones delicadas pasen por Guardian Nexus.</p>
    </div>;
  }
  return <ul className="agc-list" data-testid="list-agents">
    {visible.map((agent) => {
      const state = agentActivityState(agent, props.now);
      const busy = props.busyAgentId === agent.id;
      const confirming = props.confirmingRevokeId === agent.id;
      return <li key={agent.id} className={`agc-row is-${state}`} data-testid={`row-agent-${agent.id}`}>
        <div className="agc-row-main">
          <span className={`agc-dot is-${state}`} aria-hidden="true" />
          <div>
            <b>{agent.displayName}</b>
            <span className="agc-row-meta">
              {state === 'revoked' ? 'Dado de baja' : state === 'active' ? 'Conectado' : 'Sin actividad reciente'}
              {' · '}
              {formatLastActivity(agent.lastUsedAt, props.now)}
            </span>
          </div>
        </div>
        {props.canManage && state !== 'revoked' && <div className="agc-row-actions">
          {confirming
            ? <>
                <span className="agc-confirm-text">¿Dar de baja este agente? Dejará de poder conectarse.</span>
                <button type="button" className="agc-danger" disabled={busy} onClick={() => props.onConfirmRevoke(agent.id)} data-testid={`button-agent-revoke-confirm-${agent.id}`}>Sí, dar de baja</button>
                <button type="button" className="agc-link-button" onClick={props.onCancelRevoke}>Cancelar</button>
              </>
            : <>
                <button type="button" className="agc-secondary" disabled={busy} onClick={() => props.onRotate(agent.id)} data-testid={`button-agent-rotate-${agent.id}`}><RefreshCw size={14} /> Cambiar clave</button>
                <button type="button" className="agc-secondary" disabled={busy} onClick={() => props.onAskRevoke(agent.id)} data-testid={`button-agent-revoke-${agent.id}`}><Trash2 size={14} /> Dar de baja</button>
              </>}
        </div>}
      </li>;
    })}
  </ul>;
}
