import { useState, type FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowUpRight, Check, CircleAlert, Globe2, KeyRound, LoaderCircle, ShieldCheck } from 'lucide-react';
import {
  getGetWorkspaceIntegrationsQueryKey,
  useGetWorkspaceIntegrations,
  usePrepareAwsIntegration,
  usePrepareMicrosoftIntegration,
  useRevokeWorkspaceIntegration,
  type Workspace,
  type WorkspaceIntegration,
} from '@workspace/api-client-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const statusCopy: Record<WorkspaceIntegration['status'], string> = {
  awaiting_app_registration: 'Pendiente de registrar la aplicación',
  ready_for_admin_consent: 'Listo para consentimiento; aún no solicitado',
  awaiting_runtime_identity: 'Pendiente de identidad AWS de runtime',
  ready_for_role_trust: 'Listo para configurar la confianza del rol',
  connected: 'Conectado',
  revoked: 'Preparación cancelada localmente',
};

function ConnectorStatus({ status }: { status: WorkspaceIntegration['status'] }) {
  const isActive = status === 'connected';
  return <span className={`connector-status ${isActive ? 'connector-status-active' : ''}`}>
    <i /> {statusCopy[status]}
  </span>;
}

export default function IntegrationsPage({ workspace }: { workspace: Workspace }) {
  const queryClient = useQueryClient();
  const integrations = useGetWorkspaceIntegrations(workspace.id);
  const prepareMicrosoft = usePrepareMicrosoftIntegration();
  const prepareAws = usePrepareAwsIntegration();
  const revokeIntegration = useRevokeWorkspaceIntegration();
  const [tenantId, setTenantId] = useState('');
  const [accountId, setAccountId] = useState('');
  const [feedback, setFeedback] = useState('');
  const [error, setError] = useState('');
  const isOwner = workspace.role === 'owner';
  const loading = integrations.isLoading;
  const invalidate = () => queryClient.invalidateQueries({
    queryKey: getGetWorkspaceIntegrationsQueryKey(workspace.id),
  });

  async function submitMicrosoft(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setFeedback('');
    try {
      await prepareMicrosoft.mutateAsync({
        workspaceId: workspace.id,
        data: { tenantId: tenantId.trim() },
      });
      setTenantId('');
      setFeedback('La preparación de Microsoft se guardó. No se ha iniciado consentimiento ni conexión.');
      await invalidate();
    } catch {
      setError('No se pudo guardar la preparación. Comprueba el tenant ID y tu rol de propietario.');
    }
  }

  async function submitAws(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setFeedback('');
    try {
      await prepareAws.mutateAsync({
        workspaceId: workspace.id,
        data: { accountId: accountId.trim() },
      });
      setAccountId('');
      setFeedback('ExternalId generado para preparar la confianza del rol. No se ha llamado a AWS STS.');
      await invalidate();
    } catch {
      setError('No se pudo guardar la preparación. Comprueba el ID de cuenta y tu rol de propietario.');
    }
  }

  async function cancelPreparation(integration: WorkspaceIntegration) {
    if (integration.status === 'connected') return;
    setError('');
    setFeedback('');
    try {
      await revokeIntegration.mutateAsync({
        workspaceId: workspace.id,
        integrationId: integration.id,
      });
      setFeedback('Preparación local cancelada. Si se concedió acceso fuera de Guardian Nexus, revócalo también en el proveedor.');
      await invalidate();
    } catch {
      setError('No se pudo cancelar la preparación local.');
    }
  }

  if (loading) {
    return <div className="loading-state" role="status"><LoaderCircle className="spin" size={20} /> Cargando conexiones</div>;
  }
  if (integrations.isError || !integrations.data) {
    return <div className="notice notice-error" role="alert">
      No se ha podido cargar el estado de las integraciones.
      <Button variant="outline" onClick={() => integrations.refetch()}>Reintentar</Button>
    </div>;
  }

  const { readiness, connections } = integrations.data;
  return <div className="connector-page">
    <div className="page-heading">
      <div>
        <div className="eyebrow">CONECTORES · PREPARACIÓN CONTROLADA</div>
        <h1>Integraciones</h1>
        <p>Prepara conexiones autorizadas de solo lectura. En este entorno no se ha conectado ningún proveedor ni se han solicitado consentimientos.</p>
      </div>
      <span className="roadmap-status"><i /> SIN CONEXIONES ACTIVAS</span>
    </div>

    <div className="connector-disclaimer" role="note">
      <ShieldCheck size={18} />
      <div><b>Acceso bajo control de tu organización</b><p>No introduzcas contraseñas, tokens ni claves permanentes. El alta solo guarda identificadores y estado de preparación; cualquier consentimiento o confianza externa requiere una acción explícita del administrador.</p></div>
    </div>

    {(feedback || error) && <div className={`connector-feedback ${error ? 'connector-feedback-error' : ''}`} role={error ? 'alert' : 'status'}>
      {error ? <CircleAlert size={16} /> : <Check size={16} />}{error || feedback}
    </div>}

    <div className="connector-grid">
      <section className="connector-card">
        <div className="connector-card-head"><div className="connector-symbol"><Globe2 size={19} /></div><div><span className="panel-kicker">MICROSOFT 365 · ENTRA ID</span><h2>Microsoft Graph</h2></div></div>
        <p className="connector-card-copy">La preparación propone únicamente <code>Organization.Read.All</code> para consultar metadatos de la organización. No habilita una evaluación general de seguridad.</p>
        <div className="connector-prerequisite"><span>Aplicación de Guardian Nexus</span><b>{readiness.microsoftAppRegistrationConfigured ? 'Configurada, no verificada' : 'Pendiente'}</b></div>
        <div className="connector-prerequisite"><span>Consentimiento del administrador</span><b>No solicitado</b></div>
        <form className="connector-form" onSubmit={submitMicrosoft}>
          <label htmlFor="microsoft-tenant-id">ID del tenant de Microsoft Entra</label>
          <Input id="microsoft-tenant-id" value={tenantId} onChange={event => setTenantId(event.target.value)} placeholder="00000000-0000-0000-0000-000000000000" pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}" required disabled={!isOwner || prepareMicrosoft.isPending} data-testid="input-microsoft-tenant" />
          <Button type="submit" disabled={!isOwner || prepareMicrosoft.isPending} data-testid="button-prepare-microsoft">
            {prepareMicrosoft.isPending ? 'Guardando…' : 'Guardar preparación'}
          </Button>
        </form>
        {!isOwner && <p className="connector-role-note">Solo el propietario del espacio puede preparar conexiones.</p>}
      </section>

      <section className="connector-card">
        <div className="connector-card-head"><div className="connector-symbol connector-symbol-aws"><KeyRound size={19} /></div><div><span className="panel-kicker">AWS · IAM CROSS-ACCOUNT</span><h2>Cuenta de AWS</h2></div></div>
        <p className="connector-card-copy">Se generará un ExternalId único por espacio y cuenta. Solo podrá usarse en una trust policy después de disponer de una identidad de runtime verificada.</p>
        <div className="connector-prerequisite"><span>Identidad AWS de runtime</span><b>{readiness.awsRuntimePrincipalConfigured ? 'Declarada, no verificada' : 'No configurada'}</b></div>
        <div className="connector-prerequisite"><span>STS AssumeRole</span><b>No ejecutado</b></div>
        <form className="connector-form" onSubmit={submitAws}>
          <label htmlFor="aws-account-id">ID de cuenta AWS de 12 dígitos</label>
          <Input id="aws-account-id" value={accountId} onChange={event => setAccountId(event.target.value)} placeholder="123456789012" inputMode="numeric" pattern="[0-9]{12}" maxLength={12} required disabled={!isOwner || prepareAws.isPending} data-testid="input-aws-account" />
          <Button type="submit" disabled={!isOwner || prepareAws.isPending} data-testid="button-prepare-aws">
            {prepareAws.isPending ? 'Generando…' : 'Generar ExternalId'}
          </Button>
        </form>
        {!isOwner && <p className="connector-role-note">Solo el propietario del espacio puede preparar conexiones.</p>}
      </section>
    </div>

    <section className="connector-records">
      <div className="connector-records-heading"><div><span className="panel-kicker">ESTADO POR ESPACIO</span><h2>Preparaciones registradas</h2></div><span>{connections.length} {connections.length === 1 ? 'registro' : 'registros'}</span></div>
      {connections.length === 0
        ? <div className="connector-empty">No hay preparaciones. No se han hecho llamadas a Microsoft Graph ni a AWS.</div>
        : <div className="connector-record-list">{connections.map(connection => <article className="connector-record" key={connection.id}>
          <div className="connector-record-main"><div className="connector-record-title"><b>{connection.provider === 'microsoft' ? 'Microsoft Entra' : 'AWS'} · {connection.externalAccountId}</b><ConnectorStatus status={connection.status} /></div>
            <small>{connection.provider === 'microsoft' ? `Permiso propuesto: ${connection.requestedPermissions.join(', ')}` : 'STS no ejecutado; no hay credenciales permanentes almacenadas.'}</small>
            {connection.provider === 'aws' && connection.externalId && isOwner && <code className="connector-external-id">ExternalId: {connection.externalId}</code>}
          </div>
          {isOwner && connection.status !== 'connected' && connection.status !== 'revoked' && <Button variant="outline" onClick={() => cancelPreparation(connection)} disabled={revokeIntegration.isPending} data-testid={`button-revoke-${connection.provider}-${connection.id}`}>Cancelar preparación</Button>}
          {connection.status === 'connected' && <span className="connector-revocation-note"><ArrowUpRight size={14} /> Revoca el acceso directamente en el proveedor</span>}
        </article>)}</div>}
    </section>

    <div className="connector-footnote">
      <b>Limitaciones de esta fase</b>
      <p>El consentimiento OAuth de Microsoft, la validación de la aplicación, la trust policy y la llamada AWS STS permanecen pendientes. “Configurada” solo indica que hay valores de configuración presentes; no verifica credenciales, región, residencia de datos ni acceso real. La cancelación aquí es local y no revoca permisos en el proveedor.</p>
    </div>
  </div>;
}
