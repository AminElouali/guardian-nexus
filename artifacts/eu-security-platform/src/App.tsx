import { useEffect, useRef, useState, type ButtonHTMLAttributes, type FormEvent, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import { ClerkProvider, SignIn, SignUp, useAuth, useClerk, useUser } from '@clerk/react';
import { publishableKeyFromHost } from '@clerk/react/internal';
import { esES } from '@clerk/localizations';
import {
  Activity, ArrowRight, ArrowUpRight, Box, Check, CircleHelp, Cloud, Copy,
  Command, Database, ExternalLink, Fingerprint, FlaskConical, Gauge, Globe2, HardDrive, Layers3, LockKeyhole,
  LogOut, Menu, Plus, Radio, RefreshCw, Shield, ShieldCheck, ShieldEllipsis, SlidersHorizontal,
  Sparkles, Trash2, Users, X,
} from 'lucide-react';
import {
  getGetWorkspaceDashboardQueryKey, getListPlansQueryKey, getListWorkspacesQueryKey,
  getListWorkspaceAssetsQueryKey, getListWorkspaceIntegrationsQueryKey, getListWorkspaceMembersQueryKey, useBeginMicrosoftAuthorization, useConfigureAwsIntegration, useCreateWorkspace,
  useCreateWorkspaceAsset, useDeleteWorkspaceAsset, useGetWorkspaceDashboard, useHealthCheck,
  useListPlans, useListWorkspaceAssets, useListWorkspaceIntegrations, useListWorkspaceMembers, useListWorkspaces,
  useRevokeWorkspaceIntegration, useUpdateWorkspaceMember, useVerifyAwsIntegration,
} from '@workspace/api-client-react';
import type { Asset, AssetInput, AwsIntegrationSetup, IntegrationConnection, Member, Plan, Workspace } from '@workspace/api-client-react';
import { Route, Switch, Link, useLocation, Router as WouterRouter } from 'wouter';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import IntegrationReadinessPage from '@/components/IntegrationsPage';
import AiEvaluationPage from '@/components/AiEvaluationPage';
import NotFound from '@/pages/not-found';

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 20_000, retry: 1, refetchOnWindowFocus: false } },
});

const basePath = import.meta.env.BASE_URL.replace(/\/$/, '');
const clerkPubKey = publishableKeyFromHost(
  window.location.hostname,
  import.meta.env.VITE_CLERK_PUBLISHABLE_KEY,
);
const clerkProxyUrl = import.meta.env.VITE_CLERK_PROXY_URL;
const assetTypes = ['cloud', 'endpoint', 'application', 'identity', 'network', 'other'] as const;
const environments = ['production', 'staging', 'development', 'unknown'] as const;
const criticalities = ['critical', 'high', 'medium', 'low'] as const;

function stripBase(path: string) {
  return basePath && path.startsWith(basePath) ? path.slice(basePath.length) || '/' : path;
}

function IdentityCacheBoundary({ children }: { children: ReactNode }) {
  const { user, isLoaded } = useUser();
  const cache = useQueryClient();
  const previousIdentity = useRef<string | null | undefined>(undefined);
  useEffect(() => {
    if (!isLoaded) return;
    const identity = user?.id ?? null;
    if (previousIdentity.current !== undefined && previousIdentity.current !== identity) cache.clear();
    previousIdentity.current = identity;
  }, [cache, isLoaded, user?.id]);
  return <>{children}</>;
}

function Brand({ inverse = false }: { inverse?: boolean }) {
  return <Link href="/" className={`brand ${inverse ? 'brand-inverse' : ''}`} data-testid="link-brand">
    <span className="brand-mark"><ShieldCheck size={19} strokeWidth={2.3} /></span>
    <span className="brand-name">Guardian <span>Nexus</span></span>
  </Link>;
}

function Button({ children, variant = 'primary', className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'quiet' | 'danger' }) {
  return <button {...props} className={`button button-${variant} ${className}`}>
    {children}
  </button>;
}

function LoadingState({ label = 'Cargando datos del espacio de trabajo' }: { label?: string }) {
  return <div className="loading-state" role="status" data-testid="status-loading">
    <div className="skeleton skeleton-title" />
    <div className="skeleton-row"><div className="skeleton" /><div className="skeleton" /><div className="skeleton" /></div>
    <div className="skeleton skeleton-wide" /><span className="sr-only">{label}</span>
  </div>;
}

function QueryError({ onRetry, detail = 'No hemos podido recuperar los datos de este espacio de trabajo.' }: { onRetry: () => void; detail?: string }) {
  return <div className="notice notice-error" role="alert" data-testid="status-query-error">
    <div className="notice-icon"><RefreshCw size={17} /></div>
    <div><strong>No se ha podido cargar esta vista</strong><p>{detail}</p></div>
    <Button variant="secondary" onClick={onRetry} data-testid="button-retry">Reintentar</Button>
  </div>;
}

function EmptyState({ icon: Icon = Layers3, title, copy, action }: { icon?: typeof Layers3; title: string; copy: string; action?: ReactNode }) {
  return <div className="empty-state" data-testid="state-empty">
    <div className="empty-symbol"><Icon size={23} /></div>
    <h3>{title}</h3><p>{copy}</p>{action}
  </div>;
}

function PublicHome() {
  const { isSignedIn, isLoaded } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const startHref = isSignedIn ? '/dashboard' : '/sign-up';
  return <main className="public-page">
    <header className="public-nav wrap">
      <Brand />
      <nav id="public-navigation" className={`public-links ${mobileOpen ? 'public-links-open' : ''}`} aria-label="Navegación principal">
        <a href="#alcance" onClick={() => setMobileOpen(false)} data-testid="link-capacidades">Capacidades</a><a href="#disponible" onClick={() => setMobileOpen(false)} data-testid="link-disponible">Disponible hoy</a><a href="#preparacion" onClick={() => setMobileOpen(false)} data-testid="link-preparacion">Preparación europea</a>
      </nav>
      <div className="public-actions">
        {isLoaded && isSignedIn
          ? <Link href="/dashboard" className="button button-primary" data-testid="link-open-workspace">Abrir espacio <ArrowRight size={16} /></Link>
          : <><Link href="/sign-in" className="nav-signin" data-testid="link-sign-in">Iniciar sesión</Link><Link href="/sign-up" className="button button-primary" data-testid="link-sign-up">Crear espacio <ArrowRight size={16} /></Link></>}
        <button type="button" className="mobile-menu" aria-label={mobileOpen ? 'Cerrar navegación' : 'Mostrar navegación'} aria-expanded={mobileOpen} aria-controls="public-navigation" onClick={() => setMobileOpen(!mobileOpen)} data-testid="button-mobile-menu">{mobileOpen ? <X /> : <Menu />}</button>
      </div>
    </header>
    <section className="hero wrap">
      <div className="hero-copy reveal">
        <div className="eyebrow"><span className="eyebrow-dot" /> Guardian Nexus · Seguridad de sistemas de IA</div>
        <h1>Ciberseguridad<br />para la era de <em>la IA.</em></h1>
        <p className="hero-lede">Verificación de acciones propuestas por agentes de IA: contexto, permisos y límites antes de que una acción pueda avanzar.</p>
        <div className="hero-ctas">
          <Link href={startHref} className="button button-primary button-large" data-testid="link-hero-start">{isSignedIn ? 'Abrir mi espacio' : 'Crear espacio de trabajo'} <ArrowRight size={17} /></Link>
          <span className="hero-note"><LockKeyhole size={14} /> Preparación, no certificación</span>
        </div>
        <div className="hero-meta"><span className="meta-line" /> Un punto de partida claro para equipos responsables.</div>
      </div>
      <div className="hero-visual reveal reveal-delay-1" aria-label="Ilustración del enfoque de seguridad de Guardian Nexus">
        <div className="hero-visual-top"><span>GUARDIAN NEXUS / ENFOQUE</span><span className="live-mark"><i /> PREPARACIÓN CONTINUA</span></div>
        <div className="visual-orbit orbit-one" /><div className="visual-orbit orbit-two" />
        <div className="visual-center"><div className="visual-shield"><ShieldCheck size={41} strokeWidth={1.4} /></div><span>PREPARACIÓN</span><b>Controles con contexto</b></div>
        <div className="orbit-node node-a"><CloudGlyph /><span>Infraestructura cloud</span></div>
        <div className="orbit-node node-b"><Globe2 size={16} /><span>Sistemas de IA</span></div>
        <div className="orbit-node node-c"><Fingerprint size={16} /><span>Identidades</span></div>
        <div className="orbit-node node-d"><Database size={16} /><span>Exposición de datos</span></div>
        <div className="visual-footer"><span><span className="tiny-square" /> Visibilidad con supervisión humana</span><span>Sin promesas de certificación</span></div>
      </div>
    </section>
    <section className="lab-disclosure wrap" aria-labelledby="lab-disclosure-title" data-testid="notice-lab-scope">
      <span className="lab-disclosure-mark"><FlaskConical size={19} /></span>
      <div><p className="lab-disclosure-kicker">Alcance actual · laboratorio</p><h2 id="lab-disclosure-title">Validado en un laboratorio con datos y herramientas sintéticos.</h2><p>Hoy no hay Gmail, bancos, proveedores cloud, robots ni sistemas de clientes conectados o protegidos. Las capacidades descritas para agentes son ámbitos de evaluación, no una protección activa en entornos reales.</p></div>
    </section>
    <section id="flujo" className="agent-flow-section" aria-labelledby="agent-flow-title">
      <div className="wrap">
        <div className="agent-flow-heading"><div className="eyebrow">Un modelo de control, no una promesa de conexión</div><h2 id="agent-flow-title">Cada acción pasa por una decisión.</h2><p>El enfoque previsto coloca una verificación entre la intención del agente y su herramienta.</p></div>
        <ol className="agent-flow" data-testid="agent-flow">
          <li><span className="flow-index">01</span><div><b>El agente propone</b><p>Una acción y sus argumentos, antes de ejecutarse.</p></div></li>
          <li><span className="flow-index">02</span><div><b>Guardian verifica</b><p>La petición frente al contexto, el acceso y las reglas definidas.</p></div></li>
          <li><span className="flow-index">03</span><div><b>Decisión explícita</b><p>Permitir, bloquear o requerir aprobación humana.</p></div></li>
        </ol>
      </div>
    </section>
    <section id="alcance" className="principles-section">
      <div className="wrap">
        <div className="section-intro"><div className="eyebrow">Ámbitos de evaluación · solo laboratorio</div><h2>Ocho tipos de agente.<br />Riesgos concretos.</h2><p>Escenarios de referencia con datos y herramientas sintéticos. No equivalen a cobertura en producción ni a conectores disponibles.</p></div>
        <div className="agent-risk-grid" data-testid="agent-risk-grid">
          <article className="agent-risk-card" data-testid="agent-risk-email"><span className="agent-risk-number">01 / COMUNICACIÓN</span><div className="agent-risk-icon"><Activity size={18} /></div><h3>Email</h3><p>Phishing, exfiltración de información y envíos no autorizados.</p></article>
          <article className="agent-risk-card" data-testid="agent-risk-database"><span className="agent-risk-number">02 / DATOS</span><div className="agent-risk-icon"><Database size={18} /></div><h3>Bases de datos</h3><p>Extracción, eliminación o cambios de registros sin autorización.</p></article>
          <article className="agent-risk-card" data-testid="agent-risk-finance"><span className="agent-risk-number">03 / DINERO</span><div className="agent-risk-icon"><Gauge size={18} /></div><h3>Finanzas</h3><p>Pagos no autorizados y altas o cambios de beneficiarios.</p></article>
          <article className="agent-risk-card" data-testid="agent-risk-programming"><span className="agent-risk-number">04 / DESARROLLO</span><div className="agent-risk-icon"><Command size={18} /></div><h3>Programación</h3><p>Ejecución de comandos, exposición de secretos y ediciones de código.</p></article>
          <article className="agent-risk-card" data-testid="agent-risk-support"><span className="agent-risk-number">05 / CLIENTES</span><div className="agent-risk-icon"><Users size={18} /></div><h3>Atención al cliente</h3><p>Cambios fraudulentos de cuenta y exposición de datos personales.</p></article>
          <article className="agent-risk-card" data-testid="agent-risk-browser"><span className="agent-risk-number">06 / NAVEGACIÓN</span><div className="agent-risk-icon"><Globe2 size={18} /></div><h3>Navegador</h3><p>Inyección de prompts y acciones web iniciadas sin autorización.</p></article>
          <article className="agent-risk-card" data-testid="agent-risk-infrastructure"><span className="agent-risk-number">07 / SISTEMAS</span><div className="agent-risk-icon"><Cloud size={18} /></div><h3>Infraestructura</h3><p>Elevación de privilegios y modificaciones de configuración.</p></article>
          <article className="agent-risk-card" data-testid="agent-risk-multiagent"><span className="agent-risk-number">08 / ORQUESTACIÓN</span><div className="agent-risk-icon"><Layers3 size={18} /></div><h3>Sistemas multiagente</h3><p>Delegaciones inseguras y escalada de privilegios entre agentes.</p></article>
        </div>
        <div className="agent-ia-cta"><div><span className="eyebrow">Seguridad de IA</span><h3>Explora las evaluaciones disponibles en laboratorio.</h3><p>Perfiles y resultados acotados a escenarios sintéticos; no prueban sistemas de clientes.</p></div><Link href="/ai-evaluations" className="button button-primary" data-testid="link-home-ai-evaluations">Ver Seguridad IA <ArrowRight size={16} /></Link></div>
        <div className="section-intro capability-intro"><div className="eyebrow">Preparación de la plataforma</div><h2>Construir controles con contexto.</h2><p>Capacidades actuales y previstas, con su estado descrito de forma explícita.</p></div>
        <div className="capability-grid">
          <article className="capability-card capability-featured"><span className="capability-number">01 / SISTEMAS</span><div className="capability-icon"><Sparkles size={20} /></div><h3>Evaluación de seguridad de IA</h3><p>Prueba real y acotada sobre un agente propio de laboratorio. No analiza agentes ni datos de clientes.</p><span className="capability-state">Activo en laboratorio interno · servicio a clientes no disponible</span></article>
          <article className="capability-card"><span className="capability-number">02 / EXPOSICIÓN</span><div className="capability-icon"><Layers3 size={20} /></div><h3>Configuración, identidades y datos</h3><p>Señales sobre configuraciones incorrectas, permisos, identidades y posibles exposiciones de datos.</p><span className="capability-state">Previsto · no disponible aún</span></article>
          <article className="capability-card"><span className="capability-number">03 / AMENAZAS</span><div className="capability-icon"><ShieldEllipsis size={20} /></div><h3>Vulnerabilidades e inyección de prompts</h3><p>Consideración de vulnerabilidades y riesgos de prompt injection en los contextos relevantes.</p><span className="capability-state">Previsto · no disponible aún</span></article>
          <article className="capability-card"><span className="capability-number">04 / OPERACIÓN</span><div className="capability-icon"><Activity size={20} /></div><h3>Correlación y monitorización</h3><p>Correlación de amenazas y señales a lo largo del tiempo para dar contexto a la revisión del equipo.</p><span className="capability-state">Previsto · no disponible aún</span></article>
          <article className="capability-card"><span className="capability-number">05 / EVIDENCIA</span><div className="capability-icon"><Check size={20} /></div><h3>Evidencias verificables</h3><p>Organización de evidencias que permitan documentar controles y facilitar su revisión.</p><span className="capability-state">Previsto · no disponible aún</span></article>
          <article className="capability-card"><span className="capability-number">06 / DECISIONES</span><div className="capability-icon"><Users size={20} /></div><h3>Recomendaciones supervisadas</h3><p>Orientación para priorizar trabajo, manteniendo las decisiones y la aprobación en manos de personas.</p><span className="capability-state">Previsto · no disponible aún</span></article>
        </div>
      </div>
    </section>
    <section id="disponible" className="workspace-band">
      <div className="wrap availability-layout">
        <div className="availability-copy"><div className="eyebrow">Disponible hoy · espacio de trabajo</div><h2>Empieza por lo que ya puedes hacer.</h2><p>La experiencia actual es deliberadamente sencilla. No depende de integraciones ni presenta resultados de análisis que aún no existen.</p><Link href={startHref} className="button button-light" data-testid="link-band-create">{isSignedIn ? 'Abrir mi espacio' : 'Crear un espacio'} <ArrowRight size={16} /></Link></div>
        <div className="available-list">
          <div className="available-row"><span className="available-check"><Check size={15} /></span><div><b>Espacio de trabajo de autoservicio</b><p>Crea y gestiona un espacio para tu organización.</p></div><span className="availability-tag">Disponible</span></div>
          <div className="available-row"><span className="available-check"><Check size={15} /></span><div><b>Inventario manual de activos</b><p>Registra sistemas, entorno y criticidad con contexto.</p></div><span className="availability-tag">Disponible</span></div>
          <div className="available-row"><span className="available-check"><Check size={15} /></span><div><b>Roles básicos por función</b><p>Permisos distintos para lectura y cambios de activos.</p></div><span className="availability-tag">Disponible</span></div>
          <div className="available-row"><span className="available-check"><FlaskConical size={15} /></span><div><b>Evaluación de Seguridad de IA</b><p>Solo laboratorio interno con agente local fijo; no está disponible para sistemas de clientes.</p></div><span className="availability-tag">Laboratorio</span></div>
          <div className="available-row planned-row"><span className="planned-mark"><Layers3 size={15} /></span><div><b>Conectores empresariales</b><p>Previstos para una fase futura. No hay Gmail, bancos ni proveedores cloud conectados hoy.</p></div><span className="planned-tag">Planificado</span></div>
          <div className="available-row planned-row"><span className="planned-mark"><Command size={15} /></span><div><b>SDK, API y MCP Gateway</b><p>Vías de integración previstas, todavía no disponibles ni conectadas a sistemas externos.</p></div><span className="planned-tag">Planificado</span></div>
        </div>
      </div>
    </section>
    <section id="preparacion" className="compliance-section">
      <div className="wrap compliance-layout">
        <div className="compliance-heading"><div className="eyebrow">Requisitos europeos aplicables</div><h2>Prepararse no es certificarse.</h2></div>
        <div className="compliance-copy"><p>Los marcos y obligaciones aplicables dependen de tu organización, los sistemas que utiliza y su contexto. Guardian Nexus busca ayudar a organizar la preparación y evidencias; no determina por sí sola qué obligaciones te aplican.</p><p><strong>La plataforma no concede certificaciones ni garantiza el cumplimiento.</strong> La evaluación, interpretación de requisitos y validación deben realizarse con las personas responsables y, cuando corresponda, con asesoramiento cualificado. La referencia a Europa describe el contexto previsto, no una certificación ni una conclusión legal.</p><Link href="/roadmap" className="text-link" data-testid="link-roadmap">Consultar la hoja de ruta <ArrowRight size={15} /></Link></div>
        <div className="compliance-steps"><div><span>01</span><b>Preparar</b><small>Organizar activos y responsabilidades</small></div><i /><div><span>02</span><b>Evaluar</b><small>Revisar controles frente al contexto aplicable</small></div><i /><div className="certification-step"><span>03</span><b>Certificar</b><small>Proceso independiente, fuera de la plataforma</small></div></div>
      </div>
    </section>
    <footer className="public-footer wrap"><Brand /><span>Ciberseguridad para la era de la IA.</span><span>© {new Date().getFullYear()} Guardian Nexus</span></footer>
  </main>;
}

function CloudGlyph() { return <Database size={16} />; }

const navItems = [
  { href: '/dashboard', label: 'Resumen', icon: Activity },
  { href: '/assets', label: 'Activos', icon: Box },
  { href: '/team', label: 'Equipo', icon: Users },
  { href: '/integrations', label: 'Conexiones', icon: Globe2 },
  { href: '/ai-evaluations', label: 'Seguridad IA', icon: FlaskConical },
  { href: '/integration-readiness', label: 'Preparación', icon: Cloud },
  { href: '/plans', label: 'Planes y uso', icon: Gauge },
  { href: '/roadmap', label: 'Hoja de ruta empresarial', icon: Layers3 },
];

function AppShell({ children, workspace }: { children: ReactNode; workspace?: Workspace }) {
  const [location] = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const { user } = useUser();
  return <div className="app-shell">
    <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
      <div className="sidebar-top"><Brand inverse /><button className="sidebar-close" onClick={() => setMobileOpen(false)} aria-label="Cerrar menú"><X size={18} /></button></div>
      {workspace && <div className="workspace-chip"><div className="workspace-avatar">{workspace.name.slice(0, 1).toUpperCase()}</div><div className="workspace-chip-copy"><b>{workspace.name}</b><span>Plan {planLabel({ id: workspace.planId, name: workspace.planId })} · {roleLabel(workspace.role)}</span></div></div>}
      <div className="nav-caption">ESPACIO DE TRABAJO</div>
      <nav className="side-nav">{navItems.map(({ href, label, icon: Icon }) => <Link key={href} href={href} onClick={() => setMobileOpen(false)} className={`side-link ${location === href ? 'side-link-active' : ''}`} data-testid={`link-nav-${label.toLowerCase().replaceAll(' ', '-')}`}><Icon size={17} strokeWidth={1.8} /><span>{label}</span>{location === href && <span className="active-indicator" />}</Link>)}</nav>
      <div className="sidebar-bottom">
        <div className="sidebar-scope"><div className="scope-icon"><LockKeyhole size={14} /></div><div><b>Ámbito del espacio</b><span>Tus datos permanecen aquí</span></div></div>
        <div className="user-row"><div className="user-identity"><div className="user-avatar">{(user?.firstName?.[0] ?? user?.primaryEmailAddress?.emailAddress?.[0] ?? 'U').toUpperCase()}</div><div><b>{user?.fullName ?? 'Sesión iniciada'}</b><span>{user?.primaryEmailAddress?.emailAddress ?? 'Cuenta'}</span></div></div><SignOutButton /></div>
      </div>
    </aside>
    {mobileOpen && <button className="mobile-scrim" onClick={() => setMobileOpen(false)} aria-label="Cerrar navegación" />}
    <main className="main-area">
      <header className="topbar"><button className="mobile-menu app-mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Abrir navegación"><Menu /></button><div className="breadcrumb"><span>Espacio</span><span className="crumb-slash">/</span><b>{navItems.find(i => i.href === location)?.label ?? 'Configuración del espacio'}</b></div><div className="topbar-right"><span className="secure-pill"><i /> Espacio seguro</span><span className="topbar-separator" /><span className="topbar-region">UE / ES</span><Link href="/roadmap" className="help-button" title="Consultar la hoja de ruta" aria-label="Consultar la hoja de ruta"><CircleHelp size={17} /></Link></div></header>
      <div className="page-content">{children}</div>
    </main>
  </div>;
}

function SignOutButton() {
  const { signOut } = useClerk();
  return <button type="button" className="signout-button" onClick={() => signOut({ redirectUrl: basePath || '/' })} aria-label="Cerrar sesión" title="Cerrar sesión" data-testid="button-sign-out"><LogOut size={15} /></button>;
}

function AuthGuard({ children }: { children: ReactNode }) {
  const { isLoaded, isSignedIn } = useAuth();
  const [, setLocation] = useLocation();
  useEffect(() => { if (isLoaded && !isSignedIn) setLocation('/sign-in'); }, [isLoaded, isSignedIn, setLocation]);
  if (!isLoaded || !isSignedIn) return <div className="auth-wait"><LoadingState label="Comprobando tu sesión" /></div>;
  return <>{children}</>;
}

function WorkspaceFrame({ page: Page }: { page: (props: { workspace: Workspace }) => ReactNode }) {
  const { isLoaded, isSignedIn } = useAuth();
  const workspaces = useListWorkspaces({ query: { queryKey: getListWorkspacesQueryKey(), enabled: isLoaded && !!isSignedIn } });
  if (!isLoaded) return <div className="auth-wait"><LoadingState label="Comprobando tu cuenta" /></div>;
  if (!isSignedIn) return <AuthGuard><div /></AuthGuard>;
  if (workspaces.isLoading) return <AppShell><LoadingState /></AppShell>;
  if (workspaces.isError) return <AppShell><QueryError onRetry={() => workspaces.refetch()} /></AppShell>;
  const workspace = workspaces.data?.[0];
  if (!workspace) return <AppShell><WorkspaceSetup onCreated={() => workspaces.refetch()} /></AppShell>;
  return <AppShell workspace={workspace}><Page workspace={workspace} /></AppShell>;
}

function WorkspaceSetup({ onCreated }: { onCreated: () => void }) {
  const plans = useListPlans({ query: { queryKey: getListPlansQueryKey() } });
  const createWorkspace = useCreateWorkspace();
  const cache = useQueryClient();
  const [name, setName] = useState('');
  const [planId, setPlanId] = useState('small');
  const [message, setMessage] = useState('');
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setMessage('');
    createWorkspace.mutate({ data: { name: name.trim(), planId: planId as 'small' | 'medium' | 'large' } }, {
      onSuccess: async () => { await cache.invalidateQueries({ queryKey: getListWorkspacesQueryKey() }); onCreated(); },
      onError: () => setMessage('No se ha podido crear el espacio de trabajo. Inténtalo de nuevo.'),
    });
  };
  return <div className="setup-wrap reveal">
    <div className="setup-kicker"><Shield size={15} /> TU ESPACIO DE SEGURIDAD</div>
    <h1>Un lugar para<br /><em>empezar.</em></h1>
    <p className="setup-intro">Crea un espacio privado para los activos y las personas de los que se responsabiliza tu organización.</p>
    <form className="setup-form" onSubmit={submit}>
      <label className="field-label" htmlFor="workspace-name">Nombre del espacio</label>
      <input id="workspace-name" className="text-input" value={name} onChange={e => setName(e.target.value)} required minLength={2} maxLength={100} placeholder="p. ej., Estudio Norte" data-testid="input-workspace-name" />
      <label className="field-label field-label-spaced" htmlFor="workspace-plan">Plan inicial</label>
      {plans.isLoading ? <div className="skeleton skeleton-select" /> : plans.isError ? <div className="inline-error">Los planes no están disponibles en este momento. <button type="button" onClick={() => plans.refetch()}>Reintentar</button></div> : <select id="workspace-plan" className="text-input" value={planId} onChange={e => setPlanId(e.target.value)} data-testid="select-workspace-plan">
        {(plans.data ?? []).map(plan => <option key={plan.id} value={plan.id}>{planLabel(plan)} · hasta {plan.maxAssets} activos · {plan.maxUsers} miembros</option>)}
      </select>}
      {message && <p className="form-error" role="alert" data-testid="status-create-error">{message}</p>}
      <Button type="submit" disabled={!name.trim() || createWorkspace.isPending || plans.isError || plans.isLoading} className="button-full" data-testid="button-create-workspace">{createWorkspace.isPending ? 'Creando tu espacio…' : 'Crear espacio'} <ArrowRight size={16} /></Button>
      <span className="form-footnote"><LockKeyhole size={13} /> Privado para tu organización. Consulta los límites cuando quieras.</span>
    </form>
    <div className="setup-aside"><span className="aside-index">01</span><div><b>Un punto de partida claro</b><p>En esta fase no hay integraciones ni evaluaciones. Empieza por registrar los activos de tu organización.</p></div></div>
  </div>;
}

function PageHeading({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: ReactNode }) {
  return <div className="page-heading reveal"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{detail}</p></div>{action && <div className="heading-action">{action}</div>}</div>;
}

function Meter({ label, used, max, unit = '' }: { label: string; used: number; max: number; unit?: string }) {
  const percent = max > 0 ? Math.min(100, (used / max) * 100) : 0;
  const isFull = used >= max;
  return <div className="quota-row" data-testid={`quota-${label.toLowerCase().replaceAll(' ', '-')}`}>
    <div className="quota-line"><span>{label}</span><b className="font-mono-data">{used.toLocaleString()}{unit} <small>/ {max.toLocaleString()}{unit}</small></b></div>
    <div className="quota-track"><span className={isFull ? 'quota-full' : ''} style={{ width: `${percent}%` }} /></div>
  </div>;
}

function IntegrationsPage({ workspace }: { workspace: Workspace }) {
  const queryClient = useQueryClient();
  const integrationsQueryKey = getListWorkspaceIntegrationsQueryKey(workspace.id);
  const integrationsQuery = useListWorkspaceIntegrations(workspace.id, {
    query: { queryKey: integrationsQueryKey, refetchOnMount: 'always' },
  });
  const integrations = integrationsQuery.data ?? [];
  const beginMicrosoftAuthorization = useBeginMicrosoftAuthorization();
  const configureAwsIntegration = useConfigureAwsIntegration();
  const verifyAwsIntegration = useVerifyAwsIntegration();
  const revokeWorkspaceIntegration = useRevokeWorkspaceIntegration();
  const [actionError, setActionError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [awsSetup, setAwsSetup] = useState<AwsIntegrationSetup | null>(null);
  const canManage = workspace.role === 'owner' || workspace.role === 'admin';
  const refreshIntegrations = async () => {
    await queryClient.invalidateQueries({ queryKey: integrationsQueryKey, refetchType: 'none' });
    await integrationsQuery.refetch();
  };
  const errorMessage = (error: unknown, fallback: string) => error instanceof Error ? error.message : fallback;
  const connectMicrosoft = async () => {
    setActionError(''); setNotice(''); setBusy('microsoft');
    try {
      const result = await beginMicrosoftAuthorization.mutateAsync({ workspaceId: workspace.id });
      if (!result?.authorizationUrl) throw new Error('El servicio no ha devuelto una dirección de autorización.');
      await refreshIntegrations();
      window.location.assign(result.authorizationUrl);
    } catch (error) {
      setActionError(errorMessage(error, 'No se ha podido iniciar la autorización de Microsoft.'));
      setBusy('');
    }
  };
  const connectAws = async (event: FormEvent) => {
    event.preventDefault(); setActionError(''); setNotice('');
    if (!roleArn.trim()) return;
    setBusy('aws');
    try {
      const result = await configureAwsIntegration.mutateAsync({ workspaceId: workspace.id, data: { roleArn: roleArn.trim() } });
      await refreshIntegrations();
      setAwsSetup(result);
      setNotice('Conexión AWS preparada. Añade la relación de confianza indicada y verifica el rol.');
    } catch (error) {
      setActionError(errorMessage(error, 'No se ha podido preparar la conexión AWS.'));
    } finally { setBusy(''); }
  };
  const verifyAws = async () => {
    if (!awsSetup) return;
    setActionError(''); setBusy('verify');
    try {
      await verifyAwsIntegration.mutateAsync({ workspaceId: workspace.id });
      await refreshIntegrations();
      setNotice('El rol de AWS se ha verificado correctamente.');
      setAwsSetup(null);
    } catch (error) {
      setActionError(errorMessage(error, 'No se ha podido verificar el rol de AWS.'));
    } finally { setBusy(''); }
  };
  const revoke = async (provider: IntegrationConnection['provider']) => {
    const aws = provider === 'aws';
    const warning = aws
      ? '¿Desactivar el acceso local a AWS? Las sesiones de rol ya emitidas pueden seguir activas hasta 15 minutos. Para cortar el acceso de inmediato, elimina también la relación de confianza en tu cuenta de AWS.'
      : '¿Revocar el acceso de Microsoft 365 para este espacio?';
    if (!window.confirm(warning)) return;
    setActionError(''); setNotice(''); setBusy(`revoke-${provider}`);
    try {
      await revokeWorkspaceIntegration.mutateAsync({ workspaceId: workspace.id, provider });
      await refreshIntegrations();
      setNotice(aws
        ? 'Acceso local a AWS desactivado. Las sesiones ya emitidas pueden durar hasta 15 minutos; elimina la relación de confianza para un corte inmediato.'
        : 'Acceso local a Microsoft 365 revocado. Para retirar también el consentimiento concedido a la aplicación, elimina su acceso desde el centro de administración de Microsoft 365.');
    } catch (error) {
      setActionError(errorMessage(error, 'No se ha podido revocar el acceso.'));
    } finally { setBusy(''); }
  };
  const copyExternalId = async () => {
    if (!awsSetup) return;
    try { await navigator.clipboard.writeText(awsSetup.externalId); setNotice('ExternalId copiado.'); }
    catch { setNotice('Selecciona y copia el ExternalId manualmente.'); }
  };

  const integrationFor = (provider: IntegrationConnection['provider']) => integrations.find(item => item.provider === provider);
  const statusLabel = (status?: IntegrationConnection['status']) => {
    if (status === 'active') return 'Conectada';
    if (status === 'pending') return 'Pendiente de verificación';
    if (status === 'revoked') return 'Revocada';
    return 'Sin conectar';
  };
  const renderState = (provider: IntegrationConnection['provider'], item?: IntegrationConnection) => <span className={`integration-status integration-status-${item?.status ?? 'none'}`} data-testid={`status-integration-${provider}`}>
    <i />{statusLabel(item?.status)}
  </span>;

  return <div className="integrations-page">
    <PageHeading eyebrow="Conexiones del espacio" title="Integraciones" detail={`Conecta fuentes de identidad y nube para documentar la postura de ${workspace.name}. El acceso es explícito, de solo lectura y limitado a este espacio.`} />
    <div className="integration-scan-note" role="note" data-testid="notice-no-scan">
      <span className="scan-note-mark"><ShieldCheck size={19} /></span>
      <div><b>Conectar no inicia un análisis</b><p>Estas conexiones preparan el acceso de solo lectura. Guardian Nexus todavía no ejecuta análisis ni genera hallazgos automáticos.</p></div>
      <span className="note-index">ESTADO ACTUAL / 01</span>
    </div>
    {!canManage && <div className="integration-permission" role="status" data-testid="status-read-only-role">
      <LockKeyhole size={16} /> Tu rol ({roleLabel(workspace.role)}) puede consultar el estado, pero solo propietarios y administradores pueden gestionar conexiones.
    </div>}
    {actionError && <div className="integration-alert integration-alert-error" role="alert" data-testid="status-integration-error"><b>No se ha completado la acción</b><span>{actionError}</span><button type="button" onClick={() => setActionError('')} aria-label="Cerrar aviso" data-testid="button-dismiss-integration-error"><X size={15} /></button></div>}
    {notice && <div className="integration-alert integration-alert-success" role="status" data-testid="status-integration-success"><Check size={16} /><span>{notice}</span><button type="button" onClick={() => setNotice('')} aria-label="Cerrar aviso" data-testid="button-dismiss-integration-success"><X size={15} /></button></div>}

    {integrationsQuery.isLoading ? <div className="integration-loading" role="status" data-testid="status-integrations-loading" aria-label="Cargando integraciones"><div /><div /><div /></div>
      : integrationsQuery.isError ? <div className="notice notice-error integration-load-error" role="alert" data-testid="status-integrations-error"><div className="notice-icon"><RefreshCw size={17} /></div><div><strong>No se han podido cargar las integraciones</strong><p>{errorMessage(integrationsQuery.error, 'No se han podido recuperar las integraciones. Inténtalo de nuevo.')}</p></div><Button variant="secondary" onClick={() => void integrationsQuery.refetch()} data-testid="button-retry-integrations">Reintentar</Button></div>
      : <div className="integration-grid" data-testid="list-integrations">
        <article className="integration-card" data-testid="card-integration-microsoft">
          <div className="integration-card-top"><div className="integration-logo microsoft-logo" aria-hidden="true"><span /><span /><span /><span /></div><span className="integration-index">01 / IDENTIDAD</span></div>
          <div className="integration-title-row"><div><h2>Microsoft 365</h2><p>Microsoft Graph · organización e identidad</p></div>{renderState('microsoft_graph', integrationFor('microsoft_graph'))}</div>
          <p className="integration-description">Autoriza una conexión de solo lectura para asociar la organización y sus datos básicos de directorio a este espacio.</p>
          <div className="integration-permissions"><span>PERMISOS SOLICITADOS</span><code>openid</code><code>profile</code><code>offline_access</code><code>Organization.Read.All</code></div>
          <p className="integration-admin-note">La aprobación de <code>Organization.Read.All</code> puede requerir a una persona administradora de Microsoft 365.</p>
          <div className="integration-facts">
            <div><span>Ámbito</span><b>Solo lectura</b></div>
            <div><span>Almacenamiento</span><b>Token cifrado en servidor</b></div>
            {integrationFor('microsoft_graph')?.externalTenantId && <div><span>Id. de organización</span><b className="font-mono-data">{integrationFor('microsoft_graph')?.externalTenantId}</b></div>}
            {integrationFor('microsoft_graph')?.status === 'revoked' && <p className="revoked-copy" data-testid="state-microsoft-revoked">Acceso local revocado{integrationFor('microsoft_graph')?.revokedAt ? ` · ${new Date(integrationFor('microsoft_graph')!.revokedAt!).toLocaleDateString('es-ES')}` : ''}.</p>}
          </div>
          <div className="integration-card-actions">
            {canManage && integrationFor('microsoft_graph')?.status !== 'active' && <Button onClick={() => void connectMicrosoft()} disabled={!!busy} data-testid="button-connect-microsoft">{busy === 'microsoft' ? 'Preparando autorización…' : 'Conectar Microsoft 365'} <ExternalLink size={14} /></Button>}
            {canManage && integrationFor('microsoft_graph')?.status === 'active' && <Button variant="danger" onClick={() => void revoke('microsoft_graph')} disabled={!!busy} data-testid="button-revoke-microsoft">{busy === 'revoke-microsoft_graph' ? 'Revocando…' : 'Revocar acceso'}</Button>}
            {!integrationFor('microsoft_graph') && <span className="integration-empty-caption" data-testid="state-microsoft-empty">Aún no hay una conexión registrada.</span>}
          </div>
        </article>

        <article className="integration-card" data-testid="card-integration-aws">
          <div className="integration-card-top"><div className="integration-logo aws-logo" aria-hidden="true"><Cloud size={22} /></div><span className="integration-index">02 / INFRAESTRUCTURA</span></div>
          <div className="integration-title-row"><div><h2>Amazon Web Services</h2><p>AWS IAM Role · cuenta del cliente</p></div>{renderState('aws', integrationFor('aws'))}</div>
          <p className="integration-description">Vincula un rol que tú controlas. La sesión temporal se limita a 900 segundos y utiliza la política administrada SecurityAudit.</p>
          {canManage && integrationFor('aws')?.status !== 'active' && <form className="aws-connect-form" onSubmit={connectAws}>
            <label htmlFor="aws-role-arn">ARN del rol de IAM</label>
            <input id="aws-role-arn" value={roleArn} onChange={event => setRoleArn(event.target.value)} placeholder="arn:aws:iam::123456789012:role/GuardianAudit" required pattern="arn:aws:iam::[0-9]{12}:role/.+" data-testid="input-aws-role-arn" />
            <span>Usaremos el ExternalId generado para esta conexión. Nunca introduzcas contraseñas ni claves permanentes.</span>
            <Button type="submit" disabled={!roleArn.trim() || !!busy} data-testid="button-prepare-aws">{busy === 'aws' ? 'Preparando rol…' : integrationFor('aws')?.status === 'revoked' ? 'Volver a conectar' : 'Preparar conexión AWS'} <ArrowRight size={15} /></Button>
          </form>}
          <div className="integration-facts">
            <div><span>Permiso</span><b>SecurityAudit · solo lectura</b></div>
            <div><span>Duración STS</span><b>900 segundos</b></div>
            {integrationFor('aws')?.awsAccountId && <div><span>Cuenta AWS</span><b className="font-mono-data">{integrationFor('aws')?.awsAccountId}</b></div>}
            {integrationFor('aws')?.awsRoleArn && <div><span>Rol conectado</span><b className="font-mono-data">{integrationFor('aws')?.awsRoleArn}</b></div>}
            {integrationFor('aws')?.status === 'revoked' && <p className="revoked-copy" data-testid="state-aws-revoked">Acceso local desactivado. Las sesiones ya emitidas pueden durar hasta 15 minutos; elimina la relación de confianza en AWS para un corte inmediato.</p>}
          </div>
          {awsSetup && <section className="aws-setup-panel" aria-labelledby="aws-setup-title" data-testid="panel-aws-setup">
            <div className="aws-setup-heading"><ShieldCheck size={17} /><div><b id="aws-setup-title">Completa la relación de confianza</b><span>El acceso aún no está verificado.</span></div></div>
            <div className="external-id-row"><div><span>EXTERNAL ID</span><code data-testid="text-aws-external-id">{awsSetup.externalId}</code></div><button type="button" onClick={() => void copyExternalId()} aria-label="Copiar ExternalId" data-testid="button-copy-external-id"><Copy size={15} /></button></div>
            <div className="aws-instruction"><span>Rol solicitado</span><code>{awsSetup.roleArn}</code></div>
            {awsSetup.trustedPrincipalArn && <div className="aws-instruction"><span>Principal de confianza</span><code>{awsSetup.trustedPrincipalArn}</code></div>}
            <div className="aws-instruction"><span>Política de confianza</span><pre data-testid="text-aws-trust-policy">{awsSetup.trustPolicyJson}</pre></div>
            <div className="aws-instruction"><span>Política requerida</span><pre>{typeof awsSetup.requiredPolicy === 'string' ? awsSetup.requiredPolicy : JSON.stringify(awsSetup.requiredPolicy, null, 2)}</pre></div>
            <div className="aws-instruction"><span>Pasos para el cliente</span><pre>{typeof awsSetup.instructions === 'string' ? awsSetup.instructions : JSON.stringify(awsSetup.instructions, null, 2)}</pre></div>
            <Button onClick={() => void verifyAws()} disabled={!!busy} data-testid="button-verify-aws">{busy === 'verify' ? 'Verificando…' : 'Verificar rol AWS'} <Check size={15} /></Button>
          </section>}
          {canManage && integrationFor('aws')?.status === 'active' && <div className="integration-card-actions"><Button variant="danger" onClick={() => void revoke('aws')} disabled={!!busy} data-testid="button-revoke-aws">{busy === 'revoke-aws' ? 'Revocando…' : 'Revocar acceso AWS'}</Button></div>}
          {!integrationFor('aws') && <span className="integration-empty-caption" data-testid="state-aws-empty">Aún no hay un rol AWS conectado.</span>}
        </article>
      </div>}
    <div className="integration-footnote" data-testid="text-integration-scope"><LockKeyhole size={14} /><span>Cada conexión pertenece únicamente a <b>{workspace.name}</b>. Se requiere consentimiento explícito y no se realizan cambios en tus sistemas.</span></div>
  </div>;
}

function DashboardPage({ workspace }: { workspace: Workspace }) {
  const dashboard = useGetWorkspaceDashboard(workspace.id, { query: { queryKey: getGetWorkspaceDashboardQueryKey(workspace.id), enabled: !!workspace.id } });
  const health = useHealthCheck();
  if (dashboard.isLoading) return <LoadingState />;
  if (dashboard.isError) return <QueryError onRetry={() => dashboard.refetch()} />;
  const d = dashboard.data;
  if (!d) return null;
  const assetLimit = d.plan.maxAssets;
  const remaining = Math.max(0, assetLimit - d.assetCount);
  const date = new Date().toLocaleDateString('es-ES', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  return <div className="dashboard-page">
    <PageHeading eyebrow={date} title="Resumen de seguridad" detail={`Una visión actual de ${workspace.name}. Lo esencial, siempre a mano.`} action={<span className={`connection-state ${health.isError ? 'connection-muted' : ''}`}><i /> {health.isSuccess ? 'Servicios conectados' : health.isError ? 'Estado del servicio no disponible' : 'Comprobando servicios'}</span>} />
    <section className="overview-banner reveal reveal-delay-1">
      <div className="banner-symbol"><ShieldCheck size={25} /></div>
      <div className="banner-message"><span>ESTADO DEL ESPACIO</span><h2>{d.findingsCount === 0 ? 'Una base clara sobre la que avanzar.' : `${d.findingsCount} hallazgo${d.findingsCount === 1 ? ' registrado' : 's registrados'}.`}</h2><p>{d.findingsCount === 0 ? 'Este espacio todavía no registra hallazgos. En esta fase solo se muestran el inventario y el uso.' : 'Los hallazgos proceden del backend; en esta fase no se realizan análisis.'}</p></div>
      <div className="banner-divider" />
      <div className="banner-capacity"><span>Capacidad de activos</span><strong>{remaining}<small> disponibles</small></strong><span className="banner-capacity-note">de {assetLimit} en {planLabel(d.plan)}</span></div>
      <span className="banner-corner">01 / BASE</span>
    </section>
    <section className="metric-grid">
      <MetricCard label="Activos registrados" value={d.assetCount} detail={`de ${d.plan.maxAssets} disponibles`} icon={Box} href="/assets" />
      <MetricCard label="Miembros del equipo" value={d.memberCount} detail={`de ${d.plan.maxUsers} plazas`} icon={Users} href="/team" />
      <MetricCard label="Análisis utilizados" value={d.scansUsed} detail={`de ${d.plan.scansPerMonth} al mes`} icon={Radio} href="/plans" />
      <MetricCard label="Hallazgos registrados" value={d.findingsCount} detail="Solo datos del backend" icon={ShieldEllipsis} href="/roadmap" />
    </section>
    <section className="panel ai-lab-dashboard-card">
      <div><span className="panel-kicker">SEGURIDAD DE IA · LABORATORIO INTERNO</span><h2>Evaluación de Seguridad de IA</h2><p>Hay una evaluación real acotada para un agente local propio. No evalúa sistemas, agentes ni datos de este espacio.</p></div>
      <span className="availability-tag">No disponible para clientes</span>
      <Link href="/ai-evaluations" className="button button-secondary">Ver laboratorio <ArrowRight size={15} /></Link>
    </section>
    <div className="dashboard-lower">
      <section className="panel recent-panel">
        <div className="panel-heading"><div><div className="panel-kicker">INVENTARIO</div><h2>Últimos activos añadidos</h2></div><Link href="/assets" className="text-link" data-testid="link-view-assets">Ver inventario <ArrowRight size={14} /></Link></div>
        {d.recentAssets.length === 0 ? <EmptyState icon={Box} title="Empieza por el registro" copy="Añade el primer activo para tener a la vista la huella digital de tu organización." action={<Link href="/assets" className="button button-secondary" data-testid="link-add-first-asset"><Plus size={15} /> Añadir activo</Link>} /> : <div className="recent-list">{d.recentAssets.slice(0, 5).map(asset => <AssetRow key={asset.id} asset={asset} />)}</div>}
      </section>
      <section className="panel usage-panel">
        <div className="panel-heading"><div><div className="panel-kicker">ESTE MES</div><h2>Uso del plan</h2></div><Link href="/plans" className="panel-more" aria-label="Ver planes"><ArrowUpRight size={17} /></Link></div>
        <div className="usage-caption"><span>Plan {planLabel(d.plan)}</span><span className="plan-bullet" /></div>
        <Meter label="Activos" used={d.assetCount} max={d.plan.maxAssets} />
        <Meter label="Miembros" used={d.memberCount} max={d.plan.maxUsers} />
        <Meter label="Análisis" used={d.scansUsed} max={d.plan.scansPerMonth} />
        <Meter label="Tokens" used={d.tokensUsed} max={d.plan.tokensPerMonth} />
        <Meter label="Solicitudes API" used={d.apiRequestsUsed} max={d.plan.apiRequestsPerMonth} />
        <p className="usage-disclaimer">Uso comunicado por el backend del espacio.</p>
      </section>
    </div>
    <div className="phase-note"><div className="phase-note-icon"><LockKeyhole size={14} /></div><p><b>Servicio en preparación.</b> La evaluación de IA solo está activa en el laboratorio local; no hay escaneos ni conectores de clientes. Este resumen muestra únicamente datos devueltos por el servicio.</p><Link href="/roadmap" className="text-link">Hoja de ruta <ArrowRight size={13} /></Link></div>
  </div>;
}

function MetricCard({ label, value, detail, icon: Icon, href }: { label: string; value: number; detail: string; icon: typeof Box; href: string }) {
  return <Link href={href} className="metric-card" data-testid={`card-metric-${label.toLowerCase().replaceAll(' ', '-')}`}><div className="metric-top"><span>{label}</span><span className="metric-icon"><Icon size={17} /></span></div><div className="metric-value">{value.toLocaleString()}</div><div className="metric-detail">{detail}<ArrowUpRight size={13} /></div></Link>;
}

function AssetRow({ asset, onDelete, deleting }: { asset: Asset; onDelete?: () => void; deleting?: boolean }) {
  return <div className="asset-row" data-testid={`row-asset-${asset.id}`}><div className="asset-type-icon"><AssetTypeIcon type={asset.type} /></div><div className="asset-main"><b>{asset.name}</b><span>{assetLabel(asset.type)} <i /> {assetLabel(asset.environment)}</span></div><span className={`criticality criticality-${asset.criticality}`}>{assetLabel(asset.criticality)}</span>{onDelete && <Button variant="quiet" className="icon-button delete-asset" aria-label={`Eliminar ${asset.name}`} disabled={deleting} onClick={onDelete} data-testid={`button-delete-asset-${asset.id}`}><Trash2 size={15} /></Button>}</div>;
}

function assetLabel(value: string) {
  const labels: Record<string, string> = {
    cloud: 'Nube', endpoint: 'Dispositivo', application: 'Aplicación', identity: 'Identidad', network: 'Red', other: 'Otro',
    production: 'Producción', staging: 'Preproducción', development: 'Desarrollo', unknown: 'Sin especificar',
    critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja',
  };
  return labels[value] ?? value;
}

function AssetTypeIcon({ type }: { type: string }) {
  if (type === 'cloud') return <Database size={17} />;
  if (type === 'application') return <Layers3 size={17} />;
  if (type === 'identity') return <Fingerprint size={17} />;
  if (type === 'network') return <Globe2 size={17} />;
  return <HardDrive size={17} />;
}

function AssetsPage({ workspace }: { workspace: Workspace }) {
  const assetsQuery = useListWorkspaceAssets(workspace.id, { query: { queryKey: getListWorkspaceAssetsQueryKey(workspace.id), enabled: !!workspace.id } });
  const dashboardQuery = useGetWorkspaceDashboard(workspace.id, { query: { queryKey: getGetWorkspaceDashboardQueryKey(workspace.id), enabled: !!workspace.id } });
  const createAsset = useCreateWorkspaceAsset();
  const deleteAsset = useDeleteWorkspaceAsset();
  const cache = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [formError, setFormError] = useState('');
  const [assetName, setAssetName] = useState('');
  const [type, setType] = useState<AssetInput['type']>('cloud');
  const [environment, setEnvironment] = useState<AssetInput['environment']>('production');
  const [criticality, setCriticality] = useState<AssetInput['criticality']>('medium');
  const assets = assetsQuery.data ?? [];
  const limit = dashboardQuery.data?.plan.maxAssets ?? 0;
  const atLimit = limit > 0 && assets.length >= limit;
  const create = (event: FormEvent) => {
    event.preventDefault(); setFormError('');
    createAsset.mutate({ workspaceId: workspace.id, data: { name: assetName.trim(), type, environment, criticality } }, {
      onSuccess: async () => { setShowForm(false); setAssetName(''); await Promise.all([cache.invalidateQueries({ queryKey: getListWorkspaceAssetsQueryKey(workspace.id) }), cache.invalidateQueries({ queryKey: getGetWorkspaceDashboardQueryKey(workspace.id) })]); },
      onError: () => setFormError('No se ha podido añadir el activo. Comprueba el límite de tu plan e inténtalo de nuevo.'),
    });
  };
  const remove = (id: string, name: string) => {
    if (!window.confirm(`¿Quieres eliminar «${name}» del inventario de este espacio?`)) return;
    deleteAsset.mutate({ workspaceId: workspace.id, assetId: id }, { onSuccess: async () => { await Promise.all([cache.invalidateQueries({ queryKey: getListWorkspaceAssetsQueryKey(workspace.id) }), cache.invalidateQueries({ queryKey: getGetWorkspaceDashboardQueryKey(workspace.id) })]); } });
  };
  return <div>
    <PageHeading eyebrow="REGISTRO DE ACTIVOS" title="Activos" detail="Un registro, dentro de tu espacio, de los sistemas de los que depende tu organización." action={<Button onClick={() => { setShowForm(!showForm); setFormError(''); }} disabled={atLimit} data-testid="button-add-asset"><Plus size={16} /> Añadir activo</Button>} />
    <div className="inventory-summary"><div><Box size={17} /><span><b>{assets.length}</b> activos registrados</span></div><span className="summary-limit">{dashboardQuery.data ? `${assets.length} / ${limit} activos` : 'Cargando límite del plan'}</span><div className="summary-track"><span style={{ width: `${limit ? Math.min(100, assets.length / limit * 100) : 0}%` }} /></div></div>
    {atLimit && <div className="notice notice-limit" data-testid="status-asset-limit"><div className="notice-icon"><SlidersHorizontal size={17} /></div><div><strong>Has alcanzado el límite de activos</strong><p>El plan {dashboardQuery.data ? planLabel(dashboardQuery.data.plan) : ''} admite hasta {limit} activos. Consulta los límites de cada plan.</p></div><Link href="/plans" className="text-link">Ver planes <ArrowRight size={14} /></Link></div>}
    {showForm && <form className="asset-form panel reveal" onSubmit={create}>
      <div className="form-title"><div><span className="panel-kicker">NUEVA ENTRADA</span><h2>Añadir un activo</h2></div><button className="close-form" type="button" onClick={() => setShowForm(false)} aria-label="Cerrar formulario" data-testid="button-close-asset-form"><X size={18} /></button></div>
      <div className="asset-fields"><div className="field-group field-name"><label className="field-label" htmlFor="asset-name">Nombre del activo</label><input id="asset-name" className="text-input" value={assetName} onChange={e => setAssetName(e.target.value)} required maxLength={160} placeholder="p. ej., Portal de clientes" data-testid="input-asset-name" /></div>
        <div className="field-group"><label className="field-label" htmlFor="asset-type">Tipo</label><select id="asset-type" className="text-input" value={type} onChange={e => setType(e.target.value as AssetInput['type'])} data-testid="select-asset-type">{assetTypes.map(x => <option key={x} value={x}>{assetLabel(x)}</option>)}</select></div>
        <div className="field-group"><label className="field-label" htmlFor="asset-environment">Entorno</label><select id="asset-environment" className="text-input" value={environment} onChange={e => setEnvironment(e.target.value as AssetInput['environment'])} data-testid="select-asset-environment">{environments.map(x => <option key={x} value={x}>{assetLabel(x)}</option>)}</select></div>
        <div className="field-group"><label className="field-label" htmlFor="asset-criticality">Criticidad</label><select id="asset-criticality" className="text-input" value={criticality} onChange={e => setCriticality(e.target.value as AssetInput['criticality'])} data-testid="select-asset-criticality">{criticalities.map(x => <option key={x} value={x}>{assetLabel(x)}</option>)}</select></div></div>
      {formError && <p className="form-error" role="alert">{formError}</p>}
      <div className="form-actions"><Button type="button" variant="quiet" onClick={() => setShowForm(false)} data-testid="button-cancel-asset">Cancelar</Button><Button type="submit" disabled={!assetName.trim() || createAsset.isPending} data-testid="button-submit-asset">{createAsset.isPending ? 'Añadiendo…' : 'Añadir al inventario'} <ArrowRight size={15} /></Button></div>
    </form>}
    {assetsQuery.isLoading || dashboardQuery.isLoading ? <LoadingState /> : assetsQuery.isError ? <QueryError onRetry={() => assetsQuery.refetch()} /> : assets.length === 0 ? <EmptyState icon={Box} title="Aún no hay activos registrados" copy="Por ahora, el inventario se completa manualmente. Añade el primer sistema del que depende tu organización." action={<Button onClick={() => setShowForm(true)} data-testid="button-empty-add-asset"><Plus size={15} /> Añadir el primer activo</Button>} /> : <section className="panel inventory-panel"><div className="inventory-head"><span>ACTIVO</span><span>CRITICIDAD</span><span>AÑADIDO</span><span /></div>{assets.map(asset => <div className="inventory-table-row" key={asset.id}><div className="asset-row-content"><AssetRow asset={asset} onDelete={() => remove(asset.id, asset.name)} deleting={deleteAsset.isPending} /></div><span className="asset-created">{formatDate(asset.createdAt)}</span></div>)}</section>}
    <div className="phase-note"><div className="phase-note-icon"><LockKeyhole size={14} /></div><p>Tu equipo añade los activos manualmente. En esta fase no hay conectores ni descubrimiento automático.</p></div>
  </div>;
}

function roleLabel(role: string) {
  const labels: Record<string, string> = { owner: 'Propietario', admin: 'Administrador', analyst: 'Analista', viewer: 'Lector' };
  return labels[role] ?? role;
}
function planLabel(plan: Pick<Plan, 'id' | 'name'>) {
  const labels: Record<string, string> = { small: 'Pequeño', medium: 'Mediano', large: 'Grande' };
  return labels[plan.id] ?? plan.name;
}
function supportLabel(support: string) {
  const value = support.toLowerCase();
  if (value.includes('dedicated')) return 'Dedicado';
  if (value.includes('priority')) return 'Prioritario';
  if (value.includes('email')) return 'Por correo electrónico';
  if (value.includes('standard')) return 'Estándar';
  return support;
}
function formatDate(date: string) { const parsed = new Date(date); return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric' }); }

function TeamPage({ workspace }: { workspace: Workspace }) {
  const membersQuery = useListWorkspaceMembers(workspace.id, { query: { queryKey: getListWorkspaceMembersQueryKey(workspace.id), enabled: !!workspace.id } });
  const updateMember = useUpdateWorkspaceMember();
  const cache = useQueryClient();
  const isOwner = workspace.role === 'owner';
  const handleRole = (member: Member, role: 'admin' | 'analyst' | 'viewer') => {
    updateMember.mutate({ workspaceId: workspace.id, membershipId: member.id, data: { role } }, { onSuccess: async () => { await cache.invalidateQueries({ queryKey: getListWorkspaceMembersQueryKey(workspace.id) }); } });
  };
  return <div>
    <PageHeading eyebrow="PERSONAS Y ACCESO" title="Equipo" detail="Consulta los miembros y sus roles. Solo los propietarios pueden cambiar los roles." />
    <div className="team-intro"><div className="team-intro-icon"><Users size={18} /></div><p><b>Acceso según el rol</b><span>El propietario tiene el control completo. Los roles de administrador, analista y lector determinan el acceso al espacio.</span></p><span className="team-plan">Plan {planLabel({ id: workspace.planId, name: workspace.planId })}</span></div>
    {membersQuery.isLoading ? <LoadingState /> : membersQuery.isError ? <QueryError onRetry={() => membersQuery.refetch()} /> : !membersQuery.data?.length ? <EmptyState icon={Users} title="No hay miembros disponibles" copy="Los miembros del espacio aparecerán aquí cuando el servicio los devuelva." /> : <section className="panel members-panel">
      <div className="members-header"><span>MIEMBRO</span><span>ROL</span><span>SE UNIÓ</span><span /></div>
      {membersQuery.data.map(member => <div className="member-row" key={member.id} data-testid={`row-member-${member.id}`}><div className="member-avatar">{member.userId.slice(0, 1).toUpperCase()}</div><div className="member-details"><b>{member.userId}</b><span>ID de miembro · {member.id.slice(0, 8)}</span></div><div className="member-role">{member.role === 'owner' ? <span className="role-badge role-owner"><ShieldCheck size={13} /> Propietario</span> : isOwner ? <select value={member.role} onChange={e => handleRole(member, e.target.value as 'admin' | 'analyst' | 'viewer')} disabled={updateMember.isPending} className="role-select" aria-label={`Cambiar el rol de ${member.userId}`} data-testid={`select-member-role-${member.id}`}><option value="admin">Administrador</option><option value="analyst">Analista</option><option value="viewer">Lector</option></select> : <span className={`role-badge role-${member.role}`}>{roleLabel(member.role)}</span>}</div><div className="member-date">{formatDate(member.createdAt)}</div></div>)}
    </section>}
    {!isOwner && <div className="notice notice-limit"><div className="notice-icon"><LockKeyhole size={16} /></div><div><strong>Los cambios de rol están reservados al propietario</strong><p>Puedes consultar el equipo, pero solo el propietario puede actualizar los roles.</p></div></div>}
    <div className="phase-note"><div className="phase-note-icon"><Users size={14} /></div><p>En esta fase no se pueden invitar miembros. El equipo que aparece aquí procede del servicio del espacio.</p></div>
  </div>;
}

function PlansPage({ workspace }: { workspace: Workspace }) {
  const plansQuery = useListPlans({ query: { queryKey: getListPlansQueryKey() } });
  const dashboard = useGetWorkspaceDashboard(workspace.id, { query: { queryKey: getGetWorkspaceDashboardQueryKey(workspace.id), enabled: !!workspace.id } });
  const plans = plansQuery.data ?? [];
  const current = dashboard.data?.plan ?? plans.find(p => p.id === workspace.planId);
  return <div>
    <PageHeading eyebrow="CAPACIDAD Y SOPORTE" title="Planes y uso" detail="Consulta las cuotas del espacio con claridad. Los límites proceden directamente de tu plan." />
    {plansQuery.isLoading || dashboard.isLoading ? <LoadingState /> : plansQuery.isError ? <QueryError onRetry={() => plansQuery.refetch()} /> : <>
      {current && <div className="current-plan-callout"><div className="plan-current-mark"><Check size={16} /></div><div><span>PLAN ACTUAL</span><b>{planLabel(current)}</b></div><span className="plan-workspace-name">{workspace.name}</span></div>}
      {dashboard.data && <section className="panel usage-detail-panel"><div className="panel-heading"><div><div className="panel-kicker">USO ACTUAL DEL ESPACIO</div><h2>Cuota mensual</h2></div><span className="usage-updated">Datos del backend</span></div><div className="usage-detail-grid"><Meter label="Activos" used={dashboard.data.assetCount} max={dashboard.data.plan.maxAssets} /><Meter label="Miembros" used={dashboard.data.memberCount} max={dashboard.data.plan.maxUsers} /><Meter label="Análisis" used={dashboard.data.scansUsed} max={dashboard.data.plan.scansPerMonth} /><Meter label="Tokens" used={dashboard.data.tokensUsed} max={dashboard.data.plan.tokensPerMonth} /><Meter label="Solicitudes API" used={dashboard.data.apiRequestsUsed} max={dashboard.data.plan.apiRequestsPerMonth} /></div></section>}
      <div className="plan-section-heading"><div><span className="panel-kicker">PLANES DISPONIBLES</span><h2>Compara los límites</h2></div><span>El administrador del espacio gestiona los cambios de plan.</span></div>
      <section className="plan-grid">{plans.map((plan, index) => <PlanCard key={plan.id} plan={plan} current={plan.id === current?.id} index={index} />)}</section>
      <div className="phase-note"><div className="phase-note-icon"><CircleHelp size={14} /></div><p>Las cuotas de análisis y tokens describen la capacidad del plan. En esta fase no se ejecutan análisis ni procesamiento con IA.</p></div>
    </>}
  </div>;
}

function PlanCard({ plan, current, index }: { plan: Plan; current: boolean; index: number }) {
  return <article className={`plan-card ${current ? 'plan-card-current' : ''} ${index === 1 ? 'plan-card-featured' : ''}`} data-testid={`card-plan-${plan.id}`}>
    {current && <div className="plan-ribbon">PLAN ACTUAL</div>}
    <div className="plan-card-head"><div className="plan-mark">{index === 0 ? <Command size={17} /> : index === 1 ? <Layers3 size={17} /> : <ShieldCheck size={17} />}</div><span>{index === 0 ? 'PARA EQUIPOS PEQUEÑOS' : index === 1 ? 'PARA EQUIPOS EN CRECIMIENTO' : 'PARA ENTORNOS COMPLEJOS'}</span></div>
    <h3>{planLabel(plan)}</h3><p className="plan-support">Soporte {supportLabel(plan.support).toLowerCase()}</p>
    <div className="plan-divider" />
    <div className="plan-limit"><span>Activos</span><b>{plan.maxAssets.toLocaleString()}</b></div>
    <div className="plan-limit"><span>Miembros</span><b>{plan.maxUsers.toLocaleString()}</b></div>
    <div className="plan-limit"><span>Análisis al mes</span><b>{plan.scansPerMonth.toLocaleString()}</b></div>
    <div className="plan-limit"><span>Tokens al mes</span><b>{plan.tokensPerMonth.toLocaleString()}</b></div>
    <div className="plan-limit"><span>Solicitudes API al mes</span><b>{plan.apiRequestsPerMonth.toLocaleString()}</b></div>
    <div className="plan-support-foot"><Check size={14} /> Soporte {supportLabel(plan.support).toLowerCase()}</div>
    <div className="plan-card-bottom">{current ? <span className="plan-current-label"><Check size={14} /> Activo en el espacio</span> : <span className="plan-not-current">Límites comparados arriba</span>}</div>
  </article>;
}

function RoadmapPage() {
  const capabilities = [
    { id: '01', title: 'Integraciones de nube e identidad', category: 'CONECTIVIDAD', icon: Globe2, detail: 'Conectores para entornos en la nube y proveedores de identidad, con autorización explícita y acceso limitado.' },
    { id: '02', title: 'Descubrimiento programado de activos', category: 'INVENTARIO', icon: Radio, detail: 'Detección automatizada para mantener el inventario al día a medida que cambia el entorno.' },
    { id: '03', title: 'Evaluaciones de seguridad', category: 'EVALUACIÓN', icon: Shield, detail: 'Evaluaciones autorizadas y transparentes, con alcance, controles y evidencias definidos para cada ejecución.' },
    { id: '04', title: 'Controles de acceso empresariales', category: 'GOBERNANZA', icon: Users, detail: 'Más opciones de gobierno del espacio, federación de identidades y permisos granulares.' },
    { id: '05', title: 'Exportaciones de auditoría y cumplimiento', category: 'INFORMES', icon: ExternalLink, detail: 'Historial revisable y exportaciones estructuradas para los flujos operativos y de cumplimiento.' },
  ];
  return <div>
    <PageHeading eyebrow="TRABAJO FUTURO DOCUMENTADO" title="Hoja de ruta empresarial" detail="Un registro transparente de las capacidades aplazadas más allá de la base actual del espacio." action={<span className="roadmap-status"><i /> AÚN NO DISPONIBLE</span>} />
    <div className="roadmap-disclaimer"><div className="disclaimer-mark"><Sparkles size={17} /></div><div><b>Hoja de ruta, no funciones activas</b><p>Estos elementos se documentan como posibilidades futuras. No están disponibles para configuración; en esta fase no se ejecutan análisis, integraciones ni llamadas a IA, ni se generan hallazgos.</p></div></div>
    <div className="roadmap-timeline">{capabilities.map((item, index) => <article className={`roadmap-item reveal ${index > 1 ? 'reveal-delay-1' : ''}`} key={item.id}><div className="roadmap-step"><span>{item.id}</span><i /></div><div className="roadmap-item-icon"><item.icon size={19} /></div><div className="roadmap-item-copy"><span className="panel-kicker">{item.category} · APLAZADO</span><h2>{item.title}</h2><p>{item.detail}</p></div><div className="roadmap-item-state">Aplazado</div></article>)}</div>
    <div className="roadmap-bottom"><div className="bottom-line" /><span>Prioridad actual</span><b>Lo esencial de un espacio fiable</b><Link href="/dashboard" className="text-link">Volver al resumen <ArrowRight size={14} /></Link></div>
  </div>;
}

function AuthPage({ mode }: { mode: 'sign-in' | 'sign-up' }) {
  return <main className="auth-page">
    <div className="auth-left"><div className="auth-top"><Brand inverse /><span className="auth-locale">UE / ES</span></div><div className="auth-art">
      <div className="auth-art-rings"><span /><span /><span /></div><div className="auth-art-center"><ShieldCheck size={39} /><span>ESPACIO PRIVADO</span></div>
      <div className="auth-art-note"><span className="note-led" /> Un espacio compartido. Cada dato, bajo control.</div>
    </div><div className="auth-left-bottom"><span>VIGILANT / ACCESO</span><span>La seguridad empieza por la claridad.</span></div></div>
    <div className="auth-right"><div className="auth-mobile-brand"><Brand /></div><div className="auth-component-wrap"><div className="auth-heading"><span className="eyebrow">{mode === 'sign-in' ? 'HOLA DE NUEVO' : 'EMPIEZA AQUÍ'}</span><h1>{mode === 'sign-in' ? 'Vuelve a tu espacio de trabajo.' : 'Crea un espacio para proteger lo importante.'}</h1><p>{mode === 'sign-in' ? 'Inicia sesión para revisar el espacio de seguridad de tu organización.' : 'Crea tu cuenta y configura el espacio de trabajo de tu organización.'}</p></div>{mode === 'sign-in' ? <SignIn routing="path" path={`${basePath}/sign-in`} signUpUrl={`${basePath}/sign-up`} /> : <SignUp routing="path" path={`${basePath}/sign-up`} signInUrl={`${basePath}/sign-in`} />}</div><div className="auth-right-foot"><LockKeyhole size={13} /> Autenticación segura con Clerk</div></div>
  </main>;
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function DashboardRoute() { return <AuthGuard><WorkspaceFrame page={DashboardPage} /></AuthGuard>; }
function AssetsRoute() { return <AuthGuard><WorkspaceFrame page={AssetsPage} /></AuthGuard>; }
function TeamRoute() { return <AuthGuard><WorkspaceFrame page={TeamPage} /></AuthGuard>; }
function PlansRoute() { return <AuthGuard><WorkspaceFrame page={PlansPage} /></AuthGuard>; }
function RoadmapRoute() { return <AuthGuard><WorkspaceFrame page={() => <RoadmapPage />} /></AuthGuard>; }
function IntegrationsRoute() { return <AuthGuard><WorkspaceFrame page={IntegrationsPage} /></AuthGuard>; }
function IntegrationReadinessRoute() { return <AuthGuard><WorkspaceFrame page={({ workspace }) => <IntegrationReadinessPage workspace={workspace} />} /></AuthGuard>; }
function AiEvaluationRoute() { return <AuthGuard><WorkspaceFrame page={({ workspace }) => <AiEvaluationPage workspace={workspace} />} /></AuthGuard>; }

function Router() {
  return <RoutedErrorBoundary><Switch>
    <Route path="/" component={PublicHome} />
    <Route path="/sign-in/*?" component={() => <AuthPage mode="sign-in" />} />
    <Route path="/sign-up/*?" component={() => <AuthPage mode="sign-up" />} />
    <Route path="/dashboard" component={DashboardRoute} />
    <Route path="/assets" component={AssetsRoute} />
    <Route path="/team" component={TeamRoute} />
    <Route path="/integrations" component={IntegrationsRoute} />
    <Route path="/integration-readiness" component={IntegrationReadinessRoute} />
    <Route path="/ai-evaluations" component={AiEvaluationRoute} />
    <Route path="/plans" component={PlansRoute} />
    <Route path="/roadmap" component={RoadmapRoute} />
    <Route component={NotFound} />
  </Switch></RoutedErrorBoundary>;
}

function ClerkAppProvider() {
  const [, setLocation] = useLocation();
  return <ClerkProvider
    publishableKey={clerkPubKey}
    proxyUrl={clerkProxyUrl}
    signInUrl={`${basePath}/sign-in`}
    signUpUrl={`${basePath}/sign-up`}
    routerPush={to => setLocation(stripBase(to))}
    routerReplace={to => setLocation(stripBase(to), { replace: true })}
    localization={{
      ...esES,
      signIn: {
        ...(esES.signIn ?? {}),
        start: {
          ...(esES.signIn?.start ?? {}),
          title: 'Te damos la bienvenida',
          subtitle: 'Inicia sesión para revisar el espacio de seguridad de tu organización.',
        },
      },
      signUp: {
        ...(esES.signUp ?? {}),
        start: {
          ...(esES.signUp?.start ?? {}),
          title: 'Crea tu cuenta',
          subtitle: 'Configura el espacio de trabajo de tu organización.',
        },
      },
    }}
    appearance={{
      options: {
        logoPlacement: 'inside',
        logoLinkUrl: basePath || '/',
        logoImageUrl: `${window.location.origin}${basePath}/logo.svg`,
      },
      variables: {
        colorPrimary: '#28745b',
        colorForeground: '#203043',
        colorMutedForeground: '#6d7880',
        colorDanger: '#ad4c41',
        colorBackground: '#fbfaf6',
        colorInput: '#fffefa',
        colorInputForeground: '#203043',
        colorNeutral: '#ddd9cf',
        fontFamily: 'DM Sans, sans-serif',
        borderRadius: '0.5rem',
      },
      elements: {
        rootBox: 'w-full flex justify-center',
        cardBox: 'bg-[#fbfaf6] rounded-xl w-[440px] max-w-full overflow-hidden',
        card: '!shadow-none !border-0 !bg-transparent !rounded-none',
        footer: '!shadow-none !border-0 !bg-transparent !rounded-none',
        headerTitle: 'text-[#203043] font-semibold',
        headerSubtitle: 'text-[#6d7880]',
        socialButtonsBlockButtonText: 'text-[#203043]',
        formFieldLabel: 'text-[#43566a]',
        footerActionLink: 'text-[#28745b]',
        footerActionText: 'text-[#6d7880]',
        dividerText: 'text-[#6d7880]',
        identityPreviewEditButton: 'text-[#28745b]',
        formFieldSuccessText: 'text-[#28745b]',
        alertText: 'text-[#8b3f36]',
        logoBox: 'mb-4',
        logoImage: 'max-h-10',
        socialButtonsBlockButton: 'border-[#ddd9cf] bg-[#fffefa]',
        formButtonPrimary: 'bg-[#28745b] hover:bg-[#1e5c48]',
        formFieldInput: 'border-[#ddd9cf] bg-[#fffefa] text-[#203043]',
        footerAction: 'bg-transparent',
        dividerLine: 'bg-[#ddd9cf]',
        alert: 'bg-[#fbf1ee] border-[#e5c7c1]',
        otpCodeFieldInput: 'border-[#ddd9cf] bg-[#fffefa] text-[#203043]',
        formFieldRow: 'text-[#43566a]',
        main: 'text-[#203043]',
      },
    }}
  >
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <IdentityCacheBoundary><Router /></IdentityCacheBoundary>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  </ClerkProvider>;
}

function App() {
  return <WouterRouter base={basePath}><ClerkAppProvider /></WouterRouter>;
}

export default App;
