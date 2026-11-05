import React, { useMemo, useState } from 'react';
import {
  Activity, ArrowDownRight, ArrowRight, BadgeCheck, Ban, Check,
  ChevronDown, CircleHelp, Cloud, Code2, Database, FileSearch, Globe2, LockKeyhole,
  Mail, Network, RotateCcw, Shield, ShieldAlert, WalletCards,
} from 'lucide-react';
import './_group.css';

type Decision = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'NO_PROPOSAL';
type Profile = {
  id: string;
  name: string;
  icon: React.ElementType;
  purpose: string;
  threat: string;
  benign: string;
  adversarial: string;
};

const profiles: Profile[] = [
  { id: 'correo', name: 'Correo', icon: Mail, purpose: 'Lectura acotada y borradores locales.', threat: 'Phishing, exfiltración y envíos no autorizados.', benign: 'Preparar un borrador local', adversarial: 'Envío externo con datos sensibles' },
  { id: 'datos', name: 'Bases de datos', icon: Database, purpose: 'Consulta de registros dentro del espacio.', threat: 'Extracción masiva, borrados y cambios.', benign: 'Consultar un registro sintético', adversarial: 'Exportar datos y modificar registros' },
  { id: 'finanzas', name: 'Finanzas', icon: WalletCards, purpose: 'Lectura de facturas ficticias.', threat: 'Beneficiarios y pagos sin aprobación.', benign: 'Leer una factura ficticia', adversarial: 'Solicitar un pago a beneficiario nuevo' },
  { id: 'programacion', name: 'Programación', icon: Code2, purpose: 'Propuesta de cambio local de ejemplo.', threat: 'Comandos, secretos y ediciones no autorizadas.', benign: 'Proponer un cambio acotado', adversarial: 'Ejecutar comando y leer secretos' },
  { id: 'atencion', name: 'Atención al cliente', icon: CircleHelp, purpose: 'Borrador de respuesta a un ticket.', threat: 'Suplantación y cambios de cuenta.', benign: 'Redactar respuesta a un ticket', adversarial: 'Cambiar datos de cuenta por petición' },
  { id: 'navegador', name: 'Navegador web', icon: Globe2, purpose: 'Lectura de páginas locales sintéticas.', threat: 'Prompt injection y formularios externos.', benign: 'Leer una página de laboratorio', adversarial: 'Enviar un formulario externo' },
  { id: 'infraestructura', name: 'Infraestructura', icon: Cloud, purpose: 'Consulta de configuración ficticia.', threat: 'Privilegios, configuración y borrados.', benign: 'Consultar configuración de ejemplo', adversarial: 'Conceder privilegios de administrador' },
  { id: 'multiagente', name: 'Multiagente', icon: Network, purpose: 'Delegación de solo lectura acotada.', threat: 'Delegación y escalada de permisos.', benign: 'Delegar una lectura limitada', adversarial: 'Escalar permisos mediante delegación' },
];

const decisionMeta: Record<Decision, { label: string; icon: React.ElementType; description: string }> = {
  ALLOW: { label: 'ALLOW', icon: Check, description: 'Permitida solo dentro del simulador local.' },
  DENY: { label: 'DENY', icon: Ban, description: 'Bloqueada por política antes de cualquier acción.' },
  REQUIRE_APPROVAL: { label: 'REQUIRE_APPROVAL', icon: ShieldAlert, description: 'Necesitaría aprobación humana; aquí no se solicita.' },
  NO_PROPOSAL: { label: 'NO_PROPOSAL', icon: CircleHelp, description: 'No se recibió una propuesta. No es una denegación.' },
};

function getDecision(profile: Profile, kind: 'benign' | 'adversarial'): Decision {
  if (profile.id === 'correo' && kind === 'adversarial') return 'DENY';
  if (kind === 'benign') return 'ALLOW';
  if (profile.id === 'finanzas' || profile.id === 'atencion') return 'REQUIRE_APPROVAL';
  if (profile.id === 'multiagente') return 'DENY';
  return 'DENY';
}

export function Redesign() {
  const [selectedProfile, setSelectedProfile] = useState('correo');
  const [caseKind, setCaseKind] = useState<'benign' | 'adversarial'>('adversarial');
  const [result, setResult] = useState<{ decision: Decision; profileId: string; kind: 'benign' | 'adversarial' } | null>({
    decision: 'DENY', profileId: 'correo', kind: 'adversarial',
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const active = profiles.find((profile) => profile.id === selectedProfile) ?? profiles[0];
  const activeResult = result?.profileId === selectedProfile && result.kind === caseKind ? result : null;
  const caseLabel = caseKind === 'benign' ? active.benign : active.adversarial;
  const resultDecision = activeResult?.decision ?? null;
  const meta = resultDecision ? decisionMeta[resultDecision] : null;
  const OutcomeIcon = meta?.icon;
  const evidenceHash = useMemo(() => `sha256:fixture-${active.id}-${caseKind}-7f3a91`, [active.id, caseKind]);

  const chooseProfile = (id: string) => {
    setSelectedProfile(id);
    setError(false);
    setEvidenceOpen(false);
  };
  const chooseCase = (kind: 'benign' | 'adversarial') => {
    setCaseKind(kind);
    setError(false);
    setEvidenceOpen(false);
  };
  const runScenario = () => {
    if (busy) return;
    setBusy(true);
    setError(false);
    setResult(null);
    window.setTimeout(() => {
      try {
        const profile = profiles.find((item) => item.id === selectedProfile);
        if (!profile) throw new Error('Fixture no disponible');
        setResult({ decision: getDecision(profile, caseKind), profileId: profile.id, kind: caseKind });
      } catch {
        setError(true);
      } finally {
        setBusy(false);
      }
    }, 650);
  };
  const reset = () => {
    setSelectedProfile('correo');
    setCaseKind('adversarial');
    setResult({ decision: 'DENY', profileId: 'correo', kind: 'adversarial' });
    setError(false);
    setBusy(false);
    setEvidenceOpen(false);
  };

  return (
    <main className="gnx-lab">
      <style>{`
        .gnx-lab{--gn-ink:#173047;--gn-navy:#14364a;--gn-teal:#087d77;--gn-teal-dark:#086660;--gn-mint:#e5f3ef;--gn-paper:#f4f6f3;--gn-surface:#fffefa;--gn-line:#dce5e1;--gn-muted:#4d626b;--gn-warm:#a66e36;min-height:100vh;background:#f1f4f2;color:var(--gn-ink);font-family:var(--font-sans,'DM Sans',sans-serif);padding:clamp(16px,4vw,44px);box-sizing:border-box}
        .gnx-lab *{box-sizing:border-box}.gnx-shell{max-width:1120px;margin:0 auto;border:1px solid #dce5e1;border-radius:20px;background:#fffefa;overflow:hidden;box-shadow:0 16px 50px rgba(23,48,71,.07)}
        .gnx-topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:22px clamp(20px,4vw,42px);border-bottom:1px solid var(--gn-line);background:#fbfcfa}
        .gnx-brand{display:flex;align-items:center;gap:11px}.gnx-mark{display:grid;place-items:center;width:36px;height:36px;border-radius:11px;background:var(--gn-navy);color:#c5eee3}.gnx-brand-name{font-size:13px;font-weight:750;letter-spacing:.02em;color:var(--gn-navy)}.gnx-brand-sub{display:block;margin-top:2px;color:#566b74;font-size:11px;letter-spacing:.12em;text-transform:uppercase}
        .gnx-fixture{display:flex;align-items:center;gap:8px;padding:8px 11px;border:1px solid #d7e7df;border-radius:99px;background:#f0f7f3;color:#245d51;font:500 12px var(--font-mono,'DM Mono',monospace)}
        .gnx-hero{padding:clamp(26px,5vw,48px) clamp(20px,4vw,42px) 25px}.gnx-eyebrow{display:flex;align-items:center;gap:9px;margin:0 0 13px;color:var(--gn-teal-dark);font:500 11px var(--font-mono,'DM Mono',monospace);letter-spacing:.11em;text-transform:uppercase}
        .gnx-eyebrow:before{content:'';width:24px;height:1px;background:#80b8aa}.gnx-hero h1{margin:0;color:var(--gn-navy);font:700 clamp(28px,4vw,42px)/1.12 var(--font-display,'Manrope',sans-serif);letter-spacing:-.04em}.gnx-hero>p{max-width:650px;margin:13px 0 0;color:#465e68;font-size:14px;line-height:1.65}
        .gnx-disclaimer{display:flex;align-items:flex-start;gap:10px;margin:0 clamp(20px,4vw,42px) 26px;padding:12px 14px;border:1px solid #eadfca;border-radius:10px;background:#fbf7ee;color:#554c3e;font-size:12px;line-height:1.55}.gnx-disclaimer svg{flex:none;color:var(--gn-warm);margin-top:1px}
        .gnx-content{padding:0 clamp(20px,4vw,42px) 36px}.gnx-section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:14px}.gnx-step{display:flex;align-items:center;gap:9px;color:#536972;font:500 11px var(--font-mono,'DM Mono',monospace);letter-spacing:.08em;text-transform:uppercase}.gnx-step-num{display:grid;place-items:center;width:24px;height:24px;border:1px solid #c8dfd6;border-radius:50%;background:#f0f7f4;color:var(--gn-teal-dark);font-size:12px}
        .gnx-section-head h2{margin:5px 0 0;color:var(--gn-navy);font:650 19px var(--font-display,'Manrope',sans-serif);letter-spacing:-.025em}.gnx-profile-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:9px}
        .gnx-profile{display:flex;align-items:flex-start;gap:11px;min-height:94px;padding:13px;border:1px solid var(--gn-line);border-radius:12px;background:#fff;cursor:pointer;text-align:left;color:inherit;transition:transform .16s ease,border-color .16s ease,background .16s ease}
        .gnx-profile:hover{transform:translateY(-1px);border-color:#a9ccc0}.gnx-profile[aria-pressed=true]{border-color:#16877e;background:#f1f9f6;box-shadow:inset 0 0 0 1px #16877e}
        .gnx-profile-icon{display:grid;place-items:center;flex:none;width:32px;height:32px;border-radius:9px;background:#edf3f1;color:#315e61}.gnx-profile[aria-pressed=true] .gnx-profile-icon{background:#dcefe8;color:#08766e}
        .gnx-profile strong{display:block;color:#1c3b4d;font-size:13px;font-weight:700}.gnx-profile small{display:block;margin-top:5px;color:#4f646c;font-size:12px;line-height:1.5}.gnx-profile small b{color:#78562f;font-weight:700}
        .gnx-case-area{margin-top:30px;padding-top:25px;border-top:1px solid #e6ebe8}.gnx-case-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.gnx-case{display:flex;align-items:flex-start;gap:12px;min-height:94px;padding:16px;border:1px solid var(--gn-line);border-radius:13px;background:#fff;cursor:pointer;text-align:left;color:inherit;transition:border-color .16s ease,background .16s ease}
        .gnx-case:hover{border-color:#9fc7b9}.gnx-case[aria-pressed=true]{border-color:#16877e;background:#f2f9f6;box-shadow:inset 0 0 0 1px #16877e}.gnx-case-icon{display:grid;place-items:center;flex:none;width:34px;height:34px;border:1px solid #dce9e3;border-radius:10px;color:#277767;background:#f4f8f5}.gnx-case[data-kind=adversarial] .gnx-case-icon{color:#a56e39;background:#fbf6ec;border-color:#eee2ca}
        .gnx-case strong{display:block;margin:1px 0 5px;color:#1d3b4d;font-size:14px}.gnx-case small{color:#4f646c;font-size:12px;line-height:1.55}
        .gnx-action-row{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-top:20px}.gnx-local-note{display:flex;align-items:center;gap:7px;color:#4f646c;font:12px var(--font-mono,'DM Mono',monospace)}.gnx-run{display:inline-flex;align-items:center;justify-content:center;gap:9px;min-height:46px;padding:0 21px;border:0;border-radius:10px;background:var(--gn-teal);color:#fff;font-size:14px;font-weight:700;cursor:pointer;box-shadow:0 4px 10px rgba(8,125,119,.14);transition:background .15s ease,transform .15s ease}.gnx-run:hover:not(:disabled){background:var(--gn-teal-dark);transform:translateY(-1px)}.gnx-run:disabled{cursor:wait;opacity:.75}.gnx-reset{display:inline-flex;align-items:center;gap:7px;padding:8px 10px;border:1px solid transparent;border-radius:8px;background:transparent;color:#4f646c;font-size:12px;cursor:pointer}.gnx-reset:hover{border-color:#dbe6e1;background:#f6f9f7;color:var(--gn-navy)}
        .gnx-result{position:relative;margin-top:27px;border:1px solid var(--gn-line);border-radius:15px;background:#fff;overflow:hidden}.gnx-result:before{position:absolute;inset:0 auto 0 0;width:4px;background:#a9b8b6;content:''}.gnx-result[data-decision=DENY]:before{background:#b14d42}.gnx-result[data-decision=ALLOW]:before{background:#16877e}.gnx-result[data-decision=REQUIRE_APPROVAL]:before{background:#c18b40}.gnx-result[data-decision=NO_PROPOSAL]:before{background:#7b8b94}
        .gnx-result-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;padding:22px 24px 17px}.gnx-outcome{display:flex;align-items:center;gap:11px}.gnx-outcome-icon{display:grid;place-items:center;width:38px;height:38px;border-radius:11px;background:#edf2f0;color:#536b6a}.gnx-result[data-decision=DENY] .gnx-outcome-icon{background:#fbefed;color:#a7443a}.gnx-result[data-decision=ALLOW] .gnx-outcome-icon{background:#e4f4ef;color:#08776c}.gnx-result[data-decision=REQUIRE_APPROVAL] .gnx-outcome-icon{background:#faf2e3;color:#926328}.gnx-result[data-decision=NO_PROPOSAL] .gnx-outcome-icon{background:#eef2f3;color:#5b6c75}
        .gnx-outcome-label{color:#71818a;font:500 9px var(--font-mono,'DM Mono',monospace);letter-spacing:.12em;text-transform:uppercase}.gnx-outcome h3{margin:4px 0 0;color:#1b394a;font:700 20px var(--font-display,'Manrope',sans-serif);letter-spacing:-.025em}.gnx-policy-pill{display:inline-flex;align-items:center;gap:6px;padding:7px 9px;border:1px solid #d7e8df;border-radius:99px;background:#f2f8f4;color:#356951;font:500 10px var(--font-mono,'DM Mono',monospace);white-space:nowrap}
        .gnx-result-copy{padding:0 24px 18px 73px;color:#405a64;font-size:14px;line-height:1.6}.gnx-result-copy strong{color:#294657}.gnx-result-meta{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:13px 24px;border-top:1px solid #edf0ed;background:#fafbf9;color:#4d626b;font-size:12px}
        .gnx-detail-toggle{display:flex;align-items:center;justify-content:space-between;width:100%;padding:14px 23px;border:0;border-top:1px solid #e9eeeb;background:transparent;color:#31565e;font-size:13px;font-weight:650;text-align:left;cursor:pointer}.gnx-detail-toggle:hover{background:#f8faf8}.gnx-details{padding:0 23px 18px}.gnx-evidence-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.gnx-evidence{padding:12px;border:1px solid #e4ebe7;border-radius:9px;background:#fbfcfa}.gnx-evidence span{display:block;margin-bottom:6px;color:#536971;font:10px var(--font-mono,'DM Mono',monospace);letter-spacing:.06em;text-transform:uppercase}.gnx-evidence strong{display:block;color:#36515e;font-size:12px;line-height:1.5}.gnx-evidence code{font:11px var(--font-mono,'DM Mono',monospace);overflow-wrap:anywhere}
        .gnx-off-note{display:flex;gap:9px;margin-top:10px;padding:11px 12px;border-radius:8px;background:#f8f5ed;color:#594d39;font-size:12px;line-height:1.55}.gnx-off-note svg{flex:none;color:#8d682f}.gnx-outcomes{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:19px}.gnx-outcome-key{padding:10px 11px;border:1px solid #e3eae6;border-radius:9px;background:#fbfcfa}.gnx-outcome-key strong{display:block;color:#38505c;font:600 11px var(--font-mono,'DM Mono',monospace);letter-spacing:.02em}.gnx-outcome-key p{margin:5px 0 0;color:#4d626b;font-size:12px;line-height:1.45}.gnx-outcome-key[data-tone=deny]{border-left:2px solid #b14d42}.gnx-outcome-key[data-tone=allow]{border-left:2px solid #16877e}.gnx-outcome-key[data-tone=approval]{border-left:2px solid #c18b40}.gnx-outcome-key[data-tone=none]{border-left:2px solid #7b8b94}
        .gnx-state-message{display:flex;align-items:center;gap:10px;margin-top:22px;padding:15px 17px;border:1px solid #e6d8c1;border-radius:11px;background:#fcf8ef;color:#594b36;font-size:13px}.gnx-state-message.error{border-color:#e7c7c2;background:#fff5f3;color:#963e34}.gnx-state-message.loading{border-color:#d4e5df;background:#f3f9f6;color:#285b50}
        .gnx-foot{display:flex;align-items:center;justify-content:space-between;gap:15px;padding:15px clamp(20px,4vw,42px);border-top:1px solid var(--gn-line);background:#f8faf8;color:#4d626b;font-size:12px}.gnx-foot b{color:#38565d;font-weight:650}.gnx-lab button:focus-visible{outline:3px solid #d28a42;outline-offset:3px}.gnx-lab button:focus:not(:focus-visible){outline:none}
        @media(max-width:800px){.gnx-profile-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.gnx-outcomes{grid-template-columns:repeat(2,minmax(0,1fr))}}
        @media(max-width:560px){.gnx-lab{padding:10px}.gnx-shell{border-radius:14px}.gnx-topbar{align-items:flex-start;padding:15px 16px}.gnx-fixture{font-size:11px;padding:7px 8px}.gnx-brand-name{font-size:12px}.gnx-brand-sub{font-size:10px}.gnx-hero{padding:25px 17px 18px}.gnx-hero>p{font-size:13px}.gnx-disclaimer{margin:0 16px 21px;font-size:12px}.gnx-content{padding:0 16px 25px}.gnx-profile-grid{grid-template-columns:1fr;gap:8px}.gnx-profile{min-height:82px;padding:12px;gap:10px}.gnx-profile-icon{width:30px;height:30px}.gnx-profile strong{font-size:13px}.gnx-profile small{font-size:12px}.gnx-case-grid{grid-template-columns:1fr}.gnx-case{min-height:76px;padding:12px}.gnx-action-row{align-items:stretch;flex-direction:column}.gnx-run{width:100%}.gnx-local-note{justify-content:center}.gnx-result-head{padding:17px 16px 13px;flex-direction:column;gap:11px}.gnx-result-copy{padding:0 16px 16px;font-size:13px}.gnx-result-meta{align-items:flex-start;flex-direction:column;padding:11px 16px;font-size:12px}.gnx-details{padding:0 14px 14px}.gnx-evidence-grid{grid-template-columns:1fr}.gnx-outcomes{grid-template-columns:1fr 1fr;gap:6px}.gnx-outcome-key{padding:9px}.gnx-foot{align-items:flex-start;flex-direction:column;padding:13px 17px}.gnx-section-head{align-items:flex-start;flex-direction:column}}
        @media(prefers-reduced-motion:reduce){.gnx-lab *, .gnx-lab *:before,.gnx-lab *:after{scroll-behavior:auto!important;transition:none!important;animation-duration:.01ms!important;animation-iteration-count:1!important}}
      `}</style>
      <div className="gnx-shell">
        <header className="gnx-topbar">
          <div className="gnx-brand">
            <span className="gnx-mark" aria-hidden="true"><Shield size={19} /></span>
            <div><div className="gnx-brand-name">GUARDIAN NEXUS</div><span className="gnx-brand-sub">Policy lab · recorrido guiado</span></div>
          </div>
          <span className="gnx-fixture"><Activity size={13} /> Fixture determinista · simulación local</span>
        </header>

        <section className="gnx-hero">
          <p className="gnx-eyebrow">ENTORNO CONTROLADO · SOLO DATOS SINTÉTICOS</p>
          <h1>Inspecciona antes de actuar.</h1>
          <p>Comprueba cómo una política independiente evalúa propuestas de agentes. Sigue el origen, la decisión y la evidencia de un caso ficticio, paso a paso.</p>
        </section>

        <aside className="gnx-disclaimer" role="note">
          <LockKeyhole size={15} />
          <span><strong>Prueba visual, no integración.</strong> No hay modelos, proveedores, red ni acciones reales conectados. Cada resultado es una fixture ilustrativa y no una afirmación de eficacia.</span>
        </aside>

        <div className="gnx-content">
          <section aria-labelledby="profiles-heading">
            <div className="gnx-section-head">
              <div><div className="gnx-step"><span className="gnx-step-num">1</span> Elige un perfil</div><h2 id="profiles-heading">¿Qué agente quieres poner a prueba?</h2></div>
              <button type="button" className="gnx-reset" onClick={reset}><RotateCcw size={14} /> Reiniciar</button>
            </div>
            <div className="gnx-profile-grid" role="group" aria-label="Perfiles de agente">
              {profiles.map((profile) => {
                const Icon = profile.icon;
                return <button key={profile.id} className="gnx-profile" type="button" aria-pressed={selectedProfile === profile.id} onClick={() => chooseProfile(profile.id)}>
                  <span className="gnx-profile-icon"><Icon size={16} /></span>
                  <span><strong>{profile.name}</strong><small>{profile.purpose}<br /><b>Riesgo:</b> {profile.threat}</small></span>
                </button>;
              })}
            </div>
          </section>

          <section className="gnx-case-area" aria-labelledby="case-heading">
            <div className="gnx-section-head">
              <div><div className="gnx-step"><span className="gnx-step-num">2</span> Selecciona una fixture</div><h2 id="case-heading">¿Qué quieres comprobar?</h2></div>
            </div>
            <div className="gnx-case-grid" role="group" aria-label="Tipo de escenario">
              <button type="button" className="gnx-case" data-kind="benign" aria-pressed={caseKind === 'benign'} onClick={() => chooseCase('benign')}>
                <span className="gnx-case-icon"><BadgeCheck size={18} /></span><span><strong>Caso benigno</strong><small>{active.benign}. Una tarea de laboratorio dentro del permiso mínimo.</small></span>
              </button>
              <button type="button" className="gnx-case" data-kind="adversarial" aria-pressed={caseKind === 'adversarial'} onClick={() => chooseCase('adversarial')}>
                <span className="gnx-case-icon"><ShieldAlert size={18} /></span><span><strong>Intento adversario</strong><small>{active.adversarial}. Contenido sintético que no puede autorizar acciones.</small></span>
              </button>
            </div>
            <div className="gnx-action-row">
              <span className="gnx-local-note"><LockKeyhole size={13} /> Sin API · sin red · sin ejecución</span>
              <button className="gnx-run" type="button" onClick={runScenario} disabled={busy} aria-live="polite">
                {busy ? <Activity className="gnx-spin" size={16} /> : <FileSearch size={16} />}
                {busy ? 'Evaluando fixture…' : 'Probar escenario'}
                {!busy && <ArrowRight size={15} />}
              </button>
            </div>
            <style>{`.gnx-spin{animation:gnx-rotate .8s linear infinite}@keyframes gnx-rotate{to{transform:rotate(360deg)}}`}</style>
          </section>

          {busy && <div className="gnx-state-message loading" role="status"><Activity size={16} /> Evaluando la fixture local y preparando la evidencia redactada…</div>}
          {error && <div className="gnx-state-message error" role="alert"><ShieldAlert size={16} /> No se pudo cargar esta fixture local. Prueba a reiniciar el recorrido.</div>}
          {!busy && !error && !activeResult && <div className="gnx-state-message" role="status"><ArrowDownRight size={16} /> Elige el perfil y el caso; después prueba el escenario para ver una decisión determinista.</div>}

          {activeResult && !busy && meta && OutcomeIcon && <section className="gnx-result" data-decision={resultDecision} aria-labelledby="result-heading" aria-live="polite">
            <div className="gnx-result-head">
              <div className="gnx-outcome"><span className="gnx-outcome-icon"><OutcomeIcon size={19} /></span><div><div className="gnx-outcome-label">Decisión determinista · Policy ON</div><h3 id="result-heading">{meta.label}</h3></div></div>
              <span className="gnx-policy-pill"><Shield size={13} /> Política independiente · ON</span>
            </div>
            <div className="gnx-result-copy">
              <strong>{resultDecision === 'DENY' ? 'Propuesta bloqueada.' : resultDecision === 'ALLOW' ? 'Propuesta permitida en el simulador.' : resultDecision === 'REQUIRE_APPROVAL' ? 'La política exigiría aprobación humana.' : 'No se generó una propuesta para evaluar.'}</strong>
              {' '}{resultDecision === 'DENY' ? `${active.name}: se intentó ${caseLabel.toLowerCase()}, fuera del permiso concedido. No se ejecutó ninguna acción.` : resultDecision === 'ALLOW' ? `${caseLabel}. Se representa únicamente en estado efímero y sintético.` : resultDecision === 'REQUIRE_APPROVAL' ? 'La decisión no crea una aprobación ni activa una bandeja; no se envía ni ejecuta nada.' : 'La ausencia de propuesta significa que no hubo acción que revisar; no equivale a DENY.'}
            </div>
            <div className="gnx-result-meta">
              <span><b>Origen:</b> fixture controlada · contenido sintético · agente de demostración</span>
              <span><b>Efectos:</b> 0 acciones reales</span>
            </div>
            <button type="button" className="gnx-detail-toggle" aria-expanded={evidenceOpen} onClick={() => setEvidenceOpen(!evidenceOpen)}>
              <span>Inspeccionar evidencia redactada</span><ChevronDown size={15} style={{ transform: evidenceOpen ? 'rotate(180deg)' : undefined }} />
            </button>
            {evidenceOpen && <div className="gnx-details">
              <div className="gnx-evidence-grid">
                <div className="gnx-evidence"><span>Origen de propuesta</span><strong>Fixture local · {active.name} · {caseKind === 'benign' ? 'solicitud de usuario sintética' : 'contenido no confiable sintético'}</strong></div>
                <div className="gnx-evidence"><span>Evaluación de política</span><strong>{meta.label} · {meta.description}</strong></div>
                <div className="gnx-evidence"><span>Evidencia de caso · redactada</span><strong><code>{evidenceHash}</code></strong></div>
              </div>
              <div className="gnx-off-note"><LockKeyhole size={14} /><span><b>Policy OFF · contrafactual en clon desechable únicamente.</b> Es una comparación conceptual; nunca se ejecuta. No se muestran prompts ni argumentos en bruto.</span></div>
            </div>}
          </section>}

          <section aria-label="Significado de los resultados" className="gnx-outcomes">
            <div className="gnx-outcome-key" data-tone="allow"><strong>ALLOW</strong><p>Permitida dentro del simulador efímero.</p></div>
            <div className="gnx-outcome-key" data-tone="deny"><strong>DENY</strong><p>Bloqueada por política antes de actuar.</p></div>
            <div className="gnx-outcome-key" data-tone="approval"><strong>REQUIRE_APPROVAL</strong><p>Necesita revisión humana; aquí no se activa.</p></div>
            <div className="gnx-outcome-key" data-tone="none"><strong>NO_PROPOSAL</strong><p>No llegó propuesta; no es DENY.</p></div>
          </section>
        </div>
        <footer className="gnx-foot">
          <span><b>Guardian Nexus Lab</b> · Fixtures deterministas para inspección visual</span>
          <span>Sin conexión externa · Sin cambios persistentes</span>
        </footer>
      </div>
    </main>
  );
}
