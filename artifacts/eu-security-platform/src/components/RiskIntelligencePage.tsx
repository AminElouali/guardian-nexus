import React, { useState, type FormEvent } from "react";
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  BadgeCheck,
  BookOpenCheck,
  Code2,
  Database,
  Globe,
  Headset,
  Mail,
  Network,
  Server,
  ShieldCheck,
  Wallet,
} from "lucide-react";
import { Link } from "wouter";
import {
  RISK_INTELLIGENCE_CATALOG,
  type AgentRiskProfile,
  type ControlEvidenceStatus,
  type RiskProfileId,
  type ReviewState,
} from "@/risk-intelligence/catalog.v1";
import {
  analyzeDeclaredCapabilities,
  type CapabilityAnalysis,
  type DataSensitivity,
} from "@/risk-intelligence/capability-discovery.v1";

const statusText: Record<ReviewState, string> = {
  prepared_not_executed: "Preparado · no ejecutado",
  design_only: "Diseño inicial · no probado",
};

const evidenceStatusText: Record<ControlEvidenceStatus, string> = {
  historical_artifact_not_currently_reproducible: "Histórico · no reproducible ahora",
  historical_fixture_only: "Prueba fixture · no inferencia Qwen",
  blocked_by_current_host_preflight: "Bloqueado por el preflight del host",
  not_verified_in_this_phase: "No verificado en esta fase",
};

const iconByProfile: Record<string, typeof Mail> = {
  email: Mail,
  database: Database,
  finance: Wallet,
  programming: Code2,
  "customer-support": Headset,
  browser: Globe,
  infrastructure: Server,
  multiagent: Network,
};

const signalFields = [
  ["untrustedInputs", "Lee contenido no confiable (correo, documento, fila o página)"],
  ["externalRecipients", "Puede enviar a destinatarios o destinos externos"],
  ["persistentEffects", "Puede cambiar estado persistente"],
  ["destructiveOperations", "Incluye operaciones destructivas"],
  ["privilegeChanges", "Puede cambiar roles o privilegios"],
  ["delegation", "Puede delegar a otros agentes"],
  ["approvalRequired", "Declara que algunas acciones requieren aprobación"],
] as const;

type SignalKey = (typeof signalFields)[number][0];
type WorkspaceRole = "owner" | "admin" | "analyst" | "viewer" | string;

function ReferenceList({ ids }: { ids: string[] }) {
  const sources = RISK_INTELLIGENCE_CATALOG.sources.filter((source) => ids.includes(source.id));
  return <span>{sources.map((source) => source.name).join(" · ") || "Referencia STPA interna"}</span>;
}

function ProfileCard({
  profile,
  showTechnicalDetails,
}: {
  profile: AgentRiskProfile;
  showTechnicalDetails: boolean;
}) {
  const Icon = iconByProfile[profile.id] ?? Mail;
  const relatedControls = profile.controlEvidenceRefs
    .map((id) => RISK_INTELLIGENCE_CATALOG.controlEvidenceSnapshot.records.find((record) => record.id === id))
    .filter((record) => record !== undefined);
  const itemGroups = [
    ["Pérdidas consideradas", profile.losses],
    ["Peligros", profile.hazards],
    ["Acciones de control inseguras", profile.unsafeControlActions],
    ["Escenarios causales", profile.causalScenarios],
    ["Restricciones verificables", profile.constraints],
  ] as const;

  return (
    <article className="risk-intelligence-profile" data-testid={`risk-profile-${profile.id}`}>
      <div className="risk-intelligence-profile-head">
        <span className="risk-intelligence-icon"><Icon size={18} aria-hidden="true" /></span>
        <div>
          <span className="panel-kicker">VERTICAL · {statusText[profile.state]}</span>
          <h3>{profile.title}</h3>
        </div>
      </div>
      <p className="risk-profile-summary">{profile.executiveSummary}</p>
      <ul className="risk-intelligence-scope">
        {profile.toolAndPermissionScope.map((scope) => <li key={scope}>{scope}</li>)}
      </ul>
      <p className="risk-profile-primary-risk">
        <AlertTriangle size={14} aria-hidden="true" />
        <span><b>Riesgo principal:</b> {profile.hazards[0]?.title ?? "Pendiente de modelado"}</span>
      </p>
      <details className="risk-associated-controls">
        <summary>Controles asociados y estado de evidencia<span>{relatedControls.length}</span></summary>
        {relatedControls.length === 0 ? (
          <p className="risk-intelligence-pending">No hay controles asociados documentados.</p>
        ) : (
          <ul>
            {relatedControls.map((record) => (
              <li key={record.id}>
                <div className="risk-associated-control-head">
                  <b>{record.title}</b>
                  <span className={`risk-evidence-status risk-evidence-status-${record.status}`}>
                    {evidenceStatusText[record.status]}
                  </span>
                </div>
                <p>{record.result}</p>
                <small>{record.limitation}</small>
                {showTechnicalDetails && (
                  <>
                    {record.technicalDetails && <small>{record.technicalDetails}</small>}
                    <small className="risk-evidence-ref">{record.evidenceRef}</small>
                    {record.evidenceSha256 && <code className="risk-evidence-hash">SHA-256 {record.evidenceSha256}</code>}
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
      </details>
      {showTechnicalDetails && (
        <div className="risk-intelligence-groups">
          {itemGroups.map(([label, entries]) => (
            <details key={label} open={label === "Restricciones verificables"}>
              <summary>{label}<span>{entries.length}</span></summary>
              {entries.length === 0 ? (
                <p className="risk-intelligence-pending">No hay elementos registrados en esta categoría.</p>
              ) : (
                <ul>
                  {entries.map((entry) => (
                    <li key={entry.id} data-testid={`risk-item-${entry.id}`}>
                      <b>{entry.id} · {entry.title}</b>
                      <p>{entry.description}</p>
                      <small><ReferenceList ids={entry.sourceRefs} /> · Estado: {statusText[entry.state]}</small>
                    </li>
                  ))}
                </ul>
              )}
            </details>
          ))}
          <details>
            <summary>Pruebas sintéticas especificadas<span>{profile.syntheticTestSpecs.length}</span></summary>
            {profile.syntheticTestSpecs.length === 0 ? (
              <p className="risk-intelligence-pending">No hay casos preparados.</p>
            ) : (
              <ul>
                {profile.syntheticTestSpecs.map((testCase) => (
                  <li key={testCase.id} data-testid={`risk-test-${testCase.id}`}>
                    <b>{testCase.id} · {testCase.title}</b>
                    <p><strong>Entrada sintética:</strong> {testCase.syntheticInput}</p>
                    <p><strong>Objetivo:</strong> {testCase.controlObjective}</p>
                    <small><ReferenceList ids={testCase.sourceRefs} /> · No ejecutada</small>
                  </li>
                ))}
              </ul>
            )}
          </details>
        </div>
      )}
    </article>
  );
}

function ControlEvidencePanel({ detailed }: { detailed: boolean }) {
  return (
    <section className="risk-evidence-section" aria-labelledby="risk-evidence-heading">
      <div className="risk-intelligence-section-heading">
        <div>
          <span className="panel-kicker">ESTADO DE EVIDENCIA</span>
          <h2 id="risk-evidence-heading">Qué está probado y qué no</h2>
        </div>
        <span>Snapshot local · {RISK_INTELLIGENCE_CATALOG.controlEvidenceSnapshot.observedAt}</span>
      </div>
      <p className="risk-evidence-freshness">
        {RISK_INTELLIGENCE_CATALOG.controlEvidenceSnapshot.freshness}
      </p>
      <div className="risk-evidence-grid">
        {RISK_INTELLIGENCE_CATALOG.controlEvidenceSnapshot.records.map((record) => (
          <article key={record.id} data-testid={`risk-evidence-${record.id}`}>
            <div className="risk-evidence-card-head">
              <h3>{record.title}</h3>
              <span className={`risk-evidence-status risk-evidence-status-${record.status}`}>
                {evidenceStatusText[record.status]}
              </span>
            </div>
            <p>{record.result}</p>
            {detailed && record.technicalDetails && (
              <p className="risk-evidence-technical">{record.technicalDetails}</p>
            )}
            {detailed && <small className="risk-evidence-ref">{record.evidenceRef}</small>}
            {detailed && record.evidenceSha256 && (
              <code className="risk-evidence-hash">SHA-256 {record.evidenceSha256}</code>
            )}
            <p className="risk-evidence-limitation">{record.limitation}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

function parseDeclarationList(raw: string): string[] {
  const values = raw.split(",").map((value) => value.trim()).filter(Boolean);
  if (values.length > 12 || values.some((value) => value.length > 80)) {
    throw new Error("risk_capability_list_limit");
  }
  return values;
}

function CapabilityDiscoveryPanel() {
  const [profileId, setProfileId] = useState<RiskProfileId>("email");
  const [toolNames, setToolNames] = useState("leer_mensaje, redactar_borrador");
  const [permissionNames, setPermissionNames] = useState("read:synthetic-mailbox");
  const [dependencies, setDependencies] = useState("simulador_local");
  const [dataSensitivity, setDataSensitivity] = useState<DataSensitivity>("internal");
  const [signals, setSignals] = useState<Record<SignalKey, boolean>>({
    untrustedInputs: true,
    externalRecipients: false,
    persistentEffects: false,
    destructiveOperations: false,
    privilegeChanges: false,
    delegation: false,
    approvalRequired: false,
  });
  const [analysis, setAnalysis] = useState<CapabilityAnalysis | null>(null);
  const [error, setError] = useState("");

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    try {
      setAnalysis(analyzeDeclaredCapabilities({
        profileId,
        toolNames: parseDeclarationList(toolNames),
        permissionNames: parseDeclarationList(permissionNames),
        dependencies: parseDeclarationList(dependencies),
        dataSensitivity,
        ...signals,
      }));
    } catch (cause) {
      setAnalysis(null);
      setError(cause instanceof Error ? cause.message : "risk_capability_declaration_invalid");
    }
  };

  return (
    <section className="risk-discovery-section" aria-labelledby="risk-discovery-heading">
      <div className="risk-intelligence-section-heading">
        <div>
          <span className="panel-kicker">ANÁLISIS LOCAL · SOLO RECOMENDACIONES</span>
          <h2 id="risk-discovery-heading">Explora una declaración sintética de capacidades</h2>
        </div>
        <span>No conecta con agentes ni persiste datos</span>
      </div>
      <p className="risk-discovery-intro">
        Selecciona herramientas, permisos, sensibilidad y efectos declarados. El resultado es
        una lista de riesgos inferidos para revisión humana; no puntúa, autoriza ni ejecuta.
      </p>
      <form className="risk-discovery-form" onSubmit={submit} data-testid="risk-capability-form">
        <label>
          Perfil de laboratorio
          <select className="text-input" value={profileId} onChange={(event) => setProfileId(event.target.value as RiskProfileId)}>
            {RISK_INTELLIGENCE_CATALOG.profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>{profile.title}</option>
            ))}
          </select>
        </label>
        <label>
          Herramientas declaradas
          <input className="text-input" value={toolNames} onChange={(event) => setToolNames(event.target.value)} maxLength={500} />
        </label>
        <label>
          Permisos declarados
          <input className="text-input" value={permissionNames} onChange={(event) => setPermissionNames(event.target.value)} maxLength={500} />
        </label>
        <label>
          Dependencias declaradas
          <input className="text-input" value={dependencies} onChange={(event) => setDependencies(event.target.value)} maxLength={500} />
        </label>
        <label>
          Sensibilidad declarada
          <select className="text-input" value={dataSensitivity} onChange={(event) => setDataSensitivity(event.target.value as DataSensitivity)}>
            <option value="public">Pública</option>
            <option value="internal">Interna</option>
            <option value="confidential">Confidencial</option>
            <option value="secret">Secreta</option>
          </select>
        </label>
        <fieldset>
          <legend>Capacidades declaradas</legend>
          <div className="risk-discovery-signals">
            {signalFields.map(([key, label]) => (
              <label key={key} className="risk-discovery-check">
                <input
                  type="checkbox"
                  checked={signals[key]}
                  onChange={(event) => setSignals((current) => ({ ...current, [key]: event.target.checked }))}
                />
                <span>{label}</span>
              </label>
            ))}
          </div>
        </fieldset>
        {error && <p role="alert" className="risk-discovery-error">{error}</p>}
        <button type="submit" className="button button-primary" data-testid="button-analyze-capabilities">
          Analizar declaración local <ArrowRight size={15} />
        </button>
      </form>
      {analysis && (
        <div className="risk-discovery-results" role="region" aria-live="polite" data-testid="risk-discovery-results">
          <div className="risk-discovery-result-head">
            <div><BadgeCheck size={17} /><b>{analysis.findings.length} hallazgos para revisión</b></div>
            <span>{analysis.profileId} · sin decisión de política</span>
          </div>
          <p>{analysis.evidenceNote}</p>
          {analysis.findings.length === 0 ? (
            <p className="risk-intelligence-pending">No se detectaron señales en esta declaración; esto no demuestra ausencia de riesgos.</p>
          ) : (
            <ul>
              {analysis.findings.map((finding) => (
                <li key={finding.findingId} data-testid={`risk-finding-${finding.findingId}`}>
                  <div className="risk-finding-title">
                    <b>{finding.title}</b>
                    <span>{finding.classification === "known_source_concept" ? "Concepto de fuente" : "Inferido de declaración"} · Pendiente de prueba</span>
                  </div>
                  <p>{finding.rationale}</p>
                  <p><strong>Recomendación:</strong> {finding.recommendation}</p>
                  <small>Referencias internas: {finding.riskItemRefs.join(", ") || "ninguna"} · <ReferenceList ids={finding.sourceRefs} /></small>
                </li>
              ))}
            </ul>
          )}
          <div className="risk-discovery-no-action">
            Policy decision: <code>null</code> · despacho: <code>false</code>
          </div>
        </div>
      )}
    </section>
  );
}

export default function RiskIntelligencePage({
  workspaceRole = "viewer",
}: {
  workspaceRole?: WorkspaceRole;
}) {
  const isAdmin = workspaceRole === "owner" || workspaceRole === "admin";
  const preparedCaseCount = RISK_INTELLIGENCE_CATALOG.profiles.reduce(
    (count, profile) => count + profile.syntheticTestSpecs.length,
    0,
  );

  return (
    <div className="risk-intelligence-page" data-testid="risk-intelligence-page">
      <header className="page-heading risk-intelligence-heading">
        <div>
          <span className="eyebrow">BIBLIOTECA TRAZABLE · VERSIÓN {RISK_INTELLIGENCE_CATALOG.catalogVersion}</span>
          <h1>Risk Intelligence · STPA</h1>
          <p>
            Pérdidas, peligros, escenarios y controles de riesgo para ocho clases de agentes.
            Es una biblioteca de análisis; no acredita protección en producción.
          </p>
        </div>
        <span className="risk-intelligence-readonly"><BookOpenCheck size={15} /> Solo lectura · {RISK_INTELLIGENCE_CATALOG.updatedAt}</span>
      </header>

      <section className="risk-intelligence-notice" aria-label="Límites de esta biblioteca">
        <span><AlertTriangle size={18} /></span>
        <div>
          <b>Catálogo consultivo; no es un control de ejecución</b>
          <p>
            El análisis local no puntúa riesgos, no modifica políticas ni despacha herramientas.
            El Guardian Policy Engine existente sigue siendo el único decisor determinista.
            Los escenarios STPA son especificaciones sintéticas y no se han ejecutado en este
            incremento.
          </p>
        </div>
        <ShieldCheck size={18} aria-hidden="true" />
      </section>

      <section className="risk-executive-strip" aria-label="Resumen de cobertura del catálogo">
        <div><b>8</b><span>verticales modeladas</span></div>
        <div><b>{preparedCaseCount}</b><span>casos sintéticos preparados</span></div>
        <div><b>0</b><span>casos STPA ejecutados</span></div>
        <Link href="/ai-evaluations" className="button button-secondary" data-testid="link-risk-evaluations">
          Ver evaluaciones y aprobaciones <ArrowRight size={15} />
        </Link>
      </section>

      <ControlEvidencePanel detailed={isAdmin} />
      <CapabilityDiscoveryPanel />

      {isAdmin ? (
        <section className="risk-intelligence-source-section" aria-labelledby="risk-sources-title">
          <div className="risk-intelligence-section-heading">
            <div><span className="panel-kicker">PROCEDENCIA · LICENCIAS · LÍMITES</span><h2 id="risk-sources-title">Fuentes y revisión de uso</h2></div>
            <span>{RISK_INTELLIGENCE_CATALOG.sources.length} referencias registradas</span>
          </div>
          <div className="risk-intelligence-sources">
            {RISK_INTELLIGENCE_CATALOG.sources.map((source) => (
              <article key={source.id} data-testid={`risk-source-${source.id}`}>
                <div>
                  <h3>{source.name}</h3>
                  <small>{source.version}</small>
                </div>
                <p>{source.provenance}</p>
                <p>{source.licenseNote}</p>
                <p className="risk-intelligence-source-use">{source.useInCatalog}</p>
                <a href={source.url} target="_blank" rel="noreferrer">
                  Consultar fuente <ArrowUpRight size={13} />
                </a>
                <span className={`risk-source-state risk-source-state-${source.licenseReview}`}>
                  {source.licenseReview.replaceAll("_", " ")}
                </span>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <section className="risk-sources-summary">
          <BadgeCheck size={17} />
          <p>Las referencias y la revisión de licencias están disponibles para propietarios y administradores del espacio.</p>
        </section>
      )}

      <section className="risk-intelligence-model" aria-labelledby="risk-model-title">
        <div className="risk-intelligence-section-heading">
          <div><span className="panel-kicker">MÉTODO STPA · BORRADOR REVISABLE</span><h2 id="risk-model-title">Ocho clases de agente</h2></div>
          <span>{isAdmin ? "Pérdidas · peligros · restricciones · casos" : "Resumen ejecutivo"}</span>
        </div>
        <div className="risk-intelligence-profiles">
          {RISK_INTELLIGENCE_CATALOG.profiles.map((profile) => (
            <ProfileCard key={profile.id} profile={profile} showTechnicalDetails={isAdmin} />
          ))}
        </div>
      </section>

      <footer className="risk-intelligence-footnote">
        <b>Interpretación humana requerida.</b> Los hallazgos del analizador se infieren de
        capacidades declaradas y no están confirmados por pruebas. No se importaron filas de
        datasets ni payloads de terceros; candidatos no adoptados y licencias pendientes se
        identifican en la ficha técnica. La vista enlaza con el historial autenticado existente;
        esta biblioteca no copia ni mezcla datos de tenants.
      </footer>
    </div>
  );
}
