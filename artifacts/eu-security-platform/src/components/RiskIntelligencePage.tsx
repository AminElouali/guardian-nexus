import React from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  BookOpenCheck,
  Database,
  FileCheck2,
  Mail,
  ShieldCheck,
} from "lucide-react";
import {
  RISK_INTELLIGENCE_CATALOG,
  type AgentRiskProfile,
  type ReviewState,
} from "@/risk-intelligence/catalog.v1";

const statusText: Record<ReviewState, string> = {
  prepared_not_executed: "Preparado · no ejecutado",
  design_only: "Diseño inicial · no probado",
};

const iconByProfile: Record<string, typeof Mail> = {
  email: Mail,
  database: Database,
};

function ReferenceList({ ids }: { ids: string[] }) {
  const sources = RISK_INTELLIGENCE_CATALOG.sources.filter((source) => ids.includes(source.id));
  return <span>{sources.map((source) => source.name).join(" · ") || "Referencia STPA interna"}</span>;
}

function ProfileCard({ profile }: { profile: AgentRiskProfile }) {
  const Icon = iconByProfile[profile.id] ?? FileCheck2;
  const detailed = profile.state === "prepared_not_executed";
  const itemGroups = [
    ["Pérdidas consideradas", profile.losses],
    ["Peligros", profile.hazards],
    ["Acciones de control inseguras", profile.unsafeControlActions],
    ["Escenarios causales", profile.causalScenarios],
    ["Restricciones verificables", profile.constraints],
  ] as const;

  return (
    <article
      className={`risk-intelligence-profile${detailed ? " risk-intelligence-profile-detailed" : ""}`}
      data-testid={`risk-profile-${profile.id}`}
    >
      <div className="risk-intelligence-profile-head">
        <span className="risk-intelligence-icon"><Icon size={18} /></span>
        <div>
          <span className="panel-kicker">VERTICAL · {statusText[profile.state]}</span>
          <h3>{profile.title}</h3>
        </div>
      </div>
      <ul className="risk-intelligence-scope">
        {profile.toolAndPermissionScope.map((scope) => <li key={scope}>{scope}</li>)}
      </ul>
      {detailed ? (
        <div className="risk-intelligence-groups">
          {itemGroups.map(([label, entries]) => (
            <details key={label} open={label === "Restricciones verificables"}>
              <summary>{label}<span>{entries.length}</span></summary>
              <ul>
                {entries.map((entry) => (
                  <li key={entry.id} data-testid={`risk-item-${entry.id}`}>
                    <b>{entry.id} · {entry.title}</b>
                    <p>{entry.description}</p>
                    <small><ReferenceList ids={entry.sourceRefs} /> · Estado: {statusText[entry.state]}</small>
                  </li>
                ))}
              </ul>
            </details>
          ))}
          <details>
            <summary>Pruebas sintéticas preparadas<span>{profile.syntheticTestSpecs.length}</span></summary>
            <ul>
              {profile.syntheticTestSpecs.map((testCase) => (
                <li key={testCase.id} data-testid={`risk-test-${testCase.id}`}>
                  <b>{testCase.id} · {testCase.title}</b>
                  <p><strong>Entrada sintética:</strong> {testCase.syntheticInput}</p>
                  <p><strong>Objetivo de control:</strong> {testCase.controlObjective}</p>
                  <small><ReferenceList ids={testCase.sourceRefs} /> · No ejecutada</small>
                </li>
              ))}
            </ul>
          </details>
        </div>
      ) : (
        <p className="risk-intelligence-pending">
          Esta vertical está incluida en el catálogo; su análisis STPA detallado y sus pruebas quedan pendientes.
        </p>
      )}
    </article>
  );
}

export default function RiskIntelligencePage() {
  return (
    <div className="risk-intelligence-page" data-testid="risk-intelligence-page">
      <header className="page-heading risk-intelligence-heading">
        <div>
          <span className="eyebrow">BIBLIOTECA TRAZABLE · VERSIÓN {RISK_INTELLIGENCE_CATALOG.catalogVersion}</span>
          <h1>Risk Intelligence · STPA</h1>
          <p>
            Análisis inicial de pérdidas, peligros, acciones de control inseguras y restricciones
            para los laboratorios de agentes Guardian Nexus.
          </p>
        </div>
        <span className="risk-intelligence-readonly"><BookOpenCheck size={15} /> Solo lectura · {RISK_INTELLIGENCE_CATALOG.updatedAt}</span>
      </header>

      <section className="risk-intelligence-notice" aria-label="Límites de esta biblioteca">
        <span><AlertTriangle size={18} /></span>
        <div>
          <b>Catálogo de análisis, no un control de ejecución</b>
          <p>
            Esta vista no puntúa riesgos, no modifica políticas ni despacha herramientas. El
            Guardian Policy Engine existente sigue siendo el único decisor determinista. Los
            estados indican preparación documental; no prueban cobertura ni eficacia en runtime.
          </p>
        </div>
        <ShieldCheck size={18} aria-hidden="true" />
      </section>

      <section className="risk-intelligence-source-section" aria-labelledby="risk-sources-title">
        <div className="risk-intelligence-section-heading">
          <div><span className="panel-kicker">PROCEDENCIA · LICENCIAS · LÍMITES</span><h2 id="risk-sources-title">Fuentes y uso permitido</h2></div>
          <span>{RISK_INTELLIGENCE_CATALOG.sources.length} referencias registradas</span>
        </div>
        <div className="risk-intelligence-sources">
          {RISK_INTELLIGENCE_CATALOG.sources.map((source) => (
            <article key={source.id} data-testid={`risk-source-${source.id}`}>
              <div>
                <h3>{source.name}</h3>
                <small>{source.version}</small>
              </div>
              <p>{source.licenseNote}</p>
              <p className="risk-intelligence-source-use">{source.useInCatalog}</p>
              <a href={source.url} target="_blank" rel="noreferrer">
                Consultar fuente oficial <ArrowUpRight size={13} />
              </a>
              <span className={`risk-source-state risk-source-state-${source.licenseReview}`}>
                {source.licenseReview.replaceAll("_", " ")}
              </span>
            </article>
          ))}
        </div>
      </section>

      <section className="risk-intelligence-model" aria-labelledby="risk-model-title">
        <div className="risk-intelligence-section-heading">
          <div><span className="panel-kicker">MÉTODO STPA · BORRADOR REVISABLE</span><h2 id="risk-model-title">Ocho clases de agente</h2></div>
          <span>Correo y base de datos: primer modelado</span>
        </div>
        <div className="risk-intelligence-profiles">
          {RISK_INTELLIGENCE_CATALOG.profiles.map((profile) => <ProfileCard key={profile.id} profile={profile} />)}
        </div>
      </section>

      <footer className="risk-intelligence-footnote">
        <b>Interpretación humana requerida.</b> Las descripciones son una primera biblioteca de
        riesgos del laboratorio, no un análisis completo del sistema ni una conclusión de
        cumplimiento. Las pruebas incluidas son especificaciones sintéticas aún no ejecutadas;
        no se importaron datasets ni payloads de terceros.
      </footer>
    </div>
  );
}
