import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { Router } from "wouter";
import RiskIntelligencePage from "./RiskIntelligencePage";
import { RISK_INTELLIGENCE_CATALOG } from "@/risk-intelligence/catalog.v1";

function renderPage(workspaceRole: "owner" | "admin" | "analyst" | "viewer") {
  const previousLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { pathname: "/", search: "", hash: "" },
  });
  try {
    return renderToStaticMarkup(
      createElement(
        Router,
        {
          base: "",
          children: createElement(RiskIntelligencePage, { workspaceRole }),
        },
      ),
    );
  } finally {
    if (previousLocation) Object.defineProperty(globalThis, "location", previousLocation);
    else Reflect.deleteProperty(globalThis, "location");
  }
}

test("catalog contains complete unexecuted STPA drafts for all eight profiles", () => {
  const { profiles } = RISK_INTELLIGENCE_CATALOG;
  assert.equal(RISK_INTELLIGENCE_CATALOG.schemaVersion, "guardian-risk-intelligence-catalog/1.1.0");
  assert.equal(RISK_INTELLIGENCE_CATALOG.catalogVersion, "0.2.0");
  assert.equal(profiles.length, 8);
  assert.equal(new Set(profiles.map((profile) => profile.id)).size, 8);
  const evidenceIds = new Set(
    RISK_INTELLIGENCE_CATALOG.controlEvidenceSnapshot.records.map((record) => record.id),
  );
  assert.deepEqual(profiles.slice(0, 2).map((profile) => profile.id), ["email", "database"]);
  const itemIds = profiles.flatMap((profile) => [
    ...profile.losses,
    ...profile.hazards,
    ...profile.unsafeControlActions,
    ...profile.causalScenarios,
    ...profile.constraints,
    ...profile.syntheticTestSpecs,
  ]).map((entry) => entry.id);
  assert.equal(new Set(itemIds).size, itemIds.length);
  for (const profile of profiles) {
    assert.equal(profile.state, "prepared_not_executed");
    assert.ok(profile.controlEvidenceRefs.length > 0);
    assert.ok(profile.controlEvidenceRefs.every((id) => evidenceIds.has(id)));
    assert.ok(profile.executiveSummary.length > 30);
    assert.ok(profile.losses.length >= 3);
    assert.ok(profile.hazards.length >= 3);
    assert.ok(profile.unsafeControlActions.length >= 3);
    assert.ok(profile.causalScenarios.length >= 3);
    assert.ok(profile.constraints.length >= 3);
    assert.equal(profile.syntheticTestSpecs.length, 4);
    assert.ok(profile.syntheticTestSpecs.every((scenario) => scenario.state === "prepared_not_executed"));
  }
  assert.equal(profiles.reduce((count, profile) => count + profile.syntheticTestSpecs.length, 0), 32);
});

test("all references resolve and external identifiers remain source-scoped", () => {
  const sourceIds = new Set(RISK_INTELLIGENCE_CATALOG.sources.map((source) => source.id));
  const itemRefs = RISK_INTELLIGENCE_CATALOG.profiles.flatMap((profile) => [
    ...profile.losses,
    ...profile.hazards,
    ...profile.unsafeControlActions,
    ...profile.causalScenarios,
    ...profile.constraints,
    ...profile.syntheticTestSpecs,
  ]).flatMap((entry) => entry.sourceRefs);
  assert.ok(itemRefs.every((sourceId) => sourceIds.has(sourceId)));
  assert.deepEqual(
    RISK_INTELLIGENCE_CATALOG.externalIdentifiers.map((entry) => entry.id),
    ["AML.T0051", "AML.T0051.001", "AML.M0020"],
  );
  assert.ok(RISK_INTELLIGENCE_CATALOG.externalIdentifiers.every(
    (entry) => entry.sourceId === "mitre-atlas" && entry.exactness === "verified_official_page",
  ));
  assert.equal(RISK_INTELLIGENCE_CATALOG.runtimeVerification, "not_verified_by_this_catalog");
  assert.equal(RISK_INTELLIGENCE_CATALOG.decisionAuthority, "existing_guardian_policy_engine_only");
});

test("published evidence snapshot hashes match the referenced local files", () => {
  const records = RISK_INTELLIGENCE_CATALOG.controlEvidenceSnapshot.records
    .filter((record) => record.evidenceSha256);
  assert.ok(records.length > 0);
  for (const record of records) {
    const evidence = readFileSync(new URL(`../../../../${record.evidenceRef}`, import.meta.url));
    const actual = createHash("sha256").update(evidence).digest("hex");
    assert.equal(actual, record.evidenceSha256, record.id);
  }
});

test("HF license conflict and detector candidate are disclosed without reuse", () => {
  const dataset = RISK_INTELLIGENCE_CATALOG.sources.find((source) => source.id === "hf-deepset-prompt-injections");
  const detector = RISK_INTELLIGENCE_CATALOG.sources.find((source) => source.id === "hf-horizon-injection-detector");
  const garak = RISK_INTELLIGENCE_CATALOG.sources.find((source) => source.id === "garak-reference");
  assert.equal(dataset?.licenseReview, "license_conflict_review_blocked");
  assert.match(dataset?.licenseNote ?? "", /Apache-2\.0/);
  assert.match(dataset?.licenseNote ?? "", /CC-BY-4\.0/);
  assert.equal(detector?.licenseReview, "candidate_screened_not_adopted");
  assert.match(detector?.provenance ?? "", /no local file was downloaded or checked/i);
  assert.equal(garak?.licenseReview, "verified_repository_license");
  assert.match(garak?.version ?? "", /0\.17\.2\.pre1/);
  assert.match(garak?.licenseNote ?? "", /individual probe\/data licenses/i);
});

test("viewer sees executive summary and snapshot, not admin source or STPA internals", () => {
  const html = renderPage("viewer");
  assert.match(html, /data-testid="risk-intelligence-page"/);
  assert.match(html, /Catálogo consultivo; no es un control de ejecución/);
  assert.match(html, /no modifica las decisiones de autorización/);
  assert.match(html, /Controles asociados y estado de evidencia/);
  assert.match(html, /Prueba sintética/);
  assert.doesNotMatch(html.replace(/\sdata-testid="[^"]*"/g, ""), /Qwen/i);
  assert.match(html, /No verificado en esta fase/);
  assert.match(html, /Ver evaluaciones y aprobaciones/);
  assert.equal((html.match(/data-testid="risk-profile-/g) ?? []).length, 8);
  assert.match(html, /risk-capability-form/);
  assert.doesNotMatch(html, /risk-source-hf-deepset/);
  assert.doesNotMatch(html, /GNRI-L-01/);
});

test("workspace admins see detailed STPA items and artifact provenance", () => {
  const html = renderPage("admin");
  assert.match(html, /risk-source-hf-deepset-prompt-injections/);
  assert.match(html, /risk-source-hf-horizon-injection-detector/);
  assert.match(html, /GNRI-L-01/);
  assert.match(html, /GNRI-M-T-04/);
  assert.match(html, /6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9/);
  assert.match(html, /no consulta el estado del sistema en vivo/i);
  assert.match(html, /assessment_broker_identity_unverified/);
});

test("page exposes only an advisory capability analyzer, not policy or execution controls", () => {
  const html = renderPage("analyst");
  assert.match(html, /Analizar declaración local/);
  assert.match(html, /no puntúa riesgos, no modifica las decisiones de autorización ni ejecuta acciones/i);
  assert.doesNotMatch(html, /<button[^>]+(?:approve|execute|allow|deny)/i);
  assert.equal((html.match(/data-testid="risk-profile-/g) ?? []).length, 8);
});
