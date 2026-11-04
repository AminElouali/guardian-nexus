import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import RiskIntelligencePage from "./RiskIntelligencePage";
import { RISK_INTELLIGENCE_CATALOG } from "@/risk-intelligence/catalog.v1";

test("risk catalog covers eight profiles and marks only email/database as prepared", () => {
  const profiles = RISK_INTELLIGENCE_CATALOG.profiles;
  assert.equal(RISK_INTELLIGENCE_CATALOG.schemaVersion, "guardian-risk-intelligence-catalog/1.0.0");
  assert.equal(RISK_INTELLIGENCE_CATALOG.catalogVersion, "0.1.0");
  assert.equal(profiles.length, 8);
  assert.equal(new Set(profiles.map((profile) => profile.id)).size, 8);
  assert.deepEqual(profiles.slice(0, 2).map((profile) => profile.id), ["email", "database"]);
  for (const profile of profiles.slice(0, 2)) {
    assert.equal(profile.state, "prepared_not_executed");
    assert.ok(profile.losses.length > 0);
    assert.ok(profile.hazards.length > 0);
    assert.ok(profile.unsafeControlActions.length > 0);
    assert.ok(profile.causalScenarios.length > 0);
    assert.ok(profile.constraints.length > 0);
    assert.ok(profile.syntheticTestSpecs.length >= 4);
    assert.ok(profile.syntheticTestSpecs.every((scenario) => scenario.state === "prepared_not_executed"));
  }
  for (const profile of profiles.slice(2)) {
    assert.equal(profile.state, "design_only");
    assert.equal(profile.syntheticTestSpecs.length, 0);
  }
});

test("all source references resolve and external identifiers are explicitly source-scoped", () => {
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
  assert.ok(
    RISK_INTELLIGENCE_CATALOG.externalIdentifiers.every(
      (entry) => entry.sourceId === "mitre-atlas" && entry.exactness === "verified_official_page",
    ),
  );
  assert.equal(RISK_INTELLIGENCE_CATALOG.runtimeVerification, "not_verified_by_this_catalog");
  assert.equal(RISK_INTELLIGENCE_CATALOG.decisionAuthority, "existing_guardian_policy_engine_only");
});

test("risk intelligence page is authenticated-readonly language and does not offer policy or execution controls", () => {
  const html = renderToStaticMarkup(createElement(RiskIntelligencePage));
  assert.match(html, /data-testid="risk-intelligence-page"/);
  assert.match(html, /Catálogo de análisis, no un control de ejecución/);
  assert.match(html, /Guardian Policy Engine existente sigue siendo el único decisor determinista/);
  assert.match(html, /Correo/);
  assert.match(html, /Bases de datos/);
  assert.match(html, /Esta vertical está incluida en el catálogo/);
  assert.match(html, /no se importaron datasets ni payloads de terceros/i);
  assert.equal((html.match(/data-testid="risk-profile-/g) ?? []).length, 8);
  assert.equal((html.match(/<button\b/g) ?? []).length, 0);
  assert.equal((html.match(/<form\b/g) ?? []).length, 0);
});
