import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDeclaredCapabilities } from "./capability-discovery.v1";
import { RISK_INTELLIGENCE_CATALOG } from "./catalog.v1";

const baseDeclaration = {
  profileId: "email" as const,
  toolNames: ["mail_read_fixture", "mail_draft_fixture"],
  permissionNames: ["read:synthetic-mailbox"],
  dataSensitivity: "confidential" as const,
  untrustedInputs: true,
  externalRecipients: true,
  persistentEffects: true,
  destructiveOperations: false,
  privilegeChanges: false,
  delegation: false,
  approvalRequired: true,
  dependencies: ["fixture-mail-store"],
};

test("declared capability analysis is advisory, non-authorizing and does not echo data", () => {
  const result = analyzeDeclaredCapabilities(baseDeclaration);
  const encoded = JSON.stringify(result);
  assert.equal(result.schemaVersion, "guardian-capability-discovery/1.0.0");
  assert.equal(result.mode, "local_advisory_only");
  assert.equal(result.decisionAuthority, "guardian_policy_engine_only");
  assert.equal(result.policyDecision, null);
  assert.equal(result.actionDispatched, false);
  assert.equal(result.declaredCounts.tools, 2);
  assert.equal(result.declaredCounts.permissions, 1);
  assert.equal(result.declaredCounts.dependencies, 1);
  assert.ok(result.findings.some((finding) => finding.classification === "known_source_concept"));
  assert.ok(result.findings.some((finding) => finding.classification === "inferred_from_declared_capability"));
  assert.ok(result.findings.every((finding) => finding.validationState === "pending_validation"));
  assert.ok(result.findings.every((finding) => finding.riskItemRefs.length > 0));
  const sourceIds = new Set(RISK_INTELLIGENCE_CATALOG.sources.map((source) => source.id));
  assert.ok(result.findings.flatMap((finding) => finding.sourceRefs).every((id) => sourceIds.has(id)));
  assert.equal(Object.hasOwn(result, "tenantId"), false);
  assert.equal(Object.hasOwn(result, "actorId"), false);
  assert.doesNotMatch(encoded, /mail_read_fixture|read:synthetic-mailbox|fixture-mail-store/);
  assert.doesNotMatch(encoded, /allow|deny|require_approval/i);
});

test("all eight profiles produce only catalog-linked pending findings", () => {
  const validRiskIds = new Set(RISK_INTELLIGENCE_CATALOG.profiles.flatMap((profile) => [
    ...profile.losses,
    ...profile.hazards,
    ...profile.unsafeControlActions,
    ...profile.causalScenarios,
    ...profile.constraints,
  ]).map((item) => item.id));
  for (const profile of RISK_INTELLIGENCE_CATALOG.profiles) {
    const result = analyzeDeclaredCapabilities({
      ...baseDeclaration,
      profileId: profile.id,
      delegation: profile.id === "multiagent",
      privilegeChanges: profile.id === "infrastructure",
    });
    assert.equal(result.profileId, profile.id);
    assert.ok(result.findings.length > 0);
    assert.ok(result.findings.every((finding) => finding.validationState === "pending_validation"));
    assert.ok(result.findings.flatMap((finding) => finding.riskItemRefs).every((id) => validRiskIds.has(id)));
    assert.equal(result.actionDispatched, false);
    assert.equal(result.policyDecision, null);
  }
});

test("strict declaration schema rejects identity, tenant, authorization and unknown capability fields", () => {
  for (const extra of [
    { tenantId: "tenant-a" },
    { actorId: "user-1" },
    { verifiedBy: "admin" },
    { policyDecision: "allow" },
    { action: "execute" },
  ]) {
    assert.throws(
      () => analyzeDeclaredCapabilities({ ...baseDeclaration, ...extra }),
      /risk_capability_declaration_schema_mismatch/,
    );
  }
});

test("invalid profiles, booleans and overlong lists fail closed", () => {
  assert.throws(
    () => analyzeDeclaredCapabilities({ ...baseDeclaration, profileId: "unknown" }),
    /risk_capability_profile_invalid/,
  );
  assert.throws(
    () => analyzeDeclaredCapabilities({ ...baseDeclaration, externalRecipients: "yes" }),
    /risk_capability_signal_invalid/,
  );
  assert.throws(
    () => analyzeDeclaredCapabilities({ ...baseDeclaration, toolNames: Array(13).fill("tool") }),
    /risk_capability_tools_invalid/,
  );
  assert.throws(
    () => analyzeDeclaredCapabilities({ ...baseDeclaration, dataSensitivity: "top-secret" }),
    /risk_capability_sensitivity_invalid/,
  );
  assert.throws(
    () => analyzeDeclaredCapabilities(Object.create(baseDeclaration)),
    /risk_capability_declaration_invalid/,
  );
});

test("no signals yields no findings, not a safe or allow decision", () => {
  const result = analyzeDeclaredCapabilities({
    ...baseDeclaration,
    toolNames: [],
    permissionNames: [],
    dependencies: [],
    dataSensitivity: "public",
    untrustedInputs: false,
    externalRecipients: false,
    persistentEffects: false,
    destructiveOperations: false,
    privilegeChanges: false,
    delegation: false,
    approvalRequired: false,
  });
  assert.deepEqual(result.findings, []);
  assert.equal(result.policyDecision, null);
  assert.equal(result.actionDispatched, false);
  assert.match(result.evidenceNote, /ningún hallazgo está confirmado por una prueba de runtime/i);
});
