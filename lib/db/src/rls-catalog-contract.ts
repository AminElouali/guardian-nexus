/**
 * Shared table/policy-count contract used by the runtime preflight and the
 * disposable PostgreSQL catalog audit. Policy bodies and role grants remain
 * defined by the Drizzle schema, rls-policies.sql, and bootstrap script.
 */
export const expectedRlsPolicyCounts = {
  workspaces: 2,
  workspace_memberships: 3,
  assets: 1,
  workspace_monthly_usage: 1,
  workspace_audit_events: 2,
  workspace_integrations: 3,
  provider_connections: 4,
  connector_oauth_states: 3,
  connector_jobs: 4,
  ai_assessment_jobs: 5,
  host_boundary_attestation_challenges: 3,
  ai_assessment_approval_requests: 3,
  workspace_approval_ledger: 2,
  workspace_action_rule_heads: 3,
  workspace_action_rule_versions: 2,
  workspace_agents: 4,
} as const;

export const expectedRlsPolicyCount = Object.values(
  expectedRlsPolicyCounts,
).reduce((total, count) => total + count, 0);

export const expectedRlsTableNames = Object.keys(
  expectedRlsPolicyCounts,
) as Array<keyof typeof expectedRlsPolicyCounts>;

export const appendOnlyRlsTableNames = [
  "workspace_approval_ledger",
  "workspace_action_rule_versions",
] as const satisfies readonly (keyof typeof expectedRlsPolicyCounts)[];

export const expectedDisposableRlsTableOwner = "postgres";
