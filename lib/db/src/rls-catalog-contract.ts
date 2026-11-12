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
} as const;

export const expectedRlsTableNames = Object.keys(
  expectedRlsPolicyCounts,
) as Array<keyof typeof expectedRlsPolicyCounts>;

export const expectedDisposableRlsTableOwner = "postgres";
