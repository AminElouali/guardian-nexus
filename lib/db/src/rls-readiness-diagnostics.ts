export const rlsReadinessViolationCodes = [
  "table_catalog_query_failed",
  "table_inventory_mismatch",
  "rls_disabled",
  "rls_not_forced",
  "policy_count_mismatch",
  "policy_contract_mismatch",
  "role_catalog_query_failed",
  "runtime_login_identity_mismatch",
  "role_attributes_mismatch",
  "role_membership_mismatch",
  "worker_privileges_mismatch",
  "runtime_table_privileges_mismatch",
  "runtime_login_direct_table_access",
  "runtime_role_activation_failed",
  "worker_role_activation_failed",
  "worker_result_column_access_probe_failed",
  "worker_result_column_access_not_denied",
  "preflight_internal_error",
] as const;

export type RlsReadinessViolationCode =
  (typeof rlsReadinessViolationCodes)[number];

const allowedCodes = new Set<string>(rlsReadinessViolationCodes);

export class RlsRuntimeReadinessError extends Error {
  readonly violationCodes: readonly RlsReadinessViolationCode[];

  constructor(codes: readonly RlsReadinessViolationCode[]) {
    super("RLS runtime readiness check failed.");
    this.name = "RlsRuntimeReadinessError";
    const safeCodes = [...new Set(codes)].filter((code) =>
      allowedCodes.has(code),
    );
    this.violationCodes =
      safeCodes.length > 0
        ? safeCodes
        : ["preflight_internal_error"];
  }
}

export function safeRlsReadinessViolationCodes(
  error: unknown,
): readonly RlsReadinessViolationCode[] {
  if (!(error instanceof RlsRuntimeReadinessError)) {
    return ["preflight_internal_error"];
  }
  const safeCodes = error.violationCodes.filter((code) =>
    allowedCodes.has(code),
  );
  return safeCodes.length > 0
    ? safeCodes
    : ["preflight_internal_error"];
}
