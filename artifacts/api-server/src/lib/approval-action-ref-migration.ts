import { APPROVAL_ACTION_REFS } from "@workspace/db/approval-action-catalog";

const actionRefPattern = /^[a-z0-9][a-z0-9._-]{0,127}$/;

export type ApprovalActionRefMigrationValues = {
  current: readonly string[];
  legacy: readonly string[];
};

export function approvalActionRefMigrationValues():
  ApprovalActionRefMigrationValues {
  const current = [...APPROVAL_ACTION_REFS];
  const legacy = current.filter((ref) => ref.startsWith("guardian.synthetic."));
  if (
    current.length !== 4 ||
    new Set(current).size !== current.length ||
    current.some((ref) => !actionRefPattern.test(ref)) ||
    legacy.length !== 2
  ) {
    throw new Error("approval_action_ref_migration_catalog_invalid");
  }
  return { current, legacy };
}

export function approvalActionRefConstraintExpression(
  refs: readonly string[],
): string {
  if (refs.length === 0 || refs.some((ref) => !actionRefPattern.test(ref))) {
    throw new Error("approval_action_ref_migration_catalog_invalid");
  }
  const values = refs
    .map((ref) => `'${ref.replaceAll("'", "''")}'`)
    .join(", ");
  return `(synthetic_action_ref IS NULL AND action_sha256 IS NULL) OR (synthetic_action_ref IN (${values}) AND action_sha256 IS NOT NULL)`;
}
