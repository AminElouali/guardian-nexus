import { APPROVAL_ACTION_REFS } from "@workspace/db/approval-action-catalog";

const allRefsToken = "{{APPROVAL_ACTION_REFS_SQL}}";
const legacyRefsToken = "{{LEGACY_APPROVAL_ACTION_REFS_SQL}}";
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

function sqlStringArray(values: readonly string[]): string {
  return values
    .map((value) => {
      if (!actionRefPattern.test(value)) {
        throw new Error("approval_action_ref_migration_catalog_invalid");
      }
      return `'${value.replaceAll("'", "''")}'`;
    })
    .join(", ");
}

export function renderApprovalActionRefMigration(template: string): string {
  const values = approvalActionRefMigrationValues();
  if (
    template.split(allRefsToken).length !== 2 ||
    template.split(legacyRefsToken).length !== 2
  ) {
    throw new Error("approval_action_ref_migration_template_invalid");
  }
  return template
    .replace(allRefsToken, sqlStringArray(values.current))
    .replace(legacyRefsToken, sqlStringArray(values.legacy));
}

export function approvalActionRefConstraintExpression(
  refs: readonly string[],
): string {
  if (refs.length === 0 || refs.some((ref) => !actionRefPattern.test(ref))) {
    throw new Error("approval_action_ref_migration_catalog_invalid");
  }
  return `(synthetic_action_ref IS NULL AND action_sha256 IS NULL) OR (synthetic_action_ref IN (${sqlStringArray(refs)}) AND action_sha256 IS NOT NULL)`;
}
