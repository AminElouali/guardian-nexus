import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  approvalActionRefMigrationValues,
  renderApprovalActionRefMigration,
} from "./approval-action-ref-migration";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../",
);

test("0006 renders current and legacy refs from the shared action catalog", async () => {
  const migration = await readFile(
    path.join(
      repositoryRoot,
      "lib/db/migrations/0006_align_approval_action_refs.sql",
    ),
    "utf8",
  );
  const rendered = renderApprovalActionRefMigration(migration);
  const refs = approvalActionRefMigrationValues();

  assert.equal(rendered.includes("{{APPROVAL_ACTION_REFS_SQL}}"), false);
  assert.equal(rendered.includes("{{LEGACY_APPROVAL_ACTION_REFS_SQL}}"), false);
  for (const ref of refs.current) assert.ok(rendered.includes(`'${ref}'`));
  for (const ref of refs.legacy) assert.ok(rendered.includes(`'${ref}'`));
  assert.equal(refs.current.length, 4);
  assert.equal(refs.legacy.length, 2);
});

test("0006 template requires both catalog-generated reference arrays", async () => {
  assert.throws(
    () => renderApprovalActionRefMigration("BEGIN; COMMIT;"),
    /approval_action_ref_migration_template_invalid/,
  );
});
