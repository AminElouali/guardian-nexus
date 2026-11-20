import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { approvalActionRefMigrationValues } from "./approval-action-ref-migration";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../",
);

test("versioned action-ref migrations match the exact historical and current catalogs", async () => {
  const refs = approvalActionRefMigrationValues();
  const migration0006 = await readFile(
    path.join(repositoryRoot, "lib/db/migrations/0006_align_approval_action_refs.sql"),
    "utf8",
  );
  const migration0009 = await readFile(
    path.join(repositoryRoot, "lib/db/migrations/0009_expand_approval_action_catalog.sql"),
    "utf8",
  );
  const readArrayFrom = (migration: string, name: string): string[] => {
    const pattern = new RegExp(
      `${name}\\s+text\\[\\]\\s*:=\\s*ARRAY\\[([\\s\\S]*?)\\]::text\\[\\]`,
      "i",
    );
    const match = migration.match(pattern);
    assert.ok(match, `${name} literal array exists`);
    return [...match[1]!.matchAll(/'((?:''|[^'])*)'/g)].map((item) =>
      item[1]!.replaceAll("''", "'")
    );
  };
  assert.deepEqual(readArrayFrom(migration0006, "current_action_refs"), refs.previous);
  assert.deepEqual(readArrayFrom(migration0006, "legacy_action_refs"), refs.legacy);
  assert.deepEqual(readArrayFrom(migration0009, "current_action_refs"), refs.current);
  assert.deepEqual(readArrayFrom(migration0009, "legacy_action_refs"), refs.previous);
  assert.equal(refs.current.length, 30);
  assert.equal(refs.previous.length, 4);
  assert.equal(refs.legacy.length, 2);
});
