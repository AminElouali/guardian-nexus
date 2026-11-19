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

test("0006 literal ref arrays exactly match the shared action catalog", async () => {
  const migration = await readFile(
    path.join(
      repositoryRoot,
      "lib/db/migrations/0006_align_approval_action_refs.sql",
    ),
    "utf8",
  );
  const refs = approvalActionRefMigrationValues();
  const readArray = (name: string): string[] => {
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

  assert.deepEqual(readArray("current_action_refs"), refs.current);
  assert.deepEqual(readArray("legacy_action_refs"), refs.legacy);
  assert.equal(refs.current.length, 4);
  assert.equal(refs.legacy.length, 2);
});
