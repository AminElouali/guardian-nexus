import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  FOCUSED_APPROVAL_E2E_FORBIDDEN_MESSAGE,
  inspectApprovalE2eMode,
} from "./approval-e2e-mode";

test("focused E2E mode is forbidden when a required CI run is active", () => {
  assert.deepEqual(
    inspectApprovalE2eMode(
      {
        CI: "true",
        GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY: "1",
      },
      4,
    ),
    { focused: true, forbidden: true, omittedSubtestCount: 4 },
  );
  assert.equal(
    inspectApprovalE2eMode(
      {
        GUARDIAN_APPROVAL_E2E_REQUIRED: "1",
        GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY: "1",
      },
      4,
    ).forbidden,
    true,
  );
  assert.equal(
    inspectApprovalE2eMode(
      {
        GUARDIAN_APPROVAL_E2E_CI_SERVICE: "",
        GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY: "1",
      },
      4,
    ).forbidden,
    true,
  );
  assert.equal(
    inspectApprovalE2eMode(
      { GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY: "1" },
      4,
    ).forbidden,
    false,
  );
});

test("the E2E entrypoint fails before database setup when CI and focused mode collide", () => {
  const e2ePath = fileURLToPath(
    new URL("../ai-assessment-synthetic-approval-e2e.test.ts", import.meta.url),
  );
  const apiRoot = resolve(dirname(e2ePath), "..");
  const child = spawnSync(
    process.execPath,
    ["--import", "tsx", "--test", e2ePath],
    {
      cwd: apiRoot,
      env: {
        PATH: process.env.PATH ?? "",
        HOME: process.env.HOME ?? "",
        LANG: "C",
        LC_ALL: "C",
        CI: "true",
        GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY: "1",
      },
      encoding: "utf8",
      timeout: 15_000,
    },
  );
  const output = `${child.stdout ?? ""}\n${child.stderr ?? ""}`;
  assert.equal(child.error, undefined, "E2E guard subprocess should start");
  assert.notEqual(child.status, 0, "E2E must fail closed in required CI mode");
  assert.match(output, /MODO FOCALIZADO: se omiten 4 subpruebas/);
  assert.ok(output.includes(FOCUSED_APPROVAL_E2E_FORBIDDEN_MESSAGE));
  assert.doesNotMatch(output, /database connection|connected to database/i);
});
