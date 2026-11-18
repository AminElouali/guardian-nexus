import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { test } from "node:test";
import os from "node:os";
import path from "node:path";
import {
  API_TEST_TARGET_REJECTION,
  isSafeApiTestTarget,
  runApiTestSuite,
} from "./api-test-target-guard";

async function withPrivateLabSocket<T>(
  operation: (input: {
    env: Record<string, string | undefined>;
    socketDirectory: string;
  }) => Promise<T>,
): Promise<T> {
  const labRoot = mkdtempSync(path.join(os.tmpdir(), "guardian-nexus-pg-lab-"));
  chmodSync(labRoot, 0o700);
  const socketDirectory = path.join(labRoot, "socket");
  mkdirSync(socketDirectory, { mode: 0o700 });
  chmodSync(socketDirectory, 0o700);
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(path.join(socketDirectory, ".s.PGSQL.5432"), resolve);
  });
  const databaseName = "guardian_approval_lab_api_guard_test";
  const adminUrl = new URL(
    `postgresql://synthetic-admin:test-only@127.0.0.1:5432/${databaseName}`,
  );
  adminUrl.searchParams.set("host", socketDirectory);
  const runtimeUrl = new URL(
    `postgresql://app_runtime_login:${"r".repeat(40)}@127.0.0.1:5432/${databaseName}`,
  );
  runtimeUrl.searchParams.set("host", socketDirectory);
  const env: Record<string, string | undefined> = {
    NODE_ENV: "development",
    GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    GUARDIAN_APPROVAL_E2E_DATABASE_NAME: databaseName,
    DATABASE_URL: adminUrl.toString(),
    APP_RUNTIME_DATABASE_URL: runtimeUrl.toString(),
  };

  try {
    return await operation({ env, socketDirectory });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(labRoot, { recursive: true, force: true });
  }
}

test("API test target guard accepts the private loopback lab socket", async () => {
  await withPrivateLabSocket(async ({ env }) => {
    assert.equal(isSafeApiTestTarget(env), true);
  });
});

test("API test target guard rejects a remote database URL", async () => {
  await withPrivateLabSocket(async ({ env }) => {
    const remote = new URL(env.DATABASE_URL!);
    remote.hostname = "remote.invalid";
    env.DATABASE_URL = remote.toString();
    assert.equal(isSafeApiTestTarget(env), false);
  });
});

test("API test target guard blocks a Replit-style URL without lab markers", () => {
  assert.equal(
    isSafeApiTestTarget({
      NODE_ENV: "development",
      DATABASE_URL: "postgresql://synthetic:synthetic@managed.invalid:5432/dev",
    }),
    false,
  );
});

test("API test target guard rejects lab markers that do not match the URL database", async () => {
  await withPrivateLabSocket(async ({ env }) => {
    const wrongMarker = {
      ...env,
      GUARDIAN_APPROVAL_E2E_DATABASE_NAME: "guardian_approval_lab_other",
    };
    assert.equal(isSafeApiTestTarget(wrongMarker), false);

    const wrongRuntimeDatabase = { ...env };
    const runtimeUrl = new URL(wrongRuntimeDatabase.APP_RUNTIME_DATABASE_URL!);
    runtimeUrl.pathname = "/guardian_approval_lab_other";
    wrongRuntimeDatabase.APP_RUNTIME_DATABASE_URL = runtimeUrl.toString();
    assert.equal(isSafeApiTestTarget(wrongRuntimeDatabase), false);
  });
});

test("API test target guard rejects missing lab markers or connection URLs", async () => {
  await withPrivateLabSocket(async ({ env }) => {
    const noMarker = { ...env };
    delete noMarker.GUARDIAN_APPROVAL_E2E_DISPOSABLE;
    assert.equal(isSafeApiTestTarget(noMarker), false);

    const noRuntimeUrl = { ...env };
    delete noRuntimeUrl.APP_RUNTIME_DATABASE_URL;
    assert.equal(isSafeApiTestTarget(noRuntimeUrl), false);

    const noAdminUrl = { ...env };
    delete noAdminUrl.DATABASE_URL;
    assert.equal(isSafeApiTestTarget(noAdminUrl), false);
  });
});

test("API test target guard rejects all PG environment overrides", async () => {
  await withPrivateLabSocket(async ({ env }) => {
    assert.equal(
      isSafeApiTestTarget({ ...env, PGAPPNAME: "untrusted-override" }),
      false,
    );
  });
});

test("API test suite aborts before launching tests outside the lab", async () => {
  let launched = false;
  const result = await runApiTestSuite(
    { NODE_ENV: "development" },
    async () => {
      launched = true;
      return 0;
    },
  );

  assert.deepEqual(result, { started: false, exitCode: 1 });
  assert.equal(launched, false);
  assert.equal(API_TEST_TARGET_REJECTION, "API tests require the isolated local PostgreSQL lab target.");
});
