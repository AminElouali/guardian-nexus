import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseSafeNodeTestFailures,
  sanitizeChildOutputForReport,
} from "./run-postgres-local-lab";

const testFileName = "ai-assessment-synthetic-approval-e2e.test.ts";
const testSource = [
  "import {",
  "  assert,",
  '} from "node:assert/strict";',
  "",
  'test("synthetic approval", () => {',
  "  assert.equal(200, 409);",
  "});",
].join("\n");

test("parses a node:test assertion and selects its real source frame", () => {
  const output = [
    "TAP version 13",
    "not ok 1 - deterministic approval E2E exports signed history",
    "  ---",
    "  duration_ms: 2",
    "  type: 'test'",
    "  location: 'file:///tmp/project/src/ai-assessment-synthetic-approval-e2e.test.ts:5:1'",
    "  failureType: 'testCodeFailure'",
    "  error: |-",
    "    AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:",
    "    409 !== 200",
    "  code: 'ERR_ASSERTION'",
    "  name: 'AssertionError'",
    "  expected: 200",
    "  actual: 409",
    "  operator: 'strictEqual'",
    "  stack: |-",
    "    AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:",
    "        at helper (/tmp/node_modules/helper/index.ts:3:2)",
    `        at importFrame (file:///tmp/project/src/${testFileName}:2:4)`,
    `        TestContext.<anonymous> (file:///tmp/project/src/${testFileName}:6:3)`,
    "  ...",
    "# tests 1",
    "# pass 0",
    "# fail 1",
  ].join("\n");

  assert.deepEqual(
    parseSafeNodeTestFailures(output, testFileName, testSource),
    [{
      subtest: "deterministic approval E2E exports signed history",
      errorCode: "ERR_ASSERTION",
      errorName: "AssertionError",
      failureType: "testCodeFailure",
      message: "Expected values to be strictly equal:",
      expected: 200,
      received: 409,
      location: `${testFileName}:6`,
    }],
  );
});

test("parses sanitized diagnostics from nested TAP subtests", () => {
  const output = [
    "TAP version 13",
    "    not ok 1 - MCP proxy approval retry",
    "      ---",
    "      failureType: 'testCodeFailure'",
    "      error: |-",
    "        AssertionError: Expected values to be strictly equal:",
    "        200 !== 503",
    "      code: 'ERR_ASSERTION'",
    "      name: 'AssertionError'",
    "      expected: 200",
    "      actual: 503",
    "      stack: |-",
    `        at TestContext.<anonymous> (file:///tmp/project/src/${testFileName}:6:3)`,
    "      ...",
    "not ok 1 - deterministic approval E2E exports signed history",
    "  ---",
    "  failureType: 'subtestsFailed'",
    "  error: '1 subtest failed'",
    "  code: 'ERR_TEST_FAILURE'",
    "  name: 'SubtestFailed'",
    "  ...",
    "# tests 2",
    "# pass 0",
    "# fail 2",
  ].join("\n");

  const failures = parseSafeNodeTestFailures(output, testFileName, testSource);
  assert.equal(failures[0]?.subtest, "MCP proxy approval retry");
  assert.equal(failures[0]?.expected, 200);
  assert.equal(failures[0]?.received, 503);
  assert.equal(failures[0]?.location, `${testFileName}:6`);
});

test("redacts unsafe diagnostics and omits non-primitive values", () => {
  const output = [
    "TAP version 13",
    "not ok 1 - synthetic approval",
    "  ---",
    "  failureType: 'testCodeFailure'",
    "  error: |-",
    "    Connection failed for postgresql://synthetic:SENTINEL_PASSWORD@db.invalid/app",
    "  code: 'ERR_ASSERTION'",
    "  name: 'AssertionError'",
    "  expected: '{ row: SENTINEL_APPLICATION_ROW }'",
    "  actual: 'Bearer SENTINEL_BEARER_TOKEN_VALUE'",
    "  stack: |-",
    `    at TestContext.<anonymous> (file:///tmp/project/src/${testFileName}:6:3)`,
    "  ...",
    "# tests 1",
    "# pass 0",
    "# fail 1",
  ].join("\n");

  const failures = parseSafeNodeTestFailures(
    output,
    testFileName,
    testSource,
  );
  assert.equal(failures.length, 1);
  assert.equal(failures[0]?.message, "Connection failed for [redacted]");
  assert.equal(failures[0]?.expected, undefined);
  assert.equal(failures[0]?.received, undefined);
  assert.equal(failures[0]?.location, `${testFileName}:6`);
  const serialized = JSON.stringify(failures);
  assert.doesNotMatch(serialized, /SENTINEL_|postgresql:\/\//);
});

test("redacts the disposable connector vault keyring from child diagnostics", () => {
  const output = sanitizeChildOutputForReport({
    stage: "approval_e2e",
    stdout:
      'WORKSPACE_CONNECTOR_KEYRING_JSON={"activeKeyId":"lab-only-v1","keys":{"lab-only-v1":"SENTINEL_EPHEMERAL_VAULT_KEY"}}',
    stderr: "",
    exitCode: 1,
    signal: null,
  });
  assert.doesNotMatch(
    JSON.stringify(output),
    /SENTINEL_EPHEMERAL_VAULT_KEY/,
  );
  assert.match(output.stdout, /\[redacted/);
});

test("truncates safe assertion messages to 300 characters", () => {
  const longMessage = "Failure detail ".repeat(30);
  const output = [
    "TAP version 13",
    "not ok 1 - synthetic approval",
    "  ---",
    "  error: |-",
    `    ${longMessage}`,
    "  code: 'ERR_ASSERTION'",
    "  stack: |-",
    `    at TestContext.<anonymous> (file:///tmp/project/src/${testFileName}:6:3)`,
    "  ...",
    "# tests 1",
    "# pass 0",
    "# fail 1",
  ].join("\n");

  const failures = parseSafeNodeTestFailures(
    output,
    testFileName,
    testSource,
  );
  assert.equal(failures[0]?.message?.length, 300);
});

test("sanitizes captured stdout and stderr before writing a failure report", () => {
  const output = sanitizeChildOutputForReport({
    stage: "api_unit_tests",
    stdout: [
      "not ok 1 - synthetic database test",
      "  error: Connection to postgresql://user:TOP_SECRET@db.example/app failed",
      "  code: 'ERR_ASSERTION'",
      "  stack: at suite (security.test.ts:25:4)",
    ].join("\n"),
    stderr: [
      "APP_RUNTIME_DATABASE_URL=postgresql://runtime:OTHER_SECRET@127.0.0.1/db",
      "Authorization: Bearer SENTINEL_BEARER_VALUE",
      "-----BEGIN PRIVATE KEY-----",
      "SENTINEL_PRIVATE_KEY",
      "-----END PRIVATE KEY-----",
    ].join("\n"),
    exitCode: 1,
    signal: null,
  });

  const serialized = JSON.stringify(output);
  assert.equal(output.stage, "api_unit_tests");
  assert.equal(output.exitCode, 1);
  assert.match(output.stdout, /not ok 1 - synthetic database test/);
  assert.match(output.stdout, /security\.test\.ts:25:4/);
  assert.doesNotMatch(
    serialized,
    /TOP_SECRET|OTHER_SECRET|SENTINEL_|postgresql:\/\/|127\.0\.0\.1|db\.example|Bearer [A-Za-z0-9_-]+/,
  );
  assert.match(serialized, /\[redacted URL\]/);
  assert.match(serialized, /\[redacted private key\]/);
});

test("bounds sanitized child output and marks when it was truncated", () => {
  const output = sanitizeChildOutputForReport({
    stage: "api_unit_tests",
    // Ordinary diagnostic words exercise the size limit without matching the
    // sanitizer's long-token rule for possible credentials.
    stdout: `${"ordinary diagnostic ".repeat(1_000)}\nnot ok 119 - final failing subtest`,
    stderr: "",
    exitCode: 1,
    signal: null,
  });
  assert.equal(output.truncated, true);
  assert.match(output.stdout, /\[\.\.\.middle output omitted\.\.\.\]/);
  assert.match(output.stdout, /not ok 119 - final failing subtest$/);
});
