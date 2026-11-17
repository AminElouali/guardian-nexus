import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSafeNodeTestFailures } from "./run-postgres-local-lab";

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
