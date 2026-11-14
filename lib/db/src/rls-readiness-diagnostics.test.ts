import assert from "node:assert/strict";
import test from "node:test";
import {
  RlsRuntimeReadinessError,
  rlsReadinessViolationCodes,
  safeRlsReadinessViolationCodes,
} from "./rls-readiness-diagnostics";

test("RLS diagnostics expose only allowlisted static violation codes", () => {
  const error = new RlsRuntimeReadinessError([
    "rls_disabled",
    "policy_count_mismatch",
  ]);

  assert.deepEqual(safeRlsReadinessViolationCodes(error), [
    "rls_disabled",
    "policy_count_mismatch",
  ]);
  assert.equal(error.message, "RLS runtime readiness check failed.");
  assert.deepEqual(Object.keys(rlsReadinessViolationCodes).length, 18);
});

test("unrecognized errors never expose their message or attached details", () => {
  const sentinel = "SENSITIVE_VALUE_MUST_NOT_BE_LOGGED";
  const error = Object.assign(new Error(sentinel), {
    connectionString: sentinel,
    cause: new Error(sentinel),
  });
  const safeCodes = safeRlsReadinessViolationCodes(error);

  assert.deepEqual(safeCodes, ["preflight_internal_error"]);
  assert.equal(JSON.stringify(safeCodes).includes(sentinel), false);
});

test("diagnostic construction rejects non-allowlisted runtime values", () => {
  const sentinel = "SENSITIVE_VALUE_MUST_NOT_BE_LOGGED";
  const error = new RlsRuntimeReadinessError([
    sentinel as (typeof rlsReadinessViolationCodes)[number],
  ]);

  assert.deepEqual(safeRlsReadinessViolationCodes(error), [
    "preflight_internal_error",
  ]);
  assert.equal(error.message.includes(sentinel), false);
});
