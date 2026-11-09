import assert from "node:assert/strict";
import test from "node:test";
import { getWorkspaceLoadErrorCopy } from "./workspace-load-errors";

test("workspace errors distinguish session, access and missing resource", () => {
  assert.equal(getWorkspaceLoadErrorCopy({ status: 401 }).kind, "session");
  assert.equal(getWorkspaceLoadErrorCopy({ status: 403 }).kind, "forbidden");
  assert.equal(getWorkspaceLoadErrorCopy({ status: 404 }).kind, "not-found");
});

test("workspace errors distinguish API outage from application 5xx", () => {
  assert.equal(getWorkspaceLoadErrorCopy({ status: 502 }).kind, "unavailable");
  assert.equal(getWorkspaceLoadErrorCopy({ status: 503 }).kind, "unavailable");
  assert.equal(getWorkspaceLoadErrorCopy({ status: 504 }).kind, "unavailable");
  assert.equal(getWorkspaceLoadErrorCopy({ status: 500 }).kind, "server");
});

test("invalid or schema-shaped responses have a safe, distinct message", () => {
  const parseError = getWorkspaceLoadErrorCopy({
    name: "ResponseParseError",
    status: 200,
    message: "private response payload",
  });
  assert.equal(parseError.kind, "invalid-response");
  assert.equal(parseError.detail.includes("private response payload"), false);
  assert.equal(getWorkspaceLoadErrorCopy({ name: "ZodError" }).kind, "invalid-response");
});

test("network and unexpected errors never expose raw server messages", () => {
  const networkError = getWorkspaceLoadErrorCopy(
    new TypeError("Failed to fetch"),
  );
  assert.equal(networkError.kind, "network");

  const unexpected = getWorkspaceLoadErrorCopy(
    new Error("database password and internal SQL details"),
  );
  assert.equal(unexpected.kind, "unexpected");
  assert.equal(unexpected.detail.includes("database password"), false);
});
