import assert from "node:assert/strict";
import { test } from "node:test";
import { safeHttpRequestLog } from "./safe-http-request-log";

test("HTTP request log summary omits headers and bodies that may contain agent credentials", () => {
  const credential = `gnx_agent_v1_${"A".repeat(43)}`;
  const request = {
    id: "request-id",
    method: "POST",
    url: "/api/agent/workspaces/123/action-proposals?debug=private",
    headers: { authorization: `Bearer ${credential}` },
    body: { credential },
  };
  const summary = safeHttpRequestLog(request);
  const serialized = JSON.stringify(summary);
  assert.deepEqual(summary, {
    id: "request-id",
    method: "POST",
    url: "/api/agent/workspaces/123/action-proposals",
  });
  assert.equal(serialized.includes(credential), false);
  assert.equal(Object.hasOwn(summary, "headers"), false);
  assert.equal(Object.hasOwn(summary, "body"), false);
});
