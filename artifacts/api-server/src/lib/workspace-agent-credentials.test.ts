import assert from "node:assert/strict";
import test from "node:test";
import {
  hashWorkspaceAgentCredential,
  issueWorkspaceAgentCredential,
  workspaceAgentCredentialHashesMatch,
} from "./workspace-agent-credentials";
import { createWorkspaceAgentAttemptLimiter } from "./workspace-agent-attempt-limiter";

test("agent credentials are opaque, versioned and stored as a stable hash", () => {
  const issued = issueWorkspaceAgentCredential();
  assert.ok(
    /^gnx_agent_v1_[A-Za-z0-9_-]{43}$/.test(issued.credential),
    "issued credentials use the versioned opaque format",
  );
  assert.ok(/^[a-f0-9]{64}$/.test(issued.credentialSha256));
  assert.ok(
    hashWorkspaceAgentCredential(issued.credential) === issued.credentialSha256,
    "the raw value maps to the digest stored by the API",
  );
});

test("agent credential hashing rejects malformed inputs", () => {
  assert.equal(hashWorkspaceAgentCredential(""), null);
  assert.equal(hashWorkspaceAgentCredential("not-a-guardian-agent-token"), null);
  assert.equal(hashWorkspaceAgentCredential("gnx_agent_v1_short"), null);
  assert.equal(
    hashWorkspaceAgentCredential(`gnx_agent_v1_${"!".repeat(43)}`),
    null,
  );
});

test("agent credential digest comparison is fixed-size and rejects malformed hashes", () => {
  const issued = issueWorkspaceAgentCredential();
  assert.equal(
    workspaceAgentCredentialHashesMatch(
      issued.credentialSha256,
      issued.credentialSha256,
    ),
    true,
  );
  assert.equal(
    workspaceAgentCredentialHashesMatch(
      issued.credentialSha256,
      "0".repeat(64),
    ),
    false,
  );
  assert.equal(
    workspaceAgentCredentialHashesMatch(issued.credentialSha256, null),
    false,
  );
  assert.equal(
    workspaceAgentCredentialHashesMatch("not-a-hash", issued.credentialSha256),
    false,
  );
});

test("agent authentication attempt limit is scoped, bounded and resets after its window", () => {
  let now = 10_000;
  const limiter = createWorkspaceAgentAttemptLimiter({
    maxAttempts: 2,
    windowMs: 1_000,
    now: () => now,
  });
  assert.equal(limiter.consume("workspace-a:client-a").allowed, true);
  assert.equal(limiter.consume("workspace-a:client-a").allowed, true);
  assert.deepEqual(limiter.consume("workspace-a:client-a"), {
    allowed: false,
    retryAfterSeconds: 1,
  });
  assert.equal(limiter.consume("workspace-b:client-a").allowed, true);
  now += 1_000;
  assert.equal(limiter.consume("workspace-a:client-a").allowed, true);
});
