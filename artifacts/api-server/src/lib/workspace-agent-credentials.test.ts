import assert from "node:assert/strict";
import test from "node:test";
import {
  hashWorkspaceAgentCredential,
  issueWorkspaceAgentCredential,
} from "./workspace-agent-credentials";

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
