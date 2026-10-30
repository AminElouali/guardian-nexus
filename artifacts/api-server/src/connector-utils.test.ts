import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decryptConnectorSecret,
  encryptConnectorSecret,
  signOAuthState,
  verifyOAuthState,
} from "./lib/connector-security";
import {
  parseRetryAfter,
  retryDelaySeconds,
} from "./lib/connector-jobs";
import { canManageIntegrations } from "./lib/access-control";

test("OAuth state is signed, expiring, and rejects tampering", () => {
  const previousSecret = process.env.CONNECTOR_STATE_SECRET;
  process.env.CONNECTOR_STATE_SECRET = "local-test-secret-for-state-signing-only";
  try {
    const state = {
      workspaceId: "11111111-1111-4111-8111-111111111111",
      userId: "test-user",
      nonce: "single-use-test-nonce",
      expiresAt: Date.now() + 60_000,
    };
    const signed = signOAuthState(state);
    assert.deepEqual(verifyOAuthState(signed), state);
    const [payload, signature] = signed.split(".");
    const altered = `${payload}.${signature.slice(0, -1)}x`;
    assert.equal(verifyOAuthState(altered), undefined);
    assert.equal(
      verifyOAuthState(
        signOAuthState({ ...state, expiresAt: Date.now() - 1 }),
      ),
      undefined,
    );
  } finally {
    if (previousSecret === undefined) delete process.env.CONNECTOR_STATE_SECRET;
    else process.env.CONNECTOR_STATE_SECRET = previousSecret;
  }
});

test("OAuth refresh tokens are authenticated-encrypted at rest", () => {
  const previousKey = process.env.CONNECTOR_ENCRYPTION_KEY;
  process.env.CONNECTOR_ENCRYPTION_KEY = "11".repeat(32);
  try {
    const stored = encryptConnectorSecret("test-refresh-token");
    assert.notEqual(stored, "test-refresh-token");
    assert.equal(decryptConnectorSecret(stored), "test-refresh-token");
    assert.throws(() => decryptConnectorSecret(`${stored.slice(0, -1)}x`));
  } finally {
    if (previousKey === undefined) delete process.env.CONNECTOR_ENCRYPTION_KEY;
    else process.env.CONNECTOR_ENCRYPTION_KEY = previousKey;
  }
});

test("Retry-After supports seconds and HTTP dates; retry delay is bounded", () => {
  const now = Date.parse("2026-10-30T12:00:00.000Z");
  assert.equal(parseRetryAfter("12", now), 12);
  assert.equal(parseRetryAfter("2026-10-30T12:00:30.000Z", now), 30);
  assert.equal(parseRetryAfter("invalid", now), undefined);
  assert.equal(retryDelaySeconds(1, 15), 15);
  assert.equal(retryDelaySeconds(50), 3600);
});

test("only owners and admins may manage tenant integrations", () => {
  assert.equal(canManageIntegrations("owner"), true);
  assert.equal(canManageIntegrations("admin"), true);
  assert.equal(canManageIntegrations("analyst"), false);
  assert.equal(canManageIntegrations("viewer"), false);
});
