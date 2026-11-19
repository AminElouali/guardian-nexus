import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  ConnectorVaultError,
  decryptConnectorCredential,
  encryptConnectorCredential,
  loadConnectorVaultKeyring,
} from "./workspace-connector-vault";

function keyring(keyId: string, key = randomBytes(32)) {
  return {
    activeKeyId: keyId,
    keys: new Map([[keyId, key]]),
  };
}

test("connector credential encryption authenticates workspace/service and decrypts in memory", () => {
  const secret = "synthetic-token-that-must-not-leak";
  const ring = keyring("lab-key-v1");
  const context = {
    workspaceId: "6c83476b-d8b3-43a1-8606-d23a2100da50",
    serviceId: "lab.fake.v1",
  };
  const encrypted = encryptConnectorCredential(secret, context, ring);
  assert.equal(
    decryptConnectorCredential(encrypted, context, ring),
    secret,
  );
  assert.equal(encrypted.encryptionKeyId, "lab-key-v1");
  assert.equal(encrypted.lastFour, "leak");
  assert.notEqual(encrypted.encryptedSecret, secret);
  assert.equal(encrypted.nonce.length, 16);
  assert.equal(encrypted.authTag.length, 22);
});

test("wrong key, altered ciphertext and changed associated data fail closed", () => {
  const secret = "synthetic-credential-not-for-logs";
  const context = {
    workspaceId: "6c83476b-d8b3-43a1-8606-d23a2100da50",
    serviceId: "lab.fake.v1",
  };
  const ring = keyring("lab-key-v1");
  const encrypted = encryptConnectorCredential(secret, context, ring);
  const tampered = {
    ...encrypted,
    encryptedSecret: `${encrypted.encryptedSecret[0] === "A" ? "B" : "A"}${encrypted.encryptedSecret.slice(1)}`,
  };
  const failures = [
    () =>
      decryptConnectorCredential(
        encrypted,
        context,
        keyring("lab-key-v1"),
      ),
    () => decryptConnectorCredential(tampered, context, ring),
    () =>
      decryptConnectorCredential(
        encrypted,
        { ...context, workspaceId: "9d19f290-e66d-47bc-8224-e1991fccb3dd" },
        ring,
      ),
  ];
  for (const fail of failures) {
    assert.throws(fail, (error: unknown) => {
      assert.ok(error instanceof ConnectorVaultError);
      assert.notEqual(error.message.includes(secret), true);
      assert.equal(error.message.includes("not-for-logs"), false);
      return true;
    });
  }
});

test("vault keyring parsing accepts explicit rotation keys and rejects malformed key material", () => {
  const oldKey = randomBytes(32).toString("base64url");
  const newKey = randomBytes(32).toString("base64url");
  const environment = {
    WORKSPACE_CONNECTOR_KEYRING_JSON: JSON.stringify({
      activeKeyId: "new-key",
      keys: { "old-key": oldKey, "new-key": newKey },
    }),
  } as NodeJS.ProcessEnv;
  const rotated = loadConnectorVaultKeyring(environment);
  assert.equal(rotated.activeKeyId, "new-key");
  assert.equal(rotated.keys.size, 2);
  assert.throws(
    () =>
      loadConnectorVaultKeyring({
        WORKSPACE_CONNECTOR_KEYRING_JSON: JSON.stringify({
          activeKeyId: "bad",
          keys: { bad: "invalid-secret-key" },
        }),
      } as NodeJS.ProcessEnv),
    (error: unknown) =>
      error instanceof ConnectorVaultError &&
      error.code === "vault_keyring_invalid" &&
      !error.message.includes("invalid-secret-key"),
  );
});

test("connector vault uses fresh nonces and can decrypt records after key rotation", () => {
  const oldKey = randomBytes(32);
  const newKey = randomBytes(32);
  const oldRing = {
    activeKeyId: "key-v1",
    keys: new Map([["key-v1", oldKey]]),
  };
  const currentRing = {
    activeKeyId: "key-v2",
    keys: new Map([
      ["key-v1", oldKey],
      ["key-v2", newKey],
    ]),
  };
  const context = {
    workspaceId: "6c83476b-d8b3-43a1-8606-d23a2100da50",
    serviceId: "lab.fake.v1",
  };
  const prior = encryptConnectorCredential(
    "old-synthetic-secret-value",
    context,
    oldRing,
  );
  const current = encryptConnectorCredential(
    "new-synthetic-secret-value",
    context,
    currentRing,
  );
  assert.equal(prior.encryptionKeyId, "key-v1");
  assert.equal(current.encryptionKeyId, "key-v2");
  assert.equal(
    decryptConnectorCredential(prior, context, currentRing),
    "old-synthetic-secret-value",
  );
  assert.equal(
    decryptConnectorCredential(current, context, currentRing),
    "new-synthetic-secret-value",
  );

  const nonces = new Set<string>();
  for (let index = 0; index < 128; index += 1) {
    const item = encryptConnectorCredential(
      `synthetic-secret-${index}`,
      context,
      currentRing,
    );
    nonces.add(item.nonce);
  }
  assert.equal(nonces.size, 128);
});
