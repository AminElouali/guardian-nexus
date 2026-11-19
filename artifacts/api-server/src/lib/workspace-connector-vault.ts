import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export const CONNECTOR_VAULT_KEYRING_ENV =
  "WORKSPACE_CONNECTOR_KEYRING_JSON";
const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const SERVICE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_SECRET_BYTES = 4096;

export type ConnectorVaultErrorCode =
  | "vault_keyring_unavailable"
  | "vault_keyring_invalid"
  | "credential_input_invalid"
  | "credential_key_unavailable"
  | "credential_ciphertext_invalid";

export class ConnectorVaultError extends Error {
  constructor(readonly code: ConnectorVaultErrorCode) {
    super(`connector_vault_${code}`);
    this.name = "ConnectorVaultError";
  }
}

export type ConnectorVaultKeyring = {
  activeKeyId: string;
  keys: ReadonlyMap<string, Buffer>;
};

export type EncryptedConnectorCredential = {
  encryptedSecret: string;
  nonce: string;
  authTag: string;
  encryptionKeyId: string;
  lastFour: string;
};

export type StoredEncryptedConnectorCredential = Pick<
  EncryptedConnectorCredential,
  "encryptedSecret" | "nonce" | "authTag" | "encryptionKeyId"
>;

export function loadConnectorVaultKeyring(
  environment: NodeJS.ProcessEnv = process.env,
): ConnectorVaultKeyring {
  const encoded = environment[CONNECTOR_VAULT_KEYRING_ENV];
  if (!encoded) {
    throw new ConnectorVaultError("vault_keyring_unavailable");
  }

  try {
    const parsed: unknown = JSON.parse(encoded);
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      throw new Error();
    }
    const record = parsed as Record<string, unknown>;
    if (
      Object.keys(record).sort().join(",") !== "activeKeyId,keys" ||
      typeof record.activeKeyId !== "string" ||
      !KEY_ID_PATTERN.test(record.activeKeyId) ||
      record.keys === null ||
      typeof record.keys !== "object" ||
      Array.isArray(record.keys)
    ) {
      throw new Error();
    }

    const rawKeys = record.keys as Record<string, unknown>;
    const entries = Object.entries(rawKeys);
    if (
      entries.length < 1 ||
      entries.length > 8 ||
      !Object.hasOwn(rawKeys, record.activeKeyId)
    ) {
      throw new Error();
    }
    const keys = new Map<string, Buffer>();
    for (const [keyId, rawKey] of entries) {
      if (
        !KEY_ID_PATTERN.test(keyId) ||
        typeof rawKey !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(rawKey)
      ) {
        throw new Error();
      }
      const key = Buffer.from(rawKey, "base64url");
      if (key.length !== 32 || key.toString("base64url") !== rawKey) {
        throw new Error();
      }
      keys.set(keyId, key);
    }
    return { activeKeyId: record.activeKeyId, keys };
  } catch {
    throw new ConnectorVaultError("vault_keyring_invalid");
  }
}

function additionalAuthenticatedData(input: {
  workspaceId: string;
  serviceId: string;
  keyId: string;
}): Buffer {
  if (
    !SERVICE_ID_PATTERN.test(input.serviceId) ||
    !KEY_ID_PATTERN.test(input.keyId) ||
    !/^[0-9a-f-]{36}$/i.test(input.workspaceId)
  ) {
    throw new ConnectorVaultError("credential_input_invalid");
  }
  return Buffer.from(
    `guardian-nexus:workspace-connector-credential:v1\n${input.workspaceId}\n${input.serviceId}\n${input.keyId}`,
    "utf8",
  );
}

export function encryptConnectorCredential(
  secret: string,
  context: { workspaceId: string; serviceId: string },
  keyring: ConnectorVaultKeyring,
): EncryptedConnectorCredential {
  if (
    typeof secret !== "string" ||
    Array.from(secret).length < 8 ||
    Buffer.byteLength(secret, "utf8") > MAX_SECRET_BYTES
  ) {
    throw new ConnectorVaultError("credential_input_invalid");
  }
  const key = keyring.keys.get(keyring.activeKeyId);
  if (!key || key.length !== 32) {
    throw new ConnectorVaultError("credential_key_unavailable");
  }
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(
    additionalAuthenticatedData({
      ...context,
      keyId: keyring.activeKeyId,
    }),
  );
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(secret, "utf8")),
    cipher.final(),
  ]);
  const lastFour = Array.from(secret).slice(-4).join("");
  return {
    encryptedSecret: ciphertext.toString("base64url"),
    nonce: nonce.toString("base64url"),
    authTag: cipher.getAuthTag().toString("base64url"),
    encryptionKeyId: keyring.activeKeyId,
    lastFour,
  };
}

export function decryptConnectorCredential(
  stored: StoredEncryptedConnectorCredential,
  context: { workspaceId: string; serviceId: string },
  keyring: ConnectorVaultKeyring,
): string {
  try {
    const key = keyring.keys.get(stored.encryptionKeyId);
    if (!key || key.length !== 32) {
      throw new ConnectorVaultError("credential_key_unavailable");
    }
    if (
      !/^[A-Za-z0-9_-]{11,5462}$/.test(stored.encryptedSecret) ||
      !/^[A-Za-z0-9_-]{16}$/.test(stored.nonce) ||
      !/^[A-Za-z0-9_-]{22}$/.test(stored.authTag) ||
      Buffer.from(stored.nonce, "base64url").toString("base64url") !==
        stored.nonce ||
      Buffer.from(stored.authTag, "base64url").toString("base64url") !==
        stored.authTag
    ) {
      throw new Error();
    }
    const nonce = Buffer.from(stored.nonce, "base64url");
    const authTag = Buffer.from(stored.authTag, "base64url");
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, {
      authTagLength: 16,
    });
    decipher.setAAD(
      additionalAuthenticatedData({
        ...context,
        keyId: stored.encryptionKeyId,
      }),
    );
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(stored.encryptedSecret, "base64url")),
      decipher.final(),
    ]);
    if (plaintext.length === 0 || plaintext.length > MAX_SECRET_BYTES) {
      throw new Error();
    }
    return plaintext.toString("utf8");
  } catch (error) {
    if (
      error instanceof ConnectorVaultError &&
      error.code === "credential_key_unavailable"
    ) {
      throw error;
    }
    throw new ConnectorVaultError("credential_ciphertext_invalid");
  }
}
