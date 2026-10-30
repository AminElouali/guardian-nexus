import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export type OAuthState = {
  workspaceId: string;
  userId: string;
  nonce: string;
  expiresAt: number;
};

function stateSecret(): string {
  const secret = process.env.CONNECTOR_STATE_SECRET ?? process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("Connector OAuth state signing is not configured.");
  }
  return secret;
}

export function signOAuthState(state: OAuthState): string {
  const payload = Buffer.from(JSON.stringify(state)).toString("base64url");
  const signature = createHmac("sha256", stateSecret())
    .update(payload)
    .digest("base64url");
  return `${payload}.${signature}`;
}

export function verifyOAuthState(value: string): OAuthState | undefined {
  const [payload, signature, extra] = value.split(".");
  if (!payload || !signature || extra) return undefined;
  const expected = createHmac("sha256", stateSecret())
    .update(payload)
    .digest();
  let received: Buffer;
  try {
    received = Buffer.from(signature, "base64url");
  } catch {
    return undefined;
  }
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
    return undefined;
  }
  try {
    const claims = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    ) as OAuthState;
    if (
      typeof claims.workspaceId !== "string" ||
      typeof claims.userId !== "string" ||
      typeof claims.nonce !== "string" ||
      !Number.isSafeInteger(claims.expiresAt) ||
      claims.expiresAt <= Date.now()
    ) {
      return undefined;
    }
    return claims;
  } catch {
    return undefined;
  }
}

export function hashOAuthNonce(nonce: string): string {
  return createHash("sha256").update(nonce).digest("hex");
}

function encryptionKey(): Buffer {
  const value = process.env.CONNECTOR_ENCRYPTION_KEY;
  const rootSecret = value ?? process.env.SESSION_SECRET;
  if (!rootSecret) throw new Error("Connector token encryption is not configured.");
  const key = value
    ? /^[0-9a-f]{64}$/i.test(value)
      ? Buffer.from(value, "hex")
      : Buffer.from(value, "base64")
    : Buffer.from(
        hkdfSync(
          "sha256",
          rootSecret,
          "guardian-nexus",
          "connector-token-encryption-v1",
          32,
        ),
      );
  if (key.length !== 32) {
    throw new Error("Connector token encryption key must be 32 bytes.");
  }
  return key;
}

export function encryptConnectorSecret(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return [
    "v1",
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

export function decryptConnectorSecret(value: string): string {
  const [version, iv, tag, ciphertext, extra] = value.split(".");
  if (version !== "v1" || !iv || !tag || !ciphertext || extra) {
    throw new Error("Stored connector token has an unsupported format.");
  }
  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}
