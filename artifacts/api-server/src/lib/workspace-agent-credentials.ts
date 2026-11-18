import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

const AGENT_CREDENTIAL_PREFIX = "gnx_agent_v1_";
const AGENT_CREDENTIAL_SUFFIX = /^[A-Za-z0-9_-]{43}$/;

export function issueWorkspaceAgentCredential(): {
  credential: string;
  credentialSha256: string;
} {
  const credential = `${AGENT_CREDENTIAL_PREFIX}${randomBytes(32).toString("base64url")}`;
  const credentialSha256 = hashWorkspaceAgentCredential(credential);
  if (credentialSha256 === null) {
    throw new Error("agent_credential_generation_invalid");
  }
  return {
    credential,
    credentialSha256,
  };
}

export function hashWorkspaceAgentCredential(
  credential: string,
): string | null {
  if (
    typeof credential !== "string" ||
    !credential.startsWith(AGENT_CREDENTIAL_PREFIX) ||
    !AGENT_CREDENTIAL_SUFFIX.test(
      credential.slice(AGENT_CREDENTIAL_PREFIX.length),
    )
  ) {
    return null;
  }
  return createHash("sha256").update(credential, "utf8").digest("hex");
}

/**
 * Compare fixed-size SHA-256 digests without data-dependent byte comparison.
 * Invalid or missing values still perform one 32-byte timingSafeEqual call.
 */
export function workspaceAgentCredentialHashesMatch(
  storedHash: string | null | undefined,
  presentedHash: string | null | undefined,
): boolean {
  const storedIsValid =
    typeof storedHash === "string" && /^[a-f0-9]{64}$/.test(storedHash);
  const presentedIsValid =
    typeof presentedHash === "string" && /^[a-f0-9]{64}$/.test(presentedHash);
  const storedBytes = Buffer.from(
    storedIsValid ? storedHash : "0".repeat(64),
    "hex",
  );
  const presentedBytes = Buffer.from(
    presentedIsValid ? presentedHash : "0".repeat(64),
    "hex",
  );
  const matches = timingSafeEqual(storedBytes, presentedBytes);
  return storedIsValid && presentedIsValid && matches;
}
