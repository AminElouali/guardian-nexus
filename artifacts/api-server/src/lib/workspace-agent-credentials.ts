import { createHash, randomBytes } from "node:crypto";

const AGENT_CREDENTIAL_PREFIX = "gnx_agent_v1_";
const AGENT_CREDENTIAL_SUFFIX = /^[A-Za-z0-9_-]{43}$/;

export function issueWorkspaceAgentCredential(): {
  credential: string;
  credentialSha256: string;
} {
  const credential = `${AGENT_CREDENTIAL_PREFIX}${randomBytes(32).toString("base64url")}`;
  return {
    credential,
    credentialSha256: hashWorkspaceAgentCredential(credential),
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
