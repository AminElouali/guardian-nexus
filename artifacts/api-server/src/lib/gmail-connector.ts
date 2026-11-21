import { Buffer } from "node:buffer";
import type { ConnectorExecutionAdapter } from "./workspace-connector-executions";

export const GMAIL_CONNECTOR_SERVICE_ID = "gmail.google.v1";
export const GOOGLE_GMAIL_CALLBACK_PATH =
  "/api/oauth/google/gmail/callback";
export const GOOGLE_GMAIL_SCOPES = Object.freeze([
  "openid",
  "email",
  "https://www.googleapis.com/auth/gmail.send",
]);

const MAX_TOKEN_LENGTH = 4_096;
const MAX_ALLOWLIST_ENTRIES = 50;
const EMAIL_ADDRESS =
  /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const ALLOWLIST_DOMAIN = /^@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const GMAIL_MESSAGE_ID = /^[A-Za-z0-9_-]{1,256}$/;

export type GoogleGmailOAuthSettings = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
};

export type GmailCredentialBundleV1 = {
  version: 1;
  refreshToken: string;
  accountEmail: string;
  googleSubject: string;
  allowedRecipients: string[];
};

export type GmailConnectionStatus = {
  configured: boolean;
  connected: boolean;
  accountEmail: string | null;
  allowedRecipients: string[];
  scopes: readonly string[];
};

export type GmailSendResult =
  | { ok: true; gmailMessageId: string }
  | {
      ok: false;
      failureCode:
        | "gmail_reconnect_required"
        | "gmail_quota_exceeded"
        | "gmail_unavailable"
        | "gmail_send_rejected"
        | "gmail_recipient_not_allowed";
    };

type FetchLike = typeof fetch;

export function getGoogleGmailOAuthSettings(
  env: NodeJS.ProcessEnv = process.env,
): GoogleGmailOAuthSettings | null {
  const clientId = env.GOOGLE_OAUTH_CLIENT_ID;
  const clientSecret = env.GOOGLE_OAUTH_CLIENT_SECRET;
  const redirectUri = env.GOOGLE_OAUTH_REDIRECT_URI;
  if (!clientId || !clientSecret || !redirectUri) return null;
  try {
    const parsed = new URL(redirectUri);
    if (
      parsed.protocol !== "https:" ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      parsed.pathname !== GOOGLE_GMAIL_CALLBACK_PATH ||
      parsed.origin !== `${parsed.protocol}//${parsed.host}`
    ) {
      return null;
    }
  } catch {
    return null;
  }
  return { clientId, clientSecret, redirectUri };
}

export function validateGmailAllowlist(
  values: unknown,
): string[] | null {
  if (
    !Array.isArray(values) ||
    values.length > MAX_ALLOWLIST_ENTRIES ||
    values.some((value) => typeof value !== "string")
  ) {
    return null;
  }
  const normalized: string[] = [];
  for (const value of values as string[]) {
    const entry = value.trim().toLowerCase();
    if (
      entry.length > 254 ||
      (!EMAIL_ADDRESS.test(entry) && !ALLOWLIST_DOMAIN.test(entry))
    ) {
      return null;
    }
    normalized.push(entry);
  }
  return [...new Set(normalized)].sort();
}

export function isAllowedGmailRecipient(
  recipient: string,
  allowlist: readonly string[],
): boolean {
  if (!EMAIL_ADDRESS.test(recipient)) return false;
  const normalized = recipient.toLowerCase();
  const domain = `@${normalized.slice(normalized.lastIndexOf("@") + 1)}`;
  return allowlist.some(
    (allowed) => allowed.toLowerCase() === normalized || allowed.toLowerCase() === domain,
  );
}

export function parseGmailCredentialBundle(
  value: string,
): GmailCredentialBundleV1 | null {
  if (Buffer.byteLength(value, "utf8") > MAX_TOKEN_LENGTH) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    const record = parsed as Record<string, unknown>;
    if (
      Object.keys(record).sort().join(",") !==
        "accountEmail,allowedRecipients,googleSubject,refreshToken,version" ||
      record.version !== 1 ||
      typeof record.refreshToken !== "string" ||
      record.refreshToken.length < 8 ||
      record.refreshToken.length > MAX_TOKEN_LENGTH ||
      typeof record.accountEmail !== "string" ||
      !EMAIL_ADDRESS.test(record.accountEmail) ||
      typeof record.googleSubject !== "string" ||
      record.googleSubject.length < 1 ||
      record.googleSubject.length > 256
    ) {
      return null;
    }
    const allowedRecipients = validateGmailAllowlist(record.allowedRecipients);
    if (!allowedRecipients) return null;
    return {
      version: 1,
      refreshToken: record.refreshToken,
      accountEmail: record.accountEmail.toLowerCase(),
      googleSubject: record.googleSubject,
      allowedRecipients,
    };
  } catch {
    return null;
  }
}

function googleErrorCode(body: unknown): string | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const error = (body as Record<string, unknown>).error;
  return typeof error === "string" && error.length <= 64 ? error : null;
}

function isGmailQuotaError(status: number, body: unknown): boolean {
  if (status === 429) return true;
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  const error = (body as Record<string, unknown>).error;
  if (!error || typeof error !== "object" || Array.isArray(error)) return false;
  const errors = (error as Record<string, unknown>).errors;
  return Array.isArray(errors) && errors.some((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
    const reason = (entry as Record<string, unknown>).reason;
    return reason === "quotaExceeded" || reason === "dailyLimitExceeded";
  });
}

function testMessage(to: string): string {
  const subject = "Prueba de correo de Guardian Nexus";
  const body =
    "Este es un correo de prueba enviado por Guardian Nexus. No contiene datos de clientes.";
  return [
    `To: ${to}`,
    `Subject: ${subject}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "",
    body,
  ].join("\r\n");
}

export async function sendGmailTestMessage(
  input: {
    bundle: GmailCredentialBundleV1;
    recipient: string;
    oauth: Pick<GoogleGmailOAuthSettings, "clientId" | "clientSecret">;
    fetcher?: FetchLike;
  },
): Promise<GmailSendResult> {
  const fetcher = input.fetcher ?? fetch;
  if (!isAllowedGmailRecipient(input.recipient, input.bundle.allowedRecipients)) {
    return { ok: false, failureCode: "gmail_recipient_not_allowed" };
  }

  let tokenResponse: Response;
  try {
    tokenResponse = await fetcher("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: input.oauth.clientId,
        client_secret: input.oauth.clientSecret,
        grant_type: "refresh_token",
        refresh_token: input.bundle.refreshToken,
      }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return { ok: false, failureCode: "gmail_unavailable" };
  }
  let tokenBody: unknown = null;
  try {
    tokenBody = await tokenResponse.json();
  } catch {
    // A malformed provider response is handled as a safe reconnect failure.
  }
  if (!tokenResponse.ok) {
    if (googleErrorCode(tokenBody) === "invalid_grant" || tokenResponse.status === 401) {
      return { ok: false, failureCode: "gmail_reconnect_required" };
    }
    if (isGmailQuotaError(tokenResponse.status, tokenBody)) {
      return { ok: false, failureCode: "gmail_quota_exceeded" };
    }
    return { ok: false, failureCode: "gmail_unavailable" };
  }
  if (
    !tokenBody ||
    typeof tokenBody !== "object" ||
    Array.isArray(tokenBody) ||
    typeof (tokenBody as Record<string, unknown>).access_token !== "string"
  ) {
    return { ok: false, failureCode: "gmail_reconnect_required" };
  }
  const accessToken = (tokenBody as Record<string, unknown>).access_token as string;
  if (accessToken.length < 8 || accessToken.length > MAX_TOKEN_LENGTH) {
    return { ok: false, failureCode: "gmail_reconnect_required" };
  }

  let sendResponse: Response;
  try {
    sendResponse = await fetcher(
      "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          raw: Buffer.from(testMessage(input.recipient), "utf8").toString("base64url"),
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );
  } catch {
    return { ok: false, failureCode: "gmail_unavailable" };
  }
  let sendBody: unknown = null;
  try {
    sendBody = await sendResponse.json();
  } catch {
    // Invalid provider output is never copied into logs or responses.
  }
  if (!sendResponse.ok) {
    if (sendResponse.status === 401) {
      return { ok: false, failureCode: "gmail_reconnect_required" };
    }
    if (isGmailQuotaError(sendResponse.status, sendBody)) {
      return { ok: false, failureCode: "gmail_quota_exceeded" };
    }
    return { ok: false, failureCode: "gmail_send_rejected" };
  }
  if (
    !sendBody ||
    typeof sendBody !== "object" ||
    Array.isArray(sendBody) ||
    typeof (sendBody as Record<string, unknown>).id !== "string" ||
    !GMAIL_MESSAGE_ID.test((sendBody as Record<string, unknown>).id as string)
  ) {
    return { ok: false, failureCode: "gmail_send_rejected" };
  }
  return {
    ok: true,
    gmailMessageId: (sendBody as Record<string, unknown>).id as string,
  };
}

export async function revokeGoogleRefreshToken(
  refreshToken: string,
  fetcher: FetchLike = fetch,
): Promise<boolean> {
  try {
    const response = await fetcher("https://oauth2.googleapis.com/revoke", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: refreshToken }),
      signal: AbortSignal.timeout(5_000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

export function createGmailConnectorAdapter(
  serviceId: string,
  oauth: Pick<GoogleGmailOAuthSettings, "clientId" | "clientSecret">,
  fetcher: FetchLike = fetch,
): ConnectorExecutionAdapter {
  return {
    serviceId,
    async execute(input: {
      workspaceId: string;
      actionType: string;
      arguments: Record<string, string | number | boolean>;
      credential: string;
    }) {
      if (input.actionType !== "guardian.email.send.external.v1") {
        return {
          resultCode: "gmail_send_rejected",
          failureCode: "gmail_send_rejected",
        };
      }
      const bundle = parseGmailCredentialBundle(input.credential);
      const recipient = input.arguments.to;
      const templateId = input.arguments.template_id;
      if (
        !bundle ||
        typeof recipient !== "string" ||
        templateId !== "guardian-demo-email-v1"
      ) {
        return {
          resultCode: "gmail_send_rejected",
          failureCode: "gmail_send_rejected",
        };
      }
      const result = await sendGmailTestMessage({
        bundle,
        recipient,
        oauth,
        fetcher,
      });
      if (!result.ok) {
        return {
          resultCode: result.failureCode,
          failureCode: result.failureCode,
        };
      }
      return {
        resultCode: "gmail_sent",
        summary: "Correo de prueba enviado por Gmail.",
        auditMetadata: { gmailMessageId: result.gmailMessageId },
      };
    },
  };
}
