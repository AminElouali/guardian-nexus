import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GOOGLE_GMAIL_SCOPES,
  createGmailConnectorAdapter,
  getGoogleGmailOAuthSettings,
  isAllowedGmailRecipient,
  parseGmailCredentialBundle,
  sendGmailTestMessage,
  validateGmailAllowlist,
} from "./gmail-connector";

const oauth = {
  clientId: "synthetic-client-id",
  clientSecret: "synthetic-client-secret",
};
const bundle = {
  version: 1 as const,
  refreshToken: "synthetic-refresh-token",
  accountEmail: "test-owner@example.test",
  googleSubject: "synthetic-google-subject",
  allowedRecipients: ["test-owner@example.test"],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("Gmail configuration requires a fixed HTTPS callback and only requests the approved scopes", () => {
  assert.deepEqual(GOOGLE_GMAIL_SCOPES, [
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.send",
  ]);
  assert.ok(getGoogleGmailOAuthSettings({
    GOOGLE_OAUTH_CLIENT_ID: "synthetic-client-id",
    GOOGLE_OAUTH_CLIENT_SECRET: "synthetic-client-secret",
    GOOGLE_OAUTH_REDIRECT_URI:
      "https://guardian-nexus.replit.app/api/oauth/google/gmail/callback",
  } as NodeJS.ProcessEnv));
  assert.equal(getGoogleGmailOAuthSettings({
    GOOGLE_OAUTH_CLIENT_ID: "synthetic-client-id",
    GOOGLE_OAUTH_CLIENT_SECRET: "synthetic-client-secret",
    GOOGLE_OAUTH_REDIRECT_URI:
      "https://guardian-nexus.replit.app/unexpected",
  } as NodeJS.ProcessEnv), null);
  assert.equal(getGoogleGmailOAuthSettings({} as NodeJS.ProcessEnv), null);
});

test("allowlist accepts exact emails and domains, rejects malformed and broad patterns", () => {
  assert.deepEqual(
    validateGmailAllowlist(["Test-Owner@example.test", "@example.test"]),
    ["@example.test", "test-owner@example.test"],
  );
  assert.equal(validateGmailAllowlist(["*@example.test"]), null);
  assert.equal(validateGmailAllowlist(["@-bad.example"]), null);
  assert.equal(
    isAllowedGmailRecipient("other@example.test", ["@example.test"]),
    true,
  );
  assert.equal(
    isAllowedGmailRecipient("other@sub.example.test", ["@example.test"]),
    false,
  );
  assert.equal(
    isAllowedGmailRecipient("other@elsewhere.test", bundle.allowedRecipients),
    false,
  );
});

test("Gmail sends only the fixed test body to an allowlisted address and returns only the message ID", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = String(input);
    requests.push({ url, init });
    if (url === "https://oauth2.googleapis.com/token") {
      return jsonResponse({ access_token: "synthetic-access-token" });
    }
    if (url === "https://gmail.googleapis.com/gmail/v1/users/me/messages/send") {
      return jsonResponse({ id: "synthetic-message-id", threadId: "ignored" });
    }
    throw new Error("unexpected_test_url");
  };
  const result = await sendGmailTestMessage({
    bundle,
    recipient: "test-owner@example.test",
    oauth,
    fetcher,
  });
  assert.deepEqual(result, { ok: true, gmailMessageId: "synthetic-message-id" });
  assert.equal(requests.length, 2);
  assert.equal(requests[0]?.url, "https://oauth2.googleapis.com/token");
  assert.equal(
    requests[1]?.url,
    "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
  );
  const sendPayload = JSON.parse(String(requests[1]?.init?.body)) as {
    raw: string;
  };
  const rawMessage = Buffer.from(sendPayload.raw, "base64url").toString("utf8");
  assert.match(rawMessage, /To: test-owner@example\.test/);
  assert.match(rawMessage, /correo de prueba/i);
  assert.doesNotMatch(rawMessage, /refresh-token|access-token|datos de clientes reales/i);
  assert.doesNotMatch(JSON.stringify(result), /refresh-token|access-token|threadId/);
});

test("blocked recipient, revoked token, quota, and provider outage never call Gmail send", async () => {
  let gmailSendCalls = 0;
  const blocked = await sendGmailTestMessage({
    bundle,
    recipient: "outside@not-allowed.test",
    oauth,
    fetcher: async () => {
      throw new Error("should_not_call_provider");
    },
  });
  assert.deepEqual(blocked, {
    ok: false,
    failureCode: "gmail_recipient_not_allowed",
  });

  const revoked = await sendGmailTestMessage({
    bundle,
    recipient: "test-owner@example.test",
    oauth,
    fetcher: async () => jsonResponse({ error: "invalid_grant" }, 400),
  });
  assert.deepEqual(revoked, {
    ok: false,
    failureCode: "gmail_reconnect_required",
  });

  const quota = await sendGmailTestMessage({
    bundle,
    recipient: "test-owner@example.test",
    oauth,
    fetcher: async () => jsonResponse({ error: "rateLimitExceeded" }, 429),
  });
  assert.deepEqual(quota, {
    ok: false,
    failureCode: "gmail_quota_exceeded",
  });

  const unavailable = await sendGmailTestMessage({
    bundle,
    recipient: "test-owner@example.test",
    oauth,
    fetcher: async (input) => {
      if (String(input) === "https://oauth2.googleapis.com/token") {
        return jsonResponse({ access_token: "synthetic-access-token" });
      }
      gmailSendCalls += 1;
      throw new Error("synthetic_network_error");
    },
  });
  assert.deepEqual(unavailable, {
    ok: false,
    failureCode: "gmail_unavailable",
  });
  assert.equal(gmailSendCalls, 1);
});

test("credential parsing rejects extra fields and the adapter never includes token material in results", async () => {
  assert.equal(
    parseGmailCredentialBundle(JSON.stringify({ ...bundle, unexpected: "value" })),
    null,
  );
  const adapter = createGmailConnectorAdapter(
    "guardian-demo-mcp",
    oauth,
    async (input) => {
      if (String(input) === "https://oauth2.googleapis.com/token") {
        return jsonResponse({ access_token: "synthetic-access-token" });
      }
      return jsonResponse({ id: "synthetic-message-id" });
    },
  );
  const result = await adapter.execute({
    workspaceId: "00000000-0000-4000-8000-000000000001",
    actionType: "guardian.email.send.external.v1",
    arguments: {
      to: "test-owner@example.test",
      template_id: "guardian-demo-email-v1",
    },
    credential: JSON.stringify(bundle),
  });
  assert.equal(result.resultCode, "gmail_sent");
  assert.deepEqual(result.auditMetadata, { gmailMessageId: "synthetic-message-id" });
  assert.equal(JSON.stringify(result).includes(bundle.refreshToken), false);
});
