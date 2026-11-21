import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { WorkspaceGmailConnectionStatus } from "@workspace/api-client-react";
import { GmailConnectionCardView } from "./GmailConnectionCard";

const connected: WorkspaceGmailConnectionStatus = {
  configured: true,
  connected: true,
  accountEmail: "test-owner@example.test",
  allowedRecipients: ["test-owner@example.test"],
  scopes: [
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.send",
  ],
};

function markup(
  status: WorkspaceGmailConnectionStatus | null,
  canManage = true,
) {
  return renderToStaticMarkup(
    createElement(GmailConnectionCardView, {
      status,
      canManage,
      allowlistValue: connected.allowedRecipients.join("\n"),
    }),
  );
}

test("Gmail card clearly reports an unconfigured connector without exposing controls", () => {
  const html = markup({
    configured: false,
    connected: false,
    accountEmail: null,
    allowedRecipients: [],
    scopes: connected.scopes,
  });
  assert.match(html, /Gmail \(modo prueba\)/);
  assert.match(html, /No configurado/);
  assert.doesNotMatch(html, /button-gmail-connect/);
  assert.doesNotMatch(html, /access_token|refresh_token|client_secret/i);
});

test("connected Gmail shows the default recipient allowlist and disconnect action, never a token", () => {
  const html = markup(connected);
  assert.match(html, /test-owner@example\.test/);
  assert.match(html, /button-gmail-save-recipients/);
  assert.match(html, /button-gmail-disconnect/);
  assert.match(html, /No se lee el buzón/);
  assert.match(html, /gmail\.send/);
  assert.doesNotMatch(html, /access_token|refresh_token|Bearer /i);
});

test("non-administrators do not see Gmail account details or management controls", () => {
  const html = markup(connected, false);
  assert.match(html, /Solo propietarios y administradores/);
  assert.doesNotMatch(html, /test-owner@example\.test/);
  assert.doesNotMatch(html, /button-gmail-connect|button-gmail-disconnect|gmail-allowlist-form/);
});
