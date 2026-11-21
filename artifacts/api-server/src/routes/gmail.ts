import { randomBytes } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { Router, type IRouter } from "express";
import {
  connectorOAuthStatesTable,
  workspaceAuditEventsTable,
} from "@workspace/db";
import { requireAuth } from "../middlewares/requireAuth";
import { canManageIntegrations } from "../lib/access-control";
import {
  hashOAuthNonce,
  signOAuthState,
  verifyOAuthState,
} from "../lib/connector-security";
import {
  GOOGLE_GMAIL_CALLBACK_PATH,
  GOOGLE_GMAIL_SCOPES,
  getGoogleGmailOAuthSettings,
  parseGmailCredentialBundle,
  revokeGoogleRefreshToken,
  validateGmailAllowlist,
  type GmailCredentialBundleV1,
} from "../lib/gmail-connector";
import {
  disconnectWorkspaceGmail,
  getWorkspaceGmailStatus,
  saveWorkspaceGmailCredential,
  updateWorkspaceGmailAllowlist,
} from "../lib/workspace-gmail";
import { loadConnectorVaultKeyring } from "../lib/workspace-connector-vault";
import { withWorkspaceUserTransaction } from "../lib/tenant-db";

const router: IRouter = Router();
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_OAUTH_CODE_LENGTH = 4_096;

function safeOAuthSettings() {
  return getGoogleGmailOAuthSettings();
}

function callbackFailure(res: import("express").Response, status = 400): void {
  res.status(status).type("text/plain").send(
    status === 503
      ? "Gmail no está configurado en este servidor."
      : "No se pudo completar la conexión de Gmail. Vuelve a intentarlo desde el espacio de trabajo.",
  );
}

function queryValue(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

router.get(GOOGLE_GMAIL_CALLBACK_PATH.replace("/api", ""), async (req, res): Promise<void> => {
  const stateToken = queryValue(req.query.state);
  const state = stateToken ? verifyOAuthState(stateToken) : undefined;
  if (
    !state ||
    state.provider !== "google_gmail" ||
    !state.redirectUri ||
    !UUID_PATTERN.test(state.workspaceId) ||
    !UUID_PATTERN.test(state.userId)
  ) {
    callbackFailure(res);
    return;
  }
  const settings = safeOAuthSettings();
  if (!settings) {
    callbackFailure(res, 503);
    return;
  }
  let redirectUri: URL;
  try {
    redirectUri = new URL(state.redirectUri);
  } catch {
    callbackFailure(res);
    return;
  }
  if (
    settings.redirectUri !== state.redirectUri ||
    req.get("host")?.toLowerCase() !== redirectUri.host.toLowerCase()
  ) {
    callbackFailure(res);
    return;
  }
  const code = queryValue(req.query.code);
  const providerError = queryValue(req.query.error);
  if ((!code && !providerError) || (code && code.length > MAX_OAUTH_CODE_LENGTH)) {
    callbackFailure(res);
    return;
  }

  const consumed = await withWorkspaceUserTransaction(
    state.userId,
    state.workspaceId,
    async (tx, membership) => {
      if (!canManageIntegrations(membership.role)) return false;
      const [saved] = await tx
        .select({ nonceHash: connectorOAuthStatesTable.nonceHash })
        .from(connectorOAuthStatesTable)
        .where(
          and(
            eq(connectorOAuthStatesTable.nonceHash, hashOAuthNonce(state.nonce)),
            eq(connectorOAuthStatesTable.userId, state.userId),
            eq(connectorOAuthStatesTable.workspaceId, state.workspaceId),
          ),
        )
        .limit(1);
      if (!saved) return false;
      await tx
        .delete(connectorOAuthStatesTable)
        .where(eq(connectorOAuthStatesTable.nonceHash, saved.nonceHash));
      if (providerError) {
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId: state.workspaceId,
          actorUserId: state.userId,
          action: "integration.consent_declined",
          resourceType: "provider_connection",
          resourceId: "google_gmail",
          metadata: { provider: "google_gmail", result: "declined" },
        });
      }
      return true;
    },
  );
  if (!consumed.authorized || !consumed.value) {
    callbackFailure(res, 403);
    return;
  }
  if (providerError) {
    res.status(400).type("text/plain").send(
      "No se concedió el acceso a Gmail. No se guardó ninguna conexión.",
    );
    return;
  }
  if (!code) {
    callbackFailure(res);
    return;
  }

  try {
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: settings.clientId,
        client_secret: settings.clientSecret,
        grant_type: "authorization_code",
        code,
        redirect_uri: settings.redirectUri,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenResponse.ok) {
      callbackFailure(res, tokenResponse.status === 429 ? 429 : 400);
      return;
    }
    const tokenBody: unknown = await tokenResponse.json();
    if (!tokenBody || typeof tokenBody !== "object" || Array.isArray(tokenBody)) {
      callbackFailure(res);
      return;
    }
    const token = tokenBody as Record<string, unknown>;
    const grantedScopes =
      typeof token.scope === "string"
        ? token.scope.split(/\s+/).filter(Boolean)
        : [];
    const requiredScopesPresent =
      grantedScopes.includes("openid") &&
      (grantedScopes.includes("email") ||
        grantedScopes.includes("https://www.googleapis.com/auth/userinfo.email")) &&
      grantedScopes.includes("https://www.googleapis.com/auth/gmail.send");
    if (
      !requiredScopesPresent ||
      typeof token.refresh_token !== "string" ||
      token.refresh_token.length < 8 ||
      token.refresh_token.length > 4_096 ||
      typeof token.access_token !== "string" ||
      token.access_token.length < 8 ||
      token.access_token.length > 4_096
    ) {
      callbackFailure(res);
      return;
    }
    const identityResponse = await fetch(
      "https://openidconnect.googleapis.com/v1/userinfo",
      {
        headers: { authorization: `Bearer ${token.access_token}` },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!identityResponse.ok) {
      callbackFailure(res);
      return;
    }
    const identity: unknown = await identityResponse.json();
    if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
      callbackFailure(res);
      return;
    }
    const account = identity as Record<string, unknown>;
    if (
      typeof account.email !== "string" ||
      account.email_verified !== true ||
      typeof account.sub !== "string" ||
      account.sub.length < 1 ||
      account.sub.length > 256
    ) {
      callbackFailure(res);
      return;
    }
    const allowedRecipients = validateGmailAllowlist([account.email]);
    if (!allowedRecipients) {
      callbackFailure(res);
      return;
    }
    const bundle: GmailCredentialBundleV1 = {
      version: 1,
      refreshToken: token.refresh_token,
      accountEmail: account.email.toLowerCase(),
      googleSubject: account.sub,
      allowedRecipients,
    };
    const bundleJson = JSON.stringify(bundle);
    if (!parseGmailCredentialBundle(bundleJson)) {
      callbackFailure(res);
      return;
    }
    loadConnectorVaultKeyring();
    const saved = await withWorkspaceUserTransaction(
      state.userId,
      state.workspaceId,
      async (tx, membership) => {
        if (!canManageIntegrations(membership.role)) return false;
        await saveWorkspaceGmailCredential(tx, {
          workspaceId: state.workspaceId,
          actorUserId: state.userId,
          bundleJson,
          membershipRole: membership.role,
        });
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId: state.workspaceId,
          actorUserId: state.userId,
          action: "integration.consent_granted",
          resourceType: "provider_connection",
          resourceId: "google_gmail",
          metadata: {
            provider: "google_gmail",
            scopes: GOOGLE_GMAIL_SCOPES.join(" "),
          },
        });
        return true;
      },
    );
    if (!saved.authorized || !saved.value) {
      callbackFailure(res, 403);
      return;
    }
    res.redirect(303, new URL("/integrations?gmail=connected", redirectUri.origin).toString());
  } catch (error) {
    req.log.warn(
      {
        event: "gmail_oauth_callback_failed",
        errorName: error instanceof Error ? error.name : "UnknownError",
      },
      "Gmail OAuth callback failed",
    );
    callbackFailure(res, 503);
  }
});

router.use("/workspaces", requireAuth);

router.get("/workspaces/:workspaceId/gmail-connection", async (req, res): Promise<void> => {
  const workspaceId = req.params.workspaceId;
  if (!UUID_PATTERN.test(workspaceId)) {
    res.status(400).json({ error: "El espacio de trabajo no es válido." });
    return;
  }
  const settings = safeOAuthSettings();
  if (!settings) {
    res.json({
      configured: false,
      connected: false,
      accountEmail: null,
      allowedRecipients: [],
      scopes: GOOGLE_GMAIL_SCOPES,
    });
    return;
  }
  try {
    const result = await getWorkspaceGmailStatus(
      req.authUserId!,
      workspaceId,
      true,
    );
    if (!result.authorized || !result.value) {
      res.status(403).json({ error: "Solo una persona administradora puede ver esta conexión." });
      return;
    }
    res.json(result.value);
  } catch {
    res.status(503).json({
      error: "No se pudo leer la conexión cifrada de Gmail. Comprueba la configuración del servidor.",
    });
  }
});

router.post(
  "/workspaces/:workspaceId/gmail-connection/authorize",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    if (!UUID_PATTERN.test(workspaceId)) {
      res.status(400).json({ error: "El espacio de trabajo no es válido." });
      return;
    }
    const settings = safeOAuthSettings();
    if (!settings) {
      res.status(503).json({ error: "Gmail no está configurado en este servidor." });
      return;
    }
    try {
      loadConnectorVaultKeyring();
    } catch {
      res.status(503).json({ error: "La caja fuerte de conexiones no está configurada." });
      return;
    }
    const nonce = randomBytes(32).toString("base64url");
    const expiresAt = Date.now() + 10 * 60 * 1000;
    let stateToken: string;
    try {
      stateToken = signOAuthState({
        workspaceId,
        userId: req.authUserId!,
        nonce,
        expiresAt,
        provider: "google_gmail",
        redirectUri: settings.redirectUri,
      });
    } catch {
      res.status(503).json({ error: "No se pudo iniciar la conexión segura de Gmail." });
      return;
    }
    const started = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canManageIntegrations(membership.role)) return "forbidden" as const;
        await tx
          .delete(connectorOAuthStatesTable)
          .where(
            and(
              eq(connectorOAuthStatesTable.workspaceId, workspaceId),
              eq(connectorOAuthStatesTable.userId, req.authUserId!),
            ),
          );
        await tx.insert(connectorOAuthStatesTable).values({
          nonceHash: hashOAuthNonce(nonce),
          workspaceId,
          userId: req.authUserId!,
          expiresAt: new Date(expiresAt),
        });
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId,
          actorUserId: req.authUserId!,
          action: "integration.authorization_started",
          resourceType: "provider_connection",
          resourceId: "google_gmail",
          metadata: {
            provider: "google_gmail",
            scopes: GOOGLE_GMAIL_SCOPES.join(" "),
          },
        });
        return "started" as const;
      },
    );
    if (!started.authorized || started.value === "forbidden") {
      res.status(403).json({ error: "Solo propietarios y administradores pueden conectar Gmail." });
      return;
    }
    const authorizationUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authorizationUrl.search = new URLSearchParams({
      client_id: settings.clientId,
      redirect_uri: settings.redirectUri,
      response_type: "code",
      scope: GOOGLE_GMAIL_SCOPES.join(" "),
      access_type: "offline",
      prompt: "consent",
      state: stateToken,
    }).toString();
    res.json({
      authorizationUrl: authorizationUrl.toString(),
      scopes: GOOGLE_GMAIL_SCOPES,
    });
  },
);

router.put(
  "/workspaces/:workspaceId/gmail-connection/recipients",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    const body = req.body as Record<string, unknown> | null;
    const allowedRecipients =
      body &&
      typeof body === "object" &&
      !Array.isArray(body) &&
      Object.keys(body).length === 1 &&
      Object.hasOwn(body, "allowedRecipients")
        ? validateGmailAllowlist(body.allowedRecipients)
        : null;
    if (!UUID_PATTERN.test(workspaceId) || !allowedRecipients) {
      res.status(400).json({
        error: "Indica una lista válida de hasta 50 correos o dominios exactos.",
      });
      return;
    }
    try {
      const updated = await updateWorkspaceGmailAllowlist(
        req.authUserId!,
        workspaceId,
        allowedRecipients,
      );
      if (!updated) {
        res.status(404).json({ error: "No hay una cuenta de Gmail conectada." });
        return;
      }
      res.json({ allowedRecipients });
    } catch {
      res.status(503).json({ error: "No se pudo guardar la lista permitida de Gmail." });
    }
  },
);

router.delete(
  "/workspaces/:workspaceId/gmail-connection",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    if (!UUID_PATTERN.test(workspaceId)) {
      res.status(400).json({ error: "El espacio de trabajo no es válido." });
      return;
    }
    try {
      const disconnected = await disconnectWorkspaceGmail(
        req.authUserId!,
        workspaceId,
      );
      if (!disconnected.authorized) {
        res.status(403).json({ error: "Solo propietarios y administradores pueden desconectar Gmail." });
        return;
      }
      if (!disconnected.disconnected) {
        res.status(404).json({ error: "No hay una cuenta de Gmail conectada." });
        return;
      }
      const providerRevoked = disconnected.refreshToken
        ? await revokeGoogleRefreshToken(disconnected.refreshToken)
        : false;
      res.json({ disconnected: true, providerRevoked });
    } catch {
      res.status(503).json({ error: "No se pudo desconectar Gmail de este espacio." });
    }
  },
);

export default router;
