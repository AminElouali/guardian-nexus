import { randomBytes } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { AssumeRoleCommand, GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { fromTokenFile } from "@aws-sdk/credential-providers";
import { Router, type IRouter } from "express";
import {
  connectorOAuthStatesTable,
  connectorJobsTable,
  providerConnectionsTable,
  workspaceAuditEventsTable,
} from "@workspace/db";
import {
  BeginMicrosoftAuthorizationResponse,
  ConfigureAwsIntegrationBody,
  ConfigureAwsIntegrationResponse,
  ListWorkspaceIntegrationsParams,
  ListWorkspaceIntegrationsResponse,
  MicrosoftOAuthCallbackQueryParams,
  RevokeWorkspaceIntegrationParams,
  VerifyAwsIntegrationResponse,
} from "@workspace/api-zod";
import { requireAuth } from "../middlewares/requireAuth";
import { withWorkspaceUserTransaction } from "../lib/tenant-db";
import {
  encryptConnectorSecret,
  hashOAuthNonce,
  signOAuthState,
  verifyOAuthState,
} from "../lib/connector-security";
import {
  ProviderRateLimitError,
  parseRetryAfter,
  reserveProviderRequest,
} from "../lib/connector-jobs";
import { canManageIntegrations } from "../lib/access-control";

const router: IRouter = Router();
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GRAPH_SCOPES = [
  "openid",
  "profile",
  "offline_access",
  "Organization.Read.All",
];

function oauthSettings() {
  const clientId = process.env.MICROSOFT_CLIENT_ID;
  const clientSecret = process.env.MICROSOFT_CLIENT_SECRET;
  const redirectUri = process.env.MICROSOFT_REDIRECT_URI;
  if (!clientId || !clientSecret || !redirectUri) return undefined;
  return { clientId, clientSecret, redirectUri };
}

function errorStatus(error: unknown): number {
  if (error instanceof ProviderRateLimitError) return 429;
  if (error instanceof Error && /not configured/.test(error.message)) return 503;
  return 502;
}

function sendProviderError(
  res: import("express").Response,
  error: unknown,
): void {
  if (error instanceof ProviderRateLimitError) {
    res.setHeader("Retry-After", String(error.retryAfterSeconds));
    res.status(429).json({
      error: "Provider rate limit reached",
      retryAfterSeconds: error.retryAfterSeconds,
    });
    return;
  }
  const status = errorStatus(error);
  res.status(status).json({
    error:
      status === 503
        ? "Provider connection is not configured on this server"
        : "Provider authorization could not be completed",
  });
}

async function audit(
  tx: Parameters<Parameters<typeof withWorkspaceUserTransaction>[2]>[0],
  workspaceId: string,
  actorUserId: string,
  action: string,
  provider: string,
  metadata: Record<string, string | number | boolean | null>,
) {
  await tx.insert(workspaceAuditEventsTable).values({
    workspaceId,
    actorUserId,
    action,
    resourceType: "provider_connection",
    resourceId: provider,
    metadata: { provider, ...metadata },
  });
}

async function auditProviderEvent(
  userId: string,
  workspaceId: string,
  provider: string,
  action: string,
  metadata: Record<string, string | number | boolean | null>,
): Promise<void> {
  await withWorkspaceUserTransaction(userId, workspaceId, async (tx, membership) => {
    if (canManageIntegrations(membership.role)) {
      await audit(tx, workspaceId, userId, action, provider, metadata);
    }
  });
}

router.get("/oauth/microsoft/callback", async (req, res): Promise<void> => {
  const query = MicrosoftOAuthCallbackQueryParams.safeParse(req.query);
  const encodedState = query.success ? query.data.state : "";
  const state = verifyOAuthState(encodedState);
  if (!state || !UUID_PATTERN.test(state.workspaceId)) {
    res.status(400).send("Authorization state is invalid or expired. Start again from the workspace.");
    return;
  }

  const consumed = await withWorkspaceUserTransaction(
    state.userId,
    state.workspaceId,
    async (tx, membership) => {
      if (!canManageIntegrations(membership.role)) return { kind: "forbidden" as const };
      const nonceHash = hashOAuthNonce(state.nonce);
      const [saved] = await tx
        .select()
        .from(connectorOAuthStatesTable)
        .where(
          and(
            eq(connectorOAuthStatesTable.nonceHash, nonceHash),
            eq(connectorOAuthStatesTable.userId, state.userId),
            eq(connectorOAuthStatesTable.workspaceId, state.workspaceId),
          ),
        )
        .limit(1);
      if (!saved || saved.expiresAt.getTime() <= Date.now()) {
        return { kind: "invalid-state" as const };
      }
      await tx
        .delete(connectorOAuthStatesTable)
        .where(eq(connectorOAuthStatesTable.nonceHash, nonceHash));
      if (query.success && query.data.error) {
        await audit(tx, state.workspaceId, state.userId, "integration.consent_declined", "microsoft_graph", {
          result: "declined",
        });
      }
      return { kind: "consumed" as const };
    },
  );
  if (!consumed.authorized || consumed.value.kind === "forbidden") {
    res.status(403).send("Workspace access denied.");
    return;
  }
  if (consumed.value.kind !== "consumed") {
    res.status(400).send("Authorization state has already been used or expired.");
    return;
  }
  if (query.success && query.data.error) {
    res.status(400).send("Microsoft authorization was declined. No scan was started.");
    return;
  }
  const code = query.success ? query.data.code ?? "" : "";
  const settings = oauthSettings();
  if (!code || !settings) {
    res.status(settings ? 400 : 503).send(
      settings
        ? "Microsoft did not return an authorization code."
        : "Microsoft OAuth is not configured on this server.",
    );
    return;
  }

  const [connection] = await withWorkspaceUserTransaction(
    state.userId,
    state.workspaceId,
    (tx) =>
      tx
        .select({ id: providerConnectionsTable.id })
        .from(providerConnectionsTable)
        .where(
          and(
            eq(providerConnectionsTable.workspaceId, state.workspaceId),
            eq(providerConnectionsTable.provider, "microsoft_graph"),
            eq(providerConnectionsTable.status, "pending"),
          ),
        )
        .limit(1),
  ).then((result) => (result.authorized ? result.value : []));
  if (!connection) {
    res.status(403).send("The Microsoft connection is no longer pending.");
    return;
  }

  try {
    await reserveProviderRequest(state.userId, state.workspaceId, connection.id);
    const tokenResponse = await fetch(
      "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: settings.clientId,
          client_secret: settings.clientSecret,
          grant_type: "authorization_code",
          code,
          redirect_uri: settings.redirectUri,
          scope: GRAPH_SCOPES.join(" "),
        }),
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (!tokenResponse.ok) {
      if (tokenResponse.status === 429) {
        throw new ProviderRateLimitError(
          parseRetryAfter(tokenResponse.headers.get("retry-after")) ?? 30,
        );
      }
      throw new Error("Microsoft token exchange failed.");
    }
    const token = (await tokenResponse.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
      scope?: string;
    };
    if (!token.access_token || !token.refresh_token) {
      throw new Error("Microsoft did not return the required delegated tokens.");
    }

    const grantedScopes = (token.scope ?? "").split(/\s+/).filter(Boolean);
    if (
      !grantedScopes.some(
        (scope) =>
          scope === "Organization.Read.All" ||
          scope.endsWith("/Organization.Read.All"),
      )
    ) {
      throw new Error("Microsoft consent did not include the requested read scopes.");
    }
    const organizationResponse = await fetch(
      "https://graph.microsoft.com/v1.0/organization?$select=id",
      {
        headers: { authorization: `Bearer ${token.access_token}` },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!organizationResponse.ok) {
      if (organizationResponse.status === 429) {
        throw new ProviderRateLimitError(
          parseRetryAfter(organizationResponse.headers.get("retry-after")) ?? 30,
        );
      }
      throw new Error("Microsoft tenant identity could not be confirmed.");
    }
    const organization = (await organizationResponse.json()) as {
      value?: Array<{ id?: string }>;
    };
    const tenantId = organization.value?.[0]?.id;
    if (!tenantId) throw new Error("Microsoft tenant identity is missing.");
    const encryptedRefreshToken = encryptConnectorSecret(token.refresh_token);

    const saved = await withWorkspaceUserTransaction(
      state.userId,
      state.workspaceId,
      async (tx, membership) => {
        if (!canManageIntegrations(membership.role)) return false;
        const [updated] = await tx
          .update(providerConnectionsTable)
          .set({
            status: "active",
            externalTenantId: tenantId,
            grantedScopes:
              grantedScopes.length > 0 ? grantedScopes : ["Organization.Read.All"],
            encryptedRefreshToken,
            tokenExpiresAt: new Date(Date.now() + (token.expires_in ?? 3600) * 1000),
            consentedByUserId: state.userId,
            consentedAt: new Date(),
            revokedAt: null,
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(providerConnectionsTable.workspaceId, state.workspaceId),
              eq(providerConnectionsTable.provider, "microsoft_graph"),
              eq(providerConnectionsTable.status, "pending"),
            ),
          )
          .returning({ id: providerConnectionsTable.id });
        if (!updated) return false;
        await audit(tx, state.workspaceId, state.userId, "integration.consent_granted", "microsoft_graph", {
          tenantId,
          scopes: grantedScopes.join(" "),
        });
        return true;
      },
    );
    if (!saved.authorized || !saved.value) {
      res.status(403).send("Workspace access changed before consent could be recorded.");
      return;
    }
    res.status(200).send("Microsoft 365 is authorized for this workspace. No scan was started; return to the Guardian Nexus Integrations page.");
  } catch (error) {
    await auditProviderEvent(
      state.userId,
      state.workspaceId,
      "microsoft_graph",
      "integration.consent_verification_failed",
      { reason: error instanceof ProviderRateLimitError ? "rate_limited" : "authorization_failed" },
    );
    sendProviderError(res, error);
  }
});

router.use("/workspaces", requireAuth);

router.get(
  "/workspaces/:workspaceId/integrations",
  async (req, res): Promise<void> => {
    const params = ListWorkspaceIntegrationsParams.safeParse(req.params);
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const workspaceId = params.data.workspaceId;
    const result = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      (tx) =>
        tx
          .select({
            id: providerConnectionsTable.id,
            provider: providerConnectionsTable.provider,
            status: providerConnectionsTable.status,
            externalTenantId: providerConnectionsTable.externalTenantId,
            awsAccountId: providerConnectionsTable.awsAccountId,
            awsRoleArn: providerConnectionsTable.awsRoleArn,
            grantedScopes: providerConnectionsTable.grantedScopes,
            consentedAt: providerConnectionsTable.consentedAt,
            revokedAt: providerConnectionsTable.revokedAt,
            updatedAt: providerConnectionsTable.updatedAt,
          })
          .from(providerConnectionsTable)
          .where(eq(providerConnectionsTable.workspaceId, workspaceId)),
    );
    if (!result.authorized) {
      res.status(403).json({ error: "Workspace access denied" });
      return;
    }
    res.json(ListWorkspaceIntegrationsResponse.parse(result.value));
  },
);

router.post(
  "/workspaces/:workspaceId/integrations/microsoft/authorize",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    if (!UUID_PATTERN.test(workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const settings = oauthSettings();
    if (!settings) {
      res.status(503).json({ error: "Microsoft OAuth is not configured on this server" });
      return;
    }
    const nonce = randomBytes(32).toString("base64url");
    const expiresAt = Date.now() + 10 * 60 * 1000;
    const signedState = signOAuthState({
      workspaceId,
      userId: req.authUserId!,
      nonce,
      expiresAt,
    });
    const result = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canManageIntegrations(membership.role)) return { kind: "forbidden" as const };
        const now = new Date();
        await tx
          .insert(providerConnectionsTable)
          .values({ workspaceId, provider: "microsoft_graph", status: "pending" })
          .onConflictDoUpdate({
            target: [
              providerConnectionsTable.workspaceId,
              providerConnectionsTable.provider,
            ],
            set: {
              status: "pending",
              encryptedRefreshToken: null,
              externalTenantId: null,
              grantedScopes: [],
              consentedByUserId: null,
              consentedAt: null,
              revokedAt: null,
              updatedAt: now,
            },
          });
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
        await audit(tx, workspaceId, req.authUserId!, "integration.authorization_started", "microsoft_graph", {
          requestedScopes: GRAPH_SCOPES.join(" "),
        });
        return { kind: "started" as const };
      },
    );
    if (!result.authorized) {
      res.status(403).json({ error: "Workspace access denied" });
      return;
    }
    if (result.value.kind === "forbidden") {
      res.status(403).json({ error: "Only workspace owners and admins can manage integrations" });
      return;
    }
    const authorizationUrl = new URL(
      "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
    );
    authorizationUrl.search = new URLSearchParams({
      client_id: settings.clientId,
      response_type: "code",
      redirect_uri: settings.redirectUri,
      response_mode: "query",
      scope: GRAPH_SCOPES.join(" "),
      state: signedState,
      prompt: "consent",
    }).toString();
    res.json(
      BeginMicrosoftAuthorizationResponse.parse({
        authorizationUrl: authorizationUrl.toString(),
        scopes: GRAPH_SCOPES,
      }),
    );
  },
);

router.post(
  "/workspaces/:workspaceId/integrations/aws",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    const parsedBody = ConfigureAwsIntegrationBody.safeParse(req.body);
    const roleArn = parsedBody.success ? parsedBody.data.roleArn.trim() : "";
    const arnMatch = /^arn:aws:iam::(\d{12}):role\/[A-Za-z0-9+=,.@_/-]{1,512}$/.exec(roleArn);
    if (!UUID_PATTERN.test(workspaceId) || !arnMatch) {
      res.status(400).json({ error: "Provide a valid AWS IAM role ARN" });
      return;
    }
    if (!process.env.AWS_CONNECTOR_TRUSTED_PRINCIPAL_ARN) {
      res.status(503).json({ error: "AWS connector trust principal is not configured on this server" });
      return;
    }
    const externalId = randomBytes(32).toString("hex");
    const result = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canManageIntegrations(membership.role)) return { kind: "forbidden" as const };
        const [connection] = await tx
          .insert(providerConnectionsTable)
          .values({
            workspaceId,
            provider: "aws",
            status: "pending",
            awsAccountId: arnMatch[1],
            awsRoleArn: roleArn,
            awsExternalId: externalId,
          })
          .onConflictDoUpdate({
            target: [
              providerConnectionsTable.workspaceId,
              providerConnectionsTable.provider,
            ],
            set: {
              status: "pending",
              awsAccountId: arnMatch[1],
              awsRoleArn: roleArn,
              awsExternalId: externalId,
              consentedByUserId: null,
              consentedAt: null,
              revokedAt: null,
              updatedAt: new Date(),
            },
          })
          .returning({ id: providerConnectionsTable.id });
        await audit(tx, workspaceId, req.authUserId!, "integration.authorization_started", "aws", {
          accountId: arnMatch[1],
        });
        return { kind: "started" as const, id: connection.id };
      },
    );
    if (!result.authorized) {
      res.status(403).json({ error: "Workspace access denied" });
      return;
    }
    if (result.value.kind === "forbidden") {
      res.status(403).json({ error: "Only workspace owners and admins can manage integrations" });
      return;
    }
    res.status(201).json(ConfigureAwsIntegrationResponse.parse({
      connectionId: result.value.id,
      accountId: arnMatch[1],
      roleArn,
      externalId,
      trustedPrincipalArn: process.env.AWS_CONNECTOR_TRUSTED_PRINCIPAL_ARN ?? null,
      trustPolicyJson: JSON.stringify(
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "GuardianNexusReadOnlyCrossAccount",
              Effect: "Allow",
              Principal: {
                AWS: process.env.AWS_CONNECTOR_TRUSTED_PRINCIPAL_ARN,
              },
              Action: "sts:AssumeRole",
              Condition: {
                StringEquals: { "sts:ExternalId": externalId },
              },
            },
          ],
        },
        null,
        2,
      ),
      sessionDurationSeconds: 900,
      requiredPolicy: "arn:aws:iam::aws:policy/SecurityAudit",
      instructions:
        "Create a read-only role that trusts the supplied principal and requires this ExternalId, then verify it. Do not attach write permissions.",
    }));
  },
);

router.post(
  "/workspaces/:workspaceId/integrations/aws/verify",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    if (!UUID_PATTERN.test(workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const found = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canManageIntegrations(membership.role)) return { kind: "forbidden" as const };
        const [connection] = await tx
          .select()
          .from(providerConnectionsTable)
          .where(
            and(
              eq(providerConnectionsTable.workspaceId, workspaceId),
              eq(providerConnectionsTable.provider, "aws"),
              eq(providerConnectionsTable.status, "pending"),
            ),
          )
          .limit(1);
        return connection
          ? { kind: "pending" as const, connection }
          : { kind: "not-found" as const };
      },
    );
    if (!found.authorized) {
      res.status(403).json({ error: "Workspace access denied" });
      return;
    }
    if (found.value.kind === "forbidden") {
      res.status(403).json({ error: "Only workspace owners and admins can manage integrations" });
      return;
    }
    if (found.value.kind === "not-found") {
      res.status(404).json({ error: "Pending AWS role configuration not found" });
      return;
    }
    const connection = found.value.connection;
    if (!process.env.AWS_ROLE_ARN || !process.env.AWS_WEB_IDENTITY_TOKEN_FILE) {
      res.status(503).json({ error: "AWS workload identity is not configured on this server" });
      return;
    }

    let sourceSts: STSClient | undefined;
    let assumedSts: STSClient | undefined;
    try {
      await reserveProviderRequest(req.authUserId!, workspaceId, connection.id);
      sourceSts = new STSClient({
        region: process.env.AWS_REGION ?? "eu-west-1",
        credentials: fromTokenFile(),
      });
      const assumed = await sourceSts.send(
        new AssumeRoleCommand({
          RoleArn: connection.awsRoleArn!,
          ExternalId: connection.awsExternalId!,
          RoleSessionName: `GuardianNexus-${workspaceId.slice(0, 8)}`,
          DurationSeconds: 900,
        }),
      );
      if (
        !assumed.Credentials?.AccessKeyId ||
        !assumed.Credentials.SecretAccessKey ||
        !assumed.Credentials.SessionToken
      ) {
        throw new Error("STS did not return temporary credentials.");
      }
      assumedSts = new STSClient({
        region: process.env.AWS_REGION ?? "eu-west-1",
        credentials: {
          accessKeyId: assumed.Credentials.AccessKeyId,
          secretAccessKey: assumed.Credentials.SecretAccessKey,
          sessionToken: assumed.Credentials.SessionToken,
          expiration: assumed.Credentials.Expiration,
        },
      });
      const identity = await assumedSts.send(new GetCallerIdentityCommand({}));
      const roleName = connection.awsRoleArn!
        .split(":role/")[1]
        ?.split("/")
        .at(-1);
      if (!roleName) throw new Error("Configured AWS role ARN is invalid.");
      const expectedAssumedRoleArnPrefix =
        `arn:aws:sts::${connection.awsAccountId}:assumed-role/${roleName}/GuardianNexus-${workspaceId.slice(0, 8)}`;
      if (
        identity.Account !== connection.awsAccountId ||
        !identity.Arn?.startsWith(expectedAssumedRoleArnPrefix)
      ) {
        throw new Error("Assumed role account did not match the configured AWS account.");
      }

      const saved = await withWorkspaceUserTransaction(
        req.authUserId!,
        workspaceId,
        async (tx, membership) => {
          if (!canManageIntegrations(membership.role)) return false;
          const [updated] = await tx
            .update(providerConnectionsTable)
            .set({
              status: "active",
              consentedByUserId: req.authUserId!,
              consentedAt: new Date(),
              revokedAt: null,
              updatedAt: new Date(),
            })
            .where(
              and(
                eq(providerConnectionsTable.id, connection.id),
                eq(providerConnectionsTable.status, "pending"),
              ),
            )
            .returning({ id: providerConnectionsTable.id });
          if (!updated) return false;
          await audit(tx, workspaceId, req.authUserId!, "integration.consent_granted", "aws", {
            accountId: connection.awsAccountId!,
            roleArn: connection.awsRoleArn!,
            sessionDurationSeconds: 900,
          });
          return true;
        },
      );
      if (!saved.authorized || !saved.value) {
        res.status(403).json({ error: "Workspace access changed before consent could be recorded" });
        return;
      }
      res.json(VerifyAwsIntegrationResponse.parse({
        status: "active",
        accountId: connection.awsAccountId,
        roleArn: connection.awsRoleArn,
        sessionDurationSeconds: 900,
        message: "AWS role verified. No scan was started.",
      }));
    } catch (error) {
      const providerError = error as {
        name?: string;
        $metadata?: {
          httpStatusCode?: number;
          httpHeaders?: Record<string, string>;
        };
      };
      if (
        providerError.$metadata?.httpStatusCode === 429 ||
        /throttl/i.test(providerError.name ?? "")
      ) {
        const retryAfter = parseRetryAfter(
          providerError.$metadata?.httpHeaders?.["retry-after"],
        );
        sendProviderError(
          res,
          new ProviderRateLimitError(retryAfter ?? 30),
        );
        await auditProviderEvent(
          req.authUserId!,
          workspaceId,
          "aws",
          "integration.verification_failed",
          { reason: "rate_limited" },
        );
        return;
      }
      await auditProviderEvent(
        req.authUserId!,
        workspaceId,
        "aws",
        "integration.verification_failed",
        { reason: "role_verification_failed" },
      );
      sendProviderError(res, error);
    } finally {
      assumedSts?.destroy();
      sourceSts?.destroy();
    }
  },
);

router.delete(
  "/workspaces/:workspaceId/integrations/:provider",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    const parsedParams = RevokeWorkspaceIntegrationParams.safeParse(req.params);
    const provider = parsedParams.success ? parsedParams.data.provider : "";
    if (
      !parsedParams.success ||
      !UUID_PATTERN.test(parsedParams.data.workspaceId) ||
      workspaceId !== parsedParams.data.workspaceId
    ) {
      res.status(400).json({ error: "Invalid workspace or provider" });
      return;
    }
    const result = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canManageIntegrations(membership.role)) return { kind: "forbidden" as const };
        const [connection] = await tx
          .update(providerConnectionsTable)
          .set({
            status: "revoked",
            encryptedRefreshToken: null,
            revokedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(providerConnectionsTable.workspaceId, workspaceId),
              eq(providerConnectionsTable.provider, provider),
            ),
          )
          .returning({ id: providerConnectionsTable.id });
        if (!connection) return { kind: "not-found" as const };
        await tx
          .update(connectorJobsTable)
          .set({ status: "cancelled", updatedAt: new Date() })
          .where(
            and(
              eq(connectorJobsTable.workspaceId, workspaceId),
              eq(connectorJobsTable.providerConnectionId, connection.id),
              eq(connectorJobsTable.status, "queued"),
            ),
          );
        await audit(tx, workspaceId, req.authUserId!, "integration.revoked", provider, {
          localAccessDisabled: true,
        });
        return { kind: "revoked" as const };
      },
    );
    if (!result.authorized) {
      res.status(403).json({ error: "Workspace access denied" });
      return;
    }
    if (result.value.kind === "forbidden") {
      res.status(403).json({ error: "Only workspace owners and admins can manage integrations" });
      return;
    }
    if (result.value.kind === "not-found") {
      res.status(404).json({ error: "Provider connection not found" });
      return;
    }
    res.sendStatus(204);
  },
);

export default router;
