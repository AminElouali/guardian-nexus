import { randomBytes } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { Router, type IRouter } from "express";
import {
  workspaceAuditEventsTable,
  workspaceIntegrationsTable,
} from "@workspace/db";
import {
  GetWorkspaceIntegrationsParams,
  GetWorkspaceIntegrationsResponse,
  PrepareAwsIntegrationBody,
  PrepareAwsIntegrationParams,
  PrepareAwsIntegrationResponse,
  PrepareMicrosoftIntegrationBody,
  PrepareMicrosoftIntegrationParams,
  PrepareMicrosoftIntegrationResponse,
  RevokeWorkspaceIntegrationParams,
  RevokeWorkspaceIntegrationResponse,
} from "@workspace/api-zod";
import { canManageMemberRoles } from "../lib/access-control";
import { withWorkspaceUserTransaction } from "../lib/tenant-db";
import { requireAuth } from "../middlewares/requireAuth";

const router: IRouter = Router();
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MICROSOFT_PERMISSIONS = ["Organization.Read.All"];

function microsoftRegistrationConfigured(): boolean {
  return Boolean(
    process.env.MICROSOFT_ENTRA_CLIENT_ID &&
      process.env.MICROSOFT_ENTRA_CLIENT_SECRET &&
      process.env.MICROSOFT_ENTRA_REDIRECT_URI,
  );
}

function awsRuntimePrincipalConfigured(): boolean {
  const principalArn = process.env.AWS_CONNECTOR_PRINCIPAL_ARN;
  const hasStaticCredentials = Boolean(
    process.env.AWS_ACCESS_KEY_ID ||
      process.env.AWS_SECRET_ACCESS_KEY ||
      process.env.AWS_SESSION_TOKEN,
  );
  return Boolean(
    principalArn &&
      /^arn:aws:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(principalArn) &&
      process.env.AWS_CONNECTOR_IDENTITY_MODE === "workload_identity" &&
      !hasStaticCredentials,
  );
}

function integrationStatus(
  provider: "microsoft" | "aws",
): "awaiting_app_registration" | "ready_for_admin_consent" | "awaiting_runtime_identity" | "ready_for_role_trust" {
  if (provider === "microsoft") {
    return microsoftRegistrationConfigured()
      ? "ready_for_admin_consent"
      : "awaiting_app_registration";
  }
  return awsRuntimePrincipalConfigured()
    ? "ready_for_role_trust"
    : "awaiting_runtime_identity";
}

function publicIntegration(
  integration: typeof workspaceIntegrationsTable.$inferSelect,
  canSeeExternalId: boolean,
) {
  return {
    ...integration,
    externalId: canSeeExternalId ? integration.externalId : null,
  };
}

router.use("/workspaces", requireAuth);

router.get(
  "/workspaces/:workspaceId/integrations",
  async (req, res): Promise<void> => {
    const params = GetWorkspaceIntegrationsParams.safeParse(req.params);
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const { workspaceId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        const connections = await tx
          .select()
          .from(workspaceIntegrationsTable)
          .where(eq(workspaceIntegrationsTable.workspaceId, workspaceId))
          .orderBy(workspaceIntegrationsTable.createdAt);
        return {
          connections: connections.map((connection) =>
            publicIntegration(
              connection,
              canManageMemberRoles(membership.role),
            ),
          ),
          readiness: {
            microsoftAppRegistrationConfigured:
              microsoftRegistrationConfigured(),
            microsoftPermissions: MICROSOFT_PERMISSIONS,
            awsRuntimePrincipalConfigured: awsRuntimePrincipalConfigured(),
            liveConnectionsVerified: false,
          },
        };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    res.json(GetWorkspaceIntegrationsResponse.parse(access.value));
  },
);

export async function prepareIntegration(
  userId: string,
  workspaceId: string,
  provider: "microsoft" | "aws",
  externalAccountId: string,
  requestedPermissions: string[],
  externalId: string | null,
): Promise<
  | { kind: "forbidden" }
  | { kind: "not-found" }
  | { kind: "prepared" | "existing"; integration: typeof workspaceIntegrationsTable.$inferSelect }
> {
  const access = await withWorkspaceUserTransaction(
    userId,
    workspaceId,
    async (tx, membership) => {
      if (!canManageMemberRoles(membership.role)) {
        return { kind: "forbidden" as const };
      }

      const setupKey = externalAccountId;
      const [existing] = await tx
        .select()
        .from(workspaceIntegrationsTable)
        .where(
          and(
            eq(workspaceIntegrationsTable.workspaceId, workspaceId),
            eq(workspaceIntegrationsTable.provider, provider),
            eq(workspaceIntegrationsTable.setupKey, setupKey),
          ),
        )
        .limit(1);

      if (existing && existing.status !== "revoked") {
        return { kind: "existing" as const, integration: existing };
      }

      const status = integrationStatus(provider);
      const values = {
        provider,
        externalAccountId,
        setupKey,
        status,
        externalId,
        requestedPermissions,
        createdByUserId: userId,
        revokedAt: null,
        updatedAt: new Date(),
      };

      let integration: typeof workspaceIntegrationsTable.$inferSelect | undefined;
      if (existing) {
        [integration] = await tx
          .update(workspaceIntegrationsTable)
          .set(values)
          .where(
            and(
              eq(workspaceIntegrationsTable.id, existing.id),
              eq(workspaceIntegrationsTable.status, "revoked"),
            ),
          )
          .returning();
      } else {
        [integration] = await tx
          .insert(workspaceIntegrationsTable)
          .values({ ...values, workspaceId })
          .onConflictDoNothing({
            target: [
              workspaceIntegrationsTable.workspaceId,
              workspaceIntegrationsTable.provider,
              workspaceIntegrationsTable.setupKey,
            ],
          })
          .returning();
      }

      if (!integration) {
        const [raced] = await tx
          .select()
          .from(workspaceIntegrationsTable)
          .where(
            and(
              eq(workspaceIntegrationsTable.workspaceId, workspaceId),
              eq(workspaceIntegrationsTable.provider, provider),
              eq(workspaceIntegrationsTable.setupKey, setupKey),
            ),
          )
          .limit(1);
        return raced
          ? { kind: "existing" as const, integration: raced }
          : { kind: "not-found" as const };
      }

      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId,
        actorUserId: userId,
        action: existing
          ? "integration.setup_reopened"
          : "integration.setup_prepared",
        resourceType: "workspace_integration",
        resourceId: integration.id,
        metadata: {
          provider,
          externalAccountId,
          status,
          source: "local_setup",
        },
      });
      return { kind: "prepared" as const, integration };
    },
  );

  if (!access.authorized) return { kind: "not-found" };
  return access.value;
}

router.post(
  "/workspaces/:workspaceId/integrations/microsoft/setup",
  async (req, res): Promise<void> => {
    const params = PrepareMicrosoftIntegrationParams.safeParse(req.params);
    const body = PrepareMicrosoftIntegrationBody.safeParse(req.body);
    if (
      !params.success ||
      !body.success ||
      !UUID_PATTERN.test(params.data.workspaceId)
    ) {
      res.status(400).json({ error: "Invalid Microsoft integration setup" });
      return;
    }

    const result = await prepareIntegration(
      req.authUserId!,
      params.data.workspaceId,
      "microsoft",
      body.data.tenantId.toLowerCase(),
      MICROSOFT_PERMISSIONS,
      null,
    );
    if (result.kind === "forbidden") {
      res.status(403).json({ error: "Workspace owner role required" });
      return;
    }
    if (result.kind === "not-found") {
      res.status(404).json({ error: "Workspace setup not found" });
      return;
    }
    const response = PrepareMicrosoftIntegrationResponse.parse(
      publicIntegration(result.integration, true),
    );
    res.status(result.kind === "prepared" ? 201 : 200).json(response);
  },
);

router.post(
  "/workspaces/:workspaceId/integrations/aws/setup",
  async (req, res): Promise<void> => {
    const params = PrepareAwsIntegrationParams.safeParse(req.params);
    const body = PrepareAwsIntegrationBody.safeParse(req.body);
    if (
      !params.success ||
      !body.success ||
      !UUID_PATTERN.test(params.data.workspaceId)
    ) {
      res.status(400).json({ error: "Invalid AWS integration setup" });
      return;
    }

    const result = await prepareIntegration(
      req.authUserId!,
      params.data.workspaceId,
      "aws",
      body.data.accountId,
      [],
      randomBytes(32).toString("base64url"),
    );
    if (result.kind === "forbidden") {
      res.status(403).json({ error: "Workspace owner role required" });
      return;
    }
    if (result.kind === "not-found") {
      res.status(404).json({ error: "Workspace setup not found" });
      return;
    }
    const response = PrepareAwsIntegrationResponse.parse(
      publicIntegration(result.integration, true),
    );
    res.status(result.kind === "prepared" ? 201 : 200).json(response);
  },
);

router.post(
  "/workspaces/:workspaceId/integrations/:integrationId/revoke",
  async (req, res): Promise<void> => {
    const params = RevokeWorkspaceIntegrationParams.safeParse(req.params);
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !UUID_PATTERN.test(params.data.integrationId)
    ) {
      res.status(400).json({ error: "Invalid integration ID" });
      return;
    }
    const { workspaceId, integrationId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canManageMemberRoles(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const [integration] = await tx
          .update(workspaceIntegrationsTable)
          .set({
            status: "revoked",
            externalId: null,
            revokedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(workspaceIntegrationsTable.id, integrationId),
              eq(workspaceIntegrationsTable.workspaceId, workspaceId),
            ),
          )
          .returning();
        if (!integration) return { kind: "not-found" as const };
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId,
          actorUserId: req.authUserId!,
          action: "integration.local_setup_revoked",
          resourceType: "workspace_integration",
          resourceId: integration.id,
          metadata: {
            provider: integration.provider,
            externalAccountId: integration.externalAccountId,
            source: "local_only",
          },
        });
        return { kind: "revoked" as const, integration };
      },
    );
    if (!access.authorized || access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace owner role required" });
      return;
    }
    if (access.value.kind === "not-found") {
      res.status(404).json({ error: "Integration setup not found" });
      return;
    }
    res.json(
      RevokeWorkspaceIntegrationResponse.parse(
        publicIntegration(access.value.integration, true),
      ),
    );
  },
);

export default router;
