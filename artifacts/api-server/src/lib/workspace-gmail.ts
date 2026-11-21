import { createHash } from "node:crypto";
import { and, eq } from "drizzle-orm";
import {
  workspaceAuditEventsTable,
  workspaceConnectorCredentialsTable,
} from "@workspace/db";
import { canManageIntegrations } from "./access-control";
import {
  GMAIL_CONNECTOR_SERVICE_ID,
  GOOGLE_GMAIL_SCOPES,
  parseGmailCredentialBundle,
  type GmailConnectionStatus,
} from "./gmail-connector";
import {
  disconnectWorkspaceConnectorCredential,
  replaceWorkspaceConnectorCredential,
} from "./workspace-connector-credentials";
import {
  decryptConnectorCredential,
  loadConnectorVaultKeyring,
} from "./workspace-connector-vault";
import {
  withWorkspaceUserTransaction,
  type TenantTransaction,
} from "./tenant-db";

export type SafeWorkspaceGmailConnection = {
  accountEmail: string;
  allowedRecipients: string[];
};

async function readGmailBundle(
  tx: TenantTransaction,
  workspaceId: string,
) {
  const [row] = await tx
    .select()
    .from(workspaceConnectorCredentialsTable)
    .where(
      and(
        eq(workspaceConnectorCredentialsTable.workspaceId, workspaceId),
        eq(workspaceConnectorCredentialsTable.serviceId, GMAIL_CONNECTOR_SERVICE_ID),
      ),
    )
    .limit(1);
  if (!row) return null;
  const clear = decryptConnectorCredential(
    row,
    { workspaceId, serviceId: GMAIL_CONNECTOR_SERVICE_ID },
    loadConnectorVaultKeyring(),
  );
  const bundle = parseGmailCredentialBundle(clear);
  if (!bundle) throw new Error("gmail_credential_bundle_invalid");
  return bundle;
}

export async function getWorkspaceGmailConnection(
  userId: string,
  workspaceId: string,
): Promise<{
  authorized: boolean;
  value: SafeWorkspaceGmailConnection | null;
}> {
  const result = await withWorkspaceUserTransaction(
    userId,
    workspaceId,
    async (tx, membership) => {
      if (!canManageIntegrations(membership.role)) {
        return { kind: "forbidden" as const, connection: null };
      }
      const bundle = await readGmailBundle(tx, workspaceId);
      return {
        kind: "ok" as const,
        connection: bundle
          ? {
              accountEmail: bundle.accountEmail,
              allowedRecipients: bundle.allowedRecipients,
            }
          : null,
      };
    },
  );
  return {
    authorized:
      result.authorized && result.value.kind === "ok",
    value: result.authorized && result.value.kind === "ok"
      ? result.value.connection
      : null,
  };
}

export async function getWorkspaceGmailStatus(
  userId: string,
  workspaceId: string,
  serverConfigured: boolean,
): Promise<{ authorized: boolean; value: GmailConnectionStatus | null }> {
  const connection = await getWorkspaceGmailConnection(userId, workspaceId);
  if (!connection.authorized) return { authorized: false, value: null };
  return {
    authorized: true,
    value: {
      configured: serverConfigured,
      connected: connection.value !== null,
      accountEmail: connection.value?.accountEmail ?? null,
      allowedRecipients: connection.value?.allowedRecipients ?? [],
      scopes: GOOGLE_GMAIL_SCOPES,
    },
  };
}

export async function saveWorkspaceGmailCredential(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    actorUserId: string;
    bundleJson: string;
    membershipRole: string;
  },
): Promise<void> {
  if (!canManageIntegrations(input.membershipRole)) {
    throw new Error("workspace_admin_required");
  }
  await replaceWorkspaceConnectorCredential(tx, {
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    serviceId: GMAIL_CONNECTOR_SERVICE_ID,
    secret: input.bundleJson,
    membershipRole: input.membershipRole,
    safeLastFour: "MAIL",
  });
}

export async function updateWorkspaceGmailAllowlist(
  userId: string,
  workspaceId: string,
  allowedRecipients: string[],
): Promise<boolean> {
  const result = await withWorkspaceUserTransaction(
    userId,
    workspaceId,
    async (tx, membership) => {
      if (!canManageIntegrations(membership.role)) return false;
      const current = await readGmailBundle(tx, workspaceId);
      if (!current) return false;
      const nextBundle = { ...current, allowedRecipients };
      await replaceWorkspaceConnectorCredential(tx, {
        workspaceId,
        actorUserId: userId,
        serviceId: GMAIL_CONNECTOR_SERVICE_ID,
        secret: JSON.stringify(nextBundle),
        membershipRole: membership.role,
        safeLastFour: "MAIL",
      });
      const allowlistHash = createHash("sha256")
        .update([...allowedRecipients].sort().join("\n"), "utf8")
        .digest("hex");
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId,
        actorUserId: userId,
        action: "workspace.connector.gmail.allowlist.updated",
        resourceType: "workspace_connector_credential",
        metadata: {
          serviceId: GMAIL_CONNECTOR_SERVICE_ID,
          entryCount: allowedRecipients.length,
          allowlistSha256: allowlistHash,
        },
      });
      return true;
    },
  );
  return result.authorized && result.value;
}

export async function disconnectWorkspaceGmail(
  userId: string,
  workspaceId: string,
): Promise<{
  authorized: boolean;
  disconnected: boolean;
  refreshToken: string | null;
}> {
  const result = await withWorkspaceUserTransaction(
    userId,
    workspaceId,
    async (tx, membership) => {
      if (!canManageIntegrations(membership.role)) {
        return { kind: "forbidden" as const, disconnected: false, refreshToken: null };
      }
      let refreshToken: string | null = null;
      try {
        refreshToken = (await readGmailBundle(tx, workspaceId))?.refreshToken ?? null;
      } catch {
        // Local disconnect remains available even when the vault key is unavailable.
      }
      const disconnected = await disconnectWorkspaceConnectorCredential(tx, {
        workspaceId,
        actorUserId: userId,
        serviceId: GMAIL_CONNECTOR_SERVICE_ID,
      });
      return {
        kind: "ok" as const,
        disconnected,
        refreshToken,
      };
    },
  );
  if (!result.authorized || result.value.kind !== "ok") {
    return { authorized: false, disconnected: false, refreshToken: null };
  }
  return {
    authorized: true,
    disconnected: result.value.disconnected,
    refreshToken: result.value.refreshToken,
  };
}
