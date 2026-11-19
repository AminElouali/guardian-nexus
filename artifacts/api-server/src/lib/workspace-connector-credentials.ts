import { and, eq, sql } from "drizzle-orm";
import {
  workspaceAuditEventsTable,
  workspaceConnectorCredentialsTable,
} from "@workspace/db";
import type { TenantTransaction } from "./tenant-db";
import {
  ConnectorVaultError,
  encryptConnectorCredential,
  loadConnectorVaultKeyring,
} from "./workspace-connector-vault";

export type SafeConnectorCredentialStatus = {
  id: string;
  serviceId: string;
  configured: true;
  lastFour: string;
  encryptionKeyId: string;
  createdAt: Date;
};

export type ReplaceWorkspaceConnectorCredentialStage =
  | "validate"
  | "keyring"
  | "lock"
  | "replace_existing"
  | "encrypt"
  | "insert"
  | "insert_result"
  | "audit";

export type ConnectorCredentialInsertResultMetadata = {
  id: "string" | "other";
  serviceId: "string" | "other";
  lastFour: "string" | "other";
  encryptionKeyId: "string" | "other";
  createdAt: "date" | "string" | "other";
};

class ConnectorCredentialInsertResultError extends Error {
  readonly code = "credential_insert_result_invalid";

  constructor() {
    super("connector_credential_insert_result_invalid");
    this.name = "ConnectorCredentialInsertResultError";
  }
}

function parseReturnedCreatedAt(value: unknown): Date | null {
  if (value instanceof Date) {
    return Number.isFinite(value.getTime()) ? value : null;
  }
  if (
    typeof value !== "string" ||
    !/(?:Z|[+-]\d{2}(?::?\d{2})?)$/i.test(value)
  ) {
    return null;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp) : null;
}

export type ConnectorCredentialInsertContext = {
  workspaceSetting: string | null;
  userSetting: string | null;
  databaseRole: string | null;
  membershipRole: string;
  credentialExisted: boolean;
};

const SERVICE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export async function listWorkspaceConnectorCredentialStatuses(
  tx: TenantTransaction,
  workspaceId: string,
): Promise<SafeConnectorCredentialStatus[]> {
  const rows = await tx
    .select({
      id: workspaceConnectorCredentialsTable.id,
      serviceId: workspaceConnectorCredentialsTable.serviceId,
      lastFour: workspaceConnectorCredentialsTable.lastFour,
      encryptionKeyId: workspaceConnectorCredentialsTable.encryptionKeyId,
      createdAt: workspaceConnectorCredentialsTable.createdAt,
    })
    .from(workspaceConnectorCredentialsTable)
    .where(eq(workspaceConnectorCredentialsTable.workspaceId, workspaceId))
    .orderBy(workspaceConnectorCredentialsTable.serviceId);
  return rows.map((row) => ({ ...row, configured: true }));
}

export async function replaceWorkspaceConnectorCredential(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    actorUserId: string;
    serviceId: string;
    secret: string;
    membershipRole: string;
    onStage?: (stage: ReplaceWorkspaceConnectorCredentialStage) => void;
    onInsertContext?: (context: ConnectorCredentialInsertContext) => void;
    onInsertResultMetadata?: (
      metadata: ConnectorCredentialInsertResultMetadata,
    ) => void;
  },
): Promise<
  | { kind: "created"; credential: SafeConnectorCredentialStatus }
  | { kind: "replaced"; credential: SafeConnectorCredentialStatus }
> {
  input.onStage?.("validate");
  if (!SERVICE_ID_PATTERN.test(input.serviceId)) {
    throw new ConnectorVaultError("credential_input_invalid");
  }
  input.onStage?.("keyring");
  const keyring = loadConnectorVaultKeyring();
  input.onStage?.("lock");
  await tx.execute(
    sql`SELECT pg_advisory_xact_lock(hashtext(${input.workspaceId}), hashtext(${input.serviceId}))`,
  );
  input.onStage?.("replace_existing");
  const [existing] = await tx
    .delete(workspaceConnectorCredentialsTable)
    .where(
      and(
        eq(workspaceConnectorCredentialsTable.workspaceId, input.workspaceId),
        eq(workspaceConnectorCredentialsTable.serviceId, input.serviceId),
      ),
    )
    .returning({ id: workspaceConnectorCredentialsTable.id });

  for (let attempt = 0; attempt < 3; attempt += 1) {
    input.onStage?.("encrypt");
    const encrypted = encryptConnectorCredential(
      input.secret,
      { workspaceId: input.workspaceId, serviceId: input.serviceId },
      keyring,
    );
    if (input.onInsertContext) {
      const contextResult = await tx.execute(sql`
        SELECT current_setting('app.workspace_id', true) AS workspace_setting,
               current_setting('app.user_id', true) AS user_setting,
               current_user AS database_role
      `);
      const context = contextResult.rows[0] as
        | {
            workspace_setting: string | null;
            user_setting: string | null;
            database_role: string | null;
          }
        | undefined;
      input.onInsertContext({
        workspaceSetting: context?.workspace_setting ?? null,
        userSetting: context?.user_setting ?? null,
        databaseRole: context?.database_role ?? null,
        membershipRole: input.membershipRole,
        credentialExisted: Boolean(existing),
      });
    }
    input.onStage?.("insert");
    const inserted = await tx.execute(sql`
      INSERT INTO public.workspace_connector_credentials (
        workspace_id, service_id, encrypted_secret, nonce, auth_tag,
        encryption_key_id, last_four, created_by_user_id
      ) VALUES (
        ${input.workspaceId}, ${input.serviceId}, ${encrypted.encryptedSecret},
        ${encrypted.nonce}, ${encrypted.authTag}, ${encrypted.encryptionKeyId},
        ${encrypted.lastFour}, ${input.actorUserId}
      )
      ON CONFLICT (nonce) DO NOTHING
      RETURNING id, service_id, last_four, encryption_key_id, created_at
    `);
    const row = inserted.rows[0];
    if (row) {
      input.onStage?.("insert_result");
      const id = row.id;
      const serviceId = row.service_id;
      const lastFour = row.last_four;
      const encryptionKeyId = row.encryption_key_id;
      const createdAtValue = row.created_at;
      const createdAt = parseReturnedCreatedAt(createdAtValue);
      input.onInsertResultMetadata?.({
        id: typeof id === "string" ? "string" : "other",
        serviceId: typeof serviceId === "string" ? "string" : "other",
        lastFour: typeof lastFour === "string" ? "string" : "other",
        encryptionKeyId:
          typeof encryptionKeyId === "string" ? "string" : "other",
        createdAt: createdAt
          ? "date"
          : typeof createdAtValue === "string"
          ? "string"
          : "other",
      });
      if (
        typeof id !== "string" ||
        typeof serviceId !== "string" ||
        typeof lastFour !== "string" ||
        typeof encryptionKeyId !== "string" ||
        createdAt === null
      ) {
        throw new ConnectorCredentialInsertResultError();
      }
      input.onStage?.("audit");
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId: input.workspaceId,
        actorUserId: input.actorUserId,
        action: existing
          ? "workspace.connector.credential.replaced"
          : "workspace.connector.credential.created",
        resourceType: "workspace_connector_credential",
        resourceId: id,
        metadata: { serviceId: input.serviceId },
      });
      return {
        kind: existing ? "replaced" : "created",
        credential: {
          id,
          serviceId,
          lastFour,
          encryptionKeyId,
          createdAt,
          configured: true,
        },
      };
    }
  }
  throw new ConnectorVaultError("credential_ciphertext_invalid");
}

export async function disconnectWorkspaceConnectorCredential(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    actorUserId: string;
    serviceId: string;
  },
): Promise<boolean> {
  if (!SERVICE_ID_PATTERN.test(input.serviceId)) return false;
  await tx.execute(
    sql`SELECT pg_advisory_xact_lock(hashtext(${input.workspaceId}), hashtext(${input.serviceId}))`,
  );
  const [deleted] = await tx
    .delete(workspaceConnectorCredentialsTable)
    .where(
      and(
        eq(workspaceConnectorCredentialsTable.workspaceId, input.workspaceId),
        eq(workspaceConnectorCredentialsTable.serviceId, input.serviceId),
      ),
    )
    .returning({ id: workspaceConnectorCredentialsTable.id });
  if (!deleted) return false;
  await tx.insert(workspaceAuditEventsTable).values({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "workspace.connector.credential.disconnected",
    resourceType: "workspace_connector_credential",
    resourceId: deleted.id,
    metadata: { serviceId: input.serviceId },
  });
  return true;
}
