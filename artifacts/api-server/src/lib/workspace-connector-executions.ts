import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { and, eq, sql } from "drizzle-orm";
import {
  aiAssessmentApprovalRequestsTable,
  workspaceAuditEventsTable,
  workspaceConnectorCredentialsTable,
  workspaceConnectorExecutionsTable,
  type Membership,
} from "@workspace/db";
import {
  evaluateApprovalAction,
  getApprovalActionDefinition,
  type ApprovalActionValue,
} from "@workspace/db/approval-action-catalog";
import {
  consumeApprovalReceipt,
} from "./approval-ledger-service";
import {
  type SignedApprovalReceiptV1,
} from "./approval-ledger-crypto";
import { ApprovalLedgerError } from "./approval-ledger-keys";
import { hashGenericActionArguments } from "./generic-action-evidence";
import {
  ConnectorVaultError,
  decryptConnectorCredential,
  loadConnectorVaultKeyring,
} from "./workspace-connector-vault";
import {
  withWorkspaceUserTransaction,
  type TenantTransaction,
} from "./tenant-db";

export type ConnectorExecutionAdapterResult = {
  resultCode: string;
  summary: string;
  responseText?: string;
};

export type ConnectorExecutionAdapter = {
  serviceId: string;
  execute(input: {
    workspaceId: string;
    actionType: string;
    arguments: Record<string, ApprovalActionValue>;
    credential: string;
  }): Promise<ConnectorExecutionAdapterResult>;
};

export type ConnectorExecutionRequest = {
  workspaceId: string;
  userId: string;
  serviceId: string;
  idempotencyKey: string;
  actionType: string;
  arguments: Record<string, ApprovalActionValue>;
  receipt: unknown;
  adapters: ReadonlyMap<string, ConnectorExecutionAdapter>;
  onStage?: (stage: ConnectorExecutionStage) => void;
};

export type ConnectorExecutionResult = {
  executionId: string;
  status: "pending" | "executed" | "failed";
  replayed: boolean;
  responseSummary: string | null;
  failureCode: string | null;
  responseText?: string | null;
};

export type ConnectorExecutionStage =
  | "validate"
  | "claim_transaction"
  | "claim_lock"
  | "claim_lookup"
  | "credential_lookup"
  | "approval_lookup"
  | "consume_receipt"
  | "insert_pending"
  | "audit_pending"
  | "replay_return"
  | "audit_replay"
  | "complete_transaction"
  | "complete_lock"
  | "execution_lookup"
  | "credential_lock"
  | "adapter"
  | "update_result"
  | "audit_result";

export type ConnectorExecutionFailureCode =
  | "workspace_membership_required"
  | "workspace_admin_required"
  | "connector_unavailable"
  | "unclassified_action"
  | "action_arguments_invalid"
  | "action_not_approval_gated"
  | "idempotency_key_invalid"
  | "idempotency_key_conflict"
  | "receipt_invalid"
  | "receipt_action_mismatch"
  | "receipt_not_approved"
  | "credential_not_configured"
  | "vault_keyring_unavailable"
  | "credential_unavailable"
  | "receipt_expired"
  | "receipt_already_consumed"
  | "execution_unavailable";

export class ConnectorExecutionError extends Error {
  constructor(readonly code: ConnectorExecutionFailureCode) {
    super(`connector_execution_${code}`);
    this.name = "ConnectorExecutionError";
  }
}

type ReceiptClaims = {
  receipt: SignedApprovalReceiptV1;
  payload: {
    version: 1;
    workspaceId: string;
    approvalId: string;
    receiptId: string;
    actionSha256: string;
  };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function parseReceiptClaims(value: unknown): ReceiptClaims | null {
  if (!isRecord(value)) return null;
  if (
    Object.keys(value).sort().join(",") !==
    "payload,payloadSha256,signature"
  ) {
    return null;
  }
  const receipt = value;
  const payload = receipt.payload;
  if (!isRecord(payload)) return null;
  const claims = payload;
  const payloadKeys = [
    "actionSha256",
    "approvalId",
    "approvedBy",
    "approvedByRole",
    "expiresAt",
    "issuedAt",
    "keyId",
    "nonce",
    "proposalBindingSha256",
    "receiptId",
    "requestedBy",
    "version",
    "workspaceId",
  ];
  if (
    Object.keys(claims).sort().join(",") !== payloadKeys.sort().join(",") ||
    claims.version !== 1 ||
    typeof claims.keyId !== "string" ||
    typeof claims.receiptId !== "string" ||
    !/^[0-9a-f-]{36}$/i.test(claims.receiptId) ||
    typeof claims.workspaceId !== "string" ||
    !/^[0-9a-f-]{36}$/i.test(claims.workspaceId) ||
    typeof claims.approvalId !== "string" ||
    !/^[0-9a-f-]{36}$/i.test(claims.approvalId) ||
    typeof claims.proposalBindingSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(claims.proposalBindingSha256) ||
    typeof claims.actionSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(claims.actionSha256) ||
    typeof claims.requestedBy !== "string" ||
    typeof claims.approvedBy !== "string" ||
    (claims.approvedByRole !== "owner" && claims.approvedByRole !== "admin") ||
    typeof claims.issuedAt !== "string" ||
    typeof claims.expiresAt !== "string" ||
    typeof claims.nonce !== "string" ||
    !/^[A-Za-z0-9_-]{32,128}$/.test(claims.nonce) ||
    typeof receipt.payloadSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(receipt.payloadSha256) ||
    typeof receipt.signature !== "string" ||
    !/^[A-Za-z0-9_-]{86}$/.test(receipt.signature)
  ) {
    return null;
  }
  return {
    receipt: value as SignedApprovalReceiptV1,
    payload: {
      version: 1,
      workspaceId: claims.workspaceId,
      approvalId: claims.approvalId,
      receiptId: claims.receiptId,
      actionSha256: claims.actionSha256,
    },
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isAdministrator(membership: Membership): boolean {
  return membership.role === "owner" || membership.role === "admin";
}

function replayResult(
  row: typeof workspaceConnectorExecutionsTable.$inferSelect,
  actionType: string,
  actionSha256: string,
  receiptId: string,
): ConnectorExecutionResult {
  if (
    row.actionType !== actionType ||
    row.actionSha256 !== actionSha256 ||
    row.receiptId !== receiptId
  ) {
    throw new ConnectorExecutionError("idempotency_key_conflict");
  }
  return {
    executionId: row.id,
    status: row.status as ConnectorExecutionResult["status"],
    replayed: true,
    responseSummary: row.responseSummary,
    failureCode: row.failureCode,
    responseText: null,
  };
}

function boundedResponseText(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const limit = 4_096;
  let output = "";
  let bytes = 0;
  for (const character of value) {
    const characterBytes = Buffer.byteLength(character, "utf8");
    if (bytes + characterBytes > limit) break;
    output += character;
    bytes += characterBytes;
  }
  return output;
}

function sanitizeAdapterSummary(
  result: ConnectorExecutionAdapterResult,
): { resultCode: string; summary: string; responseText: string | null } {
  const resultCode =
    result.resultCode === "captured_locally" ||
    result.resultCode === "completed" ||
    result.resultCode === "rejected"
      ? result.resultCode
      : "completed";
  const summary =
    resultCode === "captured_locally"
      ? "Acción capturada por el conector de prueba; no se contactó ningún servicio."
      : resultCode === "rejected"
        ? "El conector rechazó la acción."
        : "El conector confirmó la acción.";
  return {
    resultCode,
    summary,
    responseText: boundedResponseText(result.responseText),
  };
}

function auditExecution(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    actorUserId: string;
    executionId: string;
    serviceId: string;
    actionType: string;
    actionSha256: string;
    status: "pending" | "executed" | "failed";
    resultCode?: string;
  },
) {
  return tx.insert(workspaceAuditEventsTable).values({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: `workspace.connector.execution.${input.status}`,
    resourceType: "workspace_connector_execution",
    resourceId: input.executionId,
    metadata: {
      serviceId: input.serviceId,
      actionType: input.actionType,
      actionSha256: input.actionSha256,
      ...(input.resultCode ? { resultCode: input.resultCode } : {}),
    },
  });
}

function auditExecutionReplay(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    actorUserId: string;
    executionId: string;
    serviceId: string;
    actionType: string;
    actionSha256: string;
  },
) {
  return tx.insert(workspaceAuditEventsTable).values({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "workspace.connector.execution.replayed",
    resourceType: "workspace_connector_execution",
    resourceId: input.executionId,
    metadata: {
      serviceId: input.serviceId,
      actionType: input.actionType,
      actionSha256: input.actionSha256,
      resultCode: "idempotent_replay",
    },
  });
}

export async function executeWorkspaceConnectorAction(
  input: ConnectorExecutionRequest,
): Promise<ConnectorExecutionResult> {
  input.onStage?.("validate");
  const adapter = input.adapters.get(input.serviceId);
  if (!adapter || adapter.serviceId !== input.serviceId) {
    throw new ConnectorExecutionError("connector_unavailable");
  }
  if (
    typeof input.idempotencyKey !== "string" ||
    input.idempotencyKey.length < 16 ||
    input.idempotencyKey.length > 128
  ) {
    throw new ConnectorExecutionError("idempotency_key_invalid");
  }

  const definition = getApprovalActionDefinition(input.actionType);
  if (!definition || definition.riskTypes.length === 0) {
    throw new ConnectorExecutionError("unclassified_action");
  }
  const evaluated = evaluateApprovalAction(input.actionType, input.arguments);
  if (!evaluated.ok) {
    throw new ConnectorExecutionError("action_arguments_invalid");
  }
  if (evaluated.decision !== "require_approval") {
    throw new ConnectorExecutionError("action_not_approval_gated");
  }
  const actionHash = hashGenericActionArguments(
    input.actionType,
    evaluated.args,
  ).actionSha256;
  const receiptClaims = parseReceiptClaims(input.receipt);
  if (!receiptClaims) {
    throw new ConnectorExecutionError("receipt_invalid");
  }
  if (
    receiptClaims.payload.workspaceId !== input.workspaceId ||
    receiptClaims.payload.actionSha256 !== actionHash
  ) {
    throw new ConnectorExecutionError("receipt_action_mismatch");
  }

  const keyHash = sha256(input.idempotencyKey);
  input.onStage?.("claim_transaction");
  const claim = await withWorkspaceUserTransaction(
    input.userId,
    input.workspaceId,
    async (tx, membership) => {
      if (!isAdministrator(membership)) {
        throw new ConnectorExecutionError("workspace_admin_required");
      }
      input.onStage?.("claim_lock");
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(hashtext(${input.workspaceId}), hashtext(${`${input.serviceId}:${keyHash}`}))`,
      );
      input.onStage?.("claim_lookup");
      const [existing] = await tx
        .select()
        .from(workspaceConnectorExecutionsTable)
        .where(
          and(
            eq(workspaceConnectorExecutionsTable.workspaceId, input.workspaceId),
            eq(workspaceConnectorExecutionsTable.serviceId, input.serviceId),
            eq(
              workspaceConnectorExecutionsTable.idempotencyKeySha256,
              keyHash,
            ),
          ),
        )
        .limit(1);
      if (existing) {
        input.onStage?.("replay_return");
        return {
          kind: "replay" as const,
          result: replayResult(
            existing,
            input.actionType,
            actionHash,
            receiptClaims.payload.receiptId,
          ),
        };
      }

      input.onStage?.("credential_lookup");
      const [credential] = await tx
        .select({
          id: workspaceConnectorCredentialsTable.id,
        })
        .from(workspaceConnectorCredentialsTable)
        .where(
          and(
            eq(workspaceConnectorCredentialsTable.workspaceId, input.workspaceId),
            eq(workspaceConnectorCredentialsTable.serviceId, input.serviceId),
          ),
        )
        .limit(1);
      if (!credential) {
        throw new ConnectorExecutionError("credential_not_configured");
      }

      input.onStage?.("approval_lookup");
      const [approval] = await tx
        .select()
        .from(aiAssessmentApprovalRequestsTable)
        .where(
          and(
            eq(aiAssessmentApprovalRequestsTable.id, receiptClaims.payload.approvalId),
            eq(aiAssessmentApprovalRequestsTable.workspaceId, input.workspaceId),
          ),
        )
        .limit(1);
      if (
        !approval ||
        approval.status !== "approved" ||
        approval.syntheticActionRef !== input.actionType ||
        approval.actionSha256 !== actionHash ||
        !approval.proposalBindingSha256 ||
        !approval.decidedByUserId ||
        (approval.decidedByRole !== "owner" &&
          approval.decidedByRole !== "admin")
      ) {
        throw new ConnectorExecutionError("receipt_not_approved");
      }
      input.onStage?.("consume_receipt");
      await consumeApprovalReceipt(tx, {
        workspaceId: input.workspaceId,
        approvalId: approval.id,
        receipt: receiptClaims.receipt,
        expected: {
          workspaceId: input.workspaceId,
          approvalId: approval.id,
          proposalBindingSha256: approval.proposalBindingSha256,
          actionSha256: actionHash,
          requestedBy: approval.requestedByUserId,
          approvedBy: approval.decidedByUserId,
          approvedByRole: approval.decidedByRole,
        },
      });
      input.onStage?.("insert_pending");
      const executionInsert = await tx.execute(sql`
        INSERT INTO public.workspace_connector_executions (
          workspace_id, service_id, credential_id, idempotency_key_sha256,
          action_type, action_sha256, receipt_id, requested_by_user_id
        ) VALUES (
          ${input.workspaceId}, ${input.serviceId}, ${credential.id},
          ${keyHash}, ${input.actionType}, ${actionHash},
          ${receiptClaims.payload.receiptId}, ${input.userId}
        )
        RETURNING id
      `);
      const executionId = executionInsert.rows[0]?.id;
      if (typeof executionId !== "string") {
        throw new ConnectorExecutionError("execution_unavailable");
      }
      input.onStage?.("audit_pending");
      await auditExecution(tx, {
        workspaceId: input.workspaceId,
        actorUserId: input.userId,
        executionId,
        serviceId: input.serviceId,
        actionType: input.actionType,
        actionSha256: actionHash,
        status: "pending",
      });
      return {
        kind: "claimed" as const,
        executionId,
        credentialId: credential.id,
      };
    },
  );
  if (!claim.authorized) {
    throw new ConnectorExecutionError("workspace_membership_required");
  }
  if (
    claim.value.kind === "replay" &&
    "result" in claim.value &&
    claim.value.result
  ) {
    const replayedExecution = claim.value.result;
    input.onStage?.("audit_replay");
    const replayAudit = await withWorkspaceUserTransaction(
      input.userId,
      input.workspaceId,
      async (tx, membership) => {
        if (!isAdministrator(membership)) {
          throw new ConnectorExecutionError("workspace_admin_required");
        }
        await auditExecutionReplay(tx, {
          workspaceId: input.workspaceId,
          actorUserId: input.userId,
          executionId: replayedExecution.executionId,
          serviceId: input.serviceId,
          actionType: input.actionType,
          actionSha256: actionHash,
        });
      },
    );
    if (!replayAudit.authorized) {
      throw new ConnectorExecutionError("workspace_membership_required");
    }
    return replayedExecution;
  }
  if (claim.value.kind !== "claimed") {
    throw new ConnectorExecutionError("execution_unavailable");
  }
  const claimedExecutionId = claim.value.executionId;
  const claimedCredentialId = claim.value.credentialId;

  input.onStage?.("complete_transaction");
  const completed = await withWorkspaceUserTransaction(
    input.userId,
    input.workspaceId,
    async (tx, membership) => {
      if (!isAdministrator(membership)) {
        throw new ConnectorExecutionError("workspace_admin_required");
      }
      input.onStage?.("complete_lock");
      await tx.execute(
        sql`SELECT set_config('app.connector_execution_writer', '1', true)`,
      );
      input.onStage?.("execution_lookup");
      const [execution] = await tx
        .select()
        .from(workspaceConnectorExecutionsTable)
        .where(
          and(
            eq(workspaceConnectorExecutionsTable.id, claimedExecutionId),
            eq(workspaceConnectorExecutionsTable.workspaceId, input.workspaceId),
          ),
        )
        .for("update")
        .limit(1);
      if (!execution || execution.status !== "pending") {
        throw new ConnectorExecutionError("execution_unavailable");
      }
      input.onStage?.("credential_lock");
      // Coordinate with replacement/disconnect without granting UPDATE on credentials.
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(hashtext(${input.workspaceId}), hashtext(${input.serviceId}))`,
      );
      const [credential] = await tx
        .select()
        .from(workspaceConnectorCredentialsTable)
        .where(
          and(
            eq(workspaceConnectorCredentialsTable.id, claimedCredentialId),
            eq(workspaceConnectorCredentialsTable.workspaceId, input.workspaceId),
            eq(workspaceConnectorCredentialsTable.serviceId, input.serviceId),
          ),
        )
        .limit(1);
      let status: "executed" | "failed" = "failed";
      let responseSummary: string | null = null;
      let failureCode: string | null = "credential_unavailable";
      let resultCode = "credential_unavailable";
      let responseText: string | null = null;
      if (credential) {
        try {
          const keyring = loadConnectorVaultKeyring();
          const clearCredential = decryptConnectorCredential(
            credential,
            { workspaceId: input.workspaceId, serviceId: input.serviceId },
            keyring,
          );
          try {
            input.onStage?.("adapter");
            const adapterResult = await adapter.execute({
              workspaceId: input.workspaceId,
              actionType: input.actionType,
              arguments: evaluated.args,
              credential: clearCredential,
            });
            const safeResult = sanitizeAdapterSummary(adapterResult);
            status = "executed";
            responseSummary = safeResult.summary;
            responseText = safeResult.responseText;
            failureCode = null;
            resultCode = safeResult.resultCode;
          } catch {
            status = "failed";
            responseSummary = null;
            responseText = null;
            failureCode = "connector_failed";
            resultCode = "connector_failed";
          }
        } catch (error) {
          status = "failed";
          responseSummary = null;
          failureCode =
            error instanceof ConnectorVaultError &&
            error.code === "vault_keyring_unavailable"
              ? "vault_key_unavailable"
              : "credential_unavailable";
          resultCode = failureCode;
        }
      }
      const completedAt = new Date();
      input.onStage?.("update_result");
      const [updated] = await tx
        .update(workspaceConnectorExecutionsTable)
        .set({
          status,
          responseSummary,
          failureCode,
          updatedAt: completedAt,
          completedAt,
        })
        .where(
          and(
            eq(workspaceConnectorExecutionsTable.id, execution.id),
            eq(workspaceConnectorExecutionsTable.status, "pending"),
          ),
        )
        .returning({
          id: workspaceConnectorExecutionsTable.id,
          status: workspaceConnectorExecutionsTable.status,
          responseSummary: workspaceConnectorExecutionsTable.responseSummary,
          failureCode: workspaceConnectorExecutionsTable.failureCode,
        });
      if (!updated) {
        throw new ConnectorExecutionError("execution_unavailable");
      }
      input.onStage?.("audit_result");
      await auditExecution(tx, {
        workspaceId: input.workspaceId,
        actorUserId: input.userId,
        executionId: execution.id,
        serviceId: input.serviceId,
        actionType: input.actionType,
        actionSha256: actionHash,
        status,
        resultCode,
      });
      return {
        executionId: updated.id,
        status: updated.status as ConnectorExecutionResult["status"],
        replayed: false,
        responseSummary: updated.responseSummary,
        failureCode: updated.failureCode,
        responseText,
      };
    },
  );
  if (!completed.authorized) {
    throw new ConnectorExecutionError("workspace_membership_required");
  }
  return completed.value;
}

export function mapConnectorExecutionError(
  error: unknown,
): ConnectorExecutionFailureCode {
  if (error instanceof ConnectorExecutionError) return error.code;
  if (error instanceof ConnectorVaultError) {
    return error.code === "vault_keyring_unavailable"
      ? "vault_keyring_unavailable"
      : "credential_unavailable";
  }
  if (error instanceof ApprovalLedgerError) {
    if (error.code === "receipt_expired") return "receipt_expired";
    if (error.code === "receipt_already_consumed") {
      return "receipt_already_consumed";
    }
    return "receipt_invalid";
  }
  return "execution_unavailable";
}
