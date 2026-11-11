import { and, eq, isNull } from "drizzle-orm";
import {
  hostAttestationChallengesTable,
  type HostAttestationChallengeRow,
} from "@workspace/db";
import type { TenantTransaction } from "./tenant-db";
import type {
  HostAttestationChallenge,
  HostAttestationNonceRepository,
} from "./host-attestation-protocol";

function toChallenge(row: HostAttestationChallengeRow): HostAttestationChallenge {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    nonceSha256: row.nonceSha256,
    runtimeCommit: row.runtimeCommit,
    runtimeDigestSha256: row.runtimeDigestSha256,
    issuedByUserId: row.issuedByUserId,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
  };
}

/**
 * Bind the nonce protocol to the caller's already-authorized RLS transaction.
 * The row lock remains held until the caller commits the final status; two
 * concurrent submissions therefore cannot both finish the same challenge.
 */
export function createHostAttestationNonceRepository(
  tx: TenantTransaction,
): HostAttestationNonceRepository {
  return {
    async insert(challenge) {
      await tx.insert(hostAttestationChallengesTable).values({
        id: challenge.id,
        workspaceId: challenge.workspaceId,
        nonceSha256: challenge.nonceSha256,
        runtimeCommit: challenge.runtimeCommit,
        runtimeDigestSha256: challenge.runtimeDigestSha256,
        issuedByUserId: challenge.issuedByUserId,
        issuedAt: challenge.issuedAt,
        expiresAt: challenge.expiresAt,
      });
    },

    async consume({ challengeId, workspaceId, now }) {
      const [row] = await tx
        .select()
        .from(hostAttestationChallengesTable)
        .where(
          and(
            eq(hostAttestationChallengesTable.id, challengeId),
            eq(hostAttestationChallengesTable.workspaceId, workspaceId),
          ),
        )
        .for("update")
        .limit(1);
      if (!row) return { kind: "missing" };
      if (row.status !== "issued" || row.consumedAt) {
        return { kind: "replay" };
      }
      if (row.expiresAt.getTime() <= now.getTime()) {
        await tx
          .update(hostAttestationChallengesTable)
          .set({ status: "expired", consumedAt: now, updatedAt: now })
          .where(
            and(
              eq(hostAttestationChallengesTable.id, challengeId),
              eq(hostAttestationChallengesTable.workspaceId, workspaceId),
              eq(hostAttestationChallengesTable.status, "issued"),
              isNull(hostAttestationChallengesTable.consumedAt),
            ),
          );
        return { kind: "expired" };
      }
      // The enclosing transaction retains this row lock through finish().
      return { kind: "consumed", challenge: toChallenge(row) };
    },

    async finish(input) {
      const [updated] = await tx
        .update(hostAttestationChallengesTable)
        .set({
          status: input.status,
          consumedAt: input.finishedAt,
          responseSha256: input.responseSha256,
          supervisorId: input.supervisorId,
          updatedAt: input.finishedAt,
        })
        .where(
          and(
            eq(hostAttestationChallengesTable.id, input.challengeId),
            eq(hostAttestationChallengesTable.workspaceId, input.workspaceId),
            eq(hostAttestationChallengesTable.status, "issued"),
            isNull(hostAttestationChallengesTable.consumedAt),
          ),
        )
        .returning({ id: hostAttestationChallengesTable.id });
      if (!updated) {
        throw new Error("assessment_host_challenge_replay_rejected");
      }
    },
  };
}
