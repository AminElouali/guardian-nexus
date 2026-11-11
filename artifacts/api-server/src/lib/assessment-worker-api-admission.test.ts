import assert from "node:assert/strict";
import { test } from "node:test";
import type { Membership } from "@workspace/db";
import type { Response } from "express";
import { QWEN_POLICY_LAB_PROFILE_IDS } from "./ai-assessment-sandbox";
import type { TenantTransaction } from "./tenant-db";
import {
  createLabJobPostHandler,
  requestLabJob,
  type LabJobRequestDependencies,
} from "../routes/ai-assessment-lab";
import { withWorkspaceUserTransaction } from "./tenant-db";

const protectedProfiles = [
  {
    label: "email",
    profileId: "guardian-agent-qwen-lab-email-v1",
  },
  {
    label: "database",
    profileId: "guardian-agent-qwen-lab-database-v1",
  },
] as const;

test("closed broker admission rejects email and database before job side effects", async () => {
  assert.deepEqual(
    QWEN_POLICY_LAB_PROFILE_IDS.slice(0, 2),
    protectedProfiles.map(({ profileId }) => profileId),
    "the regression must cover the first two Qwen profiles",
  );

  for (const { label, profileId } of protectedProfiles) {
    const effects = {
      idempotencyOrPendingReads: 0,
      inserts: 0,
      quotaReservations: 0,
      enqueues: 0,
    };

    const tx = {
      select() {
        effects.idempotencyOrPendingReads += 1;
        throw new Error("database lookup must not run while worker is disabled");
      },
      insert() {
        effects.inserts += 1;
        throw new Error("database insert must not run while worker is disabled");
      },
    } as unknown as TenantTransaction;
    const membership = { role: "owner" } as Membership;

    const withWorkspaceUserTransactionMock = (async (
      _userId: string,
      _workspaceId: string,
      operation: (
        transaction: TenantTransaction,
        actorMembership: Membership,
      ) => Promise<unknown>,
    ) => ({
      authorized: true as const,
      membership,
      value: await operation(tx, membership),
    })) as unknown as typeof withWorkspaceUserTransaction;

    const dependencies: Partial<LabJobRequestDependencies> = {
      withWorkspaceUserTransaction: withWorkspaceUserTransactionMock,
      reserveWorkspaceUsageInTransaction: async () => {
        effects.quotaReservations += 1;
        return {
          id: "synthetic-usage",
          workspaceId: "synthetic-workspace",
          monthStart: "2026-11-01",
          scansUsed: 0,
          tokensUsed: 0,
          apiRequestsUsed: 0,
          updatedAt: new Date(0),
        };
      },
      enqueueLocalAssessmentJob: () => {
        effects.enqueues += 1;
        return false;
      },
    };

    let responseStatus = 0;
    let responseBody: unknown;
    const response = {
      status(code: number) {
        responseStatus = code;
        return this;
      },
      json(body: unknown) {
        responseBody = body;
        return this;
      },
    } as unknown as Response;

    const handler = createLabJobPostHandler((input) =>
      requestLabJob(input, dependencies),
    );
    await handler(
      {
        params: {
          workspaceId: "00000000-0000-4000-8000-000000000001",
        },
        body: {
          profileId,
          idempotencyKey: `offline-${label}-request-key`,
        },
        authUserId: "synthetic-owner",
      } as never,
      response,
      (() => undefined) as never,
    );

    assert.equal(responseStatus, 503, `${label} API status`);
    assert.deepEqual(responseBody, {
      error: "Requested isolated local assessment profile is unavailable",
    });
    assert.deepEqual(effects, {
      idempotencyOrPendingReads: 0,
      inserts: 0,
      quotaReservations: 0,
      enqueues: 0,
    });
  }
});
