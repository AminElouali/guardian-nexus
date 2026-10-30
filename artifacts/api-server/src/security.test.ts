import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { and, eq, inArray } from "drizzle-orm";
import {
  assetsTable,
  db,
  membershipsTable,
  pool,
  workspaceAuditEventsTable,
  workspacesTable,
} from "@workspace/db";
import { canManageMemberRoles, canWriteAssets } from "./lib/access-control";
import { UsageQuotaError, reserveWorkspaceUsage } from "./lib/usage";
import { withWorkspaceUserTransaction } from "./lib/tenant-db";

const userA = `rls-test-a-${crypto.randomUUID()}`;
const userB = `rls-test-b-${crypto.randomUUID()}`;
let workspaceA: string;
let workspaceB: string;
let assetA: string;
let assetB: string;

before(async () => {
  const [createdA, createdB] = await db
    .insert(workspacesTable)
    .values([
      { name: "RLS test tenant A", planId: "small", createdByUserId: userA },
      { name: "RLS test tenant B", planId: "small", createdByUserId: userB },
    ])
    .returning({ id: workspacesTable.id });
  workspaceA = createdA.id;
  workspaceB = createdB.id;

  await db.insert(membershipsTable).values([
    { workspaceId: workspaceA, userId: userA, role: "owner" },
    { workspaceId: workspaceB, userId: userB, role: "owner" },
  ]);
  const [createdAssetA, createdAssetB] = await db
    .insert(assetsTable)
    .values([
      {
        workspaceId: workspaceA,
        name: "Tenant A test asset",
        type: "application",
        environment: "test",
        criticality: "low",
      },
      {
        workspaceId: workspaceB,
        name: "Tenant B test asset",
        type: "application",
        environment: "test",
        criticality: "low",
      },
    ])
    .returning({ id: assetsTable.id });
  assetA = createdAssetA.id;
  assetB = createdAssetB.id;
});

after(async () => {
  if (workspaceA && workspaceB) {
    await db
      .delete(workspacesTable)
      .where(inArray(workspacesTable.id, [workspaceA, workspaceB]));
  }
  await pool.end();
});

test("RLS scopes unfiltered asset reads to the verified tenant", async () => {
  const result = await withWorkspaceUserTransaction(
    userA,
    workspaceA,
    (tx) => tx.select().from(assetsTable),
  );

  assert.equal(result.authorized, true);
  if (!result.authorized) return;
  assert.deepEqual(
    result.value.map((asset) => asset.id),
    [assetA],
  );
  assert.equal(result.value.some((asset) => asset.id === assetB), false);
});

test("a member cannot enter another workspace context", async () => {
  const result = await withWorkspaceUserTransaction(
    userA,
    workspaceB,
    (tx) => tx.select().from(assetsTable),
  );
  assert.deepEqual(result, { authorized: false });
});

test("RLS rejects writes across workspace boundaries", async () => {
  await assert.rejects(
    withWorkspaceUserTransaction(userA, workspaceA, async (tx) => {
      await tx.insert(assetsTable).values({
        workspaceId: workspaceB,
        name: "Must be rejected",
        type: "application",
        environment: "test",
        criticality: "low",
      });
    }),
    (error: { code?: string }) => error.code === "42501",
  );
});

test("workspace usage limits are enforced atomically", async () => {
  await assert.rejects(
    reserveWorkspaceUsage(userA, workspaceA, { tokens: 100_001 }),
    UsageQuotaError,
  );
});

test("basic workspace role permissions are explicit", () => {
  assert.equal(canWriteAssets("owner"), true);
  assert.equal(canWriteAssets("admin"), true);
  assert.equal(canWriteAssets("analyst"), true);
  assert.equal(canWriteAssets("viewer"), false);
  assert.equal(canManageMemberRoles("owner"), true);
  assert.equal(canManageMemberRoles("admin"), false);
});
