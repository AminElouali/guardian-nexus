import { and, count, desc, eq, sql } from "drizzle-orm";
import { Router, type IRouter } from "express";
import {
  workspaceAuditEventsTable,
  assetsTable,
  membershipsTable,
  monthlyUsageTable,
  workspacesTable,
} from "@workspace/db";
import {
  CreateWorkspaceAssetBody,
  CreateWorkspaceAssetParams,
  CreateWorkspaceAssetResponse,
  CreateWorkspaceBody,
  CreateWorkspaceResponse,
  DeleteWorkspaceAssetParams,
  GetWorkspaceDashboardParams,
  GetWorkspaceDashboardResponse,
  ListWorkspaceAssetsParams,
  ListWorkspaceAssetsResponse,
  ListWorkspaceMembersParams,
  ListWorkspaceMembersResponse,
  ListWorkspacesResponse,
  UpdateWorkspaceMemberBody,
  UpdateWorkspaceMemberParams,
  UpdateWorkspaceMemberResponse,
  ListPlansResponse,
} from "@workspace/api-zod";
import { requireAuth } from "../middlewares/requireAuth";
import { getPlan, plans } from "../lib/plans";
import {
  canManageMemberRoles,
  canWriteAssets,
} from "../lib/access-control";
import {
  setWorkspaceContext,
  withUserTransaction,
  withWorkspaceUserTransaction,
} from "../lib/tenant-db";

const router: IRouter = Router();
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

router.get("/plans", (_req, res): void => {
  res.json(ListPlansResponse.parse(plans));
});

router.use("/workspaces", requireAuth);
router.get("/workspaces", async (req, res): Promise<void> => {
  const userId = req.authUserId!;
  const rows = await withUserTransaction(userId, (tx) =>
    tx
      .select({
        id: workspacesTable.id,
        name: workspacesTable.name,
        planId: workspacesTable.planId,
        role: membershipsTable.role,
        createdAt: workspacesTable.createdAt,
      })
      .from(membershipsTable)
      .innerJoin(
        workspacesTable,
        eq(workspacesTable.id, membershipsTable.workspaceId),
      )
      .where(eq(membershipsTable.userId, userId))
      .orderBy(desc(workspacesTable.createdAt)),
  );
  res.json(ListWorkspacesResponse.parse(rows));
});

router.post("/workspaces", async (req, res): Promise<void> => {
  const parsed = CreateWorkspaceBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const userId = req.authUserId!;
  const workspace = await withUserTransaction(userId, async (tx) => {
    const [created] = await tx
      .insert(workspacesTable)
      .values({
        name: parsed.data.name.trim(),
        planId: parsed.data.planId,
        createdByUserId: userId,
      })
      .returning();
    await setWorkspaceContext(tx, created.id);
    await tx.insert(membershipsTable).values({
      workspaceId: created.id,
      userId,
      role: "owner",
    });
    await tx.insert(workspaceAuditEventsTable).values({
      workspaceId: created.id,
      actorUserId: userId,
      action: "workspace.created",
      resourceType: "workspace",
      resourceId: created.id,
      metadata: { planId: created.planId },
    });
    return created;
  });
  res.status(201).json(
    CreateWorkspaceResponse.parse({ ...workspace, role: "owner" }),
  );
});

router.get("/workspaces/:workspaceId/dashboard", async (req, res): Promise<void> => {
  const params = GetWorkspaceDashboardParams.safeParse(req.params);
  if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
    res.status(400).json({ error: "Invalid workspace ID" });
    return;
  }
  const workspaceId = params.data.workspaceId;
  const access = await withWorkspaceUserTransaction(
    req.authUserId!,
    workspaceId,
    async (tx, membership) => {
      const [
        [workspace],
        [assetCount],
        [memberCount],
        [usage],
        recentAssets,
      ] = await Promise.all([
        tx
          .select()
          .from(workspacesTable)
          .where(eq(workspacesTable.id, workspaceId))
          .limit(1),
        tx
          .select({ value: count() })
          .from(assetsTable)
          .where(eq(assetsTable.workspaceId, workspaceId)),
        tx
          .select({ value: count() })
          .from(membershipsTable)
          .where(eq(membershipsTable.workspaceId, workspaceId)),
        tx
          .select()
          .from(monthlyUsageTable)
          .where(
            and(
              eq(monthlyUsageTable.workspaceId, workspaceId),
              eq(
                monthlyUsageTable.monthStart,
                new Date().toISOString().slice(0, 7) + "-01",
              ),
            ),
          )
          .limit(1),
        tx
          .select()
          .from(assetsTable)
          .where(eq(assetsTable.workspaceId, workspaceId))
          .orderBy(desc(assetsTable.createdAt))
          .limit(5),
      ]);

      return {
        membership,
        workspace,
        assetCount: assetCount.value,
        memberCount: memberCount.value,
        usage,
        recentAssets,
      };
    },
  );
  if (!access.authorized) {
    res.status(403).json({ error: "Workspace access denied" });
    return;
  }

  const { membership, workspace, assetCount, memberCount, usage, recentAssets } =
    access.value;
  if (!workspace) {
    res.status(404).json({ error: "Workspace not found" });
    return;
  }
  const plan = getPlan(workspace.planId);
  if (!plan) {
    res.status(500).json({ error: "Workspace has an invalid plan" });
    return;
  }
  res.json(
    GetWorkspaceDashboardResponse.parse({
      workspace: { ...workspace, role: membership.role },
      plan,
      assetCount: assetCount.value,
      memberCount: memberCount.value,
      findingsCount: 0,
      scansUsed: usage?.scansUsed ?? 0,
      tokensUsed: usage?.tokensUsed ?? 0,
      apiRequestsUsed: usage?.apiRequestsUsed ?? 0,
      recentAssets,
    }),
  );
});

router.get("/workspaces/:workspaceId/members", async (req, res): Promise<void> => {
  const params = ListWorkspaceMembersParams.safeParse(req.params);
  if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
    res.status(400).json({ error: "Invalid workspace ID" });
    return;
  }
  const workspaceId = params.data.workspaceId;
  const access = await withWorkspaceUserTransaction(
    req.authUserId!,
    workspaceId,
    async (tx) =>
      tx
        .select({
          id: membershipsTable.id,
          userId: membershipsTable.userId,
          role: membershipsTable.role,
          createdAt: membershipsTable.createdAt,
        })
        .from(membershipsTable)
        .where(eq(membershipsTable.workspaceId, workspaceId))
        .orderBy(membershipsTable.createdAt),
  );
  if (!access.authorized) {
    res.status(403).json({ error: "Workspace access denied" });
    return;
  }
  res.json(ListWorkspaceMembersResponse.parse(access.value));
});

router.patch(
  "/workspaces/:workspaceId/members/:membershipId",
  async (req, res): Promise<void> => {
    const params = UpdateWorkspaceMemberParams.safeParse(req.params);
    const parsed = UpdateWorkspaceMemberBody.safeParse(req.body);
    if (
      !params.success ||
      !parsed.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !UUID_PATTERN.test(params.data.membershipId)
    ) {
      res.status(400).json({ error: "Invalid member update" });
      return;
    }
    const { workspaceId, membershipId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, actor) => {
        if (!canManageMemberRoles(actor.role)) {
          return { kind: "forbidden" as const };
        }
        const [target] = await tx
          .select()
          .from(membershipsTable)
          .where(
            and(
              eq(membershipsTable.id, membershipId),
              eq(membershipsTable.workspaceId, workspaceId),
            ),
          )
          .for("update")
          .limit(1);
        if (!target || target.role === "owner") {
          return { kind: "not-found" as const };
        }
        const [updated] = await tx
          .update(membershipsTable)
          .set({ role: parsed.data.role })
          .where(
            and(
              eq(membershipsTable.id, membershipId),
              eq(membershipsTable.workspaceId, workspaceId),
            ),
          )
          .returning({
            id: membershipsTable.id,
            userId: membershipsTable.userId,
            role: membershipsTable.role,
            createdAt: membershipsTable.createdAt,
          });
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId,
          actorUserId: req.authUserId!,
          action: "membership.role_updated",
          resourceType: "membership",
          resourceId: target.id,
          metadata: { from: target.role, to: updated.role },
        });
        return { kind: "updated" as const, member: updated };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Only the workspace owner can change roles" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Only the workspace owner can change roles" });
      return;
    }
    if (access.value.kind === "not-found") {
      res.status(404).json({ error: "Editable member not found" });
      return;
    }
    res.json(UpdateWorkspaceMemberResponse.parse(access.value.member));
  },
);

router.get("/workspaces/:workspaceId/assets", async (req, res): Promise<void> => {
  const params = ListWorkspaceAssetsParams.safeParse(req.params);
  if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
    res.status(400).json({ error: "Invalid workspace ID" });
    return;
  }
  const workspaceId = params.data.workspaceId;
  const access = await withWorkspaceUserTransaction(
    req.authUserId!,
    workspaceId,
    (tx) =>
      tx
        .select()
        .from(assetsTable)
        .where(eq(assetsTable.workspaceId, workspaceId))
        .orderBy(desc(assetsTable.createdAt)),
  );
  if (!access.authorized) {
    res.status(403).json({ error: "Workspace access denied" });
    return;
  }
  res.json(ListWorkspaceAssetsResponse.parse(access.value));
});

router.post("/workspaces/:workspaceId/assets", async (req, res): Promise<void> => {
  const params = CreateWorkspaceAssetParams.safeParse(req.params);
  const parsed = CreateWorkspaceAssetBody.safeParse(req.body);
  if (
    !params.success ||
    !parsed.success ||
    !UUID_PATTERN.test(params.data.workspaceId)
  ) {
    res.status(400).json({ error: "Invalid asset input" });
    return;
  }
  const workspaceId = params.data.workspaceId;
  const access = await withWorkspaceUserTransaction(
    req.authUserId!,
    workspaceId,
    async (tx, membership) => {
      if (!canWriteAssets(membership.role)) {
        return { kind: "forbidden" as const };
      }
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(hashtextextended(${workspaceId}, 0))`,
      );
      const [workspace] = await tx
        .select()
        .from(workspacesTable)
        .where(eq(workspacesTable.id, workspaceId))
        .limit(1);
      if (!workspace) return { kind: "not-found" as const };
      const plan = getPlan(workspace.planId);
      if (!plan) return { kind: "invalid-plan" as const };
      const [assetCount] = await tx
        .select({ value: count() })
        .from(assetsTable)
        .where(eq(assetsTable.workspaceId, workspaceId));
      if (assetCount.value >= plan.maxAssets) return { kind: "limit" as const };
      const [asset] = await tx
        .insert(assetsTable)
        .values({ ...parsed.data, workspaceId })
        .returning();
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId,
        actorUserId: req.authUserId!,
        action: "asset.created",
        resourceType: "asset",
        resourceId: asset.id,
        metadata: { type: asset.type, environment: asset.environment },
      });
      return { kind: "created" as const, asset };
    },
  );
  if (!access.authorized) {
    res.status(403).json({ error: "Workspace write access denied" });
    return;
  }

  const result = access.value;
  if (result.kind === "forbidden") {
    res.status(403).json({ error: "Workspace write access denied" });
    return;
  }
  if (result.kind === "limit") {
    res.status(409).json({ error: "Asset limit reached for this plan" });
    return;
  }
  if (result.kind === "not-found") {
    res.status(404).json({ error: "Workspace not found" });
    return;
  }
  if (result.kind === "invalid-plan") {
    res.status(500).json({ error: "Workspace has an invalid plan" });
    return;
  }
  res.status(201).json(CreateWorkspaceAssetResponse.parse(result.asset));
});

router.delete(
  "/workspaces/:workspaceId/assets/:assetId",
  async (req, res): Promise<void> => {
    const params = DeleteWorkspaceAssetParams.safeParse(req.params);
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !UUID_PATTERN.test(params.data.assetId)
    ) {
      res.status(400).json({ error: "Invalid asset ID" });
      return;
    }
    const { workspaceId, assetId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canWriteAssets(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const [deleted] = await tx
          .delete(assetsTable)
          .where(
            and(
              eq(assetsTable.id, assetId),
              eq(assetsTable.workspaceId, workspaceId),
            ),
          )
          .returning({ id: assetsTable.id });
        if (!deleted) return { kind: "not-found" as const };
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId,
          actorUserId: req.authUserId!,
          action: "asset.deleted",
          resourceType: "asset",
          resourceId: deleted.id,
          metadata: {},
        });
        return { kind: "deleted" as const };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace write access denied" });
      return;
    }
    if (access.value.kind !== "deleted") {
      if (access.value.kind === "forbidden") {
        res.status(403).json({ error: "Workspace write access denied" });
        return;
      }
      res.status(404).json({ error: "Asset not found" });
      return;
    }
    res.sendStatus(204);
  },
);

export default router;
