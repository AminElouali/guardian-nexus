import { and, count, desc, eq } from "drizzle-orm";
import { Router, type IRouter } from "express";
import {
  assetsTable,
  db,
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

const router: IRouter = Router();
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

router.get("/plans", (_req, res): void => {
  res.json(ListPlansResponse.parse(plans));
});

router.use("/workspaces", requireAuth);
router.get("/workspaces", async (req, res): Promise<void> => {
  const userId = req.authUserId!;
  const rows = await db
    .select({
      id: workspacesTable.id,
      name: workspacesTable.name,
      planId: workspacesTable.planId,
      role: membershipsTable.role,
      createdAt: workspacesTable.createdAt,
    })
    .from(membershipsTable)
    .innerJoin(workspacesTable, eq(workspacesTable.id, membershipsTable.workspaceId))
    .where(eq(membershipsTable.userId, userId))
    .orderBy(desc(workspacesTable.createdAt));
  res.json(ListWorkspacesResponse.parse(rows));
});

router.post("/workspaces", async (req, res): Promise<void> => {
  const parsed = CreateWorkspaceBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const workspace = await db.transaction(async (tx) => {
    const [created] = await tx
      .insert(workspacesTable)
      .values({ name: parsed.data.name.trim(), planId: parsed.data.planId })
      .returning();
    await tx.insert(membershipsTable).values({
      workspaceId: created.id,
      userId: req.authUserId!,
      role: "owner",
    });
    return created;
  });
  res.status(201).json(
    CreateWorkspaceResponse.parse({ ...workspace, role: "owner" }),
  );
});

async function getWorkspaceMembership(workspaceId: string, userId: string) {
  if (!UUID_PATTERN.test(workspaceId)) return undefined;
  const [membership] = await db
    .select()
    .from(membershipsTable)
    .where(
      and(
        eq(membershipsTable.workspaceId, workspaceId),
        eq(membershipsTable.userId, userId),
      ),
    )
    .limit(1);
  return membership;
}

function canWrite(role: string): boolean {
  return role === "owner" || role === "admin" || role === "analyst";
}

router.get("/workspaces/:workspaceId/dashboard", async (req, res): Promise<void> => {
  const params = GetWorkspaceDashboardParams.safeParse(req.params);
  if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
    res.status(400).json({ error: "Invalid workspace ID" });
    return;
  }
  const workspaceId = params.data.workspaceId;
  const membership = await getWorkspaceMembership(workspaceId, req.authUserId!);
  if (!membership) {
    res.status(403).json({ error: "Workspace access denied" });
    return;
  }

  const [[workspace], [assetCount], [memberCount], [usage], recentAssets] =
    await Promise.all([
      db.select().from(workspacesTable).where(eq(workspacesTable.id, workspaceId)).limit(1),
      db.select({ value: count() }).from(assetsTable).where(eq(assetsTable.workspaceId, workspaceId)),
      db.select({ value: count() }).from(membershipsTable).where(eq(membershipsTable.workspaceId, workspaceId)),
      db
        .select()
        .from(monthlyUsageTable)
        .where(
          and(
            eq(monthlyUsageTable.workspaceId, workspaceId),
            eq(monthlyUsageTable.monthStart, new Date().toISOString().slice(0, 7) + "-01"),
          ),
        )
        .limit(1),
      db
        .select()
        .from(assetsTable)
        .where(eq(assetsTable.workspaceId, workspaceId))
        .orderBy(desc(assetsTable.createdAt))
        .limit(5),
    ]);

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
  const membership = await getWorkspaceMembership(workspaceId, req.authUserId!);
  if (!membership) {
    res.status(403).json({ error: "Workspace access denied" });
    return;
  }
  const rows = await db
    .select({
      id: membershipsTable.id,
      userId: membershipsTable.userId,
      role: membershipsTable.role,
      createdAt: membershipsTable.createdAt,
    })
    .from(membershipsTable)
    .where(eq(membershipsTable.workspaceId, workspaceId))
    .orderBy(membershipsTable.createdAt);
  res.json(ListWorkspaceMembersResponse.parse(rows));
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
    const actor = await getWorkspaceMembership(workspaceId, req.authUserId!);
    if (!actor || actor.role !== "owner") {
      res.status(403).json({ error: "Only the workspace owner can change roles" });
      return;
    }
    const [target] = await db
      .select()
      .from(membershipsTable)
      .where(
        and(
          eq(membershipsTable.id, membershipId),
          eq(membershipsTable.workspaceId, workspaceId),
        ),
      )
      .limit(1);
    if (!target || target.role === "owner") {
      res.status(404).json({ error: "Editable member not found" });
      return;
    }
    const [updated] = await db
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
    res.json(UpdateWorkspaceMemberResponse.parse(updated));
  },
);

router.get("/workspaces/:workspaceId/assets", async (req, res): Promise<void> => {
  const params = ListWorkspaceAssetsParams.safeParse(req.params);
  if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
    res.status(400).json({ error: "Invalid workspace ID" });
    return;
  }
  const workspaceId = params.data.workspaceId;
  if (!(await getWorkspaceMembership(workspaceId, req.authUserId!))) {
    res.status(403).json({ error: "Workspace access denied" });
    return;
  }
  const assets = await db
    .select()
    .from(assetsTable)
    .where(eq(assetsTable.workspaceId, workspaceId))
    .orderBy(desc(assetsTable.createdAt));
  res.json(ListWorkspaceAssetsResponse.parse(assets));
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
  const membership = await getWorkspaceMembership(workspaceId, req.authUserId!);
  if (!membership || !canWrite(membership.role)) {
    res.status(403).json({ error: "Workspace write access denied" });
    return;
  }

  const result = await db.transaction(async (tx) => {
    const [workspace] = await tx
      .select()
      .from(workspacesTable)
      .where(eq(workspacesTable.id, workspaceId))
      .for("update")
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
    return { kind: "created" as const, asset };
  });

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
    const membership = await getWorkspaceMembership(workspaceId, req.authUserId!);
    if (!membership || !canWrite(membership.role)) {
      res.status(403).json({ error: "Workspace write access denied" });
      return;
    }
    const [deleted] = await db
      .delete(assetsTable)
      .where(
        and(
          eq(assetsTable.id, assetId),
          eq(assetsTable.workspaceId, workspaceId),
        ),
      )
      .returning({ id: assetsTable.id });
    if (!deleted) {
      res.status(404).json({ error: "Asset not found" });
      return;
    }
    res.sendStatus(204);
  },
);

export default router;
