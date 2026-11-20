import { Router, type IRouter } from "express";
import healthRouter from "./health";
import aiEvaluationsRouter from "./ai-evaluations";
import aiAssessmentLabRouter from "./ai-assessment-lab";
import integrationsRouter from "./integrations";
import workspacesRouter from "./workspaces";
import workspaceIntegrationsRouter from "./workspace-integrations";
import workspaceGovernanceRouter from "./workspace-governance";
import { createMcpProxyRouter } from "./mcp-proxy";

const router: IRouter = Router();

router.use(healthRouter);
router.use(aiEvaluationsRouter);
router.use(createMcpProxyRouter());
router.use(aiAssessmentLabRouter);
router.use(workspaceGovernanceRouter);
router.use(workspacesRouter);
router.use(integrationsRouter);
router.use(workspaceIntegrationsRouter);

export default router;
