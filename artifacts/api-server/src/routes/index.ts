import { Router, type IRouter } from "express";
import healthRouter from "./health";
import aiEvaluationsRouter from "./ai-evaluations";
import integrationsRouter from "./integrations";
import workspacesRouter from "./workspaces";
import workspaceIntegrationsRouter from "./workspace-integrations";

const router: IRouter = Router();

router.use(healthRouter);
router.use(aiEvaluationsRouter);
router.use(workspacesRouter);
router.use(integrationsRouter);
router.use(workspaceIntegrationsRouter);

export default router;
