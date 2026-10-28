import { Router, type IRouter } from "express";
import healthRouter from "./health";
import workspacesRouter from "./workspaces";

const router: IRouter = Router();

router.use(healthRouter);
router.use(workspacesRouter);

export default router;
