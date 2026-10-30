import { pgRole } from "drizzle-orm/pg-core";

export const appRuntimeRole = pgRole("app_runtime").existing();
export const appRuntimeLoginRoleName = "app_runtime_login";
export const appRuntimeLoginRole = pgRole(appRuntimeLoginRoleName).existing();
export const aiAssessmentWorkerRole = pgRole(
  "app_ai_assessment_worker",
).existing();
