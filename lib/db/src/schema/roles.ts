import { pgRole } from "drizzle-orm/pg-core";

export const appRuntimeRole = pgRole("app_runtime").existing();
