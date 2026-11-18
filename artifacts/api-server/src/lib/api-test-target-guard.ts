import { isExplicitDisposableApprovalDatabase } from "./approval-e2e-db-guard";

export const API_TEST_TARGET_REJECTION =
  "API tests require the isolated local PostgreSQL lab target.";

export function isSafeApiTestTarget(
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  if (Object.keys(env).some((name) => name.startsWith("PG"))) return false;
  return isExplicitDisposableApprovalDatabase(env);
}

export async function runApiTestSuite(
  env: Readonly<Record<string, string | undefined>>,
  launch: () => Promise<number>,
): Promise<{ started: boolean; exitCode: number }> {
  if (!isSafeApiTestTarget(env)) {
    return { started: false, exitCode: 1 };
  }
  return { started: true, exitCode: await launch() };
}
