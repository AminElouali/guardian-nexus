// Do not rely on resolving "localhost": a disposable-target gate should only
// admit an IP literal whose loopback destination is explicit in the URL.
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "[::1]"]);
const DISPOSABLE_DATABASE_NAME = /^guardian_approval_lab_[a-z0-9_]+$/;

/**
 * The persistent approval E2E mutates and deletes synthetic rows. Require an
 * explicit opt-in and a uniquely named loopback database so a normal dev or
 * managed database URL can never be treated as disposable by accident.
 *
 * This helper intentionally returns only a boolean; callers must not log the
 * connection string or its credentials.
 */
export function isExplicitDisposableApprovalDatabase(
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  if (
    env.NODE_ENV !== "development" ||
    env.REPLIT_DEPLOYMENT === "1" ||
    env.GUARDIAN_APPROVAL_E2E_DISPOSABLE !== "1"
  ) {
    return false;
  }

  const databaseUrl = env.DATABASE_URL;
  const expectedDatabaseName = env.GUARDIAN_APPROVAL_E2E_DATABASE_NAME;
  if (
    !databaseUrl ||
    !expectedDatabaseName ||
    !DISPOSABLE_DATABASE_NAME.test(expectedDatabaseName)
  ) {
    return false;
  }

  try {
    const parsed = new URL(databaseUrl);
    // Do not allow libpq/driver options or fragments to alter connection
    // routing/configuration after this URL has passed the disposable-target
    // check (for example `service`, `servicefile`, `host`, or `hostaddr`).
    const hasConnectionOverrides =
      Array.from(parsed.searchParams.keys()).length > 0 ||
      parsed.hash.length > 0;
    if (
      !["postgres:", "postgresql:"].includes(parsed.protocol) ||
      !LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase()) ||
      hasConnectionOverrides
    ) {
      return false;
    }

    const databaseName = decodeURIComponent(parsed.pathname.replace(/^\/+/, ""));
    return databaseName === expectedDatabaseName;
  } catch {
    return false;
  }
}
