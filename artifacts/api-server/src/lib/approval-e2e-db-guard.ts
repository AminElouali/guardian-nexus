import {
  requestVerifiedGitHubActionsClaimsDetailed,
  type GitHubActionsOidcFailureCategory,
} from "./github-actions-oidc";

// Do not rely on resolving "localhost": a disposable-target gate should only
// admit an IP literal whose loopback destination is explicit in the URL.
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "[::1]"]);
const DISPOSABLE_DATABASE_NAME = /^guardian_approval_lab_[a-z0-9_]+$/;
const CI_DATABASE_NAME = "guardian_approval_lab_ci";
const APP_RUNTIME_LOGIN = "app_runtime_login";
const CI_REPOSITORY = "AminElouali/guardian-nexus";
const CI_MAIN_REF = "refs/heads/main";
const CI_WORKFLOW_NAME = "Guardian Nexus PostgreSQL Approval Lab";
const CI_JOB_ID = "postgres-approval-lab";
const CI_WORKFLOW_REF =
  `${CI_REPOSITORY}/.github/workflows/postgres-approval-lab.yml@${CI_MAIN_REF}`;

export type ApprovalLabCiStage = "bootstrap" | "provision" | "approval-e2e";
export type ApprovalLabRejectionCategory =
  | "github_context_missing"
  | "github_context_incompatible"
  | GitHubActionsOidcFailureCategory
  | "database_url_mismatch";
export type ApprovalLabTargetDecision =
  | { accepted: true; stage: ApprovalLabCiStage }
  | {
      accepted: false;
      category: ApprovalLabRejectionCategory;
      stage: ApprovalLabCiStage | "unknown";
    };

function isApprovalLabCiStage(value: unknown): value is ApprovalLabCiStage {
  return ["bootstrap", "provision", "approval-e2e"].includes(
    value as string,
  );
}

function hasGitHubActionsContext(
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  return [
    env.CI,
    env.GITHUB_ACTIONS,
    env.GITHUB_WORKFLOW,
    env.GITHUB_WORKFLOW_REF,
    env.GITHUB_JOB,
    env.GITHUB_EVENT_NAME,
    env.GITHUB_REPOSITORY,
    env.GITHUB_REF,
    env.GITHUB_REF_TYPE,
    env.GITHUB_RUN_ID,
    env.GITHUB_RUN_ATTEMPT,
    env.GITHUB_SHA,
    env.ACTIONS_ID_TOKEN_REQUEST_URL,
    env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
  ].some((value) => value !== undefined);
}

function matchesPostgresUrl(
  value: string | undefined,
  expected: {
    database: string;
    username: string;
    password: string;
  },
): boolean {
  if (!value) return false;
  try {
    const parsed = new URL(value);
    return (
      ["postgres:", "postgresql:"].includes(parsed.protocol) &&
      parsed.hostname === "127.0.0.1" &&
      parsed.port === "5432" &&
      decodeURIComponent(parsed.username) === expected.username &&
      decodeURIComponent(parsed.password) === expected.password &&
      parsed.pathname === `/${expected.database}` &&
      parsed.search === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

function matchesLocalRuntimeUrl(
  value: string | undefined,
  expectedDatabase: string,
  expectedHost: string,
): boolean {
  if (!value) return false;
  try {
    const parsed = new URL(value);
    const password = decodeURIComponent(parsed.password);
    return (
      ["postgres:", "postgresql:"].includes(parsed.protocol) &&
      LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase()) &&
      parsed.hostname.toLowerCase() === expectedHost.toLowerCase() &&
      parsed.port === "5432" &&
      decodeURIComponent(parsed.username) === APP_RUNTIME_LOGIN &&
      password.length >= 32 &&
      decodeURIComponent(parsed.pathname.replace(/^\/+/, "")) ===
        expectedDatabase &&
      parsed.search === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

/**
 * CI-only target contract for the PostgreSQL service declared by the dedicated
 * GitHub Actions job. A fresh OIDC token is verified before target coordinates
 * are accepted; plain environment markers are never treated as proof.
 */
export async function diagnoseGitHubActionsApprovalLabTarget(
  env: Readonly<Record<string, string | undefined>>,
  stage: string | undefined = env.GUARDIAN_APPROVAL_E2E_CI_STAGE,
): Promise<ApprovalLabTargetDecision> {
  const stageId = isApprovalLabCiStage(stage) ? stage : "unknown";
  const runId = env.GITHUB_RUN_ID;
  const runAttempt = env.GITHUB_RUN_ATTEMPT;
  const commitSha = env.GITHUB_SHA;
  const requiredContext = [
    env.NODE_ENV,
    env.CI,
    env.GITHUB_ACTIONS,
    env.GITHUB_WORKFLOW,
    env.GITHUB_WORKFLOW_REF,
    env.GITHUB_JOB,
    env.GITHUB_EVENT_NAME,
    env.GITHUB_REPOSITORY,
    env.GITHUB_REF,
    env.GITHUB_REF_TYPE,
    runId,
    runAttempt,
    commitSha,
    env.GUARDIAN_APPROVAL_E2E_CI_SERVICE,
    env.GUARDIAN_APPROVAL_E2E_DISPOSABLE,
    env.GUARDIAN_APPROVAL_E2E_CI_STAGE,
    stage,
  ];
  const reject = (
    category: ApprovalLabRejectionCategory,
  ): ApprovalLabTargetDecision => ({
    accepted: false,
    category,
    stage: stageId,
  });

  if (requiredContext.some((value) => value === undefined || value === "")) {
    return reject("github_context_missing");
  }

  if (
    env.NODE_ENV !== "development" ||
    env.REPLIT_DEPLOYMENT ||
    env.CI !== "true" ||
    env.GITHUB_ACTIONS !== "true" ||
    env.GITHUB_WORKFLOW !== CI_WORKFLOW_NAME ||
    env.GITHUB_WORKFLOW_REF?.toLowerCase() !==
      CI_WORKFLOW_REF.toLowerCase() ||
    env.GITHUB_JOB !== CI_JOB_ID ||
    env.GITHUB_EVENT_NAME !== "workflow_dispatch" ||
    env.GITHUB_REPOSITORY?.toLowerCase() !== CI_REPOSITORY.toLowerCase() ||
    env.GITHUB_REF_TYPE !== "branch" ||
    env.GITHUB_REF !== CI_MAIN_REF ||
    !runId ||
    !/^\d+$/.test(runId) ||
    !runAttempt ||
    !/^\d+$/.test(runAttempt) ||
    !commitSha ||
    !/^[a-f0-9]{40}$/i.test(commitSha) ||
    env.GUARDIAN_APPROVAL_E2E_CI_SERVICE !== "postgres" ||
    env.GUARDIAN_APPROVAL_E2E_DISPOSABLE !== "1" ||
    !isApprovalLabCiStage(stage) ||
    env.GUARDIAN_APPROVAL_E2E_CI_STAGE !== stage
  ) {
    return reject("github_context_incompatible");
  }

  let oidcResult: Awaited<
    ReturnType<typeof requestVerifiedGitHubActionsClaimsDetailed>
  >;
  try {
    oidcResult = await requestVerifiedGitHubActionsClaimsDetailed(env, {
      repository: CI_REPOSITORY,
      repositoryOwner: "AminElouali",
      workflow: CI_WORKFLOW_NAME,
      workflowRef: CI_WORKFLOW_REF,
      ref: CI_MAIN_REF,
      eventName: "workflow_dispatch",
      sha: commitSha,
      runId,
      runAttempt,
    });
  } catch {
    return reject("oidc_verification_unexpected_exception");
  }
  if (!oidcResult.ok) return reject(oidcResult.category);
  const claims = oidcResult.claims;

  // Derive expected connection values from signed claims, not caller supplied
  // run metadata. The environment URL must still match this exact destination.
  const adminPassword = `guardian-ci-${claims.run_id}-${claims.run_attempt}-${claims.sha}`;
  const database = stage === "bootstrap" ? "postgres" : CI_DATABASE_NAME;
  if (
    !matchesPostgresUrl(env.DATABASE_URL, {
      database,
      username: "postgres",
      password: adminPassword,
    })
  ) {
    return reject("database_url_mismatch");
  }

  if (stage !== "approval-e2e") {
    const runtimePassword = `guardian-runtime-${claims.run_id}-${claims.run_attempt}-${claims.sha}`;
    const runtimeConfigurationMatches =
      env.APP_RUNTIME_DATABASE_URL === undefined &&
      (env.APP_RUNTIME_DB_PASSWORD === undefined ||
        env.APP_RUNTIME_DB_PASSWORD === runtimePassword);
    return runtimeConfigurationMatches
      ? { accepted: true, stage }
      : reject("database_url_mismatch");
  }

  const runtimePassword = `guardian-runtime-${claims.run_id}-${claims.run_attempt}-${claims.sha}`;
  const runtimeUrlMatches =
    env.APP_RUNTIME_DATABASE_URL !== undefined &&
    matchesPostgresUrl(env.APP_RUNTIME_DATABASE_URL, {
      database: CI_DATABASE_NAME,
      username: "app_runtime_login",
      password: runtimePassword,
    });
  return runtimeUrlMatches
    ? { accepted: true, stage }
    : reject("database_url_mismatch");
}

export async function isGitHubActionsApprovalLabTarget(
  env: Readonly<Record<string, string | undefined>>,
  stage?: ApprovalLabCiStage,
): Promise<boolean> {
  const decision = await diagnoseGitHubActionsApprovalLabTarget(env, stage);
  return decision.accepted;
}

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
  // Synchronous opt-in is restricted to local development. CI must use the
  // asynchronous OIDC-verifying helper before importing the DB package.
  if (hasGitHubActionsContext(env)) return false;

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
  if (
    env.APP_RUNTIME_DB_PASSWORD !== undefined ||
    env.PGHOST !== undefined ||
    env.PGPORT !== undefined ||
    env.PGUSER !== undefined ||
    env.PGPASSWORD !== undefined ||
    env.PGDATABASE !== undefined
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
      parsed.port !== "5432" ||
      hasConnectionOverrides
    ) {
      return false;
    }

    const databaseName = decodeURIComponent(
      parsed.pathname.replace(/^\/+/, ""),
    );
    return (
      databaseName === expectedDatabaseName &&
      matchesLocalRuntimeUrl(
        env.APP_RUNTIME_DATABASE_URL,
        expectedDatabaseName,
        parsed.hostname,
      )
    );
  } catch {
    return false;
  }
}

export async function verifyExplicitDisposableApprovalDatabase(
  env: Readonly<Record<string, string | undefined>>,
): Promise<boolean> {
  if (hasGitHubActionsContext(env)) {
    return isGitHubActionsApprovalLabTarget(
      env,
      "approval-e2e",
    );
  }
  return isExplicitDisposableApprovalDatabase(env);
}
