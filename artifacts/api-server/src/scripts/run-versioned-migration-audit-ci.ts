import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

type VersionedMigrationReport = {
  status: "running" | "passed" | "failed";
  baselineExpected: Record<string, number>;
  baselineActual?: Record<string, number>;
  baselineMatchesDrizzleProjection?: boolean;
  baselineMatchesExpectedLegacyProjection?: boolean;
  baselineLegacyActionRefConstraintVerified?: boolean;
  baselineActionRefLegacyDifferenceOnly?: boolean;
  drizzleCatalog?: Record<string, number>;
  migratedCatalog?: Record<string, number>;
  migrationsApplied: string[];
  migration0003Idempotent?: boolean;
  migration0004Idempotent?: boolean;
  migration0005Idempotent?: boolean;
  migration0006LegacyConstraintReplaced?: boolean;
  migration0006Idempotent?: boolean;
  migration0006UnexpectedConstraintRejected?: boolean;
  inventoryMatchesDrizzle?: Record<string, boolean>;
  violationCodes: string[];
};

const emptyReport = (): VersionedMigrationReport => ({
  status: "failed",
  baselineExpected: {
    tables: 13,
    columns: 149,
    indexes: 37,
    constraints: 54,
    policies: 36,
    roles: 3,
  },
  migrationsApplied: [],
  violationCodes: ["ci_target_not_verified"],
});

const reportDirectory = process.env.RUNNER_TEMP;
const commitSha = /^[a-f0-9]{40}$/i.test(process.env.GITHUB_SHA ?? "")
  ? process.env.GITHUB_SHA!
  : null;
let report = emptyReport();

try {
  const { runVersionedMigrationAuditForCi } = await import(
    "./run-postgres-local-lab.js"
  );
  report = await runVersionedMigrationAuditForCi(
    process.env.DATABASE_URL ?? "",
    commitSha ?? "",
  );
} catch {
  report.status = "failed";
  if (report.violationCodes.length === 0) {
    report.violationCodes = ["versioned_migration_ci_audit_failed"];
  }
}

const differenceCodes = [...new Set(report.violationCodes)].sort();
const artifact = {
  version: 1,
  commitSha,
  status: report.status,
  counts: {
    baselineExpected: report.baselineExpected,
    baselineActual: report.baselineActual ?? null,
    drizzle: report.drizzleCatalog ?? null,
    versionedMigration: report.migratedCatalog ?? null,
  },
  differenceCount: differenceCodes.length,
  differenceCodes,
  idempotency: {
    migration0003: report.migration0003Idempotent ?? null,
    migration0004: report.migration0004Idempotent ?? null,
    migration0005: report.migration0005Idempotent ?? null,
    migration0006: report.migration0006Idempotent ?? null,
  },
  migration0006LegacyConstraintReplaced:
    report.migration0006LegacyConstraintReplaced ?? null,
  migration0006UnexpectedConstraintRejected:
    report.migration0006UnexpectedConstraintRejected ?? null,
  baselineMatchesDrizzleProjection:
    report.baselineMatchesDrizzleProjection ?? null,
  baselineMatchesExpectedLegacyProjection:
    report.baselineMatchesExpectedLegacyProjection ?? null,
  baselineLegacyActionRefConstraintVerified:
    report.baselineLegacyActionRefConstraintVerified ?? null,
  baselineActionRefLegacyDifferenceOnly:
    report.baselineActionRefLegacyDifferenceOnly ?? null,
  inventoryMatchesDrizzle: report.inventoryMatchesDrizzle ?? null,
  migrationsApplied: report.migrationsApplied,
  versionedMigrationAudit: report,
};

if (
  !reportDirectory ||
  !path.isAbsolute(reportDirectory) ||
  !commitSha
) {
  console.error("Versioned migration audit could not create its report.");
  process.exitCode = 1;
} else {
  const reportPath = path.join(
    reportDirectory,
    "guardian-postgres-versioned-migration-report.json",
  );
  await mkdir(reportDirectory, { recursive: true, mode: 0o700 });
  await writeFile(reportPath, `${JSON.stringify(artifact, null, 2)}\n`, {
    mode: 0o600,
  });
  console.log(
    `Versioned SQL migration audit: status=${report.status} differences=${differenceCodes.length} migration0003Idempotent=${artifact.idempotency.migration0003} migration0004Idempotent=${artifact.idempotency.migration0004} migration0005Idempotent=${artifact.idempotency.migration0005} migration0006Idempotent=${artifact.idempotency.migration0006}`,
  );
  if (report.status !== "passed" || differenceCodes.length > 0) {
    process.exitCode = 1;
  }
}
