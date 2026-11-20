import { createHash, randomBytes } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { statSync } from "node:fs";
import {
  chmod,
  lstat,
  mkdtemp,
  mkdir,
  readdir,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import {
  auditRlsPostPushCatalog,
  canonicalizeRlsExpression,
  deriveDrizzleRlsTableNames,
  expectedPostPushRoleNames,
  readRlsCatalogPhaseSnapshot,
  runPostSchemaAuditBarrier,
  type RlsCatalogPhaseSnapshot,
} from "@workspace/db/rls-catalog-phase-audit";
import {
  parseRlsCatalogContract,
  auditRlsCatalog,
  type RlsCatalogSnapshot,
} from "@workspace/db/rls-catalog-audit";
import {
  runApprovalLedgerRlsProbes,
  safeApprovalLedgerRlsProbeFailureCode,
} from "./approval-ledger-rls-probes";
import { diagnoseGitHubActionsApprovalLabTarget } from "../lib/approval-e2e-db-guard";
import { acquireGitHubActionsOidcToken } from "../lib/github-actions-oidc";
import { readCatalogSnapshot } from "./verify-rls-catalog";
import { apiTestFiles } from "./run-api-tests";
import { loadConnectorVaultKeyring } from "../lib/workspace-connector-vault";
import {
  approvalActionRefConstraintExpression,
  approvalActionRefMigrationValues,
} from "../lib/approval-action-ref-migration";

const { Client, Pool } = pg;
type RlsCatalogContractSources = Parameters<typeof parseRlsCatalogContract>[0] & {
  rlsContractSource: string;
};
const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../",
);
const forbiddenEnvironmentNames = new Set([
  "DATABASE_URL",
  "APP_RUNTIME_DATABASE_URL",
  "APP_RUNTIME_DB_PASSWORD",
]);

type Stage =
  | "preflight"
  | "postgres_init"
  | "postgres_start"
  | "instance_identity"
  | "create_database"
  | "role_hardening"
  | "drizzle_push"
  | "post_schema_audit"
  | "apply_rls"
  | "runtime_login_configuration"
  | "runtime_role_verification"
  | "runtime_login_connection"
  | "final_audit"
  | "versioned_migration_audit"
  | "api_unit_tests"
  | "development_read_only_catalog_audit"
  | "approval_ledger_rls_probes"
  | "demo_member_seed_tests"
  | "approval_e2e"
  | "mcp_promptfoo_redteam";

type SafeReport = {
  version: 1;
  stage: "post-schema" | "final";
  status: "passed" | "failed";
  commitSha: string | null;
  sourceSha256: Record<string, string>;
  counts?: {
    tables: number;
    columns: number;
    indexes: number;
    constraints: number;
    policies: number;
    roles: number;
  };
  violationCodes?: string[];
  identityVerified?: boolean;
  runtimeLoginAuthenticated?: boolean;
  developmentReadOnlyCatalogAuditPassed?: boolean;
  approvalLedgerRlsProbesPassed?: boolean;
  approvalLedgerRlsProbeCount?: number;
  approvalLedgerRlsProbeFailureCode?: string;
  approvalE2eSummary?: NodeTestSummary;
  approvalE2eFailures?: SafeNodeTestFailure[];
  approvalE2eFailureLocations?: string[];
  approvalE2eFailureErrorName?: string;
  approvalE2eFailureErrorCode?: string;
  approvalE2eFailureType?: string;
  approvalE2ePassed?: boolean;
  targetedConnectorCredentialE2e?: boolean;
  mcpPromptfooRedteamPassed?: boolean;
  mcpPromptfooRedteamSummary?: {
    attacks: number;
    blocked: number;
    idempotentReplays: number;
    failed: number;
  };
  versionedMigrationAudit?: VersionedMigrationAuditReport;
  failureOutput?: SafeChildOutput;
  failureStage?: Stage;
  apiUnitTestFailures?: SafeNodeTestFailure[];
};

type CatalogCounts = {
  tables: number;
  columns: number;
  indexes: number;
  constraints: number;
  policies: number;
  roles: number;
};

type VersionedMigrationAuditReport = {
  status: "running" | "passed" | "failed";
  baselineSourceCommit: string;
  baselineStrategy:
    | "clone_drizzle_catalog_remove_new_tables_and_restore_legacy_contract";
  baselineExpected: CatalogCounts;
  baselineActual?: CatalogCounts;
  baselineMatchesDrizzleProjection?: boolean;
  baselineMatchesExpectedLegacyProjection?: boolean;
  baselineLegacyActionRefConstraintVerified?: boolean;
  baselineExpectedLegacyDifferencesOnly?: boolean;
  drizzleCatalog?: CatalogCounts;
  migratedCatalog?: CatalogCounts;
  migrationsApplied: string[];
  migration0003Idempotent?: boolean;
  migration0004Idempotent?: boolean;
  migration0005Idempotent?: boolean;
  migration0006LegacyConstraintReplaced?: boolean;
  migration0006Postcondition?: {
    oidChanged: boolean;
    isLegacy: boolean;
    isCurrent: boolean;
    referencesInPgGetExprOrder: string[];
  };
  migration0006Idempotent?: boolean;
  migration0006UnexpectedConstraintRejected?: boolean;
  migration0007Idempotent?: boolean;
  migration0008LegacyStateReplaced?: boolean;
  migration0008Idempotent?: boolean;
  inventoryMatchesDrizzle?: {
    tables: boolean;
    columns: boolean;
    indexes: boolean;
    constraints: boolean;
    policies: boolean;
    roles: boolean;
    privilegeMatrix: boolean;
  };
  violationCodes: string[];
};

type VersionedMigrationDatabaseConnection = {
  host: string;
  port: number;
  user: string;
  password?: string;
};

type NodeTestSummary = {
  tests: number;
  pass: number;
  fail: number;
  cancelled: number;
  skipped: number;
};

export type SafeNodeTestPrimitive = string | number | boolean | null;

export type SafeNodeTestFailure = {
  subtest: string;
  errorCode?: string;
  errorName?: string;
  failureType?: string;
  message?: string;
  expected?: SafeNodeTestPrimitive;
  received?: SafeNodeTestPrimitive;
  location?: string;
};

export type SafeChildOutput = {
  stage: Stage;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
  truncated: boolean;
  captureError?: "child_start_failed" | "child_timeout" | "child_output_limit";
};

const allowedChildEnvironmentKeys = ["PATH", "HOME", "LANG", "LC_ALL"] as const;
const MAX_CAPTURED_TEST_OUTPUT_BYTES = 256 * 1024;
const MAX_SAFE_CHILD_OUTPUT_CHARACTERS = 12_000;

let latestFailureOutput: SafeChildOutput | undefined;

function redactChildOutput(value: string): {
  text: string;
  truncated: boolean;
} {
  let text = value
    .replace(/\u001b\[[0-9;]*m/g, "")
    .replace(
      /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi,
      "[redacted private key]",
    )
    .replace(
      /\b(?:postgres(?:ql)?|https?):\/\/[^\s"'<>]+/gi,
      "[redacted URL]",
    )
    .replace(
      /\bWORKSPACE_CONNECTOR_KEYRING_JSON\b["']?\s*[:=]\s*["']?\{[^}]*\}/gi,
      "WORKSPACE_CONNECTOR_KEYRING_JSON=[redacted]",
    )
    .replace(
      /\b(?:DATABASE_URL|APP_RUNTIME_DATABASE_URL|APP_RUNTIME_DB_PASSWORD|APPROVAL_LEDGER_ED25519_PRIVATE_KEY|WORKSPACE_CONNECTOR_KEYRING_JSON|SESSION_SECRET|CLERK_SECRET_KEY)\b["']?\s*[:=]\s*["']?[^,\s"'{}]+/gi,
      "[redacted environment value]",
    )
    .replace(/\bBearer\s+\S+/gi, "Bearer [redacted]")
    .replace(/\bgnx_agent_v1_[A-Za-z0-9_-]{20,}\b/g, "[redacted agent credential]")
    .replace(
      /\b(?:token|secret|password|credential|authorization)\s*[:=]\s*[^\s,;'"{}]+/gi,
      "[redacted credential]",
    )
    .replace(
      /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b|\[[0-9a-f:]+\](?::\d{1,5})?\b/gi,
      "[redacted address]",
    )
    .replace(
      /\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?:\:\d{1,5})?\b/gi,
      (candidate) =>
        /\.(?:[cm]?[jt]sx?|json|sql|md|ya?ml)(?::\d+)?$/i.test(candidate)
          ? candidate
          : "[redacted host]",
    )
    .replace(/\b[A-Za-z0-9_+/=-]{40,}\b/g, "[redacted long value]")
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, "[redacted identifier]")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ");
  const truncated = text.length > MAX_SAFE_CHILD_OUTPUT_CHARACTERS;
  if (truncated) {
    const marker = "\n[...middle output omitted...]\n";
    const retainedCharacters = MAX_SAFE_CHILD_OUTPUT_CHARACTERS - marker.length;
    const headCharacters = Math.ceil(retainedCharacters / 2);
    const tailCharacters = Math.floor(retainedCharacters / 2);
    text = `${text.slice(0, headCharacters)}${marker}${text.slice(-tailCharacters)}`;
  }
  return { text, truncated };
}

export function sanitizeChildOutputForReport(input: {
  stage: Stage;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
}): SafeChildOutput {
  const stdout = redactChildOutput(input.stdout);
  const stderr = redactChildOutput(input.stderr);
  return {
    stage: input.stage,
    stdout: stdout.text,
    stderr: stderr.text,
    exitCode: input.exitCode,
    signal: input.signal,
    truncated: stdout.truncated || stderr.truncated,
  };
}

function recordCaptureError(
  stage: Stage,
  captureError: NonNullable<SafeChildOutput["captureError"]>,
  stdout: readonly Buffer[],
  stderr: readonly Buffer[],
  truncated = false,
): void {
  const sanitized = sanitizeChildOutputForReport({
    stage,
    stdout: Buffer.concat(stdout).toString("utf8"),
    stderr: Buffer.concat(stderr).toString("utf8"),
    exitCode: null,
    signal: null,
  });
  latestFailureOutput = {
    ...sanitized,
    truncated: sanitized.truncated || truncated,
    captureError,
  };
}

function safeChildEnvironment(home: string): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const key of allowedChildEnvironmentKeys) {
    const value = process.env[key];
    if (value) environment[key] = value;
  }
  environment.HOME = home;
  environment.LANG = "C";
  environment.LC_ALL = "C";
  return environment;
}

function assertCleanParentEnvironment(): void {
  const keys = Object.keys(process.env);
  if (
    keys.some(
      (key) =>
        forbiddenEnvironmentNames.has(key) ||
        key.startsWith("PG") ||
        key.startsWith("GITHUB_"),
    ) ||
    keys.includes("CI") ||
    process.env.REPLIT_DEPLOYMENT === "1"
  ) {
    throw new Error("unsafe_parent_environment");
  }
}

function run(
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  stage: Stage,
  timeoutMs = 180_000,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let outputTruncated = false;
    const capture = (
      target: Buffer[],
      chunk: Buffer,
      stream: "stdout" | "stderr",
    ) => {
      const currentBytes = stream === "stdout" ? stdoutBytes : stderrBytes;
      const combined = Buffer.concat([...target, chunk]);
      if (combined.length > MAX_CAPTURED_TEST_OUTPUT_BYTES) {
        outputTruncated = true;
        const tail = combined.subarray(
          combined.length - MAX_CAPTURED_TEST_OUTPUT_BYTES,
        );
        target.splice(0, target.length, tail);
        if (stream === "stdout") stdoutBytes = tail.length;
        else stderrBytes = tail.length;
      } else {
        target.push(chunk);
        if (stream === "stdout") stdoutBytes = currentBytes + chunk.length;
        else stderrBytes = currentBytes + chunk.length;
      }
    };
    child.stdout.on("data", (chunk: Buffer) => capture(stdout, chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => capture(stderr, chunk, "stderr"));
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 3000).unref();
      recordCaptureError(stage, "child_timeout", stdout, stderr, outputTruncated);
      reject(new Error(`child_timeout:${stage}`));
    }, timeoutMs);
    child.once("error", () => {
      clearTimeout(timeout);
      recordCaptureError(stage, "child_start_failed", stdout, stderr, outputTruncated);
      reject(new Error(`child_start_failed:${stage}`));
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      if (code === 0 && signal === null) {
        resolve();
      } else {
        const sanitized = sanitizeChildOutputForReport({
          stage,
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
          exitCode: code,
          signal,
        });
        latestFailureOutput = {
          ...sanitized,
          truncated: sanitized.truncated || outputTruncated,
        };
        reject(new Error(`child_failed:${stage}`));
      }
    });
  });
}

function runAndCapture(
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  stage: Stage,
  timeoutMs = 240_000,
): Promise<{
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let capturedBytes = 0;
    let settled = false;
    const finishWithError = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      const captureError = error.message.startsWith("child_timeout:")
        ? "child_timeout"
        : error.message.startsWith("child_output_limit:")
          ? "child_output_limit"
          : "child_start_failed";
      recordCaptureError(stage, captureError, stdout, stderr);
      reject(error);
    };
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 3000).unref();
      finishWithError(new Error(`child_timeout:${stage}`));
    }, timeoutMs);
    const capture = (target: Buffer[], chunk: Buffer) => {
      if (settled) return;
      if (capturedBytes + chunk.length > MAX_CAPTURED_TEST_OUTPUT_BYTES) {
        child.kill("SIGTERM");
        recordCaptureError(stage, "child_output_limit", stdout, stderr, true);
        finishWithError(new Error(`child_output_limit:${stage}`));
        return;
      }
      target.push(chunk);
      capturedBytes += chunk.length;
    };

    child.stdout.on("data", (chunk: Buffer) => capture(stdout, chunk));
    child.stderr.on("data", (chunk: Buffer) => capture(stderr, chunk));
    child.once("error", () =>
      finishWithError(new Error(`child_start_failed:${stage}`)),
    );
    child.once("exit", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (code !== 0 || signal !== null) {
        latestFailureOutput = sanitizeChildOutputForReport({
          stage,
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
          exitCode: code,
          signal,
        });
      }
      resolve({
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        exitCode: code,
        signal,
      });
    });
  });
}

function parseNodeTestSummary(output: string): NodeTestSummary {
  const summary: Partial<NodeTestSummary> = {};
  for (const match of output.matchAll(
    /^# (tests|pass|fail|cancelled|skipped) (\d+)$/gm,
  )) {
    const key = match[1] as keyof NodeTestSummary;
    if (summary[key] !== undefined) {
      throw new Error("approval_e2e_summary_duplicate");
    }
    summary[key] = Number(match[2]);
  }
  if (
    summary.tests === undefined ||
    summary.pass === undefined ||
    summary.fail === undefined ||
    summary.cancelled === undefined ||
    summary.skipped === undefined ||
    summary.tests !==
      summary.pass + summary.fail + summary.cancelled + summary.skipped
  ) {
    throw new Error("approval_e2e_summary_invalid");
  }
  return summary as NodeTestSummary;
}

const safeNodeTestErrorCodes = new Set([
  "ERR_ASSERTION",
  "ERR_TEST_FAILURE",
  "ERR_MODULE_NOT_FOUND",
  "ERR_PACKAGE_PATH_NOT_EXPORTED",
  "ERR_INVALID_ARG_TYPE",
  "ERR_STREAM_PREMATURE_CLOSE",
  "23503",
  "23505",
  "42501",
  "42703",
  "42P01",
  "28P01",
]);
const safeNodeTestErrorNames = new Set([
  "AssertionError",
  "Error",
  "TypeError",
  "RangeError",
  "ReferenceError",
  "SyntaxError",
  "TimeoutError",
]);
const safeNodeTestFailureTypes = new Set([
  "testCodeFailure",
  "testTimeoutFailure",
  "hookFailed",
  "subtestsFailed",
]);
const sensitiveDiagnosticPattern =
  /(?:postgres(?:ql)?:\/\/|https?:\/\/|\b(?:bearer|token|secret|password|credential|authorization)\b|-----BEGIN [^-]*PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|\b(?:localhost|127(?:\.\d{1,3}){3}|::1)(?::\d{1,5})?\b|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d{1,5})?\b|\b[A-Za-z0-9_+/=-]{32,}\b|\b[0-9a-f]{8}-[0-9a-f-]{27,}\b)/i;

function tapField(block: string, key: string): string | undefined {
  const lines = block.split(/\r?\n/);
  const index = lines.findIndex((line) =>
    new RegExp(`^ {2}${key}:`).test(line)
  );
  if (index < 0) return undefined;
  const match = lines[index]?.match(/^ {2}[A-Za-z][A-Za-z0-9_-]*:\s*(.*)$/);
  if (!match) return undefined;
  const scalar = match[1] ?? "";
  if (/^[|>][+-]?$/.test(scalar.trim())) {
    const content: string[] = [];
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const line = lines[cursor] ?? "";
      if (/^ {2}[A-Za-z][A-Za-z0-9_-]*:/.test(line) || /^ {2}\.\.\.$/.test(line)) {
        break;
      }
      if (line.trim()) content.push(line.replace(/^ {4}/, ""));
    }
    return content.join("\n");
  }
  const value = scalar.trim();
  if (value.startsWith("'") && value.endsWith("'")) {
    return value.slice(1, -1).replaceAll("''", "'");
  }
  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      const decoded: unknown = JSON.parse(value);
      return typeof decoded === "string" ? decoded : undefined;
    } catch {
      return undefined;
    }
  }
  return value || undefined;
}

function safeFailureMessage(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const firstLine = value
    .replace(/\u001b\[[0-9;]*m/g, "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean);
  if (!firstLine) return undefined;
  const message = firstLine
    .replace(/^AssertionError(?:\s+\[[A-Z0-9_]+\])?:\s*/i, "")
    .replace(
      /(?:postgres(?:ql)?:\/\/|https?:\/\/)\S+|\bBearer\s+\S+|-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----/gi,
      "[redacted]",
    )
    .replace(
      /\b(?:token|secret|password|credential|authorization|database_url)\s*[:=]\s*[^\s,;]+/gi,
      "[redacted]",
    )
    .replace(
      /\b(?:localhost|127(?:\.\d{1,3}){3}|::1)(?::\d{1,5})?\b|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d{1,5})?\b/gi,
      "[redacted]",
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|\b[A-Za-z0-9_+/=-]{32,}\b|\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi,
      "[redacted]",
    )
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim();
  if (!message || /[{}]/.test(message)) return undefined;
  return message.slice(0, 300);
}

function safeTapPrimitive(value: string | undefined): SafeNodeTestPrimitive | undefined {
  if (value === undefined) return undefined;
  if (value === "null" || value === "~") return null;
  if (value === "true") return true;
  if (value === "false") return false;
  if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(value)) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : undefined;
  }
  let stringValue = value;
  if (value.startsWith("'") && value.endsWith("'")) {
    stringValue = value.slice(1, -1).replaceAll("''", "'");
  } else if (value.startsWith('"') && value.endsWith('"')) {
    try {
      const decoded: unknown = JSON.parse(value);
      if (typeof decoded !== "string") return undefined;
      stringValue = decoded;
    } catch {
      return undefined;
    }
  }
  if (
    stringValue.length === 0 ||
    stringValue.length > 120 ||
    /[\u0000-\u001f\u007f]/.test(stringValue) ||
    sensitiveDiagnosticPattern.test(stringValue) ||
    /[{}\[\]]/.test(stringValue)
  ) {
    return undefined;
  }
  return stringValue;
}

function importSourceLines(source: string): Set<number> {
  const result = new Set<number>();
  let inImport = false;
  for (const [index, line] of source.split(/\r?\n/).entries()) {
    if (!inImport && /^\s*import\b/.test(line)) inImport = true;
    if (!inImport) continue;
    result.add(index + 1);
    if (
      /\bfrom\s+["'][^"']+["']\s*;?\s*$/.test(line) ||
      /^\s*import\s*["'][^"']+["']\s*;?\s*$/.test(line) ||
      /;\s*$/.test(line)
    ) {
      inImport = false;
    }
  }
  return result;
}

function testSourceLocation(
  block: string,
  testFileName: string,
  source: string,
): string | undefined {
  const importLines = importSourceLines(source);
  const stack = tapField(block, "stack");
  if (!stack) return undefined;
  for (const line of stack.split(/\r?\n/)) {
    if (line.includes("/node_modules/")) continue;
    const frame = line.match(
      /(?:\(|\s)(?:file:\/\/)?([^()\s]+\.ts):(\d+):\d+\)?\s*$/,
    );
    if (!frame) continue;
    const fileName = path.basename(
      (frame[1] ?? "").replace(/^file:\/\/+/, ""),
    );
    const sourceLine = Number(frame[2]);
    if (
      fileName !== testFileName ||
      !Number.isSafeInteger(sourceLine) ||
      sourceLine < 1 ||
      importLines.has(sourceLine)
    ) {
      continue;
    }
    return `${testFileName}:${sourceLine}`;
  }
  return undefined;
}

export function parseSafeNodeTestFailures(
  output: string,
  testFileName: string,
  testSource: string,
): SafeNodeTestFailure[] {
  const failures = [...output.matchAll(/^([ \t]*)not ok \d+ - (.{1,240})$/gm)]
    .slice(0, 16);
  return failures.map((match, index) => {
    const start = match.index ?? 0;
    const indentation = match[1] ?? "";
    const nextFailure = failures.slice(index + 1).find((candidate) =>
      (candidate[1] ?? "").length <= indentation.length
    )?.index;
    const summaryOffset = output.slice(start).search(/^[ \t]*# tests \d+$/m);
    const end = nextFailure ??
      (summaryOffset >= 0 ? start + summaryOffset : output.length);
    const block = output
      .slice(start, end)
      .split(/\r?\n/)
      .map((line) => line.startsWith(indentation)
        ? line.slice(indentation.length)
        : line)
      .join("\n");
    const label = (match[2] ?? "").trim();
    const subtest = /^[A-Za-z0-9][A-Za-z0-9 .:_/-]{0,159}$/.test(label)
      ? label
      : "non_allowlisted_subtest";
    const code = tapField(block, "code");
    const name = tapField(block, "name");
    const failureType = tapField(block, "failureType");
    const message = safeFailureMessage(tapField(block, "error"));
    const expected = safeTapPrimitive(tapField(block, "expected"));
    const received = safeTapPrimitive(tapField(block, "actual"));
    const location = testSourceLocation(block, testFileName, testSource);
    return {
      subtest,
      ...(code && safeNodeTestErrorCodes.has(code) ? { errorCode: code } : {}),
      ...(name && safeNodeTestErrorNames.has(name) ? { errorName: name } : {}),
      ...(failureType && safeNodeTestFailureTypes.has(failureType)
        ? { failureType }
        : {}),
      ...(message ? { message } : {}),
      ...(expected !== undefined ? { expected } : {}),
      ...(received !== undefined ? { received } : {}),
      ...(location ? { location } : {}),
    };
  });
}

async function parseApiUnitTestFailures(
  output: string,
): Promise<SafeNodeTestFailure[]> {
  const apiServerRoot = path.join(repoRoot, "artifacts/api-server");
  const parsedBySource = await Promise.all(
    apiTestFiles.map(async (fileName) => {
      const source = await readFile(path.resolve(apiServerRoot, fileName), "utf8");
      return parseSafeNodeTestFailures(output, path.basename(fileName), source);
    }),
  );
  const failures = parsedBySource[0] ?? [];
  return failures.map((failure, index) => {
    const locatedFailure = parsedBySource
      .map((items) => items[index])
      .find((item) => item?.location);
    return {
      ...failure,
      ...(locatedFailure?.location ? { location: locatedFailure.location } : {}),
    };
  });
}

function binaryPath(name: string): string {
  const pathValue = process.env.PATH ?? "";
  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) continue;
    const candidate = path.join(directory, name);
    try {
      const details = statSync(candidate);
      if (details.isFile() && (details.mode & 0o111) !== 0) return candidate;
    } catch {
      // Continue through PATH without printing or retaining candidate paths.
    }
  }
  throw new Error("required_local_postgres_binary_missing");
}

async function runAndCheck(
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  stage: Stage,
  timeoutMs = 180_000,
): Promise<void> {
  await run(command, args, cwd, env, stage, timeoutMs);
}

async function loadContractSources(): Promise<RlsCatalogContractSources> {
  const schemaDirectory = path.join(repoRoot, "lib/db/src/schema");
  const schemaFiles = (await readdir(schemaDirectory))
    .filter((name) => name.endsWith(".ts"))
    .sort();
  const [schemaContents, rolesSource, bootstrapSource, policiesSql, contractSource] =
    await Promise.all([
      Promise.all(
        schemaFiles.map(async (name) => ({
          path: name,
          content: await readFile(path.join(schemaDirectory, name), "utf8"),
        })),
      ),
      readFile(path.join(schemaDirectory, "roles.ts"), "utf8"),
      readFile(
        path.join(repoRoot, "lib/db/scripts/bootstrap-runtime-role.mjs"),
        "utf8",
      ),
      readFile(path.join(repoRoot, "lib/db/sql/rls-policies.sql"), "utf8"),
      readFile(path.join(repoRoot, "lib/db/src/rls-catalog-contract.ts"), "utf8"),
    ]);
  return {
    schemaFiles: schemaContents,
    rolesSource,
    bootstrapSource,
    policiesSql,
    rlsContractSource: contractSource,
  };
}

function sourceHashes(sources: RlsCatalogContractSources): Record<string, string> {
  return {
    schema: createHash("sha256")
      .update(sources.schemaFiles.map((source) => source.content).join("\n"))
      .digest("hex"),
    policies: createHash("sha256").update(sources.policiesSql).digest("hex"),
    roles: createHash("sha256").update(sources.rolesSource).digest("hex"),
    bootstrap: createHash("sha256").update(sources.bootstrapSource).digest("hex"),
    contract: createHash("sha256")
      .update(sources.rlsContractSource)
      .digest("hex"),
  };
}

async function writeSafeReport(
  directory: string,
  report: SafeReport,
): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const fileName = report.stage === "post-schema"
    ? "postgres-lab-post-schema.json"
    : "postgres-lab-final.json";
  const filePath = path.join(directory, fileName);
  await writeFile(filePath, `${JSON.stringify(report, null, 2)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
}

const legacyRlsTableNames = [
  "workspaces",
  "workspace_memberships",
  "assets",
  "workspace_monthly_usage",
  "workspace_audit_events",
  "workspace_integrations",
  "provider_connections",
  "connector_oauth_states",
  "connector_jobs",
  "ai_assessment_jobs",
  "host_boundary_attestation_challenges",
  "ai_assessment_approval_requests",
  "workspace_approval_ledger",
] as const;

const versionedMigrationTableNames = [
  "workspace_action_rule_heads",
  "workspace_action_rule_versions",
  "workspace_agents",
  "workspace_connector_credentials",
  "workspace_connector_executions",
  "workspace_approval_receipts",
] as const;

const legacyCatalogCounts: CatalogCounts = {
  tables: 13,
  columns: 149,
  indexes: 37,
  constraints: 54,
  policies: 36,
  roles: 3,
};

const fullCatalogCounts: CatalogCounts = {
  tables: 19,
  columns: 205,
  indexes: 51,
  constraints: 99,
  policies: 53,
  roles: 3,
};

const baselineSourceCommit =
  "1aeb2d5b30f9bf19f35a012c5ced75d6fb310bac";

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, stableValue(record[key])]),
    );
  }
  return value;
}

function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value)) ?? "undefined";
}

function sameValue(left: unknown, right: unknown): boolean {
  return stableJson(left) === stableJson(right);
}

function catalogCounts(
  phase: RlsCatalogPhaseSnapshot,
): CatalogCounts {
  return {
    tables: phase.tables.length,
    columns: phase.columns.length,
    indexes: phase.indexes.length,
    constraints: phase.constraints.length,
    policies: phase.policies.length,
    roles: phase.roles.length,
  };
}

function canonicalIndexes(
  indexes: RlsCatalogPhaseSnapshot["indexes"],
): RlsCatalogPhaseSnapshot["indexes"] {
  return indexes.map((index) => ({
    ...index,
    where: canonicalizeRlsExpression(index.where, index.tableName),
  }));
}

function canonicalConstraints(
  constraints: RlsCatalogPhaseSnapshot["constraints"],
): RlsCatalogPhaseSnapshot["constraints"] {
  return constraints.map((constraint) => ({
    ...constraint,
    expression: canonicalizeRlsExpression(
      constraint.expression,
      constraint.tableName,
    ),
  }));
}

function canonicalPolicies(
  policies: RlsCatalogPhaseSnapshot["policies"],
): RlsCatalogPhaseSnapshot["policies"] {
  return policies.map((policy) => ({
    ...policy,
    qual: canonicalizeRlsExpression(policy.qual, policy.tableName),
    withCheck: canonicalizeRlsExpression(
      policy.withCheck,
      policy.tableName,
    ),
  }));
}

function phaseSnapshotForTables(
  snapshot: RlsCatalogPhaseSnapshot,
  tableNames: readonly string[],
): RlsCatalogPhaseSnapshot {
  const allowed = new Set(tableNames);
  return {
    ...snapshot,
    tables: snapshot.tables.filter((table) => allowed.has(table.tableName)),
    columns: snapshot.columns.filter((column) =>
      allowed.has(column.tableName)
    ),
    indexes: snapshot.indexes.filter((index) =>
      allowed.has(index.tableName)
    ),
    constraints: snapshot.constraints.filter((constraint) =>
      allowed.has(constraint.tableName)
    ),
    policies: snapshot.policies.filter((policy) =>
      allowed.has(policy.tableName)
    ),
  };
}

function grantSnapshotForTables(
  snapshot: RlsCatalogSnapshot,
  tableNames: readonly string[],
): RlsCatalogSnapshot {
  const allowed = new Set(tableNames);
  return {
    ...snapshot,
    tables: snapshot.tables.filter((table) => allowed.has(table.tableName)),
    policies: snapshot.policies.filter((policy) =>
      allowed.has(policy.tableName)
    ),
    tablePrivileges: snapshot.tablePrivileges.filter((privilege) =>
      allowed.has(privilege.tableName)
    ),
    updateColumns: snapshot.updateColumns.filter((column) =>
      allowed.has(column.tableName)
    ),
    insertColumns: snapshot.insertColumns.filter((column) =>
      allowed.has(column.tableName)
    ),
    tableColumns: snapshot.tableColumns.filter((table) =>
      allowed.has(table.tableName)
    ),
  };
}

function legacyAuditGrantProjection(
  snapshot: RlsCatalogSnapshot,
): RlsCatalogSnapshot {
  return {
    ...snapshot,
    tablePrivileges: snapshot.tablePrivileges.map((privilege) =>
      privilege.roleName === "app_runtime" &&
        privilege.tableName === "workspace_audit_events" &&
        (privilege.privilege === "UPDATE" ||
          privilege.privilege === "DELETE")
        ? { ...privilege, granted: true }
        : privilege
    ),
    updateColumns: snapshot.updateColumns.map((column) =>
      column.roleName === "app_runtime" &&
        column.tableName === "workspace_audit_events"
        ? { ...column, granted: true }
        : column
    ),
  };
}

function compareCatalogInventories(
  leftPhase: RlsCatalogPhaseSnapshot,
  leftGrants: RlsCatalogSnapshot,
  rightPhase: RlsCatalogPhaseSnapshot,
  rightGrants: RlsCatalogSnapshot,
): NonNullable<VersionedMigrationAuditReport["inventoryMatchesDrizzle"]> {
  return {
    tables: sameValue(leftPhase.tables, rightPhase.tables),
    columns: sameValue(
      {
        phase: leftPhase.columns,
        grantInventory: leftGrants.tableColumns,
      },
      {
        phase: rightPhase.columns,
        grantInventory: rightGrants.tableColumns,
      },
    ),
    indexes: sameValue(
      canonicalIndexes(leftPhase.indexes),
      canonicalIndexes(rightPhase.indexes),
    ),
    constraints: sameValue(
      canonicalConstraints(leftPhase.constraints),
      canonicalConstraints(rightPhase.constraints),
    ),
    policies: sameValue(
      canonicalPolicies(leftPhase.policies),
      canonicalPolicies(rightPhase.policies),
    ),
    roles: sameValue(
      {
        roles: leftPhase.roles,
        memberships: leftPhase.memberships,
        pgHasRole: leftGrants.pgHasRole,
      },
      {
        roles: rightPhase.roles,
        memberships: rightPhase.memberships,
        pgHasRole: rightGrants.pgHasRole,
      },
    ),
    privilegeMatrix: sameValue(
      {
        tablePrivileges: leftGrants.tablePrivileges,
        updateColumns: leftGrants.updateColumns,
        insertColumns: leftGrants.insertColumns,
      },
      {
        tablePrivileges: rightGrants.tablePrivileges,
        updateColumns: rightGrants.updateColumns,
        insertColumns: rightGrants.insertColumns,
      },
    ),
  };
}

function safeSqlState(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) {
    return undefined;
  }
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" && /^[0-9A-Z]{5}$/.test(code)
    ? code
    : undefined;
}

async function applyVersionedMigration(
  client: InstanceType<typeof Client>,
  filename: string,
): Promise<void> {
  const sqlText = await readFile(
    path.join(repoRoot, "lib/db/migrations", filename),
    "utf8",
  );
  const lines = sqlText.split(/\r?\n/);
  let firstExecutableLine = 0;
  while (firstExecutableLine < lines.length) {
    const line = lines[firstExecutableLine]?.trim() ?? "";
    if (!line || line.startsWith("--")) {
      firstExecutableLine += 1;
      continue;
    }
    break;
  }
  const firstExecutableSql = lines.slice(firstExecutableLine).join("\n");
  if (
    !/^\s*BEGIN\s*;/i.test(firstExecutableSql) ||
    !/COMMIT\s*;\s*$/i.test(sqlText) ||
    [...sqlText.matchAll(/\bBEGIN\s*;/gi)].length !== 1 ||
    [...sqlText.matchAll(/\bCOMMIT\s*;/gi)].length !== 1
  ) {
    throw new Error("versioned_migration_transaction_boundary_invalid");
  }
  try {
    await client.query(sqlText);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    const state = safeSqlState(error);
    throw new Error(
      state
        ? `versioned_migration_sql_failed:${state}`
        : "versioned_migration_sql_failed",
    );
  }
}

type ApprovalActionRefConstraintState = {
  oid: string;
  isLegacy: boolean;
  isCurrent: boolean;
  referencesInPgGetExprOrder: string[];
  mismatch: "constraint_shape" | "constraint_columns" | "constraint_definition" | null;
};

async function readApprovalActionRefConstraintState(
  client: InstanceType<typeof Client>,
): Promise<ApprovalActionRefConstraintState | null> {
  const result = await client.query(
    `SELECT
       constraint_row.oid::text AS oid,
       constraint_row.contype,
       constraint_row.convalidated,
       constraint_row.connoinherit,
       constraint_row.condeferrable,
       constraint_row.condeferred,
       ARRAY(
         SELECT attribute.attname::text
           FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key(attnum, ordinality)
           JOIN pg_attribute AS attribute
             ON attribute.attrelid = constraint_row.conrelid
            AND attribute.attnum = key.attnum
          ORDER BY key.ordinality
       ) AS column_names,
       pg_get_expr(constraint_row.conbin, constraint_row.conrelid) AS expression
     FROM pg_constraint AS constraint_row
    WHERE constraint_row.conrelid =
          'public.ai_assessment_approval_requests'::regclass
      AND constraint_row.conname =
          'ai_assessment_approval_action_ref_check'`,
  );
  const row = result.rows[0] as {
    oid?: unknown;
    contype?: unknown;
    convalidated?: unknown;
    connoinherit?: unknown;
    condeferrable?: unknown;
    condeferred?: unknown;
    column_names?: unknown;
    expression?: unknown;
  } | undefined;
  if (
    !row ||
    typeof row.oid !== "string" ||
    typeof row.expression !== "string"
  ) {
    return null;
  }
  const referencesInPgGetExprOrder = [
    ...row.expression.matchAll(/'((?:''|[^'])*)'/g),
  ].map((match) => match[1]!.replaceAll("''", "'"));
  if (
    row.contype !== "c" ||
    row.convalidated !== true ||
    row.connoinherit !== false ||
    row.condeferrable !== false ||
    row.condeferred !== false
  ) {
    return {
      oid: row.oid,
      isLegacy: false,
      isCurrent: false,
      referencesInPgGetExprOrder,
      mismatch: "constraint_shape",
    };
  }
  if (
    !Array.isArray(row.column_names) ||
    !sameValue(
      [...row.column_names].sort(),
      ["action_sha256", "synthetic_action_ref"],
    )
  ) {
    return {
      oid: row.oid,
      isLegacy: false,
      isCurrent: false,
      referencesInPgGetExprOrder,
      mismatch: "constraint_columns",
    };
  }
  const refs = approvalActionRefMigrationValues();
  const actualExpression = canonicalizeRlsExpression(
    row.expression,
    "ai_assessment_approval_requests",
  );
  const matches = (actionRefs: readonly string[]) =>
    actualExpression === canonicalizeRlsExpression(
      approvalActionRefConstraintExpression(actionRefs),
      "ai_assessment_approval_requests",
    );
  return {
    oid: row.oid,
    isLegacy: matches(refs.legacy),
    isCurrent: matches(refs.current),
    referencesInPgGetExprOrder,
    mismatch: matches(refs.legacy) || matches(refs.current)
      ? null
      : "constraint_definition",
  };
}

async function reconstructLegacyApprovalActionRefConstraint(
  client: InstanceType<typeof Client>,
): Promise<boolean> {
  const values = approvalActionRefMigrationValues();
  const before = await readApprovalActionRefConstraintState(client);
  if (!before?.isCurrent) {
    throw new Error(
      `versioned_migration_source_action_ref_${before?.mismatch ?? "constraint_missing"}`,
    );
  }
  const legacyExpression = approvalActionRefConstraintExpression(values.legacy);
  try {
    await client.query("BEGIN");
    await client.query(
      `ALTER TABLE public.ai_assessment_approval_requests
       DROP CONSTRAINT ai_assessment_approval_action_ref_check,
       ADD CONSTRAINT ai_assessment_approval_action_ref_check
       CHECK (${legacyExpression})`,
    );
    await client.query("COMMIT");
  } catch {
    await client.query("ROLLBACK").catch(() => undefined);
    throw new Error("versioned_migration_legacy_constraint_setup_failed");
  }
  const after = await readApprovalActionRefConstraintState(client);
  return after?.isLegacy === true;
}

async function reconstructLegacyAuditContract(
  client: InstanceType<typeof Client>,
): Promise<void> {
  await client.query("BEGIN");
  try {
    await client.query(`
      ALTER POLICY workspace_memberships_select_scoped
        ON public.workspace_memberships
        USING (
          user_id = NULLIF(current_setting('app.user_id', true), '')
          OR workspace_id::text =
            NULLIF(current_setting('app.workspace_id', true), '')
        );
      GRANT UPDATE, DELETE
        ON TABLE public.workspace_audit_events TO app_runtime;
      DROP FUNCTION public.workspace_current_user_is_member(uuid);
    `);
    await client.query("COMMIT");
  } catch {
    await client.query("ROLLBACK").catch(() => undefined);
    throw new Error("versioned_migration_legacy_audit_state_restore_failed");
  }
}

async function workspaceMembershipHelperContractValid(
  client: InstanceType<typeof Client>,
): Promise<boolean> {
  const expectedSource =
    "SELECT EXISTS ( SELECT 1 FROM public.workspace_memberships AS membership WHERE membership.workspace_id = target_workspace_id AND membership.user_id = NULLIF(current_setting('app.user_id', true), '') )";
  const result = await client.query(
    `
      SELECT
        count(*)::int AS function_count,
        COALESCE(bool_and(
          lang.lanname = 'sql'
          AND helper.prorettype = 'boolean'::regtype
          AND pg_get_function_identity_arguments(helper.oid) =
            'target_workspace_id uuid'
          AND helper.prosecdef
          AND helper.provolatile = 's'
          AND (
            function_owner.oid = memberships_table.relowner
            OR function_owner.rolsuper
            OR function_owner.rolbypassrls
          )
          AND (function_owner.rolsuper OR function_owner.rolbypassrls)
          AND helper.proconfig @> ARRAY[
            'search_path=pg_catalog, public',
            'row_security=off'
          ]::text[]
          AND trim(regexp_replace(
            helper.prosrc,
            '[[:space:]]+',
            ' ',
            'g'
          )) = $1
          AND NOT EXISTS (
            SELECT 1
            FROM aclexplode(
              COALESCE(helper.proacl, acldefault('f', helper.proowner))
            ) AS function_acl
            WHERE function_acl.grantee = 0
              AND function_acl.privilege_type = 'EXECUTE'
          )
          AND has_function_privilege(
            'app_runtime',
            helper.oid,
            'EXECUTE'
          )
        ), false) AS contract_valid
      FROM pg_proc AS helper
      JOIN pg_namespace AS namespace ON namespace.oid = helper.pronamespace
      JOIN pg_language AS lang ON lang.oid = helper.prolang
      JOIN pg_roles AS function_owner ON function_owner.oid = helper.proowner
      JOIN pg_class AS memberships_table
        ON memberships_table.relname = 'workspace_memberships'
        AND memberships_table.relkind IN ('r', 'p')
      JOIN pg_namespace AS memberships_namespace
        ON memberships_namespace.oid = memberships_table.relnamespace
        AND memberships_namespace.nspname = 'public'
      WHERE namespace.nspname = 'public'
        AND helper.proname = 'workspace_current_user_is_member'
    `,
    [expectedSource],
  );
  return (
    Number(result.rows[0]?.function_count) === 1 &&
    result.rows[0]?.contract_valid === true
  );
}

async function restoreCurrentApprovalActionRefConstraint(
  client: InstanceType<typeof Client>,
): Promise<void> {
  const { current } = approvalActionRefMigrationValues();
  const currentExpression = approvalActionRefConstraintExpression(current);
  await client.query("BEGIN");
  try {
    await client.query(
      `ALTER TABLE public.ai_assessment_approval_requests
       DROP CONSTRAINT ai_assessment_approval_action_ref_check,
       ADD CONSTRAINT ai_assessment_approval_action_ref_check
       CHECK (${currentExpression})`,
    );
    await client.query("COMMIT");
  } catch {
    await client.query("ROLLBACK").catch(() => undefined);
    throw new Error("versioned_migration_current_constraint_restore_failed");
  }
  const restored = await readApprovalActionRefConstraintState(client);
  if (!restored?.isCurrent) {
    throw new Error("versioned_migration_current_constraint_restore_failed");
  }
}

async function verifyMigration0006RejectsUnexpectedConstraint(
  client: InstanceType<typeof Client>,
): Promise<boolean> {
  const { current } = approvalActionRefMigrationValues();
  const currentExpression = approvalActionRefConstraintExpression(current);
  await client.query("BEGIN");
  try {
    await client.query(
      `ALTER TABLE public.ai_assessment_approval_requests
       DROP CONSTRAINT ai_assessment_approval_action_ref_check,
       ADD CONSTRAINT ai_assessment_approval_action_ref_check
       CHECK ((${currentExpression}) AND action_sha256 <> repeat('0', 64))`,
    );
    await client.query("COMMIT");
  } catch {
    await client.query("ROLLBACK").catch(() => undefined);
    throw new Error("versioned_migration_unexpected_constraint_setup_failed");
  }
  let rejected = false;
  try {
    await applyVersionedMigration(
      client,
      "0006_align_approval_action_refs.sql",
    );
  } catch (error) {
    rejected = error instanceof Error &&
      error.message === "versioned_migration_sql_failed:23514";
  }
  await restoreCurrentApprovalActionRefConstraint(client);
  return rejected;
}

function safeVersionedMigrationFailureCode(error: unknown): string {
  if (!(error instanceof Error)) return "versioned_migration_audit_failed";
  const message = error.message;
  if (
    message === "versioned_migration_transaction_boundary_invalid" ||
    message === "versioned_migration_database_identity_mismatch" ||
    message === "versioned_migration_connection_identity_mismatch" ||
    message === "versioned_migration_source_database_mismatch" ||
    message === "versioned_migration_commit_sha_invalid" ||
    message === "versioned_migration_connection_configuration_invalid" ||
    message === "versioned_migration_baseline_source_mismatch" ||
    message === "versioned_migration_baseline_new_tables_not_empty" ||
    message === "versioned_migration_baseline_reconstruction_failed" ||
    message === "versioned_migration_baseline_mismatch" ||
    message === "versioned_migration_source_action_ref_constraint_missing" ||
    message === "versioned_migration_source_action_ref_constraint_shape" ||
    message === "versioned_migration_source_action_ref_constraint_columns" ||
    message === "versioned_migration_source_action_ref_constraint_definition" ||
    message === "versioned_migration_legacy_constraint_setup_failed" ||
    message === "versioned_migration_legacy_audit_state_restore_failed" ||
    message === "versioned_migration_legacy_action_ref_not_reproduced" ||
    message === "versioned_migration_action_ref_constraint_not_updated" ||
    message === "versioned_migration_0006_not_idempotent" ||
    message === "versioned_migration_0006_unexpected_constraint_accepted" ||
    message === "versioned_migration_unexpected_constraint_setup_failed" ||
    message === "versioned_migration_current_constraint_restore_failed" ||
    message === "versioned_migration_0008_legacy_state_not_reproduced" ||
    message === "versioned_migration_0008_legacy_state_not_replaced" ||
    message === "versioned_migration_0008_not_idempotent" ||
    message === "versioned_migration_catalog_mismatch"
  ) {
    return message;
  }
  const sqlState = message.match(/^versioned_migration_sql_failed:([0-9A-Z]{5})$/)?.[1];
  return sqlState
    ? `versioned_migration_sqlstate_${sqlState}`
    : "versioned_migration_audit_failed";
}

async function runVersionedMigrationAudit(input: {
  connection: VersionedMigrationDatabaseConnection;
  sourceDatabaseName: string;
  nonce: string;
  serverNonce?: string;
  tableNames: string[];
  roleNames: string[];
  contract: ReturnType<typeof parseRlsCatalogContract>;
  drizzlePhase: RlsCatalogPhaseSnapshot;
  drizzleGrants: RlsCatalogSnapshot;
  report: VersionedMigrationAuditReport;
}): Promise<void> {
  const {
    connection,
    sourceDatabaseName,
    nonce,
    serverNonce,
    tableNames,
    roleNames,
    contract,
    drizzlePhase,
    drizzleGrants,
    report,
  } = input;
  const suffix = randomBytes(12).toString("hex");
  const migrationDatabaseName = `guardian_migrations_${suffix}`;
  const admin = new Client({
    ...connection,
    database: "postgres",
    application_name: "guardian-nexus-versioned-migration-lab-admin",
    connectionTimeoutMillis: 5000,
  });
  await admin.connect();
  try {
    await admin.query(
      `CREATE DATABASE "${migrationDatabaseName}" TEMPLATE "${sourceDatabaseName}"`,
    );
    await admin.query(
      `COMMENT ON DATABASE "${migrationDatabaseName}" IS 'guardian-nexus-versioned-migrations:${nonce}'`,
    );
    const identity = await admin.query(
      `SELECT shobj_description(oid, 'pg_database') AS comment
         FROM pg_database
        WHERE datname = $1`,
      [migrationDatabaseName],
    );
    if (
      identity.rows.length !== 1 ||
      identity.rows[0]?.comment !==
        `guardian-nexus-versioned-migrations:${nonce}`
    ) {
      throw new Error("versioned_migration_database_identity_mismatch");
    }
  } finally {
    await admin.end().catch(() => undefined);
  }

  const migrationClient = new Client({
    ...connection,
    database: migrationDatabaseName,
    application_name: "guardian-nexus-versioned-migration-lab",
    connectionTimeoutMillis: 5000,
    statement_timeout: 15000,
  });
  const migrationPool = new Pool({
    ...connection,
    database: migrationDatabaseName,
    application_name: "guardian-nexus-versioned-migration-catalog",
    max: 5,
    connectionTimeoutMillis: 5000,
    statement_timeout: 15000,
  });
  await migrationClient.connect();
  try {
    const databaseIdentity = await migrationClient.query(
      `SELECT current_database() AS database_name,
              current_setting('guardian_nexus.lab_nonce', true) AS server_nonce,
              shobj_description(
                (SELECT oid FROM pg_database WHERE datname = current_database()),
                'pg_database'
              ) AS database_comment`,
    );
    if (
      databaseIdentity.rows.length !== 1 ||
      databaseIdentity.rows[0]?.database_name !== migrationDatabaseName ||
      databaseIdentity.rows[0]?.database_comment !==
        `guardian-nexus-versioned-migrations:${nonce}` ||
      (serverNonce !== undefined &&
        databaseIdentity.rows[0]?.server_nonce !== serverNonce)
    ) {
      throw new Error("versioned_migration_connection_identity_mismatch");
    }

    const currentTableSet = [...tableNames].sort();
    const legacyTableSet = [...legacyRlsTableNames].sort();
    const actualLegacyTableSet = tableNames
      .filter(
        (tableName) =>
          !versionedMigrationTableNames.includes(
            tableName as (typeof versionedMigrationTableNames)[number],
          ),
      )
      .sort();
    if (!sameValue(currentTableSet.length, 19) ||
      !sameValue(actualLegacyTableSet, legacyTableSet)) {
      throw new Error("versioned_migration_baseline_source_mismatch");
    }

    const newTableRows = await migrationClient.query(
      `SELECT
         (SELECT count(*) FROM public.workspace_action_rule_heads) +
         (SELECT count(*) FROM public.workspace_action_rule_versions) +
         (SELECT count(*) FROM public.workspace_agents) +
         (SELECT count(*) FROM public.workspace_connector_credentials) +
         (SELECT count(*) FROM public.workspace_connector_executions) +
         (SELECT count(*) FROM public.workspace_approval_receipts) AS row_count`,
    );
    if (Number(newTableRows.rows[0]?.row_count) !== 0) {
      throw new Error("versioned_migration_baseline_new_tables_not_empty");
    }

    await migrationClient.query("BEGIN");
    try {
      await migrationClient.query(
        `DROP TABLE public.workspace_approval_receipts;
         DROP TABLE public.workspace_action_rule_heads;
         DROP TABLE public.workspace_connector_executions;
         DROP TABLE public.workspace_connector_credentials;
         DROP TABLE public.workspace_agents;
         DROP TABLE public.workspace_action_rule_versions;`,
      );
      await migrationClient.query("COMMIT");
    } catch {
      await migrationClient.query("ROLLBACK").catch(() => undefined);
      throw new Error("versioned_migration_baseline_reconstruction_failed");
    }

    report.baselineLegacyActionRefConstraintVerified =
      await reconstructLegacyApprovalActionRefConstraint(migrationClient);
    await reconstructLegacyAuditContract(migrationClient);
    const baselinePhase = await readRlsCatalogPhaseSnapshot(
      migrationPool,
      [...legacyTableSet],
      roleNames,
    );
    const { snapshot: baselineGrantSnapshot } = await readCatalogSnapshot(
      migrationPool,
      [...legacyTableSet],
      roleNames,
    );
    report.baselineActual = catalogCounts(baselinePhase);
    const drizzleLegacyPhase = phaseSnapshotForTables(
      drizzlePhase,
      legacyTableSet,
    );
    const { legacy } = approvalActionRefMigrationValues();
    const legacyActionRefExpression =
      approvalActionRefConstraintExpression(legacy);
    const drizzleLegacyProjection: RlsCatalogPhaseSnapshot = {
      ...drizzleLegacyPhase,
      constraints: drizzleLegacyPhase.constraints.map((constraint) =>
        constraint.tableName === "ai_assessment_approval_requests" &&
          constraint.constraintName ===
            "ai_assessment_approval_action_ref_check"
          ? { ...constraint, expression: legacyActionRefExpression }
          : constraint
      ),
      policies: drizzleLegacyPhase.policies.map((policy) =>
        policy.tableName === "workspace_memberships" &&
          policy.policyName === "workspace_memberships_select_scoped"
          ? {
              ...policy,
              qual: `user_id = NULLIF(current_setting('app.user_id', true), '')
                OR workspace_id::text =
                  NULLIF(current_setting('app.workspace_id', true), '')`,
            }
          : policy
      ),
    };
    const drizzlePre0008Projection: RlsCatalogPhaseSnapshot = {
      ...drizzlePhase,
      policies: drizzlePhase.policies.map((policy) =>
        policy.tableName === "workspace_memberships" &&
          policy.policyName === "workspace_memberships_select_scoped"
          ? drizzleLegacyProjection.policies.find(
              (legacyPolicy) =>
                legacyPolicy.tableName === policy.tableName &&
                legacyPolicy.policyName === policy.policyName,
            )!
          : policy
      ),
    };
    const drizzleLegacyGrantProjection = legacyAuditGrantProjection(
      grantSnapshotForTables(drizzleGrants, legacyTableSet),
    );
    const drizzlePre0008GrantProjection =
      legacyAuditGrantProjection(drizzleGrants);
    const baselineDrizzleComparison = compareCatalogInventories(
      drizzleLegacyPhase,
      grantSnapshotForTables(drizzleGrants, legacyTableSet),
      baselinePhase,
      baselineGrantSnapshot,
    );
    const baselineLegacyComparison = compareCatalogInventories(
      drizzleLegacyProjection,
      drizzleLegacyGrantProjection,
      baselinePhase,
      baselineGrantSnapshot,
    );
    report.baselineMatchesDrizzleProjection = Object.values(
      baselineDrizzleComparison,
    ).every(Boolean);
    report.baselineMatchesExpectedLegacyProjection = Object.values(
      baselineLegacyComparison,
    ).every(Boolean);
    report.baselineExpectedLegacyDifferencesOnly =
      baselineDrizzleComparison.tables &&
      baselineDrizzleComparison.columns &&
      baselineDrizzleComparison.indexes &&
      !baselineDrizzleComparison.constraints &&
      !baselineDrizzleComparison.policies &&
      baselineDrizzleComparison.roles &&
      !baselineDrizzleComparison.privilegeMatrix &&
      report.baselineLegacyActionRefConstraintVerified === true;
    const baselineRlsValid = baselinePhase.tables.every(
      (table) => table.rlsEnabled && table.rlsForced,
    );
    if (
      !sameValue(report.baselineActual, report.baselineExpected) ||
      !baselineRlsValid ||
      !report.baselineMatchesExpectedLegacyProjection ||
      !report.baselineLegacyActionRefConstraintVerified ||
      !report.baselineExpectedLegacyDifferencesOnly
    ) {
      report.violationCodes.push("versioned_migration_baseline_mismatch");
      throw new Error("versioned_migration_baseline_mismatch");
    }

    const migrationFiles = [
      "0001_workspace_action_rules.sql",
      "0002_workspace_agents.sql",
      "0003_workspace_rule_version_unique_constraint.sql",
      "0004_align_rule_check_constraint_names.sql",
      "0005_workspace_connector_foundation.sql",
      "0006_align_approval_action_refs.sql",
      "0007_workspace_approval_receipts.sql",
      "0008_audit_append_only_membership_scope.sql",
    ];
    for (const filename of migrationFiles) {
      let legacyAuditStateMatches = false;
      const beforeActionRefMigration =
        filename === "0006_align_approval_action_refs.sql"
          ? await readApprovalActionRefConstraintState(migrationClient)
          : null;
      if (filename === "0008_audit_append_only_membership_scope.sql") {
        const beforePhase = await readRlsCatalogPhaseSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const beforeGrants = await readCatalogSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        legacyAuditStateMatches = Object.values(
          compareCatalogInventories(
            drizzlePre0008Projection,
            drizzlePre0008GrantProjection,
            beforePhase,
            beforeGrants.snapshot,
          ),
        ).every(Boolean);
        if (!legacyAuditStateMatches) {
          throw new Error("versioned_migration_0008_legacy_state_not_reproduced");
        }
      }
      if (
        filename === "0006_align_approval_action_refs.sql" &&
        !beforeActionRefMigration?.isLegacy
      ) {
        throw new Error("versioned_migration_legacy_action_ref_not_reproduced");
      }
      await applyVersionedMigration(migrationClient, filename);
      report.migrationsApplied.push(filename);
      if (filename === "0003_workspace_rule_version_unique_constraint.sql") {
        await applyVersionedMigration(migrationClient, filename);
        report.migration0003Idempotent = true;
      }
      if (filename === "0004_align_rule_check_constraint_names.sql") {
        await applyVersionedMigration(migrationClient, filename);
        report.migration0004Idempotent = true;
      }
      if (filename === "0005_workspace_connector_foundation.sql") {
        await applyVersionedMigration(migrationClient, filename);
        report.migration0005Idempotent = true;
      }
      if (filename === "0006_align_approval_action_refs.sql") {
        if (beforeActionRefMigration === null) {
          throw new Error("versioned_migration_legacy_action_ref_not_reproduced");
        }
        const afterMigration = await readApprovalActionRefConstraintState(
          migrationClient,
        );
        report.migration0006Postcondition = {
          oidChanged:
            afterMigration !== null &&
            afterMigration.oid !== beforeActionRefMigration.oid,
          isLegacy: afterMigration?.isLegacy ?? false,
          isCurrent: afterMigration?.isCurrent ?? false,
          referencesInPgGetExprOrder:
            afterMigration?.referencesInPgGetExprOrder ?? [],
        };
        report.migration0006LegacyConstraintReplaced =
          afterMigration !== null &&
          afterMigration.isCurrent &&
          afterMigration.oid !== beforeActionRefMigration.oid;
        if (!report.migration0006LegacyConstraintReplaced) {
          throw new Error("versioned_migration_action_ref_constraint_not_updated");
        }

        const beforeIdempotentPhase = await readRlsCatalogPhaseSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const beforeIdempotentGrants = await readCatalogSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        await applyVersionedMigration(migrationClient, filename);
        const afterIdempotentConstraint =
          await readApprovalActionRefConstraintState(migrationClient);
        const afterIdempotentPhase = await readRlsCatalogPhaseSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const afterIdempotentGrants = await readCatalogSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const idempotentInventory = compareCatalogInventories(
          beforeIdempotentPhase,
          beforeIdempotentGrants.snapshot,
          afterIdempotentPhase,
          afterIdempotentGrants.snapshot,
        );
        report.migration0006Idempotent =
          afterMigration !== null &&
          afterIdempotentConstraint !== null &&
          afterIdempotentConstraint.isCurrent &&
          afterIdempotentConstraint.oid === afterMigration.oid &&
          sameValue(
            catalogCounts(beforeIdempotentPhase),
            catalogCounts(afterIdempotentPhase),
          ) &&
          Object.values(idempotentInventory).every(Boolean);
        if (!report.migration0006Idempotent) {
          throw new Error("versioned_migration_0006_not_idempotent");
        }
        report.migration0006UnexpectedConstraintRejected =
          await verifyMigration0006RejectsUnexpectedConstraint(migrationClient);
        if (!report.migration0006UnexpectedConstraintRejected) {
          throw new Error("versioned_migration_0006_unexpected_constraint_accepted");
        }
      }
      if (filename === "0007_workspace_approval_receipts.sql") {
        const beforeIdempotentPhase = await readRlsCatalogPhaseSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const beforeIdempotentGrants = await readCatalogSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        await applyVersionedMigration(migrationClient, filename);
        const afterIdempotentPhase = await readRlsCatalogPhaseSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const afterIdempotentGrants = await readCatalogSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const idempotentInventory = compareCatalogInventories(
          beforeIdempotentPhase,
          beforeIdempotentGrants.snapshot,
          afterIdempotentPhase,
          afterIdempotentGrants.snapshot,
        );
        report.migration0007Idempotent =
          sameValue(
            catalogCounts(beforeIdempotentPhase),
            catalogCounts(afterIdempotentPhase),
          ) &&
          Object.values(idempotentInventory).every(Boolean);
        if (!report.migration0007Idempotent) {
          throw new Error("versioned_migration_0007_not_idempotent");
        }
      }
      if (filename === "0008_audit_append_only_membership_scope.sql") {
        const afterPhase = await readRlsCatalogPhaseSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const afterGrants = await readCatalogSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const currentComparison = compareCatalogInventories(
          drizzlePhase,
          drizzleGrants,
          afterPhase,
          afterGrants.snapshot,
        );
        const helperContractValid =
          await workspaceMembershipHelperContractValid(migrationClient);
        report.migration0008LegacyStateReplaced =
          legacyAuditStateMatches &&
          helperContractValid &&
          Object.values(currentComparison).every(Boolean);
        if (!report.migration0008LegacyStateReplaced) {
          throw new Error("versioned_migration_0008_legacy_state_not_replaced");
        }

        const beforeIdempotentPhase = afterPhase;
        const beforeIdempotentGrants = afterGrants.snapshot;
        const beforeIdempotentHelperValid = helperContractValid;
        await applyVersionedMigration(migrationClient, filename);
        const afterIdempotentPhase = await readRlsCatalogPhaseSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const afterIdempotentGrants = await readCatalogSnapshot(
          migrationPool,
          tableNames,
          roleNames,
        );
        const afterIdempotentHelperValid =
          await workspaceMembershipHelperContractValid(migrationClient);
        const idempotentInventory = compareCatalogInventories(
          beforeIdempotentPhase,
          beforeIdempotentGrants,
          afterIdempotentPhase,
          afterIdempotentGrants.snapshot,
        );
        report.migration0008Idempotent =
          sameValue(
            catalogCounts(beforeIdempotentPhase),
            catalogCounts(afterIdempotentPhase),
          ) &&
          Object.values(idempotentInventory).every(Boolean) &&
          beforeIdempotentHelperValid &&
          afterIdempotentHelperValid;
        if (!report.migration0008Idempotent) {
          throw new Error("versioned_migration_0008_not_idempotent");
        }
      }
    }

    const migratedPhase = await readRlsCatalogPhaseSnapshot(
      migrationPool,
      tableNames,
      roleNames,
    );
    const migratedGrants = await readCatalogSnapshot(
      migrationPool,
      tableNames,
      roleNames,
    );
    report.migratedCatalog = catalogCounts(migratedPhase);
    report.drizzleCatalog = catalogCounts(drizzlePhase);
    const phaseAudit = auditRlsPostPushCatalog(
      contract,
      migratedPhase,
      "final",
    );
    const grantAudit = auditRlsCatalog(contract, migratedGrants.snapshot);
    const comparison = compareCatalogInventories(
      drizzlePhase,
      drizzleGrants,
      migratedPhase,
      migratedGrants.snapshot,
    );
    report.inventoryMatchesDrizzle = comparison;
    const mismatchedCategories = Object.entries(comparison)
      .filter(([, matches]) => !matches)
      .map(([category]) => `migration_vs_drizzle_${category}_mismatch`);
    const auditViolations = [
      ...phaseAudit.violations,
      ...grantAudit.violations,
      ...mismatchedCategories,
    ].sort();
    if (
      !phaseAudit.passed ||
      !grantAudit.passed ||
      !sameValue(report.migratedCatalog, fullCatalogCounts) ||
      !report.migration0003Idempotent ||
      !report.migration0004Idempotent ||
      !report.migration0005Idempotent ||
      !report.migration0006LegacyConstraintReplaced ||
      !report.migration0006Idempotent ||
      !report.migration0006UnexpectedConstraintRejected ||
      !report.migration0007Idempotent ||
      !report.migration0008LegacyStateReplaced ||
      !report.migration0008Idempotent ||
      auditViolations.length > 0
    ) {
      report.violationCodes.push(...auditViolations);
      if (auditViolations.length === 0) {
        report.violationCodes.push("versioned_migration_catalog_mismatch");
      }
      throw new Error("versioned_migration_catalog_mismatch");
    }
  } catch (error) {
    if (report.violationCodes.length === 0) {
      report.violationCodes.push(safeVersionedMigrationFailureCode(error));
    }
    throw new Error("versioned_migration_audit_failed");
  } finally {
    await migrationPool.end().catch(() => undefined);
    await migrationClient.end().catch(() => undefined);
  }
}

export async function runVersionedMigrationAuditForCi(
  databaseUrl: string,
  commitSha: string,
): Promise<VersionedMigrationAuditReport> {
  const report: VersionedMigrationAuditReport = {
    status: "running",
    baselineSourceCommit,
    baselineStrategy:
      "clone_drizzle_catalog_remove_new_tables_and_restore_legacy_contract",
    baselineExpected: legacyCatalogCounts,
    migrationsApplied: [],
    violationCodes: [],
  };

  try {
    const target = await diagnoseGitHubActionsApprovalLabTarget(
      process.env,
      "approval-e2e",
      acquireGitHubActionsOidcToken,
    );
    if (!target.accepted) {
      report.violationCodes = [
        `ci_target_rejected_${target.category}`,
        ...(target.subcategory ? [`ci_oidc_rejected_${target.subcategory}`] : []),
      ];
      report.status = "failed";
      return report;
    }
    if (!/^[a-f0-9]{40}$/i.test(commitSha)) {
      throw new Error("versioned_migration_commit_sha_invalid");
    }
    const sourceDatabaseName = decodeURIComponent(
      new URL(databaseUrl).pathname.replace(/^\/+/, ""),
    );
    if (sourceDatabaseName !== "guardian_approval_lab_ci") {
      throw new Error("versioned_migration_source_database_mismatch");
    }

    const sources = await loadContractSources();
    const contract = parseRlsCatalogContract(sources);
    const tableNames = deriveDrizzleRlsTableNames();
    const roleNames = Object.keys(contract.roles).sort();
    const sourcePool = new Pool({
      connectionString: databaseUrl,
      application_name: "guardian-nexus-versioned-migration-source-audit",
      max: 5,
      connectionTimeoutMillis: 5000,
      statement_timeout: 15000,
    });

    let drizzlePhase: RlsCatalogPhaseSnapshot;
    let drizzleGrants: RlsCatalogSnapshot;
    try {
      drizzlePhase = await readRlsCatalogPhaseSnapshot(
        sourcePool,
        tableNames,
        roleNames,
      );
      const grantResult = await readCatalogSnapshot(
        sourcePool,
        tableNames,
        roleNames,
      );
      drizzleGrants = grantResult.snapshot;
    } finally {
      await sourcePool.end().catch(() => undefined);
    }

    report.drizzleCatalog = catalogCounts(drizzlePhase);
    await runVersionedMigrationAudit({
      connection: migrationConnectionFromUrl(databaseUrl),
      sourceDatabaseName,
      nonce: randomBytes(32).toString("hex"),
      tableNames,
      roleNames,
      contract,
      drizzlePhase,
      drizzleGrants,
      report,
    });
    report.status = "passed";
  } catch (error) {
    report.status = "failed";
    if (report.violationCodes.length === 0) {
      report.violationCodes.push(safeVersionedMigrationFailureCode(error));
    }
  }

  return report;
}

function databaseUrl(databaseName: string, socketDirectory: string): string {
  const url = new URL(`postgresql://postgres@127.0.0.1:5432/${databaseName}`);
  url.searchParams.set("host", socketDirectory);
  return url.toString();
}

function migrationConnectionFromUrl(
  databaseUrl: string,
): VersionedMigrationDatabaseConnection {
  const url = new URL(databaseUrl);
  const port = Number(url.port || "5432");
  const host = url.searchParams.get("host") ?? url.hostname;
  const user = decodeURIComponent(url.username);
  const password = decodeURIComponent(url.password);
  if (
    !host ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535 ||
    !user
  ) {
    throw new Error("versioned_migration_connection_configuration_invalid");
  }
  return { host, port, user, ...(password ? { password } : {}) };
}

function runtimeUrl(
  databaseName: string,
  password: string,
  socketDirectory: string,
): string {
  const url = new URL(
    `postgresql://app_runtime_login:${encodeURIComponent(password)}@127.0.0.1:5432/${databaseName}`,
  );
  url.searchParams.set("host", socketDirectory);
  return url.toString();
}

function envForDatabase(
  home: string,
  databaseName: string,
  socketDirectory: string,
  extras: Record<string, string> = {},
): NodeJS.ProcessEnv {
  return {
    ...safeChildEnvironment(home),
    NODE_ENV: "development",
    DATABASE_URL: databaseUrl(databaseName, socketDirectory),
    ALLOW_DEV_DB_ROLE_BOOTSTRAP: "true",
    ...extras,
  };
}

async function verifyPostgresProcess(
  pgData: string,
  socketDirectory: string,
  nonce: string,
): Promise<{ postmasterPid: number; socketPath: string }> {
  const pidFile = await readFile(path.join(pgData, "postmaster.pid"), "utf8");
  const postmasterPid = Number(pidFile.split("\n", 1)[0]);
  if (!Number.isSafeInteger(postmasterPid) || postmasterPid < 1) {
    throw new Error("instance_pid_invalid");
  }
  const processArguments = (await readFile(
    `/proc/${postmasterPid}/cmdline`,
  ))
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  const argumentString = processArguments.join(" ");
  const processExecutable = path.basename(
    await realpath(`/proc/${postmasterPid}/exe`),
  );
  const socketPath = path.join(socketDirectory, ".s.PGSQL.5432");
  const socketDirectoryMode = (await stat(socketDirectory)).mode & 0o777;
  const socketInfo = await lstat(socketPath);

  if (
    processExecutable !== "postgres" ||
    !argumentString.includes(pgData) ||
    !argumentString.includes(socketDirectory) ||
    !argumentString.includes("listen_addresses=") ||
    argumentString.includes("listen_addresses=127.0.0.1") ||
    !argumentString.includes("5432") ||
    !argumentString.includes(`guardian_nexus.lab_nonce=${nonce}`) ||
    socketDirectoryMode !== 0o700 ||
    !socketInfo.isSocket()
  ) {
    throw new Error("instance_process_or_socket_mismatch");
  }
  return { postmasterPid, socketPath };
}

async function verifyConnectedInstance(
  socketDirectory: string,
  pgData: string,
  nonce: string,
): Promise<void> {
  const client = new Client({
    host: socketDirectory,
    port: 5432,
    user: "postgres",
    database: "postgres",
    application_name: "guardian-nexus-disposable-lab",
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
  });
  try {
    await client.connect();
    const result = await client.query(
      `SELECT current_setting('data_directory') AS data_directory,
              current_setting('port') AS port,
              current_setting('listen_addresses') AS listen_addresses,
              current_setting('unix_socket_directories') AS socket_directories,
              current_setting('guardian_nexus.lab_nonce') AS nonce,
              current_setting('server_version_num')::integer AS server_version_num`,
    );
    const row = result.rows[0];
    if (
      result.rows.length !== 1 ||
      path.resolve(String(row?.data_directory)) !== path.resolve(pgData) ||
      String(row?.port) !== "5432" ||
      String(row?.listen_addresses) !== "" ||
      !String(row?.socket_directories).split(",").includes(socketDirectory) ||
      row?.nonce !== nonce
    ) {
      throw new Error("connected_instance_identity_mismatch");
    }
    const serverVersionNum = Number(row?.server_version_num);
    if (!Number.isInteger(serverVersionNum) || serverVersionNum < 160000) {
      throw new Error("postgres_version_16_required");
    }
  } finally {
    await client.end().catch(() => undefined);
  }
}

async function configureRuntimeLoginScram(pgData: string): Promise<void> {
  const pgHbaPath = path.join(pgData, "pg_hba.conf");
  const fileInfo = await lstat(pgHbaPath);
  if (!fileInfo.isFile() || fileInfo.isSymbolicLink()) {
    throw new Error("pg_hba_file_not_regular");
  }
  const current = await readFile(pgHbaPath, "utf8");
  const roleRule = "local all app_runtime_login scram-sha-256";
  if (
    current
      .split(/\r?\n/)
      .some((line) => line.trim().replace(/\s+/g, " ") === roleRule)
  ) {
    throw new Error("pg_hba_runtime_rule_already_present");
  }
  await writeFile(pgHbaPath, `${roleRule}\n${current}`);
}

async function main(): Promise<void> {
  latestFailureOutput = undefined;
  let currentStage: Stage = "preflight";
  let labRoot: string | null = null;
  let pgCtl: string | null = null;
  let pgStarted = false;
  let postgresPid: number | null = null;
  let reportDirectory: string | null = null;
  let commitSha: string | null = null;
  let hashes: Record<string, string> = {};
  let identityVerified = false;
  let postSchemaPassed = false;
  let runtimeLoginAuthenticated = false;
  let apiUnitTestFailures: SafeNodeTestFailure[] = [];
  let developmentReadOnlyCatalogAuditPassed = false;
  let approvalLedgerRlsProbesPassed = false;
  let approvalLedgerRlsProbeCount = 0;
  let approvalLedgerRlsProbeFailureCode: string | undefined;
  let approvalE2eSummary: NodeTestSummary | undefined;
  let approvalE2eFailures: SafeNodeTestFailure[] = [];
  let approvalE2eFailureLocations: string[] = [];
  let approvalE2eFailureErrorName: string | undefined;
  let approvalE2eFailureErrorCode: string | undefined;
  let approvalE2eFailureType: string | undefined;
  let approvalE2ePassed = false;
  let mcpPromptfooRedteamPassed = false;
  let mcpPromptfooRedteamSummary:
    | {
      attacks: number;
      blocked: number;
      idempotentReplays: number;
      failed: number;
    }
    | undefined;
  let postSchemaCounts = {
    tables: 0,
    columns: 0,
    indexes: 0,
    constraints: 0,
    policies: 0,
    roles: 0,
  };
  let expectedObjectDiagnostics: string[] = [];
  let actualConstraintDiagnostics: string[] = [];
  let finalCounts = {
    tables: 0,
    columns: 0,
    indexes: 0,
    constraints: 0,
    policies: 0,
    roles: 0,
  };
  let drizzleCatalogPhase: RlsCatalogPhaseSnapshot | undefined;
  let drizzleCatalogGrants: RlsCatalogSnapshot | undefined;
  let versionedMigrationAudit: VersionedMigrationAuditReport | undefined;
  let violations: string[] = [];
  let databaseName = "";
  let runtimePassword = "";
  let connectorVaultKeyringJson = "";
  const connectorCredentialE2eOnly =
    process.env.GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY === "1";
  if (
    process.env.GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY !== undefined &&
    !connectorCredentialE2eOnly
  ) {
    throw new Error("targeted_lab_mode_invalid");
  }

  try {
    assertCleanParentEnvironment();
    labRoot = await mkdtemp(path.join(os.tmpdir(), "guardian-nexus-pg-lab-"));
    await chmod(labRoot, 0o700);
    const pgData = path.join(labRoot, "pgdata");
    const socketDirectory = path.join(labRoot, "socket");
    await mkdir(socketDirectory, { mode: 0o700 });
    await chmod(socketDirectory, 0o700);
    const childEnv = safeChildEnvironment(labRoot);
    const head = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      env: childEnv,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (!/^[a-f0-9]{40}$/i.test(head)) {
      throw new Error("local_head_invalid");
    }
    commitSha = head;
    const initdb = binaryPath("initdb");
    pgCtl = binaryPath("pg_ctl");
    binaryPath("postgres");
    const pnpm = binaryPath("pnpm");
    const nonce = randomBytes(32).toString("hex");
    const suffix = randomBytes(16).toString("hex");
    databaseName = `guardian_approval_lab_${suffix}`;
    runtimePassword = randomBytes(32).toString("hex");
    const connectorVaultKey = randomBytes(32).toString("base64url");
    connectorVaultKeyringJson = JSON.stringify({
      activeKeyId: "lab-ephemeral-v1",
      keys: { "lab-ephemeral-v1": connectorVaultKey },
    });
    const validatedConnectorKeyring = loadConnectorVaultKeyring({
      WORKSPACE_CONNECTOR_KEYRING_JSON: connectorVaultKeyringJson,
    } as NodeJS.ProcessEnv);
    if (
      validatedConnectorKeyring.activeKeyId !== "lab-ephemeral-v1" ||
      validatedConnectorKeyring.keys.get("lab-ephemeral-v1")?.length !== 32
    ) {
      throw new Error("connector_vault_ephemeral_keyring_invalid");
    }
    if (connectorCredentialE2eOnly) {
      console.log(
        "Focused connector E2E keyring validation passed: one active key, 32 bytes.",
      );
    }

    currentStage = "postgres_init";
    await runAndCheck(
      initdb,
      [
        "-D",
        pgData,
        "--username=postgres",
        "--auth-local=trust",
        "--auth-host=trust",
        "--no-instructions",
      ],
      repoRoot,
      childEnv,
      currentStage,
      120_000,
    );
    await configureRuntimeLoginScram(pgData);

    currentStage = "postgres_start";
    await runAndCheck(
      pgCtl,
      [
        "-D",
        pgData,
        "-l",
        "/dev/null",
        "-o",
        `-p 5432 -k ${socketDirectory} -c listen_addresses='' -c unix_socket_directories=${socketDirectory} -c unix_socket_permissions=0700 -c password_encryption=scram-sha-256 -c guardian_nexus.lab_nonce=${nonce}`,
        "-w",
        "-t",
        "30",
        "start",
      ],
      repoRoot,
      childEnv,
      currentStage,
      45_000,
    );
    pgStarted = true;

    currentStage = "instance_identity";
    const processIdentity = await verifyPostgresProcess(
      pgData,
      socketDirectory,
      nonce,
    );
    postgresPid = processIdentity.postmasterPid;
    await verifyConnectedInstance(socketDirectory, pgData, nonce);
    identityVerified = true;

    currentStage = "create_database";
    const admin = new Client({
      host: socketDirectory,
      port: 5432,
      user: "postgres",
      database: "postgres",
      application_name: "guardian-nexus-disposable-lab-admin",
      connectionTimeoutMillis: 5000,
    });
    try {
      await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      await admin.query(
        `COMMENT ON DATABASE "${databaseName}" IS 'guardian-nexus-local-lab:${nonce}'`,
      );
      const commentResult = await admin.query(
        `SELECT shobj_description(oid, 'pg_database') AS database_comment
           FROM pg_database
          WHERE datname = $1`,
        [databaseName],
      );
      if (
        commentResult.rows.length !== 1 ||
        commentResult.rows[0]?.database_comment !==
          `guardian-nexus-local-lab:${nonce}`
      ) {
        throw new Error("database_nonce_comment_mismatch");
      }
    } finally {
      await admin.end().catch(() => undefined);
    }

    reportDirectory = path.join(
      repoRoot,
      "generated-artifacts",
      `guardian-postgres-local-${suffix}`,
    );
    const sources = await loadContractSources();
    const contract = parseRlsCatalogContract(sources);
    hashes = {
      ...sourceHashes(sources),
      ledgerRlsProbes: createHash("sha256")
        .update(
          await readFile(
            path.join(
              repoRoot,
              "artifacts/api-server/src/scripts/approval-ledger-rls-probes.ts",
            ),
            "utf8",
          ),
        )
        .digest("hex"),
    };

    currentStage = "role_hardening";
    await runAndCheck(
      pnpm,
      ["--filter", "@workspace/db", "run", "harden-runtime-role:dev"],
      repoRoot,
      envForDatabase(labRoot, databaseName, socketDirectory),
      currentStage,
    );

    currentStage = "drizzle_push";
    const tableNames = deriveDrizzleRlsTableNames();
    const postSchemaBarrier = await runPostSchemaAuditBarrier(
      contract,
      async () => {
        await runAndCheck(
          pnpm,
          ["--filter", "@workspace/db", "run", "push"],
          repoRoot,
          envForDatabase(labRoot!, databaseName, socketDirectory),
          "drizzle_push",
        );
        return 0;
      },
      async () => {
        const catalogPool = new Pool({
          host: socketDirectory,
          port: 5432,
          user: "postgres",
          database: databaseName,
          application_name: "guardian-nexus-disposable-lab-catalog",
          max: 1,
          connectionTimeoutMillis: 5000,
          statement_timeout: 10000,
        });
        try {
          currentStage = "post_schema_audit";
          return await readRlsCatalogPhaseSnapshot(
            catalogPool,
            tableNames,
            expectedPostPushRoleNames(contract),
          );
        } finally {
          await catalogPool.end();
        }
      },
    );
    {
      const phaseSnapshot = postSchemaBarrier.snapshot;
      const phaseAudit = postSchemaBarrier.audit;
      const phaseReport = postSchemaBarrier.report;
      currentStage = "post_schema_audit";
      violations = phaseAudit.violations;
      expectedObjectDiagnostics = phaseAudit.diagnostics;
      const constraintMismatchTables = new Set(
        phaseAudit.diagnostics
          .filter((entry) => entry.startsWith("constraint_definition_mismatch:"))
          .map((entry) => entry.split(":")[1]?.split(".")[0])
          .filter((name): name is string => Boolean(name)),
      );
      actualConstraintDiagnostics = phaseSnapshot.constraints
        .filter((constraint) =>
          constraintMismatchTables.has(constraint.tableName),
        )
        .map(
          (constraint) =>
            `${constraint.tableName}.${constraint.constraintName}`,
        )
        .sort();
      postSchemaPassed = phaseAudit.passed;
      postSchemaCounts = {
        tables: phaseSnapshot.tables.length,
        columns: phaseSnapshot.columns.length,
        indexes: phaseSnapshot.indexes.length,
        constraints: phaseSnapshot.constraints.length,
        policies: phaseSnapshot.policies.length,
        roles: phaseSnapshot.roles.length,
      };
      console.log(
        `Post-schema catalog: tables=${postSchemaCounts.tables} columns=${postSchemaCounts.columns} indexes=${postSchemaCounts.indexes} constraints=${postSchemaCounts.constraints} policies=${postSchemaCounts.policies} roles=${postSchemaCounts.roles}`,
      );
      await writeSafeReport(reportDirectory, {
        version: 1,
        stage: phaseReport.stage,
        status: phaseReport.status,
        commitSha,
        sourceSha256: hashes,
        counts: postSchemaCounts,
        violationCodes: phaseReport.violationCodes,
        identityVerified,
      });
      if (!phaseAudit.passed) {
        const expressionMismatchIds = new Set(
          phaseAudit.diagnostics
            .filter((entry) => entry.startsWith("constraint_expression_"))
            .map((entry) => {
              const firstColon = entry.indexOf(":");
              const secondColon = entry.indexOf(":", firstColon + 1);
              return secondColon < 0
                ? entry.slice(firstColon + 1)
                : entry.slice(firstColon + 1, secondColon);
            }),
        );
        for (const constraint of phaseSnapshot.constraints) {
          const id = `${constraint.tableName}.${constraint.constraintName}`;
          if (
            expressionMismatchIds.has(id) &&
            constraint.expression !== null
          ) {
            console.error(
              `Catalog constraint definition (schema only): ${id} = ${constraint.expression}`,
            );
          }
        }
        throw new Error("post_schema_audit_failed");
      }
    }

    currentStage = "apply_rls";
    await runAndCheck(
      pnpm,
      ["--filter", "@workspace/db", "run", "apply-rls-policies:dev"],
      repoRoot,
      envForDatabase(labRoot, databaseName, socketDirectory),
      currentStage,
    );
    await runAndCheck(
      pnpm,
      ["--filter", "@workspace/db", "run", "grant-runtime-role:dev"],
      repoRoot,
      envForDatabase(labRoot, databaseName, socketDirectory),
      currentStage,
    );

    currentStage = "runtime_login_configuration";
    await runAndCheck(
      pnpm,
      ["--filter", "@workspace/db", "run", "configure-runtime-login:dev"],
      repoRoot,
      envForDatabase(labRoot, databaseName, socketDirectory, {
        APP_RUNTIME_DB_PASSWORD: runtimePassword,
      }),
      currentStage,
    );

    currentStage = "runtime_role_verification";
    await runAndCheck(
      pnpm,
      ["--filter", "@workspace/db", "run", "verify-runtime-role:dev"],
      repoRoot,
      envForDatabase(labRoot, databaseName, socketDirectory),
      currentStage,
    );

    currentStage = "runtime_login_connection";
    const runtimePool = new Pool({
      connectionString: runtimeUrl(
        databaseName,
        runtimePassword,
        socketDirectory,
      ),
      application_name: "guardian-nexus-disposable-runtime-login-check",
      max: 1,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
    });
    try {
      const runtimeIdentity = await runtimePool.query(
        "SELECT current_user AS role_name",
      );
      runtimeLoginAuthenticated =
        runtimeIdentity.rows.length === 1 &&
        runtimeIdentity.rows[0]?.role_name === "app_runtime_login";
      if (!runtimeLoginAuthenticated) {
        throw new Error("runtime_login_identity_mismatch");
      }
    } finally {
      await runtimePool.end().catch(() => undefined);
    }

    currentStage = "final_audit";
    const finalPool = new Pool({
      host: socketDirectory,
      port: 5432,
      user: "postgres",
      database: databaseName,
      application_name: "guardian-nexus-disposable-lab-final-audit",
      max: 1,
      connectionTimeoutMillis: 5000,
      statement_timeout: 10000,
    });
    try {
      const finalSnapshot = await readRlsCatalogPhaseSnapshot(
        finalPool,
        tableNames,
        Object.keys(contract.roles).sort(),
      );
      drizzleCatalogPhase = finalSnapshot;
      const finalAudit = auditRlsPostPushCatalog(
        contract,
        finalSnapshot,
        "final",
      );
      const { snapshot: completeSnapshot } = await readCatalogSnapshot(
        finalPool,
        tableNames,
        Object.keys(contract.roles).sort(),
      );
      drizzleCatalogGrants = completeSnapshot;
      const grantAudit = auditRlsCatalog(contract, completeSnapshot);
      violations = [...finalAudit.violations, ...grantAudit.violations].sort();
      expectedObjectDiagnostics = finalAudit.diagnostics;
      finalCounts = {
        tables: finalSnapshot.tables.length,
        columns: finalSnapshot.columns.length,
        indexes: finalSnapshot.indexes.length,
        constraints: finalSnapshot.constraints.length,
        policies: finalSnapshot.policies.length,
        roles: finalSnapshot.roles.length,
      };
      console.log(
        `Final catalog: tables=${finalCounts.tables} columns=${finalCounts.columns} indexes=${finalCounts.indexes} constraints=${finalCounts.constraints} policies=${finalCounts.policies} roles=${finalCounts.roles}`,
      );
      if (!finalAudit.passed || !grantAudit.passed) {
        throw new Error("final_audit_failed");
      }
    } finally {
      await finalPool.end();
    }

    if (!connectorCredentialE2eOnly) {
    currentStage = "versioned_migration_audit";
    if (!drizzleCatalogPhase || !drizzleCatalogGrants) {
      throw new Error("drizzle_catalog_snapshot_unavailable");
    }
    versionedMigrationAudit = {
      status: "running",
      baselineSourceCommit,
      baselineStrategy:
        "clone_drizzle_catalog_remove_new_tables_and_restore_legacy_contract",
      baselineExpected: legacyCatalogCounts,
      migrationsApplied: [],
      violationCodes: [],
    };
    await runVersionedMigrationAudit({
      connection: migrationConnectionFromUrl(
        databaseUrl(databaseName, socketDirectory),
      ),
      sourceDatabaseName: databaseName,
      nonce,
      serverNonce: nonce,
      tableNames,
      roleNames: Object.keys(contract.roles).sort(),
      contract,
      drizzlePhase: drizzleCatalogPhase,
      drizzleGrants: drizzleCatalogGrants,
      report: versionedMigrationAudit,
    });
    versionedMigrationAudit.status = "passed";
    console.log(
      `Versioned migration catalog: baseline=${versionedMigrationAudit.baselineActual?.tables}/${versionedMigrationAudit.baselineActual?.columns}/${versionedMigrationAudit.baselineActual?.indexes}/${versionedMigrationAudit.baselineActual?.constraints}/${versionedMigrationAudit.baselineActual?.policies}/${versionedMigrationAudit.baselineActual?.roles} migrated=${versionedMigrationAudit.migratedCatalog?.tables}/${versionedMigrationAudit.migratedCatalog?.columns}/${versionedMigrationAudit.migratedCatalog?.indexes}/${versionedMigrationAudit.migratedCatalog?.constraints}/${versionedMigrationAudit.migratedCatalog?.policies}/${versionedMigrationAudit.migratedCatalog?.roles} migration_0003_idempotent=${versionedMigrationAudit.migration0003Idempotent === true} migration_0004_idempotent=${versionedMigrationAudit.migration0004Idempotent === true} migration_0005_idempotent=${versionedMigrationAudit.migration0005Idempotent === true} migration_0006_legacy_replaced=${versionedMigrationAudit.migration0006LegacyConstraintReplaced === true} migration_0006_idempotent=${versionedMigrationAudit.migration0006Idempotent === true} migration_0007_idempotent=${versionedMigrationAudit.migration0007Idempotent === true} migration_0008_legacy_replaced=${versionedMigrationAudit.migration0008LegacyStateReplaced === true} migration_0008_idempotent=${versionedMigrationAudit.migration0008Idempotent === true}.`,
    );

    currentStage = "api_unit_tests";
    const apiTestEnv = {
      ...safeChildEnvironment(labRoot),
      NODE_ENV: "development",
      GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
      GUARDIAN_APPROVAL_E2E_DATABASE_NAME: databaseName,
      DATABASE_URL: databaseUrl(databaseName, socketDirectory),
      APP_RUNTIME_DATABASE_URL: runtimeUrl(
        databaseName,
        runtimePassword,
        socketDirectory,
      ),
    };
    const apiTestOutput = await runAndCapture(
      pnpm,
      ["--filter", "@workspace/api-server", "run", "test"],
      repoRoot,
      apiTestEnv,
      currentStage,
    );
    const apiTestSummary = parseNodeTestSummary(
      `${apiTestOutput.stdout}\n${apiTestOutput.stderr}`,
    );
    console.log(
      `node:test API unit and disposable DB suite: tests=${apiTestSummary.tests} pass=${apiTestSummary.pass} fail=${apiTestSummary.fail} skipped=${apiTestSummary.skipped}`,
    );
    if (
      apiTestSummary.tests < 1 ||
      apiTestSummary.fail > 0 ||
      apiTestSummary.skipped > 0 ||
      apiTestOutput.exitCode !== 0
    ) {
      apiUnitTestFailures = await parseApiUnitTestFailures(
        `${apiTestOutput.stdout}\n${apiTestOutput.stderr}`,
      );
      if (apiUnitTestFailures.length > 0) {
        console.error(
          `Sanitized API test failures: ${JSON.stringify(apiUnitTestFailures)}`,
        );
      }
      throw new Error("api_unit_tests_failed");
    }

    currentStage = "development_read_only_catalog_audit";
    const developmentAuditOutput = await runAndCapture(
      pnpm,
      [
        "--filter",
        "@workspace/api-server",
        "run",
        "audit:development-rls-catalog",
        "--",
        "--confirm-read-only",
        `--expected-database=${databaseName}`,
      ],
      repoRoot,
      {
        ...safeChildEnvironment(labRoot),
        NODE_ENV: "development",
        APP_RUNTIME_DATABASE_URL: runtimeUrl(
          databaseName,
          runtimePassword,
          socketDirectory,
        ),
      },
      currentStage,
    );
    const auditReportLine = developmentAuditOutput.stdout
      .split(/\r?\n/)
      .find((line) => line.trim().startsWith("{"));
    if (!auditReportLine) {
      throw new Error("development_read_only_catalog_report_missing");
    }
    const developmentAuditReport = JSON.parse(auditReportLine) as {
      status?: string;
      databaseNameMatched?: boolean;
      transactionReadOnly?: boolean;
      runtimeLoginAuthenticated?: boolean;
      expected?: {
        tables?: number;
        columns?: number;
        indexes?: number;
        constraints?: number;
        policies?: number;
        roles?: number;
      };
      actual?: {
        tables?: number;
        columns?: number;
        indexes?: number;
        constraints?: number;
        policies?: number;
        roles?: number;
      };
      violationCodes?: unknown;
    };
    const safeDevelopmentAuditCodes = Array.isArray(
      developmentAuditReport.violationCodes,
    )
      ? developmentAuditReport.violationCodes
        .filter((code): code is string =>
          typeof code === "string" &&
          /^[a-z][a-z0-9_]{1,63}$/.test(code)
        )
        .slice(0, 64)
      : [];
    if (
      developmentAuditOutput.exitCode !== 0 ||
      developmentAuditOutput.signal !== null ||
      developmentAuditReport.status !== "passed" ||
      developmentAuditReport.databaseNameMatched !== true ||
      developmentAuditReport.transactionReadOnly !== true ||
      developmentAuditReport.runtimeLoginAuthenticated !== true ||
      developmentAuditReport.expected?.tables !== 19 ||
      developmentAuditReport.expected?.columns !== 205 ||
      developmentAuditReport.expected?.indexes !== 51 ||
      developmentAuditReport.expected?.constraints !== 99 ||
      developmentAuditReport.expected?.policies !== 53 ||
      developmentAuditReport.expected?.roles !== 3 ||
      developmentAuditReport.actual?.tables !== 19 ||
      developmentAuditReport.actual?.columns !== 205 ||
      developmentAuditReport.actual?.indexes !== 51 ||
      developmentAuditReport.actual?.constraints !== 99 ||
      developmentAuditReport.actual?.policies !== 53 ||
      developmentAuditReport.actual?.roles !== 3 ||
      !Array.isArray(developmentAuditReport.violationCodes) ||
      developmentAuditReport.violationCodes.length !== 0
    ) {
      console.error(
        `Development read-only catalog audit failed safely: status=${developmentAuditReport.status ?? "invalid"} tables=${developmentAuditReport.actual?.tables ?? "unknown"} columns=${developmentAuditReport.actual?.columns ?? "unknown"} indexes=${developmentAuditReport.actual?.indexes ?? "unknown"} constraints=${developmentAuditReport.actual?.constraints ?? "unknown"} policies=${developmentAuditReport.actual?.policies ?? "unknown"} roles=${developmentAuditReport.actual?.roles ?? "unknown"} violationCodes=${safeDevelopmentAuditCodes.join(",") || "none"}.`,
      );
      throw new Error("development_read_only_catalog_audit_failed");
    }
    developmentReadOnlyCatalogAuditPassed = true;
    console.log(
      "Development read-only catalog audit passed on the disposable runtime connection: tables=19 columns=205 indexes=51 constraints=99 policies=53 roles=3.",
    );

    currentStage = "approval_ledger_rls_probes";
    const ledgerProbePool = new Pool({
      host: socketDirectory,
      port: 5432,
      user: "postgres",
      database: databaseName,
      application_name: "guardian-nexus-disposable-ledger-rls-probes",
      max: 1,
      connectionTimeoutMillis: 5000,
      statement_timeout: 10000,
    });
    try {
      const probeResult = await runApprovalLedgerRlsProbes(ledgerProbePool);
      approvalLedgerRlsProbesPassed = probeResult.passed;
      approvalLedgerRlsProbeCount = probeResult.probeCount;
      console.log(
        `Approval ledger RLS probes passed: ${probeResult.probeCount}/${probeResult.probeCount} (synthetic, disposable PostgreSQL).`,
      );
    } finally {
      await ledgerProbePool.end();
    }

    currentStage = "demo_member_seed_tests";
    const demoMemberTestEnv = {
      ...safeChildEnvironment(labRoot),
      NODE_ENV: "development",
      GUARDIAN_DEMO_MEMBER_TEST_REQUIRED: "1",
      GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
      GUARDIAN_APPROVAL_E2E_DATABASE_NAME: databaseName,
      DATABASE_URL: databaseUrl(databaseName, socketDirectory),
      APP_RUNTIME_DATABASE_URL: runtimeUrl(
        databaseName,
        runtimePassword,
        socketDirectory,
      ),
    };
    const demoMemberTestOutput = await runAndCapture(
      pnpm,
      [
        "--filter",
        "@workspace/api-server",
        "exec",
        "node",
        "--import",
        "tsx",
        "--test",
        "--test-reporter=tap",
        "src/scripts/seed-demo-member.test.ts",
      ],
      repoRoot,
      demoMemberTestEnv,
      currentStage,
    );
    const demoMemberTestSummary = parseNodeTestSummary(
      `${demoMemberTestOutput.stdout}\n${demoMemberTestOutput.stderr}`,
    );
    console.log(
      `node:test demo member seed: tests=${demoMemberTestSummary.tests} pass=${demoMemberTestSummary.pass} fail=${demoMemberTestSummary.fail} skipped=${demoMemberTestSummary.skipped}`,
    );
    if (
      demoMemberTestSummary.tests < 1 ||
      demoMemberTestSummary.fail > 0 ||
      demoMemberTestSummary.skipped > 0 ||
      demoMemberTestOutput.exitCode !== 0
    ) {
      throw new Error("demo_member_seed_tests_failed");
    }
    }

    currentStage = "approval_e2e";
    const e2eEnv = {
      ...safeChildEnvironment(labRoot),
      NODE_ENV: "development",
      GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
      GUARDIAN_APPROVAL_E2E_REQUIRED: "1",
      GUARDIAN_APPROVAL_E2E_DATABASE_NAME: databaseName,
      DATABASE_URL: databaseUrl(databaseName, socketDirectory),
      APP_RUNTIME_DATABASE_URL: runtimeUrl(
        databaseName,
        runtimePassword,
        socketDirectory,
      ),
      WORKSPACE_CONNECTOR_KEYRING_JSON: connectorVaultKeyringJson,
      ...(connectorCredentialE2eOnly
        ? { GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY: "1" }
        : {}),
    };
    const e2eArgs = [
      "--filter",
      "@workspace/api-server",
      "exec",
      "node",
      "--import",
      "tsx",
      "--test",
      "--test-reporter=tap",
      ...(connectorCredentialE2eOnly
        ? [
            "--test-name-pattern=^(?:deterministic approval E2E exports signed history and gates refund simulation|agent credentials are scoped, revocable, renewable and cannot self-approve|workspace connector vault is private, encrypted, receipt-gated and idempotent)$",
          ]
        : []),
      "src/ai-assessment-synthetic-approval-e2e.test.ts",
    ];
    const e2eOutput = await runAndCapture(
      pnpm,
      e2eArgs,
      repoRoot,
      e2eEnv,
      currentStage,
    );
    const nodeTestSummary = parseNodeTestSummary(
      `${e2eOutput.stdout}\n${e2eOutput.stderr}`,
    );
    approvalE2eSummary = nodeTestSummary;
    const combinedE2eOutput = `${e2eOutput.stdout}\n${e2eOutput.stderr}`;
    console.log(
      `node:test approval E2E: tests=${nodeTestSummary.tests} pass=${nodeTestSummary.pass} fail=${nodeTestSummary.fail} skipped=${nodeTestSummary.skipped}`,
    );
    if (connectorCredentialE2eOnly) {
      const targetSubtestName =
        "workspace connector vault is private, encrypted, receipt-gated and idempotent";
      if (!combinedE2eOutput.includes(targetSubtestName)) {
        throw new Error("focused_connector_subtest_not_observed");
      }
      const focusedEvidenceLines = combinedE2eOutput
        .split(/\r?\n/)
        .filter(
          (line) =>
            line.includes("MODO FOCALIZADO:") ||
            line.includes(targetSubtestName) ||
            line.includes("connector insert context current_user=") ||
            line.includes("workspace_connector_credential_insert_result") ||
            line.includes("workspace_connector_execution_failed") ||
            /^# (tests|pass|fail|cancelled|skipped) \d+$/.test(line),
        );
      console.log(
        `Focused connector TAP evidence: ${JSON.stringify(focusedEvidenceLines)}`,
      );
      const roleDiagnostic = combinedE2eOutput.match(
        /connector insert context current_user=app_runtime session_user=app_runtime_login; omitted-column INSERT privileges are false/,
      )?.[0];
      if (!roleDiagnostic) {
        throw new Error("focused_connector_role_diagnostic_missing");
      }
      console.log(`Focused connector role: ${roleDiagnostic}`);
    }
    const connectorContextRecords = new Set<string>();
    for (const contextDiagnostic of combinedE2eOutput.matchAll(
      /workspace_connector_credential_insert_context (\{"workspaceSetting":"(?:[0-9a-f-]{36}|invalid)","userSetting":"[A-Za-z0-9._-]{1,128}","databaseRole":"[A-Za-z_][A-Za-z0-9_]{0,62}","membershipRole":"(?:owner|admin|analyst|viewer)","credentialExisted":(?:true|false)\})/g,
    )) {
      connectorContextRecords.add(contextDiagnostic[1] ?? "");
    }
    for (const contextRecord of connectorContextRecords) {
      console.log(`Connector credential context: ${contextRecord}`);
    }
    if (nodeTestSummary.fail > 0 || e2eOutput.exitCode !== 0) {
      const e2eTestPath = path.join(
        repoRoot,
        "artifacts/api-server/src/ai-assessment-synthetic-approval-e2e.test.ts",
      );
      const e2eTestSource = await readFile(e2eTestPath, "utf8");
      approvalE2eFailures = parseSafeNodeTestFailures(
        combinedE2eOutput,
        path.basename(e2eTestPath),
        e2eTestSource,
      );
      const firstFailure = approvalE2eFailures[0];
      approvalE2eFailureLocations = firstFailure?.location
        ? [firstFailure.location]
        : [];
      approvalE2eFailureErrorName = firstFailure?.errorName;
      approvalE2eFailureErrorCode = firstFailure?.errorCode;
      approvalE2eFailureType = firstFailure?.failureType;
    }
    if (
      e2eOutput.exitCode !== 0 ||
      e2eOutput.signal !== null ||
      nodeTestSummary.pass < 1 ||
      (!connectorCredentialE2eOnly && nodeTestSummary.skipped !== 0) ||
      nodeTestSummary.fail !== 0 ||
      nodeTestSummary.cancelled !== 0
    ) {
      const connectorDiagnostic = combinedE2eOutput.match(
        /workspace_connector_credential_save_failed stage=[a-z_]{1,32} code=(?:[0-9A-Z]{5}|[A-Za-z][A-Za-z0-9_]{0,63}) chain=[A-Za-z0-9_=:,.;|-]{1,1200}/,
      )?.[0];
      if (connectorDiagnostic) {
        console.error(`Connector credential diagnostic: ${connectorDiagnostic}`);
      }
      if (approvalE2eFailures.length > 0) {
        console.error(
          `node:test failure diagnostics: ${JSON.stringify(approvalE2eFailures)}`,
        );
      }
      if (
        approvalE2eFailureErrorName ||
        approvalE2eFailureErrorCode ||
        approvalE2eFailureType
      ) {
        console.error(
          `node:test failure class: type=${approvalE2eFailureType ?? "unknown"} name=${approvalE2eFailureErrorName ?? "unknown"} code=${approvalE2eFailureErrorCode ?? "unknown"}`,
        );
      }
      throw new Error("approval_e2e_summary_rejected");
    }
    approvalE2ePassed = true;

    if (connectorCredentialE2eOnly) {
      await writeSafeReport(reportDirectory, {
        version: 1,
        stage: "final",
        status: "passed",
        commitSha,
        sourceSha256: hashes,
        counts: finalCounts,
        violationCodes: [],
        identityVerified,
        runtimeLoginAuthenticated,
        approvalE2eSummary,
        approvalE2ePassed,
        targetedConnectorCredentialE2e: true,
      });
      console.log(
        `Focused connector credential E2E passed: tests=${nodeTestSummary.tests} pass=${nodeTestSummary.pass} skipped=${nodeTestSummary.skipped}.`,
      );
      return;
    }

    currentStage = "mcp_promptfoo_redteam";
    const redteamOutput = await runAndCapture(
      pnpm,
      ["--filter", "@workspace/api-server", "run", "redteam:mcp"],
      repoRoot,
      {
        ...e2eEnv,
        GUARDIAN_PROMPTFOO_MCP_ONLY: "1",
      },
      currentStage,
    );
    const combinedRedteamOutput =
      `${redteamOutput.stdout}\n${redteamOutput.stderr}`;
    const redteamSummaryMatch = combinedRedteamOutput.match(
      /Resumen Promptfoo MCP: ataques lanzados=(\d+), bloqueados=(\d+), reintentos idempotentes=(\d+), fallidos=(\d+)\./,
    );
    if (redteamSummaryMatch) {
      mcpPromptfooRedteamSummary = {
        attacks: Number(redteamSummaryMatch[1]),
        blocked: Number(redteamSummaryMatch[2]),
        idempotentReplays: Number(redteamSummaryMatch[3]),
        failed: Number(redteamSummaryMatch[4]),
      };
      const summary = mcpPromptfooRedteamSummary;
      console.log(
        `Promptfoo MCP red team: attacks=${summary.attacks} blocked=${summary.blocked} idempotent_replays=${summary.idempotentReplays} failed=${summary.failed}`,
      );
    }
    if (
      redteamOutput.exitCode !== 0 ||
      redteamOutput.signal !== null ||
      !mcpPromptfooRedteamSummary ||
      mcpPromptfooRedteamSummary.failed > 0 ||
      mcpPromptfooRedteamSummary.idempotentReplays !== 1 ||
      mcpPromptfooRedteamSummary.blocked !==
        mcpPromptfooRedteamSummary.attacks
    ) {
      throw new Error("mcp_promptfoo_redteam_rejected");
    }
    mcpPromptfooRedteamPassed = true;

    await writeSafeReport(reportDirectory, {
      version: 1,
      stage: "final",
      status: "passed",
      commitSha,
      sourceSha256: hashes,
      counts: finalCounts,
      violationCodes: [],
      identityVerified,
      runtimeLoginAuthenticated,
      developmentReadOnlyCatalogAuditPassed,
      approvalLedgerRlsProbesPassed,
      approvalLedgerRlsProbeCount,
      approvalE2eSummary,
      approvalE2ePassed,
      mcpPromptfooRedteamPassed,
      mcpPromptfooRedteamSummary,
      versionedMigrationAudit,
    });
    console.log("Disposable PostgreSQL lab passed; sanitized reports were written.");
  } catch (error) {
    if (currentStage === "approval_ledger_rls_probes") {
      approvalLedgerRlsProbeFailureCode =
        safeApprovalLedgerRlsProbeFailureCode(error);
    }
    const status = `Disposable PostgreSQL lab failed at stage: ${currentStage}.`;
    if (versionedMigrationAudit?.status === "running") {
      versionedMigrationAudit.status = "failed";
      if (versionedMigrationAudit.violationCodes.length === 0) {
        versionedMigrationAudit.violationCodes.push(
          "versioned_migration_audit_failed",
        );
      }
      violations = versionedMigrationAudit.violationCodes;
    }
    if (reportDirectory) {
      await writeSafeReport(reportDirectory, {
        version: 1,
        stage: postSchemaPassed ? "final" : "post-schema",
        status: "failed",
        commitSha,
        sourceSha256: hashes,
        counts:
          currentStage === "post_schema_audit"
            ? postSchemaCounts
            : finalCounts,
        violationCodes: violations,
        identityVerified,
        runtimeLoginAuthenticated,
        developmentReadOnlyCatalogAuditPassed,
        approvalLedgerRlsProbesPassed,
        approvalLedgerRlsProbeCount,
        approvalLedgerRlsProbeFailureCode,
        approvalE2eSummary,
        approvalE2eFailures,
        approvalE2eFailureLocations,
        approvalE2eFailureErrorName,
        approvalE2eFailureErrorCode,
        approvalE2eFailureType,
        approvalE2ePassed,
        mcpPromptfooRedteamPassed,
        mcpPromptfooRedteamSummary,
        apiUnitTestFailures,
        versionedMigrationAudit,
        failureOutput: latestFailureOutput,
        failureStage: currentStage,
      }).catch(() => undefined);
    }
    console.error(status);
    if (approvalLedgerRlsProbeFailureCode) {
      console.error(
        `Approval ledger RLS probe failure code: ${approvalLedgerRlsProbeFailureCode}.`,
      );
    }
    if (expectedObjectDiagnostics.length > 0) {
      console.error(
        `Expected schema object identifiers with mismatches: ${expectedObjectDiagnostics.join(", ")}`,
      );
    }
    if (actualConstraintDiagnostics.length > 0) {
      console.error(
        `Observed constraint identifiers on affected tables: ${actualConstraintDiagnostics.join(", ")}`,
      );
    }
    process.exitCode = 1;
  } finally {
    let safeToDeleteLabRoot = !pgStarted;
    if (pgStarted && pgCtl && labRoot) {
      const pgData = path.join(labRoot, "pgdata");
      let stopConfirmed = false;
      try {
        await run(
          pgCtl,
          ["-D", pgData, "-m", "immediate", "-w", "stop"],
          repoRoot,
          safeChildEnvironment(labRoot),
          "postgres_start",
          30_000,
        );
        stopConfirmed = true;
      } catch {
        // Do not remove PGDATA unless the exact server is confirmed stopped.
      }
      if (postgresPid === null) {
        try {
          postgresPid = Number(
            (await readFile(path.join(pgData, "postmaster.pid"), "utf8"))
              .split("\n", 1)[0],
          );
        } catch {
          postgresPid = null;
        }
      }
      let processStillExists = true;
      if (postgresPid !== null && Number.isSafeInteger(postgresPid)) {
        try {
          await stat(`/proc/${postgresPid}`);
          processStillExists = true;
        } catch (error) {
          processStillExists =
            !(
              error &&
              typeof error === "object" &&
              "code" in error &&
              error.code === "ENOENT"
            );
        }
      }
      safeToDeleteLabRoot = stopConfirmed || !processStillExists;
      if (!safeToDeleteLabRoot) {
        console.error(
          "PostgreSQL stop was not verified; the private temporary directory was retained.",
        );
        process.exitCode = 1;
      }
    }
    if (labRoot && safeToDeleteLabRoot) {
      const resolvedRoot = path.resolve(labRoot);
      const expectedParent = path.resolve(os.tmpdir());
      const rootName = path.basename(resolvedRoot);
      const currentUid = process.getuid?.();
      try {
        const rootStat = await lstat(resolvedRoot);
        if (
          path.dirname(resolvedRoot) === expectedParent &&
          /^guardian-nexus-pg-lab-[A-Za-z0-9]+$/.test(rootName) &&
          !rootStat.isSymbolicLink() &&
          rootStat.isDirectory() &&
          (rootStat.mode & 0o077) === 0 &&
          currentUid !== undefined &&
          rootStat.uid === currentUid
        ) {
          await rm(resolvedRoot, { recursive: true, force: false });
        } else {
          console.error("Private temporary lab cleanup was not verified.");
          process.exitCode = 1;
        }
      } catch {
        console.error("Private temporary lab cleanup failed.");
        process.exitCode = 1;
      }
    }
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) ===
    path.resolve(fileURLToPath(import.meta.url))
) {
  void main();
}
