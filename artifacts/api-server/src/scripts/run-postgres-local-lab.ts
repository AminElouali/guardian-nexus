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
  deriveDrizzleRlsTableNames,
  expectedPostPushRoleNames,
  readRlsCatalogPhaseSnapshot,
  runPostSchemaAuditBarrier,
} from "@workspace/db/rls-catalog-phase-audit";
import {
  parseRlsCatalogContract,
  auditRlsCatalog,
} from "@workspace/db/rls-catalog-audit";
import {
  runApprovalLedgerRlsProbes,
  safeApprovalLedgerRlsProbeFailureCode,
} from "./approval-ledger-rls-probes";
import { readCatalogSnapshot } from "./verify-rls-catalog";

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
  | "api_unit_tests"
  | "development_read_only_catalog_audit"
  | "approval_ledger_rls_probes"
  | "demo_member_seed_tests"
  | "approval_e2e";

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
  failureStage?: Stage;
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

const allowedChildEnvironmentKeys = ["PATH", "HOME", "LANG", "LC_ALL"] as const;
const MAX_CAPTURED_TEST_OUTPUT_BYTES = 256 * 1024;

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
      stdio: ["ignore", "ignore", "ignore"],
    });
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 3000).unref();
      reject(new Error(`child_timeout:${stage}`));
    }, timeoutMs);
    child.once("error", () => {
      clearTimeout(timeout);
      reject(new Error(`child_start_failed:${stage}`));
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      if (code === 0 && signal === null) {
        resolve();
      } else {
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
  const failures = [...output.matchAll(/^not ok \d+ - (.{1,240})$/gm)]
    .slice(0, 8);
  return failures.map((match, index) => {
    const start = match.index ?? 0;
    const nextFailure = failures[index + 1]?.index;
    const summaryOffset = output.slice(start).search(/^# tests \d+$/m);
    const end = nextFailure ??
      (summaryOffset >= 0 ? start + summaryOffset : output.length);
    const block = output.slice(start, end);
    const label = (match[1] ?? "").trim();
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

function databaseUrl(databaseName: string, socketDirectory: string): string {
  const url = new URL(`postgresql://postgres@127.0.0.1:5432/${databaseName}`);
  url.searchParams.set("host", socketDirectory);
  return url.toString();
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
  let violations: string[] = [];
  let databaseName = "";
  let runtimePassword = "";

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

    currentStage = "api_unit_tests";
    const apiTestEnv = {
      ...safeChildEnvironment(labRoot),
      NODE_ENV: "development",
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
      developmentAuditReport.expected?.tables !== 16 ||
      developmentAuditReport.expected?.columns !== 173 ||
      developmentAuditReport.expected?.indexes !== 44 ||
      developmentAuditReport.expected?.constraints !== 72 ||
      developmentAuditReport.expected?.policies !== 45 ||
      developmentAuditReport.expected?.roles !== 3 ||
      developmentAuditReport.actual?.tables !== 16 ||
      developmentAuditReport.actual?.columns !== 173 ||
      developmentAuditReport.actual?.indexes !== 44 ||
      developmentAuditReport.actual?.constraints !== 72 ||
      developmentAuditReport.actual?.policies !== 45 ||
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
      "Development read-only catalog audit passed on the disposable runtime connection: tables=16 columns=173 indexes=44 constraints=72 policies=45 roles=3.",
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
    };
    const e2eOutput = await runAndCapture(
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
        "src/ai-assessment-synthetic-approval-e2e.test.ts",
      ],
      repoRoot,
      e2eEnv,
      currentStage,
    );
    const nodeTestSummary = parseNodeTestSummary(
      `${e2eOutput.stdout}\n${e2eOutput.stderr}`,
    );
    approvalE2eSummary = nodeTestSummary;
    console.log(
      `node:test approval E2E: tests=${nodeTestSummary.tests} pass=${nodeTestSummary.pass} fail=${nodeTestSummary.fail} skipped=${nodeTestSummary.skipped}`,
    );
    const combinedE2eOutput = `${e2eOutput.stdout}\n${e2eOutput.stderr}`;
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
      nodeTestSummary.skipped !== 0 ||
      nodeTestSummary.fail !== 0 ||
      nodeTestSummary.cancelled !== 0
    ) {
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
    });
    console.log("Disposable PostgreSQL lab passed; sanitized reports were written.");
  } catch (error) {
    if (currentStage === "approval_ledger_rls_probes") {
      approvalLedgerRlsProbeFailureCode =
        safeApprovalLedgerRlsProbeFailureCode(error);
    }
    const status = `Disposable PostgreSQL lab failed at stage: ${currentStage}.`;
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
