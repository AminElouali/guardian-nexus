import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  API_TEST_TARGET_REJECTION,
  runApiTestSuite,
} from "../lib/api-test-target-guard";

const testFiles = [
  "src/security.test.ts",
  "src/connector-utils.test.ts",
  "src/ai-security.test.ts",
  "src/lib/ai-assessment-qwen-evidence.test.ts",
  "src/lib/assessment-broker-grant.test.ts",
  "src/lib/assessment-worker-mode.test.ts",
  "src/lib/ai-assessment-sandbox.test.ts",
  "src/lib/guardian-agent-action-adapter.test.ts",
  "src/lib/assessment-container-control.test.ts",
  "src/lib/assessment-output-limit.test.ts",
  "src/lib/policy-lab-preview.test.ts",
  "src/lib/workspace-agent-credentials.test.ts",
  "src/lib/generic-action-evidence.test.ts",
  "src/lib/safe-http-request-log.test.ts",
  "src/lib/api-test-target-guard.test.ts",
  "src/middlewares/ai-assessment-json.test.ts",
];

function launchTests(): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [
        "--import",
        "tsx",
        "--test",
        "--test-reporter=tap",
        ...testFiles,
      ],
      {
        cwd: process.cwd(),
        env: process.env,
        stdio: "inherit",
      },
    );
    child.once("error", () => resolve(1));
    child.once("exit", (code) => resolve(code ?? 1));
  });
}

async function main(): Promise<void> {
  const result = await runApiTestSuite(process.env, launchTests);
  if (!result.started) {
    process.stderr.write(`${API_TEST_TARGET_REJECTION}\n`);
  }
  process.exitCode = result.exitCode;
}

const entryPath = process.argv[1]
  ? path.resolve(process.argv[1])
  : "";
if (entryPath === fileURLToPath(import.meta.url)) {
  void main();
}
