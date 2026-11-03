import { spawnSync } from "node:child_process";

const checks = [
  {
    name: "API and worker E2E",
    args: ["exec", "tsx", "--test", "src/ai-assessment-e2e.test.ts"],
  },
  {
    name: "dashboard component integration",
    args: [
      "exec",
      "tsx",
      "--tsconfig",
      "../eu-security-platform/tsconfig.json",
      "--test",
      "../eu-security-platform/src/components/AiEvaluationPage.integration.test.tsx",
    ],
  },
];

let failed = false;
for (const check of checks) {
  console.info(`\n[ai-assessment-e2e] starting: ${check.name}`);
  const result = spawnSync("pnpm", check.args, {
    env: { ...process.env, NODE_ENV: "development" },
    stdio: "inherit",
  });
  const exitCode = result.error ? 1 : (result.status ?? 1);
  console.info(`[ai-assessment-e2e] ${check.name} exit=${exitCode}`);
  failed ||= exitCode !== 0;
}

process.exitCode = failed ? 1 : 0;
