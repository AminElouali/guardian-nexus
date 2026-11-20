import assert from "node:assert/strict";
import test from "node:test";
import { isMcpDemoEnvironmentAllowed } from "./demo-mcp";

const validDevelopmentEnvironment = {
  NODE_ENV: "development",
  DATABASE_URL: "postgres://synthetic",
  PGHOST: "synthetic",
  PGDATABASE: "synthetic",
} as NodeJS.ProcessEnv;

test("MCP demo permits only an explicitly configured development process", () => {
  assert.equal(isMcpDemoEnvironmentAllowed(validDevelopmentEnvironment), true);
  assert.equal(
    isMcpDemoEnvironmentAllowed({
      ...validDevelopmentEnvironment,
      NODE_ENV: "production",
    }),
    false,
  );
  assert.equal(
    isMcpDemoEnvironmentAllowed({
      ...validDevelopmentEnvironment,
      REPLIT_DEPLOYMENT: "1",
    }),
    false,
  );
  assert.equal(
    isMcpDemoEnvironmentAllowed({
      ...validDevelopmentEnvironment,
      CI: "true",
    }),
    false,
  );
  assert.equal(
    isMcpDemoEnvironmentAllowed({
      ...validDevelopmentEnvironment,
      GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    }),
    false,
  );
  assert.equal(
    isMcpDemoEnvironmentAllowed({
      ...validDevelopmentEnvironment,
      PGDATABASE: undefined,
    }),
    false,
  );
});
