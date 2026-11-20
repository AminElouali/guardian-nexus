import assert from "node:assert/strict";
import test from "node:test";
import {
  APPROVAL_ACTION_CATALOG,
  evaluateApprovalAction,
} from "@workspace/db/approval-action-catalog";
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

test("MCP demo action is approval-gated by the existing catalog", () => {
  const result = evaluateApprovalAction("guardian.support.reply.send.v1", {
    ticket_id: "TICKET-SYNTH-DEMO",
    recipient_email: "demo@example.test",
    recipient_type: "external",
    compensation_cents: 5_000,
    template_id: "synthetic-support-reply-v1",
  });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.decision, "require_approval");
});

test("low-risk catalog ALLOW is still escalated for independent approval", () => {
  const result = evaluateApprovalAction("guardian.support.reply.send.v1", {
    ticket_id: "TICKET-SYNTH-DEMO",
    recipient_email: "demo@example.test",
    recipient_type: "internal",
    compensation_cents: 0,
    template_id: "synthetic-support-reply-v1",
  });
  const action = APPROVAL_ACTION_CATALOG.find(
    (entry) => entry.actionType === "guardian.support.reply.send.v1",
  );
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.decision, "allow");
  assert.equal(action?.requiresIndependentApprover, true);
});
