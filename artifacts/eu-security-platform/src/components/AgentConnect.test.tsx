import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { WorkspaceAgent } from "@workspace/api-client-react";
import {
  AgentConnectWizard,
  AgentList,
  type AgentConnectWizardProps,
  type AgentListProps,
} from "./AgentConnect";

const credential = `gnx_agent_v1_${"b".repeat(43)}`;
const mcpUrl =
  "https://app.example.com/api/workspaces/11111111-2222-4333-8444-555555555555/mcp";
const noop = () => {};

function wizard(overrides: Partial<AgentConnectWizardProps> = {}): string {
  const props: AgentConnectWizardProps = {
    step: 1,
    displayName: "",
    service: null,
    mcpUrl,
    credential: null,
    platform: "claude",
    busy: false,
    error: null,
    connection: "idle",
    onDisplayNameChange: noop,
    onServiceChange: noop,
    onPlatformChange: noop,
    onCreate: noop,
    onContinueToTest: noop,
    onTestConnection: noop,
    onClose: noop,
    ...overrides,
  };
  return renderToStaticMarkup(createElement(AgentConnectWizard, props));
}

test("step 1 shows the eight services and disables create until complete", () => {
  const html = wizard();
  for (const id of ["email", "support", "finance", "data", "code", "web", "cloud", "multiagent"]) {
    assert.ok(html.includes(`button-agent-service-${id}`), id);
  }
  assert.match(html, /data-testid="button-agent-create"[^>]*disabled=""|disabled=""[^>]*data-testid="button-agent-create"/);
  const ready = wizard({ displayName: "Bot de soporte", service: "support" });
  assert.doesNotMatch(ready, /disabled=""[^>]*data-testid="button-agent-create"/);
});

test("step 2 shows the credential once with a copy button and a warning", () => {
  const html = wizard({ step: 2, credential, platform: "generic" });
  assert.ok(html.includes(credential));
  assert.ok(html.includes(mcpUrl));
  assert.ok(html.includes("solo se muestra esta vez"));
  assert.ok(html.includes("button-agent-copy"));
});

test("step 3 never renders the credential, even if one is passed by mistake", () => {
  const html = wizard({ step: 3, credential });
  assert.ok(!html.includes(credential));
  assert.ok(html.includes("button-agent-test"));
});

test("step 3 explains each connection result in plain language", () => {
  assert.ok(wizard({ step: 3, connection: "connected" }).includes("Conectado"));
  assert.ok(wizard({ step: 3, connection: "timeout" }).includes("No hemos visto actividad"));
  assert.ok(wizard({ step: 3, connection: "error" }).includes("No se pudo comprobar"));
});

function agent(overrides: Partial<WorkspaceAgent>): WorkspaceAgent {
  return {
    id: "agent-1",
    displayName: "Bot de soporte",
    principalUserId: "user-1",
    credentialVersion: 1,
    createdAt: "2026-11-20T10:00:00Z",
    revokedAt: null,
    lastUsedAt: null,
    ...overrides,
  };
}

function list(overrides: Partial<AgentListProps> = {}): string {
  const props: AgentListProps = {
    agents: [],
    now: new Date("2026-11-21T12:00:00Z"),
    canManage: true,
    busyAgentId: null,
    confirmingRevokeId: null,
    onRotate: noop,
    onAskRevoke: noop,
    onConfirmRevoke: noop,
    onCancelRevoke: noop,
    ...overrides,
  };
  return renderToStaticMarkup(createElement(AgentList, props));
}

test("agent list shows empty state, status and management actions", () => {
  assert.ok(list().includes("state-agents-empty"));
  const html = list({
    agents: [
      agent({ id: "a1", lastUsedAt: "2026-11-21T11:50:00Z" }),
      agent({ id: "a2", displayName: "Agente inactivo" }),
      agent({ id: "a3", displayName: "Agente retirado", revokedAt: "2026-11-21T09:00:00Z" }),
    ],
  });
  assert.ok(html.includes("Conectado"));
  assert.ok(html.includes("Sin actividad reciente"));
  assert.ok(html.includes("Dado de baja"));
  assert.ok(html.includes("button-agent-rotate-a1"));
  assert.ok(!html.includes("button-agent-rotate-a3"));
  assert.ok(!html.includes("gnx_agent_v1_"));
});

test("agent list asks for confirmation before revoking and hides actions for non-admins", () => {
  const confirming = list({ agents: [agent({ id: "a1" })], confirmingRevokeId: "a1" });
  assert.ok(confirming.includes("button-agent-revoke-confirm-a1"));
  const viewer = list({ agents: [agent({ id: "a1" })], canManage: false });
  assert.ok(!viewer.includes("button-agent-rotate-a1"));
});
