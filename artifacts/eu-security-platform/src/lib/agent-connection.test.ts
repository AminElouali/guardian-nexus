import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AGENT_PLATFORMS,
  AGENT_SERVICES,
  agentActivityState,
  buildConnectionSnippet,
  buildMcpUrl,
  formatLastActivity,
  hasConnectedSince,
} from "./agent-connection";

const workspaceId = "11111111-2222-4333-8444-555555555555";
const credential = `gnx_agent_v1_${"a".repeat(43)}`;

test("buildMcpUrl uses only the public origin and the workspace id", () => {
  assert.equal(
    buildMcpUrl("https://app.example.com/dashboard?x=1#y", workspaceId),
    `https://app.example.com/api/workspaces/${workspaceId}/mcp`,
  );
  assert.throws(() => buildMcpUrl("https://app.example.com", "../other"));
  assert.throws(() => buildMcpUrl("javascript:alert(1)", workspaceId));
});

test("every platform snippet contains the URL and the bearer credential", () => {
  const url = buildMcpUrl("https://app.example.com", workspaceId);
  for (const platform of AGENT_PLATFORMS) {
    const snippet = buildConnectionSnippet(platform.id, { url, credential });
    assert.ok(snippet.includes(url), platform.id);
    assert.ok(snippet.includes(credential), platform.id);
  }
  const generic = JSON.parse(
    buildConnectionSnippet("generic", { url, credential }),
  );
  assert.equal(generic.mcpServers["guardian-nexus"].url, url);
  assert.equal(
    generic.mcpServers["guardian-nexus"].headers.Authorization,
    `Bearer ${credential}`,
  );
});

test("there are eight services with unique ids", () => {
  assert.equal(AGENT_SERVICES.length, 8);
  assert.equal(new Set(AGENT_SERVICES.map((s) => s.id)).size, 8);
});

test("hasConnectedSince only counts activity after the credential was issued", () => {
  const issuedAt = new Date("2026-11-21T10:00:00Z");
  assert.equal(
    hasConnectedSince({ revokedAt: null, lastUsedAt: null }, issuedAt),
    false,
  );
  assert.equal(
    hasConnectedSince(
      { revokedAt: null, lastUsedAt: "2026-11-21T09:00:00Z" },
      issuedAt,
    ),
    false,
  );
  assert.equal(
    hasConnectedSince(
      { revokedAt: null, lastUsedAt: "2026-11-21T10:00:30Z" },
      issuedAt,
    ),
    true,
  );
  assert.equal(
    hasConnectedSince(
      {
        revokedAt: "2026-11-21T10:01:00Z",
        lastUsedAt: "2026-11-21T10:00:30Z",
      },
      issuedAt,
    ),
    false,
  );
});

test("agentActivityState and formatLastActivity", () => {
  const now = new Date("2026-11-21T12:00:00Z");
  assert.equal(
    agentActivityState({ revokedAt: null, lastUsedAt: null }, now),
    "idle",
  );
  assert.equal(
    agentActivityState(
      { revokedAt: null, lastUsedAt: "2026-11-21T11:00:00Z" },
      now,
    ),
    "active",
  );
  assert.equal(
    agentActivityState(
      { revokedAt: null, lastUsedAt: "2026-11-19T11:00:00Z" },
      now,
    ),
    "idle",
  );
  assert.equal(
    agentActivityState(
      { revokedAt: "2026-11-21T11:00:00Z", lastUsedAt: null },
      now,
    ),
    "revoked",
  );
  assert.equal(formatLastActivity(null, now), "Sin actividad todavía");
  assert.equal(formatLastActivity("2026-11-21T11:50:00Z", now), "Hace 10 min");
  assert.equal(formatLastActivity("2026-11-21T09:00:00Z", now), "Hace 3 h");
  assert.equal(formatLastActivity("2026-11-20T12:00:00Z", now), "Hace 1 día");
});
