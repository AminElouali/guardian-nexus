/**
 * Helpers for the "Conectar agente" assistant. Pure functions only: no
 * network, no storage. Credentials passed in here are never persisted.
 */

export type AgentServiceId =
  | "email"
  | "support"
  | "finance"
  | "data"
  | "code"
  | "web"
  | "cloud"
  | "multiagent";

export const AGENT_SERVICES: ReadonlyArray<{
  id: AgentServiceId;
  label: string;
  example: string;
}> = [
  { id: "email", label: "Correo", example: "Bot de correo" },
  { id: "support", label: "Soporte", example: "Bot de soporte" },
  { id: "finance", label: "Finanzas", example: "Asistente de pagos" },
  { id: "data", label: "Datos", example: "Agente de datos" },
  { id: "code", label: "Código", example: "Agente de código" },
  { id: "web", label: "Web", example: "Agente de navegación" },
  { id: "cloud", label: "Cloud", example: "Agente de cloud" },
  { id: "multiagent", label: "Multiagente", example: "Orquestador" },
];

export type AgentPlatformId = "claude" | "openai" | "n8n" | "generic";

export const AGENT_PLATFORMS: ReadonlyArray<{ id: AgentPlatformId; label: string }> = [
  { id: "claude", label: "Claude" },
  { id: "openai", label: "ChatGPT / OpenAI Agents" },
  { id: "n8n", label: "n8n / Make" },
  { id: "generic", label: "Otro (MCP)" },
];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** MCP endpoint for a workspace, built from the public origin of the app. */
export function buildMcpUrl(origin: string, workspaceId: string): string {
  if (!UUID_RE.test(workspaceId)) {
    throw new Error("Invalid workspace identifier");
  }
  const parsed = new URL(origin);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Invalid origin");
  }
  return `${parsed.origin}/api/workspaces/${workspaceId}/mcp`;
}

/** Ready-to-paste configuration for each platform. */
export function buildConnectionSnippet(
  platform: AgentPlatformId,
  input: { url: string; credential: string },
): string {
  const { url, credential } = input;
  switch (platform) {
    case "claude":
      return [
        "# Claude Code (terminal)",
        `claude mcp add --transport http guardian-nexus ${url} \\`,
        `  --header "Authorization: Bearer ${credential}"`,
      ].join("\n");
    case "openai":
      return [
        "# OpenAI Agents SDK (Python)",
        "from agents import Agent",
        "from agents.mcp import MCPServerStreamableHttp",
        "",
        "guardian = MCPServerStreamableHttp(params={",
        `    "url": "${url}",`,
        `    "headers": {"Authorization": "Bearer ${credential}"},`,
        "})",
        "",
        'agent = Agent(name="Mi agente", mcp_servers=[guardian])',
      ].join("\n");
    case "n8n":
      return [
        "Nodo: MCP Client Tool",
        `Endpoint: ${url}`,
        "Transporte: HTTP Streamable",
        "Autenticación: Bearer",
        `Token: ${credential}`,
      ].join("\n");
    case "generic":
      return JSON.stringify(
        {
          mcpServers: {
            "guardian-nexus": {
              type: "http",
              url,
              headers: { Authorization: `Bearer ${credential}` },
            },
          },
        },
        null,
        2,
      );
  }
}

type AgentActivityInput = {
  revokedAt: string | null;
  lastUsedAt: string | null;
};

/**
 * Whether the agent has authenticated against the MCP endpoint after the
 * moment its current credential was issued.
 */
export function hasConnectedSince(
  agent: AgentActivityInput,
  issuedAt: Date,
): boolean {
  if (agent.revokedAt !== null || agent.lastUsedAt === null) return false;
  const used = Date.parse(agent.lastUsedAt);
  return Number.isFinite(used) && used >= issuedAt.getTime() - 5_000;
}

export type AgentActivityState = "active" | "idle" | "revoked";

const ACTIVE_WINDOW_MS = 24 * 60 * 60 * 1000;

export function agentActivityState(
  agent: AgentActivityInput,
  now: Date,
): AgentActivityState {
  if (agent.revokedAt !== null) return "revoked";
  if (agent.lastUsedAt === null) return "idle";
  const used = Date.parse(agent.lastUsedAt);
  if (!Number.isFinite(used)) return "idle";
  return now.getTime() - used <= ACTIVE_WINDOW_MS ? "active" : "idle";
}

export function formatLastActivity(
  lastUsedAt: string | null,
  now: Date,
): string {
  if (lastUsedAt === null) return "Sin actividad todavía";
  const used = Date.parse(lastUsedAt);
  if (!Number.isFinite(used)) return "Sin actividad todavía";
  const minutes = Math.max(0, Math.round((now.getTime() - used) / 60_000));
  if (minutes < 1) return "Hace un momento";
  if (minutes < 60) return `Hace ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `Hace ${hours} h`;
  const days = Math.round(hours / 24);
  return `Hace ${days} día${days === 1 ? "" : "s"}`;
}
