import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  evaluateApprovalAction,
  getApprovalActionDefinition,
  type ApprovalActionRiskType,
  type CatalogActionRef,
} from "@workspace/db/approval-action-catalog";
import { canonicalApprovalJson } from "./ai-assessment-approval-actions";

const MAX_IDENTIFIER_LENGTH = 64;
const MAX_ARGUMENTS_BYTES = 8 * 1024;
const MAX_JSON_CONTAINER_DEPTH = 8;
const SAFE_IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const UNSAFE_JSON_KEYS = new Set(["__proto__", "constructor", "prototype"]);

type VolumeBinding =
  | { kind: "argument"; field: string; unit: "cents" }
  | { kind: "fixed_message" };

type McpToolBinding = {
  actionType: CatalogActionRef;
  dataSensitivity: "normal" | "sensible";
  volume: VolumeBinding;
};

// Example-only registration. These names and mappings are declared by Guardian;
// no MCP-provided title, description, annotation, schema, or response is read.
const REGISTERED_MCP_TOOLS: Readonly<
  Record<string, Readonly<Record<string, McpToolBinding>>>
> = Object.freeze({
  "guardian-demo-mcp": Object.freeze({
    reply_to_support: Object.freeze({
      actionType: "guardian.support.reply.send.v1",
      dataSensitivity: "sensible",
      volume: Object.freeze({
        kind: "argument",
        field: "compensation_cents",
        unit: "cents",
      }),
    }),
    send_external_email: Object.freeze({
      actionType: "guardian.email.send.external.v1",
      dataSensitivity: "sensible",
      volume: Object.freeze({ kind: "fixed_message" }),
    }),
  }),
});

export type McpToolClassificationInput = {
  serverId: unknown;
  toolName: unknown;
  argumentsJson: unknown;
  // Accepted as opaque input only to make it explicit that MCP metadata is
  // untrusted and irrelevant to classification.
  description?: unknown;
  title?: unknown;
  annotations?: unknown;
  inputSchema?: unknown;
  responseText?: unknown;
};

export type McpVolumeLabel =
  | {
    kind: "argument";
    field: string;
    value: number;
    maximum: number;
    unit: "cents";
  }
  | {
    kind: "fixed";
    quantity: 1;
    maximum: 1;
    unit: "messages";
  };

export type McpToolClassification = {
  status: "classified" | "rejected" | "unknown";
  actionType: string;
  riskTypes: readonly ApprovalActionRiskType[];
  dataSensitivity: "normal" | "sensible" | null;
  volume: McpVolumeLabel | null;
  validatedArguments: Record<string, string | number | boolean> | null;
  canonicalInputSha256: string | null;
  blockRequired: boolean;
  reasonCode:
    | "classified"
    | "invalid_call"
    | "invalid_identifier"
    | "server_not_registered"
    | "tool_not_allowlisted"
    | "arguments_not_json_text"
    | "arguments_too_large"
    | "arguments_too_deep"
    | "arguments_duplicate_key"
    | "arguments_unsafe_key"
    | "arguments_invalid_json"
    | "arguments_invalid"
    | "catalog_action_unavailable"
    | "catalog_volume_binding_invalid";
};

type StrictJsonResult =
  | { ok: true; value: unknown }
  | {
    ok: false;
    reasonCode:
      | "arguments_too_large"
      | "arguments_too_deep"
      | "arguments_duplicate_key"
      | "arguments_unsafe_key"
      | "arguments_invalid_json";
  };

class StrictJsonFailure extends Error {
  constructor(readonly reasonCode: Exclude<
    StrictJsonResult,
    { ok: true }
  >["reasonCode"]) {
    super(reasonCode);
  }
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function parseStrictJson(source: string): StrictJsonResult {
  if (Buffer.byteLength(source, "utf8") > MAX_ARGUMENTS_BYTES) {
    return { ok: false, reasonCode: "arguments_too_large" };
  }

  let offset = 0;

  const fail = (
    reasonCode: Exclude<StrictJsonResult, { ok: true }>["reasonCode"],
  ): never => {
    throw new StrictJsonFailure(reasonCode);
  };

  const skipWhitespace = (): void => {
    while (
      source[offset] === " " ||
      source[offset] === "\t" ||
      source[offset] === "\r" ||
      source[offset] === "\n"
    ) {
      offset += 1;
    }
  };

  const parseString = (): string => {
    const start = offset;
    if (source[offset] !== "\"") return fail("arguments_invalid_json");
    offset += 1;
    let escaped = false;
    while (offset < source.length) {
      const character = source[offset]!;
      offset += 1;
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        continue;
      }
      if (character === "\"") {
        let value: unknown;
        try {
          value = JSON.parse(source.slice(start, offset));
        } catch {
          return fail("arguments_invalid_json");
        }
        if (typeof value !== "string" || !isWellFormedUnicode(value)) {
          return fail("arguments_invalid_json");
        }
        return value;
      }
    }
    return fail("arguments_invalid_json");
  };

  const parseValue = (depth: number): unknown => {
    skipWhitespace();
    const character = source[offset];
    if (character === "{" || character === "[") {
      if (depth > MAX_JSON_CONTAINER_DEPTH) {
        return fail("arguments_too_deep");
      }
      if (character === "[") {
        offset += 1;
        const values: unknown[] = [];
        skipWhitespace();
        if (source[offset] === "]") {
          offset += 1;
          return values;
        }
        while (true) {
          values.push(parseValue(depth + 1));
          skipWhitespace();
          if (source[offset] === "]") {
            offset += 1;
            return values;
          }
          if (source[offset] !== ",") return fail("arguments_invalid_json");
          offset += 1;
        }
      }

      offset += 1;
      const result = Object.create(null) as Record<string, unknown>;
      const seenKeys = new Set<string>();
      skipWhitespace();
      if (source[offset] === "}") {
        offset += 1;
        return result;
      }
      while (true) {
        skipWhitespace();
        const key = parseString();
        if (UNSAFE_JSON_KEYS.has(key)) return fail("arguments_unsafe_key");
        if (seenKeys.has(key)) return fail("arguments_duplicate_key");
        seenKeys.add(key);
        skipWhitespace();
        if (source[offset] !== ":") return fail("arguments_invalid_json");
        offset += 1;
        Object.defineProperty(result, key, {
          configurable: true,
          enumerable: true,
          value: parseValue(depth + 1),
          writable: true,
        });
        skipWhitespace();
        if (source[offset] === "}") {
          offset += 1;
          return result;
        }
        if (source[offset] !== ",") return fail("arguments_invalid_json");
        offset += 1;
      }
    }
    if (character === "\"") return parseString();
    if (source.startsWith("true", offset)) {
      offset += 4;
      return true;
    }
    if (source.startsWith("false", offset)) {
      offset += 5;
      return false;
    }
    if (source.startsWith("null", offset)) {
      offset += 4;
      return null;
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/
      .exec(source.slice(offset));
    if (number) {
      offset += number[0].length;
      const value = Number(number[0]);
      if (!Number.isFinite(value)) return fail("arguments_invalid_json");
      return value;
    }
    return fail("arguments_invalid_json");
  };

  try {
    const value = parseValue(0);
    skipWhitespace();
    if (offset !== source.length) {
      return { ok: false, reasonCode: "arguments_invalid_json" };
    }
    return { ok: true, value };
  } catch (error) {
    if (error instanceof StrictJsonFailure) {
      return { ok: false, reasonCode: error.reasonCode };
    }
    return { ok: false, reasonCode: "arguments_invalid_json" };
  }
}

function emptyUnknown(
  reasonCode: McpToolClassification["reasonCode"],
): McpToolClassification {
  return {
    status: "unknown",
    actionType: "unknown",
    riskTypes: [],
    dataSensitivity: null,
    volume: null,
    validatedArguments: null,
    canonicalInputSha256: null,
    blockRequired: true,
    reasonCode,
  };
}

function rejected(
  actionType: string,
  reasonCode: McpToolClassification["reasonCode"],
  riskTypes: readonly ApprovalActionRiskType[],
  dataSensitivity: "normal" | "sensible",
  canonicalInputSha256: string | null = null,
): McpToolClassification {
  return {
    status: "rejected",
    actionType,
    riskTypes,
    dataSensitivity,
    volume: null,
    validatedArguments: null,
    canonicalInputSha256,
    blockRequired: true,
    reasonCode,
  };
}

function canonicalInputHash(
  serverId: string,
  toolName: string,
  args: unknown,
): string {
  const canonical = canonicalApprovalJson({
    serverId,
    toolName,
    arguments: args,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function volumeLabel(
  binding: McpToolBinding["volume"],
  args: Record<string, string | number | boolean>,
  maximum?: number,
): McpVolumeLabel | null {
  if (binding.kind === "fixed_message") {
    return { kind: "fixed", quantity: 1, maximum: 1, unit: "messages" };
  }
  const value = args[binding.field];
  if (typeof value !== "number" || typeof maximum !== "number") return null;
  return {
    kind: "argument",
    field: binding.field,
    value,
    maximum,
    unit: binding.unit,
  };
}

function ownDataProperty(record: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && Object.hasOwn(descriptor, "value")
    ? descriptor.value
    : undefined;
}

/**
 * Classifies a raw MCP JSON-RPC tool call against Guardian's explicit allowlist.
 * This does not make an authorization decision or execute/dispatch the tool.
 * `argumentsJson` must be the original JSON text so duplicate keys remain
 * detectable before any ordinary JSON.parse operation discards them.
 */
export function classifyMcpToolCall(
  input: McpToolClassificationInput,
): McpToolClassification {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return emptyUnknown("invalid_call");
  }

  const serverId = ownDataProperty(input, "serverId");
  const toolName = ownDataProperty(input, "toolName");
  if (
    typeof serverId !== "string" ||
    typeof toolName !== "string" ||
    serverId.length > MAX_IDENTIFIER_LENGTH ||
    toolName.length > MAX_IDENTIFIER_LENGTH ||
    !SAFE_IDENTIFIER.test(serverId) ||
    !SAFE_IDENTIFIER.test(toolName)
  ) {
    return emptyUnknown("invalid_identifier");
  }

  const registeredTools = REGISTERED_MCP_TOOLS[serverId];
  if (!Object.hasOwn(REGISTERED_MCP_TOOLS, serverId) || !registeredTools) {
    return emptyUnknown("server_not_registered");
  }
  const binding = registeredTools[toolName];
  if (!Object.hasOwn(registeredTools, toolName) || !binding) {
    return emptyUnknown("tool_not_allowlisted");
  }

  const catalogDefinition = getApprovalActionDefinition(binding.actionType);
  if (!catalogDefinition) return emptyUnknown("catalog_action_unavailable");

  const argumentsJson = ownDataProperty(input, "argumentsJson");
  if (typeof argumentsJson !== "string") {
    return rejected(
      binding.actionType,
      "arguments_not_json_text",
      [...catalogDefinition.riskTypes],
      binding.dataSensitivity,
    );
  }
  const parsed = parseStrictJson(argumentsJson);
  if (!parsed.ok) {
    return rejected(
      binding.actionType,
      parsed.reasonCode,
      [...catalogDefinition.riskTypes],
      binding.dataSensitivity,
    );
  }

  const inputSha256 = canonicalInputHash(serverId, toolName, parsed.value);
  const evaluated = evaluateApprovalAction(binding.actionType, parsed.value);
  if (!evaluated.ok) {
    return rejected(
      binding.actionType,
      "arguments_invalid",
      [...catalogDefinition.riskTypes],
      binding.dataSensitivity,
      inputSha256,
    );
  }

  const volumeRule = binding.volume.kind === "argument"
    ? catalogDefinition.argumentSchema.properties[binding.volume.field]
    : undefined;
  const volumeMaximum = volumeRule?.type === "integer"
    ? volumeRule.max
    : undefined;
  const volume = volumeLabel(binding.volume, evaluated.args, volumeMaximum);
  if (!volume) {
    return rejected(
      binding.actionType,
      "catalog_volume_binding_invalid",
      [...evaluated.definition.riskTypes],
      binding.dataSensitivity,
      inputSha256,
    );
  }

  return {
    status: "classified",
    actionType: binding.actionType,
    riskTypes: [...evaluated.definition.riskTypes],
    dataSensitivity: binding.dataSensitivity,
    volume,
    validatedArguments: evaluated.args,
    canonicalInputSha256: inputSha256,
    blockRequired: false,
    reasonCode: "classified",
  };
}
