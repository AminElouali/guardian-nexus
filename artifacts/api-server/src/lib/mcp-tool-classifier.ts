import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  evaluateApprovalAction,
  getApprovalActionDefinition,
  type ApprovalActionProfileId,
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
  | { kind: "argument"; field: string; unit: "cents" | "records" }
  | { kind: "fixed"; unit: "messages" | "operations" };

type McpToolBinding = {
  actionType: CatalogActionRef;
  dataSensitivity: "normal" | "sensible";
  volume: VolumeBinding;
  guardianDescription: string;
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
      guardianDescription: "Propón una respuesta sintética a un caso de soporte. La regla vigente puede exigir aprobación humana.",
      volume: Object.freeze({
        kind: "argument",
        field: "compensation_cents",
        unit: "cents",
      }),
    }),
    send_external_email: Object.freeze({
      actionType: "guardian.email.send.external.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón un correo de prueba. Gmail solo lo envía tras la aprobación y a un destinatario permitido.",
      volume: Object.freeze({ kind: "fixed", unit: "messages" }),
    }),
    issue_synthetic_refund: Object.freeze({
      actionType: "guardian.synthetic.support.refund.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón un reembolso sintético de atención al cliente. La regla y el límite vigentes deciden si se permite automáticamente o requiere aprobación.",
      volume: Object.freeze({
        kind: "argument",
        field: "amount_cents",
        unit: "cents",
      }),
    }),
    reply_internal_email: Object.freeze({
      actionType: "guardian.email.reply.internal.v1",
      dataSensitivity: "normal",
      guardianDescription: "Propón una respuesta a un buzón interno ficticio; no se envía fuera.",
      volume: Object.freeze({ kind: "fixed", unit: "messages" }),
    }),
    send_sensitive_external_email: Object.freeze({
      actionType: "guardian.email.send.external_sensitive.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón un correo de prueba con adjuntos o datos de clientes.",
      volume: Object.freeze({ kind: "fixed", unit: "messages" }),
    }),
    create_forwarding_rule: Object.freeze({
      actionType: "guardian.email.forwarding_rule.create.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Evalúa una regla de reenvío sintética, bloqueada por política.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    close_customer_account: Object.freeze({
      actionType: "guardian.support.customer_account.close.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón cerrar o borrar una cuenta sintética de cliente.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    read_finance_record: Object.freeze({
      actionType: "guardian.finance.balance_invoice.read.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Consulta un saldo o factura ficticios.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    change_synthetic_bank_account: Object.freeze({
      actionType: "guardian.synthetic.finance.bank-change.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón un cambio bancario ficticio; hacen falta dos aprobaciones humanas distintas.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    pay_known_vendor: Object.freeze({
      actionType: "guardian.finance.vendor_payment.known.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón un pago sintético a un proveedor conocido.",
      volume: Object.freeze({
        kind: "argument",
        field: "amount_cents",
        unit: "cents",
      }),
    }),
    pay_new_vendor: Object.freeze({
      actionType: "guardian.finance.vendor_payment.new.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón un pago sintético a un proveedor nuevo; bloqueado por defecto.",
      volume: Object.freeze({
        kind: "argument",
        field: "amount_cents",
        unit: "cents",
      }),
    }),
    query_synthetic_data: Object.freeze({
      actionType: "guardian.data.query.read.v1",
      dataSensitivity: "normal",
      guardianDescription: "Consulta un conjunto de datos sintético predefinido, nunca SQL libre.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    export_customer_data: Object.freeze({
      actionType: "guardian.data.customer.export.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón una exportación sintética de datos de clientes.",
      volume: Object.freeze({
        kind: "argument",
        field: "record_limit",
        unit: "records",
      }),
    }),
    modify_data_batch: Object.freeze({
      actionType: "guardian.data.bulk.modify.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón una modificación sintética en lote.",
      volume: Object.freeze({
        kind: "argument",
        field: "record_limit",
        unit: "records",
      }),
    }),
    delete_data_batch: Object.freeze({
      actionType: "guardian.data.bulk.delete.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Evalúa un borrado masivo sintético, bloqueado por política.",
      volume: Object.freeze({
        kind: "argument",
        field: "record_limit",
        unit: "records",
      }),
    }),
    open_pull_request: Object.freeze({
      actionType: "guardian.code.pull_request.open.v1",
      dataSensitivity: "normal",
      guardianDescription: "Prepara un pull request ficticio sin contactar repositorios.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    merge_pull_request_main: Object.freeze({
      actionType: "guardian.code.pull_request.merge_main.v1",
      dataSensitivity: "normal",
      guardianDescription: "Propón fusionar un pull request ficticio en main.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    deploy_to_production: Object.freeze({
      actionType: "guardian.code.deploy.production.v1",
      dataSensitivity: "normal",
      guardianDescription: "Propón un despliegue ficticio; no accede a producción.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    access_repository_secret: Object.freeze({
      actionType: "guardian.code.secret.access.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Evalúa un acceso a secretos, bloqueado por política.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    read_synthetic_web_page: Object.freeze({
      actionType: "guardian.web.navigate.read.v1",
      dataSensitivity: "normal",
      guardianDescription: "Lee una página local de demostración; no navega por internet.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    submit_personal_data_form: Object.freeze({
      actionType: "guardian.web.personal_data.submit.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón un formulario ficticio con datos personales.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    purchase_synthetic_item: Object.freeze({
      actionType: "guardian.web.purchase.v1",
      dataSensitivity: "normal",
      guardianDescription: "Propón una compra ficticia; no se realiza ningún pago.",
      volume: Object.freeze({
        kind: "argument",
        field: "amount_cents",
        unit: "cents",
      }),
    }),
    submit_credentials_unapproved_site: Object.freeze({
      actionType: "guardian.web.unapproved_credentials.submit.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Evalúa introducir credenciales en un sitio no aprobado.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    read_cloud_resource: Object.freeze({
      actionType: "guardian.cloud.resource.read.v1",
      dataSensitivity: "normal",
      guardianDescription: "Consulta recursos o costes ficticios, sin conexión cloud.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    create_cloud_resource: Object.freeze({
      actionType: "guardian.cloud.resource.create.v1",
      dataSensitivity: "normal",
      guardianDescription: "Propón crear un recurso ficticio con coste estimado.",
      volume: Object.freeze({
        kind: "argument",
        field: "estimated_cost_cents",
        unit: "cents",
      }),
    }),
    change_cloud_iam_permissions: Object.freeze({
      actionType: "guardian.cloud.iam.permission.change.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón cambiar permisos IAM en un escenario ficticio.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    delete_or_public_cloud_resource: Object.freeze({
      actionType: "guardian.cloud.production_destructive.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Evalúa una acción cloud destructiva, bloqueada por política.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    delegate_equal_or_lower: Object.freeze({
      actionType: "guardian.multiagent.delegate_equal_or_lower.v1",
      dataSensitivity: "normal",
      guardianDescription: "Evalúa delegar permisos iguales o menores en modo sintético.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    delegate_higher_permissions: Object.freeze({
      actionType: "guardian.multiagent.delegate_higher_scope.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Propón delegar un alcance superior a otro agente ficticio.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
    }),
    self_assign_or_bypass_approval: Object.freeze({
      actionType: "guardian.multiagent.privilege_escalation.v1",
      dataSensitivity: "sensible",
      guardianDescription: "Evalúa un intento de autoasignar permisos o eludir aprobación.",
      volume: Object.freeze({ kind: "fixed", unit: "operations" }),
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
    unit: "cents" | "records";
  }
  | {
    kind: "fixed";
    quantity: 1;
    maximum: 1;
    unit: "messages" | "operations";
  };

export type McpToolClassification = {
  status: "classified" | "rejected" | "unknown";
  actionType: string;
  profileId: ApprovalActionProfileId | null;
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

export type GuardianMcpToolDefinition = {
  serverId: string;
  name: string;
  actionType: CatalogActionRef;
  description: string;
  inputSchema: {
    type: "object";
    additionalProperties: false;
    properties: Record<string, Record<string, unknown>>;
    required: string[];
  };
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
    profileId: null,
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
  profileId: ApprovalActionProfileId,
  reasonCode: McpToolClassification["reasonCode"],
  riskTypes: readonly ApprovalActionRiskType[],
  dataSensitivity: "normal" | "sensible",
  canonicalInputSha256: string | null = null,
): McpToolClassification {
  return {
    status: "rejected",
    actionType,
    profileId,
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
  if (binding.kind === "fixed") {
    return { kind: "fixed", quantity: 1, maximum: 1, unit: binding.unit };
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
      catalogDefinition.profileId,
      "arguments_not_json_text",
      [...catalogDefinition.riskTypes],
      binding.dataSensitivity,
    );
  }
  const parsed = parseStrictJson(argumentsJson);
  if (!parsed.ok) {
    return rejected(
      binding.actionType,
      catalogDefinition.profileId,
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
      catalogDefinition.profileId,
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
      catalogDefinition.profileId,
      "catalog_volume_binding_invalid",
      [...evaluated.definition.riskTypes],
      binding.dataSensitivity,
      inputSha256,
    );
  }

  return {
    status: "classified",
    actionType: binding.actionType,
    profileId: evaluated.definition.profileId,
    riskTypes: [...evaluated.definition.riskTypes],
    dataSensitivity: binding.dataSensitivity,
    volume,
    validatedArguments: evaluated.args,
    canonicalInputSha256: inputSha256,
    blockRequired: false,
    reasonCode: "classified",
  };
}

export function getGuardianMcpToolDefinition(
  serverId: string,
  toolName: string,
): GuardianMcpToolDefinition | null {
  const binding = REGISTERED_MCP_TOOLS[serverId]?.[toolName];
  const action = binding
    ? getApprovalActionDefinition(binding.actionType)
    : undefined;
  if (!binding || !action) return null;
  const properties: Record<string, Record<string, unknown>> = {};
  const required: string[] = [];
  for (const [name, rule] of Object.entries(action.argumentSchema.properties)) {
    properties[name] = {
      type: rule.type,
      ...(rule.min !== undefined ? { minimum: rule.min } : {}),
      ...(rule.max !== undefined ? { maximum: rule.max } : {}),
      ...(rule.maxLength !== undefined ? { maxLength: rule.maxLength } : {}),
      ...(rule.pattern ? { pattern: rule.pattern.source } : {}),
      ...(rule.enum ? { enum: [...rule.enum] } : {}),
    };
    if (rule.required) required.push(name);
  }
  return {
    serverId,
    name: toolName,
    actionType: binding.actionType,
    description: binding.guardianDescription,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties,
      required,
    },
  };
}

export function listGuardianMcpToolDefinitions(
  serverId: string,
): GuardianMcpToolDefinition[] {
  const registered = REGISTERED_MCP_TOOLS[serverId];
  if (!registered) return [];
  return Object.keys(registered)
    .sort()
    .flatMap((toolName) => {
      const definition = getGuardianMcpToolDefinition(serverId, toolName);
      return definition ? [definition] : [];
    });
}
