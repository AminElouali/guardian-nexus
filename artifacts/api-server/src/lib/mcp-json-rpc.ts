import { Buffer } from "node:buffer";

export type ParsedMcpJsonRpcRequest = {
  value: Record<string, unknown>;
  rawArgumentsJson: string | null;
};

export type McpJsonRpcParseFailure =
  | "body_not_text"
  | "body_too_large"
  | "invalid_json"
  | "duplicate_key"
  | "unsafe_key"
  | "too_deep"
  | "too_many_values"
  | "invalid_envelope";

export class McpJsonRpcParseError extends Error {
  constructor(readonly code: McpJsonRpcParseFailure) {
    super(code);
    this.name = "McpJsonRpcParseError";
  }
}

const MAX_BODY_BYTES = 16 * 1024;
const MAX_DEPTH = 16;
const MAX_VALUES = 4_000;
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export function parseMcpJsonRpcRequest(
  input: unknown,
): ParsedMcpJsonRpcRequest {
  if (typeof input !== "string") {
    throw new McpJsonRpcParseError("body_not_text");
  }
  if (Buffer.byteLength(input, "utf8") > MAX_BODY_BYTES) {
    throw new McpJsonRpcParseError("body_too_large");
  }

  let index = 0;
  let valueCount = 0;
  let rawArgumentsJson: string | null = null;
  const whitespace = () => {
    while (index < input.length && /[\u0009\u000a\u000d\u0020]/.test(input[index]!)) index++;
  };

  const parseString = (): string => {
    const start = index;
    if (input[index] !== '"') throw new McpJsonRpcParseError("invalid_json");
    index++;
    while (index < input.length) {
      const code = input.charCodeAt(index);
      if (code === 0x22) {
        index++;
        try {
          return JSON.parse(input.slice(start, index)) as string;
        } catch {
          throw new McpJsonRpcParseError("invalid_json");
        }
      }
      if (code < 0x20) throw new McpJsonRpcParseError("invalid_json");
      if (code === 0x5c) {
        index++;
        const escape = input[index];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(input.slice(index + 1, index + 5))) {
            throw new McpJsonRpcParseError("invalid_json");
          }
          index += 5;
          continue;
        }
        if (!escape || !'"\\/bfnrt'.includes(escape)) {
          throw new McpJsonRpcParseError("invalid_json");
        }
      }
      index++;
    }
    throw new McpJsonRpcParseError("invalid_json");
  };

  const parseValue = (
    depth: number,
    path: readonly string[],
  ): unknown => {
    whitespace();
    valueCount++;
    if (valueCount > MAX_VALUES) {
      throw new McpJsonRpcParseError("too_many_values");
    }
    if (depth > MAX_DEPTH) throw new McpJsonRpcParseError("too_deep");
    const first = input[index];
    if (first === '"') return parseString();
    if (first === "{") {
      index++;
      whitespace();
      const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const keys = new Set<string>();
      if (input[index] === "}") {
        index++;
      } else {
        while (true) {
          whitespace();
          const key = parseString();
          if (UNSAFE_KEYS.has(key)) throw new McpJsonRpcParseError("unsafe_key");
          if (keys.has(key)) throw new McpJsonRpcParseError("duplicate_key");
          keys.add(key);
          whitespace();
          if (input[index] !== ":") throw new McpJsonRpcParseError("invalid_json");
          index++;
          const childPath = [...path, key];
          const childStart = (() => {
            whitespace();
            return index;
          })();
          const child = parseValue(depth + 1, childPath);
          if (path.length === 1 && path[0] === "params" && key === "arguments") {
            rawArgumentsJson = input.slice(childStart, index);
          }
          result[key] = child;
          whitespace();
          if (input[index] === "}") {
            index++;
            break;
          }
          if (input[index] !== ",") throw new McpJsonRpcParseError("invalid_json");
          index++;
        }
      }
      return result;
    }
    if (first === "[") {
      index++;
      whitespace();
      const result: unknown[] = [];
      if (input[index] === "]") {
        index++;
      } else {
        while (true) {
          result.push(parseValue(depth + 1, path));
          whitespace();
          if (input[index] === "]") {
            index++;
            break;
          }
          if (input[index] !== ",") throw new McpJsonRpcParseError("invalid_json");
          index++;
        }
      }
      return result;
    }
    for (const [literal, literalValue] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (input.startsWith(literal, index)) {
        index += literal.length;
        return literalValue;
      }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      input.slice(index),
    );
    if (number) {
      index += number[0].length;
      const parsed = Number(number[0]);
      if (!Number.isFinite(parsed)) throw new McpJsonRpcParseError("invalid_json");
      return parsed;
    }
    throw new McpJsonRpcParseError("invalid_json");
  };

  whitespace();
  const parsed = parseValue(0, []);
  whitespace();
  if (index !== input.length) throw new McpJsonRpcParseError("invalid_json");
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new McpJsonRpcParseError("invalid_envelope");
  }
  const value = parsed as Record<string, unknown>;
  if (
    value.jsonrpc !== "2.0" ||
    typeof value.method !== "string" ||
    Object.keys(value).some((key) =>
      key !== "jsonrpc" && key !== "id" && key !== "method" && key !== "params"
    ) ||
    (value.id !== undefined &&
      !(typeof value.id === "string" ||
        (typeof value.id === "number" && Number.isSafeInteger(value.id))))
  ) {
    throw new McpJsonRpcParseError("invalid_envelope");
  }
  return { value, rawArgumentsJson };
}
