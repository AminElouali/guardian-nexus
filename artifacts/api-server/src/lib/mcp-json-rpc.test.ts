import assert from "node:assert/strict";
import { test } from "node:test";
import {
  McpJsonRpcParseError,
  parseMcpJsonRpcRequest,
} from "./mcp-json-rpc";

test("strict MCP JSON-RPC parser preserves the exact arguments JSON text", () => {
  const rawArguments =
    '{ "to":"qa@example.test","template_id":"guardian-demo-email-v1" }';
  const parsed = parseMcpJsonRpcRequest(
    `{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"send_external_email","arguments":${rawArguments}}}`,
  );
  assert.equal(parsed.rawArgumentsJson, rawArguments);
  assert.equal(parsed.value.method, "tools/call");
});

test("strict MCP JSON-RPC parser rejects duplicate envelope and argument keys", () => {
  assert.throws(
    () => parseMcpJsonRpcRequest(
      '{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"tools/list"}',
    ),
    (error: unknown) =>
      error instanceof McpJsonRpcParseError &&
      error.code === "duplicate_key",
  );
  assert.throws(
    () => parseMcpJsonRpcRequest(
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_external_email","arguments":{"to":"qa@example.test","to":"other@example.test"}}}',
    ),
    (error: unknown) =>
      error instanceof McpJsonRpcParseError &&
      error.code === "duplicate_key",
  );
});

test("strict MCP JSON-RPC parser rejects unsafe keys, deep input and oversized bodies", () => {
  assert.throws(
    () => parseMcpJsonRpcRequest(
      '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"__proto__":{}}}',
    ),
    (error: unknown) =>
      error instanceof McpJsonRpcParseError && error.code === "unsafe_key",
  );
  const nested = `${"[".repeat(18)}0${"]".repeat(18)}`;
  assert.throws(
    () => parseMcpJsonRpcRequest(
      `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":${nested}}}`,
    ),
    (error: unknown) =>
      error instanceof McpJsonRpcParseError && error.code === "too_deep",
  );
  assert.throws(
    () => parseMcpJsonRpcRequest(" ".repeat(16 * 1024 + 1)),
    (error: unknown) =>
      error instanceof McpJsonRpcParseError &&
      error.code === "body_too_large",
  );
});

test("strict MCP JSON-RPC parser rejects malformed request envelopes", () => {
  assert.throws(
    () => parseMcpJsonRpcRequest('{"jsonrpc":"1.0","id":1,"method":"tools/list"}'),
    (error: unknown) =>
      error instanceof McpJsonRpcParseError &&
      error.code === "invalid_envelope",
  );
  assert.throws(
    () => parseMcpJsonRpcRequest("null"),
    (error: unknown) =>
      error instanceof McpJsonRpcParseError &&
      error.code === "invalid_envelope",
  );
});
