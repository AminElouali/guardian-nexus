import assert from "node:assert/strict";
import fc from "fast-check";
import test from "node:test";
import { evaluateApprovalAction } from "@workspace/db/approval-action-catalog";
import {
  classifyMcpToolCall,
  type McpToolClassification,
  type McpToolClassificationInput,
} from "./mcp-tool-classifier";

const SERVER_ID = "guardian-demo-mcp";
const REGISTERED_TOOL_NAMES = ["reply_to_support", "send_external_email"];
const PROPERTY_SEED = 0x5eed2026;
const RUNS_PER_PROPERTY = 500;

const validSupportArgs = {
  ticket_id: "TICKET-SYNTH-42",
  recipient_email: "support@example.test",
  recipient_type: "internal",
  compensation_cents: 0,
  template_id: "synthetic-support-reply-v1",
};

const validEmailArgs = {
  to: "qa@example.test",
  template_id: "guardian-demo-email-v1",
};

function classifyArbitrary(input: unknown): McpToolClassification {
  return classifyMcpToolCall(input as McpToolClassificationInput);
}

function assertFixedSeedProperty(property: fc.IProperty<unknown>): void {
  fc.assert(property, { seed: PROPERTY_SEED, numRuns: RUNS_PER_PROPERTY });
}

const anyUnicodeString = fc.string({ unit: "binary", maxLength: 100 });
const oneCharacterReplacement = fc.string({
  unit: "binary",
  minLength: 1,
  maxLength: 1,
});
const singleCharacterToolMutation = fc.constantFrom(...REGISTERED_TOOL_NAMES)
  .chain((name) =>
    fc.tuple(
      fc.integer({ min: 0, max: name.length - 1 }),
      oneCharacterReplacement,
    ).map(([index, replacement]) =>
      `${name.slice(0, index)}${replacement}${name.slice(index + 1)}`
    )
  )
  .filter((name) => !REGISTERED_TOOL_NAMES.includes(name));

const arbitraryNonRegisteredToolName = fc.oneof(
  anyUnicodeString,
  singleCharacterToolMutation,
  fc.constantFrom(
    "REPLY_TO_SUPPORT",
    " reply_to_support",
    "reply_to_support ",
    "rеply_to_support",
    "reply_to_support\u200b",
    "reply_to_support\u0000",
    "x".repeat(65),
  ),
).filter((name) => !REGISTERED_TOOL_NAMES.includes(name));

const validSupportArgsArbitrary = fc.record({
  ticket_id: fc.constant(validSupportArgs.ticket_id),
  recipient_email: fc.constantFrom(
    "support@example.test",
    "agent@example.test",
    "qa@example.test",
  ),
  recipient_type: fc.constantFrom("internal", "external"),
  compensation_cents: fc.integer({ min: 0, max: 1_000_000 }),
  template_id: fc.constant(validSupportArgs.template_id),
});

const arbitraryJson = fc.json({ maxDepth: 16, stringUnit: "binary" });
const arbitraryKeyValueObject = fc.tuple(
  fc.string({ unit: "binary", maxLength: 40 }),
  fc.jsonValue({ maxDepth: 8, stringUnit: "binary" }),
).map(([key, value]) => JSON.stringify({ [key]: value }));
const duplicateJsonKeys = fc.string({
  unit: "binary",
  maxLength: 40,
}).map((key) => {
  const quotedKey = JSON.stringify(key);
  return `{${quotedKey}:0,${quotedKey}:1}`;
});
const deeplyNestedJson = fc.integer({ min: 9, max: 20 }).map((depth) =>
  `${"[".repeat(depth)}0${"]".repeat(depth)}`
);
const oversizedJson = fc.string({ unit: "binary", maxLength: 32 }).map((prefix) =>
  JSON.stringify({ payload: `${prefix}${"x".repeat(8_500)}` })
);
const unsafeKeyJson = fc.constantFrom("__proto__", "constructor", "prototype")
  .map((key) => JSON.stringify({ [key]: { nested: true } }));
const arbitraryArgumentsJson = fc.oneof(
  arbitraryJson,
  arbitraryKeyValueObject,
  duplicateJsonKeys,
  deeplyNestedJson,
  oversizedJson,
  unsafeKeyJson,
  validSupportArgsArbitrary.map((args) => JSON.stringify(args)),
  fc.constant(JSON.stringify(validEmailArgs)),
);

const throwingGetterCall = Object.defineProperties({}, {
  serverId: { get: () => { throw new Error("getter must not be invoked"); } },
  toolName: { get: () => { throw new Error("getter must not be invoked"); } },
  argumentsJson: {
    get: () => { throw new Error("getter must not be invoked"); },
  },
});

test("property: every non-identical tool name fails closed", () => {
  assertFixedSeedProperty(
    fc.property(arbitraryNonRegisteredToolName, (toolName) => {
      const result = classifyMcpToolCall({
        serverId: SERVER_ID,
        toolName,
        argumentsJson: JSON.stringify(validSupportArgs),
      });
      assert.equal(result.status, "unknown");
      assert.equal(result.actionType, "unknown");
      assert.equal(result.blockRequired, true);
    }),
  );
});

test("property: every unregistered server id fails closed", () => {
  assertFixedSeedProperty(
    fc.property(
      anyUnicodeString.filter((serverId) => serverId !== SERVER_ID),
      (serverId) => {
        const result = classifyMcpToolCall({
          serverId,
          toolName: "reply_to_support",
          argumentsJson: JSON.stringify(validSupportArgs),
        });
        assert.equal(result.status, "unknown");
        assert.equal(result.actionType, "unknown");
        assert.equal(result.blockRequired, true);
      },
    ),
  );
});

test("property: arbitrary MCP metadata never changes the complete result", () => {
  const metadataArbitrary = fc.tuple(
    fc.anything(),
    fc.anything(),
    fc.anything(),
    fc.anything(),
    fc.anything(),
  );
  assertFixedSeedProperty(
    fc.property(metadataArbitrary, ([
      description,
      title,
      annotations,
      inputSchema,
      responseText,
    ]) => {
      const baseline = classifyMcpToolCall({
        serverId: SERVER_ID,
        toolName: "reply_to_support",
        argumentsJson: JSON.stringify(validSupportArgs),
      });
      const withMetadata = classifyMcpToolCall({
        serverId: SERVER_ID,
        toolName: "reply_to_support",
        argumentsJson: JSON.stringify(validSupportArgs),
        description,
        title,
        annotations,
        inputSchema,
        responseText,
      });
      assert.deepEqual(withMetadata, baseline);
    }),
  );
});

test("property: arbitrary and adversarial JSON is classified only when catalog-valid", () => {
  assertFixedSeedProperty(
    fc.property(arbitraryArgumentsJson, (argumentsJson) => {
      const result = classifyMcpToolCall({
        serverId: SERVER_ID,
        toolName: "reply_to_support",
        argumentsJson,
      });
      if (result.status === "classified") {
        assert.equal(result.blockRequired, false);
        assert.ok(result.validatedArguments);
        const evaluated = evaluateApprovalAction(
          result.actionType,
          result.validatedArguments,
        );
        assert.equal(evaluated.ok, true);
        if (evaluated.ok) {
          assert.deepEqual(
            Object.keys(result.validatedArguments).sort(),
            Object.keys(evaluated.definition.argumentSchema.properties).sort(),
          );
          assert.deepEqual(result.validatedArguments, evaluated.args);
        }
      } else {
        assert.equal(result.blockRequired, true);
        assert.equal(result.validatedArguments, null);
      }
    }),
  );
});

test("property: hashes are deterministic and change when any argument value changes", () => {
  const changedField = fc.constantFrom(
    "ticket_id",
    "recipient_email",
    "recipient_type",
    "compensation_cents",
    "template_id",
  );
  assertFixedSeedProperty(
    fc.property(validSupportArgsArbitrary, changedField, fc.nat(), (
      args,
      field,
      salt,
    ) => {
      const raw = JSON.stringify(args);
      const first = classifyMcpToolCall({
        serverId: SERVER_ID,
        toolName: "reply_to_support",
        argumentsJson: raw,
      });
      const repeated = classifyMcpToolCall({
        serverId: SERVER_ID,
        toolName: "reply_to_support",
        argumentsJson: raw,
      });
      const changedArgs = {
        ...args,
        [field]: `changed-${field}-${salt}`,
      };
      const changed = classifyMcpToolCall({
        serverId: SERVER_ID,
        toolName: "reply_to_support",
        argumentsJson: JSON.stringify(changedArgs),
      });

      assert.match(first.canonicalInputSha256 ?? "", /^[a-f0-9]{64}$/);
      assert.equal(first.canonicalInputSha256, repeated.canonicalInputSha256);
      assert.notEqual(first.canonicalInputSha256, changed.canonicalInputSha256);
    }),
  );
});

test("property: arbitrary inputs, invalid JSON and throwing getters never throw", () => {
  const arbitraryInput = fc.oneof(
    fc.anything(),
    fc.constant(null),
    fc.integer(),
    fc.string({ unit: "binary", maxLength: 100 }).map((argumentsJson) => ({
      serverId: SERVER_ID,
      toolName: "reply_to_support",
      argumentsJson,
    })),
    fc.constant(throwingGetterCall),
  );
  assertFixedSeedProperty(
    fc.property(arbitraryInput, (input) => {
      let result: McpToolClassification | undefined;
      assert.doesNotThrow(() => {
        result = classifyArbitrary(input);
      });
      assert.ok(result);
      assert.ok(["classified", "rejected", "unknown"].includes(result.status));
      assert.equal(result.blockRequired, result.status !== "classified");
    }),
  );
});
