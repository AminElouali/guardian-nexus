import assert from "node:assert/strict";
import { test } from "node:test";
import { createAssessmentOutputLimit } from "./assessment-output-limit";

test("assessment output overflow triggers cleanup once and stops counting retained output", () => {
  let containerStops = 0;
  let clientStops = 0;
  const limiter = createAssessmentOutputLimit(4, () => {
    containerStops += 1;
    clientStops += 1;
  });

  assert.deepEqual(limiter.recordChunk(4), {
    bytesReceived: 4,
    exceeded: false,
  });
  assert.deepEqual(limiter.recordChunk(1), {
    bytesReceived: 5,
    exceeded: true,
  });
  assert.deepEqual(limiter.recordChunk(100), {
    bytesReceived: 5,
    exceeded: true,
  });
  assert.equal(containerStops, 1);
  assert.equal(clientStops, 1);
});

test("assessment output limit rejects invalid bounds and chunk sizes", () => {
  assert.throws(
    () => createAssessmentOutputLimit(0, () => undefined),
    /invalid_assessment_output_limit/,
  );
  const limiter = createAssessmentOutputLimit(4, () => undefined);
  assert.throws(
    () => limiter.recordChunk(-1),
    /invalid_assessment_output_chunk/,
  );
});
