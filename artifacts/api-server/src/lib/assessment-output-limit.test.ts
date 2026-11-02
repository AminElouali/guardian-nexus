import assert from "node:assert/strict";
import { test } from "node:test";
import {
  classifyAssessmentExecutionFailure,
  createAssessmentOutputCapture,
  createAssessmentOutputLimit,
  createAssessmentTimeout,
} from "./assessment-output-limit";

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

test("output capture retains only bounded data and never appends after overflow", () => {
  let stops = 0;
  const capture = createAssessmentOutputCapture(4, () => {
    stops += 1;
  });

  capture.recordChunk(Buffer.from("safe"));
  capture.recordChunk(Buffer.from("secret-overflow"));

  assert.equal(capture.output, "safe");
  assert.equal(capture.exceeded, true);
  assert.equal(capture.bytesReceived, 5);
  assert.equal(stops, 1);
});

test("execution failure classification distinguishes timeout, overflow, exit failure and success", () => {
  assert.equal(
    classifyAssessmentExecutionFailure({
      timedOut: false,
      outputExceeded: true,
      exitCode: null,
    }),
    "worker_output_limit_exceeded",
  );
  assert.equal(
    classifyAssessmentExecutionFailure({
      timedOut: true,
      outputExceeded: false,
      exitCode: null,
    }),
    "worker_timeout",
  );
  assert.equal(
    classifyAssessmentExecutionFailure({
      timedOut: false,
      outputExceeded: false,
      exitCode: 2,
    }),
    "container_execution_failed",
  );
  assert.equal(
    classifyAssessmentExecutionFailure({
      timedOut: false,
      outputExceeded: false,
      exitCode: 0,
    }),
    null,
  );
});

test("assessment timeout marks the run and calls stop once", async () => {
  let stops = 0;
  const timeout = createAssessmentTimeout(5, () => {
    stops += 1;
  });
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.equal(timeout.timedOut, true);
  assert.equal(stops, 1);
  timeout.cancel();
});
