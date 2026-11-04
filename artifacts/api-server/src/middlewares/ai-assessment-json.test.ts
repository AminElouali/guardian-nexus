import assert from "node:assert/strict";
import express from "express";
import { once } from "node:events";
import { test } from "node:test";
import {
  AI_ASSESSMENT_LAB_JOB_ROUTE,
  AI_ASSESSMENT_LAB_JSON_LIMIT_BYTES,
  AI_ASSESSMENT_POLICY_PREVIEW_ROUTE,
  aiAssessmentLabBodySizeErrorHandler,
  aiAssessmentLabJsonParser,
} from "./ai-assessment-json";

test("oversized evaluation JSON returns 413 before a job handler can run", async () => {
  const app = express();
  let jobHandlerCalls = 0;
  app.use(AI_ASSESSMENT_LAB_JOB_ROUTE, aiAssessmentLabJsonParser);
  app.use(AI_ASSESSMENT_POLICY_PREVIEW_ROUTE, aiAssessmentLabJsonParser);
  app.use(express.json());
  const endpoint = (_req: express.Request, res: express.Response) => {
    jobHandlerCalls += 1;
    res.status(202).end();
  };
  app.post("/api/workspaces/:workspaceId/ai-security-assessments/lab/jobs", endpoint);
  app.post("/api/workspaces/:workspaceId/ai-security-assessments/lab/policy-preview", endpoint);
  app.use(aiAssessmentLabBodySizeErrorHandler);

  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  try {
    for (const path of [
      "/api/workspaces/00000000-0000-4000-8000-000000000001/ai-security-assessments/lab/jobs",
      "/api/workspaces/00000000-0000-4000-8000-000000000001/ai-security-assessments/lab/policy-preview",
    ]) {
      const response = await fetch(`http://127.0.0.1:${address.port}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          idempotencyKey: "oversized-body-check-0001",
          padding: "x".repeat(AI_ASSESSMENT_LAB_JSON_LIMIT_BYTES + 1),
        }),
      });
      assert.equal(response.status, 413, path);
      assert.deepEqual(await response.json(), {
        error: "AI assessment request body too large",
      });
    }
    assert.equal(jobHandlerCalls, 0);
  } finally {
    await new Promise<void>((resolveClose, rejectClose) => {
      server.close((error) => {
        if (error) rejectClose(error);
        else resolveClose();
      });
    });
  }
});
