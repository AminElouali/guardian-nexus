import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { AiAssessmentLabJob } from "@workspace/api-client-react";
import { LabJobCard } from "./AiEvaluationPage";

test("renders the real API lab response in the authenticated dashboard card", () => {
  const responsePath = new URL(
    "../../../../generated-artifacts/ai-assessment-e2e-response.json",
    import.meta.url,
  );
  const jobs = JSON.parse(readFileSync(responsePath, "utf8")) as AiAssessmentLabJob[];
  const job = jobs.find(
    (candidate) =>
      candidate.status === "succeeded" && candidate.result?.engine === "garak",
  );
  assert.ok(job, "API integration must provide a completed real lab response");

  const markup = renderToStaticMarkup(
    createElement(LabJobCard, {
      job,
      canRun: false,
      onRetry: () => undefined,
      retryPending: false,
    }),
  );

  assert.match(markup, /data-testid="ai-lab-real-result"/);
  assert.match(markup, /EVALUACIÓN LOCAL · MOCK Y FIXTURES/);
  assert.match(markup, /Garak 0\.17\.1/);
  assert.match(markup, /Guardian Verification Engine/);
  assert.match(markup, /144/);
  if (job.result?.network.publicIpv6 === "unavailable") {
    assert.match(markup, /IPv6 no verificado/);
  } else {
    assert.match(markup, /IPv6 bloqueado/);
  }

  const localLlmJob = jobs.find(
    (candidate) =>
      candidate.status === "succeeded" &&
      candidate.result?.engine === "local_llm_lab",
  );
  assert.ok(localLlmJob, "API integration must provide a real local Qwen response");
  const localMarkup = renderToStaticMarkup(
    createElement(LabJobCard, {
      job: localLlmJob,
      canRun: false,
      onRetry: () => undefined,
      retryPending: false,
    }),
  );
  assert.match(localMarkup, /data-testid="local-llm-result"/);
  assert.match(localMarkup, /INFERENCIA REAL/);
  assert.match(localMarkup, /no es function calling nativo/);
  assert.match(localMarkup, /No disponible para clientes/);
  assert.match(localMarkup, /Qwen\/Qwen3-0\.6B-GGUF/);
});

test("renders native tool-call evidence separately from JSON emulation and fixtures", () => {
  const responsePath = new URL(
    "../../../../generated-artifacts/ai-assessment-native-e2e-response.json",
    import.meta.url,
  );
  const job = JSON.parse(
    readFileSync(responsePath, "utf8"),
  ) as AiAssessmentLabJob;
  assert.equal(job.status, "succeeded");
  assert.equal(job.profileId, "guardian-local-llm-native-tools-v1");
  assert.equal(job.result?.engine, "local_llm_lab");
  assert.equal(job.result?.toolInvocationMode, "native_tool_calls");

  const markup = renderToStaticMarkup(
    createElement(LabJobCard, {
      job,
      canRun: false,
      onRetry: () => undefined,
      retryPending: false,
    }),
  );
  assert.match(markup, /data-testid="native-tool-suite-result"/);
  assert.match(markup, /LLM REAL · TOOL CALLS NATIVAS/);
  assert.match(markup, /message\.tool_calls/);
  assert.match(markup, /el arnés seleccionó la función específica/);
  assert.match(markup, /calibration/);
  assert.match(markup, /holdout/);
  assert.match(markup, /IPv6 no verificado/);
  assert.match(markup, /no disponible para clientes/);
  assert.doesNotMatch(markup, /GN-EMAIL-EN-CAL/);
  assert.doesNotMatch(markup, /lab-recipient@invalid\.example/);
});
