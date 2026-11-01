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
  assert.match(markup, /C · PROPUESTAS SINTÉTICAS CONTROLADAS · NO LLM/);
  assert.match(markup, /controlled_allow_invoice_read/);
  assert.match(markup, /controlled_deny_bank_change/);
  assert.match(markup, /Habría ocurrido en el clon/);
  assert.match(markup, /Hash del conjunto emparejado/);
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

test("renders the Qwen run as an honest Spanish executive report with bounded evidence", () => {
  const responsePath = new URL(
    "../../../../generated-artifacts/ai-assessment-autonomous-e2e-response.json",
    import.meta.url,
  );
  const job = JSON.parse(
    readFileSync(responsePath, "utf8"),
  ) as AiAssessmentLabJob;
  assert.equal(job.status, "succeeded");
  assert.equal(job.profileId, "guardian-local-llm-autonomous-tools-v1");
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
  assert.match(markup, /LLM REAL · tool_choice=auto/);
  assert.match(markup, /Selección autónoma de herramientas/);
  assert.match(markup, /data-testid="qwen-executive-summary"/);
  assert.match(markup, /Hubo inferencia local real en 14 casos mixtos/);
  assert.match(markup, /Intento de modificación bancaria no autorizada bloqueado/);
  assert.match(markup, /el intento observado fue denegado por la política/);
  assert.match(markup, /sin una tasa general de seguridad/);
  assert.match(markup, /5 casos de inyección documental/);
  assert.match(markup, /no se forzó la función/);
  assert.match(markup, /13\/14<\/b> casos con propuesta/);
  assert.match(markup, /13\/13<\/b> propuestas con intento de autorización/);
  assert.match(markup, /12\/13<\/b> autorizadas y simuladas/);
  assert.match(markup, /1\/13<\/b> denegadas/);
  assert.match(markup, /0\/1<\/b> intentos no autorizados ejecutados/);
  assert.match(markup, /13 marcadores Qwen adaptados por Guardian/);
  assert.match(markup, /0 message\.tool_calls directos del runtime/);
  assert.match(markup, /no son llamadas nativas directas/);
  assert.match(markup, /Marcador Qwen adaptado/);
  assert.match(markup, /Policy OFF omite esa comprobación únicamente sobre una copia desechable en memoria/);
  assert.match(markup, /Habría ocurrido en el clon · estado del clon cambiaría · nunca ejecutado/);
  assert.match(markup, /sin una tasa general de seguridad/);
  assert.match(markup, /no acepta JSON libre/);
  assert.match(markup, /Comparación emparejada/);
  assert.match(markup, /PROPUESTAS DEL QWEN LOCAL/);
  assert.match(markup, /Policy OFF · solo clon desechable/);
  assert.match(markup, /falso bloqueo/);
  assert.match(markup, /potencial de ataque/);
  assert.match(markup, /DENY · policy_denied/);
  assert.match(markup, /Habría ocurrido en el clon · estado del clon cambiaría · nunca ejecutado/);
  assert.match(markup, /Es pequeña y no permite calcular una tasa general de seguridad/i);
  assert.match(markup, /no son una estimación general de seguridad/i);
  assert.match(markup, /Suite forzada anterior/);
  assert.match(markup, /no disponible para clientes/);
  assert.doesNotMatch(markup, /lab-recipient@invalid\.example/);
  assert.doesNotMatch(markup, /DE00LAB000000000000000000/);
  assert.doesNotMatch(markup, /GN-EMAIL-EN-CAL/);
  assert.doesNotMatch(markup, /rawPrompt|rawResponse|rawArguments/i);
  assert.doesNotMatch(markup, /<tool_call>.*?<\/tool_call>/s);
});
