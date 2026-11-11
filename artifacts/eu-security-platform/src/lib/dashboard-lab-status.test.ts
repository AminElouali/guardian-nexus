import assert from "node:assert/strict";
import { test } from "node:test";
import { getDashboardLabStatusPresentation } from "./dashboard-lab-status";

test("dashboard lab status presents API states without implying real-system analysis", () => {
  const ready = getDashboardLabStatusPresentation("ready");
  assert.equal(ready.title, "Disponible para pruebas sintéticas");
  assert.match(ready.description, /no equivale a analizar sistemas reales/i);
  assert.equal(ready.tone, "positive");

  const disabled = getDashboardLabStatusPresentation("disabled");
  assert.equal(disabled.title, "Deshabilitado");
  assert.match(disabled.description, /no acepta nuevas evaluaciones/i);

  const unavailable = getDashboardLabStatusPresentation("unavailable");
  assert.equal(unavailable.title, "No disponible");
  assert.match(unavailable.description, /no se asume que esté listo/i);

  for (const state of ["loading", "error", null, undefined, "unexpected"]) {
    const presentation = getDashboardLabStatusPresentation(state);
    assert.notEqual(presentation.title, ready.title, `state=${String(state)}`);
    assert.doesNotMatch(
      `${presentation.title} ${presentation.description}`,
      /assessment_broker_identity_unverified|hostBoundaryReady|Docker|Qwen/i,
    );
  }
});
