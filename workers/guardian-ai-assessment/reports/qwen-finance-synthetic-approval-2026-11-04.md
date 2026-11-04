# Aprobación sintética de finanzas — 2026-11-04

## Cambio

Se añadió cobertura unitaria del allowlist de aprobación sintética de finanzas:
el caso benigno de cambio de cuenta ficticio produce un recibo de simulación
en un clon en memoria con hashes; el caso de cambio bancario instruido desde
contenido no confiable y un nombre de herramienta distinto no son reanudables.
La prueba usa valores fijos del laboratorio y no cambia el contrato, la política,
la API ni el runtime. No ejecuta Qwen ni acredita una propuesta originada por
el modelo.

El verificador PostgreSQL del kit Linux ahora declara explícitamente
`tenant_policy_predicates=not_checked`. Su resultado de identidades, grants y
`FORCE ROW LEVEL SECURITY` no prueba que las expresiones RLS impidan acceso a
filas de otro tenant. La guía exige ejecutar aparte los tests sintéticos de
lectura/escritura cruzada antes de aceptar un host.

## Verificaciones ejecutadas, en serie

- `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-qwen-evidence.test.ts`:
  **10/10**.
- `pnpm --filter @workspace/api-server test`: **76/76**.
- `PYTHONPATH=workers/guardian-ai-assessment PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s workers/guardian-ai-assessment/tests -p 'test_lab_as_code_guards.py' -v`:
  **10/10** después de añadir la comprobación de que la guía y salida del
  verificador no afirman haber probado los predicados RLS.
- `pnpm --filter @workspace/api-server run typecheck`: pasó.
- `pnpm --filter @workspace/api-server run build`: pasó.
- E2E sintético de aprobación con `NODE_ENV=development`:
  **1/1**. La primera invocación sin `NODE_ENV` terminó en la precondición
  `NODE_ENV=development` antes de abrir el flujo; no se modificó el test ni se
  omitió la condición. La repetición seleccionó explícitamente desarrollo.
  Salida: `modelInference=false`,
  `dockerCommandRequestedByHarness=false`; hash de corrida
  `4ce2c83270893c97d43fbfee2c8c29ae9884457c5684a656f35d34f4ba7cd85e`;
  JSON redactado SHA-256
  `a7372574d98c1e938cc4cc29288fcde7c7b72c306830e043281fdda5dbadbdd2`.

## No ejecutado / límites

- No hubo inferencia Qwen nueva, ni tool calls nativas, ni marcadores adaptados,
  ni `no_proposal` nuevos. El E2E y los casos de aprobación son fixtures.
- No se repitieron suites worker distintas de los 10 controles del kit Linux,
  SDK, UI ni un recorrido Qwen API→worker en esta iteración.
- El preflight del host no se ejecutó de nuevo; el gate existente sigue
  bloqueando el runner por la falta de separación acreditada de API, broker,
  socket Docker y sesión de base de datos. Los tests de kit comprueban que la
  plantilla falla cerrada; no acreditan identidades independientes reales.
- El kit de laboratorio usa ejemplos; sus servicios externos no están
  conectados ni se desplegaron.

## Integridad

Los SHA-256 de la prueba modificada, este informe y el artefacto E2E se
registran en `qwen-finance-synthetic-approval-2026-11-04.sha256`.
