# Revisión de cobertura offline de aprobaciones

Fecha: 2026-11-11

## Alcance

Revisión de tests ya existentes para evitar duplicar cobertura de Finanzas y
Atención al cliente. Solo se ejecutaron tests unitarios filtrados con datos
sintéticos. No hubo inferencia Qwen, runner, worker, servidor API, broker,
Docker/socket, PostgreSQL, migraciones ni conexiones de red. No se inspeccionó
ni modificó `.replit`, variables, secretos o configuración de despliegue.

## Hallazgos

`src/lib/ai-assessment-qwen-evidence.test.ts` ya contiene:

- El ledger `TEST ONLY` de Finanzas y Soporte: `pending` sin simulación,
  duplicado/idempotencia en memoria, tenant cruzado, propuesta modificada,
  autoaprobación, rol no autorizado, expiración, rechazo, aprobación, replay y
  una única simulación ficticia.
- Binding v3 sensible a tenant, job, caso, propuesta, acción, solicitante,
  rol, expiración y procedencia; diferencia origen adaptado frente a
  `runtime_message_tool_calls` y rechaza procedencia inconsistente.
- Binding de replay sensible a binding de propuesta, aprobador, rol, hora y
  resultado sintético.
- Un guard unitario que admite únicamente un destino PostgreSQL loopback
  explícitamente nombrado como desechable. No intenta conectarse a la base.

Por ello, el test adicional de cuatro casos introducido en el ciclo anterior
duplicaba la mayoría de estas comprobaciones. Se redujo a una única regresión
que cubre el espacio restante: la binding v3 debe distinguir una afirmación
sintética de fixture de afirmaciones sintéticas de procedencia adaptada/nativa,
y debe ligar el `syntheticActionRef`. Los valores `real_local_qwen_inference`
son solo entradas de hash de prueba: no hubo inferencia real.

No se modificó lógica de producción. Los tests existentes son modelos en
memoria y no acreditan persistencia, atomicidad, RLS ni aislamiento.

## Pruebas ejecutadas en esta revisión

1. `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='^(TEST ONLY (finance|support) approval lifecycle binds proposal, tenant, actor, role, and expiry|approval binding v3 is provenance-bound and rejects unverified origins|offline finance/support approval contract binds expiry, approver audit, replay, and idempotent clone receipts|persistent approval E2E requires explicit opt-in to a named loopback disposable database)$' src/lib/ai-assessment-qwen-evidence.test.ts`
   - 5 pasaron, 0 fallaron.
   - Solo se ejecutaron callbacks unitarios seleccionados; no se abrió
     PostgreSQL ni se ejecutó la prueba E2E.
2. `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-approval-actions.test.ts`
   - 1 pasó, 0 fallaron.
3. `git diff --check`
   - Pasó antes del commit de la regresión reducida.

No se ejecutaron typecheck, suites amplias ni pruebas de servicios.

## Estado y límites

Commit base al iniciar: `551232d01f9d61f9f434184c88c8341e20b1233e`.
Commit de la regresión reducida: `93742fdf434252fd10f090b4bd4e05d0bccc828a`.

El SHA-256 actual del test retenido es
`7fb0e59189898e0c7056d137e6dcc506831e17a501eb0228136dd39a961ee751`.

La prueba de guard no acredita que exista una base desechable; solo comprueba
el rechazo de destinos de configuración no autorizados. El siguiente paso de
persistencia requiere una base PostgreSQL de laboratorio desechable,
explícitamente autorizada y con roles segregados. Inferencia Qwen y apertura
del worker requieren, además, atestación independiente real de aislamiento.
No se debe sustituir ninguna dependencia por un mock ni cambiar los gates.
