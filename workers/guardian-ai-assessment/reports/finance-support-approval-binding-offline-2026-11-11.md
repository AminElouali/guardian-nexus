# Finanzas y Soporte: validación offline de bindings de aprobación — 2026-11-11

## Estado y alcance

- HEAD base: `32bc5e14b04a7a9a2de29c39cac3525e82273720`, rama `main`, árbol
  limpio antes del cambio.
- No se alteró lógica de producción. Se añadió un test unitario puro para los
  helpers de aprobación existentes y se ejecutaron cuatro tests focalizados del
  worker que cubren las propuestas sintéticas de Finanzas/Soporte.
- Commit de tests: `142cbebed9d4c958f1f49a214b7ba43b328976d9`.
- SHA-256 del test nuevo:
  `9380d0c6d016876bc745bb70bd6224df1ec9529793e7c1810fe9ab400957ef2f`.

## Contrato comprobado estáticamente

- `computeApprovalProposalBindingV3` enlaza workspace/tenant, job, caso,
  `proposalSha256`, `actionSha256`, referencia sintética, solicitante, rol,
  expiración y las tres etiquetas de procedencia. `caseId` identifica el
  contexto de laboratorio; los hashes de propuesta y acción representan la
  propuesta y sus argumentos.
- `computeApprovalReplayBinding` enlaza la binding de propuesta, decisión
  aprobada, identidad/rol de quien decide, instante de decisión y el resultado
  sintético.
- `isApprovalDecisionWindowOpen` solo acepta `pending` con expiración futura.
  El endpoint compara la binding almacenada, la calculada y la enviada antes de
  actualizar la decisión; el flujo de replay/idempotencia está en el endpoint y
  la transacción PostgreSQL, no en estos helpers puros.
- El recorrido Qwen existente devuelve `approval_required_before_dispatch` y
  no llama al simulador para `REQUIRE_APPROVAL`; las pruebas focalizadas del
  worker comprueban el comportamiento con respuestas fijas. La tabla de
  acciones permitidas limita Finanzas a la propuesta sintética de cambio
  bancario y Soporte a reembolsos sintéticos exactos.

## Pruebas ejecutadas

1. `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-approval-actions.test.ts`
   — **4 pasaron, 0 fallaron**. Comprueba variación de hash con tenant,
   job/caso, propuesta/argumentos, actor/rol, expiración y procedencia;
   separa las bindings de Finanzas y Soporte; verifica binding de replay
   determinista y sensible a quien decide/resultado; y prueba que solo una
   aprobación pendiente y no expirada está en ventana de decisión.
2. Pruebas unitarias del worker — **4 pasaron, 0 fallaron**:
   - `GuardianAgentPolicyLabTests.test_remaining_profiles_adapted_markers_are_policy_gated_offline`
   - `QwenPolicyLabDispatchSelfCheckTests.test_adversarial_and_no_proposal_cases_never_receive_approval_binding`
   - `QwenPolicyLabDispatchSelfCheckTests.test_support_refund_tool_has_fixed_arguments_and_approval_only_semantics`
   - `QwenPolicyLabDispatchSelfCheckTests.test_invalid_finance_arguments_cannot_become_an_approval_request`
3. `git diff --check` — pasó.

La primera invocación de los tests del worker seleccionó tres métodos bajo una
clase incorrecta y produjo errores del cargador, sin ejecutar esos métodos. Se
corrigió el selector y la corrida focalizada posterior pasó.

## Límites y pendientes

- Los inputs de tests son valores fijos sintéticos con procedencia
  `deterministic_fixture`; no son inferencia Qwen, tool_calls nativas reales ni
  aprobación humana.
- No se ejecutó `ai-assessment-synthetic-approval-e2e.test.ts`: requiere la ruta
  API y PostgreSQL/RLS. Aunque el código de esa suite contiene escenarios de
  cross-tenant, decisiones concurrentes/replay, expiración y auditoría, aquí no
  se verificó su ejecución ni persistencia.
- Los tests de binding prueban que cambios de contexto cambian el digest y que
  la ventana de decisión se cierra para estados terminales; no demuestran por sí
  solos rechazo transaccional de replay, idempotencia durable, concurrencia,
  autorización HTTP/RBAC ni RLS. Esas afirmaciones siguen pendientes de una DB
  de laboratorio autorizada y E2E.
- No se ejecutó Qwen ni el subprocess del runner; tampoco worker, servidor API,
  broker, servicios, Docker, sockets, PostgreSQL, migraciones o red. Solo se
  lanzaron los dos runners de tests focalizados (tsx y unittest). No se tocaron
  `.replit`, variables, secretos, gates ni fixtures. No se ejecutó typecheck ni
  suite amplia.

## Siguiente paso seguro

El contrato offline de binding queda cubierto. La siguiente evidencia útil para
replay/idempotencia y RLS requiere ejecutar la suite E2E existente contra una
instancia PostgreSQL desechable autorizada con roles segregados. Hasta contar
con esa instancia, no ampliar estas pruebas con un almacén en memoria que
pretenda demostrar persistencia o atomicidad.
