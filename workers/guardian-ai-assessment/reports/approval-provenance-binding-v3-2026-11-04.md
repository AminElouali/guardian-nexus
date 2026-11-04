# Vínculo de procedencia para aprobaciones v3 — 2026-11-04

## Resultado

Implementado y validado en desarrollo un contrato de aprobación persistente que
vincula la procedencia de la evidencia al hash de la propuesta. No se ejecutó
Qwen en este hito. La prueba end-to-end usó únicamente el worker determinista y
acciones ficticias.

## Cambios verificados

- Las aprobaciones nuevas usan `bindingVersion: 3`. El hash incluye workspace,
  job, caso, hashes de propuesta y acción, acción sintética allow-listed,
  solicitante, rol, expiración, `modelInference`, `executionMode` y
  `toolCallOrigin`.
- Se aceptan solo dos combinaciones de origen:
  - Fixture: `guardian_policy_lab`, `deterministic_fixture`,
    `modelInference=false`, `controlled_fixture_not_llm`.
  - Qwen local: `guardian_qwen_policy_lab`, `real_local_qwen_inference`,
    `modelInference=true`, con origen explícito de marcador adaptado o de
    `message.tool_calls` nativa.
- Un resultado `no_proposal`, una combinación contradictoria o una acción sin
  allowlist no crea una aprobación. El worker guarda únicamente códigos y
  hashes ya redactados; no persiste prompts, respuestas ni argumentos crudos.
- Antes de aprobar y simular, la API verifica la procedencia de la fila contra
  el job y el caso persistidos, además de las validaciones existentes de
  workspace, rol, expiración, estado, binding e idempotencia. Las acciones
  permitidas siguen siendo simulaciones sintéticas de un solo uso.
- El E2E intentó cambiar una aprobación ligada a un fixture para hacerla pasar
  por evidencia Qwen. La API respondió `409`; la fila permaneció `pending` y
  `simulated_at` quedó nulo. No se despachó ninguna acción.
- La compatibilidad de lectura con filas v1/v2 se conserva. Las filas antiguas
  sin procedencia se muestran como no verificadas; una aprobación Qwen v2 no
  puede consumirse porque v2 no vinculaba el modo de inferencia ni el origen
  de la llamada.
- El esquema OpenAPI/Zod, PostgreSQL/Drizzle y la bandeja de aprobaciones
  muestran por separado fixture, marcador Qwen adaptado, llamada nativa y
  procedencia antigua no verificada. El cambio de esquema se aplicó solo a la
  base de desarrollo mediante el comando protegido `apply-rls-policies:dev`;
  no se tocó producción.

## Verificación

| Comprobación | Resultado |
| --- | --- |
| `pnpm --filter @workspace/api-spec run codegen` | Pasó; contratos generados |
| `pnpm -w run typecheck` | Pasó |
| `pnpm --filter @workspace/api-server test` | 75/75 |
| E2E sintético de aprobación con `NODE_ENV=development` | 1/1; `modelInference=false`; `dockerCommandRequestedByHarness=false` |
| `pnpm --filter @workspace/eu-security-platform exec tsx --test src/components/AiEvaluationPage.integration.test.tsx` | 8/8 |
| `pnpm --filter @workspace/guardian-agent-sdk test` | 13/13 |
| SDK Python con `unittest discover` | 8/8 |
| Build API | Pasó |
| Build web | Pasó; conserva avisos existentes de sourcemap y tamaño de chunk |
| Build SDK TypeScript | Pasó |
| Aplicación de RLS en desarrollo | Pasó; roles y RLS forzada aplicados solo en desarrollo |
| Captura de homepage pública de desarrollo | Renderiza; no equivale a una sesión Clerk ni valida la bandeja autenticada en navegador |

El E2E registró `SYNTHETIC_APPROVAL_E2E_SHA256`:
`485d0f7bbebb2a679be6f77dd8d7572f4216f1003c5432a59afb410b2fb5ebb7`.
El archivo de resultado redactado
`generated-artifacts/guardian-synthetic-approval-e2e.json` tiene SHA-256
`637011265bd2aab632586383868b6789cbfe8d1e70d3f471770f11a43cc3bec3`.

La batería Python específica del worker no se pudo ejecutar: el entorno no
tiene `pytest` (`No module named pytest`). No se instaló ningún paquete. Los
tests TypeScript del API sí ejercitaron el worker determinista y sus controles.

## Inferencia y bloqueos

No hubo inferencias Qwen nuevas. El artefacto histórico
`generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`
permanece sin cambios (SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`):
8 inferencias históricas, 7 propuestas por marcadores adaptados, 0
`message.tool_calls` nativas y 1 `no_proposal`. Esto no demuestra que las
aprobaciones v3 funcionen con una propuesta Qwen real.

El preflight histórico tampoco se alteró (SHA-256
`0b6246f76877a2874dc7834cacba1c76979a61e7871b1371515268dee8e85f52`).
Permanece bloqueado por socket Docker accesible y variables sensibles en el
entorno del proceso, y no acredita identidad independiente del broker ni de
la sesión de base de datos. No se sorteó el gate ni se inició Docker/Qwen.
Tampoco se usó una sesión autenticada real de Clerk.

## Archivos principales

API/worker y contratos: `ai-assessment-approval-actions.ts`,
`ai-assessment-worker.ts`, `ai-assessment-lab.ts`, OpenAPI y tipos generados.
Persistencia: `rls-policies.sql` y el esquema Drizzle. UI y pruebas:
`GuardianApprovalInbox.tsx`, integración de dashboard, pruebas de binding y
el E2E sintético de aprobación.

Los hashes SHA-256 de fuentes y evidencia se encuentran en el manifiesto
acompañante `approval-provenance-binding-v3-2026-11-04.sha256`.
