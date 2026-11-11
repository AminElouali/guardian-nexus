# Contrato offline de grants del preflight RLS

Fecha: 2026-11-11

## Cambios

Base: `bc5b72677dafee524615dbe9b96c92da83479afe`, rama `main`, árbol limpio.

- `assertRlsRuntimeReady()` ahora exige `SELECT,INSERT` a nivel de tabla para
  `host_boundary_attestation_challenges`, rechaza `UPDATE` a nivel de tabla y
  comprueba `UPDATE` en las cinco columnas declaradas por
  `lib/db/sql/rls-policies.sql`: `consumed_at`, `status`, `response_sha256`,
  `supervisor_id` y `updated_at`.
- Los modos `grant` y `configure-login` de
  `lib/db/scripts/bootstrap-runtime-role.mjs` conceden los nueve `UPDATE`
  column-scoped que ya requiere el preflight de aprobaciones. No se añadió
  `UPDATE` global.
- Se amplió el test estático focalizado existente para comparar el preflight,
  el SQL RLS y ambos bloques del bootstrap; no ejecuta SQL ni el script.

## Verificación ejecutada

`pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='^offline RLS grants match the runtime privilege preflight$' src/lib/ai-assessment-qwen-evidence.test.ts`

- 1 test pasó, 0 fallaron.
- `git diff --check`: pasó.
- No se ejecutaron typecheck, suites amplias, servidor, workflow, PostgreSQL,
  scripts de roles/RLS, migraciones, Qwen, workers, Docker, sockets ni red.

## Límites

Esto comprueba la coherencia estática de los archivos y los grants declarados,
no que esos grants hayan sido aplicados ni que el preflight RLS pase contra una
base real. El estado de tablas, políticas, roles, propietarios y privilegios
reales permanece sin verificar.
