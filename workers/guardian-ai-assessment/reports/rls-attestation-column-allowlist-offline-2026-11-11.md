# Allowlist efectiva de UPDATE para atestación — comprobación offline

Fecha: 2026-11-11

## Cambio incremental

Base: `760dbbe901c504a84e6eafdbf03dc25d4fd4d83f`, rama `main`.

Además de exigir los cinco `UPDATE` permitidos y rechazar el privilegio de
tabla, `assertRlsRuntimeReady()` ahora inspecciona los atributos vivos de la
tabla durante su consulta de readiness y rechaza cualquier grant de columna
`UPDATE` fuera de `consumed_at`, `status`, `response_sha256`, `supervisor_id` y
`updated_at`. Esto comprueba el conjunto efectivo sin depender de una lista
estática de las demás columnas.

## Verificación ejecutada

`pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='^offline RLS grants match the runtime privilege preflight$' src/lib/ai-assessment-qwen-evidence.test.ts`

- 1 test pasó, 0 fallaron.
- `git diff --check`: pasó.
- Solo se ejecutó el test contractual estático; no se consultó PostgreSQL ni se
  ejecutaron scripts, migraciones, servicios, workers, Qwen, Docker o red.

## Límite

La prueba confirma que el SQL de readiness expresa el mínimo privilegio
esperado. No demuestra que la base real tenga esos grants ni que el preflight
termine con éxito contra ella.
