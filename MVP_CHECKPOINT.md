# Guardian Nexus — checkpoint del laboratorio PostgreSQL

## Estado de esta iteración

- HEAD sin modificar: `0e49be7c5bb3672e9e97f3467768c021f2ab4f62`, rama `main`.
- No se creó commit, no se hizo push/fetch y no se cambiaron referencias Git.
- Se implementó y ejecutó un laboratorio PostgreSQL efímero local. No se usó la base de Replit ni una base compartida o de producción.
- GitHub Actions/OIDC real sigue `PREPARADO_NO_EJECUTADO`. El workflow no se publicó ni despachó.
- No se abrieron gates: aislamiento independiente del host, atestación, `hostBoundaryReady`, `integratedAssessmentReady` y admisión del worker no quedan acreditados por esta prueba.

## Resultado verificable

Último `pnpm lab:local`:

- identidad de la instancia temporal verificada mediante `PGDATA`, PID, argumentos del proceso, socket Unix privado, nonce del servidor y nonce en el comentario de la base;
- `listen_addresses` vacío; conexión por socket Unix en directorio temporal privado;
- post-schema: aprobado, 12 tablas, 34 shells de policy, 2 roles;
- final: aprobado, 12 tablas, 34 policies, 3 roles;
- autenticación mediante conexión real del login runtime: aprobada;
- E2E sintético de aprobaciones persistidas en la instancia temporal: aprobado;
- cero códigos de discrepancia y directorio temporal eliminado tras confirmar la parada.

Informes sanitizados:

- post-schema SHA-256 `2f6d6e90bdba76a24c14d17d20bd79e2f863aa81ce1ed17eed193723ca34a5f4`
- final SHA-256 `ee8f5b22cd5b7550bd9d78733ce7baa9a9bdfe8b593c138c231be217cd9ffe9e`

Ambos informes registran los mismos hashes de fuentes: esquema `b5227a35bc2c34eb500400b0d653047099ebda8dc701784094356e0bc98c65b1`; policies SQL `c0b4d08fb458e7f995ae30424388e15cd7d5a0fa9f3d99ed9903691ee751d4f9`; roles `eecc5eb31a48ede231fa83963295e05acfb0ef17c84909d1dafac4465480a35a`; bootstrap `8910d6f56b90c61d99bbe7c3e6036308d2b027c169c08606d468f2350af28c5f`; contrato `c159aa282f94dbb3aee9d6ec18de392d24001c0e0e4f273dc1f48efdb7c93b0e`.

## Decisión técnica

Se conserva `drizzle-kit push` 0.31.11. En la fase diagnóstica, en PostgreSQL temporal, se reprodujo que `push` puede devolver código 0 pese a omitir DDL: sin roles previos dejó 12 tablas y 0 policies; con roles previos dejó 12 tablas y 34 shells, pero sin predicados `USING`/`WITH CHECK`. La fuente de las expresiones efectivamente aplicadas continúa siendo `lib/db/sql/rls-policies.sql`.

Por eso el workflow incluye auditorías distintas: la barrera post-schema valida estructura y policies base antes de aplicar RLS; la auditoría final valida expresiones, RLS forzado, grants y roles después de la provisión. No se sustituyó `push` por `export`; equivalencia transaccional y de catálogo de `export` no está demostrada.

## Comprobaciones ejecutadas

- `approval-e2e-db-guard.test.ts`: 2/2 aprobadas.
- Caso focalizado de guard en `ai-assessment-qwen-evidence.test.ts`: 1/1 aprobado.
- `rls-catalog-audit.test.ts` + `rls-catalog-phase-audit.test.ts`: 14/14 aprobadas.
- Typecheck de `@workspace/api-server`: correcto.
- Typecheck de `@workspace/db` con caché incremental en `/tmp`: correcto.
- `git diff --check`: correcto.
- `env -i PATH="$PATH" HOME="$HOME" LANG=C pnpm lab:local`: aprobado contra la instancia temporal propia.

La última fase de trabajo solo tocó código del laboratorio, tests y documentación. Los artefactos generados están ignorados por Git.

## Pendiente

1. Revisar y publicar los cambios por el proceso autorizado.
2. Ejecutar el workflow manual protegido en GitHub y revisar su artefacto sanitizado; hasta entonces OIDC de Actions es código preparado, no evidencia real.
3. Validar por separado supervisor/trust anchor, atestación fresca e aislamiento del host antes de cualquier readiness de worker.

Este checkpoint no declara Guardian Nexus ni el MVP global completados.
