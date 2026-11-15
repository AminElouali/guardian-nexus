# Guardian Nexus — checkpoint del laboratorio PostgreSQL

## Actualización — policies de membresías en desarrollo (2026-11-15)

- Según la información del propietario, Actions run #13 terminó en verde sobre `a871b7f`; el informe final que inspeccionó reporta 12 tablas, 34 policies, 3 roles y 0 violaciones. Ese informe no se volvió a consultar durante esta operación.
- En la base de desarrollo de Replit se aplicaron en una transacción únicamente `workspace_memberships_insert_self` y `workspace_memberships_update_scoped`, usando las expresiones canónicas de `lib/db/sql/rls-policies.sql`. La verificación dentro de la transacción y una consulta posterior confirmaron la condición de creador/owner y que `public` conserva 34 policies.
- La base de desarrollo respondió como PostgreSQL 16.001; `/api/healthz` respondió HTTP 200 después del cambio.
- Respaldo de recuperación: checkpoint de Replit anterior a la operación, comprobado por el propietario en View Checkpoints. No se creó dump ni SHA-256; el identificador del checkpoint no fue proporcionado en esta sesión.
- No se modificaron grants, datos de aplicación, dependencias ni configuración.

## Estado actualizado — Actions run #12 y alcance del MVP

**Referencia de código:** `main` en `a871b7f`.

**Actions run #12:** verificado por el propietario en GitHub el 15 nov 2026 (estado `Success` sobre `5585c07`). El propietario inspeccionó el artefacto: post-schema y final reportan 12 tablas, 34 policies, 3 roles y 0 violaciones. El resultado incluye OIDC real de GitHub Actions, PostgreSQL 16 efímero, auditorías del catálogo RLS y E2E de aprobaciones.

### Implementado

- El laboratorio CI ejecutó OIDC real y validaciones contra PostgreSQL 16 efímero, incluidas auditorías RLS y E2E de aprobaciones, según Actions run #12.
- Las aprobaciones persistentes vinculan la propuesta/contexto mediante SHA-256, quedan protegidas por RLS y pasan por el Policy Engine determinista; el E2E usa fixtures y simulación, no efectos externos.
- El flujo sintético de reembolso está implementado; representa una propuesta y una simulación controlada, no el movimiento real de dinero.
- El auditor RLS incluye la corrección para detectar membresías inesperadas que involucran roles protegidos.
- El SDK de Python se usa en el E2E para proponer; la aprobación se prueba por la API directa.
- El SDK de TypeScript no está publicado.
- El worker de IA permanece deshabilitado; la validación del laboratorio no acredita aislamiento independiente del host ni autorización para habilitarlo.

### Proyectado o no implementado

- **Ejecución real de acciones de agentes:** no hay evidencia de ejecución real de un reembolso ni de otros efectos de negocio; el flujo de reembolso disponible es sintético.
- **Registro de agentes:** no implementado.
- **Motor de riesgo:** no implementado.
- **Auditoría encadenada y exportable:** no implementada; no hay registro encadenado ni artefacto de auditoría exportable del producto.
- **Worker de IA habilitado:** sigue deshabilitado.

El resultado del laboratorio PostgreSQL no equivale a una validación E2E completa del producto ni demuestra que el MVP global esté terminado.

### Limitaciones conocidas

- En las peticiones de la API, `app.user_id` procede de la identidad verificada por Clerk (`req.authUserId`), no del cuerpo ni de un encabezado del cliente. `app.workspace_id` procede del parámetro de workspace de la ruta; antes de fijarlo, `withWorkspaceUserTransaction` comprueba que la identidad autenticada pertenece a ese workspace. El E2E usa un middleware de prueba con usuarios sintéticos permitidos explícitamente.
- Las policies RLS existentes ahora exigen actor owner del mismo workspace en `USING` y `WITH CHECK`; para insertar `owner`, el usuario debe ser el creador del workspace, y `admin` no se admite por INSERT. No se cambiaron grants ni el número de policies.
- El laboratorio PostgreSQL 16 efímero local pasó: post-schema y final reportan respectivamente 12 tablas/34 policies/2 roles y 12 tablas/34 policies/3 roles, ambos con 0 violaciones. La identidad local se verificó, el login runtime se autenticó y el E2E reportó 1 pass, 0 fail y 0 skipped. Las probes revirtieron todas sus transacciones.
- En contexto viewer, el `UPDATE` a owner, el INSERT de owner en otro workspace y el INSERT de admin por la vía de creador fueron denegados. El INSERT inicial de owner por el creador y el cambio de rol por un owner fueron permitidos. Los auto-INSERT de `viewer` y `analyst` en otro workspace se conservan en el informe de probes, pero no son aserciones de aprobación del E2E.
- Límite conocido: un proceso con acceso directo como `app_runtime` puede cambiar los GUC `app.user_id`/`app.workspace_id`; por ello estas policies confían en el contexto fijado por la API y no autentican independientemente al actor. La API verifica la membresía antes de fijar el workspace; no se encontró una ruta de invitación. Directamente como `app_runtime`, el auto-INSERT de `viewer` o `analyst` en otro workspace sigue permitido si el contexto se fija a ese workspace.
- El informe sintético de las probes, sin IDs ni filas, está en `generated-artifacts/guardian-membership-role-probes.json`.

## Registro histórico — estado anterior al run #12

Este bloque conserva el checkpoint anterior como historial; sus referencias de HEAD, ejecución y publicación no describen el estado actualizado de arriba.

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
