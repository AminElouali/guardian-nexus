# Guardian Nexus — laboratorio PostgreSQL de aprobaciones

## Estado

- **Laboratorio local desechable:** ejecutado y aprobado.
- **PostgreSQL de Replit, producción o compartido:** no se usó.
- **GitHub Actions / OIDC real:** `PREPARADO_NO_EJECUTADO`; no se publicó ni despachó el workflow.
- **Aislamiento del host y readiness del worker:** no demostrado por este laboratorio.

## Diagnóstico reproducible de `drizzle-kit push`

Se mantuvo `drizzle-kit push` 0.31.11. No se sustituyó por `drizzle-kit export`: no se demostró que el SQL exportado incluya todo el esquema y las policies declaradas, se aplique transaccionalmente y produzca un catálogo equivalente.

En la fase diagnóstica, con PostgreSQL temporal creado exclusivamente para el laboratorio:

1. Sin los roles previos requeridos por las policies Drizzle, `push` terminó con código 0, creó las 12 tablas y dejó 0 policies.
2. Con los roles previos, `push` terminó con código 0 y dejó las 12 tablas y 34 entradas de policy, pero las definiciones de esas policies no tenían `USING` ni `WITH CHECK`.
3. La aplicación de `lib/db/sql/rls-policies.sql` creó las expresiones efectivas. Por ello el workflow conserva ese paso y la auditoría final compara las expresiones del catálogo con ese SQL canónico, además de usar Drizzle para el inventario estructural y los metadatos de policies.

Esto reproduce el riesgo del código/versión inspeccionados; no demuestra el estado de ninguna base externa ni que todas las versiones de Drizzle se comporten igual.

## Barreras por fase

El workflow protegido sigue siendo manual (`workflow_dispatch`) y conserva OIDC y su guard de destino. En el job, el orden de provisión es: verificar el destino, endurecer/crear el rol, `drizzle-kit push`, auditar el catálogo **post-schema**, aplicar el SQL RLS, grants, login y verificación del rol, y finalmente auditar el estado completo antes del E2E.

- **`post-schema`:** deriva el contrato estructural del esquema Drizzle y comprueba roles base, tablas, columnas, índices, constraints, shell de policy (tabla, nombre, comando, roles y modo permissive) y RLS habilitado. No exige todavía `FORCE RLS`, grants ni login.
- **`final`:** comprueba el estado completo, incluidos `FORCE RLS`, policies y sus expresiones semánticas, roles/grants y login. Los parsers desconocidos o expresiones no comparables fallan cerrados.
- Los informes contienen fase, estado, recuentos, códigos fijos y hashes de fuentes; no contienen filas de aplicación, credenciales ni URLs de conexión.

## Ejecución local segura

Desde el workspace:

```sh
env -i PATH="$PATH" HOME="$HOME" LANG=C pnpm lab:local
```

El lanzador rechaza un entorno padre con `DATABASE_URL`, `APP_RUNTIME_DATABASE_URL`, `APP_RUNTIME_DB_PASSWORD`, cualquier variable `PG*`, cualquier contexto `GITHUB_*`/`CI`, o `REPLIT_DEPLOYMENT=1`. Los procesos hijos reciben una lista permitida de variables, no el entorno completo.

El lanzador crea su propio `PGDATA` y socket Unix bajo un directorio temporal privado; `listen_addresses` queda vacío y el socket usa permisos `0700`. Antes de modificar el esquema verifica directorio, PID, ejecutable y argumentos del proceso, socket exclusivo, configuración del servidor y un nonce de instancia. Después de crear la base comprueba además el nonce en `COMMENT ON DATABASE`. Ningún nonce se registra en el informe. Al terminar usa `pg_ctl` con parada inmediata y elimina únicamente el directorio temporal de su propiedad si la parada, ruta, permisos y propietario quedan confirmados; si no puede confirmarlos, conserva el directorio y falla.

El lanzador ejecuta el pipeline completo: endurecimiento de roles, `push`, barrera post-schema, SQL RLS, grants, configuración y verificación de login, conexión real con el login runtime, auditoría final y E2E sintético persistido. Las herramientas y filas del E2E son ficticias.

## Resultado local comprobado

En la última ejecución del laboratorio:

- Identidad del PostgreSQL temporal: verificada.
- Auditoría post-schema: aprobada, 12 tablas, 34 policies base, 2 roles.
- Auditoría final: aprobada, 12 tablas, 34 policies, 3 roles.
- Conexión autenticada con el login runtime: aprobada.
- E2E sintético de aprobaciones persistentes: aprobado.
- Códigos de discrepancia: ninguno.
- No quedó un directorio temporal PostgreSQL del prefijo del laboratorio.

Informes sanitizados de esa ejecución:

- `generated-artifacts/guardian-postgres-local-a9e0e05578788304ce2acf05ece3b882/postgres-lab-post-schema.json`
  - SHA-256: `2f6d6e90bdba76a24c14d17d20bd79e2f863aa81ce1ed17eed193723ca34a5f4`
- `generated-artifacts/guardian-postgres-local-a9e0e05578788304ce2acf05ece3b882/postgres-lab-final.json`
  - SHA-256: `ee8f5b22cd5b7550bd9d78733ce7baa9a9bdfe8b593c138c231be217cd9ffe9e`

Hashes de fuentes registrados por ambos informes:

- esquema: `b5227a35bc2c34eb500400b0d653047099ebda8dc701784094356e0bc98c65b1`
- policies SQL: `c0b4d08fb458e7f995ae30424388e15cd7d5a0fa9f3d99ed9903691ee751d4f9`
- roles: `eecc5eb31a48ede231fa83963295e05acfb0ef17c84909d1dafac4465480a35a`
- bootstrap: `8910d6f56b90c61d99bbe7c3e6036308d2b027c169c08606d468f2350af28c5f`
- contrato: `c159aa282f94dbb3aee9d6ec18de392d24001c0e0e4f273dc1f48efdb7c93b0e`

## Verificación ejecutada

- `pnpm --filter @workspace/api-server exec tsx --test src/lib/approval-e2e-db-guard.test.ts` — 2 aprobadas.
- `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern 'persistent approval E2E rejects a loopback URL without private-socket proof' src/lib/ai-assessment-qwen-evidence.test.ts` — 1 aprobada.
- `pnpm --filter @workspace/api-server exec tsx --test ../../lib/db/src/rls-catalog-audit.test.ts ../../lib/db/src/rls-catalog-phase-audit.test.ts` — 14 aprobadas.
- `pnpm --filter @workspace/api-server run typecheck` — correcto.
- `pnpm --filter @workspace/db exec tsc -p tsconfig.json --tsBuildInfoFile /tmp/guardian-nexus-db-lab.tsbuildinfo` — correcto.
- `git diff --check` — correcto.
- `env -i PATH="$PATH" HOME="$HOME" LANG=C pnpm lab:local` — laboratorio PostgreSQL temporal completo aprobado.

## Límites y siguiente evidencia necesaria

La ejecución local acredita el comportamiento contra el clúster temporal creado por este lanzador, no contra Replit Database, producción, un servicio compartido ni el host de GitHub Actions. Tampoco acredita la adquisición/verificación OIDC real de GitHub, aislamiento independiente del host, autorización humana real, ni readiness/admisión del worker. La evidencia restante requiere publicar el cambio y ejecutar el workflow manual protegido en GitHub; el artefacto de ese job debe revisarse sin tratarlo como prueba de aislamiento del host.
