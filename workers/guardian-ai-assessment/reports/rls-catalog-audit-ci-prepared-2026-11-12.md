# Auditoría de catálogo RLS en CI — preparada, no ejecutada

Fecha: 2026-11-12  
HEAD inicial: `f5796d30e38723cae32bb896cd3b835f62de801c` (`main`, árbol limpio).
HEAD al cierre: `8ab21374f4260c6d99c2c49fd58171f5485b6059` (`main`). El workspace
registró ese commit local durante el trabajo; las últimas correcciones de
seguridad/documentación siguen como cambios locales sin commit. No se hizo push.

## Estado

Se amplió el workflow efímero existente para producir un artefacto
`guardian-postgres-rls-catalog-report.json` desde el servicio PostgreSQL del
propio job. Estado de esta entrega: **PREPARADO_NO_EJECUTADO**. El workflow no
se lanzó, no se conectó GitHub y no se ejecutó PostgreSQL en este workspace.

## Qué comprobará el job

El verificador usa como fuentes existentes:

- `expectedRlsPolicyCounts` compartido con `assertRlsRuntimeReady()` para el
  conjunto de 12 tablas y los recuentos esperados de 34 políticas.
- Las declaraciones de `pgPolicy()` en Drizzle para identidad, comando y rol
  de destino; los nombres/tablas deben corresponder también con
  `CREATE/ALTER POLICY` en `lib/db/sql/rls-policies.sql`.
- `bootstrap-runtime-role.mjs` y `rls-policies.sql` para derivar membresías y
  grants efectivos esperados, incluidos grants por columna.
- El archivo compartido `rls-catalog-contract.ts` para los nombres de las 12
  tablas y los recuentos esperados.

El reporte registra por cada tabla su owner (exige `postgres`, el usuario de
provisionamiento del servicio), `relrowsecurity`, `relforcerowsecurity` y
cantidad de políticas. Para cada política incluye
nombre, tabla, comando, modo permisivo, roles, `qual` y `with_check`; falla ante
identidad, rol, comando, modo o forma de predicado inesperados. Exige
`app_runtime` en las políticas de todas las tablas salvo
`ai_assessment_jobs`, cuyas políticas se comparan con los roles exactos
declarados por Drizzle.

El reporte también registra atributos seguros de los tres roles,
pertenencias directas y la matriz `pg_has_role(MEMBER/USAGE)`. Compara la matriz
`SELECT/INSERT/UPDATE/DELETE` para los tres roles en las 12 tablas y el permiso
`UPDATE` por columna en `ai_assessment_jobs`,
`host_boundary_attestation_challenges` y
`ai_assessment_approval_requests`. El preflight existente se conserva como
consumidor del contrato compartido de tablas/recuentos; este informe no invoca
el preflight y usa el inventario `pg_has_role` y privilegios de catálogo sin
consultar filas.

Las consultas del script se limitan a catálogos PostgreSQL y funciones de
privilegios; no leen filas de aplicación. El JSON contiene únicamente
metadatos de catálogo, definiciones de políticas y hashes de fuentes (esquema,
SQL RLS, bootstrap y contrato de recuentos). No incluye URLs, host, credenciales,
identificadores de ejecución ni datos de aplicación.
Se guarda en `RUNNER_TEMP`; cuando existe, el job lo publica como artefacto con
retención de 14 días incluso si la auditoría falla. Si no llega a crearse,
`upload-artifact` ignora el archivo ausente. El verificador exige el guard de
destino CI existente para `approval-e2e` antes de abrir conexiones; no habilita
destinos locales ni remotos arbitrarios.

## Límites explícitos

- Las expresiones `qual`/`with_check` efectivas se incluyen en el artefacto y se
  exige que estén presentes para el comando correspondiente. No se compara su
  equivalencia semántica con Drizzle/SQL: PostgreSQL deparsea las expresiones y
  el repositorio no dispone de un AST canónico compartido para una comparación
  fiable sin duplicar la lógica de políticas. La revisión semántica o una
  prueba de comportamiento por política sigue pendiente.
- El informe no ejecuta `assertRlsRuntimeReady()`: ese preflight contiene una
  lectura acotada de `ai_assessment_jobs.result`, incompatible con el requisito
  de no leer filas de aplicación. El informe marca
  `runtimePreflight: omitted_catalog_only_audit`; el E2E separado sigue
  pendiente para la verificación de comportamiento del login runtime/worker.
- El inventario estático y las pruebas con snapshots sintéticos solo acreditan
  el comparador y las fuentes. No acreditan que el workflow haya corrido, ni
  que PostgreSQL real tenga esas tablas, políticas o grants.
- El job depende de que este commit esté disponible en GitHub Actions y de que
  Actions esté habilitado. No se hizo push, conexión GitHub ni
  `workflow_dispatch`.
- No cambia ni demuestra `hostBoundaryReady`,
  `integratedAssessmentReady` o `workerAdmission`.

## Validaciones locales ejecutadas

En serie, sin servicios:

1. `pnpm --filter @workspace/api-server exec tsx --test ../../lib/db/src/rls-catalog-audit.test.ts`
   — 3 pasaron, 0 fallaron. Parser de fuentes canónicas, 12/34,
   privilegios/membresías y snapshots sintéticos con fallos cerrados.
2. `pnpm --filter @workspace/api-server exec tsx --test src/lib/approval-e2e-db-guard.test.ts`
   — 2 pasaron, 0 fallaron. Incluye aserciones estáticas sobre el orden del
   workflow, guard antes de conexión y carga del artefacto.
   El workflow también programa el test del comparador antes de crear su DB.
3. `pnpm --filter @workspace/db exec tsc --build tsconfig.json`
   — pasó; solo compilación de tipos/declaraciones.
4. `pnpm --filter @workspace/api-server run typecheck`
   — pasó.
5. `git diff --check` — pasó.
6. Prettier — pasó para workflow, guard/test, script, paquete, helper, tests,
   contrato y documentación. Se excluyó `lib/db/src/index.ts` del chequeo de
   archivo completo porque Prettier señala formato preexistente en líneas no
   relacionadas; las líneas modificadas no contienen cambios de formato.

No se ejecutaron Qwen, workers, API/broker, PostgreSQL, `psql`, migraciones,
Docker, sockets, red, GitHub Actions ni pruebas E2E.

## SHA-256 de los archivos relevantes

Calculados sobre el estado de trabajo descrito por este informe:

| Archivo                                                                      | SHA-256                                                            |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `.github/workflows/postgres-approval-lab.yml`                                | `f2d577929cc7ae2840334339b52ccb1ad6be1cd440b54b618303be1e9f549892` |
| `artifacts/api-server/src/lib/approval-e2e-db-guard.test.ts`                 | `c9b91b6209d543ef3a0a7cf4104d42a0cfc3fb46ae82d75f3c5957bda7ce3d98` |
| `artifacts/api-server/src/scripts/verify-rls-catalog.ts`                     | `30c5469e1b2eba4f5f46b4a5e6ed4e6911bef72ce23a5ed8b7bd01cda9d2dd2c` |
| `lib/db/package.json`                                                        | `f56dad2a0685fe4072e310646e45cb33ebabc8ba97ef78ceafbee4d0ba8bd7ca` |
| `lib/db/src/index.ts`                                                        | `90d3ea48cf6a98e25d9d49e3c2d6ae0e0f1e1d83c9a2098fc656c26a35d34ef8` |
| `lib/db/src/rls-catalog-audit.ts`                                            | `318d412b36e58c3d5a69d30cfda4026fd94b4bca524d17694f53858c6b3c639b` |
| `lib/db/src/rls-catalog-audit.test.ts`                                       | `6e69a97e96f06faa31df23a0c944efc45c78ce8ab108a5adf2ef9bb139e1d246` |
| `lib/db/src/rls-catalog-contract.ts`                                         | `c159aa282f94dbb3aee9d6ec18de392d24001c0e0e4f273dc1f48efdb7c93b0e` |
| `workers/guardian-ai-assessment/deployment/lab-as-code/postgresql/README.md` | `280ce0b329bccaf7a644b4bf21ad82786102279335aadf21a8171cbfc7a4ddb4` |
