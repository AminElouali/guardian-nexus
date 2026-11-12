# Auditoría de catálogo RLS en CI — preparada, no ejecutada

Fecha: 2026-11-12  
HEAD inicial: `f5796d30e38723cae32bb896cd3b835f62de801c` (`main`, árbol limpio).

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
- El preflight real `assertRlsRuntimeReady()` ejecutado con el login
  `app_runtime_login` contra la misma base efímera, después de producir el
  inventario de catálogos.

El reporte registra por cada tabla su owner, `relrowsecurity`,
`relforcerowsecurity` y cantidad de políticas. Para cada política incluye
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
aserción adicional para la conexión runtime y el perfil de cola.

Las consultas del script se limitan a catálogos PostgreSQL y funciones de
privilegios; no leen filas de aplicación. El JSON contiene únicamente
metadatos de catálogo, definiciones de políticas y hashes de fuentes. No incluye
URLs, host, credenciales, identificadores de ejecución ni datos de aplicación.
Se guarda en `RUNNER_TEMP`; el job lo publica como artefacto con retención de
14 días incluso si la auditoría falla. El verificador exige el guard de destino
CI existente para `approval-e2e` antes de abrir conexiones; no habilita
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
