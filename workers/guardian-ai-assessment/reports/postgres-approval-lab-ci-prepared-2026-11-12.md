# PostgreSQL Approval Lab en GitHub Actions — preparación

Fecha: 2026-11-12
HEAD inicial inspeccionado: `20ad2ce30940bc56bc2d8cb4033c34e57059fcd3`
(`main`, árbol limpio).

## Resultado

No había workflows CI en `.github` al inicio de este cambio. Se preparó
`.github/workflows/postgres-approval-lab.yml` como workflow portable, sin
modificar workflows de Replit ni configuración externa. No se pudo comprobar si
el repositorio está conectado a GitHub o si Actions está habilitado. El workflow
no se ha ejecutado; no hay resultados PostgreSQL de CI.

El job `postgres-approval-lab` declara un servicio PostgreSQL 16 propio del
runner GitHub-hosted y limita permisos a `contents: read`. Crea la base
`guardian_approval_lab_ci` desde la base administrativa vacía `postgres`, y
ejecuta en este orden:

1. Guard de destino para el servicio/DB administrativa.
2. `CREATE DATABASE guardian_approval_lab_ci`.
3. Guard de destino para la DB de laboratorio.
4. `pnpm --filter @workspace/db run push`.
5. `harden-runtime-role:dev`.
6. `apply-rls-policies:dev`.
7. `grant-runtime-role:dev`.
8. `configure-runtime-login:dev`.
9. `verify-runtime-role:dev`.
10. Guard de destino y `ai-assessment-synthetic-approval-e2e.test.ts`.

GitHub destruye el contenedor de servicio al terminar el job. El workflow no
usa URLs de DB de secrets ni variables de repositorio. La contraseña efímera se
deriva del ID/intento/SHA del run y no se imprime. El guard
`isGitHubActionsApprovalLabTarget()` exige el workflow/job exactos, el ID,
intento y SHA válidos, etapa declarada, servicio `postgres`, usuario, puerto
5432, nombre de DB y contraseña derivados del mismo run. Comprueba también que
las URLs administrativa y runtime del E2E apunten al mismo servicio/DB, sin
query ni fragmento. En contexto GitHub, cualquier URL que no cumpla el contrato
se rechaza sin caer al guard local de loopback.

El módulo `@workspace/db` elimina `APP_RUNTIME_DATABASE_URL` del entorno al
inicializar el pool. Para que el test gated pueda volver a verificar el destino
sin conservar la URL, el paso previo ejecuta el guard con ambas URLs y emite un
marcador no secreto ligado al run; el test acepta ese marcador solo con el
workflow/job/run/etapa esperados y sin variables `PG*` alternativas.

El arnés existente usa el router API en un servidor HTTP local y lanza procesos
Python deterministas de fixtures; sus propias aserciones fijan
`modelInference=false`, `externalEffects=false` y ausencia de Docker. No lanza
Qwen ni el broker/worker de producción. La ejecución de este harness en el
runner GitHub aún queda pendiente.

## Pruebas locales ejecutadas

Todas fueron offline y no abrieron conexiones:

- `pnpm --filter @workspace/api-server exec tsx --test src/lib/approval-e2e-db-guard.test.ts`
  — 2 pasaron, 0 fallaron.
- `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='^persistent approval E2E requires explicit opt-in to a named loopback disposable database$' src/lib/ai-assessment-qwen-evidence.test.ts`
  — 1 pasó, 0 fallaron.
- `pnpm --filter @workspace/api-server run typecheck` — pasó.
- `pnpm exec prettier --check .github/workflows/postgres-approval-lab.yml artifacts/api-server/src/lib/approval-e2e-db-guard.ts artifacts/api-server/src/lib/approval-e2e-db-guard.test.ts artifacts/api-server/src/scripts/verify-approval-lab-ci-target.ts workers/guardian-ai-assessment/deployment/lab-as-code/postgresql/README.md`
  — pasó.
- `git diff --cached --check` — pasó tras revisar los siete archivos staged.

Durante el desarrollo, una primera prueba reveló que el guard no contrastaba la
etapa entregada con la etapa esperada por el llamador. Se corrigió para exigir
coincidencia exacta; la prueba focalizada pasó después. No se tocó la lógica de
RLS ni las aprobaciones.

## Límites y pendientes

- No se inició PostgreSQL en Replit, no se conectó a ninguna DB y no se
  ejecutaron scripts DB, `drizzle-kit push`, migraciones ni el E2E persistente.
- No se ejecutó el workflow GitHub. La configuración y las pruebas sintéticas
  solo acreditan que el job está preparado y que el guard rechaza destinos
  incompatibles; no acreditan persistencia, roles, privilegios efectivos ni RLS.
- El preflight existente cuenta las 12 tablas/34 policies, exige `ENABLE` y
  `FORCE`, presencia de `qual`/`with_check` y roles permitidos, pero no compara
  semánticamente las 34 expresiones con una referencia canónica. No se añadió
  una segunda lista de predicados: duplicaría la lógica Drizzle/SQL y podría
  divergir. El E2E existente ejercita dos tenants en rutas de aprobación/cola,
  pero no prueba por comportamiento las 34 policies sobre las 12 tablas.
- Para activar la validación hace falta subir el commit a un repositorio GitHub
  con Actions habilitado o usar `workflow_dispatch`. Esta dependencia externa
  no se verificó.
- `hostBoundaryReady`, `integratedAssessmentReady` y `workerAdmission` no se
  modifican ni se acreditan en esta fase.

## SHA-256 de artefactos revisados

- `.github/workflows/postgres-approval-lab.yml`:
  `cc761aad34afc2ce60b8b5f2797c7634cb100b25e167408574fcf405c3cec3dc`
- `artifacts/api-server/src/lib/approval-e2e-db-guard.ts`:
  `847f2447c3a11e7627ecd3d94543c41d31a6f5b940b96fb6d6a2a4f01e95e7a0`
- `artifacts/api-server/src/lib/approval-e2e-db-guard.test.ts`:
  `e6f61a30116d6067fb3fb5bab7dac1372ab80fa4748b850e98bb1455c082f846`
- `artifacts/api-server/src/scripts/verify-approval-lab-ci-target.ts`:
  `36b94cd82e0aef9581fa3e220f02d487a235cb660bf8b088585348688bc901a7`
- `deployment/lab-as-code/postgresql/README.md`:
  `e4071c3936050cbfd7cf97c114764bdac72832b702389dbe0d246e57d4e2cf5a`
