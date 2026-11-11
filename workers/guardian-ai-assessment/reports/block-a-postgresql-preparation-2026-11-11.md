# Bloque A PostgreSQL: preparación offline y límites

Fecha: 2026-11-11. Estado inicial verificado: `main`, HEAD
`dc64f857570dc07fb51ef4654329e555c18cb6a1`, árbol limpio.

## Resultado del inventario estático

Drizzle define doce tablas tenant-protected: `workspaces`,
`workspace_memberships`, `assets`, `workspace_monthly_usage`,
`workspace_audit_events`, `workspace_integrations`, `provider_connections`,
`connector_oauth_states`, `connector_jobs`, `ai_assessment_jobs`,
`host_boundary_attestation_challenges` y `ai_assessment_approval_requests`.
El preflight `assertRlsRuntimeReady()` exige respectivamente
2/3/1/1/2/3/4/3/4/5/3/3 políticas; la suma declarada es 34. El SQL explícito
aplica `ENABLE` y `FORCE ROW LEVEL SECURITY` a las doce. Diez políticas están
declaradas en Drizzle y el SQL aporta las de atestación y aprobación.

Índices de idempotencia/lease/binding relevantes: jobs por
`(workspace_id,idempotency_key)`, slot único y estado/lease; aprobaciones
únicas por `(workspace_id,job_id,case_id)` y por workspace/estado/expiración;
challenges únicos por nonce; memberships y uso mensual únicos por tenant.
`lib/db` contiene Drizzle push y SQL RLS explícito, pero no un directorio de
migraciones versionadas.

Roles declarados: `app_runtime` como rol de grupo no-login,
`app_runtime_login` con membresía sin herencia y `SET` explícito, y
`app_ai_assessment_worker` para la cola. `bootstrap-runtime-role.mjs` endurece
atributos y grants; el preflight comprueba owners, roles, RLS y privilegios.
La primera iteración alineó los grants de challenges y aprobaciones; esta
iteración hace que el modo `harden` cree `app_runtime` cuando falta con
`NOLOGIN`, `NOINHERIT`, `NOBYPASSRLS` y sin atributos privilegiados.

## Preparación añadida

- `deployment/lab-as-code/postgresql/README.md` documenta prerequisitos, orden
  de provisionamiento, guard del E2E, separación de la DB de workflows y
  evidencia exigida. Reutiliza los scripts, SQL y harness existentes.
- El E2E de aprobación ahora consulta cinco estados desde un pool nuevo:
  `approved` de finanzas/soporte, `denied`, `expired` y `pending` tras revocar
  el rol. El código está preparado, pero no fue ejecutado contra PostgreSQL.
- La prueba contractual offline asegura que el rol de grupo se crea/hardena
  antes de conceder membership al worker y conserva el allowlist de grants.

## Pruebas ejecutadas en esta sesión

1. `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='^(TEST ONLY finance approval lifecycle binds proposal, tenant, actor, role, and expiry|TEST ONLY support approval lifecycle binds proposal, tenant, actor, role, and expiry|persistent approval E2E requires explicit opt-in to a named loopback disposable database|offline RLS grants match the runtime privilege preflight)$' src/lib/ai-assessment-qwen-evidence.test.ts`
   - 4 pasaron, 0 fallaron. Son fixtures/contratos en memoria y chequeos de
     fuente. La parte del guard recibe un objeto sintético; no leyó el
     `process.env` real ni intentó abrir DB.
2. Tras añadir la creación segura del rol:
   `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='^offline RLS grants match the runtime privilege preflight$' src/lib/ai-assessment-qwen-evidence.test.ts`
   - 1 pasó, 0 fallaron.
3. `node --check lib/db/scripts/bootstrap-runtime-role.mjs`: pasó; no ejecutó el
   script.
4. `pnpm --filter @workspace/api-server exec tsc --noEmit --pretty false --project tsconfig.json`: pasó.
5. `git diff --check`: pasó.

No se ejecutaron `push`, scripts de roles/RLS, pruebas E2E de PostgreSQL,
servidores/workflows, Qwen, workers, procesos del broker, Docker/socket,
migraciones ni red.

## Instancia y evidencia real

No hay un workflow PostgreSQL en la configuración visible y el repositorio solo
contiene plantillas de `pg_hba`/`pg_ident` y documentación de laboratorio. La
documentación oficial de Replit consultada describe la DB de desarrollo por
proyecto y la DB de producción al publicar, pero no una DB efímera adicional
para pruebas. La DB de desarrollo pertenece al mismo proyecto y no satisface
la separación solicitada. Referencias:

- https://docs.replit.com/features/data-and-storage/development-and-production
- https://docs.replit.com/features/data-and-storage/sql-database

No se intentó detectar un servidor local ni abrir conexiones, por lo que no se
afirma que no exista un proceso PostgreSQL fuera de los workflows: se afirma
que no hay una instancia desechable **acreditada** para esta tarea. El guard del
E2E solo valida opt-in, entorno de desarrollo, nombre dedicado y URL loopback
sin overrides; no demuestra que un listener local no sea un túnel ni que la DB
sea distinta de la app compartida. Esa prueba requiere confirmación del
responsable del host antes de cualquier escritura.

Resultado de Block A:

- Alineación de contratos y pruebas sintéticas: implementadas y comprobadas.
- Aprobaciones durables desde una conexión nueva: cobertura añadida, bloqueada
  sin la DB desechable.
- RLS efectivo, dos-tenant isolation, roles/owners reales y persistencia E2E:
  no verificados.
- `hostBoundaryReady` / `integratedAssessmentReady`: no modificados ni
  acreditados. API/broker/worker permanecen cerrados.
- API Server workflow figura `failed`, sin puerto ni logs nuevos; no se reinició
  y la causa actual no puede deducirse de esta fase.

## Reanudación segura

El siguiente paso de Bloque A requiere que el responsable provea y confirme una
instancia PostgreSQL vacía, efímera, local y separada de la DB de workflows, más
un proceso puntual cuyo destino se haya verificado por fuera de este repositorio.
Solo entonces ejecutar la secuencia de provisionamiento y el E2E descritos en
`deployment/lab-as-code/postgresql/README.md`. No abrir gates de host como
sustituto de esa evidencia.
