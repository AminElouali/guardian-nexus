# Continuación offline de Guardian Nexus — 2026-11-12

## Estado inicial y alcance

- Inicio: rama `main`, HEAD
  `b583d5576c15bcc089aea9e7c1a72b528e3a77d6`, árbol limpio.
- SHA-256 inicial de `MVP_CHECKPOINT.md`:
  `5f746c9766cd4334222fb26491115c795ddec82305b4f184242c62f656d178f7`.
- Se revisaron logs ya disponibles, código de arranque/preflight, contratos y
  pruebas focalizadas. No se reinició el API Server ni se ejecutaron Qwen,
  workers, E2E, Docker, sockets, PostgreSQL, migraciones, red o GitHub Actions.
- No se inspeccionaron `.replit`, secretos, valores de entorno ni configuración
  de despliegue.

## Diagnóstico del API Server

El log disponible muestra que el bundle compiló correctamente y que el proceso
intentó arrancar. `assertRlsRuntimeReady()` falló antes de `app.listen()` con:

> Tenant RLS policies are missing, unqualified, or not forced; refusing to start.

Esto demuestra que el preflight RLS rechazó el catálogo de la base a la que ya
apuntaba el proceso; por ello el API no abrió el puerto. El mensaje no identifica
qué subcondición concreta falló. No se consultó la base de datos, por lo que no
se puede atribuir a una tabla, política o valor de `pg_policies` en particular.

Comprobación estática local:

- El preflight exige las 12 tablas protegidas, `ENABLE` y `FORCE`, los conteos
  de política declarados, expresiones `qual`/`with_check` aplicables y roles
  permitidos.
- `lib/db/sql/rls-policies.sql` contiene 34 sentencias `CREATE/ALTER POLICY`;
  sus nombres coinciden con las 34 declaraciones `pgPolicy` del esquema Drizzle.
- Los conteos estáticos por tabla coinciden con `expectedPolicyCounts`; el SQL
  declara `ENABLE` y `FORCE` para las 12 tablas esperadas.
- Esta comparación de fuentes no acredita que el catálogo de la DB activa tenga
  esas políticas ni que sus predicados efectivos sean correctos. No se encontró
  una discrepancia estática que justifique modificar SQL o relajar el preflight.

**Resultado:** causa de nivel superior confirmada (fallo del preflight RLS antes
de escuchar); causa de catálogo específica no verificable sin acceso de solo
lectura a PostgreSQL. No se aplicó corrección especulativa.

## UX, admisión y contratos offline

Pruebas ejecutadas en serie:

1. `pnpm --filter @workspace/eu-security-platform exec tsx --test --test-name-pattern='workspace fallback labels API unavailability and keeps a retry action' src/components/AiEvaluationPage.integration.test.tsx`
   — **1 pasada, 0 fallidas**. Confirma mensaje de API no disponible, redacción
   que no filtra detalle privado y acción de reintento invocable.
2. `pnpm --filter @workspace/api-server exec tsx --test src/lib/assessment-worker-api-admission.test.ts`
   — **1 pasada, 0 fallidas**. Dobles para correo/BBDD confirman rechazo con
   estado 503 y cero lecturas de idempotencia, inserciones, reservas de cuota o
   enqueues mientras el broker está cerrado.
3. `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-approval-actions.test.ts`
   — **1 pasada, 0 fallidas**. Binding sintético separa fixture, origen adaptado,
   origen nativo y acción distinta.
4. `pnpm --filter @workspace/api-server exec tsx --test src/lib/approval-e2e-db-guard.test.ts`
   — **2 pasadas, 0 fallidas**. Incluye el guard de target de CI y el contrato
   estático del workflow; no ejecuta el job PostgreSQL.
5. Selección focalizada de `src/lib/ai-assessment-qwen-evidence.test.ts` con
   `--test-name-pattern` para lifecycle TEST ONLY de Finanzas/Soporte, opt-in
   E2E, binding/procedencia v3, expiración/auditoría/replay/idempotencia en
   clones y grants RLS estáticos — **6 pasadas, 0 fallidas**.
6. Segunda selección del mismo archivo para correlación de propuestas
   adaptadas, inyección de facturas y composición de propuesta→Policy ON→
   replay de aprobación — **3 pasadas, 0 fallidas**.
7. `pnpm --filter @workspace/eu-security-platform exec tsx --test src/lib/dashboard-lab-status.test.ts`
   — **1 pasada, 0 fallidas**.

Total de esta continuación: **15 casos focalizados pasaron; 0 fallaron**.
No se ejecutó typecheck ni suite amplia porque no se modificó código de
producción. No se añadieron tests: la revisión encontró cobertura existente para
los comportamientos solicitados.

## Límites de evidencia y gates

- La UX de error/reintento tiene regresión focalizada aprobada; no demuestra que
  el servidor API esté operativo.
- La admisión de correo/BBDD se probó con dobles, no contra API/DB en vivo.
- Los contratos de aprobación, expiración, replay, binding y procedencia se
  probaron en memoria/sintético. No acreditan persistencia PostgreSQL ni RLS.
- El workflow PostgreSQL CI está presente y su guard local pasó, pero GitHub
  Actions y PostgreSQL no se ejecutaron.
- El protocolo de atestación sigue siendo contractual/sintético. No hay evidencia
  nueva de supervisor independiente ni aislamiento del host.
- No hubo inferencia Qwen viva. Los resultados históricos y fixtures continúan
  separados; estas pruebas no se contabilizan como inferencias.
- Se mantienen `hostBoundaryReady=false`,
  `integratedAssessmentReady=false` y `workerAdmission=disabled`.
- Ningún cambio de código fue necesario; no se cambió API, SQL, Policy Engine,
  fixtures ni gates.

## Próximo paso seguro y bloqueos

1. Para explicar el fallo con precisión, el responsable de la DB debe aportar
   una instancia de laboratorio desechable y evidencia de solo lectura del
   catálogo de las 12 tablas, las 34 políticas, predicados, `ENABLE/FORCE` y
   roles efectivos. Hasta entonces, no tocar la DB de desarrollo ni modificar
   grants/policies basándose en el mensaje genérico.
2. El workflow PostgreSQL aislado requiere un repositorio conectado y Actions
   habilitado; no se ejecutó ni se dependió de GitHub en esta continuación.
3. La ejecución del worker/Qwen requiere supervisor independiente y trust anchor
   con atestación fresca ligada a los hashes actuales; siguen bloqueados.
4. La siguiente labor local independiente puede revisar UX de estados de
   workspace sin conexión/API caída o fortalecer una regresión puramente
   sintética solo si aparece una brecha concreta. No duplicar la cobertura que
   pasó en esta iteración.
