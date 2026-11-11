# Auditoría offline de preparación para validación real — 2026-11-11

## Alcance y estado observado

- Revisión estática en `main`, HEAD
  `f3beedd562cf0aaf0395b3dc93ee5cf21095ef1c`. El árbol estaba limpio antes de
  añadir este informe. El commit actual, `docs: record finance approval
  contract revalidation`, solo añadió 28 líneas a `MVP_CHECKPOINT.md`; el último
  cambio de código previo es `d808d241ac2fd1576c08442854cfffd6499c6d67`
  (`test: verify finance support and multiagent contracts`).
- No se consultó el estado remoto de tareas del Agent; no es verificable desde
  esta auditoría del repositorio. No se comprobó una lista de procesos.
- El estado del workspace muestra el workflow **API Server: failed**. No se
  consultaron logs nuevos ni se reinició. El checkpoint conserva un fallo
  histórico de arranque en `assertRlsRuntimeReady`; no se afirma que esa sea la
  causa actual.
- No se ejecutaron pruebas, typecheck, preflights, procesos, Qwen, workers,
  Docker, sockets, PostgreSQL, migraciones, servicios ni red. No se leyó
  `.replit`, ni valores de entorno o secretos. Lo que sigue es evidencia
  estática y registros fechados; no es una validación del host o de la DB.

## Matriz de requisitos y evidencia

| Requisito | Evidencia de código / registro | Estado de validación real |
|---|---|---|
| Challenge-response firmado, frescura y binding al runtime | `artifacts/api-server/src/lib/host-attestation-protocol.ts:32-39, 250-339` declara TTL de 2 minutos, nonce de 256 bits, trust anchor Ed25519 fijado y binding a commit/digest. `:342-477` valida respuesta, firma, claims e identidades. | **IMPLEMENTADO PERO NO VERIFICADO** con supervisor real. |
| Trust anchor fuera del proceso y supervisor independiente | El loader `loadPinnedHostTrustAnchor` exige un PEM Ed25519 root-owned, no escribible por grupo/otros, `O_NOFOLLOW` y comprobación de inode: `host-attestation-protocol.ts:478-574`. El flujo API carga esa clave desde el path fijo; el payload no proporciona la clave (`routes/ai-assessment-lab.ts:686-820`). | **BLOQUEADO EXTERNAMENTE**: la existencia/provisión actual de la clave y del supervisor independiente no se comprobó. No hay respuesta firmada independiente actual en la evidencia revisada. |
| Medición efectiva de API/broker/worker y aislamiento host | El contrato exige identidades, roles DB, grupos del socket, namespaces, privilegios/seccomp y claims de mounts/FDs. `workers/guardian-ai-assessment/guardian_ai_assessment/host_boundary_attestation.py:1-6, 23-53, 73-142` verifica el formato, frescura, procedencia del archivo y hashes; no genera mediciones del host. `deployment/BROKER_BOUNDARY.md` describe el diseño objetivo, no una frontera instalada. | **BLOQUEADO EXTERNAMENTE**: falta una medición firmada por un dominio independiente. |
| Estado histórico del socket Docker | El informe pasivo del 2026-11-10 declara explícitamente que fue una observación de metadatos, no certificación: `reports/passive-host-broker-worker-attestation-2026-11-10.md:3-16`. Registró `hostBoundaryReady=false`, identidades no verificadas y acceso de lectura/escritura del usuario de la prueba al socket según `os.access` (`:18-31`). Su resumen SHA-256 es `0d73dcfa44f4ea3d1879ec6e555429afd6230a7fc0ca1c7ebffb00538e46170d`. | **HISTÓRICO, NO ACTUAL**. No se inspeccionó ni abrió el socket en esta auditoría; no se afirma que los permisos actuales sean iguales. |
| Replay durable del challenge | El protocolo abstrae `insert/consume/finish`; `lib/db/src/schema/host-attestation.ts:28-81` declara nonce único, expiración y estados terminales. La ruta usa el repositorio tenant-scoped en una transacción (`routes/ai-assessment-lab.ts:695-724, 769-800`). | **IMPLEMENTADO PERO NO VERIFICADO** contra PostgreSQL; las pruebas de protocolo usan almacenamiento en memoria. |
| Gates de readiness y admisión | `assessment-worker-api-gate.ts:33-83` devuelve `disabled` con `assessment_broker_identity_unverified` y `enqueueLocalAssessmentJob` retorna `false`. `host-attestation-protocol.ts:235-247` fija ambos readiness en `false`; las rutas responden `workerAdmission: "disabled"` (`routes/ai-assessment-lab.ts:735-740`). | **IMPLEMENTADO Y VERIFICADO** solo como comportamiento de código/pruebas sintéticas; **NO** como verificación de aislamiento real. |
| RLS runtime y roles PostgreSQL | `lib/db/src/index.ts:65-137` comprueba 12 tablas protegidas, RLS habilitado/forzado, número y estructura de políticas; `:140-464` comprueba atributos/grants de roles y niega acceso del worker a resultados. `artifacts/api-server/src/index.ts:19-32` evita escuchar si falla. `lib/db/sql/rls-policies.sql:111-245` declara constraints, grants y `ENABLE/FORCE ROW LEVEL SECURITY` para aprobaciones. | **IMPLEMENTADO PERO NO VERIFICADO** en la DB actual. El checkpoint registra un fallo de readiness anterior, sin diagnóstico de la tabla/condición exacta; no se consultó la DB ahora. |
| Aprobaciones persistentes tenant-safe | `lib/db/src/schema/ai-assessment-jobs.ts:1276-1429` declara tenant/job, hashes de propuesta/acción, binding v1-v3, actor/rol, estados, expiración, recibos y políticas RLS. `ai-assessment-approval-actions.ts:198-395` calcula bindings y recibos solo para acciones ficticias en clones. El E2E está protegido por `approval-e2e-db-guard.ts:1-56` y prueba roles/tenant/replay en `ai-assessment-synthetic-approval-e2e.test.ts`. | **IMPLEMENTADO PERO NO VERIFICADO** en persistencia real. El E2E requiere una DB loopback desechable explícita; no se conectó ni se ejecutó. |
| Supervisor/clave/DB de laboratorio disponibles | El requisito del supervisor y una DB desechable con roles separados está descrito en `reports/host-attestation-challenge-response-2026-11-11.md:59-86` y `reports/approval-e2e-disposable-db-gate-2026-11-10.md:51-63`. | **BLOQUEADO EXTERNAMENTE**. La presencia de recursos del host no fue comprobada en esta auditoría. |

## Qué prueban y qué no prueban las pruebas existentes

1. **Unitarias sintéticas de protocolo:** `host-attestation-protocol.test.ts`
   crea una clave Ed25519 y repositorio `Map` marcados `TEST ONLY`
   (`:22-34`). Sus casos incluyen firma válida/alterada, replay, caducidad,
   digest/commit obsoleto, identidades compartidas y trust anchor ausente
   (`:238-504`). Incluso el caso “válido” comprueba readiness falso y worker
   deshabilitado. El checkpoint fecha un resultado histórico de 17/17 el
   2026-11-11; no se repitió aquí.
2. **Unitarias sintéticas de aprobaciones:** las pruebas de contrato cubren
   bindings, estados y Policy en memoria. No equivalen a transacciones,
   concurrencia ni RLS de PostgreSQL.
3. **Integración de persistencia:** el test de API
   `ai-assessment-synthetic-approval-e2e.test.ts:328-342` omite antes de crear
   conexiones cuando no se confirma explícitamente una base loopback
   `guardian_approval_lab_*`. El informe del 2026-11-10 registra ese E2E como
   `SKIP 1` antes de conexión; su SHA-256 es
   `96008ea71ad27249ffbb039ff912234ba73d23f9d08812fd211bc335cea5e43a`.
4. **Pruebas independientes de seguridad:** no hay en esta revisión evidencia
   de una evaluación realizada por el dueño del host/supervisor sobre procesos,
   permisos, namespaces, mounts, descriptores, seccomp o acceso al socket.
   Firmas, fixtures y claims sintéticos no sustituyen esa prueba.
5. **E2E actual:** no se ejecutó ni se observó una aprobación durable/RLS E2E
   actual. La auditoría tampoco ejecutó pruebas nuevas; solo leyó código,
   Git y registros ya existentes.

El último resultado focalizado registrado en `MVP_CHECKPOINT.md` es del
2026-11-11: 10 métodos unitarios Python, **10 pasaron, 0 fallaron**, en memoria
y con datos sintéticos, en la revisión del contrato de Finanzas/soporte/
multiagente. No acredita host isolation, PostgreSQL ni persistencia. La prueba
de API de admisión previamente registrada (1/1), el typecheck y `git diff
--check` corresponden a otra iteración y tampoco se ejecutaron en esta auditoría.

## Clasificación resumida

- **IMPLEMENTADO Y VERIFICADO:** únicamente comportamientos deterministas de
  rechazo/estado falso cubiertos por pruebas `TEST ONLY` registradas. No se
  extiende esta categoría al host ni a servicios.
- **IMPLEMENTADO PERO NO VERIFICADO:** protocolos, schemas, gates, SQL/RLS,
  chequeo de readiness y ciclo de aprobación presentes en el código, pero sin
  una comprobación actual de PostgreSQL o supervisor.
- **AUSENTE en la evidencia actual:** resultado independiente firmado y fresco
  que demuestre las propiedades efectivas del host; evidencia actual de
  persistencia/RLS E2E. Esto no significa que falte todo el código cliente del
  protocolo.
- **BLOQUEADO EXTERNAMENTE:** supervisor administrado fuera de API/broker/worker
  y su trust anchor provisionado; DB disposable aprobada con roles segregados y
  plan de schema/migración autorizado.

## Siguiente validación mínima segura

1. El responsable del host debe provisionar fuera del dominio de confianza de
   API/worker un supervisor y su clave pública root-owned. Debe responder a un
   challenge fresco ligado al commit/digest exactos y firmar mediciones
   efectivas de identidades distintas, grupos, namespaces, capacidades,
   `no_new_privs`/seccomp, mounts, descriptores y denegación de acceso Docker
   para API/worker. El verificador y la medición deben contrastarse
   independientemente; no basta con los claims enviados por una aplicación.
2. Por separado, el responsable de DB debe identificar y autorizar una base
   PostgreSQL desechable loopback, revisar el plan antes de cualquier migración
   y provisionar roles segregados. Solo entonces ejecutar el readiness check y
   el E2E tenant/RLS/aprobación con evidencia saneada.
3. Mantener gates cerrados hasta completar ambas verificaciones. Después, una
   modificación separada puede considerar la integración de la atestación en
   la admisión. La primera inferencia, si llega a estar permitida, debe empezar
   por Correo y luego Bases de datos; esta auditoría no acredita ninguna.

## Evidencia y hashes

- SHA-256 del informe histórico de protocolo:
  `4ea626c483f6e208ea88858726747e8b15dd7cc3b34faa48750b5644926a969e`.
- SHA-256 del informe histórico de prerequisitos del supervisor:
  `af5dbaaf3bfcb16474d7cd60bff49a4706347dd03d93107ed3c17fd2039f9a3e`.
- SHA-256 de los informes pasivos de host y DB: véanse los valores indicados
  arriba. Ninguno es una atestación actual.
- Este documento no ejecuta pruebas ni modifica gates. El SHA-256 final del
  documento y del checkpoint se registra en `MVP_CHECKPOINT.md` tras el cambio.
