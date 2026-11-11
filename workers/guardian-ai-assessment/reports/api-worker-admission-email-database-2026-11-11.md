# Admisión API fail-closed para correo y BBDD — 2026-11-11

## Cambio

- La decisión de admisión ahora es una función pura del gate API. Solo admite
  un perfil cuando la disponibilidad global y la del perfil están `ready`;
  cualquier otro estado devuelve un motivo de rechazo.
- El POST de creación de trabajos reutiliza `requestLabJob`, igual que la ruta
  de intents. La comprobación de rol/pertenencia se conserva y la decisión del
  worker se evalúa antes de idempotencia, consulta de trabajos pendientes,
  inserción de job/auditoría, reserva de cuota y enqueue.
- La regresión invoca el handler de ruta con transacción y efectos simulados
  mediante dobles. Para correo y bases de datos obtiene HTTP 503 y
  `worker_unavailable`; los contadores de consulta de idempotencia/pendientes,
  inserción, reserva de cuota y enqueue quedan en cero.
- El gate permanece cerrado con `assessment_broker_identity_unverified`.
  No se añadieron eventos de rechazo: el código existente no define un evento
  obligatorio para esta denegación, y no se crea un job cuyo ID pudiera
  auditarse.

## Verificación ejecutada en esta iteración

En serie, el 2026-11-11:

1. `pnpm --filter @workspace/api-server exec tsx --test src/lib/assessment-worker-api-admission.test.ts`
   — **1/1 aprobada**, cero fallos u omisiones.
2. `pnpm --filter @workspace/api-server exec tsx --test src/lib/assessment-worker-mode.test.ts`
   — **4/4 aprobadas**, cero fallos u omisiones.
3. `pnpm --filter @workspace/api-server run typecheck` — **aprobado**.
4. `git diff --check` — **aprobado**.

Una ejecución intermedia de typecheck encontró errores de tipos durante la
implementación; se corrigieron antes de la verificación final anterior.

No se ejecutaron Qwen, workers, broker, Docker, socket Docker, PostgreSQL,
colas reales, servicios, red, E2E de base de datos, despliegues ni publicación.
La prueba llama directamente al handler Express con dobles; no levanta un
servidor HTTP y no verifica Clerk, RLS ni persistencia real. No contiene
respuestas de modelo ni se presenta como inferencia Qwen.

## Hashes SHA-256

- `artifacts/api-server/src/lib/assessment-worker-api-gate.ts`:
  `799308245a98cb42ffb074290a766456cc59386ab2d26b59e08cc24ae18f14f3`
- `artifacts/api-server/src/routes/ai-assessment-lab.ts`:
  `b67c1d1ff6e176d96c12de6e047e6cf97475b4184fc43c58c04d3d03b3a69fe0`
- `artifacts/api-server/src/lib/assessment-worker-api-admission.test.ts`:
  `7263f2b4c734e030c749832d26877ca20b3ec098ec80fd1698f9681ee4a17aab`

## Límites y siguiente paso

Este cambio confirma el rechazo API sin efectos de admisión de trabajo cuando
el gate está cerrado. No acredita `hostBoundaryReady`, no habilita Qwen y no
demuestra aislamiento real. El siguiente prerequisito sigue siendo una
atestación independiente y actual de los límites host/broker/worker.
