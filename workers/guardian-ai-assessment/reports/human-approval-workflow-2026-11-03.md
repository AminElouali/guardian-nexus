# Flujo de aprobación humana de laboratorio — 2026-11-03

## Alcance implementado

Se añadió persistencia tenant-scoped para solicitudes de aprobación que el
worker deriva exclusivamente de evidencias con `require_approval`. La extracción
acepta los motores `guardian_policy_lab` y `guardian_qwen_policy_lab`, exige
identificadores y hashes válidos y no guarda prompts, respuestas ni argumentos
en bruto.

La solicitud queda enlazada a workspace, job, caso, hash de propuesta y hash de
acción opcional mediante un `proposalBindingSha256` calculado sobre la tupla
canónica. La decisión solo puede registrarla un owner/admin que no sea quien
solicitó la propuesta. El cambio de estado es condicional, de una sola vez, con
expiración de 24 horas y evento de auditoría. La tabla usa RLS habilitado y
forzado; `app_runtime` no recibe permiso de borrado y solo puede actualizar las
columnas de decisión.

La API autenticada expone el listado y la decisión en el espacio activo. La
interfaz muestra Pendiente, Aprobada · sin ejecutar, Denegada y Caducada. La
respuesta incluye `execution: not_performed_laboratory_approval_only`.
**Aprobar o denegar solo registra una decisión: esta versión no vuelve a
encolar, reanudar ni ejecutar herramientas, ni siquiera simuladas.** La
reanudación de una acción sintética exacta queda pendiente hasta definir una
representación mínima de acción que pueda verificarse criptográficamente sin
persistir argumentos sensibles ni permitir cambiar la propuesta.

## Validación ejecutada

- RLS de desarrollo: `ALLOW_DEV_DB_ROLE_BOOTSTRAP=true NODE_ENV=development
  pnpm --filter @workspace/db run apply-rls-policies:dev` — correcto. No se
  modificó producción.
- E2E de aprobaciones:
  `NODE_ENV=development pnpm --filter @workspace/api-server exec tsx --test
  --test-name-pattern='persistent synthetic approvals'
  src/ai-assessment-e2e.test.ts` — **1/1**. El test creó tres jobs fixture
  financieros completados y tres solicitudes; comprobó una aprobación, una
  denegación y una caducidad, además de denegar autoaprobación, rol viewer,
  tenant distinto, hash alterado y replay. Los tres casos `require_approval`
  permanecieron sin despacho y con `executed=false`.
- Inferencia Qwen real, serial:
  `NODE_ENV=development pnpm --filter @workspace/api-server exec tsx --test
  --test-name-pattern='real Qwen email, database, and finance profiles'
  src/ai-assessment-e2e.test.ts` — **1/1**, **3/3 jobs**. Se preservaron los
  resultados anteriores de correo, base de datos y finanzas. Ningún resultado
  Qwen de esta corrida solicitó aprobación; por ello la integración de
  aprobaciones se verificó con fixtures deterministas, no con una propuesta
  Qwen.
- Regresión del flujo original Garak/LLM:
  `NODE_ENV=development pnpm --filter @workspace/api-server exec tsx --test
  --test-name-pattern='authenticated requests run existing fixtures and real
  local LLM' src/ai-assessment-e2e.test.ts` — **1/1**. El primer intento falló
  porque el test esperaba literalmente worker `0.5.1`, mientras la constante
  actual y el job indicaban `0.5.2`. El test ahora compara con
  `AI_ASSESSMENT_WORKER_VERSION`; la repetición pasó sin relajar controles de
  ejecución.
- API: `pnpm --filter @workspace/api-server run test` — **56/56**.
- Worker Python en la imagen local fijada, bajo `--network=none`:
  `sh workers/guardian-ai-assessment/scripts/run-local.sh --unit-tests` —
  **87/87**. La invocación directa inicial no pudo ejecutarse porque el script
  no tiene bit ejecutable; invocarlo explícitamente con `sh` pasó.
- Componentes/UI de informe y descarga:
  `pnpm --filter @workspace/eu-security-platform exec tsx --test
  src/components/AiEvaluationPage.integration.test.tsx` — **8/8**. El primer
  intento detectó `React is not defined` en el componente nuevo; se añadió el
  import de React y la repetición pasó.
- Typecheck de API y web — correcto. Build API y build web — correctos. El
  build web conserva los avisos existentes de sourcemap en `tooltip.tsx` y
  bundle de más de 500 kB.
- `git diff --check` — correcto. `docker ps -a --filter
  name=guardian-ai-lab-` no mostró contenedores residuales.

## Límites y estado del MVP

- Los tres jobs de aprobación de esta validación proceden del perfil fixture
  `guardian-agent-lab-finance-v1`; no son inferencia Qwen.
- Qwen local real sigue verificado solo en **3/8** verticales: correo, bases
  de datos y finanzas. Las otras cinco permanecen como Policy Labs fixture.
- No se observó una propuesta Qwen `require_approval`, por lo que no se afirma
  una aprobación humana originada por inferencia Qwen.
- La UI no afirma ejecución tras aprobar. No existe reanudación, ni siquiera
  ficticia, en esta versión.
- Las llamadas Qwen siguen siendo propuestas adaptadas desde marcadores; no se
  informan como `message.tool_calls` nativas.
- No se usaron servicios externos, datos de clientes, credenciales nuevas,
  producción ni publicación.
