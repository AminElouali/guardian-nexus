# Guardian Nexus — aprobaciones sintéticas y estado del preflight

Fecha de verificación: 2026-11-04 UTC  
HEAD de partida: `3fae71c14fa856cac91908fe797941e33d1def74`

## Cambios verificados

- El E2E de aprobación de finanzas y atención al cliente comprueba que las
  propuestas provienen de fixtures deterministas (`modelInference=false`), pasan
  Policy ON y quedan retenidas antes del adaptador hasta su aprobación. La
  aprobación y reanudación son persistentes en la base de desarrollo y solo
  producen una simulación ficticia de un uso.
- Se comprueba el vínculo por SHA-256 de propuesta/acción y binding v3; rechazo
  de binding alterado o procedencia Qwen falsificada; separación solicitante /
  aprobador; permisos viewer/admin; revocación de rol; acceso entre espacios;
  expiración; carreras concurrentes con un único ganador; replay rechazado; y
  clave idempotente del trabajo.
- El E2E ahora comprueba directamente el estado persistido y los eventos de
  auditoría: aprobación/denegación/caducidad se registran una sola vez; replay y
  aprobación con rol revocado no generan una segunda simulación ni un evento de
  aprobación. Los recibos de simulación quedan hasheados y marcan
  `externalSideEffect=false`.
- Los tests deterministas cubren ataques sintéticos de procedencia no confiable
  en las ocho verticales y una propuesta benigna con recurso de otro espacio por
  vertical. Cada caso adversario se deniega antes del adaptador; no se guardan
  prompts ni argumentos crudos. No son inferencias Qwen.
- La página de evaluación informa explícitamente cuando el preflight no confirma
  disponibilidad: no se ejecutaron inferencias Qwen nuevas desde esa vista; la
  evidencia registrada es histórica y `NO_PROPOSAL` no significa `DENY`.

## Pruebas ejecutadas

| Comando | Resultado |
| --- | --- |
| `cd workers/guardian-ai-assessment && PYTHONPATH=. python tests/test_policy_lab.py GuardianAgentPolicyLabTests.test_eight_synthetic_verticals_have_allow_and_blocked_adversarial_cases GuardianAgentPolicyLabTests.test_cross_tenant_scope_denies_before_dispatch_for_all_eight_verticals GuardianAgentPolicyLabTests.test_untrusted_injection_fixtures_in_all_eight_profiles_never_dispatch` | 3/3 |
| `pnpm --filter @workspace/api-server run test:ai-assessment-synthetic-e2e` | 1/1 |
| `pnpm --filter @workspace/eu-security-platform exec tsx --test src/components/AiEvaluationPage.integration.test.tsx` | 10/10 |
| `pnpm run typecheck` | Pasó para librerías, API, web, mockup sandbox y scripts |
| `PORT=3000 BASE_PATH=/ pnpm run build` | Pasó; builds API, web, mockup sandbox y SDK |

El E2E API usa el harness de autenticación sintética de desarrollo y datos
generados por el test; limpia los espacios de trabajo al terminar. No representa
una sesión Clerk real. El primer intento de `pnpm run build` sin variables de
entorno requeridas por Vite falló antes de compilar; el mismo build pasó con
`PORT` y `BASE_PATH` explícitos. El bundle web sigue generando una advertencia
por un chunk mayor de 500 kB.

Artefacto redactado del E2E:

- `generated-artifacts/guardian-synthetic-approval-e2e.json`
- `modelInference=false`, `brokerUsed=false`,
  `dockerCommandRequestedByHarness=false`, `externalEffects=false`
- Estados: dos aprobaciones ficticias simuladas una vez; denegación y expiración
  sin simulación; una única aprobación en carrera; replay, rol revocado, binding
  alterado y cross-tenant rechazados.
- Hash interno del informe: `f0a6aedccee3930ca2765fd78d026a4aad3395c8f30dedf9d2abd64c583da864`

## Límites que siguen abiertos

- **Qwen nuevo: no ejecutado.** El preflight previo permanece bloqueado por acceso
  del usuario actual al socket Docker y presencia de variables sensibles en el
  entorno; no se leyeron sus valores. La identidad independiente del broker y
  las sesiones de base de datos separadas siguen sin verificarse. No se inició
  Qwen ni Docker en este incremento.
- La evidencia histórica de ocho inferencias no cambia: siete marcadores Qwen
  adaptados, cero `message.tool_calls` nativas y una sin propuesta
  (infraestructura). No es una corrida nueva ni un E2E API→Qwen.
- Las aprobaciones probadas nacen de fixtures, no de propuestas de Qwen. La
  bandeja no se verificó en navegador con una sesión Clerk real.
- No se contactaron servicios externos ni se ejecutaron acciones reales.

Desbloqueo requerido para la siguiente fase: host Linux de laboratorio autorizado
con identidades API/broker distintas, socket Docker inaccesible a la API,
credenciales y sesiones DB separadas, y preflight íntegro aprobado. La prueba de
Clerk requiere una sesión de desarrollo ya autorizada, sin bypass ni compartir
credenciales.
