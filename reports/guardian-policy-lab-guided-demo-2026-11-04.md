# Guardian Nexus — recorrido guiado del laboratorio

Fecha: 2026-11-04  
HEAD de partida: `8c5681f2f07d2d782d40913b8aed84e6883ab363`

## Resultado

Se amplió la sección existente de laboratorios en `/ai-evaluations`; no se creó
otra página ni se modificó el contrato API. El usuario autenticado puede elegir
uno de los ocho perfiles y un caso benigno o adversario, y seguir la procedencia,
la decisión Policy ON, el estado de simulación, el estado de aprobación y el
hash de evidencia. Si el worker está disponible, el botón solicita el job
existente y destaca el caso elegido; el API actual ejecuta el par de fixtures
fijos del perfil, no solo el caso seleccionado, y la interfaz lo explica.

Como el gate del worker permanece cerrado, se añadió una alternativa de solo
lectura que permite explorar resultados deterministas históricos ya guardados.
Se etiquetan como muestra histórica, no como ejecución nueva, no se crean jobs
ni se modifica el historial del espacio. La muestra usa
`generated-artifacts/guardian-agent-policy-labs-e2e.json` (8 perfiles; SHA-256
`9bbc87ca9ee5c7eac040a0d2f33defb6eeb41f95d5d9940979b5564b435960be`).
La vista no muestra IDs de job ni contenido bruto.

El reinicio limpia solo la selección y la muestra local; no elimina eventos,
jobs ni registros. Un caso `REQUIRE_APPROVAL` enlaza a la bandeja, pero se
indica que esa evidencia fixture no crea una aprobación persistente. No se
fabrican aprobaciones. La vista histórica de Qwen sigue separada: este cambio
no ejecutó Qwen y no altera sus recuentos de llamadas nativas, marcadores
adaptados o `NO_PROPOSAL`.

## Verificación

- UI `AiEvaluationPage.integration.test.tsx`: **9/9**.
- API `pnpm --filter @workspace/api-server test`: **76/76**.
- Worker determinista `PYTHONPATH=workers/guardian-ai-assessment python -m unittest discover -s workers/guardian-ai-assessment/tests -p 'test_policy_lab.py'`: **31/31**.
- SDK TypeScript: **13/13**; SDK Python: **8/8**.
- `pnpm run typecheck`: pasó para libs, API, web, mockup sandbox y scripts.
- Build web: pasó con `PORT=5173 BASE_PATH=/eu-security-platform/`; conserva un
  aviso de sourcemap en `tooltip.tsx` y el aviso preexistente de chunk grande
  (826.64 kB JS, 225.34 kB gzip).
- Build API y build SDK TypeScript: pasaron.
- Captura sin sesión de `/ai-evaluations`: Clerk mostró la pantalla de acceso.
  No se inició sesión, no se usó bypass y no se verificó visualmente la UI
  autenticada en navegador.

Hubo dos fallos de preparación corregidos antes de validar: la primera
invocación del build web no tenía `PORT`/`BASE_PATH`; la primera invocación de
unittest no tenía `PYTHONPATH`. La prueba UI también detectó una aserción
demasiado específica sobre el orden de atributos HTML; se corrigió la
aserción, sin cambiar el comportamiento de seguridad.

## Límites y bloqueos

- La API informa `assessment_broker_identity_unverified` y mantiene los
  perfiles deshabilitados. No se lanzó worker, Docker ni modelo local; no hay
  nuevas inferencias Qwen ni propuestas nuevas.
- La evidencia reproducible mostrada sin worker es histórica y determinista.
  No equivale a una evaluación recién ejecutada para el tenant actual.
- El fixture `REQUIRE_APPROVAL` no produce una solicitud persistente en la
  bandeja. Para probarla hace falta una ruta backend autorizada que cree la
  solicitud bajo el tenant autenticado; no se agregó porque requeriría cambiar
  persistencia/autorización y no se pudo verificar con una sesión Clerk
  autenticada en navegador en esta ejecución.
- No se probó navegador autenticado real, RLS contra una base conectada,
  inferencia Qwen, broker aislado ni ejecución de contenedor.

## Archivos modificados

- `artifacts/eu-security-platform/src/components/GuardianAgentPolicyLab.tsx`
- `artifacts/eu-security-platform/src/components/AiEvaluationPage.tsx`
- `artifacts/eu-security-platform/src/components/GuardianApprovalInbox.tsx`
- `artifacts/eu-security-platform/src/components/AiEvaluationPage.integration.test.tsx`
- `artifacts/eu-security-platform/src/index.css`
- `workers/guardian-ai-assessment/MVP_CHECKPOINT.md` (checkpoint)

Los hashes SHA-256 de los cinco archivos de UI, el artefacto fuente y este
informe quedan en `reports/guardian-policy-lab-guided-demo-2026-11-04.sha256`.
El checkpoint se actualiza por separado con el resumen de este incremento.
