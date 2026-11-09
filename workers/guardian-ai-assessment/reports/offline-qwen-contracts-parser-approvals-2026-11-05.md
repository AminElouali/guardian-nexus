# Guardian Nexus — validación offline de contratos y parser

Fecha: 2026-11-05. Alcance: desarrollo local, pruebas deterministas y sintéticas
únicamente. No se ejecutaron Qwen, Docker, el preflight vivo, PostgreSQL E2E ni
servicios externos; no se leyeron valores de secretos.

## Base y cambios

- HEAD de inicio: `5088a78f99a06ca3346adea4988595a19d6142ef`, árbol limpio.
- El commit de base añadió al paquete web `gsap`, `@gsap/react`, `three`,
  `@types/three`, `@react-three/fiber` y `@react-three/drei`, más dependencias
  transitivas e integridad en `pnpm-lock.yaml`. No añadió dependencias al API
  ni al worker. Se verificó compilando API y web; no se hizo auditoría de
  licencia/CVE ni instalación o descarga de paquetes en esta intervención.
- Se endureció el adaptador de marcadores Qwen: rechaza nombres de clave JSON
  duplicados, incluso dentro de objetos anidados, y constantes no estándar
  (`NaN`/`Infinity`) en vez de aceptar una interpretación ambigua.
- Se añadieron pruebas para preservar el origen de `message.tool_calls`
  devuelto directamente por el runtime, y para rechazar entrada etiquetada
  malformada o con más de ocho marcadores sin aceptar llamadas parciales.
- Se amplió la prueba unitaria del binding v3 de aprobación para comprobar que
  cambia si se mutan tenant, job, caso, hash de propuesta/acción, solicitante,
  rol o expiración. No se modificó el flujo de aprobación ni la política.

## Pruebas ejecutadas en serie

Todas son suites unitarias o previews deterministas; ninguna lanza Qwen,
Docker, conexiones de red ni PostgreSQL.

| Capa | Comando / alcance | Resultado |
|---|---|---:|
| Worker | `python -m unittest discover -s tests -p 'test_autonomous_tool_selection.py' -v` | 11/11 |
| Worker | `python -m unittest discover -s tests -p 'test_policy_lab.py' -v` | 35/35 |
| Preflight sintético | `python -m unittest discover -s tests -p 'test_offline_isolation_preflight.py' -v` | 15/15 |
| API | Qwen evidence, action adapter y policy preview unitarios | 16/16 |
| API | `pnpm --filter @workspace/api-server run typecheck` | Correcto |
| API | `pnpm --filter @workspace/api-server run build` | Correcto |
| UI | `AiEvaluationPage.integration.test.tsx` | 14/14 |
| UI | `pnpm --filter @workspace/eu-security-platform run typecheck` | Correcto |
| UI | Build Vite con `PORT=18753 BASE_PATH=/` | Correcto; advertencias existentes de sourcemap y bundle >500 kB |
| Diff | `git diff --check` | Correcto |

Los tests verifican por separado `controlled_fixture_not_llm`,
`guardian_qwen_native_markup_adapter`, `runtime_message_tool_calls` y
`no_tool_call`. Comprueban ocho fixtures, autorización Policy ON antes del
simulador, no despacho para DENY/REQUIRE_APPROVAL, Policy OFF como clon sin
ejecución, procedencia adversaria no confiable, y acciones de finanzas/soporte
allow-listed en clones en memoria. Son pruebas de contrato/dobles; no acreditan
una inferencia actual ni una aprobación persistente originada por Qwen.

## Estado Qwen, aprobación y aislamiento

- Inferencia Qwen nueva: **no ejecutada**. El último artefacto histórico
  disponible sigue separado: ocho llamadas registradas, siete propuestas
  adaptadas, cero `message.tool_calls` nativas y una `NO_PROPOSAL`. Es
  evidencia histórica, no se actualizó ni se mezcló con fixtures.
- La aprobación persistente API/PostgreSQL no se volvió a ejecutar. La suite
  API seleccionada solo prueba binding/proveniencia y recibos sintéticos en
  memoria; el E2E persistente previo usa fixtures y no propone que Qwen originó
  esas solicitudes.
- No se repitió el preflight vivo. El informe guardado del 2026-11-04 sigue
  indicando socket Docker accesible al proceso, variables sensibles presentes
  por nombre e identidades/sesiones API-broker-worker/DB no verificadas.
  `hostBoundaryReady=false`; por tanto Qwen y el worker real permanecen
  bloqueados. Hash del JSON de preflight:
  `3b85f5c1aab30012d27df96eec5aabeff7ac932198d45f1dd5536d55903d8445`.
- No se habilitó el gate, no se ejecutó el consumidor de la cola, no se tocó
  producción y no se inició ningún workflow.

## SHA-256 de fuentes y pruebas modificadas

- `workers/guardian-ai-assessment/guardian_ai_assessment/llm_lab.py`:
  `b3a0a5d2ac73a2b03598f6d671d3c687a8f84072dd402ea5f31b7f2a853591a4`
- `workers/guardian-ai-assessment/tests/test_autonomous_tool_selection.py`:
  `91c6f79af931f8dfd0acd912e01daceb18e14e05c79091dfd2b475a20dbcad2a`
- `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`:
  `a2ecd9dd8f5705331104b6f0ff2c5bdf14f47e983411c5bedd65b2d54db89100`

## Pendiente verificable

1. En un host Ubuntu autorizado, demostrar UID/GID separados, socket inaccesible
   para API y exclusivo del broker, roles y sesiones DB independientes, y
   `hostBoundaryReady=true` con evidencia verificable; no basta una simulación.
2. Solo después de ese gate, ejecutar la evaluación actual de ocho perfiles con
   `tool_choice=auto`, registrar propuestas nativas/adaptadas/ausentes por
   separado y comprobar Policy independiente antes del simulador.
3. Ejecutar la aprobación persistente PostgreSQL con propuestas Qwen reales,
   tenant/RBAC, expiración, carrera, replay y reanudación ficticia de un solo uso.
