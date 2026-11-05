# Guardian Nexus — procedencia Qwen y orden de autorización

Fecha: 2026-11-05  
Base revisada: `52f801d5e1b281ef4f2a1b13a434a3d76c25b4e6` (árbol limpio antes de este incremento).

## Cambio aplicado

- La vista Qwen separa cuatro resultados: marcadores Qwen adaptados, llamadas nativas `message.tool_calls`, casos sin llamada (`NO_PROPOSAL`) y marcadores rechazados por el parser. Una salida malformada ya no se cuenta como ausencia de propuesta.
- El resumen indica que las fixtures deterministas quedan fuera de los conteos Qwen y se ven en el Policy Lab separado. La traza explica que una propuesta aceptada pasa por validación y Policy ON antes del simulador sintético; solo `ALLOW` puede despacharse. `DENY`, `REQUIRE_APPROVAL`, `NO_PROPOSAL` y los marcadores rechazados no se despachan. Policy OFF sigue siendo solo contrafactual.
- La API no acepta un marcador rechazado por el parser como procedencia válida para crear una aprobación.
- La prueba worker observa el orden efectivo para los ocho perfiles deterministas: cada llamada al adaptador está ligada a la decisión `ALLOW` del mismo caso. Confirma que Policy OFF no invoca herramientas.

## Verificación ejecutada

Todas las suites se ejecutaron en serie, sin inferencia Qwen ni Docker:

| Área | Comando | Resultado |
|---|---|---:|
| Worker Policy Lab | `cd workers/guardian-ai-assessment && PYTHONPATH=. python -m unittest discover -s tests -p 'test_policy_lab.py'` | 35/35 |
| API unitaria/contratos | `pnpm --filter @workspace/api-server test` | 79/79 |
| Aprobaciones sintéticas persistentes | `pnpm --filter @workspace/api-server run test:ai-assessment-synthetic-e2e` | 1/1 |
| SDK TypeScript | `pnpm --filter @workspace/guardian-agent-sdk test` | 13/13 |
| Build SDK TypeScript | `pnpm --filter @workspace/guardian-agent-sdk build` | Correcto |
| SDK Python | `cd lib/guardian-agent-sdk-python && PYTHONPATH=src python -m unittest discover -s tests -p 'test_*.py'` | 8/8 |
| UI/integración | `TSX_TSCONFIG_PATH=/home/runner/workspace/artifacts/eu-security-platform/tsconfig.json pnpm --filter @workspace/api-server exec tsx --test ../eu-security-platform/src/components/AiEvaluationPage.integration.test.tsx` | 12/12 |
| Typecheck monorepo | `pnpm run typecheck` | Correcto |
| Build web | `PORT=3000 BASE_PATH=/ pnpm --filter @workspace/eu-security-platform run build` | Correcto |
| Build API | `pnpm --filter @workspace/api-server run build` | Correcto |

El E2E de aprobación es un harness de fixtures deterministas, no Qwen: la evidencia indica `modelInference=false`, `brokerUsed=false`, `dockerCommandRequestedByHarness=false` y `externalEffects=false`. Cubre aprobaciones y rechazos sintéticos con binding, caducidad, replay, carrera, rol revocado y separación de tenant.

Hubo fallos de invocación que se corrigieron sin cambiar el alcance de las pruebas: el primer intento UI no encontró `tsx` en la raíz; el siguiente no cargó el alias `@/` hasta fijar el `tsconfig` web; el primer typecheck detectó una posible nulabilidad en el test y se ajustó el narrowing. El primer build web carecía de `PORT`; el build con `PORT=3000 BASE_PATH=/` pasó. El primer comando del SDK Python necesitaba `PYTHONPATH=src`, no `.`. Las ejecuciones finales indicadas arriba pasaron.

El build web aún advierte por el sourcemap de `tooltip.tsx` y un chunk JavaScript de 835.83 kB (227.69 kB gzip). El build API completó con el bundle `dist/index.mjs` de 4.0 MB.

## Límites y evidencia previa

- No se ejecutó inferencia Qwen nueva ni se invocó Docker. El E2E usó la conexión PostgreSQL de desarrollo configurada para sus registros sintéticos; no se inspeccionaron ni imprimieron valores de credenciales y no se tocó producción ni un servicio de clientes.
- La evidencia Qwen existente sigue siendo histórica: 8 inferencias locales, 7 marcadores adaptados, 0 llamadas nativas `message.tool_calls`, 1 `NO_PROPOSAL`; 2 `ALLOW`, 3 `DENY`, 2 `REQUIRE_APPROVAL`, 1 `NO_PROPOSAL`; dos simulaciones sintéticas, cero ejecuciones no autorizadas y cero operaciones externas. No acredita ocho recorridos API→worker Qwen ni aprobaciones persistentes nacidas de Qwen.
- El último preflight persistido es del 2026-11-04 y no se repitió en este incremento. Sigue bloqueado: `offline_docker_socket_accessible`, `offline_sensitive_environment_present`, `assessment_broker_identity_unverified` y `assessment_database_session_identity_unverified`; su intento terminó antes de cargar el modelo (`newInferenceExecuted=false`).
- La captura de `/dashboard` sin sesión mostró el inicio de sesión de Clerk. No se utilizó bypass ni se verificó la UI autenticada en navegador. Las pruebas de componente sí verificaron el resumen, la bandeja y el JSON redactado.

## Hashes de evidencia

- E2E sintético: SHA-256 reportado por el test `abd3f2f78d3a5436d410ebc05788fcb403b8334e5571c3cb75234477d7de3f0b`; artefacto `generated-artifacts/guardian-synthetic-approval-e2e.json`, SHA-256 `2caea13b20738202470beec99111e4ae7f47700ec76e14e1f52a2c2fa0237362`.
- Qwen histórico: `generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`, SHA-256 `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
- Preflight histórico: `generated-artifacts/guardian-qwen-offline/preflight-status-2026-11-04.json`, SHA-256 `0b6246f76877a2874dc7834cacba1c76979a61e7871b1371515268dee8e85f52`.
- Los hashes de código, pruebas y artefactos están en `reports/guardian-qwen-provenance-and-policy-order-2026-11-05.sha256`.

No se publicaron cambios ni se accedió a producción, sistemas de clientes, servicios externos o credenciales. El siguiente desbloqueo para Qwen actual sigue siendo un host de laboratorio que demuestre identidades API/broker/DB independientes y que el proceso API no pueda acceder al socket Docker.
