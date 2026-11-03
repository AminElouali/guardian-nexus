# Guardian Nexus — validación Qwen y contrato de evidencia v1.6.0

Fecha: 2026-11-03
Base inspeccionada: `de654b06d085e6ad5ec70e99b4cf1e04c4add85f`
Alcance: corrección del conteo de `require_approval`, sincronización de contrato
OpenAPI/Zod y regresión serial de las evaluaciones sintéticas locales. No se
publicó ni desplegó; no se usaron clientes, servicios externos, credenciales
nuevas ni datos reales.

## Corrección verificada

La primera E2E completa falló en una aserción de prueba: sumaba autorizaciones
y denegaciones como si fueran los únicos resultados posibles. El resumen v2
contiene un tercer estado, `approvalRequiredCalls`. La prueba se corrigió para
exigir la versión v2 y contabilizar ALLOW, DENY y REQUIRE_APPROVAL por separado.
No se cambió la decisión del motor ni se relajó el validador. La repetición
serial completa pasó.

El contrato OpenAPI aclara que `nativeCallsObserved` es un contador legado de
propuestas normalizadas: en la selección autónoma incluye marcadores Qwen
adaptados y **no** equivale a llamadas directas del runtime. Para esa distinción
se usa `toolCallParsing.callsReturnedDirectlyByRuntime`. La UI ya presenta por
separado los marcadores adaptados y los `message.tool_calls` directos.

## Resultados observados

### Ocho perfiles Qwen de laboratorio

- Perfil del modelo: Qwen3-0.6B-GGUF Q8_0, revisión
  `23749fefcc72300e3a2ad315e1317431b06b590a`, modelo SHA-256
  `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`;
  `llama-cpp-python` 0.3.36; `tool_choice=auto`.
- Ocho perfiles, 28 casos y 28 llamadas de modelo: 11 casos benignos y 17
  adversarios. Hubo 19 marcadores Qwen completos adaptados por Guardian,
  **0** `message.tool_calls` directos y 9 casos sin propuesta.
- Política ON: 10 ejecuciones ficticias autorizadas, 7 denegaciones y 2
  propuestas retenidas para aprobación; 0 ejecuciones no autorizadas y 0
  llamadas externas. De las dos aprobaciones, una se simuló una vez tras una
  decisión válida y otra caducó sin ejecución.
- El modo Policy OFF no ejecutó operaciones: permaneció como contrafactual en
  clones efímeros.
- Los informes declaran `rawPromptsStored=false`,
  `rawResponsesStored=false` y `rawToolArgumentsStored=false`.
- Los límites observados incluyen Docker `--network=none`, usuario 65532,
  rootfs de solo lectura, `cap-drop=ALL`, no-new-privileges, 1 CPU, 1536 MiB y
  64 PIDs. IPv4/DNS resultaron bloqueados; IPv6 continúa
  `kernel_protocol_unavailable` y **no verificado**.

### Selección autónoma y comparación emparejada

- 14 escenarios, 13 propuestas completas emparejadas y 1 sin propuesta,
  todas solicitadas con `tool_choice=auto`; traza de 39/42 eventos, sin
  truncamiento.
- Origen: 13 marcadores Qwen adaptados, 0 llamadas directas del runtime y 0
  marcadores sin interpretar. No se incluyeron llamadas forzadas ni fixtures
  en este denominador.
- Policy ON: 10 ALLOW y simulaciones ficticias, 2 DENY y 1
  REQUIRE_APPROVAL; 0 operaciones reales, cambios persistentes o llamadas
  externas.
- Policy OFF: 12 acciones que el contrafactual habría permitido y 2 cambios en
  clones; 0 operaciones reales, cambios persistentes o llamadas externas.
- La comparación es v2 y las 13 propuestas tienen pareja.

### Suites independientes

- La suite de tool calls nativas es un perfil aparte, no la métrica autónoma:
  su sonda usó `specific_function`, `finish_reason=tool_calls`; la E2E registró
  `QWEN_NATIVE_TOOL_TRACE_COUNT=24/288`.
- Prueba separada de bandeja de aprobación basada en fixture allow-listed:
  1/1, marcada explícitamente como fixture; no se contabiliza como propuesta
  de Qwen.

## Pruebas y builds

- `pnpm --filter @workspace/api-server run test:ai-assessment-e2e`:
  API/worker E2E **6/6**; dashboard component integration **8/8**. La primera
  corrida fue 5/6 por la aserción corregida; la repetición completa pasó.
- `pnpm --filter @workspace/api-server run test`: **57/57**.
- Worker local: **118/118** en la validación previa de este mismo código
  Python; no hubo cambios posteriores en el worker.
- `pnpm --filter @workspace/api-server run typecheck` y `build`: pasaron.
- `pnpm --filter @workspace/eu-security-platform run typecheck` y `build`:
  pasaron. El build conserva avisos preexistentes de sourcemap de
  `tooltip.tsx` y chunk JavaScript mayor de 500 kB.
- Codegen OpenAPI/Zod y `pnpm -w run typecheck:libs`: pasaron.
- Captura visual de la home pública: carga y marca coherentes. No se probó
  inicio de sesión Clerk ni una sesión autenticada en navegador; no se hizo
  bypass.

## Evidencias

SHA-256 de artefactos generados (JSON redactado) y salida de la corrida:

- Ocho perfiles, Qwen v1.6.0:
  `generated-artifacts/guardian-qwen-policy-labs-e2e.json` —
  `124c0cb765a00a39453b9e301caad732708aa8e4c4814768e71be4e830c44220`.
- Selección autónoma, paired-policy v2:
  `generated-artifacts/ai-assessment-autonomous-e2e-response.json` —
  `a9e56bc7aaececa631fdbc6110e9dac3c4544640de2db443845e86d10376345c`.
- Suite nativa separada:
  `generated-artifacts/ai-assessment-native-e2e-response.json` —
  `8fb01d5034af76c7306b31de6fe39fb615e77aa4f19a37086c5775ca8672d03a`.
- Respuesta general del E2E:
  `generated-artifacts/ai-assessment-e2e-response.json` —
  `cfc558e970b2e2d5da1685f2e7fe33373562c17cb3d81f223e0f7b1ed3dc15bf`.
- Log completo de la corrida serial:
  `generated-artifacts/guardian-qwen-e2e-v1.6.0-2026-11-03.log` —
  `5dadfef88559e9b58a932cb692ec34a271fd5de0f2653c803940e6d220f3de02`.
- Imagen del evaluador Qwen fijada por ID:
  `sha256:884d4f7bc6c11e03f6ced5cfcc9e88e7a8043d85923429f1a3a181953f07830f`.
- Plantilla de chat SHA-256:
  `57f1fd00f0013a2be96aa79b857391f27e23df5b5f847072b524c897e24d0361`.

Las cifras corresponden únicamente a estas muestras locales sintéticas; no
son una estimación general de precisión ni una garantía de prevención. Los
ocho perfiles usan el mismo modelo local y herramientas ficticias. Siguen
pendientes la sesión Clerk real en navegador, IPv6 dual-stack, la separación
privilegiada API/broker y la resolución de vulnerabilidades/licencias antes
de cualquier piloto.
