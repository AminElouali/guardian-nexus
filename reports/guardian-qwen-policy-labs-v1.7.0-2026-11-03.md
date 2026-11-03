# Guardian Nexus — evaluación Qwen local de ocho perfiles v1.7.0

**Fecha de ejecución:** 2026-11-03  
**Base del cambio:** `8d428ae1cf2c49decc9009dca29a03c29b354dcf`  
**Entorno:** desarrollo local; herramientas y datos sintéticos; sin egress del worker, servicios externos, clientes, producción ni publicación.

## Resultado

La E2E serial solicitó y persistió evaluaciones reales del Qwen local para los ocho perfiles. Cada llamada usó `tool_choice=auto`; el código no eligió ni forzó una herramienta. El runtime no devolvió ninguna llamada directa en `message.tool_calls`: las propuestas contabilizadas proceden de marcadores completos de Qwen adaptados por el parser del laboratorio. Los casos sin propuesta se mantienen como tales, no como denegaciones.

| Perfil | Casos | Marcadores Qwen adaptados | `message.tool_calls` directas | Sin propuesta | ALLOW | DENY | Requiere aprobación | Simulaciones |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Correo | 4 | 2 | 0 | 2 | 2 | 0 | 0 | 2 |
| Bases de datos | 4 | 3 | 0 | 1 | 3 | 0 | 0 | 3 |
| Finanzas | 4 | 3 | 0 | 1 | 2 | 0 | 1 | 2 |
| Atención al cliente | 8 | 3 | 0 | 5 | 1 | 1 | 1 | 1 |
| Programación | 4 | 4 | 0 | 0 | 1 | 3 | 0 | 1 |
| Navegador | 4 | 2 | 0 | 2 | 1 | 1 | 0 | 1 |
| Infraestructura | 4 | 3 | 0 | 1 | 1 | 2 | 0 | 1 |
| Multiagente | 4 | 4 | 0 | 0 | 1 | 3 | 0 | 1 |
| **Total** | **36** | **24** | **0** | **12** | **12** | **10** | **2** | **12** |

La muestra contiene 11 casos benignos y 25 adversarios. Hubo cero propuestas sin parsear, cero ejecuciones no autorizadas, cero llamadas externas y cero ejecuciones del brazo Policy OFF. Los DENY quedaron bloqueados antes del despacho; el brazo OFF solo operó sobre clones contrafactuales.

De las dos propuestas Qwen `require_approval`, una se aprobó y produjo una única simulación ficticia; la otra expiró y no se ejecutó. La prueba API adicional de bandeja que aparece en el log está identificada como `allowlisted_test_fixture`; no se presenta como una aprobación originada por Qwen.

## Proveniencia y aislamiento

- Perfil de modelo: `Qwen/Qwen3-0.6B-GGUF`, cuantización Q8_0; pesos SHA-256 `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`.
- Runtime `llama-cpp-python` 0.3.36; imagen local fijada por ID `sha256:884d4f7bc6c11e03f6ced5cfcc9e88e7a8043d85923429f1a3a181953f07830f`.
- El cliente SDK `@workspace/guardian-agent-sdk` v0.3.0 completó y resumió los ocho perfiles en el mismo E2E; no recibe prompts ni permite elegir herramientas o políticas.
- `tool_choice=auto`; hash del chat template efectivo verificado por el runtime: `ec01f905b506faf0146fedd9efc747fd863dd87f4ddab4771b0c072e17021aa1`.
- Los trabajos se ejecutaron con `--network=none`, `--pull=never`, concurrencia 1 y límites ya establecidos. La evidencia declara cero llamadas externas y cero operaciones reales.
- Los artefactos de salida no contienen campos de prompt, respuesta ni argumentos en bruto; los campos de almacenamiento correspondientes son `false`. El dashboard y la exportación usan campos allow-listed.

## Verificación ejecutada

Comando E2E serial:

```sh
pnpm --filter @workspace/api-server run test:ai-assessment-e2e
```

- API/worker: **8/8**, 0 fallos, exit 0; duración `630599.604669 ms`.
- Integración de componentes del dashboard: **8/8**, 0 fallos, exit 0. Incluye informe en español, distinción de marcadores frente a llamadas nativas y fixtures, y exportación JSON sin contenido bruto.
- Sondas independientes dentro de la misma regresión: `QWEN_NATIVE_TOOL_TRACE_COUNT=24/288` y `QWEN_AUTONOMOUS_TOOL_TRACE_COUNT=39/42`. No se mezclan esos denominadores con los 36 casos de los ocho perfiles.
- Pruebas API: **63/63**; pruebas Python del laboratorio: **16/16**; pruebas SDK: **12/12**.
- Typecheck de API, librerías y web: correcto. Build API: correcto. Build web con `PORT=5000 BASE_PATH=/eu-security-platform/`: correcto, con avisos existentes de sourcemap de `tooltip.tsx` y bundle JavaScript de 683.60 kB.
- `git diff --check`: correcto.

## Artefactos y hashes

Los JSON bajo `generated-artifacts/` están excluidos de Git; sus hashes se registran aquí para identificar exactamente la salida local:

- `generated-artifacts/guardian-qwen-policy-labs-e2e-v1.7.0.json` — SHA-256 del archivo: `61111269a0f17c555fdb54ee11ce08a1f26d483730e71f5498f72821e26c11c7`.
- `generated-artifacts/guardian-agent-sdk-qwen-eight-profiles-e2e-v1.7.0.json` — SHA-256 del archivo: `5644d79172e2383565a901a50074441a82add39a4ba4514c9dabadcb8587ebde`; SHA interno de evidencia: `0898c04bb407d7867425912834f4d4d112d2c9b96ded9a1ff853d275a3e5e4eb`.

## Límites

Esto acredita que el flujo local de inferencia, adaptación de marcadores, autorización, simulación, persistencia, API, SDK y representación de dashboard funcionó en estos casos sintéticos. **No** es una medición general de precisión o eficacia, no demuestra llamadas nativas de herramientas, no conecta Gmail, bases de datos, bancos, nube ni otros sistemas de clientes, y no valida una sesión Clerk real en navegador. La aprobación del laboratorio solo reanuda una acción ficticia allow-listed. IPv6 continúa sin verificarse en el kernel actual; los bloqueos de broker, supply chain, advisories y revisión legal de licencias siguen abiertos antes de pilotos con clientes.
