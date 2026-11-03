# Verificación E2E de aprobaciones Qwen y despacho adversarial

**Fecha:** 2026-11-03  
**Commit base:** `af26a03ccb10f93e1ececc109449d7c0037c6687` (árbol limpio al inicio)  
**Alcance:** pruebas de desarrollo; no se cambió el producto ni se habilitaron acciones externas.

## Qué se verificó

Se fortaleció el E2E existente de los ocho perfiles para comprobar el orden
propuesta → política/adaptador → simulador. No se añadieron entradas al corpus:
la corrida volvió a ejecutar las 36 entradas sintéticas ya existentes, incluidas
11 benignas y 25 adversarias.

En cada perfil las aserciones ahora comprueban:

- `no_proposal` corresponde a `no_tool_call`, no se despacha y no simula;
- `deny` se detiene antes del simulador por política o validación del adaptador;
- `require_approval` queda sin despacho y sin simulación hasta una decisión válida.

## Inferencia Qwen local — `tool_choice=auto`

Modelo local Qwen3-0.6B, modo `tool_choice=auto`. El resultado cuenta
propuestas generadas por el modelo como marcadores Qwen completos que el
adaptador interpreta; **no** las presenta como llamadas nativas del runtime.

| Perfil | Casos | Marcadores adaptados | Nativas directas | Sin propuesta | ALLOW | DENY | Aprobación | Simulaciones |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Correo | 4 | 2 | 0 | 2 | 2 | 0 | 0 | 2 |
| Base de datos | 4 | 3 | 0 | 1 | 3 | 0 | 0 | 3 |
| Finanzas | 4 | 3 | 0 | 1 | 2 | 0 | 1 | 2 |
| Atención al cliente | 8 | 3 | 0 | 5 | 1 | 1 | 1 | 1 |
| Programación | 4 | 4 | 0 | 0 | 1 | 3 | 0 | 1 |
| Navegador | 4 | 2 | 0 | 2 | 1 | 1 | 0 | 1 |
| Infraestructura | 4 | 3 | 0 | 1 | 1 | 2 | 0 | 1 |
| Multiagente | 4 | 4 | 0 | 0 | 1 | 3 | 0 | 1 |
| **Total** | **36** | **24** | **0** | **12** | **12** | **10** | **2** | **12** |

No hubo marcadores sin parsear. Las 12 acciones ALLOW fueron simulaciones
ficticias. No hubo ejecución no autorizada, efecto real, llamada externa ni
ejecución con Policy OFF.

### Casos adversarios

| Perfil | Casos adversarios | Sin propuesta | DENY | `require_approval` |
|---|---:|---:|---:|---:|
| Correo | 3 | 2 | 0 | 0 |
| Base de datos | 3 | 0 | 0 | 0 |
| Finanzas | 3 | 1 | 0 | 0 |
| Atención al cliente | 4 | 3 | 1 | 0 |
| Programación | 3 | 0 | 3 | 0 |
| Navegador | 3 | 2 | 1 | 0 |
| Infraestructura | 3 | 1 | 2 | 0 |
| Multiagente | 3 | 0 | 3 | 0 |
| **Total** | **25** | **9** | **10** | **0** |

Los resultados restantes se reflejan en la tabla general, pero no se convierten
en una tasa de precisión o garantía. La muestra es pequeña y sintética; no
demuestra efectividad general contra agentes reales.

## Aprobaciones persistentes originadas por Qwen

La corrida encontró dos propuestas `require_approval`, originadas por inferencia
local real en finanzas y atención al cliente.

- **Aislamiento tenant:** un aprobador de otro tenant recibe `404`.
- **Vínculo alterado:** modificar el hash de la propuesta produce `409`; no se
  ejecuta la acción.
- **Rol revocado:** el aprobador sin el rol requerido recibe `403`; no se ejecuta.
- **Concurrencia e idempotencia:** dos decisiones simultáneas sobre la misma
  propuesta resultan en `200/409`; solo una reanuda una acción allow-listed
  ficticia y persiste hashes de simulación y replay.
- **Caducidad:** aprobar o repetir una propuesta expirada falla con conflicto y
  sin marca de simulación.
- **Denegación:** una propuesta Qwen de finanzas puede ser denegada; la decisión
  inicial devuelve `200`, el replay `409` y no existe resultado de simulación.

La suite separada de aprobación sobre fixture conserva `source=allowlisted_test_fixture`;
no se atribuye al modelo. Ninguna aprobación realiza correo, pago, cambio bancario
ni otra operación externa.

## Ejecución y artefactos

Validaciones seriales, todas con código de salida 0:

| Verificación | Resultado |
|---|---:|
| Typecheck raíz | pasó |
| Build raíz (`PORT=5000 BASE_PATH=/eu-security-platform/`) | pasó |
| Typecheck API | pasó |
| Tests unitarios API | 63/63 |
| Build SDK | pasó |
| Tests SDK | 12/12 |
| Tests worker en perfil de contenedor | 87/87 |
| E2E API/worker | 9/9, 685504 ms |
| Componentes/integración dashboard | 8/8, 1702 ms |
| `git diff --check` | pasó |

Evidencias JSON locales, ignoradas por Git:

- `generated-artifacts/guardian-qwen-policy-labs-e2e-v1.7.0.json` — SHA-256
  `f793b5ecdace054a53090adb649953eb5629f22d8aa48a57fa3d22157d00ef18`.
- `generated-artifacts/guardian-agent-sdk-qwen-eight-profiles-e2e-v1.7.0.json`
  — SHA-256 `761dcff8069af0f607aab9bfa4ea60b0b88b601c445efe9411f905b26976ab27`;
  hash interno de evidencias `f3d50a57813a93476e55ff6fcf45da22dc604fd7469b40b389b46a118aa4bb3a`.
- `generated-artifacts/guardian-qwen-approval-security-e2e-v1.json` — evidencia
  resumida de denegación Qwen en finanzas, SHA-256
  `d7d752b2b726aedfd41b0440fe6a62ad5b02c14edff908bd9349248a87616764`;
  hash interno `6eba6f935f75fed269d8218c08f2e8dc5e5c82e1f0b1df7206dbc10b74387d64`.

Los indicadores del artefacto SDK son `rawPromptsResponsesArgumentsPersisted=false`,
`externalCalls=0`, `unauthorizedExecutions=0` y `policyOffExecutions=0`.
La sonda nativa separada registró `QWEN_NATIVE_TOOL_TRACE_COUNT=24/288`; la
prueba autónoma separada, `QWEN_AUTONOMOUS_TOOL_TRACE_COUNT=39/42`. Ninguna se
mezcla con los 36 casos de selección automática aquí descritos.

## Límites pendientes

- La UI pasó pruebas de componentes/integración; no se validó una sesión real de
  Clerk en navegador.
- El flujo solo simula herramientas y no conecta Gmail/Outlook, bancos, bases de
  datos de clientes, proveedores cloud ni sistemas de terceros.
- No es una evaluación estadística de eficacia ni una garantía de bloqueo.
- La separación del daemon Docker mediante identidad host independiente,
  IPv6 dual-stack, remediación/triage de advisories y revisión legal de
  licencias/procedencia siguen pendientes antes de pilotos con clientes.
