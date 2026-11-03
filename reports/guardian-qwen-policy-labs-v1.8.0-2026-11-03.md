# Validación del corpus Qwen y contratos v1.8.0

Fecha: 2026-11-03  
Base solicitada: `afeb452c41d14b8c7e02801cc548c0041d691498`.  
HEAD de trabajo al comenzar los cambios: `9b7b22f9c1935a40ac1a62cc8a3dfc7583d2ec2a`,
descendiente de la base solicitada.  
Alcance: validar el worker reproducible, contrato de evidencia y ocho perfiles
Qwen locales; no se publicaron cambios ni se conectaron servicios empresariales.

## Cambios

- Los límites de casos del worker se derivan del corpus por perfil, no de
  constantes obsoletas. El límite coincide con los datos: seis casos para la
  mayoría, diez para atención al cliente y siete para multiagente.
- Se sincronizó OpenAPI, código Zod/cliente generado y el SDK para aceptar como
  máximo diez casos de evidencia Qwen. Se conserva la lectura de contratos
  antiguos y se rechazan once casos.
- Se retiró del E2E una ruta que convertía evidencia fixture en una supuesta
  ejecución Qwen. La regresión ahora verifica que esa ejecución siga etiquetada
  `deterministic_fixture` y rechaza, con dos respuestas `409`, una aprobación
  Qwen ligada a fixture; no despacha ni simula.
- La validación de evidencia mantiene el esquema estricto. Los errores de
  esquema ahora registran cantidad y rutas/códigos acotados (primeras 40 y
  últimas 20 incidencias), sin incluir valores, prompts, respuestas ni
  argumentos.

## Inferencia local observada

Se ejecutaron los ocho perfiles con Qwen local, `tool_choice=auto` y datos y
herramientas sintéticos. La columna «sin propuesta» no es una denegación. Las
propuestas son marcadores Qwen completos adaptados por el runner; no se
observaron `message.tool_calls` nativos en estos 53 casos.

| Perfil | Casos (benignos/adversarios) | Marcadores adaptados | Nativas | Sin propuesta | ALLOW | DENY | Aprobación |
|---|---:|---:|---:|---:|---:|---:|---:|
| Correo | 6 (2/4) | 4 | 0 | 2 | 4 | 0 | 0 |
| Bases de datos | 6 (2/4) | 5 | 0 | 1 | 5 | 0 | 0 |
| Finanzas | 6 (2/4) | 4 | 0 | 2 | 3 | 0 | 1 |
| Atención al cliente | 10 (5/5) | 3 | 0 | 7 | 1 | 1 | 1 |
| Programación | 6 (2/4) | 5 | 0 | 1 | 1 | 4 | 0 |
| Navegador | 6 (2/4) | 3 | 0 | 3 | 1 | 2 | 0 |
| Infraestructura | 6 (2/4) | 4 | 0 | 2 | 2 | 2 | 0 |
| Multiagente | 7 (2/5) | 7 | 0 | 0 | 2 | 5 | 0 |
| **Total** | **53 (19/34)** | **35** | **0** | **18** | **19** | **14** | **2** |

Las 19 acciones ALLOW se simularon; hubo cero acciones no autorizadas, cero
llamadas externas y cero ejecuciones de la rama Policy OFF. Los 14 DENY no se
despacharon. Estos resultados describen esta muestra sintética y no son una
medida general de eficacia. No se extrapolan tasas de detección.

## Aprobaciones y procedencia

- Las dos propuestas `require_approval` de la suite proceden de inferencia local
  (finanzas y soporte). Se probó una aprobación con una única simulación
  ficticia y una expiración sin ejecución.
- Mutar el hash de propuesta o cambiar la versión de política devuelve `409`;
  revocar el rol del aprobador devuelve `403`; una propuesta de finanzas
  denegada no se simula y el replay devuelve `409`.
- La sonda separada `QWEN_NATIVE_TOOL_TRACE_COUNT=24/288` no forma parte de los
  53 casos y no cambia el resultado de cero llamadas nativas en ellos.
  `QWEN_AUTONOMOUS_TOOL_TRACE_COUNT=39/42` también es una sonda independiente.
- `QWEN_ACTION_ON_FIXTURE_REJECTED=2x409` confirma que una fixture no se puede
  presentar como origen Qwen.

## Verificación ejecutada

Todos los comandos se ejecutaron en desarrollo, sin servicios externos:

- `cd workers/guardian-ai-assessment && sh scripts/run-local.sh --unit-tests`:
  **120/120** pruebas.
- `pnpm --filter @workspace/api-server typecheck` y
  `pnpm --filter @workspace/api-server test`: **63/63**.
- `pnpm --filter @workspace/guardian-agent-sdk test` y build del SDK: **13/13**.
- `pnpm --filter @workspace/api-spec codegen`: completado.
- `pnpm --filter @workspace/api-server test:ai-assessment-e2e`: API/worker
  **9/9** (823360 ms); componentes e integración del dashboard **8/8**
  (2408 ms). El test incluyó los ocho perfiles, denegación de finanzas,
  aprobaciones persistentes, aislamiento de tenant, fixtures y exportación
  JSON redactada.
- `PORT=5000 BASE_PATH=/eu-security-platform/ pnpm run build`: exit 0; incluye
  typecheck del workspace y builds. Quedan avisos de sourcemap en
  `tooltip.tsx` y de chunk JavaScript de 683.60 kB.
- `git diff --check`: limpio.

El primer build sin variables falló porque `mockup-sandbox` exige `PORT`; el
build repetido con las variables de desarrollo terminó correctamente. Una
corrida E2E intermedia informó `worker_output_invalid` en infraestructura; el
caso enfocado posterior produjo evidencia válida y la E2E completa final pasó.
La causa de esa incidencia intermedia no se atribuye sin evidencia.

## Evidencia y límites

El artefacto local `generated-artifacts/guardian-qwen-policy-labs-e2e-v1.8.0.json`
tiene 136398 bytes y SHA-256
`bb4b7cacd9963340e29a58af04be5b134d2924fac262cdb3c3689dce74edccf4`. Contiene
los ocho perfiles con versión `guardian-qwen-policy-lab-v1.8.0`; todos usan
`tool_choice=auto`. La inspección encontró cero campos de contenido bruto y
todos los indicadores de persistencia de prompt/respuesta/argumentos en
`false`.

La exportación autenticada se verificó mediante E2E y componentes; no se probó
una sesión real de Clerk en navegador. Qwen sigue usando marcadores adaptados,
no llamadas nativas en esta batería. Es un laboratorio local sintético, no
conectores empresariales ni un servicio listo para clientes. Los bloqueos de
broker Docker separado, IPv6 dual-stack, avisos de cadena de suministro,
revisión legal de licencias y sesión Clerk real permanecen abiertos.
