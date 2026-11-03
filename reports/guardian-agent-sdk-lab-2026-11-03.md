# Validación local del SDK Guardian Nexus — 2026-11-03

## Resultado

El paquete TypeScript `@workspace/guardian-agent-sdk` v0.1.0 se puede compilar,
empaquetar y consumir desde un proyecto local. Su E2E contra la API de desarrollo
completó una solicitud sintética de finanzas con aprobación persistente y una
reanudación simulada de un solo uso. No se publicó el paquete.

El flujo del SDK es deliberadamente más estrecho que un SDK de despacho
arbitrario: el cliente solo elige un `scenarioId` de un catálogo fijo. La API
deriva identidad, rol, workspace, herramienta, recurso y permisos desde la
sesión autenticada; el cliente no puede enviar una decisión de política,
argumentos de herramienta ni destino externo.

## Aprobación y límites

- El caso permitido es un cambio bancario ficticio con `require_approval`.
- La aprobación queda asociada a tenant, propuesta y binding criptográfico;
  se comprueban rol, expiración, concurrencia e idempotencia.
- Al aprobar, el sistema solo simula la acción una vez sobre un clon en memoria.
  `externalDispatch=false`; no se envían correos ni se contactan bancos,
  proveedores o sistemas de clientes.
- DENY y `require_approval` no se despachan directamente.
- El SDK recibe el token mediante un callback de la sesión anfitriona, no lo
  almacena, no envía cookies y no sigue redirecciones.

## Verificación ejecutada

| Comprobación | Resultado |
| --- | --- |
| API/worker E2E serial completo | 8/8 pruebas; exit 0; 607.161 s |
| Integración de componentes del dashboard | 8/8; exit 0 |
| E2E dirigido de aprobación persistente | 1/1 |
| API unit/regresión | 60/60 |
| Worker, `test_policy_lab.py` | 16/16 |
| SDK build y unit tests | build correcto; 8/8 |
| E2E dirigido del SDK tras el último cambio | 1/1 |
| Typecheck API y librerías | correcto |
| Typecheck y build web | correcto con `PORT=18753 BASE_PATH=/` |
| Build API | correcto |
| Workflows locales tras reinicio | API `/api/healthz` 200; web `/` 200 |
| Consumo del tarball en un consumidor temporal local | import y construcción del cliente correctos; sin registry ni dependencias nuevas |

En la misma regresión E2E, las pruebas separadas del laboratorio Qwen registraron
24/288 en la sonda de llamadas nativas y una traza autónoma de 39/42. El test de
los ocho perfiles Qwen pasó; registró dos propuestas que requerían aprobación,
una simulada una sola vez y otra expirada sin ejecución. Estos resultados Qwen
pertenecen al laboratorio existente y no son inferencia del flujo determinista
del SDK.

Después de la suite completa se hizo un ajuste acotado al mapeo sanitizado de
errores SDK. La suite completa no se repitió tras ese ajuste; sí se repitieron el
build/tests SDK (8/8) y el E2E dirigido SDK→API (1/1).

## Correcciones de contrato

- Se conserva la representación RFC3339 original de los timestamps al verificar
  el hash de evidencia; la coerción a `Date` reserializaba bytes y rompía la
  validación.
- La verificación del hash de caso sigue el contrato de cada motor: el
  laboratorio determinista calcula el digest antes de añadir el campo; Qwen
  usa el sentinel vacío. La API no relaja la validación.
- El SDK usa una consulta de propiedad propia al traducir errores conocidos, y
  conserva códigos desconocidos solo como cadenas sanitizadas.
- Se regeneraron los clientes OpenAPI/Zod.

## Evidencias y hashes

- E2E del SDK, `generated-artifacts/guardian-agent-sdk-e2e.json`:
  SHA-256 `4aa9b485bce050d9d689245c07ff8a723e98ef769548d8b8985aa34d96b7d391`.
- Resultado Qwen de ocho perfiles,
  `generated-artifacts/guardian-qwen-policy-labs-e2e.json`:
  SHA-256 `1e6dd1a6a075b7a20c0ab51cd1bc600f09e1bfdbaea6110a9fb18ea07bf18142`.
- Respuesta E2E autónoma Qwen,
  `generated-artifacts/ai-assessment-autonomous-e2e-response.json`:
  SHA-256 `3166970725017e6df31b2f3111a500652d662cf00ff1cf4698ab6bc252235756`.
- Tarball local v0.1.0, no publicado:
  SHA-256 `1614022614996784b3186ac013cf27ea6950e657b06458aac5729f7fd84de90d`.
- Log de la regresión serial (ubicado en `/tmp` durante esta ejecución):
  SHA-256 `5ea6e7f7cd33d503830c3bdace25b86c76265e9e30d69233021d0bb004c1d4b8`.

## Fallos y limitaciones

- El primer E2E completo encontró dos fallos de evidencia/expectativa; se
  corrigieron sin relajar validación. La repetición serial completa pasó 8/8.
- Un primer intento del build web omitió `PORT` y no cargó Vite; el build con
  `PORT=18753 BASE_PATH=/` terminó correctamente. Persisten avisos de sourcemap
  en `tooltip.tsx` y de chunk superior a 500 kB.
- No se verificó un inicio de sesión real de Clerk en navegador. El E2E usa un
  harness de autenticación de desarrollo; no es una sesión Clerk real.
- El paquete solo se consumió localmente desde su tarball. No está publicado,
  no hay OAuth/conectores reales y no debe presentarse como integración lista
  para clientes.
- Toda la evidencia usa datos y herramientas sintéticos. El uso de Qwen y este
  SDK no demuestra eficacia general ni garantiza prevención.
