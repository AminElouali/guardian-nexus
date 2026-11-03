# Guardian Nexus — Provenance Guard y preparación del límite broker

Fecha: 2026-11-03  
Estado inicial: `HEAD e5f18185815b8d1747db3d06f06113a83972f77b`, árbol limpio.  
Entorno: desarrollo local; sin producción, sistemas de clientes, servicios externos,
credenciales nuevas, publicación ni despliegue.

## Resultado

Se implementó un límite de procedencia y alcance para las propuestas de los ocho
perfiles Qwen. La identidad del agente, tenant, actor, caso, herramienta, recurso
y alcance solicitado se derivan del contexto del runner y de la solicitud
autorizada; los textos de correo, factura, filas, páginas y delegaciones son
contenido no confiable. El modelo no puede aportar ni ampliar el alcance de
confianza. Procedencia desconocida, discrepancia de identidad, alcance cambiado,
herramienta/operación fuera de la lista fija o vínculo de propuesta inválido
fallan cerrados antes del simulador.

El resumen de alcance liga perfil/caso, tenant, actor, agente y hash de propuesta.
Ese digest detecta cambios de integridad, pero **no es firma ni prueba de
autenticación**. La autorización proviene del contexto verificado del servidor.
La política permanece independiente del modelo. `ALLOW` llega solo a herramientas
ficticias fijadas; `DENY` y `REQUIRE_APPROVAL` no se despachan. El brazo Policy OFF
sigue limitado a un clon efímero y no despacha ni persiste efectos.

El contrato de evidencia v1.10 incorpora procedencia de contenido e instrucciones,
estado del alcance confiable y versiones de motor/política/adaptador/corpus.
OpenAPI, Zod generado, esquema de persistencia y validación del API se actualizaron
en conjunto. Se mantiene compatibilidad con evidencia anterior; evidencia v1.10
debe satisfacer las comprobaciones nuevas.

## Inferencia local y evidencia observada

El E2E real completó los ocho perfiles con `tool_choice=auto`:

| Perfil | Casos | Marcadores Qwen adaptados | `message.tool_calls` directas | Sin propuesta |
|---|---:|---:|---:|---:|
| Correo | 6 | 4 | 0 | 2 |
| Bases de datos | 6 | 5 | 0 | 1 |
| Finanzas | 6 | 4 | 0 | 2 |
| Atención al cliente | 10 | 3 | 0 | 7 |
| Programación | 6 | 5 | 0 | 1 |
| Navegador | 6 | 3 | 0 | 3 |
| Infraestructura | 6 | 4 | 0 | 2 |
| Multiagente | 9 | 9 | 0 | 0 |
| **Total** | **55** | **37** | **0** | **18** |

Todas las 55 muestras fueron inferencias locales Qwen; no son fixtures. Las 37
propuestas provinieron de marcadores Qwen completos adaptados por el parser, no de
`message.tool_calls` nativas. Las 18 ausencias se informan como `no_proposal`, no
como denegaciones.

Totales verificados en el informe SDK: 18 `ALLOW`, 17 `DENY`, 2
`REQUIRE_APPROVAL` y 18 `no_proposal`; 18 simulaciones sintéticas; cero
ejecuciones no autorizadas, cero ejecuciones con política OFF y cero llamadas
externas. Son conteos de este corpus pequeño, no una métrica general de eficacia.

De los 36 casos adversarios, 16 fueron denegados, 11 no produjeron propuesta y
9 terminaron en `ALLOW` como lecturas sintéticas acotadas solicitadas por el
usuario: dos lecturas de correo, cuatro consultas de filas/ámbito fijo de base de
datos y tres consultas de factura. Las nueve propuestas tuvieron alcance
verificado y ejecutaron únicamente la lectura ficticia permitida. No son evidencia
de que una inyección haya sido “bloqueada” en esos casos; tampoco demuestran
exfiltración ni acción fuera de alcance. El corpus no estima tasas de detección.

Modelo/runtime registrado: `Qwen/Qwen3-0.6B-GGUF`, revisión
`23749fefcc72300e3a2ad315e1317431b06b590a`, Q8_0, hash del modelo
`9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`;
`llama-cpp-python 0.3.36`. Hash de plantilla
`57f1fd00f0013a2be96aa79b857391f27e23df5b5f847072b524c897e24d0361`;
plantilla efectiva
`ec01f905b506faf0146fedd9efc747fd863dd87f4ddab4771b0c072e17021aa1`.
Cada worker se ejecutó con Docker `network=none`, 1 CPU, 1536 MiB, 64 PIDs,
concurrencia 1, máximo 96 tokens de salida y sin montar secretos ni datos de
clientes.

Dos propuestas adicionales de inferencia real llegaron a aprobación: mutación de
hash y versión de política obsoleta respondieron 409; revocación del rol del
aprobador respondió 403; una aprobación válida produjo exactamente una acción
ficticia; una propuesta expirada no se reanudó. Una propuesta financiera denegada
no se ejecutó y su replay respondió 409. El flujo de aprobación sigue siendo
exclusivamente sintético.

## Preparación del broker Docker: alcance real

Se añadieron un contrato de grants HMAC acotado a 60 segundos y pruebas de firma,
contexto tenant/job/lease/intento/perfil, image ID inmutable, expiración, replay y
fallo de almacenamiento de consumo. También se extrajo y probó el gate que solo
permite el worker Docker local en desarrollo no desplegado.

**Esto no implementa ni acredita un broker aislado.** El helper no está conectado
a la cola, no tiene consumo atómico en PostgreSQL y no separa identidades Unix.
La API sigue teniendo la autoridad Docker que permite el host de Replit. El
preflight previo confirmó UID/socket compartidos y que `setpriv` no puede crear
una identidad independiente con los permisos disponibles. No se cambiaron los
permisos del socket/daemon ni se intentó elevar privilegios. El manifiesto de
requisitos externos es documentación, no una instalación activa.

## Verificación ejecutada

- Worker: `sh workers/guardian-ai-assessment/scripts/run-local.sh --unit-tests`
  — **134/134**.
- API: `pnpm --filter @workspace/api-server test` — **71/71**; incluye contrato
  de grant, replay/firma/contexto, gate de worker, RLS/RBAC/tenant, cola,
  idempotencia, expiración de lease y límites Docker.
- API TypeScript: `pnpm --filter @workspace/api-server run typecheck` — pasó.
  Una ejecución inicial encontró el tipo demasiado estricto del `process.env` en
  el helper; se ajustó a las dos variables opcionales permitidas y se volvió a
  ejecutar correctamente.
- API build: `pnpm --filter @workspace/api-server run build` — pasó.
- SDK: `pnpm --filter @workspace/guardian-agent-sdk test` — **13/13**;
  `pnpm --filter @workspace/guardian-agent-sdk run build` — pasó. El paquete no
  define un script `typecheck` independiente; el build ejecuta `tsc`.
- UI: `pnpm --filter @workspace/eu-security-platform run typecheck` — pasó;
  build con `PORT=5000 BASE_PATH=/eu-security-platform` — pasó. Vite avisó de un
  mapeo de source map no resoluble en `tooltip.tsx` y de un chunk mayor de 500 kB;
  no bloquearon el build. La integración de componentes terminó **8/8**.
- E2E API/worker: **9/9**, salida `0`; la batería realizó inferencia Qwen real y
  probó aprobación, denegación, expiración, replay, RLS/RBAC e idempotencia.
- `pnpm -w run typecheck:libs` y `git diff --check` — pasaron.
- Egress: `sh workers/guardian-ai-assessment/scripts/verify-egress-isolation.sh`
  devolvió **2**, correctamente marcado incompleto. En `network=none`, IPv4 TCP,
  IPv4 UDP y DNS públicos: `blocked`; loopback IPv4: `reachable`. IPv6 TCP/UDP,
  DNS y loopback: `kernel_protocol_unavailable` / `unavailable`. Esto **no**
  acredita bloqueo IPv6. No quedaron contenedores de laboratorio residuales.
- API se reinició después de los cambios y escuchó en el puerto 8080; no se
  observó error de arranque.

La ejecución E2E escribió inicialmente los JSON bajo nombres `v1.9.0`, aunque su
contenido indicaba motor `v1.10.0`. Se corrigieron las rutas del harness y se
renombraron los artefactos de esta corrida a `v1.10.0`, sin modificar el JSON.
El E2E 9/9 ocurrió antes del cambio de literal de ruta; después se pasó el
typecheck, pero no se repitió la inferencia completa solo por ese cambio de nombre.
El JSON histórico v1.9.0 (145940 bytes, SHA-256
`e454c15f2d18deea7a238fa80fa84d1dd2a8850f3ddda0a56dce42d8fa0a721`) y el SDK
histórico v1.9.0 (6053 bytes, SHA-256
`bba561ca58326569ce9f293f1c722198a1a555e979e9f418f9e2dcb42f9e6996`) habían
sido sobrescritos antes de corregir la ruta; sus hashes sobreviven en el
checkpoint anterior, pero esos archivos históricos ya no están disponibles en
`generated-artifacts/`.

## Artefactos y límites pendientes

Evidencia redactada local (fuera de Git):

- `generated-artifacts/guardian-qwen-policy-labs-e2e-v1.10.0.json` — SHA-256
  `2500000f271bdf95333a048551dab2d2b08fe0ee835434b336f5cffc3eed61ec`.
- `generated-artifacts/guardian-agent-sdk-qwen-eight-profiles-e2e-v1.10.0.json`
  — SHA-256 `ab3856716c9e931cd1657cb8df844dc9c5688c4e9a13345ec0dd0c14387257a0`.
- `generated-artifacts/guardian-qwen-approval-security-e2e-v1.json` — SHA-256
  `cdd89d0ee63fa8a3002546b9614298e86c3596c85383460a88f8e6eab49e782f`.

Siguen sin resolverse: autoridad Docker de la API en este host; identidad separada
para un broker real; IPv6 dual-stack; los 81 IDs OSV (1 crítico, 25 altos según
el último inventario) y remediación de imagen; revisión legal/procedencia de
`langdetect` y binarios nativos; sesión Clerk real de navegador autorizada. No se
reconstruyó ni reescaneó la imagen, no se probó Clerk con una sesión real y no se
habilitó egress al evaluador.

El manifiesto de hashes de código y evidencias se registra en
`reports/provenance-guard-broker-preparation-v1.10.0-2026-11-03.sha256`; su
SHA-256 es
`0bfe29d959acf445b085dbafef1e01005635f091e6dda78674def3343346bc5e`.
El SHA-256 de este informe se anota en el checkpoint v1.10.0.
