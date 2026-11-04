# Preflight portable de aislamiento Qwen — 2026-11-04

## Resultado verificado en el host actual

El preflight es de solo lectura y no conecta con Docker ni PostgreSQL. Solo
consulta UID/GID/grupos efectivos, metadatos y permisos efectivos de sockets
Unix conocidos, descriptores de socket heredados y la **presencia de nombres**
de variables sensibles. Nunca lee ni imprime sus valores.

Resultado de `scripts/run_qwen_isolation_preflight.py`:

- Exit code `1`; `offlineQwenProcessReady=false`.
- Identidad efectiva: UID `1000`, GID `1000`, grupos `[1000]`.
- `DOCKER_HOST`, `DOCKER_CONTEXT` y `CONTAINER_HOST`: no configurados.
- `/var/run/docker.sock` y `/run/docker.sock`: socket y accesible para lectura
  y escritura por la identidad efectiva actual; la comprobación no conectó.
  `/run/user/1000/docker.sock`: ausente.
- Descriptores de socket heredados: `0`.
- Se detectó presencia de cuatro nombres de variables sensibles/credenciales;
  el preflight no registra cuáles, no lee sus valores y bloquea el runner con
  `offline_sensitive_environment_present`.
- Identidad real de proceso broker: no acreditada.
- Separación autenticada de identidades de base de datos API/worker: no
  verificada; no se abrió conexión DB ni se leyeron credenciales.
- Resultado integrado: `integratedAssessmentReady=false`; ninguna inferencia
  Qwen nueva se ejecutó.

La salida JSON redacted queda en
`generated-artifacts/guardian-isolation-preflight/current.json`. SHA-256:
`ddfd8720016f745d93ddbb01d33100ab1e4d1180d3157418268797e04af69d42`.

## Cambio y garantías

- Se añadió un preflight portable que distingue ejecución standalone de Qwen
  frente a preparación integrada API/worker. La identidad y el acceso al socket
  se comprueban para el proceso actual; la frontera broker/DB queda
  explícitamente `unverified` si no existe evidencia autenticada.
- El runner Qwen consulta el preflight antes de crear artefactos, leer
  manifiestos o cargar el modelo. No se debilita el preflight Docker previo ni
  el gate API, que continúa `disabled`.
- La salida no incluye valores de entorno. Las pruebas usan un mapa de entorno
  que lanza error si se intenta leer un valor.
- No se añadió una afirmación de aislamiento de DB basada en nombres de roles o
  configuración declarada. Para acreditar esa frontera harán falta identidades
  de proceso realmente separadas y una verificación de `current_user` desde
  sesiones API y broker autorizadas, sin compartir sus credenciales.

## Pruebas ejecutadas

Todas se ejecutaron serialmente, sin servicios externos, Docker ni DB:

| Suite | Resultado |
| --- | ---: |
| Worker Python en host, excluyendo únicamente `test_corpus_validation.py` | 152/152 |
| `test_offline_isolation_preflight.py` | 8/8 |
| `test_offline_process_guard.py` | 10/10 |
| `test_policy_lab.py` (ocho perfiles deterministas) | 26/26 |
| `assessment-worker-mode.test.ts` (gate y contrato broker) | 4/4 |

Las tres suites Python detalladas están incluidas en el total worker, no se
suman aparte. `test_corpus_validation.py` requiere el paquete Garak, ausente en
el host; se omitió y no se instalaron dependencias.

La prueba de integración del runner confirma que, si el preflight falla, el
runner se detiene antes de crear el directorio de resultados o cargar
manifiestos/modelo. No se ejecutó inferencia real Qwen: el host falla las dos
condiciones locales detectadas y no acredita broker/DB. Las pruebas de Policy
Lab siguen siendo fixtures deterministas; no se cuentan como inferencia.

## Límites y siguiente desbloqueo

El nuevo preflight es diagnóstico y una barrera fail-closed dentro del runner;
no revoca permisos del UID ni sustituye aislamiento de host. La API y el broker
siguen compartiendo la limitación del entorno, y la API conserva el gate
cerrado. Para habilitar ejecución integrada se necesita un host que demuestre
UID/GID distintos, socket inaccesible desde API, broker con acceso mínimo al
socket y sesiones PostgreSQL con identidades API/worker distintas. Esas
verificaciones requieren el host y las sesiones autorizadas; no se simulan.
