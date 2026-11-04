# Fase 1 en Replit: contratos del laboratorio y regresiones

**Fecha:** 2026-11-04  
**Base del cambio:** `29953c8c31b12b297abab02c3fd26d7b9345eec7`  
**Alcance:** desarrollo local, sin despliegue, publicación, servicios externos ni producción.

## Resultado

Se reforzó el paquete de transferencia para que su verificador de PostgreSQL
compruebe una frontera real cuando se ejecute en un host Linux autorizado. Antes,
el script verificaba pertenencia a roles pero no probaba el cambio efectivo de
rol ni que cada sesión se iniciara bajo el UID Unix de su servicio. Ahora:

- La verificación exige dos UIDs Unix distintos y no-root, ejecuta la sesión
  API como `guardian-api` y la sesión worker/broker como
  `guardian-assessment-broker` mediante `runuser`.
- Cada llamada de `psql` usa el socket Unix y el nombre de base `guardian_lab_*`,
  `--no-password` y un entorno `env -i`; no hereda `PGPASSWORD`, `PGSERVICE`,
  `PGOPTIONS`, `PGPASSFILE` ni otras variables libpq.
- El verificador ejecuta `SET ROLE` y comprueba `session_user` y `current_user`
  contra el login y el rol efectivo esperados. Rechaza roles de grupo que puedan
  iniciar sesión o heredar privilegios, roles privilegiados, dueños o grants
  directos de tabla/columna tenant para los logins, o tablas sin RLS forzada.
- El provisionador de login de laboratorio sigue exigiendo ACK y nombre
  `guardian_lab_*`, utiliza socket local y `--no-password`, limpia el entorno
  libpq y crea/requiere `NOINHERIT`. No altera roles en bases ajenas.
- Se añadió un test explícitamente mockeado para los ocho perfiles: con salida
  del cliente marcada `no_marker` y `tool_choice=auto`, todos quedan
  `NO_PROPOSAL`, sin despacho ni eventos. Es una regresión de contrato, no una
  inferencia.
- La suite ejecutada mantiene los tests de los ocho fixtures adversarios
  (bloqueo antes de despacho y `Policy OFF` solo en clon contrafactual) y la
  revisión histórica de nueve ALLOWs: IDs y hash de fuente fijados, validación
  de procedencia/decisión/despacho, evidencia sin datos crudos y ausencia de
  efectos externos. Rechaza mutaciones adversas de esa evidencia; no afirma que
  esos nueve casos demuestren una vulnerabilidad ni añade inferencias.

El paquete, las unidades systemd y el verificador **no se ejecutaron** contra
un host de destino ni una base externa. Las unidades siguen siendo ejemplos;
el broker independiente todavía no forma parte del runtime de Replit. El test
actual del host confirma que el preflight falla cerrado por falta de privilegios
de administración para comprobar ambas identidades.

## Verificación ejecutada

Las suites se corrieron en serie después de los cambios:

| Capa | Resultado |
|---|---:|
| Worker Python, archivos disponibles | 179/179 en 25 archivos |
| Kit lab-as-code, pruebas específicas | 10/10 |
| `compileall` del worker | Pasó |
| `bash -n` de `preflight-host.sh`, `verify-db-identities.sh`, `provision-worker-login.sh` | Pasó |
| API | 74/74 |
| E2E de aprobaciones persistentes sintéticas | 1/1 |
| SDK Python | 8/8 |
| SDK TypeScript | 13/13 y build |
| UI de evaluaciones e informes | 8/8 |
| Typecheck de workspace | Pasó |
| Build de workspace | Pasó |
| `git diff --check` | Pasó antes del commit |

El E2E usa fixtures deterministas y persistencia de laboratorio; su salida indica
`modelInference=false` y `dockerCommandRequestedByHarness=false`. No acredita una
aprobación procedente de Qwen ni una separación de credenciales entre procesos.
El build web mantiene un aviso de sourcemap y el warning de chunk de **683.62 kB**.
El primer comando de test UI no resolvió el alias `@/`; se repitió con el
`tsconfig` del artefacto web y los ocho tests pasaron.

La suite worker global no pudo importar `test_corpus_validation.py` porque falta
el paquete Garak (`ModuleNotFoundError: garak`). No se instaló ni descargó nada.
La cuenta 179/179 excluye únicamente ese módulo; no se presenta como suite Garak
aprobada.

## Evidencia de inferencia y límites

No se lanzó Docker, el runner Qwen ni el preflight real en esta fase. Por tanto,
no hay inferencia Qwen nueva ni evidencia nueva de separación UID/socket/DB.
La evidencia histórica, sin cambios, sigue siendo:

- Ocho inferencias anteriores con `tool_choice=auto`: 7 propuestas por
  marcadores Qwen adaptados, 0 `message.tool_calls` nativas y 1 `no_proposal`.
- Artefacto histórico:
  `generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`,
  SHA-256 `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
- Preflight histórico bloqueado:
  `generated-artifacts/guardian-qwen-offline/preflight-status-2026-11-04.json`,
  SHA-256 `0b6246f76877a2874dc7834cacba1c76979a61e7871b1371515268dee8e85f52`.

La prueba local de aprobación es sintética y separada de esas inferencias.
Clerk en navegador, IPv6 dual-stack, Garak, la auditoría actualizada de
dependencias/licencias y la identidad broker independiente permanecen pendientes
de sus entornos/autorizaciones respectivos. No se afirma preparación comercial.

## Siguiente paso verificable

En una VM Linux desechable autorizada, ejecutar primero el preflight con dos
cuentas no-root reales y el broker rootless, y luego el verificador DB con
autenticación `peer` local y `NOLOGIN`/`NOINHERIT` para los roles grupo. Solo si
ambos verifican UID, socket, logins y roles por separado se puede desbloquear el
runner Qwen. En Replit se mantiene el bloqueo; no se debe omitir ni relajar.

Los logs de esta corrida y el manifiesto SHA-256 se guardan junto al workspace
en `generated-artifacts/guardian-qwen-offline/phase1-continued-2026-11-04/`.
El manifiesto comprobable se versiona en
`reports/phase1-lab-contracts-and-regressions-2026-11-04.sha256`; el checkpoint
del proyecto registra los comandos, resultados y límites.
