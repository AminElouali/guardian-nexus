# Guardian Nexus — preflight de broker y controles de ejecución

Fecha: 2026-11-02. Alcance: desarrollo local; no se modificaron producción,
permisos del daemon/socket, secretos, base de datos ni configuración de Replit.
No se ejecutaron evaluaciones durante la auditoría de la frontera. Después se
validó una corrección local de limpieza ante exceso de salida.

## Conclusión sobre el broker

No es posible demostrar aislamiento API/broker en el host actual sin cambios
privilegiados del host, que no se realizaron. HEAD de partida:
`10f8c7242a998a00eccbac0cb2aad09ca80f1f22`; el árbol estaba limpio.

Evidencia observada:

- API Node: UID `runner` (1000), GID `runner` (1000), sin grupos suplementarios.
- `/var/run/docker.sock`: `root:runner`, modo `0660`; el usuario actual puede
  escribirlo y el API se ejecuta con esa misma identidad.
- `setpriv --reuid=65534 --regid=65534 --clear-groups -- /usr/bin/id` no pudo
  cambiar UID: `setresuid failed: Operation not permitted` (salida 127). No se
  intentó crear usuarios, usar `sudo`, alterar ACL/permisos ni adquirir
  privilegios.
- La búsqueda de documentación oficial Replit no confirmó ejecución con UID
  separado ni aislamiento de Secrets por workflow. No se inspeccionaron valores
  de entorno ni secretos.

Una segunda instancia Node/workflow bajo `runner` conservaría acceso al socket;
no constituye una frontera. El broker queda bloqueado hasta disponer de un host
que permita UID/GID distintos, socket accesible exclusivamente por el broker,
credenciales PostgreSQL exclusivas y confirmación de que el API no recibe esas
credenciales. El plan técnico puede conservar la tabla/leases actuales; requiere
separar grants/roles y configuración, pero no necesariamente migrar el esquema.

## Arquitectura y autorización verificadas en código

- `artifacts/api-server/src/index.ts` ejecuta `assertRlsRuntimeReady()`,
  `startLocalAssessmentQueueWorker()` y `app.listen()` en el mismo proceso.
- El poller reclama trabajos desde `ai_assessment_jobs` cada 2 s con
  `FOR UPDATE SKIP LOCKED`; lease 45 s, heartbeat 10 s, hasta dos intentos y un
  slot global.
- `withAiAssessmentQueueTransaction()` hace `SET LOCAL ROLE app_runtime` y
  después `SET LOCAL ROLE app_ai_assessment_worker`, fijando el lease. La
  comprobación de arranque requiere que la sesión pueda asumir ese rol de cola,
  aunque comprueba que este no lea la columna `result`. El test de seguridad
  verifica metadatos de cola, denegación de lectura de resultados y denegación
  de cambios de tenant. Hoy esta vía existe también desde el proceso API.
- Las rutas de trabajo usan Clerk `requireAuth`, validan membresía workspace,
  rol owner/admin para evaluación, perfil permitido, cuota e idempotencia.
  `GET /healthz` y `GET /plans` son públicos y no contienen resultados de
  tenant. El callback OAuth Microsoft no exige sesión Clerk en el retorno, pero
  verifica estado firmado/expirado, nonce de un solo uso y membresía/rol
  actuales.
- No hay endpoint de descarga JSON separado: el navegador crea el Blob desde un
  job ya recibido por la ruta autenticada y tenant-scoped. El builder del
  informe usa campos allowlisted; la prueba UI valida que se descarten
  propiedades contaminadas de otro tenant, prompts/respuestas/argumentos y
  marcadores internos.

## Límites del evaluador

Se mantienen JSON de solicitud de 8192 bytes (413 antes del handler), stdout
máximo 64 KiB, timeout Garak 135 s/Qwen 180 s, límites CPU/RAM/PIDs, usuario
65532, rootfs de solo lectura, `cap-drop=ALL`, `no-new-privileges`,
`network=none` y las imágenes/argumentos fijados del commit anterior.

Hallazgo corregido: al superar 64 KiB se mataba el cliente `docker run`, pero no
se solicitaba detener el contenedor. Ahora el límite dispara una sola vez
`docker kill` y termina el cliente; la invocación de kill tiene un límite local
de 3 s. Si el daemon no responde, el sistema no puede garantizar que el
contenedor haya terminado; el nombre fijo se vuelve a limpiar en un intento
posterior y el job falla cerrado. No se ejecutó una prueba de contenedor que
produjera realmente más de 64 KiB; la nueva prueba unitaria verifica el disparo
exactamente una vez.

## Verificación de esta corrección

- `pnpm --filter @workspace/api-server exec tsx --test
  src/lib/assessment-output-limit.test.ts`: 2/2.
- `pnpm --filter @workspace/api-server test`: 43/43, incluidos RLS/RBAC,
  idempotencia, recuperación de lease, autorización de perfil y límite JSON.
- `pnpm --filter @workspace/api-server run typecheck`: pasó.
- `pnpm --filter @workspace/api-server run build`: pasó.
- `PORT=8081 BASE_PATH=/__mockup pnpm run build`: typecheck del monorepo,
  mockup, API y web pasaron; Vite conserva el aviso no bloqueante de chunk web
  >500 kB.
- E2E autenticado de desarrollo con fixtures y evaluación local Garak/Qwen:
  1/1, tras el cambio.
- `AiEvaluationPage.integration.test.tsx`: 5/5.
- Comprobación HTTP local después del reinicio API: `/api/healthz` 200,
  `/api/plans` 200 y lectura de jobs de workspace sin sesión 401.
- Captura pública de desarrollo: home cargó; la consola mostró aviso de claves
  Clerk de desarrollo y WebGPU no disponible. No se inició sesión ni se
  verificó el dashboard autenticado en navegador.
- Sin migraciones, cambios de permisos, socket o secretos; no se publicó ni
  desplegó.

## Pendientes

- Broker independiente no implementado: bloqueo material de identidad Unix y
  acceso al socket Docker en este host.
- Crear roles/credenciales de broker exige un canal de secretos que no entregue
  esa credencial al API; su aislamiento entre workflows no está acreditado.
- No se simuló retag real concurrente, overrun real del contenedor ni timeout
  real; las defensas restantes tienen pruebas de contrato/unitarias.
- No se verificó login Clerk real en navegador. IPv6 y advisories OSV/licencias
  conservan sus estados previos; esta revisión no los modifica.

## SHA-256 de código verificado

- `artifacts/api-server/src/lib/assessment-output-limit.ts`:
  `0ac8ce8767c89a1adbfdabeedd9c1b4d82b85eb48f12d80308a5b0b5fc123ece`
- `artifacts/api-server/src/lib/assessment-output-limit.test.ts`:
  `21f50cf09c77ca913226a30483a687d0f15e9d25577e016c595cc2851f66bb2e`
- `artifacts/api-server/src/lib/ai-assessment-worker.ts`:
  `d610c0eada09727c2dcf7a12feb01d4f2513cbd87520b1015bf451bd675454d2`
- `artifacts/api-server/package.json`:
  `2bf149cccb22c7a1623bbe165947e6632eba2e7e20c2bfe752c5aebf900ff882`
