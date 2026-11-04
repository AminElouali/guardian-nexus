# Kit de laboratorio Guardian Nexus (solo preparación)

**Estado:** plantillas preparadas; no desplegadas ni ejecutadas en este host.
No acreditan separación de identidades, egress bloqueado, ni seguridad para
clientes. No usar en producción.

El host Replit actual comparte la identidad `runner` con el socket Docker y no
permite cambiar UID. Por tanto no hay un broker con frontera Unix real aquí.
Este kit sirve para preparar un host Linux de laboratorio autorizado y detectar
una configuración que no cumpla; no habilita el broker ni el runner Qwen.

## Requisitos del host

- VM Linux de laboratorio desechable y ya autorizada, con dos usuarios no-root
  distintos: `guardian-api` y `guardian-assessment-broker`.
- Daemon Docker rootless dedicado al broker. El API no debe poder leer ni
  escribir su socket; no añadir el API al grupo `docker`.
- PostgreSQL local de laboratorio (`guardian_lab_*`) y sesiones distintas:
  API `app_runtime_login`; broker `app_ai_assessment_worker_login`, miembro de
  `app_ai_assessment_worker`. La plantilla de login no guarda contraseñas:
  requiere autenticación local `peer` configurada por el administrador.
- La API actual todavía usa su pool de base de datos para reclamar trabajos y
  cambia a `app_ai_assessment_worker` con `SET LOCAL ROLE`. El login de broker
  separado de este kit **no está conectado al runtime**; no afirmar separación
  DB/API hasta implementar y probar el proceso broker.
- Hay unidades systemd de referencia en `systemd/`, protegidas por
  `ConditionPathExists` porque los ejecutables de despliegue aún no existen.
  No son servicios instalables ni están validadas en un host real.
- No se incluye una unidad systemd ejecutable: el proceso broker todavía no
  está integrado con la cola. No sustituirla por un wrapper que comparta UID o
  credenciales.

## Preparación y verificaciones

1. Revisar los archivos `.example`; no contienen credenciales. Crear usuarios,
   servicio rootless y configuración peer mediante el procedimiento aprobado
   del administrador del host.
2. Como administrador del host, ejecutar `bash scripts/preflight-host.sh`.
   Solo inspecciona UID/GID, socket y disponibilidad local de IPv6; no conecta
   con Docker, no abre sockets y no modifica el host.
3. Solo en una base desechable cuyo nombre empieza por `guardian_lab_`, y con
   autorización explícita, se puede ejecutar
   `GUARDIAN_LAB_ACK=provision-worker-login GUARDIAN_LAB_DB=guardian_lab_dev
   GUARDIAN_LAB_DB_ADMIN=postgres bash scripts/provision-worker-login.sh`.
   Usa socket Unix local, `--no-password`, no escribe contraseñas y se limita
   a crear el rol de login del broker y otorgarle el rol de worker existente.
4. Configurar `pg_ident.conf` / `pg_hba.conf` desde los ejemplos y verificar
   con `GUARDIAN_LAB_ACK=verify-local-lab-db ... bash
   scripts/verify-db-identities.sh` como administrador del host. El verificador
   solo consulta: ejecuta `psql` como cada identidad Unix con `runuser`, limpia
   el entorno de libpq (no usa `PGPASSWORD`, servicios ni opciones heredadas),
   realiza `SET ROLE` al rol efectivo esperado y verifica que login y rol sean
   distintos, no privilegiados, sin herencia implícita, propiedad de tablas ni
   grants directos a tablas/columnas tenant para los logins. También exige RLS
   forzada en tablas públicas con `tenant_id` o `workspace_id`. Los roles grupo
   `app_runtime` y
   `app_ai_assessment_worker` deben ser `NOLOGIN`/`NOINHERIT`; los logins deben
   ser distintos, `LOGIN`/`NOINHERIT` y autenticarse por `peer`.
   **Límite importante:** `database_session=passed` verifica identidades,
   privilegios y presencia de FORCE RLS; no valida que las expresiones de las
   políticas filtren correctamente por tenant ni prueba filas cruzadas.
   `tenant_policy_predicates=not_checked` es explícito en la salida. No
   habilitar el runner basándose solo en ese resultado.
5. Para el worker, conservar el preflight existente
   `python3 workers/guardian-ai-assessment/scripts/run_qwen_isolation_preflight.py`.
   Las pruebas negativas IPv4/UDP/DNS y la limitación IPv6 se documentan en
   `workers/guardian-ai-assessment/NETWORK_ISOLATION.md`; sus probes deben
   seguir ejecutándose dentro de una imagen fijada con `--network=none`.
6. Aceptar el host solo después de demostrar que el UID API no puede abrir el
   socket, que el broker usa su propio daemon rootless, que los dos logins DB
   son independientes y que los tests adversos de grants/lease/tenant/imagen
   fallan antes de crear un contenedor. Ejecutar además la suite de API contra
   una base desechable `guardian_lab_*`; exigir pruebas positivas de acceso al
   tenant propio y negativas de lectura/escritura cruzada para jobs, evidencias
   y aprobaciones. Esa suite de datos sintéticos, no este script de metadatos,
   es la evidencia de predicates RLS efectivos.

`preflight-host.sh`, la verificación PostgreSQL contra una base real y la
provisión de roles **no se ejecutaron** en Replit:
este entorno comparte el socket Docker, no cumple la frontera y no tiene
autorización para tocar un host o una base externos. El preflight de Qwen actual
permanece fail-closed.
