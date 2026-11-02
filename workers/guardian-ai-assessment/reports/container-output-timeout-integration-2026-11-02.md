# Verificación de límites de salida y timeout del worker — 2026-11-02

## Resultado

Se cerró el trabajo pendiente de detención y limpieza tras desbordamiento de
stdout y timeout. La ejecución fue exclusivamente de desarrollo, contra la
imagen Qwen local fijada por ID; no se usaron egress, servicios externos,
clientes, producción ni credenciales.

Imagen: `sha256:884d4f7bc6c11e03f6ced5cfcc9e88e7a8043d85923429f1a3a181953f07830f`.
El harness verifica antes de ejecutar el ID y las etiquetas fijadas en
`profile-image-lock.json`. Los dos contenedores usaron `--pull=never`,
`--network=none`, UID/GID `65532:65532`, rootfs de solo lectura, `cap-drop=ALL`,
`no-new-privileges`, PIDs 64, CPU 1, memoria/swap 256 MiB, `/tmp` tmpfs de 16 MiB
`noexec` y logging Docker desactivado.

## Ejecución real del contenedor

Comando de test:

```sh
pnpm --filter @workspace/api-server run test:assessment-container-integration
```

Resultado: **1/1 tests**, cero fallos.

- **stdout:** el proceso del contenedor emitió 65.537 bytes sintéticos frente
  al límite de 65.536. El supervisor clasificó
  `worker_output_limit_exceeded`, solicitó `SIGKILL` al contenedor, confirmó la
  petición de kill y ejecutó `docker rm --force`. `docker ps -a` no mostró el
  nombre exacto y `docker inspect` confirmó que el contenedor ya no existía.
  Salida del proceso Docker: señal `SIGKILL`; la comprobación de limpieza
  concluyó en 2.961 ms. El capturador no retuvo el byte que excedía el límite;
  no se guardó salida cruda en el artefacto.
- **timeout:** proceso de 30 s detenido por timeout configurado a 750 ms. El
  resultado fue `worker_timeout`, señal `SIGKILL`, salida retenida 0 bytes,
  kill/rm solicitados y ausencia verificada con `ps` e `inspect`. Tiempo total
  observado, incluido cleanup: 1.450 ms.
- Ambos casos dejaron cero contenedores residuales. `--log-driver=none`
  evita persistencia de stdout en el logging del contenedor.

Resumen JSON redactado fuera de Git:
`generated-artifacts/guardian-ai-assessment/container-hardening-integration.json`
SHA-256:
`6055e5a82476c01fcc3dbe59b442abfa3fd04161873b7cfc12451d41097accc5`.
Contiene ID, límites, clasificación, recuentos, señales, estado de limpieza y
tiempos; no contiene stdout, prompt, respuesta ni argumentos del proceso.

## Pruebas y correcciones

- `pnpm --filter @workspace/api-server typecheck`: pasó.
- `pnpm --filter @workspace/api-server test`: **52/52** pasaron; incluye
  limpieza ante fallo de kill/remove/ps, nombre inseguro, timeout del comando
  Docker, output excesivo, identidad de imagen, tenant/RLS/RBAC, lease e
  idempotencia.
- `pnpm --filter @workspace/api-server run test:assessment-container-integration`:
  **1/1** pasó con Docker real.
- `git diff --check`: pasó antes del commit.
- Una primera suite tuvo 2 fallos en dobles de prueba que programaban eventos
  antes de cada invocación secuencial. Se corrigió el test para crear cada
  proceso simulado al invocarse el spawner; la repetición final pasó 52/52.
- Un primer typecheck detectó la posibilidad de `null` en el objeto de
  `docker image inspect`; se añadió una aserción de no-null antes de acceder al
  ID. La repetición final pasó.
- No se repitieron E2E Garak/Qwen, build de UI ni análisis OSV; la prueba real
  usó únicamente el contenedor de test descrito.

## Límites

Esto prueba el control de stdout/timeout y limpieza en el host de desarrollo;
no elimina la autoridad Docker del proceso API ni acredita aislamiento en otro
host. La separación API/broker continúa bloqueada por las identidades/permisos
del host Replit. IPv6 sigue sin verificar, y los advisories OSV/licencias no se
modificaron ni se consideran remediados.
