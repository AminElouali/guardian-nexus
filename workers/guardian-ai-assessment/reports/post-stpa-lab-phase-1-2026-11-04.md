# Guardian Nexus — fase local post-STPA v0.2.0

Fecha: 2026-11-04  
HEAD de inicio: `953e75d87b1101c607fa837f47cbcaf85511fb72` (árbol limpio).

## Resultado de escenarios

Se añadió un manifiesto versionado que enlaza los 32 IDs del catálogo STPA con
decisiones esperadas y un ejecutor determinista que llama exclusivamente al
`evaluate_synthetic_action_policy` existente. No llama a un despachador,
simulador, base de datos, Docker ni proveedor de modelos. El resultado
`risk-intelligence-stpa-policy-run-2026-11-04.json` contiene 32 decisiones:

- ALLOW: 8
- DENY: 21
- REQUIRE_APPROVAL: 3
- concordancia esperada de decisión y motivo: 32/32
- objetivos STPA completos/verificados: 0

Las 32 filas son verificaciones sintéticas del motor de políticas, no
ejecuciones de agentes, no inferencias Qwen, no pruebas de propagación de
daño y no evidencia de eficacia general. Risk Intelligence sigue siendo
consultivo; el Policy Engine existente conserva la decisión.

SHA-256 del resumen de evidencia del ejecutor:  
`05e940b0832d083c56033c7d8e2ef4deda61eccab38966909bc872b7b3814cd1`.

## Preflight observado en Replit

El preflight ejecutado en modo de solo lectura terminó con código `2` (bloqueado).
El artefacto sin valores secretos es
`lab-host-preflight-2026-11-04.json`; su SHA-256 de evidencia es
`e1dbb18fed636bda22387b180714d28877e73998494d46dbd7a973811061eade`.

Hechos de esa observación:

- El proceso de preflight puede leer y escribir el socket
  `/var/run/docker.sock`; metadatos: UID propietario `0`, grupo `runner`, modo
  `0660` (representado como `432` en el JSON).
- Hay 4 nombres de variables sensibles presentes; no se leyeron ni registraron
  valores ni nombres.
- UID/GID separados para API, worker y broker, ACL mínima y acceso por identidad
  de servicio: no verificados.
- Sesiones PostgreSQL de API/worker/broker y separación real de roles: no
  verificadas; conexiones realizadas: 0.
- Prueba de identidad de un proceso hijo: no verificada. No se inició un proceso
  Qwen ni se ejecutó inferencia.
- `hostBoundaryReady=false` e `integratedAssessmentReady=false`. El gate de
  Qwen permanece cerrado.
- Docker, conexiones externas, producción y despliegue: no utilizados.

El preflight admite, solo en un host Ubuntu 24.04 dedicado, sondeos optativos
por `runuser` y `psql` de solo lectura con identidades locales separadas.
No se ejecutaron esos sondeos en Replit. La prueba de hijo es un chequeo de
identidad sin modelo, no prueba de inferencia ni de sandbox Qwen efectivo.

## Paquete transferible

`lab-host/ubuntu-24.04/` contiene un plan de aprovisionamiento idempotente con
modo `--plan` por defecto, rollback, usuarios/grupos separados, un grupo IPC
estrecho para API→broker, grupo del socket Docker solo para broker, ejemplos
systemd y plantillas de autenticación PostgreSQL local por peer. No se ejecutó
`--apply`, no se crearon usuarios, grupos o VM, no se cambió el socket ni se
instalaron unidades. Los ejemplos no configuran grants RLS por tabla; deben
revisarse con el esquema real en un host de laboratorio autorizado.

`provision.sh --plan` indicó expresamente que no modifica archivos, identidades,
servicios ni configuración Docker. `bash -n` pasó. Los guardas del paquete
fueron probados sin ejecutar aprovisionamiento.

## Verificaciones ejecutadas

Todas fueron locales; las pruebas API elegidas no usaron PostgreSQL ni servicios
externos. El E2E persistente de aprobación API se omitió deliberadamente porque
su test exige `DATABASE_URL` y crea una conexión PostgreSQL; no se accedió a
credenciales ni se conectó ninguna base.

- Worker, runner STPA + preflight + policy lab + guardas lab-as-code: **50/50**.
- API, pruebas unitarias seleccionadas: **53/53**.
- SDK Python: **8/8**.
- SDK TypeScript: **13/13**.
- Catálogo y paridad UI con manifiesto: **6/6**.
- Runner sintético de políticas: **32 escenarios**, sin despacho.
- Typecheck del monorepo: pasó.
- Build API: pasó.
- Build web: pasó con advertencia de sourcemap en `tooltip.tsx` y aviso de
  chunk JS de `747.22 kB`; no se corrigió porque es ajeno al cambio y el build
  terminó correctamente.
- Build SDK TypeScript: pasó.
- Preflight actual: bloqueado, salida `2`.

No se ejecutó la suite worker completa porque puede incluir rutas de Docker,
modelo o servicios. No se ejecutó el E2E de API/DB, no se arrancó Qwen ni Docker,
y no se generó evidencia nueva de inferencia. Las cifras históricas Qwen
(8 inferencias: 7 marcadores adaptados, 0 `message.tool_calls` nativas,
1 `no_proposal`) no pertenecen a esta fase.

## Límites y desbloqueo

El paquete está preparado, no desplegado ni verificado en Ubuntu. Para continuar
hace falta un host dedicado autorizado que acredite identidades UID/GID
distintas, API sin acceso al socket, broker como único miembro del grupo de
socket, sesiones DB peer independientes, reglas RLS reales, y luego el guard
offline del worker dentro del aislamiento efectivo. El preflight de host por sí
mismo no abre el gate integrado; el guard de runtime y hashes del modelo siguen
siendo obligatorios. No se afirma cumplimiento de IPv6, seguridad frente a
clientes, ni completitud de los 32 objetivos STPA.
