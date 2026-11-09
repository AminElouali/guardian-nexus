# Cobertura offline del parser y procedencia — 2026-11-09

## Alcance y cambio

- Base: HEAD `e7f2e98c948390575fc60b697d2b0caf382d0185`, árbol limpio y sin
  procesos relevantes activos.
- Se amplió la regresión existente de marcadores Qwen malformados de correo,
  BBDD e infraestructura a los ocho perfiles: correo, BBDD, finanzas,
  programación, soporte, navegador, infraestructura y multiagente.
- Cada caso usa un cliente falso con una propuesta sintética marcada y texto
  residual adversario. El parser debe clasificarla como
  `unparsed_qwen_native_markup`, denegar como `malformed_tool_proposal` y bloquear
  antes de evaluación de Policy y despacho. Se comprueba `tool_choice=auto`,
  cero eventos y cero llamadas al simulador.
- La prueba no es inferencia Qwen ni ejecución del worker real. La cobertura
  existente de fixtures, `NO_PROPOSAL`, llamadas nativas y salidas adaptadas se
  mantiene separada; no se alteraron esos artefactos.

## Resultados ejecutados en serie

1. Test focal del parser: **1/1** aprobado, con ocho subcasos por vertical.
2. Worker offline `test_policy_lab.py`: **37/37** aprobados.
3. Worker offline `test_autonomous_tool_selection.py`: **11/11** aprobados.
4. Suite API: **86/86** aprobados.
5. Integración UI de Seguridad IA: **17/17** aprobados.
6. `git diff --check`: aprobado.

Las pruebas API/UI incluyen contratos de clasificación de procedencia,
autorización antes de la simulación, distinción de fixtures y
`NO_PROPOSAL`. Son pruebas automatizadas locales; no acreditan PostgreSQL/RLS
en vivo ni una sesión Clerk en navegador.

## Gate, inferencia y aprobaciones

- No se ejecutaron inferencia Qwen, worker de laboratorio, Docker, socket,
  workflows, servicios externos ni conexiones PostgreSQL.
- El último preflight persistido es del **2026-11-04** y dice
  `hostBoundaryReady=false`; no se volvió a sondear. Sus hashes no demuestran
  estado actual del host.
- La evidencia Qwen de ocho perfiles sigue siendo histórica:
  7 propuestas adaptadas por marcador, 0 `message.tool_calls` nativas y
  1 `NO_PROPOSAL` de infraestructura. Los ocho fixtures siguen aparte.
- Aprobaciones finanzas/soporte: solo contratos y pruebas offline/fixtures;
  no se verificó persistencia PostgreSQL, RLS viva, concurrencia real ni
  aprobación vinculada a una inferencia Qwen.
- No se verificó una PostgreSQL desechable; por eso no se ejecutó el E2E DB.

## Evidencia y siguiente gate

Hashes de los artefactos se registran en el `MVP_CHECKPOINT.md` adjunto a este
incremento. Siguiente paso seguro: acreditar host/broker e identidades
separadas, y disponer de una PostgreSQL desechable con roles/RLS verificables.
Hasta entonces, mantener Qwen y el worker real bloqueados y continuar solo con
pruebas offline.
