# Aprobación sintética persistente por API — 2026-11-04

## Alcance

Se añadió un caso fixture independiente de reembolso de soporte que requiere
aprobación humana. El trabajador determinista local aplica Policy ON antes del
adaptador: el caso permitido queda pendiente y no invoca el adaptador hasta
recibir aprobación. La lista allow-listed del servidor vincula perfil, caso,
herramienta y argumentos ficticios a `guardian.synthetic.support.refund.v1`.
Los ocho perfiles y sus 16 casos fixture anteriores siguen intactos; el caso
de reembolso se añade aparte, por lo que el corpus fixture actual tiene 17
casos.

La prueba de integración ejecuta el módulo determinista Python para finanzas y
soporte, provisiona sus resultados sintéticos como jobs terminados en la base
de desarrollo y atraviesa la API de aprobaciones con el rol runtime y RLS.
El harness de fixture provisiona filas de prueba directamente; **no es el
consumidor real de la cola ni acredita el rol worker/broker**. No usa Docker,
Qwen, Garak, Clerk, datos de clientes ni herramientas externas.

## Resultado de aprobación

- 2 perfiles fixture: `guardian-agent-lab-finance-v1` y
  `guardian-agent-lab-customer-service-v1`.
- 4 solicitudes persistidas: 2 aprobadas, 1 denegada y 1 caducada.
- Aprobación finance y soporte: simulación allow-listed en clon de memoria,
  una vez cada una; repetición de la decisión respondida con `409`.
- Dos aprobadores concurrentes sobre la propuesta finance: exactamente un
  `200` y un `409`.
- Autoaprobación, rol viewer y acceso desde otro tenant: `403`.
- Binding/hash alterado: `409`; el estado permanece `pending`.
- Denegación y expiración: no se escribe recibo de simulación.
- Repetir el mismo completado fixture con la misma clave idempotente reutiliza
  el mismo job.
- La ruta normal de creación de jobs respondió `503` porque el worker aislado
  está deshabilitado; el conteo de jobs del workspace no cambió.
- Las filas de prueba se eliminan al terminar; los resultados no contienen
  prompts, respuestas ni argumentos en bruto.

## Verificación ejecutada

| Comprobación | Resultado |
| --- | --- |
| Worker determinista, política y fixtures de 8 perfiles | 144/144 pruebas del host, excluyendo solo el módulo que importa Garak |
| Suite worker completa en el host | 144 correctas y 1 error de importación: `garak` no está instalado en el host |
| API unitarias | 74/74 |
| API synthetic approval E2E contra PostgreSQL de desarrollo | 1/1 |
| SDK | 13/13; build correcto |
| UI integración | 8/8 |
| Typecheck raíz y API | Correctos |
| Build API y plataforma web | Correctos |

El build Vite requiere `PORT` y `BASE_PATH`; la repetición con
`PORT=18753 BASE_PATH=/` terminó correctamente. Emitió un aviso de sourcemap
para `tooltip.tsx` y otro por un chunk JavaScript mayor de 500 kB. La suite
worker completa del host sigue necesitando el entorno de imagen que contiene
Garak; no se instalaron dependencias.

## Evidencia

La corrida autenticada de desarrollo informó
`SYNTHETIC_APPROVAL_E2E_SHA256=8ffcb9fbb11b9d38a014f73e8b8c4ad44da8eca9abd1a9f1edfc13ae4a664e2f`.
El resumen redacted está en
`generated-artifacts/guardian-synthetic-approval-e2e.json`, SHA-256
`6bb8d2a3f070b81edf7a2b98addd27d86940347310904a31e852bf85db73fc68`.
El resumen declara `modelInference=false`; las propuestas son fixtures, no
Qwen ni `message.tool_calls` nativas.

## Límites pendientes

- El gate de ejecución real sigue `disabled` sin un broker aislado. Esta prueba
  no habilita ni valida jobs de cola consumidos por un worker independiente.
- No se ejecutó una nueva inferencia Qwen; el preflight conocido bloquea al
  detectar el socket Docker escribible desde la identidad actual. No se cambió
  el gate ni el acceso al socket.
- La autenticación HTTP de esta prueba usa identidades sintéticas de test; no
  equivale a una sesión Clerk real de navegador.
- El harness usa loopback para la API y PostgreSQL de desarrollo. No constituye
  una prueba de aislamiento de red del proceso ni de IPv6.
