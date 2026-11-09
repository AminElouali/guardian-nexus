# Diagnóstico de carga de `/ai-evaluations`

**Fecha:** 2026-11-09  
**Estado inicial:** `e27a11a`  
**Commit de implementación:** `ae66e32327b9ce7d59367e28600cb089cd19567a`

## Causa raíz comprobada

El servicio web de Guardian Nexus estaba activo, pero el workflow configurado del API Server no estaba iniciado. El artifact web enruta `/api` al servicio API en el puerto 8080. Por eso la interfaz podía mostrar que Clerk tenía una sesión en el navegador mientras React Query recibía un `502` al solicitar los espacios de trabajo. El middleware de Clerk, la comprobación de membresía y RLS no podían responder mientras el API no estaba disponible.

La causa observada no fue un rechazo de Clerk, una denegación RBAC, un tenant ausente ni un error de esquema. No se encontró un `401`, `403` o `5xx` del API después de iniciar el workflow y tampoco una evidencia de error de PostgreSQL/RLS en las solicitudes verificadas.

## Evidencia

- Antes de iniciar el workflow `artifacts/api-server: API Server`, las solicitudes de prueba a `/api/healthz` y `/api/workspaces` devolvían `502`.
- Tras iniciarlo, el servidor arrancó en el puerto 8080 y completó su comprobación de preparación RLS.
- Las solicitudes de prueba posteriores devolvieron `200` en `/api/healthz` y `401` en `/api/workspaces` sin sesión, resultado esperado que confirma que la protección de autenticación sigue activa.
- El navegador de preview autenticado recibió `200` en `/api/workspaces`. Las lecturas de evaluaciones, disponibilidad, aprobaciones y trabajos del laboratorio respondieron `304 Not Modified` en la validación de caché, no como `401`, `403` ni error `5xx`.
- La consola del navegador no mostró excepciones de la aplicación; los mensajes registrados fueron de conexión/reconexión de Vite.
- Se observó una advertencia de deprecación de `pg` sobre llamadas `client.query()` concurrentes. Las solicitudes observadas finalizaron correctamente; no hay evidencia de que esa advertencia causara el fallo de carga. Se deja para revisión separada.

## Cambios

- Se inició el workflow API ya configurado; no se modificaron Clerk, rutas, permisos, RLS, esquema ni el contrato del API.
- Los estados de error de carga ahora distinguen sesión no validada (`401`), falta de acceso (`403`), recurso no disponible (`404`), API no disponible (`502/503/504`), error del servicio (`5xx`), respuesta con formato inesperado, fallo de red y error desconocido. La interfaz no muestra mensajes internos del servidor.
- El reintento queda conectado a `refetch`, se desactiva mientras hay una solicitud en curso y las consultas vencidas se revalidan al volver al navegador o recuperar la conexión.
- El estado vacío explica que no se encontró un espacio asociado y recomienda comprobar una invitación antes de crear otro.
- El indicador superior ahora dice “Sesión activa” y aclara que la sesión del navegador no confirma por sí sola el acceso al servicio o al espacio.
- Seguridad IA, historial, disponibilidad del laboratorio y bandeja de aprobaciones reutilizan los mismos mensajes seguros y reintentos. No se inventan datos de respaldo cuando el API falla.

## Verificación

- Tests UI: **21/21** aprobados, incluidos clasificación de errores, mensaje sin filtración de detalles internos y callback de reintento.
- Tests API offline: **86/86** aprobados, incluidos controles de autenticación, RLS, aislamiento entre espacios y contratos sintéticos del laboratorio.
- Typecheck web y API: aprobados.
- Build Vite: aprobado usando el `PORT` y `BASE_PATH` configurados por el artifact.
- Lecturas manuales de preview: `/api/healthz` = `200`; `/api/workspaces` sin sesión = `401`.
- La captura de `/ai-evaluations` del navegador de verificación muestra el inicio de sesión de Clerk porque ese navegador no tiene sesión. La vista autenticada no se capturó visualmente; su flujo API sí aparece en los logs del preview autenticado.
- Se conservaron las advertencias previas de build sobre sourcemap en `tooltip.tsx` y el chunk principal mayor de 500 kB. La verificación no incluye despliegue ni producción.
- No se ejecutaron Qwen, el worker de inferencia, Docker ni integraciones externas; el gate de aislamiento no se modificó.

## SHA-256 de archivos de implementación

```text
7b1ed1e70115a8030a592be24824ce41a588df983c0809bf3d1e752fb3ecfb9b  src/App.tsx
f842a97f605b44b3367a17c6c573659e6d1167eb92973846fea7c8440b16e4d5  src/components/WorkspaceQueryError.tsx
648ba92b1cfd09aece5c210d08bc0463c69d9ab7c3e8d3cc7fddec8312092a2d  src/lib/workspace-load-errors.ts
4fed283ffb7bb457e2e133df47d9f2d762c79751b6c1fd2f73761fb448275550  src/lib/workspace-load-errors.test.ts
36f2c16d7ca047908eafce9f4aefe0edc8e1674a6f481ba43ebf7188b9481d76  src/components/AiEvaluationPage.tsx
251473660f6ef0cc5233d821c267fcfc1595ed96ac1434ab8dc30ac5fdeacd51  src/components/GuardianApprovalInbox.tsx
afedc39f471bb510789c7e748da41ccffc2b71e250d44a86feacad1508ff8204  src/components/AiEvaluationPage.integration.test.tsx
```

## Límites pendientes

- El navegador de captura no puede validar una sesión firmada; para cerrar esa brecha hace falta una prueba E2E autenticada con usuario y espacio sintéticos.
- La advertencia de concurrencia de `pg` no bloqueó estas solicitudes, pero su origen exacto no se trazó en esta iteración.
- Los errores PostgreSQL internos se presentan de forma genérica al cliente; no se añadió un código público de error de esquema porque no se observó uno y no se debía exponer detalle interno.
